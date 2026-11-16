@preconcurrency import AVFoundation
import Combine
import CoreImage.CIFilterBuiltins
import Foundation
import Network
import OSLog
import SwiftUI

#if os(macOS)
  import AppKit
#else
  import UIKit
#endif

/// 仅在主动打开的迁移页面维持发现、配对与传输，关闭或锁定立即撤销会话。
@MainActor
final class VaultMigrationCoordinator: ObservableObject, Identifiable {
  enum Phase: Equatable {
    case preparing, waiting, finding, connecting, confirming, awaitingPeer, authorizingTarget,
      transferring, complete,
      stopped
  }

  let id = UUID()
  let role: VaultMigrationRole
  @Published private(set) var phase: Phase = .preparing
  @Published private(set) var pairingText = ""
  @Published private(set) var verification = ""
  @Published private(set) var status = "正在准备迁移…"
  @Published private(set) var progress: VaultMigrationProgress?
  @Published private(set) var bytesPerSecond: Double = 0
  @Published private(set) var result: VaultMigrationReceipt?
  @Published private(set) var pending: [VaultMigrationPending] = []
  @Published private(set) var targetFolder: VaultMedia?
  @Published private(set) var targetAuthenticating = false
  @Published private(set) var targetError: String?
  @Published private(set) var spaceAlert: String?
  private(set) var requiresRelock = false
  private let library: VaultLibrary
  private let grant: VaultGrant
  private let parentID: UUID?
  private let sourceIDs: [UUID]
  private let queue = DispatchQueue(label: "local.encvault.migration.discovery")
  private var pairing: VaultMigrationPairing?
  private var listener: NWListener?
  private var browser: NWBrowser?
  #if os(macOS)
    private var remote: VaultMigrationRemote?
  #endif
  private var pipe: VaultMigrationPipe?
  private var source: VaultMigrationSource?
  private var incoming: VaultMigrationIncoming?
  private var receivingGrant: VaultGrant?
  private var targetApproval: CheckedContinuation<Void, Error>?
  private var targetWorker: Task<Void, Never>?
  private var runner: Task<Void, Never>?
  private var expiry: Task<Void, Never>?
  private var approval: CheckedContinuation<Void, Error>?
  private var generation = UUID()
  private var started = false
  private var cancelled = false
  private var lastProgress = Date.distantPast
  private var rateInstant: ContinuousClock.Instant?
  private var rateBytes: UInt64 = 0
  private var copiedPairing: Int?
  private var networkID = UUID()
  private static let logger = Logger(subsystem: "local.encvault", category: "Migration")

  /// 业务作用：把迁移页面限定到当前保险箱、选定来源或接收目录。
  /// 参数说明：
  /// - `role`：本次发送或接收方向。
  /// - `library`：本机保险箱，不接收外来主密钥替换现有保险箱。
  /// - `grant`：当前 App 会话，锁定后不能继续使用。
  /// - `parentID`：接收时的目标目录。
  /// - `sourceIDs`：发送时明确选择的项目；空数组表示全部根项目。
  /// 返回：尚未开启网络发现的页面状态。
  init(
    role: VaultMigrationRole, library: VaultLibrary, grant: VaultGrant,
    parentID: UUID?, sourceIDs: [UUID]
  ) {
    self.role = role
    self.library = library
    self.grant = grant
    self.parentID = parentID
    self.sourceIDs = sourceIDs
  }

  /// 业务作用：页面主动出现时准备来源或接收能力，只启动一次发现流程。
  /// 参数说明：无。
  /// 返回：来源授权完成后显示短期二维码；失败时不开放接收或交付内容。
  func start() {
    guard !started else {
      return
    }
    started = true
    restart(resumeID: nil)
  }

  /// 业务作用：用户明确选择待续传任务后重新授权来源并生成新的配对。
  /// 参数说明：
  /// - `id`：本机加密待发送记录中的任务身份。
  /// 返回：不复用旧配对密钥、ROOT 身份或已经取消的连接。
  func resume(_ id: UUID) {
    restart(resumeID: id)
  }

  /// 业务作用：替换旧发现流程前先撤销所有旧连接，异步准备结果只属于当前页面代次。
  /// 参数说明：
  /// - `resumeID`：继续已有来源任务时提供，否则重新准备当前选择。
  /// 返回：合法来源已准备后开始短期监听，不让迟到结果恢复旧会话。
  private func restart(resumeID: UUID?) {
    stopNetwork()
    cancelled = false
    let generation = UUID()
    self.generation = generation
    phase = .preparing
    status = "正在核对迁移范围…"
    progress = nil
    bytesPerSecond = 0
    rateInstant = nil
    rateBytes = 0
    result = nil
    spaceAlert = nil
    let library = library
    let grant = grant
    let ids = sourceIDs
    let role = role
    runner = Task { [weak self] in
      do {
        let prepared = try await Task.detached {
          try grant.check()
          if role == .send {
            let source =
              try resumeID.map {
                try VaultMigrationSource.resume(id: $0, in: library, using: grant)
              } ?? VaultMigrationSource(library: library, ids: ids, using: grant)
            return (
              source as VaultMigrationSource?,
              try VaultMigrationSource.pending(in: library, using: grant)
            )
          }
          return (nil as VaultMigrationSource?, [] as [VaultMigrationPending])
        }.value
        guard let self, self.generation == generation, !self.cancelled else {
          prepared.0?.revoke()
          return
        }
        self.source = prepared.0
        self.pending = prepared.1
        try self.listen()
      } catch {
        guard let self, self.generation == generation else {
          return
        }
        self.fail(error)
      }
    }
  }

  /// 业务作用：广播无敏感内容的短期服务，只接受持有二维码密钥的 TLS 对端。
  /// 参数说明：无。
  /// 返回：监听就绪后展示配对信息，超时、取消和错误会关闭监听。
  private func listen() throws {
    let pairing = try VaultMigrationPairing(role: role)
    self.pairing = pairing
    #if os(macOS)
      beginRemote(pairing, listening: true)
    #else
      let listener = try NWListener(using: pairing.parameters(), on: .any)
      self.listener = listener
      listener.service = NWListener.Service(
        name: pairing.id.uuidString, type: VaultMigrationPairing.service)
      let generation = generation
      listener.stateUpdateHandler = { [weak self, weak listener] state in
        Task {
          @MainActor in
          // 切换为主动连接后旧监听已撤下，迟到的发现事件不能撤销新 TLS 会话。
          guard let self, let listener, self.listener === listener,
            self.generation == generation, !self.cancelled
          else {
            return
          }
          switch state {
          case .ready:
            if self.phase == .preparing {
              self.phase = .waiting
              self.pairingText = (try? pairing.text()) ?? ""
              self.status = "请在另一台设备选择\(self.role == .send ? "接收" : "发送")，扫描此二维码。"
            }
          case .failed:
            if self.pipe == nil {
              self.fail(VaultMigrationError.connection)
            }
          default:
            break
          }
        }
      }
      listener.newConnectionHandler = { [weak self, weak listener] connection in
        Task {
          @MainActor in
          guard let self, let listener, self.listener === listener,
            self.generation == generation, !self.cancelled,
            self.phase == .waiting, self.pipe == nil
          else {
            connection.cancel()
            return
          }
          self.run(VaultMigrationPipe(connection), pairing: pairing, server: true)
        }
      }
      listener.start(queue: queue)
    #endif
    expiry = Task { [weak self] in
      do {
        try await Task.sleep(for: .seconds(600))
        guard let self, [.waiting, .finding, .connecting, .confirming].contains(self.phase) else {
          return
        }
        self.fail(VaultMigrationError.expired)
      } catch {
      }
    }
  }

  /// 业务作用：只查找用户扫描或粘贴的服务身份，不连接其它发现设备。
  /// 参数说明：
  /// - `text`：对端主动提供的完整配对字符串。
  /// 返回：找到同一次配对服务后建立认证连接，方向相同或信息非法时拒绝。
  func connect(_ text: String) {
    guard phase == .waiting, pipe == nil else {
      return
    }
    do {
      let remote = try VaultMigrationPairing(text: text)
      guard remote.role != role else {
        throw VaultMigrationError.pairing
      }
      listener?.cancel()
      listener = nil
      phase = .finding
      status = "正在查找已配对设备…"
      pairingText = ""
      #if os(macOS)
        self.remote?.cancel()
        self.remote = nil
        beginRemote(remote, listening: false)
      #else
        let parameters = NWParameters.tcp
        parameters.includePeerToPeer = true
        let browser = NWBrowser(
          for: .bonjour(type: VaultMigrationPairing.service, domain: nil), using: parameters)
        self.browser = browser
        let generation = generation
        browser.browseResultsChangedHandler = {
          [weak self, weak browser] results, _ in
          for result in results {
            if case .service(let name, _, _, _) = result.endpoint, name == remote.id.uuidString {
              Task {
                @MainActor in
                guard let self, let browser, self.browser === browser,
                  self.generation == generation, self.phase == .finding,
                  !self.cancelled, self.pipe == nil
                else {
                  return
                }
                self.run(
                  VaultMigrationPipe(NWConnection(to: result.endpoint, using: remote.parameters())),
                  pairing: remote,
                  server: false)
              }
              break
            }
          }
        }
        browser.stateUpdateHandler = { [weak self, weak browser] state in
          if case .failed = state {
            Task {
              @MainActor in
              guard let self, let browser, self.browser === browser,
                self.generation == generation, self.phase == .finding
              else {
                return
              }
              self.fail(VaultMigrationError.connection)
            }
          }
        }
        browser.start(queue: queue)
      #endif
    } catch {
      fail(error)
    }
  }

  #if os(macOS)
    /// 业务作用：由独立网络沙箱承担 Bonjour 与 TLS，宿主只处理端到端加密业务。
    /// 参数说明：
    /// - pairing：本次监听或对端配对身份。
    /// - listening：是否公开当前页面的短期二维码服务。
    /// 返回：认证连接就绪后交给同一业务状态机，旧页面回调被丢弃。
    private func beginRemote(_ pairing: VaultMigrationPairing, listening: Bool) {
      let generation = generation
      let networkID = UUID()
      self.networkID = networkID
      let remote = VaultMigrationRemote { [weak self] code in
        Task {
          @MainActor in
          guard let self, self.generation == generation, self.networkID == networkID,
            !self.cancelled
          else {
            return
          }
          switch code {
          case 1:
            guard self.phase == .preparing else {
              return
            }
            self.phase = .waiting
            self.pairingText = (try? pairing.text()) ?? ""
            self.status = "请在另一台设备选择\(self.role == .send ? "接收" : "发送")，扫描此二维码。"
          case 2, 3:
            guard self.pipe == nil, let remote = self.remote else {
              return
            }
            self.run(VaultMigrationPipe(remote: remote), pairing: pairing, server: code == 2)
          default:
            self.fail(VaultMigrationError.connection)
          }
        }
      }
      self.remote = remote
      runner = Task { [weak self] in
        do {
          try await remote.begin(pairing, listening: listening)
        } catch {
          guard let self, self.generation == generation else {
            return
          }
          self.fail(error)
        }
      }
    }
  #endif

  /// 业务作用：把单一认证连接交给传输状态机，清单准备和磁盘处理不占用界面线程。
  /// 参数说明：
  /// - `pipe`：已匹配配对信息的有界安全通道。
  /// - `pairing`：本次高熵认证材料。
  /// - `server`：本端是否为监听端。
  /// 返回：完成时呈现接收端持久收据，失败保留可恢复密文。
  private func run(_ pipe: VaultMigrationPipe, pairing: VaultMigrationPairing, server: Bool) {
    phase = .connecting
    status = "正在建立加密连接…"
    clearPairingCopy()
    pairingText = ""
    if !server {
      listener?.cancel()
      listener = nil
    }
    expiry?.cancel()
    expiry = nil
    self.pipe = pipe
    let generation = generation
    let role = role
    let source = source
    expiry = Task { [weak self] in
      do {
        while !Task.isCancelled {
          try await Task.sleep(for: .seconds(1))
          guard let self, self.generation == generation else {
            return
          }
          if [.confirming, .awaitingPeer, .authorizingTarget].contains(self.phase) {
            try pipe.check()
          }
          if [.connecting, .confirming, .awaitingPeer, .authorizingTarget].contains(self.phase),
            pairing.expires <= Date()
          {
            throw VaultMigrationError.expired
          }
          if [.complete, .stopped].contains(self.phase) {
            return
          }
        }
      } catch {
        guard let self, self.generation == generation, !Task.isCancelled else {
          return
        }
        self.fail(error)
      }
    }
    runner = Task { [weak self] in
      do {
        let confirm: @Sendable (String) async throws -> Void = { [weak self] number in
          guard let self else {
            throw VaultMigrationError.cancelled
          }
          try await self.awaitApproval(number, generation: generation)
        }
        let progress: @Sendable (VaultMigrationProgress) async -> Void = { [weak self] value in
          await self?.update(value, generation: generation)
        }
        let receipt: VaultMigrationReceipt
        if role == .send {
          guard let source else {
            throw VaultMigrationError.cancelled
          }
          receipt = try await VaultMigrationExchange.send(
            source: source, pipe: pipe, pairing: pairing, server: server, confirm: confirm,
            progress: progress)
        } else {
          receipt = try await VaultMigrationExchange.receive(
            pipe: pipe, pairing: pairing, server: server, confirm: confirm,
            prepare: { [weak self] manifest in
              guard let self else {
                throw VaultMigrationError.cancelled
              }
              return try await self.prepare(manifest, generation: generation)
            }, progress: progress)
        }
        guard let self, self.generation == generation, !self.cancelled else {
          return
        }
        self.result = receipt
        self.phase = .complete
        self.expiry?.cancel()
        self.expiry = nil
        self.status =
          "已复制 \(receipt.files) 个文件，改名 \(receipt.renamed) 项，合并 \(receipt.merged) 个目录。来源原件保留。"
        self.clearPairingCopy()
        pipe.cancel()
        self.incoming?.revoke()
        self.incoming = nil
        self.receivingGrant?.revoke()
        self.receivingGrant = nil
        self.source?.revoke()
      } catch {
        guard let self, self.generation == generation, !self.cancelled else {
          return
        }
        self.fail(error)
      }
    }
  }

  /// 业务作用：在双方核对同一号码并主动确认之前暂停任何保险箱清单发送。
  /// 参数说明：
  /// - `number`：由本次临时密钥与完整握手派生的核对号码。
  /// - `generation`：当前页面流程身份。
  /// 返回：用户确认后继续；取消、锁定或旧流程拒绝。
  private func awaitApproval(_ number: String, generation: UUID) async throws {
    guard self.generation == generation, !cancelled else {
      throw VaultMigrationError.cancelled
    }
    verification = number
    phase = .confirming
    status = "核对另一台设备上的号码，确认一致后两端都点“号码一致，继续”。"
    try await withCheckedThrowingContinuation {
      continuation in
      approval = continuation
    }
    phase = .awaitingPeer
    status = "等待另一端确认并准备内容…"
  }

  /// 业务作用：只消费当前配对的本机确认，不把旧按钮用于后续任务。
  /// 参数说明：无。
  /// 返回：本端允许交换本次清单，仍需对端独立批准。
  func approve() {
    guard phase == .confirming, let approval else {
      return
    }
    self.approval = nil
    approval.resume()
  }

  /// 业务作用：在后台建立接收事务，返回界面前再次检查当前页面身份。
  /// 参数说明：
  /// - `manifest`：本次加密连接已经认证的内容清单。
  /// - `generation`：当前接收页面身份。
  /// 返回：当前仍有效时交付本机事务，迟到事务立即撤权。
  private func prepare(_ manifest: VaultMigrationManifest, generation: UUID) async throws
    -> VaultMigrationIncoming
  {
    guard self.generation == generation, !cancelled else {
      throw VaultMigrationError.cancelled
    }
    let library = library
    let parent = grant
    let parentID = parentID
    if receivingGrant == nil {
      let scoped = try await Task.detached {
        try library.migrationReceivingGrant(using: parent)
      }.value
      guard self.generation == generation, !cancelled else {
        scoped.revoke()
        throw VaultMigrationError.cancelled
      }
      receivingGrant = scoped
    }
    guard let scoped = receivingGrant else {
      throw VaultMigrationError.cancelled
    }
    while true {
      do {
        let result = try await Task.detached {
          try VaultMigrationIncoming(
            manifest: manifest, library: library, parentID: parentID, using: scoped,
            recoveryUsing: parent)
        }.value
        guard self.generation == generation, !cancelled else {
          result.revoke()
          throw VaultMigrationError.cancelled
        }
        incoming = result
        return result
      } catch VaultError.folderPasswordRequired(let id) {
        let folder = try await Task.detached {
          try library.nextLockedFolder(id: id, recursive: false, using: scoped)
        }.value
        guard self.generation == generation, !cancelled, let folder else {
          throw VaultMigrationError.cancelled
        }
        targetFolder = folder
        targetError = nil
        phase = .authorizingTarget
        status = "请验证接收设备目标文件夹的访问密码，验证后继续当前迁移。"
        try await withCheckedThrowingContinuation {
          continuation in
          targetApproval = continuation
        }
      }
    }
  }

  /// 业务作用：只向本次接收任务授予目标目录权限，不更改目录密码或正常浏览会话。
  /// 参数说明：
  /// - `password`：用户本次输入的目标目录密码，仅在接收设备验证。
  /// 返回：正确时继续原任务，错误留在本页，锁定或关闭时不继续授权。
  func authenticateTarget(_ password: String) {
    guard phase == .authorizingTarget, !targetAuthenticating, let folder = targetFolder,
      let scoped = receivingGrant, targetApproval != nil
    else {
      return
    }
    targetAuthenticating = true
    targetError = nil
    let generation = generation
    let library = library
    targetWorker = Task { [weak self] in
      do {
        try await Task.detached {
          try library.authenticateFolder(id: folder.id, password: password, using: scoped)
        }.value
        guard let self, self.generation == generation, !self.cancelled else {
          return
        }
        self.targetAuthenticating = false
        self.targetFolder = nil
        self.phase = .transferring
        self.status = "正在复验接收目录…"
        let approval = self.targetApproval
        self.targetApproval = nil
        approval?.resume()
      } catch {
        guard let self, self.generation == generation, !self.cancelled else {
          return
        }
        self.targetAuthenticating = false
        if case VaultError.incorrectFolderPassword = error {
          self.targetError = "目标文件夹密码不正确，请重新输入。"
        } else {
          self.fail(error)
        }
      }
    }
  }

  /// 业务作用：关闭空间不足提示，不重新开启已被拒绝的传输。
  /// 参数说明：无。
  /// 返回：提示撤下，原有数据保持不变。
  func dismissSpaceAlert() {
    spaceAlert = nil
  }

  /// 业务作用：以有界频率刷新进度，不为每个分块排队无限界面更新。
  /// 参数说明：
  /// - `value`：当前迁移快照。
  /// - `generation`：发起进度的流程身份。
  /// 返回：只保存当前页最新状态，速率仅统计本次实际发送或保存的字节，续传前缀不计入。
  private func update(_ value: VaultMigrationProgress, generation: UUID) {
    guard self.generation == generation, !cancelled else {
      return
    }
    phase = .transferring
    if value.phase == .content {
      let now = ContinuousClock.now
      if let previous = rateInstant {
        let duration = previous.duration(to: now)
        let seconds =
          Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1e18
        if seconds >= 0.5, value.transferredBytes >= rateBytes {
          let sample = Double(value.transferredBytes - rateBytes) / seconds
          bytesPerSecond = bytesPerSecond == 0 ? sample : bytesPerSecond * 0.65 + sample * 0.35
          rateInstant = now
          rateBytes = value.transferredBytes
        }
      } else {
        rateInstant = now
        rateBytes = value.transferredBytes
      }
    }
    if Date().timeIntervalSince(lastProgress) >= 0.1 || value.phase != progress?.phase {
      progress = value
      lastProgress = Date()
      status = value.phase.rawValue
    }
  }

  /// 业务作用：明确用户操作才把短期配对信息放入本机剪贴板，不复制保险箱密码。
  /// 参数说明：无。
  /// 返回：本次配对内容可粘贴到另一端，到期或关闭时仅清理仍属本次的剪贴板。
  func copyPairing() {
    guard phase == .waiting, !pairingText.isEmpty else {
      return
    }
    #if os(macOS)
      NSPasteboard.general.prepareForNewContents(with: .currentHostOnly)
      NSPasteboard.general.setString(pairingText, forType: .string)
      copiedPairing = NSPasteboard.general.changeCount
    #else
      UIPasteboard.general.setItems(
        [[UIPasteboard.typeAutomatic: pairingText]],
        options: [.localOnly: true, .expirationDate: pairing?.expires ?? Date()])
      copiedPairing = UIPasteboard.general.changeCount
    #endif
  }

  /// 业务作用：只清除本次仍拥有的配对剪贴板，避免覆盖用户后来复制的其它内容。
  /// 参数说明：无。
  /// 返回：配对内容不继续留作可用凭据，其它剪贴板内容保持。
  private func clearPairingCopy() {
    guard let count = copiedPairing else {
      return
    }
    #if os(macOS)
      if NSPasteboard.general.changeCount == count {
        NSPasteboard.general.clearContents()
      }
    #else
      if UIPasteboard.general.changeCount == count {
        UIPasteboard.general.items = []
      }
    #endif
    copiedPairing = nil
  }

  /// 业务作用：错误时先关闭连接与明文交付能力，再给出不泄露系统路径的说明。
  /// 参数说明：
  /// - `error`：授权、协议或本机入库失败。
  /// 返回：保留待续传密文，不伪装成复制成功。
  private func fail(_ error: Error) {
    let failedPhase = phase
    let system = error as NSError
    let allowedDomains = ["NSCocoaErrorDomain", "NSPOSIXErrorDomain", "NSOSStatusErrorDomain"]
    let domain =
      allowedDomains.contains(system.domain)
      ? system.domain
      : (error is VaultMigrationError ? "migration" : (error is VaultError ? "vault" : "other"))
    Self.logger.error(
      "Migration stopped role=\(self.role.rawValue, privacy: .public) phase=\(String(describing: failedPhase), privacy: .public) domain=\(domain, privacy: .public) code=\(system.code)"
    )
    stopNetwork()
    phase = .stopped
    if case VaultMigrationError.recovery = error {
      requiresRelock = true
    }
    if VaultMigrationError.isInsufficientSpace(error) {
      spaceAlert = "本机磁盘空间不足，已拒绝接收；来源原件和目标已有内容保留。"
    } else if case VaultMigrationError.peerInsufficientSpace = error {
      spaceAlert = "对方磁盘空间不足，已拒绝本次迁移。来源原件保留。"
    }
    let reason =
      (error as? VaultMigrationError)?.errorDescription
      ?? (error as? VaultError)?.errorDescription
      ?? "无法完成设备连接或内容校验，请重新配对；来源与目标原有内容保留。"
    let context: String
    switch failedPhase {
    case .connecting:
      context = "建立加密会话时："
    case .confirming:
      context = "核对号码时："
    case .awaitingPeer:
      context = "等待另一端确认时："
    case .authorizingTarget:
      context = "验证接收目录时："
    case .transferring:
      context = progress?.phase == .committing ? "校验并入库时：" : "复制内容时："
    default:
      context = ""
    }
    status = context + reason
  }

  /// 业务作用：统一停止监听、浏览、配对等待与用途能力，迟到事件不能恢复旧流程。
  /// 参数说明：无。
  /// 返回：网络与读取能力关闭，本机未完成密文保留供重新授权恢复。
  private func stopNetwork() {
    generation = UUID()
    expiry?.cancel()
    expiry = nil
    listener?.cancel()
    listener = nil
    browser?.cancel()
    browser = nil
    pipe?.cancel()
    pipe = nil
    #if os(macOS)
      remote?.cancel()
      remote = nil
    #endif
    source?.revoke()
    source = nil
    incoming?.revoke()
    incoming = nil
    receivingGrant?.revoke()
    receivingGrant = nil
    targetWorker?.cancel()
    targetWorker = nil
    let targetApproval = targetApproval
    self.targetApproval = nil
    targetApproval?.resume(throwing: VaultMigrationError.cancelled)
    targetFolder = nil
    targetError = nil
    targetAuthenticating = false
    let approval = approval
    self.approval = nil
    approval?.resume(throwing: VaultMigrationError.cancelled)
    runner?.cancel()
    runner = nil
    clearPairingCopy()
    pairingText = ""
    verification = ""
  }

  /// 业务作用：主动关闭或 App 锁定时撤销整个迁移页面的能力。
  /// 参数说明：无。
  /// 返回：旧连接、二维码与异步回调不可再次生效。
  func cancel() {
    cancelled = true
    stopNetwork()
    phase = .stopped
  }
}

/// 两端共用迁移页面，业务内容始终留在 EncVault 的受控界面。
struct VaultMigrationView: View {
  @ObservedObject var coordinator: VaultMigrationCoordinator
  @ObservedObject var model: VaultModel
  @State private var pairingInput = ""
  @State private var scanning = false

  /// 业务作用：展示配对、双端确认、进度与结果，关闭和锁定始终可撤销传输。
  /// 参数说明：无。
  /// 返回：明确区分发送与接收的迁移流程，不复用明文系统导出入口。
  var body: some View {
    NavigationStack {
      ScrollView {
        VStack(spacing: 18) {
          Text(coordinator.status).multilineTextAlignment(.center)
          if coordinator.phase == .waiting {
            if let image = qrImage {
              Image(decorative: image, scale: 1)
                .interpolation(.none).resizable().scaledToFit()
                .frame(width: 240, height: 240)
                .padding(12).background(.white).clipShape(RoundedRectangle(cornerRadius: 12))
                .accessibilityLabel("设备迁移配对二维码")
            }
            Button("复制配对信息") {
              coordinator.copyPairing()
            }
            if !coordinator.pending.isEmpty {
              Menu("继续未完成任务") {
                ForEach(coordinator.pending) {
                  task in
                  Button(task.title) {
                    coordinator.resume(task.id)
                  }
                }
              }
            }
            Divider()
            #if os(iOS)
              Button("扫描另一台设备的二维码") {
                scanning = true
              }
            #endif
            SecureField("或粘贴另一台设备的配对信息", text: $pairingInput)
              .textFieldStyle(.roundedBorder).autocorrectionDisabled()
            Button("使用配对信息连接") {
              let input = pairingInput
              pairingInput = ""
              coordinator.connect(input)
            }
            .disabled(pairingInput.isEmpty)
          } else if coordinator.phase == .authorizingTarget, let folder = coordinator.targetFolder {
            VaultMigrationTargetPassword(coordinator: coordinator, folder: folder)
              .id(folder.id)
          } else if coordinator.phase == .confirming {
            Text(coordinator.verification).font(
              .system(size: 42, weight: .semibold, design: .monospaced))
            Button("号码一致，继续") {
              coordinator.approve()
            }
            .buttonStyle(.borderedProminent)
          } else if coordinator.phase == .preparing || coordinator.phase == .finding
            || coordinator.phase == .connecting || coordinator.phase == .awaitingPeer
          {
            ProgressView()
          }
          if let value = coordinator.progress, coordinator.phase == .transferring {
            Text(value.name).lineLimit(2).truncationMode(.middle)
            if value.phase == .committing {
              ProgressView()
              Text("内容尚未完成入库，请保持两端在前台，等待显示复制完成。")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
            } else if value.totalBytes > 0 {
              ProgressView(value: Double(value.completedBytes), total: Double(value.totalBytes))
              Text("\(bytes(value.completedBytes)) / \(bytes(value.totalBytes))")
                .font(.caption).monospacedDigit()
              if value.phase == .content, coordinator.bytesPerSecond > 0 {
                Text(
                  "\(bytes(UInt64(coordinator.bytesPerSecond))) / 秒 · 预计剩余 \(remainingTime(Double(value.totalBytes - value.completedBytes) / coordinator.bytesPerSecond))"
                )
                .font(.caption).monospacedDigit()
              }
            } else {
              ProgressView()
            }
            Text("\(value.completedFiles) / \(value.totalFiles) 项").font(.caption)
          }
          Text("新迁入的保护文件夹初始密码为 123456，请接收后修改。已有同名目录合并时保留目标原密码。")
            .font(.caption).foregroundStyle(.secondary)
          Text("两端保持 EncVault 在前台。中断后重新配对，可继续未完成的发送；来源原件不会自动删除。")
            .font(.caption).foregroundStyle(.secondary)
        }
        .padding(24).frame(maxWidth: 520)
        .frame(maxWidth: .infinity)
      }
      .navigationTitle(coordinator.role == .send ? "发送加密内容" : "接收加密内容")
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button(
            coordinator.phase == .complete
              ? "完成" : (coordinator.phase == .transferring ? "停止迁移" : "关闭")
          ) {
            model.endMigration()
          }
        }
        ToolbarItem(placement: .primaryAction) {
          Menu {
            if model.rootEnabled {
              Button("关闭 ROOT 并停止迁移") {
                model.disableRootAccess()
              }
            }
            Button("锁定并停止迁移") {
              model.lock()
            }
          } label: {
            Image(systemName: "lock.shield")
          }
        }
      }
      .sheet(isPresented: $scanning) {
        VaultMigrationScanner {
          text in
          scanning = false
          coordinator.connect(text)
        }
      }
      .task {
        coordinator.start()
      }
      .alert(
        "磁盘空间不足",
        isPresented: Binding(
          get: {
            coordinator.spaceAlert != nil
          },
          set: {
            if !$0 {
              coordinator.dismissSpaceAlert()
            }
          }
        )
      ) {
        Button("确定") {
          coordinator.dismissSpaceAlert()
        }
      } message: {
        Text(coordinator.spaceAlert ?? "")
      }
      #if os(macOS)
        .frame(minWidth: 480, idealWidth: 560, minHeight: 640)
      #endif
    }
  }

  /// 业务作用：只在配对页面内渲染短期二维码，不写入相册或普通图片文件。
  /// 参数说明：无。
  /// 返回：当前配对信息的内存图像，非法或空信息不展示。
  private var qrImage: CGImage? {
    guard !coordinator.pairingText.isEmpty else {
      return nil
    }
    let filter = CIFilter.qrCodeGenerator()
    filter.message = Data(coordinator.pairingText.utf8)
    filter.correctionLevel = "M"
    guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 4, y: 4))
    else {
      return nil
    }
    return CIContext().createCGImage(output, from: output.extent)
  }

  /// 业务作用：以统一单位显示当前传输量，不记录历史进度。
  /// 参数说明：
  /// - `value`：当前已经处理或计划处理的字节数。
  /// 返回：适合页面显示的大小文本。
  private func bytes(_ value: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .file)
  }

  /// 业务作用：按本次近期有效吞吐量显示粗略剩余时间，不包含最后校验和提交耗时。
  /// 参数说明：
  /// - `seconds`：尚未处理字节按近期速率估算的秒数。
  /// 返回：适合进度页的小时、分钟或秒数，至少显示一秒。
  private func remainingTime(_ seconds: Double) -> String {
    let value = Int(min(Double(Int.max / 2), max(1, seconds.rounded(.up))))
    if value >= 3600 {
      return "\(value / 3600) 小时 \(value % 3600 / 60) 分钟"
    }
    if value >= 60 {
      return "\(value / 60) 分 \(value % 60) 秒"
    }
    return "\(value) 秒"
  }
}

/// 目标目录密码留在接收端的原生输入框，验证不改变来源密码或目标已有密码。
private struct VaultMigrationTargetPassword: View {
  @ObservedObject var coordinator: VaultMigrationCoordinator
  let folder: VaultMedia
  @StateObject private var password = FolderPasswordDraft()
  @Environment(\.scenePhase) private var scenePhase

  /// 业务作用：在同一接收页补齐目标目录授权，不中断已配对的迁移。
  /// 参数说明：无。
  /// 返回：只在本机验证的目录密码输入，提交、离开前台或关闭后立即清空。
  var body: some View {
    VStack(spacing: 14) {
      Text("接收目标：\(folder.originalFilename)").font(.headline)
      FolderPasswordFieldRow(
        title: "目标文件夹访问密码", draft: password,
        enabled: !coordinator.targetAuthenticating)
      if let error = coordinator.targetError {
        Text(error).foregroundStyle(.red).font(.callout)
      }
      Button("验证并继续迁移") {
        coordinator.authenticateTarget(password.take())
      }
      .buttonStyle(.borderedProminent)
      .disabled(password.isEmpty || coordinator.targetAuthenticating)
      if coordinator.targetAuthenticating {
        ProgressView()
      }
      Text("仅验证接收设备已有目录；不会把此密码发送给另一台设备。")
        .font(.caption).foregroundStyle(.secondary)
    }
    .onDisappear {
      password.clear()
    }
    .onChange(of: scenePhase) {
      _, phase in
      if phase != .active {
        password.clear()
      }
    }
  }
}

/// 相机只识别当前配对二维码，不录制、不拍照、不访问系统照片。
private final class VaultMigrationCapture: NSObject, AVCaptureMetadataOutputObjectsDelegate,
  @unchecked Sendable
{
  let session = AVCaptureSession()
  private let queue = DispatchQueue(label: "local.encvault.migration.qr")
  private let found: @Sendable (String) -> Void
  private let failed: @Sendable () -> Void
  private var configured = false
  private var delivered = false

  /// 业务作用：建立仅输出二维码字符串的相机适配器，不创建媒体文件输出。
  /// 参数说明：
  /// - `found`：识别到 EncVault 配对信息时交付。
  /// - `failed`：相机不可用时交付通用失败，不携带设备隐私信息。
  /// 返回：尚未打开相机的适配器。
  init(found: @escaping @Sendable (String) -> Void, failed: @escaping @Sendable () -> Void) {
    self.found = found
    self.failed = failed
  }

  /// 业务作用：在串行队列配置视频输入和二维码元数据输出，拒绝不可用相机。
  /// 参数说明：无。
  /// 返回：授权已由界面确认后开始实时识别，不申请麦克风权限。
  func start() {
    queue.async { [weak self] in
      guard let self else {
        return
      }
      do {
        if !self.configured {
          guard let device = AVCaptureDevice.default(for: .video) else {
            self.failed()
            return
          }
          let input = try AVCaptureDeviceInput(device: device)
          let output = AVCaptureMetadataOutput()
          self.session.beginConfiguration()
          guard self.session.canAddInput(input), self.session.canAddOutput(output) else {
            self.session.commitConfiguration()
            self.failed()
            return
          }
          self.session.addInput(input)
          self.session.addOutput(output)
          output.setMetadataObjectsDelegate(self, queue: self.queue)
          guard output.availableMetadataObjectTypes.contains(.qr) else {
            self.session.commitConfiguration()
            self.failed()
            return
          }
          output.metadataObjectTypes = [.qr]
          self.session.commitConfiguration()
          self.configured = true
        }
        self.delivered = false
        self.session.startRunning()
      } catch {
        self.failed()
      }
    }
  }

  /// 业务作用：关闭扫码页面后立即停止相机，不在后台继续识别。
  /// 参数说明：无。
  /// 返回：串行队列完成当前回调后释放相机使用。
  func stop() {
    queue.async { [weak self] in
      self?.session.stopRunning()
    }
  }

  /// 业务作用：只消费首个合法 EncVault 配对二维码，忽略其它二维码和迟到识别。
  /// 参数说明：
  /// - `output`：本次相机元数据输出。
  /// - `metadataObjects`：当前帧识别的二维码对象。
  /// - `connection`：系统提供的相机连接，不用于网络传输。
  /// 返回：合法字符串交付一次后停止识别，不保存原始画面。
  func metadataOutput(
    _ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject],
    from connection: AVCaptureConnection
  ) {
    guard !delivered else {
      return
    }
    for object in metadataObjects {
      guard let text = (object as? AVMetadataMachineReadableCodeObject)?.stringValue,
        text.hasPrefix("encvault-pair:"), text.utf8.count <= 2048
      else {
        continue
      }
      delivered = true
      found(text)
      stop()
      return
    }
  }
}

@MainActor
private final class VaultMigrationCameraModel: ObservableObject {
  @Published var message = "将二维码放入画面内"
  private var active = false
  private let found: (String) -> Void
  lazy var capture = VaultMigrationCapture(
    found: { [weak self] text in
      Task {
        @MainActor in
        guard let self, self.active else {
          return
        }
        self.active = false
        self.found(text)
      }
    },
    failed: { [weak self] in
      Task {
        @MainActor in
        self?.message = "相机不可用，也可以返回后粘贴配对信息。"
      }
    })

  /// 业务作用：将当前扫码结果限定在仍显示的配对页面。
  /// 参数说明：
  /// - `found`：本机页面接收配对字符串的回调。
  /// 返回：未请求相机权限的页面状态。
  init(found: @escaping (String) -> Void) {
    self.found = found
  }

  /// 业务作用：只有用户明确进入扫码时请求相机权限，取消页面后迟到授权不能开启相机。
  /// 参数说明：无。
  /// 返回：系统授权成功且页面仍活动时开始识别，否则提示本机权限设置。
  func start() async {
    active = true
    let status = AVCaptureDevice.authorizationStatus(for: .video)
    let allowed: Bool
    if status == .notDetermined {
      allowed = await AVCaptureDevice.requestAccess(for: .video)
    } else {
      allowed = status == .authorized
    }
    guard active else {
      return
    }
    if allowed {
      capture.start()
    } else {
      message = "请在系统设置中允许 EncVault 使用相机，或返回后粘贴配对信息。"
    }
  }

  /// 业务作用：扫码关闭时撤销当前页面交付权，停止相机。
  /// 参数说明：无。
  /// 返回：迟到的相机结果不再连接任何设备。
  func stop() {
    active = false
    capture.stop()
  }
}

private struct VaultMigrationScanner: View {
  @Environment(\.dismiss) private var dismiss
  @StateObject private var model: VaultMigrationCameraModel

  /// 业务作用：创建一次扫码页面，不跨多次配对复用相机结果。
  /// 参数说明：
  /// - `found`：当前迁移页面接收配对信息的动作。
  /// 返回：独立相机页面与关闭入口。
  init(found: @escaping (String) -> Void) {
    _model = StateObject(wrappedValue: VaultMigrationCameraModel(found: found))
  }

  /// 业务作用：实时展示扫码取景，不导出画面或写入相册。
  /// 参数说明：无。
  /// 返回：相机预览、权限状态和显式取消入口。
  var body: some View {
    NavigationStack {
      VStack(spacing: 12) {
        VaultMigrationCameraPreview(session: model.capture.session)
          .frame(minWidth: 280, minHeight: 300)
          .clipShape(RoundedRectangle(cornerRadius: 12))
        Text(model.message).font(.callout).multilineTextAlignment(.center)
      }
      .padding(20)
      .navigationTitle("扫描配对二维码")
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("取消") {
            dismiss()
          }
        }
      }
      .task {
        await model.start()
      }
      .onDisappear {
        model.stop()
      }
    }
    #if os(macOS)
      .frame(minWidth: 440, minHeight: 440)
    #endif
  }
}

#if os(macOS)
  private struct VaultMigrationCameraPreview: NSViewRepresentable {
    let session: AVCaptureSession

    /// 业务作用：将仅预览的视频层挂接到本机窗口，不创建录制输出。
    /// 参数说明：无。
    /// 返回：由当前扫码会话驱动的预览视图。
    func makeNSView(context: Context) -> MigrationPreviewNSView {
      MigrationPreviewNSView(session: session)
    }

    /// 业务作用：保持当前扫码预览层，不因界面刷新重复开启相机。
    /// 参数说明：无。
    /// 返回：相机配置由扫码生命周期统一管理。
    func updateNSView(_ nsView: MigrationPreviewNSView, context: Context) {}
  }

  private final class MigrationPreviewNSView: NSView {
    let preview: AVCaptureVideoPreviewLayer

    /// 业务作用：显示当前扫码相机，裁切仅用于取景显示。
    /// 参数说明：
    /// - `session`：已授权的二维码识别会话。
    /// 返回：不保存画面的原生视图。
    init(session: AVCaptureSession) {
      preview = AVCaptureVideoPreviewLayer(session: session)
      super.init(frame: .zero)
      wantsLayer = true
      preview.videoGravity = .resizeAspectFill
      layer?.addSublayer(preview)
    }

    /// 业务作用：拒绝恢复历史相机视图，扫码只能由本次页面创建。
    /// 参数说明：无。
    /// 返回：不从归档恢复。
    required init?(coder: NSCoder) {
      nil
    }

    /// 业务作用：让预览随窗口改变大小，不调整采集内容或开启额外输出。
    /// 参数说明：无。
    /// 返回：当前预览层覆盖取景视图。
    override func layout() {
      super.layout()
      preview.frame = bounds
    }
  }
#else
  private struct VaultMigrationCameraPreview: UIViewRepresentable {
    let session: AVCaptureSession

    /// 业务作用：将扫码预览挂接到手机页面，不生成相册项目。
    /// 参数说明：无。
    /// 返回：当前扫码会话的原生预览。
    func makeUIView(context: Context) -> MigrationPreviewUIView {
      MigrationPreviewUIView(session: session)
    }

    /// 业务作用：保留当前预览实例，避免界面刷新重复建立相机输入。
    /// 参数说明：无。
    /// 返回：相机会话由页面生命周期管理。
    func updateUIView(_ uiView: MigrationPreviewUIView, context: Context) {}
  }

  private final class MigrationPreviewUIView: UIView {
    /// 业务作用：以系统视频预览层显示扫码取景，不建立图像缓存。
    /// 参数说明：无。
    /// 返回：AVCaptureVideoPreviewLayer 的视图层类型。
    override class var layerClass: AnyClass {
      AVCaptureVideoPreviewLayer.self
    }

    /// 业务作用：挂接本次已授权的二维码相机会话。
    /// 参数说明：
    /// - `session`：只输出二维码元数据的相机采集会话。
    /// 返回：不拍照、不录制的取景视图。
    init(session: AVCaptureSession) {
      super.init(frame: .zero)
      let preview = layer as! AVCaptureVideoPreviewLayer
      preview.session = session
      preview.videoGravity = .resizeAspectFill
    }

    /// 业务作用：拒绝从历史归档恢复相机界面。
    /// 参数说明：无。
    /// 返回：只能通过本次扫码页面创建。
    required init?(coder: NSCoder) {
      nil
    }
  }
#endif
