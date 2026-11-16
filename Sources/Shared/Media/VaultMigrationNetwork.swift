import CryptoKit
import Foundation
import Network
import OSLog
import Security

enum VaultMigrationRole: String, Codable, Sendable {
  case send, receive
}

/// 一次性高熵配对只授权本次连接，不包含保险箱主密钥或任何密码。
struct VaultMigrationPairing: Codable, Sendable {
  let formatVersion: Int
  let id: UUID
  let role: VaultMigrationRole
  let secret: Data
  let expires: Date
  static let service = "_encvault._tcp"

  /// 业务作用：为主动打开的迁移页面创建短期配对身份和随机连接密钥。
  /// 参数说明：
  /// - `role`：当前页面发送或接收的方向。
  /// 返回：十分钟内可用于二维码配对的独立会话，不依赖 Apple ID。
  init(role: VaultMigrationRole) throws {
    formatVersion = 1
    id = UUID()
    self.role = role
    secret = try VaultCrypto.random(32)
    expires = Date().addingTimeInterval(600)
  }

  /// 业务作用：解析用户扫描或粘贴的配对信息，拒绝未知格式、弱密钥与已过期会话。
  /// 参数说明：
  /// - `text`：本次对端页面提供的完整配对字符串。
  /// 返回：经过边界检查的高熵配对描述，不把短验证码作为连接密钥。
  init(text: String) throws {
    let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
    let prefix = "encvault-pair:"
    guard text.utf8.count <= 2048, text.hasPrefix(prefix),
      let data = Data(base64Encoded: String(text.dropFirst(prefix.count)))
    else {
      throw VaultMigrationError.pairing
    }
    self = try JSONDecoder().decode(Self.self, from: data)
    guard formatVersion == 1, secret.count == 32 else {
      throw VaultMigrationError.pairing
    }
    guard expires > Date(), expires.timeIntervalSinceNow <= 900 else {
      throw VaultMigrationError.expired
    }
  }

  /// 业务作用：生成只供本次扫码或主动复制使用的配对字符串。
  /// 参数说明：无。
  /// 返回：不含文件名与保险箱凭据的短期配对内容。
  func text() throws -> String {
    "encvault-pair:" + (try VaultCrypto.encode(self)).base64EncodedString()
  }

  /// 业务作用：配置强制加密的点对点 TCP 连接，使用完整随机 PSK 而不是六位校验号码。
  /// 参数说明：无。
  /// 返回：只允许 TLS 1.2 AEAD PSK 的参数；旧 Network API 的 PSK 不支持 TLS 1.3。
  func parameters() -> NWParameters {
    let options = NWProtocolTLS.Options()
    sec_protocol_options_set_min_tls_protocol_version(options.securityProtocolOptions, .TLSv12)
    sec_protocol_options_set_max_tls_protocol_version(options.securityProtocolOptions, .TLSv12)
    sec_protocol_options_append_tls_ciphersuite(
      options.securityProtocolOptions,
      tls_ciphersuite_t(rawValue: UInt16(TLS_PSK_WITH_AES_128_GCM_SHA256))!)
    let identity = Data(id.uuidString.utf8)
    secret.withUnsafeBytes {
      secretBytes in
      identity.withUnsafeBytes {
        identityBytes in
        sec_protocol_options_add_pre_shared_key(
          options.securityProtocolOptions,
          DispatchData(bytes: secretBytes) as __DispatchData,
          DispatchData(bytes: identityBytes) as __DispatchData)
      }
    }
    sec_protocol_options_set_tls_pre_shared_key_identity_hint(
      options.securityProtocolOptions,
      identity.withUnsafeBytes {
        DispatchData(bytes: $0) as __DispatchData
      })
    let parameters = NWParameters(tls: options, tcp: NWProtocolTCP.Options())
    parameters.includePeerToPeer = true
    return parameters
  }
}

enum VaultMigrationFrame: UInt8, Sendable {
  case hello = 1
  case approve, offer, item, manifestEnd, prepared, request, chunk, fileEnd
  case commitRequest, commitGrant, complete, failure
  case failureAck
}

/// 有界帧封装在认证 TLS 连接中，单次只允许一个待发送或待接收分块。
final class VaultMigrationPipe: @unchecked Sendable {
  private let connection: NWConnection?
  #if os(macOS)
    private var remote: VaultMigrationRemote?
  #endif
  private let queue = DispatchQueue(label: "local.encvault.migration.connection")
  private let mutex = NSLock()
  private var active = true
  private var ready = false
  private var transportFailure: VaultMigrationError?
  private var starter: CheckedContinuation<Void, Error>?
  private var pendingTimeout: Task<Void, Never>?
  static let frameLimit = 1_048_576 + 65_536
  private static let logger = Logger(subsystem: "local.encvault", category: "MigrationTransport")

  /// 业务作用：为已配置 TLS 的连接建立独立串行回调队列。
  /// 参数说明：
  /// - `connection`：来自本次监听或已匹配 Bonjour 服务的连接。
  /// 返回：尚未开始传输任何保险箱数据的管道。
  init(_ connection: NWConnection) {
    self.connection = connection
  }

  #if os(macOS)
    /// 业务作用：使用独立沙箱网络服务，主应用不获得网络访问权限。
    /// 参数说明：
    /// - remote：当前已完成 TLS 认证的服务通道。
    /// 返回：业务端到端加密仍由主应用执行的有界管道。
    init(remote: VaultMigrationRemote) {
      connection = nil
      self.remote = remote
    }
  #endif

  /// 业务作用：等待 TLS 身份认证完成，超时、取消或握手失败均关闭连接。
  /// 参数说明：无。
  /// 返回：连接可用时成功，不以 TCP 建连代替加密认证。
  func start() async throws {
    #if os(macOS)
      if let remote {
        try remote.check()
        finishStart(success: true)
        return
      }
    #endif
    guard let connection else {
      throw VaultMigrationError.connection
    }
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        mutex.lock()
        guard active else {
          mutex.unlock()
          continuation.resume(throwing: VaultMigrationError.connection)
          return
        }
        starter = continuation
        mutex.unlock()
        connection.stateUpdateHandler = { [weak self] state in
          guard let self else {
            return
          }
          switch state {
          case .ready:
            self.finishStart(success: true)
          case .failed(let error):
            Self.logger.error("TLS state failed code=\((error as NSError).code)")
            self.mutex.lock()
            self.transportFailure = .transport((error as NSError).code)
            self.mutex.unlock()
            self.finishStart(success: false)
          case .cancelled:
            self.finishStart(success: false)
          default:
            break
          }
        }
        pendingTimeout = Task { [weak self] in
          do {
            try await Task.sleep(for: .seconds(20))
            self?.cancel()
          } catch {
          }
        }
        connection.start(queue: queue)
      }
    } onCancel: {
      self.cancel()
    }
  }

  /// 业务作用：以互斥状态只完成一次握手等待，拒绝迟到事件重新开放取消的连接。
  /// 参数说明：
  /// - `success`：系统是否已经完成安全握手。
  /// 返回：等待者只恢复一次，失败时管道不再交付数据。
  private func finishStart(success: Bool) {
    mutex.lock()
    let continuation = starter
    starter = nil
    ready = success && active
    let succeeded = ready
    let failure = transportFailure ?? .connection
    if !success {
      active = false
    }
    mutex.unlock()
    pendingTimeout?.cancel()
    if succeeded {
      continuation?.resume()
    } else {
      continuation?.resume(throwing: failure)
    }
  }

  /// 业务作用：在每次数据交付和最终提交前检查连接未被取消。
  /// 参数说明：无。
  /// 返回：当前 TLS 管道仍可用时成功，否则停止后续副作用。
  func check() throws {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    guard active && ready else {
      throw transportFailure ?? VaultMigrationError.connection
    }
    #if os(macOS)
      try remote?.check()
    #endif
  }

  /// 业务作用：发送带上限的单帧，等待系统消耗当前缓冲后才允许调用方产生下一个分块。
  /// 参数说明：
  /// - `kind`：协议当前阶段允许的帧类型。
  /// - `data`：当前控制记录或加密内容分块。
  /// 返回：缓冲已由网络栈接收；不代表对端已经保存或提交。
  func send(_ kind: VaultMigrationFrame, data: Data = Data()) async throws {
    try check()
    guard data.count + 1 <= Self.frameLimit else {
      throw VaultMigrationError.invalidManifest
    }
    var length = UInt32(data.count + 1).bigEndian
    var packet = withUnsafeBytes(of: &length) {
      Data($0)
    }
    packet.append(kind.rawValue)
    packet.append(data)
    let timeout = Task { [weak self] in
      do {
        try await Task.sleep(for: .seconds(300))
        self?.cancel()
      } catch {
      }
    }
    defer {
      timeout.cancel()
    }
    #if os(macOS)
      if let remote {
        try await remote.send(packet)
        return
      }
    #endif
    guard let connection else {
      throw VaultMigrationError.connection
    }
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        connection.send(
          content: packet,
          completion: .contentProcessed {
            error in
            if let error {
              Self.logger.error("TLS send failed code=\((error as NSError).code)")
              continuation.resume(throwing: VaultMigrationError.transport((error as NSError).code))
            } else {
              continuation.resume()
            }
          })
      }
    } onCancel: {
      self.cancel()
    }
  }

  /// 业务作用：编码有界控制结构后发送，不将本机完整元数据结构直接发往网络。
  /// 参数说明：
  /// - `kind`：控制帧类型。
  /// - `value`：已经经过白名单选择的协议结构。
  /// 返回：编码与发送成功；过长结构拒绝。
  func send<T: Encodable>(_ kind: VaultMigrationFrame, value: T) async throws {
    try await send(kind, data: VaultCrypto.encode(value))
  }

  /// 业务作用：精确读取一个有界帧，拒绝越界长度、未知阶段与提前结束。
  /// 参数说明：
  /// - `expected`：当前状态机唯一允许接收的帧类型。
  /// 返回：该帧的内容；对端失败帧只呈现通用说明，不反射外来路径或正文。
  func receive(_ expected: VaultMigrationFrame) async throws -> Data {
    let (kind, data) = try await receiveFrame()
    guard kind == expected else {
      throw VaultMigrationError.invalidManifest
    }
    return data
  }

  /// 业务作用：读取完整有界帧并保留真实类型，供业务认证同时绑定正常消息和拒绝原因。
  /// 参数说明：无。
  /// 返回：已知帧类型和完整字节；上层仍须核对当前阶段并认证密文。
  func receiveFrame() async throws -> (VaultMigrationFrame, Data) {
    let header = try await receiveBytes(4)
    let size = header.reduce(0) {
      ($0 << 8) | Int($1)
    }
    guard size > 0, size <= Self.frameLimit else {
      throw VaultMigrationError.invalidManifest
    }
    let bytes = try await receiveBytes(size)
    guard let raw = bytes.first, let kind = VaultMigrationFrame(rawValue: raw) else {
      throw VaultMigrationError.invalidManifest
    }
    return (kind, Data(bytes.dropFirst()))
  }

  /// 业务作用：读取并解码当前状态机预期的控制记录。
  /// 参数说明：
  /// - `expected`：允许的协议阶段。
  /// - `type`：该阶段的固定白名单结构。
  /// 返回：完整结构或明确失败，不猜测其它版本或协议。
  func receive<T: Decodable>(_ expected: VaultMigrationFrame, as type: T.Type) async throws -> T {
    try JSONDecoder().decode(type, from: await receive(expected))
  }

  /// 业务作用：按已验证的字段长度聚合网络分片，限制内存并在取消时释放等待。
  /// 参数说明：
  /// - `count`：已验证上限的本次字段长度。
  /// 返回：恰好指定长度的字节，EOF、失败或取消时不交付部分字段。
  private func receiveBytes(_ count: Int) async throws -> Data {
    try check()
    guard count > 0, count <= Self.frameLimit else {
      throw VaultMigrationError.invalidManifest
    }
    var result = Data()
    let timeout = Task { [weak self] in
      do {
        try await Task.sleep(for: .seconds(300))
        self?.cancel()
      } catch {
      }
    }
    defer {
      timeout.cancel()
    }
    while result.count < count {
      try Task.checkCancellation()
      let remaining = count - result.count
      #if os(macOS)
        if let remote {
          result.append(try await remote.receive(remaining))
          continue
        }
      #endif
      guard let connection else {
        throw VaultMigrationError.connection
      }
      let data: Data = try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation {
          continuation in
          // 正文长度已经受帧上限约束，聚合当前字段可避免每个 TLS 小片段触发一次任务唤醒。
          connection.receive(minimumIncompleteLength: remaining, maximumLength: remaining) {
            data, _, complete, error in
            if let error {
              Self.logger.error("TLS receive failed code=\((error as NSError).code)")
              continuation.resume(throwing: VaultMigrationError.transport((error as NSError).code))
            } else if let data, !data.isEmpty {
              continuation.resume(returning: data)
            } else if !complete {
              continuation.resume(returning: Data())
            } else {
              continuation.resume(throwing: VaultMigrationError.peerClosed)
            }
          }
        }
      } onCancel: {
        self.cancel()
      }
      result.append(data)
      if data.isEmpty {
        // 无正文的协议事件不等于对端关闭，继续等当前字段，整体超时仍约束等待。
        await Task.yield()
      }
    }
    return result
  }

  /// 业务作用：立即关闭当前管道及尚未完成的安全握手，不保留监听或内容交付能力。
  /// 参数说明：无。
  /// 返回：后续读写与提交检查拒绝；已提交的本机副本不受影响。
  func cancel() {
    mutex.lock()
    active = false
    ready = false
    let continuation = starter
    starter = nil
    mutex.unlock()
    pendingTimeout?.cancel()
    continuation?.resume(throwing: VaultMigrationError.connection)
    connection?.cancel()
    #if os(macOS)
      remote?.cancel()
    #endif
  }
}

private struct VaultMigrationHello: Codable {
  let formatVersion: Int
  let pairingID: UUID
  let role: VaultMigrationRole
  let nonce: Data
  let publicKey: Data
}

private struct VaultMigrationOffer: Codable {
  let formatVersion: Int
  let taskID: UUID
  let sourceVaultID: UUID
  let roots: [UUID]
  let count: Int
  let digest: Data
}

private struct VaultMigrationRequest: Codable {
  let id: UUID
  let offset: UInt64
}

private enum VaultMigrationRejection: String, Codable {
  case insufficientSpace
}

/// 进度只存在当前迁移页面，恢复记录保存内容清单而不保存查看或播放事件。
struct VaultMigrationProgress: Sendable {
  enum Phase: String, Sendable {
    case manifest = "正在核对目录"
    case content = "正在复制加密内容"
    case committing = "正在校验并提交"
  }
  let phase: Phase
  let name: String
  let completedBytes: UInt64
  let totalBytes: UInt64
  let completedFiles: Int
  let totalFiles: Int
  var transferredBytes: UInt64 = 0
}

/// TLS 内再用临时密钥协商保护业务帧，配对密钥以后泄露也不能单独还原旧传输内容。
// 每个方向只有一个顺序调用者；正文预取不能同时操作同一方向的认证计数器。
private final class VaultMigrationSecurePipe: @unchecked Sendable {
  let pipe: VaultMigrationPipe
  private let key: SymmetricKey
  private let transcript: Data
  private let sendingDirection: String
  private let receivingDirection: String
  private var sent: UInt64 = 0
  private var received: UInt64 = 0

  /// 业务作用：将临时协商密钥限定到当前握手与方向，拒绝帧重放和反射。
  /// 参数说明：
  /// - `pipe`：已经通过随机 PSK 认证的 TLS 管道。
  /// - `key`：仅本次临时密钥协商得到的业务密钥。
  /// - `transcript`：按监听端、连接端顺序认证的完整握手摘要。
  /// - `role`：本端的业务方向。
  /// 返回：不持久化会话密钥的业务封装。
  init(pipe: VaultMigrationPipe, key: SymmetricKey, transcript: Data, role: VaultMigrationRole) {
    self.pipe = pipe
    self.key = key
    self.transcript = transcript
    sendingDirection = role.rawValue
    receivingDirection =
      role == .send ? VaultMigrationRole.receive.rawValue : VaultMigrationRole.send.rawValue
  }

  /// 业务作用：加密当前状态机中的唯一下一帧，名称、摘要与正文均不以 TLS 内明文保存。
  /// 参数说明：
  /// - `kind`：业务阶段。
  /// - `data`：当前有界字段或分块。
  /// 返回：经过本次会话认证的帧已发送，计数器只单调增加。
  func send(_ kind: VaultMigrationFrame, data: Data) async throws {
    guard sent < UInt64.max else {
      throw VaultMigrationError.connection
    }
    let context = transcript + Data("/\(sendingDirection)/\(sent)/\(kind.rawValue)".utf8)
    let encrypted = try autoreleasepool {
      try VaultCrypto.seal(data, key: key, context: context)
    }
    sent += 1
    try await pipe.send(kind, data: encrypted)
  }

  /// 业务作用：将白名单控制结构编码进加密业务帧。
  /// 参数说明：
  /// - `kind`：当前阶段。
  /// - `value`：本阶段唯一允许的结构。
  /// 返回：控制结构已认证发送，不包含来源密码材料。
  func send<T: Encodable>(_ kind: VaultMigrationFrame, value: T) async throws {
    try await send(kind, data: VaultCrypto.encode(value))
  }

  /// 业务作用：认证当前方向和顺序的业务帧，不允许旧任务或其它阶段重放。
  /// 参数说明：
  /// - `kind`：期待的阶段。
  /// 返回：仅在本次认证会话内交付的字段或分块。
  func receive(_ kind: VaultMigrationFrame) async throws -> Data {
    guard received < UInt64.max else {
      throw VaultMigrationError.connection
    }
    let (actual, encrypted) = try await pipe.receiveFrame()
    guard actual == kind || actual == .failure else {
      throw VaultMigrationError.invalidManifest
    }
    let context = transcript + Data("/\(receivingDirection)/\(received)/\(actual.rawValue)".utf8)
    let data = try autoreleasepool {
      try VaultCrypto.open(encrypted, key: key, context: context)
    }
    received += 1
    if actual == .failure {
      let rejection = try JSONDecoder().decode(VaultMigrationRejection.self, from: data)
      try? await send(.failureAck, data: Data())
      switch rejection {
      case .insufficientSpace:
        throw VaultMigrationError.peerInsufficientSpace
      }
    }
    return data
  }

  /// 业务作用：解码已经通过会话认证的白名单控制结构。
  /// 参数说明：
  /// - `kind`：期待的业务阶段。
  /// - `type`：该阶段固定结构。
  /// 返回：结构完全匹配时成功，异常时关闭业务流程。
  func receive<T: Decodable>(_ kind: VaultMigrationFrame, as type: T.Type) async throws -> T {
    try JSONDecoder().decode(type, from: await receive(kind))
  }
}

/// 传输状态机不访问界面或系统相册，只处理已授权范围与本机加密候选。
enum VaultMigrationExchange {
  /// 业务作用：协商临时业务密钥并由双方核对号码，批准之前不交付任何保险箱清单。
  /// 参数说明：
  /// - `pipe`：本次 TLS 管道。
  /// - `pairing`：扫码绑定的高熵配对身份。
  /// - `role`：本端发送或接收方向。
  /// - `server`：本端是否为监听端，用于固定握手顺序。
  /// - `confirm`：在本机界面核对双方号码并明确批准。
  /// 返回：双方均批准的临时业务管道。
  private static func handshake(
    pipe: VaultMigrationPipe, pairing: VaultMigrationPairing, role: VaultMigrationRole,
    server: Bool,
    confirm: @Sendable (String) async throws -> Void
  ) async throws -> VaultMigrationSecurePipe {
    guard pairing.expires > Date() else {
      throw VaultMigrationError.expired
    }
    try await pipe.start()
    let privateKey = Curve25519.KeyAgreement.PrivateKey()
    let local = VaultMigrationHello(
      formatVersion: 1, pairingID: pairing.id, role: role,
      nonce: try VaultCrypto.random(32), publicKey: privateKey.publicKey.rawRepresentation)
    try await pipe.send(.hello, value: local)
    let remote = try await pipe.receive(.hello, as: VaultMigrationHello.self)
    guard remote.formatVersion == 1, remote.pairingID == pairing.id, remote.role != role,
      remote.nonce.count == 32, remote.publicKey.count == 32, remote.nonce != local.nonce
    else {
      throw VaultMigrationError.pairing
    }
    let transcript = Data(
      SHA256.hash(
        data:
          try VaultCrypto.encode(server ? local : remote)
          + VaultCrypto.encode(server ? remote : local)))
    let shared = try privateKey.sharedSecretFromKeyAgreement(
      with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: remote.publicKey))
    let salt = Data(
      HMAC<SHA256>.authenticationCode(
        for: transcript, using: SymmetricKey(data: pairing.secret)))
    let key = shared.hkdfDerivedSymmetricKey(
      using: SHA256.self, salt: salt, sharedInfo: Data("EncVault/migration/session".utf8),
      outputByteCount: 32)
    let proof = Data(HMAC<SHA256>.authenticationCode(for: transcript, using: key))
    let number =
      proof.prefix(4).reduce(UInt32(0)) {
        ($0 << 8) | UInt32($1)
      } % 1_000_000
    try await confirm(String(format: "%06u", number))
    guard pairing.expires > Date() else {
      throw VaultMigrationError.expired
    }
    try await pipe.send(.approve, data: proof)
    guard try await pipe.receive(.approve) == proof else {
      throw VaultMigrationError.pairing
    }
    return VaultMigrationSecurePipe(pipe: pipe, key: key, transcript: transcript, role: role)
  }

  /// 业务作用：仅发送当前所选内容的加密业务帧，接收端持久确认后才结束待续传记录。
  /// 参数说明：
  /// - `source`：持续受来源 ROOT 与 App 会话约束的用途能力。
  /// - `pipe`：本次 TLS 管道。
  /// - `pairing`：经过扫码或主动粘贴的配对身份。
  /// - `server`：本端是否为监听端。
  /// - `confirm`：双方核对验证号码的交互。
  /// - `progress`：有界进度交付，不写访问历史。
  /// 返回：接收端已经持久提交的收据，任何失败均不删除来源媒体。
  static func send(
    source: VaultMigrationSource, pipe: VaultMigrationPipe, pairing: VaultMigrationPairing,
    server: Bool,
    confirm: @Sendable (String) async throws -> Void,
    progress: @Sendable (VaultMigrationProgress) async -> Void
  ) async throws -> VaultMigrationReceipt {
    let secure = try await handshake(
      pipe: pipe, pairing: pairing, role: .send, server: server, confirm: confirm)
    await progress(
      VaultMigrationProgress(
        phase: .manifest, name: "正在核对迁移清单", completedBytes: 0, totalBytes: 0,
        completedFiles: 0, totalFiles: 0))
    try source.check()
    try source.savePending()
    let manifest = source.manifest
    let digest = try manifest.digest()
    try await secure.send(
      .offer,
      value: VaultMigrationOffer(
        formatVersion: 1, taskID: manifest.taskID, sourceVaultID: manifest.sourceVaultID,
        roots: manifest.roots, count: manifest.items.count, digest: digest))
    for item in manifest.items {
      try source.check()
      try await secure.send(.item, value: item)
    }
    try await secure.send(.manifestEnd, data: digest)
    let initial = try await secure.receive(.prepared, as: Bool.self)
    if !initial {
      let receipt = try await secure.receive(.complete, as: VaultMigrationReceipt.self)
      guard receipt.taskID == manifest.taskID, receipt.manifestDigest == digest else {
        throw VaultMigrationError.invalidManifest
      }
      try source.finishPending()
      return receipt
    }
    var bytes: UInt64 = 0
    var transferred: UInt64 = 0
    var files = 0
    let total = manifest.items.reduce(UInt64(0)) {
      $0 + $1.byteCount
    }
    let totalFiles = manifest.items.filter {
      !$0.shape.isFolder
    }.count
    for item in manifest.items {
      try source.check()
      let request = try await secure.receive(.request, as: VaultMigrationRequest.self)
      guard request.id == item.id, request.offset <= item.byteCount,
        request.offset == item.byteCount || request.offset % UInt64(VaultMediaReader.chunkSize) == 0
      else {
        throw VaultMigrationError.invalidManifest
      }
      var offset = request.offset
      if offset < item.byteCount {
        let reader = try source.reader(id: item.id)
        var buffered: Data? = try reader.read(offset: offset, count: VaultMediaReader.chunkSize)
        while let data = buffered {
          try source.check()
          // 只预取下一块，读盘解密与当前块的会话加密、网络背压重叠；不积压整文件明文。
          async let sending: Void = sendChunk(data, source: source, secure: secure)
          let nextOffset = offset + UInt64(data.count)
          let next: Data? = try autoreleasepool {
            nextOffset < item.byteCount
              ? try reader.read(offset: nextOffset, count: VaultMediaReader.chunkSize) : nil
          }
          try await sending
          offset = nextOffset
          transferred += UInt64(data.count)
          await progress(
            VaultMigrationProgress(
              phase: .content, name: item.name, completedBytes: bytes + offset, totalBytes: total,
              completedFiles: files, totalFiles: totalFiles, transferredBytes: transferred))
          buffered = next
        }
      }
      try source.check()
      try await secure.send(
        .fileEnd, value: VaultMigrationRequest(id: item.id, offset: item.byteCount))
      bytes += item.byteCount
      if !item.shape.isFolder {
        files += 1
      }
    }
    await progress(
      VaultMigrationProgress(
        phase: .committing, name: "正在等待接收设备校验并入库", completedBytes: total,
        totalBytes: total, completedFiles: files, totalFiles: totalFiles,
        transferredBytes: transferred))
    guard try await secure.receive(.commitRequest) == digest else {
      throw VaultMigrationError.invalidManifest
    }
    try source.verifySnapshot()
    try await secure.send(.commitGrant, data: digest)
    // 等待接收端提交期间持续复验来源权威；关闭 ROOT 或锁定会撤销该连接的后续授权。
    let watcher = Task {
      do {
        while !Task.isCancelled {
          try source.check()
          try await Task.sleep(for: .milliseconds(100))
        }
      } catch {
        if !Task.isCancelled {
          pipe.cancel()
        }
      }
    }
    defer {
      watcher.cancel()
    }
    let receipt = try await secure.receive(.complete, as: VaultMigrationReceipt.self)
    guard receipt.taskID == manifest.taskID, receipt.manifestDigest == digest,
      receipt.files == totalFiles
    else {
      throw VaultMigrationError.invalidManifest
    }
    try source.finishPending()
    return receipt
  }

  /// 业务作用：预取流水线在实际交付当前块前复验来源权威，保持会话帧的顺序与背压。
  /// 参数说明：
  /// - `data`：已读取的单个有界内容分块。
  /// - `source`：持续受 App 会话与 ROOT 激活身份约束的来源。
  /// - `secure`：当前方向仅允许一个发送者的认证管道。
  /// 返回：当前块已发送；失权、取消或网络失败时停止后续交付。
  private static func sendChunk(
    _ data: Data, source: VaultMigrationSource, secure: VaultMigrationSecurePipe
  ) async throws {
    try source.check()
    try await secure.send(.chunk, data: data)
  }

  /// 业务作用：把认证配对交付的选定内容直接写入本机密文候选，整批验证后再提交。
  /// 参数说明：
  /// - `pipe`：本次 TLS 管道。
  /// - `pairing`：已绑定的高熵配对身份。
  /// - `server`：本端是否为监听端。
  /// - `confirm`：双方核对号码的本机交互。
  /// - `prepare`：按本机用户选择的目录和会话创建接收事务。
  /// - `progress`：只更新当前界面的有界进度。
  /// 返回：已经持久提交的本机收据；失败保留可恢复密文，不发布部分目录。
  static func receive(
    pipe: VaultMigrationPipe, pairing: VaultMigrationPairing, server: Bool,
    confirm: @Sendable (String) async throws -> Void,
    prepare: @Sendable (VaultMigrationManifest) async throws -> VaultMigrationIncoming,
    progress: @Sendable (VaultMigrationProgress) async -> Void
  ) async throws -> VaultMigrationReceipt {
    let secure = try await handshake(
      pipe: pipe, pairing: pairing, role: .receive, server: server, confirm: confirm)
    await progress(
      VaultMigrationProgress(
        phase: .manifest, name: "正在核对迁移清单", completedBytes: 0, totalBytes: 0,
        completedFiles: 0, totalFiles: 0))
    let offer = try await secure.receive(.offer, as: VaultMigrationOffer.self)
    guard offer.formatVersion == 1, offer.count > 0, offer.count <= 100_000,
      offer.roots.count <= offer.count, offer.digest.count == 32
    else {
      throw VaultMigrationError.invalidManifest
    }
    var items: [VaultMigrationItem] = []
    var metadataBytes = 0
    for number in 0..<offer.count {
      let data = try await secure.receive(.item)
      metadataBytes += data.count
      guard data.count <= 65_536, metadataBytes <= 64 * 1024 * 1024 else {
        throw VaultMigrationError.invalidManifest
      }
      items.append(try JSONDecoder().decode(VaultMigrationItem.self, from: data))
      if number % 100 == 0 {
        await progress(
          VaultMigrationProgress(
            phase: .manifest, name: "正在认证所选目录", completedBytes: 0, totalBytes: 0,
            completedFiles: number, totalFiles: offer.count))
      }
    }
    let manifest = VaultMigrationManifest(
      formatVersion: offer.formatVersion, taskID: offer.taskID, sourceVaultID: offer.sourceVaultID,
      roots: offer.roots, items: items)
    try manifest.validate()
    guard try manifest.digest() == offer.digest,
      try await secure.receive(.manifestEnd) == offer.digest
    else {
      throw VaultMigrationError.invalidManifest
    }
    let incoming: VaultMigrationIncoming
    do {
      incoming = try await prepare(manifest)
    } catch {
      guard VaultMigrationError.isInsufficientSpace(error) else {
        throw error
      }
      // 拒绝在任何正文请求之前交付，并等待对端收到原因，不能只关闭连接让发送方误报断网。
      try await secure.send(.failure, value: VaultMigrationRejection.insufficientSpace)
      let timeout = Task {
        do {
          try await Task.sleep(for: .seconds(5))
          pipe.cancel()
        } catch {
        }
      }
      defer {
        timeout.cancel()
      }
      _ = try? await secure.receive(.failureAck)
      throw VaultMigrationError.insufficientSpace
    }
    if let receipt = incoming.existingReceipt {
      try await secure.send(.prepared, value: false)
      try await secure.send(.complete, value: receipt)
      return receipt
    }
    try await secure.send(.prepared, value: true)
    var bytes: UInt64 = 0
    var transferred: UInt64 = 0
    var files = 0
    var total: UInt64 = 0
    for item in items {
      let sum = total.addingReportingOverflow(item.byteCount)
      guard !sum.overflow else {
        throw VaultMigrationError.invalidManifest
      }
      total = sum.partialValue
    }
    let totalFiles = items.filter {
      !$0.shape.isFolder
    }.count
    for item in items {
      try incoming.check()
      let complete = try incoming.isComplete(item.id)
      let writer = try complete ? nil : incoming.writer(item.id)
      var offset = writer?.count ?? item.byteCount
      try await secure.send(.request, value: VaultMigrationRequest(id: item.id, offset: offset))
      var buffered: Data? = offset < item.byteCount ? try await secure.receive(.chunk) : nil
      while let data = buffered {
        guard data.count == Int(min(UInt64(VaultMediaReader.chunkSize), item.byteCount - offset))
        else {
          throw VaultMigrationError.invalidManifest
        }
        let nextOffset = offset + UInt64(data.count)
        // 下一块的接收认证与当前块的本机加密写入重叠；同一文件仍按顺序写，保留 nonce 与续传边界。
        async let next: Data? = nextOffset < item.byteCount ? secure.receive(.chunk) : nil
        try incoming.check()
        guard let writer else {
          throw VaultMigrationError.invalidManifest
        }
        try autoreleasepool {
          try writer.append(data)
        }
        offset = nextOffset
        transferred += UInt64(data.count)
        await progress(
          VaultMigrationProgress(
            phase: .content, name: item.name, completedBytes: bytes + offset, totalBytes: total,
            completedFiles: files, totalFiles: totalFiles, transferredBytes: transferred))
        buffered = try await next
      }
      let end = try await secure.receive(.fileEnd, as: VaultMigrationRequest.self)
      guard end.id == item.id, end.offset == item.byteCount else {
        throw VaultMigrationError.invalidManifest
      }
      try incoming.check()
      try writer?.finish()
      bytes += item.byteCount
      if !item.shape.isFolder {
        files += 1
      }
    }
    await progress(
      VaultMigrationProgress(
        phase: .committing, name: "正在完整校验并提交", completedBytes: total, totalBytes: total,
        completedFiles: files, totalFiles: totalFiles))
    try await secure.send(.commitRequest, data: offer.digest)
    guard try await secure.receive(.commitGrant) == offer.digest else {
      throw VaultMigrationError.invalidManifest
    }
    let receipt = try incoming.commit {
      try pipe.check()
    }
    try await secure.send(.complete, value: receipt)
    return receipt
  }
}
