import Combine
import Foundation
import PhotosUI
import SwiftUI

#if os(macOS)
  import AppKit
  typealias VaultImage = NSImage
#else
  import UIKit
  typealias VaultImage = UIImage
#endif

/// 两种系统保存入口均保留原件，受保护内容的复制与导出采用不同目录规则。
enum SystemSaveAction: String, CaseIterable, Sendable {
  case copy = "复制"
  case export = "导出"

  /// 业务作用：为系统保存确认页与菜单提供一致的操作名称。
  /// 参数说明：无。
  /// 返回：当前用户选择的解密复制或解密导出标题。
  var title: String {
    "解密\(rawValue)到系统"
  }
}

/// 后台导入只覆盖最新进度，前台定时读取，不能为每个分块无限排队界面任务。
private final class ImportProgressBuffer: @unchecked Sendable {
  private let mutex = NSLock()
  private var latest: ImportProgress?

  /// 业务作用：用当前阶段替换旧快照，使生产速度不受界面刷新速度影响。
  /// 参数说明：
  /// - `update`：当前文件阶段及累计完成数量。
  /// 返回：只保留一个内存快照，不调度主线程任务或写入磁盘。
  func publish(_ update: ImportProgress) {
    mutex.lock()
    latest = update
    mutex.unlock()
  }

  /// 业务作用：让前台按固定频率取得最新阶段，避免保存过期的分块事件。
  /// 参数说明：无。
  /// 返回：当前内存快照；尚无进度时为空。
  func snapshot() -> ImportProgress? {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    return latest
  }
}

/// 当前前台界面的状态；媒体选择和播放状态只保存在该实例的内存中。
@MainActor
final class VaultModel: ObservableObject {
  enum Screen {
    case setup, locked, library, unavailable
  }

  struct FolderPrompt: Identifiable, Sendable {
    enum Kind: Sendable {
      case access, setting, removing, copy, move, rename
    }
    let id: UUID
    let challengeID = UUID()
    let folder: VaultMedia
    let kind: Kind
  }

  struct MoveSelection: Identifiable {
    let id = UUID()
    let media: [VaultMedia]
  }

  private enum CopyDestination: Sendable {
    case directory(URL)
    case photos
  }

  private struct PendingCopy: Sendable {
    let media: VaultMedia
    let destination: CopyDestination
    let session: VaultCopySession
  }

  private struct InternalDrag {
    let token: UUID
    let mediaID: UUID
    let parentID: UUID?
  }

  private enum FolderAction: Sendable {
    case enter(VaultMedia)
    case delete(VaultMedia)
    case export(VaultMedia, URL)
    case move([VaultMedia], UUID?)
    case movePath([VaultMedia], String)
    case rename(VaultMedia, String)

    /// 业务作用：取得本次明确操作的来源快照，批量移动不从最近选择推断项目。
    /// 参数说明：无。
    /// 返回：用户明确选择的认证条目列表，单项动作也以单元素列表表示。
    var sources: [VaultMedia] {
      switch self {
      case .enter(let media), .delete(let media), .export(let media, _), .rename(let media, _):
        return [media]
      case .move(let media, _), .movePath(let media, _):
        return media
      }
    }

    /// 业务作用：识别需要统一结束目标验证与显示移动错误的动作。
    /// 参数说明：无。
    /// 返回：单项或批量移动时为真，其它目录动作不受此错误呈现规则影响。
    var isMove: Bool {
      switch self {
      case .move, .movePath:
        return true
      default:
        return false
      }
    }
  }

  private struct FolderActionResult: Sendable {
    let prompt: VaultMedia?
    let folderID: UUID?
    let items: [VaultMedia]
    let message: String?
    var replacement: VaultGrant? = nil
    var moveFailure: String? = nil
  }

  @Published var screen: Screen = .unavailable
  @Published var kind: CredentialKind = .pin
  @Published var items: [VaultMedia] = []
  @Published private(set) var currentFolderID: UUID? {
    didSet {
      if oldValue != currentFolderID {
        internalDrag = nil
        endSelection()
        // 导航离开后同时撤销目录能力和缓存，旧读取器与迟到缩略图不能继续交付内容。
        grant?.retainFolderAccess(currentFolderPathIDs)
        clearThumbnails()
      }
    }
  }
  @Published var folderPrompt: FolderPrompt?
  @Published var movingMedia: MoveSelection?
  @Published private(set) var selecting = false
  @Published private(set) var selectedIDs: Set<UUID> = []
  @Published var moveFailure: String?
  private var pendingFolderAction: FolderAction?
  private var pendingCopy: PendingCopy?
  @Published private var internalDrag: InternalDrag?
  @Published var busy = false {
    didSet {
      if busy {
        internalDrag = nil
      }
    }
  }
  @Published var progress: Double = 0
  @Published private(set) var importProgress: ImportProgress?
  @Published private(set) var importing = false
  @Published private(set) var moving = false
  private var importProgressTask: Task<Void, Never>?
  @Published var message: String?
  @Published var photoImportFailure: String?
  @Published var offer: EnrollmentOffer?
  @Published var selected: VaultMedia?
  @Published var image: VaultImage?
  @Published var playback: LocalPlayback?
  @Published private(set) var document: VaultDocument?
  @Published var requestingTextEdit = false
  struct AutomaticLockRequest: Identifiable {
    let id = UUID()
  }
  @Published private(set) var automaticLockRequest: AutomaticLockRequest?
  @Published private(set) var editingText: String?
  private var textEdit: VaultTextEdit?
  @Published private(set) var thumbnails: [UUID: VaultImage] = [:]
  @Published private(set) var credentialStatus: CredentialLockoutStatus?
  @Published var savedSources: [SavedImport] = []
  @Published var savedPhotos: [SavedPhotoImport] = []
  private(set) var store: VaultStore?
  private var library: VaultLibrary?
  private var photos: PhotoVaultService?
  private var grant: VaultGrant?
  private var operation: Task<Void, Never>?
  private var epoch: UInt64 = 0
  private var thumbnailJobs: [VaultMedia] = []
  private var thumbnailOrder: [UUID] = []
  private var thumbnailWorker: Task<Void, Never>?
  private var thumbnailInFlight: VaultMedia?
  private var thumbnailGeneration: UInt64 = 0
  private var thumbnailFailures: [UUID: Data] = [:]

  /// 业务作用：执行两端的切换锁定偏好，Mac 导入或移动期间仅临时豁免。
  /// 参数说明：无。
  /// 返回：是否应在失去前台时锁定；iPhone 不因导入自动豁免，遵循用户验证后的偏好。
  var shouldLockWhenInactive: Bool {
    #if os(macOS)
      return VaultWindowPolicy.lockWhenInactive && !importing && !moving
    #else
      return VaultWindowPolicy.lockWhenInactive
    #endif
  }

  /// 业务作用：开启切换锁定直接生效，关闭则创建本次独立的 App 凭据验证请求。
  /// 参数说明：
  /// - `enabled`：用户在设置中选择的切换应用锁定状态。
  /// 返回：开启立即保存；关闭验证前保持开启，已关闭或会话不可用时不开放验证。
  func setAutomaticLock(_ enabled: Bool) {
    guard !busy, screen == .library else {
      return
    }
    message = nil
    if enabled {
      automaticLockRequest = nil
      UserDefaults.standard.set(true, forKey: VaultWindowPolicy.lockWhenInactiveKey)
    } else if VaultWindowPolicy.lockWhenInactive, automaticLockRequest == nil {
      automaticLockRequest = AutomaticLockRequest()
    }
  }

  /// 业务作用：取消本次关闭自动锁定的请求，不改变现有锁定策略。
  /// 参数说明：无。
  /// 返回：请求身份失效，迟到验证不能用于后续请求。
  func cancelAutomaticLockRequest() {
    automaticLockRequest = nil
    message = nil
  }

  /// 业务作用：仅在当前请求的 App 密码或手势重新验证成功后关闭切换锁定。
  /// 参数说明：
  /// - `credential`：本次输入的 App 独立凭据，不接受文件夹或系统密码。
  /// - `requestID`：当前设置表单身份，防止旧表单向新请求提交。
  /// 返回：认证失败、取消或会话失权均保持原策略；成功只消费本次关闭请求。
  func authenticateAutomaticLock(_ credential: VaultCredential, requestID: UUID) {
    guard !busy, screen == .library, automaticLockRequest?.id == requestID,
      VaultWindowPolicy.lockWhenInactive, let store, let grant
    else {
      return
    }
    perform(
      {
        try store.verifyCredential(credential, using: grant)
      },
      success: { [weak self] in
        guard let self, self.screen == .library,
          self.automaticLockRequest?.id == requestID, (try? grant.check()) != nil
        else {
          return
        }
        // 只有仍属当前会话的独立验证可以降低保护强度，取消或切换后的结果不能落盘。
        UserDefaults.standard.set(false, forKey: VaultWindowPolicy.lockWhenInactiveKey)
        self.automaticLockRequest = nil
        self.refreshCredentialStatus()
      })
  }

  /// 业务作用：开始有界进度消费，并临时暂停与导入无关的缩略图解码。
  /// 参数说明：无。
  /// 返回：本次后台任务可发布的单槽进度缓冲；Mac 的临时锁定豁免仅保存在内存。
  private func beginImport() -> ImportProgressBuffer {
    importProgressTask?.cancel()
    importing = true
    importProgress = nil
    clearThumbnails()
    let buffer = ImportProgressBuffer()
    let expected = epoch
    importProgressTask = Task { [weak self] in
      while !Task.isCancelled {
        do {
          try await Task.sleep(for: .milliseconds(100))
        } catch {
          return
        }
        guard let self, self.epoch == expected, self.importing, self.busy else {
          return
        }
        if let update = buffer.snapshot() {
          self.importProgress = update
          self.progress = update.fraction ?? 0
        }
      }
    }
    return buffer
  }

  /// 业务作用：导入结束立即撤销临时切换豁免，不能把解锁窗口留在后台。
  /// 参数说明：无。
  /// 返回：停止进度任务并恢复原锁定策略；Mac 已处后台且原策略开启时立即锁定。
  private func finishImport() {
    guard importing else {
      return
    }
    importing = false
    importProgressTask?.cancel()
    importProgressTask = nil
    importProgress = nil
    #if os(macOS)
      // 偏好开关始终保持原值；后台完成时补执行锁定，避免豁免期间错过失焦通知。
      if VaultWindowPolicy.lockWhenInactive, !NSApplication.shared.isActive {
        lock()
      }
    #endif
  }

  /// 业务作用：移动任务结束时撤销临时切换豁免，后台完成也必须恢复原有锁定策略。
  /// 参数说明：无。
  /// 返回：内存移动标记清空；原策略开启且应用在后台时立即撤销会话。
  private func finishMoving() {
    guard moving else {
      return
    }
    moving = false
    #if os(macOS)
      // 偏好不随任务改写，后台完成后补执行锁定，避免豁免期间错过失焦事件。
      if VaultWindowPolicy.lockWhenInactive, !NSApplication.shared.isActive {
        lock()
      }
    #endif
  }
  #if os(iOS)
    private var foregroundProtection: VaultForegroundProtection?
  #endif

  /// 业务作用：仅展示当前目录的直接子项，目录身份和层级只存在于解锁后的内存中。
  /// 参数说明：无。
  /// 返回：文件夹在前、各组按原名排序的当前层级条目；文档包归入文件，根目录不混入子目录内容。
  var visibleItems: [VaultMedia] {
    items.filter {
      $0.parentID == currentFolderID
    }.sorted {
      let leftFolder = $0.isFolder && !$0.isDocument
      let rightFolder = $1.isFolder && !$1.isDocument
      if leftFolder != rightFolder {
        return leftFolder
      }
      let order = $0.originalFilename.localizedStandardCompare($1.originalFilename)
      if order == .orderedSame {
        return $0.id.uuidString < $1.id.uuidString
      }
      return order == .orderedAscending
    }
  }

  /// 业务作用：只让同一目录内的图片和视频进入相册连续浏览，过滤普通文件及目录。
  /// 参数说明：无。
  /// 返回：当前目录内已经识别为图片或视频的条目；普通文件使用独立的管理页面。
  var browsingItems: [VaultMedia] {
    visibleItems.filter {
      $0.isImage || $0.isVideo
    }
  }

  /// 业务作用：在目录导航中显示当前认证原名，不从磁盘明文路径取得名称。
  /// 参数说明：无。
  /// 返回：当前目录原名，根目录为空。
  var currentFolder: VaultMedia? {
    items.first {
      $0.id == currentFolderID
    }
  }

  /// 业务作用：只保留当前目录及祖先路径的授权，离开后不记住可直接复用的目录密码权限。
  /// 参数说明：无。
  /// 返回：当前路径的目录身份集合，根目录为空。
  private var currentFolderPathIDs: Set<UUID> {
    var ids: Set<UUID> = []
    var next = currentFolderID
    while let id = next, ids.count < 256, ids.insert(id).inserted {
      next = items.first(where: { $0.id == id })?.parentID
    }
    return ids
  }

  /// 业务作用：返回加密目录的上一层，不创建访问记录。
  /// 参数说明：无。
  /// 返回：空闲时切换到父目录，当前浏览状态清空。
  func leaveFolder() {
    guard !busy, screen == .library else {
      return
    }
    closeViewer()
    currentFolderID = currentFolder?.parentID
    refresh()
  }

  /// 业务作用：按当前认证目录关系判断条目是否位于指定目录树中，异常关系按不可用处理。
  /// 参数说明：
  /// - `media`：当前已认证条目。
  /// 返回：包括自身的已知祖先路径，缺失或循环关系为空。
  private func path(for media: VaultMedia) -> [VaultMedia] {
    var result = [
      items.first(where: {
        $0.id == media.id
      }) ?? media
    ]
    var seen: Set<UUID> = [media.id]
    while let parentID = result.last?.parentID {
      guard result.count < 256, seen.insert(parentID).inserted,
        let parent = items.first(where: {
          $0.id == parentID
        })
      else {
        return []
      }
      result.append(parent)
    }
    return result
  }

  /// 业务作用：在独立密码输入中标明当前已知目录路径，便于区分不同位置的同名目录。
  /// 参数说明：
  /// - `folder`：当前密码请求明确对应的目录。
  /// 返回：完整的已知保险箱路径；祖先尚不可见时为空，不猜测或展示错误路径。
  func folderPathLabel(_ folder: VaultMedia) -> String? {
    let ancestors = path(for: folder)
    guard !ancestors.isEmpty else {
      return nil
    }
    return "/" + ancestors.reversed().map(\.originalFilename).joined(separator: "/")
  }

  /// 业务作用：阻止菜单向受密码保护的来源目录树开放删除或移动。
  /// 参数说明：
  /// - `media`：用户当前选中的来源。
  /// 返回：来源自身或已认证子树中含密码目录时为真。
  func containsProtectedFolder(_ media: VaultMedia) -> Bool {
    let current =
      items.first(where: {
        $0.id == media.id
      }) ?? media
    return current.folderPassword != nil
      || (current.isFolder
        && items.contains { item in
          item.folderPassword != nil
            && path(for: item).contains(where: {
              $0.id == media.id
            })
        })
  }

  /// 业务作用：在导出菜单检查祖先及子目录保护，复制另经独立的单次密码验证。
  /// 参数说明：
  /// - `media`：待导出的条目。
  /// 返回：路径未知或涉及任一受保护目录时禁止原有导出操作。
  func exportRestricted(_ media: VaultMedia) -> Bool {
    let ancestors = path(for: media)
    return ancestors.isEmpty
      || ancestors.contains {
        $0.folderPassword != nil
      }
      || containsProtectedFolder(media)
  }

  /// 业务作用：提供符合层级和保护范围限制的移动目标，提交时仍复验同名冲突。
  /// 参数说明：
  /// - `media`：当前准备移动的条目。
  /// 返回：当前可见的目标目录身份及路径，根目录用空身份表示；受保护目标仍需独立验证。
  func moveDestinations(for media: VaultMedia) -> [(id: UUID?, title: String)] {
    let sourceProtection = Set(
      path(for: media).dropFirst().filter {
        $0.folderPassword != nil
      }.map(\.id))
    var result: [(id: UUID?, title: String)] = []
    if media.parentID != nil && sourceProtection.isEmpty {
      result.append((nil, "保险箱根目录"))
    }
    for folder in items.filter({
      $0.isFolder && !$0.isDocument
    }).sorted(by: {
      $0.originalFilename.localizedStandardCompare($1.originalFilename) == .orderedAscending
    }) {
      let ancestors = path(for: folder)
      guard folder.id != media.parentID, !ancestors.isEmpty,
        !ancestors.contains(where: {
          $0.id == media.id
        }),
        sourceProtection.isSubset(of: Set(ancestors.map(\.id)))
      else {
        continue
      }
      result.append(
        (folder.id, ancestors.reversed().map(\.originalFilename).joined(separator: " / ")))
    }
    return result
  }

  /// 业务作用：取得当前目录勾选的真实条目，忽略已离开列表的旧身份。
  /// 参数说明：无。
  /// 返回：与当前网格顺序一致的选择，不持有文件内容或跨目录选择历史。
  var selectedItems: [VaultMedia] {
    visibleItems.filter {
      selectedIDs.contains($0.id)
    }
  }

  /// 业务作用：仅在全部勾选来源可移动时开放统一移动入口。
  /// 参数说明：无。
  /// 返回：非空且不含受密码保护目录树的当前选择可移动。
  var canMoveSelection: Bool {
    let media = selectedItems
    return !media.isEmpty && !media.contains(where: containsProtectedFolder)
  }

  /// 业务作用：只向不含密码保护目录树的整批选择开放删除，不能用多选绕过单项限制。
  /// 参数说明：无。
  /// 返回：当前非空选择中全部目录已取消保护时为真，执行时仍由存储层预检整批。
  var canDeleteSelection: Bool {
    !selectedItems.isEmpty && !selectedItems.contains(where: containsProtectedFolder)
  }

  /// 业务作用：进入只用于批量整理的选择模式，关闭旧拖放身份。
  /// 参数说明：无。
  /// 返回：当前已解锁且空闲时显示勾选入口，不打开媒体或恢复旧选择。
  func beginSelection() {
    guard screen == .library, !busy, selected == nil, folderPrompt == nil else {
      return
    }
    internalDrag = nil
    selectedIDs = []
    selecting = true
  }

  /// 业务作用：结束多选并释放当前选择身份，导航、锁定和完成移动均可调用。
  /// 参数说明：无。
  /// 返回：选择状态清空，不移动或删除任何文件。
  func endSelection() {
    selectedIDs = []
    selecting = false
  }

  /// 业务作用：勾选或取消当前目录的单个条目，不触发打开或解密播放。
  /// 参数说明：
  /// - `media`：本次点击的可见条目。
  /// 返回：仅更改内存选择；忙碌、失权或旧条目时忽略点击。
  func toggleSelection(_ media: VaultMedia) {
    guard selecting, screen == .library, !busy, visibleItems.contains(media) else {
      return
    }
    if !selectedIDs.insert(media.id).inserted {
      selectedIDs.remove(media.id)
    }
  }

  /// 业务作用：一次勾选当前目录全部条目，或清空本次勾选。
  /// 参数说明：无。
  /// 返回：只影响当前目录；受保护项目仍保留移动门禁，不被全选绕过或静默跳过。
  func toggleSelectAll() {
    guard selecting, screen == .library, !busy else {
      return
    }
    let all = Set(visibleItems.map(\.id))
    selectedIDs = all.isSubset(of: selectedIDs) ? [] : all
  }

  /// 业务作用：为同一批来源提供共同可用的目标，不允许选入任一来源自身或子树。
  /// 参数说明：
  /// - `media`：本次准备统一移动的来源快照。
  /// 返回：全部来源均符合层级与保护范围的目标；提交时仍检查整批同名冲突。
  func moveDestinations(for media: [VaultMedia]) -> [(id: UUID?, title: String)] {
    guard let first = media.first, !media.contains(where: containsProtectedFolder) else {
      return []
    }
    let candidates = moveDestinations(for: first)
    var common = Set(candidates.map(\.id))
    for item in media.dropFirst() {
      common.formIntersection(moveDestinations(for: item).map(\.id))
    }
    return candidates.filter {
      common.contains($0.id)
    }
  }

  /// 业务作用：向当前已授权目录新建空文件夹，不建立保险箱之外的来源目录。
  /// 参数说明：
  /// - `name`：用户确认的新目录名。
  /// 返回：成功后刷新当前目录；非法名称或失权时只显示错误。
  func createFolder(_ name: String) {
    guard let library, let grant, screen == .library, !busy, closeViewer() else {
      return
    }
    let parentID = currentFolderID
    perform(
      {
        _ = try library.createFolder(name: name, in: parentID, using: grant)
        return try library.list(using: grant)
      },
      success: { [weak self] items in
        self?.items = items
        self?.message = "已新建文件夹。"
      })
  }

  /// 业务作用：对明确来源开启内部移动，保护校验由统一目录动作继续完成。
  /// 参数说明：
  /// - `media`：选中的文件或无密码目录树。
  /// - `parentID`：用户明确选择的接收目录。
  /// 返回：需要目标密码时呈现验证，否则执行移动；始终不解密导出到系统。
  func move(_ media: VaultMedia, to parentID: UUID?) {
    move([media], to: parentID)
  }

  /// 业务作用：对同一批明确来源开启统一目标移动，目标密码只在本次批次验证。
  /// 参数说明：
  /// - `media`：本次选定的文件与普通目录。
  /// - `parentID`：全部项目共用的接收目录。
  /// 返回：先等待必要的密码，再整体预检并逐项提交，不生成系统明文。
  func move(_ media: [VaultMedia], to parentID: UUID?) {
    guard !media.isEmpty, !busy, screen == .library, folderPrompt == nil else {
      return
    }
    moveFailure = nil
    // 每次移动只保留当前浏览路径的证明，不能复用此前其它目标的密码授权。
    grant?.retainFolderAccess(currentFolderPathIDs)
    runFolderAction(.move(media, parentID))
  }

  /// 业务作用：判断来源能否移到其父目录的上一级，保护范围不得被越过。
  /// 参数说明：
  /// - `media`：位于保险箱子目录中的来源。
  /// 返回：父层存在且上一级满足现有移动约束时为真。
  func canMoveToParent(_ media: VaultMedia) -> Bool {
    guard let parentID = media.parentID, let parent = items.first(where: { $0.id == parentID })
    else {
      return false
    }
    return !containsProtectedFolder(media)
      && moveDestinations(for: media).contains(where: { $0.id == parent.parentID })
  }

  /// 业务作用：把子目录中的条目移到上一层，复用普通移动的密码与原子发布约束。
  /// 参数说明：
  /// - `media`：本次明确选择的来源文件或普通目录。
  /// 返回：允许时开始移动；根目录条目或保护范围不允许时保持原位。
  func moveToParent(_ media: VaultMedia) {
    guard canMoveToParent(media), let parent = items.first(where: { $0.id == media.parentID })
    else {
      return
    }
    move(media, to: parent.parentID)
  }

  /// 业务作用：把同层的多项选择移到上一级，并要求全部来源符合保护限制。
  /// 参数说明：
  /// - `media`：本次选定的同层条目。
  /// 返回：全部允许时开始移动，任一来源不允许时均保留原位。
  func moveToParent(_ media: [VaultMedia]) {
    guard let first = media.first, media.allSatisfy(canMoveToParent),
      let parent = items.first(where: { $0.id == first.parentID })
    else {
      return
    }
    move(media, to: parent.parentID)
  }

  /// 业务作用：按用户输入的保险箱绝对路径开启内部移动，不创建缺失目录。
  /// 参数说明：
  /// - `media`：当前已授权来源。
  /// - `path`：以 / 开头的保险箱内部目录，原文仅在本次操作内存中保留。
  /// 返回：逐层验证目标后移动；不存在或不可移动时弹出错误且来源保持原位。
  func move(_ media: VaultMedia, toVaultPath path: String) {
    move([media], toVaultPath: path)
  }

  /// 业务作用：按手动输入的保险箱路径把一批来源移到同一目录，不创建缺失目录。
  /// 参数说明：
  /// - `media`：本次明确选定的同层条目。
  /// - `path`：以 / 开头的保险箱虚拟绝对目录。
  /// 返回：目标与整批限制通过后逐项移动；路径不存在或验证取消时来源保持原位。
  func move(_ media: [VaultMedia], toVaultPath path: String) {
    guard !media.isEmpty, !busy, screen == .library, folderPrompt == nil else {
      return
    }
    moveFailure = nil
    // 指定路径与拖放采用同一新验证边界，不继承旧目标的临时访问权。
    grant?.retainFolderAccess(currentFolderPathIDs)
    runFolderAction(.movePath(media, path))
  }

  /// 业务作用：仅允许从当前目录拖动普通文件或不含密码保护的目录树。
  /// 参数说明：
  /// - `media`：准备由鼠标或单指拖动的条目。
  /// 返回：当前会话空闲、来源仍可见且允许移动时为真。
  func canDrag(_ media: VaultMedia) -> Bool {
    screen == .library && !busy && !selecting && selected == nil && folderPrompt == nil
      && movingMedia == nil && visibleItems.contains(media) && !containsProtectedFolder(media)
  }

  /// 业务作用：为本次内部拖放创建不含名称、路径、内容或密码的随机凭据。
  /// 参数说明：
  /// - `media`：当前目录中允许移动的来源。
  /// 返回：仅本进程可交付的随机令牌；无效来源不建立拖放状态。
  func beginDragging(_ media: VaultMedia) -> Data? {
    guard canDrag(media) else {
      return nil
    }
    let request = InternalDrag(token: UUID(), mediaID: media.id, parentID: currentFolderID)
    internalDrag = request
    return Data(request.token.uuidString.utf8)
  }

  /// 业务作用：原生拖动结束时撤销尚未消费的令牌，不影响后来建立的新拖动。
  /// 参数说明：
  /// - `data`：结束会话持有的随机令牌。
  /// 返回：仅匹配当前拖动时清空状态；已经完成或替换的会话不受影响。
  func cancelDragging(_ data: Data) {
    guard let request = internalDrag, data == Data(request.token.uuidString.utf8) else {
      return
    }
    internalDrag = nil
  }

  /// 业务作用：在悬停阶段判断内部拖放目标，不读取目标内容或提前授予密码权限。
  /// 参数说明：
  /// - `folder`：指针或手指下的接收目录。
  /// 返回：来源与目标仍属于当前列表且满足层级、保护和重名约束时为真。
  func canDrop(into folder: VaultMedia) -> Bool {
    guard let request = internalDrag, request.parentID == currentFolderID,
      let source = visibleItems.first(where: { $0.id == request.mediaID }), canDrag(source),
      visibleItems.contains(folder), folder.isFolder, !folder.isDocument,
      moveDestinations(for: source).contains(where: { $0.id == folder.id })
    else {
      return false
    }
    return !items.contains {
      $0.parentID == folder.id
        && $0.originalFilename.localizedCaseInsensitiveCompare(source.originalFilename)
          == .orderedSame
    }
  }

  /// 业务作用：松手后消费当前拖放令牌，再通过统一移动流程验证目标密码。
  /// 参数说明：
  /// - `data`：本进程拖放提供者交付的随机令牌。
  /// - `folderID`：松手时明确选择的目标目录身份。
  /// 返回：有效拖放开始验证或移动；旧令牌、锁定后回调及无效目标均不改变任何条目。
  func completeDrop(_ data: Data, into folderID: UUID) {
    // 迟到回调不能消费新拖动的身份，也不能在切换目录或失权后执行旧移动。
    guard let request = internalDrag, data == Data(request.token.uuidString.utf8),
      let folder = visibleItems.first(where: { $0.id == folderID }), canDrop(into: folder),
      let source = visibleItems.first(where: { $0.id == request.mediaID })
    else {
      return
    }
    internalDrag = nil
    move(source, to: folderID)
  }

  /// 业务作用：在设置或取消目录保护前呈现独立文本密码输入，不使用 App 凭据代替。
  /// 参数说明：
  /// - `folder`：当前可见的普通目录。
  /// - `removing`：是否需要凭原密码取消已有保护。
  /// 返回：只打开当前目录的表单，不立即更改保护状态。
  func requestFolderPassword(_ folder: VaultMedia, removing: Bool) {
    guard screen == .library, !busy, folder.isFolder, !folder.isDocument,
      visibleItems.contains(folder)
    else {
      return
    }
    pendingFolderAction = nil
    cancelSystemCopy()
    message = nil
    folderPrompt = FolderPrompt(
      id: UUID(), folder: folder, kind: removing ? .removing : .setting)
  }

  /// 业务作用：只在当前表单与 App 会话仍有效时验证目录密码或提交目录保护变更。
  /// 参数说明：
  /// - `password`：本次输入的独立文本密码，原始值仅供内存派生使用。
  /// - `challengeID`：输入界面持有的本次目录验证身份，不能用于后来出现的表单。
  /// 返回：访问、移动或复制验证成功后继续本次操作；保护变更后撤销旧能力、回到根目录，错误时保留表单。
  func submitFolderPassword(_ password: String, challengeID: UUID) {
    guard let prompt = folderPrompt, let library, let grant, let store,
      screen == .library, !busy
    else {
      return
    }
    // 迟到的界面提交不属于密码校验失败，不能把上一轮错误提示继续当作本轮结果。
    guard prompt.challengeID == challengeID else {
      message = "密码输入页面已更新，本次未验证，请重新输入。"
      return
    }
    if prompt.kind == .copy {
      guard let request = pendingCopy else {
        return
      }
      perform(
        {
          try library.authenticateCopyFolder(
            id: prompt.folder.id, password: password, session: request.session, using: grant)
        },
        success: { [weak self] in
          guard let self, self.folderPrompt?.challengeID == prompt.challengeID,
            self.pendingCopy?.session === request.session
          else {
            request.session.revoke()
            return
          }
          self.continueSystemCopy(request)
        })
      return
    }
    if prompt.kind == .access || prompt.kind == .move || prompt.kind == .rename {
      perform(
        {
          try library.authenticateFolder(id: prompt.folder.id, password: password, using: grant)
        },
        success: { [weak self] in
          guard let self, self.folderPrompt?.challengeID == prompt.challengeID,
            let action = self.pendingFolderAction
          else {
            return
          }
          self.runFolderAction(action)
        })
      return
    }
    closeViewer()
    clearThumbnails()
    perform(
      {
        let replacement = try library.changeFolderPassword(
          id: prompt.folder.id, password: prompt.kind == .setting ? password : nil,
          previous: prompt.kind == .removing ? password : nil, using: grant)
        do {
          return (replacement, try library.list(using: replacement))
        } catch {
          store.lock()
          throw VaultError.folderCommitUncertain
        }
      },
      discard: { replacement, _ in
        replacement.revoke()
      },
      success: { [weak self] replacement, items in
        guard let self else {
          replacement.revoke()
          return
        }
        self.grant = replacement
        self.items = items
        self.currentFolderID = nil
        self.pendingFolderAction = nil
        self.folderPrompt = nil
        self.message = prompt.kind == .setting ? "已设置文件夹独立访问密码。" : "已取消文件夹访问密码。"
      })
  }

  /// 业务作用：取消当前目录输入及尚未执行的复制，撤销临时复制证明与其它路径权限。
  /// 参数说明：无。
  /// 返回：保留当前浏览路径权限，其它目录再次进入仍需验证。
  func cancelFolderPrompt() {
    guard !busy else {
      return
    }
    let cancelled = folderPrompt != nil || pendingFolderAction != nil
    folderPrompt = nil
    pendingFolderAction = nil
    cancelSystemCopy()
    grant?.retainFolderAccess(currentFolderPathIDs)
    if cancelled {
      clearThumbnails()
      message = nil
    }
  }

  /// 业务作用：访问或移入目标目录前验证密码，导出与删除直接执行目录保护限制。
  /// 参数说明：
  /// - `action`：用户明确选择且已完成外层确认的目录或文件操作。
  /// 返回：访问或移入目标需要密码时等待验证；移动后撤销旧层级能力，失败不放开保护。
  private func runFolderAction(_ action: FolderAction) {
    guard let library, let grant, !busy, screen == .library else {
      return
    }
    guard closeViewer() else {
      return
    }
    if action.isMove {
      // 移动会撤销旧层级读取，先释放预览和排队解码，避免批次处理期间保留过期内容。
      clearThumbnails()
    }
    cancelSystemCopy()
    pendingFolderAction = action
    let previousFolderID = currentFolderID
    moving = action.isMove
    perform(
      {
        var moveParentID: UUID?
        // 删除和导出不能把访问密码当作取消保护；移入受保护目标则必须先取得该目录访问权。
        switch action {
        case .delete, .export:
          break
        case .enter(let folder), .rename(let folder, _):
          if let locked = try library.nextLockedFolder(
            id: folder.id, recursive: false, using: grant)
          {
            return FolderActionResult(prompt: locked, folderID: nil, items: [], message: nil)
          }
        case .move(_, let parentID):
          moveParentID = parentID
          if let parentID,
            let locked = try library.nextLockedFolder(id: parentID, recursive: false, using: grant)
          {
            return FolderActionResult(prompt: locked, folderID: nil, items: [], message: nil)
          }
        case .movePath(_, let path):
          let target = try library.resolveMoveDirectory(path: path, using: grant)
          if let locked = target.locked {
            return FolderActionResult(prompt: locked, folderID: nil, items: [], message: nil)
          }
          moveParentID = target.id
        }
        let folderID: UUID?
        let notice: String?
        switch action {
        case .enter(let folder):
          try library.reader(id: folder.id, using: grant).verify()
          folderID = folder.id
          notice = nil
        case .delete(let media):
          try library.delete(id: media.id, using: grant)
          folderID = previousFolderID
          notice = "已删除保险箱内的加密文件。"
        case .export(let media, let directory):
          _ = try library.export(id: media.id, to: directory, using: grant)
          folderID = previousFolderID
          notice = "已按原名导出到系统，保险箱内原件保留。系统中的副本不再受保险箱密码保护。"
        case .move, .movePath:
          let result = try library.move(
            ids: action.sources.map(\.id), to: moveParentID, using: grant)
          let replacement = result.grant
          do {
            let notice = result.failure.map {
              "已移动 \(result.movedCount) / \(result.totalCount) 项，其余项目保留原位。\(Self.message($0))"
            }
            return FolderActionResult(
              prompt: nil, folderID: nil,
              items: try library.list(using: replacement),
              message: notice ?? "已移动 \(result.movedCount) 项，文件名和内容保持不变。",
              replacement: replacement,
              moveFailure: notice)
          } catch {
            replacement.revoke()
            throw VaultError.organizationCommitUncertain
          }
        case .rename(let media, let name):
          let ordinaryFolder = media.isFolder && !media.isDocument
          let replacement: VaultGrant
          if ordinaryFolder {
            replacement = try library.renameFolder(id: media.id, to: name, using: grant)
          } else {
            replacement = try library.renameFile(id: media.id, to: name, using: grant)
          }
          do {
            return FolderActionResult(
              prompt: nil, folderID: nil, items: try library.list(using: replacement),
              message: ordinaryFolder
                ? "已重命名文件夹，内容和原密码保持不变。" : "已重命名文件，内容、格式和所在目录保持不变。",
              replacement: replacement)
          } catch {
            replacement.revoke()
            throw VaultError.organizationCommitUncertain
          }
        }
        try library.retainFolderAccess(to: folderID, using: grant)
        return FolderActionResult(
          prompt: nil, folderID: folderID, items: try library.list(using: grant), message: notice)
      },
      discard: { result in
        result.replacement?.revoke()
      },
      success: { [weak self] result in
        guard let self else {
          return
        }
        defer {
          self.finishMoving()
        }
        if let replacement = result.replacement {
          self.grant = replacement
        }
        if let folder = result.prompt {
          let kind: FolderPrompt.Kind
          switch action {
          case .move, .movePath:
            kind = .move
          case .rename:
            kind = .rename
          default:
            kind = .access
          }
          self.folderPrompt = FolderPrompt(
            id: self.folderPrompt?.id ?? UUID(), folder: folder, kind: kind)
          return
        }
        self.items = result.items
        if action.isMove {
          self.endSelection()
        }
        self.currentFolderID = result.folderID
        self.grant?.retainFolderAccess(self.currentFolderPathIDs)
        self.clearThumbnails()
        self.pendingFolderAction = nil
        self.folderPrompt = nil
        self.message = result.message
        self.moveFailure = result.moveFailure
      })
  }

  /// 业务作用：打开本机保险箱入口，仅读取凭据种类，不自动解锁或恢复最近媒体。
  /// 参数说明：无。
  /// 返回：首次设置、锁定或明确失败的界面状态。
  init() {
    do {
      let store = try VaultStore(
        directory: VaultStore.defaultDirectory(),
        secrets: KeychainSecrets(
          service: (Bundle.main.bundleIdentifier ?? "local.encvault") + ".device"))
      self.store = store
      let library = VaultLibrary(store: store)
      self.library = library
      // 排他目录已经取得后才能回收中断预览，避免另一个实例仍在读取同一副本。
      try VaultDocument.removeInterruptedPreviews(in: store)
      photos = try PhotoVaultService(store: store, library: library)
      if let kind = try store.credentialKind() {
        self.kind = kind
        screen = .locked
        refreshCredentialStatus()
      } else {
        screen = .setup
      }
    } catch {
      screen = .unavailable
      message = Self.message(error)
    }
    #if os(iOS)
      foregroundProtection = VaultForegroundProtection(model: self)
    #endif
  }

  /// 业务作用：后台执行有界磁盘或派生操作，仅允许当前前台代次更新界面。
  /// 参数说明：
  /// - `action`：不访问界面状态的业务操作。
  /// - `discard`：失去前台代次后撤销本次新取得的能力，不能影响后续会话。
  /// - `success`：仍属于当前代次时执行的界面提交。
  /// 返回：立即返回；取消和失权后的结果不会重新打开媒体或恢复码。
  private func perform<T: Sendable>(
    _ action: @escaping @Sendable () async throws -> T,
    discard: @escaping @Sendable (T) -> Void = { _ in },
    success: @escaping @MainActor (T) -> Void
  ) {
    guard !busy else {
      return
    }
    busy = true
    message = nil
    let expected = epoch
    let store = store
    let worker = Task.detached(priority: .userInitiated) {
      try await action()
    }
    operation = Task { [weak self] in
      do {
        let result = try await withTaskCancellationHandler {
          try await worker.value
        } onCancel: {
          worker.cancel()
        }
        // 失去前台代次的任务只能释放本次能力，不能重新开放媒体或展示恢复材料。
        guard let self, self.epoch == expected, !Task.isCancelled else {
          discard(result)
          if let proposal = result as? EnrollmentOffer {
            store?.cancelEnrollment(proposal.token)
          }
          return
        }
        self.busy = false
        self.operation = nil
        success(result)
        self.finishImport()
      } catch {
        guard let self, self.epoch == expected else {
          return
        }
        if case VaultError.documentCommitUncertain = error {
          // 文档发布结果不明时清除草稿和授权，重新解锁读取实际密文，不能自动重试覆盖。
          self.lock()
        }
        if case VaultError.folderCommitUncertain = error {
          self.lock()
        }
        if case VaultError.organizationCommitUncertain = error {
          self.lock()
        }
        if self.pendingFolderAction?.isMove == true {
          switch error {
          case VaultError.invalidFolderPassword, VaultError.incorrectFolderPassword:
            // 密码错误仍留在当前验证表单，不把错误输入当作目标不存在。
            break
          default:
            self.folderPrompt = nil
            self.moveFailure = Self.message(error)
            // 路径拒绝后撤销沿途临时验证，避免失败操作留下额外目录访问权。
            self.grant?.retainFolderAccess(self.currentFolderPathIDs)
          }
        }
        if self.folderPrompt == nil {
          self.pendingFolderAction = nil
          self.cancelSystemCopy()
        }
        if case VaultError.credentialCommitUncertain = error {
          self.lock()
          do {
            if let kind = try store?.credentialKind() {
              self.kind = kind
              self.screen = .locked
            } else {
              self.screen = .setup
            }
          } catch {
            self.screen = .unavailable
          }
        }
        self.finishImport()
        self.finishMoving()
        self.busy = false
        self.operation = nil
        if case VaultError.wait = error {
          // 底层认证冻结已经撤销能力，界面也必须立即清空媒体与未提交的改密材料。
          self.lock()
        }
        self.refreshCredentialStatus()
        self.message = Self.message(error)
        if let prompt = self.folderPrompt {
          switch error {
          case VaultError.invalidFolderPassword, VaultError.incorrectFolderPassword:
            // 拒绝后换发输入身份，旧原生编辑器与迟到的提交不能复用下一次验证。
            self.folderPrompt = FolderPrompt(
              id: prompt.id, folder: prompt.folder, kind: prompt.kind)
          default:
            break
          }
        }
      }
    }
  }

  /// 业务作用：以独立密码建立会话并读取认证后的原名列表，不恢复上次查看内容。
  /// 参数说明：
  /// - `credential`：当前输入的密码或手势。
  /// 返回：成功后进入媒体列表；失败保持锁定并显示脱敏原因。
  func unlock(_ credential: VaultCredential) {
    guard let store, let library else {
      return
    }
    perform(
      {
        let grant = try store.unlock(credential)
        do {
          return (grant, try library.list(using: grant))
        } catch {
          store.lock()
          throw error
        }
      },
      discard: { grant, _ in
        grant.revoke()
      },
      success: { [weak self] grant, items in
        self?.grant = grant
        self?.items = items
        self?.screen = .library
        self?.refreshCredentialStatus()
      })
  }

  /// 业务作用：为首次设置生成待确认恢复码，不提前发布密码。
  /// 参数说明：
  /// - `credential`：用户重复确认的凭据。
  /// 返回：成功后展示仅当前设置会话有效的恢复码。
  func setup(_ credential: VaultCredential) {
    guard let store else {
      return
    }
    perform(
      {
        try store.prepareSetup(credential)
      },
      success: { [weak self] in
        self?.offer = $0
      })
  }

  /// 业务作用：验证旧密码后准备新的独立密码或手势方式。
  /// 参数说明：
  /// - `old`：当前独立凭据。
  /// - `new`：两次确认一致的新凭据。
  /// 返回：成功后展示新恢复码，尚未改变现有有效密码。
  func change(old: VaultCredential, new: VaultCredential) {
    guard let store else {
      return
    }
    perform(
      {
        try store.prepareChange(old: old, new: new)
      },
      success: { [weak self] in
        self?.offer = $0
      })
  }

  /// 业务作用：以离线恢复码准备保留数据的密码重设。
  /// 参数说明：
  /// - `code`：用户保留的恢复码。
  /// - `new`：两次确认一致的新凭据。
  /// 返回：成功后展示替代恢复码；错误不会清空数据。
  func recover(code: String, new: VaultCredential) {
    guard let store else {
      return
    }
    perform(
      {
        try store.prepareRecovery(code: code, credential: new)
      },
      success: { [weak self] in
        self?.offer = $0
      })
  }

  /// 业务作用：用户确认新恢复码后提交凭据，并以新会话重新读取原名列表。
  /// 参数说明：无。
  /// 返回：成功后进入媒体列表，旧读取被撤销；失败不谎报密码已更改。
  func confirmOffer() {
    guard let store, let offer else {
      return
    }
    closeViewer()
    perform(
      {
        let grant = try store.confirmEnrollment(offer.token)
        let kind = try store.credentialKind() ?? .pin
        return (grant, kind)
      },
      discard: { grant, _ in
        grant.revoke()
      },
      success: { [weak self] grant, kind in
        self?.offer = nil
        self?.grant = grant
        self?.items = []
        self?.kind = kind
        self?.refreshCredentialStatus()
        self?.screen = .library
        self?.refresh()
      })
  }

  /// 业务作用：重新枚举已提交的密文，使单个导入失败不隐藏此前成功保存的文件。
  /// 参数说明：无。
  /// 返回：成功后更新原名列表；损坏或失权时保留明确错误。
  func refresh() {
    guard let library, let grant else {
      return
    }
    perform(
      {
        try library.list(using: grant)
      },
      success: { [weak self] in
        self?.items = $0
      })
  }

  /// 业务作用：离开未提交的密码设置时丢弃恢复材料，不切换当前有效凭据。
  /// 参数说明：无。
  /// 返回：当前恢复码界面关闭。
  func cancelOffer() {
    if let offer {
      store?.cancelEnrollment(offer.token)
    }
    offer = nil
  }

  /// 业务作用：同步持久化冻结状态，使重新打开、锁定与失败后的输入门禁保持一致。
  /// 参数说明：无。
  /// 返回：成功时更新倒计时依据；不能读取限制时禁用密码输入，保留独立恢复码入口。
  func refreshCredentialStatus() {
    do {
      credentialStatus = try store?.credentialStatus()
    } catch VaultError.notConfigured {
      credentialStatus = nil
    } catch {
      credentialStatus = nil
      message = Self.message(error)
    }
  }

  /// 业务作用：串行保存所选文件或完整目录，完整成功后只保留普通文件的当前会话删源收据。
  /// 参数说明：
  /// - `urls`：系统明确授权的本地文件、文件包或目录。
  /// 返回：保存进度和成功收据留在内存；保留目录层级，失败及未完成的来源不移除。
  func importFiles(_ urls: [URL]) {
    guard let library, let grant, !urls.isEmpty, !busy, screen == .library, closeViewer() else {
      return
    }
    savedSources = []
    savedPhotos = []
    progress = 0
    let buffer = beginImport()
    perform(
      {
        var saved: [SavedImport] = []
        var failures = 0
        var completedBytes: UInt64 = 0
        for url in urls {
          if Task.isCancelled {
            throw VaultError.cancelled
          }
          do {
            let scoped = url.startAccessingSecurityScopedResource()
            defer {
              if scoped {
                url.stopAccessingSecurityScopedResource()
              }
            }
            let previousFiles = saved.count
            let previousBytes = completedBytes
            let previousFailures = failures
            let report: @Sendable (ImportProgress) -> Void = { update in
              buffer.publish(
                update.adding(
                  files: previousFiles, bytes: previousBytes, failures: previousFailures))
            }
            if try url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory == true {
              let result = try library.saveFolder(source: url, using: grant, status: report)
              saved.append(contentsOf: result.saved)
              completedBytes += result.saved.reduce(0) { $0 + $1.media.byteCount }
              failures += result.failures
            } else {
              let receipt = try library.save(source: url, using: grant, status: report)
              saved.append(receipt)
              completedBytes += receipt.media.byteCount
            }
          } catch {
            try grant.check()
            if Task.isCancelled {
              throw VaultError.cancelled
            }
            failures += 1
          }
        }
        return (saved, try library.list(using: grant), failures)
      },
      success: { [weak self] saved, items, failures in
        self?.items = items
        self?.currentFolderID = nil
        self?.savedSources = saved
        self?.progress = 1
        if failures > 0 {
          self?.message = "部分文件未能保存，原件仍保留。成功保存的文件已显示在列表中。"
        }
      })
  }

  /// 业务作用：保存系统选择器交付的所选文件，不枚举图库，也不把资产身份当作文件内容。
  /// 参数说明：
  /// - `selections`：本次明确勾选、由系统选择器交付的照片或视频。
  /// 返回：成功文件进入原名列表，只有完整成功的资产获得可选删源收据。
  func importPhotos(_ selections: [PhotosPickerItem]) {
    guard let photos, let library, let grant, !selections.isEmpty, !busy,
      screen == .library, closeViewer()
    else {
      return
    }
    savedPhotos = []
    savedSources = []
    photoImportFailure = nil
    progress = 0
    let buffer = beginImport()
    perform(
      {
        var saved: [SavedPhotoImport] = []
        var savedCount = 0
        var completedBytes: UInt64 = 0
        var failures: [String] = []
        for selection in selections {
          do {
            buffer.publish(
              ImportProgress(
                phase: .directory, filename: "正在接收所选照片或视频", currentBytes: 0, totalBytes: 0,
                completedFiles: savedCount, completedBytes: completedBytes,
                failedFiles: failures.count))
            guard let picked = try await selection.loadTransferable(type: PickedPhotoFile.self)
            else {
              throw VaultError.photoResource
            }
            defer {
              try? FileManager.default.removeItem(at: picked.directory)
            }
            try grant.check()
            let previousCount = savedCount
            let previousBytes = completedBytes
            let previousFailures = failures.count
            let result = try photos.savePickedFile(
              picked.file, identifier: selection.itemIdentifier, using: grant,
              progress: { update in
                buffer.publish(
                  update.adding(
                    files: previousCount, bytes: previousBytes, failures: previousFailures))
              })
            savedCount += 1
            completedBytes += result.media.byteCount
            if let receipt = result.receipt {
              saved.append(receipt)
            }
          } catch {
            try grant.check()
            if Task.isCancelled {
              throw VaultError.cancelled
            }
            failures.append(Self.message(error))
          }
        }
        return (saved, savedCount, try library.list(using: grant), failures)
      },
      success: { [weak self] saved, savedCount, items, failures in
        self?.savedPhotos = saved
        self?.items = items
        if !failures.isEmpty {
          let reasons = Array(Set(failures)).sorted().joined(separator: "\n")
          let message = "已保存 \(savedCount) 项，\(failures.count) 项未能导入。\n\(reasons)\n未导入的原件已保留。"
          self?.message = message
          if savedCount == 0 {
            // 全部失败时必须明确反馈原因，不能只关闭选择器并在空相册底部留下难以发现的提示。
            self?.photoImportFailure = message
          }
        } else if savedCount > 0 && saved.count < savedCount {
          self?.message = "已加密保存所选文件；请通过系统照片管理无法复验的原件。"
        }
      })
  }

  /// 业务作用：仅处理用户刚确认的成功保存收据，逐一复验后请求系统移除来源。
  /// 参数说明：无。
  /// 返回：成功或部分失败的数量提示；加密文件不因此删除。
  func removeSavedSources() {
    guard let library, let grant, !savedSources.isEmpty || !savedPhotos.isEmpty else {
      return
    }
    let receipts = savedSources
    let photoReceipts = savedPhotos
    let photos = photos
    savedSources = []
    savedPhotos = []
    perform(
      {
        var removed = 0
        for receipt in receipts {
          do {
            try library.removeSource(receipt, using: grant)
            removed += 1
          } catch {
            try grant.check()
          }
        }
        if let photos {
          for receipt in photoReceipts {
            do {
              try await photos.removeSource(receipt, using: grant)
              removed += 1
            } catch {
              try grant.check()
            }
          }
        }
        return removed
      },
      success: { [weak self] removed in
        self?.message =
          removed == receipts.count + photoReceipts.count
          ? "已请求系统移除原件。加密文件保留在保险箱中。"
          : "加密文件已保存；部分原件未能移除，请通过系统检查。"
      })
  }

  /// 业务作用：删除用户确认的密文，并重新枚举剩余文件。
  /// 参数说明：
  /// - `media`：明确选中并确认删除的媒体。
  /// 返回：成功后条目消失；不会删除来源或导出副本。
  func delete(_ media: VaultMedia) {
    runFolderAction(.delete(media))
  }

  /// 业务作用：删除用户已二次确认的当前层级选择，整批先验证保护规则，完成后刷新当前目录。
  /// 参数说明：
  /// - `media`：确认界面持有的所选条目快照，不能改用后来勾选的项目。
  /// 返回：成功后清空选择并显示删除数量；受保护来源整批拒绝，磁盘失败时展示实际完成数量。
  func delete(_ media: [VaultMedia]) {
    guard let library, let grant, screen == .library, !busy, !media.isEmpty,
      media.allSatisfy(visibleItems.contains), closeViewer()
    else {
      return
    }
    clearThumbnails()
    perform(
      {
        let result = try library.delete(ids: media.map(\.id), using: grant)
        return (result, try library.list(using: grant))
      },
      success: { [weak self] result, items in
        guard let self else {
          return
        }
        self.items = items
        self.endSelection()
        if let failure = result.failure {
          self.message =
            "已完成删除 \(result.deletedCount) / \(result.totalCount) 项，其余项目或部分内容未能删除。\(Self.message(failure))"
        } else {
          self.message = "已删除保险箱内的 \(result.deletedCount) 个所选项目。"
        }
      })
  }

  /// 业务作用：把明确确认的新名称交给目录事务，保护目录仍需先输入独立密码。
  /// 参数说明：
  /// - `folder`：当前可见且明确选中的普通文件夹。
  /// - `name`：用户手动确认的新名称。
  /// 返回：未验证时打开密码表单，成功后回根目录并刷新名称，不改变密码或子项。
  func renameFolder(_ folder: VaultMedia, to name: String) {
    guard screen == .library, !busy, folder.isFolder, !folder.isDocument,
      visibleItems.contains(folder)
    else {
      return
    }
    runFolderAction(.rename(folder, name))
  }

  /// 业务作用：将用户确认的普通文件或文档包名称交给认证事务，不改变文件格式。
  /// 参数说明：
  /// - `media`：当前目录或查看页面明确选择的文件。
  /// - `name`：保留原扩展名的新名称。
  /// 返回：编辑未退出时不执行；需要所属目录密码时先验证，成功后回根目录刷新名称并撤销旧读取。
  func renameFile(_ media: VaultMedia, to name: String) {
    // 改名会关闭查看并轮换会话，不能借此丢弃尚未由用户保存或确认退出的草稿。
    guard screen == .library, !busy, editingText == nil, !media.isFolder || media.isDocument,
      visibleItems.contains(media)
    else {
      return
    }
    runFolderAction(.rename(media, name))
  }

  /// 业务作用：将用户确认导出的文件按原名保存到系统目录，保险箱密文继续保留。
  /// 参数说明：
  /// - `media`：用户明确选择的媒体。
  /// - `directory`：系统选择器授权的目标目录。
  /// 返回：完整导出时显示提示；失败不覆盖原有同名文件。
  func export(_ media: VaultMedia, to directory: URL) {
    runFolderAction(.export(media, directory))
  }

  /// 业务作用：将用户选中的文件或完整目录解密复制到系统，同时保留保险箱内原件。
  /// 参数说明：
  /// - `media`：明确选择的文件或文件夹，目录复制保留全部层级与原名。
  /// - `directory`：系统选择器授权的目标目录。
  /// 返回：涉及保护时要求本次重新验证，全部通过且内容完整后发布；失权或重名时拒绝，不删除密文。
  func copyToSystem(_ media: VaultMedia, to directory: URL) {
    beginSystemCopy(media, destination: .directory(directory))
  }

  /// 业务作用：用户确认后将选中媒体按原名解密保存到系统照片，不删除保险箱副本。
  /// 参数说明：
  /// - `media`：当前明确选择的已认证媒体。
  /// 返回：系统保存与完整复验成功时提示；权限拒绝或无法确认时保留密文。
  func exportToPhotos(_ media: VaultMedia) {
    saveToPhotos(media)
  }

  /// 业务作用：按用户明确选择将图片或视频解密复制到系统照片，保留保险箱原件。
  /// 参数说明：
  /// - `media`：当前明确选择的图片或视频。
  /// 返回：系统副本完整复验后提示成功；失败或结果不明时保留保险箱原件。
  func copyToPhotos(_ media: VaultMedia) {
    guard media.isImage || media.isVideo else {
      return
    }
    beginSystemCopy(media, destination: .photos)
  }

  /// 业务作用：每次复制都建立新的目录验证事务，不能沿用浏览时取得的密码证明。
  /// 参数说明：
  /// - `media`：用户明确选择的文件或完整目录。
  /// - `destination`：本次确认的系统目录或系统照片。
  /// 返回：准备只属于本次复制的临时能力；未通过目录密码前不生成明文。
  private func beginSystemCopy(_ media: VaultMedia, destination: CopyDestination) {
    guard let library, let grant, screen == .library, !busy, closeViewer() else {
      return
    }
    // 每次用户选择都从新的复制事务开始，不能复用上一次取消或已完成的目录验证。
    cancelSystemCopy()
    folderPrompt = nil
    pendingFolderAction = nil
    perform(
      {
        try library.beginCopy(id: media.id, using: grant)
      },
      discard: { session in
        session.revoke()
      },
      success: { [weak self] session in
        guard let self else {
          session.revoke()
          return
        }
        let request = PendingCopy(media: media, destination: destination, session: session)
        self.pendingCopy = request
        self.continueSystemCopy(request)
      })
  }

  /// 业务作用：按顺序要求本次复制涉及的所有目录密码，全部通过后才开放系统输出。
  /// 参数说明：
  /// - `request`：绑定当前选中条目和目的地的复制请求。
  /// 返回：缺少证明时显示独立目录输入；全部满足后关闭输入并开始复制。
  private func continueSystemCopy(_ request: PendingCopy) {
    guard let library, let grant, pendingCopy?.session === request.session,
      screen == .library, !busy
    else {
      request.session.revoke()
      return
    }
    perform(
      {
        try library.nextCopyFolder(request.session, using: grant)
      },
      discard: { _ in
        request.session.revoke()
      },
      success: { [weak self] folder in
        guard let self, self.pendingCopy?.session === request.session else {
          request.session.revoke()
          return
        }
        if let folder {
          self.folderPrompt = FolderPrompt(
            id: self.folderPrompt?.id ?? UUID(), folder: folder, kind: .copy)
        } else {
          // 全部目录证明齐备后才关闭密码输入并开始输出，底层仍会在消费时再次核对。
          self.folderPrompt = nil
          self.finishSystemCopy(request)
        }
      })
  }

  /// 业务作用：消费已重新验证的单次复制权限，保存系统副本但不更改保险箱原件与保护状态。
  /// 参数说明：
  /// - `request`：目录验证完整且仍属于当前界面的复制请求。
  /// 返回：成功后撤销临时能力并提示；失败保留原件，不把权限留给下一次复制。
  private func finishSystemCopy(_ request: PendingCopy) {
    guard let library, let grant, pendingCopy?.session === request.session,
      screen == .library, !busy
    else {
      request.session.revoke()
      return
    }
    let photos = photos
    perform(
      {
        defer {
          request.session.revoke()
        }
        switch request.destination {
        case .directory(let directory):
          _ = try library.copyToSystem(request.session, to: directory, using: grant)
        case .photos:
          guard let photos else {
            throw VaultError.storage
          }
          try await photos.copy(request.media, session: request.session, using: grant)
        }
      },
      success: { [weak self] in
        guard let self, self.pendingCopy?.session === request.session else {
          return
        }
        self.cancelSystemCopy()
        self.message = "已按原名复制到系统，保险箱内原件及文件夹密码保护继续保留。系统中的副本未加密。"
      })
  }

  /// 业务作用：取消或结束请求时撤销全部临时复制证明，不影响当前目录的普通浏览权限。
  /// 参数说明：无。
  /// 返回：下一次复制必须重新建立事务并输入相关目录密码。
  private func cancelSystemCopy() {
    pendingCopy?.session.revoke()
    pendingCopy = nil
  }

  /// 业务作用：保持原有系统照片导出入口的原名复验和受保护内容禁止导出规则。
  /// 参数说明：
  /// - `media`：本次明确选择的图片或视频。
  /// 返回：已解锁且不受目录保护时开始保存；拒绝时不申请照片权限或生成外部明文。
  private func saveToPhotos(_ media: VaultMedia) {
    guard let photos, let grant, screen == .library, !busy,
      media.isImage || media.isVideo
    else {
      return
    }
    // 已有浏览或复制验证不能代替取消保护，原有照片导出在申请系统权限前直接拒绝。
    guard !exportRestricted(media) else {
      message = VaultError.protectedFolderExport.localizedDescription
      return
    }
    guard closeViewer() else {
      return
    }
    perform(
      {
        try await photos.export(media, using: grant)
      },
      success: { [weak self] in
        self?.message = "已按原名导出到系统照片，保险箱内原件保留。相册中的明文副本不再受保险箱密码保护。"
      })
  }

  /// 业务作用：只在本次选择后读取媒体，图片明文与播放器都不持久化。
  /// 参数说明：
  /// - `media`：已解锁列表中选中的媒体。
  /// - `autoplay`：视频准备后是否开始播放，默认开启；图片与文档忽略此参数。
  /// 返回：成功后展示原名和媒体或只读文档，视频默认开始播放；失败不打开外部应用。
  func open(_ media: VaultMedia, autoplay: Bool = true) {
    if selecting {
      toggleSelection(media)
      return
    }
    guard let library, let grant, !busy else {
      return
    }
    closeViewer()
    if media.isFolder && !media.isDocument {
      runFolderAction(.enter(media))
      return
    }
    // 保留当前明确选择的原名，使异步读取期间相册工具栏和标题仍对应本次选择。
    selected = media
    guard media.isImage || media.isVideo else {
      if media.isDocument {
        openDocument(media)
      }
      return
    }
    perform(
      {
        let reader = try library.reader(id: media.id, using: grant)
        return (reader, media.isVideo ? nil : try await MediaImageDecoder.render(reader))
      },
      success: { [weak self] reader, bitmap in
        // 关闭查看后的迟到读取不能创建隐藏播放器或恢复已经取消的图片。
        guard let self, self.selected?.id == media.id else {
          return
        }
        if media.isVideo {
          self.playback = LocalPlayback(reader: reader)
          if autoplay {
            self.playback?.toggle()
          }
        } else if let bitmap {
          #if os(macOS)
            self.image = VaultImage(
              cgImage: bitmap, size: CGSize(width: bitmap.width, height: bitmap.height))
          #else
            self.image = VaultImage(cgImage: bitmap)
          #endif
        } else {
          self.message = "系统无法显示此图片。"
          return
        }
      })
  }

  /// 业务作用：仅为当前明确选择的普通文档准备完整验证的只读副本。
  /// 参数说明：
  /// - `media`：当前选中的已认证文档。
  /// 返回：成功发布当前文档；锁定、取消或选择变化后精确清理迟到副本。
  func openDocument(_ media: VaultMedia) {
    guard let library, let store, let grant, selected?.id == media.id, document == nil else {
      return
    }
    perform(
      {
        try VaultDocument.prepare(media, library: library, store: store, using: grant)
      },
      discard: {
        try? $0.close()
      },
      success: { [weak self] document in
        guard let self, self.selected?.id == media.id else {
          try? document.close()
          return
        }
        self.document = document
      })
  }

  /// 业务作用：仅对当前可无损保存的纯文本请求本次独立编辑验证。
  /// 参数说明：无。
  /// 返回：显示密码或手势输入；仍保持只读，尚未开放草稿。
  func requestTextEditing() {
    guard !busy, screen == .library, editingText == nil,
      document?.textFormat != nil, document?.text != nil
    else {
      return
    }
    message = nil
    requestingTextEdit = true
  }

  /// 业务作用：重新验证当前保险箱密码后，才为当前文档开放一次编辑。
  /// 参数说明：
  /// - `credential`：本次输入的独立六位密码或手势，遵循相同的错误冻结规则。
  /// 返回：成功后生成仅内存草稿；失败保持只读，迟到认证立即撤销。
  func authenticateTextEditing(_ credential: VaultCredential) {
    guard requestingTextEdit, editingText == nil, let document,
      let store, let library, let grant
    else {
      return
    }
    perform(
      {
        try VaultTextEdit.authorize(
          document: document, credential: credential, store: store, library: library, using: grant)
      },
      discard: {
        $0.revoke()
      },
      success: { [weak self] edit in
        guard let self, self.requestingTextEdit, self.document === document,
          self.selected?.id == edit.media.id
        else {
          edit.revoke()
          return
        }
        self.textEdit = edit
        self.editingText = document.text
        self.requestingTextEdit = false
        self.refreshCredentialStatus()
      })
  }

  /// 业务作用：接收原生编辑器的内存变更，不写入文件、草稿或查看记录。
  /// 参数说明：
  /// - `text`：编辑器当前正文。
  /// 返回：当前编辑会话有效且未保存时更新内存；其它状态忽略。
  func updateEditingText(_ text: String) {
    guard textEdit != nil, editingText != nil, !busy else {
      return
    }
    editingText = text
  }

  /// 业务作用：用户明确点保存后消费本次编辑权限，并返回新内容的只读查看。
  /// 参数说明：无。
  /// 返回：完整密文发布成功后清空草稿；发布前失败保留本次草稿供调整或退出。
  func saveTextEditing() {
    guard let textEdit, let editingText, let library, !busy else {
      return
    }
    perform(
      {
        try library.replaceText(editingText, editing: textEdit)
      },
      success: { [weak self] media in
        guard let self, self.closeViewer() else {
          return
        }
        self.items = self.items.map {
          $0.id == media.id ? media : $0
        }
        // 新正文发布后立即撤下旧图，尚在生成的旧摘要结果也不能覆盖新内容预览。
        self.thumbnails.removeValue(forKey: media.id)
        self.thumbnailFailures.removeValue(forKey: media.id)
        self.thumbnailOrder.removeAll {
          $0 == media.id
        }
        self.selected = media
        self.openDocument(media)
      })
  }

  /// 业务作用：确认退出或安全锁定时撤销编辑能力并丢弃所有未保存的正文。
  /// 参数说明：无。
  /// 返回：回到原内容只读状态；没有文件写入，下一次编辑必须重新认证。
  func discardTextEditing() {
    textEdit?.revoke()
    textEdit = nil
    editingText = nil
    requestingTextEdit = false
  }

  /// 业务作用：关闭当前查看，丢弃播放器、图片和文档副本，不记录最近文件。
  /// 参数说明：无。
  /// 返回：查看状态清空；明文文档清理失败时返回假并提示，密文不受影响。
  @discardableResult
  func closeViewer() -> Bool {
    discardTextEditing()
    playback?.close()
    playback = nil
    image = nil
    selected = nil
    let previous = document
    document = nil
    do {
      try previous?.close()
      return true
    } catch {
      // 清理未完成时关闭后续读取入口，避免继续开放带有遗留明文的查看会话。
      store?.lock()
      grant = nil
      items = []
      screen = .unavailable
      message = "文档临时副本未能清理，请退出并重新打开保险箱后再查看。"
      return false
    }
  }

  /// 业务作用：为可见媒体及文档排队生成预览，限制并行解码与内存缓存数量。
  /// 参数说明：
  /// - `media`：当前已解锁列表中的可见媒体或文档。
  /// 返回：立即返回；串行生成缩略图，最多排队 48 项并保留 96 张小图，不写入磁盘。
  func requestThumbnail(_ media: VaultMedia) {
    guard screen == .library, !busy, let library, grant != nil,
      media.isImage || media.isVideo || media.isDocument,
      thumbnails[media.id] == nil,
      thumbnailInFlight != media,
      thumbnailFailures[media.id] != media.sha256,
      items.contains(where: {
        $0 == media
      })
    else {
      return
    }
    if let index = thumbnailJobs.firstIndex(where: {
      $0.id == media.id
    }) {
      thumbnailJobs[index] = media
    } else {
      thumbnailJobs.append(media)
    }
    if thumbnailJobs.count > 48 {
      thumbnailJobs.removeFirst()
    }
    guard thumbnailWorker == nil else {
      return
    }
    let expected = epoch
    let generation = thumbnailGeneration
    thumbnailWorker = Task { [weak self] in
      guard let self else {
        return
      }
      defer {
        if self.epoch == expected, self.thumbnailGeneration == generation {
          self.thumbnailWorker = nil
          self.thumbnailInFlight = nil
        }
      }
      while !Task.isCancelled, self.epoch == expected,
        self.thumbnailGeneration == generation, !self.thumbnailJobs.isEmpty
      {
        let media = self.thumbnailJobs.removeFirst()
        guard let grant = self.grant else {
          return
        }
        self.thumbnailInFlight = media
        let entries = self.items
        let worker = Task.detached(priority: .utility) {
          if media.isImage || media.isVideo {
            return try await MediaThumbnail.render(library.reader(id: media.id, using: grant))
          }
          return try DocumentThumbnail.render(
            media, entries: entries, library: library, using: grant)
        }
        do {
          let bytes = try await withTaskCancellationHandler {
            try await worker.value
          } onCancel: {
            worker.cancel()
          }
          // 离开前台或删除媒体后，迟到的解码结果不能重新发布明文预览。
          guard self.epoch == expected, self.thumbnailGeneration == generation, !Task.isCancelled,
            self.screen == .library
          else {
            return
          }
          try grant.check()
          if self.items.contains(where: {
            $0 == media
          }),
            let image = VaultImage(data: bytes)
          {
            self.thumbnails[media.id] = image
            self.thumbnailOrder.removeAll {
              $0 == media.id
            }
            self.thumbnailOrder.append(media.id)
            while self.thumbnailOrder.count > 96 {
              self.thumbnails.removeValue(forKey: self.thumbnailOrder.removeFirst())
            }
          }
        } catch {
          // 单项预览失败时保留类型图标；明确打开文件时仍由完整读取入口报告错误。
          if self.epoch == expected, self.thumbnailGeneration == generation, !Task.isCancelled,
            self.items.contains(media)
          {
            self.thumbnailFailures[media.id] = media.sha256
          }
          continue
        }
      }
    }
  }

  /// 业务作用：撤销当前会话的缩略图任务与全部明文缓存，不留下访问顺序或预览文件。
  /// 参数说明：无。
  /// 返回：队列与内存图片清空；旧任务受会话代次门禁约束，不能恢复缓存。
  private func clearThumbnails() {
    // 缓存代次独立于密码会话，使删除后的旧任务不能清空新队列或发布旧正文图像。
    thumbnailGeneration &+= 1
    thumbnailWorker?.cancel()
    thumbnailWorker = nil
    thumbnailInFlight = nil
    thumbnailJobs = []
    thumbnailOrder = []
    thumbnails = [:]
    thumbnailFailures = [:]
  }

  /// 业务作用：离开前台时先撤销明文能力，再清空界面和未确认恢复材料。
  /// 参数说明：无。
  /// 返回：后续必须重新验证独立密码，不恢复上次选择和进度。
  func lock() {
    automaticLockRequest = nil
    importing = false
    moving = false
    importProgressTask?.cancel()
    importProgressTask = nil
    importProgress = nil
    epoch &+= 1
    operation?.cancel()
    operation = nil
    // 撤销先于界面清空，后台任务不能趁界面切换继续交付明文或删源。
    store?.lock()
    cancelSystemCopy()
    grant = nil
    folderPrompt = nil
    movingMedia = nil
    endSelection()
    moveFailure = nil
    internalDrag = nil
    pendingFolderAction = nil
    clearThumbnails()
    let documentCleaned = closeViewer()
    items = []
    currentFolderID = nil
    savedSources = []
    savedPhotos = []
    cancelOffer()
    busy = false
    progress = 0
    if !documentCleaned {
      message = "文档临时副本未能清理，请退出并重新打开保险箱后再查看。"
    } else if screen != .unavailable {
      message = nil
    }
    photoImportFailure = nil
    if screen == .library {
      screen = .locked
    }
    if screen == .locked {
      refreshCredentialStatus()
    }
  }

  /// 业务作用：用户明确确认丢失凭据后的清空重建，来源原件不参与操作。
  /// 参数说明：无。
  /// 返回：成功后回到首次设置；未完成时显示错误，不声称保留原密文。
  func erase() {
    guard let store else {
      return
    }
    lock()
    perform(
      {
        try store.erase()
      },
      success: { [weak self] in
        self?.screen = .setup
        self?.kind = .pin
      })
  }

  /// 业务作用：取消当前保存或派生操作，并撤销会话以阻止任何延迟删源。
  /// 参数说明：无。
  /// 返回：回到锁定或首次设置界面，已完成的密文由下次解锁重新枚举。
  func cancelOperation() {
    lock()
  }

  /// 业务作用：将操作错误转换为脱敏业务提示，不读取界面状态或泄露来源路径与资源 URL。
  /// 参数说明：
  /// - `error`：底层操作失败。
  /// 返回：适合本地界面的脱敏说明。
  nonisolated private static func message(_ error: Error) -> String {
    (error as? VaultError)?.errorDescription ?? "操作未完成，请检查本地文件、空间与权限。"
  }
}
