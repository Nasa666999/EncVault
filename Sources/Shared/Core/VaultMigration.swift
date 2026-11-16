import CryptoKit
import Darwin
import Foundation
import UniformTypeIdentifiers

/// 迁移失败只说明业务原因，不携带密钥、系统路径或来源密码材料。
enum VaultMigrationError: Error, LocalizedError, Sendable {
  case invalidManifest, changedSource, changedTarget, protectionConflict, hiddenConflict
  case pairing, connection, expired, cancelled, recovery, insufficientSpace
  case transport(Int)
  case peerClosed
  case peerInsufficientSpace

  /// 业务作用：把系统写盘空间错误统一识别为可向对端明确拒绝的业务原因。
  /// 参数说明：
  /// - `error`：本机规划、建目录或保存恢复信息时产生的错误。
  /// 返回：仅空间不足为真，其它权限、格式和设备错误不会被误标。
  static func isInsufficientSpace(_ error: Error) -> Bool {
    if case VaultMigrationError.insufficientSpace = error {
      return true
    }
    let value = error as NSError
    return value.domain == NSPOSIXErrorDomain && value.code == Int(ENOSPC)
      || value.domain == NSCocoaErrorDomain && value.code == NSFileWriteOutOfSpaceError
  }

  /// 业务作用：将迁移拒绝转换为可向两端显示的脱敏说明。
  /// 参数说明：无。
  /// 返回：明确的失败原因，不声称未提交内容已完成，也不允许据此删除来源。
  var errorDescription: String? {
    switch self {
    case .invalidManifest:
      return "迁移清单或文件认证无效，未完成内容没有发布。"
    case .changedSource:
      return "来源已变化，请重新选择并发起迁移；来源文件保留。"
    case .changedTarget:
      return "接收目录已变化，请重新确认目标后继续；已有内容保留。"
    case .protectionConflict:
      return "同名目录的保护状态冲突，不能将受保护内容合并到未保护目录。"
    case .hiddenConflict:
      return "同名目录的隐藏状态冲突，不能将隐藏内容合并到可见目录。"
    case .pairing:
      return "配对信息或对端身份不匹配，请重新配对。"
    case .connection:
      return "连接已中断，可重新配对并继续未完成的迁移。"
    case .transport(let code):
      return "设备连接已中断（系统代码 \(code)），可重新配对继续。"
    case .peerClosed:
      return "另一台设备已结束本次连接，请重新配对继续。"
    case .peerInsufficientSpace:
      return "对方磁盘空间不足，已拒绝本次迁移。来源原件保留。"
    case .expired:
      return "本次配对已过期，请重新配对。"
    case .cancelled:
      return "迁移已停止，来源和目标原有内容保留。"
    case .recovery:
      return "迁移发布状态无法确认，请保留保险箱并重新解锁核对。"
    case .insufficientSpace:
      return "接收设备可用空间不足，来源和目标原有内容保留。"
    }
  }
}

/// 可离开来源设备的目录白名单，不包含原密码或原目录校验材料。
struct VaultMigrationItem: Codable, Sendable, Equatable, Identifiable {
  let id: UUID
  let parentID: UUID?
  let name: String
  let contentType: String
  let byteCount: UInt64
  let sha256: Data
  let protected: Bool
  let hidden: Bool
  let photoAsset: VaultPhotoAsset?

  /// 业务作用：从已授权条目提取迁移所需信息，主动剔除来源目录密码校验结构。
  /// 参数说明：
  /// - `media`：仍保留在来源设备的认证条目。
  /// - `parentID`：所选范围内的父目录；所选根条目为空。
  /// 返回：可在认证连接内交付的白名单记录。
  init(media: VaultMedia, parentID: UUID?) {
    id = media.id
    self.parentID = parentID
    name = media.originalFilename
    contentType = media.contentType
    byteCount = media.byteCount
    sha256 = media.sha256
    protected = media.folderPassword != nil
    hidden = media.isHidden
    photoAsset = media.photoAsset
  }

  /// 业务作用：将迁移描述映射为无密码材料的类型判断视图，不授予读取能力。
  /// 参数说明：无。
  /// 返回：仅用于目录、文档包和照片包分类的临时元数据。
  var shape: VaultMedia {
    VaultMedia(
      id: id, originalFilename: name, contentType: contentType, byteCount: byteCount,
      sha256: sha256, parentID: parentID, hidden: hidden, photoAsset: photoAsset)
  }
}

/// 一次用户选择的稳定内容描述，任务身份用于经过重新授权的续传和幂等提交。
struct VaultMigrationManifest: Codable, Sendable, Equatable {
  let formatVersion: Int
  let taskID: UUID
  let sourceVaultID: UUID
  let roots: [UUID]
  let items: [VaultMigrationItem]

  /// 业务作用：认证整份清单的内容，避免同一任务身份被不同内容复用。
  /// 参数说明：无。
  /// 返回：包含层级、名称、内容摘要与保护标记的稳定摘要。
  func digest() throws -> Data {
    Data(SHA256.hash(data: try VaultCrypto.encode(self)))
  }

  /// 业务作用：在分配磁盘和解析父子关系前限制外来清单，拒绝循环、路径穿越和遗漏内部资源。
  /// 参数说明：无。
  /// 返回：清单为有界、完整且父项在先的目录树时成功，否则拒绝整批。
  func validate() throws {
    guard formatVersion == 1, !items.isEmpty, items.count <= 100_000,
      !roots.isEmpty, Set(roots).count == roots.count
    else {
      throw VaultMigrationError.invalidManifest
    }
    var index: [UUID: VaultMigrationItem] = [:]
    var depth: [UUID: Int] = [:]
    let rootIDs = Set(roots)
    var total: UInt64 = 0
    var fileCounts: [UUID: Int] = [:]
    var byteCounts: [UUID: UInt64] = [:]
    for item in items {
      let addition = total.addingReportingOverflow(item.byteCount)
      guard !addition.overflow, addition.partialValue <= UInt64(Int64.max) else {
        throw VaultMigrationError.invalidManifest
      }
      total = addition.partialValue
      guard index[item.id] == nil, !item.name.isEmpty, item.name != ".", item.name != "..",
        item.name.utf8.count <= 4096, !item.name.contains("/"), !item.name.contains("\0"),
        item.sha256.count == 32, item.byteCount <= UInt64(UInt32.max) * 1_048_576,
        item.shape.isFolder || item.contentType == UTType.data.identifier
          || UTType(item.contentType)?.conforms(to: .image) == true
          || UTType(item.contentType)?.conforms(to: .movie) == true
      else {
        throw VaultMigrationError.invalidManifest
      }
      if let parent = item.parentID {
        guard let ancestor = index[parent], ancestor.shape.isFolder,
          let parentDepth = depth[parent], parentDepth < 255
        else {
          throw VaultMigrationError.invalidManifest
        }
        depth[item.id] = parentDepth + 1
      } else {
        guard rootIDs.contains(item.id) else {
          throw VaultMigrationError.invalidManifest
        }
        depth[item.id] = 0
      }
      if item.shape.isFolder {
        guard item.byteCount == 0, item.sha256 == Data(SHA256.hash(data: Data())) else {
          throw VaultMigrationError.invalidManifest
        }
      } else if item.protected || item.hidden || item.photoAsset != nil {
        throw VaultMigrationError.invalidManifest
      }
      if item.shape.isFilePackage && (item.protected || item.hidden) {
        throw VaultMigrationError.invalidManifest
      }
      index[item.id] = item
      fileCounts[item.id] = item.shape.isFolder ? 0 : 1
      byteCounts[item.id] = item.byteCount
    }
    guard
      Set(
        items.filter {
          $0.parentID == nil
        }.map(\.id)) == Set(roots)
    else {
      throw VaultMigrationError.invalidManifest
    }
    for item in items.reversed() {
      if let parent = item.parentID {
        fileCounts[parent, default: 0] += fileCounts[item.id, default: 0]
        byteCounts[parent, default: 0] += byteCounts[item.id, default: 0]
      }
    }
    for item in items {
      if let photo = item.photoAsset {
        guard let primary = index[photo.primaryID], let manifest = index[photo.manifestID],
          primary.id != manifest.id,
          primary.parentID != nil, manifest.parentID == item.id,
          primary.byteCount == photo.byteCount, primary.sha256 == photo.sha256,
          primary.contentType == photo.contentType, !primary.shape.isFolder,
          !manifest.shape.isFolder, photo.resourceCount > 0, photo.resourceCount <= 4096,
          fileCounts[item.id] == photo.resourceCount + 1,
          byteCounts[item.id, default: 0] >= manifest.byteCount,
          byteCounts[item.id, default: 0] - manifest.byteCount == photo.totalByteCount
        else {
          throw VaultMigrationError.invalidManifest
        }
        for resource in [primary, manifest] {
          var parent = resource.parentID
          var found = false
          while let value = parent {
            if value == item.id {
              found = true
              break
            }
            parent = index[value]?.parentID
          }
          guard found else {
            throw VaultMigrationError.invalidManifest
          }
        }
      }
    }
  }
}

private struct VaultMigrationOutgoing: Codable {
  let manifest: VaultMigrationManifest
  let fingerprint: Data
  let requiresRoot: Bool
}

/// 待续传任务只在本机解锁后展示，关闭 ROOT 时不展示受限来源名称。
struct VaultMigrationPending: Identifiable, Sendable {
  let id: UUID
  let title: String
  let requiresRoot: Bool
}

/// 未入库接收的清理快照只包含任务身份与占用量，不向界面暴露受限目录名称。
struct VaultMigrationStaging: Sendable {
  let taskIDs: [UUID]
  let byteCount: UInt64
}

extension VaultLibrary {
  /// 业务作用：统计可停止续传的接收暂存，供用户明确确认清理范围。
  /// 参数说明：
  /// - `grant`：当前已解锁的 App 会话。
  /// 返回：不含正在写入或已经入库任务的身份和磁盘占用，不读取媒体正文。
  func incomingMigrationStaging(using grant: VaultGrant) throws -> VaultMigrationStaging {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    try VaultMigrationStorage.recover(store, using: grant)
    let root = try VaultMigrationStorage.directory(store)
    var ids: [UUID] = []
    var bytes: UInt64 = 0
    for id in try VaultMigrationStorage.stagedIDs(in: root) {
      guard
        let lease = try? VaultMigrationLease(root.appendingPathComponent(id.uuidString + ".lock"))
      else {
        continue
      }
      defer {
        lease.release()
      }
      if FileManager.default.fileExists(
        atPath: root.appendingPathComponent(id.uuidString + ".receipt").path)
      {
        continue
      }
      let size = try VaultMigrationStorage.stagedBytes(
        root.appendingPathComponent(id.uuidString), using: grant)
      let sum = bytes.addingReportingOverflow(size)
      guard !sum.overflow else {
        throw VaultError.storage
      }
      bytes = sum.partialValue
      ids.append(id)
    }
    return VaultMigrationStaging(taskIDs: ids, byteCount: bytes)
  }

  /// 业务作用：只清理用户确认过且尚未入库的接收候选，释放取消任务占用的空间。
  /// 参数说明：
  /// - `ids`：确认界面固定的任务身份，不扩展到确认后新增的任务。
  /// - `grant`：当前 App 会话，锁定后不能继续删除。
  /// 返回：实际清理的任务和字节数；活动任务拒绝，已提交任务和正式媒体始终保留。
  func discardIncomingMigrations(_ ids: [UUID], using grant: VaultGrant) throws
    -> VaultMigrationStaging
  {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    try VaultMigrationStorage.recover(store, using: grant)
    guard Set(ids).count == ids.count else {
      throw VaultError.invalidSelection
    }
    let root = try VaultMigrationStorage.directory(store)
    var cleared: [UUID] = []
    var bytes: UInt64 = 0
    for id in ids {
      let lease = try VaultMigrationLease(root.appendingPathComponent(id.uuidString + ".lock"))
      defer {
        lease.release()
      }
      let directory = root.appendingPathComponent(id.uuidString)
      if !FileManager.default.fileExists(atPath: directory.path)
        || FileManager.default.fileExists(
          atPath: root.appendingPathComponent(id.uuidString + ".receipt").path)
      {
        continue
      }
      let size = try VaultMigrationStorage.stagedBytes(directory, using: grant)
      let sum = bytes.addingReportingOverflow(size)
      guard !sum.overflow else {
        throw VaultError.storage
      }
      // 排他持有接收任务后只删除其私有候选目录，不能触及 media、提交收据或来源待发送记录。
      try grant.access { _ in
        try FileManager.default.removeItem(at: directory)
        try VaultStorage.synchronizeDirectory(root)
      }
      cleared.append(id)
      bytes = sum.partialValue
    }
    return VaultMigrationStaging(taskIDs: cleared, byteCount: bytes)
  }

  /// 业务作用：为接收任务建立独立目录验证范围，沿用已有授权而不向正常浏览会话新增权限。
  /// 参数说明：
  /// - `parent`：本机已解锁的正常浏览会话。
  /// 返回：当前有效目录证明的任务副本；新验证仅作用于该副本，锁定仍由父会话撤销。
  func migrationReceivingGrant(using parent: VaultGrant) throws -> VaultGrant {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(parent)
    let scoped = try parent.access {
      root in
      VaultGrant(root: root, vaultID: parent.vaultID, parent: parent)
    }
    for folder in try migrationEntries(using: parent) {
      guard let protection = folder.folderPassword else {
        continue
      }
      do {
        try parent.access(folders: [folder.id: protection.revision]) {
          _ in ()
        }
        try scoped.allowFolder(folder.id, revision: protection.revision)
      } catch VaultError.folderPasswordRequired {
        continue
      }
    }
    return scoped
  }
}

/// 来源能力只覆盖用户选定的快照，ROOT 身份变化即撤销受限内容的后续交付。
final class VaultMigrationSource: @unchecked Sendable {
  let manifest: VaultMigrationManifest
  private let library: VaultLibrary
  private let parent: VaultGrant
  private let grant: VaultGrant
  private let originals: [UUID: VaultMedia]
  private let rootToken: UUID?
  private let folderRequirements: [UUID: UUID]

  /// 业务作用：以当前选择建立单次迁移能力，ROOT 关闭时拒绝任一受限祖先或后代。
  /// 参数说明：
  /// - `library`：来源保险箱。
  /// - `ids`：用户明确选择的条目，空数组表示全部根项目。
  /// - `parent`：当前已解锁的 App 会话。
  /// - `taskID`：继续已授权任务时沿用的身份，新任务为空。
  /// 返回：不包含来源密码的清单与持续受会话约束的读取能力。
  init(library: VaultLibrary, ids: [UUID], using parent: VaultGrant, taskID: UUID? = nil) throws {
    library.mutation.lock()
    defer {
      library.mutation.unlock()
    }
    try library.store.authorize(parent)
    let all = try library.migrationEntries(using: parent)
    let index = Dictionary(
      uniqueKeysWithValues: all.map {
        ($0.id, $0)
      })
    let selected =
      ids.isEmpty
      ? all.filter {
        $0.parentID == nil
      }.map(\.id) : ids
    guard !selected.isEmpty, Set(selected).count == selected.count,
      selected.allSatisfy({
        index[$0] != nil
      })
    else {
      throw VaultError.invalidSelection
    }
    var children: [UUID: [VaultMedia]] = [:]
    for media in all {
      if let id = media.parentID {
        children[id, default: []].append(media)
      }
    }
    var ordered: [VaultMedia] = []
    var seen: Set<UUID> = []
    var queue = selected
    var position = 0
    while position < queue.count {
      let id = queue[position]
      position += 1
      guard seen.insert(id).inserted, let media = index[id], seen.count <= 100_000 else {
        throw VaultError.invalidSelection
      }
      ordered.append(media)
      queue.append(contentsOf: children[id, default: []].map(\.id))
    }
    var requirements: [UUID: UUID] = [:]
    var restricted = false
    for media in ordered {
      var next: UUID? = media.isFolder ? media.id : media.parentID
      var path: Set<UUID> = []
      while let id = next {
        guard path.count < 256, path.insert(id).inserted, let ancestor = index[id],
          ancestor.isFolder
        else {
          throw VaultMigrationError.invalidManifest
        }
        if let protection = ancestor.folderPassword {
          requirements[id] = protection.revision
          restricted = true
        }
        restricted = restricted || ancestor.isHidden
        next = ancestor.parentID
      }
    }
    let token = try parent.rootToken()
    // 浏览时输入的目录密码不能代替向外迁移受限内容所需的 ROOT 权威。
    guard !restricted || token != nil else {
      throw VaultError.rootRequired
    }
    self.library = library
    self.parent = parent
    rootToken = restricted ? token : nil
    folderRequirements = requirements
    grant = try parent.access(rootToken: rootToken) {
      root in
      VaultGrant(root: root, vaultID: parent.vaultID, parent: parent)
    }
    for (id, revision) in requirements {
      try grant.allowFolder(id, revision: revision)
    }
    originals = Dictionary(
      uniqueKeysWithValues: ordered.map {
        ($0.id, $0)
      })
    manifest = VaultMigrationManifest(
      formatVersion: 1, taskID: taskID ?? UUID(), sourceVaultID: parent.vaultID,
      roots: selected,
      items: ordered.map {
        VaultMigrationItem(
          media: $0,
          parentID: $0.parentID.flatMap {
            seen.contains($0) ? $0 : nil
          })
      })
    try manifest.validate()
  }

  /// 业务作用：在下一次网络交付或最终确认前复验来源会话与本次 ROOT 激活身份。
  /// 参数说明：无。
  /// 返回：仍拥有该次选择权威时成功，锁定、取消或重新开启 ROOT 均不能复用旧能力。
  func check() throws {
    try Task.checkCancellation()
    try grant.access(rootToken: rootToken) {
      _ in
      ()
    }
  }

  /// 业务作用：为所选内容文件取得分块读取器，不交付来源目录验证结构或整库主密钥。
  /// 参数说明：
  /// - `id`：清单内的普通内容文件身份。
  /// 返回：来源元数据未变化且权威仍有效的读取器，目录或清单外请求拒绝。
  func reader(id: UUID) throws -> VaultMediaReader {
    try check()
    guard let expected = originals[id], !expected.isFolder else {
      throw VaultMigrationError.invalidManifest
    }
    let reader = try VaultMediaReader(
      url: library.store.mediaDirectory.appendingPathComponent(id.uuidString + ".evm"),
      grant: grant, folderRequirements: folderRequirements, rootToken: rootToken)
    guard reader.media == expected else {
      throw VaultMigrationError.changedSource
    }
    return reader
  }

  /// 业务作用：发送结束后核对完整来源快照，不能把目录变化误报为同一批次成功。
  /// 参数说明：无。
  /// 返回：清单中全部条目仍与授权快照一致时成功。
  func verifySnapshot() throws {
    try check()
    library.mutation.lock()
    defer {
      library.mutation.unlock()
    }
    let current = Dictionary(
      uniqueKeysWithValues: try library.migrationEntries(using: grant).map {
        ($0.id, $0)
      })
    guard
      originals.allSatisfy({
        current[$0.key] == $0.value
      })
    else {
      throw VaultMigrationError.changedSource
    }
    try check()
  }

  /// 业务作用：结束迁移时撤销所选范围的临时证明，不影响来源普通浏览能力。
  /// 参数说明：无。
  /// 返回：旧任务不能继续读取或确认发送。
  func revoke() {
    grant.revoke()
  }

  /// 业务作用：为经过用户确认的发送保存加密续传依据，不记录已完成的来源历史。
  /// 参数说明：无。
  /// 返回：可在重新解锁、重新配对和重新检查 ROOT 后继续同一任务。
  func savePending() throws {
    try check()
    let directory = try VaultMigrationStorage.directory(library.store)
    let fingerprint = Data(
      SHA256.hash(
        data: try VaultCrypto.encode(
          originals.values.sorted {
            $0.id.uuidString < $1.id.uuidString
          })))
    try VaultMigrationStorage.write(
      VaultMigrationOutgoing(
        manifest: manifest, fingerprint: fingerprint, requiresRoot: rootToken != nil),
      to: directory.appendingPathComponent(manifest.taskID.uuidString + ".outgoing"), using: grant)
  }

  /// 业务作用：接收端持久提交得到认证确认后删除本次待发送记录，来源媒体不删除。
  /// 参数说明：无。
  /// 返回：该任务不再作为待续传任务展示，不改变来源文件或保护。
  func finishPending() throws {
    try check()
    let directory = try VaultMigrationStorage.directory(library.store)
    let url = directory.appendingPathComponent(manifest.taskID.uuidString + ".outgoing")
    if FileManager.default.fileExists(atPath: url.path) {
      let saved = try VaultMigrationStorage.read(
        VaultMigrationOutgoing.self, from: url, using: grant)
      guard saved.manifest == manifest else {
        throw VaultMigrationError.changedSource
      }
      try FileManager.default.removeItem(at: url)
      try VaultStorage.synchronizeDirectory(directory)
    }
  }

  /// 业务作用：列出尚未完成的用户迁移任务，不在 ROOT 关闭时泄露受限来源名称。
  /// 参数说明：
  /// - `library`：本机来源保险箱。
  /// - `grant`：已解锁的本机会话。
  /// 返回：有界待续传描述，不包含密码或外部路径。
  static func pending(in library: VaultLibrary, using grant: VaultGrant) throws
    -> [VaultMigrationPending]
  {
    try library.store.authorize(grant)
    let directory = try VaultMigrationStorage.directory(library.store)
    let root = try grant.rootToken() != nil
    var result: [VaultMigrationPending] = []
    for url in try FileManager.default.contentsOfDirectory(
      at: directory, includingPropertiesForKeys: nil)
    where url.pathExtension == "outgoing" {
      guard result.count < 1000 else {
        throw VaultMigrationError.invalidManifest
      }
      let saved = try VaultMigrationStorage.read(
        VaultMigrationOutgoing.self, from: url, using: grant)
      guard url.deletingPathExtension().lastPathComponent == saved.manifest.taskID.uuidString else {
        throw VaultMigrationError.recovery
      }
      let first =
        saved.manifest.items.first(where: {
          saved.manifest.roots.contains($0.id)
        })?.name ?? "迁移任务"
      result.append(
        VaultMigrationPending(
          id: saved.manifest.taskID,
          title: saved.requiresRoot && !root ? "需要 ROOT 的待续传任务" : first,
          requiresRoot: saved.requiresRoot))
    }
    return result.sorted {
      $0.id.uuidString < $1.id.uuidString
    }
  }

  /// 业务作用：重新选择待续传任务时复验完整来源快照，不复用旧 ROOT 身份或旧配对。
  /// 参数说明：
  /// - `id`：用户明确选择的本机待续传任务身份。
  /// - `library`：原来源保险箱。
  /// - `grant`：重新解锁并按需开启 ROOT 的当前会话。
  /// 返回：来源未变化的新用途能力；内容、目录或保护变化时要求重新发起。
  static func resume(id: UUID, in library: VaultLibrary, using grant: VaultGrant) throws
    -> VaultMigrationSource
  {
    let directory = try VaultMigrationStorage.directory(library.store)
    let saved = try VaultMigrationStorage.read(
      VaultMigrationOutgoing.self,
      from: directory.appendingPathComponent(id.uuidString + ".outgoing"), using: grant)
    let source = try VaultMigrationSource(
      library: library, ids: saved.manifest.roots, using: grant, taskID: id)
    let fingerprint = Data(
      SHA256.hash(
        data: try VaultCrypto.encode(
          source.originals.values.sorted {
            $0.id.uuidString < $1.id.uuidString
          })))
    guard source.manifest == saved.manifest, fingerprint == saved.fingerprint else {
      source.revoke()
      throw VaultMigrationError.changedSource
    }
    return source
  }

  /// 业务作用：释放任务时补充撤销仍存活的迁移能力。
  /// 参数说明：无。
  /// 返回：不保留可供后续任务复用的读取授权。
  deinit {
    revoke()
  }
}

/// 私有接收候选只写认证密文；内存中的单个明文分块不会成为系统文件。
final class VaultMigrationWriter {
  let media: VaultMedia
  private(set) var url: URL
  private let grant: VaultGrant
  private let folders: [UUID: UUID]
  private let rootToken: UUID?
  private let key: SymmetricKey
  private let identity: MediaIdentity
  private let headerDigest: Data
  private let output: FileHandle
  private var hash = SHA256()
  private(set) var count: UInt64 = 0
  private var closed = false

  /// 业务作用：为目标身份创建全新随机密钥和 nonce 的候选文件，不复用来源密钥。
  /// 参数说明：
  /// - `media`：已经确定名称、目录关系与本机保护的目标元数据。
  /// - `url`：本任务独占的密文候选路径。
  /// - `grant`：接收设备当前有效的本机会话。
  /// - `folders`：接收任务需要持续保留的目标目录证明。
  /// - `rootToken`：本次接收依赖的固定 ROOT 激活身份。
  /// 返回：只持有有界写入状态的接收器；创建失败不产生正常媒体条目。
  init(
    media: VaultMedia, url: URL, using grant: VaultGrant,
    folders: [UUID: UUID] = [:], rootToken: UUID? = nil
  ) throws {
    self.media = media
    self.url = url
    self.grant = grant
    self.folders = folders
    self.rootToken = rootToken
    let identity = MediaIdentity(
      formatVersion: 1, id: media.id, vaultID: grant.vaultID, byteCount: media.byteCount,
      chunkSize: VaultMediaReader.chunkSize,
      chunkCount: Int((media.byteCount + 1_048_575) / 1_048_576),
      noncePrefix: try VaultCrypto.random(8))
    self.identity = identity
    let raw = try VaultCrypto.random(32)
    key = SymmetricKey(data: raw)
    let context = try VaultCrypto.encode(identity)
    let header = try grant.access(folders: folders, rootToken: rootToken) {
      root in
      MediaHeader(
        identity: identity,
        wrappedKey: try VaultCrypto.seal(raw, key: SymmetricKey(data: root), context: context),
        metadata: try VaultCrypto.seal(
          VaultCrypto.encode(media), key: VaultCrypto.key(raw, context: Data("metadata".utf8)),
          context: context))
    }
    let bytes = try VaultCrypto.encode(header)
    guard bytes.count <= 65_536 else {
      throw VaultMigrationError.invalidManifest
    }
    headerDigest = Data(SHA256.hash(data: bytes))
    output = try VaultStorage.create(url)
    try output.write(contentsOf: VaultMediaReader.magic)
    var length = UInt32(bytes.count).bigEndian
    try withUnsafeBytes(of: &length) {
      try output.write(contentsOf: Data($0))
    }
    try output.write(contentsOf: bytes)
  }

  /// 业务作用：将已认证连接交付的一个完整明文分块立即加密为目标候选。
  /// 参数说明：
  /// - `data`：恰好覆盖下一分块的内存字节，不接受重放或越界长度。
  /// 返回：候选只增加当前分块的认证密文，失权时不写入后续字节。
  func append(_ data: Data) throws {
    guard !closed, count < media.byteCount,
      data.count == Int(min(UInt64(VaultMediaReader.chunkSize), media.byteCount - count))
    else {
      throw VaultMigrationError.invalidManifest
    }
    try Task.checkCancellation()
    try grant.access(folders: folders, rootToken: rootToken) {
      _ in
      let index = Int(count / UInt64(VaultMediaReader.chunkSize))
      let sealed = try AES.GCM.seal(
        data, using: key,
        nonce: VaultMediaReader.nonce(prefix: identity.noncePrefix, index: index),
        authenticating: VaultMediaReader.chunkContext(
          headerDigest, index: index, length: data.count))
      try output.write(contentsOf: sealed.ciphertext)
      try output.write(contentsOf: sealed.tag)
      hash.update(data: data)
      count += UInt64(data.count)
    }
  }

  /// 业务作用：完成候选的内容摘要、持久化和逐块回读，不把部分文件标记为可发布。
  /// 参数说明：无。
  /// 返回：全部字节与清单摘要一致且认证回读成功后关闭写入。
  func finish() throws {
    guard !closed, count == media.byteCount, Data(hash.finalize()) == media.sha256 else {
      throw VaultMigrationError.invalidManifest
    }
    try grant.access(folders: folders, rootToken: rootToken) {
      _ in
      ()
    }
    try output.synchronize()
    try output.close()
    closed = true
    try VaultMediaReader(
      url: url, grant: grant, folderRequirements: folders, rootToken: rootToken
    ).verify()
  }

  /// 业务作用：恢复已认证的完整分块，并在继续写入前轮换文件密钥和 nonce，避免重复使用旧 nonce。
  /// 参数说明：
  /// - `media`：本次固定的目标元数据。
  /// - `url`：任务内可能包含部分密文的候选。
  /// - `grant`：当前重新授权的本机会话。
  /// - `folders`：接收依赖的目标目录证明。
  /// - `rootToken`：当前任务绑定的 ROOT 激活身份。
  /// 返回：已恢复合法前缀的写入器；损坏候选从该文件开头重新接收，失权时不清除可恢复内容。
  static func resume(
    media: VaultMedia, url: URL, using grant: VaultGrant,
    folders: [UUID: UUID], rootToken: UUID?
  ) throws -> VaultMigrationWriter {
    guard FileManager.default.fileExists(atPath: url.path) else {
      return try VaultMigrationWriter(
        media: media, url: url, using: grant, folders: folders, rootToken: rootToken)
    }
    let temporary = url.deletingLastPathComponent().appendingPathComponent(".\(UUID()).partial")
    var moved = false
    defer {
      if !moved {
        try? FileManager.default.removeItem(at: temporary)
      }
    }
    let writer = try VaultMigrationWriter(
      media: media, url: temporary, using: grant, folders: folders, rootToken: rootToken)
    do {
      let source = try FileHandle(forReadingFrom: url)
      defer {
        try? source.close()
      }
      let sourceIdentity = try SourceIdentity(source)
      guard try VaultStorage.read(source, count: 8) == VaultMediaReader.magic else {
        throw VaultMigrationError.invalidManifest
      }
      let sizeData = try VaultStorage.read(source, count: 4)
      let size = sizeData.reduce(0) {
        ($0 << 8) | Int($1)
      }
      guard size > 0, size <= 65_536 else {
        throw VaultMigrationError.invalidManifest
      }
      let bytes = try VaultStorage.read(source, count: size)
      let header = try JSONDecoder().decode(MediaHeader.self, from: bytes)
      guard header.identity.id == media.id, header.identity.vaultID == grant.vaultID,
        header.identity.formatVersion == 1,
        header.identity.chunkSize == VaultMediaReader.chunkSize,
        header.identity.byteCount == media.byteCount, header.identity.noncePrefix.count == 8,
        header.identity.chunkCount == writer.identity.chunkCount
      else {
        throw VaultMigrationError.invalidManifest
      }
      let key: SymmetricKey = try grant.access(folders: folders, rootToken: rootToken) {
        root in
        let context = try VaultCrypto.encode(header.identity)
        let material = try VaultCrypto.open(
          header.wrappedKey, key: SymmetricKey(data: root), context: context)
        guard material.count == 32 else {
          throw VaultMigrationError.invalidManifest
        }
        let metadata = try VaultCrypto.open(
          header.metadata, key: VaultCrypto.key(material, context: Data("metadata".utf8)),
          context: context)
        guard try JSONDecoder().decode(VaultMedia.self, from: metadata) == media else {
          throw VaultMigrationError.invalidManifest
        }
        return SymmetricKey(data: material)
      }
      let digest = Data(SHA256.hash(data: bytes))
      var available = max(0, sourceIdentity.size - Int64(12 + size))
      for index in 0..<header.identity.chunkCount {
        let length = Int(min(UInt64(VaultMediaReader.chunkSize), media.byteCount - writer.count))
        if available < Int64(length + 16) {
          break
        }
        // 续传可能轮换整个大文件，逐块释放 Foundation 临时对象，避免前缀大小转化为内存峰值。
        try autoreleasepool {
          let ciphertext = try VaultStorage.read(source, count: length)
          let tag = try VaultStorage.read(source, count: 16)
          let plaintext = try grant.access(folders: folders, rootToken: rootToken) {
            _ in
            try AES.GCM.open(
              AES.GCM.SealedBox(
                nonce: VaultMediaReader.nonce(prefix: header.identity.noncePrefix, index: index),
                ciphertext: ciphertext, tag: tag), using: key,
              authenticating: VaultMediaReader.chunkContext(digest, index: index, length: length))
          }
          try writer.append(plaintext)
        }
        available -= Int64(length + 16)
      }
      guard try SourceIdentity(source) == sourceIdentity else {
        throw VaultMigrationError.changedTarget
      }
      if writer.count == media.byteCount, Data(writer.hash.finalize()) != media.sha256 {
        throw VaultMigrationError.invalidManifest
      }
    } catch {
      try grant.access(folders: folders, rootToken: rootToken) {
        _ in
        ()
      }
      if Task.isCancelled {
        throw VaultMigrationError.cancelled
      }
      switch error {
      case VaultMigrationError.invalidManifest, VaultError.corrupt,
        CryptoKitError.authenticationFailure, CryptoKitError.incorrectParameterSize,
        CryptoKitError.incorrectKeySize:
        break
      case is DecodingError:
        break
      default:
        throw error
      }
      // 损坏前缀不能成为续传依据；新的候选使用全新密钥，旧字节不会被同 nonce 重写。
      try? writer.output.close()
      try? FileManager.default.removeItem(at: temporary)
      let fresh = try VaultMigrationWriter(
        media: media, url: temporary, using: grant, folders: folders, rootToken: rootToken)
      try fresh.output.synchronize()
      guard Darwin.rename(temporary.path, url.path) == 0 else {
        throw VaultError.storage
      }
      fresh.url = url
      moved = true
      return fresh
    }
    try writer.output.synchronize()
    guard Darwin.rename(temporary.path, url.path) == 0 else {
      throw VaultError.storage
    }
    writer.url = url
    moved = true
    return writer
  }

  /// 业务作用：断开或退出时关闭候选句柄，未完成内容继续保持为私有密文。
  /// 参数说明：无。
  /// 返回：不删除可供重新授权后恢复的候选，也不发布它。
  deinit {
    try? output.close()
  }
}

/// 目标目录映射只持久化在本机加密任务记录中，不向来源交付目标密码材料。
struct VaultMigrationMapping: Codable, Sendable {
  let sourceID: UUID
  var media: VaultMedia
  let isNew: Bool
}

/// 入库收据是幂等提交依据，不授予源端删除权。
struct VaultMigrationReceipt: Codable, Sendable {
  let taskID: UUID
  let manifestDigest: Data
  let roots: [UUID]
  let files: Int
  let renamed: Int
  let merged: Int
}

private struct VaultMigrationState: Codable {
  let manifest: VaultMigrationManifest
  let parentID: UUID?
  let mappings: [VaultMigrationMapping]
  let expectedTargets: [VaultMedia]
}

private struct VaultMigrationPublishedFile: Codable {
  let id: UUID
  let digest: Data
}

private struct VaultMigrationJournal: Codable {
  let taskID: UUID
  let manifestDigest: Data
  let files: [VaultMigrationPublishedFile]
}

/// 单个接收任务的排他持有者，取消后旧写入器先失权，再允许新会话恢复。
private final class VaultMigrationLease {
  private let mutex = NSLock()
  private var descriptor: Int32

  /// 业务作用：拒绝同一任务同时被两个接收流程写入。
  /// 参数说明：
  /// - `url`：本机迁移目录内按任务身份分配的锁文件。
  /// 返回：取得本机排他锁；已有持有者或路径异常时拒绝。
  init(_ url: URL) throws {
    descriptor = Darwin.open(url.path, O_RDWR | O_CREAT | O_NOFOLLOW | O_EXLOCK | O_NONBLOCK, 0o600)
    guard descriptor >= 0 else {
      if errno == ENOSPC {
        throw VaultMigrationError.insufficientSpace
      }
      throw VaultMigrationError.changedTarget
    }
  }

  /// 业务作用：在旧能力已撤销后释放本任务排他持有权。
  /// 参数说明：无。
  /// 返回：重复释放无副作用，新的恢复流程可以重新取得任务锁。
  func release() {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    if descriptor >= 0 {
      Darwin.close(descriptor)
      descriptor = -1
    }
  }

  /// 业务作用：初始化失败或任务释放时补充关闭排他句柄。
  /// 参数说明：无。
  /// 返回：不删除任何接收候选。
  deinit {
    release()
  }
}

/// 所有恢复信息都由本机保险箱主密钥保护，磁盘任务名只使用随机身份。
enum VaultMigrationStorage {
  /// 业务作用：仅识别迁移命名空间内的接收任务目录，不跟随链接或接受外来路径。
  /// 参数说明：
  /// - `root`：本机迁移专用目录。
  /// 返回：规范 UUID 命名的真实目录身份，不包含发送记录和提交日志。
  static func stagedIDs(in root: URL) throws -> [UUID] {
    var result: [UUID] = []
    for url in try FileManager.default.contentsOfDirectory(
      at: root, includingPropertiesForKeys: nil)
    {
      guard let id = UUID(uuidString: url.lastPathComponent),
        id.uuidString == url.lastPathComponent,
        try FileManager.default.attributesOfItem(atPath: url.path)[.type] as? FileAttributeType
          == .typeDirectory
      else {
        continue
      }
      result.append(id)
    }
    return result.sorted { $0.uuidString < $1.uuidString }
  }

  /// 业务作用：有界统计当前接收格式的平铺密文，不解密内容或遍历到命名空间之外。
  /// 参数说明：
  /// - `directory`：规范任务身份对应的私有目录。
  /// - `grant`：清理期间必须持续有效的 App 会话。
  /// 返回：所有候选与恢复记录的实际字节数；链接、嵌套目录和异常大小拒绝清理。
  static func stagedBytes(_ directory: URL, using grant: VaultGrant) throws -> UInt64 {
    guard
      try FileManager.default.attributesOfItem(atPath: directory.path)[.type] as? FileAttributeType
        == .typeDirectory
    else {
      throw VaultError.storage
    }
    var bytes: UInt64 = 0
    for file in try FileManager.default.contentsOfDirectory(
      at: directory, includingPropertiesForKeys: nil)
    {
      try grant.check()
      let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
      guard attributes[.type] as? FileAttributeType == .typeRegular,
        let size = attributes[.size] as? NSNumber
      else {
        throw VaultError.storage
      }
      let sum = bytes.addingReportingOverflow(size.uint64Value)
      guard !sum.overflow else {
        throw VaultError.storage
      }
      bytes = sum.partialValue
    }
    return bytes
  }

  /// 业务作用：撤回接收目标已被删除的未入库暂存，使删除文件夹同时释放其待接收数据。
  /// 参数说明：
  /// - `store`：当前保险箱。
  /// - `liveIDs`：已经认证的正式媒体身份集合。
  /// - `grant`：当前 App 会话。
  /// 返回：只清理有认证恢复记录且目标身份已消失的任务；活动、已提交或无法确认归属的任务保留。
  static func discardOrphanedIncoming(
    _ store: VaultStore, liveIDs: Set<UUID>, using grant: VaultGrant
  ) throws {
    let root = try directory(store)
    for id in try stagedIDs(in: root) {
      guard
        let lease = try? VaultMigrationLease(root.appendingPathComponent(id.uuidString + ".lock"))
      else {
        continue
      }
      defer {
        lease.release()
      }
      let directory = root.appendingPathComponent(id.uuidString)
      if FileManager.default.fileExists(
        atPath: root.appendingPathComponent(id.uuidString + ".receipt").path)
      {
        continue
      }
      let state: VaultMigrationState
      do {
        state = try read(
          VaultMigrationState.self, from: directory.appendingPathComponent("receive.evp"),
          using: grant)
        try state.manifest.validate()
      } catch {
        try grant.check()
        continue
      }
      guard state.manifest.taskID == id else {
        continue
      }
      let targets = Set(state.expectedTargets.map(\.id)).union(state.parentID.map { [$0] } ?? [])
      guard !targets.isSubset(of: liveIDs) else {
        continue
      }
      // 只有稳定目标身份的消失才表示用户已删除接收位置，同名新目录不能继承或保住旧任务。
      _ = try stagedBytes(directory, using: grant)
      try grant.access { _ in
        try FileManager.default.removeItem(at: directory)
        try VaultStorage.synchronizeDirectory(root)
      }
    }
  }

  /// 业务作用：在请求正文前取得接收卷容量，不把未知容量当作空间充足。
  /// 参数说明：
  /// - `url`：本机迁移暂存所在的私有目录。
  /// 返回：优先采用当前可用字节，其次采用系统可回收容量；均不可取时拒绝开始。
  static func availableCapacity(at url: URL) throws -> UInt64 {
    let values = try url.resourceValues(forKeys: [
      .volumeAvailableCapacityKey, .volumeAvailableCapacityForImportantUsageKey,
    ])
    if let capacity = values.volumeAvailableCapacity {
      return UInt64(max(0, capacity))
    }
    if let capacity = values.volumeAvailableCapacityForImportantUsage {
      return UInt64(max(0, capacity))
    }
    throw VaultError.storage
  }
  /// 业务作用：取得本机迁移专用目录，与正常媒体及文档明文暂存分离。
  /// 参数说明：
  /// - `store`：本机独占的保险箱。
  /// 返回：权限收紧且不进入普通媒体枚举的目录。
  static func directory(_ store: VaultStore) throws -> URL {
    let root = store.directory.appendingPathComponent("migration.noindex", isDirectory: true)
    try VaultStorage.directory(root)
    return root
  }

  /// 业务作用：为任务记录派生本机用途密钥，将任务身份和保险箱身份绑定到密文。
  /// 参数说明：
  /// - `value`：只在本机恢复或幂等检查使用的结构。
  /// - `url`：以本机随机身份分配的记录路径。
  /// - `grant`：仍有效的本机会话。
  /// 返回：原子持久化记录；失权时不写入密码或裸密钥。
  static func write<T: Encodable>(_ value: T, to url: URL, using grant: VaultGrant) throws {
    let context = Data("EncVault/migration/\(grant.vaultID)/\(url.lastPathComponent)".utf8)
    let encoded = try VaultCrypto.encode(value)
    guard encoded.count <= 64 * 1024 * 1024 else {
      throw VaultMigrationError.invalidManifest
    }
    try grant.access {
      root in
      let key = VaultCrypto.key(root, context: Data("migration-state".utf8))
      try VaultStorage.atomicWrite(
        try VaultCrypto.seal(encoded, key: key, context: context), to: url)
    }
  }

  /// 业务作用：只在解锁后认证读取本机恢复记录，拒绝跨任务替换或超长输入。
  /// 参数说明：
  /// - `type`：期待的本机记录结构。
  /// - `url`：当前任务记录。
  /// - `grant`：仍有效的本机会话。
  /// 返回：完整认证的结构，失败时不尝试把损坏内容作为空任务继续。
  static func read<T: Decodable>(_ type: T.Type, from url: URL, using grant: VaultGrant) throws -> T
  {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard attributes[.type] as? FileAttributeType == .typeRegular,
      let size = attributes[.size] as? NSNumber, size.uint64Value <= 65 * 1024 * 1024
    else {
      throw VaultMigrationError.recovery
    }
    let context = Data("EncVault/migration/\(grant.vaultID)/\(url.lastPathComponent)".utf8)
    let bytes = try Data(contentsOf: url)
    return try grant.access {
      root in
      let key = VaultCrypto.key(root, context: Data("migration-state".utf8))
      return try JSONDecoder().decode(
        type, from: VaultCrypto.open(bytes, key: key, context: context))
    }
  }

  /// 业务作用：对候选密文计算有界摘要，以便崩溃恢复只撤回本任务发布的准确字节。
  /// 参数说明：
  /// - `url`：本任务创建的密文。
  /// - `grant`：每一分块处理前需仍有效的会话。
  /// 返回：以单块内存上限计算完整密文摘要，不解密内容或记录文件名称。
  static func digest(_ url: URL, using grant: VaultGrant) throws -> Data {
    let file = try FileHandle(forReadingFrom: url)
    defer {
      try? file.close()
    }
    var hash = SHA256()
    while true {
      try grant.check()
      // 大批量提交和回滚都可能连续遍历数 GiB，不能等整个遍历结束才释放读盘临时对象。
      let reachedEnd = try autoreleasepool {
        let data = try file.read(upToCount: VaultMediaReader.chunkSize) ?? Data()
        if data.isEmpty {
          return true
        }
        hash.update(data: data)
        return false
      }
      if reachedEnd {
        return Data(hash.finalize())
      }
    }
  }

  /// 业务作用：在媒体枚举之前恢复未结束的发布日志，避免显示部分接收目录。
  /// 参数说明：
  /// - `store`：当前本机保险箱。
  /// - `grant`：已认证的本机会话。
  /// 返回：已提交任务保留；未提交任务只撤回摘要匹配的新增文件，异常时保持保护并拒绝枚举。
  static func recover(_ store: VaultStore, using grant: VaultGrant) throws {
    let directory = try directory(store)
    for url in try FileManager.default.contentsOfDirectory(
      at: directory, includingPropertiesForKeys: nil)
    where url.pathExtension == "pending" {
      let journal = try read(VaultMigrationJournal.self, from: url, using: grant)
      guard url.deletingPathExtension().lastPathComponent == journal.taskID.uuidString,
        journal.files.count <= 100_000, Set(journal.files.map(\.id)).count == journal.files.count
      else {
        throw VaultMigrationError.recovery
      }
      let receiptURL = directory.appendingPathComponent(journal.taskID.uuidString + ".receipt")
      if FileManager.default.fileExists(atPath: receiptURL.path) {
        let receipt = try read(VaultMigrationReceipt.self, from: receiptURL, using: grant)
        guard receipt.taskID == journal.taskID, receipt.manifestDigest == journal.manifestDigest
        else {
          throw VaultMigrationError.recovery
        }
      } else {
        // 没有持久提交证据时只撤回本次新增且摘要一致的密文，不能触及合并目标原有目录。
        for entry in journal.files {
          let file = store.mediaDirectory.appendingPathComponent(entry.id.uuidString + ".evm")
          if FileManager.default.fileExists(atPath: file.path) {
            guard try digest(file, using: grant) == entry.digest else {
              throw VaultMigrationError.recovery
            }
            try grant.check()
            try FileManager.default.removeItem(at: file)
          }
        }
        try VaultStorage.synchronizeDirectory(store.mediaDirectory)
      }
      try FileManager.default.removeItem(at: url)
      try VaultStorage.synchronizeDirectory(directory)
    }
  }
}

/// 接收事务只新增文件，普通同名目录复用目标身份，原有目录从不作为失败清理目标。
final class VaultMigrationIncoming: @unchecked Sendable {
  let manifest: VaultMigrationManifest
  let mappings: [VaultMigrationMapping]
  let directory: URL
  private let library: VaultLibrary
  private let grant: VaultGrant
  private let parent: VaultGrant
  private let rootToken: UUID?
  private let targetRequirements: [UUID: UUID]
  private let expectedTargets: [VaultMedia]
  private let parentID: UUID?
  private let digest: Data
  private let receiptURL: URL
  private let lease: VaultMigrationLease
  private(set) var existingReceipt: VaultMigrationReceipt?

  /// 业务作用：规划接收名称、目录合并与本机保护，或恢复同一任务的已加密规划。
  /// 参数说明：
  /// - `manifest`：经过认证连接交付的白名单清单。
  /// - `library`：接收设备本机保险箱。
  /// - `parentID`：用户明确选择的接收目录。
  /// - `parent`：本机已解锁会话，不继承来源密码。
  /// - `recovery`：取消任务后仍可撤回未提交新增密文的 App 会话；不用于内容读写授权。
  /// 返回：独立暂存事务；权限、保护冲突、空间不足和任务内容错配在交付正文前拒绝。
  init(
    manifest: VaultMigrationManifest, library: VaultLibrary, parentID: UUID?,
    using parent: VaultGrant, recoveryUsing recovery: VaultGrant? = nil
  ) throws {
    try manifest.validate()
    library.mutation.lock()
    defer {
      library.mutation.unlock()
    }
    try library.store.authorize(parent)
    try library.store.authorize(recovery ?? parent)
    try VaultMigrationStorage.recover(library.store, using: parent)
    self.manifest = manifest
    self.library = library
    self.parentID = parentID
    self.parent = recovery ?? parent
    digest = try manifest.digest()
    let root = try VaultMigrationStorage.directory(library.store)
    lease = try VaultMigrationLease(
      root.appendingPathComponent(manifest.taskID.uuidString + ".lock"))
    directory = root.appendingPathComponent(manifest.taskID.uuidString, isDirectory: true)
    receiptURL = root.appendingPathComponent(manifest.taskID.uuidString + ".receipt")
    grant = try parent.access {
      material in
      VaultGrant(root: material, vaultID: parent.vaultID, parent: parent)
    }
    if FileManager.default.fileExists(atPath: receiptURL.path) {
      let receipt = try VaultMigrationStorage.read(
        VaultMigrationReceipt.self, from: receiptURL, using: grant)
      guard receipt.taskID == manifest.taskID, receipt.manifestDigest == digest else {
        throw VaultMigrationError.invalidManifest
      }
      mappings = []
      expectedTargets = []
      rootToken = nil
      targetRequirements = [:]
      existingReceipt = receipt
      return
    }
    if !FileManager.default.fileExists(atPath: directory.path) {
      var required: UInt64 = 32 * 1024 * 1024
      for item in manifest.items {
        let chunks =
          (item.byteCount + UInt64(VaultMediaReader.chunkSize) - 1)
          / UInt64(VaultMediaReader.chunkSize)
        let addition = required.addingReportingOverflow(item.byteCount + chunks * 16 + 65_548)
        guard !addition.overflow else {
          throw VaultMigrationError.invalidManifest
        }
        required = addition.partialValue
      }
      let capacity = try VaultMigrationStorage.availableCapacity(at: root)
      // 新任务先预留完整内容、认证封装和恢复余量，空间不足时不请求正文或目标目录密码。
      if required > capacity {
        throw VaultMigrationError.insufficientSpace
      }
    }
    let all = try library.migrationEntries(using: parent)
    let index = Dictionary(
      uniqueKeysWithValues: all.map {
        ($0.id, $0)
      })
    let stateURL = directory.appendingPathComponent("receive.evp")
    let state: VaultMigrationState
    if FileManager.default.fileExists(atPath: stateURL.path) {
      state = try VaultMigrationStorage.read(
        VaultMigrationState.self, from: stateURL, using: parent)
      guard state.manifest == manifest, state.parentID == parentID else {
        throw VaultMigrationError.changedTarget
      }
    } else {
      state = try Self.plan(manifest, parentID: parentID, existing: all, using: parent)
    }
    mappings = state.mappings
    expectedTargets = state.expectedTargets
    var requirements: [UUID: UUID] = [:]
    var requiresRoot = manifest.items.contains(where: \.hidden)
    for target in expectedTargets {
      guard index[target.id] == target else {
        throw VaultMigrationError.changedTarget
      }
      if let protection = target.folderPassword {
        requirements[target.id] = protection.revision
      }
      requiresRoot = requiresRoot || target.isHidden
    }
    let token = try parent.rootToken()
    // 隐藏目标必须先取得本机 ROOT，不能借目录密码提示暴露未授权隐藏路径。
    guard !requiresRoot || token != nil else {
      throw VaultError.rootRequired
    }
    // 接收端 ROOT 可授权本次合并写入；关闭时仍要求目标原有目录证明，不能由来源密码替代。
    if token != nil, !requirements.isEmpty {
      requiresRoot = true
    } else {
      try parent.access(folders: requirements) {
        _ in
        ()
      }
    }
    guard !requiresRoot || token != nil else {
      throw VaultError.rootRequired
    }
    rootToken = requiresRoot ? token : nil
    targetRequirements = token == nil ? requirements : [:]
    for (id, revision) in targetRequirements {
      try grant.allowFolder(id, revision: revision)
    }
    try VaultStorage.directory(directory)
    var total: UInt64 = 32 * 1024 * 1024
    var rotation: UInt64 = 0
    for record in mappings where record.isNew {
      let media = record.media
      let chunks =
        (media.byteCount + UInt64(VaultMediaReader.chunkSize) - 1)
        / UInt64(VaultMediaReader.chunkSize)
      let expected = media.byteCount + chunks * 16 + 65_548
      let url = directory.appendingPathComponent(media.id.uuidString + ".evm")
      let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
      let saved = min(expected, (attributes?[.size] as? NSNumber)?.uint64Value ?? 0)
      // 续传先轮换已接收前缀的密钥，需同时预留最大单文件前缀的临时空间。
      if saved > 0, !(try isComplete(record.sourceID)) {
        rotation = max(rotation, saved)
      }
      let sum = total.addingReportingOverflow(expected - saved)
      guard !sum.overflow else {
        throw VaultMigrationError.invalidManifest
      }
      total = sum.partialValue
    }
    let sum = total.addingReportingOverflow(rotation)
    guard !sum.overflow else {
      throw VaultMigrationError.invalidManifest
    }
    total = sum.partialValue
    let capacity = try VaultMigrationStorage.availableCapacity(at: directory)
    if total > capacity {
      throw VaultMigrationError.insufficientSpace
    }
    try VaultMigrationStorage.write(state, to: stateURL, using: grant)
    try check()
  }

  /// 业务作用：建立目标路径、名称和保护映射，原有目录身份与密码保持原值。
  /// 参数说明：
  /// - `manifest`：待接收的有界目录清单。
  /// - `parentID`：明确选择的本机目标。
  /// - `existing`：本机认证目录快照。
  /// - `grant`：创建本机目录保护校验的会话。
  /// 返回：完整接收规划；同名文件递增改名，普通目录递归合并，保护降级拒绝。
  private static func plan(
    _ manifest: VaultMigrationManifest, parentID: UUID?, existing: [VaultMedia],
    using grant: VaultGrant
  ) throws -> VaultMigrationState {
    let index = Dictionary(
      uniqueKeysWithValues: existing.map {
        ($0.id, $0)
      })
    var expected: [UUID: VaultMedia] = [:]
    var next = parentID
    var seen: Set<UUID> = []
    while let id = next {
      guard seen.count < 256, seen.insert(id).inserted, let folder = index[id],
        folder.isFolder, !folder.isFilePackage
      else {
        throw VaultMigrationError.changedTarget
      }
      expected[id] = folder
      next = folder.parentID
    }
    var children: [String: [VaultMedia]] = [:]
    for item in existing {
      children[item.parentID?.uuidString ?? "root", default: []].append(item)
    }
    var ids = Dictionary(
      uniqueKeysWithValues: manifest.items.map {
        ($0.id, UUID())
      })
    var records: [VaultMigrationMapping] = []
    for item in manifest.items {
      let destinationParent =
        item.parentID.flatMap {
          ids[$0]
        } ?? parentID
      let parentKey = destinationParent?.uuidString ?? "root"
      let matches = children[parentKey, default: []].filter {
        nameKey($0.originalFilename) == nameKey(item.name)
      }
      if item.shape.isFolder, !item.shape.isFilePackage,
        let target = matches.first, target.isFolder, !target.isFilePackage
      {
        guard matches.count == 1 else {
          throw VaultMigrationError.changedTarget
        }
        guard !item.protected || target.folderPassword != nil else {
          throw VaultMigrationError.protectionConflict
        }
        guard !item.hidden || target.isHidden else {
          throw VaultMigrationError.hiddenConflict
        }
        ids[item.id] = target.id
        if index[target.id] != nil {
          expected[target.id] = target
        }
        records.append(VaultMigrationMapping(sourceID: item.id, media: target, isNew: false))
        continue
      }
      let occupied = Set(
        children[parentKey, default: []].map {
          nameKey($0.originalFilename)
        })
      let name = try availableName(
        item.name, file: !item.shape.isFolder || item.shape.isFilePackage, occupied: occupied)
      let id = ids[item.id]!
      let protection =
        try item.protected
        ? VaultCrypto.folderPassword("123456", folderID: id, using: grant) : nil
      let media = VaultMedia(
        id: id, originalFilename: name, contentType: item.contentType,
        byteCount: item.byteCount, sha256: item.sha256, parentID: destinationParent,
        folderPassword: protection, hidden: item.hidden ? true : nil, photoAsset: item.photoAsset)
      records.append(VaultMigrationMapping(sourceID: item.id, media: media, isNew: true))
      children[parentKey, default: []].append(media)
    }
    for position in records.indices {
      if let photo = records[position].media.photoAsset {
        guard let primary = ids[photo.primaryID], let manifest = ids[photo.manifestID] else {
          throw VaultMigrationError.invalidManifest
        }
        records[position].media.photoAsset = VaultPhotoAsset(
          primaryID: primary, contentType: photo.contentType, byteCount: photo.byteCount,
          sha256: photo.sha256, totalByteCount: photo.totalByteCount,
          resourceCount: photo.resourceCount, manifestID: manifest)
      }
    }
    return VaultMigrationState(
      manifest: manifest, parentID: parentID, mappings: records,
      expectedTargets: expected.values.sorted {
        $0.id.uuidString < $1.id.uuidString
      })
  }

  /// 业务作用：对同层名字使用一致的大小写与 Unicode 规范，避免两端判断重名不一致。
  /// 参数说明：
  /// - `name`：原名或已经分配的候选名称。
  /// 返回：只在内存规划中使用的比较键，不改变用户原名。
  private static func nameKey(_ name: String) -> String {
    name.precomposedStringWithCanonicalMapping.folding(
      options: .caseInsensitive, locale: Locale(identifier: "en_US_POSIX"))
  }

  /// 业务作用：在扩展名前分配第一个空闲序号，不覆盖已有文件或为续传重复叠加后缀。
  /// 参数说明：
  /// - `name`：本次来源原名。
  /// - `file`：普通文件和文档、照片包保留扩展名，普通目录保留完整名称。
  /// - `occupied`：同层已有与本批次预留的比较键。
  /// 返回：原名或可用带序号名称；超长或序号耗尽时拒绝。
  private static func availableName(_ name: String, file: Bool, occupied: Set<String>) throws
    -> String
  {
    if !occupied.contains(nameKey(name)) {
      return name
    }
    let suffix = file ? (name as NSString).pathExtension : ""
    let stem = suffix.isEmpty ? name : (name as NSString).deletingPathExtension
    for number in 1...100_000 {
      let candidate = stem + "(\(number))" + (suffix.isEmpty ? "" : "." + suffix)
      guard candidate.utf8.count <= 4096 else {
        throw VaultError.invalidFileName
      }
      if !occupied.contains(nameKey(candidate)) {
        return candidate
      }
    }
    throw VaultMigrationError.changedTarget
  }

  /// 业务作用：每次候选写入、续传和提交前复验接收端会话与所依赖的 ROOT 或目录证明。
  /// 参数说明：无。
  /// 返回：接收能力持续有效时成功；关闭 ROOT 或锁定后拒绝继续入库。
  func check() throws {
    try Task.checkCancellation()
    try grant.access(folders: targetRequirements, rootToken: rootToken) {
      _ in
      ()
    }
  }

  /// 业务作用：主动停止时先撤销候选写入能力，再释放任务排他权供重新配对恢复。
  /// 参数说明：无。
  /// 返回：迟到分块不能继续写入，已经接收的密文保留。
  func revoke() {
    grant.revoke()
    lease.release()
  }

  /// 业务作用：取得单一清单条目的私有候选位置，路径不使用外来文件名。
  /// 参数说明：
  /// - `record`：已经过规划的目标映射。
  /// 返回：本任务目录内的随机身份路径。
  private func candidate(_ record: VaultMigrationMapping) -> URL {
    directory.appendingPathComponent(record.media.id.uuidString + ".evm")
  }

  /// 业务作用：检查已完整接收的密文，允许续传跳过它而不生成第二份文件。
  /// 参数说明：
  /// - `sourceID`：清单中的来源身份。
  /// 返回：候选已完整认证且元数据匹配时为真，不完整候选仍需继续处理。
  func isComplete(_ sourceID: UUID) throws -> Bool {
    try check()
    guard
      let record = mappings.first(where: {
        $0.sourceID == sourceID
      })
    else {
      throw VaultMigrationError.invalidManifest
    }
    if !record.isNew || existingReceipt != nil {
      return true
    }
    guard FileManager.default.fileExists(atPath: candidate(record).path) else {
      return false
    }
    do {
      let reader = try VaultMediaReader(
        url: candidate(record), grant: grant,
        folderRequirements: targetRequirements, rootToken: rootToken)
      guard reader.media == record.media else {
        throw VaultMigrationError.invalidManifest
      }
      try reader.verify()
      return true
    } catch {
      try check()
      return false
    }
  }

  /// 业务作用：创建目标密文写入器，目录记录由本机生成，不接收来源密码验证结构。
  /// 参数说明：
  /// - `sourceID`：本次清单中的来源身份。
  /// 返回：该条目的私有候选写入器，已合并目录或已提交任务拒绝重复写入。
  func writer(_ sourceID: UUID) throws -> VaultMigrationWriter {
    try check()
    guard existingReceipt == nil,
      let record = mappings.first(where: {
        $0.sourceID == sourceID
      }),
      record.isNew
    else {
      throw VaultMigrationError.invalidManifest
    }
    let url = candidate(record)
    return try VaultMigrationWriter.resume(
      media: record.media, url: url, using: grant,
      folders: targetRequirements, rootToken: rootToken)
  }

  /// 业务作用：整批回读后按先日志、后文件、再持久收据的顺序发布，合并目录本身不改写。
  /// 参数说明：
  /// - `authorizeSource`：在最终发布前通过认证连接取得来源仍有效的提交授权。
  /// 返回：持久化的幂等收据；不能确认提交时保持恢复日志并拒绝宣称成功。
  func commit(authorizeSource: () throws -> Void) throws -> VaultMigrationReceipt {
    try check()
    if let existingReceipt {
      return existingReceipt
    }
    library.mutation.lock()
    defer {
      library.mutation.unlock()
    }
    let all = try library.migrationEntries(using: grant)
    let index = Dictionary(
      uniqueKeysWithValues: all.map {
        ($0.id, $0)
      })
    for item in expectedTargets where index[item.id] != item {
      throw VaultMigrationError.changedTarget
    }
    let added = mappings.filter(\.isNew)
    var published: [VaultMigrationPublishedFile] = []
    for record in added {
      guard index[record.media.id] == nil,
        !all.contains(where: {
          $0.parentID == record.media.parentID
            && Self.nameKey($0.originalFilename) == Self.nameKey(record.media.originalFilename)
        })
      else {
        throw VaultMigrationError.changedTarget
      }
      let reader = try VaultMediaReader(
        url: candidate(record), grant: grant,
        folderRequirements: targetRequirements, rootToken: rootToken)
      guard reader.media == record.media else {
        throw VaultMigrationError.invalidManifest
      }
      try reader.verify()
      published.append(
        VaultMigrationPublishedFile(
          id: record.media.id,
          digest: try VaultMigrationStorage.digest(candidate(record), using: grant)))
    }
    try authorizeSource()
    try check()
    let root = try VaultMigrationStorage.directory(library.store)
    let journalURL = root.appendingPathComponent(manifest.taskID.uuidString + ".pending")
    let journal = VaultMigrationJournal(
      taskID: manifest.taskID, manifestDigest: digest, files: published)
    // 新文件离开暂存前先持久化撤回依据，崩溃不能让一部分目录变成可见的已完成内容。
    try VaultMigrationStorage.write(journal, to: journalURL, using: grant)
    do {
      for record in added {
        try check()
        let destination = library.store.mediaDirectory.appendingPathComponent(
          record.media.id.uuidString + ".evm")
        // 发布和撤权共用同一道同步门禁，锁定或清空返回后不能再出现旧会话的新文件。
        try grant.access(folders: targetRequirements, rootToken: rootToken) {
          _ in
          guard
            Darwin.renameatx_np(
              AT_FDCWD, candidate(record).path, AT_FDCWD, destination.path, UInt32(RENAME_EXCL))
              == 0
          else {
            throw VaultError.storage
          }
        }
      }
      try VaultStorage.synchronizeDirectory(library.store.mediaDirectory)
      try authorizeSource()
      try check()
      let originals = Dictionary(
        uniqueKeysWithValues: manifest.items.map {
          ($0.id, $0)
        })
      let receipt = VaultMigrationReceipt(
        taskID: manifest.taskID, manifestDigest: digest,
        roots: manifest.roots.compactMap {
          id in
          mappings.first(where: {
            $0.sourceID == id
          })?.media.id
        },
        files: manifest.items.filter {
          !$0.shape.isFolder
        }.count,
        renamed: mappings.filter {
          originals[$0.sourceID]?.name != $0.media.originalFilename
        }
        .count,
        merged: mappings.filter {
          !$0.isNew
        }.count)
      // 收据是提交点；只有它持久化后才允许正常枚举与向来源报告入库成功。
      try VaultMigrationStorage.write(receipt, to: receiptURL, using: grant)
      existingReceipt = receipt
      try FileManager.default.removeItem(at: journalURL)
      try VaultStorage.synchronizeDirectory(root)
      try? FileManager.default.removeItem(at: directory)
      return receipt
    } catch {
      do {
        try VaultMigrationStorage.recover(library.store, using: parent)
      } catch {
        library.store.lock()
        throw VaultMigrationError.recovery
      }
      throw error
    }
  }

  /// 业务作用：释放接收事务时撤销本次候选处理能力，不清除可恢复密文。
  /// 参数说明：无。
  /// 返回：旧接收任务不能继续写入，不撤销本机正常浏览会话。
  deinit {
    revoke()
  }
}
