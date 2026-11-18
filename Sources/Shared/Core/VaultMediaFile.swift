import CryptoKit
import Darwin
import Foundation
import ImageIO
import UniformTypeIdentifiers

/// 一个密文文件的公开结构身份，敏感名称与媒体信息另行认证加密。
struct MediaIdentity: Codable, Sendable {
  let formatVersion: Int
  let id: UUID
  let vaultID: UUID
  let byteCount: UInt64
  let chunkSize: Int
  let chunkCount: Int
  let noncePrefix: Data
}

struct MediaHeader: Codable, Sendable {
  let identity: MediaIdentity
  let wrappedKey: Data
  let metadata: Data
}

/// 完整照片资源清单只记录原始角色与相对路径，不包含相册资产身份或查看历史。
private struct PhotoAssetResourceEntry: Decodable {
  let resourceType: Int
  let originalFilename: String
  let uniformTypeIdentifier: String
  let path: String
}

/// 来源句柄的稳定身份，仅在本次保存及可选移除原件的会话内使用。
struct SourceIdentity: Sendable, Equatable {
  let device: Int32
  let inode: UInt64
  let size: Int64
  let seconds: Int
  let nanoseconds: Int

  /// 业务作用：从已经打开的来源句柄读取身份，拒绝目录、设备和特殊文件。
  /// 参数说明：
  /// - `file`：本次使用的来源句柄。
  /// 返回：普通文件身份；无法确认时拒绝保存或删源。
  init(_ file: FileHandle) throws {
    var value = stat()
    guard fstat(file.fileDescriptor, &value) == 0,
      value.st_mode & S_IFMT == S_IFREG, value.st_size >= 0
    else {
      throw VaultError.storage
    }
    device = value.st_dev
    inode = value.st_ino
    size = value.st_size
    seconds = value.st_mtimespec.tv_sec
    nanoseconds = value.st_mtimespec.tv_nsec
  }
}

/// 已完整保存与验证的来源收据，不落盘，不构成最近导入或查看历史。
struct SavedImport: Sendable {
  let media: VaultMedia
  let source: URL
  let identity: SourceIdentity
}

/// 同时约束文件读取、格式边界与会话撤销的有界密文读取器。
final class VaultMediaReader: @unchecked Sendable {
  static let chunkSize = 1024 * 1024
  static let magic = Data("ENCVLT01".utf8)
  private let mutex = NSLock()
  private let file: FileHandle
  private let header: MediaHeader
  private let headerDigest: Data
  private let payloadOffset: UInt64
  let grant: VaultGrant
  let media: VaultMedia
  let folderRequirements: [UUID: UUID]
  let rootToken: UUID?

  /// 业务作用：有界解析密文头并认证原始文件名，只有当前保险箱会话可以取得媒体信息。
  /// 参数说明：
  /// - `url`：保险箱中的密文文件。
  /// - `grant`：当前独立密码授权的会话。
  /// - `folderRequirements`：本次读取需持续有效的目录密码授权。
  /// - `rootToken`：隐藏目录读取所绑定的本次 ROOT 激活身份。
  /// 返回：已经认证元数据的读取器；身份、长度、格式或密钥错误时失败。
  init(
    url: URL, grant: VaultGrant, folderRequirements: [UUID: UUID] = [:], rootToken: UUID? = nil
  ) throws {
    self.grant = grant
    self.folderRequirements = folderRequirements
    self.rootToken = rootToken
    let file = try FileHandle(forReadingFrom: url)
    self.file = file
    guard try VaultStorage.read(file, count: 8) == Self.magic else {
      throw VaultError.corrupt
    }
    let sizeData = try VaultStorage.read(file, count: 4)
    let headerSize = sizeData.reduce(0) {
      ($0 << 8) | Int($1)
    }
    guard headerSize > 0, headerSize <= 65_536 else {
      throw VaultError.corrupt
    }
    let bytes = try VaultStorage.read(file, count: headerSize)
    guard let parsed = try? JSONDecoder().decode(MediaHeader.self, from: bytes) else {
      throw VaultError.corrupt
    }
    let identity = parsed.identity
    guard identity.formatVersion == 1, identity.vaultID == grant.vaultID,
      identity.chunkSize == Self.chunkSize, identity.noncePrefix.count == 8,
      identity.byteCount <= UInt64(Self.chunkSize) * UInt64(UInt32.max),
      identity.chunkCount
        == Int((identity.byteCount + UInt64(Self.chunkSize) - 1) / UInt64(Self.chunkSize))
    else {
      throw VaultError.corrupt
    }
    let offset = UInt64(12 + headerSize)
    let expectedLength = offset + identity.byteCount + UInt64(identity.chunkCount) * 16
    guard try file.seekToEnd() == expectedLength else {
      throw VaultError.corrupt
    }
    let context = try VaultCrypto.encode(identity)
    let decoded: VaultMedia = try grant.access(folders: folderRequirements, rootToken: rootToken) {
      root in
      let key = try VaultCrypto.open(
        parsed.wrappedKey, key: SymmetricKey(data: root), context: context)
      guard key.count == 32 else {
        throw VaultError.corrupt
      }
      let metadata = try VaultCrypto.open(
        parsed.metadata, key: VaultCrypto.key(key, context: Data("metadata".utf8)), context: context
      )
      return try JSONDecoder().decode(VaultMedia.self, from: metadata)
    }
    guard decoded.id == identity.id, decoded.byteCount == identity.byteCount,
      decoded.sha256.count == 32, !decoded.originalFilename.isEmpty,
      decoded.originalFilename.utf8.count <= 4096,
      decoded.isImage || decoded.isVideo || decoded.contentType == UTType.data.identifier
        || decoded.isFolder && decoded.byteCount == 0
    else {
      throw VaultError.corrupt
    }
    if let protection = decoded.folderPassword {
      guard decoded.isFolder, !decoded.isFilePackage, protection.salt.count == 16,
        protection.iterations >= VaultCrypto.rounds, protection.iterations <= 3_000_000,
        protection.verification.count == 44
      else {
        throw VaultError.corrupt
      }
    }
    if let asset = decoded.photoAsset {
      guard decoded.isFolder, decoded.byteCount == 0, decoded.folderPassword == nil,
        decoded.hidden != true, asset.primaryID != decoded.id, asset.manifestID != decoded.id,
        asset.primaryID != asset.manifestID,
        asset.byteCount > 0, asset.sha256.count == 32,
        asset.totalByteCount >= asset.byteCount, asset.resourceCount > 0,
        asset.resourceCount <= 4096,
        UTType(asset.contentType)?.conforms(to: .image) == true
          || UTType(asset.contentType)?.conforms(to: .movie) == true
      else {
        throw VaultError.corrupt
      }
    }
    self.header = parsed
    self.headerDigest = Data(SHA256.hash(data: bytes))
    self.payloadOffset = offset
    self.media = decoded
  }

  /// 业务作用：读取器释放时关闭密文句柄，不保存播放进度或访问记录。
  /// 参数说明：无。
  /// 返回：句柄释放，源密文保持不变。
  deinit {
    try? file.close()
  }

  /// 业务作用：在单次有界范围内认证解密需要的分块，服务播放器随机读取。
  /// 参数说明：
  /// - `offset`：原始媒体的字节偏移。
  /// - `count`：需要的字节数，单次最多一个块大小。
  /// 返回：不超过指定长度的认证明文；失权、截断或标签不符时拒绝。
  func read(offset: UInt64, count: Int) throws -> Data {
    guard count >= 0, count <= Self.chunkSize, offset <= media.byteCount else {
      throw VaultError.corrupt
    }
    let end = min(media.byteCount, offset + UInt64(count))
    if offset == end {
      try checkAccess()
      return Data()
    }
    mutex.lock()
    defer {
      mutex.unlock()
    }
    // 每次读取结束即释放 Foundation 的临时密文与解密对象，长期播放或完整复验不能累积所有块。
    return try autoreleasepool {
      try grant.access(folders: folderRequirements, rootToken: rootToken) { root in
        let identity = header.identity
        let context = try VaultCrypto.encode(identity)
        let key = try VaultCrypto.open(
          header.wrappedKey, key: SymmetricKey(data: root), context: context)
        var result = Data()
        var position = offset
        while position < end {
          let index = Int(position / UInt64(Self.chunkSize))
          let start = UInt64(index) * UInt64(Self.chunkSize)
          let length = Int(min(UInt64(Self.chunkSize), media.byteCount - start))
          try file.seek(toOffset: payloadOffset + UInt64(index) * UInt64(Self.chunkSize + 16))
          let sealed = try VaultStorage.read(file, count: length + 16)
          let nonce = try Self.nonce(prefix: identity.noncePrefix, index: index)
          let box = try AES.GCM.SealedBox(
            nonce: nonce, ciphertext: sealed.prefix(length), tag: sealed.suffix(16))
          let plain = try AES.GCM.open(
            box, using: SymmetricKey(data: key),
            authenticating: Self.chunkContext(headerDigest, index: index, length: length))
          let localStart = Int(position - start)
          let amount = Int(min(end - position, UInt64(length - localStart)))
          result.append(plain[localStart..<(localStart + amount)])
          position += UInt64(amount)
        }
        return result
      }
    }
  }

  /// 业务作用：在有限内存中完整校验密文与原媒体摘要，作为成功保存后删源的必要证据。
  /// 参数说明：
  /// - `progress`：当前完整复验的已验证比例，只在内存中使用。
  /// 返回：所有分块及完整摘要匹配时成功；取消、失权或内容变化时失败。
  func verify(progress: @Sendable (Double) -> Void = { _ in }) throws {
    var digest = SHA256()
    var offset: UInt64 = 0
    while offset < media.byteCount {
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      try autoreleasepool {
        let data = try read(
          offset: offset, count: Int(min(UInt64(Self.chunkSize), media.byteCount - offset)))
        digest.update(data: data)
        offset += UInt64(data.count)
      }
      progress(Double(offset) / Double(media.byteCount))
    }
    try checkAccess()
    guard Data(digest.finalize()) == media.sha256 else {
      throw VaultError.corrupt
    }
    progress(1)
  }

  /// 业务作用：为图片或小型文档查看取得有严格上限的完整内容，避免任意大文件一次装入内存。
  /// 参数说明：
  /// - `limit`：允许的明文总字节数。
  /// 返回：逐块认证且完整摘要一致的内容；超限、失权或损坏时失败。
  func imageData(limit: Int = 64 * 1024 * 1024) throws -> Data {
    guard !media.isVideo, media.byteCount <= UInt64(limit) else {
      throw VaultError.unsupportedMedia
    }
    var result = Data()
    while UInt64(result.count) < media.byteCount {
      let amount = Int(min(UInt64(Self.chunkSize), media.byteCount - UInt64(result.count)))
      try autoreleasepool {
        result.append(try read(offset: UInt64(result.count), count: amount))
      }
    }
    guard Data(SHA256.hash(data: result)) == media.sha256 else {
      throw VaultError.corrupt
    }
    try checkAccess()
    return result
  }

  /// 业务作用：复验 App 会话和本次读取绑定的全部目录授权，禁止离开目录后的迟到内容交付。
  /// 参数说明：无。
  /// 返回：所有能力仍有效时成功；App 锁定或目录授权撤销后拒绝。
  func checkAccess() throws {
    try grant.access(folders: folderRequirements, rootToken: rootToken) { _ in
      ()
    }
  }

  /// 业务作用：为每个文件的内容分块生成不重复 nonce，禁止计数器溢出后重用。
  /// 参数说明：
  /// - `prefix`：该文件随机生成的 8 字节前缀。
  /// - `index`：从零开始的块索引。
  /// 返回：96 位 AES-GCM nonce；越界时拒绝。
  static func nonce(prefix: Data, index: Int) throws -> AES.GCM.Nonce {
    guard prefix.count == 8, index >= 0, index < Int(UInt32.max) else {
      throw VaultError.corrupt
    }
    var bytes = prefix
    var number = UInt32(index).bigEndian
    withUnsafeBytes(of: &number) {
      bytes.append(contentsOf: $0)
    }
    return try AES.GCM.Nonce(data: bytes)
  }

  /// 业务作用：将内容标签绑定到完整头部、块位置和真实长度，防止重排或截断。
  /// 参数说明：
  /// - `digest`：完整认证头部的摘要。
  /// - `index`：当前块位置。
  /// - `length`：当前块明文长度。
  /// 返回：分块 AES-GCM 的关联数据。
  static func chunkContext(_ digest: Data, index: Int, length: Int) -> Data {
    var result = digest
    for value in [UInt64(index), UInt64(length)] {
      var value = value.bigEndian
      withUnsafeBytes(of: &value) {
        result.append(contentsOf: $0)
      }
    }
    return result
  }
}

/// 仅用于一个选中条目的单次系统复制，目录证明不与普通浏览会话混用。
final class VaultCopySession: @unchecked Sendable {
  let mediaID: UUID
  private let owner: VaultLibrary
  private let parent: VaultGrant
  private let grant: VaultGrant
  private let mutex = NSLock()
  private var available = true

  /// 业务作用：为本次复制建立依赖 App 会话且没有任何旧目录证明的临时能力。
  /// 参数说明：
  /// - `mediaID`：本次唯一允许复制的文件或目录身份。
  /// - `owner`：创建复制事务的保险箱入口。
  /// - `parent`：仍有效的 App 会话，锁定后临时能力也必须失效。
  /// 返回：只保存在内存中的复制事务，不继承已经验证的浏览权限。
  fileprivate init(mediaID: UUID, owner: VaultLibrary, parent: VaultGrant) throws {
    self.mediaID = mediaID
    self.owner = owner
    self.parent = parent
    // 复制从空目录证明开始，不能把日常浏览已输入的密码变成长期系统复制权限。
    grant = try parent.access { root in
      VaultGrant(root: root, vaultID: parent.vaultID, parent: parent)
    }
  }

  /// 业务作用：复验复制事务归属，并在开始输出时一次性消费事务。
  /// 参数说明：
  /// - `owner`：本次执行操作的同一保险箱入口。
  /// - `parent`：本次仍持有的同一 App 会话。
  /// - `consume`：真正开始复制时为真，密码验证和预检时为假。
  /// 返回：尚未消费且归属一致时交付内部临时能力；取消、重放或错配时拒绝。
  fileprivate func permission(
    owner: VaultLibrary, parent: VaultGrant, consume: Bool = false
  ) throws -> VaultGrant {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    // 事务不能移交给其它入口或 App 会话，已经消费或取消的证明也不能再次使用。
    guard available, self.owner === owner, self.parent === parent else {
      throw VaultError.locked
    }
    if consume {
      // 任何输出之前先消费权限，后续即使重名或磁盘失败，也必须重新建立验证事务。
      available = false
    }
    return grant
  }

  /// 业务作用：取消、锁定或结束复制时撤销本次所有目录证明，不能用于下一次复制。
  /// 参数说明：无。
  /// 返回：当前同步分块完成后不再交付明文，不影响普通浏览会话。
  func revoke() {
    mutex.lock()
    // 先关闭事务入口，再撤销分块交付，取消与迟到的后台操作不能重新取得权限。
    available = false
    mutex.unlock()
    grant.revoke()
  }

  /// 业务作用：释放复制事务时补充清除未消费的临时目录权限。
  /// 参数说明：无。
  /// 返回：不遗留可供后续操作复用的复制能力。
  deinit {
    revoke()
  }
}

/// 一批来源文件移出保护范围时的单次证明，范围内整理只借用仍有效的浏览权限。
final class VaultMoveSession: @unchecked Sendable {
  let mediaIDs: [UUID]
  private let owner: VaultLibrary
  private let parent: VaultGrant
  private let grant: VaultGrant
  private let mutex = NSLock()
  private var available = true
  private var destinationBound = false
  private var destinationID: UUID?

  /// 业务作用：为明确选择的移动来源建立没有旧目录证明的临时能力。
  /// 参数说明：
  /// - `mediaIDs`：本次批次唯一允许移动的来源身份。
  /// - `owner`：创建本次移动的保险箱入口。
  /// - `parent`：本次仍有效的 App 会话。
  /// 返回：依赖 App 会话的空能力，后续只可借用共同保护范围的有效浏览证明。
  fileprivate init(mediaIDs: [UUID], owner: VaultLibrary, parent: VaultGrant) throws {
    self.mediaIDs = mediaIDs
    self.owner = owner
    self.parent = parent
    grant = try parent.access { root in
      VaultGrant(root: root, vaultID: parent.vaultID, parent: parent)
    }
  }

  /// 业务作用：把范围判断与本次唯一目标绑定，防止范围内借用的浏览证明被改用于移出。
  /// 参数说明：
  /// - `id`：本次接收目录身份，空值表示保险箱根目录。
  /// - `owner`：执行本次移动的保险箱入口。
  /// - `parent`：创建本次证明的同一 App 会话。
  /// 返回：首次绑定或目标未变时成功；目标改变、归属错配、取消或消费后拒绝。
  fileprivate func bindDestination(_ id: UUID?, owner: VaultLibrary, parent: VaultGrant) throws {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    // 共同范围的浏览证明不等于移出授权，同一证明不能先借用后改换接收目录。
    guard available, self.owner === owner, self.parent === parent,
      !destinationBound || destinationID == id
    else {
      throw VaultError.invalidMove
    }
    destinationID = id
    destinationBound = true
  }

  /// 业务作用：核对移动证明的归属，并在实际移动前一次性消费证明。
  /// 参数说明：
  /// - `owner`：执行本次移动的同一保险箱入口。
  /// - `parent`：创建本次证明的同一 App 会话。
  /// - `consume`：开始移动时为真，目录验证时为假。
  /// 返回：归属一致且尚未消费时交付临时能力；错配、取消或重放时拒绝。
  fileprivate func permission(
    owner: VaultLibrary, parent: VaultGrant, consume: Bool = false
  ) throws -> VaultGrant {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    // 目录证明只属于一次明确移动，不能转给其它来源或后来重新建立的会话。
    guard available, self.owner === owner, self.parent === parent else {
      throw VaultError.locked
    }
    if consume {
      available = false
    }
    return grant
  }

  /// 业务作用：结束或取消移动时清除本次目录证明，不撤销当前浏览权限。
  /// 参数说明：无。
  /// 返回：该证明不能再验证密码或开始移动。
  func revoke() {
    mutex.lock()
    available = false
    mutex.unlock()
    grant.revoke()
  }

  /// 业务作用：释放移动请求时清除未消费的临时权限。
  /// 参数说明：无。
  /// 返回：不保留可供后续移动复用的密码证明。
  deinit {
    revoke()
  }
}

/// 批量移动只返回会话与完成情况，不持有文件内容或密码原文。
struct VaultBatchMoveResult: Sendable {
  let grant: VaultGrant
  let movedCount: Int
  let totalCount: Int
  let failure: VaultError?
}

/// 系统批量保存只记录已经完整完成的条目，失败项目不能计入成功数量。
struct VaultSystemSaveResult: Sendable {
  let completedIDs: [UUID]
  let totalCount: Int
  let failure: VaultError?
}

/// 加密媒体目录，不创建播放历史、明文索引或明文缩略图。
final class VaultLibrary: @unchecked Sendable {
  let store: VaultStore
  let mutation = NSRecursiveLock()

  /// 业务作用：把媒体事务限定到指定保险箱的私有目录。
  /// 参数说明：
  /// - `store`：持有目录独占权的保险箱。
  /// 返回：不自动读取或导入媒体的目录入口。
  init(store: VaultStore) {
    self.store = store
  }

  /// 业务作用：枚举当前授权可见条目，识别完整照片资源包，不展示照片内部资源或未授权文件。
  /// 参数说明：
  /// - `grant`：当前前台会话能力。
  /// 返回：照片呈现转换保留全部资源与身份；可见媒体按原名排序，任一密文头损坏时明确失败。
  func list(using grant: VaultGrant) throws -> [VaultMedia] {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    var entries = try allEntries(using: grant)
    for position in entries.indices {
      let item = entries[position]
      if item.photoAsset == nil, item.isFolder,
        item.originalFilename.hasSuffix("（完整照片资源）")
          || item.originalFilename.hasSuffix("（实况照片）")
          || item.originalFilename.hasSuffix("（完整资源）")
      {
        do {
          entries[position] = try completePhotoAsset(id: item.id, using: grant)
        } catch VaultError.folderPasswordRequired {
          continue
        } catch VaultError.rootRequired {
          continue
        }
      }
    }
    let index = Dictionary(uniqueKeysWithValues: entries.map { ($0.id, $0) })
    return try entries.filter { media in
      do {
        let path = try folderChain(for: media, includingSelf: true, entries: index, using: grant)
        // 配套资源仅作为所属照片的内部内容，不出现在相册、普通文件列表或移动目标中。
        guard !path.contains(where: { $0.id != media.id && $0.photoAsset != nil }) else {
          return false
        }
        let token = try rootRequirement(in: path, using: grant)
        let requirements = try folderRequirements(
          for: media, includingSelf: false, entries: index, using: grant)
        try grant.access(folders: requirements, rootToken: token) { _ in
          ()
        }
        return true
      } catch VaultError.folderPasswordRequired {
        return false
      } catch VaultError.rootRequired {
        return false
      }
    }.sorted {
      if $0.originalFilename == $1.originalFilename {
        return $0.id.uuidString < $1.id.uuidString
      }
      return $0.originalFilename < $1.originalFilename
    }
  }

  /// 业务作用：认证目录关系供访问门禁与完整子树操作使用，不直接向界面发布全部原名。
  /// 参数说明：
  /// - `grant`：当前 App 会话。
  /// 返回：完整认证并稳定排序的内部目录，任何损坏均明确拒绝。
  private func allEntries(using grant: VaultGrant) throws -> [VaultMedia] {
    try store.authorize(grant)
    // 媒体进入普通列表前先完成遗留迁移事务的提交判定或精确撤回，不能显示半份接收目录。
    try VaultMigrationStorage.recover(store, using: grant)
    let urls = try FileManager.default.contentsOfDirectory(
      at: store.mediaDirectory, includingPropertiesForKeys: nil)
    let items = try urls.filter {
      $0.pathExtension == "evm"
    }.map { url in
      try autoreleasepool {
        let media = try VaultMediaReader(url: url, grant: grant).media
        // 文件身份必须与随机文件名一致，复制或替换的重复头部不能导致目录索引冲突。
        guard url.lastPathComponent == media.id.uuidString + ".evm" else {
          throw VaultError.corrupt
        }
        return media
      }
    }
    try VaultMigrationStorage.discardOrphanedIncoming(
      store, liveIDs: Set(items.map(\.id)), using: grant)
    try grant.check()
    return items.sorted {
      if $0.originalFilename == $1.originalFilename {
        return $0.id.uuidString < $1.id.uuidString
      }
      return $0.originalFilename < $1.originalFilename
    }
  }

  /// 业务作用：为密文迁移取得完整认证目录，访问范围由迁移事务另行按 ROOT 与祖先关系收紧。
  /// 参数说明：
  /// - `grant`：当前保险箱会话，不授予迁移以外的新能力。
  /// 返回：仅供内部规划的条目，不直接向未授权界面或网络交付原目录验证材料。
  func migrationEntries(using grant: VaultGrant) throws -> [VaultMedia] {
    try allEntries(using: grant)
  }

  /// 业务作用：为选中的密文创建受会话约束的随机读取入口，不把原名暴露为外部文档 URL。
  /// 参数说明：
  /// - `id`：已解锁列表中的媒体身份。
  /// - `grant`：当前前台会话能力。
  /// 返回：元数据已认证的密文读取器。
  func reader(id: UUID, using grant: VaultGrant) throws -> VaultMediaReader {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let metadata = try rawReader(id: id, using: grant).media
    let requirements = try folderRequirements(for: metadata, includingSelf: true, using: grant)
    let token = try rootRequirement(
      in: folderChain(for: metadata, includingSelf: true, using: grant), using: grant)
    return try VaultMediaReader(
      url: store.mediaDirectory.appendingPathComponent(id.uuidString + ".evm"), grant: grant,
      folderRequirements: requirements, rootToken: token)
  }

  /// 业务作用：为照片缩略图和播放取得主图或主视频，配套资源继续保留在同一照片内部。
  /// 参数说明：
  /// - `id`：当前选择的照片、视频或普通媒体身份。
  /// - `grant`：当前目录及 ROOT 状态均有效的会话。
  /// 返回：普通媒体直接返回自身，照片包只返回经过目录归属与摘要核对的主资源读取器。
  func presentationReader(id: UUID, using grant: VaultGrant) throws -> VaultMediaReader {
    let root = try reader(id: id, using: grant)
    guard let asset = root.media.photoAsset else {
      return root
    }
    let entries = try photoAssetContents(id: id, using: grant)
    let files = entries.filter { !$0.isFolder }
    guard let primary = files.first(where: { $0.id == asset.primaryID }),
      files.contains(where: { $0.id == asset.manifestID }),
      files.count == asset.resourceCount + 1,
      primary.contentType == asset.contentType, primary.byteCount == asset.byteCount,
      primary.sha256 == asset.sha256
    else {
      throw VaultError.corrupt
    }
    return try reader(id: primary.id, using: grant)
  }

  /// 业务作用：在完整照片导出和主资源复验时取得内部资源，不把它们发布为普通相册条目。
  /// 参数说明：
  /// - `id`：已认证照片包身份。
  /// - `grant`：拥有该照片及全部祖先目录访问权的会话。
  /// 返回：根条目在前的全部内部资源；缺失、越界或失权时拒绝。
  func photoAssetContents(id: UUID, using grant: VaultGrant) throws -> [VaultMedia] {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    let root = try reader(id: id, using: grant).media
    guard root.photoAsset != nil else {
      throw VaultError.invalidSelection
    }
    return try descendants(of: root, using: grant)
  }

  /// 业务作用：将完整资源归为单个照片条目，并兼容此前已保存的资源目录，不删除任何配套内容。
  /// 参数说明：
  /// - `id`：本应用保存的完整照片资源目录身份。
  /// - `grant`：当前已验证的目录会话，保持原有权限不变。
  /// 返回：资源清单、层级和主图均成立时发布照片展示元数据；非照片目录保持原样。
  func completePhotoAsset(id: UUID, using grant: VaultGrant) throws -> VaultMedia {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    let original = try reader(id: id, using: grant).media
    guard original.isFolder, original.photoAsset == nil, !original.isDocument,
      original.folderPassword == nil, !original.isHidden
    else {
      return original
    }
    let entries = try descendants(of: original, using: grant)
    guard !entries.contains(where: { $0.folderPassword != nil || $0.isHidden }),
      let manifest = entries.first(where: {
        $0.parentID == id && !$0.isFolder && $0.originalFilename == "资源清单.json"
      }), manifest.byteCount > 0, manifest.byteCount <= 1024 * 1024
    else {
      return original
    }
    let data = try reader(id: manifest.id, using: grant).imageData(limit: 1024 * 1024)
    guard let records = try? JSONDecoder().decode([PhotoAssetResourceEntry].self, from: data),
      !records.isEmpty, records.count <= 4096,
      entries.filter({ !$0.isFolder }).count == records.count + 1
    else {
      return original
    }
    var resources: [(role: Int, media: VaultMedia)] = []
    var visited: Set<UUID> = []
    for record in records {
      let parts = record.path.split(separator: "/", omittingEmptySubsequences: false).map(
        String.init)
      guard parts.count == 2, !parts.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }),
        let directory = entries.first(where: {
          $0.parentID == id && $0.isFolder && $0.originalFilename == parts[0]
        }),
        let file = entries.first(where: {
          $0.parentID == directory.id && !$0.isFolder && $0.originalFilename == parts[1]
        }), visited.insert(file.id).inserted
      else {
        return original
      }
      resources.append((record.resourceType, file))
    }
    let priority = [5, 4, 1, 6, 2]
    guard
      let primary = priority.lazy.compactMap({ role in
        resources.first(where: { $0.role == role && ($0.media.isImage || $0.media.isVideo) })?.media
      }).first
    else {
      return original
    }
    var total: UInt64 = 0
    for resource in resources {
      let addition = total.addingReportingOverflow(resource.media.byteCount)
      guard !addition.overflow else {
        throw VaultError.unsupportedMedia
      }
      total = addition.partialValue
    }
    let asset = VaultPhotoAsset(
      primaryID: primary.id, contentType: primary.contentType, byteCount: primary.byteCount,
      sha256: primary.sha256, totalByteCount: total, resourceCount: resources.count,
      manifestID: manifest.id)
    let updated = VaultMedia(
      id: original.id, originalFilename: primary.originalFilename,
      contentType: original.contentType,
      byteCount: original.byteCount, sha256: original.sha256, parentID: original.parentID,
      folderPassword: original.folderPassword, hidden: original.hidden, photoAsset: asset)
    let requirements = try folderRequirements(for: original, includingSelf: true, using: grant)
    // 只改变零载荷目录的照片呈现方式，全部子项及保护策略保持原样，不撤销当前导入所用的目录授权。
    _ = try publishMetadata(
      updated, replacing: original, requirements: requirements, using: grant,
      uncertain: .organizationCommitUncertain, retainingSession: true)
    return updated
  }

  /// 业务作用：仅读取认证元数据以定位目录门禁，不提供绕过密码的载荷读取入口。
  /// 参数说明：
  /// - `id`：当前保险箱中的随机文件身份。
  /// - `grant`：当前 App 会话。
  /// 返回：只供内部结构检查使用的读取器，调用方不得向外部交付其载荷。
  private func rawReader(id: UUID, using grant: VaultGrant) throws -> VaultMediaReader {
    try VaultMediaReader(
      url: store.mediaDirectory.appendingPathComponent(id.uuidString + ".evm"), grant: grant)
  }

  /// 业务作用：沿认证父子关系建立本次访问的完整目录路径，拒绝循环、缺席或非目录父项。
  /// 参数说明：
  /// - `media`：当前待访问条目。
  /// - `includingSelf`：目标为目录时是否同时要求目标目录密码。
  /// - `entries`：已有认证目录快照，未提供时按祖先身份读取。
  /// - `grant`：当前 App 会话。
  /// 返回：从外层到内层的目录路径；异常关系不开放访问。
  private func folderChain(
    for media: VaultMedia, includingSelf: Bool, entries: [UUID: VaultMedia]? = nil,
    using grant: VaultGrant
  ) throws -> [VaultMedia] {
    var path: [VaultMedia] = []
    var next = includingSelf && media.isFolder ? media.id : media.parentID
    var visited: Set<UUID> = []
    while let id = next {
      guard path.count < 256, visited.insert(id).inserted else {
        throw VaultError.corrupt
      }
      let folder: VaultMedia
      if let entries {
        guard let found = entries[id] else {
          throw VaultError.corrupt
        }
        folder = found
      } else {
        folder = id == media.id ? media : try rawReader(id: id, using: grant).media
      }
      guard folder.isFolder else {
        throw VaultError.corrupt
      }
      path.append(folder)
      next = folder.parentID
    }
    return path.reversed()
  }

  /// 业务作用：把目录路径转换为每次明文交付都必须复验的内存授权要求。
  /// 参数说明：
  /// - `media`：待读取的认证条目。
  /// - `includingSelf`：是否包含目标目录自身。
  /// - `entries`：可选认证元数据快照。
  /// - `grant`：当前 App 会话。
  /// 返回：受保护目录身份与密码代次；涉及隐藏路径时要求 ROOT 已开启，不包含密码或访问历史。
  private func folderRequirements(
    for media: VaultMedia, includingSelf: Bool, entries: [UUID: VaultMedia]? = nil,
    using grant: VaultGrant
  ) throws -> [UUID: UUID] {
    let path = try folderChain(
      for: media, includingSelf: includingSelf, entries: entries, using: grant)
    _ = try rootRequirement(in: path, using: grant)
    return Dictionary(
      uniqueKeysWithValues: path.compactMap { folder in
        folder.folderPassword.map { (folder.id, $0.revision) }
      })
  }

  /// 业务作用：将隐藏目录及其后代的访问绑定到本次 ROOT 激活，不把普通 App 解锁当作授权。
  /// 参数说明：
  /// - `path`：已经认证的目录路径，包含当前操作需要访问的目录。
  /// - `grant`：当前 App 会话或依赖它的临时能力。
  /// 返回：路径涉及隐藏文件夹时交付有效 ROOT 身份，普通路径为空；未开启 ROOT 时拒绝。
  private func rootRequirement(in path: [VaultMedia], using grant: VaultGrant) throws -> UUID? {
    guard
      path.contains(where: {
        $0.isHidden
      })
    else {
      return nil
    }
    guard let token = try grant.rootToken() else {
      throw VaultError.rootRequired
    }
    try grant.access(rootToken: token) { _ in
      ()
    }
    return token
  }

  /// 业务作用：操作开始前按外层优先找出尚未验证的目录，导出和删除不能绕过内部保护。
  /// 参数说明：
  /// - `id`：本次明确选择的条目。
  /// - `recursive`：完整子树操作需逐项检查所有受保护目录。
  /// - `grant`：当前 App 会话。
  /// 返回：下一项需要验证的目录；全部满足时为空，不产生文件副作用。
  func nextLockedFolder(id: UUID, recursive: Bool, using grant: VaultGrant) throws -> VaultMedia? {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let media = try rawReader(id: id, using: grant).media
    let candidates =
      recursive && media.isFolder ? try descendantEntries(of: media, using: grant) : [media]
    for candidate in candidates {
      let path = try folderChain(for: candidate, includingSelf: true, using: grant)
      _ = try rootRequirement(in: path, using: grant)
      for folder in path {
        if let password = folder.folderPassword {
          do {
            try grant.access(folders: [folder.id: password.revision]) { _ in
              ()
            }
          } catch VaultError.folderPasswordRequired {
            return folder
          }
        }
      }
    }
    return nil
  }

  /// 业务作用：通过独立目录密码后只为当前 App 会话发放该目录的读取授权。
  /// 参数说明：
  /// - `id`：请求验证的目录。
  /// - `password`：用户本次输入的文本密码。
  /// - `grant`：当前 App 会话。
  /// 返回：正确时开放目录；祖先未验证、目录已变化、错误或失权时拒绝。
  func authenticateFolder(id: UUID, password: String, using grant: VaultGrant) throws {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let folder = try rawReader(id: id, using: grant).media
    let parents = try folderRequirements(for: folder, includingSelf: false, using: grant)
    try grant.access(folders: parents) { _ in
      ()
    }
    guard folder.isFolder, !folder.isFilePackage, let protection = folder.folderPassword else {
      throw VaultError.invalidFolder
    }
    try VaultCrypto.verifyFolderPassword(
      password, protection: protection, folderID: id, using: grant)
    guard try rawReader(id: id, using: grant).media == folder else {
      throw VaultError.documentChanged
    }
    try grant.allowFolder(id, revision: protection.revision, requiring: parents)
  }

  /// 业务作用：结束目录操作后只保留当前浏览路径权限，重新进入其它目录必须再次验证。
  /// 参数说明：
  /// - `id`：新的当前目录；根目录为空。
  /// - `grant`：当前 App 会话。
  /// 返回：其它目录的旧读取器立即失权，不保存访问位置。
  func retainFolderAccess(to id: UUID?, using grant: VaultGrant) throws {
    try store.authorize(grant)
    let path =
      try id.map { id in
        try folderChain(
          for: rawReader(id: id, using: grant).media, includingSelf: true, using: grant)
      } ?? []
    grant.retainFolderAccess(Set(path.map(\.id)))
  }

  /// 业务作用：将目录密码材料写入新的认证密文，并撤销全部旧读取以防策略变更被绕过。
  /// 参数说明：
  /// - `id`：需要设置、修改或取消保护的普通目录。
  /// - `password`：设置或修改后的新密码；取消保护时为空。
  /// - `previous`：修改或取消保护时必须重新验证的原目录密码；首次设置时为空。
  /// - `grant`：当前 App 会话。
  /// 返回：成功后交付清空目录权限的新 App 会话；失败保留原密文或锁定后要求核实。
  func changeFolderPassword(
    id: UUID, password: String?, previous: String?, using grant: VaultGrant
  ) throws -> VaultGrant {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let original = try rawReader(id: id, using: grant).media
    guard original.isFolder, !original.isFilePackage else {
      throw VaultError.invalidFolder
    }
    let parents = try folderRequirements(for: original, includingSelf: false, using: grant)
    try grant.access(folders: parents) { _ in
      ()
    }
    let protection: FolderPassword?
    if let password {
      if original.folderPassword != nil {
        // 浏览授权与 ROOT 不能代替改密验证；原保护持续生效，只有本次原密码正确才能发布新校验材料。
        guard let previous else {
          throw VaultError.folderProtectionExists
        }
        try authenticateFolder(id: id, password: previous, using: grant)
      } else if previous != nil {
        // 首次设置没有可供验证的原密码，不能让已过期的保护管理请求被当成新设置继续执行。
        throw VaultError.invalidFolder
      }
      let prepared = try VaultCrypto.folderPassword(password, folderID: id, using: grant)
      // 新保护必须能由本次确认的原始输入立即验证，不能发布尚未证明可用的校验材料。
      try VaultCrypto.verifyFolderPassword(
        password, protection: prepared, folderID: id, using: grant)
      protection = prepared
    } else {
      guard let previous, original.folderPassword != nil else {
        throw VaultError.invalidFolder
      }
      try authenticateFolder(id: id, password: previous, using: grant)
      protection = nil
    }
    let media = VaultMedia(
      id: original.id, originalFilename: original.originalFilename,
      contentType: original.contentType,
      byteCount: 0, sha256: original.sha256, parentID: original.parentID,
      folderPassword: protection,
      hidden: original.hidden
    )
    return try publishMetadata(
      media, replacing: original, requirements: parents, using: grant,
      uncertain: .folderCommitUncertain)
  }

  /// 业务作用：仅在 ROOT 已验证开启时更改普通文件夹隐藏状态，保留独立目录密码与全部内容。
  /// 参数说明：
  /// - `id`：当前明确选择的普通文件夹，不接受文件或文档包。
  /// - `hidden`：设为隐藏或取消隐藏。
  /// - `grant`：拥有当前父目录访问权且已开启 ROOT 的 App 会话。
  /// 返回：完整发布后交付保留 ROOT 及父目录授权的新会话；拒绝或发布前失败时保持原状态。
  func setHidden(id: UUID, hidden: Bool, using grant: VaultGrant) throws -> VaultGrant {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    guard let token = try grant.rootToken() else {
      throw VaultError.rootRequired
    }
    try grant.access(rootToken: token) { _ in
      ()
    }
    let original = try rawReader(id: id, using: grant).media
    guard original.isFolder, !original.isFilePackage else {
      throw VaultError.invalidSelection
    }
    let parents = try folderRequirements(for: original, includingSelf: false, using: grant)
    var media = original
    media.hidden = hidden ? true : nil
    // ROOT 仅授权可见性管理，不读取目录载荷或取消目录密码；父目录仍必须已经授权。
    let replacement = try publishMetadata(
      media, replacing: original, requirements: parents, using: grant,
      uncertain: .organizationCommitUncertain)
    for (folderID, revision) in parents {
      try replacement.allowFolder(folderID, revision: revision)
    }
    return replacement
  }

  /// 业务作用：有界重新封装名称或保护元数据并原子发布，保持原始内容与目录子项不变。
  /// 参数说明：
  /// - `media`：本次需要持久化的完整元数据，内容长度和摘要不得改变。
  /// - `original`：发布前必须仍有效的文件或目录快照。
  /// - `requirements`：提交期间必须保持有效的目录授权。
  /// - `grant`：当前 App 会话。
  /// - `uncertain`：撤销旧会话后无法确认提交时向界面交付的保护态原因。
  /// - `retainingSession`：仅照片呈现转换保持当前会话，禁止用于改变目录保护或父子关系。
  /// - `retainedFolders`：改名后转交的原父路径浏览证明，不得超出提交前已经验证的路径。
  /// 返回：完整校验后交付新会话及指定原路径证明，照片呈现转换沿用当前会话；发布不明时锁定。
  private func publishMetadata(
    _ media: VaultMedia, replacing original: VaultMedia, requirements: [UUID: UUID],
    using grant: VaultGrant, uncertain: VaultError, retainingSession: Bool = false,
    retainedFolders: [UUID: UUID] = [:]
  ) throws -> VaultGrant {
    let id = original.id
    guard media.id == id, media.byteCount == original.byteCount,
      media.sha256 == original.sha256
    else {
      throw VaultError.corrupt
    }
    // 只有层级和保护未改变的改名可以保留原父路径，不能转交来源自身或无关目录的临时权限。
    guard
      retainedFolders.isEmpty
        || (!retainingSession && original.parentID == media.parentID
          && original.folderPassword == media.folderPassword && original.hidden == media.hidden
          && original.contentType == media.contentType && original.photoAsset == media.photoAsset
          && retainedFolders[original.id] == nil
          && retainedFolders.allSatisfy({
            requirements[$0.key] == $0.value
          }))
    else {
      throw VaultError.invalidSelection
    }
    if retainingSession {
      guard original.isFolder, media.isFolder, media.photoAsset != nil,
        original.parentID == media.parentID, original.folderPassword == media.folderPassword,
        original.hidden == media.hidden, original.folderPassword == nil, !original.isHidden
      else {
        throw VaultError.invalidSelection
      }
    }
    let destination = store.mediaDirectory.appendingPathComponent(id.uuidString + ".evm")
    let input = try VaultMediaReader(
      url: destination, grant: grant, folderRequirements: requirements)
    guard input.media == original else {
      throw VaultError.documentChanged
    }
    let identity = MediaIdentity(
      formatVersion: 1, id: id, vaultID: grant.vaultID, byteCount: original.byteCount,
      chunkSize: VaultMediaReader.chunkSize,
      chunkCount: Int(
        (original.byteCount + UInt64(VaultMediaReader.chunkSize) - 1)
          / UInt64(VaultMediaReader.chunkSize)),
      noncePrefix: try VaultCrypto.random(8))
    let context = try VaultCrypto.encode(identity)
    let fileKey = try VaultCrypto.random(32)
    let header = try grant.access(folders: requirements) { root in
      MediaHeader(
        identity: identity,
        wrappedKey: try VaultCrypto.seal(fileKey, key: SymmetricKey(data: root), context: context),
        metadata: try VaultCrypto.seal(
          VaultCrypto.encode(media), key: VaultCrypto.key(fileKey, context: Data("metadata".utf8)),
          context: context))
    }
    let bytes = try VaultCrypto.encode(header)
    guard bytes.count <= 65_536 else {
      throw VaultError.storage
    }
    let temporary = store.mediaDirectory.appendingPathComponent(".\(UUID()).partial")
    defer {
      try? FileManager.default.removeItem(at: temporary)
    }
    let output = try VaultStorage.create(temporary)
    defer {
      try? output.close()
    }
    try output.write(contentsOf: VaultMediaReader.magic)
    var size = UInt32(bytes.count).bigEndian
    try withUnsafeBytes(of: &size) {
      try output.write(contentsOf: Data($0))
    }
    try output.write(contentsOf: bytes)
    let headerHash = Data(SHA256.hash(data: bytes))
    // 内容分块绑定完整头部；名称改变后必须使用新密钥和 nonce，不能修改头部后沿用旧标签。
    for index in 0..<identity.chunkCount {
      try autoreleasepool {
        try Task.checkCancellation()
        let part = try input.read(
          offset: UInt64(index) * UInt64(VaultMediaReader.chunkSize),
          count: VaultMediaReader.chunkSize)
        let sealed = try AES.GCM.seal(
          part, using: SymmetricKey(data: fileKey),
          nonce: VaultMediaReader.nonce(prefix: identity.noncePrefix, index: index),
          authenticating: VaultMediaReader.chunkContext(
            headerHash, index: index, length: part.count))
        try output.write(contentsOf: sealed.ciphertext)
        try output.write(contentsOf: sealed.tag)
      }
    }
    try output.synchronize()
    try output.close()
    let staged = try VaultMediaReader(url: temporary, grant: grant)
    guard staged.media == media else {
      throw VaultError.corrupt
    }
    try staged.verify()
    try Task.checkCancellation()
    guard try rawReader(id: id, using: grant).media == original else {
      throw VaultError.documentChanged
    }
    // 用户改名或保护变化先撤销旧能力；零载荷照片呈现转换不改变权限或内容，沿用本次已验证会话。
    let replacement: VaultGrant
    if retainingSession {
      replacement = grant
    } else {
      replacement = try store.rotateSession(using: grant, folders: requirements)
    }
    do {
      try replacement.access { _ in
        try Task.checkCancellation()
        guard Darwin.rename(temporary.path, destination.path) == 0 else {
          throw VaultError.storage
        }
        try VaultStorage.synchronizeDirectory(store.mediaDirectory)
      }
      // 密文已完整发布后才恢复原父路径的已有浏览证明，旧读取器仍随会话轮换失效。
      for (folderID, revision) in retainedFolders {
        try replacement.allowFolder(folderID, revision: revision)
      }
      return replacement
    } catch {
      // 失权和发布状态不明时关闭新会话，避免继续使用无法确认的名称或保护状态。
      store.lock()
      throw uncertain
    }
  }

  /// 业务作用：从同一来源句柄流式保存密文，完整校验并发布后才发放可选删源收据。
  /// 参数说明：
  /// - `source`：用户授权的本地普通文件，媒体与其它文件均保持原始字节。
  /// - `originalName`：系统交付临时文件时对应的原名；普通本地文件为空。
  /// - `parentID`：当前已授权的接收目录；为空时保存到保险箱根目录。
  /// - `grant`：当前独立密码授权的会话。
  /// - `status`：当前文件的阶段、字节进度和已完成计数，仅在本次内存中交付。
  /// - `progress`：仅在当前界面使用的进度，不落盘。
  /// 返回：保存完整的媒体与来源身份；失败或失权时保留来源，不发布部分文件。
  func save(
    source: URL, originalName: String? = nil, in parentID: UUID? = nil, using grant: VaultGrant,
    status: @escaping @Sendable (ImportProgress) -> Void = { _ in },
    progress: @escaping @Sendable (Double) -> Void = { _ in }
  ) throws -> SavedImport {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try validateImportDestination(parentID, using: grant)
    return try autoreleasepool {
      try saveEntry(
        source: source, name: originalName ?? source.lastPathComponent, parentID: parentID,
        directoryEntry: false,
        using: grant, status: status, progress: progress)
    }
  }

  /// 业务作用：确认用户选择的导入位置仍是已授权普通目录，不把文档包内部当作接收位置。
  /// 参数说明：
  /// - `parentID`：导入开始时的目录身份；为空时使用保险箱根目录。
  /// - `grant`：当前浏览会话，复用进入目录时已有的权限。
  /// 返回：位置及权限有效时成功；失效、失权或文档包目标时拒绝，不回退到根目录。
  private func validateImportDestination(_ parentID: UUID?, using grant: VaultGrant) throws {
    try store.authorize(grant)
    if let parentID {
      let parent = try reader(id: parentID, using: grant).media
      guard parent.isFolder, !parent.isFilePackage else {
        throw VaultError.invalidFolder
      }
    }
  }

  /// 业务作用：仅在用户手动保存且本次编辑认证有效时，完整校验后原子替换文本密文。
  /// 参数说明：
  /// - `text`：当前编辑草稿，只在内存中编码和加密。
  /// - `edit`：绑定原文件身份及原摘要的一次性编辑能力。
  /// 返回：保持文件身份、原名和目录的认证元数据；发布前失败保留旧文件，发布状态不明时要求重新解锁核实。
  func replaceText(_ text: String, editing edit: VaultTextEdit) throws -> VaultMedia {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    let grant = try edit.authorization()
    try store.authorize(grant)
    let original = edit.media
    guard original.isTextDocument,
      try reader(id: original.id, using: grant).media == original
    else {
      throw VaultError.documentChanged
    }
    let data = try edit.format.encode(text)
    let size = UInt64(data.count)
    let identity = MediaIdentity(
      formatVersion: 1, id: original.id, vaultID: grant.vaultID, byteCount: size,
      chunkSize: VaultMediaReader.chunkSize,
      chunkCount: (data.count + VaultMediaReader.chunkSize - 1) / VaultMediaReader.chunkSize,
      noncePrefix: try VaultCrypto.random(8))
    let media = VaultMedia(
      id: original.id, originalFilename: original.originalFilename,
      contentType: original.contentType, byteCount: size, sha256: Data(SHA256.hash(data: data)),
      parentID: original.parentID, hidden: original.hidden)
    // 每次保存使用新的文件密钥与 nonce 前缀，不能在同一密钥下重用旧分块的 nonce。
    let fileKey = try VaultCrypto.random(32)
    let context = try VaultCrypto.encode(identity)
    let wrapped = try grant.access { root in
      try VaultCrypto.seal(fileKey, key: SymmetricKey(data: root), context: context)
    }
    let header = MediaHeader(
      identity: identity, wrappedKey: wrapped,
      metadata: try VaultCrypto.seal(
        VaultCrypto.encode(media), key: VaultCrypto.key(fileKey, context: Data("metadata".utf8)),
        context: context))
    let headerBytes = try VaultCrypto.encode(header)
    guard headerBytes.count <= 65_536 else {
      throw VaultError.unsupportedMedia
    }
    let digest = Data(SHA256.hash(data: headerBytes))
    let temporary = store.mediaDirectory.appendingPathComponent(".\(UUID().uuidString).partial")
    let destination = store.mediaDirectory.appendingPathComponent(original.id.uuidString + ".evm")
    defer {
      try? FileManager.default.removeItem(at: temporary)
    }
    let output = try VaultStorage.create(temporary)
    defer {
      try? output.close()
    }
    try output.write(contentsOf: VaultMediaReader.magic)
    var length = UInt32(headerBytes.count).bigEndian
    try withUnsafeBytes(of: &length) {
      try output.write(contentsOf: Data($0))
    }
    try output.write(contentsOf: headerBytes)
    for index in 0..<identity.chunkCount {
      try grant.check()
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      let start = index * VaultMediaReader.chunkSize
      let bytes = data.subdata(in: start..<min(start + VaultMediaReader.chunkSize, data.count))
      let sealed = try AES.GCM.seal(
        bytes, using: SymmetricKey(data: fileKey),
        nonce: VaultMediaReader.nonce(prefix: identity.noncePrefix, index: index),
        authenticating: VaultMediaReader.chunkContext(digest, index: index, length: bytes.count))
      try output.write(contentsOf: sealed.ciphertext)
      try output.write(contentsOf: sealed.tag)
    }
    try output.synchronize()
    try output.close()
    // 暂存始终为密文；逐块复验与原内容检查完成前，旧密文保持不变。
    try VaultMediaReader(url: temporary, grant: grant).verify()
    guard try reader(id: original.id, using: grant).media == original else {
      throw VaultError.documentChanged
    }
    if Task.isCancelled {
      throw VaultError.cancelled
    }
    try edit.publish {
      guard Darwin.rename(temporary.path, destination.path) == 0 else {
        throw VaultError.documentCommitUncertain
      }
      do {
        try VaultStorage.synchronizeDirectory(store.mediaDirectory)
      } catch {
        // 替换已经发生后不能回滚为旧内容或声称没有保存，关闭会话后由重新读取确认。
        throw VaultError.documentCommitUncertain
      }
    }
    return media
  }

  /// 业务作用：将文件内容与加密目录身份绑定后发布一个完整条目，目录条目只携带认证元数据。
  /// 参数说明：
  /// - `source`：已授权普通文件，目录条目使用本次创建的空暂存。
  /// - `name`：保留的文件名或目录名，不能包含路径分隔符。
  /// - `parentID`：加密父目录身份，根级条目为空。
  /// - `directoryEntry`：是否创建没有数据载荷的目录条目。
  /// - `grant`：当前独立密码会话。
  /// - `status`：当前文件阶段及字节数量，不持久化来源或进度。
  /// - `progress`：当前条目的内存进度。
  /// 返回：完整认证并同步的密文及来源收据；失败不发布部分文件。
  private func saveEntry(
    source: URL, name: String, parentID: UUID?, directoryEntry: Bool,
    using grant: VaultGrant, status: @escaping @Sendable (ImportProgress) -> Void = { _ in },
    progress: @escaping @Sendable (Double) -> Void = { _ in }
  ) throws -> SavedImport {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let directoryRequirements: [UUID: UUID] =
      try parentID.map { parentID in
        let parent = try rawReader(id: parentID, using: grant).media
        // 内部层级必须仍是目录；文档包的子项也通过此入口保留完整结构。
        guard parent.isFolder else {
          throw VaultError.invalidFolder
        }
        return try folderRequirements(for: parent, includingSelf: true, using: grant)
      } ?? [:]
    // 导入复用进入目录时取得的权限，不再次索取密码；离开路径或锁定后失权即停止写入。
    try grant.access(folders: directoryRequirements) { _ in
      ()
    }
    let scoped = source.startAccessingSecurityScopedResource()
    defer {
      if scoped {
        source.stopAccessingSecurityScopedResource()
      }
    }
    let resources = try source.resourceValues(forKeys: [
      .isSymbolicLinkKey, .isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey,
    ])
    guard resources.isSymbolicLink != true, !name.isEmpty, name != ".", name != "..",
      !name.contains("/"), !name.contains("\0")
    else {
      throw VaultError.unsupportedSource
    }
    if resources.isUbiquitousItem == true,
      resources.ubiquitousItemDownloadingStatus != .current,
      resources.ubiquitousItemDownloadingStatus != .downloaded
    {
      throw VaultError.cloudOnly
    }
    let descriptor = Darwin.open(source.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard descriptor >= 0 else {
      throw VaultError.unsupportedSource
    }
    let input = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    defer {
      try? input.close()
    }
    let fingerprint = try SourceIdentity(input)
    let contentType: String
    if directoryEntry {
      contentType = UTType.folder.identifier
    } else {
      contentType = try type(file: input)
    }
    let size = UInt64(fingerprint.size)
    guard size <= UInt64(VaultMediaReader.chunkSize) * UInt64(UInt32.max - 1),
      !directoryEntry || size == 0
    else {
      throw VaultError.unsupportedMedia
    }
    let id = UUID()
    let identity = MediaIdentity(
      formatVersion: 1, id: id, vaultID: grant.vaultID, byteCount: size,
      chunkSize: VaultMediaReader.chunkSize,
      chunkCount: Int(
        (size + UInt64(VaultMediaReader.chunkSize) - 1) / UInt64(VaultMediaReader.chunkSize)),
      noncePrefix: try VaultCrypto.random(8))
    let report: @Sendable (ImportPhase, UInt64) -> Void = { phase, bytes in
      let update = ImportProgress(
        phase: phase, filename: name, currentBytes: bytes, totalBytes: size)
      status(update)
      progress(update.fraction ?? 0)
    }
    report(.digest, 0)
    let digest = try hash(input, grant: grant) { bytes in
      report(.digest, bytes)
    }
    guard try SourceIdentity(input) == fingerprint else {
      throw VaultError.sourceChanged
    }
    let media = VaultMedia(
      id: id, originalFilename: name,
      contentType: contentType, byteCount: size, sha256: digest, parentID: parentID)
    let fileKey = try VaultCrypto.random(32)
    let context = try VaultCrypto.encode(identity)
    let wrapped = try grant.access { root in
      try VaultCrypto.seal(fileKey, key: SymmetricKey(data: root), context: context)
    }
    let header = MediaHeader(
      identity: identity, wrappedKey: wrapped,
      metadata: try VaultCrypto.seal(
        VaultCrypto.encode(media), key: VaultCrypto.key(fileKey, context: Data("metadata".utf8)),
        context: context))
    let headerBytes = try VaultCrypto.encode(header)
    guard headerBytes.count <= 65_536 else {
      throw VaultError.unsupportedMedia
    }
    let headerHash = Data(SHA256.hash(data: headerBytes))
    let temporary = store.mediaDirectory.appendingPathComponent(".\(id).partial")
    let destination = store.mediaDirectory.appendingPathComponent(id.uuidString + ".evm")
    defer {
      try? FileManager.default.removeItem(at: temporary)
    }
    let output = try VaultStorage.create(temporary)
    defer {
      try? output.close()
    }
    try output.write(contentsOf: VaultMediaReader.magic)
    var length = UInt32(headerBytes.count).bigEndian
    try withUnsafeBytes(of: &length) {
      try output.write(contentsOf: Data($0))
    }
    try output.write(contentsOf: headerBytes)
    try input.seek(toOffset: 0)
    var secondHash = SHA256()
    var position: UInt64 = 0
    report(.encrypt, 0)
    for index in 0..<identity.chunkCount {
      // 一块完成写入后立即回收读取、加密与桥接缓冲，内存不随源文件总大小增长。
      try autoreleasepool {
        if Task.isCancelled {
          throw VaultError.cancelled
        }
        try grant.check()
        let amount = Int(min(UInt64(VaultMediaReader.chunkSize), size - position))
        let bytes = try VaultStorage.read(input, count: amount)
        secondHash.update(data: bytes)
        let sealed = try AES.GCM.seal(
          bytes, using: SymmetricKey(data: fileKey),
          nonce: VaultMediaReader.nonce(prefix: identity.noncePrefix, index: index),
          authenticating: VaultMediaReader.chunkContext(
            headerHash, index: index, length: bytes.count)
        )
        try output.write(contentsOf: sealed.ciphertext)
        try output.write(contentsOf: sealed.tag)
        position += UInt64(amount)
        report(.encrypt, position)
      }
    }
    guard try SourceIdentity(input) == fingerprint, Data(secondHash.finalize()) == digest else {
      throw VaultError.sourceChanged
    }
    try output.synchronize()
    try output.close()
    // 在最终发布之前重新打开暂存并校验全部分块，不能仅依赖写入成功来授权删源。
    report(.verify, 0)
    try VaultMediaReader(url: temporary, grant: grant).verify { fraction in
      report(.verify, UInt64(Double(size) * min(1, max(0, fraction))))
    }
    report(.commit, size)
    try grant.access(folders: directoryRequirements) { _ in
      guard !FileManager.default.fileExists(atPath: destination.path),
        Darwin.rename(temporary.path, destination.path) == 0
      else {
        throw VaultError.storage
      }
      try VaultStorage.synchronizeDirectory(store.mediaDirectory)
    }
    report(.confirm, 0)
    try VaultMediaReader(url: destination, grant: grant).verify { fraction in
      report(.confirm, UInt64(Double(size) * min(1, max(0, fraction))))
    }
    status(
      ImportProgress(
        phase: .saved, filename: name, currentBytes: size, totalBytes: size,
        completedFiles: directoryEntry ? 0 : 1, completedBytes: size))
    progress(1)
    return SavedImport(media: media, source: source, identity: fingerprint)
  }

  /// 业务作用：边遍历边逐文件提交目录，保留层级、空目录与原名，不预装全部来源路径。
  /// 参数说明：
  /// - `source`：用户通过系统选择器授权的本地目录。
  /// - `parentID`：当前已授权的接收目录；来源目录作为其子目录保存，空值表示保险箱根目录。
  /// - `grant`：当前独立密码会话。
  /// - `status`：当前条目的阶段、字节进度及累计完成数量，不建立持久化来源清单。
  /// - `progress`：当前文件内的进度，目录未知总量时不表示整个目录的百分比。
  /// 返回：已建立的根目录、完整文件收据与失败数量；失败或中断保留来源，已完成条目仍可解锁读取。
  func saveFolder(
    source: URL, in parentID: UUID? = nil, using grant: VaultGrant,
    status: @escaping @Sendable (ImportProgress) -> Void = { _ in },
    progress: @escaping @Sendable (Double) -> Void = { _ in }
  ) throws -> (folder: VaultMedia, saved: [SavedImport], failures: Int) {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try validateImportDestination(parentID, using: grant)
    let scoped = source.startAccessingSecurityScopedResource()
    defer {
      if scoped {
        source.stopAccessingSecurityScopedResource()
      }
    }
    let root = source.standardizedFileURL
    let attributes = try root.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
    let canonical = root.resolvingSymlinksInPath().path
    let vaultPath = store.directory.resolvingSymlinksInPath().path
    // 不能枚举包含保险箱自身的目录，否则导入过程中创建的密文可能再次成为来源。
    guard attributes.isDirectory == true, attributes.isSymbolicLink != true,
      canonical != vaultPath, !vaultPath.hasPrefix(canonical + "/")
    else {
      throw VaultError.invalidFolder
    }
    let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey]
    var traversalError: Error?
    guard
      let enumerator = FileManager.default.enumerator(
        at: root, includingPropertiesForKeys: keys, options: [],
        errorHandler: { _, error in
          traversalError = error
          return false
        })
    else {
      throw VaultError.storage
    }
    status(
      ImportProgress(
        phase: .directory, filename: root.lastPathComponent,
        currentBytes: 0, totalBytes: 0))
    let folder = try autoreleasepool {
      try saveDirectory(name: root.lastPathComponent, parentID: parentID, using: grant)
    }
    var parents: [(level: Int, id: UUID)] = [(0, folder.id)]
    var saved: [SavedImport] = []
    var failures = 0
    var completedBytes: UInt64 = 0
    while true {
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      try grant.check()
      // 每次只持有当前条目的 Foundation 对象；父目录栈随层级收缩，不累积整棵来源目录。
      let more = try autoreleasepool {
        guard let item = enumerator.nextObject() as? URL else {
          return false
        }
        let level = enumerator.level
        while let parent = parents.last, parent.level >= level {
          parents.removeLast()
        }
        do {
          guard let parent = parents.last, parent.level == level - 1 else {
            throw VaultError.sourceChanged
          }
          let values = try item.resourceValues(forKeys: Set(keys))
          // 不跟随链接；已提交文件继续保留，不能把尚未验证的来源计为成功或删源依据。
          guard values.isSymbolicLink != true,
            values.isDirectory == true || values.isRegularFile == true
          else {
            throw VaultError.unsupportedSource
          }
          if values.isDirectory == true {
            let child = try saveDirectory(
              name: item.lastPathComponent, parentID: parent.id, using: grant)
            parents.append((level, child.id))
            status(
              ImportProgress(
                phase: .directory, filename: item.lastPathComponent,
                currentBytes: 0, totalBytes: 0
              ).adding(files: saved.count, bytes: completedBytes, failures: failures))
          } else {
            let previousFiles = saved.count
            let previousBytes = completedBytes
            let previousFailures = failures
            let receipt = try saveEntry(
              source: item, name: item.lastPathComponent, parentID: parent.id,
              directoryEntry: false,
              using: grant,
              status: { update in
                status(
                  update.adding(
                    files: previousFiles, bytes: previousBytes, failures: previousFailures))
              }, progress: progress)
            saved.append(receipt)
            completedBytes += receipt.media.byteCount
          }
        } catch {
          try grant.check()
          if Task.isCancelled {
            throw VaultError.cancelled
          }
          // 当前目录失败后不枚举它的子项，不能把子项错误归到上一层；其余条目仍可逐个提交。
          enumerator.skipDescendants()
          failures += 1
        }
        return true
      }
      if !more {
        break
      }
    }
    if traversalError != nil {
      failures += 1
    }
    status(
      ImportProgress(
        phase: .saved, filename: root.lastPathComponent,
        currentBytes: 0, totalBytes: 0
      ).adding(files: saved.count, bytes: completedBytes, failures: failures))
    progress(1)
    return (folder, saved, failures)
  }

  /// 业务作用：将目录名称及父目录身份写入认证密文，使空目录也能被保存和原样导出。
  /// 参数说明：
  /// - `name`：用户选择范围内的原目录名。
  /// - `parentID`：父目录密文身份，根目录为空。
  /// - `grant`：当前独立密码会话。
  /// 返回：已经完整保存的零载荷目录条目；空暂存不包含用户文件内容且在退出时移除。
  private func saveDirectory(name: String, parentID: UUID?, using grant: VaultGrant) throws
    -> VaultMedia
  {
    let empty = store.directory.appendingPathComponent(".\(UUID()).partial")
    let output = try VaultStorage.create(empty)
    try output.close()
    defer {
      try? FileManager.default.removeItem(at: empty)
    }
    return try saveEntry(
      source: empty, name: name, parentID: parentID, directoryEntry: true, using: grant
    ).media
  }

  /// 业务作用：在当前已授权目录内新建空文件夹，名称及层级仅保存为认证密文。
  /// 参数说明：
  /// - `name`：用户输入的单层文件夹名称。
  /// - `parentID`：目标普通目录；为空时在保险箱根目录创建。
  /// - `grant`：具备目标目录访问权的当前会话。
  /// 返回：完整保存的新文件夹；名称非法、重名或失权时不创建条目。
  func createFolder(name: String, in parentID: UUID?, using grant: VaultGrant) throws -> VaultMedia
  {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      name != ".", name != "..", !name.contains("/"), !name.contains("\0"),
      name.utf8.count <= 255
    else {
      throw VaultError.invalidFolderName
    }
    if let parentID {
      let parent = try reader(id: parentID, using: grant).media
      guard parent.isFolder, !parent.isFilePackage else {
        throw VaultError.invalidFolder
      }
    }
    guard
      try !allEntries(using: grant).contains(where: {
        $0.parentID == parentID
          && $0.originalFilename.localizedCaseInsensitiveCompare(name) == .orderedSame
      })
    else {
      throw VaultError.invalidFolderName
    }
    return try saveDirectory(name: name, parentID: parentID, using: grant)
  }

  /// 业务作用：只更改文件夹的加密名称，保持目录身份、子项层级和原密码验证材料不变。
  /// 参数说明：
  /// - `id`：明确选择的普通文件夹。
  /// - `name`：新的单层名称，不能与同级项目重名。
  /// - `retainingParentAccess`：是否转交原父路径的已有浏览权，不继承来源自身或其它目录权限。
  /// - `grant`：已验证该目录及其祖先的当前 App 会话。
  /// 返回：名称发布后返回新会话，可保留原父路径浏览权；非法名称、重名或未验证保护时保持原目录。
  func renameFolder(
    id: UUID, to name: String, retainingParentAccess: Bool = false, using grant: VaultGrant
  ) throws -> VaultGrant {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let original = try rawReader(id: id, using: grant).media
    guard original.isFolder, !original.isFilePackage else {
      throw VaultError.invalidFolder
    }
    guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      name != ".", name != "..", !name.contains("/"), !name.contains("\0"),
      name.utf8.count <= 255,
      try !allEntries(using: grant).contains(where: {
        $0.id != id && $0.parentID == original.parentID
          && $0.originalFilename.localizedCaseInsensitiveCompare(name) == .orderedSame
      })
    else {
      throw VaultError.invalidFolderName
    }
    let requirements = try folderRequirements(for: original, includingSelf: true, using: grant)
    // 重命名不能借可见的目录名称绕过保护，必须在重写密文前验证整条路径。
    try grant.access(folders: requirements) { _ in
      ()
    }
    if name == original.originalFilename {
      return grant
    }
    let media = VaultMedia(
      id: original.id, originalFilename: name, contentType: original.contentType,
      byteCount: 0, sha256: original.sha256, parentID: original.parentID,
      folderPassword: original.folderPassword, hidden: original.hidden,
      photoAsset: original.photoAsset)
    let retained =
      retainingParentAccess
      ? try folderRequirements(for: original, includingSelf: false, using: grant) : [:]
    return try publishMetadata(
      media, replacing: original, requirements: requirements, using: grant,
      uncertain: .organizationCommitUncertain, retainedFolders: retained)
  }

  /// 业务作用：更改普通文件或文档包的加密名称，保留内容、身份、格式与所在目录。
  /// 参数说明：
  /// - `id`：当前保险箱内明确选择的文件或文档包。
  /// - `name`：保留原扩展名的新单层名称，不得与同级项目重名。
  /// - `retainingParentAccess`：是否转交原父路径的已有浏览权，不继承其它目录权限。
  /// - `grant`：已验证所属保护目录的当前会话。
  /// 返回：完整密文发布后返回新会话及指定原父路径浏览权；名称非法、内容损坏、取消或未授权时不替换原件。
  func renameFile(
    id: UUID, to name: String, retainingParentAccess: Bool = false, using grant: VaultGrant
  ) throws -> VaultGrant {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let original = try rawReader(id: id, using: grant).media
    guard !original.isFolder || original.isFilePackage else {
      throw VaultError.invalidSelection
    }
    let requirements = try folderRequirements(for: original, includingSelf: true, using: grant)
    // 文件改名仍需所属目录的访问权，名称校验也不能泄露未授权目录的同名条目。
    try grant.access(folders: requirements) { _ in
      ()
    }
    guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      name != ".", name != "..", !name.contains("/"), !name.contains("\0"),
      name.utf8.count <= 255,
      try !allEntries(using: grant).contains(where: {
        $0.id != id && $0.parentID == original.parentID
          && $0.originalFilename.localizedCaseInsensitiveCompare(name) == .orderedSame
      })
    else {
      throw VaultError.invalidFileName
    }
    guard
      (name as NSString).pathExtension.lowercased()
        == (original.originalFilename as NSString).pathExtension.lowercased()
    else {
      throw VaultError.fileExtensionChanged
    }
    if name == original.originalFilename {
      return grant
    }
    let media = VaultMedia(
      id: original.id, originalFilename: name, contentType: original.contentType,
      byteCount: original.byteCount, sha256: original.sha256, parentID: original.parentID,
      folderPassword: original.folderPassword, hidden: original.hidden,
      photoAsset: original.photoAsset)
    let retained =
      retainingParentAccess
      ? try folderRequirements(for: original, includingSelf: false, using: grant) : [:]
    return try publishMetadata(
      media, replacing: original, requirements: requirements, using: grant,
      uncertain: .organizationCommitUncertain, retainedFolders: retained)
  }

  /// 业务作用：按保险箱虚拟绝对路径定位移动目标，逐层验证保护，不访问同名系统路径。
  /// 参数说明：
  /// - `path`：以 / 表示保险箱根目录的完整目录路径。
  /// - `grant`：当前 App 会话及本次已验证的目录证明。
  /// 返回：已验证的目标身份或下一层密码门禁；不存在、非法或失权时不移动或创建目录。
  func resolveMoveDirectory(
    path: String, using grant: VaultGrant
  ) throws -> (id: UUID?, locked: VaultMedia?) {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let components = path.split(separator: "/").map(String.init)
    guard path.hasPrefix("/"), path.utf8.count <= 65_536, components.count < 256,
      components.allSatisfy({ $0 != "." && $0 != ".." && !$0.contains("\0") })
    else {
      throw VaultError.invalidVaultPath
    }
    let entries = try allEntries(using: grant)
    var parentID: UUID?
    for name in components {
      let matches = entries.filter {
        $0.parentID == parentID && $0.isFolder && !$0.isFilePackage
          && $0.originalFilename.localizedCaseInsensitiveCompare(name) == .orderedSame
      }
      guard let folder = matches.first else {
        throw VaultError.moveDirectoryNotFound
      }
      guard matches.count == 1 else {
        throw VaultError.corrupt
      }
      _ = try rootRequirement(
        in: folderChain(for: folder, includingSelf: true, using: grant), using: grant)
      // 在查找下一层名称前先验证当前保护，不能通过路径探测受保护目录的内部结构。
      if let protection = folder.folderPassword {
        do {
          try grant.access(folders: [folder.id: protection.revision]) { _ in
            ()
          }
        } catch VaultError.folderPasswordRequired {
          return (nil, folder)
        }
      }
      parentID = folder.id
    }
    try grant.check()
    return (parentID, nil)
  }

  /// 业务作用：在移动前检查来源、目标、保护范围与同名冲突，不产生文件副作用。
  /// 参数说明：
  /// - `id`：明确选中的来源文件或未受密码保护的目录树。
  /// - `parentID`：接收目录；为空时移至保险箱根目录。
  /// - `grant`：具有来源及目标目录访问权的当前会话。
  /// 返回：已认证来源与本次所需目录证明；受保护目录树、目录保护范围逃逸、循环或重名时拒绝。
  private func prepareMove(id: UUID, to parentID: UUID?, using grant: VaultGrant) throws
    -> (media: VaultMedia, requirements: [UUID: UUID])
  {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let original = try rawReader(id: id, using: grant).media
    let entries = original.isFolder ? try descendantEntries(of: original, using: grant) : [original]
    // 受保护的来源目录也不能随上级移动，来源访问密码不等于取消目录保护。
    guard
      !entries.contains(where: {
        $0.folderPassword != nil
      })
    else {
      throw VaultError.protectedFolderMove
    }
    var requirements = try folderRequirements(for: original, includingSelf: true, using: grant)
    let sourceProtection = Set(requirements.keys)
    var destinationProtection: [UUID: UUID] = [:]
    if let parentID {
      let parent = try rawReader(id: parentID, using: grant).media
      guard parent.isFolder, !parent.isFilePackage,
        !entries.contains(where: {
          $0.id == parentID
        })
      else {
        throw VaultError.invalidMove
      }
      destinationProtection = try folderRequirements(for: parent, includingSelf: true, using: grant)
    }
    // 普通目录树仍保留祖先保护范围；单个文件经过本次密码验证后可以移到范围外。
    guard
      original.isFilePackage || !original.isFolder
        || sourceProtection.isSubset(of: Set(destinationProtection.keys))
    else {
      throw VaultError.protectedFolderMove
    }
    requirements.merge(destinationProtection) { _, destination in
      destination
    }
    try grant.access(folders: requirements) { _ in
      ()
    }
    guard original.parentID != parentID,
      try !allEntries(using: grant).contains(where: {
        $0.id != id && $0.parentID == parentID
          && $0.originalFilename.localizedCaseInsensitiveCompare(original.originalFilename)
            == .orderedSame
      })
    else {
      throw VaultError.invalidMove
    }
    return (original, requirements)
  }

  /// 业务作用：为一批明确来源建立单次移动证明，将移出保护范围的验证与浏览隔离。
  /// 参数说明：
  /// - `ids`：本次明确选定且不重复的来源身份。
  /// - `grant`：仍有效的 App 会话。
  /// 返回：尚无目录权限的单次移动证明；空批次或重复来源时拒绝。
  func beginMove(ids: [UUID], using grant: VaultGrant) throws -> VaultMoveSession {
    try store.authorize(grant)
    guard !ids.isEmpty, Set(ids).count == ids.count else {
      throw VaultError.invalidMove
    }
    return try VaultMoveSession(mediaIDs: ids, owner: self, parent: grant)
  }

  /// 业务作用：认证移动目标的保护路径，供来源与目标比较密码保护范围。
  /// 参数说明：
  /// - `parentID`：本次接收目录身份；为空时表示保险箱根目录。
  /// - `grant`：当前仍有效的 App 会话。
  /// 返回：目标及其祖先的密码代次；非普通目录、隐藏路径失权或元数据异常时拒绝。
  private func moveDestinationProtection(to parentID: UUID?, using grant: VaultGrant) throws
    -> [UUID: UUID]
  {
    try store.authorize(grant)
    guard let parentID else {
      return [:]
    }
    let parent = try rawReader(id: parentID, using: grant).media
    // 文档包与照片内部目录不能成为整理目标，避免把文件写入不可见的内部资源树。
    guard parent.isFolder, !parent.isFilePackage else {
      throw VaultError.invalidMove
    }
    return try folderRequirements(for: parent, includingSelf: true, using: grant)
  }

  /// 业务作用：仅对本次移动将离开的保护层要求独立来源验证，共同保护层复验当前浏览权。
  /// 参数说明：
  /// - `session`：本次明确来源的单次移动证明。
  /// - `parentID`：本次接收目录；为空时移至保险箱根目录。
  /// - `grant`：创建该证明的同一 App 会话。
  /// 返回：外层优先的下一项待验证保护目录；范围内权限有效且离开的保护层均已验证时为空。
  func nextMoveFolder(
    _ session: VaultMoveSession, to parentID: UUID? = nil, using grant: VaultGrant
  ) throws -> VaultMedia? {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    try session.bindDestination(parentID, owner: self, parent: grant)
    let permission = try session.permission(owner: self, parent: grant)
    let destination = try moveDestinationProtection(to: parentID, using: grant)
    for id in session.mediaIDs {
      let source = try rawReader(id: id, using: grant).media
      let path = try folderChain(for: source, includingSelf: true, using: grant)
      _ = try rootRequirement(in: path, using: grant)
      for folder in path {
        guard let protection = folder.folderPassword else {
          continue
        }
        let requirement = [folder.id: protection.revision]
        if destination[folder.id] == protection.revision {
          // 共同祖先仍保护移动后的文件；只借用当前有效的浏览证明，不能凭目标位于范围内直接授权。
          try grant.access(folders: requirement) { _ in
            ()
          }
          try permission.allowFolder(folder.id, revision: protection.revision)
        } else {
          do {
            try permission.access(folders: requirement) { _ in
              ()
            }
          } catch VaultError.folderPasswordRequired {
            return folder
          }
        }
      }
    }
    return nil
  }

  /// 业务作用：仅为本次移动验证下一项来源目录密码，不改变普通浏览权限。
  /// 参数说明：
  /// - `id`：当前要求验证的目录身份。
  /// - `password`：本次重新输入的独立目录密码。
  /// - `session`：本次明确来源的单次移动证明。
  /// - `parentID`：本次接收目录；为空时移至保险箱根目录。
  /// - `grant`：创建该证明的同一 App 会话。
  /// 返回：正确时增加本次移动证明；错配、错误密码或失权时不开始移动。
  func authenticateMoveFolder(
    id: UUID, password: String, session: VaultMoveSession, to parentID: UUID? = nil,
    using grant: VaultGrant
  ) throws {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    // 来源密码必须逐层验证，不能跳过祖先或用无关目录的密码扩大移动权限。
    guard try nextMoveFolder(session, to: parentID, using: grant)?.id == id else {
      throw VaultError.invalidFolder
    }
    try authenticateFolder(
      id: id, password: password,
      using: session.permission(owner: self, parent: grant))
  }

  /// 业务作用：逐项移动同一目录内的多个条目，先检查整批约束，再以有界缓冲逐文件提交。
  /// 参数说明：
  /// - `ids`：当前批次明确选择且不重复的来源身份。
  /// - `parentID`：统一接收目录；为空时接收至保险箱根目录。
  /// - `authorization`：文件移出任一来源保护层时必须提供本次重新验证的单次证明。
  /// - `browsingFolderID`：需要继续浏览的来源父目录，只能保留移动前已经有效的路径证明。
  /// - `grant`：已验证来源与目标密码的当前会话。
  /// 返回：新会话、完成数量和中途失败说明；保留指定来源父目录的已有浏览权，临时移动与额外目标证明不继承。
  func move(
    ids: [UUID], to parentID: UUID?, authorization: VaultMoveSession? = nil,
    retainingAccessTo browsingFolderID: UUID? = nil, using grant: VaultGrant
  ) throws -> VaultBatchMoveResult {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    guard !ids.isEmpty, Set(ids).count == ids.count else {
      throw VaultError.invalidMove
    }
    defer {
      authorization?.revoke()
    }
    // 浏览证明必须在移动授权转入前复验，不能把本次移出验证或额外目标权限当作原有浏览权。
    let browsingProtection: [UUID: UUID]
    if let browsingFolderID {
      let folder = try rawReader(id: browsingFolderID, using: grant).media
      guard folder.isFolder, !folder.isFilePackage else {
        throw VaultError.invalidFolder
      }
      browsingProtection = try folderRequirements(for: folder, includingSelf: true, using: grant)
      try grant.access(folders: browsingProtection) { _ in
        ()
      }
    } else {
      browsingProtection = [:]
    }
    let permission: VaultGrant?
    if let authorization {
      guard authorization.mediaIDs == ids,
        try nextMoveFolder(authorization, to: parentID, using: grant) == nil
      else {
        throw VaultError.invalidMove
      }
      permission = try authorization.permission(owner: self, parent: grant, consume: true)
    } else {
      permission = nil
    }
    let destination = try moveDestinationProtection(to: parentID, using: grant)
    var sharedProtection = destination
    for id in ids {
      let source = try rawReader(id: id, using: grant).media
      let requirements = try folderRequirements(for: source, includingSelf: true, using: grant)
      sharedProtection = sharedProtection.filter { requirements[$0.key] == $0.value }
      let leaving = requirements.filter { destination[$0.key] != $0.value }
      if !source.isFolder || source.isFilePackage, let protectedID = leaving.keys.first {
        // 仅越过的保护层必须重新验证；仍留在共同保护范围内的文件继续受原目录密码约束。
        guard let permission else {
          throw VaultError.folderPasswordRequired(protectedID)
        }
        try permission.access(folders: leaving) { _ in
          ()
        }
        for (folderID, revision) in leaving {
          try grant.allowFolder(folderID, revision: revision)
        }
      }
      try grant.access(folders: requirements) { _ in
        ()
      }
    }
    let plans = try ids.map {
      try prepareMove(id: $0, to: parentID, using: grant)
    }
    let sourceParent = plans[0].media.parentID
    // 仅允许保留实际来源父目录，防止调用方借移动把无关目录的临时证明带入后续浏览。
    guard browsingFolderID == nil || browsingFolderID == sourceParent else {
      throw VaultError.invalidMove
    }
    var preservedProtection = sharedProtection
    preservedProtection.merge(browsingProtection) { original, _ in
      original
    }
    var names: [String] = []
    var authorization: [UUID: UUID] = [:]
    for plan in plans {
      // 整批必须来自同一层，避免同时选择祖先与子项，也避免批次自身制造同名冲突。
      guard plan.media.parentID == sourceParent,
        !names.contains(where: {
          $0.localizedCaseInsensitiveCompare(plan.media.originalFilename) == .orderedSame
        })
      else {
        throw VaultError.invalidMove
      }
      names.append(plan.media.originalFilename)
      authorization.merge(plan.requirements) { current, _ in
        current
      }
    }
    try grant.access(folders: authorization) { _ in
      ()
    }
    var current = grant
    var moved = 0
    defer {
      if moved > 0 {
        // 发布后只保留共同保护层和移动前已验证的来源浏览路径，临时移出与额外目标证明到此撤销。
        current.retainFolderAccess(Set(preservedProtection.keys))
      }
    }
    for id in ids {
      do {
        try Task.checkCancellation()
        try store.authorize(current)
        if moved > 0 {
          // 每个文件提交都会轮换会话；同批次仅转交已验证且被目录互斥保护的证明，不保存密码原文。
          for (folderID, revision) in authorization {
            try current.allowFolder(folderID, revision: revision)
          }
        }
        current = try moveEntry(id: id, to: parentID, using: current)
        moved += 1
        // 新会话仍撤销旧读取器，只转交已有浏览路径和共同保护层，使当前列表继续可用。
        for (folderID, revision) in preservedProtection {
          try current.allowFolder(folderID, revision: revision)
        }
      } catch {
        // 发布结果不明必须保持底层保护态，不能把未知结果计为普通部分完成。
        if case VaultError.organizationCommitUncertain = error {
          throw error
        }
        if moved == 0 || Task.isCancelled {
          throw error
        }
        do {
          try store.authorize(current)
        } catch {
          throw VaultError.organizationCommitUncertain
        }
        return VaultBatchMoveResult(
          grant: current,
          movedCount: moved,
          totalCount: ids.count,
          failure: error as? VaultError ?? .storage)
      }
    }
    return VaultBatchMoveResult(
      grant: current,
      movedCount: moved,
      totalCount: ids.count,
      failure: nil)
  }

  /// 业务作用：在保险箱内部移动条目，重新认证加密元数据及载荷，不产生外部明文。
  /// 参数说明：
  /// - `id`：明确选中的来源文件或未受密码保护的目录树。
  /// - `parentID`：接收目录；为空时移至保险箱根目录。
  /// - `grant`：具有来源及目标目录访问权的当前会话。
  /// - `authorization`：文件移出任一来源保护层时必须提供本次重新验证的单次证明。
  /// 返回：移动发布后撤销旧读取并交付新会话；范围内复验浏览权，缺少移出证明、受保护目录树、循环或重名时拒绝。
  func move(
    id: UUID, to parentID: UUID?, authorization: VaultMoveSession? = nil, using grant: VaultGrant
  ) throws -> VaultGrant {
    try move(ids: [id], to: parentID, authorization: authorization, using: grant).grant
  }

  /// 业务作用：整批预检通过后发布单个来源的新层级，逐块重加密并撤销旧读取能力。
  /// 参数说明：
  /// - `id`：本批次已完成来源密码验证的条目。
  /// - `parentID`：本批次明确选择的接收目录。
  /// - `grant`：持有本批次来源和目标证明的当前会话。
  /// 返回：完整发布后交付新会话；发布前失败保留原密文，结果不明时锁定保险箱。
  private func moveEntry(id: UUID, to parentID: UUID?, using grant: VaultGrant) throws -> VaultGrant
  {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    let plan = try prepareMove(id: id, to: parentID, using: grant)
    let original = plan.media
    let requirements = plan.requirements
    let input = try reader(id: id, using: grant)
    let media = VaultMedia(
      id: id, originalFilename: original.originalFilename, contentType: original.contentType,
      byteCount: original.byteCount, sha256: original.sha256, parentID: parentID,
      folderPassword: original.folderPassword, hidden: original.hidden,
      photoAsset: original.photoAsset)
    let identity = MediaIdentity(
      formatVersion: 1, id: id, vaultID: grant.vaultID, byteCount: media.byteCount,
      chunkSize: VaultMediaReader.chunkSize,
      chunkCount: Int(
        (media.byteCount + UInt64(VaultMediaReader.chunkSize) - 1)
          / UInt64(VaultMediaReader.chunkSize)),
      noncePrefix: try VaultCrypto.random(8))
    let key = try VaultCrypto.random(32)
    let context = try VaultCrypto.encode(identity)
    let header = try grant.access(folders: requirements) { root in
      MediaHeader(
        identity: identity,
        wrappedKey: try VaultCrypto.seal(key, key: SymmetricKey(data: root), context: context),
        metadata: try VaultCrypto.seal(
          VaultCrypto.encode(media),
          key: VaultCrypto.key(key, context: Data("metadata".utf8)), context: context))
    }
    let bytes = try VaultCrypto.encode(header)
    guard bytes.count <= 65_536 else {
      throw VaultError.storage
    }
    let temporary = store.mediaDirectory.appendingPathComponent(".\(UUID()).partial")
    defer {
      try? FileManager.default.removeItem(at: temporary)
    }
    let output = try VaultStorage.create(temporary)
    defer {
      try? output.close()
    }
    try output.write(contentsOf: VaultMediaReader.magic)
    var size = UInt32(bytes.count).bigEndian
    try withUnsafeBytes(of: &size) {
      try output.write(contentsOf: Data($0))
    }
    try output.write(contentsOf: bytes)
    let headerHash = Data(SHA256.hash(data: bytes))
    // 分块认证绑定完整头部，层级改变后使用新文件密钥和 nonce 重新封装，不能只改父目录字段。
    for index in 0..<identity.chunkCount {
      try autoreleasepool {
        try Task.checkCancellation()
        try grant.access(folders: requirements) { _ in
          ()
        }
        let part = try input.read(
          offset: UInt64(index) * UInt64(VaultMediaReader.chunkSize),
          count: VaultMediaReader.chunkSize)
        let sealed = try AES.GCM.seal(
          part, using: SymmetricKey(data: key),
          nonce: VaultMediaReader.nonce(prefix: identity.noncePrefix, index: index),
          authenticating: VaultMediaReader.chunkContext(
            headerHash, index: index, length: part.count))
        try output.write(contentsOf: sealed.ciphertext)
        try output.write(contentsOf: sealed.tag)
      }
    }
    try output.synchronize()
    try output.close()
    try VaultMediaReader(url: temporary, grant: grant).verify()
    try Task.checkCancellation()
    guard try rawReader(id: id, using: grant).media == original else {
      throw VaultError.documentChanged
    }
    // 先撤销旧层级的全部读取能力，再发布新层级，旧读取器不能绕过目标目录密码。
    let replacement = try store.rotateSession(using: grant, folders: requirements)
    do {
      try replacement.access { _ in
        try Task.checkCancellation()
        guard
          Darwin.rename(
            temporary.path, store.mediaDirectory.appendingPathComponent(id.uuidString + ".evm").path
          ) == 0
        else {
          throw VaultError.storage
        }
        try VaultStorage.synchronizeDirectory(store.mediaDirectory)
      }
      return replacement
    } catch {
      store.lock()
      throw VaultError.organizationCommitUncertain
    }
  }

  /// 业务作用：用户确认后复验来源与已保存密文，Mac 直接删除原件，不移入废纸篓。
  /// 参数说明：
  /// - `receipt`：当前会话中完整保存成功的来源收据。
  /// - `grant`：仍有效的前台会话。
  /// 返回：来源删除后成功；来源改变、失权或系统拒绝时保留密文并返回失败，不递归删除目录。
  func removeSource(_ receipt: SavedImport, using grant: VaultGrant) throws {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let scoped = receipt.source.startAccessingSecurityScopedResource()
    defer {
      if scoped {
        receipt.source.stopAccessingSecurityScopedResource()
      }
    }
    var initialPath = stat()
    guard Darwin.lstat(receipt.source.path, &initialPath) == 0,
      initialPath.st_mode & S_IFMT == S_IFREG,
      initialPath.st_dev == receipt.identity.device, initialPath.st_ino == receipt.identity.inode
    else {
      throw VaultError.sourceChanged
    }
    var coordinationError: NSError?
    var removalError: Error?
    NSFileCoordinator().coordinate(
      writingItemAt: receipt.source, options: .forDeleting, error: &coordinationError
    ) { url in
      do {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
          throw VaultError.sourceChanged
        }
        let current = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer {
          try? current.close()
        }
        // 在协调范围内重新读取完整来源，拒绝替换、修改、链接或特殊文件，不能只凭旧收据删源。
        guard try SourceIdentity(current) == receipt.identity,
          try hash(current, grant: grant) == receipt.media.sha256,
          try SourceIdentity(current) == receipt.identity
        else {
          throw VaultError.sourceChanged
        }
        try reader(id: receipt.media.id, using: grant).verify()
        // 协调后重新核对路径身份；最后一次复验与移除共用会话门禁，失权后不能补执行。
        try grant.access { _ in
          var finalPath = stat()
          // 密文复验可能持续一段时间，提交删除前再次核对路径与句柄，替换的来源必须保留。
          guard Darwin.lstat(url.path, &finalPath) == 0,
            finalPath.st_mode & S_IFMT == S_IFREG,
            finalPath.st_dev == receipt.identity.device, finalPath.st_ino == receipt.identity.inode,
            try SourceIdentity(current) == receipt.identity
          else {
            throw VaultError.sourceChanged
          }
          #if os(macOS)
            // 用户已明确确认直接删除；unlink 只移除当前文件条目，目录替换时失败，不递归删目录。
            guard Darwin.unlink(url.path) == 0 else {
              throw VaultError.sourceRemoval
            }
          #else
            try FileManager.default.removeItem(at: url)
          #endif
        }
      } catch {
        removalError = error
      }
    }
    if coordinationError != nil || removalError != nil {
      throw VaultError.sourceRemoval
    }
  }

  /// 业务作用：仅删除已取消目录密码保护的保险箱条目，不触及来源或已经导出的文件。
  /// 参数说明：
  /// - `id`：待删除的媒体身份。
  /// - `grant`：独立密码授权的当前会话。
  /// 返回：目标路径及目录树均无密码保护且删除、同步成功后完成；仍受保护时保留全部密文。
  func delete(id: UUID, using grant: VaultGrant) throws {
    let result = try delete(ids: [id], using: grant)
    if let failure = result.failure {
      throw failure
    }
  }

  /// 业务作用：先检查整批来源的保护规则，再按子项先于父项的顺序删除，不能静默跳过保护目录。
  /// 参数说明：
  /// - `ids`：用户在同一层明确勾选并确认删除的唯一条目身份。
  /// - `grant`：当前仍有效的独立密码会话。
  /// 返回：全部删除或部分完成的数量及失败原因；预检拒绝时不删除任何条目，来源文件不受影响。
  func delete(ids: [UUID], using grant: VaultGrant) throws
    -> (deletedCount: Int, totalCount: Int, failure: VaultError?)
  {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    guard !ids.isEmpty, Set(ids).count == ids.count else {
      throw VaultError.invalidSelection
    }
    let media = try ids.map {
      try rawReader(id: $0, using: grant).media
    }
    guard
      media.allSatisfy({
        $0.parentID == media[0].parentID
      })
    else {
      throw VaultError.invalidSelection
    }
    let groups = try media.map {
      $0.isFolder ? try descendantEntries(of: $0, using: grant) : [$0]
    }
    let entries = groups.flatMap {
      $0
    }
    // 访问验证不会解除删除保护；先检查整棵目录树，不能通过删除上级目录间接移除受保护子项。
    guard
      !entries.contains(where: {
        $0.folderPassword != nil
      })
    else {
      throw VaultError.protectedFolderDeletion
    }
    var folders: [UUID: UUID] = [:]
    for entry in entries {
      for (id, revision) in try folderRequirements(for: entry, includingSelf: true, using: grant) {
        folders[id] = revision
      }
    }
    // 祖先保护同样禁止删除单个子文件，访问密码和其它操作证明均不能解除删除保护。
    guard folders.isEmpty else {
      throw VaultError.protectedFolderDeletion
    }
    // 永久删除必须由当前会话明确授权，不能在锁定后由排队任务补执行。
    var deleted = 0
    for group in groups {
      do {
        try Task.checkCancellation()
        try grant.access(folders: folders) { _ in
          // 同一来源先移除子项再移除父目录身份，失败时保留仍可进入的父目录。
          for entry in group.reversed() {
            let url = store.mediaDirectory.appendingPathComponent(entry.id.uuidString + ".evm")
            try FileManager.default.removeItem(at: url)
          }
          try VaultStorage.synchronizeDirectory(store.mediaDirectory)
        }
        deleted += 1
      } catch {
        try grant.check()
        return (deleted, ids.count, error as? VaultError ?? .storage)
      }
    }
    return (deleted, ids.count, nil)
  }

  /// 业务作用：按原名完整导出并校验本地副本，持久发布成功后移除保险箱原件。
  /// 参数说明：
  /// - `id`：需要导出的媒体身份。
  /// - `directory`：用户明确授权的本地目标目录。
  /// - `grant`：当前独立密码会话。
  /// - `progress`：仅用于当前界面的导出进度。
  /// 返回：无密码保护、系统副本完整发布且密文移除后交付目标路径；写入失败保留密文，发布后清理不明时明确报告。
  func export(
    id: UUID, to directory: URL, using grant: VaultGrant,
    progress: @Sendable (Double) -> Void = { _ in }
  ) throws -> URL {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let media = try rawReader(id: id, using: grant).media
    let ancestors = try folderChain(for: media, includingSelf: true, using: grant)
    let entries = media.isFolder ? try descendantEntries(of: media, using: grant) : [media]
    // 访问授权不能代替取消保护，也不能借上级目录或单独导出子文件绕过目录限制。
    guard
      !(ancestors + entries).contains(where: {
        $0.folderPassword != nil
      })
    else {
      throw VaultError.protectedFolderExport
    }
    let destination = try materialize(id: id, to: directory, using: grant) { fraction in
      progress(fraction * 0.95)
    }
    do {
      // 只有全部外部字节复验并持久发布后才能删源；同一目录互斥内重新检查保护，复制和私有预览不经过此分支。
      try Task.checkCancellation()
      try delete(id: id, using: grant)
    } catch {
      // 副本已经发布，清理失败或失权不能回滚系统副本，也不能声称保险箱原件已全部移除。
      throw VaultError.exportRemovalUncertain
    }
    progress(1)
    return destination
  }

  /// 业务作用：整批检查保护与目标冲突后逐项导出，只有当前项目完整保存后才删除其原件。
  /// 参数说明：
  /// - `ids`：当前同层明确选择且不重复的条目身份。
  /// - `directory`：本批次统一的系统目标目录。
  /// - `grant`：当前有效的独立密码会话。
  /// 返回：整批预检拒绝时没有输出；处理中失败则报告已完成身份并停止，其余项目不继续执行。
  func export(ids: [UUID], to directory: URL, using grant: VaultGrant) throws
    -> VaultSystemSaveResult
  {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    let media = try systemSaveEntries(ids: ids, using: grant)
    // 任一来源仍受保护时整批拒绝，不能先导出普通项目再跳过保护项目。
    for item in media {
      let path = try folderChain(for: item, includingSelf: true, using: grant)
      let contents = item.isFolder ? try descendantEntries(of: item, using: grant) : [item]
      guard
        !(path + contents).contains(where: {
          $0.folderPassword != nil
        })
      else {
        throw VaultError.protectedFolderExport
      }
      // 隐藏子目录也必须在批次输出前核对 ROOT，不能在前项删源后才发现后项无权访问。
      _ = try rootRequirement(in: path + contents, using: grant)
    }
    try preflightSystemDestination(media, to: directory)
    var completed: [UUID] = []
    for id in ids {
      do {
        try Task.checkCancellation()
        _ = try export(id: id, to: directory, using: grant)
        completed.append(id)
      } catch {
        // 已完整导出的项目不能回滚；当前删源不明时也不声称所有未计数项目仍完整留在原处。
        return VaultSystemSaveResult(
          completedIDs: completed, totalCount: ids.count,
          failure: error as? VaultError ?? .storage)
      }
    }
    return VaultSystemSaveResult(completedIDs: completed, totalCount: ids.count, failure: nil)
  }

  /// 业务作用：限定批量系统保存为同层唯一条目，避免重复输出或祖先与子项被同时处理。
  /// 参数说明：
  /// - `ids`：本次明确选择的条目身份。
  /// - `grant`：当前有效的 App 会话。
  /// 返回：认证元数据快照；重复、跨层、失权或隐藏路径不可访问时拒绝。
  private func systemSaveEntries(ids: [UUID], using grant: VaultGrant) throws -> [VaultMedia] {
    try store.authorize(grant)
    guard !ids.isEmpty, Set(ids).count == ids.count else {
      throw VaultError.invalidSelection
    }
    let media = try ids.map {
      try rawReader(id: $0, using: grant).media
    }
    // 同层选择不能包含自身祖先，保护检查和输出清单始终针对这一份明确选择。
    guard
      media.allSatisfy({
        $0.parentID == media[0].parentID
      })
    else {
      throw VaultError.invalidSelection
    }
    for item in media {
      _ = try folderRequirements(for: item, includingSelf: true, using: grant)
    }
    return media
  }

  /// 业务作用：在任何批量明文输出前检查目标目录和整批最终名称，拒绝覆盖或自动改名。
  /// 参数说明：
  /// - `media`：本批次已经认证的同层条目。
  /// - `directory`：用户明确选择的系统目标目录。
  /// 返回：本地普通目录且所有名称均可用时成功；冲突或无效位置时不生成文件。
  private func preflightSystemDestination(_ media: [VaultMedia], to directory: URL) throws {
    let scoped = directory.startAccessingSecurityScopedResource()
    defer {
      if scoped {
        directory.stopAccessingSecurityScopedResource()
      }
    }
    let properties = try directory.resourceValues(forKeys: [
      .isDirectoryKey, .isSymbolicLinkKey, .isUbiquitousItemKey, .volumeIsLocalKey,
    ])
    guard properties.isDirectory == true, properties.isSymbolicLink != true,
      properties.isUbiquitousItem != true, properties.volumeIsLocal != false
    else {
      throw VaultError.storage
    }
    var names: [String] = []
    for item in media {
      let name =
        item.photoAsset == nil
        ? item.originalFilename
        : (item.originalFilename as NSString).deletingPathExtension + "（完整资源）"
      guard name != ".", name != "..", !name.contains("/"), !name.contains("\0") else {
        throw VaultError.corrupt
      }
      // 名称同时对整批及现有目录检查，防止前几个项目完成后才发现可预知的后续冲突。
      guard
        !names.contains(where: {
          $0.localizedCaseInsensitiveCompare(name) == .orderedSame
        }),
        !FileManager.default.fileExists(atPath: directory.appendingPathComponent(name).path)
      else {
        throw VaultError.destinationExists
      }
      names.append(name)
    }
  }

  /// 业务作用：为系统相册导出准备经过校验的单一媒体暂存，系统提交前不删除保险箱原件。
  /// 参数说明：
  /// - `id`：明确选择的媒体或完整照片身份。
  /// - `directory`：本次相册写入独占的私有暂存目录。
  /// - `grant`：当前会话；原有禁止导出受保护内容的规则继续成立。
  /// 返回：单一图片或视频已经完整复验；复合资源或受保护路径拒绝，全部原件保持不变。
  func exportPresentation(id: UUID, to directory: URL, using grant: VaultGrant) throws -> URL {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    let media = try reader(id: id, using: grant).media
    // 单张主图不能代表 Live Photo、RAW 或编辑资产的全部资源，删源导出必须改用完整本地资源包。
    guard !media.isFolder, media.photoAsset == nil, media.isImage || media.isVideo else {
      throw VaultError.compositePhoto
    }
    let ancestors = try folderChain(for: media, includingSelf: true, using: grant)
    let entries = media.isFolder ? try descendantEntries(of: media, using: grant) : [media]
    guard !(ancestors + entries).contains(where: { $0.folderPassword != nil }) else {
      throw VaultError.protectedFolderExport
    }
    let primary = try presentationReader(id: id, using: grant).media
    return try materialize(id: primary.id, to: directory, using: grant, progress: { _ in })
  }

  /// 业务作用：系统相册完整提交并复验后，只移除与本次导出快照一致的单一媒体原件。
  /// 参数说明：
  /// - `expected`：提交系统相册前取得的已认证图片或视频元数据。
  /// - `grant`：导出开始时的同一有效会话。
  /// 返回：身份、内容和保护均未变化时删除密文；改动、失权或仍有保护时拒绝删除。
  func removeExportedPhoto(_ expected: VaultMedia, using grant: VaultGrant) throws {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    // 系统提交包含异步等待，不能依据旧界面选择删除后来被替换、移动或增加配套资源的条目。
    guard !expected.isFolder, expected.photoAsset == nil,
      expected.isImage || expected.isVideo,
      try rawReader(id: expected.id, using: grant).media == expected
    else {
      throw VaultError.documentChanged
    }
    try Task.checkCancellation()
    try delete(id: expected.id, using: grant)
  }

  /// 业务作用：为一次明确的系统复制建立独立事务，不沿用普通浏览时已经输入的目录密码。
  /// 参数说明：
  /// - `id`：本次唯一允许复制的文件或目录身份。
  /// - `grant`：当前 App 会话。
  /// 返回：尚无目录权限的临时复制事务，不生成明文或改变保护状态。
  func beginCopy(id: UUID, using grant: VaultGrant) throws -> VaultCopySession {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    _ = try rawReader(id: id, using: grant).media
    return try VaultCopySession(mediaID: id, owner: self, parent: grant)
  }

  /// 业务作用：为同层选择建立彼此独立、同属本次批量操作的复制能力。
  /// 参数说明：
  /// - `ids`：当前明确选择且不重复的来源身份。
  /// - `grant`：当前有效的 App 会话。
  /// 返回：每项尚未消费的复制事务；没有输出或继承浏览密码证明。
  func beginCopies(ids: [UUID], using grant: VaultGrant) throws -> [VaultCopySession] {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    _ = try systemSaveEntries(ids: ids, using: grant)
    return try ids.map {
      try beginCopy(id: $0, using: grant)
    }
  }

  /// 业务作用：按批次顺序查找尚缺的目录证明，共同目录已经验证后不重复提示。
  /// 参数说明：
  /// - `sessions`：本批次每个来源独占的复制事务。
  /// - `grant`：创建全部事务的同一 App 会话。
  /// 返回：下一项待验证目录；全部完成时为空，失效事务立即拒绝。
  func nextCopyFolder(_ sessions: [VaultCopySession], using grant: VaultGrant) throws -> VaultMedia?
  {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    _ = try systemSaveEntries(ids: sessions.map(\.mediaID), using: grant)
    for session in sessions {
      if let folder = try nextCopyFolder(session, using: grant) {
        return folder
      }
    }
    return nil
  }

  /// 业务作用：为本批次验证一次共同目录密码，只向确实需要此目录的复制事务转交证明。
  /// 参数说明：
  /// - `id`：批次当前要求验证的保护目录。
  /// - `password`：本次原始目录密码，仅在调用期间使用。
  /// - `sessions`：同一批次来源的复制事务。
  /// - `grant`：创建事务的同一有效 App 会话。
  /// 返回：正确时授权当前共同保护层；错误、跳层、错配或取消时不输出明文。
  func authenticateCopyFolder(
    id: UUID, password: String, sessions: [VaultCopySession], using grant: VaultGrant
  ) throws {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    guard try nextCopyFolder(sessions, using: grant)?.id == id,
      let first = try sessions.first(where: {
        try nextCopyFolder($0, using: grant)?.id == id
      })
    else {
      throw VaultError.invalidFolder
    }
    try authenticateCopyFolder(id: id, password: password, session: first, using: grant)
    let folder = try rawReader(id: id, using: grant).media
    guard let protection = folder.folderPassword else {
      throw VaultError.invalidFolder
    }
    for session in sessions where session !== first {
      if try nextCopyFolder(session, using: grant)?.id == id {
        let permission = try session.permission(owner: self, parent: grant)
        let parents = try folderRequirements(for: folder, includingSelf: false, using: permission)
        // 仅向本批次当前确实缺少该层、且祖先已验证的临时能力转交证明，不授予浏览或导出权限。
        try permission.allowFolder(id, revision: protection.revision, requiring: parents)
      }
    }
  }

  /// 业务作用：所有复制证明齐备后，整批检查本地输出名称，之后各项仍须独立消费自己的能力。
  /// 参数说明：
  /// - `sessions`：当前批次尚未消费的复制事务。
  /// - `directory`：统一系统目标目录。
  /// - `grant`：创建事务的当前会话。
  /// 返回：授权和目标均完整时成功；任一缺失或冲突时没有明文输出。
  func preflightCopies(_ sessions: [VaultCopySession], to directory: URL, using grant: VaultGrant)
    throws
  {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    if let folder = try nextCopyFolder(sessions, using: grant) {
      throw VaultError.folderPasswordRequired(folder.id)
    }
    try preflightSystemDestination(
      systemSaveEntries(ids: sessions.map(\.mediaID), using: grant), to: directory)
  }

  /// 业务作用：在本次复制中按外层优先找出需要重新验证的目录，包含所有受保护子目录。
  /// 参数说明：
  /// - `session`：尚未消费的本次复制事务。
  /// - `grant`：创建该事务的同一 App 会话。
  /// 返回：下一项需要输入保护密码的目录；全部验证后为空，不产生外部副本。
  func nextCopyFolder(_ session: VaultCopySession, using grant: VaultGrant) throws -> VaultMedia? {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let permission = try session.permission(owner: self, parent: grant)
    return try nextLockedFolder(id: session.mediaID, recursive: true, using: permission)
  }

  /// 业务作用：只为当前复制事务验证下一项目录密码，不开放浏览、移动或导出权限。
  /// 参数说明：
  /// - `id`：当前预检要求验证的目录身份。
  /// - `password`：本次重新输入的目录独立密码。
  /// - `session`：待完成的单次复制事务。
  /// - `grant`：创建该事务的同一 App 会话。
  /// 返回：密码正确时只增加本次复制证明；错配、错误密码、取消或失权时不开放输出。
  func authenticateCopyFolder(
    id: UUID, password: String, session: VaultCopySession, using grant: VaultGrant
  ) throws {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    // 只接受当前目录树要求的下一项，不能跳过外层密码或验证无关目录来扩大复制范围。
    guard try nextCopyFolder(session, using: grant)?.id == id else {
      throw VaultError.invalidFolder
    }
    let permission = try session.permission(owner: self, parent: grant)
    try authenticateFolder(id: id, password: password, using: permission)
  }

  /// 业务作用：消费本次重新验证的复制权限，逐块生成明文副本并保留全部加密原件与密码保护。
  /// 参数说明：
  /// - `session`：绑定选中条目且尚未消费的单次复制事务。
  /// - `directory`：用户明确选择的系统目标目录。
  /// - `grant`：创建该事务的同一 App 会话。
  /// - `presentationOnly`：写入系统照片时只交付主媒体，完整资源仍保留在保险箱中。
  /// - `progress`：本次内存中的完成比例，不保存来源或查看历史。
  /// 返回：全部相关目录密码已重新验证且内容完整时发布副本；失败清理暂存，事务不能重放。
  func copyToSystem(
    _ session: VaultCopySession, to directory: URL, using grant: VaultGrant,
    presentationOnly: Bool = false,
    progress: @Sendable (Double) -> Void = { _ in }
  ) throws -> URL {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let permission = try session.permission(owner: self, parent: grant, consume: true)
    defer {
      session.revoke()
    }
    // 不能在验证一半时创建明文目录，也不能把已有浏览授权当成本次复制的证明。
    if let missing = try nextLockedFolder(id: session.mediaID, recursive: true, using: permission) {
      throw VaultError.folderPasswordRequired(missing.id)
    }
    let id =
      presentationOnly
      ? try presentationReader(id: session.mediaID, using: permission).media.id
      : session.mediaID
    return try materialize(id: id, to: directory, using: permission, progress: progress)
  }

  /// 业务作用：只向保险箱自有随机预览目录交付文档副本，不开放受保护内容的系统导出。
  /// 参数说明：
  /// - `id`：明确选中的文档身份。
  /// - `directory`：当前保险箱 documents.noindex 下已创建的 UUID 目录。
  /// - `grant`：仍具备所属目录访问权的当前会话。
  /// 返回：完整认证的私有查看副本；非文档、外部位置或失权时拒绝。
  func prepareDocumentCopy(id: UUID, in directory: URL, using grant: VaultGrant) throws -> URL {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let root = store.directory.appendingPathComponent("documents.noindex", isDirectory: true)
    let normalized = directory.standardizedFileURL
    guard normalized.deletingLastPathComponent() == root.standardizedFileURL,
      UUID(uuidString: normalized.lastPathComponent) != nil,
      normalized.resolvingSymlinksInPath() == normalized,
      try reader(id: id, using: grant).media.isDocument
    else {
      throw VaultError.storage
    }
    return try materialize(id: id, to: normalized, using: grant, progress: { _ in })
  }

  /// 业务作用：在调用方完成导出策略、单次复制验证或私有预览位置校验后，认证并重建原名内容。
  /// 参数说明：
  /// - `id`：当前事务中的条目身份。
  /// - `directory`：已经限定用途的本地目录。
  /// - `grant`：每次明文写入都必须复验的访问能力。
  /// - `progress`：只在本次内存中交付的完成比例。
  /// 返回：完整复验后排他发布的路径；失败清理本次暂存。
  private func materialize(
    id: UUID, to directory: URL, using grant: VaultGrant,
    progress: @Sendable (Double) -> Void
  ) throws -> URL {
    let scoped = directory.startAccessingSecurityScopedResource()
    defer {
      if scoped {
        directory.stopAccessingSecurityScopedResource()
      }
    }
    let properties = try directory.resourceValues(forKeys: [
      .isDirectoryKey, .isSymbolicLinkKey, .isUbiquitousItemKey, .volumeIsLocalKey,
    ])
    guard properties.isDirectory == true, properties.isSymbolicLink != true,
      properties.isUbiquitousItem != true, properties.volumeIsLocal != false
    else {
      throw VaultError.storage
    }
    let input = try reader(id: id, using: grant)
    if input.media.isFolder {
      return try exportFolder(input.media, to: directory, using: grant, progress: progress)
    }
    let name = input.media.originalFilename
    guard name != ".", name != "..", !name.contains("/"), !name.contains("\0") else {
      throw VaultError.corrupt
    }
    let destination = directory.appendingPathComponent(name)
    guard !FileManager.default.fileExists(atPath: destination.path) else {
      throw VaultError.destinationExists
    }
    let temporary = directory.appendingPathComponent(".EncVault-\(UUID()).partial")
    defer {
      try? FileManager.default.removeItem(at: temporary)
    }
    let output = try VaultStorage.create(temporary)
    defer {
      try? output.close()
    }
    var offset: UInt64 = 0
    var digest = SHA256()
    while offset < input.media.byteCount {
      try autoreleasepool {
        if Task.isCancelled {
          throw VaultError.cancelled
        }
        let part = try input.read(
          offset: offset,
          count: Int(min(UInt64(VaultMediaReader.chunkSize), input.media.byteCount - offset)))
        // 明文写入也必须受撤销门禁保护，取消后不继续向保险箱外输出。
        try grant.access(folders: input.folderRequirements) { _ in
          try output.write(contentsOf: part)
        }
        digest.update(data: part)
        offset += UInt64(part.count)
        progress(Double(offset) / Double(input.media.byteCount) * 0.8)
      }
    }
    guard Data(digest.finalize()) == input.media.sha256 else {
      throw VaultError.corrupt
    }
    try output.synchronize()
    try output.close()
    let verification = try FileHandle(forReadingFrom: temporary)
    defer {
      try? verification.close()
    }
    guard try hash(verification, grant: grant) == input.media.sha256 else {
      throw VaultError.corrupt
    }
    // 排他重命名避免检查后出现同名文件而覆盖；只在完整校验后发布用户明确请求的明文。
    try grant.access(folders: input.folderRequirements) { _ in
      guard Darwin.renamex_np(temporary.path, destination.path, UInt32(RENAME_EXCL)) == 0 else {
        if errno == EEXIST {
          throw VaultError.destinationExists
        }
        throw VaultError.storage
      }
      try VaultStorage.synchronizeDirectory(directory)
    }
    progress(1)
    return destination
  }

  /// 业务作用：只沿认证父目录关系收集指定目录树，拒绝循环关系，避免越界遍历。
  /// 参数说明：
  /// - `folder`：本次操作的已认证根目录。
  /// - `grant`：当前独立密码会话。
  /// 返回：父项在子项之前的完整子树，包含根目录；关系异常时不执行导出或删除。
  private func descendants(of folder: VaultMedia, using grant: VaultGrant) throws -> [VaultMedia] {
    let entries = try descendantEntries(of: folder, using: grant)
    for entry in entries {
      let requirements = try folderRequirements(for: entry, includingSelf: true, using: grant)
      try grant.access(folders: requirements) { _ in
        ()
      }
    }
    return entries
  }

  /// 业务作用：在认证目录内收集完整子树，供检查所有目录密码后再开始有副作用的操作。
  /// 参数说明：
  /// - `folder`：本次操作的根目录。
  /// - `grant`：当前 App 会话。
  /// 返回：父项在前的完整目录树，循环或非法关系时失败。
  private func descendantEntries(of folder: VaultMedia, using grant: VaultGrant) throws
    -> [VaultMedia]
  {
    let children = Dictionary(grouping: try allEntries(using: grant), by: \.parentID)
    var entries = [folder]
    var visited: Set<UUID> = [folder.id]
    var index = 0
    while index < entries.count {
      try grant.check()
      let parent = entries[index]
      let nested = children[parent.id] ?? []
      guard parent.isFolder || nested.isEmpty else {
        throw VaultError.corrupt
      }
      for child in nested {
        guard visited.insert(child.id).inserted else {
          throw VaultError.corrupt
        }
        entries.append(child)
      }
      index += 1
    }
    return entries
  }

  /// 业务作用：在私有暂存目录重建原目录树，全部文件完整复验后一次发布根目录。
  /// 参数说明：
  /// - `folder`：本次明确导出的目录或文件包。
  /// - `directory`：用户授权的本地目标位置。
  /// - `grant`：当前独立密码会话。
  /// - `progress`：当前目录树的内存进度。
  /// 返回：保留原名、层级及空目录的明文目录；失败清理本次暂存且不覆盖已有文件。
  private func exportFolder(
    _ folder: VaultMedia, to directory: URL, using grant: VaultGrant,
    progress: @Sendable (Double) -> Void
  ) throws -> URL {
    let entries = try descendants(of: folder, using: grant)
    var folders: [UUID: UUID] = [:]
    for entry in entries {
      for (id, revision) in try folderRequirements(for: entry, includingSelf: true, using: grant) {
        folders[id] = revision
      }
    }
    let name =
      folder.photoAsset == nil
      ? folder.originalFilename
      : (folder.originalFilename as NSString).deletingPathExtension + "（完整资源）"
    guard name != ".", name != "..", !name.contains("/"), !name.contains("\0") else {
      throw VaultError.corrupt
    }
    let destination = directory.appendingPathComponent(name, isDirectory: true)
    guard !FileManager.default.fileExists(atPath: destination.path) else {
      throw VaultError.destinationExists
    }
    let stage = directory.appendingPathComponent(".EncVault-\(UUID()).partial", isDirectory: true)
    try VaultStorage.directory(stage)
    defer {
      try? FileManager.default.removeItem(at: stage)
    }
    var parents = [folder.id: stage]
    for (index, entry) in entries.enumerated() {
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      try grant.check()
      if entry.id == folder.id {
        try reader(id: entry.id, using: grant).verify()
      } else {
        guard let parentID = entry.parentID, let parent = parents[parentID] else {
          throw VaultError.corrupt
        }
        if entry.isFolder {
          let childName =
            entry.photoAsset == nil
            ? entry.originalFilename
            : (entry.originalFilename as NSString).deletingPathExtension + "（完整资源）"
          guard childName != ".", childName != "..", !childName.contains("/"),
            !childName.contains("\0")
          else {
            throw VaultError.corrupt
          }
          try reader(id: entry.id, using: grant).verify()
          let child = parent.appendingPathComponent(childName, isDirectory: true)
          guard !FileManager.default.fileExists(atPath: child.path) else {
            throw VaultError.destinationExists
          }
          try grant.access { _ in
            try VaultStorage.directory(child)
          }
          parents[entry.id] = child
        } else {
          _ = try materialize(id: entry.id, to: parent, using: grant, progress: { _ in })
        }
      }
      progress(Double(index + 1) / Double(entries.count) * 0.95)
    }
    // 整个目录树验证完成后才对外发布，排他重命名同时保护文件包和已有同名目录。
    try grant.access(folders: folders) { _ in
      guard Darwin.renamex_np(stage.path, destination.path, UInt32(RENAME_EXCL)) == 0 else {
        if errno == EEXIST {
          throw VaultError.destinationExists
        }
        throw VaultError.storage
      }
      try VaultStorage.synchronizeDirectory(directory)
    }
    progress(1)
    return destination
  }

  /// 业务作用：有界计算来源摘要，为稳定内容和删源证据提供完整字节比较。
  /// 参数说明：
  /// - `file`：本次来源句柄。
  /// - `grant`：每一轮都要复验的会话能力。
  /// - `progress`：已经校验的来源字节数，不包含来源内容。
  /// 返回：完整 SHA-256；取消或失权时拒绝。
  private func hash(
    _ file: FileHandle, grant: VaultGrant, progress: @Sendable (UInt64) -> Void = { _ in }
  ) throws -> Data {
    try file.seek(toOffset: 0)
    var digest = SHA256()
    var bytes: UInt64 = 0
    while true {
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      try grant.check()
      let finished = try autoreleasepool {
        let part = try file.read(upToCount: VaultMediaReader.chunkSize) ?? Data()
        if part.isEmpty {
          return true
        }
        digest.update(data: part)
        bytes += UInt64(part.count)
        return false
      }
      if finished {
        break
      }
      progress(bytes)
    }
    return Data(digest.finalize())
  }

  /// 业务作用：从同一来源句柄的有界文件头识别媒体，不以改写扩展名来适配播放器。
  /// 参数说明：
  /// - `file`：已打开的来源句柄。
  /// 返回：可识别媒体的真实 UTI；其它内容作为普通数据完整加密保存。
  private func type(file: FileHandle) throws -> String {
    try file.seek(toOffset: 0)
    let prefix = try file.read(upToCount: 4096) ?? Data()
    // 类型识别与加密共用来源句柄，路径被替换时不会采用另一文件的类型或再次打开其路径。
    // ImageIO 也可能识别 PDF；只有图片类型进入媒体相册，其它文档按普通数据保存。
    if let image = CGImageSourceCreateWithData(prefix as CFData, nil),
      let identifier = CGImageSourceGetType(image) as String?,
      UTType(identifier)?.conforms(to: .image) == true
    {
      return identifier
    }
    if prefix.starts(with: [0xFF, 0xD8, 0xFF]) {
      return UTType.jpeg.identifier
    }
    if prefix.starts(with: [137, 80, 78, 71, 13, 10, 26, 10]) {
      return UTType.png.identifier
    }
    if prefix.count >= 12, String(data: prefix[4..<8], encoding: .ascii) == "ftyp" {
      let brand = String(data: prefix[8..<12], encoding: .ascii) ?? ""
      if brand == "qt  " {
        return UTType.quickTimeMovie.identifier
      }
      if ["heic", "heix", "hevc", "hevx"].contains(brand) {
        return UTType.heic.identifier
      }
      if ["mif1", "msf1"].contains(brand) {
        return UTType.heif.identifier
      }
      if [
        "isom", "iso2", "iso3", "iso4", "iso5", "iso6", "iso7", "iso8", "iso9", "mp41", "mp42",
        "avc1", "M4V ", "MSNV",
      ].contains(brand) {
        return UTType.mpeg4Movie.identifier
      }
    }
    if prefix.starts(with: [0x1A, 0x45, 0xDF, 0xA3])
      || prefix.starts(with: [0x46, 0x4C, 0x56])
      || prefix.starts(with: [0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11])
      || prefix.starts(with: [0, 0, 1, 0xBA])
      || prefix.starts(with: [0, 0, 1, 0xB3])
      || prefix.count > 12 && String(data: prefix[0..<4], encoding: .ascii) == "RIFF"
        && String(data: prefix[8..<12], encoding: .ascii) == "AVI "
      || prefix.count > 376 && prefix[0] == 0x47 && prefix[188] == 0x47 && prefix[376] == 0x47
    {
      return UTType.movie.identifier
    }
    return UTType.data.identifier
  }
}
