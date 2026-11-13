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

private struct MediaHeader: Codable, Sendable {
  let identity: MediaIdentity
  let wrappedKey: Data
  let metadata: Data
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

  /// 业务作用：有界解析密文头并认证原始文件名，只有当前保险箱会话可以取得媒体信息。
  /// 参数说明：
  /// - `url`：保险箱中的密文文件。
  /// - `grant`：当前独立密码授权的会话。
  /// - `folderRequirements`：本次读取需持续有效的目录密码授权。
  /// 返回：已经认证元数据的读取器；身份、长度、格式或密钥错误时失败。
  init(url: URL, grant: VaultGrant, folderRequirements: [UUID: UUID] = [:]) throws {
    self.grant = grant
    self.folderRequirements = folderRequirements
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
    let decoded: VaultMedia = try grant.access(folders: folderRequirements) { root in
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
      guard decoded.isFolder, !decoded.isDocument, protection.salt.count == 16,
        protection.iterations >= VaultCrypto.rounds, protection.iterations <= 3_000_000,
        protection.verification.count == 44
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
      try grant.access(folders: folderRequirements) { root in
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
    try grant.access(folders: folderRequirements) { _ in
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

/// 批量移动只返回会话与完成情况，不持有文件内容或密码原文。
struct VaultBatchMoveResult: Sendable {
  let grant: VaultGrant
  let movedCount: Int
  let totalCount: Int
  let failure: VaultError?
}

/// 加密媒体目录，不创建播放历史、明文索引或明文缩略图。
final class VaultLibrary: @unchecked Sendable {
  private let store: VaultStore
  private let mutation = NSRecursiveLock()

  /// 业务作用：把媒体事务限定到指定保险箱的私有目录。
  /// 参数说明：
  /// - `store`：持有目录独占权的保险箱。
  /// 返回：不自动读取或导入媒体的目录入口。
  init(store: VaultStore) {
    self.store = store
  }

  /// 业务作用：只枚举当前 App 和目录授权允许看到的原名，不展示未验证目录的内部文件。
  /// 参数说明：
  /// - `grant`：当前前台会话能力。
  /// 返回：按原名和随机身份稳定排序的媒体；任一密文头损坏时明确失败，不静默吞掉数据。
  func list(using grant: VaultGrant) throws -> [VaultMedia] {
    let entries = try allEntries(using: grant)
    let index = Dictionary(uniqueKeysWithValues: entries.map { ($0.id, $0) })
    return try entries.filter { media in
      let requirements = try folderRequirements(
        for: media, includingSelf: false, entries: index, using: grant)
      do {
        try grant.access(folders: requirements) { _ in
          ()
        }
        return true
      } catch VaultError.folderPasswordRequired {
        return false
      }
    }
  }

  /// 业务作用：认证目录关系供访问门禁与完整子树操作使用，不直接向界面发布全部原名。
  /// 参数说明：
  /// - `grant`：当前 App 会话。
  /// 返回：完整认证并稳定排序的内部目录，任何损坏均明确拒绝。
  private func allEntries(using grant: VaultGrant) throws -> [VaultMedia] {
    try store.authorize(grant)
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
    try grant.check()
    return items.sorted {
      if $0.originalFilename == $1.originalFilename {
        return $0.id.uuidString < $1.id.uuidString
      }
      return $0.originalFilename < $1.originalFilename
    }
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
    return try VaultMediaReader(
      url: store.mediaDirectory.appendingPathComponent(id.uuidString + ".evm"), grant: grant,
      folderRequirements: requirements)
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
  /// 返回：受保护目录身份与密码代次，不包含密码或访问历史。
  private func folderRequirements(
    for media: VaultMedia, includingSelf: Bool, entries: [UUID: VaultMedia]? = nil,
    using grant: VaultGrant
  ) throws -> [UUID: UUID] {
    let path = try folderChain(
      for: media, includingSelf: includingSelf, entries: entries, using: grant)
    return Dictionary(
      uniqueKeysWithValues: path.compactMap { folder in
        folder.folderPassword.map { (folder.id, $0.revision) }
      })
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
      for folder in try folderChain(for: candidate, includingSelf: true, using: grant) {
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
    guard folder.isFolder, !folder.isDocument, let protection = folder.folderPassword else {
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
  /// - `id`：需要设置或取消保护的普通目录。
  /// - `password`：设置时的新密码；取消时为空。
  /// - `previous`：取消保护必须重新验证的原目录密码。
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
    guard original.isFolder, !original.isDocument else {
      throw VaultError.invalidFolder
    }
    let parents = try folderRequirements(for: original, includingSelf: false, using: grant)
    try grant.access(folders: parents) { _ in
      ()
    }
    let protection: FolderPassword?
    if let password {
      guard original.folderPassword == nil else {
        throw VaultError.folderProtectionExists
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
      byteCount: 0, sha256: original.sha256, parentID: original.parentID, folderPassword: protection
    )
    return try publishMetadata(
      media, replacing: original, requirements: parents, using: grant,
      uncertain: .folderCommitUncertain)
  }

  /// 业务作用：有界重新封装名称或保护元数据并原子发布，保持原始内容与目录子项不变。
  /// 参数说明：
  /// - `media`：本次需要持久化的完整元数据，内容长度和摘要不得改变。
  /// - `original`：发布前必须仍有效的文件或目录快照。
  /// - `requirements`：提交期间必须保持有效的目录授权。
  /// - `grant`：当前 App 会话。
  /// - `uncertain`：撤销旧会话后无法确认提交时向界面交付的保护态原因。
  /// 返回：完整校验并发布后返回新会话；发布前失败保留原件，发布结果不明时锁定。
  private func publishMetadata(
    _ media: VaultMedia, replacing original: VaultMedia, requirements: [UUID: UUID],
    using grant: VaultGrant, uncertain: VaultError
  ) throws -> VaultGrant {
    let id = original.id
    guard media.id == id, media.byteCount == original.byteCount,
      media.sha256 == original.sha256
    else {
      throw VaultError.corrupt
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
    // 新密文完整校验后先撤销旧能力，再发布元数据，旧读者不能继续交付过期策略或名称。
    let replacement = try store.rotateSession(using: grant, folders: requirements)
    do {
      try replacement.access { _ in
        try Task.checkCancellation()
        guard Darwin.rename(temporary.path, destination.path) == 0 else {
          throw VaultError.storage
        }
        try VaultStorage.synchronizeDirectory(store.mediaDirectory)
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
  /// - `grant`：当前独立密码授权的会话。
  /// - `status`：当前文件的阶段、字节进度和已完成计数，仅在本次内存中交付。
  /// - `progress`：仅在当前界面使用的进度，不落盘。
  /// 返回：保存完整的媒体与来源身份；失败或失权时保留来源，不发布部分文件。
  func save(
    source: URL, originalName: String? = nil, using grant: VaultGrant,
    status: @escaping @Sendable (ImportProgress) -> Void = { _ in },
    progress: @escaping @Sendable (Double) -> Void = { _ in }
  ) throws -> SavedImport {
    try autoreleasepool {
      try saveEntry(
        source: source, name: originalName ?? source.lastPathComponent, parentID: nil,
        directoryEntry: false,
        using: grant, status: status, progress: progress)
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
      parentID: original.parentID)
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
    let directoryRequirements =
      try parentID.map { parentID in
        try folderRequirements(
          for: rawReader(id: parentID, using: grant).media, includingSelf: true, using: grant)
      } ?? [:]
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
  /// - `grant`：当前独立密码会话。
  /// - `status`：当前条目的阶段、字节进度及累计完成数量，不建立持久化来源清单。
  /// - `progress`：当前文件内的进度，目录未知总量时不表示整个目录的百分比。
  /// 返回：已建立的根目录、完整文件收据与失败数量；失败或中断保留来源，已完成条目仍可解锁读取。
  func saveFolder(
    source: URL, using grant: VaultGrant,
    status: @escaping @Sendable (ImportProgress) -> Void = { _ in },
    progress: @escaping @Sendable (Double) -> Void = { _ in }
  ) throws -> (folder: VaultMedia, saved: [SavedImport], failures: Int) {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
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
      try saveDirectory(name: root.lastPathComponent, parentID: nil, using: grant)
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
      guard parent.isFolder, !parent.isDocument else {
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
  /// - `grant`：已验证该目录及其祖先的当前 App 会话。
  /// 返回：名称发布后返回清空目录权限的新会话；非法名称、重名或未验证保护时保持原目录。
  func renameFolder(id: UUID, to name: String, using grant: VaultGrant) throws -> VaultGrant {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let original = try rawReader(id: id, using: grant).media
    guard original.isFolder, !original.isDocument else {
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
      folderPassword: original.folderPassword)
    return try publishMetadata(
      media, replacing: original, requirements: requirements, using: grant,
      uncertain: .organizationCommitUncertain)
  }

  /// 业务作用：更改普通文件或文档包的加密名称，保留内容、身份、格式与所在目录。
  /// 参数说明：
  /// - `id`：当前保险箱内明确选择的文件或文档包。
  /// - `name`：保留原扩展名的新单层名称，不得与同级项目重名。
  /// - `grant`：已验证所属保护目录的当前会话。
  /// 返回：完整密文发布后返回新会话；名称非法、内容损坏、取消或未授权时不替换原件。
  func renameFile(id: UUID, to name: String, using grant: VaultGrant) throws -> VaultGrant {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    try store.authorize(grant)
    let original = try rawReader(id: id, using: grant).media
    guard !original.isFolder || original.isDocument else {
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
      folderPassword: original.folderPassword)
    return try publishMetadata(
      media, replacing: original, requirements: requirements, using: grant,
      uncertain: .organizationCommitUncertain)
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
        $0.parentID == parentID && $0.isFolder && !$0.isDocument
          && $0.originalFilename.localizedCaseInsensitiveCompare(name) == .orderedSame
      }
      guard let folder = matches.first else {
        throw VaultError.moveDirectoryNotFound
      }
      guard matches.count == 1 else {
        throw VaultError.corrupt
      }
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
  /// 返回：已认证来源与本次所需目录证明；受保护来源、保护范围逃逸、循环或重名时拒绝。
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
      guard parent.isFolder, !parent.isDocument,
        !entries.contains(where: {
          $0.id == parentID
        })
      else {
        throw VaultError.invalidMove
      }
      destinationProtection = try folderRequirements(for: parent, includingSelf: true, using: grant)
    }
    // 来源仍受祖先保护时，移动不得把内容带到该保护范围之外再导出。
    guard sourceProtection.isSubset(of: Set(destinationProtection.keys)) else {
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

  /// 业务作用：逐项移动同一目录内的多个条目，先检查整批约束，再以有界缓冲逐文件提交。
  /// 参数说明：
  /// - `ids`：当前批次明确选择且不重复的来源身份。
  /// - `parentID`：统一接收目录；为空时接收至保险箱根目录。
  /// - `grant`：已验证来源与目标密码的当前会话。
  /// 返回：新会话、完成数量和中途失败说明；预检失败不移动任何条目，中途失败保留已完成项及其余原件。
  func move(ids: [UUID], to parentID: UUID?, using grant: VaultGrant) throws -> VaultBatchMoveResult
  {
    mutation.lock()
    defer {
      mutation.unlock()
    }
    guard !ids.isEmpty, Set(ids).count == ids.count else {
      throw VaultError.invalidMove
    }
    let plans = try ids.map {
      try prepareMove(id: $0, to: parentID, using: grant)
    }
    let sourceParent = plans[0].media.parentID
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
        current.retainFolderAccess([])
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
        current = try move(id: id, to: parentID, using: current)
        moved += 1
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
  /// 返回：移动发布后撤销旧读取并交付新会话；受保护来源、保护范围逃逸、循环或重名时拒绝。
  func move(id: UUID, to parentID: UUID?, using grant: VaultGrant) throws -> VaultGrant {
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
      folderPassword: original.folderPassword)
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
  /// 返回：目标目录树均无密码保护且删除、同步成功后完成；仍受保护时保留全部密文。
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

  /// 业务作用：按原名逐块解密导出到用户选择的位置，验证完整内容后才发布明文。
  /// 参数说明：
  /// - `id`：需要导出的媒体身份。
  /// - `directory`：用户明确授权的本地目标目录。
  /// - `grant`：当前独立密码会话。
  /// - `progress`：仅用于当前界面的导出进度。
  /// 返回：目标、祖先及子目录均无密码保护且完整验证后发布明文；拒绝时保留密文，不生成导出副本。
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
    return try materialize(id: id, to: directory, using: grant, progress: progress)
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
  /// - `progress`：本次内存中的完成比例，不保存来源或查看历史。
  /// 返回：全部相关目录密码已重新验证且内容完整时发布副本；失败清理暂存，事务不能重放。
  func copyToSystem(
    _ session: VaultCopySession, to directory: URL, using grant: VaultGrant,
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
    return try materialize(
      id: session.mediaID, to: directory, using: permission, progress: progress)
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
    let name = folder.originalFilename
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
          let childName = entry.originalFilename
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
