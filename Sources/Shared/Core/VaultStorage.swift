import CryptoKit
import Darwin
import Foundation

/// 有界文件操作与原子发布，避免不完整的密文或凭据头被当作有效数据。
enum VaultStorage {
  /// 业务作用：创建仅当前用户可访问的本地保险箱目录，并拒绝符号链接替代存储位置。
  /// 参数说明：
  /// - `url`：保险箱私有目录。
  /// 返回：真实目录可用且权限收紧后成功；创建或权限设置失败时拒绝。
  static func directory(_ url: URL) throws {
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard attributes[.type] as? FileAttributeType == .typeDirectory else {
      throw VaultError.storage
    }
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    #if os(iOS)
      try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
    #endif
  }

  /// 业务作用：通过独占创建的文件句柄写暂存内容，避免覆盖已有文件或跟随链接。
  /// 参数说明：
  /// - `url`：本次操作新分配的暂存路径。
  /// 返回：权限为 0600 的新文件句柄；路径已存在或无法创建时失败。
  static func create(_ url: URL) throws -> FileHandle {
    let descriptor = Darwin.open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else {
      throw VaultError.storage
    }
    return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
  }

  /// 业务作用：原子提交小型凭据结构，完成持久化后才向调用方报告成功。
  /// 参数说明：
  /// - `data`：完整的待提交结构。
  /// - `url`：当前有效文件的固定位置。
  /// 返回：暂存内容同步并原子替换成功；失败不主动删除原有效文件。
  static func atomicWrite(_ data: Data, to url: URL) throws {
    let temporary = url.deletingLastPathComponent().appendingPathComponent(
      ".\(UUID().uuidString).partial")
    defer {
      try? FileManager.default.removeItem(at: temporary)
    }
    let file = try create(temporary)
    try file.write(contentsOf: data)
    try file.synchronize()
    try file.close()
    guard Darwin.rename(temporary.path, url.path) == 0 else {
      throw VaultError.storage
    }
    try synchronizeDirectory(url.deletingLastPathComponent())
  }

  /// 业务作用：让目录中的重命名和新增条目进入文件系统持久化顺序。
  /// 参数说明：
  /// - `url`：刚完成发布的文件所在目录。
  /// 返回：目录同步成功；系统无法确认时失败，不授权后续删源。
  static func synchronizeDirectory(_ url: URL) throws {
    let descriptor = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard descriptor >= 0 else {
      throw VaultError.storage
    }
    defer {
      Darwin.close(descriptor)
    }
    guard Darwin.fsync(descriptor) == 0 else {
      throw VaultError.storage
    }
  }

  /// 业务作用：从单一文件句柄精确读取格式字段，截断时拒绝而不交付部分字段。
  /// 参数说明：
  /// - `file`：已经打开的文件。
  /// - `count`：本次字段所需的字节数。
  /// 返回：指定长度的数据；文件提前结束或读取失败时失败。
  static func read(_ file: FileHandle, count: Int) throws -> Data {
    guard count >= 0, count <= 2 * 1024 * 1024 else {
      throw VaultError.corrupt
    }
    var result = Data()
    while result.count < count {
      let part = try file.read(upToCount: count - result.count) ?? Data()
      guard !part.isEmpty else {
        throw VaultError.corrupt
      }
      result.append(part)
    }
    return result
  }
}

/// 可立即撤销的明文读取权威；不存储查看事件、时间或进度。
final class VaultGrant: @unchecked Sendable {
  private let mutex = NSLock()
  private var root: Data?
  private var active = true
  private var folderAccess: [UUID: UUID] = [:]
  private let parent: VaultGrant?
  let vaultID: UUID

  /// 业务作用：为已验证的主会话建立读取权威，或建立用途受限且依赖主会话的临时能力。
  /// 参数说明：
  /// - `root`：主会话已认证的随机密钥；依赖父会话时不另行持有该密钥。
  /// - `vaultID`：该主密钥所属的保险箱。
  /// - `parent`：临时用途能力依赖的 App 会话；为空时是独立验证取得的主会话。
  /// 返回：仅保存在内存中的会话能力。
  init(root: Data, vaultID: UUID, parent: VaultGrant? = nil) {
    self.root = parent == nil ? root : nil
    self.vaultID = vaultID
    self.parent = parent
  }

  /// 业务作用：在线性化的授权范围内使用主密钥或交付明文，使撤销之后旧任务无法继续交付。
  /// 参数说明：
  /// - `folders`：本次交付需要保持有效的目录验证代次。
  /// - `operation`：同步完成的受保护操作，不得再次进入同一能力。
  /// 返回：操作成功的结果；会话撤销后立即拒绝。
  func access<T>(folders: [UUID: UUID] = [:], _ operation: (Data) throws -> T) throws -> T {
    if let parent {
      // 临时复制能力每次交付都依赖原 App 会话；锁定父会话即可阻止下一块读写。
      return try parent.access { root in
        try accessRoot(folders: folders, inheritedRoot: root, operation)
      }
    }
    return try accessRoot(folders: folders, operation)
  }

  /// 业务作用：在当前能力自己的门禁内复验目录证明，并同步交付密钥或明文。
  /// 参数说明：
  /// - `folders`：本次操作必须仍有效的目录密码代次。
  /// - `inheritedRoot`：父会话在当前门禁内临时交付的密钥，不存入当前能力。
  /// - `operation`：不能重入当前能力的同步操作。
  /// 返回：当前能力和目录证明均有效时交付结果，否则在任何副作用之前拒绝。
  private func accessRoot<T>(
    folders: [UUID: UUID], inheritedRoot: Data? = nil, _ operation: (Data) throws -> T
  ) throws -> T {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    // 取消临时能力后，即使其父会话仍然解锁，也不能借父密钥恢复已结束的复制。
    guard active, let root = inheritedRoot ?? root else {
      throw VaultError.locked
    }
    for (id, revision) in folders where folderAccess[id] != revision {
      throw VaultError.folderPasswordRequired(id)
    }
    return try operation(root)
  }

  /// 业务作用：检查当前会话仍有效，供有界读写循环在下一步副作用前复验。
  /// 参数说明：无。
  /// 返回：能力有效时成功，已锁定时失败。
  func check() throws {
    try access { _ in
      ()
    }
  }

  /// 业务作用：把本次正确目录密码验证限制在当前 App 会话，不保存访问凭证。
  /// 参数说明：
  /// - `id`：已验证的目录身份。
  /// - `revision`：本次密码校验材料的身份。
  /// - `parents`：派生完成后仍需有效的祖先目录授权。
  /// 返回：会话仍有效时允许当前目录读取；App 锁定后拒绝授权。
  func allowFolder(_ id: UUID, revision: UUID, requiring parents: [UUID: UUID] = [:]) throws {
    try access(folders: parents) { _ in
      folderAccess[id] = revision
    }
  }

  /// 业务作用：离开浏览路径时撤销其它目录权限，使旧读取器也不能继续取数。
  /// 参数说明：
  /// - `ids`：当前浏览路径仍需保留的祖先目录身份。
  /// 返回：只保留当前路径的内存授权，不建立访问记录。
  func retainFolderAccess(_ ids: Set<UUID>) {
    mutex.lock()
    folderAccess = folderAccess.filter {
      ids.contains($0.key)
    }
    mutex.unlock()
  }

  /// 业务作用：撤销所有持有本会话的异步读取能力，解除内存中主密钥引用。
  /// 参数说明：无。
  /// 返回：等待当前同步交付结束后，后续访问均失败。
  func revoke() {
    mutex.lock()
    active = false
    root = nil
    folderAccess = [:]
    mutex.unlock()
  }
}
