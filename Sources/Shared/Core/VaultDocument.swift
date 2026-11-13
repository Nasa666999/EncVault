import Foundation

#if os(macOS)
  import Darwin
#endif

/// 系统预览所需的私有明文副本；所有权随当前查看会话结束，不向密文写回内容。
final class VaultDocument: @unchecked Sendable {
  let url: URL
  let text: String?
  let media: VaultMedia
  let textFormat: VaultTextFormat?
  let reader: VaultMediaReader
  private let directory: URL
  private let mutex = NSLock()
  private var closed = false
  private var acceptingRendering = true
  #if os(macOS)
    private var parser: Process?
  #endif

  /// 业务作用：绑定完整验证后的原名副本，限制其生命周期属于一次只读查看。
  /// 参数说明：
  /// - `url`：保持原文件名的私有明文位置。
  /// - `text`：文本类文件的离线内容；非文本由系统文档预览显示。
  /// - `media`：本次查看完整验证的文件身份与内容摘要。
  /// - `textFormat`：能无损往返的文本编码及字节序标记；不能安全编辑时为空。
  /// - `directory`：仅由本次查看拥有的随机暂存目录。
  /// - `reader`：限定所属目录权限的认证读取器，供禁止系统分享的内置预览使用。
  /// 返回：具有幂等清理能力的查看材料，读取器随 App 锁定失权。
  private init(
    url: URL, text: String?, media: VaultMedia, textFormat: VaultTextFormat?, directory: URL,
    reader: VaultMediaReader
  ) {
    self.url = url
    self.text = text
    self.media = media
    self.textFormat = textFormat
    self.directory = directory
    self.reader = reader
  }

  /// 业务作用：在保险箱排他打开后清除上次中断留下的自有预览副本。
  /// 参数说明：
  /// - `store`：已取得排他目录所有权的保险箱。
  /// 返回：自有 UUID 暂存清理成功；清理失败时拒绝继续开放保险箱。
  static func removeInterruptedPreviews(in store: VaultStore) throws {
    let root = try stagingRoot(in: store)
    for child in try FileManager.default.contentsOfDirectory(
      at: root, includingPropertiesForKeys: nil)
    {
      guard UUID(uuidString: child.lastPathComponent) != nil else {
        continue
      }
      try FileManager.default.removeItem(at: child)
    }
  }

  /// 业务作用：为明确选择的文档解密并复验全部内容后，才交给只读预览。
  /// 参数说明：
  /// - `media`：已认证的普通文档或文档文件包。
  /// - `library`：当前保险箱的加密文件入口。
  /// - `store`：拥有暂存位置的保险箱。
  /// - `grant`：随锁定撤销的本次解锁能力。
  /// 返回：保持原名的完整只读副本；失权、超限或内容损坏时清理本次副本并拒绝。
  static func prepare(
    _ media: VaultMedia, library: VaultLibrary, store: VaultStore, using grant: VaultGrant
  ) throws -> VaultDocument {
    guard media.isDocument else {
      throw VaultError.unsupportedMedia
    }
    let reader = try library.reader(id: media.id, using: grant)
    let entries = try library.list(using: grant)
    var included: Set<UUID> = [media.id]
    var total = media.byteCount
    if media.isFolder {
      var changed = true
      while changed {
        changed = false
        for entry in entries where !included.contains(entry.id) {
          if let parent = entry.parentID, included.contains(parent) {
            included.insert(entry.id)
            // 包内所有载荷共享上限，避免把目录文件包作为绕过预览资源限制的入口。
            guard entry.byteCount <= 512 * 1024 * 1024 - min(total, 512 * 1024 * 1024) else {
              throw VaultError.documentTooLarge
            }
            total += entry.byteCount
            changed = true
          }
        }
      }
    }
    guard total <= (media.isTextDocument ? 8 : 512) * 1024 * 1024 else {
      throw VaultError.documentTooLarge
    }
    let root = try stagingRoot(in: store)
    let directory = root.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try VaultStorage.directory(directory)
    do {
      let url = try library.prepareDocumentCopy(id: media.id, in: directory, using: grant)
      var files = [url]
      if media.isFolder {
        guard
          let enumerator = FileManager.default.enumerator(
            at: url, includingPropertiesForKeys: [.isRegularFileKey])
        else {
          throw VaultError.storage
        }
        files += enumerator.allObjects.compactMap {
          $0 as? URL
        }
      }
      for file in files {
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        if attributes[.type] as? FileAttributeType == .typeRegular {
          try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: file.path)
        }
      }
      var text: String?
      var textFormat: VaultTextFormat?
      if media.isTextDocument {
        var encoding = String.Encoding.utf8
        text = try String(contentsOf: url, usedEncoding: &encoding)
        if let text {
          textFormat = VaultTextFormat.detect(
            data: try Data(contentsOf: url), text: text, fallback: encoding)
        }
      }
      // 私有副本完整复验后再次检查目录会话，锁定期间完成的工作不能重新发布查看入口。
      try reader.checkAccess()
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      return VaultDocument(
        url: url, text: text, media: media, textFormat: textFormat, directory: directory,
        reader: reader)
    } catch {
      try FileManager.default.removeItem(at: directory)
      throw error
    }
  }

  /// 业务作用：将文档暂存限制在保险箱私有、不参与备份的目录内。
  /// 参数说明：
  /// - `store`：当前排他打开的保险箱。
  /// 返回：权限为 0700、排除备份的固定暂存根目录；无法收紧权限时拒绝。
  private static func stagingRoot(in store: VaultStore) throws -> URL {
    var root = store.directory.appendingPathComponent("documents.noindex", isDirectory: true)
    try VaultStorage.directory(root)
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try root.setResourceValues(values)
    return root
  }

  /// 业务作用：在交付原生排版结果前复验本次文档仍开放，关闭后不能重新展示正文。
  /// 参数说明：无。
  /// 返回：本次查看仍有效时成功，关闭或锁定后拒绝。
  func checkOpen() throws {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    guard !closed, acceptingRendering else {
      throw VaultError.locked
    }
  }

  #if os(macOS)
    /// 业务作用：通过随包、继承当前沙箱的解析器读取 Pages 正文，不启动外部文档应用。
    /// 参数说明：无。
    /// 返回：仅内存中的格式化正文；超时、超限、取消或文档关闭时停止子进程并拒绝结果。
    func pagesHTML() throws -> Data {
      let executable = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/PagesReader")
      guard FileManager.default.isExecutableFile(atPath: executable.path) else {
        throw VaultError.documentPreviewUnavailable
      }
      let process = Process()
      process.executableURL = executable
      process.arguments = [url.path]
      let pipe = Pipe()
      process.standardOutput = pipe
      process.standardError = FileHandle.nullDevice
      let descriptor = pipe.fileHandleForReading.fileDescriptor
      guard fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else {
        throw VaultError.documentPreviewUnavailable
      }
      // 关闭文档与启动解析共用门禁，锁定后不能产生新的明文解析进程。
      mutex.lock()
      do {
        guard !closed, acceptingRendering, parser == nil else {
          throw VaultError.locked
        }
        try process.run()
        parser = process
        mutex.unlock()
      } catch {
        mutex.unlock()
        throw error
      }
      defer {
        if process.isRunning {
          Darwin.kill(process.processIdentifier, SIGKILL)
        }
        process.waitUntilExit()
        try? pipe.fileHandleForReading.close()
        try? pipe.fileHandleForWriting.close()
        mutex.lock()
        if parser === process {
          parser = nil
        }
        mutex.unlock()
      }
      let deadline = ProcessInfo.processInfo.systemUptime + 20
      var result = Data()
      var buffer = [UInt8](repeating: 0, count: 65_536)
      while true {
        try checkOpen()
        if Task.isCancelled {
          throw VaultError.cancelled
        }
        guard ProcessInfo.processInfo.systemUptime < deadline else {
          throw VaultError.documentPreviewUnavailable
        }
        let count = Darwin.read(descriptor, &buffer, buffer.count)
        if count > 0 {
          guard result.count <= 64 * 1024 * 1024 - count else {
            throw VaultError.documentTooLarge
          }
          result.append(contentsOf: buffer.prefix(count))
        } else if count == 0 || !process.isRunning && count < 0 {
          break
        } else if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
          throw VaultError.documentPreviewUnavailable
        } else {
          Thread.sleep(forTimeInterval: 0.02)
        }
      }
      process.waitUntilExit()
      guard process.terminationStatus == 0, !result.isEmpty else {
        throw VaultError.documentPreviewUnavailable
      }
      try checkOpen()
      return result
    }
  #endif

  /// 业务作用：结束查看或丢弃迟到结果时，精确删除本次拥有的全部明文材料。
  /// 参数说明：无。
  /// 返回：清理完成后幂等成功；删除失败时保留重试能力并报告失败。
  func close() throws {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    guard !closed else {
      return
    }
    acceptingRendering = false
    #if os(macOS)
      // 先终止当前自有解析进程再移除原名副本，退出或锁定不能让后台继续读取正文。
      if let parser, parser.isRunning {
        Darwin.kill(parser.processIdentifier, SIGKILL)
        parser.waitUntilExit()
      }
      parser = nil
    #endif
    if FileManager.default.fileExists(atPath: directory.path) {
      try FileManager.default.removeItem(at: directory)
    }
    closed = true
  }

  /// 业务作用：在调用方释放查看材料时补充清理，避免未发布结果留下私有明文。
  /// 参数说明：无。
  /// 返回：尽力删除本次副本；进程中断后的残留由下次启动门禁清理。
  deinit {
    try? close()
  }
}

/// 文本保存保持原编码和字节序标记，无法无损表示的新字符必须由用户处理。
struct VaultTextFormat: Sendable {
  let encoding: UInt
  let prefix: Data

  /// 业务作用：只为能逐字节往返的文本开放编辑，避免静默改变编码或原始标记。
  /// 参数说明：
  /// - `data`：已完整认证的原始文本字节。
  /// - `text`：系统解码得到的正文。
  /// - `fallback`：没有字节序标记时由系统识别的编码。
  /// 返回：编码与标记的无损组合；无法确认时保留只读查看。
  static func detect(data: Data, text: String, fallback: String.Encoding) -> VaultTextFormat? {
    let candidates: [(Data, String.Encoding)] = [
      (Data([0x00, 0x00, 0xFE, 0xFF]), .utf32BigEndian),
      (Data([0xFF, 0xFE, 0x00, 0x00]), .utf32LittleEndian),
      (Data([0xEF, 0xBB, 0xBF]), .utf8),
      (Data([0xFE, 0xFF]), .utf16BigEndian),
      (Data([0xFF, 0xFE]), .utf16LittleEndian),
    ]
    let match = candidates.first {
      data.starts(with: $0.0)
    }
    let format = VaultTextFormat(
      encoding: (match?.1 ?? fallback).rawValue, prefix: match?.0 ?? Data())
    guard (try? format.encode(text)) == data else {
      return nil
    }
    return format
  }

  /// 业务作用：保存前在内存中完成无损编码，禁止替换无法表示的字符。
  /// 参数说明：
  /// - `text`：用户明确点保存的当前草稿。
  /// 返回：保留原标记的字节；不可表示或超过文本上限时不产生磁盘副作用。
  func encode(_ text: String) throws -> Data {
    guard
      let body = text.data(using: String.Encoding(rawValue: encoding), allowLossyConversion: false),
      body.count <= 8 * 1024 * 1024 - prefix.count
    else {
      throw VaultError.textEncoding
    }
    return prefix + body
  }
}

/// 每次编辑独立认证的一次性能力，绑定文件和进入编辑时的内容，不保存密码或草稿。
final class VaultTextEdit: @unchecked Sendable {
  let media: VaultMedia
  let format: VaultTextFormat
  private let mutex = NSLock()
  private var grant: VaultGrant?
  private let readGrant: VaultGrant
  private let folderRequirements: [UUID: UUID]

  /// 业务作用：仅将新的密码认证结果绑定到当前文档，普通解锁能力不能直接进入编辑。
  /// 参数说明：
  /// - `document`：当前已经完整验证的只读文本。
  /// - `credential`：本次重新输入的保险箱密码或手势。
  /// - `store`：执行冻结规则与密码认证的保险箱。
  /// - `library`：复验当前文件身份的密文入口。
  /// - `readGrant`：当前只读会话，认证期间失权时拒绝开放编辑。
  /// 返回：只供当前文件保存一次的编辑能力；失败不改变文件内容。
  static func authorize(
    document: VaultDocument, credential: VaultCredential, store: VaultStore,
    library: VaultLibrary, using readGrant: VaultGrant
  ) throws -> VaultTextEdit {
    try readGrant.check()
    guard document.text != nil, document.media.isTextDocument, let format = document.textFormat
    else {
      throw VaultError.unsupportedMedia
    }
    let grant = try store.unlock(credential)
    do {
      // 重新认证不能使已经关闭的前台会话恢复控制权。
      try readGrant.check()
      let reader = try library.reader(id: document.media.id, using: readGrant)
      guard reader.media == document.media else {
        throw VaultError.documentChanged
      }
      return VaultTextEdit(
        media: document.media, format: format, grant: grant, readGrant: readGrant,
        folderRequirements: reader.folderRequirements)
    } catch {
      grant.revoke()
      throw error
    }
  }

  /// 业务作用：将已认证能力限制为单个文档的本次编辑。
  /// 参数说明：
  /// - `media`：认证的文件身份及原摘要。
  /// - `format`：已确认可无损往返的编码。
  /// - `grant`：本次独立认证取得的新能力。
  /// - `readGrant`：仍持有当前目录权限的原读取会话。
  /// - `folderRequirements`：编辑期间需持续有效的目录验证。
  /// 返回：仅在内存中生效的编辑会话。
  private init(
    media: VaultMedia, format: VaultTextFormat, grant: VaultGrant, readGrant: VaultGrant,
    folderRequirements: [UUID: UUID]
  ) {
    self.media = media
    self.format = format
    self.grant = grant
    self.readGrant = readGrant
    self.folderRequirements = folderRequirements
  }

  /// 业务作用：允许加密暂存使用当前编辑能力，退出或锁定后立即拒绝。
  /// 参数说明：无。
  /// 返回：仍有效的编辑能力；不提供重新激活入口。
  func authorization() throws -> VaultGrant {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    guard let grant else {
      throw VaultError.locked
    }
    try grant.check()
    try readGrant.access(folders: folderRequirements) { _ in
      ()
    }
    return readGrant
  }

  /// 业务作用：在最后发布门禁内消费本次编辑授权，串行化退出与密文替换。
  /// 参数说明：
  /// - `operation`：只执行最终密文替换与目录同步，不得再次进入编辑能力。
  /// 返回：发布成功或失败后均撤销编辑能力；已退出或锁定时不执行替换。
  func publish<T>(_ operation: () throws -> T) throws -> T {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    guard let current = grant else {
      throw VaultError.locked
    }
    defer {
      grant = nil
      current.revoke()
    }
    try current.check()
    // 编辑认证不替代目录密码，最终发布仍受原目录授权的同一门禁约束。
    return try readGrant.access(folders: folderRequirements) { _ in
      try operation()
    }
  }

  /// 业务作用：退出编辑、锁定或丢弃迟到认证结果时撤销本次保存权限。
  /// 参数说明：无。
  /// 返回：后续保存被拒绝，必须再次输入密码或手势。
  func revoke() {
    mutex.lock()
    let previous = grant
    grant = nil
    mutex.unlock()
    previous?.revoke()
  }

  /// 业务作用：释放编辑会话时补充撤销未使用的保存权限。
  /// 参数说明：无。
  /// 返回：后续不能通过该会话保存。
  deinit {
    revoke()
  }
}
