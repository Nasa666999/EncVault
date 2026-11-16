import Foundation
import UniformTypeIdentifiers

/// 导入阶段只在当前会话展示，不序列化来源、进度或文件访问历史。
enum ImportPhase: Sendable {
  case directory, digest, encrypt, verify, commit, confirm, saved

  /// 业务作用：说明当前磁盘工作阶段，避免大文件计算摘要时界面看似停滞。
  /// 参数说明：无。
  /// 返回：只用于当前导入界面的阶段标题。
  var title: String {
    switch self {
    case .directory:
      return "遍历文件夹"
    case .digest:
      return "校验原文件"
    case .encrypt:
      return "分块加密"
    case .verify:
      return "复验密文"
    case .commit:
      return "保存密文"
    case .confirm:
      return "确认落盘文件"
    case .saved:
      return "本文件已保存"
    }
  }
}

/// 有界进度快照只包含当前文件和累计数量，不保存已处理路径列表。
struct ImportProgress: Sendable {
  let phase: ImportPhase
  let filename: String
  let currentBytes: UInt64
  let totalBytes: UInt64
  var completedFiles = 0
  var completedBytes: UInt64 = 0
  var failedFiles = 0

  /// 业务作用：把单文件阶段映射为该文件内的连续进度，目录未知总量不伪造总百分比。
  /// 参数说明：无。
  /// 返回：当前文件的阶段比例；正在遍历目录时为空。
  var fraction: Double? {
    let part = totalBytes == 0 ? 1 : min(1, Double(currentBytes) / Double(totalBytes))
    switch phase {
    case .directory:
      return nil
    case .digest:
      return part * 0.2
    case .encrypt:
      return 0.2 + part * 0.6
    case .verify:
      return 0.8 + part * 0.15
    case .commit:
      return 0.95
    case .confirm:
      return 0.95 + part * 0.05
    case .saved:
      return 1
    }
  }

  /// 业务作用：将当前文件进度叠加到此前已提交条目，累计计数不携带历史文件名。
  /// 参数说明：
  /// - `files`：此前已完整发布的普通文件数量。
  /// - `bytes`：此前已完整发布的原始字节总量。
  /// - `failures`：此前未能完成的条目数量。
  /// 返回：只在内存中交付的累计快照，累计字节显示超限时饱和而不回绕。
  func adding(files: Int, bytes: UInt64, failures: Int) -> ImportProgress {
    var result = self
    result.completedFiles += files
    let sum = result.completedBytes.addingReportingOverflow(bytes)
    result.completedBytes = sum.overflow ? UInt64.max : sum.partialValue
    result.failedFiles += failures
    return result
  }
}

/// 保险箱只接受用户单独设置的数字或手势凭据。
enum CredentialKind: String, Codable, CaseIterable, Sendable {
  case pin
  case pattern

  /// 业务作用：向独立凭据界面提供当前输入方式的准确名称。
  /// 参数说明：无。
  /// 返回：数字密码或手势密码的本地显示名称。
  var title: String {
    switch self {
    case .pin:
      return "6 位数字密码"
    case .pattern:
      return "手势密码"
    }
  }
}

/// 用于统一界面、密钥派生与两端输入规则的独立凭据。
struct VaultCredential: Sendable {
  let kind: CredentialKind
  let value: String

  /// 业务作用：校验独立凭据并生成有类型前缀的稳定编码，避免两种密码方式互相混淆。
  /// 参数说明：无。
  /// 返回：合法密码的派生输入；长度、字符或手势序列不合法时拒绝。
  func encoded() throws -> Data {
    switch kind {
    case .pin:
      guard value.utf8.count == 6,
        value.utf8.allSatisfy({
          (48...57).contains($0)
        })
      else {
        throw VaultError.invalidPIN
      }
    case .pattern:
      let nodes = value.split(separator: ",").compactMap {
        Int($0)
      }
      guard nodes.count >= 4, nodes.count <= 9,
        Set(nodes).count == nodes.count,
        nodes.allSatisfy({
          (0...8).contains($0)
        }),
        nodes.map(String.init).joined(separator: ",") == value,
        PatternRules.normalized(nodes) == nodes
      else {
        throw VaultError.invalidPattern
      }
    }
    return Data((kind.rawValue + ":" + value).utf8)
  }
}

/// 九宫格按行编号，跨过尚未选择的中心节点时补入该节点。
enum PatternRules {
  /// 业务作用：统一触摸、鼠标和凭据校验采用的手势节点顺序。
  /// 参数说明：
  /// - `input`：用户依次触及的节点，编号为 0 至 8。
  /// 返回：不重复且补齐跨越节点的序列；越界节点被忽略。
  static func normalized(_ input: [Int]) -> [Int] {
    var result: [Int] = []
    for node in input where (0...8).contains(node) && !result.contains(node) {
      if let previous = result.last {
        let dx = node % 3 - previous % 3
        let dy = node / 3 - previous / 3
        if abs(dx) == 2 && dy == 0 || abs(dy) == 2 && dx == 0
          || abs(dx) == 2 && abs(dy) == 2
        {
          let middle = (previous / 3 + dy / 2) * 3 + previous % 3 + dx / 2
          if !result.contains(middle) {
            result.append(middle)
          }
        }
      }
      result.append(node)
    }
    return result
  }
}

/// 对用户暴露稳定错误，不携带来源路径、密钥或媒体正文。
enum VaultError: Error, LocalizedError, Sendable {
  case invalidPIN
  case invalidPattern
  case incorrectCredential
  case invalidRecovery
  case locked
  case corrupt
  case storage
  case keychain(Int32)
  case wait(Int)
  case alreadyConfigured
  case notConfigured
  case invalidEnrollment
  case unsupportedMedia
  case sourceChanged
  case cloudOnly
  case cancelled
  case sourceRemoval
  case destinationExists
  case credentialCommitUncertain
  case photoAccess
  case photoResource
  case photoSelectionDelivery(Int)
  case photoResourceUnavailable(String, Int)
  case photoResourcePending
  case incompletePhotoBundle
  case photoLocalResource
  case invalidFolder
  case unsupportedSource
  case compositePhoto
  case photoChange
  case systemExportUncertain
  case documentTooLarge
  case textEncoding
  case documentChanged
  case documentCommitUncertain
  case documentPreviewUnavailable
  case folderPasswordRequired(UUID)
  case invalidFolderPassword
  case incorrectFolderPassword
  case folderVerificationUnavailable
  case folderProtectionExists
  case protectedFolderDeletion
  case protectedFolderExport
  case protectedFolderMove
  case invalidFolderName
  case invalidFileName
  case fileExtensionChanged
  case invalidSelection
  case invalidMove
  case invalidVaultPath
  case moveDirectoryNotFound
  case organizationCommitUncertain
  case folderCommitUncertain
  case rootRequired
  case rootNotConfigured
  case rootAlreadyConfigured
  case invalidRootPassword
  case incorrectRootPassword
  case rootCommitUncertain

  /// 业务作用：为界面提供脱敏失败说明，不泄露路径、密钥和媒体正文。
  /// 参数说明：无。
  /// 返回：对应失败边界的本地提示。
  var errorDescription: String? {
    switch self {
    case .rootRequired:
      return "请先验证 ROOT 密码并开启 ROOT 权限。"
    case .rootNotConfigured:
      return "请先设置独立的 ROOT 密码。"
    case .rootAlreadyConfigured:
      return "ROOT 密码已经设置，请使用 ROOT 密码验证开启。"
    case .invalidRootPassword:
      return "ROOT 密码需为 6 至 128 个字符，不能全部为空白。"
    case .incorrectRootPassword:
      return "ROOT 密码校验未通过。"
    case .rootCommitUncertain:
      return "ROOT 密码保存状态未能确认，请重新解锁后再验证；不要清空保险箱。"
    case .invalidPIN:
      return "请输入完整的 6 位数字密码。"
    case .invalidPattern:
      return "手势至少连接 4 个不同节点。"
    case .incorrectCredential:
      return "密码不正确。"
    case .invalidRecovery:
      return "恢复码不正确或无法恢复此保险箱。"
    case .locked:
      return "保险箱已锁定，请重新输入独立密码。"
    case .corrupt:
      return "文件不完整或已发生变化，无法安全读取。"
    case .storage:
      return "无法完成本地保存，请检查空间和文件权限。"
    case .keychain:
      return "本机密钥存储不可用。可尝试离线恢复，不能使用设备密码代替保险箱密码。"
    case .wait(let seconds):
      return "密码输入已冻结，请等待 \(CredentialLockout.durationText(seconds)) 后再试。"
    case .alreadyConfigured:
      return "保险箱已经设置，请使用修改密码。"
    case .notConfigured:
      return "请先设置保险箱密码。"
    case .invalidEnrollment:
      return "本次设置已经失效，请重新开始。"
    case .unsupportedMedia:
      return "当前文件的大小、结构或编码暂不受此操作支持。"
    case .sourceChanged:
      return "来源文件在保存过程中发生变化，原件已保留。"
    case .cloudOnly:
      return "原件尚未下载到本机，请先通过系统下载后再导入。"
    case .cancelled:
      return "操作已取消，原件已保留。"
    case .sourceRemoval:
      return "加密文件已保存，但系统未能移除原件。"
    case .destinationExists:
      return "目标已有同名文件。请选择其它目录，原名不会被改写，也不会覆盖文件。"
    case .credentialCommitUncertain:
      return "密码提交状态未能确认。请重新打开，尝试原密码、新密码或刚保存的恢复码；不要清空保险箱。"
    case .photoAccess:
      return "无法访问所选照片。请在系统设置中允许照片访问，返回后重新解锁操作。"
    case .photoResource:
      return "系统未能交付所选文件，请重新选择，或通过本地文件入口导入；原件已保留。"
    case .photoSelectionDelivery(let code):
      return "系统照片选择器未能交付此项目（错误 \(code)）；请重新选择，原件保留。"
    case .photoResourceUnavailable(let role, let code):
      return "\(role)暂时无法读取（系统错误 \(code)）；已交付的文件仍可保存，原件保留。"
    case .photoResourcePending:
      return "系统仍在处理照片原件，目前只有代理图；可保存所选副本，原件处理完成前不能删源。"
    case .incompletePhotoBundle:
      return "配套资源未能全部保存并确认，原件保留；已交付的文件仍可单独保存。"
    case .photoLocalResource:
      return "系统未能提供可离线读取的照片或视频原件。请重新选择，或通过本地文件入口导入；原件已保留。"
    case .invalidFolder:
      return "请选择本地文件夹；不能把保险箱所在目录导入保险箱自身。"
    case .unsupportedSource:
      return "来源不是可读取的普通文件或目录，符号链接和特殊文件不会被导入。"
    case .compositePhoto:
      return "此相册操作要求单一照片或视频资源；组合资源请按完整文件夹保存或导出，原件保留。"
    case .photoChange:
      return "系统未能确认相册操作完成，请检查系统照片；保险箱内的加密文件保留。"
    case .systemExportUncertain:
      return "系统照片中可能已生成明文副本，但未能完成复验。请检查相册；保险箱密文保留。"
    case .documentTooLarge:
      return "文档超过只读预览上限（文本 8 MiB，其它文档或文件包 512 MiB），仍可按原名解密导出。"
    case .textEncoding:
      return "修改后的文字无法用原编码无损保存，或超过文本大小上限（8 MiB）。请调整内容后再保存。"
    case .documentChanged:
      return "文件内容已发生变化，请退出编辑，重新打开并验证密码后再编辑。"
    case .documentCommitUncertain:
      return "未能确认文档保存完成。保险箱已锁定，请重新解锁并查看文件内容；不要清空保险箱。"
    case .documentPreviewUnavailable:
      return "未能完成此文档的正文预览。可重试，或按原名解密导出。"
    case .folderPasswordRequired:
      return "请先输入此文件夹的独立访问密码。"
    case .invalidFolderPassword:
      return "文件夹密码需为 6 至 128 个字符，不能全部为空白。"
    case .incorrectFolderPassword:
      return "文件夹密码校验未通过。"
    case .folderVerificationUnavailable:
      return "系统暂时无法完成文件夹加密校验，请重试。本次未判定密码是否正确。"
    case .folderProtectionExists:
      return "此文件夹已设置访问密码，请先凭原密码取消。"
    case .protectedFolderDeletion:
      return "此项目位于受保护的文件夹中，或包含受保护的子文件夹，请先取消相关文件夹密码再删除。"
    case .protectedFolderExport:
      return "此项目位于受保护的文件夹中，或包含受保护的子文件夹，请先取消相关文件夹密码再导出。"
    case .protectedFolderMove:
      return "受密码保护的文件夹及包含保护子目录的目录树不能移动；普通目录树不能移出祖先的保护范围。文件需重新验证来源文件夹密码后移动。"
    case .invalidFolderName:
      return "请输入有效文件夹名称，不能含路径分隔符，且不能与同级项目重名。"
    case .invalidFileName:
      return "请输入有效文件名称，不能含路径分隔符，且不能与同级项目重名。"
    case .fileExtensionChanged:
      return "重命名时请保留原扩展名，文件格式不会随名称改变。"
    case .invalidSelection:
      return "请选择当前目录中的文件或文件夹，不能重复选择或混合不同层级。"
    case .invalidMove:
      return "不能移到原位置、文件自身、其子文件夹或含同名项目的位置。"
    case .invalidVaultPath:
      return "请输入以 / 开头的保险箱目录，例如 /cp 或 /import/cc。"
    case .moveDirectoryNotFound:
      return "指定的保险箱目录不存在，文件仍保留在原位置。"
    case .organizationCommitUncertain:
      return "未能确认目录整理结果，保险箱已锁定，请重新解锁核对名称和文件位置。"
    case .folderCommitUncertain:
      return "未能确认文件夹密码保存完成，请重新解锁后核对此文件夹。"
    }
  }
}

/// 目录访问校验材料只作为加密元数据保存，不包含原始密码或可直接使用的明文密钥。
struct FolderPassword: Codable, Sendable, Equatable {
  let revision: UUID
  let salt: Data
  let iterations: Int
  let verification: Data
}

/// ROOT 独立密码的校验材料，整体仅保存在保险箱主密钥保护的密文中。
struct RootPassword: Codable, Sendable, Equatable {
  let revision: UUID
  let salt: Data
  let iterations: Int
  let verification: Data
}

/// 照片内部资源的展示入口，附件继续由同一加密目录关系管理。
struct VaultPhotoAsset: Codable, Sendable, Equatable {
  let primaryID: UUID
  let contentType: String
  let byteCount: UInt64
  let sha256: Data
  let totalByteCount: UInt64
  let resourceCount: Int
  let manifestID: UUID
}

/// 已解锁后可展示的媒体信息，不包含任何查看时间或播放进度。
struct VaultMedia: Codable, Identifiable, Sendable, Equatable {
  let id: UUID
  let originalFilename: String
  let contentType: String
  let byteCount: UInt64
  let sha256: Data
  var parentID: UUID? = nil
  var folderPassword: FolderPassword? = nil
  var hidden: Bool? = nil
  var photoAsset: VaultPhotoAsset? = nil

  /// 业务作用：把文档包及带配套资源的照片作为单个文件操作，不开放普通目录管理入口。
  /// 参数说明：无。
  /// 返回：条目使用内部目录保存完整文件内容时为真，不表示用户创建的普通文件夹。
  var isFilePackage: Bool {
    isFolder && (photoAsset != nil || isDocument)
  }

  /// 业务作用：将隐藏标记限定为普通文件夹，旧元数据缺少标记时保持可见。
  /// 参数说明：无。
  /// 返回：普通文件夹已设置隐藏时为真；文件、文档包及照片包不具有隐藏状态。
  var isHidden: Bool {
    isFolder && !isFilePackage && hidden == true
  }

  /// 业务作用：按认证内容类型选择视频播放入口，不依赖文件扩展名。
  /// 参数说明：无。
  /// 返回：真实内容被识别为视频时为真。
  var isVideo: Bool {
    let type = photoAsset?.contentType ?? contentType
    return UTType(type)?.conforms(to: .movie) == true || type == "public.movie"
  }

  /// 业务作用：按认证内容类型选择本地图片解码入口。
  /// 参数说明：无。
  /// 返回：内容类型符合图片类型时为真。
  var isImage: Bool {
    UTType(photoAsset?.contentType ?? contentType)?.conforms(to: .image) == true
  }

  /// 业务作用：区分携带加密目录关系的零载荷条目与普通文件。
  /// 参数说明：无。
  /// 返回：条目是目录或目录形式的文件包时为真。
  var isFolder: Bool {
    contentType == UTType.folder.identifier
  }

  /// 业务作用：选择不执行脚本、不加载外部资源的纯文本查看入口。
  /// 参数说明：无。
  /// 返回：认证原名属于文本扩展名且条目不是目录时为真。
  var isTextDocument: Bool {
    !isFolder
      && [
        "txt", "md", "markdown", "html", "htm", "csv", "log", "json", "xml", "yaml", "yml",
        "css", "js", "swift", "rs",
      ].contains((originalFilename as NSString).pathExtension.lowercased())
  }

  /// 业务作用：把可只读查看的普通文档及文档包与媒体相册、一般目录分开。
  /// 参数说明：无。
  /// 返回：文本、常见办公文档、PDF 或受支持文档包为真；不承诺任意扩展名可预览。
  var isDocument: Bool {
    guard !isImage, !isVideo else {
      return false
    }
    let suffix = (originalFilename as NSString).pathExtension.lowercased()
    if isFolder {
      return ["pages", "numbers", "key", "rtfd"].contains(suffix)
    }
    return isTextDocument
      || [
        "pages", "numbers", "key", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf",
        "odt", "ods", "odp",
      ].contains(suffix)
  }

  /// 业务作用：为列表和辅助功能提供与实际操作入口一致的文件类型说明。
  /// 参数说明：无。
  /// 返回：普通或隐藏文件夹、视频、图片或普通文件的本地说明。
  var kindTitle: String {
    if isFolder && !isFilePackage {
      return isHidden ? "隐藏文件夹" : "文件夹"
    }
    if isVideo {
      return "视频"
    }
    return isImage ? "图片" : "文件"
  }

  /// 业务作用：在没有媒体预览时显示对应类型图标，不把普通文档当作图片解码。
  /// 参数说明：无。
  /// 返回：系统文件类型图标名称。
  var symbolName: String {
    if isFolder && !isFilePackage {
      return "folder.fill"
    }
    if isVideo {
      return "film"
    }
    return isImage ? "photo" : "doc.fill"
  }
}

/// 一次设置或重设的确认材料；恢复码仅交付到当前设置界面。
struct EnrollmentOffer: Sendable {
  let token: UUID
  let recoveryCode: String
}

/// 只记录认证失败的退避状态，与媒体访问和播放行为无关。
struct DeviceSecretState: Codable, Sendable {
  var secret: Data
  var failures: Int = 0
  var retryAfter: TimeInterval = 0
  var lastFailureTime: TimeInterval = 0
  var freezeLevel: Int?
}

/// 只向锁定界面交付认证限制，不包含设备因子、密码或访问记录。
struct CredentialLockoutStatus: Sendable {
  let blockedUntil: TimeInterval
  let attemptsRemaining: Int
  let nextFreeze: Int

  /// 业务作用：随本机时间计算当前冻结剩余秒数，使到期后可以重新输入。
  /// 参数说明：
  /// - `now`：当前本机时间。
  /// 返回：未到期时的向上取整秒数，到期后为零；无效时间保持拒绝。
  func remainingSeconds(at now: TimeInterval) -> Int {
    guard now.isFinite else {
      return 30 * 86_400
    }
    return Int(min(366 * 86_400 * 10_000, max(0, ceil(blockedUntil - now))))
  }

  /// 业务作用：冻结到期后恢复本轮三次输入机会，不要求重新启动界面。
  /// 参数说明：
  /// - `now`：当前本机时间。
  /// 返回：冻结时为零，到期时为三次，未冻结的当前轮保留已有剩余次数。
  func availableAttempts(at now: TimeInterval) -> Int {
    guard remainingSeconds(at: now) == 0 else {
      return 0
    }
    return attemptsRemaining == 0 ? 3 : attemptsRemaining
  }
}

/// 每三次失败进入下一轮冻结，状态由当前凭据代次的 Keychain 因子一同保存。
enum CredentialLockout {
  private static let durations = [86_400, 259_200, 777_600, 2_332_800, 2_592_000]

  /// 业务作用：校验持久化限制并把旧的短时退避状态转换为三次失败冻结策略。
  /// 参数说明：
  /// - `saved`：当前凭据代次保存的设备因子与失败状态。
  /// 返回：可用于认证的限制状态；损坏计数和非有限时间拒绝使用。
  static func normalized(_ saved: DeviceSecretState) throws -> DeviceSecretState {
    guard (0...30).contains(saved.failures),
      saved.retryAfter.isFinite, (0...253_402_300_799).contains(saved.retryAfter),
      saved.lastFailureTime.isFinite, (0...253_402_300_799).contains(saved.lastFailureTime)
    else {
      throw VaultError.corrupt
    }
    var state = saved
    if state.freezeLevel == nil {
      state.freezeLevel = state.failures >= 3 ? 1 : 0
      if state.failures >= 3 {
        // 已有三次失败不能因策略切换恢复猜测机会，冻结从最后一次已记账尝试计算。
        state.failures = 3
        state.retryAfter = max(state.retryAfter, state.lastFailureTime + Double(durations[0]))
      }
    }
    guard let level = state.freezeLevel, (0...durations.count).contains(level),
      (0...3).contains(state.failures)
    else {
      throw VaultError.corrupt
    }
    return state
  }

  /// 业务作用：为认证入口与两端锁定界面计算同一冻结门禁。
  /// 参数说明：
  /// - `saved`：当前持久化的限制状态。
  /// - `now`：当前本机时间。
  /// 返回：冻结截止、可用次数与下轮时长；无效状态或时间拒绝。
  static func status(_ saved: DeviceSecretState, at now: TimeInterval) throws
    -> CredentialLockoutStatus
  {
    guard now.isFinite, (0...253_399_708_799).contains(now) else {
      throw VaultError.storage
    }
    let state = try normalized(saved)
    // 回拨时间不能抹掉已记账的失败或缩短仍有效的冻结。
    let deadline = max(
      state.retryAfter, now + 5 < state.lastFailureTime ? state.lastFailureTime : 0)
    let frozen = now < deadline
    let failures = state.failures == 3 && !frozen ? 0 : state.failures
    return CredentialLockoutStatus(
      blockedUntil: deadline,
      attemptsRemaining: frozen ? 0 : 3 - failures,
      nextFreeze: durations[min(state.freezeLevel ?? 0, durations.count - 1)])
  }

  /// 业务作用：认证计算前消费一次尝试，第三次预记账时持久化本轮冻结。
  /// 参数说明：
  /// - `saved`：当前凭据代次的限制状态。
  /// - `now`：开始认证的本机时间。
  /// 返回：需要先持久化的新状态；冻结未到期时拒绝，不增加次数或延长截止。
  static func recordingAttempt(_ saved: DeviceSecretState, at now: TimeInterval) throws
    -> DeviceSecretState
  {
    let remaining = try status(saved, at: now).remainingSeconds(at: now)
    guard remaining == 0 else {
      throw VaultError.wait(remaining)
    }
    var state = try normalized(saved)
    if state.failures == 3 {
      state.failures = 0
    }
    state.retryAfter = 0
    state.failures += 1
    state.lastFailureTime = now
    if state.failures == 3 {
      let level = state.freezeLevel ?? 0
      state.retryAfter = now + Double(durations[min(level, durations.count - 1)])
      state.freezeLevel = min(level + 1, durations.count)
    }
    return state
  }

  /// 业务作用：把冻结时间转换为可读的天、小时、分钟和秒，不显示大段秒数。
  /// 参数说明：
  /// - `seconds`：当前限制剩余的整秒数。
  /// 返回：适合锁定提示与倒计时的中文时长。
  static func durationText(_ seconds: Int) -> String {
    let value = max(0, seconds)
    let parts = [
      (value / 86_400, "天"), (value % 86_400 / 3600, "小时"),
      (value % 3600 / 60, "分钟"), (value % 60, "秒"),
    ]
    let text = parts.filter {
      $0.0 > 0
    }.map {
      "\($0.0)\($0.1)"
    }.joined(separator: " ")
    return text.isEmpty ? "0秒" : text
  }
}

/// 本机秘密存储的业务边界；应用实现使用 Keychain。
protocol DeviceSecretStore: Sendable {
  /// 业务作用：读取指定保险箱凭据代次的本机秘密，不执行生物识别或设备密码验证。
  /// 参数说明：
  /// - `account`：当前凭据代次的随机账户标识。
  /// 返回：已有秘密；不存在时为空，系统拒绝访问时失败。
  func read(account: String) throws -> DeviceSecretState?

  /// 业务作用：持久化本机秘密和失败退避状态。
  /// 参数说明：
  /// - `state`：需要保存的设备秘密及认证失败状态。
  /// - `account`：本次凭据代次的随机账户标识。
  /// 返回：系统确认写入时成功；拒绝或写入失败时不得继续授权。
  func write(_ state: DeviceSecretState, account: String) throws

  /// 业务作用：清理已不再被有效凭据头引用的本机秘密。
  /// 参数说明：
  /// - `account`：已经失效的账户标识。
  /// 返回：已删除或本来不存在时成功，系统拒绝时失败。
  func remove(account: String) throws
}
