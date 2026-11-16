@preconcurrency import AVFoundation
import CoreTransferable
import CryptoKit
import Foundation
@preconcurrency import Photos
import UniformTypeIdentifiers

/// 系统选择器交付的本次来源副本，仅暂存在应用私有目录，不作为查看或播放缓存。
struct PickedPhotoFile: Transferable, Sendable {
  let file: URL
  let directory: URL

  /// 业务作用：按系统声明的图片、视频或通用文件类型接收选择结果，避免要求不存在的通用表示。
  /// 参数说明：无。
  /// 返回：有界文件交付规则，不为导入强制申请相册读写权限。
  static var transferRepresentation: some TransferRepresentation {
    FileRepresentation(importedContentType: .image) { received in
      try receive(received)
    }
    FileRepresentation(importedContentType: .movie) { received in
      try receive(received)
    }
    FileRepresentation(importedContentType: .data) { received in
      try receive(received)
    }
  }

  /// 业务作用：在系统临时文件有效期内复制内容，统一所有表示的暂存权限和失败清理。
  /// 参数说明：
  /// - `received`：系统选择器当前交付的文件，不在回调结束后直接持有其临时路径。
  /// 返回：本次选择独占的私有副本；复制失败、取消或名称非法时清理暂存并拒绝。
  private static func receive(_ received: ReceivedTransferredFile) throws -> PickedPhotoFile {
    guard received.file.isFileURL else {
      throw VaultError.photoResource
    }
    let incoming = try VaultStore.defaultDirectory().appendingPathComponent(
      "incoming.noindex", isDirectory: true)
    try VaultStorage.directory(incoming)
    let directory = incoming.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try VaultStorage.directory(directory)
    var accepted = false
    defer {
      if !accepted {
        try? FileManager.default.removeItem(at: directory)
      }
    }
    let name = received.file.lastPathComponent
    guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0")
    else {
      throw VaultError.photoResource
    }
    let file = directory.appendingPathComponent(name)
    let scoped = received.file.startAccessingSecurityScopedResource()
    defer {
      if scoped {
        received.file.stopAccessingSecurityScopedResource()
      }
    }
    try FileManager.default.copyItem(at: received.file, to: file)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    #if os(iOS)
      try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete], ofItemAtPath: file.path)
    #endif
    if Task.isCancelled {
      throw VaultError.cancelled
    }
    accepted = true
    return PickedPhotoFile(file: file, directory: directory)
  }

}

/// 系统资源的内容角色与原名，用于确认组合资产没有遗漏任何配套资源。
private struct PhotoResourceIdentity: Codable, Hashable, Sendable {
  let resourceType: Int
  let resourceName: String
  let resourceUTI: String

  /// 业务作用：捕获系统资源的稳定描述，不持久化相册资产身份。
  /// 参数说明：
  /// - `resource`：当前资产包含的一个完整资源。
  /// 返回：用于导入清单与删源复验的资源描述。
  init(_ resource: PHAssetResource) {
    resourceType = resource.type.rawValue
    if #available(iOS 27, macOS 27, *) {
      resourceName = resource.filename ?? ""
    } else {
      resourceName = resource.originalFilename
    }
    resourceUTI = resource.uniformTypeIdentifier
  }
}

/// 完整资源与保险箱密文之间的对应关系，仅保留在当前会话。
private struct SavedPhotoResource: Sendable {
  let identity: PhotoResourceIdentity
  let media: VaultMedia
}

/// 仅在本次导入会话内保留的相册来源证据，不记录查看行为。
struct SavedPhotoImport: Sendable {
  let media: VaultMedia
  let assetIdentifier: String?
  let modificationDate: Date?
  fileprivate let resources: [SavedPhotoResource]
  fileprivate let auxiliary: [VaultMedia]
  let retentionReason: String?

  /// 业务作用：按实际资源计算组合资产的导入字节数，避免把文件夹的零载荷当作内容大小。
  /// 参数说明：无。
  /// 返回：组合资产的全部资源字节数；选择器副本使用自身大小。
  var byteCount: UInt64 {
    resources.isEmpty ? media.byteCount : resources.reduce(0) { $0 + $1.media.byteCount }
  }
}

/// 批量删源逐项核对后的结果，未删除项目始终保留明确原因。
struct PhotoSourceRemovalResult: Sendable {
  let removed: Int
  let retained: [String]
}

/// 将 PhotoKit 事务构造阶段的拒绝原因传递给完成回调。
private final class PhotoChangeOutcome: @unchecked Sendable {
  private let mutex = NSLock()
  private var failure: Error?
  private var identifier: String?

  /// 业务作用：记录本次 PhotoKit 事务对应的新资产或授权失败，不持久化到应用目录。
  /// 参数说明：
  /// - `identifier`：新建资产的系统身份，删除事务为空。
  /// - `failure`：构造事务前失权或其它明确拒绝原因。
  /// 返回：内存中的事务状态更新完成。
  func record(identifier: String? = nil, failure: Error? = nil) {
    mutex.lock()
    self.identifier = identifier
    self.failure = failure
    mutex.unlock()
  }

  /// 业务作用：在异步完成回调中复验事务是否实际取得授权。
  /// 参数说明：无。
  /// 返回：本次事务的新资产身份与构造阶段错误。
  func result() -> (String?, Error?) {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    return (identifier, failure)
  }
}

/// 将系统分批交付的原始资源直接写入私有暂存，不把整个视频装入内存。
private final class PhotoResourceSink: @unchecked Sendable {
  private let mutex = NSLock()
  private let output: FileHandle
  private var failure: Error?

  /// 业务作用：为当前资源请求创建排他的私有输出文件。
  /// 参数说明：
  /// - `destination`：本次来源读取独占的暂存路径。
  /// 返回：可流式接收系统原始字节的写入端；创建失败时不发起系统读取。
  init(destination: URL) throws {
    output = try VaultStorage.create(destination)
  }

  /// 业务作用：立即消费系统回调中的字节，避免依赖回调结束后的数据生命周期。
  /// 参数说明：
  /// - `data`：系统当前交付的连续资源片段。
  /// 返回：片段写入完成，写入错误保留到请求结束统一交付，不继续写入后续片段。
  func append(_ data: Data) {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    guard failure == nil else {
      return
    }
    do {
      try output.write(contentsOf: data)
    } catch {
      failure = error
    }
  }

  /// 业务作用：仅在系统完整交付后同步并关闭来源暂存，拒绝把部分资源视为成功。
  /// 参数说明：无。
  /// 返回：所有片段已经同步时成功；任一写入失败时抛出错误并关闭文件。
  func finish() throws {
    mutex.lock()
    defer {
      try? output.close()
      mutex.unlock()
    }
    if let failure {
      throw failure
    }
    try output.synchronize()
  }
}

/// 本地照片资源导入、删源与导出，所有资源请求明确禁止网络下载。
final class PhotoVaultService: @unchecked Sendable {
  private let library: VaultLibrary
  private let incoming: URL

  /// 业务作用：建立仅用于导入或明确导出的私有暂存区，并清理上次中断的自有暂存。
  /// 参数说明：
  /// - `store`：已独占目录的保险箱。
  /// - `library`：处理认证加密文件的业务入口。
  /// 返回：不申请相册权限、不读取相册内容的适配器。
  init(store: VaultStore, library: VaultLibrary) throws {
    self.library = library
    incoming = store.directory.appendingPathComponent("incoming.noindex", isDirectory: true)
    try VaultStorage.directory(incoming)
    // 保险箱目录已经独占；只清理本适配器分配的 UUID 暂存，避免把外来目录视为未完成导入。
    for entry in try FileManager.default.contentsOfDirectory(
      at: incoming, includingPropertiesForKeys: nil)
    where UUID(uuidString: entry.lastPathComponent) != nil {
      try FileManager.default.removeItem(at: entry)
    }
  }

  /// 业务作用：Mac 明确选择照片后为完整原件导入申请尚未决定的系统权限，避免依赖不可用的文件交付表示。
  /// 参数说明：无。
  /// 返回：系统已有选择时不重复询问；拒绝后仍可尝试选择器已经授权的文件副本。
  func prepareImportAccess() async {
    if PHPhotoLibrary.authorizationStatus(for: .readWrite) == .notDetermined {
      _ = await PHPhotoLibrary.requestAuthorization(for: .readWrite)
    }
  }

  /// 业务作用：有相册权限时保存所选资产的全部原始资源，否则仅保存系统选择器交付的副本。
  /// 参数说明：
  /// - `file`：没有原资产访问权时使用的选择器副本，已复制到本次私有暂存。
  /// - `identifier`：所选系统资产身份，有权限时据此读取完整资源并在删源前复验。
  /// - `parentID`：当前已授权的接收目录；为空时保存到保险箱根目录。
  /// - `grant`：当前独立密码会话。
  /// - `progress`：所选文件的加密阶段，仅在当前内存中交付。
  /// 返回：完整资源读取失败时仍保存选择器已交付的文件；删源需要另行取得权限并补齐全部资源。
  func savePickedFile(
    _ file: URL, identifier: String?, in parentID: UUID? = nil, using grant: VaultGrant,
    progress: @escaping @Sendable (ImportProgress) -> Void = { _ in }
  ) async throws -> SavedPhotoImport {
    let accessible = try await saveAccessibleAsset(
      identifier: identifier, in: parentID, using: grant, progress: progress)
    if let saved = accessible.saved {
      return saved
    }
    return try saveDeliveredFile(
      file, identifier: identifier, reason: accessible.reason, in: parentID,
      using: grant, progress: progress)
  }

  /// 业务作用：直接读取已授权原件，只有原件不可读时才要求选择器交付文件，避免交付失败阻断可用资源。
  /// 参数说明：
  /// - `identifier`：本次明确选择的相册身份。
  /// - `parentID`：当前已授权的接收目录。
  /// - `grant`：当前独立密码会话。
  /// - `receive`：仅在确实需要时调用的系统选择器交付操作。
  /// - `progress`：当前保存阶段的有界进度。
  /// 返回：正常照片或完整照片条目；两种读取均失败时保留原件不可读的具体原因，不以选择器错误覆盖。
  func saveSelection(
    identifier: String?, in parentID: UUID?, using grant: VaultGrant,
    receive: @Sendable () async throws -> PickedPhotoFile,
    progress: @escaping @Sendable (ImportProgress) -> Void
  ) async throws -> SavedPhotoImport {
    let accessible = try await saveAccessibleAsset(
      identifier: identifier, in: parentID, using: grant, progress: progress)
    if let saved = accessible.saved {
      return saved
    }
    var sourceFailure = accessible.failure
    let picked: PickedPhotoFile
    do {
      picked = try await receive()
    } catch {
      try grant.check()
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      #if os(macOS)
        if identifier != nil {
          // Mac 的选择器文件表示不可用时，按这次明确选择申请原件访问，拒绝授权仍保留全部来源。
          try await authorize()
          try grant.check()
          let original = try await saveAccessibleAsset(
            identifier: identifier, in: parentID, using: grant, progress: progress)
          if let saved = original.saved {
            return saved
          }
          sourceFailure = original.failure ?? sourceFailure
        }
      #endif
      // 原件与选择器副本均不可读时，原片缺失等原因才能说明后续动作，通用交付错误不能覆盖它。
      if let sourceFailure {
        throw sourceFailure
      }
      if let error = error as? VaultError {
        throw error
      }
      throw VaultError.photoSelectionDelivery((error as NSError).code)
    }
    defer {
      try? FileManager.default.removeItem(at: picked.directory)
    }
    return try saveDeliveredFile(
      picked.file, identifier: identifier, reason: accessible.reason, in: parentID,
      using: grant, progress: progress)
  }

  /// 业务作用：读取本次选择已经授权的完整资源，不把选择器交付作为原件读取的前置条件。
  /// 参数说明：
  /// - `identifier`：系统选择器提供的资产身份。
  /// - `parentID`：当前接收目录。
  /// - `grant`：当前会话。
  /// - `progress`：完整资源加密进度。
  /// 返回：完整资源可读时返回保存结果，否则保留原因及对应错误；存储及失权错误仍拒绝。
  private func saveAccessibleAsset(
    identifier: String?, in parentID: UUID?, using grant: VaultGrant,
    progress: @escaping @Sendable (ImportProgress) -> Void
  ) async throws -> (saved: SavedPhotoImport?, reason: String?, failure: VaultError?) {
    try grant.check()
    let status = PHPhotoLibrary.authorizationStatus(for: .readWrite)
    if let identifier, status == .authorized || status == .limited,
      let original = try? asset(identifier)
    {
      do {
        return (
          try await saveAsset(original, in: parentID, using: grant, progress: progress), nil, nil
        )
      } catch {
        try grant.check()
        if Task.isCancelled {
          throw VaultError.cancelled
        }
        switch error {
        case VaultError.photoAccess, VaultError.photoResource, VaultError.photoLocalResource,
          VaultError.cloudOnly,
          VaultError.photoResourceUnavailable, VaultError.photoResourcePending,
          VaultError.incompletePhotoBundle, VaultError.sourceChanged:
          // 完整资源暂不可读不应丢弃选择器已交付的内容；这份副本不会直接获得整项删源能力。
          return (nil, Self.removalReason(error), error as? VaultError)
        default:
          throw error
        }
      }
    }
    return (nil, nil, nil)
  }

  /// 业务作用：只保存系统已经交付的文件，保留之后补齐原件的可能性，不把交付副本直接作为删源证据。
  /// 参数说明：
  /// - `file`：本次私有暂存中的选择器文件。
  /// - `identifier`：可选的相册来源身份。
  /// - `reason`：完整原件暂时不可读的说明。
  /// - `parentID`：当前接收目录。
  /// - `grant`：当前会话。
  /// - `progress`：本次副本保存的进度。
  /// 返回：完整加密的副本收据；失权、文件变化或存储失败时不发放收据。
  private func saveDeliveredFile(
    _ file: URL, identifier: String?, reason: String?, in parentID: UUID?, using grant: VaultGrant,
    progress: @escaping @Sendable (ImportProgress) -> Void
  ) throws -> SavedPhotoImport {
    let saved = try library.save(
      source: file, in: parentID, using: grant, status: progress)
    return SavedPhotoImport(
      media: saved.media, assetIdentifier: identifier, modificationDate: nil,
      resources: [], auxiliary: [],
      retentionReason: reason
        ?? (identifier == nil
          ? "系统选择器未提供相册身份，无法确认对应原件。"
          : "目前保存了选择器副本；删除原件时需要申请相册权限，并补齐、复验完整资源。"))
  }

  /// 业务作用：将明确选择的相册资产及所有配套资源加密保存，完成后发放删源证据。
  /// 参数说明：
  /// - `identifier`：系统照片选择器返回的资产身份。
  /// - `grant`：当前独立密码会话。
  /// 返回：完整保存和验证后的收据；云端资源无法离线读取或失权时保留原件。
  func save(identifier: String, using grant: VaultGrant) async throws -> SavedPhotoImport {
    try await authorize()
    try grant.check()
    return try await saveAsset(try asset(identifier), in: nil, using: grant, progress: { _ in })
  }

  /// 业务作用：完整保存实况、RAW 与编辑资源，向相册提供单个正常照片或视频条目。
  /// 参数说明：
  /// - `original`：本次明确选择且可访问的系统资产。
  /// - `parentID`：当前已授权的导入目录。
  /// - `grant`：当前独立密码会话。
  /// - `progress`：完整资源加密保存时的进度。
  /// 返回：全部资源、资源清单及密文均完整时发放收据；部分保存或资源变化时不允许删源。
  private func saveAsset(
    _ original: PHAsset, in parentID: UUID?, using grant: VaultGrant,
    progress: @escaping @Sendable (ImportProgress) -> Void
  ) async throws -> SavedPhotoImport {
    let resources = try assetResources(original)
    let identities = resources.map(PhotoResourceIdentity.init)
    let modified = original.modificationDate
    let stage = try stagingDirectory()
    defer {
      try? FileManager.default.removeItem(at: stage)
    }
    let media: VaultMedia
    let savedResources: [SavedPhotoResource]
    let auxiliary: [VaultMedia]
    if resources.count == 1, let resource = resources.first,
      resource.type == .photo || resource.type == .video
    {
      let source = try sourceURL(resourceFilename(identities[0], index: 0), directory: stage)
      try await write(original, resource: resource, to: source)
      try validateAsset(original.localIdentifier, modified: modified, resources: identities)
      let saved = try library.save(source: source, in: parentID, using: grant, status: progress)
      media = saved.media
      savedResources = [SavedPhotoResource(identity: identities[0], media: media)]
      auxiliary = []
    } else {
      let primary =
        identities.first(where: {
          $0.resourceType == PHAssetResourceType.photo.rawValue
            || $0.resourceType == PHAssetResourceType.video.rawValue
        }) ?? identities[0]
      let primaryName = resourceFilename(primary, index: 0)
      let stem = URL(fileURLWithPath: primaryName).deletingPathExtension().lastPathComponent
      let suffix = original.mediaSubtypes.contains(.photoLive) ? "实况照片" : "完整照片资源"
      let bundle = try sourceURL("\(stem)（\(suffix)）", directory: stage)
      try VaultStorage.directory(bundle)
      var paths: [URL] = []
      var manifest: [[String: Any]] = []
      for (index, resource) in resources.enumerated() {
        try grant.check()
        if Task.isCancelled {
          throw VaultError.cancelled
        }
        let directory = bundle.appendingPathComponent(
          "\(index + 1)-\(resourceName(resource.type))")
        try VaultStorage.directory(directory)
        let name = resourceFilename(identities[index], index: index)
        let file = try sourceURL(name, directory: directory)
        // 组合资产逐项使用原始资源接口，不能把某个资源替换为当前渲染图而仍声称完整。
        try await write(original, resource: resource, to: file)
        paths.append(file)
        manifest.append([
          "resourceType": resource.type.rawValue,
          "originalFilename": identities[index].resourceName,
          "uniformTypeIdentifier": resource.uniformTypeIdentifier,
          "path": directory.lastPathComponent + "/" + name,
        ])
      }
      let manifestURL = bundle.appendingPathComponent("资源清单.json")
      let output = try VaultStorage.create(manifestURL)
      do {
        try output.write(
          contentsOf: JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys]))
        try output.synchronize()
        try output.close()
      } catch {
        try? output.close()
        throw error
      }
      try validateAsset(original.localIdentifier, modified: modified, resources: identities)
      let saved = try library.saveFolder(
        source: bundle, in: parentID, using: grant, status: progress)
      guard saved.failures == 0, saved.saved.count == resources.count + 1 else {
        throw VaultError.incompletePhotoBundle
      }
      let files = Dictionary(
        uniqueKeysWithValues: saved.saved.map {
          ($0.source.standardizedFileURL.resolvingSymlinksInPath().path, $0.media)
        })
      savedResources = try zip(identities, paths).map { identity, path in
        guard let resource = files[path.standardizedFileURL.resolvingSymlinksInPath().path] else {
          throw VaultError.incompletePhotoBundle
        }
        return SavedPhotoResource(identity: identity, media: resource)
      }
      guard let list = files[manifestURL.standardizedFileURL.resolvingSymlinksInPath().path] else {
        throw VaultError.incompletePhotoBundle
      }
      media = try library.completePhotoAsset(id: saved.folder.id, using: grant)
      auxiliary = [list]
    }
    try validateAsset(original.localIdentifier, modified: modified, resources: identities)
    // 全部明文暂存已清理后才发放删源证据；不能因某个配套文件遗漏而删除整项系统资产。
    try FileManager.default.removeItem(at: stage)
    return SavedPhotoImport(
      media: media, assetIdentifier: original.localIdentifier, modificationDate: modified,
      resources: savedResources, auxiliary: auxiliary, retentionReason: nil)
  }

  /// 业务作用：逐项复验本批全部资源，再用同一个系统事务删除可确认完整保存的资产。
  /// 参数说明：
  /// - `receipts`：用户刚确认删除来源的全部保存结果，包含无法删除的项目。
  /// - `grant`：仍有效的独立密码会话。
  /// 返回：系统实际移除数量及每项保留原因；一次批量确认，不把跳过项目计作成功。
  func removeSources(
    _ receipts: [SavedPhotoImport], using grant: VaultGrant
  ) async throws -> PhotoSourceRemovalResult {
    try grant.check()
    var retained: [String] = []
    var candidates: [SavedPhotoImport] = []
    for receipt in receipts {
      if receipt.assetIdentifier != nil {
        candidates.append(receipt)
      } else {
        retained.append("\(receipt.media.originalFilename)：系统未提供相册身份，无法确认对应原件。")
      }
    }
    guard !candidates.isEmpty else {
      return PhotoSourceRemovalResult(removed: 0, retained: retained)
    }
    do {
      // 选择器交付与 PhotoKit 删源是两项权限；必须先请求本次操作权限，再复验待补齐的副本。
      try await authorize()
      try grant.check()
    } catch {
      retained += candidates.map { "\($0.media.originalFilename)：\(Self.removalReason(error))" }
      return PhotoSourceRemovalResult(removed: 0, retained: retained)
    }
    var verified: [SavedPhotoImport] = []
    for receipt in candidates {
      do {
        let complete = try await completeSource(receipt, using: grant)
        try await verifySource(complete, using: grant)
        verified.append(complete)
      } catch {
        try grant.check()
        if Task.isCancelled {
          throw VaultError.cancelled
        }
        retained.append("\(receipt.media.originalFilename)：\(Self.removalReason(error))")
      }
    }
    guard !verified.isEmpty else {
      return PhotoSourceRemovalResult(removed: 0, retained: retained)
    }
    let confirmed = verified
    do {
      _ = try await commit {
        // 在唯一系统事务中复验整批来源身份并取得当前授权，提示出现后不再逐张启动新事务。
        try grant.access { _ in
          let assets = try confirmed.map { receipt in
            try self.validateSource(receipt)
          }
          PHAssetChangeRequest.deleteAssets(assets as NSArray)
        }
        return nil
      }
    } catch {
      retained += confirmed.map { "\($0.media.originalFilename)：\(Self.removalReason(error))" }
      return PhotoSourceRemovalResult(removed: 0, retained: retained)
    }
    var removed = 0
    // 系统确认后只核对已提交资产的可见身份，不再读取保险箱或请求新的删除权限。
    for receipt in confirmed {
      if let identifier = receipt.assetIdentifier,
        PHAsset.fetchAssets(withLocalIdentifiers: [identifier], options: nil).firstObject != nil
      {
        retained.append("\(receipt.media.originalFilename)：系统确认后原件仍可访问，请检查相册后重试。")
      } else {
        removed += 1
      }
    }
    return PhotoSourceRemovalResult(removed: removed, retained: retained)
  }

  /// 业务作用：用户选择删源后，为选择器副本补齐相册访问和完整资源证据，不永久沿用导入时的权限状态。
  /// 参数说明：
  /// - `receipt`：本次保存结果，可以是尚未具备完整资源证据的选择器副本。
  /// - `grant`：当前仍有效且拥有接收目录访问权的会话。
  /// 返回：已有完整收据时直接复验；单资源摘要匹配时复用副本，多资源完整保存后才能继续删源。
  private func completeSource(
    _ receipt: SavedPhotoImport, using grant: VaultGrant
  ) async throws -> SavedPhotoImport {
    guard receipt.resources.isEmpty else {
      return receipt
    }
    let reader = try library.reader(id: receipt.media.id, using: grant)
    guard reader.media == receipt.media, let identifier = receipt.assetIdentifier else {
      throw VaultError.sourceChanged
    }
    try reader.verify()
    let original = try asset(identifier)
    let resources = try assetResources(original)
    if resources.count == 1, let resource = resources.first,
      resource.type == .photo || resource.type == .video
    {
      let modified = original.modificationDate
      let stage = try stagingDirectory()
      defer {
        try? FileManager.default.removeItem(at: stage)
      }
      let file = stage.appendingPathComponent("original")
      try await write(original, resource: resource, to: file)
      let matchesCopy = try digest(file, using: grant) == receipt.media.sha256
      try validateAsset(
        identifier, modified: modified, resources: resources.map(PhotoResourceIdentity.init))
      try FileManager.default.removeItem(at: stage)
      if !matchesCopy {
        // 选择器允许交付不同编码；保留已导入的表示，再完整保存真正原片，不能把转码副本直接当作原片删源。
        return try await saveAsset(
          original, in: receipt.media.parentID, using: grant, progress: { _ in })
      }
      return SavedPhotoImport(
        media: receipt.media, assetIdentifier: identifier, modificationDate: modified,
        resources: [
          SavedPhotoResource(identity: PhotoResourceIdentity(resource), media: receipt.media)
        ],
        auxiliary: [], retentionReason: nil)
    }
    // 多资源资产不能凭一张静态图删源；先把当前全部原始资源另存为完整文件夹，再发放本次证据。
    return try await saveAsset(
      original, in: receipt.media.parentID, using: grant, progress: { _ in })
  }

  /// 业务作用：对单个资产的全部来源字节、密文和资源清单进行删源前的完整核对。
  /// 参数说明：
  /// - `receipt`：本次完整保存的资产及配套资源。
  /// - `grant`：仍有效的当前会话。
  /// 返回：完整匹配时成功；遗漏、变更、损坏或无法删除时保留整个相册资产。
  private func verifySource(_ receipt: SavedPhotoImport, using grant: VaultGrant) async throws {
    let original = try validateSource(receipt)
    guard original.canPerform(.delete) else {
      throw VaultError.sourceRemoval
    }
    for media in [receipt.media] + receipt.auxiliary {
      let reader = try library.reader(id: media.id, using: grant)
      guard reader.media == media else {
        throw VaultError.sourceChanged
      }
      try reader.verify()
    }
    let stage = try stagingDirectory()
    defer {
      try? FileManager.default.removeItem(at: stage)
    }
    var resources = try assetResources(original)
    for (index, saved) in receipt.resources.enumerated() {
      let reader = try library.reader(id: saved.media.id, using: grant)
      guard reader.media == saved.media else {
        throw VaultError.sourceChanged
      }
      try reader.verify()
      var match: Int?
      for (candidate, resource) in resources.enumerated()
      where PhotoResourceIdentity(resource) == saved.identity {
        let source = stage.appendingPathComponent("\(index)-\(candidate)")
        try await write(original, resource: resource, to: source)
        let matches = try digest(source, using: grant) == saved.media.sha256
        try FileManager.default.removeItem(at: source)
        if matches {
          match = candidate
          break
        }
      }
      guard let match else {
        throw VaultError.sourceChanged
      }
      // 同名同类型的附加资源也必须逐份匹配并消费，不能重复使用某个资源的摘要来掩盖遗漏。
      resources.remove(at: match)
    }
    guard resources.isEmpty else {
      throw VaultError.sourceChanged
    }
    _ = try validateSource(receipt)
    try FileManager.default.removeItem(at: stage)
  }

  /// 业务作用：复验资产修改时间和完整资源集合，不把单张静态图当作实况资产的全部内容。
  /// 参数说明：
  /// - `receipt`：当前待删除资产的完整保存证据。
  /// 返回：当前未变化的系统资产；证据缺失或任一资源变化时拒绝。
  private func validateSource(_ receipt: SavedPhotoImport) throws -> PHAsset {
    guard let identifier = receipt.assetIdentifier, !receipt.resources.isEmpty else {
      throw VaultError.sourceChanged
    }
    return try validateAsset(
      identifier, modified: receipt.modificationDate, resources: receipt.resources.map(\.identity))
  }

  /// 业务作用：在保存完成和删除提交的边界重新取得当前资产，拒绝使用过期系统对象。
  /// 参数说明：
  /// - `identifier`：用户本次选择的系统身份。
  /// - `modified`：导入开始时的修改时间。
  /// - `resources`：已完整保存的资源描述。
  /// 返回：修改时间及资源集合均一致时返回当前资产，否则保留原件。
  @discardableResult
  private func validateAsset(
    _ identifier: String, modified: Date?, resources: [PhotoResourceIdentity]
  ) throws -> PHAsset {
    let current = try asset(identifier)
    let identities = try assetResources(current).map(PhotoResourceIdentity.init)
    guard current.modificationDate == modified, identities.count == resources.count,
      Dictionary(grouping: identities, by: { $0 }).mapValues(\.count)
        == Dictionary(grouping: resources, by: { $0 }).mapValues(\.count)
    else {
      throw VaultError.sourceChanged
    }
    return current
  }

  /// 业务作用：取得资产声明的全部资源，包含当前 SDK 尚未命名的附加原始数据。
  /// 参数说明：
  /// - `asset`：明确选择的图片或视频资产。
  /// 返回：完整的非空资源集合；仍在处理的代理原片不允许删源，未知角色按原始字节保存。
  private func assetResources(_ asset: PHAsset) throws -> [PHAssetResource] {
    let resources = PHAssetResource.assetResources(for: asset)
    // 未完成处理的代理图不等于原片；其它未知角色完整保留，不以 SDK 的命名范围缩减资产内容。
    if resources.contains(where: { $0.type.rawValue == 19 }) {
      throw VaultError.photoResourcePending
    }
    guard asset.mediaType == .image || asset.mediaType == .video,
      !resources.isEmpty
    else {
      throw VaultError.photoResource
    }
    return resources
  }

  /// 业务作用：为没有系统文件名的附加资源分配安全存储名称，原始空名称仍保留在资源清单中。
  /// 参数说明：
  /// - `identity`：系统原始资源描述。
  /// - `index`：当前资产内的资源序号，用于区分同名附加资源。
  /// 返回：可以作为单层文件名的原名或生成名称，不把缺少文件名视为缺少资源。
  private func resourceFilename(_ identity: PhotoResourceIdentity, index: Int) -> String {
    let name = identity.resourceName
    if !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0") {
      return name
    }
    return "资源-\(identity.resourceType)-\(index + 1).data"
  }

  /// 业务作用：在完整资源文件夹中区分原始、实况和编辑内容，保留子文件的原始名称。
  /// 参数说明：
  /// - `type`：系统定义的资源角色。
  /// 返回：用于资源子目录的可读名称；未知角色以原数值标注附加资源，不改变资源内容。
  private func resourceName(_ type: PHAssetResourceType) -> String {
    switch type {
    case .photo:
      return "原始照片"
    case .video:
      return "原始视频"
    case .audio:
      return "音频"
    case .alternatePhoto:
      return "备选照片"
    case .fullSizePhoto:
      return "编辑后照片"
    case .fullSizeVideo:
      return "编辑后视频"
    case .adjustmentData:
      return "编辑数据"
    case .adjustmentBasePhoto:
      return "编辑基准照片"
    case .pairedVideo:
      return "实况视频"
    case .fullSizePairedVideo:
      return "编辑后实况视频"
    case .adjustmentBasePairedVideo:
      return "编辑基准实况视频"
    case .adjustmentBaseVideo:
      return "编辑基准视频"
    default:
      return "附加资源 \(type.rawValue)"
    }
  }

  /// 业务作用：把删源失败转换为不泄露系统资源路径的逐项说明。
  /// 参数说明：
  /// - `error`：复验或系统事务拒绝原因。
  /// 返回：适合与文件名一起展示的保留原因。
  private static func removalReason(_ error: Error) -> String {
    (error as? VaultError)?.errorDescription ?? "系统拒绝或取消了删除，原件未确认移除。"
  }

  /// 业务作用：用户明确确认后按原名解密保存到系统照片，并复验新资产的完整内容。
  /// 参数说明：
  /// - `media`：已解锁列表中的媒体。
  /// - `grant`：当前独立密码会话。
  /// 返回：新相册资产已按原名完整保存；提交后无法复验时明确提示系统中可能已有副本。
  func export(_ media: VaultMedia, using grant: VaultGrant) async throws {
    let primary = try library.presentationReader(id: media.id, using: grant).media
    let presented = VaultMedia(
      id: media.id, originalFilename: media.originalFilename, contentType: primary.contentType,
      byteCount: primary.byteCount, sha256: primary.sha256, parentID: media.parentID)
    try await saveToPhotos(presented, using: grant) { stage in
      try self.library.exportPresentation(id: media.id, to: stage, using: grant)
    }
  }

  /// 业务作用：把已为本次操作重新验证目录密码的图片或视频复制到系统照片，保留密文。
  /// 参数说明：
  /// - `media`：本次选中且与复制事务身份一致的图片或视频。
  /// - `session`：所有相关目录密码均已经重新验证的单次复制事务。
  /// - `grant`：创建该复制事务的同一 App 会话。
  /// 返回：系统新资产完整复验后成功；错配、失权或保存不明时不删除保险箱原件。
  func copy(
    _ media: VaultMedia, session: VaultCopySession, using grant: VaultGrant
  ) async throws {
    guard session.mediaID == media.id, media.isImage || media.isVideo else {
      throw VaultError.unsupportedMedia
    }
    // 申请系统权限前也要复验完整目录证明，不能让调用方绕过模型直接跳过密码步骤。
    if let missing = try library.nextCopyFolder(session, using: grant) {
      throw VaultError.folderPasswordRequired(missing.id)
    }
    let presented: VaultMedia
    if let asset = media.photoAsset {
      presented = VaultMedia(
        id: media.id, originalFilename: media.originalFilename, contentType: asset.contentType,
        byteCount: asset.byteCount, sha256: asset.sha256, parentID: media.parentID)
    } else {
      presented = media
    }
    try await saveToPhotos(presented, using: grant) { stage in
      try self.library.copyToSystem(session, to: stage, using: grant, presentationOnly: true)
    }
  }

  /// 业务作用：让两种系统照片入口共用事务提交、原名和完整摘要复验，不改变各自的目录门禁。
  /// 参数说明：
  /// - `media`：本次明确保存的图片或视频。
  /// - `grant`：当前 App 会话，系统提交前仍需有效。
  /// - `source`：各入口完成独立权限检查后向私有暂存交付完整明文的操作。
  /// 返回：系统新资产完整保存且复验后成功；失败清理私有暂存并明确保留原件。
  private func saveToPhotos(
    _ media: VaultMedia, using grant: VaultGrant, source: @Sendable (URL) throws -> URL
  ) async throws {
    try await authorize()
    try grant.check()
    let stage = try stagingDirectory()
    defer {
      try? FileManager.default.removeItem(at: stage)
    }
    let file = try source(stage)
    let identifier = try await commit {
      try grant.access { _ in
        let request = PHAssetCreationRequest.forAsset()
        let options = PHAssetResourceCreationOptions()
        options.originalFilename = media.originalFilename
        options.uniformTypeIdentifier = media.contentType
        options.shouldMoveFile = false
        request.addResource(
          with: media.isVideo ? .video : .photo, fileURL: file, options: options)
        return request.placeholderForCreatedAsset?.localIdentifier
      }
    }
    do {
      try grant.check()
      guard let identifier else {
        throw VaultError.storage
      }
      let exportedAsset = try asset(identifier)
      let resource = try singleResource(exportedAsset)
      guard resource.originalFilename == media.originalFilename else {
        throw VaultError.storage
      }
      let verification = stage.appendingPathComponent("verification", isDirectory: true)
      try VaultStorage.directory(verification)
      let copy = try sourceURL(media.originalFilename, directory: verification)
      try await write(exportedAsset, resource: resource, to: copy)
      guard try digest(copy, using: grant) == media.sha256 else {
        throw VaultError.corrupt
      }
      try FileManager.default.removeItem(at: stage)
    } catch {
      // 系统事务已经完成，复验失败不能声称没有导出，也不能擅自删除用户已确认创建的副本。
      throw VaultError.systemExportUncertain
    }
  }

  /// 业务作用：只在用户主动操作照片时申请必要权限，拒绝时不尝试其它系统验证入口。
  /// 参数说明：无。
  /// 返回：拥有完整或有限资产访问权限；其它状态保持保险箱数据不变。
  private func authorize() async throws {
    let status = await PHPhotoLibrary.requestAuthorization(for: .readWrite)
    guard status == .authorized || status == .limited else {
      throw VaultError.photoAccess
    }
  }

  /// 业务作用：按明确选择的系统身份取得当前可访问资产，不枚举用户整个相册。
  /// 参数说明：
  /// - `identifier`：当前导入或导出涉及的系统资产身份。
  /// 返回：可访问资产；缺失或已撤销权限时拒绝。
  private func asset(_ identifier: String) throws -> PHAsset {
    guard
      let asset = PHAsset.fetchAssets(withLocalIdentifiers: [identifier], options: nil).firstObject
    else {
      throw VaultError.photoAccess
    }
    return asset
  }

  /// 业务作用：复验写回系统照片的新资产仍是单资源，拒绝把系统生成的组合内容视为同一个导出文件。
  /// 参数说明：
  /// - `asset`：当前选择的系统资产。
  /// 返回：唯一原始照片或视频资源；Live Photo、RAW 组合和编辑资源组合明确拒绝。
  private func singleResource(_ asset: PHAsset) throws -> PHAssetResource {
    let resources = PHAssetResource.assetResources(for: asset)
    guard resources.count == 1, let resource = resources.first,
      resource.type == .photo || resource.type == .video
    else {
      throw VaultError.compositePhoto
    }
    return resource
  }

  /// 业务作用：分配由本适配器独占的私有暂存目录。
  /// 参数说明：无。
  /// 返回：权限收紧、名称为随机 UUID 的新目录。
  private func stagingDirectory() throws -> URL {
    let directory = incoming.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try VaultStorage.directory(directory)
    return directory
  }

  /// 业务作用：保留原名同时限制来源资源只能落在当前暂存目录内。
  /// 参数说明：
  /// - `name`：系统提供的原始文件名。
  /// - `directory`：当前暂存目录。
  /// 返回：没有路径穿越的原名位置；异常名称拒绝。
  private func sourceURL(_ name: String, directory: URL) throws -> URL {
    guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0") else {
      throw VaultError.unsupportedMedia
    }
    return directory.appendingPathComponent(name)
  }

  /// 业务作用：读取指定角色的原始资源，必要时复用系统原片或实况交付入口，不自动下载。
  /// 参数说明：
  /// - `asset`：用户明确选择、已经取得权限的资产。
  /// - `resource`：保留原始文件名与资源身份的系统描述。
  /// - `destination`：当前私有暂存中的新路径。
  /// 返回：本地原始字节已完整写入并收紧权限；系统不能离线交付时明确拒绝，不断言用户没有下载。
  private func write(_ asset: PHAsset, resource: PHAssetResource, to destination: URL) async throws
  {
    do {
      try await writeResource(resource, to: destination)
    } catch {
      let resourceFailure = error
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      // 资源请求可能留下部分文件，只移除本次独占暂存中的目标后再尝试系统本地原件入口。
      if FileManager.default.fileExists(atPath: destination.path) {
        try FileManager.default.removeItem(at: destination)
      }
      do {
        if asset.mediaType == .video, resource.type == .video {
          let local = try await localVideo(asset, version: .original)
          let scoped = local.url.startAccessingSecurityScopedResource()
          defer {
            if scoped {
              local.url.stopAccessingSecurityScopedResource()
            }
          }
          let source = try FileHandle(forReadingFrom: local.url)
          defer {
            try? source.close()
          }
          let identity = try SourceIdentity(source)
          guard identity.size > 0 else {
            throw VaultError.photoLocalResource
          }
          // original 版本与禁止网络选项共同约束来源；保留 AVURLAsset 生命周期以维持本地文件授权。
          try withExtendedLifetime(local) {
            try FileManager.default.copyItem(at: local.url, to: destination)
          }
          guard try SourceIdentity(source) == identity else {
            throw VaultError.sourceChanged
          }
        } else if asset.mediaType == .image, resource.type == .photo {
          let data = try await localImage(asset, expectedType: resource.uniformTypeIdentifier)
          let output = try VaultStorage.create(destination)
          defer {
            try? output.close()
          }
          try output.write(contentsOf: data)
          try output.synchronize()
        } else if resource.type == .pairedVideo, asset.mediaSubtypes.contains(.photoLive) {
          let live = try await localLivePhoto(asset)
          guard
            let original = PHAssetResource.assetResources(for: live).first(where: {
              PhotoResourceIdentity($0) == PhotoResourceIdentity(resource)
            })
          else {
            throw VaultError.photoLocalResource
          }
          try await writeResource(original, to: destination)
        } else {
          throw resourceFailure
        }
      } catch VaultError.cancelled {
        throw VaultError.cancelled
      } catch {
        throw resourceFailure
      }
    }
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o600], ofItemAtPath: destination.path)
    #if os(iOS)
      try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete], ofItemAtPath: destination.path)
    #endif
  }

  /// 业务作用：要求系统交付已在本机可用的原始视频文件，不接受远程 URL 或导出转码。
  /// 参数说明：
  /// - `asset`：用户明确选择的本地视频资产。
  /// - `version`：需要交付的原始版本；删源证据不接受编辑后的渲染替代品。
  /// 返回：原始版本的本地 AVURLAsset；取消、远程资源或系统无法交付时失败。
  private func localVideo(_ asset: PHAsset, version: PHVideoRequestOptionsVersion) async throws
    -> AVURLAsset
  {
    let options = PHVideoRequestOptions()
    options.version = version
    options.deliveryMode = .highQualityFormat
    options.isNetworkAccessAllowed = false
    return try await withCheckedThrowingContinuation { continuation in
      PHImageManager.default().requestAVAsset(forVideo: asset, options: options) { video, _, info in
        if info?[PHImageCancelledKey] as? Bool == true {
          continuation.resume(throwing: VaultError.cancelled)
        } else if let local = video as? AVURLAsset, local.url.isFileURL {
          continuation.resume(returning: local)
        } else {
          continuation.resume(throwing: VaultError.photoLocalResource)
        }
      }
    }
  }

  /// 业务作用：从系统本地缓存交付原始图片字节，不因缩略图或网络标记而提前判定原件缺失。
  /// 参数说明：
  /// - `asset`：用户明确选择的本地图片资产。
  /// - `expectedType`：当前原始资源声明的类型，防止 RAW 组合中的其它表示替代目标资源。
  /// 返回：原始版本的完整图片数据；取消或本地不可用时失败。
  private func localImage(_ asset: PHAsset, expectedType: String) async throws -> Data {
    let options = PHImageRequestOptions()
    options.version = .original
    options.deliveryMode = .highQualityFormat
    options.isNetworkAccessAllowed = false
    return try await withCheckedThrowingContinuation { continuation in
      PHImageManager.default().requestImageDataAndOrientation(for: asset, options: options) {
        data, type, _, info in
        if info?[PHImageCancelledKey] as? Bool == true {
          continuation.resume(throwing: VaultError.cancelled)
        } else if let data, !data.isEmpty, type == expectedType {
          continuation.resume(returning: data)
        } else {
          continuation.resume(throwing: VaultError.photoLocalResource)
        }
      }
    }
  }

  /// 业务作用：向系统申请本地原始实况对象，为配套视频取得与原资产相同角色的可读资源。
  /// 参数说明：
  /// - `asset`：本次明确选择的实况资产。
  /// 返回：非降质的原始实况对象；本地不可用、取消或交付失败时保留原件。
  private func localLivePhoto(_ asset: PHAsset) async throws -> PHLivePhoto {
    let options = PHLivePhotoRequestOptions()
    options.version = .original
    options.deliveryMode = .highQualityFormat
    options.isNetworkAccessAllowed = false
    return try await withCheckedThrowingContinuation { continuation in
      PHImageManager.default().requestLivePhoto(
        for: asset, targetSize: PHImageManagerMaximumSize, contentMode: .aspectFit, options: options
      ) { live, info in
        if info?[PHImageResultIsDegradedKey] as? Bool == true {
          return
        }
        if info?[PHImageCancelledKey] as? Bool == true {
          continuation.resume(throwing: VaultError.cancelled)
        } else if let live {
          continuation.resume(returning: live)
        } else {
          continuation.resume(throwing: VaultError.photoLocalResource)
        }
      }
    }
  }

  /// 业务作用：通过原始资源接口请求本地字节，禁止网络并向调用方交付明确读取失败。
  /// 参数说明：
  /// - `resource`：资产中当前需要保存的一个原始资源。
  /// - `destination`：当前私有暂存中的新路径。
  /// 返回：本机完整资源可用；失败由调用方精确清理暂存目录。
  private func writeResource(_ resource: PHAssetResource, to destination: URL) async throws {
    let options = PHAssetResourceRequestOptions()
    options.isNetworkAccessAllowed = false
    do {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        PHAssetResourceManager.default().writeData(
          for: resource, toFile: destination, options: options
        ) { error in
          if let error {
            continuation.resume(throwing: error)
          } else {
            continuation.resume()
          }
        }
      }
    } catch {
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      // 系统文件交付与流式交付可能具有不同的本地可用状态；失败后只清理本次独占目标再重试读取。
      if FileManager.default.fileExists(atPath: destination.path) {
        try FileManager.default.removeItem(at: destination)
      }
      try await streamResource(resource, to: destination, options: options)
    }
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o600], ofItemAtPath: destination.path)
    #if os(iOS)
      try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete], ofItemAtPath: destination.path)
    #endif
    let file = try FileHandle(forWritingTo: destination)
    defer {
      try? file.close()
    }
    // 系统回调成功也必须有实际资源字节，空文件不能成为删除整项相册原件的证据。
    guard try file.seekToEnd() > 0 else {
      throw VaultError.photoLocalResource
    }
    try file.synchronize()
  }

  /// 业务作用：系统不能直接交付资源文件时，逐块读取同一原始资源，不以渲染或缩略图替代。
  /// 参数说明：
  /// - `resource`：与直接文件交付相同的资源身份。
  /// - `destination`：清理过失败文件的独占暂存位置。
  /// - `options`：仍然禁止自动下载的同一请求策略。
  /// 返回：完整流式资源已经同步；失败保留资源角色与系统错误码，供结果说明。
  private func streamResource(
    _ resource: PHAssetResource, to destination: URL, options: PHAssetResourceRequestOptions
  ) async throws {
    let sink = try PhotoResourceSink(destination: destination)
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      PHAssetResourceManager.default().requestData(
        for: resource, options: options,
        dataReceivedHandler: { data in
          sink.append(data)
        },
        completionHandler: { error in
          do {
            try sink.finish()
            if let error {
              let failure = error as NSError
              if failure.domain == PHPhotosErrorDomain
                && failure.code == PHPhotosError.networkAccessRequired.rawValue
              {
                throw VaultError.cloudOnly
              }
              throw VaultError.photoResourceUnavailable(
                self.resourceName(resource.type), failure.code)
            }
            continuation.resume()
          } catch {
            continuation.resume(throwing: error)
          }
        })
    }
  }

  /// 业务作用：流式复验系统来源或导出资产的完整字节，不把资源整体读入内存。
  /// 参数说明：
  /// - `source`：本次私有暂存中的资源。
  /// - `grant`：每块读取前必须仍有效的会话。
  /// 返回：完整 SHA-256；失权或取消时拒绝。
  private func digest(_ source: URL, using grant: VaultGrant) throws -> Data {
    let file = try FileHandle(forReadingFrom: source)
    defer {
      try? file.close()
    }
    var hash = SHA256()
    while true {
      try grant.check()
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      let finished = try autoreleasepool {
        let bytes = try file.read(upToCount: VaultMediaReader.chunkSize) ?? Data()
        if bytes.isEmpty {
          return true
        }
        hash.update(data: bytes)
        return false
      }
      if finished {
        break
      }
    }
    return Data(hash.finalize())
  }

  /// 业务作用：把已授权的相册副作用交给系统事务，并保留构造阶段的拒绝原因。
  /// 参数说明：
  /// - `changes`：只构造本次明确授权的创建或删除动作。
  /// 返回：系统完成事务后的新资产身份；失权或系统拒绝时失败。
  private func commit(_ changes: @escaping @Sendable () throws -> String?) async throws -> String? {
    let outcome = PhotoChangeOutcome()
    return try await withCheckedThrowingContinuation { continuation in
      PHPhotoLibrary.shared().performChanges {
        do {
          outcome.record(identifier: try changes())
        } catch {
          outcome.record(failure: error)
        }
      } completionHandler: { success, error in
        let (identifier, failure) = outcome.result()
        if let failure {
          continuation.resume(throwing: failure)
        } else if success {
          continuation.resume(returning: identifier)
        } else {
          continuation.resume(throwing: error ?? VaultError.photoChange)
        }
      }
    }
  }
}
