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

  /// 业务作用：在系统交付所选文件的有效期内复制字节，保留真实名称并限制暂存访问。
  /// 参数说明：无。
  /// 返回：本次选择对应的私有文件；取消或复制失败时清理本次目录，不返回悬空系统临时 URL。
  static var transferRepresentation: some TransferRepresentation {
    FileRepresentation(importedContentType: .data) { received in
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
}

/// 仅在本次导入会话内保留的相册来源证据，不记录查看行为。
struct SavedPhotoImport: Sendable {
  let media: VaultMedia
  let assetIdentifier: String
  let resourceType: Int
  let resourceName: String
  let resourceUTI: String
  let modificationDate: Date?
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

  /// 业务作用：加密保存系统选择器实际交付的文件，不为读取所选内容额外申请整库权限。
  /// 参数说明：
  /// - `file`：系统交付后已经复制到本次私有暂存的文件。
  /// - `identifier`：可选的系统资产身份，只用于原名核对和后续删源复验。
  /// - `grant`：当前独立密码会话。
  /// - `progress`：所选文件的加密阶段，仅在当前内存中交付。
  /// 返回：已完整加密保存的文件与可选删源收据；无法复验的来源不发放删源收据。
  func savePickedFile(
    _ file: URL, identifier: String?, using grant: VaultGrant,
    progress: @escaping @Sendable (ImportProgress) -> Void = { _ in }
  ) throws -> (media: VaultMedia, receipt: SavedPhotoImport?) {
    try grant.check()
    var original: PHAsset?
    var resource: PHAssetResource?
    let status = PHPhotoLibrary.authorizationStatus(for: .readWrite)
    if let identifier, status == .authorized || status == .limited {
      original = try? asset(identifier)
      if let original {
        resource = try? singleResource(original)
      }
    }
    let saved = try library.save(
      source: file, originalName: resource?.originalFilename, using: grant, status: progress)
    guard let identifier, let original, let resource else {
      return (saved.media, nil)
    }
    // 选择器交付成功只授权保存；删除仍须通过原资源身份、修改时间和完整摘要复验。
    let receipt = SavedPhotoImport(
      media: saved.media, assetIdentifier: identifier, resourceType: resource.type.rawValue,
      resourceName: resource.originalFilename, resourceUTI: resource.uniformTypeIdentifier,
      modificationDate: original.modificationDate)
    return (saved.media, receipt)
  }

  /// 业务作用：将用户选择的单资源照片或视频按原名加密保存，成功后发放可选删源证据。
  /// 参数说明：
  /// - `identifier`：系统照片选择器返回的资产身份。
  /// - `grant`：当前独立密码会话。
  /// 返回：完整保存和验证后的收据；组合资产、云端未下载资源或失权时拒绝删源。
  func save(identifier: String, using grant: VaultGrant) async throws -> SavedPhotoImport {
    try await authorize()
    try grant.check()
    let asset = try asset(identifier)
    let resource = try singleResource(asset)
    let stage = try stagingDirectory()
    defer {
      try? FileManager.default.removeItem(at: stage)
    }
    let source = try sourceURL(resource.originalFilename, directory: stage)
    try await write(asset, resource: resource, to: source)
    if Task.isCancelled {
      throw VaultError.cancelled
    }
    try grant.check()
    let receipt = try library.save(source: source, using: grant)
    // 清理被确认成功后才发放删源证据；清理失败时保留原件，由下次启动重试自有暂存清理。
    try FileManager.default.removeItem(at: stage)
    return SavedPhotoImport(
      media: receipt.media, assetIdentifier: identifier, resourceType: resource.type.rawValue,
      resourceName: resource.originalFilename, resourceUTI: resource.uniformTypeIdentifier,
      modificationDate: asset.modificationDate)
  }

  /// 业务作用：只删除本次完整保存且内容未变化的单资源相册资产。
  /// 参数说明：
  /// - `receipt`：当前会话保存成功的相册来源证据。
  /// - `grant`：仍有效的独立密码会话。
  /// 返回：PhotoKit 完成删除后成功；系统可保留最近删除，不能保证物理擦除或备份消失。
  func removeSource(_ receipt: SavedPhotoImport, using grant: VaultGrant) async throws {
    try await authorize()
    try grant.check()
    let original = try asset(receipt.assetIdentifier)
    let resource = try singleResource(original)
    guard resource.type.rawValue == receipt.resourceType,
      resource.originalFilename == receipt.resourceName,
      resource.uniformTypeIdentifier == receipt.resourceUTI,
      original.modificationDate == receipt.modificationDate
    else {
      throw VaultError.sourceChanged
    }
    let stage = try stagingDirectory()
    defer {
      try? FileManager.default.removeItem(at: stage)
    }
    let source = try sourceURL(resource.originalFilename, directory: stage)
    try await write(original, resource: resource, to: source)
    guard try digest(source, using: grant) == receipt.media.sha256,
      try asset(receipt.assetIdentifier).modificationDate == receipt.modificationDate
    else {
      throw VaultError.sourceChanged
    }
    try library.reader(id: receipt.media.id, using: grant).verify()
    _ = try await commit {
      // 密文完整性和来源证据均成立后才构造系统删除请求；请求提交后的确认由 PhotoKit 管理。
      try grant.access { _ in
        PHAssetChangeRequest.deleteAssets([original] as NSArray)
      }
      return nil
    }
    try FileManager.default.removeItem(at: stage)
  }

  /// 业务作用：用户明确确认后按原名解密保存到系统照片，并复验新资产的完整内容。
  /// 参数说明：
  /// - `media`：已解锁列表中的媒体。
  /// - `grant`：当前独立密码会话。
  /// 返回：新相册资产已按原名完整保存；提交后无法复验时明确提示系统中可能已有副本。
  func export(_ media: VaultMedia, using grant: VaultGrant) async throws {
    try await saveToPhotos(media, using: grant) { stage in
      try self.library.export(id: media.id, to: stage, using: grant)
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
    try await saveToPhotos(media, using: grant) { stage in
      try self.library.copyToSystem(session, to: stage, using: grant)
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

  /// 业务作用：只接收能够完整保留的单资源资产，避免组合内容只保存一部分后删源。
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

  /// 业务作用：优先读取原始资源，资源接口拒绝时复用系统已经缓存的本地原件，不自动下载。
  /// 参数说明：
  /// - `asset`：用户明确选择、已经取得权限的单资源资产。
  /// - `resource`：保留原始文件名与资源身份的系统描述。
  /// - `destination`：当前私有暂存中的新路径。
  /// 返回：本地原始字节已完整写入并收紧权限；系统不能离线交付时明确拒绝，不断言用户没有下载。
  private func write(_ asset: PHAsset, resource: PHAssetResource, to destination: URL) async throws
  {
    do {
      try await writeResource(resource, to: destination)
    } catch {
      if Task.isCancelled {
        throw VaultError.cancelled
      }
      // 资源请求可能留下部分文件，只移除本次独占暂存中的目标后再尝试系统本地原件入口。
      if FileManager.default.fileExists(atPath: destination.path) {
        try FileManager.default.removeItem(at: destination)
      }
      do {
        if asset.mediaType == .video {
          let local: AVURLAsset
          do {
            local = try await localVideo(asset, version: .original)
          } catch {
            // 单资源视频没有另存的编辑资源，允许复用系统当前已缓存的本地文件，仍禁止下载。
            local = try await localVideo(asset, version: .current)
          }
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
          // original 版本与禁止网络选项共同约束来源；保留 AVURLAsset 生命周期以维持本地文件授权。
          try withExtendedLifetime(local) {
            try FileManager.default.copyItem(at: local.url, to: destination)
          }
          guard try SourceIdentity(source) == identity else {
            throw VaultError.sourceChanged
          }
        } else if asset.mediaType == .image {
          let data = try await localImage(asset)
          let output = try VaultStorage.create(destination)
          defer {
            try? output.close()
          }
          try output.write(contentsOf: data)
          try output.synchronize()
        } else {
          throw VaultError.unsupportedMedia
        }
      } catch VaultError.cancelled {
        throw VaultError.cancelled
      } catch {
        throw VaultError.photoLocalResource
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
  /// - `version`：先请求原始版本，单资源资产也可请求当前本地版本。
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
  /// 返回：原始版本的完整图片数据；取消或本地不可用时失败。
  private func localImage(_ asset: PHAsset) async throws -> Data {
    let options = PHImageRequestOptions()
    options.version = .original
    options.deliveryMode = .highQualityFormat
    options.isNetworkAccessAllowed = false
    return try await withCheckedThrowingContinuation { continuation in
      PHImageManager.default().requestImageDataAndOrientation(for: asset, options: options) {
        data, _, _, info in
        if info?[PHImageCancelledKey] as? Bool == true {
          continuation.resume(throwing: VaultError.cancelled)
        } else if let data, !data.isEmpty {
          continuation.resume(returning: data)
        } else {
          continuation.resume(throwing: VaultError.photoLocalResource)
        }
      }
    }
  }

  /// 业务作用：通过原始资源接口请求本地字节，禁止网络并向调用方交付明确读取失败。
  /// 参数说明：
  /// - `resource`：当前唯一的系统原始资源。
  /// - `destination`：当前私有暂存中的新路径。
  /// 返回：本机完整资源可用；失败由调用方精确清理暂存目录。
  private func writeResource(_ resource: PHAssetResource, to destination: URL) async throws {
    let options = PHAssetResourceRequestOptions()
    options.isNetworkAccessAllowed = false
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
              throw VaultError.photoResource
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
      } completionHandler: { success, _ in
        let (identifier, failure) = outcome.result()
        if let failure {
          continuation.resume(throwing: failure)
        } else if success {
          continuation.resume(returning: identifier)
        } else {
          continuation.resume(throwing: VaultError.photoChange)
        }
      }
    }
  }
}
