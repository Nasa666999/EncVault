@preconcurrency import AVFoundation
import Foundation
import UniformTypeIdentifiers

/// 单一资源请求的取消门禁，避免取消和明文交付交错。
private final class MediaLoadingJob: @unchecked Sendable {
  let request: AVAssetResourceLoadingRequest
  private let mutex = NSLock()
  private var cancelled = false

  /// 业务作用：把系统媒体请求绑定到独立的取消状态。
  /// 参数说明：
  /// - `request`：只由当前任务响应的系统请求。
  /// 返回：不持久化媒体 URL 或访问记录的请求容器。
  init(_ request: AVAssetResourceLoadingRequest) {
    self.request = request
  }

  /// 业务作用：在请求仍有效时同步交付数据，取消后拒绝后续交付。
  /// 参数说明：
  /// - `operation`：本次系统响应或完成动作。
  /// 返回：操作结果；系统或本地取消后失败。
  func access<T>(_ operation: () throws -> T) throws -> T {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    guard !cancelled, !request.isCancelled else {
      throw VaultError.cancelled
    }
    return try operation()
  }

  /// 业务作用：使未完成请求失去继续交付明文的资格。
  /// 参数说明：无。
  /// 返回：当前同步响应结束后不再交付数据。
  func cancel() {
    mutex.lock()
    cancelled = true
    mutex.unlock()
  }
}

/// 从本地密文按范围提供数据，不启动服务器，不发布系统媒体信息。
final class EncryptedMediaLoader: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
  private let reader: VaultMediaReader
  private let mutex = NSLock()
  private let workers: OperationQueue
  private var jobs: [ObjectIdentifier: MediaLoadingJob] = [:]
  private var active = true

  /// 业务作用：为一个已认证媒体建立最多两个并行的有界读取任务。
  /// 参数说明：
  /// - `reader`：受当前会话约束的密文读取器。
  /// 返回：只服务该密文的加载器。
  init(reader: VaultMediaReader) {
    self.reader = reader
    workers = OperationQueue()
    workers.maxConcurrentOperationCount = 2
    workers.qualityOfService = .userInitiated
    super.init()
  }

  /// 业务作用：接收自有本地资源请求，未知协议不进入解密路径。
  /// 参数说明：
  /// - `resourceLoader`：系统 URL asset 的资源加载器。
  /// - `loadingRequest`：需要的头部或字节范围。
  /// 返回：自有资源被接管时为 true；会话关闭或协议不符时拒绝接管。
  func resourceLoader(
    _ resourceLoader: AVAssetResourceLoader,
    shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
  ) -> Bool {
    guard loadingRequest.request.url?.scheme == "encvault" else {
      return false
    }
    mutex.lock()
    guard active else {
      mutex.unlock()
      return false
    }
    let job = MediaLoadingJob(loadingRequest)
    jobs[ObjectIdentifier(loadingRequest)] = job
    mutex.unlock()
    workers.addOperation { [weak self, job] in
      self?.serve(job)
    }
    return true
  }

  /// 业务作用：系统不再需要某次范围读取时，只撤销该请求，不影响其它请求。
  /// 参数说明：
  /// - `resourceLoader`：系统资源加载器。
  /// - `loadingRequest`：已被系统取消的请求。
  /// 返回：该请求后续不再交付明文。
  func resourceLoader(
    _ resourceLoader: AVAssetResourceLoader,
    didCancel loadingRequest: AVAssetResourceLoadingRequest
  ) {
    mutex.lock()
    let job = jobs.removeValue(forKey: ObjectIdentifier(loadingRequest))
    mutex.unlock()
    job?.cancel()
  }

  /// 业务作用：有界响应实际请求的范围，每次交付前复验会话和请求资格。
  /// 参数说明：
  /// - `job`：本次唯一响应的系统请求。
  /// 返回：完整响应、拒绝损坏数据或因取消而停止；不保存当前位置。
  private func serve(_ job: MediaLoadingJob) {
    defer {
      mutex.lock()
      jobs.removeValue(forKey: ObjectIdentifier(job.request))
      mutex.unlock()
    }
    do {
      try reader.grant.access(folders: reader.folderRequirements) { _ in
        try job.access {
          if let information = job.request.contentInformationRequest {
            var selected = reader.media.contentType
            if let allowed = information.allowedContentTypes, !allowed.isEmpty,
              !allowed.contains(selected)
            {
              guard
                let matching = allowed.first(where: {
                  guard let actual = UTType(selected), let candidate = UTType($0) else {
                    return false
                  }
                  return actual.conforms(to: candidate)
                })
              else {
                throw VaultError.unsupportedMedia
              }
              selected = matching
            }
            information.contentType = selected
            information.contentLength = Int64(reader.media.byteCount)
            information.isByteRangeAccessSupported = true
          }
        }
      }
      if let request = job.request.dataRequest {
        guard request.requestedOffset >= 0, request.currentOffset >= 0, request.requestedLength >= 0
        else {
          throw VaultError.corrupt
        }
        var offset = UInt64(max(request.requestedOffset, request.currentOffset))
        let end =
          request.requestsAllDataToEndOfResource
          ? reader.media.byteCount
          : min(
            reader.media.byteCount,
            UInt64(request.requestedOffset) + UInt64(request.requestedLength))
        guard offset <= reader.media.byteCount else {
          throw VaultError.corrupt
        }
        while offset < end {
          try job.access {}
          let count = Int(min(262_144, end - offset))
          let data = try reader.read(offset: offset, count: count)
          // 撤销和交付共用能力门禁，旧任务不能在重新解锁后补交明文。
          try reader.grant.access(folders: reader.folderRequirements) { _ in
            try job.access {
              request.respond(with: data)
            }
          }
          offset += UInt64(data.count)
        }
      }
      try reader.grant.access(folders: reader.folderRequirements) { _ in
        try job.access {
          job.request.finishLoading()
        }
      }
    } catch {
      try? job.access {
        job.request.finishLoading(with: VaultError.corrupt)
      }
    }
  }

  /// 业务作用：关闭查看或锁定时撤销全部范围请求，不保留播放队列和进度。
  /// 参数说明：无。
  /// 返回：后续请求不再被接管，已有任务只允许结束当前有界操作。
  func cancelAll() {
    mutex.lock()
    active = false
    let current = Array(jobs.values)
    jobs.removeAll()
    mutex.unlock()
    for job in current {
      job.cancel()
    }
    workers.cancelAllOperations()
  }
}

/// 只使用不含原名的本地虚拟 URL，禁止媒体引用外部网络资源。
final class EncryptedMediaResource: @unchecked Sendable {
  let asset: AVURLAsset
  let loader: EncryptedMediaLoader
  private let queue = DispatchQueue(label: "local.encvault.media-delegate")

  /// 业务作用：把系统解码器连接到当前密文读取器，屏蔽远程与外部媒体引用。
  /// 参数说明：
  /// - `reader`：已经解锁并认证的媒体。
  /// 返回：仅在 App 内使用的 asset，不登记最近文档。
  init(reader: VaultMediaReader) {
    loader = EncryptedMediaLoader(reader: reader)
    let url = URL(string: "encvault://media/\(reader.media.id.uuidString)")!
    // 虚拟 URL 不暴露原名；用认证后的真实容器类型选择解码器，原扩展名可以与容器不同。
    asset = AVURLAsset(
      url: url,
      options: [
        AVURLAssetReferenceRestrictionsKey: AVAssetReferenceRestrictions.forbidAll.rawValue,
        AVURLAssetOverrideMIMETypeKey: reader.media.contentType == UTType.quickTimeMovie.identifier
          ? "video/quicktime" : "video/mp4",
      ]
    )
    asset.resourceLoader.setDelegate(loader, queue: queue)
  }

  /// 业务作用：资源释放时终止未完成解密请求。
  /// 参数说明：无。
  /// 返回：加载器关闭，不产生持久化访问记录。
  deinit {
    loader.cancelAll()
  }
}
