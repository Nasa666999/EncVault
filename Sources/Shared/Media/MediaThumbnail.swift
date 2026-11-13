@preconcurrency import AVFoundation
import Foundation
import ImageIO
import UniformTypeIdentifiers

/// 当前图片查看的有界像素解码，来源字节保持原样，兼容回退也只使用内存。
enum MediaImageDecoder {
  /// 业务作用：按正确方向生成当前图片画面，限制解压后的尺寸，并兼容系统不接受的图片编码。
  /// 参数说明：
  /// - `reader`：当前会话授权、已经认证的图片读取器。
  /// 返回：最长边不超过 8192 像素的查看画面；失权、损坏及无法解码时拒绝。
  static func render(_ reader: VaultMediaReader) async throws -> CGImage {
    let bytes = try reader.imageData()
    try Task.checkCancellation()
    if let source = CGImageSourceCreateWithData(
      bytes as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
      let image = CGImageSourceCreateThumbnailAtIndex(
        source, 0,
        [
          kCGImageSourceCreateThumbnailFromImageAlways: true,
          kCGImageSourceCreateThumbnailWithTransform: true,
          kCGImageSourceThumbnailMaxPixelSize: 8192,
          kCGImageSourceShouldCacheImmediately: true,
        ] as CFDictionary)
    {
      try reader.checkAccess()
      return image
    }
    let image = try await LocalMediaCodecs.preview(reader, maximumDimension: 8192)
    try reader.checkAccess()
    return image
  }
}

/// 为当前解锁会话生成小尺寸预览，全部输入和输出均留在内存中。
enum MediaThumbnail {
  /// 业务作用：按需解密图片或视频首帧，供相册网格与统一缩略图栏显示。
  /// 参数说明：
  /// - `reader`：当前独立密码会话授权的媒体读取器。
  /// 返回：最长边不超过 256 像素的 PNG 数据；取消、密文损坏或解码失败时抛出错误。
  static func render(_ reader: VaultMediaReader) async throws -> Data {
    try Task.checkCancellation()
    let image: CGImage
    if reader.media.isVideo {
      let resource = EncryptedMediaResource(reader: reader)
      let generator = AVAssetImageGenerator(asset: resource.asset)
      generator.appliesPreferredTrackTransform = true
      generator.maximumSize = CGSize(width: 256, height: 256)
      defer {
        resource.loader.cancelAll()
      }
      do {
        image = try await withTaskCancellationHandler {
          try await generator.image(at: .zero).image
        } onCancel: {
          // 同时结束解码请求与字节供给，避免锁定后的任务等待未完成的系统帧请求。
          generator.cancelAllCGImageGeneration()
          resource.loader.cancelAll()
        }
      } catch {
        try Task.checkCancellation()
        try reader.checkAccess()
        image = try await LocalMediaCodecs.preview(reader, maximumDimension: 256)
      }
    } else {
      let bytes = try reader.imageData()
      if let source = CGImageSourceCreateWithData(
        bytes as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
        let thumbnail = CGImageSourceCreateThumbnailAtIndex(
          source, 0,
          [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: 256,
            kCGImageSourceShouldCacheImmediately: true,
          ] as CFDictionary)
      {
        image = thumbnail
      } else {
        image = try await LocalMediaCodecs.preview(reader, maximumDimension: 256)
      }
    }
    try Task.checkCancellation()
    try reader.checkAccess()
    let result = try png(image)
    try reader.checkAccess()
    return result
  }

  /// 业务作用：将小图像素编码到内存，不复制来源的定位、文件名等元数据。
  /// 参数说明：
  /// - `image`：受像素预算约束的当前会话预览。
  /// 返回：仅包含像素的 PNG 数据；分配、编码或取消失败时拒绝。
  static func png(_ image: CGImage) throws -> Data {
    try Task.checkCancellation()
    let bytes = NSMutableData()
    guard
      let destination = CGImageDestinationCreateWithData(
        bytes, UTType.png.identifier as CFString, 1, nil)
    else {
      throw VaultError.storage
    }
    // 仅把像素编码到内存，不复制来源的定位、文件名等元数据，也不创建磁盘缩略图。
    CGImageDestinationAddImage(destination, image, nil)
    guard CGImageDestinationFinalize(destination) else {
      throw VaultError.storage
    }
    try Task.checkCancellation()
    return bytes as Data
  }
}
