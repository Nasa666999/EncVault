import Compression
import CoreText
import Foundation
import ImageIO

/// 文档卡片从认证字节生成小图，不提交系统最近文档，也不创建明文或缩略图文件。
enum DocumentThumbnail {
  /// 业务作用：为禁止系统导出的文档提供应用自有内容，不交付系统分享控制器。
  /// 参数说明：
  /// - `document`：已通过目录访问验证的当前文档副本。
  /// 返回：正文、PDF 或内嵌首页；无法受控预览时拒绝，不改用带分享入口的预览。
  static func privateContent(_ document: VaultDocument) throws -> PrivateDocumentContent {
    let reader = document.reader
    try reader.checkAccess()
    let suffix = (document.media.originalFilename as NSString).pathExtension.lowercased()
    let result: PrivateDocumentContent
    if suffix == "docx" {
      let xml = try DocumentArchivePreview.entry(
        in: reader, names: ["word/document.xml"], limit: 8 * 1024 * 1024
      ).data
      result = .text(try WordThumbnailText.read(xml, limit: 8 * 1024 * 1024))
    } else if suffix == "pdf" {
      result = .pdf(try reader.imageData(limit: 64 * 1024 * 1024))
    } else if suffix == "pages" {
      let names = ["QuickLook/Preview.pdf", "preview.jpg", "QuickLook/Thumbnail.jpg"]
      let preview: (name: String, data: Data)
      if document.media.isFolder {
        guard
          let name = names.first(where: {
            FileManager.default.fileExists(atPath: document.url.appendingPathComponent($0).path)
          })
        else {
          throw VaultError.documentPreviewUnavailable
        }
        let url = document.url.appendingPathComponent(name)
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max
        guard size <= 64 * 1024 * 1024 else {
          throw VaultError.documentTooLarge
        }
        preview = (name, try Data(contentsOf: url))
      } else {
        preview = try DocumentArchivePreview.entry(
          in: reader, names: names, limit: 64 * 1024 * 1024)
      }
      if preview.name.hasSuffix(".pdf") {
        result = .pdf(preview.data)
      } else {
        guard let source = CGImageSourceCreateWithData(preview.data as CFData, nil),
          let image = CGImageSourceCreateThumbnailAtIndex(
            source, 0,
            [
              kCGImageSourceCreateThumbnailFromImageAlways: true,
              kCGImageSourceCreateThumbnailWithTransform: true,
              kCGImageSourceThumbnailMaxPixelSize: 8192,
            ] as CFDictionary)
        else {
          throw VaultError.documentPreviewUnavailable
        }
        result = .image(image)
      }
    } else {
      throw VaultError.documentPreviewUnavailable
    }
    try Task.checkCancellation()
    try reader.checkAccess()
    return result
  }

  /// 业务作用：为当前解锁列表生成文本片段、办公文档首页或 PDF 首页预览。
  /// 参数说明：
  /// - `media`：当前认证的文档身份。
  /// - `entries`：当前认证列表，用于查找 Pages 文件包内的预览资源。
  /// - `library`：有界认证读取入口。
  /// - `grant`：锁定时撤销的当前会话。
  /// 返回：最长边不超过 256 像素的内存 PNG；超限、失权或不支持时保留类型图标。
  static func render(
    _ media: VaultMedia, entries: [VaultMedia], library: VaultLibrary, using grant: VaultGrant
  ) throws -> Data {
    try Task.checkCancellation()
    try grant.check()
    let authorization = try library.reader(id: media.id, using: grant)
    let image: CGImage
    let suffix = (media.originalFilename as NSString).pathExtension.lowercased()
    if media.isFolder {
      guard suffix == "pages" else {
        throw VaultError.unsupportedMedia
      }
      let candidates = entries.filter {
        $0.parentID == media.id && $0.originalFilename == "preview.jpg" && !$0.isFolder
      }
      let quickLook = entries.first {
        $0.parentID == media.id && $0.originalFilename == "QuickLook" && $0.isFolder
      }
      let nested = entries.filter {
        quickLook != nil && $0.parentID == quickLook?.id
          && ["Preview.pdf", "Thumbnail.jpg"].contains($0.originalFilename) && !$0.isFolder
      }
      guard let preview = (candidates + nested).first else {
        throw VaultError.unsupportedMedia
      }
      let reader = try library.reader(id: preview.id, using: grant)
      let data = try reader.imageData(limit: 8 * 1024 * 1024)
      image = preview.originalFilename.hasSuffix(".pdf") ? try pdf(data) : try bitmap(data)
    } else {
      let reader = try library.reader(id: media.id, using: grant)
      if media.isTextDocument {
        let data = try reader.imageData(limit: 8 * 1024 * 1024)
        guard let body = decodeText(data) else {
          throw VaultError.unsupportedMedia
        }
        image = try text(body)
      } else if suffix == "pages" {
        let preview = try DocumentArchivePreview.entry(
          in: reader, names: ["preview.jpg", "QuickLook/Preview.pdf", "QuickLook/Thumbnail.jpg"],
          limit: 8 * 1024 * 1024)
        image = preview.name.hasSuffix(".pdf") ? try pdf(preview.data) : try bitmap(preview.data)
      } else if suffix == "docx" {
        let xml = try DocumentArchivePreview.entry(
          in: reader, names: ["word/document.xml"], limit: 2 * 1024 * 1024
        ).data
        image = try text(WordThumbnailText.read(xml))
      } else if suffix == "pdf" {
        image = try pdf(reader.imageData(limit: 16 * 1024 * 1024))
      } else {
        throw VaultError.unsupportedMedia
      }
    }
    try Task.checkCancellation()
    try authorization.checkAccess()
    let result = try MediaThumbnail.png(image)
    try authorization.checkAccess()
    return result
  }

  /// 业务作用：识别常见文本编码，缩略图仅读取内容，不改变原文件编码。
  /// 参数说明：
  /// - `data`：完整认证的有界文本字节。
  /// 返回：UTF-8、带标记的 UTF-16 或常见兼容文本；无法识别时为空。
  private static func decodeText(_ data: Data) -> String? {
    if data.starts(with: [0xFF, 0xFE]) || data.starts(with: [0xFE, 0xFF]) {
      return String(data: data, encoding: .utf16)
    }
    return String(data: data, encoding: .utf8) ?? String(data: data, encoding: .windowsCP1252)
  }

  /// 业务作用：以固定像素预算建立文档小图，不继承来源的定位或其它元数据。
  /// 参数说明：无。
  /// 返回：白底、192×256 像素的内存画布；分配失败时拒绝预览。
  private static func canvas() throws -> CGContext {
    guard
      let context = CGContext(
        data: nil, width: 192, height: 256, bitsPerComponent: 8, bytesPerRow: 0,
        space: CGColorSpaceCreateDeviceRGB(),
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
    else {
      throw VaultError.storage
    }
    context.setFillColor(CGColor(gray: 1, alpha: 1))
    context.fill(CGRect(x: 0, y: 0, width: 192, height: 256))
    return context
  }

  /// 业务作用：把文本开头排成可辨认的文档卡片，不执行 HTML 或 Markdown 内容。
  /// 参数说明：
  /// - `body`：已认证的正文或 Word 段落。
  /// 返回：有界正文片段的小图，不保存文字或排版状态。
  private static func text(_ body: String) throws -> CGImage {
    let context = try canvas()
    let prefix = String(body.prefix(3000)).trimmingCharacters(in: .whitespacesAndNewlines)
    let content = prefix.isEmpty ? "（空白文档）" : prefix
    let attributed = NSAttributedString(
      string: content,
      attributes: [
        NSAttributedString.Key(kCTFontAttributeName as String): CTFontCreateWithName(
          "Helvetica" as CFString, 9, nil),
        NSAttributedString.Key(kCTForegroundColorAttributeName as String): CGColor(
          gray: 0.12, alpha: 1),
      ])
    let frame = CTFramesetterCreateFrame(
      CTFramesetterCreateWithAttributedString(attributed), CFRange(location: 0, length: 0),
      CGPath(rect: CGRect(x: 14, y: 12, width: 164, height: 232), transform: nil), nil)
    CTFrameDraw(frame, context)
    guard let image = context.makeImage() else {
      throw VaultError.storage
    }
    return image
  }

  /// 业务作用：从文档内嵌首页图片解码小图，不生成完整尺寸图片缓存。
  /// 参数说明：
  /// - `data`：已认证并限制大小的预览资源。
  /// 返回：最长边不超过 256 像素的正确方向预览。
  private static func bitmap(_ data: Data) throws -> CGImage {
    guard
      let source = CGImageSourceCreateWithData(
        data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
      let image = CGImageSourceCreateThumbnailAtIndex(
        source, 0,
        [
          kCGImageSourceCreateThumbnailFromImageAlways: true,
          kCGImageSourceCreateThumbnailWithTransform: true,
          kCGImageSourceThumbnailMaxPixelSize: 256,
          kCGImageSourceShouldCacheImmediately: true,
        ] as CFDictionary)
    else {
      throw VaultError.unsupportedMedia
    }
    return image
  }

  /// 业务作用：在内存中绘制 PDF 第一页，不登记系统文档或打开外部应用。
  /// 参数说明：
  /// - `data`：完整认证并有大小上限的 PDF 字节。
  /// 返回：白底首页小图；没有有效首页时拒绝。
  private static func pdf(_ data: Data) throws -> CGImage {
    guard let provider = CGDataProvider(data: data as CFData),
      let document = CGPDFDocument(provider), let page = document.page(at: 1)
    else {
      throw VaultError.unsupportedMedia
    }
    let context = try canvas()
    context.concatenate(
      page.getDrawingTransform(
        .cropBox, rect: CGRect(x: 4, y: 4, width: 184, height: 248), rotate: 0,
        preserveAspectRatio: true))
    context.drawPDFPage(page)
    guard let image = context.makeImage() else {
      throw VaultError.storage
    }
    return image
  }
}

/// 仅从 ZIP 中提取允许的预览资源，所有偏移、解压大小及校验均有界，不落盘解包。
private enum DocumentArchivePreview {
  /// 业务作用：在认证归档中寻找首页图片或正文，不信任归档提供的路径和长度。
  /// 参数说明：
  /// - `reader`：当前会话的认证随机读取器。
  /// - `names`：按优先顺序允许读取的归档内部名称。
  /// - `limit`：允许的压缩和解压字节上限。
  /// 返回：匹配的完整资源；分卷、ZIP64、加密、截断、重复名称及校验失败时拒绝。
  static func entry(
    in reader: VaultMediaReader, names: [String], limit: Int
  ) throws -> (name: String, data: Data) {
    let size = reader.media.byteCount
    guard size >= 22 else {
      throw VaultError.corrupt
    }
    let tailCount = Int(min(size, 65_557))
    let tail = try reader.read(offset: size - UInt64(tailCount), count: tailCount)
    // 归档尾部必须与声明的注释长度一致，不能把资源内部的相同字节当作目录尾。
    let position = stride(from: tailCount - 22, through: 0, by: -1).first { index in
      (try? number(tail, at: index, count: 4)) == 0x0605_4B50
        && (try? number(tail, at: index + 20, count: 2)) == UInt32(tailCount - index - 22)
    }
    guard let position, try number(tail, at: position + 4, count: 2) == 0,
      try number(tail, at: position + 6, count: 2) == 0
    else {
      throw VaultError.corrupt
    }
    let count = Int(try number(tail, at: position + 10, count: 2))
    let directorySize = Int(try number(tail, at: position + 12, count: 4))
    let directoryOffset = UInt64(try number(tail, at: position + 16, count: 4))
    guard count > 0, count <= 4096,
      try number(tail, at: position + 8, count: 2) == UInt32(count),
      directorySize <= 1024 * 1024,
      directoryOffset + UInt64(directorySize) <= size - UInt64(tailCount) + UInt64(position)
    else {
      throw VaultError.corrupt
    }
    let directory = try reader.read(offset: directoryOffset, count: directorySize)
    var cursor = 0
    var found:
      [String: (
        offset: UInt64, compressed: Int, expanded: Int, crc: UInt32, method: UInt32, flags: UInt32
      )] = [:]
    for _ in 0..<count {
      guard try number(directory, at: cursor, count: 4) == 0x0201_4B50 else {
        throw VaultError.corrupt
      }
      let nameLength = Int(try number(directory, at: cursor + 28, count: 2))
      let extra = Int(try number(directory, at: cursor + 30, count: 2))
      let comment = Int(try number(directory, at: cursor + 32, count: 2))
      let next = cursor + 46 + nameLength + extra + comment
      guard next <= directory.count else {
        throw VaultError.corrupt
      }
      let name = String(
        decoding: directory[(cursor + 46)..<(cursor + 46 + nameLength)], as: UTF8.self)
      if names.contains(name) {
        let flags = try number(directory, at: cursor + 8, count: 2)
        let method = try number(directory, at: cursor + 10, count: 2)
        let compressed = Int(try number(directory, at: cursor + 20, count: 4))
        let expanded = Int(try number(directory, at: cursor + 24, count: 4))
        guard found[name] == nil, flags & 1 == 0, method == 0 || method == 8,
          compressed > 0, compressed <= limit, expanded > 0, expanded <= limit,
          try number(directory, at: cursor + 34, count: 2) == 0
        else {
          throw VaultError.corrupt
        }
        found[name] = (
          UInt64(try number(directory, at: cursor + 42, count: 4)), compressed, expanded,
          try number(directory, at: cursor + 16, count: 4), method, flags
        )
      }
      cursor = next
    }
    guard cursor == directory.count, let name = names.first(where: { found[$0] != nil }),
      let item = found[name], item.offset + 30 <= directoryOffset
    else {
      throw VaultError.unsupportedMedia
    }
    let header = try reader.read(offset: item.offset, count: 30)
    let nameLength = Int(try number(header, at: 26, count: 2))
    let extra = Int(try number(header, at: 28, count: 2))
    let dataOffset = item.offset + UInt64(30 + nameLength + extra)
    guard try number(header, at: 0, count: 4) == 0x0403_4B50,
      try number(header, at: 6, count: 2) == item.flags,
      try number(header, at: 8, count: 2) == item.method,
      dataOffset + UInt64(item.compressed) <= directoryOffset,
      try reader.read(offset: item.offset + 30, count: nameLength) == Data(name.utf8)
    else {
      throw VaultError.corrupt
    }
    var compressed = Data()
    while compressed.count < item.compressed {
      try Task.checkCancellation()
      compressed.append(
        try reader.read(
          offset: dataOffset + UInt64(compressed.count),
          count: min(VaultMediaReader.chunkSize, item.compressed - compressed.count)))
    }
    let result: Data
    if item.method == 0 {
      guard compressed.count == item.expanded else {
        throw VaultError.corrupt
      }
      result = compressed
    } else {
      var output = [UInt8](repeating: 0, count: item.expanded)
      let decoded = compressed.withUnsafeBytes { source in
        output.withUnsafeMutableBytes { destination in
          compression_decode_buffer(
            destination.baseAddress!.assumingMemoryBound(to: UInt8.self), item.expanded,
            source.baseAddress!.assumingMemoryBound(to: UInt8.self), compressed.count,
            nil, COMPRESSION_ZLIB)
        }
      }
      guard decoded == item.expanded else {
        throw VaultError.corrupt
      }
      result = Data(output)
    }
    guard crc32(result) == item.crc else {
      throw VaultError.corrupt
    }
    try reader.checkAccess()
    return (name, result)
  }

  /// 业务作用：在归档边界内读取小端结构字段，拒绝截断或越界偏移。
  /// 参数说明：
  /// - `data`：当前已认证的结构区域。
  /// - `offset`：字段在该区域内的偏移。
  /// - `count`：两字节或四字节的结构字段宽度。
  /// 返回：有界整数；字段不完整时失败。
  private static func number(_ data: Data, at offset: Int, count: Int) throws -> UInt32 {
    guard offset >= 0, count > 0, count <= 4, offset <= data.count - count else {
      throw VaultError.corrupt
    }
    return (0..<count).reduce(0) {
      $0 | UInt32(data[offset + $1]) << (8 * $1)
    }
  }

  /// 业务作用：复验 ZIP 资源的结构校验值；会话安全仍由每个密文分块的认证保证。
  /// 参数说明：
  /// - `data`：有界解压结果。
  /// 返回：标准 ZIP CRC-32 值，不替代 AES-GCM 认证。
  private static func crc32(_ data: Data) -> UInt32 {
    var value: UInt32 = 0xFFFF_FFFF
    for byte in data {
      value ^= UInt32(byte)
      for _ in 0..<8 {
        value = (value >> 1) ^ (value & 1 == 0 ? 0 : 0xEDB8_8320)
      }
    }
    return ~value
  }
}

/// Word 缩略图与受控预览共用有界正文读取，不执行脚本或读取外部 XML 实体。
private final class WordThumbnailText: NSObject, XMLParserDelegate {
  private var collecting = false
  private var body = ""
  private var reachedLimit = false
  private var remaining = 3000

  /// 业务作用：从 Word 正文 XML 收集开头段落，保护缩略图工作量和外部资源边界。
  /// 参数说明：
  /// - `data`：已认证并限制大小的 document.xml。
  /// - `limit`：本次缩略图或私有正文的字符预算。
  /// 返回：预算内正文；带 DTD、实体声明或损坏结构时拒绝。
  static func read(_ data: Data, limit: Int = 3000) throws -> String {
    guard let xml = String(data: data, encoding: .utf8), !xml.contains("\0"),
      !xml.uppercased().contains("<!DOCTYPE"), !xml.uppercased().contains("<!ENTITY")
    else {
      throw VaultError.unsupportedMedia
    }
    let delegate = WordThumbnailText()
    delegate.remaining = limit
    let parser = XMLParser(data: data)
    parser.shouldResolveExternalEntities = false
    parser.externalEntityResolvingPolicy = .never
    parser.delegate = delegate
    guard parser.parse() || delegate.reachedLimit else {
      throw VaultError.corrupt
    }
    return delegate.body
  }

  /// 业务作用：仅接受正文文本节点，不把格式或关系字段当作内容。
  /// 参数说明：
  /// - `parser`：本次有界解析器。
  /// - `elementName`：当前 XML 节点名称。
  /// - `namespaceURI`：系统提供的命名空间。
  /// - `qName`：系统提供的限定名称。
  /// - `attributeDict`：不用于外部资源加载的节点属性。
  /// 返回：只在文字节点内开放正文收集。
  func parser(
    _ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
    qualifiedName qName: String?, attributes attributeDict: [String: String]
  ) {
    collecting = elementName.split(separator: ":").last == "t"
  }

  /// 业务作用：达到本次文字预算后主动结束解析，正文读取不反复遍历已收集的大段文字。
  /// 参数说明：
  /// - `parser`：本次解析器。
  /// - `string`：当前正文片段。
  /// 返回：保留有界片段，达到预算后中止剩余 XML。
  func parser(_ parser: XMLParser, foundCharacters string: String) {
    if collecting {
      let part = string.prefix(max(0, remaining))
      body += part
      remaining -= part.count
      if remaining == 0 {
        reachedLimit = true
        parser.abortParsing()
      }
    }
  }

  /// 业务作用：保留正文段落和表格行的阅读分隔，不生成完整排版状态。
  /// 参数说明：
  /// - `parser`：本次解析器。
  /// - `elementName`：结束的 XML 节点。
  /// - `namespaceURI`：系统提供的命名空间。
  /// - `qName`：系统提供的限定名称。
  /// 返回：结束文字收集，并在段落边界补充换行。
  func parser(
    _ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?,
    qualifiedName qName: String?
  ) {
    collecting = false
    if ["p", "tr"].contains(String(elementName.split(separator: ":").last ?? "")),
      remaining > 0
    {
      body += "\n"
      remaining -= 1
    }
  }
}

/// 受保护文档只向应用自有画布交付内存内容，不带外部打开或分享动作。
enum PrivateDocumentContent {
  case text(String)
  case pdf(Data)
  case image(CGImage)
}
