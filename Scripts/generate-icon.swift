import AppKit
import Foundation
import ImageIO
import UniformTypeIdentifiers

/// 业务作用：以青蓝至紫色渐变衬托两端统一的白色保险箱，小尺寸下保持轮廓可辨认。
/// 参数说明：
/// - `size`：目标像素边长。
/// - `macOS`：是否保留 Mac 图标的透明外缘与圆角留白。
/// 返回：使用 sRGB 的正方形图像；无法建立绘图上下文时停止生成。
func render(size: Int, macOS: Bool) throws -> CGImage {
  let alpha = macOS ? CGImageAlphaInfo.premultipliedLast : .noneSkipLast
  guard let space = CGColorSpace(name: CGColorSpace.sRGB),
    let context = CGContext(
      data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: size * 4,
      space: space, bitmapInfo: alpha.rawValue)
  else {
    throw CocoaError(.fileWriteUnknown)
  }
  context.scaleBy(x: CGFloat(size) / 1024, y: CGFloat(size) / 1024)
  let tile =
    macOS
    ? CGRect(x: 64, y: 64, width: 896, height: 896)
    : CGRect(x: 0, y: 0, width: 1024, height: 1024)
  context.saveGState()
  if macOS {
    context.addPath(CGPath(roundedRect: tile, cornerWidth: 196, cornerHeight: 196, transform: nil))
    context.clip()
  }
  let colors = [
    CGColor(srgbRed: 0.33, green: 0.83, blue: 0.95, alpha: 1),
    CGColor(srgbRed: 0.56, green: 0.43, blue: 0.96, alpha: 1),
  ]
  guard let gradient = CGGradient(colorsSpace: space, colors: colors as CFArray, locations: [0, 1])
  else {
    throw CocoaError(.fileWriteUnknown)
  }
  context.drawLinearGradient(
    gradient, start: CGPoint(x: 512, y: tile.maxY), end: CGPoint(x: 512, y: tile.minY), options: [])
  context.restoreGState()

  context.setStrokeColor(CGColor(gray: 1, alpha: 1))
  context.setFillColor(CGColor(gray: 1, alpha: 1))
  context.setLineWidth(32)
  context.setLineCap(.round)
  context.setLineJoin(.round)
  context.addPath(
    CGPath(
      roundedRect: CGRect(x: 306, y: 280, width: 432, height: 464),
      cornerWidth: 70, cornerHeight: 70, transform: nil))
  context.strokePath()
  for y in [CGFloat(396), CGFloat(628)] {
    context.move(to: CGPoint(x: 278, y: y))
    context.addLine(to: CGPoint(x: 306, y: y))
    context.strokePath()
  }
  let keyhole = CGMutablePath()
  keyhole.addEllipse(in: CGRect(x: 486, y: 510, width: 72, height: 72))
  keyhole.move(to: CGPoint(x: 506, y: 518))
  keyhole.addLine(to: CGPoint(x: 494, y: 448))
  keyhole.addQuadCurve(to: CGPoint(x: 506, y: 436), control: CGPoint(x: 492, y: 436))
  keyhole.addLine(to: CGPoint(x: 538, y: 436))
  keyhole.addQuadCurve(to: CGPoint(x: 550, y: 448), control: CGPoint(x: 552, y: 436))
  keyhole.addLine(to: CGPoint(x: 538, y: 518))
  keyhole.closeSubpath()
  context.addPath(keyhole)
  context.fillPath()
  guard let image = context.makeImage() else {
    throw CocoaError(.fileWriteUnknown)
  }
  return image
}

/// 业务作用：将图标保存为系统资产目录可直接使用的 PNG。
/// 参数说明：
/// - `image`：已绘制的目标尺寸图像。
/// - `url`：产品资源中的输出位置。
/// 返回：PNG 完整写入；失败停止，避免生成缺失尺寸的图标集合。
func save(_ image: CGImage, to url: URL) throws {
  guard
    let destination = CGImageDestinationCreateWithURL(
      url as CFURL, UTType.png.identifier as CFString, 1, nil)
  else {
    throw CocoaError(.fileWriteUnknown)
  }
  CGImageDestinationAddImage(destination, image, nil)
  guard CGImageDestinationFinalize(destination) else {
    throw CocoaError(.fileWriteUnknown)
  }
}

/// 业务作用：生成 Xcode 资产目录与 macOS iconutil 所需的完整尺寸集合。
/// 参数说明：
/// - `directory`：产品资源根目录。
/// 返回：两端图标资源和 Mac iconset 已完整保存；不读取媒体或用户凭据。
func generate(in directory: URL) throws {
  let catalog = directory.appendingPathComponent("Assets.xcassets", isDirectory: true)
  let icons = catalog.appendingPathComponent("AppIcon.appiconset", isDirectory: true)
  let iconset = directory.appendingPathComponent("AppIcon.iconset", isDirectory: true)
  for folder in [catalog, icons, iconset] {
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
  }
  let information: [String: Any] = ["version": 1, "author": "xcode"]
  var images: [[String: String]] = []
  for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
      let name = "icon_\(size)x\(size)" + (scale == 2 ? "@2x" : "") + ".png"
      let image = try render(size: size * scale, macOS: true)
      try save(image, to: iconset.appendingPathComponent(name))
      try save(image, to: icons.appendingPathComponent(name))
      images.append([
        "idiom": "mac", "size": "\(size)x\(size)", "scale": "\(scale)x", "filename": name,
      ])
    }
  }
  for size in [20, 29, 40, 60] {
    for scale in [2, 3] {
      let name = "iphone_\(size)@\(scale)x.png"
      try save(render(size: size * scale, macOS: false), to: icons.appendingPathComponent(name))
      images.append([
        "idiom": "iphone", "size": "\(size)x\(size)", "scale": "\(scale)x", "filename": name,
      ])
    }
  }
  try save(render(size: 1024, macOS: false), to: icons.appendingPathComponent("AppIcon-iOS.png"))
  images.append([
    "idiom": "ios-marketing", "size": "1024x1024", "scale": "1x", "filename": "AppIcon-iOS.png",
  ])
  try JSONSerialization.data(
    withJSONObject: ["info": information], options: [.prettyPrinted, .sortedKeys]
  )
  .write(to: catalog.appendingPathComponent("Contents.json"))
  try JSONSerialization.data(
    withJSONObject: ["images": images, "info": information], options: [.prettyPrinted, .sortedKeys]
  ).write(to: icons.appendingPathComponent("Contents.json"))
}

let resources = URL(
  fileURLWithPath: CommandLine.arguments.dropFirst().first ?? "Resources", isDirectory: true)
try generate(in: resources)
