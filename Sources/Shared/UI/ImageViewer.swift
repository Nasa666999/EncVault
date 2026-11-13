import SwiftUI

/// 只识别明确的水平翻页，不把纵向操作或轻微手抖当作媒体切换。
enum MediaSwipe {
  /// 业务作用：把当前横向拖动转换为相册上一项或下一项的请求。
  /// 参数说明：
  /// - `translation`：当前手势相对起点的位移。
  /// 返回：左滑为下一项 1，右滑为上一项 -1；不足阈值或主要纵向移动时为空。
  static func step(for translation: CGSize) -> Int? {
    guard translation.width.isFinite, translation.height.isFinite,
      abs(translation.width) > 44,
      abs(translation.width) > abs(translation.height) * 1.3
    else {
      return nil
    }
    return translation.width < 0 ? 1 : -1
  }
}

/// 当前查看区的缩放与位移，只存在内存中，不记录图片访问或跨会话位置。
struct ImageViewport: Equatable, Sendable {
  static let minimumScale: CGFloat = 1
  static let maximumScale: CGFloat = 8
  private(set) var scale: CGFloat = 1
  private(set) var offset: CGSize = .zero

  /// 业务作用：计算完整图片适合当前查看区时的尺寸，作为缩放的基准。
  /// 参数说明：
  /// - `imageSize`：解码图片的显示尺寸。
  /// - `viewportSize`：当前可见查看区尺寸。
  /// 返回：保持比例且不超出查看区的尺寸；无效尺寸返回零，避免产生非有限布局。
  static func fittedSize(imageSize: CGSize, viewportSize: CGSize) -> CGSize {
    guard imageSize.width.isFinite, imageSize.height.isFinite,
      viewportSize.width.isFinite, viewportSize.height.isFinite,
      imageSize.width > 0, imageSize.height > 0,
      viewportSize.width > 0, viewportSize.height > 0
    else {
      return .zero
    }
    let factor = min(viewportSize.width / imageSize.width, viewportSize.height / imageSize.height)
    guard factor.isFinite, factor > 0 else {
      return .zero
    }
    return CGSize(width: imageSize.width * factor, height: imageSize.height * factor)
  }

  /// 业务作用：围绕触摸或鼠标指定位置缩放，保留该位置下的图片内容。
  /// 参数说明：
  /// - `proposedScale`：相对适合查看区尺寸的目标倍率。
  /// - `anchor`：相对查看区中心的缩放位置；零表示中心。
  /// - `imageSize`：当前解码图片尺寸。
  /// - `viewportSize`：当前可见查看区尺寸。
  /// 返回：倍率限制在 1 至 8 倍，并约束位置；非有限输入不改变当前状态。
  mutating func magnify(
    to proposedScale: CGFloat, around anchor: CGPoint,
    imageSize: CGSize, viewportSize: CGSize
  ) {
    guard proposedScale.isFinite, anchor.x.isFinite, anchor.y.isFinite else {
      return
    }
    let next = min(Self.maximumScale, max(Self.minimumScale, proposedScale))
    let ratio = next / scale
    offset = CGSize(
      width: anchor.x + (offset.width - anchor.x) * ratio,
      height: anchor.y + (offset.height - anchor.y) * ratio)
    scale = next
    constrain(imageSize: imageSize, viewportSize: viewportSize)
  }

  /// 业务作用：移动放大后的图片，使用户能查看超出当前区域的内容。
  /// 参数说明：
  /// - `proposedOffset`：相对查看区中心的目标位移。
  /// - `imageSize`：当前解码图片尺寸。
  /// - `viewportSize`：当前可见查看区尺寸。
  /// 返回：图片边缘保持在可见区边界内；不需要滚动的方向始终居中。
  mutating func move(
    to proposedOffset: CGSize, imageSize: CGSize, viewportSize: CGSize
  ) {
    offset = CGSize(
      width: proposedOffset.width.isFinite ? proposedOffset.width : 0,
      height: proposedOffset.height.isFinite ? proposedOffset.height : 0)
    constrain(imageSize: imageSize, viewportSize: viewportSize)
  }

  /// 业务作用：旋转、调整窗口或缩小时约束当前位移，避免把图片拖出查看区。
  /// 参数说明：
  /// - `imageSize`：当前解码图片尺寸。
  /// - `viewportSize`：当前可见查看区尺寸。
  /// 返回：沿需要移动的方向限制边缘，其余方向居中；无效查看区清空位移。
  mutating func constrain(imageSize: CGSize, viewportSize: CGSize) {
    let fitted = Self.fittedSize(imageSize: imageSize, viewportSize: viewportSize)
    guard fitted.width > 0, fitted.height > 0 else {
      offset = .zero
      return
    }
    let horizontal = max(0, (fitted.width * scale - viewportSize.width) / 2)
    let vertical = max(0, (fitted.height * scale - viewportSize.height) / 2)
    offset = CGSize(
      width: min(horizontal, max(-horizontal, offset.width)),
      height: min(vertical, max(-vertical, offset.height)))
  }
}

/// 复用当前已解密图片提供缩放与拖动，不生成明文副本或持久缩略图。
struct VaultImageViewer: View {
  let image: VaultImage
  @Binding var viewport: ImageViewport
  var showsControls = true
  var onNavigate: (Int) -> Void = { _ in }
  var onToggleChrome: () -> Void = {}
  @State private var pinchOrigin: ImageViewport?
  @State private var dragOrigin: CGSize?
  @State private var dragWasMagnified = false
  #if os(iOS)
    private let controlsHeight: CGFloat = 44
  #else
    private let controlsHeight: CGFloat = 28
  #endif

  /// 业务作用：提供两端共用的图片缩放、还原和放大后的拖动查看。
  /// 参数说明：无。
  /// 返回：仅使用当前内存图片的查看区；离开查看时丢弃缩放与位置。
  var body: some View {
    GeometryReader { geometry in
      let size = CGSize(
        width: geometry.size.width,
        height: max(0, geometry.size.height - (showsControls ? controlsHeight + 8 : 0)))
      VStack(spacing: showsControls ? 8 : 0) {
        canvas(in: size)
        if showsControls {
          VaultImageControls(viewport: $viewport, imageSize: image.size, viewportSize: size)
            .frame(height: controlsHeight)
        }
      }
      .frame(width: geometry.size.width, height: geometry.size.height)
    }
    .onDisappear {
      reset()
    }
    .privacySensitive()
  }

  /// 业务作用：仅在独立的图片区域绘制和移动当前图片，保持控制条可见可用。
  /// 参数说明：
  /// - `size`：当前画布尺寸；独立显示控制条时已扣除该控制条的高度。
  /// 返回：支持缩放、拖动和双击切换的裁剪画面，不覆盖其它操作区域。
  private func canvas(in size: CGSize) -> some View {
    let fitted = ImageViewport.fittedSize(imageSize: image.size, viewportSize: size)
    return ZStack {
      displayedImage
        .resizable().scaledToFit()
        .frame(width: fitted.width, height: fitted.height)
        .scaleEffect(viewport.scale)
        .offset(viewport.offset)
    }
    .frame(width: size.width, height: size.height)
    .contentShape(Rectangle())
    // 放大的像素只在当前画布内绘制，外层相册工具栏始终叠放在画布上方。
    .clipped()
    .gesture(drag(in: size))
    .simultaneousGesture(magnify(in: size))
    .simultaneousGesture(
      SpatialTapGesture(count: 2).exclusively(before: SpatialTapGesture()).onEnded { value in
        switch value {
        case .first(let tap):
          if viewport.scale > ImageViewport.minimumScale {
            reset()
          } else {
            viewport.magnify(
              to: 2,
              around: CGPoint(
                x: tap.location.x - size.width / 2,
                y: tap.location.y - size.height / 2),
              imageSize: image.size, viewportSize: size)
          }
        case .second:
          onToggleChrome()
        }
      }
    )
    .accessibilityElement(children: .ignore)
    .accessibilityLabel("图片预览")
    .accessibilityValue("\(percentage)%")
    .onChange(of: size) { _, size in
      pinchOrigin = nil
      dragOrigin = nil
      viewport.constrain(imageSize: image.size, viewportSize: size)
    }
  }

  /// 业务作用：把当前内存图片交给对应平台的绘制入口，保留原始文件不变。
  /// 参数说明：无。
  /// 返回：不包含文件路径或系统预览登记的图片视图。
  private var displayedImage: Image {
    #if os(macOS)
      Image(nsImage: image)
    #else
      Image(uiImage: image)
    #endif
  }

  /// 业务作用：向用户显示相对适合查看区大小的当前倍率。
  /// 参数说明：无。
  /// 返回：100 至 800 的整数百分比，仅用于当前界面。
  private var percentage: Int {
    Int((viewport.scale * 100).rounded())
  }

  /// 业务作用：接收双指或触控板缩放，使手势开始位置下的图片内容保持稳定。
  /// 参数说明：
  /// - `size`：当前可见图片区尺寸。
  /// 返回：倍率与位置均受约束的缩放手势，不持久化手势轨迹。
  private func magnify(in size: CGSize) -> some Gesture {
    MagnifyGesture()
      .onChanged { value in
        dragWasMagnified = true
        if pinchOrigin == nil {
          pinchOrigin = viewport
          dragOrigin = nil
        }
        guard var next = pinchOrigin else {
          return
        }
        next.magnify(
          to: next.scale * value.magnification,
          around: CGPoint(
            x: (value.startAnchor.x - 0.5) * size.width,
            y: (value.startAnchor.y - 0.5) * size.height),
          imageSize: image.size, viewportSize: size)
        viewport = next
      }
      .onEnded { _ in
        pinchOrigin = nil
        dragOrigin = nil
        // 双指结束可能同时产生拖动结束，下一轮事件再解除门禁，防止缩放误触翻页。
        DispatchQueue.main.async {
          dragWasMagnified = false
        }
      }
  }

  /// 业务作用：在图片放大后响应单指或鼠标拖动，不把图片拖出可见边界。
  /// 参数说明：
  /// - `size`：当前可见图片区尺寸。
  /// 返回：只更新当前查看位移的拖动手势；适合窗口时保持居中。
  private func drag(in size: CGSize) -> some Gesture {
    DragGesture()
      .onChanged { value in
        guard pinchOrigin == nil, viewport.scale > ImageViewport.minimumScale else {
          return
        }
        if dragOrigin == nil {
          dragOrigin = viewport.offset
        }
        guard let origin = dragOrigin else {
          return
        }
        viewport.move(
          to: CGSize(
            width: origin.width + value.translation.width,
            height: origin.height + value.translation.height),
          imageSize: image.size, viewportSize: size)
      }
      .onEnded { value in
        dragOrigin = nil
        if !dragWasMagnified, pinchOrigin == nil,
          viewport.scale <= ImageViewport.minimumScale,
          let step = MediaSwipe.step(for: value.translation)
        {
          onNavigate(step)
        }
      }
  }

  /// 业务作用：还原为适合窗口并丢弃当前手势状态，关闭查看后不保留缩放记录。
  /// 参数说明：无。
  /// 返回：图片居中、倍率回到 100%，不写入磁盘或偏好设置。
  private func reset() {
    viewport = ImageViewport()
    pinchOrigin = nil
    dragOrigin = nil
    dragWasMagnified = false
  }
}

/// 图片缩放控制独立于画面布局，可叠加在统一相册的工具栏中。
struct VaultImageControls: View {
  @Binding var viewport: ImageViewport
  let imageSize: CGSize
  let viewportSize: CGSize

  /// 业务作用：向触摸与鼠标提供缩小、放大和还原操作，不额外占用媒体画面高度。
  /// 参数说明：无。
  /// 返回：当前查看的缩放按钮与百分比，不创建或保存图片副本。
  var body: some View {
    let size = viewportSize
    return HStack(spacing: 12) {
      control("缩小", symbol: "minus.magnifyingglass", disabled: viewport.scale <= 1) {
        zoom(by: 1 / 1.5, in: size)
      }
      Text("\(percentage)%")
        .font(.callout.monospacedDigit())
        .frame(minWidth: 48)
        .accessibilityLabel("图片缩放比例 \(percentage)%")
        .help("100% 表示适合当前查看区")
      control("放大", symbol: "plus.magnifyingglass", disabled: viewport.scale >= 8) {
        zoom(by: 1.5, in: size)
      }
      control("还原", symbol: "arrow.counterclockwise", disabled: viewport.scale <= 1) {
        viewport = ImageViewport()
      }
    }
    .frame(maxWidth: .infinity)
  }

  /// 业务作用：向用户显示相对适合查看区大小的当前倍率。
  /// 参数说明：无。
  /// 返回：仅用于当前界面的整数百分比。
  private var percentage: Int {
    Int((viewport.scale * 100).rounded())
  }

  /// 业务作用：为图片缩放操作提供当前平台合适的点击区域和辅助功能名称。
  /// 参数说明：
  /// - `title`：操作的可见名称。
  /// - `symbol`：表示该操作的系统图标。
  /// - `disabled`：达到倍率边界时拒绝无效操作。
  /// - `action`：当前查看中的缩放动作。
  /// 返回：iPhone 至少 44 点高、Mac 至少 28 点高的操作按钮。
  private func control(
    _ title: String, symbol: String, disabled: Bool, action: @escaping () -> Void
  ) -> some View {
    Button(action: action) {
      Label(title, systemImage: symbol)
        .font(.callout)
        .frame(minWidth: 44)
        #if os(iOS)
          .frame(minHeight: 44)
        #else
          .frame(minHeight: 28)
        #endif
        .contentShape(Rectangle())
    }
    .buttonStyle(.borderless)
    .accessibilityLabel(title + "图片")
    .disabled(disabled)
  }

  /// 业务作用：以查看区中心执行按钮缩放，不改变当前文件或创建其它图片副本。
  /// 参数说明：
  /// - `factor`：相对当前倍率的变化因子。
  /// - `size`：当前可见图片区尺寸。
  /// 返回：当前内存倍率与位置更新到允许范围。
  private func zoom(by factor: CGFloat, in size: CGSize) {
    viewport.magnify(
      to: viewport.scale * factor, around: .zero, imageSize: imageSize, viewportSize: size)
  }
}
