#if os(macOS)
  import AppKit
  import SwiftUI

  /// 一次双指滚动只产生一次媒体切换，惯性与纵向滚动不参与翻页。
  struct MacMediaScrollGesture {
    private var tracking = false
    private var total = CGSize.zero
    private var vertical = false
    private var axisChosen = false
    private(set) var panning = false

    /// 业务作用：累积同一双指手势的明确横向位移，抬手后请求切换相邻媒体。
    /// 参数说明：
    /// - `delta`：已统一为手指方向的本次位移。
    /// - `phase`：手指接触、移动、结束或取消阶段。
    /// - `momentum`：手指离开后的惯性阶段。
    /// - `zoomed`：手势开始时是否应移动放大图片。
    /// 返回：有效左滑为下一项 1、右滑为上一项 -1；取消、纵向、惯性和放大拖动不翻页。
    mutating func consume(
      delta: CGSize, phase: NSEvent.Phase, momentum: NSEvent.Phase, zoomed: Bool
    ) -> Int? {
      guard momentum.isEmpty else {
        return nil
      }
      if phase.contains(.mayBegin) || phase.contains(.cancelled) {
        self = MacMediaScrollGesture()
        return nil
      }
      if phase.contains(.began) {
        self = MacMediaScrollGesture()
        tracking = true
        panning = zoomed
      }
      guard tracking, delta.width.isFinite, delta.height.isFinite else {
        self = MacMediaScrollGesture()
        return nil
      }
      total.width += delta.width
      total.height += delta.height
      if !axisChosen, max(abs(total.width), abs(total.height)) >= 8 {
        if abs(total.height) > abs(total.width) * 1.3 {
          vertical = true
          axisChosen = true
        } else if abs(total.width) > abs(total.height) * 1.3 {
          axisChosen = true
        }
      }
      guard phase.contains(.ended) else {
        return nil
      }
      let step = !panning && !vertical ? MediaSwipe.step(for: total) : nil
      self = MacMediaScrollGesture()
      return step
    }

    /// 业务作用：将系统滚动偏好转换为一致的手指左右方向，翻页不随自然滚动设置反转。
    /// 参数说明：
    /// - `delta`：系统给出的滚动位移。
    /// - `inverted`：系统是否已经按自然滚动偏好反转设备位移。
    /// 返回：左侧位移为负、右侧位移为正的手指方向。
    static func fingerDelta(_ delta: CGSize, inverted: Bool) -> CGSize {
      let factor: CGFloat = inverted ? 1 : -1
      return CGSize(
        width: delta.width * factor,
        height: delta.height * factor)
    }
  }

  /// 透明视图只接收当前媒体画布内的双指滚动，其它输入继续交给 SwiftUI。
  final class MacMediaScrollView: NSView {
    var enabled = false
    var zoomed = false
    var topInset: CGFloat = 0
    var bottomInset: CGFloat = 0
    var contentID: UUID?
    var gesture = MacMediaScrollGesture()
    var navigate: (Int) -> Void = { _ in }
    var pan: (CGSize) -> Void = { _ in }

    /// 业务作用：使用与 SwiftUI 一致的顶部坐标排除浮动工具栏。
    /// 参数说明：无。
    /// 返回：顶部为纵坐标原点。
    override var isFlipped: Bool {
      true
    }

    /// 业务作用：只在画布中接管带阶段的精确滚动，不遮挡点击、双击、鼠标拖动和捏合。
    /// 参数说明：
    /// - `point`：父视图坐标中的事件位置。
    /// 返回：符合双指滚动条件时为当前画布接收器，其它事件透传给原视图。
    override func hitTest(_ point: NSPoint) -> NSView? {
      guard enabled, !isHiddenOrHasHiddenAncestor,
        let event = NSApp.currentEvent, event.type == .scrollWheel,
        event.hasPreciseScrollingDeltas,
        !event.phase.isEmpty || !event.momentumPhase.isEmpty
      else {
        return nil
      }
      let local = convert(point, from: superview)
      // 缩略图栏和控制条保留自己的滚动行为，不能在操作它们时切换当前媒体。
      guard containsCanvasPoint(local) else {
        return nil
      }
      return self
    }

    /// 业务作用：把顶部操作与底部控制、缩略图排除在画布翻页范围之外。
    /// 参数说明：
    /// - `point`：当前画布坐标中的位置。
    /// 返回：位置位于可滚动媒体区域时为真，工具栏或无效布局为假。
    func containsCanvasPoint(_ point: NSPoint) -> Bool {
      bounds.contains(point) && point.y >= topInset && point.y < bounds.height - bottomInset
    }

    /// 业务作用：在当前前台媒体内识别双指翻页，放大图片时改为平移，惯性不连续跳项。
    /// 参数说明：
    /// - `event`：系统交给当前画布的精确滚动事件。
    /// 返回：最多在本次抬手时切换一项；窗口失去前台后立即丢弃手势。
    override func scrollWheel(with event: NSEvent) {
      guard enabled, NSApp.isActive, window?.isKeyWindow == true,
        event.hasPreciseScrollingDeltas
      else {
        gesture = MacMediaScrollGesture()
        return
      }
      let delta = CGSize(
        width: event.scrollingDeltaX,
        height: event.scrollingDeltaY)
      let panning = gesture.panning || (event.phase.contains(.began) && zoomed)
      let step = gesture.consume(
        delta: MacMediaScrollGesture.fingerDelta(
          delta, inverted: event.isDirectionInvertedFromDevice),
        phase: event.phase,
        momentum: event.momentumPhase,
        zoomed: zoomed)
      if panning, event.momentumPhase.isEmpty, !event.phase.contains(.cancelled) {
        pan(delta)
      }
      if let step {
        navigate(step)
      }
    }
  }

  /// 只在 Mac 查看画布挂接原生双指滚动，不安装系统或应用全局事件监听。
  struct MacMediaTrackpad: NSViewRepresentable {
    let enabled: Bool
    let zoomed: Bool
    let topInset: CGFloat
    let bottomInset: CGFloat
    let contentID: UUID?
    let navigate: (Int) -> Void
    let pan: (CGSize) -> Void

    /// 业务作用：创建只属于当前媒体视图的原生滚动接收器。
    /// 参数说明：
    /// - `context`：SwiftUI 生命周期上下文。
    /// 返回：透明画布，不创建媒体路径、访问记录或全局监听。
    func makeNSView(context: Context) -> MacMediaScrollView {
      MacMediaScrollView()
    }

    /// 业务作用：同步当前授权、图片倍率与工具栏范围，切换媒体后撤销旧手势。
    /// 参数说明：
    /// - `view`：当前画布的滚动接收器。
    /// - `context`：SwiftUI 生命周期上下文。
    /// 返回：后续事件只能作用于当前仍可查看的媒体。
    func updateNSView(_ view: MacMediaScrollView, context: Context) {
      if !enabled || view.contentID != contentID {
        view.gesture = MacMediaScrollGesture()
      }
      view.enabled = enabled
      view.zoomed = zoomed
      view.topInset = topInset
      view.bottomInset = bottomInset
      view.contentID = contentID
      view.navigate = navigate
      view.pan = pan
    }

    /// 业务作用：画布离开时撤销输入回调和未完成手势，不向后续查看交付旧事件。
    /// 参数说明：
    /// - `view`：需要拆除的滚动接收器。
    /// - `coordinator`：默认生命周期协调器。
    /// 返回：当前原生视图不再能改变媒体选择或图片位置。
    static func dismantleNSView(_ view: MacMediaScrollView, coordinator: ()) {
      view.enabled = false
      view.gesture = MacMediaScrollGesture()
      view.navigate = { _ in }
      view.pan = { _ in }
    }
  }

  /// 底部工具的实际高度用于排除触控板翻页区域。
  enum MacMediaFooterHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0

    /// 业务作用：保留当前底部工具的完整高度，避免媒体滚动接收器覆盖控件。
    /// 参数说明：
    /// - `value`：已经收集的底部工具高度。
    /// - `nextValue`：本轮布局给出的高度。
    /// 返回：本轮最大的工具高度。
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
      value = max(value, nextValue())
    }
  }
#endif
