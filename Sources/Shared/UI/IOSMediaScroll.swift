import Foundation

/// 触控板滚动单独计次，不改变 iPhone 直接触摸的单指手势。
struct IndirectMediaPan {
  enum Phase {
    case began, changed, ended, cancelled
  }
  enum Action: Equatable {
    case navigate(Int)
    case pan(CGSize)
  }
  private var active = false
  private var panning = false
  private var previous = CGSize.zero

  /// 业务作用：把一次间接滚动转换为单次翻页或放大图片的增量平移。
  /// 参数说明：
  /// - `translation`：UIKit 提供的本次手势累计位移。
  /// - `phase`：当前手势阶段。
  /// - `zoomed`：开始滚动时是否正在查看放大的图片。
  /// 返回：抬手时最多翻一项；放大时只平移，取消或无效位移不产生切换。
  mutating func update(translation: CGSize, phase: Phase, zoomed: Bool) -> Action? {
    guard translation.width.isFinite, translation.height.isFinite, phase != .cancelled else {
      self = IndirectMediaPan()
      return nil
    }
    if phase == .began {
      self = IndirectMediaPan()
      active = true
      panning = zoomed
    }
    guard active else {
      return nil
    }
    let delta = CGSize(
      width: translation.width - previous.width,
      height: translation.height - previous.height)
    previous = translation
    let action: Action?
    if panning {
      action = .pan(delta)
    } else if phase == .ended, let step = MediaSwipe.step(for: translation) {
      action = .navigate(step)
    } else {
      action = nil
    }
    if phase == .ended {
      self = IndirectMediaPan()
    }
    return action
  }
}

#if os(iOS)
  import SwiftUI
  import UIKit

  /// 接收 Device Hub 或指针设备转发的滚动，不把它伪装成屏幕双指触摸。
  final class IOSMediaScrollView: UIView, UIGestureRecognizerDelegate {
    var enabled = false
    var zoomed = false
    var topInset: CGFloat = 0
    var bottomInset: CGFloat = 0
    var contentID: UUID?
    var gesture = IndirectMediaPan()
    var navigate: (Int) -> Void = { _ in }
    var pan: (CGSize) -> Void = { _ in }
    private weak var installedWindow: UIWindow?
    private(set) var scrollPan: UIPanGestureRecognizer!

    /// 业务作用：建立只接收连续滚动的识别器，保留屏幕单指与捏合的原有识别。
    /// 参数说明：
    /// - `frame`：当前媒体画布的初始区域。
    /// 返回：不参与点击命中的透明定位视图。
    override init(frame: CGRect) {
      super.init(frame: frame)
      isUserInteractionEnabled = false
      backgroundColor = .clear
      let recognizer = UIPanGestureRecognizer(target: self, action: #selector(receiveScroll(_:)))
      recognizer.allowedScrollTypesMask = .continuous
      recognizer.allowedTouchTypes = []
      recognizer.cancelsTouchesInView = false
      recognizer.delegate = self
      scrollPan = recognizer
    }

    /// 业务作用：拒绝从归档恢复媒体输入，避免旧事件重新取得查看权限。
    /// 参数说明：
    /// - `coder`：系统归档输入。
    /// 返回：始终拒绝归档初始化。
    required init?(coder: NSCoder) {
      return nil
    }

    /// 业务作用：随画布所属窗口挂接滚动，窗口变更前移除旧识别器。
    /// 参数说明：无。
    /// 返回：只在当前查看窗口内识别间接滚动，不安装系统或应用全局监听。
    override func didMoveToWindow() {
      super.didMoveToWindow()
      detach()
      if let window {
        window.addGestureRecognizer(scrollPan)
        installedWindow = window
      }
    }

    /// 业务作用：撤销当前窗口的滚动入口，丢弃未结束的手势。
    /// 参数说明：无。
    /// 返回：旧窗口不再能通过此识别器改变媒体选择。
    func detach() {
      installedWindow?.removeGestureRecognizer(scrollPan)
      installedWindow = nil
      gesture = IndirectMediaPan()
    }

    /// 业务作用：仅允许画面范围内的滚动开始，排除工具栏和媒体缩略图。
    /// 参数说明：
    /// - `point`：当前定位视图坐标中的位置。
    /// 返回：点位于有效媒体画布时为真。
    func containsCanvasPoint(_ point: CGPoint) -> Bool {
      bounds.contains(point) && point.y >= topInset && point.y < bounds.height - bottomInset
    }

    /// 业务作用：在滚动开始前复验窗口前台状态与画布范围，避免滚动控件时翻页。
    /// 参数说明：
    /// - `gestureRecognizer`：当前请求开始的识别器。
    /// 返回：仅当前前台画布中的自有识别器可开始。
    override func gestureRecognizerShouldBegin(_ gestureRecognizer: UIGestureRecognizer) -> Bool {
      guard enabled, gestureRecognizer === scrollPan,
        window?.windowScene?.activationState == .foregroundActive, !isHidden
      else {
        return false
      }
      return containsCanvasPoint(gestureRecognizer.location(in: self))
    }

    /// 业务作用：保持原有滚动控件与系统手势的识别，不独占屏幕直接触摸。
    /// 参数说明：
    /// - `gestureRecognizer`：当前滚动识别器。
    /// - `otherGestureRecognizer`：同一窗口中的其它识别器。
    /// 返回：允许同时识别；画布范围和输入类型仍由独立门禁限定。
    func gestureRecognizer(
      _ gestureRecognizer: UIGestureRecognizer,
      shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer
    ) -> Bool {
      true
    }

    /// 业务作用：处理当前间接滚动，翻页与图片平移都限定在本次仍有效的查看会话。
    /// 参数说明：
    /// - `recognizer`：只接收连续滚动的原生识别器。
    /// 返回：完成时最多切换一个项目；失去前台、取消和旧事件只清空手势。
    @objc private func receiveScroll(_ recognizer: UIPanGestureRecognizer) {
      guard enabled, window?.windowScene?.activationState == .foregroundActive else {
        gesture = IndirectMediaPan()
        return
      }
      let phase: IndirectMediaPan.Phase
      switch recognizer.state {
      case .began:
        phase = .began
      case .changed:
        phase = .changed
      case .ended:
        phase = .ended
      default:
        phase = .cancelled
      }
      let translation = recognizer.translation(in: self)
      let action = gesture.update(
        translation: CGSize(width: translation.x, height: translation.y),
        phase: phase,
        zoomed: zoomed)
      switch action {
      case .navigate(let step):
        navigate(step)
      case .pan(let delta):
        pan(delta)
      case nil:
        break
      }
    }
  }

  /// 将 iOS 间接滚动接到统一相册，直接触摸仍交给 SwiftUI 原有手势。
  struct IOSMediaScroll: UIViewRepresentable {
    let enabled: Bool
    let zoomed: Bool
    let topInset: CGFloat
    let bottomInset: CGFloat
    let contentID: UUID?
    let navigate: (Int) -> Void
    let pan: (CGSize) -> Void

    /// 业务作用：创建当前画布的原生滚动定位视图。
    /// 参数说明：
    /// - `context`：SwiftUI 生命周期上下文。
    /// 返回：透明视图，不遮挡单指、点击或捏合。
    func makeUIView(context: Context) -> IOSMediaScrollView {
      IOSMediaScrollView(frame: .zero)
    }

    /// 业务作用：更新当前媒体、倍率与工具栏范围，失权或切换媒体时撤销旧手势。
    /// 参数说明：
    /// - `view`：当前原生滚动定位视图。
    /// - `context`：SwiftUI 生命周期上下文。
    /// 返回：后续滚动只能操作当前媒体。
    func updateUIView(_ view: IOSMediaScrollView, context: Context) {
      if !enabled || view.contentID != contentID {
        view.gesture = IndirectMediaPan()
      }
      view.enabled = enabled
      view.scrollPan.isEnabled = enabled
      view.zoomed = zoomed
      view.topInset = topInset
      view.bottomInset = bottomInset
      view.contentID = contentID
      view.navigate = navigate
      view.pan = pan
    }

    /// 业务作用：画布拆除时移除窗口滚动识别器和所有输入回调。
    /// 参数说明：
    /// - `view`：需要拆除的定位视图。
    /// - `coordinator`：默认生命周期协调器。
    /// 返回：旧视图不再能切换媒体，不保留手势记录。
    static func dismantleUIView(_ view: IOSMediaScrollView, coordinator: ()) {
      view.enabled = false
      view.detach()
      view.navigate = { _ in }
      view.pan = { _ in }
    }
  }

  /// 底部工具实际高度用于限定 iOS 间接滚动的画布范围。
  enum IOSMediaFooterHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0

    /// 业务作用：收集控制条与缩略图栏高度，防止将其滚动误识别为翻页。
    /// 参数说明：
    /// - `value`：已收集的高度。
    /// - `nextValue`：当前布局的高度。
    /// 返回：本轮最大的工具高度。
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
      value = max(value, nextValue())
    }
  }
#endif
