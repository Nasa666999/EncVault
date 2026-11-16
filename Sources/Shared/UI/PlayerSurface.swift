@preconcurrency import AVFoundation
import SwiftUI
@preconcurrency import VLCKit

#if os(macOS)
  import AppKit

  /// 只承载画面层，不接入系统播放器控制器和文档恢复。
  final class VaultVideoView: NSView, NSGestureRecognizerDelegate {
    let videoLayer = AVPlayerLayer()
    let compatibilityView = VLCVideoView()
    weak var playback: LocalPlayback?
    var onScrub: (Double?) -> Void = { _ in }
    private(set) var scrubPan: NSPanGestureRecognizer!
    private var scrubOrigin: (position: Double, duration: Double, width: CGFloat)?
    private var horizontalScrub = false

    /// 业务作用：创建仅供当前保险箱会话使用的媒体画面，接收鼠标左键横向进度预览。
    /// 参数说明：
    /// - `frameRect`：初始画面区域。
    /// 返回：没有媒体地址和历史记录的画面层。
    override init(frame frameRect: NSRect) {
      super.init(frame: frameRect)
      wantsLayer = true
      layer?.backgroundColor = NSColor.black.cgColor
      videoLayer.videoGravity = .resizeAspect
      layer?.addSublayer(videoLayer)
      compatibilityView.isHidden = true
      compatibilityView.backColor = .black
      compatibilityView.fillScreen = false
      addSubview(compatibilityView)
      let pan = NSPanGestureRecognizer(target: self, action: #selector(receiveScrub(_:)))
      pan.buttonMask = 0x1
      pan.allowedTouchTypes = []
      pan.delegate = self
      pan.isEnabled = false
      addGestureRecognizer(pan)
      scrubPan = pan
    }

    /// 业务作用：拒绝从归档恢复媒体画面。
    /// 参数说明：
    /// - `coder`：系统提供的归档输入。
    /// 返回：始终拒绝恢复，媒体必须重新解锁并主动选择。
    required init?(coder: NSCoder) {
      return nil
    }

    /// 业务作用：随窗口大小调整当前画面，不保存媒体位置。
    /// 参数说明：无。
    /// 返回：画面层覆盖当前可用区域。
    override func layout() {
      super.layout()
      // 窗口布局只调整现有画面边界，不为连续进度刷新引入隐式图层动画。
      CATransaction.begin()
      CATransaction.setDisableActions(true)
      videoLayer.frame = bounds
      compatibilityView.frame = bounds
      CATransaction.commit()
    }

    /// 业务作用：允许在当前视频画面第一次按下左键时就开始拖动，不丢失本次起点。
    /// 参数说明：
    /// - `event`：用户按下鼠标按钮的事件。
    /// 返回：已开放定位时接收左键，其他输入沿用系统的窗口激活行为。
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool {
      if event?.buttonNumber == 0, scrubPan?.isEnabled == true {
        return true
      }
      return super.acceptsFirstMouse(for: event)
    }

    /// 业务作用：仅让当前已绑定的视频画面接收鼠标左键拖动，方向由实际位移判定。
    /// 参数说明：
    /// - `gestureRecognizer`：请求开始的画面手势。
    /// 返回：当前画面和时长有效时开始追踪，不依赖识别开始前尚未建立的速度值。
    func gestureRecognizerShouldBegin(_ gestureRecognizer: NSGestureRecognizer) -> Bool {
      guard gestureRecognizer === scrubPan, window != nil, !isHiddenOrHasHiddenAncestor,
        let playback, playback.duration.isFinite, playback.duration > 0,
        playback.position.isFinite, bounds.width.isFinite, bounds.width > 0
      else {
        return false
      }
      return true
    }

    /// 业务作用：让画面点击与横向拖动分别识别，保留工具栏显隐和双击全屏入口。
    /// 参数说明：
    /// - `gestureRecognizer`：当前画面手势。
    /// - `otherGestureRecognizer`：同一鼠标事件序列中的其它手势。
    /// 返回：允许同时识别，定位仍只接收鼠标左键拖动。
    func gestureRecognizer(
      _ gestureRecognizer: NSGestureRecognizer,
      shouldRecognizeSimultaneouslyWith otherGestureRecognizer: NSGestureRecognizer
    ) -> Bool {
      true
    }

    /// 业务作用：撤销未完成的进度预览，防止切换媒体或拆除画面后提交旧手势。
    /// 参数说明：
    /// - `notify`：是否通知当前查看区撤下预览；视图重新绑定时由查看区清空。
    /// 返回：取消当前识别且不跳转，后续拖动从新的播放位置开始。
    func cancelScrub(notify: Bool = true) {
      let hadPreview = horizontalScrub
      scrubOrigin = nil
      horizontalScrub = false
      let enabled = scrubPan.isEnabled
      scrubPan.isEnabled = false
      scrubPan.isEnabled = enabled
      if hadPreview && notify {
        onScrub(nil)
      }
    }

    /// 业务作用：鼠标左键拖动期间连续预览当前视频进度，正常松开时提交一次定位。
    /// 参数说明：
    /// - `recognizer`：仅接收左键拖动的画面识别器。
    /// 返回：以开始时的进度和画面宽度计算目标，取消、撤下画面或布局变化时放弃定位。
    @objc private func receiveScrub(_ recognizer: NSPanGestureRecognizer) {
      // 只接收当前画面的鼠标事件，撤下或隐藏画面后旧拖动不得继续发布进度。
      guard let playback, window != nil, !isHiddenOrHasHiddenAncestor else {
        cancelScrub()
        return
      }
      switch recognizer.state {
      case .began:
        scrubOrigin = (playback.position, playback.duration, bounds.width)
        horizontalScrub = false
      case .changed, .ended:
        break
      default:
        cancelScrub()
        return
      }
      // 调整窗口后原坐标不再可靠，放弃旧目标以免跳到错误位置。
      guard let origin = scrubOrigin, origin.width == bounds.width,
        origin.width.isFinite, origin.width > 0,
        origin.position.isFinite, origin.duration.isFinite, origin.duration > 0
      else {
        cancelScrub()
        return
      }
      let translation = recognizer.translation(in: self)
      guard translation.x.isFinite, translation.y.isFinite else {
        cancelScrub()
        return
      }
      if !horizontalScrub {
        if abs(translation.y) >= 8, abs(translation.y) > abs(translation.x) * 1.3 {
          cancelScrub()
          return
        }
        guard abs(translation.x) >= 8, abs(translation.x) > abs(translation.y) * 1.3 else {
          if recognizer.state == .ended {
            cancelScrub()
          }
          return
        }
        horizontalScrub = true
      }
      // 固定本次拖动的起点，播放采样与往返拖动都不能累加改变定位基准。
      let fraction = Double(min(1, max(-1, translation.x / origin.width)))
      let target = min(
        origin.duration, max(0, origin.position + fraction * min(origin.duration, 120)))
      onScrub(target)
      if recognizer.state == .ended {
        scrubOrigin = nil
        horizontalScrub = false
        playback.seek(target)
        onScrub(nil)
      }
    }
  }

  struct PlayerSurface: NSViewRepresentable {
    @ObservedObject var playback: LocalPlayback
    var scrubbingEnabled = false
    var onScrub: (Double?) -> Void = { _ in }

    /// 业务作用：连接当前会话播放器与自有画面层。
    /// 参数说明：
    /// - `context`：SwiftUI 的视图生命周期上下文。
    /// 返回：只显示当前播放器的原生视图。
    func makeNSView(context: Context) -> VaultVideoView {
      let view = VaultVideoView(frame: .zero)
      bind(view)
      return view
    }

    /// 业务作用：维持当前播放器绑定，不引入系统媒体控制器。
    /// 参数说明：
    /// - `view`：当前原生画面。
    /// - `context`：SwiftUI 的视图生命周期上下文。
    /// 返回：当前画面绑定更新完成。
    func updateNSView(_ view: VaultVideoView, context: Context) {
      bind(view)
    }

    /// 业务作用：在同一画面绑定解码器与左键进度手势，媒体变化时撤销旧拖动。
    /// 参数说明：
    /// - `view`：当前查看区的原生画面。
    /// 返回：只有当前采用的解码器可以绘制视频。
    private func bind(_ view: VaultVideoView) {
      // 更换媒体或关闭交互时先撤销旧识别，后续事件只能访问新绑定的播放器。
      if view.playback !== playback || !scrubbingEnabled {
        view.cancelScrub(notify: false)
      }
      view.playback = playback
      view.onScrub = onScrub
      if view.scrubPan.isEnabled != scrubbingEnabled {
        view.scrubPan.isEnabled = scrubbingEnabled
      }
      let compatible = playback.compatiblePlayer != nil
      view.videoLayer.isHidden = compatible
      let player = compatible ? nil : playback.player
      // 进度采样与拖动预览会频繁刷新视图，同一播放器不能反复重新挂接画面层。
      if view.videoLayer.player !== player {
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        view.videoLayer.player = player
        CATransaction.commit()
      }
      view.compatibilityView.isHidden = !compatible
      if compatible {
        playback.attachCompatibility(to: view.compatibilityView)
      }
    }

    /// 业务作用：视图离开时解除播放器引用，避免残留解码画面。
    /// 参数说明：
    /// - `view`：需要拆除的画面。
    /// - `coordinator`：默认生命周期协调器。
    /// 返回：画面层不再持有播放器。
    static func dismantleNSView(_ view: VaultVideoView, coordinator: ()) {
      view.cancelScrub(notify: false)
      view.scrubPan.isEnabled = false
      view.playback = nil
      view.onScrub = { _ in }
      view.videoLayer.player = nil
      view.compatibilityView.removeFromSuperview()
    }
  }
#else
  import UIKit

  /// 视频方向只属于当前查看会话，不写入偏好、文档恢复或播放记录。
  @MainActor
  final class VaultVideoOrientation {
    static let shared = VaultVideoOrientation()
    private(set) var supported: UIInterfaceOrientationMask = .allButUpsideDown
    private(set) var active = false
    private var previous: UIInterfaceOrientation = .portrait
    private var requested: UIInterfaceOrientation = .landscapeRight

    /// 业务作用：取得承载当前前台保险箱窗口的场景，避免旋转其它窗口。
    /// 参数说明：无。
    /// 返回：当前前台窗口场景；应用不在前台时为空。
    private var scene: UIWindowScene? {
      UIApplication.shared.connectedScenes.compactMap {
        $0 as? UIWindowScene
      }.first {
        $0.activationState == .foregroundActive
      }
    }

    /// 业务作用：首次进入视频全屏时沿用已有横屏或根据持机方向选择横屏。
    /// 参数说明：无。
    /// 返回：只调整窗口方向，当前播放器、解密读取器和播放进度保持不变。
    func enter() {
      guard !active else {
        return
      }
      previous = scene?.interfaceOrientation ?? .portrait
      active = true
      supported = .landscape
      UIDevice.current.beginGeneratingDeviceOrientationNotifications()
      apply(deviceLandscape ?? (previous.isLandscape ? previous : .landscapeRight))
    }

    /// 业务作用：在视频全屏期间跟随两种有效持机横屏方向，忽略平放和竖屏噪声。
    /// 参数说明：无。
    /// 返回：方向发生变化时旋转同一窗口，不退出视频全屏。
    func followDevice() {
      guard active, let direction = deviceLandscape, direction != requested else {
        return
      }
      apply(direction)
    }

    /// 业务作用：为锁定系统旋转或不同握持习惯提供可重复点击的手动横屏切换。
    /// 参数说明：无。
    /// 返回：首次点击进入横屏，之后每次在左横屏与右横屏之间交替。
    func cycle() {
      if !active {
        enter()
        return
      }
      apply(requested == .landscapeLeft ? .landscapeRight : .landscapeLeft)
    }

    /// 业务作用：离开视频全屏或失去会话后恢复普通屏幕方向权限。
    /// 参数说明：无。
    /// 返回：结束持机监听，恢复进入前的方向，不保留上次播放方向。
    func leave() {
      guard active else {
        return
      }
      active = false
      supported = .allButUpsideDown
      UIDevice.current.endGeneratingDeviceOrientationNotifications()
      apply(previous == .unknown || previous == .portraitUpsideDown ? .portrait : previous)
      previous = .portrait
    }

    /// 业务作用：区分设备物理方向与界面方向相反的枚举约定。
    /// 参数说明：无。
    /// 返回：手机当前左、右横持对应的界面方向；其它姿态为空。
    private var deviceLandscape: UIInterfaceOrientation? {
      switch UIDevice.current.orientation {
      case .landscapeLeft:
        return .landscapeRight
      case .landscapeRight:
        return .landscapeLeft
      default:
        return nil
      }
    }

    /// 业务作用：通过系统公开场景接口请求窗口旋转，保持现有媒体实例。
    /// 参数说明：
    /// - `direction`：本次明确选择的界面方向。
    /// 返回：前台窗口提交方向请求；系统拒绝时仍可旋转手机或再次点击方向按钮。
    private func apply(_ direction: UIInterfaceOrientation) {
      requested = direction
      guard let scene else {
        return
      }
      for window in scene.windows {
        window.rootViewController?.setNeedsUpdateOfSupportedInterfaceOrientations()
      }
      let mask = UIInterfaceOrientationMask(rawValue: 1 << direction.rawValue)
      scene.requestGeometryUpdate(.iOS(interfaceOrientations: mask)) { _ in }
    }
  }

  /// 将当前视频会话的方向权限交给 UIKit，普通浏览仍允许竖屏和两种横屏。
  @MainActor
  final class VaultIOSApplicationDelegate: NSObject, UIApplicationDelegate {
    /// 业务作用：在视频全屏期间开放左右横屏，退出后恢复普通方向集合。
    /// 参数说明：
    /// - `application`：当前应用。
    /// - `window`：系统正在查询方向的窗口。
    /// 返回：仅属于当前内存会话的方向权限。
    func application(
      _ application: UIApplication, supportedInterfaceOrientationsFor window: UIWindow?
    ) -> UIInterfaceOrientationMask {
      VaultVideoOrientation.shared.supported
    }
  }

  final class VaultVideoView: UIView, UIGestureRecognizerDelegate {
    let compatibilityView = UIView()
    weak var playback: LocalPlayback?
    var onScrub: (Double?) -> Void = { _ in }
    private(set) var scrubPan: UIPanGestureRecognizer!
    private var scrubOrigin: (position: Double, duration: Double, width: CGFloat)?

    /// 业务作用：创建当前视频的两种自有画面承载层，接收单指横向进度预览。
    /// 参数说明：
    /// - `frame`：当前初始画面区域。
    /// 返回：默认只开放系统画面，兼容画面等待明确绑定。
    override init(frame: CGRect) {
      super.init(frame: frame)
      compatibilityView.backgroundColor = .black
      compatibilityView.isHidden = true
      addSubview(compatibilityView)
      let pan = UIPanGestureRecognizer(target: self, action: #selector(receiveScrub(_:)))
      pan.minimumNumberOfTouches = 1
      pan.maximumNumberOfTouches = 1
      pan.allowedTouchTypes = [NSNumber(value: UITouch.TouchType.direct.rawValue)]
      pan.delegate = self
      pan.isEnabled = false
      addGestureRecognizer(pan)
      scrubPan = pan
    }

    /// 业务作用：拒绝归档恢复过去的视频画面。
    /// 参数说明：
    /// - `coder`：系统提供的归档输入。
    /// 返回：始终拒绝，视频必须在解锁后重新选择。
    required init?(coder: NSCoder) {
      return nil
    }

    /// 业务作用：窗口旋转和全屏切换时让兼容画面跟随完整可用区域。
    /// 参数说明：无。
    /// 返回：两种解码画面使用相同的可见区域。
    override func layoutSubviews() {
      super.layoutSubviews()
      compatibilityView.frame = bounds
    }
    /// 业务作用：使用应用自有画面层承载当前视频，不引入系统播放控制器。
    /// 参数说明：无。
    /// 返回：支持当前会话播放器绑定的 AVPlayerLayer 类型。
    override class var layerClass: AnyClass {
      AVPlayerLayer.self
    }

    /// 业务作用：仅让当前前台视频中的单指横向拖动取得进度预览权限。
    /// 参数说明：
    /// - `gestureRecognizer`：请求开始的画面手势。
    /// 返回：时长和画面有效且主要横向移动时允许开始，纵向操作不改变进度。
    override func gestureRecognizerShouldBegin(_ gestureRecognizer: UIGestureRecognizer) -> Bool {
      guard gestureRecognizer === scrubPan,
        window?.windowScene?.activationState == .foregroundActive,
        let playback, playback.duration.isFinite, playback.duration > 0,
        playback.position.isFinite, bounds.width.isFinite, bounds.width > 0
      else {
        return false
      }
      let velocity = scrubPan.velocity(in: self)
      return velocity.x.isFinite && velocity.y.isFinite
        && abs(velocity.x) > abs(velocity.y) * 1.3
    }

    /// 业务作用：让画面的点击与横向拖动分别识别，保留工具栏显隐和双击全屏入口。
    /// 参数说明：
    /// - `gestureRecognizer`：当前画面手势。
    /// - `otherGestureRecognizer`：同一触摸序列中的其它手势。
    /// 返回：允许同时识别，直接拖动仍限制为单指。
    func gestureRecognizer(
      _ gestureRecognizer: UIGestureRecognizer,
      shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer
    ) -> Bool {
      true
    }

    /// 业务作用：撤销未完成的进度预览，防止切换媒体或拆除画面后提交旧手势。
    /// 参数说明：
    /// - `notify`：是否通知当前查看区撤下预览；视图重新绑定时由查看区清空。
    /// 返回：取消当前识别且不跳转，后续触摸从新的播放位置开始。
    func cancelScrub(notify: Bool = true) {
      let hadPreview = scrubOrigin != nil
      scrubOrigin = nil
      let enabled = scrubPan.isEnabled
      scrubPan.isEnabled = false
      scrubPan.isEnabled = enabled
      if hadPreview && notify {
        onScrub(nil)
      }
    }

    /// 业务作用：滑动期间连续预览当前视频进度，只有正常抬手才提交一次播放定位。
    /// 参数说明：
    /// - `recognizer`：仅接收屏幕单指触摸的画面拖动识别器。
    /// 返回：以开始时的进度和画面宽度计算目标，取消、失去前台或画面变化时放弃定位。
    @objc private func receiveScrub(_ recognizer: UIPanGestureRecognizer) {
      // 失去前台或播放器绑定后，旧手势不得继续发布进度或恢复播放。
      guard let playback, window?.windowScene?.activationState == .foregroundActive else {
        cancelScrub()
        return
      }
      switch recognizer.state {
      case .began:
        scrubOrigin = (playback.position, playback.duration, bounds.width)
      case .changed, .ended:
        break
      default:
        cancelScrub()
        return
      }
      // 旋转或重排画面后旧坐标不再可靠，放弃旧目标以免跳到错误位置。
      guard let origin = scrubOrigin, origin.width == bounds.width,
        origin.width.isFinite, origin.width > 0,
        origin.position.isFinite, origin.duration.isFinite, origin.duration > 0
      else {
        cancelScrub()
        return
      }
      let translation = recognizer.translation(in: self).x
      guard translation.isFinite else {
        cancelScrub()
        return
      }
      // 固定本次滑动的起点，连续播放采样和往返拖动都不能累加改变定位基准。
      let fraction = Double(min(1, max(-1, translation / origin.width)))
      let target = min(
        origin.duration, max(0, origin.position + fraction * min(origin.duration, 120)))
      onScrub(target)
      if recognizer.state == .ended {
        scrubOrigin = nil
        playback.seek(target)
        onScrub(nil)
      }
    }
  }

  struct PlayerSurface: UIViewRepresentable {
    @ObservedObject var playback: LocalPlayback
    var scrubbingEnabled = false
    var onScrub: (Double?) -> Void = { _ in }

    /// 业务作用：连接当前会话播放器与自有画面层。
    /// 参数说明：
    /// - `context`：SwiftUI 的视图生命周期上下文。
    /// 返回：只显示当前播放器的原生视图。
    func makeUIView(context: Context) -> VaultVideoView {
      let view = VaultVideoView()
      view.backgroundColor = .black
      (view.layer as? AVPlayerLayer)?.videoGravity = .resizeAspect
      bind(view)
      return view
    }

    /// 业务作用：维持当前播放器绑定，不引入系统媒体控制器。
    /// 参数说明：
    /// - `view`：当前原生画面。
    /// - `context`：SwiftUI 的视图生命周期上下文。
    /// 返回：当前画面绑定更新完成。
    func updateUIView(_ view: VaultVideoView, context: Context) {
      bind(view)
    }

    /// 业务作用：在当前应用画面中绑定解码器与进度手势，媒体变化时撤销旧手势。
    /// 参数说明：
    /// - `view`：当前查看区的原生画面。
    /// 返回：当前采用的解码器完成绑定，只有仍开放交互的画面可以预览进度。
    private func bind(_ view: VaultVideoView) {
      // 更换媒体或关闭交互时先撤销旧识别，后续事件只能访问新绑定的播放器。
      if view.playback !== playback || !scrubbingEnabled {
        view.cancelScrub(notify: false)
      }
      view.playback = playback
      view.onScrub = onScrub
      if view.scrubPan.isEnabled != scrubbingEnabled {
        view.scrubPan.isEnabled = scrubbingEnabled
      }
      let compatible = playback.compatiblePlayer != nil
      let layer = view.layer as? AVPlayerLayer
      let player = compatible ? nil : playback.player
      // 预览进度变化只更新控制栏，保持原画面层绑定，避免重复挂接触发画面重绘。
      if layer?.player !== player {
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        layer?.player = player
        CATransaction.commit()
      }
      view.compatibilityView.isHidden = !compatible
      if compatible {
        playback.attachCompatibility(to: view.compatibilityView)
      }
    }

    /// 业务作用：离开查看时解除画面层引用。
    /// 参数说明：
    /// - `view`：需要拆除的画面。
    /// - `coordinator`：默认生命周期协调器。
    /// 返回：画面层不再持有播放器。
    static func dismantleUIView(_ view: VaultVideoView, coordinator: ()) {
      view.cancelScrub(notify: false)
      view.scrubPan.isEnabled = false
      view.playback = nil
      view.onScrub = { _ in }
      (view.layer as? AVPlayerLayer)?.player = nil
      view.compatibilityView.removeFromSuperview()
    }
  }
#endif

/// 播放控制只保存于当前视图内存，不登记系统播放信息。
struct VaultPlayerControls: View {
  @ObservedObject var playback: LocalPlayback
  let fullScreen: Bool
  let toggleFullScreen: () -> Void
  var rotateVideo: (() -> Void)? = nil
  var previewPosition: Double? = nil
  @State private var scrub: Double = 0
  @State private var dragging = false

  /// 业务作用：提供当前查看的拖动进度，手机将操作按钮交给右侧浮动栏以保留完整拖动宽度。
  /// 参数说明：无。
  /// 返回：可叠加在相册画面上的控制条，不创建系统媒体控制器。
  var body: some View {
    VStack(spacing: 4) {
      #if os(iOS)
        VStack(spacing: 0) {
          progressControls
            .frame(minHeight: 44)
          playbackTime
            .frame(maxWidth: .infinity, alignment: .trailing)
        }
      #else
        HStack {
          Button {
            playback.toggle()
          } label: {
            Text(playback.playing ? "暂停" : "播放")
          }
          progressControls
          playbackTime
          Button {
            playback.looping.toggle()
          } label: {
            Image(systemName: "repeat.1")
              .foregroundStyle(playback.looping ? Color.accentColor : .secondary)
              .frame(width: 28, height: 24)
              .background(
                Color.accentColor.opacity(playback.looping ? 0.15 : 0),
                in: RoundedRectangle(cornerRadius: 8)
              )
              .contentShape(Rectangle())
          }
          .buttonStyle(.borderless)
          .help("循环播放当前视频")
          .accessibilityLabel("循环播放")
          .accessibilityValue(playback.looping ? "已开启" : "已关闭")
          if let rotateVideo {
            Button(action: rotateVideo) {
              Image(systemName: "rotate.right")
                .frame(width: 44, height: 44)
                .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("切换横屏方向")
            .help("左横屏／右横屏")
          }
          Button(action: toggleFullScreen) {
            Image(
              systemName: fullScreen
                ? "arrow.down.right.and.arrow.up.left" : "arrow.up.left.and.arrow.down.right"
            )
            .frame(width: 28, height: 24)
            .contentShape(Rectangle())
          }
          .buttonStyle(.borderless)
          .help(fullScreen ? "退出全屏（Esc）" : "全屏")
          .accessibilityLabel(fullScreen ? "退出全屏" : "全屏")
          .keyboardShortcut(fullScreen ? KeyboardShortcut(.escape, modifiers: []) : nil)
        }
      #endif
      if let failure = playback.failure {
        Text(failure).foregroundStyle(.red)
      }
    }
    .onAppear {
      // 新建控件时沿用当前会话位置，暂停或布局变化时也不能把滑块显示为起点。
      scrub = previewPosition ?? playback.position
    }
    .onChange(of: playback.position) { _, value in
      if !dragging && previewPosition == nil {
        scrub = value
      }
    }
    .onChange(of: previewPosition) { _, value in
      scrub = value ?? playback.position
    }
  }

  /// 业务作用：在滑块两侧提供固定步长定位，便于触摸或鼠标反复微调播放位置。
  /// 参数说明：无。
  /// 返回：回退五秒、当前进度及前进十五秒组成的水平定位区。
  private var progressControls: some View {
    HStack(spacing: 4) {
      seekButton(forward: false)
      progressSlider
      seekButton(forward: true)
    }
  }

  /// 业务作用：按用户明确选择的方向定位当前视频，保留原有播放或暂停意图。
  /// 参数说明：
  /// - `forward`：为真时前进十五秒，为假时回退五秒。
  /// 返回：当前查看有效且时长已知时可点击的定位按钮；边界由播放器限制在有效时长内。
  private func seekButton(forward: Bool) -> some View {
    Button {
      playback.seek(playback.position + (forward ? 15 : -5))
    } label: {
      Image(systemName: forward ? "plus" : "minus")
        #if os(macOS)
          .frame(width: 28, height: 24)
        #else
          .frame(width: 44, height: 44)
        #endif
        .contentShape(Rectangle())
    }
    .buttonStyle(.borderless)
    .accessibilityLabel(forward ? "前进15秒" : "回退5秒")
    .help(forward ? "前进 15 秒" : "回退 5 秒")
    .disabled(dragging || previewPosition != nil || playback.duration <= 0)
  }

  /// 业务作用：实时显示滑块或画面拖动的预览位置，抬手后才定位视频。
  /// 参数说明：无。
  /// 返回：属于当前播放器的进度滑块，未知时长时禁用定位。
  private var progressSlider: some View {
    Slider(
      value: Binding(
        get: { previewPosition ?? scrub },
        set: { scrub = $0 }),
      in: 0...max(1, playback.duration),
      onEditingChanged: { editing in
        dragging = editing
        if !editing {
          playback.seek(scrub)
        }
      }
    )
    .accessibilityLabel("播放进度")
    .disabled(playback.duration <= 0)
    .allowsHitTesting(previewPosition == nil)
  }

  /// 业务作用：与滑块同步显示当前或预览时间，不占用手机进度滑块的水平空间。
  /// 参数说明：无。
  /// 返回：等宽数字时间标签，未知总时长时显示明确状态。
  private var playbackTime: some View {
    Text(
      playback.duration > 0
        ? "\(time(previewPosition ?? scrub)) / \(time(playback.duration))"
        : "\(time(playback.position)) · 时长未知"
    )
    .monospacedDigit().font(.caption)
  }

  /// 业务作用：将当前内存中的进度表示为播放器时间标签。
  /// 参数说明：
  /// - `value`：本次查看中的秒数。
  /// 返回：分钟和秒数，不持久化该值。
  private func time(_ value: Double) -> String {
    let seconds = value.isFinite ? Int(max(0, value)) : 0
    return String(format: "%d:%02d", seconds / 60, seconds % 60)
  }
}

#if os(iOS)
  /// 手机的视频操作独立叠加在画面右侧，底部进度条保留完整宽度。
  struct VaultPlayerActions: View {
    @ObservedObject var playback: LocalPlayback
    let fullScreen: Bool
    let toggleFullScreen: () -> Void
    var rotateVideo: (() -> Void)? = nil

    /// 业务作用：以竖排触摸按钮控制同一视频会话，不因旋转或显示控制栏而重建播放器。
    /// 参数说明：无。
    /// 返回：播放、循环、横屏和全屏入口，保持独立的辅助功能名称及触摸范围。
    var body: some View {
      VStack(spacing: 0) {
        Button {
          playback.toggle()
        } label: {
          Image(systemName: playback.playing ? "pause.fill" : "play.fill")
            .frame(width: 44, height: 44)
            .contentShape(Rectangle())
        }
        .accessibilityLabel(playback.playing ? "暂停" : "播放")
        Button {
          playback.looping.toggle()
        } label: {
          Image(systemName: "repeat.1")
            .foregroundStyle(playback.looping ? Color.accentColor : .white)
            .frame(width: 44, height: 44)
            .background(
              Color.accentColor.opacity(playback.looping ? 0.15 : 0),
              in: RoundedRectangle(cornerRadius: 8)
            )
            .contentShape(Rectangle())
        }
        .accessibilityLabel("循环播放")
        .accessibilityValue(playback.looping ? "已开启" : "已关闭")
        if let rotateVideo {
          Button(action: rotateVideo) {
            Image(systemName: "rotate.right")
              .frame(width: 44, height: 44)
              .contentShape(Rectangle())
          }
          .accessibilityLabel("切换横屏方向")
        }
        Button(action: toggleFullScreen) {
          Image(
            systemName: fullScreen
              ? "arrow.down.right.and.arrow.up.left" : "arrow.up.left.and.arrow.down.right"
          )
          .frame(width: 44, height: 44)
          .contentShape(Rectangle())
        }
        .accessibilityLabel(fullScreen ? "退出全屏" : "全屏")
      }
      .font(.system(size: 18, weight: .medium))
      .foregroundStyle(.white)
      .buttonStyle(.borderless)
      .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14))
      .accessibilityElement(children: .contain)
      .accessibilityLabel("视频播放操作")
    }
  }
#endif
