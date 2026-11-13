@preconcurrency import AVFoundation
import SwiftUI
@preconcurrency import VLCKit

#if os(macOS)
  import AppKit

  /// 只承载画面层，不接入系统播放器控制器和文档恢复。
  final class VaultVideoView: NSView {
    let videoLayer = AVPlayerLayer()
    let compatibilityView = VLCVideoView()

    /// 业务作用：创建仅供保险箱当前会话使用的媒体画面。
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
      videoLayer.frame = bounds
      compatibilityView.frame = bounds
    }

  }

  struct PlayerSurface: NSViewRepresentable {
    @ObservedObject var playback: LocalPlayback

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

    /// 业务作用：在同一自有画面中切换系统和兼容解码，保持比例且不新增播放窗口。
    /// 参数说明：
    /// - `view`：当前查看区的原生画面。
    /// 返回：只有当前采用的解码器可以绘制视频。
    private func bind(_ view: VaultVideoView) {
      let compatible = playback.compatiblePlayer != nil
      view.videoLayer.isHidden = compatible
      view.videoLayer.player = compatible ? nil : playback.player
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

  final class VaultVideoView: UIView {
    let compatibilityView = UIView()

    /// 业务作用：创建当前视频的两种自有画面承载层，不接入系统媒体控制器。
    /// 参数说明：
    /// - `frame`：当前初始画面区域。
    /// 返回：默认只开放系统画面，兼容画面等待明确绑定。
    override init(frame: CGRect) {
      super.init(frame: frame)
      compatibilityView.backgroundColor = .black
      compatibilityView.isHidden = true
      addSubview(compatibilityView)
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
  }

  struct PlayerSurface: UIViewRepresentable {
    @ObservedObject var playback: LocalPlayback

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

    /// 业务作用：在当前应用画面中选择解码器，兼容模式不生成外部播放器界面。
    /// 参数说明：
    /// - `view`：当前查看区的原生画面。
    /// 返回：当前采用的解码器完成绑定，另一画面停止绘制。
    private func bind(_ view: VaultVideoView) {
      let compatible = playback.compatiblePlayer != nil
      (view.layer as? AVPlayerLayer)?.player = compatible ? nil : playback.player
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
      scrub = playback.position
    }
    .onChange(of: playback.position) { _, value in
      if !dragging {
        scrub = value
      }
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
    .disabled(dragging || playback.duration <= 0)
  }

  /// 业务作用：只在用户结束本次拖动后定位视频，连续播放采样不会覆盖正在选择的位置。
  /// 参数说明：无。
  /// 返回：属于当前播放器的进度滑块，未知时长时禁用定位。
  private var progressSlider: some View {
    Slider(
      value: $scrub, in: 0...max(1, playback.duration),
      onEditingChanged: { editing in
        dragging = editing
        if !editing {
          playback.seek(scrub)
        }
      }
    )
    .accessibilityLabel("播放进度")
    .disabled(playback.duration <= 0)
  }

  /// 业务作用：展示当前会话时间与总时长，不占用手机进度滑块的水平空间。
  /// 参数说明：无。
  /// 返回：等宽数字时间标签，未知总时长时显示明确状态。
  private var playbackTime: some View {
    Text(
      playback.duration > 0
        ? "\(time(playback.position)) / \(time(playback.duration))"
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
