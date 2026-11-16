import SwiftUI

/// 两端共用切换应用锁定偏好，未设置时保持自动锁定。
enum VaultWindowPolicy {
  static let lockWhenInactiveKey = "lockWhenInactive"

  /// 业务作用：读取用户选择的切换应用锁定策略，未设置时保持自动锁定。
  /// 参数说明：无。
  /// 返回：失去前台时是否应撤销当前会话；iPhone 的后台遮罩始终保留。
  static var lockWhenInactive: Bool {
    UserDefaults.standard.object(forKey: lockWhenInactiveKey) as? Bool ?? true
  }

  #if os(macOS)
    static let allowScreenshotsKey = "allowScreenshots"
    static let mainWindowID = "vault"
    /// 业务作用：读取用户是否允许系统捕获当前窗口，未设置时保持关闭。
    /// 参数说明：无。
    /// 返回：仅用户明确启用时允许窗口捕获，不改变密码验证。
    static var allowsScreenshots: Bool {
      UserDefaults.standard.bool(forKey: allowScreenshotsKey)
    }
  #endif
}

#if os(macOS)
  import AppKit

  /// 禁用窗口恢复和文件代理，标题不包含原始媒体名称。
  struct VaultWindowProtection: NSViewRepresentable {
    let model: VaultModel
    let allowsScreenshots: Bool
    @Environment(\.openWindow) private var openWindow
    final class ProtectedView: NSView {
      weak var model: VaultModel?
      var allowsScreenshots = false
      var renewWindow: ((NSWindow) -> Void)?
      private var renewalRequested = false
      private var observing = false
      private let cover = NSView()
      /// 业务作用：窗口挂接时关闭系统窗口内容恢复，避免重启自动打开媒体。
      /// 参数说明：无。
      /// 返回：窗口只保留固定产品标题，不登记来源 URL。
      override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        window?.isRestorable = false
        window?.representedURL = nil
        window?.title = "EncVault"
        applyCapturePolicy()
        if !observing {
          observing = true
          NotificationCenter.default.addObserver(
            self, selector: #selector(conceal(_:)),
            name: NSApplication.willResignActiveNotification, object: nil)
          NotificationCenter.default.addObserver(
            self, selector: #selector(reveal(_:)),
            name: NSApplication.didBecomeActiveNotification, object: nil)
        }
      }

      /// 业务作用：把当前截图选择立即应用到原生窗口及已打开的附属窗口。
      /// 参数说明：无。
      /// 返回：窗口捕获状态与用户当前选择一致，不依赖窗口重新挂接或应用重启。
      func applyCapturePolicy() {
        guard let window else {
          return
        }
        // 已进入禁止捕获状态的窗口可能无法恢复；先创建可捕获窗口，再关闭旧窗口，保留原会话。
        if allowsScreenshots, window.sharingType == .none {
          if !renewalRequested {
            renewalRequested = true
            Task { @MainActor [weak self, weak window] in
              guard let self, let window else {
                return
              }
              self.renewWindow?(window)
            }
          }
          return
        }
        window.sharingType = allowsScreenshots ? .readOnly : .none
        for child in window.childWindows ?? [] {
          child.sharingType = allowsScreenshots ? .readOnly : .none
        }
      }

      /// 业务作用：在窗口失去前台前直接遮住原生内容，避免依赖延迟的界面重新绘制。
      /// 参数说明：
      /// - `notification`：系统即将切换前台的通知。
      /// 返回：当前会话要求锁定时遮住媒体并撤权；相册删源确认期间只遮挡，任务结束恢复原策略。
      @objc private func conceal(_ notification: Notification) {
        guard window != nil else {
          return
        }
        let shouldLock = model?.shouldLockWhenInactive ?? VaultWindowPolicy.lockWhenInactive
        let confirmingPhotos = model?.photoSourceRemovalInProgress == true
        guard shouldLock || confirmingPhotos else {
          return
        }
        cover.frame = bounds
        cover.autoresizingMask = [.width, .height]
        cover.wantsLayer = true
        cover.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        // 遮罩只附加到应用自有视图，保持 SwiftUI 托管层级完整，避免破坏弹窗和事件分发。
        addSubview(cover)
        // 系统确认尚未结束时保留本次事务授权，遮罩不等于开放其它后台操作。
        if shouldLock {
          model?.lock()
        }
      }

      /// 业务作用：重新进入前台时移除遮罩，底层会话仍需独立密码验证。
      /// 参数说明：
      /// - `notification`：系统前台恢复通知。
      /// 返回：只解除遮罩，不恢复任何媒体或进度。
      @objc private func reveal(_ notification: Notification) {
        cover.removeFromSuperview()
      }

      /// 业务作用：释放窗口策略实例的系统通知绑定。
      /// 参数说明：无。
      /// 返回：通知不再引用已销毁的窗口策略。
      deinit {
        NotificationCenter.default.removeObserver(self)
      }
    }

    /// 业务作用：为主窗口附加不持久化媒体状态的窗口策略。
    /// 参数说明：
    /// - `context`：SwiftUI 的视图生命周期上下文。
    /// 返回：不绘制媒体的策略视图。
    func makeNSView(context: Context) -> ProtectedView {
      let view = ProtectedView()
      view.model = model
      view.allowsScreenshots = allowsScreenshots
      view.renewWindow = renewCaptureWindow
      return view
    }

    /// 业务作用：同步用户选择的窗口捕获策略，不保存窗口或媒体内容。
    /// 参数说明：
    /// - `view`：当前策略视图。
    /// - `context`：SwiftUI 的视图生命周期上下文。
    /// 返回：不产生持久副作用。
    func updateNSView(_ view: ProtectedView, context: Context) {
      view.model = model
      view.allowsScreenshots = allowsScreenshots
      view.renewWindow = renewCaptureWindow
      view.applyCapturePolicy()
    }

    /// 业务作用：启用截图时替换不能恢复捕获的原生窗口，沿用同一保险箱会话和浏览目录。
    /// 参数说明：
    /// - `original`：已经禁止捕获且当前仍打开的窗口。
    /// 返回：新窗口可见后保留原尺寸并关闭旧窗口；创建失败时保留原窗口并提示。
    private func renewCaptureWindow(_ original: NSWindow) {
      openWindow(id: VaultWindowPolicy.mainWindowID)
      Task { @MainActor [weak original] in
        for _ in 0..<100 {
          guard let original else {
            return
          }
          if let replacement = NSApplication.shared.windows.first(where: {
            $0 !== original && $0.title == "EncVault" && $0.isVisible
              && $0.sharingType == .readOnly
          }) {
            replacement.setFrame(original.frame, display: true)
            if original.isKeyWindow {
              replacement.makeKeyAndOrderFront(nil)
            }
            // 可捕获的新窗口已经承接同一模型后才关闭原窗口，不能留下无窗口会话或丢弃目录状态。
            original.close()
            return
          }
          do {
            try await Task.sleep(for: .milliseconds(25))
          } catch {
            return
          }
        }
        model.message = "截图窗口未能重新打开，请关闭并重新打开 EncVault 后再截图。"
      }
    }
  }
#else
  import Combine
  import SwiftUI
  import UIKit

  /// 保护对象随密码会话入口存活，不依赖被系统全屏文档暂时移出窗口的 SwiftUI 视图。
  @MainActor
  final class VaultForegroundProtection: NSObject {
    private weak var model: VaultModel?
    private var covers: [UIView] = []
    private var playbackObservation: AnyCancellable?
    private var migrationObservation: AnyCancellable?
    private var foreground = false
    private var videoPlaying = false
    private var migrating = false

    /// 业务作用：绑定应用前后台保护与当前视频的防息屏状态，覆盖两套解码器及系统文档预览。
    /// 参数说明：
    /// - `model`：拥有独立密码会话与明文查看材料的入口。
    /// 返回：前台视频播放或加密传输期间保亮，停止、失败或失去前台后恢复系统自动息屏。
    init(model: VaultModel) {
      self.model = model
      super.init()
      foreground = UIApplication.shared.applicationState == .active
      playbackObservation = model.$playback.map { playback -> AnyPublisher<Bool, Never> in
        guard let playback else {
          return Just(false).eraseToAnyPublisher()
        }
        return playback.$playing.combineLatest(playback.$failure).map { playing, failure in
          playing && failure == nil
        }.eraseToAnyPublisher()
      }.switchToLatest().combineLatest(model.$screen).map { playing, screen in
        playing && screen == .library
      }.removeDuplicates().sink { [weak self] playing in
        self?.videoPlaying = playing
        self?.updateDisplayWake()
      }
      migrationObservation = model.$migration.map { migration -> AnyPublisher<Bool, Never> in
        guard let migration else {
          return Just(false).eraseToAnyPublisher()
        }
        return migration.$phase.map {
          $0 == .transferring || $0 == .awaitingPeer || $0 == .authorizingTarget
        }.eraseToAnyPublisher()
      }.switchToLatest().combineLatest(model.$screen).map { transferring, screen in
        transferring && screen == .library
      }.removeDuplicates().sink { [weak self] transferring in
        self?.migrating = transferring
        self?.updateDisplayWake()
      }
      NotificationCenter.default.addObserver(
        self, selector: #selector(conceal(_:)),
        name: UIApplication.willResignActiveNotification, object: nil)
      NotificationCenter.default.addObserver(
        self, selector: #selector(reveal(_:)),
        name: UIApplication.didBecomeActiveNotification, object: nil)
      NotificationCenter.default.addObserver(
        self, selector: #selector(enterBackground(_:)),
        name: UIApplication.didEnterBackgroundNotification, object: nil)
      NotificationCenter.default.addObserver(
        self, selector: #selector(endDisplayWake(_:)),
        name: UIApplication.willTerminateNotification, object: nil)
    }

    /// 业务作用：前台播放或传输期间暂停闲置计时，不更改系统自动锁定时长。
    /// 参数说明：无。
    /// 返回：系统闲置计时与当前有效任务一致，旧任务不能继续要求保亮。
    private func updateDisplayWake() {
      let disabled = foreground && (videoPlaying || migrating)
      if UIApplication.shared.isIdleTimerDisabled != disabled {
        UIApplication.shared.isIdleTimerDisabled = disabled
      }
    }

    /// 业务作用：应用结束时撤销视频保亮，不把播放期间的闲置豁免延续到结束之后。
    /// 参数说明：
    /// - `notification`：系统应用终止通知。
    /// 返回：系统自动息屏恢复，后续排队的播放状态不能重新保亮。
    @objc private func endDisplayWake(_ notification: Notification) {
      foreground = false
      updateDisplayWake()
    }

    /// 业务作用：离开前台时先覆盖应用窗口，再按用户选择撤销会话。
    /// 参数说明：
    /// - `notification`：系统即将退出前台的通知。
    /// 返回：快照始终遮挡；相册删源确认和迁移配对弹窗允许暂时失焦，真正进入后台仍撤权。
    @objc private func conceal(_ notification: Notification) {
      // 先撤销保亮，再暂停或锁定；排队的播放通知不能在失去前台后重新禁用闲置计时。
      foreground = false
      updateDisplayWake()
      if covers.isEmpty {
        let windows = UIApplication.shared.connectedScenes.compactMap {
          $0 as? UIWindowScene
        }.flatMap(\.windows).filter {
          !$0.isHidden && $0.windowLevel == .normal
        }
        for window in windows {
          let cover = UIView(frame: window.bounds)
          cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
          cover.backgroundColor = .systemBackground
          // 遮罩先于撤销和界面重绘，系统完整文档也不能在后台快照中继续展示。
          window.addSubview(cover)
          covers.append(cover)
        }
      }
      // 模态页面可能让原页面脱离窗口；锁定策略不得以原页面仍可见为前提。
      if (model?.shouldLockWhenInactive ?? VaultWindowPolicy.lockWhenInactive)
        && model?.photoSourceRemovalInProgress != true
        && model?.migration == nil
      {
        model?.lock()
      } else if let playback = model?.playback, playback.playing {
        playback.toggle()
      }
      UIApplication.shared.ignoreSnapshotOnNextApplicationLaunch()
    }

    /// 业务作用：相册删除确认期间也保留真实后台锁定边界，不能把系统弹窗豁免延续到其它应用。
    /// 参数说明：
    /// - `notification`：应用已经进入后台的系统通知。
    /// 返回：启用切换锁定时立即撤销会话，尚未提交的删源动作停止。
    @objc private func enterBackground(_ notification: Notification) {
      foreground = false
      updateDisplayWake()
      // 临时系统弹窗与真正离开应用分别处理，后台永远不能借待确认事务保留明文访问权。
      if model?.shouldLockWhenInactive ?? VaultWindowPolicy.lockWhenInactive {
        model?.lock()
      }
    }

    /// 业务作用：回到前台后按会话是否有效处理模态内容，再撤下覆盖层。
    /// 参数说明：
    /// - `notification`：系统恢复前台的通知。
    /// 返回：已锁定时先撤下旧文档；用户已验证关闭自动锁定时保留当前查看。
    @objc private func reveal(_ notification: Notification) {
      foreground = true
      updateDisplayWake()
      for cover in covers {
        if model?.screen != .library, let window = cover.superview as? UIWindow,
          let root = window.rootViewController, root.presentedViewController != nil
        {
          // 旧模态页面彻底撤下后才揭开窗口，避免前台首帧出现已经失权的文档。
          root.dismiss(animated: false) {
            cover.removeFromSuperview()
          }
        } else {
          cover.removeFromSuperview()
        }
      }
      covers = []
    }

    /// 业务作用：释放应用入口时撤销通知绑定。
    /// 参数说明：无。
    /// 返回：系统不再调用已经销毁的保护对象。
    deinit {
      NotificationCenter.default.removeObserver(self)
    }
  }

  /// iPhone 的原生遮罩由应用级保护对象统一维护。
  struct VaultWindowProtection: View {
    let model: VaultModel

    /// 业务作用：保持两端统一的窗口策略挂接位置，不依赖该视图承担生命周期监听。
    /// 参数说明：无。
    /// 返回：不遮挡用户操作的透明界面占位。
    var body: some View {
      Color.clear.allowsHitTesting(false)
    }
  }
#endif
