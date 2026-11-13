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
    final class ProtectedView: NSView {
      weak var model: VaultModel?
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
        window?.sharingType = VaultWindowPolicy.allowsScreenshots ? .readOnly : .none
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

      /// 业务作用：在窗口失去前台前直接遮住原生内容，避免依赖延迟的界面重新绘制。
      /// 参数说明：
      /// - `notification`：系统即将切换前台的通知。
      /// 返回：当前会话要求锁定时遮住媒体并撤权；导入期间沿用内存中的临时豁免。
      @objc private func conceal(_ notification: Notification) {
        guard window != nil,
          model?.shouldLockWhenInactive ?? VaultWindowPolicy.lockWhenInactive
        else {
          return
        }
        cover.frame = bounds
        cover.autoresizingMask = [.width, .height]
        cover.wantsLayer = true
        cover.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        // 遮罩只附加到应用自有视图，保持 SwiftUI 托管层级完整，避免破坏弹窗和事件分发。
        addSubview(cover)
        model?.lock()
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
      return view
    }

    /// 业务作用：同步用户选择的窗口捕获策略，不保存窗口或媒体内容。
    /// 参数说明：
    /// - `view`：当前策略视图。
    /// - `context`：SwiftUI 的视图生命周期上下文。
    /// 返回：不产生持久副作用。
    func updateNSView(_ view: ProtectedView, context: Context) {
      view.window?.sharingType = VaultWindowPolicy.allowsScreenshots ? .readOnly : .none
    }
  }
#else
  import SwiftUI
  import UIKit

  /// 保护对象随密码会话入口存活，不依赖被系统全屏文档暂时移出窗口的 SwiftUI 视图。
  @MainActor
  final class VaultForegroundProtection: NSObject {
    private weak var model: VaultModel?
    private var covers: [UIView] = []

    /// 业务作用：在应用级绑定前后台保护，覆盖系统文档预览和普通媒体页面。
    /// 参数说明：
    /// - `model`：拥有独立密码会话与明文查看材料的入口。
    /// 返回：通知监听与入口同生命周期，不因页面被模态覆盖而失效。
    init(model: VaultModel) {
      self.model = model
      super.init()
      NotificationCenter.default.addObserver(
        self, selector: #selector(conceal(_:)),
        name: UIApplication.willResignActiveNotification, object: nil)
      NotificationCenter.default.addObserver(
        self, selector: #selector(reveal(_:)),
        name: UIApplication.didBecomeActiveNotification, object: nil)
    }

    /// 业务作用：离开前台时先覆盖应用窗口，再按用户选择撤销会话。
    /// 参数说明：
    /// - `notification`：系统即将退出前台的通知。
    /// 返回：后台快照始终遮挡；开启自动锁定时撤权，关闭时保留会话并暂停视频。
    @objc private func conceal(_ notification: Notification) {
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
      if model?.shouldLockWhenInactive ?? VaultWindowPolicy.lockWhenInactive {
        model?.lock()
      } else if let playback = model?.playback, playback.playing {
        playback.toggle()
      }
      UIApplication.shared.ignoreSnapshotOnNextApplicationLaunch()
    }

    /// 业务作用：回到前台后按会话是否有效处理模态内容，再撤下覆盖层。
    /// 参数说明：
    /// - `notification`：系统恢复前台的通知。
    /// 返回：已锁定时先撤下旧文档；用户已验证关闭自动锁定时保留当前查看。
    @objc private func reveal(_ notification: Notification) {
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
