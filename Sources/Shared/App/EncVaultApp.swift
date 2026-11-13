import SwiftUI

#if os(macOS)
  import AppKit

  /// 关闭系统应用状态恢复，并按用户选择执行切换应用锁定。
  @MainActor
  final class VaultApplicationDelegate: NSObject, NSApplicationDelegate {
    weak var model: VaultModel?

    /// 业务作用：按用户选择的 Mac 切换策略撤销明文交付能力。
    /// 参数说明：
    /// - `notification`：系统前台状态通知。
    /// 返回：非导入状态按原策略锁定；导入期间保留当前会话，仍可主动锁定。
    func applicationWillResignActive(_ notification: Notification) {
      if model?.shouldLockWhenInactive ?? VaultWindowPolicy.lockWhenInactive {
        model?.lock()
      }
    }

    /// 业务作用：正常退出应用时提前清理本次仍持有的恢复码剪贴板内容。
    /// 参数说明：
    /// - `notification`：系统即将终止当前应用的通知。
    /// 返回：本次恢复码复制被撤下；其它应用后来写入的剪贴板内容不受影响。
    func applicationWillTerminate(_ notification: Notification) {
      RecoveryClipboard.clearOwnedCopy()
    }

    /// 业务作用：拒绝保存窗口和媒体界面恢复状态。
    /// 参数说明：
    /// - `app`：当前应用实例。
    /// 返回：始终不保存应用恢复归档。
    func applicationShouldSaveSecureApplicationState(_ app: NSApplication) -> Bool {
      false
    }

    /// 业务作用：拒绝恢复过去的窗口内容和媒体选择。
    /// 参数说明：
    /// - `app`：当前应用实例。
    /// 返回：始终从首次设置或锁定入口启动。
    func applicationShouldRestoreSecureApplicationState(_ app: NSApplication) -> Bool {
      false
    }

    /// 业务作用：关闭最后窗口后终止进程，避免无窗口会话留在后台。
    /// 参数说明：
    /// - `sender`：当前应用实例。
    /// 返回：关闭最后窗口时退出。
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
      true
    }
  }
#endif

/// EncVault 在 iPhone 与 Mac 上共用的应用入口。
@main
struct EncVaultApp: App {
  @StateObject private var model = VaultModel()
  #if os(macOS)
    @NSApplicationDelegateAdaptor(VaultApplicationDelegate.self) private var delegate
  #else
    @UIApplicationDelegateAdaptor(VaultIOSApplicationDelegate.self) private var delegate
  #endif
  /// 业务作用：创建保险箱的主窗口，保持两端进入同一界面入口。
  ///
  /// 参数说明：无。
  ///
  /// 返回：从首次设置或锁定界面开始，不自动恢复上次媒体。
  var body: some Scene {
    WindowGroup {
      VaultLandingView(model: model)
        #if os(macOS)
          .onAppear {
            delegate.model = model
          }
        #endif
    }
    #if os(macOS)
      .defaultSize(width: 860, height: 680)
      .commands {
        CommandGroup(replacing: .newItem) {
        }
      }
    #endif
  }
}
