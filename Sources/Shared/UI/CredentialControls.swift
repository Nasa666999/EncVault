import SwiftUI
import UniformTypeIdentifiers

#if os(macOS)
  import AppKit
#else
  import UIKit
#endif

/// 只有用户明确复制时才把恢复码交给本机剪贴板，不参与跨设备接力。
@MainActor
enum RecoveryClipboard {
  #if os(macOS)
    private static var cleanup: Task<Void, Never>?
    private static var ownedChangeCount: Int?
  #endif

  /// 业务作用：按用户请求复制完整恢复码，限制在本机使用并安排限时清理。
  /// 参数说明：
  /// - `code`：当前确认页面显示的完整恢复码，不附加提示或换行。
  /// 返回：写入成功时为真；Mac 写入失败时为假，不记录恢复码或自动确认保存。
  static func copy(_ code: String) -> Bool {
    #if os(macOS)
      cleanup?.cancel()
      cleanup = nil
      ownedChangeCount = nil
      let pasteboard = NSPasteboard.general
      pasteboard.prepareForNewContents(with: .currentHostOnly)
      guard pasteboard.setString(code, forType: .string) else {
        return false
      }
      let changeCount = pasteboard.changeCount
      ownedChangeCount = changeCount
      cleanup = Task { @MainActor in
        do {
          try await Task.sleep(for: .seconds(60))
        } catch {
          return
        }
        guard ownedChangeCount == changeCount else {
          return
        }
        clearOwnedCopy()
      }
    #else
      UIPasteboard.general.setItems(
        [[UTType.utf8PlainText.identifier: code]],
        options: [
          .localOnly: true,
          .expirationDate: Date().addingTimeInterval(60),
        ])
    #endif
    return true
  }

  #if os(macOS)
    /// 业务作用：到期或正常退出时移除仍属于本次恢复码复制的剪贴板内容。
    /// 参数说明：无。
    /// 返回：清理本次仍持有的复制内容；用户后来复制的其它内容保持不变。
    static func clearOwnedCopy() {
      cleanup?.cancel()
      cleanup = nil
      guard let changeCount = ownedChangeCount else {
        return
      }
      ownedChangeCount = nil
      let pasteboard = NSPasteboard.general
      // 只凭本次写入代次清理，不读取用户后来复制的内容，也不能把其它应用的复制结果清空。
      guard pasteboard.changeCount == changeCount else {
        return
      }
      pasteboard.clearContents()
    }
  #endif
}

/// 关闭切换锁定必须重新验证当前 App 凭据，已有解锁会话不能代替本次输入。
struct AutomaticLockAuthentication: View {
  @ObservedObject var model: VaultModel
  let requestID: UUID
  @Environment(\.scenePhase) private var scenePhase
  @State private var password = ""

  /// 业务作用：在降低切换保护前提供独立密码或手势验证与取消入口。
  /// 参数说明：无。
  /// 返回：验证前保持自动锁定，手势画完自动提交，数字密码由用户明确提交。
  var body: some View {
    ScrollView {
      VStack(spacing: 20) {
        Label("关闭自动锁定", systemImage: "lock.shield").font(.title2)
        Text("请输入 App 密码或绘制当前手势。关闭后，切换应用再返回时无需重新解锁；每次启动仍需解锁。")
          .foregroundStyle(.secondary)
        CredentialInput(
          title: model.kind.title, kind: model.kind, value: $password,
          patternCompleted: authenticate
        )
        .disabled(model.busy)
        .onSubmit {
          if model.kind == .pin {
            authenticate()
          }
        }
        if model.kind == .pin {
          Button("验证并关闭", action: authenticate)
            .buttonStyle(.borderedProminent)
            .disabled(model.busy || password.count != 6)
        } else {
          Text("绘制完成后自动验证").font(.caption).foregroundStyle(.secondary)
        }
        if model.busy {
          ProgressView()
        }
        if let message = model.message {
          Text(message).foregroundStyle(.red)
        }
        Button("取消") {
          password = ""
          model.cancelAutomaticLockRequest()
        }
        .disabled(model.busy)
      }
      .padding(24)
      .frame(maxWidth: 420)
      .frame(maxWidth: .infinity)
    }
    #if os(macOS)
      .frame(minWidth: 340, minHeight: 420)
    #endif
    .privacySensitive()
    .onChange(of: scenePhase) { _, phase in
      if phase != .active {
        password = ""
      }
    }
    .onDisappear {
      password = ""
    }
  }

  /// 业务作用：提交本次完整凭据并立即清空界面输入，防止重复或旧表单授权。
  /// 参数说明：无。
  /// 返回：仅当前有效请求交给会话模型验证；不记录输入内容。
  private func authenticate() {
    guard !model.busy, model.automaticLockRequest?.id == requestID else {
      return
    }
    let credential = VaultCredential(kind: model.kind, value: password)
    guard (try? credential.encoded()) != nil else {
      return
    }
    password = ""
    model.authenticateAutomaticLock(credential, requestID: requestID)
  }
}

/// 只在当前视图中保留输入的六位独立密码，不请求系统密码自动填充。
struct PINInput: View {
  let title: String
  @Binding var value: String

  /// 业务作用：收集本次六位数字输入，不启用系统凭据自动填充。
  /// 参数说明：无。
  /// 返回：仅绑定当前内存输入的密码控件。
  var body: some View {
    let field = SecureField(title, text: $value)
      .textFieldStyle(.roundedBorder)
      .autocorrectionDisabled()
      .onChange(of: value) { _, new in
        let filtered = String(
          new.utf8.filter {
            (48...57).contains($0)
          }.prefix(6).map {
            Character(UnicodeScalar($0))
          })
        if value != filtered {
          value = filtered
        }
      }
    #if os(iOS)
      field.keyboardType(.numberPad)
    #else
      field
    #endif
  }
}

/// 两端共用的九宫格输入，手指或鼠标抬起后不继续显示已输入轨迹。
struct PatternInput: View {
  let title: String
  @Binding var value: String
  var completed: () -> Void = {}
  var side: CGFloat = 225
  @State private var nodes: [Int] = []
  @State private var drawing = false

  /// 业务作用：收集规范化手势，结束输入后隐藏轨迹，并仅在有效绘制结束时通知当前入口。
  /// 参数说明：无。
  /// 返回：支持触摸和鼠标的当前会话输入区域。
  var body: some View {
    VStack(spacing: 8) {
      Text(title).font(.subheadline)
      GeometryReader { geometry in
        let side = min(geometry.size.width, geometry.size.height)
        ZStack {
          if drawing {
            Path { path in
              for (index, node) in nodes.enumerated() {
                let point = point(node, side: side)
                if index == 0 {
                  path.move(to: point)
                } else {
                  path.addLine(to: point)
                }
              }
            }
            .stroke(Color.accentColor.opacity(0.65), lineWidth: 5)
          }
          ForEach(0..<9, id: \.self) { node in
            Circle()
              .fill(
                drawing && nodes.contains(node) ? Color.accentColor : Color.secondary.opacity(0.35)
              )
              .frame(width: side * 22 / 225, height: side * 22 / 225)
              .position(point(node, side: side))
          }
        }
        .contentShape(Rectangle())
        .gesture(
          DragGesture(minimumDistance: 0)
            .onChanged { event in
              if !drawing {
                drawing = true
                nodes = []
                value = ""
              }
              for node in 0..<9 {
                let center = point(node, side: side)
                if hypot(event.location.x - center.x, event.location.y - center.y) < side / 9 {
                  nodes = PatternRules.normalized(nodes + [node])
                }
              }
            }
            .onEnded { _ in
              value = nodes.count >= 4 ? nodes.map(String.init).joined(separator: ",") : ""
              nodes = []
              drawing = false
              if !value.isEmpty {
                completed()
              }
            }
        )
      }
      .frame(width: side, height: side)
      .accessibilityElement(children: .ignore)
      .accessibilityLabel(title)
      .accessibilityIdentifier("手势输入区域")
      Text(value.isEmpty ? "连接至少 4 个节点" : "已输入手势")
        .font(.caption).foregroundStyle(.secondary)
    }
    .privacySensitive()
  }

  /// 业务作用：保持触摸和鼠标输入采用相同的节点位置和顺序。
  /// 参数说明：
  /// - `node`：按行编号的九宫格节点。
  /// - `side`：当前输入区域边长。
  /// 返回：输入区域内的节点中心位置。
  private func point(_ node: Int, side: CGFloat) -> CGPoint {
    CGPoint(x: (CGFloat(node % 3) + 0.5) * side / 3, y: (CGFloat(node / 3) + 0.5) * side / 3)
  }
}

/// 统一独立密码输入控件，不调用系统生物识别或设备密码入口。
struct CredentialInput: View {
  let title: String
  let kind: CredentialKind
  @Binding var value: String
  var patternCompleted: () -> Void = {}
  var patternSide: CGFloat = 225

  /// 业务作用：按保险箱独立凭据类型提供唯一匹配的输入方式。
  /// 参数说明：无。
  /// 返回：六位数字或手势输入，不创建系统认证入口。
  var body: some View {
    if kind == .pin {
      PINInput(title: title, value: $value)
    } else {
      PatternInput(title: title, value: $value, completed: patternCompleted, side: patternSide)
    }
  }
}

/// 解锁入口按可用窗口排版，认证、恢复与清空仍由各自明确的操作提交。
struct CredentialUnlockView: View {
  @ObservedObject var model: VaultModel
  @Binding var password: String
  let unlock: () -> Void
  let recover: () -> Void
  let erase: () -> Void

  /// 业务作用：让两端的独立密码入口随屏幕与窗口尺寸展开，保留冻结和恢复边界。
  /// 参数说明：无。
  /// 返回：可滚动的响应式解锁页，小屏、键盘和大字号下不隐藏认证或恢复操作。
  var body: some View {
    TimelineView(.periodic(from: .now, by: 1)) { timeline in
      let allowed =
        model.credentialStatus?.remainingSeconds(at: timeline.date.timeIntervalSince1970) == 0
      GeometryReader { geometry in
        ScrollView {
          content(in: geometry.size, allowed: allowed, now: timeline.date)
        }
        .scrollBounceBehavior(.basedOnSize)
        .background(Color.accentColor.opacity(0.035).ignoresSafeArea())
      }
      .onChange(of: allowed) { previous, value in
        // 冻结立即撤下尚未提交的输入，到期后重新读取认证限制再开放操作。
        if !value {
          password = ""
        } else if !previous {
          model.refreshCredentialStatus()
          model.message = nil
        }
      }
    }
    .onAppear {
      model.refreshCredentialStatus()
    }
  }

  /// 业务作用：按当前可用空间组织解锁内容，宽屏分列、窄屏纵排，不固定正文区域尺寸。
  /// 参数说明：
  /// - `size`：扣除系统安全区域和键盘后的可用空间。
  /// - `allowed`：当前冻结是否允许本次认证。
  /// - `now`：冻结提示的当前时间。
  /// 返回：可由外层滚动容器容纳的内容，小空间不裁掉认证与恢复入口。
  func content(in size: CGSize, allowed: Bool, now: Date) -> some View {
    let wide = size.width >= 700 && size.width > size.height
    let width = max(0, min(size.width - 40, wide ? 940 : 520))
    let side = max(
      180,
      min(min(wide ? width * 0.54 - 48 : width - 32, size.height - (wide ? 200 : 440)), 370))
    return Group {
      if wide {
        HStack(spacing: 32) {
          VStack(spacing: 32) {
            brand
            recoveryActions
          }
          .frame(maxWidth: .infinity)
          authentication(allowed: allowed, now: now, side: side)
        }
      } else {
        VStack(spacing: 0) {
          brand.padding(.top, 8)
          Spacer(minLength: 20)
          authentication(allowed: allowed, now: now, side: side)
          Spacer(minLength: 20)
          recoveryActions
        }
      }
    }
    .frame(width: width)
    .frame(minHeight: max(0, size.height - 40))
    .padding(20)
    .frame(maxWidth: .infinity)
  }

  /// 业务作用：用统一的名称与本地加密提示建立解锁页层次，不展示保险箱文件信息。
  /// 参数说明：无。
  /// 返回：支持系统文字缩放的品牌标题。
  private var brand: some View {
    HStack(spacing: 12) {
      Image(systemName: "lock.shield.fill")
        .font(.system(size: 30, weight: .medium))
        .foregroundStyle(Color.accentColor)
        .frame(width: 58, height: 58)
        .background(Color.accentColor.opacity(0.1), in: RoundedRectangle(cornerRadius: 18))
        .accessibilityHidden(true)
      VStack(alignment: .leading, spacing: 3) {
        Text("EncVault").font(.largeTitle.weight(.semibold))
        Text("本地加密保险箱").font(.subheadline).foregroundStyle(.secondary)
      }
    }
    .frame(maxWidth: .infinity)
  }

  /// 业务作用：在当前冻结规则允许时收集独立凭据，绘制结束继续使用同一认证入口。
  /// 参数说明：
  /// - `allowed`：当前冻结已到期且允许尝试认证。
  /// - `now`：冻结提示使用的当前时间。
  /// - `side`：由可用窗口计算的手势画布边长。
  /// 返回：密码或手势卡片；错误、忙碌与冻结状态不改变认证规则。
  private func authentication(allowed: Bool, now: Date, side: CGFloat) -> some View {
    VStack(spacing: 16) {
      Text("输入独立密码解锁").font(.title2.weight(.semibold)).multilineTextAlignment(.center)
      if let status = model.credentialStatus {
        CredentialFreezeNotice(status: status, now: now)
          .multilineTextAlignment(.center)
      }
      CredentialInput(
        title: model.kind.title, kind: model.kind, value: $password,
        patternCompleted: unlock, patternSide: side
      )
      .disabled(model.busy || !allowed)
      .allowsHitTesting(!model.busy && allowed)
      .onSubmit {
        if model.kind == .pin {
          unlock()
        }
      }
      if model.kind == .pin {
        Button(action: unlock) {
          Text("解锁").font(.headline).frame(maxWidth: .infinity).padding(.vertical, 6)
        }
        .buttonStyle(.borderedProminent).controlSize(.large)
        .disabled(model.busy || !allowed)
      } else {
        Text("绘制完成后自动解锁").font(.caption).foregroundStyle(.secondary)
      }
      if model.busy {
        ProgressView()
      }
      if let message = model.message {
        Text(message).font(.callout).foregroundStyle(.red).multilineTextAlignment(.center)
      }
    }
    .padding(16)
    .frame(maxWidth: .infinity)
    .background(surface, in: RoundedRectangle(cornerRadius: 24))
    .overlay {
      RoundedRectangle(cornerRadius: 24).strokeBorder(.primary.opacity(0.06), lineWidth: 1)
    }
  }

  /// 业务作用：将恢复与永久清空分开呈现，点击仅打开各自原有的独立确认流程。
  /// 参数说明：无。
  /// 返回：全宽恢复入口与较低强调的清空入口；不绕过密码或恢复码校验。
  private var recoveryActions: some View {
    VStack(spacing: 8) {
      Button(action: recover) {
        HStack(spacing: 8) {
          Image(systemName: "key.horizontal")
          Text("忘记密码：使用离线恢复码").multilineTextAlignment(.leading)
          Spacer(minLength: 0)
          Image(systemName: "chevron.right").font(.caption.weight(.semibold))
        }
        .font(.callout.weight(.medium))
        .padding(.horizontal, 16).padding(.vertical, 14)
        .frame(maxWidth: .infinity, minHeight: 48)
        .foregroundStyle(Color.accentColor)
        .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      .accessibilityLabel("忘记密码：使用离线恢复码")
      Button(role: .destructive, action: erase) {
        Text("密码和恢复码均丢失：清空重建")
          .font(.caption).foregroundStyle(.secondary)
          .frame(maxWidth: .infinity, minHeight: 44)
          .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
    }
    .disabled(model.busy)
  }

  /// 业务作用：采用系统明暗外观的表面色，保持密码与手势区域的可读性。
  /// 参数说明：无。
  /// 返回：当前平台的原生内容背景色。
  private var surface: Color {
    #if os(macOS)
      Color(nsColor: .controlBackgroundColor)
    #else
      Color(uiColor: .systemBackground)
    #endif
  }
}

/// 原生密码框是输入的唯一来源，提交时直接读取当前编辑器，不依赖延迟的视图绑定。
@MainActor
final class FolderPasswordDraft: ObservableObject {
  @Published private(set) var isEmpty = true
  #if os(macOS)
    private weak var field: NSTextField?
  #else
    private weak var field: UITextField?
  #endif

  #if os(macOS)
    /// 业务作用：绑定当前表单的原生安全输入框，拒绝上一表单的迟到编辑通知。
    /// 参数说明：
    /// - `field`：当前表单新建的密码框。
    /// 返回：此前输入已清空，新密码只保存在当前原生控件内存中。
    func attach(_ field: NSTextField) {
      clear()
      self.field = field
    }

    /// 业务作用：根据当前原生编辑器更新提交门禁，不复制密码到视图状态。
    /// 参数说明：
    /// - `field`：发出编辑通知的安全输入框。
    /// 返回：仅当前控件可改变空值状态，旧控件通知不生效。
    func changed(_ field: NSTextField) {
      guard self.field === field else {
        return
      }
      let empty = (field.currentEditor()?.string ?? field.stringValue).isEmpty
      if isEmpty != empty {
        isEmpty = empty
      }
    }

    /// 业务作用：只解绑退出表单的那个原生控件，不能清空后来绑定的新控件。
    /// 参数说明：
    /// - `field`：正在结束生命周期的安全输入框。
    /// 返回：匹配当前控件时清空并解绑，迟到的旧控件回调不影响新表单。
    func detach(_ field: NSTextField) {
      guard self.field === field else {
        return
      }
      clear()
      self.field = nil
    }

    /// 业务作用：切换明文与密文显示时转交当前原生输入，不能恢复已离开表单的编辑器。
    /// 参数说明：
    /// - `previous`：当前持有输入的原生控件。
    /// - `next`：即将接收同一输入的原生控件。
    /// 返回：仅当前控件可转交输入；旧控件内容及编辑器同步清空，不建立密码副本记录。
    func transfer(from previous: NSTextField, to next: NSTextField) {
      guard field === previous else {
        return
      }
      let value = currentValue()
      let focused = previous.currentEditor() != nil
      previous.currentEditor()?.string = ""
      previous.stringValue = ""
      if focused {
        previous.window?.makeFirstResponder(nil)
      }
      field = next
      next.stringValue = value
      if focused {
        next.window?.makeFirstResponder(next)
      }
    }
  #else
    /// 业务作用：绑定当前表单的原生安全输入框，避免复用上一表单的编辑缓冲。
    /// 参数说明：
    /// - `field`：当前表单新建的密码框。
    /// 返回：此前输入已清空，新密码只保存在当前原生控件内存中。
    func attach(_ field: UITextField) {
      clear()
      self.field = field
    }

    /// 业务作用：由当前原生输入更新提交门禁，不另存一份密码绑定。
    /// 参数说明：
    /// - `field`：发出编辑通知的安全输入框。
    /// 返回：仅当前控件可改变空值状态，旧控件通知不生效。
    func changed(_ field: UITextField) {
      guard self.field === field else {
        return
      }
      let empty = (field.text ?? "").isEmpty
      if isEmpty != empty {
        isEmpty = empty
      }
    }

    /// 业务作用：只解绑当前退出的输入框，不能清空后来建立的输入会话。
    /// 参数说明：
    /// - `field`：正在结束生命周期的安全输入框。
    /// 返回：当前控件清空并解绑，旧控件迟到的结束事件不改变新输入。
    func detach(_ field: UITextField) {
      guard self.field === field else {
        return
      }
      clear()
      self.field = nil
    }
  #endif

  /// 业务作用：按用户明确要求在本机查看当前输入，所见内容与提交读取同一原生控件。
  /// 参数说明：无。
  /// 返回：当前原始字符的内存值，不清空输入、不写入配置或记录。
  func currentValue() -> String {
    #if os(macOS)
      return field?.stringValue ?? ""
    #else
      return field?.text ?? ""
    #endif
  }

  /// 业务作用：在提交边界取得正在编辑的完整密码，再同步清空原生输入及焦点。
  /// 参数说明：无。
  /// 返回：本次原始输入的内存快照，大小写、空白与字符编码均保持不变，不写入日志或磁盘。
  func take() -> String {
    let value = currentValue()
    clear()
    return value
  }

  /// 业务作用：结束输入时同时销毁原生控件值与编辑器缓冲，避免清空绑定后仍残留旧输入。
  /// 参数说明：无。
  /// 返回：本次密码输入清空且不再拥有编辑焦点，不影响其它表单。
  func clear() {
    #if os(macOS)
      if let field {
        field.currentEditor()?.string = ""
        field.stringValue = ""
        if field.currentEditor() != nil {
          field.window?.makeFirstResponder(nil)
        }
      }
    #else
      field?.text = ""
      field?.resignFirstResponder()
    #endif
    if !isEmpty {
      isEmpty = true
    }
  }
}

#if os(macOS)
  /// 当前目录表单独占一个原生安全输入框，验证期间禁止继续修改提交材料。
  struct FolderPasswordField: NSViewRepresentable {
    let title: String
    let draft: FolderPasswordDraft
    let enabled: Bool
    let revealed: Bool

    final class InputView: NSView {
      let secure: NSSecureTextField
      let plain: NSTextField
      private(set) var field: NSTextField
      let draft: FolderPasswordDraft

      /// 业务作用：为同一密码提供互斥的隐藏与明文控件，只让当前显示控件持有输入。
      /// 参数说明：
      /// - `title`：输入框用途及辅助功能名称。
      /// - `draft`：当前表单的输入拥有者。
      /// - `coordinator`：统一原始字符输入与隐私设置的通知处理器。
      /// 返回：默认隐藏字符且不保留撤销历史的原生输入容器，焦点不额外绘制内层描边。
      init(title: String, draft: FolderPasswordDraft, coordinator: Coordinator) {
        let secure = NSSecureTextField()
        self.secure = secure
        self.plain = NSTextField()
        self.draft = draft
        self.field = secure
        super.init(frame: .zero)
        for input in [secure, plain] {
          input.placeholderString = title
          input.isBordered = false
          input.isBezeled = false
          input.drawsBackground = false
          input.focusRingType = .none
          input.font = .systemFont(ofSize: NSFont.systemFontSize)
          input.delegate = coordinator
          input.setAccessibilityLabel(title)
          input.translatesAutoresizingMaskIntoConstraints = false
          addSubview(input)
          NSLayoutConstraint.activate([
            input.leadingAnchor.constraint(equalTo: leadingAnchor),
            input.trailingAnchor.constraint(equalTo: trailingAnchor),
            input.centerYAnchor.constraint(equalTo: centerYAnchor),
          ])
        }
        plain.isHidden = true
        draft.attach(secure)
      }

      /// 业务作用：拒绝从界面恢复归档恢复密码输入。
      /// 参数说明：
      /// - `coder`：系统尝试提供的归档读取器。
      /// 返回：不从归档建立密码框。
      required init?(coder: NSCoder) {
        return nil
      }

      /// 业务作用：响应眼睛按钮，转交当前输入后清空并隐藏另一控件。
      /// 参数说明：
      /// - `revealed`：用户是否明确选择明文显示。
      /// - `enabled`：当前是否允许修改输入。
      /// 返回：显示方式变化不改变密码字符，验证期间两个控件均不可编辑。
      func update(revealed: Bool, enabled: Bool) {
        let next = revealed ? plain : secure
        if field !== next {
          let previous = field
          next.isHidden = false
          draft.transfer(from: previous, to: next)
          previous.isHidden = true
          field = next
        }
        secure.isEnabled = enabled
        plain.isEnabled = enabled
      }
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
      let draft: FolderPasswordDraft

      /// 业务作用：只转发当前表单的原生编辑通知，不保存密码副本。
      /// 参数说明：
      /// - `draft`：当前表单的临时输入拥有者。
      /// 返回：与当前安全输入框同生命周期的通知处理器。
      init(draft: FolderPasswordDraft) {
        self.draft = draft
      }

      /// 业务作用：用当前原生编辑器状态控制提交按钮，避免视图绑定滞后。
      /// 参数说明：
      /// - `notification`：本安全输入框的文本变化通知。
      /// 返回：只更新空值门禁，不保留输入历史。
      func controlTextDidChange(_ notification: Notification) {
        if let field = notification.object as? NSTextField {
          draft.changed(field)
        }
      }

      /// 业务作用：关闭密码编辑器中的撤销和文本替换，输入只能按原字符参与验证。
      /// 参数说明：
      /// - `notification`：本安全输入框开始编辑的通知。
      /// 返回：当前编辑器不积累撤销、纠错或自动替换材料。
      func controlTextDidBeginEditing(_ notification: Notification) {
        guard let field = notification.object as? NSTextField,
          let editor = field.currentEditor() as? NSTextView
        else {
          return
        }
        editor.allowsUndo = false
        editor.isAutomaticSpellingCorrectionEnabled = false
        editor.isAutomaticTextReplacementEnabled = false
        editor.isAutomaticQuoteSubstitutionEnabled = false
        editor.isAutomaticDashSubstitutionEnabled = false
        editor.isContinuousSpellCheckingEnabled = false
      }
    }

    /// 业务作用：建立当前表单独立的原生输入通知处理器。
    /// 参数说明：无。
    /// 返回：只引用当前临时输入拥有者的处理器。
    func makeCoordinator() -> Coordinator {
      Coordinator(draft: draft)
    }

    /// 业务作用：创建不通过 SwiftUI 字符串绑定中转的安全输入框。
    /// 参数说明：
    /// - `context`：当前输入框的生命周期上下文。
    /// 返回：绑定当前表单、默认隐藏字符的原生密码框。
    func makeNSView(context: Context) -> InputView {
      let view = InputView(title: title, draft: draft, coordinator: context.coordinator)
      view.update(revealed: revealed, enabled: enabled)
      return view
    }

    /// 业务作用：同步验证门禁，不能用界面刷新覆盖正在编辑的密码。
    /// 参数说明：
    /// - `field`：当前表单拥有的安全输入框。
    /// - `context`：当前输入框的生命周期上下文。
    /// 返回：验证期间停止编辑，密码内容不从其它状态回填。
    func updateNSView(_ field: InputView, context: Context) {
      field.update(revealed: revealed, enabled: enabled)
    }

    /// 业务作用：销毁表单时移除安全输入及编辑通知，不留下可复用的原生输入会话。
    /// 参数说明：
    /// - `field`：即将退出表单的安全输入框。
    /// - `coordinator`：当前输入框的通知处理器。
    /// 返回：原生输入清空且不再转发任何通知。
    static func dismantleNSView(_ field: InputView, coordinator: Coordinator) {
      coordinator.draft.detach(field.field)
      for input in [field.secure, field.plain] {
        input.delegate = nil
        input.stringValue = ""
      }
    }
  }
#else
  /// iPhone 同样在提交时直接读取原生安全输入，不让输入法更改密码字符。
  struct FolderPasswordField: UIViewRepresentable {
    let title: String
    let draft: FolderPasswordDraft
    let enabled: Bool
    let revealed: Bool

    @MainActor
    final class Coordinator: NSObject {
      let draft: FolderPasswordDraft

      /// 业务作用：限定原生编辑通知只属于当前目录表单。
      /// 参数说明：
      /// - `draft`：当前表单的临时输入拥有者。
      /// 返回：不持有密码副本的通知处理器。
      init(draft: FolderPasswordDraft) {
        self.draft = draft
      }

      /// 业务作用：由当前原生输入控制提交按钮，不缓存字符或建立输入历史。
      /// 参数说明：
      /// - `field`：本次发生变化的密码框。
      /// 返回：仅更新当前表单的空值门禁。
      @objc func changed(_ field: UITextField) {
        draft.changed(field)
      }
    }

    /// 业务作用：建立当前 iPhone 表单的原生输入通知处理器。
    /// 参数说明：无。
    /// 返回：与当前临时输入同生命周期的处理器。
    func makeCoordinator() -> Coordinator {
      Coordinator(draft: draft)
    }

    /// 业务作用：创建不自动替换、不自动大写且隐藏字符的密码输入框。
    /// 参数说明：
    /// - `context`：当前输入框的生命周期上下文。
    /// 返回：原始字符只保存在当前控件中的安全输入框。
    func makeUIView(context: Context) -> UITextField {
      let field = UITextField()
      field.placeholder = title
      field.accessibilityLabel = title
      field.borderStyle = .none
      field.isSecureTextEntry = true
      field.autocorrectionType = .no
      field.spellCheckingType = .no
      field.autocapitalizationType = .none
      field.smartQuotesType = .no
      field.smartDashesType = .no
      field.smartInsertDeleteType = .no
      field.isEnabled = enabled
      field.addTarget(
        context.coordinator, action: #selector(Coordinator.changed(_:)), for: .editingChanged)
      draft.attach(field)
      return field
    }

    /// 业务作用：同步验证期间的输入门禁，不从其它状态恢复旧密码。
    /// 参数说明：
    /// - `field`：当前表单的原生密码框。
    /// - `context`：当前输入框的生命周期上下文。
    /// 返回：只更新可编辑状态，不改变当前输入字符。
    func updateUIView(_ field: UITextField, context: Context) {
      field.isEnabled = enabled
      if field.isSecureTextEntry == revealed {
        let text = field.text
        let selection = field.selectedTextRange.map {
          (
            field.offset(from: field.beginningOfDocument, to: $0.start),
            field.offset(from: field.beginningOfDocument, to: $0.end)
          )
        }
        // 系统切换安全显示时可能重置光标；按原字符恢复选择，不触发新的密码草稿。
        field.isSecureTextEntry = !revealed
        field.text = text
        if let selection,
          let start = field.position(from: field.beginningOfDocument, offset: selection.0),
          let end = field.position(from: field.beginningOfDocument, offset: selection.1)
        {
          field.selectedTextRange = field.textRange(from: start, to: end)
        }
      }
    }

    /// 业务作用：退出当前表单后销毁原生输入和回调。
    /// 参数说明：
    /// - `field`：即将移出的密码框。
    /// - `coordinator`：当前输入通知处理器。
    /// 返回：输入清空且不能再向当前表单发送编辑事件。
    static func dismantleUIView(_ field: UITextField, coordinator: Coordinator) {
      coordinator.draft.detach(field)
      field.removeTarget(coordinator, action: nil, for: .allEvents)
      field.text = ""
    }
  }
#endif

/// 每个输入框独立控制眼睛状态，结束输入或离开前台后恢复隐藏。
struct FolderPasswordFieldRow: View {
  let title: String
  @ObservedObject var draft: FolderPasswordDraft
  let enabled: Bool
  @State private var revealed = false
  @Environment(\.scenePhase) private var scenePhase

  /// 业务作用：把明文显示入口放在输入框右侧，显示与隐藏都使用同一份原生输入。
  /// 参数说明：无。
  /// 返回：默认闭眼隐藏字符，睁眼显示原文；提交、清空或离开前台后隐藏。
  var body: some View {
    HStack(spacing: 8) {
      FolderPasswordField(title: title, draft: draft, enabled: enabled, revealed: revealed)
        .frame(maxWidth: .infinity)
      Button {
        revealed.toggle()
      } label: {
        Image(systemName: revealed ? "eye" : "eye.slash")
          .frame(width: 28, height: 28)
      }
      .buttonStyle(.plain)
      .accessibilityLabel(revealed ? "隐藏密码" : "显示密码")
      .disabled(!enabled)
    }
    .padding(.horizontal, 10)
    .frame(height: 40)
    .background(.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 8))
    .overlay {
      RoundedRectangle(cornerRadius: 8).stroke(.secondary.opacity(0.3), lineWidth: 1)
    }
    .onChange(of: draft.isEmpty) { _, empty in
      if empty {
        revealed = false
      }
    }
    .onChange(of: enabled) { _, value in
      if !value {
        revealed = false
      }
    }
    .onChange(of: scenePhase) { _, value in
      if value != .active {
        revealed = false
      }
    }
    .privacySensitive()
  }
}

/// 弹窗持有呈现身份，具体目录与验证代次始终从当前模型读取，连续验证不能沿用旧表单快照。
struct FolderPasswordPresentation: View {
  @ObservedObject var model: VaultModel
  let presentationID: UUID

  /// 业务作用：在当前呈现内跟随目录和验证身份变化，确保显示、输入与提交属于同一请求。
  /// 参数说明：无。
  /// 返回：只展示仍有效的当前密码表单；旧呈现不能显示或提交后来请求。
  var body: some View {
    if let prompt = model.folderPrompt, prompt.id == presentationID {
      FolderPasswordForm(model: model, prompt: prompt)
        .id(prompt.challengeID)
    }
  }
}

/// 目录密码只在当前表单内存中输入，设置、访问和取消保护均不复用 App 密码。
struct FolderPasswordForm: View {
  @ObservedObject var model: VaultModel
  let prompt: VaultModel.FolderPrompt
  @Environment(\.scenePhase) private var scenePhase
  @StateObject private var password = FolderPasswordDraft()
  @StateObject private var confirmation = FolderPasswordDraft()
  @State private var localError: String?

  /// 业务作用：提供独立目录密码的确认和验证入口，提交后立即丢弃输入原文。
  /// 参数说明：无。
  /// 返回：只操作当前目录的密码表单，离开前台或结束呈现后不保留输入。
  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      Label(prompt.folder.originalFilename, systemImage: "folder.fill")
        .font(.headline).lineLimit(2)
      Text(title).font(.title2.weight(.semibold))
      Text("此密码独立于 App 密码和手势密码。")
        .font(.callout).foregroundStyle(.secondary)
      if let path = model.folderPathLabel(prompt.folder) {
        Text(path).font(.caption.monospaced()).foregroundStyle(.secondary)
          .lineLimit(3)
      }
      passwordField(
        prompt.kind == .setting ? "新文件夹密码" : "文件夹密码", draft: password)
      if prompt.kind == .setting {
        passwordField("再次确认文件夹密码", draft: confirmation)
        Text("使用 6 至 128 个字符。请妥善保存，App 密码和恢复码不能代替此密码。")
          .font(.caption).foregroundStyle(.secondary)
      } else if prompt.kind == .removing {
        Text("验证原密码后取消保护，之后只要解锁 App 即可访问此文件夹。")
          .font(.caption).foregroundStyle(.secondary)
      } else if prompt.kind == .copy {
        Text("仅授权本次解密复制，保险箱内的密码保护保持不变。嵌套受保护目录需要分别验证。")
          .font(.caption).foregroundStyle(.secondary)
      } else if prompt.kind == .move {
        Text("验证目标文件夹密码后才会移入。取消或密码不正确时，来源保持原位。")
          .font(.caption).foregroundStyle(.secondary)
      } else if prompt.kind == .rename {
        Text("验证文件夹独立密码后只更改名称，原密码和内部文件保持不变。")
          .font(.caption).foregroundStyle(.secondary)
      }
      Text("密码区分大小写，空格也属于密码。")
        .font(.caption).foregroundStyle(.secondary)
      if let error = localError ?? model.message {
        Text(error).font(.callout).foregroundStyle(.red)
      }
      HStack {
        Button("取消", role: .cancel) {
          clearDraft()
          model.cancelFolderPrompt()
        }
        .disabled(model.busy)
        Spacer()
        if model.busy {
          ProgressView().controlSize(.small)
        }
        Button(prompt.kind == .setting ? "设置密码" : prompt.kind == .removing ? "取消密码保护" : "验证并继续") {
          submit()
        }
        .buttonStyle(.borderedProminent)
        .disabled(model.busy || password.isEmpty)
      }
    }
    .padding(24)
    .frame(maxWidth: 460)
    #if os(macOS)
      .frame(minWidth: 360)
    #else
      .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    #endif
    .onChange(of: prompt.folder.id) { _, _ in
      clearDraft()
    }
    .onChange(of: scenePhase) { _, phase in
      if phase != .active {
        clearDraft()
      }
    }
    .onDisappear(perform: clearDraft)
    .privacySensitive()
  }

  /// 业务作用：区分访问、单次复制验证与保护设置，避免把输入密码误认为取消保护。
  /// 参数说明：无。
  /// 返回：当前独立目录操作的标题。
  private var title: String {
    switch prompt.kind {
    case .access:
      return "输入文件夹独立密码"
    case .copy:
      return "复制前验证文件夹密码"
    case .move:
      return "移入前验证文件夹密码"
    case .rename:
      return "重命名前验证文件夹密码"
    case .setting:
      return "设置文件夹访问密码"
    case .removing:
      return "取消文件夹访问密码"
    }
  }

  /// 业务作用：收集当前文本密码，不自动更正、替换或提交到系统凭据保存。
  /// 参数说明：
  /// - `title`：当前密码字段的用途说明。
  /// - `draft`：当前表单独占的原生输入拥有者。
  /// 返回：不展示密码原文的独立输入框。
  private func passwordField(_ title: String, draft: FolderPasswordDraft) -> some View {
    FolderPasswordFieldRow(title: title, draft: draft, enabled: !model.busy)
  }

  /// 业务作用：设置时先检查两次输入一致，再交给受 App 会话保护的派生和验证入口。
  /// 参数说明：无。
  /// 返回：确认不一致时保留表单；提交后输入原文立即从视图状态移除。
  private func submit() {
    guard !model.busy else {
      return
    }
    // 在清空控件或更新忙碌状态之前取得原生编辑器快照，后续界面刷新不能改动本次凭据。
    let value = password.take()
    let repeated = confirmation.take()
    if prompt.kind == .setting, !value.utf8.elementsEqual(repeated.utf8) {
      localError = "两次文件夹密码不一致，请重新确认。"
      return
    }
    localError = nil
    model.submitFolderPassword(value, challengeID: prompt.challengeID)
  }

  /// 业务作用：结束或切换当前表单时释放密码与确认输入，不建立草稿或日志。
  /// 参数说明：无。
  /// 返回：密码字段与本地提示全部清空。
  private func clearDraft() {
    password.clear()
    confirmation.clear()
    localError = nil
  }
}

enum CredentialFormMode {
  case setup, change, recovery

  var title: String {
    switch self {
    case .setup: return "设置独立密码"
    case .change: return "修改独立密码"
    case .recovery: return "离线重设密码"
    }
  }
}

/// 新手势只在当前设置流程中保留，确认一致后才交付凭据准备入口。
struct PatternEnrollmentDraft {
  enum Step: Hashable {
    case drawing, confirmation
  }

  enum ConfirmationError: LocalizedError {
    case mismatch

    /// 业务作用：说明两次新手势未匹配，不把设置确认错误当作已有密码认证失败。
    /// 参数说明：无。
    /// 返回：要求留在确认页面重新绘制的提示。
    var errorDescription: String? {
      "两次手势不一致，请重新绘制确认手势。"
    }
  }

  private(set) var step: Step = .drawing
  var input = ""
  private var first = ""

  /// 业务作用：分开接收首次绘制与确认绘制，阻止未确认或不一致的手势进入密码准备。
  /// 参数说明：无。
  /// 返回：首次合法绘制只切换到确认步骤；一致时清空草稿并交付凭据，不一致时清空本次确认并拒绝。
  mutating func finishInput() throws -> VaultCredential? {
    let credential = VaultCredential(kind: .pattern, value: input)
    _ = try credential.encoded()
    input = ""
    if step == .drawing {
      first = credential.value
      step = .confirmation
      return nil
    }
    // 第二次只用于比较，不把首次手势显示回画布，也不允许错误确认触发凭据变更。
    guard credential.value == first else {
      throw ConfirmationError.mismatch
    }
    reset()
    return credential
  }

  /// 业务作用：重新绘制、离开前台或退出设置时丢弃本次两步设置的全部手势材料。
  /// 参数说明：无。
  /// 返回：恢复首次绘制步骤，不保留可用于后续确认的手势。
  mutating func reset() {
    self = PatternEnrollmentDraft()
  }
}

/// 两端锁定界面共用的认证限制提示，不提供跳过冻结的密码入口。
struct CredentialFreezeNotice: View {
  let status: CredentialLockoutStatus
  let now: Date

  /// 业务作用：显示当前冻结倒计时或下一轮剩余尝试次数。
  /// 参数说明：无。
  /// 返回：冻结到期前明确说明输入已禁用；到期后提示三次失败的下轮冻结时长。
  var body: some View {
    let remaining = status.remainingSeconds(at: now.timeIntervalSince1970)
    VStack(spacing: 6) {
      if remaining > 0 {
        Label("密码输入已冻结", systemImage: "lock.clock")
          .font(.headline).foregroundStyle(.orange)
        Text("剩余 " + CredentialLockout.durationText(remaining))
          .monospacedDigit().accessibilityLabel("冻结剩余时间")
        Text("到期后可再次输入密码或手势，也可使用离线恢复码重设。")
          .font(.caption).foregroundStyle(.secondary)
      } else {
        Text(
          "再输错 \(status.availableAttempts(at: now.timeIntervalSince1970)) 次将冻结 "
            + CredentialLockout.durationText(status.nextFreeze)
        )
        .font(.caption).foregroundStyle(.secondary)
      }
    }
  }
}

/// 首次设置、更改与恢复的共同界面，确认恢复码之前不发布新凭据。
struct CredentialForm: View {
  @ObservedObject var model: VaultModel
  let mode: CredentialFormMode
  var dismiss: () -> Void = {}
  @Environment(\.scenePhase) private var scenePhase
  @State private var selectedKind: CredentialKind = .pin
  @State private var old = ""
  @State private var new = ""
  @State private var confirmation = ""
  @State private var recovery = ""
  @State private var localError: String?
  @State private var patternDraft = PatternEnrollmentDraft()
  @State private var patternStarted = false

  /// 业务作用：组织独立凭据设置与恢复码确认，首次和确认手势分别占用一个页面。
  /// 参数说明：无。
  /// 返回：只保留当前设置会话输入的表单。
  var body: some View {
    ScrollView {
      VStack(spacing: 20) {
        Label("EncVault", systemImage: "lock.shield").font(.title)
        Text(mode.title).font(.title2.weight(.semibold))
        if let offer = model.offer {
          RecoveryConfirmation(model: model, offer: offer)
        } else {
          if model.busy {
            Text("正在准备密码…").foregroundStyle(.secondary)
          } else if selectedKind == .pattern && (mode == .setup || patternStarted) {
            patternSetup
          } else {
            credentialDetails
          }
          if let localError {
            Text(localError).foregroundStyle(.red)
          }
          Text("仅使用 EncVault 自己的密码，每次打开都需要验证。")
            .font(.caption).foregroundStyle(.secondary)
        }
        if let message = model.message {
          Text(message).foregroundStyle(.red)
        }
        if model.busy {
          ProgressView()
        }
        if mode != .setup {
          Button("取消") {
            clearDraft()
            model.cancelOffer()
            dismiss()
          }
          .disabled(model.busy)
        }
      }
      .padding(28)
      .frame(maxWidth: 420)
      .frame(maxWidth: .infinity)
    }
    .onChange(of: model.screen) { _, screen in
      if screen == .library && model.offer == nil {
        dismiss()
      }
    }
    .onChange(of: model.offer?.token) { previous, current in
      if previous != nil && current == nil && model.screen == .library {
        dismiss()
      }
    }
    .onChange(of: selectedKind) { _, _ in
      new = ""
      confirmation = ""
      patternDraft.reset()
      patternStarted = false
      localError = nil
    }
    .onChange(of: scenePhase) { _, phase in
      if phase != .active {
        // 离开前台后必须重新绘制两次，不能用重新打开前留存的半完成手势确认密码。
        clearDraft()
      }
    }
    .onDisappear {
      clearDraft()
    }
    #if os(macOS)
      .onReceive(
        NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)
      ) {
        _ in
        clearDraft()
      }
    #endif
    .privacySensitive()
  }

  /// 业务作用：选择新凭据方式时撤销此前未完成的设置，避免跨方式复用确认结果。
  /// 参数说明：无。
  /// 返回：当前新凭据类型的选择器，不改变当前有效密码。
  private var kindPicker: some View {
    Picker("密码方式", selection: $selectedKind) {
      ForEach(CredentialKind.allCases, id: \.self) { kind in
        Text(kind.title).tag(kind)
      }
    }
    .pickerStyle(.segmented)
  }

  /// 业务作用：收集原凭据或恢复材料；新手势在后续页面单独绘制，避免同屏出现多个手势区。
  /// 参数说明：无。
  /// 返回：数字密码表单或进入新手势设置的准备入口，不提前提交密码变更。
  private var credentialDetails: some View {
    Group {
      if mode == .change {
        CredentialInput(title: "当前密码", kind: model.kind, value: $old)
      }
      if mode == .recovery {
        SecureField("离线恢复码", text: $recovery)
          .textFieldStyle(.roundedBorder).autocorrectionDisabled()
      }
      kindPicker
      if selectedKind == .pin {
        PINInput(title: "新密码", value: $new)
        PINInput(title: "再次确认新密码", value: $confirmation)
        Button("继续") {
          submitPIN()
        }
        .buttonStyle(.borderedProminent)
      } else {
        Text("接下来分两步绘制并确认新手势。")
          .font(.callout).foregroundStyle(.secondary)
        Button("开始设置手势") {
          beginPatternSetup()
        }
        .buttonStyle(.borderedProminent)
      }
    }
  }

  /// 业务作用：每页只提供一个新手势输入区，以明确步骤区分首次绘制和确认绘制。
  /// 参数说明：无。
  /// 返回：首次绘制自动进入确认页，确认不一致保留在第二页，并允许从头重新设置。
  private var patternSetup: some View {
    let confirming = patternDraft.step == .confirmation
    return Group {
      if mode == .setup && !confirming {
        kindPicker
      }
      Text(confirming ? "第 2 步 · 确认手势" : "第 1 步 · 设置手势")
        .font(.subheadline.weight(.medium)).foregroundStyle(.secondary)
      PatternInput(
        title: confirming ? "再次绘制相同手势" : "绘制新手势密码",
        value: $patternDraft.input,
        completed: finishPattern
      )
      .id(patternDraft.step)
      Text(confirming ? "两次一致后继续保存恢复码。" : "绘制完成后自动进入确认页面。")
        .font(.callout).foregroundStyle(.secondary)
      if confirming {
        Button("重新绘制") {
          patternDraft.reset()
          localError = nil
        }
      } else if mode != .setup {
        Button("返回") {
          patternDraft.reset()
          patternStarted = false
          localError = nil
        }
      }
    }
  }

  /// 业务作用：只允许当前前台的对应设置入口接收绘制结果或提交密码。
  /// 参数说明：无。
  /// 返回：入口仍有效、空闲且处于前台时为真，失权后的迟到输入拒绝提交。
  private var acceptsInput: Bool {
    guard !model.busy, model.offer == nil else {
      return false
    }
    switch mode {
    case .setup:
      guard model.screen == .setup else {
        return false
      }
    case .change:
      guard model.screen == .library else {
        return false
      }
    case .recovery:
      guard model.screen == .locked else {
        return false
      }
    }
    #if os(macOS)
      return NSApplication.shared.isActive
    #else
      return UIApplication.shared.applicationState == .active
    #endif
  }

  /// 业务作用：收集更改或恢复所需材料后进入独立的新手势绘制，不在同页堆叠旧手势与新手势。
  /// 参数说明：无。
  /// 返回：材料格式可用时进入首次绘制；实际旧密码或恢复码仍由凭据准备操作验证。
  private func beginPatternSetup() {
    guard acceptsInput, selectedKind == .pattern else {
      return
    }
    do {
      if mode == .change {
        _ = try VaultCredential(kind: model.kind, value: old).encoded()
      }
      if mode == .recovery && recovery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        throw VaultError.invalidRecovery
      }
      patternDraft.reset()
      localError = nil
      patternStarted = true
    } catch {
      localError = (error as? LocalizedError)?.errorDescription ?? "输入不合法。"
    }
  }

  /// 业务作用：处理当前页面的一次完整绘制，两次匹配后才把新手势交给凭据准备入口。
  /// 参数说明：无。
  /// 返回：首次绘制进入确认，错误只要求重新确认，一致时进入恢复码准备。
  private func finishPattern() {
    guard acceptsInput, selectedKind == .pattern, mode == .setup || patternStarted else {
      return
    }
    do {
      if let credential = try patternDraft.finishInput() {
        prepare(credential)
      } else {
        localError = nil
      }
    } catch {
      localError = (error as? LocalizedError)?.errorDescription ?? "输入不合法。"
    }
  }

  /// 业务作用：检查两次数字密码一致后请求准备新凭据，不复用手势设置的确认材料。
  /// 参数说明：无。
  /// 返回：合法输入进入恢复码确认；错误留在当前界面，不修改密码。
  private func submitPIN() {
    guard acceptsInput, selectedKind == .pin else {
      return
    }
    let credential = VaultCredential(kind: .pin, value: new)
    do {
      _ = try credential.encoded()
      guard new == confirmation else {
        localError = "两次输入不一致，请重新确认。"
        return
      }
      prepare(credential)
    } catch {
      localError = (error as? VaultError)?.errorDescription ?? "输入不合法。"
    }
  }

  /// 业务作用：统一提交已经重复确认的独立凭据，新密码仍须保存并核对恢复码后才生效。
  /// 参数说明：
  /// - `credential`：两次输入一致且已通过格式检查的新数字密码或新手势。
  /// 返回：请求准备对应的设置、修改或恢复操作，并丢弃界面中的原密码与新凭据草稿。
  private func prepare(_ credential: VaultCredential) {
    guard acceptsInput else {
      return
    }
    switch mode {
    case .setup:
      model.setup(credential)
    case .change:
      model.change(old: VaultCredential(kind: model.kind, value: old), new: credential)
    case .recovery:
      model.recover(code: recovery, new: credential)
    }
    clearDraft()
  }

  /// 业务作用：离开设置、切换前台或提交后释放当前流程收集的全部凭据输入。
  /// 参数说明：无。
  /// 返回：所有输入清空，新手势流程回到起点，不触及已提交的保险箱凭据。
  private func clearDraft() {
    old = ""
    new = ""
    confirmation = ""
    recovery = ""
    localError = nil
    patternDraft.reset()
    patternStarted = false
  }
}

/// 只在当前设置会话显示恢复码，离开前台后不自动恢复显示。
struct RecoveryConfirmation: View {
  @ObservedObject var model: VaultModel
  let offer: EnrollmentOffer
  @State private var acknowledged = false
  @State private var suffix = ""
  @State private var copyMessage: String?

  /// 业务作用：要求用户离线保存并核对恢复码后才开放凭据发布。
  /// 参数说明：无。
  /// 返回：当前票据对应的确认界面；只在用户明确复制时写入限时本机剪贴板，不写入偏好设置。
  var body: some View {
    VStack(spacing: 18) {
      Text("请离线保存恢复码").font(.headline)
      Text(offer.recoveryCode)
        .font(.system(.body, design: .monospaced))
        .padding().background(.quaternary, in: RoundedRectangle(cornerRadius: 12))
      Button {
        copyMessage =
          RecoveryClipboard.copy(offer.recoveryCode)
          ? "已复制，请妥善保存。" : "无法复制恢复码，请重试。"
      } label: {
        Label("复制恢复码", systemImage: "doc.on.doc")
          #if os(iOS)
            .frame(minHeight: 44)
          #endif
      }
      .buttonStyle(.bordered)
      .disabled(model.busy)
      if let copyMessage {
        Text(copyMessage).font(.caption).foregroundStyle(.secondary)
      }
      Text("忘记密码时可用它保留数据并重设密码。密码和恢复码都丢失时，无法解密已有文件。")
        .font(.callout).foregroundStyle(.secondary)
      Toggle("我已妥善离线保存恢复码", isOn: $acknowledged)
      TextField("输入恢复码最后 4 位", text: $suffix)
        .textFieldStyle(.roundedBorder).autocorrectionDisabled()
      Button("确认并启用密码") {
        model.confirmOffer()
      }
      .buttonStyle(.borderedProminent)
      .disabled(
        !acknowledged || suffix.uppercased() != String(offer.recoveryCode.suffix(4)) || model.busy
      )
    }
    .id(offer.token)
    .privacySensitive()
  }
}
