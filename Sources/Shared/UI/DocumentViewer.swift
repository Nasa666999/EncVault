import SwiftUI

/// 受保护文档的自有画布不提供分享、打印、拖出或外部打开入口。
private struct PrivateDocumentPreview: View {
  let document: VaultDocument
  let zoom: CGFloat
  @State private var content: PrivateDocumentContent?
  @State private var failed = false

  /// 业务作用：在目录授权有效时绘制正文、PDF 或 Pages 内嵌预览，避免系统分享绕过导出限制。
  /// 参数说明：无。
  /// 返回：可缩放的应用内内容；不支持的格式保持明确说明，不自动启动系统预览。
  var body: some View {
    Group {
      if let content {
        GeometryReader { geometry in
          ScrollView([.horizontal, .vertical]) {
            let width = max(geometry.size.width - 24, 160) * zoom
            switch content {
            case .text(let text):
              Text(text).font(.system(size: 17 * zoom))
                .frame(width: width, alignment: .topLeading).padding(12)
            case .image(let image):
              VStack {
                Image(decorative: image, scale: 1).resizable()
                  .frame(width: width, height: width * CGFloat(image.height) / CGFloat(image.width))
                Text("Pages 内嵌首页预览").font(.caption).foregroundStyle(.secondary)
              }.padding(12)
            case .pdf(let data):
              if let provider = CGDataProvider(data: data as CFData),
                let pdf = CGPDFDocument(provider), (1...512).contains(pdf.numberOfPages)
              {
                LazyVStack(spacing: 12) {
                  ForEach(1...pdf.numberOfPages, id: \.self) { index in
                    if let page = pdf.page(at: index) {
                      let box = page.getBoxRect(.mediaBox)
                      if box.width > 0, box.height > 0, box.width.isFinite, box.height.isFinite,
                        box.minX.isFinite, box.minY.isFinite,
                        (0.01...100).contains(box.height / box.width)
                      {
                        Canvas { context, size in
                          context.withCGContext { graphics in
                            graphics.setFillColor(CGColor(gray: 1, alpha: 1))
                            graphics.fill(CGRect(origin: .zero, size: size))
                            graphics.translateBy(x: 0, y: size.height)
                            graphics.scaleBy(x: size.width / box.width, y: -size.width / box.width)
                            graphics.translateBy(x: -box.minX, y: -box.minY)
                            graphics.drawPDFPage(page)
                          }
                        }
                        .frame(width: width, height: width * box.height / box.width)
                      }
                    }
                  }
                }.padding(12)
              } else {
                Text("无法安全预览此 PDF。")
              }
            }
          }
        }
      } else if failed {
        Text("此格式暂不支持禁止分享的内置预览。请先取消文件夹密码，再使用系统完整预览。")
          .foregroundStyle(.secondary).padding(24)
      } else {
        ProgressView("正在读取文档")
      }
    }
    .accessibilityIdentifier("禁止导出的文档预览")
    .task(id: document.url) {
      do {
        let result = try DocumentThumbnail.privateContent(document)
        try Task.checkCancellation()
        try document.reader.checkAccess()
        content = result
      } catch {
        failed = true
      }
    }
  }
}

#if os(macOS)
  import Quartz
#else
  import QuickLook
#endif

/// 文档查看与相册播放独立，只有独立认证后开放纯文本编辑，不执行脚本或加载远程资源。
struct VaultDocumentViewer: View {
  let document: VaultDocument
  var editingText: Binding<String>? = nil
  let onClose: () -> Void
  @State private var zoom: CGFloat = 1
  @State private var pinchOrigin: CGFloat?

  /// 业务作用：显示当前明确选择的文档，只在已授权的文本编辑期间绑定内存草稿。
  /// 参数说明：无。
  /// 返回：默认只读的自适应文档画布；草稿不自动写回密文或启动外部应用。
  var body: some View {
    VStack(spacing: 8) {
      Group {
        if let editingText {
          VaultTextEditor(text: editingText, fontSize: baseFontSize * zoom)
        } else if let text = document.text {
          ScrollView {
            Text(text)
              .font(.system(size: baseFontSize * zoom, design: .monospaced))
              .frame(maxWidth: .infinity, alignment: .topLeading)
              .padding(16)
              .accessibilityIdentifier("只读文本内容")
          }
          .simultaneousGesture(
            MagnifyGesture().onChanged { value in
              if pinchOrigin == nil {
                pinchOrigin = zoom
              }
              setZoom((pinchOrigin ?? zoom) * value.magnification)
            }.onEnded { _ in
              pinchOrigin = nil
            })
        } else {
          #if os(macOS)
            if let type = NativeDocumentType(filename: document.media.originalFilename) {
              NativeFormattedDocument(document: document, type: type, zoom: zoom)
                .id(document.url)
                .simultaneousGesture(
                  MagnifyGesture().onChanged { value in
                    if pinchOrigin == nil {
                      pinchOrigin = zoom
                    }
                    setZoom((pinchOrigin ?? zoom) * value.magnification)
                  }.onEnded { _ in
                    pinchOrigin = nil
                  })
            } else {
              if !document.reader.folderRequirements.isEmpty {
                PrivateDocumentPreview(document: document, zoom: zoom)
              } else {
                SystemDocumentPreview(url: document.url, zoom: zoom, onZoom: setZoom)
                  .id(document.url)
                  .accessibilityIdentifier("系统只读文档预览")
              }
            }
          #else
            if !document.reader.folderRequirements.isEmpty {
              PrivateDocumentPreview(document: document, zoom: zoom)
            } else {
              SystemDocumentPreview(url: document.url, onClose: onClose)
                .id(document.url)
                .accessibilityIdentifier("系统只读文档预览")
            }
          #endif
        }
      }
      .frame(maxWidth: .infinity, maxHeight: .infinity)
      #if os(macOS)
        zoomControls
      #else
        if document.text != nil || !document.reader.folderRequirements.isEmpty {
          zoomControls
        }
      #endif
    }
    .onChange(of: document.url) { _, _ in
      zoom = 1
      pinchOrigin = nil
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("只读文档查看")
    .privacySensitive()
  }

  /// 业务作用：让纯文本在当前平台采用可读的默认字号，缩放只影响当前查看。
  /// 参数说明：无。
  /// 返回：Mac 为 14 点，iPhone 为 17 点，不保存文档的阅读偏好。
  private var baseFontSize: CGFloat {
    #if os(macOS)
      14
    #else
      17
    #endif
  }

  /// 业务作用：为只读文档提供明确的缩放入口和当前倍率。
  /// 参数说明：无。
  /// 返回：缩小、放大和还原控制，倍率在本次查看结束时丢弃。
  private var zoomControls: some View {
    HStack(spacing: 16) {
      Button {
        setZoom(zoom / 1.25)
      } label: {
        Label("缩小", systemImage: "minus.magnifyingglass")
      }
      .accessibilityLabel("缩小文档")
      .keyboardShortcut("-", modifiers: .command)
      .disabled(zoom <= 0.5)
      Text("\(Int((zoom * 100).rounded()))%")
        .monospacedDigit()
        .frame(minWidth: 48)
        .accessibilityLabel("文档缩放比例 \(Int((zoom * 100).rounded()))%")
      Button {
        setZoom(zoom * 1.25)
      } label: {
        Label("放大", systemImage: "plus.magnifyingglass")
      }
      .accessibilityLabel("放大文档")
      .keyboardShortcut("+", modifiers: .command)
      .disabled(zoom >= 4)
      Button("还原") {
        setZoom(1)
      }
      .accessibilityLabel("还原文档缩放")
      .keyboardShortcut("0", modifiers: .command)
      .disabled(abs(zoom - 1) < 0.001)
    }
    .buttonStyle(.borderless)
    .padding(.vertical, 4)
  }

  /// 业务作用：约束当前文档的内存缩放状态，防止无效输入或无限放大。
  /// 参数说明：
  /// - `value`：按钮或手势请求的新倍率。
  /// 返回：有限倍率被限制在 50% 至 400%；不写入文件或查看历史。
  private func setZoom(_ value: CGFloat) {
    guard value.isFinite else {
      return
    }
    zoom = min(4, max(0.5, value))
  }
}

/// 每次进入编辑都重新验证当前保险箱凭据，不使用 Face ID 或设备密码。
struct TextEditAuthentication: View {
  @ObservedObject var model: VaultModel
  @State private var password = ""

  /// 业务作用：在开放编辑前重新认证，取消时保持当前文档只读。
  /// 参数说明：无。
  /// 返回：只提供当前凭据类型的输入，错误沿用保险箱的冻结规则。
  var body: some View {
    ScrollView {
      VStack(spacing: 20) {
        Label("验证后编辑", systemImage: "lock.shield").font(.title2)
        Text("请输入保险箱密码，本次授权仅用于编辑当前文件。")
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
          Button("验证并编辑", action: authenticate)
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
          model.requestingTextEdit = false
          model.message = nil
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
    .onDisappear {
      password = ""
    }
  }

  /// 业务作用：只提交完整的当前凭据，提交后立即清空界面密码。
  /// 参数说明：无。
  /// 返回：认证交给会话模型；无效或重复提交不产生新操作。
  private func authenticate() {
    guard !model.busy else {
      return
    }
    let credential = VaultCredential(kind: model.kind, value: password)
    guard (try? credential.encoded()) != nil else {
      return
    }
    password = ""
    model.authenticateTextEditing(credential)
  }
}

#if os(macOS)
  /// 纯文本草稿只绑定内存，关闭智能替换、拼写服务与撤销归档。
  private struct VaultTextEditor: NSViewRepresentable {
    @Binding var text: String
    let fontSize: CGFloat

    /// 业务作用：将原生文本输入同步到当前内存草稿。
    /// 参数说明：无。
    /// 返回：只持有本次绑定的协调器。
    func makeCoordinator() -> Coordinator {
      Coordinator(text: $text)
    }

    /// 业务作用：建立可滚动、自适应窗口的纯文本输入，不开放文档自动保存。
    /// 参数说明：
    /// - `context`：当前草稿绑定上下文。
    /// 返回：不注册最近文档、拼写学习或撤销历史的原生编辑区域。
    func makeNSView(context: Context) -> NSScrollView {
      let scroll = NSScrollView()
      scroll.hasVerticalScroller = true
      scroll.autohidesScrollers = true
      let editor = NSTextView()
      editor.isRichText = false
      editor.importsGraphics = false
      editor.allowsUndo = false
      editor.isContinuousSpellCheckingEnabled = false
      editor.isGrammarCheckingEnabled = false
      editor.isAutomaticSpellingCorrectionEnabled = false
      editor.isAutomaticTextCompletionEnabled = false
      editor.isAutomaticQuoteSubstitutionEnabled = false
      editor.isAutomaticDashSubstitutionEnabled = false
      editor.isAutomaticTextReplacementEnabled = false
      editor.isAutomaticLinkDetectionEnabled = false
      editor.usesFindBar = false
      if #available(macOS 15.0, *) {
        editor.writingToolsBehavior = .none
      }
      editor.isVerticallyResizable = true
      editor.isHorizontallyResizable = false
      editor.autoresizingMask = [.width]
      editor.maxSize = NSSize(
        width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
      editor.textContainer?.widthTracksTextView = true
      editor.textContainer?.containerSize = NSSize(
        width: 0, height: CGFloat.greatestFiniteMagnitude)
      editor.textContainerInset = NSSize(width: 12, height: 12)
      editor.setAccessibilityIdentifier("文本编辑内容")
      editor.delegate = context.coordinator
      editor.string = text
      scroll.documentView = editor
      return scroll
    }

    /// 业务作用：同步当前草稿与字号，避免普通重绘重置光标或正文。
    /// 参数说明：
    /// - `view`：当前草稿的滚动区域。
    /// - `context`：当前内存绑定上下文。
    /// 返回：仅在值变化时更新正文，不产生文件写入。
    func updateNSView(_ view: NSScrollView, context: Context) {
      context.coordinator.text = $text
      guard let editor = view.documentView as? NSTextView else {
        return
      }
      if editor.string != text {
        editor.string = text
      }
      editor.font = .monospacedSystemFont(ofSize: fontSize, weight: .regular)
    }

    /// 业务作用：退出编辑时解除绑定并清空原生输入控件持有的正文。
    /// 参数说明：
    /// - `view`：退出后的编辑区域。
    /// - `coordinator`：即将释放的草稿协调器。
    /// 返回：没有保留可恢复的原生编辑内容。
    static func dismantleNSView(_ view: NSScrollView, coordinator: Coordinator) {
      if let editor = view.documentView as? NSTextView {
        editor.delegate = nil
        editor.string = ""
        editor.undoManager?.removeAllActions()
      }
    }

    @MainActor
    final class Coordinator: NSObject, NSTextViewDelegate {
      var text: Binding<String>

      /// 业务作用：绑定本次编辑正文，不持有文件路径或保存入口。
      /// 参数说明：
      /// - `text`：仅内存草稿绑定。
      /// 返回：当前编辑的输入协调器。
      init(text: Binding<String>) {
        self.text = text
      }

      /// 业务作用：将用户输入交给内存草稿，保存仍由独立按钮触发。
      /// 参数说明：
      /// - `notification`：本次正文变化通知。
      /// 返回：更新绑定，不执行磁盘写入。
      func textDidChange(_ notification: Notification) {
        guard let editor = notification.object as? NSTextView else {
          return
        }
        text.wrappedValue = editor.string
      }
    }
  }
#else
  /// 纯文本输入不使用系统文档编辑器，不建立自动保存或编辑历史。
  private struct VaultTextEditor: UIViewRepresentable {
    @Binding var text: String
    let fontSize: CGFloat

    /// 业务作用：为当前内存草稿建立输入协调器。
    /// 参数说明：无。
    /// 返回：只绑定本次编辑内容的协调器。
    func makeCoordinator() -> Coordinator {
      Coordinator(text: $text)
    }

    /// 业务作用：建立可滚动的本地纯文本输入，关闭自动更正、拼写检查与智能替换。
    /// 参数说明：
    /// - `context`：当前草稿绑定上下文。
    /// 返回：仅接收本次编辑的原生文本区域。
    func makeUIView(context: Context) -> PrivateTextView {
      let view = PrivateTextView()
      view.delegate = context.coordinator
      view.autocorrectionType = .no
      view.spellCheckingType = .no
      view.smartQuotesType = .no
      view.smartDashesType = .no
      view.smartInsertDeleteType = .no
      view.autocapitalizationType = .none
      view.textContentType = nil
      view.dataDetectorTypes = []
      if #available(iOS 18.0, *) {
        view.writingToolsBehavior = .none
      }
      view.accessibilityIdentifier = "文本编辑内容"
      view.text = text
      return view
    }

    /// 业务作用：保持当前草稿与缩放字号，不在重绘时重建输入内容。
    /// 参数说明：
    /// - `view`：当前本地编辑器。
    /// - `context`：当前内存绑定上下文。
    /// 返回：正文和字号同步，不写入磁盘。
    func updateUIView(_ view: PrivateTextView, context: Context) {
      context.coordinator.text = $text
      if view.text != text {
        view.text = text
      }
      view.font = .monospacedSystemFont(ofSize: fontSize, weight: .regular)
    }

    /// 业务作用：退出或锁定时解除输入并丢弃原生控件持有的草稿。
    /// 参数说明：
    /// - `view`：即将移除的编辑器。
    /// - `coordinator`：即将释放的输入绑定。
    /// 返回：键盘关闭、正文清空，不自动保存。
    static func dismantleUIView(_ view: PrivateTextView, coordinator: Coordinator) {
      view.delegate = nil
      view.resignFirstResponder()
      view.text = ""
    }

    @MainActor
    final class Coordinator: NSObject, UITextViewDelegate {
      var text: Binding<String>

      /// 业务作用：绑定本次编辑草稿，不持有文件或自动保存入口。
      /// 参数说明：
      /// - `text`：当前仅内存正文绑定。
      /// 返回：本次编辑的输入协调器。
      init(text: Binding<String>) {
        self.text = text
      }

      /// 业务作用：同步手动输入到内存，禁止通过输入事件自动保存。
      /// 参数说明：
      /// - `textView`：产生当前正文变化的编辑器。
      /// 返回：草稿更新，密文保持不变。
      func textViewDidChange(_ textView: UITextView) {
        text.wrappedValue = textView.text
      }
    }

    final class PrivateTextView: UITextView {
      /// 业务作用：禁止系统撤销管理器持有跨编辑会话的正文快照。
      /// 参数说明：无。
      /// 返回：不提供撤销历史管理器。
      override var undoManager: UndoManager? {
        nil
      }
    }
  }
#endif

#if os(macOS)
  /// 办公正文使用原生文字排版，避免将低分辨率封面当作完整文档。
  private enum NativeDocumentType: Sendable {
    case pages, word, legacyWord, rtf, openDocument

    /// 业务作用：为需要正文排版的文档选择离线解码入口。
    /// 参数说明：
    /// - `filename`：认证的原始文件名。
    /// 返回：支持正文读取的格式；其它格式沿用系统预览。
    init?(filename: String) {
      switch (filename as NSString).pathExtension.lowercased() {
      case "pages":
        if #available(macOS 26.0, *) {
          self = .pages
        } else {
          return nil
        }
      case "docx": self = .word
      case "doc": self = .legacyWord
      case "rtf": self = .rtf
      case "odt": self = .openDocument
      default: return nil
      }
    }

    /// 业务作用：指定原生格式读取器，不把二进制文档当作普通文本。
    /// 参数说明：无。
    /// 返回：对应的原生富文本格式；Pages 使用离线解析器生成的格式化正文。
    var attributedType: NSAttributedString.DocumentType {
      switch self {
      case .pages: return .html
      case .word: return .officeOpenXML
      case .legacyWord: return .docFormat
      case .rtf: return .rtf
      case .openDocument: return .openDocument
      }
    }
  }

  /// 只在当前查看生命周期内保留格式化正文，不向外部应用登记文档。
  private struct NativeFormattedDocument: View {
    let document: VaultDocument
    let type: NativeDocumentType
    let zoom: CGFloat
    @State private var content: NSAttributedString?
    @State private var failure: String?

    /// 业务作用：加载完整正文后原生排版，未取得正文时显示明确进度或失败。
    /// 参数说明：无。
    /// 返回：可缩放、随窗口换行的只读正文，不以缩略图替代失败结果。
    var body: some View {
      Group {
        if let content {
          RichDocumentCanvas(
            content: content, zoom: zoom,
            allowSelection: document.reader.folderRequirements.isEmpty
          )
          .accessibilityIdentifier("原生只读文档正文")
        } else if let failure {
          Text(failure).foregroundStyle(.secondary).padding(24)
        } else {
          ProgressView("正在排版文档正文…")
        }
      }
      .frame(maxWidth: .infinity, maxHeight: .infinity)
      .task(id: document.url) {
        let worker = Task.detached(priority: .userInitiated) {
          if type == .pages {
            return try document.pagesHTML()
          }
          try document.checkOpen()
          return try Data(contentsOf: document.url)
        }
        do {
          let data = try await withTaskCancellationHandler {
            try await worker.value
          } onCancel: {
            worker.cancel()
          }
          try Task.checkCancellation()
          try document.checkOpen()
          let rendered = try NSAttributedString(
            data: data, options: [.documentType: type.attributedType, .timeout: 5.0],
            documentAttributes: nil)
          let readonly = NSMutableAttributedString(attributedString: rendered)
          readonly.removeAttribute(.link, range: NSRange(location: 0, length: readonly.length))
          // 排版期间失去查看权限时，只能丢弃结果，不能重新把正文交回窗口。
          try Task.checkCancellation()
          try document.checkOpen()
          content = NSAttributedString(attributedString: readonly)
        } catch {
          if !Task.isCancelled {
            failure =
              (error as? VaultError)?.errorDescription
              ?? VaultError.documentPreviewUnavailable.errorDescription
          }
        }
      }
      .onDisappear {
        content = nil
        failure = nil
      }
    }
  }

  /// 正文缩放重新计算原生字形与换行，不放大预览图片。
  private struct RichDocumentCanvas: NSViewRepresentable {
    let content: NSAttributedString
    let zoom: CGFloat
    let allowSelection: Bool

    /// 业务作用：建立不带编辑、撤销或最近文档能力的滚动正文区域。
    /// 参数说明：
    /// - `context`：本次原生正文的界面上下文。
    /// 返回：随可用区域排版的只读原生视图。
    func makeNSView(context: Context) -> RichDocumentScrollView {
      RichDocumentScrollView(content: content, allowSelection: allowSelection)
    }

    /// 业务作用：改变字号与段落布局实现清晰缩放，不重启文档解析。
    /// 参数说明：
    /// - `view`：当前只读正文区域。
    /// - `context`：本次原生正文的界面上下文。
    /// 返回：只有倍率变化时重新排版，不写入文件。
    func updateNSView(_ view: RichDocumentScrollView, context: Context) {
      view.textView.isSelectable = allowSelection
      view.applyZoom(zoom)
    }

    /// 业务作用：使用当前窗口分配的正文区域，避免原生内容的理想尺寸压缩视图。
    /// 参数说明：
    /// - `proposal`：SwiftUI 分配的可用区域。
    /// - `nsView`：本次文档正文区域。
    /// - `context`：原生视图上下文。
    /// 返回：有界区域按实际宽高铺满，未分配时由布局系统决定。
    func sizeThatFits(
      _ proposal: ProposedViewSize, nsView: RichDocumentScrollView, context: Context
    ) -> CGSize? {
      guard let width = proposal.width, let height = proposal.height,
        width.isFinite, height.isFinite
      else {
        return nil
      }
      return CGSize(width: max(1, width), height: max(1, height))
    }

    /// 业务作用：结束查看后立即丢弃原生控件持有的正文与布局材料。
    /// 参数说明：
    /// - `view`：即将移除的正文区域。
    /// - `coordinator`：此适配器没有额外协调状态。
    /// 返回：正文清空，不恢复先前选择或缩放位置。
    static func dismantleNSView(_ view: RichDocumentScrollView, coordinator: ()) {
      view.finish()
    }
  }

  @MainActor
  private final class RichDocumentScrollView: NSScrollView {
    let textView = NSTextView()
    private var original: NSAttributedString?
    private var zoom: CGFloat?
    private let bodyScale: CGFloat

    /// 业务作用：将完整正文放入只读文字画布，初始正文字号至少达到常规阅读大小。
    /// 参数说明：
    /// - `content`：经过本次文档权限复验的格式化正文。
    /// - `allowSelection`：未受目录保护的只读文档可选择正文，受保护内容不开放复制或拖出。
    /// 返回：没有编辑、链接跳转、拼写或撤销历史的阅读区域。
    init(content: NSAttributedString, allowSelection: Bool) {
      original = content
      var sizes: [CGFloat: Int] = [:]
      content.enumerateAttribute(.font, in: NSRange(location: 0, length: content.length)) {
        value, range, _ in
        if let font = value as? NSFont {
          sizes[font.pointSize, default: 0] += range.length
        }
      }
      let bodySize = sizes.max(by: { $0.value < $1.value })?.key ?? 16
      bodyScale = max(1, 16 / max(1, bodySize))
      super.init(frame: .zero)
      hasVerticalScroller = true
      autohidesScrollers = true
      borderType = .noBorder
      drawsBackground = true
      backgroundColor = .white
      textView.isEditable = false
      textView.isSelectable = allowSelection
      textView.isRichText = true
      textView.allowsUndo = false
      textView.isContinuousSpellCheckingEnabled = false
      textView.isGrammarCheckingEnabled = false
      textView.isAutomaticLinkDetectionEnabled = false
      textView.usesFindBar = false
      textView.backgroundColor = .white
      textView.isVerticallyResizable = true
      textView.isHorizontallyResizable = false
      textView.autoresizingMask = [.width]
      textView.textContainer?.widthTracksTextView = true
      textView.textContainer?.containerSize = NSSize(
        width: 0, height: CGFloat.greatestFiniteMagnitude)
      textView.maxSize = NSSize(
        width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
      textView.textContainerInset = NSSize(width: 24, height: 24)
      textView.setAccessibilityIdentifier("只读格式化正文")
      if #available(macOS 15.0, *) {
        textView.writingToolsBehavior = .none
      }
      documentView = textView
      setContentHuggingPriority(.defaultLow, for: .horizontal)
      setContentHuggingPriority(.defaultLow, for: .vertical)
      applyZoom(1)
    }

    /// 业务作用：拒绝从系统归档恢复已结束的文档正文。
    /// 参数说明：
    /// - `coder`：系统恢复归档。
    /// 返回：不创建恢复视图，文档必须重新验证并明确打开。
    required init?(coder: NSCoder) {
      return nil
    }

    /// 业务作用：按当前可用宽度重排正文，高度由实际文字内容决定。
    /// 参数说明：无。
    /// 返回：窗口拖大拖小时重新换行，没有固定正文宽高。
    override func layout() {
      super.layout()
      let width = max(1, contentView.bounds.width)
      if abs(textView.frame.width - width) > 0.5 {
        textView.setFrameSize(NSSize(width: width, height: textView.frame.height))
      }
      if let container = textView.textContainer, let manager = textView.layoutManager {
        manager.ensureLayout(for: container)
        let height = max(contentView.bounds.height, manager.usedRect(for: container).height + 48)
        if abs(textView.frame.height - height) > 0.5 {
          textView.setFrameSize(NSSize(width: width, height: height))
        }
      }
    }

    /// 业务作用：从原始样式重新计算字号，重复缩放不累积误差或降低字形清晰度。
    /// 参数说明：
    /// - `value`：当前页面的相对阅读倍率。
    /// 返回：字形重新排版，当前原件和密文保持不变。
    func applyZoom(_ value: CGFloat) {
      guard zoom != value, let original else {
        return
      }
      zoom = value
      let scaled = NSMutableAttributedString(attributedString: original)
      original.enumerateAttribute(.font, in: NSRange(location: 0, length: original.length)) {
        attribute, range, _ in
        let font = attribute as? NSFont ?? NSFont.systemFont(ofSize: 16)
        scaled.addAttribute(
          .font,
          value: NSFontManager.shared.convert(font, toSize: font.pointSize * bodyScale * value),
          range: range)
      }
      textView.textStorage?.setAttributedString(scaled)
      needsLayout = true
    }

    /// 业务作用：结束查看时释放原始格式和原生正文，不保留阅读状态。
    /// 参数说明：无。
    /// 返回：当前控件不再持有文档内容。
    func finish() {
      original = nil
      textView.string = ""
      textView.undoManager?.removeAllActions()
    }
  }

  /// 将系统 Quick Look 嵌入保险箱，不启动外部编辑应用或登记最近文档。
  private struct SystemDocumentPreview: NSViewRepresentable {
    let url: URL
    let zoom: CGFloat
    let onZoom: (CGFloat) -> Void

    /// 业务作用：为本次文档选择创建独立的系统预览视图。
    /// 参数说明：
    /// - `context`：SwiftUI 管理的原生视图上下文。
    /// 返回：关闭自动播放、只绑定本次私有副本的预览视图。
    func makeNSView(context: Context) -> DocumentScrollView {
      let view = DocumentScrollView(url: url)
      view.onZoom = onZoom
      return view
    }

    /// 业务作用：保持系统预览只对应当前原名副本，不恢复其它文档。
    /// 参数说明：
    /// - `view`：当前嵌入的预览视图。
    /// - `context`：SwiftUI 管理的原生视图上下文。
    /// 返回：地址改变时重新加载当前选择，不保存查看状态。
    func updateNSView(_ view: DocumentScrollView, context: Context) {
      view.onZoom = onZoom
      view.load(url)
      if abs(view.magnification - zoom) > 0.001 {
        view.setMagnification(
          zoom,
          centeredAt: NSPoint(x: view.contentView.bounds.midX, y: view.contentView.bounds.midY))
      }
    }

    /// 业务作用：按查看区提议尺寸铺满原生预览，避免使用系统视图的缩略图理想尺寸。
    /// 参数说明：
    /// - `proposal`：SwiftUI 分配给正文的可用区域。
    /// - `nsView`：当前文档的滚动缩放容器。
    /// - `context`：SwiftUI 原生视图上下文。
    /// 返回：有界、非零的可用区域尺寸；尚未分配区域时交还布局系统，不设置固定宽高。
    func sizeThatFits(
      _ proposal: ProposedViewSize, nsView: DocumentScrollView, context: Context
    ) -> CGSize? {
      guard let width = proposal.width, let height = proposal.height,
        width.isFinite, height.isFinite
      else {
        return nil
      }
      return CGSize(
        width: max(1, width),
        height: max(1, height))
    }

    /// 业务作用：从界面移除文档时释放系统预览持有的内容与句柄。
    /// 参数说明：
    /// - `view`：即将移除的系统视图。
    /// - `coordinator`：此适配器无独立协调状态。
    /// 返回：原生预览关闭，不允许继续接收文件。
    static func dismantleNSView(_ view: DocumentScrollView, coordinator: ()) {
      view.finish()
    }
  }

  /// 只读系统预览使用全部正文区域，缩放在滚动容器内完成，不依赖系统内部的缩放状态。
  @MainActor
  private final class DocumentScrollView: NSScrollView {
    private let preview = QLPreviewView(frame: .zero, style: .normal)!
    private var source: URL?
    private var loaded: URL?
    var onZoom: ((CGFloat) -> Void)?

    /// 业务作用：建立可滚动缩放的文档画布，延后到可用布局完成再加载系统预览。
    /// 参数说明：
    /// - `url`：当前完整认证后的原名副本。
    /// 返回：具备 50% 至 400% 缩放能力的私有查看容器。
    init(url: URL) {
      source = url
      super.init(frame: .zero)
      borderType = .noBorder
      drawsBackground = false
      hasHorizontalScroller = true
      hasVerticalScroller = true
      autohidesScrollers = true
      allowsMagnification = true
      minMagnification = 0.5
      maxMagnification = 4
      preview.shouldCloseWithWindow = false
      preview.autostarts = false
      documentView = preview
      setContentHuggingPriority(.defaultLow, for: .horizontal)
      setContentHuggingPriority(.defaultLow, for: .vertical)
    }

    /// 业务作用：禁止通过系统恢复材料重新打开已经失效的文档副本。
    /// 参数说明：
    /// - `coder`：系统提供的恢复归档。
    /// 返回：拒绝恢复，文档只能由新的明确选择打开。
    required init?(coder: NSCoder) {
      return nil
    }

    /// 业务作用：让原生预览按当前窗口正文大小排版，而非沿用初始零尺寸。
    /// 参数说明：无。
    /// 返回：预览基准尺寸与查看区一致，倍率由滚动容器独立维护。
    override func layout() {
      super.layout()
      let size = contentView.frame.size
      if size.width > 0, size.height > 0, preview.frame.size != size {
        preview.setFrameSize(size)
      }
      beginPreviewIfReady()
    }

    /// 业务作用：进入真实窗口后再交付文档，避免在没有显示区域时启动系统文档转换。
    /// 参数说明：无。
    /// 返回：有可用区域时加载当前副本；未进入窗口时保持等待。
    override func viewDidMoveToWindow() {
      super.viewDidMoveToWindow()
      needsLayout = true
      beginPreviewIfReady()
    }

    /// 业务作用：只在文件身份实际变化时重新加载，保持缩放引起的重绘不重启文档转换。
    /// 参数说明：
    /// - `url`：当前明确选择的原名副本。
    /// 返回：相同副本不重复交付系统，变化时撤下上一项再等待有效区域。
    func load(_ url: URL) {
      if source != url {
        preview.previewItem = nil
        source = url
        loaded = nil
      }
      beginPreviewIfReady()
    }

    /// 业务作用：满足可见窗口与非零区域后，只交付一次当前原名文档。
    /// 参数说明：无。
    /// 返回：没有重复转换；仍未获得有效区域时不提前启动系统服务。
    private func beginPreviewIfReady() {
      guard window != nil, preview.bounds.width > 0, preview.bounds.height > 0,
        let source, loaded != source
      else {
        return
      }
      loaded = source
      preview.previewItem = source as NSURL
    }

    /// 业务作用：将触控板原生缩放同步到当前页面倍率，不保存阅读状态。
    /// 参数说明：
    /// - `event`：触控板放大或缩小事件。
    /// 返回：系统处理缩放和平移，按钮显示同步到当前倍率。
    override func magnify(with event: NSEvent) {
      super.magnify(with: event)
      onZoom?(magnification)
    }

    /// 业务作用：结束查看时撤下文件并释放系统预览，不留跨文件的查看状态。
    /// 参数说明：无。
    /// 返回：原名 URL、缩放回调和系统预览全部撤销。
    func finish() {
      source = nil
      loaded = nil
      onZoom = nil
      preview.previewItem = nil
      preview.close()
    }
  }
#else
  /// 通过系统正式展示入口打开只读文档，完整预览随保险箱锁定而撤下。
  private struct SystemDocumentPreview: UIViewControllerRepresentable {
    let url: URL
    let onClose: () -> Void

    /// 业务作用：提供当前单个文档的数据源，隔离其它保险箱文件。
    /// 参数说明：无。
    /// 返回：只保留当前副本 URL 的协调器。
    func makeCoordinator() -> Coordinator {
      Coordinator(url: url, onClose: onClose)
    }

    /// 业务作用：建立只读系统文档预览，不开放编辑或外部链接跳转。
    /// 参数说明：
    /// - `context`：持有本次单文件数据源的界面上下文。
    /// 返回：仅在进入窗口后正式呈现系统预览的宿主。
    func makeUIViewController(context: Context) -> PreviewHost {
      let controller = QLPreviewController()
      controller.dataSource = context.coordinator
      controller.delegate = context.coordinator
      controller.modalPresentationStyle = .fullScreen
      controller.currentPreviewItemIndex = 0
      return PreviewHost(preview: controller)
    }

    /// 业务作用：使已有控制器保持本次文件身份，不添加其它文档或播放状态。
    /// 参数说明：
    /// - `controller`：当前系统预览控制器。
    /// - `context`：持有单文件数据源的界面上下文。
    /// 返回：当前地址不变时不重复加载。
    func updateUIViewController(_ controller: PreviewHost, context: Context) {
    }

    /// 业务作用：界面退出时撤下系统数据源，停止继续索取私有文档。
    /// 参数说明：
    /// - `controller`：即将移除的系统控制器。
    /// - `coordinator`：仅属于该控制器的数据源。
    /// 返回：预览条目被撤下，系统控制器不再持有可读取的文档列表。
    static func dismantleUIViewController(
      _ controller: PreviewHost, coordinator: Coordinator
    ) {
      controller.preview.dataSource = nil
      controller.preview.delegate = nil
      controller.preview.reloadData()
      controller.dismiss(animated: false)
    }

    @MainActor
    final class Coordinator: NSObject, QLPreviewControllerDataSource, QLPreviewControllerDelegate {
      let item: OriginalDocumentItem
      let onClose: () -> Void

      /// 业务作用：绑定当前已完整验证的原名文件副本。
      /// 参数说明：
      /// - `url`：本次只读查看拥有的私有位置。
      /// - `onClose`：系统结束查看后撤销选择与清理副本的入口。
      /// 返回：单文件数据源，不枚举其它保险箱内容。
      init(url: URL, onClose: @escaping () -> Void) {
        item = OriginalDocumentItem(url: url)
        self.onClose = onClose
      }

      /// 业务作用：限制系统预览只读取当前明确选择的文档。
      /// 参数说明：
      /// - `controller`：请求条目数量的系统预览。
      /// 返回：始终为一个文档。
      func numberOfPreviewItems(in controller: QLPreviewController) -> Int {
        1
      }

      /// 业务作用：以原文件名交付本次经过验证的私有副本。
      /// 参数说明：
      /// - `controller`：请求内容的系统预览。
      /// - `index`：系统当前选择的单个条目位置。
      /// 返回：本次只读文档，不交付密文或其它保险箱路径。
      func previewController(
        _ controller: QLPreviewController, previewItemAt index: Int
      ) -> any QLPreviewItem {
        item
      }

      /// 业务作用：系统完成文档查看后结束本次明文副本的所有权。
      /// 参数说明：
      /// - `controller`：已经结束展示的只读系统预览。
      /// 返回：主线程关闭保险箱文档页面，不保留最近选择。
      nonisolated func previewControllerDidDismiss(_ controller: QLPreviewController) {
        Task { @MainActor [weak self] in
          self?.onClose()
        }
      }

      /// 业务作用：禁止系统标注、裁剪及其它文档写回行为。
      /// 参数说明：
      /// - `controller`：显示当前文档的系统预览。
      /// - `previewItem`：当前只读副本。
      /// 返回：始终禁用编辑，保险箱密文不会被修改。
      nonisolated func previewController(
        _ controller: QLPreviewController, editingModeFor previewItem: any QLPreviewItem
      ) -> QLPreviewItemEditingMode {
        .disabled
      }

      /// 业务作用：阻止文档中的链接跳转到网络或其它应用。
      /// 参数说明：
      /// - `controller`：当前系统预览。
      /// - `url`：文档尝试打开的链接。
      /// - `item`：产生链接的当前文档。
      /// 返回：始终拒绝跳转，保持离线只读查看。
      nonisolated func previewController(
        _ controller: QLPreviewController, shouldOpen url: URL, for item: any QLPreviewItem
      ) -> Bool {
        false
      }
    }
  }

  /// 原始文件名完整交付给系统，不由系统自动省略扩展名。
  private final class OriginalDocumentItem: NSObject, QLPreviewItem {
    let previewItemURL: URL?
    let previewItemTitle: String?

    /// 业务作用：为当前已认证副本提供系统原名和本地地址。
    /// 参数说明：
    /// - `url`：本次只读副本的原名路径。
    /// 返回：单文档预览身份，不携带密码或其它文件地址。
    init(url: URL) {
      previewItemURL = url
      previewItemTitle = url.lastPathComponent
    }
  }

  /// 系统文档完整预览使用正式模态呈现，避免把办公文档退化为嵌入式静态内容。
  @MainActor
  private final class PreviewHost: UIViewController {
    let preview: QLPreviewController
    private var presented = false

    /// 业务作用：绑定本次选择的系统预览，等待进入窗口再开放展示。
    /// 参数说明：
    /// - `preview`：本次文档专用的只读控制器。
    /// 返回：没有自动打开其它文件能力的宿主。
    init(preview: QLPreviewController) {
      self.preview = preview
      super.init(nibName: nil, bundle: nil)
    }

    /// 业务作用：禁止从系统恢复归档重新打开已经失效的文档。
    /// 参数说明：
    /// - `coder`：系统尝试使用的界面恢复归档。
    /// 返回：拒绝恢复；文档必须经过新的独立密码会话和明确选择。
    required init?(coder: NSCoder) {
      return nil
    }

    /// 业务作用：宿主进入窗口后呈现本次文档，结束后不循环重新打开。
    /// 参数说明：
    /// - `animated`：宿主当前展示转换的动画状态。
    /// 返回：每个宿主最多呈现一次系统预览。
    override func viewDidAppear(_ animated: Bool) {
      super.viewDidAppear(animated)
      guard !presented else {
        return
      }
      presented = true
      present(preview, animated: false)
    }
  }
#endif
