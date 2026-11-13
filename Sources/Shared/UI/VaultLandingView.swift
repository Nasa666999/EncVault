import Photos
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

/// 两端共用的离线保险箱入口，任何查看状态均随锁定清空。
struct VaultLandingView: View {
  private enum FileSelection {
    case media
    case importDirectory
    case systemDirectory
  }
  @ObservedObject var model: VaultModel
  @Environment(\.scenePhase) private var scenePhase
  @State private var password = ""
  @State private var changing = false
  @State private var recovering = false
  @State private var choosingFile = false
  @State private var fileSelection: FileSelection = .media
  @State private var sourceConfirmation = false
  @State private var eraseConfirmation = false
  @State private var eraseText = ""
  @State private var deleting: VaultMedia?
  @State private var deletingSelection: [VaultMedia] = []
  @State private var renamingItem: VaultMedia?
  @State private var renamedItemName = ""
  @State private var systemSaveMedia: VaultMedia?
  @State private var systemSaveAction = SystemSaveAction.export
  @State private var systemSaveWarning = false
  @State private var choosingPhotos = false
  @State private var selectedPhotos: [PhotosPickerItem] = []
  @State private var fullScreen = false
  @State private var exitEditingConfirmation = false
  @State private var creatingFolder = false
  @State private var folderName = ""
  @State private var pendingMove: ([VaultMedia], UUID?)?
  @State private var pendingMovePath: ([VaultMedia], String)?
  @State private var moveByPath = false
  @State private var movePath = ""
  @AppStorage(VaultWindowPolicy.lockWhenInactiveKey) private var lockWhenInactive = true
  #if os(macOS)
    @State private var nativePanel: NSOpenPanel?
    @AppStorage(VaultWindowPolicy.allowScreenshotsKey) private var allowScreenshots = false
  #endif

  /// 业务作用：仅在独立验证成功后开放媒体列表与查看入口。
  /// 参数说明：无。
  /// 返回：当前前台会话界面，不恢复最近文件或播放进度。
  var body: some View {
    operationDialogs
      .alert(
        "无法移动",
        isPresented: Binding(
          get: { model.moveFailure != nil },
          set: { if !$0 { model.moveFailure = nil } })
      ) {
        Button("确定", role: .cancel) {
          model.moveFailure = nil
        }
      } message: {
        Text(model.moveFailure ?? "")
      }
      .alert(
        "相册导入未完成",
        isPresented: Binding(
          get: {
            model.photoImportFailure != nil
          },
          set: { presented in
            if !presented {
              model.photoImportFailure = nil
            }
          })
      ) {
        Button("确定", role: .cancel) {
          model.photoImportFailure = nil
        }
      } message: {
        Text(model.photoImportFailure ?? "原件已保留，请重试。")
      }
      .onChange(of: model.savedSources.count + model.savedPhotos.count) { _, count in
        sourceConfirmation = count > 0
      }
      .onChange(of: model.screen) { _, _ in
        password = ""
        changing = false
        recovering = false
        eraseConfirmation = false
        sourceConfirmation = false
        eraseText = ""
        exitEditingConfirmation = false
        if model.screen != .library {
          deleting = nil
          deletingSelection = []
          renamingItem = nil
          renamedItemName = ""
          systemSaveWarning = false
          systemSaveMedia = nil
          systemSaveAction = .export
          leaveFullScreen()
        }
      }
      .onChange(of: model.selected?.id) { _, id in
        if id == nil {
          leaveFullScreen()
        }
      }
      #if os(macOS)
        .onReceive(
          NotificationCenter.default.publisher(for: NSWindow.didEnterFullScreenNotification)
        ) {
          notification in
          guard let window = notification.object as? NSWindow,
            window == NSApplication.shared.mainWindow,
            model.screen == .library, model.selected != nil
          else {
            return
          }
          fullScreen = true
        }
        .onReceive(
          NotificationCenter.default.publisher(for: NSWindow.didExitFullScreenNotification)
        ) {
          notification in
          guard let window = notification.object as? NSWindow,
            window == NSApplication.shared.mainWindow
          else {
            return
          }
          fullScreen = false
        }
        .onReceive(
          NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)
        ) {
          _ in
          if model.shouldLockWhenInactive {
            conceal()
          }
        }
        .onReceive(
          NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)
        ) {
          _ in model.lock()
        }
      #else
        .onReceive(
          NotificationCenter.default.publisher(for: UIDevice.orientationDidChangeNotification)
        ) { _ in
          if fullScreen, model.playback != nil {
            VaultVideoOrientation.shared.followDevice()
          }
        }
        .onChange(of: model.playback != nil) { _, playingVideo in
          if fullScreen, playingVideo {
            VaultVideoOrientation.shared.enter()
          } else if !playingVideo, model.selected?.isVideo != true {
            VaultVideoOrientation.shared.leave()
          }
        }
        .onChange(of: scenePhase) { _, phase in
          if phase != .active, model.shouldLockWhenInactive {
            conceal()
          }
        }
      #endif
      .privacySensitive()
  }

  /// 业务作用：按会话状态选择锁定、相册或当前媒体内容。
  /// 参数说明：无。
  /// 返回：只展示当前授权状态允许的主内容。
  private var activeContent: some View {
    Group {
      switch model.screen {
      case .setup:
        CredentialForm(model: model, mode: .setup)
      case .locked:
        locked
      case .library:
        library
      case .unavailable:
        VStack(spacing: 20) {
          Label("保险箱暂时不可用", systemImage: "lock.trianglebadge.exclamationmark")
          Text(model.message ?? "请确认没有另一个实例正在使用保险箱。")
        }
        .padding(32)
      }
    }
  }

  /// 业务作用：为当前内容挂接凭据管理和明确清空入口。
  /// 参数说明：无。
  /// 返回：带当前会话密码弹窗的内容，不自动提交凭据。
  private var credentialContent: some View {
    activeContent
      #if os(macOS)
        .frame(minWidth: 340, minHeight: 520)
      #else
        .frame(maxWidth: .infinity, maxHeight: .infinity)
      #endif
      .overlay(VaultWindowProtection(model: model).allowsHitTesting(false))
      .sheet(
        isPresented: $changing,
        onDismiss: {
          model.cancelOffer()
        }
      ) {
        CredentialForm(
          model: model, mode: .change,
          dismiss: {
            changing = false
          }
        )
        #if os(macOS)
          .frame(minWidth: 340, minHeight: 520)
        #else
          .frame(maxWidth: .infinity, maxHeight: .infinity)
        #endif
      }
      .sheet(
        isPresented: $recovering,
        onDismiss: {
          model.cancelOffer()
        }
      ) {
        CredentialForm(
          model: model, mode: .recovery,
          dismiss: {
            recovering = false
          }
        )
        #if os(macOS)
          .frame(minWidth: 340, minHeight: 520)
        #else
          .frame(maxWidth: .infinity, maxHeight: .infinity)
        #endif
      }
      .sheet(isPresented: $eraseConfirmation) {
        VStack(spacing: 20) {
          Text("清空保险箱").font(.title2)
          Text("这会永久删除保险箱内的全部加密文件。仅在密码和恢复码均丢失时使用。来源原件不受影响。")
          TextField("输入“清空保险箱”确认", text: $eraseText).textFieldStyle(.roundedBorder)
          Button("永久清空", role: .destructive) {
            eraseConfirmation = false
            eraseText = ""
            model.erase()
          }
          .disabled(eraseText != "清空保险箱")
          Button("取消") {
            eraseConfirmation = false
            eraseText = ""
          }
        }
        .padding(28).frame(maxWidth: 420)
      }
      .sheet(isPresented: $model.requestingTextEdit) {
        TextEditAuthentication(model: model)
          .interactiveDismissDisabled(model.busy)
      }
      .sheet(
        item: Binding(
          get: {
            model.automaticLockRequest
          },
          set: { request in
            if request == nil {
              model.cancelAutomaticLockRequest()
            }
          })
      ) { request in
        AutomaticLockAuthentication(model: model, requestID: request.id)
          .interactiveDismissDisabled()
      }
      .sheet(item: $model.folderPrompt) { prompt in
        FolderPasswordPresentation(model: model, presentationID: prompt.id)
          .interactiveDismissDisabled()
      }
      .sheet(
        item: $model.movingMedia,
        onDismiss: {
          movePath = ""
          if let request = pendingMovePath {
            pendingMovePath = nil
            model.move(request.0, toVaultPath: request.1)
          } else if let request = pendingMove {
            pendingMove = nil
            model.move(request.0, to: request.1)
          }
        }
      ) { request in
        let media = request.media
        VStack(alignment: .leading, spacing: 16) {
          Text(moveByPath ? "移动到指定目录" : "移动到文件夹").font(.title2.weight(.semibold))
          Text(media.count == 1 ? media.first?.originalFilename ?? "" : "已选择 \(media.count) 项")
            .foregroundStyle(.secondary).lineLimit(2)
          if moveByPath {
            Text("手动输入保险箱内的目录。/ 表示保险箱根目录。")
              .font(.callout).foregroundStyle(.secondary)
            TextField("例如 /cp 或 /import/cc", text: $movePath)
              .textFieldStyle(.roundedBorder).autocorrectionDisabled()
              .accessibilityLabel("保险箱目标目录")
              #if os(iOS)
                .textInputAutocapitalization(.never)
              #endif
            Text("只移动到已存在的目录；有保护密码时继续验证。")
              .font(.caption).foregroundStyle(.secondary)
            Button("移动") {
              pendingMovePath = (media, movePath)
              model.movingMedia = nil
            }
            .buttonStyle(.borderedProminent)
            .disabled(movePath.isEmpty)
          } else {
            let destinations = model.moveDestinations(for: media)
            if destinations.isEmpty {
              Text("暂无可用目标，请先返回保险箱新建文件夹。")
            } else {
              List(Array(destinations.enumerated()), id: \.offset) { _, destination in
                Button {
                  pendingMove = (media, destination.id)
                  model.movingMedia = nil
                } label: {
                  Label(destination.title, systemImage: "folder.fill")
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .accessibilityIdentifier("移动目标-" + destination.title)
              }
            }
          }
          Button("取消移动") {
            pendingMove = nil
            pendingMovePath = nil
            model.movingMedia = nil
          }
        }
        .padding(24)
        #if os(macOS)
          .frame(minWidth: 420, minHeight: 380)
        #endif
      }
      .alert("新建文件夹", isPresented: $creatingFolder) {
        TextField("文件夹名称", text: $folderName)
        Button("创建") {
          let name = folderName
          folderName = ""
          model.createFolder(name)
        }
        Button("取消", role: .cancel) {
          folderName = ""
        }
      }
      .alert(
        renamingItem?.isFolder == true && renamingItem?.isDocument == false ? "重命名文件夹" : "重命名文件",
        isPresented: Binding(
          get: {
            renamingItem != nil
          },
          set: { presented in
            if !presented {
              renamingItem = nil
              renamedItemName = ""
            }
          })
      ) {
        TextField("新名称", text: $renamedItemName)
        Button("重命名") {
          if let media = renamingItem {
            if media.isFolder && !media.isDocument {
              model.renameFolder(media, to: renamedItemName)
            } else {
              model.renameFile(media, to: renamedItemName)
            }
          }
          renamingItem = nil
          renamedItemName = ""
        }
        .disabled(renamedItemName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        Button("取消", role: .cancel) {
          renamingItem = nil
          renamedItemName = ""
        }
      } message: {
        if renamingItem?.isFolder == true && renamingItem?.isDocument == false {
          Text("只更改文件夹名称，内容和原密码保持不变。受保护文件夹需要验证独立密码。")
        } else {
          Text("请保留原扩展名。只更改文件名称，内容、格式和所在目录保持不变。")
        }
      }
  }

  /// 业务作用：为明确的文件与相册选择请求提供统一呈现入口。
  /// 参数说明：无。
  /// 返回：只处理本次选择结果，不恢复先前来源。
  private var selectionContent: some View {
    credentialContent
      .fileImporter(
        isPresented: $choosingFile,
        allowedContentTypes: fileSelection == .media ? [.item] : [.folder],
        allowsMultipleSelection: fileSelection == .media
      ) { result in
        completeFileSelection(result)
      }
      .photosPicker(
        isPresented: $choosingPhotos, selection: $selectedPhotos,
        matching: .any(of: [.images, .videos]), preferredItemEncoding: .current,
        photoLibrary: .shared()
      )
      .onChange(of: selectedPhotos) { _, selected in
        if !selected.isEmpty {
          selectedPhotos = []
          model.importPhotos(selected)
        }
      }
  }

  /// 业务作用：在删除、系统复制、导出和删源之前呈现独立的用户确认。
  /// 参数说明：无。
  /// 返回：保留各操作明确边界的确认界面。
  private var operationDialogs: some View {
    selectionContent
      .confirmationDialog(
        "永久删除所选 \(deletingSelection.count) 项及其中内容？",
        isPresented: Binding(
          get: {
            !deletingSelection.isEmpty
          },
          set: { presented in
            if !presented {
              deletingSelection = []
            }
          })
      ) {
        Button("删除所选项目", role: .destructive) {
          let confirmed = deletingSelection
          deletingSelection = []
          model.delete(confirmed)
        }
        Button("取消", role: .cancel) {
          deletingSelection = []
        }
      } message: {
        Text("此操作不能撤销，将永久删除保险箱内所选项目及文件夹内容。包含密码保护目录时整批拒绝，请先取消相关保护。系统来源和已复制的副本不受影响。")
      }
      .confirmationDialog(
        deleting?.isFolder == true ? "永久删除此文件夹及全部内容？" : "永久删除此加密文件？",
        isPresented: Binding<Bool>(
          get: {
            deleting != nil
          },
          set: {
            if !$0 {
              deleting = nil
            }
          }
        )
      ) {
        Button(deleting?.isFolder == true ? "删除保险箱内文件夹" : "删除保险箱内文件", role: .destructive) {
          if let media = deleting {
            model.delete(media)
          }
          deleting = nil
        }
      } message: {
        Text(
          deleting?.isFolder == true
            ? "此操作不能撤销，将永久删除文件夹及其中全部加密子项。目录树中仍有密码保护时不能删除，请先取消相关文件夹密码。来源原件和此前导出的副本不受影响。"
            : "此操作不能撤销。来源原件和此前导出的副本不受影响。")
      }
      .confirmationDialog(systemSaveAction.title, isPresented: $systemSaveWarning) {
        Button("选择本地目录并\(systemSaveAction.rawValue)") {
          chooseFiles(for: .systemDirectory)
        }
        if let media = systemSaveMedia, media.isImage || media.isVideo {
          Button(systemSaveAction == .copy ? "复制到系统照片" : "保存到系统照片") {
            switch systemSaveAction {
            case .copy:
              model.copyToPhotos(media)
            case .export:
              model.exportToPhotos(media)
            }
            systemSaveMedia = nil
          }
        }
        #if os(macOS)
          // Mac 识别取消角色后不会再自动补出第二个取消按钮。
          Button("取消", role: .cancel) {
            systemSaveMedia = nil
          }
        #else
          // iPhone 弹出菜单会隐藏系统取消动作，保留一个可见的返回入口。
          Button("取消") {
            systemSaveMedia = nil
          }
        #endif
      } message: {
        Text(
          systemSaveAction == .copy
            ? "按原名生成未加密副本，保险箱内原件继续保留，密码保护不变。受保护目录每次复制需重新验证，文件夹包含全部内容。系统副本可能按系统设置同步或备份。"
            : "按原名保存未加密副本，保险箱内原件继续保留。受保护内容需先取消目录密码。系统副本可能按系统设置同步或备份。"
        )
      }
      .confirmationDialog("加密保存并复验完成", isPresented: $sourceConfirmation) {
        // 保留来源是正式的收尾选择，浮层呈现时也必须直接显示，不能只依赖点外部取消。
        Button("保留原件") {
          model.savedSources = []
          model.savedPhotos = []
        }
        Button("删除已保存的原件", role: .destructive) {
          model.removeSavedSources()
        }
      } message: {
        #if os(macOS)
          Text("本地原件将直接删除，不进入废纸篓，无法通过废纸篓恢复；删除前会再次完整复验加密副本。系统照片仍受最近删除和 iCloud 同步规则管理。")
        #else
          Text("只删除刚完成加密并完整复验的原件。系统照片可能保留最近删除，并按 iCloud 设置同步到其它设备。")
        #endif
      }
  }

  /// 业务作用：在独立密码验证前只开放认证、恢复和明确清空入口。
  /// 参数说明：无。
  /// 返回：不展示媒体元数据的锁定界面。
  private var locked: some View {
    CredentialUnlockView(
      model: model, password: $password, unlock: unlock,
      recover: {
        recovering = true
      },
      erase: {
        eraseConfirmation = true
      })
  }

  /// 业务作用：在统一缩略图相册和当前媒体查看之间切换，保持独立密码会话边界。
  /// 参数说明：无。
  /// 返回：未选择时显示相册网格；选择后让图片和视频占满查看区，不堆叠多行标题栏。
  private var library: some View {
    Group {
      if let media = model.selected {
        if media.isImage || media.isVideo {
          VaultMediaBrowser(
            model: model, fullScreen: fullScreen, toggleFullScreen: toggleFullScreen,
            rotateVideo: rotateVideo
          ) {
            mediaActions(media)
          }
        } else {
          fileDetails(media)
        }
      } else {
        VStack(spacing: 4) {
          libraryToolbar
          if model.visibleItems.isEmpty {
            Spacer()
            Image(systemName: "photo.on.rectangle.angled").font(.largeTitle).foregroundStyle(
              .secondary)
            Text(model.currentFolderID == nil ? "保险箱为空" : "文件夹为空").font(.title2)
            Text("导入文件或整个文件夹，解锁后查看。")
              .font(.callout).foregroundStyle(.secondary)
            Spacer()
          } else {
            VaultAlbumGrid(
              model: model,
              actions: {
                mediaActionItems($0)
              })
          }
          if model.selecting {
            selectionControls
          }
          if model.busy {
            importStatus
          }
          if let message = model.message {
            Text(message).font(.caption).foregroundStyle(.secondary).padding(.horizontal, 12)
          }
        }
      }
    }
  }

  /// 业务作用：展示正在处理的文件、阶段与已提交数量，目录遍历不伪装成已知总量。
  /// 参数说明：无。
  /// 返回：有界刷新且不保存历史的导入状态，并保留随时取消与锁定入口。
  private var importStatus: some View {
    VStack(alignment: .leading, spacing: 6) {
      if let status = model.importProgress {
        HStack {
          Text(status.phase.title).font(.callout.weight(.medium))
          Text(status.filename).lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
          Spacer(minLength: 0)
        }
        if let fraction = status.fraction {
          ProgressView(value: fraction)
        } else {
          ProgressView().controlSize(.small)
        }
        Text(
          "已保存 \(status.completedFiles) 项 · \(ByteCountFormatter.string(fromByteCount: Int64(clamping: status.completedBytes), countStyle: .file))"
        )
        .font(.caption).foregroundStyle(.secondary)
      } else {
        ProgressView(model.importing ? "正在准备导入…" : "正在处理…")
      }
      HStack {
        #if os(macOS)
          if model.importing {
            Text("导入期间可切换应用；结束后恢复原自动锁定设置。")
              .font(.caption).foregroundStyle(.secondary)
          }
        #endif
        Spacer(minLength: 0)
        Button("取消并锁定") {
          model.cancelOperation()
        }
      }
    }
    .padding(12)
    .accessibilityIdentifier("导入进度")
  }

  /// 业务作用：为普通文档提供独立的加密文件管理页，不接入媒体播放、缩略图或滑动序列。
  /// 参数说明：
  /// - `media`：当前明确选中的非图片、非视频文件。
  /// 返回：原名标题、只读文档或明确的不可预览说明，保留导出和删除入口。
  private func fileDetails(_ media: VaultMedia) -> some View {
    VStack(spacing: 16) {
      HStack {
        Button {
          if model.editingText != nil {
            exitEditingConfirmation = true
          } else {
            model.closeViewer()
          }
        } label: {
          Image(systemName: "chevron.left").frame(width: 44, height: 44)
        }
        .accessibilityLabel("关闭文件详情")
        .disabled(model.busy)
        Text(media.originalFilename).font(.headline).lineLimit(1).truncationMode(.middle)
        Spacer()
        Button("锁定") {
          model.lock()
        }
        Menu {
          mediaActions(media)
        } label: {
          Image(systemName: "ellipsis.circle").frame(width: 44, height: 44)
        }
        .accessibilityLabel("文件操作")
        .disabled(model.editingText != nil || model.busy)
      }
      if let document = model.document {
        if model.editingText != nil {
          HStack {
            Text("正在编辑").font(.subheadline)
            Spacer()
            Button("退出编辑") {
              exitEditingConfirmation = true
            }
            .disabled(model.busy)
            Button("保存") {
              model.saveTextEditing()
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.busy)
          }
        } else if document.textFormat != nil {
          HStack {
            Text("只读查看").font(.subheadline).foregroundStyle(.secondary)
            Spacer()
            Button("编辑") {
              model.requestTextEditing()
            }
            .disabled(model.busy)
          }
        }
        VaultDocumentViewer(
          document: document,
          editingText: model.editingText == nil
            ? nil
            : Binding(
              get: {
                model.editingText ?? ""
              },
              set: {
                model.updateEditingText($0)
              }),
          onClose: {
            model.closeViewer()
          }
        )
        .disabled(model.busy)
        if model.busy {
          ProgressView("正在加密保存并验证…")
        }
        if let message = model.message {
          Text(message).font(.callout).foregroundStyle(.red)
        }
        Text(
          model.editingText == nil
            ? "只读查看 · 关闭或锁定后清理临时副本"
            : "仅点保存才会写入 · 退出编辑或锁定会丢弃未保存内容"
        )
        .font(.caption2).foregroundStyle(.secondary)
      } else {
        Spacer()
        Image(systemName: media.symbolName).font(.system(size: 64)).foregroundStyle(.secondary)
        Text(media.originalFilename).font(.title3).multilineTextAlignment(.center)
        if model.busy {
          ProgressView("正在解密并验证文档…")
        } else if media.isDocument {
          Button("只读查看") {
            model.openDocument(media)
          }
        } else {
          Text("此格式暂不支持预览，可按原名解密复制或导出到系统。")
            .foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        if let message = model.message {
          Text(message).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        systemSaveButtons(media)
        Spacer()
      }
    }
    .padding(12)
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("加密文件详情")
    .alert("退出编辑？", isPresented: $exitEditingConfirmation) {
      Button("继续编辑", role: .cancel) {}
      Button("丢弃修改并退出", role: .destructive) {
        model.discardTextEditing()
      }
    } message: {
      Text("本次未保存的修改将立即丢弃，文件保留上次保存的内容。")
    }
  }

  /// 业务作用：仅在相册首页提供导入、密码管理和主动锁定，浏览时不重复占用画面。
  /// 参数说明：无。
  /// 返回：一行相册工具栏，已保存的图片和视频共享同一入口。
  private var libraryToolbar: some View {
    HStack {
      if model.selecting {
        Button("取消") {
          model.endSelection()
        }
        .accessibilityLabel("取消选择")
        .disabled(model.busy)
        Spacer()
        Text("选择项目").font(.headline)
        Spacer()
        Button(model.selectedItems.count == model.visibleItems.count ? "取消全选" : "全选") {
          model.toggleSelectAll()
        }
        .disabled(model.busy || model.visibleItems.isEmpty)
      } else {
        if model.currentFolderID != nil {
          Button {
            model.leaveFolder()
          } label: {
            Image(systemName: "chevron.left").frame(width: 32, height: 44)
          }
          .accessibilityLabel("返回上级文件夹")
          .disabled(model.busy)
        }
        VStack(alignment: .leading, spacing: 0) {
          Label(model.currentFolder?.originalFilename ?? "EncVault", systemImage: "lock.shield")
            .font(.headline).lineLimit(1).truncationMode(.middle)
          if !model.visibleItems.isEmpty {
            Text("\(model.visibleItems.count) 项").font(.caption2).foregroundStyle(.secondary)
          }
        }
        Spacer()
        Button("选择") {
          model.beginSelection()
        }
        .disabled(model.busy || model.visibleItems.isEmpty)
        Button {
          folderName = ""
          creatingFolder = true
        } label: {
          Image(systemName: "folder.badge.plus").frame(width: 32, height: 44)
        }
        .accessibilityLabel("新建文件夹")
        .disabled(model.busy)
        Menu("导入") {
          Button("从本地文件导入") {
            chooseFiles(for: .media)
          }
          Button("导入整个文件夹") {
            chooseFiles(for: .importDirectory)
          }
          Button("从系统照片导入") {
            choosingPhotos = true
          }
        }.disabled(model.busy)
        Menu("设置") {
          Button("修改密码或切换手势") {
            model.closeViewer()
            changing = true
          }
          Divider()
          Toggle(
            "切换应用时自动锁定",
            isOn: Binding(
              get: {
                lockWhenInactive
              },
              set: {
                model.setAutomaticLock($0)
              }))
          #if os(macOS)
            Toggle("允许窗口截屏", isOn: $allowScreenshots)
          #endif
        }.disabled(model.busy)
      }
      Button("锁定") {
        model.lock()
      }
    }
    .frame(minHeight: 44)
    .padding(.horizontal, 12).padding(.vertical, 4)
    .fixedSize(horizontal: false, vertical: true)
    .layoutPriority(1)
  }

  /// 业务作用：在选择模式集中呈现数量、批量目标与来源保护限制。
  /// 参数说明：无。
  /// 返回：可对整批选择移动或二次确认删除，不能静默跳过受保护来源。
  private var selectionControls: some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack {
        Text("已选 \(model.selectedItems.count) 项").font(.headline)
          .accessibilityIdentifier("多选数量")
        Spacer()
        Menu {
          Button("移动到文件夹") {
            presentMove(model.selectedItems, byPath: false)
          }
          Button("移动到指定目录") {
            presentMove(model.selectedItems, byPath: true)
          }
          if model.currentFolderID != nil {
            Button("移动到上级") {
              model.moveToParent(model.selectedItems)
            }
            .disabled(!model.selectedItems.allSatisfy(model.canMoveToParent))
          }
        } label: {
          Label("移动", systemImage: "folder")
        }
        .buttonStyle(.borderedProminent)
        .accessibilityLabel("移动所选项目")
        .disabled(model.busy || !model.canMoveSelection)
        Button(role: .destructive) {
          deletingSelection = model.selectedItems
        } label: {
          Label("删除", systemImage: "trash")
        }
        .accessibilityLabel("删除所选项目")
        .disabled(model.busy || !model.canDeleteSelection)
      }
      if !model.selectedItems.isEmpty && !model.canMoveSelection {
        Text("所选项目含密码保护文件夹，请先取消保护后再移动或删除。")
          .font(.caption).foregroundStyle(.secondary)
      }
    }
    .padding(12)
  }

  /// 业务作用：以本次来源快照打开统一目标选择，避免弹窗期间的选择变化改换操作对象。
  /// 参数说明：
  /// - `media`：本次单项或批量来源。
  /// - `byPath`：是否要求用户手动输入保险箱目录。
  /// 返回：仅在空闲且没有未保存草稿时呈现目录输入或选择页。
  private func presentMove(_ media: [VaultMedia], byPath: Bool) {
    guard !media.isEmpty, !model.busy, model.closeViewer() else {
      return
    }
    pendingMove = nil
    pendingMovePath = nil
    movePath = ""
    moveByPath = byPath
    model.movingMedia = VaultModel.MoveSelection(media: media)
  }

  /// 业务作用：切换当前媒体的全屏呈现，Mac 同步系统窗口全屏状态。
  /// 参数说明：无。
  /// 返回：仅更改窗口和布局，当前媒体、图片倍率与播放位置保持不变。
  private func toggleFullScreen() {
    // 迟到的画面事件不能在锁定后重新打开媒体呈现。
    guard model.screen == .library, model.selected != nil,
      model.playback != nil || model.image != nil
    else {
      return
    }
    if fullScreen {
      leaveFullScreen()
      return
    }
    fullScreen = true
    #if os(macOS)
      if let window = NSApplication.shared.mainWindow ?? NSApplication.shared.keyWindow,
        !window.styleMask.contains(.fullScreen)
      {
        window.toggleFullScreen(nil)
      }
    #else
      if model.playback != nil {
        VaultVideoOrientation.shared.enter()
      }
    #endif
  }

  /// 业务作用：在 iPhone 视频画面中交替选择两个横屏方向，不重新打开媒体。
  /// 参数说明：无。
  /// 返回：Mac 不提供额外方向按钮；iPhone 进入视频全屏并切换左、右横屏。
  private var rotateVideo: (() -> Void)? {
    #if os(iOS)
      return {
        guard model.screen == .library, model.playback != nil else {
          return
        }
        fullScreen = true
        VaultVideoOrientation.shared.cycle()
      }
    #else
      return nil
    #endif
  }

  /// 业务作用：退出全屏或失去会话时恢复普通布局，不让锁定界面继续保留媒体全屏状态。
  /// 参数说明：无。
  /// 返回：全屏标记与系统窗口恢复普通状态，不关闭仍有效的当前媒体。
  private func leaveFullScreen() {
    guard fullScreen else {
      return
    }
    fullScreen = false
    #if os(macOS)
      if let window = NSApplication.shared.mainWindow ?? NSApplication.shared.keyWindow,
        window.styleMask.contains(.fullScreen)
      {
        window.toggleFullScreen(nil)
      }
    #else
      VaultVideoOrientation.shared.leave()
    #endif
  }

  /// 业务作用：提交本次独立凭据后立即丢弃输入文本。
  /// 参数说明：无。
  /// 返回：开始验证，不保留密码到列表和下一次进入。
  private func unlock() {
    // 绘制结束可能与窗口失去前台相邻；失权或正在验证时不能重新开启认证任务。
    guard model.screen == .locked, !model.busy, !password.isEmpty else {
      return
    }
    #if os(macOS)
      guard NSApplication.shared.isActive else {
        return
      }
    #else
      guard UIApplication.shared.applicationState == .active else {
        return
      }
    #endif
    model.unlock(VaultCredential(kind: model.kind, value: password))
    password = ""
  }

  /// 业务作用：使用唯一选择入口呈现媒体或目录，Mac 通过原生窗口挂接避免呈现器覆盖。
  /// 参数说明：
  /// - `selection`：本次需要选取来源还是系统复制、导出的目标目录。
  /// 返回：仅在当前已解锁且空闲的会话中打开选择器。
  private func chooseFiles(for selection: FileSelection) {
    // 选择器不能从已锁定或正在处理文件的界面重新开放来源读取或外部明文交付。
    guard model.screen == .library, !model.busy else {
      return
    }
    fileSelection = selection
    #if os(macOS)
      guard nativePanel == nil,
        let window = NSApplication.shared.mainWindow ?? NSApplication.shared.keyWindow
      else {
        model.message = "当前窗口无法打开文件选择器，请关闭其它弹窗后重试。"
        return
      }
      let panel = NSOpenPanel()
      panel.canChooseFiles = selection == .media
      panel.canChooseDirectories = selection != .media
      panel.canCreateDirectories = selection == .systemDirectory
      panel.allowsMultipleSelection = selection == .media
      switch selection {
      case .media:
        panel.title = "选择本地文件"
      case .importDirectory:
        panel.title = "选择要完整加密保存的文件夹"
      case .systemDirectory:
        panel.title = "选择解密\(systemSaveAction.rawValue)目录"
      }
      panel.prompt = selection == .systemDirectory ? "选择目录" : "加密导入"
      nativePanel = panel
      // 原生面板直接附着应用主窗口，来源与目标目录共用此通路，不叠加同层文件呈现器。
      panel.beginSheetModal(for: window) { response in
        nativePanel = nil
        if response == .OK {
          completeFileSelection(.success(panel.urls))
        } else {
          completeFileSelection(.failure(CocoaError(.userCancelled)))
        }
      }
    #else
      choosingFile = true
    #endif
  }

  /// 业务作用：按本次明确目的处理选择结果，取消不报错，其它失败不再静默忽略。
  /// 参数说明：
  /// - `result`：唯一系统选择器返回的媒体或目录列表。
  /// 返回：有效选择进入对应业务；失权后的回调不再读取文件。
  private func completeFileSelection(_ result: Result<[URL], Error>) {
    guard model.screen == .library else {
      return
    }
    switch result {
    case .success(let urls):
      switch fileSelection {
      case .media, .importDirectory:
        model.importFiles(urls)
      case .systemDirectory:
        if let directory = urls.first, let media = systemSaveMedia {
          switch systemSaveAction {
          case .copy:
            model.copyToSystem(media, to: directory)
          case .export:
            model.export(media, to: directory)
          }
        }
        systemSaveMedia = nil
      }
    case .failure(let error):
      let failure = error as NSError
      if failure.domain != NSCocoaErrorDomain || failure.code != NSUserCancelledError {
        model.message = "系统文件选择器未能完成操作，请重试。"
      }
      if fileSelection == .systemDirectory {
        systemSaveMedia = nil
      }
    }
  }

  /// 业务作用：提供复制、导出、移动、删除和目录保护入口，各动作维持独立的保护限制。
  /// 参数说明：
  /// - `media`：本次操作的媒体，不依赖最近文件状态。
  /// 返回：只向允许的来源开放管理动作，受保护的接收目录在移动时继续验证。
  private func mediaActions(_ media: VaultMedia) -> some View {
    VaultMediaMenu(items: mediaActionItems(media))
  }

  /// 业务作用：为手机系统长按菜单与两端其它菜单建立同一份动作，保持保护规则一致。
  /// 参数说明：
  /// - `media`：当前目录或查看页面明确选择的认证条目。
  /// 返回：按当前层级计算的管理入口；密码保护提示不包含可执行动作。
  private func mediaActionItems(_ media: VaultMedia) -> [VaultMediaMenuItem] {
    var result: [VaultMediaMenuItem] = []
    let protected = model.containsProtectedFolder(media)
    result.append(
      VaultMediaMenuItem(
        title: media.isFolder && !media.isDocument ? "重命名文件夹" : "重命名文件",
        enabled: !model.busy && model.editingText == nil,
        action: {
          renamedItemName = media.originalFilename
          renamingItem = media
        }))
    if media.isFolder && !media.isDocument {
      result.append(
        VaultMediaMenuItem(
          title: media.folderPassword == nil ? "设置文件夹访问密码" : "取消文件夹访问密码",
          action: {
            model.requestFolderPassword(media, removing: media.folderPassword != nil)
          }))
    }
    result.append(contentsOf: systemSaveItems(media))
    if model.exportRestricted(media) {
      result.append(
        VaultMediaMenuItem(title: "复制需验证文件夹密码；导出需先取消保护"))
    }
    result.append(
      VaultMediaMenuItem(
        title: "移动到文件夹", enabled: !protected,
        action: {
          presentMove([media], byPath: false)
        }))
    if media.parentID != nil {
      result.append(
        VaultMediaMenuItem(
          title: "移动到上级", enabled: model.canMoveToParent(media),
          action: {
            model.moveToParent(media)
          }))
      result.append(
        VaultMediaMenuItem(
          title: "移动到指定目录", enabled: !protected,
          action: {
            presentMove([media], byPath: true)
          }))
    }
    result.append(
      VaultMediaMenuItem(
        title: "删除加密文件", destructive: true, enabled: !protected,
        action: {
          deleting = media
        }))
    if protected {
      result.append(VaultMediaMenuItem(title: "先取消文件夹密码后再删除"))
    }
    return result
  }

  /// 业务作用：让文件详情与两端的文件操作菜单都提供独立的复制与导出入口。
  /// 参数说明：
  /// - `media`：本次明确选择的文件或完整目录。
  /// 返回：复制允许重新验证目录密码，导出保留禁止受保护内容的门禁；两者均需明确选择系统目标。
  private func systemSaveButtons(_ media: VaultMedia) -> some View {
    VaultMediaMenu(items: systemSaveItems(media))
  }

  /// 业务作用：统一系统复制与导出的确认入口，不把菜单显示当作目录密码授权。
  /// 参数说明：
  /// - `media`：待复制或导出的完整条目。
  /// 返回：复制保留独立验证、导出保持保护门禁的两个动作，执行后仍需选择目标。
  private func systemSaveItems(_ media: VaultMedia) -> [VaultMediaMenuItem] {
    SystemSaveAction.allCases.map { action in
      VaultMediaMenuItem(
        title: action.title,
        enabled: !model.busy && (action == .copy || !model.exportRestricted(media)),
        action: {
          guard model.screen == .library, !model.busy,
            action == .copy || !model.exportRestricted(media)
          else {
            return
          }
          systemSaveAction = action
          systemSaveMedia = media
          systemSaveWarning = true
        })
    }
  }

  /// 业务作用：进入非前台状态时关闭敏感弹窗并撤销媒体读取。
  /// 参数说明：无。
  /// 返回：界面不继续显示媒体、密码输入或恢复码。
  private func conceal() {
    #if os(macOS)
      nativePanel?.cancel(nil)
      nativePanel = nil
    #endif
    choosingFile = false
    changing = false
    recovering = false
    eraseConfirmation = false
    sourceConfirmation = false
    deleting = nil
    systemSaveMedia = nil
    systemSaveWarning = false
    systemSaveAction = .export
    choosingPhotos = false
    selectedPhotos = []
    creatingFolder = false
    folderName = ""
    pendingMove = nil
    pendingMovePath = nil
    movePath = ""
    password = ""
    eraseText = ""
    model.lock()
  }
}
