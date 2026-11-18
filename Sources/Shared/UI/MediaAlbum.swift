import SwiftUI
import UniformTypeIdentifiers

#if os(macOS)
  import AppKit
#else
  import UIKit
#endif

/// 相册按已认证列表顺序浏览，边界不循环，不保存最近选择。
enum MediaNavigation {
  /// 业务作用：在同一列表中定位图片或视频的相邻项目。
  /// 参数说明：
  /// - `items`：当前解锁会话的全部媒体，顺序与相册一致。
  /// - `selectedID`：当前明确选择的媒体身份。
  /// - `step`：上一项为 -1，下一项为 1。
  /// 返回：存在且未越过边界的相邻媒体；没有选择或越界时为空。
  static func adjacent(in items: [VaultMedia], selectedID: UUID?, step: Int) -> VaultMedia? {
    guard step == -1 || step == 1,
      let index = items.firstIndex(where: {
        $0.id == selectedID
      }),
      items.indices.contains(index + step)
    else {
      return nil
    }
    return items[index + step]
  }
}

/// 仅显示当前会话缓存的小图，以类型标记区分视频和文档，失败时保留类型图标。
struct VaultMediaThumbnail: View {
  let media: VaultMedia
  let image: VaultImage?

  /// 业务作用：让媒体和文档内容填满正方形卡片，保留类型区分。
  /// 参数说明：无。
  /// 返回：裁剪填充的小图或类型占位，不创建磁盘缩略图。
  var body: some View {
    GeometryReader { geometry in
      ZStack {
        if media.isFolder && !media.isFilePackage {
          folder
            .padding(geometry.size.width * 0.08)
            .opacity(media.isHidden ? 0.4 : 1)
        } else {
          Color.secondary.opacity(0.15)
          if let image {
            thumbnail(image)
              .resizable()
              .aspectRatio(contentMode: .fill)
              .frame(width: geometry.size.width, height: geometry.size.height)
              .accessibilityLabel(media.isDocument ? "文档内容预览" : "媒体内容预览")
              .accessibilityIdentifier("内容缩略图-" + media.originalFilename)
          } else {
            Image(systemName: media.symbolName)
              .font(.title2).foregroundStyle(.secondary)
          }
        }
      }
      .frame(width: geometry.size.width, height: geometry.size.height)
      .clipped()
      .overlay(alignment: .bottomTrailing) {
        if media.isVideo {
          Image(systemName: "play.fill")
            .font(.caption2).foregroundStyle(.white)
            .padding(6).background(.black.opacity(0.65), in: Circle()).padding(4)
        } else if media.isDocument {
          Text((media.originalFilename as NSString).pathExtension.uppercased())
            .font(.system(size: 9, weight: .semibold))
            .foregroundStyle(.white).padding(.horizontal, 5).padding(.vertical, 3)
            .background(.black.opacity(0.65), in: RoundedRectangle(cornerRadius: 3)).padding(4)
        } else if media.folderPassword != nil {
          Image(systemName: "lock.fill")
            .font(.caption).foregroundStyle(.white)
            .padding(6).background(.black.opacity(0.65), in: Circle()).padding(4)
        }
      }
    }
    .aspectRatio(1, contentMode: .fit)
    .privacySensitive()
  }

  /// 业务作用：用平台原生文件夹外观区分可进入目录，不读取目录外的任何文件或图标。
  /// 参数说明：无。
  /// 返回：透明背景的系统文件夹标记，隐藏文件夹由外层以半透明显示；文档包由预览入口处理。
  private var folder: some View {
    Group {
      #if os(macOS)
        Image(nsImage: NSWorkspace.shared.icon(for: .folder))
          .resizable().scaledToFit()
      #else
        Image(systemName: "folder.fill")
          .resizable().scaledToFit()
          .foregroundStyle(.blue.gradient)
      #endif
    }
    .accessibilityLabel(media.isHidden ? "隐藏文件夹" : "文件夹")
    .accessibilityIdentifier("系统文件夹-" + media.originalFilename)
  }

  /// 业务作用：把当前小图交给对应平台绘制，不加载原始媒体路径。
  /// 参数说明：
  /// - `image`：当前授权会话内存中的预览。
  /// 返回：仅用于缩略图的图片绘制对象。
  private func thumbnail(_ image: VaultImage) -> Image {
    #if os(macOS)
      Image(nsImage: image)
    #else
      Image(uiImage: image)
    #endif
  }
}

/// 两端菜单共用同一动作及禁用条件，提示项不携带可执行操作。
struct VaultMediaMenuItem {
  let title: String
  var destructive = false
  var enabled = true
  var action: (() -> Void)?
}

/// SwiftUI 菜单和文件详情复用同一份管理动作。
struct VaultMediaMenu: View {
  let items: [VaultMediaMenuItem]

  /// 业务作用：按当前动作门禁展示菜单，不把提示文字转换成可点击权限。
  /// 参数说明：无。
  /// 返回：可执行按钮或只读说明，实际写入仍由保险箱核心复验。
  var body: some View {
    ForEach(items.indices, id: \.self) { index in
      let item = items[index]
      if let action = item.action {
        Button(item.title, role: item.destructive ? .destructive : nil, action: action)
          .disabled(!item.enabled)
      } else {
        Text(item.title)
      }
    }
  }
}

/// 文件和目录共用网格首页，内容缩略图只在当前解锁会话内按可见项目生成。
struct VaultAlbumGrid: View {
  @ObservedObject var model: VaultModel
  let actions: (VaultMedia) -> [VaultMediaMenuItem]

  /// 业务作用：以缩略图网格展示文件和目录，保留原名及文件类型。
  /// 参数说明：无。
  /// 返回：可点击查看或进入目录的网格，文档与媒体使用各自的查看入口。
  var body: some View {
    ScrollView {
      LazyVGrid(columns: [GridItem(.adaptive(minimum: 110, maximum: 180), spacing: 6)], spacing: 12)
      {
        ForEach(model.visibleItems) { media in
          VaultAlbumCell(model: model, media: media, actions: actions)
            .onAppear {
              model.requestThumbnail(media)
            }
            .onChange(of: media.sha256) { _, _ in
              model.requestThumbnail(media)
            }
            .onChange(of: model.busy) { _, busy in
              if !busy {
                model.requestThumbnail(media)
              }
            }
        }
      }
      .padding(6)
    }
    .accessibilityLabel("相册缩略图列表")
  }
}

/// 内部拖放只传递本进程可读的随机令牌，系统拖放内容不包含原件或解密路径。
private let vaultInternalDragType = UTType.data

/// 网格卡片保留点击与菜单操作，手机长按菜单可连续转入单指拖动。
private struct VaultAlbumCell: View {
  @ObservedObject var model: VaultModel
  let media: VaultMedia
  let actions: (VaultMedia) -> [VaultMediaMenuItem]
  @State private var targeted = false

  /// 业务作用：为卡片提供管理菜单与受限拖动，并给有效接收目录提供松手提示。
  /// 参数说明：无。
  /// 返回：含密码保护的目录树不能拖走；松手后仅验证移出的来源保护范围及尚未授权的目标目录。
  var body: some View {
    Group {
      #if os(iOS)
        IOSVaultDragCell(
          model: model, media: media, targeted: $targeted, content: card,
          menuItems: {
            actions(media)
          })
      #else
        if model.canDrag(media) {
          card.onDrag {
            let provider = NSItemProvider()
            if let data = model.beginDragging(media) {
              provider.registerDataRepresentation(
                forTypeIdentifier: vaultInternalDragType.identifier, visibility: .ownProcess
              ) { completion in
                completion(data, nil)
                return nil
              }
            }
            return provider
          } preview: {
            Label("保险箱内移动", systemImage: "lock.doc")
              .padding(12).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
          }
        } else {
          card
        }
      #endif
    }
    #if os(macOS)
      .contextMenu {
        if !model.selecting {
          VaultMediaMenu(items: actions(media))
        }
      }
    #endif
    .overlay {
      if targeted && model.canDrop(into: media) {
        RoundedRectangle(cornerRadius: 8)
          .fill(Color.accentColor.opacity(0.14))
          .overlay {
            RoundedRectangle(cornerRadius: 8).stroke(Color.accentColor, lineWidth: 3)
          }
          .overlay(alignment: .bottom) {
            Text(media.folderPassword == nil ? "松开移入" : "松开后验证密码")
              .font(.caption.weight(.semibold)).foregroundStyle(.white)
              .padding(6).background(Color.accentColor, in: Capsule()).padding(6)
          }
          .allowsHitTesting(false)
      }
    }
    .overlay(alignment: .topTrailing) {
      if model.selecting {
        Image(systemName: model.selectedIDs.contains(media.id) ? "checkmark.circle.fill" : "circle")
          .font(.title2).foregroundStyle(
            model.selectedIDs.contains(media.id) ? Color.accentColor : Color.secondary
          )
          .padding(4).background(.regularMaterial, in: Circle()).padding(6)
          .allowsHitTesting(false)
      }
    }
    .overlay {
      if model.selecting && model.selectedIDs.contains(media.id) {
        RoundedRectangle(cornerRadius: 8).stroke(Color.accentColor, lineWidth: 2)
          .allowsHitTesting(false)
      }
    }
    #if os(macOS)
      .onDrop(
        of: [vaultInternalDragType],
        delegate: VaultFolderDropDelegate(model: model, folder: media, targeted: $targeted))
    #endif
  }

  /// 业务作用：为拖动与普通点击共用原名卡片，不因附加拖放而改变查看入口。
  /// 参数说明：无。
  /// 返回：当前会话内的缩略图、名称与点击查看入口，管理菜单由卡片外层提供。
  private var card: some View {
    Button {
      model.open(media)
    } label: {
      VStack(alignment: .leading, spacing: 4) {
        VaultMediaThumbnail(media: media, image: model.thumbnails[media.id])
          .clipShape(RoundedRectangle(cornerRadius: 6))
        Text(media.originalFilename)
          .font(.caption).lineLimit(1).truncationMode(.middle)
          .foregroundStyle(.primary)
      }
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain).disabled(model.busy)
    .accessibilityLabel(media.originalFilename)
    .accessibilityValue(
      model.selecting
        ? "\(media.kindTitle)，\(model.selectedIDs.contains(media.id) ? "已选择" : "未选择")"
        : media.kindTitle)
  }
}

/// 目标验证与移动只在释放后执行，悬停不打开目录或调用密码派生。
@MainActor
private struct VaultFolderDropDelegate: DropDelegate {
  let model: VaultModel
  let folder: VaultMedia
  @Binding var targeted: Bool

  /// 业务作用：让普通目录接收本类拖放会话，具体来源与层级由悬停和释放阶段复验。
  /// 参数说明：
  /// - `info`：本次系统拖放携带的类型信息。
  /// 返回：当前解锁且空闲的普通目录可继续协商，不授予移动或密码权限。
  func validateDrop(info: DropInfo) -> Bool {
    // 系统可能先协商目标再调用来源提供者，不能把尚未建立的令牌当作永久拒绝依据。
    info.hasItemsConforming(to: [vaultInternalDragType]) && model.screen == .library && !model.busy
      && folder.isFolder && !folder.isFilePackage
  }

  /// 业务作用：进入有效目录时展示松手提示，不开始移动。
  /// 参数说明：
  /// - `info`：进入卡片的系统拖放信息。
  /// 返回：只更新当前卡片的内存高亮。
  func dropEntered(info: DropInfo) {
    targeted = validateDrop(info: info) && model.canDrop(into: folder)
  }

  /// 业务作用：离开卡片时清除目标高亮，允许拖动继续选择其它目录。
  /// 参数说明：
  /// - `info`：离开卡片的系统拖放信息。
  /// 返回：不改变来源、密码或移动权限。
  func dropExited(info: DropInfo) {
    targeted = false
  }

  /// 业务作用：向系统声明本次为保险箱内部移动，避免出现复制到外部的指示。
  /// 参数说明：
  /// - `info`：当前悬停的系统拖放信息。
  /// 返回：有效目标显示移动；失权或无效目标显示禁止。
  func dropUpdated(info: DropInfo) -> DropProposal? {
    let accepted = validateDrop(info: info) && model.canDrop(into: folder)
    targeted = accepted
    return DropProposal(operation: accepted ? .move : .forbidden)
  }

  /// 业务作用：释放后接收唯一的内部随机令牌，再由模型复验当前会话并开启移动。
  /// 参数说明：
  /// - `info`：释放时的系统拖放提供者。
  /// 返回：已接收有效的单项内部拖放；密码取消或失败时仍不会移动来源。
  func performDrop(info: DropInfo) -> Bool {
    targeted = false
    guard validateDrop(info: info), model.canDrop(into: folder) else {
      return false
    }
    let providers = info.itemProviders(for: [vaultInternalDragType])
    guard providers.count == 1, let provider = providers.first else {
      return false
    }
    let model = model
    let folderID = folder.id
    provider.loadDataRepresentation(forTypeIdentifier: vaultInternalDragType.identifier) {
      data, _ in
      guard let data, data.count == 36 else {
        return
      }
      Task { @MainActor in
        model.completeDrop(data, into: folderID)
      }
    }
    return true
  }
}

#if os(iOS)
  /// 手机内部拖放用本地对象交接令牌，禁止跨应用拖出，避免系统表示转换影响松手交付。
  private struct IOSVaultDragCell<Content: View>: UIViewRepresentable {
    let model: VaultModel
    let media: VaultMedia
    @Binding var targeted: Bool
    let content: Content
    let menuItems: () -> [VaultMediaMenuItem]

    /// 业务作用：将卡片的本地拖放和长按菜单交给同一协调者管理。
    /// 参数说明：无。
    /// 返回：只持有当前卡片及内存令牌的协调者。
    func makeCoordinator() -> Coordinator {
      Coordinator(model: model, media: media, targeted: $targeted, menuItems: menuItems)
    }

    /// 业务作用：让系统长按菜单、单指拖放与卡片点击共存，允许菜单连续过渡到拖动。
    /// 参数说明：
    /// - `context`：当前卡片的协调者。
    /// 返回：承载原有 SwiftUI 内容的透明视图，不提供文件 URL。
    func makeUIView(context: Context) -> UIView {
      let host = UIHostingController(rootView: content)
      host.view.backgroundColor = .clear
      context.coordinator.host = host
      let drag = UIDragInteraction(delegate: context.coordinator)
      drag.isEnabled = model.canDrag(media)
      host.view.addInteraction(drag)
      host.view.addInteraction(UIDropInteraction(delegate: context.coordinator))
      // 两种系统交互挂在同一卡片上，长按菜单与拖动由 UIKit 协调，不能各自抢占手势。
      host.view.addInteraction(UIContextMenuInteraction(delegate: context.coordinator))
      return host.view
    }

    /// 业务作用：随会话和条目变化更新内容与交互门禁，失权时关闭菜单且不恢复旧令牌。
    /// 参数说明：
    /// - `view`：当前卡片视图。
    /// - `context`：当前拖放协调者。
    /// 返回：来源失权或正在处理时停止新拖动，目标验证仍在释放时执行。
    func updateUIView(_ view: UIView, context: Context) {
      context.coordinator.media = media
      context.coordinator.menuItems = menuItems
      context.coordinator.host?.rootView = content
      for interaction in view.interactions {
        if let drag = interaction as? UIDragInteraction {
          drag.isEnabled = model.canDrag(media)
        } else if let menu = interaction as? UIContextMenuInteraction,
          model.screen != .library || model.busy || model.selecting
        {
          // 失权或进入选择模式后立即撤下菜单，旧菜单不能继续交付原名或管理入口。
          menu.dismissMenu()
        }
      }
    }

    /// 业务作用：按网格实际宽度计算卡片高度，窗口与文字尺寸变化时同步排版。
    /// 参数说明：
    /// - `proposal`：网格分配的可用尺寸。
    /// - `view`：当前原生卡片。
    /// - `context`：持有内容控制器的协调者。
    /// 返回：内容在当前宽度下的自适应尺寸，不固定屏幕或卡片宽高。
    func sizeThatFits(_ proposal: ProposedViewSize, uiView view: UIView, context: Context)
      -> CGSize?
    {
      guard let width = proposal.width else {
        return nil
      }
      return context.coordinator.host?.sizeThatFits(
        in: CGSize(width: width, height: .greatestFiniteMagnitude))
    }

    /// 业务作用：卡片移出视图树时撤销菜单与拖动回调，不保留已离开目录的管理动作。
    /// 参数说明：
    /// - `view`：已结束使用的原生卡片。
    /// - `coordinator`：当前卡片的交互协调者。
    /// 返回：系统菜单关闭，未消费令牌撤销，原名卡片和动作闭包释放。
    static func dismantleUIView(_ view: UIView, coordinator: Coordinator) {
      for interaction in view.interactions {
        if let menu = interaction as? UIContextMenuInteraction {
          menu.dismissMenu()
        }
        view.removeInteraction(interaction)
      }
      coordinator.cancelToken()
      coordinator.host = nil
      coordinator.menuItems = {
        []
      }
    }

    @MainActor
    final class Coordinator: NSObject, UIDragInteractionDelegate, UIDropInteractionDelegate,
      UIContextMenuInteractionDelegate
    {
      let model: VaultModel
      var media: VaultMedia
      let targeted: Binding<Bool>
      var host: UIHostingController<Content>?
      var menuItems: () -> [VaultMediaMenuItem]
      private var token: Data?

      /// 业务作用：绑定当前卡片，不保存拖放路径、名称历史或密码。
      /// 参数说明：
      /// - `model`：当前解锁会话。
      /// - `media`：卡片对应的认证条目。
      /// - `targeted`：本次悬停高亮。
      /// - `menuItems`：按最新会话计算的菜单动作与门禁。
      /// 返回：等待原生交互事件的协调者。
      init(
        model: VaultModel, media: VaultMedia, targeted: Binding<Bool>,
        menuItems: @escaping () -> [VaultMediaMenuItem]
      ) {
        self.model = model
        self.media = media
        self.targeted = targeted
        self.menuItems = menuItems
      }

      /// 业务作用：只为当前目录内仍可见且已解锁的卡片提供长按菜单。
      /// 参数说明：
      /// - `interaction`：与本地拖动共用卡片的系统菜单交互。
      /// - `location`：本次长按位置，不保存到历史。
      /// 返回：当前动作菜单；失权、繁忙或多选模式下拒绝呈现。
      func contextMenuInteraction(
        _ interaction: UIContextMenuInteraction, configurationForMenuAtLocation location: CGPoint
      ) -> UIContextMenuConfiguration? {
        guard menuAllowed else {
          return nil
        }
        return UIContextMenuConfiguration(
          identifier: media.id.uuidString as NSString, previewProvider: nil
        ) { [weak self] _ in
          guard let self, self.menuAllowed else {
            return nil
          }
          return UIMenu(
            children: self.menuItems().map { item in
              var attributes: UIMenuElement.Attributes = []
              if item.destructive {
                attributes.insert(.destructive)
              }
              if !item.enabled || item.action == nil {
                attributes.insert(.disabled)
              }
              return UIAction(title: item.title, attributes: attributes) { [weak self] _ in
                // 系统菜单可跨多帧存在，执行时重验会话与目录，不能使用锁定前的旧动作。
                guard let self, self.menuAllowed, item.enabled else {
                  return
                }
                item.action?()
              }
            })
        }
      }

      /// 业务作用：限制长按与菜单执行只能作用于当前浏览路径，不从旧卡片恢复访问。
      /// 参数说明：无。
      /// 返回：当前已解锁、空闲、非选择模式且条目仍在此目录时为真。
      private var menuAllowed: Bool {
        model.screen == .library && !model.busy && !model.selecting
          && model.currentFolderID == media.parentID && model.visibleItems.contains(media)
      }

      /// 业务作用：让取消拖动与拆除卡片共用同一令牌撤销入口。
      /// 参数说明：无。
      /// 返回：未消费的本次令牌失效，不影响其它新建拖动会话。
      func cancelToken() {
        if let token {
          model.cancelDragging(token)
        }
        token = nil
      }

      /// 业务作用：启动单项内部拖动，只把随机令牌附在本地拖动对象上。
      /// 参数说明：
      /// - `interaction`：当前卡片的拖动交互。
      /// - `session`：系统发起的单指拖动会话。
      /// 返回：允许移动时交付一个本地对象；含密码保护的目录树或失权时为空。
      func dragInteraction(
        _ interaction: UIDragInteraction, itemsForBeginning session: any UIDragSession
      ) -> [UIDragItem] {
        guard let data = model.beginDragging(media) else {
          return []
        }
        token = data
        let provider = NSItemProvider()
        provider.registerDataRepresentation(
          forTypeIdentifier: vaultInternalDragType.identifier, visibility: .ownProcess
        ) { completion in
          completion(data, nil)
          return nil
        }
        let item = UIDragItem(itemProvider: provider)
        item.localObject = data
        item.previewProvider = {
          let label = UILabel(frame: CGRect(x: 0, y: 0, width: 180, height: 44))
          label.text = "保险箱内移动"
          label.textAlignment = .center
          label.backgroundColor = .secondarySystemBackground
          return UIDragPreview(view: label)
        }
        return [item]
      }

      /// 业务作用：把手机拖动限制在当前应用，不能拖出解密内容或令牌给其它应用。
      /// 参数说明：
      /// - `interaction`：当前来源交互。
      /// - `session`：当前拖动会话。
      /// 返回：始终限制在本应用。
      func dragInteraction(
        _ interaction: UIDragInteraction,
        sessionIsRestrictedToDraggingApplication session: any UIDragSession
      ) -> Bool {
        true
      }

      /// 业务作用：允许系统为本次内部整理显示移动指示。
      /// 参数说明：
      /// - `interaction`：当前来源交互。
      /// - `session`：当前拖动会话。
      /// 返回：支持内部移动，目标仍独立检查层级与密码。
      func dragInteraction(
        _ interaction: UIDragInteraction, sessionAllowsMoveOperation session: any UIDragSession
      ) -> Bool {
        true
      }

      /// 业务作用：拖动结束立即撤销未消费的令牌，不让取消拖动留下可用回调。
      /// 参数说明：
      /// - `interaction`：结束的来源交互。
      /// - `session`：结束的拖动会话。
      /// - `operation`：系统报告的最终操作。
      /// 返回：已完成移动不受影响，取消或失败的旧令牌失效。
      func dragInteraction(
        _ interaction: UIDragInteraction, session: any UIDragSession,
        didEndWith operation: UIDropOperation
      ) {
        cancelToken()
      }

      /// 业务作用：只让普通目录接收本应用单项拖动对象，外部文件与文本均不接入。
      /// 参数说明：
      /// - `interaction`：当前目标交互。
      /// - `session`：进入卡片的拖放会话。
      /// 返回：本地令牌类型与目标目录都有效时继续协商，不提前开放密码目录。
      func dropInteraction(_ interaction: UIDropInteraction, canHandle session: any UIDropSession)
        -> Bool
      {
        session.localDragSession != nil && session.items.count == 1
          && session.items.first?.localObject is Data && media.isFolder && !media.isFilePackage
          && model.screen == .library && !model.busy
      }

      /// 业务作用：跟随手指更新有效目标高亮，并拒绝自身、重名与违反目录保护范围的目标。
      /// 参数说明：
      /// - `interaction`：当前目标交互。
      /// - `session`：本次内部拖放。
      /// 返回：有效目标显示移动，其它目标显示禁止。
      func dropInteraction(
        _ interaction: UIDropInteraction, sessionDidUpdate session: any UIDropSession
      ) -> UIDropProposal {
        let accepted =
          dropInteraction(interaction, canHandle: session) && model.canDrop(into: media)
        targeted.wrappedValue = accepted
        return UIDropProposal(operation: accepted ? .move : .forbidden)
      }

      /// 业务作用：离开目标时清除高亮，不触发访问或密码验证。
      /// 参数说明：
      /// - `interaction`：离开的目标交互。
      /// - `session`：尚未释放的拖放会话。
      /// 返回：来源及其保护保持不变。
      func dropInteraction(
        _ interaction: UIDropInteraction, sessionDidExit session: any UIDropSession
      ) {
        targeted.wrappedValue = false
      }

      /// 业务作用：松手后同步消费本地令牌，再由统一移动入口验证来源与目标密码。
      /// 参数说明：
      /// - `interaction`：明确接收本次释放的目标。
      /// - `session`：仅含本应用随机令牌的拖放会话。
      /// 返回：有效释放开始验证或移动；取消密码或验证失败时来源不变。
      func dropInteraction(_ interaction: UIDropInteraction, performDrop session: any UIDropSession)
      {
        targeted.wrappedValue = false
        guard dropInteraction(interaction, canHandle: session), model.canDrop(into: media),
          let data = session.items.first?.localObject as? Data
        else {
          return
        }
        model.completeDrop(data, into: media.id)
      }

      /// 业务作用：系统结束目标会话后移除悬停样式，不保存访问顺序。
      /// 参数说明：
      /// - `interaction`：已结束的目标交互。
      /// - `session`：已完成或取消的系统会话。
      /// 返回：当前卡片恢复普通状态。
      func dropInteraction(
        _ interaction: UIDropInteraction, sessionDidEnd session: any UIDropSession
      ) {
        targeted.wrappedValue = false
      }
    }
  }
#endif

/// 当前查看的底部缩略图栏，图片和视频保持与首页一致的顺序。
struct VaultAlbumStrip: View {
  @ObservedObject var model: VaultModel

  /// 业务作用：让用户直接切换任意图片或视频，并把当前项保持在缩略图栏可见范围内。
  /// 参数说明：无。
  /// 返回：横向滚动的统一媒体栏，选择状态只保存在当前会话。
  var body: some View {
    ScrollViewReader { proxy in
      ScrollView(.horizontal) {
        LazyHStack(spacing: 6) {
          ForEach(model.browsingItems) { media in
            Button {
              model.open(media, autoplay: media.isVideo)
            } label: {
              VStack(spacing: 3) {
                VaultMediaThumbnail(media: media, image: model.thumbnails[media.id])
                  .frame(width: 60, height: 60)
                  .clipShape(RoundedRectangle(cornerRadius: 5))
                  .overlay {
                    RoundedRectangle(cornerRadius: 5)
                      .stroke(
                        media.id == model.selected?.id ? Color.accentColor : .clear, lineWidth: 3)
                  }
                Text(media.originalFilename).font(.caption2).lineLimit(1).truncationMode(.middle)
              }
              .frame(width: 68)
              .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(model.busy || media.id == model.selected?.id)
            .accessibilityLabel(media.originalFilename)
            .accessibilityValue(
              media.id == model.selected?.id ? "当前媒体" : media.kindTitle
            )
            .id(media.id)
            .onAppear {
              model.requestThumbnail(media)
            }
          }
        }
        .padding(.horizontal, 4).padding(.vertical, 3)
      }
      .scrollIndicators(.hidden)
      .onChange(of: model.selected?.id, initial: true) { _, id in
        if let id {
          proxy.scrollTo(id, anchor: .center)
        }
      }
    }
    .frame(height: 84)
    .accessibilityLabel("全部媒体缩略图")
  }
}

/// 全尺寸相册浏览器，工具栏覆盖画面，避免为标题、操作和列表重复预留高度。
struct VaultMediaBrowser<Actions: View>: View {
  @ObservedObject var model: VaultModel
  let fullScreen: Bool
  let toggleFullScreen: () -> Void
  var rotateVideo: (() -> Void)? = nil
  @ViewBuilder let actions: () -> Actions
  @State private var chromeVisible = true
  @State private var stripVisible = true
  @State private var imageViewport = ImageViewport()
  @State private var footerHeight: CGFloat = 0
  @State private var videoScrubPosition: Double?

  /// 业务作用：在同一查看区连续浏览图片与视频，使用浮动操作和可隐藏缩略图栏。
  /// 参数说明：无。
  /// 返回：保持原名、可左右切换的完整画面；不保存浏览顺序或播放进度。
  var body: some View {
    GeometryReader { geometry in
      ZStack {
        Color.black
        mediaSurface
          .frame(maxWidth: .infinity, maxHeight: .infinity)
          #if os(iOS)
            .ignoresSafeArea(fullScreen && model.playback != nil ? .all : [], edges: .all)
          #endif
          #if os(macOS)
            .overlay {
              MacMediaTrackpad(
                enabled: model.screen == .library && !model.busy,
                zoomed: model.image != nil && imageViewport.scale > 1,
                topInset: chromeVisible ? 48 : 0,
                bottomInset: chromeVisible ? footerHeight : 0,
                contentID: model.selected?.id,
                navigate: navigate,
                pan: { delta in
                  guard let image = model.image else {
                    return
                  }
                  imageViewport.move(
                    to: CGSize(
                      width: imageViewport.offset.width + delta.width,
                      height: imageViewport.offset.height + delta.height),
                    imageSize: image.size,
                    viewportSize: geometry.size)
                })
            }
          #else
            .overlay {
              IOSMediaScroll(
                enabled: model.screen == .library && !model.busy,
                zoomed: model.image != nil && imageViewport.scale > 1,
                topInset: chromeVisible ? 48 : 0,
                bottomInset: chromeVisible ? footerHeight : 0,
                contentID: model.selected?.id,
                navigate: navigate,
                pan: { delta in
                  guard let image = model.image else {
                    return
                  }
                  imageViewport.move(
                    to: CGSize(
                      width: imageViewport.offset.width + delta.width,
                      height: imageViewport.offset.height + delta.height),
                    imageSize: image.size,
                    viewportSize: geometry.size)
                })
            }
          #endif
        if model.busy {
          ProgressView().tint(.white).padding(16).background(.ultraThinMaterial, in: Circle())
        }
        if chromeVisible {
          VStack(spacing: 0) {
            header
              .padding(.horizontal, 8)
              .background(
                .linearGradient(
                  colors: [.black.opacity(0.8), .clear], startPoint: .top, endPoint: .bottom))
            Spacer(minLength: 0)
            footer(in: geometry.size)
              .padding(.horizontal, 12).padding(.bottom, 4)
              #if os(macOS)
                .background {
                  GeometryReader { footer in
                    Color.clear.preference(
                      key: MacMediaFooterHeight.self, value: footer.size.height)
                  }
                }
                .onPreferenceChange(MacMediaFooterHeight.self) { height in
                  footerHeight = height
                }
              #else
                .background {
                  GeometryReader { footer in
                    Color.clear.preference(
                      key: IOSMediaFooterHeight.self, value: footer.size.height)
                  }
                }
                .onPreferenceChange(IOSMediaFooterHeight.self) { height in
                  footerHeight = height
                }
              #endif
              .background(
                .linearGradient(
                  colors: [.clear, .black.opacity(0.9)], startPoint: .top, endPoint: .bottom))
          }
          #if os(iOS)
            .overlay(alignment: .bottomTrailing) {
              if let playback = model.playback {
                VaultPlayerActions(
                  playback: playback, fullScreen: fullScreen,
                  toggleFullScreen: toggleFullScreen, rotateVideo: rotateVideo
                )
                .padding(.trailing, 12)
                .padding(.bottom, footerHeight + 8)
              }
            }
          #endif
        }
      }
      .frame(width: geometry.size.width, height: geometry.size.height)
    }
    .background {
      Color.black.ignoresSafeArea()
    }
    .preferredColorScheme(.dark)
    #if os(iOS)
      .statusBarHidden(true)
    #else
      .onExitCommand {
        if fullScreen {
          toggleFullScreen()
        } else {
          model.closeViewer()
        }
      }
    #endif
    .onChange(of: model.selected?.id) { _, _ in
      imageViewport = ImageViewport()
      videoScrubPosition = nil
    }
    .onChange(of: model.screen) { _, value in
      if value != .library {
        videoScrubPosition = nil
      }
    }
    .onChange(of: model.busy) { _, value in
      if value {
        videoScrubPosition = nil
      }
    }
    .onChange(of: fullScreen) { _, value in
      chromeVisible = !value
      videoScrubPosition = nil
    }
    .onDisappear {
      videoScrubPosition = nil
    }
    .privacySensitive()
  }

  /// 业务作用：保持当前媒体占满查看区，两端视频横向拖动定位，图片横向拖动切换媒体。
  /// 参数说明：无。
  /// 返回：当前媒体、短暂预览或失败提示，工具栏手势不触发画面操作。
  private var mediaSurface: some View {
    Group {
      if let media = model.selected {
        if media.isVideo, let playback = model.playback {
          PlayerSurface(
            playback: playback,
            scrubbingEnabled: model.screen == .library && !model.busy,
            onScrub: { position in
              guard model.playback === playback, model.screen == .library, !model.busy else {
                videoScrubPosition = nil
                return
              }
              videoScrubPosition = position
              if position != nil {
                chromeVisible = true
              }
            }
          )
          .contentShape(Rectangle())
          .simultaneousGesture(
            SpatialTapGesture(count: 2).exclusively(before: SpatialTapGesture()).onEnded {
              value in
              switch value {
              case .first:
                toggleFullScreen()
              case .second:
                chromeVisible.toggle()
              }
            }
          )
          .accessibilityLabel("视频预览")
          #if os(iOS)
            .accessibilityHint("单指左滑后退，右滑前进")
          #else
            .accessibilityHint("按住鼠标左键向左拖动后退，向右拖动前进")
          #endif
        } else if !media.isVideo, let image = model.image {
          VaultImageViewer(
            image: image, viewport: $imageViewport, showsControls: false,
            onNavigate: navigate,
            onToggleChrome: {
              chromeVisible.toggle()
            }
          ).id(media.id)
        } else if !media.isImage && !media.isVideo {
          VStack(spacing: 16) {
            Image(systemName: media.symbolName).font(.system(size: 64))
            Text(media.originalFilename).font(.headline).multilineTextAlignment(.center)
            Text("文件已加密保存，可通过右上角菜单按原名解密导出。")
              .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
          }
          .padding(24)
        } else if let preview = model.thumbnails[media.id] {
          previewImage(preview).resizable().scaledToFit()
        } else if !model.busy {
          Text("无法显示此媒体，请返回相册选择其它文件。")
            .foregroundStyle(.secondary).padding(24)
        }
      }
    }
  }

  /// 业务作用：在一行内提供返回、原名、媒体位置和相邻切换，文件操作收进菜单。
  /// 参数说明：无。
  /// 返回：不再额外占用多行标题和文件操作的浮动工具栏。
  private var header: some View {
    HStack(spacing: 4) {
      Button {
        model.closeViewer()
      } label: {
        Image(systemName: "chevron.left").frame(width: 44, height: 44)
      }
      .accessibilityLabel("关闭查看").help("返回相册")
      VStack(alignment: .leading, spacing: 1) {
        Text(model.selected?.originalFilename ?? "").font(.subheadline.weight(.semibold))
          .lineLimit(1).truncationMode(.middle)
        Text(position).font(.caption2).foregroundStyle(.secondary)
          .accessibilityLabel("媒体位置 " + position)
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      directionButton(-1)
      directionButton(1)
      Menu {
        actions()
        Divider()
        Button(stripVisible ? "隐藏缩略图" : "显示缩略图") {
          stripVisible.toggle()
        }
        Button("锁定") {
          model.lock()
        }
      } label: {
        Image(systemName: "ellipsis.circle").frame(width: 44, height: 44)
      }
      .accessibilityLabel("文件操作")
    }
    .buttonStyle(.borderless)
    .foregroundStyle(.white)
    .frame(height: 48)
  }

  /// 业务作用：按当前列表计算媒体位置，不创建观看计数或历史记录。
  /// 参数说明：无。
  /// 返回：当前项下标与全部媒体数量。
  private var position: String {
    let index =
      model.browsingItems.firstIndex {
        $0.id == model.selected?.id
      } ?? 0
    return "\(index + 1) / \(model.browsingItems.count)"
  }

  /// 业务作用：提供鼠标与键盘可用的上一项、下一项入口，边界禁用。
  /// 参数说明：
  /// - `step`：上一项 -1 或下一项 1。
  /// 返回：不越过相册边界的导航按钮。
  private func directionButton(_ step: Int) -> some View {
    Button {
      navigate(step)
    } label: {
      Image(systemName: step < 0 ? "chevron.left.circle" : "chevron.right.circle")
        .frame(width: 44, height: 44)
    }
    .accessibilityLabel(step < 0 ? "上一项" : "下一项")
    .disabled(
      model.busy
        || MediaNavigation.adjacent(
          in: model.browsingItems, selectedID: model.selected?.id, step: step)
          == nil
    )
    .keyboardShortcut(step < 0 ? .leftArrow : .rightArrow, modifiers: [])
  }

  /// 业务作用：把缩放或播放控制与统一媒体缩略图栏叠加在画面下方。
  /// 参数说明：
  /// - `size`：完整查看区尺寸，用于图片居中缩放。
  /// 返回：触摸范围完整、可收起且不压缩画面尺寸的底部工具。
  private func footer(in size: CGSize) -> some View {
    VStack(spacing: 6) {
      if let playback = model.playback {
        VaultPlayerControls(
          playback: playback, fullScreen: fullScreen, toggleFullScreen: toggleFullScreen,
          rotateVideo: rotateVideo, previewPosition: videoScrubPosition)
      } else if let image = model.image {
        HStack(spacing: 4) {
          VaultImageControls(viewport: $imageViewport, imageSize: image.size, viewportSize: size)
          Button(action: toggleFullScreen) {
            Image(
              systemName: fullScreen
                ? "arrow.down.right.and.arrow.up.left" : "arrow.up.left.and.arrow.down.right"
            )
            .frame(width: 44, height: 44)
          }
          .accessibilityLabel(fullScreen ? "退出全屏" : "全屏")
          .buttonStyle(.borderless)
        }
      }
      if stripVisible {
        VaultAlbumStrip(model: model)
      }
      if let message = model.message {
        Text(message).font(.caption).foregroundStyle(.secondary).lineLimit(2)
      }
    }
  }

  /// 业务作用：响应明确的相册切换，关闭旧媒体，只解密新选择的完整内容。
  /// 参数说明：
  /// - `step`：上一项 -1 或下一项 1。
  /// 返回：合法相邻项目打开；视频切换后播放，图片缩放回到适合窗口。
  private func navigate(_ step: Int) {
    guard !model.busy,
      let media = MediaNavigation.adjacent(
        in: model.browsingItems, selectedID: model.selected?.id, step: step)
    else {
      return
    }
    imageViewport = ImageViewport()
    model.open(media, autoplay: media.isVideo)
  }

  /// 业务作用：在完整媒体准备期间显示当前会话已有的小图，不交付磁盘明文。
  /// 参数说明：
  /// - `image`：当前会话的缩略图。
  /// 返回：当前平台的临时图片绘制对象。
  private func previewImage(_ image: VaultImage) -> Image {
    #if os(macOS)
      Image(nsImage: image)
    #else
      Image(uiImage: image)
    #endif
  }
}
