@preconcurrency import AVFoundation
import Combine
import Foundation
@preconcurrency import VLCKit

/// 本地兼容解码共享静态策略，不发布媒体地址、自动搜索外部字幕或写入查看偏好。
@MainActor
enum LocalMediaCodecs {
  static let library: VLCLibrary = {
    let options = [
      "--quiet", "--verbose=-1", "--no-osd", "--no-video-title-show", "--no-snapshot-preview",
      "--no-metadata-network-access", "--no-sub-autodetect-file", "--no-auto-preparse",
      "--extraintf=",
    ]
    // 上游 Mac 默认值会写入偏好并开启详细日志；注册静态默认值避免观看触发这些副作用。
    UserDefaults.standard.register(defaults: ["VLCParams": options])
    let library = VLCLibrary(options: options)
    library.loggers = nil
    return library
  }()

  /// 业务作用：统一建立有准确长度、独立打开和可撤销能力的本地媒体输入。
  /// 参数说明：
  /// - `reader`：当前会话的认证读取器，不包含外部资源授权。
  /// 返回：只从当前密文取数的媒体；结构不安全或无法建立回调时拒绝。
  static func streamMedia(_ reader: VaultMediaReader) throws -> VLCMedia {
    try authorize(reader)
    _ = library
    let factory: @Sendable () -> InputStream? = {
      VaultInputStream(reader: reader)
    }
    guard let media = VaultCreateStreamMedia(reader.media.byteCount, factory) else {
      throw VaultError.unsupportedMedia
    }
    media.addOption(":no-metadata-network-access")
    media.addOption(":no-sub-autodetect-file")
    if reader.media.isImage {
      media.addOption(":codec=avcodec")
    }
    return media
  }

  /// 业务作用：兼容解码前拒绝外部引用电影，保持系统播放器禁止外部资源的边界。
  /// 参数说明：
  /// - `reader`：本次需要兼容解码的认证文件。
  /// 返回：普通图片和本地容器直接通过；MP4、MOV 仅在所有数据引用均指向自身时通过。
  static func authorize(_ reader: VaultMediaReader) throws {
    try reader.checkAccess()
    guard reader.media.isImage || reader.media.isVideo else {
      throw VaultError.unsupportedMedia
    }
    // ISO 图片容器的外部项目引用不交给兼容解码器；系统不能直接交付时保留文件供原样导出。
    guard !["public.heic", "public.heif", "public.avif"].contains(reader.media.contentType) else {
      throw VaultError.unsupportedMedia
    }
    guard
      reader.media.contentType == "public.mpeg-4"
        || reader.media.contentType == "com.apple.quicktime-movie"
    else {
      return
    }
    var offset: UInt64 = 0
    var roots = 0
    var metadataBytes = 0
    var references = 0
    while offset < reader.media.byteCount {
      roots += 1
      guard roots <= 2048 else {
        throw VaultError.unsupportedMedia
      }
      let header = try reader.read(offset: offset, count: 16)
      let box = try movieBox(
        header, start: 0, end: header.count, available: reader.media.byteCount - offset)
      if ["rmra", "rmda", "rdrf"].contains(box.kind) {
        throw VaultError.unsupportedMedia
      }
      if box.kind == "moov" {
        let amount = Int(box.size - UInt64(box.header))
        metadataBytes += amount
        guard metadataBytes <= 16 * 1024 * 1024 else {
          throw VaultError.unsupportedMedia
        }
        var bytes = Data()
        while bytes.count < amount {
          bytes.append(
            try reader.read(
              offset: offset + UInt64(box.header + bytes.count),
              count: min(VaultMediaReader.chunkSize, amount - bytes.count)))
        }
        references += try movieReferences(bytes, start: 0, end: bytes.count, depth: 0)
      }
      offset += box.size
    }
    // 没有可验证的数据引用也不能交给另一解码器猜测，避免绕过系统拒绝的引用电影。
    guard references > 0 else {
      throw VaultError.unsupportedMedia
    }
    try reader.checkAccess()
  }

  /// 业务作用：有界解析电影原子头，拒绝越界长度与不完整扩展长度。
  /// 参数说明：
  /// - `bytes`：当前已读取的电影头或元数据。
  /// - `start`：当前原子在缓冲区内的起点。
  /// - `end`：缓冲区允许读取的末尾。
  /// - `available`：原子在所属容器内最多可占用的字节数。
  /// 返回：验证后的类型、总长度及头长；异常结构拒绝兼容解码。
  private static func movieBox(
    _ bytes: Data, start: Int, end: Int, available: UInt64
  ) throws -> (kind: String, size: UInt64, header: Int) {
    guard start >= 0, end - start >= 8, end <= bytes.count,
      let kind = String(data: bytes[(start + 4)..<(start + 8)], encoding: .isoLatin1)
    else {
      throw VaultError.unsupportedMedia
    }
    var size = bytes[start..<(start + 4)].reduce(UInt64(0)) {
      ($0 << 8) | UInt64($1)
    }
    let header = size == 1 ? 16 : 8
    if size == 1 {
      guard end - start >= 16 else {
        throw VaultError.unsupportedMedia
      }
      size = bytes[(start + 8)..<(start + 16)].reduce(UInt64(0)) {
        ($0 << 8) | UInt64($1)
      }
    } else if size == 0 {
      size = available
    }
    guard size >= UInt64(header), size <= available else {
      throw VaultError.unsupportedMedia
    }
    return (kind, size, header)
  }

  /// 业务作用：检查电影元数据中的数据来源，只接受没有外部地址的自身数据引用。
  /// 参数说明：
  /// - `bytes`：长度已受限的电影元数据。
  /// - `start`：当前容器载荷的起点。
  /// - `end`：当前容器载荷的末尾。
  /// - `depth`：当前嵌套深度，防止异常深层结构耗尽调用栈。
  /// 返回：已验证的自身引用数量；外部地址、引用电影及异常结构均被拒绝。
  private static func movieReferences(_ bytes: Data, start: Int, end: Int, depth: Int) throws -> Int
  {
    guard depth <= 12 else {
      throw VaultError.unsupportedMedia
    }
    var offset = start
    var references = 0
    while offset < end {
      let box = try movieBox(bytes, start: offset, end: end, available: UInt64(end - offset))
      let payload = offset + box.header
      let next = offset + Int(box.size)
      if ["rmra", "rmda", "rdrf"].contains(box.kind) {
        throw VaultError.unsupportedMedia
      }
      if ["trak", "mdia", "minf", "dinf", "edts", "mvex", "udta"].contains(box.kind) {
        references += try movieReferences(bytes, start: payload, end: next, depth: depth + 1)
      } else if box.kind == "dref" {
        guard next - payload >= 8 else {
          throw VaultError.unsupportedMedia
        }
        let count = bytes[(payload + 4)..<(payload + 8)].reduce(UInt64(0)) {
          ($0 << 8) | UInt64($1)
        }
        guard count > 0, count <= 1024 else {
          throw VaultError.unsupportedMedia
        }
        var entry = payload + 8
        for _ in 0..<count {
          let reference = try movieBox(
            bytes, start: entry, end: next, available: UInt64(next - entry))
          // 自身引用没有 URL、别名或其它载荷；旗标和长度必须同时成立，不能只按扩展名放行。
          guard ["url ", "alis"].contains(reference.kind),
            reference.size == UInt64(reference.header + 4),
            bytes[(entry + reference.header)..<(entry + reference.header + 4)]
              == Data([0, 0, 0, 1])
          else {
            throw VaultError.unsupportedMedia
          }
          references += 1
          entry += Int(reference.size)
        }
        guard entry == next else {
          throw VaultError.unsupportedMedia
        }
      }
      offset = next
    }
    return references
  }

  /// 业务作用：从当前密文生成有界内存画面，供系统不能解码的图片和视频预览使用。
  /// 参数说明：
  /// - `reader`：当前独立密码会话授权的密文读取器。
  /// - `maximumDimension`：内存画面的最长边上限。
  /// 返回：只存在内存中的认证来源画面；取消、失权、超时或解码失败时拒绝。
  static func preview(_ reader: VaultMediaReader, maximumDimension: CGFloat) async throws -> CGImage
  {
    let request = LocalPreviewRequest(reader: reader, maximumDimension: maximumDimension)
    return try await request.image()
  }
}

/// 单次兼容画面请求只保留输入流与内存像素，结束后立即撤销解码和回调。
@MainActor
private final class LocalPreviewRequest: NSObject, VLCMediaThumbnailerDelegate {
  private let reader: VaultMediaReader
  private let maximumDimension: CGFloat
  private var thumbnailer: VLCMediaThumbnailer?
  private var continuation: CheckedContinuation<CGImage, Error>?
  private var deadline: Task<Void, Never>?

  /// 业务作用：建立一次有界的本地兼容图片请求，不提前读取或解析媒体。
  /// 参数说明：
  /// - `reader`：当前会话的认证读取器。
  /// - `maximumDimension`：请求画面的最长边上限。
  /// 返回：尚未开始解码的单次请求。
  init(reader: VaultMediaReader, maximumDimension: CGFloat) {
    self.reader = reader
    self.maximumDimension = maximumDimension
  }

  /// 业务作用：启动内存画面请求，并把取消和超时转换为同一次明确完成。
  /// 参数说明：无。
  /// 返回：当前仍有授权的像素画面；失败不返回部分结果或生成文件。
  func image() async throws -> CGImage {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        self.continuation = continuation
        do {
          try Task.checkCancellation()
          try reader.checkAccess()
          let library = LocalMediaCodecs.library
          let media = try LocalMediaCodecs.streamMedia(reader)
          let thumbnailer = VLCMediaThumbnailer(
            media: media, delegate: self, andVLCLibrary: library)
          thumbnailer.thumbnailWidth = maximumDimension
          thumbnailer.thumbnailHeight = maximumDimension
          thumbnailer.cropsToFit = false
          thumbnailer.snapshotTime = VLCTime(int: 0)
          thumbnailer.hardwareDecodingEnabled = false
          self.thumbnailer = thumbnailer
          deadline = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(20))
            if !Task.isCancelled {
              self?.finish(.failure(VaultError.unsupportedMedia))
            }
          }
          thumbnailer.fetchThumbnail()
        } catch {
          finish(.failure(error))
        }
      }
    } onCancel: {
      Task { @MainActor in
        self.finish(.failure(VaultError.cancelled))
      }
    }
  }

  /// 业务作用：将解码器超时交付回当前请求，不能继续等待已经结束的读取。
  /// 参数说明：
  /// - `mediaThumbnailer`：报告超时的本次解码器。
  /// 返回：请求结束并撤销输入流，不发布旧画面。
  nonisolated func mediaThumbnailerDidTimeOut(_ mediaThumbnailer: VLCMediaThumbnailer) {
    Task { @MainActor in
      finish(.failure(VaultError.unsupportedMedia))
    }
  }

  /// 业务作用：接收兼容解码器产生的内存画面，在发布前重新验证独立密码会话。
  /// 参数说明：
  /// - `mediaThumbnailer`：交付当前画面的解码器。
  /// - `thumbnail`：本次生成、未落盘的像素画面。
  /// 返回：会话仍有效时完成请求；锁定或取消后拒绝画面。
  nonisolated func mediaThumbnailer(
    _ mediaThumbnailer: VLCMediaThumbnailer, didFinishThumbnail thumbnail: CGImage
  ) {
    Task { @MainActor in
      do {
        try reader.checkAccess()
        finish(.success(thumbnail))
      } catch {
        finish(.failure(error))
      }
    }
  }

  /// 业务作用：统一结束一次画面请求，先撤销解码和输入，再把唯一结果交付调用方。
  /// 参数说明：
  /// - `result`：本次成功画面或明确失败。
  /// 返回：至多唤醒一次等待方；所有迟到回调均被丢弃。
  private func finish(_ result: Result<CGImage, Error>) {
    guard let continuation else {
      return
    }
    self.continuation = nil
    deadline?.cancel()
    deadline = nil
    thumbnailer?.delegate = nil
    if let media = thumbnailer?.media {
      VaultRevokeStreamMedia(media)
    }
    thumbnailer?.cancel()
    thumbnailer = nil
    continuation.resume(with: result)
  }
}

/// 兼容解码器只能通过本地认证分块取数，不取得明文文件路径或网络资源地址。
final class VaultInputStream: InputStream, @unchecked Sendable {
  private let reader: VaultMediaReader
  private let mutex = NSLock()
  private var offset: UInt64 = 0
  private var status: Stream.Status = .notOpen
  private var failure: Error?

  /// 业务作用：把已解锁的密文读取器连接到同步、可定位的本地输入流。
  /// 参数说明：
  /// - `reader`：当前独立密码会话授权的文件读取器。
  /// 返回：尚未打开、不持有完整明文的输入流。
  init(reader: VaultMediaReader) {
    self.reader = reader
    super.init(data: Data())
  }

  /// 业务作用：打开一次解码读取会话，关闭或失权后的流不能重新开放。
  /// 参数说明：无。
  /// 返回：会话仍有效时进入可读状态，否则进入错误状态。
  override func open() {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    guard status == .notOpen else {
      return
    }
    do {
      try reader.checkAccess()
      status = .open
    } catch {
      failure = error
      status = .error
    }
  }

  /// 业务作用：关闭当前兼容解码输入，不保留可恢复的读取位置。
  /// 参数说明：无。
  /// 返回：后续读取和定位全部拒绝。
  override func close() {
    mutex.lock()
    status = .closed
    offset = 0
    mutex.unlock()
  }

  /// 业务作用：按解码器需要有界解密并交付字节，每次交付都重新验证会话。
  /// 参数说明：
  /// - `buffer`：解码器提供的输出内存。
  /// - `len`：输出内存容量，单次交付仍限制为一个加密块。
  /// 返回：成功交付的字节数、文件末尾的零，或失权及认证失败时的 -1。
  override func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    guard status == .open || status == .atEnd, len >= 0 else {
      return -1
    }
    do {
      let amount = min(len, VaultMediaReader.chunkSize)
      let bytes = try reader.read(offset: offset, count: amount)
      // 解密完成不等于仍可交付；复制到解码器内存也必须与撤销使用同一会话门禁。
      try reader.grant.access(folders: reader.folderRequirements) { _ in
        bytes.copyBytes(to: buffer, count: bytes.count)
      }
      offset += UInt64(bytes.count)
      status = offset == reader.media.byteCount ? .atEnd : .open
      return bytes.count
    } catch {
      failure = error
      status = .error
      return -1
    }
  }

  /// 业务作用：禁止解码器取得未经会话门禁约束的常驻明文缓冲区。
  /// 参数说明：
  /// - `buffer`：调用方用于接收直接内存地址的位置。
  /// - `len`：调用方用于接收直接内存长度的位置。
  /// 返回：始终为假，解码器必须通过有界读取入口取数。
  override func getBuffer(
    _ buffer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    length len: UnsafeMutablePointer<Int>
  ) -> Bool {
    false
  }

  /// 业务作用：向解码器提供当前输入状态，不触发额外读取。
  /// 参数说明：无。
  /// 返回：受互斥保护的流生命周期状态。
  override var streamStatus: Stream.Status {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    return status
  }

  /// 业务作用：交付当前流的明确失败状态，不包含来源 URL 或原名。
  /// 参数说明：无。
  /// 返回：当前认证或会话错误，尚无错误时为空。
  override var streamError: Error? {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    return failure
  }

  /// 业务作用：报告当前会话流是否还有未消费的字节。
  /// 参数说明：无。
  /// 返回：处于可读状态且未到文件末尾时为真。
  override var hasBytesAvailable: Bool {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    return status == .open && offset < reader.media.byteCount
  }

  /// 业务作用：为容器随机读取提供当前本地字节位置，不暴露实际存储路径。
  /// 参数说明：
  /// - `key`：解码器查询的流属性。
  /// 返回：当前定位位置；其它属性不提供。
  override func property(forKey key: Stream.PropertyKey) -> Any? {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    return key == .fileCurrentOffsetKey ? NSNumber(value: offset) : nil
  }

  /// 业务作用：允许解码器在已认证文件范围内定位，关闭、失权和越界定位全部拒绝。
  /// 参数说明：
  /// - `property`：请求定位的非负字节位置。
  /// - `key`：只接受当前文件偏移属性。
  /// 返回：有效定位时更新内存位置；其它请求不改变状态并返回假。
  override func setProperty(_ property: Any?, forKey key: Stream.PropertyKey) -> Bool {
    mutex.lock()
    defer {
      mutex.unlock()
    }
    guard key == .fileCurrentOffsetKey, let value = property as? NSNumber,
      value.doubleValue.isFinite, value.doubleValue >= 0,
      value.uint64Value <= reader.media.byteCount,
      status == .open || status == .atEnd
    else {
      return false
    }
    do {
      try reader.checkAccess()
      offset = value.uint64Value
      status = offset == reader.media.byteCount ? .atEnd : .open
      return true
    } catch {
      failure = error
      status = .error
      return false
    }
  }
}

/// 仅在当前查看界面存活的播放状态，不持久化任何观看行为。
@MainActor
final class LocalPlayback: ObservableObject {
  let player: AVPlayer
  let resource: EncryptedMediaResource
  @Published var position: Double = 0
  @Published var duration: Double = 0
  @Published var playing = false
  @Published var failure: String?
  @Published var looping = true {
    didSet {
      if !looping, replaying {
        // 关闭循环必须撤销尚未完成的回卷，迟到的 seek 完成不能再次启动播放。
        playbackRevision &+= 1
        replaying = false
        requestedPlay = false
        player.pause()
        refreshState()
      }
    }
  }
  @Published private(set) var compatiblePlayer: VLCMediaPlayer?
  private let reader: VaultMediaReader
  private var compatibilityPoll: Task<Void, Never>?
  private var requestedPlay = false
  private var compatibilityStarted = false
  private var observer: Any?
  private var endObserver: NSObjectProtocol?
  private var playbackRevision: UInt64 = 0
  private var nativeSeekRevision: UInt64?
  private var compatibilitySeekTarget: (seconds: Double, deadline: ContinuousClock.Instant)?
  private var replaying = false
  private var statusObserver: NSKeyValueObservation?
  private var durationObserver: NSKeyValueObservation?
  private var closed = false
  #if os(iOS)
    private var audioSessionUnavailable = false
  #endif

  /// 业务作用：为 App 自有画面层创建本地播放器，关闭外部和后台播放能力。
  /// 参数说明：
  /// - `reader`：当前会话授权的密文读取器。
  /// 返回：尚未开始播放、默认循环当前视频的播放器；不登记最近播放或系统媒体信息。
  init(reader: VaultMediaReader) {
    self.reader = reader
    resource = EncryptedMediaResource(reader: reader)
    let item = AVPlayerItem(asset: resource.asset)
    player = AVPlayer(playerItem: item)
    player.allowsExternalPlayback = false
    player.audiovisualBackgroundPlaybackPolicy = .pauses
    // iPhone 的保亮由前台会话统一控制，两套解码器共用暂停、锁定和失焦时的撤销边界。
    player.preventsDisplaySleepDuringVideoPlayback = false
    player.actionAtItemEnd = .pause
    endObserver = NotificationCenter.default.addObserver(
      forName: .AVPlayerItemDidPlayToEndTime, object: item, queue: .main
    ) { [weak self] _ in
      Task { @MainActor [weak self] in
        guard let self, !self.closed, self.compatiblePlayer == nil, !self.replaying,
          self.nativeSeekRevision == nil
        else {
          return
        }
        let current = self.player.currentTime().seconds
        let duration = self.player.currentItem?.duration.seconds ?? 0
        // 已经离开片尾的跳转不能被旧结束通知拉回起点。
        if current.isFinite, duration.isFinite, duration > 0, current < duration - 0.25 {
          return
        }
        self.finishedPlayback()
      }
    }
    statusObserver = item.observe(\.status, options: [.initial, .new]) { [weak self] item, _ in
      let failed = item.status == .failed
      let ready = item.status == .readyToPlay
      Task { @MainActor [weak self] in
        guard let self, !self.closed else {
          return
        }
        if failed {
          self.activateCompatibility()
        } else if ready {
          self.refreshState()
        }
      }
    }
    durationObserver = item.observe(\.duration, options: [.initial, .new]) { [weak self] _, _ in
      Task { @MainActor [weak self] in
        guard let self, !self.closed else {
          return
        }
        // 本地视频未开始播放时也要提供正确的时长与跳转范围，不能依赖播放计时通知。
        self.refreshState()
      }
    }
    observer = player.addPeriodicTimeObserver(
      forInterval: CMTime(seconds: 0.25, preferredTimescale: 600), queue: .main
    ) { [weak self] _ in
      Task { @MainActor [weak self] in
        guard let self, !self.closed else {
          return
        }
        // 排队的通知可能早于暂停或画面切换，发布时读取播放器现值，避免旧采样覆盖当前进度。
        self.refreshState()
      }
    }
    if reader.media.contentType == "public.movie" {
      activateCompatibility()
    }
  }

  /// 业务作用：系统解码器不接受容器或编码时，使用自有本地输入流交给兼容解码器。
  /// 参数说明：无。
  /// 返回：成功后改用兼容画面；无法建立本地流时保留明确失败提示，不生成明文副本。
  private func activateCompatibility() {
    guard !closed, compatiblePlayer == nil else {
      return
    }
    do {
      try reader.checkAccess()
      let library = LocalMediaCodecs.library
      let media = try LocalMediaCodecs.streamMedia(reader)
      let decoder = VLCMediaPlayer(library: library)
      decoder.media = media
      // 先停止系统读取再开放兼容解码，两个解码器不能同时持有可播放的画面。
      playbackRevision &+= 1
      nativeSeekRevision = nil
      compatibilitySeekTarget = nil
      replaying = false
      player.pause()
      player.replaceCurrentItem(with: nil)
      resource.loader.cancelAll()
      compatiblePlayer = decoder
      failure = nil
      compatibilityPoll = Task { @MainActor [weak self] in
        while !Task.isCancelled {
          try? await Task.sleep(for: .milliseconds(250))
          guard !Task.isCancelled, let self, !self.closed else {
            return
          }
          self.refreshState()
        }
      }
    } catch {
      failure = "无法播放此文件，请确认文件完整且编码受支持。"
      playing = false
    }
  }

  /// 业务作用：只在应用自有画面已经挂接时允许兼容视频开始显示，避免解码器另开窗口。
  /// 参数说明：
  /// - `drawable`：当前查看界面拥有的原生画面视图。
  /// 返回：兼容解码器绑定当前画面，排队的播放请求仅在此画面内执行。
  func attachCompatibility(to drawable: AnyObject) {
    guard !closed, let decoder = compatiblePlayer else {
      return
    }
    if decoder.drawable as AnyObject? !== drawable {
      decoder.drawable = drawable
      if requestedPlay {
        decoder.play()
      }
    }
  }

  /// 业务作用：按媒体播放用途启用 iPhone 音频，避免沿用系统默认的环境音策略。
  /// 参数说明：无。
  /// 返回：声音会话可用时允许开始播放；失败时保留可重试提示，不改系统音量或强制切换输出设备。
  private func activateAudioSession() -> Bool {
    #if os(iOS)
      do {
        let session = AVAudioSession.sharedInstance()
        // 只声明媒体播放用途，由系统沿用用户的耳机或扬声器选择，不开启录音与后台播放。
        try session.setCategory(.playback, mode: .moviePlayback, options: [])
        try session.setActive(true)
        if audioSessionUnavailable {
          failure = nil
          audioSessionUnavailable = false
        }
      } catch {
        requestedPlay = false
        playing = false
        audioSessionUnavailable = true
        failure = "无法启用视频声音，请稍后点击播放重试。"
        return false
      }
    #endif
    return true
  }

  /// 业务作用：只在当前查看会话中切换播放或暂停，不写入恢复进度。
  /// 参数说明：无。
  /// 返回：播放器切换状态，关闭后的实例不重新启动。
  func toggle() {
    guard !closed else {
      return
    }
    if let decoder = compatiblePlayer {
      do {
        try reader.checkAccess()
        if decoder.state == .stopped, compatibilityStarted {
          requestedPlay = false
          compatibilityStarted = false
        }
        requestedPlay.toggle()
        if !requestedPlay {
          decoder.pause()
        } else {
          guard activateAudioSession() else {
            return
          }
          if decoder.drawable != nil {
            decoder.play()
          }
        }
      } catch {
        failure = "无法播放此文件，请确认文件完整且编码受支持。"
        requestedPlay = false
      }
      refreshState()
      return
    }
    playbackRevision &+= 1
    replaying = false
    if requestedPlay || player.rate > 0 {
      player.pause()
      requestedPlay = false
      refreshState()
    } else {
      do {
        try reader.checkAccess()
        guard activateAudioSession() else {
          return
        }
        requestedPlay = true
        if duration > 0, position >= duration - 0.1 {
          seekNative(to: 0, automaticRepeat: false)
        } else {
          player.play()
          playing = true
        }
      } catch {
        requestedPlay = false
        playing = false
        failure = "无法播放此文件，请确认文件完整且编码受支持。"
      }
    }
  }

  /// 业务作用：同步播放器状态，定位期间维持已选择的目标，完成后再交给实际进度采样。
  /// 参数说明：无。
  /// 返回：内存中的进度、时长和播放状态更新，不写入文件或系统媒体信息。
  private func refreshState() {
    if let decoder = compatiblePlayer {
      let current = max(0, (decoder.time.value?.doubleValue ?? 0) / 1000)
      duration = max(0, (decoder.media?.length.value?.doubleValue ?? 0) / 1000)
      // 异步定位尚未到达目标时不能用旧采样回退滑块；解码失败或超时后恢复实际进度。
      if let target = compatibilitySeekTarget,
        abs(current - target.seconds) <= 0.75 || ContinuousClock.now >= target.deadline
          || decoder.state == .error
      {
        compatibilitySeekTarget = nil
      }
      if compatibilitySeekTarget == nil {
        position = current
      }
      playing = decoder.isPlaying || compatibilitySeekTarget != nil && requestedPlay
      if decoder.state == .playing || decoder.state == .opening {
        compatibilityStarted = true
      }
      if decoder.state == .stopped, compatibilityStarted, compatibilitySeekTarget == nil {
        compatibilityStarted = false
        finishedPlayback()
      }
      if decoder.state == .error {
        failure = "无法播放此文件，请确认文件完整且编码受支持。"
        playing = false
        requestedPlay = false
      }
      return
    }
    let current = player.currentTime().seconds
    let length = player.currentItem?.duration.seconds ?? 0
    // 定位完成回调负责交接目标与实际进度，排队的旧采样不能抢先覆盖手指选择的位置。
    if nativeSeekRevision == nil {
      position = current.isFinite ? max(0, current) : 0
    }
    duration = length.isFinite ? max(0, length) : 0
    playing = player.rate > 0 || (replaying || nativeSeekRevision != nil) && requestedPlay
  }

  /// 业务作用：仅在仍有播放意图和当前会话授权时重播当前视频，关闭循环时结束播放。
  /// 参数说明：无。
  /// 返回：自然结束后按当前开关回到起点或停止；失权和解码失败不会继续发起重播。
  private func finishedPlayback() {
    guard !closed, requestedPlay else {
      return
    }
    guard looping, failure == nil else {
      requestedPlay = false
      playing = false
      return
    }
    do {
      // 每一轮重新检查授权，关闭、锁定或切换视频后的旧实例不能恢复读取。
      try reader.checkAccess()
      if let decoder = compatiblePlayer {
        guard decoder.drawable != nil else {
          requestedPlay = false
          playing = false
          return
        }
        decoder.play()
      } else {
        seekNative(to: 0, automaticRepeat: true)
      }
    } catch {
      requestedPlay = false
      playing = false
    }
  }

  /// 业务作用：把系统播放器定位到当前目标，并阻止暂停、关闭和新跳转后的旧完成回调恢复播放。
  /// 参数说明：
  /// - `seconds`：本次明确跳转或片尾回卷的目标秒数。
  /// - `automaticRepeat`：本次是否由循环触发，完成时仍需保持循环开启。
  /// 返回：先稳定显示目标并暂停旧位置输出，定位成功且仍有授权时按原播放意图继续。
  private func seekNative(to seconds: Double, automaticRepeat: Bool) {
    playbackRevision &+= 1
    let revision = playbackRevision
    nativeSeekRevision = revision
    replaying = automaticRepeat
    position = seconds
    // 先暂停旧位置输出，待本次定位完成并复验授权后再恢复，避免旧帧与目标帧交错呈现。
    player.pause()
    player.seek(
      to: CMTime(seconds: seconds, preferredTimescale: 600),
      toleranceBefore: .zero, toleranceAfter: .zero
    ) { [weak self] finished in
      Task { @MainActor [weak self] in
        guard let self, !self.closed else {
          return
        }
        if self.nativeSeekRevision == revision {
          self.nativeSeekRevision = nil
        }
        guard self.playbackRevision == revision else {
          return
        }
        self.replaying = false
        guard finished, !automaticRepeat || self.looping else {
          self.requestedPlay = false
          self.refreshState()
          return
        }
        do {
          try self.reader.checkAccess()
          if self.requestedPlay {
            self.player.play()
          }
        } catch {
          self.requestedPlay = false
          self.player.pause()
        }
        self.refreshState()
      }
    }
  }

  /// 业务作用：响应用户在当前会话内拖动进度，不保存跳转位置。
  /// 参数说明：
  /// - `seconds`：需要跳转的媒体时间。
  /// 返回：目标立即接管界面进度，定位完成后恢复实际采样；关闭后不执行。
  func seek(_ seconds: Double) {
    guard !closed, seconds.isFinite else {
      return
    }
    if let decoder = compatiblePlayer {
      guard duration.isFinite, duration > 0, decoder.isSeekable else {
        return
      }
      // 有准确长度的本地输入使用归一化位置，兼容不提供按时间索引的容器。
      let target = min(max(0, seconds), duration)
      compatibilitySeekTarget = (target, ContinuousClock.now.advanced(by: .seconds(2)))
      position = target
      decoder.position = target / duration
      return
    }
    seekNative(to: min(max(0, seconds), max(0, duration)), automaticRepeat: false)
  }

  /// 业务作用：关闭查看时停止播放、撤销请求并释放观察器，丢弃全部会话内进度。
  /// 参数说明：无。
  /// 返回：播放器不可恢复使用，下次查看必须新建实例。
  func close() {
    guard !closed else {
      return
    }
    closed = true
    playbackRevision &+= 1
    nativeSeekRevision = nil
    compatibilitySeekTarget = nil
    replaying = false
    // 撤下画面和输入后才停止解码器，迟到的解码请求不能再次获得明文。
    compatibilityPoll?.cancel()
    compatibilityPoll = nil
    compatiblePlayer?.drawable = nil
    if let media = compatiblePlayer?.media {
      VaultRevokeStreamMedia(media)
    }
    compatiblePlayer?.stop()
    // stop 为异步动作；媒体包装必须随解码器保留到其内部读取完全结束，不能提前释放回调输入流。
    compatiblePlayer = nil
    requestedPlay = false
    compatibilityStarted = false
    player.pause()
    if let observer {
      player.removeTimeObserver(observer)
    }
    observer = nil
    if let endObserver {
      NotificationCenter.default.removeObserver(endObserver)
    }
    endObserver = nil
    statusObserver?.invalidate()
    statusObserver = nil
    durationObserver?.invalidate()
    durationObserver = nil
    player.replaceCurrentItem(with: nil)
    resource.loader.cancelAll()
    position = 0
    duration = 0
    playing = false
  }
}
