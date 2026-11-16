import Foundation
import Network
import Security

/// 仅承载短期 TLS 连接，不具有保险箱文件、相册或文档解析权限。
final class MigrationNetworkService: NSObject, NSXPCListenerDelegate, VaultMigrationNetworkService {
  private let queue = DispatchQueue(label: "local.encvault.migration.network-service")
  private weak var client: NSXPCConnection?
  private var listener: NWListener?
  private var browser: NWBrowser?
  private var channel: NWConnection?
  private var authorized = false
  private var challenge: Data?
  private var challengeExpires = Date.distantPast
  private var ready = false
  private var sending = false
  private var receiving = false
  private var epoch = UUID()

  /// 业务作用：只向同一用户启动且签名与宿主匹配的应用开放网络服务。
  /// 参数说明：
  /// - listener：系统管理的 XPC 监听器。
  /// - newConnection：待认证的本地调用者。
  /// 返回：调用者身份不符时拒绝，不向其它进程提供通用网络代理。
  func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection)
    -> Bool
  {
    guard newConnection.effectiveUserIdentifier == geteuid() else {
      return false
    }
    // 每条 XPC 连接持有独立网络状态，旧连接的退出回调不能关闭之后重新配对的连接。
    let session = MigrationNetworkService()
    session.client = newConnection
    newConnection.exportedInterface = NSXPCInterface(with: VaultMigrationNetworkService.self)
    newConnection.exportedObject = session
    newConnection.remoteObjectInterface = NSXPCInterface(with: VaultMigrationNetworkEvents.self)
    newConnection.invalidationHandler = { [weak session] in
      session?.stop()
    }
    newConnection.interruptionHandler = { [weak session] in
      session?.stop()
    }
    newConnection.resume()
    return true
  }

  /// 业务作用：只读取宿主主动交付的代码句柄，并由系统对后续每条 XPC 消息校验签名。
  /// 参数说明：
  /// - host：包含本服务的主应用可执行文件，只允许只读且路径完全匹配。
  /// - reply：本地调用者通过宿主签名要求后返回真。
  /// 返回：验证前所有网络请求拒绝，不授予服务读取保险箱或整个宿主目录的权限。
  func authorize(_ host: FileHandle, withReply reply: @escaping (Data?) -> Void) {
    queue.async { [self] in
      var length: UInt32 = 0
      _NSGetExecutablePath(nil, &length)
      var executablePath = [CChar](repeating: 0, count: Int(length))
      guard _NSGetExecutablePath(&executablePath, &length) == 0 else {
        reply(nil)
        return
      }
      let executable = URL(fileURLWithPath: String(cString: executablePath))
        .resolvingSymlinksInPath()
      let service = executable.deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent()
      let app = service.deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent()
      var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
      let descriptor = host.fileDescriptor
      guard service.pathExtension == "xpc", app.pathExtension == "app",
        let hostName = Bundle.main.object(forInfoDictionaryKey: "EncVaultHostExecutable")
          as? String,
        !hostName.contains("/"),
        fcntl(descriptor, F_GETPATH, &path) == 0,
        URL(fileURLWithPath: String(cString: path)).resolvingSymlinksInPath()
          == app.appendingPathComponent("Contents/MacOS").appendingPathComponent(hostName),
        fcntl(descriptor, F_GETFL) & O_ACCMODE == O_RDONLY
      else {
        reply(nil)
        return
      }
      var code: SecStaticCode?
      var requirement: SecRequirement?
      var text: CFString?
      // 只读句柄跨越文件沙箱，签名要求由系统绑定调用者的审计身份，避免依赖可复用的进程号。
      guard
        SecStaticCodeCreateWithPath(
          URL(fileURLWithPath: "/dev/fd/\(descriptor)") as CFURL, [], &code) == errSecSuccess,
        let code, SecCodeCopyDesignatedRequirement(code, [], &requirement) == errSecSuccess,
        let requirement, SecRequirementCopyString(requirement, [], &text) == errSecSuccess,
        let text, let client = self.client
      else {
        reply(nil)
        return
      }
      client.setCodeSigningRequirement(text as String)
      var bytes = Data(count: 32)
      let status = bytes.withUnsafeMutableBytes {
        SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
      }
      guard status == errSecSuccess else {
        reply(nil)
        return
      }
      self.challenge = bytes
      self.challengeExpires = Date().addingTimeInterval(10)
      reply(bytes)
    }
  }

  /// 业务作用：在系统已绑定签名要求后消费一次随机挑战，才开放网络路由。
  /// 参数说明：
  /// - value：收到前一条认证回复后才能知道的随机挑战。
  /// - reply：本通道挑战未过期且匹配时返回真。
  /// 返回：已排队的未认证请求不能预知挑战，不能提前开启网络。
  func activate(_ value: Data, withReply reply: @escaping (Bool) -> Void) {
    queue.async { [self] in
      guard let expected = challenge, value == expected, challengeExpires > Date() else {
        reply(false)
        return
      }
      challenge = nil
      authorized = true
      reply(true)
    }
  }

  /// 业务作用：解析有界短期配对配置，拒绝无效随机密钥与过期发现。
  /// 参数说明：
  /// - data：宿主明确提供的配对网络字段。
  /// 返回：合法配置或空值，不接受任意主机地址和持久服务。
  private func configuration(_ data: Data) -> VaultMigrationNetworkConfiguration? {
    guard data.count <= 2048,
      let value = try? JSONDecoder().decode(VaultMigrationNetworkConfiguration.self, from: data),
      value.secret.count == 32, value.expires > Date(), value.expires.timeIntervalSinceNow <= 900
    else {
      return nil
    }
    return value
  }

  /// 业务作用：强制使用高熵 PSK 的 TLS AEAD 连接并允许 Apple 点对点接口。
  /// 参数说明：
  /// - value：本次独立配对随机密钥。
  /// 返回：只允许 TLS 1.2 AEAD PSK 的系统连接参数。
  private func parameters(_ value: VaultMigrationNetworkConfiguration) -> NWParameters {
    let options = NWProtocolTLS.Options()
    let security = options.securityProtocolOptions
    sec_protocol_options_set_min_tls_protocol_version(security, .TLSv12)
    sec_protocol_options_set_max_tls_protocol_version(security, .TLSv12)
    sec_protocol_options_append_tls_ciphersuite(
      security, tls_ciphersuite_t(rawValue: UInt16(TLS_PSK_WITH_AES_128_GCM_SHA256))!)
    let identity = Data(value.id.uuidString.utf8)
    value.secret.withUnsafeBytes {
      secret in
      identity.withUnsafeBytes {
        identity in
        sec_protocol_options_add_pre_shared_key(
          security, DispatchData(bytes: secret) as __DispatchData,
          DispatchData(bytes: identity) as __DispatchData)
      }
    }
    sec_protocol_options_set_tls_pre_shared_key_identity_hint(
      security,
      identity.withUnsafeBytes {
        DispatchData(bytes: $0) as __DispatchData
      })
    let result = NWParameters(tls: options, tcp: NWProtocolTCP.Options())
    result.includePeerToPeer = true
    return result
  }

  /// 业务作用：向宿主报告连接状态而不解释任何保险箱内容。
  /// 参数说明：
  /// - code：监听就绪、认证就绪或失败的固定状态码。
  /// 返回：事件交付当前本地通道。
  private func event(_ code: Int) {
    (client?.remoteObjectProxy as? VaultMigrationNetworkEvents)?.networkEvent(code)
  }

  /// 业务作用：只为本次随机服务名称开放短期监听。
  /// 参数说明：
  /// - pairing：宿主提供的配对网络配置。
  /// - reply：报告配置是否被接纳。
  /// 返回：监听只接受单个 TLS 对端，失效即停止。
  func listen(_ pairing: Data, withReply reply: @escaping (Bool) -> Void) {
    queue.async { [self] in
      guard self.authorized, let value = self.configuration(pairing) else {
        reply(false)
        return
      }
      self.close()
      let epoch = self.epoch
      do {
        let listener = try NWListener(using: self.parameters(value), on: .any)
        self.listener = listener
        listener.service = NWListener.Service(
          name: value.id.uuidString, type: VaultMigrationNetworkConfiguration.bonjour)
        listener.stateUpdateHandler = { [weak self] state in
          guard let self, self.epoch == epoch else {
            return
          }
          if case .ready = state {
            self.event(1)
          }
          if case .failed = state {
            if self.channel == nil {
              self.event(4)
              self.close()
            }
          }
        }
        listener.newConnectionHandler = { [weak self] channel in
          guard let self, self.epoch == epoch, self.channel == nil else {
            channel.cancel()
            return
          }
          self.attach(channel, server: true)
        }
        listener.start(queue: self.queue)
        reply(true)
      } catch {
        reply(false)
      }
    }
  }

  /// 业务作用：只发现二维码标识的单个 Bonjour 服务，禁止宿主任意指定网络目的地。
  /// 参数说明：
  /// - pairing：用户提供的短期对端配对字段。
  /// - reply：报告发现请求是否被接纳。
  /// 返回：匹配服务后使用其 PSK 认证，失败即停止。
  func connect(_ pairing: Data, withReply reply: @escaping (Bool) -> Void) {
    queue.async { [self] in
      guard self.authorized, let value = self.configuration(pairing) else {
        reply(false)
        return
      }
      self.close()
      let epoch = self.epoch
      let options = NWParameters.tcp
      options.includePeerToPeer = true
      let browser = NWBrowser(
        for: .bonjour(type: VaultMigrationNetworkConfiguration.bonjour, domain: nil), using: options
      )
      self.browser = browser
      browser.browseResultsChangedHandler = {
        [weak self] results, _ in
        guard let self, self.epoch == epoch, self.channel == nil else {
          return
        }
        for result in results {
          if case .service(let name, _, _, _) = result.endpoint, name == value.id.uuidString {
            self.attach(
              NWConnection(to: result.endpoint, using: self.parameters(value)), server: false)
            break
          }
        }
      }
      browser.stateUpdateHandler = { [weak self] state in
        guard let self, self.epoch == epoch else {
          return
        }
        if case .failed = state {
          if self.channel == nil {
            self.event(4)
            self.close()
          }
        }
      }
      browser.start(queue: self.queue)
      reply(true)
    }
  }

  /// 业务作用：认证完成后才开放字节通道，监听端不接受第二个连接。
  /// 参数说明：
  /// - channel：本次配对建立的 TLS 连接。
  /// - server：当前是否监听端。
  /// 返回：宿主收到就绪事件时才可以交换业务握手。
  private func attach(_ channel: NWConnection, server: Bool) {
    self.channel = channel
    let epoch = epoch
    // 配对确认期间保留 Bonjour 服务和发现对象，连接只接纳第一个对端，直到明确结束才撤下。
    channel.stateUpdateHandler = { [weak self] state in
      guard let self, self.epoch == epoch else {
        return
      }
      switch state {
      case .ready:
        self.ready = true
        self.event(server ? 2 : 3)
      case .failed:
        self.event(4)
        self.close()
      default: break
      }
    }
    channel.start(queue: queue)
  }

  /// 业务作用：限制单帧和未完成写入数量，避免宿主请求积压。
  /// 参数说明：
  /// - packet：已经加密的业务字节。
  /// - reply：完成当前缓冲发送后报告状态。
  /// 返回：只向已认证的本次连接交付有界数据。
  func send(_ packet: Data, withReply reply: @escaping (Bool) -> Void) {
    queue.async { [self] in
      guard self.ready, !self.sending, packet.count <= VaultMigrationNetworkConfiguration.limit + 4,
        let channel = self.channel
      else {
        reply(false)
        return
      }
      self.sending = true
      channel.send(
        content: packet,
        completion: .contentProcessed {
          error in
          self.sending = false
          reply(error == nil)
        })
    }
  }

  /// 业务作用：按宿主给定字段聚合密文，限制一次读取和在途请求数。
  /// 参数说明：
  /// - maximum：已通过协议上限检查的当前字段剩余长度。
  /// - reply：聚合后的密文字段或失败，断开时可能短于请求长度。
  /// 返回：字节来自唯一认证通道，提前断开不返回成功。
  func receive(_ maximum: Int, withReply reply: @escaping (Data?) -> Void) {
    queue.async { [self] in
      guard self.ready, !self.receiving, maximum > 0,
        maximum <= VaultMigrationNetworkConfiguration.limit,
        let channel = self.channel
      else {
        reply(nil)
        return
      }
      self.receiving = true
      // 服务只聚合有界密文，减少 TLS 分片逐个跨 XPC 往返；不取得正文解密能力。
      channel.receive(minimumIncompleteLength: maximum, maximumLength: maximum) {
        data, _, _, error in
        self.receiving = false
        reply(error == nil ? data : nil)
      }
    }
  }

  /// 业务作用：在串行网络队列关闭全部网络能力。
  /// 参数说明：无。
  /// 返回：所有旧监听与连接撤销，不保留长期服务。
  private func close() {
    epoch = UUID()
    ready = false
    listener?.cancel()
    browser?.cancel()
    channel?.cancel()
    listener = nil
    browser = nil
    channel = nil
  }

  /// 业务作用：宿主关闭页面或失联时停止独立网络服务。
  /// 参数说明：无。
  /// 返回：网络队列撤销全部监听与连接。
  func stop() {
    queue.async { [self] in
      self.authorized = false
      self.challenge = nil
      self.close()
    }
  }

  /// 业务作用：本地调用者退出后释放该连接独有的网络能力。
  /// 参数说明：无。
  /// 返回：不会残留仍可接收连接的监听或未取消的传输。
  deinit {
    listener?.cancel()
    browser?.cancel()
    channel?.cancel()
  }
}

@main
enum MigrationNetworkEntry {
  /// 业务作用：由系统启动本应用专用的沙箱网络服务。
  /// 参数说明：无。
  /// 返回：仅在宿主请求期间处理 XPC 事件，由系统管理生命周期。
  static func main() {
    let service = MigrationNetworkService()
    let listener = NSXPCListener.service()
    listener.delegate = service
    listener.resume()
  }
}
