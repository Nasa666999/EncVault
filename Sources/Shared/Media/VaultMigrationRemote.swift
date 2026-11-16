#if os(macOS)
  import Foundation

  /// 独立网络服务只传递密文；宿主与文档解析进程保持无网络权限。
  final class VaultMigrationRemote: NSObject, VaultMigrationNetworkEvents, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let mutex = NSLock()
    private var active = true
    private var ready = false
    private var pending: [UUID: () -> Void] = [:]
    private let event: @Sendable (Int) -> Void

    /// 业务作用：为当前迁移页面建立独立、可撤销的网络服务通道。
    /// 参数说明：
    /// - event：仅处理当前页面代次的连接事件。
    /// 返回：尚未启用网络发现的 RPC 通道。
    init(event: @escaping @Sendable (Int) -> Void) {
      self.event = event
      connection = NSXPCConnection(serviceName: VaultMigrationNetworkConfiguration.serviceID)
      super.init()
      connection.remoteObjectInterface = NSXPCInterface(with: VaultMigrationNetworkService.self)
      connection.exportedInterface = NSXPCInterface(with: VaultMigrationNetworkEvents.self)
      connection.exportedObject = self
      connection.invalidationHandler = { [weak self] in
        self?.cancel()
      }
      connection.interruptionHandler = { [weak self] in
        self?.cancel()
      }
      connection.resume()
    }

    /// 业务作用：只接受本通道的连接事件，认证完成之前不允许内容读写。
    /// 参数说明：
    /// - code：服务发出的有界状态码。
    /// 返回：失败即撤销所有等待，迟到就绪不会重新开放。
    func networkEvent(_ code: Int) {
      mutex.lock()
      guard active else {
        mutex.unlock()
        return
      }
      if code == 2 || code == 3 {
        ready = true
      }
      mutex.unlock()
      if code == 4 {
        cancel()
      }
      event(code)
    }

    /// 业务作用：跨进程请求只恢复一次，连接失效会释放全部等待。
    /// 参数说明：
    /// - action：调用有独立回复的有界 RPC。
    /// 返回：有效回复；服务退出、取消或拒绝时抛出连接错误。
    private func request<T: Sendable>(
      _ action: @escaping (VaultMigrationNetworkService, @escaping (T?) -> Void) -> Void
    ) async throws -> T {
      try await withCheckedThrowingContinuation {
        continuation in
        let id = UUID()
        mutex.lock()
        guard active else {
          mutex.unlock()
          continuation.resume(throwing: VaultMigrationError.connection)
          return
        }
        pending[id] = {
          continuation.resume(throwing: VaultMigrationError.connection)
        }
        mutex.unlock()
        let finish: (T?) -> Void = { [weak self] value in
          guard let self else {
            return
          }
          self.mutex.lock()
          let waiting = self.pending.removeValue(forKey: id)
          self.mutex.unlock()
          guard waiting != nil else {
            return
          }
          if let value {
            continuation.resume(returning: value)
          } else {
            waiting?()
          }
        }
        guard
          let proxy = connection.remoteObjectProxyWithErrorHandler({
            _ in finish(nil)
          })
            as? VaultMigrationNetworkService
        else {
          finish(nil)
          return
        }
        action(proxy, finish)
      }
    }

    /// 业务作用：将配对范围转换为无保险箱凭据的网络配置。
    /// 参数说明：
    /// - pairing：本次页面生成或用户提供的短期配对。
    /// - listening：是否监听本机配对。
    /// 返回：服务接纳配置；后续 TLS 完成另行通知。
    func begin(_ pairing: VaultMigrationPairing, listening: Bool) async throws {
      guard let executable = Bundle.main.executableURL else {
        throw VaultMigrationError.connection
      }
      let host = try FileHandle(forReadingFrom: executable)
      defer {
        try? host.close()
      }
      let challenge: Data = try await request {
        proxy, finish in
        proxy.authorize(host) {
          finish($0)
        }
      }
      guard challenge.count == 32 else {
        throw VaultMigrationError.connection
      }
      let authorized: Bool = try await request {
        proxy, finish in
        proxy.activate(challenge) {
          finish($0)
        }
      }
      guard authorized else {
        throw VaultMigrationError.connection
      }
      let data = try JSONEncoder().encode(
        VaultMigrationNetworkConfiguration(
          id: pairing.id, secret: pairing.secret, expires: pairing.expires))
      let accepted: Bool = try await request {
        proxy, finish in
        if listening {
          proxy.listen(data) {
            finish($0)
          }
        } else {
          proxy.connect(data) {
            finish($0)
          }
        }
      }
      guard accepted else {
        throw VaultMigrationError.connection
      }
    }

    /// 业务作用：验证独立服务仍在本次认证连接中。
    /// 参数说明：无。
    /// 返回：只有已认证且未撤销的连接可以继续读写和提交。
    func check() throws {
      mutex.lock()
      defer {
        mutex.unlock()
      }
      guard active && ready else {
        throw VaultMigrationError.connection
      }
    }

    /// 业务作用：向独立服务交付一个已加密业务帧并等待背压。
    /// 参数说明：
    /// - packet：经过长度限制的协议字节。
    /// 返回：服务完成本次发送；断开时拒绝。
    func send(_ packet: Data) async throws {
      try check()
      let sent: Bool = try await request {
        proxy, finish in
        proxy.send(packet) {
          finish($0)
        }
      }
      guard sent else {
        throw VaultMigrationError.connection
      }
    }

    /// 业务作用：只读取当前字段需要的有界片段。
    /// 参数说明：
    /// - maximum：当前字段尚缺少的最大字节数。
    /// 返回：非空密文字节，服务失效时不继续等待。
    func receive(_ maximum: Int) async throws -> Data {
      try check()
      let data: Data = try await request {
        proxy, finish in
        proxy.receive(maximum) {
          finish($0)
        }
      }
      guard !data.isEmpty, data.count <= maximum else {
        throw VaultMigrationError.connection
      }
      return data
    }

    /// 业务作用：撤销本通道并释放尚未收到服务回复的读写。
    /// 参数说明：无。
    /// 返回：关闭服务连接，所有旧请求拒绝。
    func cancel() {
      mutex.lock()
      guard active else {
        mutex.unlock()
        return
      }
      active = false
      ready = false
      let waiting = Array(pending.values)
      pending.removeAll()
      mutex.unlock()
      (connection.remoteObjectProxy as? VaultMigrationNetworkService)?.stop()
      connection.invalidate()
      waiting.forEach {
        $0()
      }
    }
  }
#endif
