#if os(macOS)
  import Foundation

  @objc protocol VaultMigrationNetworkEvents {
    /// 业务作用：仅传递连接状态，不让网络进程接触保险箱内容或界面状态。
    /// 参数说明：
    /// - code：监听就绪、服务端连接就绪、客户端连接就绪或连接失败。
    /// 返回：宿主按当前会话消费事件，旧会话不会恢复。
    func networkEvent(_ code: Int)
  }

  @objc protocol VaultMigrationNetworkService {
    /// 业务作用：以宿主自身只读代码句柄验证本地调用者，不扩大服务文件系统权限。
    /// 参数说明：
    /// - host：仅指向包含本服务的主应用可执行文件的只读句柄。
    /// - reply：返回签名要求建立后才产生的一次性挑战，失败为空。
    /// 返回：此步不开放网络，必须经下一条受系统签名校验的消息回应挑战。
    func authorize(_ host: FileHandle, withReply reply: @escaping (Data?) -> Void)
    /// 业务作用：要求调用者在签名规则生效后回应随机挑战，避免预先排队请求越权。
    /// 参数说明：
    /// - challenge：本通道刚生成的短期随机挑战。
    /// - reply：本条消息已通过系统签名要求且挑战匹配时返回真。
    /// 返回：仅该通道获得后续网络请求能力。
    func activate(_ challenge: Data, withReply reply: @escaping (Bool) -> Void)
    /// 业务作用：为一次短期配对开启独立网络监听。
    /// 参数说明：
    /// - configuration：只含随机配对身份、密钥和有效期的配置。
    /// - reply：配置被接纳时返回 true，认证就绪由独立事件通知。
    /// 返回：不接收保险箱凭据，不访问文件系统中的保险箱。
    func listen(_ configuration: Data, withReply reply: @escaping (Bool) -> Void)
    /// 业务作用：查找并连接用户明确选择的 Bonjour 配对身份。
    /// 参数说明：
    /// - configuration：只含对端短期配对材料的配置。
    /// - reply：配置被接纳时返回 true。
    /// 返回：只连接指定身份，不遍历尝试其它设备。
    func connect(_ configuration: Data, withReply reply: @escaping (Bool) -> Void)
    /// 业务作用：传递宿主已经加密的单个有界业务帧。
    /// 参数说明：
    /// - packet：不含保险箱主密钥或明文文件的加密字节。
    /// - reply：网络栈消耗缓冲后返回是否成功。
    /// 返回：完成背压等待，不代表对端已提交。
    func send(_ packet: Data, withReply reply: @escaping (Bool) -> Void)
    /// 业务作用：从认证连接读取有界数据片段。
    /// 参数说明：
    /// - maximum：允许交付的最大字节数。
    /// - reply：交付片段或连接失败。
    /// 返回：不解释业务内容，不写入磁盘。
    func receive(_ maximum: Int, withReply reply: @escaping (Data?) -> Void)
    /// 业务作用：关闭本次发现、监听及连接。
    /// 参数说明：无。
    /// 返回：不再具有交付网络数据的能力。
    func stop()
  }

  struct VaultMigrationNetworkConfiguration: Codable {
    let id: UUID
    let secret: Data
    let expires: Date
    static let serviceID = "local.encvault.migration.networkservice"
    static let bonjour = "_encvault._tcp"
    static let limit = 1_048_576 + 65_536
  }
#endif
