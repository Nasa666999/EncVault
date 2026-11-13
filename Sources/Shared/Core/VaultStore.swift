import CryptoKit
import Darwin
import Foundation
import Security

/// 凭据封装头，只包含盐、密文和随机身份，不包含密码或媒体名称。
struct VaultHeader: Codable, Sendable {
  let formatVersion: Int
  let vaultID: UUID
  let generation: UUID
  let kind: CredentialKind
  let salt: Data
  let iterations: Int
  let deviceAccount: String
  let credentialRoot: Data
  let recoveryRoot: Data

  var credentialContext: Data {
    Data("EncVault/credential/\(vaultID)/\(generation)/\(kind.rawValue)".utf8)
  }

  var recoveryContext: Data {
    Data("EncVault/recovery/\(vaultID)/\(generation)".utf8)
  }
}

private struct PendingEnrollment {
  let offer: EnrollmentOffer
  let header: VaultHeader
  let secret: DeviceSecretState
  let root: Data
  let previousGeneration: UUID?
}

/// 本机保险箱的凭据和文件事务入口，所有持久化变更串行执行。
final class VaultStore: @unchecked Sendable {
  let directory: URL
  let mediaDirectory: URL
  private let secrets: any DeviceSecretStore
  private let transaction = NSRecursiveLock()
  private let grantsLock = NSLock()
  private var grants: [VaultGrant] = []
  private var pending: PendingEnrollment?
  private let lockDescriptor: Int32

  /// 业务作用：打开私有保险箱并独占该目录，避免多个进程同时更改凭据和媒体。
  /// 参数说明：
  /// - `directory`：App 私有存储位置。
  /// - `secrets`：本机随机秘密与认证退避的系统存储。
  /// 返回：目录可用且取得独占权的存储入口；不能独占或权限不符时失败。
  init(directory: URL, secrets: any DeviceSecretStore) throws {
    self.directory = directory
    self.mediaDirectory = directory.appendingPathComponent("media", isDirectory: true)
    self.secrets = secrets
    try VaultStorage.directory(directory)
    try VaultStorage.directory(mediaDirectory)
    let descriptor = Darwin.open(
      directory.appendingPathComponent("access.lock").path,
      O_RDWR | O_CREAT | O_NOFOLLOW | O_EXLOCK | O_NONBLOCK, 0o600)
    guard descriptor >= 0 else {
      throw VaultError.storage
    }
    // 打开句柄时已经取得非阻塞独占锁，只有持权实例可以清理本目录的未完成暂存。
    lockDescriptor = descriptor
    var ready = false
    defer {
      if !ready {
        Darwin.close(descriptor)
      }
    }
    for parent in [directory, mediaDirectory] {
      for file in try FileManager.default.contentsOfDirectory(
        at: parent, includingPropertiesForKeys: nil)
      where file.lastPathComponent.hasPrefix(".") && file.pathExtension == "partial"
        && UUID(uuidString: String(file.deletingPathExtension().lastPathComponent.dropFirst()))
          != nil
      {
        // 仅删除本格式创建的暂存，完整媒体和有效凭据头不参与启动清理。
        try FileManager.default.removeItem(at: file)
      }
    }
    var protected = directory
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try protected.setResourceValues(values)
    ready = true
  }

  /// 业务作用：关闭实例时撤销会话并释放本机目录独占权。
  /// 参数说明：无。
  /// 返回：不删除任何有效密文。
  deinit {
    lock()
    Darwin.close(lockDescriptor)
  }

  /// 业务作用：确定 App 的默认本地保险箱位置，使系统索引不直接索引私密目录。
  /// 参数说明：无。
  /// 返回：App 支持目录中的独立保险箱位置。
  static func defaultDirectory() throws -> URL {
    try FileManager.default.url(
      for: .applicationSupportDirectory, in: .userDomainMask,
      appropriateFor: nil, create: true
    ).appendingPathComponent("EncVault.noindex", isDirectory: true)
  }

  /// 业务作用：读取当前凭据方式供锁定界面选择输入控件，不读取媒体元数据。
  /// 参数说明：无。
  /// 返回：未设置时为空；有效时返回密码种类，损坏头部拒绝。
  func credentialKind() throws -> CredentialKind? {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    return try header()?.kind
  }

  /// 业务作用：在不解锁媒体的情况下读取持久化冻结限制，供输入门禁和倒计时使用。
  /// 参数说明：无。
  /// 返回：当前凭据的冻结状态；设备因子缺失或限制损坏时拒绝密码输入。
  func credentialStatus() throws -> CredentialLockoutStatus {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    guard let current = try header() else {
      throw VaultError.notConfigured
    }
    guard let saved = try secrets.read(account: current.deviceAccount), saved.secret.count == 32
    else {
      throw VaultError.keychain(errSecItemNotFound)
    }
    let state = try CredentialLockout.normalized(saved)
    if saved.freezeLevel == nil {
      // 旧限制先升级并落入 Keychain，重新启动不能反复回到旧的短时退避策略。
      try secrets.write(state, account: current.deviceAccount)
    }
    return try CredentialLockout.status(state, at: Date().timeIntervalSince1970)
  }

  /// 业务作用：复验媒体操作的能力确实属于当前保险箱，防止把另一保险箱的会话用于此目录。
  /// 参数说明：
  /// - `grant`：调用方当前持有的前台会话能力。
  /// 返回：保险箱身份相符且能力有效时成功；未设置、失权或身份不符时拒绝。
  func authorize(_ grant: VaultGrant) throws {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    // 能力必须同时属于当前保险箱且未被撤销，不能把其它目录或旧会话的能力用于媒体写入。
    guard let current = try header(), current.vaultID == grant.vaultID else {
      throw VaultError.locked
    }
    try grant.check()
  }

  /// 业务作用：目录保护或层级变更前撤销全部旧读取与编辑能力，再延续已验证的 App 会话。
  /// 参数说明：
  /// - `current`：本次策略变更所使用的有效会话。
  /// - `folders`：切换前必须仍然有效的目录授权。
  /// 返回：使用同一主密钥的新会话，所有目录权限清空；失权时不创建替代能力。
  func rotateSession(using current: VaultGrant, folders: [UUID: UUID] = [:]) throws -> VaultGrant {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    try authorize(current)
    grantsLock.lock()
    let transition: (VaultGrant, [VaultGrant])
    do {
      guard grants.contains(where: { $0 === current }) else {
        throw VaultError.locked
      }
      transition = try current.access(folders: folders) { root in
        let replacement = VaultGrant(root: root, vaultID: current.vaultID)
        let previous = grants
        // 在同一门禁内登记新能力；并发锁定要么先拒绝旧能力，要么能撤销已登记的新能力。
        grants = [replacement]
        return (replacement, previous)
      }
    } catch {
      grantsLock.unlock()
      throw error
    }
    grantsLock.unlock()
    // 先撤销旧能力再发布新目录策略，旧的未保护读取器不能越过后来设置的密码。
    for previous in transition.1 {
      previous.revoke()
    }
    return transition.0
  }

  /// 业务作用：有界读取并校验凭据头，拒绝未知格式和不受支持的派生预算。
  /// 参数说明：无。
  /// 返回：已有凭据头或未设置；读取失败不视为新保险箱。
  private func header() throws -> VaultHeader? {
    let url = directory.appendingPathComponent("vault.json")
    guard FileManager.default.fileExists(atPath: url.path) else {
      return nil
    }
    let file = try FileHandle(forReadingFrom: url)
    defer {
      try? file.close()
    }
    let data = try file.read(upToCount: 65_537) ?? Data()
    guard data.count <= 65_536,
      let result = try? JSONDecoder().decode(VaultHeader.self, from: data),
      result.formatVersion == 1, result.salt.count == 16,
      result.iterations >= VaultCrypto.rounds, result.iterations <= 3_000_000,
      UUID(uuidString: result.deviceAccount) != nil
    else {
      throw VaultError.corrupt
    }
    return result
  }

  /// 业务作用：为首次设置准备密码封装和一次性恢复码，确认前不发布有效凭据。
  /// 参数说明：
  /// - `credential`：已由用户重复确认的新密码。
  /// 返回：待确认的恢复材料；已有保险箱时拒绝。
  func prepareSetup(_ credential: VaultCredential) throws -> EnrollmentOffer {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    guard try header() == nil else {
      throw VaultError.alreadyConfigured
    }
    return try prepare(credential, root: VaultCrypto.random(32), vaultID: UUID(), previous: nil)
  }

  /// 业务作用：正常改密先验证旧密码，再为同一主密钥准备新密码与恢复码。
  /// 参数说明：
  /// - `old`：当前有效的独立密码。
  /// - `new`：用户重复确认的新独立密码。
  /// 返回：待确认的新恢复材料；旧密码失败时不改动当前封装。
  func prepareChange(old: VaultCredential, new: VaultCredential) throws -> EnrollmentOffer {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    guard let current = try header() else {
      throw VaultError.notConfigured
    }
    let root = try authenticate(old, header: current)
    return try prepare(new, root: root, vaultID: current.vaultID, previous: current.generation)
  }

  /// 业务作用：以高熵离线恢复码授权保留媒体的密码重设，不依赖设备密码或旧设备因子。
  /// 参数说明：
  /// - `code`：用户保存的离线恢复码。
  /// - `credential`：用户重复确认的新独立密码。
  /// 返回：待确认的新恢复材料；错误恢复码不改变已有数据。
  func prepareRecovery(code: String, credential: VaultCredential) throws -> EnrollmentOffer {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    guard let current = try header() else {
      throw VaultError.notConfigured
    }
    let key = VaultCrypto.key(try VaultCrypto.recoveryBytes(code), context: current.recoveryContext)
    guard
      let root = try? VaultCrypto.open(
        current.recoveryRoot, key: key, context: current.recoveryContext), root.count == 32
    else {
      throw VaultError.invalidRecovery
    }
    return try prepare(
      credential, root: root, vaultID: current.vaultID, previous: current.generation)
  }

  /// 业务作用：把当前主密钥封装到新的独立凭据和高熵恢复入口，二者均自检后才允许确认。
  /// 参数说明：
  /// - `credential`：新的凭据。
  /// - `root`：需要保留的主密钥。
  /// - `vaultID`：保险箱身份。
  /// - `previous`：确认时必须仍有效的旧凭据代次，首次设置为空。
  /// 返回：仅当前操作有效的恢复码确认票据。
  private func prepare(
    _ credential: VaultCredential, root: Data, vaultID: UUID, previous: UUID?
  ) throws -> EnrollmentOffer {
    let encoded = try credential.encoded()
    let generation = UUID()
    let account = UUID().uuidString
    let salt = try VaultCrypto.random(16)
    let secret = DeviceSecretState(secret: try VaultCrypto.random(32))
    let recovery = try VaultCrypto.random(16)
    let credentialContext = Data(
      "EncVault/credential/\(vaultID)/\(generation)/\(credential.kind.rawValue)".utf8)
    let recoveryContext = Data("EncVault/recovery/\(vaultID)/\(generation)".utf8)
    let credentialKey = try VaultCrypto.credentialKey(
      credential: encoded, salt: salt, device: secret.secret,
      iterations: VaultCrypto.rounds, context: credentialContext)
    let recoveryKey = VaultCrypto.key(recovery, context: recoveryContext)
    let header = VaultHeader(
      formatVersion: 1, vaultID: vaultID, generation: generation, kind: credential.kind,
      salt: salt, iterations: VaultCrypto.rounds, deviceAccount: account,
      credentialRoot: try VaultCrypto.seal(root, key: credentialKey, context: credentialContext),
      recoveryRoot: try VaultCrypto.seal(root, key: recoveryKey, context: recoveryContext))
    guard
      try VaultCrypto.open(header.credentialRoot, key: credentialKey, context: credentialContext)
        == root,
      try VaultCrypto.open(header.recoveryRoot, key: recoveryKey, context: recoveryContext) == root
    else {
      throw VaultError.corrupt
    }
    let offer = EnrollmentOffer(token: UUID(), recoveryCode: VaultCrypto.recoveryText(recovery))
    pending = PendingEnrollment(
      offer: offer, header: header, secret: secret, root: root, previousGeneration: previous)
    return offer
  }

  /// 业务作用：用户确认已保存恢复码后，先持久化设备因子再原子发布新凭据，最后撤销旧会话。
  /// 参数说明：
  /// - `token`：当前恢复码界面的确认票据。
  /// 返回：确认持久化后的新会话；票据过期或旧代次变化时拒绝，提交状态不确定时撤销会话并保留两套设备因子。
  func confirmEnrollment(_ token: UUID) throws -> VaultGrant {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    guard let proposal = pending, proposal.offer.token == token else {
      throw VaultError.invalidEnrollment
    }
    let current = try header()
    // 复验待替换的代次，旧界面不能覆盖后续已经生效的密码。
    guard current?.generation == proposal.previousGeneration else {
      throw VaultError.invalidEnrollment
    }
    try secrets.write(proposal.secret, account: proposal.header.deviceAccount)
    do {
      try VaultStorage.atomicWrite(
        VaultCrypto.encode(proposal.header), to: directory.appendingPathComponent("vault.json"))
    } catch {
      // 重命名成功但目录同步失败时，新头部可能已生效；保留两套因子，不能以删除新因子补偿。
      lock()
      pending = nil
      throw VaultError.credentialCommitUncertain
    }
    // 新会话交付前撤销旧会话，避免凭据切换完成后仍交付旧授权的明文。
    lock()
    pending = nil
    if let current {
      try? secrets.remove(account: current.deviceAccount)
    }
    return grant(root: proposal.root, vaultID: proposal.header.vaultID)
  }

  /// 业务作用：丢弃未确认的恢复码和待发布密钥，不影响当前有效保险箱。
  /// 参数说明：
  /// - `token`：仅取消匹配的设置；为空时丢弃当前未提交设置。
  /// 返回：待设置材料引用被释放。
  func cancelEnrollment(_ token: UUID? = nil) {
    transaction.lock()
    if token == nil || pending?.offer.token == token {
      pending = nil
    }
    transaction.unlock()
  }

  /// 业务作用：验证独立密码并建立前台会话，不保存成功访问事件。
  /// 参数说明：
  /// - `credential`：用户本次输入的独立密码。
  /// 返回：已验证的会话能力；错误、退避或存储不可用时保持锁定。
  func unlock(_ credential: VaultCredential) throws -> VaultGrant {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    guard let current = try header() else {
      throw VaultError.notConfigured
    }
    return grant(root: try authenticate(credential, header: current), vaultID: current.vaultID)
  }

  /// 业务作用：为降低保护强度的设置重新验证 App 凭据，不发放额外读取能力。
  /// 参数说明：
  /// - `credential`：本次重新输入的保险箱密码或手势，沿用错误冻结规则。
  /// - `current`：发起设置变更的当前会话，验证期间失权时不得继续。
  /// 返回：凭据正确且原会话仍有效时成功；失败不更改设置、不新增会话。
  func verifyCredential(_ credential: VaultCredential, using current: VaultGrant) throws {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    try authorize(current)
    guard let header = try header() else {
      throw VaultError.notConfigured
    }
    _ = try authenticate(credential, header: header)
    // 认证不能恢复已经撤销的会话，切换或主动锁定后的迟到结果必须拒绝。
    try authorize(current)
    try Task.checkCancellation()
  }

  /// 业务作用：提前记账认证尝试，每三次失败递增冻结，阻止关闭应用绕过限制。
  /// 参数说明：
  /// - `credential`：本次独立凭据。
  /// - `header`：当前有效凭据头。
  /// 返回：认证成功的主密钥；失败或不能持久化限制时不授权。
  private func authenticate(_ credential: VaultCredential, header: VaultHeader) throws -> Data {
    let encoded = try credential.encoded()
    guard let saved = try secrets.read(account: header.deviceAccount), saved.secret.count == 32
    else {
      throw VaultError.keychain(errSecItemNotFound)
    }
    let now = Date().timeIntervalSince1970
    let state = try CredentialLockout.recordingAttempt(saved, at: now)
    // 在计算和认证之前持久化尝试，崩溃或取消不能把一次错误尝试抹掉。
    try secrets.write(state, account: header.deviceAccount)
    do {
      let key = try VaultCrypto.credentialKey(
        credential: encoded, salt: header.salt, device: state.secret,
        iterations: header.iterations, context: header.credentialContext)
      guard credential.kind == header.kind,
        let root = try? VaultCrypto.open(
          header.credentialRoot, key: key, context: header.credentialContext),
        root.count == 32
      else {
        throw VaultError.incorrectCredential
      }
      try secrets.write(DeviceSecretState(secret: state.secret), account: header.deviceAccount)
      return root
    } catch {
      if state.retryAfter > now {
        // 第三次失败或认证未完成时撤销旧授权；不能靠旧会话或未确认改密材料越过冻结。
        lock()
        pending = nil
        if case VaultError.incorrectCredential = error {
          throw VaultError.wait(Int(ceil(state.retryAfter - now)))
        }
      }
      throw error
    }
  }

  /// 业务作用：登记当前有效能力，供锁定和凭据更改统一撤销。
  /// 参数说明：
  /// - `root`：已认证的主密钥。
  /// - `vaultID`：所属保险箱。
  /// 返回：登记后的前台会话能力。
  private func grant(root: Data, vaultID: UUID) -> VaultGrant {
    let result = VaultGrant(root: root, vaultID: vaultID)
    grantsLock.lock()
    grants.append(result)
    grantsLock.unlock()
    return result
  }

  /// 业务作用：不等待文件事务即可撤销所有已发出的明文能力。
  /// 参数说明：无。
  /// 返回：正在同步交付的步骤结束后，旧能力不能继续读取或交付明文。
  func lock() {
    grantsLock.lock()
    let current = grants
    grants.removeAll()
    grantsLock.unlock()
    for grant in current {
      grant.revoke()
    }
  }

  /// 业务作用：用户明确选择不可恢复地清空时，仅移除当前保险箱的密文和凭据。
  /// 参数说明：无。
  /// 返回：成功后回到首次设置；失败可能需要重试，不处理任何来源原件。
  func erase() throws {
    transaction.lock()
    defer {
      transaction.unlock()
    }
    // 先撤销读取能力，再进行用户已确认的不可恢复删除。
    lock()
    pending = nil
    let current = try? header()
    try FileManager.default.removeItem(at: mediaDirectory)
    try VaultStorage.directory(mediaDirectory)
    let headerURL = directory.appendingPathComponent("vault.json")
    if FileManager.default.fileExists(atPath: headerURL.path) {
      try FileManager.default.removeItem(at: headerURL)
    }
    try VaultStorage.synchronizeDirectory(directory)
    if let current {
      try? secrets.remove(account: current.deviceAccount)
    }
  }
}
