import Foundation
import LocalAuthentication
import Security

/// 只通过系统 Keychain 持久化随机因子和认证失败状态，不存放媒体访问记录。
struct KeychainSecrets: DeviceSecretStore {
  let service: String

  /// 业务作用：构造限定应用服务与账户的秘密查找条件，禁止系统验证界面作为保险箱入口。
  /// 参数说明：
  /// - `account`：凭据代次标识。
  /// 返回：不包含用户密码或生物识别策略的查询。
  private func query(_ account: String) -> [String: Any] {
    // 这个上下文只禁止系统认证交互，不评估生物识别或设备密码；独立密码仍由保险箱验证。
    let context = LAContext()
    context.interactionNotAllowed = true
    return [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrSynchronizable as String: false,
      kSecUseAuthenticationContext as String: context,
    ]
  }

  /// 业务作用：取得当前代次的本机秘密，系统不可访问时保持保险箱关闭。
  /// 参数说明：
  /// - `account`：凭据代次标识。
  /// 返回：已解码的秘密，缺失时为空；系统失败或格式不符时拒绝。
  func read(account: String) throws -> DeviceSecretState? {
    var request = query(account)
    request[kSecReturnData as String] = true
    request[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(request as CFDictionary, &result)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess, let data = result as? Data else {
      throw VaultError.keychain(status)
    }
    return try JSONDecoder().decode(DeviceSecretState.self, from: data)
  }

  /// 业务作用：保存随机秘密或提前记账的失败次数，不启用系统密码和生物识别认证。
  /// 参数说明：
  /// - `state`：需要持久化的本机秘密与退避状态。
  /// - `account`：凭据代次标识。
  /// 返回：Keychain 确认更新或创建后成功；错误时停止后续授权。
  func write(_ state: DeviceSecretState, account: String) throws {
    let data = try VaultCrypto.encode(state)
    let status = SecItemUpdate(
      query(account) as CFDictionary, [kSecValueData as String: data] as CFDictionary
    )
    if status == errSecSuccess {
      return
    }
    guard status == errSecItemNotFound else {
      throw VaultError.keychain(status)
    }
    var request = query(account)
    request[kSecValueData as String] = data
    #if os(iOS)
      request[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    #endif
    let added = SecItemAdd(request as CFDictionary, nil)
    guard added == errSecSuccess else {
      throw VaultError.keychain(added)
    }
  }

  /// 业务作用：移除失效凭据代次的本机秘密，不改变当前有效代次。
  /// 参数说明：
  /// - `account`：已失效的账户。
  /// 返回：已删除或不存在时成功；系统拒绝时失败。
  func remove(account: String) throws {
    let status = SecItemDelete(query(account) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw VaultError.keychain(status)
    }
  }
}
