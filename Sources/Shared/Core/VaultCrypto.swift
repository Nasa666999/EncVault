import CommonCrypto
import CryptoKit
import Foundation
import Security

/// 通过系统加密原语完成密钥生成、派生和认证封装。
enum VaultCrypto {
  static let rounds = 600_000

  /// 业务作用：检查独立文本密码的工作量与有效内容，不沿用 App 数字或手势密码。
  /// 参数说明：
  /// - `password`：当前输入的目录独立文本密码，保持原字符不自动裁剪。
  /// 返回：带独立用途前缀的内存字节；空白或超限时拒绝，不写入磁盘。
  private static func folderPasswordBytes(_ password: String) throws -> Data {
    guard (6...128).contains(password.count), password.utf8.count <= 512,
      !password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    else {
      throw VaultError.invalidFolderPassword
    }
    return Data(("folder-password:" + password).utf8)
  }

  /// 业务作用：用随机盐和慢速派生建立目录独立校验，原始密码不进入持久化结构。
  /// 参数说明：
  /// - `password`：两次确认一致的目录文本密码。
  /// - `folderID`：校验材料绑定的目录身份。
  /// - `grant`：当前已解锁的保险箱会话。
  /// 返回：仅包含随机身份、派生参数和认证密文的材料，后续还须放入加密目录元数据。
  static func folderPassword(_ password: String, folderID: UUID, using grant: VaultGrant) throws
    -> FolderPassword
  {
    let bytes = try folderPasswordBytes(password)
    let revision = UUID()
    let salt = try random(16)
    let context = Data("EncVault/folder/\(grant.vaultID)/\(folderID)/\(revision)".utf8)
    let factor = try grant.access { root in
      root
    }
    let key = try credentialKey(
      credential: bytes, salt: salt, device: factor, iterations: rounds, context: context)
    try Task.checkCancellation()
    try grant.check()
    return FolderPassword(
      revision: revision, salt: salt, iterations: rounds,
      verification: try seal(Data("directory-access".utf8), key: key, context: context))
  }

  /// 业务作用：验证目录密码对应的认证封套，不与 App 密码或手势进行比较。
  /// 参数说明：
  /// - `password`：用户当前输入的目录密码。
  /// - `protection`：从认证加密元数据读取的校验材料。
  /// - `folderID`：当前请求访问的目录身份。
  /// - `grant`：仍有效的保险箱会话。
  /// 返回：密码和绑定身份均正确时成功；认证拒绝、材料损坏与系统加密失败分别呈现，均不开放目录。
  static func verifyFolderPassword(
    _ password: String, protection: FolderPassword, folderID: UUID, using grant: VaultGrant
  ) throws {
    let bytes = try folderPasswordBytes(password)
    let context = Data("EncVault/folder/\(grant.vaultID)/\(folderID)/\(protection.revision)".utf8)
    let factor = try grant.access { root in
      root
    }
    let key = try credentialKey(
      credential: bytes, salt: protection.salt, device: factor,
      iterations: protection.iterations, context: context)
    try Task.checkCancellation()
    try grant.check()
    let result: Data
    do {
      result = try open(protection.verification, key: key, context: context)
    } catch CryptoKitError.authenticationFailure {
      throw VaultError.incorrectFolderPassword
    } catch CryptoKitError.incorrectParameterSize, CryptoKitError.incorrectKeySize,
      CryptoKitError.invalidParameter
    {
      throw VaultError.corrupt
    } catch {
      // 系统不能完成加密运算不代表密码错误，不能吞掉原因后误导用户重复改密。
      throw VaultError.folderVerificationUnavailable
    }
    guard result == Data("directory-access".utf8) else {
      throw VaultError.corrupt
    }
  }

  /// 业务作用：取得系统安全随机数，供盐、密钥、nonce 和恢复码使用。
  /// 参数说明：
  /// - `count`：需要的字节数。
  /// 返回：完整随机字节；系统随机源失败时拒绝继续。
  static func random(_ count: Int) throws -> Data {
    var data = Data(count: count)
    let status = data.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
    }
    guard status == errSecSuccess else {
      throw VaultError.storage
    }
    return data
  }

  /// 业务作用：把独立密码与本机随机因子组合为凭据封装密钥，避免仅凭短密码复制密文后离线尝试。
  /// 参数说明：
  /// - `credential`：已通过输入规则校验的密码编码。
  /// - `salt`：保险箱当前凭据代次的随机盐。
  /// - `device`：只保存在本机 Keychain 的随机因子。
  /// - `iterations`：受限的慢速派生工作因子。
  /// - `context`：绑定保险箱和凭据代次的用途标识。
  /// 返回：256 位封装密钥；非法参数或系统派生失败时拒绝。
  static func credentialKey(
    credential: Data, salt: Data, device: Data, iterations: Int, context: Data
  ) throws -> SymmetricKey {
    guard salt.count == 16, device.count == 32,
      iterations >= rounds, iterations <= 3_000_000
    else {
      throw VaultError.corrupt
    }
    var derived = Data(count: 32)
    let status = derived.withUnsafeMutableBytes { output in
      credential.withUnsafeBytes { password in
        salt.withUnsafeBytes { saltBytes in
          CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            password.baseAddress!.assumingMemoryBound(to: Int8.self), credential.count,
            saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
            output.baseAddress!.assumingMemoryBound(to: UInt8.self), 32
          )
        }
      }
    }
    guard status == kCCSuccess else {
      throw VaultError.storage
    }
    return HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: device), salt: derived, info: context,
      outputByteCount: 32
    )
  }

  /// 业务作用：从高熵材料派生单一用途的密钥，隔离媒体、元数据和恢复入口。
  /// 参数说明：
  /// - `material`：随机密钥材料。
  /// - `context`：绑定对象身份和用途的字节。
  /// 返回：256 位用途密钥。
  static func key(_ material: Data, context: Data) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: material), salt: Data(), info: context,
      outputByteCount: 32
    )
  }

  /// 业务作用：认证加密密钥封装或敏感元数据，绑定调用方指定的对象身份。
  /// 参数说明：
  /// - `data`：待保护的材料。
  /// - `key`：该用途的密钥。
  /// - `context`：必须同时认证的身份与用途。
  /// 返回：包含随机 nonce 和认证标签的密文；加密失败时不返回部分材料。
  static func seal(_ data: Data, key: SymmetricKey, context: Data) throws -> Data {
    guard let combined = try AES.GCM.seal(data, using: key, authenticating: context).combined else {
      throw VaultError.storage
    }
    return combined
  }

  /// 业务作用：只有密钥与关联身份都通过认证时才交付封装中的明文。
  /// 参数说明：
  /// - `data`：完整的认证密文。
  /// - `key`：该用途的密钥。
  /// - `context`：当前预期的身份和用途。
  /// 返回：认证成功的明文；错误密钥、损坏或身份不符均失败。
  static func open(_ data: Data, key: SymmetricKey, context: Data) throws -> Data {
    try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: key, authenticating: context)
  }

  /// 业务作用：产生稳定的结构编码，用于头部认证和原子持久化。
  /// 参数说明：
  /// - `value`：要编码的业务结构。
  /// 返回：按键排序的 JSON；不可编码时失败。
  static func encode<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(value)
  }

  /// 业务作用：生成可人工保存的高熵离线恢复码。
  /// 参数说明：
  /// - `data`：16 字节的随机恢复材料。
  /// 返回：分组十六进制恢复码，不记录或复制到剪贴板。
  static func recoveryText(_ data: Data) -> String {
    let text = data.map {
      String(format: "%02X", $0)
    }.joined()
    return stride(from: 0, to: text.count, by: 4).map { offset in
      let start = text.index(text.startIndex, offsetBy: offset)
      return String(text[start..<text.index(start, offsetBy: 4)])
    }.joined(separator: "-")
  }

  /// 业务作用：读取用户手动输入的离线恢复材料，不接受截断或非十六进制字符。
  /// 参数说明：
  /// - `text`：允许分组连字符和空白的恢复码。
  /// 返回：完整 128 位材料；格式不符时拒绝。
  static func recoveryBytes(_ text: String) throws -> Data {
    let compact = text.filter {
      !$0.isWhitespace && $0 != "-"
    }
    guard compact.utf8.count == 32,
      compact.utf8.allSatisfy({
        (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
      })
    else {
      throw VaultError.invalidRecovery
    }
    var result = Data()
    var index = compact.startIndex
    while index < compact.endIndex {
      let end = compact.index(index, offsetBy: 2)
      guard let byte = UInt8(compact[index..<end], radix: 16) else {
        throw VaultError.invalidRecovery
      }
      result.append(byte)
      index = end
    }
    return result
  }
}
