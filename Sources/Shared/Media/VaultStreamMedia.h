#import <Foundation/Foundation.h>
#import <VLCKit/VLCKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef NSInputStream *_Nullable (^VaultInputFactory)(void) NS_SWIFT_SENDABLE;

/**
 * 业务作用：通过 libVLC 的本地回调输入创建媒体，每次打开使用独立读取器并提供准确长度。
 * 参数说明：
 * - byteCount：已认证文件的原始字节数。
 * - factory：可在解码线程调用的输入工厂，不提供文件路径或网络 URL。
 * 返回：只依赖本地输入的媒体；无法建立描述符时为空。
 */
FOUNDATION_EXPORT VLCMedia *_Nullable VaultCreateStreamMedia(uint64_t byteCount, VaultInputFactory factory);

/**
 * 业务作用：关闭本次媒体的全部输入并拒绝新的打开请求，阻止关闭查看后的迟到读取。
 * 参数说明：
 * - media：本适配器创建的媒体。
 * 返回：输入均已关闭，后续读取失败；解码器仍须正常停止以完成内部资源释放。
 */
FOUNDATION_EXPORT void VaultRevokeStreamMedia(VLCMedia *media);

NS_ASSUME_NONNULL_END
