#import "VaultStreamMedia.h"
#import <objc/runtime.h>
#include <limits.h>

// libVLC 公开回调 ABI 的 version 0 布局；依赖固定到工程声明的源码提交。
typedef struct libvlc_media_t libvlc_media_t;
struct libvlc_media_open_cbs {
    uint32_t version;
    int (*open)(void *, void **, uint64_t *);
    ptrdiff_t (*read)(void *, unsigned char *, size_t);
    int (*seek)(void *, uint64_t);
    void (*close)(void *);
};
extern libvlc_media_t *libvlc_media_new_callbacks(const struct libvlc_media_open_cbs *, void *);
extern void libvlc_media_release(libvlc_media_t *);

// 描述符包装沿用固定 VLCKit 提交中的桥接签名，不涉及平台私有接口。
@interface VLCMedia (VaultDescriptor)
- (nullable instancetype)initWithLibVLCMediaDescriptor:(void *)descriptor;
@end

@interface VaultInputOwner : NSObject {
    NSLock *_mutex;
    BOOL _active;
    VaultInputFactory _factory;
    NSMutableSet<NSInputStream *> *_inputs;
}
@property(nonatomic, readonly) uint64_t byteCount;
- (instancetype)initWithByteCount:(uint64_t)byteCount factory:(VaultInputFactory)factory;
- (nullable NSInputStream *)openInput;
- (void)closeInput:(NSInputStream *)input;
- (void)revoke;
@end

@implementation VaultInputOwner
/**
 * 业务作用：建立单个媒体的输入权威，长度只来自认证元数据。
 * 参数说明：
 * - byteCount：媒体原始字节数。
 * - factory：只创建当前会话本地输入的工厂。
 * 返回：尚无活动输入的媒体权威。
 */
- (instancetype)initWithByteCount:(uint64_t)byteCount factory:(VaultInputFactory)factory {
    self = [super init];
    if (self) {
        _byteCount = byteCount;
        _factory = [factory copy];
        _mutex = [NSLock new];
        _inputs = [NSMutableSet new];
        _active = YES;
    }
    return self;
}

/**
 * 业务作用：每次解析或播放独立打开流，避免复用已到末尾或关闭的输入。
 * 参数说明：无。
 * 返回：已经打开的独立输入；撤销、会话失效或工厂失败时为空。
 */
- (NSInputStream *)openInput {
    [_mutex lock];
    // 关闭查看后不得再创建输入；工厂和活动输入集合受同一权威门禁保护。
    if (!_active) {
        [_mutex unlock];
        return nil;
    }
    NSInputStream *input = _factory();
    if (input) {
        [_inputs addObject:input];
    }
    [_mutex unlock];
    [input open];
    if (input.streamStatus != NSStreamStatusOpen) {
        if (input) {
            [self closeInput:input];
        }
        return nil;
    }
    return input;
}

/**
 * 业务作用：结束解码器归还的单次输入，不影响同一媒体其它独立读取实例。
 * 参数说明：
 * - input：本次已经结束的输入。
 * 返回：流关闭且从活动集合中移除。
 */
- (void)closeInput:(NSInputStream *)input {
    [input close];
    [_mutex lock];
    [_inputs removeObject:input];
    [_mutex unlock];
}

/**
 * 业务作用：先拒绝新输入，再同步关闭已有输入，迟到的解码动作不再获得字节。
 * 参数说明：无。
 * 返回：所有输入已关闭，工厂捕获的会话引用已撤下。
 */
- (void)revoke {
    [_mutex lock];
    _active = NO;
    _factory = nil;
    NSArray<NSInputStream *> *inputs = _inputs.allObjects;
    [_inputs removeAllObjects];
    [_mutex unlock];
    // 关闭可能等待单次有界读取，不能持有集合锁等待解码线程归还输入。
    for (NSInputStream *input in inputs) {
        [input close];
    }
}
@end

@interface VaultOpenedInput : NSObject
@property(nonatomic, strong) VaultInputOwner *owner;
@property(nonatomic, strong) NSInputStream *input;
@end
@implementation VaultOpenedInput
@end

/**
 * 业务作用：为一次 libVLC 打开分配独立上下文，并声明准确长度以支持容器解析和定位。
 * 参数说明：
 * - opaque：媒体输入权威。
 * - data：接收本次读取上下文的位置。
 * - size：接收认证文件长度的位置。
 * 返回：成功为零；撤销或无法打开时失败且不交付上下文。
 */
static int VaultOpen(void *opaque, void **data, uint64_t *size) {
    @autoreleasepool {
        VaultInputOwner *owner = (__bridge VaultInputOwner *)opaque;
        NSInputStream *input = [owner openInput];
        if (!input) {
            return -1;
        }
        VaultOpenedInput *opened = [VaultOpenedInput new];
        opened.owner = owner;
        opened.input = input;
        // 上下文独立保留到 close 回调，异步停止不能提前释放回调仍在使用的对象。
        *data = (__bridge_retained void *)opened;
        *size = owner.byteCount;
        return 0;
    }
}

/**
 * 业务作用：只通过当前独立输入交付有界认证明文，不暴露底层密文或来源路径。
 * 参数说明：
 * - data：本次打开独占的上下文。
 * - buffer：解码器提供的接收内存。
 * - length：接收内存的容量。
 * 返回：读取字节数、末尾的零或关闭和失权后的负值。
 */
static ptrdiff_t VaultRead(void *data, unsigned char *buffer, size_t length) {
    // 解码线程由 C 库创建；每次读取都及时归还 Foundation 的临时对象，不能累积到整段视频结束。
    @autoreleasepool {
        if (length == 0) {
            return 0;
        }
        if (!buffer) {
            return -1;
        }
        VaultOpenedInput *opened = (__bridge VaultOpenedInput *)data;
        return [opened.input read:buffer maxLength:MIN(length, (size_t)INT_MAX)];
    }
}

/**
 * 业务作用：把容器的绝对字节定位交给受会话和文件边界约束的输入流。
 * 参数说明：
 * - data：本次打开独占的上下文。
 * - offset：需要定位的原始文件偏移。
 * 返回：有效定位为零；越界、关闭或失权时失败。
 */
static int VaultSeek(void *data, uint64_t offset) {
    @autoreleasepool {
        VaultOpenedInput *opened = (__bridge VaultOpenedInput *)data;
        return [opened.input setProperty:@(offset) forKey:NSStreamFileCurrentOffsetKey] ? 0 : -1;
    }
}

/**
 * 业务作用：归还一次读取并释放其独立所有权，允许媒体后续从头建立新的输入。
 * 参数说明：
 * - data：本次打开所保留的上下文，只能归还一次。
 * 返回：输入关闭且上下文释放，不保留播放位置。
 */
static void VaultClose(void *data) {
    @autoreleasepool {
        VaultOpenedInput *opened = (__bridge_transfer VaultOpenedInput *)data;
        [opened.owner closeInput:opened.input];
    }
}

static const struct libvlc_media_open_cbs VaultCallbacks = {
    .version = 0,
    .open = VaultOpen,
    .read = VaultRead,
    .seek = VaultSeek,
    .close = VaultClose,
};
static char VaultOwnerKey;

VLCMedia *VaultCreateStreamMedia(uint64_t byteCount, VaultInputFactory factory) {
    if (!factory) {
        return nil;
    }
    VaultInputOwner *owner = [[VaultInputOwner alloc] initWithByteCount:byteCount
                                                           factory:factory];
    libvlc_media_t *descriptor = libvlc_media_new_callbacks(&VaultCallbacks, (__bridge void *)owner);
    if (!descriptor) {
        return nil;
    }
    VLCMedia *media = [[VLCMedia alloc] initWithLibVLCMediaDescriptor:descriptor];
    libvlc_media_release(descriptor);
    if (!media) {
        return nil;
    }
    objc_setAssociatedObject(media, &VaultOwnerKey, owner, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return media;
}

void VaultRevokeStreamMedia(VLCMedia *media) {
    VaultInputOwner *owner = objc_getAssociatedObject(media, &VaultOwnerKey);
    [owner revoke];
}
