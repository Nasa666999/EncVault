#include <cstdio>
#include <memory>
#include <sys/resource.h>

#include <libetonyek/libetonyek.h>
#include <librevenge-generators/librevenge-generators.h>
#include <librevenge-stream/librevenge-stream.h>

/// 业务作用：限制文档解析时长与落盘能力，禁止明文核心转储和文件写入。
/// 参数说明：
/// - resource：本次子进程需要收紧的系统资源。
/// - amount：允许的硬上限与软上限。
/// 返回：限制成功时为真；不能建立边界时拒绝开始解析。
static bool constrain(int resource, rlim_t amount) {
    const rlimit limit = {
        amount,
        amount,
    };
    return setrlimit(resource, &limit) == 0;
}

/// 业务作用：将当前原名 Pages 文件或完整文件包转换为内存正文，只向受控管道交付。
/// 参数说明：
/// - argc：必须只提供一个文档路径。
/// - argv：由保险箱提供的绝对路径，不接受目录外的索引片段作为入口。
/// 返回：完整正文交付成功时为零；资源、格式或解析失败时非零，不记录正文或来源路径。
int main(int argc, char *argv[]) {
    if (argc != 2 || !constrain(RLIMIT_CORE, 0) || !constrain(RLIMIT_FSIZE, 0)
        || !constrain(RLIMIT_CPU, 10)) {
        return 1;
    }
    try {
        std::unique_ptr<librevenge::RVNGInputStream> input;
        if (librevenge::RVNGDirectoryStream::isDirectory(argv[1])) {
            input = std::make_unique<librevenge::RVNGDirectoryStream>(argv[1]);
        } else {
            input = std::make_unique<librevenge::RVNGFileStream>(argv[1]);
        }
        auto type = libetonyek::EtonyekDocument::TYPE_UNKNOWN;
        const auto confidence = libetonyek::EtonyekDocument::isSupported(input.get(), &type);
        // 只解析本次完整文件或文件包，不按片段向父目录搜索其它文档材料。
        if (confidence != libetonyek::EtonyekDocument::CONFIDENCE_EXCELLENT
            || type != libetonyek::EtonyekDocument::TYPE_PAGES) {
            return 2;
        }
        librevenge::RVNGString output;
        librevenge::RVNGHTMLTextGenerator generator(output);
        if (!libetonyek::EtonyekDocument::parse(input.get(), &generator) || output.empty()) {
            return 3;
        }
        return std::fputs(output.cstr(), stdout) < 0 ? 4 : 0;
    } catch (...) {
        return 5;
    }
}
