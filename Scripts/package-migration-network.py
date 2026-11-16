#!/usr/bin/env python3
"""将独立网络沙箱服务装入 Mac 应用，主应用不增加网络权限。"""

from pathlib import Path
import os
import plistlib
import subprocess
import sys


def package(app, identity):
    """业务作用: 将独立迁移网络服务嵌入应用，并以受限网络权限签名。

    参数说明:
    - app: 接收网络服务的 macOS 应用包路径。
    - identity: 与主应用保持一致的签名身份，空值使用临时签名。
    返回: 成功后服务已写入应用包并签名；编译或签名失败时终止打包。
    """
    """业务作用：构建并签名只承载迁移密文的独立 XPC 服务。
    参数说明：
    - app：已建立的 Mac 应用包。
    - identity：与宿主一致的签名身份。
    返回：服务先于外层应用签名完成，构建失败时拒绝归档。
    """
    project = Path(__file__).resolve().parent.parent
    destination = app.resolve() / "Contents/XPCServices/VaultMigrationNetwork.xpc/Contents"
    destination.mkdir(parents=True, exist_ok=True)
    executable = destination / "MacOS/VaultMigrationNetwork"
    executable.parent.mkdir(exist_ok=True)
    plist = {
        "CFBundleIdentifier": "local.encvault.migration.networkservice",
        "CFBundleName": "VaultMigrationNetwork",
        "CFBundleExecutable": "VaultMigrationNetwork",
        "CFBundlePackageType": "XPC!",
        "CFBundleVersion": "1",
        "CFBundleShortVersionString": "1.0",
        "LSMinimumSystemVersion": "14.0",
        "EncVaultHostExecutable": plistlib.loads((app / "Contents/Info.plist").read_bytes())["CFBundleExecutable"] if (app / "Contents/Info.plist").exists() else os.environ.get("EXECUTABLE_NAME", "EncVault"),
        "NSLocalNetworkUsageDescription": "仅在主动迁移时发现并连接另一台 EncVault，传输加密内容。",
        "NSBonjourServices": ["_encvault._tcp"],
        "XPCService": {"ServiceType": "Application"},
    }
    (destination / "Info.plist").write_bytes(plistlib.dumps(plist))
    subprocess.run([
        "xcrun", "swiftc", "-O", "-swift-version", "5",
        "-target", os.uname().machine + "-apple-macos14.0",
        str(project / "Sources/Shared/Media/VaultMigrationRPC.swift"),
        str(project / "Sources/Helpers/MigrationNetworkService.swift"),
        "-o", str(executable),
    ], check=True)
    subprocess.run([
        "codesign", "--force", "--sign", identity or "-", "--options", "runtime",
        "--entitlements", str(project / "Resources/MigrationNetwork.entitlements"),
        str(destination.parent),
    ], check=True)


if __name__ == "__main__":
    package(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else "-")
