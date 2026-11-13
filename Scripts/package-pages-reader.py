#!/usr/bin/env python3
"""将本机架构的离线 Pages 解析器及动态依赖装入 Mac 应用。"""

from pathlib import Path
import os
import plistlib
import shutil
import subprocess
import sys


def run(*arguments):
    """业务作用：用独立参数执行构建工具，避免路径被解释为 shell 命令。
    参数说明：
    - arguments：构建工具及其参数。
    返回：成功时返回标准输出，失败时中止打包。
    """
    return subprocess.check_output(arguments, text=True).strip()


def dependencies(binary):
    """业务作用：枚举 Mach-O 的动态依赖，保留系统框架并收集需随应用分发的库。
    参数说明：
    - binary：待检查的可执行文件或动态库。
    返回：非系统动态库的原始安装路径。
    """
    paths = []
    for line in run("otool", "-L", str(binary)).splitlines()[1:]:
        name = line.strip().split(" (", 1)[0]
        if name.startswith("/opt/homebrew/") or name.startswith("/usr/local/"):
            paths.append(name)
    return paths


def package(app, identity):
    """业务作用：构建自包含的 Pages 解析器，运行时无需 Homebrew 或网络下载。
    参数说明：
    - app：本次构建的 Mac 应用包。
    - identity：与宿主匹配的代码签名身份，临时本机签名使用减号。
    返回：解析器与全部非系统依赖复制、重定位并签名完成；依赖不完整时拒绝打包。
    """
    project = Path(__file__).resolve().parent.parent
    app = app.resolve()
    if app.suffix != ".app" or not (app / "Contents").is_dir():
        raise RuntimeError("需要已经建立的 Mac 应用包")
    brew = shutil.which("brew")
    if brew is None:
        brew = "/opt/homebrew/bin/brew" if Path("/opt/homebrew/bin/brew").is_file() else "/usr/local/bin/brew"
    prefix = Path(run(brew, "--prefix", "libetonyek"))
    revenge = Path(run(brew, "--prefix", "librevenge"))
    if run(str(prefix / "bin/pages2html"), "--version").split()[-1] != "0.1.13":
        raise RuntimeError("需要 libetonyek 0.1.13")
    original = prefix / "bin/pages2html"
    libraries = {}
    pending = [original]
    seen = set()
    while pending:
        binary = pending.pop()
        canonical = binary.resolve()
        if canonical in seen:
            continue
        seen.add(canonical)
        for dependency in dependencies(binary):
            source = Path(dependency).resolve()
            if source == canonical:
                continue
            if source.name in libraries and libraries[source.name] != source:
                raise RuntimeError("动态库名称冲突")
            libraries[source.name] = source
            pending.append(source)
    destination = app / "Contents/Frameworks/PagesParsing"
    destination.mkdir(parents=True, exist_ok=True)
    helpers = app / "Contents/Helpers"
    helpers.mkdir(exist_ok=True)
    executable = helpers / "PagesReader"
    run(
        "clang++", "-std=c++17", "-O2", "-mmacosx-version-min=26.0",
        "-I" + str(prefix / "include/libetonyek-0.1"),
        "-I" + str(revenge / "include/librevenge-0.0"),
        str(project / "Sources/Helpers/PagesReader.cpp"),
        "-L" + str(prefix / "lib"), "-L" + str(revenge / "lib"),
        "-letonyek-0.1", "-lrevenge-generators-0.0", "-lrevenge-stream-0.0", "-lrevenge-0.0",
        "-o", str(executable),
    )
    os.chmod(executable, 0o755)
    for name, source in libraries.items():
        shutil.copy2(source, destination / name)
        os.chmod(destination / name, 0o755)
    for binary in [executable] + [destination / name for name in libraries]:
        for dependency in dependencies(binary):
            source = Path(dependency).resolve()
            if source.name not in libraries:
                continue
            replacement = (
                "@executable_path/../Frameworks/PagesParsing/" + source.name
                if binary == executable
                else "@loader_path/" + source.name
            )
            run("install_name_tool", "-change", dependency, replacement, str(binary))
        if binary != executable:
            run("install_name_tool", "-id", "@rpath/PagesParsing/" + binary.name, str(binary))
            run("codesign", "--force", "--sign", identity, "--options", "runtime", str(binary))
    entitlements = project / "Resources/PagesReader.entitlements"
    local_entitlements = app.parent / "PagesReaderLocalSigning.plist"
    if identity == "-":
        values = plistlib.loads(entitlements.read_bytes())
        values["com.apple.security.cs.disable-library-validation"] = True
        local_entitlements.write_bytes(plistlib.dumps(values))
        entitlements = local_entitlements
    try:
        run(
            "codesign", "--force", "--sign", identity, "--options", "runtime",
            "--entitlements", str(entitlements), str(executable),
        )
    finally:
        if identity == "-":
            local_entitlements.unlink()
    print("已打包离线 Pages 解析器及其动态依赖")


if __name__ == "__main__":
    package(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else "-")
