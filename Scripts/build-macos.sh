#!/bin/bash
set -euo pipefail

# 使用同一多平台工程嵌入离线解码依赖；正式分发仍需要稳定的开发者签名。
cd "$(dirname "$0")/.."
output="${1:-build}"
bundle_id="${2:-local.encvault.macos}"
package_directory="${3:-build/Dependencies}"
if [[ ! "$bundle_id" =~ ^[A-Za-z0-9][A-Za-z0-9.-]+$ ]]; then
  exit 2
fi
mkdir -p "$output/BuildResults" "$package_directory"
output="$(cd "$output" && pwd)"
local_entitlements="$output/LocalSigning.plist"
cp Resources/EncVault-macOS.entitlements "$local_entitlements"
# 临时本机签名没有可匹配的团队身份；只在此构建允许加载兼容框架，正式签名沿用工程策略。
/usr/libexec/PlistBuddy -c 'Add :com.apple.security.cs.disable-library-validation bool true' "$local_entitlements"
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
"$DEVELOPER_DIR/usr/bin/xcodebuild" -quiet \
  -project EncVault.xcodeproj -scheme EncVault-macOS -configuration Release \
  -destination "platform=macOS,arch=$(uname -m)" \
  -derivedDataPath "$output/DerivedData" \
  -clonedSourcePackagesDirPath "$package_directory" \
  -resultBundlePath "$output/BuildResults/$(uuidgen).xcresult" \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= \
  CODE_SIGN_ENTITLEMENTS="$local_entitlements" \
  PRODUCT_BUNDLE_IDENTIFIER="$bundle_id" build
ditto "$output/DerivedData/Build/Products/Release/EncVault.app" "$output/EncVault.app"
codesign --verify --deep --strict "$output/EncVault.app"
printf '%s\n' "$output/EncVault.app"
