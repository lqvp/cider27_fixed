#!/bin/bash
# Build the simulator .app for Cinder27 and install it on the booted simulator.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/sim"
APP="$OUT/Cinder27.app"
SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
MIN_IOS="${MIN_IOS:-17.0}"

echo "== seeds =="
python3 "$ROOT/scripts/gen_seeds.py" > /dev/null

echo "== icon =="
if [ ! -f "$ROOT/Resources/AppIcon-1024.png" ]; then
  python3 "$ROOT/scripts/gen_icon.py" > /dev/null
fi

echo "== clean =="
rm -rf "$OUT"
mkdir -p "$APP"

echo "== compile (arm64 simulator, min iOS $MIN_IOS) =="
xcrun --sdk iphonesimulator swiftc \
  -parse-as-library \
  -swift-version 5 \
  -O \
  -target "arm64-apple-ios${MIN_IOS}-simulator" \
  -sdk "$SDK" \
  -o "$APP/Cinder27" \
  "$ROOT"/Sources/*.swift

echo "== resources =="
cp "$ROOT/Info.plist" "$APP/Info.plist"
printf 'APPL????' > "$APP/PkgInfo"
cp "$ROOT"/seeds/* "$APP/"

# The device Info.plist carries iPhoneOS platform keys; the simulator requires the
# simulator variants or SpringBoard refuses the install.
plutil -replace CFBundleSupportedPlatforms -json '["iPhoneSimulator"]' "$APP/Info.plist"
plutil -replace DTPlatformName -string iphonesimulator "$APP/Info.plist"
plutil -replace DTSDKName -string iphonesimulator "$APP/Info.plist"

echo "== asset catalog =="
xcrun actool "$ROOT/Resources/Assets.xcassets" \
  --compile "$APP" \
  --platform iphonesimulator \
  --minimum-deployment-target "$MIN_IOS" \
  --app-icon AppIcon \
  --output-partial-info-plist "$OUT/assetcatalog_generated_info.plist" \
  --target-device iphone \
  --target-device ipad > /dev/null

echo "== merge asset catalog Info.plist keys =="
python3 - "$APP/Info.plist" "$OUT/assetcatalog_generated_info.plist" <<'PY'
import plistlib, sys
info_path, partial_path = sys.argv[1], sys.argv[2]
with open(info_path, "rb") as fh:
    info = plistlib.load(fh)
with open(partial_path, "rb") as fh:
    partial = plistlib.load(fh)
partial.pop("com.apple.actool.compilation-results", None)
info.update(partial)
with open(info_path, "wb") as fh:
    plistlib.dump(info, fh, fmt=plistlib.FMT_BINARY)
PY

chmod 755 "$APP/Cinder27"
chmod 644 "$APP/Info.plist"
/usr/bin/plutil -lint "$APP/Info.plist"

echo "== install =="
xcrun simctl install booted "$APP"
echo "installed: $APP"
