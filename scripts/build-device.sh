#!/bin/bash
# Build an unsigned arm64 IPA for Cinder27.
# The IPA is deliberately unsigned — sign it with your own certificate / profile.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/device"
APP="$OUT/Payload/Cinder27.app"
IPA="$ROOT/dist/Cinder27-unsigned.ipa"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
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

echo "== compile (arm64, min iOS $MIN_IOS) =="
xcrun --sdk iphoneos swiftc \
  -parse-as-library \
  -swift-version 5 \
  -O \
  -target "arm64-apple-ios$MIN_IOS" \
  -sdk "$SDK" \
  -o "$APP/Cinder27" \
  "$ROOT"/Sources/*.swift

echo "== resources =="
cp "$ROOT/Info.plist" "$APP/Info.plist"
printf 'APPL????' > "$APP/PkgInfo"
cp "$ROOT"/seeds/* "$APP/"

echo "== asset catalog =="
xcrun actool "$ROOT/Resources/Assets.xcassets" \
  --compile "$APP" \
  --platform iphoneos \
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

echo "== package Payload/ -> .ipa =="
mkdir -p "$ROOT/dist"
rm -f "$IPA"
( cd "$OUT" && zip -qry "$IPA" Payload )
echo "IPA: $IPA"
ls -lh "$IPA"
