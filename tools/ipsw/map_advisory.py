#!/usr/bin/env python3
"""Map the iOS 27.2 advisory entries to binary candidates and emit a report skeleton.

Usage: python3 map_advisory.py <advisory.json> <out.md>
The mapping is a heuristic name table; it is refined later by the actual kext and
dylib inventory extracted from the IPSWs.
"""
import json
import sys

# component -> (kind, candidate binary / kext)
MAP = {
    "Kernel": ("kernel", "kernelcache core (pmap/ipc/vm/bsd)"),
    "AVEVideoEncoder": ("kernel+user", "com.apple.driver.AppleAVE2 / VideoToolbox AVE plugin"),
    "Apple Neural Engine": ("kernel+user", "AppleH16ANEInterface / AppleNeuralEngine.framework"),
    "IOKit": ("kernel+user", "IOKit.framework / IOKit kexts"),
    "IOHIDFamily": ("kernel", "com.apple.iokit.IOHIDFamily"),
    "IOStorageFamily": ("kernel", "com.apple.iokit.IOStorageFamily"),
    "IOMobileFrameBuffer": ("kernel", "com.apple.driver.IOMobileFrameBuffer"),
    "IOSurface": ("kernel+user", "IOSurface.framework / IOSurface kext"),
    "HFS": ("kernel", "com.apple.filesystems.hfs.kext"),
    "Compression": ("user", "libcompression.dylib"),
    "CoreMedia": ("user", "CoreMedia.framework / mediaplaybackd"),
    "CoreGraphics": ("user", "CoreGraphics.framework"),
    "CoreText": ("user", "CoreText.framework"),
    "CoreAudio": ("user", "CoreAudio.framework / AudioToolbox"),
    "Audio": ("user", "AudioToolbox / AudioCodecs"),
    "ImageIO": ("user", "ImageIO.framework"),
    "FontParser": ("user", "FontParser.framework"),
    "libarchive": ("user", "libarchive.2.dylib"),
    "LinkPresentation": ("user", "LinkPresentation.framework"),
    "WebKit": ("user", "JavaScriptCore / WebKit / WebCore"),
    "WebKit Canvas": ("user", "WebCore (canvas)"),
    "WebKit JavaScript Bindings": ("user", "JavaScriptCore bindings"),
    "WebKit Process Model": ("user", "WebKit process model"),
    "WebRTC": ("user", "WebRTC.framework"),
    "Security": ("user", "Security.framework"),
    "Wi-Fi": ("user+kernel", "WiFi frameworks / IO80211 kext"),
    "USB": ("kernel", "USB kexts"),
    "Power Management": ("kernel", "com.apple.driver.AppleARMPlatform / PM kexts"),
    "Bluetooth": ("user+kernel", "Bluetooth.framework / IOBluetooth kexts"),
    "mDNSResponder": ("user", "mDNSResponder"),
    "Thread": ("user", "ThreadNetwork.framework"),
    "MobileGestalt": ("user", "MobileGestalt"),
    "SpringBoard": ("user", "SpringBoard"),
    "Messages": ("user", "Messages / IMSharedUtilities"),
    "Mail": ("user", "Mail"),
    "Maps": ("user", "Maps"),
    "Photos Storage": ("user", "Photos"),
    "Spotlight": ("user", "Spotlight"),
    "Siri": ("user", "Siri"),
    "Shortcuts": ("user", "Shortcuts"),
    "HomeKit": ("user", "HomeKit"),
    "CloudKit": ("user", "CloudKit"),
    "Contacts": ("user", "Contacts"),
    "Calendar": ("user", "CalendarFoundation"),
    "App Store": ("user", "AppStore"),
    "App Intents": ("user", "AppIntents"),
    "Apple Intelligence": ("user", "AppleIntelligence"),
    "AccessorySetupKit": ("user", "AccessorySetupKit"),
    "Accounts": ("user", "Accounts"),
    "FileProvider": ("user", "FileProvider"),
    "Files": ("user", "Files"),
    "Heimdal": ("user", "Heimdal (Kerberos)"),
    "MediaAnalysis": ("user", "MediaAnalysis"),
    "MediaRemote": ("user", "MediaRemote"),
    "Quick Look": ("user", "QuickLook"),
    "RealityKit": ("user", "RealityKit"),
    "ReplayKit": ("user", "ReplayKit"),
    "Safety Check": ("user", "SafetyCheck"),
    "SceneKit": ("user", "SceneKit"),
    "Screen Time": ("user", "ScreenTime"),
    "SwiftUI": ("user", "SwiftUI"),
    "System Preferences": ("user", "SystemPreferences"),
    "TextKit": ("user", "TextKit"),
    "Accelerate Framework": ("user", "Accelerate"),
    "ColorSync": ("user", "ColorSync"),
}


def main():
    rows = json.load(open(sys.argv[1]))
    out = sys.argv[2]
    lines = ["# iOS 27.2 advisory — component → binary map", ""]
    lines.append(f"Entries: {len(rows)}  Components: {len(set(r['component'] for r in rows))}")
    lines.append("")
    lines.append("| CVE | Component | Impact | Binary candidate |")
    lines.append("|---|---|---|---|")
    for r in sorted(rows, key=lambda x: (x["component"], x["cve"])):
        kind, cand = MAP.get(r["component"], ("unknown", "?"))
        lines.append(f"| {r['cve']} | {r['component']} | {r['impact'][:70]} | {cand} |")
    open(out, "w").write("\n".join(lines) + "\n")
    print("wrote", out, len(rows), "entries")
    missing = sorted(set(r["component"] for r in rows) - set(MAP))
    print("unmapped components:", missing)


if __name__ == "__main__":
    main()
