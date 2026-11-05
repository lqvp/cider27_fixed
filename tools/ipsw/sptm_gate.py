#!/usr/bin/env python3
"""Check whether an IPSW's SPTM TLBI verification gate is enabled for a device.

Usage: python3 sptm_gate.py <sptm.bin> <devicetree.bin>
Both inputs are decoded Mach-O/IM4P payloads (see remote_ipsw.py + ipswlib.py).

Background: SPTM 27.2 parses /arm-io/sgx and looks up
verify-gmmu-tlbis-at-sync. If the property is missing it sets the verify flag
to 0 (0xfffffff0270cc18c: strb wzr,[x22,#0x81]) and the GMMU TLBI completion
check is skipped. This script reports whether the gate is present in the DT.
"""
import sys

KEYS = [
    b"verify-gmmu-tlbis-at-sync",
    b"gmmu-tlbi-verification-reg",
    b"gmmu-tlbi-verification-bit",
]


def main():
    sptm = open(sys.argv[1], "rb").read()
    dt = open(sys.argv[2], "rb").read()
    print("SPTM strings:")
    for k in KEYS:
        print(f"  {k.decode():32} {'present' if k in sptm else 'absent'}")
    print("DeviceTree gate:")
    for k in KEYS:
        print(f"  {k.decode():32} {'present' if k in dt else 'absent'}")
    gate = all(k in dt for k in KEYS)
    print()
    print("VERDICT:", "gate ENABLED" if gate else "gate DISABLED (SPTM check will be skipped)")
    return 0 if gate else 1


if __name__ == "__main__":
    sys.exit(main())
