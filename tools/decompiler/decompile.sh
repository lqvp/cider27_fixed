#!/bin/bash
# Decompile one function from a raw ARM64 blob with Cutter's rz-ghidra.
# usage: decompile.sh <raw.bin> <offset-hex> [sleighhome]
set -e
RZ=/Applications/Cutter.app/Contents/Resources/bin/rizin
export DYLD_LIBRARY_PATH=/Applications/Cutter.app/Contents/Resources/lib
export SLEIGHHOME=${3:-/Applications/Cutter.app/Contents/Resources/lib/rizin/plugins/rz_ghidra_sleigh}
"$RZ" -a arm -b 64 -e scr.color=0 -q -c "s $2; af; pdg" "$1"
