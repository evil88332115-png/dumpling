#!/usr/bin/env bash
# Pack the kernel build record (used by the software department for CRA vulnerability assessment).
# Read-only: it does not modify the build directories and does not use the network.
#
# Usage:
#   bash pack-build-record.sh <kernel-build-dir> <output.tar.gz> [--uefi=<uefi-build-dir>] [out-of-tree-module-dir ...]
#   kernel-build-dir       = the directory where make was run (contains .config and System.map;
#                            if you built with O=, give the O= directory)
#   --uefi=<dir>           = the UEFI source/build directory you built (Jetson: sources/uefi). Packs the generated
#                            Kconfig file(s) nvidia-config/*/config.dsc.inc and the build log(s) Build/BUILDLOG_*.txt
#                            (optional; needed to tell whether libraries such as Mbed TLS are built into UEFI)
#   out-of-tree-module-dir = build directories of out-of-tree modules, e.g. NVIDIA nvidia-oot, nvgpu (optional)
#
# Example (Jetson):
#   bash pack-build-record.sh sources/kernel/kernel-noble BuildRecord-<product>-<version>.tar.gz \
#     --uefi=sources/uefi sources/nvidia-oot sources/nvgpu sources/nvdisplay sources/hwpm sources/nvethernetrm \
#     sources/unifiedgpudisp/kernel-open
# Example (Rockchip):
#   bash pack-build-record.sh kernel-6.1 BuildRecord-<product>-<version>.tar.gz external/rkwifibt/drivers/bcmdhd
set -euo pipefail
K=${1:?missing kernel build directory}; OUT=${2:?missing output file name}; shift 2
UEFI=""; ARGS=()
for a in "$@"; do case "$a" in --uefi=*) UEFI=${a#--uefi=};; *) ARGS+=("$a");; esac; done
set -- "${ARGS[@]+"${ARGS[@]}"}"
[ -f "$K/.config" ] && [ -f "$K/System.map" ] || { echo "error: $K does not look like a kernel build directory (no .config or System.map)" >&2; exit 1; }
OUT=$(readlink -f -- "$OUT")
LIST=$(mktemp); trap 'rm -f "$LIST"' EXIT

# 1. Kernel: configuration, build commands, module lists, symbol map, build identity files
( cd "$K"
  for f in .config System.map modules.order modules.builtin modules.builtin.modinfo Module.symvers \
           include/generated/utsversion.h include/generated/compile.h include/config/kernel.release; do
    [ -f "$f" ] && echo "kernel/$f"
  done
  find . -name '.*.cmd' -type f | sed 's|^\./|kernel/|'
) > "$LIST"

# 2. Out-of-tree modules: build commands and module lists
i=0
for D in "$@"; do
  i=$((i+1)); [ -d "$D" ] || { echo "skipped (not a directory): $D" >&2; continue; }
  n="oot$i-$(basename "$D")"
  c=$( cd "$D"; find . -name '.*.cmd' -type f | wc -l )
  k=$( cd "$D"; find . -name '*.ko' -type f | wc -l )
  ( cd "$D"; find . \( -name '.*.cmd' -o -name 'modules.order' -o -name 'Module.symvers' -o -name '*.ko' \) -type f | sed "s|^\./|$n/|" ) >> "$LIST"
  if [ "$c" -gt 0 ] && [ "$k" -eq 0 ]; then
    echo "WARNING: $D has build commands but no .ko files; the scanner cannot confirm these modules are the shipped ones." >&2
  fi
  if [ "$c" -eq 0 ]; then
    echo "WARNING: $D has no build commands (.*.cmd). Was it built here? If you built with O=<dir> or nvbuild.sh (kernel_out/), give that directory instead." >&2
  fi
  echo "out-of-tree $D: $c build command file(s), $k module file(s) (.ko)"
done
# 2b. UEFI (optional): generated Kconfig file(s) and build log(s)
if [ -n "$UEFI" ]; then
  if [ -d "$UEFI" ]; then
    u=$( cd "$UEFI"; { find nvidia-config -mindepth 2 -maxdepth 2 -name 'config.dsc.inc' -type f 2>/dev/null; find Build -maxdepth 1 -name 'BUILDLOG_*.txt' -type f 2>/dev/null; } | sed 's|^|uefi/|' || true )
    if [ -n "$u" ]; then echo "$u" >> "$LIST"; fi
    nu=$(printf '%s' "$u" | grep -c 'config.dsc.inc' || true)
    echo "uefi $UEFI: $nu Kconfig file(s) (nvidia-config/*/config.dsc.inc)"
    [ "$nu" -gt 0 ] || echo "WARNING: $UEFI has no nvidia-config/*/config.dsc.inc. Was UEFI built in this directory?" >&2
  else
    echo "skipped (not a directory): --uefi=$UEFI" >&2; UEFI=""
  fi
fi
kc=$(grep -c '^kernel/.*\.cmd$' "$LIST" || true)
echo "kernel $K: $kc build command file(s)"
[ "$kc" -gt 0 ] || echo "WARNING: the kernel directory has no build commands (.*.cmd); the record will not be usable." >&2

# 3. Map the sources under kernel/ and oot*/ with temporary symlinks, then pack (no files are copied)
TMP=$(mktemp -d); trap 'rm -rf "$TMP" "$LIST"' EXIT
ln -s "$(readlink -f "$K")" "$TMP/kernel"
i=0; for D in "$@"; do i=$((i+1)); [ -d "$D" ] && ln -s "$(readlink -f "$D")" "$TMP/oot$i-$(basename "$D")"; done
[ -n "$UEFI" ] && ln -s "$(readlink -f "$UEFI")" "$TMP/uefi"

# 4. Record the kernel image hash and the toolchain version
{
  echo "packed_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for img in arch/arm64/boot/Image arch/arm64/boot/Image.gz arch/x86/boot/bzImage; do
    [ -f "$K/$img" ] && echo "image=$img sha256=$(sha256sum "$K/$img" | cut -d' ' -f1)"
  done
  grep -m1 '^CONFIG_CC_VERSION_TEXT' "$K/.config" || true
} > "$TMP/BUILD-INFO.txt"
echo "BUILD-INFO.txt" >> "$LIST"

tar -C "$TMP" -czhf "$OUT" -T "$LIST"
echo "Done: $OUT ($(wc -l < "$LIST") files, $(du -h "$OUT" | cut -f1))"
echo "Put this file in the BuildRecord/ folder of the release package and deliver it with the flash package."
