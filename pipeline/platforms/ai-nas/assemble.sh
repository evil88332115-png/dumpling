#!/usr/bin/env bash
# assemble：示範專案不重組映像，直接用官方映像；把它解成未壓縮的磁碟映像（$DUMPLING_OUT/work/disk.img）給 scan 唯讀解析。
# 收到 <專案資料夾> <版本>，環境變數見 pipeline/platform.sh。最後一行 assemble: OK｜GAP｜FAIL（…）。
set -uo pipefail
root=${DUMPLING_ROOT:?}; out=${DUMPLING_OUT:?}
rm -f "$out/work/disk.img"
exec python3 -I "$root/pipeline/platforms/_shared/disk_image.py" prepare "$1" "$2" \
  --downloads "$out/downloads" --work "$out/work" --json "$out/assemble.json"
