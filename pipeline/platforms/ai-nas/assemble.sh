#!/usr/bin/env bash
# assemble（AI NAS）：
#  1. 官方 Debian 雲端映像原樣使用，解成未壓縮的磁碟映像（$DUMPLING_OUT/work/disk.img）給 scan 唯讀解析。
#  2. 核心原始碼：上游 orig ＋ debian.tar.xz 的修補（debian/patches/series 依序 patch -p1，不執行任何腳本；D-035）
#     → $DUMPLING_OUT/work/kernel-source.tar.gz 與 kernel-source.json。套不上 → GAP（scan 改用 orig，核心原始碼判斷標 PARTIAL）。
# 收到 <專案資料夾> <版本>，環境變數見 pipeline/platform.sh。最後一行 assemble: OK｜GAP｜FAIL（…），兩步取最差的。
set -uo pipefail
root=${DUMPLING_ROOT:?}; out=${DUMPLING_OUT:?}
di=$root/pipeline/platforms/_shared/disk_image.py
rm -rf "$out/work/disk.img" "$out/assemble.json" "$out/kernel-source.json" "$out/work/kernel-source.tar.gz" "$out/work/ksrc"   # 失敗時不留上一次的結果
line=$(python3 -I "$di" prepare "$1" "$2" --downloads "$out/downloads" --work "$out/work" --json "$out/assemble.json"); rc=$?
echo "$line"
case $rc in 0) ;; 3) echo "assemble: GAP（映像沒有準備好）"; exit 3;; *) echo "assemble: FAIL（映像準備失敗）"; exit 1;; esac
orig=$(python3 -I "$di" param "$1" "$2" kernel_orig_file 2> /dev/null) && deb=$(python3 -I "$di" param "$1" "$2" kernel_debian_file 2> /dev/null) \
  || { echo "assemble: GAP（sources.yml 沒有 kernel_orig_file／kernel_debian_file：核心原始碼只能用上游，判斷標 PARTIAL）"; exit 3; }
for f in "$orig" "$deb"; do
  if [ ! -f "$out/downloads/$f" ] || [ -L "$out/downloads/$f" ]; then echo "assemble: FAIL（downloads/ 沒有 $f，先執行 fetch）"; exit 1; fi
done
ks=$(python3 -I "$root/pipeline/platforms/_shared/debian_kernel_source.py" prepare --orig "$out/downloads/$orig" --debian "$out/downloads/$deb" \
  --work "$out/work/ksrc" --out "$out/work/kernel-source.tar.gz" --json "$out/kernel-source.json"); krc=$?
echo "$ks"
case $krc in
  0) echo "assemble: OK（映像已解開；${ks#kernel-source: }）"; exit 0;;
  3) echo "assemble: GAP（映像已解開；核心原始碼：${ks#kernel-source: }）"; exit 3;;
  *) echo "assemble: FAIL（核心原始碼準備失敗：${ks#kernel-source: }）"; exit 1;;
esac
