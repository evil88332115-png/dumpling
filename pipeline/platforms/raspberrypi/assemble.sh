#!/usr/bin/env bash
# assemble：示範專案不重組映像，直接用官方映像；
#  1. 解成未壓縮的磁碟映像（$DUMPLING_OUT/work/disk.img）給 scan 唯讀解析。
#  2. 從映像 rootfs 的 dpkg .list 產生 owners.json（{路徑: 擁有它的套件}；分層時 Syft 的檔案紀錄靠它找層）。
# 收到 <專案資料夾> <版本>，環境變數見 pipeline/platform.sh。最後一行 assemble: OK｜GAP｜FAIL（…），取最差的。
set -uo pipefail
root=${DUMPLING_ROOT:?}; out=${DUMPLING_OUT:?}
di=$root/pipeline/platforms/_shared/disk_image.py
rm -f "$out/work/disk.img" "$out/assemble.json" "$out/owners.json"   # 失敗時不留上一次的結果
line=$(python3 -I "$di" prepare "$1" "$2" --downloads "$out/downloads" --work "$out/work" --json "$out/assemble.json"); rc=$?
echo "$line"
case $rc in 0) ;; 3) echo "assemble: GAP（映像沒有準備好）"; exit 3;; *) echo "assemble: FAIL（映像準備失敗）"; exit 1;; esac
ow=$(python3 -I "$di" owners "$out/assemble.json" --out "$out/owners.json"); orc=$?
echo "$ow"
case $orc in
  0) echo "assemble: OK（${line#assemble: }；${ow#owners: }）"; exit 0;;
  3) echo "assemble: GAP（映像已解開；${ow#owners: }）"; exit 3;;
  *) echo "assemble: FAIL（owners：${ow#owners: }）"; exit 1;;
esac
