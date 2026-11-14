#!/usr/bin/env bash
# assemble：不重組映像，直接用官方 GPT 映像；解成未壓縮的磁碟映像（$DUMPLING_OUT/work/disk.img），
# 從 rootfs 的 dpkg .list 產生 owners.json（分層用），再呼叫選用掛點 raw-sectors 清點第一個分割區之前的開機程式（以原始磁區為準，D-027）。
# 收到 <專案資料夾> <版本>，環境變數見 pipeline/platform.sh。最後一行 assemble: OK｜GAP｜FAIL（…），兩步取最差的。
set -uo pipefail
root=${DUMPLING_ROOT:?}; out=${DUMPLING_OUT:?}
rm -f "$out/work/disk.img" "$out/assemble.json" "$out/raw-sectors.json" "$out/owners.json"   # 失敗時不留上一次的結果
line=$(python3 -I "$root/pipeline/platforms/_shared/disk_image.py" prepare "$1" "$2" \
  --downloads "$out/downloads" --work "$out/work" --json "$out/assemble.json"); rc=$?
echo "$line"
case $rc in 0) ;; 3) echo "assemble: GAP（映像沒有準備好，不做原始磁區清點）"; exit 3;; *) echo "assemble: FAIL（映像準備失敗）"; exit 1;; esac
ow=$(python3 -I "$root/pipeline/platforms/_shared/disk_image.py" owners "$out/assemble.json" --out "$out/owners.json"); orc=$?
echo "$ow"
case $orc in 0|3) ;; *) echo "assemble: FAIL（owners：${ow#owners: }）"; exit 1;; esac
rs=$(bash "$root/pipeline/platform.sh" raw-sectors "$1" "$2" --out "$out"); rrc=$?
echo "$rs"
[ "$orc" = 3 ] && [ "$rrc" = 0 ] && rrc=3      # owners 有 GAP：整體至少 GAP
case $rrc in
  0) echo "assemble: OK（映像已解開；原始磁區：$(tail -1 <<< "$rs" | sed 's/^raw-sectors: //')）"; exit 0;;
  3) echo "assemble: GAP（映像已解開；原始磁區：$(tail -1 <<< "$rs" | sed 's/^raw-sectors: //')）"; exit 3;;
  *) echo "assemble: FAIL（原始磁區清點失敗：$(tail -1 <<< "$rs")）"; exit 1;;
esac
