#!/usr/bin/env bash
# Jetson 轉接器 assemble 步驟：BSP ＋ 範例 rootfs 組刷機包，核心與樹外模組換成 build 步驟編出來的那一份。
# 收到 <專案資料夾> <版本>，環境變數見 pipeline/platform.sh。
#
# 輸入：$DUMPLING_OUT/downloads/（fetch）、$DUMPLING_OUT/deliver/deliverables.tar 與 kernel.release（build；scan job 從 artifact 放回來）、
#       $DUMPLING_OUT/BuildRecord-*.tar.gz
# 輸出：
#   FlashPackage/<專案>-<版本>-flashpkg.tar(+.md5)  Linux_for_Tegra/ 形式（BSP ＋ rootfs；kernel/Image 與 rootfs/boot/Image 都是 CI 編的那顆）
#   SourceCode/<專案>-<版本>-source.tar(+.md5)       套好 patch 的原始碼樹（精靈的 SourceCode 輸入；上游比對用）
#   assemble.json                                    換了什麼、丟了什麼
#
# 規則：
# - 下載的檔案是不可信資料：只讀 tar 結構與 deb（ar）的結構，**不解開 BSP 或 rootfs 到主機、不執行任何東西、不跑 apply_binaries.sh 或 flash.sh**
#   （rootfs 與 NVIDIA 套件的合併由 tools/demo/jetson_rootfs.py 做，見該檔說明）。
# - 這是近似值，不是刷機後的系統（apply_binaries.sh 依板子挑套件、維護者腳本產生的檔案都沒有）；見 docs/JETSON.md。
# - .md5 是組裝當下算的值（只防 assemble 到 scan 之間損壞），不是 NVIDIA 公布的雜湊；NVIDIA 原始檔的核對在 fetch 步驟。
# 最後一行：assemble: OK｜GAP｜FAIL（說明）。
set -uo pipefail
proj=${1:?專案資料夾}; ver=${2:?版本}
root=${DUMPLING_ROOT:?}; out=${DUMPLING_OUT:?}
pyl() { python3 -I "$root/pipeline/lib/$1" "${@:2}"; }
fail() { echo "assemble: FAIL（$*）"; exit 1; }
dl=$out/downloads work=$out/assemble
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
t0=$(date +%s)

for f in "$out/deliver/kernel.release" "$out/deliver/kernel-subdir" "$out/build.json"; do
  [ -f "$f" ] || fail "缺少 build 的輸出 $f"
done
bsp='' rfs=''
while IFS=$'\t' read -r role name; do
  case $role in bsp) bsp=$name;; rootfs) rfs=$name;; esac
done < <(pyl jetson_build.py files "$proj" "$ver")
if [ -z "$bsp" ] || [ -z "$rfs" ]; then fail "sources.yml 的這個版本要有 role: bsp 與 role: rootfs 的檔案"; fi
if [ ! -f "$dl/$bsp" ] || [ ! -f "$dl/$rfs" ]; then fail "downloads/ 缺 $bsp 或 $rfs（先執行 fetch）"; fi

rm -rf "$work" "$out/FlashPackage" "$out/SourceCode" "$out/tee-source"
mkdir -p "$work" "$out/FlashPackage" "$out/SourceCode" || fail "無法建立資料夾"

# 1. CI 的交付檔（我們自己的 build 輸出，仍用安全解壓）
if [ -f "$out/deliver/deliverables.tar.zst" ]; then
  zstd -d -q -c "$out/deliver/deliverables.tar.zst" > "$work/deliverables.tar" || fail "解壓 deliverables.tar.zst 失敗"
elif [ -f "$out/deliver/deliverables.tar" ]; then cp "$out/deliver/deliverables.tar" "$work/deliverables.tar"
else fail "缺少 build 的輸出 deliver/deliverables.tar.zst"; fi
pyl safe_extract.py "$work/deliverables.tar" "$work/deliver" > /dev/null || fail "解開 deliverables 被拒絕或失敗"
rm -f "$work/deliverables.tar"

# 2. 範例 rootfs ＋ BSP 的 NVIDIA 套件合併成 rootfs tar（只讀 tar／deb 結構，不執行任何東西）；不要模擬客製版
python3 -I "$root/tools/demo/jetson_rootfs.py" --bsp "$dl/$bsp" --rootfs "$dl/$rfs" --work "$work" \
  --out-base "$work/base.tar" --report "$out/prep.json" > "$work/prep.txt" 2>&1 || { tail -3 "$work/prep.txt"; fail "jetson_rootfs.py 失敗"; }
echo "rootfs：$(tail -1 "$work/prep.txt")"

# 3. 刷機包
krel=$(cat "$out/deliver/kernel.release"); ksub=$(sed 's|^\./||' "$out/deliver/kernel-subdir")
pkg=$out/FlashPackage/$DUMPLING_PROJECT-$ver-flashpkg.tar
line=$(pyl jetson_assemble.py --bsp "$dl/$bsp" --rootfs-tar "$work/base.tar" --deliver "$work/deliver" --kernel-release "$krel" \
  --kernel-subdir "$ksub" --out "$pkg" --report "$out/assemble.json") || fail "$(printf '%s' "$line" | sed 's/^jetson_assemble: FAIL（//; s/）$//')"
echo "$line"
rm -f "$work/base.tar"
( cd "$out/FlashPackage" && md5sum "$(basename "$pkg")" > "$(basename "$pkg").md5" )

# 4. 原始碼（套好 patch；重新從 public_sources 做，與 build 同樣的步驟）
DUMPLING_TEE_DIR=$out/tee-source bash "$here/prepare-source.sh" "$proj" "$ver" "$work/src" "$work/tmp" "$out/source.json" > "$work/prepare.log" 2>&1 \
  || { tail -3 "$work/prepare.log"; fail "準備原始碼失敗"; }
grep -E '^(patch|prepare-source)' "$work/prepare.log"
src=$out/SourceCode/$DUMPLING_PROJECT-$ver-source.tar
tar -cf "$src" -C "$work/src" . || fail "打包原始碼失敗"
( cd "$out/SourceCode" && md5sum "$(basename "$src")" > "$(basename "$src").md5" )
rm -rf "$work"

python3 -I - "$out/assemble.json" << 'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["note"] = "近似值：NVIDIA 套件以 jetson_rootfs.py 合併（所有 arm64／all），未執行 apply_binaries.sh 或維護者腳本；.md5 為組裝當下的值"
json.dump(d, open(p, "w"), indent=1, ensure_ascii=False)
PY
echo "assemble: OK（刷機包 $(du -h "$pkg" | cut -f1)；核心 $krel；kernel/Image 與 rootfs/boot/Image 都是 CI 編的；用時 $(( $(date +%s) - t0 )) 秒）"
