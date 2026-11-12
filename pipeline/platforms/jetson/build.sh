#!/usr/bin/env bash
# Jetson 轉接器 build 步驟：public_sources → 核對元件 SHA-1 → 安全解壓 → 套 patch → nvbuild.sh 原生編譯（aarch64 主機）
# → 打包建置紀錄（BuildRecord）→ 整理交付檔。收到 <專案資料夾> <版本>，環境變數見 pipeline/platform.sh。
#
# 輸入：$DUMPLING_OUT/downloads/{public_sources.tbz2,public_sources_sha.txt}（fetch 步驟已核對 sha256）
# 輸出（都在 $DUMPLING_OUT；交給 scan 的東西一律放 handoff/，workflow 整個資料夾上傳、在 scan job 放回同一個路徑，不指名個別檔案）：
#   handoff/BuildRecord-<專案>-<版本>.tar.gz   pack-build-record.sh 的結果（UEFI 未自編：D-002，不給 --uefi）
#   handoff/deliverables.tar.zst              Image、樹內與樹外 .ko、dtb、modules.*、核心建置設定（assemble 步驟用）
#   handoff/kernel.release、kernel-subdir     核心版本字串、核心樹在編譯輸出裡的相對路徑
#   handoff/build.json                        Image 的 SHA-256、核心版本字串、元件 SHA-1 核對、patch、nvbuild 結束碼與時間
#   handoff/nvbuild-tail.txt、build-summary.md  nvbuild.log 的最後 40 行、一行摘要（workflow 的 step summary 用）
#   work/                                     解壓與編譯的暫存（不交接；資料夾名稱固定；.cmd 內有絕對路徑，編譯後不要搬動）
# 建置不可重現（同一份原始碼編兩次 Image 的 SHA-256 不同）：建置紀錄與交付檔一定來自這一次編譯。
#
# 規則：
# - 下載的檔案是不可信資料：只用 pipeline/lib/safe_extract.py 解開（拒絕絕對路徑、..、裝置檔、跳出的連結）；不執行 BSP 或 rootfs 的任何東西。
# - 編譯時執行的是原始碼樹自己的 Makefile／kbuild 與 NVIDIA 原始碼包附的 nvbuild.sh（只用 rsync 與 make，不用 sudo，-i 不使用；內容已讀過）。
# - 只在 aarch64 主機編譯（不用交叉工具鏈）；x86 主機回報 NOT_RUN。
# 最後一行：build: OK｜GAP｜NOT_RUN｜FAIL（說明）。
set -uo pipefail
proj=${1:?專案資料夾}; ver=${2:?版本}
root=${DUMPLING_ROOT:?}; out=${DUMPLING_OUT:?}
dl=$out/downloads work=$out/work
fail() { echo "build: FAIL（$*）"; exit 1; }
t_start=$(date +%s)

[ "$(uname -m)" = aarch64 ] || { echo "build: NOT_RUN（只在 aarch64 主機原生編譯；這台是 $(uname -m)）"; exit 4; }
for c in rsync make gcc bc bison flex pahole perl tar sha256sum patch zstd; do
  command -v "$c" > /dev/null || fail "缺少 $c（apt 相依見 docs/JETSON.md）"
done
[ -f "$dl/public_sources.tbz2" ] || fail "沒有 $dl/public_sources.tbz2（先執行 fetch）"
[ -f "$dl/public_sources_sha.txt" ] || fail "沒有 $dl/public_sources_sha.txt（先執行 fetch）"
H=$out/handoff
rm -rf "$work" "$H"
mkdir -p "$work" "$H" || fail "無法建立 $work"

# 1.～4. 解開、核對元件 SHA-1、四個元件解到同一個資料夾、套這個版本的 patch（與 assemble 共用 prepare-source.sh）
B=$work/src
bash "$(dirname "${BASH_SOURCE[0]}")/prepare-source.sh" "$proj" "$ver" "$B" "$work/tmp" "$work/source.json" > "$work/prepare.log" 2>&1 \
  || { tail -3 "$work/prepare.log"; fail "準備原始碼失敗（$(tail -1 "$work/prepare.log")）"; }
grep -E '^(patch|prepare-source)' "$work/prepare.log"
[ -x "$B/nvbuild.sh" ] || fail "原始碼樹裡沒有 nvbuild.sh"
kname=$(basename "$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["kernel_dir"])' "$work/source.json")")
np=$(python3 -I -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["patches"]))' "$work/source.json")
comp_json=$(python3 -I -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1]))["components"]))' "$work/source.json")
patches_json=$(python3 -I -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1]))["patches"]))' "$work/source.json")

# 5. 編譯（nvbuild.sh：核心 Image 與 modules → 樹外模組 → dtbs）
OUT=$work/out
t_b=$(date +%s)
( cd "$B" && ./nvbuild.sh -o "$OUT" ) > "$work/nvbuild.log" 2>&1
rc=$?
t_build=$(( $(date +%s) - t_b ))
echo "nvbuild.sh 結束碼 $rc，$t_build 秒；警告 $(grep -c 'warning:' "$work/nvbuild.log" || true) 行"
if [ $rc -ne 0 ]; then tail -30 "$work/nvbuild.log"; fail "nvbuild.sh 結束碼 $rc（log 在 work/nvbuild.log）"; fi
K=$OUT/kernel/$kname
for f in arch/arm64/boot/Image .config System.map; do [ -f "$K/$f" ] || fail "編譯結果缺 $f"; done
image_sha=$(sha256sum "$K/arch/arm64/boot/Image" | cut -d' ' -f1)
krel=$(cat "$K/include/config/kernel.release" 2> /dev/null)
[ -n "$krel" ] || fail "讀不到 include/config/kernel.release"
echo "核心 $krel，Image sha256 $image_sha"

# 6. 建置紀錄（樹外模組資料夾照 pack-build-record.sh 的範例；UEFI 未自編，D-002）
oot=()
for d in nvidia-oot nvgpu nvdisplay hwpm nvethernetrm unifiedgpudisp/kernel-open; do [ -d "$OUT/$d" ] && oot+=("$OUT/$d"); done
br=$H/BuildRecord-$DUMPLING_PROJECT-$ver.tar.gz
bash "$root/tools/demo/pack-build-record.sh" "$K" "$br" "${oot[@]}" > "$work/pack.log" 2>&1 || { tail -5 "$work/pack.log"; fail "pack-build-record.sh 失敗"; }
tail -2 "$work/pack.log"
br_sha=$(sha256sum "$br" | cut -d' ' -f1)

# 7. 交付檔：Image、.ko（樹內與樹外，保留相對於編譯輸出的路徑）、dtb、modules.*、kernel.release
D=$H
L=$work/deliver.list
( cd "$OUT" && find . \( -name '*.ko' -o -name '*.dtb' -o -name '*.dtbo' \) -type f | sort > "$L"
  for f in arch/arm64/boot/Image modules.order modules.builtin modules.builtin.modinfo include/config/kernel.release .config Makefile Module.symvers; do
    [ -f "kernel/$kname/$f" ] && echo "./kernel/$kname/$f"
  done >> "$L"
  tar -cf - -T "$L" | zstd -3 -T0 -q -o "$D/deliverables.tar.zst" ) || fail "整理交付檔失敗"
nko=$(grep -c '\.ko$' "$L" || true); ndtb=$(grep -c '\.dtbo\?$' "$L" || true)
printf '%s\n' "$krel" > "$D/kernel.release"
printf '%s\n' "./kernel/$kname" > "$D/kernel-subdir"

python3 -I - "$H/build.json" "$ver" "$krel" "$image_sha" "$br_sha" "$comp_json" "$patches_json" "$rc" "$t_build" "$nko" "$ndtb" "$(( $(date +%s) - t_start ))" "$(gcc --version | head -1)" << 'PY'
import json, sys
o, ver, krel, ish, bsh, comp, patches, rc, tb, nko, ndtb, total, gcc = sys.argv[1:14]
json.dump({"schema": 1, "version": ver, "kernel_release": krel, "image_sha256": ish, "build_record_sha256": bsh,
           "components": json.loads(comp), "patches": json.loads(patches), "nvbuild_exit": int(rc), "nvbuild_seconds": int(tb),
           "ko_count": int(nko), "dtb_count": int(ndtb), "total_seconds": int(total), "gcc": gcc,
           "uefi": "未自編（D-002，使用 BSP 內建）", "reproducible": False}, open(o, "w"), indent=1, ensure_ascii=False)
PY
cm=$(printf '%s' "$comp_json" | python3 -I -c 'import json,sys;d=json.load(sys.stdin);print("%d/%d"%(d["matched"],d["checked"]))')
tail -n 40 "$work/nvbuild.log" > "$H/nvbuild-tail.txt"
summary="build: OK（核心 $krel；Image sha256 $image_sha；.ko $nko、dtb $ndtb；patch $np 個；元件 SHA-1 核對 $cm；UEFI 未自編；編譯 ${t_build} 秒）"
printf '%s\n' "$summary" > "$H/build-summary.md"
echo "$summary"
