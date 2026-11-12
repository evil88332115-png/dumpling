#!/usr/bin/env bash
# Jetson：把 public_sources 變成「套好 patch 的原始碼樹」。build 步驟（編譯）與 assemble 步驟（交給精靈的 SourceCode）共用，
# 兩邊從同一份下載、同樣的步驟得到同樣的樹（解壓與 patch 是確定的；只有編譯不可重現）。
#
# 用法：prepare-source.sh <專案資料夾> <版本> <目的資料夾（會清空重建）> <暫存資料夾> <結果 JSON>
# 環境變數：DUMPLING_ROOT、DUMPLING_OUT（要有 downloads/）。
# 做的事：解開 public_sources.tbz2（pipeline/lib/safe_extract.py）→ 元件 SHA-1 對 NVIDIA 公布的 public_sources_sha.txt →
#   四個元件（kernel_src、kernel_oot_modules_src、兩個顯示驅動）解到同一個資料夾 → 套這個版本的 patch（--dry-run 後 --fuzz=0）。
# 結果 JSON：{components: {checked, matched, required}, patches: [{file, dir, sha256}], kernel_dir}。
# 最後一行 prepare-source: OK｜FAIL（說明）；結束碼 0／1。
set -uo pipefail
proj=${1:?專案資料夾}; ver=${2:?版本}; B=${3:?目的資料夾}; tmp=${4:?暫存資料夾}; res=${5:?結果JSON}
root=${DUMPLING_ROOT:?}; out=${DUMPLING_OUT:?}
pyl() { python3 -I "$root/pipeline/lib/$1" "${@:2}"; }
dl=$out/downloads
fail() { echo "prepare-source: FAIL（$*）"; exit 1; }
[ -f "$dl/public_sources.tbz2" ] || fail "沒有 $dl/public_sources.tbz2（先執行 fetch）"
[ -f "$dl/public_sources_sha.txt" ] || fail "沒有 $dl/public_sources_sha.txt（先執行 fetch）"
case $B in "$out"/*) ;; *) fail "目的資料夾必須在 \$DUMPLING_OUT 底下";; esac
rm -rf "$B" "$tmp"; mkdir -p "$B" "$tmp" || fail "無法建立資料夾"

pyl safe_extract.py "$dl/public_sources.tbz2" "$tmp/ps" > /dev/null || fail "解開 public_sources.tbz2 被拒絕或失敗"
S=$tmp/ps/Linux_for_Tegra/source
[ -d "$S" ] || fail "public_sources 裡沒有 Linux_for_Tegra/source"
comps=(kernel_src.tbz2 kernel_oot_modules_src.tbz2 nvidia_kernel_display_driver_source.tbz2 nvidia_unified_gpu_display_driver_source.tbz2)
if ! comp_json=$(pyl jetson_build.py components "$dl/public_sources_sha.txt" "$S" --require "${comps[@]}"); then
  fail "$(printf '%s' "$comp_json" | sed 's/^jetson_build: FAIL（//; s/）$//')"
fi
for c in "${comps[@]}"; do
  pyl safe_extract.py "$S/$c" "$B" --allow-nonempty > /dev/null || fail "解開 $c 被拒絕或失敗"
done
rm -rf "$tmp/ps"
ksrc=$(find "$B/kernel" -maxdepth 1 -mindepth 1 -type d -name 'kernel-*')
if [ -z "$ksrc" ] || [ "$(printf '%s\n' "$ksrc" | wc -l)" != 1 ]; then fail "kernel/ 底下要剛好一個 kernel-* 資料夾"; fi

patches_json="[]"
if ! pl=$(pyl jetson_build.py patches "$proj" "$ver"); then fail "$(printf '%s' "$pl" | sed 's/^jetson_build: FAIL（//; s/）$//')"; fi
np=0
while IFS=$'\t' read -r pdir pfile phash; do
  [ -n "$pfile" ] || continue
  [ -d "$B/$pdir" ] || fail "patch 的目錄不存在：$pdir"
  patch -p1 --dry-run --fuzz=0 --forward -d "$B/$pdir" -i "$pfile" > "$tmp/patch-$np.log" 2>&1 || fail "patch $(basename "$pfile") 無法乾淨套用（$pdir）：$(tail -1 "$tmp/patch-$np.log")"
  patch -p1 --fuzz=0 --forward --no-backup-if-mismatch -d "$B/$pdir" -i "$pfile" >> "$tmp/patch-$np.log" 2>&1 || fail "patch $(basename "$pfile") 套用失敗"
  echo "patch 已套用：$(basename "$pfile")（$pdir，sha256 $phash）"
  patches_json=$(python3 -I -c 'import json,sys;l=json.loads(sys.argv[1]);l.append({"file":sys.argv[2],"dir":sys.argv[3],"sha256":sys.argv[4]});print(json.dumps(l))' "$patches_json" "$(basename "$pfile")" "$pdir" "$phash")
  np=$((np+1))
done <<< "$pl"
python3 -I -c 'import json,sys;json.dump({"components":json.loads(sys.argv[1]),"patches":json.loads(sys.argv[2]),"kernel_dir":sys.argv[3]},open(sys.argv[4],"w"),indent=1,ensure_ascii=False)' \
  "$comp_json" "$patches_json" "kernel/$(basename "$ksrc")" "$res" || fail "寫不出結果 JSON"
echo "prepare-source: OK（元件 SHA-1 核對 $(printf '%s' "$comp_json" | python3 -I -c 'import json,sys;d=json.load(sys.stdin);print("%d/%d"%(d["matched"],d["checked"]))')；patch $np 個）"
