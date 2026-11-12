#!/usr/bin/env bash
# M2 spike：解開 public_sources.tbz2，核對包內各元件 SHA-1（對 NVIDIA 另外公布的 public_sources_sha.txt），
# 列出元件大小，解開核心與樹外模組相關元件。只解開、不執行任何東西。
# 用法：m2-inspect.sh <下載資料夾（含 public_sources.tbz2、public_sources_sha.txt）> <工作資料夾>
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tools/spike/m2-lib.sh
. "$HERE/m2-lib.sh"
D=${1:?下載資料夾}; W=${2:?工作資料夾}; init_res; mkdir -p "$W"
PY=(python3 -I "$HERE/m2_safe_extract.py")

timed extract-public_sources "${PY[@]}" "$D/public_sources.tbz2" "$W/ps" || exit 1
echo "== 解開後的頂層"; ls -la "$W/ps"; find "$W/ps" -maxdepth 3 | head -80
du -sb "$W/ps"
S=$(find "$W/ps" -name public_sources_sha.txt -printf '%h\n' | head -1)
[ -n "$S" ] || { echo "找不到元件資料夾（public_sources_sha.txt）"; find "$W/ps" -maxdepth 4 -type d | head; exit 1; }
echo "元件資料夾：${S#"$W"/}"
echo "== 元件大小（bytes）"; ls -l "$S" | awk '{print $5, $9}' | sort -rn | head -60

echo "== 包內元件 SHA-1 對 NVIDIA 公布的 public_sources_sha.txt（另外下載）"
ok=0; bad=0; missing=0
while read -r h n; do
  n=${n#\*}; f=$S/$n
  [ -f "$f" ] || { missing=$((missing+1)); continue; }
  case $n in *.sha1sum) continue;; esac
  g=$(sha1sum "$f" | cut -d' ' -f1)
  if [ "$g" = "$h" ]; then ok=$((ok+1)); else bad=$((bad+1)); echo "SHA-1 不符：$n 算出 $g，公布 $h"; fi
done < "$D/public_sources_sha.txt"
echo "元件 SHA-1：相符 $ok、不符 $bad、清單有但包內沒有 $missing"
diff <(sed 's/^[^ ]* \*//' "$D/public_sources_sha.txt" | grep -v '\.sha1sum$' | sort) <(ls "$S" | grep -v '\.sha1sum$' | sort) > /dev/null && echo "包內檔案和清單一致" || echo "包內檔案和清單有差異"

echo "== NVIDIA 附的建置腳本（只讀內容，不執行）"
# 每行前面加 "| "：避免內容被 Actions 當成工作流程指令（以 :: 或 ## 開頭的行）吃掉
show() { echo "----- $1"; sed 's/^/| /' "$1"; }
for f in nv_public_src_build.sh nv_public_src_build_tos.sh; do
  [ -f "$S/$f" ] && show "$S/$f"
done

# 解開核心與樹外模組元件
for c in kernel_src.tbz2 kernel_oot_modules_src.tbz2 kernel_nvgpu_src.tbz2 nvidia_kernel_display_driver_source.tbz2 nvidia_unified_gpu_display_driver_source.tbz2; do
  if [ -f "$S/$c" ]; then
    timed "extract-$c" "${PY[@]}" "$S/$c" "$W/x/${c%.tbz2}"
    du -sb "$W/x/${c%.tbz2}"
  else echo "沒有 $c"; fi
done
echo "== 解開後頂層"; ls -la "$W/x"/* | head -80
K=$W/x/kernel_src
echo "== kernel_src 建置腳本（只讀內容，不執行）"
for f in nvbuild.sh nvcommon_build.sh kernel_src_build_env.sh; do [ -f "$K/$f" ] && show "$K/$f"; done
echo "== kernel_src/kernel 內容"; find "$K/kernel" -maxdepth 2 | head -40
echo "== oot Makefile"; [ -f "$W/x/kernel_oot_modules_src/Makefile" ] && show "$W/x/kernel_oot_modules_src/Makefile"
echo "== oot 各元件頂層"; find "$W/x/kernel_oot_modules_src" -maxdepth 2 -mindepth 2 | head -60
# 把要讀的腳本與 Makefile 複製出來（日誌顯示會吃掉部分行，改用小型 artifact 取回）
mkdir -p "$RES/inspect"
cp "$S"/nv_public_src_build.sh "$S"/nv_public_src_build_tos.sh "$RES/inspect/" 2> /dev/null || true
cp "$K"/*.sh "$RES/inspect/" 2> /dev/null || true
cp "$W/x/kernel_oot_modules_src/Makefile" "$RES/inspect/oot-Makefile" 2> /dev/null || true
find "$W/x" -maxdepth 4 -not -path '*/.git/*' \( -type d -o -type f -name 'Makefile' -o -name 'Kconfig' -o -name '*defconfig' \) 2> /dev/null | head -400 | sed "s|^$W/||" > "$RES/inspect/tree.txt"
find "$K/kernel" -maxdepth 3 -type f \( -name 'Makefile' -o -name 'tegra*defconfig' -o -name 'defconfig' \) 2> /dev/null | sed "s|^$W/||" > "$RES/inspect/kernel-files.txt"
snap_df 解開後
