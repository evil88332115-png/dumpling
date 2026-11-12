#!/usr/bin/env bash
# M2 spike 第 3 件：在 arm64 runner 上原生編核心＋樹外模組（不用交叉工具鏈）。
# 用法：m2-build.sh <下載資料夾（含 public_sources.tbz2、public_sources_sha.txt）> <工作資料夾>
#
# 做法照 NVIDIA 公開原始碼包內的 nv_public_src_build.sh／nvbuild.sh（2026-11-12 讀過）：
#   kernel_src、kernel_oot_modules_src、nvidia_kernel_display_driver_source、nvidia_unified_gpu_display_driver_source
#   四包解開到同一個資料夾，再執行 ./nvbuild.sh -o <輸出>。
#   nvbuild.sh 在 aarch64 主機上不需要 CROSS_COMPILE；只用 rsync 與 make，-i（install，要 sudo）不使用。
#   它依序：make -C <輸出>/kernel（核心 Image、modules）→ make modules（hwpm、nvidia-oot、nvgpu、nvdisplay、unifiedgpudisp）→ make dtbs。
# 下載的壓縮檔是不可信資料：只用 m2_safe_extract.py 解開（拒絕跳出目的資料夾的連結與裝置檔），
# 不執行 BSP 或 rootfs 的任何東西；編譯時跑的是原始碼樹自己的 Makefile／kbuild 與 nvbuild.sh（內容已讀過）。
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
# shellcheck source=tools/spike/m2-lib.sh
. "$HERE/m2-lib.sh"
D=${1:?下載資料夾}; W=${2:?工作資料夾}; init_res; mkdir -p "$W"
PY=(python3 -I "$HERE/m2_safe_extract.py")
PKGS=(build-essential bc bison flex libssl-dev libelf-dev rsync dwarves cpio kmod device-tree-compiler python3 xz-utils zstd lz4 libncurses-dev pkg-config perl)

echo "== 環境"; uname -srm; nproc; free -b | sed -n 1,2p; df -B1 / | tail -1; gcc --version | head -1; make --version | head -1
sampler_start 15
trap 'sampler_stop' EXIT

timed apt-install sh -c "sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ${PKGS[*]} > /dev/null"
echo "== 相依套件實際版本"
dpkg-query -W -f='${Package}=${Version}\n' "${PKGS[@]}" gcc make binutils 2> /dev/null | tee "$RES/apt-versions.txt"
echo "gcc: $(gcc --version | head -1)"; echo "ld: $(ld --version | head -1)"; echo "pahole: $(pahole --version 2> /dev/null)"

timed extract-public_sources "${PY[@]}" "$D/public_sources.tbz2" "$W/ps" || exit 1
S=$W/ps/Linux_for_Tegra/source
B=$W/build; mkdir -p "$B"
for c in kernel_src kernel_oot_modules_src nvidia_kernel_display_driver_source nvidia_unified_gpu_display_driver_source; do
  want=$(awk -v n="$c.tbz2" '{x=$2; sub(/^\*/,"",x); if (x==n) print $1}' "$D/public_sources_sha.txt")
  got=$(sha1sum "$S/$c.tbz2" | cut -d' ' -f1)
  if [ -n "$want" ] && [ "$want" = "$got" ]; then echo "$c.tbz2 SHA-1 與 NVIDIA 公布的相符 ($got)"
  else echo "$c.tbz2 SHA-1 不符（算出 $got，公布 ${want:-無}）"; exit 1; fi
  timed "extract-$c" "${PY[@]}" "$S/$c.tbz2" "$B" --allow-nonempty || exit 1
done
rm -rf "$W/ps"   # 騰出空間：元件包已解開
du -sb "$B"; ls "$B"
echo "== kernel/Makefile（NVIDIA 的包裝；只讀內容）"; sed 's/^/| /' "$B/kernel/Makefile" | grep -v '^| #' | head -80
cp "$B/kernel/Makefile" "$RES/kernel-wrapper-Makefile" 2> /dev/null || true

OUT=$W/out
run_nvbuild() (
  cd "$B" || exit 1
  # 每行前面加上開始後的秒數，之後從標記行算各段時間
  set -o pipefail
  ./nvbuild.sh -o "$OUT" 2>&1 | perl -MTime::HiRes=time -ne 'BEGIN{$|=1;$t=time} printf "%7.0f %s", time-$t, $_' > "$RES/nvbuild.log"
)
timed nvbuild run_nvbuild; rc=$?
echo "nvbuild.sh 退出碼 $rc"
echo "== 各段時間（從 nvbuild.log 的標記行；左欄是開始後秒數）"
grep -E "^ *[0-9]+ (Syncing|Building|Kernel sources|Modules compiled|DTBs compiled|make .* - |Error|The output|Using KERNEL)" "$RES/nvbuild.log" | head -60
echo "== 失敗訊息（若有）"; grep -n -E "error:|Error [0-9]|\*\*\*|No such file|fatal" "$RES/nvbuild.log" | head -30
echo "== log 末 40 行"; tail -40 "$RES/nvbuild.log"
gzip -f "$RES/nvbuild.log"

echo "== 建置結果"
if [ -d "$OUT" ]; then
  du -sb "$OUT"; du -sb "$OUT"/* 2> /dev/null | sort -rn | head -20
  K=$OUT/kernel/kernel-noble
  ls -l "$K/arch/arm64/boot/Image" "$K/.config" "$K/System.map" 2> /dev/null
  sha256sum "$K/arch/arm64/boot/Image" 2> /dev/null
  echo "核心 .ko：$(find "$K" -name '*.ko' | wc -l)；樹外 .ko：$(find "$OUT" -path "$K" -prune -o -name '*.ko' -print | wc -l)；.cmd：$(find "$OUT" -name '.*.cmd' | wc -l)"
  echo "dtb：$(find "$OUT" -name '*.dtb' | wc -l)"
  find "$OUT" -path "$K" -prune -o -name '*.ko' -print | sed "s|^$OUT/||" | head -60
  # 建置資料夾能不能讓 pack-build-record.sh 打包（這次只量，不留存）
  oot=()
  for d in nvidia-oot nvgpu nvdisplay hwpm nvethernetrm unifiedgpudisp/kernel-open; do [ -d "$OUT/$d" ] && oot+=("$OUT/$d"); done
  timed pack-build-record bash "$ROOT/tools/demo/pack-build-record.sh" "$K" "$RES/BuildRecord-spike.tar.gz" "${oot[@]}"
  ls -l "$RES/BuildRecord-spike.tar.gz" 2> /dev/null
  # 傳給下一個 job 的大小估計
  est() { # <標籤> <tar 的檔案清單來源：-T 檔案 或 .>
    local l=$1; shift
    timed "pack-$l" sh -c "tar -C '$OUT' -cf - $* 2>/dev/null | zstd -3 -T0 -q | wc -c > '$RES/size-$l.txt'"
    echo "pack-$l 壓縮後 $(cat "$RES/size-$l.txt") bytes"
  }
  est everything .
  # 只留下交付與紀錄需要的：Image、dtb、.ko、.config、System.map、Module.symvers、modules.order、.cmd
  ( cd "$OUT" && find . \( -name Image -path '*/arch/arm64/boot/*' -o -name '*.dtb' -o -name '*.ko' -o -name .config -o -name System.map -o -name Module.symvers -o -name 'modules.*' -o -name '.*.cmd' -o -name 'utsversion.h' -o -name compile.h -o -name kernel.release \) -type f ) > "$RES/deliver.list"
  echo "交付與紀錄檔：$(wc -l < "$RES/deliver.list") 個，$(cd "$OUT" && xargs -a "$RES/deliver.list" -d '\n' du -cb 2>/dev/null | tail -1 | cut -f1) bytes"
  est deliverables "-T '$RES/deliver.list'"
fi
snap_df 編譯後
sampler_stop
echo "nvbuild exit=$rc" > "$RES/rc.txt"
exit "$rc"
