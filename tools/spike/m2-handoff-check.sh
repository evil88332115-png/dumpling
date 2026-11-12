#!/usr/bin/env bash
# M2 spike：下一個 job 把 artifact（交付與紀錄檔）與 cache（整個輸出資料夾）解開，
# 核對 Image 的 SHA-256，並用 pack-build-record.sh 重新打包，比對檔案清單是否和編譯 job 一致。
# 用法：m2-handoff-check.sh <artifact 資料夾> <cache 資料夾> <工作資料夾>
# 路徑要和編譯 job 相同（.cmd 檔裡有絕對路徑），所以輸出放 <工作資料夾>/out。
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
# shellcheck source=tools/spike/m2-lib.sh
. "$HERE/m2-lib.sh"
A=${1:?artifact 資料夾}; C=${2:?cache 資料夾}; W=${3:?工作資料夾}; init_res
ls -l "$A" "$C"
want=$(cat "$A/image.sha256"); wantlist=$(cat "$A/buildrecord.listsha"); fail=0
check() { # <標籤> <壓縮檔>
  local l=$1 f=$2 O=$W/out
  rm -rf "$O"; mkdir -p "$O"
  timed "untar-$l" sh -c "zstd -d -q -c '$f' | tar -x -C '$O' --no-same-owner --no-same-permissions"
  local K=$O/kernel/kernel-noble
  got=$(sha256sum "$K/arch/arm64/boot/Image" | cut -d' ' -f1)
  [ "$got" = "$want" ] && echo "[$l] Image SHA-256 相符 ($got)" || { echo "[$l] Image SHA-256 不符：$got 對 $want"; fail=1; }
  oot=()
  for d in nvidia-oot nvgpu nvdisplay hwpm nvethernetrm unifiedgpudisp/kernel-open; do [ -d "$O/$d" ] && oot+=("$O/$d"); done
  timed "pack-$l" bash "$ROOT/tools/demo/pack-build-record.sh" "$K" "$RES/BR-$l.tar.gz" "${oot[@]}"
  gotlist=$(tar -tzf "$RES/BR-$l.tar.gz" | sort | sha256sum | cut -d' ' -f1)
  # BUILD-INFO.txt 內容含時間，但檔名相同；清單只比檔名
  [ "$gotlist" = "$wantlist" ] && echo "[$l] BuildRecord 檔案清單與編譯 job 相同" || { echo "[$l] BuildRecord 檔案清單不同（$gotlist 對 $wantlist）"; fail=1; }
  du -sb "$O" | cut -f1
}
check deliverables "$A/deliverables.tar.zst"
check everything "$C/everything.tar.zst"
snap_df 完成
exit "$fail"
