#!/usr/bin/env bash
# M2 spike 第 2 件：下載＋核對。用法：m2-download.sh <版本> <目的資料夾>
# 目的資料夾裡已經有檔案（例如從 actions/cache 還原）就不重下載，只核對 SHA-256（來源記為 cache）。
# 下載的檔案是不可信資料：只算雜湊、不解開、不執行。
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tools/spike/m2-lib.sh
. "$HERE/m2-lib.sh"
# shellcheck source=tools/spike/m2-release.sh
. "$HERE/m2-release.sh" "${1:?版本}"
D=${2:?目的資料夾}; mkdir -p "$D"; init_res
fail=0
TSV=$RES/downloads.tsv
[ -f "$TSV" ] || printf 'file\tsource\tbytes\tsha1\tsha256\tnvidia_sha1\tresult\n' > "$TSV"

timed fetch-hash-lists sh -c "curl -fsSL --retry 3 -m 120 -o '$D/release_sha_hashes.txt' '$REL/release/release_sha_hashes.txt' && curl -fsSL --retry 3 -m 120 -o '$D/public_sources_sha.txt' '$REL/sources/public_sources_sha.txt'"

fetch() {  # <檔名> <網址> <NVIDIA SHA-1 或空> <寫死的 SHA-256>
  local f=$1 url=$2 want1=$3 want256=$4 src=download got1 got256 sz res=OK
  if [ -s "$D/$f" ]; then src=cache
  else
    curl -fsSL --retry 3 --retry-max-time 1800 -m 3000 -o "$D/$f" "$url" || { echo "下載失敗：$f"; printf '%s\tdownload\t0\t\t\t%s\tFAIL-download\n' "$f" "$want1" >> "$TSV"; fail=1; return 1; }
  fi
  got1=$(sha1sum "$D/$f" | cut -d' ' -f1); got256=$(sha256sum "$D/$f" | cut -d' ' -f1); sz=$(stat -c %s "$D/$f")
  if [ -n "$want1" ] && [ "$got1" != "$want1" ]; then res="FAIL-sha1"; fail=1; fi
  if [ "$want256" = PENDING ]; then res="$res+SHA256-首次記錄(GAP:NVIDIA未公布整包SHA-1)"
  elif [ "$got256" != "$want256" ]; then res="FAIL-sha256"; fail=1; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$src" "$sz" "$got1" "$got256" "${want1:-無}" "$res" >> "$TSV"
  echo "$f: 來源=$src bytes=$sz sha1=$got1 sha256=$got256 → $res"
}
nv_sha1() { awk -v f="$1" '{n=$2; sub(/^\*/,"",n); sub(/^\.\//,"",n); if(n==f) print $1}' "$D/release_sha_hashes.txt"; }

pub=$(nv_sha1 "$BSP"); [ "$pub" = "$BSP_SHA1" ] || { echo "NVIDIA 公布的 $BSP SHA-1（${pub:-無}）和寫死的不同"; fail=1; }
pub=$(nv_sha1 "$RFS"); [ "$pub" = "$RFS_SHA1" ] || { echo "NVIDIA 公布的 $RFS SHA-1（${pub:-無}）和寫死的不同"; fail=1; }
timed "dl-bsp" fetch "$BSP" "$REL/release/$BSP" "$BSP_SHA1" "$BSP_SHA256"
timed "dl-rootfs" fetch "$RFS" "$REL/release/$RFS" "$RFS_SHA1" "$RFS_SHA256"
timed "dl-public_sources" fetch "$SRC" "$REL/sources/$SRC" "" "$SRC_SHA256"
echo "== 下載資料夾"; ls -l "$D"; du -sb "$D"
snap_df "下載後"
exit "$fail"
