#!/usr/bin/env bash
# 更新主機角色（需連網）：下載 ENISA 歐盟弱點資料庫（EUVD）的兩份官方大檔，產生精簡索引（CVE → EUVD 編號、是否在 KEV），並寫出 manifest。
# 來源（2026-11-02 實際下載核對；說明取自 https://euvd.enisa.europa.eu/apidoc）：
#   <API>/dump/cve-euvd-mapping  CSV（euvd_id,cve_id），只含已發布 CVE 的紀錄，每日 07:00 UTC 更新；實測 398,838 列、12 MB
#   <API>/kev/dump               JSON 陣列（cveId、euvdId、dateAdded、sources），CISA KEV 與 ENISA EU KEV 的合併，每日 07:00 UTC 更新；實測 1,783 筆
# 只用這兩個大檔（共 2 次請求），不逐筆查詢 /api/enisaid（一次 Jetson 掃描約 9000 個 CVE）。
# 索引由 tools/pilot/lib/euvd.py build 產生；--check 由原始檔重建索引比對，並檢查筆數與新舊（euvd.py check-mirror）。
# 內網：把整個資料夾放到掃描主機，tools/pilot/lib/euvd.py annotate --index <資料夾> 讀 index.tsv（不連網）。
# DT 的 ENISA KEV 來源檔不是這支產生的：tools/mirror/dt-feeds.sh 的 euvdkev 部分（DT_KEV_EUVD_FROM=<這個資料夾> 時沿用這裡的 kev-dump.json）；
#   deploy/pilot/euvd-mirror.sh 把它放在 <資料夾>/dt-feeds/（另有 <資料夾>.dt-feeds.manifest）。--check 時有 dt-feeds/ 就一併檢查。
# 用法：euvd.sh <鏡像輸出資料夾（必須全新）> <manifest 輸出檔>
#       euvd.sh --check <鏡像資料夾>
# 環境變數：EUVD_API_URL（預設 https://euvdservices.enisa.europa.eu/api）
#   EUVD_MAX_AGE_DAYS（--check 的下載時間上限，預設 3；檔案本身沒有發布日期，只能以下載時間判斷）
#   EUVD_KEV_MAX_AGE_DAYS（KEV 最新 dateAdded 的上限，預設 14，同 DT_KEV_MAX_AGE_DAYS）
#   EUVD_MIN_MAPPING_ROWS（預設 300000）、EUVD_MIN_KEV_ENTRIES（預設 1000）：少於這個數視為下載不完整
set -euo pipefail
API="${EUVD_API_URL:-https://euvdservices.enisa.europa.eu/api}"
LIB="$(cd "$(dirname "$0")/../pilot/lib" && pwd)/euvd.py"
check(){ local x=0
  python3 -I "$LIB" check-mirror "$1" || x=1
  # deploy/pilot/euvd-mirror.sh 的版面：同一份資料夾裡有 dt-feeds.sh 的 euvdkev 輸出（DT 的 ENISA KEV 來源檔）
  if [ -d "$1/dt-feeds" ]; then DT_FEEDS_PARTS=euvdkev bash "$(dirname "$0")/dt-feeds.sh" --check "$1/dt-feeds" || x=1; fi
  return $x; }
if [ "${1:-}" = "--check" ]; then check "${2:?缺少鏡像資料夾}"; exit $?; fi
DEST="${1:?用法見檔頭}"; MANIFEST="${2:?}"
for p in "$DEST" "$MANIFEST"; do [ ! -e "$p" ] || { echo "已存在，拒絕覆蓋：$p" >&2; exit 3; }; done
# 官方沒有公布速率限制（apidoc 只寫 search 每次最多 100 筆）；這裡只有 2 次請求，失敗時退避重試
get(){ local i; for i in 1 2 3 4 5; do rm -f "$2"
  curl -fsSL --http1.1 -m 900 -o "$2" "$1" && [ -s "$2" ] && return 0; echo "retry $i: $1" >&2; sleep $(( i * 10 )); done; return 1; }
mkdir -p "$DEST/raw"; FETCHED="$(date -u +%FT%TZ)"; T0=$(date +%s)
get "$API/dump/cve-euvd-mapping" "$DEST/raw/cve-euvd-mapping.csv"
sleep 2
get "$API/kev/dump" "$DEST/raw/kev-dump.json"
python3 -I "$LIB" build --raw "$DEST/raw" --fetched "$FETCHED" --out "$DEST/index.tsv"
check "$DEST"
{
  echo "# source_mapping: $API/dump/cve-euvd-mapping"; echo "# source_kev: $API/kev/dump"; echo "# fetched_utc: $FETCHED"
  echo "# seconds: $(( $(date +%s) - T0 ))"
  echo "# files: $(find "$DEST" -type f | wc -l)  bytes: $(du -sb "$DEST" | cut -f1)"
  (cd "$DEST" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
} > "$MANIFEST"
echo "OK mirror=$DEST manifest=$MANIFEST"
