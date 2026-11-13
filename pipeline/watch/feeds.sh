#!/usr/bin/env bash
# 每日監控的資料源（WATCH.md 第 3 節）：下載到 <輸出資料夾>，每個來源一行狀態；任何一個失敗不中止（match.py 依缺的來源標 GAP／NOT_RUN）。
# 用法：pipeline/watch/feeds.sh <輸出資料夾（必須不存在或是空的）> [--no-kernel-cve] [--no-euvd]
# 產出：
#   <out>/cisa-kev.json   CISA KEV（官方 feed；JSON 檢查：有 vulnerabilities 陣列、至少 CISA_KEV_MIN_ENTRIES 筆，預設 1000）
#   <out>/euvd/           tools/mirror/euvd.sh 的鏡像（index.tsv）
#   <out>/kernel-cve/     tools/mirror/kernel-cve.sh 的鏡像（SOURCE＋kernel-cves.zip）
#   Grype DB：grype db update（GRYPE_DB_CACHE_DIR；grype 要在 PATH）
#   <out>/feeds.tsv       來源<TAB>狀態<TAB>說明
# 下載的檔案一律當不可信資料：只讀、不執行。
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
out=${1:?用法：feeds.sh <輸出資料夾> [--no-kernel-cve] [--no-euvd]}
shift
kcve=1; euvd=1
for x in "$@"; do
  case "$x" in
    --no-kernel-cve) kcve=0 ;;
    --no-euvd) euvd=0 ;;
    *) echo "feeds: 不認得的參數 $x" >&2; exit 64 ;;
  esac
done
if [ -e "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then echo "feeds: $out 不是空的" >&2; exit 64; fi
mkdir -p "$out"
tsv="$out/feeds.tsv"
: > "$tsv"
row() { printf '%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$3" | tr '\t\n' '  ' | cut -c1-300)" | tee -a "$tsv"; }

# CISA KEV
CISA_KEV_URL=${CISA_KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}
if curl --fail --location --proto '=https' --proto-redir '=https' --silent --show-error --retry 3 --retry-delay 20 \
     --connect-timeout 30 --max-time 300 --max-filesize 104857600 --output "$out/cisa-kev.json.tmp" -- "$CISA_KEV_URL" 2> "$out/cisa.err"; then
  if msg=$(python3 -I - "$out/cisa-kev.json.tmp" "${CISA_KEV_MIN_ENTRIES:-1000}" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8-sig"))
v = d.get("vulnerabilities") if isinstance(d, dict) else None
if not isinstance(v, list) or len(v) < int(sys.argv[2]):
    sys.exit(f"vulnerabilities 不是陣列或少於 {sys.argv[2]} 筆")
print(f"{len(v)} 筆，dateReleased {d.get('dateReleased')}")
PY
  ); then mv "$out/cisa-kev.json.tmp" "$out/cisa-kev.json"; row cisa-kev OK "$msg"
  else rm -f "$out/cisa-kev.json.tmp"; row cisa-kev GAP "下載的檔案不合格：$msg"; fi
else
  rm -f "$out/cisa-kev.json.tmp"; row cisa-kev GAP "下載失敗：$(tail -n1 "$out/cisa.err")"
fi
rm -f "$out/cisa.err"

# EUVD
if [ "$euvd" = 1 ]; then
  if bash "$root/tools/mirror/euvd.sh" "$out/euvd" "$out/euvd.manifest" > "$out/euvd.log" 2>&1; then row euvd OK "$(tail -n1 "$out/euvd.log")"
  else row euvd GAP "tools/mirror/euvd.sh 失敗：$(tail -n1 "$out/euvd.log")"; fi
else row euvd NOT_RUN "--no-euvd"; fi

# 核心 CNA
if [ "$kcve" = 1 ]; then
  if bash "$root/tools/mirror/kernel-cve.sh" "$out/kernel-cve" "$out/kernel-cve.manifest" > "$out/kernel-cve.log" 2>&1; then row kernel-cve OK "$(tail -n1 "$out/kernel-cve.log")"
  else row kernel-cve GAP "tools/mirror/kernel-cve.sh 失敗：$(tail -n1 "$out/kernel-cve.log")"; fi
else row kernel-cve NOT_RUN "--no-kernel-cve"; fi

# Grype DB
if command -v grype > /dev/null; then
  if timeout 900 env GRYPE_CHECK_FOR_APP_UPDATE=false grype db update > "$out/grype-db.log" 2>&1; then
    row grype-db OK "$(timeout 60 grype db status 2>&1 | grep -E '^(Built|Status):' | tr '\n' ' ')"
  else row grype-db GAP "grype db update 失敗：$(tail -n1 "$out/grype-db.log")"; fi
else row grype-db NOT_RUN "grype 不在 PATH"; fi
exit 0
