#!/usr/bin/env bash
# 每日監控的資料源（WATCH.md 第 3 節）：下載到 <輸出資料夾>，每個來源一行狀態；任何一個失敗不中止（match.py 依缺的來源標 GAP／NOT_RUN）。
# 用法：pipeline/watch/feeds.sh <輸出資料夾（必須不存在或是空的）> [--no-kernel-cve] [--no-euvd]
# 環境變數：KCVE_CACHE_DIR（上一份核心 CVE 鏡像，actions/cache 還原的；見 pipeline/lib/mirrors.sh）、MIRRORS_TRIES、MIRRORS_RETRY_DELAY
#   INTERNAL_MIRROR_URL、DUMPLING_REQUIRE_INTERNAL_MIRROR、INTERNAL_MIRROR_FRESH_HOURS：內部鏡像模式（見下面「內部鏡像模式」與 pipeline/lib/mirrors.sh）
# 產出：
#   <out>/cisa-kev.json   CISA KEV（官方 feed；JSON 檢查：有 vulnerabilities 陣列、至少 CISA_KEV_MIN_ENTRIES 筆，預設 1000）
#   <out>/euvd/           tools/mirror/euvd.sh 的鏡像（index.tsv）；<out>/euvd.result 是腳本最後一行
#   <out>/kernel-cve/     tools/mirror/kernel-cve.sh 的鏡像（SOURCE＋kernel-cves.zip）；<out>/kernel-cve.result 是腳本最後一行
#   鏡像都經過 pipeline/lib/mirrors.sh（跟 Release 掃描同一份：最多試 MIRRORS_TRIES 次；最後一行 ATTENTION＝用了舊資料頂替，
#   例如 git.kernel.org 連不上、沿用 $KCVE_CACHE_DIR 裡 48 小時內的上一份 → feeds.tsv 記 ATTENTION，match.py 把那一行寫進報告與 Issue）。
#   失敗時刪掉不完整的資料夾（match.py 看到沒有資料夾 → NOT_RUN／GAP，不會讀到半份鏡像）。
#   Grype DB：grype db update（GRYPE_DB_CACHE_DIR；grype 要在 PATH）
#   <out>/feeds.tsv       來源<TAB>狀態<TAB>說明
# 內部鏡像模式（T-06；GitLab 的資料源都來自 runner 主機上的內部鏡像根目錄，斷外網也能跑）：設了 INTERNAL_MIRROR_URL=file:///<根目錄>
#   （或 DUMPLING_REQUIRE_INTERNAL_MIRROR=1）時，這支腳本不執行任何公開下載：沒有 curl、沒有 git clone、沒有 grype db update；失敗也不會改走公開網址。
#   - CISA KEV：mirror cisa-kev.sh（<根>/cisa-kev/，內容是 tools/mirror/cisa-kev.sh 的輸出，複製到 <out>/cisa-kev/）→ 檔案放到 <out>/cisa-kev.json（match.py 的讀取不變）。
#   - EUVD、核心 CVE：照樣經過 mirrors.sh 的 mirror／mirror_kernel_cve，它在內部模式自己改讀 <根>/euvd/、<根>/kernel-cve/（不用 KCVE_CACHE_DIR）。
#   - Grype DB：mirror grype-db.sh（<根>/grype-db/）通過 --check 之後 grype db import <複本裡的壓縮檔>，取代 grype db update；
#     grype 的 GRYPE_DB_AUTO_UPDATE、GRYPE_CHECK_FOR_APP_UPDATE 都設 false。比對階段（match.py）本來就用同樣的兩個設定，不會自己更新。
#   - 新鮮度：資料下載時間超過 INTERNAL_MIRROR_FRESH_HOURS（預設 36）小時 → feeds.tsv 記 ATTENTION；超過各鏡像 --check 的上限，
#     或根目錄底下沒有那種鏡像（例如 runner 主機還沒有同步 euvd、grype-db、cisa-kev）→ 記 GAP。feeds.tsv 每一列的說明都標明 source=internal 或「內部鏡像」。
#   - 每種鏡像在根目錄底下的子路徑預設是種類名稱（cisa-kev、euvd、kernel-cve、grype-db），可用 INTERNAL_MIRROR_PATH_<種類> 覆寫（見 mirrors.sh）；
#     cisa-kev 的子路徑可以直接指到單一 JSON 檔（沒有同步時間，只依 dateReleased：超過 7 天 ATTENTION、超過 14 天 GAP）。
#   - 失敗門檻：資料超過 INTERNAL_MIRROR_MAX_HOURS（預設 72）小時，或超過各鏡像 --check 的上限 → GAP。
#   - INTERNAL_MIRROR_URL 的值不合法（不是 file:///<絕對路徑>、含 ..、?、#、控制字元）、或 DUMPLING_REQUIRE_INTERNAL_MIRROR=1 卻沒設 INTERNAL_MIRROR_URL：
#     每個來源記 GAP、結束碼 64（不當作「沒設」，也不去公開網址）。INTERNAL_MIRROR_PATH_<種類> 的值不合法同理；解開之後跳出根目錄的，該來源記 GAP、最後結束碼 64。
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

# 內部鏡像模式與否（用法錯誤在任何下載之前就處理掉）；EUVD、核心 CNA 與內部模式的 KEV、Grype DB 都經過 pipeline/lib/mirrors.sh
. "$root/pipeline/lib/mirrors.sh"
internal=0; tag=""; usage_rc=0
mirror_internal_config; cfg=$?
case $cfg in
  0) internal=1; tag="（內部鏡像模式）" ;;
  1) ;;
  *)
    msg="INTERNAL_MIRROR_URL／DUMPLING_REQUIRE_INTERNAL_MIRROR 用法錯誤（原因在 stderr）：沒有下載任何資料，也沒有改走公開網址"
    row cisa-kev GAP "$msg"
    if [ "$euvd" = 1 ]; then row euvd GAP "$msg"; else row euvd NOT_RUN "--no-euvd"; fi
    if [ "$kcve" = 1 ]; then row kernel-cve GAP "$msg"; else row kernel-cve NOT_RUN "--no-kernel-cve"; fi
    row grype-db GAP "$msg"
    exit 64 ;;
esac

mirror_row() {  # <來源名> <成功與否> ：依 <out>/<名>.result 記 OK／ATTENTION；失敗記 GAP 並刪掉不完整的資料夾
  local n=$1 ok=$2 last
  [ "$ok" != 64 ] || usage_rc=64      # 子路徑變數跳出根目錄之類的用法錯誤：這個來源記 GAP，整支腳本最後結束碼 64
  if [ "$ok" = 0 ] && [ -f "$out/$n.result" ]; then
    last=$(head -n 1 "$out/$n.result")
    case $last in ATTENTION*) row "$n" ATTENTION "$last" ;; *) row "$n" OK "$last" ;; esac      # ::warning:: 由 mirror 印
  else
    rm -rf "${out:?}/$n" "$out/$n.result"
    if [ "$internal" = 1 ]; then row "$n" GAP "內部鏡像 $n 不可用（沒有改走公開網址）：$(tail -n 1 "$out/$n.log" 2>/dev/null)"
    else row "$n" GAP "tools/mirror/$n.sh 失敗：$(tail -n 1 "$out/$n.log" 2>/dev/null)"; fi
  fi
}
export MIRRORS_DIR="$out"
unset MIRRORS_STEPS

# CISA KEV
CISA_KEV_URL=${CISA_KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}
if [ "$internal" = 1 ]; then
  # 內部鏡像：不 curl。複本在 <out>/cisa-kev/（SOURCE 與原檔），通過 --check 之後把檔案放到 match.py 讀的位置
  mirror cisa-kev.sh cisa-kev; kok=$?
  if [ "$kok" = 0 ] && [ -f "$out/cisa-kev/known_exploited_vulnerabilities.json" ] && [ ! -L "$out/cisa-kev/known_exploited_vulnerabilities.json" ]; then
    cp -- "$out/cisa-kev/known_exploited_vulnerabilities.json" "$out/cisa-kev.json" || { kok=1; rm -f "$out/cisa-kev.json"; echo "複製 cisa-kev.json 失敗" >> "$out/cisa-kev.log"; }
  elif [ "$kok" = 0 ]; then
    kok=1; echo "內部鏡像 cisa-kev 沒有 known_exploited_vulnerabilities.json" >> "$out/cisa-kev.log"
  fi
  mirror_row cisa-kev "$kok"
elif curl --fail --location --proto '=https' --proto-redir '=https' --silent --show-error --retry 3 --retry-delay 20 \
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

# EUVD、核心 CNA：經過 pipeline/lib/mirrors.sh（不在這裡另寫一份重試／頂替規則）
# mirror 的進度（第幾次失敗、OK／ATTENTION）直接印在 log；鏡像腳本自己的輸出在 <out>/<名>.log
if [ "$euvd" = 1 ]; then
  mirror euvd.sh euvd; mirror_row euvd $?
else row euvd NOT_RUN "--no-euvd$tag"; fi
# 核心 CVE：kernel-cve.sh 自己會重試 clone（KERNEL_CVE_GIT_TRIES，預設 3 次、每次最多 KERNEL_CVE_GIT_TIMEOUT=900 秒），
# mirror 再整支重試 3 次會疊成兩個多小時、超過 compute job 的上限 → 每日監控預設只讓 mirror 試 1 次（WATCH_KCVE_MIRROR_TRIES 可改）。
# 上游連不上時有 $KCVE_CACHE_DIR 就用 48 小時內的上一份頂替（ATTENTION），不用一直重試。
if [ "$kcve" = 1 ]; then
  MIRRORS_TRIES=${WATCH_KCVE_MIRROR_TRIES:-1} mirror_kernel_cve kernel-cve; mirror_row kernel-cve $?
else row kernel-cve NOT_RUN "--no-kernel-cve$tag"; fi

# Grype DB
if command -v grype > /dev/null; then
  if [ "$internal" = 1 ]; then
    # 內部鏡像：不 grype db update。複本通過 --check（含匯入測試）之後匯入複本裡的壓縮檔；匯入完刪掉複本（資料庫很大）
    mirror grype-db.sh grype-db; gok=$?
    if [ "$gok" = 0 ] && garc=$(grype_db_archive grype-db); then
      if timeout 900 env GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_AUTO_UPDATE=false grype db import "$garc" >> "$out/grype-db.log" 2>&1; then
        gres=$(head -n 1 "$out/grype-db.result")
        gst=OK; case $gres in ATTENTION*) gst=ATTENTION ;; esac
        row grype-db "$gst" "$gres；已匯入（grype db import）：$(timeout 60 env GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_AUTO_UPDATE=false grype db status 2>&1 | grep -E '^(Built|Status):' | tr '\n' ' ')"
      else row grype-db GAP "內部鏡像 grype-db 的 grype db import 失敗（沒有改走公開網址）：$(tail -n1 "$out/grype-db.log")"; fi
      rm -rf "${out:?}/grype-db"
    else
      [ "$gok" != 0 ] || { gok=1; echo "內部鏡像 grype-db 沒有可匯入的壓縮檔" >> "$out/grype-db.log"; }
      mirror_row grype-db "$gok"
    fi
  elif timeout 900 env GRYPE_CHECK_FOR_APP_UPDATE=false grype db update > "$out/grype-db.log" 2>&1; then
    row grype-db OK "$(timeout 60 grype db status 2>&1 | grep -E '^(Built|Status):' | tr '\n' ' ')"
  else row grype-db GAP "grype db update 失敗：$(tail -n1 "$out/grype-db.log")"; fi
else row grype-db NOT_RUN "grype 不在 PATH$tag"; fi
exit "$usage_rc"
