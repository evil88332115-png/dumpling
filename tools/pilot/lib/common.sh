# 共用函式：由 tools/pilot/sca-scan 與 tools/e2e/real-projects.sh 載入（只定義函式，不執行任何步驟）。
# 這些函式是從 real-projects.sh 原樣搬出來的（行為不變）；grype_db_check 是 e2e 的 Grype DB 檢查。
# 呼叫前需要：status()（各腳本自己定義；寫 status.tsv）。runlog 需要 LOG。
# 狀態只用 OK／ATTENTION／GAP／NOT_ASSESSED／FAIL／NOT_RUN；OK 只表示該階段完成且輸出可用，不代表沒有弱點。

now(){ date -u +%FT%TZ; }

jlen(){  # 檔案 欄位（空字串＝頂層本身）→ 長度；無法解析時印 x
  python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));v=d.get(sys.argv[2]) if sys.argv[2] else d;print(len(v) if isinstance(v,list) else "x")' "$1" "${2:-}" 2>/dev/null || echo x; }

runlog(){  # 標籤 stdout檔 stderr檔 指令...：執行並把起訖時間、退出碼、指令記到 $LOG（指令列不可含秘密）
  local l=$1 o=$2 e=$3; shift 3; local s; s=$(now); local t0; t0=$(date +%s.%N)
  "$@" > "$o" 2> "$e"; local x=$?
  printf '%s\t%s\t%s\t%s\t%.1fs\t%s\n' "$l" "$s" "$(now)" "$x" "$(echo "$(date +%s.%N) - $t0" | bc)" "$*" >> "$LOG"; return $x; }

fetch_pinned(){  # 目的資料夾 git網址 完整commit：只取這個 commit（淺取），核對 HEAD，刪 .git；不執行專案的任何腳本
  local d=$1; rm -rf "$d"; mkdir -p "$d"
  git -C "$d" init -q && git -C "$d" remote add origin "$2" && git -C "$d" fetch -q --depth 1 origin "$3" && git -C "$d" checkout -q FETCH_HEAD \
    && [ "$(git -C "$d" rev-parse HEAD)" = "$3" ] && rm -rf "$d/.git"; }

copy_dir(){  # 來源 目的 [不複製的路徑...]：複製資料夾（不含 .git）。不複製的路徑在來源底下時排除
  # （sca-scan 的暫存區與輸出：暫存區有金鑰標頭檔，`sca-scan --dir .` 時就在來源底下，不排除會被複製進沙箱、打包上傳 ScanCode.io）
  local src p r; src=$(readlink -f "$1") || return 1; local dst=$2; shift 2; local ex=(--exclude=.git)
  for p in "$@"; do
    r=$(realpath -m --relative-to="$src" "$p") || return 1
    case $r in ..|../*|.) ;; *) ex+=(--anchored --no-wildcards "--exclude=./$r" --wildcards --no-anchored);; esac
  done
  tar -C "$src" "${ex[@]}" -cf - . | tar -C "$dst" -xf -; }

sbom_status(){  # 階段 退出碼 檔案：SBOM 產生器的結果（0 個元件是 NOT_ASSESSED，規則 12）
  local n; n=$(jlen "$3" components)
  if [ "$2" != 0 ]; then status "$1" FAIL "exit=$2"
  elif [ "$n" = x ]; then status "$1" FAIL "輸出不存在或無法解析"
  elif [ "$n" = 0 ]; then status "$1" NOT_ASSESSED "0 個元件（規則 12：不可當作不存在弱點）"
  else status "$1" OK "$n components"; fi; }

govuln_count(){  # govulncheck -format json 的輸出 → 不重複的 OSV ID 數；沒有 config 訊息或無法解析時印 x
  python3 -I -c '
import json,sys
t=open(sys.argv[1]).read();dec=json.JSONDecoder();i=0;ids=set();cfg=0
while i<len(t):
    while i<len(t) and t[i].isspace(): i+=1
    if i>=len(t): break
    o,i=dec.raw_decode(t,i);cfg+="config" in o
    if "finding" in o: ids.add(o["finding"]["osv"])
print(len(ids) if cfg else "x")' "$1" 2>/dev/null || echo x; }

dt_workflow_status(){  # workflow-runs 的 JSON 檔 BOM上傳token → 「名稱=狀態 …」（DT 5.2.0 /api/v2/internal/workflow-runs 的 items）
  python3 -I - "$1" "$2" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]));tok=sys.argv[2];o={}
for r in d.get('items',[]):
  if (r.get('labels') or {}).get('bom_upload_token')==tok: o[r['workflow_name']]=r['status']
print(' '.join(f'{k}={v}' for k,v in sorted(o.items())))
PY
}

grype_db_refresh(){  # grype執行檔 輸出資料夾 [模式，預設 $GRYPE_DB_UPDATE 或 online]：掃描前的 Grype DB 更新（明確的一步，與比對時的 db.auto-update 無關），印「OK|FAIL|NOT_RUN<TAB>說明」
  # online＝grype db update（連 Grype 官方下載網址；現在的做法）；import:<檔案或 URL>＝grype db import（正式離線部署：從本機鏡像匯入，鏡像做法見 tools/mirror/grype-db.sh）；
  # off＝不更新（測試，或 DB 由別處管理）→ NOT_RUN。記錄寫在 <輸出資料夾>/grype-db-update.log。
  local g=$1 o=$2 m=${3:-${GRYPE_DB_UPDATE:-online}} x
  case $m in
    online) "$g" db update > "$o/grype-db-update.log" 2>&1; x=$?
      if [ $x = 0 ]; then printf 'OK\t線上更新完成（grype db update）\n'; else printf 'FAIL\t更新失敗（exit=%s，%s）\n' "$x" "$(tail -1 "$o/grype-db-update.log" | tr '\t' ' ')"; fi;;
    import:-*|import:*[[:space:][:cntrl:]]*) printf 'FAIL\tGRYPE_DB_UPDATE=import: 的值不可以以 - 開頭或含空白、控制字元（避免被當成 grype 的選項）；沒有執行 grype\n';;
    import:?*) "$g" db import "${m#import:}" > "$o/grype-db-update.log" 2>&1; x=$?
      if [ $x = 0 ]; then printf 'OK\t已從鏡像匯入（grype db import %s）\n' "${m#import:}"; else printf 'FAIL\t鏡像匯入失敗（exit=%s，%s）\n' "$x" "$(tail -1 "$o/grype-db-update.log" | tr '\t' ' ')"; fi;;
    off) : > "$o/grype-db-update.log"; printf 'NOT_RUN\tGRYPE_DB_UPDATE=off：掃描前沒有更新 Grype DB，用現有資料庫\n';;
    import:) printf 'FAIL\tGRYPE_DB_UPDATE=import: 後面沒有給鏡像檔案或 URL\n';;
    *) printf 'FAIL\tGRYPE_DB_UPDATE 只接受 online、import:<檔案或 URL>、off（收到 %s）\n' "$(printf '%s' "$m" | cut -c1-60)";;
  esac; }

grype_db_eval(){  # grype執行檔 輸出資料夾 上限天數 更新結果(OK|FAIL|NOT_RUN) [嚴格 0|1，預設 0]：讀 grype db status 並判斷，印「狀態<TAB>說明」；年齡以小時顯示
  # 狀態不可用或讀不到 Built → FAIL；Built 超過上限（天×24 小時）→ GAP（不論更新是否成功）；
  # 更新失敗但在上限內 → ATTENTION；嚴格＝1（grype_db_check、每日監控）時更新失敗一律 FAIL（舊行為），且先於 GAP 判斷；其餘 OK。
  local g=$1 o=$2 max=${3:-1} ust=${4:-NOT_RUN} strict=${5:-0} udet=${6:-更新失敗} sx built dbst age lim
  "$g" db status > "$o/grype-db-status.txt" 2>&1; sx=$?
  built=$(sed -n 's/^Built:[[:space:]]*//p' "$o/grype-db-status.txt"); dbst=$(sed -n 's/^Status:[[:space:]]*//p' "$o/grype-db-status.txt")
  age=$(python3 -I -c 'import sys,datetime as d; b=d.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")); print("%.1f" % ((d.datetime.now(d.timezone.utc)-b).total_seconds()/3600))' "$built" 2>/dev/null)
  lim=$(python3 -I -c 'import sys,math; v=float(sys.argv[1])*24; assert math.isfinite(v) and v>0; print("%g" % v)' "$max" 2>/dev/null)
  if [ -z "$lim" ]; then printf 'FAIL\t設定錯誤：GRYPE_DB_MAX_AGE_DAYS=%s 必須是大於 0 的有限數字；更新：%s\n' "$(printf '%s' "$max" | cut -c1-30)" "$ust"
  elif [ $sx != 0 ] || [ "$dbst" != valid ] || [ -z "$age" ]; then printf 'FAIL\tdb status exit=%s Status=%s Built=%s；更新：%s\n' "$sx" "${dbst:-無}" "${built:-無}" "$ust"
  elif python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) < -0.1 else 1)' "$age"; then
    printf 'GAP\t資料庫 Built=%s（UTC）時間在未來（主機時鐘或資料異常，%s 小時）；更新：%s\n' "$built" "$age" "$ust"
  elif [ "$ust" = FAIL ] && [ "$strict" = 1 ]; then printf 'FAIL\t%s，沿用 Built=%s（UTC，%s 小時）的舊資料庫\n' "$udet" "$built" "$age"
  elif python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) > float(sys.argv[2]) else 1)' "$age" "$lim"; then
    printf 'GAP\t資料庫 Built=%s（UTC），已 %s 小時（上限 %s 小時）；更新：%s；結果可能漏掉新弱點\n' "$built" "$age" "$lim" "$ust"
  elif [ "$ust" = FAIL ]; then printf 'ATTENTION\t更新失敗，沿用 Built=%s（UTC，%s 小時，上限 %s 小時）的資料庫\n' "$built" "$age" "$lim"
  else printf 'OK\tBuilt=%s（UTC，%s 小時，上限 %s 小時）Status=%s\n' "$built" "$age" "$lim" "$dbst"; fi; }

grype_db_check(){  # grype執行檔 輸出資料夾 [上限天數，預設 1]：線上更新 Grype DB 並判斷狀態，印「狀態<TAB>說明」（每日監控 exploited-watch-daily.sh 用；更新失敗＝FAIL，嚴格）
  # 長期使用的機器會保留 ~/.cache/grype，更新失敗時 grype 會靜默沿用舊資料庫，所以更新失敗要當 FAIL。
  local r; r=$(grype_db_refresh "$1" "$2" online); grype_db_eval "$1" "$2" "${3:-1}" "${r%%$'\t'*}" 1 "${r#*$'\t'}"; }

pick_python(){  # [最低版本，預設 3.12]：印出第一個版本夠新的 Python 的路徑；都不夠新時回傳 1（不印）。
  # 順序：$SCA_PYTHON、${SCA_TOOLS_DIR:-/opt/sca-tools}/bin/python3（sudo 的 secure_path 不含這個資料夾）、python3.13、python3.12、python3。
  # 只執行 -I -c 檢查版本（不載入目前資料夾的模組；每個最多 10 秒）
  local min=${1:-3.12} c p to=()
  command -v timeout > /dev/null 2>&1 && to=(timeout 10)
  for c in "${SCA_PYTHON:-}" "${SCA_TOOLS_DIR:-/opt/sca-tools}/bin/python3" python3.13 python3.12 python3; do
    [ -n "$c" ] || continue
    case $c in */*) [ -x "$c" ] || continue; p=$c;; *) p=$(command -v "$c" 2>/dev/null) || continue;; esac
    if "${to[@]+"${to[@]}"}" "$p" -I -c 'import sys; m = tuple(int(x) for x in sys.argv[1].split(".")); sys.exit(0 if sys.version_info[:len(m)] >= m else 1)' "$min" 2>/dev/null; then
      printf '%s\n' "$p"; return 0; fi
  done
  return 1; }
