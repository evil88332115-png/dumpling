#!/usr/bin/env bash
# 弱點資料鏡像的共用函式（source 進來用；各平台的 scan.sh 共用，不要各寫一份）。
#
#   source pipeline/lib/mirrors.sh
#   MIRRORS_DIR=<鏡像的輸出資料夾> MIRRORS_STEPS=<pipeline-steps.tsv> mirror <tools/mirror 底下的腳本> <資料夾名>
#   mirror_kernel_cve <資料夾名>        （kernel-cve.sh；有 $KCVE_CACHE_DIR 就當作上一份鏡像：沒變就沿用、上游連不上就退而求其次）
#
# 環境變數：
#   MIRRORS_DIR          必填。鏡像放這裡：<資料夾名>/、<資料夾名>.manifest、<資料夾名>.log、<資料夾名>.result（腳本最後一行）
#   MIRRORS_STEPS        pipeline-steps.tsv 的路徑；沒設就不記列（單獨使用時）
#   MIRRORS_SCRIPT_DIR   鏡像腳本所在資料夾（預設是這個 repo 的 tools/mirror）
#   MIRRORS_TRIES        最多試幾次（預設 3，每次換新資料夾）；MIRRORS_RETRY_DELAY 兩次之間等幾秒（預設 60）
#   KCVE_CACHE_DIR       上一份 kernel-cve 鏡像（actions/cache 還原出來的資料夾，裡面有 kernel-cves.zip 與 SOURCE）
#
# 結果看腳本輸出的最後一行：
#   OK …         成功。
#   ATTENTION …  成功，但用了舊資料頂替（例如核心 CVE：git.kernel.org 與備援來源都連不上、沿用 48 小時內的上一份）：繼續往下走，並在 pipeline-steps.tsv 記一列
#                「pipeline-<腳本名>-mirror	ATTENTION	0	<那一行>」（整體狀態因此不是 OK，也不會 FAIL；報告、release-meta.json、Release 說明都看得到）。
#   其他（含結束碼不是 0）  這一次失敗；試完 MIRRORS_TRIES 次都失敗 → mirror 回傳 1（弱點資料不完整，不能當作沒有漏洞）。
# 回傳值：0＝成功（OK 或 ATTENTION）；1＝失敗。呼叫端自己決定怎麼 fail。成功時印一行「鏡像 <名>：OK｜ATTENTION（…）」。
#
# 內部鏡像模式（T-06，GITLAB-PORT 第 6 節）：設了 INTERNAL_MIRROR_URL（或 DUMPLING_REQUIRE_INTERNAL_MIRROR=1）時，mirror 完全不執行下載腳本，
# 也不會因為任何原因改走公開網址或 KCVE_CACHE_DIR 的舊資料；沒設的時候，行為與輸出和以前逐字相同。
#   INTERNAL_MIRROR_URL                  file:///<runner 主機上內部鏡像根目錄的絕對路徑>（例如 file:///srv/mirror）。只收這一種形式：
#                                        https://、相對路徑、含 ..、?、#、空白或控制字元的值都是用法錯誤（回傳 64），不會被當成「沒設」。空字串等於沒設。
#   DUMPLING_REQUIRE_INTERNAL_MIRROR=1   GitLab 範本固定設這個：INTERNAL_MIRROR_URL 沒設（或是空的）也是用法錯誤（回傳 64），不會默默去公開網址。
#   INTERNAL_MIRROR_FRESH_HOURS          新鮮門檻（小時，預設 36）：資料的下載時間（SOURCE 的 fetched_utc；EUVD 讀 index.tsv 第 1 行；Grype DB 讀 latest.json 的 built）
#                                        超過這個值 → 最後一行 ATTENTION（照現有的 ATTENTION 路徑記進 MIRRORS_STEPS）。
#   INTERNAL_MIRROR_MAX_HOURS            失敗門檻（小時，預設 72，不可小於新鮮門檻）：超過就失敗（mirror 回傳 1）。各腳本自己的 --check 也有上限
#                                        （核心 7 天、EUVD 3 天…），兩者取較嚴的：超過 --check 的上限 → --check 失敗 → mirror 回傳 1。
#   INTERNAL_MIRROR_PATH_<種類>          這一種鏡像在根目錄底下的子路徑（種類名稱大寫、- 換成 _：INTERNAL_MIRROR_PATH_KERNEL_CVE、…_EUVD、…_OSV_DISTRO、
#                                        …_NVIDIA_BULLETINS、…_GRYPE_DB、…_CISA_KEV）。預設是種類名稱本身（kernel-cve、euvd、osv-distro、nvidia-bulletins、
#                                        grype-db、cisa-kev）。必須是相對路徑，不可含 ..、控制字元；解開符號連結之後必須還在根目錄裡面，跳出去是用法錯誤（回傳 64）。
#   INTERNAL_MIRROR_KEV_FILE_FRESH_DAYS  cisa-kev 的子路徑指到單一 JSON 檔時（沒有 SOURCE、沒有同步時間）的 ATTENTION 門檻（天，預設 7）：
#                                        只依檔案裡的 dateReleased；超過 CISA_KEV_MAX_RELEASE_AGE_DAYS（預設 14 天）就失敗。不用檔案的 mtime（複製時可能被改掉）。
# 內容就是 tools/mirror/<種類>.sh 的輸出。mirror <腳本> <資料夾名> 在內部模式下的步驟（種類由腳本名決定：kernel-cve.sh → kernel-cve，
# 另有 euvd、osv-distro、nvidia-bulletins、grype-db、cisa-kev）：
#   1. <根>/<子路徑> 要存在、是資料夾（cisa-kev 可以是單一 JSON 檔）；資料夾裡面只有一般檔案與資料夾（符號連結、FIFO、裝置一律失敗）；
#   2. 複製到 $MIRRORS_DIR/<資料夾名>（cp -R --no-dereference；單一檔案複製成 known_exploited_vulnerabilities.json），複製後再檢查一次型別；
#   3. 跑 <腳本> --check <複本>（單一檔案：cisa-kev.sh --check-file；失敗＝這個來源失敗）；
#   4. 依新鮮門檻決定 OK 或 ATTENTION、依失敗門檻決定失敗；寫 .result（開頭 OK|ATTENTION，帶 source=internal 與種類，不寫主機名或路徑）、.manifest、.log。
#      單一檔案模式沒有同步時間：.result 固定寫「同步時間不明（單一檔案，只依 dateReleased）」，OK 也一樣。
# 只試一次（本機複製，不重試）。回傳值：0＝成功（OK 或 ATTENTION）；1＝這個來源不可用（呼叫端：scan 要 FAIL、feeds.sh 記 GAP）；
#   64＝用法錯誤（變數的值不合法；呼叫端一律失敗，不可改走公開下載）。mirror_is_fresh 在內部模式一律回傳 1（內部複本不存回 cache）。
# grype_db_mode <資料夾名>：給 sca-scan 的 GRYPE_DB_UPDATE 值。公開模式印 online；內部模式先 mirror grype-db.sh 之後印 import:<複本裡的壓縮檔>
#   （內部模式絕不印 online；鏡像不可用就回傳 1、什麼都不印）。目前 scan.sh 還沒有改用它（T-06 PR-2）。
_mirrors_lib=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

_mirror_public() {  # <腳本> <資料夾名>：公開模式（沒設 INTERNAL_MIRROR_URL）：跟以前完全一樣
  local s=$1 d=$2 n ok=0 tries=${MIRRORS_TRIES:-3} last=""
  local mir=${MIRRORS_DIR:?MIRRORS_DIR 必填} sd=${MIRRORS_SCRIPT_DIR:-$_mirrors_lib/../../tools/mirror}
  mkdir -p "$mir" || return 1
  for n in $(seq 1 "$tries"); do
    rm -rf "${mir:?}/$d" "$mir/$d.manifest" "$mir/$d.result"
    if bash "$sd/$s" "$mir/$d" "$mir/$d.manifest" > "$mir/$d.log" 2>&1; then
      last=$(grep -v '^[[:space:]]*$' "$mir/$d.log" | tail -n 1)
      case $last in OK|OK\ *|ATTENTION|ATTENTION\ *) ok=1; break;; esac
      echo "鏡像 $d 第 $n 次：結束碼 0，但最後一行不是 OK 或 ATTENTION：$(printf '%s' "$last" | cut -c1-200)"
    else
      echo "鏡像 $d 第 $n 次失敗：$(tail -n 1 "$mir/$d.log" | cut -c1-200)"
    fi
    [ "$n" = "$tries" ] || sleep "${MIRRORS_RETRY_DELAY:-60}"
  done
  if [ $ok != 1 ]; then tail -n 5 "$mir/$d.log"; return 1; fi
  printf '%s\n' "$last" > "$mir/$d.result"
  case $last in
    ATTENTION*)
      echo "鏡像 $d：ATTENTION（$last）"
      echo "::warning::鏡像 $d 用了舊資料頂替：$last"
      if [ -n "${MIRRORS_STEPS:-}" ]; then
        python3 -I "$_mirrors_lib/step_rows.py" append "$MIRRORS_STEPS" "${s%.sh}-mirror" ATTENTION 0 "$last" || return 1
      fi;;
    *) echo "鏡像 $d：OK（$(printf '%s' "$last" | cut -c1-160)）";;
  esac
}

# ---------- 內部鏡像模式 ----------

_mirror_internal_intent() {  # 有任何要用內部鏡像的跡象（URL 非空、或要求一定要內部鏡像）→ 0
  [ -n "${INTERNAL_MIRROR_URL:-}" ] && return 0
  case ${DUMPLING_REQUIRE_INTERNAL_MIRROR:-} in ""|0) return 1;; *) return 0;; esac
}

_mirror_pos_num() {  # <值>：大於 0 的數字 → 0
  [[ $1 =~ ^[0-9]+(\.[0-9]+)?$ ]] && [ -n "$(printf '%s' "$1" | tr -d '0.')" ]
}

_mirror_internal_kinds=(kernel-cve euvd osv-distro nvidia-bulletins grype-db cisa-kev)

_mirror_internal_pathvar() {  # <種類>：印子路徑變數的名稱（INTERNAL_MIRROR_PATH_KERNEL_CVE…）
  printf 'INTERNAL_MIRROR_PATH_%s' "$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')"
}

_mirror_internal_subpath() {  # <種類>：印這一種鏡像在根目錄底下的子路徑（變數沒設或是空的 → 種類名稱本身；尾端的 / 去掉）
  local name sv
  name=$(_mirror_internal_pathvar "$1")
  sv=${!name-}
  sv=${sv%/}
  printf '%s' "${sv:-$1}"
}

# 讀 INTERNAL_MIRROR_URL、DUMPLING_REQUIRE_INTERNAL_MIRROR、INTERNAL_MIRROR_FRESH_HOURS、INTERNAL_MIRROR_MAX_HOURS、INTERNAL_MIRROR_KEV_FILE_FRESH_DAYS、
# INTERNAL_MIRROR_PATH_<種類>。回傳 0＝內部模式（根目錄放在 MIRROR_INTERNAL_ROOT；門檻放在 MIRROR_INTERNAL_FRESH、MIRROR_INTERNAL_MAX、
# MIRROR_INTERNAL_KEV_FILE_FRESH，單位都是小時）；1＝沒設（公開模式）；64＝用法錯誤（訊息印在 stderr；不印變數的值，URL 可能帶帳密）。
mirror_internal_config() {
  local LC_ALL=C
  local v=${INTERNAL_MIRROR_URL-} req=${DUMPLING_REQUIRE_INTERNAL_MIRROR-} fresh=${INTERNAL_MIRROR_FRESH_HOURS-} max=${INTERNAL_MIRROR_MAX_HOURS-}
  local kevd=${INTERNAL_MIRROR_KEV_FILE_FRESH_DAYS-} p="" why="" k name sv
  MIRROR_INTERNAL_ROOT=""
  MIRROR_INTERNAL_FRESH=36
  MIRROR_INTERNAL_MAX=72
  MIRROR_INTERNAL_KEV_FILE_FRESH=168
  case $req in
    ""|0) req=0;;
    1) ;;
    *) why="DUMPLING_REQUIRE_INTERNAL_MIRROR 只接受 1（要求內部鏡像）或 0／空（不要求）";;
  esac
  if [ -z "$why" ]; then
    if [ -z "$v" ]; then
      [ "$req" = 1 ] || return 1
      why="DUMPLING_REQUIRE_INTERNAL_MIRROR=1，但 INTERNAL_MIRROR_URL 沒設或是空的"
    else
      case $v in
        file:///*)
          p=${v#file://}; p=${p%/}
          if ! [[ $p =~ ^(/[A-Za-z0-9._+@,=:-]+)+$ ]]; then
            why="INTERNAL_MIRROR_URL 的路徑含有不允許的字元、空的路徑段，或是根目錄本身（只收英數字與 . _ + @ , = : -）"
          elif [[ $p == *..* ]] || [[ $p =~ (^|/)\.(/|$) ]]; then
            why="INTERNAL_MIRROR_URL 的路徑不可以含 .."
          fi;;
        *) why="INTERNAL_MIRROR_URL 只收 file:///<絕對路徑>（不收 https://、相對路徑或其他形式）";;
      esac
    fi
  fi
  if [ -z "$why" ] && [ -n "$fresh" ]; then
    if _mirror_pos_num "$fresh"; then MIRROR_INTERNAL_FRESH=$fresh
    else why="INTERNAL_MIRROR_FRESH_HOURS 必須是大於 0 的數字"; fi
  fi
  if [ -z "$why" ] && [ -n "$max" ]; then
    if _mirror_pos_num "$max"; then MIRROR_INTERNAL_MAX=$max
    else why="INTERNAL_MIRROR_MAX_HOURS 必須是大於 0 的數字"; fi
  fi
  if [ -z "$why" ] && ! awk -v a="$MIRROR_INTERNAL_MAX" -v b="$MIRROR_INTERNAL_FRESH" 'BEGIN { exit !(a + 0 >= b + 0) }'; then
    why="INTERNAL_MIRROR_MAX_HOURS（失敗門檻）不可以小於 INTERNAL_MIRROR_FRESH_HOURS（ATTENTION 門檻）"
  fi
  if [ -z "$why" ] && [ -n "$kevd" ]; then
    if _mirror_pos_num "$kevd"; then MIRROR_INTERNAL_KEV_FILE_FRESH=$(awk -v d="$kevd" 'BEGIN { printf "%.3f", d * 24 }')
    else why="INTERNAL_MIRROR_KEV_FILE_FRESH_DAYS 必須是大於 0 的數字"; fi
  fi
  if [ -z "$why" ]; then
    for k in "${_mirror_internal_kinds[@]}"; do
      name=$(_mirror_internal_pathvar "$k")
      sv=${!name-}; sv=${sv%/}
      [ -z "$sv" ] && continue
      if ! [[ $sv =~ ^[A-Za-z0-9._+@,=:-]+(/[A-Za-z0-9._+@,=:-]+)*$ ]] || [[ $sv == *..* ]] || [[ $sv =~ (^|/)\.(/|$) ]]; then
        why="$name 必須是相對於根目錄的路徑（不可以是絕對路徑，不可含 ..、控制字元或空白；只收英數字與 . _ + @ , = : -）"
        break
      fi
    done
  fi
  if [ -n "$why" ]; then
    printf '鏡像：用法錯誤：%s。不下載任何資料，也不會改走公開網址。\n' "$why" >&2
    return 64
  fi
  MIRROR_INTERNAL_ROOT=$p
  return 0
}

_mirror_internal_scan() {  # <資料夾>：不是一般檔案或資料夾的東西 → 印第一個的相對路徑（已清掉控制字元）並回傳 1；走訪失敗回傳 2；乾淨回傳 0
  local d=$1 out rc
  out=$(find "$d/" -mindepth 1 ! -type f ! -type d -print -quit 2>&1); rc=$?
  [ "$rc" -eq 0 ] || { printf '無法走訪資料夾'; return 2; }
  if [ -n "$out" ]; then printf '%s' "${out#"$d"/}" | tr -c '[:print:]' '?'; return 1; fi
  return 0
}

# 資料的時間：印「<欄位名>TAB<UTC 時間>TAB<幾小時前>TAB<超過新鮮門檻 0|1>TAB<SOURCE 標了 fallback=yes 0|1>TAB<超過失敗門檻 0|1>」；
# 讀不到、無法解析或在未來 → 回傳 1（原因印在 stderr）。種類 cisa-kev-file＝單一 JSON 檔：時間是檔案裡的 dateReleased（沒有 SOURCE，不用 mtime）。
_mirror_internal_age() {  # <種類> <複本資料夾> <新鮮門檻小時> <失敗門檻小時（inf＝不在這裡判斷）>
  python3 -I - "$1" "$2" "$3" "$4" <<'PY'
import datetime, json, os, sys
kind, d, fresh, mx = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
def fail(m):
    print(m, file=sys.stderr); sys.exit(1)
fb = 0
try:
    if kind == "euvd":
        key = "fetched_utc"
        with open(os.path.join(d, "index.tsv"), encoding="utf-8") as f:
            first = f.readline().rstrip("\n").split("\t")
        val = dict(x.split("=", 1) for x in first[1:] if "=" in x).get(key)
    elif kind == "grype-db":
        key = "built_utc"
        with open(os.path.join(d, "v6", "latest.json"), encoding="utf-8") as f:
            val = json.load(f).get("built")
    elif kind == "cisa-kev-file":
        key = "date_released"
        with open(os.path.join(d, "known_exploited_vulnerabilities.json"), encoding="utf-8-sig") as f:
            val = json.load(f).get("dateReleased")
    else:
        key = "fetched_utc"
        with open(os.path.join(d, "SOURCE"), encoding="utf-8") as f:
            src = dict(x.split("=", 1) for x in f.read().splitlines() if "=" in x)
        val = src.get(key)
        fb = 1 if src.get("fallback") == "yes" else 0
    if not isinstance(val, str) or not val:
        fail(f"沒有 {key}（無法判斷新舊）")
    t = datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
    if t.tzinfo is None:
        if kind == "cisa-kev-file":
            t = t.replace(tzinfo=datetime.timezone.utc)
        else:
            fail(f"{key} 沒有時區：{val[:40]!r}")
except (OSError, ValueError, AttributeError, RecursionError) as e:
    fail(f"讀不到可解析的資料時間（{type(e).__name__}）")
h = (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() / 3600
if h < -24 if kind == "cisa-kev-file" else h < -1:
    fail(f"{key} 在未來（{val[:40]}；主機時鐘或資料異常）")
print("\t".join([key, t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "%.1f" % max(h, 0.0),
                 "1" if h > fresh else "0", str(fb), "1" if h > mx else "0"]))
PY
}

_mirror_internal_fail() {  # <資料夾名> <種類> <原因>：原因寫進 .log，刪掉不完整的複本與 .result，回傳 1
  local d=$1 kind=$2 why=$3 mir=${MIRRORS_DIR:?}
  printf '%s\n' "$why" >> "$mir/$d.log"
  rm -rf "${mir:?}/${d:?}" "${mir:?}/${d:?}.manifest" "${mir:?}/${d:?}.result"
  echo "鏡像 $d 失敗（內部鏡像 $kind，不改走公開網址）：$(printf '%s' "$why" | cut -c1-300)"
  return 1
}

_mirror_internal_usage() {  # <資料夾名> <原因>：用法錯誤（回傳 64）：跟失敗一樣清掉輸出，訊息印在 stderr
  local d=$1 why=$2 mir=${MIRRORS_DIR:?}
  rm -rf "${mir:?}/${d:?}" "${mir:?}/${d:?}.manifest" "${mir:?}/${d:?}.result"
  printf '%s\n' "$why" >> "$mir/$d.log"
  printf '鏡像 %s：用法錯誤：%s。不下載任何資料，也不會改走公開網址。\n' "$d" "$why" >&2
  return 64
}

_mirror_internal() {  # <腳本> <資料夾名>（先呼叫過 mirror_internal_config 並得到 0）。回傳 0／1／64（子路徑跳出根目錄）
  local s=$1 d=$2 kind mir=${MIRRORS_DIR:?MIRRORS_DIR 必填} sd=${MIRRORS_SCRIPT_DIR:-$_mirrors_lib/../../tools/mirror}
  local root=$MIRROR_INTERNAL_ROOT src dest sub bad rc info key val hours over fb overmax last why="" srcsha n rroot rsrc meta mode=dir fresh sz
  kind=${s%.sh}
  mkdir -p "$mir" || return 1
  rm -rf "${mir:?}/${d:?}" "${mir:?}/${d:?}.manifest" "${mir:?}/${d:?}.result"
  : > "$mir/$d.log"
  case $kind in
    kernel-cve|euvd|osv-distro|nvidia-bulletins|grype-db|cisa-kev) ;;
    *) _mirror_internal_fail "$d" "$kind" "腳本 $s 沒有對應的內部鏡像種類（只有 kernel-cve、euvd、osv-distro、nvidia-bulletins、grype-db、cisa-kev）"; return 1;;
  esac
  sub=$(_mirror_internal_subpath "$kind")
  src=$root/$sub
  dest=$mir/$d
  [ -d "$root" ] || { _mirror_internal_fail "$d" "$kind" "內部鏡像根目錄不存在或不是資料夾"; return 1; }
  [ -e "$src" ] || { _mirror_internal_fail "$d" "$kind" "內部鏡像根目錄底下沒有 $kind 的子路徑（$sub）：這種鏡像還沒有同步到 runner 主機"; return 1; }
  rroot=$(realpath -e -- "$root") && rsrc=$(realpath -e -- "$src") || { _mirror_internal_fail "$d" "$kind" "無法解開 $kind 的子路徑"; return 1; }
  case $rsrc in
    "$rroot"/*) ;;
    *) _mirror_internal_usage "$d" "$(_mirror_internal_pathvar "$kind") 的子路徑解開之後跳出了內部鏡像根目錄"; return 64;;
  esac
  # 之後的檢查與複製一律用解開後的 $rsrc：頂層的符號連結在「檢查」與「複製」之間被換掉，也不會改去複製根目錄外的東西
  if [ -f "$rsrc" ] && [ ! -L "$rsrc" ]; then
    [ "$kind" = cisa-kev ] || { _mirror_internal_fail "$d" "$kind" "$kind 的子路徑是檔案（只有 cisa-kev 可以指到單一 JSON 檔）"; return 1; }
    mode=file
  elif [ ! -d "$rsrc" ] || [ -L "$rsrc" ]; then
    _mirror_internal_fail "$d" "$kind" "$kind 的子路徑不是資料夾"; return 1
  fi
  mkdir -p "$dest" || return 1
  if [ "$mode" = file ]; then
    # 單一 JSON 檔（沒有 SOURCE）：複製成資料夾模式一樣的檔名，feeds.sh 與 match.py 的讀取不變
    sz=$(stat -c %s -- "$rsrc" 2> /dev/null) || sz=
    if [ -z "$sz" ] || [ "$sz" -gt "${CISA_KEV_MAX_BYTES:-104857600}" ] 2> /dev/null; then
      _mirror_internal_fail "$d" "$kind" "單一檔案讀不到大小，或超過 CISA_KEV_MAX_BYTES（預設 100 MB）"; return 1
    fi
    cp -- "$rsrc" "$dest/known_exploited_vulnerabilities.json" 2>> "$mir/$d.log" || { _mirror_internal_fail "$d" "$kind" "複製單一檔案失敗"; return 1; }
    { [ -f "$dest/known_exploited_vulnerabilities.json" ] && [ ! -L "$dest/known_exploited_vulnerabilities.json" ]; } \
      || { _mirror_internal_fail "$d" "$kind" "複製之後的檔案不是一般檔案"; return 1; }
    if ! bash "$sd/$s" --check-file "$dest/known_exploited_vulnerabilities.json" >> "$mir/$d.log" 2>&1; then
      _mirror_internal_fail "$d" "$kind" "$s --check-file 失敗：$(grep -v '^[[:space:]]*$' "$mir/$d.log" | tail -n 1 | cut -c1-200)"; return 1
    fi
    info=$(_mirror_internal_age cisa-kev-file "$dest" "$MIRROR_INTERNAL_KEV_FILE_FRESH" inf 2>> "$mir/$d.log"); rc=$?
  else
    bad=$(_mirror_internal_scan "$rsrc"); rc=$?
    [ "$rc" -eq 0 ] || { _mirror_internal_fail "$d" "$kind" "內部鏡像 $kind 不合格：${bad:-}（只收一般檔案與資料夾；符號連結、FIFO、裝置一律失敗）"; return 1; }
    if ! cp -R --no-dereference -- "$rsrc/." "$dest/" 2>> "$mir/$d.log"; then
      _mirror_internal_fail "$d" "$kind" "複製內部鏡像 $kind 失敗"; return 1
    fi
    bad=$(_mirror_internal_scan "$dest"); rc=$?
    [ "$rc" -eq 0 ] || { _mirror_internal_fail "$d" "$kind" "複製之後的檢查不合格：${bad:-}（來源在檢查與複製之間被改過？）"; return 1; }
    chmod -R u+rwX "$dest" 2>> "$mir/$d.log" || { _mirror_internal_fail "$d" "$kind" "複本的權限無法調整"; return 1; }
    if ! GRYPE_DB_AUTO_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false bash "$sd/$s" --check "$dest" >> "$mir/$d.log" 2>&1; then
      _mirror_internal_fail "$d" "$kind" "$s --check 失敗：$(grep -v '^[[:space:]]*$' "$mir/$d.log" | tail -n 1 | cut -c1-200)"; return 1
    fi
    info=$(_mirror_internal_age "$kind" "$dest" "$MIRROR_INTERNAL_FRESH" "$MIRROR_INTERNAL_MAX" 2>> "$mir/$d.log"); rc=$?
  fi
  if [ "$rc" -ne 0 ]; then _mirror_internal_fail "$d" "$kind" "無法判斷新舊：$(tail -n 1 "$mir/$d.log" | cut -c1-200)"; return 1; fi
  IFS=$'\t' read -r key val hours over fb overmax <<< "$info"
  if [ "$overmax" = 1 ]; then
    _mirror_internal_fail "$d" "$kind" "內部鏡像的資料已 $hours 小時，超過失敗門檻 INTERNAL_MIRROR_MAX_HOURS=$MIRROR_INTERNAL_MAX 小時"; return 1
  fi
  meta="source=internal kind=$kind"
  fresh=$MIRROR_INTERNAL_FRESH
  if [ "$mode" = file ]; then
    meta="$meta mode=file 同步時間不明（單一檔案，只依 dateReleased）"
    fresh=$MIRROR_INTERNAL_KEV_FILE_FRESH
  fi
  if [ "$over" = 1 ]; then
    why="內部鏡像的資料已 $hours 小時，超過新鮮門檻 $fresh 小時：這段時間新增的弱點可能不在資料裡"
  fi
  if [ "$fb" = 1 ]; then
    why="${why:+$why；}內部鏡像本身是沿用的舊資料（SOURCE 記 fallback=yes）"
  fi
  last="OK $meta $key=$val age_hours=$hours"
  [ -z "$why" ] || last="ATTENTION $meta $key=$val age_hours=$hours $why"
  srcsha=無
  for n in SOURCE index.tsv v6/latest.json known_exploited_vulnerabilities.json; do
    if [ -f "$dest/$n" ]; then srcsha=$(sha256sum "$dest/$n" | cut -d' ' -f1); break; fi
  done
  {
    echo "# 內部鏡像複本（source=internal）；沒有下載"
    echo "# kind: $kind${mode:+（mode=$mode）}"; echo "# $key: $val"; echo "# age_hours: $hours（新鮮門檻 $fresh 小時）"
    [ "$mode" != file ] || echo "# 同步時間不明（單一檔案，只依 dateReleased）"
    echo "# SOURCE（或 index.tsv、v6/latest.json、單一檔案）sha256: $srcsha"
    echo "# files: $(find "$dest" -type f | wc -l)  bytes: $(du -sb "$dest" | cut -f1)"
    (cd "$dest" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
  } > "$mir/$d.manifest" || { _mirror_internal_fail "$d" "$kind" "寫不出 manifest"; return 1; }
  printf '%s\n' "$last" > "$mir/$d.result"
  printf '%s\n' "$last" >> "$mir/$d.log"
  case $last in
    ATTENTION*)
      echo "鏡像 $d：ATTENTION（$last）"
      echo "::warning::鏡像 $d 的內部鏡像不夠新或本身是舊資料：$last"
      if [ -n "${MIRRORS_STEPS:-}" ]; then
        python3 -I "$_mirrors_lib/step_rows.py" append "$MIRRORS_STEPS" "${s%.sh}-mirror" ATTENTION 0 "$last" || return 1
      fi;;
    *) echo "鏡像 $d：OK（$(printf '%s' "$last" | cut -c1-160)）";;
  esac
}

mirror() {  # <腳本> <資料夾名>
  local rc
  mirror_internal_config; rc=$?
  case $rc in
    0) _mirror_internal "$@";;
    1) _mirror_public "$@";;
    *) return "$rc";;
  esac
}

mirror_kernel_cve() {  # <資料夾名>
  # 內部模式（或要求內部鏡像）：不用 KCVE_CACHE_DIR——內部鏡像就是唯一來源，壞了就失敗，不拿 cache 也不拿公開網址頂替
  if [ -n "${KCVE_CACHE_DIR:-}" ] && [ -f "$KCVE_CACHE_DIR/SOURCE" ] && ! _mirror_internal_intent; then
    KERNEL_CVE_REUSE_FROM=$KCVE_CACHE_DIR KERNEL_CVE_FALLBACK_FROM=$KCVE_CACHE_DIR mirror kernel-cve.sh "$1"
  else
    mirror kernel-cve.sh "$1"
  fi
}

# 這一份鏡像是這次新抓的嗎（可以存進 cache）？OK 結果、SOURCE 沒有 fallback=yes 才算；沿用或頂替的舊資料不能當新的存回去。
# 內部鏡像的複本（現在是內部模式，或 .result 有 source=internal）一律不是：它不是這次抓的，不存回 cache。
mirror_is_fresh() {  # <資料夾名>
  local d=$1 mir=${MIRRORS_DIR:?}
  _mirror_internal_intent && return 1
  [ -f "$mir/$d/SOURCE" ] && [ -f "$mir/$d.result" ] || return 1
  case $(head -n 1 "$mir/$d.result") in *source=internal*) return 1;; esac
  case $(head -n 1 "$mir/$d.result") in OK|OK\ *) ;; *) return 1;; esac
  ! grep -q '^fallback=yes' "$mir/$d/SOURCE"
}

grype_db_archive() {  # <資料夾名>：印內部鏡像複本（mirror grype-db.sh 之後）裡的 Grype DB 壓縮檔路徑；不合格回傳 1（什麼都不印）
  local d=$1 mir=${MIRRORS_DIR:?} arc
  arc=$(python3 -I -c 'import json, sys
p = json.load(open(sys.argv[1], encoding="utf-8")).get("path")
assert isinstance(p, str) and p and "/" not in p and not p.startswith(".") and "\n" not in p
print(p)' "$mir/$d/v6/latest.json" 2> /dev/null) || return 1
  [ -f "$mir/$d/v6/$arc" ] && [ ! -L "$mir/$d/v6/$arc" ] || return 1
  printf '%s\n' "$mir/$d/v6/$arc"
}

grype_db_mode() {  # <資料夾名>：印 grype_db_refresh 的模式（GRYPE_DB_UPDATE 的值）。公開模式 online；內部模式 import:<複本裡的壓縮檔>
  # 內部模式絕不印 online：鏡像不可用 → 回傳 1、什麼都不印；用法錯誤 → 回傳 64
  local d=$1 rc arc
  mirror_internal_config; rc=$?
  case $rc in
    1) printf 'online\n'; return 0;;
    0) ;;
    *) return "$rc";;
  esac
  mirror grype-db.sh "$d" >&2; rc=$?
  [ "$rc" -eq 0 ] || return "$rc"
  arc=$(grype_db_archive "$d") || return 1
  printf 'import:%s\n' "$arc"
}
