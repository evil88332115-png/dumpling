#!/usr/bin/env bash
# 臨時 Dependency-Track（apiserver＋Postgres）：up | wait | env <路徑> | down
# 每個子指令最後印一行狀態；失敗時結束碼不是 0。秘密（密碼、API key）不印出、不寫進 repo。
#
#   up    隨機產生密碼、起 compose、改 admin 密碼、建 API key、設定資料源（只開 OSV 與 KEV，關 NVD）。
#   wait  等 OSV 與 CISA KEV 鏡像完成（必要）。逾時或失敗 → 印 GAP／FAIL 並以非 0 結束，不當成「沒有漏洞」。
#         ENISA KEV 是選用：必要的完成後最多再等 DT_OPTIONAL_GRACE_MIN（預設 5）分鐘，沒完成或失敗只在狀態行標 GAP。
#   env   輸出 pilot.env（tools/pilot/sca-scan 讀的 KEY=VALUE），權限 600。
#   down  關掉並刪除容器與 volume，再刪狀態檔。
#
# 環境變數（都有預設值）：
#   DT_EPH_PROJECT    compose 專案名（預設 dumpling-dt）
#   DT_PORT           只綁 127.0.0.1 的埠（預設 8080）
#   DT_EPH_DIR        狀態檔資料夾（預設 ${RUNNER_TEMP:-${TMPDIR:-/tmp}}/dumpling-dt-eph-<專案名>），權限 700
#   DT_OSV_ECOSYSTEMS OSV 生態系，逗號分隔（預設 PyPI,npm,Ubuntu）
#   DT_EPSS_ENABLED   false＝關 EPSS（預設保留 DT 預設值）
#   DT_UP_TIMEOUT_SEC 等 API 就緒的秒數（預設 600）
#   DT_WAIT_MIN       wait 的上限分鐘（預設 40）
#   DT_API_KEY_DAYS   API key 有效天數（預設 1）
set -euo pipefail

PROJECT=${DT_EPH_PROJECT:-dumpling-dt}
PORT=${DT_PORT:-8080}
STATE_DIR=${DT_EPH_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/dumpling-dt-eph-$PROJECT}
STATE=$STATE_DIR/state.env
ECOS=${DT_OSV_ECOSYSTEMS:-PyPI,npm,Ubuntu}
here=$(cd "$(dirname "$0")" && pwd)
COMPOSE_FILE=$here/dt-compose.yaml
DT=http://127.0.0.1:$PORT
sub=${1:-}

compose() { DT_PORT=$PORT DT_DB_PASSWORD="${DT_DB_PASSWORD:-unused}" docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }
mask() { if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::add-mask::$1"; fi; }
die() { echo "dt-ephemeral $sub: FAIL（$*）"; exit 1; }
pj() { python3 -I -c "$@"; }

# 以管理員 JWT 呼叫（含 curl 失敗時的退出）；秘密放標頭檔，不出現在指令列
HDR=
mkhdr() { # $1=Authorization 的值
  HDR=$(mktemp "$STATE_DIR/hdr.XXXXXX"); chmod 600 "$HDR"
  printf 'header = "%s"\n' "$1" > "$HDR"
}
api() { local m=$1 p=$2; shift 2; curl -sS -m 120 -X "$m" -K "$HDR" "$@" "$DT$p"; }
code() { local m=$1 p=$2; shift 2; curl -sS -m 120 -o /dev/null -w '%{http_code}' -X "$m" -K "$HDR" "$@" "$DT$p"; }
ext() { echo "/api/v2/extension-points/$1/extensions/$2/config"; }

# 讀 extension 設定、改欄位（用 python 片段），PUT 回去；回傳 http 碼
ext_set() { # $1=點 $2=名 $3=python 片段（改 c，c 是 config dict）
  local cur put
  cur=$(api GET "$(ext "$1" "$2")") || return 1
  put=$(printf '%s' "$cur" | pj "import json,sys;d=json.load(sys.stdin);c=d['config'];$3;print(json.dumps({'config':c}))") || return 1
  code PUT "$(ext "$1" "$2")" -H 'Content-Type: application/json' --data "$put"
}

load_state() {
  [ -f "$STATE" ] || die "找不到狀態檔 $STATE（先執行 up）"
  # shellcheck disable=SC1090
  . "$STATE"
}

cmd_up() {
  command -v docker >/dev/null || die "沒有 docker"
  umask 077
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  # 上次被取消的執行可能留下用舊密碼建的 volume：先清除同名專案
  compose down -v >/dev/null 2>&1 || true
  DT_DB_PASSWORD=$(openssl rand -hex 24); export DT_DB_PASSWORD
  local admin_pw; admin_pw="$(openssl rand -hex 20)Aa1!"
  mask "$DT_DB_PASSWORD"; mask "$admin_pw"
  compose up -d >"$STATE_DIR/compose-up.log" 2>&1 || { tail -5 "$STATE_DIR/compose-up.log" >&2; die "docker compose up 失敗"; }

  local ver=
  for _ in $(seq 1 $(( ${DT_UP_TIMEOUT_SEC:-600} / 5 ))); do
    ver=$(curl -sf -m 5 "$DT/api/version" 2>/dev/null) && break
    ver=; sleep 5
  done
  [ -n "$ver" ] || die "API ${DT_UP_TIMEOUT_SEC:-600} 秒內沒有回應"
  local version; version=$(printf '%s' "$ver" | pj "import json,sys;print(json.load(sys.stdin).get('version',''))")

  # 改 admin 預設密碼並登入
  local c
  c=$(curl -sS -m 60 -o /dev/null -w '%{http_code}' -X POST "$DT/api/v1/user/forceChangePassword" \
    --data-urlencode username=admin --data-urlencode password=admin \
    --data-urlencode "newPassword=$admin_pw" --data-urlencode "confirmPassword=$admin_pw")
  case $c in 2??) ;; *) die "改 admin 密碼 http=$c";; esac
  local jwt; jwt=$(curl -sS -m 60 -w '\n%{http_code}' -X POST "$DT/api/v1/user/login" --data-urlencode username=admin --data-urlencode "password=$admin_pw")
  c=${jwt##*$'\n'}; jwt=${jwt%$'\n'*}
  if [ "$c" != 200 ] || [ -z "$jwt" ]; then die "admin 登入失敗 http=$c"; fi
  mask "$jwt"; mkhdr "Authorization: Bearer $jwt"

  # 資料源：關 NVD；開 OSV（指定生態系、別名同步）；KEV 保持啟用（CISA、ENISA）
  c=$(ext_set vuln-data-source nvd "c['enabled']=False") || die "讀 NVD 設定失敗"
  case $c in 200|204|304) ;; *) die "關閉 NVD http=$c";; esac
  local ecos_json; ecos_json=$(printf '%s' "$ECOS" | pj "import json,sys;print(json.dumps([e.strip() for e in sys.stdin.read().split(',') if e.strip()]))")
  c=$(ext_set vuln-data-source osv "c.update(enabled=True,ecosystems=json.loads('$ecos_json'),aliasSyncEnabled=True)") || die "讀 OSV 設定失敗"
  case $c in 200|204|304) ;; *) die "設定 OSV http=$c";; esac
  for s in cisa enisa; do
    c=$(ext_set kev-data-source "$s" "c['enabled']=True") || die "讀 KEV $s 設定失敗"
    case $c in 200|204|304) ;; *) die "啟用 KEV $s http=$c";; esac
  done
  if [ "${DT_EPSS_ENABLED:-}" = false ]; then
    c=$(code POST /api/v1/configProperty -H 'Content-Type: application/json' \
      -d '{"groupName":"vuln-source","propertyName":"epss.enabled","propertyValue":"false"}')
    [ "$c" = 200 ] || die "關閉 EPSS http=$c"
  fi
  # 設定生效後明確觸發 OSV 與 KEV 鏡像（已在跑會回 409，視為正常）
  for s in vuln-data-sources/osv kev-data-sources/cisa kev-data-sources/enisa; do
    c=$(code POST "/api/v2/$s/mirror-runs")
    case $c in 2??|409) ;; *) die "觸發 $s 鏡像 http=$c";; esac
  done

  # 服務帳號與 API key（上傳 BOM、讀專案與漏洞、讀資料源狀態）
  c=$(code POST /api/v2/service-accounts -H 'Content-Type: application/json' -d '{"name":"ci-dumpling"}')
  case $c in 2??|409) ;; *) die "建服務帳號 http=$c";; esac
  local p
  for p in BOM_UPLOAD PROJECT_CREATION_UPLOAD PORTFOLIO_MANAGEMENT VIEW_PORTFOLIO VIEW_VULNERABILITY \
           VULNERABILITY_ANALYSIS VULNERABILITY_MANAGEMENT POLICY_MANAGEMENT VIEW_POLICY_VIOLATION SYSTEM_CONFIGURATION_READ; do
    c=$(code POST "/api/v1/permission/$p/user/svc:ci-dumpling")
    case $c in 2??|304) ;; *) die "授權 $p http=$c";; esac
  done
  local key
  key=$(api POST /api/v2/service-accounts/ci-dumpling/api-keys -H 'Content-Type: application/json' \
    -d "{\"comment\":\"ci\",\"expires_in_days\":${DT_API_KEY_DAYS:-1}}" | pj "import json,sys;print(json.load(sys.stdin).get('key',''))" 2>/dev/null) || key=
  [ -n "$key" ] || die "沒有取得 API key"
  mask "$key"
  rm -f "$HDR"

  {
    printf 'DT_API_KEY=%s\n' "$key"
    printf 'DT_VERSION=%s\n' "$version"
    printf 'DT_ECOSYSTEMS=%s\n' "$ECOS"
    printf 'DT_STARTED_AT=%s\n' "$(date +%s)"
  } > "$STATE"; chmod 600 "$STATE"
  echo "dt-ephemeral up: OK（apiserver $version，OSV: $ECOS；KEV: cisa,enisa；NVD 關閉；$DT）"
}

# 讀某資料源最近一次 mirror 的狀態；無資料或錯誤回傳 http 碼
mirror_status() { # $1=vuln-data-sources/osv 等
  local out c
  out=$(mktemp "$STATE_DIR/m.XXXXXX")
  c=$(curl -sS -m 30 -o "$out" -w '%{http_code}' -K "$HDR" "$DT/api/v2/$1/mirror-runs/latest" 2>/dev/null) || c=000
  if [ "$c" = 200 ]; then pj "import json,sys;d=json.load(open(sys.argv[1]));print(d.get('status') or 'UNKNOWN', d.get('failure_reason') or '')" "$out" 2>/dev/null || echo UNKNOWN
  else echo "http$c"; fi
  rm -f "$out"
}

cmd_wait() {
  load_state
  mkhdr "X-Api-Key: $DT_API_KEY"
  local limit=$(( ${DT_WAIT_MIN:-40} * 60 )) grace=$(( ${DT_OPTIONAL_GRACE_MIN:-5} * 60 )) t0 now line req_done opt_done st s name failed='' opt_gap='' req_at=''
  t0=$(date +%s)
  # 必要：OSV（漏洞）＋CISA KEV（PLAN「已知卡點」）。選用：ENISA KEV——未完成或失敗只標 GAP，不判失敗。
  local required=(vuln-data-sources/osv kev-data-sources/cisa) optional=(kev-data-sources/enisa)
  while :; do
    req_done=1; opt_done=1; line=; failed=; opt_gap=
    for s in "${required[@]}" "${optional[@]}"; do
      st=$(mirror_status "$s"); name=${s%%-data-sources*}:${s##*/}
      line+="$name=${st%% *} "
      local is_opt=0; case " ${optional[*]} " in *" $s "*) is_opt=1;; esac
      case ${st%% *} in
        COMPLETED) ;;
        FAILED) if [ "$is_opt" = 1 ]; then opt_gap+="$name 失敗（${st#* }） "; else failed+="$name（${st#* }） "; req_done=0; fi;;
        *) if [ "$is_opt" = 1 ]; then opt_done=0; opt_gap+="$name 未完成 "; else req_done=0; fi;;
      esac
    done
    now=$(date +%s)
    if [ -n "$failed" ]; then
      rm -f "$HDR"; echo "dt-ephemeral wait: FAIL（鏡像失敗：$failed；弱點資料不完整，不能當作沒有漏洞）"; return 1
    fi
    if [ "$req_done" = 1 ]; then
      [ -n "$req_at" ] || req_at=$now
      if [ "$opt_done" = 1 ] || [ $(( now - req_at )) -ge "$grace" ] || [ $(( now - t0 )) -ge "$limit" ]; then
        rm -f "$HDR"
        echo "dt-ephemeral wait: OK（${line}；用時 $(( now - t0 )) 秒；DT 啟動後 $(( now - DT_STARTED_AT )) 秒${opt_gap:+；選用資料源 GAP：${opt_gap% }}）"
        return 0
      fi
    elif [ $(( now - t0 )) -ge "$limit" ]; then
      rm -f "$HDR"; echo "dt-ephemeral wait: GAP（${DT_WAIT_MIN:-40} 分鐘內未完成：${line}；弱點資料不完整，不能當作沒有漏洞）"; return 3
    fi
    sleep 15
  done
}

cmd_env() {
  local out=${1:-}
  [ -n "$out" ] || die "用法：env <輸出路徑>"
  load_state
  mask "$DT_API_KEY"
  umask 077
  { printf 'DT_URL=%s\n' "$DT"; printf 'DT_API_KEY=%s\n' "$DT_API_KEY"; } > "$out"
  chmod 600 "$out"
  echo "dt-ephemeral env: OK（已寫入 pilot.env，權限 600，鍵：DT_URL、DT_API_KEY）"
}

cmd_down() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  local left
  left=$(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" -q | wc -l)
  left=$(( left + $(docker volume ls --filter "label=com.docker.compose.project=$PROJECT" -q | wc -l) ))
  rm -rf "$STATE_DIR"
  if [ "$left" -eq 0 ]; then echo "dt-ephemeral down: OK（容器與 volume 已刪除）"
  else echo "dt-ephemeral down: FAIL（專案 $PROJECT 還剩 $left 個容器或 volume）"; return 1; fi
}

case $sub in
  up) cmd_up;;
  wait) cmd_wait;;
  env) cmd_env "${2:-}";;
  down) cmd_down;;
  *) echo "用法：$0 up|wait|env <路徑>|down" >&2; exit 64;;
esac
