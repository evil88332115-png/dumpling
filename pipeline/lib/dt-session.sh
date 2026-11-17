# shellcheck shell=bash disable=SC2154  # root、out 由呼叫端定義（見下面的說明；函式開頭也用 ${root:?}／${out:?} 擋住沒設的情況）
# 供 source：scan 步驟的 DT 連線（T-14）。pipeline/platforms/jetson/scan.sh 與 _shared/scan-disk.sh 用（之後 C2 的 firmware 也用）。
# 呼叫端要先定義 fail（印「…: FAIL（說明）」並結束）以及 $root（repo 根目錄）、$out（DUMPLING_OUT）。
#
# DUMPLING_DT_MODE
#   ephemeral（預設）：pipeline/dt-ephemeral.sh 起臨時 DT。命令、順序、輸出和 T-14 之前的 scan.sh 相同，只多了一個保護：
#     PILOT_ENV 在 DUMPLING_OUT 底下就 FAIL（現有的 pipeline.yml、dt-smoke.yml 與 GitLab 範本都不在底下，不會碰到）。
#   resident：連既有的常駐 DT（公司內部 GitLab 用）。不起、不關 docker 的 DT；不設 MIRROR_REFRESH_STATUS（狀態檔讀不到 → C-mirror-freshness GAP）。
#     DUMPLING_DT_CONN     連線檔的路徑（GitLab 的 File 類型、protected 變數）。格式見 pipeline/lib/dt_resident.py；沒有就 FAIL，不退回臨時 DT。
#     DUMPLING_DT_CA_FILE  （選用）公司自己的 CA 憑證（PEM）。和系統的 CA 合併成暫存檔，CURL_CA_BUNDLE 指過去。
#                          **只影響 curl**（sca-scan 連 DT 只用 curl）；python 的 urllib／requests 看 SSL_CERT_FILE／REQUESTS_CA_BUNDLE、
#                          git 看 GIT_SSL_CAINFO，這裡都不設。不提供關掉 TLS 驗證的選項。
#     只做「查專案、建專案、上傳、讀結果」（sca-scan 本身的動作）；這裡只讀 /api/version 與 key 自己的權限，不改資料源、不刪專案、不管 key。
#     GitHub Actions 上不能用（公開 repo 沒有常駐 DT 的連線檔；GITHUB_ACTIONS=true → FAIL）。
#
# 三段（中間的鏡像留在呼叫端，和臨時 DT 的啟動並行）：
#   dt_begin <臨時 DT 預設的 OSV 生態系>   ephemeral：EXIT trap、DT_OSV_ECOSYSTEMS／DT_WAIT_MIN、dt-ephemeral.sh up
#                                         resident：檢查連線檔與 CA、建私用暫存資料夾（不在 $out 底下）
#   dt_ready <PILOT_ENV>                  ephemeral：dt-ephemeral.sh wait、env
#                                         resident：寫 PILOT_ENV（權限 600）、GET /api/version、讀 key 的權限，記一列 pipeline-dt-resident
#   dt_mirror_status                      呼叫端 export MIRROR_REFRESH_STATUS="" 之後呼叫：resident 時把它拿掉
#   dt_end                                EXIT 時執行（dt_begin 把它接在呼叫端原有的 EXIT trap 後面，不蓋掉）
# PILOT_ENV 裡有 API key：不能放在 $out 底下（$out 會上傳成 artifact）→ 兩種模式都檢查，放在底下就 FAIL。

_dt_lib=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
_DT_PREV_EXIT=
_DT_TMP=

dt_mode() { printf '%s' "${DUMPLING_DT_MODE:-ephemeral}"; }

# 常駐 DT 的 HTTP：-q 不讀 .curlrc（第一個參數）；回應上限 1 MB（--max-filesize；伺服器沒給長度時 curl 可能收完才知道，讀的那一端另有上限）。
# 不加 -k／--insecure（不提供關掉 TLS 驗證的選項）。
_DT_MAX_BYTES=1048576
_dt_curl() { curl -q -sS -m 30 --max-filesize "$_DT_MAX_BYTES" "$@"; }
_dt_http() {  # <curl 參數…> → 印 HTTP 狀態碼（curl 失敗印 000）；回應超過上限（curl 結束碼 63）→ 回傳 63，呼叫端寫明是太大而不是連不上
  local c rc
  c=$(_dt_curl "$@"); rc=$?
  [ "$rc" = 63 ] && return 63
  [ "$rc" = 0 ] || c=000
  printf '%s' "$c"
}
_dt_too_big() { fail "常駐 DT 回應太大（$1，超過 $_DT_MAX_BYTES bytes），不處理"; }

_dt_take3() { _DT_PREV_EXIT=$3; }

_dt_on_exit() {  # dt_end 接在原有的 EXIT trap 後面（只接一次）
  local cur
  cur=$(trap -p EXIT)
  if [ -n "$cur" ]; then
    eval "_dt_take3 $cur"       # trap -p 的輸出已經是 shell 引號格式：trap -- '<指令>' EXIT → 第三個參數是原本的指令
  fi
  # shellcheck disable=SC2016 # 結束時才展開
  trap 'eval "$_DT_PREV_EXIT"; dt_end' EXIT
}

_dt_outside_out() {  # <路徑>：不在 $out 底下 → 0
  local p o
  p=$(realpath -m -- "$1") || return 1
  o=$(realpath -m -- "$out") || return 1
  case $p/ in "$o"/*) return 1;; esac
  return 0
}

dt_begin() {
  : "${root:?}" "${out:?}"
  case $(dt_mode) in
    ephemeral)
      _dt_on_exit
      export DT_OSV_ECOSYSTEMS=${DT_OSV_ECOSYSTEMS:-$1}
      export DT_WAIT_MIN=${DT_WAIT_MIN:-60}
      bash "$root/pipeline/dt-ephemeral.sh" up || fail "臨時 DT up 失敗"
      ;;
    resident)
      [ "${GITHUB_ACTIONS:-}" = true ] && fail "常駐 DT 模式不在 GitHub Actions 上用（公開 repo 沒有常駐 DT 的連線檔）"
      [ -n "${DUMPLING_DT_CONN:-}" ] || fail "DUMPLING_DT_MODE=resident 需要 DUMPLING_DT_CONN（常駐 DT 連線檔的路徑）；不退回臨時 DT"
      local msg sys=
      msg=$(python3 -I "$_dt_lib/dt_resident.py" check "$DUMPLING_DT_CONN") || fail "常駐 DT 的連線檔不合：$msg"
      _DT_TMP=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/dumpling-dt.XXXXXX") || fail "建不了常駐 DT 的暫存資料夾"
      chmod 700 "$_DT_TMP"
      _dt_on_exit
      _dt_outside_out "$_DT_TMP" || fail "常駐 DT 的暫存資料夾不能在 DUMPLING_OUT 底下（裡面會有 API key）"
      if [ -n "${DUMPLING_DT_CA_FILE:-}" ]; then
        if ! { [ -f "$DUMPLING_DT_CA_FILE" ] && grep -q -- "-----BEGIN CERTIFICATE-----" "$DUMPLING_DT_CA_FILE"; }; then
          fail "DUMPLING_DT_CA_FILE 不是 PEM 格式的憑證檔"
        fi
        for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
          [ -f "$f" ] && { sys=$f; break; }
        done
        [ -n "$sys" ] || fail "找不到系統的 CA bundle，不能和 DUMPLING_DT_CA_FILE 合併（只放公司 CA 會讓其他連公開網址的 curl 失敗）"
        { cat "$sys"; echo; cat "$DUMPLING_DT_CA_FILE"; } > "$_DT_TMP/ca-bundle.pem" || fail "合併 CA 失敗"
        export CURL_CA_BUNDLE=$_DT_TMP/ca-bundle.pem     # 只影響 curl（見檔頭）
      fi
      echo "dt-session: 常駐 DT 模式（不起臨時 DT）"
      ;;
    *) fail "DUMPLING_DT_MODE 不認得：$(dt_mode)（ephemeral｜resident）";;
  esac
}

dt_ready() {  # <PILOT_ENV>
  local pe=$1 rc
  : "${root:?}" "${out:?}"
  _dt_outside_out "$pe" || fail "PILOT_ENV 不能放在 DUMPLING_OUT 底下（裡面有 DT 的 API key，DUMPLING_OUT 會上傳成 artifact）"
  case $(dt_mode) in
    ephemeral)
      bash "$root/pipeline/dt-ephemeral.sh" wait || { rc=$?; [ $rc = 3 ] && fail "臨時 DT 的鏡像逾時（GAP：弱點資料不完整）"; fail "臨時 DT wait 失敗"; }
      mkdir -p "$(dirname "$pe")"
      bash "$root/pipeline/dt-ephemeral.sh" env "$pe" || fail "臨時 DT env 失敗"
      ;;
    resident)
      local url c src r ver
      mkdir -p "$(dirname "$pe")"
      r=$(umask 077; python3 -I "$_dt_lib/dt_resident.py" write "$DUMPLING_DT_CONN" "$pe") || fail "寫不了 PILOT_ENV：$r"
      url=$(python3 -I "$_dt_lib/dt_resident.py" url "$DUMPLING_DT_CONN") || fail "常駐 DT 的連線檔不合：$url"
      c=$(_dt_http -o "$_DT_TMP/version.json" -w '%{http_code}' "$url/api/version") || _dt_too_big "/api/version"
      [ "$c" = 200 ] || fail "常駐 DT 連不上：GET /api/version http=$c"
      ver=$(python3 -I "$_dt_lib/dt_resident.py" version "$_DT_TMP/version.json" 2> /dev/null) || ver='?'
      r=$(python3 -I "$_dt_lib/dt_resident.py" curlcfg "$DUMPLING_DT_CONN" "$_DT_TMP/key.cfg") || fail "常駐 DT 的連線檔不合：$r"
      # API key 屬於使用者／服務帳號 → /api/v1/user/self/permissions；屬於團隊（那個端點回 401）→ /api/v1/team/self（apiserver 5.2.0）
      c=$(_dt_http -K "$_DT_TMP/key.cfg" -o "$_DT_TMP/perm.json" -w '%{http_code}' "$url/api/v1/user/self/permissions") || _dt_too_big "/api/v1/user/self/permissions"
      src=user
      if [ "$c" = 401 ]; then
        c=$(_dt_http -K "$_DT_TMP/key.cfg" -o "$_DT_TMP/perm.json" -w '%{http_code}' "$url/api/v1/team/self") || _dt_too_big "/api/v1/team/self"
        src=team
      fi
      rm -f "$_DT_TMP/key.cfg"
      [ "$c" = 200 ] || fail "讀不到 API key 的權限（$src：http=$c；key 無效、過期，或不屬於使用者／服務帳號／團隊）"
      r=$(python3 -I "$_dt_lib/dt_resident.py" perms "$_DT_TMP/perm.json" "$src") || fail "$r"
      python3 -I "$_dt_lib/step_rows.py" append "${MIRRORS_STEPS:-$out/pipeline-steps.tsv}" dt-resident OK 0 \
        "常駐 DT（apiserver $ver）；${r#*$'\t'}" || fail "寫不了 pipeline-steps.tsv"
      echo "dt-session: OK（常駐 DT apiserver $ver；${r#*$'\t'}）"
      ;;
  esac
}

dt_mirror_status() {
  if [ "$(dt_mode)" = resident ]; then unset MIRROR_REFRESH_STATUS; fi
  return 0
}

dt_end() {
  case $(dt_mode) in
    ephemeral) bash "$root/pipeline/dt-ephemeral.sh" down > /dev/null 2>&1 || true;;
    resident) [ -n "$_DT_TMP" ] && rm -rf "$_DT_TMP";;
  esac
  return 0
}
