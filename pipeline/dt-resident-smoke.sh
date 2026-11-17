#!/usr/bin/env bash
# T-14 收尾的整合測試：同一台 runner 上 pipeline/dt-ephemeral.sh 起的臨時 DT 當成「常駐 DT」，用 DUMPLING_DT_MODE=resident 連它。
# 只在 .github/workflows/dt-smoke.yml 的一個步驟跑（那一步設 DUMPLING_DT_TEST_RESIDENT=1；pipeline/lib/dt-session.sh 另外核對
# GITHUB_WORKFLOW_REF 是 dt-smoke.yml，兩個條件都要）。API key 是 dt-ephemeral.sh 在這個 job 裡產生的，不是 secret。
# 需要：PILOT_ENV（dt-ephemeral.sh env 寫的，含 DT_URL、DT_API_KEY）、RUNNER_TEMP；已經裝好 sca-scan 要的工具。
# 檢查：
#   1. dt_begin／dt_ready（resident）成功；pipeline-dt-resident 那一列 OK，權限讀自 /api/v1/user/self/permissions（dt-ephemeral 的 key 是服務帳號的）；
#      dt_mirror_status 把 MIRROR_REFRESH_STATUS 拿掉。
#   2. resident 不起、不關容器：前後 docker ps 的容器 ID 相同。
#   3. sca-scan --sbom 用同一個名稱與版本跑兩次：第一次 D-dt-project「建立」、第二次「沿用」；兩次 dt-verify.py verify 都通過。
#   4. 不設 MIRROR_REFRESH_STATUS，預設路徑（/var/lib/sca-gitlab/refresh-status.tsv）放一個過期的狀態檔 → C-mirror-freshness GAP；測完刪掉。
# 以 GitHub runner 上的假常駐 DT 驗證；對真實的內部常駐 DT 未驗證。
# 最後一行：dt-resident-smoke: OK｜FAIL（說明）。
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail() { echo "dt-resident-smoke: FAIL（$*）"; exit 1; }
if [ -z "${PILOT_ENV:-}" ] || [ ! -f "$PILOT_ENV" ]; then fail "需要 PILOT_ENV（dt-ephemeral.sh env 寫的 pilot.env）"; fi
[ -n "${RUNNER_TEMP:-}" ] || fail "需要 RUNNER_TEMP"
w=$RUNNER_TEMP/dt-resident
rm -rf "$w"; mkdir -p "$w/conn" "$w/pilot-env" "$w/out"; chmod 700 "$w/conn" "$w/pilot-env"
status_file=/var/lib/sca-gitlab/refresh-status.tsv
cleanup() { sudo rm -f "$status_file" 2> /dev/null || true; }
trap cleanup EXIT

# 連線檔：只放 DT_URL、DT_API_KEY（權限 600；值不印）
(umask 077; grep -E '^(DT_URL|DT_API_KEY)=' "$PILOT_ENV" > "$w/conn/dt.conn") || fail "做不了連線檔"
[ "$(grep -c . "$w/conn/dt.conn")" = 2 ] || fail "pilot.env 沒有剛好一個 DT_URL 與一個 DT_API_KEY"
export DUMPLING_DT_MODE=resident DUMPLING_DT_CONN=$w/conn/dt.conn DUMPLING_DT_ALLOW_HTTP_LOCAL=1
containers() { docker ps -q --no-trunc | sort; }
before=$(containers)

# 1. dt-session（resident）：另開一個 bash，跟 scan.sh 一樣的用法（fail、root、out）
pe=$w/pilot-env/pilot.env
r=$(bash -c '
  set -uo pipefail
  root=$1; out=$2
  fail() { echo "scan: FAIL（$*）"; exit 1; }
  . "$root/pipeline/lib/dt-session.sh"
  dt_begin PyPI
  dt_ready "$3"
  export MIRROR_REFRESH_STATUS=""
  dt_mirror_status
  echo "MRS=${MIRROR_REFRESH_STATUS-unset}"
' _ "$root" "$w/out" "$pe" 2>&1) || { echo "$r"; fail "dt-session（resident）失敗"; }
echo "$r"
grep -qx "MRS=unset" <<< "$r" || fail "dt_mirror_status 沒有拿掉 MIRROR_REFRESH_STATUS"
row=$(grep -P '^pipeline-dt-resident\t' "$w/out/pipeline-steps.tsv" 2> /dev/null) || fail "pipeline-steps.tsv 沒有 pipeline-dt-resident 那一列"
[ "$(cut -f2 <<< "$row")" = OK ] || fail "pipeline-dt-resident 不是 OK：$(cut -f4 <<< "$row")"
grep -qF "/api/v1/user/self/permissions" <<< "$row" || fail "權限不是讀自 /api/v1/user/self/permissions：$(cut -f4 <<< "$row")"
if [ ! -f "$pe" ] || [ "$(stat -c %a "$pe")" != 600 ]; then fail "PILOT_ENV 沒有寫成權限 600"; fi
[ "$(containers)" = "$before" ] || fail "resident 模式起或關了容器"

# 4 的準備：預設路徑放過期的狀態檔（finished 太舊 → GAP）
sudo mkdir -p "$(dirname "$status_file")" || fail "建不了 $(dirname "$status_file")"
printf '# sca-nvd-refresh status 1\nfinished\t2020-01-01T00:00:00Z\n' | sudo tee "$status_file" > /dev/null || fail "寫不了過期的狀態檔"
sudo chmod 644 "$status_file"

# 3. sca-scan 跑兩次（同名同版）；dt-verify 兩次都通過
name=dumpling-dt-resident
python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));d["project_name"]=sys.argv[3];json.dump(d,open(sys.argv[2],"w"))' \
  "$root/tests/fixtures/sbom/smoke.expected.json" "$w/expected.json" "$name" || fail "寫不了 expected.json"
for i in 1 2; do
  rc=0
  env -u MIRROR_REFRESH_STATUS PILOT_ENV="$pe" "$root/tools/pilot/sca-scan" --sbom "$root/tests/fixtures/sbom/smoke.cdx.json" --name "$name" --version 1.0.0 \
    --out "$w/scan$i" --no-license > "$w/sca-scan$i.log" 2>&1 || rc=$?
  case $rc in 0|2) ;; *) tail -40 "$w/sca-scan$i.log"; fail "第 $i 次 sca-scan 結束碼 $rc";; esac
  st=$w/scan$i/status.tsv
  want=建立; [ "$i" = 2 ] && want=沿用
  p=$(awk -F'\t' '$1=="D-dt-project"{print $2"\t"$3}' "$st")
  [ "$(cut -f1 <<< "$p")" = OK ] || fail "第 $i 次 D-dt-project 不是 OK：$(cut -f2 <<< "$p")"
  case $(cut -f2 <<< "$p") in "$want $name@1.0.0"*) ;; *) fail "第 $i 次 D-dt-project 應該是「$want」：$(cut -f2 <<< "$p")";; esac
  m=$(awk -F'\t' '$1=="C-mirror-freshness"{print $2}' "$st")
  [ "$m" = GAP ] || fail "第 $i 次 C-mirror-freshness 應該是 GAP（過期的狀態檔），實際 ${m:-沒有這一列}"
  PILOT_ENV="$pe" python3 -I "$root/pipeline/dt-verify.py" verify "$w/expected.json" "$w/verify$i" > "$w/verify$i.log" 2>&1 \
    || { tail -20 "$w/verify$i.log"; fail "第 $i 次 dt-verify 沒有通過"; }
  echo "第 $i 次：D-dt-project $(cut -f2 <<< "$p" | cut -c1-80)；C-mirror-freshness $m；dt-verify 通過"
done
[ "$(containers)" = "$before" ] || fail "掃描期間容器有變（resident 模式不應該起或關容器）"
echo "dt-resident-smoke: OK（resident 連同一台的臨時 DT：權限讀自 /api/v1/user/self/permissions、沒有起或關容器、專案第一次建立第二次沿用、過期狀態檔 → C-mirror-freshness GAP；對真實的內部常駐 DT 未驗證）"
