#!/usr/bin/env bash
# GitLab 範本 watch:drill 的每日監控演練（GITLAB-PORT T-16；對應 GitHub 的 watch.yml drill-1-baseline／drill-2-new-kev／drill-3-repeat／drill-close）。
# 合成 Release（tests/fixtures/watch/drill）＋合成 KEV（drill-kev-overlay.json），三輪：
#   1. 建基準（預期開 0 個 Issue）  2. 加入合成 KEV（預期開 2 個）  3. 同樣的資料再跑（預期 0 個：不重複開）
# 最後關閉演練 Issue（close-drill）。任何一輪失敗或數量不符 → 照樣收掉演練 Issue，結束碼 1。
# DUMPLING_WATCH_DRY_RUN=1：每一輪都只算不寫（不開 Issue、不寫狀態、不關閉），不核對數量。
#
# 用法：bash gitlab/watch-drill.sh <工作資料夾> <輸出資料夾>
# 環境變數：WATCH_READ_TOKEN（讀狀態用）、WATCH_WRITE_TOKEN（開／關 Issue、寫狀態用）、CI_API_V4_URL、CI_PROJECT_ID、CI_PIPELINE_URL；
#   DUMPLING_WATCH_TOOLS（測試用：pipeline/watch 的位置）、DUMPLING_WATCH_FIXTURES（測試用：合成資料的位置）
set -euo pipefail
work=${1:?工作資料夾}; out=${2:?輸出資料夾}
W=${DUMPLING_WATCH_TOOLS:-pipeline/watch}
FX=${DUMPLING_WATCH_FIXTURES:-tests/fixtures/watch}
dry=${DUMPLING_WATCH_DRY_RUN:-0}
case $dry in 0|1) ;; *) echo "watch-drill: FAIL（DUMPLING_WATCH_DRY_RUN 只能是 0 或 1）"; exit 1 ;; esac
: "${CI_API_V4_URL:?}" "${CI_PROJECT_ID:?}"
gl=(--backend gitlab --gitlab-url "$CI_API_V4_URL" --project "$CI_PROJECT_ID")
mkdir -p "$work" "$out"
: "${WATCH_READ_TOKEN:?}" "${WATCH_WRITE_TOKEN:?}"
# 讀取用 read token，開／關 Issue 與寫狀態用寫入 token（#91 驗證建議 3）
rd() { GITLAB_TOKEN="$WATCH_READ_TOKEN" "$@"; }
wr() { GITLAB_TOKEN="$WATCH_WRITE_TOKEN" "$@"; }

# 收掉演練 Issue：失敗要讓整體非 0（#91 驗證應修）。只收一次；逾時或被取消時由 trap 收（job 的 after_script 會再收一次）
closed=0
close_ok=1
close() {
  [ "$dry" = 1 ] && return 0
  [ "$closed" = 1 ] && return 0
  closed=1
  if ! wr python3 -I "$W/issues.py" close-drill "${gl[@]}"; then
    close_ok=0
    echo "watch-drill: 收掉演練 Issue 失敗（請人工關閉 drill 標籤的 Issue）"
    return 1
  fi
}
trap 'close' EXIT
trap 'echo "watch-drill: 收到中斷訊號，收掉演練 Issue"; close; exit 1' INT TERM

# 注意：round 在 && 串裡呼叫，bash 在這種情況下整個函式都不套用 set -e——每個指令都要自己 || return 1
round() {  # <輪次> <是否加合成 KEV 0|1> <預期開出數>
  local n=$1 overlay=$2 want=$3 rc=0 got
  local st="$work/state-$n" o="$out/round-$n"
  rm -rf "$st" "$o"
  rd python3 -I "$W/issues.py" read-state "${gl[@]}" --mode drill --out "$st" || { echo "watch-drill: 第 $n 輪讀狀態 FAIL"; return 1; }
  local extra=(--allow-baseline)
  [ "$overlay" = 1 ] && extra+=(--kev-overlay "$FX/drill-kev-overlay.json")
  python3 -I "$W/match.py" --inventory "$work/inv/inventory.json" --state-dir "$st" --feeds "$work/feeds" --out "$o" \
    --mode drill --run-url "${CI_PIPELINE_URL:-}" "${extra[@]}" || rc=$?
  [ "$rc" = 0 ] || [ "$rc" = 2 ] || [ "$rc" = 3 ] || { echo "watch-drill: 第 $n 輪比對 FAIL（結束碼 $rc）"; return 1; }
  # 演練一定要有 plan：沒有 plan（例如 fixtures 壞掉 → GAP）時驗收等於沒做（同 watch-round.yml）
  [ -f "$o/plan.json" ] || { echo "watch-drill: 第 $n 輪沒有 plan.json（比對結束碼 $rc），驗收不能跳過"; return 1; }
  local d=()
  [ "$dry" = 1 ] && d=(--dry-run)
  wr python3 -I "$W/issues.py" apply "${gl[@]}" --confidential --mode drill --plan "$o/plan.json" "${d[@]}" || { echo "watch-drill: 第 $n 輪套用 FAIL"; return 1; }
  if [ "$dry" = 1 ]; then
    echo "watch-drill: 第 $n 輪（dry-run）：不核對數量"
    return 0
  fi
  got=$(python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); print(sum(1 for a in r["actions"] if a.get("result") in ("opened","would_open")))' "$o/apply-result.json") \
    || { echo "watch-drill: 第 $n 輪讀不到 apply-result.json"; return 1; }
  echo "watch-drill: 第 $n 輪開出 $got 個 Issue（預期 $want）"
  [ "$got" = "$want" ] || { echo "watch-drill: 第 $n 輪的數量不符"; return 1; }
}

ok=1
rc=0
python3 -I "$W/collect.py" --from-dir "$FX/drill" --out "$work/inv" || rc=$?
if [ "$rc" != 0 ] && [ "$rc" != 3 ]; then echo "watch-drill: 收集合成 Release FAIL（結束碼 $rc）"; ok=0; fi
# 演練不下載核心 CVE 與 EUVD（同 watch-round.yml 的 drill）
if [ "$ok" = 1 ]; then bash "$W/feeds.sh" "$work/feeds" --no-kernel-cve --no-euvd || { echo "watch-drill: 資料源 FAIL"; ok=0; }; fi
if [ "$ok" = 1 ]; then
  round 1 0 0 && round 2 1 2 && round 3 1 0 || ok=0
fi
close || true
if [ "$ok" = 1 ] && [ "$close_ok" = 1 ]; then
  echo "watch-drill: OK$([ "$dry" = 1 ] && echo "（dry-run）")"
  exit 0
fi
if [ "$close_ok" = 1 ]; then
  echo "watch-drill: FAIL（演練 Issue 已收掉）"
elif [ "$ok" = 1 ]; then
  echo "watch-drill: FAIL（三輪都正常，但收掉演練 Issue 失敗：請人工關閉 drill 標籤的 Issue）"
else
  echo "watch-drill: FAIL（演練失敗，而且收掉演練 Issue 也失敗：請人工關閉 drill 標籤的 Issue）"
fi
exit 1
