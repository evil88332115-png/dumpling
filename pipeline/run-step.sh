#!/usr/bin/env bash
# workflow 呼叫 pipeline/platform.sh 的唯一入口：所有步驟（validate、fetch、build、assemble、scan、raw-sectors）用同一個結束碼規則，並把每一步的結果記下來。
#
#   pipeline/run-step.sh <步驟> <專案資料夾> <版本>
#   pipeline/run-step.sh --record <專案資料夾> <版本> <步驟> <OK|GAP|NOT_RUN|FAIL> <結束碼> <說明>     （只記一列，不執行；例如 build.mode: none 的 build）
#
# 結束碼規則（與 docs/PLATFORM-INTERFACE.md 的步驟結束碼一致）：
#   0 → OK        1、64 或其他 → FAIL（這個 script 以 1 結束，job 失敗）
#   3 → GAP       印 ::warning::，這個 script 以 0 結束（繼續下一步；結果照樣產生，但整體狀態不是 OK）
#   4 → NOT_RUN   印 ::notice::，這個 script 以 0 結束（繼續；不能當成成功，會照實列在報告裡）
# 紀錄：每一步在 $DUMPLING_OUT/pipeline-steps.tsv 加一列「pipeline-<步驟>	狀態	結束碼	最後一行輸出」（$DUMPLING_OUT ＝ $DUMPLING_OUT_BASE/<專案>/<版本>）。
# 報告（platform_scan.collect）、release-meta.json、scan-status-check 讀這個檔，所以平台的 scan 沒有讀 raw-sectors.json 之類的檔案，GAP 也不會消失。
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
rows() { python3 -I "$here/lib/step_rows.py" "$@"; }
out_of() { echo "${DUMPLING_OUT:-${DUMPLING_OUT_BASE:-$root/out}/$(basename "$1")/$2}"; }

if [ "${1:-}" = --record ]; then
  [ $# -eq 7 ] || { echo "用法：run-step.sh --record <專案資料夾> <版本> <步驟> <狀態> <結束碼> <說明>" >&2; exit 64; }
  out=$(out_of "$2" "$3"); mkdir -p "$out" || exit 1
  rows append "$out/pipeline-steps.tsv" "$4" "$5" "$6" "$7" || exit 1
  echo "pipeline-$4: $5（$7）"
  exit 0
fi
[ $# -eq 3 ] || { echo "用法：run-step.sh <步驟> <專案資料夾> <版本>" >&2; exit 64; }
step=$1; proj=$2; ver=$3
out=$(out_of "$proj" "$ver"); mkdir -p "$out" || exit 1
log=$(mktemp "${TMPDIR:-/tmp}/run-step.XXXXXX"); trap 'rm -f "$log"' EXIT
bash "$here/platform.sh" "$step" "$proj" "$ver" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
last=$(grep -v '^[[:space:]]*$' "$log" | tail -n 1)
case $rc in 0) st=OK;; 3) st=GAP;; 4) st=NOT_RUN;; *) st=FAIL;; esac
rows append "$out/pipeline-steps.tsv" "$step" "$st" "$rc" "${last:-（沒有輸出）}" || exit 1
case $st in
  OK) exit 0;;
  GAP) echo "::warning::pipeline-$step 回報 GAP（結束碼 $rc）：${last}。結果照樣產生，但不能當成通過"; exit 0;;
  NOT_RUN) echo "::notice::pipeline-$step 沒有執行（NOT_RUN，結束碼 $rc）：${last}"; exit 0;;
  *) echo "::error::pipeline-$step 失敗（結束碼 $rc）：${last}"; exit 1;;
esac
