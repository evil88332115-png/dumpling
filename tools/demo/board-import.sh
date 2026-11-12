#!/usr/bin/env bash
# 把板子安全檢查的結果（board-on-device.sh、board-from-network.sh 的 .tar.gz）匯入 scan-flash-package 的結果，再重新產生 CRA 文件
# （風險評估第 9 節、技術文件第 6 項、security-findings.md；CRA Annex I Part II (3)、Annex VII 6）。
#
# 用法（以 runner 執行，結果資料夾是 runner 的：sudo -u runner bash tools/demo/board-import.sh …）：
#   bash board-import.sh --result <結果資料夾>/<rootfs> [--replace] [--no-cra] [<board-test-*.tar.gz>] [<board-net-*.tar.gz> …]
#       [--kernel-modules-from <rootfs 資料夾｜rootfs tar｜刷機包 tbz2> [--kernel-modules-prefix <rootfs 在刷機包裡的路徑>]
#        [--kernel-version <版本>] [--image-sha256 sha256:<hex>] [--lsmod <檔案>] --owner <負責人> [--captured YYYY-MM-DD]
#        [--accept-unread-initramfs]]
#   --replace：同名的結果（或內容不同的 kernel-modules.json）已經有了時取代。--no-cra：只匯入，不重新產生 CRA 文件。
#   不給壓縮檔：只依已匯入的結果重寫 board-test.json。--kernel-modules-from：另寫 CRA/Config/kernel-modules.json（K2 的輸入；
#   映像雜湊取自 <rootfs>/scan/meta.json，loaded 取自板子結果的 lsmod.txt；見 board-test.md「核心模組清單」；要 Python 3.12 以上）。
# 結果：<rootfs>/board-test/<壓縮檔名稱>/（解開的文字檔）、<rootfs>/board-test/board-test.json（findings）；
#   有 <rootfs>/cra-project 與 <rootfs>/scan 時重新產生 <rootfs>/cra-project/CRA/Reports/（沿用上一次的公司共用設定）。
# 壓縮檔是不可信資料：tools/cra/board_import.py 只收兩支腳本會寫的檔名與一般檔案，不收連結、絕對路徑、..，有大小與行數上限；
# 整個匯入有時間上限（環境變數 BOARD_IMPORT_TIMEOUT 秒，預設 900）。
set -uo pipefail
umask 077
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)
RES= NOCRA=0 ARGS=()
while [ $# -gt 0 ]; do case $1 in
  --result) [ $# -ge 2 ] || { echo "--result 要給 <結果資料夾>/<rootfs>" >&2; exit 64; }; RES=$2; shift 2;;
  --replace) ARGS+=(--replace); shift;;
  --no-cra) NOCRA=1; shift;;
  --kernel-modules-from|--kernel-modules-prefix|--kernel-version|--image-sha256|--lsmod|--owner|--captured)
    [ $# -ge 2 ] || { echo "$1 要給值" >&2; exit 64; }; ARGS+=("$1=$2"); shift 2;;
  --accept-unread-initramfs) ARGS+=("$1"); shift;;
  -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  -*) echo "不認得的參數：$1" >&2; exit 64;;
  *) ARGS+=("$1"); shift;;
esac; done
[ -n "$RES" ] || { echo "要給 --result <結果資料夾>/<rootfs>" >&2; exit 64; }
[ -d "$RES" ] && [ ! -L "$RES" ] || { echo "--result 要是 scan-flash-package 結果裡的 <rootfs> 資料夾：$RES" >&2; exit 64; }

# Python：--kernel-modules-from 要 3.12 以上（kernel_config.py）。sudo -u runner 的 secure_path 只有系統的 python3（22.04 是 3.10），
# 所以明確挑（pick_python：$SCA_PYTHON、/opt/sca-tools/bin/python3、python3.13、python3.12、python3）；沒有就停下來說清楚
. "$ROOT/tools/pilot/lib/common.sh"
KM=0; for a in "${ARGS[@]+"${ARGS[@]}"}"; do case $a in --kernel-modules-from=*) KM=1;; esac; done
if PY=$(pick_python 3.12); then :
elif [ $KM = 1 ]; then
  printf 'D-kernel-modules\tFAIL\t找不到 Python 3.12 以上（找過 $SCA_PYTHON、%s/bin/python3、python3.13、python3.12、python3）：設 SCA_PYTHON=<python3.12 的路徑> 後重跑\n' "${SCA_TOOLS_DIR:-/opt/sca-tools}"
  exit 1
else PY=$(command -v python3) || { echo "找不到 python3" >&2; exit 1; }; fi
# 壓縮檔是不可信資料：整個匯入有時間上限（BOARD_IMPORT_TIMEOUT 秒，預設 900），逾時當 FAIL
lim=${BOARD_IMPORT_TIMEOUT:-900}
timeout --foreground -k 30 "$lim" "$PY" -I "$ROOT/tools/cra/board_import.py" --result "$RES" "${ARGS[@]+"${ARGS[@]}"}"; x=$?
if [ $x = 124 ] || [ $x = 137 ]; then printf 'D-board-test\tFAIL\tboard_import.py 逾時（%s 秒）\n' "$lim"; exit 1; fi
[ $x = 1 ] || [ $x = 64 ] && exit $x
[ $NOCRA = 1 ] && exit $x
P=$RES/cra-project S=$RES/scan
if [ ! -f "$P/CRA/Config/config.json" ] || [ ! -f "$S/status.tsv" ]; then
  echo "沒有 $P/CRA/Config/config.json 或 $S/status.tsv：只匯入，沒有產生 CRA 文件"; exit $x; fi
# 公司共用設定沿用上一次（summary.json 的 company_config.path；上一次沒有用就 --no-company）。上一次沒有文件、上一次 FAIL、
# 或讀不到那份設定時不重新產生：cra_report 失敗會刪掉上一次的文件
prev=$("$PY" -I -c '
import json, sys
try:
    s = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("NONE-PREV"); sys.exit()
c = s.get("company_config")
if s.get("status") == "FAIL":
    print("NONE-PREV")
elif isinstance(c, dict) and isinstance(c.get("path"), str):
    print("PATH\t" + c["path"])
else:
    print("NO-COMPANY")' "$P/CRA/Reports/summary.json")
cmd="$PY -I $ROOT/tools/cra/cra_report.py --project $P --scan $S"
case $prev in
  NO-COMPANY) CA=(--no-company);;
  PATH*) cf=${prev#PATH$'\t'}
    [ -r "$cf" ] || { echo "讀不到上一次用的公司共用設定 $cf：沒有重新產生 CRA 文件（手動：$cmd --company <檔案>）"; exit 2; }
    CA=(--company "$cf");;
  *) echo "沒有上一次的 CRA 文件（或上一次是 FAIL）：沒有重新產生（手動：$cmd [--company <檔案>|--no-company]）"; exit 2;;
esac
mkdir -p "$RES/logs"
r=$("$PY" -I "$ROOT/tools/cra/cra_report.py" --project "$P" --scan "$S" "${CA[@]}" 2> "$RES/logs/cra-board-import.err"); y=$?
if [ $y = 1 ] || [ $y = 64 ]; then echo "CRA 文件產生失敗（exit $y）：$r；見 $RES/logs/cra-board-import.err"; exit 1; fi
echo "CRA 文件已重新產生：$r"
echo "security-findings.md：$P/CRA/Reports/security-findings.md；決定（fixed／accepted／false_positive）用 tools/cra/security_findings.py decide"
[ $x = 0 ] && [ $y = 0 ] && exit 0 || exit 2
