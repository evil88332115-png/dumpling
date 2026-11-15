#!/usr/bin/env bash
# 每天重跑韌體公告比對（x86_firmware.py --rematch 的包裝）：讀 Release 上的 fw-inventory-<slug>.json，用 repo 當下的三張表
# （Intel 微碼、NVIDIA vBIOS、廠商公告規則）重新比對，重新產生狀態、SBOM 與報告。完全離線：不讀映像、不連網、不重新解析。
# 用法：pipeline/firmware-rematch.sh --meta <firmware-meta.json> --dir <附件資料夾> --now <UTC，例如 2026-11-21T02:00:00Z> --out <資料夾>
#   --out 必須不存在或是空資料夾。--now 必填（時只收 00～23）。
# 輸出（在 --out）：rematch-<slug>.json、fw-<slug>.cdx.json、fw-inventory-<slug>.md、rematch-summary.json（說明見 docs/notes/c2-firmware-rematch.md）。
# stdout：每個樣本一行 FIRMWARE-REMATCH<TAB>OK|ATTENTION|GAP<TAB><slug><TAB>說明；寫不出輸出時 FIRMWARE-REMATCH<TAB>FAIL<TAB>-<TAB>原因。
# 退出碼：0＝每個樣本都是 OK；2＝有 ATTENTION 或 GAP（輸出照寫）；1＝FAIL；64＝參數錯誤。不輸出 NOT_RUN（沒跑或沒有輸出，由呼叫端標）。
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
tool="$root/tools/cra/x86_firmware.py"

fail() {      # 狀態行永遠是 FIRMWARE-REMATCH 開頭；說明裡的換行與 tab 換成空白
  local msg=${2//$'\n'/ }
  printf 'FIRMWARE-REMATCH\tFAIL\t-\t%s\n' "${msg//$'\t'/ }"
  exit "$1"
}

meta=""; dir=""; now=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --meta) [ $# -ge 2 ] || fail 64 "--meta 少了參數"; meta=$2; shift 2 ;;
    --dir)  [ $# -ge 2 ] || fail 64 "--dir 少了參數"; dir=$2; shift 2 ;;
    --now)  [ $# -ge 2 ] || fail 64 "--now 少了參數"; now=$2; shift 2 ;;
    --out)  [ $# -ge 2 ] || fail 64 "--out 少了參數"; out=$2; shift 2 ;;
    *) fail 64 "未知參數 $1" ;;
  esac
done
[ -n "$meta" ] && [ -n "$dir" ] && [ -n "$now" ] && [ -n "$out" ] || fail 64 "用法：firmware-rematch.sh --meta <firmware-meta.json> --dir <附件資料夾> --now <UTC> --out <資料夾>（四個都要給）"
[ -f "$tool" ] || fail 1 "找不到 x86_firmware.py"

exec python3 -I "$tool" --rematch --meta "$meta" --dir "$dir" --now "$now" --out "$out"
