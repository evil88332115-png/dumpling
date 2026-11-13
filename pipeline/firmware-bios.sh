#!/usr/bin/env bash
# BIOS／vBIOS 映像只讀解析 → CycloneDX 1.6 SBOM（x86_firmware.py inventory 的包裝）。
# 用法：pipeline/firmware-bios.sh <檔案或資料夾>... --out <資料夾> [--manifest <版本清單.csv>]
#   輸入也可以是 .zip（x86_firmware.py 只讀、不解開到磁碟、不執行裡面的東西）。
# 輸出（在 --out）：fw.cdx.json（SBOM）、fw-inventory.json、fw-inventory.md。
# stdout 只有一行：FIRMWARE-BIOS<TAB>OK|ATTENTION|GAP|FAIL<TAB>說明（沿用 x86_firmware.py 的狀態，不顯示整體 PASS 或「安全」）。
# 退出碼：0＝OK；2＝ATTENTION 或 GAP；1＝FAIL；64＝參數錯誤。
# 狀態只代表解析的結果；每個元件的漏洞比對狀態是 NOT_ASSESSED（SBOM 的 dumpling:vuln-assessment property）。
# Intel 微碼另外離線比對 tools/cra/data/intel-microcode-releases.json（dumpling:advisory-* property、fw-inventory.md 的「公告比對」）：候選公告不是確定受影響，資料表讀不到時狀態 ATTENTION。
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
tool="$root/tools/cra/x86_firmware.py"

fail() {      # 狀態行永遠只有一行；說明裡的換行與 tab 換成空白
  local msg=${2//$'\n'/ }
  printf 'FIRMWARE-BIOS\tFAIL\t%s\n' "${msg//$'\t'/ }"
  exit "$1"
}

inputs=()
out=""
manifest=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out)
      [ $# -ge 2 ] || fail 64 "--out 少了參數"
      out=$2; shift 2 ;;
    --manifest)
      [ $# -ge 2 ] || fail 64 "--manifest 少了參數"
      manifest=$2; shift 2 ;;
    --*) fail 64 "未知參數 $1" ;;
    *) inputs+=("$1"); shift ;;
  esac
done
[ ${#inputs[@]} -gt 0 ] || fail 64 "用法：firmware-bios.sh <檔案或資料夾>... --out <資料夾> [--manifest <csv>]（沒有輸入）"
[ -n "$out" ] || fail 64 "沒有指定 --out"
[ -f "$tool" ] || fail 1 "找不到 x86_firmware.py"

args=(inventory)
for i in "${inputs[@]}"; do args+=(--in "$i"); done
[ -n "$manifest" ] && args+=(--manifest "$manifest")
args+=(--out "$out")

res=$(python3 -I "$tool" "${args[@]}")
rc=$?
line=$(printf '%s\n' "$res" | grep -m1 -P '^FW-INVENTORY\t(OK|ATTENTION|GAP|FAIL)\t') || true
if [ -z "$line" ]; then
  fail 1 "x86_firmware.py 沒有輸出狀態行（exit $rc）"
fi
printf 'FIRMWARE-BIOS\t%s\n' "${line#FW-INVENTORY$'\t'}"
exit "$rc"
