#!/usr/bin/env bash
# CI 用：對每個 kind: bios、status: ok 的樣本跑 firmware-bios.sh，再跑 firmware-expect.py。
# 用法：pipeline/firmware-ci.sh <下載資料夾（firmware-fetch 的 --out）> <工作資料夾> <產出資料夾> <摘要.md> [firmware.yml...]
#   沒有指定 firmware.yml 時用 firmware/bios/*/firmware.yml。
# 產出：<產出>/<樣本>/{fw.cdx.json,fw-inventory.json,fw-inventory.md,expect.log}；摘要.md 是每個樣本一列的 markdown 表。
# 退出碼：1＝有樣本 firmware-bios.sh FAIL（exit 1 或 64）、expected 有 MISMATCH／MISSING、輸入準備失敗或格式錯誤；
#   firmware-bios.sh 的 ATTENTION／GAP（exit 2）不算失敗。沒有可解析輸入的樣本記 NOT_RUN，也算失敗（不能悄悄略過）。
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
[ $# -ge 4 ] || { echo "用法：firmware-ci.sh <下載資料夾> <工作資料夾> <產出資料夾> <摘要.md> [firmware.yml...]" >&2; exit 64; }
dl=$1; work=$2; art=$3; summary=$4; shift 4
if [ $# -gt 0 ]; then manifests=("$@"); else manifests=("$root"/firmware/bios/*/firmware.yml); fi
mkdir -p "$work" "$art"

{
  echo '| 樣本 | firmware-bios 狀態行 | 元件數 | expected 比對 | 微碼公告比對（候選不是確定受影響） |'
  echo '|---|---|---|---|---|'
} > "$summary"

# 摘要.md 的儲存格：狀態行與 expected 說明含解析出來的文字，一律經共用的 md_safe（濾控制字元、跳脫 markdown 特殊字元、截短）
cell() { python3 -I "$here/lib/firmware_mdsafe.py" --limit 600 -- "$1"; }

rc=0
for m in "${manifests[@]}"; do
  slug=$(basename "$(dirname "$m")")
  if ! python3 -I -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1],encoding="utf-8")); sys.exit(0 if isinstance(d,dict) and d.get("kind")=="bios" and d.get("status")=="ok" else 3)' "$m"; then
    continue          # vbios 或 GAP：不在這裡處理
  fi
  out="$art/$slug"; mkdir -p "$out"
  if ! mapfile -t inputs < <(python3 -I "$here/lib/firmware_plan.py" "$m" --dl "$dl" --work "$work"); then
    echo "FIRMWARE-CI	FAIL	$slug	輸入準備失敗"
    echo "| $slug | FAIL（輸入準備失敗） | - | NOT_RUN | - |" >> "$summary"; rc=1; continue
  fi
  if [ ${#inputs[@]} -eq 0 ]; then
    echo "FIRMWARE-CI	NOT_RUN	$slug	沒有 role: image／package 的檔案"
    echo "| $slug | NOT_RUN（沒有可解析的檔案） | - | NOT_RUN | - |" >> "$summary"; rc=1; continue
  fi
  line=$("$here/firmware-bios.sh" "${inputs[@]}" --out "$out"); brc=$?
  printf '%s\n' "$line"
  case $brc in 0|2) ;; *) rc=1 ;; esac
  count=$(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["components"]))' "$out/fw.cdx.json" 2>/dev/null || echo "-")
  python3 -I "$here/firmware-expect.py" "$m" --out "$out" --strict > "$out/expect.log"; erc=$?
  cat "$out/expect.log"
  [ "$erc" -eq 0 ] || rc=1
  est=$(grep -P '^FIRMWARE-EXPECT\tSUMMARY\t' "$out/expect.log" | cut -f4)
  [ -n "$est" ] || est=$(grep -P '^FIRMWARE-EXPECT\tERROR\t' "$out/expect.log" | cut -f4)
  [ "$erc" -eq 0 ] || est="${est:-expect 失敗}（exit $erc）"
  [ "$erc" -eq 0 ] && flag="" || flag="**不符**："
  adv=$(python3 -I "$here/lib/firmware_advisory_cell.py" "$out/fw-inventory.json" 2>/dev/null || echo "-")
  echo "| $slug | $(cell "${line#FIRMWARE-BIOS$'\t'}") | $count | $flag$(cell "$est") | $(cell "$adv") |" >> "$summary"
  # 不符的明細也寫進摘要，方便不點進 log 就看到
  if [ "$erc" -ne 0 ]; then
    { echo; echo "<details open><summary>$slug 不符明細</summary>"; echo; echo '```'
      grep -P '^FIRMWARE-EXPECT\t(MISMATCH|MISSING|NOT_RUN|ERROR)\t' "$out/expect.log" | cut -f2-
      echo '```'; echo "</details>"; echo; } >> "$summary.detail"
  fi
done
[ -f "$summary.detail" ] && { echo; cat "$summary.detail"; } >> "$summary" && rm -f "$summary.detail"
echo "FIRMWARE-CI	DONE	-	退出碼 $rc（這不是整體通過；每個樣本以上方的狀態行為準）"
exit $rc
