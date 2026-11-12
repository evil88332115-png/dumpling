#!/usr/bin/env bash
# 韌體 SBOM 上傳臨時 Dependency-Track（DT）：每個樣本 prep → expected → sca-scan --sbom → scan-status-check → dt-verify，最後 report。
# workflow（.github/workflows/firmware.yml 的 firmware-dt）與本機用同一支。臨時 DT 的 up／wait／env／down 不在這裡（由呼叫端做）：
#   呼叫前先 `pipeline/dt-ephemeral.sh up`、`wait`、`env <自己的子資料夾>/pilot.env` 並 `export PILOT_ENV=…`；
#   wait 的結束碼寫進 <結果>/dt-wait.rc（3＝GAP，report 會把所有樣本標 GAP）。沒有 PILOT_ENV 時 sca-scan 的上傳階段是 NOT_RUN。
#
# 用法：pipeline/firmware-dt.sh --work <工作資料夾> --result <結果資料夾>
#          [--sample <firmware.yml> <SBOM>]...          已有 SBOM 的樣本（BIOS：firmware-ci.sh 的 fw.cdx.json；供應商 SBOM：下載的 *.sbom.json）
#          [--synthetic-vbios <firmware.yml>]           用 tools/cra/tests/synthetic_vbios.py 產合成 ROM → firmware-bios.sh → SBOM（firmware.yml 是 GAP 的 vBIOS）
# 輸出：<結果>/<專案名>/{scan/,summary.json,summary.md}（sca-scan 與 dt-verify 的輸出）、<結果>/report/firmware-dt.md、<結果>/firmware-dt.log
# stdout：每個步驟的狀態行，最後是 report 的 FIRMWARE-DT 行（每個樣本一行）。沒有整體 PASS 或「安全」的結論。
# 退出碼：0＝每個步驟都跑完且沒有 FAIL；1＝有 FAIL（prep 失敗、sca-scan 失敗、必要階段不是 OK、dt-verify FAIL、report FAIL）；64＝參數錯誤。
#   GAP／ATTENTION／NOT_RUN 本身不讓結束碼變 1（report 的狀態行才是結果）；單一樣本失敗不中止其他樣本。
#
# 必要階段（scan-status-check.py 的第二個參數起）：和 C1 的預設清單相同的 11 個，一個都沒拿掉（A-source、B-sandbox、B-sandbox-secrets、
#   B-sbom-provided、C-grype、C-upload-sbom、D-dt-project、D-dt-upload、D-dt-bom-processing、D-dt-vuln-analysis、F-secret-scan）。
#   C-sbomgate 不在清單內，也不能要求：sbomgate 只把 library／framework 算成套件，firmware 類型列為忽略，所以韌體 SBOM 的 C-sbomgate
#   一定是 NOT_ASSESSED（預期，不是失敗；漏洞比對的缺口由 report 的 NOT_ASSESSED／GAP 欄位說明）。
#   明列清單是為了 C1 之後改預設時，韌體要求的階段不會被悄悄改掉。環境變數 FIRMWARE_DT_NEED（空白分隔）可覆寫，測試用。
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
fdt="$here/lib/firmware_dt.py"

usage() { echo "用法：firmware-dt.sh --work <工作資料夾> --result <結果資料夾> [--sample <firmware.yml> <SBOM>]... [--synthetic-vbios <firmware.yml>]" >&2; exit 64; }

work=""; result=""
yml=(); sbom=(); synth=()      # 樣本：yml[i]、sbom[i]、synth[i]（1＝合成）
vb_yml=()
while [ $# -gt 0 ]; do
  case "$1" in
    --work)   [ $# -ge 2 ] || usage; work=$2; shift 2 ;;
    --result) [ $# -ge 2 ] || usage; result=$2; shift 2 ;;
    --sample) [ $# -ge 3 ] || usage; yml+=("$2"); sbom+=("$3"); synth+=(0); shift 3 ;;
    --synthetic-vbios) [ $# -ge 2 ] || usage; vb_yml+=("$2"); shift 2 ;;
    *) echo "未知參數：$1" >&2; usage ;;
  esac
done
if [ -z "$work" ] || [ -z "$result" ]; then usage; fi
[ ${#yml[@]} -gt 0 ] || [ ${#vb_yml[@]} -gt 0 ] || { echo "沒有樣本（--sample 或 --synthetic-vbios）" >&2; usage; }
mkdir -p "$work" "$result" || exit 64

if [ -n "${FIRMWARE_DT_NEED:-}" ]; then read -r -a need <<< "$FIRMWARE_DT_NEED"
else need=(A-source B-sandbox B-sandbox-secrets B-sbom-provided C-grype C-upload-sbom D-dt-project D-dt-upload D-dt-bom-processing D-dt-vuln-analysis F-secret-scan); fi

rc=0
log="$result/firmware-dt.log"; : > "$log"
say() { printf '%s\n' "$*" | tee -a "$log"; }
cell() { python3 -I "$here/lib/firmware_mdsafe.py" --limit 300 -- "$1"; }

# 合成 vBIOS：ROM → SBOM（失敗只記 FAIL，不中止其他樣本）
for m in "${vb_yml[@]}"; do
  d="$work/synthetic-vbios-$(basename "$(dirname "$m")")"; mkdir -p "$d/rom" "$d/out"
  if python3 -I "$root/tools/cra/tests/synthetic_vbios.py" --out "$d/rom/synthetic-nvidia-option-rom.rom" > "$d/gen.log" 2>&1; then
    line=$("$here/firmware-bios.sh" "$d/rom" --out "$d/out"); brc=$?
    say "$line"
    case $brc in
      0|2) yml+=("$m"); sbom+=("$d/out/fw.cdx.json"); synth+=(1) ;;
      *) say "FIRMWARE-DT-STEP	FAIL	$m	合成 vBIOS 的 firmware-bios.sh 退出碼 $brc"; rc=1 ;;
    esac
  else
    say "FIRMWARE-DT-STEP	FAIL	$m	合成 ROM 產生失敗（見 $d/gen.log）"; rc=1
  fi
done

# prep、expected
preps=()
for i in "${!yml[@]}"; do
  m=${yml[$i]}; s=${sbom[$i]}
  slug=$(basename "$(dirname "$m")")
  p="$work/prep/$slug"
  args=(prep --sbom "$s" --sample "$m" --out "$p"); [ "${synth[$i]}" = 1 ] && args+=(--synthetic)
  if python3 -I "$fdt" "${args[@]}" | tee -a "$log" | grep -q $'^FIRMWARE-DT-PREP\tOK\t' \
     && python3 -I "$fdt" expected --prep "$p" | tee -a "$log" | grep -q $'^FIRMWARE-DT-EXPECTED\tOK\t'; then
    preps+=("$p")
  else
    say "FIRMWARE-DT-STEP	FAIL	$slug	prep 或 expected 失敗（這個樣本不會上傳）"; rc=1
  fi
done

# 每個樣本：sca-scan → scan-status-check → dt-verify。單一步驟失敗不中止後面的樣本。
wait_rc=""
[ -f "$result/dt-wait.rc" ] && wait_rc=$(tr -d '[:space:]' < "$result/dt-wait.rc")
for p in "${preps[@]}"; do
  name=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["project_name"])' "$p/dt-project.json")
  ver=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["project_version"])' "$p/dt-project.json")
  sd="$result/$name"
  if [ -e "$sd/scan" ]; then       # sca-scan 不接受非空的輸出資料夾；舊結果也不能混進這次的 report
    say "FIRMWARE-DT-STEP	FAIL	$name	結果資料夾已有舊結果（$sd/scan）：請用全新的 --result 資料夾"; rc=1; continue
  fi
  mkdir -p "$sd"
  if [ ! -x "$root/tools/pilot/sca-scan" ]; then
    say "FIRMWARE-DT-STEP	NOT_RUN	$name	沒有 tools/pilot/sca-scan（C1 的工具還沒進這個分支）"; continue
  fi
  # firmware.yml 宣告 expected_dt（DT 會拒收這份 SBOM）的樣本：sca-scan 結束碼 1、必要階段不是 OK、dt-verify 失敗是預期的後果，
  # 這三步不單獨讓結束碼變 1；是否真的「只有被拒收這一個原因」由 report 核對 status.tsv 與 summary.json（其他失敗照常 FAIL）。
  declared=$(python3 -I -c 'import json,sys; print(1 if json.load(open(sys.argv[1])).get("expected_dt") else 0)' "$p/dt-project.json")
  srcrc=0
  "$root/tools/pilot/sca-scan" --sbom "$p/sbom.cdx.json" --name "$name" --version "$ver" --out "$sd/scan" --no-license \
    > "$sd/sca-scan.log" 2>&1 || srcrc=$?
  tail -3 "$sd/sca-scan.log" >> "$log"
  case $srcrc in
    0|2) ;;           # 2＝沒有 FAIL，但有 NOT_RUN／GAP／ATTENTION
    1) if [ "$declared" = 1 ]; then say "FIRMWARE-DT-STEP	EXPECTED	$name	sca-scan 結束碼 1（firmware.yml 宣告 expected_dt，交給 report 核對）"
       else say "FIRMWARE-DT-STEP	FAIL	$name	sca-scan 結束碼 1"; rc=1; fi ;;
    *) say "FIRMWARE-DT-STEP	FAIL	$name	sca-scan 結束碼 $srcrc"; rc=1 ;;
  esac
  if [ -f "$sd/scan/status.tsv" ]; then
    if line=$(python3 -I "$root/pipeline/scan-status-check.py" "$sd/scan/status.tsv" "${need[@]}"); then
      say "FIRMWARE-DT-STEP	OK	$name	$(cell "$line")"
    elif [ "$wait_rc" = 3 ]; then
      say "FIRMWARE-DT-STEP	GAP	$name	必要階段不是 OK，但 dt-ephemeral wait 結束碼 3（資料不完整）：$(cell "$line")"
    elif [ "$declared" = 1 ]; then
      say "FIRMWARE-DT-STEP	EXPECTED	$name	必要階段不是 OK（firmware.yml 宣告 expected_dt，交給 report 核對）：$(cell "$line")"
    else
      say "FIRMWARE-DT-STEP	FAIL	$name	$(cell "$line")"; rc=1
    fi
  else
    say "FIRMWARE-DT-STEP	FAIL	$name	sca-scan 沒有產生 status.tsv"; rc=1
  fi
  # dt-verify：FAIL 不中止其他樣本；summary.json 由 report 讀
  vrc=0
  python3 -I "$root/pipeline/dt-verify.py" verify "$p/expected.json" "$sd" > "$sd/verify.log" 2>&1 || vrc=$?
  tail -3 "$sd/verify.log" >> "$log"
  if [ "$vrc" -eq 0 ]; then say "FIRMWARE-DT-STEP	OK	$name	dt-verify 通過"
  elif [ "$declared" = 1 ]; then say "FIRMWARE-DT-STEP	EXPECTED	$name	dt-verify 結束碼 $vrc（firmware.yml 宣告 expected_dt，交給 report 核對）"
  else say "FIRMWARE-DT-STEP	FAIL	$name	dt-verify 結束碼 $vrc"; rc=1; fi
done

# report
if [ ${#preps[@]} -gt 0 ]; then
  python3 -I "$fdt" report --prep "${preps[@]}" --dt-result "$result" --out "$result/report" | tee -a "$log"
  [ "${PIPESTATUS[0]}" -eq 0 ] || rc=1
else
  say "FIRMWARE-DT	NOT_RUN	-	沒有成功 prep 的樣本"; rc=1
fi
say "FIRMWARE-DT-DONE	-	-	退出碼 $rc（這不是整體通過；每個樣本以上方 FIRMWARE-DT 行的狀態為準）"
exit "$rc"
