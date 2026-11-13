#!/usr/bin/env bash
# Jetson 轉接器 scan 步驟：臨時 DT → 鏡像資料 → 精靈（完整掃描）→ 分層（每層重跑比對）→ 收集報告 → 標準答案比對。
# 收到 <專案資料夾> <版本>，環境變數見 pipeline/platform.sh；另需 PILOT_ENV（pilot.env 的路徑；單獨一個資料夾）。
#
# 輸入：assemble 的 FlashPackage/、SourceCode/、tee-source/，build 交接的 handoff/（BuildRecord-*.tar.gz、build.json），fetch 的 downloads/。
# 輸出（$DUMPLING_OUT）：release/（Release 附件＋manifest.tsv＋notes.md）、scan.json、expected-check.txt、summary.md、wizard-out/（精靈的輸出）。
#
# 流程與理由（詳見 docs/JETSON.md「scan」）：
#  1. 臨時 DT（只開 OSV：Ubuntu、PyPI、Go、Maven，與 CISA／ENISA KEV；關 NVD）。一邊鏡像一邊下載其他資料鏡像
#     （NVIDIA 公告、Ubuntu／OSV 發行版紀錄、Linux 核心 CNA、EUVD），寫進 pilot.env。任何一個鏡像失敗 = FAIL（弱點資料不完整，不當作沒有漏洞）。
#  2. 精靈 tools/wizard/cra-scan.py --yes 跑一次完整掃描（CI 自編的建置紀錄，不是自編模式；--platform 原樣傳下去，不從映像格式推測）：
#     Syft 產生完整 SBOM、Grype／DT 比對、核心判斷、A0 上游比對、CRA 文件、報告包。
#  3. 分層：pipeline/sbom-layers.py split 把完整 SBOM 依層拆開；依 layers.json 的 scan_plan，每一項用精靈的 --rescan-from
#     （換成該層 SBOM 的複本）重跑比對 → 一個 DT 專案（<名稱>-bsp、<名稱>-os）＋一份報告包。
#     完整掃描的那次也上傳了一個 DT 專案（<名稱>），報告當作「全部」的對照；分層的報告才是 bsp／os 各自的待辦。
#  4. 收集：Release 附件（ASCII 檔名，中文標籤）、scan.json；與 tests/expected/<專案>/<版本>.json 比對，不符 = FAIL。
# 最後一行：scan: OK｜ATTENTION｜GAP｜FAIL（說明）。ATTENTION＝弱點資料鏡像用了舊資料頂替（不擋）；GAP＝資料不齊（沒有標準答案、分層有 GAP）：結果照樣產生，但不當成通過。
set -uo pipefail
proj=${1:?專案資料夾}; ver=${2:?版本}
root=${DUMPLING_ROOT:?}; out=${DUMPLING_OUT:?}
pyl() { python3 -I "$root/pipeline/lib/$1" "${@:2}"; }
fail() { echo "scan: FAIL（$*）"; exit 1; }
t0=$(date +%s)
[ -n "${PILOT_ENV:-}" ] || fail "需要環境變數 PILOT_ENV（pilot.env 的路徑，放在單獨的資料夾）"

for c in docker syft grype bwrap git python3 curl; do command -v "$c" > /dev/null || fail "缺少 $c"; done
pkg=$out/FlashPackage/$DUMPLING_PROJECT-$ver-flashpkg.tar
br=$(find "$out/handoff" -maxdepth 1 -name "BuildRecord-*.tar.gz" | head -1)
[ -f "$pkg" ] || fail "沒有 $pkg（先執行 assemble）"
[ -n "$br" ] || fail "沒有建置紀錄 BuildRecord-*.tar.gz"
rel=$(pyl jetson_build.py param "$proj" "$ver" l4t_release) || fail "sources.yml 的 $ver 沒有 platform_params.l4t_release"
bsp='' ; while IFS=$'\t' read -r role name; do [ "$role" = bsp ] && bsp=$name; done < <(pyl jetson_build.py files "$proj" "$ver")
if [ ! -f "$out/downloads/public_sources.tbz2" ] || [ ! -f "$out/downloads/$bsp" ]; then fail "downloads/ 缺 public_sources.tbz2 或 BSP"; fi
role_info=$(python3 -I "$root/pipeline/project-info.py" --dir "$proj" "$ver") || fail "project-info 失敗"
crole=$(sed -n 's/^COMPANY_ROLE=//p' <<< "$role_info")
# 平台設定（platform_params.kernel_release／kernel_upstream_version／kernel_not_distro，加上 platform.yml 的 scan.kernel_not_distro 預設）→
# 精靈的核心參數（Jetson 目前沒設定，是空的；其他平台照這樣呼叫）
kargs_out=$(python3 -I "$root/pipeline/project-info.py" --kernel-args "$proj" "$ver") || fail "platform_params 的核心參數不合法：$(tail -1 <<< "$kargs_out")"
mapfile -t kargs <<< "$kargs_out"; [ -n "$kargs_out" ] || kargs=()

# ---------- 1. 臨時 DT 與鏡像 ----------
trap 'bash "$root/pipeline/dt-ephemeral.sh" down > /dev/null 2>&1 || true' EXIT
export DT_OSV_ECOSYSTEMS=${DT_OSV_ECOSYSTEMS:-Ubuntu,PyPI,Go,Maven}
export DT_WAIT_MIN=${DT_WAIT_MIN:-60}
bash "$root/pipeline/dt-ephemeral.sh" up || fail "臨時 DT up 失敗"
export MIRRORS_DIR=$out/mirrors MIRRORS_STEPS=$out/pipeline-steps.tsv
mir=$MIRRORS_DIR; rm -rf "$mir"; mkdir -p "$mir"
# shellcheck disable=SC1091 # 路徑用變數組（$root），shellcheck 跟不到
. "$root/pipeline/lib/mirrors.sh"   # mirror：上游偶爾逾時，最多試 3 次；最後一行 ATTENTION（用舊資料頂替）算成功並記一列，其他失敗 = FAIL
mirror nvidia-bulletins.sh nvbul || fail "鏡像 nvidia-bulletins.sh 失敗（弱點資料不完整，不當作沒有漏洞）"
mirror_kernel_cve kcve || fail "鏡像 kernel-cve.sh 失敗（弱點資料不完整，不當作沒有漏洞）"
mirror euvd.sh euvd || fail "鏡像 euvd.sh 失敗（弱點資料不完整，不當作沒有漏洞）"
OSV_DISTRO_ECOSYSTEMS=Ubuntu mirror osv-distro.sh osv || fail "鏡像 osv-distro.sh 失敗（弱點資料不完整，不當作沒有漏洞）"
bash "$root/pipeline/dt-ephemeral.sh" wait || { rc=$?; [ $rc = 3 ] && fail "臨時 DT 的鏡像逾時（GAP：弱點資料不完整）"; fail "臨時 DT wait 失敗"; }
mkdir -p "$(dirname "$PILOT_ENV")"
bash "$root/pipeline/dt-ephemeral.sh" env "$PILOT_ENV" || fail "臨時 DT env 失敗"
{
  echo "NVIDIA_BULLETINS_MIRROR=$mir/nvbul"
  echo "KERNEL_CVE_MIRROR=$mir/kcve"
  echo "EUVD_MIRROR=$mir/euvd"
  echo "OSV_DISTRO_MIRROR=$mir/osv"
} >> "$PILOT_ENV"

# ---------- 2. 精靈（完整掃描） ----------
wk=$out/wizard-root; wo=$out/wizard-out
rm -rf "$wk" "$wo" "$out/release" "$out/cra-config" "$out/layers" "$out/rescan-src"; mkdir -p "$wk" "$wo" "$out/release"
pyl jetson_scan.py inputs --src "$proj/CRA/Config" --dst "$out/cra-config" --release "$rel" > /dev/null || fail "inputs.json 準備失敗"
pyl jetson_scan.py site-config --out "$out/wizard.json" --repo "$root" --root "$wk" --outroot "$wo" --pilot-env "$PILOT_ENV" \
  --grype-cache "$out/grype-db" --upstream-set "jetson-r$rel" --public-sources "$out/downloads/public_sources.tbz2" --bsp "$out/downloads/$bsp" \
  --python "$(command -v python3)" > /dev/null || fail "站台設定失敗"
export GRYPE_DB_UPDATE=online MIRROR_REFRESH_STATUS="" SCA_ARCH="${DUMPLING_ARCH:-arm64}"   # SCA_ARCH：docker import 的架構（platform.yml 的 arch）
wiz() {  # <名稱後綴> [額外參數…]  → 精靈輸出資料夾印在最後一行 "WIZARD_OUT=…"
  local suffix=$1; shift
  local tee=(); [ -d "$out/tee-source" ] && tee=(--tee-source "$out/tee-source")
  python3 -I "$root/tools/wizard/cra-scan.py" --site-config "$out/wizard.json" --archive "$pkg" --source "$out/SourceCode" --build-record "$br" \
    --name "$DUMPLING_PROJECT$suffix" --version "$ver" --rootfs rootfs --config "$out/cra-config" --role "$crole" --yes \
    --platform "$DUMPLING_PLATFORM" "${tee[@]}" "${kargs[@]+"${kargs[@]}"}" "$@" > "$out/wizard$suffix.log" 2>&1
  local rc=$?
  tail -25 "$out/wizard$suffix.log"
  [ $rc = 0 ] || return $rc
  local d; d=$(pyl jetson_scan.py newest --root "$wo" --prefix "$DUMPLING_PROJECT$suffix-") || return 1
  echo "WIZARD_OUT=$d"
}
echo "== 完整掃描（精靈）"
w0=$(wiz "" | tee /dev/stderr | sed -n 's/^WIZARD_OUT=//p') || fail "精靈（完整掃描）失敗，見 wizard.log"
if [ -z "$w0" ] || [ ! -d "$w0/報告" ]; then fail "精靈沒有產生報告包（$w0）"; fi
sbom0=$w0/scan/rootfs/scan/sbom/sbom.cdx.json
[ -s "$sbom0" ] || fail "沒有完整 SBOM（$sbom0）"

# ---------- 3. 分層 ----------
echo "== 分層"
lrc=0
python3 -I "$root/pipeline/sbom-layers.py" split "$sbom0" "$DUMPLING_PLATFORM" "$proj" "$out/layers" --os-responsibility "$DUMPLING_OS_RESPONSIBILITY" --owners "$out/owners.json" || lrc=$?
case $lrc in 0|3) ;; *) fail "sbom-layers split 失敗（結束碼 $lrc）";; esac
runs=("=$w0")
n=0
# 分隔字元是 0x1F，不是 TAB：TAB 是 IFS 空白字元，ours 的空後綴會被吃掉（檔名跑進 suffix）。後綴是空字串的那項（ours）報告取這次重跑。
plan=$(pyl jetson_scan.py plan --layers-json "$out/layers/layers.json") || fail "讀不到掃描計畫：$(tail -1 <<< "$plan")"
while IFS=$'\x1f' read -r suffix sfile; do
  [ -n "$sfile" ] || continue
  n=$((n+1))
  src=$out/rescan-src/$n; mkdir -p "$src"
  cp -a "$w0/scan" "$src/scan" && cp "$w0/wizard-steps.json" "$src/" 2> /dev/null
  cp "$out/layers/$sfile" "$src/scan/rootfs/scan/sbom/sbom.cdx.json" || fail "放不進分層 SBOM $sfile"
  echo "== 分層重跑 ${suffix:-（單一專案）}：$sfile"
  # 分層的重跑（後綴不是空的）：核心永遠在 bsp 層，os 層的 SBOM 沒有核心，核心階段不該對映像裡的核心再跑一遍 → 告訴 sca-scan 核心在 <專案>-bsp 報告判定
  # （只在 SBOM 真的沒有核心時才不執行；bsp 層有核心，照舊）。完整掃描和 ours 的單一專案重跑（後綴是空的，SBOM 是整個產品）不給。
  lk=(); [ -z "$suffix" ] || lk=(--kernel-in-other-report "$DUMPLING_PROJECT-bsp")
  wl=$(wiz "$suffix" "${lk[@]+"${lk[@]}"}" --rescan-from "$src/scan" | tee /dev/stderr | sed -n 's/^WIZARD_OUT=//p') || fail "精靈（分層 $suffix）失敗，見 wizard$suffix.log"
  if [ -z "$wl" ] || [ ! -d "$wl/報告" ]; then fail "分層 $suffix 沒有報告包"; fi
  runs+=("$suffix=$wl")
  rm -rf "$src"
done <<< "$plan"

# ---------- 4. 收集與標準答案 ----------
echo "== 收集"
runargs=(); for r in "${runs[@]}"; do runargs+=("--run=$r"); done
official=(); [ "${GITHUB_EVENT_NAME:-}" = push ] && official=(--official)
pyl jetson_scan.py collect --out "$out/release" --project "$DUMPLING_PROJECT" --version "$ver" --layers "$out/layers" \
  --build-json "$out/handoff/build.json" --assemble-json "$out/assemble.json" --scan-json "$out/scan.json" --build-record "$br" --project-dir "$proj" --steps "$out/pipeline-steps.tsv" --steps-md "$out/steps-summary.md" "${runargs[@]}" "${official[@]}" \
  || fail "收集結果失敗"
cp "$out/wizard.log" "$out/release/" 2> /dev/null; rm -f "$out/release/wizard.log"
exp=$root/tests/expected/$DUMPLING_PROJECT/$ver.json
state=OK; msg=""
if [ -f "$exp" ]; then
  if python3 -I "$root/pipeline/check-expected.py" "$exp" "$out/scan.json" | tee "$out/expected-check.txt"; then msg="標準答案比對通過"
  else fail "標準答案不符（見 expected-check.txt）"; fi
else
  state=GAP; msg="沒有標準答案 tests/expected/$DUMPLING_PROJECT/$ver.json，沒有比對"
fi
# workflow 前面步驟（validate、fetch、build、assemble…）的結果：有 GAP 或 FAIL 整體就不是 OK（pipeline/run-step.sh 寫的 pipeline-steps.tsv）
sp=$(python3 -I "$root/pipeline/lib/step_rows.py" status "$out/pipeline-steps.tsv" 2> /dev/null || echo GAP)
case $sp in
  OK) ;;
  ATTENTION) state=ATTENTION; msg="$msg；流程步驟有 ATTENTION（用了舊資料頂替，見 pipeline-steps.tsv）";;
  *) state=GAP; msg="$msg；流程步驟的整體狀態是 $sp（見 pipeline-steps.tsv）";;
esac
if [ "$lrc" = 3 ]; then state=GAP; msg="$msg；分層有 GAP（沒有 os_responsibility）"; fi   # GAP 比 ATTENTION 重，蓋過它
{
  echo "## scan（$DUMPLING_PROJECT $ver）"
  echo "- 狀態：$state（$msg）"
  python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));print("- 核心 %s；建置紀錄 %s；C-kernel-boot %s；元件 %s；上游比對 %s"%(d["kernel_release"],d["build_record_status"],d["kernel_boot"],d["components"],d["upstream_source"]));print("- 漏洞 %s"%d["vulnerabilities"])' "$out/scan.json"
  [ ! -f "$out/steps-summary.md" ] || { echo; cat "$out/steps-summary.md"; }
} > "$out/summary.md"
echo "scan: $state（$msg；用時 $(( $(date +%s) - t0 )) 秒）"
case $state in OK|ATTENTION) exit 0;; *) exit 3;; esac   # ATTENTION 不是 GAP：scan 步驟記 OK，整體狀態由 pipeline-steps.tsv 的 ATTENTION 列表示
