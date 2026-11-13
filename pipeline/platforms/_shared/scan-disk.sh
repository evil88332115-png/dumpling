#!/usr/bin/env bash
# WP7 平台（raspberrypi、rockchip、ai-nas）共用的 scan 步驟：臨時 DT → 鏡像資料 → 精靈（完整掃描官方磁碟映像）→（平台的補充元件）
# → 分層（每層重跑比對）→ 收集報告 → 標準答案比對 → 刪掉解開的大檔。各平台的 scan.sh 設好下面的變數後 exec 這個檔。
# 收到 <專案資料夾> <版本>，環境變數見 pipeline/platform.sh；另需 PILOT_ENV（pilot.env 的路徑，放在單獨的資料夾）。
#
# 平台設的變數：
#   WP7_AUGMENT        none｜raw-sectors（Rockchip：assemble 的 raw-sectors.json 併成 firmware 元件）｜app-source（AI NAS：掃 NAS 應用原始碼後併入）
#   DT_OSV_ECOSYSTEMS  臨時 DT 的 OSV 生態系（平台給預設）
# 輸入：assemble 的 assemble.json（磁碟映像的相對路徑）、raw-sectors.json（Rockchip）；fetch 的 downloads/；
#       sources.yml 的 platform_params：kernel_source_file（給精靈的核心原始碼壓縮檔，role: source）、AI NAS 的 app_repo、app_commit。
# 輸出（$DUMPLING_OUT）：release/（Release 附件＋manifest.tsv＋notes.md）、scan.json、summary.md、wizard-out/。
# 平台一律由 project.yml 明確給定（scan.platform_arg，沒有就是 $DUMPLING_PLATFORM），原樣傳給精靈，不從映像格式推測。
# 最後一行：scan: OK｜GAP｜FAIL（說明）。GAP＝資料不齊（沒有標準答案、分層或補充元件有 GAP）：結果照樣產生，但不當成通過。
set -uo pipefail
proj=${1:?專案資料夾}; ver=${2:?版本}
root=${DUMPLING_ROOT:?}; out=${DUMPLING_OUT:?}
here=$root/pipeline/platforms/_shared
fail() { echo "scan: FAIL（$*）"; exit 1; }
t0=$(date +%s)
augment=${WP7_AUGMENT:-none}
case $augment in none|raw-sectors|app-source) ;; *) fail "WP7_AUGMENT 不認得：$augment";; esac
[ -n "${PILOT_ENV:-}" ] || fail "需要環境變數 PILOT_ENV（pilot.env 的路徑，放在單獨的資料夾）"
for c in docker syft grype bwrap git python3 curl; do command -v "$c" > /dev/null || fail "缺少 $c"; done
img=$(python3 -I "$here/disk_image.py" disk "$out/assemble.json" 2> /dev/null) || fail "assemble.json 沒有可用的磁碟映像（先執行 assemble）"
info=$(python3 -I "$root/pipeline/project-info.py" --dir "$proj" "$ver") || fail "project-info 失敗"
crole=$(sed -n 's/^COMPANY_ROLE=//p' <<< "$info")
parg=$(python3 -I -c 'import sys;sys.path.insert(0,sys.argv[1]);import project_config as p
print((p.load_platform_config(sys.argv[2]).get("scan") or {}).get("platform_arg") or sys.argv[2])' "$root/pipeline/lib" "$DUMPLING_PLATFORM") \
  || fail "讀不到平台設定"
if [ "$augment" = raw-sectors ] && [ ! -f "$out/raw-sectors.json" ]; then fail "沒有 raw-sectors.json（先執行 assemble）"; fi
# 精靈要一份原始碼壓縮檔（核心判斷、上游比對）：sources.yml 的 platform_params.kernel_source_file，必須是 fetch 核對過的 role: source
ksrc=$(python3 -I "$here/disk_image.py" param "$proj" "$ver" kernel_source_file) || fail "sources.yml 沒有 platform_params.kernel_source_file（精靈需要核心原始碼壓縮檔）"
python3 -I "$here/disk_image.py" files "$proj" "$ver" --role source | cut -f2 | grep -qxF -- "$ksrc" || fail "kernel_source_file（$ksrc）不是 sources.yml 裡 role: source 的檔案"
if [ ! -f "$out/downloads/$ksrc" ] || [ -L "$out/downloads/$ksrc" ]; then fail "downloads/ 沒有 $ksrc（先執行 fetch）"; fi
srcpath=$out/downloads/$ksrc; ksjson=()
# AI NAS（D-035）：assemble 套好 Debian 修補的原始碼優先；套不上（GAP）就用上游 orig，scan.json 與報告標 PARTIAL
if [ -f "$out/kernel-source.json" ]; then
  ksjson=(--kernel-source-json "$out/kernel-source.json")
  ka=$(python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["archive"] if d.get("status")=="OK" and d.get("archive") else "")' "$out/kernel-source.json") \
    || fail "kernel-source.json 讀不了"
  if [ -n "$ka" ]; then
    [[ $ka =~ ^[A-Za-z0-9._-]+$ ]] || fail "kernel-source.json 的 archive 不合法"
    [ -f "$out/work/$ka" ] || fail "沒有 work/$ka（先執行 assemble）"
    srcpath=$out/work/$ka
  fi
fi
if [ "$augment" = app-source ]; then
  arepo=$(python3 -I "$here/disk_image.py" param "$proj" "$ver" app_repo) || fail "sources.yml 沒有 platform_params.app_repo"
  acommit=$(python3 -I "$here/disk_image.py" param "$proj" "$ver" app_commit) || fail "sources.yml 沒有 platform_params.app_commit"
  [[ $acommit =~ ^[0-9a-f]{40}$ ]] || fail "app_commit 必須是 40 位 commit SHA"
  [[ $arepo =~ ^https://[A-Za-z0-9./_-]+$ ]] || fail "app_repo 必須是 https 網址"
fi

# ---------- 1. 臨時 DT 與鏡像 ----------
trap 'bash "$root/pipeline/dt-ephemeral.sh" down > /dev/null 2>&1 || true' EXIT
export DT_OSV_ECOSYSTEMS=${DT_OSV_ECOSYSTEMS:-Debian,PyPI,Go,npm,Maven}
export DT_WAIT_MIN=${DT_WAIT_MIN:-60}
bash "$root/pipeline/dt-ephemeral.sh" up || fail "臨時 DT up 失敗"
mir=$out/mirrors; rm -rf "$mir"; mkdir -p "$mir"
mirror() {  # <腳本> <資料夾名>（腳本的參數：新資料夾、manifest）
  local s=$1 d=$2
  if ! bash "$root/tools/mirror/$s" "$mir/$d" "$mir/$d.manifest" > "$mir/$d.log" 2>&1; then tail -5 "$mir/$d.log"; fail "鏡像 $s 失敗（弱點資料不完整，不當作沒有漏洞）"; fi
  echo "鏡像 $d：OK（$(tail -1 "$mir/$d.log" | cut -c1-160)）"
}
mirror kernel-cve.sh kcve
mirror euvd.sh euvd
OSV_DISTRO_ECOSYSTEMS=Debian mirror osv-distro.sh osv
bash "$root/pipeline/dt-ephemeral.sh" wait || { rc=$?; [ $rc = 3 ] && fail "臨時 DT 的鏡像逾時（GAP：弱點資料不完整）"; fail "臨時 DT wait 失敗"; }
mkdir -p "$(dirname "$PILOT_ENV")"
bash "$root/pipeline/dt-ephemeral.sh" env "$PILOT_ENV" || fail "臨時 DT env 失敗"
{
  echo "KERNEL_CVE_MIRROR=$mir/kcve"
  echo "EUVD_MIRROR=$mir/euvd"
  echo "OSV_DISTRO_MIRROR=$mir/osv"
} >> "$PILOT_ENV"

# ---------- 2. 精靈（完整掃描） ----------
wk=$out/wizard-root; wo=$out/wizard-out
rm -rf "$wk" "$wo" "$out/release" "$out/cra-config" "$out/layers" "$out/rescan-src" "$out/augment"; mkdir -p "$wk" "$wo" "$out/release" "$out/augment"
cp -r "$proj/CRA/Config" "$out/cra-config" || fail "複製 CRA/Config 失敗"
python3 -I "$here/wp7_scan.py" site-config --out "$out/wizard.json" --repo "$root" --root "$wk" --outroot "$wo" --pilot-env "$PILOT_ENV" \
  --grype-cache "$out/grype-db" --python "$(command -v python3)" > /dev/null || fail "站台設定失敗"
export GRYPE_DB_UPDATE=online MIRROR_REFRESH_STATUS="" SCA_ARCH="${DUMPLING_ARCH:-arm64}"   # SCA_ARCH：docker import 的架構（platform.yml 的 arch）
wiz() {  # <名稱後綴> [額外參數…]  → 精靈輸出資料夾印在最後一行 "WIZARD_OUT=…"
  local suffix=$1; shift
  python3 -I "$root/tools/wizard/cra-scan.py" --site-config "$out/wizard.json" --archive "$img" --source "$srcpath" \
    --name "$DUMPLING_PROJECT$suffix" --version "$ver" --rootfs rootfs --config "$out/cra-config" --role "$crole" --yes \
    --platform "$parg" "$@" > "$out/wizard$suffix.log" 2>&1
  local rc=$?
  tail -25 "$out/wizard$suffix.log"
  [ $rc = 0 ] || return $rc
  local d; d=$(python3 -I "$here/wp7_scan.py" newest --root "$wo" --prefix "$DUMPLING_PROJECT$suffix-") || return 1
  echo "WIZARD_OUT=$d"
}
echo "== 完整掃描（精靈；平台 $parg、架構 $SCA_ARCH）"
w0=$(wiz "" | tee /dev/stderr | sed -n 's/^WIZARD_OUT=//p') || fail "精靈（完整掃描）失敗，見 wizard.log"
if [ -z "$w0" ] || [ ! -d "$w0/報告" ]; then fail "精靈沒有產生報告包（$w0）"; fi
sbom0=$w0/scan/rootfs/scan/sbom/sbom.cdx.json
[ -s "$sbom0" ] || fail "沒有完整 SBOM（$sbom0）"

# ---------- 3. 補充元件（映像掃描以外：原始磁區的開機程式、NAS 應用的原始碼） ----------
arc=0; srcjson=; rsargs=()
sbom1=$sbom0
case $augment in
  raw-sectors)
    echo "== 補充：原始磁區的開機程式"
    python3 -I "$here/sbom_augment.py" raw-sectors "$sbom0" "$out/raw-sectors.json" "$out/augment/sbom.cdx.json" || arc=$?
    sbom1=$out/augment/sbom.cdx.json; rsargs=(--raw-sectors "$out/raw-sectors.json");;
  app-source)
    echo "== 補充：NAS 應用的原始碼（$arepo @ $acommit；只產生 SBOM，不上傳、不跑授權）"
    if ! bash "$root/tools/pilot/sca-scan" --git "$arepo" --ref "$acommit" --name "$DUMPLING_PROJECT-app-source" --out "$out/augment/app-scan" \
        --no-upload --no-license > "$out/augment/app-scan.log" 2>&1; then
      tail -15 "$out/augment/app-scan.log"
      # sca-scan 有非 OK 的階段也會非 0；只要 SBOM 產生了就照樣併入，狀態記成 GAP（見 status.tsv）
      arc=3
    fi
    asbom=$out/augment/app-scan/sbom/sbom.cdx.json
    [ -s "$asbom" ] || fail "NAS 應用原始碼沒有產生 SBOM（見 augment/app-scan.log）"
    mrc=0
    line=$(python3 -I "$here/sbom_augment.py" merge-source "$sbom0" "$asbom" "$out/augment/sbom.cdx.json" \
      --label app-source --repo "$arepo" --commit "$acommit") || mrc=$?
    echo "$line"
    case $mrc in 0) ;; 3) arc=3;; *) fail "併入原始碼 SBOM 失敗";; esac
    python3 -I -c 'import json,sys;json.dump({"repo":sys.argv[1],"commit":sys.argv[2],"line":sys.argv[3]},open(sys.argv[4],"w"),ensure_ascii=False)' \
      "$arepo" "$acommit" "${line#sbom-augment: }" "$out/augment/source.json"
    srcjson=$out/augment/source.json
    sbom1=$out/augment/sbom.cdx.json;;
esac
case $arc in 0|3) ;; *) fail "補充元件失敗（結束碼 $arc）";; esac

# ---------- 4. 分層 ----------
echo "== 分層"
lrc=0
owargs=(); [ -f "$out/owners.json" ] && owargs=(--owners "$out/owners.json")   # assemble 從 dpkg .list 產生；沒有時檔案紀錄會是 unknown
python3 -I "$root/pipeline/sbom-layers.py" split "$sbom1" "$DUMPLING_PLATFORM" "$proj" "$out/layers" --os-responsibility "$DUMPLING_OS_RESPONSIBILITY" ${owargs[@]+"${owargs[@]}"} || lrc=$?
case $lrc in 0|3) ;; *) fail "sbom-layers split 失敗（結束碼 $lrc）";; esac
runs=("=$w0")
n=0
while IFS=$'\t' read -r suffix sfile; do
  n=$((n+1))
  src=$out/rescan-src/$n; mkdir -p "$src"
  cp -a "$w0/scan" "$src/scan" && cp "$w0/wizard-steps.json" "$src/" 2> /dev/null
  cp "$out/layers/$sfile" "$src/scan/rootfs/scan/sbom/sbom.cdx.json" || fail "放不進分層 SBOM $sfile"
  echo "== 分層重跑 ${suffix:-（單一專案）}：$sfile"
  wl=$(wiz "$suffix" --rescan-from "$src/scan" | tee /dev/stderr | sed -n 's/^WIZARD_OUT=//p') || fail "精靈（分層 $suffix）失敗，見 wizard$suffix.log"
  if [ -z "$wl" ] || [ ! -d "$wl/報告" ]; then fail "分層 $suffix 沒有報告包"; fi
  runs+=("$suffix=$wl")
  rm -rf "$src"
done < <(python3 -I -c 'import json,sys
for it in json.load(open(sys.argv[1]))["scan_plan"]: print(it["name_suffix"] + "\t" + it["sbom"])' "$out/layers/layers.json")

# ---------- 5. 收集與標準答案 ----------
echo "== 收集"
runargs=(); for r in "${runs[@]}"; do runargs+=("--run=$r"); done
official=(); [ "${GITHUB_EVENT_NAME:-}" = push ] && official=(--official)
srcargs=(); [ -n "$srcjson" ] && srcargs=(--source-json "$srcjson")
python3 -I "$here/wp7_scan.py" collect --out "$out/release" --project "$DUMPLING_PROJECT" --version "$ver" --layers "$out/layers" \
  --assemble-json "$out/assemble.json" --scan-json "$out/scan.json" "${runargs[@]}" ${rsargs[@]+"${rsargs[@]}"} ${ksjson[@]+"${ksjson[@]}"} \
  ${srcargs[@]+"${srcargs[@]}"} ${official[@]+"${official[@]}"} || fail "收集結果失敗"
exp=$root/tests/expected/$DUMPLING_PROJECT/$ver.json
state=OK; msg=""
if [ -f "$exp" ]; then
  if python3 -I "$root/pipeline/check-expected.py" "$exp" "$out/scan.json" | tee "$out/expected-check.txt"; then msg="標準答案比對通過"
  else fail "標準答案不符（見 expected-check.txt）"; fi
else
  state=GAP; msg="沒有標準答案 tests/expected/$DUMPLING_PROJECT/$ver.json，沒有比對"
fi
if [ "$lrc" = 3 ]; then state=GAP; msg="$msg；分層有 GAP"; fi
if [ "$arc" = 3 ]; then state=GAP; msg="$msg；補充元件有 GAP（$augment）"; fi
kst=$(python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));print((d.get("kernel_source") or {}).get("status") or "")' "$out/scan.json" 2> /dev/null)
case $kst in ""|OK) ;; *) state=GAP; msg="$msg；核心原始碼判斷 $kst（見 scan.json 的 kernel_source）";; esac
{
  echo "## scan（$DUMPLING_PROJECT $ver，平台 $DUMPLING_PLATFORM）"
  echo "- 狀態：$state（$msg）"
  python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]))
print("- 映像 %s；元件 %s"%((d.get("image") or {}).get("file"),d.get("components")))
if d.get("raw_sectors"): print("- 原始磁區 %s"%d["raw_sectors"].get("status"))
if d.get("external_services"): print("- 對外連線服務 %s"%", ".join(h["name"] for h in d["external_services"]))
print("- 漏洞 %s"%d.get("vulnerabilities"))' "$out/scan.json"
} > "$out/summary.md"
# 解開的大檔用完就刪（磁碟映像可能好幾 GB；官方映像的壓縮檔留在 downloads/）
rm -f "$out/work/disk.img" "$out/work/kernel-source.tar.gz"
echo "scan: $state（$msg；用時 $(( $(date +%s) - t0 )) 秒）"
[ "$state" = OK ] && exit 0 || exit 3
