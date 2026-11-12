#!/usr/bin/env bash
# 平台 dispatcher：workflow 只呼叫這個，依 project.yml 的 platform 欄位選轉接器。契約見 docs/PLATFORM-INTERFACE.md。
#
#   pipeline/platform.sh <步驟> <專案資料夾> <版本> [--out <資料夾>]
#   步驟：validate | fetch | build | assemble | scan | raw-sectors
#
# - validate：驗證 project.yml、sources.yml、平台設定，不做別的。
# - fetch：轉接器沒有自己的 fetch 腳本時，用共用的 pipeline/lib/platform_fetch.py（讀 sources.yml、下載核對）。
# - build／assemble／scan：執行 pipeline/platforms/<平台>/<步驟>.sh；沒有該腳本 → NOT_RUN（結束碼 4）。
# - raw-sectors（選用掛點）：執行 pipeline/platforms/<平台>/raw-sectors.sh；平台設定 raw_sectors.enabled 為 false 時
#   回報 OK（不適用）。通常由該平台自己的 assemble／scan 腳本呼叫。
# 每一步最後印一行 "<步驟>: OK|GAP|NOT_RUN|FAIL（說明）"。結束碼：0＝OK、1＝FAIL、3＝GAP、4＝NOT_RUN（沒做）、64＝用法錯誤。
#
# 轉接器收到的環境變數（都由這裡設定）：DUMPLING_ROOT、DUMPLING_PROJECT、DUMPLING_PROJECT_DIR、DUMPLING_VERSION、
# DUMPLING_PLATFORM、DUMPLING_PLATFORM_DIR、DUMPLING_OS_RESPONSIBILITY、DUMPLING_ARCH（platform.yml 的 arch，預設 arm64）、DUMPLING_OUT（預設 $DUMPLING_OUT_BASE 或 <repo>/out，
# 底下 <專案>/<版本>/；--out 直接指定）。轉接器的位置參數：<專案資料夾> <版本>。
# 可用環境變數 DUMPLING_PLATFORMS_DIR 換掉轉接器根目錄（測試用）。
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
step=${1:-}
case $step in
  validate|fetch|build|assemble|scan|raw-sectors) ;;
  *) echo "用法：platform.sh <validate|fetch|build|assemble|scan|raw-sectors> <專案資料夾> <版本> [--out <資料夾>]" >&2; exit 64;;
esac
shift
out=
proj=${1:-}; ver=${2:-}
[ $# -ge 2 ] || { echo "$step: FAIL（缺少 <專案資料夾> <版本>）"; exit 64; }
shift 2
while [ $# -gt 0 ]; do
  case $1 in
    --out) [ $# -ge 2 ] || { echo "$step: FAIL（--out 要給值）"; exit 64; }; out=$2; shift 2;;
    *) echo "$step: FAIL（不認得的參數）"; exit 64;;
  esac
done
fail() { echo "$step: FAIL（$*）"; exit 1; }
if [ ! -d "$proj" ] || [ -L "$proj" ]; then fail "專案資料夾不存在或是 symlink"; fi
proj=$(cd "$proj" && pwd)
pname=$(basename "$proj")
plat_root=${DUMPLING_PLATFORMS_DIR:-$here/platforms}

# 驗證專案＋取平台名稱（project.yml 沒給或不認得 → FAIL，不猜）
info=$(python3 -I "$here/project-info.py" --dir "$proj" "$ver") || fail "$(printf '%s' "$info" | head -1 | sed 's/^project-info: FAIL（//; s/）$//')"
platform=$(sed -n 's/^PLATFORM=//p' <<< "$info")
osr=$(sed -n 's/^OS_RESPONSIBILITY=//p' <<< "$info")
arch=$(sed -n 's/^ARCH=//p' <<< "$info")
pdir=$plat_root/$platform
[ -f "$pdir/platform.yml" ] || fail "未知平台 $platform"
python3 -I "$here/lib/project_config.py" platform "$pdir/platform.yml" > /dev/null || fail "平台設定 $platform 驗證失敗"
if [ "$step" = validate ]; then echo "validate: OK（$pname $ver，平台 $platform）"; exit 0; fi

out=${out:-${DUMPLING_OUT_BASE:-$root/out}/$pname/$ver}
mkdir -p "$out" || fail "無法建立輸出資料夾"
export DUMPLING_ROOT=$root DUMPLING_PROJECT=$pname DUMPLING_PROJECT_DIR=$proj DUMPLING_VERSION=$ver \
  DUMPLING_PLATFORM=$platform DUMPLING_PLATFORM_DIR=$pdir DUMPLING_OS_RESPONSIBILITY=$osr DUMPLING_ARCH=$arch DUMPLING_OUT=$out

script=$pdir/$step.sh
case $step in
  fetch)
    if [ ! -f "$script" ]; then exec python3 -I "$here/lib/platform_fetch.py" "$proj" "$ver" --out "$out/downloads"; fi;;
  raw-sectors)
    if [ ! -f "$script" ]; then
      if python3 -I -c 'import sys;sys.path.insert(0,sys.argv[1]);import project_config as p;c=p.load_platform_config(sys.argv[2]);sys.exit(1 if c.get("raw_sectors",{}).get("enabled") else 0)' "$here/lib" "$pdir/platform.yml"; then
        echo "raw-sectors: OK（此平台不適用）"; exit 0
      fi
      fail "平台設定 raw_sectors.enabled 為 true，但沒有 raw-sectors.sh"
    fi;;
  *)
    if [ ! -f "$script" ]; then echo "$step: NOT_RUN（平台 $platform 沒有實作 $step）"; exit 4; fi;;
esac
exec bash "$script" "$proj" "$ver"
