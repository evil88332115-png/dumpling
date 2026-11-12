#!/usr/bin/env bash
# 選用掛點 raw-sectors：清點 GPT 原始磁碟在第一個分割區之前的開機程式（idbloader、u-boot.itb），以原始磁區為準（D-027）。
# 佐證：sources.yml 裡名稱以 u-boot- 開頭的官方套件（role: package，fetch 已核對 sha256）＋映像 rootfs 的 /usr/lib/u-boot/<板子>/。
# 板子名稱取自 sources.yml 的 platform_params.uboot_board。輸出 $DUMPLING_OUT/raw-sectors.json。
# 最後一行 raw-sectors: OK｜GAP｜FAIL（…）；結束碼 OK 0、FAIL 1、GAP 3。
set -uo pipefail
root=${DUMPLING_ROOT:?}; out=${DUMPLING_OUT:?}
di=$root/pipeline/platforms/_shared/disk_image.py
img=$out/work/disk.img
[ -f "$img" ] || { echo "raw-sectors: FAIL（沒有 $img，先執行 assemble）"; exit 1; }
board=$(python3 -I "$di" param "$1" "$2" uboot_board) || { echo "raw-sectors: GAP（sources.yml 沒有 platform_params.uboot_board，不知道要比對哪個板子的套件檔）"; exit 3; }
debs=()
while IFS=$'\t' read -r role name; do
  case $name in u-boot-*.deb) [ -f "$out/downloads/$name" ] && debs+=(--deb "$out/downloads/$name");; esac
done < <(python3 -I "$di" files "$1" "$2" --role package)
exec python3 -I "$root/pipeline/platforms/rockchip/raw_sectors.py" inventory --image "$img" --out "$out/raw-sectors.json" \
  --board "$board" --platform "$DUMPLING_PLATFORM" "${debs[@]}"
