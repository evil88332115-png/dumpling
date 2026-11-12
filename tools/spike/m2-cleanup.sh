#!/usr/bin/env bash
# M2 spike 第 1 件：runner 磁碟清理量測。先看有什麼、多大，再逐項刪，記每項騰出多少、花多久。
# 在 GitHub 內建 runner 上用（需要 sudo）。不碰 repo 以外的資料，不執行任何下載的檔案。
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tools/spike/m2-lib.sh
. "$HERE/m2-lib.sh"
init_res

echo "== 系統"
uname -srm; nproc; lscpu | sed -n '1,20p'; free -b
echo "== 區塊裝置與掛載"
lsblk -b 2> /dev/null || true
df -h
findmnt -no TARGET,SOURCE,FSTYPE,SIZE,AVAIL / "$MNT" 2> /dev/null || true
echo "== swap"; swapon --show 2> /dev/null || true
echo "== docker"; { command -v docker && sudo docker system df && sudo docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | head -40; } 2>&1 || echo "沒有 docker"
snap_df 清理前

echo "== 頂層用量（-x 不跨檔案系統；bytes 由大到小）"
timed du-top sh -c 'sudo du -xsb /usr/share/* /usr/local/* /usr/local/lib/* /opt/* /usr/lib/* /var/lib/* /var/cache/* /home/* /root /swapfile /mnt/* 2>/dev/null | sort -rn | head -45'

echo "== 候選項目實際存在與大小"
CANDS=(
  /usr/share/dotnet /usr/local/lib/android /opt/ghc /usr/local/.ghcup /opt/hostedtoolcache
  /usr/local/share/boost /usr/share/swift /usr/local/share/powershell /usr/local/share/chromium
  /opt/microsoft /opt/google /usr/lib/jvm /usr/local/julia /usr/lib/google-cloud-sdk
  /usr/local/aws-cli /usr/local/aws-sam-cli /usr/share/miniconda /usr/local/graalvm /opt/az /opt/pipx
  /home/linuxbrew /usr/local/lib/node_modules /usr/local/n /usr/local/share/vcpkg /usr/lib/firefox
  /usr/local/bin/aliyun /usr/local/bin/azcopy /usr/local/bin/bicep /usr/local/bin/oc /usr/local/bin/kubectl
  /usr/share/kotlin /usr/share/gradle-* /usr/local/share/kubernetes /usr/local/doc
)
EXIST=()
for p in "${CANDS[@]}"; do
  # shellcheck disable=SC2086  # 允許萬用字元展開
  for q in $p; do
    if [ -e "$q" ]; then
      b=$(sudo du -xsb "$q" 2> /dev/null | cut -f1)
      printf '%s\t%s\n' "$q" "$b" >> "$RES/candidates.tsv"
      printf '%8s GiB  %s\n' "$(gib "$b")" "$q"
      EXIST+=("$q")
    fi
  done
done
[ "${#EXIST[@]}" -gt 0 ] || echo "沒有任何候選項目存在"

echo "== 套件大小前 25 名（dpkg Installed-Size，KiB）"
dpkg-query -Wf '${Installed-Size}\t${Package}\n' 2> /dev/null | sort -rn | head -25

echo "== 逐項刪除"
for p in "${EXIST[@]}"; do
  timed "rm:$p" sudo rm -rf "$p"
done

# docker 映像
if command -v docker > /dev/null 2>&1; then
  timed docker-image-prune sudo docker image prune -af
  timed docker-system-prune sudo docker system prune -af --volumes
fi
# swap 檔
for sw in $(swapon --show=NAME --noheadings 2> /dev/null); do
  timed "swapoff:$sw" sudo swapoff "$sw"
  [ -f "$sw" ] && timed "rm-swap:$sw" sudo rm -f "$sw"
done
# apt 快取
timed apt-clean sh -c 'sudo apt-get clean && sudo rm -rf /var/lib/apt/lists/*'

snap_df 清理後
echo "== 清理後 / 與 /mnt"
df -h / "$MNT" 2> /dev/null || df -h /
echo "== 清理後頂層用量"
sudo du -xsb /usr/share/* /usr/local/* /opt/* /usr/lib/* /var/lib/* /home/* /root 2> /dev/null | sort -rn | head -15
