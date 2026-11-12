#!/usr/bin/env bash
# M2 spike：Jetson Linux 公開下載的網址與雜湊（以 source 載入）。用法：. m2-release.sh 39.2.1
# 值來自 tools/demo/jetson.sh（NVIDIA release_sha_hashes.txt 2026-10-27／2026-11-04 讀過的 SHA-1；
# SHA-256 是 SHA-1 相符後記下的值）。public_sources.tbz2 沒有 NVIDIA 公布的整包 SHA-1：
# 同目錄的 public_sources_sha.txt 只列包內各元件的 SHA-1，整包 SHA-256 是首次下載記錄。
JR=${1:?需要版本}
case $JR in
  39.2.1)
    REL=https://developer.download.nvidia.com/embedded/L4T/r39_Release_v2.1
    BSP=Jetson_Linux_R39.2.1_aarch64.tbz2;                        BSP_SHA1=8fe9a3ac9a98550b6077df450441599141ba47fb
    BSP_SHA256=2e5619088ba88e85dab25247f033d70659b6f676ff835176a07766dcb0fdbe6b
    RFS=Tegra_Linux_Sample-Root-Filesystem_R39.2.1_aarch64.tbz2;  RFS_SHA1=9a991a4f94b09304d10a73c89da7d5feae11c303
    RFS_SHA256=58a6485b56c6d6b5ee8478e902eed0ed4984fd73135b88b76aeaa5c1f44be66e
    SRC_SHA256=PENDING;;   # 首次下載記錄（待填）
  39.2.0)
    REL=https://developer.download.nvidia.com/embedded/L4T/r39_Release_v2.0
    BSP=Jetson_Linux_R39.2.0_aarch64.tbz2;                        BSP_SHA1=346043847d47793669f3f1d86d8d1a3b50c3dbb6
    BSP_SHA256=1626626cd827de0e350b8802033b9da653c69b2290accedb9e5d01f49607e099
    RFS=Tegra_Linux_Sample-Root-Filesystem_R39.2.0_aarch64.tbz2;  RFS_SHA1=94b2b42f6fe2667af10f28a33900d25a4a4eea47
    RFS_SHA256=3e3e4c110dc911efcaee44fffe405d355341f4d5a169b2516bf4330f846d2037
    SRC_SHA256=PENDING;;
  *) echo "版本只接受 39.2.1 或 39.2.0：$JR" >&2; return 64 2> /dev/null || exit 64;;
esac
SRC=public_sources.tbz2
export REL BSP BSP_SHA1 BSP_SHA256 RFS RFS_SHA1 RFS_SHA256 SRC SRC_SHA256
