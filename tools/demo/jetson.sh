#!/usr/bin/env bash
# Jetson Linux 示範（預設 R39.2.1；JETSON_RELEASE=39.2.0 另一版。CRA 文件「示範」一節）：下載 NVIDIA 的 BSP 與範例根檔案系統 → 組成基礎版與模擬客製版兩個映像
# → 各跑一次 sca-scan（Syft、Grype、上傳 DT）→ 比對差異、在 DT 查「哪些版本受影響」。
# 用法：OUT=<結果資料夾> WORK=<暫存資料夾> PILOT_ENV=<pilot.env> tools/demo/jetson.sh
# 可選：JETSON_RELEASE=39.2.1（預設）｜39.2.0（下載網址與雜湊都寫死在下面）；DEMO_VULN_ONLY=1（sca-scan 加 --no-license：只做漏洞與 DT，不跑 ScanCode.io／DejaCode，約省一半時間）；DEMO_NO_UPLOAD=1（sca-scan 加 --no-upload，查詢階段記 NOT_RUN；這時不需要 PILOT_ENV）
#
# 規則：
# - 下載網址、NVIDIA 公布的 SHA-1（release_sha_hashes.txt，2026-10-27 讀過）寫死；下載的檔案逐一核對，另記 SHA-256。不符就停止。
#   SHA-256 是 示範掃描 下載、SHA-1 相符後記下的值，一併寫死。下載即表示同意 NVIDIA 的軟體授權協議（下載頁的說明）；使用者 2026-10-27 同意。
# - 下載的檔案是不可信資料：jetson_rootfs.py 只讀 tar／deb 結構，不解開到主機、不執行套件內容、不跑 apply_binaries.sh；
#   docker import 由 Docker 解開成映像（不啟動容器）。映像是 arm64，這台機器不會執行裡面的程式。
# - sca-scan 不做逐套件授權掃描與檔案層級掃描（--no-package-scan --no-files-scan）：deb 的下載網址是已知限制（PR 2 的範圍），
#   幾 GB 的檔案層級掃描時間太長。報告裡這兩個階段記 NOT_RUN。
# - 每個階段寫一列到 <OUT>/status.tsv，最後 Z-demo-done。退出碼：有 FAIL → 1，有其他非 OK → 2，全 OK → 0。
set -uo pipefail
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)
OUT=${OUT:?需要 OUT}; WORK=${WORK:?需要 WORK}
mkdir -p "$OUT" "$WORK"; OUT=$(cd "$OUT" && pwd); WORK=$(cd "$WORK" && pwd)
ST=$OUT/status.tsv; printf 'stage\tstatus\tdetail\n' > "$ST"
status(){ local d; d=$(printf '%s' "${3:-}" | tr '\n\t\r' '   ' | cut -c1-500 | iconv -f UTF-8 -t UTF-8 -c); printf '%s\t%s\t%s\n' "$1" "$2" "$d" >> "$ST"; echo "[$2] $1 $d"; }
finish(){
  local x; x=$(awk -F'\t' 'NR>1 && $1!="Z-demo-done"{ if($2=="FAIL") f=1; else if($2!="OK" && $2!="INFO") n=1 } END{ print f?1:(n?2:0) }' "$ST")
  status Z-demo-done INFO "jetson.sh 跑完（退出碼 $x）"; exit "$x"; }
disk(){ df -h "$WORK" | tail -1 | awk '{print "可用 "$4"／"$2}'; }
scan_worst(){  # sca-scan 的 status.tsv → 最嚴重的狀態（FAIL > NOT_ASSESSED > GAP > NOT_RUN > ATTENTION > OK）
  # 沒有檔案、沒有 F-secret-scan 列（sca-scan 沒跑完）→ FAIL；不認得的狀態當 FAIL
  [ -f "$1" ] && grep -q $'^F-secret-scan\t' "$1" || { echo FAIL; return; }
  awk -F'\t' -v vo="${DEMO_VULN_ONLY:-0}" 'BEGIN{vo=(vo=="1");r["OK"]=0;r["INFO"]=0;r["ATTENTION"]=1;r["NOT_RUN"]=2;r["GAP"]=3;r["NOT_ASSESSED"]=4;r["FAIL"]=5;w="OK";m=0}
    NR>1 && !($2=="NOT_RUN" && ($1 ~ /^E-(package-scan-submit|package-scans|package-scan-update|license-sync|copyrights|files-scan)$/ || (vo && $1 ~ /^E-/))) {
      v=(($2 in r)?r[$2]:5); if(v>m){m=v;w=(($2 in r)?$2:"FAIL")} } END{print (NR<2?"FAIL":w)}' "$1"; }

# 沒指定時：GitHub Actions 的分支名稱含 r39.2.0→ 39.2.0；其他 39.2.1
JR=${JETSON_RELEASE:-}
[ -z "$JR" ] && [[ "${GITHUB_REF_NAME:-}" == *r39.2.0* ]] && JR=39.2.0
JR=${JR:-39.2.1}
case $JR in
  39.2.1)
    REL=https://developer.download.nvidia.com/embedded/L4T/r39_Release_v2.1/release
    BSP=Jetson_Linux_R39.2.1_aarch64.tbz2;                       BSP_SHA1=8fe9a3ac9a98550b6077df450441599141ba47fb
    BSP_SHA256=2e5619088ba88e85dab25247f033d70659b6f676ff835176a07766dcb0fdbe6b
    RFS=Tegra_Linux_Sample-Root-Filesystem_R39.2.1_aarch64.tbz2; RFS_SHA1=9a991a4f94b09304d10a73c89da7d5feae11c303
    RFS_SHA256=58a6485b56c6d6b5ee8478e902eed0ed4984fd73135b88b76aeaa5c1f44be66e;;
  39.2.0)   # release_sha_hashes.txt 2026-11-04 讀過；SHA-256 是 2026-11-04 下載、SHA-1 相符後記下的值
    REL=https://developer.download.nvidia.com/embedded/L4T/r39_Release_v2.0/release
    BSP=Jetson_Linux_R39.2.0_aarch64.tbz2;                       BSP_SHA1=346043847d47793669f3f1d86d8d1a3b50c3dbb6
    BSP_SHA256=1626626cd827de0e350b8802033b9da653c69b2290accedb9e5d01f49607e099
    RFS=Tegra_Linux_Sample-Root-Filesystem_R39.2.0_aarch64.tbz2; RFS_SHA1=94b2b42f6fe2667af10f28a33900d25a4a4eea47
    RFS_SHA256=3e3e4c110dc911efcaee44fffe405d355341f4d5a169b2516bf4330f846d2037;;
  *) echo "JETSON_RELEASE 只接受 39.2.1 或 39.2.0：$JR" >&2; exit 64;;
esac
TAG_BASE=sca-demo/jetson-r$JR:base TAG_CUST=sca-demo/jetson-r$JR:custom-v1

# sca-scan 沒拿到 PILOT_ENV 時會用 repo 預設的 deploy/pilot/state/pilot.env（可能是正式部署）：示範一定要明確指定
PILOT_ENV=${PILOT_ENV:-}
if [ -z "$PILOT_ENV" ] && [ "${DEMO_NO_UPLOAD:-0}" != 1 ]; then status A-env FAIL "需要 PILOT_ENV（或 DEMO_NO_UPLOAD=1）"; finish; fi
droot=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)
status A-env INFO "$(uname -m)；docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 無)；python $(python3 -V 2>&1 | cut -d' ' -f2)；zstd $(command -v zstd > /dev/null && echo 有 || echo 無)；暫存區 $(disk)；Docker 資料 ${droot:-未知}（$( [ -n "$droot" ] && df -h "$droot" 2>/dev/null | tail -1 | awk '{print "可用 "$4"／"$2}')）"

# ---------- A. 下載與核對 ----------
D=$WORK/dl; mkdir -p "$D"
printf 'file\turl\tsha1_nvidia\tsha256\tbytes\n' > "$OUT/downloads.tsv"
if ! curl -fsSL --retry 3 --retry-max-time 600 -m 120 -o "$D/release_sha_hashes.txt" "$REL/release_sha_hashes.txt" 2> "$D/.err"; then
  status A-hashes FAIL "下載 release_sha_hashes.txt 失敗：$(tail -1 "$D/.err")"; finish; fi
cp "$D/release_sha_hashes.txt" "$OUT/release_sha_hashes.txt"
ok=1
for spec in "$BSP:$BSP_SHA1:$BSP_SHA256" "$RFS:$RFS_SHA1:$RFS_SHA256"; do
  IFS=: read -r f want want256 <<< "$spec"
  pub=$(awk -v f="$f" '{n=$2; sub(/^\*/,"",n); sub(/^\.\//,"",n); if(n==f) print $1}' "$D/release_sha_hashes.txt")
  [ "$pub" = "$want" ] || { status "A-download-$f" FAIL "NVIDIA 公布的 SHA-1 是 ${pub:-（沒有這個檔）}，和寫死的 $want 不同"; ok=0; continue; }
  t0=$(date +%s)
  if ! curl -fsSL --retry 3 --retry-max-time 3600 -m 3600 -o "$D/$f" "$REL/$f" 2> "$D/.err"; then status "A-download-$f" FAIL "下載失敗：$(tail -1 "$D/.err")"; ok=0; continue; fi
  got=$(sha1sum "$D/$f" | cut -d' ' -f1)
  [ "$got" = "$want" ] || { status "A-download-$f" FAIL "SHA-1 $got 和 NVIDIA 公布的 $want 不同"; ok=0; continue; }
  s256=$(sha256sum "$D/$f" | cut -d' ' -f1); sz=$(stat -c %s "$D/$f")
  [ "$s256" = "$want256" ] || { status "A-download-$f" FAIL "SHA-1 相符，但 SHA-256 $s256 和寫死的 $want256 不同"; ok=0; continue; }
  printf '%s\t%s\t%s\t%s\t%s\n' "$f" "$REL/$f" "$got" "$s256" "$sz" >> "$OUT/downloads.tsv"
  status "A-download-$f" OK "SHA-1 與 NVIDIA 公布的相符、SHA-256 與寫死的相符（$s256）；$sz bytes；$(( $(date +%s)-t0 )) 秒"
done
[ $ok = 1 ] || finish

# ---------- B. 組成兩個映像 ----------
t0=$(date +%s)
if python3 -I "$ROOT/tools/demo/jetson_rootfs.py" --bsp "$D/$BSP" --rootfs "$D/$RFS" --work "$WORK" \
     --out-base "$WORK/base.tar" --out-custom "$WORK/custom.tar" --report "$OUT/prep.json" > "$WORK/prep.txt" 2>&1; then
  status B-prep OK "$(tail -1 "$WORK/prep.txt")；$(( $(date +%s)-t0 )) 秒；$(disk)"
else status B-prep FAIL "jetson_rootfs.py：$(tail -1 "$WORK/prep.txt")"; cp "$WORK/prep.txt" "$OUT/prep.log"; finish; fi
rm -f "$D/$BSP" "$D/$RFS"
declare -A IID=()
for v in base custom; do
  tag=$TAG_BASE; [ $v = custom ] && tag=$TAG_CUST
  docker image rm -f "$tag" > /dev/null 2>&1 || true
  msg="sca-center demo ($v): Jetson Linux R$JR sample rootfs + BSP debs (unpacked, not installed)"
  # --platform 讓映像標成 arm64（Grype／Syft 不依賴它）；舊版 docker 不支援時不帶
  iid=$(docker import --platform linux/arm64 -m "$msg" "$WORK/$v.tar" "$tag" 2> "$WORK/import-$v.err") || \
    { grep -qi 'platform' "$WORK/import-$v.err" && iid=$(docker import -m "$msg" "$WORK/$v.tar" "$tag" 2> "$WORK/import-$v.err"); }
  if [[ "$iid" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    IID[$v]=$iid; status "B-import-$v" OK "$tag → $iid（$(docker image inspect --format '{{.Architecture}} {{.Size}} bytes' "$iid" 2>/dev/null)）"
  else status "B-import-$v" FAIL "docker import 失敗：$(tail -1 "$WORK/import-$v.err")"; fi
  rm -f "$WORK/$v.tar"
done
[ -n "${IID[base]:-}" ] && [ -n "${IID[custom]:-}" ] || finish

# ---------- C. sca-scan ----------
up=(); [ "${DEMO_NO_UPLOAD:-0}" = 1 ] && up=(--no-upload); [ "${DEMO_VULN_ONLY:-0}" = 1 ] && up+=(--no-license)
for v in base custom; do
  t0=$(date +%s)
  # DEMO_NO_UPLOAD=1 又沒有 PILOT_ENV 時給一個不存在的路徑：sca-scan 不會退回預設的正式部署設定
  PILOT_ENV=${PILOT_ENV:-$WORK/no-pilot.env} bash "$ROOT/tools/pilot/sca-scan" --image "${IID[$v]}" --name "jetson-r$JR-$v" --out "$OUT/$v" \
    --no-package-scan --no-files-scan "${up[@]}" > "$WORK/scan-$v.txt" 2>&1; x=$?
  # 狀態取 sca-scan 各階段最嚴重的；--no-package-scan、--no-files-scan 造成的 NOT_RUN 不算（示範刻意不做）
  s=$(scan_worst "$OUT/$v/status.tsv"); case $x in 0|2) ;; *) s=FAIL;; esac
  status "C-scan-$v" "$s" "sca-scan exit=$x；$(( $(date +%s)-t0 )) 秒；非 OK 階段：$(awk -F'\t' 'NR>1 && $2!="OK"{printf "%s=%s ", $1, $2}' "$OUT/$v/status.tsv" 2>/dev/null)"
done

# ---------- G. 比對與查詢 ----------
if r=$(python3 -I "$ROOT/tools/demo/jetson_lookup.py" --scan "base=$OUT/base" --scan "custom=$OUT/custom" --out "$OUT" \
         --pilot-env "${PILOT_ENV:-}" --release "$JR" 2> "$WORK/lookup.err"); then
  while IFS=$'\t' read -r s1 s2 s3; do [ -n "$s1" ] && status "$s1" "$s2" "$s3"; done <<< "$r"
else status G-lookup FAIL "jetson_lookup.py：$(tail -1 "$WORK/lookup.err")"; fi
for v in base custom; do docker image rm -f "${IID[$v]}" > /dev/null 2>&1 || true; done
finish
