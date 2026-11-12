#!/usr/bin/env bash
# 更新主機角色（需連網）：下載 OSV 的 Ubuntu、Debian 生態系資料（發行版自己的弱點紀錄），給 tools/pilot/lib/distro_recheck.py
# （sca-scan 的 D-distro-recheck）用，寫出 manifest。
# 來源（不是猜的）：osv.dev 公開的資料桶 https://osv-vulnerabilities.storage.googleapis.com/<生態系>/all.zip（同 dt-feeds.sh 的 OSV）。
#   ecosystems.txt 只有 Ubuntu、Debian 兩個名稱（沒有 Ubuntu:24.04 之類的子目錄）；各發行版本寫在紀錄裡 affected[].package.ecosystem：
#   Ubuntu:24.04:LTS、Ubuntu:25.10、Ubuntu:Pro:24.04:LTS（ESM）、Ubuntu:Pro:FIPS-updates:24.04:LTS…；Debian:12、Debian:13…。
#   purl 的 distro qualifier 是代號（noble、bookworm）。實測 2026-11-02：
#     Ubuntu/all.zip 806 MB（解壓約 7.9 GB；UBUNTU-CVE-* 64,670 筆、USN-* 8,266 筆、LSN-* 56 筆）；
#     Debian/all.zip 80 MB（解壓約 255 MB；DEBIAN-CVE-* 61,634 筆、DSA-* 6,246、DLA-* 4,701、DTSA-* 207、CVE-* 290）。
#   每個 CVE 一筆的紀錄（UBUNTU-CVE-<CVE>、DEBIAN-CVE-<CVE>）以檔名就能找到，upstream 欄位列 CVE；
#   USN／DSA／DLA 的 upstream（與 related）列出涵蓋的 CVE。
# 只存 zip，不解壓（distro_recheck.py 直接讀 zip 裡需要的紀錄）。目錄結構同資料桶（<輸出>/Ubuntu/all.zip），內網檔案伺服器可原樣提供。
# SOURCE：fetched_utc（下載時間；新舊依它判斷，上游 all.zip 不是每天重建：2026-11-02 時 Ubuntu 的 Last-Modified 是 2 天前）、
#   每個 zip 的 sha256、大小、上游 Last-Modified、紀錄數。--check 與 distro_recheck.py 都比對 SOURCE 的 sha256。
# 用法：osv-distro.sh <鏡像輸出資料夾（必須全新）> <manifest 輸出檔>
#       osv-distro.sh --check <鏡像資料夾>
# 環境變數：
#   OSV_DISTRO_BASE_URL        資料桶網址（預設 https://osv-vulnerabilities.storage.googleapis.com；測試可用 file://）
#   OSV_DISTRO_ECOSYSTEMS      要下載的生態系（預設 "Ubuntu Debian"；只接受這兩個）
#   OSV_DISTRO_MAX_AGE_DAYS    --check 的新舊上限（預設 3；依據 SOURCE 的 fetched_utc；與 distro_recheck.py 相同）
#   OSV_DISTRO_MIN_RECORDS     每個生態系至少幾筆「每個 CVE 一筆」的紀錄（預設 10000），防止拿到空檔或一部分
#   OSV_DISTRO_MAX_DOWNLOAD_MB 單一 zip 的下載上限（預設 3000）；OSV_DISTRO_MAX_TOTAL_MB 全部 zip 合計上限（預設 4000）
#   OSV_DISTRO_MAX_UNPACKED_MB 單一 zip 解壓後（中央目錄記的大小）合計上限（預設 30000），防 zip bomb
#   OSV_DISTRO_CURL_MAX_TIME   單一 zip 的下載時間上限秒數（預設 1800；連線上限 30 秒），卡住不會拖住每日排程
#   OSV_DISTRO_REUSE_FROM      上一份鏡像（例如 releases/<上一次>）：上游的 Last-Modified 與大小都沒變時沿用那個 zip（以 SOURCE 的 sha256 驗過），
#                              不重新下載 800 MB（deploy/pilot/osv-distro-mirror.sh 每日更新用）
# --check 遇到一般檔案與資料夾以外的東西（符號連結、FIFO、裝置）一律失敗：鏡像會被別的帳號（root 的 mirror-sync.sh）讀取與複製。
# --check 不做完整的 CRC 檢查（Ubuntu 要解壓 7.9 GB）；下載時做一次（testzip）。之後以 sha256 確認檔案沒變。
set -euo pipefail
BASE="${OSV_DISTRO_BASE_URL:-https://osv-vulnerabilities.storage.googleapis.com}"
ECOS="${OSV_DISTRO_ECOSYSTEMS:-Ubuntu Debian}"
CURL_LIMITS=(--connect-timeout 30 --max-time "${OSV_DISTRO_CURL_MAX_TIME:-1800}")
for e in $ECOS; do case $e in Ubuntu|Debian) ;; *) echo "FAIL OSV_DISTRO_ECOSYSTEMS 只接受 Ubuntu、Debian：$e" >&2; exit 3;; esac; done
check() {
  python3 -I - "$1" "${OSV_DISTRO_MAX_AGE_DAYS:-3}" "${OSV_DISTRO_MIN_RECORDS:-10000}" "${OSV_DISTRO_MAX_UNPACKED_MB:-30000}" "${2:-0}" <<'PY'
import datetime, hashlib, json, os, stat, sys, zipfile
d, max_age, min_rec, max_mb, full = sys.argv[1], float(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5] == "1"
PREFIX = {"Ubuntu": "UBUNTU-CVE-", "Debian": "DEBIAN-CVE-"}
def fail(msg):
    print(f"FAIL {msg}"); sys.exit(1)
# 先檢查型別、才開檔：符號連結可能指向鏡像外的檔案，FIFO 會讓讀取卡住
if not os.path.isdir(d):
    fail(f"不是資料夾：{d}")
for root, dirs, files in os.walk(d):
    for n in dirs + files:
        m = os.lstat(os.path.join(root, n)).st_mode
        if not (stat.S_ISREG(m) or stat.S_ISDIR(m)):
            fail(f"鏡像裡有一般檔案與資料夾以外的東西：{os.path.relpath(os.path.join(root, n), d)}")
try:
    src = dict(l.split("=", 1) for l in open(os.path.join(d, "SOURCE"), encoding="utf-8").read().splitlines() if "=" in l)
except OSError:
    fail("缺少 SOURCE（無法判斷新舊）")
try:
    fetched = datetime.datetime.fromisoformat(src["fetched_utc"].replace("Z", "+00:00"))
except (KeyError, ValueError):
    fail("SOURCE 沒有可解析的 fetched_utc")
age = (datetime.datetime.now(datetime.timezone.utc) - fetched).total_seconds() / 86400
if age > max_age:
    fail(f"過期：下載後 {age:.1f} 天 > {max_age:g}（fetched_utc={src['fetched_utc']}）")
ecos = src.get("ecosystems", "").split()
if not ecos or any(e not in PREFIX for e in ecos):
    fail(f"SOURCE 的 ecosystems 不對：{src.get('ecosystems')!r}")
out = []
for e in ecos:
    p = os.path.join(d, e, "all.zip")
    if not os.path.isfile(p):
        fail(f"缺少 {e}/all.zip")
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    if h.hexdigest() != src.get(f"{e.lower()}_sha256"):
        fail(f"{e}/all.zip 的 sha256 與 SOURCE 不符")
    try:
        z = zipfile.ZipFile(p)
        infos = z.infolist()
    except (zipfile.BadZipFile, OSError) as ex:
        fail(f"{e}/all.zip 不是可讀的 zip（{type(ex).__name__}）")
    unpacked = sum(i.file_size for i in infos)
    if unpacked > max_mb << 20:
        fail(f"{e}/all.zip 解壓後 {unpacked >> 20} MB > OSV_DISTRO_MAX_UNPACKED_MB={max_mb}")
    per_cve = [i for i in infos if i.filename.startswith(PREFIX[e]) and i.filename.endswith(".json") and "/" not in i.filename]
    if len(per_cve) < min_rec:
        fail(f"{e}/all.zip 只有 {len(per_cve)} 筆 {PREFIX[e]}* 紀錄（< {min_rec}），可能只下載到一部分或來源不對")
    # 抽幾筆確認格式：id 與檔名相同、affected 的 ecosystem 是這個發行版
    for i in per_cve[:: max(1, len(per_cve) // 5)][:5]:
        if i.file_size > 64 << 20:
            fail(f"{e}/{i.filename} 太大（{i.file_size >> 20} MB）")
        try:
            r = json.loads(z.read(i))
        except (ValueError, zipfile.BadZipFile) as ex:
            fail(f"{e}/{i.filename} 無法解析（{type(ex).__name__}）")
        if r.get("id") + ".json" != i.filename or not all(str((a.get("package") or {}).get("ecosystem", "")).startswith(e + ":")
                                                        for a in r.get("affected") or []):
            fail(f"{e}/{i.filename} 的格式不是預期的 OSV {e} 紀錄")
    if full:
        bad = z.testzip()
        if bad:
            fail(f"{e}/all.zip 壓縮檔損壞：{bad}")
    out.append(f"{e}: records={len(infos)} per_cve={len(per_cve)} bytes={os.path.getsize(p)} unpacked_mb={unpacked >> 20}"
               f" upstream_last_modified={src.get(e.lower() + '_last_modified', '未取得')}")
print(f"OK fetched_utc={src['fetched_utc']} age_days={age:.1f} " + "；".join(out))
PY
}
if [ "${1:-}" = "--check" ]; then check "${2:?缺少鏡像資料夾}" 0; exit $?; fi
DEST="${1:?用法見檔頭}"; MANIFEST="${2:?}"
for p in "$DEST" "$MANIFEST"; do [ ! -e "$p" ] || { echo "已存在，拒絕覆蓋：$p" >&2; exit 3; }; done
REUSE="${OSV_DISTRO_REUSE_FROM:-}"
FETCHED="$(date -u +%FT%TZ)"
mkdir -p "$DEST"
total=0 src_lines=
for e in $ECOS; do
  lc=$(printf '%s' "$e" | tr 'A-Z' 'a-z'); url="$BASE/$e/all.zip"; mkdir -p "$DEST/$e"
  # 上游的 Last-Modified 與大小（HEAD；取不到就照常下載）
  lm=; len=
  if [[ "$url" == http* ]]; then
    h=$(curl -fsSI --connect-timeout 30 --max-time 60 "$url" 2>/dev/null | tr -d '\r') || h=
    lm=$(printf '%s\n' "$h" | sed -n 's/^[Ll]ast-[Mm]odified: *//p' | tail -1); len=$(printf '%s\n' "$h" | sed -n 's/^[Cc]ontent-[Ll]ength: *//p' | tail -1)
  fi
  how=下載
  # 沿用上一份：上游的 Last-Modified 與大小相同、上一份的 SOURCE 記了同樣的值，而且上一份的檔案 sha256 與它的 SOURCE 相符
  if [ -n "$REUSE" ] && [ -n "$lm" ] && [ -n "$len" ] && [ -f "$REUSE/SOURCE" ] && [ -f "$REUSE/$e/all.zip" ] && [ ! -L "$REUSE/$e/all.zip" ] \
     && [ "$(sed -n "s/^${lc}_last_modified=//p" "$REUSE/SOURCE")" = "$lm" ] && [ "$(sed -n "s/^${lc}_bytes=//p" "$REUSE/SOURCE")" = "$len" ]; then
    old=$(sed -n "s/^${lc}_sha256=//p" "$REUSE/SOURCE")
    if [ -n "$old" ] && [ "$(sha256sum "$REUSE/$e/all.zip" | cut -d' ' -f1)" = "$old" ]; then
      cp --reflink=auto "$REUSE/$e/all.zip" "$DEST/$e/all.zip"; how="沿用 $REUSE（上游沒有變）"
    fi
  fi
  if [ "$how" = 下載 ]; then
    curl -fsSL "${CURL_LIMITS[@]}" --max-filesize $(( ${OSV_DISTRO_MAX_DOWNLOAD_MB:-3000} * 1048576 )) --retry 3 -o "$DEST/$e/all.zip" "$url"
  fi
  sz=$(stat -c %s "$DEST/$e/all.zip"); total=$(( total + sz ))
  if [ $total -gt $(( ${OSV_DISTRO_MAX_TOTAL_MB:-4000} * 1048576 )) ]; then echo "FAIL 合計超過 OSV_DISTRO_MAX_TOTAL_MB=${OSV_DISTRO_MAX_TOTAL_MB:-4000} MB" >&2; exit 1; fi
  sha=$(sha256sum "$DEST/$e/all.zip" | cut -d' ' -f1)
  src_lines+="${lc}_url=$url"$'\n'"${lc}_sha256=$sha"$'\n'"${lc}_bytes=$sz"$'\n'"${lc}_last_modified=${lm:-未取得}"$'\n'
  echo "$e: $how，$sz bytes，Last-Modified ${lm:-未取得}"
done
printf 'source=%s\necosystems=%s\nfetched_utc=%s\n%s' "$BASE" "$ECOS" "$FETCHED" "$src_lines" > "$DEST/SOURCE"   # --check 與 distro_recheck.py 用來判斷新舊與完整
check "$DEST" 1    # 下載時多做一次完整的 CRC 檢查（testzip）
{
  echo "# source: $BASE"; echo "# ecosystems: $ECOS"; echo "# fetched_utc: $FETCHED"
  echo "# files: $(find "$DEST" -type f | wc -l)  bytes: $(du -sb "$DEST" | cut -f1)"
  (cd "$DEST" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
} > "$MANIFEST"
echo "OK mirror=$DEST manifest=$MANIFEST"
