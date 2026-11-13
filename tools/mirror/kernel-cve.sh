#!/usr/bin/env bash
# 更新主機角色（需連網）：下載 Linux 核心 CNA（kernel.org）的 CVE 紀錄，給 tools/pilot/lib/kernel_config.py（sca-scan 的 C-kernel-config）用，
# 寫出 manifest。kernel_config.py 只用每筆紀錄的 containers.cna.affected[].programFiles（修補動到的檔案）。
# 來源的選擇（2026-11-02 實測）：
#   - git.kernel.org/pub/scm/linux/security/vulns.git（CNA 自己的 repo）：cve/published/<年>/CVE-….json 共 18,164 筆（168 MB），
#     shallow clone 約 73 MB（伺服器不支援 --filter，所以連 .mbox／.dyad 一起下載），約 30 秒。
#   - cvelistV5（CVE Program 的全部 CVE）：每日的 zip 超過 500 MB，Linux 核心只是其中一部分，同一份 CNA 紀錄。
#   選 vulns.git：比較小，而且是 CNA 的原始資料。只把 cve/published/*/CVE-*.json 打包成一個 zip（約 20 MB），其他檔案不留。
# 輸出：<鏡像>/kernel-cves.zip（成員 cve/published/<年>/CVE-….json，原樣）、<鏡像>/SOURCE（source、commit、commit_date、fetched_utc、
#   zip_sha256、zip_bytes、records、unpacked_bytes）。--check 與 kernel_config.py 都比對 SOURCE 的 sha256，新舊依 fetched_utc。
# 用法：kernel-cve.sh <鏡像輸出資料夾（必須全新）> <manifest 輸出檔>
#       kernel-cve.sh --check <鏡像資料夾>
# 環境變數：
#   KERNEL_CVE_GIT_URL         來源（預設 https://git.kernel.org/pub/scm/linux/security/vulns.git；只接受 https:// 與 file://）
#   KERNEL_CVE_MAX_AGE_DAYS    --check 的新舊上限（預設 7；與 kernel_config.py 相同。過期只會讓新的 CVE 變成「沒有紀錄」→ unknown，
#                              不會產生錯的「沒編進核心」，所以比 NVD／OSV 的 3 天寬）
#   KERNEL_CVE_MIN_RECORDS     至少幾筆紀錄（預設 10000），防止拿到空的或一部分
#   KERNEL_CVE_MAX_DOWNLOAD_MB clone 寫入的單一檔案上限（預設 500；以 ulimit -f 擋，git 的 pack 超過就失敗）
#   KERNEL_CVE_MAX_RECORD_KB   單筆紀錄上限（預設 4096；實測最大約 1 MB）；KERNEL_CVE_MAX_UNPACKED_MB 全部紀錄合計上限（預設 1500）
#   KERNEL_CVE_GIT_TIMEOUT     每次 clone 的時間上限秒數（預設 900）；ls-remote 固定 120 秒
#   KERNEL_CVE_GIT_TRIES       clone 最多試幾次（預設 3；runner 連 git.kernel.org 偶爾逾時）；KERNEL_CVE_GIT_RETRY_DELAY 第一次重試前
#                              等幾秒（預設 30，之後每次加倍：30、60…）。傳輸 60 秒低於 1 KB/s 就放棄這一次（http.lowSpeedLimit／Time）。
#                              全部失敗才 FAIL；不換來源、不用舊資料頂替
#   KERNEL_CVE_REUSE_FROM      上一份鏡像：上游的 HEAD commit（git ls-remote）和它的 SOURCE 相同、而且 zip 的 sha256 相符時沿用，不重新 clone
# 安全：下載的內容不可信，只讀：git 不 checkout（--no-checkout），hooks 指到 /dev/null，只允許 https 與 file 協定；
#   紀錄以 git ls-tree＋cat-file 讀出（不用 git archive，不套用 repo 裡的 .gitattributes）；只收 cve/published/<年>/CVE-<年>-<數字>.json
#   的一般檔案（mode 100644）；--check 遇到一般檔案與資料夾以外的東西（符號連結、FIFO、裝置）一律失敗（鏡像會被 root 的 mirror-sync.sh 複製）。
set -euo pipefail
URL="${KERNEL_CVE_GIT_URL:-https://git.kernel.org/pub/scm/linux/security/vulns.git}"
case $URL in https://*|file://*) ;; *) echo "FAIL KERNEL_CVE_GIT_URL 只接受 https:// 或 file://：$URL" >&2; exit 3;; esac
for v in KERNEL_CVE_MAX_AGE_DAYS KERNEL_CVE_MIN_RECORDS KERNEL_CVE_MAX_DOWNLOAD_MB KERNEL_CVE_MAX_RECORD_KB KERNEL_CVE_MAX_UNPACKED_MB KERNEL_CVE_GIT_TIMEOUT \
         KERNEL_CVE_GIT_TRIES KERNEL_CVE_GIT_RETRY_DELAY; do
  [ -z "${!v:-}" ] || [[ "${!v}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "FAIL $v 必須是數字" >&2; exit 3; }; done
GITC=(git -c core.hooksPath=/dev/null -c protocol.allow=never -c protocol.https.allow=always -c protocol.file.allow=always -c core.fsmonitor=false
      -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60)
check() {
  python3 -I - "$1" "${KERNEL_CVE_MAX_AGE_DAYS:-7}" "${KERNEL_CVE_MIN_RECORDS:-10000}" "${KERNEL_CVE_MAX_UNPACKED_MB:-1500}" "${KERNEL_CVE_MAX_RECORD_KB:-4096}" "${2:-0}" <<'PY'
import datetime, hashlib, json, os, re, stat, sys, zipfile
d, max_age, min_rec, max_mb, max_kb, full = sys.argv[1], float(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), sys.argv[6] == "1"
ORG = "f4215fc3-5b6b-47ff-a258-f7189bd81038"      # Linux 核心 CNA（kernel.org）的 assignerOrgId
NAME = re.compile(r"^cve/published/(\d{4})/CVE-(\d{4})-\d{4,}\.json$")
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
if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", src.get("commit", "")):
    fail("SOURCE 的 commit 不是 git 的雜湊")
p = os.path.join(d, "kernel-cves.zip")
if not os.path.isfile(p):
    fail("缺少 kernel-cves.zip")
h = hashlib.sha256()
with open(p, "rb") as f:
    for b in iter(lambda: f.read(1 << 20), b""):
        h.update(b)
if h.hexdigest() != src.get("zip_sha256"):
    fail("kernel-cves.zip 的 sha256 與 SOURCE 不符")
try:
    z = zipfile.ZipFile(p)
    infos = z.infolist()
except (zipfile.BadZipFile, OSError) as ex:
    fail(f"kernel-cves.zip 不是可讀的 zip（{type(ex).__name__}）")
bad = [i.filename for i in infos if not NAME.match(i.filename) or NAME.match(i.filename).group(1) != NAME.match(i.filename).group(2)]
if bad:
    fail(f"kernel-cves.zip 有不是 cve/published/<年>/CVE-….json 的成員：{bad[0][:120]}")
big = [i.filename for i in infos if i.file_size > max_kb << 10]
if big:
    fail(f"紀錄太大（> {max_kb} KB）：{big[0]}")
unpacked = sum(i.file_size for i in infos)
if unpacked > max_mb << 20:
    fail(f"解壓後 {unpacked >> 20} MB > KERNEL_CVE_MAX_UNPACKED_MB={max_mb}")
if len(infos) < min_rec:
    fail(f"只有 {len(infos)} 筆紀錄（< {min_rec}），可能只下載到一部分或來源不對")
if str(len(infos)) != src.get("records"):
    fail(f"紀錄數 {len(infos)} 與 SOURCE 的 records={src.get('records')} 不符")
# 抽幾筆確認格式：cveId 與檔名相同、是 Linux 核心 CNA 發的、有 affected
for i in infos[:: max(1, len(infos) // 5)][:5]:
    try:
        r = json.loads(z.read(i))
    except (ValueError, zipfile.BadZipFile) as ex:
        fail(f"{i.filename} 無法解析（{type(ex).__name__}）")
    meta = r.get("cveMetadata") or {}
    if meta.get("cveId") + ".json" != i.filename.rsplit("/", 1)[-1] or meta.get("assignerOrgId") != ORG \
            or not isinstance(((r.get("containers") or {}).get("cna") or {}).get("affected"), list):
        fail(f"{i.filename} 的格式不是預期的 Linux 核心 CNA 紀錄")
if full:
    b = z.testzip()
    if b:
        fail(f"kernel-cves.zip 壓縮檔損壞：{b}")
print(f"OK commit={src['commit']} commit_date={src.get('commit_date', '未取得')} fetched_utc={src['fetched_utc']} age_days={age:.1f} "
      f"records={len(infos)} bytes={os.path.getsize(p)} unpacked_mb={unpacked >> 20}")
PY
}
if [ "${1:-}" = "--check" ]; then check "${2:?缺少鏡像資料夾}" 0; exit $?; fi
DEST="${1:?用法見檔頭}"; MANIFEST="${2:?}"
for p in "$DEST" "$MANIFEST"; do [ ! -e "$p" ] || { echo "已存在，拒絕覆蓋：$p" >&2; exit 3; }; done
REUSE="${KERNEL_CVE_REUSE_FROM:-}"
FETCHED="$(date -u +%FT%TZ)"
mkdir -p "$DEST"
work=$(mktemp -d "$(dirname "$DEST")/.kernel-cve-clone.XXXXXX")
trap 'rm -rf "$work"' EXIT
# 上游的 HEAD（只問 commit，不下載）；取不到就照常 clone
head=$(timeout 120 "${GITC[@]}" ls-remote "$URL" HEAD 2>/dev/null | awk 'NR==1{print $1}') || head=
how=clone
if [ -n "$REUSE" ] && [ -n "$head" ] && [ -f "$REUSE/SOURCE" ] && [ -f "$REUSE/kernel-cves.zip" ] && [ ! -L "$REUSE/kernel-cves.zip" ] \
   && [ "$(sed -n 's/^commit=//p' "$REUSE/SOURCE")" = "$head" ] \
   && [ "$(sha256sum "$REUSE/kernel-cves.zip" | cut -d' ' -f1)" = "$(sed -n 's/^zip_sha256=//p' "$REUSE/SOURCE")" ]; then
  cp --reflink=auto "$REUSE/kernel-cves.zip" "$DEST/kernel-cves.zip"
  grep -E '^(commit|commit_date|records|unpacked_bytes)=' "$REUSE/SOURCE" > "$work/meta"
  how="沿用 $REUSE（上游 HEAD 沒有變：$head）"
fi
if [ "$how" = clone ]; then
  tries=${KERNEL_CVE_GIT_TRIES:-3}; tries=${tries%%.*}; [ "$tries" -ge 1 ] 2> /dev/null || tries=1
  delay=${KERNEL_CVE_GIT_RETRY_DELAY:-30}; delay=${delay%%.*}
  n=1
  until ( ulimit -f $(( ${KERNEL_CVE_MAX_DOWNLOAD_MB:-500} * 1024 ))
          timeout "${KERNEL_CVE_GIT_TIMEOUT:-900}" "${GITC[@]}" clone -q --depth 1 --no-checkout --single-branch --no-tags "$URL" "$work/v" ); do
    rm -rf "$work/v"
    if [ "$n" -ge "$tries" ]; then
      echo "FAIL git clone 試了 $n 次都失敗（每次超過 ${KERNEL_CVE_GIT_TIMEOUT:-900} 秒、連線失敗或超過 KERNEL_CVE_MAX_DOWNLOAD_MB=${KERNEL_CVE_MAX_DOWNLOAD_MB:-500}）：$URL" >&2
      exit 1
    fi
    echo "git clone 第 $n 次失敗，$delay 秒後重試（最多 $tries 次）：$URL" >&2
    sleep "$delay"; delay=$(( delay * 2 )); n=$(( n + 1 ))
  done
  [ "$n" -eq 1 ] || echo "git clone 第 $n 次成功" >&2
  # 只讀 cve/published/<年>/CVE-….json 的 blob（ls-tree＋cat-file；不 checkout，不套用 .gitattributes），打包成 zip
  python3 -I - "$work/v" "$DEST/kernel-cves.zip" "$work/meta" "${KERNEL_CVE_MAX_RECORD_KB:-4096}" "${KERNEL_CVE_MAX_UNPACKED_MB:-1500}" <<'PY'
import os, re, subprocess, sys, zipfile
repo, out, meta, max_kb, max_mb = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
NAME = re.compile(r"^cve/published/(\d{4})/CVE-(\d{4})-\d{4,}\.json$")
G = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", repo]
def fail(m):
    print(f"FAIL {m}", file=sys.stderr); sys.exit(1)
commit = subprocess.run(G + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
cdate = subprocess.run(G + ["log", "-1", "--format=%cI", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
ls = subprocess.run(G + ["ls-tree", "-r", "-z", "--full-tree", "HEAD", "cve/published"], capture_output=True, check=True).stdout
want = []
for ent in ls.split(b"\0"):
    if not ent:
        continue
    info, path = ent.split(b"\t", 1)
    mode, typ, sha = info.split()
    path = path.decode("utf-8", "replace")
    m = NAME.match(path)
    if m and m.group(1) == m.group(2) and typ == b"blob" and mode == b"100644":
        want.append((sha.decode(), path))
p = subprocess.Popen(G + ["cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
total = 0
with zipfile.ZipFile(out + ".tmp", "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for sha, path in sorted(want, key=lambda x: x[1]):
        p.stdin.write(sha.encode() + b"\n"); p.stdin.flush()
        hdr = p.stdout.readline().split()
        if len(hdr) != 3 or hdr[1] != b"blob":
            fail(f"讀不到 {path}")
        size = int(hdr[2])
        if size > max_kb << 10:
            fail(f"{path} 太大（{size} bytes > KERNEL_CVE_MAX_RECORD_KB={max_kb}）")
        data = p.stdout.read(size); p.stdout.read(1)
        total += size
        if total > max_mb << 20:
            fail(f"紀錄合計超過 KERNEL_CVE_MAX_UNPACKED_MB={max_mb}")
        zi = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, data)
p.stdin.close(); p.wait()
os.replace(out + ".tmp", out)
with open(meta, "w", encoding="utf-8") as f:
    f.write(f"commit={commit}\ncommit_date={cdate}\nrecords={len(want)}\nunpacked_bytes={total}\n")
print(f"{len(want)} 筆紀錄，{total} bytes（commit {commit[:12]}，{cdate}）")
PY
  rm -rf "$work/v"
fi
sha=$(sha256sum "$DEST/kernel-cves.zip" | cut -d' ' -f1); sz=$(stat -c %s "$DEST/kernel-cves.zip")
{ printf 'source=%s\nfetched_utc=%s\nzip_sha256=%s\nzip_bytes=%s\n' "$URL" "$FETCHED" "$sha" "$sz"; cat "$work/meta"; } > "$DEST/SOURCE"
echo "kernel-cves.zip：$how，$sz bytes"
check "$DEST" 1    # 下載時多做一次完整的 CRC 檢查（testzip）
{
  echo "# source: $URL"; echo "# fetched_utc: $FETCHED"; echo "# $(grep -E '^commit=' "$DEST/SOURCE")"
  echo "# files: $(find "$DEST" -type f | wc -l)  bytes: $(du -sb "$DEST" | cut -f1)"
  (cd "$DEST" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
} > "$MANIFEST"
echo "OK mirror=$DEST manifest=$MANIFEST"
