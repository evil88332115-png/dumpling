#!/usr/bin/env bash
# 更新主機角色（需連網）：下載 CISA 的已知遭利用弱點清單（KEV）官方 JSON，寫出 SOURCE 與 manifest，給內部鏡像用
# （pipeline/watch/feeds.sh 的內部鏡像模式讀 <鏡像>/known_exploited_vulnerabilities.json；match.py 的讀取方式不變）。
# 來源：CISA 官方 feed，預設 https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
#   （格式：{"title", "catalogVersion", "dateReleased", "count", "vulnerabilities": [{"cveID", …}]}；與 pipeline/watch/feeds.sh 公開模式用的是同一個檔）。
# 下載的檔案一律當不可信資料：只讀、不執行；只當 JSON 解析，不信任裡面的任何欄位當路徑或指令。
# 輸出：<鏡像>/known_exploited_vulnerabilities.json（原樣）、<鏡像>/SOURCE（source、fetched_utc、sha256、bytes、entries、date_released）。
#   SOURCE 的 sha256 是整個檔案的；--check 重算比對。entries 是 vulnerabilities 陣列的長度。
# 用法：cisa-kev.sh <鏡像輸出資料夾（必須全新）> <manifest 輸出檔>
#       cisa-kev.sh --check <鏡像資料夾>       有 SOURCE 的資料夾：驗 sha256、筆數、同步時間（fetched_utc）與內容日期（dateReleased）
#       cisa-kev.sh --check-file <JSON 檔>     只有單一檔案（沒有 SOURCE，例如別處鏡像放的單一檔）：驗 JSON 格式、筆數下限、dateReleased；
#                                              沒有同步時間可驗，也不用檔案的 mtime（複製時可能被改掉）
# 環境變數：
#   CISA_KEV_URL            來源（預設見上；只接受 https:// 與 file://，後者給測試用）
#   CISA_KEV_MIN_ENTRIES    至少幾筆合格的紀錄（cveID 符合 CVE-<年>-<數字>；預設 1000，與 feeds.sh 公開模式相同），防止拿到空檔或一部分
#   CISA_KEV_MAX_AGE_DAYS   --check 的同步時間上限（預設 3；依據 SOURCE 的 fetched_utc）。理由：KEV 是「已經有人在用」的弱點，漏掉新加入的項目比
#                           核心 CNA（7 天）嚴重，與 EUVD、OSV、Grype DB 的 3 天一致。
#   CISA_KEV_MAX_RELEASE_AGE_DAYS  內容日期上限（預設 14；依據檔案裡的 dateReleased，--check 與 --check-file 都驗；與 match.py 的 DT_KEV_MAX_AGE_DAYS 同）。
#                           dateReleased 另外驗的理由：CISA 週末與假日不發布，dateReleased 可能好幾天不變，不能拿來套 36 小時之類的短門檻；
#                           但來源本身停更 14 天以上就不能當作現況。dateReleased 必須能解析，否則失敗。
#   CISA_KEV_MAX_BYTES      檔案大小上限（預設 104857600＝100 MB；實際約 1 MB）；下載時 curl 也用同一個上限
# --check 遇到一般檔案與資料夾以外的東西（符號連結、FIFO、裝置）一律失敗：鏡像會被別的帳號（root 的同步腳本）讀取與複製；先檢查型別、才開檔。
set -euo pipefail
URL="${CISA_KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
FILE=known_exploited_vulnerabilities.json
for v in CISA_KEV_MIN_ENTRIES CISA_KEV_MAX_AGE_DAYS CISA_KEV_MAX_RELEASE_AGE_DAYS CISA_KEV_MAX_BYTES; do
  [ -z "${!v:-}" ] || [[ "${!v}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "FAIL $v 必須是數字" >&2; exit 3; }; done
py() {  # check <資料夾> …｜check-file <檔案> …｜stats <檔案> <大小上限>
  python3 -I - "$@" <<'PY'
import datetime, hashlib, json, os, re, stat, sys
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
FILE = "known_exploited_vulnerabilities.json"
NOW = datetime.datetime.now(datetime.timezone.utc)
def fail(msg):
    print(f"FAIL {msg}"); sys.exit(1)
def parse(path, max_bytes):
    """（檔案內容的 sha256、bytes、紀錄數、合格紀錄數、dateReleased）；壞掉或太大就 FAIL。"""
    if os.path.getsize(path) > max_bytes:
        fail(f"{FILE} 超過 CISA_KEV_MAX_BYTES={max_bytes}")
    raw = open(path, "rb").read()
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError) as ex:
        fail(f"{FILE} 不是可解析的 JSON（{type(ex).__name__}）")
    v = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(v, list):
        fail("vulnerabilities 不是陣列")
    good = sum(1 for x in v if isinstance(x, dict) and isinstance(x.get("cveID"), str) and CVE.match(x["cveID"].strip()))
    rel = doc.get("dateReleased")
    return hashlib.sha256(raw).hexdigest(), len(raw), len(v), good, rel if isinstance(rel, str) else ""
def release_age(rel, max_days):
    """dateReleased 的天數；無法解析、沒有時區（例如只有日期）、在未來超過 1 小時或超過上限都 FAIL。
    沒有時區不能假設是 UTC：猜錯會讓舊資料看起來是新的（CISA 官方的 dateReleased 都帶 Z）。"""
    try:
        t = datetime.datetime.fromisoformat(rel.replace("Z", "+00:00"))
    except ValueError:
        fail(f"dateReleased 無法解析：{rel[:40]!r}")
    if t.tzinfo is None:
        fail(f"dateReleased 沒有時區：{rel[:40]!r}（無法判斷新舊）")
    age = (NOW - t).total_seconds() / 86400
    if age < -1 / 24:
        fail(f"dateReleased 在未來（{rel[:40]}；主機時鐘或資料異常）")
    if age > max_days:
        fail(f"內容太舊：dateReleased {rel[:40]} 是 {age:.1f} 天前 > {max_days:g}（CISA_KEV_MAX_RELEASE_AGE_DAYS）")
    return max(age, 0.0)
mode = sys.argv[1]
if mode == "stats":
    sha, size, n, good, rel = parse(sys.argv[2], int(sys.argv[3]))
    print(f"{sha}\t{size}\t{n}\t{good}\t{rel}")
    sys.exit(0)
if mode == "check-file":
    p, min_n, max_bytes, max_rel = sys.argv[2], int(float(sys.argv[3])), int(float(sys.argv[4])), float(sys.argv[5])
    try:
        m = os.lstat(p).st_mode
    except OSError:
        fail(f"找不到檔案：{p}")
    if not stat.S_ISREG(m):           # 符號連結、FIFO、裝置：不開
        fail("不是一般檔案")
    sha, size, n, good, rel = parse(p, max_bytes)
    if good < min_n:
        fail(f"只有 {good} 筆合格的紀錄（< {min_n}；cveID 要符合 CVE-<年>-<數字>），可能只下載到一部分或來源不對")
    ra = release_age(rel, max_rel)
    print(f"OK single_file entries={n} valid={good} date_released={rel} release_age_days={ra:.1f} bytes={size}（沒有 SOURCE：同步時間不明，只依 dateReleased）")
    sys.exit(0)
d, max_age, min_n, max_bytes, max_rel = sys.argv[2], float(sys.argv[3]), int(float(sys.argv[4])), int(float(sys.argv[5])), float(sys.argv[6])
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
    if fetched.tzinfo is None:
        raise ValueError("no tz")
except (KeyError, ValueError):
    fail("SOURCE 沒有可解析的 fetched_utc")
age = (NOW - fetched).total_seconds() / 86400
if age < -1 / 24:
    fail(f"fetched_utc 在未來（{src['fetched_utc']}）")
if age > max_age:
    fail(f"過期：下載後 {age:.1f} 天 > {max_age:g}（fetched_utc={src['fetched_utc']}）")
p = os.path.join(d, FILE)
if not os.path.isfile(p):
    fail(f"缺少 {FILE}")
sha, size, n, good, rel = parse(p, max_bytes)
if sha != src.get("sha256"):
    fail(f"{FILE} 的 sha256 與 SOURCE 不符")
if str(n) != src.get("entries"):
    fail(f"紀錄數 {n} 與 SOURCE 的 entries={src.get('entries')} 不符")
if good < min_n:
    fail(f"只有 {good} 筆合格的紀錄（< {min_n}；cveID 要符合 CVE-<年>-<數字>），可能只下載到一部分或來源不對")
ra = release_age(rel, max_rel)
print(f"OK fetched_utc={src['fetched_utc']} age_days={age:.1f} entries={n} valid={good} date_released={rel} release_age_days={ra:.1f} bytes={size}")
PY
}
check() { py check "$1" "${CISA_KEV_MAX_AGE_DAYS:-3}" "${CISA_KEV_MIN_ENTRIES:-1000}" "${CISA_KEV_MAX_BYTES:-104857600}" "${CISA_KEV_MAX_RELEASE_AGE_DAYS:-14}"; }
if [ "${1:-}" = "--check" ]; then check "${2:?缺少鏡像資料夾}"; exit $?; fi
if [ "${1:-}" = "--check-file" ]; then
  py check-file "${2:?缺少 JSON 檔}" "${CISA_KEV_MIN_ENTRIES:-1000}" "${CISA_KEV_MAX_BYTES:-104857600}" "${CISA_KEV_MAX_RELEASE_AGE_DAYS:-14}"; exit $?; fi
DEST="${1:?用法見檔頭}"; MANIFEST="${2:?}"
for p in "$DEST" "$MANIFEST"; do [ ! -e "$p" ] || { echo "已存在，拒絕覆蓋：$p" >&2; exit 3; }; done
case $URL in
  https://*) PROTO=https;;
  file://*) PROTO=file;;
  *) echo "FAIL CISA_KEV_URL 只接受 https:// 或 file://：$URL" >&2; exit 3;;
esac
mkdir -p "$DEST"
FETCHED="$(date -u +%FT%TZ)"
curl --fail --location --proto "=$PROTO" --proto-redir "=$PROTO" --silent --show-error --retry 3 --retry-delay 20 \
  --connect-timeout 30 --max-time 300 --max-filesize "${CISA_KEV_MAX_BYTES:-104857600}" --output "$DEST/$FILE" -- "$URL"
stats=$(py stats "$DEST/$FILE" "${CISA_KEV_MAX_BYTES:-104857600}") || { echo "$stats" >&2; exit 1; }
IFS=$'\t' read -r SHA SIZE N GOOD REL <<< "$stats"
printf 'source=%s\nfetched_utc=%s\nsha256=%s\nbytes=%s\nentries=%s\ndate_released=%s\n' "$URL" "$FETCHED" "$SHA" "$SIZE" "$N" "$REL" > "$DEST/SOURCE"
check "$DEST"
{
  echo "# source: $URL"; echo "# fetched_utc: $FETCHED"; echo "# entries: $N  date_released: $REL"
  echo "# files: $(find "$DEST" -type f | wc -l)  bytes: $(du -sb "$DEST" | cut -f1)"
  (cd "$DEST" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
} > "$MANIFEST"
echo "OK mirror=$DEST manifest=$MANIFEST"
