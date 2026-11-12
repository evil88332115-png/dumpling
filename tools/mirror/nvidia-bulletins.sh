#!/usr/bin/env bash
# 更新主機角色（需連網）：取得 NVIDIA 產品安全公告中我們的產品線用得到的部分（CSAF、CVE JSON、Markdown），寫出 manifest。
# 選取群組（一則公告可以屬於多個群組；比對標題、CSAF 產品名稱、CVE_index.csv 的 Affected Product）：
#   jetson        Jetson／IGX／JetPack／L4T（Jetson 產品的 rootfs 與 flash）
#   gpu-firmware  VBIOS、GPU firmware（顯卡 vBIOS）。不用單獨的 firmware（會選到 DGX、BlueField 等）。
#                 注意：2026-11 的倉庫裡標題有 VBIOS 的只有一則、而且是 HGX／DGX；消費型顯卡的 vBIOS 幾乎沒有公開公告。
#   gpu-driver    GPU Display Driver；CSAF 產品名稱有 GeForce／RTX／Quadro 的（顯示驅動與工具軟體；驅動公告的標題很泛，產品樹才有型號）
# 來源：https://github.com/NVIDIA/product-security（2026-10-01 起 NVIDIA 只在這裡發布公告）。
#   每個公告一個資料夾 <年>/<公告編號>/：<編號>.json（CSAF 2.0）、<編號>.md、CVE-*.json（CVE 5 格式），多數檔案另有 <檔名>.sha256。
#   每年另有 <年>/CVE_index.csv（分號分隔，欄位含 Bulletin、Affected Product）。
#   NVIDIA 沒有 provider-metadata.json、ROLIE 或簽章；能驗的只有同一個倉庫裡的 .sha256（只能防傳輸損壞，不能防竄改）。
# 做法：git ls-remote 取 main 的 commit → 下載該 commit 的 tarball（codeload，一次下載，不吃 GitHub API 的次數限制）
#   → 在記憶體裡讀每個公告的 CSAF 標題與產品名稱、CVE_index.csv 的 Affected Product，屬於任一選取群組的公告才解出
#   → 逐檔驗 NVIDIA 的 .sha256（有的才驗；沒有的記數量）。tarball 本身不放進鏡像，只在 manifest 記它的 sha256。
#   commit 日期另以 GitHub API 取一次（取不到不影響鏡像，記「未取得」）。
# 鏡像內容：SOURCE（commit、fetched_utc…）、index.json（倉庫裡所有公告的編號、標題、日期、是否選入、屬於哪些群組 groups 與理由）、
#   <年>/CVE_index.csv、選入公告的 <年>/<編號>/ 資料夾。內網由 tools/pilot/lib/nvidia_bulletins.py candidates／match 讀
#   （依產品類型選群組：Jetson → jetson；顯卡 vBIOS → gpu-firmware；驅動、工具軟體 → gpu-driver）。manifest 也逐則記群組。
# 用法：nvidia-bulletins.sh <鏡像輸出資料夾（必須全新）> <manifest 輸出檔>
#       nvidia-bulletins.sh --check <鏡像資料夾>
# 環境變數：
#   NVBUL_REPO          GitHub 倉庫（預設 NVIDIA/product-security）；NVBUL_REF 分支（預設 main）
#   NVBUL_COMMIT        指定 commit（40 位 hex；不給就用 git ls-remote 取 NVBUL_REF 的最新 commit）
#   NVBUL_ARCHIVE_URL   tarball 網址（預設 https://codeload.github.com/<倉庫>/tar.gz/<commit>；測試可用 file://）
#   NVBUL_COMMIT_DATE   指定 commit 日期（不給就問 GitHub API；NVBUL_API 預設 https://api.github.com）
#   NVBUL_MAX_AGE_DAYS  --check 的新舊上限（預設 7）。依據是下載時間 fetched_utc，不是 commit 日期：倉庫可能好幾週沒有新公告。
#   NVBUL_MIN_BULLETINS --check 要求倉庫至少有幾個公告（預設 100；2026-11 約 207 個），防止拿到空倉庫或錯的倉庫
#   NVBUL_MAX_DOWNLOAD_MB tarball 下載上限（預設 100；2026-11 實測約 3 MB）；NVBUL_MAX_UNPACKED_MB 解壓後全部成員的合計上限（預設 500）
# 連線都有時間上限：git ls-remote 120 秒、curl 連線 30 秒／整體 300 秒，卡住不會拖住每日排程。
# --check 遇到一般檔案與資料夾以外的東西（符號連結、FIFO、裝置）一律失敗：鏡像會被別的帳號（root 的 nvbul-sync.sh）讀取與複製。
set -euo pipefail
REPO="${NVBUL_REPO:-NVIDIA/product-security}"
REF="${NVBUL_REF:-main}"
API="${NVBUL_API:-https://api.github.com}"
export GIT_TERMINAL_PROMPT=0
CURL_LIMITS=(--connect-timeout 30 --max-time 300)
check() {
  python3 -I - "$1" "${NVBUL_MAX_AGE_DAYS:-7}" "${NVBUL_MIN_BULLETINS:-100}" <<'PY'
import datetime, hashlib, json, os, re, stat, sys
d, max_age, min_b = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
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
    fail(f"過期：下載後 {age:.1f} 天 > {max_age:g}")
try:
    idx = json.load(open(os.path.join(d, "index.json"), encoding="utf-8"))
except (OSError, ValueError, RecursionError) as e:
    fail(f"index.json 無法讀取（{type(e).__name__}）")
bs = idx.get("bulletins") or []
sel = [b for b in bs if b.get("selected")]
if len(bs) < min_b:
    fail(f"倉庫只有 {len(bs)} 個公告（< {min_b}），可能不是完整的倉庫")
def groups_of(b):
    return b.get("groups") if isinstance(b.get("groups"), list) else ["jetson"]     # 舊格式（只有 Jetson）
if not any("jetson" in groups_of(b) for b in sel):
    fail("沒有任何 Jetson／IGX 公告（選取規則或來源有問題）")
bad, deep, unread, nosum, checked = [], [], [], 0, 0
# 認得的群組取自同一份 index.json 的 selection（產生鏡像的那一版的 GROUPS），不在這裡另寫一份；舊格式只有 jetson
known = set(idx["selection"]) if isinstance(idx.get("selection"), dict) else {"jetson"}
for b in bs:                       # 新格式：groups 和 selected 要一致、群組名稱是認得的字串
    g = b.get("groups")
    if isinstance(g, list) and (bool(g) != bool(b.get("selected")) or not all(isinstance(x, str) and x in known for x in g)):
        fail(f"index.json 的 {b.get('id')}：groups {g} 和 selected={b.get('selected')} 不一致或有不認得的群組")
integ = [b["id"] for b in sel if b.get("integrity_error")]
if any("jetson" in groups_of(b) for b in sel if b.get("integrity_error")):
    fail("Jetson 公告有 integrity_error（不該發生：Jetson 的 sha256 不符應該整個失敗）")
for b in sel:
    if b.get("integrity_error"):
        continue
    p = os.path.join(d, b["year"], b["id"], b["id"] + ".json")
    why = None
    try:
        doc = json.loads(open(p, "rb").read())     # bytes：BOM、UTF-16 和鏡像端（json.loads(bytes)）一樣讀得懂
        if str(doc["document"]["tracking"]["id"]).strip() != b["id"]:
            why = "tracking.id 不符"
    except RecursionError:
        # 很深的 CSAF：多深會 RecursionError 和 Python 版本有關（鏡像主機 3.12 讀得到、這台 3.10 讀不到）
        why = "RecursionError"
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:    # 讀不到、不是 JSON、沒有 document.tracking、型別錯
        why = type(e).__name__
    if not why or not (b.get("csaf") or why == "tracking.id 不符"):    # 因 .md 或 CVE_index 被選入、本來就沒有 CSAF
        continue
    # 非 Jetson 群組只計數、顯示在 OK 那一行（不拖住 Jetson 的每日更新）；Jetson 的照舊算問題
    if "jetson" in groups_of(b):
        bad.append(f"{b['id']}: CSAF {why}" if why == "tracking.id 不符" else f"{b['id']}: CSAF 無法讀取（{why}）")
    elif why == "RecursionError":
        deep.append(b["id"])
    else:
        unread.append(f"{b['id']}:{why}")
for root, _, files in os.walk(d):
    for f in files:
        if f.endswith(".sha256") or f in ("SOURCE", "index.json") or f.endswith(".csv"):
            continue
        p = os.path.join(root, f)
        if not os.path.exists(p + ".sha256"):
            nosum += 1; continue
        m = re.match(r"\s*([0-9a-fA-F]{64})\b", open(p + ".sha256", encoding="utf-8", errors="replace").read())
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        checked += 1
        if not m or m.group(1).lower() != h:
            bad.append(f"{os.path.relpath(p, d)}: sha256 不符")
if bad:
    fail(f"{len(bad)} 個問題：{bad[:5]}")
per = {g: sum(1 for b in sel if g in groups_of(b)) for g in ("jetson", "gpu-firmware", "gpu-driver")}   # 輸出的欄位固定
print(f"OK commit={src.get('commit')} fetched_utc={src.get('fetched_utc')} age_days={age:.1f} "
      f"bulletins={len(bs)} selected={len(sel)} jetson_igx={per['jetson']} gpu_firmware={per['gpu-firmware']} "
      f"gpu_driver={per['gpu-driver']} sha256_verified={checked} no_sha256={nosum} integrity_error={len(integ)}"
      + (f" ({', '.join(integ[:5])})" if integ else "")
      + f" csaf_too_deep={len(deep)}" + (f" ({', '.join(deep[:5])})" if deep else "")
      + f" csaf_unreadable={len(unread)}" + (f" ({', '.join(unread[:5])})" if unread else ""))
PY
}
if [ "${1:-}" = "--check" ]; then check "${2:?缺少鏡像資料夾}"; exit $?; fi
DEST="${1:?用法見檔頭}"; MANIFEST="${2:?}"
for p in "$DEST" "$MANIFEST"; do [ ! -e "$p" ] || { echo "已存在，拒絕覆蓋：$p" >&2; exit 3; }; done
FETCHED="$(date -u +%FT%TZ)"
COMMIT="${NVBUL_COMMIT:-$(timeout 120 git ls-remote "https://github.com/$REPO" "refs/heads/$REF" | cut -f1)}"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "FAIL 取不到 $REPO $REF 的 commit：'$COMMIT'" >&2; exit 1; }
ARCHIVE_URL="${NVBUL_ARCHIVE_URL:-https://codeload.github.com/$REPO/tar.gz/$COMMIT}"
CDATE="${NVBUL_COMMIT_DATE:-$(curl -fsSL "${CURL_LIMITS[@]}" --retry 2 -H 'Accept: application/vnd.github+json' "$API/repos/$REPO/commits/$COMMIT" 2>/dev/null \
  | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["commit"]["committer"]["date"])' 2>/dev/null || echo 未取得)}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "${CURL_LIMITS[@]}" --max-filesize $(( ${NVBUL_MAX_DOWNLOAD_MB:-100} * 1048576 )) --retry 3 -o "$tmp/repo.tar.gz" "$ARCHIVE_URL"
TAR_SHA="$(sha256sum "$tmp/repo.tar.gz" | cut -d' ' -f1)"
mkdir -p "$DEST"
python3 -I - "$tmp/repo.tar.gz" "$DEST" "$COMMIT" "${NVBUL_MAX_UNPACKED_MB:-500}" <<'PY'
import csv, hashlib, io, json, os, re, sys, tarfile
arc, dest, commit, max_mb = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
# 選取群組（與 tools/pilot/lib/nvidia_bulletins.py 的 GROUPS 相同，測試會比對）：標題、CSAF 產品名稱或 CVE_index.csv 的 Affected Product
GROUPS = {
    "jetson": re.compile(r"\b(jetson|igx|jetpack|l4t)\b", re.I),
    "gpu-firmware": re.compile(r"\b(vbios|gpu firmware)\b", re.I),
    "gpu-driver": re.compile(r"\b(gpu display driver|geforce|quadro|rtx)\b", re.I),
}
BUL = re.compile(r"^[^/]+/(\d{4})/(\d{3,6})/([A-Za-z0-9][A-Za-z0-9._-]*\.(?:json|md|sha256))$")
IDX = re.compile(r"^[^/]+/(\d{4})/CVE_index\.csv$")
MAX = 20 << 20     # 單檔上限；公告檔案都在 1 MB 以下
files, csvs = {}, {}
total = 0
with tarfile.open(arc, "r:gz") as t:
    for m in t:
        total += max(m.size, 0)
        if total > max_mb << 20:
            sys.exit(f"FAIL tarball 解壓後超過 NVBUL_MAX_UNPACKED_MB={max_mb} MB，不是預期的公告倉庫")
        if not m.isfile() or m.size > MAX:
            continue
        b, i = BUL.match(m.name), IDX.match(m.name)
        if b:
            files[(b.group(1), b.group(2), b.group(3))] = t.extractfile(m).read()
        elif i:
            csvs[i.group(1)] = t.extractfile(m).read()
csv_products = {}
for year, raw in csvs.items():
    for row in csv.DictReader(io.StringIO(raw.decode("utf-8-sig", "replace")), delimiter=";"):
        bid = (row.get("Bulletin") or "").strip()
        if bid:
            csv_products.setdefault(bid, set()).add((row.get("Affected Product") or "").strip())
def names(node, out):
    """CSAF 產品樹裡所有字串的 name；用自己的堆疊走（很深的 JSON 不會 RecursionError）。"""
    stack = [node]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            if isinstance(x.get("name"), str):
                out.append(x["name"])
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return out
def text(v):
    return v if isinstance(v, str) else None      # 標題、日期不是字串（格式錯的 CSAF）就當沒有
bulletins = {}
for (year, bid, fn) in files:
    bulletins.setdefault((year, bid), set()).add(fn)
index, n_files, n_ok, n_nosum, n_bad = [], 0, 0, 0, 0
for (year, bid), fns in sorted(bulletins.items(), key=lambda x: (x[0][0], int(x[0][1]))):
    e = {"id": bid, "year": year, "title": None, "initial_release_date": None, "current_release_date": None,
         "revision": None, "csaf": f"{bid}.json" in fns, "selected": False, "groups": [], "match": [], "match_by_group": {}}
    prod = []
    if e["csaf"]:
        try:
            doc = json.loads(files[(year, bid, f"{bid}.json")])
            dm = doc.get("document") or {}
            tr = dm.get("tracking") or {}
            e.update(title=text(dm.get("title")), initial_release_date=text(tr.get("initial_release_date")),
                     current_release_date=text(tr.get("current_release_date")), revision=text(tr.get("version")))
            prod = names(doc.get("product_tree") or {}, [])
        except (ValueError, AttributeError, RecursionError):
            e["csaf"] = False
    if not e["title"] and f"{bid}.md" in fns:
        first = files[(year, bid, f"{bid}.md")].decode("utf-8", "replace").lstrip().splitlines()[:1]
        e["title"] = first[0].lstrip("#").strip() if first else None
    for g, rx in GROUPS.items():
        how = []
        if e["title"] and rx.search(e["title"]):
            how.append("title")
        if any(rx.search(p) for p in prod):
            how.append("csaf_product")
        if any(rx.search(p) for p in csv_products.get(bid, ())):
            how.append("cve_index_product")
        if how:
            e["groups"].append(g)
            e["match_by_group"][g] = how
    e["match"] = [k for k in ("title", "csaf_product", "cve_index_product") if any(k in v for v in e["match_by_group"].values())]
    e["selected"] = bool(e["groups"])
    index.append(e)
    if not e["selected"]:
        continue
    # 先驗完這個公告的所有檔案才寫出。Jetson 群組的公告 sha256 不符 → 整個鏡像 FAIL（原本的規則不變）；
    # 只屬於其他群組的公告不符（NVIDIA 改了檔案沒更新 .sha256，2026-11 實際遇到 2024/5586）→ 不解出、記 integrity_error，
    # candidates 列成待審（sha256_mismatch），不讓它拖住 Jetson 的每日更新。
    bad, ok, nosum = [], 0, 0
    for fn in sorted(fns):
        if fn.endswith(".sha256"):
            continue
        s = files.get((year, bid, fn + ".sha256"))
        if s is None:
            nosum += 1
            continue
        m = re.match(rb"\s*([0-9a-fA-F]{64})\b", s)
        if not m or m.group(1).decode().lower() != hashlib.sha256(files[(year, bid, fn)]).hexdigest():
            bad.append(fn)
        else:
            ok += 1
    if bad and "jetson" in e["groups"]:
        sys.exit(f"FAIL sha256 不符：{year}/{bid}/{bad[0]}")
    if bad:
        e["integrity_error"] = f"sha256 不符（NVIDIA 附的 .sha256 和檔案不同）：{', '.join(bad[:5])}；沒有解出"
        n_bad += 1
        continue
    d = os.path.join(dest, year, bid)
    os.makedirs(d, exist_ok=True)
    for fn in sorted(fns):
        with open(os.path.join(d, fn), "wb") as fh:
            fh.write(files[(year, bid, fn)])
    n_files += ok + nosum
    n_ok += ok
    n_nosum += nosum
for year, raw in csvs.items():
    os.makedirs(os.path.join(dest, year), exist_ok=True)
    with open(os.path.join(dest, year, "CVE_index.csv"), "wb") as fh:
        fh.write(raw)
json.dump({"schema": "sca-nvidia-bulletins-mirror/2", "commit": commit, "selection": {g: rx.pattern for g, rx in GROUPS.items()},
           "bulletins": index}, open(os.path.join(dest, "index.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
sel = [e["id"] for e in index if e["selected"]]
per = " ".join(f"{g}={sum(1 for e in index if g in e['groups'])}" for g in GROUPS)
print(f"OK bulletins={len(index)} selected={len(sel)} ({', '.join(sel)}) {per} files={n_files} sha256_ok={n_ok} no_sha256={n_nosum}"
      f" integrity_error={n_bad}")
PY
printf 'source=https://github.com/%s\nref=%s\ncommit=%s\ncommit_date=%s\nfetched_utc=%s\narchive_url=%s\narchive_sha256=%s\n' \
  "$REPO" "$REF" "$COMMIT" "$CDATE" "$FETCHED" "$ARCHIVE_URL" "$TAR_SHA" > "$DEST/SOURCE"   # 內網 --check 與 candidates 用來判斷新舊
check "$DEST"
{
  echo "# source: https://github.com/$REPO"; echo "# ref: $REF"; echo "# commit: $COMMIT"; echo "# commit_date: $CDATE"
  echo "# archive_url: $ARCHIVE_URL"; echo "# archive_sha256: $TAR_SHA"; echo "# fetched_utc: $FETCHED"
  echo "# files: $(find "$DEST" -type f | wc -l)  bytes: $(du -sb "$DEST" | cut -f1)"
  python3 -I -c 'import json,sys
for b in json.load(open(sys.argv[1], encoding="utf-8"))["bulletins"]:
    if b.get("selected"):
        print("# bulletin %s/%s groups=%s%s" % (b["year"], b["id"], ",".join(b["groups"]),
              " integrity_error (not extracted)" if b.get("integrity_error") else ""))' "$DEST/index.json"
  (cd "$DEST" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
} > "$MANIFEST"
echo "OK mirror=$DEST manifest=$MANIFEST commit=$COMMIT"
