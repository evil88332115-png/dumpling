#!/usr/bin/env python3
"""euvd.py：ENISA 歐盟弱點資料庫（EUVD）的本機索引，以及替 CVE 標上 EUVD 編號與「已遭利用」標記（C-euvd）；
另由 EUVD 的 kev/dump 產生 DT 5.2 的 ENISA KEV 來源檔（dt-enisa）。

子命令：
  annotate --index <鏡像資料夾> --cves <檔案> [--cves <檔案>…] --out <euvd.json> [--max-age-days 天數]
      為每個 CVE 寫出 EUVD 編號、EUVD 的已遭利用標記與 EUVD 網頁連結，並印一行 status：
        C-euvd<TAB>狀態<TAB>說明
      --cves 可以是：
        - 文字檔：每行一個或多個 CVE（空白或逗號分隔；# 開頭為註解）。不是 CVE 的內容 → 輸入錯誤；
        - DT 的 finding 清單（dt/findings.json，tools/e2e/dtread.py 的輸出）：取 vulnerability.vulnId 與 aliases；
        - Grype JSON（scan/grype.json）：取 matches 的 vulnerability.id 與 relatedVulnerabilities；
        - NVIDIA 公告比對結果（scan/nvidia-bulletins.json）：取 findings、presumed_included、needs_vendor_confirmation 的 cve；
        - JSON 字串陣列，或 {"cves": [字串…]}。
        檔名以 .xz 結尾時先解壓。UBUNTU-CVE-…、DEBIAN-CVE-… 對應到 CVE（同 cra_report.py 的 CVE_RE）；GHSA 等非 CVE 編號只計數。
      判定：
        - --index ""（沒有設定鏡像）、索引不存在、無法解析或內容不一致 → GAP，輸出**沒有 cves**（讀取端不可能把它當成「0 個已被利用」）；
        - 索引過期（下載時間超過 EUVD_MAX_AGE_DAYS，預設 3 天；或 KEV 最新加入日期超過 EUVD_KEV_MAX_AGE_DAYS，預設 14 天）→ GAP（仍標註，但註明過期）；
        - 輸入沒有任何 CVE、索引可用 → OK（cves 是空的）；
        - 其他 → OK（只表示標註完成；不在 EUVD 的 CVE 一律是 unknown，不代表沒有被利用）。
      退出碼：0 已判定；3 輸入錯誤（同時印 FAIL 那一行，不印 traceback）。
  build --raw <raw 資料夾> --fetched <UTC 時間> --out <index.tsv>
      由 tools/mirror/euvd.sh 呼叫：把兩份官方大檔轉成精簡索引。
  check-mirror <鏡像資料夾>
      由 tools/mirror/euvd.sh --check 呼叫：檢查檔案、筆數、新舊，並由原始檔重建索引比對（索引必須和原始檔一致）。
  dt-enisa --dir <kev/euvd 資料夾> --fetched <UTC 時間> --dump-url <網址> --upstream-url <網址>
      由 tools/mirror/dt-feeds.sh 的 euvdkev 部分呼叫：由 <dir>/kev-dump.json（與可缺的 upstream-eukev.json）產生 DT 5.2 ENISA KEV 來源
      讀得懂的 eukev.json 與 SOURCE.json（DT 的讀法與選取規則見 dt_enisa_build 上面的註解）。
  dt-enisa-check <kev/euvd 資料夾>
      由 dt-feeds.sh --check 呼叫：重建比對、DT 的格式、筆數、新舊；上游 eukev.json 落後 EUVD 時印 NOTE。
另有 exploited_index()：給 tools/cra/exploited_watch.py 讀索引的已遭利用集合與新舊判定。

資料來源（2026-11-02 實際下載核對；欄位說明取自 https://euvd.enisa.europa.eu/apidoc 的網頁內容）：
  - <API>/dump/cve-euvd-mapping：CSV，欄位 euvd_id,cve_id；「只含已發布 CVE 的紀錄，每日 07:00 UTC 更新」。
    實測 398,838 列，一個 CVE 只對應一個 EUVD 編號（反之亦然），約 12 MB。
  - <API>/kev/dump：JSON 陣列，欄位 cveId、euvdId、dateAdded（YYYY-MM-DD，各 KEV 來源中最早加入的日期）、
    sources（cisa_kev、eukev_kev）；「合併 CISA KEV 與 ENISA EU KEV，每日 07:00 UTC 更新」。實測 1,783 筆，約 260 KB。
  - 實測 <API>/search?exploited=true 的 1,782 個 EUVD 編號與 kev/dump 的 euvdId 完全相同（另有 1 筆 kev/dump 只有 CVE、
    還沒有 EUVD 編號）：EUVD 的「已遭利用」就是 CISA KEV 與 EU KEV 的聯集，不是另外的情資來源。
  索引的 exploited 欄位因此只表示「EUVD 標示在 KEV 清單中」；沒有標示 ≠ 沒有被利用。

索引格式（index.tsv，UTF-8）：
  第 1 行：# euvd-index 1<TAB>鍵=值…（fetched_utc、mapping_rows、mapping_bad、kev_entries、kev_bad、kev_newest_date_added、
           mapping_sha256、kev_sha256、cves）
  第 2 行：欄位名稱 cve、euvd_ids（逗號分隔）、exploited（1／0）、kev_date_added、kev_sources（逗號分隔）
  其餘：每個 CVE 一行，依 CVE 年份與號碼排序。原始資料是外部的不可信資料：每個值都先以正規式驗證，不合格的列只計數、不寫入。
"""
import argparse
import csv
import datetime
import hashlib
import io
import json
import lzma
import os
import re
import sys

STAGE = "C-euvd"
INDEX = "index.tsv"
RAW_MAP = "cve-euvd-mapping.csv"
RAW_KEV = "kev-dump.json"
MAGIC = "# euvd-index 1"
COLUMNS = ["cve", "euvd_ids", "exploited", "kev_date_added", "kev_sources"]
CVE_STRICT = re.compile(r"^CVE-(\d{4})-(\d{4,7})$", re.ASCII)   # re.ASCII：\d 不收其他文字的數字（外部資料）
CVE_RE = re.compile(r"^(?:[A-Z]+-)?(CVE-\d{4}-\d{4,7})$", re.ASCII)   # CVE-…、UBUNTU-CVE-…、DEBIAN-CVE-…（同 cra_report.py）
EUVD_RE = re.compile(r"^EUVD-\d{4}-\d{1,7}$", re.ASCII)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$", re.ASCII)
SRC_RE = re.compile(r"^[a-z0-9_]{1,32}$")
PAGE = "https://euvd.enisa.europa.eu/vulnerability/{}"
UTC = datetime.timezone.utc


class InputError(Exception):
    pass


class IndexError_(Exception):
    """索引不能用（不存在、格式錯、內容不一致）：annotate 記 GAP，不是輸入錯誤。"""


def env_float(name, default):
    try:
        return float(os.environ.get(name) or default)
    except ValueError:
        return float(default)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def cve_key(c):
    m = CVE_STRICT.match(c)
    return (int(m.group(1)), int(m.group(2))) if m else (9999, 0)


def age_days(ts, now=None):
    """ISO 時間或日期 → 距今天數（UTC）；無法解析回 None。"""
    if not isinstance(ts, str) or not ts:
        return None
    try:
        t = datetime.datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=UTC)
    return ((now or datetime.datetime.now(UTC)) - t).total_seconds() / 86400


# ---------- build：原始檔 → 索引 ----------

def parse_raw(raw):
    """讀兩份原始檔，回傳（每個 CVE 的資料 dict, 統計 dict）。格式不對（表頭、頂層型別）→ IndexError_。"""
    mp, kp = os.path.join(raw, RAW_MAP), os.path.join(raw, RAW_KEV)
    for p in (mp, kp):
        if not os.path.isfile(p):
            raise IndexError_(f"缺少 {os.path.basename(p)}")
    data, st = {}, {"mapping_rows": 0, "mapping_bad": 0, "kev_entries": 0, "kev_bad": 0, "kev_newest_date_added": ""}
    with open(mp, encoding="utf-8-sig", newline="") as f:
        r = csv.reader(f)
        head = next(r, None)
        if head != ["euvd_id", "cve_id"]:
            raise IndexError_(f"{RAW_MAP} 的表頭不是 euvd_id,cve_id：{str(head)[:80]}")
        for row in r:
            if not row:
                continue
            st["mapping_rows"] += 1
            if len(row) != 2 or not EUVD_RE.match(row[0].strip()) or not CVE_STRICT.match(row[1].strip()):
                st["mapping_bad"] += 1
                continue
            data.setdefault(row[1].strip(), {"euvd": set(), "kev": None})["euvd"].add(row[0].strip())
    try:
        with open(kp, encoding="utf-8-sig") as f:
            kev = json.load(f)
    except (OSError, ValueError, RecursionError) as e:
        raise IndexError_(f"{RAW_KEV} 無法解析（{type(e).__name__}）")
    if not isinstance(kev, list):
        raise IndexError_(f"{RAW_KEV} 的頂層不是陣列")
    for x in kev:
        st["kev_entries"] += 1
        c = x.get("cveId") if isinstance(x, dict) else None
        if not isinstance(c, str) or not CVE_STRICT.match(c.strip()):
            st["kev_bad"] += 1
            continue
        c = c.strip()
        e = x.get("euvdId")
        d = x.get("dateAdded")
        srcs = x.get("sources") if isinstance(x.get("sources"), list) else []
        rec = data.setdefault(c, {"euvd": set(), "kev": None})
        if isinstance(e, str) and EUVD_RE.match(e.strip()):
            rec["euvd"].add(e.strip())
        d = d.strip() if isinstance(d, str) and DATE_RE.match(d.strip()) else ""
        srcs = sorted({s for s in srcs if isinstance(s, str) and SRC_RE.match(s)})
        old = rec["kev"]
        if old:   # 同一個 CVE 出現兩次：日期取最早、來源取聯集
            d = min(x for x in (d, old["date"]) if x) if (d or old["date"]) else ""
            srcs = sorted(set(srcs) | set(old["sources"]))
        rec["kev"] = {"date": d, "sources": srcs}
        if d and d > st["kev_newest_date_added"]:
            st["kev_newest_date_added"] = d
    st["mapping_sha256"], st["kev_sha256"] = sha256_file(mp), sha256_file(kp)
    st["cves"] = len(data)
    return data, st


def render_index(data, st, fetched):
    meta = {"fetched_utc": fetched, **{k: st[k] for k in ("mapping_rows", "mapping_bad", "kev_entries", "kev_bad",
                                                         "kev_newest_date_added", "mapping_sha256", "kev_sha256", "cves")}}
    out = io.StringIO()
    out.write(MAGIC + "".join(f"\t{k}={v}" for k, v in meta.items()) + "\n")
    out.write("\t".join(COLUMNS) + "\n")
    for c in sorted(data, key=cve_key):
        r = data[c]
        k = r["kev"]
        out.write("\t".join([c, ",".join(sorted(r["euvd"])), "1" if k else "0", (k or {}).get("date", ""),
                             ",".join((k or {}).get("sources", []))]) + "\n")
    return out.getvalue()


def cmd_build(a):
    if age_days(a.fetched) is None:
        print(f"FAIL --fetched 不是 ISO 時間：{a.fetched!r}")
        return 3
    try:
        data, st = parse_raw(a.raw)
    except IndexError_ as e:
        print(f"FAIL {e}")
        return 1
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(render_index(data, st, a.fetched))
    print(f"OK index cves={st['cves']} mapping_rows={st['mapping_rows']} mapping_bad={st['mapping_bad']} "
          f"kev_entries={st['kev_entries']} kev_bad={st['kev_bad']} kev_newest_date_added={st['kev_newest_date_added']}")
    return 0


# ---------- 讀索引 ----------

def read_meta(line):
    if not line.startswith(MAGIC):
        raise IndexError_(f"{INDEX} 第 1 行不是 {MAGIC}")
    meta = {}
    for kv in line.rstrip("\n").split("\t")[1:]:
        k, _, v = kv.partition("=")
        meta[k] = v
    for k in ("fetched_utc", "cves", "kev_newest_date_added"):
        if k not in meta:
            raise IndexError_(f"{INDEX} 第 1 行缺少 {k}")
    return meta


def load_index(d):
    """回傳（meta, {cve: (euvd_ids, exploited, kev_date, kev_sources)}）。任何問題 → IndexError_。"""
    p = os.path.join(d, INDEX)
    if not os.path.isdir(d):
        raise IndexError_(f"沒有 EUVD 鏡像資料夾 {d}")
    if not os.path.isfile(p):
        raise IndexError_(f"鏡像資料夾沒有 {INDEX}")
    idx = {}
    try:
        with open(p, encoding="utf-8") as f:
            meta = read_meta(f.readline())
            if f.readline().rstrip("\n").split("\t") != COLUMNS:
                raise IndexError_(f"{INDEX} 第 2 行的欄位名稱不符")
            for n, ln in enumerate(f, 3):
                x = ln.rstrip("\n").split("\t")
                if len(x) != 5 or not CVE_STRICT.match(x[0]) or x[2] not in ("0", "1") \
                        or any(not EUVD_RE.match(e) for e in x[1].split(",") if e) \
                        or (x[3] and not DATE_RE.match(x[3])) or any(not SRC_RE.match(s) for s in x[4].split(",") if s):
                    raise IndexError_(f"{INDEX} 第 {n} 行格式錯誤")
                idx[x[0]] = ([e for e in x[1].split(",") if e], x[2] == "1", x[3], [s for s in x[4].split(",") if s])
    except (OSError, UnicodeDecodeError) as e:
        raise IndexError_(f"{INDEX} 無法讀取（{type(e).__name__}）")
    if str(len(idx)) != meta["cves"]:
        raise IndexError_(f"{INDEX} 的列數 {len(idx)} 與表頭的 cves={meta['cves']} 不符（檔案可能被截斷）")
    return meta, idx


# ---------- check-mirror ----------

def cmd_check(a):
    d, bad = a.dir, []
    p = os.path.join(d, INDEX)
    try:
        with open(p, encoding="utf-8") as f:
            meta = read_meta(f.readline())
        data, st = parse_raw(os.path.join(d, "raw"))
        _, idx = load_index(d)
        want = render_index(data, st, meta["fetched_utc"])
        with open(p, encoding="utf-8", newline="") as f:
            if f.read() != want:
                bad.append(f"{INDEX} 與原始檔重建的結果不同（原始檔或索引被改過）")
    except (OSError, IndexError_) as e:
        print(f"FAIL {e}")
        return 1
    min_rows = env_float("EUVD_MIN_MAPPING_ROWS", 300000)
    min_kev = env_float("EUVD_MIN_KEV_ENTRIES", 1000)
    if st["mapping_rows"] < min_rows:
        bad.append(f"cve-euvd-mapping 只有 {st['mapping_rows']} 列（< {min_rows:.0f}，可能下載不完整）")
    if st["mapping_bad"] > max(10, st["mapping_rows"] // 1000):
        bad.append(f"cve-euvd-mapping 有 {st['mapping_bad']} 列格式不符")
    if st["kev_entries"] < min_kev:
        bad.append(f"kev/dump 只有 {st['kev_entries']} 筆（< {min_kev:.0f}）")
    if st["kev_bad"] > 10:
        bad.append(f"kev/dump 有 {st['kev_bad']} 筆沒有合格的 cveId")
    print(f"OK mapping rows={st['mapping_rows']} bad={st['mapping_bad']} cves={st['cves']}")
    print(f"OK kev entries={st['kev_entries']} bad={st['kev_bad']} exploited_cves={sum(1 for v in idx.values() if v[1])} "
          f"without_euvd_id={sum(1 for v in idx.values() if v[1] and not v[0])}")
    for label, ts, lim in (("fetched_utc", meta["fetched_utc"], env_float("EUVD_MAX_AGE_DAYS", 3)),
                           ("kev newest dateAdded", meta["kev_newest_date_added"], env_float("EUVD_KEV_MAX_AGE_DAYS", 14))):
        ag = age_days(ts)
        if ag is None:
            bad.append(f"{label}: 無法解析日期 {ts!r}")
        elif ag > lim:
            bad.append(f"{label}: 過期（{ag:.1f} 天 > {lim:g}）")
        elif ag < -1:
            bad.append(f"{label}: 日期在未來 {ts}")
        else:
            print(f"OK {label}={ts} age_days={ag:.1f}")
    for b in bad:
        print("FAIL", b)
    return 1 if bad else 0


# ---------- DT 5.2 的 ENISA KEV 來源檔（dt-enisa、dt-enisa-check；tools/mirror/dt-feeds.sh 的 euvdkev 部分） ----------
# DT 5.2.0 讀 ENISA KEV 的方式（DependencyTrack/dependency-track tag 5.2.0，commit d67a6a3a，2026-11-05 讀原始碼核對）：
#   kev-data-source/builtin/.../enisa/EnisaKevDataSourceFactory.java：名稱 enisa、顯示「ENISA EU KEV」、預設 feedUrl＝
#     https://raw.githubusercontent.com/enisaeu/CNW/main/advisories/eukev/eukev.json
#   .../jsonfeed/AbstractJsonFeedKevDataSource.java：GET feedUrl（逾時 1 分鐘），HTTP 不是 200 → 例外（mirror run FAILED）
#   .../enisa/EnisaKevDataSource.java parseEntries：第一個 token 不是 START_ARRAY → 回傳空清單（不報錯；MirrorKevDataSourceActivity
#     遇到 0 筆而資料庫已有 ENISA 的資料時只記 warn、保留舊資料）；每個元素以 Jackson 轉成 EnisaKevEntry：
#     cveID（@Nullable；null → 這筆略過）、euvdID（沒有用到，只在 raw）、dateReported（LocalDate，@JsonFormat pattern "yyyy/MM/dd"；
#     沒有 @Nullable，toKevAssertion 直接呼叫 dateReported().atStartOfDay(UTC)：缺少時 NullPointerException → 整次 mirror 失敗）、
#     shortDescription（→ description，可缺）、exploitationType（等於 "ransomware"（不分大小寫）→ knownRansomware=true，其他 → null，可缺）。
#     @JsonIgnoreProperties(ignoreUnknown = true)：其他欄位不影響解析，整筆 JSON 存在 KEV_ASSERTION.RAW。
#     KevAssertion：vulnSource 固定 "NVD"、vulnId＝cveID 原字串（不 trim）。
#   apiserver/.../MirrorKevDataSourceActivity.java＋KevDao：以 asserter＝enisa upsert，之後刪掉這次沒看到的 enisa 斷言（deleteStale）。
# 因此產生的檔：頂層陣列；每筆都有 cveID（CVE-YYYY-N）與合法的 dateReported（yyyy/MM/dd）；其他欄位可缺。
DT_DUMP, DT_UP, DT_FEED, DT_SOURCE = "kev-dump.json", "upstream-eukev.json", "eukev.json", "SOURCE.json"
DT_CISA = "cisa-kev.json"   # CISA KEV（DT 的 CISA 來源讀的同一份檔；可缺）：只用來列出「EUVD 標已遭利用、DT 的 CISA ∪ ENISA 都沒有」的 CVE
DT_SCHEMA = "sca-dt-enisa-kev/1"
DT_PARSER = ("DependencyTrack/dependency-track 5.2.0 (d67a6a3a) kev-data-source/builtin/src/main/java/org/dependencytrack/"
             "kevdatasource/enisa/EnisaKevDataSource.java, EnisaKevEntry.java")
TEXT_FIELDS = ("vendorProject", "product", "vulnerabilityName", "shortDescription", "exploitationType")
EU_SOURCE = "eukev_kev"


def clean_text(v, limit=2000):
    """外部的文字欄位：字串、去頭尾空白、1..limit 字、沒有控制字元；不合格 → None（不寫）。"""
    if not isinstance(v, str):
        return None
    v = v.strip()
    if not v or len(v) > limit or any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
        return None
    return v


def real_date(s, sep):
    """YYYY<sep>MM<sep>DD 而且是真的日期 → 原字串（去空白）；否則 None。"""
    if not isinstance(s, str):
        return None
    s = s.strip()
    if not re.match(r"^\d{4}" + re.escape(sep) + r"\d{2}" + re.escape(sep) + r"\d{2}$", s, re.ASCII):
        return None
    try:
        datetime.date(*map(int, s.split(sep)))
    except ValueError:
        return None
    return s


def load_list(path, name):
    try:
        with open(path, encoding="utf-8-sig") as f:
            doc = json.load(f)
    except (OSError, ValueError, RecursionError) as e:
        raise IndexError_(f"{name} 無法解析（{type(e).__name__}）")
    if not isinstance(doc, list):
        raise IndexError_(f"{name} 的頂層不是陣列")
    return doc


def dt_enisa_build(d, fetched, dump_url, upstream_url):
    """由 <d>/kev-dump.json（EUVD /api/kev/dump，必要）與 <d>/upstream-eukev.json（enisaeu/CNW 的 eukev.json，可缺）產生
    DT 5.2 ENISA KEV 來源讀得懂的檔。回傳（eukev.json 文字, SOURCE.json 文字, 統計）。

    選哪些：kev/dump 裡 sources 含 eukev_kev 的 CVE（DT 這個來源叫「ENISA EU KEV」，CISA 的條目 DT 由 CISA 來源讀；
    兩邊都放會讓 enisa 的 asserter 也替 CISA 的條目背書）。
    欄位：cveID；euvdID（kev/dump 的 euvdId，沒有時用上游的）；dateReported（上游 eukev.json 有這個 CVE 而且日期合法時用它的，
    否則用 kev/dump 的 dateAdded——注意 dateAdded 是「各 KEV 來源最早加入的日期」，也在 CISA KEV 的條目可能是 CISA 的日期）；
    vendorProject、product、vulnerabilityName、shortDescription、exploitationType（上游有就用上游的，前三個上游沒有時用 kev/dump 的；
    kev/dump 沒有後兩個欄位，DT 因此 description 與 knownRansomware 是 null＝未知）；另加 euvdSources、euvdDateAdded、dataOrigin
    （DT 不讀，只存在 RAW，方便追溯）。日期無法轉成合法 yyyy/MM/dd 的條目不寫（DT 會整次失敗），計數 skipped_no_date。
    上游有而 EUVD 的 EU KEV 沒有的 CVE 也照上游寫進（dateReported 與欄位用上游的，dataOrigin 標「只在上游」）：DT 的 deleteStale
    會刪掉這次沒看到的 enisa 斷言，不寫的話 DT 會默默少掉它們；計數 upstream_only_entries。
    另有 <d>/cisa-kev.json（CISA KEV，可缺）時，列出 kev/dump 標已遭利用、但 CISA KEV 與這份檔都沒有的 CVE（euvd_not_in_dt；
    DT 的 isKev 不會標，例如 2026-11-05 的 CVE-2026-69836：EUVD 標 cisa_kev、當天的 CISA 檔沒有）；沒有 CISA 檔時是 None（未比對；
    D-dt-kev-sources 記 ATTENTION）。已列在 skipped_no_date 的 CVE 不再列入 euvd_not_in_dt：同一個 CVE 只列一次，原因不同——
    skipped_no_date 是這裡自己沒寫進檔（ATTENTION），euvd_not_in_dt 是來源之間的不一致（NOTE）。
    注意：cisa-kev.json 是 dt-feeds.sh 的 euvdkev 部分另抓的（euvd-mirror.sh update 的時候），不是 DT 的 CISA 來源實際讀的那一份
    （DT 自己在排程時讀 www.cisa.gov），兩份通常差不到一天，更新失敗時可差幾天：這段期間 CISA 新增的 CVE 可能漏列、移除的可能多列。"""
    dump = load_list(os.path.join(d, DT_DUMP), DT_DUMP)
    up, up_problem = None, None
    up_path = os.path.join(d, DT_UP)
    if os.path.isfile(up_path):
        try:
            up = load_list(up_path, DT_UP)
        except IndexError_ as e:
            up_problem = str(e)
    else:
        up_problem = f"沒有 {DT_UP}（上游沒有下載或下載失敗）"
    st = {"dump_entries": 0, "dump_bad": 0, "dump_newest_date_added": "", "eu_entries": 0, "eu_newest_date_added": ""}
    eu, allk = {}, {}
    for x in dump:
        st["dump_entries"] += 1
        c = x.get("cveId") if isinstance(x, dict) else None
        if not isinstance(c, str) or not CVE_STRICT.match(c.strip()):
            st["dump_bad"] += 1
            continue
        c = c.strip()
        da = real_date(x.get("dateAdded"), "-") or ""
        if da > st["dump_newest_date_added"]:
            st["dump_newest_date_added"] = da
        srcs = {s for s in (x.get("sources") if isinstance(x.get("sources"), list) else []) if isinstance(s, str) and SRC_RE.match(s)}
        allk.setdefault(c, set()).update(srcs)
        if EU_SOURCE not in srcs:
            continue
        r = eu.setdefault(c, {"euvd": "", "date": "", "sources": set(), "text": {}})
        e = x.get("euvdId")
        if not r["euvd"] and isinstance(e, str) and EUVD_RE.match(e.strip()):
            r["euvd"] = e.strip()
        if da and (not r["date"] or da < r["date"]):    # 同一個 CVE 出現兩次：日期取最早、來源取聯集
            r["date"] = da
        r["sources"] |= srcs
        for k in ("vendorProject", "product", "vulnerabilityName"):
            v = clean_text(x.get(k))
            if v is not None:
                r["text"].setdefault(k, v)
    st["eu_entries"] = len(eu)
    st["eu_newest_date_added"] = max((r["date"] for r in eu.values()), default="")
    upmap, ust = {}, None
    if up is not None:
        ust = {"entries": len(up), "bad": 0, "newest_date_reported": ""}
        for x in up:
            c = x.get("cveID") if isinstance(x, dict) else None
            if not isinstance(c, str) or not CVE_STRICT.match(c.strip()):
                ust["bad"] += 1
                continue
            c = c.strip()
            # 重複時取第一筆有合法 dateReported 的（都沒有時取第一筆）
            if c not in upmap or (not real_date(upmap[c].get("dateReported"), "/") and real_date(x.get("dateReported"), "/")):
                upmap[c] = x
            dr = real_date(x.get("dateReported"), "/") or ""
            if dr > ust["newest_date_reported"]:
                ust["newest_date_reported"] = dr
        ust["with_cve"] = len(upmap)
        ust["not_in_euvd"] = sorted(set(upmap) - set(eu), key=cve_key)
        ust["missing_from_upstream"] = sorted(set(eu) - set(upmap), key=cve_key)
    entries, skipped, from_up = [], [], 0
    for c in sorted(eu, key=cve_key):
        r, u = eu[c], upmap.get(c)
        date = real_date(u.get("dateReported"), "/") if u else None
        if not date and r["date"]:
            date = r["date"].replace("-", "/")
        if not date:
            skipped.append(c)
            continue
        e = {"cveID": c, "dateReported": date}
        eid = r["euvd"] or (u.get("euvdID").strip() if u and isinstance(u.get("euvdID"), str) and EUVD_RE.match(u["euvdID"].strip()) else "")
        if eid:
            e["euvdID"] = eid
        for k in TEXT_FIELDS:
            v = clean_text(u.get(k)) if u else None
            if v is None:
                v = r["text"].get(k)
            if v is not None:
                e[k] = v
        e["euvdSources"] = sorted(r["sources"])
        if r["date"]:
            e["euvdDateAdded"] = r["date"]
        e["dataOrigin"] = "ENISA EUVD /api/kev/dump" + (" + enisaeu/CNW eukev.json" if u else "")
        from_up += 1 if u else 0
        entries.append(e)
    up_only = []
    for c in (ust or {}).get("not_in_euvd") or []:     # 只在上游：照上游寫進，DT 不會少掉
        u = upmap[c]
        date = real_date(u.get("dateReported"), "/")
        if not date:
            skipped.append(c)
            continue
        e = {"cveID": c, "dateReported": date,
             "dataOrigin": "enisaeu/CNW eukev.json only (not an eukev_kev entry in ENISA EUVD /api/kev/dump)"}
        if isinstance(u.get("euvdID"), str) and EUVD_RE.match(u["euvdID"].strip()):
            e["euvdID"] = u["euvdID"].strip()
        for k in TEXT_FIELDS:
            v = clean_text(u.get(k))
            if v is not None:
                e[k] = v
        up_only.append(c)
        entries.append(e)
    entries.sort(key=lambda e: cve_key(e["cveID"]))
    skipped.sort(key=cve_key)
    feed = json.dumps(entries, ensure_ascii=True, indent=1, sort_keys=True) + "\n"
    # DT 的 CISA ∪ 這份檔都沒有、EUVD 卻標已遭利用的 CVE（DT 的 isKev 不會標）
    cisa_path, cisa_set, cisa_problem = os.path.join(d, DT_CISA), None, None
    if os.path.isfile(cisa_path):
        try:
            with open(cisa_path, encoding="utf-8-sig") as f:
                cj = json.load(f)
            vs = cj.get("vulnerabilities") if isinstance(cj, dict) else None
            if not isinstance(vs, list):
                raise ValueError("沒有 vulnerabilities 陣列")
            cisa_set = {v["cveID"].strip() for v in vs if isinstance(v, dict) and isinstance(v.get("cveID"), str)
                        and CVE_STRICT.match(v["cveID"].strip())}
            if not cisa_set:
                # 讀得到、卻沒有任何合格的 cveID（空的清單、欄位改名）：比對無效，不能當成「CISA 沒有任何 CVE」
                cisa_set = None
                raise ValueError("沒有任何合格的 cveID")
        except (OSError, ValueError, RecursionError) as ex:
            cisa_problem = f"{DT_CISA} 無法解析（{type(ex).__name__}）"
    else:
        cisa_problem = f"沒有 {DT_CISA}（CISA KEV 沒有下載）"
    in_feed = {e["cveID"] for e in entries}
    not_in_dt = None if cisa_set is None else [{"cve": c, "sources": sorted(allk[c])}
                                               for c in sorted(set(allk) - cisa_set - in_feed - set(skipped), key=cve_key)]
    src = {"schema": DT_SCHEMA, "fetched_utc": fetched, "dump_url": dump_url, "upstream_url": upstream_url,
           "dump_sha256": sha256_file(os.path.join(d, DT_DUMP)),
           "upstream_sha256": sha256_file(up_path) if up is not None else None, "upstream_problem": up_problem,
           **st, "entries": len(entries), "entries_with_upstream_fields": from_up, "skipped_no_date": skipped,
           "upstream_only_entries": len(up_only), "upstream_only": up_only,
           "cisa_sha256": sha256_file(cisa_path) if cisa_set is not None else None, "cisa_entries": len(cisa_set) if cisa_set is not None else None,
           "cisa_problem": cisa_problem, "euvd_not_in_dt": not_in_dt,
           "newest_date_reported": max((e["dateReported"] for e in entries), default=""),
           "eukev_sha256": hashlib.sha256(feed.encode()).hexdigest(), "upstream": ust, "dt_parser": DT_PARSER,
           "selection": "kev/dump entries whose sources include eukev_kev (CISA KEV entries are read by DT's CISA source), plus "
                        "upstream eukev.json entries that EUVD does not list as eukev_kev (kept so DT does not drop them)"}
    return feed, json.dumps(src, ensure_ascii=True, indent=1, sort_keys=True) + "\n", src


def dt_feed_problems(entries):
    """產生的檔是否符合 DT 5.2 EnisaKevDataSource 的讀法（上面的註解）。回傳問題清單（空＝可以讀）。"""
    if not isinstance(entries, list):
        return ["頂層不是陣列（DT 會靜默讀成 0 筆）"]
    out, seen = [], set()
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            out.append(f"第 {i} 筆不是物件（Jackson 轉不成 EnisaKevEntry，整次 mirror 失敗）")
            continue
        c = e.get("cveID")
        if not isinstance(c, str) or not CVE_STRICT.match(c):
            out.append(f"第 {i} 筆的 cveID 不是 CVE 編號：{str(c)[:40]!r}")
        elif c in seen:
            out.append(f"{c} 重複")
        seen.add(c)
        dr = real_date(e.get("dateReported"), "/")
        if dr is None or dr != e.get("dateReported"):
            out.append(f"第 {i} 筆的 dateReported 不是合法的 yyyy/MM/dd：{str(e.get('dateReported'))[:20]!r}（DT 會整次失敗）")
        for k in ("euvdID",) + TEXT_FIELDS:
            if k in e and not isinstance(e[k], str):
                out.append(f"第 {i} 筆的 {k} 不是字串")
        if "euvdID" in e and isinstance(e["euvdID"], str) and not EUVD_RE.match(e["euvdID"]):
            out.append(f"第 {i} 筆的 euvdID 格式不符")
    return out


def cmd_dt_enisa(a):
    if age_days(a.fetched) is None:
        print(f"FAIL --fetched 不是 ISO 時間：{a.fetched!r}")
        return 3
    try:
        feed, srctext, src = dt_enisa_build(a.dir, a.fetched, a.dump_url, a.upstream_url)
    except IndexError_ as e:
        print(f"FAIL {e}")
        return 1
    for name, text in ((DT_FEED, feed), (DT_SOURCE, srctext)):
        with open(os.path.join(a.dir, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    print(f"OK dt-enisa entries={src['entries']} eu_entries={src['eu_entries']} with_upstream_fields={src['entries_with_upstream_fields']} "
          f"skipped_no_date={len(src['skipped_no_date'])} dump_entries={src['dump_entries']}")
    return 0


def cmd_dt_check(a):
    """dt-feeds.sh --check 的 euvdkev 部分：由原始檔重建比對、DT 格式、筆數、新舊；上游 eukev.json 落後時印 NOTE（不 FAIL：DT 改讀這份檔）。"""
    d, bad = a.dir, []
    try:
        with open(os.path.join(d, DT_SOURCE), encoding="utf-8") as f:
            old = json.load(f)
        if not isinstance(old, dict) or old.get("schema") != DT_SCHEMA:
            raise IndexError_(f"{DT_SOURCE} 不是 {DT_SCHEMA}")
        feed, srctext, src = dt_enisa_build(d, str(old.get("fetched_utc")), old.get("dump_url"), old.get("upstream_url"))
        for name, want in ((DT_FEED, feed), (DT_SOURCE, srctext)):
            with open(os.path.join(d, name), encoding="utf-8", newline="") as f:
                if f.read() != want:
                    bad.append(f"kev euvd: {name} 與原始檔重建的結果不同（原始檔或產生的檔被改過）")
        entries = json.loads(feed)
    except (OSError, ValueError, IndexError_) as e:
        print(f"FAIL kev euvd: {e}")
        return 1
    bad += [f"kev euvd: {x}" for x in dt_feed_problems(entries)[:10]]
    if src["dump_entries"] < env_float("EUVD_MIN_KEV_ENTRIES", 1000):
        bad.append(f"kev euvd: kev/dump 只有 {src['dump_entries']} 筆（< {env_float('EUVD_MIN_KEV_ENTRIES', 1000):.0f}，可能下載不完整）")
    if src["dump_bad"] > 10:
        bad.append(f"kev euvd: kev/dump 有 {src['dump_bad']} 筆沒有合格的 cveId")
    min_eu = env_float("DT_KEV_EUVD_MIN_ENTRIES", 30)
    if src["entries"] < min_eu:
        bad.append(f"kev euvd: 只有 {src['entries']} 筆 EU KEV（< {min_eu:.0f}；2026-11-05 實測 82 筆，格式可能變了）")
    print(f"OK kev euvd entries={src['entries']} (EU KEV in EUVD kev/dump; with eukev.json fields {src['entries_with_upstream_fields']}) "
          f"dump_entries={src['dump_entries']} newest dateReported={src['newest_date_reported']}")
    if src["skipped_no_date"]:
        print(f"NOTE kev euvd: {len(src['skipped_no_date'])} 筆沒有可用的日期，沒有寫進 DT 的檔（DT 會整次失敗）："
              + ", ".join(src["skipped_no_date"][:10]))
    for label, ts, lim in (("kev euvd fetched_utc", src["fetched_utc"], env_float("DT_KEV_EUVD_MAX_AGE_DAYS", env_float("EUVD_MAX_AGE_DAYS", 3))),
                           ("kev euvd dump newest dateAdded", src["dump_newest_date_added"], env_float("EUVD_KEV_MAX_AGE_DAYS", 14))):
        ag = age_days(ts)
        if ag is None:
            bad.append(f"{label}: 無法解析日期 {ts!r}")
        elif ag > lim:
            bad.append(f"{label}: 過期（{ag:.1f} 天 > {lim:g}）")
        elif ag < -1:
            bad.append(f"{label}: 日期在未來 {ts}")
        else:
            print(f"OK {label}={ts} age_days={ag:.1f}")
    u = src["upstream"]
    if u is None:
        print(f"NOTE kev euvd: 沒有上游 eukev.json（{src['upstream_problem']}）：shortDescription、exploitationType 全部缺（DT 記 null）")
    else:
        miss = u["missing_from_upstream"]
        print(f"NOTE kev euvd: 上游 eukev.json {u['entries']} 筆、最新 dateReported {u['newest_date_reported'] or '?'}；"
              + (f"EUVD 的 EU KEV 有 {len(miss)} 個 CVE 上游沒有（上游不是最新；DT 要讀 kev/euvd/eukev.json）：{', '.join(miss[:12])}"
                 + ("…" if len(miss) > 12 else "") if miss else "上游與 EUVD 的 EU KEV 一致")
              + (f"；上游有、EUVD 的 EU KEV 沒有的 {len(u['not_in_euvd'])} 個照上游寫進（dataOrigin 標明）：{', '.join(u['not_in_euvd'][:12])}"
                 if u["not_in_euvd"] else ""))
    if src["euvd_not_in_dt"] is None:
        print(f"NOTE kev euvd: 沒有和 CISA KEV 比對（{src['cisa_problem']}）：EUVD 標已遭利用、DT 的 CISA ∪ ENISA 都沒有的 CVE 未知"
              "（sca-scan 的 D-dt-kev-sources 記 ATTENTION）")
    elif src["euvd_not_in_dt"]:
        print(f"NOTE kev euvd: EUVD 標已遭利用、DT 的 CISA KEV ∪ 這份檔都沒有的 {len(src['euvd_not_in_dt'])} 個 CVE（DT 的 isKev 不會標；"
              f"以這裡的 {DT_CISA} 比對，不是 DT 實際讀的那一份，通常差不到一天、更新失敗時可差幾天）："
              + ", ".join(f"{x['cve']} ({'/'.join(x['sources'])})" for x in src["euvd_not_in_dt"][:12]))
    for b in bad:
        print("FAIL", b)
    return 1 if bad else 0


# ---------- annotate ----------

def read_input(path):
    """回傳（CVE 集合, 非 CVE 編號數）。讀不到或格式無法辨識 → InputError。"""
    try:
        if path.endswith(".xz"):
            with lzma.open(path, "rt", encoding="utf-8-sig") as f:
                text = f.read()
        else:
            with open(path, encoding="utf-8-sig") as f:
                text = f.read()
    except (OSError, UnicodeDecodeError, lzma.LZMAError) as e:
        raise InputError(f"{path} 無法讀取（{type(e).__name__}）")
    ids = []
    s = text.lstrip()
    if s.startswith(("[", "{")):
        try:
            doc = json.loads(s)
        except (ValueError, RecursionError) as e:
            raise InputError(f"{path} 不是合格的 JSON（{type(e).__name__}）")
        ids = json_ids(doc, path)
    else:
        for n, ln in enumerate(text.splitlines(), 1):
            ln = ln.split("#", 1)[0].strip()
            for tok in filter(None, re.split(r"[\s,]+", ln)):
                if not CVE_RE.match(tok):
                    raise InputError(f"{path} 第 {n} 行不是 CVE 編號：{tok[:40]!r}")
                ids.append(tok)
    cves = {m.group(1) for m in map(CVE_RE.match, ids) if m}
    return cves, sum(1 for i in ids if not CVE_RE.match(i))


def json_ids(doc, path):
    def strs(xs):
        return [x for x in xs if isinstance(x, str) and x]
    if isinstance(doc, dict) and isinstance(doc.get("matches"), list):        # Grype JSON
        out = []
        for m in doc["matches"]:
            if not isinstance(m, dict):
                continue
            v = m.get("vulnerability") or {}
            out += strs([v.get("id")] if isinstance(v, dict) else [])
            out += strs([r.get("id") for r in m.get("relatedVulnerabilities") or [] if isinstance(r, dict)])
        return out
    if isinstance(doc, dict) and str(doc.get("schema") or "").startswith("sca-nvidia-bulletins-findings/"):
        # scan/nvidia-bulletins.json：公告的 CVE（有發現的、推定已含修正的、要原廠確認的）。這些 CVE 不在 DT／Grype 的結果裡，
        # 不一起查 EUVD／KEV 就會停在「公告 in_triage」而不進 P1。未審核列（unreviewed_would_match）不算發現，不查
        out = []
        for k in ("findings", "presumed_included", "needs_vendor_confirmation"):
            for x in doc.get(k) or []:
                if isinstance(x, dict):
                    v = x.get("vulnerability") if isinstance(x.get("vulnerability"), dict) else {}   # findings：DT 形式的發現
                    out += strs([x.get("cve"), v.get("vulnId")])
        return out
    if isinstance(doc, dict) and isinstance(doc.get("cves"), list):
        return strs(doc["cves"])
    if isinstance(doc, list) and all(isinstance(x, str) for x in doc):
        return doc
    if isinstance(doc, list) and all(isinstance(x, dict) and isinstance(x.get("vulnerability"), dict) for x in doc):   # DT findings
        out = []
        for f in doc:
            v = f["vulnerability"]
            out += strs([v.get("vulnId")])
            for al in v.get("aliases") or []:
                if isinstance(al, dict):
                    out += strs(list(al.values()))
        return out
    raise InputError(f"{path} 的 JSON 格式無法辨識（要 DT findings、Grype JSON、字串陣列或 {{\"cves\": [...]}}）")


def annotate(cves, index_dir, max_age, kev_max_age, now=None):
    """回傳（狀態, 說明, 輸出 dict）。index_dir 是空字串＝沒有設定鏡像。
    索引不能用（或沒有設定）時輸出**沒有 cves**：讀取端（cra_report、vex_export）不可能把它讀成「0 個已被利用」。"""
    problem, meta, idx, stale = None, None, None, []
    if not index_dir:
        problem = "沒有設定 EUVD 鏡像（PILOT_ENV 的 EUVD_MIRROR；deploy/pilot/euvd-mirror.sh 寫入）"
    else:
        try:
            meta, idx = load_index(index_dir)
        except IndexError_ as e:
            problem = str(e)
    src = {"index_dir": index_dir or None, "max_age_days": max_age, "kev_max_age_days": kev_max_age}
    if meta:
        fa, ka = age_days(meta["fetched_utc"], now), age_days(meta["kev_newest_date_added"], now)
        src.update({k: meta.get(k) for k in ("fetched_utc", "kev_newest_date_added", "cves", "mapping_sha256", "kev_sha256")})
        src.update({"age_days": round(fa, 1) if fa is not None else None, "kev_age_days": round(ka, 1) if ka is not None else None})
        stale = stale_reasons(meta, max_age, kev_max_age, now)
    n = {"cves": len(cves), "in_euvd": 0, "exploited": 0, "not_flagged": 0, "not_in_euvd": 0, "unknown_no_index": 0}
    note = ("exploited=yes 表示 EUVD 標示在 CISA KEV 或 ENISA EU KEV（EUVD 的已遭利用標記就是這兩份清單）；"
            "not_flagged 只表示不在這兩份清單；unknown 表示 EUVD 沒有這個 CVE。")
    if problem:
        n["unknown_no_index"] = len(cves)
        detail = (f"EUVD 索引不能用：{problem}。{n['cves']} 個 CVE 的 EUVD 已遭利用標記未知（不代表沒有被利用）；"
                  "輸出不含 cves，風險評估要當成 GAP")
        return "GAP", detail, {"stage": STAGE, "status": "GAP", "detail": detail, "source": src, "counts": n,
                               "note": note + "這個檔沒有 cves：沒有可用的 EUVD 索引，不能當成「沒有 CVE 被利用」。"}
    res = {}
    for c in sorted(cves, key=cve_key):
        hit = idx.get(c)
        if hit is None:
            n["not_in_euvd"] += 1
            res[c] = {"in_euvd": False, "euvd_ids": [], "exploited": "unknown", "exploited_text": "unknown (not in EUVD)",
                      "kev_date_added": None, "kev_sources": [], "links": []}
            continue
        eids, ex, kd, ks = hit
        n["in_euvd"] += 1
        if ex:
            n["exploited"] += 1
            txt = "yes (EUVD: listed in " + (", ".join(ks) or "a KEV catalogue") + (f", added {kd}" if kd else "") + ")"
        else:
            n["not_flagged"] += 1
            txt = "not flagged by EUVD (not in CISA KEV / EU KEV; this does not mean it is not exploited)"
        res[c] = {"in_euvd": True, "euvd_ids": eids, "exploited": "yes" if ex else "not_flagged", "exploited_text": txt,
                  "kev_date_added": kd or None, "kev_sources": ks, "links": [PAGE.format(e) for e in eids]}
    tally = (f"{n['cves']} 個 CVE：{n['in_euvd']} 個有 EUVD 編號（{n['exploited']} 個 EUVD 標示已遭利用，"
             f"即在 CISA KEV 或 EU KEV），{n['not_in_euvd']} 個不在 EUVD（已遭利用與否未知，不代表沒有被利用）")
    if stale:
        st, detail = "GAP", "EUVD 索引過期：" + "；".join(stale) + f"。仍以舊資料標註，新的 EUVD 編號與已遭利用標記可能缺漏。{tally}"
    elif not cves:
        st, detail = "OK", f"輸入沒有任何 CVE，沒有可標註的項目（索引下載於 {meta['fetched_utc']}，{src['age_days']} 天前）"
    else:
        st, detail = "OK", f"{tally}。索引下載於 {meta['fetched_utc']}（{src['age_days']} 天前）"
    return st, detail, {"stage": STAGE, "status": st, "detail": detail, "source": src, "counts": n, "cves": res, "note": note}


def stale_reasons(meta, max_age, kev_max_age, now=None):
    """索引過期的原因（空清單＝沒過期）：下載時間超過 max_age 天，或 KEV 最新加入日期超過 kev_max_age 天（含無法解析、在未來超過 1 天）。"""
    out = []
    fa, ka = age_days(meta["fetched_utc"], now), age_days(meta["kev_newest_date_added"], now)
    if fa is None or fa > max_age or fa < -1:
        out.append(f"索引下載於 {meta['fetched_utc']}" + (f"（{fa:.1f} 天，上限 {max_age:g} 天）" if fa is not None else "（時間無法解析）"))
    if ka is None or ka > kev_max_age or ka < -1:
        out.append(f"KEV 最新加入日期 {meta['kev_newest_date_added'] or '（空白）'}"
                   + (f"（{ka:.1f} 天，上限 {kev_max_age:g} 天）" if ka is not None else "（無法解析）"))
    return out


def exploited_index(index_dir, max_age=None, kev_max_age=None, now=None):
    """給 exploited_watch.py：讀索引，回傳 dict：
         status    OK／GAP（GAP＝沒有設定、不能用或過期）
         detail    說明（英文，進監控報告）
         usable    索引讀得到（過期也是 True：照樣比對，但狀態是 GAP）
         exploited {CVE: {"euvd_ids": [...], "sources": [...], "date_added": "YYYY-MM-DD" 或 None}}（usable 才有）
         meta      索引第 1 行的鍵值（usable 才有）"""
    max_age = env_float("EUVD_MAX_AGE_DAYS", 3) if max_age is None else max_age
    kev_max_age = env_float("EUVD_KEV_MAX_AGE_DAYS", 14) if kev_max_age is None else kev_max_age
    if not index_dir:
        return {"status": "GAP", "usable": False, "exploited": None, "meta": None,
                "detail": "no EUVD mirror configured (EUVD_MIRROR in PILOT_ENV or --euvd-mirror): EU KEV entries that "
                          "Dependency-Track does not flag are not checked"}
    try:
        meta, idx = load_index(index_dir)
    except IndexError_ as e:
        return {"status": "GAP", "usable": False, "exploited": None, "meta": None,
                "detail": f"EUVD index at {index_dir} is unusable ({e}): EU KEV entries that Dependency-Track does not flag are not checked"}
    ex = {c: {"euvd_ids": v[0], "sources": v[3], "date_added": v[2] or None} for c, v in idx.items() if v[1]}
    stale = stale_reasons(meta, max_age, kev_max_age, now)
    base = (f"EUVD index fetched {meta['fetched_utc']}, newest KEV dateAdded {meta['kev_newest_date_added'] or '?'}, "
            f"{len(ex)} CVE(s) flagged exploited")
    if stale:
        return {"status": "GAP", "usable": True, "exploited": ex, "meta": meta,
                "detail": f"EUVD index is stale ({len(stale)} limit(s) exceeded: fetched {meta['fetched_utc']}, newest KEV dateAdded "
                          f"{meta['kev_newest_date_added'] or '?'}; limits {max_age:g} and {kev_max_age:g} days): still matched, "
                          f"but newer EUVD exploited flags may be missing. {base}"}
    return {"status": "OK", "usable": True, "exploited": ex, "meta": meta, "detail": base}


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + detail.replace("\t", " ").replace("\n", " "))


def cmd_annotate(a):
    try:
        cves, non_cve = set(), 0
        for p in a.cves:
            c, k = read_input(p)
            cves |= c
            non_cve += k
        max_age = a.max_age_days if a.max_age_days is not None else env_float("EUVD_MAX_AGE_DAYS", 3)
        st, detail, out = annotate(cves, a.index, max_age, env_float("EUVD_KEV_MAX_AGE_DAYS", 14))
    except InputError as e:
        line("FAIL", f"euvd.py 輸入錯誤：{e}")
        return 3
    except Exception as e:   # 結構意外：記 FAIL，不讓掃描中斷、不印 traceback
        line("FAIL", f"euvd.py 無法判定（{type(e).__name__}）")
        return 3
    out["inputs"], out["counts"]["non_cve_ids"] = a.cves, non_cve
    try:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
    except OSError as e:
        line("FAIL", f"無法寫入 {a.out}（{type(e).__name__}）")
        return 3
    line(st, detail)
    return 0


class Parser(argparse.ArgumentParser):
    def error(self, message):   # 參數錯誤也照慣例：FAIL 一行、退出碼 3
        line("FAIL", f"euvd.py 參數錯誤：{message}")
        sys.exit(3)


def main(argv=None):
    ap = Parser(description="EUVD 索引與 CVE 標註（C-euvd）")
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=Parser)
    p = sub.add_parser("annotate")
    p.add_argument("--index", required=True)
    p.add_argument("--cves", required=True, action="append")
    p.add_argument("--out", required=True)
    p.add_argument("--max-age-days", type=float)
    p = sub.add_parser("build")
    p.add_argument("--raw", required=True)
    p.add_argument("--fetched", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("check-mirror")
    p.add_argument("dir")
    p = sub.add_parser("dt-enisa")
    p.add_argument("--dir", required=True)
    p.add_argument("--fetched", required=True)
    p.add_argument("--dump-url", required=True)
    p.add_argument("--upstream-url", required=True)
    p = sub.add_parser("dt-enisa-check")
    p.add_argument("dir")
    a = ap.parse_args(argv)
    return {"annotate": cmd_annotate, "build": cmd_build, "check-mirror": cmd_check, "dt-enisa": cmd_dt_enisa,
            "dt-enisa-check": cmd_dt_check}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
