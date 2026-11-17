"""弱點資料的來源（T-06 PR-2）：這次 scan 用的每一種弱點資料是內部鏡像還是公開下載，以及資料的快照時間。

給 scan.json（platform_scan.collect）、notes.md 的一行摘要、release-meta.json 的 data_sources（pipeline/release-meta.py）用：
之後給客戶或稽核看「這次用的是哪一天的漏洞資料」的證據（C0，2026-11-17）。

輸入：
- 鏡像資料夾 MIRRORS_DIR（pipeline/lib/mirrors.sh 寫的 <資料夾名>.result 與 <資料夾名>/ 複本）；
- 清單 DUMPLING_DATA_SOURCES（scan.sh 設定）：以空白分隔的「<資料夾名>=<種類>」，例如 "kcve=kernel-cve euvd=euvd"；
- 完整掃描那次 sca-scan 的 meta.json（grype_db_built、grype_db_update）：公開模式的 Grype DB 不經過 mirrors.sh，由 sca-scan 掃描前
  grype db update 下載，快照時間取 meta.json 的 grype_db_built。

輸出（每一種一個 dict，只有下列欄位；不寫路徑、主機名、網址，也不抄 .result 的原文——公開模式的 .result 有本機路徑）：
  {"kind": 種類, "source": "internal"|"public", "status": "OK"|"ATTENTION"|"UNKNOWN",
   "snapshot_field": "fetched_utc"|"built_utc"|"date_released"|None, "snapshot_utc": "YYYY-MM-DDTHH:MM:SSZ"|None}
summary(items) → {"mode": "internal"|"public"|"mixed"|"unknown", "items": items}。
"""
import datetime
import json
import os
import re

KINDS = ("kernel-cve", "euvd", "osv-distro", "nvidia-bulletins", "grype-db", "cisa-kev")
SNAPSHOT_FIELDS = ("fetched_utc", "built_utc", "date_released")
STATUSES = ("OK", "ATTENTION", "UNKNOWN")
SOURCES = ("internal", "public")
MODES = ("internal", "public", "mixed", "unknown")
DIR_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
KEYS = ("kind", "source", "status", "snapshot_field", "snapshot_utc")


def _utc(val):
    """ISO 8601 字串 → 'YYYY-MM-DDTHH:MM:SSZ'；沒有時區、解析不了 → None（不猜時區）。"""
    if not isinstance(val, str) or not val or len(val) > 64:
        return None
    try:
        t = datetime.datetime.fromisoformat(val.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        return None
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_spec(spec):
    """'kcve=kernel-cve euvd=euvd' → [("kcve", "kernel-cve"), …]；不合格的項目丟掉（資料夾名與種類都是白名單格式）。"""
    out = []
    for tok in (spec or "").split():
        d, _, kind = tok.partition("=")
        if DIR_RE.fullmatch(d) and kind in KINDS and all(d != x for x, _ in out):
            out.append((d, kind))
    return out


def _first_line(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.readline().strip()
    except OSError:
        return None


def _public_snapshot(kind, d):
    """公開模式的資料時間：euvd 讀 index.tsv 第 1 行的 fetched_utc；其他讀 SOURCE 的 fetched_utc（沿用舊資料時是上一份的時間）。"""
    try:
        if kind == "euvd":
            first = (_first_line(os.path.join(d, "index.tsv")) or "").split("\t")
            val = dict(x.split("=", 1) for x in first[1:] if "=" in x).get("fetched_utc")
        else:
            with open(os.path.join(d, "SOURCE"), encoding="utf-8", errors="replace") as f:
                val = dict(x.split("=", 1) for x in f.read().splitlines() if "=" in x).get("fetched_utc")
    except OSError:
        return None
    return _utc(val)


def mirror_item(mirrors_dir, d, kind):
    """一個鏡像的來源與快照時間（讀 <d>.result 的第一行與 <d>/ 複本）。"""
    item = {"kind": kind, "source": None, "status": "UNKNOWN", "snapshot_field": None, "snapshot_utc": None}
    line = _first_line(os.path.join(mirrors_dir, d + ".result"))
    if not line:
        return item
    head = line.split(" ", 1)[0]
    item["status"] = head if head in ("OK", "ATTENTION") else "UNKNOWN"
    toks = line.split()
    if "source=internal" in toks:
        item["source"] = "internal"
        if ("kind=" + kind) not in toks:        # .result 的種類和清單不一致：不採信時間
            item["status"] = "UNKNOWN"
            return item
        for t in toks:
            k, _, v = t.partition("=")
            if k in SNAPSHOT_FIELDS:
                item["snapshot_field"], item["snapshot_utc"] = k, _utc(v)
                break
    else:
        item["source"] = "public"
        item["snapshot_field"] = "fetched_utc"
        item["snapshot_utc"] = _public_snapshot(kind, os.path.join(mirrors_dir, d))
    if item["snapshot_utc"] is None:
        item["snapshot_field"] = None
    return item


def grype_item(meta):
    """公開模式的 Grype DB（sca-scan 掃描前 grype db update）：meta.json 的 grype_db_update 是 online 才算公開下載。"""
    item = {"kind": "grype-db", "source": None, "status": "UNKNOWN", "snapshot_field": None, "snapshot_utc": None}
    if not isinstance(meta, dict):
        return item
    upd = meta.get("grype_db_update")
    if upd == "online":
        item["source"] = "public"
    elif isinstance(upd, str) and upd.startswith("import:"):
        item["source"] = "internal"           # 理論上不會走到這裡（內部模式由 gdb 鏡像那一項記）；只記來源，不抄路徑
    st = meta.get("grype_db_update_status")
    item["status"] = "OK" if st == "OK" else "UNKNOWN"
    built = _utc(meta.get("grype_db_built"))
    if built:
        item["snapshot_field"], item["snapshot_utc"] = "built_utc", built
    return item


def collect(mirrors_dir, spec, meta=None):
    """→ 項目清單（照清單順序；清單沒有 grype-db 時，最後加 meta.json 推出的那一項）。沒有清單 → None（沒有記錄，不是「沒有資料」）。"""
    pairs = parse_spec(spec)
    if not pairs or not mirrors_dir:
        return None
    items = [mirror_item(mirrors_dir, d, kind) for d, kind in pairs]
    if all(kind != "grype-db" for _, kind in pairs):
        items.append(grype_item(meta))
    return items


def clean(items):
    """release-meta.py 用：scan.json 的 data_sources 再過一次白名單（欄位、值的格式），不合格的項目丟掉；不是清單 → None。"""
    if not isinstance(items, list):
        return None
    out = []
    for it in items[:16]:
        if not isinstance(it, dict) or it.get("kind") not in KINDS:
            continue
        src = it.get("source") if it.get("source") in SOURCES else None
        st = it.get("status") if it.get("status") in STATUSES else "UNKNOWN"
        sf = it.get("snapshot_field") if it.get("snapshot_field") in SNAPSHOT_FIELDS else None
        su = it.get("snapshot_utc") if isinstance(it.get("snapshot_utc"), str) and UTC_RE.fullmatch(it["snapshot_utc"]) else None
        if sf is None or su is None:
            sf = su = None
        out.append({"kind": it["kind"], "source": src, "status": st, "snapshot_field": sf, "snapshot_utc": su})
    return out


def summary(items):
    """→ {"mode", "items"}；mode：全部 internal＝internal、全部 public＝public、兩種都有＝mixed、有不明的或沒有項目＝unknown。"""
    items = clean(items)
    if items is None:
        return None
    srcs = {it["source"] for it in items}
    if not items or None in srcs:
        mode = "unknown"
    elif srcs == {"internal"}:
        mode = "internal"
    elif srcs == {"public"}:
        mode = "public"
    else:
        mode = "mixed"
    return {"mode": mode, "items": items}


MODE_TEXT = {"internal": "內部鏡像", "public": "公開來源（掃描時下載）", "mixed": "內部鏡像與公開來源混用", "unknown": "有一部分來源不明"}
SOURCE_TEXT = {"internal": "內部鏡像", "public": "公開", None: "來源不明"}


def notes_line(ds):
    """notes.md 的一行摘要（Markdown）；ds 是 summary() 的結果，None → None（不寫）。"""
    if not isinstance(ds, dict) or ds.get("mode") not in MODES:
        return None
    parts = []
    for it in ds.get("items") or []:
        t = it["snapshot_utc"] or "時間不明"
        extra = "" if it["status"] == "OK" else "，%s" % it["status"]
        parts.append("%s %s（%s%s）" % (it["kind"], t, SOURCE_TEXT.get(it["source"], "來源不明"), extra))
    return ("- 弱點資料來源：%s。快照時間（UTC）：%s。Dependency-Track 的資料由 DT 自己的資料源提供，不在此列；"
            "機器可讀的版本在 `release-meta.json` 的 `data_sources`。" % (MODE_TEXT[ds["mode"]], "、".join(parts) or "沒有記錄"))


def read_meta(path):
    try:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
    except (OSError, ValueError):
        return None
    return v if isinstance(v, dict) else None
