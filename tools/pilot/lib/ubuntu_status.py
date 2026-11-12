#!/usr/bin/env python3
"""ubuntu_status.py：從 Ubuntu CVE Tracker 狀態鏡像只取出這個映像要用的部分（sca-scan 的 D-ubuntu-status）。
寫 scan/ubuntu-status.json，並印一行 status：
  D-ubuntu-status<TAB>狀態<TAB>說明

用法：python3 -I ubuntu_status.py --findings <dt/findings.json[.xz]> [--sbom <sbom.cdx.json[.xz]>] [--mirror <鏡像資料夾>]
                               [--max-age-days N] [--max-commit-age-days N] --out <scan/ubuntu-status.json>
  --mirror：tools/mirror/ubuntu-cve-status.sh 的輸出（PILOT_ENV 的 UBUNTU_CVE_STATUS_MIRROR；
    Ubuntu CVE Tracker 狀態鏡像，schema sca-ubuntu-cve-status/1）。只讀一般套件的索引 ubuntu-cve-status.json.gz
    （核心 linux、linux-* 的索引約 1.3 GB 不讀：證據規則 U1 不用在核心的列，核心走 K1–K4）。一個 CVE 可以兩個檔都有，但核心以外的
    套件只在一般檔，所以不用合併。
  --max-age-days：SOURCE 的 fetched_utc 最多幾天（預設 3，環境變數 UBUNTU_CVE_MAX_AGE_DAYS；同 ubuntu-cve-status.sh --check）。
  --max-commit-age-days：上游最後 commit（SOURCE 的 commit_date）最多幾天（預設 14，UBUNTU_CVE_MAX_COMMIT_AGE_DAYS）。
退出碼：0 已處理（OK／NOT_RUN）；3 輸入錯誤（同時印 FAIL 那一行）。原始的 findings 與鏡像都不改。

為什麼：證據規則 U1（vex_export.py）在 Ubuntu 說「這個原始碼套件在這個發行版 not-affected」而且安裝的版本符合註記時設 not_affected。
鏡像的一般索引讀進記憶體約 80 MB，cra_report 不直接讀它：這裡只留下 DT findings 裡 Ubuntu 套件上的 (CVE, 原始碼套件, 發行版)，
像 D-ubuntu-priority 對 priority 做的一樣。cra_report 也用這份推出沒有 Grype 修補狀態的 Ubuntu 列的修補狀態（apply_ubuntu_tracker：
released → fixed、needed／pending／in-progress／deferred → not-fixed、ignored → wont-fix）。
取出的內容：
  components：DT findings 裡每個 pkg:deb/ubuntu/ 元件的 purl → 原始碼套件、原始碼版本、發行版代號。原始碼依序取：purl 是 arch=source
    （D-dt-deb-sources 加的原始碼套件元件）→ 名稱與版本就是原始碼；purl 的 upstream qualifier；SBOM（Syft）的 syft:metadata:source／
    sourceVersion；都沒有 → 二進位名稱與版本（dpkg 只在不同時才寫 Source）。發行版取 purl 的 distro qualifier（ubuntu-24.04 → noble）。
    DT findings 裡 Ubuntu 打包的 Python 模組（/usr/lib/python3/dist-packages 的 pypi 元件；cra_report.deb_python_index 從 --sbom 找到
    唯一擁有它的 deb 套件）：也收擁有它的 deb 套件（以它的 purl 為鍵，同樣的方式取原始碼）與 (CVE, 它的原始碼套件, 發行版)；
    counts.deb_python_owners 是這樣多收的 deb 元件數。沒有 --sbom 時不收。
  entries：{CVE: {原始碼套件: {發行版: {status, note[, priority][, conflict]}}}}，照鏡像原樣（不轉換狀態、不猜）；鏡像沒有＝Ubuntu 沒有表示意見。
  other_releases：{CVE: {原始碼套件: {其他發行版: {status, note}}}}：同一個 CVE、同一個原始碼套件在鏡像裡其他 Ubuntu 版本的狀態
    （目前不用於判定：留給人判斷「revision 比註記舊」的列時參考，之後放寬時用）。
  cve_info：{CVE: {priority（CVE 層級；空的 Priority 是 null）, tracker_file（tracker 裡的檔案 active/<CVE> 或 retired/<CVE>）}}，
    只收 entries 裡有的 CVE；和 mirror 的 source、commit、commit_date 一起是 U1 排除清單的出處。
  mirror_counts：鏡像標頭裡的異常計數（全體：duplicate_lines、conflicting_entries、malformed_lines、skipped_names、non_utf8_files、
    odd_line_breaks、unknown_priorities、truncated_fields；這個檔：part_conflicting_entries）與取出的筆數中認得的狀態以外的值（unknown_status），
    cra_report 的 VEX 小節不是 0 時列出。有 conflict 的狀態（後面不同的行：[{status, note}, …]）原樣保留，U1 一律不判定。
狀態：DT findings 沒有 Ubuntu 套件上的 CVE → NOT_RUN（不寫檔案；sca-scan 不寫這一列）；有，但沒有鏡像、過期、SOURCE 不完整、
  sha256 或大小與 SOURCE 不符、格式不對、映像的發行版不在鏡像裡 → NOT_RUN 並寫檔案（status NOT_RUN 與原因；U1 不套用，列照樣受影響）；
  其他 → OK。鏡像的資料不可信：只解析；索引檔要是一般檔案、大小有上限、解壓後也有上限（防 gzip bomb）；取出的字串截斷到 4096 字。
"""
import argparse
import datetime
import gzip
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import sys
from pathlib import Path

STAGE = "D-ubuntu-status"
SCHEMA = "sca-center-ubuntu-status/1"
MIRROR_SCHEMA = "sca-ubuntu-cve-status/1"
INDEX = "ubuntu-cve-status.json.gz"
LINUX_INDEX = "ubuntu-cve-status-linux.json.gz"
CVE_KEY = re.compile(r"^CVE-\d{4}-\d{4,}$")
PKG_NAME = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,127}$")
HERE = Path(__file__).resolve().parent
KNOWN = ("DNE", "ignored", "not-affected", "needs-triage", "needed", "in-progress", "deferred", "pending", "released")
LINUX_PART = re.compile(r"^linux($|-)")
MAX_TEXT = 4096
MAX_INDEX_MB = 512
SKEW_DAYS = 1
# 鏡像標頭的全體計數（ubuntu-cve-status.sh 的 GLOBAL；兩個檔相同，也寫在 SOURCE 的 count_<名稱>）
GLOBAL_COUNTS = ("cve_files", "dne_not_kept", "malformed_lines", "skipped_names", "duplicate_lines", "conflicting_entries",
                 "non_utf8_files", "odd_line_breaks", "unknown_priorities", "truncated_fields")
# 要人看的（不是 0 時報告列出）
REVIEW_COUNTS = ("duplicate_lines", "conflicting_entries", "malformed_lines", "skipped_names", "non_utf8_files", "odd_line_breaks",
                 "unknown_priorities", "truncated_fields")


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + re.sub(r"[\t\r\n]+", " ", str(detail))[:900])


def drc():
    """distro_recheck.py（load、InputError、libs、release_of、sbom_sources）：依路徑載入同一份規則。"""
    spec = importlib.util.spec_from_file_location("sca_center_distro_recheck", HERE / "distro_recheck.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def wanted(findings, bom, dr, pyres=None):
    """→ (components {purl: {source, source_version, release}}, {(CVE, 原始碼, 發行版)}, 計數)。核心的原始碼套件（linux、linux-*）不收。
    DT findings 裡 Ubuntu 打包的 Python 模組（pypi 元件，cra_report.deb_python_index 從 SBOM 找到唯一擁有它的 deb 套件）上的 CVE，
    也收擁有它的 deb 套件（components 以那個 deb 的 purl 為鍵）與 (CVE, 它的原始碼套件, 發行版)：cra_report 沒有 Grype 修補狀態時
    依 Tracker 推出修補狀態用（apply_ubuntu_tracker）。"""
    cra, ds, _ = dr.libs()
    srcs = dr.sbom_sources(bom) if bom else {}
    comps, pairs = {}, set()
    cnt = {"ubuntu_components": 0, "kernel_skipped": 0, "release_unknown": 0, "source_unknown": 0, "deb_python_owners": 0}

    def add(purl, p):
        ns, name, ver, q = p
        if q.get("arch") == "source":
            src, sver = name, ver
        elif q.get("upstream"):
            src, sver = ds.source_of(name, ver, q)
        else:
            # SBOM 裡有這個元件：Syft 的 source 屬性，沒有就是二進位本身（dpkg 只在不同時才寫 Source）；SBOM 裡也沒有 → 不知道，不猜
            src, sver = srcs.get(purl) or srcs.get((ns, name, ver)) or (None, None)
        rel = dr.release_of(ns, q.get("distro"))
        comps[purl] = {"source": src, "source_version": sver, "release": rel["codename"] if rel else None}
        cnt["ubuntu_components"] += 1
        if src is None:
            cnt["source_unknown"] += 1
        elif LINUX_PART.match(src):
            cnt["kernel_skipped"] += 1
        elif not rel:
            cnt["release_unknown"] += 1

    def want(purl, v):
        x = comps[purl]
        if x["source"] is None or LINUX_PART.match(x["source"]) or not x["release"]:
            return
        for cve in cra.cves_of(cra.ids_of(v)):
            pairs.add((cve, x["source"], x["release"]))
    dpy = {}
    if bom:
        dpy = cra.deb_python_index([c for c in cra.flatten((bom or {}).get("components")) if c.get("type") != "file"], pyres)[0]
    for f in findings:
        if not isinstance(f, dict):
            continue
        c, v = f.get("component") or {}, f.get("vulnerability") or {}
        if not isinstance(c, dict) or not isinstance(v, dict):
            continue
        purl = str(c.get("purl") or "")
        if purl.startswith("pkg:pypi/"):
            # Ubuntu 打包的 Python 模組：擁有它的 deb 套件（唯一的）
            x = dpy.get(purl.split("#", 1)[0].split("?", 1)[0]) or {}
            o = x.get("owner") or x.get("source_owner")     # source_owner：候選都來自同一個原始碼套件、同一個版本
            p = ds.parse(o["purl"]) if o else None
            if not p or p[0].lower() != "ubuntu":
                continue
            if o["purl"] not in comps:
                add(o["purl"], p)
                cnt["deb_python_owners"] += 1
            want(o["purl"], v)
            continue
        p = ds.parse(purl)
        if not p or p[0].lower() != "ubuntu":
            continue
        if purl not in comps:
            add(purl, p)
        want(purl, v)
    comps = {k: x for k, x in comps.items() if x["source"] is None or not LINUX_PART.match(x["source"])}
    return comps, pairs, cnt


def _age(src, key, now):
    try:
        t = datetime.datetime.fromisoformat(str(src.get(key)).replace("Z", "+00:00"))
    except ValueError:
        return None, f"SOURCE 沒有可解析的 {key}"
    if t.tzinfo is None:
        return None, f"SOURCE 的 {key} 沒有時區"
    a = (now - t).total_seconds() / 86400
    if a < -SKEW_DAYS:
        return None, f"SOURCE 的 {key}={src.get(key)} 在未來"
    return a, None


def open_mirror(path, max_age, max_commit_age, now=None):
    """→ (索引 dict 或 None, 鏡像狀態)。任何檢查不過 → (None, 狀態含 reason)。"""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    stt = {"path": path, "ok": False, "reason": None, "source": None, "commit": None, "commit_date": None, "fetched_utc": None, "sha256": None,
           "releases": None, "max_age_days": max_age, "max_commit_age_days": max_commit_age}

    def bad(why):
        stt["reason"] = why
        return None, stt
    if not path:
        return bad("沒有設定鏡像（PILOT_ENV 的 UBUNTU_CVE_STATUS_MIRROR）")
    if not os.path.isdir(path):
        return bad(f"鏡像資料夾不存在：{path}")
    sp, ip = os.path.join(path, "SOURCE"), os.path.join(path, INDEX)
    for root, dirs, files in os.walk(path):
        for n in dirs + files:
            if not (stat.S_ISREG(os.lstat(os.path.join(root, n)).st_mode) or stat.S_ISDIR(os.lstat(os.path.join(root, n)).st_mode)):
                return bad(f"鏡像裡有一般檔案與資料夾以外的東西：{os.path.relpath(os.path.join(root, n), path)[:120]}")
    try:
        if not stat.S_ISREG(os.lstat(sp).st_mode):
            return bad("SOURCE 不是一般檔案")
        src = dict(ln.split("=", 1) for ln in open(sp, encoding="utf-8").read().splitlines() if "=" in ln)
    except (OSError, UnicodeDecodeError):
        return bad("缺少 SOURCE（無法判斷新舊）")
    stt.update(fetched_utc=src.get("fetched_utc"), commit=src.get("commit"), commit_date=src.get("commit_date"))
    a, why = _age(src, "fetched_utc", now)
    if why:
        return bad(why)
    if a > max_age:
        return bad(f"鏡像過期：下載後 {a:.1f} 天 > {max_age:g} 天（fetched_utc={src.get('fetched_utc')}）")
    a, why = _age(src, "commit_date", now)
    if why:
        return bad(why)
    if a > max_commit_age:
        return bad(f"上游太久沒有更新：最後 commit 是 {a:.1f} 天前 > {max_commit_age:g} 天（上游可能搬家或停更）")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", src.get("commit", "")):
        return bad("SOURCE 的 commit 不是 git 的雜湊")
    try:
        if not stat.S_ISREG(os.lstat(ip).st_mode):
            return bad(f"{INDEX} 不是一般檔案")
        size = os.path.getsize(ip)
        if str(size) != src.get("main_bytes") or size > MAX_INDEX_MB << 20:
            return bad(f"{INDEX} 的大小與 SOURCE 不符（或超過上限）")
        if sha256_of(ip) != src.get("main_sha256"):
            return bad(f"{INDEX} 的 sha256 與 SOURCE 不符（下載不完整或被換掉）")
        buf = bytearray()
        with gzip.open(ip, "rb") as g:
            for b in iter(lambda: g.read(1 << 20), b""):
                buf += b
                if len(buf) > MAX_INDEX_MB << 20:
                    return bad(f"{INDEX} 解壓後超過 {MAX_INDEX_MB} MB")
        idx = json.loads(buf.decode("utf-8"))
    except (OSError, EOFError, ValueError, UnicodeDecodeError) as e:
        return bad(f"{INDEX} 無法讀取（{type(e).__name__}）")
    if not isinstance(idx, dict) or idx.get("schema") != MIRROR_SCHEMA or idx.get("part") != "main" or not isinstance(idx.get("cves"), dict):
        return bad(f"{INDEX} 不是 {MIRROR_SCHEMA} 的一般套件索引")
    if idx.get("linux_part_rule") != LINUX_PART.pattern:
        return bad(f"{INDEX} 的 linux_part_rule 不是 {LINUX_PART.pattern}（核心套件的分檔規則變了）")
    # 標頭與 SOURCE 一致（同 ubuntu-cve-status.sh --check：sha256 不涵蓋 SOURCE，兩邊都要比）
    for k, want in (("source", src.get("source")), ("commit", src.get("commit")), ("commit_date", src.get("commit_date")),
                    ("releases", src.get("releases", "").split()), ("keep_dne", src.get("keep_dne") == "1")):
        if idx.get(k) != want or (k == "keep_dne" and not isinstance(idx.get(k), bool)):
            return bad(f"{INDEX} 的 {k} 與 SOURCE 不符")
    cnt = idx.get("counts")
    if not isinstance(cnt, dict) or not isinstance(cnt.get("part"), dict):
        return bad(f"{INDEX} 沒有 counts")
    for k in GLOBAL_COUNTS:
        if not isinstance(cnt.get(k), int) or isinstance(cnt.get(k), bool) or str(cnt[k]) != src.get(f"count_{k}"):
            return bad(f"{INDEX} 的 counts.{k} 與 SOURCE 的 count_{k} 不符")
    for k in ("cves", "entries", "conflicting_entries"):
        if str(cnt["part"].get(k)) != src.get(f"main_{k}"):
            return bad(f"{INDEX} 的 counts.part.{k} 與 SOURCE 的 main_{k} 不符")
    # 內容（同 ubuntu-cve-status.sh --check：鍵的格式、每筆的格式、DNE、發行版），counts.part 用內容重算後比對
    why = check_content(idx, src.get("keep_dne") == "1")
    if why:
        return bad(f"{INDEX} {why}")
    # linux 檔不讀內容，但要在、是一般檔案、大小與 sha256 和 SOURCE 一致（鏡像是一整份；只剩一半就是不完整）
    lp = os.path.join(path, LINUX_INDEX)
    try:
        if not stat.S_ISREG(os.lstat(lp).st_mode):
            return bad(f"{LINUX_INDEX} 不是一般檔案")
        if str(os.path.getsize(lp)) != src.get("linux_bytes") or sha256_of(lp) != src.get("linux_sha256"):
            return bad(f"{LINUX_INDEX} 的 sha256 或大小與 SOURCE 不符")
    except OSError:
        return bad(f"缺少 {LINUX_INDEX}（鏡像不完整）")
    stt.update(ok=True, source=_text(src.get("source"))[:512], sha256=src.get("main_sha256"), releases=[str(r) for r in idx["releases"]])
    return idx, stt


def sha256_of(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _txt(v):
    return isinstance(v, str) and len(v) <= MAX_TEXT


def entry_ok(e):
    """同 ubuntu-cve-status.sh --check 的 entry_ok。"""
    return isinstance(e, dict) and _txt(e.get("status")) and _txt(e.get("note")) \
        and set(e) <= {"status", "note", "priority", "conflict"} and ("priority" not in e or _txt(e["priority"])) \
        and ("conflict" not in e or isinstance(e["conflict"], list) and bool(e["conflict"])
             and all(isinstance(x, dict) and set(x) == {"status", "note"} and _txt(x["status"]) and _txt(x["note"]) for x in e["conflict"]))


def check_content(idx, keep_dne):
    """一般檔的每一筆（同 --check）→ 問題或 None。"""
    rels = idx["releases"]
    if not isinstance(rels, list) or not all(isinstance(r, str) for r in rels):
        return "的 releases 格式不對"
    entries, conflicts, by_rel = 0, 0, {r: {} for r in rels}
    for c, r in idx["cves"].items():
        if not CVE_KEY.match(str(c)) or not isinstance(r, dict) or set(r) != {"priority", "tracker_dir", "packages"}:
            return "裡有不是 CVE 編號的鍵或格式不對"
        if not (r["priority"] is None or _txt(r["priority"])) or r["tracker_dir"] not in ("active", "retired"):
            return f"的 {c} 的 priority 或 tracker_dir 格式不對"
        if not isinstance(r["packages"], dict) or not r["packages"]:
            return f"的 {c} 沒有任何套件狀態"
        for name, rs in r["packages"].items():
            if not isinstance(name, str) or not PKG_NAME.match(name) or LINUX_PART.match(name) or not isinstance(rs, dict) or not rs:
                return f"的 {c} 的套件名稱或格式不對（或核心套件放在一般檔）"
            for rel, e in rs.items():
                if rel not in by_rel or not entry_ok(e):
                    return f"的 {c} {name} 的發行版或狀態格式不對"
                if e["status"] == "DNE" and not keep_dne and "conflict" not in e:
                    return f"的 {c} {name} {rel} 是 DNE，但這份索引不收 DNE"
                entries += 1
                conflicts += "conflict" in e
                by_rel[rel][e["status"]] = by_rel[rel].get(e["status"], 0) + 1
    if idx["counts"]["part"] != {"cves": len(idx["cves"]), "entries": entries, "conflicting_entries": conflicts, "by_release": by_rel}:
        return "的 counts.part 與內容不符"
    return None


def _text(x):
    return str(x)[:MAX_TEXT] if x is not None else ""


def ubuntu_status(findings, bom, mirror, max_age, max_commit_age, dr=None, now=None, pyres=None):
    """回傳 (狀態, 說明, 輸出 JSON 或 None)。"""
    dr = dr or drc()
    if not isinstance(findings, list):
        raise dr.InputError("DT findings 不是清單")
    comps, pairs, cnt = wanted(findings, bom, dr, pyres)
    if not pairs:
        return "NOT_RUN", "DT findings 沒有 Ubuntu 套件（核心以外）上的 CVE", None
    idx, mst = open_mirror(mirror, max_age, max_commit_age, now)
    out = {"schema": SCHEMA, "stage": STAGE,
           "generated": (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "mirror": mst, "components": comps, "entries": {}, "other_releases": {}, "cve_info": {}, "mirror_counts": {}, "counts": dict(cnt, pairs=len(pairs))}
    if idx is None:
        detail = f"Ubuntu 套件上的 (CVE, 原始碼套件) {len(pairs)} 組沒有讀 Ubuntu CVE Tracker 的狀態（{mst['reason']}）；證據規則 U1 不套用"
        out.update(status="NOT_RUN", detail=detail)
        return "NOT_RUN", detail, out
    rels = set(mst["releases"])
    missing_rel = sorted({r for _, _, r in pairs} - rels)
    if missing_rel:
        detail = f"映像的發行版 {', '.join(missing_rel)} 不在鏡像裡（鏡像有 {', '.join(sorted(rels))}；UBUNTU_CVE_RELEASES）；證據規則 U1 不套用"
        out.update(status="NOT_RUN", detail=detail)
        return "NOT_RUN", detail, out
    hc = (idx.get("counts") or {}) if isinstance(idx.get("counts"), dict) else {}
    out["mirror_counts"] = {k: hc.get(k) for k in REVIEW_COUNTS}
    out["mirror_counts"]["part_conflicting_entries"] = (hc.get("part") or {}).get("conflicting_entries")
    by, unknown, conflicts = {}, {}, 0
    for cve, src, rel in sorted(pairs):
        rec = idx["cves"].get(cve)
        pk = (((rec.get("packages") or {}) if isinstance(rec, dict) else {}).get(src) or {})
        # 同一個 CVE、同一個原始碼套件在鏡像裡其他 Ubuntu 版本的狀態（目前不用於判定；給人參考、之後放寬時用）
        oth = {r2: {"status": _text(x2.get("status"))[:64], "note": _text(x2.get("note"))}
               for r2, x2 in (pk.items() if isinstance(pk, dict) else ()) if r2 != rel and isinstance(x2, dict) and isinstance(x2.get("status"), str)}
        if oth:
            out["other_releases"].setdefault(cve, {})[src] = oth
        e = pk.get(rel) if isinstance(pk, dict) else None
        if not isinstance(e, dict) or not isinstance(e.get("status"), str):
            continue
        x = {"status": _text(e["status"])[:64], "note": _text(e.get("note"))}
        if isinstance(e.get("priority"), str):
            x["priority"] = _text(e["priority"])[:64]
        if "conflict" in e:
            # 後面不同的行：[{status, note}, …]（格式不對的也當作有衝突，偏保守）
            cl = e["conflict"] if isinstance(e["conflict"], list) else [e["conflict"]]
            x["conflict"] = [{"status": _text(c.get("status"))[:64], "note": _text(c.get("note"))} if isinstance(c, dict)
                             else {"status": "?", "note": _text(c)} for c in cl][:20] or [{"status": "?", "note": ""}]
            conflicts += 1
        out["entries"].setdefault(cve, {}).setdefault(src, {})[rel] = x
        if cve not in out["cve_info"]:
            # 出處：tracker 裡的檔案（<tracker_dir>/<CVE>）與 CVE 層級的 Priority（空的是 null）；證據規則 U1 的排除清單用
            td = rec.get("tracker_dir") if rec.get("tracker_dir") in ("active", "retired") else None
            out["cve_info"][cve] = {"priority": _text(rec["priority"])[:64] if isinstance(rec.get("priority"), str) else None,
                                    "tracker_file": f"{td}/{cve}" if td else None}
        by[x["status"]] = by.get(x["status"], 0) + 1
        if x["status"] not in KNOWN:
            unknown[x["status"]] = unknown.get(x["status"], 0) + 1
    out["mirror_counts"]["unknown_status"] = sum(unknown.values())
    n = sum(by.values())
    out["counts"].update(with_entry=n, no_entry=len(pairs) - n, by_status=dict(sorted(by.items())), conflict=conflicts,
                         unknown_status=dict(sorted(unknown.items())))
    review = {k: v for k, v in out["mirror_counts"].items() if v}
    detail = (f"Ubuntu 套件上的 (CVE, 原始碼套件) {len(pairs)} 組：Tracker 有狀態 {n}（"
              + "、".join(f"{k} {v}" for k, v in sorted(by.items())) + f"）、沒有 {len(pairs) - n}、conflict {conflicts}"
              + (f"；要人看的計數：{'、'.join(f'{k}={v}' for k, v in review.items())}" if review else "")
              + f"（scan/ubuntu-status.json；Tracker commit {str(mst['commit'])[:12]}，fetched_utc={mst['fetched_utc']}；核心套件不在範圍）")
    out.update(status="OK", detail=detail)
    return "OK", detail, out


def days(arg, env, default):
    """新舊上限（天）：參數優先，再來環境變數；要是有限的非負數（nan、inf、負數、不是數字 → 輸入錯誤，指出是哪一個）。"""
    raw = arg if arg is not None else (os.environ.get(env) or default)
    try:
        v = float(raw)
    except (TypeError, ValueError):
        v = None
    if v is None or not math.isfinite(v) or v < 0:
        raise drc().InputError(f"{env}（或對應的參數）不是有限的非負數：{str(raw)[:40]}")
    return v


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ubuntu 套件上的 CVE → Ubuntu CVE Tracker 的狀態（D-ubuntu-status；證據規則 U1 用）")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--sbom")
    ap.add_argument("--py-versions", help="py_dpkg_version.py scan 的 python-versions.json（選用；dpkg 擁有 Python 模組的 metadata 檔時，用檔案所有權找擁有它的 deb）")
    ap.add_argument("--mirror")
    ap.add_argument("--max-age-days", type=float, default=None)
    ap.add_argument("--max-commit-age-days", type=float, default=None)
    ap.add_argument("--out", required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        line("FAIL", "ubuntu_status.py 參數錯誤")
        return 3
    try:
        dr = drc()
        max_age = days(a.max_age_days, "UBUNTU_CVE_MAX_AGE_DAYS", 3)
        mca = days(a.max_commit_age_days, "UBUNTU_CVE_MAX_COMMIT_AGE_DAYS", 14)
        pyres = None
        if a.py_versions:
            pm = dr.libs()[0].pyver_mod()
            pyres = pm.by_path(pm.load(a.py_versions))
        st, detail, out = ubuntu_status(dr.load(a.findings, "DT findings"), dr.load(a.sbom, "SBOM"), a.mirror, max_age, mca, dr, pyres=pyres)
    except Exception as e:      # 含 InputError：記 FAIL，不讓掃描中斷、不印 traceback
        line("FAIL", f"ubuntu_status.py 無法處理（{e if type(e).__name__ == 'InputError' else type(e).__name__}）")
        return 3
    if out is not None:
        try:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=1)
        except OSError as e:
            line("FAIL", f"無法寫入 {a.out}（{type(e).__name__}）")
            return 3
    line(st, detail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
