#!/usr/bin/env python3
"""nvidia_distro.py：NVIDIA 公告列出的 CVE 中，其實是發行版套件（polkit 等，不是 NVIDIA 的程式）的，改依發行版資料判斷。

為什麼：NVIDIA 的 Jetson Linux 公告有時會列第三方套件的 CVE（例如 CVE-2021-4034 的 pkexec）。這類 CVE 掛在 nvidia-l4t-core 上
只能是「推定已含修正、NVIDIA 未確認」，但映像裡真正的套件是 Ubuntu 的 polkit，發行版資料（Grype DB v6）已經有答案。

做法（唯讀；資料庫用 sqlite 唯讀模式開啟，不執行任何內容，不連網）：
  0. 資料庫必須是 Grype v6（db_metadata.model＝6、有 vulnerability_handles 等表）、建置時間可解析而且不超過 max_age_days（預設 3 天，
     同 uefi_bundled.py／exploited_grype.py 的 GRYPE_DB_MAX_AGE_DAYS）。否則不查（info.checked＝false 與原因），維持原狀。
  1. 這個 CVE 在發行版資料庫（映像的發行版，Ubuntu 或 Debian 那一個提供者）有沒有記錄，記錄的套件名（來源套件名或二進位套件名）是不是映像 SBOM 裡
     某個 deb 套件的名稱或來源套件名（purl 的 upstream）。nvidia-l4t-* 不算。沒有 → 不是發行版套件的 CVE，回傳裡不出現。
  2. 有 → 只在有「正面證據」時關閉（任何一條都不成立 → ambiguous，維持原狀，證據只寫成備註）：
     (a) 這個發行版本對這個套件有 not-affected 記錄（沒有版本限制）→ not_affected／code_not_present。
     (b) 這個發行版本有 fixed 記錄「< X」：安裝版本 >= X → resolved（已修）；< X → affected（VEX in_triage，指向發行版套件的列）。
         記錄是 not-fixed／wont-fix／其他、或版本限制看不懂 → affected（發行版沒有說已修／不受影響）。
         有這個發行版本自己的記錄時，只依 (a)(b)，不用下面的 (c)。
     (c) 這個發行版本沒有記錄，但有有問題的執行檔清單（VULN_BINARIES，逐個 CVE 的表），而且給了 rootfs、清單內的檔案全部不在 rootfs
         → not_affected／code_not_present（執行檔不存在；版本資料只當補充說明）。
     發行版的修補版本是各版本線內的 backport 編號，不同版本線的修補版本不能互相比大小，所以「安裝版本比其他版本的修補版本都新」不構成關閉的理由。
  3. 同一個來源套件有多個二進位套件、安裝版本不同時各自判斷；結果全部相同才採用，否則 ambiguous。
只用標準函式庫。這個模組不做任何網路連線。"""
import datetime
import json
import os
import re
import sqlite3
import stat
import urllib.parse
from pathlib import Path

# CVE → rootfs 內有問題的執行檔（逐個 CVE 的表；沒列的 CVE 不查）。清單內全部不存在才算「執行檔不存在」
VULN_BINARIES = {"CVE-2021-4034": ["usr/bin/pkexec"]}
CLOSED = ("not_affected", "resolved")
DEFAULT_MAX_AGE_DAYS = 3.0


class DbError(Exception):
    """資料庫找不到、不是 Grype v6、讀不了、太舊或建置時間不明。args[0] 是原因（英文，寫進 summary.json）。"""


def _meta(path):
    """→ (db_metadata 的 dict) 或 raise DbError。確認是 Grype v6：有 db_metadata（model＝6）與 vulnerability_handles。"""
    try:
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            tables = {r[0] for r in c.execute("select name from sqlite_master where type='table'")}
            if not {"db_metadata", "vulnerability_handles", "affected_package_handles", "packages", "operating_systems", "blobs"} <= tables:
                raise DbError(f"{path} is not a Grype v6 database (tables missing)")
            row = c.execute("select build_timestamp,model,revision,addition from db_metadata").fetchone()
        finally:
            c.close()
    except sqlite3.Error as e:
        raise DbError(f"{path} cannot be read as a Grype database ({type(e).__name__})")
    if not row or str(row[1]) != "6":
        raise DbError(f"{path} is not a Grype v6 database (schema model {row[1] if row else 'unknown'})")
    return {"built": str(row[0]), "model": row[1], "revision": row[2], "addition": row[3]}


def find_db(explicit=None, env=None):
    """--grype-db（vulnerability.db 或含 vulnerability.db／6/vulnerability.db 的資料夾）；沒給時才看環境變數 GRYPE_DB_CACHE_DIR。
    → (路徑, 來源 "option"|"env") 或 None（沒給、也沒有環境變數，或環境變數指的地方沒有檔案）。
    明確給了 --grype-db 卻找不到 → raise DbError（不退回環境變數）。找到的檔案不是 Grype v6 → raise DbError。"""
    env = os.environ if env is None else env
    for base, src in ((explicit, "option"), (None if explicit else env.get("GRYPE_DB_CACHE_DIR"), "env")):
        if not base:
            continue
        p = Path(base)
        found = [c for c in (p, p / "vulnerability.db", p / "6" / "vulnerability.db") if c.is_file()]
        if not found:
            if src == "option":
                raise DbError(f"--grype-db {base}: no vulnerability.db found")
            continue
        _meta(found[0])          # v6 檢查；失敗 raise DbError
        return found[0], src
    return None


def _parse_ts(s):
    s = str(s).strip().replace("Z", "+00:00")
    try:
        d = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


def open_db(path, source, now, max_age_days=DEFAULT_MAX_AGE_DAYS):
    """→ (連線, info)；info＝{path, source, model, revision, addition, built, age_days}。太舊、建置時間不明 → raise DbError。"""
    m = _meta(path)
    built, cur = _parse_ts(m["built"]), _parse_ts(now)
    if built is None or cur is None:
        raise DbError(f"database build time is unparsable ({m['built']!r})")
    age = (cur - built).total_seconds() / 86400
    if age > max_age_days:
        raise DbError(f"database older than {max_age_days:g} days, built {m['built']} ({age:.1f} days)")
    if age < -1:
        raise DbError(f"database build time {m['built']} is in the future")
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    return c, dict(m, path=str(path), source=source, age_days=round(age, 2))


def deb_packages(components):
    """CycloneDX 元件 → [{name, version, source, os, major, minor}]（只收 pkg:deb/ubuntu|debian，不含 nvidia-l4t-*）。"""
    out = []
    for c in components or []:
        purl = str(c.get("purl") or "") if isinstance(c, dict) else ""
        m = re.match(r"pkg:deb/(ubuntu|debian)/", purl)
        if not m or str(c.get("name") or "").startswith("nvidia-l4t"):
            continue
        base, _, qs = purl.split("#", 1)[0].partition("?")
        q = {k.lower(): urllib.parse.unquote(v[0]) for k, v in urllib.parse.parse_qs(qs).items() if v}
        d = re.match(r"(ubuntu|debian)-(\d+)(?:\.(\d+))?", q.get("distro", ""))
        if not d:
            continue
        name = str(c.get("name") or "")
        src = re.sub(r"[ (].*", "", q.get("upstream") or name)
        out.append({"name": name, "version": str(c.get("version") or ""), "source": src, "os": d.group(1),
                    "major": d.group(2), "minor": str(int(d.group(3))) if d.group(3) else None})
    return out


def _records(c, cve, osname):
    """→ 該 CVE、該發行版提供者的所有 affected／unaffected 記錄 [{kind, pkg, major, minor, channel, eol, ranges}]（一次查詢，之後在記憶體裡篩）。"""
    out = []
    for kind in ("affected", "unaffected"):
        sql = (f"select p.name,o.major_version,o.minor_version,o.channel,o.eol_date,b.value from {kind}_package_handles x "
               "join vulnerability_handles v on v.id=x.vulnerability_id join operating_systems o on o.id=x.operating_system_id "
               "join packages p on p.id=x.package_id left join blobs b on b.id=x.blob_id "
               "where v.name=? and v.provider_id=? and o.name=?")
        for pkg, major, minor, ch, eol, blob in c.execute(sql, (cve, osname, osname)):
            try:
                rng = json.loads(blob)["ranges"]
            except (TypeError, ValueError, KeyError):
                rng = None
            out.append({"kind": kind, "pkg": pkg, "major": str(major or ""), "minor": str(int(minor)) if str(minor or "").isdigit() else "",
                        "channel": ch or "", "eol": eol, "ranges": rng})
    return out


def _constraint_fix(r):
    fx = r.get("fix") or {}
    return fx.get("state"), fx.get("version"), (r.get("version") or {}).get("constraint")


def _rel_key(x):
    return (int(x["major"]) if x["major"].isdigit() else 0, int(x["minor"]) if x["minor"].isdigit() else 0)


def _label(osn, major, minor):
    return f"{osn.capitalize()} {major}" + (f".{int(minor):02d}" if str(minor or "").isdigit() else "")


def _judge_pkg(recs_all, pk, version, vercmp, now, binary):
    """一個 (套件名, 安裝版本) → dict(state, basis, detail) 或 None（資料庫對這個套件名沒有這個 CVE 的記錄）。
    binary：(state "absent"|"present"|None, 說明文字)。"""
    recs = [x for x in recs_all if x["pkg"] == pk["pkg_name"]]
    cve = pk["cve"]
    if not recs:
        return None
    rel = [x for x in recs if x["major"] == pk["major"] and (pk["minor"] is None or x["minor"] == pk["minor"])]
    if any(x["channel"] == "" for x in rel):          # 同一發行版本有一般與 ESM 兩種頻道時用一般頻道
        rel = [x for x in rel if x["channel"] == ""]
    label = _label(pk["os"], pk["major"], pk["minor"])
    n = pk["pkg_name"]
    if rel:
        notes = []
        for x in rel:
            if x["ranges"] is None:
                return {"state": "ambiguous", "basis": "unreadable", "detail": f"{label} record for {n} is unreadable"}
            for r in x["ranges"]:
                st, fv, cons = _constraint_fix(r)
                if x["kind"] == "unaffected" and st == "not-affected" and not cons:
                    return {"state": "not_affected", "basis": "release_unaffected",
                            "detail": f"{label} data marks {n} as not affected by {cve}"}
                if st == "fixed" and fv:
                    if vercmp(version, fv) >= 0:
                        return {"state": "resolved", "basis": "release_fixed", "fixed": fv,
                                "detail": f"{label} data lists {n} as fixed in {fv}; installed {version} is the same or newer"}
                    notes.append(f"fixed in {fv}, installed {version} is older")
                else:
                    notes.append(f"state {st or 'unknown'}" + (f" ({cons})" if cons else ""))
        return {"state": "affected", "basis": "release_affected",
                "detail": f"{label} data lists {n} as affected ({'; '.join(notes)})"}
    # 這個發行版本沒有記錄：只有正面證據才關閉（見檔頭 (c)：完整清單證明執行檔不存在）；其他版本的修補版本只當備註，不比較
    others = [x for x in recs if x["kind"] == "affected"]
    fixed = []
    for x in sorted(others, key=_rel_key):
        for r in x["ranges"] or []:
            st, fv, _ = _constraint_fix(r)
            if st == "fixed" and fv:
                fixed.append((_label(pk["os"], x["major"], x["minor"]), fv))
    fixed = sorted(set(fixed), key=lambda t: (t[0].split()[0], [int(p) for p in re.findall(r"\d+", t[0])], t[1]))
    others_txt = (f"; the distribution data lists {cve} for " + ", ".join(sorted({f[0] for f in fixed}, key=lambda s: [int(p) for p in re.findall(r"\d+", s)]))
                  + " only, fixed in " + ", ".join(f[1] for f in fixed)) if fixed else ""
    base = f"{label} data has no record for {n}"
    if binary[0] == "absent":
        return {"state": "not_affected", "basis": "binary_absent", "justification": "code_not_present",
                "detail": f"{base}; the vulnerable executable is {binary[1]}{others_txt} (fix numbers of other releases are backport numbers of their own "
                          "package lines and are not compared with the installed version)"}
    why = (f"; {binary[1]}" if binary[1] else "")
    return {"state": "ambiguous", "basis": "no_release_record",
            "detail": f"{base}, and there is no positive evidence for the installed version{others_txt} (other releases' fix numbers are not "
                      f"compared with the installed version){why}"}


MAX_OWNERS = 256 << 20


def _canon(path):
    p = str(path)
    for d in ("/bin/", "/sbin/", "/lib/", "/lib64/"):
        if p.startswith(d):
            return "/usr" + p
    return p


def load_owners(pkgdb):
    """pkgdb 資料夾（pkg_why.py extract）的 dpkg-file-owners → ({正規化路徑: {套件}}, None)；沒有、被截斷（#partial）、空的、讀不了
    → (None, 原因)。不跟隨符號連結。這是「已安裝套件擁有的檔案」的完整清單才能拿來證明檔案不存在。"""
    if pkgdb is None:
        return None, "no pkgdb"
    p = os.path.join(str(pkgdb), "dpkg-file-owners")
    try:
        st = os.lstat(p)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_OWNERS:
            return None, "dpkg-file-owners is not a regular file or too large"
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            text = f.read(MAX_OWNERS + 1).decode("utf-8", "replace")
    except FileNotFoundError:
        return None, "the scanned image has no dpkg file lists"
    except OSError as e:
        return None, f"dpkg-file-owners unreadable ({type(e).__name__})"
    if text.startswith("#partial"):
        return None, "the dpkg file lists are partial"
    owners = {}
    for line in text.splitlines():
        pkg, _, path = line.partition("\t")
        if pkg and path.startswith("/"):
            owners.setdefault(_canon(path), set()).add(pkg)
    return (owners, None) if owners else (None, "dpkg-file-owners is empty")


def load_rootfs_files(pkgdb):
    """pkgdb 資料夾的 rootfs-files（pkg_why.py extract 抽出的「映像裡所有項目」完整清單）→ ({路徑: (kind, link 目標)}, None)；
    沒有、第一行不是 #complete（#partial 或舊格式）、空的、讀不了 → (None, 原因)。不跟隨符號連結。"""
    if pkgdb is None:
        return None, "no pkgdb"
    p = os.path.join(str(pkgdb), "rootfs-files")
    try:
        st = os.lstat(p)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_OWNERS:
            return None, "rootfs-files is not a regular file or too large"
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            text = f.read(MAX_OWNERS + 1).decode("utf-8", "replace")
    except FileNotFoundError:
        return None, "the scan has no complete listing of the root file system (re-run the scan to extract it)"
    except OSError as e:
        return None, f"rootfs-files unreadable ({type(e).__name__})"
    lines = text.split("\n")
    if not lines or lines[0] != "#complete":
        return None, "the root file system listing is partial or in an unknown format"
    files = {}
    for line in lines[1:]:
        kind, _, rest = line.partition("\t")
        path, _, link = rest.partition("\t")
        if kind and path.startswith("/"):
            files[path] = (kind, link)
    return (files, None) if files else (None, "the root file system listing is empty")


def _resolve(path, files, hops=40):
    """絕對路徑 → 沿著清單裡的符號連結（只看上層資料夾；最後一個元件不展開）解開後的路徑。"""
    parts = [x for x in path.split("/") if x]
    for _ in range(hops):
        cur = ""
        for i, part in enumerate(parts[:-1]):
            cur += "/" + part
            ent = files.get(cur)
            if ent and ent[0] == "symlink":
                tgt = ent[1]
                base = tgt.split("/") if tgt.startswith("/") else cur.rsplit("/", 1)[0].split("/") + tgt.split("/")
                out = []
                for x in base + parts[i + 1:]:
                    if x in ("", "."):
                        continue
                    if x == "..":
                        if out:
                            out.pop()
                        continue
                    out.append(x)
                parts = out
                break
        else:
            return "/" + "/".join(parts)
    return None


def binary_check(cve, rootfs_dir=None, files=None, owners=None, covered=None):
    """有問題的執行檔在映像裡有沒有。→ ("absent"|"present"|None, 說明)。CVE 不在表內 → (None, None)。清單內全部不在才是 absent。
    1. 給了解開的 rootfs 資料夾：只看路徑存在，不跟隨符號連結、不讀內容。
    2. 否則用完整的 rootfs 項目清單（files，load_rootfs_files；所有一般檔案、連結、資料夾，不只 dpkg 管理的）：路徑（上層資料夾的符號連結解開後）在清單裡
       （任何種類，包含符號連結）→ present；不在 → absent。解不開符號連結 → 不明。
    3. 只有 dpkg 檔案擁有者清單（owners）時，只能說「沒有任何已安裝套件列出」，不能說檔案不存在（映像建置時放進去的非套件檔案看不到）
       → 狀態不明（None），說明文字保留 dpkg 的證據；有套件列出 → present。
    沒給 rootfs、沒有完整清單 → (None, None)：不明，絕不當成 absent。"""
    paths = VULN_BINARIES.get(cve)
    if not paths:
        return None, None
    if rootfs_dir:
        root = Path(rootfs_dir)
        if root.is_dir():
            here, unknown = [], []
            for p in paths:
                try:
                    os.lstat(root / p)
                    here.append(p)
                except (FileNotFoundError, NotADirectoryError):
                    pass
                except OSError as e:           # 權限不足、迴圈、I/O 錯誤…：不知道，絕不當成不存在
                    unknown.append(f"{p} ({type(e).__name__})")
            if here:
                return "present", "present in the root file system: /" + ", /".join(here)
            if unknown:
                return None, "could not be checked in the extracted root file system: /" + ", /".join(unknown)
            return "absent", "absent from the root file system: /" + ", /".join(paths)
    if files:
        res = [(p, _resolve("/" + p, files)) for p in paths]
        if any(r is None for _, r in res):
            return None, None
        here = [p for p, r in res if r in files]
        if here:
            return "present", "present in the root file system listing: /" + ", /".join(here)
        return "absent", ("absent from the complete listing of the root file system (" + str(len(files)) + " entries): /" + ", /".join(paths))
    if owners:
        listed = {"/" + p: sorted(owners.get(_canon("/" + p), ())) for p in paths}
        here = [p for p, o in listed.items() if o]
        if here:
            return "present", "listed by installed packages: " + ", ".join(f"{p} ({'/'.join(listed[p])})" for p in here)
        owner_pkgs = set().union(*owners.values())
        if covered and set(covered) & owner_pkgs:
            return None, "not listed by any installed package; non-package files not checked: /" + ", /".join(paths)
    return None, None


def _combine(results):
    states = {r["state"] for r in results}
    if len(states) == 1:
        st = states.pop()
    else:
        st = "ambiguous"
    first = sorted(results, key=lambda r: (r["state"] != st, r["package"], r["version"]))[0]
    return st, first


def remap(cves, components, db_path, vercmp, now=None, rootfs_dir=None, max_age_days=DEFAULT_MAX_AGE_DAYS, source="option", owners=None, files=None):
    """cves：NVIDIA 公告的 CVE 清單。→ (結果, info)。
    info：{"checked": bool, "reason": str|None, "db": {path, source, model, revision, addition, built, age_days}|None}。
    資料庫找不到／不是 v6／讀不了／太舊 → checked＝false（結果 {}），呼叫端要記下原因，不能當成「沒有發行版套件」。
    結果只含「資料庫有該 CVE 的記錄、套件在映像裡」的 CVE（其餘不是發行版套件的 CVE，不出現）：state（not_affected／resolved／affected／ambiguous）、
    package（套件名）、binaries、version、basis、detail（英文）、justification（not_affected 才有）、db、binary_note（補充證據，可為 None）。"""
    now = now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not db_path:
        return {}, {"checked": False, "reason": "no Grype DB given", "db": None}
    try:
        c, dbi = open_db(db_path, source, now, max_age_days)
    except DbError as e:
        return {}, {"checked": False, "reason": str(e.args[0]), "db": None}
    pk_all = deb_packages(components)
    out = {}
    try:
        for cve in sorted({str(x).upper() for x in cves}):
            try:
                recs_by_os = {o: _records(c, cve, o) for o in sorted({p["os"] for p in pk_all})}
            except sqlite3.Error as e:
                return {}, {"checked": False, "reason": f"database query failed ({type(e).__name__})", "db": None}
            if not any(recs_by_os.values()):
                continue
            dbnames = {x["pkg"] for rs in recs_by_os.values() for x in rs}
            covered = {p["name"] for p in pk_all if p["source"] in dbnames or p["name"] in dbnames}
            binary = binary_check(cve, rootfs_dir, files, owners, covered)
            groups = {}
            for p in pk_all:
                groups.setdefault((p["os"], p["major"], p["minor"], p["source"], p["version"]), []).append(p)
            results = []
            for (osn, major, minor, src, ver), ps in sorted(groups.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
                # 資料庫的套件名可能是來源套件名，也可能是二進位名稱：每一個有記錄的名稱都判斷，不只第一個
                for nm in [src] + sorted({p["name"] for p in ps} - {src}):
                    r = _judge_pkg(recs_by_os.get(osn, []), {"os": osn, "major": major, "minor": minor, "pkg_name": nm, "cve": cve},
                                   ver, vercmp, now, binary)
                    if r is not None:
                        r.update(package=nm, binaries=sorted({p["name"] for p in ps}), version=ver)
                        results.append(r)
            if not results:
                continue
            st, first = _combine(results)
            res = dict(first, state=st, db=dbi, checked_packages=len(results))
            if st == "ambiguous" and len({r["state"] for r in results}) > 1:
                res.update(basis="mixed", detail="packages of this CVE disagree: " + " | ".join(
                    f"{r['package']} {r['version']}: {r['state']} ({r['detail']})" for r in results))
            elif len(results) > 1:
                res["detail"] = " | ".join(sorted({r["detail"] for r in results}))
            if st == "not_affected":
                res["justification"] = first.get("justification") or "code_not_present"
            else:
                res.pop("justification", None)
            res["binary_note"] = binary[1]
            out[cve] = res
    finally:
        c.close()
    return out, {"checked": True, "reason": None, "db": dbi}


def statement_text(res, cve):
    """VEX 的 detail（英文，給客戶的檔案也會用）。"""
    s = (f"The NVIDIA bulletin lists {cve}, but it is a vulnerability of the distribution package {res['package']} "
         f"(installed {res['version']}; binary packages {', '.join(res['binaries'])}), not of NVIDIA code. Assessed from the distribution data "
         f"(Grype DB built {res['db']['built']}): {res['detail']}.")
    if res.get("binary_note") and res.get("basis") != "binary_absent":
        s += f" Supporting evidence only: the vulnerable executable is {res['binary_note']}."
    return s
