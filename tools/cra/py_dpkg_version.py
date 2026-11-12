#!/usr/bin/env python3
"""py_dpkg_version.py：Debian／Ubuntu 打包的 Python 模組，egg-info／dist-info 的版本是佔位值（0.0.0、0.0、0 或沒有）時，
用擁有那個 metadata 檔的 dpkg 套件的上游版本當真正的版本，並記錄出處。

用法：
  python3 -I py_dpkg_version.py scan --from <rootfs tar｜刷機包 tbz2｜rootfs 資料夾> [--prefix <路徑>] --pkgdb <pkg_why.py extract 的資料夾>
                                      [--out <json，預設 <pkgdb>/python-versions.json>]
  python3 -I py_dpkg_version.py apply --sbom <SBOM> --resolved <python-versions.json> --out <新的 SBOM>

scan：從映像串流讀 usr/lib/python3*/dist-packages 下的 *.egg-info（檔案或資料夾的 PKG-INFO）與 *.dist-info/METADATA（上限 1 MB），
  以及頂層套件資料夾的 __init__.py（只讀前 64 KB，用正規表示式找 __version__ = '…'，不執行任何東西）。來源是不可信資料：
  不解開到磁碟、不跟隨連結。版本是佔位值的，用 <pkgdb>/dpkg-file-owners（pkg_why.py extract 產生；/var/lib/dpkg/info/*.list，
  :arch 後綴已去掉）找出擁有那個 metadata 檔的 dpkg 套件，版本取 <pkgdb>/dpkg-status 的上游版本（去掉 epoch、Debian revision 與
  +dfsg／+ds／+repack）。判定（state）：
    RESOLVED   dpkg 擁有、上游版本可用；若有 __version__ 就要相同。
    DISAGREE   dpkg 的上游版本與 __version__ 不同 → 版本仍然未知（GAP），兩個值都記，不猜。
    NOT_OWNED  沒有 dpkg 套件擁有它（或不只一個）→ 版本仍然未知（規則 13 不變）。
    UNSURE     dpkg 的上游版本不能安全對應成 Python 版本（+really、~、+git…、不是純數字加點）或本身也是佔位值（0.0.0-1）→ 版本仍然未知。
    NO_OWNER_DATA  沒有 dpkg-file-owners／dpkg-status → 無法判斷，版本仍然未知。
apply：把 RESOLVED 的元件寫進 SBOM 副本（版本、purl、bom-ref、cpe 裡的版本換掉），並加屬性 sca:version-source、sca:original-version；
  原始 SBOM 不動。DISAGREE／NOT_OWNED 的元件不改，只加屬性 sca:version-resolution=<state>。
"""
import argparse
import contextlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = "sca-center-python-versions/1"
MAX_META = 1 << 20
MAX_INIT = 64 << 10
MAX_ENTRIES = 20000
PLACEHOLDER = re.compile(r"^0+(\.0+)*$")
DP = r"(?:usr/)?lib/python3(?:\.\d+)?/dist-packages"
META_RE = re.compile(rf"^{DP}/([^/]+)\.(egg-info|dist-info)(?:/(PKG-INFO|METADATA))?$")
INIT_RE = re.compile(rf"^{DP}/([^/]+)/__init__\.py$")
VER_LINE = re.compile(r"^__version__\s*=\s*['\"]([^'\"\s]+)['\"]", re.M)
DEB_NOISE = re.compile(r"\+(?:dfsg|ds|repack)[0-9.]*$", re.I)


class Fail(Exception):
    pass


def is_placeholder(v):
    v = (v or "").strip()
    return v == "" or bool(PLACEHOLDER.match(v))


def deb_upstream(v):
    """1:1.2.1+dfsg-3ubuntu1 → 1.2.1。去掉 epoch、最後一個 - 之後的 Debian revision、+dfsg／+ds／+repack。"""
    v = str(v or "").strip()
    if re.match(r"^\d+:", v):
        v = v.split(":", 1)[1]
    if "-" in v:
        v = v.rpartition("-")[0]
    return DEB_NOISE.sub("", v)


SAFE_UP = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?$")


def safe_upstream(up):
    """上游版本 → (版本, None)；不能安全對應成 PEP 440 的版本（含 +really、~、+git…）或本身是佔位值 → (None, 原因)。"""
    if not up or not SAFE_UP.match(up):
        return None, f"dpkg upstream version {up!r} cannot be safely mapped to a Python version (+really, ~, +git… or not plain digits)"
    if is_placeholder(up):
        return None, f"dpkg upstream version {up!r} is itself a placeholder"
    return up, None


def same_version(a, b):
    trim = lambda x: re.sub(r"(?:\.0)+$", "", x.strip().lower())    # noqa: E731
    return trim(a) == trim(b)


def norm(n):
    return re.sub(r"[-_.]+", "-", str(n or "")).lower()


def header(text, key):
    m = re.search(rf"^{key}:[ \t]*(.*)$", text, re.M | re.I)
    return m.group(1).strip() if m else ""


# ---------- 讀 dpkg 資料 ----------

def parse_status(text):
    """dpkg status → {套件: {版本集合}}（只收已安裝：Status 的最後一個字是 installed）。"""
    out = {}
    for para in re.split(r"\n\s*\n", text or ""):
        f = {}
        for line in para.splitlines():
            if line[:1] in " \t" or ":" not in line:
                continue
            k, _, v = line.partition(":")
            f[k.strip().lower()] = v.strip()
        st = f.get("status", "").split()
        if f.get("package") and f.get("version") and (not st or st[-1] == "installed"):
            out.setdefault(f["package"], set()).add(f["version"])
    return out


def parse_owners(text):
    """dpkg-file-owners（pkg<TAB>path 每行）→ {path: {套件}}；#partial 開頭表示不完整。"""
    out, partial = {}, False
    for line in (text or "").splitlines():
        if line.startswith("#partial"):
            partial = True
        pkg, tab, path = line.partition("\t")
        if tab and path.startswith("/"):
            out.setdefault(path, set()).add(pkg)
    return out, partial


def owners_of(owners, rel):
    """rel（無前導 / 的映像路徑）→ 擁有它的套件集合；/usr 合併的兩種寫法都試。"""
    cands = {"/" + rel}
    cands.add("/" + rel[4:] if rel.startswith("usr/") else "/usr/" + rel)
    got = set()
    for c in cands:
        got |= owners.get(c, set())
    return got


# ---------- 從映像收集 ----------

def flash_package():
    spec = importlib.util.spec_from_file_location("sca_center_flash_package", ROOT / "tools" / "demo" / "flash_package.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _decode(b):
    return b.decode("utf-8", "replace")


def collect_tar(fp, src, prefix):
    """→ (metas, inits, notes)。metas：{metadata 檔的相對路徑: 文字}；inits：{__init__.py 的資料夾相對路徑: __version__ 或 None}。"""
    metas, inits, notes = {}, {}, []
    pre = "/".join(prefix) + "/" if prefix else ""
    seen = 0
    with fp.open_stream(src) as t:
        for e in fp.tar_entries(t):
            n = e.name
            if not n.startswith(pre):
                continue
            rel = n[len(pre):]
            m = META_RE.match(rel)
            i = INIT_RE.match(rel) if not m else None
            if not (m or i):
                continue
            seen += 1
            if seen > MAX_ENTRIES:
                notes.append(f"超過 {MAX_ENTRIES} 個相關成員，後面的沒有收")
                break
            if e.kind != "file":
                if m and e.kind not in ("dir",):
                    notes.append(f"{rel} 是 {e.kind}（不讀）")
                continue
            if m:
                if e.size > MAX_META:
                    notes.append(f"{rel} 超過 {MAX_META} bytes（不讀）")
                    continue
                with contextlib.closing(e.open()) as f:
                    metas[rel] = _decode(f.read(MAX_META))
            elif i:
                with contextlib.closing(e.open()) as f:
                    mm = VER_LINE.search(_decode(f.read(MAX_INIT)))
                inits[rel.rsplit("/", 1)[0]] = mm.group(1) if mm else None
    return metas, inits, notes


def collect_dir(fp, src, prefix):
    metas, inits, notes = {}, {}, []
    base = os.path.join(src, *prefix) if prefix else src
    for pyd in ("usr/lib", "lib"):
        lib = os.path.join(base, *pyd.split("/"))
        try:
            subs = sorted(os.listdir(lib))
        except OSError:
            continue
        if pyd == "lib" and os.path.islink(os.path.join(base, "lib")):
            continue                         # lib → usr/lib：已經讀過
        for sub in subs:
            if not re.match(r"^python3(?:\.\d+)?$", sub):
                continue
            dp = os.path.join(lib, sub, "dist-packages")
            if os.path.islink(dp) or not os.path.isdir(dp):
                continue
            relbase = f"{pyd}/{sub}/dist-packages"
            for name in sorted(os.listdir(dp)):
                p = os.path.join(dp, name)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                mt = re.match(r"^(.+)\.(egg-info|dist-info)$", name)
                targets = []
                if mt and stat.S_ISREG(st.st_mode) and mt.group(2) == "egg-info":
                    targets = [(p, f"{relbase}/{name}", "meta")]
                elif mt and stat.S_ISDIR(st.st_mode):
                    f = "PKG-INFO" if mt.group(2) == "egg-info" else "METADATA"
                    targets = [(os.path.join(p, f), f"{relbase}/{name}/{f}", "meta")]
                elif stat.S_ISDIR(st.st_mode):
                    targets = [(os.path.join(p, "__init__.py"), f"{relbase}/{name}", "init")]
                for tp, rel, kind in targets:
                    try:
                        with fp.open_nofollow(tp) as f:
                            data = f.read(MAX_META if kind == "meta" else MAX_INIT)
                    except OSError:
                        continue
                    if kind == "meta":
                        metas[rel] = _decode(data)
                    else:
                        mm = VER_LINE.search(_decode(data))
                        inits[rel] = mm.group(1) if mm else None
    return metas, inits, notes


# ---------- 判定 ----------

def resolve(metas, inits, status, owners, owners_partial=False):
    """純函式。回傳 [entry]（只含版本是佔位值的 metadata；另回傳總數在 scan() 的 summary）。"""
    out = []
    for rel in sorted(metas):
        m = META_RE.match(rel)
        text = metas[rel]
        name = header(text, "Name") or re.sub(r"-[0-9][^/]*$", "", m.group(1))
        ver = header(text, "Version")
        if not is_placeholder(ver):
            continue
        d = rel.rsplit("/", 1)[0] if m.group(3) else None
        base = re.match(rf"^({DP})/", rel).group(1)
        mod = None
        for cand in (name, name.replace("-", "_"), name.lower(), name.lower().replace("-", "_")):
            if f"{base}/{cand}" in inits:
                mod = f"{base}/{cand}"
                break
        init_ver = inits.get(mod) if mod else None
        e = {"name": name, "path": "/" + rel, "original_version": ver or None, "state": None, "version": None,
             "dpkg": None, "init_version": init_ver, "reason": None}
        if not status or not owners:
            e["state"], e["reason"] = "NO_OWNER_DATA", "no dpkg-status or dpkg-file-owners to read the owner from"
            out.append(e)
            continue
        own = owners_of(owners, rel) or (owners_of(owners, d) if d else set())
        if len(own) != 1:
            e["state"] = "NOT_OWNED"
            e["reason"] = ("more than one dpkg package lists this file: " + ", ".join(sorted(own))) if own else \
                          ("no dpkg package lists this file" + (" (file-owner list is partial)" if owners_partial else ""))
            out.append(e)
            continue
        pkg = next(iter(own))
        vers = status.get(pkg) or set()
        if len(vers) != 1:
            e["state"], e["reason"] = "NOT_OWNED", f"dpkg package {pkg} has {len(vers)} installed versions in dpkg status"
            out.append(e)
            continue
        dv = next(iter(vers))
        up = deb_upstream(dv)
        e["dpkg"] = {"name": pkg, "version": dv, "upstream": up}
        safe, why = safe_upstream(up)
        if safe is None:
            e["state"], e["reason"] = "UNSURE", f"{pkg} {dv}: {why}; version stays unknown"
        elif init_ver and not same_version(up, init_ver):
            e["state"] = "DISAGREE"
            e["reason"] = f"dpkg {pkg} {dv} (upstream {up}) and __version__ {init_ver} differ; version stays unknown"
        else:
            e["state"], e["version"] = "RESOLVED", up
            e["reason"] = f"dpkg:{pkg} {dv}" + (f"; __version__ {init_ver} agrees" if init_ver else "; no __version__ to cross-check")
        out.append(e)
    return out


def scan(src, prefix, pkgdb, out):
    fp = flash_package()
    pp = ()
    if prefix:
        pp = tuple(fp.split_name(prefix) or ())
        if not pp:
            raise Fail(f"--prefix 不合法：{prefix}")
    if os.path.isdir(src):
        metas, inits, notes = collect_dir(fp, src, pp)
    elif os.path.isfile(src):
        try:
            metas, inits, notes = collect_tar(fp, src, pp)
        except fp.Fail as e:
            raise Fail(str(e))
    else:
        raise Fail(f"--from 不是檔案也不是資料夾：{src}")
    pkgdb = Path(pkgdb)

    def rd(n):
        try:
            return (pkgdb / n).read_text(encoding="utf-8", errors="replace") if (pkgdb / n).is_file() and not (pkgdb / n).is_symlink() else ""
        except OSError:
            return ""
    status, (owners, partial) = parse_status(rd("dpkg-status")), parse_owners(rd("dpkg-file-owners"))
    comps = resolve(metas, inits, status, owners, partial)
    counts = {"metadata_files": len(metas), "placeholder": len(comps)}
    for s in ("RESOLVED", "DISAGREE", "UNSURE", "NOT_OWNED", "NO_OWNER_DATA"):
        counts[s.lower()] = sum(1 for c in comps if c["state"] == s)
    doc = {"schema": SCHEMA, "counts": counts, "notes": notes, "components": comps}
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    return doc


def load(path):
    """python-versions.json → doc；沒有或格式不對 → None。"""
    try:
        p = Path(path)
        if not p.is_file() or p.is_symlink():
            return None
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) and d.get("schema") == SCHEMA and isinstance(d.get("components"), list) else None


def by_path(doc):
    """{metadata 檔路徑（有前導 /）: entry}"""
    return {c["path"]: c for c in (doc or {}).get("components") or [] if isinstance(c, dict) and isinstance(c.get("path"), str)}


# ---------- 寫進 SBOM 副本 ----------

def _props(c):
    return c.setdefault("properties", [])


def flat_components(bom):
    out, stack = [], list(bom.get("components") or [])
    while stack:
        c = stack.pop()
        if isinstance(c, dict):
            out.append(c)
            stack.extend(c.get("components") or [])
    return out


def with_version(ref, old, new):
    """purl／bom-ref 裡的 @old → @new；old 是空的（沒有 @版本）時，把 @new 插在 ?、# 之前。已經是別的版本的不動。"""
    if not isinstance(ref, str):
        return ref
    if old:
        return re.sub(rf"@{re.escape(old)}(?=[?#]|$)", lambda m: "@" + new, ref, count=1)
    m = re.search(r"[?#]", ref)
    k = m.start() if m else len(ref)
    return ref if "@" in ref[:k] else ref[:k] + "@" + new + ref[k:]


def purl_pairs(bom):
    """已改過版本的 SBOM 副本 → [(原始 purl, 改過的 purl)]（用 sca:original-version 屬性；沒有改過的元件不收）。
    dt_writeback 用它把產品 SBOM／VEX 的原始 purl 對到 DT 收到的改過 purl。"""
    out = []
    for c in flat_components(bom):
        pr = {p.get("name"): p.get("value") for p in c.get("properties") or [] if isinstance(p, dict)}
        if "sca:original-version" in pr and isinstance(c.get("purl"), str) and c.get("version"):
            old = pr["sca:original-version"] or ""
            o = with_version(c["purl"], c["version"], old) if old else re.sub(r"@[^?#]*", "", c["purl"], count=1)
            if o != c["purl"]:
                out.append((o, c["purl"]))
    return out


def patch_sbom(bom, doc):
    """bom（dict）原地修改：回傳 {state: 數量}。以元件的 syft:location:N:path 對 metadata 檔路徑。
    RESOLVED 的元件：版本、purl、bom-ref、cpe 換成新版本，dependencies[].ref／dependsOn（與 compositions 的參照）跟著換，
    不留指向舊 bom-ref 的懸空參照。"""
    idx, counts, refmap = by_path(doc), {}, {}
    stack = list(bom.get("components") or [])
    while stack:
        c = stack.pop()
        if not isinstance(c, dict):
            continue
        stack.extend(c.get("components") or [])
        purl = c.get("purl")
        if not (isinstance(purl, str) and purl.startswith("pkg:pypi/")):
            continue
        locs = [p.get("value") for p in c.get("properties") or []
                if isinstance(p, dict) and re.match(r"^syft:location:\d+:path$", str(p.get("name"))) and isinstance(p.get("value"), str)]
        hit = next((idx[x] for x in locs if x in idx), None)
        if hit is None:
            continue
        counts[hit["state"]] = counts.get(hit["state"], 0) + 1
        if hit["state"] != "RESOLVED":
            _props(c).append({"name": "sca:version-resolution", "value": f"{hit['state']}: {hit['reason']}"})
            continue
        old, new = c.get("version") or "", hit["version"]
        oldref = c.get("bom-ref")
        c["purl"] = with_version(c["purl"], old, new)
        if isinstance(oldref, str):
            c["bom-ref"] = with_version(oldref, old, new)
            if c["bom-ref"] != oldref:
                refmap[oldref] = c["bom-ref"]
        if isinstance(c.get("cpe"), str) and old:
            c["cpe"] = c["cpe"].replace(f":{old}:", f":{new}:")
        c["version"] = new
        pr = _props(c)
        pr[:] = [p for p in pr if not (isinstance(p, dict) and p.get("name") == "syft:cpe23" and old and f":{old}:" in str(p.get("value")))]
        src = hit["reason"].split(";")[0]
        pr += [{"name": "sca:version-source", "value": src + ("" if hit.get("init_version") else " (presumed to be the module version; no __version__ to cross-check)")},
               {"name": "sca:original-version", "value": old},
               {"name": "sca:version-resolution", "value": f"RESOLVED: {hit['reason']}"}]
    if refmap:
        for d in bom.get("dependencies") or []:
            if isinstance(d, dict):
                d["ref"] = refmap.get(d.get("ref"), d.get("ref"))
                if isinstance(d.get("dependsOn"), list):
                    d["dependsOn"] = [refmap.get(x, x) for x in d["dependsOn"]]
        for comp in bom.get("compositions") or []:
            if isinstance(comp, dict):
                for k in ("assemblies", "dependencies"):
                    if isinstance(comp.get(k), list):
                        comp[k] = [refmap.get(x, x) for x in comp[k]]
    return counts


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("scan")
    a.add_argument("--from", dest="from_", required=True)
    a.add_argument("--prefix")
    a.add_argument("--pkgdb", required=True)
    a.add_argument("--out")
    b = sub.add_parser("apply")
    b.add_argument("--sbom", required=True)
    b.add_argument("--resolved", required=True)
    b.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "scan":
            doc = scan(a.from_, a.prefix, a.pkgdb, a.out or os.path.join(a.pkgdb, "python-versions.json"))
            c = doc["counts"]
            nd = c["metadata_files"]
            st = "GAP" if c["no_owner_data"] or not nd else "ATTENTION" if c["disagree"] or c["unsure"] or c["not_owned"] else "OK"
            print(f"PYVER\t{st}\tPython metadata {nd}; placeholder version {c['placeholder']}; resolved {c['resolved']}, "
                  f"disagree {c['disagree']}, unsure {c['unsure']}, not owned {c['not_owned']}, no owner data {c['no_owner_data']}")
            return 0
        bom = json.load(open(a.sbom, encoding="utf-8-sig"))
        doc = load(a.resolved)
        if doc is None:
            raise Fail(f"--resolved 不是 {SCHEMA}：{a.resolved}")
        n = patch_sbom(bom, doc)
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(bom, f, ensure_ascii=False, indent=1)
        left = [c for c in flat_components(bom) if isinstance(c.get("purl"), str) and c["purl"].startswith("pkg:pypi/")
                and is_placeholder(c.get("version"))]
        done = n.get("RESOLVED", 0)
        # 版本被換掉的元件：OK；還剩佔位值版本的 pypi 元件（不一致、沒有擁有者、不在 python-versions.json）→ GAP（版本仍然未知，規則 13）
        st = "GAP" if left else "OK"
        print(f"PYVER-APPLY\t{st}\tresolved {done} component(s) in the SBOM copy; {len(left)} Python component(s) still have a placeholder version "
              f"({', '.join(sorted(c.get('name') or '?' for c in left)[:10])}); states {json.dumps(n, sort_keys=True)}")
        return 0
    except (Fail, OSError, ValueError) as e:
        print(f"py_dpkg_version.py：{e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
