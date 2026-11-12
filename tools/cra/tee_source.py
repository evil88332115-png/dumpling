#!/usr/bin/env python3
"""Jetson 刷機包的 tos-optee_<soc>.img（OP-TEE 加 TF-A）：從廠商公開原始碼讀版本，並與刷機包裡的映像做一致性對照。只讀、不執行任何東西。

用法（python3 -I）：
  python3 -I tee_source.py --tree <廠商公開原始碼資料夾> --out <輸出資料夾>
        [--inventory <flash-inventory.json> (--archive <tbz2> | --dir <刷機包資料夾>)]
  讀（唯讀，走訪深度、項目數、檔案大小都有上限；不跟隨符號連結）：
    TF-A       arm-trusted-firmware*/Makefile 的 VERSION_MAJOR／VERSION_MINOR／VERSION_PATCH
    OP-TEE     optee_os/mk/config.mk 的 CFG_OPTEE_REVISION_MAJOR／MINOR／EXTRA
    Mbed TLS   optee_os/lib/libmbedtls/mbedtls/include/mbedtls/build_info.h 的 MBEDTLS_VERSION_STRING（並與 MAJOR／MINOR／PATCH 互相核對）
    Hafnium、SPE FreeRTOS  只在原始碼樹裡有它們的資料夾時才列；版本只看它們自己的版本檔（Hafnium 的 VERSION；FreeRTOS 的
               Source/include/task.h tskKERNEL_VERSION_NUMBER），讀不到就是版本未知。
    建置設定事實（證據，不用來判斷受不受影響）：optee_os/core/arch/arm/plat-tegra/conf.mk 與 mk/config.mk 的
               CFG_CORE_MBEDTLS_MPI、CFG_TA_MBEDTLS、CFG_CRYPTOLIB_NAME。
  版本互相矛盾或讀不到 → 版本未知 → GAP、不給 CPE（不猜）。
  給了 --inventory 與刷機包：讀清點裡每個 tos-optee_<soc>.img（用 bootloader_coverage.py 的串流讀取，單檔上限，不解開到磁碟），
  在映像裡找 OP-TEE 與 TF-A 的版本字串，每個映像一個結果：consistent／different／not assessed
  （與用這份原始碼建置一致，不是逐位元相同的比對；用語同 uefi-binary-check）。
輸出（<out>/）：tee-source.cdx.json（元件：OP-TEE、TF-A、Mbed TLS，版本確定時才有 CPE）、tee-source.json（狀態、GAP、證據）。
stdout 一行 `B-tee-source<TAB>OK|ATTENTION|GAP|FAIL<TAB>說明`。退出碼：OK 0；ATTENTION／GAP 2；FAIL 1；參數錯誤 64。
Grype 比對與 CRA 報告的列在 tee_bundled.py。
"""
import argparse
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
SCHEMA = "sca-center-tee-source/1"
CDX, REPORT = "tee-source.cdx.json", "tee-source.json"
MAX_FILE = 1 << 20
MAX_ENTRIES = 200000
MAX_DEPTH = 5
EXTRA_RE = re.compile(r"^[-+.][A-Za-z0-9.+-]*$")
VER_RE = re.compile(r"^\d+\.\d+\.\d+$")
VER2_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")
IMG_RE = re.compile(r"^tos-optee_[a-z0-9]+\.img$")
WORDING = "consistent with being built from this source version (not a bit-for-bit comparison)"
CONF_KEYS = ("CFG_CORE_MBEDTLS_MPI", "CFG_TA_MBEDTLS", "CFG_CRYPTOLIB_NAME")
CPE = {"optee": ["cpe:2.3:a:linaro:op-tee:{v}:*:*:*:*:*:*:*"],
       "tfa": ["cpe:2.3:a:trustedfirmware:trusted_firmware-a:{v}:*:*:*:*:*:*:*"],
       "mbedtls": ["cpe:2.3:a:arm:mbed_tls:{v}:*:*:*:*:*:*:*"]}      # trustedfirmware:mbed_tls 的別名由 tee_bundled 加（同 uefi_bundled）
PURL = {"optee": "op-tee", "tfa": "trusted-firmware-a", "mbedtls": "mbedtls", "hafnium": "hafnium", "freertos": "freertos"}
NAME = {"optee": "OP-TEE", "tfa": "TF-A", "mbedtls": "Mbed TLS", "hafnium": "Hafnium", "freertos": "FreeRTOS"}


class Fail(Exception):
    pass


def _bootmod():
    p = HERE / "bootloader_coverage.py"
    try:
        spec = importlib.util.spec_from_file_location("sca_center_bootloader_coverage_tee", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    except Exception as e:      # noqa: BLE001
        raise Fail(f"cannot load {p.name} ({type(e).__name__})")
    return m


def read_text(path):
    """一般檔案（不跟隨符號連結）→ 文字（最多 MAX_FILE）；讀不到 → None。"""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb", closefd=False) as f:
            return f.read(MAX_FILE).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def find_dirs(tree):
    """走訪樹（深度、項目數有上限；不跟隨符號連結）→ {種類: [資料夾]}。"""
    found = {"tfa": [], "optee_os": [], "hafnium": [], "freertos": []}
    n = 0
    stack = [(Path(tree), 0)]
    truncated = False
    while stack:
        d, depth = stack.pop()
        try:
            with os.scandir(d) as it:
                ents = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for e in ents:
            n += 1
            if n > MAX_ENTRIES:
                truncated = True
                stack = []
                break
            try:
                if e.is_symlink() or not e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            low = e.name.lower()
            if low.startswith("arm-trusted-firmware"):
                found["tfa"].append(Path(e.path))
            elif low == "optee_os":
                found["optee_os"].append(Path(e.path))
            elif low.startswith("hafnium"):
                found["hafnium"].append(Path(e.path))
            elif "freertos" in low:
                found["freertos"].append(Path(e.path))
            if depth + 1 < MAX_DEPTH:
                stack.append((Path(e.path), depth + 1))
    return found, truncated


def _defs(text, names, rx):
    out = {}
    for m in re.finditer(rx, text, re.M):
        if m.group(1) in names:
            out.setdefault(m.group(1), []).append(m.group(2).strip())
    return out


TFA_NO_PATCH_NOTE = ("Makefile 沒有 VERSION_PATCH（TF-A 2.8 以前的寫法），版本記為 {mm}。LTS 修補層級未知：弱點比對把 {mm} 當 {mm}.0，"
                     "結果可能包含較晚的 {mm}.x LTS 版已修的問題；不因此判定任何項目不受影響")


def read_tfa(d):
    """→ (版本 或 None, 依據, 原因)。"""
    t = read_text(d / "Makefile")
    if t is None:
        return None, None, f"{d.name}/Makefile not readable"
    v = _defs(t, {"VERSION_MAJOR", "VERSION_MINOR", "VERSION_PATCH"}, r"^(VERSION_(?:MAJOR|MINOR|PATCH))\s*:?=\s*([^\s#]*)")
    parts = []
    for k in ("VERSION_MAJOR", "VERSION_MINOR", "VERSION_PATCH"):
        vals = set(v.get(k, []))
        if k == "VERSION_PATCH" and not vals and len(parts) == 2:
            # 只是沒有 PATCH（TF-A 2.8 以前的寫法），不是矛盾：版本記為 MAJOR.MINOR
            mm = ".".join(parts)
            return mm, f"{d.name}/Makefile VERSION_MAJOR/MINOR; " + TFA_NO_PATCH_NOTE.format(mm=mm), None
        if len(vals) != 1 or not next(iter(vals)).isdigit():
            return None, None, f"{d.name}/Makefile: {k} missing, repeated with different values or not a number"
        parts.append(next(iter(vals)))
    return ".".join(parts), f"{d.name}/Makefile VERSION_MAJOR/MINOR/PATCH", None


def read_optee(d):
    t = read_text(d / "mk" / "config.mk")
    if t is None:
        return None, None, "optee_os/mk/config.mk not readable", {}, ""
    v = _defs(t, {"CFG_OPTEE_REVISION_MAJOR", "CFG_OPTEE_REVISION_MINOR", "CFG_OPTEE_REVISION_EXTRA"},
              r"^(CFG_OPTEE_REVISION_(?:MAJOR|MINOR|EXTRA))\s*[?:]?=([^\n#]*)")
    mm = []
    for k in ("CFG_OPTEE_REVISION_MAJOR", "CFG_OPTEE_REVISION_MINOR"):
        vals = set(v.get(k, []))
        if len(vals) != 1 or not next(iter(vals)).isdigit():
            return None, None, f"optee_os/mk/config.mk: {k} missing, repeated with different values or not a number", {}, ""
        mm.append(next(iter(vals)))
    extra = {x.strip() for x in v.get("CFG_OPTEE_REVISION_EXTRA", [""])}
    if len(extra) != 1:
        return None, None, "optee_os/mk/config.mk: CFG_OPTEE_REVISION_EXTRA given with different values", {}, ""
    ex = next(iter(extra))
    if ex and not EXTRA_RE.match(ex):
        return None, None, ("optee_os/mk/config.mk: CFG_OPTEE_REVISION_EXTRA is not a plain suffix (quoted text or a make expression), "
                            "so the revision is not a fixed string"), {}, ""
    # 版本只用 MAJOR.MINOR；EXTRA 不為空（例如 -dev）時不把它當成已發行的版本，另外記 ATTENTION
    return ".".join(mm), "optee_os/mk/config.mk CFG_OPTEE_REVISION_MAJOR/MINOR", None, read_conf(d), ex


class _Pair:
    def __init__(self, k, v):
        self._p = (k, v)

    def group(self, i):
        return self._p[i - 1]


def read_conf(d):
    """OP-TEE 建置設定事實：先看 plat-tegra/conf.mk（平台設定），再看 mk/config.mk（預設值）。只記錄，不判斷。"""
    facts = {}
    for key in CONF_KEYS:
        facts[key] = {"value": None, "source": None, "line": None}
    for rel in ("core/arch/arm/plat-tegra/conf.mk", "mk/config.mk"):
        t = read_text(d / rel)
        if t is None:
            continue
        for i, ln in enumerate(t.splitlines(), 1):
            s = ln.strip()
            if s.startswith("#"):
                continue
            m = re.match(r"^\$\(call\s+force\s*,\s*(CFG_[A-Z0-9_]+)\s*,\s*([^)\s]*)\s*\)", s)
            op = "force"
            if not m:
                m = re.match(r"^(CFG_[A-Z0-9_]+)\s*([?:]?=)\s*([^#]*)", s)
                if m:
                    op = m.group(2)
                    m = _Pair(m.group(1), m.group(3))
            if m and m.group(1) in facts and facts[m.group(1)]["value"] is None:
                facts[m.group(1)] = {"value": m.group(2).strip(), "source": f"optee_os/{rel}", "line": i, "operator": op}
    return facts


def read_mbedtls(d):
    p = d / "lib" / "libmbedtls" / "mbedtls" / "include" / "mbedtls" / "build_info.h"
    t = read_text(p)
    if t is None:
        return None, None, "optee_os/lib/libmbedtls/mbedtls/include/mbedtls/build_info.h not readable (submodule not checked out?)"
    s = set(re.findall(r'^\s*#\s*define\s+MBEDTLS_VERSION_STRING\s+"([^"]*)"', t, re.M))
    parts = []
    for k in ("MAJOR", "MINOR", "PATCH"):
        vals = set(re.findall(rf"^\s*#\s*define\s+MBEDTLS_VERSION_{k}\s+(\d+)\b", t, re.M))
        parts.append(vals)
    if len(s) != 1 or not VER_RE.match(next(iter(s))):
        return None, None, "build_info.h: MBEDTLS_VERSION_STRING missing, repeated with different values or not x.y.z"
    v = next(iter(s))
    if any(len(p_) != 1 for p_ in parts) or ".".join(next(iter(p_)) for p_ in parts) != v:
        return None, None, "build_info.h: MBEDTLS_VERSION_STRING and MBEDTLS_VERSION_MAJOR/MINOR/PATCH conflict or are missing"
    return v, "optee_os/lib/libmbedtls/.../build_info.h MBEDTLS_VERSION_STRING", None


def read_hafnium(d):
    t = read_text(d / "VERSION")
    if t is None:
        return None, None, f"{d.name}: no VERSION file (version is taken from its own version file only)"
    v = t.strip().splitlines()[0].strip() if t.strip() else ""
    return (v, f"{d.name}/VERSION", None) if VER2_RE.match(v) else (None, None, f"{d.name}/VERSION: not a version number")


def read_freertos(d):
    for p in [d / "Source" / "include" / "task.h", *sorted(d.glob("*/Source/include/task.h"))[:3], *sorted(d.glob("*/*/Source/include/task.h"))[:3]]:
        t = read_text(p)
        if t is None:
            continue
        vs = set(re.findall(r'^\s*#\s*define\s+tskKERNEL_VERSION_NUMBER\s+"V?([0-9][0-9.]*)"', t, re.M))
        if len(vs) == 1 and VER2_RE.match(next(iter(vs))):
            return next(iter(vs)), f"{d.name}/.../task.h tskKERNEL_VERSION_NUMBER", None
        if vs:
            return None, None, f"{d.name}: tskKERNEL_VERSION_NUMBER conflicting or not a version number"
    return None, None, f"{d.name}: no task.h with tskKERNEL_VERSION_NUMBER (version is taken from its own version file only)"


def resolve(cands):
    """同一種元件可能有幾份資料夾：版本都相同才算確定；不同 → 矛盾；全讀不到 → 未知。→ (版本, 依據, [GAP 原因])。"""
    vs = {c[0] for c in cands if c[0]}
    reasons = [c[2] for c in cands if c[2]]
    if len(vs) == 1:
        return next(iter(vs)), next(c[1] for c in cands if c[0]), reasons
    if len(vs) > 1:
        return None, None, [f"conflicting versions in the tree: {', '.join(sorted(vs))}"] + reasons
    return None, None, reasons


# ---------------------------------------------------------------- 映像對照

OPTEE_RE = re.compile(rb"(?<![\w.])(\d+\.\d+(?:\.\d+)?(?:[-+][\w.+-]*)?) \(gcc version")
OPTEE_LIT_RE = re.compile(rb"OP-TEE version: (?!%s)([0-9][\w.+-]*)")
TFA_RE = re.compile(rb"v(\d+\.\d+(?:\.\d+)?)(?:-[\w.+-]*)?\((?:release|debug)\)")


def _same(found, want):
    return found == want or found.startswith((want + ".", want + "-"))


def check_image(data, optee_v, tfa_v, truncated=False, tfa_note=None):
    """映像內容 → {result, detail, optee, tfa}。result：MATCH／MISMATCH／NOT_ASSESSED（用語：與這份原始碼一致，不是逐位元相同）。"""
    res = {}
    ov = sorted({m.group(1).decode() for m in OPTEE_RE.finditer(data)} | {m.group(1).decode() for m in OPTEE_LIT_RE.finditer(data)})
    tv = sorted({m.group(1).decode() for m in TFA_RE.finditer(data)})
    for key, found, want in (("optee", ov, optee_v), ("tfa", tv, tfa_v)):
        if not want:
            r, why = "NOT_ASSESSED", "source version unknown"
        elif key == "tfa" and tfa_note:
            r, why = "NOT_ASSESSED", tfa_note
        elif not found:
            r, why = "NOT_ASSESSED", "no version string found in the image"
        elif any(_same(f, want) for f in found):
            r, why = "MATCH", None
        elif any(f.endswith(want) and f[:-len(want)].rstrip("-").isdecimal() for f in found):
            r, why = "NOT_ASSESSED", f"found {found[0]}: the leading character may be a binary byte in front of {want}; boundary not certain"
        else:
            r, why = "MISMATCH", None
        res[key] = {"source_version": want, "found_in_image": found[:5], "result": r, **({"why": why} if why else {})}
    rs = [res["optee"]["result"], res["tfa"]["result"]]
    overall = "MISMATCH" if "MISMATCH" in rs else "MATCH" if rs == ["MATCH", "MATCH"] else "NOT_ASSESSED"
    det = "; ".join(f"{NAME[k]}: {res[k]['result']}" + (f" ({res[k]['why']})" if res[k].get("why") else "") for k in ("optee", "tfa"))
    return {"result": overall, "detail": det + ("; only the first part of the image was searched" if truncated else ""),
            **res, "wording": WORDING}


def check_images(inv, archive, directory, optee_v, tfa_v, tfa_socs=()):
    items = [x for x in (inv.get("bootloader") or []) if isinstance(x, dict) and x.get("type") == "file"
             and IMG_RE.match(str(x.get("path", "")).rsplit("/", 1)[-1].lower())]
    out = []
    if not items:
        return out, "the flash package inventory lists no tos-optee_<soc>.img"
    bm = _bootmod()
    try:
        imgs = bm.read_images(items, archive, directory)
    except Exception as e:      # noqa: BLE001
        return [{"path": x["path"], "sha256": x.get("sha256"), "result": "NOT_ASSESSED", "detail": f"cannot be read ({type(e).__name__})"}
                for x in items], None
    for x in items:
        data, trunc, why = imgs[x["path"]]
        r = {"path": x["path"], "sha256": x.get("sha256")}
        soc = re.match(r"tos-optee_([a-z0-9]+)\.img$", str(x["path"]).rsplit("/", 1)[-1].lower())
        note = (f"the TF-A source tree is for {'/'.join(sorted(tfa_socs))}, this image is {soc.group(1)}"
                if tfa_socs and soc and soc.group(1) not in tfa_socs else None)
        r.update({"result": "NOT_ASSESSED", "detail": why} if data is None else check_image(data, optee_v, tfa_v, trunc, note))
        out.append(r)
    return out, None


# ---------------------------------------------------------------- 主流程

def by_kind_version(comps, kind):
    return next((c["version"] for c in comps if c["kind"] == kind), None)


def config_note(facts):
    """OP-TEE 建置設定的事實句（沒有檔名與行號，可進客戶文件）。不判斷受不受影響。"""
    def val(k):
        v = (facts or {}).get(k) or {}
        return v.get("value") if v.get("value") is not None else "unknown"
    return (f"OP-TEE build config: core CFG_CORE_MBEDTLS_MPI={val('CFG_CORE_MBEDTLS_MPI')}; TA library CFG_TA_MBEDTLS={val('CFG_TA_MBEDTLS')}; "
            f"crypto library {val('CFG_CRYPTOLIB_NAME')}; affectedness not assessed")


def prop(n, v):
    return {"name": n, "value": v}


def scan(tree, inv=None, archive=None, directory=None):
    tree = Path(tree)
    found, trunc = find_dirs(tree)
    gaps, att, comps, facts = [], [], [], {}
    if trunc:
        gaps.append(f"the source tree has more than {MAX_ENTRIES} entries; the walk stopped early (NOT_ASSESSED for anything after that)")
    resolved = {}

    def add(kind, cands, parent=None, cpe=True, missing=None):
        if not cands:
            if missing:
                gaps.append(missing)
            return None
        v, basis, reasons = resolve(cands)
        c = {"kind": kind, "name": NAME[kind], "version": v, "basis": basis, "purl": f"pkg:generic/{PURL[kind]}" + (f"@{quote(v, safe='.-_~')}" if v else ""),
             "cpe": None, "reasons": reasons}
        if v and cpe:
            c["cpe"] = CPE[kind][0].format(v=v)
        if not v:
            gaps.append(f"{NAME[kind]}: version unknown, NOT_ASSESSED (no CPE, not matched against vulnerability data): "
                        + ("; ".join(reasons) or "no version file"))
        elif not cpe:
            gaps.append(f"{NAME[kind]} {v}: no CPE defined for it, NOT_ASSESSED (not matched against vulnerability data)")
        elif reasons:
            att.append(f"{NAME[kind]}: other copies could not be read: " + "; ".join(reasons))
        resolved[kind] = v
        comps.append(c)
        return c

    add("tfa", [read_tfa(d) for d in found["tfa"]], missing="TF-A: no arm-trusted-firmware*/Makefile found in the source tree (NOT_ASSESSED)")
    oc = [read_optee(d) for d in found["optee_os"]]
    add("optee", [c[:3] for c in oc], missing="OP-TEE: no optee_os folder found in the source tree (NOT_ASSESSED)")
    for c in oc:
        if c[3]:
            facts = c[3]
            break
    ex = sorted({c[4] for c in oc if len(c) > 4 and c[4]})
    if ex and by_kind_version(comps, "optee"):
        att.append(f"OP-TEE: revision suffix present in CFG_OPTEE_REVISION_EXTRA ({', '.join(ex)}): the version is taken as the base "
                   f"{resolved.get('optee')} only; confirm the build is that release (a suffixed build is not matched as the release)")
    mc = [read_mbedtls(d) for d in found["optee_os"]]
    m = add("mbedtls", mc, missing="Mbed TLS: no optee_os folder (so no bundled Mbed TLS) found in the source tree (NOT_ASSESSED)")
    if m:
        m["parent"] = "optee"
    for kind, rd in (("hafnium", read_hafnium), ("freertos", read_freertos)):
        if found[kind]:
            add(kind, [rd(d) for d in found[kind]], cpe=False)
    if facts:
        for k, f in facts.items():
            if f["value"] is None:
                att.append(f"{k}: not set in plat-tegra/conf.mk or mk/config.mk (unknown, not assumed)")
    rep = {"schema": SCHEMA, "status": "OK", "wording": WORDING, "versions": {k: v for k, v in resolved.items()},
           "components": [{k: c[k] for k in ("kind", "name", "version", "basis", "purl", "cpe")} for c in comps],
           "build_config": {"facts": facts,
                            "note": config_note(facts) + ". Values are read from the source files (platform conf.mk first, then mk/config.mk defaults); "
                                    "a make-command-line override is not visible here."},
           "image_check": {"status": "NOT_RUN", "images": [], "detail": "no flash package given"},
           "gaps": gaps, "attention": att}
    if inv is not None and (archive or directory):
        imgs, why = check_images(inv, archive, directory, resolved.get("optee"), resolved.get("tfa"),
                                  {m.group(1) for d in found["tfa"] for m in [re.search(r"[._-](t\d{3})$", d.name)] if m})
        cnt = {k: sum(1 for i in imgs if i["result"] == k) for k in ("MATCH", "MISMATCH", "NOT_ASSESSED")}
        if why:
            rep["image_check"] = {"status": "GAP", "images": [], "detail": why}
            gaps.append(why + ": the image was not compared with the source")
        else:
            st = "ATTENTION" if cnt["MISMATCH"] else "GAP" if cnt["NOT_ASSESSED"] else "OK"
            rep["image_check"] = {"status": st, "images": imgs, "counts": cnt, "wording": WORDING,
                                  "detail": f"{len(imgs)} tos-optee image(s): consistent with the source version {cnt['MATCH']}, different {cnt['MISMATCH']}, "
                                            f"not assessed {cnt['NOT_ASSESSED']} (consistency, not a bit-for-bit comparison)"}
            if cnt["MISMATCH"]:
                att.append("a flashed tos-optee image is NOT consistent with this source version: the source scan may not describe it")
            if cnt["NOT_ASSESSED"]:
                names = ", ".join(i["path"].rsplit("/", 1)[-1] for i in imgs if i["result"] == "NOT_ASSESSED")
                gaps.append(f"flashed tos-optee image(s) not compared with the source (NOT_ASSESSED): {names} "
                            "(version string not found, source tree for another SoC, or image unreadable; see image_check in tee-source.json)")
    elif inv is not None:
        rep["image_check"]["detail"] = "no --archive/--dir: the images were not compared with the source"
    rep["status"] = "GAP" if gaps else "ATTENTION" if att else "OK"
    return rep, comps


def cyclonedx(comps, rep):
    out, ref = [], {}
    for c in comps:
        r = f"tee-{c['kind']}"
        ref[c["kind"]] = r
        x = {"type": "library" if c["kind"] != "tfa" and c["kind"] != "optee" else "firmware", "bom-ref": r, "name": c["name"], "purl": c["purl"]}
        if c["version"]:
            x["version"] = c["version"]
        if c["cpe"]:
            x["cpe"] = c["cpe"]
        ps = [prop("sca-center:tee:role", c["kind"])]
        if c["basis"]:
            ps.append(prop("sca-center:tee:version-basis", c["basis"]))
        if c["kind"] == "mbedtls":
            ps.append(prop("sca-center:tee:note", config_note(rep["build_config"]["facts"])))
            for k, f in rep["build_config"]["facts"].items():
                if f["value"] is not None:
                    ps.append(prop(f"sca-center:tee:config:{k}", str(f["value"])))
        if c["kind"] in ("optee", "tfa"):
            ps.append(prop("sca-center:tee:coverage", "vulnerability data coverage is limited; 0 matches does not mean no vulnerabilities"))
        if not c["version"]:
            ps.append(prop("sca-center:gap", "version unknown"))
        x["properties"] = ps
        out.append(x)
    deps = [{"ref": r, "dependsOn": [ref["mbedtls"]] if k == "optee" and "mbedtls" in ref else []} for k, r in ref.items()]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": out, "dependencies": deps}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    ap.add_argument("--tree", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--inventory")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--archive")
    g.add_argument("--dir")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    try:
        if not os.path.isdir(a.tree):
            raise Fail("--tree is not a folder")
        inv = None
        if a.inventory:
            try:
                with open(a.inventory, encoding="utf-8") as f:
                    inv = json.load(f)
            except (OSError, ValueError):
                raise Fail("flash-inventory.json is missing or unreadable")
            if not isinstance(inv, dict):
                raise Fail("flash-inventory.json is not an object")
        rep, comps = scan(a.tree, inv, a.archive, a.dir)
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / CDX).write_text(json.dumps(cyclonedx(comps, rep), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        (out / REPORT).write_text(json.dumps(rep, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        vs = ", ".join(f"{NAME[k]} {v or 'unknown'}" for k, v in ((c["kind"], c["version"]) for c in comps))
        print(f"B-tee-source\t{rep['status']}\t{vs or 'no component found'}; image check: {rep['image_check']['detail']}"
              + (f"; GAP: {rep['gaps'][0][:150]}" if rep["gaps"] else ""))
        return 0 if rep["status"] == "OK" else 2
    except Fail as e:
        print(f"B-tee-source\tFAIL\t{e}")
        return 1
    except Exception as e:      # noqa: BLE001
        print(f"B-tee-source\tFAIL\ttee_source.py could not complete ({type(e).__name__}: {str(e)[:100]})")
        return 1


if __name__ == "__main__":
    sys.exit(main())
