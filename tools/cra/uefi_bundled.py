#!/usr/bin/env python3
"""UEFI 內建函式庫（OpenSSL、Mbed TLS…）併進產品 SBOM、用 Grype（離線資料庫）比對，成為 CRA 報告的列。

兩個動作：
  python3 -I uefi_bundled.py grype --dir <uefi-source 的輸出資料夾> [--grype <執行檔>] [--max-age-days N]
      對 <dir>/uefi-source.cdx.json 跑 `grype sbom:…`（離線：GRYPE_DB_AUTO_UPDATE=false、GRYPE_CHECK_FOR_APP_UPDATE=false，
      資料庫在 GRYPE_DB_CACHE_DIR，預設 $HOME/.cache/grype/db，和 sca-scan 相同），寫 <dir>/grype.json 與 <dir>/grype-run.json。
      stdout 一行 `B-uefi-grype<TAB>OK|GAP|NOT_RUN|FAIL<TAB>說明`。退出碼：OK 0、GAP／NOT_RUN 2、FAIL 1。
  （cra_report.py 用 load()、rows_fix()、text()；沒有給資料夾時整個功能不執行，輸出和以前逐位元組相同。）

實測（Grype 0.121.0、v6 資料庫）：pkg:generic 元件**只靠 CPE 比對**（nvd:cpe，matchDetails.type=cpe-match）；
沒有 CPE 就 0 筆；而且比對用的是 CPE 裡的版本，不是元件的 version 欄。所以 load() 要求 CPE 的版本和元件的 version 相同，
不同就丟掉 CPE（元件仍留在 SBOM，標 GAP：不比對）。uefi_source.py 本來就只在版本確定時才給 CPE。

規則（專案規則）：版本未知的函式庫（沒有版本檔、版本檔互相矛盾、submodule 沒取出）不比對、列 GAP／NOT_ASSESSED，不顯示成沒有弱點；
找不到或讀不到 uefi-source 的輸出 → GAP；Grype 沒跑、失敗或資料庫過期 → GAP（比對結果「沒有」不等於安全）。
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

CDX, REPORT, GRYPE_OUT, RUN = "uefi-source.cdx.json", "uefi-source.json", "grype.json", "grype-run.json"
GRYPE_IN, REUSED = "grype-input.cdx.json", "reused.json"
# Grype 只收這些 CPE（vendor:product）：NVD 的 edk2 CPE 範圍沒有上界，會把 2014 年的 CVE 算到 2025 年的 tag（誤報），所以 edk2 不比對
# Mbed TLS 在 Grype 資料庫有兩個 vendor：arm:mbed_tls（舊）與 trustedfirmware:mbed_tls（新，2026 年的 CVE 多在這裡）；兩個都給，Grype 才找得全
# （實測 Mbed TLS 3.6.2：arm 16 筆、trustedfirmware 6 筆、兩個都給 22 筆，沒有重疊）。OpenSSL 在資料庫只有 vendor openssl 是真的 OpenSSL
# （其他 vendor 的 openssl 是 redhat、ruby-lang、sfackler 的包裝），不需要別名
ALLOWED_CPE = {("openssl", "openssl"), ("arm", "mbed_tls"), ("trustedfirmware", "mbed_tls")}
ALT_CPE = {("arm", "mbed_tls"): [("trustedfirmware", "mbed_tls")]}
EDK2_REASON = ("NOT_ASSESSED: edk2 itself is not matched against NVD (its CPE version ranges have no upper bound, so old CVEs would be "
               "reported on current tags); NVIDIA's edk2-nvidia is covered by the NVIDIA security bulletins")
MAX_COMPS, STR_MAX, GAP_MAX = 64, 500, 50
NAMES = {"openssl": "OpenSSL", "mbedtls": "Mbed TLS", "edk2": "edk2"}
SUFFIX = "(bundled in UEFI)"
TIMEOUT = 600


def _s(v, n=STR_MAX):
    return v[:n] if isinstance(v, str) else ""


def _json(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _prop(c, name):
    return [p.get("value") for p in c.get("properties") or [] if isinstance(p, dict) and p.get("name") == name]


def label(name, version, role):
    n = NAMES.get(str(name).lower(), str(name))
    v = f" {version}" if version else ""
    if role == "other-copy":
        return f"{n}{v} (copy in the UEFI source tree)"
    return f"{n}{v} (UEFI firmware)" if role == "uefi" else f"{n}{v} {SUFFIX}"


def _cpe_version(cpe):
    f = cpe.split(":")
    return f[5] if len(f) > 5 and f[:2] == ["cpe", "2.3"] else None


def _cpe_allowed(cpe, version):
    """CPE 2.3 字串剛好 13 欄（cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other）、
    part 是 a、vendor:product 在允許清單、版本等於元件的 version。"""
    f = cpe.split(":") if isinstance(cpe, str) else []
    return bool(version) and len(f) == 13 and f[:3] == ["cpe", "2.3", "a"] and (f[3], f[4]) in ALLOWED_CPE and f[5] == version


def alt_cpes(cpe):
    """主要的 CPE → 同一個函式庫在資料庫裡的別名 vendor 的 CPE。"""
    f = cpe.split(":")
    return [":".join(f[:3] + [v, p] + f[5:]) for v, p in ALT_CPE.get((f[3], f[4]), [])]


def kept_components(cdx):
    """uefi-source.cdx.json 的元件 → (留下的元件, 略過的數量, 超過上限的數量)。load() 與 grype_input() 用同一個規則，
    所以「進 SBOM 的元件」「給 Grype 的元件」「允許的 purl」三者一致（超過上限之後的元件不會被比對到而成為沒有標示的列）。"""
    comps = cdx.get("components") if isinstance(cdx, dict) and isinstance(cdx.get("components"), list) else []
    kept, seen, skipped = [], set(), 0
    for c in comps[:MAX_COMPS]:
        if not isinstance(c, dict) or not _s(c.get("name")) or not _s(c.get("bom-ref")) or c["bom-ref"] in seen:
            skipped += 1
            continue
        seen.add(c["bom-ref"])
        kept.append(c)
    return kept, skipped, max(0, len(comps) - MAX_COMPS)


def grype_input(cdx):
    """uefi-source.cdx.json → (給 Grype 的 SBOM 位元組, 允許的 purl 集合)：只含留下的元件裡 CPE 在允許清單、而且 CPE 的版本等於元件 version 的函式庫
    （edk2、CPE 版本不符、版本不明的都不給 Grype）；Mbed TLS 另帶別名 vendor 的 CPE（syft:cpe23 屬性，Grype 讀 CycloneDX 時一起用）。
    輸出固定（排序、不含時間），sha256 記在 grype-run.json，load() 重算核對。"""
    comps, purls = [], set()
    for c in kept_components(cdx)[0]:
        if not isinstance(c.get("name"), str) or not isinstance(c.get("purl"), str):
            continue
        if _prop(c, "sca-center:uefi:role") == ["uefi"] or not _cpe_allowed(c.get("cpe"), c.get("version")):
            continue
        x = {"type": "library", "bom-ref": str(c.get("bom-ref")), "name": c["name"], "version": c["version"], "purl": c["purl"], "cpe": c["cpe"]}
        alts = alt_cpes(c["cpe"])
        if alts:
            x["properties"] = [{"name": "syft:cpe23", "value": a} for a in alts]
        comps.append(x)
        purls.add(c["purl"])
    comps.sort(key=lambda x: (x["purl"], x["bom-ref"]))
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": comps}
    return (json.dumps(doc, sort_keys=True, indent=1) + "\n").encode(), purls


def dedupe(matches):
    """同一個元件（purl）上同一個弱點編號只留一筆（兩個 CPE 別名可能各比對到一次）。"""
    out, seen = [], set()
    for m in matches:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        k = (v.get("id"), a.get("purl"), a.get("version"))
        if k not in seen:
            seen.add(k)
            out.append(m)
    return out


def load(d):
    """<dir>（uefi-source.py 的輸出＋grype.py 的結果）→ info。永遠回傳 info，不丟例外（輸入是不可信資料）。
    info：status（OK／ATTENTION／GAP）、gaps、attention、comps／deps／top（要併進 SBOM 的）、libs（含 label、known）、
    grype（解析後的 grype.json 或 None）、grype_run、matches。"""
    d = Path(d)
    info = {"status": "OK", "dir": d.name, "source_status": None, "gaps": [], "attention": [], "comps": [], "deps": {}, "top": [],
            "libs": [], "grype": None, "grype_run": None, "matches": None}
    cdx, rep = _json(d / CDX), _json(d / REPORT)
    if not isinstance(cdx, dict) or not isinstance(cdx.get("components"), list):
        info["status"] = "GAP"
        info["gaps"].append(f"`{d.name}/{CDX}` not found or not readable: the libraries bundled in the UEFI are NOT_ASSESSED "
                            "(not in the SBOM, not matched; run uefi_source.py on the UEFI source tree)")
        return info
    try:
        _load(info, cdx, rep, d)
    except Exception as e:      # noqa: BLE001 — 格式怪異時不讓整份 CRA 文件失敗
        info.update(status="GAP", comps=[], deps={}, top=[], libs=[], grype=None)
        info["gaps"] = [f"`{d.name}/{CDX}` could not be processed ({type(e).__name__}): the libraries bundled in the UEFI are NOT_ASSESSED"]
    return info


def _load(info, cdx, rep, d):
    gaps, att = info["gaps"], info["attention"]
    if isinstance(rep, dict):
        info["source_status"] = _s(rep.get("status"), 20)
        gaps += [_s(g) for g in rep.get("gaps") or [] if _s(g)][:GAP_MAX]
        att += [_s(g) for g in rep.get("attention") or [] if _s(g)][:GAP_MAX]
        if info["source_status"] in ("GAP", "FAIL") and not gaps:
            gaps.append(f"uefi_source.py reported {info['source_status']} without giving a reason: treated as GAP")
        elif info["source_status"] == "ATTENTION" and not att:
            att.append("uefi_source.py reported ATTENTION without giving a reason")
    else:
        gaps.append(f"`{d.name}/{REPORT}` not found or not readable: the notes of uefi_source.py (conflicts, empty submodules) are missing")
    ru = _json(d / REUSED)
    if isinstance(ru, dict) and ru.get("reused"):
        info["reused"] = _s(ru.get("original_date"), 40) or "unknown date"
        att.append(f"the UEFI source tree was NOT re-read in this run: the uefi-source output of an earlier run ({info['reused']}) is reused "
                   "(only Grype was run again, with the current database)")
    uefi_ref = None
    kept, skipped, over = kept_components(cdx)
    if over:
        gaps.append(f"{over} component(s) of `{d.name}/{CDX}` are beyond the limit of {MAX_COMPS} and were NOT added "
                    "to the SBOM or matched (NOT_ASSESSED)")
    for c in kept:
        role = (_prop(c, "sca-center:uefi:role") or [""])[0]
        x = {"type": "firmware" if role == "uefi" else "library", "bom-ref": c["bom-ref"], "name": _s(c["name"])}
        ver = _s(c.get("version"), 100)
        if ver:
            x["version"] = ver
        if _s(c.get("purl")).startswith("pkg:generic/"):
            x["purl"] = c["purl"][:STR_MAX]
        cpe = _s(c.get("cpe"))
        if cpe and role == "uefi":
            pass            # edk2 的 CPE 不放進產品 SBOM（下游工具用它比對 NVD 會誤報）；原因記在屬性
        elif cpe:
            if _cpe_allowed(cpe, ver):
                x["cpe"] = cpe
            elif ver and _cpe_version(cpe) == ver:
                gaps.append(f"{x['name']}: the CPE {':'.join(cpe.split(':')[3:5])} is not on the list of CPEs that are matched "
                            "(NOT_ASSESSED); the CPE was dropped")
            else:       # Grype 用 CPE 的版本，不用元件的 version：兩者不同就不給 CPE（不比對，標 GAP）
                gaps.append(f"{x['name']}: the CPE version ({_cpe_version(cpe)}) differs from the component version ({ver or 'none'}); "
                            "the CPE was dropped and the component is not matched")
        x["properties"] = ([{"name": "sca-center:not-assessed", "value": EDK2_REASON}] if role == "uefi" else []) + \
            [{"name": p["name"][:100], "value": _s(p.get("value"))} for p in c.get("properties") or []
             if isinstance(p, dict) and isinstance(p.get("name"), str) and p["name"].startswith("sca-center:")]
        if x.get("cpe"):
            x["properties"] += [{"name": "syft:cpe23", "value": a} for a in alt_cpes(x["cpe"])]
        bi = (_prop(c, "sca-center:built-in") or [""])[0]
        # 「no」不存在（舊輸出可能有）：一律當 unknown，不排除任何列
        bi = "unknown" if bi == "no" else (bi if bi in ("yes", "unknown") else "")
        if role == "edk2-submodule":
            built = {"state": bi or "unknown", "evidence": [_s(e, 400) for e in _prop(c, "sca-center:built-in-evidence")][:8],
                     "reasons": [_s(e, 500) for e in _prop(c, "sca-center:built-in-reason")][:3], "checked": bool(bi)}
            x["properties"].append({"name": "sca-center:built-in", "value": built["state"]})
        else:
            built = None
        info["comps"].append(x)
        if role == "uefi":
            uefi_ref = x["bom-ref"]
            info["top"].append(uefi_ref)
        lab = label(x["name"], ver, role)
        known = bool(ver and x.get("cpe")) and role != "uefi"
        info["libs"].append({"ref": x["bom-ref"], "name": x["name"], "version": ver or None, "purl": x.get("purl", ""), "label": lab,
                             "role": role, "known": known, "built_in": built["state"] if built else None,
                             "built_in_evidence": built["evidence"] if built else [], "built_in_reasons": built["reasons"] if built else [],
                             "built_in_checked": built["checked"] if built else None})
        own = [_s(g) for g in _prop(c, "sca-center:gap") if _s(g)]
        if role != "uefi" and not ver:
            gaps.append(f"{lab.replace(' ' + SUFFIX, '')} ({_s(_prop(c, 'sca-center:uefi:path')[0] if _prop(c, 'sca-center:uefi:path') else '?', 200)}): "
                        "version unknown, NOT_ASSESSED (not matched against vulnerability data)" + (f": {'; '.join(own)}" if own else ""))
        elif role != "uefi" and not known:
            gaps.append(f"{lab}: no usable CPE, NOT_ASSESSED (Grype matches generic components only through the CPE)")
        elif role == "uefi":
            att.append(f"{x['name']}{' ' + ver if ver else ''}: {EDK2_REASON}")
    unchecked = [l for l in info["libs"] if l["built_in"] == "unknown" and not l["built_in_checked"]]
    unclear = [l for l in info["libs"] if l["built_in"] == "unknown" and l["built_in_checked"]]
    if unchecked:
        att.append("whether " + " and ".join(NAMES.get(l["name"].lower(), l["name"]) for l in unchecked) + (" are" if len(unchecked) > 1 else " is") + " built into the firmware was NOT checked "
                   "(built-in: unknown; no platform DSC was given or found: uefi_source.py --platform-dsc); the findings are listed as if it were built in")
    for l in unclear:
        nm = NAMES.get(l["name"].lower(), l["name"])
        if any("built-in: unknown" in a and nm in a for a in att):      # uefi_source.py 的報告已經寫了
            continue
        att.append(f"{nm}: built into the firmware could not be decided (built-in: unknown): "
                   f"{'; '.join(l['built_in_reasons']) or 'see the uefi-source report'}; the findings are listed as if it were built in")
    if skipped:
        gaps.append(f"{skipped} component(s) of `{d.name}/{CDX}` were skipped (not an object, no name or bom-ref, or a duplicate bom-ref) "
                    "and are NOT in the SBOM and NOT matched (NOT_ASSESSED)")
    if not info["comps"]:
        gaps.append(f"`{d.name}/{CDX}` has no usable component: nothing bundled in the UEFI was found or listed (NOT_ASSESSED)")
    if uefi_ref:
        deps = [x["bom-ref"] for x in info["comps"] if x["bom-ref"] != uefi_ref]
        if deps:
            info["deps"][uefi_ref] = deps
    else:       # 沒有 UEFI 元件：函式庫直接掛在產品下
        info["top"] = [x["bom-ref"] for x in info["comps"]]
    # Grype 的結果
    run = _json(d / RUN)
    info["grype_run"] = run if isinstance(run, dict) else None
    g = _json(d / GRYPE_OUT)
    try:
        gsha = hashlib.sha256((d / GRYPE_OUT).read_bytes()).hexdigest()
    except OSError:
        gsha = None
    want, purls = grype_input(cdx)
    info["allowed_purls"] = sorted(purls)
    stale = isinstance(run, dict) and run.get("input_sha256") != hashlib.sha256(want).hexdigest()
    altered = isinstance(run, dict) and not stale and run.get("grype_sha256") != gsha
    if stale and isinstance(g, dict):
        gaps.append("the Grype result is not for the current uefi-source output (grype-run.json has no matching input_sha256): "
                    "its matches were NOT used; run uefi_bundled.py grype again (NOT_ASSESSED)")
    elif altered and isinstance(g, dict):
        gaps.append("grype.json is not the file that uefi_bundled.py wrote (grype-run.json has no matching grype_sha256): "
                    "its matches were NOT used; run uefi_bundled.py grype again (NOT_ASSESSED)")
    elif isinstance(g, dict) and isinstance(g.get("matches"), list) and isinstance(run, dict) and run.get("status") in ("OK", "GAP"):
        ms = dedupe([m for m in g["matches"] if isinstance(m, dict) and isinstance(m.get("artifact"), dict) and m["artifact"].get("purl") in purls])
        n_off = sum(1 for m in g["matches"] if not (isinstance(m, dict) and isinstance(m.get("artifact"), dict) and m["artifact"].get("purl") in purls))
        if n_off:
            att.append(f"{n_off} Grype match(es) on components that are not in the matched list were dropped")
        info["grype"], info["matches"] = dict(g, matches=ms), len(ms)
        if run.get("status") == "GAP":
            gaps.append(f"Grype database: {_s(run.get('detail'))} (matches may be missing newer vulnerabilities)")
    else:
        why = _s(run.get("detail")) if isinstance(run, dict) else f"`{d.name}/{RUN}` not found"
        if any(l["known"] for l in info["libs"]) or not info["comps"]:
            gaps.append(f"the libraries bundled in the UEFI were NOT matched against vulnerability data (Grype did not run or its result is "
                        f"not usable: {why or 'no result'}); no row does not mean no vulnerability")
    if gaps:
        info["status"] = "GAP"
    elif att or info["source_status"] in ("ATTENTION",):
        info["status"] = "ATTENTION"


def _line(version, vers):
    """修補版本裡和這個版本同一條發行線（3.4.1 → 3.4.x）的；沒有同線的就全部。"""
    m = re.match(r"(\d+)\.(\d+)", version or "")
    own = [v for v in vers if m and v.startswith(f"{m.group(1)}.{m.group(2)}.")]
    return own or list(vers)


IMG_RESULTS = ("present", "absent", "not_assessed")


def image_check(info, chk):
    """bootloader_coverage.py uefi-check 的輸出（uefi-binary-check.json）→ info["image_libs"]：每個函式庫的映像檢查結果與證據。
    chk 沒有 "libraries"（舊輸出、沒給）→ 什麼都不做（info 不變，報告和以前逐位元組相同）。永遠不丟例外。
    absent 只在「所有出貨的 UEFI 映像」都 absent 時才成立（uefi_image.combine 已經算好）；證據是各映像解開後的統計。"""
    libs = chk.get("libraries") if isinstance(chk, dict) else None
    imgs = chk.get("images") if isinstance(chk, dict) and isinstance(chk.get("images"), list) else []
    if not isinstance(libs, dict) or not libs:
        return
    out = {}
    for lib, v in libs.items():
        if not isinstance(v, dict) or v.get("result") not in IMG_RESULTS or not isinstance(lib, str):
            continue
        per = [((i.get("bundled_libs") or {}), ((i.get("bundled_libs") or {}).get("libraries") or {}).get(lib) or {}) for i in imgs if isinstance(i, dict)]
        ev = {"images": len(per), "ffs_files": sum(int(b.get("ffs_files") or 0) for b, _ in per),
              "decompressed_total": sum(int(b.get("decompressed_total") or 0) for b, _ in per),
              "methods": sorted({str(b.get("method")) for b, _ in per}),
              "distinct_strings": max([int(x.get("distinct_strings") or 0) for _, x in per] or [0]),
              "distinct_paths": max([int(x.get("distinct_paths") or 0) for _, x in per] or [0]),
              "strings": sum(int(x.get("strings") or 0) for _, x in per), "paths": sum(int(x.get("paths") or 0) for _, x in per),
              "undecoded": [f"{_s(u.get('where'), 120)}: {_s(u.get('reason'), 200)}" for b, _ in per for u in (b.get("undecoded") or [])
                            if isinstance(u, dict)][:5],
              "reasons": sorted({_s(x.get("reason"), 200) for _, x in per if x.get("reason")})[:3]}
        co = (chk.get("corroboration") or {}).get(lib) if isinstance(chk.get("corroboration"), dict) else None
        if isinstance(co, dict):
            ev["corroboration"] = {"ok": co.get("ok") is True, "reason": _s(co.get("reason"), 300), "dsc": [_s(x, 200) for x in co.get("dsc") or []][:4],
                                   "evidence": [_s(x, 300) for x in co.get("evidence") or []][:8],
                                   "unresolved_includes": [_s(x, 300) for x in co.get("unresolved_includes") or []][:5],
                                   "missing_inf_count": int(co.get("missing_inf_count") or 0) if isinstance(co.get("missing_inf_count"), int) else 0,
                                   "missing_inf_first": [_s(x, 200) for x in co.get("missing_inf_first") or []][:3],
                                   "defines_files": [_s(x, 200) for x in co.get("defines_files") or []][:3]}
        ev["scope"] = _s(chk.get("scope"), 300) or "the UEFI images uefi_*.bin listed in the flash package; capsules were not examined"
        out[lib.lower()] = {"result": v["result"], "evidence": ev, "present_in": [_s(x, 200) for x in v.get("present_in") or []][:10],
                            "not_assessed_in": [_s(x, 200) for x in v.get("not_assessed_in") or []][:10]}
    if out:
        info["image_libs"] = out
        for lib, v in sorted(out.items()):
            if v["result"] == "not_assessed":
                nm = NAMES.get(lib, lib)
                info["attention"].append(f"{nm}: the shipped UEFI image(s) could not be fully checked for this library (not_assessed): "
                                         f"{'; '.join(v['evidence']['undecoded'] or v['evidence']['reasons']) or 'see uefi-binary-check.json'}; "
                                         "the rows are not changed by the image check")
        if info["status"] == "OK" and info["attention"]:
            info["status"] = "ATTENTION"


def relabel_rows(rows, info):
    """Grype 比對的列（found_by＝grype only）：元件欄換成「OpenSSL 3.4.1 (bundled in UEFI)」，修補建議改成重建 UEFI。
    樹裡其他位置的副本（role other-copy）不說「bundled in UEFI」：沒有確認有編進韌體。"""
    by_purl = {}
    for l in sorted(info["libs"], key=lambda l: l["role"] == "other-copy"):      # 同一個 purl 有主要的與副本時用主要的
        if l["purl"]:
            by_purl.setdefault(l["purl"], l)
    for r in rows:
        l = by_purl.get((r.get("purl") or "").split("?", 1)[0])
        if not l:
            continue
        what = NAMES.get(l["name"].lower(), l["name"])
        allv = r.get("fix_versions") or []
        vers = _line(l["version"], allv)
        copy = l["role"] == "other-copy"
        r["component"], r["bundled_in"] = l["label"], ("UEFI source tree (copy)" if copy else "UEFI")
        if info.get("build_check") and not copy:
            r["uefi_build_check"] = info["build_check"]      # 映像與這份原始碼是否一致（bootloader_coverage.py uefi-check）：列的證據
        ic = (info.get("image_libs") or {}).get(l["name"].lower())
        if ic:          # 出貨映像的函式庫檢查（uefi_image.py）：vex_export.uefi_image_suggestion 依它在列上加「建議」（row["suggestion"]；不改判定）
            r["uefi_image_check"] = {"library": l["name"].lower(), "label": NAMES.get(l["name"].lower(), l["name"]), "result": ic["result"],
                                     "evidence": ic["evidence"], "present_in": ic["present_in"], "not_assessed_in": ic["not_assessed_in"]}
        r["fix_versions_all"] = allv
        more = f"; Grype lists fixes for several release lines: {', '.join(allv)}" if vers != allv else ""
        where = ("found in the UEFI source tree, not confirmed to be built into the firmware; if it is, rebuild the UEFI with"
                 if copy else "rebuild the UEFI with")
        r["fix"] = (f"{where} {what} {', '.join(vers)} or later (an apt upgrade does not apply{more})" if vers else
                    f"no fixed {what} version known to Grype ({r.get('fix_state')}); {where} a fixed {what} once one exists "
                    "(an apt upgrade does not apply)")
    return rows


def text(info, table):
    """sbom.md 的一小節。"""
    out = ["### Libraries bundled in the UEFI (`uefi-source`)", "",
           f"**Status: {info['status']}**. Read from the UEFI source tree by `uefi_source.py` (`{info['dir']}/{CDX}`), added to the product "
           f"SBOM as components under the UEFI component, and matched with Grype and the mirrored database (offline). Matches: "
           f"**{info['matches'] if info['matches'] is not None else 'not matched'}**."
           + (f" Grype database: {info['grype_run'].get('detail')}" if info.get("grype_run") else ""), ""]
    if info.get("build_check"):
        out += [info["build_check"], ""]
    if info.get("image_libs"):
        out += ["Shipped UEFI image check (the images were decoded and searched for library code and strings; `absent` needs every image fully decoded and, for libraries with weak markers, corroboration from the platform DSC; scope: the UEFI images uefi_*.bin listed in the flash package, capsules were not examined):", ""] + \
               [f"- {NAMES.get(k, k)}: **{v['result']}** ({v['evidence']['images']} image(s); {v['evidence']['distinct_strings']} distinct strings, "
                f"{v['evidence']['distinct_paths']} build paths)" for k, v in sorted(info["image_libs"].items())] + [""]
    if info["libs"]:
        out += [table(["Component", "Version", "purl", "Matched", "Built into the firmware"],
                      [[l["label"], l["version"] or "**version unknown**", f"`{l['purl']}`" if l["purl"] else "—",
                        "yes (CPE)" if l["known"] and info["grype"] is not None else "**no (NOT_ASSESSED)**",
                        ("—" if l["built_in"] is None else
                         f"**{l['built_in']}**" + ("" if l["built_in_checked"] else " (not checked)"))] for l in info["libs"]]), ""]
        for l in info["libs"]:
            if l["built_in"] in ("yes", "unknown") and l["built_in_evidence"]:
                out += [f"Built into the firmware, {l['name']}: **{l['built_in']}** (platform DSC analysis, best effort; it never excludes a row):", ""] + \
                       [f"- `{e}`" for e in l["built_in_evidence"][:6]] + [""]
    for title, items in (("GAP", info["gaps"]), ("Needs confirmation", info["attention"])):
        if items:
            out += [f"**{title}**:", ""] + [f"- {g}" for g in items[:GAP_MAX]] + [""]
    out += ["Only the versions found in the source tree are matched; \"no match\" does not mean the library is free of vulnerabilities."]
    return "\n".join(out)


# ---------- grype 動作 ----------

def run_grype(d, grype="grype", max_age=3.0, env=None):
    """對 <d>/uefi-source.cdx.json 跑 Grype（離線）→ (status, detail)，並寫 grype.json、grype-run.json。"""
    d = Path(d)
    e = dict(os.environ if env is None else env, GRYPE_DB_AUTO_UPDATE="false", GRYPE_CHECK_FOR_APP_UPDATE="false")
    e.setdefault("GRYPE_DB_CACHE_DIR", str(Path(e.get("HOME", "~")).expanduser() / ".cache" / "grype" / "db"))
    run = {"schema": "sca-center-uefi-grype/1", "status": "FAIL", "detail": "", "db_built": None, "matches": None}

    def done(status, detail):
        run.update(status=status, detail=detail)
        (d / RUN).write_text(json.dumps(run, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        return status, detail
    (d / GRYPE_OUT).unlink(missing_ok=True)
    cdx = _json(d / CDX)
    if not isinstance(cdx, dict):
        return done("NOT_RUN", f"{CDX} not found or not readable")
    body, purls = grype_input(cdx)
    run["input_sha256"] = hashlib.sha256(body).hexdigest()
    if not purls:
        return done("NOT_RUN", "no library with a version and an allowed CPE in the UEFI SBOM (nothing Grype could match; edk2 itself is not matched)")
    (d / GRYPE_IN).write_bytes(body)
    try:
        st = subprocess.run([grype, "db", "status"], capture_output=True, text=True, timeout=120, env=e)
    except (OSError, subprocess.TimeoutExpired) as ex:
        return done("NOT_RUN", f"grype not usable ({type(ex).__name__})")
    m = {k: v.strip() for k, v in (re.match(r"(\w+):\s*(.*)", ln).groups() for ln in st.stdout.splitlines() if re.match(r"(\w+):\s*(.*)", ln))}
    built = m.get("Built")
    try:
        age = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(built.replace("Z", "+00:00"))).total_seconds() / 86400
    except (AttributeError, ValueError):
        age = None
    if st.returncode != 0 or m.get("Status") != "valid" or age is None:
        return done("NOT_RUN", f"Grype database not usable (db status exit {st.returncode}, Status={m.get('Status') or 'none'}, Built={built or 'none'})")
    run["db_built"] = built
    try:
        r = subprocess.run([grype, f"sbom:{d / GRYPE_IN}", "-o", "json"], capture_output=True, text=True, timeout=TIMEOUT, env=e)
        g = json.loads(r.stdout) if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, ValueError) as ex:
        return done("FAIL", f"grype failed ({type(ex).__name__})")
    if not isinstance(g, dict) or not isinstance(g.get("matches"), list):
        return done("FAIL", f"grype exit {r.returncode}: {r.stderr.strip().splitlines()[-1][:200] if r.stderr.strip() else 'no output'}")
    g["matches"] = dedupe([m for m in g["matches"] if isinstance(m, dict) and isinstance(m.get("artifact"), dict) and m["artifact"].get("purl") in purls])
    (d / GRYPE_OUT).write_text(json.dumps(g, ensure_ascii=False) + "\n", encoding="utf-8")
    run["grype_sha256"] = hashlib.sha256((d / GRYPE_OUT).read_bytes()).hexdigest()
    run["matches"] = len(g["matches"])
    if age > max_age:
        return done("GAP", f"database Built={built}, {age:.0f} days old (limit {max_age:g}); {len(g['matches'])} matches")
    return done("OK", f"database Built={built} ({age:.0f} days); {len(g['matches'])} matches (matching done; not proof that no other vulnerability exists)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grype")
    g.add_argument("--dir", required=True)
    g.add_argument("--grype", default="grype")
    g.add_argument("--max-age-days", type=float, default=3.0)
    a = ap.parse_args(argv)
    if not Path(a.dir).is_dir():
        ap.error(f"not a directory: {a.dir}")
    s, d = run_grype(a.dir, a.grype, a.max_age_days)
    print(f"B-uefi-grype\t{s}\t{d}")
    return {"OK": 0, "GAP": 2, "NOT_RUN": 2}.get(s, 1)


if __name__ == "__main__":
    sys.exit(main())
