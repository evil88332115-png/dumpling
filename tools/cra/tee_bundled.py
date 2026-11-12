#!/usr/bin/env python3
"""tos-optee 映像（OP-TEE、TF-A）與 OP-TEE 內建的 Mbed TLS 併進產品 SBOM、用 Grype（離線資料庫）比對，成為 CRA 報告的列。

動作：
  python3 -I tee_bundled.py grype --dir <tee_source.py 的輸出資料夾> [--grype <執行檔>] [--max-age-days N]
      對 <dir>/tee-source.cdx.json 跑 `grype sbom:…`（離線設定同 uefi_bundled.py：GRYPE_DB_AUTO_UPDATE=false、GRYPE_CHECK_FOR_APP_UPDATE=false，
      資料庫在 GRYPE_DB_CACHE_DIR），寫 <dir>/grype.json、grype-run.json。stdout 一行 `B-tee-grype<TAB>OK|GAP|NOT_RUN|FAIL<TAB>說明`。
  （cra_report.py 用 load()、relabel_rows()、text()；沒有給資料夾時整個功能不執行，輸出和以前逐位元組相同。）

Grype 的執行與輸入檔重用 uefi_bundled.py（載入一份私有副本，只換檔名與 CPE 允許清單），所以離線環境變數、資料庫年齡檢查、
輸入雜湊核對都和 UEFI 內建函式庫相同。pkg:generic 元件只靠 CPE 比對；沒有版本就沒有 CPE（tee_source.py），不比對、列 GAP。
OP-TEE 與 TF-A 的弱點資料涵蓋有限：0 筆不等於沒有弱點。Mbed TLS 在 OP-TEE 的建置設定只當事實記錄，是否受影響不在這裡判斷。
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CDX, REPORT, GRYPE_OUT, RUN = "tee-source.cdx.json", "tee-source.json", "grype.json", "grype-run.json"
ALLOWED = {("linaro", "op-tee"), ("trustedfirmware", "trusted_firmware-a"), ("arm", "mbed_tls"), ("trustedfirmware", "mbed_tls")}
SUFFIX = {"mbedtls": "(bundled in OP-TEE)", "optee": "(tos-optee image)", "tfa": "(tos-optee image)"}
PLAIN_NOTE = "OP-TEE build config not read from the source; affectedness not assessed"
LIMITED = "vulnerability data coverage is limited; 0 matches does not mean no vulnerabilities"
MAX_COMPS = 16
_UB = None


def ub():
    """uefi_bundled.py 的私有副本（換檔名與 CPE 允許清單）。"""
    global _UB
    if _UB is None:
        p = HERE / "uefi_bundled.py"
        spec = importlib.util.spec_from_file_location("sca_center_uefi_bundled_for_tee", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.CDX, m.ALLOWED_CPE, m.MAX_COMPS = CDX, ALLOWED, MAX_COMPS
        m.ALT_CPE = {("arm", "mbed_tls"): [("trustedfirmware", "mbed_tls")]}
        _UB = m
    return _UB


def label(name, version, kind):
    return f"{name}{' ' + version if version else ''} {SUFFIX.get(kind, '(tos-optee image)')}"


def load(d):
    """<dir>（tee_source.py 的輸出＋tee_bundled.py grype 的結果）→ info（形狀同 uefi_bundled.load）。不丟例外。"""
    d = Path(d)
    info = {"status": "OK", "dir": d.name, "source_status": None, "gaps": [], "attention": [], "comps": [], "deps": {}, "top": [],
            "libs": [], "grype": None, "grype_run": None, "matches": None, "image_check": None, "build_config": None}
    try:
        _load(info, d)
    except Exception as e:      # noqa: BLE001
        info.update(status="GAP", comps=[], deps={}, top=[], libs=[], grype=None, matches=None)
        info["gaps"] = [f"`{d.name}/{CDX}` could not be processed ({type(e).__name__}): OP-TEE, TF-A and the bundled Mbed TLS are NOT_ASSESSED"]
    return info


def _load(info, d):
    u = ub()
    s, j = u._s, u._json
    cdx, rep = j(d / CDX), j(d / REPORT)
    gaps, att = info["gaps"], info["attention"]
    if not isinstance(cdx, dict) or not isinstance(cdx.get("components"), list):
        info["status"] = "GAP"
        gaps.append(f"`{d.name}/{CDX}` not found or not readable: OP-TEE, TF-A and the bundled Mbed TLS are NOT_ASSESSED "
                    "(not in the SBOM, not matched; run tee_source.py on the vendor public source tree)")
        return
    if isinstance(rep, dict):
        info["source_status"] = s(rep.get("status"), 20)
        gaps += [s(g) for g in rep.get("gaps") or [] if s(g)][:50]
        att += [s(g) for g in rep.get("attention") or [] if s(g)][:50]
        info["image_check"] = rep.get("image_check") if isinstance(rep.get("image_check"), dict) else None
        info["build_config"] = rep.get("build_config") if isinstance(rep.get("build_config"), dict) else None
        if info["source_status"] in ("GAP", "FAIL") and not gaps:
            gaps.append(f"tee_source.py reported {info['source_status']} without giving a reason: treated as GAP")
    else:
        gaps.append(f"`{d.name}/{REPORT}` not found or not readable: the notes of tee_source.py (conflicts, image check) are missing")
    kept, skipped, over = u.kept_components(cdx)
    if over:
        gaps.append(f"{over} component(s) of `{d.name}/{CDX}` are beyond the limit of {MAX_COMPS} and were NOT added (NOT_ASSESSED)")
    if skipped:
        gaps.append(f"{skipped} component(s) of `{d.name}/{CDX}` were skipped (not an object, no name or bom-ref, or a duplicate bom-ref) (NOT_ASSESSED)")
    for c in kept:
        kind = (u._prop(c, "sca-center:tee:role") or [""])[0]
        ver = s(c.get("version"), 100)
        x = {"type": c.get("type") if c.get("type") in ("firmware", "library") else "library", "bom-ref": c["bom-ref"], "name": s(c["name"])}
        if ver:
            x["version"] = ver
        if s(c.get("purl")).startswith("pkg:generic/"):
            x["purl"] = c["purl"][:500]
        cpe = s(c.get("cpe"))
        if cpe:
            if u._cpe_allowed(cpe, ver):
                x["cpe"] = cpe
            else:
                gaps.append(f"{x['name']}: the CPE is not usable (not on the list of matched CPEs or its version differs from {ver or 'none'}); "
                            "the CPE was dropped and the component is not matched")
        x["properties"] = [{"name": p["name"][:100], "value": s(p.get("value"))} for p in c.get("properties") or []
                           if isinstance(p, dict) and isinstance(p.get("name"), str) and p["name"].startswith("sca-center:")]
        if x.get("cpe"):
            x["properties"] += [{"name": "syft:cpe23", "value": a} for a in u.alt_cpes(x["cpe"])]
        info["comps"].append(x)
        known = bool(ver and x.get("cpe"))
        info["libs"].append({"ref": x["bom-ref"], "name": x["name"], "version": ver or None, "purl": x.get("purl", ""), "kind": kind,
                             "label": label(x["name"], ver, kind), "known": known})
    if not info["comps"]:
        gaps.append(f"`{d.name}/{CDX}` has no usable component: nothing was found or listed (NOT_ASSESSED)")
    refs = {l["kind"]: l["ref"] for l in info["libs"]}
    if "optee" in refs and "mbedtls" in refs:
        info["deps"][refs["optee"]] = [refs["mbedtls"]]
    info["top"] = [x["bom-ref"] for x in info["comps"] if x["bom-ref"] != refs.get("mbedtls") or "optee" not in refs]
    # Grype 的結果（同 uefi_bundled 的核對：輸入雜湊、輸出雜湊）
    run, g = j(d / RUN), j(d / GRYPE_OUT)
    info["grype_run"] = run if isinstance(run, dict) else None
    try:
        gsha = hashlib.sha256((d / GRYPE_OUT).read_bytes()).hexdigest()
    except OSError:
        gsha = None
    want, purls = u.grype_input(cdx)
    info["allowed_purls"] = sorted(purls)
    stale = isinstance(run, dict) and run.get("input_sha256") != hashlib.sha256(want).hexdigest()
    altered = isinstance(run, dict) and not stale and run.get("grype_sha256") != gsha
    if stale and isinstance(g, dict):
        gaps.append("the Grype result is not for the current tee-source output: its matches were NOT used; run tee_bundled.py grype again (NOT_ASSESSED)")
    elif altered and isinstance(g, dict):
        gaps.append("grype.json is not the file that tee_bundled.py wrote: its matches were NOT used; run tee_bundled.py grype again (NOT_ASSESSED)")
    elif isinstance(g, dict) and isinstance(g.get("matches"), list) and isinstance(run, dict) and run.get("status") in ("OK", "GAP"):
        ms = u.dedupe([m for m in g["matches"] if isinstance(m, dict) and isinstance(m.get("artifact"), dict) and m["artifact"].get("purl") in purls])
        info["grype"], info["matches"] = dict(g, matches=ms), len(ms)
        if run.get("status") == "GAP":
            gaps.append(f"Grype database: {s(run.get('detail'))} (matches may be missing newer vulnerabilities)")
    else:
        why = s(run.get("detail")) if isinstance(run, dict) else f"`{d.name}/{RUN}` not found"
        if any(l["known"] for l in info["libs"]) or not info["comps"]:
            gaps.append("OP-TEE, TF-A and the bundled Mbed TLS were NOT matched against vulnerability data (Grype did not run or its result is "
                        f"not usable: {why or 'no result'}); no row does not mean no vulnerability")
    if gaps:
        info["status"] = "GAP"
    elif att:
        info["status"] = "ATTENTION"


def config_note(info):
    """OP-TEE 建置設定的事實句（tee_source.config_note 的同一個句子；沒有檔名與行號）。"""
    facts = ((info.get("build_config") or {}).get("facts"))
    if not isinstance(facts, dict) or not facts:
        return PLAIN_NOTE

    def val(k):
        v = facts.get(k)
        return v.get("value") if isinstance(v, dict) and v.get("value") is not None else "unknown"
    return (f"OP-TEE build config: core CFG_CORE_MBEDTLS_MPI={val('CFG_CORE_MBEDTLS_MPI')}; TA library CFG_TA_MBEDTLS={val('CFG_TA_MBEDTLS')}; "
            f"crypto library {val('CFG_CRYPTOLIB_NAME')}; affectedness not assessed")


def relabel_rows(rows, info):
    """Grype 比對的列：元件欄換成「Mbed TLS 3.6.5 (bundled in OP-TEE)」，修補建議改成用修補後的版本重建 tos-optee 映像。"""
    by = {l["purl"]: l for l in info["libs"] if l["purl"]}
    for r in rows:
        l = by.get((r.get("purl") or "").split("?", 1)[0])
        if not l:
            continue
        allv = r.get("fix_versions") or []
        note = "; " + config_note(info) if l["kind"] == "mbedtls" else ""
        r["component"], r["bundled_in"] = l["label"], "OP-TEE" if l["kind"] == "mbedtls" else "tos-optee image"
        r["fix_versions_all"] = allv
        vers = ub()._line(l["version"], allv)
        more = f"; Grype lists fixes for several release lines: {', '.join(allv)}" if vers != allv else ""
        r["fix"] = (f"rebuild the tos-optee image with a fixed {l['name']} ({', '.join(vers)} or later; an apt upgrade does not apply{more}){note}" if vers else
                    f"no fixed {l['name']} version known to Grype ({r.get('fix_state')}); rebuild the tos-optee image with a fixed {l['name']} once one exists "
                    f"(an apt upgrade does not apply){note}")
        r["tee_note"] = (config_note(info) if l["kind"] == "mbedtls" else LIMITED)
    return rows


def text(info, table):
    """sbom.md 的一小節。"""
    out = ["### OP-TEE, TF-A and bundled Mbed TLS (`tee-source`)", "",
           f"**Status: {info['status']}**. Read from the vendor public source tree by `tee_source.py` (`{info['dir']}/{CDX}`), added to the product "
           f"SBOM and matched with Grype and the mirrored database (offline). Matches: "
           f"**{info['matches'] if info['matches'] is not None else 'not matched'}**."
           + (f" Grype database: {info['grype_run'].get('detail')}" if info.get("grype_run") else ""), ""]
    ic = info.get("image_check")
    if isinstance(ic, dict) and ic.get("detail"):
        out += [f"Flashed tos-optee images compared with this source: {ic['detail']}.", ""]
    if info["libs"]:
        out += [table(["Component", "Version", "purl", "Matched"],
                      [[l["label"], l["version"] or "**version unknown**", f"`{l['purl']}`" if l["purl"] else "—",
                        "yes (CPE)" if l["known"] and info["grype"] is not None else "**no (NOT_ASSESSED)**"] for l in info["libs"]]), ""]
    bc = ((info.get("build_config") or {}).get("facts")) or {}
    if bc:
        out += [config_note(info) + " (read from the source files; evidence only).", ""]
    if info.get("auto_detected"):
        out += ["This input was picked up automatically from the `tee-source` folder next to the scan output (no `--tee-source` was given).", ""]
    for title, items in (("GAP", info["gaps"]), ("Needs confirmation", info["attention"])):
        if items:
            out += [f"**{title}**:", ""] + [f"- {g}" for g in items[:50]] + [""]
    out += [f"OP-TEE and TF-A: {LIMITED}. Only the versions found in the source tree are matched."]
    return "\n".join(out)


def run_grype(d, grype="grype", max_age=3.0, env=None):
    return ub().run_grype(d, grype, max_age, env)


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
    print(f"B-tee-grype\t{s}\t{d}")
    return {"OK": 0, "GAP": 2, "NOT_RUN": 2}.get(s, 1)


if __name__ == "__main__":
    sys.exit(main())
