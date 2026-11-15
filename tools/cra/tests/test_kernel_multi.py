"""多顆核心逐顆判定與合併、核心列去重（M7d-1，D-036／D-061）。合成資料。

合成兩顆核心的映像（Raspberry Pi 型：兩顆實際的 linux-image-<版本> 加兩個 meta 套件 linux-image-rpi-*），每個 CVE 在四個核心套件上各一個 DT finding。
"""
import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import kernel_merge as km  # noqa: E402
import vex_export as vx  # noqa: E402
from test_cra_report import finding, make_project, make_scan, run, write_json  # noqa: E402
from test_vex_evidence import erule, rules_of  # noqa: E402

A, B = "6.12.34+rpt-rpi-2712", "6.12.34+rpt-rpi-v8"
VER = "1:6.12.34-1+rpt1"
PURL = "pkg:deb/debian/{}@1%3A6.12.34-1%2Brpt1?arch=arm64&distro=debian-13"
PKGS = {"imgA": f"linux-image-{A}", "imgB": f"linux-image-{B}", "metaA": "linux-image-rpi-2712", "metaB": "linux-image-rpi-v8"}
SHA = {A: "a" * 64, B: "b" * 64}
KV3 = "sca-center-kernel-versions/3"
KCFG_SCHEMA = "sca-center-kernel-config/1"


def kvdoc(judged=(A, B), shipped=(A, B), not_judged=(), basis="auto-detected", schema=KV3):
    return {"schema": schema, "shipped": [{"version": v, "upstream_version": None, "upstream_basis": None, "upstream_note": "x"} for v in shipped],
            "requested": [] if basis == "auto-detected" else list(judged),
            "judged": [{"version": v, "basis": basis, "config_file": f"scan/kernels/{v}/kernel-config.json", "config_status": "OK",
                        "module_map_file": f"scan/kernels/{v}/kernel-module-map.json", "module_map_status": "OK"} for v in judged],
            "not_judged": [{"version": v, "reason": "x", "shipped": True} for v in not_judged]}


def kdoc(ver, results, status="OK", sha=None):
    return {"schema": KCFG_SCHEMA, "status": status, "detail": "x",
            "kernel": {"version": ver, "config_source": "/usr/src/.config", "config_sha256": sha or SHA[ver]},
            "component": {"name": PKGS["imgA"], "version": VER, "purl": PURL.format(PKGS["imgA"])},     # 工具記的是第一個找到的核心元件，不是這顆的
            "results": [{"cve": c, "decision": d, "detail": f"detail {c} {ver}", "files": [{"path": f"drivers/{c}.c", "built": d != "not_affected"}]}
                        for c, d in results.items()], "counts": {}}


def mapdoc(ver, cves=None):
    return {"schema": "sca-center-kernel-module-map/1", "status": "OK", "kernel": {"version": ver}, "component": {"name": "x", "version": VER, "purl": "pkg:deb/debian/x"},
            "cves": cves or {}, "modules_order": ["kernel/drivers/foo.ko"], "modules_builtin": [], "modules_present": ["foo.ko"], "modules_present_gaps": []}


def krow(cve, name, ver=VER, **kw):
    r = {"id": cve, "key": [cve, name, ver], "cves": [cve], "all_ids": [cve], "source_ids": ["NVD:" + cve], "component": name, "name": name, "version": ver,
         "purl": PURL.format(name), "ptype": "deb", "severity": "MEDIUM", "cvss": None, "kev": False, "analysis": [], "kernel": True, "installed_as": [],
         "mapped_from": None, "cpe": "", "n_findings": 1, "tier": "p2", "fix_state": "not-fixed", "fix_versions": [], "fix": "x", "fix_next": None}
    r.update(kw)
    return r


def pkg_scope(name):
    return {PKGS["imgA"]: {"scope": "kernel", "kernels": [A]}, PKGS["imgB"]: {"scope": "kernel", "kernels": [B]}}.get(name, {"scope": "product", "kernels": []})


def merged_row(cve, **kw):
    """四個核心套件合併的一列（kernel_merge.merge_rows）。"""
    rows = [krow(cve, n) for n in PKGS.values()]
    sc = {id(r): pkg_scope(r["name"]) for r in rows}
    return km.merge_rows(rows, sc, {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNASSIGNED": 5}) | kw


def multi_doc(a, b, judged=(A, B), kvers=None):
    """per-kernel 的結果 {CVE: 判定}（a：A 的，b：B 的；None＝沒有這顆的檔案）→ 合併文件。"""
    docs = {A: None if a is None else kdoc(A, a), B: None if b is None else kdoc(B, b)}
    return vx.kernel_multi_doc(docs, kvers or kvdoc(judged=judged))


# ---------- 報告端：合成的兩顆核心的掃描 ----------

def sbom_of(names):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1", "metadata": {"tools": {"components": [{"name": "syft", "version": "1.55.0"}]}},
            "components": [{"type": "library", "name": n, "version": VER, "purl": PURL.format(n), "bom-ref": f"pkg-{n}"} for n in names]}


def grype_of(cves, names, state="not-fixed", versions=()):
    return {"matches": [{"vulnerability": {"id": c, "fix": {"state": state, "versions": list(versions)}}, "relatedVulnerabilities": [],
                         "artifact": {"name": n, "version": VER, "type": "deb", "purl": PURL.format(n)}} for c in cves for n in names]}


OWNERS = (f"{PKGS['imgA']}\t/usr/lib/modules/{A}/kernel/drivers/foo.ko\n{PKGS['imgA']}\t/usr/lib/modules/{A}/modules.order\n"
          f"{PKGS['imgB']}\t/usr/lib/modules/{B}/kernel/drivers/foo.ko\n{PKGS['imgB']}\t/boot/vmlinuz-{B}\n"
          f"{PKGS['metaA']}\t/usr/share/doc/{PKGS['metaA']}/copyright\n{PKGS['metaB']}\t/usr/share/doc/{PKGS['metaB']}/copyright\n"
          "openssl\t/usr/bin/openssl\n")


def multi_scan(tmp, a, b, kvers=None, severities=None, names=None, owners=OWNERS, with_docs=True, fix=("not-fixed", ()), mm=None):
    """a、b：A、B 兩顆核心的 {CVE: 判定}（None＝沒有那顆的檔案）。每個 CVE 在四個核心套件上各一個 DT finding（severities：{CVE: {套件鍵: 嚴重度}}）。"""
    names = names or list(PKGS.values())
    cves = sorted(set(a or {}) | set(b or {}))
    sev = severities or {}
    findings = [finding(n, VER, c, "NVD", (sev.get(c) or {}).get(k, "MEDIUM"), purl=PURL.format(n)) for c in cves for k, n in PKGS.items() if n in names]
    scan = make_scan(tmp / "s", findings=findings, grype=grype_of(cves, names, *fix), sbom=sbom_of(names),
                     stages={"C-kernel-coverage": "OK", "C-kernel-config": "OK", "C-kernel-module-map": "OK"})
    if kvers is not False:
        write_json(scan / "scan" / "kernel-versions.json", kvers or kvdoc())
    if with_docs:
        for v, res in ((A, a), (B, b)):
            if res is not None:
                write_json(scan / "scan" / "kernels" / v / "kernel-config.json", kdoc(v, res))
            if mm and v in mm:
                write_json(scan / "scan" / "kernels" / v / "kernel-module-map.json", mm[v])
    if owners is not None:
        pk = tmp / "pkgdb"
        pk.mkdir(parents=True, exist_ok=True)
        (pk / "dpkg-status").write_text("Package: openssl\nVersion: 1\n\n")
        (pk / "dpkg-file-owners").write_text(owners)
    return scan


def rows_of(reports):
    return json.loads((reports / "vulnerability-rows.json").read_text(encoding="utf-8"))


def vex_of(reports):
    return json.loads((reports / "vex.cdx.json").read_text(encoding="utf-8"))


def stmt_of(reports, cve):
    return next(v for v in vex_of(reports)["vulnerabilities"] if v["id"] == cve)


def smoke(tmp_path):
    a = {"CVE-2026-1001": "not_affected", "CVE-2026-1002": "not_affected", "CVE-2026-1003": "not_affected"}
    b = {"CVE-2026-1001": "not_affected", "CVE-2026-1002": "affected", "CVE-2026-1003": "unknown"}
    scan = multi_scan(tmp_path, a, b)
    proj = make_project(tmp_path / "p")
    r, s, reports = run(proj, scan)
    return r, s, reports


# ===================== kernel_merge：合併規則的真值表 =====================

import itertools  # noqa: E402

AFF, NA, UNK, NORES, NJ = km.AFFECTED, km.NOT_AFFECTED, km.UNKNOWN, "none", km.NOT_JUDGED
SHIP = [A, B]


def results_for(sa, sb, usable=True):
    """兩顆核心各自的狀態 → merge_cve 的輸入（judged、results）。NORES＝judged 了但沒有這顆的結果檔案；NJ＝沒有判定。"""
    judged, results = [], {}
    for v, s in ((A, sa), (B, sb)):
        if s == NJ:
            continue
        judged.append(v)
        results[v] = None if s == NORES else {"usable": usable, "decisions": {"CVE-X": s}}
    return judged, results


def expect(sa, sb):
    """規則（獨立寫一份，不呼叫 kernel_merge）：任一顆 affected → affected；兩顆都 not_affected → not_affected；其他 → unknown（不排除）。"""
    if AFF in (sa, sb):
        return AFF
    return NA if (sa, sb) == (NA, NA) else UNK


@pytest.mark.parametrize("sa,sb", list(itertools.product((AFF, NA, UNK, NORES, NJ), repeat=2)))
def test_truth_table_two_kernels(sa, sb):
    judged, results = results_for(sa, sb)
    m = km.merge_cve("CVE-X", SHIP, judged, results)
    assert m["decision"] == expect(sa, sb), (sa, sb, m)
    # 只有「全部 not_affected 而且可採用」會排除；結果不可採用（usable False）一律不排除（有 affected 的除外）
    j2, r2 = results_for(sa, sb, usable=False)
    m2 = km.merge_cve("CVE-X", SHIP, j2, r2)
    assert m2["decision"] != NA


def test_truth_table_row_not_matched_and_shipped_unknown():
    j, r = results_for(NA, NA)
    assert km.merge_cve("CVE-X", SHIP, j, r)["decision"] == NA
    assert km.merge_cve("CVE-X", SHIP, j, r, row_matched=False) == {"decision": UNK, "reason": "row_unmatched", "states": {A: NA, B: NA}}
    assert km.merge_cve("CVE-X", None, j, r)["decision"] == UNK and km.merge_cve("CVE-X", None, j, r)["reason"] == "shipped_unknown"
    assert km.merge_cve("CVE-X", [], j, r)["decision"] == UNK                              # 出貨的核心清單是空的：沒有核心可以排除
    j, r = results_for(AFF, NA)
    assert km.merge_cve("CVE-X", SHIP, j, r, row_matched=False)["decision"] == AFF         # affected 不看這一列對不對得到核心
    assert km.merge_cve("CVE-X", None, j, r)["decision"] == AFF
    # 這一顆結果裡沒有這個 CVE：沒有結果，不排除
    j, r = results_for(NA, NA)
    assert km.merge_cve("CVE-OTHER", SHIP, j, r)["decision"] == UNK and km.merge_cve("CVE-OTHER", SHIP, j, r)["states"] == {A: km.NO_RESULT, B: km.NO_RESULT}


def test_truth_table_three_kernels_and_extras():
    names = ["k1", "k2", "k3"]
    for combo in itertools.product((AFF, NA, UNK, NORES, NJ), repeat=3):
        judged = [v for v, s in zip(names, combo) if s != NJ]
        res = {v: (None if s == NORES else {"usable": True, "decisions": {"C": s}}) for v, s in zip(names, combo) if s != NJ}
        want = AFF if AFF in combo else NA if all(s == NA for s in combo) else UNK
        assert km.merge_cve("C", names, judged, res)["decision"] == want, combo
    # judged 了但映像沒有的核心：不要求 not_affected（它不在映像裡）；有 affected 的證據就算 affected
    res = {A: {"usable": True, "decisions": {"C": NA}}, "gone": None}
    assert km.merge_cve("C", [A], [A, "gone"], res)["decision"] == NA
    res = {A: {"usable": True, "decisions": {"C": NA}}, "gone": {"usable": True, "decisions": {"C": AFF}}}
    assert km.merge_cve("C", [A], [A, "gone"], res)["decision"] == AFF


def test_unrecognized_values_never_exclude():
    for bad in ("not-affected", "NOT_AFFECTED", "", None, 1, True):
        res = {A: {"usable": True, "decisions": {"C": NA}}, B: {"usable": True, "decisions": {"C": bad}}}
        assert km.merge_cve("C", SHIP, SHIP, res)["decision"] == UNK, bad
    for u in (False, None, "yes", 1, 0):                                                      # usable 要剛好是 True
        res = {A: {"usable": True, "decisions": {"C": NA}}, B: {"usable": u, "decisions": {"C": NA}}}
        assert km.merge_cve("C", SHIP, SHIP, res)["decision"] == UNK, u


def test_k2_overrides_only_apply_where_k2_applies():
    """K2（kernel-modules.json 的那一顆）：那一顆用 K2 成立，其他核心只看 K1；K2 不適用的核心（沒有 override）不會因此變成 not_affected。"""
    judged, results = results_for(AFF, NA)                                                  # A 的 K1 說 affected（例如 =m）、B 的 K1 not_affected
    assert km.merge_cve("CVE-X", SHIP, judged, results)["decision"] == AFF
    assert km.merge_cve("CVE-X", SHIP, judged, results, overrides={A: NA})["decision"] == NA      # A 因 K2 成立，B 靠 K1
    # B 的 K1 是 unknown：K2 只管 A，B 沒有排除 → 不排除
    judged, results = results_for(AFF, UNK)
    assert km.merge_cve("CVE-X", SHIP, judged, results, overrides={A: NA})["decision"] == UNK
    # 沒有 override：維持原樣；override 的版本不在清單、值不是 not_affected、沒判定的核心：不改
    judged, results = results_for(AFF, NA)
    for ov in ({}, None, {"zz": NA}, {A: UNK}, {A: AFF}, {A: "unknown"}):
        assert km.merge_cve("CVE-X", SHIP, judged, results, overrides=ov)["decision"] == AFF, ov
    judged, results = results_for(NJ, NA)
    assert km.merge_cve("CVE-X", SHIP, judged, results, overrides={A: NA})["decision"] == UNK     # 沒判定的核心不能被 K2 蓋過
    assert km.override_states({A: NJ}, {A: NA}) == {A: NJ}


def test_row_states_combines_cves_per_kernel():
    s = km.row_states([{A: NA, B: NA}, {A: NA, B: AFF}])
    assert s == {A: NA, B: AFF}
    assert km.row_states([{A: NA, B: UNK}, {A: NA, B: NA}]) == {A: NA, B: UNK}
    assert km.row_states([{A: NA}, {A: km.NO_RESULT}]) == {A: km.NO_RESULT}
    assert km.row_states([{A: NA}, {A: NJ}]) == {A: NJ}
    assert km.row_states([]) == {}


# ===================== 核心套件對到哪顆核心（dpkg 的檔案清單） =====================

def test_kernel_version_of_path():
    f = km.kernel_version_of_path
    assert f(f"/usr/lib/modules/{A}/kernel/x.ko") == A and f(f"/lib/modules/{A}/modules.order") == A and f(f"/usr/lib/modules/{A}") == A
    assert f(f"/boot/vmlinuz-{B}") == B and f(f"/boot/config-{B}") == B and f(f"/boot/initrd.img-{B}") == B
    for bad in ("/usr/share/doc/x/copyright", "/usr/lib/modules/", "/usr/lib/modules", "/usr/lib/modules/../etc/passwd/x", "/usr/lib/modules/a;b/x",
                "/boot/vmlinuz-a b", "/opt/usr/lib/modules/6.1/x", "usr/lib/modules/6.1/x", "/boot/other-6.1", "/usr/lib/python3/modules/6.1/x"):
        assert f(bad) is None, bad


def test_read_kernel_owners_and_scopes(tmp_path):
    d = tmp_path / "pkgdb"
    d.mkdir()
    (d / "dpkg-file-owners").write_text(OWNERS + f"{PKGS['imgA']}:arm64\t/boot/System.map-{A}\n")
    owners, why = km.read_kernel_owners(d)
    assert why is None and owners == {PKGS["imgA"]: {A}, PKGS["imgB"]: {B}}
    sc = lambda n: km.package_scope(n, owners, SHIP)           # noqa: E731
    assert sc(PKGS["imgA"]) == {"scope": "kernel", "kernels": [A]} and sc(PKGS["imgB"]) == {"scope": "kernel", "kernels": [B]}
    assert sc(PKGS["metaA"]) == {"scope": "product", "kernels": []}          # 沒有核心檔案的 meta 套件：算整個產品
    assert sc("linux-base") == {"scope": "product", "kernels": []} and sc(None) == {"scope": "product", "kernels": []}
    # 套件擁有的核心檔案屬於不是出貨的核心：對不到
    assert km.package_scope(PKGS["imgA"], {PKGS["imgA"]: {A, "9.9.9"}}, SHIP) == {"scope": "unmatched", "kernels": [A], "unknown_kernels": ["9.9.9"]}
    assert km.package_scope(PKGS["imgA"], {PKGS["imgA"]: {"9.9.9"}}, SHIP)["scope"] == "unmatched"
    # 沒有檔案清單：全部算整個產品（更嚴格，不是更寬鬆）
    assert km.package_scope(PKGS["imgA"], None, SHIP) == {"scope": "product", "kernels": []}
    # 一個套件擁有兩顆核心的檔案：兩顆都算
    assert km.package_scope("x", {"x": {A, B}}, SHIP) == {"scope": "kernel", "kernels": [A, B]}
    assert km.row_matched([km.package_of(krow("C", "x"), sc(PKGS["imgA"]))]) and not km.row_matched([]) and not km.row_matched(None)
    bad = km.package_of(krow("C", "x"), {"scope": "unmatched", "kernels": []})
    assert not km.row_matched([km.package_of(krow("C", "y"), sc(PKGS["imgA"])), bad])


def test_read_kernel_owners_refuses_bad_files(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    assert km.read_kernel_owners(d)[0] is None and km.read_kernel_owners(None)[0] is None
    (d / "dpkg-file-owners").write_text("#partial\n" + OWNERS)
    assert km.read_kernel_owners(d) == (None, "the dpkg file lists are partial")
    (d / "dpkg-file-owners").write_text("")
    assert km.read_kernel_owners(d)[0] is None
    (d / "dpkg-file-owners").unlink()
    real = tmp_path / "real"
    real.write_text(OWNERS)
    (d / "dpkg-file-owners").symlink_to(real)                                  # 符號連結不跟隨
    assert km.read_kernel_owners(d)[0] is None
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "dpkg-file-owners").mkdir()
    assert km.read_kernel_owners(tmp_path / "dir")[0] is None


# ===================== 核心列的合併（每個 CVE 一列） =====================

SEVR = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNASSIGNED": 5}


def merge4(per_pkg=None, **common):
    """四個套件的列合併：per_pkg {套件鍵: 欄位覆寫}。"""
    rows = []
    for k, n in PKGS.items():
        r = krow("CVE-M", n, **common)
        r.update((per_pkg or {}).get(k, {}))
        rows.append(r)
    return km.merge_rows(rows, {id(r): pkg_scope(r["name"]) for r in rows}, SEVR), rows


def test_merge_rows_identity_and_packages():
    m, rows = merge4()
    assert [p["name"] for p in m["kernel_packages"]] == [PKGS["imgA"], PKGS["imgB"], PKGS["metaA"], PKGS["metaB"]]       # 有對到核心的在前
    assert m["component"] == PKGS["imgA"] and m["purl"] == PURL.format(PKGS["imgA"]) and m["id"] == "CVE-M" and m["kernel_merge"] == {"members": 4}
    assert [(p["scope"], p["kernels"]) for p in m["kernel_packages"]] == [("kernel", [A]), ("kernel", [B]), ("product", []), ("product", [])]
    assert all(set(p) >= {"name", "component", "version", "purl", "scope", "kernels"} for p in m["kernel_packages"])
    assert [r["component"] for r in rows] == list(PKGS.values())               # 輸入不被改
    assert "kernel_packages" not in rows[0]
    # 輸入順序不影響結果
    r2 = [krow("CVE-M", n) for n in reversed(list(PKGS.values()))]
    m2 = km.merge_rows(r2, {id(r): pkg_scope(r["name"]) for r in r2}, SEVR)
    assert m2["kernel_packages"] == m["kernel_packages"] and m2["component"] == m["component"]
    with pytest.raises(ValueError):
        km.merge_rows(rows[:1], {id(rows[0]): pkg_scope(rows[0]["name"])}, SEVR)


def test_merge_rows_severity_is_the_highest_and_fix_state_is_conservative():
    m, _ = merge4({"metaA": {"severity": "HIGH", "severity_source": "ubuntu-priority", "severity_detail": "d"}, "imgB": {"severity": "LOW"}})
    assert m["severity"] == "HIGH" and m["severity_source"] == "ubuntu-priority" and m["severity_detail"] == "d"
    m, _ = merge4({"imgA": {"severity": "LOW"}, "imgB": {"severity": "CRITICAL"}, "metaA": {"severity": "UNASSIGNED"}})
    assert m["severity"] == "CRITICAL"
    # fix_state：全部 fixed 才是 fixed；有一個不是就不是 fixed（取最需要處理的）
    fx = lambda *st: merge4({k: {"fix_state": s} for k, s in zip(PKGS, st)})[0]["fix_state"]      # noqa: E731
    assert fx("fixed", "fixed", "fixed", "fixed") == "fixed"
    assert fx("fixed", "fixed", "fixed", "not-fixed") == "not-fixed"
    assert fx("fixed", "unknown", "fixed", "fixed") == "unknown" and fx("no Grype data", "fixed", "fixed", "fixed") == "no Grype data"
    assert fx("fixed", "wont-fix", "unknown", "fixed") == "wont-fix" and fx("wont-fix", "not-fixed", "fixed", "fixed") == "not-fixed"
    assert fx("unknown", "no Grype data", "fixed", "fixed") == "unknown"
    for order in itertools.permutations(("fixed", "fixed", "not-fixed", "unknown")):       # 與順序無關
        assert fx(*order) == "not-fixed"
    # 修補版本取聯集；fix_next 只有每一列都有而且相同才留
    m, _ = merge4({"imgA": {"fix_versions": ["1:6.12.40-1"], "fix_next": "1:6.12.40-1"}, "imgB": {"fix_versions": ["1:6.12.41-1"], "fix_next": "1:6.12.40-1"},
                   "metaA": {"fix_versions": [], "fix_next": "1:6.12.40-1"}, "metaB": {"fix_next": "1:6.12.40-1"}})
    assert m["fix_versions"] == ["1:6.12.40-1", "1:6.12.41-1"] and m["fix_next"] == "1:6.12.40-1"
    m, _ = merge4({"imgA": {"fix_next": "1:6.12.40-1"}})
    assert m["fix_next"] is None
    m, _ = merge4(fix_next="1:6.12.40-1", fix_versions=["1:6.12.40-1"])
    assert m["fix_next"] == "1:6.12.40-1" and m["fix_versions"] == ["1:6.12.40-1"]


def test_merge_rows_kev_epss_counts_and_ids():
    m, _ = merge4({"imgB": {"kev": True, "kev_sources": ["DT"]}, "metaA": {"kev": True, "kev_sources": ["same CVE"], "kev_by_cve": True}})
    assert m["kev"] is True and m["kev_sources"] == ["DT", "same CVE"] and m["kev_by_cve"] is True
    m, _ = merge4({"imgA": {"epss": 0.1, "epss_pct": 0.2}, "metaB": {"epss": 0.7, "epss_pct": 0.9}})
    assert (m["epss"], m["epss_pct"]) == (0.7, 0.9)
    m, _ = merge4({"imgA": {"cvss_score": 5.0, "cvss": "5.0 (v3)"}, "imgB": {"cvss_score": 8.1, "cvss": "8.1 (v3)"}})
    assert (m["cvss_score"], m["cvss"]) == (8.1, "8.1 (v3)")
    m, _ = merge4({"imgA": {"source_ids": ["NVD:CVE-M"]}, "imgB": {"source_ids": ["OSV:UBUNTU-CVE-M"]}, "metaA": {"all_ids": ["CVE-M", "GHSA-x"]}})
    assert m["source_ids"] == ["NVD:CVE-M", "OSV:UBUNTU-CVE-M"] and m["all_ids"] == ["CVE-M", "GHSA-x"]
    assert m["n_findings"] == 4


def test_merge_rows_dt_analysis_never_spreads_a_closing_decision():
    """一個套件上的人工排除（DT 的 NOT_AFFECTED）不能代表其他套件：只有部分列有時，關閉弱點的判定不帶進合併的列。"""
    closing = {"state": "NOT_AFFECTED", "suppressed": False, "justification": "CODE_NOT_PRESENT", "response": "", "details": "d", "vuln_id": "CVE-M", "cves": ["CVE-M"]}
    exploit = dict(closing, state="EXPLOITABLE")
    m, _ = merge4({"imgA": {"analysis": [closing]}})
    assert m["analysis"] == [] and m["kernel_merge"]["dropped_analysis"] == [{"state": "NOT_AFFECTED", "vuln_id": "CVE-M"}]
    m, _ = merge4({"imgA": {"analysis": [closing]}, "imgB": {"analysis": [exploit]}})
    assert [a["state"] for a in m["analysis"]] == ["EXPLOITABLE"]                 # 不關閉的判定留著
    m, _ = merge4({k: {"analysis": [closing]} for k in PKGS})                      # 每一列都有同樣的排除：全留
    assert len(m["analysis"]) == 4 and "dropped_analysis" not in m["kernel_merge"]
    r = vx.assess([merged_row("CVE-M", analysis=[])], kcfg=None)[0][0]
    assert r["vex"] is None


# ===================== vex_export：逐顆判定的合併文件、K1、依據 =====================

from test_vex_evidence import KV as K2_KV, ctx as ev_ctx, kmods as ev_kmods, mmap as ev_mmap  # noqa: E402,F401


def results4(**kw):
    return {"CVE-1": "not_affected", "CVE-2": "not_affected", **kw}


def assess_rows(rows, kc, rules=(), **ctx_kw):
    return vx.assess(copy.deepcopy(rows), kcfg=kc, rules=list(rules), rule_ctx=ev_ctx(**ctx_kw))


def test_multi_doc_shape_and_usability():
    d = multi_doc({"CVE-1": "not_affected", "CVE-2": "affected"}, {"CVE-1": "not_affected", "CVE-2": "unknown", "CVE-3": "not_affected"})
    assert d["merged"] is True and d["schema"] == KCFG_SCHEMA and vx.kconfig_usable(d)
    res = {x["cve"]: x for x in d["results"]}
    assert {c: x["decision"] for c, x in res.items()} == {"CVE-1": "not_affected", "CVE-2": "affected", "CVE-3": "unknown"}      # CVE-3：A 沒有結果 → 不排除
    assert res["CVE-3"]["per_kernel"] == {A: "no_result", B: "not_affected"}
    assert [x["version"] for x in d["kernel"]["kernels"]] == [A, B] and d["kernel"]["config_sha256"] is None
    assert vx.kconfig_index(d).keys() == {"CVE-1"} and vx.kconfig_all(d) == {"CVE-1": "not_affected", "CVE-2": "affected", "CVE-3": "unknown"}
    # 少於 2 顆 judged：None（走單顆）
    assert vx.kernel_multi_doc({A: kdoc(A, {"CVE-1": "not_affected"})}, kvdoc(judged=(A,))) is None
    assert vx.kernel_multi_doc({}, None) is None and vx.kernel_multi_doc(None, kvdoc()) is None
    # 版本字串不合法的核心不收（版本會成為路徑）
    assert vx.kernel_multi_doc({}, dict(kvdoc(), judged=[{"version": "a/b"}, {"version": A}])) is None
    # /1、/2 的 judged（字串清單）也讀得懂
    assert vx.kvers_judged({"schema": "sca-center-kernel-versions/2", "judged": [A, B]}) == [A, B]
    assert vx.kvers_judged({"schema": "sca-center-kernel-versions/1", "judged": [A]}) == [A]
    assert vx.kvers_judged(kvdoc()) == [A, B] and vx.kvers_judged({"schema": "x/9", "judged": [A]}) == [] and vx.kvers_judged(None) == []
    assert vx.kvers_shipped(kvdoc()) == [A, B] and vx.kvers_shipped({"schema": KV3, "shipped": None}) is None


def test_unusable_kernel_results_never_exclude():
    for status in ("GAP", "FAIL", "ATTENTION", "NOT_RUN", None):         # ATTENTION 沒有完整的 IKCONFIG：不採用
        d = vx.kernel_multi_doc({A: kdoc(A, {"CVE-1": "not_affected"}), B: kdoc(B, {"CVE-1": "not_affected"}, status=status)}, kvdoc())
        assert {x["cve"]: x["decision"] for x in d["results"]} == {"CVE-1": "unknown"}, status
        assert d["status"] == "ATTENTION"
    d = multi_doc({"CVE-1": "not_affected"}, None)                         # 沒有這顆的檔案
    assert d["results"][0]["decision"] == "unknown" and d["results"][0]["per_kernel"] == {A: "not_affected", B: "no_result"} and d["status"] == "ATTENTION"
    d = multi_doc(None, None)
    assert d["results"] == [] and d["status"] == "GAP"
    d = vx.kernel_multi_doc({A: kdoc(A, {"CVE-1": "not_affected"}, status="GAP"), B: kdoc(B, {"CVE-1": "affected"}, status="FAIL")}, kvdoc())
    assert d["results"] == [] and d["status"] == "GAP" and vx.kconfig_all(d) == {} and vx.kconfig_index(d) == {}     # 沒有任何一顆可採用：沒有逐 CVE 的判定（同單顆）


def test_k1_excludes_only_when_every_kernel_is_not_affected():
    rows = [merged_row(c) for c in ("CVE-1", "CVE-2", "CVE-3", "CVE-4")]
    kc = multi_doc({"CVE-1": "not_affected", "CVE-2": "not_affected", "CVE-3": "not_affected", "CVE-4": "affected"},
                   {"CVE-1": "not_affected", "CVE-2": "affected", "CVE-3": "unknown", "CVE-4": "affected"})
    allr, _, info = assess_rows(rows, kc)
    got = {r["id"]: (r["vex"] or {}).get("state") for r in allr}
    assert got == {"CVE-1": "not_affected", "CVE-2": None, "CVE-3": None, "CVE-4": None}
    s = allr[0]["vex"]
    assert s["source"] == "kconfig" and s["justification"] == "code_not_present"
    assert [(e["type"], e["kernel"]) for e in s["evidence_basis"]] == [("build-record", A), ("build-record", B)]            # 依據逐顆列出
    for e, v in zip(s["evidence_basis"], (A, B)):
        assert e["location"] == f"scan/kernels/{v}/kernel-config.json (kernel {v}, config SHA-256 {SHA[v]})" and ";" not in e["location"]
    assert info["kernel_config"]["used"] is True and [x["version"] for x in info["kernel_config"]["merged_kernels"]] == [A, B]
    # 規則 K1（證據規則）：同樣的結論與依據
    allr, _, info = assess_rows(rows, kc, rules_of(erule("K1", "K1")))
    s = allr[0]["vex"]
    assert s["source"] == "rule" and s["evidence"] == "K1" and [e["kernel"] for e in s["evidence_basis"]] == [A, B]
    assert [r["id"] for r in allr if r["vex"]] == ["CVE-1"]
    assert A in s["rule_inputs"] and B in s["rule_inputs"] and SHA[A][:12] in s["rule_inputs"]


def test_k1_evidence_locations_stay_within_the_limit():
    """一顆核心一筆依據：每筆位置遠小於 vexconv 的 512 字上限，沒有「;」；版本字串到上限（100 字）也一樣。"""
    long_a, long_b = "6." + "a" * 98, "6." + "b" * 98
    docs = {long_a: kdoc(A, {"CVE-1": "not_affected"}, sha="c" * 64), long_b: kdoc(B, {"CVE-1": "not_affected"}, sha="d" * 64)}
    for v, d in docs.items():
        d["kernel"]["version"] = v
    kvs = kvdoc(judged=(long_a, long_b), shipped=(long_a, long_b))
    d = vx.kernel_multi_doc(docs, kvs)
    entries = vx.kcfg_basis_list(d)
    assert len(entries) == 2
    for e in entries:
        assert len(e["location"]) <= vx._vexconv().LOCATION_MAX and ";" not in e["location"] and not vx._vexconv().location_problem(e["location"])
        assert e["kernel"] in (long_a, long_b)
    # 工具自己組的位置超過上限時 safe_location 截斷到 512 字（確定的縮寫方式）、「;」換成「,」
    assert len(vx.safe_location("x" * 900)) == 512 and vx.safe_location("a;b") == "a,b"


def test_scope_incomplete_withholds_merged_exclusions():
    """出貨但沒判定的核心（kernel-versions.json 的 not_judged）：K1／K2 的排除不採用，逐顆判定也一樣。"""
    kvs = kvdoc(not_judged=("6.12.99+rpt-rpi-x",))
    kc = vx.kernel_with_scope(multi_doc(results4(), results4(), kvers=kvs), kvs)
    assert kc["scope_incomplete"] is True and not vx.kconfig_usable(kc)
    allr, _, info = assess_rows([merged_row("CVE-1")], kc, rules_of(erule("K1", "K1")))
    assert allr[0]["vex"] is None and "6.12.99+rpt-rpi-x" in allr[0]["vex_note"] and info["kernel_scope_withheld"] == 1
    allr, _, _ = assess_rows([merged_row("CVE-1")], kc)
    assert allr[0]["vex"] is None
    allr, _, _ = assess_rows([merged_row("CVE-1")], vx.kernel_with_scope(multi_doc(results4(), results4()), kvdoc()))
    assert allr[0]["vex"]["state"] == "not_affected"                       # 對照：沒有 not_judged 時排除


def test_unmatched_package_blocks_exclusion():
    """這一列有一個核心套件對不到判定過的核心（它擁有的核心檔案屬於不是出貨的核心）：不排除。"""
    rows = [krow("CVE-1", n) for n in PKGS.values()]
    scopes = {id(r): pkg_scope(r["name"]) for r in rows}
    scopes[id(rows[2])] = {"scope": "unmatched", "kernels": [], "unknown_kernels": ["9.9.9"]}
    m = km.merge_rows(rows, scopes, SEVR)
    kc = multi_doc(results4(), results4())
    allr, _, _ = assess_rows([m], kc, rules_of(erule("K1", "K1")))
    assert allr[0]["vex"] is None
    assert vx.kconfig_component_matches(m, kc) is False and vx.kconfig_component_matches(merged_row("CVE-1"), kc) is True
    # 沒有 kernel_packages 的列（不是去重的）：舊的比對規則，merged 文件沒有 component → 不套用
    assert vx.kconfig_component_matches(krow("CVE-1", PKGS["imgA"]), kc) is False


def test_single_kernel_doc_with_merged_row():
    """只判定 1 顆核心（單顆文件），但同一個 CVE 在幾個核心套件上：每個套件都要對得到那顆核心或是整個產品，才套用 K1。"""
    from test_vex_export import kcfg as legacy_kcfg
    kc = legacy_kcfg([{"cve": "CVE-1", "decision": "not_affected", "detail": "CONFIG_X is not set"}])
    kc["kernel"]["version"] = A
    row_ok = merged_row("CVE-1")                               # imgA（核心 A）、imgB（核心 B）、兩個 meta：imgB 不是這一顆 → 不套用
    assert vx.kconfig_component_matches(row_ok, kc) is False
    rows = [krow("CVE-1", PKGS["imgA"]), krow("CVE-1", PKGS["metaA"])]
    m = km.merge_rows(rows, {id(rows[0]): pkg_scope(PKGS["imgA"]), id(rows[1]): pkg_scope(PKGS["metaA"])}, SEVR)
    assert vx.kconfig_component_matches(m, kc) is True        # 一顆核心 A 的套件、一個整個產品的 meta 套件
    allr, _, _ = assess_rows([m], kc)
    assert allr[0]["vex"]["state"] == "not_affected" and [e["kernel"] for e in allr[0]["vex"]["evidence_basis"]] == [A]
    kc2 = dict(kc, component={})                               # 單顆文件沒有 component：不套用（同舊的規則）
    assert vx.kconfig_component_matches(m, kc2) is False


# ===================== K2：只用在 kernel-modules.json 的那一顆，其他核心只看 K1 =====================

K2_CVES = {"CVE-RM": {"modules": ["gone_mod"], "builtin": False}, "CVE-LD": {"modules": ["loaded_mod"], "builtin": False}}


def k2_assess(a, b, k2_kernel=A, rows=None, mm_version=None, **kw):
    """逐顆判定的 K2：module map 與 kernel-modules.json 都是 k2_kernel 那一顆的（cra_report 依 kernel-modules.json 的 kernel_version 挑）。"""
    kc = multi_doc(a, b)
    mm = ev_mmap(K2_CVES, version=mm_version or k2_kernel)
    kmo = ev_kmods(kernel_version=k2_kernel)
    return assess_rows(rows or [merged_row("CVE-RM")], kc, rules_of(erule("K1", "K1"), erule("K2", "K2")), module_map=mm, module_map_sha256="9" * 64,
                       kernel_modules=kmo, **kw)


def test_k2_applies_to_one_kernel_and_k1_to_the_others():
    # A 的 K1 說 affected（=m 的模組），B 的 K1 not_affected；kernel-modules.json 是 A 的，模組已移除 → 產品 not_affected
    allr, _, info = k2_assess({"CVE-RM": "affected"}, {"CVE-RM": "not_affected"})
    s = allr[0]["vex"]
    assert s["state"] == "not_affected" and s["evidence"] == "K2" and s["justification"] == "code_not_present"
    kinds = [(e["type"], e["kernel"]) for e in s["evidence_basis"]]
    assert kinds == [("build-record", A), ("build-record", B)]
    locs = {e["kernel"]: e["location"] for e in s["evidence_basis"]}
    assert f"scan/kernels/{A}/kernel-config.json" in locs[A] and f"scan/kernels/{A}/kernel-module-map.json" in locs[A] and "kernel-modules.json" in locs[A]
    assert SHA[A] in locs[A] and "9" * 64 in locs[A]                            # K2 那顆：config、模組對應、映像模組清單各附 SHA-256
    assert locs[B] == f"scan/kernels/{B}/kernel-config.json (kernel {B}, config SHA-256 {SHA[B]})"
    assert all(len(e["location"]) <= 512 and ";" not in e["location"] for e in s["evidence_basis"])
    assert "K1" in s["detail"] and B in s["detail"]
    # 對調：kernel-modules.json 是 B 的
    allr, _, _ = k2_assess({"CVE-RM": "not_affected"}, {"CVE-RM": "affected"}, k2_kernel=B)
    assert allr[0]["vex"]["state"] == "not_affected" and [e["kernel"] for e in allr[0]["vex"]["evidence_basis"]] == [A, B]
    assert f"scan/kernels/{B}/kernel-module-map.json" in allr[0]["vex"]["evidence_basis"][1]["location"]


@pytest.mark.parametrize("other", ["affected", "unknown", None])
def test_k2_does_not_exclude_when_another_kernel_is_not_shown_unaffected(other):
    """K2 只管它那一顆；另一顆的 K1 是 affected／unknown／沒有結果 → 不排除，原因 other_kernels（K2 不適用的核心不能讓合併結果變 not_affected）。"""
    b = {"CVE-RM": other} if other else {"CVE-OTHER": "not_affected"}
    allr, _, info = k2_assess({"CVE-RM": "affected"}, b)
    assert allr[0]["vex"] is None
    k2 = next(x for x in info["rules"] if x["id"] == "K2")
    assert k2["applied"] == 0 and k2["not_applied"] == {"other_kernels": 1}
    assert "covers kernel" in k2["not_applied_sample"][0]["detail"] and "K2 not applied" in k2["not_applied_sample"][0]["detail"]


def test_k2_load_blocked_module_and_loaded_module():
    # 已移除的 CVE-RM 成立；載入中的模組（CVE-LD）K2 本身不成立 → 不排除，不看其他核心
    allr, _, _ = k2_assess({"CVE-RM": "affected", "CVE-LD": "affected"}, {"CVE-RM": "not_affected", "CVE-LD": "not_affected"},
                           rows=[merged_row("CVE-RM"), merged_row("CVE-LD")])
    got = {r["id"]: (r["vex"] or {}).get("state") for r in allr}
    assert got == {"CVE-RM": "not_affected", "CVE-LD": None}


def test_k2_kernel_not_among_judged_or_wrong_module_map():
    allr, _, info = k2_assess({"CVE-RM": "affected"}, {"CVE-RM": "not_affected"}, k2_kernel="9.9.9")
    assert allr[0]["vex"] is None and next(x for x in info["rules"] if x["id"] == "K2")["not_applied"] == {"other_kernels": 1}
    assert "not among the judged kernels" in next(x for x in info["rules"] if x["id"] == "K2")["not_applied_sample"][0]["detail"]
    # kernel-modules.json 是 B 的，module map 卻是 A 的 → 兩者版本不同，K2 的輸入過期（原本的檢查）
    allr, _, info = k2_assess({"CVE-RM": "affected"}, {"CVE-RM": "not_affected"}, k2_kernel=B, mm_version=A)
    assert allr[0]["vex"] is None
    assert info["evidence_inputs"]["kernel_modules"].startswith("CRA/Config/kernel-modules.json is for kernel")


def test_k2_k1_wins_when_k1_already_excludes():
    allr, _, _ = k2_assess({"CVE-RM": "not_affected"}, {"CVE-RM": "not_affected"})
    assert allr[0]["vex"]["evidence"] == "K1"


def test_k2_without_module_map_for_that_kernel_is_not_applied():
    kc = multi_doc({"CVE-RM": "affected"}, {"CVE-RM": "not_affected"})
    allr, _, info = assess_rows([merged_row("CVE-RM")], kc, rules_of(erule("K1", "K1"), erule("K2", "K2")), module_map=None, kernel_modules=ev_kmods(kernel_version=A))
    assert allr[0]["vex"] is None
    assert any(m["code"] == "K4" for m in allr[0]["vex_markers"])


# ===================== 報告：一個 CVE 一列、逐顆結果、VEX 一條陳述 =====================

def test_report_one_row_per_cve_with_kernel_packages(tmp_path):
    a = {"CVE-2026-1001": "not_affected", "CVE-2026-1002": "not_affected", "CVE-2026-1003": "not_affected", "CVE-2026-1004": "not_affected"}
    b = {"CVE-2026-1001": "not_affected", "CVE-2026-1002": "affected", "CVE-2026-1003": "unknown"}          # CVE-2026-1004：B 沒有結果
    sev = {"CVE-2026-1002": {"metaB": "CRITICAL", "imgA": "LOW"}}
    scan = multi_scan(tmp_path, a, b, severities=sev)
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    assert r.returncode in (0, 2), r.stderr
    doc = rows_of(reports)
    rows = {x["id"]: x for x in doc["rows"]}
    assert doc["row_count"] == 4 and sorted(rows) == sorted(a)                          # 16 個 finding（4 CVE × 4 套件）→ 4 列
    for x in rows.values():
        assert [p["name"] for p in x["kernel_packages"]] == [PKGS["imgA"], PKGS["imgB"], PKGS["metaA"], PKGS["metaB"]]
        assert x["is_kernel"] is True and set(x["kernel_results"]) == {A, B}
    assert rows["CVE-2026-1001"]["kernel_results"] == {A: "not_affected", B: "not_affected"}
    assert rows["CVE-2026-1002"]["kernel_results"] == {A: "not_affected", B: "affected"}
    assert rows["CVE-2026-1003"]["kernel_results"] == {A: "not_affected", B: "unknown"}
    assert rows["CVE-2026-1004"]["kernel_results"] == {A: "not_affected", B: "no_result"}
    assert rows["CVE-2026-1002"]["severity"] == "CRITICAL"                              # 嚴重度取最高
    assert rows["CVE-2026-1001"]["vex"]["state"] == "not_affected" and rows["CVE-2026-1001"]["vex"]["source"] == "kconfig"
    for c in ("CVE-2026-1002", "CVE-2026-1003", "CVE-2026-1004"):
        assert rows[c]["vex"] is None                                                   # 有一顆受影響、unknown、沒有結果：不排除
    # VEX：每個 CVE 一條陳述，affects 帶四個套件的 ref
    vulns = vex_of(reports)["vulnerabilities"]
    assert sorted(v["id"] for v in vulns) == sorted(a)
    for v in vulns:
        assert len(v["affects"]) == 4 and len({x["ref"] for x in v["affects"]}) == 4
    assert stmt_of(reports, "CVE-2026-1001")["analysis"]["state"] == "not_affected"
    for c in ("CVE-2026-1002", "CVE-2026-1003", "CVE-2026-1004"):
        v = stmt_of(reports, c)
        assert v["analysis"]["state"] == "in_triage" and {"name": "dumpling:assessment", "value": "NOT_ASSESSED"} in v["properties"]
    ev = [(p["name"], p["value"]) for p in stmt_of(reports, "CVE-2026-1001")["properties"] if p["name"].startswith("dumpling:evidence")]
    assert [x for x in ev if x[0] == "dumpling:evidence"] == [("dumpling:evidence", "build-record")] * 2
    assert [x[1] for x in ev if x[0] == "dumpling:evidence-kernel"] == [A, B]
    # summary：去重與逐顆判定
    assert s["counts"]["kernel_dedupe"]["merged_rows"] == 4 and s["counts"]["kernel_dedupe"]["rows_before"] == 16 and s["counts"]["kernel_dedupe"]["rows_after"] == 4
    assert [x["version"] for x in s["counts"]["kernel_judged"]] == [A, B] and s["counts"]["kernel_judged"][0]["basis"] == "auto-detected"
    assert s["counts"]["kernel"]["rows"] == 4 and s["vex"]["kernel_config"]["merged_kernels"][1]["version"] == B
    assert f"scan/kernels/{A}/kernel-config.json" in s["inputs"] and s["inputs"][f"scan/kernels/{A}/kernel-config.json"]["sha256"]
    # 報告：kernel-vulnerabilities.md 逐顆寫結果、列出判定了哪幾顆與依據
    md = (reports / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    assert "Kernels judged one by one" in md and "auto-detected (listed by the image)" in md and "Per-kernel result (K1)" in md
    line = next(x for x in md.splitlines() if "CVE-2026-1002" in x and x.startswith("| "))
    assert f"{A}: not built in the kernel; {B}: affected" in line and "+3 more kernel packages" in line
    risk = (reports / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Kernels judged one by one" in risk and "Each kernel CVE is listed once" in risk


def test_report_eight_packages_one_cve_one_row_eight_refs(tmp_path):
    """8 個核心套件 × 同一個 CVE → 1 列，affects 帶 8 個 ref。"""
    eight = {"imgA": f"linux-image-{A}", "imgB": f"linux-image-{B}", "metaA": "linux-image-rpi-2712", "metaB": "linux-image-rpi-v8",
             "unsA": f"linux-image-{A}-unsigned", "unsB": f"linux-image-{B}-unsigned", "modA": f"linux-modules-{A}", "modB": f"linux-modules-{B}"}
    cves = ["CVE-2026-2001", "CVE-2026-2002"]
    findings = [finding(n, VER, c, "NVD", "MEDIUM", purl=PURL.format(n)) for c in cves for n in eight.values()]
    own = "".join(f"{eight[k]}\t/usr/lib/modules/{v}/kernel/foo.ko\n" for k, v in (("imgA", A), ("imgB", B), ("modA", A), ("modB", B)))
    scan = make_scan(tmp_path / "s", findings=findings, grype=grype_of(cves, list(eight.values())), sbom=sbom_of(list(eight.values())),
                     stages={"C-kernel-coverage": "OK", "C-kernel-config": "OK", "C-kernel-module-map": "OK"})
    write_json(scan / "scan" / "kernel-versions.json", kvdoc())
    for v in (A, B):
        write_json(scan / "scan" / "kernels" / v / "kernel-config.json", kdoc(v, dict.fromkeys(cves, "not_affected")))
    (tmp_path / "pkgdb").mkdir()
    (tmp_path / "pkgdb" / "dpkg-status").write_text("Package: x\n\n")
    (tmp_path / "pkgdb" / "dpkg-file-owners").write_text(own)
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    doc = rows_of(reports)
    assert doc["row_count"] == 2 and all(len(x["kernel_packages"]) == 8 for x in doc["rows"])
    assert s["counts"]["kernel_dedupe"]["rows_before"] == 16 and s["counts"]["kernel_dedupe"]["rows_after"] == 2
    for c in cves:
        v = stmt_of(reports, c)
        assert len(v["affects"]) == 8 and len({x["ref"] for x in v["affects"]}) == 8 and v["analysis"]["state"] == "not_affected"
    assert len([v for v in vex_of(reports)["vulnerabilities"] if v["id"] == cves[0]]) == 1
    sc = {p["name"]: (p["scope"], p["kernels"]) for p in doc["rows"][0]["kernel_packages"]}
    assert sc[eight["modA"]] == ("kernel", [A]) and sc[eight["unsB"]] == ("product", []) and sc[eight["metaA"]] == ("product", [])


def test_report_without_file_lists_every_package_counts_as_the_whole_product(tmp_path):
    a = {"CVE-2026-1001": "not_affected"}
    scan = multi_scan(tmp_path, a, dict(a), owners=None)
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    doc = rows_of(reports)
    assert {p["scope"] for p in doc["rows"][0]["kernel_packages"]} == {"product"} and doc["rows"][0]["vex"]["state"] == "not_affected"
    assert s["counts"]["kernel_dedupe"]["owners"] is None and s["counts"]["kernel_dedupe"]["owners_problem"]


def test_report_package_with_files_of_a_kernel_that_is_not_shipped_is_not_excluded(tmp_path):
    a = {"CVE-2026-1001": "not_affected"}
    own = OWNERS + f"{PKGS['metaA']}\t/usr/lib/modules/9.9.9/kernel/foo.ko\n"
    scan = multi_scan(tmp_path, a, dict(a), owners=own)
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    x = rows_of(reports)["rows"][0]
    assert x["vex"] is None and next(p for p in x["kernel_packages"] if p["name"] == PKGS["metaA"])["scope"] == "unmatched"
    assert s["counts"]["kernel_dedupe"]["packages_unmatched"] == [PKGS["metaA"]]


def test_report_not_judged_kernel_withholds_all_exclusions(tmp_path):
    a = {"CVE-2026-1001": "not_affected"}
    kvs = kvdoc(judged=(A, B), shipped=(A, B, "6.12.99+rpt-rpi-x"), not_judged=("6.12.99+rpt-rpi-x",))
    scan = multi_scan(tmp_path, a, dict(a), kvers=kvs)
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    x = rows_of(reports)["rows"][0]
    assert x["vex"] is None and x["kernel_results"] == {A: "not_affected", B: "not_affected", "6.12.99+rpt-rpi-x": "not_judged"}
    assert s["vex"]["kernel_config"]["scope_incomplete"] is True
    md = (reports / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    assert "not judged" in md and "Shipped but not judged" in md and "6.12.99+rpt-rpi-x" in md


def test_report_missing_per_kernel_file_does_not_exclude(tmp_path):
    a = {"CVE-2026-1001": "not_affected"}
    scan = multi_scan(tmp_path, a, None)
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    x = rows_of(reports)["rows"][0]
    assert x["vex"] is None and x["kernel_results"] == {A: "not_affected", B: "no_result"}


def test_report_one_judged_kernel_keeps_the_single_kernel_files_and_sections(tmp_path):
    """judged 只有 1 顆：不用 scan/kernels/，沒有逐顆判定的表與 per-kernel 欄位（和以前相同）；同一個 CVE 的多個核心套件仍合併成一列。"""
    from test_vex_export import kcfg as legacy_kcfg
    a = {"CVE-2026-1001": "not_affected"}
    scan = multi_scan(tmp_path, a, None, kvers=kvdoc(judged=(A,), shipped=(A,)), with_docs=False)
    d = legacy_kcfg([{"cve": "CVE-2026-1001", "decision": "not_affected", "detail": "CONFIG_X is not set"}])
    d["kernel"]["version"] = A
    d["component"] = {"name": PKGS["imgA"], "version": VER, "purl": PURL.format(PKGS["imgA"])}
    write_json(scan / "scan" / "kernel-config.json", d)
    own = f"{PKGS['imgA']}\t/usr/lib/modules/{A}/kernel/foo.ko\n"
    (tmp_path / "pkgdb").mkdir(exist_ok=True)
    (tmp_path / "pkgdb" / "dpkg-file-owners").write_text(own)
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    doc = rows_of(reports)
    x = doc["rows"][0]
    assert doc["row_count"] == 1 and len(x["kernel_packages"]) == 4 and "kernel_results" not in x       # 去重了，但沒有逐顆結果
    assert x["vex"]["state"] == "not_affected" and [e for e in stmt_of(reports, "CVE-2026-1001")["properties"] if e["name"] == "dumpling:evidence-kernel"] == \
        [{"name": "dumpling:evidence-kernel", "value": A}]
    md = (reports / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    assert "Kernels judged one by one" not in md and "Per-kernel result" not in md
    assert "kernel_judged" not in s["counts"]


# ===================== 客戶版、vexconv、xlsx、證據包、待確認事項 =====================

def test_customer_view_has_only_the_merged_conclusion_and_the_evidence_type(tmp_path):
    import supplier_package as sp
    a = {"CVE-2026-1001": "not_affected", "CVE-2026-1002": "not_affected"}
    b = {"CVE-2026-1001": "not_affected", "CVE-2026-1002": "affected"}
    r, s, reports = run(make_project(tmp_path / "p"), multi_scan(tmp_path, a, b))
    out = sp.customer_cdx(vex_of(reports))
    by = {v["id"]: v for v in out["vulnerabilities"]}
    d = by["CVE-2026-1001"]["analysis"]
    assert d["detail"] == "The affected code is not built into the shipped kernel (kernel build configuration). Evidence: build artifacts."      # D-057 的固定句
    assert len(by["CVE-2026-1001"]["affects"]) == 4
    text = json.dumps([{k: v for k, v in x.items() if k != "affects"} for x in out["vulnerabilities"]])       # affects 的 ref 是 SBOM 元件的 bom-ref（套件名稱）
    for internal in (A, B, "scan/kernels", "kernel-config.json", "SHA-256", "dumpling", "sca-scan"):
        assert internal not in text, internal
    assert by["CVE-2026-1002"]["analysis"]["state"] == "in_triage" and by["CVE-2026-1002"]["analysis"]["detail"] == "Not yet assessed by the manufacturer"
    # 內部 OpenVEX 的依據行：一顆核心一行；位置不超過上限、沒有分號；vexconv 轉回 CycloneDX 的屬性一致
    ov = json.loads((reports / "vex.openvex.json").read_text(encoding="utf-8"))
    st = next(x for x in ov["statements"] if x["vulnerability"]["name"] == "CVE-2026-1001")
    lines = [l for l in st["status_notes"].splitlines() if l.startswith("dumpling: evidence=")]
    assert len(lines) == 2 and [l.split("; ")[1] for l in lines] == [f"kernel={A}", f"kernel={B}"]
    assert len(st["products"]) == 4
    vc = vx._vexconv()
    for l in lines:
        loc = l.split("location=", 1)[1]
        assert not vc.location_problem(loc) and len(loc) <= vc.LOCATION_MAX


def test_vexconv_round_trip_keeps_one_evidence_group_per_kernel(tmp_path):
    vc = vx._vexconv()
    a = {"CVE-2026-1001": "not_affected"}
    r, s, reports = run(make_project(tmp_path / "p"), multi_scan(tmp_path, a, dict(a)))
    cdx = vex_of(reports)
    back = [(p["name"], p["value"]) for p in stmt_of(reports, "CVE-2026-1001")["properties"] if p["name"].startswith("dumpling:evidence")]
    assert [x for x in back if x[0] == vc.PROP_EVIDENCE_KERNEL] == [(vc.PROP_EVIDENCE_KERNEL, A), (vc.PROP_EVIDENCE_KERNEL, B)]
    assert [x for x in back if x[0] == vc.PROP_EVIDENCE_LOCATION][0][1].startswith(f"scan/kernels/{A}/kernel-config.json")
    assert cdx["vulnerabilities"][0]["affects"] and len(cdx["vulnerabilities"]) == 1


def test_report_package_xlsx_shows_all_packages_and_per_kernel_results(tmp_path):
    import zipfile
    import report_package as rp
    a = {"CVE-2026-1001": "not_affected", "CVE-2026-1002": "not_affected"}
    b = {"CVE-2026-1001": "not_affected", "CVE-2026-1002": "affected"}
    proj = make_project(tmp_path / "p")
    run(proj, multi_scan(tmp_path, a, b, severities={"CVE-2026-1002": {"imgA": "CRITICAL"}}))
    out = tmp_path / "pkg-out"
    code, msgs = rp.build(proj, out, allow_tmp=True)
    assert code in (0, 2), msgs
    z = zipfile.ZipFile(out / "交給PM" / "漏洞清單.xlsx")
    xml = " ".join(z.read(n).decode("utf-8", "replace") for n in z.namelist() if n.endswith(".xml"))
    assert "另有 3 個核心套件" in xml and f"{A}：沒編進核心；{B}：受影響" in xml
    z = zipfile.ZipFile(out / "給RD" / "P1判斷表.xlsx")
    assert z.namelist()


def test_evidence_bundle_includes_per_kernel_results(tmp_path):
    import evidence_bundle as eb
    root = tmp_path / "res"
    a = {"CVE-2026-1001": "not_affected"}
    scan = multi_scan(tmp_path, a, dict(a))
    (scan / "scan" / "kernels" / "a;b").mkdir(parents=True)
    (scan / "scan" / "kernels" / "a;b" / "kernel-config.json").write_text("{}")
    st = eb.Stager(tmp_path / "stage", dict(eb.LIMITS))
    (tmp_path / "stage").mkdir()
    fd = __import__("os").open(scan, __import__("os").O_RDONLY)
    try:
        st.add_scan(fd, "", "scan-out")
    finally:
        __import__("os").close(fd)
    names = sorted(st.files)
    assert f"scan-out/scan/kernels/{A}/kernel-config.json" in names and f"scan-out/scan/kernels/{B}/kernel-config.json" in names
    assert not any("a;b" in n for n in names) and any("a;b" in x["path"] and "合法的核心版本" in x["reason"] for x in st.skipped)


def test_confirm_item_reads_schema_3_judged_objects():
    import confirm_items as ci
    d = kvdoc(judged=(A,), shipped=(A, B), not_judged=(B,), basis="project-specified")
    x = ci.kernel_versions_items(d)
    assert len(x) == 1 and f"（{A}）" in x[0]["impact"] and B in x[0]["finding"] and "設計文件" in x[0]["suggestion"] and "多顆逐一判定還沒實作" not in x[0]["suggestion"]
    assert ci.kernel_versions_items(kvdoc()) == []                                       # 兩顆都判定：不問


# ===================== 人的判定與批次規則不跨套件擴大 =====================

def ann(state, purl=None, cve="CVE-M", **kw):
    a = {"cve": cve, "state": state, "detail": "d", "author": "Alice", "date": "2026-11-01"}
    if purl:
        a["purl"] = purl
    a.update(kw)
    return a


def test_annotations_do_not_spread_a_closing_decision_to_other_packages():
    m, _ = merge4()
    one = PURL.format(PKGS["imgA"]).split("?")[0].split("@")[0]
    # 排除（not_affected）只對上一個套件：不適用於合併的列；其他套件也要有判定（每個套件都對上才算）
    assert vx.annotation_matches(ann("not_affected", one, justification="code_not_present"), m) is False
    # 會讓列保持未解決的判定（exploitable）：有一個套件對上就算（偏保守）
    assert vx.annotation_matches(ann("exploitable", one, response=["update"]), m) is True
    # 沒有 purl（整個 CVE）的判定：每個套件都對上
    assert vx.annotation_matches(ann("exploitable"), m) is True
    # 單一套件的列：和以前相同
    single = krow("CVE-M", PKGS["imgA"])
    assert vx.annotation_matches(ann("not_affected", one, justification="code_not_present"), single) is True
    allr, _, _ = vx.assess([m], annotations=[ann("not_affected", one, justification="code_not_present", detail="only this package")])
    assert allr[0]["vex"] is None


def test_bulk_rule_purl_conditions_must_hold_for_every_package():
    m, _ = merge4()
    rule = {"match": {"scope": "kernel", "purl_prefix": ["pkg:deb/debian/linux-image-6"]}}
    assert vx.rule_criteria(rule, m, None) is False                              # meta 套件（linux-image-rpi-*）不在前綴下
    rule = {"match": {"scope": "kernel", "purl_prefix": ["pkg:deb/debian/linux-image"]}}
    assert vx.rule_criteria(rule, m, None) is True
    assert vx.rule_criteria({"match": {"scope": "kernel", "purl_type": ["deb"]}}, m, None) is True
    assert vx.rule_criteria({"match": {"scope": "kernel", "purl_type": ["npm"]}}, m, None) is False
    assert vx.rule_criteria({"match": {"scope": "kernel", "purl_prefix": ["pkg:deb/debian/linux-image-6"]}}, krow("CVE-M", PKGS["imgA"]), None) is True


def test_scope_without_a_shipped_kernel_list_does_not_invent_unmatched():
    owners = {PKGS["imgA"]: {A}}
    assert km.package_scope(PKGS["imgA"], owners, None) == {"scope": "kernel", "kernels": [A]}          # 舊掃描沒有 kernel-versions.json：不核對
    assert km.package_scope(PKGS["imgA"], owners, [B])["scope"] == "unmatched"
    assert km.package_scope(PKGS["imgA"], owners, [])["scope"] == "unmatched"


def test_report_without_kernel_versions_file_still_merges_duplicates(tmp_path):
    """沒有 kernel-versions.json 的掃描（舊的、或只有一顆核心沒有記）：同一個 CVE 的多個核心套件仍合併成一列；單顆文件的 K1 要每個套件對得到那顆核心或整個產品。"""
    from test_vex_export import kcfg as legacy_kcfg
    scan = multi_scan(tmp_path, {"CVE-2026-1001": "not_affected"}, None, kvers=False, with_docs=False, names=[PKGS["imgA"], PKGS["metaA"]])
    d = legacy_kcfg([{"cve": "CVE-2026-1001", "decision": "not_affected", "detail": "CONFIG_X is not set"}])
    d["kernel"]["version"] = A
    d["component"] = {"name": PKGS["imgA"], "version": VER, "purl": PURL.format(PKGS["imgA"])}
    write_json(scan / "scan" / "kernel-config.json", d)
    r, s, reports = run(make_project(tmp_path / "p"), scan)
    doc = rows_of(reports)
    assert doc["row_count"] == 1 and len(doc["rows"][0]["kernel_packages"]) == 2 and "kernel_results" not in doc["rows"][0]
    assert doc["rows"][0]["vex"]["state"] == "not_affected" and s["counts"]["kernel_dedupe"]["shipped"] is None


def test_scope_of_reads_schema_3():
    d = kvdoc(judged=(A,), shipped=(A, B), not_judged=(B,), basis="project-specified")
    assert vx.kernel_scope_of(d) == {"judged": [A], "not_judged": [B]}
    assert vx.kernel_scope_of(kvdoc()) is None                                         # 兩顆都判定：沒有範圍限制
    n = vx.kernel_scope_note(vx.kernel_with_scope(multi_doc(results4(), results4()), kvdoc(judged=(A, B), shipped=(A, B, "6.12.99+rpt-rpi-x"),
                                                                                       not_judged=("6.12.99+rpt-rpi-x",))))
    assert "6.12.99+rpt-rpi-x shipped but was not judged" in n and A in n and B in n


def test_judged_but_not_shipped_kernel_does_not_block_and_unknown_shipped_does():
    """指定了但映像沒有的核心（沒有結果）不擋排除；出貨清單不明（null）時一律不排除（不知道有沒有別顆）。"""
    ghost = "6.99.0-ghost"
    docs = {A: kdoc(A, {"CVE-1": "not_affected"}), B: kdoc(B, {"CVE-1": "not_affected"}), ghost: None}
    d = vx.kernel_multi_doc(docs, kvdoc(judged=(A, B, ghost), shipped=(A, B)))
    assert d["results"][0]["decision"] == "not_affected" and d["results"][0]["per_kernel"][ghost] == "no_result"
    d = vx.kernel_multi_doc({A: kdoc(A, {"CVE-1": "not_affected"}), B: kdoc(B, {"CVE-1": "not_affected"}), ghost: kdoc(B, {"CVE-1": "affected"})},
                            kvdoc(judged=(A, B, ghost), shipped=(A, B)))
    assert d["results"][0]["decision"] == "affected"
    kv = dict(kvdoc(), shipped=None)
    d = vx.kernel_multi_doc({A: kdoc(A, {"CVE-1": "not_affected"}), B: kdoc(B, {"CVE-1": "not_affected"})}, kv)
    assert d["results"][0]["decision"] == "unknown"
    d = vx.kernel_multi_doc({A: kdoc(A, {"CVE-1": "affected"}), B: kdoc(B, {"CVE-1": "not_affected"})}, kv)
    assert d["results"][0]["decision"] == "affected"
