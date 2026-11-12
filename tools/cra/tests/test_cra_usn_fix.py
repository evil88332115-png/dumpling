"""cra_report.py：自成一列的 USN（沒有 CVE 別名）的修補狀態取自 USN 的修補版本（scan/usn-cves.json 的 fixed；apply_usn_fix）。
USN 是 Ubuntu 發布修補版本的公告：映像的 Ubuntu 版本裡這個原始碼套件的修補版本 V，安裝的比 V 舊 → fixed、{fix_version} V（R3）；
一樣或比較新 → 已修好。全部是合成資料。"""
import json
import sys
from pathlib import Path

from test_cra_report import MIN_CFG, SBOM, finding, make_project, make_scan, rows_for, run, write_json
from test_cra_ubuntu_tracker_fix import RULES

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cra_report as cr  # noqa: E402
import vex_export as vx  # noqa: E402

U24 = "distro=ubuntu-24.04"
APT = f"pkg:deb/ubuntu/apt@2.8.3?arch=arm64&{U24}"
CURL = f"pkg:deb/ubuntu/curl@8.5.0-2ubuntu10.10?arch=source&{U24}"
SSL = f"pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.11?arch=arm64&upstream=openssl&{U24}"
XZ = f"pkg:deb/ubuntu/liblzma5@5.4.5-0.3?arch=arm64&{U24}"
KERN = f"pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&{U24}"
FINDS = [finding("apt", "2.8.3", "USN-8996-1", "OSV", "UNASSIGNED", purl=APT),
         finding("curl", "8.5.0-2ubuntu10.10", "USN-8525-1", "OSV", "UNASSIGNED", purl=CURL),
         finding("libssl3t64", "3.0.13-0ubuntu3.11", "USN-9001-1", "OSV", "UNASSIGNED", purl=SSL),
         finding("liblzma5", "5.4.5-0.3", "USN-9002-1", "OSV", "UNASSIGNED", purl=XZ),
         finding("apt", "2.8.3", "USN-9003-1", "OSV", "UNASSIGNED", purl=APT),
         finding("apt", "2.8.3", "USN-9004-1", "OSV", "UNASSIGNED", purl=APT),
         finding("linux-nvidia-tegra", "6.8.0-1021.21", "USN-9005-1", "OSV", "UNASSIGNED", purl=KERN)]
SBOMX = dict(SBOM, components=SBOM["components"] + [
    {"type": "library", "name": "liblzma5", "version": "5.4.5-0.3", "purl": XZ,
     "properties": [{"name": "syft:metadata:source", "value": "xz-utils"}, {"name": "syft:metadata:sourceVersion", "value": "5.4.5-0.3"}]}])


def F(pkg, ver, eco="Ubuntu:24.04:LTS"):
    return {"ecosystem": eco, "package": pkg, "fixed": [ver]}


def udoc(status="OK", fixed=None):
    return {"schema": "sca-center-usn-cves/1", "status": status, "mirror": {"fetched_utc": "2026-11-06T01:12:04Z"},
            "usns": {"USN-8996-1": {"cves": ["CVE-2026-109518"], "modified": "2026-11-05T11:58:19Z"}},
            "fixed": fixed if fixed is not None else {
                "USN-8996-1": [F("apt", "1.0.1ubuntu2.24+esm4", "Ubuntu:Pro:14.04:LTS"), F("apt", "2.8.3ubuntu0.1"), F("apt", "2.4.14", "Ubuntu:22.04:LTS")],
                "USN-8525-1": [F("curl", "8.5.0-2ubuntu10.10")],                       # 安裝的就是修好的版本
                "USN-9001-1": [F("openssl", "3.0.13-0ubuntu3.12")],                    # 二進位 libssl3t64 的原始碼套件
                "USN-9002-1": [F("xz-utils", "5.4.5-0.3ubuntu0.1")],                   # SBOM 的 syft:metadata:source
                "USN-9003-1": [F("apt", "2.8.4", "Ubuntu:Pro:24.04:LTS")],             # 只有 Pro：不推
                "USN-9005-1": [F("linux-nvidia-tegra", "6.8.0-1030.33")]}}


def rows(doc=None, comps=SBOMX["components"]):
    rs = rows_for(MIN_CFG, FINDS, {"matches": []})
    for r in rs:
        r["kernel"] = r["component"].startswith("linux")
    info = cr.apply_usn_fix(rs, udoc() if doc is None else doc, comps)
    return {r["id"]: r for r in rs}, info


def test_usn_rows_get_the_notice_fix_version():
    r, info = rows()
    a = r["USN-8996-1"]
    assert (a["fix_state"], a["fix_versions"], a["fix_next"], a["fix_state_source"]) == ("fixed", ["2.8.3ubuntu0.1"], "2.8.3ubuntu0.1", "usn")
    assert a["usn"] == {"id": "USN-8996-1", "package": "apt", "ecosystem": "Ubuntu:24.04:LTS", "fixed": "2.8.3ubuntu0.1",
                        "source_version": "2.8.3", "modified": "2026-11-05", "fetched_utc": "2026-11-06T01:12:04Z"}
    assert a["fix_state_detail"] == ("fix state from Ubuntu security notice USN-8996-1 (OSV record modified 2026-11-05, mirror fetched "
                                     "2026-11-06): fixed in 2.8.3ubuntu0.1 for source package apt in Ubuntu:24.04:LTS, installed source version 2.8.3")
    assert a["fix"].startswith("fixed in 2.8.3ubuntu0.1 (fix state from Ubuntu security notice USN-8996-1")
    c = r["USN-8525-1"]
    assert (c["fix_state"], c["fix_next"]) == ("fixed", None) and c["fix"].startswith("already fixed in the installed source version")
    assert r["USN-9001-1"]["usn"]["package"] == "openssl" and r["USN-9001-1"]["fix_next"] == "3.0.13-0ubuntu3.12"
    assert r["USN-9002-1"]["usn"]["package"] == "xz-utils" and r["USN-9002-1"]["fix_next"] == "5.4.5-0.3ubuntu0.1"
    for u in ("USN-9003-1", "USN-9004-1", "USN-9005-1"):             # 只有 Pro、紀錄沒有修補版本、核心
        assert r[u]["fix_state"] == "no Grype data" and "fix_state_source" not in r[u], u
    assert info == {"status": "OK", "derived": 4, "already_fixed": 1, "not_derived": {"no_fixed_version_in_record": 1, "package_not_in_record": 1}}


def test_usn_source_package_must_be_known():
    # 二進位名稱和 USN 的套件不同、SBOM 也沒有 source → 不知道原始碼套件，不推（不用二進位名稱猜別的套件）
    r, info = rows(comps=[])
    assert r["USN-9002-1"]["fix_state"] == "no Grype data" and info["not_derived"]["package_not_in_record"] == 2
    # 同一個發行版與套件有不同的修補版本 → 不推
    d = udoc(fixed={"USN-8996-1": [F("apt", "2.8.3ubuntu0.1"), {"ecosystem": "Ubuntu:24.04", "package": "apt", "fixed": ["2.8.3ubuntu0.2"]}]})
    r, info = rows(d)
    assert r["USN-8996-1"]["fix_state"] == "no Grype data" and info["not_derived"] == {"ambiguous": 1, "no_fixed_version_in_record": 5}


def test_no_usable_usn_file_changes_nothing():
    for d in (None, {"status": "OK", "usns": {}}, udoc(status="NOT_RUN"), {"status": "OK", "fixed": []}):
        rs = rows_for(MIN_CFG, FINDS, {"matches": []})
        info = cr.apply_usn_fix(rs, d, SBOMX["components"])
        assert info["status"] == "not_available" and all("fix_state_source" not in x for x in rs)
    # 有 CVE 的列（USN 併進 CVE 的列，或一般的 CVE 列）不動
    rs = rows_for(MIN_CFG, [finding("apt", "2.8.3", "CVE-2026-109518", purl=APT)], {"matches": []})
    for x in rs:
        x["kernel"] = False
    assert cr.apply_usn_fix(rs, udoc(), [])["derived"] == 0


def test_report_applies_r3_to_usn_rows(tmp_path):
    proj = make_project(tmp_path / "p")
    write_json(proj / vx.RULES_REL, RULES)
    sc = make_scan(tmp_path / "s", findings=FINDS, grype={"matches": []}, sbom=SBOMX)
    r0, s0, _ = run(proj, sc)
    assert r0.returncode in (0, 2), r0.stdout + r0.stderr
    assert "usn_fix" not in s0 and {x["id"]: x["applied"] for x in s0["vex"]["rules"]["rules"]}["R3"] == 0
    write_json(sc / "scan" / "usn-cves.json", udoc())
    r, s, rep = run(proj, sc)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    assert {x["id"]: x["applied"] for x in s["vex"]["rules"]["rules"]}["R3"] == 3 and s["usn_fix"]["derived"] == 4
    assert {k: s["counts"][k] for k in ("p1", "p2", "p3", "accepted")} == {k: s0["counts"][k] for k in ("p1", "p2", "p3", "accepted")}
    det = {v["id"]: v["analysis"].get("detail", "") for v in json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))["vulnerabilities"]}
    assert det["USN-8996-1"].startswith("Fixed in apt 2.8.3ubuntu0.1 (installed 2.8.3). Fix state from Ubuntu security notice USN-8996-1")
    assert det["USN-8996-1"].endswith("(bulk rule R3: Ubuntu package: newer fixed package available)")
    assert "USN-8525-1" not in det                                    # 已修好：R3 沒有 {fix_version}，不套用
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Fix state for 4 Ubuntu security notice rows without a CVE is taken from the fixed version in the notice" in md
