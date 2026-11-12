"""cra_report.py：Ubuntu 打包的 Python 模組（/usr/lib/python3/dist-packages）與沒有 CVE 別名的 USN（scan/usn-cves.json）。

- Ubuntu 打包的 Python 模組不是 pip 管理的：列保留，指向擁有它的 deb 套件與版本，修補欄指向 Ubuntu 套件，批次規則不套用。
- 沒有 CVE 別名的 USN 併進同一個元件版本上它列出的 CVE 的列；沒有對應檔時照舊，報告寫明對應不可用。
- 每一筆 DT finding 的編號都剛好出現在一列的 source_ids。
"""
import json
import sys
from collections import Counter
from pathlib import Path

from test_cra_report import FINDINGS, GRYPE, MIN_CFG, SBOM, finding, make_project, make_scan, rows_for, run, write_json

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cra_report as cr  # noqa: E402
import vex_export as vx  # noqa: E402

U24 = "distro=ubuntu-24.04"
DP = "/usr/lib/python3/dist-packages"
CVE_B = "CVE-2026-111497"


def loc(c, *paths):
    return dict(c, properties=[{"name": f"syft:location:{i}:path", "value": p} for i, p in enumerate(paths)])


def pyc(name, ver, *paths):
    return loc({"type": "library", "name": name, "version": ver, "purl": f"pkg:pypi/{name}@{ver}"}, *paths)


def debc(name, ver, upstream=None, arch="all"):
    q = f"?arch={arch}&{U24}" + (f"&upstream={upstream}" if upstream else "")
    return {"type": "library", "name": name, "version": ver, "purl": f"pkg:deb/ubuntu/{name}@{ver}{q}"}


# 合成的 SBOM：Ubuntu 打包的 mpmath（egg-info 版本 0.0.0）與 brotli、pip 裝的 requests、兩份都有的 six、找不到擁有者的 foo、
# 兩個可能擁有者的 bar、用 pip 裝進 dist-packages 的新版 urllib3（版本和 python3-urllib3 不同）
DSBOM = dict(SBOM, components=[
    pyc("mpmath", "0.0.0", f"{DP}/mpmath-0.0.0.egg-info/PKG-INFO"),
    debc("python3-mpmath", "1.2.1-3", "mpmath"),
    pyc("brotli", "1.1.0", f"{DP}/Brotli-1.1.0.egg-info"),
    debc("python3-brotli", "1.1.0-2build2", "brotli", arch="arm64"),
    pyc("requests", "2.31.0", "/usr/local/lib/python3.12/dist-packages/requests-2.31.0.dist-info/METADATA"),
    debc("python3-requests", "2.31.0+dfsg-1ubuntu1", "requests"),
    pyc("six", "1.16.0", f"{DP}/six-1.16.0.egg-info"), pyc("six", "1.16.0", "/opt/venv/lib/python3.12/site-packages/six.dist-info/METADATA"),
    pyc("foo", "0.0.0", f"{DP}/foo-0.0.0.egg-info"),
    pyc("bar", "1.0", f"{DP}/bar-1.0.egg-info"),
    debc("python3-bar-a", "1.0-1", "bar"), debc("python3-bar-b", "1.0-2", "bar"),
    pyc("urllib3", "2.2.3", f"{DP}/urllib3-2.2.3.dist-info/METADATA"),
    debc("python3-urllib3", "2.0.7-1ubuntu0.1", "python-urllib3"),
    debc("openssl", "3.0.13-0ubuntu3.11", arch="arm64"),
])
SRC = "pkg:deb/ubuntu/brotli@1.1.0-2build2?arch=source&" + U24
DFINDINGS = [
    finding("brotli", "1.1.0", "GHSA-9v8h-qqgm-4m35", "GITHUB", "HIGH", [{"cveId": CVE_B}], purl="pkg:pypi/brotli@1.1.0"),
    finding("mpmath", "0.0.0", "GHSA-mpmp-mpmp-mpmp", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-2001"}], purl="pkg:pypi/mpmath@0.0.0"),
    finding("requests", "2.31.0", "GHSA-rrrr-rrrr-rrrr", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-2002"}], purl="pkg:pypi/requests@2.31.0"),
    finding("foo", "0.0.0", "GHSA-ffff-ffff-ffff", "GITHUB", "LOW", [{"cveId": "CVE-2026-2003"}], purl="pkg:pypi/foo@0.0.0"),
    finding("urllib3", "2.2.3", "GHSA-uuuu-uuuu-uuuu", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-2004"}], purl="pkg:pypi/urllib3@2.2.3"),
    # 擁有 brotli 的原始碼套件上同一個 CVE（Ubuntu 的紀錄）
    finding("brotli", "1.1.0-2build2", f"UBUNTU-{CVE_B}", "OSV", "HIGH", [{"cveId": CVE_B}], purl=SRC),
]
DGRYPE = {"matches": [
    {"vulnerability": {"id": "GHSA-ffff-ffff-ffff", "fix": {"state": "fixed", "versions": ["0.1.0"]}},
     "relatedVulnerabilities": [{"id": "CVE-2026-2003"}], "artifact": {"name": "foo", "version": "0.0.0", "type": "python"}},
    {"vulnerability": {"id": "GHSA-uuuu-uuuu-uuuu", "fix": {"state": "fixed", "versions": ["2.3.0"]}},
     "relatedVulnerabilities": [{"id": "CVE-2026-2004"}], "artifact": {"name": "urllib3", "version": "2.2.3", "type": "python"}},
    {"vulnerability": {"id": "GHSA-9v8h-qqgm-4m35", "fix": {"state": "fixed", "versions": ["1.2.1"]}},
     "relatedVulnerabilities": [{"id": CVE_B}], "artifact": {"name": "brotli", "version": "1.1.0", "type": "python"}},
    {"vulnerability": {"id": CVE_B, "fix": {"state": "fixed", "versions": ["1.1.0-2ubuntu0.1"]}},
     "relatedVulnerabilities": [], "artifact": {"name": "brotli", "version": "1.1.0-2build2", "type": "deb"}},
    {"vulnerability": {"id": "GHSA-mpmp-mpmp-mpmp", "fix": {"state": "fixed", "versions": ["1.3.0"]}},
     "relatedVulnerabilities": [{"id": "CVE-2026-2001"}], "artifact": {"name": "mpmath", "version": "0.0.0", "type": "python"}},
    {"vulnerability": {"id": "CVE-2026-2001", "fix": {"state": "not-fixed", "versions": []}},
     "relatedVulnerabilities": [], "artifact": {"name": "python3-mpmath", "version": "1.2.1-3", "type": "deb"}},
    {"vulnerability": {"id": "GHSA-rrrr-rrrr-rrrr", "fix": {"state": "fixed", "versions": ["2.32.0"]}},
     "relatedVulnerabilities": [{"id": "CVE-2026-2002"}], "artifact": {"name": "requests", "version": "2.31.0", "type": "python"}},
]}
PIP_RULE = {"schema": "sca-center-vex-rules/1", "author": "Tester", "rules": [
    {"id": "R4", "description": "PyPI package: newer fixed version available", "date": "2026-11-02",
     "reason": "Upgrade the Python package in the next image.",
     "match": {"scope": "non_kernel", "purl_type": ["pypi"], "fix_state": ["fixed"]},
     "set": {"state": "exploitable", "response": ["update"], "detail_template": "Fixed in {component} {fix_version}.",
             "recommendation": "pip install --upgrade {component}>={fix_version}"}},
    {"id": "R9", "description": "Anything else", "date": "2026-11-02", "reason": "Track.",
     "match": {"scope": "all"}, "set": {"state": "in_triage", "detail_template": "Tracked."}}]}


def deb_rows(findings=DFINDINGS, grype=DGRYPE, sbom=DSBOM):
    rows = rows_for(findings=findings, grype=grype)
    idx, _ = cr.grype_index(grype)
    dpy, mixed = cr.deb_python_index(list(cr.flatten(sbom["components"])))
    return rows, cr.apply_deb_python(rows, dpy, idx, True), dpy, mixed


def one(rows, rid, ptype):
    got = [r for r in rows if r["id"] == rid and r["ptype"] == ptype]
    assert len(got) == 1, (rid, ptype, got)
    return got[0]


# ---------- Ubuntu 打包的 Python 模組 ----------

def test_deb_python_index_owner_by_name_and_upstream():
    dpy, notes = cr.deb_python_index(list(cr.flatten(DSBOM["components"])))
    mixed = notes["mixed"]
    assert dpy["pkg:pypi/mpmath@0.0.0"]["owner"]["name"] == "python3-mpmath"
    assert dpy["pkg:pypi/mpmath@0.0.0"]["owner"]["version"] == "1.2.1-3"
    assert dpy["pkg:pypi/brotli@1.1.0"]["owner"]["source"] == "brotli"
    assert "pkg:pypi/requests@2.31.0" not in dpy                      # pip 裝在 /usr/local：照舊是 pip 套件
    assert mixed == ["pkg:pypi/six@1.16.0"] and "pkg:pypi/six@1.16.0" not in dpy   # 另有 venv 的一份：不改
    assert dpy["pkg:pypi/foo@0.0.0"]["owner"] is None and dpy["pkg:pypi/foo@0.0.0"]["candidates"] == []
    bar = dpy["pkg:pypi/bar@1.0"]
    assert bar["owner"] is None and bar["candidates"] == ["python3-bar-a 1.0-1", "python3-bar-b 1.0-2"]   # 多個：不猜
    # 套件名稱不同（python-dateutil → python3-dateutil）時用 upstream（原始碼套件）
    d2, _ = cr.deb_python_index([pyc("python-dateutil", "2.8.2", f"{DP}/python_dateutil-2.8.2.egg-info"),
                                 debc("python3-dateutil", "2.8.2-3ubuntu1", "python-dateutil")])
    assert d2["pkg:pypi/python-dateutil@2.8.2"]["owner"]["name"] == "python3-dateutil"


def test_deb_python_version_must_match_owner():
    """pip 裝進 /usr/lib/python3/dist-packages 的新版（版本和名稱對到的 deb 不同）不是那個 deb 的：照舊當 pip 套件。"""
    dpy, notes = cr.deb_python_index(list(cr.flatten(DSBOM["components"])))
    assert "pkg:pypi/urllib3@2.2.3" not in dpy and notes["version_mismatch"] == ["pkg:pypi/urllib3@2.2.3"]
    for py, deb, want in (("2.31.0", "2.31.0+dfsg-1ubuntu1", True), ("1.26.5", "1:1.26.5-1~exp1", True), ("1.2", "1.2.0-3", True),
                          ("0.0.0", "9.9-1", True), ("", "9.9-1", True), ("2.32.3", "2.31.0+dfsg-1ubuntu1", False), ("1.1", "1.10-1", False)):
        assert cr.version_matches(py, deb) is want, (py, deb)
    rows, done, _, _ = deb_rows()
    u = one(rows, "CVE-2026-2004", "pypi")
    assert "deb_python" not in u and u["fix"] == "fixed in 2.3.0" and u not in done


def test_deb_python_rows_point_to_ubuntu_package():
    rows, done, _, _ = deb_rows()
    assert len(rows) == 6 and len(done) == 3                           # 列不刪：brotli、mpmath、foo 改寫，requests、urllib3 與 deb 列不動
    b = one(rows, CVE_B, "pypi")
    assert b["deb_python"]["owner"]["name"] == "python3-brotli"
    assert b["deb_python"]["row"] == f"{CVE_B} on brotli 1.1.0-2build2"
    assert b["fix"].startswith("update the Ubuntu package python3-brotli (installed 1.1.0-2build2), not pip; fixed in 1.1.0-2ubuntu0.1")
    assert "the PyPI fix 1.2.1 does not apply" in b["fix"]
    assert b["fix_state"] == "fixed" and b["fix_versions"] == ["1.1.0-2ubuntu0.1"] and b["fix_next"] == "1.1.0-2ubuntu0.1"
    assert cr.type_text(b) == "pypi (deb-packaged)" and "Ubuntu package python3-brotli 1.1.0-2build2" in cr.component_text(b)
    m = one(rows, "CVE-2026-2001", "pypi")                             # 原始碼套件上沒有這個 CVE 的列：用 Grype 對 deb 的結果
    assert m["fix"].startswith("update the Ubuntu package python3-mpmath (installed 1.2.1-3), not pip; Ubuntu fix state: not-fixed")
    assert "1.3.0 does not apply" in m["fix"] and m["fix_versions"] == [] and m["fix_next"] is None
    assert cr.version_text(m) == "1.2.1-3 (deb python3-mpmath; Python metadata 0.0.0)" and m["version"] == "0.0.0"
    f = one(rows, "CVE-2026-2003", "pypi")                             # 找不到擁有者：PyPI 的修補資料照留，不說「不是 pip」
    assert f["fix"].startswith("fixed in 0.1.0; installed in /usr/lib/python3/dist-packages (normally by a distribution package), "
                               "owning deb package not found in the SBOM: check which package installed it")
    assert "not pip" not in f["fix"] and "does not apply" not in f["fix"]
    assert f["fix_state"] == "fixed" and f["fix_versions"] == ["0.1.0"] and f["fix_next"] == "0.1.0"
    assert "owning deb package not found in the SBOM" in cr.component_text(f) and cr.version_text(f) == "0.0.0"
    r = one(rows, "CVE-2026-2002", "pypi")
    assert "deb_python" not in r and r["fix"] == "fixed in 2.32.0"   # pip 裝的：照舊


def test_deb_python_gets_the_owning_deb_rule_not_a_pip_rule(tmp_path):
    proj, scan = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "s", findings=DFINDINGS, grype=DGRYPE, sbom=DSBOM)
    write_json(proj / "CRA" / "Config" / "vex-rules.json", PIP_RULE)
    r, s, rep = run(proj, scan)
    assert s is not None and r.returncode in (0, 2), r.stdout + r.stderr
    rules = {x["id"]: x for x in s["vex"]["rules"]["rules"]}
    # R4（pypi、fixed）：brotli、foo（擁有者不明）以 pypi 不套用，pip 裝的 requests、urllib3 套用；mpmath（Ubuntu 沒修：not-fixed）落到 R9。
    # 排除之後（deb_python_rules）：brotli 沿用擁有它的原始碼套件那一列的 R9；mpmath 的擁有者沒有這個 CVE 的列 → 以擁有者 python3-mpmath
    # （deb）直接套用 R9；foo 擁有者不明，照舊不套用。PyPI 的規則（R4）一律不會套在這些列
    # 每一列只算一次：沿用或以擁有者套用了的列不再算 excluded_deb_python（brotli、mpmath）；只剩 foo
    assert rules["R4"]["excluded_deb_python"] == 1 and rules["R4"]["applied"] == 2 and rules["R4"]["inherited_deb_python"] == 0
    assert rules["R9"]["excluded_deb_python"] == 0 and rules["R9"]["applied"] == 2 and rules["R9"]["inherited_deb_python"] == 1
    assert s["counts"]["deb_python"] == {"rows": 3, "with_owner": 2, "without_owner": 1, "sbom_components": 4, "mixed_purls": 1,
                                         "version_mismatch_purls": 1}
    vex = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    ruled = {v["id"] for v in vex["vulnerabilities"] if any(p["name"] == "sca-center:vex-rule" for p in v.get("properties") or [])}
    assert ruled == {CVE_B, "CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2004"}
    det = sorted((v["id"], v["analysis"]["detail"]) for v in vex["vulnerabilities"])
    assert (CVE_B, "inherited from brotli 1.1.0-2build2 (the Ubuntu source package of python3-brotli, which installed this module): "
                   "Tracked. (bulk rule R9: Anything else)") in det
    assert (CVE_B, "Tracked. (bulk rule R9: Anything else)") in det                 # 原始碼套件那一列自己的
    py_m = next(d for i, d in det if i == "CVE-2026-2001")
    assert py_m.startswith("applied to the Ubuntu package python3-mpmath 1.2.1-3, which installed this module (mpmath 0.0.0): Tracked.")
    assert "CVE-2026-2003" not in ruled                                  # 擁有者不明：不套用
    assert (s["vex"]["deb_python_rule_inherited"], s["vex"]["deb_python_rule_direct"]) == (1, 1)
    assert len([v for v in vex["vulnerabilities"] if v["id"] == CVE_B]) == 2         # 原始碼套件那一列與沿用的 Python 模組那一列
    ra = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Ubuntu package python3-mpmath 1.2.1-3 installs it in /usr/lib/python3/dist-packages" in ra
    assert "1.2.1-3 (deb python3-mpmath; Python metadata 0.0.0)" in ra
    assert "3 rows are for Python modules installed by Ubuntu packages" in ra and "for 1 of them the owning package was not identified" in ra
    assert {c["component"] for c in s["vex"]["gate"]["open_components"] if c["type"] == "pypi-deb"} == {"brotli", "mpmath", "foo"}


# ---------- 沒有 CVE 別名的 USN ----------

USN = "USN-8956-1"
LIBB = "pkg:deb/ubuntu/libbrotli1@1.1.0-2build2?arch=arm64&" + U24
CURL = "pkg:deb/ubuntu/curl@8.5.0-2ubuntu10.6?arch=source&" + U24
UFINDINGS = [
    finding("brotli", "1.1.0-2build2", f"UBUNTU-{CVE_B}", "OSV", "HIGH", [{"cveId": CVE_B}], purl=SRC),
    finding("brotli", "1.1.0-2build2", "GHSA-aaaa-aaaa-aaaa", "GITHUB", "LOW",                 # 一列兩個 CVE（列在 CVE-2026-0001）
            [{"cveId": "CVE-2026-0001"}, {"cveId": "CVE-2026-0002"}], purl=SRC),
    finding("brotli", "1.1.0-2build2", USN, "OSV", "MEDIUM", purl=SRC),                    # 只列 CVE_B → 併
    finding("brotli", "1.1.0-2build2", "USN-8960-1", "OSV", "LOW", purl=SRC),              # 列的 CVE 在別列的別名裡 → 併進那一列
    finding("brotli", "1.1.0-2build2", "USN-8961-1", "OSV", "LOW", purl=SRC),              # 有一個 CVE 在這個元件上沒有列 → 不併
    finding("brotli", "1.1.0-2build2", "USN-8962-1", "OSV", "LOW", purl=SRC),              # 兩個 CVE 都有列 → 併（排序最前的）
    finding("libbrotli1", "1.1.0-2build2", USN, "OSV", "MEDIUM", purl=LIBB),               # 同一個 USN 在另一個元件上：自成一列
    finding("curl", "8.5.0-2ubuntu10.6", "USN-9000-1", "OSV", "LOW", purl=CURL),           # 列的 CVE 在這個元件上沒有列
    finding("curl", "8.5.0-2ubuntu10.6", "USN-9001-1", "OSV", "LOW", purl=CURL),           # 鏡像沒有 → 沒有對應
]
UMAP = {USN: [CVE_B], "USN-8960-1": ["CVE-2026-0002"], "USN-8961-1": [CVE_B, "CVE-2026-0999"],
        "USN-8962-1": [CVE_B, "CVE-2026-0002"], "USN-9000-1": ["CVE-2026-8000"]}
UDOC = {"schema": "sca-center-usn-cves/1", "status": "OK", "mirror": {"fetched_utc": "2026-11-02T00:00:00Z"},
        "usns": {k: {"cves": v} for k, v in UMAP.items()}, "not_found": ["USN-9001-1"]}


def ident(f):
    """一筆 finding：（來源:編號、元件、版本）——同一個編號在不同元件上是不同的 finding。"""
    v, c = f["vulnerability"], f["component"]
    return f"{v['source']}:{v['vulnId']}", cr.purl_fullname(c["purl"]), c["version"]


def assert_each_finding_once(findings, rows):
    c = Counter((x, *r["key"][1:]) for r in rows for x in r["source_ids"])
    for f in findings:
        assert c[ident(f)] == 1, (ident(f), c[ident(f)])


def usn_rows(findings=UFINDINGS + FINDINGS, usn=UMAP):
    idx, _ = cr.grype_index(GRYPE)
    return cr.build_rows(findings, cr.policy_of(MIN_CFG), idx, True, usn=usn)


def test_usn_joins_cve_row_on_same_component():
    rows = usn_rows(usn=None)
    assert {USN, "USN-8960-1", "USN-8962-1"} <= {r["id"] for r in rows}   # 沒有對應：照舊自成一列
    assert_each_finding_once(UFINDINGS + FINDINGS, rows)
    rows = usn_rows(usn=cr.usn_map(UDOC))
    assert_each_finding_once(UFINDINGS + FINDINGS, rows)
    b = one(rows, CVE_B, "deb")
    assert b["source_ids"] == [f"OSV:UBUNTU-{CVE_B}", f"OSV:{USN}"] and b["usn_merged"] == {USN: [CVE_B]}
    assert b["cves"] == [CVE_B] and b["severity"] == "HIGH" and b["n_findings"] == 2
    # CVE-2026-0002 只是 CVE-2026-0001 列（GHSA 的別名）裡的 CVE：USN-8960-1 也併進那一列；USN-8962-1 的兩個 CVE 都有列，
    # 併進排序最前的（CVE-2026-0002 → 同一列）；USN 的 CVE 不加進列的 CVE
    a = one(rows, "CVE-2026-0001", "deb")
    assert set(a["usn_merged"]) == {"USN-8960-1", "USN-8962-1"} and a["cves"] == ["CVE-2026-0001", "CVE-2026-0002"]
    ids = {(r["id"], r["component"]) for r in rows}
    assert (USN, "brotli") not in ids and (USN, "libbrotli1") in ids    # 同一個 USN 在另一個元件上自成一列
    u = one(rows, "USN-8961-1", "deb")                                   # CVE-2026-0999 在 brotli 上沒有列：不併（CVE-0999 不會因 CVE_B 的判定消失）
    assert u["usn_listed"] == ["CVE-2026-0999", CVE_B] and "not every listed CVE has a row" in cr.cve_text(u)
    assert one(rows, "USN-9000-1", "deb")["usn_listed"] == ["CVE-2026-8000"]
    assert one(rows, "USN-9001-1", "deb").get("usn_listed") is None
    # 對應檔不是 OK、或內容不可信（不是 USN／CVE 的格式）→ 不採用
    assert cr.usn_map(dict(UDOC, status="NOT_RUN")) is None
    assert cr.usn_map(dict(UDOC, usns={"USN-1-1": {"cves": ["CVE-1-1", "x"]}, "bad": {"cves": [CVE_B]}})) == {}


def test_usn_dt_analysis_used_only_for_single_cve():
    """USN 只列一個 CVE 時，DT 對 USN 的分析可當那個 CVE 的判定；列多個 CVE 時不採用（同 GHSA 多個別名）。"""
    an = {"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE", "details": "not used"}
    fs = [UFINDINGS[0], finding("brotli", "1.1.0-2build2", "CVE-2026-0002", "NVD", "LOW", purl=SRC), dict(UFINDINGS[2], analysis=an)]
    for listed, rid, want in (([CVE_B], CVE_B, "dt"), ([CVE_B, "CVE-2026-0002"], "CVE-2026-0002", None)):
        allrows, _, _ = vx.assess(usn_rows(fs, {USN: listed}))
        r = one(allrows, rid, "deb")
        assert USN in r["usn_merged"] and (r["vex"] or {}).get("source") == want, (listed, r["vex"])
        if want is None:
            assert r["dt_unusable"] == {"other_vulnerability": ["NOT_AFFECTED"]} and r["vex_extra"] == []


def test_usn_annotation_on_merged_row_only_for_single_cve():
    """判定檔寫 USN 編號：USN 只列這一列的 CVE 時套用到併進的列；列多個 CVE 時不套用（不能變成其中一個 CVE 的陳述）。"""
    rows = usn_rows(usn=cr.usn_map(UDOC))
    ann = lambda u: {"cve": u, "purl": "pkg:deb/ubuntu/brotli", "state": "not_affected", "justification": "code_not_reachable",   # noqa: E731
                     "detail": "x", "author": "Tester", "date": "2026-11-03"}
    assert vx.annotation_matches(ann(USN), one(rows, CVE_B, "deb"))
    b2 = dict(one(rows, CVE_B, "deb"), usn_merged={USN: [CVE_B, "CVE-2026-0999"]})        # 同一列，但 USN 列兩個 CVE
    assert not vx.annotation_matches(ann(USN), b2)
    a = one(rows, "CVE-2026-0001", "deb")
    a1 = dict(a, cves=["CVE-2026-0001"])                                                   # 就算列只有一個 CVE
    assert not vx.annotation_matches(ann("USN-8962-1"), a1) and not vx.annotation_matches(ann("USN-8960-1"), a1)
    allrows, _, info = vx.assess(rows, annotations=[ann("USN-8962-1")])
    assert info["annotations_used"] == 0 and not any((r["vex"] or {}).get("source") == "annotation" for r in allrows)


def test_usn_mapping_in_report_and_without_it(tmp_path):
    findings = FINDINGS + UFINDINGS
    proj = make_project(tmp_path / "p", MIN_CFG)
    scan = make_scan(tmp_path / "s", findings=findings)
    r, s0, rep = run(proj, scan)
    assert s0 is not None, r.stdout + r.stderr
    u0 = s0["counts"]["usn_cves"]
    assert u0["mapping"] == "not_available" and u0["without_cve"] == 6 and u0["merged"] == [] and len(u0["own_row"]) == 7
    ra0 = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "mapping of Ubuntu security notices (USN) to CVEs was not available (no `scan/usn-cves.json`" in ra0
    write_json(scan / "scan" / "usn-cves.json", UDOC)
    r, s1, rep = run(proj, scan)
    u = s1["counts"]["usn_cves"]
    # 依（USN、元件版本）計數：USN-8956-1 在 brotli 併、在 libbrotli1 自成一列，兩邊都算
    assert u["mapping"] == "OK" and u["merged"] == [f"{x} on brotli 1.1.0-2build2" for x in (USN, "USN-8960-1", "USN-8962-1")]
    assert u["own_row"] == [f"{USN} on libbrotli1 1.1.0-2build2", "USN-8961-1 on brotli 1.1.0-2build2",
                            "USN-9000-1 on curl 8.5.0-2ubuntu10.6", "USN-9001-1 on curl 8.5.0-2ubuntu10.6"]
    assert s1["counts"]["rows"] == s0["counts"]["rows"] - 3 and s1["counts"]["findings_raw"] == s0["counts"]["findings_raw"]
    ra1 = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "3 Ubuntu security notice findings (USN) without a CVE alias were merged into the row of a CVE" in ra1
    assert "mirror fetched 2026-11-02T00:00:00Z" in ra1 and "4 notice findings stay a row of their own" in ra1
    assert s1["inputs"]["scan/usn-cves.json"]["sha256"]
    # 對應檔 status NOT_RUN（例如沒有鏡像）：照舊，並寫原因
    write_json(scan / "scan" / "usn-cves.json", dict(UDOC, status="NOT_RUN"))
    r, s2, rep = run(proj, scan)
    assert s2["counts"]["rows"] == s0["counts"]["rows"] and s2["counts"]["usn_cves"]["mapping"] == "not_available"
    assert "`scan/usn-cves.json` has status NOT_RUN" in (rep / "risk-assessment.md").read_text(encoding="utf-8")


def test_no_source_id_lost_with_both_fixes():
    """兩個修正一起用時，每一筆 DT finding 的編號仍剛好在一列的 source_ids 裡（列不刪、不重複）。"""
    findings = FINDINGS + DFINDINGS + UFINDINGS
    idx, _ = cr.grype_index(DGRYPE)
    rows = cr.build_rows(findings, cr.policy_of(MIN_CFG), idx, True, usn=cr.usn_map(UDOC))
    dpy, _ = cr.deb_python_index(list(cr.flatten(DSBOM["components"])))
    cr.apply_deb_python(rows, dpy, idx, True)
    assert_each_finding_once(findings, rows)
    allrows, _, _ = vx.assess(rows)
    assert_each_finding_once(findings, [r for r in allrows if r.get("tier") != "nvidia_bulletin"])


def test_deb_python_inherits_decision_of_owning_deb_row(tmp_path):
    """Ubuntu 打包的 brotli（pypi 列）沿用擁有它的原始碼套件 brotli 1.1.0-2build2 那一列的判定（annotation 寫 deb 的 purl）：
    VEX 有兩條陳述（deb 與 pypi 各一，pypi 那條註明沿用自哪一列），風險評估兩列都移到 accepted；規則不沿用（R9 仍只套 deb 列時不影響）。"""
    proj, scan = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "s", findings=DFINDINGS, grype=DGRYPE, sbom=DSBOM)
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [
        {"cve": CVE_B, "purl": "pkg:deb/ubuntu/brotli", "state": "not_affected", "justification": "code_not_reachable",
         "detail": "the decoder is not reachable from any service", "author": "Tester", "date": "2026-11-03"}]})
    r, s, rep = run(proj, scan)
    assert s is not None and r.returncode in (0, 2), r.stdout + r.stderr
    vex = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    vb = [v for v in vex["vulnerabilities"] if v["id"] == CVE_B]
    assert len(vb) == 2 and {v["analysis"]["state"] for v in vb} == {"not_affected"}
    inh = [v for v in vb if any(p["name"] == "sca-center:vex-inherited-from" for p in v["properties"])]
    assert len(inh) == 1 and {"name": "sca-center:component-purl", "value": "pkg:pypi/brotli@1.1.0"} in inh[0]["properties"]
    assert s["counts"]["accepted_by_vex"] == {"annotation": 2} and s["vex"]["deb_python_inherited"] == 1
    assert "brotli" not in {c["component"] for c in s["vex"]["gate"]["open_components"] if c["type"] == "pypi-deb"}
    ra = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "inherited from the decision on the Ubuntu source package brotli 1.1.0-2build2, from which python3-brotli" in ra


def test_deb_python_inherited_dt_decision_moves_row_to_accepted(tmp_path):
    """DT 的人工分析在 brotli 原始碼套件的 finding 上：deb 列由 tier_of 移到 accepted，沿用的 pypi 列也要移（VEX 與風險評估一致）。"""
    an = {"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE", "details": "decoder not reachable"}
    fs = [dict(f, analysis=an) if f["vulnerability"]["vulnId"] == f"UBUNTU-{CVE_B}" else f for f in DFINDINGS]
    proj, scan = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "s", findings=fs, grype=DGRYPE, sbom=DSBOM)
    r, s, rep = run(proj, scan)
    assert s is not None and r.returncode in (0, 2), r.stdout + r.stderr
    vex = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    assert {v["analysis"]["state"] for v in vex["vulnerabilities"] if v["id"] == CVE_B} == {"not_affected"}
    assert s["vex"]["deb_python_inherited"] == 1 and s["counts"]["accepted_by_vex"] == {"dt": 1}
    p2 = (rep / "risk-assessment.md").read_text(encoding="utf-8").split("### 8.5 P2")[1].split("### 8.6")[0]
    assert CVE_B not in p2



def test_deb_python_does_not_inherit_partial_dt_analysis(tmp_path):
    """原始碼套件列併了兩筆 finding（UBUNTU 有分析、NVD 沒有）：deb 列留在 P1–P3（tier_of），pypi 列也不能沿用而被關掉。"""
    an = {"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE", "details": "decoder not reachable"}
    fs = [dict(f, analysis=an) if f["vulnerability"]["vulnId"] == f"UBUNTU-{CVE_B}" else f for f in DFINDINGS]
    fs.append(finding("brotli", "1.1.0-2build2", CVE_B, "NVD", "HIGH", purl=SRC))
    proj, scan = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "s", findings=fs, grype=DGRYPE, sbom=DSBOM)
    r, s, rep = run(proj, scan)
    assert s is not None and r.returncode in (0, 2), r.stdout + r.stderr
    assert s["vex"]["deb_python_inherited"] == 0 and s["counts"]["accepted_by_vex"] == {}
    assert "brotli" in {c["component"] for c in s["vex"]["gate"]["open_components"] if c["type"] == "pypi-deb"}


def test_deb_python_uses_ubuntu_priority_of_owning_package(tmp_path):
    """審查（低）：Ubuntu 打包的 brotli（pypi 列，GHSA HIGH）和擁有它的 Ubuntu 套件一樣用 Ubuntu priority（low）；
    pip 裝的 requests 照舊用 DT 的值。"""
    scan = make_scan(tmp_path / "s", findings=DFINDINGS, grype=DGRYPE, sbom=DSBOM)
    write_json(scan / "scan" / "ubuntu-priority.json", {"schema": "sca-center-ubuntu-priority/1", "status": "OK", "mirror": {},
                                                         "cves": {CVE_B: {"priority": "low"}, "CVE-2026-2002": {"priority": "low"}}})
    r, s, rep = run(make_project(tmp_path / "p", MIN_CFG), scan)
    ra = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    rows = [x for x in ra.split("### 8.6")[1].split("### 8.7")[0].splitlines() if CVE_B in x]
    assert len(rows) == 2 and all("| LOW | Ubuntu priority (low); Dependency-Track HIGH |" in x for x in rows), rows
    req = next(x for x in ra.splitlines() if "CVE-2026-2002" in x and x.startswith("| "))
    assert "| MEDIUM | other |" in req                      # pip 裝的（/usr/local）：Ubuntu priority 不適用


PIL = [pyc("pillow", "10.2.0", f"{DP}/pillow-10.2.0.dist-info/METADATA"),
       debc("python3-pil.imagetk", "10.2.0-1ubuntu1.2", "pillow", arch="arm64"), debc("python3-pil", "10.2.0-1ubuntu1.2", "pillow", arch="arm64")]


def test_candidates_from_one_source_and_version_give_a_source_owner():
    """pillow：python3-pil 與 python3-pil.imagetk 都從原始碼套件 pillow 的同一個版本建出來 → source_owner（名稱最短的當代表），只給
    Ubuntu 的修補狀態與批次規則用；owner 照舊是 None。原始碼套件或版本不同 → 沒有 source_owner（不猜）。"""
    d, _ = cr.deb_python_index(PIL)
    x = d["pkg:pypi/pillow@10.2.0"]
    assert x["owner"] is None and x["source_owner"]["name"] == "python3-pil" and x["source_owner"]["source"] == "pillow"
    assert x["candidates"] == ["python3-pil 10.2.0-1ubuntu1.2", "python3-pil.imagetk 10.2.0-1ubuntu1.2"]
    # 版本不同（同一個原始碼套件）→ 不明
    d, _ = cr.deb_python_index([PIL[0], debc("python3-pil.imagetk", "10.2.0-1ubuntu1.1", "pillow", arch="arm64"), PIL[2]])
    assert d["pkg:pypi/pillow@10.2.0"]["owner"] is None and "source_owner" not in d["pkg:pypi/pillow@10.2.0"]
    # 原始碼套件不同（同一個版本）→ 不明
    d, _ = cr.deb_python_index([pyc("bar", "1.0", f"{DP}/bar-1.0.egg-info"), debc("python3-bar-a", "1.0-1", "bar"),
                                debc("python3-bar-b", "1.0-1", "python-bar")])
    assert d["pkg:pypi/bar@1.0"]["owner"] is None and "source_owner" not in d["pkg:pypi/bar@1.0"]
    # 這一列的欄位和擁有者不明時一樣（PyPI 的修補資料、ambiguous），Ubuntu 的修補狀態另記在 source_owner_fix
    rows = rows_for(findings=[finding("pillow", "10.2.0", "GHSA-pppp-pppp-pppp", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-7001"}],
                                      purl="pkg:pypi/pillow@10.2.0")],
                    grype={"matches": [{"vulnerability": {"id": "GHSA-pppp-pppp-pppp", "fix": {"state": "fixed", "versions": ["10.3.0"]}},
                                        "relatedVulnerabilities": [{"id": "CVE-2026-7001"}],
                                        "artifact": {"name": "pillow", "version": "10.2.0", "type": "python"}}]})
    idx, _ = cr.grype_index({"matches": []})
    cr.apply_deb_python(rows, cr.deb_python_index(PIL)[0], idx, True)
    r = rows[0]
    assert r["fix_state"] == "fixed" and r["fix_versions"] == ["10.3.0"] and "owning deb package ambiguous" in r["fix"]
    assert r["deb_python"]["owner"] is None and r["deb_python"]["source_owner"]["name"] == "python3-pil"
    assert r["deb_python"]["source_owner_fix"] == {"fix_state": "no Grype data", "fix_versions": [], "row": None, "fix_next": None}
    assert "owning deb package ambiguous: python3-pil 10.2.0-1ubuntu1.2, python3-pil.imagetk" in cr.component_text(r)


def test_source_owner_keeps_severity_tier_and_human_decisions(tmp_path):
    """審查 High（repro_tier.py）：GHSA CRITICAL＋Ubuntu priority low。source_owner 不改嚴重度與層級（仍是 P2 CRITICAL，和 origin/main
    一樣），人工判定不沿用；批次規則的陳述可以有（以 source_owner 套用）。"""
    f = [finding("pillow", "10.2.0", "GHSA-pppp-pppp-pppp", "GITHUB", "CRITICAL", [{"cveId": "CVE-2026-7001"}], purl="pkg:pypi/pillow@10.2.0")]
    sc = make_scan(tmp_path / "s", findings=f, grype={"matches": []}, sbom=dict(SBOM, components=PIL))
    write_json(sc / "scan" / "ubuntu-priority.json", {"schema": "sca-center-ubuntu-priority/1", "status": "OK", "mirror": {},
                                                      "cves": {"CVE-2026-7001": {"priority": "low"}}})
    proj = make_project(tmp_path / "p", MIN_CFG)
    write_json(proj / "CRA" / "Config" / "vex-rules.json", {"schema": "sca-center-vex-rules/1", "author": "Tester", "rules": [
        {"id": "R6", "description": "Ubuntu package: no fix yet", "date": "2026-11-02", "reason": "x",
         "match": {"scope": "non_kernel", "purl_type": ["deb"]}, "set": {"state": "exploitable", "response": ["can_not_fix"],
                                                                         "detail_template": "No fixed {component} yet."}}]})
    r, s, rep = run(proj, sc)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    ra = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    line = next(x for x in ra.splitlines() if x.startswith("| 1 | CVE-2026-7001 |"))
    assert "| CRITICAL" in line and "Ubuntu priority" not in line and "owning deb package ambiguous" in line, line
    assert s["counts"]["p2"] == 1 and s["counts"]["p3"] == 0
    vex = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    v = next(x for x in vex["vulnerabilities"] if x["id"] == "CVE-2026-7001")
    assert v["analysis"]["detail"].startswith("applied to the Ubuntu packages built from source package pillow (python3-pil, python3-pil.imagetk")
    # 擁有者的原始碼套件列有人工判定（DT 分析）→ 不沿用（inherit_deb_python 只看 owner）
    src = "pkg:deb/ubuntu/pillow@10.2.0-1ubuntu1.2?arch=source&distro=ubuntu-24.04"
    f2 = f + [finding("pillow", "10.2.0-1ubuntu1.2", "CVE-2026-7001", "NVD", "LOW", purl=src,
                      analysis={"isSuppressed": False, "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE", "details": "not used"})]
    write_json(sc / "dt" / "findings.json", f2)
    r, s, rep = run(proj, sc)
    vex = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    st = [x["analysis"] for x in vex["vulnerabilities"] if x["id"] == "CVE-2026-7001"]
    assert st == [{"state": "not_affected", "justification": "code_not_reachable", "detail": "not used"}] or \
        (len(st) == 1 and st[0]["state"] == "not_affected" and "inherited" not in st[0]["detail"])        # 只有 deb 列自己的
    assert s["vex"]["deb_python_inherited"] == 0 and s["counts"]["p2"] == 1 and s["counts"]["accepted"] == 1


def test_rule_counts_each_module_row_once(tmp_path):
    """審查 Low（repro_kev.py）：以擁有者套用時 applied、excluded_kev、excluded_deb_python 不重算。"""
    f = [dict(x) for x in DFINDINGS]
    for x in f:
        if x["vulnerability"]["vulnId"] == "GHSA-mpmp-mpmp-mpmp":
            x["vulnerability"] = dict(x["vulnerability"], isKev=True)
    rules = {"schema": "sca-center-vex-rules/1", "author": "Tester", "rules": [
        {"id": "R9", "description": "Anything else", "date": "2026-11-02", "reason": "Track.",
         "match": {"scope": "all", "allow_p1": True}, "set": {"state": "in_triage", "detail_template": "Tracked."}}]}
    proj, scan = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "s", findings=f, grype=DGRYPE, sbom=DSBOM)
    write_json(proj / "CRA" / "Config" / "vex-rules.json", rules)
    r, s, rep = run(proj, scan)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    x = {y["id"]: y for y in s["vex"]["rules"]["rules"]}["R9"]
    # 6 列：brotli 原始碼套件、requests、urllib3 套用；brotli 模組沿用；mpmath 模組 KEV（只算一次）；foo 擁有者不明
    assert (x["applied"], x["excluded_kev"], x["excluded_deb_python"], x["inherited_deb_python"]) == (3, 1, 1, 1)
    assert x["applied"] + x["excluded_kev"] + x["excluded_deb_python"] + x["inherited_deb_python"] == 6


def test_source_owner_statement_names_every_candidate(tmp_path):
    """審查 Low（repro_so.py）：擁有者不明（source_owner）的列，VEX 陳述與處理說明不說是哪一個套件裝的，列出全部候選
    （風險表寫 ambiguous）。以擁有者套用與沿用 deb 列兩條路都一樣。"""
    f = [finding("pillow", "10.2.0", "GHSA-pppp-pppp-pppp", "GITHUB", "CRITICAL", [{"cveId": "CVE-2026-7001"}], purl="pkg:pypi/pillow@10.2.0")]
    sc = make_scan(tmp_path / "s", findings=f, grype={"matches": []}, sbom=dict(SBOM, components=PIL))
    proj = make_project(tmp_path / "p", MIN_CFG)
    write_json(proj / "CRA" / "Config" / "vex-rules.json", {"schema": "sca-center-vex-rules/1", "author": "Tester", "rules": [
        {"id": "R3", "description": "deb", "date": "2026-11-02", "reason": "x",
         "match": {"scope": "non_kernel", "purl_type": ["deb"], "fix_state": ["fixed", "not-fixed", "no Grype data"]},
         "set": {"state": "exploitable", "response": ["update"], "detail_template": "Ubuntu {component} installed {installed_version}.",
                 "recommendation": "apt upgrade {component}"}}]})
    r, s, rep = run(proj, sc)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    v = next(x for x in json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))["vulnerabilities"] if x["id"] == "CVE-2026-7001")
    assert v["analysis"]["detail"].startswith(
        "applied to the Ubuntu packages built from source package pillow (python3-pil, python3-pil.imagetk 10.2.0-1ubuntu1.2), one of which "
        "installed this module (pillow 10.2.0): Ubuntu python3-pil python3-pil.imagetk installed 10.2.0-1ubuntu1.2.")
    props = {p["name"]: p["value"] for p in v.get("properties") or []}
    assert props["openvex:action_statement"] == "apt upgrade python3-pil python3-pil.imagetk (bulk rule R3: deb)"
    assert "which installed this module (pillow" in v["analysis"]["detail"] and "the Ubuntu package python3-pil 10.2.0" not in v["analysis"]["detail"]
    # 沿用的路：擁有者的原始碼套件 pillow 有這個 CVE 的列（R3 套用）
    rules = {"schema": "sca-center-vex-rules/1", "author": "Tester", "rules": [
        {"id": "R3", "description": "deb fixed", "date": "2026-11-02", "reason": "x",
         "match": {"scope": "non_kernel", "purl_type": ["deb"], "fix_state": ["fixed"]},
         "set": {"state": "exploitable", "response": ["update"], "detail_template": "Fixed in {component} {fix_version}.",
                 "recommendation": "apt upgrade {component} to {fix_version} or later"}}]}
    vx.check_rules(rules)
    src = "pkg:deb/ubuntu/pillow@10.2.0-1ubuntu1.2?arch=source&distro=ubuntu-24.04"
    g = {"matches": [{"vulnerability": {"id": "CVE-2026-7001", "fix": {"state": "fixed", "versions": ["10.2.0-1ubuntu1.3"]}},
                      "relatedVulnerabilities": [], "artifact": {"name": "pillow", "version": "10.2.0-1ubuntu1.2", "type": "deb"}}]}
    rows = rows_for(findings=f + [finding("pillow", "10.2.0-1ubuntu1.2", "CVE-2026-7001", "NVD", "LOW", purl=src)], grype=g)
    idx, _ = cr.grype_index(g)
    cr.apply_deb_python(rows, cr.deb_python_index(PIL)[0], idx, True)
    for x in rows:
        x["kernel"] = False
    allr, _, _ = vx.assess(rows, rules=vx.effective_rules(rules), rule_ctx={})
    py = next(x for x in allr if x["ptype"] == "pypi")
    assert py["vex"]["detail"].startswith(
        "inherited from pillow 10.2.0-1ubuntu1.2 (the Ubuntu packages built from source package pillow (python3-pil, python3-pil.imagetk "
        "10.2.0-1ubuntu1.2), one of which installed this module): Fixed in pillow 10.2.0-1ubuntu1.3.")
    assert py["vex"]["action_statement"] == "apt upgrade python3-pil python3-pil.imagetk to 10.2.0-1ubuntu1.3 or later (bulk rule R3: deb fixed)"
