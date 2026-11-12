"""cra_report.py：Grype 沒有修補狀態的 Ubuntu 列，依 Ubuntu CVE Tracker（scan/ubuntu-status.json）推出修補狀態（apply_ubuntu_tracker）。

- released（安裝的原始碼版本比註記舊）→ fixed，修補版本＝註記，批次規則 R3 的 {fix_version} 有值；比較新或一樣 → fixed（已修好，沒有 {fix_version}）。
- needed／pending／in-progress／deferred → not-fixed（R6）；ignored → wont-fix（R7，註記寫進陳述）。
- needs-triage、DNE、沒有、conflict、not-affected → 不推（not-affected 是證據規則 U1 的事）。核心的列不推。
- Ubuntu 打包的 Python 模組的列看擁有它的 deb 套件的原始碼套件。
- Grype 有修補狀態 → 照用 Grype 的；和 Tracker 不同 → 交叉核對並列。
- 沒有 scan/ubuntu-status.json、status 不是 OK → 什麼都不改，summary 沒有 ubuntu_tracker_fix。
全部是合成資料。
"""
import copy
import json
import sys
from pathlib import Path

from test_cra_deb_python_usn import DP, debc, pyc
from test_cra_report import MIN_CFG, SBOM, finding, make_project, make_scan, rows_for, run, write_json

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cra_report as cr  # noqa: E402
import vex_export as vx  # noqa: E402

U24 = "distro=ubuntu-24.04"
PV = "10.2.0-1ubuntu1"
PIL_SRC = f"pkg:deb/ubuntu/pillow@{PV}?arch=source&{U24}"
PIL_BIN = f"pkg:deb/ubuntu/python3-pil@{PV}?arch=arm64&{U24}&upstream=pillow"
KERN = f"pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&{U24}"
COMMIT = "b" * 40
E = {
    "CVE-2026-5001": ("released", "10.2.0-1ubuntu1.3"),          # 新的修補 → R3
    "CVE-2026-5002": ("released", PV),                            # 安裝的就是修好的版本
    "CVE-2026-5003": ("needed", ""),                              # → R6
    "CVE-2026-5004": ("ignored", "end of standard support"),      # → R7
    "CVE-2026-5005": ("needs-triage", ""),
    "CVE-2026-5006": ("deferred", "2026-10-22"),                  # 同 Grype：not-fixed
    "CVE-2026-5007": ("needed", ""),                              # Grype 說 fixed → 並列
    "CVE-2026-5008": ("pending", "10.2.0-1ubuntu1.4"),
    "CVE-2026-5009": ("not-affected", PV),                        # U1 的事
    "CVE-2026-5010": ("released", "10.2.0-1ubuntu1.5"),           # 有 conflict
    "CVE-2026-5011": ("DNE", ""),
    "CVE-2026-5012": ("released", "not a version"),
}


def ustat(entries=None, status="OK", comps=None):
    ent = {c: {"pillow": {"noble": dict({"status": st, "note": n}, **({"conflict": [{"status": "needed", "note": ""}]} if c == "CVE-2026-5010" else {}))}}
           for c, (st, n) in (E if entries is None else entries).items()}
    ent.setdefault("CVE-2026-6001", {})["linux-nvidia-tegra"] = {"noble": {"status": "released", "note": "6.8.0-1030.33"}}
    return {"schema": vx.USTATUS_SCHEMA, "status": status, "detail": "x",
            "mirror": {"commit": COMMIT, "commit_date": "2026-11-05T00:00:00Z", "fetched_utc": "2026-11-06T01:00:00Z"},
            "components": comps if comps is not None else {
                PIL_SRC: {"source": "pillow", "source_version": PV, "release": "noble"},
                PIL_BIN: {"source": "pillow", "source_version": PV, "release": "noble"},
                KERN: {"source": "linux-nvidia-tegra", "source_version": "6.8.0-1021.21", "release": "noble"}},
            "entries": ent, "mirror_counts": {}}


FINDS = [finding("pillow", PV, c, "NVD", "MEDIUM", purl=PIL_SRC) for c in E] \
    + [finding("linux-nvidia-tegra", "6.8.0-1021.21", "CVE-2026-6001", "NVD", "MEDIUM", purl=KERN)]
# Grype 只有 CVE-2026-5007（在原始碼套件的名稱上）
GRY = {"matches": [{"vulnerability": {"id": "CVE-2026-5007", "fix": {"state": "fixed", "versions": ["10.2.0-1ubuntu1.9"]}},
                    "relatedVulnerabilities": [], "artifact": {"name": "pillow", "version": PV, "type": "deb"}}]}


def rows(us=None, grype=GRY, findings=FINDS):
    rs = rows_for(MIN_CFG, findings, grype)
    for r in rs:
        r["kernel"] = r["component"].startswith("linux")
    info = cr.apply_ubuntu_tracker(rs, ustat() if us is None else us)
    return {r["id"]: r for r in rs}, info


def test_states_from_the_tracker():
    r, info = rows()
    a = r["CVE-2026-5001"]
    assert (a["fix_state"], a["fix_versions"], a["fix_next"], a["fix_state_source"]) == ("fixed", ["10.2.0-1ubuntu1.3"], "10.2.0-1ubuntu1.3", "ubuntu-tracker")
    assert a["fix_state_detail"] == (f"fix state from Ubuntu CVE Tracker (commit {COMMIT[:12]}, 2026-11-06): released 10.2.0-1ubuntu1.3 "
                                     f"for source package pillow in noble, installed source version {PV}")
    assert a["fix"].startswith("fixed in 10.2.0-1ubuntu1.3 (fix state from Ubuntu CVE Tracker")
    assert a["ubuntu_tracker"] == {"status": "released", "note": "10.2.0-1ubuntu1.3", "source_package": "pillow", "source_version": PV,
                                   "release": "noble", "per_cve": [{"cve": "CVE-2026-5001", "status": "released", "note": "10.2.0-1ubuntu1.3"}],
                                   "commit": COMMIT, "commit_date": "2026-11-05T00:00:00Z", "fetched_utc": "2026-11-06T01:00:00Z"}
    # 安裝的原始碼版本已經是修好的版本：fixed，沒有更新的修補版本（R3 的 {fix_version} 沒有值）
    b = r["CVE-2026-5002"]
    assert (b["fix_state"], b["fix_versions"], b["fix_next"]) == ("fixed", [PV], None)
    assert b["fix"].startswith(f"already fixed in the installed source version (fixed in {PV})")
    assert r["CVE-2026-5003"]["fix_state"] == "not-fixed" and r["CVE-2026-5003"]["fix_versions"] == []
    w = r["CVE-2026-5004"]
    assert w["fix_state"] == "wont-fix" and "ignored (end of standard support)" in w["fix_state_detail"]
    assert r["CVE-2026-5006"]["fix_state"] == "not-fixed" and "deferred (2026-10-22)" in r["CVE-2026-5006"]["fix_state_detail"]
    p = r["CVE-2026-5008"]
    assert p["fix_state"] == "not-fixed" and p["fix_next"] is None and "pending (10.2.0-1ubuntu1.4)" in p["fix_state_detail"]
    # 不推：needs-triage、not-affected（U1）、conflict、DNE、released 的註記不是版本、核心
    for c in ("CVE-2026-5005", "CVE-2026-5009", "CVE-2026-5010", "CVE-2026-5011", "CVE-2026-5012", "CVE-2026-6001"):
        assert r[c]["fix_state"] == "no Grype data" and "fix_state_source" not in r[c] and "fix_state_detail" not in r[c], c
    assert info["derived"] == 6 and info["by_state"] == {"fixed": 2, "not-fixed": 3, "wont-fix": 1} and info["already_fixed"] == 1
    # 核心的原始碼套件（linux、linux-*）：就算列沒有標成核心也不推
    assert cr.tracker_fix(dict(r["CVE-2026-6001"], kernel=False), ustat()) is None


def test_grype_wins_and_the_disagreement_is_listed():
    r, info = rows()
    g = r["CVE-2026-5007"]
    assert (g["fix_state"], g["fix_versions"]) == ("fixed", ["10.2.0-1ubuntu1.9"]) and "fix_state_source" not in g
    assert info["disagreements"] == [{"id": "CVE-2026-5007", "component": "pillow", "version": PV,
                                      "grype": {"fix_state": "fixed", "fix_versions": ["10.2.0-1ubuntu1.9"]},
                                      "tracker": {"fix_state": "not-fixed", "status": "needed", "note": "", "source_package": "pillow",
                                                  "release": "noble"}}]
    # 同一個狀態、同一個修補版本 → 不列；修補版本不同 → 列
    same = ustat({"CVE-2026-5007": ("released", "10.2.0-1ubuntu1.9")})
    assert rows(same)[1]["disagreements"] == []
    other = ustat({"CVE-2026-5007": ("released", "10.2.0-1ubuntu1.8")})
    assert rows(other)[1]["disagreements"][0]["tracker"]["note"] == "10.2.0-1ubuntu1.8"


def test_no_usable_tracker_changes_nothing():
    base, _ = rows(ustat({}))
    for us in ({"schema": "x"}, ustat(status="NOT_RUN"), dict(ustat(), entries=[])):
        r, info = rows(us)
        assert info["status"] == "not_available" and info["derived"] == 0 and info["detail"]
        assert {k: v["fix_state"] for k, v in r.items()} == {k: v["fix_state"] for k, v in base.items()}
    rs = rows_for(MIN_CFG, FINDS, GRY)
    info = cr.apply_ubuntu_tracker(rs, None)
    assert info["status"] == "not_available" and all("fix_state_source" not in x for x in rs)
    # 元件不在 components、原始碼版本不知道 → 不推
    for comps in ({}, {PIL_SRC: {"source": "pillow", "source_version": None, "release": "noble"}}):
        r, info = rows(ustat(comps=comps))
        assert info["derived"] == 0


def test_multi_cve_row_needs_one_state():
    us = ustat(dict(E, **{"CVE-2026-5013": ("released", "10.2.0-1ubuntu1.6")}))
    mixed = [finding("pillow", PV, "GHSA-aaaa-bbbb-cccc", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-5001"}, {"cveId": "CVE-2026-5003"}], purl=PIL_SRC)]
    r, info = rows(us, None, mixed)
    assert r["CVE-2026-5001"]["fix_state"] == "no Grype data" and info["derived"] == 0       # released ＋ needed：不推
    both = [finding("pillow", PV, "GHSA-dddd-eeee-ffff", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-5001"}, {"cveId": "CVE-2026-5013"}], purl=PIL_SRC)]
    x = rows(us, None, both)[0]["CVE-2026-5001"]
    # 兩個 CVE 都 released：修補版本兩個都列，{fix_version} 取比安裝版本新的最低的（同 Grype 的列）
    assert x["fix_versions"] == ["10.2.0-1ubuntu1.3", "10.2.0-1ubuntu1.6"] and x["fix_next"] == "10.2.0-1ubuntu1.3"
    assert "CVE-2026-5001 released 10.2.0-1ubuntu1.3; CVE-2026-5013 released 10.2.0-1ubuntu1.6 for source package pillow" in x["fix_state_detail"]


def test_deb_python_module_uses_the_owning_deb_source():
    sbom = dict(SBOM, components=[pyc("pillow", "10.2.0", f"{DP}/pillow-10.2.0.dist-info/METADATA"),
                                  debc("python3-pil", PV, "pillow", arch="arm64")])
    f = [finding("pillow", "10.2.0", "GHSA-pppp-pppp-pppp", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-5003"}], purl="pkg:pypi/pillow@10.2.0"),
         finding("pillow", "10.2.0", "GHSA-qqqq-qqqq-qqqq", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-5001"}], purl="pkg:pypi/pillow@10.2.0")]
    rs = rows_for(MIN_CFG, f, {"matches": []})
    dpy, _ = cr.deb_python_index(sbom["components"])
    assert dpy["pkg:pypi/pillow@10.2.0"]["owner"]["purl"] == PIL_BIN
    cr.apply_deb_python(rs, dpy, {}, True)
    for r in rs:
        r["kernel"] = False
    info = cr.apply_ubuntu_tracker(rs, ustat())
    r = {x["id"]: x for x in rs}
    n = r["CVE-2026-5003"]
    assert n["fix_state"] == "not-fixed" and n["fix_state_source"] == "ubuntu-tracker" and n["ubuntu_tracker"]["source_package"] == "pillow"
    assert n["fix"].startswith(f"update the Ubuntu package python3-pil (installed {PV}), not pip; Ubuntu fix state: not fixed yet (fix state from")
    y = r["CVE-2026-5001"]
    assert (y["fix_state"], y["fix_next"]) == ("fixed", "10.2.0-1ubuntu1.3") and info["derived"] == 2
    # 擁有它的 deb 套件沒有這些 CVE 的列：以擁有者 python3-pil（deb）直接套用批次規則（vex_export.deb_python_rules）；PyPI 的規則不套用
    pyrule = dict(RULES, rules=[dict(RULES["rules"][0], id="R4", match={"scope": "non_kernel", "purl_type": ["pypi"], "fix_state": ["fixed"]})])
    allr, _, vinfo = vx.assess(copy.deepcopy(rs), rules=vx.effective_rules(pyrule), rule_ctx={})
    assert all(x["vex"] is None for x in allr) and [x["excluded_deb_python"] for x in vinfo["rules"]] == [1]
    allr, _, vinfo = vx.assess(copy.deepcopy(rs), rules=vx.effective_rules(RULES), rule_ctx={})
    v = {x["id"]: x["vex"] for x in allr}
    assert v["CVE-2026-5001"]["rule"] == "R3" and v["CVE-2026-5003"]["rule"] == "R6"
    assert v["CVE-2026-5001"]["detail"].startswith(
        f"applied to the Ubuntu package python3-pil {PV}, which installed this module (pillow 10.2.0): Fixed in python3-pil 10.2.0-1ubuntu1.3 "
        f"(installed {PV}). Fix state from Ubuntu CVE Tracker")
    assert v["CVE-2026-5001"]["fix_version"] == "10.2.0-1ubuntu1.3" and v["CVE-2026-5001"]["applied_via_owner"]["purl"] == PIL_BIN
    assert vinfo["deb_python_rule_direct"] == 2 and {x["id"]: x["applied"] for x in vinfo["rules"]} == {"R3": 1, "R6": 1, "R7": 0}


RULES = {"schema": vx.RULES_SCHEMA, "author": "Tester", "rules": [
    {"id": "R3", "description": "Ubuntu package: newer fixed package available", "date": "2026-11-02", "reason": "update",
     "match": {"scope": "non_kernel", "purl_type": ["deb"], "fix_state": ["fixed"]},
     "set": {"state": "exploitable", "response": ["update"], "detail_template": "Fixed in {component} {fix_version} (installed {installed_version}).",
             "recommendation": "apt upgrade {component} to {fix_version} or later in the next image."}},
    {"id": "R6", "description": "Ubuntu package: no fixed package available yet", "date": "2026-11-02", "reason": "no fix",
     "match": {"scope": "non_kernel", "purl_type": ["deb"], "fix_state": ["not-fixed"]},
     "set": {"state": "exploitable", "response": ["can_not_fix"], "detail_template": "No fixed {component} package yet (installed {installed_version})."}},
    {"id": "R7", "description": "Ubuntu package: Ubuntu will not fix", "date": "2026-11-02", "reason": "won't fix",
     "match": {"scope": "non_kernel", "purl_type": ["deb"], "fix_state": ["wont-fix"]},
     "set": {"state": "exploitable", "response": ["will_not_fix"], "detail_template": "Ubuntu will not fix {component} (installed {installed_version})."}}]}
vx.check_rules(RULES)


def test_report_applies_rules_r3_r6_r7_with_tracker_provenance(tmp_path):
    proj = make_project(tmp_path / "p")
    write_json(proj / vx.RULES_REL, RULES)
    sc = make_scan(tmp_path / "s", findings=FINDS, grype=GRY)
    # 沒有 scan/ubuntu-status.json：和以前一樣（沒有 ubuntu_tracker_fix、規則看不到 Tracker）
    r0, s0, rep0 = run(proj, sc)
    assert r0.returncode in (0, 2), r0.stdout + r0.stderr
    assert "ubuntu_tracker_fix" not in s0 and "from the Ubuntu CVE Tracker" not in (rep0 / "risk-assessment.md").read_text(encoding="utf-8")
    applied0 = {x["id"]: x["applied"] for x in s0["vex"]["rules"]["rules"]}
    assert applied0 == {"R3": 1, "R6": 0, "R7": 0}                                     # 只有 Grype 的 CVE-2026-5007
    md0 = (rep0 / "risk-assessment.md").read_text(encoding="utf-8")

    write_json(sc / "scan" / "ubuntu-status.json", ustat())
    r, s, rep = run(proj, sc)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    assert {x["id"]: x["applied"] for x in s["vex"]["rules"]["rules"]} == {"R3": 2, "R6": 3, "R7": 1}
    assert s["ubuntu_tracker_fix"]["derived"] == 6 and len(s["ubuntu_tracker_fix"]["disagreements"]) == 1
    # 層級不變（修補狀態不是分級的輸入）
    assert {k: s["counts"][k] for k in ("p1", "p2", "p3", "accepted")} == {k: s0["counts"][k] for k in ("p1", "p2", "p3", "accepted")}
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    det = {v["id"]: v["analysis"].get("detail", "") for v in cdx["vulnerabilities"]}
    assert det["CVE-2026-5001"].startswith(f"Fixed in pillow 10.2.0-1ubuntu1.3 (installed {PV}). Fix state from Ubuntu CVE Tracker "
                                           f"(commit {COMMIT[:12]}, 2026-11-06): released 10.2.0-1ubuntu1.3 for source package pillow in noble")
    assert det["CVE-2026-5001"].endswith("(bulk rule R3: Ubuntu package: newer fixed package available)")
    assert "ignored (end of standard support)" in det["CVE-2026-5004"] and "bulk rule R7" in det["CVE-2026-5004"]
    assert "bulk rule R6" in det["CVE-2026-5003"] and "bulk rule R6" in det["CVE-2026-5006"]
    # Grype 的修補狀態：陳述沒有 Tracker 的出處
    assert "Ubuntu CVE Tracker" not in det["CVE-2026-5007"] and "10.2.0-1ubuntu1.9" in det["CVE-2026-5007"]
    md = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Fix state for 6 Ubuntu rows without a Grype fix state is taken from the Ubuntu CVE Tracker" in md
    assert "1 row: Grype's fix state differs from the Ubuntu CVE Tracker; Grype's is used, both are shown: CVE-2026-5007 on pillow " \
           f"{PV}: Grype fixed 10.2.0-1ubuntu1.9, Tracker needed" in md
    assert md != md0
    # Tracker 不可用（NOT_RUN：過期、沒有鏡像）→ 和沒有檔案時的規則結果一樣
    write_json(sc / "scan" / "ubuntu-status.json", ustat(status="NOT_RUN"))
    r2, s2, _ = run(proj, sc)
    assert {x["id"]: x["applied"] for x in s2["vex"]["rules"]["rules"]} == applied0
    assert s2["ubuntu_tracker_fix"]["status"] == "not_available" and s2["ubuntu_tracker_fix"]["derived"] == 0


def test_summary_without_file_is_unchanged(tmp_path):
    """沒有 scan/ubuntu-status.json：summary 與文件不多任何東西。"""
    sc = make_scan(tmp_path / "s", findings=FINDS, grype=GRY)
    r, s, rep = run(make_project(tmp_path / "p"), sc)
    assert r.returncode in (0, 2) and "ubuntu_tracker_fix" not in s
    assert "fix_state_source" not in json.dumps(s) and "from the Ubuntu CVE Tracker" not in (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "fix state from Ubuntu CVE Tracker" not in (rep / "vex.cdx.json").read_text(encoding="utf-8").lower()


def test_copy_is_not_mutated():
    us = ustat()
    keep = copy.deepcopy(us)
    rows(us)
    assert us == keep


# ---------- Ubuntu 打包的 Python 模組：沿用擁有它的 deb 列的批次規則判定（vex_export.deb_python_rules） ----------

PYSBOM = [pyc("pillow", "10.2.0", f"{DP}/pillow-10.2.0.dist-info/METADATA"), debc("python3-pil", PV, "pillow", arch="arm64")]


def py_rows(*cves, kev=(), extra=()):
    """pillow 原始碼套件（DT）與 Ubuntu 打包的 pillow 模組（GHSA）上同樣的 CVE；修補狀態取自 Tracker。"""
    f = [finding("pillow", PV, c, "NVD", "MEDIUM", purl=PIL_SRC) for c in cves] + list(extra) \
        + [finding("pillow", "10.2.0", f"GHSA-{i:04d}-pppp-pppp", "GITHUB", "MEDIUM", [{"cveId": c}], purl="pkg:pypi/pillow@10.2.0", kev=c in kev)
           for i, c in enumerate(cves)]
    rs = rows_for(MIN_CFG, f, {"matches": []})
    cr.apply_deb_python(rs, cr.deb_python_index(PYSBOM)[0], {}, True)
    for r in rs:
        r["kernel"] = False
    cr.apply_ubuntu_tracker(rs, ustat())
    return rs


def py_of(allr, cve):
    return next(x for x in allr if x["id"] == cve and x["ptype"] == "pypi")


def deb_of(allr, cve):
    return next(x for x in allr if x["id"] == cve and x["ptype"] == "deb")


def test_module_inherits_the_owning_deb_rule_statement():
    allr, _, info = vx.assess(py_rows("CVE-2026-5001", "CVE-2026-5003", "CVE-2026-5004"), rules=vx.effective_rules(RULES), rule_ctx={})
    for c, rule in (("CVE-2026-5001", "R3"), ("CVE-2026-5003", "R6"), ("CVE-2026-5004", "R7")):
        d, x = deb_of(allr, c), py_of(allr, c)
        assert d["vex"]["rule"] == rule and x["vex"]["rule"] == rule and x["vex"]["source"] == "rule", c
        assert (x["vex"]["state"], x["vex"].get("response")) == (d["vex"]["state"], d["vex"].get("response"))
        assert x["vex"]["detail"] == (f"inherited from pillow {PV} (the Ubuntu source package of python3-pil, which installed this module): "
                                      + d["vex"]["detail"])
        assert x["vex"]["inherited_from"] == {"id": c, "component": "pillow", "version": PV}
    assert py_of(allr, "CVE-2026-5001")["vex"]["fix_version"] == "10.2.0-1ubuntu1.3"
    assert py_of(allr, "CVE-2026-5001")["vex"]["action_statement"].startswith("apt upgrade pillow to 10.2.0-1ubuntu1.3")
    assert info["deb_python_rule_inherited"] == 3 and info.get("deb_python_rule_direct", 0) == 0
    assert {x["id"]: (x["applied"], x["inherited_deb_python"]) for x in info["rules"]} == {"R3": (1, 1), "R6": (1, 1), "R7": (1, 1)}


def test_module_rule_inheritance_exclusions():
    rules = vx.effective_rules(RULES)
    # KEV（任一來源）、被利用（EUVD、人工證據）的模組列：不沿用
    allr, _, info = vx.assess(py_rows("CVE-2026-5001", kev=("CVE-2026-5001",)), rules=rules, rule_ctx={})
    assert py_of(allr, "CVE-2026-5001")["vex"] is None
    allr, _, info = vx.assess(py_rows("CVE-2026-5003"), rules=rules, rule_ctx={"exploited": ["CVE-2026-5003"]})
    assert py_of(allr, "CVE-2026-5003")["vex"] is None and deb_of(allr, "CVE-2026-5003")["vex"] is None
    # P1 的模組列（規則沒有 allow_p1）：不沿用
    rs = py_rows("CVE-2026-5003")
    py_of(rs, "CVE-2026-5003")["tier"] = "p1"
    allr, _, info = vx.assess(rs, rules=rules, rule_ctx={})
    assert py_of(allr, "CVE-2026-5003")["vex"] is None and info["deb_python_rule_p1_not_inherited"] == 1
    # deb 列已修好（沒有 {fix_version}，R3 不套用）→ deb 列沒有判定，模組列也不套（不另外以擁有者套用）
    allr, _, info = vx.assess(py_rows("CVE-2026-5002"), rules=rules, rule_ctx={})
    assert deb_of(allr, "CVE-2026-5002")["vex"] is None and py_of(allr, "CVE-2026-5002")["vex"] is None
    # deb 列的判定是人的（vex-annotations.json）：照舊由 inherit_deb_python 沿用，不是規則
    ann = [{"cve": "CVE-2026-5003", "purl": "pkg:deb/ubuntu/pillow", "version": PV, "state": "not_affected",
            "justification": "code_not_reachable", "detail": "feature not used", "author": "Carol", "date": "2026-11-03"}]
    allr, _, info = vx.assess(py_rows("CVE-2026-5003"), annotations=ann, rules=rules, rule_ctx={})
    x = py_of(allr, "CVE-2026-5003")
    assert x["vex"]["source"] == "annotation" and x["vex"]["detail"].startswith("inherited from the decision on") and "rule" not in x["vex"]
    # DT 裡模組列已 suppress（人看過）：不動
    rs = py_rows("CVE-2026-5003")
    py_of(rs, "CVE-2026-5003")["analysis"] = [dict(py_of(rs, "CVE-2026-5003")["analysis"][0], suppressed=True)]
    assert py_of(vx.assess(rs, rules=rules, rule_ctx={})[0], "CVE-2026-5003")["vex"] is None


def test_module_does_not_inherit_evidence_rules():
    """證據規則（U1 等）的判定是對 deb 列的產物檢查的，不沿用到模組列（模組列也不會因此移到 accepted）。"""
    from test_vex_evidence import erule
    us = ustat({"CVE-2026-5009": ("not-affected", PV)})
    rs = py_rows("CVE-2026-5009")
    doc = {"schema": vx.RULES_SCHEMA, "author": "Tester", "rules": [erule("U1", "U1")] + RULES["rules"]}
    vx.check_rules(doc)
    allr, _, info = vx.assess(rs, rules=vx.effective_rules(doc), rule_ctx={"ubuntu_status": us, "vercmp": cr.deb_vercmp,
                                                                            "today": "2026-11-06", "image_ids": ["a" * 64]})
    assert deb_of(allr, "CVE-2026-5009")["vex"]["evidence"] == "U1"
    assert py_of(allr, "CVE-2026-5009")["vex"] is None


def test_module_rule_conflict_between_binary_and_source_rows():
    """擁有者的二進位套件列與原始碼套件列的規則判定不同 → 不沿用，vex_note 寫出來。"""
    binf = finding("python3-pil", PV, "CVE-2026-5003", "NVD", "MEDIUM", purl=PIL_BIN)
    rs = py_rows("CVE-2026-5003", extra=[binf])
    b = next(x for x in rs if x["purl"] == PIL_BIN)
    b["fix_state"], b["fix_versions"], b["fix_next"] = "wont-fix", [], None
    allr, _, info = vx.assess(rs, rules=vx.effective_rules(RULES), rule_ctx={})
    x = py_of(allr, "CVE-2026-5003")
    assert x["vex"] is None and "different bulk-rule decisions" in x["vex_note"] and info["deb_python_rule_inherit_conflict"] == 1


def test_source_owner_fix_state_from_the_tracker_leaves_the_row_alone():
    """候選都來自同一個原始碼套件（source_owner）的模組列：Tracker 推出的修補狀態只記在 deb_python.source_owner_fix，列自己的修補欄照舊。"""
    sb = [pyc("pillow", "10.2.0", f"{DP}/pillow-10.2.0.dist-info/METADATA"), debc("python3-pil", PV, "pillow", arch="arm64"),
          debc("python3-pil.imagetk", PV, "pillow", arch="arm64")]
    f = [finding("pillow", "10.2.0", "GHSA-pppp-pppp-pppp", "GITHUB", "MEDIUM", [{"cveId": "CVE-2026-5003"}], purl="pkg:pypi/pillow@10.2.0")]
    rs = rows_for(MIN_CFG, f, {"matches": []})
    cr.apply_deb_python(rs, cr.deb_python_index(sb)[0], {}, True)
    rs[0]["kernel"] = False
    before = {k: rs[0][k] for k in ("fix_state", "fix_versions", "fix_next", "fix")}
    info = cr.apply_ubuntu_tracker(rs, ustat())
    assert {k: rs[0][k] for k in before} == before and "fix_state_source" not in rs[0]
    sf = rs[0]["deb_python"]["source_owner_fix"]
    assert sf["fix_state"] == "not-fixed" and sf["fix_state_source"] == "ubuntu-tracker" and info["derived_source_owner"] == 1
    allr, _, vinfo = vx.assess(rs, rules=vx.effective_rules(RULES), rule_ctx={})
    assert allr[0]["vex"]["rule"] == "R6" and "Fix state from Ubuntu CVE Tracker" in allr[0]["vex"]["detail"]


def test_module_evidence_and_bulk_rule_on_owner_rows_is_a_conflict():
    """審查 Low：擁有者的原始碼套件列是 U1（not_affected）、二進位套件列是批次規則 → 不沿用，vex_note 寫出來。"""
    from test_vex_evidence import erule
    binf = finding("python3-pil", PV, "CVE-2026-5009", "NVD", "MEDIUM", purl=PIL_BIN)
    rs = py_rows("CVE-2026-5009", extra=[binf])
    b = next(x for x in rs if x["purl"] == PIL_BIN)
    b["fix_state"], b["fix_versions"], b["fix_next"] = "not-fixed", [], None
    doc = {"schema": vx.RULES_SCHEMA, "author": "Tester", "rules": [erule("U1", "U1")] + RULES["rules"]}
    vx.check_rules(doc)
    us = ustat({"CVE-2026-5009": ("not-affected", PV)}, comps={PIL_SRC: {"source": "pillow", "source_version": PV, "release": "noble"}})
    allr, _, info = vx.assess(rs, rules=vx.effective_rules(doc), rule_ctx={"ubuntu_status": us,
                                                                            "vercmp": cr.deb_vercmp, "today": "2026-11-06", "image_ids": ["a" * 64]})
    assert deb_of(allr, "CVE-2026-5009")["vex"]["evidence"] == "U1" and b["vex"]["rule"] == "R6"
    x = py_of(allr, "CVE-2026-5009")
    assert x["vex"] is None and "an evidence-rule decision and a bulk-rule decision" in x["vex_note"]
    assert info["deb_python_rule_evidence_conflict"] == 1


def test_module_inherits_only_when_the_rule_criteria_hold_for_it():
    """審查 Low：規則的條件（severity、tier、epss_percentile_max）要對 Python 模組的列也成立，否則不沿用。"""
    sev = {"schema": vx.RULES_SCHEMA, "author": "Tester", "rules": [dict(RULES["rules"][1], match=dict(RULES["rules"][1]["match"], severity=["MEDIUM"]))]}
    vx.check_rules(sev)
    rs = py_rows("CVE-2026-5003")
    py_of(rs, "CVE-2026-5003")["severity"] = "CRITICAL"            # deb 列 MEDIUM（R6 套用），模組列 CRITICAL
    allr, _, info = vx.assess(rs, rules=vx.effective_rules(sev), rule_ctx={})
    assert deb_of(allr, "CVE-2026-5003")["vex"]["rule"] == "R6" and py_of(allr, "CVE-2026-5003")["vex"] is None
    assert info["deb_python_rule_criteria_not_met"] == 1
    # 一樣的嚴重度 → 沿用
    allr, _, info = vx.assess(py_rows("CVE-2026-5003"), rules=vx.effective_rules(sev), rule_ctx={})
    assert py_of(allr, "CVE-2026-5003")["vex"]["rule"] == "R6"
    # EPSS 上限：模組列的 EPSS 比較高 → 不沿用
    ep = {"schema": vx.RULES_SCHEMA, "author": "Tester", "rules": [dict(RULES["rules"][1], match=dict(RULES["rules"][1]["match"],
                                                                                                  epss_percentile_max=0.5, include_no_epss=True))]}
    vx.check_rules(ep)
    rs = py_rows("CVE-2026-5003")
    py_of(rs, "CVE-2026-5003")["epss_pct"] = 0.9
    allr, _, info = vx.assess(rs, rules=vx.effective_rules(ep), rule_ctx={})
    assert deb_of(allr, "CVE-2026-5003")["vex"]["rule"] == "R6" and py_of(allr, "CVE-2026-5003")["vex"] is None
    # tier：規則只給 p3，模組列是 p2 → 不沿用
    tr = {"schema": vx.RULES_SCHEMA, "author": "Tester", "rules": [dict(RULES["rules"][1], match=dict(RULES["rules"][1]["match"], tier=["p3"]))]}
    vx.check_rules(tr)
    rs = py_rows("CVE-2026-5003")
    py_of(rs, "CVE-2026-5003")["tier"] = "p2"
    allr, _, info = vx.assess(rs, rules=vx.effective_rules(tr), rule_ctx={})
    assert py_of(allr, "CVE-2026-5003")["vex"] is None and info["deb_python_rule_criteria_not_met"] == 1
