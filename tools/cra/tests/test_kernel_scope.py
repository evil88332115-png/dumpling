"""映像另有出貨但沒判定的核心（scan/kernel-versions.json 的 not_judged）：K1（kernel-config.json）與 K2（kernel-module-map.json）的排除
不套用到整個產品。合成資料。沒有檔案、或 not_judged 為空時輸出和以前完全相同。"""
import copy
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import runtime_evidence as re_  # noqa: E402
import vex_export as vx  # noqa: E402
from test_cra_report import kernel_scan, make_project, run, write_json  # noqa: E402
from test_vex_evidence import KCFG, MMAP, assess, erule, kmods, rules_of  # noqa: E402
from test_vex_export import kcfg, ra, row  # noqa: E402
from test_vex_rules import krow  # noqa: E402

A, B = "6.8.12-1021-tegra", "6.8.12-1099-tegra"          # 合成的核心版本
SCHEMA = "sca-center-kernel-versions/2"


def kv(judged, not_judged, shipped=None):
    return {"schema": SCHEMA, "shipped": [{"version": v, "upstream_version": None, "upstream_basis": None, "upstream_note": "x"} for v in (shipped or sorted(judged + not_judged))], "requested": judged, "judged": judged,
            "not_judged": [{"version": v, "reason": "x", "shipped": True} for v in not_judged]}


PARTIAL = kv([A], [B])


def test_scope_of_and_with_scope():
    assert vx.kernel_scope_of(None) is None and vx.kernel_scope_of({}) is None and vx.kernel_scope_of(kv([A], [])) is None
    assert vx.kernel_scope_of(dict(PARTIAL, schema="other/1")) is None
    assert vx.kernel_scope_of(PARTIAL) == {"judged": [A], "not_judged": [B]}
    assert vx.kernel_scope_of(dict(PARTIAL, schema="sca-center-kernel-versions/1", shipped=[A, B])) == {"judged": [A], "not_judged": [B]}      # 舊檔照樣讀
    # 指定了但映像沒有的核心不算「出貨但沒判定」
    assert vx.kernel_scope_of({"schema": SCHEMA, "judged": [], "not_judged": [{"version": "9.9", "shipped": False}]}) is None
    assert vx.kernel_with_scope(KCFG, None) is KCFG and vx.kernel_with_scope(KCFG, kv([A], [])) is KCFG       # 沒有限制：原樣
    d = vx.kernel_with_scope(KCFG, PARTIAL)
    assert d is not KCFG and d["scope_incomplete"] is True and d["scope"] == {"judged": [A], "not_judged": [B]} and "scope_incomplete" not in KCFG
    assert vx.kernel_with_scope(None, PARTIAL) is None
    n = vx.kernel_scope_note(d)
    assert f"only kernel {A} was judged" in n and f"{B} shipped but was not judged" in n and "does not apply to the whole product" in n
    assert f"只判定了核心 {A}；{B} 已出貨、未判定，排除不適用整個產品" in n
    assert vx.kernel_scope_note(KCFG) == ""


def test_k1_k2_exclusions_are_not_adopted():
    rules = rules_of(erule("K1", "K1"), erule("K2", "K2"))
    rows = [krow("CVE-K1"), krow("CVE-RM")]
    base, _, _ = assess(rows, rules, KCFG, module_map=MMAP, kernel_modules=kmods())
    assert [(r["id"], r["vex"]["state"]) for r in base] == [("CVE-K1", "not_affected"), ("CVE-RM", "not_affected")]       # 對照：沒有限制時
    allr, _, info = assess(rows, rules, vx.kernel_with_scope(KCFG, PARTIAL), module_map=vx.kernel_with_scope(MMAP, PARTIAL), kernel_modules=kmods())
    assert [r["vex"] for r in allr] == [None, None]
    for r in allr:
        assert f"only kernel {A} was judged" in r["vex_note"] and B in r["vex_note"] and "只判定了核心" in r["vex_note"]
    assert info["kernel_scope_withheld"] == 2 and info["kernel_config"]["scope_incomplete"] is True and info["kernel_config"]["used"] is False
    # 自動的來源 (c)（沒有批次規則時的 kconfig）也一樣
    allr, _, info = vx.assess(copy.deepcopy([krow("CVE-K1")]), kcfg=vx.kernel_with_scope(KCFG, PARTIAL))
    assert allr[0]["vex"] is None and info["kernel_scope_withheld"] == 1
    allr, _, _ = vx.assess(copy.deepcopy([krow("CVE-K1")]), kcfg=KCFG)
    assert allr[0]["vex"]["source"] == "kconfig"
    # 一般批次規則的 kernel_config 條件也不成立
    assert vx.kconfig_all(vx.kernel_with_scope(KCFG, PARTIAL)) == {} and vx.kconfig_index(vx.kernel_with_scope(KCFG, PARTIAL)) == {}
    assert vx.module_map_of(vx.kernel_with_scope(MMAP, PARTIAL))[0] is None and "covers only part" in vx.module_map_of(vx.kernel_with_scope(MMAP, PARTIAL))[1]
    assert vx.module_map_of(MMAP)[0] is MMAP


def test_other_decisions_are_untouched():
    """人的判定、其他來源照舊；有判定的列不加說明。"""
    r = krow("CVE-K1", analysis=[{"state": "EXPLOITABLE", "suppressed": False, "justification": "", "response": "update", "details": ""}])
    allr, _, _ = vx.assess([r], kcfg=vx.kernel_with_scope(KCFG, PARTIAL))
    assert allr[0]["vex"]["state"] == "exploitable" and allr[0]["vex_note"] == ""


def test_runtime_evidence_does_not_use_scoped_kernel_config():
    k = {"schema": "sca-center-kernel-config/1", "results": [{"cve": "CVE-5", "decision": "not_affected", "files": [{"path": "a.c", "built": False}]}]}
    from test_runtime_evidence import runtime
    st = lambda kc: re_.Evidence(runtime(), None, "x", None, kc).fields({"id": "CVE-5", "kernel": True, "cves": ["CVE-5"]})["module_state"]
    assert st(k) is None and st(vx.kernel_with_scope(k, PARTIAL)) == re_.UNKNOWN


def make_report(tmp, kvers):
    sc = kernel_scan(tmp / "s")
    write_json(sc / "scan" / "kernel-config.json", kcfg([{"cve": "CVE-2025-0102", "decision": "not_affected", "detail": "CONFIG_X not set"}]))
    if kvers is not None:
        write_json(sc / "scan" / "kernel-versions.json", kvers)
    return run(make_project(tmp / "p"), sc)


def test_report_withholds_k1_and_shows_note(tmp_path):
    # 對照：沒有檔案時 K1 照舊排除
    r0, s0, rep0 = make_report(tmp_path / "a", None)
    assert s0["vex"]["sources"]["kconfig"] == 1 and "scope_incomplete" not in s0["vex"]["kernel_config"]
    # 只判定 1 顆、另一顆出貨未判定：不排除，列在核心表，附說明
    r1, s1, rep1 = make_report(tmp_path / "b", PARTIAL)
    assert s1["vex"]["sources"]["kconfig"] == 0 and s1["vex"]["kernel_config"]["scope_incomplete"] is True
    assert s1["vex"]["kernel_config"]["rows_withheld"] == 1 and s1["counts"]["accepted_by_vex"] == {}
    full = (rep1 / "kernel-vulnerabilities.md").read_text(encoding="utf-8")
    line = next(x for x in full.splitlines() if "CVE-2025-0102" in x)
    assert "not_affected" not in line and "untriaged [K1/K2 not adopted: another shipped kernel was not judged]" in line      # 表格的 VEX status 欄
    md = ra(rep1)
    assert "K1/K2" in md and B in md and "只判定了部分核心" in md and "1 kernel rows would have been excluded" in md
    assert any(B in w and "沒有判定" in w for w in s1.get("config_warnings", []))
    # VEX 檔案：對照組有這個 CVE 的 not_affected 陳述；這裡沒有任何判定的陳述。A4（M7c-1）起沒有判定的列也輸出，
    # 所以是一條沒評估的陳述（CycloneDX in_triage＋NOT_ASSESSED、OpenVEX under_investigation＋not assessed），不是 not_affected
    c0 = json.loads((rep0 / "vex.cdx.json").read_text(encoding="utf-8"))["vulnerabilities"]
    c1 = json.loads((rep1 / "vex.cdx.json").read_text(encoding="utf-8"))["vulnerabilities"]
    assert [v["analysis"]["state"] for v in c0 if v["id"] == "CVE-2025-0102"] == ["not_affected"]
    assert [(v["analysis"]["state"], {"name": "dumpling:assessment", "value": "NOT_ASSESSED"} in v["properties"]) for v in c1 if v["id"] == "CVE-2025-0102"] == [("in_triage", True)]
    o0 = json.loads((rep0 / "vex.openvex.json").read_text(encoding="utf-8"))["statements"]
    o1 = json.loads((rep1 / "vex.openvex.json").read_text(encoding="utf-8"))["statements"]
    assert [s["status"] for s in o0 if s["vulnerability"]["name"] == "CVE-2025-0102"] == ["not_affected"]
    assert [(s["status"], s["status_notes"]) for s in o1 if s["vulnerability"]["name"] == "CVE-2025-0102"] == [("under_investigation", "dumpling: not assessed")]
    # not_judged 為空：和沒有檔案完全相同
    r2, s2, rep2 = make_report(tmp_path / "c", kv([A], []))
    stamp = lambda p: re.sub(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", "T", p.read_text(encoding="utf-8"))      # 產生時間不比
    assert stamp(rep2 / "kernel-vulnerabilities.md") == stamp(rep0 / "kernel-vulnerabilities.md")
    assert s2["vex"]["sources"] == s0["vex"]["sources"] and s2["vex"]["kernel_config"] == s0["vex"]["kernel_config"]
