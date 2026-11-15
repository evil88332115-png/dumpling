"""M7c-2（D-035／D-057）：每一筆排除（resolved、not_affected、false_positive…）記依據類型與位置。
各來源的類型與位置（kconfig、K1、K2、U1、U2、distro、annotation、dt）、annotation 的欄位與驗證（on-device 的檔案檢查、design-doc）、
閘門（沒有類型的排除算進 untriaged_for_gate）、閘門基準（改動前 vs 改動後）、內部 CycloneDX／OpenVEX 的輸出、vexconv 往返、客戶版、
dt_writeback 不變、報告（summary.json、風險評估、文件狀態）。全部是合成資料。"""
import copy
import json
import os
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import supplier_package as sp  # noqa: E402
import vex_export as vx  # noqa: E402
from test_cra_distro import recheck_doc  # noqa: E402
from test_cra_report import FINDINGS, make_project, make_scan, run, write_json  # noqa: E402
from test_vex_evidence import KCFG, KV, MMAP, erule, kmods, mmap, rules_of  # noqa: E402
from test_vex_export import DEB, PBOM, ann, dt, kcfg, row, two_cve_row, typed  # noqa: E402
from test_vex_rules import krow  # noqa: E402
from test_vex_u1_flag import OSSL_PURL, UST as UST_U1, ustat  # noqa: E402
from test_vex_u2 import UST as UST_U2, prow  # noqa: E402
import vex_gate_scenarios as sc  # noqa: E402

VC = vx._vexconv()
GOLDEN = HERE / "data" / "vex_gate_before_d035.json"
OV_SCHEMA = os.path.join(HERE, "data", "openvex", "openvex_json_schema.json")
P = "pkg:deb/ubuntu/openssl"
IMG = sc.IMG


def prop_names(v):
    return [p["name"] for p in v["properties"]]


def build(rows, **kw):
    allr, conf, info = vx.assess(rows, **kw)
    cdx, st = vx.cdx_vex(allr, PBOM, {"finished": "2026-11-02T02:43:55Z", "name": "img"}, {"name": "EX-J100"}, "ATTENTION")
    return allr, conf, info, cdx, vx.openvex(cdx, "Example Co.", vx.purl_by_bomlink(PBOM))


def evidence_of(cdx, vid):
    """CycloneDX 的陳述（同一個編號有多條時取第一條有依據屬性的）→ 依序的依據 [(類型, 位置, 核心或 None)]（none 的位置是 None）。"""
    for v in cdx["vulnerabilities"]:
        if v["id"] != vid:
            continue
        out, ps = [], v["properties"]
        for i, p in enumerate(ps):
            if p["name"] == VC.PROP_EVIDENCE:
                loc = ps[i + 1]["value"] if i + 1 < len(ps) and ps[i + 1]["name"] == VC.PROP_EVIDENCE_LOCATION else None
                ker = ps[i + 2]["value"] if loc and i + 2 < len(ps) and ps[i + 2]["name"] == VC.PROP_EVIDENCE_KERNEL else None
                out.append((p["value"], loc, ker))
        if out:
            return out
    return []


# ---------- 常數與格式 ----------

def test_constants_match_across_modules():
    assert vx.EVIDENCE_TYPES == VC.EVIDENCE_TYPES == ("build-record", "source", "on-device", "design-doc", "vendor-statement")
    assert sp.EVIDENCE_PROP == VC.PROP_EVIDENCE and set(sp.EVIDENCE_SENTENCES) == set(VC.EVIDENCE_TYPES)
    assert VC.LOCATION_MAX == 512
    # 客戶版的句子：每種類型一句固定英文、不含內部名稱（check_customer_text 照常檢查）
    for t, text in sp.EVIDENCE_SENTENCES.items():
        assert text.startswith("Evidence: ") and sp.check_customer_text("vex.cdx.json", text) == [], t
    assert sp.check_customer_text("vex.cdx.json", sp.EVIDENCE_NOT_RECORDED) == []


# ---------- 各來源的類型與位置 ----------

def basis_of(r):
    return r["vex"]["evidence_basis"]


def test_kconfig_source_is_build_record_with_kernel_version_and_config_sha():
    k = kcfg([{"cve": "CVE-2025-1", "decision": "not_affected", "detail": "CONFIG_FOO is not set"}])
    allr, _, info = vx.assess([krow("CVE-2025-1")], kcfg=k)
    assert allr[0]["vex"]["source"] == "kconfig"
    assert basis_of(allr[0]) == [{"type": "build-record", "kernel": "6.8.12-1021-tegra",
                                  "location": "scan/kernel-config.json (kernel 6.8.12-1021-tegra, config SHA-256 " + "ab" * 32 + ")"}]
    assert info["evidence"]["by_type"]["build-record"] == 1 and info["evidence"]["without_type"]["total"] == 0


def test_k1_rule_keeps_its_rule_kind_and_adds_build_record():
    rules = rules_of(erule("K1", "K1"))
    allr, _, _ = vx.assess([krow("CVE-K1")], kcfg=KCFG, rules=rules, rule_ctx={"image_ids": [IMG], "today": "2026-11-05"})
    s = allr[0]["vex"]
    assert s["source"] == "rule" and s["evidence"] == "K1"                     # 原本規則的 evidence 欄位（規則種類）不動
    assert s["evidence_basis"] == [{"type": "build-record", "kernel": "6.8.12-1021-tegra",
                                    "location": "scan/kernel-config.json (kernel 6.8.12-1021-tegra, config SHA-256 " + "ab" * 32 + ")"}]


def k2_ctx(version=KV, **kw):
    return dict(image_ids=[IMG], today="2026-11-05", vercmp=None, kernel_fix_all={}, module_map_sha256="cd" * 32,
                kernel_modules=kmods(kernel_version=version), kernel_modules_info={"image": vx.norm_image(IMG), "sha256": "ef" * 32}, **kw)


def test_k2_is_build_record_with_module_map_and_module_list_locations():
    rules = rules_of(erule("K2", "K2"))
    allr, _, _ = vx.assess([krow("CVE-RM")], kcfg=KCFG, rules=rules, rule_ctx=k2_ctx(module_map=MMAP))
    s = allr[0]["vex"]
    assert s["source"] == "rule" and s["evidence"] == "K2" and s["state"] == "not_affected"
    assert s["evidence_basis"] == [{"type": "build-record", "kernel": KV, "location":
                                    "scan/kernel-config.json (config SHA-256 " + "ab" * 32 + "), scan/kernel-module-map.json (SHA-256 " + "cd" * 32
                                    + "), CRA/Config/kernel-modules.json (SHA-256 " + "ef" * 32 + ")"}]
    # 沒有核心設定檢查時不寫 kernel-config.json
    allr, _, _ = vx.assess([krow("CVE-RM")], rules=rules, rule_ctx=k2_ctx(module_map=MMAP))
    assert [e["location"].split(" (")[0] for e in basis_of(allr[0])] == ["scan/kernel-module-map.json"]
    assert "scan/kernel-config.json" not in basis_of(allr[0])[0]["location"]


def test_k2_kernel_field_follows_the_kernel_of_each_module_map():
    """映像有多顆核心時（D-036）每顆核心各有自己的依據：kernel 欄位是那顆核心的版本，不是別顆的。"""
    rules = rules_of(erule("K2", "K2"))
    got = {}
    for ver in ("6.8.12-1021-tegra", "5.15.136-tegra"):
        mm = mmap({"CVE-RM": {"modules": ["gone_mod"], "builtin": False}}, version=ver)
        allr, _, _ = vx.assess([krow("CVE-RM")], rules=rules, rule_ctx=k2_ctx(ver, module_map=mm))
        got[ver] = basis_of(allr[0])[0]["kernel"]
    assert got == {"6.8.12-1021-tegra": "6.8.12-1021-tegra", "5.15.136-tegra": "5.15.136-tegra"}


def ubuntu_status_with_tracker_files():
    u = ustat({"CVE-U1": {"openssl": {"noble": {"status": "not-affected", "note": "3.0.13-0ubuntu3.11"}}},
               "CVE-U2": {"openssl": {"noble": {"status": "not-affected", "note": "3.0.13-0ubuntu3.4"}}}})
    u["cve_info"] = {c: {"priority": "low", "tracker_file": f"active/{c}"} for c in ("CVE-U1", "CVE-U2")}
    return u


def test_u1_is_vendor_statement_one_per_cve_with_tracker_file_commit_and_page():
    rules = rules_of(erule("U1", "U1"))
    ctx = dict(image_ids=[IMG], today="2026-11-05", vercmp=__import__("cra_report").deb_vercmp, ubuntu_status=ubuntu_status_with_tracker_files())
    allr, _, _ = vx.assess([row("CVE-U1", cves=["CVE-U1", "CVE-U2"])], rules=rules, rule_ctx=ctx)
    s = allr[0]["vex"]
    assert s["evidence"] == "U1" and s["state"] == "not_affected"
    assert s["evidence_basis"] == [{"type": "vendor-statement", "location": f"Ubuntu CVE Tracker active/{c}@{'a' * 40}, https://ubuntu.com/security/{c}"}
                                   for c in ("CVE-U1", "CVE-U2")]
    # 沒有 tracker_file（cve_info 是空的）時用 CVE 編號代替；不知道 commit 時位置照樣寫得出來
    ctx["ubuntu_status"] = dict(ubuntu_status_with_tracker_files(), cve_info={}, mirror={})
    allr, _, _ = vx.assess([row("CVE-U1")], rules=rules, rule_ctx=ctx)
    assert basis_of(allr[0]) == [{"type": "vendor-statement", "location": "Ubuntu CVE Tracker CVE-U1 (commit not recorded), https://ubuntu.com/security/CVE-U1"}]


def test_u2_is_vendor_statement_with_tracker_commit_and_page():
    rules = rules_of(erule("U2", "U2"))
    ust = dict(UST_U2, cve_info={"CVE-P1": {"tracker_file": "active/CVE-P1"}})
    allr, _, _ = vx.assess([prow("CVE-P1")], rules=rules, rule_ctx=dict(image_ids=[IMG], today="2026-11-05", vercmp=__import__("cra_report").deb_vercmp,
                                                                       ubuntu_status=ust))
    s = allr[0]["vex"]
    assert s["state"] == "resolved" and s["evidence"] == "U2"
    assert s["evidence_basis"] == [{"type": "vendor-statement", "location": f"Ubuntu CVE Tracker active/CVE-P1@{'b' * 40}, https://ubuntu.com/security/CVE-P1"}]


def test_distro_fixed_is_vendor_statement_one_per_record_id():
    allr, _, _ = vx.assess([row("CVE-2024-6119"), row("CVE-2026-2000")], drc=recheck_doc())
    got = {r["id"]: basis_of(r) for r in allr}
    assert got["CVE-2024-6119"] == [{"type": "vendor-statement", "location": "UBUNTU-CVE-2024-6119"}]
    assert got["CVE-2026-2000"] == [{"type": "vendor-statement", "location": "USN-8000-1"}]


def test_distro_without_a_record_id_has_no_type():
    drc = recheck_doc()
    for r in drc["rows"]:
        for e in r["evidence"]:
            e["record"] = None
    allr, _, info = vx.assess([row("CVE-2024-6119")], drc=drc)
    assert allr[0]["vex"]["source"] == "distro" and vx.exclusion_basis(allr[0]["vex"]) == ([], "distro_no_record")
    assert info["evidence"]["without_type"]["by_reason"] == {"distro_no_record": 1}


def test_distro_basis_drops_record_ids_that_cannot_be_a_location():
    """紀錄編號清理之後仍然不合格（只有換行、控制字元或空白，清理後是空的）→ 不放進依據；合格的照樣放。含「;」或換行的編號清理成合格的位置。"""
    def drc_with(*records):
        d = recheck_doc()
        for r in d["rows"]:
            r["evidence"] = [{"record": rec} for rec in records]
        return d
    allr, _, info = vx.assess([row("CVE-2024-6119")], drc=drc_with("USN-1-1", "\n", "\x00\t ", "   "))
    assert basis_of(allr[0]) == [{"type": "vendor-statement", "location": "USN-1-1"}]
    for e in basis_of(allr[0]):
        assert not VC.location_problem(e["location"])
    # 只剩不合格的編號：沒有類型（原因 distro_no_record），不是一筆位置是空字串的依據
    allr, _, info = vx.assess([row("CVE-2024-6119")], drc=drc_with("\n", "\x00"))
    assert allr[0]["vex"]["source"] == "distro" and vx.exclusion_basis(allr[0]["vex"]) == ([], "distro_no_record")
    assert info["evidence"]["without_type"]["by_reason"] == {"distro_no_record": 1}
    # 含「;」或換行的編號不會原樣進位置：清理成通過 location_problem 的文字
    allr, _, _ = vx.assess([row("CVE-2024-6119")], drc=drc_with("USN-1;2\nx"))
    assert basis_of(allr[0]) == [{"type": "vendor-statement", "location": "USN-1,2 x"}]


def test_safe_location_makes_tool_built_locations_pass_the_location_check():
    """工具自己組的依據位置（safe_location）：「;」換成「,」、換行與控制字元換成空白（連續空白併成一個）、去掉前後空白、截到 512 字。
    原樣回傳時，含這些字元的位置會被 vexconv 拒收（或根本不能寫成依據行）。"""
    assert vx.safe_location("a;b") == "a,b"
    assert vx.safe_location("a\nb\r\nc\td\x00e\u2028f\u200bg\u2029h") == "a b c d e f g h"
    assert vx.safe_location("  padded  ") == "padded"
    assert len(vx.safe_location("x" * 600)) == VC.LOCATION_MAX == 512
    assert vx.safe_location("x" * 511 + " " + "y" * 20) == "x" * 511                  # 截斷後尾端的空白去掉
    for raw in ("a;b", "line1\nline2; x", "ctrl\x07\x00", "  lead", "z" * 1000, "rtl\u202eyx"):
        assert VC.location_problem(vx.safe_location(raw)) is None, repr(raw)
    # 進到依據裡也一樣（basis_entry、Ubuntu tracker 的檔案名稱含「;」與換行）
    assert vx.basis_entry("source", "fix; commit\nabc") == {"type": "source", "location": "fix, commit abc"}
    ust = ubuntu_status_with_tracker_files()
    ust["cve_info"]["CVE-U1"]["tracker_file"] = "active/CVE-U1;\nbad"
    rules = rules_of(erule("U1", "U1"))
    ctx = dict(image_ids=[IMG], today="2026-11-05", vercmp=__import__("cra_report").deb_vercmp, ubuntu_status=ust)
    allr, _, _ = vx.assess([row("CVE-U1")], rules=rules, rule_ctx=ctx)
    loc = basis_of(allr[0])[0]["location"]
    assert loc.startswith("Ubuntu CVE Tracker active/CVE-U1, bad@") and VC.location_problem(loc) is None


def test_dt_is_always_without_type_even_when_an_annotation_with_evidence_says_the_same():
    """DT 的人工判定沒有放依據類型的欄位；DT 與 annotation 結論相同時 DT 優先（來源順序），所以這一列沒有類型。"""
    a = ann("CVE-1", "not_affected", purl=P, evidence="source", evidence_location="fix commit abc123")
    allr, _, info = vx.assess([row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="x"))], annotations=[a])
    assert allr[0]["vex"]["source"] == "dt" and vx.exclusion_basis(allr[0]["vex"]) == ([], "dt")
    assert info["evidence"]["without_type"] == {"total": 1, "by_reason": {"dt": 1}, "sample": [
        {"id": "CVE-1", "component": "openssl", "version": allr[0]["version"], "source": "dt", "reason": "dt"}]}
    # DT 只用其他的狀態表示時（FALSE_POSITIVE、RESOLVED）一樣
    for st in ("FALSE_POSITIVE", "RESOLVED"):
        r = vx.assess([row("CVE-2", analysis=dt(st, "CODE_NOT_PRESENT", details="x"))])[0][0]
        assert vx.exclusion_basis(r["vex"]) == ([], "dt"), st


def test_only_known_sources_produce_exclusions_and_each_has_a_known_type():
    """盤點（M7c-2 第 1 點）：產生排除的來源只有 dt、annotation、distro、kconfig 與證據規則 K1／K2／U1／U2；plain 規則（match／set）不能
    排除、nvidia 只給 in_triage。用所有來源的資料跑一次，看每一筆排除的來源。"""
    sc_all = {n: sc.run_unit(n, spec)[0] for n, spec in sc.scenarios().items()}
    seen = {}
    for allr in sc_all.values():
        for r in allr:
            for x in [r] + (r.get("vex_extra") or []):
                if vx.is_exclusion(x.get("vex")):
                    s = x["vex"]
                    seen.setdefault((s["source"], s.get("evidence")), set()).add(bool(s.get("evidence_basis")))
    assert set(seen) == {("dt", None), ("annotation", None), ("distro", None), ("kconfig", None),
                         ("rule", "K1"), ("rule", "K2"), ("rule", "U1"), ("rule", "U2")}
    # 工具來源都帶類型；人的來源（dt、annotation）在這些輸入裡都沒有
    assert {k: v for k, v in seen.items() if k[0] in ("distro", "kconfig", "rule")} == {k: {True} for k in seen if k[0] in ("distro", "kconfig", "rule")}
    assert seen[("dt", None)] == {False} and seen[("annotation", None)] == {False}
    # plain 規則不能設 not_affected／resolved（規則檔整份拒絕），NVIDIA 推定只給 in_triage
    from test_vex_rules import doc, rule
    for state in ("not_affected", "resolved", "false_positive"):
        with pytest.raises(vx.VexInputError):
            vx.check_rules(doc(rule(state=state, response=())))
    allr, _, info = vx.assess([row("CVE-2021-34401", "nvidia-l4t-core", "39.2.1-20260806224157")], nvb=sc.NVB)
    assert allr[0]["vex"]["source"] == "nvidia" and allr[0]["vex"]["state"] == "in_triage" and info["evidence"]["exclusions"] == 0


# ---------- annotation 的欄位與驗證 ----------

def errs(**kw):
    return vx.validate_annotation(ann("CVE-2026-1", "not_affected", purl=P, **kw), "a")


@pytest.mark.parametrize("kw,msg", [
    (dict(evidence="guess", evidence_location="x"), "evidence：只能是"),
    (dict(evidence="source"), "要一起寫"),
    (dict(evidence_location="x"), "要一起寫"),
    (dict(evidence="source", evidence_location=""), "must not be empty"),
    (dict(evidence="source", evidence_location="   "), "must not be empty"),
    (dict(evidence="source", evidence_location=" x"), "whitespace"),
    (dict(evidence="source", evidence_location="x" * 513), "longer than 512"),
    (dict(evidence="source", evidence_location="line\nbreak"), "line break or a control"),
    (dict(evidence="source", evidence_location="tab\there"), "line break or a control"),
    (dict(evidence="source", evidence_location="nul\x00x"), "line break or a control"),
    (dict(evidence="source", evidence_location="bell\x07x"), "line break or a control"),
    (dict(evidence="source", evidence_location="del\x7fx"), "line break or a control"),
    (dict(evidence="source", evidence_location="sep\u2028x"), "line break or a control"),
    (dict(evidence="source", evidence_location="rtl\u202ex"), "line break or a control"),
    (dict(evidence="source", evidence_location="a;b"), "must not contain ';'"),
    (dict(evidence="source", evidence_location=["ok", "a;b"]), "evidence_location[1]"),
    (dict(evidence="source", evidence_location=[]), "清單要有"),
    (dict(evidence="source", evidence_location=5), "must be a string"),
    (dict(evidence="source", evidence_location="x", evidence_basis=[{"type": "source", "location": "x"}]), "不能和"),
    (dict(evidence_basis=[]), "清單"),
    (dict(evidence_basis="x"), "清單"),
    (dict(evidence_basis=["x"]), "要是物件"),
    (dict(evidence_basis=[{"type": "nope", "location": "x"}]), "type：只能是"),
    (dict(evidence_basis=[{"type": "source", "location": "a;b"}]), "location：must not contain"),
    (dict(evidence_basis=[{"type": "source", "location": "x", "kernel": "bad kernel"}]), "kernel："),
    (dict(evidence_basis=[{"type": "source", "location": "x", "extra": 1}]), "不認得的鍵"),
])
def test_annotation_evidence_validation_errors(kw, msg):
    e = errs(**kw)
    assert e and any(msg in x for x in e), (kw, e)


def test_annotation_evidence_valid_forms_and_basis_expansion():
    assert errs() == []
    assert errs(evidence="build-record", evidence_location="scan/kernel-config.json") == []
    assert errs(evidence="design-doc", evidence_location=["Design spec v3 §4.2", "Design spec v3 §4.3"]) == []
    assert errs(evidence="source", evidence_location="x" * 512) == []
    assert errs(evidence_basis=[{"type": "build-record", "location": "k1", "kernel": "5.15.136-tegra"},
                                {"type": "build-record", "location": "k2", "kernel": "6.8.12-1021-tegra"}]) == []
    a = ann("CVE-1", purl=P, evidence="source", evidence_location=["a", "b", "a"])
    assert vx.annotation_basis(a) == [{"type": "source", "location": "a"}, {"type": "source", "location": "b"}]       # 重複的只留一筆
    a = ann("CVE-1", purl=P, evidence_basis=[{"type": "on-device", "location": "x", "kernel": "5.15"}])
    assert vx.annotation_basis(a) == [{"type": "on-device", "location": "x", "kernel": "5.15"}]
    assert vx.annotation_basis(ann("CVE-1", purl=P)) == []
    # check_annotations（整份檔案）把錯誤帶進訊息；有錯的整份拒絕
    with pytest.raises(vx.VexInputError, match="evidence_location"):
        vx.check_annotations({"schema": vx.ANN_SCHEMA, "annotations": [ann("CVE-1", purl=P, evidence="source", evidence_location="a;b")]})


def project_with(tmp_path, files=()):
    for f in files:
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("measured on the device\n", encoding="utf-8")
    return tmp_path


def test_on_device_location_must_be_an_existing_file_inside_the_project(tmp_path):
    proj = project_with(tmp_path / "proj", ["CRA/evidence/dev-check.txt", "plain.txt"])
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    (proj / "link-out").symlink_to(outside)
    (proj / "link-in").symlink_to(proj / "plain.txt")
    (proj / "link-dir-out").symlink_to(tmp_path)
    (proj / "adir").mkdir()
    f = vx.on_device_problem
    assert f("CRA/evidence/dev-check.txt", proj) is None and f("plain.txt", proj) is None
    assert f("./plain.txt", proj) is None and f("CRA//evidence/dev-check.txt", proj) is None
    assert f("link-in", proj) is None                                              # 符號連結但指到專案內
    assert f("link-out", proj) == "on_device_missing"                               # 指到專案外面＝算不存在
    assert f("link-dir-out/outside.txt", proj) == "on_device_missing"              # 經過資料夾的符號連結到外面
    assert f("missing.txt", proj) == "on_device_missing" and f("adir", proj) == "on_device_missing"      # 不存在、是資料夾
    assert f(str(outside), proj) == "on_device_unsafe_path"                         # 絕對路徑（即使檔案存在）
    assert f("/etc/passwd", proj) == "on_device_unsafe_path"
    assert f("../outside.txt", proj) == "on_device_unsafe_path" and f("CRA/../plain.txt", proj) == "on_device_unsafe_path"
    assert f("a\\b", proj) == "on_device_unsafe_path" and f("C:/x", proj) == "on_device_unsafe_path" and f("~/x", proj) == "on_device_unsafe_path"
    assert f("plain.txt", None) == "on_device_no_project" and f("../x", None) == "on_device_unsafe_path"
    # 檔案的內容完全不看：空檔案也算
    (proj / "empty.txt").write_text("")
    assert f("empty.txt", proj) is None


def test_on_device_annotation_gets_a_type_only_when_the_file_checks_out(tmp_path):
    proj = project_with(tmp_path / "proj", ["CRA/evidence/dev-check.txt"])
    cases = {"CRA/evidence/dev-check.txt": None, "CRA/evidence/none.txt": "on_device_missing", "/abs/path.txt": "on_device_unsafe_path",
             "../up.txt": "on_device_unsafe_path"}
    for loc, why in cases.items():
        a = ann("CVE-1", "not_affected", purl=P, evidence="on-device", evidence_location=loc)
        allr, _, info = vx.assess([row("CVE-1")], annotations=[a], project=proj)
        s = allr[0]["vex"]
        assert s["source"] == "annotation"
        if why is None:
            assert s["evidence_basis"] == [{"type": "on-device", "location": loc}] and info["evidence"]["on_device"][0]["location"] == loc
        else:
            assert vx.exclusion_basis(s) == ([], why) and info["evidence"]["without_type"]["by_reason"] == {why: 1}
    # 沒給專案資料夾 → 不能檢查，沒有類型
    allr, _, _ = vx.assess([row("CVE-1")], annotations=[ann("CVE-1", "not_affected", purl=P, evidence="on-device", evidence_location="CRA/evidence/dev-check.txt")])
    assert vx.exclusion_basis(allr[0]["vex"]) == ([], "on_device_no_project")
    # 一筆不合格，整筆都沒有類型（不能靠另一筆依據過關）
    a = ann("CVE-1", "not_affected", purl=P, evidence_basis=[{"type": "source", "location": "commit abc"}, {"type": "on-device", "location": "nope.txt"}])
    allr, _, _ = vx.assess([row("CVE-1")], annotations=[a], project=proj)
    assert vx.exclusion_basis(allr[0]["vex"]) == ([], "on_device_missing")


def test_design_doc_needs_no_file_and_other_types_do_not_check_files(tmp_path):
    a = ann("CVE-1", "not_affected", purl=P, evidence="design-doc", evidence_location="Product design spec v3, section 4.2 (no network stack)")
    allr, _, info = vx.assess([row("CVE-1")], annotations=[a], project=tmp_path)
    assert allr[0]["vex"]["evidence_basis"] == [{"type": "design-doc", "location": "Product design spec v3, section 4.2 (no network stack)"}]
    assert info["evidence"]["design_doc"][0]["location"].startswith("Product design spec") and info["evidence"]["by_type"]["design-doc"] == 1
    a = ann("CVE-1", "not_affected", purl=P, evidence="source", evidence_location="does/not/exist.c")
    assert vx.assess([row("CVE-1")], annotations=[a], project=tmp_path)[0][0]["vex"]["evidence_basis"][0]["type"] == "source"


def test_annotation_without_evidence_or_with_unvalidated_bad_evidence_has_no_type():
    allr, _, _ = vx.assess([row("CVE-1")], annotations=[ann("CVE-1", "not_affected", purl=P)])
    assert vx.exclusion_basis(allr[0]["vex"]) == ([], "annotation_no_evidence")
    # 呼叫端沒經過 check_annotations 就給進來的壞資料也不會變成有類型
    bad = ann("CVE-1", "not_affected", purl=P, evidence="source", evidence_location="a;b\nc")
    allr, _, _ = vx.assess([row("CVE-1")], annotations=[bad])
    assert vx.exclusion_basis(allr[0]["vex"]) == ([], "annotation_evidence_invalid")
    # exploitable、in_triage 的判定不看依據
    allr, _, info = vx.assess([row("CVE-2")], annotations=[ann("CVE-2", "exploitable", purl=P, evidence="source", evidence_location="x")])
    assert "evidence_basis" not in allr[0]["vex"] and info["evidence"]["exclusions"] == 0


def test_annotate_cli_flags_and_validation(tmp_path):
    proj = project_with(tmp_path / "p", ["CRA/evidence/dev-check.txt"])
    args = ["annotate", "--project", str(proj), "--cve", "CVE-2026-9", "--state", "not_affected", "--justification", "code_not_reachable",
            "--detail", "checked on the device", "--author", "Alice", "--date", "2026-11-01", "--purl", P]
    assert vx.main(args + ["--evidence", "on-device", "--evidence-location", "CRA/evidence/dev-check.txt"]) == 0
    doc = json.loads((proj / vx.ANN_REL).read_text(encoding="utf-8"))
    assert doc["annotations"][0]["evidence"] == "on-device" and doc["annotations"][0]["evidence_location"] == "CRA/evidence/dev-check.txt"
    # 多個位置＝清單；每顆核心各一筆
    assert vx.main(args[:4] + ["CVE-2026-8"] + args[5:] + ["--evidence", "source", "--evidence-location", "commit a1", "commit b2"]) == 0
    assert vx.main(args[:4] + ["CVE-2026-7"] + args[5:] + ["--evidence-basis", json.dumps([
        {"type": "build-record", "location": "k1 config", "kernel": "5.15.136-tegra"}, {"type": "build-record", "location": "k2 config", "kernel": "6.8.12-1021-tegra"}])]) == 0
    doc = json.loads((proj / vx.ANN_REL).read_text(encoding="utf-8"))
    by = {a["cve"]: a for a in doc["annotations"]}
    assert by["CVE-2026-8"]["evidence_location"] == ["commit a1", "commit b2"] and [e["kernel"] for e in by["CVE-2026-7"]["evidence_basis"]] == ["5.15.136-tegra", "6.8.12-1021-tegra"]
    vx.check_annotations(doc)
    # 不合格的依據：錯誤、檔案不變
    before = (proj / vx.ANN_REL).read_bytes()
    for extra in (["--evidence", "source", "--evidence-location", "a;b"], ["--evidence", "source"], ["--evidence-location", "x"],
                  ["--evidence-basis", "not json"], ["--evidence-basis", "[]"],
                  ["--evidence", "source", "--evidence-location", "x", "--evidence-basis", '[{"type":"source","location":"y"}]']):
        assert vx.main(args[:4] + ["CVE-2026-6"] + args[5:] + extra) == 1, extra
        assert (proj / vx.ANN_REL).read_bytes() == before
    # on-device 的檔案不存在：照樣寫入（之後補檔案），但訊息警告，閘門算沒有類型
    assert vx.main(args[:4] + ["CVE-2026-5"] + args[5:] + ["--evidence", "on-device", "--evidence-location", "CRA/evidence/later.txt"]) == 0


def test_annotate_warns_about_missing_on_device_file_and_check_repeats_it(tmp_path, capsys):
    proj = tmp_path / "p"
    proj.mkdir()
    base = ["annotate", "--project", str(proj), "--cve", "CVE-2026-9", "--state", "not_affected", "--justification", "code_not_reachable",
            "--detail", "d", "--author", "Alice", "--purl", P, "--evidence", "on-device", "--evidence-location", "CRA/evidence/later.txt"]
    assert vx.main(base) == 0
    out = capsys.readouterr().out
    assert "注意" in out and "CRA/evidence/later.txt" in out and "on_device_missing" in out
    assert "補檔前這筆排除算沒有依據類型，會擋發行閘門" in out
    assert vx.main(["check", "--project", str(proj)]) == 0
    assert "WARN" in capsys.readouterr().out
    (proj / "CRA" / "evidence").mkdir(parents=True)
    (proj / "CRA" / "evidence" / "later.txt").write_text("x")
    assert vx.main(["check", "--project", str(proj)]) == 0 and "WARN" not in capsys.readouterr().out


# ---------- 閘門 ----------

def test_untyped_exclusions_count_in_untriaged_for_gate_with_reason_and_breakdown():
    rows = [row("CVE-D1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="x")), row("CVE-D2", analysis=dt("RESOLVED")),
            row("CVE-A1"), row("CVE-A2"), row("CVE-T1"), row("CVE-X1")]
    anns = [ann("CVE-A1", "not_affected", purl=P), ann("CVE-A2", "resolved", purl=P, evidence="on-device", evidence_location="missing.txt"),
            ann("CVE-T1", "not_affected", purl=P, evidence="design-doc", evidence_location="Design spec v1")]
    allr, conf, _ = vx.assess(rows, annotations=anns, project=Path("/nonexistent-project-dir"))
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    a = g["assessment"]
    # 沒有類型的排除：D1、D2（DT）、A1（沒寫依據）、A2（on-device 的檔案在不存在的專案資料夾裡）；T1（design-doc）有類型
    assert a["exclusions_without_evidence"] == 4 and a["untriaged"] == 1 and a["untriaged_for_gate"] == 5 and a["complete"] is False
    assert g["verdict"] == "ATTENTION"
    why = [r for r in g["reasons"] if r.startswith("4 exclusions without evidence type")]
    assert len(why) == 1
    assert vx.EVIDENCE_MISSING["dt"] + " 2" in why[0] and "clear it in Dependency-Track" in vx.EVIDENCE_MISSING["dt"]
    assert "annotation without evidence 1" in why[0] and "on-device file missing 1" in why[0]
    assert all(x in why[0] for x in ("CVE-D1", "CVE-D2", "CVE-A1", "CVE-A2")) and "CVE-T1" not in why[0]
    # counts 與 untriaged 不變（排除仍是排除）：沒有類型只影響 untriaged_for_gate、complete 與理由
    assert g["counts"]["total"] == {"rows": 6, "resolved": 2, "not_affected": 3, "exploitable": 0, "in_triage": 0, "untriaged": 1}
    assert g["untriaged_by_tier"] == {"p1": 0, "p2": 1, "p3": 0, "other": 0}


def test_on_device_reason_and_examples_limit():
    rows = [row(f"CVE-{i:04d}", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="x")) for i in range(12)]
    allr, conf, _ = vx.assess(rows)
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    r = next(x for x in g["reasons"] if x.startswith("12 exclusions without evidence type"))
    assert r.count(" on openssl ") == 10 and ", …" in r
    assert g["assessment"]["untriaged_for_gate"] == 12 and g["assessment"]["untriaged"] == 0 and g["assessment"]["complete"] is False
    # 有 exploitable 時不再寫 "assessment complete;"（評估不完整）
    rows = [row("CVE-1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="x")), row("CVE-2", analysis=dt("EXPLOITABLE", response="UPDATE"))]
    allr, conf, _ = vx.assess(rows)
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert not any(x.startswith("assessment complete") for x in g["reasons"]) and any(x.startswith("1 affected rows") for x in g["reasons"])
    typed(allr)
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert g["assessment"]["complete"] is True and g["reasons"][0].startswith("assessment complete; 1 affected rows")


def test_extra_cve_exclusion_without_type_counts_and_typed_one_does_not():
    allr, conf, _ = vx.assess([two_cve_row()], annotations=[ann("CVE-2026-0001", "not_affected", purl=P),
                                                            ann("CVE-2026-0002", "not_affected", purl=P, evidence="source", evidence_location="commit abc")])
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert g["assessment"]["exclusions_without_evidence"] == 1 and "CVE-2026-0001" in g["reasons"][0] and "CVE-2026-0002" not in g["reasons"][0]


def test_extra_cve_untyped_exclusion_counts_even_when_the_main_row_is_typed():
    """主列有類型、別名列（vex_extra）沒有：只有別名列算沒有類型的排除（閘門要把 vex_extra 也算進去，不能只看主列）。"""
    allr, conf, _ = vx.assess([two_cve_row()], annotations=[ann("CVE-2026-0001", "not_affected", purl=P, evidence="source", evidence_location="commit abc"),
                                                            ann("CVE-2026-0002", "not_affected", purl=P)])
    assert vx.exclusion_basis(allr[0]["vex"])[0] and vx.exclusion_basis(allr[0]["vex_extra"][0]["vex"]) == ([], "annotation_no_evidence")
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    a = g["assessment"]
    assert a["exclusions_without_evidence"] == 1 and a["untriaged_for_gate"] == 1 and a["complete"] is False and g["verdict"] == "ATTENTION"
    assert len(g["reasons"]) == 1 and "CVE-2026-0002" in g["reasons"][0] and "CVE-2026-0001" not in g["reasons"][0]


def deb_python_rows(owner_vex_kw):
    """擁有者 deb 列（brotli 的原始碼套件）加上 Ubuntu 打包的 Python 模組的列（deb_python 的 owner）。"""
    src = "pkg:deb/ubuntu/brotli@1.1.0-2?arch=source"
    owner = row("CVE-2026-0100", "brotli", "1.1.0-2", purl=src, ptype="deb", **owner_vex_kw)
    py = row("CVE-2026-0100", "brotli", "1.1.0-2", purl="pkg:pypi/brotli@1.1.0-2", ptype="pypi",
             deb_python={"owner": {"name": "brotli", "source": "brotli", "version": "1.1.0-2"}})
    return [owner, py], src


def test_inherited_deb_python_decision_carries_the_evidence_basis_of_the_owner_decision():
    """沿用（inherit_deb_python）整個陳述：擁有者的 annotation 有依據時，沿用的列也有同一筆依據（不是沒有類型的排除）；
    擁有者是 DT 的判定（沒有依據）時兩列都沒有類型。"""
    rows, src = deb_python_rows({})
    a = ann("CVE-2026-0100", "not_affected", purl=src, evidence="source", evidence_location="fix commit abc")
    allr, conf, info = vx.assess(rows, annotations=[a])
    owner, py = allr
    assert py["vex"]["inherited_from"]["component"] == "brotli" and info["deb_python_inherited"] == 1
    assert basis_of(owner) == [{"type": "source", "location": "fix commit abc"}]
    assert basis_of(py) == basis_of(owner) and vx.exclusion_basis(py["vex"])[0]
    assert info["evidence"]["exclusions"] == 2 and info["evidence"]["with_type"] == 2 and info["evidence"]["without_type"]["total"] == 0
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert g["assessment"]["exclusions_without_evidence"] == 0 and g["verdict"] == "OK"
    # 擁有者是 DT 的判定：沒有依據，兩列各算一次
    rows, _ = deb_python_rows({"analysis": dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="x")})
    allr, conf, info = vx.assess(rows)
    assert [r["vex"]["source"] for r in allr] == ["dt", "dt"] and allr[1]["vex"].get("inherited_from")
    assert info["evidence"]["without_type"]["total"] == 2
    assert vx.gate(allr, conf, grype_checked=True, not_assessed=[])["assessment"]["exclusions_without_evidence"] == 2


def test_typed_exclusions_do_not_touch_the_gate():
    rows = [row("CVE-1"), row("CVE-2", "linux", "6.8", kernel=True, tier="p3")]
    anns = [ann("CVE-1", "not_affected", purl=P, evidence="source", evidence_location="fix commit abc"),
            ann("CVE-2", "resolved", purl="pkg:deb/ubuntu/linux", evidence="vendor-statement", evidence_location="USN-1234-1")]
    allr, conf, _ = vx.assess(rows, annotations=anns)
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    assert g["verdict"] == "OK" and g["reasons"] == [] and g["assessment"]["exclusions_without_evidence"] == 0 and g["assessment"]["complete"] is True


GATE_LINE = re.compile(r"untriaged (\d+)（[^）]*）＋別名 CVE 沒有判定 (\d+)＋規則設 in_triage (\d+)（未評估）＋沒有類型的排除 (\d+)＝(\d+)；")


def test_gate_line_lists_every_term_of_untriaged_for_gate():
    """GATE 行（vex_export.gate_line）列出的各項加總＝untriaged_for_gate。四種都有：沒有判定的列、併進別列而自己沒有判定的別名 CVE、
    批次規則設的 in_triage、沒有類型的排除（DT）；每一項都不是 0，所以不是 0＝0 的巧合，少列任何一項加總就對不上。"""
    rows = [two_cve_row(), row("CVE-D1", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="x")), row("CVE-U1"), row("CVE-R1")]
    # 主列 CVE-2026-0001 有帶依據的判定；別名 CVE-2026-0002 沒有判定（extra_cves_untriaged）
    allr, conf, _ = vx.assess(rows, annotations=[ann("CVE-2026-0001", "not_affected", purl=P, evidence="source", evidence_location="commit abc")])
    r1 = next(r for r in allr if r["id"] == "CVE-R1")
    assert r1.get("vex") is None
    r1["vex"] = vx.stmt("rule", "in_triage", "x (bulk rule R1: y)", rule="R1", rule_author="Someone")     # 批次規則設的 in_triage
    g = vx.gate(allr, conf, grype_checked=True, not_assessed=[])
    a = g["assessment"]
    assert (a["untriaged"], a["extra_cves_untriaged"], a["in_triage_by_rule"], a["exclusions_without_evidence"]) == (1, 1, 1, 1), a
    m = GATE_LINE.search(vx.gate_line(g))
    assert m, vx.gate_line(g)
    n_un, n_alias, n_rule, n_exc, total = map(int, m.groups())
    assert (n_un, n_alias, n_rule, n_exc) == (1, 1, 1, 1) and total == a["untriaged_for_gate"] == 4


def test_rules_check_gate_line_adds_up_to_untriaged_for_gate(tmp_path):
    """rules check --scan 的 GATE 行：untriaged ＋ 別名 CVE 沒有判定 ＋ 規則設 in_triage ＋ 沒有類型的排除 ＝ untriaged_for_gate（加起來要對得上）。"""
    from test_vex_rules import EXAMPLE_RULES, RULE_FINDINGS, RULE_GRYPE, cli
    proj = make_project(tmp_path / "proj")
    scan = make_scan(tmp_path / "scan", findings=RULE_FINDINGS, grype=RULE_GRYPE)
    write_json(proj / vx.RULES_REL, EXAMPLE_RULES)
    r = cli("rules", "check", "--project", str(proj), "--scan", str(scan))
    assert r.returncode == 0, r.stdout + r.stderr
    gl = next(x for x in r.stdout.splitlines() if x.startswith("GATE"))
    m = GATE_LINE.search(gl)
    assert m, gl
    n_un, n_alias, n_rule, n_exc, total = map(int, m.groups())
    assert n_un + n_alias + n_rule + n_exc == total
    assert n_exc >= 1, gl                       # 這份輸入有 DT 的排除（沒有依據類型），不是只有 0＝0 的巧合


# ---------- 閘門基準：改動前 vs 改動後 ----------

def test_gate_baseline_before_d035_unit():
    """data/vex_gate_before_d035.json 是在改動前的程式碼（main bf92964）上、用 vex_gate_scenarios.py 的輸入產生的。
    沒有排除的輸入：閘門全等（只多了新欄位 exclusions_without_evidence＝0）；有排除的輸入：每一個變動的數字都能用「沒有類型的排除算進
    untriaged_for_gate」解釋（d035_unexplained 回報解釋不了的差異）。補上依據類型的輸入：全等。"""
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert golden["_source_commit"].startswith("bf92964") and set(golden["unit"]) == set(sc.scenarios())
    for name, spec in sc.scenarios().items():
        allr, conf, g = sc.run_unit(name, spec)
        new, old = sc.gate_json(g), golden["unit"][name]
        n = new["assessment"]["exclusions_without_evidence"]
        want = sum(1 for r in allr for x in [r] + (r.get("vex_extra") or []) if vx.is_exclusion(x.get("vex")) and x["vex"]["source"] in ("dt", "annotation"))
        assert n == want, (name, n, want)                                                    # 沒有類型的排除正好是人的來源（這些輸入沒給依據）
        assert sc.d035_unexplained(old, new) == [], name
        if name == "no_exclusions":
            assert n == 0 and new["assessment"].pop("exclusions_without_evidence") == 0 and new == old       # 沒有排除：閘門全等
        else:
            assert n > 0 or name in ("automatic_sources", "evidence_rules"), name
        # 補上依據類型之後：全等（證明差異只有沒有類型的排除造成的）
        typed(allr)
        again = sc.gate_json(vx.gate(allr, conf, grype_checked=True, not_assessed=[]))
        assert again["assessment"].pop("exclusions_without_evidence") == 0 and again == old, name


def test_gate_baseline_before_d035_end_to_end(tmp_path):
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    for name, case in sc.e2e_cases().items():
        new, old = sc.run_e2e(name, case, tmp_path), golden["e2e"][name]
        assert sc.d035_unexplained(old, new) == [], name
        if name == "e2e_no_exclusions":                           # 沒有排除：全等（只多了新欄位 exclusions_without_evidence＝0）
            assert new["assessment"].pop("exclusions_without_evidence") == 0 and new == old, name
        else:                                                     # 其他各有一筆沒有類型的排除（DT 或 annotation；e2e_distro 的 distro 排除有類型）
            assert new["assessment"]["exclusions_without_evidence"] == 1, name


def test_d035_unexplained_catches_a_change_that_is_not_the_exclusion_effect():
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    old = golden["unit"]["dt_and_annotation"]
    allr, conf, g = sc.run_unit("dt_and_annotation", sc.scenarios()["dt_and_annotation"])
    new = sc.gate_json(g)
    assert sc.d035_unexplained(old, new) == []
    for mutate in (lambda d: d["counts"]["total"].update(untriaged=d["counts"]["total"]["untriaged"] + 1),
                   lambda d: d["assessment"].update(untriaged=d["assessment"]["untriaged"] + 1),
                   lambda d: d["assessment"].update(untriaged_for_gate=d["assessment"]["untriaged_for_gate"] + 1),
                   lambda d: d.update(verdict="OK"), lambda d: d["untriaged_by_tier"].update(p1=5),
                   lambda d: d["reasons"].append("something else"), lambda d: d["assessment"].update(complete=True)):
        bad = copy.deepcopy(new)
        mutate(bad)
        assert sc.d035_unexplained(old, bad), "an unexplained change was not reported"


# ---------- 內部 CycloneDX ----------

def evidence_rows():
    """每種類型各一條排除（annotation 的 on-device 檔案在 tmp_path）；DT 的排除沒有類型；一條有兩顆核心；一條 NOT_ASSESSED。"""
    return [row("CVE-B", analysis=dt("IN_TRIAGE")),
            row("CVE-1"), row("CVE-2"), row("CVE-3"), row("CVE-4"), row("CVE-5"), row("CVE-6"),
            row("CVE-D", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="human")), row("CVE-NA")]


def evidence_anns():
    return [ann("CVE-1", "not_affected", purl=P, evidence="build-record", evidence_location="scan/kernel-config.json (kernel 6.8.12-1021-tegra)"),
            ann("CVE-2", "not_affected", purl=P, evidence="source", evidence_location=["fix commit a1b2c3", "fix commit d4e5f6"]),
            ann("CVE-3", "resolved", purl=P, evidence="on-device", evidence_location="CRA/evidence/dev-check.txt"),
            ann("CVE-4", "false_positive", purl=P, justification="code_not_present", evidence="design-doc", evidence_location="Design spec v3 §4.2"),
            ann("CVE-5", "not_affected", purl=P, evidence="vendor-statement", evidence_location="USN-9999-1"),
            ann("CVE-6", "not_affected", purl=P, evidence_basis=[{"type": "build-record", "location": "k1 config", "kernel": "5.15.136-tegra"},
                                                                 {"type": "build-record", "location": "k2 config", "kernel": "6.8.12-1021-tegra"}])]


def test_cdx_properties_per_exclusion(tmp_path):
    proj = project_with(tmp_path, ["CRA/evidence/dev-check.txt"])
    allr, _, info, cdx, ov = build(evidence_rows(), annotations=evidence_anns(), project=proj)
    assert evidence_of(cdx, "CVE-1") == [("build-record", "scan/kernel-config.json (kernel 6.8.12-1021-tegra)", None)]
    assert evidence_of(cdx, "CVE-2") == [("source", "fix commit a1b2c3", None), ("source", "fix commit d4e5f6", None)]       # 多筆依據：依序一組一組
    assert evidence_of(cdx, "CVE-3") == [("on-device", "CRA/evidence/dev-check.txt", None)]
    assert evidence_of(cdx, "CVE-4") == [("design-doc", "Design spec v3 §4.2", None)]
    assert evidence_of(cdx, "CVE-5") == [("vendor-statement", "USN-9999-1", None)]
    assert evidence_of(cdx, "CVE-6") == [("build-record", "k1 config", "5.15.136-tegra"), ("build-record", "k2 config", "6.8.12-1021-tegra")]
    # 沒有類型的排除：只有 dumpling:evidence＝none，沒有位置；沒有判定與非排除的陳述沒有這個屬性
    assert evidence_of(cdx, "CVE-D") == [("none", None, None)]
    for vid in ("CVE-B", "CVE-NA"):
        assert not [p for p in next(x for x in cdx["vulnerabilities"] if x["id"] == vid)["properties"] if p["name"].startswith("dumpling:evidence")]
    # 屬性名稱與值的型別（CycloneDX 的 property 是 name／value 兩個字串）
    assert all(isinstance(p["name"], str) and isinstance(p["value"], str) for v in cdx["vulnerabilities"] for p in v["properties"])
    assert info["evidence"]["by_type"] == {"build-record": 2, "source": 1, "on-device": 1, "design-doc": 1, "vendor-statement": 1}
    assert info["evidence"]["without_type"]["total"] == 1 and info["evidence"]["exclusions"] == 7


def test_official_schemas_with_evidence_statements(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    from cdx_schema import cdx_validator
    proj = project_with(tmp_path, ["CRA/evidence/dev-check.txt"])
    _, _, _, cdx, ov = build(evidence_rows(), annotations=evidence_anns(), project=proj)
    errs_ = list(cdx_validator().iter_errors(cdx))
    assert not errs_, [e.message for e in errs_[:3]]
    errs_ = list(jsonschema.Draft202012Validator(json.load(open(OV_SCHEMA)), format_checker=jsonschema.FormatChecker()).iter_errors(ov))
    assert not errs_, [e.message for e in errs_[:3]]
    # 客戶版也要過
    for obj, name in ((sp.customer_cdx(cdx), "cdx"), (sp.customer_openvex(ov), "ov")):
        v = list(cdx_validator().iter_errors(obj)) if name == "cdx" else list(
            jsonschema.Draft202012Validator(json.load(open(OV_SCHEMA)), format_checker=jsonschema.FormatChecker()).iter_errors(obj))
        assert not v, [e.message for e in v[:3]]


# ---------- 內部 OpenVEX ----------

def test_openvex_status_notes_lines_and_coexistence(tmp_path):
    proj = project_with(tmp_path, ["CRA/evidence/dev-check.txt"])
    _, _, _, cdx, ov = build(evidence_rows(), annotations=evidence_anns(), project=proj)
    by = {s["vulnerability"]["name"]: s for s in ov["statements"]}
    assert by["CVE-1"]["status"] == "not_affected"
    assert by["CVE-1"]["status_notes"] == "dumpling: evidence=build-record; location=scan/kernel-config.json (kernel 6.8.12-1021-tegra)"
    assert by["CVE-2"]["status_notes"].split("\n") == ["dumpling: evidence=source; location=fix commit a1b2c3", "dumpling: evidence=source; location=fix commit d4e5f6"]
    # fixed：status_notes 本來就是 detail，依據行接在後面
    n3 = by["CVE-3"]["status_notes"].split("\n")
    assert by["CVE-3"]["status"] == "fixed" and n3[0] == "checked by hand" and n3[1] == "dumpling: evidence=on-device; location=CRA/evidence/dev-check.txt"
    assert by["CVE-6"]["status_notes"].split("\n") == ["dumpling: evidence=build-record; kernel=5.15.136-tegra; location=k1 config",
                                                       "dumpling: evidence=build-record; kernel=6.8.12-1021-tegra; location=k2 config"]
    assert by["CVE-D"]["status_notes"] == "dumpling: evidence=none"
    # 沒有評估：照 M7c-1 只有固定的 notes，不帶依據；人設的 in_triage 沒有 notes
    assert by["CVE-NA"]["status_notes"] == "dumpling: not assessed" and "dumpling:" not in by["CVE-B"]["status_notes"]
    # 每一條依據行都符合固定格式（fullmatch），類型是五種之一或 none
    lines = [l for s in ov["statements"] for l in (s.get("status_notes") or "").split("\n") if l.startswith("dumpling: evidence=")]
    assert len(lines) == 9 and all(re.fullmatch(r"dumpling: evidence=(?:(?:build-record|source|on-device|design-doc|vendor-statement)"
                                                 r"(?:; kernel=[A-Za-z0-9][A-Za-z0-9._+~:-]*)?; location=[^;\n]+|none)", l) for l in lines)
    # 其他的 notes 與依據共存：not_affected 有 impact_statement（detail）也有 status_notes（依據）
    assert by["CVE-1"]["impact_statement"] == "checked by hand"


def test_not_assessed_count_is_unaffected_by_evidence_lines():
    _, _, _, cdx, ov = build([row("CVE-NA"), row("CVE-X", analysis=dt("NOT_AFFECTED", "CODE_NOT_PRESENT", details="x"))])
    assert vx.not_assessed_count(cdx, "vex.cdx.json") == vx.not_assessed_count(ov, "vex.openvex.json") == 1


# ---------- vexconv 往返 ----------

def test_roundtrip_through_vexconv_keeps_evidence_both_ways(tmp_path):
    proj = project_with(tmp_path, ["CRA/evidence/dev-check.txt"])
    _, _, _, cdx, ov = build(evidence_rows(), annotations=evidence_anns(), project=proj)

    def evid(c):
        return {v["id"]: evidence_of({"vulnerabilities": [v]}, v["id"]) for v in c["vulnerabilities"] if evidence_of({"vulnerabilities": [v]}, v["id"])}
    want = evid(cdx)
    # cdx → openvex → cdx
    assert evid(VC.to_cdx(VC.to_openvex(cdx, lenient=True))) == want
    assert evid(VC.to_cdx(ov)) == want
    # openvex → cdx → openvex（每條的 status_notes 一字不差）
    again = VC.to_openvex(VC.to_cdx(ov), lenient=True)
    assert [(s["vulnerability"]["name"], s["status"], s.get("status_notes")) for s in again["statements"]] == \
           [(s["vulnerability"]["name"], s["status"], s.get("status_notes")) for s in ov["statements"]]
    # 依據行不會留在轉回去的 detail／notes 屬性裡（不重複）
    back = VC.to_cdx(ov)
    assert not any("dumpling: evidence=" in (p.get("value") or "") for v in back["vulnerabilities"] for p in v["properties"])
    assert not any("dumpling: evidence=" in (v["analysis"].get("detail") or "") for v in back["vulnerabilities"])


# ---------- 客戶版 ----------

def test_customer_files_carry_only_types_and_fixed_sentences(tmp_path):
    proj = project_with(tmp_path, ["CRA/evidence/dev-check.txt"])
    _, _, _, cdx, ov = build(evidence_rows(), annotations=evidence_anns(), project=proj)
    ccdx, cov = sp.customer_cdx(cdx), sp.customer_openvex(ov)
    d = {v["id"]: v["analysis"]["detail"] for v in ccdx["vulnerabilities"]}
    n = {s["vulnerability"]["name"]: s for s in cov["statements"]}
    expect = {"CVE-1": "Evidence: build artifacts.", "CVE-2": "Evidence: source code.", "CVE-3": "Evidence: on-device check.",
              "CVE-4": "Evidence: design documentation.", "CVE-5": "Evidence: vendor statement.", "CVE-6": "Evidence: build artifacts.",
              "CVE-D": "Evidence: not recorded."}
    for vid, sentence in expect.items():
        assert d[vid].endswith(" " + sentence) or d[vid] == sentence, (vid, d[vid])
        assert n[vid]["status_notes"].endswith(sentence), (vid, n[vid].get("status_notes"))
        assert d[vid].count("Evidence:") == 1 and n[vid]["status_notes"].count("Evidence:") == 1
    # 位置、核心、內部名稱都不在客戶版；check_customer_text 照常通過；沒有評估與非排除的陳述不加這句
    for obj, name in ((ccdx, "vex.cdx.json"), (cov, "vex.openvex.json")):
        text = json.dumps(obj, ensure_ascii=False)
        for secret in ("dev-check.txt", "kernel-config.json", "USN-9999-1", "fix commit", "Design spec", "5.15.136", "k1 config", "dumpling", "location="):
            assert secret not in text, (name, secret)
        assert sp.check_customer_text(name, text) == []
    assert "Evidence" not in d["CVE-NA"] and d["CVE-NA"] == sp.CUSTOMER_NOT_ASSESSED and "Evidence" not in n["CVE-NA"]["status_notes"]
    assert "Evidence" not in d["CVE-B"] and "Evidence" not in n["CVE-B"]["status_notes"]
    # 兩種類型同時有：每種一句、順序固定
    assert sp.with_evidence("Done.", ["vendor-statement", "on-device", "none", "bogus"]) == "Done. Evidence: on-device check. Evidence: vendor statement."
    assert sp.with_evidence("", []) == "Evidence: not recorded." and sp.with_evidence("no period", ["source"]) == "no period. Evidence: source code."
    # 沒有依據屬性的內部檔（舊版）：排除也寫 not recorded，不省略（D-043）
    old = copy.deepcopy(cdx)
    for v in old["vulnerabilities"]:
        v["properties"] = [p for p in v["properties"] if not p["name"].startswith("dumpling:evidence")]
    assert all(v["analysis"]["detail"].endswith("Evidence: not recorded.") for v in sp.customer_cdx(old)["vulnerabilities"]
               if v["analysis"]["state"] in ("resolved", "not_affected", "false_positive"))


def test_customer_openvex_never_leaks_locations_even_with_odd_notes():
    ov = {"statements": [
        {"vulnerability": {"name": "CVE-1"}, "products": [], "status": "not_affected", "justification": "component_not_present",
         "status_notes": "dumpling: evidence=source; location=/mnt/dev/secret/path.c\ndumpling: evidence=bogus; location=/mnt/x\nplain note"},
        {"vulnerability": {"name": "CVE-2"}, "products": [], "status": "fixed",
         "status_notes": "\\dumpling: evidence=source; location=/mnt/dev/x"}]}
    out = sp.customer_openvex(ov)
    text = json.dumps(out)
    assert "/mnt/dev" not in text and "/mnt/x" not in text and "secret" not in text and "dumpling" not in text.lower() and sp.check_customer_text("vex.openvex.json", text) == []
    assert out["statements"][0]["status_notes"].endswith("Evidence: source code.") and out["statements"][1]["status_notes"].endswith("Evidence: not recorded.")


# ---------- dt_writeback ----------

def test_dt_writeback_ignores_evidence_properties(tmp_path):
    import test_dt_writeback as tw
    base = tw.good_stmts()
    with_ev = copy.deepcopy(base)
    for s_ in with_ev:
        s_["properties"] += [{"name": VC.PROP_EVIDENCE, "value": "source"}, {"name": VC.PROP_EVIDENCE_LOCATION, "value": "fix commit abc123"},
                             {"name": VC.PROP_EVIDENCE_KERNEL, "value": "6.8.12"}]
    a = tw.go(tmp_path / "a", base)
    b = tw.go(tmp_path / "b", with_ev)
    assert a[0] == b[0] == 0 and a[1] == b[1]
    sent_a = json.loads((a[3] / "dt-vex.cdx.json").read_text())
    sent_b = json.loads((b[3] / "dt-vex.cdx.json").read_text())
    assert sent_a == sent_b and "evidence" not in json.dumps(sent_b) and "abc123" not in json.dumps(sent_b)
    assert json.loads((a[3] / "dt-writeback.json").read_text()) == json.loads((b[3] / "dt-writeback.json").read_text())


# ---------- 報告（cra_report 端對端） ----------

def report_project(tmp_path, anns, files=()):
    proj = make_project(tmp_path / "p")
    project_with(proj, files)
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": anns})
    no_analysis = [dict(f, analysis={"isSuppressed": False}) if (f["analysis"] or {}).get("state") in ("NOT_AFFECTED", "FALSE_POSITIVE") else f
                   for f in FINDINGS]
    scan = make_scan(tmp_path / "s", findings=no_analysis)
    return run(proj, scan)


def test_report_lists_types_and_single_out_on_device_and_design_doc_with_escaped_locations(tmp_path):
    evil = "CRA/evidence/dev `x` | <b>[l](http://x)</b>.txt"
    anns = [ann("CVE-2025-0003", "not_affected", purl=P, version="3.0.13-0ubuntu3.11", evidence="on-device", evidence_location=evil),
            ann("CVE-2026-61897", "not_affected", purl="pkg:deb/ubuntu/accountsservice", evidence="design-doc",
                evidence_location="Design | spec `v3` <i>§4</i>")]
    r, s, rep = report_project(tmp_path, anns, files=[evil])
    assert s["status"] != "FAIL", r.stdout + r.stderr
    ev = s["vex"]["evidence"]
    assert ev["exclusions"] == 2 and ev["by_type"] == {"build-record": 0, "source": 0, "on-device": 1, "design-doc": 1, "vendor-statement": 0}
    assert ev["without_type"]["total"] == 0 and ev["with_type"] == 2
    assert [(x["id"], x["location"]) for x in ev["on_device"]] == [("CVE-2025-0003", evil)]
    assert ev["on_device"][0]["component"] == "openssl" and ev["on_device"][0]["version"] == "3.0.13-0ubuntu3.11"
    assert [x["location"] for x in ev["design_doc"]] == ["Design | spec `v3` <i>§4</i>"]
    t = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "Exclusions based on an on-device check (1)" in t and "Exclusions based on a design document (1)" in t
    assert "only checks that the file exists; it does not verify the file's content" in t
    assert "build-record 0, source 0, on-device 1, design-doc 1, vendor-statement 0" in t
    # 位置放進行內程式碼（code span，反引號框比文字裡最長的反引號多一個），表格的「|」跳脫：連結、HTML、強調都不會被當成 Markdown 解讀
    assert "``CRA/evidence/dev `x` \\| <b>[l](http://x)</b>.txt``" in t
    assert "``Design \\| spec `v3` <i>§4</i>``" in t
    row_on_device = next(l for l in t.splitlines() if "CVE-2025-0003" in l and "dev-check" not in l and "dev `x`" in l)
    assert row_on_device.count("\\|") == 1 and "[l](http://x)" in row_on_device and row_on_device.index("``") < row_on_device.index("[l]")
    # 沒有類型的排除是 0：閘門的理由沒有這一條，文件狀態沒有因此加 ATTENTION
    assert s["vex"]["gate"]["assessment"]["exclusions_without_evidence"] == 0
    assert not any("without an evidence type" in x for x in s["documents"]["risk-assessment"]["detail"])


def test_report_untyped_exclusions_make_the_document_attention_and_block_the_gate(tmp_path):
    anns = [ann("CVE-2025-0003", "not_affected", purl=P, version="3.0.13-0ubuntu3.11"),                       # 沒有依據
            ann("CVE-2026-61897", "not_affected", purl="pkg:deb/ubuntu/accountsservice", evidence="on-device",
                evidence_location="CRA/evidence/not-there.txt")]                                            # 檔案不存在
    r, s, rep = report_project(tmp_path, anns)
    ev, g = s["vex"]["evidence"], s["vex"]["gate"]
    assert ev["without_type"]["total"] == 2 and ev["without_type"]["by_reason"] == {"annotation_no_evidence": 1, "on_device_missing": 1}
    assert g["assessment"]["exclusions_without_evidence"] == 2 and g["assessment"]["complete"] is False
    assert any(x.startswith("2 exclusions without evidence type") for x in g["reasons"])
    ra = s["documents"]["risk-assessment"]
    assert ra["status"] in ("ATTENTION", "GAP", "NOT_ASSESSED", "FAIL") and any("2 exclusions" in x and "evidence type" in x for x in ra["detail"])
    assert s["status"] != "OK"
    t = (rep / "risk-assessment.md").read_text(encoding="utf-8")
    assert "2 exclusions have no evidence type" in t and "they count in the release gate" in t
    # 同一份資料沒有這兩筆排除時，文件狀態不因 D-035 變：理由不在
    r2, s2, _ = report_project(tmp_path / "again", [])
    assert not any("without an evidence type" in x for x in s2["documents"]["risk-assessment"]["detail"])
    # 進內部 VEX 檔：沒有類型的是 none，客戶版是 not recorded
    cdx = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    assert evidence_of(cdx, "CVE-2025-0003") == [("none", None, None)] and evidence_of(cdx, "CVE-2026-61897") == [("none", None, None)]


def test_report_status_follows_untyped_exclusions_only_through_the_evidence_reason(tmp_path):
    """文件狀態的差別只有 D-035 的理由：同一份輸入，有沒有類型的排除，risk-assessment 的狀態與理由清單只差那一條。"""
    typed_anns = [ann("CVE-2025-0003", "not_affected", purl=P, version="3.0.13-0ubuntu3.11", evidence="source", evidence_location="fix commit abc")]
    untyped_anns = [ann("CVE-2025-0003", "not_affected", purl=P, version="3.0.13-0ubuntu3.11")]
    _, s_t, _ = report_project(tmp_path / "t", typed_anns)
    _, s_u, _ = report_project(tmp_path / "u", untyped_anns)
    d_t, d_u = s_t["documents"]["risk-assessment"], s_u["documents"]["risk-assessment"]
    assert [x for x in d_u["detail"] if x not in d_t["detail"]] and not [x for x in d_t["detail"] if x not in d_u["detail"]]
    extra = [x for x in d_u["detail"] if x not in d_t["detail"]]
    assert len(extra) == 1 and "1 exclusions" in extra[0]
    worst = {"OK": 0, "ATTENTION": 1, "GAP": 2, "NOT_ASSESSED": 3, "FAIL": 4}
    assert worst[d_u["status"]] >= max(worst[d_t["status"]], 1)


def clean_report(tmp_path, name, anns):
    """沒有其他 ATTENTION 的夾具（test_layers_report 的分層情境：OS 層的列、Grype 全對上、安全測試都有結果）加上 annotation。"""
    import test_layers_report as tl
    from test_cra_report import EXAMPLE, clean_security
    clean_security(tmp_path / name)
    proj = make_project(tmp_path / f"proj-{name}", EXAMPLE)
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": anns})
    fs = [tl.fnd(tl.OSP, "CVE-2026-0003", "LOW")]
    scan = make_scan(tmp_path / name / "scan", findings=fs, grype=tl.grype_for(fs), sbom=tl.bom("customer", *tl.TAGGED))
    return run(proj, scan)


def test_risk_assessment_status_becomes_attention_only_because_of_untyped_exclusions(tmp_path):
    """文件狀態含 D-035 的 ev_st：其餘都 OK 時，有沒有類型的排除就是 OK 與 ATTENTION 的差別（理由是唯一的那一條）；
    漏洞資料狀態（risk_st，8.1 的資料狀態）不因此改變。"""
    a_typed = ann("CVE-2026-0003", "not_affected", purl=P, evidence="source", evidence_location="fix commit abc")
    a_untyped = ann("CVE-2026-0003", "not_affected", purl=P)
    r1, s1, _ = clean_report(tmp_path, "typed", [a_typed])
    r2, s2, rep2 = clean_report(tmp_path, "untyped", [a_untyped])
    d1, d2 = s1["documents"]["risk-assessment"], s2["documents"]["risk-assessment"]
    assert d1["status"] == "OK" and s1["status"] == "OK", (d1, r1.stdout)
    assert s1["vex"]["gate"]["assessment"]["exclusions_without_evidence"] == 0
    assert s2["vex"]["gate"]["assessment"]["exclusions_without_evidence"] == 1
    assert d2["status"] == "ATTENTION" and s2["status"] == "ATTENTION", (d2, r2.stdout)
    assert [x for x in d2["detail"] if x not in d1["detail"]] == [x for x in d2["detail"] if "1 exclusions" in x and "evidence type" in x]
    assert len([x for x in d2["detail"] if x not in d1["detail"]]) == 1
    # 漏洞資料狀態沒有因為這一條降級（和 D-054 的 fw_st 一樣只進文件狀態）
    assert "Note (counted in this document's status, not in the vulnerability data status above)" in (rep2 / "risk-assessment.md").read_text(encoding="utf-8")


def test_supplier_package_end_to_end_distro_and_annotation_evidence(tmp_path):
    """端對端：發行版修補紀錄（vendor-statement）與 annotation（on-device、沒有依據）的排除，內部版有位置，客戶版只有類型的固定句子，
    語言檢查通過；客戶版沒有位置與內部名稱。"""
    from test_cra_distro import EXTRA
    from test_cra_report import MIN_CFG
    from test_customer_package_wording import pkg
    proj = make_project(tmp_path / "p", dict(MIN_CFG, role="supplier"))
    project_with(proj, ["CRA/evidence/dev-check.txt"])
    write_json(proj / vx.ANN_REL, {"schema": vx.ANN_SCHEMA, "annotations": [
        ann("CVE-2025-0003", "not_affected", purl=P, version="3.0.13-0ubuntu3.11", evidence="on-device", evidence_location="CRA/evidence/dev-check.txt"),
        ann("CVE-2026-61897", "not_affected", purl="pkg:deb/ubuntu/accountsservice")]})
    scan = make_scan(tmp_path / "s", findings=FINDINGS + EXTRA)
    write_json(scan / "scan" / "distro-recheck.json", recheck_doc())
    r, s, rep = run(proj, scan)
    assert s["status"] != "FAIL", r.stdout + r.stderr
    internal = json.loads((rep / "vex.cdx.json").read_text(encoding="utf-8"))
    assert evidence_of(internal, "CVE-2024-6119") == [("vendor-statement", "UBUNTU-CVE-2024-6119", None)]
    assert evidence_of(internal, "CVE-2025-0003") == [("on-device", "CRA/evidence/dev-check.txt", None)]
    assert evidence_of(internal, "CVE-2026-61897") == [("none", None, None)]
    customer = json.loads((pkg(rep) / "vex.cdx.json").read_text(encoding="utf-8"))
    d = {v["id"]: v["analysis"]["detail"] for v in customer["vulnerabilities"] if v["analysis"]["state"] != "in_triage"}     # 同一個編號有別的版本沒評估
    assert d["CVE-2024-6119"].endswith("Evidence: vendor statement.") and d["CVE-2025-0003"].endswith("Evidence: on-device check.")
    assert d["CVE-2026-61897"].endswith("Evidence: not recorded.")
    cov = json.loads((pkg(rep) / "vex.openvex.json").read_text(encoding="utf-8"))
    n = {x["vulnerability"]["name"]: x.get("status_notes") for x in cov["statements"] if x["status"] != "under_investigation"}
    assert n["CVE-2024-6119"].endswith("Evidence: vendor statement.") and n["CVE-2025-0003"].endswith("Evidence: on-device check.")
    for name in ("vex.cdx.json", "vex.openvex.json"):
        t = (pkg(rep) / name).read_text(encoding="utf-8")
        assert "dumpling" not in t.lower() and "dev-check" not in t and "UBUNTU-CVE" not in t and sp.check_customer_text(name, t) == [], name
    summ = json.loads((pkg(rep) / "summary.json").read_text(encoding="utf-8"))
    assert summ["language_check"]["status"] == "OK"
    # 客戶版的「評估完整」說明提到沒有類型的排除（評估不完整，但不是還在評估的列）
    status_md = (pkg(rep) / "vulnerability-status.md").read_text(encoding="utf-8")
    assert "Assessment complete: **no**" in status_md and "2 fixed or not affected rows without a recorded type of evidence" in status_md


def test_report_without_vex_exclusions_says_so(tmp_path):
    r, s, rep = report_project(tmp_path, [])
    assert s["vex"]["evidence"]["exclusions"] == 0 and s["vex"]["evidence"]["without_type"]["total"] == 0
    assert "there is no `resolved` or `not_affected` statement" in (rep / "risk-assessment.md").read_text(encoding="utf-8")


def test_md_code_escaping():
    assert vx.md_code("a|b") == "`a|b`" and vx.md_code("a`b") == "``a`b``" and vx.md_code("`a`") == "`` `a` ``"
    assert vx.md_code("x``y`z") == "```x``y`z```"
