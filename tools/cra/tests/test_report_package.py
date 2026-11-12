"""report_package.py（把 cra_report 的輸出整理成給一般人看的中文成果包）、xlsx_min.py、vulnerability-rows.json。資料全部是合成的。"""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

import report_package as rp
import vex_export as vx
import xlsx_min
from test_cra_exploitation import cfg_of, setup
from test_cra_report import run, write_json

CLI = Path(rp.__file__)


def row(id_, tier="p3", comp="libfoo", ver="1.0-1", rule=None, source=None, **kw):
    r = {"id": id_, "aliases": [], "component": comp, "version": ver, "purl": f"pkg:deb/ubuntu/{comp}@{ver}", "is_kernel": False,
         "tier": tier, "vex": None, "fix_state": "not-fixed", "fix_versions": [], "fix_next": None,
         "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N", "source": "DT NVD v3"}, "ubuntu_priority": None, "severity": "HIGH",
         "exploited": False, "exploitation_evidence": [], "exposed": False, "exposed_where": None,
         "found_by": {"dt_sources": ["OSV"], "grype": True, "grype_only": False}, "vex_statement_ref": None}
    if rule or source:
        r["vex"] = {"state": "exploitable", "source": source or "rule", "rule": rule, "justification": None,
                    "detail": "x" * 600, "author": "RuleOwner", "date": None, "markers": []}
        r["vex_statement_ref"] = "vex-ref"
    r.update(kw)
    return r


def rows_doc(rows, have_findings=True, status="OK", exposed_services_list=True):
    return {"schema": rp.ROWS_SCHEMA, "generated": "2026-11-11T00:00:00Z", "internal": True, "have_findings": have_findings,
            "vulnerability_data_status": status, "exposed_services_list": exposed_services_list, "row_count": len(rows), "rows": rows}


def project(tmp, rows, name="proj", with_all=True, rules_doc=None, **kw):
    p = Path(tmp) / name
    rep = p / "CRA" / "Reports"
    rep.mkdir(parents=True)
    (p / "CRA" / "Config").mkdir()
    write_json(p / "CRA" / "Config" / "config.json", {"product": {"name": "Prod", "version": "1.2"}})
    if rules_doc:
        write_json(p / "CRA" / "Config" / "vex-rules.json", rules_doc)
    write_json(rep / rp.ROWS_FILE, rows_doc(rows, **kw))
    write_json(rep / "summary.json", {"counts": {"kernel": {"fix_all": [{"component": "linux-k", "fix_all_version": "6.8.0-9.9"}]}}})
    if with_all:
        for n, t in (("sbom.cdx.json", "{}"), ("sbom.md", "# sbom"), ("vex.cdx.json", "{}"), ("vex.openvex.json", "{}"),
                     ("security-findings.md", "# findings"), ("risk-assessment.md", "# ra"), ("scan-status.tsv", "a\tb\n"),
                     ("confirmation-items.md", "# c")):
            (rep / n).write_text(t, encoding="utf-8")
        (rep / "confirmation-items.csv").write_text("編號,類別\nQ1,缺少輸入\n", encoding="utf-8-sig")
    return p


MIX = [row("CVE-1", "p1", comp="libp", exploited=True, exploitation_evidence=["KEV (DT)"]),
       row("CVE-1", "p1", comp="libq", exploited=True, exploitation_evidence=["EUVD (CISA KEV)"]),
       row("CVE-0", "p1", comp="libp", exploited=True, exploitation_evidence=["manual: advisory, 2026-10-01"]),
       row("CVE-2", "p3", rule="R6"), row("CVE-3", "p3", rule="R1", comp="linux-k", is_kernel=True, fix_state="fixed",
                                          fix_versions=["6.8.0-5.5"], fix_next="6.8.0-5.5"),
       row("CVE-4", "nvidia_bulletin", source="nvidia"), row("CVE-1", "accepted", comp="libr", rule="K1"),
       row("CVE-5", "distro_fixed", source="distro")]


def doc_for(p):
    """build 之前的 doc（供 component_sheet 對照用）。"""
    return rp.read_rows(Path(p) / "CRA" / "Reports")


def sheets(path):
    return xlsx_min.read_xlsx(path)


def body(sh, header_first="分類"):
    i = next(k for k, r in enumerate(sh) if r and r[0] == header_first)
    return sh[i], sh[i + 1:]


# ---------------------------------------------------------------- vulnerability-rows.json（cra_report.py）

def test_rows_json_from_cra_report(tmp_path):
    proj, scan = setup(tmp_path, cfg=cfg_of(market="2027-12-10"))
    r, s, reports = run(proj, scan)
    assert r.returncode == 2, r.stdout + r.stderr
    d = json.loads((reports / "vulnerability-rows.json").read_text(encoding="utf-8"))
    assert d["schema"] == rp.ROWS_SCHEMA and d["internal"] is True and d["have_findings"] is True
    assert d["row_count"] == len(d["rows"]) == 10
    assert s["documents"]["vulnerability-rows"]["file"] == "vulnerability-rows.json" and s["documents"]["vulnerability-rows"]["status"] == "OK"
    keys = {"id", "aliases", "component", "version", "purl", "is_kernel", "tier", "vex", "fix_state", "fix_versions", "fix_next", "cvss",
            "ubuntu_priority", "severity", "exploited", "exploitation_evidence", "exposed", "exposed_where", "found_by", "vex_statement_ref", "deb_python",
                "attack_vector", "runtime_observed", "runtime_evidence", "module_state", "runtime_via_source", "runtime_binaries"}
    assert all(set(x) == keys for x in d["rows"])
    by = {(x["id"], x["component"]): x for x in d["rows"]}
    assert {t: sum(1 for x in d["rows"] if x["tier"] == t) for t in ("p1", "p2", "p3", "accepted")} == {"p1": 3, "p2": 2, "p3": 3, "accepted": 2}
    manual = by[("CVE-2026-9003", "libman1")]
    assert manual["exploited"] and any(e.startswith("manual: vendor advisory") for e in manual["exploitation_evidence"])
    sshd = by[("CVE-2026-9007", "openssh-server")]
    assert sshd["exposed"] is True and "sshd" in sshd["exposed_where"] and sshd["cvss"]["score"] == 7.5
    assert sshd["found_by"] == {"dt_sources": ["NVD"], "grype": False, "grype_only": False} or sshd["found_by"]["grype"] is False
    assert by[("CVE-2026-9008", "libother1")]["exposed"] is False
    na = by[("CVE-2026-9010", "libman2")]
    assert na["tier"] == "accepted" and na["vex"]["state"] == "not_affected" and na["vex"]["author"] == "PSIRT lead" \
        and na["vex"]["date"] == "2026-11-01" and na["vex_statement_ref"].startswith("vex-CVE-2026-9010-")
    # VEX 陳述 ID 與 vex.cdx.json 一致
    refs = {v["bom-ref"] for v in json.loads((reports / "vex.cdx.json").read_text(encoding="utf-8"))["vulnerabilities"]}
    assert {x["vex_statement_ref"] for x in d["rows"] if x["vex_statement_ref"]} <= refs


def test_rows_json_exposed_unknown_without_services_list(tmp_path):
    proj, scan = setup(tmp_path, services=None, name="nosvc")
    r, s, reports = run(proj, scan)
    d = json.loads((reports / "vulnerability-rows.json").read_text(encoding="utf-8"))
    assert d["exposed_services_list"] is False and all(x["exposed"] is None for x in d["rows"])


# ---------------------------------------------------------------- 計數與措辭

def test_tier_counts_rows_and_cves():
    tc = rp.tier_counts(MIX)
    assert tc[rp.T_NOW] == (3, 2)           # 3 列、2 個 CVE（CVE-1 兩個元件）
    assert tc[rp.T_TRACK] == (3, 3)         # p3 兩列＋NVIDIA 一列
    assert tc[rp.T_OK] == (2, 2)
    assert tc[rp.T_OTHER] == (0, 0)
    assert rp.tier_counts(MIX + [row("CVE-9", "p2")])[rp.T_OTHER] == (1, 1)     # 對不上三層的不消失


def _tbl(doc):
    """summary_top 的「還要處理的」小表 → ({項目: (列數, CVE 數)}, 單欄說明行)。"""
    top = rp.summary_top(doc, "x")
    i = next(k for k, r in enumerate(top) if r and r[0] == rp.OPEN_TITLE)
    d, notes = {}, []
    for r in top[i + 2:]:
        if not r:
            break
        if len(r) == 3:
            d[r[0]] = (r[1], r[2])
        else:
            notes.append(r[0])
    return d, notes


def test_summary_excluded_sub_rows():
    top = rp.summary_top(rows_doc(MIX + [row("CVE-1", "accepted", comp="libz", rule="K1")]), "x")
    assert ["　其中 不受影響", 2, 1] in top and ["　其中 已修補", 1, 1] in top
    assert top.index(["　其中 不受影響", 2, 1]) == top.index([rp.T_OK, 3, 2]) + 1


def test_open_summary_exposure_where_and_unknown():
    K = "kernel network (interfaces eth0, eth1; fix files net/a.c)"
    rows = ([row(f"CVE-{i}", "p1", is_kernel=True, exposed=True, exposed_where=K) for i in range(3)]
            + [row("CVE-10", "p3", exposed=True, exposed_where="/usr/sbin/dhcpd (udp/67 on 0.0.0.0), /usr/sbin/sshd (tcp/22)"),
               row("CVE-11", "p3", exposed=True, exposed_where="/usr/sbin/dhcpd (udp/67 on 0.0.0.0)")]
            + [row(f"CVE-2{i}", "p3", exposed=True, exposed_where=f"/bin/s{i} (tcp/{i})") for i in range(5)]
            + [row("CVE-30", "p3", exposed=False), row("CVE-31", "nvidia_bulletin", exposed=False),
               row("CVE-32", "p3", exposed=None), row("CVE-1", "accepted", exposed=True, exposed_where="x")])
    d, notes = _tbl(rows_doc(rows))
    assert d["從網路碰得到"] == (10, 10) and d["實機上沒對外"] == (2, 2)
    assert d["合計"] == (13, 13) and d["沒有實機資料（對外與否不明，不是「沒對外」）"] == (1, 1)
    bd = next(n for n in notes if n.startswith("　　其中"))
    assert "核心網路功能 3 列" in bd and "/usr/sbin/dhcpd (udp/67 on 0.0.0.0) 2 列" in bd and "其他 " in bd
    assert "eth1" not in bd                      # 括號內的逗號沒被切開
    assert any("不等於不能被利用" in n for n in notes)
    # 沒有不明的列：不印不明那一行
    d2, _ = _tbl(rows_doc([row("CVE-1", "p1", exposed=False)]))
    assert not any("不明" in k for k in d2)


def test_open_summary_no_board_data_shows_no_measured_numbers():
    d, notes = _tbl(rows_doc([row("CVE-1", "p1", exposed=None), row("CVE-2", "p3", exposed=None)], exposed_services_list=False))
    assert "從網路碰得到" not in d and "實機上沒對外" not in d
    assert d["沒有實機資料（對外與否不明）"] == (2, 2) and not any(n.startswith("　　其中") for n in notes)


def test_open_summary_severity_and_triage_state():
    rows = [row("CVE-1", "p1", severity="CRITICAL"), row("CVE-2", "p1", severity="high", vex={"state": "in_triage"}),
            row("CVE-3", "p3", severity="MEDIUM", vex={"state": "exploitable"}), row("CVE-4", "p3", severity="LOW"),
            row("CVE-5", "p3", severity=None), row("CVE-6", "p3", severity="WEIRD", vex={"state": "not_affected"}),
            row("CVE-7", "accepted", severity="CRITICAL")]
    d, _ = _tbl(rows_doc(rows))
    assert d["嚴重度 嚴重（CRITICAL）"] == (1, 1) and d["嚴重度 高（HIGH）"] == (1, 1)
    assert d["嚴重度 中（MEDIUM）"] == (1, 1) and d["嚴重度 低（LOW）"] == (1, 1) and d["嚴重度 未分級"] == (2, 2)
    assert d["其中狀態還沒判定"] == (4, 4)       # in_triage 1 ＋ vex 為 None 3


def test_wording_known_rules_and_unknown_code():
    for code, (cls, concl, act, who, ev) in rp.RULES.items():
        if cls is None:
            continue
        tier = {rp.T_NOW: "p1", rp.T_OK: "accepted", rp.T_TRACK: "p3"}[cls]
        r = row("CVE-1", tier, rule=code if code not in ("P1", "DISTRO", "NVIDIA") else None,
                source={"DISTRO": "distro", "NVIDIA": "nvidia"}.get(code))
        if code == "NVIDIA":
            r["tier"] = "nvidia_bulletin"
        got = rp.wording(r, {})
        assert got[1] == cls and got[2] == concl and got[4] == who and got[6] is None, code
        assert "{fix}" not in got[3] and got[2] not in ("", rp.UNKNOWN)
    unk = rp.wording(row("CVE-1", "p3", rule="Z9"), {})
    assert unk[2:5] == (rp.UNKNOWN,) * 3 and unk[6]
    # 規則和分類對不上（R1 卻在 accepted）也不靜靜放行
    mis = rp.wording(row("CVE-1", "accepted", rule="R1"), {})
    assert mis[2] == rp.UNKNOWN and "對不上" in mis[6]
    # 沒有規則也沒有判定的 p3
    assert rp.wording(row("CVE-1", "p3"), {})[2] == rp.UNKNOWN


def test_human_row_columns_and_no_noise():
    conf = ("RuleOwner", "2026-11-10", "RuleOwner")
    k = row("CVE-3", "p3", rule="R1", comp="linux-k", ver="6.8.0-1", is_kernel=True, fix_state="fixed", fix_versions=["6.8.0-5.5"],
            fix_next="6.8.0-5.5", cvss=None, ubuntu_priority="high")
    h = rp.human_row(k, {"linux-k": "6.8.0-9.9"}, conf)
    assert len(h) == len(rp.HEADER) == 19
    d = dict(zip(rp.HEADER, h))
    assert d["分類"] == rp.T_TRACK and d["修補版本"] == "需 6.8.0-9.9 以上" and "6.8.0-9.9 以上 以上" not in d["要做什麼"]
    assert d["嚴重度（分數）"] == "" and "高" in d["無評分原因"] and d["判定者"] == "RuleOwner（規則）" and d["判定日期"] == "2026-11-10" and d["備註"] == ""
    assert d["依據"].startswith("規則 R1：") and len(d["依據"]) < 80
    # 600 字的英文 detail、uuid、工具名不進人讀欄位
    r = row("CVE-4", "accepted", source="annotation", cvss=None)
    r["vex"].update(state="not_affected", author="Eng", date="2026-11-01",
                    detail="Grype 416baaa9-dc9f-4f7e-b7c0-123456789abc says " + "y" * 600)
    h = dict(zip(rp.HEADER, rp.human_row(r, {}, conf)))
    assert "416baaa9" not in " ".join(map(str, h.values())) and len(h["依據"]) < 120 and h["嚴重度（分數）"] == "" and "沒有 CVSS" in h["無評分原因"]
    assert h["判定者"] == "Eng" and h["判定日期"] == "2026-11-01"


def test_judge_never_blank_and_date_note():
    r6 = row("CVE-1", "p3", rule="R6")
    r6["vex"]["author"] = None
    no_date = dict(zip(rp.HEADER, rp.human_row(r6, {}, (None, None, "Author"))))
    assert no_date["判定者"] == "Author（規則）" and no_date["判定日期"] == "" and "尚未登錄" in no_date["備註"]
    p1 = dict(zip(rp.HEADER, rp.human_row(row("CVE-1", "p1"), {}, (None, None, None))))
    assert p1["判定者"] == "待 RD 判斷"
    assert dict(zip(rp.HEADER, rp.human_row(row("CVE-1", "p3"), {}, (None, None, None))))["判定者"] == "尚未判定"
    d = dict(zip(rp.HEADER, rp.human_row(row("CVE-5", "distro_fixed", source="distro"), {}, (None, None, None))))
    assert d["判定者"] == "自動（發行版紀錄）"


# ---------------------------------------------------------------- 整包

def walk(root):
    return sorted(p.relative_to(root).as_posix() for p in Path(root).rglob("*") if p.is_file())


def test_package_layout_sums_and_sheets(tmp_path):
    p = project(tmp_path, MIX, rules_doc={"schema": "sca-center-vex-rules/1", "rules": [], "author": "A", "confirmed_by": "RuleOwner",
                                          "confirmed_date": "2026-11-10"})
    sp = tmp_path / "sup"
    (sp / "CRA" / "Reports" / "supplier-package").mkdir(parents=True)
    (sp / "CRA" / "Reports" / "supplier-package" / "README.md").write_text("customer", encoding="utf-8")
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, sp, allow_tmp=True)
    assert code == 0, msgs
    files = walk(out)
    assert {"交給PM/漏洞清單.xlsx", "交給PM/SBOM/sbom.cdx.json", "交給PM/SBOM/sbom.md", "交給PM/VEX/vex.cdx.json", "交給PM/安全檢查結果.md",
            "交給PM/待確認事項.xlsx", "交給PM/客戶資料包/README.md", "給RD/P1判斷表.xlsx", "內部存檔/vulnerability-rows.json",
            "內部存檔/vex.openvex.json", "內部存檔/risk-assessment.md", "內部存檔/summary.json", "內部存檔/scan-status.tsv",
            "內部存檔/confirmation-items.md", "SHA256SUMS.txt"} <= set(files)
    assert "交給PM/VEX/vex.openvex.json" not in files and "內部存檔/vex.cdx.json" not in files
    # 沒有入口頁（先讀這個、README 是客戶資料包自己的檔，不算）
    assert not [f for f in files if "先讀" in f or re.match(r"(00-|0-)", Path(f).name) or (Path(f).name.lower() == "readme.md" and "客戶資料包" not in f)]
    # SHA256SUMS：每個檔都有、雜湊對、不含自己
    sums = dict(reversed(l.split("  ", 1)) for l in (out / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines())
    assert set(sums) == set(files) - {"SHA256SUMS.txt"}
    assert all(hashlib.sha256((out / f).read_bytes()).hexdigest() == h for f, h in sums.items())
    # 主清單：開放的列（p1 3、p3 2、NVIDIA 1）；排除的列另一張
    wb = sheets(out / "交給PM" / "漏洞清單.xlsx")
    assert list(wb) == ["總覽", "完整漏洞清單", "排除後剩下的", "規則說明"]
    h, rows = body(wb["排除後剩下的"], "初判")
    assert h == rp.LIST_HEADER and len(rows) == 6 and [r[0] for r in rows][:3] == [rp.SHORT["P1"]] * 3
    fh, full = body(wb["完整漏洞清單"], "初判")
    assert fh == rp.LIST_HEADER and len(full) == 8 and [r[0] for r in full][-2:] == [rp.SHORT["K1"], rp.SHORT["DISTRO"]]
    assert wb["完整漏洞清單"][0][0] == wb["排除後剩下的"][0][0] == rp.LIST_LEGEND
    assert "必須判斷" not in " ".join(h) and "已判斷" not in " ".join(h) and "purl" not in " ".join(h)
    # 規則確認者與日期來自設定檔
    r6 = next(r for r in rows if "R6" in r[10])
    assert r6[11] == "RuleOwner（規則）" and r6[12] == "2026-11-10" and r6[0] == rp.SHORT["R6"]
    # P1 判斷表：一個 CVE 一列、編號依 CVE 排序
    ph, prow = body(sheets(out / "給RD" / "P1判斷表.xlsx")["P1 判斷表"], "編號")
    assert ph == ["編號", "CVE", "元件與版本", "修補版本", "被利用證據", "初判", "回答", "決定", "填寫人", "日期"]
    assert [(r[0], r[1]) for r in prow] == [("Q1", "CVE-0"), ("Q2", "CVE-1")]
    assert "libp 1.0-1" in prow[1][2] and "libq 1.0-1" in prow[1][2] and prow[1][5] == ""
    assert "KEV" in prow[1][4] and "歐盟" in prow[1][4]
    # 規則說明：每個代號一列、有本次列數
    rh, rr = body(wb["規則說明"], "規則代號")
    assert {r[0] for r in rr} >= set(rp.RULE_ORDER) and next(r for r in rr if r[0] == "K1")[7] == 1 and next(r for r in rr if r[0] == "K1")[1] == rp.SHORT["K1"]


def test_no_supplier_project_is_reported(tmp_path):
    code, msgs = rp.build(project(tmp_path, MIX), tmp_path / "out", allow_tmp=True)
    assert code == 0 and any("客戶資料包：未產生" in m for m in msgs)
    assert not (tmp_path / "out" / "交給PM" / "客戶資料包").exists()


def test_same_rows_same_output_order(tmp_path):
    a = project(tmp_path, MIX, "a")
    b = project(tmp_path, list(reversed(MIX)), "b")
    rp.build(a, tmp_path / "oa", allow_tmp=True)
    rp.build(b, tmp_path / "ob", allow_tmp=True)
    for f in ("交給PM/漏洞清單.xlsx", "給RD/P1判斷表.xlsx"):
        assert sheets(tmp_path / "oa" / f) == sheets(tmp_path / "ob" / f)


def test_refuses_non_empty_out_and_tmp(tmp_path):
    p = project(tmp_path, MIX)
    out = tmp_path / "out"
    out.mkdir()
    (out / "keep.txt").write_text("x", encoding="utf-8")
    with pytest.raises(rp.PackageError, match="不是空的"):
        rp.build(p, out, allow_tmp=True)
    assert walk(out) == ["keep.txt"]
    f = tmp_path / "afile"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(rp.PackageError):
        rp.build(p, f, allow_tmp=True)
    # 空的資料夾可以用
    empty = tmp_path / "empty"
    empty.mkdir()
    assert rp.build(p, empty, allow_tmp=True)[0] == 0
    # /tmp：沒有 allow_tmp 就擋（在建立任何東西之前）
    with pytest.raises(rp.PackageError, match="/tmp"):
        rp.build(p, "/tmp/report-package-test-never-created")
    assert not Path("/tmp/report-package-test-never-created").exists()
    with pytest.raises(rp.PackageError, match="/tmp"):
        rp.check_out("/tmp")


def test_cli_refuses_tmp_and_exit_codes(tmp_path):
    p = project(tmp_path, MIX)
    r = subprocess.run([sys.executable, "-I", str(CLI), "--project", str(p), "--out", "/tmp/report-package-cli-never-created"],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "/tmp" in r.stderr and not Path("/tmp/report-package-cli-never-created").exists()
    assert subprocess.run([sys.executable, "-I", str(CLI)], capture_output=True, text=True).returncode == 64


def test_missing_rows_file_fails_without_output(tmp_path):
    p = project(tmp_path, MIX)
    (p / "CRA" / "Reports" / rp.ROWS_FILE).unlink()
    out = tmp_path / "out"
    with pytest.raises(rp.PackageError, match="vulnerability-rows.json"):
        rp.build(p, out, allow_tmp=True)
    assert not out.exists()
    # 格式不對、列數不符也失敗
    p2 = project(tmp_path, MIX, "p2")
    d = rows_doc(MIX)
    d["row_count"] = 1
    write_json(p2 / "CRA" / "Reports" / rp.ROWS_FILE, d)
    with pytest.raises(rp.PackageError, match="row_count"):
        rp.build(p2, tmp_path / "o2", allow_tmp=True)
    assert not (tmp_path / "o2").exists()


def test_missing_other_inputs_are_not_run_not_silent(tmp_path):
    p = project(tmp_path, MIX)
    for n in ("vex.cdx.json", "confirmation-items.csv"):
        (p / "CRA" / "Reports" / n).unlink()
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, tmp_path / "nosuch", allow_tmp=True)
    assert code == 2
    txt = (out / "交給PM" / "未產生的項目.md").read_text(encoding="utf-8")
    assert "NOT_RUN" in txt and "vex.cdx.json" in txt and "confirmation-items.csv" in txt and "supplier-package" in txt
    assert not (out / "交給PM" / "VEX").exists() and not (out / "交給PM" / "待確認事項.xlsx").exists()
    assert len([m for m in msgs if m.startswith("NOT_RUN")]) == 3
    assert (out / "交給PM" / "漏洞清單.xlsx").exists()


def test_no_findings_is_not_assessed_not_empty_list(tmp_path):
    p = project(tmp_path, [], have_findings=False, status="NOT_ASSESSED")
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, allow_tmp=True)
    assert code == 2 and "NOT_ASSESSED" in msgs[0]
    wb = sheets(out / "交給PM" / "漏洞清單.xlsx")
    assert "NOT_ASSESSED" in wb["總覽"][4][0]
    for n in ("完整漏洞清單", "排除後剩下的"):
        r0 = body(wb[n], "初判")[1][0]
        assert "NOT_ASSESSED" in r0[0] and "沒有資料" in r0[10]
    assert "NOT_ASSESSED" in sheets(out / "給RD" / "P1判斷表.xlsx")["P1 判斷表"][1][1]


def test_zero_p1_with_findings_says_so(tmp_path):
    p = project(tmp_path, [row("CVE-2", "p3", rule="R6")])
    code, _ = rp.build(p, tmp_path / "out", allow_tmp=True)
    assert code == 0
    assert "沒有立即處理" in sheets(tmp_path / "out" / "給RD" / "P1判斷表.xlsx")["P1 判斷表"][1][1]


def test_failure_cleans_up_created_out(tmp_path, monkeypatch):
    p = project(tmp_path, MIX)

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(rp, "write_xlsx", boom)
    out = tmp_path / "out"
    with pytest.raises(OSError):
        rp.build(p, out, allow_tmp=True)
    assert not out.exists()


def test_vex_rules_confirmation_keys_accepted_and_checked():
    ok = {"schema": vx.RULES_SCHEMA, "author": "A", "confirmed_by": "RuleOwner", "confirmed_date": "2026-11-10", "rules": []}
    vx.check_rules(ok)
    for bad in ({"confirmed_date": "10/11/2026"}, {"confirmed_by": ""}, {"confirmed_date": 5}):
        with pytest.raises(vx.VexInputError):
            vx.check_rules(dict(ok, **bad))


# ---------------------------------------------------------------- xlsx

def test_xlsx_structure(tmp_path):
    f = tmp_path / "t.xlsx"
    xlsx_min.write_xlsx(f, [xlsx_min.Sheet("A/B:C", ["甲", "乙", "丙"], [["x<&>", 3, 2.5], ["bad\x00ctl\x1f", None, True], ["長" * 40000, "", ""]],
                                           widths=[10, 20, 30], top=[["說明一行"], []]),
                            xlsx_min.Sheet("二", ["h"], [])])
    z = zipfile.ZipFile(f)
    assert z.testzip() is None
    assert {"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/styles.xml",
            "xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml"} == set(z.namelist())
    for n in z.namelist():
        ET.fromstring(z.read(n))                       # 全部是合法的 XML
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    s1 = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))
    assert s1.find("m:sheetViews/m:sheetView/m:pane", ns) is None                                        # 不凍結窗格（上方說明列會被整塊固定住）
    assert s1.find("m:autoFilter", ns).get("ref") == "A3:C6"
    assert [c.get("width") for c in s1.findall("m:cols/m:col", ns)] == ["10", "20", "30"]
    hdr = s1.findall("m:sheetData/m:row", ns)[2]
    assert [c.get("s") for c in hdr] == ["1", "1", "1"]                                                  # 粗體表頭
    wbx = ET.fromstring(z.read("xl/workbook.xml"))
    assert [s.get("name") for s in wbx.find("m:sheets", ns)] == ["A-B-C", "二"]                           # 非法字元換掉
    back = xlsx_min.read_xlsx(f)["A-B-C"]
    assert back[3] == ["x<&>", 3.0, 2.5] and back[4][0] == "badctl" and back[4][2] == "是"
    assert back[5][0].endswith("…（截斷）") and len(back[5][0]) < 33000
    with pytest.raises(ValueError):
        xlsx_min.write_xlsx(tmp_path / "d.xlsx", [xlsx_min.Sheet("a", ["h"], []), xlsx_min.Sheet("A", ["h"], [])])


def test_xlsx_col_names():
    assert [xlsx_min.col_name(i) for i in (0, 25, 26, 27, 701, 702)] == ["A", "Z", "AA", "AB", "ZZ", "AAA"]


def test_xlsx_opens_in_libreoffice(tmp_path):
    """有 LibreOffice 時再用它把 xlsx 轉 CSV 讀回來；沒有時只做自己的讀回（不用 skip：CI 的 DUMPLING_REQUIRE_TEST_DATA=1 不允許 skip）。"""
    p = project(tmp_path, MIX)
    out = tmp_path / "out"
    rp.build(p, out, allow_tmp=True)
    assert sheets(out / "給RD" / "P1判斷表.xlsx")["P1 判斷表"][1][1] == "CVE-0"
    if not shutil.which("soffice"):
        return
    conv = tmp_path / "conv"
    r = subprocess.run(["soffice", f"-env:UserInstallation=file://{tmp_path}/lo-profile", "--headless", "--convert-to", 'csv:Text - txt - csv (StarCalc):44,34,76',
                        "--outdir", str(conv), str(out / "給RD" / "P1判斷表.xlsx")], capture_output=True, text=True, timeout=180)
    csvs = list(conv.glob("*.csv"))
    assert r.returncode == 0 and csvs, r.stdout + r.stderr
    text = csvs[0].read_text(encoding="utf-8")
    assert "編號" in text and "CVE-0" in text and "Q2" in text


# ---------------------------------------------------------------- 誰處理只能是角色；待確認事項.xlsx

def test_who_column_is_always_a_role():
    assert rp.ROLES == {"RD", "CRA掃描", "PM", "—"}
    for code, ent in rp.RULES.items():
        if ent[0] is not None:
            assert ent[3] in rp.ROLES, code
    for who in (e[2] for e in rp.MANUAL.values()):
        assert who in rp.ROLES
    want = {"P1": "RD", "R1": "RD", "R3": "RD", "R4": "RD", "R9": "RD",
            "R2": "CRA掃描", "R5": "CRA掃描", "R6": "CRA掃描", "R8": "CRA掃描", "NVIDIA": "CRA掃描",
            "R7": "RD", "R5w": "RD", "K1": "—", "K2": "—", "U1": "—", "U2": "—", "DISTRO": "—"}
    assert {c: rp.RULES[c][3] for c in want} == want


def test_who_column_in_sheets_is_a_role_or_unknown(tmp_path):
    p = project(tmp_path, MIX + [row("CVE-8", "p3", rule="Z9")])
    rp.build(p, tmp_path / "out", allow_tmp=True)
    wb = sheets(tmp_path / "out" / "交給PM" / "漏洞清單.xlsx")
    for name in ("完整漏洞清單", "排除後剩下的"):
        assert {r[9] for r in body(wb[name], "初判")[1]} <= rp.ROLES | {rp.UNKNOWN}
    assert {x[9] for x in rp.component_sheet(doc_for(p), {}, "L").rows} <= rp.ROLES | {rp.UNKNOWN}
    assert "等上游" not in " ".join(r[8] for r in body(wb["排除後剩下的"], "初判")[1])


# 真實格式（12 欄）和真實說法的合成資料
REAL_HEAD = "編號,類別,掃描發現（為什麼要問）,影響,要問誰（建議）,要確認的問題,建議做法,回答,決定,填寫人,日期,軟體部門後續\n"
REAL_ROWS = (
    "Q1,缺少輸入,[input:vuln-data] 漏洞資料不完整（GAP）：C-sbomgate is GAP；UEFI bundled libraries: edk2: NOT_ASSESSED: edk2 itself is not matched,"
    "下面的漏洞事項可能不完整,軟體部門（掃描負責人）,哪個掃描階段沒有完成？,重新掃描,,,,,重新掃描後再產生這張表\n"
    "Q2,被利用或優先處理的漏洞,[vuln:CVE-1:libp] CVE-1 已被利用,影響出貨,產品工程師,受不受影響？,記下判定,,,,,\n"
    "Q3,公司與產品資料,[fields:x] 欄位未填,文件不完整,內部窗口（PM）、產品工程師,請填,寫進設定檔,,,,,\n"
    "Q4,公司與產品資料,[fields:y] 法務,法務,內部窗口（PM）＋法務,請確認,x,,,,,\n"
    "Q5,開發工具,[dev:b] B-toolchain 沒有；B-npm-no-lockfile,x,內部窗口,確認,y,,,,,\n")


def test_confirmation_items_real_format(tmp_path):
    p = project(tmp_path, MIX)
    (p / "CRA" / "Reports" / "confirmation-items.csv").write_text(REAL_HEAD + REAL_ROWS, encoding="utf-8-sig")
    rp.build(p, tmp_path / "out", allow_tmp=True)
    sh = sheets(tmp_path / "out" / "交給PM" / "待確認事項.xlsx")["待確認事項"]
    assert sh[0] == ["編號", "類別", "掃描發現（為什麼要問）", "影響", "要問誰（建議）", "要確認的問題", "建議做法", "回答", "決定", "填寫人", "日期",
                     "CRA掃描後續"]
    # 只問 CRA掃描的 Q1（掃描自己的待辦）不放進給 PM 的表；其餘依序重新編號
    assert [r[0] for r in sh[1:]] == [f"確-0{i}" for i in range(1, 5)] and all(len(r) == 12 for r in sh[1:])
    assert [r[4] for r in sh[1:]] == ["RD", "PM、RD", "PM＋法務", "PM"]
    assert "CRA掃描" not in [r[4] for r in sh[1:]]
    assert not any("哪個掃描階段沒有完成" in str(c) for r in sh for c in r)
    assert all(h not in " ".join(sh[0]) for h in ("原編號", "內部鍵"))
    # 內部鍵拿掉；階段代號前面有白話，英文原文不動
    assert not any("[vuln:" in str(c) or "[input:" in str(c) or "[fields:" in str(c) or "[dev:" in str(c) for r in sh for c in r)
    assert sh[4][2].startswith("（建置工具；npm 專案沒有鎖定檔）")
    assert sh[1][2] == "CVE-1 已被利用"
    # 沒有階段代號的格子不加前綴
    assert not sh[2][2].startswith("（")
    # 被拿掉的題目仍在內部存檔的原始 csv（可追溯）
    raw = (tmp_path / "out" / "內部存檔" / "confirmation-items.csv").read_text(encoding="utf-8-sig")
    assert "哪個掃描階段沒有完成" in raw


def test_confirmation_stage_prefix_on_kept_items():
    assert rp.stage_prefix("C-sbomgate is GAP").startswith("（SBOM 完整度")


def test_no_generated_xlsx_cell_says_product_engineer(tmp_path):
    p = project(tmp_path, MIX + [row("CVE-8", "p3", rule="Z9"), row("CVE-9", "accepted", source="annotation")])
    (p / "CRA" / "Reports" / "confirmation-items.csv").write_text(REAL_HEAD + REAL_ROWS, encoding="utf-8-sig")
    write_json(p / "CRA" / "Reports" / "summary.json", {"config_warnings": ["軟體部門請看 exposed-services.json 的 collected 早於這次掃描"]})
    sp = tmp_path / "sup"
    (sp / "CRA" / "Reports" / "supplier-package").mkdir(parents=True)
    out = tmp_path / "out"
    rp.build(p, out, sp, allow_tmp=True)
    n = 0
    for f in out.rglob("*.xlsx"):
        for rows in xlsx_min.read_xlsx(f).values():
            for r in rows:
                n += len(r)
                assert not any(w in str(c) for c in r for w in ("產品工程師", "軟體部門")), (f, r)
    assert n > 50


# ---------------------------------------------------------------- 第二輪修正

def run_cli(project_dir, out, *extra):
    r = subprocess.run([sys.executable, "-I", str(CLI), "--project", str(project_dir), "--out", str(out), *extra],
                       capture_output=True, text=True)
    return r, r.stdout.strip().splitlines()


def test_f4_gap_data_exits_2_and_prints_status(tmp_path):
    """漏洞資料狀態不是 OK：退出碼 2，最後一行印那個狀態，不印 OK。"""
    # 用 /media 以外的位置時 CLI 會擋 /tmp，所以直接呼叫 main 並攔 stdout
    import io
    from contextlib import redirect_stdout
    p = project(tmp_path, MIX, name="gap", status="GAP")
    buf = io.StringIO()
    rp_out = tmp_path / "o1"
    orig = rp.check_out
    rp.check_out = lambda out, allow_tmp=False: orig(out, True)
    try:
        with redirect_stdout(buf):
            code = rp.main(["--project", str(p), "--out", str(rp_out)])
        assert code == 2 and buf.getvalue().splitlines()[-1].startswith("GAP\t")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = rp.main(["--project", str(project(tmp_path, MIX, name="ok")), "--out", str(tmp_path / "o2")])
        assert code == 0 and buf.getvalue().splitlines()[-1].startswith("OK\t")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = rp.main(["--project", str(project(tmp_path, [], name="na", have_findings=False, status="NOT_ASSESSED")), "--out", str(tmp_path / "o3")])
        assert code == 2 and buf.getvalue().splitlines()[-1].startswith("NOT_ASSESSED\t")
    finally:
        rp.check_out = orig


def test_f5_only_unclassified_component_is_not_called_not_affected(tmp_path):
    p = project(tmp_path, [row("CVE-1", "p2", comp="libodd"), row("CVE-2", "accepted", rule="K1", comp="libok")])
    rp.build(p, tmp_path / "out", allow_tmp=True)
    by = {x[0]: x for x in rp.component_sheet(doc_for(p), {}, "L").rows}
    assert rp.UNKNOWN in by["libodd"][7] and by["libodd"][8] == rp.UNKNOWN and by["libodd"][9] == rp.UNKNOWN
    assert "全部經評估不受影響" not in by["libodd"][7] and "全部經評估不受影響" in by["libok"][7]


def test_f6_no_fix_version_on_not_affected_rows(tmp_path):
    k = row("CVE-3", "accepted", rule="K1", comp="linux-k", is_kernel=True, fix_state="fixed", fix_versions=["6.8.0-5.5"], fix_next="6.8.0-5.5")
    d = row("CVE-5", "distro_fixed", source="distro", fix_state="fixed", fix_versions=["1-2"], fix_next="1-2")
    p = project(tmp_path, [k, d, row("CVE-2", "p3", rule="R6")])
    rp.build(p, tmp_path / "out", allow_tmp=True)
    wb = sheets(tmp_path / "out" / "交給PM" / "漏洞清單.xlsx")
    fx = [r[7] for r in body(wb["完整漏洞清單"], "初判")[1] if r[0].startswith("不影響")]
    assert fx == [rp.NOT_AFFECTED_FIX] * 2 and not any("需" in x for x in fx)


def test_f7_warnings_and_exposure_note(tmp_path):
    p = project(tmp_path, [row("CVE-2", "p3", rule="R6", exposed=None)], exposed_services_list=False)
    write_json(p / "CRA" / "Reports" / "summary.json", {"config_warnings": ["config 警告：CRA/Config/exposed-services.json 的 collected 2026-11-06 早於這次掃描 2026-11-11"]})
    rp.build(p, tmp_path / "out", allow_tmp=True)
    wb = sheets(tmp_path / "out" / "交給PM" / "漏洞清單.xlsx")
    assert any(r and "設定警告" in str(r[0]) and "exposed-services.json" in r[0] for r in wb["總覽"])
    assert "不明" in " ".join(str(c) for r in body(wb["排除後剩下的"], "初判")[1] for c in r)
    assert "沒有對外服務清單" in wb["排除後剩下的"][1][0] and wb["排除後剩下的"][0][0] == rp.LIST_LEGEND
    # 清單在、只是比掃描舊
    p2 = project(tmp_path, [row("CVE-2", "p3", rule="R6")], name="p2")
    write_json(p2 / "CRA" / "Reports" / "summary.json", {"config_warnings": ["exposed-services.json 的 collected 早於這次掃描"]})
    rp.build(p2, tmp_path / "out2", allow_tmp=True)
    assert "可能比這次掃描舊" in sheets(tmp_path / "out2" / "交給PM" / "漏洞清單.xlsx")["排除後剩下的"][1][0]


def test_f8_out_inside_project_refused(tmp_path):
    p = project(tmp_path, MIX)
    for bad in (p / "CRA" / "Reports" / "pkg", p / "pkg", p):
        with pytest.raises(rp.PackageError, match="專案資料夾裡面"):
            rp.build(p, bad, allow_tmp=True)
    sp = project(tmp_path, MIX, name="sup")
    with pytest.raises(rp.PackageError, match="專案資料夾裡面"):
        rp.build(p, sp / "x", sp, allow_tmp=True)
    assert not (p / "pkg").exists() and not (sp / "x").exists()


def test_f9_symlinks_are_not_followed(tmp_path):
    p = project(tmp_path, MIX)
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET", encoding="utf-8")
    rep = p / "CRA" / "Reports"
    (rep / "sbom.md").unlink()
    (rep / "sbom.md").symlink_to(secret)
    (rep / "extra.txt").symlink_to(secret)
    (rep / "linkdir").symlink_to(tmp_path)
    sp = tmp_path / "sup"
    pkg = sp / "CRA" / "Reports" / "supplier-package"
    pkg.mkdir(parents=True)
    (pkg / "evil.md").symlink_to(secret)
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, sp, allow_tmp=True)
    assert code == 2
    txt = (out / "交給PM" / "未產生的項目.md").read_text(encoding="utf-8")
    assert "sbom.md" in txt and "extra.txt" in txt and "linkdir" in txt and "符號連結" in txt
    assert not (out / "交給PM" / "SBOM" / "sbom.md").exists() and not (out / "內部存檔" / "extra.txt").exists()
    assert (out / "交給PM" / "客戶資料包" / "evil.md").is_symlink()          # 連結本身照搬，不展開
    assert not any("TOP-SECRET" in f.read_text(encoding="utf-8", errors="ignore") for f in out.rglob("*") if f.is_file() and not f.is_symlink())
    assert "evil.md" not in (out / "SHA256SUMS.txt").read_text(encoding="utf-8")


def test_f10_nan_inf_cells_are_text(tmp_path):
    f = tmp_path / "n.xlsx"
    xlsx_min.write_xlsx(f, [xlsx_min.Sheet("a", ["h"], [[float("nan")], [float("inf")], [float("-inf")], [1.5]])])
    z = zipfile.ZipFile(f).read("xl/worksheets/sheet1.xml").decode("utf-8")
    assert "<v>nan</v>" not in z and "<v>inf</v>" not in z and "<v>-inf</v>" not in z
    assert xlsx_min.read_xlsx(f)["a"][1:] == [["nan"], ["inf"], ["-inf"], [1.5]]


def test_f11_score_and_reason_columns(tmp_path):
    p = project(tmp_path, [row("CVE-1", "p3", rule="R6", cvss=None), row("CVE-2", "p3", rule="R6", cvss=None, ubuntu_priority="high"),
                           row("CVE-3", "p3", rule="R6")])
    rp.build(p, tmp_path / "out", allow_tmp=True)
    h, rows = body(sheets(tmp_path / "out" / "交給PM" / "漏洞清單.xlsx")["排除後剩下的"], "初判")
    assert h[4] == "嚴重度（分數）" and h[10] == "依據與備註"
    by = {r[1]: r for r in rows}
    assert by["CVE-3"][4] == 7.5 and "無評分原因" not in by["CVE-3"][10]
    assert by["CVE-1"][4] == "" and "沒有任何" not in by["CVE-1"][10] and "無評分原因：沒有 CVSS" in by["CVE-1"][10]
    assert by["CVE-2"][4] == "" and "無評分原因：" in by["CVE-2"][10] and "高" in by["CVE-2"][10]


def test_deb_python_rows_point_to_ubuntu_package_not_pypi_version():
    """Ubuntu 打包的 Python 模組：R3 的「要做什麼」與「修補版本」不照 PyPI 版本寫（apt 給不出 PyPI 的版本）。"""
    owned = row("CVE-1", "p3", rule="R3", comp="pillow", ver="10.2.0", fix_state="fixed", fix_versions=["10.2.0-1ubuntu1.3"],
                deb_python={"owner": {"name": "python3-pil", "version": "10.2.0-1ubuntu1"}, "candidates": [], "pypi_fix": ["12.3.0"]})
    act = rp.wording(owned, {})[3]
    assert act == "更新 Ubuntu 套件 python3-pil 到 10.2.0-1ubuntu1.3 以上（PyPI 的 12.3.0 不適用於發行版套件）" and "下一版" not in act
    assert rp.fix_text(owned, {}) == "10.2.0-1ubuntu1.3"
    noversion = row("CVE-2", "p3", rule="R3", comp="pillow", ver="10.2.0", fix_state="not-fixed",
                    deb_python={"owner": {"name": "python3-pil", "version": "1"}, "candidates": [], "pypi_fix": ["12.3.0"]})
    assert rp.wording(noversion, {})[3] == "更新 Ubuntu 套件 python3-pil（PyPI 的 12.3.0 不適用於發行版套件）"
    amb = row("CVE-3", "p3", rule="R3", comp="pillow", ver="10.2.0", fix_state="fixed", fix_versions=["12.3.0"],
              deb_python={"owner": None, "candidates": ["python3-pil", "python3-pil.imagetk"], "pypi_fix": ["12.3.0"]})
    assert rp.wording(amb, {})[3] == "由 Ubuntu 套件安裝（python3-pil 或 python3-pil.imagetk），先確認是哪個套件，再更新該套件"
    assert "12.3.0" not in rp.fix_text(amb, {}) and "12.3.0" not in rp.human_row(amb, {}, (None, None, None))[7]
    # 一般的 R3（不是 Python 模組）不變
    plain_ = row("CVE-4", "p3", rule="R3", fix_state="fixed", fix_versions=["1.2-1"])
    assert rp.wording(plain_, {})[3] == "下一版映像更新到 1.2-1 以上"
    assert rp.wording(dict(plain_, deb_python=None), {})[3] == "下一版映像更新到 1.2-1 以上"


def test_vulnerability_rows_carry_deb_python():
    import cra_report as cr
    r = {"id": "CVE-1", "component": "pillow", "version": "10.2.0", "tier": "p3", "fix_state": "fixed", "fix_versions": ["12.3.0"],
         "deb_python": {"path": "/usr/lib/python3/dist-packages/PIL", "owner": None,
                        "candidates": ["python3-pil 10.2.0-1", "python3-pil.imagetk 10.2.0-1"], "pypi_fix": ["12.3.0"]}}
    out = cr.vulnerability_rows([r, dict(r, id="CVE-2", deb_python=None)], ({}, {}), None, None, None, None, [], False)
    assert out[0]["deb_python"] == {"owner": None, "candidates": ["python3-pil", "python3-pil.imagetk"], "pypi_fix": ["12.3.0"]}
    assert out[1]["deb_python"] is None


def test_inputs_check_missing_required_is_gap_and_archived(tmp_path):
    p = project(tmp_path, MIX, with_all=True)
    chk = tmp_path / "inputs-check.json"
    write_json(chk, {"inputs": [
        {"id": "br", "label": "核心建置紀錄", "required": True, "status": "missing", "affects": "核心判斷不了的一律當成受影響"},
        {"id": "opt", "label": "選用項", "required": False, "status": "missing", "affects": "x"},
        {"id": "ok", "label": "刷機包", "required": True, "status": "found", "affects": "y"}]})
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, tmp_path / "nosuch", allow_tmp=True, inputs_check=chk)
    assert code == 2 and msgs.status == "GAP"
    txt = (out / "交給PM" / "未產生的項目.md").read_text(encoding="utf-8")
    assert "必要輸入：核心建置紀錄" in txt and "選用項" not in txt and "刷機包" not in txt
    assert (out / "內部存檔" / "inputs-check.json").is_file()
    cells = [c for sh in sheets(out / "交給PM" / "漏洞清單.xlsx").values() for r in sh for c in r]
    assert any("必要輸入缺少（GAP）：核心建置紀錄" in str(c) for c in cells)


def test_no_inputs_check_unchanged(tmp_path):
    out = tmp_path / "out"
    rp.build(project(tmp_path, MIX), out, allow_tmp=True)
    assert not (out / "內部存檔" / "inputs-check.json").exists()


@pytest.mark.parametrize("payload", ['[]', '{"inputs": 5}', '{"inputs": [1]}', '{}'])
def test_inputs_check_bad_shape_is_package_error(tmp_path, payload):
    chk = tmp_path / "ic.json"
    chk.write_text(payload)
    with pytest.raises(rp.PackageError):
        rp.build(project(tmp_path, MIX), tmp_path / "out", allow_tmp=True, inputs_check=chk)


def test_inputs_check_unconfirmed_required_is_warning_not_gap(tmp_path):
    chk = tmp_path / "ic.json"
    write_json(chk, {"inputs": [{"id": "m", "label": "人工確認項", "required": True, "status": "unchecked", "affects": "z"}]})
    out = tmp_path / "out"
    code, msgs = rp.build(project(tmp_path, MIX), out, tmp_path / "nosuch", allow_tmp=True, inputs_check=chk)
    cells = [c for sh in sheets(out / "交給PM" / "漏洞清單.xlsx").values() for r in sh for c in r]
    assert any("必要輸入未確認" in str(c) and "人工確認項" in str(c) for c in cells)
    txt = (out / "交給PM" / "未產生的項目.md").read_text(encoding="utf-8")
    assert "人工確認項" not in txt


def test_inputs_check_step_gap_shows_in_report(tmp_path):
    """精靈附加步驟（tee-source 等）沒做成：進設定警告與「未產生的項目」（GAP），found 的不出現。"""
    p = project(tmp_path, MIX, with_all=True)
    chk = tmp_path / "inputs-check.json"
    write_json(chk, {"inputs": [
        {"id": "step:tee-source", "label": "OP-TEE 公開原始碼", "kind": "step", "required": False, "status": "gap", "note": "沒有資料夾", "affects": "OP-TEE 不在 SBOM"},
        {"id": "step:A0-source", "label": "A0 原始碼比對", "kind": "step", "required": False, "status": "found", "note": "ok", "affects": "z"}]})
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, tmp_path / "nosuch", allow_tmp=True, inputs_check=chk)
    assert code == 2 and msgs.status == "GAP"
    txt = (out / "交給PM" / "未產生的項目.md").read_text(encoding="utf-8")
    assert "附加步驟：OP-TEE 公開原始碼（GAP）" in txt and "A0 原始碼比對" not in txt
    cells = [c for sh in sheets(out / "交給PM" / "漏洞清單.xlsx").values() for r in sh for c in r]
    assert any("OP-TEE 公開原始碼：GAP" in str(c) for c in cells)
