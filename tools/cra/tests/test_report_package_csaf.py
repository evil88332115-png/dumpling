"""report_package.py --csaf-previous：CSAF 修補公告草稿放 交給PM/CSAF/、進 SHA256SUMS、不進客戶資料包。資料全部是合成的。"""
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import csaf_advisory as ca
import report_package as rp
from test_csaf_advisory import CFG, NEW, OLD, SBOM_NEW, csaf_validator, reports as csaf_reports
from test_report_package import MIX, CLI, project, walk


def pkg_project(tmp, cfg=None):
    """報告套件要的專案（假的 rows）＋新版的 VEX／SBOM／summary（csaf_advisory 的合成資料）。"""
    p = project(tmp, MIX)
    src = csaf_reports(Path(tmp) / "newsrc", "1.1.0", NEW, 3, SBOM_NEW)
    for n in ("vex.cdx.json", "sbom.cdx.json", "summary.json"):
        shutil.copyfile(src / n, p / "CRA" / "Reports" / n)
    (p / "CRA" / "Config" / "config.json").write_text(json.dumps(dict(cfg or CFG, product={"name": "ACME-X100", "version": "1.1.0"})), encoding="utf-8")
    return p


def old_reports(tmp):
    return csaf_reports(Path(tmp) / "oldrep", "1.0.0", OLD)


def test_csaf_with_previous_is_in_pm_folder_and_sums(tmp_path):
    p = pkg_project(tmp_path)
    sp = tmp_path / "sup"
    (sp / "CRA" / "Reports" / "supplier-package").mkdir(parents=True)
    (sp / "CRA" / "Reports" / "supplier-package" / "README.md").write_text("customer", encoding="utf-8")
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, sp, allow_tmp=True, csaf_previous=old_reports(tmp_path))
    files = walk(out)
    f = "交給PM/CSAF/csaf-fix-advisory-ACME-X100-1.1.0.json"
    assert f in files and "交給PM/CSAF/README.md" in files and "內部存檔/csaf-fix-advisory/csaf-summary.json" in files
    assert not [x for x in files if "客戶資料包" in x and "csaf" in x.lower()]           # 不自動進客戶資料包
    doc = json.loads((out / f).read_text(encoding="utf-8"))
    assert not list(csaf_validator().iter_errors(doc)) and doc["document"]["tracking"]["status"] == "draft"
    sums = dict(reversed(l.split("  ", 1)) for l in (out / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines())
    assert f in sums and "交給PM/CSAF/README.md" in sums and hashlib.sha256((out / f).read_bytes()).hexdigest() == sums[f]
    assert any(m.startswith("CSAF 修補公告草稿：") and "已修補 2" in m for m in msgs) and code == 0, msgs
    rd = (out / "交給PM/CSAF/README.md").read_text(encoding="utf-8")
    for must in ("草稿", "reassessed", "**這不是修補**", "我們是供應商時", "製造商", "官網", "單一通報平台", "csaf_advisory.py exploited", "不會自動放進客戶資料包"):
        assert must in rd, must
    assert "| 已修補（fixed） | 2 |" in rd and "| 重新評估（reassessed） | 0 |" in rd


def test_csaf_missing_publisher_is_attention_in_readme(tmp_path):
    p = pkg_project(tmp_path, cfg={"manufacturer": {"name": "Acme Boards Ltd."}})
    out = tmp_path / "out"
    rp.build(p, out, allow_tmp=True, csaf_previous=old_reports(tmp_path))
    rd = (out / "交給PM/CSAF/README.md").read_text(encoding="utf-8")
    assert "這一次還缺：csaf.publisher_namespace" in rd and "ATTENTION" in rd
    doc = json.loads((out / "交給PM/CSAF/csaf-fix-advisory-ACME-X100-1.1.0.json").read_text(encoding="utf-8"))
    assert doc["document"]["publisher"]["namespace"] == ca.TBC_URI


def test_no_previous_is_not_run_not_gap(tmp_path):
    p = pkg_project(tmp_path)
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, allow_tmp=True)
    assert "交給PM/CSAF/README.md" not in walk(out) and not (out / "交給PM" / "CSAF").exists()
    assert any("CSAF 修補公告：未產生（NOT_RUN" in m for m in msgs)
    assert not any("CSAF" in x for x in walk(out))


def test_previous_without_vex_is_gap_listed_not_silent(tmp_path):
    p = pkg_project(tmp_path)
    prev = tmp_path / "emptyprev"
    prev.mkdir()
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, allow_tmp=True, csaf_previous=prev)
    assert code == 2 and not (out / "交給PM" / "CSAF").exists()
    text = (out / "交給PM" / "未產生的項目.md").read_text(encoding="utf-8")
    assert "CSAF 修補公告草稿" in text and "vex.cdx.json" in text


def test_previous_same_as_current_and_wrong_order_are_gap(tmp_path):
    p = pkg_project(tmp_path)
    code, msgs = rp.build(p, tmp_path / "o1", allow_tmp=True, csaf_previous=p / "CRA" / "Reports")
    assert code == 2 and "同一個資料夾" in (tmp_path / "o1" / "交給PM" / "未產生的項目.md").read_text(encoding="utf-8")
    # 前一版比這一版新（對調）：csaf_advisory 判定 FAIL，不產生
    newer = csaf_reports(tmp_path / "newer", "2.0.0", OLD)
    code, msgs = rp.build(p, tmp_path / "o2", allow_tmp=True, csaf_previous=newer)
    assert code == 2 and not (tmp_path / "o2" / "交給PM" / "CSAF").exists()


def test_wizard_output_folder_is_accepted_as_previous(tmp_path):
    p = pkg_project(tmp_path)
    wiz = tmp_path / "wiz"
    shutil.copytree(old_reports(tmp_path), wiz / "cra-project" / "CRA" / "Reports")
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, allow_tmp=True, csaf_previous=wiz)
    assert (out / "交給PM/CSAF/csaf-fix-advisory-ACME-X100-1.1.0.json").is_file()


def test_informational_not_run_step_is_not_gap(tmp_path):
    p = pkg_project(tmp_path)
    ic = tmp_path / "ic.json"
    ic.write_text(json.dumps({"inputs": [{"id": "step:csaf-fix-advisory", "label": "CSAF 修補公告草稿", "kind": "step", "status": "not_run",
                                          "informational": True, "required": False, "note": "沒有前一版", "affects": "沒有修補公告草稿"}]}), encoding="utf-8")
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, allow_tmp=True, inputs_check=ic)
    assert code == 0 and not (out / "交給PM" / "未產生的項目.md").exists()
    # informational 只對 csaf-fix-advisory 這個 id 有效：其他步驟自己標 informational 也照舊算 GAP
    d = json.loads(ic.read_text(encoding="utf-8"))
    d["inputs"][0]["id"] = "step:something-else"
    ic.write_text(json.dumps(d), encoding="utf-8")
    assert rp.build(p, tmp_path / "out3", allow_tmp=True, inputs_check=ic)[0] == 2
    d["inputs"][0]["id"] = "step:csaf-fix-advisory"
    ic.write_text(json.dumps(d), encoding="utf-8")
    # 沒有 informational 標記的同樣步驟照舊算 GAP
    d = json.loads(ic.read_text(encoding="utf-8"))
    d["inputs"][0].pop("informational")
    ic.write_text(json.dumps(d), encoding="utf-8")
    code, msgs = rp.build(p, tmp_path / "out2", allow_tmp=True, inputs_check=ic)
    assert code == 2


def test_cli_flag(tmp_path, capsys, monkeypatch):
    p = pkg_project(tmp_path)
    orig = rp.check_out
    monkeypatch.setattr(rp, "check_out", lambda out, allow_tmp=False: orig(out, True))      # CI 的 tmp_path 在 /tmp：CLI 預設不寫 /tmp
    rc = rp.main(["--project", str(p), "--out", str(tmp_path / "o"), "--csaf-previous", str(old_reports(tmp_path))])
    assert "CSAF 修補公告草稿" in capsys.readouterr().out and (tmp_path / "o/交給PM/CSAF/README.md").is_file() and rc in (0, 2)
    r = subprocess.run([sys.executable, "-I", str(CLI), "--help"], capture_output=True, text=True)
    assert "--csaf-previous" in r.stdout


def test_customer_package_never_contains_csaf(tmp_path):
    """dumpling：客戶資料包（--supplier-project 的資料包，加上 --previous 的英文差異）裡沒有任何 CSAF 檔案或 CSAF 內容；
    CSAF 草稿只在 交給PM/CSAF/ 與 內部存檔/csaf-fix-advisory/。"""
    p = pkg_project(tmp_path)
    sp = tmp_path / "sup"
    (sp / "CRA" / "Reports" / "supplier-package").mkdir(parents=True)
    (sp / "CRA" / "Reports" / "supplier-package" / "README.md").write_text("customer", encoding="utf-8")
    out = tmp_path / "out"
    code, msgs = rp.build(p, out, sp, allow_tmp=True, csaf_previous=old_reports(tmp_path))
    cust = [x for x in walk(out) if x.startswith("交給PM/客戶資料包/")]
    assert cust, "客戶資料包應該有產生（否則這個測試沒有意義）"
    for x in cust:
        assert "csaf" not in x.lower(), x
        data = (out / x).read_bytes()
        assert b"csaf_security_advisory" not in data and b"csaf_version" not in data, x
    csaf_files = [x for x in walk(out) if "csaf" in x.lower()]
    assert csaf_files and all(x.startswith(("交給PM/CSAF/", "內部存檔/csaf-fix-advisory/")) for x in csaf_files), csaf_files
