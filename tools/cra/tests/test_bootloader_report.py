"""bootloader_coverage.py 的結果進 cra_report.py（sbom.md、風險表的列）與供應商資料包（sbom.md）。
UEFI 假樹與 Grype 假結果沿用 test_uefi_bundled.py 的 helper。"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import bootloader_coverage as bc  # noqa: E402
import supplier_package as sp  # noqa: E402
from test_bootloader_coverage import NAMES, inv_of  # noqa: E402
from test_uefi_bundled import grype_json, make_uefi, put_grype, report  # noqa: E402


def rows_of(rep):
    d = json.loads((rep / "vulnerability-rows.json").read_text(encoding="utf-8"))
    return d["rows"] if isinstance(d, dict) else d


def test_without_coverage_files_report_has_no_new_section_or_field(tmp_path):
    u = make_uefi(tmp_path)
    put_grype(u, grype_json())
    _, rep, _ = report(tmp_path, u)
    assert "Boot firmware coverage" not in (rep / "sbom.md").read_text(encoding="utf-8")
    assert not any("uefi_build_check" in r for r in rows_of(rep))


def test_sbom_md_and_rows_get_coverage_and_check(tmp_path):
    res = tmp_path / "res"
    res.mkdir(parents=True)
    cov = bc.build_coverage(inv_of(NAMES), [], {"status": "OK"}, None, "rootfs")
    (res / "bootloader-coverage.json").write_text(json.dumps(cov))
    (tmp_path / "uefi-binary-check.json").write_text(json.dumps({"schema": bc.CHECK_SCHEMA, "counts": {"MATCH": 1, "MISMATCH": 0, "NOT_ASSESSED": 1}}))
    u = make_uefi(tmp_path)
    put_grype(u, grype_json())
    _, rep, _ = report(tmp_path, u)
    sbom_md = (rep / "sbom.md").read_text(encoding="utf-8")
    assert "### Boot firmware coverage" in sbom_md and "no component-level scan" in sbom_md
    assert "Flashed UEFI images compared with the scanned UEFI source" in sbom_md
    uefi_rows = [r for r in rows_of(rep) if "UEFI" in str(r.get("component"))]
    assert uefi_rows and all("not a bit-for-bit comparison" in r["uefi_build_check"] for r in uefi_rows)


def test_supplier_sbom_summary_section_only_when_given():
    ctx = {"product": "P 1", "supplier": "S", "now": "2026-11-11", "customer": "C", "artifact": {}, "absent_reason": {}}

    def table(h, r):
        return "\n".join(["|".join(h)] + ["|".join(str(c) for c in x) for x in r])

    without = sp.sbom_summary({}, ctx, table, {"sbom.cdx.json"}, {"components": []})
    assert "Boot firmware coverage" not in without
    ctx["artifact"] = {"boot_firmware_text": "TEXT-BLOCK"}
    with_ = sp.sbom_summary({}, ctx, table, {"sbom.cdx.json"}, {"components": []})
    assert with_.startswith(without.rstrip("\n")) and "## Boot firmware coverage\n\nTEXT-BLOCK" in with_
