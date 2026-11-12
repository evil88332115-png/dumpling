"""support_check.py：產品支援期 vs 元件維護期（資料表用測試自己產生的小表；另檢查 repo 內建的資料表格式）。"""
import datetime
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import support_check as sc  # noqa: E402
from test_cra_report import MIN_CFG, SBOM, make_project, make_scan, run, write_json  # noqa: E402

TODAY = datetime.date(2026, 11, 3)
TABLE = {"schema": sc.SCHEMA, "max_age_days": 180, "entries": [
    {"id": "os", "name": "Example OS 24.04", "match": [{"type": "operating-system", "name": "ubuntu", "version_prefix": "24.04"}],
     "phases": [{"name": "standard", "end": "2029-05"}, {"name": "extended", "end": "2034-05", "requires": "Pro"}],
     "sources": ["https://example.com/os"], "checked": "2026-11-01"},
    {"id": "bsp", "name": "Example BSP 39", "match": [{"name": "nvidia-l4t-core", "version_prefix": "39."}],
     "phases": [{"name": "vendor maintenance", "end": None}], "note": "not published", "sources": ["https://example.com/bsp"],
     "checked": "2026-11-01"},
    {"id": "upstream", "name": "Upstream kernel 6.8", "informational": True,
     "match": [{"name_regex": "^nvidia-l4t-kernel$", "version_prefix": "6.8."}],
     "phases": [{"name": "upstream", "end": "2024-05"}], "sources": ["https://example.com/kernel"], "checked": "2026-11-01"},
]}
BOM_OS = {"components": [{"type": "operating-system", "name": "ubuntu", "version": "24.04"}]}
BOM_JETSON = {"components": [{"type": "operating-system", "name": "ubuntu", "version": "24.04"},
                             {"type": "library", "name": "nvidia-l4t-core", "version": "39.2.1-20260101"},
                             {"type": "library", "name": "nvidia-l4t-kernel", "version": "6.8.12-tegra-39.2.1-20260101"}]}


def chk(bom, end=None, subs=None, table=TABLE, today=TODAY):
    sup = {}
    if end:
        sup["end_date"] = end
    if subs is not None:
        sup["subscriptions"] = subs
    return sc.check(bom, {"support": sup}, table, "0" * 64, today)


def test_covers_and_ends_before():
    assert chk(BOM_OS, "2029-05")["status"] == "OK"
    r = chk(BOM_OS, "2031-12")
    assert r["status"] == "ATTENTION" and "Example OS 24.04: ends before the product support period (2029-05)" in r["reasons"]
    # 付費維護有設定時才算進去
    assert chk(BOM_OS, "2031-12", ["Pro"])["status"] == "OK"
    assert chk(BOM_OS, "2031-12", ["Pro"])["entries"][0]["end"] == "2034-05"


def test_unpublished_end_and_informational():
    r = chk(BOM_JETSON, "2029-05")
    e = {x["id"]: x for x in r["entries"]}
    assert e["bsp"]["verdict"] == "end of maintenance not published" and e["upstream"]["informational"]
    assert r["status"] == "ATTENTION" and not any("Upstream" in x for x in r["reasons"])   # 上游只列出，不影響狀態
    assert e["upstream"]["verdict"] == "ends before the product support period"


def test_not_assessed_cases():
    r = chk(BOM_OS)
    assert r["status"] == "NOT_ASSESSED" and any("support.end_date" in x for x in r["reasons"])
    r = chk({"components": [{"type": "library", "name": "zlib", "version": "1"}]}, "2029-05")
    assert r["status"] == "NOT_ASSESSED" and "does not mean" in r["reasons"][0]
    assert chk(None, "2029-05")["status"] == "NOT_ASSESSED"


def test_stale_table():
    r = chk(BOM_OS, "2029-05", today=datetime.date(2027, 6, 1))
    assert r["status"] == "ATTENTION" and r["table"]["stale"] == ["os"]


@pytest.mark.parametrize("change,msg", [
    (lambda t: t.update(schema="x"), "schema"),
    (lambda t: t["entries"][0].update(id="bsp"), "id"),
    (lambda t: t["entries"][0]["phases"][0].update(end="2029-5"), "phases"),
    (lambda t: t["entries"][0].update(sources=["http://x"]), "sources"),
    (lambda t: t["entries"][0].update(checked="2026-13-01"), "checked"),
    (lambda t: t["entries"][0].update(match=[{"vendor": "x"}]), "match"),
    (lambda t: t["entries"][0].update(match=[{"name_regex": "("}]), "name_regex"),
    (lambda t: t.update(max_age_days=0), "max_age_days"),
    (lambda t: t["entries"][0].update(coverage=["main"]), "coverage"),
])
def test_table_errors(tmp_path, change, msg):
    t = json.loads(json.dumps(TABLE))
    change(t)
    p = tmp_path / "t.json"
    p.write_text(json.dumps(t), encoding="utf-8")
    with pytest.raises(sc.TableError, match=msg):
        sc.load_table(p)
    r = sc.run(BOM_OS, {"support": {"end_date": "2029-05"}}, TODAY, p)
    assert r["status"] == "FAIL" and "FAIL" in sc.section(r, sc._table)


def test_builtin_table_valid_and_sourced():
    t, sha = sc.load_table()
    assert len(sha) == 64 and {e["id"] for e in t["entries"]} >= {"ubuntu-24.04", "jetson-linux-r39", "linux-6.8-upstream"}
    for e in t["entries"]:
        assert e["sources"] and e["checked"]


def test_section_text():
    md = sc.section(chk(BOM_JETSON, "2031-12"), sc._table)
    assert "**Support period check: ATTENTION**" in md and "| Upstream kernel 6.8 (for information) |" in md
    assert "https://example.com/bsp (2026-11-01)" in md and "Example BSP 39: not published" in md


def test_cli(tmp_path):
    write_json(tmp_path / "s.json", BOM_OS)
    write_json(tmp_path / "c.json", {"support": {"end_date": "2029-05"}})
    write_json(tmp_path / "t.json", TABLE)
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "support_check.py"), "--sbom", str(tmp_path / "s.json"),
                        "--config", str(tmp_path / "c.json"), "--table", str(tmp_path / "t.json"), "--today", "2026-11-03"],
                       capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.startswith("SUPPORT-CHECK\tOK")
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "support_check.py"), "--sbom", "x", "--config", "y", "--today", "3.11.2026"],
                       capture_output=True, text=True)
    assert r.returncode == 64


def test_cra_report_section_and_summary(tmp_path):
    sbom = json.loads(json.dumps(SBOM))       # 共用的假 SBOM 有 ubuntu 24.04
    r, s, rep = run(make_project(tmp_path / "p", dict(MIN_CFG, support={"end_date": "2031-12"})), make_scan(tmp_path / "scan", sbom=sbom))
    assert r.returncode in (0, 2), r.stdout + r.stderr
    assert s["support_check"]["status"] == "ATTENTION"
    md = (rep / "technical-documentation.md").read_text(encoding="utf-8")
    assert "**Support period check: ATTENTION**" in md and "Ubuntu 24.04 LTS: ends before the product support period (2029-05)" in md


def test_cra_report_old_template_warns(tmp_path):
    proj = make_project(tmp_path / "p", MIN_CFG, templates={"technical-documentation": "# TD {{ product.name }}\n"})
    _, s, _ = run(proj, make_scan(tmp_path / "scan"))
    assert any("text.support_check" in w for w in s["config_warnings"]) and s["support_check"]["status"] == "NOT_ASSESSED"
    # role supplier：沒有技術文件 → 不提醒範本，summary.json 照樣有結果
    proj = make_project(tmp_path / "q", dict(MIN_CFG, role="supplier"), templates={"technical-documentation": "# TD {{ product.name }}\n"})
    r, s, _ = run(proj, make_scan(tmp_path / "scan2"))
    assert not any("text.support_check" in w for w in s["config_warnings"]) and s["support_check"]["status"] == "NOT_ASSESSED"
    assert "支援期檢查 NOT_ASSESSED" in r.stdout


FAM_TABLE = dict(TABLE, families=[{"name": "operating system", "match": {"type": "operating-system"}},
                                  {"name": "Jetson Linux", "match": {"name": "nvidia-l4t-core"}}])


def test_release_not_in_table_is_not_assessed():
    bom = {"components": [{"type": "operating-system", "name": "ubuntu", "version": "24.04"},
                          {"type": "library", "name": "nvidia-l4t-core", "version": "38.4.0-20250101"},
                          {"type": "operating-system", "name": "debian", "version": "12"}]}
    r = chk(bom, "2029-05", table=FAM_TABLE)
    assert r["status"] == "NOT_ASSESSED" and sorted(r["not_in_table"]) == ["debian 12", "nvidia-l4t-core 38.4.0-20250101"]
    assert "not in the support lifecycle table" in r["reasons"][0]


def test_informational_match_does_not_cover_family():
    t = dict(TABLE, families=[{"name": "kernel", "match": {"name": "nvidia-l4t-kernel"}}])
    bom = {"components": [{"type": "operating-system", "name": "ubuntu", "version": "24.04"},
                          {"type": "library", "name": "nvidia-l4t-kernel", "version": "6.8.12-tegra-39.2.1"}]}
    assert chk(bom, "2029-05", table=t)["not_in_table"] == ["nvidia-l4t-kernel 6.8.12-tegra-39.2.1"]


def test_scope_text_on_ok_and_date_recorded():
    r = chk(BOM_OS, "2029-05")
    md = sc.section(r, sc._table)
    assert r["status"] == "OK" and r["today"] == "2026-11-03"
    assert "only components that are in the lifecycle table (3 entries) were compared" in md and "checked on 2026-11-03" in md


def test_subscription_name_mismatch_and_future_date():
    r = chk(BOM_OS, "2029-05", ["pro"])
    assert r["status"] == "ATTENTION" and any("not used by any lifecycle entry" in x for x in r["reasons"])
    t = json.loads(json.dumps(TABLE))
    t["entries"][0]["checked"] = "2099-01-01"
    r = chk(BOM_OS, "2029-05", table=t)
    assert r["status"] == "ATTENTION" and r["table"]["future"] == ["os"]


def test_nested_components_matched():
    bom = {"components": [{"type": "application", "name": "x", "components": [{"type": "operating-system", "name": "ubuntu", "version": "24.04.1"}]}]}
    assert chk(bom, "2029-05")["entries"][0]["id"] == "os"


def test_builtin_table_matches_real_sbom_shapes():
    """Syft 對 Jetson rootfs 與 Ubuntu x86 的元件形狀（名稱、版本格式）。"""
    t, sha = sc.load_table()
    bom = {"components": [{"type": "operating-system", "name": "ubuntu", "version": "24.04"},
                          {"type": "library", "name": "nvidia-l4t-core", "version": "39.2.1-20260801000000"},
                          {"type": "library", "name": "nvidia-l4t-kernel", "version": "6.8.12-tegra-39.2.1-20260801000000"},
                          {"type": "library", "name": "linux-kernel", "version": "6.8.12-tegra"},
                          {"type": "library", "name": "linux-image-6.8.0-45-generic", "version": "6.8.0-45.45"}]}
    r = sc.check(bom, {"support": {"end_date": "2029-05"}}, t, sha, TODAY)
    ids = {x["id"] for x in r["entries"]}
    assert ids == {"ubuntu-24.04", "ubuntu-24.04-kernel-6.8", "jetson-linux-r39", "linux-6.8-tegra", "linux-6.8-upstream"}
    assert not r["not_in_table"]
    up = next(x for x in r["entries"] if x["id"] == "linux-6.8-upstream")
    assert "linux-image-6.8.0-45-generic 6.8.0-45.45" in up["matched"] and r["status"] == "ATTENTION"   # R39 沒有公開維護期
    r38 = sc.check({"components": [{"type": "library", "name": "nvidia-l4t-core", "version": "38.4.0-1"}]},
                   {"support": {"end_date": "2029-05"}}, t, sha, TODAY)
    assert [x["id"] for x in r38["entries"]] == ["jetson-linux-r38"]
    r36 = sc.check({"components": [{"type": "library", "name": "nvidia-l4t-core", "version": "36.4.3-1"}]},
                   {"support": {"end_date": "2029-05"}}, t, sha, TODAY)
    assert r36["status"] == "NOT_ASSESSED" and r36["not_in_table"] == ["nvidia-l4t-core 36.4.3-1"]


def test_cra_report_fail_and_no_sbom(tmp_path, monkeypatch):
    r, s, rep = run(make_project(tmp_path / "p", dict(MIN_CFG, support={"end_date": "2029-05"})), make_scan(tmp_path / "scan", sbom=None))
    assert s["support_check"]["status"] == "NOT_ASSESSED" and "no SBOM" in s["support_check"]["reasons"]
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    res = sc.run(BOM_OS, {}, TODAY, bad)
    assert set(res) >= {"status", "today", "subscriptions", "entries", "not_in_table", "table"} and res["table"]["sha256"] is None


def test_hwe_and_other_flavours_not_matched_as_noble_ga():
    t, sha = sc.load_table()
    for name, ver in (("linux-image-6.8.0-52-generic", "6.8.0-52.53~22.04.1"), ("linux-image-6.8.0-1012-oem", "6.8.0-1012.12"),
                      ("linux-image-6.8.0-1010-nvidia-tegra", "6.8.0-1010.10")):
        r = sc.check({"components": [{"type": "library", "name": name, "version": ver}]}, {"support": {"end_date": "2029-05"}}, t, sha, TODAY)
        assert "ubuntu-24.04-kernel-6.8" not in {x["id"] for x in r["entries"]}, name
        assert r["status"] == "NOT_ASSESSED" and r["not_in_table"] == [f"{name} {ver}"]


def test_legacy_needs_pro():
    t = json.loads(json.dumps(TABLE))
    t["entries"][0]["phases"].append({"name": "legacy", "end": "2039-04", "requires": "Legacy"})
    assert chk(BOM_OS, "2031-12", ["Legacy"], table=t)["entries"][0]["end"] == "2029-05"
    assert chk(BOM_OS, "2031-12", ["Pro", "Legacy"], table=t)["entries"][0]["end"] == "2039-04"


def test_end_date_format_message():
    r = sc.check(BOM_OS, {"support": {"end_date": "2029-05-31"}}, TABLE, "0" * 64, TODAY)
    assert r["status"] == "NOT_ASSESSED" and any("not in YYYY-MM format: 2029-05-31" in x for x in r["reasons"])


def test_cra_report_sees_flash_package_jetson_linux(tmp_path):
    """刷機包的「NVIDIA Jetson Linux」邏輯元件只在產品 SBOM（firmware_bom 加進去的），掃描器 SBOM 沒有 → 支援期檢查要讀產品 SBOM。"""
    from test_firmware_bom import flash_result
    proj, scan = flash_result(tmp_path, cfg=dict(MIN_CFG, support={"end_date": "2031-12"}))
    r, s, _ = run(proj, scan)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    hit = [e for e in s["support_check"]["entries"] if e["id"] == "jetson-linux-r39"]
    assert hit and any("NVIDIA Jetson Linux" in str(c) for c in hit[0]["matched"]), s["support_check"]


def test_ubuntu_coverage_stated(tmp_path):
    """Ubuntu 24.04 那列「維護到產品支援期結束」只涵蓋 main／restricted：文件與 summary 都寫明 universe 要 Pro、第三方套件沒有評估。"""
    t, sha = sc.load_table()
    bom = {"components": [{"type": "operating-system", "name": "ubuntu", "version": "24.04"},
                          {"type": "library", "name": "ros-jazzy-foo", "version": "1.0"}, {"type": "library", "name": "docker-ce", "version": "27.0"}]}
    r = sc.check(bom, {"support": {"end_date": "2029-05"}}, t, sha, TODAY)
    u = next(x for x in r["entries"] if x["id"] == "ubuntu-24.04")
    assert "main and restricted" in u["coverage"] and "Ubuntu Pro (ESM-Apps)" in u["coverage"]
    md = sc.section(r, sc._table)
    assert "What a match covers:" in md and md.index("What a match covers:") < md.index("| Component |")
    assert "not maintained by Canonical and were not assessed" in md
    # coverage 沒寫的項目不出現這段
    assert "What a match covers:" not in sc.section(chk(BOM_JETSON, "2031-12"), sc._table)


def test_unsigned_kernel_image_is_not_silently_skipped():
    t, sha = sc.load_table()
    c = {"type": "library", "name": "linux-image-unsigned-6.8.0-45-generic", "version": "6.8.0-45.45"}
    r = sc.check({"components": [c]}, {"support": {"end_date": "2029-05"}}, t, sha, TODAY)
    assert r["status"] == "NOT_ASSESSED" and r["not_in_table"] == ["linux-image-unsigned-6.8.0-45-generic 6.8.0-45.45"]
