"""韌體 SBOM 的廠商公告規則表（fw_advisory_rules.py、x86_firmware.py 的「規則表比對」）：
- schema 驗證：每一條規則正反兩面（id fullmatch、元件固定清單、版本格式依元件、不認得的欄位每一層都拒收、日期、網址、review、重複）。
- 版本比較函式：AGESA（依規則表的順序序列）、CSME／FSP（點分數字，版本線）、PSP（byte）、AMD 微碼（整數）、BIOS 版本；邊界、順序不確定、格式怪異。
- 各元件的比對結果與整合：affected > NOT_ASSESSED > not-affected、no-rule、AMI 一律 NOT_ASSESSED。
- 狀態規則：affected 一定讓狀態變 ATTENTION（即使規則是初審）；not-affected 不能讓狀態變好；整張表壞掉＝所有元件 NOT_ASSESSED 加 ATTENTION。
- SBOM property、fw-inventory.md 的文字（不能出現「不受影響」「安全」「不適用」）、firmware_advisory_cell。
- 進 repo 的規則表：schema 合格、sha256 與程式固定值一致、第一批公告的關鍵欄位。
全部不連網。"""
import copy
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import fw_advisory_rules as fr  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_amd_psp import good_image, put  # noqa: E402
from test_x86_firmware import spi_image  # noqa: E402

REPO = HERE.parents[2]
CELL = REPO / "pipeline" / "lib" / "firmware_advisory_cell.py"
DATA = HERE.parent / "data" / "fw-advisory-rules.json"
ROLE = "韌體分析（C2 角色）初審"
AMD = "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-%s.html"
INTEL = "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-%s.html"
AMI_PDF = "https://go.ami.com/hubfs/Security%20Advisories/2026/AMI-SA-2026001.pdf"
UPDATED = "2026-11-14"
FORBIDDEN = ("不受影響", "安全", "不適用")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cell = _load("fw_advisory_cell_for_rules_test", CELL)


# ---------- 合成規則表 ----------

def seq(*items):
    return [{"version": v, "listed": d, "source": AMD % "7014"} for v, d in items]


AM4 = seq(("1.2.0.8", "2022-07-29"), ("1.2.0.9", "2023-01-24"), ("1.2.0.B", "2023-08-25"), ("1.2.0.C", "2024-02-07"), ("1.2.0.Ca", "2024-03-14"),
          ("1.2.0.Cb", "2024-07-30"), ("1.2.0.Cc", "2024-08-16"), ("1.2.0.D", "2024-11-07"), ("1.2.0.F", "2025-04-30"), ("1.2.0.10", "2025-10-31"))
AM5 = seq(("1.0.0.7a", "2023-05-05"), ("1.0.8.0", "2023-08-25"), ("1.2.0.1", "2024-08-07"))


def review(state="preliminary", **kw):
    r = {"state": state, "preliminary_by": ROLE, "preliminary_at": "2026-11-13"}
    if state == "confirmed":
        r.update(confirmed_by="產品負責人", confirmed_at="2026-11-14")
    r.update(kw)
    return r


def rule(rid="AMD-SB-7014", match=None, vendor="AMD", state="preliminary", url=None, **kw):
    r = {"id": rid, "vendor": vendor, "title": "Test advisory", "published": "2026-01-01", "cves": ["CVE-2026-0001"],
         "sources": [{"url": url or AMD % rid[-4:], "read_at": UPDATED, "verification": "direct"}],
         "match": match if match is not None else [{"component": "amd_agesa", "family": "ComboAM4v2PI", "fixed_in": "1.2.0.Cb"}],
         "review": review(state)}
    r.update(kw)
    return r


def doc(*rules, orderings=None):
    return {"schema": fr.SCHEMA, "table_updated": UPDATED,
            "orderings": copy.deepcopy(orderings if orderings is not None else
                                       [{"family": "ComboAM4v2PI", "component": "amd_agesa", "sequence": AM4},
                                        {"family": "ComboAM5PI", "component": "amd_agesa", "sequence": AM5}]),
            "rules": list(rules) or [rule()]}


def write(tmp_path, d, name="rules.json"):
    p = tmp_path / name
    p.write_text(d if isinstance(d, str) else json.dumps(d), encoding="utf-8")
    return p


def build(tmp_path, d, name="rules.json"):
    """dict → Table（sha256 用檔案自己的，只測 schema）。"""
    import hashlib
    p = write(tmp_path, d, name)
    return fr.load(p, expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest())


def invalid(tmp_path, d, match=None):
    with pytest.raises(fr.TableError) as e:
        build(tmp_path, d)
    assert e.value.reason == "table-invalid", e.value.detail
    if match:
        assert match in e.value.detail


def ok(tmp_path, d):
    return build(tmp_path, d)


# ---------- schema：id、廠商、元件 ----------

@pytest.mark.parametrize("rid,vendor", [("AMD-SB-7014", "AMD"), ("AMD-SB-70145", "AMD"), ("INTEL-SA-01372", "Intel"), ("AMI-SA-2026001", "AMI")])
def test_valid_ids(tmp_path, rid, vendor):
    comp = {"AMD": {"component": "amd_psp", "psp_type": 1, "fixed_in": "00.09.00.7f"}, "Intel": {"component": "intel_csme", "line": "18.1", "fixed_in": "18.1.21"},
            "AMI": {"component": "ami_core", "product": "Aptio V"}}[vendor]
    url = {"AMD": AMD % rid.split("-")[-1], "Intel": INTEL % rid.split("-")[-1], "AMI": AMI_PDF.replace("2026001", rid.split("-")[-1])}[vendor]
    ok(tmp_path, doc(rule(rid, [comp], vendor, url=url)))


@pytest.mark.parametrize("rid,vendor", [
    ("AMD-SB-701", "AMD"), ("AMD-SB-701456", "AMD"), ("amd-sb-7014", "AMD"), ("AMD-SB-7014x", "AMD"), (" AMD-SB-7014", "AMD"), ("AMD-SB-7014\n", "AMD"),
    ("AMD-SB-701４", "AMD"), ("INTEL-SA-1372", "Intel"), ("INTEL-SA-013720", "Intel"), ("INTEL-SA-0137a", "Intel"), ("INTEL-SA-01372\n", "Intel"),
    ("AMI-SA-202601", "AMI"), ("AMI-SA-20260011", "AMI"), ("AMI-SA-2026001\n", "AMI"), ("AMD-SB-7014", "Intel"), ("INTEL-SA-01372", "AMD"), ("AMD-SB-7014", "NVIDIA"),
    ("", "AMD"), (7014, "AMD")])
def test_bad_ids_and_vendor_mismatch(tmp_path, rid, vendor):
    invalid(tmp_path, doc(rule(rid, vendor=vendor, url=AMD % "7014")))


def test_component_must_be_in_the_fixed_list_and_match_the_vendor(tmp_path):
    for comp in fr.COMPONENTS:
        assert comp in ("amd_agesa", "amd_psp", "amd_microcode", "intel_csme", "intel_fsp", "ami_core", "bios_image")
    invalid(tmp_path, doc(rule(match=[{"component": "amd_bios", "fixed_in": "1"}])), "component")
    invalid(tmp_path, doc(rule(match=[{"component": "AMD_AGESA", "family": "ComboAM4v2PI", "fixed_in": "1.2.0.Cb"}])), "component")
    invalid(tmp_path, doc(rule(match=[{"fixed_in": "1"}])), "component")
    invalid(tmp_path, doc(rule(match=[{"component": ["amd_agesa"]}])), "component")
    invalid(tmp_path, doc(rule(match=[{"component": "intel_csme", "line": "14.0", "fixed_in": "14.0.45"}])), "Intel")          # AMD 公告不能有 Intel 元件
    invalid(tmp_path, doc(rule("INTEL-SA-01372", [{"component": "amd_psp", "psp_type": 1, "fixed_in": "00.00.00.01"}], "Intel", url=INTEL % "01372")), "AMD")
    ok(tmp_path, doc(rule(match=[{"component": "bios_image", "name_prefix": "PRIME", "fixed_in": "3404"}])))                     # bios_image 不分廠商


# ---------- schema：不認得的欄位每一層都拒收 ----------

def with_extra(d, path):
    d = copy.deepcopy(d)
    node = d
    for k in path:
        node = node[k]
    node["extra_field"] = "x"
    return d


@pytest.mark.parametrize("path", [(), ("orderings", 0), ("orderings", 0, "sequence", 0), ("rules", 0), ("rules", 0, "sources", 0), ("rules", 0, "match", 0),
                                  ("rules", 0, "review")])
def test_unknown_fields_are_rejected_at_every_level(tmp_path, path):
    d = doc(rule())
    ok(tmp_path, d)
    invalid(tmp_path, with_extra(d, path), "unknown field")


CONDITIONS = [
    {"component": "amd_agesa", "family": "ComboAM4v2PI", "fixed_in": "1.2.0.Cb"},
    {"component": "amd_psp", "psp_type": 1, "fixed_in": "00.09.00.7f"},
    {"component": "amd_microcode", "equiv_id": "0x8082", "fixed_in": "0x0800820d"},
    {"component": "intel_csme", "line": "14.0", "fixed_in": "14.0.45"},
    {"component": "intel_fsp", "line": "9.0", "fixed_in": "9.0.123.32"},
    {"component": "ami_core", "product": "Aptio V"},
    {"component": "bios_image", "name_prefix": "PRIME", "fixed_in": "3404"},
]


def cond_rule(c):
    vendor = {"amd_": "AMD", "inte": "Intel", "ami_": "AMI"}.get(c["component"][:4], "AMD")
    rid = {"AMD": "AMD-SB-7014", "Intel": "INTEL-SA-01372", "AMI": "AMI-SA-2026001"}[vendor]
    url = {"AMD": AMD % "7014", "Intel": INTEL % "01372", "AMI": AMI_PDF}[vendor]
    return rule(rid, [c], vendor, url=url)


@pytest.mark.parametrize("c", CONDITIONS, ids=[c["component"] for c in CONDITIONS])
def test_each_condition_kind_accepts_its_fields_and_rejects_extra_and_missing(tmp_path, c):
    ok(tmp_path, doc(cond_rule(c)))
    invalid(tmp_path, doc(cond_rule({**c, "other": 1})), "unknown field")
    ok(tmp_path, doc(cond_rule({**c, "note": "a note"})))
    invalid(tmp_path, doc(cond_rule({**c, "note": "x" * 601})), "note")
    invalid(tmp_path, doc(cond_rule({**c, "note": "a\nb"})), "note")
    for k in list(c):
        if k not in ("component", "fixed_in") or (k == "fixed_in" and c["component"] != "ami_core"):
            if k == "component":
                continue
            invalid(tmp_path, doc(cond_rule({kk: v for kk, v in c.items() if kk != k})))


# ---------- schema：版本格式依元件 ----------

def test_agesa_conditions(tmp_path):
    ok(tmp_path, doc(rule(match=[{"component": "amd_agesa", "family": "ComboAM4v2PI", "fixed_in": "1.2.0.Cb", "affected_from": "1.2.0.B"}])))
    ok(tmp_path, doc(rule(match=[{"component": "amd_agesa", "family": "comboam4v2pi", "fixed_in": "1.2.0.cb"}])))            # 不分大小寫
    for bad, why in [({"family": "ComboAM6PI"}, "no ordering"), ({"fixed_in": "1.2.0.Zz"}, "not in the ordering"), ({"fixed_in": "1.2.0Cb"}, "bad format"),
                     ({"fixed_in": "1.2.0"}, "bad format"), ({"fixed_in": "1.2.0.B", "affected_from": "1.2.0.Cb"}, "after fixed_in"),
                     ({"affected_from": "1.2.0.Zz"}, "not in the ordering"), ({"family": "Combo AM4"}, "bad format"), ({"family": "AM"}, "bad format"),
                     ({"fixed_in": "1.2.0.Cb\n"}, "bad format"), ({"fixed_in": 12}, "bad format")]:
        invalid(tmp_path, doc(rule(match=[{"component": "amd_agesa", "family": "ComboAM4v2PI", "fixed_in": "1.2.0.Cb", **bad}])), None)


def test_psp_microcode_csme_fsp_bios_ami_formats(tmp_path):
    def one(c, rid="AMD-SB-7014", vendor="AMD", url=None):
        return doc(rule(rid, [c], vendor, url=url or AMD % rid[-4:]))
    ok(tmp_path, one({"component": "amd_psp", "psp_type": 0, "fixed_in": "00.00.00.00"}))
    ok(tmp_path, one({"component": "amd_psp", "psp_type": 255, "fixed_in": "ff.ff.ff.ff"}))
    for bad in ({"psp_type": 256}, {"psp_type": -1}, {"psp_type": True}, {"psp_type": "1"}, {"psp_type": 1.0}, {"fixed_in": "00.09.00"}, {"fixed_in": "00.09.00.7F"},
                {"fixed_in": "0.9.0.7f"}, {"fixed_in": "00.09.00.7f.00"}, {"fixed_in": "g0.09.00.7f"}):
        invalid(tmp_path, one({"component": "amd_psp", "psp_type": 1, "fixed_in": "00.09.00.7f", **bad}))
    ok(tmp_path, one({"component": "amd_microcode", "cpuid": "00A20F10", "fixed_in": "0x0a20102b"}))
    for bad in ({"cpuid": "00a20f10"}, {"cpuid": "A20F10"}, {"cpuid": "0x00A20F10"}, {"equiv_id": "0x8082"}, {"fixed_in": "0x0a20102"}, {"fixed_in": "0X0A20102B"},
                {"fixed_in": "0a20102b"}):
        c = {"component": "amd_microcode", "cpuid": "00A20F10", "fixed_in": "0x0a20102b", **bad}
        invalid(tmp_path, one(c))
    invalid(tmp_path, one({"component": "amd_microcode", "fixed_in": "0x0a20102b"}), "exactly one")
    invalid(tmp_path, one({"component": "amd_microcode", "fixed_in": "0x0a20102b", "cpuid": "00A20F10", "equiv_id": "0x8082"}), "exactly one")
    ok(tmp_path, one({"component": "amd_microcode", "equiv_id": "0xa210", "fixed_in": "0x0a20102b"}))
    invalid(tmp_path, one({"component": "amd_microcode", "equiv_id": "0xA210", "fixed_in": "0x0a20102b"}))
    intel = lambda c: one(c, "INTEL-SA-01372", "Intel", INTEL % "01372")      # noqa: E731
    ok(tmp_path, intel({"component": "intel_csme", "line": "18.1", "fixed_in": "18.1.21"}))
    ok(tmp_path, intel({"component": "intel_csme", "line": "18.1", "fixed_in": "18.1.21.2000", "affected_from": "18.1.5"}))
    for bad in ({"line": "18"}, {"line": "18.1.2"}, {"fixed_in": "18.2.21"}, {"fixed_in": "18.10.21"}, {"fixed_in": "18.1"}, {"fixed_in": "18.1.21.1.1"}, {"fixed_in": "18.1.x"},
                {"affected_from": "18.2.0"}, {"affected_from": "18.1.30"}, {"line": "18.1\n"}):
        invalid(tmp_path, intel({"component": "intel_csme", "line": "18.1", "fixed_in": "18.1.21", **bad}))
    ok(tmp_path, intel({"component": "intel_fsp", "line": "9.0", "fixed_in": "9.0.123.32"}))
    for bad in ({"fixed_in": "9.0.123"}, {"fixed_in": "9.2.123.32"}, {"line": "9"}, {"fixed_in": "9.0.123.32.1"}, {"affected_from": "9.0.200.1"}):
        invalid(tmp_path, intel({"component": "intel_fsp", "line": "9.0", "fixed_in": "9.0.123.32", **bad}))
    ami = lambda c: one(c, "AMI-SA-2026001", "AMI", AMI_PDF)      # noqa: E731
    ok(tmp_path, ami({"component": "ami_core", "product": "Aptio V", "fixed_in": "AptioV_5.044"}))
    invalid(tmp_path, ami({"component": "ami_core", "product": ""}))
    invalid(tmp_path, ami({"component": "ami_core", "product": "x\ty"}))
    invalid(tmp_path, ami({"component": "ami_core", "product": "Aptio V", "fixed_in": "a" * 201}))
    for bad in ({"fixed_in": "3404a"}, {"fixed_in": ""}, {"fixed_in": "1..2"}, {"name_prefix": ""}, {"name_prefix": "-x"}, {"name_prefix": "a b"}, {"name_prefix": "a" * 65}, {"fixed_in": "1.2.3.4.5"}):
        invalid(tmp_path, one({"component": "bios_image", "name_prefix": "PRIME", "fixed_in": "3404", **bad}))
    ok(tmp_path, one({"component": "bios_image", "name_prefix": "PRIME-B550M-A", "fixed_in": "3404.1"}))


# ---------- schema：日期、網址、review、重複、其他 ----------

def test_dates(tmp_path):
    for bad in ("2026-02-30", "2026-13-01", "26-01-01", "2026/01/01", "2026-1-1", "1999-01-01", "2101-01-01", "2026-01-01\n", "", None, 20260101):
        invalid(tmp_path, doc(rule(published=bad)))
        d = doc(rule())
        d["table_updated"] = bad
        invalid(tmp_path, d)
    ok(tmp_path, doc(rule(published="2026-11-14", revised="2026-11-14")))
    invalid(tmp_path, doc(rule(published="2026-11-15")), "published")
    invalid(tmp_path, doc(rule(published="2026-05-01", revised="2026-04-30")), "revised")
    invalid(tmp_path, doc(rule(published="2026-05-01", revised="2026-11-15")), "revised")
    d = doc(rule())
    d["rules"][0]["sources"][0]["read_at"] = "2026-11-15"
    invalid(tmp_path, d, "read_at")


def test_ordering_rules(tmp_path):
    base = [{"family": "ComboAM4v2PI", "component": "amd_agesa", "sequence": AM4}]
    ok(tmp_path, doc(orderings=base))
    d = copy.deepcopy(base)
    d[0]["sequence"][2]["listed"] = "2023-01-24"                                            # 與前一個相同日期：順序不能靠日期證明
    invalid(tmp_path, doc(orderings=d), "strictly increasing")
    d = copy.deepcopy(base)
    d[0]["sequence"][1]["listed"] = "2022-01-01"
    invalid(tmp_path, doc(orderings=d), "strictly increasing")
    d = copy.deepcopy(base)
    d[0]["sequence"][3]["version"] = "1.2.0.b"                                              # 不分大小寫重複
    invalid(tmp_path, doc(orderings=d), "duplicate version")
    invalid(tmp_path, doc(orderings=base + copy.deepcopy(base)), "duplicate family")
    d = copy.deepcopy(base)
    d[0]["sequence"] = d[0]["sequence"][:1]
    invalid(tmp_path, doc(orderings=d), "sequence")
    d = copy.deepcopy(base)
    d[0]["sequence"][0]["source"] = "https://example.invalid/amd-sb-7014.html"
    invalid(tmp_path, doc(orderings=d), "source")
    d = copy.deepcopy(base)
    d[0]["component"] = "intel_csme"
    invalid(tmp_path, doc(orderings=d), "component")
    d = copy.deepcopy(base)
    d[0]["sequence"][-1]["listed"] = "2026-11-15"
    invalid(tmp_path, doc(orderings=d), "after table_updated")
    d = copy.deepcopy(base)
    d[0]["sequence"][0]["version"] = "1.2.0"
    invalid(tmp_path, doc(orderings=d), "version")


@pytest.mark.parametrize("url,good", [
    (AMD % "7014", True), ("http://www.amd.com/en/resources/product-security/bulletin/amd-sb-7014.html", False),
    ("https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7014.html?x=1", False),
    ("https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7014.html#a", False),
    ("https://www.amd.com.evil.test/en/resources/product-security/bulletin/amd-sb-7014.html", False),
    ("https://evil.test/https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7014.html", False),
    ("https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7005.html", False),         # 與 id 對不上
    ("https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7014.html\n", False), ("", False), (None, False),
    (INTEL % "01372", False)])
def test_amd_source_urls(tmp_path, url, good):
    d = doc(rule())
    d["rules"][0]["sources"][0]["url"] = url
    if good:
        ok(tmp_path, d)
    else:
        invalid(tmp_path, d)


def test_intel_and_ami_source_urls(tmp_path):
    intel = lambda url: doc(rule("INTEL-SA-01372", [{"component": "intel_csme", "line": "18.1", "fixed_in": "18.1.21"}], "Intel", url=url))      # noqa: E731
    ok(tmp_path, intel(INTEL % "01372"))
    for bad in (INTEL % "01280", "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01372.html?wapkw=x",
                "https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01372.html", AMD % "7014"):
        invalid(tmp_path, intel(bad))
    ami = lambda *urls: doc(rule("AMI-SA-2026001", [{"component": "ami_core", "product": "Aptio V"}], "AMI", url=urls[0]) |      # noqa: E731
                            {"sources": [{"url": u, "read_at": UPDATED, "verification": "direct"} for u in urls]})
    ok(tmp_path, ami(AMI_PDF))
    ok(tmp_path, ami(AMI_PDF, fr.AMI_INDEX_URL))
    ok(tmp_path, ami("https://9443417.fs1.hubspotusercontent-na1.net/hubfs/9443417/Security%20Advisories/2024/AMI-SA-2026001.pdf"))
    invalid(tmp_path, ami(AMI_PDF.replace("2026001", "2026002")))
    invalid(tmp_path, ami(AMI_PDF, AMI_PDF))                                                      # 重複網址
    invalid(tmp_path, ami("https://go.ami.com/hubfs/Security%20Advisories/2026/AMI-SA-2026001.pdf?x"))
    amd_index = doc(rule()) | {}
    amd_index["rules"][0]["sources"][0]["url"] = fr.AMI_INDEX_URL
    invalid(tmp_path, amd_index)                                                                  # AMI 的索引頁只給 AMI 規則
    d = doc(rule())
    d["rules"][0]["sources"] = []
    invalid(tmp_path, d, "sources")
    d["rules"][0]["sources"] = [{"url": AMD % "7014", "read_at": UPDATED, "verification": "direct"}] * 2
    invalid(tmp_path, d, "duplicate url")


def test_review_rules(tmp_path):
    ok(tmp_path, doc(rule(state="confirmed")))
    ok(tmp_path, doc(rule(state="preliminary")))
    ok(tmp_path, doc(rule() | {"review": review("confirmed", confirmed_at="2026-11-13")}))                  # 確認日可以等於初審日
    invalid(tmp_path, doc(rule() | {"review": review("preliminary", confirmed_by="x")}), "preliminary")
    invalid(tmp_path, doc(rule() | {"review": review("preliminary", confirmed_at="2026-11-14")}), "preliminary")
    invalid(tmp_path, doc(rule() | {"review": {"state": "confirmed", "preliminary_by": ROLE, "preliminary_at": "2026-11-13"}}), "confirmed")
    invalid(tmp_path, doc(rule() | {"review": review("confirmed", confirmed_at="2026-11-12")}), "between")
    invalid(tmp_path, doc(rule() | {"review": review("confirmed", confirmed_at="2026-11-15")}), "between")
    invalid(tmp_path, doc(rule() | {"review": review(preliminary_at="2026-11-15")}), "preliminary_at")
    for bad in ("draft", "Confirmed", "", None):
        invalid(tmp_path, doc(rule() | {"review": review(state=bad)}), "state")
    for role in ("a\u200bb", "a\u202eb", "a\x7fb", "a\u2028b", "a@example.com", "@everyone", "https://x.test", "mailto:x", "[x](y)", "x|y", "`x`", "<b>x</b>", "", "x" * 81, "a\nb", "a‮b", "x&amp;y"):
        invalid(tmp_path, doc(rule() | {"review": review(preliminary_by=role)}), "preliminary_by")
        invalid(tmp_path, doc(rule() | {"review": review("confirmed", confirmed_by=role)}), "confirmed_by")
    ok(tmp_path, doc(rule() | {"review": review(preliminary_by="產品負責人")}))


def test_duplicates_cves_and_sizes(tmp_path):
    invalid(tmp_path, doc(rule(), rule()), "duplicate id")
    ok(tmp_path, doc(rule(), rule("AMD-SB-7005")))
    invalid(tmp_path, doc(rule(cves=["CVE-2026-0001", "CVE-2026-0001"])), "cves")
    for bad in ("CVE-2026-1", "cve-2026-0001", "CVE-2026-0001\n", "CVE-26-0001", 5):
        invalid(tmp_path, doc(rule(cves=[bad])), "cves")
    invalid(tmp_path, doc(rule(cves="CVE-2026-0001")), "cves")
    ok(tmp_path, doc(rule(cves=[])))
    invalid(tmp_path, doc(rule(match=[])), "match")
    invalid(tmp_path, doc(rule(match=[CONDITIONS[0]] * 17)), "match")
    invalid(tmp_path, {**doc(), "rules": []}, "rules")
    invalid(tmp_path, {**doc(), "rules": "x"}, "rules")
    invalid(tmp_path, doc(rule(title="")), "title")
    invalid(tmp_path, doc(rule(title="a\nb")), "title")
    invalid(tmp_path, doc(rule(title="x" * 201)), "title")
    ok(tmp_path, doc(rule(title="Title with [brackets] and @name <b>")))                       # 標題是自由文字；報告一律經 md_esc
    invalid(tmp_path, doc(rule(note="x" * 601)), "note")
    ok(tmp_path, doc(rule(note="a note")))
    d = doc(rule())
    d["$comment"] = "x"
    ok(tmp_path, d)
    d["$comment"] = "a\nb"
    invalid(tmp_path, d, "$comment")


def test_schema_name_and_json_level_problems(tmp_path):
    d = doc()
    d["schema"] = "dumpling-fw-advisory-rules/2"
    invalid(tmp_path, d, "schema")
    d["schema"] = None
    invalid(tmp_path, d)
    for text in ("[]", "null", "5", '"x"'):
        with pytest.raises(fr.TableError) as e:
            build(tmp_path, text)
        assert e.value.reason == "table-invalid"
    for text in ("", "{", "\x00", "{'a': 1}", '{"schema": NaN}', '{"a": Infinity}'):
        with pytest.raises(fr.TableError) as e:
            build(tmp_path, text)
        assert e.value.reason == "table-unreadable", text
    p = write(tmp_path, '{"schema": "' + fr.SCHEMA + '", "schema": "x"}')                    # 重複的鍵
    import hashlib
    with pytest.raises(fr.TableError) as e:
        fr.load(p, expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    assert e.value.reason == "table-unreadable"
    deep = "[" * 100000
    with pytest.raises(fr.TableError):
        build(tmp_path, deep)


def test_load_failure_modes(tmp_path):
    import hashlib
    p = write(tmp_path, doc())
    sha = hashlib.sha256(p.read_bytes()).hexdigest()
    assert fr.load(p, expected_sha256=sha).sha256 == sha
    with pytest.raises(fr.TableError) as e:
        fr.load(p, expected_sha256="0" * 64)
    assert e.value.reason == "table-sha-mismatch"
    for bad in (tmp_path / "missing.json", tmp_path):
        with pytest.raises(fr.TableError) as e:
            fr.load(bad, expected_sha256=sha)
        assert e.value.reason == "table-unreadable"
    link = tmp_path / "link.json"
    link.symlink_to(p)
    with pytest.raises(fr.TableError) as e:
        fr.load(link, expected_sha256=sha)
    assert e.value.reason == "table-unreadable"
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (fr.MAX_TABLE + 1))
    with pytest.raises(fr.TableError) as e:
        fr.load(big, expected_sha256="0" * 64)
    assert e.value.reason == "table-unreadable"
    bad_utf8 = tmp_path / "u.json"
    bad_utf8.write_bytes(b"\xff\xfe{}")
    with pytest.raises(fr.TableError) as e:
        fr.load(bad_utf8, expected_sha256=hashlib.sha256(bad_utf8.read_bytes()).hexdigest())
    assert e.value.reason == "table-unreadable"
    assert fr.load_default()[0] is not None                                                   # repo 內的表


def test_removing_a_rule_changes_the_hash(tmp_path):
    """少一筆規則就是不同的檔案：固定的 sha256 會擋下（不會悄悄少算）。"""
    import hashlib
    d = json.loads(DATA.read_text(encoding="utf-8"))
    d["rules"].pop()
    p = write(tmp_path, d, "fewer.json")
    assert hashlib.sha256(p.read_bytes()).hexdigest() != fr.TABLE_SHA256
    with pytest.raises(fr.TableError) as e:
        fr.load(p)
    assert e.value.reason == "table-sha-mismatch"


# ---------- 版本比較函式 ----------

@pytest.fixture
def table(tmp_path):
    def mk(*rules, **kw):
        return build(tmp_path, doc(*rules, **kw))
    return mk


def agesa(table_, value, **cond):
    c = {"component": "amd_agesa", "family": "ComboAM4v2PI", "fixed_in": "1.2.0.Cb", **cond}
    return fr.evaluate_condition(table_, c, {"value": value})


def test_agesa_order_boundaries(table):
    t = table()
    for v in ("1.2.0.8", "1.2.0.9", "1.2.0.B", "1.2.0.C", "1.2.0.Ca"):
        assert agesa(t, f"ComboAM4v2PI {v}")["result"] == "affected", v
    for v in ("1.2.0.Cb", "1.2.0.Cc", "1.2.0.D", "1.2.0.F", "1.2.0.10"):
        assert agesa(t, f"ComboAM4v2PI {v}")["result"] == "not-affected", v
    assert agesa(t, "ComboAM4v2PI 1.2.0.CB")["result"] == "not-affected"                       # 不分大小寫
    assert agesa(t, "ComboAM4v2PI 1.2.0.ca")["result"] == "affected"
    assert agesa(t, "comboam4v2pi 1.2.0.Cb")["result"] == "not-affected"
    assert agesa(t, "ComboAM4v2PI_1.2.0.Cb")["result"] == "not-affected"                       # AMD 頁面有底線的寫法
    assert agesa(t, "ComboAM4v2PI 1.2.0.10", fixed_in="1.2.0.F")["result"] == "not-affected"     # 10 在 F 之後（AMD 的日期證明），不是字串順序
    assert agesa(t, "ComboAM4v2PI 1.2.0.F", fixed_in="1.2.0.10")["result"] == "affected"
    assert agesa(t, "ComboAM4v2PI 1.2.0.9", fixed_in="1.2.0.B")["result"] == "affected"
    assert agesa(t, "ComboAM4v2PI 1.2.0.B", fixed_in="1.2.0.B")["result"] == "not-affected"


def test_committed_am4_sequence_tail():
    """repo 內的表：1.2.0.12（AMD-SB-7064，2026-05-27）在 1.2.0.10 之後；1.2.0.11 沒有出現在 AMD 公告頁，不在序列裡 → 不猜。"""
    t, err = fr.load_default()
    assert err is None
    assert agesa(t, "ComboAM4v2PI 1.2.0.12", fixed_in="1.2.0.10")["result"] == "not-affected"
    assert agesa(t, "ComboAM4v2PI 1.2.0.10", fixed_in="1.2.0.12")["result"] == "affected"
    assert agesa(t, "ComboAM4v2PI 1.2.0.11", fixed_in="1.2.0.10")["reason"] == "agesa-order-unknown"


@pytest.mark.parametrize("value,reason", [
    ("ComboAM4v2PI 1.2.0.A", "agesa-order-unknown"),                 # 規則表的序列沒有 A（沒有 AMD 日期可證明位置）：不猜
    ("ComboAM4v2PI 1.2.0.E", "agesa-order-unknown"), ("ComboAM4v2PI 1.2.0.Cd", "agesa-order-unknown"), ("ComboAM4v2PI 1.2.0.6c", "agesa-order-unknown"),
    ("ComboAM4v2PI 1.1.0.B", "agesa-order-unknown"), ("ComboAM4v2PI 1.2.0.11", "agesa-order-unknown"),
    ("ComboAM4v2PI 1.2.0Cb", "version-unreadable"),                  # 少一個點
    ("ComboAM4v2PI 1.2.0", "version-unreadable"), ("ComboAM4v2PI", "version-unreadable"), ("1.2.0.B", "version-unreadable"), ("", "version-unreadable"),
    (None, "version-unreadable"), ("ComboAM4v2PI 1.2.0.B extra", "version-unreadable"), ("ComboAM4v2PI  1.2.0.B\x00", "version-unreadable"),
    ("ComboAM4v2PI 1.2.0.Bbbbbbb", "version-unreadable"), ("Combo AM4v2 PI 1.2.0.B", "version-unreadable"), (b"ComboAM4v2PI 1.2.0.B", "version-unreadable"),
    ("ComboAM4v2PI 1.2.0.B\n1.2.0.C", "version-unreadable")])
def test_agesa_unknown_order_and_odd_formats_are_not_assessed(table, value, reason):
    r = agesa(table(), value)
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", reason)


def test_agesa_family_mismatch_is_out_of_scope_and_affected_from(table):
    t = table()
    assert agesa(t, "ComboAM5PI 1.0.8.0")["result"] == fr.OUT                                  # 另一個 family 的規則不適用
    assert agesa(t, "RenoirPI-FP6 1.0.0.8")["result"] == "NOT_ASSESSED"                       # 名稱含 - 不是這個格式
    r = agesa(t, "ComboAM4v2PI 1.2.0.8", affected_from="1.2.0.B")
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "below-affected-from")
    assert agesa(t, "ComboAM4v2PI 1.2.0.B", affected_from="1.2.0.B")["result"] == "affected"
    assert agesa(t, "ComboAM4v2PI 1.2.0.Cb", affected_from="1.2.0.B")["result"] == "not-affected"
    assert fr.parse_agesa("ComboAM4v2PI 1.2.0.B") == ("ComboAM4v2PI", "1.2.0.B")
    assert fr.agesa_compare(["1.2.0.B", "1.2.0.C"], "1.2.0.C", "1.2.0.B") == 1
    assert fr.agesa_compare(["1.2.0.B", "1.2.0.C"], "1.2.0.D", "1.2.0.B") is None
    assert fr.agesa_index(["1.2.0.B"], "1.2.0.b") == 0


def csme(table_, version, line="14.0", fixed="14.0.45", basis="listed", **extra):
    c = {"component": "intel_csme", "line": line, "fixed_in": fixed, **{k: v for k, v in extra.items() if k == "affected_from"}}
    comp = {"version": version, "family": None, "family_conflict": None, "family_basis": basis}
    comp.update({k: v for k, v in extra.items() if k != "affected_from"})
    return fr.evaluate_condition(table_, c, comp)


def test_csme_boundaries_line_and_fields(table):
    t = table()
    assert csme(t, "14.0.44.9999")["result"] == "affected"
    assert csme(t, "14.0.45.0")["result"] == "not-affected"                                    # fixed_in 三段：只比前三段，build 不比
    assert csme(t, "14.0.45")["result"] == "not-affected"
    assert csme(t, "14.0.47.1558")["result"] == "not-affected"
    assert csme(t, "14.0.9.1")["result"] == "affected"                                         # 數字比，不是字串比（9 < 45）
    assert csme(t, "14.0.100.1")["result"] == "not-affected"
    assert csme(t, "14.1.47.1558")["result"] == fr.OUT and csme(t, "14.1.47.1558")["reason"] == "line-mismatch"
    assert csme(t, "14.10.1.1")["result"] == fr.OUT and csme(t, "1.14.0.1")["result"] == fr.OUT         # 版本線是整段比，不是前綴
    assert csme(t, "14.0.45.1000", fixed="14.0.45.2000")["result"] == "affected"                 # fixed_in 四段：比四段
    assert csme(t, "14.0.45.2000", fixed="14.0.45.2000")["result"] == "not-affected"
    r = csme(t, "14.0.45", fixed="14.0.45.2000")
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "version-too-short")
    assert csme(t, "14.0.40.1", affected_from="14.0.30")["result"] == "affected"
    r = csme(t, "14.0.20.1", affected_from="14.0.30")
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "below-affected-from")
    assert csme(t, "14.0.30.1", affected_from="14.0.30")["result"] == "affected"
    for bad in ("14.0", "14", "14.0.47.1558.1", "14.0.x.1", "14.0.47-1558", "v14.0.47", "", None, "14.0.47\n", " 14.0.47", "١٤.0.47.1", 14.047):
        r = csme(t, bad)
        assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "version-unreadable"), bad


def test_csme_family_rules(table):
    t = table()
    assert csme(t, "14.0.40.1", basis="inferred")["result"] == "affected"
    assert "inferred" in csme(t, "14.0.40.1", basis="inferred")["detail"]
    assert "inferred" not in csme(t, "14.0.40.1", basis="listed")["detail"]
    r = csme(t, "14.0.40.1", basis=None)
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "family-unknown")
    r = csme(t, "14.0.40.1", family="TXE", basis=None)
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "family-not-csme")
    assert csme(t, "14.0.40.1", family="CSME", basis="listed")["result"] == "affected"
    r = csme(t, "14.0.40.1", family_conflict=["CSME", "TXE"])
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "family-conflict")


def test_fsp_psp_ucode_bios_comparisons(table):
    t = table()
    fsp = lambda v, line="9.0", fixed="9.0.123.32": fr.evaluate_condition(t, {"component": "intel_fsp", "line": line, "fixed_in": fixed}, {"version": v})      # noqa: E731
    assert fsp("9.0.123.31")["result"] == "affected" and fsp("9.0.123.32")["result"] == "not-affected" and fsp("9.0.124.0")["result"] == "not-affected"
    assert fsp("9.0.99.200")["result"] == "affected"                                           # 數字比
    assert fsp("9.2.123.32")["result"] == fr.OUT
    for bad in ("9.0.123", "9.0.123.32.1", "x", None, ""):
        assert fsp(bad)["reason"] == "version-unreadable"
    psp = lambda ty, v, fixed="00.09.00.7f": fr.evaluate_condition(t, {"component": "amd_psp", "psp_type": 1, "fixed_in": fixed}, {"type": ty, "version": v})     # noqa: E731
    assert psp(1, "00.09.00.7e")["result"] == "affected" and psp(1, "00.09.00.7f")["result"] == "not-affected" and psp(1, "00.0a.00.00")["result"] == "not-affected"
    assert psp(1, "00.09.00.80")["result"] == "not-affected" and psp(1, "00.10.00.00", "00.0f.00.00")["result"] == "not-affected"
    assert psp(8, "00.09.00.7e")["result"] == fr.OUT and psp("0x01", "00.09.00.7e")["result"] == "affected" and psp(None, "00.09.00.7e")["result"] == fr.OUT
    assert psp(1, "00.09.00.7E")["result"] == "affected"                                       # 大小寫不影響
    for bad in ("0.9.0.7f", "00.09.00", "gg.09.00.7f", None, "00.09.00.7f.00"):
        assert psp(1, bad)["reason"] == "version-unreadable"
    uc = lambda comp, **c: fr.evaluate_condition(t, {"component": "amd_microcode", "fixed_in": "0x0a20102b", **c}, comp)      # noqa: E731
    base = {"equiv_id": "0xa210", "cpuids": ["00A20F10"], "patch_id": "0x0a201029"}
    assert uc(base, equiv_id="0xa210")["result"] == "affected" and uc({**base, "patch_id": "0x0a20102b"}, equiv_id="0xa210")["result"] == "not-affected"
    assert uc({**base, "patch_id": "0x0a20102A"}, equiv_id="0xa210")["result"] == "affected"
    assert uc({**base, "patch_id": "0x0a201030"}, equiv_id="0xa210")["result"] == "not-affected"
    assert uc({**base, "patch_id": "0x1a201029"}, equiv_id="0xa210")["result"] == "not-affected"      # 無號整數比較
    assert uc(base, equiv_id="0x8082")["result"] == fr.OUT
    assert uc(base, cpuid="00A20F10")["result"] == "affected" and uc(base, cpuid="00A20F11")["result"] == fr.OUT
    r = uc({**base, "cpuids": None}, cpuid="00A20F10")
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "cpuid-unknown")
    assert uc({**base, "cpuids": []}, cpuid="00A20F10")["reason"] == "cpuid-unknown"
    assert uc({**base, "cpuids": None}, equiv_id="0xa210")["result"] == "affected"             # equiv_id 不需要 CPUID
    assert uc({**base, "patch_id": "0x1"}, equiv_id="0xa210")["reason"] == "version-unreadable"
    assert uc({**base, "patch_id": None}, equiv_id="0xa210")["reason"] == "version-unreadable"
    bios = lambda comp, **c: fr.evaluate_condition(t, {"component": "bios_image", "name_prefix": "PRIME-B550M", "fixed_in": "3404", **c}, comp)      # noqa: E731
    img = {"file": "PRIME-B550M-A-ASUS-3404.zip!PRIME-B550M-A-ASUS-3404.CAP", "declared_version": "3202"}
    assert bios(img)["result"] == "affected" and bios({**img, "declared_version": "3404"})["result"] == "not-affected"
    assert bios({**img, "declared_version": "3404.1"})["result"] == "not-affected" and bios({**img, "declared_version": "33"})["result"] == "affected"
    assert bios({**img, "declared_version": "10000"})["result"] == "not-affected"              # 數字比
    assert bios({**img, "file": "prime-b550m-x.cap"})["result"] == "affected"                  # 檔名開頭不分大小寫
    assert bios({**img, "file": "X-PRIME-B550M.cap"})["result"] == fr.OUT
    assert bios({**img, "declared_version": None})["reason"] == "no-declared-version"
    assert bios({**img, "declared_version": "1.05 beta"})["reason"] == "version-unreadable"
    assert bios({**img, "declared_version": "v3404"})["reason"] == "version-unreadable"
    assert fr.tuple_compare((1, 2), (1, 2, 0)) == 0 and fr.tuple_compare((1, 2), (1, 2, 1)) == -1


def test_ami_core_is_always_not_assessed(table):
    t = table()
    r = fr.evaluate_condition(t, {"component": "ami_core", "product": "Aptio V", "fixed_in": "AptioV_5.044"}, {"ami": True})
    assert (r["result"], r["reason"]) == ("NOT_ASSESSED", "no-ami-core-version") and "no AMI core version" in r["detail"]
    r = fr.evaluate_condition(t, {"component": "ami_core", "product": "Aptio V"}, {"ami": True, "core_version": "AptioV_5.099"})        # 就算有人塞了版本也不比
    assert r["result"] == "NOT_ASSESSED"


# ---------- 整個元件的建議 ----------

def csme_rule(rid, fixed, state="preliminary", line="14.0"):
    return rule(rid, [{"component": "intel_csme", "line": line, "fixed_in": fixed}], "Intel", state, url=INTEL % rid[-5:])


def test_affected_beats_not_affected_and_unreadable_blocks_not_affected(table):
    t = table(csme_rule("INTEL-SA-00391", "14.0.45"), csme_rule("INTEL-SA-00900", "14.0.60", "confirmed"), csme_rule("INTEL-SA-00500", "14.0.40"))
    comp = {"version": "14.0.47.1558", "family": None, "family_conflict": None, "family_basis": "inferred"}
    r = fr.evaluate(t, "intel_csme", comp)
    assert r["suggestion"] == "affected" and r["rule_ids"] == ["INTEL-SA-00900"] and r["state"] == "confirmed" and r["reason"] is None
    assert "INTEL-SA-00391 [preliminary]: not-affected" in r["basis"] and "INTEL-SA-00500" in r["basis"] and r["evidence"] == []
    r = fr.evaluate(t, "intel_csme", {**comp, "version": "14.0.30.1"})
    assert r["suggestion"] == "affected" and r["rule_ids"] == ["INTEL-SA-00391", "INTEL-SA-00500", "INTEL-SA-00900"] and r["state"] == "preliminary+confirmed"
    t2 = table(csme_rule("INTEL-SA-00391", "14.0.45"), csme_rule("INTEL-SA-00500", "14.0.40"))
    r = fr.evaluate(t2, "intel_csme", comp)
    assert r["suggestion"] == "not-affected" and r["rule_ids"] == ["INTEL-SA-00391", "INTEL-SA-00500"] and r["state"] == "preliminary"
    assert r["evidence"] == [INTEL % "00391", INTEL % "00500"] and "vendor-statement" in r["basis"] and "decided by the vendor advisory" in r["basis"]
    # 另一條規則讀不懂（fixed_in 四段而版本只有三段）→ 不能說 not-affected
    t3 = table(csme_rule("INTEL-SA-00391", "14.0.45"), csme_rule("INTEL-SA-00600", "14.0.47.9999"))
    r = fr.evaluate(t3, "intel_csme", {**comp, "version": "14.0.47"})
    assert r["suggestion"] == "NOT_ASSESSED" and r["reason"] == "version-too-short" and r["rule_ids"] == [] and r["state"] is None and r["evidence"] == []
    assert "no data in the database; the vendor advisory is authoritative" in r["basis"]
    # 但另一條是 affected 時，讀不懂的那條不擋 affected
    r = fr.evaluate(t3, "intel_csme", {**comp, "version": "14.0.30"})
    assert r["suggestion"] == "affected"


def test_no_rule_and_no_rule_for_line(table):
    t = table(csme_rule("INTEL-SA-00391", "14.0.45"))
    comp = {"version": "18.1.18.2724", "family": None, "family_conflict": None, "family_basis": "inferred"}
    r = fr.evaluate(t, "intel_csme", comp)
    assert (r["suggestion"], r["reason"], r["rule_ids"]) == ("NOT_ASSESSED", "no-rule-for-line", []) and "INTEL-SA-00391" in r["basis"]
    r = fr.evaluate(t, "amd_psp", {"type": 1, "version": "00.09.00.7f"})
    assert (r["suggestion"], r["reason"]) == ("NOT_ASSESSED", "no-rule") and "no data in the database" in r["basis"]
    r = fr.evaluate(t, "intel_fsp", {"version": "9.0.1.1"})
    assert r["reason"] == "no-rule"


def test_ami_rules_never_give_a_suggestion_but_list_related(table):
    ami = rule("AMI-SA-2026001", [{"component": "ami_core", "product": "Aptio V", "fixed_in": "AptioV_5.044"}], "AMI", url=AMI_PDF)
    t = table(ami, rule("AMD-SB-7014", [{"component": "bios_image", "name_prefix": "PRIME", "fixed_in": "3404"}]))
    r = fr.evaluate(t, "bios_image", {"file": "PRIME-X.CAP", "declared_version": "3500", "ami": True})
    assert r["suggestion"] == "NOT_ASSESSED" and r["reason"] == "no-ami-core-version" and r["rule_ids"] == [] and r["related"] == ["AMI-SA-2026001"]
    assert "the SBOM has no AMI core version" in r["basis"] and "AMI-SA-2026001" in r["basis"]
    r = fr.evaluate(t, "bios_image", {"file": "PRIME-X.CAP", "declared_version": "3500", "ami": False})          # 沒有 AMI 線索：AMI 公告不列、不擋
    assert r["suggestion"] == "not-affected" and r["related"] == []
    r = fr.evaluate(t, "bios_image", {"file": "PRIME-X.CAP", "declared_version": "3000", "ami": True})           # 別的規則是 affected 就是 affected
    assert r["suggestion"] == "affected" and r["rule_ids"] == ["AMD-SB-7014"] and r["related"] == ["AMI-SA-2026001"]
    r = fr.evaluate(t, "amd_psp", {"type": 1, "version": "00.09.00.7f", "ami": True})
    assert r["related"] == []                                                                                      # 只有 BIOS 映像列相關的 AMI 公告


def test_table_unavailable_makes_every_component_not_assessed():
    for err in (fr.TableError("table-invalid", "x"), fr.TableError("table-unreadable", "x"), fr.TableError("table-sha-mismatch", "x")):
        for kind, comp in (("amd_agesa", {"value": "ComboAM4v2PI 1.2.0.B"}), ("intel_csme", {"version": "14.0.1.1", "family_basis": "listed"}),
                           ("bios_image", {"file": "a", "ami": True}), ("amd_psp", {"type": 1, "version": "00.00.00.01"})):
            r = fr.evaluate(err, kind, comp)
            assert r["suggestion"] == "NOT_ASSESSED" and r["reason"] == err.reason and r["rule_ids"] == [] and "no data in the database" in r["basis"]
    assert fr.counts([{"suggestion": "affected"}, {"suggestion": "affected"}, {"suggestion": "NOT_ASSESSED"}]) == {"affected": 2, "NOT_ASSESSED": 1}


# ---------- x86_firmware 整合：SBOM property、狀態、報告 ----------

def props(c, name):
    return [p["value"] for p in c["properties"] if p["name"] == name]


def amd_file(tmp_path, agesa="ComboAM4v2PI 1.2.0.B"):
    img = good_image()
    put(img, 0x80000, b"AGESA!V9\x00" + agesa.encode() + b"\x00")
    p = tmp_path / "amd.bin"
    p.write_bytes(bytes(img))
    return p


def agesa_rule(state="preliminary", fixed="1.2.0.Cb", rid="AMD-SB-7014"):
    return rule(rid, [{"component": "amd_agesa", "family": "ComboAM4v2PI", "fixed_in": fixed}], state=state)


def test_affected_suggestion_in_sbom_and_vuln_assessment_stays_not_assessed(tmp_path):
    t = build(tmp_path, doc(agesa_rule()))
    inv = xf.inventory([amd_file(tmp_path)], rules=t)
    comps, deps = xf.components(inv)
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    ag = next(c for c in comps if c["name"] == "AMD AGESA")
    assert props(ag, "dumpling:advisory-rule-suggestion") == ["affected"] and props(ag, "dumpling:advisory-rule-ids") == ["AMD-SB-7014"]
    assert props(ag, "dumpling:advisory-rule-state") == ["preliminary"] and "decided by the vendor advisory" in props(ag, "dumpling:advisory-rule-basis")[0]
    assert props(ag, "dumpling:evidence") == [] and "preliminary" in props(ag, "dumpling:advisory-rule-source")[0] and "last compiled 2026-11-14" in props(ag, "dumpling:advisory-rule-source")[0]
    assert props(ag, "dumpling:vuln-assessment") == ["NOT_ASSESSED"]                           # 建議不改漏洞比對狀態
    assert props(ag, "dumpling:advisory-match") == ["NOT_ASSESSED"]                            # 既有的 advisory-match 也不動
    for c in comps:
        assert props(c, "dumpling:vuln-assessment") == ["NOT_ASSESSED"], c["name"]
        if c["name"].startswith("AMD PSP") or c["name"].startswith("AMD CPU microcode"):
            assert props(c, "dumpling:advisory-rule-suggestion") == ["NOT_ASSESSED"] and props(c, "dumpling:advisory-rule-ids") == []
            assert props(c, "dumpling:advisory-rule-reason") == ["no-rule"]
    img = next(c for c in comps if c["name"] == "amd.bin")
    assert props(img, "dumpling:advisory-rule-suggestion") == ["NOT_ASSESSED"]
    assert not any(n.startswith("dumpling:advisory-rule") for c in comps if c["name"].startswith("Intel CPU") for n in (p["name"] for p in c["properties"]))


def test_not_affected_records_vendor_statement_and_url(tmp_path):
    t = build(tmp_path, doc(agesa_rule(fixed="1.2.0.B")))
    comps, _ = xf.components(xf.inventory([amd_file(tmp_path)], rules=t))
    ag = next(c for c in comps if c["name"] == "AMD AGESA")
    assert props(ag, "dumpling:advisory-rule-suggestion") == ["not-affected"]
    assert props(ag, "dumpling:evidence") == ["vendor-statement"] and props(ag, "dumpling:evidence-location") == [AMD % "7014"]
    assert props(ag, "dumpling:advisory-rule-ids") == ["AMD-SB-7014"] and props(ag, "dumpling:vuln-assessment") == ["NOT_ASSESSED"]
    assert not any(p["name"] == "dumpling:evidence" for c in comps if c is not ag for p in c["properties"])


def test_mixed_states_and_confirmed(tmp_path):
    t = build(tmp_path, doc(agesa_rule("preliminary", rid="AMD-SB-7014"), agesa_rule("confirmed", "1.2.0.C", "AMD-SB-7005")))
    inv = xf.inventory([amd_file(tmp_path)], rules=t)
    ag = next(c for c in xf.components(inv)[0] if c["name"] == "AMD AGESA")
    assert props(ag, "dumpling:advisory-rule-state") == ["preliminary+confirmed"] and props(ag, "dumpling:advisory-rule-ids") == ["AMD-SB-7005, AMD-SB-7014"]
    t = build(tmp_path, doc(agesa_rule("confirmed")), "c.json")
    inv = xf.inventory([amd_file(tmp_path)], rules=t)
    assert xf.components(inv)[0] and "依已確認規則的建議" in xf.status_of(inv)[1] and "初審" not in xf.status_of(inv)[1]
    md = xf.markdown(inv)
    assert "依已確認規則的建議；是否受影響以廠商公告為準" in md and "依初審規則的建議" not in md.split("### 各元件的建議")[0].split("### 建議 affected（待人審）")[1]


def ok_status_inventory(tmp_path, rules):
    """沒有規則表時狀態是 OK 的 Intel 映像（把其他 ATTENTION 的原因清掉，只看規則表的影響）。"""
    p = tmp_path / "intel.bin"
    p.write_bytes(spi_image())
    inv = xf.inventory([p], rules=rules)
    inv["comparison"] = []
    return inv


def test_status_affected_is_attention_not_affected_does_not_improve(tmp_path):
    csme16 = lambda fixed, state="preliminary": rule("INTEL-SA-01372", [{"component": "intel_csme", "line": "16.1", "fixed_in": fixed}], "Intel", state, url=INTEL % "01372")      # noqa: E731
    none = ok_status_inventory(tmp_path, build(tmp_path, doc(agesa_rule()), "n.json"))                      # 規則表有規則、但沒有一條適用
    base_status, base_detail = xf.status_of(none)
    assert base_status == "OK", base_detail
    notaff = ok_status_inventory(tmp_path, build(tmp_path, doc(csme16("16.1.20")), "na.json"))               # 16.1.30.2307 不低於 16.1.20
    assert notaff["rules_advisory"]["counts"]["not-affected"] == 1
    assert xf.status_of(notaff) == (base_status, base_detail)                                                # not-affected 不改狀態，也不加說明
    aff = ok_status_inventory(tmp_path, build(tmp_path, doc(csme16("16.1.40")), "a.json"))
    st, detail = xf.status_of(aff)
    assert st == "ATTENTION" and "規則表建議 affected：1 個元件（規則 INTEL-SA-01372；依初審規則的建議，待負責單位確認；是否受影響以廠商公告為準），待人審" in detail
    conf = ok_status_inventory(tmp_path, build(tmp_path, doc(csme16("16.1.40", "confirmed")), "ac.json"))
    st, detail = xf.status_of(conf)
    assert st == "ATTENTION" and "依已確認規則的建議" in detail
    # affected 加 not-affected 並存：還是 ATTENTION
    both = ok_status_inventory(tmp_path, build(tmp_path, doc(csme16("16.1.40"), rule("INTEL-SA-00391", [{"component": "intel_csme", "line": "16.1", "fixed_in": "16.1.10"}], "Intel",
                                                                                      url=INTEL % "00391")), "b.json"))
    assert xf.status_of(both)[0] == "ATTENTION"
    # NOT_ASSESSED（版本線不同）照舊
    na = ok_status_inventory(tmp_path, build(tmp_path, doc(rule("INTEL-SA-01372", [{"component": "intel_csme", "line": "14.0", "fixed_in": "14.0.45"}], "Intel", url=INTEL % "01372")), "nl.json"))
    assert xf.status_of(na) == (base_status, base_detail)


def test_status_attention_when_table_is_invalid(tmp_path):
    for err in (fr.TableError("table-invalid", "rules[0].id: bad format"), fr.TableError("table-sha-mismatch", "x"), fr.TableError("table-unreadable", "x")):
        inv = ok_status_inventory(tmp_path, err)
        st, detail = xf.status_of(inv)
        assert st == "ATTENTION" and "廠商公告規則表不能用（GAP，" + err.reason in detail and "NOT_ASSESSED：資料庫沒有資料，以廠商公告為準" in detail
        ra = inv["rules_advisory"]
        assert ra["status"] == "GAP" and ra["counts"] == {"NOT_ASSESSED": ra["components"]} and ra["components"] >= 2
        comps, _ = xf.components(inv)
        me = next(c for c in comps if c["name"] == "Intel CSE firmware")
        assert props(me, "dumpling:advisory-rule-suggestion") == ["NOT_ASSESSED"] and props(me, "dumpling:advisory-rule-reason") == [err.reason]
        md = xf.markdown(inv)
        assert "規則表：**GAP（不能用）**" in md and err.reason in md


def test_matching_error_is_contained(tmp_path, monkeypatch):
    t = build(tmp_path, doc(agesa_rule()))
    mod = xf.load_sibling("fw_advisory_rules")

    def boom(*a, **k):
        raise RuntimeError("x")
    monkeypatch.setattr(mod, "evaluate", boom)
    inv = xf.inventory([amd_file(tmp_path)], rules=t)
    assert inv["rules_advisory"]["counts"] == {"NOT_ASSESSED": inv["rules_advisory"]["components"]}
    ag = inv["bios"][0]["amd"]["agesa"]["values"][0]["rule_advisory"]
    assert ag["reason"] == "match-error" and ag["suggestion"] == "NOT_ASSESSED"


def test_ami_related_advisories_listed_without_a_suggestion(tmp_path):
    ami = rule("AMI-SA-2026001", [{"component": "ami_core", "product": "Aptio V", "fixed_in": "AptioV_5.044"}], "AMI", url=AMI_PDF)
    inv = ok_status_inventory(tmp_path, build(tmp_path, doc(ami)))
    b = inv["bios"][0]
    assert "AMI" in b["ibv_hint"]
    r = b["rule_advisory"]
    assert r["suggestion"] == "NOT_ASSESSED" and r["reason"] == "no-ami-core-version" and r["related"] == ["AMI-SA-2026001"]
    assert xf.status_of(inv)[0] == "OK"
    comps, _ = xf.components(inv)
    img = next(c for c in comps if c["name"] == "intel.bin")
    assert props(img, "dumpling:advisory-rule-related") == ["AMI-SA-2026001"] and props(img, "dumpling:advisory-rule-suggestion") == ["NOT_ASSESSED"]
    md = xf.markdown(inv)
    section = md.split("### 可能相關的 AMI 公告（沒有建議）")[1].split("###")[0]
    assert "AMI-SA-2026001" in section and "沒有可用的 AMI 核心版本" in section


def test_report_text(tmp_path):
    t = build(tmp_path, doc(agesa_rule(), agesa_rule(fixed="1.2.0.B", rid="AMD-SB-7005")))
    inv = xf.inventory([amd_file(tmp_path)], rules=t)
    md = xf.markdown(inv)
    sec = md[md.index("## 規則表比對"):]
    assert "最後整理日期 **2026-11-14**；之後的新公告沒有收錄，以廠商公告為準" in sec and t.sha256 in sec
    assert "規則表：2 筆（初審 2、已確認 0）" in sec and "元件 7 個：affected 1、NOT_ASSESSED 6" in sec
    assert "依初審規則的建議（待負責單位確認）" in sec and "是否受影響以廠商公告為準" in sec
    assert "### 規則表內容" in sec and "| AMD-SB-7014 | AMD | Test advisory | 2026-01-01 | 初審（韌體分析（C2 角色）初審，2026-11-13）待負責單位確認 |" in sec
    assert "AMD-SB-7005" in sec and "not-affected" in sec and "資料庫沒有資料，以廠商公告為準" in sec
    for w in FORBIDDEN:
        assert w not in sec, w
    assert "沒有任何一項代表「沒有漏洞」" in sec and "PASS" not in sec
    # 只有 not-affected（沒有 affected）的報告：「建議 affected」沒有項目，而 not-affected 單獨列出並寫依據類型與網址
    t2 = build(tmp_path, doc(agesa_rule(fixed="1.2.0.B")), "na.json")
    sec2 = xf.markdown(xf.inventory([amd_file(tmp_path)], rules=t2))
    sec2 = sec2[sec2.index("### 建議 affected（待人審）"):]
    a, n = sec2.split("### 建議 not-affected（依據類型 vendor-statement）")
    assert "沒有。" in a and "AMD-SB-7014" in n and AMD % "7014" in n.replace("\\", "") and "不會讓報告狀態變好" in n
    # 其他段落沒有宣稱規則表還沒做
    assert "規則表還沒有" not in md and "rule table has not been built" not in json.dumps(xf.components(inv)[0])


def test_report_without_rules_field_is_a_gap_not_a_crash():
    inv = {"bios": [], "vbios": [], "other_roms": [], "skipped": [], "partial": [], "advisory": None}
    lines = xf.rules_markdown(inv)
    assert any("GAP（不能用）" in x for x in lines)


# ---------- firmware_advisory_cell ----------

def test_cell_reflects_rules(tmp_path):
    inv = xf.inventory([amd_file(tmp_path)], rules=build(tmp_path, doc(agesa_rule())))
    text = cell.cell(json.loads(json.dumps(inv)))
    assert "規則表建議（2026-11-14 整理）affected 1、NOT_ASSESSED 6：affected 1 個待人審（AMD-SB-7014；依初審規則的建議，待負責單位確認）；是否受影響以廠商公告為準，之後的新公告沒有收錄" in text
    assert text.startswith("沒有 Intel 微碼；AMD 微碼已解析 2 份，沒有做公告比對")                    # 既有的段落維持原樣在前面
    inv2 = xf.inventory([amd_file(tmp_path)], rules=build(tmp_path, doc(agesa_rule(fixed="1.2.0.B")), "n.json"))
    t2 = cell.cell(json.loads(json.dumps(inv2)))
    assert "not-affected 1" in t2 and "待人審" not in t2
    inv3 = xf.inventory([amd_file(tmp_path)], rules=fr.TableError("table-invalid", "bad"))
    t3 = cell.cell(json.loads(json.dumps(inv3)))
    assert "規則表 GAP（table-invalid: bad）：7 個元件的規則建議都是 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準" in t3
    old = json.loads(json.dumps(inv))
    del old["rules_advisory"]
    assert "規則表" not in cell.cell(old)                                                          # 舊的 inventory：欄位維持原樣
    for w in FORBIDDEN:
        assert w not in text and w not in t2 and w not in t3


# 第二批（2026-11-14 讀頁面）新增的條件：Intel 15.x 與 18.0 的列，AMD 資料中心的微碼列（equiv_id → patch level）
SECOND_BATCH_FIXED = {
    ("INTEL-SA-01280", "15.0"): "15.0.52", ("INTEL-SA-01280", "15.20"): "15.20.23", ("INTEL-SA-01280", "15.40"): "15.40.37",
    ("INTEL-SA-01372", "15.0"): "15.0.56", ("INTEL-SA-01372", "15.20"): "15.20.26", ("INTEL-SA-01372", "15.40"): "15.40.42",
    ("INTEL-SA-01152", "14.1"): "14.1.75", ("INTEL-SA-01152", "14.5"): "14.5.55", ("INTEL-SA-01152", "15.0"): "15.0.50",
    ("INTEL-SA-01152", "15.20"): "15.20.20", ("INTEL-SA-01152", "15.40"): "15.40.35",
    ("INTEL-SA-01209", "14.1"): "14.1.75", ("INTEL-SA-01209", "14.5"): "14.5.55", ("INTEL-SA-01209", "15.0"): "15.0.50",
    ("INTEL-SA-01209", "15.20"): "15.20.20", ("INTEL-SA-01209", "15.40"): "15.40.35", ("INTEL-SA-01209", "18.0"): "18.0.10",
    ("INTEL-SA-01315", "14.1"): "14.1.79", ("INTEL-SA-01315", "15.0"): "15.0.55", ("INTEL-SA-01315", "15.20"): "15.20.25", ("INTEL-SA-01315", "18.0"): "18.0.18",
    ("AMD-SB-7014", "0x8012"): "0x0800126f", ("AMD-SB-7014", "0x8310"): "0x0830107c", ("AMD-SB-7014", "0xa011"): "0x0a0011d5",
    ("AMD-SB-7014", "0xa012"): "0x0a001238", ("AMD-SB-7014", "0xa111"): "0x0a101148", ("AMD-SB-7014", "0xa112"): "0x0a101248", ("AMD-SB-7014", "0xaa02"): "0x0aa00215",
    ("AMD-SB-7033", "0x8012"): "0x08001278", ("AMD-SB-7033", "0x8310"): "0x0830107d", ("AMD-SB-7033", "0xa011"): "0x0a0011db",
    ("AMD-SB-7033", "0xa012"): "0x0a001244", ("AMD-SB-7033", "0xa111"): "0x0a101154", ("AMD-SB-7033", "0xa112"): "0x0a10124f",
    ("AMD-SB-7033", "0xaa02"): "0x0aa00219", ("AMD-SB-7033", "0xb021"): "0x0b002147",
}
# 公開的 linux-firmware AMD 微碼容器（microcode_amd_fam17h／fam19h／fam1ah.bin）的等價表：equivalence id → CPUID。AMD 公告列的是 CPUID，映像的微碼只有 equivalence id
EQUIV_TO_CPUID = {"0x8012": "00800F12", "0x8310": "00830F10", "0xa011": "00A00F11", "0xa012": "00A00F12", "0xa111": "00A10F11", "0xa112": "00A10F12",
                  "0xaa02": "00AA0F02", "0xb021": "00B00F21"}


# ---------- 進 repo 的規則表 ----------

def test_repo_table_is_valid_pinned_and_first_batch_is_what_the_pages_say():
    import hashlib
    assert hashlib.sha256(DATA.read_bytes()).hexdigest() == fr.TABLE_SHA256
    t, err = fr.load_default()
    assert err is None and t.updated == UPDATED
    assert [r["id"] for r in t.rules] == ["AMD-SB-7005", "AMD-SB-7014", "AMD-SB-7033", "INTEL-SA-00391", "INTEL-SA-01152", "INTEL-SA-01209", "INTEL-SA-01280",
                                          "INTEL-SA-01315", "INTEL-SA-01372", "AMI-SA-2026001", "AMI-SA-2026002"]
    for r in t.rules:
        assert r["review"]["state"] == "preliminary" and r["review"]["preliminary_by"] == ROLE and "confirmed_by" not in r["review"]
        assert all(s["read_at"] == UPDATED for s in r["sources"])
    ver = {r["id"]: {s["verification"] for s in r["sources"]} for r in t.rules}
    assert ver == {"AMD-SB-7005": {"direct"}, "AMD-SB-7014": {"direct"}, "AMD-SB-7033": {"direct"}, "INTEL-SA-00391": {"independent:nvd"}, "INTEL-SA-01152": {"summary-tool"},
                   "INTEL-SA-01209": {"summary-tool"}, "INTEL-SA-01280": {"summary-tool"}, "INTEL-SA-01315": {"summary-tool"}, "INTEL-SA-01372": {"summary-tool"},
                   "AMI-SA-2026001": {"direct"}, "AMI-SA-2026002": {"direct"}}
    assert {r["title"] for r in t.rules if r["vendor"] == "AMI"} == {"Security Audit Reported Vulnerabilities"}
    fixed = {(r["id"], c.get("family") or c.get("line") or c.get("equiv_id")): c["fixed_in"] for r in t.rules for c in r["match"] if c["component"] != "ami_core"}
    assert fixed == {("AMD-SB-7005", "ComboAM4v2PI"): "1.2.0.B", ("AMD-SB-7005", "ComboAM5PI"): "1.0.8.0", ("AMD-SB-7014", "ComboAM4v2PI"): "1.2.0.Cc",
                     ("AMD-SB-7014", "ComboAM5PI"): "1.2.0.1", ("INTEL-SA-00391", "14.0"): "14.0.45", ("INTEL-SA-00391", "14.5"): "14.5.25",
                     ("INTEL-SA-01280", "14.1"): "14.1.77", ("INTEL-SA-01280", "14.5"): "14.5.57", ("INTEL-SA-01280", "18.1"): "18.1.18",
                     ("INTEL-SA-01372", "14.1"): "14.1.80", ("INTEL-SA-01372", "14.5"): "14.5.62", ("INTEL-SA-01372", "18.1"): "18.1.21",
                     **SECOND_BATCH_FIXED}
    assert {c["product"] for r in t.rules for c in r["match"] if c["component"] == "ami_core"} == {"Aptio V"}


@pytest.mark.parametrize("comp_kind,comp,want,ids", [
    ("amd_agesa", {"value": "ComboAM4v2PI 1.2.0.B"}, "affected", ["AMD-SB-7014"]),               # B550M／ASRock 的 AGESA：AMD-SB-7005 已修正（B 不低於 B），AMD-SB-7014 還沒（B < Cc）
    ("amd_agesa", {"value": "ComboAM5PI 1.0.8.0"}, "affected", ["AMD-SB-7014"]),                 # B650M：AMD-SB-7005 的 1.0.8.0，AMD-SB-7014 的 1.2.0.1
    ("amd_agesa", {"value": "ComboAM4v2PI 1.2.0.Cb"}, "affected", ["AMD-SB-7014"]),                # Vermeer 的 7014 修正版是 Cb，但規則取同表最高的 Cc（Matisse），所以 Cb 還是建議 affected
    ("amd_agesa", {"value": "ComboAM4v2PI 1.2.0.Cc"}, "not-affected", ["AMD-SB-7005", "AMD-SB-7014"]),
    ("amd_agesa", {"value": "ComboAM4v2PI 1.2.0.D"}, "not-affected", ["AMD-SB-7005", "AMD-SB-7014"]),
    ("amd_agesa", {"value": "ComboAM5PI 1.2.0.1"}, "not-affected", ["AMD-SB-7005", "AMD-SB-7014"]),
    ("amd_agesa", {"value": "ComboAM4v2PI 1.2.0.A"}, "NOT_ASSESSED", []),                       # 順序不確定
    ("amd_agesa", {"value": "ComboAM4PI 1.0.0.C"}, "NOT_ASSESSED", []),                          # 規則表沒有這個 family
    ("intel_csme", {"version": "14.0.47.1558", "family_basis": "inferred"}, "not-affected", ["INTEL-SA-00391"]),       # Protectli
    ("intel_csme", {"version": "18.1.18.2724", "family_basis": "inferred"}, "affected", ["INTEL-SA-01372"]),           # 18.1.18：01280 的 Versions Before 18.1.18 修正了，01372 的 18.1.21 還沒
    ("intel_csme", {"version": "18.1.21.1", "family_basis": "inferred"}, "not-affected", ["INTEL-SA-01280", "INTEL-SA-01372"]),
    ("intel_csme", {"version": "18.0.10.2285", "family_basis": "inferred"}, "affected", ["INTEL-SA-01315"]),          # V540TU：01209 的 18.0.10 不低於，01315 的 18.0.18 還沒
    ("intel_csme", {"version": "18.0.18.1", "family_basis": "inferred"}, "not-affected", ["INTEL-SA-01209", "INTEL-SA-01315"]),
    ("intel_csme", {"version": "18.0.9.1", "family_basis": "inferred"}, "affected", ["INTEL-SA-01209", "INTEL-SA-01315"]),
    ("intel_csme", {"version": "18.2.1.1", "family_basis": "inferred"}, "NOT_ASSESSED", []),                          # 18.2 版本線沒有收規則
    ("intel_csme", {"version": "15.0.51.1", "family_basis": "listed"}, "affected", ["INTEL-SA-01280", "INTEL-SA-01315", "INTEL-SA-01372"]),     # 01152、01209 的 15.0.50 已不低於
    ("intel_csme", {"version": "15.0.56.1", "family_basis": "listed"}, "not-affected", ["INTEL-SA-01152", "INTEL-SA-01209", "INTEL-SA-01280", "INTEL-SA-01315", "INTEL-SA-01372"]),
    ("intel_csme", {"version": "15.20.22.9", "family_basis": "listed"}, "affected", ["INTEL-SA-01280", "INTEL-SA-01315", "INTEL-SA-01372"]),
    ("intel_csme", {"version": "15.40.36.9", "family_basis": "listed"}, "affected", ["INTEL-SA-01280", "INTEL-SA-01372"]),               # 01315 沒有 15.40 的列
    ("intel_csme", {"version": "15.40.42", "family_basis": "listed"}, "not-affected", ["INTEL-SA-01152", "INTEL-SA-01209", "INTEL-SA-01280", "INTEL-SA-01372"]),
    ("intel_csme", {"version": "15.60.1.1", "family_basis": "listed"}, "NOT_ASSESSED", []),
    ("intel_csme", {"version": "16.1.30.2307", "family_basis": "inferred"}, "NOT_ASSESSED", []),
])
def test_first_batch_results(comp_kind, comp, want, ids):
    t, err = fr.load_default()
    r = fr.evaluate(t, comp_kind, {"family": None, "family_conflict": None, **comp})
    assert (r["suggestion"], r["rule_ids"]) == (want, ids), r["basis"]


# ---------- 核對狀態（sources[].verification） ----------

def with_ver(rid, ver, fixed="16.1.40", state="preliminary"):
    r = rule(rid, [{"component": "intel_csme", "line": "16.1", "fixed_in": fixed}], "Intel", state, url=INTEL % rid[-5:])
    r["sources"][0]["verification"] = ver
    return r


def test_verification_is_required_and_enumerated(tmp_path):
    for v in fr.VERIFICATIONS:
        ok(tmp_path, doc(with_ver("INTEL-SA-01372", v)))
    assert fr.VERIFICATIONS == ("direct", "summary-tool", "independent:nvd")
    for bad in ("Direct", "nvd", "independent", "summary_tool", "", None, ["direct"], {"direct": 1}, 1, True):
        invalid(tmp_path, doc(with_ver("INTEL-SA-01372", bad)), "verification")
    d = doc(rule())
    del d["rules"][0]["sources"][0]["verification"]
    invalid(tmp_path, d, "missing field")
    d = doc(rule())
    d["rules"][0]["sources"][0]["verified"] = "direct"                                     # 欄位名稱打錯 → 不認得的欄位
    invalid(tmp_path, d, "unknown field")


def test_confirmed_rule_rejects_summary_tool_source(tmp_path):
    invalid(tmp_path, doc(with_ver("INTEL-SA-01372", "summary-tool", state="confirmed")), "summary-tool")      # 沒直接對照原頁面，不能確認
    for v in ("direct", "independent:nvd"):
        ok(tmp_path, doc(with_ver("INTEL-SA-01372", v, state="confirmed")))
    ok(tmp_path, doc(with_ver("INTEL-SA-01372", "summary-tool")))                                               # 初審可以


def test_weakest_verification_of_several_sources(tmp_path):
    ami = rule("AMI-SA-2026001", [{"component": "ami_core", "product": "Aptio V"}], "AMI", url=AMI_PDF)
    ami["sources"].append({"url": fr.AMI_INDEX_URL, "read_at": UPDATED, "verification": "summary-tool"})
    t = build(tmp_path, doc(ami, with_ver("INTEL-SA-00391", "independent:nvd"), with_ver("INTEL-SA-01280", "direct")))
    assert (t.verification("AMI-SA-2026001"), t.verification("INTEL-SA-00391"), t.verification("INTEL-SA-01280")) == ("summary-tool", "independent:nvd", "direct")


def test_unverified_values_are_flagged_in_suggestion_property_and_report(tmp_path):
    t = build(tmp_path, doc(with_ver("INTEL-SA-01372", "summary-tool", "16.1.40"), with_ver("INTEL-SA-00391", "independent:nvd", "16.1.10"), with_ver("INTEL-SA-01280", "direct", "16.1.10")))
    inv = ok_status_inventory(tmp_path, t)
    r = inv["bios"][0]["me"]["rule_advisory"]
    assert r["suggestion"] == "affected" and r["verification"] == {"INTEL-SA-01372": "summary-tool"}
    assert "INTEL-SA-01372 were read only through a page summary tool and are not independently verified" in r["basis"]
    me = next(c for c in xf.components(inv)[0] if c["name"] == "Intel CSE firmware")
    assert props(me, "dumpling:advisory-rule-verification") == ["INTEL-SA-01372=summary-tool"]
    md = xf.markdown(inv)
    sec = md[md.index("## 規則表比對"):]
    assert "版本值未獨立核對（只經網頁摘要工具讀到），請負責單位對照原頁面" in sec                       # 規則清單的欄位
    assert "直接下載原文解析" in sec and "官方頁面加 NVD 的版本範圍另行核對" in sec
    aff = sec.split("### 建議 affected（待人審）")[1].split("###")[0]
    assert "INTEL-SA-01372 的版本值未獨立核對，請負責單位對照原頁面" in aff
    t2 = build(tmp_path, doc(with_ver("INTEL-SA-00391", "independent:nvd", "16.1.10")), "n.json")                      # not-affected、有獨立核對的：沒有提醒
    inv2 = ok_status_inventory(tmp_path, t2)
    assert inv2["bios"][0]["me"]["rule_advisory"]["suggestion"] == "not-affected" and "未獨立核對" not in xf.markdown(inv2).split("### 建議 not-affected")[1].split("###")[0]
    t3 = build(tmp_path, doc(with_ver("INTEL-SA-01280", "summary-tool", "16.1.10")), "s.json")                          # not-affected 但只經摘要工具：也要提醒
    md3 = xf.markdown(ok_status_inventory(tmp_path, t3))
    assert "INTEL-SA-01280 的版本值未獨立核對" in md3.split("### 建議 not-affected")[1].split("###")[0]


# ---------- 同一條規則內的優先順序 ----------

def two_conditions(fixed_a, fixed_b):
    return rule("INTEL-SA-00391", [{"component": "intel_csme", "line": "14.0", "fixed_in": fixed_a},
                                   {"component": "intel_csme", "line": "14.0", "fixed_in": fixed_b}], "Intel", url=INTEL % "00391")


CSME_COMP = {"family": None, "family_conflict": None, "family_basis": "listed"}


def test_within_one_rule_not_assessed_beats_not_affected(table):
    t = table(two_conditions("14.0.45", "14.0.47.9999"))                    # 14.0.47：第一個條件 not-affected，第二個要四段、版本只有三段 → NOT_ASSESSED
    r = fr.evaluate(t, "intel_csme", {**CSME_COMP, "version": "14.0.47"})
    assert r["suggestion"] == "NOT_ASSESSED" and r["reason"] == "version-too-short" and r["rule_ids"] == [] and r["evidence"] == []
    assert [x["result"] for x in r["results"]] == ["NOT_ASSESSED"]            # 一條規則只留一個結果
    r = fr.evaluate(t, "intel_csme", {**CSME_COMP, "version": "14.0.47.1558"})        # 版本四段：兩個條件都能比，第二個是 affected（1558 < 9999）
    assert r["suggestion"] == "affected"


def test_within_one_rule_affected_beats_not_affected_and_not_assessed(table):
    t = table(two_conditions("14.0.40", "14.0.50"))                          # 14.0.45：一個 not-affected、一個 affected
    r = fr.evaluate(t, "intel_csme", {**CSME_COMP, "version": "14.0.45.1"})
    assert r["suggestion"] == "affected" and r["rule_ids"] == ["INTEL-SA-00391"] and r["evidence"] == []
    assert [x["result"] for x in r["results"]] == ["affected"]
    t = table(two_conditions("14.0.50", "14.0.47.9999"))                     # 一個 affected、一個 NOT_ASSESSED（三段版本）
    r = fr.evaluate(t, "intel_csme", {**CSME_COMP, "version": "14.0.47"})
    assert r["suggestion"] == "affected" and r["rule_ids"] == ["INTEL-SA-00391"]
    t = table(two_conditions("14.0.40", "14.0.30"))                          # 兩個都 not-affected → not-affected（單一結果）
    r = fr.evaluate(t, "intel_csme", {**CSME_COMP, "version": "14.0.45.1"})
    assert r["suggestion"] == "not-affected" and len(r["results"]) == 1


# ---------- 怪型別：load() 與 validate() 直接呼叫都是 table-invalid／TableError ----------

def weird_docs():
    base = doc(rule())
    out = {}

    def mut(name, fn):
        d = copy.deepcopy(base)
        fn(d)
        out[name] = d
    mut("vendor-list", lambda d: d["rules"][0].__setitem__("vendor", ["AMD"]))
    mut("vendor-dict", lambda d: d["rules"][0].__setitem__("vendor", {"a": 1}))
    mut("id-list", lambda d: d["rules"][0].__setitem__("id", ["AMD-SB-7014"]))
    mut("cves-dict-element", lambda d: d["rules"][0].__setitem__("cves", [{"a": 1}, {"a": 1}]))
    mut("cves-list-element", lambda d: d["rules"][0].__setitem__("cves", [["x"], ["x"]]))
    mut("title-dict", lambda d: d["rules"][0].__setitem__("title", {"a": 1}))
    mut("sources-entry-list", lambda d: d["rules"][0].__setitem__("sources", [["x"]]))
    mut("source-url-list", lambda d: d["rules"][0]["sources"][0].__setitem__("url", ["x"]))
    mut("source-verification-dict", lambda d: d["rules"][0]["sources"][0].__setitem__("verification", {"a": 1}))
    mut("match-entry-list", lambda d: d["rules"][0].__setitem__("match", [["x"]]))
    mut("match-component-dict", lambda d: d["rules"][0]["match"][0].__setitem__("component", {"a": 1}))
    mut("match-family-list", lambda d: d["rules"][0]["match"][0].__setitem__("family", ["x"]))
    mut("review-list", lambda d: d["rules"][0].__setitem__("review", ["x"]))
    mut("review-state-dict", lambda d: d["rules"][0]["review"].__setitem__("state", {"a": 1}))
    mut("review-by-list", lambda d: d["rules"][0]["review"].__setitem__("preliminary_by", ["x"]))
    mut("orderings-str", lambda d: d.__setitem__("orderings", "x"))
    mut("orderings-entry-list", lambda d: d.__setitem__("orderings", [["x"]]))
    mut("ordering-family-dict", lambda d: d["orderings"][0].__setitem__("family", {"a": 1}))
    mut("ordering-sequence-entry-list", lambda d: d["orderings"][0].__setitem__("sequence", [["a"], ["b"]]))
    mut("ordering-version-dict", lambda d: d["orderings"][0]["sequence"][0].__setitem__("version", {"a": 1}))
    mut("rules-dict", lambda d: d.__setitem__("rules", {"a": 1}))
    mut("rule-entry-str", lambda d: d.__setitem__("rules", ["x"]))
    mut("published-list", lambda d: d["rules"][0].__setitem__("published", ["2026-01-01"]))
    mut("table-updated-dict", lambda d: d.__setitem__("table_updated", {"a": 1}))
    mut("schema-list", lambda d: d.__setitem__("schema", [fr.SCHEMA]))
    mut("comment-list", lambda d: d.__setitem__("$comment", ["x"]))
    out["list-top"] = []
    out["none-top"] = None
    out["int-top"] = 5
    return out


@pytest.mark.parametrize("name", sorted(weird_docs()))
def test_odd_types_are_table_invalid_through_load_and_validate(tmp_path, name):
    d = weird_docs()[name]
    invalid(tmp_path, d)                                                      # load()：table-invalid
    with pytest.raises(fr.TableError) as e:                                   # validate() 直接呼叫：TableError（不是 TypeError）
        fr.validate(d)
    assert e.value.reason == "table-invalid"


def test_unhashable_values_in_validate_raise_table_error_not_type_error():
    d = doc(rule(cves=[{"a": 1}, {"a": 1}]))
    with pytest.raises(fr.TableError):
        fr.validate(d)
    d = doc(rule())
    d["rules"][0]["vendor"] = []
    with pytest.raises(fr.TableError):
        fr.validate(d)
    nested = []
    for _ in range(5000):
        nested = [nested]
    d = doc(rule(cves=nested))
    with pytest.raises(fr.TableError):
        fr.validate(d)


def test_roles_and_text_must_not_be_blank(tmp_path):
    for blank in (" ", "   ", "　", " ", "\t", " x", "x "):
        invalid(tmp_path, doc(rule() | {"review": review(preliminary_by=blank)}), "preliminary_by")
        invalid(tmp_path, doc(rule() | {"review": review("confirmed", confirmed_by=blank)}), "confirmed_by")
    for blank in (" ", "  ", " x"):
        invalid(tmp_path, doc(rule(title=blank)), "title")
        invalid(tmp_path, doc(rule(note=blank)), "note")
    ok(tmp_path, doc(rule() | {"review": review(preliminary_by="產品負責 角色")}))              # 中間的空白可以


# ---------- 比對出錯、同時有 affected 與 not-affected、禁用詞、AMI 相關公告 ----------

def test_match_error_makes_the_status_attention(tmp_path, monkeypatch):
    t = build(tmp_path, doc(csme_rule("INTEL-SA-01372", "16.1.10", line="16.1")))
    inv = ok_status_inventory(tmp_path, t)
    assert xf.status_of(inv)[0] == "OK" and inv["rules_advisory"]["errors"] == 0                  # 沒出錯時 not-affected 不影響狀態
    mod = xf.load_sibling("fw_advisory_rules")

    def boom(*a, **k):
        raise RuntimeError("x")
    monkeypatch.setattr(mod, "evaluate", boom)
    inv = ok_status_inventory(tmp_path, t)
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and inv["rules_advisory"]["errors"] == 2 and "規則表比對出錯：2 個元件" in detail and "match-error" in detail
    assert "規則表建議 affected" not in detail


def test_affected_keeps_its_review_line_when_another_component_is_not_affected(tmp_path):
    psp_ok = rule("AMD-SB-7005", [{"component": "amd_psp", "psp_type": 1, "fixed_in": "00.01.00.00"}])        # PSP type 1 的版本 00.09.00.7f 不低於 → not-affected
    t = build(tmp_path, doc(agesa_rule(), psp_ok))
    inv = xf.inventory([amd_file(tmp_path)], rules=t)
    assert inv["rules_advisory"]["counts"] == {"affected": 1, "not-affected": 1, "NOT_ASSESSED": 5}
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "規則表建議 affected：1 個元件（規則 AMD-SB-7014；依初審規則的建議，待負責單位確認；是否受影響以廠商公告為準），待人審" in detail
    assert "AMD-SB-7005" not in detail.split("規則表建議 affected：")[1].split("；沒有版本清單")[0]
    md = xf.markdown(inv)
    sec = md[md.index("### 建議 affected（待人審）"):]
    aff, notaff = sec.split("### 建議 not-affected（依據類型 vendor-statement）")
    assert "AGESA ComboAM4v2PI 1.2.0.B" in aff and "AMD-SB-7014" in aff and "待負責單位確認" in aff and "PSP type 0x01" not in aff.split("###")[0]
    assert "PSP type 0x01" in notaff and "AMD-SB-7005" in notaff.split("###")[0]
    assert "規則表建議（2026-11-14 整理）affected 1、not-affected 1" in cell.cell(json.loads(json.dumps(inv)))


def test_component_table_with_only_not_affected_has_no_forbidden_words(tmp_path):
    t = build(tmp_path, doc(rule("AMD-SB-7005", [{"component": "amd_psp", "psp_type": 1, "fixed_in": "00.01.00.00"},
                                                 {"component": "amd_agesa", "family": "ComboAM4v2PI", "fixed_in": "1.2.0.B"}])))
    inv = xf.inventory([amd_file(tmp_path)], rules=t)
    assert inv["rules_advisory"]["counts"]["not-affected"] == 2 and "affected" not in inv["rules_advisory"]["counts"]
    assert xf.status_of(inv)[1].count("規則表建議 affected") == 0
    md = xf.markdown(inv)
    sec = md[md.index("## 規則表比對"):]
    table_part = sec[sec.index("### 各元件的建議"):]
    assert "not-affected（依規則的建議：版本不低於公告列的修正版本；依據類型 vendor-statement）" in table_part and "AMD-SB-7005（preliminary）" in table_part
    for w in FORBIDDEN:
        assert w not in sec, w
    assert "沒有。" in sec.split("### 建議 affected（待人審）")[1].split("###")[0]


def test_ami_possibly_related_sentence_is_in_the_basis(table):
    ami = rule("AMI-SA-2026001", [{"component": "ami_core", "product": "Aptio V"}], "AMI", url=AMI_PDF)
    ami2 = rule("AMI-SA-2026002", [{"component": "ami_core", "product": "Aptio V"}], "AMI", url=AMI_PDF.replace("2026001", "2026002"))
    t = table(ami, ami2)
    r = fr.evaluate(t, "bios_image", {"file": "x.CAP", "declared_version": None, "ami": True})
    assert "possibly related AMI advisories (not matched): AMI-SA-2026001, AMI-SA-2026002" in r["basis"]
    assert r["suggestion"] == "NOT_ASSESSED" and r["rule_ids"] == []
    r = fr.evaluate(t, "bios_image", {"file": "x.CAP", "declared_version": None, "ami": False})           # 沒有 AMI 線索：沒有這句，也不是 no-ami-core-version
    assert "possibly related" not in r["basis"] and r["related"] == [] and r["reason"] == "no-rule"


# ---------- 第二批（2026-11-14）：Intel 15.x／18.0、AMD 資料中心微碼；PSP、FSP 沒有規則 ----------

def uc_comp(equiv, patch):
    return {"equiv_id": equiv, "cpuids": None, "patch_id": patch}                       # 映像的微碼是單獨的 patch、沒有等價表（cpuids 是 None）


def test_second_batch_microcode_conditions_are_tied_to_the_cpuid_the_bulletin_names():
    t, err = fr.load_default()
    assert err is None
    seen = set()
    for r in t.rules:
        for c in r["match"]:
            if c["component"] != "amd_microcode":
                continue
            assert "equiv_id" in c and "cpuid" not in c                                  # 映像沒有 CPUID，只能用 equivalence id
            assert f"CPUID 0x{EQUIV_TO_CPUID[c['equiv_id']]}" in c["note"] and "linux-firmware" in c["note"], (r["id"], c)
            seen.add((r["id"], c["equiv_id"]))
            fx = int(c["fixed_in"], 16)
            lo, hi = "0x%08x" % (fx - 1), c["fixed_in"]                                  # 低一階 → affected、剛好 → not-affected
            res = {rid: fr.evaluate_condition(t, c, uc_comp(c["equiv_id"], p))["result"] for rid, p in ((r["id"] + "-lo", lo), (r["id"] + "-hi", hi))}
            assert list(res.values()) == ["affected", "not-affected"], (r["id"], c, res)
            assert fr.evaluate_condition(t, c, uc_comp("0x8082" if c["equiv_id"] != "0x8082" else "0x8012", "0x00000001"))["result"] == fr.OUT
            assert fr.evaluate_condition(t, c, uc_comp(c["equiv_id"], "0x1"))["reason"] == "version-unreadable"
    assert seen == {k for k in SECOND_BATCH_FIXED if k[1].startswith("0x")}


@pytest.mark.parametrize("equiv,patch,want,ids,reason", [
    ("0x8012", "0x08001250", "affected", ["AMD-SB-7014", "AMD-SB-7033"], None),         # B550M／ASRock 的 Naples B2 patch：兩則公告的最低版本（…6f、…78）都更高
    ("0x8012", "0x08001270", "affected", ["AMD-SB-7033"], None),                          # 7014 的 0x0800126f 已達到，7033 的 0x08001278 還沒
    ("0x8012", "0x08001278", "not-affected", ["AMD-SB-7014", "AMD-SB-7033"], None),
    ("0x8310", "0x0830107c", "affected", ["AMD-SB-7033"], None),
    ("0xaa02", "0x0aa00219", "not-affected", ["AMD-SB-7014", "AMD-SB-7033"], None),
    ("0xb021", "0x0b002146", "affected", ["AMD-SB-7033"], None),
    ("0x8082", "0x0800820d", "NOT_ASSESSED", [], "no-rule-for-line"),                      # B550M 的另一份 patch：公告沒有這個 equivalence id
    ("0xa612", "0x0a601206", "NOT_ASSESSED", [], "no-rule-for-line"),                      # B650M：Raphael 的客戶端列只有 PI 版本，沒有微碼 patch level
    ("0xa611", "0x0a601119", "NOT_ASSESSED", [], "no-rule-for-line"),
])
def test_second_batch_amd_microcode_results(equiv, patch, want, ids, reason):
    t, err = fr.load_default()
    r = fr.evaluate(t, "amd_microcode", uc_comp(equiv, patch))
    assert (r["suggestion"], r["rule_ids"], r["reason"]) == (want, ids, reason), r["basis"]
    if want == "not-affected":
        assert r["evidence"] and all(u.startswith("https://www.amd.com/en/resources/product-security/bulletin/amd-sb-") for u in r["evidence"])
    if want == "NOT_ASSESSED":
        assert "no data in the database; the vendor advisory is authoritative" in r["basis"]


def test_condition_note_travels_with_the_suggestion_into_the_basis():
    """條件的 note（例如「公告列的是資料中心 Naples 的 CPUID」）是解讀的限制：affected／not-affected 的 basis 要帶著，報告與 SBOM 才看得到。"""
    t, err = fr.load_default()
    r = fr.evaluate(t, "amd_microcode", uc_comp("0x8012", "0x08001250"))
    assert r["suggestion"] == "affected" and r["basis"].count("condition note: ") == 2 and "Naples" in r["basis"] and "00800F12" in r["basis"]
    r = fr.evaluate(t, "amd_microcode", uc_comp("0x8082", "0x0800820d"))
    assert r["suggestion"] == "NOT_ASSESSED" and "condition note" not in r["basis"]                          # 沒有比到的條件不帶 note
    c = {"component": "amd_microcode", "equiv_id": "0x8012", "fixed_in": "0x0800126f"}
    assert "condition note" not in fr.evaluate_condition(t, c, uc_comp("0x8012", "0x08001250"))["detail"]       # 沒有 note 的條件不加


@pytest.mark.parametrize("version", ["14.10.1.1", "15.2.1.1", "15.200.1.1", "1.15.20.9", "150.20.1.1", "18.10.0.1", "14.50.1.1"])
def test_shipped_table_compares_whole_version_lines_only(version):
    """版本線是整段的數字比：14.10 不會被 14.1 的條件比到、15.2／15.200 不會被 15.20 比到（數字相同的寫法如 15.020 等於 15.20，是數字比的結果）。"""
    t, err = fr.load_default()
    r = fr.evaluate(t, "intel_csme", {"version": version, "family": None, "family_conflict": None, "family_basis": "listed"})
    assert (r["suggestion"], r["rule_ids"]) == ("NOT_ASSESSED", []), (version, r["basis"])
    assert all(x["result"] != "affected" and x["result"] != "not-affected" for x in r["results"]), version


def test_no_rule_for_psp_and_fsp_stays_not_assessed_in_basis_sbom_and_report():
    """D-043：沒有規則的元件種類（PSP 韌體、FSP）要寫「資料庫沒有資料，以廠商公告為準」，不能看起來像沒有問題。
    AMD 的公告沒有 PSP 韌體版本、Intel 的公告沒有 FSP 版本，所以規則表沒有這兩種條件。"""
    t, err = fr.load_default()
    assert err is None
    assert not {c["component"] for r in t.rules for c in r["match"]} & {"amd_psp", "intel_fsp"}
    inv = {"bios": [{"file": "x.rom", "declared_version": None, "ami_core": None, "me": None,
                     "amd": {"psp_firmware": [{"type": 1, "version": "00.09.00.7f"}, {"type": 8, "version": "00.40.47.00"}],
                             "microcode": [{"equiv_id": "0x8082", "cpuids": None, "patch_id": "0x0800820d"}], "agesa": {"values": []}},
                     "cbfs": {"fsp": [{"revision": "9.0.1.1", "extended_image_revision": 0}]}}]}
    inv["rules_advisory"] = xf.rules_section(inv, t)
    b = inv["bios"][0]
    for holder in (b["amd"]["psp_firmware"][0], b["amd"]["psp_firmware"][1], b["amd"]["microcode"][0], b["cbfs"]["fsp"][0]):
        r = holder["rule_advisory"]
        assert r["suggestion"] == "NOT_ASSESSED" and r["rule_ids"] == [] and "no data in the database; the vendor advisory is authoritative" in r["basis"]
        props_ = {p["name"]: p["value"] for p in xf.rule_props(r)}
        assert props_["dumpling:advisory-rule-suggestion"] == "NOT_ASSESSED" and "dumpling:evidence" not in props_
        assert props_["dumpling:advisory-rule-reason"] in ("no-rule", "no-rule-for-line")
    assert b["cbfs"]["fsp"][0]["rule_advisory"]["reason"] == "no-rule" and b["amd"]["microcode"][0]["rule_advisory"]["reason"] == "no-rule-for-line"
    md = "\n".join(xf.rules_markdown(inv))
    assert "FSP 9.0.1.1" in md and "NOT_ASSESSED（資料庫沒有資料，以廠商公告為準）" in md                    # FSP 逐項列出
    assert "其餘 3 個元件沒有適用的規則" in md and "amd\\_psp 2 個（no-rule）" in md and "amd\\_microcode 1 個（no-rule-for-line）" in md
    assert "都是 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準" in md
    for w in FORBIDDEN:
        assert w not in md
