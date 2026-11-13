"""NVIDIA vBIOS 的公告比對（nvidia_vbios_advisory.py）：affected／fixed／NOT_ASSESSED 的每一種原因、表的驗證、
SBOM property、fw-inventory.md 的 vBIOS 段落、進 repo 的表。全部用合成的表與合成的 vBIOS（不連網、不含任何產品映像）；
表裡的公告編號 9001 起、CVE-2099 是假的，只用來測規則。"""
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import nvidia_vbios_advisory as nva  # noqa: E402
import synthetic_vbios as sv  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_x86_firmware import option_image, vbios_rom  # noqa: E402

REPO = HERE.parents[2]
COMMITTED = REPO / "tools" / "pilot" / "lib" / "nvidia-bulletins-gpu-firmware.json"
SCRIPT = REPO / "pipeline" / "firmware-bios.sh"
NOW = datetime.datetime(2026, 11, 14, tzinfo=datetime.timezone.utc)
FETCHED = "2026-11-13T16:52:04Z"
COMMIT = "a" * 40
NO_DATA = "no data in the database; the vendor advisory is authoritative"


def props(c, name):
    return [p["value"] for p in c["properties"] if p["name"] == name]


def row(bulletin="9001", cve="CVE-2099-0001", devices=("2489",), **kw):
    r = {"bulletin": bulletin, "cve": cve, "line": "vbios", "pci_vendor": "10de", "pci_devices": list(devices),
         "vbios_affected_below": None, "vbios_affected_max": None, "vbios_fixed_in": None,
         "reviewed": True, "reviewed_by": "測試", "reviewed_at": "2026-11-14"}
    r.update(kw)
    return r


def doc(*rows, reviewed_until="2025-09-02", mirror=True, **over):
    bulletins = sorted({r["bulletin"] for r in rows})
    d = {"schema": "sca-nvidia-bulletins-table/1", "reviewed_until": reviewed_until,
         "bulletins": [{"id": b, "cves": {}} for b in bulletins], "not_applicable": [], "rows": list(rows)}
    if mirror:
        d["mirror"] = {"commit": COMMIT, "commit_date": "2026-11-10T13:01:57Z", "fetched_utc": FETCHED}
    d.update(over)
    return d


def write(tmp_path, d, name="t.json"):
    p = tmp_path / name
    p.write_text(d if isinstance(d, str) else json.dumps(d), encoding="utf-8")
    return p


def table(tmp_path, *rows, **kw):
    return nva.load(write(tmp_path, doc(*rows, **kw)))


def vb(version="94.04.5E.00.92", device="2489", vendor="10de", **kw):
    v = {"vendor": vendor, "device": device, "version": version, "terminated": "last-flag",
         "images": [{"code_type": 0, "device": device, "vendor": vendor}, {"code_type": 3, "device": device, "vendor": vendor}]}
    v.update(kw)
    return v


def m(t, v, now=NOW):
    return nva.match_vbios(t, v, now=now)


def assert_na(r, reason):
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == reason, r
    assert NO_DATA in r["basis"] and "partner" in r["basis"]
    assert not r["bulletins"] and not r["cves"]


# ---------- affected／fixed ----------

def test_affected_below_fixed_and_boundary(tmp_path):
    t = table(tmp_path, row(vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"))
    r = m(t, vb("94.04.5E.00.92"))
    assert r["match"] == "affected" and r["bulletins"] == ["9001"] and r["cves"] == ["CVE-2099-0001"]
    assert "bulletin 9001 CVE-2099-0001" in r["basis"] and "PCI 10de:2489" in r["basis"] and "authoritative" in r["basis"]
    assert r["source"] == t.label() and "mirror commit aaaaaaaaaaaa" in r["source"] and "reviewed_until 2025-09-02" in r["source"]
    r = m(t, vb("94.04.6A.00.01"))                              # 剛好是修正版本 → fixed
    assert r["match"] == "fixed" and r["bulletins"] == ["9001"]
    assert m(t, vb("94.04.6A.00.02"))["match"] == "fixed" and m(t, vb("95.00.00.00.01"))["match"] == "fixed"
    assert m(t, vb("94.04.6A.00.00"))["match"] == "affected"     # 比修正版本低一點仍受影響（五段都比）


def test_affected_max_inclusive_and_gap(tmp_path):
    t = table(tmp_path, row(vbios_affected_max="94.04.5E.00.92", vbios_fixed_in="94.04.7F.00.01"))
    assert m(t, vb("94.04.5E.00.92"))["match"] == "affected"                  # 含上界
    r = m(t, vb("94.04.5E.00.93"))                                           # 上界與修正版本之間的空隙：不猜
    assert_na(r, "range-gap")
    assert m(t, vb("94.04.7F.00.01"))["match"] == "fixed"


def test_fixed_in_only_means_everything_below_is_affected(tmp_path):
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"))
    assert m(t, vb("93.FF.FF.FF.FF"))["match"] == "affected" and m(t, vb("94.04.00.00.01"))["match"] == "fixed"


def test_prefix_versions_compare_only_the_given_segments(tmp_path):
    t = table(tmp_path, row(vbios_affected_below="94.04", vbios_fixed_in="94.04"))
    assert m(t, vb("94.03.FF.FF.FF"))["match"] == "affected"
    assert m(t, vb("94.04.00.00.01"))["match"] == "fixed"                    # 前兩段相等 → 不低於 94.04
    t = table(tmp_path, row(vbios_affected_max="94.04"))
    assert m(t, vb("94.04.FF.00.01"))["match"] == "affected"                  # 前兩段相等 → 不高於 94.04
    assert_na(m(t, vb("94.05.00.00.01")), "range-gap")                       # 沒有 fixed_in：超過上界落在空隙


def test_hex_segments_compare_numerically_not_as_text(tmp_path):
    t = table(tmp_path, row(vbios_affected_below="94.0A.00.00.00", vbios_fixed_in="94.0A.00.00.00"))
    assert m(t, vb("94.09.FF.00.01"))["match"] == "affected"                  # 0x09 < 0x0A
    assert m(t, vb("94.10.00.00.01"))["match"] == "fixed"                     # 0x10 > 0x0A（文字比較會得到相反結果）
    assert m(t, vb("94.0a.00.00.01"))["match"] == "fixed"                     # 小寫十六進位也讀得懂


def test_several_rows_for_one_device(tmp_path):
    a = row(cve="CVE-2099-0001", vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01")
    b = row(bulletin="9002", cve="CVE-2099-0002", vbios_affected_below="94.04.50.00.01", vbios_fixed_in="94.04.50.00.01")
    t = table(tmp_path, a, b)
    r = m(t, vb("94.04.5E.00.92"))                                           # a 受影響、b 已修補
    assert r["match"] == "affected" and r["bulletins"] == ["9001"] and "9002" in " ".join(r["notes"])
    r = m(t, vb("94.04.7F.00.01"))                                           # 兩個都已修補
    assert r["match"] == "fixed" and r["bulletins"] == ["9001", "9002"] and r["cves"] == ["CVE-2099-0001", "CVE-2099-0002"]
    gapped = row(bulletin="9003", cve="CVE-2099-0003", vbios_affected_max="94.01.00.00.01", vbios_fixed_in="94.08.00.00.01")
    t = table(tmp_path, a, gapped)
    r = m(t, vb("94.04.5E.00.92"))                                           # a 受影響、另一列落在空隙：受影響，空隙加註
    assert r["match"] == "affected" and "confirm with the vendor advisory" in " ".join(r["notes"])
    assert_na(m(table(tmp_path, b, gapped), vb("94.04.7F.00.01")), "range-gap")                          # 已修補 + 空隙：不能寫 fixed


def test_device_list_and_other_devices(tmp_path):
    t = table(tmp_path, row(devices=("2489", "2488"), vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"))
    assert m(t, vb(device="2488"))["match"] == "affected"
    r = m(t, vb(device="2504"))                                              # 裝置不符：不能套用別的裝置的列
    assert_na(r, "no-row") and "10de:2504" in r["basis"]


# ---------- NOT_ASSESSED 的每一種原因 ----------

def test_no_row_and_unreviewed_row(tmp_path):
    t = table(tmp_path)
    assert_na(m(t, vb()), "no-row")
    draft = row(reviewed=False, reviewed_by=None, reviewed_at=None, pci_vendor=None, pci_devices=None)
    t = table(tmp_path, draft, row(devices=("2489",), reviewed=False, reviewed_by=None, reviewed_at=None, vbios_fixed_in="94.04.00.00.01"))
    r = m(t, vb())
    assert_na(r, "table-not-reviewed")             # 表裡有未審核的列：整張表算未經負責人確認（未審核的列不產生結果）
    assert "2 unreviewed" in r["basis"]


def test_reviewed_and_unreviewed_rows_for_the_same_device_is_not_fixed(tmp_path):
    # 同一台裝置有已審核的列（會判 fixed）與未審核的列：表還沒確認完，不能給 fixed
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"),
              row(reviewed=False, reviewed_by=None, reviewed_at=None, vbios_affected_below="94.05"))
    assert not t.confirmed
    assert_na(m(t, vb()), "table-not-reviewed")
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"))
    assert t.confirmed and m(t, vb())["match"] == "fixed"


def test_version_unreadable_and_odd_formats(tmp_path):
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"))
    for bad in (None, "", "XX.XX.XX.XX.XX", "xx.xx.xx.xx.xx", "94.04.5E.00", "94.04.5E.00.92.01", "94.04.5E.00.9", "0x94.04.5E.00.92",
                "94-04-5E-00-92", "94.04.5E.00.G2", " 94.04.5E.00.92", "94.04.5E.00.92\n", 940455, "٩٤.٠٤.5E.00.92"):
        assert_na(m(t, vb(bad)), "version-unreadable")


def test_vendor_and_device_unreadable_or_ambiguous(tmp_path):
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"))
    assert_na(m(t, vb(vendor="8086")), "vendor-mismatch")
    assert_na(m(t, vb(device="0000")), "device-unreadable")
    assert_na(m(t, vb(device="ffff")), "device-unreadable")
    assert_na(m(t, vb(device="24")), "device-unreadable")
    assert_na(m(t, vb(device=None)), "device-unreadable")
    two = vb()
    two["images"] = [{"code_type": 0, "device": "2489"}, {"code_type": 3, "device": "2504"}]
    assert_na(m(t, two), "device-ambiguous")
    only_other = vb()
    only_other["images"] = [{"code_type": 0xE0, "device": "2504"}, {"code_type": 3, "device": "2489"}]   # 非開機影像的 device 不算
    assert m(t, only_other)["match"] == "fixed"


def test_rom_incomplete(tmp_path):
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"))
    assert_na(m(t, vb(terminated="truncated")), "rom-incomplete")
    assert_na(m(t, vb(start_note="two candidates")), "rom-incomplete")


def test_table_not_reviewed(tmp_path):
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"), reviewed_until=None)
    assert_na(m(t, vb()), "table-not-reviewed")


def test_stale_or_unknown_mirror_downgrades_fixed_but_not_affected(tmp_path):
    rows = (row(vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"),)
    t = table(tmp_path, *rows)
    late = NOW + datetime.timedelta(days=nva.MAX_MIRROR_AGE_DAYS + 5)
    r = m(t, vb("94.04.6A.00.01"), now=late)
    assert r["match"] == "NOT_ASSESSED" and r["reason"] == "table-stale" and NO_DATA in r["basis"] and "too old" in r["basis"]
    assert r["bulletins"] == ["9001"]                                                             # 公告編號留著給人看，但不是 fixed
    r = m(t, vb("94.04.5E.00.92"), now=late)
    assert r["match"] == "affected" and "refresh the table" in " ".join(r["notes"])
    assert m(t, vb("94.04.6A.00.01"), now=NOW)["match"] == "fixed"                                # 沒過期就是 fixed
    nomirror = table(tmp_path, *rows, mirror=False)
    assert m(nomirror, vb("94.04.6A.00.01"))["reason"] == "table-stale"                           # 日期不明也當成過期
    assert "unknown" in nomirror.label()
    r = m(table(tmp_path), vb(), now=late)
    assert_na(r, "no-row") and "refresh the table" in " ".join(r["notes"])


# ---------- 表的驗證 ----------

def test_table_load_failures_are_table_errors(tmp_path):
    for p, reason in ((tmp_path / "missing.json", "table-unreadable"),
                      (write(tmp_path, "not json {"), "table-unreadable"),
                      (write(tmp_path, "[1, 2]", "list.json"), "table-invalid"),
                      (write(tmp_path, doc(schema="other/1"), "schema.json"), "table-invalid"),
                      (write(tmp_path, doc(reviewed_until="2026/11/10"), "date.json"), "table-invalid"),
                      (write(tmp_path, doc(row(reviewed_by=None)), "who.json"), "table-invalid")):       # C1 的 validate_table：已審核要有審核人
        with pytest.raises(nva.TableError) as ei:
            nva.load(p)
        assert ei.value.reason == reason, (p, ei.value.reason, ei.value.detail)
    (tmp_path / "dir.json").mkdir()
    with pytest.raises(nva.TableError):
        nva.load(tmp_path / "dir.json")
    real = write(tmp_path, doc(), "real.json")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(nva.TableError):                                                           # 不跟隨 symlink
        nva.load(link)
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (nva.MAX_TABLE + 1))
    with pytest.raises(nva.TableError) as ei:
        nva.load(big)
    assert "larger than limit" in ei.value.detail


@pytest.mark.parametrize("bad", [
    {"pci_vendor": "8086"}, {"pci_vendor": None}, {"pci_devices": []}, {"pci_devices": "2489"}, {"pci_devices": ["2489", "XYZ1"]},
    {"pci_devices": ["2489", "24AB"]}, {"pci_devices": [2489]},
    {"vbios_fixed_in": "94.04.XX.00.01"}, {"vbios_fixed_in": "1.8.0"}, {"vbios_fixed_in": "94.04.5E.00.92.01"},
    {"vbios_affected_below": "94.04.5E.00.92", "vbios_affected_max": "94.04.5E.00.92"},
    {"vbios_affected_below": None, "vbios_affected_max": None, "vbios_fixed_in": None},
])
def test_invalid_reviewed_row_makes_the_whole_table_invalid(tmp_path, bad):
    base = dict(vbios_fixed_in="94.04.00.00.01")
    base.update(bad)
    p = write(tmp_path, doc(row(**base)))
    with pytest.raises(nva.TableError) as ei:
        nva.load(p)
    assert ei.value.reason == "table-invalid"
    r = nva.match_vbios(ei.value, vb())                                                          # 表壞掉 → 每個 vBIOS 都是 NOT_ASSESSED，不是少算
    assert_na(r, "table-invalid") and "cannot be used" in r["basis"] and r["source"] is None


def test_c1_decimal_version_fields_are_still_validated_by_c1(tmp_path):
    with pytest.raises(nva.TableError) as ei:                                                    # C1 的欄位只收點分十進位：vBIOS 的十六進位版本不能寫在那裡
        nva.load(write(tmp_path, doc(row(vbios_fixed_in="94.04.00.00.01", fixed_in="94.04.5E.00.92"))))
    assert "validate_table" in ei.value.detail


def test_unreviewed_draft_rows_do_not_need_vbios_fields(tmp_path):
    t = table(tmp_path, {"bulletin": "9001", "cve": "CVE-2099-0001", "line": "?", "reviewed": False, "reviewed_by": None, "reviewed_at": None})
    assert len(t.unreviewed) == 1 and not t.rows


# ---------- 進 repo 的表 ----------

def test_committed_table_passes_c1_validation_and_is_not_yet_confirmed():
    t = nva.load(COMMITTED)
    c1 = nva._c1()
    text = COMMITTED.read_text(encoding="utf-8")
    d = json.loads(text)
    c1.validate_table(d)
    assert d["reviewed_until"] is None and t.mirror_commit == "98dc5d70d87f6f068c38161930fcda2ae3193bb3"      # 負責人確認前維持待審
    assert d["rows"] == [] and d["bulletins"] == []
    [na] = d["not_applicable"]
    assert na["bulletin"] == "5674" and na["reviewed"] is False and na["reviewed_by"] is None and na["reviewed_at"] is None
    assert na["preliminary_by"] == "韌體分析（C2 角色）初審，待負責人確認"                                                  # 只寫角色
    assert na["current_release_date"] == "2025-09-02T00:00:00Z" and na["csaf_fields"]
    assert "無法對應" in na["reason"] and "不適用" not in na["reason"] and "5561" in na["reason"]
    assert t.awaiting == ["5674"] and t.not_applicable == []
    assert d["mirror"]["commit_date"] == "2026-11-10T13:01:57Z" and "2025-09-02" in d["about"] and "不是鏡像 commit 的日期" in d["about"]
    assert "@" not in text and "/home/" not in text


def test_committed_table_stays_pending_for_c1_candidates():
    """負責人確認前，C1 的 candidates 要列為待審（ATTENTION），不會因為 C2 的初審就回 OK。"""
    c1 = nva._c1()
    d = json.loads(COMMITTED.read_text(encoding="utf-8"))
    mirror_entry = {"id": "5674", "year": "2025", "current_release_date": "2025-09-02T00:00:00Z", "initial_release_date": "2025-09-02T00:00:00Z"}
    [p] = c1.pending_bulletins([mirror_entry], d)
    assert "unreviewed_not_applicable" in p["reasons"] and "after_reviewed_until" in p["reasons"] and "not_in_table" not in p["reasons"]
    # 負責人確認後（reviewed=true、reviewed_until 有值）才會關掉
    done = json.loads(json.dumps(d))
    done["not_applicable"][0].update(reviewed=True, reviewed_by="負責人", reviewed_at="2026-12-01")
    done["reviewed_until"] = "2025-09-02"                                        # 看過的最新公告日期（不是鏡像的日期）
    c1.validate_table(done)
    assert c1.pending_bulletins([mirror_entry], done) == []
    assert c1.pending_bulletins([{**mirror_entry, "id": "9999"}], done)[0]["reasons"][0] == "not_in_table"        # 新公告仍會列為待審


def test_committed_table_gives_not_assessed_not_reviewed_for_every_vbios():
    t = nva.load(COMMITTED)
    for v in (vb(), vb("00.00.00.00.01", "fffe"), vb(None, "2489"), vb("94.04.5E.00.92", "2504")):
        r = m(t, v)
        if v["version"]:
            assert_na(r, "table-not-reviewed")
            assert "表尚未經負責人確認" in r["basis"] and "5674" in r["basis"]
        assert r["match"] == "NOT_ASSESSED" and NO_DATA in r["basis"], r
    assert "mirror commit 98dc5d70d87f" in t.label() and "awaiting confirmation (5674)" in t.label()
    late = NOW + datetime.timedelta(days=5000)                                       # 沒審核過的表不吃時鐘
    assert m(t, vb(), now=late) == m(t, vb(), now=NOW)


def test_never_says_safe_or_not_affected(tmp_path):
    t = table(tmp_path, row(vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"))
    for v in (vb("94.04.5E.00.92"), vb("94.04.6A.00.01"), vb(device="2504"), vb("XX.XX.XX.XX.XX")):
        r = m(t, v)
        text = (r["basis"] + " ".join(r["notes"])).lower()
        for w in ("not affected", "unaffected", "safe", "secure", "no vulnerabilit", "pass"):
            assert w not in text, (w, text)


# ---------- x86_firmware.py：SBOM、報告、狀態 ----------

def sbom(tmp_path, data, vbios_advisory, now=NOW):
    p = tmp_path / "in.bin"
    p.write_bytes(data)
    inv = xf.inventory([p], vbios_advisory=vbios_advisory, vbios_now=now)
    st, detail = xf.status_of(inv)
    inv["status"], inv["detail"] = st, detail
    comps, deps = xf.components(inv)
    d = xf.bom(comps, deps)
    assert not list(cdx_validator().iter_errors(d))
    return inv, comps, xf.markdown(inv)


def test_sbom_properties_for_affected_fixed_and_not_assessed(tmp_path):
    t = table(tmp_path, row(devices=("2489",), vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"))
    data = (vbios_rom(0x2489, "94.04.5E.00.92") + b"\x00" * 512 + vbios_rom(0x2504, "95.07.00.00.01") + b"\x00" * 512
            + option_image(0x10DE, 0x2204, 2, 0, False, b"NVIDIA VBIOS Version XX.XX.XX.XX.XX") + option_image(0x10DE, 0x2204, 1, 3, True))
    inv, comps, md = sbom(tmp_path, data, t)
    by = {c["name"]: c for c in comps if c["name"].startswith("NVIDIA VBIOS")}
    a, b = by["NVIDIA VBIOS 2489"], by["NVIDIA VBIOS 2504"]
    assert props(a, "dumpling:advisory-match") == ["affected"] and props(a, "dumpling:advisory-bulletins") == ["9001"]
    assert props(a, "dumpling:advisory-cves") == ["CVE-2099-0001"] and "mirror commit aaaaaaaaaaaa" in props(a, "dumpling:advisory-source")[0]
    assert "bulletin 9001" in props(a, "dumpling:advisory-basis")[0] and any("PCIR header" in n for n in props(a, "dumpling:advisory-note"))
    assert props(b, "dumpling:advisory-match") == ["NOT_ASSESSED"] and not props(b, "dumpling:advisory-bulletins")
    assert NO_DATA in props(b, "dumpling:advisory-basis")[0] and "reviewed_until 2025-09-02" in props(b, "dumpling:advisory-source")[0]
    for c in by.values():                                             # 狀態仍是 NOT_ASSESSED；不出現任何「沒有漏洞」的值
        assert props(c, "dumpling:vuln-assessment") == ["NOT_ASSESSED"] and props(c, "dumpling:vuln-assessment-note") == [xf.ASSESS_NOTES["nvidia-vbios"]]
    ph = by["NVIDIA VBIOS 2204"]                                      # 版本是佔位字串：讀不到版本 → NOT_ASSESSED
    assert props(ph, "dumpling:advisory-match") == ["NOT_ASSESSED"] and "version could not be read" in props(ph, "dumpling:advisory-basis")[0]
    assert len(by) == 3
    assert inv["vbios_advisory"]["status"] == "OK" and inv["vbios_advisory"]["vbios"] == len(by)
    assert inv["vbios_advisory"]["counts"]["affected"] == 1 and inv["vbios_advisory"]["source"]["not_applicable"] == []
    assert inv["vbios_advisory"]["stale"] is False
    assert not any(p["value"].startswith("Intel") for c in by.values() for p in c["properties"] if p["name"] == "dumpling:advisory-source")


def test_fixed_in_sbom(tmp_path):
    t = table(tmp_path, row(devices=("2489",), vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"))
    inv, comps, md = sbom(tmp_path, vbios_rom(0x2489, "94.04.6A.00.01"), t)
    [c] = [c for c in comps if c["name"].startswith("NVIDIA VBIOS")]
    assert props(c, "dumpling:advisory-match") == ["fixed"] and props(c, "dumpling:vuln-assessment") == ["NOT_ASSESSED"]
    assert "已修補" in md and "不代表沒有其他漏洞" in md


def test_report_section_for_vbios(tmp_path):
    t = table(tmp_path, row(devices=("2489",), vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"))
    inv, comps, md = sbom(tmp_path, vbios_rom(0x2489, "94.04.5E.00.92"), t)
    sec = md[md.index("## 公告比對"):]
    assert "### NVIDIA vBIOS（1 個）" in sec and "| 2489 | 94.04.5E.00.92 | affected" in sec and "9001" in sec and "CVE-2099-0001" in sec
    assert "合作夥伴通知" in sec and "資料庫沒有資料，以廠商公告" in sec and "沒有任何一項代表「沒有漏洞」" in sec
    assert "鏡像 commit `" + COMMIT + "`" in sec and "已審核的 vBIOS 列 1 筆" in sec and "審核到 2025-09-02" in sec
    assert "這一版沒有做" not in sec
    for w in ("PASS", "不受影響", "安全"):
        assert w not in sec, w
    # 沒有 vBIOS 的 BIOS 樣本：不多出 vBIOS 段落
    assert "NVIDIA vBIOS（" not in xf.markdown(xf.inventory([_empty(tmp_path)], vbios_advisory=t, vbios_now=NOW))


def _empty(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"\x00" * 64)
    return p


def test_no_vbios_and_no_bios_says_so(tmp_path):
    inv = xf.inventory([_empty(tmp_path)])
    sec = "\n".join(xf.advisory_markdown(inv))
    assert "沒有找到 NVIDIA vBIOS，沒有可比對的項目（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）" in sec
    assert inv["vbios_advisory"]["vbios"] == 0 and inv["vbios_advisory"]["status"] == "OK"


def test_table_gap_is_attention_and_every_vbios_is_not_assessed(tmp_path):
    err = nva.TableError("table-invalid", "validate_table: broken")
    inv, comps, md = sbom(tmp_path, vbios_rom(0x2489, "94.04.5E.00.92"), err)
    assert inv["vbios_advisory"]["status"] == "GAP" and inv["vbios_advisory"]["counts"] == {"NOT_ASSESSED": 1}
    assert inv["status"] == "ATTENTION" and "NVIDIA vBIOS 公告比對的對照表不能用" in inv["detail"]
    [c] = [c for c in comps if c["name"].startswith("NVIDIA VBIOS")]
    assert props(c, "dumpling:advisory-match") == ["NOT_ASSESSED"] and props(c, "dumpling:advisory-source") == ["advisory table not available"]
    assert "cannot be used" in props(c, "dumpling:advisory-basis")[0] and NO_DATA in props(c, "dumpling:advisory-basis")[0]
    assert "GAP（不能用）" in md[md.index("### NVIDIA vBIOS"):]


def test_match_errors_become_not_assessed_not_exceptions(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise KeyError("x")
    monkeypatch.setattr(nva, "match_vbios", boom)
    t = table(tmp_path)
    inv, comps, md = sbom(tmp_path, vbios_rom(0x2489, "94.04.5E.00.92"), t)
    [c] = [c for c in comps if c["name"].startswith("NVIDIA VBIOS")]
    assert props(c, "dumpling:advisory-match") == ["NOT_ASSESSED"] and "KeyError" in props(c, "dumpling:advisory-basis")[0]
    assert inv["vbios_advisory"]["counts"] == {"NOT_ASSESSED": 1}


def test_default_table_is_the_committed_one(tmp_path):
    inv, comps, md = sbom(tmp_path, vbios_rom(0x2489, "94.04.5E.00.92"), None)
    [c] = [c for c in comps if c["name"].startswith("NVIDIA VBIOS")]
    assert props(c, "dumpling:advisory-match") == ["NOT_ASSESSED"] and "表尚未經負責人確認" in props(c, "dumpling:advisory-basis")[0]
    assert "reviewed_until null" in props(c, "dumpling:advisory-source")[0] and inv["vbios_advisory"]["source"]["awaiting_confirmation"] == ["5674"]
    assert inv["status"] == "ATTENTION" and "公告比對的對照表不能用" not in inv["detail"] and "過期" not in inv["detail"]
    assert "表尚未經負責人確認" in md and "無法對應" in md and "不適用" not in md[md.index("### NVIDIA vBIOS"):]
    late = xf.inventory([tmp_path / "in.bin"], vbios_now=NOW + datetime.timedelta(days=5000))["vbios_advisory"]   # 沒審核過的表：不吃時鐘，也不報過期
    assert late["stale"] is False and late["counts"] == {"NOT_ASSESSED": 1}


def test_synthetic_rom_end_to_end(tmp_path):
    """合成 option ROM → pipeline/firmware-bios.sh → SBOM：每個 vBIOS 元件都有比對結果，通過 schema，沒有「沒有漏洞」的說法。"""
    rom = tmp_path / "in" / "synthetic-nvidia-option-rom.rom"
    rom.parent.mkdir()
    rom.write_bytes(sv.synthetic_rom())                                # 版本 00.00.00.00.01、裝置 fffe
    out = tmp_path / "out"
    env = {**os.environ, "TMPDIR": str(tmp_path)}
    r = subprocess.run(["bash", str(SCRIPT), str(rom), "--out", str(out)], capture_output=True, text=True, timeout=120, env=env)
    assert r.returncode == 2 and r.stdout.startswith("FIRMWARE-BIOS\tATTENTION\t"), r.stdout + r.stderr
    d = json.loads((out / "fw.cdx.json").read_text(encoding="utf-8"))
    assert not list(cdx_validator().iter_errors(d))
    [c] = d["components"]
    assert props(c, "dumpling:advisory-match") == ["NOT_ASSESSED"] and props(c, "dumpling:vuln-assessment") == ["NOT_ASSESSED"]
    assert "表尚未經負責人確認" in props(c, "dumpling:advisory-basis")[0] and NO_DATA in props(c, "dumpling:advisory-basis")[0]
    assert "mirror commit 98dc5d70d87f" in props(c, "dumpling:advisory-source")[0]
    md = (out / "fw-inventory.md").read_text(encoding="utf-8")
    assert "### NVIDIA vBIOS（1 個）" in md and "NOT_ASSESSED（資料庫沒有資料，以廠商公告為準）" in md
    inv = json.loads((out / "fw-inventory.json").read_text(encoding="utf-8"))
    assert inv["vbios_advisory"]["counts"] == {"NOT_ASSESSED": 1} and inv["vbios"][0]["advisory"]["reason"] == "table-not-reviewed"
    assert "PASS" not in r.stdout and "安全" not in r.stdout and "不受影響" not in md


# ---------- 矛盾的列、影像 vendor、多個版本字串 ----------

@pytest.mark.parametrize("kw", [
    {"vbios_affected_max": "94.05", "vbios_fixed_in": "94.04"},                      # 修正版本低於受影響上界
    {"vbios_affected_max": "94.04.5E.00.92", "vbios_fixed_in": "94.04.5E.00.92"},    # 修正版本等於受影響上界（上界含）：同一個版本又受影響又已修補
    {"vbios_affected_max": "94.04", "vbios_fixed_in": "94.04.00.00.01"},             # 上界只寫前兩段（含 94.04.FF.FF.FF）
    {"vbios_affected_below": "94.05", "vbios_fixed_in": "94.04"},                    # 修正版本低於「低於」的界線
    {"vbios_affected_below": "94.04.5E.00.92", "vbios_fixed_in": "94.04.5E.00.91"},
])
def test_contradictory_rows_make_the_table_invalid(tmp_path, kw):
    base = {"vbios_affected_below": None, "vbios_affected_max": None, "vbios_fixed_in": None}
    base.update(kw)
    with pytest.raises(nva.TableError) as ei:
        nva.load(write(tmp_path, doc(row(**base))))
    assert ei.value.reason == "table-invalid" and "contradictory" in ei.value.detail
    assert_na(nva.match_vbios(ei.value, vb()), "table-invalid")


@pytest.mark.parametrize("kw", [
    {"vbios_affected_below": "94.04", "vbios_fixed_in": "94.04"},                    # 一般的「prior to X、fixed in X」
    {"vbios_affected_below": "94.04", "vbios_fixed_in": "94.04.00.00.01"},
    {"vbios_affected_max": "94.04.5E.00.92", "vbios_fixed_in": "94.04.5E.00.93"},
    {"vbios_affected_max": "94.04", "vbios_fixed_in": "94.05"},
    {"vbios_affected_max": "94.04"}, {"vbios_affected_below": "94.04"}, {"vbios_fixed_in": "94.04"},
])
def test_consistent_rows_are_accepted(tmp_path, kw):
    base = {"vbios_affected_below": None, "vbios_affected_max": None, "vbios_fixed_in": None}
    base.update(kw)
    assert nva.load(write(tmp_path, doc(row(**base)))).rows


def test_unreviewed_contradictory_draft_rows_are_not_checked(tmp_path):
    draft = row(reviewed=False, reviewed_by=None, reviewed_at=None, vbios_affected_max="94.05", vbios_fixed_in="94.04")
    assert nva.load(write(tmp_path, doc(draft))).unreviewed


def test_every_boot_image_must_be_nvidia(tmp_path):
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"))
    assert m(t, vb())["match"] == "fixed"
    odd = vb()
    odd["images"] = [{"code_type": 0, "device": "2489", "vendor": "10de"}, {"code_type": 3, "device": "2489", "vendor": "8086"}]
    assert_na(m(t, odd), "vendor-mismatch")
    odd["images"] = [{"code_type": 0, "device": "2489", "vendor": "8086"}, {"code_type": 3, "device": "2489", "vendor": "10de"}]
    assert_na(m(t, odd), "vendor-mismatch")
    other = vb()
    other["images"] = [{"code_type": 0xE0, "device": "2489", "vendor": "8086"}, {"code_type": 3, "device": "2489", "vendor": "10de"}]   # 非開機影像不算
    assert m(t, other)["match"] == "fixed"
    assert_na(m(t, vb(vendor="8086")), "vendor-mismatch")


def rom_with_versions(*versions, vendor2=0x10DE):
    text = b"NVIDIA VBIOS Version " + b" and ".join(x.encode() for x in versions)
    return option_image(0x10DE, 0x2489, 2, 0, False, text) + option_image(vendor2, 0x2489, 1, 3, True)


def test_rom_with_two_different_version_strings_is_never_fixed(tmp_path):
    t = table(tmp_path, row(devices=("2489",), vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"))
    inv, comps, md = sbom(tmp_path, rom_with_versions("94.04.6A.00.01", "94.04.5E.00.92"), t)
    [v] = inv["vbios"]
    assert v["version"] == "94.04.6A.00.01" and v["other_versions"] == ["94.04.5E.00.92"]
    assert v["advisory"]["match"] == "NOT_ASSESSED" and v["advisory"]["reason"] == "version-ambiguous" and NO_DATA in v["advisory"]["basis"]
    [c] = [c for c in comps if c["name"].startswith("NVIDIA VBIOS")]
    assert props(c, "dumpling:advisory-match") == ["NOT_ASSESSED"] and any("more than one" in x for x in props(c, "sca-center:note"))
    # 同一個字串重複出現不算多個；只有一個版本字串時行為不變（沒有 other_versions 這個鍵）
    inv, comps, md = sbom(tmp_path, rom_with_versions("94.04.6A.00.01", "94.04.6A.00.01"), t)
    assert "other_versions" not in inv["vbios"][0] and inv["vbios"][0]["advisory"]["match"] == "fixed"
    [c] = [c for c in comps if c["name"].startswith("NVIDIA VBIOS")]
    assert not props(c, "sca-center:note")
    inv, _, _ = sbom(tmp_path, vbios_rom(0x2489, "94.04.6A.00.01"), t)
    assert "other_versions" not in inv["vbios"][0]


def test_rom_whose_second_image_has_another_vendor_is_not_matched(tmp_path):
    t = table(tmp_path, row(devices=("2489",), vbios_fixed_in="94.04.00.00.01"))
    inv, _, _ = sbom(tmp_path, rom_with_versions("94.04.6A.00.01", vendor2=0x8086), t)
    for v in inv["vbios"]:
        assert v["advisory"]["match"] != "fixed" or all(i["vendor"] == "10de" for i in v["images"])


# ---------- 過期（時鐘）----------

FETCHED_DT = datetime.datetime(2026, 11, 13, 16, 52, 4, tzinfo=datetime.timezone.utc)


@pytest.mark.parametrize("days,stale", [(0, False), (1, False), (45, False), (89, False), (90, False), (90.0001, True), (91, True), (400, True),
                                        (-0.5, False), (-1, False), (-1.01, True), (-30, True)])
def test_stale_boundaries(tmp_path, days, stale):
    t = table(tmp_path, row(vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"))
    now = FETCHED_DT + datetime.timedelta(days=days)
    assert t.stale(now) is stale
    r = m(t, vb("94.04.6A.00.01"), now=now)
    assert (r["reason"] == "table-stale") is stale and r["match"] == ("NOT_ASSESSED" if stale else "fixed")
    r = m(t, vb("94.04.5E.00.92"), now=now)
    assert r["match"] == "affected" and any("refresh the table" in n for n in r["notes"]) is stale


def test_naive_now_and_naive_fetched_do_not_raise(tmp_path):
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"))
    assert m(t, vb(), now=datetime.datetime(2026, 11, 14))["match"] == "fixed"                         # 沒有時區的 now 當成 UTC
    assert t.stale(datetime.datetime(2027, 6, 1)) is True
    d = doc(row(vbios_fixed_in="94.04.00.00.01"))
    # 沒有時區或讀不到的 fetched_utc 是格式錯誤：C1 的 validate_table 擋下 → table-invalid（M7a2 與 C1 約定；原本當成過期 table-stale）
    for bad in ("2026-11-13T16:52:04", "2026-11-13", "yesterday", 12, None, "9999-99-99T00:00:00Z"):
        d["mirror"]["fetched_utc"] = bad
        with pytest.raises(nva.TableError) as ei:
            nva.load(write(tmp_path, d, "b.json"))
        assert ei.value.reason == "table-invalid" and "fetched_utc" in ei.value.detail
        assert m(ei.value, vb())["match"] == "NOT_ASSESSED"


def test_mirror_with_keys_missing_is_invalid_and_without_mirror_is_stale(tmp_path):
    """mirror 有寫：commit、commit_date、fetched_utc 三個都要有（缺一個、null 都是 table-invalid）；整個沒寫或 null 才是 table-stale。"""
    for key in ("commit", "commit_date", "fetched_utc"):                                                # mirror 有寫：三個鍵都要有，缺一個（含 null）是 table-invalid
        for how in ("absent", "null"):
            d = doc(row(vbios_fixed_in="94.04.00.00.01"))
            if how == "absent":
                del d["mirror"][key]
            else:
                d["mirror"][key] = None
            with pytest.raises(nva.TableError) as ei:
                nva.load(write(tmp_path, d, "k.json"))
            assert ei.value.reason == "table-invalid" and f"mirror.{key}" in ei.value.detail, (key, how)
    for bad in ("x", 5, [], "", False):                                                                # mirror 不是物件
        d = doc(row(vbios_fixed_in="94.04.00.00.01"))
        d["mirror"] = bad
        with pytest.raises(nva.TableError) as ei:
            nva.load(write(tmp_path, d, "str.json"))
        assert ei.value.reason == "table-invalid"
    d = doc(row(vbios_fixed_in="94.04.00.00.01"), mirror=False)                                         # 整個沒寫：日期不明，table-stale
    assert m(nva.load(write(tmp_path, d, "nomirror.json")), vb())["reason"] == "table-stale"
    d["mirror"] = None                                                                                  # null：同樣是整個沒寫
    assert m(nva.load(write(tmp_path, d, "nullmirror.json")), vb())["reason"] == "table-stale"


def test_note_texts_for_stale_gap_and_fixed(tmp_path):
    a = row(cve="CVE-2099-0001", vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01")
    b = row(bulletin="9002", cve="CVE-2099-0002", vbios_affected_below="94.04.50.00.01", vbios_fixed_in="94.04.50.00.01")
    g = row(bulletin="9003", cve="CVE-2099-0003", vbios_affected_max="94.01.00.00.01", vbios_fixed_in="94.08.00.00.01")
    late = NOW + datetime.timedelta(days=200)
    r = m(table(tmp_path, a, b, g), vb("94.04.5E.00.92"), now=late)
    notes = " | ".join(r["notes"])
    assert r["match"] == "affected" and "refresh the table" in notes and "confirm with the vendor advisory" in notes and "already at or above the fixed version" in notes
    assert "PCIR header" in notes
    r = m(table(tmp_path, b), vb("94.04.5E.00.92"), now=NOW)
    assert r["match"] == "fixed" and "PCIR header" in " ".join(r["notes"]) and "refresh" not in " ".join(r["notes"])


def test_affected_below_alone_at_the_boundary(tmp_path):
    t = table(tmp_path, row(vbios_affected_below="94.04.5E.00.92"))
    assert m(t, vb("94.04.5E.00.91"))["match"] == "affected"
    assert_na(m(t, vb("94.04.5E.00.92")), "range-gap")                                                 # 剛好是界線、沒有修正版本：不猜
    assert_na(m(t, vb("94.04.5E.00.93")), "range-gap")


def test_not_applicable_without_a_reviewed_key(tmp_path):
    ok = {"bulletin": "9005", "reviewed_by": "負責人", "reviewed_at": "2026-11-14"}                  # 沒有 reviewed 鍵：C1 當成已審核，要有審核人與日期
    t = nva.load(write(tmp_path, doc(not_applicable=[ok])))
    assert t.not_applicable == ["9005"] and t.awaiting == []
    with pytest.raises(nva.TableError) as ei:
        nva.load(write(tmp_path, doc(not_applicable=[{"bulletin": "9005"}]), "na.json"))
    assert ei.value.reason == "table-invalid"
    t = nva.load(write(tmp_path, doc(not_applicable=[{"bulletin": "9005", "reviewed": False}]), "na2.json"))
    assert t.not_applicable == [] and t.awaiting == ["9005"]


def test_stale_table_makes_the_status_attention_only_with_vbios(tmp_path):
    t = table(tmp_path, row(devices=("2489",), vbios_fixed_in="94.04.00.00.01"))
    late = NOW + datetime.timedelta(days=400)
    inv, comps, md = sbom(tmp_path, vbios_rom(0x2489, "94.04.6A.00.01"), t, now=late)
    assert inv["vbios_advisory"]["stale"] is True and inv["status"] == "ATTENTION" and "NVIDIA vBIOS 公告對照表過期" in inv["detail"]
    assert "對照表過期" in md and "table-stale" in md
    [c] = [c for c in comps if c["name"].startswith("NVIDIA VBIOS")]
    assert props(c, "dumpling:advisory-match") == ["NOT_ASSESSED"]
    inv, _, _ = sbom(tmp_path, vbios_rom(0x2489, "94.04.6A.00.01"), t, now=NOW)
    assert inv["vbios_advisory"]["stale"] is False and "過期" not in inv["detail"]
    inv = xf.inventory([_empty(tmp_path)], vbios_advisory=t, vbios_now=late)                          # 沒有 vBIOS：狀態不受影響
    assert "過期" not in xf.status_of(inv)[1]
    future = FETCHED_DT - datetime.timedelta(days=3)
    inv, _, _ = sbom(tmp_path, vbios_rom(0x2489, "94.04.6A.00.01"), t, now=future)                    # 鏡像日期在未來：也當成過期
    assert inv["vbios_advisory"]["stale"] is True


# ---------- fail-closed、確認流程、報告與 property 的細節 ----------

def test_missing_terminated_key_is_incomplete_not_complete(tmp_path):
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"))
    v = vb()
    del v["terminated"]
    assert_na(m(t, v), "rom-incomplete")
    assert m(t, vb())["match"] == "fixed"


def confirmed_doc(*rows, **kw):
    """負責人確認後的表：5674 的初審意見改成 reviewed=true，reviewed_until 填看過的最新公告日期。"""
    na = {"bulletin": "5674", "current_release_date": "2025-09-02T00:00:00Z", "reason": "沒有 PCI ID 與 option ROM 版本的對應",
          "reviewed": True, "reviewed_by": "韌體負責人", "reviewed_at": "2026-11-20"}
    return doc(*rows, reviewed_until="2025-09-02", not_applicable=[na], **kw)


def test_awaiting_bulletin_keeps_the_table_unconfirmed_even_if_reviewed_until_is_set(tmp_path):
    na = {"bulletin": "5674", "reason": "初審", "reviewed": False, "reviewed_by": None, "reviewed_at": None}
    t = nva.load(write(tmp_path, doc(row(vbios_fixed_in="94.04.00.00.01"), reviewed_until="2025-09-02", not_applicable=[na])))
    assert t.confirmed is False and t.awaiting == ["5674"]
    r = m(t, vb())
    assert_na(r, "table-not-reviewed")
    assert "表尚未經負責人確認" in r["basis"] and "still unconfirmed" in r["basis"] and "5674" in r["basis"]
    late = NOW + datetime.timedelta(days=500)
    assert m(t, vb(), now=late) == r                                         # 沒確認的表不吃時鐘
    assert "awaiting confirmation (5674)" in t.label() and "not applicable" not in t.label().lower()
    t = nva.load(write(tmp_path, confirmed_doc(row(vbios_fixed_in="94.04.00.00.01")), "c.json"))
    assert t.confirmed is True and m(t, vb())["match"] == "fixed"
    assert "confirmed as not mappable to option ROM versions (5674)" in t.label() and "not applicable" not in t.label().lower()


def test_confirmed_table_report_says_confirmed_not_mappable(tmp_path):
    t = nva.load(write(tmp_path, confirmed_doc()))
    inv, comps, md = sbom(tmp_path, vbios_rom(0x2489, "94.04.5E.00.92"), t)
    [v] = inv["vbios"]
    assert v["advisory"]["reason"] == "no-row"
    sec = md[md.index("### NVIDIA vBIOS"):]
    assert "已確認無法對應到 option ROM 版本與裝置的公告：5674（技術理由見對照表）" in sec and "審核到 2025-09-02" in sec
    assert "表尚未經負責人確認" not in sec and "初審無法對應" not in sec
    assert "不適用" not in sec and "not applicable" not in sec.lower()
    assert inv["vbios_advisory"]["source"]["not_applicable"] == ["5674"] and inv["vbios_advisory"]["stale"] is False
    for x in (md, json.dumps(inv), json.dumps(comps)):
        assert "not applicable" not in x.lower() and "不適用" not in x[x.find("NVIDIA vBIOS"):]


def test_unconfirmed_table_report_says_preliminary(tmp_path):
    inv, comps, md = sbom(tmp_path, vbios_rom(0x2489, "94.04.5E.00.92"), nva.load(COMMITTED))
    sec = md[md.index("### NVIDIA vBIOS"):]
    assert "初審無法對應（待負責人確認）的公告：5674" in sec and "表尚未經負責人確認" in sec
    assert "不適用" not in sec and "not applicable" not in json.dumps(comps).lower()


def test_below_and_max_together_are_rejected(tmp_path):
    with pytest.raises(nva.TableError) as ei:
        nva.load(write(tmp_path, doc(row(vbios_affected_below="94.04", vbios_affected_max="94.03"))))
    assert "mutually exclusive" in ei.value.detail
    with pytest.raises(nva.TableError):                                       # 兩個都有、而且值互相一致也不行
        nva.load(write(tmp_path, doc(row(vbios_affected_below="94.04", vbios_affected_max="94.04", vbios_fixed_in="94.05")), "x.json"))


def test_pad_boundaries_of_the_contradiction_check(tmp_path):
    def load(**kw):
        base = {"vbios_affected_below": None, "vbios_affected_max": None, "vbios_fixed_in": None}
        base.update(kw)
        return nva.load(write(tmp_path, doc(row(**base)), "p.json"))
    with pytest.raises(nva.TableError):                                       # fixed 94.04（補 00 ＝ 94.04.00.00.00）低於 below 94.04.00.00.01
        load(vbios_affected_below="94.04.00.00.01", vbios_fixed_in="94.04")
    assert load(vbios_affected_below="94.04.00.00.00", vbios_fixed_in="94.04").rows       # 補 00 後相等：正常
    with pytest.raises(nva.TableError):                                       # fixed 94.04.00.00.00 不高於 max 94.04（補 FF）
        load(vbios_affected_max="94.04", vbios_fixed_in="94.04.00.00.00")
    assert load(vbios_affected_max="94.04", vbios_fixed_in="94.05").rows
    with pytest.raises(nva.TableError):                                       # 上界補 FF：94.04.FF.FF.FF 與 fixed 94.04.FF.FF.FF 相等也矛盾
        load(vbios_affected_max="94.04", vbios_fixed_in="94.04.FF.FF.FF")
    assert load(vbios_affected_max="94.04", vbios_fixed_in="94.05.00.00.00").rows


def test_stale_with_non_utc_aware_now(tmp_path):
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"))
    plus8 = datetime.timezone(datetime.timedelta(hours=8))
    minus5 = datetime.timezone(datetime.timedelta(hours=-5))
    edge = FETCHED_DT + datetime.timedelta(days=90)                           # 正好 90 天（UTC）
    assert t.stale(edge.astimezone(plus8)) is False and t.stale(edge.astimezone(minus5)) is False
    over = edge + datetime.timedelta(seconds=1)
    assert t.stale(over.astimezone(plus8)) is True and t.stale(over.astimezone(minus5)) is True
    assert m(t, vb(), now=edge.astimezone(plus8))["match"] == "fixed"
    # 同一個瞬間，不同時區的字面值：naive 的當成 UTC，與換算後的 aware 一致
    assert t.stale(datetime.datetime(2027, 2, 11, 16, 52, 5)) is True and t.stale(datetime.datetime(2027, 2, 11, 16, 52, 4)) is False


def test_bulletin_and_cve_properties_for_fixed_and_stale(tmp_path):
    t = table(tmp_path, row(devices=("2489",), vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01"))
    data = vbios_rom(0x2489, "94.04.6A.00.01")
    inv, comps, md = sbom(tmp_path, data, t)
    [c] = [c for c in comps if c["name"].startswith("NVIDIA VBIOS")]
    assert props(c, "dumpling:advisory-match") == ["fixed"]
    assert props(c, "dumpling:advisory-bulletins") == ["9001"] and props(c, "dumpling:advisory-cves") == ["CVE-2099-0001"]
    inv, comps, md = sbom(tmp_path, data, t, now=NOW + datetime.timedelta(days=400))                  # 過期：降成 NOT_ASSESSED，不寫公告與 CVE
    [c] = [c for c in comps if c["name"].startswith("NVIDIA VBIOS")]
    assert props(c, "dumpling:advisory-match") == ["NOT_ASSESSED"]
    assert not props(c, "dumpling:advisory-bulletins") and not props(c, "dumpling:advisory-cves")
    assert any("refresh the table" in n for n in props(c, "dumpling:advisory-note"))


def test_report_rows_and_count_line_for_affected_and_fixed(tmp_path):
    a = row(cve="CVE-2099-0001", devices=("2489",), vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01")
    b = row(bulletin="9002", cve="CVE-2099-0002", devices=("2504",), vbios_affected_below="95.00.00.00.01", vbios_fixed_in="95.00.00.00.01")
    data = vbios_rom(0x2489, "94.04.5E.00.92") + b"\x00" * 512 + vbios_rom(0x2504, "95.07.00.00.01")
    inv, comps, md = sbom(tmp_path, data, table(tmp_path, a, b))
    sec = md[md.index("### NVIDIA vBIOS"):]
    assert "- NVIDIA vBIOS 2 個：affected 1、fixed 1" in sec
    assert "| 2489 | 94.04.5E.00.92 | affected（對照表列為受影響；不是完整的漏洞判定） | 9001 | CVE-2099-0001 |" in sec
    assert "| 2504 | 95.07.00.00.01 | fixed（對照表列為已修補；不代表沒有其他漏洞） | 9002 | CVE-2099-0002 |" in sec
    assert "NOT_ASSESSED（資料庫沒有資料" not in sec.split("| PCI device")[1].split("- `")[0]
    inv2, _, md2 = sbom(tmp_path, data, table(tmp_path, a, b), now=NOW)
    assert inv2["vbios_advisory"]["counts"] == {"affected": 1, "fixed": 1}


# ---------- 公告編號格式、mirror 日期格式、報告的確認狀態、md_esc 的 @ ----------

@pytest.mark.parametrize("where", ["bulletins", "rows", "not_applicable", "unreviewed-row"])
@pytest.mark.parametrize("bad", ["@everyone", "9001@x", "&commat;", "[x](http://e)", "<b>", "", "12345678 ", "123456789", "9a", "９００１", "-1", "9001\n", " 9001"])
def test_bulletin_id_must_be_digits(tmp_path, where, bad):
    """公告編號會寫進報告與 SBOM：只收 1～8 位 ASCII 數字（與 C1 nvidia_bulletins.py 的 BULLETIN_ID_RE 相同），任何位置不合都是 table-invalid。"""
    d = doc(row(vbios_fixed_in="94.04.00.00.01"))
    if where == "bulletins":
        d["bulletins"][0]["id"] = bad
        d["rows"][0]["bulletin"] = bad                                              # C1 的 validate_table 要求 rows 的公告在 bulletins 裡
    elif where == "rows":
        d["bulletins"].append({"id": bad, "cves": {}})
        d["rows"][0]["bulletin"] = bad
    elif where == "not_applicable":
        d["not_applicable"] = [{"bulletin": bad, "reviewed": False}]
    else:
        d["bulletins"].append({"id": bad, "cves": {}})
        d["rows"].append(row(bad, "CVE-2099-0009", vbios_fixed_in="94.09.00.00.01", reviewed=False, reviewed_by=None, reviewed_at=None))
    with pytest.raises(nva.TableError) as ei:
        nva.load(write(tmp_path, d))
    assert ei.value.reason == "table-invalid" and "bulletin" in ei.value.detail
    assert nva.match_vbios(ei.value, vb(), now=NOW)["reason"] == "table-invalid"


@pytest.mark.parametrize("good", ["1", "9001", "5674", "12345678", "00123"])
def test_bulletin_id_boundaries_accepted(tmp_path, good):
    d = doc(row(good, vbios_fixed_in="94.04.00.00.01"), not_applicable=[{"bulletin": good, "reviewed": False}])
    assert nva.load(write(tmp_path, d)).rows[0]["bulletin"] == good


def test_report_confirmed_state_counts_unreviewed_rows(tmp_path):
    """「對照表」那一行：reviewed_until 有值、沒有初審意見，但還有未審核的列時也是「尚未經負責人確認」，並寫出未審核的筆數。"""
    unrev = row("9002", "CVE-2099-0002", reviewed=False, reviewed_by=None, reviewed_at=None, vbios_fixed_in="94.09.00.00.01")
    rom = vbios_rom(0x2489, "94.04.5E.00.92")
    for rows, extra, want_confirmed, want in (
            ((row(vbios_fixed_in="94.04.00.00.01"),), {}, True, None),
            ((row(vbios_fixed_in="94.04.00.00.01"), unrev), {}, False, ["還有 1 筆未審核的列"]),
            ((row(vbios_fixed_in="94.04.00.00.01"), unrev, dict(unrev, bulletin="9003", cve="CVE-2099-0003")), {}, False, ["還有 2 筆未審核的列"]),
            ((row(vbios_fixed_in="94.04.00.00.01"),), {"reviewed_until": None}, False, ["reviewed_until 為 null"]),
            ((row(vbios_fixed_in="94.04.00.00.01"), unrev), {"reviewed_until": None}, False, ["reviewed_until 為 null", "還有 1 筆未審核的列"]),
    ):
        d = doc(*rows, **extra)
        t = nva.load(write(tmp_path, d))
        assert t.confirmed is want_confirmed
        inv, comps, md = sbom(tmp_path, rom, t)
        line = [l for l in md.splitlines() if l.startswith("- 對照表：")][0]
        assert inv["vbios_advisory"]["vbios"] == 1
        if want_confirmed:
            assert "審核到 2025-09-02" in line and "尚未經負責人確認" not in line
        else:
            assert "審核到" not in line and "**表尚未經負責人確認**" in line and "所有 vBIOS 都是 NOT_ASSESSED" in line
            for w in want:
                assert w in line, (w, line)
            assert inv["vbios"][0]["advisory"]["match"] == "NOT_ASSESSED"          # 報告與比對結果一致
        assert "未審核 %d 筆" % len(t.unreviewed) in line


def test_report_awaiting_and_unreviewed_reasons_together(tmp_path):
    na = {"bulletin": "5674", "reason": "初審", "reviewed": False, "reviewed_by": None, "reviewed_at": None}
    unrev = row("9002", "CVE-2099-0002", reviewed=False, reviewed_by=None, reviewed_at=None, vbios_fixed_in="94.09.00.00.01")
    t = nva.load(write(tmp_path, doc(row(vbios_fixed_in="94.04.00.00.01"), unrev, not_applicable=[na])))
    inv, comps, md = sbom(tmp_path, vbios_rom(0x2489, "94.04.5E.00.92"), t)
    line = [l for l in md.splitlines() if l.startswith("- 對照表：")][0]
    assert "還有公告只有初審意見、還有 1 筆未審核的列" in line


def test_md_esc_defangs_mentions_email_and_bare_urls():
    z = "\u200b"
    e = xf.md_esc
    assert e("@user") == "@" + z + "user" and e("x @org/team") == "x @" + z + "org/team" and e("＠u") == "＠" + z + "u"
    assert e("a@example.com") == "a" + z + "@" + z + "example.com" and e("mailto:a@example.com") == "mailto\\:a" + z + "@" + z + "example.com"
    assert e("pkg:generic/zlib@1.2.11") == "pkg:generic/zlib@1.2.11" and e("name@host") == "name@host"
    assert e("&commat;u") == "&amp;commat;u"
    assert e("https://evil.example") == "https\\://evil.example" and e("www.evil.example") == "www\\.evil.example"
    assert e("a_b@example.org") == "a\\_b" + z + "@" + z + "example.org"                       # 跳脫前看原文：_ 不會讓網域形式漏掉
    assert e("a@b_c.com") == "a" + z + "@" + z + "b\\_c.com"
    # 原有的跳脫不變
    assert e("[x](y) <b> a|b `c` *d* #e") == "\\[x\\](y) &lt;b&gt; a\\|b \\`c\\` \\*d\\* \\#e"
    assert e("a\n  b") == "a b" and e(5) == "5"


def test_md_esc_uses_the_same_at_rules_as_firmware_mdsafe():
    import importlib.util
    spec = importlib.util.spec_from_file_location("mdsafe_for_parity", REPO / "pipeline" / "lib" / "firmware_mdsafe.py")
    ms = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ms)
    for raw in ("@u", "x@y.test", "pkg:generic/a@1.0", "a@b.c@d", "x @a.b _@u", "a＠b", "name@host", "mailto:a@b.test", "xmpp:a/b@c.test"):
        assert xf.md_esc(raw).replace("\\", "") == ms.defang_links(ms.defang_at(" ".join(raw.split()))).replace("\\", ""), raw


@pytest.mark.parametrize("text,ok", [
    ("2026-11-13T16:52:04Z", True), ("2026-11-13T16:52:04+00:00", True), ("2026-11-13T16:52:04-05:30", True),
    ("2026-11-13T16:52:04.123Z", True), ("2026-11-13T16:52:04.123456+08:00", True),
    ("2026-11-13T16:52:04+0000", False),            # Python 3.11 起 fromisoformat 才收的格式
    ("2026-11-13 16:52:04Z", False), ("2026-11-13 16:52:04+00:00", False),          # 空白分隔
    ("2026-11-13T16:52Z", False), ("2026-11-13T16Z", False),                        # 沒有秒
    ("2026-11-13T16:52:04", False), ("2026-11-13", False), ("20261113T165204Z", False),
    ("2026-11-13T16:52:04.1Z", False), ("2026-11-13T16:52:04.12Z", False), ("2026-11-13T16:52:04.1234Z", False), ("2026-11-13T16:52:04.1234567Z", False),
    ("2026-11-13T16:52:04+00", False), ("2026-11-13T16:52:04z", False), ("2026-11-13t16:52:04Z", False),
    ("2026-11-13T16:52:04Z\n", False), (" 2026-11-13T16:52:04Z", False), ("２０２６-11-13T16:52:04Z", False),
    ("2026-13-13T16:52:04Z", False), ("2026-02-30T16:52:04Z", False), ("2026-11-13T24:00:00Z", False), ("2026-11-13T16:60:04Z", False),
    ("2026-11-13T16:52:04+99:00", False), ("", False), (None, False), (5, False)])
def test_parse_utc_accepts_only_the_c1_time_format(text, ok):
    d = nva._parse_utc(text)
    assert (d is not None) is ok, text
    if ok:
        assert d.tzinfo is not None


def test_parse_utc_values():
    assert nva._parse_utc("2026-11-13T16:52:04Z") == datetime.datetime(2026, 11, 13, 16, 52, 4, tzinfo=datetime.timezone.utc)
    assert nva._parse_utc("2026-11-13T16:52:04+08:00") == datetime.datetime(2026, 11, 13, 8, 52, 4, tzinfo=datetime.timezone.utc)
    assert nva._parse_utc("2026-11-13T16:52:04.250Z").microsecond == 250000


@pytest.mark.parametrize("key,bad", [("fetched_utc", "2026-11-13T16:52:04+0000"), ("fetched_utc", "2026-11-13 16:52:04Z"), ("fetched_utc", "2026-11-13T16:52Z"),
                                     ("commit_date", "2026-11-10T13:01:57"), ("commit_date", "2026-13-10"), ("commit_date", "yesterday"), ("commit_date", 7),
                                     ("commit", "A" * 40), ("commit", "a" * 39), ("commit", "a" * 40 + "\n"), ("commit", 5)])
def test_mirror_values_must_be_well_formed(tmp_path, key, bad):
    d = doc(row(vbios_fixed_in="94.04.00.00.01"))
    d["mirror"][key] = bad
    with pytest.raises(nva.TableError) as ei:
        nva.load(write(tmp_path, d))
    assert ei.value.reason == "table-invalid" and f"mirror.{key}" in ei.value.detail


def test_format_regexes_use_fullmatch_so_a_trailing_newline_is_rejected(tmp_path):
    """Python 的 `$` 會放行字串結尾的換行：驗證格式一律 fullmatch。"""
    assert nva.parse_version("94.04.5E.00.92\n") is None and nva.parse_version("94.04.5E.00.92") is not None
    assert nva.parse_version("94\n") is None
    for devices in (["2204\n"], ["2204", "2489\n"]):
        with pytest.raises(nva.TableError) as ei:
            nva.load(write(tmp_path, doc(row(devices=devices, vbios_fixed_in="94.04.00.00.01"))))
        assert ei.value.reason == "table-invalid" and "pci_devices" in ei.value.detail
    t = table(tmp_path, row(vbios_fixed_in="94.04.00.00.01"))
    for dev in ("2489\n", "\n2489"):
        assert_na(m(t, vb(device=dev)), "device-unreadable")
    assert_na(m(t, vb("94.04.5E.00.92\n")), "version-unreadable")
    assert t.mirror_commit == COMMIT
    d = doc(row(vbios_fixed_in="94.04.00.00.01"))
    d["mirror"]["commit"] = COMMIT + "\n"
    with pytest.raises(nva.TableError):
        nva.load(write(tmp_path, d, "c.json"))
    assert nva.BULLETIN_ID_RE.pattern == r"^[0-9]{1,8}$"


def test_commit_date_may_be_a_date_like_c1_accepts(tmp_path):
    d = doc(row(vbios_fixed_in="94.04.00.00.01"))
    for ok in ("2026-11-10", "2026-11-10T13:01:57Z", "2026-11-10T13:01:57+08:00"):
        d["mirror"]["commit_date"] = ok
        assert nva.load(write(tmp_path, d)).mirror_commit_date == ok
