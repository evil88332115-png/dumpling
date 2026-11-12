"""uefi_gfx.py（BIOS 映像的 UEFI 內容裡找 Intel GOP 驅動、獨立 VBT、legacy VBIOS）與 x86_firmware.py 的接線。
全部用測試自己組的合成 FV（FV 標頭＋FFS＋section，含 LZMA 包層與巢狀 FV），不含任何真實映像的位元組。
走訪靠 C1 的 uefi_image.py（Scan 子類別），介面契約另見 test_uefi_image_contract.py。"""
import hashlib
import lzma
import struct
import sys
import time
import uuid
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import intel_vbios as iv  # noqa: E402
import uefi_image as ui  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_coreboot_cbfs import vbt_blob  # noqa: E402
from test_vbios_intel import NAME, fake_pe, intel_vbios, u16  # noqa: E402
from test_x86_firmware import LZMA, comp, fv, guided, sec, secs, spi_image  # noqa: E402

gfx = xf.load_sibling("uefi_gfx")
GOP_GUID = "A1B2C3D4-0000-4000-8000-000000000001"
VBT_GUID = "A1B2C3D4-0000-4000-8000-000000000002"
ROM_GUID = "A1B2C3D4-0000-4000-8000-000000000003"
SUBTYPE = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes_le


def props(c, name):
    return [p["value"] for p in c["properties"] if p["name"] == name]


def gop_pe(build="1070"):
    return fake_pe(body=NAME + b"\0" * 0x60 + u16(build) + u16("Intel(R) Graphics Controller"))


def ffs_g(guid, body, ftype=0x07):
    """指定 GUID 的 FFS 檔案（EFI_FFS_FILE_HEADER 0x18；uefi_image 不檢查 state）。"""
    return uuid.UUID(guid).bytes_le + b"\x00\x00" + bytes([ftype, 0]) + (0x18 + len(body)).to_bytes(3, "little") + b"\xf8" + body


def lzma_sec(inner):
    return guided(LZMA, lzma.compress(inner, format=lzma.FORMAT_ALONE))


def walk(data, **kw):
    return gfx.scan(data, **kw)


def ui_name(name):
    return sec(0x15, (name + "\0").encode("utf-16-le"))


# ---------- 走訪：GOP、VBT ----------

def test_gop_in_pe32_section_is_found_with_module_and_version():
    r = walk(fv([ffs_g(GOP_GUID, secs(sec(0x10, gop_pe()), ui_name("IntelGop")))]))
    assert r["performed"] and len(r["gop"]) == 1
    g = r["gop"][0]
    assert g["version"] == "1070" and g["name"] == "Intel(R) GOP Driver" and g["machine"] == "x64"
    pe = gop_pe()
    assert g["sha256"] == hashlib.sha256(pe).hexdigest() and g["size"] == len(pe) and g["sha512"] == hashlib.sha512(pe).hexdigest()
    assert g["found"] == [{"module": GOP_GUID, "offset": 0, "ui_name": "IntelGop"}]       # UI 名稱在內容之後，walk 結束後用 GUID 對回去
    assert r["vbt"] == []


def test_gop_in_freeform_subtype_guid_section_has_16_byte_prefix():
    r = walk(fv([ffs_g(GOP_GUID, sec(0x18, SUBTYPE + gop_pe()), ftype=0x02)]))
    assert len(r["gop"]) == 1 and r["gop"][0]["found"][0]["offset"] == 16
    assert r["gop"][0]["sha256"] == hashlib.sha256(gop_pe()).hexdigest()          # 雜湊不含子類型 GUID


def test_gop_inside_lzma_section_and_nested_lzma_fv():
    leaf = fv([ffs_g(GOP_GUID, sec(0x10, gop_pe("2222")))])
    mid = lzma_sec(secs(sec(0x17, leaf)))                                           # LZMA 裡的 FV image section 裡的 FV
    r = walk(fv([ffs_g(VBT_GUID, secs(mid), ftype=0x0B), ffs_g(ROM_GUID, secs(lzma_sec(secs(sec(0x10, gop_pe("3333"))))))]))
    assert sorted(g["version"] for g in r["gop"]) == ["2222", "3333"]
    assert r["stats"]["decompressed_total"] > 0 and r["stats"]["fvs"] == 2


def test_not_a_gop_is_not_listed():
    other = fake_pe(body=u16("Some Other Driver") + b"\0" * 8 + u16("1070"))
    app = fake_pe(subsystem=2, body=NAME + u16("1"))                                 # 不是 EFI subsystem
    r = walk(fv([ffs_g(GOP_GUID, secs(sec(0x10, other), sec(0x10, app)))]))
    assert r["gop"] == [] and r["performed"]


def test_standalone_vbt_listed_but_embedded_vbt_is_not():
    v = vbt_blob(100, 243, b"$VBT TIGERLAKE")[:600]
    embedded = b"\xff" * 64 + vbt_blob(100, 223, b"$VBT ICELAKE")
    r = walk(fv([ffs_g(VBT_GUID, secs(sec(0x19, v + b"\xff" * 20), ui_name("IntelGopVbt"))),
                 ffs_g(ROM_GUID, sec(0x19, embedded), ftype=0x01)]))
    assert len(r["vbt"]) == 1
    t = r["vbt"][0]
    assert (t["signature"], t["version"], t["bdb_version"], t["vbt_size"]) == ("$VBT TIGERLAKE", "1.00", "2.43", 600)
    assert t["sha256"] == hashlib.sha256(v).hexdigest()                              # 雜湊只涵蓋 vbt_size（不含後面的填充）
    assert t["found"] == [{"module": VBT_GUID, "offset": 0, "ui_name": "IntelGopVbt"}]


def test_duplicates_are_listed_once_with_all_locations():
    fvdata = fv([ffs_g(GOP_GUID, sec(0x10, gop_pe())), ffs_g(VBT_GUID, sec(0x10, gop_pe())),
                 ffs_g(ROM_GUID, secs(lzma_sec(secs(sec(0x10, gop_pe())))))])
    fvdata += b"\xff" * (-len(fvdata) % 8)                                           # 第二個 FV 要 8 bytes 對齊
    r = walk(fvdata + fvdata)                                                        # 備份 FV：位元組完全相同
    assert r["stats"]["fvs"] == 2
    assert len(r["gop"]) == 1 and {w["module"] for w in r["gop"][0]["found"]} == {GOP_GUID, VBT_GUID, ROM_GUID}
    assert r["stats"]["duplicate_blocks"] >= 5 and r["stats"]["inspected_blocks"] < 8


# ---------- 完整性：沒解開、上限、失敗都要記 GAP ----------

def test_clean_walk_is_complete_and_says_nothing_is_missing():
    r = walk(fv([ffs_g(GOP_GUID, sec(0x10, gop_pe()))]))
    assert r["complete"] and r["gaps"] == [] and r["stopped"] is None


def test_efi_standard_compressed_section_makes_the_walk_incomplete():
    r = walk(fv([ffs_g(GOP_GUID, secs(comp(1, b"\x33" * 40), sec(0x10, gop_pe())))]))
    assert len(r["gop"]) == 1 and not r["complete"]                                  # 找到的照樣列出，但不能說「其他地方沒有」
    assert any("not decoded" in x and "EFI_STANDARD_COMPRESSION" in x and "not found does not mean absent" in x for x in r["gaps"])


def test_bytes_outside_the_top_level_fv_are_info_not_a_gap():
    r = walk(b"\x00" * 0x100 + b"firmware descriptor, ME and so on " * 20 + fv([ffs_g(GOP_GUID, sec(0x10, gop_pe()))]))
    assert r["complete"] and r["stats"]["outside_fv_nonblank_bytes"] > 0 and len(r["gop"]) == 1


def test_nesting_deeper_than_the_walker_limit_is_a_gap():
    inner = fv([ffs_g(GOP_GUID, sec(0x10, gop_pe()))])
    for _ in range(ui.MAX_DEPTH + 1):
        inner = fv([ffs_g(VBT_GUID, lzma_sec(secs(sec(0x17, inner))))])
    r = walk(inner)
    assert r["gop"] == [] and not r["complete"] and any("deeper than" in x for x in r["gaps"])


def test_walker_stop_is_recorded(monkeypatch):
    monkeypatch.setattr(ui, "MAX_FILES", 2)
    r = walk(fv([ffs_g(GOP_GUID, sec(0x10, gop_pe())) for _ in range(5)]))
    assert not r["complete"] and r["stopped"].startswith("limit reached") and any("incomplete" in x for x in r["gaps"])


def test_unexpected_exception_is_a_gap_not_a_crash():
    def boom(body, module):
        raise RuntimeError("x")
    r = walk(fv([ffs_g(ROM_GUID, sec(0x19, b"PCIR" * 8))]), find_roms=boom)
    assert not r["complete"] and r["stopped"] == "UEFI walk failed (RuntimeError)"


def test_soft_exception_is_stopped_early_with_a_gap():
    class Over(Exception):
        pass

    def over(body, module):
        raise Over("time")
    r = walk(fv([ffs_g(ROM_GUID, sec(0x19, b"PCIR" * 8))]), find_roms=over, soft=(Over,))
    assert r["stopped"] == "stopped early: time" and not r["complete"]


def test_budget_is_checked_for_each_block():
    class B:
        n = 0

        def check(self):
            self.n += 1
    b = B()
    walk(fv([ffs_g(GOP_GUID, sec(0x10, gop_pe())), ffs_g(VBT_GUID, sec(0x10, gop_pe("9")))]), budget=b)
    assert b.n >= 2


def test_missing_uefi_image_is_a_gap_not_an_error(monkeypatch):
    def nope(name):
        if name == "uefi_image":
            raise ImportError("cannot load uefi_image.py")
        return sys.modules[name]
    monkeypatch.setattr(gfx, "_sibling", nope)
    r = walk(fv([ffs_g(GOP_GUID, sec(0x10, gop_pe()))]))
    assert not r["performed"] and not r["complete"] and "not performed" in r["reason"] and r["gaps"]


def test_no_firmware_volume_found_is_a_gap():
    r = walk(b"\x00" * 4096 + b"not a firmware volume")
    assert r["performed"] and not r["complete"] and any("no valid UEFI firmware volume" in x for x in r["gaps"])


# ---------- 大輸入：不放大 ----------

def test_raw_fallback_and_duplicates_do_not_multiply_the_work():
    junk = (b"$VBT " + b"PCIR" + b"MZ" + b"\x55\xaa") * (1 << 18)                    # 約 2.5 MB，滿是各種特徵
    body = sec(0x19, junk)
    t = time.monotonic()
    r = walk(fv([ffs_g(GOP_GUID, body, ftype=0x01), ffs_g(VBT_GUID, body, ftype=0x01), ffs_g(ROM_GUID, junk, ftype=0x01)]), find_roms=lambda b, m: None)
    assert time.monotonic() - t < 20
    assert r["stats"]["inspected_bytes"] <= 3 * len(junk) + 4096                      # 同一份內容只辨識一次（section 內容、FFS 整塊當原始內容各一份）
    assert r["gop"] == [] and r["vbt"] == []


def test_inspect_cap_is_a_gap(monkeypatch):
    monkeypatch.setattr(gfx, "MAX_INSPECT", 4096)
    r = walk(fv([ffs_g(GOP_GUID, sec(0x10, gop_pe(str(i)))) for i in range(20)]))
    assert r["stats"]["inspected_bytes"] <= 4096 and not r["complete"] and any("was not searched" in x for x in r["gaps"])


def test_deep_lzma_nesting_scans_each_layer_once():
    leaf = b"A" * 100_000
    inner = fv([ffs_g(GOP_GUID, sec(0x19, leaf), ftype=0x01)])
    for _ in range(2):                                                                  # 在 MAX_DEPTH 之內的巢狀
        inner = fv([ffs_g(VBT_GUID, lzma_sec(secs(sec(0x17, inner))))])
    r = walk(inner)
    assert r["stats"]["inspected_bytes"] <= 3 * len(leaf) + 8192 and r["stats"]["decompressed_total"] <= 3 * len(inner) + 3 * len(leaf)


# ---------- 接線：inventory／SBOM ----------

def bios_with(fvdata):
    img = bytearray(spi_image())
    img[0xC100:0xC100 + len(fvdata)] = fvdata
    return bytes(img)


def sbom_of(tmp_path, data, name="BIOS.bin"):
    p = tmp_path / name
    p.write_bytes(data)
    inv = xf.inventory([p])
    comps, deps = xf.components(inv)
    doc = xf.bom(comps, deps)
    assert not list(cdx_validator().iter_errors(doc))
    return inv, comps, deps


def full_fv():
    rom = intel_vbios(vbt=vbt_blob(100, 223, b"$VBT FAKEPLAT"))
    return fv([ffs_g(GOP_GUID, secs(sec(0x10, gop_pe()), ui_name("GopDrv"))),
               ffs_g(VBT_GUID, secs(sec(0x19, vbt_blob(100, 243, b"$VBT FAKEPLAT")[:600]), ui_name("GopVbt"))),
               ffs_g(ROM_GUID, secs(lzma_sec(secs(sec(0x18, SUBTYPE + rom)))), ftype=0x02)])      # legacy VBIOS 在 LZMA 裡的子類型 section


def test_inventory_adds_gop_vbt_and_legacy_vbios_under_the_bios_image(tmp_path):
    inv, comps, deps = sbom_of(tmp_path, bios_with(full_fv()))
    by = {c["name"]: c for c in comps}
    bios = next(c for c in comps if c["name"] == "BIOS.bin")
    gop = by["Intel GOP driver"]
    assert gop["version"] == "1070" and gop["manufacturer"] == {"name": "Intel Corporation"}
    assert [h["alg"] for h in gop["hashes"]] == ["SHA-256", "SHA-512"]
    assert gop["hashes"][0]["content"] == hashlib.sha256(gop_pe()).hexdigest()
    assert props(gop, "dumpling:vuln-assessment") == ["NOT_ASSESSED"] and props(gop, "dumpling:version-status") == ["OK"]
    assert props(gop, "dumpling:vuln-assessment-note") == [xf.ASSESS_NOTES["intel"]]
    assert "build number only" in props(gop, "sca-center:version-basis")[0]
    assert props(gop, "sca-center:found-in") == [f"UEFI module {GOP_GUID} (GopDrv), offset 0x0 in the section content"]
    vbt = by["Intel VBT (Video BIOS Table)"]
    assert vbt["version"] == "1.00" and props(vbt, "sca-center:vbt-signature") == ["$VBT FAKEPLAT"]
    assert props(vbt, "dumpling:vuln-assessment-note") == [xf.ASSESS_NOTES["vbt"]]
    vb = by["Intel legacy VBIOS (option ROM)"]
    assert vb["version"] == "4321 PC 15.67" and props(vb, "dumpling:version-status") == ["OK"]
    assert props(vb, "sca-center:found-in") == [f"{inv['bios'][0]['locations'][0]}{xf.UEFI_GFX_SEP}{ROM_GUID} @0x10"]
    assert {c["bom-ref"] for c in (gop, vbt, vb)} <= set(deps[bios["bom-ref"]])      # 全部掛在 BIOS 映像底下
    # 沒有整體 PASS 或「安全」
    assert not any(w in str(comps) for w in ("PASS", "安全", "secure"))


def test_gop_without_a_readable_version_is_gap_without_version(tmp_path):
    pe = fake_pe(body=NAME + b"\0" * 0x600 + u16("1070"))                               # 版本字串超出範圍
    _, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_g(GOP_GUID, sec(0x10, pe))])))
    gop = next(c for c in comps if c["name"] == "Intel GOP driver")
    assert "version" not in gop and props(gop, "dumpling:version-status") == ["GAP"] and "version not read" in props(gop, "sca-center:gap")[0]


def test_incomplete_walk_shows_gap_on_the_bios_image_and_attention(tmp_path):
    fvdata = fv([ffs_g(GOP_GUID, secs(comp(1, b"\x33" * 40), sec(0x10, gop_pe())))])
    inv, comps, _ = sbom_of(tmp_path, bios_with(fvdata))
    bios = next(c for c in comps if c["name"] == "BIOS.bin")
    assert any("not decoded" in x and "not found does not mean absent" in x for x in props(bios, "sca-center:gap"))
    assert props(bios, "sca-center:uefi-gfx-search")[0].startswith("incomplete (not found does not mean absent)")
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "搜尋不完整" in detail and "沒找到不代表不存在" in detail
    assert "UEFI 內的 Intel 顯示韌體（GOP／VBT／legacy VBIOS）" in xf.markdown(inv)


def test_complete_walk_without_gfx_firmware_says_so_and_stays_ok_on_this_part(tmp_path):
    inv, comps, _ = sbom_of(tmp_path, bios_with(fv([ffs_g(GOP_GUID, sec(0x10, b"MZ" + b"\0" * 30))])))
    bios = next(c for c in comps if c["name"] == "BIOS.bin")
    assert props(bios, "sca-center:uefi-gfx-search")[0].startswith("complete (all firmware volumes found were decoded)")
    assert not any("GOP" in x for x in props(bios, "sca-center:gap"))
    assert "Intel GOP driver" not in {c["name"] for c in comps}
    assert "沒有找到 Intel GOP 驅動或獨立 VBT（找到的 firmware volume 都解開了" in xf.markdown(inv)


def test_same_image_in_two_files_is_walked_once(tmp_path, monkeypatch):
    calls = []
    real = gfx.scan
    monkeypatch.setattr(gfx, "scan", lambda *a, **k: calls.append(1) or real(*a, **k))
    data = bios_with(full_fv())
    for n in ("one.bin", "two.bin"):
        (tmp_path / n).write_bytes(data)
    inv = xf.inventory([tmp_path / "one.bin", tmp_path / "two.bin"])
    assert len(calls) == 1 and len(inv["bios"]) == 1 and len(inv["bios"][0]["locations"]) == 2
    comps, deps = xf.components(inv)
    assert len([c for c in comps if c["name"] == "Intel GOP driver"]) == 1
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))


def test_image_without_firmware_volume_but_with_cbfs_or_uefi_evidence_is_not_searched_gap():
    b = {"uefi": {"volumes": 0}, "evidence": ["cbfs"], "gaps": [], "file": "x"}
    xf.uefi_gfx_search(b, "x", b"", None, {}, [])
    assert b["uefi_gfx"]["performed"] is False and b["gaps"] == [b["uefi_gfx"]["reason"]] and "not searched" in b["gaps"][0]
    assert xf.uefi_gfx_status(b)
    other = {"uefi": {"volumes": 0}, "evidence": ["microcode"], "gaps": [], "file": "x"}      # UEFI／coreboot 以外：不加
    xf.uefi_gfx_search(other, "x", b"", None, {}, [])
    assert "uefi_gfx" not in other and other["gaps"] == []


def test_missing_uefi_image_gives_gap_in_sbom(tmp_path, monkeypatch):
    real = gfx._sibling
    monkeypatch.setattr(gfx, "_sibling", lambda n: (_ for _ in ()).throw(ImportError("x")) if n == "uefi_image" else real(n))
    inv, comps, _ = sbom_of(tmp_path, bios_with(full_fv()))
    bios = next(c for c in comps if c["name"] == "BIOS.bin")
    assert props(bios, "sca-center:uefi-gfx-search") == ["not performed"] and any("not performed" in x for x in props(bios, "sca-center:gap"))
    assert xf.status_of(inv)[0] == "ATTENTION"


# ---------- legacy VBIOS 的位置：前綴要接分隔符 ----------

def test_legacy_vbios_parent_uses_prefix_with_separator():
    rom = intel_vbios()
    roms = xf.option_roms(rom)
    store = {}
    xf.intel_gfx_collect(roms, rom, "a.bin2" + xf.UEFI_GFX_SEP + "GUID", store)
    inv = {"bios": [{"sha256": "a" * 64, "locations": ["a.bin"]}, {"sha256": "b" * 64, "locations": ["a.bin2"]}], "intel_vbios": list(store.values())}
    comps, deps = [], {}
    xf.intel_gfx_components(inv, comps, deps)
    assert deps == {f"{xf.REF}bios:{'b' * 16}": [comps[0]["bom-ref"]]}                  # a.bin 不是 a.bin2 的父
    # 位置剛好等於映像的位置（外層掃描找到的）也掛上；不接分隔符的前綴不算
    store2 = {}
    xf.intel_gfx_collect(roms, rom, "a.bin", store2)
    xf.intel_gfx_collect(roms, rom, "a.binX!uefi/G", store2)
    inv2 = {"bios": [{"sha256": "a" * 64, "locations": ["a.bin"]}], "intel_vbios": list(store2.values())}
    comps, deps = [], {}
    xf.intel_gfx_components(inv2, comps, deps)
    assert deps == {f"{xf.REF}bios:{'a' * 16}": [comps[0]["bom-ref"]]}                  # 同一個 ROM 兩個位置、只有一個對得上：掛一次
    inv3 = {"bios": [{"sha256": "a" * 64, "locations": ["a.bin"]}], "intel_vbios": [{**list(store2.values())[0], "locations": ["a.binX!uefi/G"]}]}
    comps, deps = [], {}
    xf.intel_gfx_components(inv3, comps, deps)
    assert deps == {}


def test_nested_zip_style_labels_choose_the_longest_matching_location():
    rom = intel_vbios()
    store = {}
    xf.intel_gfx_collect(xf.option_roms(rom), rom, "p.zip!x.cap" + xf.UEFI_GFX_SEP + "G", store)
    inv = {"bios": [{"sha256": "a" * 64, "locations": ["p.zip"]}, {"sha256": "b" * 64, "locations": ["p.zip!x.cap"]}], "intel_vbios": list(store.values())}
    comps, deps = [], {}
    xf.intel_gfx_components(inv, comps, deps)
    assert list(deps) == [f"{xf.REF}bios:{'b' * 16}"]


def test_gop_driver_function_still_rejects_subtype_prefix_without_stripping():
    assert iv.gop_driver(SUBTYPE + gop_pe()) is None        # 剝掉 16 bytes 子類型 GUID 是 uefi_gfx 的事，不是 gop_driver 的


def test_legacy_vbios_in_two_ffs_files_lists_both_locations(tmp_path):
    rom = intel_vbios()
    inv, comps, deps = sbom_of(tmp_path, bios_with(fv([ffs_g(GOP_GUID, sec(0x19, rom), ftype=0x01), ffs_g(ROM_GUID, sec(0x19, rom), ftype=0x01)])))
    (v,) = inv["intel_vbios"]
    # 未壓縮的 FV：外層的整檔掃描也找得到（位置是檔案本身），FV 走訪再各記一個 `!uefi/<模組>` 位置；全部掛同一個 BIOS 映像
    assert [x.rsplit(xf.UEFI_GFX_SEP, 1)[1] for x in v["locations"] if xf.UEFI_GFX_SEP in x] == [GOP_GUID, ROM_GUID]
    vb = next(c for c in comps if c["name"] == "Intel legacy VBIOS (option ROM)")
    assert len(props(vb, "sca-center:found-in")) == 4          # 外層整檔掃描 2 處＋FV 走訪 2 處（同一個 ROM 的位置都記）
    assert vb["bom-ref"] in deps[next(c for c in comps if c["name"] == "BIOS.bin")["bom-ref"]]


def test_coreboot_cbfs_makes_the_search_incomplete(tmp_path):
    b = {"uefi": {"volumes": 1}, "evidence": ["uefi", "cbfs"], "cbfs": {"x": 1}, "gaps": [], "file": "x"}
    xf.uefi_gfx_search(b, "x", fv([ffs_g(GOP_GUID, sec(0x10, gop_pe()))]), None, {}, [])
    assert b["uefi_gfx"]["performed"] and not b["uefi_gfx"]["complete"] and len(b["uefi_gfx"]["gop"]) == 1
    assert any("CBFS" in x and "not found does not mean absent" in x for x in b["gaps"]) and xf.uefi_gfx_status(b)
