"""Intel 內顯 vBIOS 子元件辨識：intel_vbt.py（VBT 標頭，從 coreboot_cbfs 搬出來）、intel_vbios.py（legacy VBIOS option ROM、
GOP 驅動的辨識函式）、x86_firmware.py 的 Intel legacy VBIOS 元件。全部用測試自己組的假資料，不含任何真實映像的位元組。"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import coreboot_cbfs as cb  # noqa: E402
import intel_vbios as iv  # noqa: E402
import intel_vbt  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_coreboot_cbfs import vbt_blob  # noqa: E402
from test_x86_firmware import option_image, spi_image, vbios_rom  # noqa: E402

REPO = HERE.parents[2]
SCRIPT = REPO / "pipeline" / "firmware-bios.sh"
INTEL_NOTE = xf.ASSESS_NOTES["intel"]


def props(c, name):
    return [p["value"] for p in c["properties"] if p["name"] == name]


# ---------- 假資料 ----------

BANNER = b"Intel(R) TST Mobile/Desktop PCI Accelerated SVGA BIOS"


def build_line(num=b"4321", pc=b"15.67", when=b"01/02/2003  04:05:06"):
    return b"Build Number: " + num + b" PC " + pc + b"  " + when


def intel_vbios(did=0x0406, build=None, banner=BANNER, vbt=None, units=4, vid=0x8086):
    """假的 Intel legacy VBIOS：vendor 0x8086、class 030000、一個 x86 影像（最後一個）。內容的字串與數字都是測試自己編的。"""
    payload = b""
    if vbt is not None:
        payload += vbt + b"\0" * 4
    if banner:
        payload += banner + b"\r\n"
    payload += (build_line() if build is None else build) + b"\r\n"
    return option_image(vid, did, units, 0, True, payload)


def fake_pe(subsystem=11, machine=0x8664, body=b"", magic=0x20B):
    pe = bytearray(0x400)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", pe, 0x84, machine, 0, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", pe, 0x98, magic)
    struct.pack_into("<H", pe, 0x98 + 68, subsystem)
    return bytes(pe) + body


def u16(s):
    return s.encode("utf-16-le") + b"\0\0"


NAME = u16("Intel(R) GOP Driver")


# ---------- intel_vbt（搬出來的 parse_vbt） ----------

def test_parse_vbt_moved_and_coreboot_still_exports_it():
    assert cb.parse_vbt is intel_vbt.parse_vbt
    r = intel_vbt.parse_vbt(vbt_blob(100, 228, b"$VBT SKYLAKE"))
    assert (r["signature"], r["version"], r["bdb_version"], r["vbt_size"]) == ("$VBT SKYLAKE", "1.00", "2.28", 600)
    assert intel_vbt.parse_vbt(b"$VBT " + b"\0" * 10) is None                 # 太短
    assert intel_vbt.parse_vbt(b"x" * 100) is None                            # 不是 $VBT
    bad = bytearray(vbt_blob())
    bad[22:24] = struct.pack("<H", 10)                                         # header_size < 48
    assert intel_vbt.parse_vbt(bytes(bad)) is None


def test_find_vbt_filters_strays_and_is_bounded():
    v = vbt_blob(100, 223, b"$VBT TIGERLAKE")
    data = b"say $VBT hello " + b"\0" * 8 + v + b"\xff" * 16 + b"$VBT " * 3 + v[:30]
    found = intel_vbt.find_vbt(data)
    assert [(o, r["signature"]) for o, r in found] == [(data.index(v), "$VBT TIGERLAKE")]
    assert found[0][1]["bdb_version"] == "2.23"
    assert intel_vbt.find_vbt(b"$VBT " * 1000, limit=5) == []                  # 候選數有上限
    assert len(intel_vbt.find_vbt(v * 40, limit=40)) == 40
    assert len(intel_vbt.find_vbt(v * 40, limit=3)) <= 3
    truncated = v[:599]                                                       # vbt_size（600）超出資料
    assert intel_vbt.find_vbt(truncated) == []


# ---------- legacy VBIOS ----------

def test_legacy_info_reads_banner_build_and_embedded_vbt():
    rom = intel_vbios(vbt=vbt_blob(100, 223, b"$VBT FAKEPLAT"))
    r = iv.legacy_info(rom)
    assert r["banner"] == BANNER.decode() and r["version"] == "4321 PC 15.67"
    assert (r["build_number"], r["pc_version"], r["build_time"]) == ("4321", "15.67", "01/02/2003 04:05:06")
    assert r["version_note"] is None
    assert r["vbt"]["signature"] == "$VBT FAKEPLAT" and r["vbt"]["version"] == "1.00" and r["vbt"]["bdb_version"] == "2.23"
    assert rom[r["vbt"]["offset"]:r["vbt"]["offset"] + 5] == b"$VBT "


@pytest.mark.parametrize("build,why", [
    (b"no build info here", "no 'Build Number"),
    (b"Build Number: 12 something else", "format differs"),
    (build_line(num=b"1") + b"\r\n" + build_line(num=b"2"), "2 different"),
    (build_line(num=b"1234567"), "no 'Build Number"),              # 數字超過 6 位 → 不符合格式，不猜
])
def test_legacy_info_version_is_none_when_not_certain(build, why):
    r = iv.legacy_info(intel_vbios(build=build))
    assert r["version"] is None and why in r["version_note"]


def test_legacy_info_same_build_line_twice_is_fine():
    assert iv.legacy_info(intel_vbios(build=build_line() + b"\r\n" + build_line()))["version"] == "4321 PC 15.67"


def test_legacy_info_without_banner_or_vbt():
    r = iv.legacy_info(intel_vbios(banner=b""))
    assert r["banner"] is None and r["vbt"] is None and r["version"] == "4321 PC 15.67"


def rom_dict(data):
    [r] = xf.option_roms(data)
    return r


def test_is_legacy_vbios_conditions():
    assert iv.is_legacy_vbios(rom_dict(intel_vbios()))
    assert not iv.is_legacy_vbios(rom_dict(intel_vbios(vid=0x10DE)))                           # NVIDIA 不是
    pxe = bytearray(intel_vbios())
    pxe[0x4D:0x50] = bytes([0x00, 0x00, 0x02])                                                 # class 020000（網路）
    assert not iv.is_legacy_vbios(rom_dict(bytes(pxe)))
    efi_only = option_image(0x8086, 0x0406, 2, 3, True, b"x")
    assert not iv.is_legacy_vbios(rom_dict(efi_only))                                          # 沒有 x86 影像
    assert not iv.is_legacy_vbios({"vendor": "8086", "class": "", "images": []})
    assert not iv.is_legacy_vbios({"vendor": "8086", "class": "03", "images": [{"code_type": 0}]})


# ---------- x86_firmware：Intel legacy VBIOS 元件 ----------

def inventory_of(tmp_path, files):
    paths = []
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
        paths.append(tmp_path / name)
    return xf.inventory(paths)


def test_intel_legacy_vbios_component(tmp_path):
    rom = intel_vbios(vbt=vbt_blob(100, 223, b"$VBT FAKEPLAT"))
    inv = inventory_of(tmp_path, {"intel-fake.rom": rom})
    assert inv["vbios"] == [] and len(inv["intel_vbios"]) == 1
    comps, deps = xf.components(inv)
    doc = xf.bom(comps, deps)
    assert not list(cdx_validator().iter_errors(doc))
    [c] = comps
    assert c["name"] == "Intel legacy VBIOS (option ROM)" and c["version"] == "4321 PC 15.67"
    assert c["manufacturer"] == {"name": "Intel Corporation"} and c["type"] == "firmware"
    assert {h["alg"]: h["content"] for h in c["hashes"]} == {"SHA-256": hashlib.sha256(rom).hexdigest(), "SHA-512": hashlib.sha512(rom).hexdigest()}
    assert props(c, "dumpling:vuln-assessment") == ["NOT_ASSESSED"]
    assert props(c, "dumpling:vuln-assessment-note") == [INTEL_NOTE]                          # 跟 ME／微碼同一句
    assert props(c, "dumpling:version-status") == ["OK"]
    assert props(c, "dumpling:vbios-banner") == [BANNER.decode()]
    assert props(c, "dumpling:vbios-build-time") == ["01/02/2003 04:05:06"]
    assert "$VBT FAKEPLAT v1.00, BDB 2.23" in props(c, "dumpling:vbios-vbt")[0]
    assert props(c, "sca-center:pci-vendor-id") == ["8086"] and props(c, "sca-center:rom-images") == ["x86"]
    assert props(c, "bsi:component:filename") == ["intel-fake.rom"]
    assert "checked against one public sample only" in props(c, "sca-center:version-basis")[0]
    assert deps == {} or all(v == [] for v in deps.values())


def test_intel_legacy_vbios_without_version_is_gap(tmp_path):
    inv = inventory_of(tmp_path, {"a.rom": intel_vbios(build=b"nothing useful")})
    comps, deps = xf.components(inv)
    [c] = comps
    assert "version" not in c and props(c, "dumpling:version-status") == ["GAP"]
    assert "version not read" in props(c, "sca-center:gap")[0]
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "ROM 裡讀不到版本" in detail


def test_same_rom_in_two_files_is_one_component(tmp_path):
    rom = intel_vbios()
    inv = inventory_of(tmp_path, {"a.rom": rom, "b.rom": rom + b"\0" * 16})
    assert len(inv["intel_vbios"]) == 1 and sorted(Path(x).name for x in inv["intel_vbios"][0]["locations"]) == ["a.rom", "b.rom"]
    comps, _ = xf.components(inv)
    assert len(comps) == 1 and len(props(comps[0], "sca-center:found-in")) == 2


def test_other_intel_option_roms_are_not_vbios_components(tmp_path):
    pxe = bytearray(intel_vbios())
    pxe[0x4D:0x50] = bytes([0x00, 0x00, 0x02])
    inv = inventory_of(tmp_path, {"pxe.rom": bytes(pxe)})
    assert inv["intel_vbios"] == [] and inv["vbios"] == []
    st, detail = xf.status_of(inv)
    assert st == "GAP"                                                                         # Intel 網路 ROM 不算 vBIOS
    assert xf.components(inv) == ([], {})


def test_nvidia_and_intel_roms_together(tmp_path):
    inv = inventory_of(tmp_path, {"both.bin": vbios_rom(0x2489, "94.04.5E.00.92") + intel_vbios()})
    assert len(inv["vbios"]) == 1 and len(inv["intel_vbios"]) == 1
    comps, deps = xf.components(inv)
    assert sorted(c["name"] for c in comps) == ["Intel legacy VBIOS (option ROM)", "NVIDIA VBIOS 2489"]
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))


def test_vbios_inside_a_bios_image_is_a_dependency_of_the_image(tmp_path):
    inv = inventory_of(tmp_path, {"bios.bin": spi_image() + intel_vbios()})
    assert len(inv["bios"]) == 1 and len(inv["intel_vbios"]) == 1
    comps, deps = xf.components(inv)
    img = next(c["bom-ref"] for c in comps if c["bom-ref"].startswith(xf.REF + "bios:"))
    vb = next(c["bom-ref"] for c in comps if c["name"].startswith("Intel legacy VBIOS"))
    assert vb in deps[img]
    doc = xf.bom(comps, deps)
    assert not list(cdx_validator().iter_errors(doc))
    assert next(d for d in doc["dependencies"] if d["ref"] == img)["dependsOn"].count(vb) == 1


def test_intel_vbios_incomplete_chain_is_marked(tmp_path):
    rom = bytearray(option_image(0x8086, 0x0406, 2, 0, False, build_line() + b"\r\n"))        # 沒標最後一個、後面也沒有下一個影像
    inv = inventory_of(tmp_path, {"a.rom": bytes(rom) + b"\xff" * 1024})
    [v] = inv["intel_vbios"]
    assert v["terminated"] == "invalid-next-image"
    comps, _ = xf.components(inv)
    assert "only part of the ROM" in props(comps[0], "sca-center:incomplete")[0]
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "ROM 鏈沒有正常結束" in detail


def test_markdown_and_cli_pipeline(tmp_path):
    rom_file = tmp_path / "in" / "intel-fake.rom"
    rom_file.parent.mkdir()
    rom_file.write_bytes(intel_vbios(vbt=vbt_blob(100, 223, b"$VBT FAKEPLAT")))
    out = tmp_path / "out"
    r = subprocess.run(["bash", str(SCRIPT), str(rom_file), "--out", str(out)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 2 and r.stdout.startswith("FIRMWARE-BIOS\tATTENTION\t"), r.stdout + r.stderr   # 沒有版本清單 → ATTENTION
    assert "Intel legacy VBIOS 1 個" in r.stdout and "PASS" not in r.stdout and "安全" not in r.stdout
    md = (out / "fw-inventory.md").read_text(encoding="utf-8")
    assert "## Intel legacy VBIOS" in md and "4321 PC 15.67" in md and "$VBT FAKEPLAT" in md
    doc = json.loads((out / "fw.cdx.json").read_text(encoding="utf-8"))
    assert not list(cdx_validator().iter_errors(doc)) and [c["version"] for c in doc["components"]] == ["4321 PC 15.67"]


def test_crafted_rom_text_is_bounded_and_escaped(tmp_path):
    long_banner = b"Intel(R) " + b"A" * 5000 + b" SVGA BIOS"
    r = iv.legacy_info(intel_vbios(banner=long_banner, units=16))
    assert r["banner"] is None                                                                   # 橫幅超過長度上限就不收
    odd = b"Intel(R) <b>x</b> | `y` SVGA BIOS"
    inv = inventory_of(tmp_path, {"a.rom": intel_vbios(banner=odd)})
    md = xf.markdown({**inv, "status": "OK", "detail": ""})
    assert "<b>" not in md and "&lt;b&gt;" in md


# ---------- GOP 驅動 ----------

def gop_body(version=None, gap=0x60, tail=u16("Intel(R) Graphics Controller")):
    return b"\0" * 16 + NAME + b"\0" * gap + (u16(version) if version else b"") + b"\0" * 24 + tail


def test_gop_driver_reads_name_and_build_number():
    r = iv.gop_driver(fake_pe(body=gop_body("4321")))
    assert (r["name"], r["version"], r["machine"], r["subsystem"]) == ("Intel(R) GOP Driver", "4321", "x64", 11)
    assert r["subsystem_name"] == "EFI boot service driver" and r["version_note"] is None and "build number only" in r["version_basis"]
    assert iv.gop_driver(fake_pe(body=gop_body("17.0.1234")))["version"] == "17.0.1234"        # 點分數字也接受
    assert iv.gop_driver(fake_pe(machine=0x14C, subsystem=12, body=gop_body("9")))["machine"] == "ia32"


@pytest.mark.parametrize("body,why", [
    (gop_body(None), "not a version number"),                                                  # 名稱後面接的是控制器名稱，不是版本
    (gop_body("abc"), "not a version number"),
    (gop_body("12 34"), "not a version number"),
    (gop_body("1.2.3.4.5"), "not a version number"),
    (gop_body("1234567"), "not a version number"),
    (gop_body("1070", gap=0x400), "no string"),                                                  # 超出找版本的範圍
])
def test_gop_driver_version_is_none_when_not_certain(body, why):
    r = iv.gop_driver(fake_pe(body=body))
    assert r is not None and r["version"] is None and why in r["version_note"]


def test_gop_driver_rejects_what_is_not_a_gop_pe():
    assert iv.gop_driver(b"") is None and iv.gop_driver(b"MZ" + b"\0" * 10) is None
    assert iv.gop_driver(fake_pe(body=b"\0" * 64 + u16("Some Other Driver") + u16("1070"))) is None   # 沒有 GOP 名稱
    assert iv.gop_driver(fake_pe(subsystem=2, body=gop_body("1"))) is None                             # 不是 EFI subsystem
    assert iv.gop_driver(fake_pe(magic=0x107, body=gop_body("1"))) is None                             # 不是 PE32／PE32+
    assert iv.gop_driver(gop_body("1")) is None                                                        # 沒有 MZ
    bad_pe = bytearray(fake_pe(body=gop_body("1")))
    bad_pe[0x80:0x84] = b"XX\0\0"
    assert iv.gop_driver(bytes(bad_pe)) is None
    far = bytearray(fake_pe(body=gop_body("1")))
    struct.pack_into("<I", far, 0x3C, 0xFFFFFF00)                                                       # e_lfanew 超出
    assert iv.gop_driver(bytes(far)) is None
    # 名稱沒有以 NUL 結尾（被截斷）或位置沒有 2 bytes 對齊 → 不算
    assert iv.gop_driver(fake_pe(body=b"\0" + NAME[:-2] + b"x\0")) is None


def test_gop_driver_misaligned_name_is_not_accepted():
    odd = fake_pe(body=b"\0" + NAME + b"\0" * 8 + u16("77"))
    assert iv.gop_driver(odd) is None


def test_gop_driver_truncated_and_big_inputs_do_not_crash():
    good = fake_pe(body=gop_body("55"))
    for n in range(0, len(good), 97):
        iv.gop_driver(good[:n])                                                                         # 任何截斷都不丟例外
    assert iv.pe_info(b"MZ" + b"\0" * (iv.MAX_PE)) is None                                             # 超過上限不解析
