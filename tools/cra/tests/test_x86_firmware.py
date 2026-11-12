"""x86_firmware.py：BIOS（Intel SPI 映像）與 NVIDIA vBIOS 的只讀解析、版本清單比對。全部用測試自己組出來的假資料（不含任何產品映像）。"""
import json
import os
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402

CLI = HERE.parent / "x86_firmware.py"


# ---------- 假資料 ----------

def option_image(vid, did, units, code_type, last, payload=b""):
    img = bytearray(units * 512)
    img[0:2] = b"\x55\xaa"
    img[2] = units
    struct.pack_into("<H", img, 0x18, 0x40)
    img[0x40:0x44] = b"PCIR"
    struct.pack_into("<HHHHB", img, 0x44, vid, did, 0, 0x18, 0)
    img[0x4D:0x50] = bytes([0x00, 0x00, 0x03])          # class code 030000（顯示卡），little endian
    struct.pack_into("<HHBB", img, 0x50, units, 1, code_type, 0x80 if last else 0)
    img[0x100:0x100 + len(payload)] = payload
    return bytes(img)


def vbios_rom(did, version, vid=0x10DE):
    return option_image(vid, did, 2, 0, False, b"NVIDIA VBIOS Version " + version.encode()) + option_image(vid, did, 1, 3, True)


def nvflash_exe(*roms):
    """像 nvflash＋內嵌 ROM 的 .exe：前面有 nvflash 自己的表格版本（同格式，不能被當成 vBIOS 版本）。"""
    out = bytearray(b"MZ" + b"\x00" * 0x3E + b"nvflash table 95.04.00.00.01 " + b"\x00" * 0x200)
    for r in roms:
        out += b"\x00" * (-len(out) % 512) + r + b"\xcc" * 300
    return bytes(out)


def microcode(cpuid, rev, date_mdy, pf=0xE0, total=1024):
    data = bytearray(total)
    struct.pack_into("<IiIIIIIII", data, 0, 1, rev, date_mdy, cpuid, 0, 1, pf, total - 48, total)
    data[48:56] = b"UCODE!!!"
    ck = (-sum(struct.unpack_from(f"<{total // 4}I", data))) & 0xFFFFFFFF
    struct.pack_into("<I", data, 16, ck)
    return bytes(data)


def me_manifest(ver, date_ymd):
    h = bytearray(0x80)
    struct.pack_into("<IIIIII", h, 0, 4, 0xA1, 0x10000, 0, 0x8086, date_ymd)
    h[0x1C:0x20] = b"$MN2"
    struct.pack_into("<4H", h, 0x24, *ver)
    return bytes(h)


def spi_image(with_descriptor=True):
    img = bytearray(b"\xff" * 0x10000)
    if with_descriptor:
        img[0:0x1000] = b"\x00" * 0x1000
        img[0x10:0x14] = xf.FD_SIG
        struct.pack_into("<I", img, 0x14, 0x00040000)                    # FRBA = 0x04 << 4 = 0x40
        regs = [0x00000000, (0xF << 16) | 0x8, (0x6 << 16) | 0x1, (0x7 << 16) | 0x7] + [0x00007FFF] * 12
        struct.pack_into("<16I", img, 0x40, *regs)                       # descriptor, bios 0x8000-0xFFFF, me 0x1000-0x6FFF, gbe 0x7000
    img[0x1100:0x1180] = me_manifest((16, 1, 30, 2307), 0x20230501)
    img[0x2000:0x2010] = b"$CPD" + b"\x00" * 8 + b"FTPR"                # 沒有 $FPT：舊的退路靠 $CPD 指出 FTPR
    img[0x2100:0x2180] = me_manifest((16, 1, 30, 2307), 0x20230501)
    img[0x3100:0x3180] = me_manifest((1, 0, 5, 1200), 0x20230101)      # 其他分割區的版本
    img[0x9000:0x9400] = microcode(0x000B06A2, 0x4121, 0x05172023)
    img[0xA000:0xA400] = microcode(0x000B06A2, 0x4121, 0x05172023)     # 同一份的備援
    img[0xB000:0xB400] = microcode(0x000B0671, 0x123, 0x03012023, pf=0x32)
    img[0xC000:0xC006] = b"ALASKA"
    return bytes(img)


# ---------- vBIOS ----------

def test_vbios_in_exe_ignores_nvflash_version(tmp_path):
    exe = nvflash_exe(vbios_rom(0x2489, "94.04.5E.00.92"))
    roms = [r for r in xf.option_roms(exe) if r["vendor"] == "10de"]
    assert len(roms) == 1
    r = roms[0]
    assert (r["device"], r["version"], r["length"], r["class"]) == ("2489", "94.04.5E.00.92", 1536, "030000")
    assert [i["code_type"] for i in r["images"]] == [0, 3]
    rom = exe[r["offset"]:r["offset"] + r["length"]]
    assert r["sha256"] == xf.hashes(rom)["sha256"]


def test_vbios_package_zip_dedup_and_per_board(tmp_path):
    a, b = vbios_rom(0x2489, "94.04.5E.00.92"), vbios_rom(0x2488, "94.04.5E.00.A1")
    z = tmp_path / "vbios-update.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("UpdateVBios_X.exe", nvflash_exe(a))
        f.writestr("VBios/board1.exe", nvflash_exe(a))                   # 同一個 ROM 出現兩次 → 一個元件、兩個位置
        f.writestr("VBios/board2.exe", nvflash_exe(b))
        f.writestr("VBios/other.rom", option_image(0x8086, 0x1234, 1, 0, True))   # 不是 NVIDIA → 不算
    inv = xf.inventory([z])
    assert [(v["device"], v["version"], len(v["locations"])) for v in inv["vbios"]] == [("2488", "94.04.5E.00.A1", 1),
                                                                                        ("2489", "94.04.5E.00.92", 2)]
    assert inv["bios"] == []
    comps, deps = xf.components(inv)
    assert {c["name"] for c in comps} == {"NVIDIA VBIOS 2488", "NVIDIA VBIOS 2489"}
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))


# ---------- BIOS ----------

def test_spi_descriptor_me_microcode_ibv():
    b = xf.bios_image(spi_image())
    assert b["descriptor"] and {r["name"]: (r["base"], r["limit"]) for r in b["regions"]} == {
        "descriptor": (0, 0xFFF), "bios": (0x8000, 0xFFFF), "me": (0x1000, 0x6FFF), "gbe": (0x7000, 0x7FFF)}
    assert b["me"] == {"version": "16.1.30.2307", "date": "2023-05-01", "other_versions": ["1.0.5.1200"], "offset": 0x2100,
                       "family": None, "basis": "FTPR partition manifest"}
    assert b["me_status"] == "found" and "no $FPT" in b["me_note"] and "fell back" in b["me_note"]
    assert b["incomplete"] == []
    assert [(u["cpuid"], u["revision"], u["date"], u["platform_id"]) for u in b["microcode"]] == [
        ("000B06A2", "0x4121", "2023-05-17", "0xE0"), ("000B0671", "0x123", "2023-03-01", "0x32")]
    assert b["ibv_hint"] == ["AMI"]


def test_bad_checksum_and_no_descriptor():
    img = bytearray(spi_image(with_descriptor=False))
    img[0xB000 + 100] ^= 0xFF                                            # 第二個 microcode checksum 壞掉 → 不算
    b = xf.bios_image(bytes(img))
    assert not b["descriptor"] and "no Intel flash descriptor" in b["descriptor_note"] and b["regions"] == []
    assert [u["cpuid"] for u in b["microcode"]] == ["000B06A2"]
    # 沒有 descriptor、也沒有 $FPT：零散的 $MN2 不當成 CSE 版本（2a 以前會報 16.1.30.2307），狀態是沒有 ME 區域
    assert b["me"] is None and b["me_status"] == "no-me-region" and "not reported as the CSE version" in b["me_note"]
    assert xf.bios_image(b"\x00" * 0x2000) is None


def test_bios_components_valid_cyclonedx(tmp_path):
    p = tmp_path / "BIOS.bin"
    p.write_bytes(spi_image())
    inv = xf.inventory([p])
    comps, deps = xf.components(inv)
    names = {c["name"]: c for c in comps}
    assert names["Intel CSE firmware"]["version"] == "16.1.30.2307"
    assert names["Intel CPU microcode 000B06A2"]["version"] == "0x4121"
    img = names["BIOS.bin"]
    assert len(deps[img["bom-ref"]]) == 6            # descriptor、bios、me、gbe 區域＋兩個 microcode
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))


# ---------- 版本清單 ----------

MANIFEST = """product,firmware,firmware_version,component,identifier,version,date,vendor,note
# 範例,BIOS,9.99,bios,,9.99,,,不讀
MB-1,BIOS,1.05,bios,,1.05,2026-10-15,,
MB-1,BIOS,1.05,ibv-core,,Aptio V 5.27,,AMI,
MB-1,BIOS,1.05,me,,16.1.30.2307,,Intel,
MB-1,BIOS,1.05,microcode,b06a2,4121,,Intel,
MB-1,BIOS,1.05,microcode,000B0671,0x124,,Intel,版本寫錯
MB-1,BIOS,1.05,microcode,000906EA,0xF0,,Intel,映像裡沒有
MB-1,BIOS,1.05,fsp,,不知道,,Intel,
MB-1,vBIOS,94.04.5E.00.92,vbios,0x2489,94.04.5e.00.92,,NVIDIA,
"""


def test_manifest_comparison(tmp_path):
    (tmp_path / "BIOS.bin").write_bytes(spi_image())
    (tmp_path / "v.exe").write_bytes(nvflash_exe(vbios_rom(0x2489, "94.04.5E.00.92"), vbios_rom(0x2488, "94.04.5E.00.A1")))
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST, encoding="utf-8")
    inv = xf.inventory([tmp_path / "BIOS.bin", tmp_path / "v.exe"], m)
    res = {(c["component"], c["identifier"]): c["result"] for c in inv["comparison"]}
    assert res == {("bios", None): "declared-only", ("ibv-core", None): "declared-only", ("me", None): "match",
                   ("microcode", "000B06A2"): "match", ("microcode", "000B0671"): "mismatch",
                   ("microcode", "000906EA"): "declared-only", ("fsp", None): "unknown", ("vbios", "2489"): "match",
                   ("vbios", "2488"): "extracted-only"}
    verif = {(c["component"], c["identifier"]): c["verifiable"] for c in inv["comparison"]}
    assert not verif[("ibv-core", None)] and verif[("microcode", "000906EA")]
    assert inv["bios"][0]["declared_version"] == "1.05"
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "待確認 3 項" in detail and "不知道」1 項" in detail


def test_template_parses_and_bad_manifest(tmp_path):
    assert xf.read_manifest(HERE.parent / "data" / "fw-manifest-template.csv") == []        # 範本只有範例列
    excel = tmp_path / "excel.csv"                                      # Excel 另存 CSV：BOM、欄名前有分組標題列、尾端空欄
    excel.write_text("\ufeff版本清單（一個元件一列）,,,,,,,,,\n" + MANIFEST.replace("\n", ",\n"), encoding="utf-8")
    assert [r["component"] for r in xf.read_manifest(excel)][:3] == ["bios", "ibv-core", "me"]
    bad = tmp_path / "bad.csv"
    bad.write_text("product,firmware,component\nx,y,me\n", encoding="utf-8")
    with pytest.raises(xf.Fail, match="少了欄位"):
        xf.read_manifest(bad)
    bad.write_text(MANIFEST.replace(",me,", ",cpu,"), encoding="utf-8")
    with pytest.raises(xf.Fail, match="component「cpu」"):
        xf.read_manifest(bad)


# ---------- CLI 與不可信輸入 ----------

def cli(*a):
    return subprocess.run([sys.executable, "-I", str(CLI), *a], capture_output=True, text=True, timeout=60)


def test_cli_outputs_and_statuses(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "BIOS.bin").write_bytes(spi_image())
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST.split("MB-1,BIOS,1.05,microcode,000B0671")[0], encoding="utf-8")   # 前幾列：bios、ibv-core、me、000B06A2
    r = cli("inventory", "--in", str(tmp_path / "in"), "--manifest", str(m), "--out", str(tmp_path / "out"))
    assert r.stdout.startswith("FW-INVENTORY\tATTENTION\t"), r.stdout + r.stderr   # 000B0671 只有映像
    inv = json.loads((tmp_path / "out" / "fw-inventory.json").read_text(encoding="utf-8"))
    assert inv["status"] == "ATTENTION" and (tmp_path / "out" / "fw.cdx.json").exists()
    (tmp_path / "empty").mkdir()
    (tmp_path / "empty" / "readme.txt").write_text("nothing", encoding="utf-8")
    r = cli("inventory", "--in", str(tmp_path / "empty"), "--out", str(tmp_path / "o2"))
    assert r.stdout.startswith("FW-INVENTORY\tGAP\t") and r.returncode == 2
    r = cli("inventory", "--in", str(tmp_path / "in"), "--manifest", str(tmp_path / "nope.csv"), "--out", str(tmp_path / "o3"))
    assert r.stdout.startswith("FW-INVENTORY\tFAIL\t") and r.returncode == 1


def test_symlink_not_followed_and_size_limit(tmp_path, monkeypatch):
    d = tmp_path / "in"
    d.mkdir()
    (tmp_path / "outside.bin").write_bytes(spi_image())
    os.symlink(tmp_path / "outside.bin", d / "link.bin")
    (d / "big.bin").write_bytes(b"\x00" * 5000)
    monkeypatch.setattr(xf, "MAX_FILE", 4096)
    inv = xf.inventory([d])
    assert inv["bios"] == [] and {s["file"].rsplit("/", 1)[-1]: s["reason"] for s in inv["skipped"]} == {
        "big.bin": "太大（5000 bytes）", "link.bin": "不是一般檔案（不跟隨連結）"}
    z = tmp_path / "z.zip"
    with zipfile.ZipFile(z, "w", compression=zipfile.ZIP_DEFLATED) as f:
        f.writestr("huge.bin", b"\x00" * 10000)                          # 宣告大小超過上限 → 不讀
    inv = xf.inventory([z])
    assert inv["skipped"] and "太大" in inv["skipped"][0]["reason"]


# ---------- 補充：壞檔、上限、去重、逐份比對、其他內嵌映像 ----------

def corrupt_zip(path, members, bad):
    """members 都用 deflate 壓；bad 那個成員的壓縮資料中間改壞（zlib.error 或 CRC 錯）。"""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as f:
        for n, data in members.items():
            f.writestr(n, data)
    raw = bytearray(path.read_bytes())
    with zipfile.ZipFile(path) as f:
        info = f.getinfo(bad)
    start = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
    for k in range(start + 2, start + min(info.compress_size, 40)):
        raw[k] ^= 0x5A
    path.write_bytes(bytes(raw))


def test_corrupt_zip_member_is_skipped_others_still_parsed(tmp_path):
    z = tmp_path / "pkg.zip"
    corrupt_zip(z, {"a_bad.bin": os.urandom(4096) * 4, "b_bios.bin": spi_image()}, "a_bad.bin")
    inv = xf.inventory([z])
    assert len(inv["bios"]) == 1 and [s["file"] for s in inv["skipped"]] == ["pkg.zip!a_bad.bin"]
    assert "ZIP 成員讀不到" in inv["skipped"][0]["reason"]
    r = cli("inventory", "--in", str(z), "--out", str(tmp_path / "out"))
    assert r.stdout.startswith("FW-INVENTORY\tATTENTION\t") and "Traceback" not in r.stderr, r.stdout + r.stderr


def test_same_bios_image_twice_is_one_component_and_valid_cyclonedx(tmp_path):
    for n in ("BIOS_A.zip", "BIOS_B.zip"):
        with zipfile.ZipFile(tmp_path / n, "w") as f:
            f.writestr("image.bin", spi_image())
    inv = xf.inventory([tmp_path])
    assert len(inv["bios"]) == 1 and len(inv["bios"][0]["locations"]) == 2
    comps, deps = xf.components(inv)
    assert len({c["bom-ref"] for c in comps}) == len(comps)
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    with pytest.raises(xf.Fail, match="bom-ref 重複"):
        xf.bom(comps + comps[:1], deps)


def test_each_image_is_compared_not_any_one(tmp_path):
    """兩個 BIOS 檔的 ME 不同、清單只填一個：符合的那份不能蓋掉另一份 → ATTENTION。"""
    a = bytearray(spi_image())
    a[0x1100:0x1180] = a[0x2100:0x2180] = me_manifest((16, 1, 25, 1), 0x20230101)
    (tmp_path / "old.bin").write_bytes(bytes(a))
    (tmp_path / "new.bin").write_bytes(spi_image())
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST.splitlines()[0] + "\nMB-1,BIOS,1.05,me,,16.1.30,,Intel,\nMB-1,BIOS,1.05,microcode,b06a2/0xE0,4121,,,\n"
                 "MB-1,BIOS,1.05,microcode,b0671,123,,,\n", encoding="utf-8")
    inv = xf.inventory([tmp_path / "old.bin", tmp_path / "new.bin"], m)
    me = [c for c in inv["comparison"] if c["component"] == "me"]
    assert [(c["result"], c["extracted"]) for c in me] == [("match", "16.1.25.1, 16.1.30.2307"), ("mismatch", "16.1.25.1")]
    assert me[1]["found"] == [{"version": "16.1.25.1", "file": "old.bin"}]
    assert {c["result"] for c in inv["comparison"] if c["component"] == "microcode"} == {"match"}
    assert "declared_version" not in inv["bios"][0]          # 兩個完整映像 → 不猜清單的 BIOS 版本是哪一個
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "待確認 1 項" in detail


def test_unknown_firmware_version_not_used_as_component_version(tmp_path):
    (tmp_path / "BIOS.bin").write_bytes(spi_image())
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST.splitlines()[0] + "\nMB-1,BIOS,不知道,me,,16.1.30.2307,,Intel,\n", encoding="utf-8")
    inv = xf.inventory([tmp_path / "BIOS.bin"], m)
    assert "declared_version" not in inv["bios"][0]
    comps, _ = xf.components(inv)
    assert all(c.get("version") != "不知道" for c in comps)


def test_microcode_data_size_zero_and_extended_signatures():
    old = bytearray(2048)                                                 # data size 0、total size 0 → 2000＋48
    struct.pack_into("<IiIIIIIII", old, 0, 1, 0x2F, 0x07152019, 0x000906EA, 0, 1, 0x22, 0, 0)
    struct.pack_into("<I", old, 16, (-sum(struct.unpack_from("<512I", old))) & 0xFFFFFFFF)
    ext = bytearray(3072)                                                 # data 2048、extended table 2 筆
    struct.pack_into("<IiIIIIIII", ext, 0, 1, 0xF0, 0x01012024, 0x000906EB, 0, 1, 0x02, 2048, 3072)
    struct.pack_into("<III", ext, 48 + 2048, 2, 0, 0)
    struct.pack_into("<IIIIII", ext, 48 + 2048 + 20, 0x000906EC, 0x22, 0, 0x000906ED, 0x02, 0)
    struct.pack_into("<I", ext, 16, (-sum(struct.unpack_from("<768I", ext))) & 0xFFFFFFFF)
    found, note = xf.microcodes(b"\xff" * 64 + bytes(old) + bytes(ext))
    assert note is None and [(u["cpuid"], u["revision"], u["size"]) for u in found] == [("000906EA", "0x2F", 2048),
                                                                                      ("000906EB", "0xF0", 3072)]
    assert found[1]["extended_signatures"] == [{"cpuid": "000906EC", "platform_id": "0x22"},
                                               {"cpuid": "000906ED", "platform_id": "0x02"}]


def test_crafted_microcode_candidates_are_bounded(monkeypatch):
    """header 合法、checksum 錯的候選塞滿整個檔：checksum 總量到上限就停，記下沒找完。"""
    bad = bytearray(microcode(0x000B06A2, 0x4121, 0x05172023, total=4096))
    bad[100] ^= 1
    data = bytes(bad) * 64
    found, note = xf.microcodes(data, checksum_cap=16 * 4096)
    assert found == [] and "沒有找完" in note
    monkeypatch.setattr(xf, "MAX_CHECKSUM", 16 * 4096)
    b = xf.bios_image(spi_image(with_descriptor=False) + data)
    assert b["microcode"] and any("沒有找完" in x for x in b["incomplete"])        # 前面找到的保留，記下沒找完
    assert xf.status_of({"vbios": [], "other_roms": [], "bios": [dict(b, file="x.bin")], "skipped": []})[0] == "ATTENTION"
    only = xf.bios_image(data)                                            # 什麼都沒找到但沒找完 → 不能當成「沒有 BIOS 結構」
    assert only is not None and only["microcode"] == [] and "沒有找完" in only["incomplete"][0]


def test_time_and_total_limits(tmp_path):
    (tmp_path / "a.bin").write_bytes(spi_image())
    (tmp_path / "b.bin").write_bytes(spi_image(with_descriptor=False))
    inv = xf.inventory([tmp_path], budget=xf.Budget(time_limit=-1))
    assert inv["bios"] == [] and all("時間上限" in s["reason"] for s in inv["skipped"]) and len(inv["skipped"]) == 2
    inv = xf.inventory([tmp_path], budget=xf.Budget(max_total=0x10000 + 10))
    assert len(inv["bios"]) == 1 and "總量上限" in inv["skipped"][0]["reason"]
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "略過 1 個檔案" in detail


def test_rom_without_x86_or_efi_image_is_not_the_vbios(tmp_path):
    """燒錄工具自帶的 NVIDIA 映像（只有 code type 0xE0）：列在 other_roms，不是產品元件、不影響狀態。"""
    tool = option_image(0x10DE, 0x1AEF, 1, 0xE0, True)
    (tmp_path / "v.exe").write_bytes(nvflash_exe(vbios_rom(0x2489, "94.04.5E.00.92"), tool))
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST.splitlines()[0] + "\nG-1,vBIOS,94.04.5E.00.92,vbios,2489,94.04.5E.00.92,,NVIDIA,\n", encoding="utf-8")
    inv = xf.inventory([tmp_path / "v.exe"], m)
    assert [v["device"] for v in inv["vbios"]] == ["2489"]
    assert [(x["device"], x["code_types"]) for x in inv["other_roms"]] == [("1aef", [0xE0])]
    st, detail = xf.status_of(inv)
    assert st == "OK" and "其他內嵌 NVIDIA 映像 1 個（裝置 ID 1aef" in detail
    comps, _ = xf.components(inv)
    assert [c["name"] for c in comps] == ["NVIDIA VBIOS 2489"]


def test_me_version_prefers_ftpr_partition():
    img = bytearray(spi_image())
    cpd = bytearray(0x10)
    cpd[0:4], cpd[0x0C:0x10] = b"$CPD", b"FTPR"
    img[0x1100:0x1180] = me_manifest((16, 0, 0, 1), 0x20220101)          # 前面的其他分割區
    img[0x2000:0x2010] = bytes(cpd)
    b = xf.bios_image(bytes(img))
    assert b["me"]["version"] == "16.1.30.2307" and b["me"]["basis"] == "FTPR partition manifest"
    assert "16.0.0.1" in b["me"]["other_versions"]


def test_nested_archive_and_truncated_region_are_noted(tmp_path):
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w", compression=zipfile.ZIP_DEFLATED) as f:
        f.writestr("BIOS.bin", spi_image())
    with zipfile.ZipFile(tmp_path / "outer.zip", "w") as f:
        f.write(inner, "inner.zip")
    inv = xf.inventory([tmp_path / "outer.zip"])
    assert inv["bios"] == [] and "壓縮檔（zip）沒有展開" in inv["skipped"][0]["reason"]
    b = xf.bios_image(spi_image()[:0xC000])                               # bios 區域 0x8000–0xFFFF 超出檔案
    assert any("beyond the end of the file" in x and "bios" in x for x in b["incomplete"])


# ---------- 第二輪：NPDE、低 ----------

def with_npde(img, units, last):
    """在影像的 PCIR（0x40、長度 0x18）之後、對齊 16 的 0x60 放 NPDE：長度與最後一個旗標以它為準。"""
    b = bytearray(img)
    b[0x60:0x64] = b"NPDE"
    struct.pack_into("<HHHHB", b, 0x64, 0x0100, 0x0010, units, 0x80 if last else 0, 0)
    return bytes(b)


def test_npde_overrides_pcir_last_flag_and_length():
    """NPDE 優先於 PCIR：EFI 的 PCIR 標最後一個、NPDE 說還沒完 → 往後串；0xE0 影像的 PCIR 說 1 個單位、NPDE 說 2 個 → 以 NPDE 為準。
    （合成資料；實際樣本的 EFI 影像 NPDE 也標最後一個，見 test_real_layout_efi_last_then_separate_e0。）"""
    x86 = with_npde(option_image(0x10DE, 0x2489, 2, 0, False, b"NVIDIA VBIOS Version 94.04.5E.00.92"), 2, False)
    efi = with_npde(option_image(0x10DE, 0x2489, 1, 3, True), 1, False)
    fw = with_npde(option_image(0x10DE, 0x248A, 1, 0xE0, False) + b"\xab" * 512, 2, True)
    exe = nvflash_exe(x86 + efi + fw)
    roms = [r for r in xf.option_roms(exe) if r["vendor"] == "10de"]
    assert len(roms) == 1
    r = roms[0]
    assert [(i["code_type"], i["length"], i["length_basis"]) for i in r["images"]] == [(0, 1024, "NPDE"), (3, 512, "NPDE"),
                                                                                      (0xE0, 1024, "NPDE")]
    assert r["length"] == 2560 and r["sha256"] == xf.hashes(x86 + efi + fw)["sha256"] and xf.is_vbios(r)
    assert r["terminated"] == "last-flag"
    # 沒有 NPDE：照 PCIR 停在 EFI（舊行為）
    plain = [x for x in xf.option_roms(nvflash_exe(vbios_rom(0x2489, "94.04.5E.00.92"))) if x["vendor"] == "10de"]
    assert [i["length_basis"] for i in plain[0]["images"]] == ["PCIR", "PCIR"]


def test_other_roms_record_offsets_and_found_lists_all_sources(tmp_path):
    tool = option_image(0x10DE, 0x1AEF, 1, 0xE0, True)
    for n in ("a.exe", "b.exe"):
        (tmp_path / n).write_bytes(nvflash_exe(vbios_rom(0x2489, "94.04.5E.00.92"), tool))
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST.splitlines()[0] + "\nG-1,vBIOS,1,vbios,2489,94.04.5E.00.92,,NVIDIA,\n", encoding="utf-8")
    inv = xf.inventory([tmp_path / "a.exe", tmp_path / "b.exe"], m)
    o = inv["other_roms"][0]
    assert o["locations"] == ["a.exe", "b.exe"] and [x["file"] for x in o["found_at"]] == ["a.exe", "b.exe"]
    assert [f["file"] for f in inv["comparison"][0]["found"]] == ["a.exe", "b.exe"]


def test_bios_stage_timeout_keeps_vbios(tmp_path, monkeypatch):
    (tmp_path / "v.exe").write_bytes(nvflash_exe(vbios_rom(0x2489, "94.04.5E.00.92")))

    def slow(data, budget=None):
        raise xf.OverBudget("超過時間上限 1 秒，沒有解析完")
    monkeypatch.setattr(xf, "bios_image", slow)
    inv = xf.inventory([tmp_path / "v.exe"])
    assert [v["device"] for v in inv["vbios"]] == ["2489"] and inv["partial"][0]["reason"].startswith("BIOS 解析：超過時間上限")
    assert inv["skipped"] == [] and "1 個檔案只解析了一部分" in xf.status_of(inv)[1]


def test_documents_gzip_and_broken_zip_reasons(tmp_path):
    d = tmp_path / "in"
    d.mkdir()
    doc = d / "ReleaseNote.docx"
    with zipfile.ZipFile(doc, "w") as f:
        f.writestr("[Content_Types].xml", "<Types/>")
    (d / "bin.dat").write_bytes(b"\x1f\x8b" + b"\x00" * 100)                 # 只有 2 bytes 像 gzip
    (d / "broken.zip").write_bytes(b"PK\x03\x04" + b"\x00" * 100)           # 開頭像 ZIP 但讀不了
    inv = xf.inventory([d])
    assert {s["file"]: s["reason"] for s in inv["skipped"]} == {"in/broken.zip": "ZIP 讀不到（格式損壞），只當一般檔案掃描"}


def test_fail_removes_previous_outputs_and_time_limit_must_be_finite(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    for n in ("fw-inventory.json", "fw.cdx.json"):
        (out / n).write_text("{}", encoding="utf-8")
    (tmp_path / "BIOS.bin").write_bytes(spi_image())
    r = cli("inventory", "--in", str(tmp_path / "BIOS.bin"), "--manifest", str(tmp_path / "nope.csv"), "--out", str(out))
    assert r.stdout.startswith("FW-INVENTORY\tFAIL\t") and not list(out.iterdir())
    (out / "fw.cdx.json").write_text("{}", encoding="utf-8")
    r = cli("inventory", "--in", str(tmp_path / "BIOS.bin"), "--out", str(out), "--time-limit", "inf")
    assert r.returncode == 64 and r.stdout.startswith("FW-INVENTORY\tFAIL\t參數錯誤") and "--time-limit" in r.stdout
    assert not list(out.iterdir())
    r = cli("inventory", "--in", str(tmp_path / "BIOS.bin"), "--out", str(out), "--time-limit", "30")
    assert json.loads((out / "fw-inventory.json").read_text(encoding="utf-8"))["limits"]["time_limit_s"] == 30


# ---------- 第三輪：鏈沒有正常結束、PCIR 指標超過 0x1000、NPDE 的邊界 ----------

def pcir_far(vid, did, units, code_type, last, po=0x1200):
    """PCIR 指標大於 0x1000 的影像（實際樣本的 0xE0 影像就是這樣）。"""
    img = bytearray(max(units * 512, po + 0x100))
    img[0:2] = b"\x55\xaa"
    struct.pack_into("<H", img, 0x18, po)
    img[po:po + 4] = b"PCIR"
    struct.pack_into("<HHHHB", img, po + 4, vid, did, 0, 0x18, 0)
    struct.pack_into("<HHBB", img, po + 0x10, len(img) // 512, 1, code_type, 0x80 if last else 0)
    return bytes(img)


def test_real_layout_efi_last_then_separate_e0():
    """實際樣本的排法：EFI 的 NPDE 也標最後一個 → vBIOS 停在 EFI；緊接著的 0xE0 影像（裝置 ID 不同、PCIR 指標 > 0x1000）
    是另一個映像，要列在 other_roms，不能整個漏掉。"""
    x86 = with_npde(option_image(0x10DE, 0x2489, 2, 0, False, b"NVIDIA VBIOS Version 94.04.5E.00.92"), 2, False)
    efi = with_npde(option_image(0x10DE, 0x2489, 1, 3, True), 1, True)
    e0 = pcir_far(0x10DE, 0x1AEF, 10, 0xE0, True)
    exe = nvflash_exe(x86 + efi + e0)
    roms = {r["device"]: r for r in xf.option_roms(exe) if r["vendor"] == "10de"}
    assert roms["2489"]["length"] == 1536 and roms["2489"]["terminated"] == "last-flag"
    assert roms["1aef"]["images"][0]["code_type"] == 0xE0 and not xf.is_vbios(roms["1aef"])


def test_chain_that_does_not_end_is_marked_and_attention(tmp_path):
    x86 = with_npde(option_image(0x10DE, 0x2489, 2, 0, False, b"NVIDIA VBIOS Version 94.04.5E.00.92"), 2, False)
    efi_open = with_npde(option_image(0x10DE, 0x2489, 1, 3, True), 1, False)       # NPDE 說還沒完，後面是 0xFF
    (tmp_path / "a.rom").write_bytes(x86 + efi_open + b"\xff" * 2048)
    inv = xf.inventory([tmp_path / "a.rom"])
    v = inv["vbios"][0]
    assert v["terminated"] == "invalid-next-image" and "no option ROM signature" in v["terminated_note"] and v["length"] == 1536
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "ROM 鏈沒有正常結束" in detail
    efi_long = with_npde(option_image(0x10DE, 0x2489, 1, 3, True), 40, True)       # NPDE 長度超出檔案 → 留下讀得到的部分，標 truncated
    roms = [r for r in xf.option_roms(x86 + efi_long) if r["vendor"] == "10de"]
    assert roms[0]["length"] == 1536 and roms[0]["terminated"] == "truncated"
    assert "past the end of the file" in roms[0]["terminated_note"]


def test_npde_edge_cases():
    x86 = option_image(0x10DE, 0x2489, 2, 0, False)
    zero = with_npde(option_image(0x10DE, 0x2489, 1, 3, True), 0, False)             # NPDE 長度 0 → 退回 PCIR（最後一個）
    r = xf.option_roms(x86 + zero)[0]
    assert r["images"][1]["length_basis"] == "PCIR" and r["terminated"] == "last-flag"
    other = with_npde(option_image(0x8086, 0x1234, 1, 0, True), 4, False)            # 不是 NVIDIA：NPDE 不套用
    r = xf.option_roms(other)[0]
    assert r["images"][0]["length_basis"] == "PCIR" and r["length"] == 512 and r["terminated"] == "last-flag"
    t70 = with_npde(option_image(0x10DE, 0x2489, 1, 0x70, False), 4, False)          # 0x70：不用 NPDE、一定是最後一個
    r = xf.option_roms(x86 + t70 + option_image(0x10DE, 0x2489, 1, 3, True))[0]
    assert len(r["images"]) == 2 and r["images"][1]["length_basis"] == "PCIR" and r["terminated"] == "last-flag"
    trunc = (x86 + with_npde(option_image(0x10DE, 0x2489, 1, 3, True), 1, True))[:-100]   # 截斷 → 留下讀得到的部分，標出來
    r = xf.option_roms(trunc)[0]
    assert r["length"] == 1436 and r["terminated"] == "truncated"
    first = with_npde(option_image(0x10DE, 0x2489, 2, 0, True), 8, True)             # 第一個影像就被截斷（NPDE 說 4096、檔案 1024）
    r = xf.option_roms(first)[0]
    assert r["length"] == 1024 and r["terminated"] == "truncated" and len(r["images"]) == 1


def test_vbios_stage_parse_error_still_runs_bios_stage(tmp_path, monkeypatch):
    (tmp_path / "BIOS.bin").write_bytes(spi_image())

    def broken(data, budget=None, notes=None):
        raise struct.error("boom")
    monkeypatch.setattr(xf, "option_roms", broken)
    inv = xf.inventory([tmp_path / "BIOS.bin"])
    assert len(inv["bios"]) == 1 and inv["partial"][0]["reason"] == "vBIOS 解析失敗（error）" and inv["skipped"] == []


def test_document_detection_uses_first_member_name(tmp_path):
    z = tmp_path / "notes.bin"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("readme.txt", "see [Content_Types].xml")                       # 內容提到但不是 Office 文件
    assert xf.archive_kind(z.read_bytes(), "notes.bin") == "zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("[Content_Types].xml", "<Types/>")
    assert xf.archive_kind(z.read_bytes(), "notes.bin") is None


# ---------- 第四輪：沒正常結束的鏈不能讓時間上限失效、PCIR 在影像範圍內、不完整的 vBIOS 在 SBOM 標出來 ----------

def test_unterminated_chains_respect_time_limit():
    """每 512 bytes 一個「長度 2 MB、沒標最後」的標頭：每個都會被重找、各算一次大雜湊。時間上限要每個 ROM 都檢查。"""
    unit = bytearray(option_image(0x10DE, 0x2489, 1, 0, False))
    struct.pack_into("<H", unit, 0x50, 4096)                            # PCIR 長度 4096×512 = 2 MB
    data = bytes(unit) * 8192                                            # 4 MB
    with pytest.raises(xf.OverBudget):
        xf.option_roms(data, xf.Budget(time_limit=0.5))
    import time
    t = time.monotonic()
    try:
        xf.option_roms(data, xf.Budget(time_limit=0.5))
    except xf.OverBudget:
        pass
    assert time.monotonic() - t < 3                                      # 在上限附近停下（每個 ROM 最多多算一次雜湊）


def test_pcir_pointer_must_be_inside_the_image():
    """雜散的 55AA，+0x18 剛好指到後面真 ROM 的 PCIR（超出它自己的影像長度）→ 不能多出一個假 vBIOS。"""
    real = option_image(0x10DE, 0x2489, 1, 0, True)
    stray = bytearray(b"\x00" * 0x2000)
    stray[0:2] = b"\x55\xaa"
    struct.pack_into("<H", stray, 0x18, 0x2000 + 0x40)                   # 指到 real 的 PCIR；real 的長度 1 單位 < 指標
    roms = xf.option_roms(bytes(stray) + real)
    assert [(r["offset"], r["length"]) for r in roms] == [(0x2000, 512)]


def test_incomplete_vbios_is_marked_in_sbom(tmp_path):
    x86 = with_npde(option_image(0x10DE, 0x2489, 2, 0, False, b"NVIDIA VBIOS Version 94.04.5E.00.92"), 2, False)
    (tmp_path / "a.rom").write_bytes(x86 + b"\xff" * 1024)
    inv = xf.inventory([tmp_path / "a.rom"])
    comps, deps = xf.components(inv)
    props = {p["name"]: p["value"] for p in comps[0]["properties"]}
    assert props["sca-center:rom-terminated"] == "invalid-next-image" and "only part of the ROM" in props["sca-center:incomplete"]
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    (tmp_path / "b.rom").write_bytes(vbios_rom(0x2489, "94.04.5E.00.92"))                 # 完整的：沒有這兩個屬性
    comps, _ = xf.components(xf.inventory([tmp_path / "b.rom"]))
    assert not {"sca-center:rom-terminated", "sca-center:incomplete"} & {p["name"] for p in comps[0]["properties"]}


def test_image_with_4e56_signature_found_after_a_broken_chain():
    """0x4E56 開頭的影像不只在鏈的後續位置：前一條鏈沒正常結束、重找時也要找得到。"""
    broken = with_npde(option_image(0x10DE, 0x2489, 2, 0, False), 2, False) + b"\xff" * 512
    nv = bytearray(option_image(0x10DE, 0x1AEF, 1, 0xE0, True))
    nv[0:2] = b"\x56\x4e"
    roms = xf.option_roms(broken + bytes(nv))
    assert [(r["device"], r["terminated"]) for r in roms] == [("2489", "invalid-next-image"), ("1aef", "last-flag")]


def test_invalid_time_limit_clears_previous_outputs(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "fw.cdx.json").write_text("{}", encoding="utf-8")
    (tmp_path / "BIOS.bin").write_bytes(spi_image())
    r = cli("inventory", "--in", str(tmp_path / "BIOS.bin"), "--out", str(out), "--time-limit", "0")
    assert r.returncode == 64 and r.stdout.startswith("FW-INVENTORY\tFAIL\t參數錯誤") and not list(out.iterdir())


# ---------- 第五輪：雜散特徵碼在真 ROM 前方、沒有正常結束的 ROM 數上限、超時保留已找到的、參數錯誤 ----------

@pytest.mark.parametrize("layout", ["one-image", "x86+efi"])
def test_stray_signature_before_real_rom_does_not_hide_it(layout):
    """雜散 55AA 在真 vBIOS 前 0x1000，+0x18＝0x1040 正好指到真 ROM 的 PCIR，而且 < 真 ROM 的長度（64 KB）：
    以前輸出 offset 0 的假 vBIOS（雜湊少了真 ROM 最後 4 KB）；真 ROM 只有一個影像時真的那個還會消失（one-image），
    兩個影像時多一個假的、沒正常結束的（x86+efi）。PCIR 屬於離它最近、指標正好指到它的影像開頭。"""
    import hashlib
    ver = b"NVIDIA VBIOS Version 94.04.5E.00.92"
    real = (option_image(0x10DE, 0x2489, 128, 0, True, ver) if layout == "one-image"
            else option_image(0x10DE, 0x2489, 127, 0, False, ver) + option_image(0x10DE, 0x2489, 1, 3, True))
    stray = bytearray(0x1000)
    stray[0:2] = b"\x55\xaa"
    struct.pack_into("<H", stray, 0x18, 0x1040)
    roms = xf.option_roms(bytes(stray) + real)
    assert [(r["offset"], r["length"], r["terminated"]) for r in roms] == [(0x1000, 65536, "last-flag")]
    assert roms[0]["sha256"] == hashlib.sha256(real).hexdigest()
    # 指標不是正好指到 PCIR 的特徵碼不影響（真 ROM 自己就是最近的開頭）
    assert xf.option_roms(real)[0]["sha256"] == roms[0]["sha256"]


def test_broken_rom_count_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(xf, "MAX_BROKEN_ROMS", 3)
    data = b"".join(option_image(0x10DE, 0x2400 + i, 1, 0, False) + b"\x00" * 512 for i in range(10))
    notes = []
    roms = xf.option_roms(data, notes=notes)
    assert len(roms) == 3 and all(r["terminated"] == "invalid-next-image" for r in roms) and "達 3 個" in notes[-1]
    (tmp_path / "x.rom").write_bytes(data)
    inv = xf.inventory([tmp_path / "x.rom"])
    assert len(inv["vbios"]) == 3 and inv["partial"][0]["reason"].startswith("vBIOS 解析：沒有正常結束（或開頭不確定）的 option ROM 達 3 個")
    st, detail = xf.status_of(inv)                    # 掃了一部分，不是「略過」
    assert inv["skipped"] == [] and st == "ATTENTION" and "1 個檔案只解析了一部分" in detail and "略過" not in detail


def test_timeout_inside_option_roms_keeps_what_was_found(tmp_path, monkeypatch):
    class Stop:
        n = 0

        def check(self):
            self.n += 1
            if self.n == 4:          # tick（第 0 個特徵碼）、ImageStarts 掃描的 tick、第一個 ROM 之後、第二個 ROM → 超時
                raise xf.OverBudget("超過時間上限 1 秒，沒有解析完")
    exe = nvflash_exe(vbios_rom(0x2489, "94.04.5E.00.92"), vbios_rom(0x2504, "94.06.1C.00.10"))
    with pytest.raises(xf.OverBudget) as e:
        xf.option_roms(exe, Stop())
    assert [r["device"] for r in e.value.partial] == ["2489"]
    real = xf.option_roms

    def partial(data, budget=None, notes=None):
        err = xf.OverBudget("超過時間上限 1 秒，沒有解析完")
        err.partial = real(data)[:1]
        raise err
    monkeypatch.setattr(xf, "option_roms", partial)
    (tmp_path / "v.exe").write_bytes(exe)
    inv = xf.inventory([tmp_path / "v.exe"])
    assert [v["device"] for v in inv["vbios"]] == ["2489"] and inv["partial"][0]["reason"].startswith("vBIOS 解析：超過時間上限")
    assert inv["skipped"] == [] and xf.status_of(inv)[0] == "ATTENTION"


@pytest.mark.parametrize("args", [["--time-limit", "abc"], ["--bogus"], ["--time-limit", "0"], ["--time-limit", "-5"],
                                  ["--time-limit", "inf"], ["--time-limit", "nan"], ["--time-limi", "5"]])
def test_argument_error_is_fail_and_clears_outputs(tmp_path, args):
    out = tmp_path / "out"
    out.mkdir()
    for n in ("fw-inventory.json", "fw.cdx.json"):
        (out / n).write_text("{}", encoding="utf-8")
    r = cli("inventory", "--in", str(tmp_path), "--out", str(out), *args)
    assert r.returncode == 64 and r.stdout.startswith("FW-INVENTORY\tFAIL\t參數錯誤") and not list(out.iterdir()), r.stdout + r.stderr
    (out / "fw.cdx.json").write_text("{}", encoding="utf-8")
    r = cli("inventory", "--in", str(tmp_path), f"--out={out}", "--time-limit", "x")
    assert r.returncode == 64 and r.stdout.startswith("FW-INVENTORY\tFAIL\t") and not list(out.iterdir())


# ---------- 第六輪：雜散判斷線性時間、開頭決勝、較近的開頭要是合法影像、參數 ----------

def shared_pcir_window(m=1755, a=12600, size=0x10800):
    """以前是平方時間的排法：A 區 m 個雜散特徵碼（間隔 7），各自的 0x18 指標指到 C 區自己的 PCIR；B 區對每個 PCIR 各有一個較近的開頭。
    以前每個 A 的候選都要往後掃過約 m 個特徵碼才找到較近的開頭（0.54 MB 約 4.8 秒）。"""
    w = bytearray(size)
    c = 2 * a
    for i in range(m):
        r = c + 0x18 * i
        for q in (7 * i, a + 7 * i):
            w[q:q + 2] = b"\x55\xaa"
            struct.pack_into("<H", w, q + 0x18, r - q)
        w[a + 7 * i + 2] = 112                                          # B 區的開頭（真的那個）影像大小相符 → 選它、不用說明
        w[r:r + 4] = b"PCIR"
        struct.pack_into("<HHHHB", w, r + 4, 0x10DE, 0x2489, 0, 0x18, 0)
        struct.pack_into("<HHBB", w, r + 0x10, 112, 1, 0, 0x80)
    return bytes(w)


def test_stray_signature_check_is_linear(monkeypatch):
    import time
    win = shared_pcir_window()
    # 工作量（不受機器快慢影響）：struct.unpack_from 的呼叫次數要和特徵碼數成正比；以前每個雜散候選都掃約 1755 個特徵碼
    data = win * 2
    sigs = len(xf.IMAGE_SIG_RE.findall(data))
    calls = [0]
    real = xf.struct

    class Counting:
        def __getattr__(self, name):
            return getattr(real, name)

        def unpack_from(self, *a):
            calls[0] += 1
            return real.unpack_from(*a)
    monkeypatch.setattr(xf, "struct", Counting())
    roms = xf.option_roms(data)
    monkeypatch.setattr(xf, "struct", real)
    assert calls[0] < 20 * sigs, (calls[0], sigs)
    assert roms and all(r["offset"] % len(win) >= 12600 and not r.get("start_note") for r in roms)   # A 區的雜散特徵碼都不算
    # 時間：16 個區塊（1.1 MB，以前約 9 秒）；上限放寬給慢的 CI
    data = win * 16
    t = time.monotonic()
    xf.option_roms(data, xf.Budget(time_limit=60))
    assert time.monotonic() - t < 3
    # 時間上限照樣有效（建索引那一段也會檢查）
    with pytest.raises(xf.OverBudget) as e:
        xf.option_roms(data, xf.Budget(time_limit=-1))
    assert e.value.partial == []


def test_image_starts_memory_is_bounded():
    """ImageStarts 只保留目前位置附近的 PCIR，不會每個檔案記下全部。"""
    win = shared_pcir_window()
    data = win * 16
    s = xf.ImageStarts(data)
    most = 0
    for k in range(16):
        p = k * len(win) + 12600                                           # 每個區塊 B 區的第一個開頭
        r = p + struct.unpack_from("<H", data, p + 0x18)[0]
        assert s.owner(p, r)[0] == p                                       # B 區的開頭是唯一大小相符的最近候選
        most = max(most, len(s.by_pcir))
    assert most <= 6 * 1755                                               # 全部是 16×1755


def header_stray(img, at=0x20, size_byte=0):
    """真 ROM 的標頭裡剛好有 "VN"（0x4E56）、+0x18 剛好指到同一個 PCIR（0x40）。"""
    b = bytearray(img)
    b[at:at + 2] = b"\x56\x4e"
    b[at + 2] = size_byte
    struct.pack_into("<H", b, at + 0x18, 0x40 - at)
    return bytes(b)


def test_signature_inside_real_header_is_flagged_not_silent(tmp_path):
    """以前選了後面那個開頭：offset 0x20、雜湊多算 0x20 bytes，狀態仍 OK。最近的開頭仍然勝出（雜散的特徵碼在真 ROM 前方時要這樣，
    見 test_real_header_size_smaller_than_image_is_not_silent），但標頭的影像大小和 PCIR 長度不符 → start_note、ATTENTION、SBOM 標出來。"""
    real = header_stray(option_image(0x10DE, 0x2489, 2, 0, True, b"NVIDIA VBIOS Version 94.04.5E.00.92"))
    (tmp_path / "a.rom").write_bytes(real)
    inv = xf.inventory([tmp_path / "a.rom"])
    v = inv["vbios"][0]
    assert v["found_at"][0]["offset"] == 0x20 and "2 image starts point at the PCIR at file offset 0x40" in v["start_note"]
    assert "does not match" in v["start_note"]
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "ROM 開頭不確定" in detail
    comps, deps = xf.components(inv)
    assert any(p["name"] == "sca-center:note" and "ambiguous" in p["value"] for p in comps[0]["properties"])
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    # 兩個開頭的影像大小都相符：也記下來
    amb = header_stray(option_image(0x10DE, 0x2489, 2, 0, True), size_byte=2)
    r = xf.option_roms(amb)
    assert [x["offset"] for x in r] == [0x20] and "2 of them have a header image size matching" in r[0]["start_note"]
    # 沒有正常結束、從 p＋2 重找：同一個 PCIR 不會變成兩個 ROM
    broken = header_stray(option_image(0x10DE, 0x2489, 2, 0, False)) + b"\xff" * 1024
    r = xf.option_roms(broken)
    assert [(x["offset"], x["terminated"]) for x in r] == [(0x20, "invalid-next-image")] and r[0]["start_note"]


def test_nearest_start_with_broken_chain_loses_to_one_that_ends_normally():
    """真 ROM 是 x86＋EFI 兩個影像，x86 影像的標頭裡 0x20 有雜散的 "VN" 指到同一個 PCIR。從 0x20 串，下一個位置不是影像（鏈斷了）；
    從 0 串正常結束 → 選 0（一定記 start_note）。以前選 0x20：一個沒正常結束的假 ROM，EFI 影像另外變成一個沒有說明的 ROM。"""
    import hashlib
    real = header_stray(option_image(0x10DE, 0x2489, 2, 0, False, b"NVIDIA VBIOS Version 94.04.5E.00.92")) + \
        option_image(0x10DE, 0x2489, 1, 3, True)
    roms = xf.option_roms(real + b"\xff" * 512)
    assert [(r["offset"], r["length"], r["terminated"]) for r in roms] == [(0, 1536, "last-flag")]
    assert roms[0]["sha256"] == hashlib.sha256(real).hexdigest() and "whose image chain ends normally" in roms[0]["start_note"]


def test_real_header_size_smaller_than_image_is_not_silent(tmp_path):
    """PCI 3.0：標頭第 2 個 byte 是 init size，可以小於影像長度。真 ROM（0x200，byte2＝0）前方 0x100 有雜散的 55AA，byte2 剛好等於
    PCIR 長度：不能因為影像大小而改選雜散的（雜湊錯、而且沒有說明）。仍選最近的真 ROM，但記下來。"""
    import hashlib
    real = bytearray(option_image(0x10DE, 0x2489, 2, 0, True, b"NVIDIA VBIOS Version 94.04.5E.00.92"))
    real[2] = 0
    data = bytearray(0x200) + real + b"\xff" * 0x200
    data[0x100:0x103] = b"\x55\xaa\x02"
    struct.pack_into("<H", data, 0x118, 0x140)
    roms = xf.option_roms(bytes(data))
    assert [(r["offset"], r["length"]) for r in roms] == [(0x200, 1024)]
    assert roms[0]["sha256"] == hashlib.sha256(bytes(real)).hexdigest() and "does not match" in roms[0]["start_note"]
    (tmp_path / "x.rom").write_bytes(bytes(data))
    assert xf.status_of(xf.inventory([tmp_path / "x.rom"]))[0] == "ATTENTION"


@pytest.mark.parametrize("b_size", [0, 2])
def test_start_inside_an_accepted_rom_is_not_a_candidate(b_size):
    """ROM A（0–0x3FF）的內容裡 0x300 有 55AA、byte2＝2、+0x18 指到 ROM B（0x400）的 PCIR。A 被接受以後 0x300 不會再被看，
    不能算 B 的候選：以前 B 的 byte2 不符時 owner 選了 0x300、B 整個消失（沒有任何說明）；相符時多一個假的 start_note。"""
    a = option_image(0x10DE, 0x2489, 2, 0, True, b"NVIDIA VBIOS Version 94.04.5E.00.92")
    b = bytearray(option_image(0x10DE, 0x2504, 2, 0, True, b"NVIDIA VBIOS Version 94.06.1C.00.10"))
    b[2] = b_size
    data = bytearray(a + bytes(b) + b"\xff" * 0x200)
    data[0x300:0x303] = b"\x55\xaa\x02"
    struct.pack_into("<H", data, 0x318, 0x440 - 0x300)
    roms = xf.option_roms(bytes(data))
    assert [(r["offset"], r["device"], r["terminated"], r.get("start_note")) for r in roms] == [
        (0, "2489", "last-flag", None), (0x400, "2504", "last-flag", None)]


def test_long_accepted_rom_is_not_rescanned(monkeypatch):
    """一個 4 MB、正常結束的 ROM，裡面塞滿各自合法的小影像（間隔 0x34）；後面還有一個 ROM。ImageStarts 不能把被跳過的範圍整個掃一遍
    （以前每個都呼叫 pci_image、每個 PCIR 記一筆：記憶體約 1.7 倍輸入大小）。"""
    cell = bytearray(0x34)
    cell[0:2] = b"\x55\xaa"
    struct.pack_into("<H", cell, 0x18, 0x1A)
    cell[0x1A:0x1E] = b"PCIR"
    struct.pack_into("<HHHHB", cell, 0x1E, 0x8086, 0x1234, 0, 0x18, 0)
    struct.pack_into("<HHBB", cell, 0x2A, 1, 1, 0, 0x80)
    size = 8192 * 512
    body = bytearray(bytes(cell) * (size // 0x34 + 1))[:size]
    body[0:0x200] = option_image(0x10DE, 0x2489, 1, 0, True)[:0x200]
    struct.pack_into("<H", body, 0x50, 8192)                              # 第一個 ROM：PCIR 長度 8192×512 = 4 MB
    data = bytes(body) + option_image(0x10DE, 0x2504, 2, 0, True)
    calls = [0]
    real = xf.pci_image

    def counting(*a):
        calls[0] += 1
        return real(*a)
    monkeypatch.setattr(xf, "pci_image", counting)
    roms = xf.option_roms(data)
    assert [(r["offset"], r["length"]) for r in roms] == [(0, size), (size, 1024)]
    assert calls[0] < 100, calls[0]                                       # 以前約 8 萬次（每個被跳過的小影像一次）


@pytest.mark.parametrize("at", [0x21, 0x20])
def test_nearer_start_must_be_a_valid_image(at):
    """真 ROM 的 PCIR 長度 0、長度只靠 NPDE；標頭裡的雜散 "VN" 指到同一個 PCIR。0x21（不對齊）：以它為起點找不到 NPDE、
    不是合法影像 → 不能因為它把真 ROM 丟掉（以前一個 ROM 都沒有）。0x20：以它為起點也是合法影像 → 最近的勝出，但大小不符要記 start_note。"""
    b = bytearray(with_npde(option_image(0x10DE, 0x2489, 2, 0, True), 2, True))
    struct.pack_into("<H", b, 0x50, 0)                                    # PCIR 長度 0
    real = header_stray(bytes(b), at=at)
    roms = xf.option_roms(real)
    if at == 0x21:
        assert [(r["offset"], r["length"], r["images"][0]["length_basis"]) for r in roms] == [(0, 1024, "NPDE")]
        assert "start_note" not in roms[0]
    else:
        assert [r["offset"] for r in roms] == [0x20] and "does not match" in roms[0]["start_note"]


def test_option_abbreviations_are_rejected(tmp_path):
    """--ou 不能當成 --out（參數錯誤時 out_arg 找不到它，上一次的輸出不會被清掉）。"""
    (tmp_path / "BIOS.bin").write_bytes(spi_image())
    r = cli("inventory", "--in", str(tmp_path / "BIOS.bin"), "--ou", str(tmp_path / "out"))
    assert r.returncode == 64 and r.stdout.startswith("FW-INVENTORY\tFAIL\t參數錯誤") and not (tmp_path / "out").exists()


def test_status_counts_files_not_entries():
    """skipped 與 partial 都以檔案數計（同一個檔案可能有多筆原因）。"""
    inv = {"vbios": [], "other_roms": [], "bios": [], "skipped": [{"file": "a.zip", "reason": "x"}, {"file": "a.zip", "reason": "y"}],
           "partial": [{"file": "b.exe", "reason": "x"}, {"file": "b.exe", "reason": "y"}]}
    st, detail = xf.status_of(inv)
    assert st == "GAP" and "略過 1 個檔案" in detail and "1 個檔案只解析了一部分" in detail


# ---------- 第七輪：快取的決定過期、鏈檢查上限用完、不確定的 ROM 之後的 ROM ----------

def stray_at(d, q, r, size_byte):
    d[q:q + 3] = b"\x55\xaa" + bytes([size_byte])
    struct.pack_into("<H", d, q + 0x18, r - q)


def test_cached_owner_covered_by_a_later_rom_is_decided_again():
    """0x0 與 0x300 的雜散特徵碼都指到 ROM B（0x600）的 PCIR；0x0 先問，決定給 0x300（B 的鏈斷了、0x300 的鏈正常結束）；
    之後 ROM A（0x100）被接受、蓋過 0x300。以前 B 來問時拿到過期的決定（0x300）→ B 整個消失、沒有任何說明。"""
    d = bytearray(0x2000)
    d[0x100:0x500] = option_image(0x10DE, 0x2489, 2, 0, True)
    d[0x600:0x1600] = option_image(0x10DE, 0x2504, 8, 0, False)
    stray_at(d, 0x0, 0x640, 8)
    stray_at(d, 0x300, 0x640, 8)
    d[0x1300:0x1500] = option_image(0x10DE, 0x1111, 1, 0xE0, True)
    roms = xf.option_roms(bytes(d))
    assert [(r["offset"], r["device"], r["terminated"]) for r in roms] == [
        (0x100, "2489", "last-flag"), (0x600, "2504", "invalid-next-image"), (0x1300, "1111", "last-flag")]


def test_chosen_start_swallowed_with_no_candidate_left_is_noted():
    """PCIR P（0x1040，前面沒有真的開頭）：0x0 與 0x600 的雜散特徵碼都指到它，0x0 先問、決定給較近的 0x600（0x0 因此被丟掉）。
    0x400 的真 ROM（x86＋EFI，標頭裡也有雜散 "VN"）開頭不確定、從 EFI 之後重找 → 0x600 沒有被看到，也不是任何影像的開頭、
    不在開頭確定的 ROM 裡 → P 沒有任何 ROM，要記在 notes（partial）。"""
    d = bytearray(0x1400)
    real = bytearray(option_image(0x10DE, 0x2489, 2, 0, False) + option_image(0x10DE, 0x2489, 1, 3, True))
    real[0x20:0x23] = b"\x56\x4e\x00"
    struct.pack_into("<H", real, 0x38, 0x20)
    d[0x400:0xA00] = real
    d[0x1040:0x1044] = b"PCIR"
    struct.pack_into("<HHHHB", d, 0x1044, 0x10DE, 0x1111, 0, 0x18, 0)
    struct.pack_into("<HHBB", d, 0x1050, 9, 1, 0xE0, 0x80)                # 9 個單位：指標 0x1040 要在影像長度內
    stray_at(d, 0x0, 0x1040, 0)
    stray_at(d, 0x600, 0x1040, 0)
    notes = []
    roms = xf.option_roms(bytes(d), notes=notes)
    assert [(r["offset"], bool(r.get("start_note"))) for r in roms] == [(0x400, True)]
    assert any("PCIR 0x1040" in x and "沒有變成 ROM" in x for x in notes), notes


def test_stray_pointing_at_a_later_image_of_an_accepted_rom_is_not_lost(tmp_path):
    """多影像 ROM A（0x200）前方 0x100 有雜散 55AA，+0x18 指到 A 第二個影像（0x600）的 PCIR。0x600 是 A 鏈裡的影像開頭、已經用掉：
    以前在 partial 記「PCIR 0x640 沒有變成 ROM」，狀態多「1 個檔案只解析了一部分」，其實什麼都沒少。"""
    a = option_image(0x10DE, 0x2489, 2, 0, False, b"NVIDIA VBIOS Version 94.04.5E.00.92") + option_image(0x10DE, 0x2489, 8, 3, True)
    d = bytearray(0x200) + a + b"\xff" * 0x200
    stray_at(d, 0x100, 0x640, 8)
    notes = []
    roms = xf.option_roms(bytes(d), notes=notes)
    assert [(r["offset"], r["length"], r["terminated"], r.get("start_note")) for r in roms] == [(0x200, 5120, "last-flag", None)]
    assert notes == []
    (tmp_path / "c.rom").write_bytes(bytes(d))
    inv = xf.inventory([tmp_path / "c.rom"])
    assert inv["partial"] == [] and "只解析了一部分" not in xf.status_of(inv)[1]


def test_lost_pcir_notes_are_bounded(tmp_path):
    """shared_pcir_window 的 B 區開頭大小相符、各自正常結束：每個 B 的 ROM（56 KB）都蓋過後面的 B，那些 PCIR 早就被 A 區問過、決定給被蓋過的 B。
    以前每個都在 partial 記一筆（4.2 MB 輸入 → 88,193 筆、17 MB 的 fw-inventory.json）；被開頭確定的 ROM 蓋過的不算，記的也有上限。"""
    data = shared_pcir_window() * 16
    notes = []
    xf.option_roms(data, notes=notes)
    assert len(notes) <= 12, len(notes)
    (tmp_path / "x.rom").write_bytes(data)
    inv = xf.inventory([tmp_path / "x.rom"])
    assert len(inv["partial"]) <= 12 and len(json.dumps(inv, ensure_ascii=False)) < 1 << 20
    # 真的沒有變成 ROM 的：只列 MAX_LOST_NOTES 個，其餘合成一筆
    st = xf.ImageStarts(b"")
    for k in range(20):
        e = xf._Pcir()
        e.decision = (k, None)
        st._lost(0x100 + k, e)
    assert len(st.all_notes()) == xf.MAX_LOST_NOTES + 1 and "另外還有 12 個" in st.all_notes()[-1]


@pytest.mark.parametrize("exc", [xf.OverBudget("超過時間上限 1 秒，沒有解析完"), struct.error("boom")])
def test_vbios_notes_survive_an_exception(tmp_path, monkeypatch, exc):
    """option_roms 記了原因（例如鏈檢查上限）之後才超時或解析失敗：那些原因也要進 partial。"""
    def failing(data, budget=None, notes=None):
        notes.append("選 PCIR 的影像開頭時試串影像鏈的次數達上限 0")
        if isinstance(exc, xf.OverBudget):
            exc.partial = []
        raise exc
    monkeypatch.setattr(xf, "option_roms", failing)
    (tmp_path / "v.rom").write_bytes(vbios_rom(0x2489, "94.04.5E.00.92"))
    inv = xf.inventory([tmp_path / "v.rom"])
    reasons = [x["reason"] for x in inv["partial"]]
    assert any("達上限 0" in x for x in reasons) and len(reasons) == 2, reasons


def l1_multi(real_size=0, stray_size=2):
    """x86＋EFI 的真 ROM，x86 標頭 0x20 有雜散的 "VN" 指到同一個 PCIR。"""
    d = bytearray(option_image(0x10DE, 0x2489, 2, 0, False, b"NVIDIA VBIOS Version 94.04.5E.00.92") + option_image(0x10DE, 0x2489, 2, 3, True)
                  + b"\xff" * 0x400)
    d[2] = real_size
    d[0x20:0x23] = b"\x56\x4e" + bytes([stray_size])
    struct.pack_into("<H", d, 0x38, 0x20)
    return bytes(d)


def test_chain_check_limit_is_recorded_and_never_silent(tmp_path, monkeypatch):
    """鏈檢查的總數用完（構造的輸入可以先燒完）：以前最近的（雜散的 0x20）靜默勝出，EFI 影像另外變成一個看起來正常的 vBIOS。
    現在：上限記在 partial；選擇記 start_note；在它範圍裡開始的 EFI 也記 start_note。"""
    monkeypatch.setattr(xf, "MAX_CHAIN_CHECK", 0)
    (tmp_path / "x.rom").write_bytes(l1_multi())
    inv = xf.inventory([tmp_path / "x.rom"])
    assert any("達上限 0" in x["reason"] for x in inv["partial"])
    assert inv["vbios"] and all(v["start_note"] for v in inv["vbios"]) and len(inv["vbios"]) == 2
    assert "check limit reached" in xf.option_roms(l1_multi())[0]["start_note"]
    assert xf.status_of(inv)[0] == "ATTENTION"


def test_rom_after_an_uncertain_start_is_still_found():
    """單一影像的真 ROM 標頭 0x20 有 "VN"：最近的 0x20 勝出（有 start_note），它的範圍 0x20–0x420 蓋到下一個 ROM（0x400）的開頭。
    以前直接跳到 0x420，下一個 ROM（2504）不見了；現在從 0x22 重找，找得到（也標出來：兩個範圍重疊）。"""
    one = bytearray(option_image(0x10DE, 0x2489, 2, 0, True))
    one[0x20:0x23] = b"\x56\x4e\x00"
    struct.pack_into("<H", one, 0x38, 0x20)
    roms = xf.option_roms(bytes(one) + option_image(0x10DE, 0x2504, 2, 0, True))
    assert [(r["offset"], r["device"]) for r in roms] == [(0x20, "2489"), (0x400, "2504")]
    assert all(r.get("start_note") for r in roms) and "inside the range" in roms[1]["start_note"]


# ---------- BIOS 第 2a 步：CSME（$FPT）、FIT 微碼、AMD、UEFI 壓縮統計、fw-inventory.md ----------

import uuid  # noqa: E402

FFS2 = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"
LZMA = "EE4E5898-3914-4259-9D6E-DC7BD79403CF"
LZMA_F86 = "D42AE6BD-1352-4BFB-909A-CA72A6EAE889"
BROTLI = "3D532050-5CDA-4FD0-879E-0F7F630D5AFB"
TIANO = "A31280AD-481E-41B6-95E8-127F4C984779"
CRC32 = "FC1BCDB0-7D31-49AA-936A-A4600D9DD083"
SIGNED = "A7717414-C616-4977-9420-844712A735BF"     # 不是壓縮、需要處理的 GUID（RSA2048/SHA256）


def cpd(entries, part=b"FTPR", hl=0x10):
    """$CPD 目錄（MEAnalyzer CPD_Header_R1／R2）：表頭 hl bytes，每項 0x18（名稱 12、offset、大小、保留）。"""
    h = bytearray(hl)
    h[0:4] = b"$CPD"
    struct.pack_into("<I", h, 4, len(entries))
    h[8], h[9], h[0x0A] = 1 if hl == 0x10 else 2, 1, hl
    h[0x0C:0x10] = part
    for n, o in entries:
        h += n.ljust(12, b"\x00") + struct.pack("<III", o, 0x80, 0)
    return bytes(h)


def fpt(entries, n=None):
    """$FPT 表頭 0x20 bytes＋每項 0x20 bytes（名稱、owner、offset、size，相對 ME 區域開頭；me_cleaner、MEAnalyzer）。"""
    h = bytearray(0x20)
    h[0:4] = b"$FPT"
    struct.pack_into("<I", h, 4, len(entries) if n is None else n)
    h[8], h[9], h[0x0A] = 0x20, 0x10, 0x20
    for name, off, size in entries:
        h += name.ljust(4, b"\x00") + b"\x00" * 4 + struct.pack("<II", off, size) + b"\x00" * 16
    return bytes(h)


def me_region(style, fpt_off=0, size=0x6000, hl=0x10):
    """ME 區域：RBEP 分割區（0x800，誘餌版本 16.0.0.1）在 FTPR（0x2000）前面。
    me11：兩個分割區都以 $CPD 開頭、manifest 在 xxxx.man 那一項；me10：沒有 $CPD，manifest 就在分割區開頭。"""
    r = bytearray(b"\xff" * size)
    t = fpt([(b"RBEP", 0x800, 0x800), (b"FTPR", 0x2000, 0x1000)])
    r[fpt_off:fpt_off + len(t)] = t
    decoy, real = me_manifest((16, 0, 0, 1), 0x20220101), me_manifest((16, 1, 30, 2307), 0x20230501)
    if style == "me11":
        c = cpd([(b"RBEP.man", 0x40)], b"RBEP", hl)
        r[0x800:0x800 + len(c)] = c
        r[0x840:0x8C0] = decoy
        c = cpd([(b"FTPR.cse", 0x200), (b"FTPR.man", 0x80)], b"FTPR", hl)
        r[0x2000:0x2000 + len(c)] = c
        r[0x2080:0x2100] = real
    else:
        r[0x800:0x880] = decoy
        r[0x2000:0x2080] = real
    return bytes(r)


def with_me(region):
    img = bytearray(spi_image())
    img[0x1000:0x7000] = region                   # spi_image 的 ME 區域 0x1000–0x6FFF（覆蓋原本的 $MN2）
    return bytes(img)


@pytest.mark.parametrize("style,fpt_off,hl", [("me11", 0, 0x10), ("me11", 0x10, 0x14), ("me10", 0, 0x10), ("me10", 0x10, 0x10)])
def test_me_version_from_fpt_ftpr_partition(style, fpt_off, hl):
    """$FPT（區域開頭或 +0x10）→ FTPR 分割區 → manifest。ME 10 型沒有 $CPD：以前退回「第一個 $MN2」，拿到前面分割區的 16.0.0.1。"""
    b = xf.bios_image(with_me(me_region(style, fpt_off, hl=hl)))
    assert b["me_status"] == "found" and b["me_note"] is None
    assert (b["me"]["version"], b["me"]["date"], b["me"]["offset"]) == ("16.1.30.2307", "2023-05-01",
                                                                         0x1000 + (0x2080 if style == "me11" else 0x2000))
    assert b["me"]["basis"] == ("FTPR partition ($FPT, $CPD FTPR.man)" if style == "me11" else
                                "FTPR partition ($FPT, manifest at the partition start, no $CPD)")
    assert b["me"]["other_versions"] == ["16.0.0.1"] and b["me"]["family"] is None
    if style == "me10":                            # 舊的做法（沒有 $FPT 時的退路）會選錯：證明這裡走的是 $FPT
        assert xf.me_manifests(with_me(me_region(style, fpt_off)), 0x1000, 0x7000)[0]["version"] == "16.0.0.1"


def test_me_states_no_me_region_and_unknown(tmp_path):
    # 只有 BIOS 區域的更新檔（沒有 descriptor、沒有 $FPT、沒有 $MN2）→ no-me-region，不是 unknown
    bios_only = bytearray(spi_image(with_descriptor=False))
    for o in (0x1100, 0x2100, 0x3100):
        bios_only[o:o + 0x80] = b"\xff" * 0x80
    b = xf.bios_image(bytes(bios_only))
    assert (b["me"], b["me_status"]) == (None, "no-me-region") and "no flash descriptor, no $FPT and no $CPD named FTPR" in b["me_note"]
    # descriptor 裡沒有 ME 區域
    no_me = bytearray(spi_image())
    struct.pack_into("<I", no_me, 0x48, 0x00007FFF)
    b = xf.bios_image(bytes(no_me))
    assert b["me_status"] == "no-me-region" and b["me_note"] == "the flash descriptor has no ME region"
    # 有 ME 區域、$FPT 在，但 FTPR 的 manifest 壞了（tag 改掉），區域裡也沒有其他 $MN2 → unknown、ATTENTION
    bad = bytearray(me_region("me10"))
    bad[0x81C:0x820] = b"XXXX"
    bad[0x201C:0x2020] = b"XXXX"
    b = xf.bios_image(with_me(bytes(bad)))
    assert (b["me"], b["me_status"]) == (None, "unknown") and "no valid $MN2 manifest at the start of the FTPR partition" in b["me_note"]
    # 有 ME 區域但完全是空的（沒有 $FPT、沒有 $MN2）→ unknown
    b = xf.bios_image(with_me(b"\xff" * 0x6000))
    assert b["me_status"] == "unknown" and "no $FPT" in b["me_note"]
    p = tmp_path / "BIOS.bin"
    p.write_bytes(with_me(bytes(bad)))
    inv = xf.inventory([p])
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "ME 版本 unknown" in detail
    comps, deps = xf.components(inv)
    me_reg = next(c for c in comps if c["name"] == "me region")
    assert {"name": "sca-center:me-status", "value": "unknown"} in me_reg["properties"]
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))


def test_me_fpt_broken_falls_back_to_cpd_scan_with_note():
    """$FPT 在但沒有 FTPR 那一項：保留舊的 $CPD 做法當退路（basis 照舊），原因記在 me_note。"""
    r = bytearray(me_region("me11"))
    r[0x20 + 0x20:0x20 + 0x24] = b"XXXX"          # 第二項（FTPR）改名
    b = xf.bios_image(with_me(bytes(r)))
    assert b["me_status"] == "found" and b["me"]["version"] == "16.1.30.2307" and b["me"]["basis"] == "FTPR partition manifest"
    assert "has no FTPR partition" in b["me_note"] and "fell back" in b["me_note"]


def test_standalone_me_update_file(tmp_path):
    """單獨的 ME 更新檔（有 $FPT、沒有 descriptor）：照樣解析、basis 寫明；FIT 不適用。"""
    b = xf.bios_image(me_region("me11", 0x10))
    assert not b["descriptor"] and b["me_status"] == "found" and b["me"]["version"] == "16.1.30.2307"
    assert b["me"]["basis"].startswith("FTPR partition ($FPT, $CPD FTPR.man); standalone ME image")
    assert b["fit"]["status"] == "not-applicable" and b["microcode"] == [] and b["incomplete"] == []
    # capsule 包著的（$FPT 不在 0／0x10）：也找得到，basis 寫明
    b = xf.bios_image(b"\x00" * 0x800 + me_region("me10"))
    assert b["me"]["version"] == "16.1.30.2307" and "$FPT at file offset 0x800 (e.g. a capsule)" in b["me"]["basis"]
    assert b["fit"]["status"] != "not-applicable"


def test_me_family_only_from_version_list(tmp_path):
    p = tmp_path / "BIOS.bin"
    p.write_bytes(with_me(me_region("me11")))
    comps, _ = xf.components(xf.inventory([p]))
    me = next(c for c in comps if c.get("version") == "16.1.30.2307")
    props = {x["name"]: x["value"] for x in me["properties"]}
    assert me["name"] == "Intel CSE firmware" and props["sca-center:me-family"] == "unknown" and props["sca-center:me-status"] == "found"
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST.splitlines()[0] + "\nMB-1,BIOS,1.05,me,csme,16.1.30.2307,,Intel,\n", encoding="utf-8")
    inv = xf.inventory([p], m)
    assert inv["bios"][0]["me"]["family"] == "CSME" and inv["comparison"][0]["result"] == "match"
    props = {x["name"]: x["value"] for c in xf.components(inv)[0] if c.get("version") == "16.1.30.2307" for x in c["properties"]}
    assert props["sca-center:me-family"] == "CSME" and props["sca-center:me-family-basis"] == "version list"


def with_fit(img, fit_off, entries, ptr=None):
    """在檔尾 −0x40 放 FIT 指標（檔尾對到 4 GB），fit_off 放 FIT：表頭 "_FIT_   "、size＝項目數（含表頭）、version 0x0100、type 0；
    entries：(type, 檔案位置或 ("raw", 位址))。"""
    b = bytearray(img)
    n = len(b)

    def addr(o):
        return o[1] if isinstance(o, tuple) else (1 << 32) - (n - o)
    t = b"_FIT_   " + (len(entries) + 1).to_bytes(3, "little") + b"\x00" + struct.pack("<HBB", 0x0100, 0, 0)
    for typ, o in entries:
        t += struct.pack("<Q", addr(o)) + b"\x00" * 4 + struct.pack("<HBB", 0x0100, typ, 0)
    b[fit_off:fit_off + len(t)] = t
    struct.pack_into("<Q", b, n - 0x40, addr(fit_off) if ptr is None else ptr)
    return bytes(b)


def test_fit_microcode_in_fit_and_bad_pointer(tmp_path):
    """FIT 兩份 microcode（0xB06A2 指到備援那份 0xA000）加一個指到不是 microcode 的位置（0xC000）、一個非 microcode 項目。"""
    img = with_fit(spi_image(), 0xE000, [(0x01, 0xA000), (0x01, 0xB000), (0x01, 0xC000), (0x02, 0xD000)])
    b = xf.bios_image(img)
    f = b["fit"]
    assert (f["status"], f["offset"], f["entries"]) == ("found", 0xE000, 4)
    assert [(e["entry"], e["offset"], e["valid"]) for e in f["microcode"]] == [(1, 0xA000, True), (2, 0xB000, True), (3, 0xC000, False)]
    assert [(u["cpuid"], u["offset"], u["in_fit"], u.get("fit_offset")) for u in b["microcode"]] == [
        ("000B06A2", 0x9000, True, 0xA000), ("000B0671", 0xB000, True, 0xB000)]
    assert any("FIT entry 3" in x and "no valid microcode header" in x for x in b["incomplete"])
    p = tmp_path / "BIOS.bin"
    p.write_bytes(img)
    inv = xf.inventory([p])
    assert xf.status_of(inv)[0] == "ATTENTION"
    comps, deps = xf.components(inv)
    uc = {c["name"]: {x["name"]: x["value"] for x in c["properties"]} for c in comps if c["name"].startswith("Intel CPU microcode")}
    assert uc["Intel CPU microcode 000B06A2"]["sca-center:in-fit"] == "true"
    assert "file offset 0xa000" in uc["Intel CPU microcode 000B06A2"]["sca-center:in-fit-basis"]
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    # 只列一份：另一份 in_fit False（FIT 找到了、沒有列它）
    b = xf.bios_image(with_fit(spi_image(), 0xE000, [(0x01, 0xB000)]))
    assert [(u["cpuid"], u["in_fit"]) for u in b["microcode"]] == [("000B06A2", False), ("000B0671", True)] and b["incomplete"] == []


def test_fit_pointer_outside_file_or_missing():
    # 指標像 FIT（4 GB 以下 16 MB 內），但對到檔案前面 → invalid、in_fit 不知道（不是 False）、incomplete
    b = xf.bios_image(with_fit(spi_image(), 0xE000, [(0x01, 0xB000)], ptr=(1 << 32) - 0x20000))
    assert b["fit"]["status"] == "invalid" and "maps outside the BIOS region" in b["fit"]["note"]
    assert all(u["in_fit"] is None for u in b["microcode"]) and any("in_fit unknown" in x for x in b["incomplete"])
    # 指標位置是 0xFF（舊平台、沒有 FIT）→ not-found，只記說明，不算不完整
    b = xf.bios_image(spi_image())
    assert b["fit"]["status"] == "not-found" and b["incomplete"] == [] and all(u["in_fit"] is None for u in b["microcode"])
    comps, _ = xf.components({"vbios": [], "bios": [dict(b, file="x.bin", locations=["x.bin"], sha256="0" * 64, sha512="0" * 128)]})
    assert {x["value"] for c in comps if c["name"].startswith("Intel CPU") for x in c["properties"] if x["name"] == "sca-center:in-fit"} == {"unknown"}
    # 指標對到檔案裡、但那裡不是 FIT 表頭 → invalid
    b = xf.bios_image(with_fit(spi_image(), 0xE000, [], ptr=(1 << 32) - 0x1000))
    assert b["fit"]["status"] == "invalid" and "no _FIT_ header" in b["fit"]["note"]
    # 只有 BIOS 區域的檔案：檔尾對到 4 GB
    b = xf.bios_image(with_fit(spi_image(with_descriptor=False), 0xE000, [(0x01, 0x9000)]))
    assert b["fit"]["status"] == "found" and b["microcode"][0]["in_fit"] is True


def test_fit_entry_cap_and_microcode_only_in_fit(monkeypatch):
    monkeypatch.setattr(xf, "MAX_FIT_ENTRIES", 2)
    b = xf.bios_image(with_fit(spi_image(), 0xE000, [(0x01, 0xB000)] + [(0x7F, 0xD000)] * 10))
    assert any("declares 11 entries; only the first 2" in x for x in b["incomplete"])
    # 全檔掃描的 checksum 上限用完、沒列到的 microcode：FIT 指到的照樣列出
    monkeypatch.setattr(xf, "MAX_CHECKSUM", 1024)
    b = xf.bios_image(with_fit(spi_image(), 0xE000, [(0x01, 0xB000)]))
    assert ("000B0671", True) in [(u["cpuid"], u["in_fit"]) for u in b["microcode"]]


def test_amd_platform_is_a_gap_not_no_microcode(tmp_path):
    img = bytearray(b"\xff" * 0x21000)
    img[0x20000:0x20004] = xf.AMD_EFS_SIG
    img[0x20800:0x20810] = b"$PSP" + struct.pack("<III", 0, 5, 0)
    img[0x20900:0x20910] = b"$BHD" + struct.pack("<III", 0, 0, 0)      # 項目數 0：不算
    b = xf.bios_image(bytes(img))
    assert b is not None and b["platform"] == "amd" and b["microcode"] == []
    assert b["amd_markers"] == ["AMD embedded firmware structure at 0x20000", "AMD $PSP directory at 0x20800"]
    assert any("AMD microcode" in x and "not 'no microcode'" in x for x in b["gaps"])
    p = tmp_path / "amd.bin"
    p.write_bytes(bytes(img))
    inv = xf.inventory([p])
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "AMD microcode 不支援（GAP" in detail
    md = xf.markdown(inv)
    assert "AMD microcode 不支援（GAP）" in md and "不代表沒有 microcode" in md
    assert xf.amd_markers(b"\xff" * 0x100 + b"$BHD" + struct.pack("<III", 0, 0, 0)) == []


# --- UEFI firmware volume（PI 規格：edk2 PiFirmwareVolume.h、PiFirmwareFile.h） ---

def sec(typ, body):
    return (4 + len(body)).to_bytes(3, "little") + bytes([typ]) + body


def secs(*xs):
    """section 之間 4 bytes 對齊（最後一個後面不補）。"""
    out = b""
    for x in xs:
        out += b"\x00" * (-len(out) % 4) + x
    return out


def comp(ctype, inner=b"\x11" * 8):
    return sec(0x01, struct.pack("<IB", len(inner), ctype) + inner)


def guided(g, inner=b"\x22" * 8, attr=0x01):
    return sec(0x02, uuid.UUID(g).bytes_le + struct.pack("<HH", 4 + 20, attr) + inner)


def ffs(ftype, body, state=0xF8, k=0):
    """FFS 檔案（EFI_FFS_FILE_HEADER 0x18）；erase polarity 1 時 state 位元反過來：0xF8 → DATA_VALID 是最高位。"""
    return bytes([k + 1] * 16) + b"\x00\x00" + bytes([ftype, 0]) + (0x18 + len(body)).to_bytes(3, "little") + bytes([state]) + body


def fv(files, fs=FFS2, tail=0x40):
    body = b""
    for f in files:
        body += b"\xff" * (-(0x48 + len(body)) % 8) + f
    body += b"\xff" * tail
    h = bytearray(0x48)
    h[0x10:0x20] = uuid.UUID(fs).bytes_le
    struct.pack_into("<Q", h, 0x20, 0x48 + len(body))
    h[0x28:0x2C] = b"_FVH"
    struct.pack_into("<IHHHBB", h, 0x2C, 0x800, 0x48, 0, 0, 0, 2)
    struct.pack_into("<II", h, 0x38, 1, 0x48 + len(body))
    struct.pack_into("<H", h, 0x32, (-sum(struct.unpack_from("<36H", h))) & 0xFFFF)
    return bytes(h) + body


def sample_fv():
    inner = fv([ffs(0x07, secs(guided(LZMA)), k=9)])                  # 巢狀 FV（FV image section 裡）：由 _FVH 掃描算一次
    return fv([
        ffs(0x07, secs(sec(0x10, b"MZ" + b"\x00" * 30), comp(1), sec(0x15, "Name".encode("utf-16-le"))), k=0),
        ffs(0x07, secs(comp(0, secs(guided(LZMA), guided(BROTLI)))), k=1),            # 沒壓縮的 compression section：往下走
        ffs(0x06, secs(guided(LZMA_F86), guided(TIANO), guided(SIGNED)), k=2),
        ffs(0x07, secs(guided(CRC32, secs(comp(1)), attr=0x02)), k=3),               # 不需處理的 GUID（CRC32）：往下走
        ffs(0x07, secs(comp(1)), state=0xE8, k=4),                                   # 已刪除：不算
        ffs(0x01, comp(1), k=5),                                                      # RAW 檔：不是 section 格式
        ffs(0xF0, b"\xff" * 16, k=6),                                                 # pad
        ffs(0x0B, secs(sec(0x17, b"\x00" * 4 + inner)), k=7),
        ffs(0x07, secs(comp(5)), k=8),                                                # 不認得的壓縮方式
    ])


def test_uefi_compressed_sections_are_counted_not_decompressed(tmp_path):
    nvram = fv([], fs="FFF12B8D-7696-4C8B-A985-2747075B4F50")                        # 其他檔案系統（NVRAM）：只計數
    img = bytearray(spi_image())
    data = sample_fv() + nvram
    img[0xC100:0xC100 + len(data)] = data
    b = xf.bios_image(bytes(img))
    u = b["uefi"]
    assert u["compressed"] == {"efi-standard": 2, "lzma": 2, "brotli": 1, "lzma-f86": 1, "tiano-custom": 1, "compression-type-0x05": 1}
    assert u["guided_other"] == {SIGNED: 1} and (u["volumes"], u["volumes_other_fs"]) == (2, 1) and u["notes"] == []
    assert u["files"] == 9                                                          # 8 個有效的＋巢狀 FV 的 1 個（刪除的不算）
    assert any(x.startswith("8 compressed UEFI sections not parsed (brotli 1, compression-type-0x05 1, efi-standard 2, lzma 2")
               for x in b["gaps"])
    assert any("1 GUID-defined UEFI sections that need processing" in x for x in b["gaps"])
    assert b["incomplete"] == []
    p = tmp_path / "BIOS.bin"
    p.write_bytes(bytes(img))
    inv = xf.inventory([p])
    st, detail = xf.status_of(inv)
    assert "8 個壓縮的 UEFI section 沒有解析（GAP" in detail
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST.splitlines()[0] + "\nMB-1,BIOS,1.05,me,,16.1.30.2307,,Intel,\nMB-1,BIOS,1.05,microcode,b06a2,4121,,,\n"
                 "MB-1,BIOS,1.05,microcode,b0671,123,,,\n", encoding="utf-8")
    # 其他都對上版本清單，只剩壓縮 section 沒有解析：工具知道自己略過了內容，不能是 OK
    st, detail = xf.status_of(xf.inventory([p], m))
    assert st == "ATTENTION" and detail.endswith("8 個壓縮的 UEFI section 沒有解析（GAP，裡面的模組與版本沒有列出）；"
                                                 "BIOS.bin：1 個需要處理的 GUID-defined UEFI section（GUID 不認得）沒有解析（GAP，裡面的模組與版本沒有列出）")
    img2 = bytearray(img)                                                            # 對照：沒有壓縮 section 的同一個映像 → OK
    img2[0xC100:0xC100 + len(data)] = b"\xff" * len(data)
    p.write_bytes(bytes(img2))
    assert xf.status_of(xf.inventory([p], m))[0] == "OK"
    comps, deps = xf.components(inv)
    props = {x["name"]: x["value"] for x in comps[0]["properties"]}
    assert props["sca-center:uefi-compressed-sections"] == "brotli=1, compression-type-0x05=1, efi-standard=2, lzma=2, lzma-f86=1, tiano-custom=1"
    assert not list(cdx_validator().iter_errors(xf.bom(comps, deps)))
    # 只有 FV 的檔案（例如 capsule 的內容）也算 BIOS 結構
    assert xf.bios_image(sample_fv())["uefi"]["volumes"] == 2


def test_uefi_bad_structures_and_caps(monkeypatch):
    bad = bytearray(sample_fv())
    bad[0x32] ^= 1                                                                    # header checksum 錯 → 不是 FV（巢狀的那個還在）
    assert xf.uefi_stats(bytes(bad), 0, len(bad))["volumes"] == 1
    short = bytearray(fv([ffs(0x07, secs(comp(1)))]))
    short[0x48 + 0x14:0x48 + 0x17] = (0x10000).to_bytes(3, "little")                # 檔案大小超出 FV
    u = xf.uefi_stats(bytes(short), 0, len(short))
    assert u["compressed"] == {} and "invalid size" in u["notes"][0]
    monkeypatch.setattr(xf, "MAX_FV", 1)
    u = xf.uefi_stats(sample_fv(), 0, len(sample_fv()))
    assert u["volumes"] == 1 and any("more than 1 firmware volumes" in x for x in u["incomplete"])
    monkeypatch.setattr(xf, "MAX_FV", 512)
    monkeypatch.setattr(xf, "MAX_FFS_ITEMS", 3)
    u = xf.uefi_stats(sample_fv(), 0, len(sample_fv()))
    assert any("more than 3 FFS files and sections" in x for x in u["incomplete"]) and u["files"] <= 2
    monkeypatch.setattr(xf, "MAX_FFS_ITEMS", 1 << 17)
    monkeypatch.setattr(xf, "MAX_SECTION_DEPTH", 0)
    u = xf.uefi_stats(sample_fv(), 0, len(sample_fv()))
    assert any("nested deeper than 0" in x for x in u["incomplete"]) and "brotli" not in u["compressed"]
    b = xf.bios_image(spi_image()[:0xC100] + sample_fv() + b"\xff" * 0x100)
    assert b is not None and any("nested deeper" in x for x in b["incomplete"])
    monkeypatch.setattr(xf, "MAX_FVH_SCAN", 1)
    u = xf.uefi_stats(sample_fv(), 0, len(sample_fv()))
    assert u["volumes"] == 1 and any("more than 1 _FVH candidates" in x for x in u["incomplete"])


def test_crafted_fvh_candidates_are_bounded():
    """每 16 bytes 一個 `_FVH`、HeaderLength 與 FvLength 都是 0x1000（每個候選都要算 header checksum）：候選數與時間都有上限。"""
    import time
    cell = bytearray(16)
    cell[0:4] = b"_FVH"
    struct.pack_into("<H", cell, 0x30 - 0x28, 0x1000)                                # 也是下一個候選的 FvLength（−8）
    data = bytes(cell) * (1 << 18)                                                    # 4 MB、26 萬個候選
    t = time.monotonic()
    u = xf.uefi_stats(data, 0, len(data))
    assert u["volumes"] == 0 and any("_FVH candidates" in x for x in u["incomplete"]) and time.monotonic() - t < 10
    with pytest.raises(xf.OverBudget):
        xf.uefi_stats(data, 0, len(data), xf.Budget(time_limit=-1))


def test_fpt_and_cpd_caps(monkeypatch):
    r = bytearray(me_region("me11"))
    struct.pack_into("<I", r, 4, 1000)                                               # 宣告 1000 個分割區
    b = xf.bios_image(with_me(bytes(r)))
    assert "declares 1000 partitions" in b["me_note"] and b["me"]["basis"] == "FTPR partition manifest"     # 退回 $CPD 掃描
    monkeypatch.setattr(xf, "MAX_CPD_ENTRIES", 1)
    b = xf.bios_image(with_me(me_region("me11")))
    assert "declares 2 entries" in b["me_note"]
    monkeypatch.setattr(xf, "MAX_FPT_SCAN", 0)                                        # 沒有 descriptor 的全檔 $FPT 搜尋也有上限
    b = xf.bios_image(b"\x00" * 0x800 + me_region("me10"))                           # 上限用完：unknown（不是 no-me-region）、記 incomplete
    assert b["me_status"] == "unknown" and any("more than 0 $FPT candidates" in x for x in b["incomplete"])


def test_fw_inventory_md_written_and_cleared_on_fail(tmp_path):
    img = with_fit(with_me(me_region("me11")), 0xE000, [(0x01, 0xB000)])
    img = img[:0xC100] + sample_fv() + img[0xC100 + len(sample_fv()):]
    d = tmp_path / "in"
    d.mkdir()
    (d / "BIOS|<b>.bin").write_bytes(img)                                            # 檔名是不可信資料：不能變成表格或 HTML
    bios_only = bytearray(spi_image(with_descriptor=False))
    for o in (0x1100, 0x2100, 0x3100):
        bios_only[o:o + 0x80] = b"\xff" * 0x80
    (d / "region.bin").write_bytes(bytes(bios_only))
    (d / "v.exe").write_bytes(nvflash_exe(vbios_rom(0x2489, "94.04.5E.00.92")))
    out = tmp_path / "out"
    r = cli("inventory", "--in", str(d), "--out", str(out))
    assert r.stdout.startswith("FW-INVENTORY\tATTENTION\t"), r.stdout + r.stderr
    md = (out / "fw-inventory.md").read_text(encoding="utf-8")
    assert "- found（找到）：1 個：BIOS\\|&lt;b&gt;.bin" in md and "- no-me-region（沒有 ME 區域）：1 個：region.bin" in md
    assert "- unknown（有 ME 區域，版本拿不到）：0 個" in md
    assert "| found（找到） | 16.1.30.2307 | 2023-05-01 | family unknown | 0x3080 | FTPR partition ($FPT, $CPD FTPR.man) |" in md
    assert "| 000B0671 | 0x32 | 0x123 | 2023-03-01 | true | 0xb000 |" in md and "| 000B06A2 | 0xE0 | 0x4121 | 2023-05-17 | false | 0x9000 |" in md
    assert "FIT：found（file offset 0xe000，1 項）" in md and "| lzma | 2 |" in md and "| efi-standard | 2 |" in md
    assert "AMI（未壓縮的字串，只是線索）" in md and "| 2489 | 94.04.5E.00.92 | last-flag |" in md
    assert "<b>" not in md
    inv = json.loads((out / "fw-inventory.json").read_text(encoding="utf-8"))
    assert "start_note" not in inv["vbios"][0]                                       # 沒有說明時不寫這個鍵（以前是 null）
    r = cli("inventory", "--in", str(d), "--manifest", str(tmp_path / "nope.csv"), "--out", str(out))
    assert r.stdout.startswith("FW-INVENTORY\tFAIL\t") and not list(out.iterdir())
    (out / "fw-inventory.md").write_text("old", encoding="utf-8")
    r = cli("inventory", "--in", str(d), "--out", str(out), "--bogus")
    assert r.returncode == 64 and not list(out.iterdir())


# ---------- 補充：退路不能報錯的分割區、AMD 誤判、$FPT +0x10、雜散 $FPT、family、&、$MN2 上限 ----------

def test_first_mn2_fallback_is_unknown_not_found(tmp_path):
    """沒有 $FPT（或 FTPR 拿不到）、也沒有 $CPD 指出 FTPR 時，以前取「第一個 $MN2」當 found：ME 10 型會報前面 RBEP 分割區的 16.0.0.1，
    SBOM 也是這個版本、狀態沒有 ME 的原因。現在是 unknown，候選版本只記在 me_note。$CPD 指出 FTPR 的退路照舊是 found。"""
    no_fpt = bytearray(me_region("me10"))
    no_fpt[0:4] = b"XXXX"
    bad_ftpr = bytearray(me_region("me10"))
    struct.pack_into("<I", bad_ftpr, 0x20 + 0x20 + 8, 0x3000)          # FTPR 的 offset 指到空白
    no_cpd = bytearray(spi_image())
    no_cpd[0x2000:0x2010] = b"\xff" * 16                                # 舊的 spi_image：沒有 $FPT、也沒有 $CPD
    for img, why in ((with_me(bytes(no_fpt)), "no $FPT"), (with_me(bytes(bad_ftpr)), "no valid $MN2 manifest at the start"),
                     (bytes(no_cpd), "no $FPT")):
        b = xf.bios_image(img)
        assert (b["me"], b["me_status"]) == (None, "unknown"), b["me"]
        assert why in b["me_note"] and "no $CPD names the FTPR partition" in b["me_note"] and "not reported as the CSE version" in b["me_note"]
    p = tmp_path / "BIOS.bin"
    p.write_bytes(with_me(bytes(no_fpt)))
    inv = xf.inventory([p])
    assert "ME 版本 unknown" in xf.status_of(inv)[1]
    comps, _ = xf.components(inv)
    assert all(c.get("version") != "16.0.0.1" for c in comps) and not any(c["name"] == "Intel CSE firmware" for c in comps)
    # $CPD 指出 FTPR 的退路：found
    me11 = bytearray(me_region("me11"))
    me11[0:4] = b"XXXX"
    b = xf.bios_image(with_me(bytes(me11)))
    assert (b["me_status"], b["me"]["version"], b["me"]["basis"]) == ("found", "16.1.30.2307", "FTPR partition manifest")


def test_amd_needs_efs_or_two_markers_and_never_on_intel(tmp_path):
    # Intel SPI 映像（descriptor＋Intel microcode）裡雜散的 $BHD／$PSP：不是 AMD
    d = bytearray(spi_image())
    d[0xD000:0xD010] = b"$BHD" + struct.pack("<III", 0, 1, 0)
    d[0xD100:0xD110] = b"$PSP" + struct.pack("<III", 0, 3, 0)
    b = xf.bios_image(bytes(d))
    assert b["platform"] is None and b["amd_markers"] == [] and not b["gaps"]
    # 沒有 descriptor、只有一種 cookie：不算；兩種：算
    one = b"\xff" * 0x100 + b"$PSP" + struct.pack("<III", 0, 3, 0) + b"\xff" * 0x100
    assert xf.amd_markers(one) == [] and xf.bios_image(one) is None
    two = one + b"$BHD" + struct.pack("<III", 0, 2, 0)
    assert xf.amd_markers(two) == ["AMD $PSP directory at 0x100", "AMD $BHD directory at 0x210"]
    # nvflash .exe（vBIOS 更新包）裡有 AMD 標記：不會變成 BIOS 映像
    exe = nvflash_exe(vbios_rom(0x2489, "94.04.5E.00.92")) + b"$PSP" + struct.pack("<III", 0, 3, 0) + b"$BHD" + struct.pack("<III", 0, 2, 0)
    (tmp_path / "v.exe").write_bytes(exe)
    inv = xf.inventory([tmp_path / "v.exe"])
    assert inv["bios"] == [] and [v["device"] for v in inv["vbios"]] == ["2489"]
    assert xf.bios_image(exe)["evidence"] == ["amd"]


def test_fpt_at_plus_0x10_is_tried_when_plus_0_is_bad():
    """+0 有 $FPT 但表壞了（分割區數 200）、+0x10 的表是好的：以前只看 +0 → 退回 $CPD 掃描。"""
    r = bytearray(me_region("me11", 0x10))
    r[0:8] = b"$FPT" + struct.pack("<I", 200)
    b = xf.bios_image(with_me(bytes(r)))
    assert b["me_status"] == "found" and b["me"]["basis"] == "FTPR partition ($FPT, $CPD FTPR.man)" and b["me_note"] is None


def test_stray_fpt_without_descriptor_is_not_an_me_region():
    """只有 BIOS 區域的檔案裡雜散的 "$FPT"（分割區數 3 看起來合理，但沒有 FTPR 那一項）：以前 unknown（ATTENTION），應該是 no-me-region。"""
    blob = bytearray(b"\xff" * 0x10000)
    blob[0x9000:0x9400] = microcode(0x000B06A2, 0x4121, 0x05172023)
    blob[0x6000:0x6008] = b"$FPT" + struct.pack("<I", 3)
    b = xf.bios_image(bytes(blob))
    assert b["me_status"] == "no-me-region" and "no flash descriptor, no $FPT and no $CPD named FTPR" in b["me_note"]
    struct.pack_into("<4sII", blob, 0x6020 + 0x20, b"FTPR", 0x100000, 0x1000)   # FTPR 那一項指到檔案外：也不算
    assert xf.bios_image(bytes(blob))["me_status"] == "no-me-region"


def test_me_family_needs_a_matching_version_row(tmp_path):
    p = tmp_path / "BIOS.bin"
    p.write_bytes(with_me(me_region("me11")))
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST.splitlines()[0] + "\nMB-1,BIOS,1.05,me,TXE,4.0.10.1,,Intel,\n", encoding="utf-8")   # 版本對不上
    inv = xf.inventory([p], m)
    assert inv["bios"][0]["me"]["family"] is None and inv["comparison"][0]["result"] == "mismatch"
    m.write_text(MANIFEST.splitlines()[0] + "\nMB-1,BIOS,1.05,me,TXE,4.0.10.1,,Intel,\nMB-1,BIOS,1.05,me,CSME,16.1.30,,Intel,\n",
                 encoding="utf-8")
    assert xf.inventory([p], m)["bios"][0]["me"]["family"] == "CSME"         # 相符的那一列（只填到 hotfix 也算）


def test_md_escapes_ampersand(tmp_path):
    (tmp_path / "x&lt;y.bin").write_bytes(spi_image())
    md = xf.markdown(xf.inventory([tmp_path / "x&lt;y.bin"]))
    assert "x&amp;lt;y.bin" in md and "x&lt;y" not in md


def test_loose_mn2_scan_is_capped(monkeypatch):
    """沒有 descriptor 的檔案塞滿 $MN2 header：以前每個一筆 dict（32 MB → 約 +229 MB 記憶體），現在最多 MAX_MN2 個、記在 incomplete。"""
    data = bytes(me_manifest((1, 2, 3, 4), 0x20230101)[:0x30]) * 2000
    notes = []
    assert len(xf.me_manifests(data, notes=notes)) == xf.MAX_MN2 and "more than 64 $MN2 manifests" in notes[0]
    b = xf.bios_image(data)
    assert b["me_status"] == "no-me-region" and "64 $MN2 manifest(s) in the file are not reported" in b["me_note"]
    assert any(x.startswith("ME: more than 64 $MN2") for x in b["incomplete"])
    with pytest.raises(xf.OverBudget):
        xf.me_manifests(data, budget=xf.Budget(time_limit=-1))


def test_amd_bios_with_a_pxe_rom_is_still_a_bios(tmp_path):
    """AMD BIOS（EFS 在 0x20000）裡有 Realtek PXE option ROM（10EC）、沒有 FV：以前「有 option ROM 就丟掉只有 AMD 標記的 BIOS」，
    結果 GAP。只有 NVIDIA vBIOS 更新包才丟。"""
    d = bytearray(b"\xff" * 0x30000)
    d[0x20000:0x20004] = xf.AMD_EFS_SIG
    rom = option_image(0x10EC, 0x8168, 2, 0, True)
    d[0x24000:0x24000 + len(rom)] = rom
    (tmp_path / "amd.bin").write_bytes(bytes(d))
    inv = xf.inventory([tmp_path / "amd.bin"])
    assert [(b["platform"], b["evidence"]) for b in inv["bios"]] == [("amd", ["amd"])]
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "AMD microcode 不支援" in detail


# ---------- 補充：CSME 12 型的單獨 ME 映像、$FPT 上限、_FVH 上限保留紀錄 ----------

def csme12_image(ftpr_ok=True):
    """CSME 12 以後的單獨 ME 映像（沒有 descriptor）：$FPT 在 +0x1000、只有其他分割區（沒有 FTPR 那一項），
    FTPR 只能從名稱是 FTPR 的 $CPD 目錄找（0x3000，FTPR.man 在 +0x80）；前面另有一個 RBEP 的 $CPD 與誘餌版本。"""
    r = bytearray(b"\xff" * 0x8000)
    t = fpt([(b"FTUP", 0x2000, 0x3000), (b"DLMP", 0x6000, 0x1000)])
    r[0x1000:0x1000 + len(t)] = t
    c = cpd([(b"RBEP.man", 0x40)], b"RBEP", 0x14)
    r[0x2000:0x2000 + len(c)] = c
    r[0x2040:0x20C0] = me_manifest((12, 0, 0, 1), 0x20200101)
    c = cpd([(b"FTPR.cse", 0x200), (b"FTPR.man", 0x80)], b"FTPR", 0x14)
    r[0x3000:0x3000 + len(c)] = c
    r[0x3080:0x3100] = me_manifest((12, 0, 90, 2072), 0x20230301)
    if not ftpr_ok:
        r[0x309C:0x30A0] = b"XXXX"                                               # FTPR.man 的 $MN2 tag 壞掉
    return bytes(r)


def test_csme12_standalone_me_image_found_via_ftpr_cpd(tmp_path):
    """以前：$FPT 沒有 FTPR 那一項 → 不算 ME 區域 → no-me-region，版本消失。"""
    b = xf.bios_image(csme12_image())
    assert (b["me_status"], b["me"]["version"], b["me"]["offset"]) == ("found", "12.0.90.2072", 0x3080)
    assert b["me"]["basis"] == ("FTPR $CPD FTPR.man ($CPD at file offset 0x3000; no flash descriptor; "
                                "$FPT at file offset 0x1000 has no FTPR entry)")
    assert b["me"]["other_versions"] == ["12.0.0.1"] and b["fit"]["status"] == "not-applicable"
    # FTPR 的 $CPD 在、但 manifest 壞了 → unknown（不是 no-me-region），原因寫明，誘餌版本不當成 CSE 版本
    b = xf.bios_image(csme12_image(ftpr_ok=False))
    assert (b["me"], b["me_status"]) == (None, "unknown")
    assert "ME structures found but no usable FTPR manifest" in b["me_note"] and "FTPR.man at 0x3080 is not a valid $MN2" in b["me_note"]
    assert "not reported as the CSE version" in b["me_note"]
    # 只有表頭像真的 $FPT（沒有 FTPR、也沒有 FTPR 的 $CPD）→ unknown
    only_fpt = bytearray(csme12_image())
    only_fpt[0x3000:0x3200] = b"\xff" * 0x200
    b = xf.bios_image(bytes(only_fpt))
    assert b["me_status"] == "unknown" and "$FPT at file offset 0x1000 has no FTPR entry" in b["me_note"]
    p = tmp_path / "me.bin"
    p.write_bytes(csme12_image())
    comps, _ = xf.components(xf.inventory([p]))
    assert any(c["name"] == "Intel CSE firmware" and c["version"] == "12.0.90.2072" for c in comps)


def test_fpt_candidate_cap_is_recorded_and_unknown(monkeypatch):
    """全檔找 $FPT 的候選數用完：以前沒有任何紀錄，結果是 no-me-region。"""
    data = (b"$FPT" + b"\xff" * 0x3C) * 70 + me_region("me10")
    b = xf.bios_image(data)
    assert b["me_status"] == "unknown" and any("more than 64 $FPT candidates" in x for x in b["incomplete"])
    assert "candidate limit reached" in b["me_note"]


def test_fvh_cap_without_other_evidence_keeps_a_record(monkeypatch, tmp_path):
    """只有 _FVH 候選（用完上限、沒有其他 BIOS 結構）：以前 bios_image 回傳 None，記錄與「沒找完」一起消失（GAP「沒有找到」）。"""
    monkeypatch.setattr(xf, "MAX_FVH_SCAN", 2)
    data = b"\x00" * 0x40 + b"_FVH" * 8 + b"\x00" * 0x40
    b = xf.bios_image(data)
    assert b is not None and b["evidence"] == ["uefi"] and any("_FVH candidates" in x for x in b["incomplete"])
    (tmp_path / "x.bin").write_bytes(data)
    assert xf.status_of(xf.inventory([tmp_path / "x.bin"]))[0] == "ATTENTION"


# ---------- 補充：capsule 裡兩個 ME 映像、GUID 不認得的 section ----------

def test_two_me_images_with_different_ftpr_versions_are_flagged(tmp_path):
    """capsule 裡兩個 CSME 12 型的 ME 映像（12.0.90.2072 在前、12.0.85.1000 在後）：以前靜默選第一個，第二個只出現在 other_versions。"""
    second = bytearray(csme12_image())
    second[0x3080:0x3100] = me_manifest((12, 0, 85, 1000), 0x20220601)
    data = b"\x00" * 0x400 + csme12_image() + b"\x00" * 0x400 + bytes(second)
    b = xf.bios_image(data)
    assert b["me_status"] == "found" and b["me"]["version"] == "12.0.90.2072" and "12.0.85.1000" in b["me"]["other_versions"]
    assert b["me_conflict"] == ("2 different FTPR manifest versions in the file: 12.0.90.2072 at 0x3480, 12.0.85.1000 at 0xb880; "
                                "reported 12.0.90.2072 at 0x3480 (the first one found by the method in basis); "
                                "the others are only in other_versions")
    assert b["me_conflict"] in b["me_note"]
    (tmp_path / "cap.bin").write_bytes(data)
    inv = xf.inventory([tmp_path / "cap.bin"])
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "有不同版本的 FTPR manifest" in detail
    comps, _ = xf.components(inv)
    me = next(c for c in comps if c["name"] == "Intel CSE firmware")
    assert any(x["name"] == "sca-center:me-note" and "2 different FTPR" in x["value"] for x in me["properties"])
    # 同一個版本出現兩次（備援）、單一映像：不是衝突
    assert xf.bios_image(b"\x00" * 0x400 + csme12_image() + b"\x00" * 0x400 + csme12_image())["me_conflict"] is None
    assert xf.bios_image(csme12_image())["me_conflict"] is None
    # 有 $FPT FTPR 的兩個 ME 10 型映像（沒有 descriptor）也一樣
    other10 = bytearray(me_region("me10"))
    other10[0x2000:0x2080] = me_manifest((11, 8, 50, 3425), 0x20190101)
    b = xf.bios_image(b"\x00" * 0x800 + me_region("me10") + bytes(other10))
    assert b["me"]["version"] == "16.1.30.2307" and "11.8.50.3425" in b["me_conflict"]


def test_unknown_processing_required_guid_sections_make_attention(tmp_path):
    """需要處理、GUID 不認得的 section（例如簽章）：以前列在 gaps、狀態仍 OK。"""
    m = tmp_path / "m.csv"
    m.write_text(MANIFEST.splitlines()[0] + "\nMB-1,BIOS,1.05,me,,16.1.30.2307,,Intel,\nMB-1,BIOS,1.05,microcode,b06a2,4121,,,\n"
                 "MB-1,BIOS,1.05,microcode,b0671,123,,,\n", encoding="utf-8")

    def status(fvdata):
        img = bytearray(spi_image())
        img[0xC100:0xC100 + len(fvdata)] = fvdata
        (tmp_path / "b.bin").write_bytes(bytes(img))
        return xf.status_of(xf.inventory([tmp_path / "b.bin"], m))
    assert status(fv([ffs(0x07, secs(sec(0x10, b"MZ" + b"\x00" * 30)))]))[0] == "OK"
    st, detail = status(fv([ffs(0x07, secs(guided(SIGNED)))]))
    assert st == "ATTENTION" and detail.endswith("1 個需要處理的 GUID-defined UEFI section（GUID 不認得）沒有解析（GAP，裡面的模組與版本沒有列出）")
