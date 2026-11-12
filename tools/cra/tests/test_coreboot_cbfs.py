"""coreboot_cbfs.py（CBFS／FMAP 解析、LZMA／LZ4）與 x86_firmware.py 的 coreboot SBOM 元件。
全部用測試自己組的假資料（FMAP＋CBFS 檔頭＋壓縮內容＋假 FSPH／VBT／revision／config），不含任何真實映像。"""
import json
import lzma
import struct
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import coreboot_cbfs as cb  # noqa: E402
import x86_firmware as xf  # noqa: E402
from cdx_schema import cdx_validator  # noqa: E402
from test_x86_firmware import microcode, spi_image  # noqa: E402

CLI = HERE.parent / "x86_firmware.py"
FULL_REV = "0123456789abcdef0123456789abcdef01234567"
EDK2_REV = "2a15268b36cc732aa9d0a34a33965de6b0fca122"


# ---------- 假資料 ----------

def lz4_seq(seqs, tail=b""):
    """LZ4 block：seqs＝[(literals, offset, match_len)…]，tail＝最後只有 literal 的 sequence。"""
    out = bytearray()
    for lit, off, ml in seqs:
        m = ml - 4
        out.append((min(len(lit), 15) << 4) | min(m, 15))
        if len(lit) >= 15:
            n = len(lit) - 15
            out += b"\xff" * (n // 255) + bytes([n % 255])
        out += lit + struct.pack("<H", off)
        if m >= 15:
            n = m - 15
            out += b"\xff" * (n // 255) + bytes([n % 255])
    out.append(min(len(tail), 15) << 4)
    if len(tail) >= 15:
        n = len(tail) - 15
        out += b"\xff" * (n // 255) + bytes([n % 255])
    return bytes(out + tail)


def lz4_frame_of(blocks, content_size=None, block_checksum=False, bd=0x70, flg_extra=0):
    """blocks＝[(bytes, 是否已壓縮 block)]。"""
    flg = 0x60 | flg_extra | (0x08 if content_size is not None else 0) | (0x10 if block_checksum else 0)
    out = bytearray(b"\x04\x22\x4d\x18" + bytes([flg, bd]))
    if content_size is not None:
        out += struct.pack("<Q", content_size)
    out.append(0)                                                  # header checksum（coreboot 不驗證）
    for b, compressed in blocks:
        out += struct.pack("<I", len(b) | (0 if compressed else 0x80000000)) + b
        if block_checksum:
            out += b"\0\0\0\0"
    return bytes(out + struct.pack("<I", 0))


def lz4_of(data, content_size=True):
    """把 data 做成 LZ4 frame：前 8 bytes 當 literal，其餘用 offset 1 的重疊 match 還原 data[8:]（data[8:] 必須是同一個 byte 重複）。"""
    assert len(data) > 12 and len(set(data[8:])) == 1
    block = lz4_seq([(data[:8], 1 if data[7] == data[8] else 8, len(data) - 8)], tail=b"")
    if data[7] != data[8]:       # offset 8 時只能重複前 8 個 byte；改成全部當 literal
        block = lz4_seq([], tail=data)
    return lz4_frame_of([(block, True)], len(data) if content_size else None)


def attrs(comp=None, size=None):
    if comp is None:
        return b""
    return struct.pack(">IIII", cb.ATTR_COMPRESSION, 16, comp, size)


def cbfs_file(name, data, ftype=0x50, comp=None, size=None, raw_len=None):
    """一個 CBFS 檔案（含對齊到 64 bytes 的結尾）。data 是儲存的內容（已壓縮就是壓縮後的 bytes）。"""
    nm = name.encode() + b"\0"
    a = attrs(comp, size)
    off = 24 + len(nm) + len(a)
    off += -off % 16
    hdr = bytearray(b"LARCHIVE" + struct.pack(">IIII", len(data) if raw_len is None else raw_len, ftype, 24 + len(nm) if a else 0, off))
    hdr += nm + a
    hdr += b"\0" * (off - len(hdr))
    out = bytes(hdr) + data
    return out + b"\xff" * (-len(out) % 64)


def lzma_of(data):
    return lzma.compress(data, format=lzma.FORMAT_ALONE)


def empty_file(n):
    """n bytes（64 的倍數）的空檔案。"""
    hdr = b"LARCHIVE" + struct.pack(">IIII", n - 40, 0xFFFFFFFF, 0, 40) + b"\0" * 16
    return hdr + b"\xff" * (n - 40)


def region(files, size):
    body = b"".join(files)
    assert len(body) <= size
    pad = size - len(body)
    return body + (empty_file(pad) if pad >= 64 else b"\xff" * pad)


def fmap_blob(size, areas, name=b"FLASH", ver=(1, 1)):
    out = b"__FMAP__" + bytes(ver) + struct.pack("<QI", 0xFF000000, size) + name.ljust(32, b"\0") + struct.pack("<H", len(areas))
    for nm, off, sz in areas:
        out += struct.pack("<II", off, sz) + nm.encode().ljust(32, b"\0") + struct.pack("<H", 0)
    return out


def fsp_blob(rev=(9, 0, 123, 32), ctype=2, image_id=b"$CMLFSP$", base=0xFF76B000, total=0x2000):
    d = bytearray(b"\xaa" * total)
    d[0:4] = b"_FVH"
    h = 0x94
    d[h:h + 4] = b"FSPH"
    struct.pack_into("<I", d, h + 4, 0x48)
    d[h + 10], d[h + 11] = 0x21, 4
    struct.pack_into("<I", d, h + 12, (rev[0] << 24) | (rev[1] << 16) | (rev[2] << 8) | rev[3])
    d[h + 16:h + 24] = image_id
    struct.pack_into("<II", d, h + 24, total, base)
    struct.pack_into("<HH", d, h + 32, 0, (ctype << 12) | 3)
    return bytes(d)


def vbt_blob(version=100, bdb=228, sig=b"$VBT SKYLAKE"):
    d = bytearray(1024)
    d[0:20] = sig.ljust(20, b" ")
    struct.pack_into("<HHHBBI", d, 20, version, 48, 600, 0, 0, 48)
    d[48:64] = b"BIOS_DATA_BLOCK "
    struct.pack_into("<HHH", d, 64, bdb, 22, 500)
    return bytes(d)


def revision_text(ver="board_v0.9.2", rev="add9d7206e30", dasharo="v1.2.0", ts=1710343106):
    return (f'#define COREBOOT_VERSION "{ver}"\n/* timesource: git */\n#define COREBOOT_VERSION_TIMESTAMP {ts}\n'
            f'#define COREBOOT_ORIGIN_GIT_REVISION "{rev}"\n' + (f'#define DASHARO_VERSION "{dasharo}"\n' if dasharo else "")
            + '#define COREBOOT_BUILD "Wed Mar 13 15:18:26 UTC 2024"\n#define COREBOOT_MAJOR_VERSION 0\n').encode()


BUILD_INFO = b"COREBOOT_VERSION: board_v0.9.2\nMAINBOARD_VENDOR: Acme\nMAINBOARD_PART_NUMBER: X1\n"


def config_text(edk2_rev=EDK2_REV, repo="https://github.com/Dasharo/edk2", extra=""):
    return ("# Automatically generated\nCONFIG_LOCALVERSION=\"v1.2.0\"\nCONFIG_VBOOT=y\nCONFIG_PAYLOAD_EDK2=y\n"
            f"CONFIG_EDK2_REPOSITORY=\"{repo}\"\nCONFIG_EDK2_TAG_OR_REV=\"{edk2_rev}\"\nCONFIG_SOC_INTEL_COMETLAKE=y\n"
            "CONFIG_SOC_INTEL_COMMON=y\n# CONFIG_SOC_INTEL_OTHER is not set\nCONFIG_OTHER_THING=y\n" + extra).encode()


def self_payload(seg_len=100):
    segs = struct.pack(">4sIIQII", b"CODE", 1, 56, 0x800000, seg_len, 4096)
    segs += struct.pack(">4sIIQII", b"ENTR", 0, 0, 0x800860, 0, 0)
    return segs + b"\x5d" * seg_len


def standard_files(fsp_rev=(9, 0, 123, 32), rev=None, cfg=None, vbt=None, with_payload=True, microcode_blob=None):
    """coreboot 映像裡常見的檔案組合（RO、RW 各放一份相同內容）。"""
    files = [cbfs_file("fallback/romstage", b"\x90" * 300, 0x11)]
    if microcode_blob is not None:
        files.append(cbfs_file("cpu_microcode_blob.bin", microcode_blob, 0x53))
    cfg = config_text() if cfg is None else cfg
    files += [cbfs_file("config", lzma_of(cfg), comp=1, size=len(cfg)),
              cbfs_file("revision", revision_text() if rev is None else rev),
              cbfs_file("build_info", BUILD_INFO)]
    v = vbt_blob() if vbt is None else vbt
    files.append(cbfs_file("vbt.bin", lzma_of(v), comp=1, size=len(v)))
    fm = fsp_blob(fsp_rev, 2)
    files.append(cbfs_file("fspm.bin", fm, 0x60))
    fs = fsp_blob(fsp_rev, 3)
    files.append(cbfs_file("fsps.bin", lzma_of(fs), 0x60, comp=1, size=len(fs)))
    if with_payload:
        files.append(cbfs_file("fallback/payload", self_payload(), 0x20))
    return files


FLASH = 0x100000
RO_AT, RO_SZ = 0x10000, 0x40000
RW_AT, RW_SZ = 0x50000, 0x40000


def flash(ro_files, rw_files=None, extra_areas=(), junk=True, fmap=True):
    """1 MiB 的 flash：FMAP 在 0x1000（區域 FMAP）、RO（COREBOOT）、RW_A（FW_MAIN_A）。junk：程式碼裡的 `__FMAP__` 字串常數。"""
    img = bytearray(b"\xff" * FLASH)
    if junk:
        junk1 = b"FMAP missing or corrupted!\x00__FMAP__"
        img[0x300:0x300 + len(junk1)] = junk1
        img[0x8000:0x8048] = b"__FMAP__" + b"\x00" * 0x40
    areas = [("FMAP", 0x1000, 0x800), ("COREBOOT", RO_AT, RO_SZ)] + ([("FW_MAIN_A", RW_AT, RW_SZ)] if rw_files is not None else [])
    areas += list(extra_areas)
    if fmap:
        fm = fmap_blob(FLASH, areas)
        img[0x1000:0x1000 + len(fm)] = fm
    img[RO_AT:RO_AT + RO_SZ] = region(ro_files, RO_SZ)
    if rw_files is not None:
        img[RW_AT:RW_AT + RW_SZ] = region(rw_files, RW_SZ)
    return bytearray(img)


def analyze(img, **kw):
    return cb.analyze(bytes(img), **kw)


def comp_names(r, key):
    return [it["version"] if key == "coreboot" else it.get("revision") for it in r[key]]


# ---------- LZ4 ----------

def test_lz4_block_literals_and_overlapping_match():
    assert cb.lz4_block(lz4_seq([], b"hello"), 100) == b"hello"
    blk = lz4_seq([(b"ab", 2, 20)], tail=b"xyz")          # 重疊複製：ababab…
    assert cb.lz4_block(blk, 100) == b"ab" + b"ab" * 10 + b"xyz"
    long_lit = bytes(range(256)) * 2                          # literal 長度需要延伸位元組
    assert cb.lz4_block(lz4_seq([], long_lit), 1000) == long_lit
    assert cb.lz4_block(lz4_seq([(b"q", 1, 600)], b"."), 1000) == b"q" * 601 + b"."     # match 長度需要延伸位元組


@pytest.mark.parametrize("blk,max_out,exc", [
    (b"\x14ab\x00\x00z", 100, cb.Lz4Error),                                                     # offset 0
    (lz4_seq([(b"ab", 5, 8)], b"x"), 100, cb.Lz4Error),                                          # offset 超過已輸出長度
    (b"\x50abc", 100, cb.Lz4Error),                                                              # literal 長度 5 但只有 3 bytes
    (b"", 100, cb.Lz4Error),                                                                     # 沒有 token
    (b"\x11a\x01", 100, cb.Lz4Error),                                                              # 有 match 但 offset 被截斷
    (b"\xf0" + b"\xff" * 200 + b"\x00", 100, cb.TooBig),                                         # literal 長度溢位（遠超輸出上限）
    (b"\x1f" + b"a" + b"\x01\x00" + b"\xff" * 400, 100, (cb.TooBig, cb.Lz4Error)),               # match 長度溢位
    (b"\xf0" + b"\xff" * 5, 10 ** 9, cb.Lz4Error),                                               # 延伸長度沒有結束（輸入截斷）
    (lz4_seq([(b"a", 1, 90)], b"b"), 50, cb.TooBig),                                             # 輸出超過上限
])
def test_lz4_block_malicious_input_raises(blk, max_out, exc):
    with pytest.raises(exc):
        cb.lz4_block(blk, max_out)


def test_lz4_block_random_input_only_raises_lz4_errors_and_respects_the_limit():
    import random
    rnd = random.Random(7)
    for _ in range(3000):
        blk = bytes(rnd.choice([0, 1, 0x0f, 0x1f, 0xf0, 0xff, rnd.randrange(256)]) for _ in range(rnd.randrange(1, 40)))
        try:
            out = cb.lz4_block(blk, 64)
        except cb.CbfsError:
            continue
        assert len(out) <= 64


def test_lz4_block_never_loops_on_zero_offset_match():
    blk = b"\x1f" + b"a" + b"\x00\x00" + b"\x00" * 10
    with pytest.raises(cb.Lz4Error):
        cb.lz4_block(blk, 1 << 20)


def test_lz4_frame_forms():
    raw = b"R" * 10
    comp = lz4_seq([(b"ab", 2, 10)], tail=b"end")
    expected = b"ab" + b"ab" * 5 + b"end"
    assert cb.lz4_frame(lz4_frame_of([(comp, True)]), 1000) == expected
    assert cb.lz4_frame(lz4_frame_of([(comp, True)], content_size=len(expected), block_checksum=True), 1000) == expected
    assert cb.lz4_frame(lz4_frame_of([(raw, False), (comp, True)]), 1000) == raw + expected


@pytest.mark.parametrize("frame,exc", [
    (b"\x00" * 20, cb.Lz4Error),                                                          # magic 不對
    (lz4_frame_of([(lz4_seq([], b"a"), True)], flg_extra=0x01), cb.Lz4Error),             # 字典 ID／保留位元
    (lz4_frame_of([(lz4_seq([], b"a"), True)], bd=0x00), cb.Lz4Error),                    # 區塊大小代號不合法
    (lz4_frame_of([(lz4_seq([], b"a"), True)])[:-4], cb.Lz4Error),                        # 沒有 EndMark（截斷）
    (lz4_frame_of([(lz4_seq([], b"a"), True)], content_size=5), cb.Lz4Error),             # 宣告 5、實際 1
    (lz4_frame_of([(lz4_seq([], b"a"), True)], content_size=10 ** 12), cb.TooBig),        # 宣告大小超過上限
    (b"\x04\x22\x4d\x18\x40\x70\x00" + struct.pack("<I", 5) + b"x", cb.Lz4Error),        # 區塊相依（不獨立）
    (b"\x04\x22\x4d\x18\x60\x70\x00" + struct.pack("<I", 0x7FFFFFF0) + b"x", cb.Lz4Error),  # 區塊長度超出輸入
])
def test_lz4_frame_bad_inputs(frame, exc):
    with pytest.raises(exc):
        cb.lz4_frame(frame, 4096)


def test_lz4_frame_block_larger_than_declared_block_size():
    big = lz4_frame_of([(b"x" * (70 << 10), False)], bd=0x40)                 # 區塊上限 64 KiB
    with pytest.raises(cb.Lz4Error):
        cb.lz4_frame(big, 1 << 20)


# ---------- LZMA ----------

def test_lzma_requires_exact_declared_size_and_limit():
    data = b"hello world" * 50
    z = lzma_of(data)
    assert cb.decompress(1, z, len(data), 1 << 20) == data
    for declared in (len(data) - 1, len(data) + 1):
        with pytest.raises(cb.CbfsError):
            cb.decompress(1, z, declared, 1 << 20)
    with pytest.raises(cb.TooBig):
        cb.decompress(1, z, len(data), 100)
    with pytest.raises(cb.CbfsError):
        cb.decompress(1, z[:20], len(data), 1 << 20)                 # 截斷
    with pytest.raises(cb.CbfsError):
        cb.decompress(1, b"\x00" * 64, 10, 1 << 20)                  # 不是 LZMA
    with pytest.raises(cb.CbfsError):
        cb.decompress(3, z, len(data), 1 << 20)                      # 不認得的壓縮


def test_lz4_through_cbfs_file():
    cfg = config_text()
    lz = lz4_frame_of([(lz4_seq([], cfg), True)], content_size=len(cfg))          # 全 literal 的 frame
    files = standard_files()
    files[1] = cbfs_file("config", lz, comp=2, size=len(cfg))
    r = analyze(flash(files, None))
    assert not r["incomplete"] and r["coreboot"][0]["config"]["keys"]["CONFIG_EDK2_TAG_OR_REV"] == EDK2_REV
    # 帶 match 的區塊（offset 2 的重疊複製）
    assert cb.decompress(2, lz4_frame_of([(lz4_seq([(b"ab", 2, 6)], b"!"), True)]), 9, 100) == b"abababab!"


# ---------- FMAP＋CBFS ----------

def test_fmap_regions_and_everything_read():
    mc = microcode(0x000B06A2, 0x4121, 0x05172023)
    files = standard_files(microcode_blob=mc)
    r = analyze(flash(files, files))
    assert r["method"] == "fmap" and r["fmap"]["flash_start"] == 0 and r["fmap"]["areas"] == 3
    assert [(x["name"], x["role"], x["offset"]) for x in r["regions"]] == [("COREBOOT", "RO", RO_AT), ("FW_MAIN_A", "RW_A", RW_AT)]
    assert not r["incomplete"]
    names = [f["name"] for f in r["regions"][0]["files"]]
    assert names == ["fallback/romstage", "cpu_microcode_blob.bin", "config", "revision", "build_info", "vbt.bin", "fspm.bin", "fsps.bin",
                     "fallback/payload"]
    assert r["regions"][0]["empty"] == 1
    # coreboot：RO、RW_A 內容相同 → 一個，兩個位置
    [c] = r["coreboot"]
    assert (c["version"], c["git_revision"], c["dasharo_version"], c["build_time"]) == ("board_v0.9.2", "add9d7206e30", "v1.2.0", "2024-03-13T15:18:26Z")
    assert (c["mainboard_vendor"], c["mainboard_part"], c["build"]) == ("Acme", "X1", "Wed Mar 13 15:18:26 UTC 2024")
    assert [l["role"] for l in c["locations"]] == ["RO", "RW_A"]
    cfg = c["config"]
    assert cfg["keys"]["CONFIG_EDK2_TAG_OR_REV"] == EDK2_REV and cfg["keys"]["CONFIG_VBOOT"] == "y"
    assert cfg["payload"] == ["CONFIG_PAYLOAD_EDK2"] and cfg["soc"] == ["CONFIG_SOC_INTEL_COMETLAKE", "CONFIG_SOC_INTEL_COMMON"]
    assert "CONFIG_OTHER_THING" not in cfg["keys"] and cfg["size"] == len(config_text())
    # FSP：M、S 分開；VBT；payload
    by_type = {f["type"]: f for f in r["fsp"]}
    assert set(by_type) == {"M", "S"} and len(r["fsp"]) == 2
    assert by_type["M"]["revision"] == by_type["S"]["revision"] == "9.0.123.32" and by_type["M"]["image_id"] == "$CMLFSP$"
    assert (by_type["M"]["spec_version"], by_type["M"]["component_attribute"], by_type["M"]["image_base"]) == ("2.1", "0x2003", "0xff76b000")
    assert [l["role"] for l in by_type["S"]["locations"]] == ["RO", "RW_A"]
    [v] = r["vbt"]
    assert (v["signature"], v["version"], v["bdb_version"]) == ("$VBT SKYLAKE", "1.00", "2.28") and len(v["locations"]) == 2
    [p] = r["payloads"]
    assert p["entry"] == "0x800860" and p["segments"][0]["type"] == "CODE" and p["segments"][0]["compression"] == "lzma"
    assert p["segments"][0]["load_address"] == "0x800000" and len(p["locations"]) == 2
    assert [l["file"] for l in r["microcode_files"]] == ["cpu_microcode_blob.bin"] * 2
    assert r["limits"]["decompressed_total"] > 0


def test_files_with_different_content_are_separate_components():
    ro = standard_files(fsp_rev=(9, 0, 123, 32))
    rw = standard_files(fsp_rev=(9, 2, 123, 32), rev=revision_text(rev="bbbbbbbbbbbb"))
    r = analyze(flash(ro, rw))
    assert sorted(x["revision"] for x in r["fsp"] if x["type"] == "M") == ["9.0.123.32", "9.2.123.32"]
    assert sorted(c["git_revision"] for c in r["coreboot"]) == ["add9d7206e30", "bbbbbbbbbbbb"]


def test_fake_fmap_strings_are_ignored_and_second_fmap_is_noted():
    img = flash(standard_files(), None)
    r = analyze(img)
    assert r["fmap"]["offset"] == 0x1000 and len(r["regions"]) == 1
    other = fmap_blob(FLASH, [("COREBOOT", RO_AT, RO_SZ)])
    img[0x20000 - 0x100 + 0x40000 - 0x40000:0x20000 - 0x100 + len(other)] = other     # RO 區域內的另一份不同的 FMAP
    r = analyze(img)
    assert any("different valid FMAPs" in x for x in r["incomplete"])


def test_flash_start_when_image_is_only_the_bios_region():
    """沒有名叫 FMAP 的區域：flash 大小等於整個檔案時起點是 0；等於 BIOS 區域時起點是 BIOS 區域開頭。"""
    img = bytearray(b"\xff" * 0x80000)
    fm = fmap_blob(0x80000, [("COREBOOT", 0x1000, 0x70000)])
    img[0x100:0x100 + len(fm)] = fm
    img[0x1000:0x1000 + 0x70000] = region(standard_files(), 0x70000)
    r = analyze(img)
    assert r["method"] == "fmap" and r["regions"][0]["offset"] == 0x1000
    bigger = b"\xaa" * 0x80000 + bytes(img)                      # 前面多了不相關的 0x80000 bytes，BIOS 區域在後半
    r = cb.analyze(bigger, 0x80000, len(bigger))
    assert r["regions"][0]["offset"] == 0x80000 + 0x1000


def test_fmap_area_without_cbfs_header_and_outside_flash():
    img = flash(standard_files(), None, extra_areas=[("FW_MAIN_B", 0x90000, 0x1000), ("RW_LEGACY", 0xFF000, 0x10000)])
    r = analyze(img)
    assert len(r["regions"]) == 1
    assert any("FW_MAIN_B has no CBFS header" in x for x in r["incomplete"])
    assert any("RW_LEGACY" in x and "outside" in x for x in r["incomplete"])


def test_overlapping_fmap_areas_are_parsed_once():
    img = flash(standard_files(), None, extra_areas=[("ALIAS", RO_AT, RO_SZ), ("INNER", RO_AT, 0x1000)])
    r = analyze(img)
    assert [x["name"] for x in r["regions"]] == ["COREBOOT"]
    assert sum("overlaps CBFS region COREBOOT" in x for x in r["incomplete"]) == 2
    assert len(r["coreboot"]) == 1 and len(r["coreboot"][0]["locations"]) == 1


def test_other_named_cbfs_area_is_listed_under_its_own_name():
    img = flash(standard_files(), None, extra_areas=[("BOOTSPLASH", 0x90000, 0x10000)])
    img[0x90000:0xA0000] = region([cbfs_file("bootsplash.bmp", b"BM" * 20, 0x40)], 0x10000)
    r = analyze(img)
    assert [(x["name"], x["role"]) for x in r["regions"]] == [("COREBOOT", "RO"), ("BOOTSPLASH", "BOOTSPLASH")]


# ---------- 沒有 FMAP：掃 LARCHIVE ----------

def test_scan_without_fmap_needs_two_valid_entries():
    img = flash(standard_files(), None, fmap=False, junk=False)
    r = analyze(img)
    assert r["method"] == "scan" and r["fmap"] is None and len(r["regions"]) == 1
    assert r["regions"][0]["offset"] == RO_AT and r["coreboot"][0]["version"] == "board_v0.9.2"
    one = bytearray(b"\xff" * 0x4000)
    one[0x1000:0x1000 + 128] = cbfs_file("only", b"x" * 20)[:128]
    assert analyze(one) is None                                         # 只有一個檔案：不當成 CBFS
    stray = bytearray(b"\x00" * 0x4000)
    stray[0x1001:0x1009] = b"LARCHIVE"                                  # 沒對齊
    stray[0x2000:0x2008] = b"LARCHIVE"                                  # 對齊，但欄位是 0（offset < 24）
    assert analyze(stray) is None


def test_fmap_without_cbfs_area_falls_back_to_scan():
    img = flash(standard_files(), None, fmap=False, junk=False)
    fm = fmap_blob(FLASH, [("FMAP", 0x1000, 0x800), ("SOMETHING", 0x70000, 0x1000)])
    img[0x1000:0x1000 + len(fm)] = fm
    r = analyze(img)
    assert r["method"] == "scan" and any("scanned for LARCHIVE" in x for x in r["incomplete"])


# ---------- 壞資料 ----------

def test_not_cbfs_returns_none_and_no_components():
    for blob in (b"", b"\xff" * 4096, b"LARCHIVE" * 100, b"__FMAP__" + b"\x01\x01" + b"\x00" * 100, bytes(range(256)) * 64):
        assert cb.analyze(blob) is None


def test_truncated_image_and_oversized_length():
    img = flash(standard_files(), None)
    r = analyze(img[:RO_AT + 0x500])          # 檔案被截在 CBFS 中間：FMAP 宣告的 flash 比檔案大 → 不用這份 FMAP，改掃 LARCHIVE（仍標記）
    assert r is not None and any("does not fit in the file" in x for x in r["incomplete"]) and r["method"] == "scan"
    big = bytearray(flash(standard_files(), None))
    first = RO_AT
    struct.pack_into(">I", big, first + 8, 0x7FFFFFF0)                   # 第一個檔案宣告 2 GiB
    r = analyze(big)
    assert r is not None and any("extends past the end of the region" in x for x in r["incomplete"])
    assert r["coreboot"] and r["coreboot"][0]["version"] == "board_v0.9.2"      # 壞的那個之後的檔案照樣讀（往後找下一個檔頭）


def test_bad_header_fields_are_reported():
    img = flash(standard_files(), None)
    b = bytearray(img)
    struct.pack_into(">I", b, RO_AT + 20, 8)                            # 資料位置 8 < 24
    r = analyze(b)
    assert r is not None and any("data offset 8 is out of range" in x for x in r["incomplete"])
    b = bytearray(img)
    b[RO_AT + 24:RO_AT + 40] = b"\x01bad\x02name\x00".ljust(16, b"\x00")      # 檔名有不可列印字元
    r = analyze(b)
    assert any("non-printable" in x for x in r["incomplete"])
    b = bytearray(img)
    b[RO_AT + 24:RO_AT + 40] = b"A" * 16                                      # 檔名沒有 NUL（資料位置之前都是檔名）
    struct.pack_into(">I", b, RO_AT + 20, 24 + 16)
    r = analyze(b)
    assert any("not NUL-terminated" in x for x in r["incomplete"])


def test_zero_length_entries_terminate_and_are_capped(monkeypatch):
    files = [cbfs_file(f"f{i}", b"") for i in range(50)]
    img = flash(files, None)
    monkeypatch.setattr(cb, "MAX_FILES", 10)
    r = analyze(img)
    assert r["regions"][0]["entries"] == 10 and any("more than 10 entries" in x for x in r["incomplete"])


def test_garbage_after_last_entry_is_reported_but_ff_padding_is_not():
    clean_img = flash(standard_files(), None)
    assert not analyze(clean_img)["incomplete"]
    files = standard_files()
    files[1] = b"JUNKJUNK" + files[1][8:]                 # 第二個檔案的 LARCHIVE 壞了：往後找下一個檔頭，跳過的 bytes 不是 0xff → 問題
    r = analyze(flash(files, None))
    assert any("no CBFS entry here" in x and "skipped" in x for x in r["incomplete"])
    assert r["coreboot"][0]["version"] == "board_v0.9.2"


def test_compressed_file_that_does_not_decode_is_attention_but_others_still_read():
    files = standard_files()
    files[1] = cbfs_file("config", b"\x00" * 64, comp=1, size=100)          # config：LZMA 解不開
    r = analyze(flash(files, None))
    assert any("'config'" in x and "LZMA" in x for x in r["incomplete"])
    assert r["coreboot"][0]["version"] == "board_v0.9.2" and r["coreboot"][0]["config"] is None
    assert len(r["fsp"]) == 2 and r["vbt"]
    # config 不見了，payload 的身分沒有依據
    assert r["payloads"][0]["config"] is None


def test_unknown_compression_and_missing_size():
    files = standard_files()
    files[1] = cbfs_file("config", b"x" * 20, comp=9, size=20)
    r = analyze(flash(files, None))
    assert any("unknown compression 9" in x for x in r["incomplete"])


def test_decompression_limits(monkeypatch):
    # 單檔：宣告的解壓後大小超過上限 → 不解、記 incomplete
    big = b"Z" * 100000
    files = standard_files()
    files[1] = cbfs_file("config", lzma_of(big), comp=1, size=len(big))
    r = analyze(flash(files, None), max_text=4096)
    assert any("'config'" in x and "exceeds the limit" in x for x in r["incomplete"])
    assert r["limits"]["decompressed_total"] < len(big)
    # 宣告很小、實際很大（lzma 炸彈）：不會輸出超過宣告 → 不符合就失敗
    bomb = cbfs_file("config", lzma_of(b"\x00" * (20 << 20)), comp=1, size=1000)
    r = analyze(flash([bomb, *standard_files()[2:]], None))
    assert any("'config'" in x and "declared size" in x for x in r["incomplete"])
    # 總量：兩個不同的壓縮檔，總量上限只夠一個
    files = standard_files()
    r = analyze(flash(files, None), max_total=len(config_text()) + 10)
    assert any("remaining total limit" in x for x in r["incomplete"])
    assert r["coreboot"][0]["config"] is not None and not r["vbt"]
    # 相同內容的檔案（RO、RW_A）只解一次、只計一次
    r1 = analyze(flash(standard_files(), None))
    r2 = analyze(flash(standard_files(), standard_files()))
    assert r1["limits"]["decompressed_total"] == r2["limits"]["decompressed_total"]


def test_lz4_limits_through_cbfs():
    bomb = lz4_frame_of([(lz4_seq([(b"a", 1, 5000)], b"b"), True)], content_size=5002)
    files = standard_files()
    files[1] = cbfs_file("config", bomb, comp=2, size=2000)                   # 宣告 2000，frame 實際是 5002
    r = analyze(flash(files, None))
    assert any("'config'" in x and "LZ4" in x for x in r["incomplete"])


def test_fsp_and_vbt_validation():
    files = standard_files()
    names = [f[24:].split(b"\0")[0].decode() for f in files]
    files[names.index("fspm.bin")] = cbfs_file("fspm.bin", b"\xaa" * 2000, 0x60)                    # 沒有 FSPH
    files[names.index("vbt.bin")] = cbfs_file("vbt.bin", b"not a vbt" * 20)
    r = analyze(flash(files, None))
    assert any("no valid FSPH" in x for x in r["incomplete"]) and any("not a valid $VBT" in x for x in r["incomplete"])
    assert [x["type"] for x in r["fsp"]] == ["S"] and not r["vbt"]
    late = bytearray(b"\xaa" * 0x3000)                                         # FSPH 在前 4 KiB 之外：不算
    late[0x2000:0x2004] = b"FSPH"
    assert cb.parse_fsph(late) is None


def test_self_payload_problems():
    seg = struct.pack(">4sIIQII", b"CODE", 0, 56, 0x800000, 10 ** 9, 4096)       # segment 超出 payload
    no_entr = struct.pack(">4sIIQII", b"CODE", 0, 28, 0, 4, 4) + b"abcd"
    unknown = struct.pack(">4sIIQII", b"WHAT", 0, 0, 0, 0, 0)
    for payload, needle in ((seg + struct.pack(">4sIIQII", b"ENTR", 0, 0, 1, 0, 0), "extends past the payload"), (no_entr, "no ENTR"),
                            (unknown, "unknown segment type")):
        r = analyze(flash([cbfs_file("fallback/payload", payload, 0x20), *standard_files()[1:4]], None))
        assert any(needle in x for x in r["incomplete"]), (needle, r["incomplete"])
    many = b"".join(struct.pack(">4sIIQII", b"DATA", 0, 0, 0, 0, 0) for _ in range(100))
    segs, entry, probs = cb.parse_self(many, len(many))
    assert len(segs) == cb.MAX_SEGMENTS and any("more than" in x for x in probs)


def test_microcode_found_in_cbfs_file(tmp_path):
    mc = microcode(0x000B06A2, 0x4121, 0x05172023)
    img = bytes(flash(standard_files(microcode_blob=mc), None))
    p = tmp_path / "mc.rom"
    p.write_bytes(img)
    inv = xf.inventory([p])
    comps, _ = xf.components(inv)
    uc = [c for c in comps if c["name"].startswith("Intel CPU microcode")]
    assert len(uc) == 1
    assert [p["value"] for p in uc[0]["properties"] if p["name"] == "sca-center:found-in"] == [
        f"CBFS RO [COREBOOT]: cpu_microcode_blob.bin @0x{img.find(mc):x}"]


# ---------- SBOM ----------

def props(c, name):
    return [p["value"] for p in c["properties"] if p["name"] == name]


def with_descriptor(img):
    """Intel descriptor：BIOS 區域是後半（0x80000–0xFFFFF），FMAP 的 flash 是整個檔案。"""
    b = bytearray(img)
    b[0:0x1000] = b"\x00" * 0x1000
    b[0x10:0x14] = xf.FD_SIG
    struct.pack_into("<I", b, 0x14, 0x00040000)
    regs = [0x00000000, (0xFF << 16) | 0x80, 0x00007FFF, 0x00007FFF] + [0x00007FFF] * 12
    struct.pack_into("<16I", b, 0x40, *regs)
    return bytes(b)


def sbom(tmp_path, img):
    p = tmp_path / "bios.rom"
    p.write_bytes(img)
    inv = xf.inventory([p])
    comps, deps = xf.components(inv)
    doc = xf.bom(comps, deps)
    assert not list(cdx_validator().iter_errors(doc))
    return inv, comps, deps


def dasharo_like(rev=revision_text(rev=FULL_REV), cfg=None):
    """descriptor＋FMAP（含 FMAP 區域）＋RO＋RW_A，全部在 BIOS 區域（後半）；FMAP 的 offset 相對整個檔案。"""
    files = standard_files(rev=rev, cfg=cfg)
    img = bytearray(b"\xff" * FLASH)
    ro_at, rw_at, sz = 0x90000, 0xC0000, 0x30000
    fm = fmap_blob(FLASH, [("SI_ALL", 0, 0x80000), ("FMAP", 0x81000, 0x800), ("COREBOOT", ro_at, sz), ("FW_MAIN_A", rw_at, sz)])
    img[0x81000:0x81000 + len(fm)] = fm
    img[ro_at:ro_at + sz] = region(files, sz)
    img[rw_at:rw_at + sz] = region(files, sz)
    return with_descriptor(img)


def test_sbom_components_properties_and_dependencies(tmp_path):
    inv, comps, deps = sbom(tmp_path, dasharo_like())
    [b] = inv["bios"]
    assert b["cbfs"]["method"] == "fmap" and [r["role"] for r in b["cbfs"]["regions"]] == ["RO", "RW_A"]
    img_ref = next(c["bom-ref"] for c in comps if c["name"] == "bios.rom")
    by = {c["name"]: c for c in comps}
    cbc = by["coreboot"]
    assert cbc["version"] == "board_v0.9.2" and cbc["purl"] == f"pkg:github/dasharo/coreboot@{FULL_REV}"
    assert props(cbc, "sca-center:coreboot-git-revision") == [FULL_REV] and props(cbc, "sca-center:coreboot-dasharo-version") == ["v1.2.0"]
    assert props(cbc, "sca-center:coreboot-build-time") == ["2024-03-13T15:18:26Z"]
    assert "CONFIG_EDK2_TAG_OR_REV=" + EDK2_REV in props(cbc, "sca-center:coreboot-config")
    assert props(cbc, "sca-center:coreboot-config-soc") == ["SOC_INTEL_COMETLAKE, SOC_INTEL_COMMON"]
    assert len(props(cbc, "sca-center:coreboot-config-sha256")[0]) == 64
    assert props(cbc, "sca-center:found-in") == [f"CBFS RO [COREBOOT]: revision @0x{b['cbfs']['coreboot'][0]['locations'][0]['offset']:x}",
                                                 f"CBFS RW_A [FW_MAIN_A]: revision @0x{b['cbfs']['coreboot'][0]['locations'][1]['offset']:x}"]
    assert props(cbc, "dumpling:vuln-assessment") == ["NOT_ASSESSED"] and "NVD" in props(cbc, "dumpling:vuln-assessment-note")[0]
    assert props(cbc, "dumpling:version-status") == ["OK"]
    pl = by["edk2 payload"]
    assert "version" not in pl and props(pl, "dumpling:version-status") == ["GAP"]
    assert pl["purl"] == f"pkg:github/dasharo/edk2@{EDK2_REV}"
    assert f"CONFIG_EDK2_TAG_OR_REV={EDK2_REV}" in props(pl, "sca-center:coreboot-config")
    assert props(pl, "sca-center:payload-segment") == ["CODE lzma offset=56 load=0x800000 length=100 memory=4096"]
    fm, fs = by["Intel FSP-M ($CMLFSP$)"], by["Intel FSP-S ($CMLFSP$)"]
    assert fm["version"] == fs["version"] == "9.0.123.32" and fm["manufacturer"]["name"] == "Intel Corporation"
    assert props(fm, "dumpling:vuln-assessment-note") == props(fs, "dumpling:vuln-assessment-note") == [xf.ASSESS_NOTES["intel"]]
    vbt = by["Intel VBT (Video BIOS Table)"]
    assert vbt["version"] == "1.00" and "not executable code" in props(vbt, "dumpling:vuln-assessment-note")[0]
    assert props(vbt, "sca-center:vbt-bdb-version") == ["2.28 (228 x100)"]
    for c in (cbc, pl, fm, fs, vbt):
        assert props(c, "dumpling:vuln-assessment") == ["NOT_ASSESSED"] and len(props(c, "dumpling:vuln-assessment-note")) == 1
        assert c["bom-ref"] in next(d for d in deps.items() if d[0] == img_ref)[1]
    assert len({c["bom-ref"] for c in comps}) == len(comps)
    assert len([c for c in comps if c["name"] == "coreboot"]) == 1                # RO、RW_A 內容相同：一個元件


def test_status_is_never_ok_when_cbfs_is_broken_and_never_overall_pass(tmp_path):
    img = bytearray(dasharo_like())
    struct.pack_into(">I", img, 0x90000 + 8, 0x7FFFFFF0)
    p = tmp_path / "bad.rom"
    p.write_bytes(bytes(img))
    inv = xf.inventory([p])
    st, detail = xf.status_of(inv)
    assert st == "ATTENTION" and "CBFS" in detail and "PASS" not in detail and "安全" not in detail
    assert not list(cdx_validator().iter_errors(xf.bom(*xf.components(inv))))


@pytest.mark.parametrize("rev,dasharo,expect_purl,why", [
    (FULL_REV, "v1.2.0", True, None),
    (FULL_REV, None, False, "cannot be determined"),
    ("add9d7206e30", "v1.2.0", False, "abbreviated (12 characters)"),
    (FULL_REV.upper(), "v1.2.0", False, "abbreviated"),
])
def test_coreboot_purl_rules(tmp_path, rev, dasharo, expect_purl, why):
    _, comps, _ = sbom(tmp_path, dasharo_like(rev=revision_text(rev=rev, dasharo=dasharo)))
    c = next(c for c in comps if c["name"] == "coreboot")
    assert ("purl" in c) is expect_purl
    if why:
        assert why in " ".join(props(c, "sca-center:note"))
    assert props(c, "sca-center:coreboot-git-revision") == [rev]


@pytest.mark.parametrize("rev,repo,expect", [
    (EDK2_REV, "https://github.com/Dasharo/edk2", True),
    (EDK2_REV, "https://github.com/dasharo/edk2.git", True),
    (EDK2_REV, "https://github.com/tianocore/edk2", False),
    (EDK2_REV, "https://github.com/Dasharo/edk2-platforms", False),
    (EDK2_REV, "https://evil.example/github.com/Dasharo/edk2", False),
    ("2a15268b36cc", "https://github.com/Dasharo/edk2", False),
    ("edk2-stable202402", "https://github.com/Dasharo/edk2", False),
])
def test_edk2_purl_rules(tmp_path, rev, repo, expect):
    _, comps, _ = sbom(tmp_path, dasharo_like(cfg=config_text(edk2_rev=rev, repo=repo)))
    pl = next(c for c in comps if c["name"] == "edk2 payload")
    assert ("purl" in pl) is expect
    assert "version" not in pl and f"CONFIG_EDK2_TAG_OR_REV={rev}" in props(pl, "sca-center:coreboot-config")


def test_other_payload_is_identity_only(tmp_path):
    cfg = config_text().replace(b"CONFIG_PAYLOAD_EDK2=y", b"CONFIG_PAYLOAD_SEABIOS=y")
    _, comps, _ = sbom(tmp_path, dasharo_like(cfg=cfg))
    pl = next(c for c in comps if c["name"].startswith("coreboot payload"))
    assert pl["name"] == "coreboot payload (seabios)" and "purl" not in pl and "version" not in pl
    assert props(pl, "dumpling:version-status") == ["GAP"] and not any(c["name"] == "edk2 payload" for c in comps)


def test_no_cbfs_means_no_components_and_unchanged_status(tmp_path):
    p = tmp_path / "plain.rom"
    p.write_bytes(spi_image())
    inv = xf.inventory([p])
    [b] = inv["bios"]
    assert b["cbfs"] is None
    comps, _ = xf.components(inv)
    assert not any(c["name"] in ("coreboot", "edk2 payload") or c["name"].startswith(("Intel FSP", "Intel VBT")) for c in comps)
    assert all("cbfs" not in k for u in b["microcode"] for k in u)
    assert not any(x.startswith("CBFS") for x in b["incomplete"]) and not any("CBFS" in x for x in b["gaps"])
    # 檔案裡有 LARCHIVE 字串（例如 coreboot 程式碼的常數）也不會產生假元件
    q = tmp_path / "strings.rom"
    q.write_bytes(spi_image()[:0x4000] + b"LARCHIVE" * 8 + spi_image()[0x4040:])
    inv2 = xf.inventory([q])
    assert inv2["bios"][0]["cbfs"] is None


def test_cli_with_isolated_python_loads_the_module_and_writes_sbom(tmp_path):
    p = tmp_path / "bios.rom"
    p.write_bytes(dasharo_like())
    out = tmp_path / "out"
    res = subprocess.run([sys.executable, "-I", str(CLI), "inventory", "--in", str(p), "--out", str(out)], capture_output=True, text=True)
    assert res.returncode == 2, res.stderr
    assert res.stdout.startswith("FW-INVENTORY\tATTENTION\t") and "PASS" not in res.stdout
    doc = json.loads((out / "fw.cdx.json").read_text(encoding="utf-8"))
    assert not list(cdx_validator().iter_errors(doc))
    assert {"coreboot", "edk2 payload", "Intel VBT (Video BIOS Table)"} <= {c["name"] for c in doc["components"]}
    md = (out / "fw-inventory.md").read_text(encoding="utf-8")
    assert "### CBFS（coreboot）" in md and "board\\_v0.9.2" in md
