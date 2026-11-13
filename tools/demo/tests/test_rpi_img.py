"""rpi_img.py（原始磁碟映像：MBR／GPT、FAT12／16、ext4）與 flash_package.py 的整合。
FAT 由這裡手工組出（不需要 mtools 或掛載），ext4 用 mke2fs -d（沒有時略過那些測試）。"""
import gzip
import io
import json
import lzma
import os
import struct
import sys
import tarfile
import zlib

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "..", "cra"))
import flash_package as fp  # noqa: E402
import test_rockchip_img as trk  # noqa: E402
import bootloader_coverage as bc  # noqa: E402

rp = fp.rpimod()
need_mke2fs = trk.need_mke2fs


# ---------- 產生測試資料 ----------
def lfn_entries(name, short11):
    s = 0
    for c in short11:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    u = name.encode("utf-16-le") + b"\0\0"
    u += b"\xff\xff" * ((-(len(u) // 2)) % 13)
    chunks = [u[i:i + 26] for i in range(0, len(u), 26)]
    out = []
    for n, ch in enumerate(chunks, 1):
        seq = n | (0x40 if n == len(chunks) else 0)
        out.append(bytes([seq]) + ch[0:10] + b"\x0f\x00" + bytes([s]) + ch[10:22] + b"\x00\x00" + ch[22:26])
    return list(reversed(out))


def is_83(name):
    base, _, ext = name.partition(".")
    return name == name.upper() and 0 < len(base) <= 8 and len(ext) <= 3


def fat_image(tree, kind=16, sectors=None):
    """tree：{名稱: bytes（檔案）或 dict（資料夾）} → FAT12／16 的檔案系統 bytes（1 sector／簇，1 份 FAT）。"""
    sectors = sectors or (1000 if kind == 12 else 5000)
    bps, rsvd, fsz, rootent = 512, 1, (4 if kind == 12 else 20), 512
    data_start = rsvd + fsz + rootent * 32 // bps
    img = bytearray(sectors * bps)
    fat = {}
    nxt = [2]

    def alloc(data):
        if not data:
            return 0
        n = -(-len(data) // bps)
        first = nxt[0]
        for i in range(n):
            c = first + i
            fat[c] = c + 1 if i < n - 1 else -1
            o = (data_start + c - 2) * bps
            img[o:o + bps] = data[i * bps:(i + 1) * bps].ljust(bps, b"\0")
        nxt[0] += n
        return first

    def dir_bytes(d, parent_cl=None, self_cl=None):
        out, count = bytearray(), 0
        if self_cl is not None:
            for nm, cl in ((b".          ", self_cl), (b"..         ", parent_cl)):
                out += nm + b"\x10" + b"\0" * 14 + struct.pack("<H", cl) + b"\0" * 4
        for name, v in d.items():
            if is_83(name):
                base, _, ext = name.partition(".")
                short = (base.ljust(8) + ext.ljust(3)).encode()
            else:
                count += 1
                short = (name.upper().replace(" ", "")[:6] + "~" + str(count)).ljust(8)[:8].encode() + b"   "
                out += b"".join(lfn_entries(name, short))
            if isinstance(v, dict):
                cl = nxt[0]
                nxt[0] += 1                      # 目錄本身佔一個簇（內容不超過 512 位元組）；先保留，再建內容
                body = dir_bytes(v, 0, cl)
                assert len(body) <= bps
                fat[cl] = -1
                o = (data_start + cl - 2) * bps
                img[o:o + bps] = body.ljust(bps, b"\0")
                out += short + b"\x10" + b"\0" * 14 + struct.pack("<H", cl) + b"\0" * 4
            else:
                cl = alloc(v)
                out += short + b"\x20" + b"\0" * 14 + struct.pack("<H", cl) + struct.pack("<I", len(v))
        return bytes(out)

    root = dir_bytes(tree)
    img[(rsvd + fsz) * bps:(rsvd + fsz) * bps + len(root)] = root
    f = bytearray(fsz * bps)
    f[0:3] = b"\xf8\xff\xff"
    if kind == 16:
        f[3] = 0xFF
    for c, v in fat.items():
        v = (0xFFF if kind == 12 else 0xFFFF) if v == -1 else v
        if kind == 16:
            struct.pack_into("<H", f, c * 2, v)
        else:
            o = c + c // 2
            cur = struct.unpack_from("<H", f, o)[0]
            cur = ((cur & 0x000F) | (v << 4)) if c & 1 else ((cur & 0xF000) | v)
            struct.pack_into("<H", f, o, cur)
    img[rsvd * bps:rsvd * bps + len(f)] = f
    bs = bytearray(512)
    bs[0:3] = b"\xeb\x3c\x90"
    bs[3:11] = b"MSWIN4.1"
    struct.pack_into("<HBHBHHBH", bs, 11, bps, 1, rsvd, 1, rootent, sectors, 0xF8, fsz)
    bs[510:512] = b"\x55\xaa"
    img[0:512] = bs
    return bytes(img)


BOOT = {"config.txt": b"arm_64bit=1\n", "cmdline.txt": b"console=tty1 root=PARTUUID=x\n", "start4.elf": b"\x7fELF" + b"S" * 700,
        "fixup4.dat": b"F" * 300, "bootcode.bin": b"B" * 100, "kernel8.img": b"\x00" * 64 + b"ARM\x64" + b"K" * 1500,
        "initramfs8": b"I" * 600, "bcm2711-rpi-4-b.dtb": b"D" * 200, "overlays": {"vc4-kms-v3d.dtbo": b"O" * 900, "README": b"r"}}


def mbr(parts):
    m = bytearray(512)
    for i, (typ, start, sec) in enumerate(parts):
        struct.pack_into("<B3sB3sII", m, 446 + 16 * i, 0, b"\0\0\0", typ, b"\0\0\0", start, sec)
    m[510:512] = b"\x55\xaa"
    return bytes(m)


def disk(tmp_path, boot=BOOT, kind=16, with_root=True, name="disk.img"):
    b = fat_image(boot, kind)
    root = trk.ext4_image(tmp_path, size_kb=4096) if with_root else b""
    start1 = 2048
    s1 = len(b) // 512
    start2 = start1 + s1 + 100
    parts = [(0x0E, start1, s1)] + ([(0x83, start2, len(root) // 512)] if with_root else [])
    img = bytearray(start2 * 512 + len(root))
    img[0:512] = mbr(parts)
    img[start1 * 512:start1 * 512 + len(b)] = b
    img[start2 * 512:start2 * 512 + len(root)] = root
    p = tmp_path / name
    p.write_bytes(img)
    return p


def gpt_disk(tmp_path, bad_crc=False, ent_lba=2):
    total = 4096
    img = bytearray(total * 512)
    img[0:512] = mbr([(0xEE, 1, total - 1)])
    ents = bytearray(128 * 128)
    ents[0:16] = bytes.fromhex("A2A0D0EBE5B9334487C068B6B72699C7")
    ents[16:32] = b"\x01" * 16
    struct.pack_into("<QQ", ents, 32, 64, 1023)
    ents[56:56 + 12] = "bootfs".encode("utf-16-le")
    h = bytearray(92)
    h[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", h, 8, 0x10000, 92, 0, 0, 1, total - 1, 34, total - 34)
    h[56:72] = b"\x02" * 16
    struct.pack_into("<QIII", h, 72, ent_lba, 128, 128, zlib.crc32(bytes(ents)) & 0xFFFFFFFF)
    struct.pack_into("<I", h, 16, (zlib.crc32(bytes(h)) & 0xFFFFFFFF) ^ (1 if bad_crc else 0))
    img[512:512 + 92] = h
    img[1024:1024 + len(ents)] = ents
    p = tmp_path / ("gpt-bad.img" if bad_crc else "gpt.img")
    p.write_bytes(img)
    return p


@pytest.mark.parametrize("lba", [2 ** 63 + 5, 2 ** 64 - 1, 2 ** 54, 5000])
def test_gpt_entry_lba_out_of_range_is_clean_error(tmp_path, lba):
    p = gpt_disk(tmp_path, ent_lba=lba)
    with pytest.raises(rp.RpiError, match="outside the file"):
        rp.read_table(os.open(p, os.O_RDONLY), p.stat().st_size)
    assert fp.archive_format(str(p)) == "raw-disk-img"
    assert fp.main(["list", "--archive", str(p), "--out", str(tmp_path / "l.json"), "--inventory", str(tmp_path / "i.json")]) == 1
    if lba >= 2 ** 54:
        with pytest.raises(OSError):
            rp.pread(os.open(p, os.O_RDONLY), lba * 512, 16)


def test_extract_existing_output_is_clean_error(tmp_path):
    x = tmp_path / "a.img.xz"
    x.write_bytes(lzma.compress(mbr([(0x83, 2048, 100)]) + b"\0" * 4096))
    out = tmp_path / "o.img"
    out.write_bytes(b"keep")
    with pytest.raises(rp.RpiError, match="must not exist"):
        rp.extract_image(str(x), str(out))
    assert out.read_bytes() == b"keep"
    assert fp.main(["img-extract", "--archive", str(x), "--out", str(out)]) == 1


# ---------- 分割區表 ----------
def test_gpt_parsed_and_crc_checked(tmp_path):
    p = gpt_disk(tmp_path)
    scheme, parts, notes, _ = rp.read_table(os.open(p, os.O_RDONLY), p.stat().st_size)
    assert scheme == "gpt" and len(parts) == 1 and parts[0]["name"] == "bootfs" and parts[0]["sectors"] == 960
    q = gpt_disk(tmp_path, True)
    with pytest.raises(rp.RpiError, match="CRC32"):
        rp.read_table(os.open(q, os.O_RDONLY), q.stat().st_size)


def test_mbr_overlap_and_truncation_are_noted(tmp_path):
    img = bytearray(1 << 20)
    img[0:512] = mbr([(0x0C, 100, 800), (0x83, 500, 800), (0x83, 1500, 4000)])
    p = tmp_path / "o.img"
    p.write_bytes(img)
    _, parts, notes, _ = rp.read_table(os.open(p, os.O_RDONLY), len(img))
    assert any("overlaps" in n for n in notes) and any("truncated" in n for n in notes)
    assert parts[1]["overlaps_previous"] and parts[2]["truncated"]


def test_detect_not_disk(tmp_path):
    t = tmp_path / "a.tar"
    with tarfile.open(t, "w") as tf:
        i = tarfile.TarInfo("x")
        i.size = 1
        tf.addfile(i, io.BytesIO(b"x"))
    assert fp.archive_format(str(t)) == "tar"
    g = tmp_path / "a.tar.gz"
    g.write_bytes(gzip.compress(t.read_bytes()))
    assert fp.archive_format(str(g)) == "tar"
    x = tmp_path / "a.tar.xz"
    x.write_bytes(lzma.compress(t.read_bytes()))
    assert fp.archive_format(str(x)) == "tar"
    z = tmp_path / "zero.img"
    z.write_bytes(b"\0" * 4096)
    assert fp.archive_format(str(z)) == "tar"


# ---------- FAT ----------
@pytest.mark.parametrize("kind", [12, 16])
def test_fat_reader_long_names(tmp_path, kind):
    tree = {"config.txt": b"x" * 5, "Mixed Case Name.txt": b"hello", "overlays": {"vc4-kms-v3d.dtbo": b"O" * 900}}
    data = fat_image(tree, kind)
    p = tmp_path / "f.img"
    p.write_bytes(data)
    fd = os.open(p, os.O_RDONLY)
    fat = rp.Fat(fd, 0, len(data))
    assert fat.kind == kind
    ents, bad = fat.entries(fat.read_dir(0))
    names = {e["name"]: e for e in ents}
    assert bad == 0 and set(names) == {"config.txt", "Mixed Case Name.txt", "overlays"}, list(names)
    sub, _ = fat.entries(fat.read_dir(names["overlays"]["cluster"]))
    assert [e["name"] for e in sub] == ["vc4-kms-v3d.dtbo"]
    e = sub[0]
    runs = fat.runs(fat.chain(e["cluster"], e["size"]), e["size"])
    assert rp.RunsReader(fd, runs).read() == b"O" * 900


def test_fat_chain_loop_and_bad_bpb(tmp_path):
    data = bytearray(fat_image({"A.TXT": b"x" * 1200}, 16))
    struct.pack_into("<H", data, 512 + 2 * 4, 2)          # 簇 4 → 簇 2（迴圈）
    p = tmp_path / "l.img"
    p.write_bytes(data)
    fat = rp.Fat(os.open(p, os.O_RDONLY), 0, len(data))
    with pytest.raises(rp.FatError, match="loops"):
        fat.chain(2)
    data[13] = 3                                           # sectors/cluster 不是 2 的次方
    p.write_bytes(data)
    with pytest.raises(rp.FatError):
        rp.Fat(os.open(p, os.O_RDONLY), 0, len(data))


# ---------- 整合 ----------
@need_mke2fs
def test_list_rootfs_tar_inventory(tmp_path):
    p = disk(tmp_path)
    assert fp.archive_format(str(p)) == "raw-disk-img"
    out, inv = tmp_path / "list.json", tmp_path / "inv.json"
    assert fp.main(["list", "--archive", str(p), "--out", str(out), "--inventory", str(inv)]) == 0
    r = json.loads(out.read_text())
    d = r["disk_image"]
    assert d["scheme"] == "mbr" and [x["fs_kind"] for x in d["partitions"]] == ["fat", "ext"], d
    assert d["status"] in ("OK", "ATTENTION") and d["not_in_image"][0]["status"] == "NOT_ASSESSED"
    assert r["rootfs"][0]["prefix"] == "rootfs" and r["rootfs"][0]["looks_like_rootfs"]
    i = json.loads(inv.read_text())
    boot = {x["path"] for x in i["bootloader"]}
    assert {"bootloader/start4.elf", "bootloader/fixup4.dat", "bootloader/bootcode.bin", "bootloader/config.txt", "bootloader/cmdline.txt",
            "bootloader/bcm2711-rpi-4-b.dtb", "bootloader/overlays/vc4-kms-v3d.dtbo"} <= boot
    assert {x["path"] for x in i["outside_rootfs"] if x["path"].startswith("kernel/")} == {"kernel/kernel8.img", "kernel/initramfs8"}
    assert fp.main(["pick", "--list", str(out), "--rootfs", "rootfs"]) == 0
    tar = tmp_path / "r.tar"
    assert fp.main(["rootfs-tar", "--archive", str(p), "--target", f"rootfs={tar}={tmp_path / 'rep.json'}"]) == 0
    assert tarfile.is_tarfile(tar)
    with fp.open_stream(str(p)) as t:
        names = []
        while True:
            m = t.next()
            if m is None:
                break
            names.append(m.name)
    assert "kernel/kernel8.img" in names and "bootloader/overlays/vc4-kms-v3d.dtbo" in names and "rootfs" in names


@need_mke2fs
def test_xz_img_extract_and_container(tmp_path):
    p = disk(tmp_path)
    x = tmp_path / "pi.img.xz"
    x.write_bytes(lzma.compress(p.read_bytes()))
    g = tmp_path / "pi.img.gz"
    g.write_bytes(gzip.compress(p.read_bytes()))
    assert fp.archive_format(str(x)) == "raw-disk-img-xz" and fp.archive_format(str(g)) == "raw-disk-img-gz"
    with pytest.raises(fp.Fail, match="img-extract"):
        with fp.open_stream(str(x)):
            pass
    work = tmp_path / "work"
    work.mkdir()
    out = work / "disk.img"
    assert fp.main(["img-extract", "--archive", str(x), "--out", str(out)]) == 0
    assert out.read_bytes() == p.read_bytes() and (out.stat().st_mode & 0o777) == 0o600
    lst = tmp_path / "l.json"
    assert fp.main(["list", "--archive", str(out), "--container", str(x), "--out", str(lst), "--inventory", str(tmp_path / "i.json")]) == 0
    r = json.loads(lst.read_text())
    assert r["archive"]["file"] == "pi.img.xz" and r["disk_image"]["container"]["file"] == "pi.img.xz"
    assert fp.main(["rk-status", "--list", str(lst)]) == 0


def test_extract_cap_and_cleanup(tmp_path):
    d = mbr([(0x83, 2048, 100)]) + b"\0" * (1 << 20)
    x = tmp_path / "big.img.xz"
    x.write_bytes(lzma.compress(d))
    out = tmp_path / "o.img"
    with pytest.raises(rp.RpiError, match="limit"):
        rp.extract_image(str(x), str(out), max_bytes=4096)
    assert not out.exists()
    y = tmp_path / "trunc.img.xz"
    y.write_bytes(lzma.compress(d)[:-30])
    with pytest.raises(rp.RpiError):
        rp.extract_image(str(y), str(out))
    assert not out.exists()


@need_mke2fs
def test_no_rootfs_is_gap_not_failure(tmp_path):
    p = disk(tmp_path, with_root=False)
    out = tmp_path / "l.json"
    assert fp.main(["list", "--archive", str(p), "--out", str(out), "--inventory", str(tmp_path / "i.json")]) == 0
    d = json.loads(out.read_text())["disk_image"]
    assert d["status"] == "GAP" and "rootfs" in d["detail"]
    with pytest.raises(fp.Fail):
        with fp.open_stream(str(p)):
            pass


def multi_fat_disk(tmp_path, fats, name="multi.img"):
    """多個 FAT 分割區的 MBR 映像（沒有 rootfs）：fats = [(MBR 類型, 檔案樹)]。"""
    blobs = [(typ, fat_image(tree, 16)) for typ, tree in fats]
    parts, start = [], 2048
    for typ, b in blobs:
        parts.append((typ, start, len(b) // 512))
        start += len(b) // 512 + 64
    img = bytearray(start * 512)
    img[0:512] = mbr(parts)
    for (typ, st, _sec), (_t, b) in zip(parts, blobs):
        img[st * 512:st * 512 + len(b)] = b
    p = tmp_path / name
    p.write_bytes(img)
    return p


RADXA_CONFIG = {"config.txt": b"# rsetup\n", "before.txt": b"x\n"}            # 合成：只有設定檔的小 FAT
RADXA_ESP = {"extlinux": {"extlinux.conf": b"label l\n"}, "vmlinuz-6.1.0": b"K" * 900, "initrd.img-6.1.0": b"I" * 300}


def boot_of(path):
    img = rp.RpiImage(str(path))
    try:
        b = img.boot()
        return (b["index"] if b else None), img.boot_why, img.table()
    finally:
        img.close()


def test_boot_picked_by_content_not_order(tmp_path):
    # Radxa 形狀：第一個 FAT 只有 config.txt，核心與 extlinux 在第二個（EFI system）
    idx, why, t = boot_of(multi_fat_disk(tmp_path, [(0x0C, RADXA_CONFIG), (0xEF, RADXA_ESP)]))
    assert idx == 2 and why is None and t["boot_partition"] == 2, t
    assert t["partitions"][1]["boot_signs"] == ["extlinux/", "vmlinuz-6.1.0"] and t["partitions"][0]["boot_signs"] == []
    # 順序對調、ESP 改成一般 FAT 類型：仍依內容選
    idx, why, _ = boot_of(multi_fat_disk(tmp_path, [(0x0C, RADXA_ESP), (0x0C, RADXA_CONFIG)], "swap.img"))
    assert idx == 1 and why is None


def test_boot_rpi_firmware_and_boot_subdir(tmp_path):
    idx, _, _ = boot_of(multi_fat_disk(tmp_path, [(0x0C, RADXA_CONFIG), (0x0C, {"start4.elf": b"S" * 10})]))
    assert idx == 2
    idx, _, t = boot_of(multi_fat_disk(tmp_path, [(0x0C, RADXA_CONFIG), (0x0C, {"boot": {"Image": b"K" * 10}})], "sub.img"))
    assert idx == 2 and t["partitions"][1]["boot_signs"] == ["boot/Image"]


def test_boot_ambiguous_is_not_guessed(tmp_path):
    idx, why, t = boot_of(multi_fat_disk(tmp_path, [(0x0C, RADXA_ESP), (0x0C, RADXA_ESP)]))
    assert idx is None and "not guessing" in why and t["boot_partition"] is None and t["boot_why"] == why
    # 兩個都有開機檔，恰好一個是 EFI system → 選它
    idx, why, _ = boot_of(multi_fat_disk(tmp_path, [(0x0C, RADXA_ESP), (0xEF, RADXA_ESP)], "esp.img"))
    assert idx == 2 and why is None
    # 兩個都沒有開機檔、沒有 ESP → 不猜
    idx, why, _ = boot_of(multi_fat_disk(tmp_path, [(0x0C, RADXA_CONFIG), (0x0C, RADXA_CONFIG)], "none.img"))
    assert idx is None and "none has boot files" in why


def test_single_fat_without_boot_files_still_used(tmp_path):
    idx, why, _ = boot_of(multi_fat_disk(tmp_path, [(0x0C, RADXA_CONFIG)]))
    assert idx == 1 and why is None


# ---------- 涵蓋說明 ----------
def test_rpi_coverage_classes():
    inv = {"bootloader": [{"type": "file", "path": f"bootloader/{n}", "sha256": "a"} for n in
                          ("start4.elf", "fixup4.dat", "bootcode.bin", "bcm2711.dtb", "overlays/x.dtbo", "config.txt", "LICENCE.broadcom", "mystery.bin")],
           "outside_rootfs": [{"type": "file", "path": "kernel/kernel8.img"}, {"type": "file", "path": "kernel/initramfs8"},
                              {"type": "file", "path": "bootloader/config.txt"}]}
    c = bc.build_coverage_rpi(inv, "rootfs")
    assert c["counts"] == {"vendor_firmware": 3, "kernel": 2, "data": 2, "unclassified": 1, "not_firmware": 2, "not_file": 0}
    assert c["counts_add_up"] and c["total"] == 10 and c["status"] == "GAP"
    assert c["not_in_image"][0]["status"] == "NOT_ASSESSED"
    txt = bc.customer_text(c)
    assert "EEPROM" in txt and "release notes" in txt
    assert "EEPROM" in bc.markdown_zh(c)
