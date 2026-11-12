"""Rockchip update.img（tools/demo/rockchip_img.py 與 flash_package.py 的 Rockchip 分支）。全部是測試裡產生的合成映像：
ext4 用 mke2fs -d（e2fsprogs；沒有時略過那些測試），RKFW／RKAF、FIT、LZ4 由這裡組出來；溢位用比較小的 2^32（monkeypatch TWO32）模擬。"""
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import zipfile

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
import flash_package as fp  # noqa: E402

rk = fp.rkmod()
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SCRIPT = os.path.join(REPO, "scripts", "demo", "scan-flash-package.sh")
MKE2FS = shutil.which("mke2fs") or next((p for p in ("/sbin/mke2fs", "/usr/sbin/mke2fs") if os.path.exists(p)), None)
need_mke2fs = pytest.mark.skipif(MKE2FS is None, reason="沒有 mke2fs（e2fsprogs）")
STATUS = b"Package: libc6\nStatus: install ok installed\nArchitecture: arm64\nVersion: 2.36-9+deb12u7\n\n"
CONFIG = b"CONFIG_ARM64=y\nCONFIG_IKCONFIG=y\nCONFIG_ROCKCHIP_RKNPU=m\n# CONFIG_FOO is not set\n"
KERNEL = b"\x00" * 64 + b"ARM64 kernel" + b"IKCFG_ST" + gzip.compress(CONFIG, mtime=0) + b"IKCFG_ED" + b"\x11" * 300


# ---------- 產生測試資料 ----------

def make_tree(base):
    """各種檔案：一般、大檔（多個區塊）、稀疏檔、短與長的符號連結、硬連結、setuid、FIFO、很多項目的目錄、空檔。"""
    r = base / "tree"
    for d in ("etc", "usr/bin", "usr/lib", "var/lib/dpkg", "boot", "big", "empty"):
        (r / d).mkdir(parents=True, exist_ok=True)
    (r / "etc/os-release").write_bytes(b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\n')
    (r / "var/lib/dpkg/status").write_bytes(STATUS)
    (r / "usr/bin/su").write_bytes(b"su-binary")
    os.chmod(r / "usr/bin/su", 0o4755)
    (r / "usr/bin/perl5").write_bytes(b"perl" * 1000)
    os.link(r / "usr/bin/perl5", r / "usr/bin/perl")
    (r / "usr/lib/large.bin").write_bytes(bytes(range(256)) * 1200)          # 300 KB：ext2 的 1 KB 區塊會用到雙重間接
    with open(r / "usr/lib/sparse.bin", "wb") as f:
        f.write(b"head")
        f.seek(200000)
        f.write(b"tail")
    os.symlink("usr/lib", r / "lib")
    os.symlink("/" + "x" * 90 + "/target", r / "etc/long-link")             # 長的符號連結（目標在資料區塊）
    os.mkfifo(r / "etc/initctl")
    (r / "empty/zero").write_bytes(b"")
    for k in range(300):
        (r / "big" / f"file-{k:03d}").write_bytes(str(k).encode())
    return r


def small_tree(base):
    r = base / "oem-tree"
    (r / "app").mkdir(parents=True, exist_ok=True)
    (r / "app" / "run.sh").write_bytes(b"#!/bin/sh\n")
    return r


def mkfs(path, tree, size_kb, *opts):
    if os.path.exists(path):
        os.remove(path)
    subprocess.run([MKE2FS, "-q", "-F", *opts, "-d", str(tree), str(path), f"{size_kb}k"], check=True, capture_output=True)
    return open(path, "rb").read()


def ext4_image(tmp_path, tree=None, size_kb=4096, opts=("-t", "ext4", "-b", "1024", "-L", "rootfs"), name="fs.img"):
    t = tree or make_tree(tmp_path)
    return mkfs(tmp_path / name, t, size_kb, *opts)


def fdt(root):
    """(名稱, {屬性: bytes}, [子節點]) → FDT（version 17）。"""
    strings, offs, body = bytearray(), {}, bytearray()

    def pad(b):
        return b + b"\0" * (-len(b) % 4)

    def so(n):
        if n not in offs:
            offs[n] = len(strings)
            strings.extend(n.encode() + b"\0")
        return offs[n]

    def node(name, props, kids):
        body.extend(struct.pack(">I", 1) + pad(name.encode() + b"\0"))
        for k, v in props.items():
            body.extend(struct.pack(">III", 3, len(v), so(k)) + pad(v))
        for c in kids:
            node(*c)
        body.extend(struct.pack(">I", 2))
    node(*root)
    body.extend(struct.pack(">I", 9))
    off_s, off_str = 56, 56 + len(body)
    total = off_str + len(strings)
    return struct.pack(">10I", 0xD00DFEED, total, off_s, off_str, 40, 17, 16, 0, len(strings), len(body)) + b"\0" * 16 + bytes(body) + bytes(strings)


def fit(kernel, compression="none", external=False):
    kp = {"type": b"kernel\0", "compression": compression.encode() + b"\0"}
    if not external:
        kp["data"] = kernel
        return fdt(("", {}, [("images", {}, [("kernel", kp, []), ("fdt", {"type": b"flat_dt\0", "data": b"dtb"}, [])]),
                              ("configurations", {"default": b"conf\0"}, [("conf", {"kernel": b"kernel\0"}, [])])]))
    kp["data-size"] = struct.pack(">I", len(kernel))
    kp["data-position"] = struct.pack(">I", 0)        # 先放 0，算出表頭大小後再改
    blob = fdt(("", {}, [("images", {}, [("kernel", kp, [])])]))
    pos = (len(blob) + 3) & ~3
    kp["data-position"] = struct.pack(">I", pos)
    blob = fdt(("", {}, [("images", {}, [("kernel", kp, [])])]))
    return blob + b"\0" * (pos - len(blob)) + kernel


def lz4_frame(data):
    """LZ4 frame：一個壓縮區塊（字面＋重疊的比對）＋其餘未壓縮區塊。"""
    blk = bytes([0x58]) + b"abcde" + struct.pack("<H", 5) + bytes([0x30]) + b"xyz"    # → abcdeabcdeabcdeabxyz
    out = struct.pack("<I", 0x184D2204) + bytes([0x60, 0x40, 0x00])
    out += struct.pack("<I", len(blk)) + blk
    out += struct.pack("<I", 0x80000000 | len(data)) + data
    return out + struct.pack("<I", 0), b"abcdeabcdeabcdeabxyz" + data


def align(n, a=0x800):
    return (n + a - 1) // a * a


def build(path, parts, two32=1 << 32, trailer=True, tamper=None, loader=b"BOOT" + b"L" * 60):
    """parts：[(名稱, 檔名, 內容)] → RKFW＋loader＋RKAF＋MD5 結尾。存的值是真正的值 mod two32。"""
    n = len(parts)
    rkaf_off = align(0x66 + len(loader))
    hdr = bytearray(RKAF := rk.RKAF_HDR + n * rk.PART_SIZE)
    hdr[0:4] = b"RKAF"
    hdr[8:8 + 6] = b"RK3588"
    hdr[0x48:0x48 + 8] = b"TESTVEND"
    struct.pack_into("<I", hdr, 0x88, n)
    body, pos = bytearray(), align(RKAF)
    real = []
    for k, (name, fname, data) in enumerate(parts):
        o = rk.RKAF_HDR + k * rk.PART_SIZE
        hdr[o:o + len(name)] = name
        hdr[o + 32:o + 32 + len(fname)] = fname
        pad = align(len(data))
        real.append((pos, len(data)))
        struct.pack_into("<5I", hdr, o + 92, 0, pos % two32, 0, pad % two32, len(data) % two32)
        body += data + b"\0" * (pad - len(data))
        pos += pad
    length = pos
    struct.pack_into("<I", hdr, 4, length % two32)
    blob = bytes(hdr) + b"\0" * (align(RKAF) - RKAF) + bytes(body) + b"\0\0\0\0"      # 最後 4 bytes：afptool 的 CRC 位置
    rkfw = bytearray(0x66)
    rkfw[0:4] = b"RKFW"
    struct.pack_into("<IIII", rkfw, 0x19, 0x66, len(loader), rkaf_off, len(blob) % two32)
    img = bytearray(bytes(rkfw) + loader + b"\0" * (rkaf_off - 0x66 - len(loader)) + blob)
    if tamper:
        tamper(img, rkaf_off)
    if trailer:
        img += hashlib.md5(img).hexdigest().encode()
    with open(path, "wb") as f:
        f.write(img)
    return {"rkaf_offset": rkaf_off, "real": real}


def std_parts(rootfs, oem=None, kernel=KERNEL, compression="none", external=False, boot=None):
    p = [(b"package-file", b"package-file", b"# NAME Relative path\npackage-file package-file\n"),
         (b"parameter", b"Image/parameter.txt", b"FIRMWARE_VER: 1.0\nCMDLINE: mtdparts=rk29xxnand:-@0x0(rootfs)\n"),
         (b"bootloader", b"Image/MiniLoaderAll.bin", b"BOOT" + b"\x01" * 3000),
         (b"uboot", b"Image/uboot.img", fit(b"u-boot", "none")),
         (b"misc", b"Image/misc.img", b"\0" * 49152),
         (b"boot", b"Image/boot.img", boot if boot is not None else fit(kernel, compression, external)),
         (b"rootfs", b"Image/rootfs.img", rootfs)]
    if oem is not None:
        p.append((b"oem", b"Image/oem.img", oem))
    return p


def vt_members(path):
    with rk.open_virtual(path) as vt:
        out = {}
        while True:
            m = vt.next()
            if m is None:
                return out, vt.stats
            vt.members.clear()
            out[m.name] = (m, vt.extractfile(m).read() if m.isreg() and m.size else b"" if m.isreg() else None)


def tree_view(root):
    out, inodes = {}, {}
    for d, dirs, files in os.walk(root):
        for n in dirs + files:
            p = os.path.join(d, n)
            rel = "rootfs/" + os.path.relpath(p, root)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("symlink", os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", stat.S_IMODE(st.st_mode))
            elif stat.S_ISFIFO(st.st_mode):
                out[rel] = ("fifo", stat.S_IMODE(st.st_mode))
            else:
                inodes.setdefault((st.st_dev, st.st_ino), []).append(rel)
                out[rel] = ("file", stat.S_IMODE(st.st_mode), hashlib.sha256(open(p, "rb").read()).hexdigest(), (st.st_dev, st.st_ino))
    return canon(out, inodes)


def canon(out, groups):
    """硬連結的群組 → 群組裡最小的名稱（兩邊「第一個」的順序不同）。"""
    first = {k: min(v) for k, v in groups.items()}
    return {n: (v[:3] + (first[v[3]],) if v[0] == "file" else v) for n, v in out.items()}


def virt_view(mem):
    out, groups = {}, {}
    for name, (m, data) in mem.items():
        if not name.startswith("rootfs/") or name.startswith("rootfs/lost+found"):
            continue
        if m.issym():
            out[name] = ("symlink", m.linkname)
        elif m.isdir():
            out[name] = ("dir", m.mode)
        elif m.isfifo():
            out[name] = ("fifo", m.mode)
        elif m.islnk():
            t = mem[m.linkname]
            groups.setdefault(m.linkname, [m.linkname]).append(name)
            out[name] = ("file", t[0].mode, hashlib.sha256(t[1]).hexdigest(), m.linkname)
        else:
            groups.setdefault(name, [name])
            out[name] = ("file", m.mode, hashlib.sha256(data).hexdigest(), name)
    return canon(out, groups)


# ---------- ext4 讀取：和來源資料夾逐項相同 ----------

@need_mke2fs
@pytest.mark.parametrize("opts", [("-t", "ext4", "-b", "1024"), ("-t", "ext4", "-b", "4096", "-O", "64bit,metadata_csum"),
                                  ("-t", "ext2", "-b", "1024"), ("-t", "ext4", "-b", "1024", "-O", "inline_data"),
                                  ("-t", "ext4", "-b", "1024", "-O", "meta_bg,^resize_inode")])
def test_ext4_reader_matches_tree(tmp_path, opts):
    tree = make_tree(tmp_path)
    fs = mkfs(tmp_path / "fs.img", tree, 8192, *opts)
    build(tmp_path / "update.img", std_parts(fs))
    mem, stats = vt_members(str(tmp_path / "update.img"))
    want, got = tree_view(tree), virt_view(mem)
    assert got == want
    assert stats["unreadable_files"] == stats["unreadable_dirs"] == stats["rejected_names"] == 0, stats
    assert mem["rootfs/usr/lib/sparse.bin"][1] == b"head" + b"\0" * (200000 - 4) + b"tail"
    assert mem["rootfs/usr/bin/perl5"][0].islnk() and mem["rootfs/usr/bin/perl5"][0].linkname == "rootfs/usr/bin/perl"
    assert mem["rootfs/usr/bin/su"][0].mode == 0o4755


# ---------- update.img：分割區表、清點、rootfs tar、核心 ----------

@need_mke2fs
def test_list_rootfs_tar_and_inventory(tmp_path):
    fs = ext4_image(tmp_path)
    oem = mkfs(tmp_path / "oem.img", small_tree(tmp_path), 2048, "-t", "ext4", "-b", "1024")
    parts = std_parts(fs, oem)
    info = build(tmp_path / "update.img", parts)
    img = str(tmp_path / "update.img")
    assert fp.archive_format(img) == "rockchip-img"
    r = fp.do_list(str(tmp_path / "list.json"), str(tmp_path / "inv.json"), archive=img)
    x = r["rockchip"]
    # oem 有檔案、沒有掃描 → ATTENTION；分割區的位置、大小、sha256 都對
    assert x["status"] == "ATTENTION" and "oem" in x["detail"] and x["overflow_corrected"] == [], x["detail"]
    for p, (name, _, data), (pos, size) in zip(x["partitions"], parts, info["real"]):
        assert (p["name"], p["pos"], p["size"], p["sha256"]) == (name.decode(), pos, size, hashlib.sha256(data).hexdigest())
        assert p["overflow_corrected"] is False
    assert [p["name"] for p in x["partitions"] if p["ext4"]] == ["rootfs", "oem"]
    assert x["md5_trailer"]["match"] is True and x["update_img"]["sha256"] == hashlib.sha256(open(img, "rb").read()).hexdigest()
    assert x["rkfw"]["loader_sha256"] == hashlib.sha256(b"BOOT" + b"L" * 60).hexdigest()
    c = r["rootfs"][0]
    assert (c["variant"], c["prefix"], c["looks_like_rootfs"], c["l4t"]["status"]) == ("rootfs", "rootfs", True, "INFO")
    assert c["dpkg"]["installed_packages"] == 1 and c["os_release"].startswith("Debian")
    inv = json.load(open(tmp_path / "inv.json"))
    paths = {i["path"]: i for i in inv["outside_rootfs"]}
    assert set(paths) >= {"bootloader/uboot.img", "bootloader/bootloader.img", "bootloader/boot.img", "bootloader/misc.img",
                          "config/parameter.txt", "config/package-file.txt", "kernel/Image"}
    assert paths["kernel/Image"]["sha256"] == hashlib.sha256(KERNEL).hexdigest()
    assert inv["rockchip"]["partitions"][6]["name"] == "rootfs"
    assert fp.main(["pick", "--list", str(tmp_path / "list.json"), "--rootfs", "all"]) == 0
    reps = fp.do_rootfs_tar([("rootfs", str(tmp_path / "r.tar"), str(tmp_path / "r.json"))], archive=img)
    with tarfile.open(tmp_path / "r.tar") as t:
        ms = {m.name: m for m in t.getmembers()}
        assert t.extractfile(ms["./var/lib/dpkg/status"]).read() == STATUS
        assert ms["./usr/bin/perl5"].islnk() and ms["./usr/bin/su"].mode == 0o4755 and ms["./lib"].linkname == "usr/lib"
        assert ms["./usr/bin/su"].uid == 0 and "./etc/initctl" not in ms
    assert reps[0]["skipped_fifos"] == 1 and reps[0]["unreadable_files"] == 0
    assert json.load(open(tmp_path / "r.json"))["source"]["format"] == "rockchip-update-img"


@need_mke2fs
@pytest.mark.parametrize("comp,external", [("none", False), ("none", True), ("gzip", False), ("lz4", True)])
def test_kernel_from_fit_reaches_kernel_config(tmp_path, comp, external):
    """boot 的 FIT → kernel/Image；kernel_config.py 不用改就讀到 IKCONFIG（--prefix rootfs 的上一層 kernel/Image）。"""
    if comp == "gzip":
        data, want = gzip.compress(KERNEL, mtime=0), gzip.compress(KERNEL, mtime=0)
    elif comp == "lz4":
        data, want = lz4_frame(KERNEL)
    else:
        data = want = KERNEL
    build(tmp_path / "update.img", std_parts(ext4_image(tmp_path), kernel=data, compression=comp, external=external))
    mem, _ = vt_members(str(tmp_path / "update.img"))
    assert mem["kernel/Image"][1] == want
    kc = fp.importlib.util.spec_from_file_location("kc_test", os.path.join(REPO, "scripts", "pilot", "lib", "kernel_config.py"))
    m = fp.importlib.util.module_from_spec(kc)
    kc.loader.exec_module(m)
    col, src = m.collect(str(tmp_path / "update.img"), prefix="rootfs", images=True)
    probe = col.pkg_images["Image"]
    assert probe.config is not None and b"CONFIG_ROCKCHIP_RKNPU=m" in (probe.config if isinstance(probe.config, bytes) else probe.config.encode())
    assert src["type"] == "archive"


def test_lz4_decoder():
    frame, want = lz4_frame(b"0123456789")
    assert rk.lz4_decompress(frame, 1 << 20) == want
    blk = bytes([0x58]) + b"abcde" + struct.pack("<H", 5) + bytes([0x30]) + b"xyz"
    legacy = struct.pack("<I", 0x184C2102) + struct.pack("<I", len(blk)) + blk
    assert rk.lz4_decompress(legacy + struct.pack("<I", 20), 1 << 20) == b"abcdeabcdeabcdeabxyz"
    with pytest.raises(ValueError):
        rk.lz4_decompress(struct.pack("<I", 0x184C2102) + struct.pack("<I", 5) + bytes([0x00, 0x10, 0x00, 0x09, 0x00]), 1 << 20)
    with pytest.raises(ValueError):
        rk.lz4_decompress(frame, 8)


@need_mke2fs
def test_boot_not_fit_is_noted(tmp_path):
    build(tmp_path / "update.img", std_parts(ext4_image(tmp_path), boot=b"ANDROID!" + b"\0" * 4000))
    r = fp.do_list(str(tmp_path / "list.json"), str(tmp_path / "inv.json"), archive=str(tmp_path / "update.img"))
    assert "Android boot image" in r["rockchip"]["kernel"]["note"] and r["rockchip"]["status"] == "ATTENTION"
    assert "boot（android-boot）" in r["rockchip"]["detail"]
    assert "kernel/Image" not in {i["path"] for i in json.load(open(tmp_path / "inv.json"))["outside_rootfs"]}


# ---------- 32 位元溢位（2^32 換成 4 MB 模擬） ----------

FAKE32 = 4 << 20


@need_mke2fs
def test_overflow_corrected(tmp_path, monkeypatch):
    monkeypatch.setattr(rk, "TWO32", FAKE32)
    fs = ext4_image(tmp_path, size_kb=6144)                     # rootfs 6 MB > 「2^32」：size 存成 2 MB，之後的 pos 都少 4 MB
    oem = mkfs(tmp_path / "oem.img", small_tree(tmp_path), 1536, "-t", "ext4", "-b", "1024")
    info = build(tmp_path / "update.img", std_parts(fs, oem), two32=FAKE32)
    with rk.RkImage(str(tmp_path / "update.img")) as img:
        assert img.ok, img.reason
        got = {p["name"]: (p["pos"], p["size"], p["overflow_corrected"]) for p in img.parts}
        assert got["rootfs"] == (info["real"][6][0], len(fs), True) and got["oem"][:2] == info["real"][7] and got["oem"][2] is True
        assert got["boot"][2] is False and img.rkaf["length_corrected"] is True
        assert set(img.corrected()) == {"rootfs", "oem", "RKAF length"}
    mem, _ = vt_members(str(tmp_path / "update.img"))
    assert mem["rootfs/var/lib/dpkg/status"][1] == STATUS


@need_mke2fs
def test_overflow_inconsistent_is_gap(tmp_path, monkeypatch):
    """ext4 的大小和分割區對不起來（size 少一個區塊）：沒有任何一組符合 → GAP，list 照樣寫出分割區表，rootfs-tar 失敗。"""
    monkeypatch.setattr(rk, "TWO32", FAKE32)
    fs = ext4_image(tmp_path, size_kb=6144)

    def shrink(img, off):
        o = off + rk.RKAF_HDR + 6 * rk.PART_SIZE + 92 + 16
        struct.pack_into("<I", img, o, struct.unpack_from("<I", img, o)[0] - 4096)
    build(tmp_path / "update.img", std_parts(fs), two32=FAKE32, tamper=shrink)
    img = str(tmp_path / "update.img")
    r = fp.do_list(str(tmp_path / "list.json"), str(tmp_path / "inv.json"), archive=img)
    assert r["rockchip"]["status"] == "GAP" and "沒有任何一組" in r["rockchip"]["detail"] and r["rootfs"] == []
    assert all(p["pos"] is None for p in r["rockchip"]["partitions"])
    assert fp.main(["rk-status", "--list", str(tmp_path / "list.json")]) == 0
    with pytest.raises(fp.Fail, match="沒有任何一組"):
        fp.do_rootfs_tar([("rootfs", str(tmp_path / "r.tar"), str(tmp_path / "r.json"))], archive=img)
    with pytest.raises(fp.Fail):
        with fp.open_stream(img):
            pass


def test_overflow_ambiguous_is_gap(tmp_path, monkeypatch):
    """兩個認不出內容的分割區，哪一個吸收 2^32 都說得通 → 多組 → GAP。"""
    monkeypatch.setattr(rk, "TWO32", FAKE32)
    build(tmp_path / "update.img", [(b"a", b"a.img", b"\x07" * (5 << 20)), (b"b", b"b.img", b"\x08" * (1 << 20))], two32=FAKE32)
    with rk.RkImage(str(tmp_path / "update.img")) as img:
        assert img.status == "GAP" and img.solutions == 2 and "不只一組" in img.reason


@need_mke2fs
def test_overflow_anchor_rejects_shifted_rootfs(tmp_path, monkeypatch):
    """rootfs 溢位時，「前一個分割區（boot）吸收 2^32、rootfs 往後挪」也符合連續與結尾；rootfs 的 ext4 超級區塊只在真正的位置 → 唯一。"""
    monkeypatch.setattr(rk, "TWO32", FAKE32)
    fs = ext4_image(tmp_path, size_kb=6144)
    build(tmp_path / "update.img", std_parts(fs), two32=FAKE32)
    with rk.RkImage(str(tmp_path / "update.img")) as img:
        assert img.ok and img.solutions == 1, img.reason
        assert {p["name"]: p["anchored"] for p in img.parts}["rootfs"] is True


# ---------- 壞掉的輸入 ----------

def test_bad_inputs(tmp_path):
    p = tmp_path / "x.img"
    p.write_bytes(b"NOPE" + b"\0" * 100)
    assert fp.archive_format(str(p)) == "tar"
    p.write_bytes(b"RKFW" + b"\0" * 10)
    with pytest.raises(rk.RkError, match="太短"):
        rk.RkImage(str(p))

    def bad_magic(img, off):
        img[off:off + 4] = b"XXXX"
    build(p, [(b"a", b"a", b"x" * 10)], tamper=bad_magic)
    with pytest.raises(rk.RkError, match="不是 RKAF"):
        rk.RkImage(str(p))
    with pytest.raises(fp.Fail, match="不是 RKAF"):
        fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=str(p))

    def many(img, off):
        struct.pack_into("<I", img, off + 0x88, 17)
    build(p, [(b"a", b"a", b"x" * 10)], tamper=many)
    with pytest.raises(rk.RkError, match="分割區數 17"):
        rk.RkImage(str(p))
    build(p, [(b"a", b"a", b"x" * 10)])
    data = p.read_bytes()
    p.write_bytes(data[:0x30])                                   # 截斷：RKAF 位移超出檔案
    with pytest.raises(rk.RkError, match="超出檔案"):
        rk.RkImage(str(p))
    build(p, [(b"a", b"a", b"x" * 10)], trailer=False)          # 沒有 MD5 結尾 → GAP
    with rk.RkImage(str(p)) as img:
        assert img.status == "GAP" and "MD5" in img.reason


@need_mke2fs
def test_md5_trailer_mismatch_is_attention(tmp_path):
    build(tmp_path / "update.img", std_parts(ext4_image(tmp_path)))
    d = bytearray((tmp_path / "update.img").read_bytes())
    d[-32:] = b"0" * 32
    (tmp_path / "update.img").write_bytes(bytes(d))
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=str(tmp_path / "update.img"))
    assert r["rockchip"]["status"] == "ATTENTION" and r["rockchip"]["md5_trailer"]["match"] is False


@need_mke2fs
def test_partition_name_traversal_not_used(tmp_path):
    """名稱含 ../ 的分割區：只記錄，不當成成員名稱；另一個也叫 rootfs 的不合法名稱不會被選。"""
    fs = ext4_image(tmp_path)
    parts = std_parts(fs) + [(b"../../etc/passwd", b"x", b"evil" * 10), (b"rootfs/../x", b"y", b"z" * 10)]
    build(tmp_path / "update.img", parts)
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=str(tmp_path / "update.img"))
    assert r["rockchip"]["status"] == "ATTENTION" and "名稱不合法" in r["rockchip"]["detail"]
    names = {i["path"] for i in json.load(open(tmp_path / "i.json"))["outside_rootfs"]}
    assert not any(".." in n or "passwd" in n for n in names)
    assert [c["prefix"] for c in r["rootfs"]] == ["rootfs"]


@need_mke2fs
def test_ext4_bad_names_and_blocks_counted(tmp_path):
    """目錄項名稱含 /（改 ext4 映像的位元組）→ 拒絕並計數；指到範圍外的 extent → 讀不到的檔案，不中止。"""
    tree = tmp_path / "t"
    (tree / "d").mkdir(parents=True)
    (tree / "d" / "evilXname").write_bytes(b"x")
    (tree / "d" / "victim.bin").write_bytes(b"V" * 5000)
    (tree / "etc").mkdir()
    fs = bytearray(mkfs(tmp_path / "fs.img", tree, 2048, "-t", "ext4", "-b", "1024"))
    i = fs.find(b"evilXname")
    fs[i + 4] = ord("/")
    # victim.bin 的 extent：找 inode 表裡內容區塊的指標，改成超出檔案系統
    tgt = fs.find(b"V" * 1024) // 1024
    hdr = struct.pack("<HHHH", 0xF30A, 1, 4, 0)
    k = fs.find(hdr)
    while k >= 0 and struct.unpack_from("<I", fs, k + 12 + 8)[0] != tgt:
        k = fs.find(hdr, k + 1)
    assert k >= 0
    struct.pack_into("<I", fs, k + 12 + 8, 10 ** 8)
    build(tmp_path / "update.img", std_parts(bytes(fs)))
    reps = fp.do_rootfs_tar([("rootfs", str(tmp_path / "r.tar"), str(tmp_path / "r.json"))], archive=str(tmp_path / "update.img"))
    rep = reps[0]
    assert rep["rejected"] >= 1 and rep["unreadable_files"] == 1, rep
    with tarfile.open(tmp_path / "r.tar") as t:
        assert "./d/victim.bin" not in t.getnames()              # 讀不到的不寫成成員（型別不明），只計數
    ex = rep["source"]["ext4"]["examples"]
    assert any("evil" in x for x in ex) and any("victim.bin" in x for x in ex)


# ---------- zip ----------

@need_mke2fs
def test_zip_wrapper(tmp_path):
    build(tmp_path / "update.img", std_parts(ext4_image(tmp_path)))
    z = tmp_path / "RK_TEST_V1.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(tmp_path / "update.img", "Firmware/update.img")
        zf.writestr("Tools/RKDevTool.exe", b"MZ" + b"\0" * 100)
        zf.writestr("../evil.txt", b"x")
    assert fp.archive_format(str(z)) == "rockchip-zip"
    with pytest.raises(fp.Fail, match="rk-extract"):
        with fp.open_stream(str(z)):
            pass
    out = tmp_path / "work" / "update.img"
    out.parent.mkdir()
    assert fp.main(["rk-extract", "--archive", str(z), "--out", str(out)]) == 0
    assert out.read_bytes() == (tmp_path / "update.img").read_bytes() and oct(out.stat().st_mode & 0o777) == "0o600"
    assert not (tmp_path / "evil.txt").exists() and not (tmp_path / "work" / "Tools").exists()
    assert fp.main(["rk-extract", "--archive", str(z), "--out", str(out)]) == 1        # 已經存在：不覆蓋
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=str(out), container=str(z))
    assert r["archive"] == {"file": "RK_TEST_V1.zip", "bytes": z.stat().st_size}
    c = r["rockchip"]["container"]
    assert c["member"] == "Firmware/update.img" and {m["name"] for m in c["other_members"]} == {"Tools/RKDevTool.exe", "../evil.txt"}
    with zipfile.ZipFile(tmp_path / "two.zip", "w") as zf:
        zf.writestr("a/update.img", b"RKFW")
        zf.writestr("b/UPDATE.IMG", b"RKFW")
    with pytest.raises(rk.RkError, match="2 個 update.img"):
        rk.zip_info(str(tmp_path / "two.zip"))
    assert rk.zip_info(str(tmp_path / "two.zip"), "b/UPDATE.IMG")["member"] == "b/UPDATE.IMG"


# ---------- scan-flash-package.sh ----------

def stub_path(tmp_path):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    for t in ("syft", "grype", "bwrap"):
        (b / t).write_text("#!/bin/sh\necho 'Version: 0.0.0'\n")
    (b / "docker").write_text(f"#!/bin/sh\ncase \"$1\" in info) echo {tmp_path};; version) echo 0;; import) echo 'stub: no import' >&2; exit 1;; "
                              "*) exit 1;; esac\n")
    for f in b.iterdir():
        f.chmod(0o755)
    return f"{b}:{os.environ['PATH']}"


def run_script(tmp_path, *args):
    e = dict(os.environ, PATH=stub_path(tmp_path), FLASHPKG_ALLOW_TMP_OUT="1")
    return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, env=e, timeout=300)


@need_mke2fs
@pytest.mark.parametrize("wrap", ["img", "zip"])
def test_script_flow_until_import(tmp_path, wrap):
    build(tmp_path / "update.img", std_parts(ext4_image(tmp_path)))
    a = tmp_path / "update.img"
    if wrap == "zip":
        a = tmp_path / "RK_V1.zip"
        with zipfile.ZipFile(a, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(tmp_path / "update.img", "update.img")
        os.remove(tmp_path / "update.img")
    out = tmp_path / "res"
    p = run_script(tmp_path, "--archive", str(a), "--rootfs", "rootfs", "--name", "RK", "--version", "V1", "--out", str(out), "--no-upload")
    st = (out / "status.tsv").read_text()
    assert p.returncode == 1, st + p.stderr
    rows = ["B-list\tOK", "B-rockchip\tOK", "B-l4t-rootfs\tINFO", "B-rootfs-tar-rootfs\tOK", "B-pkgdb-rootfs\tOK",
            "B-import-rootfs\tFAIL", "E-summary\tOK"] + (["B-rk-extract\tOK"] if wrap == "zip" else [])
    for row in rows:
        assert row in st, row + "\n" + st
    assert "略過裝置檔 0、FIFO 1" in st                              # 同 Jetson：FIFO 略過只計數
    assert "B-image-check-rootfs\t" in st and "B-image-check-rootfs\tFAIL" not in st, st
    assert "不用（Rockchip rockchip-" in st and not (out / ".work").exists()
    lst = json.load(open(out / "list.json"))
    assert lst["archive"]["file"] == a.name and lst["rockchip"]["status"] == "OK"


@need_mke2fs
def test_script_gap_layout_stops(tmp_path):
    build(tmp_path / "update.img", std_parts(ext4_image(tmp_path)), trailer=False)
    out = tmp_path / "res"
    p = run_script(tmp_path, "--archive", str(tmp_path / "update.img"), "--rootfs", "rootfs", "--name", "RK", "--version", "V1",
                   "--out", str(out), "--no-upload")
    st = (out / "status.tsv").read_text()
    assert p.returncode == 2 and "B-rockchip\tGAP" in st and "B-rootfs-tar" not in st, st


# ---------- 獨立審查找到的情況 ----------

def ext4_inode_offset(fs_bytes, path):
    """合成的 ext4 映像裡 path 的 inode 在映像裡的位移（用 rockchip_img 自己的讀取器找）。"""
    import tempfile
    with tempfile.TemporaryFile() as f:
        f.write(fs_bytes)
        f.flush()
        fs = rk.Ext4(f.fileno(), 0, len(fs_bytes))
        ino, node = 2, fs.inode(2)
        for part in path.split("/"):
            ents, _ = fs.entries(node)
            ino = dict(ents)[part.encode()]
            node = fs.inode(ino)
        g, idx = divmod(ino - 1, fs.sb["inodes_per_group"])
        return fs.gdesc(g)[0] * fs.bs + idx * fs.sb["inode_size"], node


@need_mke2fs
def test_corrupt_dir_block_is_attention(tmp_path):
    """目錄區塊的 rec_len 壞掉：那個區塊其餘的項目讀不到 → rootfs-tar 與 B-rockchip 都 ATTENTION（不能顯示 OK）。"""
    fs = bytearray(ext4_image(tmp_path))
    i = fs.find(b"file-150")
    struct.pack_into("<H", fs, i - 8 + 4, 3)
    build(tmp_path / "update.img", std_parts(bytes(fs)))
    img = str(tmp_path / "update.img")
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=img)
    assert r["rockchip"]["status"] == "ATTENTION" and "corrupt_dir_blocks 1" in r["rockchip"]["detail"], r["rockchip"]["detail"]
    rep = fp.do_rootfs_tar([("rootfs", str(tmp_path / "r.tar"), str(tmp_path / "r.json"))], archive=img)[0]
    assert rep["unreadable_dirs"] >= 1 and any("目錄區塊格式不對" in x for x in rep["examples"]["unreadable"])


def test_lz4_match_length_bounded():
    """很長的比對長度（每個 255 加 255）：在配置記憶體之前就拒絕。"""
    blk = bytes([0x1F]) + b"a" + struct.pack("<H", 1) + b"\xff" * 400000 + b"\x00"
    data = struct.pack("<I", 0x184C2102) + struct.pack("<I", len(blk)) + blk
    with pytest.raises(ValueError, match="larger than"):
        rk.lz4_decompress(data, 1 << 20)


@need_mke2fs
def test_dir_blocks_reused_is_unreadable(tmp_path):
    """目錄的兩個邏輯區塊指到同一個實體區塊（放大攻擊）：這個目錄算讀不到，不展開。"""
    fs = bytearray(ext4_image(tmp_path, opts=("-t", "ext2", "-b", "1024")))
    off, node = ext4_inode_offset(bytes(fs), "big")
    first = struct.unpack_from("<I", fs, off + 0x28)[0]
    struct.pack_into("<I", fs, off + 0x28 + 4, first)
    build(tmp_path / "update.img", std_parts(bytes(fs)))
    mem, stats = vt_members(str(tmp_path / "update.img"))
    assert stats["unreadable_dirs"] == 1 and not any(n.startswith("rootfs/big/") for n in mem)


@need_mke2fs
def test_root_inode_not_dir(tmp_path):
    """根目錄（inode 2）的型別改成一般檔案：open_virtual 就拒絕（不在走訪中途丟例外），list 記 GAP、rootfs-tar 乾淨地失敗。"""
    import tempfile
    fs = bytearray(ext4_image(tmp_path))
    with tempfile.TemporaryFile() as f:
        f.write(fs)
        f.flush()
        e = rk.Ext4(f.fileno(), 0, len(fs))
        root = e.gdesc(0)[0] * e.bs + 1 * e.sb["inode_size"]
    struct.pack_into("<H", fs, root, 0x81A4)
    build(tmp_path / "update.img", std_parts(bytes(fs)))
    img = str(tmp_path / "update.img")
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=img)
    assert r["rockchip"]["status"] == "GAP" and "inode 2" in r["rockchip"]["detail"]
    with pytest.raises(fp.Fail, match="inode 2"):
        fp.do_rootfs_tar([("rootfs", str(tmp_path / "r.tar"), str(tmp_path / "r.json"))], archive=img)


def test_rk_status_if_present(tmp_path, capsys):
    (tmp_path / "l.json").write_text(json.dumps({"rootfs": []}))
    assert fp.main(["rk-status", "--list", str(tmp_path / "l.json"), "--if-present"]) == 0 and capsys.readouterr().out == ""
    assert fp.main(["rk-status", "--list", str(tmp_path / "l.json")]) == 1


def test_rk_extract_corrupt_deflate(tmp_path, capsys):
    z = tmp_path / "x.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("update.img", os.urandom(1) * 200000)
    d = bytearray(z.read_bytes())
    i = d.find(b"update.img") + len(b"update.img")
    d[i + 10:i + 60] = b"\xff" * 50
    z.write_bytes(bytes(d))
    assert fp.main(["rk-extract", "--archive", str(z), "--out", str(tmp_path / "u.img")]) == 1
    assert "錯誤" in capsys.readouterr().err and not (tmp_path / "u.img").exists()


@need_mke2fs
def test_loss_under_lib_modules_is_named(tmp_path):
    """lib/modules 底下的目錄讀不到：B-rockchip 特別寫出 K2 的模組證據不要採用（kernel_module_map 看不到計數）。"""
    tree = tmp_path / "t"
    d = tree / "lib" / "modules" / "6.1.0" / "kernel"
    d.mkdir(parents=True)
    for k in range(200):
        (d / f"m{k:03d}.ko").write_bytes(b"\x7fELF")
    (tree / "var" / "lib" / "dpkg").mkdir(parents=True)
    (tree / "var" / "lib" / "dpkg" / "status").write_bytes(STATUS)
    fs = bytearray(mkfs(tmp_path / "fs.img", tree, 2048, "-t", "ext4", "-b", "1024"))
    i = fs.find(b"m150.ko")
    struct.pack_into("<H", fs, i - 8 + 4, 3)
    build(tmp_path / "update.img", std_parts(bytes(fs)))
    r = fp.do_list(str(tmp_path / "l.json"), str(tmp_path / "i.json"), archive=str(tmp_path / "update.img"))
    assert r["rockchip"]["status"] == "ATTENTION" and "K2" in r["rockchip"]["detail"], r["rockchip"]["detail"]
