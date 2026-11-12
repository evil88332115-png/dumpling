"""Android image packages (tools/demo/android_img.py and the flash_package.py hook).  Everything is synthetic and built here:
sparse wrapper, LP metadata (super.img), ext4 via mke2fs -d (skipped without e2fsprogs), a tiny EROFS writer, boot images v2/v4,
binary AndroidManifest.xml.  No real Android image was available when this was written: the EROFS and LP layouts are written from
the format descriptions, so passing tests prove self-consistency, not compatibility with images produced by Google's tools."""
import gzip
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import zipfile

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import flash_package as fp  # noqa: E402
import test_rockchip_img as T  # noqa: E402

an = fp.amod()
need_mke2fs = T.need_mke2fs

PROP_SYSTEM = (b"# comment\nro.build.version.release=14\nro.build.version.sdk=34\nro.build.version.security_patch=2024-05-05\n"
               b"ro.build.fingerprint=acme/prod/dev:14/UP1A.231005.007/1234:user/release-keys\nro.build.id=UP1A.231005.007\n")
PROP_VENDOR = b"ro.vendor.build.security_patch=2024-04-05\nro.vendor.build.fingerprint=acme/prod/dev:14/V1:user/release-keys\n"
KERNEL_TXT = b"\0" * 64 + b"Linux version 5.10.43-android12-9-g1234 (build@host) (clang 14) #1 SMP\n" + b"\x11" * 200
CONFIG = b"CONFIG_ARM64=y\nCONFIG_IKCONFIG=y\n# CONFIG_FOO is not set\n"
KERNEL = KERNEL_TXT + b"IKCFG_ST" + gzip.compress(CONFIG, mtime=0) + b"IKCFG_ED" + b"\x22" * 64


# ---------- builders ----------

def axml(package, version_name, version_code):
    strings = ["manifest", "package", "versionName", "versionCode", package, version_name]
    pool = b"".join(struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\0\0" for s in strings)
    offs, o = [], 0
    for s in strings:
        offs.append(o)
        o += 2 + len(s) * 2 + 2
    pool += b"\0" * (-len(pool) % 4)
    sp_hdr = struct.pack("<HHIIIIII", 1, 28, 28 + 4 * len(strings) + len(pool), len(strings), 0, 0, 28 + 4 * len(strings), 0)
    sp = sp_hdr + b"".join(struct.pack("<I", x) for x in offs) + pool

    def attr(name, raw, dtype, data):
        return struct.pack("<IIIHBBI", 0xFFFFFFFF, name, raw, 8, 0, dtype, data)
    attrs = attr(1, 4, 3, 4) + attr(2, 5, 3, 5) + attr(3, 0xFFFFFFFF, 0x10, version_code)
    body = struct.pack("<IIHHHHHH", 0xFFFFFFFF, 0, 20, 20, 3, 0, 0, 0)
    body = struct.pack("<II", 0xFFFFFFFF, 0) + struct.pack("<HHHHHH", 20, 20, 3, 0, 0, 0)
    el = struct.pack("<HHIII", 0x0102, 16, 16 + len(body) + len(attrs), 1, 0xFFFFFFFF) + body + attrs
    total = 8 + len(sp) + len(el)
    return struct.pack("<HHI", 3, 8, total) + sp + el


def make_apk(package, vname, vcode):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("AndroidManifest.xml", axml(package, vname, vcode))
        z.writestr("classes.dex", b"dex\n035\0" + b"\0" * 20)
    return b.getvalue()


def elf(text):
    return b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<HH", 3, 183) + b"\0" * 40 + text


def android_tree(base, name, props, apks=(), libs=None):
    r = base / name
    (r / "etc").mkdir(parents=True, exist_ok=True)
    (r / "build.prop").write_bytes(props)
    for k, (pkg, vn, vc) in enumerate(apks):
        d = r / "app" / f"App{k}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"App{k}.apk").write_bytes(make_apk(pkg, vn, vc))
    (r / "lib64").mkdir(exist_ok=True)
    for fn, text in (libs or {}).items():
        (r / "lib64" / fn).write_bytes(elf(text))
    return r


def sparse_wrap(raw, blk=4096):
    """Raw image -> Android sparse: raw chunks for non-zero blocks, dont-care for zero runs, one fill chunk, one crc32 chunk."""
    assert len(raw) % blk == 0
    nb = len(raw) // blk
    chunks, i = [], 0
    while i < nb:
        z = raw[i * blk:(i + 1) * blk] == b"\0" * blk
        j = i
        while j < nb and (raw[j * blk:(j + 1) * blk] == b"\0" * blk) == z:
            j += 1
        if z:
            chunks.append(struct.pack("<HHII", 0xCAC3, 0, j - i, 12))
        else:
            chunks.append(struct.pack("<HHII", 0xCAC1, 0, j - i, 12 + (j - i) * blk) + raw[i * blk:j * blk])
        i = j
    chunks.append(struct.pack("<HHII", 0xCAC4, 0, 0, 16) + b"\0\0\0\0")
    return struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, nb, len(chunks), 0) + b"".join(chunks)


def lp_super(parts, total=8 << 20, slots=2, max_meta=4096):
    """parts: [(name, [(sector_count, first_sector)])]  -> bytes of a super.img with geometry and slot-0 metadata (data left zero)."""
    import hashlib as h
    geo = bytearray(struct.pack("<II32sIII", 0x616C4467, 52, b"\0" * 32, max_meta, slots, 4096))
    geo[8:40] = h.sha256(bytes(geo)).digest()
    ptab, etab = b"", b""
    ei = 0
    for name, exts in parts:
        ptab += struct.pack("<36sIIII", name.encode(), 0, ei, len(exts), 0)
        for sec, first in exts:
            etab += struct.pack("<QIQI", sec, 0, first, 0)
            ei += 1
    gtab = struct.pack("<36sIQ", b"default", 0, 0)
    gtab = gtab + b"\0" * (48 - len(gtab)) if len(gtab) < 48 else gtab
    btab = struct.pack("<QIIQ36sI", 2048, 0, 0, total, b"super", 0)
    tables = ptab + etab + gtab + btab
    descs = [(0, len(parts), 52), (len(ptab), ei, 24), (len(ptab) + len(etab), 1, 48), (len(ptab) + len(etab) + len(gtab), 1, 64)]
    hdr = bytearray(struct.pack("<IHHI32sI32s", 0x414C5030, 10, 0, 128, b"\0" * 32, len(tables), h.sha256(tables).digest())
                    + b"".join(struct.pack("<III", *d) for d in descs))
    hdr = hdr + b"\0" * (128 - len(hdr))
    hdr[12:44] = h.sha256(bytes(hdr)).digest()
    img = bytearray(total)
    img[4096:4096 + 52] = geo
    img[8192:8192 + 52] = geo
    img[12288:12288 + 128] = hdr
    img[12288 + 128:12288 + 128 + len(tables)] = tables
    return img


def cpio_newc(files):
    out = b""
    for ino, (name, data, mode) in enumerate(files, 1):
        nm = name.encode() + b"\0"
        out += b"070701" + b"".join(b"%08x" % v for v in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0))
        out += nm + b"\0" * (-(110 + len(nm)) % 4) + data + b"\0" * (-len(data) % 4)
    nm = b"TRAILER!!!\0"
    out += b"070701" + b"".join(b"%08x" % v for v in (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(nm), 0)) + nm
    return out + b"\0" * (-len(out) % 4)


def os_version_word(a, b, c, y, m):
    return (a << 25) | (b << 18) | (c << 11) | ((y - 2000) << 4) | m


def pad(b, n):
    return b + b"\0" * (-len(b) % n)


def boot_v2(kernel, ramdisk, dtb=b"", page=4096, osv=os_version_word(14, 0, 0, 2024, 5)):
    h = bytearray(page)
    h[0:8] = b"ANDROID!"
    struct.pack_into("<IIIIIIII", h, 8, len(kernel), 0x8000, len(ramdisk), 0x1000000, 0, 0, 0, page)
    struct.pack_into("<II", h, 40, 2, osv)
    h[48:48 + 4] = b"test"
    h[64:64 + 20] = b"console=ttyS0 quiet\0"
    struct.pack_into("<I", h, 1648, len(dtb))
    return bytes(h) + pad(kernel, page) + pad(ramdisk, page) + pad(dtb, page)


def boot_v4(kernel, ramdisk, osv=os_version_word(14, 0, 0, 2024, 5)):
    h = bytearray(4096)
    h[0:8] = b"ANDROID!"
    struct.pack_into("<IIII", h, 8, len(kernel), len(ramdisk), osv, 4096)
    struct.pack_into("<I", h, 40, 4)
    h[44:44 + 12] = b"androidboot\0"
    return bytes(h) + pad(kernel, 4096) + pad(ramdisk, 4096)


def fdt_blob(model):
    return bytes.fromhex("")


def erofs_image(tree, bs=4096, compressed_names=()):
    """tree: {path: bytes | None(dir) | ('link', target)}.  Compact inodes, flat plain / flat inline; names in compressed_names get layout 1."""
    paths = sorted(tree)
    dirs = {""}
    for p in paths:
        parts = p.split("/")
        for k in range(1, len(parts)):
            dirs.add("/".join(parts[:k]))
    nodes = sorted(dirs | set(paths), key=lambda x: (x.count("/"), x))
    meta_start = bs                                          # block 1
    infos, off = {}, 0
    for n in nodes:                                          # reserve inode slots (32 bytes each) + inline data
        infos[n] = {"off": off}
        off += 32
        t = tree.get(n)
        if isinstance(t, bytes) and 0 < len(t) < bs // 2 and n not in compressed_names:
            infos[n]["inline"] = True
            off += (len(t) + 31) // 32 * 32
        elif isinstance(t, tuple):
            infos[n]["inline"] = True
            off += (len(t[1]) + 31) // 32 * 32
    meta_blocks = -(-off // bs) + 1
    data_blk = 1 + meta_blocks
    datas, blocks = [], 0

    def alloc(b):
        nonlocal blocks
        start = data_blk + blocks
        blocks += -(-len(b) // bs)
        datas.append(pad(b, bs))
        return start
    nid = {n: infos[n]["off"] // 32 for n in nodes}

    def dir_bytes(d):
        def parent(n):
            return n.rsplit("/", 1)[0] if "/" in n else ""
        kids = sorted((n.rsplit("/", 1)[-1], n) for n in nodes if n and parent(n) == d)
        ents = [(".", d), ("..", d)] + kids
        head = len(ents) * 12
        names = b"".join(k.encode() for k, _ in ents)
        out, o = b"", head
        for k, n in ents:
            ft = 2 if (n in dirs) else 1
            out += struct.pack("<QHBB", nid[n], o, ft, 0)
            o += len(k.encode())
        assert head + len(names) <= bs
        return out + names
    body = bytearray(meta_blocks * bs)
    for n in nodes:
        t = tree.get(n)
        i = infos[n]
        if n in dirs:
            content, mode = dir_bytes(n), 0o40755
        elif isinstance(t, tuple):
            content, mode = t[1].encode(), 0o120777
        else:
            content, mode = t, 0o100644
        layout, iu = 0, 0
        if n in compressed_names:
            layout, iu = 1, 0
        elif i.get("inline"):
            layout = 2
        elif len(content):
            iu = alloc(content)
        rec = struct.pack("<HHHHIIIIHHI", layout << 1, 0, mode, 1, len(content), 0, iu, 0, 0, 0, 0)
        o = i["off"]
        body[o:o + 32] = rec
        if layout == 2:
            body[o + 32:o + 32 + len(content)] = content
    sb = bytearray(bs)
    struct.pack_into("<IIIBBHQQIIII", sb, 1024, 0xE0F5E1E2, 0, 0, 12, 0, nid[""], len(nodes), 0, 0, 1 + meta_blocks + blocks, 1, 0)
    # fields after build_time_nsec: blocks @36, meta_blkaddr @40
    struct.pack_into("<I", sb, 1024 + 36, 1 + meta_blocks + blocks)
    struct.pack_into("<I", sb, 1024 + 40, 1)
    sb[1024 + 64:1024 + 64 + 6] = b"system"
    return bytes(sb) + bytes(body) + b"".join(datas)


def run_list(tmp_path, **kw):
    out = tmp_path / "res"
    out.mkdir(exist_ok=True)
    r = fp.do_list(str(out / "list.json"), str(out / "flash-inventory.json"), **kw)
    return r, out


def summary(out):
    return json.loads((out / "android-summary.json").read_text())


@pytest.fixture
def pkgdir(tmp_path):
    """Directory with sparse system.img, super.img (vendor in 2 extents, product empty), boot.img v2, init_boot.img v4, vbmeta."""
    T_ = T
    sysroot = android_tree(tmp_path, "sysroot", PROP_SYSTEM, [("com.acme.app", "1.2.3", 42)],
                           {"libcrypto.so": b"OpenSSL 1.1.1k  25 Mar 2021\0", "libz.so": b"inflate 1.2.11 Copyright 1995-2017 Mark Adler\0",
                            "libcrypto_bs.so": b"x"})
    (sysroot / "lib64" / "libcrypto_bs.so").write_bytes(elf(b"OpenSSL 1.1.1 (compatible; BoringSSL)\0"))
    venroot = android_tree(tmp_path, "venroot", PROP_VENDOR)
    sys_img = T_.mkfs(tmp_path / "s.img", sysroot, 2048, "-t", "ext4", "-b", "1024")
    ven_img = T_.mkfs(tmp_path / "v.img", venroot, 1024, "-t", "ext4", "-b", "1024")
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "system.img").write_bytes(sparse_wrap(pad(sys_img, 4096)))
    half = len(ven_img) // 2
    s_sec = half // 512
    sup = lp_super([("vendor_a", [(s_sec, 4096), (s_sec, 8192)]), ("product_a", [])], total=8 << 20)
    # vendor in two non-adjacent extents (sectors 4096.. and 8192.. => byte offsets 2MiB and 4MiB)
    sup[4096 * 512:4096 * 512 + half] = ven_img[:half]
    sup[8192 * 512:8192 * 512 + half] = ven_img[half:]
    (d / "super.img").write_bytes(sparse_wrap(bytes(sup)))
    rd = gzip.compress(cpio_newc([("prop.default", b"ro.build.version.release=14\n", 0o100644), ("init", b"#!init", 0o100755)]))
    (d / "boot.img").write_bytes(boot_v2(KERNEL, rd))
    (d / "init_boot.img").write_bytes(boot_v4(b"", rd))
    (d / "vbmeta.img").write_bytes(b"AVB0" + b"\0" * 252)
    (d / "README.txt").write_text("hello")
    return d


# ---------- tests ----------

def test_sparse_roundtrip(tmp_path):
    raw = os.urandom(4096) + b"\0" * 8192 + os.urandom(4096)
    out = tmp_path / "o.raw"
    with open(tmp_path / "s.img", "wb") as f:
        f.write(sparse_wrap(raw))
    with open(tmp_path / "s.img", "rb") as f:
        info = an.unsparse(f, str(out))
    assert out.read_bytes() == raw
    assert info["chunks"]["crc32"] == 1 and "not verified" in info["note"]


def test_sparse_bad_inputs(tmp_path):
    good = sparse_wrap(os.urandom(8192))
    for bad in (good[:-30], good[:4] + b"\x02\x00" + good[6:], good[:20] + struct.pack("<I", 99) + good[24:]):
        with pytest.raises(an.AndroidError):
            an.unsparse(io.BytesIO(bad), str(tmp_path / "x.raw"))


def test_sparse_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(an, "MAX_IMAGE", 4096)
    with pytest.raises(an.AndroidError, match="cap"):
        an.unsparse(io.BytesIO(sparse_wrap(os.urandom(8192))), str(tmp_path / "x.raw"))


def test_lp_parse_and_corruption(tmp_path):
    img = lp_super([("system_a", [(8, 2048)]), ("vendor_a", [(4, 4096), (4, 9000)])])
    p = tmp_path / "super.img"
    p.write_bytes(img)
    fd = os.open(p, os.O_RDONLY)
    lp = an.parse_super(fd)
    assert [x["name"] for x in lp["partitions"]] == ["system_a", "vendor_a"]
    assert lp["partitions"][1]["size"] == 8 * 512 and len(lp["partitions"][1]["extents"]) == 2
    bad = bytearray(img)
    bad[12288 + 200] ^= 1
    p.write_bytes(bytes(bad))
    with pytest.raises(an.AndroidError, match="checksum"):
        an.parse_super(os.open(p, os.O_RDONLY))


@need_mke2fs
def test_directory_package_full(pkgdir, tmp_path):
    work = tmp_path / "res"
    r, out = run_list(tmp_path, archive=None, directory=str(pkgdir))
    s = summary(out)
    f = s["facts"]
    assert f["android_version"]["value"] == "14" and f["security_patch"]["value"] == "2024-05-05"
    assert f["vendor_security_patch"]["value"] == "2024-04-05"
    assert f["fingerprint"]["value"].startswith("acme/prod/dev:14/")
    assert f["build_id"]["value"] == "UP1A.231005.007"
    names = {p["name"]: p for p in s["partitions"]}
    assert names["system"]["fs"]["type"] == "ext4" and names["vendor_a"]["fs"]["type"] == "ext4"
    assert names["product_a"]["status"] == "EMPTY"
    assert any("not contiguous" in x for x in names["vendor_a"]["reasons"])
    assert names["vbmeta"]["status"] == "OK" and "presence" in names["vbmeta"]["note"]
    assert s["kernel"]["version"] == "5.10.43-android12-9-g1234" and s["kernel"]["compression"] == "raw"
    if an.kernel_config() is not None:
        assert s["kernel"]["ikconfig"]["status"] == "OK"
    apk = s["apks"]["items"][0]
    assert apk["package"] == "com.acme.app" and apk["version_name"] == "1.2.3" and apk["version_code"] == 42 and len(apk["sha256"]) == 64
    wk = {(w["component"], w["version"]) for w in s["native_libs"]["well_known_versions"]}
    assert ("openssl", "1.1.1k") in wk and ("zlib", "1.2.11") in wk and ("boringssl", None) in wk
    assert all(w["status"] == "version string, not verified" for w in s["native_libs"]["well_known_versions"])
    assert s["vulnerability_matching"]["status"] == "NOT_RUN"
    assert s["security_patch_level"]["comparison"]["status"] == "NOT_ASSESSED"
    assert s["security_patch_level"]["boot_header"] == "2024-05"
    assert s["boot_images"][0]["ramdisk"]["files"] == 2
    assert any(o["name"].endswith("README.txt") for o in s["other_members"])
    lst = json.loads((out / "list.json").read_text())
    assert lst["rootfs"] == [] and lst["android"]["status"] in ("OK", "ATTENTION", "GAP")
    inv = json.loads((out / "flash-inventory.json").read_text())
    assert any(x["kind"] == "apk" for x in inv["outside_rootfs"])
    assert (out / "android-summary.md").read_text().count("NOT_RUN") >= 1
    assert not [x for x in os.listdir(out) if x.startswith(".android-work")]        # temp files deleted
    del work


@need_mke2fs
def test_virtual_tar_layout(pkgdir, tmp_path, monkeypatch):
    monkeypatch.setenv("ANDROID_WORKDIR", str(tmp_path / "w"))
    with fp.open_stream(str(pkgdir / "boot.img")) as vt:
        names = []
        while (m := vt.next()) is not None:
            names.append(m.name)
            if m.name == "kernel/Image":
                assert vt.extractfile(m).read() == KERNEL
    assert "boot/boot/ramdisk/prop.default" in names and "kernel/Image" in names and "boot/boot.img" in names
    with fp.open_source(directory=str(pkgdir)) as (entries, src):
        paths = ["/".join(e.parts) for e in entries]
    assert src["format"] == "android"
    assert "system/build.prop" in paths and "vendor/build.prop" in paths        # slot suffix removed, system from sparse image
    assert "kernel/Image" in paths and "bootloader/vbmeta.img" in paths


@need_mke2fs
def test_zip_with_nested_factory_zip(pkgdir, tmp_path):
    inner = tmp_path / "image-dev-1.zip"
    with zipfile.ZipFile(inner, "w") as z:
        for n in ("system.img", "super.img", "boot.img"):
            z.write(pkgdir / n, n)
    outer = tmp_path / "factory.zip"
    with zipfile.ZipFile(outer, "w") as z:
        z.write(inner, "dev-1/image-dev-1.zip")
        z.writestr("dev-1/flash-all.sh", "#!/bin/sh\n")
    assert fp.archive_format(str(outer)) == "android"
    r, out = run_list(tmp_path, archive=str(outer), directory=None)
    s = summary(out)
    assert s["facts"]["security_patch"]["value"] == "2024-05-05"
    assert any("flash-all.sh" in o["name"] for o in s["other_members"])
    tar = tmp_path / "pkg.tar"
    with tarfile.open(tar, "w") as t:
        t.add(pkgdir / "boot.img", "boot.img")
        t.add(pkgdir / "system.img", "system.img")
    assert fp.archive_format(str(tar)) == "android"


def test_rockchip_zip_not_taken(tmp_path):
    z = tmp_path / "rk.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("update.img", b"RKFW")
        zf.writestr("boot.img", b"x")
    assert fp.archive_format(str(z)) == "rockchip-zip"


def test_boot_v4_and_init_boot(tmp_path):
    rd = gzip.compress(cpio_newc([("prop.default", b"ro.build.version.security_patch=2024-03-05\n", 0o100644)]))
    d = tmp_path / "p"
    d.mkdir()
    (d / "init_boot.img").write_bytes(boot_v4(b"", rd, os_version_word(14, 0, 0, 2024, 3)))
    (d / "boot.img").write_bytes(boot_v4(gzip.compress(KERNEL), b""))
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    assert s["kernel"]["compression"] == "gzip" and s["kernel"]["version"].startswith("5.10.43")
    assert s["facts"]["security_patch"]["value"] == "2024-03-05"
    assert s["facts"]["android_version"]["status"] == "NOT_ASSESSED"          # no system image: unknown, not guessed
    assert s["status"] == "GAP" and "android_version NOT_ASSESSED" in s["detail"]   # never "complete" with the key facts unknown
    assert s["vulnerability_matching"]["status"] == "NOT_RUN"


def test_boot_truncated_is_not_assessed(tmp_path):
    img = boot_v2(KERNEL, b"x" * 100)
    d = tmp_path / "p"
    d.mkdir()
    (d / "boot.img").write_bytes(img[:5000])
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    assert s["status"] == "GAP" and s["partitions"][0]["status"] == "NOT_ASSESSED"
    assert s["kernel"]["version"] is None


def test_unknown_kernel_compression_is_not_assessed(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "boot.img").write_bytes(boot_v4(b"\x28\xb5\x2f\xfd" + b"\0" * 100, b""))
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    assert s["kernel"]["status"] == "NOT_ASSESSED" and "zstd" in s["kernel"]["reason"]


def test_erofs_plain_inline_and_compressed(tmp_path, monkeypatch):
    monkeypatch.setenv("ANDROID_WORKDIR", str(tmp_path / "w"))
    big = os.urandom(10000)
    tree = {"build.prop": PROP_SYSTEM, "app": None, "app/big.bin": big, "etc": None, "etc/link": ("link", "../build.prop"),
            "lib": None, "lib/libz.so": elf(b"inflate 1.2.12 Copyright 1995-2022"), "secret": b"A" * 5000}
    img = erofs_image(tree, compressed_names=("secret",))
    d = tmp_path / "p"
    d.mkdir()
    (d / "system.img").write_bytes(img)
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    p = s["partitions"][0]
    assert p["fs"]["type"] == "erofs" and p["status"] == "NOT_ASSESSED"          # one compressed file => the partition is partial
    assert "compressed" in " ".join(p["reasons"]) and p["contents"]["files"] == 4
    assert s["facts"]["security_patch"]["value"] == "2024-05-05"                   # readable files are still used
    assert ("zlib", "1.2.12") in {(w["component"], w["version"]) for w in s["native_libs"]["well_known_versions"]}
    assert s["status"] == "GAP"
    with fp.open_source(directory=str(d)) as (entries, _):
        got = {}
        for e in entries:
            if e.kind == "file":
                got["/".join(e.parts)] = e.open().read()
            elif e.kind == "symlink":
                got["/".join(e.parts)] = e.link
    assert got["system/app/big.bin"] == big and got["system/etc/link"] == "../build.prop" and "system/secret" not in got


def test_erofs_bad_inputs(tmp_path):
    img = bytearray(erofs_image({"a": b"x"}))
    struct_ = struct.pack("<I", 1 << 30)
    img[1024 + 36:1024 + 40] = struct_                                              # block count larger than the image
    p = tmp_path / "e.img"
    p.write_bytes(bytes(img))
    fd = os.open(p, os.O_RDONLY)
    with pytest.raises(an.ErofsError):
        an.Erofs(fd, 0, len(img))


def test_f2fs_and_unknown_are_not_assessed(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    f2 = bytearray(8192)
    struct.pack_into("<I", f2, 1024, 0xF2F52010)
    (d / "userdata.img").write_bytes(bytes(f2))
    (d / "vendor.img").write_bytes(b"\x01" * 8192)
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    st = {p["name"]: p["status"] for p in s["partitions"]}
    assert st == {"userdata": "NOT_ASSESSED", "vendor": "NOT_ASSESSED"} and s["status"] == "GAP"


def test_apk_manifest_parser_rejects_garbage():
    assert an.apk_manifest(make_apk("a.b", "9", 1))[0]["package"] == "a.b"
    assert an.apk_manifest(b"PK not a zip")[0] is None
    with pytest.raises(ValueError):
        an.read_axml(axml("a.b", "1", 1)[:40])


def test_cpio_rejects_traversal():
    files, notes, rej = an.cpio_files(cpio_newc([("../../etc/x", b"a", 0o100644), ("ok/y", b"b", 0o100644), ("/abs", b"c", 0o100644)]))
    assert [f["path"] for f in files] == ["ok/y", "abs"] and rej == 1 and not notes


def test_super_extent_beyond_file_is_not_assessed(tmp_path):
    img = lp_super([("system", [(2000, 4096)])], total=1 << 20)             # extent past the end of the 1 MiB file
    d = tmp_path / "p"
    d.mkdir()
    (d / "super.img").write_bytes(bytes(img))
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    assert s["partitions"][0]["status"] == "NOT_ASSESSED" and "past the end" in s["partitions"][0]["reasons"][0]
    assert s["status"] == "GAP"


def test_empty_directory_is_not_android(tmp_path):
    assert not an.is_android_dir(str(tmp_path))


# ---------- round-1 verification fixes ----------

def test_sparse_chunk_validation(tmp_path):
    hdr = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 4096, 4, 1, 0)
    cases = {
        "dont_care with body": struct.pack("<HHII", 0xCAC3, 0, 1, 12 + 4096) + b"\0" * 4096,
        "crc32 too big": struct.pack("<HHII", 0xCAC4, 0, 0, 12 + (1 << 30)),
        "unknown type": struct.pack("<HHII", 0xCAC9, 0, 4, 12),
    }
    for name, chunk in cases.items():
        with pytest.raises(an.AndroidError):
            an.unsparse(io.BytesIO(hdr + chunk), str(tmp_path / "x.raw"))


def test_sparse_space_reserved_before_write(tmp_path):
    seen = []

    def reserve(n):
        seen.append(n)
        raise an.AndroidError("too small")
    with pytest.raises(an.AndroidError, match="too small"):
        an.unsparse(io.BytesIO(sparse_wrap(os.urandom(8192))), str(tmp_path / "x.raw"), reserve=reserve)
    assert seen == [8192] and not (tmp_path / "x.raw").exists()


def test_broken_boot_image_via_open_virtual_and_open_source(tmp_path, monkeypatch):
    monkeypatch.setenv("ANDROID_WORKDIR", str(tmp_path / "w"))
    d = tmp_path / "p"
    d.mkdir()
    good = boot_v2(KERNEL, b"x" * 100)
    (d / "boot.img").write_bytes(good[:5000])                                   # header ok, kernel past EOF
    (d / "vendor_boot.img").write_bytes(b"VNDRBOOT" + b"\xff" * 4000)
    with an.open_virtual(str(d)) as vt:
        names = []
        while (m := vt.next()) is not None:
            names.append(m.name)
    assert "boot" in names
    with fp.open_source(directory=str(d)) as (entries, _):
        list(entries)                                                           # must not raise StopIteration / RuntimeError
    assert not any(x.startswith("android-work") for x in os.listdir(tmp_path / "w"))


def test_vendor_boot_table_bomb(tmp_path):
    h = bytearray(4096)
    h[0:8] = b"VNDRBOOT"
    struct.pack_into("<II", h, 8, 4, 4096)
    struct.pack_into("<I", h, 24, 4096)                                          # vendor ramdisk
    struct.pack_into("<I", h, 2096, 2128)
    struct.pack_into("<IIII", h, 2112, 0xFFFFFFF0, 0x7FFFFFFF, 108, 0)           # table size / entries / entry size / bootconfig
    d = tmp_path / "p"
    d.mkdir()
    (d / "vendor_boot.img").write_bytes(bytes(h) + b"\0" * 8192)
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    assert s["partitions"][0]["status"] == "NOT_ASSESSED" and "implausible" in s["partitions"][0]["reasons"][0]
    assert s["status"] == "GAP"


def test_ramdisk_total_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(an, "RAMDISK_MAX", 4096)
    rd = gzip.compress(cpio_newc([("big", b"A" * 20000, 0o100644)]))
    d = tmp_path / "p"
    d.mkdir()
    (d / "init_boot.img").write_bytes(boot_v4(b"", rd))
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    assert s["partitions"][0]["status"] == "NOT_ASSESSED" and s["status"] == "GAP"


def test_status_never_ok_for_vbmeta_only(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "vbmeta.img").write_bytes(b"AVB0" + b"\0" * 252)
    (d / "dtbo.img").write_bytes(b"\xd7\xb7\xab\x1e" + struct.pack(">5I", 32, 32, 20, 0, 32) + b"\0" * 8)
    with an.AndroidPackage(str(d), str(tmp_path / "w")) as pkg:
        pkg.load()
        s = pkg.summary()
    assert s["status"] == "GAP" and s["kernel"]["status"] == "NOT_ASSESSED"
    assert s["security_patch_level"]["system"]["status"] == "NOT_ASSESSED"


@need_mke2fs
def test_spl_invalid_is_flagged_and_values_kept(tmp_path):
    a = android_tree(tmp_path, "a", b"ro.build.version.release=14\nro.build.version.security_patch=2024-05-05\n")
    b = android_tree(tmp_path, "b", b"ro.build.version.security_patch=2023-01-05\n")
    d = tmp_path / "p"
    d.mkdir()
    (d / "system.img").write_bytes(T.mkfs(tmp_path / "a.img", a, 2048, "-t", "ext4", "-b", "1024"))
    (d / "product.img").write_bytes(T.mkfs(tmp_path / "b.img", b, 2048, "-t", "ext4", "-b", "1024"))
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    assert {x["value"] for x in s["facts"]["security_patch"]["all"]} == {"2024-05-05", "2023-01-05"}   # side by side, not overwritten
    c = android_tree(tmp_path, "c", b"ro.build.version.security_patch=bad\nro.build.version.release=14\n")
    (d / "system.img").write_bytes(T.mkfs(tmp_path / "c.img", c, 2048, "-t", "ext4", "-b", "1024"))
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    sp = s["security_patch_level"]["system"]
    assert sp["value"] is None and sp["invalid"] and sp["raw"] == "bad"
    assert s["status"] in ("ATTENTION", "GAP")
    assert json.loads((out / "list.json").read_text())["android"]["security_patch_level"]["system"]["value"] is None


def test_spl_conflict_same_key():
    pkg = an.AndroidPackage.__new__(an.AndroidPackage)
    p1, p2 = an.Part("system", "fs", None, 0, 0, "x"), an.Part("system_ext", "fs", None, 0, 0, "x")
    p1.props = {"system/build.prop": {"ro.build.version.security_patch": "2024-05-05"}}
    p2.props = {"system_ext/build.prop": {"ro.build.version.security_patch": "2024-04-05"}}
    pkg.parts, pkg.boots, pkg.notes, pkg.images, pkg.kernel = [p1, p2], [], [], [], {"status": "OK"}
    facts = pkg.build_facts()
    assert facts["security_patch"]["conflict"] is True
    pkg.facts = facts
    pkg.lp, pkg.other_members, pkg.source = None, [], "x"
    s = pkg.summary()
    assert s["security_patch_level"]["system"]["value"] is None and s["security_patch_level"]["system"]["conflict"]
    assert s["status"] == "GAP" or "conflicting" in s["detail"]


def test_lp_partition_name_sanitised(tmp_path):
    img = lp_super([("../../evil name", [])])
    d = tmp_path / "p"
    d.mkdir()
    (d / "super.img").write_bytes(bytes(img))
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    p = summary(out)["partitions"][0]
    assert p["name"] == "evil_name" and p["lp_name_raw"] == "../../evil name"


def test_lp_overlapping_extents_not_hashed_repeatedly(tmp_path):
    img = lp_super([(f"p{i}", [(8000, 2048)]) for i in range(6)], total=8 << 20)     # six partitions on the same 4 MB
    d = tmp_path / "p"
    d.mkdir()
    (d / "super.img").write_bytes(bytes(img))
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    st = [p["status"] for p in summary(out)["partitions"]]
    assert st.count("NOT_ASSESSED") >= 4


def test_workdir_rules(tmp_path, monkeypatch):
    monkeypatch.delenv("ANDROID_WORKDIR", raising=False)
    with pytest.raises(an.AndroidError, match="ANDROID_WORKDIR"):
        an.AndroidPackage(str(tmp_path))
    g = tmp_path / "repo"
    (g / ".git").mkdir(parents=True)
    with pytest.raises(an.AndroidError, match="git work tree"):
        an.AndroidPackage(str(tmp_path), str(g / "w"))


def test_temp_cleanup_on_exception(tmp_path, monkeypatch):
    d = tmp_path / "p"
    d.mkdir()
    (d / "boot.img").write_bytes(boot_v4(KERNEL, b""))
    (d / "system.img").write_bytes(sparse_wrap(os.urandom(8192)))

    def boom(self):
        raise RuntimeError("boom")
    monkeypatch.setattr(an.AndroidPackage, "pick_kernel", boom)
    out = tmp_path / "res"
    out.mkdir()
    with pytest.raises(RuntimeError):
        fp.do_list(str(out / "list.json"), str(out / "i.json"), directory=str(d))
    assert not [x for x in os.listdir(out) if x.startswith(".android-work")]
    monkeypatch.setenv("ANDROID_WORKDIR", str(tmp_path / "w"))
    with pytest.raises(RuntimeError):
        an.open_virtual(str(d))
    assert os.listdir(tmp_path / "w") == []


def test_member_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(an, "MAX_MEMBERS", 3)
    z = tmp_path / "f.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for i in range(6):
            zf.writestr(f"doc{i}.txt", "x")
        zf.writestr("boot.img", b"x")
    pkg = an.AndroidPackage(str(z), str(tmp_path / "w"))
    with pkg:
        pkg.load()
        assert any(i["name"] == "members" and i["status"] == "NOT_ASSESSED" for i in pkg.images)
        assert pkg.status()[0] == "GAP"


def test_list_cap_is_gap(tmp_path, monkeypatch):
    monkeypatch.setattr(an, "LIST_CAP", 1)
    tree = {"build.prop": PROP_SYSTEM, "lib": None, "lib/liba.so": elf(b"x"), "lib/libb.so": elf(b"y")}
    d = tmp_path / "p"
    d.mkdir()
    (d / "system.img").write_bytes(erofs_image(tree))
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    p = summary(out)["partitions"][0]
    assert p["status"] == "NOT_ASSESSED" and any("truncated" in x for x in p["reasons"])


def test_memory_error_is_caught(tmp_path, monkeypatch):
    d = tmp_path / "p"
    d.mkdir()
    (d / "boot.img").write_bytes(boot_v4(KERNEL, b""))

    def boom(blob):
        raise MemoryError()
    monkeypatch.setattr(an, "analyse_kernel", boom)
    r, out = run_list(tmp_path, archive=None, directory=str(d))
    s = summary(out)
    assert s["partitions"][0]["status"] == "NOT_ASSESSED" and "MemoryError" in s["partitions"][0]["reasons"][0]


def test_rockchip_split_zip_keeps_precedence(tmp_path):
    z = tmp_path / "rk.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for n in ("rootfs.img", "boot.img", "uboot.img", "parameter.txt", "package-file"):
            zf.writestr(n, b"x")
    assert fp.archive_format(str(z)) == "rockchip-zip"


def test_archive_format_order_android_vs_raw_disk_vs_rockchip(tmp_path):
    import gzip as gz
    import lzma
    import test_rpi_img as RP
    disk = RP.disk(tmp_path, with_root=False)
    assert fp.archive_format(str(disk)) == "raw-disk-img"                       # Raspberry Pi style MBR image is not android
    x = tmp_path / "disk.img.xz"
    x.write_bytes(lzma.compress(disk.read_bytes()))
    g = tmp_path / "disk.img.gz"
    g.write_bytes(gz.compress(disk.read_bytes()))
    assert fp.archive_format(str(x)) == "raw-disk-img-xz" and fp.archive_format(str(g)) == "raw-disk-img-gz"
    boot = tmp_path / "boot.img"
    boot.write_bytes(boot_v4(KERNEL, b""))
    sp = tmp_path / "s.img"
    sp.write_bytes(sparse_wrap(os.urandom(8192)))
    sup = tmp_path / "super.img"
    sup.write_bytes(bytes(lp_super([("system", [])])))
    er = tmp_path / "e.img"
    er.write_bytes(erofs_image({"a": b"x"}))
    for f in (boot, sp, sup, er):
        assert fp.archive_format(str(f)) == "android", f.name
    z = tmp_path / "f.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("boot.img", b"x")
    assert fp.archive_format(str(z)) == "android"
    rk = tmp_path / "rk.bin"
    rk.write_bytes(b"RKFW" + b"\0" * 100)
    assert fp.archive_format(str(rk)) == "rockchip-img"
    z2 = tmp_path / "u.zip"
    with zipfile.ZipFile(z2, "w") as zf:
        zf.writestr("update.img", b"RKFW")
    assert fp.archive_format(str(z2)) == "rockchip-zip"
