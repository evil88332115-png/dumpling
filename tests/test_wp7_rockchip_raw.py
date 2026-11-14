"""WP7：Rockchip 原始磁區清點（pipeline/platforms/rockchip/raw_sectors.py）與共用的映像準備（_shared/disk_image.py）。

全部用合成資料（不連網、不需要真的映像）：在暫存資料夾組出 GPT 磁碟、假的 idbloader（RKNS）、FIT（外部資料）、.deb。
跑法：tests/run.d/c4-wp7.sh（python3 -B -m unittest）。
"""
import binascii
import hashlib
import importlib.util
import io
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RAW = os.path.join(ROOT, "pipeline", "platforms", "rockchip", "raw_sectors.py")
DISK = os.path.join(ROOT, "pipeline", "platforms", "_shared", "disk_image.py")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


R = load("wp7_raw_sectors", RAW)
SECTOR = 512
LINUX_FS = bytes.fromhex("af3dc60f838472478e793d69d8477de4")   # 0FC63DAF-8483-4772-8E79-3D69D8477DE4（混合位元組序）

def rj(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def rb(path):
    with open(path, "rb") as f:
        return f.read()


def wb(path, data):
    with open(path, "wb") as f:
        f.write(data)



# ---------------------------------------------------------------- 合成資料

def gpt_disk(path, total_sectors, parts, payloads=(), ent_lba=2):
    """parts：[(起始 LBA, 磁區數, 名稱)]；payloads：[(LBA, bytes)]。寫出有 CRC 的主要 GPT（保護 MBR＋表頭＋陣列）。"""
    disk = bytearray(total_sectors * SECTOR)
    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\0\0\0", 0xEE, b"\0\0\0", 1, min(total_sectors - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    disk[0:SECTOR] = mbr
    entries = bytearray(128 * 128)
    for i, (start, n, name) in enumerate(parts):
        e = LINUX_FS + os.urandom(16) + struct.pack("<QQQ", start, start + n - 1, 0) + name.encode("utf-16-le").ljust(72, b"\0")
        entries[i * 128:(i + 1) * 128] = e
    disk[ent_lba * SECTOR:ent_lba * SECTOR + len(entries)] = entries
    first_usable = ent_lba + 32
    hdr = bytearray(struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x10000, 92, 0, 0, 1, total_sectors - 1, first_usable,
                                total_sectors - 34, os.urandom(16), ent_lba, 128, 128, binascii.crc32(entries) & 0xFFFFFFFF))
    struct.pack_into("<I", hdr, 16, binascii.crc32(hdr[:92]) & 0xFFFFFFFF)
    disk[SECTOR:SECTOR + len(hdr)] = hdr
    for lba, data in payloads:
        disk[lba * SECTOR:lba * SECTOR + len(data)] = data
    with open(path, "wb") as f:
        f.write(disk)


def fdt(nodes, align_ext=4, ext=b""):
    """最小的 FDT 產生器：nodes＝[(路徑層數, 名稱, {屬性: bytes}) ...]，依序開／關節點。回傳整個 FIT（FDT＋外部資料）。"""
    strings, soff = bytearray(), {}

    def sref(n):
        if n not in soff:
            soff[n] = len(strings)
            strings.extend(n.encode() + b"\0")
        return soff[n]

    st = bytearray()

    def pad():
        while len(st) % 4:
            st.append(0)

    depth = 0
    for lvl, name, props in nodes:
        while depth > lvl:
            st.extend(struct.pack(">I", 2)); depth -= 1
        st.extend(struct.pack(">I", 1)); st.extend(name.encode() + b"\0"); pad(); depth += 1
        for k, v in props.items():
            st.extend(struct.pack(">III", 3, len(v), sref(k))); st.extend(v); pad()
    while depth > 0:
        st.extend(struct.pack(">I", 2)); depth -= 1
    st.extend(struct.pack(">I", 9))
    off_rsv = 40
    off_struct = off_rsv + 16
    off_strings = off_struct + len(st)
    total = off_strings + len(strings)
    hdr = struct.pack(">10I", 0xd00dfeed, total, off_struct, off_strings, off_rsv, 17, 16, 0, len(strings), len(st))
    blob = hdr + b"\0" * 16 + bytes(st) + bytes(strings)
    base = (total + align_ext - 1) & ~(align_ext - 1)
    return blob + b"\0" * (base - total) + ext


def s(t):
    return t.encode() + b"\0"


def u32(v):
    return struct.pack(">I", v)


def make_fit(align=512, corrupt=False):
    uboot = b"U-Boot rk2410-2017.09-1-gabcdef1 (Jan 1 2026)\0" + os.urandom(3000)
    atf = b"bl31-v1.54\0v2.3-1-g1234567:someone, fwver: v1.54\0" + os.urandom(2000)
    ext = uboot + atf
    h_u = hashlib.sha256(uboot).digest()
    h_a = hashlib.sha256(atf if not corrupt else atf + b"x").digest()
    nodes = [(0, "", {"description": s("FIT Image with ATF/OP-TEE/U-Boot/MCU")}),
             (1, "images", {}),
             (2, "uboot", {"description": s("U-Boot"), "type": s("standalone"), "arch": s("arm64"),
                           "data-offset": u32(0), "data-size": u32(len(uboot))}),
             (3, "hash", {"algo": s("sha256"), "value": h_u}),
             (2, "atf-1", {"description": s("ARM Trusted Firmware"), "type": s("firmware"), "arch": s("arm64"),
                           "data-offset": u32(len(uboot)), "data-size": u32(len(atf))}),
             (3, "hash", {"algo": s("sha256"), "value": h_a}),
             (1, "configurations", {}),
             (2, "conf", {"description": s("rk3588-test-board")})]
    return fdt(nodes, align_ext=align, ext=ext)


def make_idb():
    return b"RKNS" + os.urandom(1000) + b"U-Boot SPL board init\0U-Boot SPL rk2410-2017.09-1-gabcdef1 (x)\0ddr-v1.22-d4bf75a5a6\0" + os.urandom(500)


def make_deb(path, board, files, package="u-boot-test", version="1.0"):
    def tar_xz(members):
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w") as t:
            for name, data in members:
                ti = tarfile.TarInfo(name); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
        return lzma.compress(bio.getvalue())

    ctrl = tar_xz([("./control", ("Package: %s\nVersion: %s\n" % (package, version)).encode())])
    data = tar_xz([("./usr/lib/u-boot/%s/%s" % (board, n), d) for n, d in files.items()])
    out = bytearray(b"!<arch>\n")
    for name, body in (("debian-binary", b"2.0\n"), ("control.tar.xz", ctrl), ("data.tar.xz", data)):
        out += ("%-16s%-12s%-6s%-6s%-8s%-10d`\n" % (name, "0", "0", "0", "100644", len(body))).encode()
        out += body
        if len(body) % 2:
            out += b"\n"
    with open(path, "wb") as f:
        f.write(out)


def run_raw(*args):
    p = subprocess.run([sys.executable, "-I", RAW, "inventory", *args], capture_output=True, text=True)
    return p.returncode, p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""


class RawSectorsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wp7-raw-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.img = os.path.join(self.tmp, "disk.img")
        self.out = os.path.join(self.tmp, "raw.json")
        self.idb = make_idb()
        self.fit = make_fit()
        # 槽位用小的 LBA，映像才不會太大：idbloader 64、u-boot.itb 256；第一個分割區 1024
        self.slots = ["--slot", "idbloader.img=64", "--slot", "u-boot.itb=256", "--slot", "trust.img=900"]

    def disk(self, payloads=None, parts=((1024, 512, "rootfs"),)):
        if payloads is None:
            payloads = [(64, self.idb), (256, self.fit)]
        gpt_disk(self.img, 2048, list(parts), payloads)

    def deb(self, files=None, name="u-boot.deb"):
        p = os.path.join(self.tmp, name)
        make_deb(p, "test-board", files if files is not None else {"idbloader.img": self.idb, "u-boot.itb": self.fit})
        return p

    def inv(self, *extra):
        rc, line = run_raw("--image", self.img, "--out", self.out, "--board", "test-board", *self.slots, *extra)
        doc = rj(self.out) if os.path.exists(self.out) else None
        return rc, line, doc

    def test_consistent_package_is_ok(self):
        self.disk()
        rc, line, doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 0, line)
        self.assertTrue(line.startswith("raw-sectors: OK"), line)
        self.assertEqual([r["slot"] for r in doc["regions"]], ["idbloader.img", "u-boot.itb"])
        idb, fit = doc["regions"]
        self.assertEqual(idb["identity"]["kind"], "rockchip-idblock")
        self.assertEqual(fit["identity"]["kind"], "fit")
        pkg = [c for c in idb["corroboration"] if c["source"] == "package"][0]
        self.assertEqual((pkg["state"], pkg["package"], pkg["version"]), ("一致", "u-boot-test", "1.0"))
        # rootfs 讀不到（合成映像沒有 ext4）→ 記下來，但有套件一致就不是 GAP
        self.assertIn("找不到", [c for c in idb["corroboration"] if c["source"] == "rootfs"][0]["state"])

    def test_versions_only_take_version_fields(self):
        self.disk()
        _rc, _line, doc = self.inv("--deb", self.deb())
        idb, fit = doc["regions"]
        v = {(x["component"], x["version"]) for x in idb["identity"]["versions"]}
        self.assertIn(("U-Boot SPL", "rk2410-2017.09-1-gabcdef1"), v)
        self.assertIn(("Rockchip DDR init", "v1.22"), v)
        self.assertNotIn(("U-Boot SPL", "board"), v)            # 「U-Boot SPL board init」不是版本
        fv = {(x["component"], x["version"]) for x in fit["identity"]["versions"]}
        self.assertIn(("TF-A BL31 (Rockchip rkbin)", "v1.54"), fv)
        self.assertIn(("TF-A git describe", "v2.3-1-g1234567"), fv)
        self.assertNotIn("someone", json.dumps(doc))             # 建置者名稱不進輸出

    def test_fit_hash_checked_with_512_and_4_byte_base(self):
        for align, label in ((512, "block-512"), (4, "upstream-4")):
            self.fit = make_fit(align=align)
            self.disk()
            rc, line, doc = self.inv("--deb", self.deb())
            self.assertEqual(rc, 0, line)
            imgs = doc["regions"][1]["identity"]["fit"]["images"]
            self.assertTrue(all(i["fit_hash"]["matches"] for i in imgs))
            self.assertEqual({i["data_base"] for i in imgs}, {label})

    def test_fit_hash_mismatch_is_gap(self):
        self.fit = make_fit(corrupt=True)
        self.disk()
        rc, line, _doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 3)
        self.assertIn("雜湊跟 FIT 記載的不符", line)

    def test_package_differs_is_gap(self):
        self.disk()
        other = bytearray(self.idb); other[100] ^= 0xFF
        rc, line, doc = self.inv("--deb", self.deb({"idbloader.img": bytes(other), "u-boot.itb": self.fit}))
        self.assertEqual(rc, 3)
        self.assertEqual([c["state"] for c in doc["regions"][0]["corroboration"] if c["source"] == "package"], ["不一致"])
        self.assertIn("LBA 64", line)

    def test_no_package_is_gap(self):
        self.disk()
        rc, line, _doc = self.inv()
        self.assertEqual(rc, 3)
        self.assertIn("沒有任何佐證來源一致", line)

    def test_unknown_data_before_first_slot_is_gap(self):
        self.disk(payloads=[(40, b"\x01" * 600), (64, self.idb), (256, self.fit)])
        rc, line, doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 3)
        self.assertEqual(doc["regions"][0]["slot"], None)
        self.assertIn("身分不明", line)

    def test_trailing_zero_sector_in_file_still_consistent(self):
        idb = self.idb + b"\0" * (SECTOR * 2)            # 檔案結尾是全零的磁區：非零區段比檔案短
        self.disk(payloads=[(64, idb), (256, self.fit)])
        rc, line, _doc = self.inv("--deb", self.deb({"idbloader.img": idb, "u-boot.itb": self.fit}))
        self.assertEqual(rc, 0, line)

    def test_extra_data_after_file_is_inconsistent(self):
        self.disk(payloads=[(64, self.idb + b"\0" * 40 + b"\x07" * 16), (256, self.fit)])
        rc, _line, doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 3)
        self.assertEqual([c["state"] for c in doc["regions"][0]["corroboration"] if c["source"] == "package"], ["不一致"])

    def test_nothing_before_partition_is_gap(self):
        self.disk(payloads=[])
        rc, line, _doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 3)
        self.assertIn("沒有任何非零磁區", line)

    def test_mbr_image_fails(self):
        with open(self.img, "wb") as f:
            mbr = bytearray(SECTOR * 2048)
            mbr[446:462] = struct.pack("<B3sB3sII", 0x80, b"\0\0\0", 0x83, b"\0\0\0", 1024, 512)
            mbr[510:512] = b"\x55\xaa"
            f.write(mbr)
        rc, line, _doc = self.inv()
        self.assertEqual(rc, 1)
        self.assertIn("不是 GPT", line)

    def test_bad_args(self):
        self.disk()
        rc, line, _doc = self.inv("--slot", "bad slot=abc")
        self.assertEqual(rc, 64)
        rc, _line = run_raw("--image", self.img, "--out", self.out, "--board", "../x")
        self.assertEqual(rc, 64)

    def test_malformed_fdt_is_unparsed_not_crash(self):
        bad = bytearray(self.fit); struct.pack_into(">I", bad, 8, 0xFFFFFF)   # off_dt_struct 超出範圍
        self.disk(payloads=[(64, self.idb), (256, bytes(bad))])
        rc, _line, doc = self.inv("--deb", self.deb({"idbloader.img": self.idb, "u-boot.itb": bytes(bad)}))
        self.assertEqual(rc, 3)
        self.assertEqual(doc["regions"][1]["identity"]["kind"], "fdt-unparsed")

    def test_not_a_deb_is_recorded(self):
        self.disk()
        junk = os.path.join(self.tmp, "junk.deb")
        wb(junk, b"not an ar archive")
        rc, _line, doc = self.inv("--deb", junk, "--deb", self.deb())
        self.assertEqual(rc, 0)
        self.assertIn("不是 ar", [x for x in doc["sources"] if x["file"] == "junk.deb"][0]["error"])

    # ---- 驗證代理指出的缺口（GAP 不能變成 OK）
    def test_slot_zero_but_package_has_file_is_gap(self):
        self.disk(payloads=[(64, self.idb)])                     # u-boot.itb 的磁區全零
        rc, line, _doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 3, line)
        self.assertIn("磁區卻是全零", line)

    def test_fit_without_sha256_is_gap(self):
        self.fit = self.fit.replace(b"sha256\0", b"crc32\0\0")    # 每個 hash 節點的 algo 都改掉：沒有 sha256 可以驗證
        self.disk()
        rc, line, doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 3, line)
        self.assertIn("無法驗證", line)
        self.assertTrue(all(i["fit_hash"] is None for i in doc["regions"][1]["identity"]["fit"]["images"]))

    def test_fit_data_out_of_range_is_gap(self):
        cut = self.fit[:len(self.fit) - 1500]                    # 外部資料被截掉一段（超過一個磁區）
        self.fit = cut
        self.disk()
        rc, line, doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 3, line)
        self.assertIn("out-of-range", {i["data"] for i in doc["regions"][1]["identity"]["fit"]["images"]})

    def test_contradicting_sources_is_gap(self):
        self.disk()
        other = bytearray(self.idb); other[200] ^= 1
        rc, line, _doc = self.inv("--deb", self.deb(), "--deb", self.deb({"idbloader.img": bytes(other), "u-boot.itb": self.fit}, "b.deb"))
        self.assertEqual(rc, 3, line)
        self.assertIn("互相矛盾", line)

    def test_bad_gzip_deb_is_source_error_not_fail(self):
        self.disk()
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w:gz") as t:
            ti = tarfile.TarInfo("./usr/lib/u-boot/test-board/idbloader.img"); ti.size = len(self.idb); t.addfile(ti, io.BytesIO(self.idb))
        gz = bytearray(bio.getvalue()); gz[15] ^= 0xFF
        out = bytearray(b"!<arch>\n")
        for name, body in (("debian-binary", b"2.0\n"), ("data.tar.gz", bytes(gz))):
            out += ("%-16s%-12s%-6s%-6s%-8s%-10d`\n" % (name, "0", "0", "0", "100644", len(body))).encode() + body + (b"\n" if len(body) % 2 else b"")
        bad = os.path.join(self.tmp, "bad.deb"); wb(bad, bytes(out))
        rc, line, doc = self.inv("--deb", bad, "--deb", self.deb())
        self.assertEqual(rc, 0, line)
        self.assertTrue([x for x in doc["sources"] if x["file"] == "bad.deb"][0]["error"])

    def test_truncated_xz_in_deb_is_source_error(self):
        self.disk()
        good = self.deb()
        b = rb(good)
        # 把 data.tar.xz 尾端剪掉 30 bytes（ar 標頭的大小一起改）
        i = b.index(b"data.tar.xz")
        size = int(b[i + 48:i + 58])
        body = b[i + 60:i + 60 + size][:-30]
        hdr = ("%-16s%-12s%-6s%-6s%-8s%-10d`\n" % ("data.tar.xz", "0", "0", "0", "100644", len(body))).encode()
        trunc = os.path.join(self.tmp, "trunc.deb"); wb(trunc, b[:i] + hdr + body + (b"\n" if len(body) % 2 else b""))
        rc, line, doc = self.inv("--deb", trunc)
        self.assertEqual(rc, 3, line)
        self.assertIn("RawError", [x for x in doc["sources"] if x["file"] == "trunc.deb"][0]["error"])

    def test_too_many_ar_members_is_source_error(self):
        self.disk()
        out = bytearray(b"!<arch>\n")
        for k in range(40):
            out += ("%-16s%-12s%-6s%-6s%-8s%-10d`\n" % ("m%d" % k, "0", "0", "0", "100644", 0)).encode()
        many = os.path.join(self.tmp, "many.deb"); wb(many, bytes(out))
        _rc, _line, doc = self.inv("--deb", many, "--deb", self.deb())
        self.assertIn("成員超過", [x for x in doc["sources"] if x["file"] == "many.deb"][0]["error"])

    def test_fdt_without_end_is_unparsed(self):
        fit = bytearray(self.fit)
        off_struct, size_struct = struct.unpack(">I", fit[8:12])[0], struct.unpack(">I", fit[36:40])[0]
        struct.pack_into(">I", fit, off_struct + size_struct - 4, 4)          # END 改成 NOP
        self.fit = bytes(fit)
        self.disk()
        rc, _line, doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 3)
        self.assertEqual(doc["regions"][1]["identity"]["kind"], "fdt-unparsed")

    def test_package_file_longer_than_image_is_inconsistent(self):
        self.disk()
        big = self.fit + os.urandom(SECTOR * 1100)              # 比映像剩下的長
        rc, _line, doc = self.inv("--deb", self.deb({"idbloader.img": self.idb, "u-boot.itb": big}))
        self.assertEqual(rc, 3)
        self.assertEqual([c["state"] for c in doc["regions"][1]["corroboration"] if c["source"] == "package"], ["不一致"])

    @unittest.skipUnless(shutil.which("mkfs.ext4"), "需要 mkfs.ext4（e2fsprogs）")
    def test_rootfs_files_are_corroboration(self):
        tree = os.path.join(self.tmp, "tree")
        b = os.path.join(tree, "usr", "lib", "u-boot", "test-board")
        os.makedirs(b); os.makedirs(os.path.join(tree, "etc"))
        wb(os.path.join(b, "idbloader.img"), self.idb)
        wb(os.path.join(b, "u-boot.itb"), self.fit)
        os.symlink("/etc/passwd", os.path.join(b, "trust.img"))           # 符號連結不跟
        ext = os.path.join(self.tmp, "root.ext4")
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", tree, ext, "4M"], check=True, capture_output=True)
        e = rb(ext)
        nsec = len(e) // SECTOR
        self.disk(payloads=[(64, self.idb), (256, self.fit), (1024, e)], parts=((1024, nsec, "rootfs"),))
        gpt_disk(self.img, 1024 + nsec + 40, [(1024, nsec, "rootfs")], [(64, self.idb), (256, self.fit), (1024, e)])
        rc, line, doc = self.inv()
        self.assertEqual(rc, 0, line)
        for r in doc["regions"]:
            self.assertEqual([c["state"] for c in r["corroboration"] if c["source"] == "rootfs"], ["一致"])
        self.assertEqual([x for x in doc["sources"] if x["source"] == "rootfs"][0]["found"], ["idbloader.img", "u-boot.itb"])

    def test_gpt_array_moved_still_scans_early_slots(self):
        # 分割區陣列放在 LBA 128（第 1 到 127 磁區之間有 idbloader）：不能只從陣列之後開始掃
        gpt_disk(self.img, 2048, [(1024, 512, "rootfs")], [(64, self.idb), (256, self.fit)], ent_lba=128)
        rc, line, doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 0, line)
        self.assertEqual([r["slot"] for r in doc["regions"]], ["idbloader.img", "u-boot.itb"])
        self.assertEqual(doc["gpt_entry_array_lba"], [128, 160])

    def test_slot_inside_gpt_array_is_gap(self):
        gpt_disk(self.img, 2048, [(1024, 512, "rootfs")], [(256, self.fit)], ent_lba=48)   # 陣列 48–79，槽位 64 在裡面
        rc, line, _doc = self.inv("--deb", self.deb())
        self.assertEqual(rc, 3, line)
        self.assertIn("分割區陣列裡", line)


class DiskImageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wp7-disk-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.proj = os.path.join(self.tmp, "proj")
        os.makedirs(self.proj)
        self.dl = os.path.join(self.tmp, "downloads")
        os.makedirs(self.dl)

    def sources(self, name, extra_params=""):
        with open(os.path.join(self.proj, "sources.yml"), "w", encoding="utf-8") as f:
            f.write("schema: 1\nreleases:\n  v1.0.0-t:\n    platform_params:\n      image: %s\n%s    files:\n"
                    "      - name: %s\n        url: https://example.com/%s\n        sha256: %s\n        role: image\n"
                    % (name, extra_params, name, name, "a" * 64))

    def tarxz(self, name, members):
        p = os.path.join(self.dl, name)
        with tarfile.open(p, "w:xz") as t:
            for m in members:
                t.addfile(m[0], io.BytesIO(m[1]) if m[1] is not None else None)
        return p

    def prepare(self):
        work = os.path.join(self.tmp, "work")
        p = subprocess.run([sys.executable, "-I", DISK, "prepare", self.proj, "v1.0.0-t", "--downloads", self.dl,
                            "--work", work, "--json", os.path.join(self.tmp, "assemble.json")], capture_output=True, text=True)
        return p.returncode, (p.stdout.strip().splitlines() or [""])[-1], os.path.join(work, "disk.img")

    def ti(self, name, data=b"", typ=tarfile.REGTYPE, link=""):
        t = tarfile.TarInfo(name); t.type = typ; t.size = len(data) if typ == tarfile.REGTYPE else 0; t.linkname = link
        return (t, data if typ == tarfile.REGTYPE else None)

    def test_tar_member_extracted_only(self):
        body = os.urandom(70000)
        self.tarxz("img.tar.xz", [self.ti("README", b"hi"), self.ti("disk.raw", body)])
        self.sources("img.tar.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 0, line)
        self.assertEqual(rb(img), body)
        self.assertEqual(os.stat(img).st_mode & 0o777, 0o600)
        doc = rj(os.path.join(self.tmp, "assemble.json"))
        self.assertEqual(doc["disk_sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual([m["name"] for m in doc["other_members"]], ["README"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "work", "README")))

    def test_tar_member_dot_slash_and_custom_name(self):
        body = b"x" * 1000
        self.tarxz("img.tar.xz", [self.ti("./image.raw", body)])
        self.sources("img.tar.xz", "      image_member: image.raw\n")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 0, line)
        self.assertEqual(rb(img), body)

    def test_symlink_member_fails(self):
        self.tarxz("img.tar.xz", [self.ti("disk.raw", typ=tarfile.SYMTYPE, link="/etc/passwd")])
        self.sources("img.tar.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("不是一般檔案", line)
        self.assertFalse(os.path.exists(img))

    def test_duplicate_member_fails(self):
        self.tarxz("img.tar.xz", [self.ti("disk.raw", b"a"), self.ti("disk.raw", b"b")])
        self.sources("img.tar.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("兩個", line)
        self.assertFalse(os.path.exists(img))

    def test_missing_member_fails(self):
        self.tarxz("img.tar.xz", [self.ti("other.raw", b"a")])
        self.sources("img.tar.xz")
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("沒有 disk.raw", line)

    def test_img_xz_extracted(self):
        body = os.urandom(5000)
        wb(os.path.join(self.dl, "a.img.xz"), lzma.compress(body))
        self.sources("a.img.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 0, line)
        self.assertEqual(rb(img), body)

    def test_not_downloaded_fails(self):
        self.sources("a.img.xz")
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("先執行 fetch", line)

    def test_image_param_must_be_role_image(self):
        with open(os.path.join(self.proj, "sources.yml"), "w", encoding="utf-8") as f:
            f.write("schema: 1\nreleases:\n  v1.0.0-t:\n    platform_params: {image: x.deb}\n    files:\n"
                    "      - {name: x.deb, url: 'https://example.com/x', sha256: '%s', role: package}\n" % ("a" * 64))
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("role: image", line)

    def raw_tar(self, name, blocks):
        """自己組 tar 區塊（測試 longname／PAX 的大小上限），再壓成 xz。"""
        p = os.path.join(self.dl, name)
        wb(p, lzma.compress(b"".join(blocks) + b"\0" * 1024))
        return p

    def hdr(self, name, size, typ=b"0"):
        h = bytearray(512)
        h[0:len(name)] = name
        h[100:108] = b"0000644\0"; h[108:116] = b"0000000\0"; h[116:124] = b"0000000\0"
        h[124:136] = b"%011o\0" % size
        h[136:148] = b"00000000000\0"
        h[156:157] = typ
        h[257:263] = b"ustar\0"; h[263:265] = b"00"
        h[148:156] = b" " * 8
        h[148:156] = b"%06o\0 " % sum(h)
        return bytes(h)

    def test_longname_size_bomb_is_rejected(self):
        self.raw_tar("bomb.tar.xz", [self.hdr(b"././@LongLink", 1500 << 20, b"L")])
        self.sources("bomb.tar.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("longname", line)
        self.assertFalse(os.path.exists(img))

    def test_pax_path_names_member(self):
        body = b"z" * 700
        rec = b"path=disk.raw\n"
        rec = b"%d %s" % (len(rec) + 3, rec)
        assert int(rec.split(b" ")[0]) == len(rec)
        pad = lambda b: b + b"\0" * (-len(b) % 512)
        self.raw_tar("pax.tar.xz", [self.hdr(b"PaxHeader", len(rec), b"x"), pad(rec),
                                     self.hdr(b"something-else", len(body)), pad(body)])
        self.sources("pax.tar.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 0, line)
        self.assertEqual(rb(img), body)

    def test_bad_checksum_fails(self):
        h = bytearray(self.hdr(b"disk.raw", 10)); h[0] = ord("x")
        self.raw_tar("chk.tar.xz", [bytes(h), b"a" * 10 + b"\0" * 502])
        self.sources("chk.tar.xz")
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("檢查碼", line)

    def test_truncated_xz_fails(self):
        p = self.tarxz("img.tar.xz", [self.ti("disk.raw", os.urandom(4000))])
        wb(p, rb(p)[:-20])
        self.sources("img.tar.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 1, line)
        self.assertFalse(os.path.exists(img))

    def test_trailing_garbage_after_tar_fails(self):
        blocks = [self.hdr(b"disk.raw", 10), b"a" * 10 + b"\0" * 502, b"\0" * 1024, b"GARBAGE"]
        wb(os.path.join(self.dl, "g.tar.xz"), lzma.compress(b"".join(blocks)))
        self.sources("g.tar.xz")
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 1, line)

    def test_hardlink_member_fails(self):
        self.tarxz("img.tar.xz", [self.ti("other", b"x"), self.ti("disk.raw", typ=tarfile.LNKTYPE, link="other")])
        self.sources("img.tar.xz")
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("不是一般檔案", line)

    def test_uncompressed_img_and_disk_path(self):
        wb(os.path.join(self.dl, "a.img"), b"\0" * 4096)
        self.sources("a.img")
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 0, line)
        j = os.path.join(self.tmp, "assemble.json")
        self.assertEqual(rj(j)["disk_image"], os.path.relpath(os.path.join(self.dl, "a.img"), self.tmp))
        p = subprocess.run([sys.executable, "-I", DISK, "disk", j], capture_output=True, text=True)
        self.assertEqual(p.stdout.strip(), os.path.join(self.dl, "a.img"))

    def test_assemble_json_has_no_absolute_path(self):
        self.tarxz("img.tar.xz", [self.ti("disk.raw", b"x" * 100)])
        self.sources("img.tar.xz")
        self.assertEqual(self.prepare()[0], 0)
        text = rb(os.path.join(self.tmp, "assemble.json")).decode()
        self.assertNotIn(self.tmp, text)
        self.assertEqual(rj(os.path.join(self.tmp, "assemble.json"))["disk_image"], "work/disk.img")

    def test_disk_path_rejects_escape(self):
        j = os.path.join(self.tmp, "assemble.json")
        wb(j, json.dumps({"disk_image": "../etc/passwd"}).encode())
        p = subprocess.run([sys.executable, "-I", DISK, "disk", j], capture_output=True, text=True)
        self.assertEqual(p.returncode, 1)

    def test_gap_entry_is_gap(self):
        with open(os.path.join(self.proj, "sources.yml"), "w", encoding="utf-8") as f:
            f.write("schema: 1\nreleases:\n  v1.0.0-t:\n    platform_params: {image: a.img.xz}\n    files:\n"
                    "      - {name: a.img.xz, url: 'https://example.com/x', role: image, gap: 還沒有雜湊}\n")
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 3, line)

    def gnu_hdr(self, name, size, typ=b"0", sparse=(), realsize=0, ext=False):
        """GNU 格式（magic "ustar  \0"）的標頭；sparse：最多 4 筆 (offset, numbytes)。"""
        h = bytearray(512)
        h[0:len(name)] = name
        h[100:108] = b"0000644\0"; h[108:116] = b"0000000\0"; h[116:124] = b"0000000\0"
        h[124:136] = b"%011o\0" % size
        h[136:148] = b"00000000000\0"
        h[156:157] = typ
        h[257:265] = b"ustar  \0"
        h[345:357] = b"77777777777\0"          # GNU 的 atime：不是 prefix（POSIX 才有 prefix）
        for k, (off, n) in enumerate(sparse):
            o = 386 + 24 * k
            h[o:o + 12] = b"%011o\0" % off
            h[o + 12:o + 24] = b"%011o\0" % n
        h[482] = 1 if ext else 0
        h[483:495] = b"%011o\0" % realsize
        h[148:156] = b" " * 8
        h[148:156] = b"%06o\0 " % sum(h)
        return bytes(h)

    def test_gnu_sparse_member(self):
        # 真實的 Debian 雲端映像是 GNU 舊式稀疏（型別 S）：資料兩段、中間與結尾是洞
        a, b = os.urandom(1000), os.urandom(600)
        real = 1 << 16
        data = a + b
        blocks = [self.gnu_hdr(b"disk.raw", len(data), b"S", [(0, 1000), (8192, 600), (real, 0)], real),
                  data + b"\0" * (-len(data) % 512)]
        self.raw_tar("sp.tar.xz", blocks)
        self.sources("sp.tar.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 0, line)
        want = a + b"\0" * (8192 - 1000) + b + b"\0" * (real - 8192 - 600)
        self.assertEqual(rb(img), want)
        self.assertEqual(rj(os.path.join(self.tmp, "assemble.json"))["disk_sha256"], hashlib.sha256(want).hexdigest())

    def test_gnu_sparse_extended_table(self):
        # 4 筆以上的稀疏表放在延伸區塊（每塊 21 筆）
        parts, data, real = [], b"", 1 << 16
        for k in range(6):
            parts.append((k * 4096, 100)); data += bytes([k + 1]) * 100
        h = self.gnu_hdr(b"disk.raw", len(data), b"S", parts[:4], real, ext=True)
        ext = bytearray(512)
        for k, (off, n) in enumerate(parts[4:]):
            ext[24 * k:24 * k + 12] = b"%011o\0" % off
            ext[24 * k + 12:24 * k + 24] = b"%011o\0" % n
        self.raw_tar("spx.tar.xz", [h, bytes(ext), data + b"\0" * (-len(data) % 512)])
        self.sources("spx.tar.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 0, line)
        got = rb(img)
        self.assertEqual(len(got), real)
        for k, (off, n) in enumerate(parts):
            self.assertEqual(got[off:off + n], bytes([k + 1]) * n)

    def test_gnu_sparse_overlap_fails(self):
        self.raw_tar("bad.tar.xz", [self.gnu_hdr(b"disk.raw", 200, b"S", [(100, 100), (150, 100)], 4096), b"x" * 200 + b"\0" * 312])
        self.sources("bad.tar.xz")
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("重疊", line)

    def test_gnu_magic_does_not_use_prefix(self):
        body = b"q" * 300
        self.raw_tar("g.tar.xz", [self.gnu_hdr(b"disk.raw", len(body)), body + b"\0" * 212])
        self.sources("g.tar.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 0, line)
        self.assertEqual(rb(img), body)

    def test_negative_pax_size_fails(self):
        rec = b"size=-5\n"
        rec = b"%d %s" % (len(rec) + 3, rec)
        assert int(rec.split(b" ")[0]) == len(rec)
        pad = lambda b: b + b"\0" * (-len(b) % 512)
        self.raw_tar("neg.tar.xz", [self.hdr(b"PaxHeader", len(rec), b"x"), pad(rec), self.hdr(b"disk.raw", 0), b"x" * 5])
        self.sources("neg.tar.xz")
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("size", line)

    def test_empty_member_fails(self):
        self.raw_tar("e.tar.xz", [self.hdr(b"disk.raw", 0)])
        self.sources("e.tar.xz")
        rc, line, _img = self.prepare()
        self.assertEqual(rc, 1)
        self.assertIn("空檔", line)

    def test_xz_trailing_garbage_fails(self):
        p = self.tarxz("img.tar.xz", [self.ti("disk.raw", os.urandom(3000))])
        wb(p, rb(p) + b"JUNKJUNK")
        self.sources("img.tar.xz")
        rc, line, img = self.prepare()
        self.assertEqual(rc, 1, line)
        self.assertFalse(os.path.exists(img))

    @unittest.skipUnless(shutil.which("mkfs.ext4"), "需要 mkfs.ext4（e2fsprogs）")
    def test_owners_from_dpkg_lists(self):
        tree = os.path.join(self.tmp, "tree")
        info = os.path.join(tree, "var", "lib", "dpkg", "info")
        os.makedirs(info); os.makedirs(os.path.join(tree, "etc")); os.makedirs(os.path.join(tree, "usr"))
        wb(os.path.join(info, "bash.list"), b"/.\n/usr/bin/bash\n/usr/share/doc/bash\n")
        wb(os.path.join(info, "libc6:arm64.list"), b"/usr/lib/aarch64-linux-gnu/libc.so.6\n/usr/share/doc/bash\n")
        wb(os.path.join(info, "bash.md5sums"), b"x\n")
        ext = os.path.join(self.tmp, "root.ext4")
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", tree, ext, "4M"], check=True, capture_output=True)
        e = rb(ext)
        img = os.path.join(self.dl, "a.img")
        gpt_disk(img, 64 + len(e) // 512 + 40, [(64, len(e) // 512, "rootfs")], [(64, e)])
        self.sources("a.img")
        self.assertEqual(self.prepare()[0], 0)
        out = os.path.join(self.tmp, "owners.json")
        p = subprocess.run([sys.executable, "-I", DISK, "owners", os.path.join(self.tmp, "assemble.json"), "--out", out], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("2 個 .list", p.stdout)
        self.assertEqual(rj(out), {"/usr/bin/bash": "bash", "/usr/lib/aarch64-linux-gnu/libc.so.6": "libc6", "/usr/share/doc/bash": "bash"})

    def test_owners_without_rootfs_is_gap(self):
        gpt_disk(os.path.join(self.dl, "a.img"), 2048, [(1024, 512, "data")])     # 有 GPT、分割區不是 ext4：沒有 rootfs
        self.sources("a.img")
        self.assertEqual(self.prepare()[0], 0)
        p = subprocess.run([sys.executable, "-I", DISK, "owners", os.path.join(self.tmp, "assemble.json"), "--out", os.path.join(self.tmp, "o.json")],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 3, p.stdout)

    def test_param_and_files(self):
        self.sources("a.img.xz", "      uboot_board: rock-5b\n")
        p = subprocess.run([sys.executable, "-I", DISK, "param", self.proj, "v1.0.0-t", "uboot_board"], capture_output=True, text=True)
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "rock-5b"))
        p = subprocess.run([sys.executable, "-I", DISK, "param", self.proj, "v1.0.0-t", "nope"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 3)
        p = subprocess.run([sys.executable, "-I", DISK, "files", self.proj, "v1.0.0-t", "--role", "image"], capture_output=True, text=True)
        self.assertEqual(p.stdout.strip(), "image\ta.img.xz")


class PlatformConfigTest(unittest.TestCase):
    """三個平台設定與示範專案都要通過 C1 的驗證；分層清單照 D-027（只看名稱、不看版本字尾）。"""

    def setUp(self):
        sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
        import project_config
        self.pc = project_config

    def test_platforms_validate(self):
        for p in ("raspberrypi", "rockchip", "ai-nas"):
            self.pc.load_platform_config(p)

    def test_projects_validate(self):
        for p in ("rpi-lite-demo", "rock-5b-demo", "ai-nas-demo"):
            subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "lib", "project_config.py"), "validate",
                            os.path.join(ROOT, "projects", p)], check=True, capture_output=True)

    def test_layer_examples(self):
        rpi = self.pc.load_platform_config("raspberrypi")
        for name, want in (("linux-image-6.18.50+rpt-rpi-2712", "bsp"), ("raspi-firmware", "bsp"), ("libcamera0.6", "bsp"),
                           ("alsa-utils", "os"), ("rpi-connect-lite", "os"), ("firmware-realtek", "os"), ("bluez", "os"),
                           # D-049：分層看元件本身，不跟相依走——RPi.GPIO 相容層綁板子（bsp），它依賴的 lgpio 函式庫是通用的（os）
                           ("python3-rpi-lgpio", "bsp"), ("liblgpio1", "os"), ("python3-lgpio", "os")):
            self.assertEqual(self.pc.classify_package(name, rpi), want, name)
        rk = self.pc.load_platform_config("rockchip")
        for name, want in (("linux-image-6.1.84-8-rk2410", "bsp"), ("u-boot-rk2410", "bsp"), ("u-boot-menu", "os"),
                           ("radxa-firmware", "bsp"), ("radxa-sddm-theme", "os"), ("rtkit", "os"), ("task-kde-desktop", "os"),
                           ("librockchip-mpp1", "bsp"), ("linux-base", "os"), ("rtl8852bu-dkms", "bsp"), ("rtw89-dkms", "bsp"),
                           ("firmware-realtek", "os"), ("dthelper", "bsp"), ("libmraa2", "bsp"), ("libmraa-dev", "bsp")):
            self.assertEqual(self.pc.classify_package(name, rk), want, name)
        for plat in ("raspberrypi", "rockchip", "ai-nas"):        # dpkg 自己的資料庫檔歸 os（不屬於任何套件）
            self.assertEqual(self.pc.classify_path("var/lib/dpkg/info/bash.list", self.pc.load_platform_config(plat)), "os", plat)
        nas = self.pc.load_platform_config("ai-nas")
        for name, want in (("openmediavault", "bsp"), ("openmediavault-flashmemory", "bsp"), ("linux-image-amd64", "os")):
            self.assertEqual(self.pc.classify_package(name, nas), want, name)

    def test_new_project_needs_no_workflow_change(self):
        """M6：新增專案只要 new-project.sh＋填欄位；每個 WP7 平台開一個新專案都通過驗證，project-info 讀得出平台設定。"""
        tmp = tempfile.mkdtemp(prefix="wp7-newproj-")
        self.addCleanup(shutil.rmtree, tmp, True)
        for plat, resp, arch in (("raspberrypi", "customer", "arm64"), ("rockchip", "customer", "arm64"), ("ai-nas", "ours", "amd64")):
            name = "fourth-%s" % plat
            p = subprocess.run(["bash", os.path.join(ROOT, "pipeline", "new-project.sh"), name, "--platform", plat,
                                "--company-role", "manufacturer", "--os-responsibility", resp, "--product-name", "X", "--brand", "Y",
                                "--markets", "EU-ALL", "--support-until", "2031-12-31", "--projects-dir", tmp],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            d = os.path.join(tmp, name)
            info = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "project-info.py"), "--dir", d, "v0.1.0-dev1"],
                                  capture_output=True, text=True)
            self.assertEqual(info.returncode, 0, info.stdout + info.stderr)
            kv = dict(l.split("=", 1) for l in info.stdout.splitlines() if "=" in l)
            self.assertEqual((kv["PLATFORM"], kv["BUILD_MODE"], kv["ARCH"], kv["OS_RESPONSIBILITY"]), (plat, "none", arch, resp))


if __name__ == "__main__":
    unittest.main()
