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

def gpt_disk(path, total_sectors, parts, payloads=()):
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
    disk[2 * SECTOR:2 * SECTOR + len(entries)] = entries
    hdr = bytearray(struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x10000, 92, 0, 0, 1, total_sectors - 1, 34,
                                total_sectors - 34, os.urandom(16), 2, 128, 128, binascii.crc32(entries) & 0xFFFFFFFF))
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
                           ("alsa-utils", "os"), ("rpi-connect-lite", "os"), ("firmware-realtek", "os"), ("bluez", "os")):
            self.assertEqual(self.pc.classify_package(name, rpi), want, name)
        rk = self.pc.load_platform_config("rockchip")
        for name, want in (("linux-image-6.1.84-8-rk2410", "bsp"), ("u-boot-rk2410", "bsp"), ("u-boot-menu", "os"),
                           ("radxa-firmware", "bsp"), ("radxa-sddm-theme", "os"), ("rtkit", "os"), ("task-kde-desktop", "os"),
                           ("librockchip-mpp1", "bsp"), ("linux-base", "os")):
            self.assertEqual(self.pc.classify_package(name, rk), want, name)
        nas = self.pc.load_platform_config("ai-nas")
        for name, want in (("openmediavault", "bsp"), ("openmediavault-flashmemory", "bsp"), ("linux-image-amd64", "os")):
            self.assertEqual(self.pc.classify_package(name, nas), want, name)


if __name__ == "__main__":
    unittest.main()
