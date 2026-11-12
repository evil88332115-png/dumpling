"""Jetson 轉接器（M2 J 軌）的單元測試：不連網、不下載 BSP、不編譯。
涵蓋：安全解壓、元件 SHA-1 核對、patch 清單規則、刷機包組裝、標準答案比對、release-meta、project-info --matrix、精靈輸入與摘要。"""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
LIB = os.path.join(ROOT, "pipeline", "lib")
sys.path.insert(0, LIB)
import jetson_assemble as ja  # noqa: E402
import jetson_build as jb  # noqa: E402
import jetson_scan as js  # noqa: E402
import safe_extract as se  # noqa: E402


def add(t, name, data=b"", mode=0o644, typ=tarfile.REGTYPE, link=None):
    ti = tarfile.TarInfo(name)
    ti.type, ti.mode = typ, mode
    if typ == tarfile.REGTYPE:
        ti.size = len(data)
    if link is not None:
        ti.linkname = link
    t.addfile(ti, io.BytesIO(data) if typ == tarfile.REGTYPE else None)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dumpling-jetson-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def p(self, *a):
        return os.path.join(self.tmp, *a)

    def mktar(self, name, members, mode="w"):
        path = self.p(name)
        with tarfile.open(path, mode) as t:
            for m in members:
                add(t, *m[:2], **(m[2] if len(m) > 2 else {}))
        return path


class SafeExtract(Tmp):
    def test_good(self):
        a = self.mktar("a.tar", [("d", b"", {"typ": tarfile.DIRTYPE, "mode": 0o755}), ("d/f.txt", b"hi"), ("d/l", b"", {"typ": tarfile.SYMTYPE, "link": "f.txt"})])
        st = se.extract(a, self.p("out"))
        self.assertEqual(st["members"], 3)
        self.assertEqual(open(self.p("out", "d", "f.txt"), "rb").read(), b"hi")

    def test_bz2_stream(self):
        a = self.mktar("a.tbz2", [("x/y", b"1")], "w:bz2")
        self.assertEqual(se.extract(a, self.p("o"))["members"], 1)

    def test_rejects(self):
        cases = {
            "abs": [("/etc/x", b"1")],
            "dotdot": [("a/../../x", b"1")],
            "dev": [("n", b"", {"typ": tarfile.CHRTYPE})],
            "fifo": [("n", b"", {"typ": tarfile.FIFOTYPE})],
            "symabs": [("l", b"", {"typ": tarfile.SYMTYPE, "link": "/etc/passwd"})],
            "symup": [("l", b"", {"typ": tarfile.SYMTYPE, "link": "../../etc/passwd"})],
            "hard": [("l", b"", {"typ": tarfile.LNKTYPE, "link": "../x"})],
        }
        for k, members in cases.items():
            with self.subTest(k):
                a = self.mktar(k + ".tar", members)
                with self.assertRaises(se.UnsafeArchive):
                    se.extract(a, self.p("out-" + k))

    def test_nonempty_dest(self):
        a = self.mktar("a.tar", [("f", b"1")])
        os.makedirs(self.p("d"))
        open(self.p("d", "keep"), "w").close()
        with self.assertRaises(se.UnsafeArchive):
            se.extract(a, self.p("d"))
        self.assertEqual(se.extract(a, self.p("d"), allow_nonempty=True)["members"], 1)

    def test_cli_exit_codes(self):
        a = self.mktar("bad.tar", [("/abs", b"1")])
        r = subprocess.run([sys.executable, "-I", os.path.join(LIB, "safe_extract.py"), a, self.p("o")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("拒絕", r.stdout)

    def test_setuid_cleared(self):
        a = self.mktar("a.tar", [("f", b"1", {"mode": 0o4755})])
        se.extract(a, self.p("o"))
        self.assertEqual(os.stat(self.p("o", "f")).st_mode & 0o7000, 0)


class Components(Tmp):
    def test_check(self):
        os.makedirs(self.p("c"))
        data = {"kernel_src.tbz2": b"k", "oot.tbz2": b"o", "other.tbz2": b"x"}
        lines = []
        for n, d in data.items():
            open(self.p("c", n), "wb").write(d)
            lines.append("%s *%s" % (hashlib.sha1(d).hexdigest(), n))
        lines.append("%s *public_sources_sha.txt" % ("0" * 40))
        lines.append("%s *kernel_src.tbz2.sha1sum" % ("1" * 40))
        txt = "\n".join(lines)
        r = jb.check_components(txt, self.p("c"), ["kernel_src.tbz2", "oot.tbz2"])
        self.assertEqual((r["checked"], r["matched"]), (3, 3))

    def test_mismatch_and_missing(self):
        os.makedirs(self.p("c"))
        open(self.p("c", "a.tbz2"), "wb").write(b"a")
        txt = "%s *a.tbz2\n" % ("2" * 40)
        with self.assertRaises(jb.BuildError):
            jb.check_components(txt, self.p("c"))
        txt = "%s *a.tbz2\n" % hashlib.sha1(b"a").hexdigest()
        with self.assertRaises(jb.BuildError):
            jb.check_components(txt, self.p("c"), ["b.tbz2"])
        with self.assertRaises(jb.BuildError):
            jb.check_components("", self.p("c"))


class Patches(Tmp):
    def project(self, patches_yaml, files=()):
        d = self.p("projects", "demo")
        os.makedirs(os.path.join(d, "patches"))
        for f in files:
            open(os.path.join(d, "patches", f), "w").write("--- a/x\n+++ b/x\n")
        open(os.path.join(d, "sources.yml"), "w").write(
            "schema: 1\nreleases:\n  v1.0:\n    platform_params:\n      patches: %s\n    files:\n      - name: a.bin\n        url: https://example.com/a.bin\n"
            "        sha256: %s\n        role: bsp\n" % (patches_yaml, "a" * 64))
        return d

    def test_list_and_default_dir(self):
        d = self.project("[0001-a.patch, {file: 0002-b.patch, dir: nvidia-oot}]", ["0001-a.patch", "0002-b.patch", "0003-unused.patch"])
        got = jb.release_patches(d, "v1.0")
        self.assertEqual([g[0] for g in got], ["kernel/kernel-noble", "nvidia-oot"])
        self.assertEqual(len(got[0][2]), 64)
        self.assertEqual(jb.unlisted_patches(d), ["0003-unused.patch"])

    def test_none(self):
        d = self.project("[]")
        self.assertEqual(jb.release_patches(d, "v1.0"), [])

    def test_bad(self):
        for y, files in (("[../evil.patch]", []), ("[missing.patch]", []), ("[{file: a.patch, dir: ../x}]", ["a.patch"]),
                         ("[{file: a.patch, dir: /abs}]", ["a.patch"]), ("[a.patch, a.patch]", ["a.patch"]), ("[{file: a.patch, extra: 1}]", ["a.patch"])):
            with self.subTest(y):
                d = self.p("projects", "demo")
                shutil.rmtree(d, ignore_errors=True)
                d = self.project(y, files)
                with self.assertRaises(jb.BuildError):
                    jb.release_patches(d, "v1.0")

    def test_real_project_patches_listed(self):
        """專案裡每個 .patch 都有被某個版本列出（沒列的不會套用），列出的檔案都存在。"""
        d = os.path.join(ROOT, "projects", "orin-nano-demo")
        self.assertEqual(jb.unlisted_patches(d), [])
        for ver in ("v39.2.0-demo1", "v39.2.1-demo1"):
            jb.release_patches(d, ver)


class Assemble(Tmp):
    def setUp(self):
        super().setUp()
        self.bsp = self.mktar("bsp.tbz2", [
            ("Linux_for_Tegra/", b"", {"typ": tarfile.DIRTYPE, "mode": 0o755}),
            ("Linux_for_Tegra/flash.sh", b"#!/bin/sh\n", {"mode": 0o755}),
            ("Linux_for_Tegra/kernel/Image", b"NVIDIA-IMAGE"),
            ("Linux_for_Tegra/kernel/dtb/a.dtb", b"nv-a"),
            ("Linux_for_Tegra/kernel/dtb/b.dtb", b"nv-b"),
            ("Linux_for_Tegra/kernel/dtb/x.dtbo", b"nv-x"),
            ("Linux_for_Tegra/rootfs/README.txt", b"empty"),
        ], "w:bz2")
        self.rfs = self.mktar("base.tar", [
            ("./", b"", {"typ": tarfile.DIRTYPE, "mode": 0o755}),
            ("./etc/os-release", b"ubuntu"),
            ("./lib", b"", {"typ": tarfile.SYMTYPE, "link": "usr/lib"}),
            ("./usr/lib/modules/6.8.12-1021-tegra/kernel/drivers/old.ko", b"nv-old"),
            ("./usr/lib/modules/6.8.12-1021-tegra/updates/nv.ko", b"nv-oot"),
            ("./usr/lib/modules/6.8.12-1021-tegra/modules.dep", b""),
            ("./boot/Image", b"NVIDIA-IMAGE"),
            ("./boot/extlinux/extlinux.conf", b"LINUX /boot/Image"),
            ("./bin/hl", b"", {"typ": tarfile.LNKTYPE, "link": "./etc/os-release"}),
        ])
        d = self.p("deliver")
        for rel, data in (("kernel/kernel-noble/arch/arm64/boot/Image", b"CI-IMAGE"), ("kernel/kernel-noble/drivers/net/x.ko", b"ci-x"),
                          ("nvidia-oot/drivers/y/y.ko", b"ci-y"), ("kernel/kernel-noble/modules.order", b"kernel/drivers/net/x.ko\n"),
                          ("kernel/kernel-noble/.config", b"CONFIG_X=y\n"), ("kernel/kernel-noble/Makefile", b"VERSION = 6\n"),
                          ("kernel-devicetree/a.dtb", b"ci-a"), ("one/b.dtb", b"ci-b1"), ("two/b.dtb", b"ci-b2")):
            os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
            open(os.path.join(d, rel), "wb").write(data)
        self.deliver = d

    def run_it(self):
        out = self.p("pkg.tar")
        rep = ja.assemble(self.bsp, self.rfs, self.deliver, "6.8.12-ci", out)
        with tarfile.open(out) as t:
            names = {m.name: m for m in t.getmembers()}
            data = {n: t.extractfile(m).read() for n, m in names.items() if m.isreg()}
        return rep, names, data

    def test_kernel_and_modules_replaced(self):
        rep, names, data = self.run_it()
        self.assertEqual(data["Linux_for_Tegra/kernel/Image"], b"CI-IMAGE")
        self.assertEqual(data["Linux_for_Tegra/rootfs/boot/Image"], b"CI-IMAGE")
        self.assertTrue(rep["kernel_image_replaced"] and rep["rootfs_boot_image_replaced"])
        self.assertEqual(data["Linux_for_Tegra/kernel/dtb/a.dtb"], b"ci-a")
        self.assertEqual(data["Linux_for_Tegra/kernel/dtb/b.dtb"], b"nv-b")   # CI 有兩個同名 → 不換
        self.assertEqual(data["Linux_for_Tegra/kernel/dtb/x.dtbo"], b"nv-x")
        self.assertEqual(rep["dtb_replaced"], ["a.dtb"])
        base = "Linux_for_Tegra/rootfs/usr/lib/modules/6.8.12-ci/"
        self.assertEqual(data[base + "kernel/drivers/net/x.ko"], b"ci-x")
        self.assertEqual(data[base + "updates/nvidia-oot/drivers/y/y.ko"], b"ci-y")
        self.assertIn(base + "modules.order", data)
        self.assertEqual(data[base + "build/.config"], b"CONFIG_X=y\n")      # 映像裡要找得到出貨核心的 .config 與 Makefile
        self.assertEqual(data[base + "build/Makefile"], b"VERSION = 6\n")
        self.assertFalse([n for n in names if "6.8.12-1021-tegra" in n])     # NVIDIA 的模組目錄整個不在
        self.assertEqual((rep["nvidia_modules_dropped"], rep["ci_modules_in_tree"], rep["ci_modules_out_of_tree"]), (2, 1, 1))

    def test_rootfs_kept_and_bsp_rootfs_dropped(self):
        rep, names, data = self.run_it()
        self.assertEqual(data["Linux_for_Tegra/rootfs/etc/os-release"], b"ubuntu")
        self.assertNotIn("Linux_for_Tegra/rootfs/README.txt", names)
        self.assertEqual(rep["bsp_rootfs_members_dropped"], 1)
        self.assertEqual(names["Linux_for_Tegra/rootfs/lib"].linkname, "usr/lib")
        self.assertEqual(names["Linux_for_Tegra/rootfs/bin/hl"].linkname, "Linux_for_Tegra/rootfs/etc/os-release")
        self.assertIn("Linux_for_Tegra/flash.sh", data)

    def test_long_paths_keep_the_prefix(self):
        """PAX 格式的長路徑成員（>100 字元）帶著舊的 path 標頭：改名後一定要寫在 Linux_for_Tegra/rootfs/ 底下，不能漏在最上層。"""
        long_dir = "./usr/share/" + "/".join(["averyveryverylongdirectoryname%d" % i for i in range(5)])
        rfs = self.p("pax.tar")
        with tarfile.open(rfs, "w", format=tarfile.PAX_FORMAT) as t:
            add(t, long_dir + "/file.txt", b"long")
            add(t, "./usr/share/short", b"s")
            add(t, long_dir + "/hl", b"", typ=tarfile.LNKTYPE, link=long_dir + "/file.txt")
        out = self.p("o.tar")
        ja.assemble(self.bsp, rfs, self.deliver, "6.8.12-ci", out)
        with tarfile.open(out) as t:
            names = t.getnames()
            hl = [m for m in t.getmembers() if m.name.endswith("/hl")][0]
        stray = [n for n in names if n != "Linux_for_Tegra" and not n.startswith("Linux_for_Tegra/")]
        self.assertEqual(stray, [])
        self.assertIn("Linux_for_Tegra/rootfs/" + long_dir[2:] + "/file.txt", names)
        self.assertEqual(hl.linkname, "Linux_for_Tegra/rootfs/" + long_dir[2:] + "/file.txt")

    def test_owners_from_dpkg_lists(self):
        rfs = self.mktar("own.tar", [("./var/lib/dpkg/info/nvidia-l4t-core.list", b"/.\n/usr\n/usr/lib/nv/a.so\n/lib/b.so\n"),
                                     ("./var/lib/dpkg/info/libfoo:arm64.list", b"/usr/lib/f.so\n"), ("./var/lib/dpkg/info/other.md5sums", b"x")])
        out = self.p("own.json")
        rep = ja.assemble(self.bsp, rfs, self.deliver, "6.8.12-ci", self.p("o.tar"), owners_out=out)
        d = json.load(open(out))
        self.assertEqual(d["/usr/lib/nv/a.so"], "nvidia-l4t-core")
        self.assertEqual(d["/usr/lib/f.so"], "libfoo")
        self.assertNotIn("/.", d)
        self.assertEqual(rep["owners"]["paths"], 4)
        with tarfile.open(self.p("o.tar")) as t:     # .list 照常寫進刷機包
            self.assertIn("Linux_for_Tegra/rootfs/var/lib/dpkg/info/libfoo:arm64.list", t.getnames())

    def test_dirs_exist_for_every_file(self):
        rep, names, data = self.run_it()
        dirs = {n.rstrip("/") for n, m in names.items() if m.isdir()}
        for n in data:
            if n.startswith("Linux_for_Tegra/rootfs/usr/lib/modules/6.8.12-ci/"):
                self.assertIn(os.path.dirname(n), dirs)

    def test_errors(self):
        with self.assertRaises(ja.AssembleError):
            ja.assemble(self.bsp, self.rfs, self.deliver, "../evil", self.p("o.tar"))
        os.remove(os.path.join(self.deliver, "kernel/kernel-noble/arch/arm64/boot/Image"))
        with self.assertRaises(ja.AssembleError):
            ja.assemble(self.bsp, self.rfs, self.deliver, "6.8.12-ci", self.p("o.tar"))

    def test_rootfs_absolute_symlinks_are_kept(self):
        rfs = self.mktar("abs.tar", [("./etc/fonts/x.conf", b"", {"typ": tarfile.SYMTYPE, "link": "/usr/share/fontconfig/conf.avail/x.conf"}),
                                     ("./etc/up", b"", {"typ": tarfile.SYMTYPE, "link": "../../x"})])
        rep = ja.assemble(self.bsp, rfs, self.deliver, "6.8.12-ci", self.p("o.tar"))
        with tarfile.open(self.p("o.tar")) as t:
            names = {m.name: m for m in t.getmembers()}
        self.assertEqual(names["Linux_for_Tegra/rootfs/etc/fonts/x.conf"].linkname, "/usr/share/fontconfig/conf.avail/x.conf")
        self.assertEqual(rep["rootfs_members"], 2)
        # 解壓到主機的 safe_extract 仍然拒絕絕對連結
        a = self.mktar("abs2.tar", [("l", b"", {"typ": tarfile.SYMTYPE, "link": "/etc/passwd"})])
        with self.assertRaises(se.UnsafeArchive):
            se.extract(a, self.p("x"))

    def test_unsafe_rootfs_member_aborts(self):
        bad = self.mktar("bad.tar", [("./etc/x", b"1"), ("../evil", b"1")])
        with self.assertRaises(ja.AssembleError):
            ja.assemble(self.bsp, bad, self.deliver, "6.8.12-ci", self.p("o.tar"))

    def test_unsafe_bsp_member_skipped(self):
        bsp = self.mktar("bsp2.tbz2", [("Linux_for_Tegra/kernel/Image", b"x"), ("Linux_for_Tegra/dev", b"", {"typ": tarfile.CHRTYPE}),
                                       ("/abs/x", b"1"), ("other/x", b"1")], "w:bz2")
        rep = ja.assemble(bsp, self.rfs, self.deliver, "6.8.12-ci", self.p("o.tar"))
        self.assertEqual(len(rep["bsp_skipped"]), 3)


class CheckExpected(Tmp):
    def run_cli(self, expected, actual):
        e, a = self.p("e.json"), self.p("a.json")
        json.dump(expected, open(e, "w"))
        json.dump(actual, open(a, "w"))
        return subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "check-expected.py"), e, a], capture_output=True, text=True)

    def test_pass_and_fail(self):
        exp = {"schema": 1, "project": "p", "checks": {"a.b": {"min": 10, "max": 20}, "s": {"equals": "OK"}, "t": {"in": ["OK", "GAP"]}}}
        ok = self.run_cli(exp, {"project": "p", "a": {"b": 15}, "s": "OK", "t": "GAP"})
        self.assertEqual(ok.returncode, 0, ok.stdout)
        self.assertIn("expected: OK", ok.stdout)
        bad = self.run_cli(exp, {"project": "p", "a": {"b": 25}, "s": "GAP", "t": "NOT_RUN"})
        self.assertEqual(bad.returncode, 1)
        self.assertIn("高於上限", bad.stdout)
        self.assertIn("應為 'OK'", bad.stdout)
        self.assertIn("expected: FAIL（3 項不符", bad.stdout)

    def test_missing_path_and_null_fail(self):
        exp = {"schema": 1, "checks": {"x.y": {"min": 0}, "z": {"equals": "OK"}}}
        r = self.run_cli(exp, {"z": None})
        self.assertEqual(r.returncode, 1)
        self.assertIn("沒有 x.y", r.stdout)
        self.assertIn("應為 'OK'，實際 None", r.stdout)

    def test_project_mismatch_and_bad_format(self):
        r = self.run_cli({"schema": 1, "project": "p", "checks": {"a": {"equals": 1}}}, {"project": "q", "a": 1})
        self.assertEqual(r.returncode, 1)
        r = self.run_cli({"schema": 2, "checks": {}}, {})
        self.assertEqual(r.returncode, 64)
        r = self.run_cli({"schema": 1, "checks": {"a": {}}}, {"a": 1})
        self.assertEqual(r.returncode, 1)

    def test_bool_is_not_number(self):
        r = self.run_cli({"schema": 1, "checks": {"a": {"min": 0}}}, {"a": True})
        self.assertEqual(r.returncode, 1)


class ExpectedFiles(unittest.TestCase):
    def test_every_expected_file_is_well_formed_and_matches_a_real_release(self):
        base = os.path.join(ROOT, "tests", "expected")
        found = 0
        for proj in sorted(os.listdir(base)):
            sources = jb.pc.load_sources(os.path.join(ROOT, "projects", proj, "sources.yml"))
            for fn in sorted(os.listdir(os.path.join(base, proj))):
                with open(os.path.join(base, proj, fn), encoding="utf-8") as fh:
                    d = json.load(fh)
                found += 1
                self.assertEqual((d["schema"], d["project"], d["version"] + ".json"), (1, proj, fn))
                self.assertIn(d["version"], sources["releases"])
                self.assertTrue(d["checks"])
                for path, spec in d["checks"].items():
                    self.assertTrue({"equals", "min", "max", "in"} & set(spec), path)
                    self.assertTrue(spec.get("reason"), "%s 要寫理由（為什麼是這個值或範圍）" % path)
                    if "min" in spec and "max" in spec:
                        self.assertLessEqual(spec["min"], spec["max"], path)
                # 驗收項目一定在：建置紀錄 OK、C-kernel-boot OK、上游比對的修改檔數
                for must in ("build_record_status", "kernel_boot", "upstream_source.modified"):
                    self.assertIn(must, d["checks"])
        self.assertGreaterEqual(found, 2)

    def test_patch_versions_expect_one_modified_file_and_the_others_zero(self):
        base = os.path.join(ROOT, "tests", "expected", "orin-nano-demo")
        for ver in ("v39.2.0-demo1", "v39.2.1-demo1"):
            d = json.load(open(os.path.join(base, ver + ".json"), encoding="utf-8"))
            patched = bool(jb.release_patches(os.path.join(ROOT, "projects", "orin-nano-demo"), ver))
            self.assertEqual(d["checks"]["upstream_source.modified"]["equals"], len(jb.release_patches(os.path.join(ROOT, "projects", "orin-nano-demo"), ver)) and 1)
            self.assertEqual(patched, ver == "v39.2.1-demo1")


class ReleaseMeta(Tmp):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "release-meta.py"), *args], capture_output=True, text=True)

    def test_fields(self):
        out = self.p("m.json")
        r = self.run_cli("--project", "orin-nano-demo", "--version", "v39.2.1-demo1", "--commit", "a" * 40, "--run-id", "42",
                         "--built-at", "2026-11-12T00:00:00Z", "--out", out)
        self.assertEqual(r.returncode, 0, r.stdout)
        d = json.load(open(out))
        self.assertEqual(set(d), {"schema", "project", "version", "tag", "status", "platform", "os_responsibility", "commit", "built_at", "workflow_run"})
        self.assertEqual((d["tag"], d["platform"], d["workflow_run"]), ("orin-nano-demo/v39.2.1-demo1", "jetson", "42"))
        self.assertIn(d["status"], ("shipped", "development"))

    def test_dev_tag_and_bad_input(self):
        out = self.p("m.json")
        r = self.run_cli("--project", "orin-nano-demo", "--version", "v39.2.1-demo1", "--tag", "dev/orin-nano-demo", "--commit", "b" * 40, "--run-id", "1", "--out", out)
        self.assertEqual(json.load(open(out))["tag"], "dev/orin-nano-demo")
        for bad in (["--commit", "xyz"], ["--run-id", "abc"], ["--version", "v9.9"], ["--project", "../x"], ["--built-at", "yesterday"]):
            args = {"--project": "orin-nano-demo", "--version": "v39.2.1-demo1", "--commit": "a" * 40, "--run-id": "1", "--out": self.p("x.json")}
            args[bad[0]] = bad[1]
            r = self.run_cli(*[x for kv in args.items() for x in kv])
            self.assertEqual(r.returncode, 1, bad)
            self.assertFalse(os.path.exists(self.p("x.json")))


class ProjectInfoMatrix(unittest.TestCase):
    def test_matrix(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "project-info.py"), "--matrix"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        m = json.loads(r.stdout)
        self.assertIn({"project": "orin-nano-demo", "version": "v39.2.1-demo1"}, m)
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "project-info.py"), "--matrix", "nope"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)


class ScanHelpers(Tmp):
    def test_rewrite_inputs(self):
        src = os.path.join(ROOT, "projects", "orin-nano-demo", "CRA", "Config")
        js.rewrite_inputs(src, self.p("cfg"), "39.2.1")
        d = json.load(open(self.p("cfg", "inputs.json")))
        self.assertEqual(d["upstream_set"], "jetson-r39.2.1")
        txt = open(self.p("cfg", "inputs.json"), encoding="utf-8").read()
        self.assertNotIn("39.2.0", txt)
        self.assertIn("r39.2.1", txt)
        # 原本的設定包沒被動到
        self.assertEqual(json.load(open(os.path.join(src, "inputs.json")))["upstream_set"], "jetson-r39.2.0")
        with self.assertRaises(ValueError):
            js.rewrite_inputs(src, self.p("cfg"), "39.2.1")
        with self.assertRaises(ValueError):
            js.rewrite_inputs(src, self.p("cfg2"), "39;rm")

    def test_site_config_keys_accepted_by_wizard(self):
        js.site_config(self.p("w.json"), "/r", "/w", "/o", "/p/pilot.env", "/g", "jetson-r39.2.1", "/ps.tbz2", "/bsp.tbz2", "/usr/bin/python3")
        d = json.load(open(self.p("w.json")))
        src = open(os.path.join(ROOT, "tools", "wizard", "cra-scan.py"), encoding="utf-8").read()
        site_keys = eval(src.split("SITE_KEYS = ", 1)[1].split("\n", 1)[0])
        self.assertTrue(set(d) <= site_keys, set(d) - site_keys)
        self.assertEqual(d["upstream"]["jetson-r39.2.1"], {"public_sources": "/ps.tbz2", "bsp": "/bsp.tbz2"})

    def test_vuln_metrics(self):
        rows = {"rows": [{"id": "CVE-1", "tier": "p1", "layer": "bsp"}, {"id": "CVE-1", "tier": "p1", "layer": "bsp"},
                         {"id": "CVE-2", "tier": "p1", "layer": "os"}, {"id": "CVE-3", "tier": "p3", "layer": "unknown"},
                         {"id": "CVE-4", "tier": "p1", "layer": "unknown"}]}
        m = js.vuln_metrics(rows)
        self.assertEqual((m["rows_total"], m["cves_total"], m["p1_rows"]), (5, 4, 2))
        self.assertIsNone(js.vuln_metrics({"nope": 1}))
        self.assertIsNone(js.vuln_metrics(None))

    def test_sbom_layer_counts(self):
        sb = {"components": [
            {"purl": "pkg:deb/ubuntu/a@1", "properties": [{"name": "dumpling:layer", "value": "os"}]},
            {"purl": "pkg:deb/ubuntu/nvidia-l4t-core@1", "properties": [{"name": "dumpling:layer", "value": "bsp"}]},
            {"purl": "pkg:golang/x@1", "properties": [{"name": "dumpling:layer", "value": "unknown"}]}]}
        json.dump(sb, open(self.p("s.json"), "w"))
        n, deb = js.sbom_layer_counts(self.p("s.json"))
        self.assertEqual(n, {"os": 1, "bsp": 1, "unknown": 1})
        self.assertEqual(deb, {"os": 1, "bsp": 1})
        self.assertEqual(js.sbom_layer_counts(self.p("missing.json")), (None, None))

    def test_newest_dir(self):
        for n in ("p-v-20261112-1000", "p-v-20261112-1100", "q-v-1"):
            os.makedirs(self.p(n))
        self.assertTrue(js.newest_dir(self.tmp, "p-v-").endswith("1100"))
        self.assertIsNone(js.newest_dir(self.tmp, "zzz"))

    def test_collect_with_fake_run(self):
        w = self.p("w0")
        rows = {"schema": "sca-center-vulnerability-rows/1", "row_count": 1, "rows": [{"id": "CVE-1", "tier": "p1", "layer": "bsp"}]}
        for rel, content in (("scan/rootfs/scan/status.tsv", "stage\tstatus\tdetail\nC-kernel-boot\tOK\tsame\n"),
                             ("scan/rootfs/scan/scan/kernel-config.json", json.dumps({"kernel": {"build_record": {"status": "OK"}}})),
                             ("scan/rootfs/upstream-baseline-source.json", json.dumps({"status": "ATTENTION", "totals": {"modified": 1, "ours_only": 0, "same": 9, "upstream_only": 0},
                                                                                       "components": [{"modified": [{"path": "kernel/kernel-noble/net/x.c"}]}]})),
                             ("cra-project/CRA/Reports/vulnerability-rows.json", json.dumps(rows)),
                             ("報告/交給PM/VEX/vex.cdx.json", "{}"), ("報告/交給PM/漏洞清單.xlsx", "x"), ("報告/給RD/P1判斷表.xlsx", "y")):
            os.makedirs(os.path.dirname(os.path.join(w, rel)), exist_ok=True)
            open(os.path.join(w, rel), "w", encoding="utf-8").write(content)
        lay = self.p("layers")
        os.makedirs(lay)
        json.dump({"platform": "jetson", "os_responsibility": "customer", "components_total": 3, "components": {"bsp": 1, "os": 1, "unknown": 1, "host-tool": 0},
                   "unknown": {"by_purl_type": {"golang": 1}}, "gaps": []}, open(os.path.join(lay, "layers.json"), "w"))
        for n in ("sbom.product.cdx.json", "sbom.bsp.cdx.json", "sbom.os.cdx.json"):
            json.dump({"components": []}, open(os.path.join(lay, n), "w"))
        json.dump({"kernel_release": "6.8.12-ci", "image_sha256": "a" * 64, "build_record_sha256": "b" * 64, "patches": []}, open(self.p("build.json"), "w"))
        json.dump({"package_sha256": "c" * 64}, open(self.p("assemble.json"), "w"))
        args = js.argparse.Namespace(out=self.p("rel"), project="p", version="v1", layers=lay, build_json=self.p("build.json"), assemble_json=self.p("assemble.json"),
                                     scan_json=self.p("scan.json"), run=["=" + w], build_record="/x/BuildRecord-p-v1.tar.gz", project_dir=os.path.join(ROOT, "projects", "orin-nano-demo"), official=False)
        scan = js.collect(args)
        self.assertEqual(scan["build_record_status"], "OK")
        self.assertEqual(scan["kernel_boot"], "OK")
        self.assertEqual(scan["upstream_source"]["modified"], 1)
        self.assertEqual(scan["upstream_source"]["modified_files"], ["kernel/kernel-noble/net/x.c"])
        self.assertEqual(scan["vulnerabilities"]["full"]["p1_rows"], 1)
        names = {l.split("\t")[0] for l in open(self.p("rel", "manifest.tsv"), encoding="utf-8").read().splitlines()}
        for want in ("sbom-p-v1.cdx.json", "sbom-p-v1-bsp.cdx.json", "sbom-p-v1-os.cdx.json", "layers.json", "report-p-v1.zip", "vex-p-v1.cdx.json",
                     "vuln-list-p-v1.xlsx", "p1-table-p-v1.xlsx", "build-record-p-v1.json", "scan-summary-p-v1.json"):
            self.assertIn(want, names)
        for n in names:
            self.assertTrue(n.isascii(), n)       # 附件檔名一律 ASCII（GitHub 會改掉非 ASCII 字元）
        self.assertTrue(os.path.isfile(self.p("rel", "notes.md")))


if __name__ == "__main__":
    unittest.main()
