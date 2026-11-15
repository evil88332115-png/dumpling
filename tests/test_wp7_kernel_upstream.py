"""WP7：廠商 BSP 核心的上游版本核對（pipeline/platforms/_shared/kernel_upstream.py，D-038）。合成資料、不連網。"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KU = os.path.join(ROOT, "pipeline", "platforms", "_shared", "kernel_upstream.py")
sys.path.insert(0, os.path.dirname(__file__))
from test_wp7_rockchip_raw import gpt_disk  # noqa: E402

REL = "6.1.84-8-rk2410"


@unittest.skipUnless(shutil.which("mkfs.ext4"), "需要 mkfs.ext4（e2fsprogs）")
class KernelUpstreamTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wp7-ku-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def image(self, modules=(REL,), config=True):
        tree = os.path.join(self.tmp, "tree")
        os.makedirs(os.path.join(tree, "etc")); os.makedirs(os.path.join(tree, "boot"))
        for m in modules:
            os.makedirs(os.path.join(tree, "usr", "lib", "modules", m))
        if config:
            with open(os.path.join(tree, "boot", "config-" + REL), "w") as f:
                f.write("CONFIG_NET=y\n")
        ext = os.path.join(self.tmp, "root.ext4")
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", tree, ext, "4M"], check=True, capture_output=True)
        with open(ext, "rb") as f:
            e = f.read()
        img = os.path.join(self.tmp, "disk.img")
        gpt_disk(img, 64 + len(e) // 512 + 40, [(64, len(e) // 512, "rootfs")], [(64, e)])
        return img

    def source(self, sub="84"):
        p = os.path.join(self.tmp, "src.tar.gz")
        mk = ("VERSION = 6\nPATCHLEVEL = 1\nSUBLEVEL = %s\nEXTRAVERSION =\n" % sub).encode()
        with tarfile.open(p, "w:gz") as t:
            for name, data in (("kernel-abc/README", b"x"), ("kernel-abc/Makefile", mk), ("kernel-abc/scripts/Makefile", b"SUBLEVEL = 1\n")):
                ti = tarfile.TarInfo(name); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
        return p

    def run_ku(self, img, src, upstream="6.1.84", release=REL):
        out = os.path.join(self.tmp, "ku.json")
        p = subprocess.run([sys.executable, "-I", KU, "check", "--image", img, "--source", src, "--upstream", upstream, "--release", release,
                            "--out", out], capture_output=True, text=True)
        doc = None
        if os.path.exists(out):
            with open(out, encoding="utf-8") as f:
                doc = json.load(f)
        return p.returncode, p.stdout.strip().splitlines()[-1], doc

    def test_both_sources_agree(self):
        rc, line, doc = self.run_ku(self.image(), self.source())
        self.assertEqual(rc, 0, line)
        self.assertTrue(doc["upstream_verified"])
        self.assertEqual(doc["sources"]["source_makefile"]["version"], "6.1.84")
        self.assertEqual(doc["sources"]["image_modules"]["upstream_from_release"], "6.1.84")
        self.assertEqual(doc["shipped_config"]["path"], "/boot/config-" + REL)
        self.assertEqual(doc["config_basis"], "shipped-config")

    def test_plus_suffix_release_like_raspberry_pi(self):
        # Raspberry Pi 的模組資料夾是 6.18.50+rpt-rpi-2712：上游版本取開頭的 X.Y.Z（只切 "-" 會讀成 6.18.50+rpt）
        rel = "6.1.84+rpt-rpi-2712"
        rc, line, doc = self.run_ku(self.image(modules=(rel,), config=False), self.source(), release=rel)
        self.assertEqual(doc["sources"]["image_modules"]["upstream_from_release"], "6.1.84")
        self.assertTrue(doc["upstream_verified"], line)
        self.assertEqual(rc, 3)                 # 只因為這個合成映像沒有 /boot/config-<release>

    def test_release_without_separator_is_not_read_as_upstream(self):
        rc, _line, doc = self.run_ku(self.image(modules=("6.1.84rc1",), config=False), self.source(), release="6.1.84rc1")
        self.assertIsNone(doc["sources"]["image_modules"]["upstream_from_release"])
        self.assertFalse(doc["upstream_verified"])
        self.assertEqual(rc, 3)

    def test_makefile_mismatch_is_gap_and_lists_both_values(self):
        rc, line, doc = self.run_ku(self.image(), self.source(sub="85"))
        self.assertEqual(rc, 3, line)
        self.assertFalse(doc["upstream_verified"])
        self.assertIn("6.1.85", line)
        self.assertIn("6.1.84", line)

    def test_missing_shipped_config_is_gap_but_version_verified(self):
        rc, line, doc = self.run_ku(self.image(config=False), self.source())
        self.assertEqual(rc, 3, line)
        self.assertTrue(doc["upstream_verified"])
        self.assertIsNone(doc["shipped_config"])
        self.assertIn("defconfig", line)

    def test_release_not_in_image_is_gap(self):
        rc, line, doc = self.run_ku(self.image(modules=("6.1.75-1-rk2410",)), self.source())
        self.assertEqual(rc, 3, line)
        self.assertFalse(doc["upstream_verified"])
        self.assertIn("6.1.75-1-rk2410", line)

    def test_bad_args(self):
        rc, _line, _doc = self.run_ku(self.image(), self.source(), upstream="6.1")
        self.assertEqual(rc, 64)


if __name__ == "__main__":
    unittest.main()
