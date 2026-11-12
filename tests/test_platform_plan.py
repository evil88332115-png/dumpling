"""workflow 的規劃值（platform.yml 的 build.mode／runner／apt、scan.runner／apt、arch → pipeline/project-info.py 的輸出）與檔案 role 的單元測試。不連網。"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
import project_config as pc  # noqa: E402

INFO = os.path.join(ROOT, "pipeline", "project-info.py")


def info(*args, env=None):
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run([sys.executable, "-I", INFO, *args], capture_output=True, text=True, env=e)
    kv = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)
    return r, kv


class Plan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dumpling-plan-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def project(self, name, platform):
        d = os.path.join(self.tmp, name)
        shutil.copytree(os.path.join(ROOT, "projects", "orin-nano-demo"), d)
        p = os.path.join(d, "project.yml")
        t = open(p, encoding="utf-8").read().replace('platform: "jetson"', 'platform: "%s"' % platform)
        open(p, "w", encoding="utf-8").write(t)
        return d

    def test_compile_platform_jetson(self):
        r, kv = info("orin-nano-demo/v39.2.1-demo1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual((kv["BUILD_MODE"], kv["BUILD_RUNNER"], kv["SCAN_RUNNER"], kv["ARCH"]), ("compile", "ubuntu-24.04-arm", "ubuntu-24.04", "arm64"))
        apt = kv["BUILD_APT"].split()
        for need in ("build-essential", "bc", "bison", "flex", "libssl-dev", "libelf-dev", "rsync", "dwarves", "cpio", "kmod", "device-tree-compiler",
                     "zstd", "lz4", "libncurses-dev", "pkg-config", "perl", "patch"):
            self.assertIn(need, apt)
        self.assertEqual(kv["SCAN_APT"], "zstd lbzip2")

    def test_none_platform_example_with_defaults(self):
        d = self.project("plan-none", "example")
        r, kv = info("--dir", d, "v39.2.1-demo1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(kv["BUILD_MODE"], "none")
        # 沒寫的欄位用預設值：build.runner＝arm64、scan.runner＝amd64、arch＝arm64；apt 清單是空的
        self.assertEqual((kv["BUILD_RUNNER"], kv["SCAN_RUNNER"], kv["ARCH"], kv["BUILD_APT"], kv["SCAN_APT"]), ("ubuntu-24.04-arm", "ubuntu-24.04", "arm64", "", ""))
        self.assertEqual(kv["PLATFORM"], "example")

    def test_overrides_and_scan_runner_does_not_follow_arch(self):
        base = pc.load_platform_config("example")
        cfg = copy.deepcopy(base)
        cfg.update(arch="amd64")
        cfg["build"] = {"mode": "compile", "runner": "amd64", "apt": ["make", "gcc"]}
        cfg["scan"] = dict(cfg.get("scan") or {}, apt=["zstd"])
        self.assertEqual(pc.validate_platform_config(cfg, "example"), [])
        plan = pc.platform_plan(cfg)
        self.assertEqual(plan, {"build_mode": "compile", "build_runner": "ubuntu-24.04", "build_apt": ["make", "gcc"],
                                "scan_runner": "ubuntu-24.04", "scan_apt": ["zstd"], "arch": "amd64"})
        cfg["arch"] = "arm64"
        cfg["scan"]["runner"] = "arm64"
        self.assertEqual(pc.platform_plan(cfg)["scan_runner"], "ubuntu-24.04-arm")        # 只有明確寫才換；不看 arch
        cfg["scan"].pop("runner")
        cfg["arch"] = "amd64"
        self.assertEqual(pc.platform_plan(cfg)["scan_runner"], "ubuntu-24.04")             # arch 是 amd64 也一樣是預設的 amd64
        cfg["arch"] = "arm64"
        self.assertEqual(pc.platform_plan(cfg)["scan_runner"], "ubuntu-24.04")             # arch 是 arm64，scan 仍然在 amd64（不跟 arch）

    def test_bad_platform_fields_are_rejected(self):
        base = pc.load_platform_config("example")
        for mut in (lambda c: c.update(arch="riscv"), lambda c: c["build"].update(runner="x86"), lambda c: c["build"].update(apt="make"),
                    lambda c: c["build"].update(apt=["make; rm -rf /"]), lambda c: c["build"].update(apt=["Make"]), lambda c: c["build"].update(extra=1),
                    lambda c: c["scan"].update(runner="windows"), lambda c: c["scan"].update(apt=[1]), lambda c: c["scan"].update(bogus=1)):
            cfg = copy.deepcopy(base)
            mut(cfg)
            self.assertTrue(pc.validate_platform_config(cfg, "example"), mut)

    def test_matrix_unchanged(self):
        r = subprocess.run([sys.executable, "-I", INFO, "--matrix"], capture_output=True, text=True)
        self.assertIn({"project": "orin-nano-demo", "version": "v39.2.1-demo1"}, json.loads(r.stdout))


class Roles(unittest.TestCase):
    def doc(self, role):
        return {"schema": 1, "releases": {"v1": {"files": [{"name": "a.info", "url": "https://example.com/a.info", "sha256": "a" * 64, "role": role}]}}}

    def test_metadata_role_is_accepted_and_unknown_is_rejected(self):
        self.assertIn("metadata", pc.FILE_ROLES)
        self.assertEqual(pc.validate_sources(self.doc("metadata")), [])
        for r in pc.FILE_ROLES:
            self.assertEqual(pc.validate_sources(self.doc(r)), [], r)
        self.assertTrue(pc.validate_sources(self.doc("zzz")))

    def test_no_adapter_code_selects_files_by_excluding_a_role(self):
        """metadata 不會被當成掃描輸入：Jetson 轉接器只依 role 明確挑 bsp 與 rootfs（不用「不是某 role 的都算」）。"""
        for f in ("assemble.sh", "scan.sh", "build.sh"):
            t = open(os.path.join(ROOT, "pipeline", "platforms", "jetson", f), encoding="utf-8").read()
            self.assertNotIn("!= metadata", t)
            self.assertNotIn("-ne metadata", t)
        t = open(os.path.join(ROOT, "pipeline", "platforms", "jetson", "assemble.sh"), encoding="utf-8").read()
        self.assertIn("bsp) bsp=$name;; rootfs) rfs=$name;;", t)


if __name__ == "__main__":
    unittest.main()
