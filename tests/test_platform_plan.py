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
                                "scan_runner": "ubuntu-24.04", "scan_apt": ["zstd"], "scan_tools": "sbom-only", "arch": "amd64"})
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

    def test_dispatcher_passes_arch_to_the_adapter(self):
        """platform.sh 把 platform.yml 的 arch 放進 DUMPLING_ARCH（沒寫是 arm64）；scan 的 docker import 用它。"""
        for arch, want in (("amd64", "amd64"), (None, "arm64")):
            plats = os.path.join(self.tmp, "plats-%s" % arch)
            shutil.copytree(os.path.join(ROOT, "pipeline", "platforms", "example"), os.path.join(plats, "archp"))
            y = os.path.join(plats, "archp", "platform.yml")
            t = open(y, encoding="utf-8").read().replace("platform: example", "platform: archp")
            t = "\n".join(l for l in t.splitlines() if not l.startswith("arch:"))
            if arch:
                t += "\narch: %s\n" % arch
            open(y, "w", encoding="utf-8").write(t)
            open(os.path.join(plats, "archp", "build.sh"), "w").write('#!/usr/bin/env bash\necho "arch=$DUMPLING_ARCH"\necho "build: OK（測試）"\n')
            d = self.project("plan-arch-%s" % (arch or "default"), "archp")
            env = dict(os.environ, DUMPLING_PLATFORMS_DIR=plats, DUMPLING_OUT_BASE=os.path.join(self.tmp, "out"))
            r = subprocess.run(["bash", os.path.join(ROOT, "pipeline", "platform.sh"), "build", d, "v39.2.1-demo1"], capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("arch=%s" % want, r.stdout)

    def platforms_with_scan_tools(self, value):
        plats = os.path.join(self.tmp, "plats-tools-%s" % value)
        shutil.copytree(os.path.join(ROOT, "pipeline", "platforms", "example"), os.path.join(plats, "toolp"))
        y = os.path.join(plats, "toolp", "platform.yml")
        t = open(y, encoding="utf-8").read().replace("platform: example", "platform: toolp")
        import re
        t = re.sub(r"\n  tools: [^\n#]*", "", t, count=1)             # 範例平台自己寫了 tools: sbom-only：先拿掉，再依測試要的值加回去
        if value is not None:
            t = t.replace("scan:\n", "scan:\n  tools: %s\n" % value, 1)
        open(y, "w", encoding="utf-8").write(t)
        return plats

    def test_scan_tools_default_full_and_invalid(self):
        """scan.tools：不寫＝sbom-only（Jetson 不設，行為不變）；sbom-only／full 都接受；其他值結束碼 64（project-info 與 platform.sh validate）。"""
        _, kv = info("orin-nano-demo/v39.2.1-demo1")
        self.assertEqual(kv["SCAN_TOOLS"], "sbom-only")
        self.assertNotIn("tools", pc.load_platform_config("jetson").get("scan", {}))
        for value, want in ((None, "sbom-only"), ("sbom-only", "sbom-only"), ("full", "full")):
            plats = self.platforms_with_scan_tools(value)
            d = self.project("plan-tools-%s" % (value or "default").replace("-", ""), "toolp")
            r, kv = info("--dir", d, "v39.2.1-demo1", env={"DUMPLING_PLATFORMS_DIR": plats})
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertEqual(kv["SCAN_TOOLS"], want)
        for bad in ("minimal", "FULL", "[syft]", "'full; rm'"):
            plats = self.platforms_with_scan_tools(bad.replace("'", "q").replace("[", "l").replace("]", "r").replace(" ", "_").replace(";", "s"))
            y = os.path.join(plats, "toolp", "platform.yml")
            t = open(y, encoding="utf-8").read()
            import re
            t = re.sub(r"  tools: .*\n", "  tools: %s\n" % bad, t, count=1)
            open(y, "w", encoding="utf-8").write(t)
            d = self.project("plan-tools-bad%d" % abs(hash(bad) % 1000), "toolp")
            r, _ = info("--dir", d, "v39.2.1-demo1", env={"DUMPLING_PLATFORMS_DIR": plats})
            self.assertEqual(r.returncode, 64, (bad, r.stdout))
            self.assertIn("scan.tools", r.stdout)
            v = subprocess.run(["bash", os.path.join(ROOT, "pipeline", "platform.sh"), "validate", d, "v39.2.1-demo1"], capture_output=True, text=True,
                               env=dict(os.environ, DUMPLING_PLATFORMS_DIR=plats))
            self.assertEqual(v.returncode, 64, (bad, v.stdout))
            self.assertRegex(v.stdout.strip(), r"^validate: FAIL（.*scan\.tools")

    def test_install_script_rejects_a_bad_mode_and_missing_argument(self):
        sh = os.path.join(ROOT, "pipeline", "install-scan-tools.sh")
        for args in (["minimal", "/tmp/x"], [], ["FULL", "/tmp/x"]):
            r = subprocess.run(["bash", sh, *args], capture_output=True, text=True)
            self.assertEqual(r.returncode, 64, args)
        r = subprocess.run(["bash", sh, "full"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 64)
        t = open(os.path.join(ROOT, ".github", "workflows", "pipeline.yml"), encoding="utf-8").read()
        self.assertIn("pipeline/install-scan-tools.sh", t)
        self.assertIn("SCAN_TOOLS: ${{ steps.p.outputs.SCAN_TOOLS }}", t)

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
