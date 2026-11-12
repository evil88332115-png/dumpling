"""平台介面與開案範本（pipeline/platform.sh、new-project.sh、project-info.py、lib/*）的單元測試。不連網、不下載。"""
import hashlib
import inspect
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
LIB = os.path.join(ROOT, "pipeline", "lib")
sys.path.insert(0, LIB)
import fetch_verify as fv  # noqa: E402
import firmware_fetch as ff  # noqa: E402
import platform_fetch as pf  # noqa: E402
import project_config as pc  # noqa: E402

PIPE = os.path.join(ROOT, "pipeline")


def run(cmd, env=None, cwd=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(cmd, capture_output=True, text=True, env=e, cwd=cwd)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dumpling-platform-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, rel, text):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p


class FetchVerify(Tmp):
    def entry(self, data=b"hello", **kw):
        e = {"name": "a.bin", "url": "https://example.com/a.bin", "sha256": sha(data), "size": len(data)}
        e.update(kw)
        return e

    def dl(self, data):
        calls = []

        def downloader(url, dest, max_size):
            calls.append((url, dest, max_size))
            with open(dest, "wb") as fh:
                fh.write(data)
            return None
        downloader.calls = calls
        return downloader

    def test_success(self):
        d = self.dl(b"hello")
        ok, msg = fv.fetch_one(self.entry(), self.tmp, d)
        self.assertTrue(ok, msg)
        self.assertEqual(open(os.path.join(self.tmp, "a.bin"), "rb").read(), b"hello")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, ".a.bin.part")))
        self.assertTrue(d.calls[0][1].endswith(".a.bin.part"))
        self.assertEqual(d.calls[0][2], 5)

    def test_existing_ok_skips_download(self):
        fv.fetch_one(self.entry(), self.tmp, self.dl(b"hello"))
        d = self.dl(b"other")
        ok, msg = fv.fetch_one(self.entry(), self.tmp, d)
        self.assertTrue(ok)
        self.assertEqual(d.calls, [])

    def test_sha_mismatch(self):
        ok, msg = fv.fetch_one(self.entry(sha256=sha(b"x")), self.tmp, self.dl(b"hello"))
        self.assertFalse(ok)
        self.assertIn("sha256 不符", msg)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_size_mismatch(self):
        ok, msg = fv.fetch_one(self.entry(size=3), self.tmp, self.dl(b"hello"))
        self.assertFalse(ok)
        self.assertIn("大小不符", msg)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_size_unknown_uses_default_cap(self):
        d = self.dl(b"hello")
        ok, _ = fv.fetch_one(self.entry(size=None), self.tmp, d)
        self.assertTrue(ok)
        self.assertEqual(d.calls[0][2], fv.DEFAULT_MAX_SIZE)

    def test_symlink_final_refused(self):
        target = self.write("real", "x")
        os.symlink(target, os.path.join(self.tmp, "a.bin"))
        d = self.dl(b"hello")
        ok, msg = fv.fetch_one(self.entry(), self.tmp, d)
        self.assertFalse(ok)
        self.assertIn("不是一般檔案", msg)
        self.assertEqual(d.calls, [])

    def test_symlink_part_refused(self):
        target = self.write("real", "x")
        os.symlink(target, os.path.join(self.tmp, ".a.bin.part"))
        ok, msg = fv.fetch_one(self.entry(), self.tmp, self.dl(b"hello"))
        self.assertFalse(ok)
        self.assertEqual(open(target).read(), "x")

    def test_symlink_created_by_downloader_refused(self):
        target = self.write("real", "hello")

        def evil(url, dest, max_size):
            os.symlink(target, dest)
        ok, msg = fv.fetch_one(self.entry(), self.tmp, evil)
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "a.bin")))

    def test_non_https_refused_without_download(self):
        for url in ("http://example.com/a", "file:///etc/passwd", "ftp://example.com/a"):
            d = self.dl(b"hello")
            ok, msg = fv.fetch_one(self.entry(url=url), self.tmp, d)
            self.assertFalse(ok)
            self.assertEqual(d.calls, [])

    def test_downloader_error(self):
        ok, msg = fv.fetch_one(self.entry(), self.tmp, lambda u, d, m: "連線失敗")
        self.assertFalse(ok)
        self.assertIn("連線失敗", msg)

    def test_curl_command_is_https_only(self):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, "", "")
        orig = fv.subprocess.run
        fv.subprocess.run = fake_run
        try:
            self.assertIsNone(fv.curl_download("https://example.com/x", "/dev/null", 10))
        finally:
            fv.subprocess.run = orig
        c = seen["cmd"]
        self.assertIn("=https", c)
        self.assertEqual(c[c.index("--proto") + 1], "=https")
        self.assertEqual(c[c.index("--proto-redir") + 1], "=https")
        self.assertEqual(c[c.index("--max-filesize") + 1], "10")

    def test_signatures_match_firmware_fetch(self):
        """C2 之後會把 firmware_fetch.py 改成 import 這個模組：簽名必須一致（含下載函式的介面）。"""
        for name in ("curl_download", "sha256_of", "check_file", "fetch_one"):
            a = inspect.signature(getattr(fv, name))
            b = inspect.signature(getattr(ff, name))
            self.assertEqual([(p.name, p.kind) for p in a.parameters.values()],
                             [(p.name, p.kind) for p in b.parameters.values()], name)
        self.assertEqual(inspect.signature(fv.fetch_one).parameters["downloader"].default, fv.curl_download)
        self.assertEqual(list(inspect.signature(fv.curl_download).parameters), ["url", "dest", "max_size"])
        # process() 的 downloader 注入點：預設值是同一個下載函式的行為
        self.assertIn("downloader", inspect.signature(ff.process).parameters)


class PlatformFetch(Tmp):
    def src(self, files):
        import yaml
        self.write("proj/sources.yml", yaml.safe_dump({"schema": 1, "releases": {"v1": {"files": files}}}))
        return os.path.join(self.tmp, "proj")

    def test_gap_entry_not_downloaded(self):
        proj = self.src([{"name": "a.bin", "url": "https://example.com/a", "role": "source", "gap": "未記錄"}])

        def boom(*a):
            raise AssertionError("不該下載")
        st, msg, lines = pf.run(proj, "v1", os.path.join(self.tmp, "o"), downloader=boom)
        self.assertEqual(st, "GAP")

    def test_ok_and_sha1(self):
        data = b"abc"
        e = {"name": "a.bin", "url": "https://example.com/a", "role": "bsp", "sha256": sha(data),
             "sha1": hashlib.sha1(data).hexdigest()}
        proj = self.src([e])
        dl = lambda u, d, m: open(d, "wb").write(data) and None  # noqa: E731
        st, msg, _ = pf.run(proj, "v1", os.path.join(self.tmp, "o"), downloader=dl)
        self.assertEqual(st, "OK", msg)

    def test_sha1_mismatch_fails_and_removes(self):
        data = b"abc"
        e = {"name": "a.bin", "url": "https://example.com/a", "role": "bsp", "sha256": sha(data), "sha1": "0" * 40}
        proj = self.src([e])
        dl = lambda u, d, m: open(d, "wb").write(data) and None  # noqa: E731
        out = os.path.join(self.tmp, "o")
        st, msg, _ = pf.run(proj, "v1", out, downloader=dl)
        self.assertEqual(st, "FAIL")
        self.assertFalse(os.path.exists(os.path.join(out, "a.bin")))

    def test_commit_archive_mismatch_uses_clone_never_accepts_new_sha(self):
        commit = "a" * 40
        e = {"name": "src.tar.gz", "url": "https://example.com/a", "role": "source", "sha256": sha(b"old"),
             "commit": commit, "repo": "https://example.com/r.git"}
        proj = self.src([e])
        dl = lambda u, d, m: open(d, "wb").write(b"new") and None  # noqa: E731
        calls = []

        def cloner(repo, c, dest):
            calls.append((repo, c, dest))
            return None
        out = os.path.join(self.tmp, "o")
        st, msg, _ = pf.run(proj, "v1", out, downloader=dl, cloner=cloner)
        self.assertEqual(st, "OK", msg)
        self.assertEqual(calls[0][:2], ("https://example.com/r.git", commit))
        self.assertFalse(os.path.exists(os.path.join(out, "src.tar.gz")))  # 新雜湊的封存檔不留
        # clone 失敗 → FAIL
        shutil.rmtree(out)
        st, msg, _ = pf.run(proj, "v1", out, downloader=dl, cloner=lambda r, c, d: "壞了")
        self.assertEqual(st, "FAIL")

    def test_unknown_version(self):
        proj = self.src([{"name": "a", "url": "https://example.com/a", "role": "bsp", "gap": "x"}])
        self.assertEqual(pf.run(proj, "v9", os.path.join(self.tmp, "o"))[0], "FAIL")


class Config(Tmp):
    def good_project(self):
        return {"schema": 1, "product_name": "P", "brand": "B", "company_role": "manufacturer", "markets": ["EU"],
                "platform": "jetson", "platform_version": "x", "bsp_os_source": "x", "kernel_source": "x",
                "bootloader": "x", "own_software": [], "interfaces": ["Ethernet"], "support_until": "2031-12-31",
                "status": "development", "os_responsibility": "ours"}

    def test_parse_tag(self):
        self.assertEqual(pc.parse_tag("orin-nano-demo/v39.2.1-demo1"), ("orin-nano-demo", "v39.2.1-demo1"))
        for bad in ("", "x", "a/b/c", "A/v1", "a/1.0", "a/v", "a b/v1", "../v1", "a/v1;rm", None, "a/"):
            with self.assertRaises(pc.ConfigError, msg=repr(bad)):
                pc.parse_tag(bad)

    def test_project_good(self):
        errs, todo = pc.validate_project(self.good_project())
        self.assertEqual((errs, todo), ([], []))

    def test_project_errors(self):
        d = self.good_project()
        del d["brand"]
        self.assertIn("缺欄位 brand", pc.validate_project(d)[0])
        for key, val in (("status", "done"), ("os_responsibility", "nobody"), ("company_role", "x"), ("platform", "nope"),
                         ("support_until", "2031-13-40"), ("support_until", "soon"), ("markets", "EU"), ("interfaces", []),
                         ("product_name", ""), ("schema", 2)):
            d = self.good_project()
            d[key] = val
            self.assertTrue(pc.validate_project(d)[0], key)
        self.assertTrue(pc.validate_project([])[0])

    def test_os_responsibility_three_values(self):
        for v in ("ours", "customer", "upstream-vendor"):
            d = self.good_project()
            d["os_responsibility"] = v
            self.assertEqual(pc.validate_project(d)[0], [])

    def test_placeholder_blocks_shipped(self):
        d = self.good_project()
        d["brand"] = pc.PLACEHOLDER
        errs, todo = pc.validate_project(d)
        self.assertEqual((errs, todo), ([], ["brand"]))
        d["status"] = "shipped"
        self.assertTrue(pc.validate_project(d)[0])

    def test_sources_validation(self):
        good = {"schema": 1, "releases": {"v1": {"files": [{"name": "a", "url": "https://e.com/a", "role": "bsp", "sha256": "a" * 64}]}}}
        self.assertEqual(pc.validate_sources(good), [])
        import copy
        for mut in (lambda d: d["releases"]["v1"]["files"][0].update(url="http://e.com/a"),
                    lambda d: d["releases"]["v1"]["files"][0].update(sha256="ABC"),
                    lambda d: d["releases"]["v1"]["files"][0].pop("sha256"),
                    lambda d: d["releases"]["v1"]["files"][0].update(role="zzz"),
                    lambda d: d["releases"]["v1"]["files"][0].update(size=-1),
                    lambda d: d["releases"]["v1"]["files"][0].update(commit="abc", repo="https://e.com/r"),
                    lambda d: d["releases"]["v1"]["files"][0].update(commit="a" * 40),
                    lambda d: d["releases"]["v1"]["files"][0].update(gap="why"),
                    lambda d: d["releases"].update({"1.0": d["releases"]["v1"]}),
                    lambda d: d["releases"]["v1"].update(files=[]),
                    lambda d: d.update(releases={})):
            d = copy.deepcopy(good)
            mut(d)
            self.assertTrue(pc.validate_sources(d))
        d = copy.deepcopy(good)
        f = d["releases"]["v1"]["files"][0]
        f.pop("sha256")
        f["gap"] = "未記錄"
        self.assertEqual(pc.validate_sources(d), [])

    def test_real_platform_configs(self):
        for name in ("jetson", "example"):
            cfg = pc.load_platform_config(name)
            self.assertEqual(cfg["platform"], name)

    def test_platform_config_errors(self):
        import copy
        good = pc.load_platform_config("jetson")
        for mut in (lambda d: d.update(schema=2), lambda d: d["build"].update(mode="x"),
                    lambda d: d["layers"]["bsp"].update(packages=["Bad/Name"]),
                    lambda d: d["layers"]["bsp"].update(packages="nvidia-l4t-*"),
                    lambda d: d["layers"]["host-tool"].update(paths=["/etc/x"]),
                    lambda d: d["layers"]["host-tool"].update(paths=["a/../b"]),
                    lambda d: d["layers"].update(other={}),
                    lambda d: d.update(raw_sectors={"enabled": "yes"}),
                    lambda d: d.update(platform="other"),
                    lambda d: d.update(project_defaults={"os_responsibility": "ours"})):
            d = copy.deepcopy(good)
            mut(d)
            self.assertTrue(pc.validate_platform_config(d, "jetson"), d)

    def test_classify_by_name_not_version_suffix(self):
        cfg = pc.load_platform_config("jetson")
        self.assertEqual(pc.classify_package("nvidia-l4t-core", cfg), "bsp")
        self.assertEqual(pc.classify_package("nvidia-l4t-kernel-oot-modules", cfg), "bsp")
        self.assertEqual(pc.classify_package("openssl", cfg), "os")
        self.assertEqual(pc.classify_package("libc6", cfg), "os")
        self.assertEqual(pc.classify_path("Linux_for_Tegra/flash.sh", cfg), "host-tool")
        self.assertEqual(pc.classify_path("Linux_for_Tegra/tools/kernel_flash/x.py", cfg), "host-tool")
        self.assertEqual(pc.classify_path("etc/passwd", cfg), "os")


class Scripts(Tmp):
    def new(self, name, platform="jetson", extra=None, projects=None):
        projects = projects or os.path.join(self.tmp, "projects")
        cmd = [os.path.join(PIPE, "new-project.sh"), name, "--platform", platform, "--company-role", "manufacturer",
               "--os-responsibility", "ours", "--projects-dir", projects] + (extra or [])
        return run(cmd), projects

    def test_new_project_generates_valid_project(self):
        r, projects = self.new("my-product", extra=["--brand", "Example Corp", "--product-name", "My Product"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(r.stdout.strip().splitlines()[-1].startswith("new-project: OK"))
        d = os.path.join(projects, "my-product")
        for f in ("project.yml", "sources.yml", "patches", "CRA/Config/config.json", "CRA/Config/inputs.json",
                  "CRA/Config/vex-rules.json"):
            self.assertTrue(os.path.exists(os.path.join(d, f)), f)
        v = run([sys.executable, "-I", os.path.join(LIB, "project_config.py"), "validate", d])
        self.assertEqual(v.returncode, 0, v.stdout)
        self.assertIn("待填欄位", v.stdout)
        self.assertEqual(os.listdir(projects), ["my-product"])  # 沒留 .tmp-new

    def test_new_project_failures(self):
        r, projects = self.new("my-product")
        self.assertEqual(r.returncode, 0)
        r2, _ = self.new("my-product", projects=projects)
        self.assertEqual(r2.returncode, 1)
        self.assertIn("已存在", r2.stdout)
        for name, plat in (("BadName", "jetson"), ("p2", "no-such-platform"), ("../x", "jetson")):
            r3, _ = self.new(name, platform=plat, projects=projects)
            self.assertEqual(r3.returncode, 1, name)
            self.assertIn("new-project: FAIL", r3.stdout)
        r4 = run([os.path.join(PIPE, "new-project.sh"), "p3", "--platform", "jetson", "--projects-dir", projects])
        self.assertEqual(r4.returncode, 64)  # 缺 --company-role／--os-responsibility
        r5, _ = self.new("p4", extra=["--status", "weird"], projects=projects)
        self.assertEqual(r5.returncode, 1)
        self.assertEqual(sorted(os.listdir(projects)), ["my-product"])

    def test_validate_catches_broken_project(self):
        r, projects = self.new("p1")
        d = os.path.join(projects, "p1")
        yml = os.path.join(d, "project.yml")
        text = open(yml, encoding="utf-8").read()
        for bad in (text.replace('platform: "jetson"', 'platform: "unknown-x"'),
                    text.replace('status: "development"', 'status: "weird"'),
                    "\n".join(line for line in text.splitlines() if not line.startswith("brand:")),
                    "schema: [unclosed"):
            open(yml, "w", encoding="utf-8").write(bad)
            v = run([sys.executable, "-I", os.path.join(LIB, "project_config.py"), "validate", d])
            self.assertEqual(v.returncode, 1, bad[:40])
            self.assertIn("validate: FAIL", v.stdout)

    def info(self, tag, projects):
        return run([sys.executable, "-I", os.path.join(PIPE, "project-info.py"), tag], env={"DUMPLING_PROJECTS_DIR": projects})

    def test_project_info(self):
        r, projects = self.new("p1", extra=["--version", "v1.0.0-rc1"])
        ok = self.info("p1/v1.0.0-rc1", projects)
        self.assertEqual(ok.returncode, 0, ok.stdout)
        kv = dict(line.split("=", 1) for line in ok.stdout.splitlines())
        self.assertEqual((kv["PROJECT"], kv["VERSION"], kv["PLATFORM"], kv["STATUS"], kv["OS_RESPONSIBILITY"]),
                         ("p1", "v1.0.0-rc1", "jetson", "development", "ours"))
        for bad in ("p1/v9", "nope/v1.0.0-rc1", "p1", "p1/1.0", "P1/v1", "p1/v1/x", ""):
            f = self.info(bad, projects)
            self.assertEqual(f.returncode, 1, bad)
            self.assertTrue(f.stdout.startswith("project-info: FAIL"), bad)
            self.assertNotIn("=", f.stdout.split("（")[0])

    def test_demo_project(self):
        d = os.path.join(ROOT, "projects", "orin-nano-demo")
        v = run([sys.executable, "-I", os.path.join(LIB, "project_config.py"), "validate", d])
        self.assertEqual(v.returncode, 0, v.stdout)
        for ver in ("v39.2.0-demo1", "v39.2.1-demo1"):
            r = run([sys.executable, "-I", os.path.join(PIPE, "project-info.py"), "orin-nano-demo/" + ver])
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("PLATFORM=jetson", r.stdout)
        src = pc.load_sources(os.path.join(d, "sources.yml"))
        for ver, rel in src["releases"].items():
            self.assertEqual({f["role"] for f in rel["files"]}, {"bsp", "rootfs", "source"})
        self.assertTrue(os.path.isfile(os.path.join(d, "patches", "README.md")))

    def plat(self, step, proj, ver, platforms=None, extra=None):
        env = {"DUMPLING_PLATFORMS_DIR": platforms} if platforms else {}
        env["DUMPLING_OUT_BASE"] = os.path.join(self.tmp, "out")
        return run([os.path.join(PIPE, "platform.sh"), step, proj, ver] + (extra or []), env=env)

    def make_platform(self, platforms, name, steps):
        d = os.path.join(platforms, name)
        os.makedirs(d)
        with open(os.path.join(d, "platform.yml"), "w", encoding="utf-8") as fh:
            fh.write("schema: 1\nplatform: %s\ndescription: test\nbuild: {mode: none}\nlayers: {default: os}\n" % name)
        for s in steps:
            with open(os.path.join(d, s + ".sh"), "w", encoding="utf-8") as fh:
                fh.write('#!/usr/bin/env bash\necho "%s: OK（%s %s $DUMPLING_PLATFORM $DUMPLING_OS_RESPONSIBILITY $2）"\n' % (s, name, s))

    def test_dispatcher_selects_adapter_per_step(self):
        """新增平台＝加資料夾＋platform.yml，不改 dispatcher：test 在暫存目錄臨時建兩個平台。"""
        platforms = os.path.join(self.tmp, "platforms")
        self.make_platform(platforms, "alpha", ["build", "assemble", "scan"])
        self.make_platform(platforms, "beta", ["build", "assemble", "scan"])
        for plat in ("alpha", "beta"):
            os.environ["DUMPLING_PLATFORMS_DIR"] = platforms
            try:
                r, projects = self.new("proj-" + plat, platform=plat)
            finally:
                del os.environ["DUMPLING_PLATFORMS_DIR"]
            self.assertEqual(r.returncode, 0, r.stdout)
            proj = os.path.join(projects, "proj-" + plat)
            ver = "v0.1.0-dev1"
            for step in ("build", "assemble", "scan"):
                p = self.plat(step, proj, ver, platforms)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertEqual(p.stdout.strip(), "%s: OK（%s %s %s ours %s）" % (step, plat, step, plat, ver))
            v = self.plat("validate", proj, ver, platforms)
            self.assertEqual(v.returncode, 0, v.stdout)

    def test_dispatcher_errors_and_not_run(self):
        platforms = os.path.join(self.tmp, "platforms")
        self.make_platform(platforms, "alpha", ["build"])
        os.environ["DUMPLING_PLATFORMS_DIR"] = platforms
        try:
            r, projects = self.new("p1", platform="alpha")
        finally:
            del os.environ["DUMPLING_PLATFORMS_DIR"]
        proj = os.path.join(projects, "p1")
        p = self.plat("scan", proj, "v0.1.0-dev1", platforms)
        self.assertEqual(p.returncode, 4)
        self.assertTrue(p.stdout.startswith("scan: NOT_RUN"))
        # 沒有 raw_sectors 設定 → 預設不適用
        p = self.plat("raw-sectors", proj, "v0.1.0-dev1", platforms)
        self.assertEqual((p.returncode, p.stdout.split("（")[0]), (0, "raw-sectors: OK"))
        # 未知平台（project.yml 的 platform 不在轉接器根目錄）、未知版本、未知步驟、專案不存在
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        self.assertEqual(self.plat("build", proj, "v0.1.0-dev1", empty).returncode, 1)
        self.assertEqual(self.plat("build", proj, "v9.9", platforms).returncode, 1)
        self.assertEqual(self.plat("bogus", proj, "v0.1.0-dev1", platforms).returncode, 64)
        self.assertEqual(self.plat("build", os.path.join(self.tmp, "nope"), "v1", platforms).returncode, 1)
        self.assertEqual(self.plat("build", proj, "v0.1.0-dev1", platforms, ["--bad"]).returncode, 64)
        for p in (self.plat("build", proj, "v9.9", platforms), self.plat("build", os.path.join(self.tmp, "nope"), "v1", platforms)):
            self.assertRegex(p.stdout.strip().splitlines()[-1], r"^build: FAIL（")

    def test_example_platform_end_to_end(self):
        r, projects = self.new("ex1", platform="example")
        self.assertEqual(r.returncode, 0, r.stdout)
        proj = os.path.join(projects, "ex1")
        ver = "v0.1.0-dev1"
        expect = {"fetch": (3, "GAP"), "build": (0, "OK"), "assemble": (0, "OK"), "scan": (3, "GAP"), "raw-sectors": (0, "OK")}
        for step, (code, word) in expect.items():
            p = self.plat(step, proj, ver)
            self.assertEqual(p.returncode, code, step + p.stdout + p.stderr)
            self.assertRegex(p.stdout.strip().splitlines()[-1], r"^%s: %s" % (step, word))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, "out", "ex1", ver, "raw-sectors.json")))

    def test_jetson_skeleton_and_shared_fetch(self):
        proj = os.path.join(ROOT, "projects", "orin-nano-demo")
        for step in ("build", "assemble", "scan"):
            p = self.plat(step, proj, "v39.2.1-demo1")
            self.assertEqual(p.returncode, 4, p.stdout)
            self.assertEqual(p.stdout.strip(), "%s: NOT_RUN（J 軌實作）" % step)
        p = self.plat("raw-sectors", proj, "v39.2.1-demo1")
        self.assertEqual((p.returncode, p.stdout.split("（")[0]), (0, "raw-sectors: OK"))
        p = self.plat("validate", proj, "v39.2.0-demo1")
        self.assertEqual(p.returncode, 0, p.stdout)

    def test_scan_flash_package_rejects_unknown_platform(self):
        p = run(["bash", os.path.join(ROOT, "tools", "demo", "scan-flash-package.sh"), "--platform", "bogus"])
        self.assertEqual(p.returncode, 64, p.stderr)


if __name__ == "__main__":
    unittest.main()
