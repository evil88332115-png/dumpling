"""平台介面與開案範本（pipeline/platform.sh、new-project.sh、project-info.py、lib/*）的單元測試。不連網、不下載。"""
import hashlib
import inspect
import os
import re
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

    def test_sha1_match_is_checked_by_fetch_one_itself(self):
        d = self.dl(b"hello")
        ok, msg = fv.fetch_one(self.entry(sha1=hashlib.sha1(b"hello").hexdigest()), self.tmp, d)
        self.assertTrue(ok, msg)
        self.assertIn("SHA-1", msg)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "a.bin")))

    def test_sha1_mismatch_fails_like_a_sha256_mismatch(self):
        for kw in ({"sha1": "0" * 40}, {"sha256": sha(b"x")}):       # sha1 不符與 sha256 不符：同樣失敗、同樣不留檔案（正式檔與暫存檔都沒有）
            tmp = tempfile.mkdtemp(prefix="dumpling-sha1-")
            self.addCleanup(shutil.rmtree, tmp, True)
            ok, msg = fv.fetch_one(self.entry(**kw), tmp, self.dl(b"hello"))
            self.assertFalse(ok, kw)
            self.assertEqual(os.listdir(tmp), [], kw)
        ok, msg = fv.fetch_one(self.entry(sha1="0" * 40), self.tmp, self.dl(b"hello"))
        self.assertIn("sha1 不符", msg)

    def test_no_sha1_is_fine(self):
        ok, msg = fv.fetch_one(self.entry(), self.tmp, self.dl(b"hello"))
        self.assertTrue(ok, msg)
        self.assertNotIn("SHA-1", msg)

    def test_existing_file_with_wrong_sha1_is_downloaded_again(self):
        fv.fetch_one(self.entry(), self.tmp, self.dl(b"hello"))
        d = self.dl(b"hello")
        ok, msg = fv.fetch_one(self.entry(sha1="0" * 40), self.tmp, d)      # 已存在的檔案 sha256 相符、sha1 不符：不信任，重新下載後仍不符 → 失敗
        self.assertFalse(ok)
        self.assertEqual(len(d.calls), 1)

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
            fh.write("schema: 1\nplatform: %s\ndescription: test\nbuild: {mode: none}\nlayers: {default: os}\nscan: {platform_arg: generic}\n" % name)
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

    def test_jetson_steps_without_inputs_and_shared_fetch(self):
        """J 軌實作後：沒有輸入（沒下載、沒有 build 的輸出）時，各步驟回報 FAIL 或 NOT_RUN（非 aarch64 的 build），不會假裝成功。"""
        proj = os.path.join(ROOT, "projects", "orin-nano-demo")
        p = self.plat("build", proj, "v39.2.1-demo1")
        if os.uname().machine == "aarch64":
            self.assertEqual(p.returncode, 1, p.stdout)
            self.assertRegex(p.stdout.strip(), r"^build: FAIL（")
        else:
            self.assertEqual(p.returncode, 4, p.stdout)
            self.assertRegex(p.stdout.strip(), r"^build: NOT_RUN（只在 aarch64 主機原生編譯")
        for step in ("assemble", "scan"):
            p = self.plat(step, proj, "v39.2.1-demo1")
            self.assertEqual(p.returncode, 1, p.stdout)
            self.assertRegex(p.stdout.strip().splitlines()[-1], r"^%s: FAIL（" % step)
        p = self.plat("raw-sectors", proj, "v39.2.1-demo1")
        self.assertEqual((p.returncode, p.stdout.split("（")[0]), (0, "raw-sectors: OK"))
        p = self.plat("validate", proj, "v39.2.0-demo1")
        self.assertEqual(p.returncode, 0, p.stdout)

    def test_scan_flash_package_platform_generic_and_arch_arguments(self):
        """--platform generic 與 --arch／SCA_ARCH 的參數處理（不跑 Docker）：合法值過了參數檢查（之後因為沒給 --archive 才結束碼 64），不合法的值在參數檢查就被拒絕。"""
        sfp = os.path.join(ROOT, "tools", "demo", "scan-flash-package.sh")

        def rc(*args, env=None):
            p = run(["bash", sfp, *args], env=env)
            return p.returncode, p.stderr
        for args, env in ((["--platform", "generic"], None), (["--platform", "generic", "--arch", "amd64"], None), (["--arch", "arm64"], None),
                          ([], {"SCA_ARCH": "amd64"}), ([], {"SCA_PLATFORM": "generic"})):
            code, err = rc(*args, env=env)
            self.assertEqual(code, 64, err)
            self.assertNotIn("只接受", err, (args, env))             # 沒有被參數檢查擋下來，而是後面「需要 --archive」
            self.assertIn("需要 --archive", err)
        for args, env, word in ((["--platform", "bogus"], None, "--platform"), (["--arch", "riscv64"], None, "--arch"), (["--arch", ""], None, "--arch"),
                                ([], {"SCA_ARCH": "x86"}, "--arch"), ([], {"SCA_ARCH": "ARM64"}, "--arch")):
            code, err = rc(*args, env=env)
            self.assertEqual(code, 64, err)
            self.assertIn("只接受", err)
            self.assertIn(word, err)
        self.assertEqual(rc("--arch")[0], 64)                                     # 缺值
        src = open(sfp, encoding="utf-8").read()
        self.assertIn('docker import --platform "linux/$ARCH"', src)               # 架構參數真的用在 docker import
        self.assertNotIn("linux/arm64", src.split("set -uo pipefail", 1)[1])        # 預設值 arm64 在變數裡，不寫死在 import
        self.assertIn('[ "$PLATFORM" != generic ] || na=(--not-assessed generic)', src)   # generic 走 --not-assessed generic（NOT_ASSESSED，不是 GAP）

    def test_scan_flash_package_rejects_unknown_platform(self):
        p = run(["bash", os.path.join(ROOT, "tools", "demo", "scan-flash-package.sh"), "--platform", "bogus"])
        self.assertEqual(p.returncode, 64, p.stderr)


class KernelWizardArgs(unittest.TestCase):
    """platform_params.kernel_release／kernel_upstream_version → 精靈的 --kernel-version／--kernel-upstream-version（project_config.kernel_wizard_args、
    project-info.py --kernel-args）。"""

    def test_shapes(self):
        f = pc.kernel_wizard_args
        self.assertEqual(f(None), [])
        self.assertEqual(f({"l4t_release": "1.0"}), [])
        self.assertEqual(f({"kernel_release": "6.1.0-v8"}), ["--kernel-version", "6.1.0-v8"])
        self.assertEqual(f({"kernel_release": "6.1.0-v8", "kernel_upstream_version": "6.1.93"}),
                         ["--kernel-version", "6.1.0-v8", "--kernel-upstream-version", "6.1.0-v8=6.1.93"])
        self.assertEqual(f({"kernel_release": ["6.1.0-a", "6.1.0-b"], "kernel_upstream_version": {"6.1.0-b": "6.1.93"}}),
                         ["--kernel-version", "6.1.0-a", "--kernel-version", "6.1.0-b", "--kernel-upstream-version", "6.1.0-b=6.1.93"])

    def test_bad_shapes(self):
        for params in ({"kernel_release": "a;b"}, {"kernel_release": ["x", "x"]}, {"kernel_release": 3},
                       {"kernel_release": ["a", "b"], "kernel_upstream_version": "6.1.93"},       # 字串只用於一顆
                       {"kernel_upstream_version": "6.1.93"},                                      # 沒有 kernel_release
                       {"kernel_release": "a", "kernel_upstream_version": "6.1"},
                       {"kernel_release": "a", "kernel_upstream_version": {"b": "6.1.93"}},
                       {"kernel_release": "a", "kernel_upstream_version": ["6.1.93"]}):
            with self.assertRaises(pc.ConfigError, msg=params):
                pc.kernel_wizard_args(params)
        errs = pc.validate_sources({"schema": 1, "releases": {"v1": {"platform_params": {"kernel_release": "a;b"},
                                                                     "files": [{"name": "x", "url": "https://e.invalid/x", "sha256": "0" * 64, "role": "bsp"}]}}})
        self.assertTrue(any("kernel_release" in e for e in errs), errs)

    def test_not_distro_shapes(self):
        """kernel_not_distro：理由字串 → --kernel-not-distro；platform.yml 的預設（第二個參數）被版本的 platform_params 取代。"""
        f = pc.kernel_wizard_args
        self.assertEqual(f({"kernel_not_distro": "廠商核心，版本字串看不出來"}), ["--kernel-not-distro", "廠商核心，版本字串看不出來"])
        self.assertEqual(f({"kernel_release": "6.1.84-8", "kernel_not_distro": "x"}), ["--kernel-version", "6.1.84-8", "--kernel-not-distro", "x"])
        self.assertEqual(f(None, "平台預設"), ["--kernel-not-distro", "平台預設"])
        self.assertEqual(f({}, "平台預設"), ["--kernel-not-distro", "平台預設"])
        self.assertEqual(f({"kernel_not_distro": "版本的理由"}, "平台預設"), ["--kernel-not-distro", "版本的理由"])      # 版本優先
        self.assertEqual(f({"l4t_release": "1.0"}, None), [])                                                         # Jetson：都沒有就不印
        for bad in ("", "   ", "a\nb", "a\tb", 3, ["x"], "x" * 301, "--evil", " -x"):            # - 開頭：精靈的 argparse 會當成選項
            with self.assertRaises(pc.ConfigError, msg=repr(bad)):
                f({"kernel_not_distro": bad})
            with self.assertRaises(pc.ConfigError, msg=repr(bad)):
                f({}, bad)
        errs = pc.validate_sources({"schema": 1, "releases": {"v1": {"platform_params": {"kernel_not_distro": ""},
                                                                     "files": [{"name": "x", "url": "https://e.invalid/x", "sha256": "0" * 64, "role": "bsp"}]}}})
        self.assertTrue(any("kernel_not_distro" in e for e in errs), errs)

    def test_platform_yml_scan_kernel_not_distro_validated(self):
        base = pc.load_platform_config("jetson")
        self.assertNotIn("kernel_not_distro", base.get("scan", {}))                     # Jetson 不設
        ok = dict(base, scan=dict(base["scan"], kernel_not_distro="平台的核心不是發行版建的"))
        self.assertEqual(pc.validate_platform_config(ok, "jetson"), [])
        for bad in ("", "a\nb", 3, "x" * 301):
            errs = pc.validate_platform_config(dict(base, scan=dict(base["scan"], kernel_not_distro=bad)), "jetson")
            self.assertTrue(any("kernel_not_distro" in e for e in errs), (bad, errs))

    def test_project_info_platform_default_and_release_override(self):
        tmp = tempfile.mkdtemp(prefix="dumpling-nd-")
        self.addCleanup(shutil.rmtree, tmp, True)
        plats = os.path.join(tmp, "plats")
        shutil.copytree(os.path.join(ROOT, "pipeline", "platforms", "jetson"), os.path.join(plats, "jetson"))
        yml = os.path.join(plats, "jetson", "platform.yml")
        with open(yml, encoding="utf-8") as fh:
            text = fh.read()
        with open(yml, "w", encoding="utf-8") as fh:
            self.assertIn("\nscan:\n", text)
            fh.write(text.replace("\nscan:\n", "\nscan:\n  kernel_not_distro: \"平台預設的理由\"\n", 1))
        dst = os.path.join(tmp, "nd-demo")
        shutil.copytree(os.path.join(ROOT, "projects", "orin-nano-demo"), dst)
        env = dict(os.environ, DUMPLING_PLATFORMS_DIR=plats)
        cmd = [sys.executable, "-I", os.path.join(PIPE, "project-info.py"), "--kernel-args", dst, "v39.2.1-demo1"]
        r = run(cmd, env=env)
        self.assertEqual((r.returncode, r.stdout.splitlines()), (0, ["--kernel-not-distro", "平台預設的理由"]), r.stdout + r.stderr)   # 平台預設套用到每個版本
        sp = os.path.join(dst, "sources.yml")
        with open(sp, encoding="utf-8") as fh:
            text = fh.read()
        with open(sp, "w", encoding="utf-8") as fh:
            fh.write(text.replace('      l4t_release: "39.2.1"\n', '      l4t_release: "39.2.1"\n      kernel_not_distro: "這一版的理由"\n', 1))
        r = run(cmd, env=env)
        self.assertEqual((r.returncode, r.stdout.splitlines()), (0, ["--kernel-not-distro", "這一版的理由"]), r.stdout + r.stderr)      # 版本覆蓋平台預設
        r = run(cmd[:4] + [os.path.join(ROOT, "projects", "orin-nano-demo"), "v39.2.1-demo1"])
        self.assertEqual((r.returncode, r.stdout), (0, ""), r.stdout + r.stderr)                                                       # 真的 Jetson 平台沒設：不印

    def test_project_info_kernel_args(self):
        tmp = tempfile.mkdtemp(prefix="dumpling-kargs-")
        self.addCleanup(shutil.rmtree, tmp, True)
        src = os.path.join(ROOT, "projects", "orin-nano-demo")
        dst = os.path.join(tmp, "kargs-demo")
        shutil.copytree(src, dst)
        r = run([sys.executable, "-I", os.path.join(PIPE, "project-info.py"), "--kernel-args", dst, "v39.2.1-demo1"])
        self.assertEqual((r.returncode, r.stdout), (0, ""), r.stdout + r.stderr)          # Jetson 沒設定：不印
        sp = os.path.join(dst, "sources.yml")
        with open(sp, encoding="utf-8") as fh:
            text = fh.read()
        with open(sp, "w", encoding="utf-8") as fh:
            fh.write(text.replace('      l4t_release: "39.2.1"\n',
                                  '      l4t_release: "39.2.1"\n      kernel_release: [6.8.12-a, 6.8.12-b]\n      kernel_upstream_version: {6.8.12-a: 6.8.12}\n', 1))
        r = run([sys.executable, "-I", os.path.join(PIPE, "project-info.py"), "--kernel-args", dst, "v39.2.1-demo1"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stdout.splitlines(), ["--kernel-version", "6.8.12-a", "--kernel-version", "6.8.12-b", "--kernel-upstream-version", "6.8.12-a=6.8.12"])
        r = run([sys.executable, "-I", os.path.join(PIPE, "project-info.py"), "--kernel-args", dst, "v0-nope"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("project-info: FAIL", r.stdout)

    def test_jetson_scan_passes_them_to_the_wizard(self):
        with open(os.path.join(ROOT, "pipeline", "platforms", "jetson", "scan.sh"), encoding="utf-8") as fh:
            s = fh.read()
        self.assertIn('project-info.py" --kernel-args "$proj" "$ver"', s)
        self.assertIn('"${kargs[@]+"${kargs[@]}"}"', s)

    def test_jetson_layer_rescans_pass_kernel_in_other_report_only_for_non_bsp_layers(self):
        """bsp 以外的分層重跑（-os）才給 --kernel-in-other-report <專案>-bsp；-bsp（會指向自己）、完整掃描與 ours 的空後綴重跑不給。"""
        with open(os.path.join(ROOT, "pipeline", "platforms", "jetson", "scan.sh"), encoding="utf-8") as fh:
            s = fh.read()
        self.assertIn('case $suffix in ""|-bsp) lk=();; *) lk=(--kernel-in-other-report "$DUMPLING_PROJECT-bsp");; esac', s)
        self.assertIn('wiz "$suffix" "${lk[@]+"${lk[@]}"}" --rescan-from', s)
        self.assertIn('w0=$(wiz "" |', s)                                    # 完整掃描：不給
        self.assertEqual(len(re.findall(r"^\s*case \$suffix in", s, re.M)), 1)
        # 把那一行單獨執行：空後綴與 -bsp 不給、-os 給 <專案>-bsp
        line = re.search(r'^\s*(case \$suffix in .*esac)$', s, re.M).group(1)
        for suffix, want in (("", ""), ("-bsp", ""), ("-os", "--kernel-in-other-report demo-bsp")):
            r = subprocess.run(["bash", "-c", 'DUMPLING_PROJECT=demo; suffix="$1"; %s; echo "${lk[*]-}"' % line, "x", suffix], capture_output=True, text=True)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, want), r.stderr)


if __name__ == "__main__":
    unittest.main()
