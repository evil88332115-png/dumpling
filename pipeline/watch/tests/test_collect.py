"""collect.py：收集 Release 附件。全部合成資料、不連網（假 opener 或本機 127.0.0.1 http.server）。"""
import contextlib
import http.server
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import collect  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
DRILL = os.path.join(ROOT, "tests", "fixtures", "watch", "drill")
API = "https://api.github.com"
TOKEN = "ghp_SYNTHETICTOKEN0123456789"
HEX = "0123456789abcdef" * 2 + "01234567"


def j(o):
    return json.dumps(o).encode()


def meta(project="p", version="v1", tag=None, status="shipped", **over):
    m = {"schema": 1, "project": project, "version": version, "tag": tag or "%s/%s" % (project, version),
         "status": status, "platform": "jetson", "os_responsibility": "customer", "commit": HEX,
         "built_at": "2026-11-13T02:33:37Z", "workflow_run": "1", "steps": [], "pipeline_result": "OK",
         "report_status": "OK", "release_gate": "OK", "reports": [], "kernel_versions": None}
    m.update(over)
    return m


def sbom(fmt="CycloneDX"):
    return j({"bomFormat": fmt, "specVersion": "1.6", "version": 1,
              "components": [{"type": "library", "name": "requests", "version": "2.19.0",
                              "purl": "pkg:pypi/requests@2.19.0"}]})


def files(project="p", version="v1", layered=True, **meta_over):
    f = {"release-meta.json": j(meta(project, version, **meta_over)), "layers.json": j({"layers": []})}
    base = "sbom-%s-%s" % (project, version)
    if layered:
        f[base + "-bsp.cdx.json"] = sbom()
        f[base + "-os.cdx.json"] = sbom()
    else:
        f[base + ".cdx.json"] = sbom()
    return f


class Resp:
    def __init__(self, body, headers=None, status=200):
        self._b = io.BytesIO(body)
        self.status = status
        self.headers = headers or {}

    def read(self, n=-1):
        return self._b.read(n)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def redirect(url, code, loc):
    return urllib.error.HTTPError(url, code, "x", {"Location": loc}, None)


class World:
    """假的 GitHub：Release 清單（可分頁）、附件（302 到 CDN 或直接給）。"""

    def __init__(self, page_size=100, use_redirect=True):
        self.entries, self.blobs, self.requests = [], {}, []
        self.page_size, self.use_redirect, self.hooks = page_size, use_redirect, {}
        self.seq = 0

    def add(self, tag, fl, prerelease=False, draft=False, size_lie=None):
        assets = []
        for name, body in fl.items():
            self.seq += 1
            url = "%s/repos/o/r/releases/assets/%d" % (API, self.seq)
            self.blobs[url] = body
            assets.append({"name": name, "url": url, "size": len(body) if size_lie is None else size_lie})
        self.entries.append({"tag_name": tag, "draft": draft, "prerelease": prerelease,
                             "published_at": "2026-11-01T00:00:00Z", "html_url": "https://github.com/o/r/x",
                             "assets": assets})

    def cdn(self, url):
        return url.replace(API + "/repos/o/r/releases/assets/", "https://objects.githubusercontent.com/blob/")

    def open(self, req, timeout=None):
        url = req.full_url
        hdr = {k.lower(): v for k, v in req.header_items()}
        self.requests.append((url, hdr))
        if url in self.hooks:
            return self.hooks[url](req)
        if url.startswith(API + "/repos/o/r/releases?"):
            page = 1
            if "&page=" in url:
                page = int(url.rsplit("&page=", 1)[1])
            lo = (page - 1) * self.page_size
            chunk = self.entries[lo:lo + self.page_size]
            h = {}
            if lo + self.page_size < len(self.entries):
                h["Link"] = '<%s/repos/o/r/releases?per_page=100&page=%d>; rel="next", <x>; rel="last"' % (API, page + 1)
            return Resp(j(chunk), h)
        if url in self.blobs:
            if self.use_redirect:
                raise redirect(url, 302, self.cdn(url))
            return Resp(self.blobs[url])
        for u, b in self.blobs.items():
            if self.cdn(u) == url:
                return Resp(b)
        raise urllib.error.HTTPError(url, 404, "nf", {}, None)


def go(args, env=None, opener=None):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = collect.run(args, env=env if env is not None else {}, opener=opener,
                           now="2026-11-13T00:00:00Z")
    return code, out.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.out = os.path.join(self._td.name, "work")

    def repo(self, world, extra=(), env=None):
        e = {"GH_TOKEN": TOKEN}
        e.update(env or {})
        code, so = go(["--repo", "o/r", "--out", self.out, *extra], e, world)
        return code, so, self.inv()

    def inv(self):
        p = os.path.join(self.out, "inventory.json")
        if not os.path.exists(p):
            return None
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    def dirs(self, spec):
        """spec: {資料夾: (release.json 內容, {檔名: bytes})} → 回根資料夾"""
        root = os.path.join(self._td.name, "src")
        for d, (rj, fl) in spec.items():
            os.makedirs(os.path.join(root, d))
            if rj is not None:
                with open(os.path.join(root, d, "release.json"), "w") as f:
                    json.dump(rj, f)
            for n, b in fl.items():
                with open(os.path.join(root, d, n), "wb") as f:
                    f.write(b)
        return root


class TestGitHub(Base):
    def test_ok_and_headers(self):
        w = World()
        w.add("p/v1", files())
        code, so, inv = self.repo(w)
        self.assertEqual(code, 0, so)
        self.assertEqual(so, "WATCH-COLLECT\tOK\t正式版 1、開發版 0、略過 0、draft 0\n")
        r = inv["releases"][0]
        self.assertEqual((r["kind"], r["watch_version"], r["status"], r["commit"]), ("release", "v1", "shipped", HEX))
        self.assertEqual(set(r["sboms"]), {"bsp", "os"})
        self.assertEqual(r["sboms"]["bsp"]["file"], "releases/0/sbom-p-v1-bsp.cdx.json")
        self.assertEqual(r["sboms"]["bsp"]["size"], len(sbom()))
        self.assertTrue(os.path.exists(os.path.join(self.out, "releases/0/release-meta.json")))
        list_req = w.requests[0]
        self.assertTrue(list_req[0].endswith("/repos/o/r/releases?per_page=100"))
        self.assertEqual(list_req[1]["authorization"], "Bearer " + TOKEN)
        asset_reqs = [h for u, h in w.requests if "/releases/assets/" in u]
        self.assertTrue(all(h["accept"] == "application/octet-stream" for h in asset_reqs))

    def test_pagination(self):
        w = World(page_size=2)
        for i in range(5):
            w.add("p/v%d" % i, files(version="v%d" % i, layered=False))
        code, so, inv = self.repo(w)
        self.assertEqual(code, 0, so)
        self.assertEqual([r["version"] for r in inv["releases"]], ["v0", "v1", "v2", "v3", "v4"])
        lists = [u for u, h in w.requests if "/releases?" in u]
        self.assertEqual(len(lists), 3)
        self.assertTrue(all(h.get("authorization") == "Bearer " + TOKEN for u, h in w.requests if "/releases?" in u))

    def test_next_page_other_host_is_fail(self):
        w = World()
        w.add("p/v1", files())
        w.hooks[API + "/repos/o/r/releases?per_page=100"] = lambda req: Resp(
            j([]), {"Link": '<https://evil.example/repos/o/r/releases?page=2>; rel="next"'})
        code, so, inv = self.repo(w)
        self.assertEqual(code, 1)
        self.assertEqual(inv["status"], "FAIL")
        self.assertFalse(any("evil.example" in u for u, h in w.requests))

    def test_pagination_loop_is_fail(self):
        w = World()
        w.hooks[API + "/repos/o/r/releases?per_page=100"] = lambda req: Resp(
            j([]), {"Link": '<%s/repos/o/r/releases?per_page=100>; rel="next"' % API})
        code, so, inv = self.repo(w)
        self.assertEqual(code, 1)

    def test_api_failure_is_fail(self):
        w = World()
        w.hooks[API + "/repos/o/r/releases?per_page=100"] = lambda req: (_ for _ in ()).throw(
            urllib.error.HTTPError(req.full_url, 500, "x", {}, None))
        code, so, inv = self.repo(w)
        self.assertEqual(code, 1)
        self.assertEqual(inv["status"], "FAIL")
        self.assertEqual(inv["releases"], [])

    def test_api_redirect_not_followed(self):
        w = World()
        w.hooks[API + "/repos/o/r/releases?per_page=100"] = lambda req: (_ for _ in ()).throw(
            redirect(req.full_url, 301, "https://evil.example/"))
        code, so, inv = self.repo(w)
        self.assertEqual(code, 1)
        self.assertEqual(len(w.requests), 1)

    def test_draft_skipped(self):
        w = World()
        w.add("p/v1", files(), draft=True)
        w.add("p/v2", files(version="v2"))
        code, so, inv = self.repo(w)
        self.assertEqual(code, 0, so)
        self.assertEqual([r["tag"] for r in inv["releases"]], ["p/v2"])
        self.assertEqual(inv["skipped"], [])
        self.assertEqual(inv["drafts"], ["p/v1"])            # match.py 只列出、不降級
        self.assertIn("draft 1", so)
        self.assertFalse(any("/assets/1" in u for u, h in w.requests))  # draft 的附件沒碰

    def test_tag_rules(self):
        w = World()
        w.add("p/v1", files())                                                   # release
        w.add("dev/p", files(tag="dev/p", status="development", version="dev-abc"), prerelease=True)  # dev
        w.add("dev/q", files("q"), prerelease=False)                              # dev 但不是 prerelease
        w.add("p/v2", files(version="v2"), prerelease=True)                       # <p>/<v> 卻是 prerelease
        w.add("v1.0", files())                                                    # 沒有斜線
        w.add("a/b/c", files())                                                   # 太多層
        w.add("Bad_Name/v1", files())                                             # 專案名不合規則
        code, so, inv = self.repo(w)
        self.assertEqual(code, 0, so)
        self.assertEqual([(r["tag"], r["kind"], r["watch_version"]) for r in inv["releases"]],
                         [("p/v1", "release", "v1"), ("dev/p", "dev", "dev")])
        self.assertEqual(inv["releases"][1]["version"], "dev-abc")
        sk = {s["tag"]: s["why"] for s in inv["skipped"]}
        self.assertEqual(set(sk), {"dev/q", "p/v2", "v1.0", "a/b/c", "Bad_Name/v1"})
        self.assertIn("不是 prerelease", sk["dev/q"])
        self.assertIn("是 prerelease", sk["p/v2"])
        # 被略過的 Release 不下載附件
        self.assertEqual(len([u for u, h in w.requests if "/releases/assets/" in u]),
                         len(files()) + len(files(version="dev-abc")))

    def test_dev_kernel_versions_uses_meta_version(self):
        w = World()
        f = files("p", "dev-abc", tag="dev/p", status="development", kernel_versions="kernel-versions-p-dev-abc.json")
        f["kernel-versions-p-dev-abc.json"] = j({"k": 1})
        f["scan-summary-p-dev-abc.json"] = j({"s": 1})
        f["kernel-versions.json"] = j({"old": 1})  # 舊名不收
        w.add("dev/p", f, prerelease=True)
        code, so, inv = self.repo(w)
        self.assertEqual(code, 0, so)
        r = inv["releases"][0]
        self.assertEqual(r["kernel_versions"], "releases/0/kernel-versions-p-dev-abc.json")
        self.assertEqual(r["scan_summary"], "releases/0/scan-summary-p-dev-abc.json")
        self.assertFalse(os.path.exists(os.path.join(self.out, "releases/0/kernel-versions.json")))

    def test_kernel_versions_follows_meta_field(self):
        """release-meta 的 kernel_versions 是 null → 不讀附件；不是規則檔名 → problem、不讀；列了但沒有附件 → problem。"""
        w = World()
        f = files(kernel_versions=None)
        f["kernel-versions-p-v1.json"] = j({"k": 1})
        w.add("p/v1", f)
        _, _, inv = self.repo(w)
        self.assertEqual((inv["releases"][0]["kernel_versions"], inv["releases"][0]["problems"]), (None, []))
        w = World()
        f = files(kernel_versions="../evil.json")
        w.add("p/v1", f)
        _, _, inv = self.repo(w)
        self.assertIsNone(inv["releases"][0]["kernel_versions"])
        self.assertTrue(any("規則檔名" in x for x in inv["releases"][0]["problems"]))
        w = World()
        w.add("p/v1", files(kernel_versions="kernel-versions-p-v1.json"))
        _, _, inv = self.repo(w)
        self.assertTrue(any("沒有這個附件" in x for x in inv["releases"][0]["problems"]))

    def test_optional_absent_is_fine(self):
        w = World()
        w.add("p/v1", files())
        code, so, inv = self.repo(w)
        r = inv["releases"][0]
        self.assertEqual((r["kernel_versions"], r["scan_summary"], r["problems"]), (None, None, []))

    def test_meta_mismatch(self):
        cases = {
            "project": dict(project="other"),
            "version": dict(version="v9"),
            "tag": dict(tag="p/v9"),
            "status": dict(status="released"),
            "commit": dict(commit="A" * 40),
            "commit-short": dict(commit="abc"),
            "schema": dict(schema=2),
            "schema-bool": dict(schema=True),
        }
        for label, over in cases.items():
            with self.subTest(label):
                w = World()
                f = files()
                f["release-meta.json"] = j(meta(**dict(dict(project="p", version="v1"), **over)))
                w.add("p/v1", f)
                w.add("p/v2", files(version="v2"))
                code, so, inv = self.repo(w)
                self.assertEqual(code, 3, so)
                bad, good = inv["releases"]
                self.assertTrue(bad["problems"])
                self.assertEqual(bad["sboms"], {})
                self.assertEqual(good["problems"], [])
                self.assertEqual(set(good["sboms"]), {"bsp", "os"})
                self.assertFalse(os.path.exists(os.path.join(self.out, "releases/0/release-meta.json")))
                self.assertEqual(inv["status"], "GAP")

    def test_meta_missing_or_not_json(self):
        w = World()
        f = files()
        del f["release-meta.json"]
        w.add("p/v1", f)
        f2 = files(version="v2")
        f2["release-meta.json"] = b"{not json"
        w.add("p/v2", f2)
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3)
        self.assertTrue(all(r["problems"] and r["sboms"] == {} for r in inv["releases"]))

    def test_redirect_strips_authorization(self):
        w = World()
        w.add("p/v1", files(layered=False))
        code, so, inv = self.repo(w)
        self.assertEqual(code, 0, so)
        api_reqs = [h for u, h in w.requests if u.startswith(API + "/repos/o/r/releases/assets/")]
        cdn_reqs = [h for u, h in w.requests if u.startswith("https://objects.githubusercontent.com/")]
        self.assertTrue(api_reqs and cdn_reqs)
        self.assertTrue(all(h["authorization"] == "Bearer " + TOKEN for h in api_reqs))
        self.assertTrue(all("authorization" not in h for h in cdn_reqs))

    def test_redirect_to_disallowed_hosts(self):
        bad = ["http://objects.githubusercontent.com/x", "https://evil.example/x",
               "https://githubusercontent.com.evil.example/x", "https://x.githubusercontent.com@evil.example/x",
               "https://evil.example\\@x.githubusercontent.com/x", "https://notgithubusercontent.com/x",
               "https://x.githubusercontent.com:8443/x", "/relative/path", "file:///etc/passwd", ""]
        for loc in bad:
            with self.subTest(loc):
                w = World()
                w.add("p/v1", files(layered=False))
                meta_url = w.entries[0]["assets"][0]["url"]
                self.assertTrue(w.entries[0]["assets"][0]["name"] == "release-meta.json")
                w.hooks[meta_url] = lambda req, loc=loc: (_ for _ in ()).throw(redirect(req.full_url, 302, loc))
                code, so, inv = self.repo(w)
                self.assertEqual(code, 3, so)
                r = inv["releases"][0]
                self.assertTrue(any("轉址目標不允許" in p for p in r["problems"]), r["problems"])
                self.assertEqual(r["sboms"], {})
                self.assertFalse(any(u.startswith("https://evil") or u.startswith("http://") for u, h in w.requests))

    def test_allowed_download_url(self):
        ok = ["https://objects.githubusercontent.com/a?b=c", "https://release-assets.githubusercontent.com/x",
              "https://githubusercontent.com/x"]
        for u in ok:
            self.assertTrue(collect.allowed_download_url(u), u)
        for u in ["https://github.com/x", "https://api.github.com/x", "ftp://x.githubusercontent.com/"]:
            self.assertFalse(collect.allowed_download_url(u), u)

    def test_second_redirect_hop_checked(self):
        w = World()
        w.add("p/v1", files(layered=False))
        meta_url = w.entries[0]["assets"][0]["url"]
        cdn = w.cdn(meta_url)
        w.hooks[cdn] = lambda req: (_ for _ in ()).throw(redirect(req.full_url, 302, "https://evil.example/y"))
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3)
        self.assertFalse(any("evil.example" in u for u, h in w.requests))

    def test_too_many_redirects(self):
        w = World()
        w.add("p/v1", files(layered=False))
        meta_url = w.entries[0]["assets"][0]["url"]
        w.hooks[w.cdn(meta_url)] = lambda req: (_ for _ in ()).throw(
            redirect(req.full_url, 302, "https://a.githubusercontent.com/z"))
        w.hooks["https://a.githubusercontent.com/z"] = lambda req: (_ for _ in ()).throw(
            redirect(req.full_url, 302, "https://a.githubusercontent.com/z"))
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3)
        self.assertTrue(any("轉址次數" in p for p in inv["releases"][0]["problems"]))

    def test_asset_url_other_host_not_fetched(self):
        w = World()
        w.add("p/v1", files(layered=False))
        w.entries[0]["assets"][0]["url"] = "https://evil.example/asset"
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3)
        self.assertFalse(any("evil.example" in u for u, h in w.requests))

    def test_size_from_api_field(self):
        w = World()
        f = files(layered=False)
        f["sbom-p-v1.cdx.json"] = sbom()
        w.add("p/v1", f)
        code, so, inv = self.repo(w, ["--max-asset-mb", "0.0001"])  # 約 104 bytes
        r = inv["releases"][0]
        self.assertEqual(code, 3)
        # meta 本身就超過 → 沒有任何附件被下載
        self.assertFalse(any("/assets/" in u and "cdn" in u for u, h in w.requests))
        self.assertTrue(any("超過大小上限" in p for p in r["problems"]))

    def test_size_while_streaming(self):
        w = World()
        f = files(layered=False)
        big = j({"bomFormat": "CycloneDX", "pad": "x" * 5000})
        f["sbom-p-v1.cdx.json"] = big
        w.add("p/v1", f)
        # API 標示的 size 很小（說謊），實際內容超過上限 → 下載時中止
        for a in w.entries[0]["assets"]:
            if a["name"] == "sbom-p-v1.cdx.json":
                a["size"] = 10
        code, so, inv = self.repo(w, ["--max-asset-mb", "0.002"])  # 約 2097 bytes
        r = inv["releases"][0]
        self.assertEqual(code, 3, r["problems"])
        self.assertTrue(any("sbom-p-v1.cdx.json：超過大小上限" in p for p in r["problems"]), r["problems"])
        self.assertEqual(r["sboms"], {})
        left = os.listdir(os.path.join(self.out, "releases/0"))
        self.assertNotIn("sbom-p-v1.cdx.json", left)
        self.assertFalse([n for n in left if n.startswith(".part")])  # 暫存檔清掉

    def test_content_length_over_limit(self):
        w = World(use_redirect=False)
        f = files(layered=False)
        w.add("p/v1", f)
        sb = [a for a in w.entries[0]["assets"] if a["name"] == "sbom-p-v1.cdx.json"][0]
        w.hooks[sb["url"]] = lambda req: Resp(sbom(), {"Content-Length": "999999999"})
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3)
        self.assertTrue(any("Content-Length" in p for p in inv["releases"][0]["problems"]))

    def test_size_mismatch_with_api(self):
        w = World()
        w.add("p/v1", files(layered=False))
        sb = [a for a in w.entries[0]["assets"] if a["name"] == "sbom-p-v1.cdx.json"][0]
        sb["size"] = len(sbom()) + 5
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3)
        self.assertFalse(os.path.exists(os.path.join(self.out, "releases/0/sbom-p-v1.cdx.json")))

    def test_not_cyclonedx(self):
        w = World()
        f = files()
        f["sbom-p-v1-bsp.cdx.json"] = sbom("SPDX")
        f["sbom-p-v1-os.cdx.json"] = j([1, 2])
        w.add("p/v1", f)
        code, so, inv = self.repo(w)
        r = inv["releases"][0]
        self.assertEqual(code, 3)
        self.assertEqual(r["sboms"], {})
        self.assertEqual(len(r["problems"]), 2)
        self.assertFalse(os.path.exists(os.path.join(self.out, "releases/0/sbom-p-v1-bsp.cdx.json")))

    def test_sbom_not_json(self):
        w = World()
        f = files(layered=False)
        f["sbom-p-v1.cdx.json"] = b"\xff\xfe nope"
        w.add("p/v1", f)
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3)
        self.assertEqual(inv["releases"][0]["sboms"], {})

    def test_layered_vs_whole(self):
        w = World()
        f = files()  # 分層
        f["sbom-p-v1.cdx.json"] = sbom()  # 同時有整份 → 只收分層
        w.add("p/v1", f)
        w.add("p/v2", files(version="v2", layered=False))
        code, so, inv = self.repo(w)
        self.assertEqual(code, 0, so)
        a, b = inv["releases"]
        self.assertEqual(set(a["sboms"]), {"bsp", "os"})
        self.assertFalse(os.path.exists(os.path.join(self.out, "releases/0/sbom-p-v1.cdx.json")))
        self.assertEqual(set(b["sboms"]), {"product"})
        self.assertEqual(b["sboms"]["product"]["file"], "releases/1/sbom-p-v2.cdx.json")
        import hashlib
        self.assertEqual(b["sboms"]["product"]["sha256"], hashlib.sha256(sbom()).hexdigest())

    def test_only_one_layer_is_problem(self):
        w = World()
        f = files()
        del f["sbom-p-v1-os.cdx.json"]
        f["sbom-p-v1.cdx.json"] = sbom()
        w.add("p/v1", f)
        code, so, inv = self.repo(w)
        r = inv["releases"][0]
        self.assertEqual(code, 3)
        self.assertEqual(set(r["sboms"]), {"bsp"})
        self.assertTrue(any("缺少分層 SBOM" in p for p in r["problems"]))

    def test_no_sbom_is_problem(self):
        w = World()
        f = files()
        for k in [k for k in f if k.startswith("sbom-")]:
            del f[k]
        w.add("p/v1", f)
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3)

    def test_no_monitorable_release_is_gap(self):
        w = World()
        w.add("p/v1", files(), draft=True)
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3)
        self.assertEqual(so.split("\t")[:2], ["WATCH-COLLECT", "GAP"])
        self.assertIn("沒有可監控的 Release", so)
        self.assertEqual(inv["status"], "GAP")

    def test_duplicate_tag_and_asset_names(self):
        w = World()
        w.add("p/v1", files())
        w.add("p/v1", files())
        code, so, inv = self.repo(w)
        self.assertEqual(len(inv["releases"]), 1)
        self.assertEqual(inv["skipped"][0]["tag"], "p/v1")
        w2 = World()
        w2.add("p/v1", files())
        w2.entries[0]["assets"].append(dict(w2.entries[0]["assets"][0]))
        self.setUp()
        code, so, inv = self.repo(w2)
        self.assertEqual(code, 3)

    def test_malformed_entry(self):
        w = World()
        w.add("p/v1", files())
        w.entries.append({"tag_name": "p/v2", "draft": "no", "prerelease": False})
        w.entries.append("junk")
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3)
        self.assertEqual(len(inv["releases"]), 1)
        self.assertEqual(len(inv["skipped"]), 2)

    def test_api_filenames_not_used_as_path(self):
        w = World()
        f = files(layered=False)
        w.add("p/v1", f)
        w.entries[0]["assets"].append({"name": "../../evil.json", "url": API + "/repos/o/r/releases/assets/999", "size": 1})
        w.entries[0]["assets"].append({"name": "/abs/x.json", "url": API + "/repos/o/r/releases/assets/998", "size": 1})
        code, so, inv = self.repo(w)
        self.assertEqual(code, 0, so)
        self.assertFalse(os.path.exists(os.path.join(self._td.name, "evil.json")))
        self.assertFalse(any("999" in u or "998" in u for u, h in w.requests))

    def test_token_never_in_output(self):
        w = World()
        w.add("p/v1", files())
        w.add("p/v2", files(version="v2", status="bogus"))
        w.hooks[w.entries[0]["assets"][1]["url"]] = lambda req: (_ for _ in ()).throw(
            OSError("boom " + req.get_header("Authorization")))
        code, so, inv = self.repo(w)
        self.assertEqual(code, 3, so)
        self.assertNotIn(TOKEN, so)
        for dp, dn, fn in os.walk(self.out):
            for n in fn:
                with open(os.path.join(dp, n), "rb") as f:
                    self.assertNotIn(TOKEN.encode(), f.read(), n)

    def test_token_in_api_error_scrubbed(self):
        w = World()
        w.hooks[API + "/repos/o/r/releases?per_page=100"] = lambda req: (_ for _ in ()).throw(
            RuntimeError(req.get_header("Authorization")))
        code, so, inv = self.repo(w)
        self.assertEqual(code, 1)
        self.assertNotIn(TOKEN, so)
        self.assertNotIn(TOKEN, json.dumps(inv))

    def test_github_token_env_fallback(self):
        w = World()
        w.add("p/v1", files())
        code, so, inv = self.repo(w, env={"GH_TOKEN": "", "GITHUB_TOKEN": "tok_b"})
        self.assertEqual(w.requests[0][1]["authorization"], "Bearer tok_b")

    def test_no_absolute_paths_in_inventory(self):
        w = World()
        w.add("p/v1", files())
        w.add("dev/p", files(version="dev-1", tag="dev/p", status="development"), prerelease=True)
        code, so, inv = self.repo(w)

        def walk(o):
            if isinstance(o, dict):
                for v in o.values():
                    yield from walk(v)
            elif isinstance(o, list):
                for v in o:
                    yield from walk(v)
            elif isinstance(o, str):
                yield o
        for s in walk(inv):
            self.assertFalse(s.startswith("/"), s)
            self.assertNotIn(self._td.name, s)
            self.assertNotIn("/home/", s)
        for r in inv["releases"]:
            for s in list(r["sboms"].values()):
                self.assertFalse(os.path.isabs(s["file"]))


class TestDir(Base):
    def spec(self):
        rj = {"tag_name": "p/v1", "prerelease": False, "draft": False,
              "published_at": "2026-11-01T00:00:00Z", "html_url": "https://github.com/o/r/x"}
        return {"a": (rj, files())}

    def test_from_dir_same_format(self):
        root = self.dirs(self.spec())
        code, so = go(["--from-dir", root, "--out", self.out])
        inv = self.inv()
        self.assertEqual(code, 0, so)
        self.assertEqual(inv["source"], "dir")
        self.assertEqual(set(inv["releases"][0]["sboms"]), {"bsp", "os"})
        self.assertEqual(inv["releases"][0]["sboms"]["os"]["file"], "releases/0/sbom-p-v1-os.cdx.json")
        self.assertNotIn(self._td.name, json.dumps(inv))

    def test_from_dir_same_as_repo(self):
        root = self.dirs(self.spec())
        go(["--from-dir", root, "--out", self.out])
        a = self.inv()
        w = World()
        w.add("p/v1", files())
        self.out = os.path.join(self._td.name, "work2")
        self.repo(w)
        b = self.inv()
        for x in (a, b):
            x.pop("source")
        self.assertEqual(a, b)

    def test_draft_dev_and_rules(self):
        base = {"prerelease": False, "draft": False}
        spec = {
            "d1": (dict(base, tag_name="p/v1", draft=True), files()),
            "d2": (dict(base, tag_name="dev/p", prerelease=True), files(version="dev-1", tag="dev/p", status="development")),
            "d3": (dict(base, tag_name="dev/q"), files("q")),
            "d4": (dict(base, tag_name="p/v3", prerelease=True), files(version="v3")),
        }
        root = self.dirs(spec)
        code, so = go(["--from-dir", root, "--out", self.out])
        inv = self.inv()
        self.assertEqual(code, 0, so)
        self.assertEqual([r["tag"] for r in inv["releases"]], ["dev/p"])
        self.assertEqual({s["tag"] for s in inv["skipped"]}, {"dev/q", "p/v3"})

    def test_symlink_and_nonregular_rejected(self):
        spec = self.spec()
        root = self.dirs(spec)
        d = os.path.join(root, "a")
        target = os.path.join(self._td.name, "outside.json")
        with open(target, "wb") as f:
            f.write(sbom())
        os.unlink(os.path.join(d, "sbom-p-v1-bsp.cdx.json"))
        os.symlink(target, os.path.join(d, "sbom-p-v1-bsp.cdx.json"))
        os.unlink(os.path.join(d, "sbom-p-v1-os.cdx.json"))
        os.mkfifo(os.path.join(d, "sbom-p-v1-os.cdx.json"))
        code, so = go(["--from-dir", root, "--out", self.out])
        r = self.inv()["releases"][0]
        self.assertEqual(code, 3, so)
        self.assertEqual(r["sboms"], {})
        self.assertEqual(len(r["problems"]), 2)
        self.assertFalse(os.path.exists(os.path.join(self.out, "releases/0/sbom-p-v1-bsp.cdx.json")))

    def test_symlinked_release_folder_ignored(self):
        root = self.dirs(self.spec())
        os.symlink(os.path.join(root, "a"), os.path.join(root, "b"))
        code, so = go(["--from-dir", root, "--out", self.out])
        self.assertEqual(len(self.inv()["releases"]), 1)

    def test_missing_release_json_is_gap(self):
        root = self.dirs({"a": (None, files())})
        code, so = go(["--from-dir", root, "--out", self.out])
        self.assertEqual(code, 3)
        self.assertEqual(self.inv()["skipped"][0]["tag"], "a")

    def test_dir_oversize(self):
        spec = self.spec()
        spec["a"][1]["sbom-p-v1-bsp.cdx.json"] = j({"bomFormat": "CycloneDX", "pad": "x" * 5000})
        root = self.dirs(spec)
        code, so = go(["--from-dir", root, "--out", self.out, "--max-asset-mb", "0.002"])
        r = self.inv()["releases"][0]
        self.assertEqual(code, 3)
        self.assertNotIn("bsp", r["sboms"])

    def test_drill_fixture(self):
        code, so = go(["--from-dir", DRILL, "--out", self.out])
        inv = self.inv()
        self.assertEqual(code, 0, so)
        by = {r["tag"]: r for r in inv["releases"]}
        rel, dev = by["drill-demo/v1.0.0"], by["dev/drill-demo"]
        self.assertEqual((rel["kind"], rel["status"], set(rel["sboms"])), ("release", "shipped", {"bsp", "os"}))
        self.assertEqual((dev["kind"], dev["status"], dev["watch_version"], set(dev["sboms"])),
                         ("dev", "development", "dev", {"product"}))

    def test_subprocess_isolated_mode(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "..", "collect.py"), "--from-dir", DRILL,
                            "--out", self.out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("WATCH-COLLECT\tOK\t"))


class TestExit(Base):
    def test_usage(self):
        for args in ([], ["--out", "x"], ["--repo", "o/r"], ["--repo", "o/r", "--from-dir", "d", "--out", "x"],
                     ["--repo", "bad", "--out", "x"], ["--repo", "../x", "--out", "x"],
                     ["--repo", "o/r", "--out", "x", "--max-asset-mb", "0"],
                     ["--repo", "o/r", "--out", "x", "--max-asset-mb", "nan"]):
            with self.subTest(args):
                code, so = go(args)
                self.assertEqual(code, 64)
                self.assertEqual(so, "")

    def test_from_dir_missing_is_fail(self):
        code, so = go(["--from-dir", os.path.join(self._td.name, "nope"), "--out", self.out])
        self.assertEqual(code, 1)
        self.assertEqual(self.inv()["status"], "FAIL")

    def test_empty_dir_is_gap(self):
        root = os.path.join(self._td.name, "e")
        os.makedirs(root)
        code, so = go(["--from-dir", root, "--out", self.out])
        self.assertEqual(code, 3)

    def test_bad_api_url_fail(self):
        w = World()
        code, so, inv = self.repo(w, env={"GITHUB_API_URL": "http://api.example.invalid"})
        self.assertEqual(code, 1)
        self.assertEqual(w.requests, [])

    def test_bad_token_chars(self):
        w = World()
        code, so, inv = self.repo(w, env={"GH_TOKEN": "a b\nc"})
        self.assertEqual(code, 1)
        self.assertNotIn("a b", so)
        self.assertEqual(w.requests, [])

    def test_stale_releases_dir_cleared(self):
        os.makedirs(os.path.join(self.out, "releases", "9"))
        w = World()
        w.add("p/v1", files())
        self.repo(w)
        self.assertFalse(os.path.exists(os.path.join(self.out, "releases", "9")))


class _Handler(http.server.BaseHTTPRequestHandler):
    log = []
    mode = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        S = type(self)
        S.log.append((self.path, self.headers.get("Authorization")))
        port = self.server.server_address[1]
        base = "http://127.0.0.1:%d" % port
        if self.path.startswith("/repos/o/r/releases?"):
            page = 2 if "page=2" in self.path else 1
            assets = lambda n, b: [{"name": k, "size": len(v), "url": "%s/repos/o/r/releases/assets/%s%d" % (base, n, i)}
                                   for i, (k, v) in enumerate(b.items())]
            if page == 1:
                body = [{"tag_name": "p/v1", "draft": False, "prerelease": False, "assets": assets("a", files())}]
                self.send_response(200)
                self.send_header("Link", '<%s/repos/o/r/releases?per_page=100&page=2>; rel="next"' % base)
            else:
                body = [{"tag_name": "p/v2", "draft": False, "prerelease": False,
                         "assets": assets("b", files(version="v2"))}]
                self.send_response(200)
            data = json.dumps(body).encode()
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        for tag, fl in (("a", files()), ("b", files(version="v2"))):
            for i, (k, v) in enumerate(fl.items()):
                if self.path == "/repos/o/r/releases/assets/%s%d" % (tag, i):
                    if tag == "b":  # 第二個 Release：轉到不允許的主機
                        self.send_response(302)
                        self.send_header("Location", "https://evil.example/x")
                        self.end_headers()
                        return
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(v)))
                    self.end_headers()
                    self.wfile.write(v)
                    return
        self.send_response(404)
        self.end_headers()


class TestRealHttp(Base):
    def setUp(self):
        super().setUp()
        _Handler.log = []
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def test_real_opener(self):
        env = {"GH_TOKEN": TOKEN, "GITHUB_API_URL": "http://127.0.0.1:%d" % self.srv.server_address[1]}
        # 環境有 proxy 設定也不能被使用
        with mock.patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9"}):
            code, so = go(["--repo", "o/r", "--out", self.out], env)
        inv = self.inv()
        self.assertEqual(code, 3, so)
        a, b = inv["releases"]
        self.assertEqual(a["problems"], [])
        self.assertEqual(set(a["sboms"]), {"bsp", "os"})
        self.assertTrue(any("轉址目標不允許" in p for p in b["problems"]))
        self.assertTrue(all(auth == "Bearer " + TOKEN for path, auth in _Handler.log))
        self.assertEqual(sum(1 for p, _ in _Handler.log if p.startswith("/repos/o/r/releases?")), 2)
        self.assertNotIn(TOKEN, so)


if __name__ == "__main__":
    unittest.main()


class TestMetaResults(unittest.TestCase):
    """release-meta 的結論欄位（C1 wp1/m2 9f1d2f0 的實際格式）：六種合法值照原值，其他一律 NOT_RUN；只讀 reports，不讀舊格式。"""

    def test_values_kept_as_is(self):
        for v in collect.RESULT_VALUES:
            r = collect.meta_results({"report_status": v, "release_gate": v, "pipeline_result": v})
            self.assertEqual((r["report_status"], r["release_gate"], r["pipeline_result"]), (v, v, v))

    def test_not_assessed_not_converted(self):
        self.assertEqual(collect.meta_results({"release_gate": "NOT_ASSESSED"})["release_gate"], "NOT_ASSESSED")

    def test_missing_or_bad_is_not_run(self):
        r = collect.meta_results({"report_status": "SAFE", "release_gate": 1})
        self.assertEqual((r["report_status"], r["release_gate"], r["pipeline_result"]), ("NOT_RUN", "NOT_RUN", "NOT_RUN"))

    def test_old_shapes_not_read(self):
        r = collect.meta_results({"result": "GAP", "report_status": {"overall": "GAP"}, "report_status_layers": [{"layer": "bsp", "status": "GAP"}]})
        self.assertEqual((r["report_status"], r["pipeline_result"], r["reports"]), ("NOT_RUN", "NOT_RUN", []))

    def test_reports_and_attention(self):
        r = collect.meta_results({"report_status": "GAP", "reports": [
            {"report": "bsp", "report_status": "GAP", "release_gate": "FAIL"}, {"report": "os", "report_status": "weird", "release_gate": "OK"},
            {"report": "../x", "report_status": "OK", "release_gate": "OK"}], "attention": ["kernel-cve 沿用舊鏡像 <x>", 3]})
        self.assertEqual(r["reports"], [{"report": "bsp", "report_status": "GAP", "release_gate": "FAIL"},
                                        {"report": "os", "report_status": "NOT_RUN", "release_gate": "OK"}])
        self.assertEqual(r["attention"], ["kernel-cve 沿用舊鏡像  x"])
