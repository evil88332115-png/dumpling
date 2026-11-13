"""collect.py 的 GitLab 來源（GITLAB-PORT T-05）：只有假 API 的測試（假 opener），沒有對真實 GitLab 驗證過。測資全部合成。"""
import json
import os
import sys
import tempfile
import unittest
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import collect  # noqa: E402
import test_collect as tc  # noqa: E402  共用合成資料與假回應

BASE = "https://gitlab.example.com/api/v4"
PROJ = "7"
PKG = BASE + "/projects/7/packages/generic/"
TOKEN = "glpat-SYNTHETICTOKEN0123456789"


class World:
    """假的 GitLab：Release 清單（Link 分頁）與 Generic Package 檔案。"""

    def __init__(self, page_size=100):
        self.entries, self.blobs, self.requests, self.hooks = [], {}, [], {}
        self.page_size = page_size
        self.extra_links = {}

    def add(self, tag, fl, upcoming=None, size_lie=None, pkg="p"):
        links = []
        for name, body in fl.items():
            url = "%s%s/%s/%s" % (PKG, pkg, tag.split("/")[-1], name)
            self.blobs[url] = body
            links.append({"id": len(self.blobs), "name": name, "url": url, "direct_asset_url": url, "link_type": "package"})
        links += self.extra_links.get(tag, [])
        e = {"tag_name": tag, "name": tag, "released_at": "2026-11-01T00:00:00Z", "assets": {"count": len(links), "sources": [], "links": links}}
        if upcoming is not None:
            e["upcoming_release"] = upcoming
        self.entries.append(e)

    def open(self, req, timeout=None):
        url = req.full_url
        hdr = {k.lower(): v for k, v in req.header_items()}
        self.requests.append((url, hdr))
        if url in self.hooks:
            return self.hooks[url](req)
        if url.startswith(BASE + "/projects/7/releases?"):
            page = int(url.rsplit("&page=", 1)[1]) if "&page=" in url else 1
            lo = (page - 1) * self.page_size
            h = {}
            if lo + self.page_size < len(self.entries):
                h["Link"] = '<%s/projects/7/releases?per_page=100&page=%d>; rel="next", <x>; rel="last"' % (BASE, page + 1)
            return tc.Resp(tc.j(self.entries[lo:lo + self.page_size]), h)
        if url in self.blobs:
            return tc.Resp(self.blobs[url])
        raise urllib.error.HTTPError(url, 404, "nf", {}, None)


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.out = os.path.join(self._td.name, "work")

    def gl(self, world, extra=(), env=None, url=BASE):
        e = {"GITLAB_TOKEN": TOKEN}
        e.update(env or {})
        code, so = tc.go(["--backend", "gitlab", "--gitlab-url", url, "--project", PROJ, "--out", self.out, *extra], e, world)
        p = os.path.join(self.out, "inventory.json")
        inv = None
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                inv = json.load(f)
        return code, so, inv


class TestGitLab(Base):
    def test_happy_path_same_schema_as_github(self):
        w = World()
        w.add("p/v1", tc.files())
        code, so, inv = self.gl(w)
        self.assertEqual(code, 0, so)
        self.assertEqual(inv["schema"], collect.SCHEMA)
        self.assertEqual(inv["source"], "gitlab:7")
        r = inv["releases"][0]
        self.assertEqual((r["tag"], r["kind"], r["project"], r["version"], r["status"]), ("p/v1", "release", "p", "v1", "shipped"))
        self.assertEqual(sorted(r["sboms"]), ["bsp", "os"])
        self.assertEqual(r["problems"], [])
        self.assertTrue(os.path.exists(os.path.join(self.out, r["sboms"]["bsp"]["file"])))
        # 跟 GitHub 來源同一組鍵
        gh = tc.World(use_redirect=False)
        gh.add("p/v1", tc.files())
        c2, _ = tc.go(["--repo", "o/r", "--out", os.path.join(self._td.name, "gh")], {"GH_TOKEN": tc.TOKEN}, gh)
        with open(os.path.join(self._td.name, "gh", "inventory.json")) as f:
            ginv = json.load(f)
        self.assertEqual(sorted(inv), sorted(ginv))
        self.assertEqual(sorted(inv["releases"][0]), sorted(ginv["releases"][0]))
        self.assertEqual(inv["releases"][0]["sboms"]["os"]["sha256"], ginv["releases"][0]["sboms"]["os"]["sha256"])

    def test_private_token_header_and_no_authorization(self):
        w = World()
        w.add("p/v1", tc.files())
        self.gl(w)
        self.assertTrue(w.requests)
        for url, h in w.requests:
            self.assertEqual(h.get("private-token"), TOKEN)
            self.assertNotIn("authorization", h)
            self.assertTrue(url.startswith(BASE + "/projects/7/"))

    def test_pagination(self):
        w = World(page_size=1)
        for v in ("v1", "v2", "v3"):
            w.add("p/" + v, tc.files("p", v))
        code, so, inv = self.gl(w)
        self.assertEqual(code, 0, so)
        self.assertEqual([r["tag"] for r in inv["releases"]], ["p/v1", "p/v2", "p/v3"])

    def test_next_page_other_host_is_fail(self):
        w = World()
        w.hooks[BASE + "/projects/7/releases?per_page=100"] = lambda req: tc.Resp(
            b"[]", {"Link": '<https://evil.example.test/api/v4/projects/7/releases?page=2>; rel="next"'})
        code, so, inv = self.gl(w)
        self.assertEqual(code, 1)
        self.assertEqual(inv["status"], "FAIL")
        self.assertEqual(len(w.requests), 1)

    def test_upcoming_release_is_draft(self):
        w = World()
        w.add("p/v1", tc.files())
        w.add("p/v2", tc.files("p", "v2"), upcoming=True)
        w.add("p/v3", tc.files("p", "v3"), upcoming=False)
        code, so, inv = self.gl(w)
        self.assertEqual(code, 0, so)
        self.assertEqual([r["tag"] for r in inv["releases"]], ["p/v1", "p/v3"])
        self.assertEqual(inv["drafts"], ["p/v2"])
        self.assertFalse([u for u, _ in w.requests if "/v2/" in u])      # 不下載

    def test_bad_upcoming_field_is_skipped_gap(self):
        w = World()
        w.add("p/v1", tc.files(), upcoming="yes")
        code, so, inv = self.gl(w)
        self.assertEqual(code, 3)
        self.assertEqual(inv["skipped"][0]["why"], "upcoming_release 欄位不是布林")

    def test_dev_rolling_release_not_invented(self):
        w = World()
        w.add("dev/p", tc.files("p", "dev"))
        code, so, inv = self.gl(w)
        self.assertEqual(code, 3)                         # 沒有可監控的 Release；dev 滾動 Release 的收法是 T-03 的決定
        self.assertEqual(inv["releases"], [])
        self.assertEqual(len(inv["skipped"]), 1)

    def test_link_to_other_host_refused_and_not_followed(self):
        w = World()
        w.extra_links["p/v1"] = [{"id": 99, "name": "sbom-p-v1.cdx.json", "link_type": "other",
                                  "url": "https://evil.example.test/api/v4/projects/7/packages/generic/p/v1/sbom-p-v1.cdx.json"}]
        w.add("p/v1", {k: v for k, v in tc.files().items() if "cdx" not in k})
        code, so, inv = self.gl(w)
        self.assertEqual(code, 3)
        probs = inv["releases"][0]["problems"]
        self.assertTrue(any("不是本專案 Generic Package" in p for p in probs), probs)
        self.assertFalse([u for u, _ in w.requests if "evil" in u])

    def test_link_refusals(self):
        bad = [PKG.replace("/projects/7/", "/projects/8/") + "p/v1/x.json",                    # 別的專案
               BASE + "/projects/7/releases/p/v1/downloads/x.json",                            # 不是 Generic Package
               PKG + "p/v1/x.json?x=1", PKG + "p/v1/x.json#f", PKG + "p/v1/%2e%2e", PKG + "p/v1/a/b",
               PKG + "p/v1/", PKG + "p/v1/.hidden", "http://gitlab.example.com/api/v4/projects/7/packages/generic/p/v1/x.json",
               "https://gitlab.example.com:8443/api/v4/projects/7/packages/generic/p/v1/x.json",
               "https://user" + chr(64) + "gitlab.example.com/api/v4/projects/7/packages/generic/p/v1/x.json",
               "https://gitlab.example.com/other/api/v4/projects/7/packages/generic/p/v1/x.json", None, 5]
        src = collect.GitLabSource(PROJ, BASE, TOKEN, None, 1000)
        for u in bad:
            self.assertIsNone(src._package_file(u), u)
        self.assertEqual(src._package_file(PKG + "p/v1/sbom-p-v1.cdx.json"), "sbom-p-v1.cdx.json")

    def test_link_name_not_used_as_path(self):
        w = World()
        w.add("p/v1", tc.files())
        for l in w.entries[0]["assets"]["links"]:
            l["name"] = "../../evil"
        code, so, inv = self.gl(w)
        self.assertEqual(code, 0, so)
        self.assertEqual(inv["releases"][0]["problems"], [])
        for root, _, fs in os.walk(os.path.join(self._td.name)):
            self.assertNotIn("evil", root)

    def test_redirect_on_download_not_followed(self):
        w = World()
        w.add("p/v1", tc.files())
        url = PKG + "p/v1/release-meta.json"
        w.hooks[url] = lambda req: (_ for _ in ()).throw(tc.redirect(url, 302, "https://objects.example.test/blob"))
        code, so, inv = self.gl(w)
        self.assertEqual(code, 3)
        self.assertIn("轉址（不跟隨）", inv["releases"][0]["problems"][0])
        self.assertFalse([u for u, _ in w.requests if "objects.example" in u])

    def test_api_redirect_not_followed(self):
        w = World()
        w.hooks[BASE + "/projects/7/releases?per_page=100"] = lambda req: (_ for _ in ()).throw(
            tc.redirect(req.full_url, 302, "https://evil.example.test/"))
        code, so, inv = self.gl(w)
        self.assertEqual(code, 1)
        self.assertIn("轉址", inv["detail"])

    def test_size_limit_streaming_and_content_length(self):
        w = World()
        files = tc.files(layered=False)
        files["layers.json"] = b"[" + b"1," * 600000 + b"1]"
        w.add("p/v1", files)
        code, so, inv = self.gl(w, ["--max-asset-mb", "0.5"])
        self.assertEqual(code, 3)
        self.assertTrue(any("超過大小上限" in p for p in inv["releases"][0]["problems"]), inv["releases"][0]["problems"])
        self.assertEqual(sorted(inv["releases"][0]["sboms"]), ["product"])      # 其他附件不受影響
        w2 = World()
        w2.add("p/v1", tc.files())
        url = PKG + "p/v1/layers.json"
        w2.hooks[url] = lambda req: tc.Resp(b"{}", {"Content-Length": "999999999"})
        code, so, inv = self.gl(w2, ["--max-asset-mb", "1"])
        self.assertTrue(any("Content-Length" in p for p in inv["releases"][0]["problems"]))

    def test_duplicate_file_name_is_problem(self):
        w = World()
        w.add("p/v1", tc.files())
        dup = dict(w.entries[0]["assets"]["links"][0])
        dup["id"] = 500
        w.entries[0]["assets"]["links"].append(dup)
        code, so, inv = self.gl(w)
        self.assertTrue(any("同名重複" in p for p in inv["releases"][0]["problems"]))

    def test_token_never_in_output_or_inventory(self):
        w = World()
        w.hooks[BASE + "/projects/7/releases?per_page=100"] = lambda req: (_ for _ in ()).throw(
            urllib.error.URLError("fail " + TOKEN))
        code, so, inv = self.gl(w)
        self.assertEqual(code, 1)
        self.assertNotIn(TOKEN, so)
        self.assertNotIn(TOKEN, json.dumps(inv))
        w = World()
        w.add("p/v1", tc.files())
        code, so, inv = self.gl(w)
        self.assertNotIn(TOKEN, so + json.dumps(inv))

    def test_token_from_gitlab_token_env_only(self):
        w = World()
        w.add("p/v1", tc.files())
        self.gl(w, env={"GITLAB_TOKEN": "", "GH_TOKEN": tc.TOKEN})
        self.assertTrue(all("private-token" not in h for _, h in w.requests))
        self.assertTrue(all(tc.TOKEN not in str(h) for _, h in w.requests))

    def test_bad_token_chars_no_request(self):
        w = World()
        code, so, inv = self.gl(w, env={"GITLAB_TOKEN": "a b\nc"})
        self.assertEqual(code, 1)
        self.assertEqual(w.requests, [])

    def test_no_absolute_paths_in_inventory(self):
        w = World()
        w.add("p/v1", tc.files())
        code, so, inv = self.gl(w)
        self.assertNotIn(self._td.name, json.dumps(inv))


class TestGitLabUsage(Base):
    def usage(self, args):
        code, so = tc.go([*args, "--out", self.out], {"GITLAB_TOKEN": TOKEN}, World())
        self.assertEqual(code, 64, args)
        self.assertEqual(so, "")

    def test_usage_errors(self):
        self.usage(["--backend", "gitlab"])
        self.usage(["--backend", "gitlab", "--gitlab-url", BASE])
        self.usage(["--backend", "gitlab", "--project", "7"])
        self.usage(["--backend", "gitlab", "--gitlab-url", BASE, "--project", "a/b"])
        self.usage(["--backend", "gitlab", "--gitlab-url", "http://gitlab.example.com/api/v4", "--project", "7"])
        self.usage(["--backend", "gitlab", "--gitlab-url", "https://gitlab.example.com", "--project", "7"])
        self.usage(["--backend", "gitlab", "--gitlab-url", BASE + "?x=1", "--project", "7"])
        self.usage(["--backend", "gitlab", "--gitlab-url", BASE, "--project", "7", "--repo", "o/r"])
        self.usage(["--backend", "gitlab", "--gitlab-url", BASE, "--project", "7", "--from-dir", "x"])
        self.usage(["--repo", "o/r", "--project", "7"])
        self.usage(["--repo", "o/r", "--gitlab-url", BASE])
        self.usage(["--backend", "svn", "--repo", "o/r"])
        self.usage([])

    def test_loopback_http_allowed(self):
        w = World()
        code, so = tc.go(["--backend", "gitlab", "--gitlab-url", "http://127.0.0.1:9/api/v4", "--project", "7", "--out", self.out],
                         {}, w)
        self.assertNotEqual(code, 64)


if __name__ == "__main__":
    unittest.main()
