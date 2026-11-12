import json, os, subprocess, sys, unittest
from datetime import datetime, timezone
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(HERE, ".."))
import sbomgate as sg
EV = os.path.join(ROOT, "tests", "results", "round1-variants-20261022")
NOW = datetime(2026, 10, 22, 3, 0, tzinfo=timezone.utc)


def j(name):
    with open(os.path.join(EV, name), encoding="utf-8") as f:
        return json.load(f)


def man(path):
    return sg.read_manifest(os.path.join(ROOT, path))




class Synthetic(unittest.TestCase):
    @staticmethod
    def comp(name, ver="1.0", purl=None, **kw):
        c = {"type": "library", "name": name, "version": ver, "purl": purl or f"pkg:pypi/{name.lower()}@{ver}"}
        c.update(kw)
        return c

    @staticmethod
    def match(name, ver, vid="GHSA-x", purl=None):
        return {"vulnerability": {"id": vid}, "artifact": {"name": name, "version": ver, "purl": purl or f"pkg:pypi/{name.lower()}@{ver}"}}

    GRYPE_OK = {"descriptor": {"db": {"status": {"built": "2026-10-21T06:31:02Z"}}}}

    def grype(self, matches):
        g = json.loads(json.dumps(self.GRYPE_OK)); g["matches"] = matches; return g

    def test_no_grype_is_not_run(self):
        r = sg.run({"components": [self.comp("a")]}, None, None, "full", NOW)
        self.assertEqual(r["vulnerability_analysis"]["status"], "NOT_RUN")

    def test_unmapped_match_kept_and_partial(self):
        r = sg.run({"components": [self.comp("a")]}, self.grype([self.match("zzz", "9")]), None, "full", NOW)
        self.assertEqual(len(r["unmapped_matches"]), 1)
        self.assertEqual(r["vulnerability_analysis"]["status"], "PARTIAL")

    def test_mixed_unknown_without_counterpart_is_partial(self):
        lb = self.comp("b", "2.0", properties=[{"name": "cdx:pypi:versionSpecifiers", "value": ">=2.0"}],
                       evidence={"identity": [{"confidence": 0.5, "methods": [{"technique": "manifest-analysis"}]}]})
        r = sg.run({"components": [self.comp("a"), lb]}, self.grype([self.match("b", "2.0")]), None, "full", NOW)
        self.assertEqual(r["vulnerability_analysis"]["status"], "PARTIAL")
        self.assertEqual(len(r["excluded_matches"]), 1)

    def test_range_marker_with_instrumentation_is_resolved(self):
        c = self.comp("a", "1.0", properties=[{"name": "cdx:pypi:versionSpecifiers", "value": ">=1"}],
                      evidence={"identity": [{"confidence": 1, "methods": [{"technique": "instrumentation"}]}]})
        self.assertEqual(sg.classify_component(c)[0], "RESOLVED")

    def test_evidence_identity_as_object_and_garbage(self):
        c = self.comp("a", properties=[{"name": "cdx:pypi:versionSpecifiers", "value": ">=1"}], evidence={"identity": {"confidence": 0.5, "methods": [{"technique": "manifest-analysis"}]}})
        self.assertEqual(sg.classify_component(c)[0], "VERSION_FROM_RANGE")
        for ev in (None, [], "x", {"identity": "x"}, {"identity": [1, None]}):
            c2 = self.comp("a", properties=[{"name": "cdx:pypi:versionSpecifiers", "value": ">=1"}], evidence=ev)
            self.assertEqual(sg.classify_component(c2)[0], "VERSION_FROM_RANGE")   # 證據讀不懂：保守視為範圍

    def test_no_version(self):
        for v in (None, "", "  "):
            self.assertEqual(sg.classify_component({"name": "a", "version": v})[0], "NO_VERSION")

    def test_file_entries_ignored(self):
        r = sg.run({"components": [{"type": "file", "name": "/abs/package-lock.json"}]}, None, None, "full", NOW)
        self.assertEqual(r["sbom"]["status"], "EMPTY")
        self.assertEqual(r["sbom"]["non_package_entries_ignored"], {"file": 1})

    def test_scoped_npm_group(self):
        c = {"type": "library", "group": "@scope", "name": "pkg", "version": "1.0.0", "purl": "pkg:npm/%40scope/pkg@1.0.0"}
        r = sg.run({"components": [c]}, None, ("npm", {"@scope/pkg"}, set(), 0), "full", NOW)
        self.assertEqual(r["sbom"]["status"], "OK")

    def test_pypi_name_normalisation(self):
        r = sg.run({"components": [self.comp("charset_normalizer", "3.5.2", "pkg:pypi/charset-normalizer@3.5.2")]},
                   None, ("pypi", {"charset-normalizer"}, set(), 0), "full", NOW)
        self.assertEqual(r["sbom"]["status"], "OK")

    def test_requirements_parser(self):
        req, _, unparsed = sg.parse_requirements("# c\nrequests>=2.0  # x\n-r other.txt\nPyYAML[extra]==5.3\n\n./local\nJinja2\n")
        self.assertEqual(req, {"requests", "pyyaml", "jinja2"})
        self.assertEqual(unparsed, 2)

    def test_package_json_dev_not_required(self):
        req, dev, un = sg.parse_package_json(json.dumps({"dependencies": {"a": "1"}, "devDependencies": {"b": "1"}}))
        self.assertEqual((req, dev, un), ({"a"}, {"b"}, 0))

    def test_db_unknown_date(self):
        r = sg.run({"components": [self.comp("a")]}, {"matches": []}, None, "full", NOW)
        self.assertEqual(r["grype_db"]["status"], "UNKNOWN")
        self.assertEqual(r["vulnerability_analysis"]["status"], "PARTIAL")

    def test_never_says_safe(self):
        r = sg.run({"components": [self.comp("a")]}, self.grype([]), None, "full", NOW)
        self.assertEqual(r["vulnerability_analysis"]["status"], "COMPLETE")
        self.assertEqual(r["vulnerability_analysis"]["valid_findings"], 0)
        s = json.dumps(r, ensure_ascii=False)
        for bad in ('"PASS"', '"SAFE"', '安全"'):
            self.assertNotIn(bad, s)


class ReviewRegressions(unittest.TestCase):
    """獨立審查（對抗式）找到的缺陷，每一項一個測試。"""
    C = staticmethod(Synthetic.comp)
    M = staticmethod(Synthetic.match)
    G = GRYPE_OK = Synthetic.GRYPE_OK

    def grype(self, matches, **kw):
        g = json.loads(json.dumps(self.G)); g["matches"] = matches; g.update(kw); return g

    LB = {"properties": [{"name": "cdx:pypi:versionSpecifiers", "value": ">=2.0"}],
          "evidence": {"identity": [{"confidence": 0.5, "methods": [{"technique": "manifest-analysis"}]}]}}

    def test_2_application_only_sbom_is_empty(self):
        for typ in ("application", "operating-system", "container", "file"):
            r = sg.run({"components": [{"type": typ, "name": "x", "version": "1.0"}]}, self.grype([]), None, "full", NOW)
            self.assertEqual(r["sbom"]["status"], "EMPTY", typ)
            self.assertEqual(r["vulnerability_analysis"]["status"], "NOT_ASSESSED", typ)

    def test_3_grype_without_matches_is_input_error(self):
        for g in ({"descriptor": {}}, {"matches": None}, {"matches": {}}, {"matches": "x"}):
            with self.assertRaises(sg.InputError):
                sg.run({"components": [self.C("a")]}, g, None, "full", NOW)

    def test_4_ignored_matches_passed_through(self):
        r = sg.run({"components": [self.C("a")]}, self.grype([], ignoredMatches=[self.M("a", "1.0", "CVE-1")]), None, "full", NOW)
        self.assertEqual(r["vulnerability_analysis"]["ignored_findings"], 1)
        self.assertEqual(r["ignored_matches"][0]["id"], "CVE-1")

    def test_5_same_key_resolved_wins_regardless_of_order(self):
        lb = self.C("requests", "2.0", **self.LB); rs = self.C("requests", "2.0")
        for order in ([lb, rs], [rs, lb]):
            r = sg.run({"components": order}, self.grype([self.M("requests", "2.0")]), None, "full", NOW)
            self.assertEqual((len(r["valid_matches"]), len(r["excluded_matches"])), (1, 0), order)

    def test_6_evidence_not_mixed_across_entries(self):
        c = self.C("a", "1.0", properties=[{"name": "cdx:pypi:versionSpecifiers", "value": ">=1"}],
                   evidence={"identity": [{"confidence": 0.5, "methods": [{"technique": "instrumentation"}]},
                                          {"confidence": 1, "methods": [{"technique": "manifest-analysis"}]}]})
        self.assertEqual(sg.classify_component(c)[0], "VERSION_FROM_RANGE")
        for conf in (True, "1", None):
            c2 = self.C("a", "1.0", properties=[{"name": "cdx:pypi:versionSpecifiers", "value": ">=1"}],
                        evidence={"identity": [{"confidence": conf, "methods": [{"technique": "instrumentation"}]}]})
            self.assertEqual(sg.classify_component(c2)[0], "VERSION_FROM_RANGE", conf)

    def test_7_ecosystem_is_part_of_identity(self):
        lb = self.C("requests", "2.0", **self.LB)
        npm = {"type": "library", "name": "requests", "version": "3.0.0", "purl": "pkg:npm/requests@3.0.0"}
        r = sg.run({"components": [lb, npm]}, self.grype([]), None, "full", NOW)
        self.assertFalse([c for c in r["component_details"] if c["purl"].startswith("pkg:pypi")][0].get("superseded_by_resolved"))
        self.assertEqual(r["vulnerability_analysis"]["status"], "PARTIAL")
        npm_lodash = {"type": "library", "name": "lodash", "version": "1.0", "purl": "pkg:npm/lodash@1.0"}
        r2 = sg.run({"components": [npm_lodash]}, self.grype([self.M("lodash", "1.0", purl="pkg:pypi/lodash@1.0")]), None, "full", NOW)
        self.assertEqual((len(r2["valid_matches"]), len(r2["unmapped_matches"])), (0, 1))

    def test_7_go_module_case_is_not_folded(self):
        a = {"type": "library", "name": "github.com/Foo/bar", "version": "v1.0.0", "purl": "pkg:golang/github.com/Foo/bar@v1.0.0"}
        r = sg.run({"components": [a]}, self.grype([self.M("github.com/foo/bar", "v1.0.0", purl="pkg:golang/github.com/foo/bar@v1.0.0")]), None, "full", NOW)
        self.assertEqual(len(r["unmapped_matches"]), 1)

    def test_maven_group_name_mapping(self):
        a = {"type": "library", "group": "org.x", "name": "a", "version": "1.0", "purl": "pkg:maven/org.x/a@1.0"}
        r = sg.run({"components": [a]}, self.grype([self.M("org.x:a", "1.0", purl="pkg:maven/org.x/a@1.0")]), None, "full", NOW)
        self.assertEqual(len(r["valid_matches"]), 1)

    def test_8_range_looking_versions(self):
        for v in (">=2.0", "2.*", "^1.2.3", "~1.2", "1.x", "x", "*", "latest", "UNKNOWN", ">=1,<2", "1.0 || 2.0"):
            self.assertNotEqual(sg.classify_component(self.C("a", v))[0], "RESOLVED", v)
        for v in ("1.0.0", "2026.10.19", "1.0.0-rc.1", "1.0.0+build5", "v1.2.3", "3.5.2"):
            self.assertEqual(sg.classify_component(self.C("a", v))[0], "RESOLVED", v)

    def test_9_empty_sbom_without_grype_is_not_assessed(self):
        r = sg.run({"components": []}, None, None, "full", NOW)
        self.assertEqual(r["vulnerability_analysis"]["status"], "NOT_ASSESSED")
        self.assertIn("規則 12", " ".join(r["vulnerability_analysis"]["reasons"]))

    def test_10_manifest_unparsed_makes_incomplete(self):
        req, dev, un = sg.parse_requirements("-r base.txt\n")
        r = sg.run({"components": [self.C("a")]}, self.grype([]), ("pypi", req, dev, un), "full", NOW)
        self.assertEqual(r["sbom"]["status"], "INCOMPLETE")
        self.assertEqual(r["vulnerability_analysis"]["status"], "PARTIAL")
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            mp = os.path.join(d, "requirements.txt")
            open(mp, "wb").write(b"\xef\xbb\xbfflask\nrequests\n")
            self.assertEqual(sg.read_manifest(mp)[1], {"flask", "requests"})   # 帶 BOM 的清單檔，第一個套件不能消失
        _, _, un2 = sg.parse_package_json(json.dumps({"dependencies": ["a", "b"]}))
        self.assertEqual(un2, 1)

    def test_nested_components_are_flattened(self):
        r = sg.run({"components": [{"type": "library", "name": "outer", "version": "1.0", "purl": "pkg:pypi/outer@1.0",
                                    "components": [self.C("inner")]}]}, self.grype([]), None, "full", NOW)
        self.assertEqual(r["sbom"]["components_total"], 2)

    def test_future_db_date_not_trusted(self):
        g = self.grype([], descriptor={"db": {"status": {"built": "2030-01-01T00:00:00Z"}}})
        r = sg.run({"components": [self.C("a")]}, g, None, "full", NOW)
        self.assertEqual(r["grype_db"]["status"], "UNKNOWN")
        self.assertEqual(r["vulnerability_analysis"]["status"], "PARTIAL")

    def test_1_odd_types_do_not_crash(self):
        weird_components = [None, 5, "x", [], {"name": 5}, {"name": "a", "version": [1]}, {"name": "a", "purl": 5},
                            {"name": "a", "properties": [{"name": ["x"]}]}, {"type": 5, "name": "a"},
                            {"name": "a", "version": "1.0", "evidence": 7}, {"name": "a", "components": "x"}]
        weird_matches = [None, 5, {"artifact": [1], "vulnerability": "x"}, {"artifact": {"name": 5, "version": [1]}},
                         {"artifact": {"purl": 5}}, {}]
        for g in (self.grype(weird_matches), self.grype([], descriptor="x"), self.grype([], descriptor={"db": "x"}),
                  self.grype([], ignoredMatches=[None, 5, {"artifact": 3}])):
            r = sg.run({"components": weird_components}, g, None, "full", NOW)
            self.assertIn(r["vulnerability_analysis"]["status"], ("COMPLETE", "PARTIAL", "NOT_ASSESSED"))
        for sb in ({"components": None}, {"components": {"a": 1}}, {"components": "x"}, {}):
            sg.run(sb, None, None, "full", NOW)
        r = sg.run({"components": [{"name": "", "version": "1.0", "purl": "pkg:pypi/x@1.0"}]}, self.grype([]), None, "full", NOW)
        self.assertEqual(r["components"]["UNIDENTIFIABLE"], 1)



class SecondRound(unittest.TestCase):
    """第二輪審查找到的新問題。"""
    C = staticmethod(Synthetic.comp)
    M = staticmethod(Synthetic.match)

    def grype(self, matches):
        g = json.loads(json.dumps(Synthetic.GRYPE_OK)); g["matches"] = matches; return g

    def test_hash_pinned_requirements_are_not_unparsed(self):
        text = "--index-url https://x\nflask==2.0 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\nrequests==2.0 --hash=sha256:cc\n"
        names, _, un = sg.parse_requirements(text)
        self.assertEqual((names, un), ({"flask", "requests"}, 0))
        _, _, un2 = sg.parse_requirements("-r base.txt\n-e .\nhttps://x/y.whl\n")
        self.assertEqual(un2, 3)

    def test_non_package_with_purl_downgrades(self):
        sb = {"components": [self.C("a"), {"type": "application", "name": "openssl", "version": "3.0", "purl": "pkg:deb/debian/openssl@3.0"}]}
        r = sg.run(sb, self.grype([]), None, "full", NOW)
        self.assertEqual(r["vulnerability_analysis"]["status"], "PARTIAL")
        self.assertIn("application", " ".join(r["vulnerability_analysis"]["reasons"]))

    def test_github_actions_are_reported_not_downgrading(self):
        act = {"type": "application", "name": "checkout", "version": "v4", "purl": "pkg:github/actions/checkout@v4",
               "properties": [{"name": "cdx:github:workflow:file", "value": ".github/workflows/ci.yml"}]}
        r = sg.run({"components": [self.C("a"), act, dict(act, purl="pkg:github/actions/checkout@v4")]}, self.grype([]), None, "full", NOW)
        va = r["vulnerability_analysis"]
        self.assertEqual(va["status"], "COMPLETE")
        self.assertEqual(r["sbom"]["ci_workflow_actions_not_assessed"], ["pkg:github/actions/checkout@v4"])
        self.assertEqual(r["sbom"]["non_package_entries_with_purl"], 0)
        self.assertTrue(any("GitHub Actions" in n and "未評估" in n for n in va["notes"]))

    def test_github_purl_on_other_types_still_downgrades(self):
        # 只有 application＋github 才算 CI 動作；其他型別帶 github purl、或 application 帶其他 purl，仍然降為 PARTIAL
        wf = [{"name": "cdx:github:workflow:file", "value": "w.yml"}]
        for c in ({"type": "file", "name": "x", "purl": "pkg:github/a/b@v1", "properties": wf},
                  {"type": "application", "name": "x", "purl": "pkg:npm/x@1", "properties": wf},
                  {"type": "application", "name": "x", "purl": "pkg:github/a/b@v1"},                      # 沒有 workflow 屬性
                  {"type": "application", "name": "x", "purl": "pkg:github/a/b@v1", "properties": [{"name": "other", "value": "1"}]}):
            r = sg.run({"components": [self.C("a"), c]}, self.grype([]), None, "full", NOW)
            self.assertEqual(r["vulnerability_analysis"]["status"], "PARTIAL", c)

    def test_only_github_actions_is_still_empty(self):
        act = {"type": "application", "name": "checkout", "purl": "pkg:github/actions/checkout@v4",
               "properties": [{"name": "cdx:github:action:uses", "value": "actions/checkout@v4"}]}
        r = sg.run({"components": [act]}, self.grype([]), None, "full", NOW)
        self.assertEqual(r["sbom"]["status"], "EMPTY")
        self.assertEqual(r["vulnerability_analysis"]["status"], "NOT_ASSESSED")

    def test_self_component_unversioned_not_gap(self):
        main_mod = {"type": "library", "name": "github.com/x/app", "version": "UNKNOWN", "purl": "pkg:golang/github.com/x/app"}
        dep = {"type": "library", "name": "github.com/y/lib", "version": "v1.0.0", "purl": "pkg:golang/github.com/y/lib@v1.0.0"}
        r0 = sg.run({"components": [main_mod, dep]}, self.grype([]), None, "full", NOW)
        self.assertEqual(r0["vulnerability_analysis"]["status"], "PARTIAL")          # 沒宣告 --self：照舊是 GAP
        r = sg.run({"components": [main_mod, dep]}, self.grype([]), None, "full", NOW, self_purls=["pkg:golang/github.com/x/app@v9"])
        self.assertEqual(r["vulnerability_analysis"]["status"], "COMPLETE")
        self.assertEqual(r["components"]["self_components_unversioned"], ["github.com/x/app"])
        self.assertTrue(any("--self" in n for n in r["vulnerability_analysis"]["notes"]))
        # --self 只豁免同名的元件；其他沒有版本的元件仍然是 GAP
        other = {"type": "library", "name": "github.com/z/other", "purl": "pkg:golang/github.com/z/other"}
        r2 = sg.run({"components": [main_mod, dep, other]}, self.grype([]), None, "full", NOW, self_purls=["pkg:golang/github.com/x/app"])
        self.assertEqual(r2["vulnerability_analysis"]["status"], "PARTIAL")
        # 生態系不同不算同一個
        r3 = sg.run({"components": [main_mod, dep]}, self.grype([]), None, "full", NOW, self_purls=["pkg:npm/github.com/x/app"])
        self.assertEqual(r3["vulnerability_analysis"]["status"], "PARTIAL")

    def test_self_hint_only_excludes_unmapped_unversioned_match(self):
        """--self-hint（專案檔的 name，不可信）：只排除對不上元件的無版本比對，不豁免元件；和元件同名時不採用。"""
        dep = {"type": "library", "name": "lib", "version": "1.0.0", "purl": "pkg:composer/acme/lib@1.0.0"}
        m = {"vulnerability": {"id": "GHSA-self"}, "artifact": {"name": "laravel/laravel", "version": "", "purl": "pkg:composer/laravel/laravel"}}
        r0 = sg.run({"components": [dep]}, self.grype([m]), None, "full", NOW)
        self.assertEqual(r0["vulnerability_analysis"]["status"], "PARTIAL")
        r = sg.run({"components": [dep]}, self.grype([m]), None, "full", NOW, self_hints=["pkg:composer/laravel/laravel"])
        self.assertEqual(r["vulnerability_analysis"]["status"], "COMPLETE")
        self.assertEqual(r["excluded_matches"][0]["self_source"], "--self-hint")
        # 不豁免元件：同名、版本未知的元件仍然是 GAP（提示和元件同名時整個不採用）
        lodash = {"type": "library", "name": "lodash", "purl": "pkg:npm/lodash"}
        r2 = sg.run({"components": [dep, lodash]}, self.grype([]), None, "full", NOW, self_hints=["pkg:npm/lodash"])
        self.assertEqual(r2["vulnerability_analysis"]["status"], "PARTIAL")
        self.assertEqual(r2["components"]["self_declared"]["--self-hint_rejected_same_name_as_component"], ["npm:lodash"])

    def test_self_hint_scoped_npm_encoded(self):
        dep = {"type": "library", "name": "x", "version": "1.0.0", "purl": "pkg:npm/x@1.0.0"}
        m = {"vulnerability": {"id": "GHSA-scope"}, "artifact": {"name": "@acme/web-app", "version": "", "purl": "pkg:npm/%40acme/web-app"}}
        r = sg.run({"components": [dep]}, self.grype([m]), None, "full", NOW, self_hints=["pkg:npm/%40acme/web-app"])
        self.assertEqual(r["vulnerability_analysis"]["status"], "COMPLETE")

    def test_self_with_version_is_matched_normally(self):
        app = {"type": "library", "name": "github.com/x/app", "version": "v1.2.0", "purl": "pkg:golang/github.com/x/app@v1.2.0"}
        m = {"vulnerability": {"id": "GO-1"}, "artifact": {"name": "github.com/x/app", "version": "v1.2.0", "purl": "pkg:golang/github.com/x/app@v1.2.0"}}
        r = sg.run({"components": [app]}, self.grype([m]), None, "full", NOW, self_purls=["pkg:golang/github.com/x/app"])
        self.assertEqual(r["components"]["self_components_unversioned"], [])
        self.assertEqual(r["components"]["RESOLVED"], 1)
        self.assertEqual(r["vulnerability_analysis"]["valid_findings"], 1)

    def test_unversioned_match_on_project_itself_is_excluded(self):
        dep = {"type": "library", "name": "lib", "version": "1.0.0", "purl": "pkg:composer/v/lib@1.0.0"}
        m = {"vulnerability": {"id": "GHSA-x"}, "artifact": {"name": "v/app", "version": "", "purl": "pkg:composer/v/app"}}
        sb = {"metadata": {"component": {"type": "application", "name": "app", "purl": "pkg:composer/v/app"}}, "components": [dep]}
        r = sg.run(sb, self.grype([m]), None, "full", NOW)
        va = r["vulnerability_analysis"]
        self.assertEqual((va["status"], va["excluded_findings"], va["unmapped_findings"]), ("COMPLETE", 1, 0))
        self.assertEqual(r["excluded_matches"][0]["excluded_reason"], "SELF_NO_VERSION")
        self.assertTrue(any("專案本身且沒有版本" in n for n in va["notes"]))
        # 沒有 metadata.component 也沒有 --self：照舊是對不上元件（PARTIAL）
        r2 = sg.run({"components": [dep]}, self.grype([m]), None, "full", NOW)
        self.assertEqual((r2["vulnerability_analysis"]["status"], r2["vulnerability_analysis"]["unmapped_findings"]), ("PARTIAL", 1))
        # 有版本的專案本身比對不屬於這個例外（找不到元件就仍是對不上）
        m2 = {"vulnerability": {"id": "GHSA-y"}, "artifact": {"name": "v/app", "version": "2.0", "purl": "pkg:composer/v/app@2.0"}}
        r3 = sg.run(sb, self.grype([m2]), None, "full", NOW)
        self.assertEqual(r3["vulnerability_analysis"]["unmapped_findings"], 1)

    def test_metadata_component_never_exempts_components(self):
        ok = {"type": "library", "name": "a", "version": "1.0", "purl": "pkg:composer/v/a@1.0"}
        fw = {"type": "library", "name": "framework", "purl": "pkg:composer/laravel/framework"}      # 真的沒有版本的依賴
        m = {"vulnerability": {"id": "GHSA-z"}, "artifact": {"name": "laravel/framework", "version": "", "purl": "pkg:composer/laravel/framework"}}
        sb = {"metadata": {"component": {"type": "application", "purl": "pkg:composer/laravel/framework"}}, "components": [ok, fw]}
        r = sg.run(sb, self.grype([m]), None, "full", NOW)
        va = r["vulnerability_analysis"]
        self.assertEqual(va["status"], "PARTIAL")                         # GAP 不可被不可信的 metadata.component 隱藏
        self.assertEqual(r["components"]["self_components_unversioned"], [])
        self.assertTrue(r["components"]["self_declared"]["metadata.component_rejected_same_name_as_component"])
        self.assertTrue(any("同名" in n for n in va["notes"]))
        # 同名時對它的無版本比對也不排除（對應到那個無版本元件，照規則 13 排除為 NO_VERSION）
        self.assertNotIn("SELF_NO_VERSION", [e.get("excluded_reason") for e in r["excluded_matches"]])

    def test_self_rejects_bad_purl(self):
        self.assertEqual(sg.main(["--sbom", os.devnull, "--self", "not-a-purl"]), 3)

    def test_floating_versions_not_resolved(self):
        for v in ("1.+", "1.2.+", "RELEASE", "main", "any", "dev-master", "5.x-dev", "@1.0", "master"):
            self.assertNotEqual(sg.classify_component(self.C("a", v))[0], "RESOLVED", v)

    def test_legit_versions_still_resolved(self):
        for v in ("1.0~rc1", "1!2.0", "1:2.3-4", "v0.0.0-20200101000000-abcdef123456", "1.0-SNAPSHOT", "2.3-4.el8", "1.0.0.Final", "1.0+build.5", "2.0.0-beta.1"):
            self.assertEqual(sg.classify_component(self.C("a", v))[0], "RESOLVED", v)
        self.assertEqual(sg.classify_component(self.C("a", "~1.2"))[0], "VERSION_FROM_RANGE")


    def test_maven_bare_artifact_name_matches_via_purl(self):
        c = {"type": "library", "group": "org.apache.logging.log4j", "name": "log4j-core", "version": "2.14.1",
             "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
        m = {"vulnerability": {"id": "CVE-2021-44228"}, "artifact": {"name": "log4j-core", "version": "2.14.1",
             "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}}
        r = sg.run({"components": [c]}, self.grype([m]), None, "full", NOW)
        self.assertEqual((len(r["valid_matches"]), len(r["unmapped_matches"])), (1, 0))

    def test_npm_scope_purl_matches_group_name(self):
        c = {"type": "library", "group": "@babel", "name": "core", "version": "7.0.0", "purl": "pkg:npm/%40babel/core@7.0.0"}
        m = {"vulnerability": {"id": "X"}, "artifact": {"name": "@babel/core", "version": "7.0.0", "purl": "pkg:npm/%40babel/core@7.0.0"}}
        r = sg.run({"components": [c]}, self.grype([m]), None, "full", NOW)
        self.assertEqual(len(r["valid_matches"]), 1)

    def test_flatten_limit_is_not_silent(self):
        with self.assertRaises(sg.InputError):
            sg.flatten([{"name": str(i)} for i in range(10)], limit=5)


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "..", "sbomgate.py"), *args], capture_output=True, text=True)
        return p.returncode, p.stdout, p.stderr


    def test_input_errors(self):
        for args in (["--sbom", "/no/such"], ["--sbom", __file__], ["--sbom", os.path.join(EV, "A2-cdxgen-npm.cdx.json"), "--manifest", "/x/other.yaml"],
                     ["--sbom", os.path.join(EV, "A2-cdxgen-npm.cdx.json"), "--now", "bad"]):
            rc, out, err = self.run_cli(*args)
            self.assertEqual(rc, 3, args)
            self.assertIn("輸入錯誤", err)

    def test_json_not_object(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("[1,2]"); path = f.name
        try:
            self.assertEqual(self.run_cli("--sbom", path)[0], 3)
        finally:
            os.unlink(path)


class MultipleManifests(unittest.TestCase):
    """--manifest 可重複（多生態系專案）：每個清單檔各自核對，任一個缺套件就是 INCOMPLETE。"""




if __name__ == "__main__":
    unittest.main()
