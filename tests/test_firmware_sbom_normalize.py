"""firmware_sbom_normalize.py（供應商 SBOM 上傳 DT 前的最小格式正規化）與它在 firmware_dt.py prep／report 的接線。
不連網、不起 Docker。CycloneDX 官方 schema 驗證在 tools/cra/tests/test_supplier_sbom_schema.py（需要 jsonschema，由 pytest 那一組跑）。"""
import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "pipeline", "lib", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fsn = _load("firmware_sbom_normalize")
fd = _load("firmware_dt")
SHA = "ab" * 32


def canon(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def rj(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def sha_of(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def doc14(bad=False, **extra):
    """bad=True：coreboot 的第二個 license 項目只有 url（已知違規，一處）。"""
    d = {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
         "metadata": {"properties": [{"name": "p0", "value": "v0"}]},
         "components": [
             {"type": "firmware", "name": "coreboot", "bom-ref": "a",
              "licenses": [{"license": {"id": "MIT"}}, {"license": {"name": "X"}}]},
             {"type": "library", "name": "nolic", "bom-ref": "b"}]}
    if bad:
        d["components"][0]["licenses"].insert(1, {"license": {"url": "https://spdx.org/licenses/exceptions.html"}})
    d.update(extra)
    return d


class Rules(unittest.TestCase):
    def test_top_level_extra_fields_moved_with_record(self):
        d = doc14(platform="Notebook X", firmware_version="v1", obj={"b": 1, "a": [1, 2]})
        rec = fsn.normalize(d, SHA)
        self.assertTrue(rec["applied"])
        for k in ("platform", "firmware_version", "obj"):
            self.assertNotIn(k, d)
        props = {p["name"]: p["value"] for p in d["metadata"]["properties"]}
        self.assertEqual(props["dumpling:supplier-extra:platform"], "Notebook X")          # 字串用原值
        self.assertEqual(props["dumpling:supplier-extra:obj"], '{"a":[1,2],"b":1}')         # 其他型別用標準 JSON
        self.assertEqual(props["dumpling:normalized-from-sha256"], SHA)
        self.assertEqual(props["dumpling:normalized-changes"], "3")
        self.assertEqual(props["p0"], "v0")                                                  # 原本的 property 保留
        by = {c["from"]: c for c in rec["changes"]}
        self.assertEqual(set(by), {"/platform", "/firmware_version", "/obj"})
        self.assertEqual(by["/platform"]["value_sha256"], canon("Notebook X"))
        self.assertEqual(by["/obj"]["value_sha256"], canon({"b": 1, "a": [1, 2]}))
        self.assertEqual(by["/platform"]["property"], ["dumpling:supplier-extra:platform"])
        # 新位置的指標指到真的 property
        for c in rec["changes"]:
            idx = int(c["to"][0].rsplit("/", 1)[1])
            self.assertEqual(d["metadata"]["properties"][idx]["name"], c["property"][0])

    def test_license_without_id_or_name_url_only(self):
        d = doc14(bad=True)
        rec = fsn.normalize(d, SHA)
        self.assertEqual(len(rec["changes"]), 1)
        ch = rec["changes"][0]
        self.assertEqual((ch["rule"], ch["from"], ch["to"], ch["property"]),
                         ("license-without-id-or-name", "/components/0/licenses/1", ["/components/0/properties/0"], ["dumpling:supplier-license-url"]))
        self.assertEqual(ch["value_sha256"], canon({"license": {"url": "https://spdx.org/licenses/exceptions.html"}}))
        c = d["components"][0]
        self.assertEqual(c["licenses"], [{"license": {"id": "MIT"}}, {"license": {"name": "X"}}])       # 有 id／name 的保留
        self.assertEqual(c["properties"], [{"name": "dumpling:supplier-license-url", "value": "https://spdx.org/licenses/exceptions.html"}])
        self.assertNotIn("name", [l["license"] for l in c["licenses"]][0])    # 沒有把 url 填成 name
        self.assertEqual(d["components"][1], {"type": "library", "name": "nolic", "bom-ref": "b"})

    def test_license_with_other_fields_kept_as_json(self):
        d = doc14(bad=True)
        d["components"][0]["licenses"][1] = {"license": {"url": "https://example.com/l", "text": {"content": "abc"}}}
        rec = fsn.normalize(d, SHA)
        self.assertEqual(rec["changes"][0]["property"], ["dumpling:supplier-license-url", "dumpling:supplier-license-entry"])
        props = {p["name"]: p["value"] for p in d["components"][0]["properties"]}
        self.assertEqual(props["dumpling:supplier-license-url"], "https://example.com/l")
        self.assertEqual(json.loads(props["dumpling:supplier-license-entry"]), {"url": "https://example.com/l", "text": {"content": "abc"}})
        # url 不是字串：只留整個物件
        d2 = doc14(bad=True)
        d2["components"][0]["licenses"][1] = {"license": {"url": 5}}
        fsn.normalize(d2, SHA)
        self.assertEqual([p["name"] for p in d2["components"][0]["properties"]], ["dumpling:supplier-license-entry"])

    def test_license_pointers_use_original_indices_and_nested_components(self):
        d = doc14(bad=True)
        lic = d["components"][0]["licenses"]
        lic.insert(0, {"license": {"url": "https://a.example/1"}})
        lic.append({"license": {"url": "https://a.example/2"}})
        d["components"][0]["components"] = [{"type": "library", "name": "n", "licenses": [{"license": {"url": "https://a.example/3"}}],
                                             "properties": [{"name": "keep", "value": "1"}]}]
        rec = fsn.normalize(d, SHA)
        self.assertEqual([c["from"] for c in rec["changes"]],
                         ["/components/0/licenses/0", "/components/0/licenses/2", "/components/0/licenses/4",
                          "/components/0/components/0/licenses/0"])
        self.assertEqual([c["to"][0] for c in rec["changes"]],
                         ["/components/0/properties/0", "/components/0/properties/1", "/components/0/properties/2",
                          "/components/0/components/0/properties/1"])
        self.assertEqual(len(d["components"][0]["licenses"]), 2)
        self.assertEqual(d["components"][0]["components"][0]["licenses"], [])     # 全部移走時留空陣列（schema 允許），不刪鍵
        self.assertEqual(d["components"][0]["components"][0]["properties"][0], {"name": "keep", "value": "1"})

    def test_pointer_escaping(self):
        d = doc14(**{"a/b~c": 1})
        rec = fsn.normalize(d, SHA)
        self.assertEqual(rec["changes"][0]["from"], "/a~1b~0c")

    def test_no_change_when_nothing_to_fix(self):
        d = doc14()
        before = copy.deepcopy(d)
        rec = fsn.normalize(d, SHA)
        self.assertFalse(rec["applied"])
        self.assertEqual(rec["changes"], [])
        self.assertEqual(d, before)                      # 完全不動，也不加 normalized-* property

    def test_unknown_violations_untouched(self):
        d = doc14(bad=True)
        c = d["components"][0]
        c["type"] = "bogus"                                                  # 不認得的違規
        c["licenses"] += [{"license": {"id": ""}}, {"license": {"name": ""}},      # 有 id／name 這個鍵（值不合格）≠ 缺
                          {"license": {}, "extra": 1},                               # 項目多一個鍵
                          {"expression": "MIT OR GPL-2.0-only"}, "str", 7, None, {"license": "x"}]
        c["x-unknown"] = 1
        d["components"][1]["licenses"] = "not-a-list"
        before = copy.deepcopy(d)
        rec = fsn.normalize(d, SHA)
        self.assertEqual(len(rec["changes"]), 1)         # 只有原本那一筆 url-only
        self.assertEqual(c["licenses"][-8:], before["components"][0]["licenses"][-8:])      # 認不得的項目一個字都沒動
        self.assertEqual(c["type"], "bogus")
        self.assertEqual(c["x-unknown"], 1)
        self.assertEqual(d["components"][1]["licenses"], "not-a-list")

    def test_unsupported_spec_versions_untouched(self):
        for sv in ("1.2", "1.3", "1.7", "2.0", "", None, 1.4, ["1.4"]):
            d = doc14(platform="x")
            d["specVersion"] = sv
            before = copy.deepcopy(d)
            rec = fsn.normalize(d, SHA)
            self.assertFalse(rec["applied"], sv)
            self.assertEqual(d, before, sv)
            self.assertTrue(rec["notes"])

    def test_15_and_16_top_level_keys(self):
        for sv in ("1.5", "1.6"):
            d = doc14(properties=[{"name": "ok", "value": "1"}], annotations=[], platform="x")
            d["specVersion"] = sv
            fsn.normalize(d, SHA)
            self.assertIn("properties", d)               # 該版本合法的頂層欄位不搬
            self.assertIn("annotations", d)
            self.assertNotIn("platform", d)
        d = doc14(declarations={}, vulnerabilities=[], signature={})
        fsn.normalize(d, SHA)
        self.assertEqual(sorted(k for k in ("declarations", "vulnerabilities", "signature") if k in d), ["signature", "vulnerabilities"])

    def test_metadata_missing_is_created_and_bad_metadata_untouched(self):
        d = doc14(platform="x")
        del d["metadata"]
        fsn.normalize(d, SHA)
        self.assertEqual(d["metadata"]["properties"][0], {"name": "dumpling:supplier-extra:platform", "value": "x"})
        for bad in ("m", [], {"properties": "x"}, {"properties": {}}):
            d = doc14(platform="x")
            d["metadata"] = bad
            before = copy.deepcopy(d)
            rec = fsn.normalize(d, SHA)
            self.assertFalse(rec["applied"])
            self.assertEqual(d, before)

    def test_component_properties_not_list_is_unnormalized(self):
        d = doc14(bad=True)
        d["components"][0]["properties"] = "oops"
        before = copy.deepcopy(d)
        rec = fsn.normalize(d, SHA)
        self.assertFalse(rec["applied"])
        self.assertEqual(d, before)
        self.assertEqual([u["rule"] for u in rec["unnormalized"]], ["license-without-id-or-name"])
        self.assertEqual(rec["unnormalized"][0]["at"], "/components/0/licenses/1")


class Limits(unittest.TestCase):
    def test_value_too_big_not_moved(self):
        d = doc14(platform="x" * (fsn.MAX_VALUE_BYTES + 1), firmware_version="ok")
        rec = fsn.normalize(d, SHA)
        self.assertIn("platform", d)                     # 原樣留著（DT 會拒收，報告照實 FAIL）
        self.assertNotIn("firmware_version", d)
        self.assertEqual([c["from"] for c in rec["changes"]], ["/firmware_version"])
        self.assertEqual([u["at"] for u in rec["unnormalized"]], ["/platform"])
        d = doc14(big=["x" * 100] * 200)                 # 序列化後超過上限
        rec = fsn.normalize(d, SHA)
        self.assertIn("big", d)
        self.assertEqual(rec["unnormalized"][0]["at"], "/big")
        self.assertFalse(rec["applied"])
        # 大小以位元組計：多位元組字元
        d = doc14(platform="界" * (fsn.MAX_VALUE_BYTES // 3 + 1))
        fsn.normalize(d, SHA)
        self.assertIn("platform", d)

    def test_license_url_too_big_not_moved(self):
        d = doc14(bad=True)
        d["components"][0]["licenses"][1]["license"]["url"] = "http://x/" + "a" * (fsn.MAX_VALUE_BYTES + 1)
        before = copy.deepcopy(d)
        rec = fsn.normalize(d, SHA)
        self.assertFalse(rec["applied"])
        self.assertEqual(d, before)
        self.assertEqual(rec["unnormalized"][0]["rule"], "license-without-id-or-name")

    def test_total_and_count_limits(self):
        old = (fsn.MAX_TOTAL_BYTES, fsn.MAX_CHANGES)
        self.addCleanup(lambda: (setattr(fsn, "MAX_TOTAL_BYTES", old[0]), setattr(fsn, "MAX_CHANGES", old[1])))
        fsn.MAX_TOTAL_BYTES = 25
        d = doc14(**{"f%d" % i: "0123456789" for i in range(5)})
        rec = fsn.normalize(d, SHA)
        self.assertEqual(len(rec["changes"]), 2)         # 25 位元組只放得下兩個 10 位元組的值
        self.assertEqual(len(rec["unnormalized"]), 3)
        self.assertEqual(sum(1 for k in d if k.startswith("f") and k != "firmware"), 3)
        fsn.MAX_TOTAL_BYTES, fsn.MAX_CHANGES = old[0], 3
        d = doc14(**{"g%d" % i: "x" for i in range(5)})
        d["components"][0]["licenses"] += [{"license": {"url": "https://u/%d" % i}} for i in range(5)]
        rec = fsn.normalize(d, SHA)
        self.assertEqual(len(rec["changes"]), 3)
        self.assertEqual(len(rec["changes"]) + len(rec["unnormalized"]), 10)

    def test_unnormalized_list_is_capped(self):
        d = doc14(**{"k%d" % i: "x" * (fsn.MAX_VALUE_BYTES + 1) for i in range(fsn.MAX_UNNORMALIZED + 50)})
        rec = fsn.normalize(d, SHA)
        self.assertLessEqual(len(rec["unnormalized"]), fsn.MAX_UNNORMALIZED + 1)

    def test_bad_field_names(self):
        d = doc14(**{"": 1, "a" * 101: 1, "ctl\x01": 1, "ok-name": 1, "\ud800": 1})
        rec = fsn.normalize(d, SHA)
        self.assertEqual([c["from"] for c in rec["changes"]], ["/ok-name"])
        self.assertEqual(len(rec["unnormalized"]), 4)
        self.assertEqual(len(json.dumps(rec, ensure_ascii=True)) < 5000, True)    # 紀錄裡不帶超長名稱

    def test_surrogate_value_not_moved(self):
        d = doc14(platform="a\ud800b")
        rec = fsn.normalize(d, SHA)
        self.assertIn("platform", d)
        self.assertEqual(rec["unnormalized"][0]["at"], "/platform")


class Hostile(unittest.TestCase):
    def test_deep_nested_value_and_components(self):
        v = cur = {}
        for _ in range(5000):
            cur["n"] = {}
            cur = cur["n"]
        d = doc14(deep=v)                                  # 超深的欄位值：序列化失敗或超限，不崩潰
        rec = fsn.normalize(d, SHA)
        self.assertIn("deep", d)
        self.assertEqual(rec["unnormalized"][0]["at"], "/deep")
        comp = {"type": "library", "name": "n0"}
        root = {"type": "library", "name": "root", "components": [comp]}
        for i in range(fsn.MAX_NEST + 20):
            nxt = {"type": "library", "name": "n%d" % (i + 1), "licenses": [{"license": {"url": "https://x/%d" % i}}]}
            comp["components"] = [nxt]
            comp = nxt
        d = doc14()
        d["components"] = [root]
        rec = fsn.normalize(d, SHA)
        self.assertTrue(any(u["rule"] == "nesting-too-deep" for u in rec["unnormalized"]))
        self.assertLessEqual(len(rec["changes"]), fsn.MAX_NEST)

    def test_odd_shapes_do_not_crash(self):
        shapes = [None, [], "x", 1, {"bomFormat": "CycloneDX"}, {"specVersion": "1.4"},
                  doc14(components=None), doc14(components="x"), doc14(components={"a": 1}), doc14(components=[None, 1, "a", [], {}]),
                  doc14(components=[{"licenses": None}, {"licenses": {}}, {"licenses": [[]]}, {"components": "x"}, {"components": [None]}]),
                  doc14(metadata=None, platform=1), doc14(**{"x" * 5000: 1})]
        for s in shapes:
            fsn.normalize(copy.deepcopy(s), SHA)
        d = doc14(components=[{"licenses": [{"license": {"url": "u"}}], "properties": None}])
        rec = fsn.normalize(d, SHA)                          # properties 為 null 視同沒有
        self.assertTrue(rec["applied"])
        self.assertEqual(d["components"][0]["properties"], [{"name": "dumpling:supplier-license-url", "value": "u"}])

    def test_many_licenses_linear(self):
        d = doc14()
        d["components"][0]["licenses"] = [{"license": {"url": "https://u/%d" % i}} for i in range(1500)]
        rec = fsn.normalize(d, SHA)
        self.assertEqual(len(rec["changes"]), 1500)
        self.assertEqual(d["components"][0]["licenses"], [])


class PrepIntegration(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = self._td.name
        self.addCleanup(self._td.cleanup)

    def w(self, rel, text):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text if isinstance(text, str) else json.dumps(text))
        return p

    def prep(self, doc, kind="sbom", out="prep", extra=""):
        yml = self.w("firmware/%s/sup-box/firmware.yml" % kind, "kind: %s\nvendor: Acme\nmodel: Box\nstatus: ok\nfirmware_version: v1\n%s" % (kind, extra))
        src = self.w("in/s.json", doc)
        o = os.path.join(self.tmp, out)
        return fd.prep(src, yml, o), o, src

    def test_sbom_kind_normalized_copy_original_untouched(self):
        d = doc14(bad=True, platform="Notebook X")
        info, o, src = self.prep(d)
        sha_in = sha_of(src)
        out = rj(os.path.join(o, "sbom.cdx.json"))
        self.assertNotIn("platform", out)
        self.assertEqual(len(out["components"][0]["licenses"]), 2)
        props = {p["name"]: p["value"] for p in out["metadata"]["properties"]}
        self.assertEqual(props["dumpling:normalized-from-sha256"], sha_in)
        self.assertEqual(props["dumpling:normalized-changes"], "2")
        self.assertEqual(out["metadata"]["component"]["type"], "firmware")      # prep 原本的行為不變
        rec = rj(os.path.join(o, "normalize.json"))
        self.assertEqual(rec["input_sha256"], sha_in)
        self.assertEqual(len(rec["changes"]), 2)
        self.assertEqual(info["normalize"], {"file": "normalize.json", "applied": True, "changes": 2, "unnormalized": 0})
        self.assertEqual(info["input_sbom_sha256"], sha_in)
        self.assertEqual(rj(src), d)               # 原檔沒動
        self.assertEqual(sha_of(src), sha_in)
        self.assertEqual(info["summary"]["components"], 2)                          # 元件數不變

    def test_sbom_kind_without_violations_has_empty_record(self):
        d = doc14()
        info, o, _ = self.prep(d)
        out = rj(os.path.join(o, "sbom.cdx.json"))
        self.assertNotIn("dumpling:normalized-changes", json.dumps(out))
        rec = rj(os.path.join(o, "normalize.json"))
        self.assertEqual((rec["applied"], rec["changes"]), (False, []))
        self.assertEqual(info["normalize"]["changes"], 0)

    def test_bios_kind_not_normalized_and_stale_record_removed(self):
        d = doc14(platform="x")
        self.w("prep/normalize.json", "{}")
        info, o, _ = self.prep(d, kind="bios")
        out = rj(os.path.join(o, "sbom.cdx.json"))
        self.assertIn("platform", out)                   # 只對 kind: sbom 的供應商 SBOM 做
        self.assertFalse(os.path.exists(os.path.join(o, "normalize.json")))
        self.assertIsNone(info["normalize"])

    def test_report_mentions_normalization(self):
        info, o, _ = self.prep(doc14(bad=True, platform="x"))
        lines, failed = fd.report([o], None, os.path.join(self.tmp, "rep"))
        self.assertIn("已正規化 2 處（見 normalize.json", lines[0])
        with open(os.path.join(self.tmp, "rep", "firmware-dt.md"), encoding="utf-8") as fh:
            self.assertIn("已正規化 2 處", fh.read())
        # 無法正規化的也要說
        d = doc14(bad=True, platform="x" * (fsn.MAX_VALUE_BYTES + 1))
        info, o2, _ = self.prep(d, out="prep2")
        lines, _ = fd.report([o2], None, os.path.join(self.tmp, "rep2"))
        self.assertIn("已正規化 1 處", lines[0])
        self.assertIn("另有 1 處已知違規無法正規化", lines[0])

    def test_prep_cli_line(self):
        info, o, src = self.prep(doc14(bad=True))
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = fd.main(["prep", "--sbom", src, "--sample", os.path.join(self.tmp, "firmware/sbom/sup-box/firmware.yml"), "--out", os.path.join(self.tmp, "o3")])
        self.assertEqual(rc, 0)
        self.assertIn("已正規化 1 處", buf.getvalue())

    def test_declared_rejected_still_works_with_normalization(self):
        info, o, _ = self.prep(doc14(bad=True), extra='expected_dt:\n  upload: rejected\n  reason: "x"\n')
        self.assertEqual(info["expected_dt"]["upload"], "rejected")
        self.assertEqual(info["normalize"]["changes"], 1)


if __name__ == "__main__":
    unittest.main()
