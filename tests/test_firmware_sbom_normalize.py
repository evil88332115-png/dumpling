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

    def test_license_change_records_whether_component_properties_existed(self):
        # 還原用：副本的 properties 一律是陣列，原檔可能沒有這個鍵、是 null 或空陣列，三者在副本裡分不出來，所以紀錄原本的狀態
        for before, setter in (("absent", None), ("null", None), ("array", [])):
            d = doc14(bad=True)
            if before != "absent":
                d["components"][0]["properties"] = setter
            rec = fsn.normalize(d, SHA)
            self.assertEqual(rec["changes"][0]["component_properties_before"], before)
        self.assertEqual([fsn.key_state({"a": 1}, "a"), fsn.key_state({"a": {}}, "a"), fsn.key_state({}, "a"), fsn.key_state(None, "a"),
                          fsn.key_state({"a": None}, "a"), fsn.key_state({"a": []}, "a"), fsn.key_state({"a": "x"}, "a")],
                         ["int", "object", "absent", "absent", "null", "array", "str"])

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


class AuditRecord(unittest.TestCase):
    """normalize.json 的稽核內容：位置、無法正規化的原因、雜湊的固定向量。"""

    def test_canonical_sha256_fixed_vector(self):
        # 標準 JSON：sort_keys、分隔符 , :、ensure_ascii=False、UTF-8。期望值是對下面這串位元組直接算的 SHA-256（不經 json.dumps）
        value = {"b": "\u00e9", "a": [1, "\u754c", None, True, 1.5]}
        want = '{"a":[1,"\u754c",null,true,1.5],"b":"\u00e9"}'.encode("utf-8")
        self.assertEqual(hashlib.sha256(want).hexdigest(), "bc9e8853e8a022c63fea7e24e21eed563fade186a441ce745eb0c6f097d38831")
        self.assertEqual(fsn.canonical_sha256(value), "bc9e8853e8a022c63fea7e24e21eed563fade186a441ce745eb0c6f097d38831")
        self.assertEqual(fsn.canonical_sha256({"a": 1, "b": 2}), fsn.canonical_sha256({"b": 2, "a": 1}))     # 鍵順序不影響
        # ensure_ascii=True 的寫法會得到不同的雜湊（固定不用）
        self.assertNotEqual(fsn.canonical_sha256("\u754c"), hashlib.sha256(json.dumps("\u754c").encode()).hexdigest())
        self.assertEqual(fsn.canonical_sha256("\u754c"), hashlib.sha256('"\u754c"'.encode("utf-8")).hexdigest())
        # 不能序列化就是 None，不丟例外
        self.assertIsNone(fsn.canonical_sha256(object()))

    def test_top_level_to_points_after_existing_properties(self):
        d = doc14(platform="x", firmware_version="y")                       # metadata.properties 原本有 1 個
        rec = fsn.normalize(d, SHA)
        self.assertEqual([(c["rule"], c["from"], c["to"], c["property"]) for c in rec["changes"]],
                         [("top-level-extra-field", "/platform", ["/metadata/properties/1"], ["dumpling:supplier-extra:platform"]),
                          ("top-level-extra-field", "/firmware_version", ["/metadata/properties/2"], ["dumpling:supplier-extra:firmware_version"])])
        d = doc14(platform="x")
        d["metadata"]["properties"] = None
        rec = fsn.normalize(d, SHA)
        self.assertEqual(rec["changes"][0]["to"], ["/metadata/properties/0"])
        d = doc14(platform="x")
        del d["metadata"]
        rec = fsn.normalize(d, SHA)
        self.assertEqual(rec["changes"][0]["to"], ["/metadata/properties/0"])

    def test_unnormalized_rule_at_reason(self):
        d = doc14(platform="x" * (fsn.MAX_VALUE_BYTES + 1), **{"": 1, "ctl\x01": 1, "a" * 101: 1})
        rec = fsn.normalize(d, SHA)
        bad_name = "欄位名稱不合格（空、過長或含控制字元）"
        self.assertEqual(rec["unnormalized"], [
            {"rule": "top-level-extra-field", "at": "/platform", "reason": "值超過 8192 位元組上限或無法序列化"},
            {"rule": "top-level-extra-field", "at": "/", "reason": bad_name},
            {"rule": "top-level-extra-field", "at": "/ctl\x01", "reason": bad_name},
            {"rule": "top-level-extra-field", "at": "(欄位名稱過長或不是字串)", "reason": bad_name}])
        for u in rec["unnormalized"]:
            self.assertEqual(set(u), {"rule", "at", "reason"})
        # license 的無法正規化：值太大／總量上限
        d = doc14(bad=True)
        d["components"][0]["licenses"][1]["license"]["url"] = "http://x/" + "a" * fsn.MAX_VALUE_BYTES
        self.assertEqual(fsn.normalize(d, SHA)["unnormalized"],
                         [{"rule": "license-without-id-or-name", "at": "/components/0/licenses/1", "reason": "值超過 8192 位元組上限或無法序列化"}])
        old = fsn.MAX_CHANGES
        self.addCleanup(setattr, fsn, "MAX_CHANGES", old)
        fsn.MAX_CHANGES = 1
        d = doc14(a1="x", a2="y")
        self.assertEqual(fsn.normalize(d, SHA)["unnormalized"],
                         [{"rule": "top-level-extra-field", "at": "/a2", "reason": "超過搬移總量上限（262144 位元組或 1 筆）"}])

    def test_unnormalized_overflow_marker(self):
        d = doc14(**{"k%03d" % i: "x" * (fsn.MAX_VALUE_BYTES + 1) for i in range(fsn.MAX_UNNORMALIZED + 5)})
        un = fsn.normalize(d, SHA)["unnormalized"]
        self.assertEqual(len(un), fsn.MAX_UNNORMALIZED + 1)
        self.assertEqual(un[-1], {"rule": "more", "at": "", "reason": "無法正規化的項目超過 200，以下不列"})

    def test_nesting_deeper_than_limit_is_recorded_once(self):
        comp = {"type": "library", "name": "n0"}
        root = {"type": "library", "name": "root", "components": [comp]}
        for i in range(fsn.MAX_NEST + 20):
            nxt = {"type": "library", "name": "n%d" % (i + 1), "licenses": [{"license": {"url": "https://x/%d" % i}}]}
            comp["components"] = [nxt]
            comp = nxt
        d = doc14()
        d["components"] = [root]
        rec = fsn.normalize(d, SHA)
        self.assertEqual(rec["unnormalized"], [{"rule": "nesting-too-deep", "at": "/components" + "/0/components" * (fsn.MAX_NEST - 1) + "/0/components",
                                                "reason": "元件巢狀超過 100 層，以下不處理"}])
        self.assertEqual(rec["unnormalized"][0]["at"].count("/components"), fsn.MAX_NEST + 1)
        self.assertTrue(rec["applied"])
        self.assertEqual(len(rec["changes"]), 98)            # 第 3～100 層的 98 個元件有 license 項目；100 層以下不動
        self.assertEqual(rec["changes"][-1]["from"].count("/components"), fsn.MAX_NEST)
        # 超過 100 層的元件原樣留著
        cur = d["components"][0]
        for _ in range(fsn.MAX_NEST - 1):
            cur = cur["components"][0]
        self.assertEqual(cur["components"][0]["licenses"], [{"license": {"url": "https://x/%d" % (fsn.MAX_NEST - 2)}}])

    def test_component_properties_not_array_skip_path(self):
        for bad in ("oops", {"a": 1}, 5, True):
            d = doc14(bad=True, platform="x")
            d["components"][0]["properties"] = bad
            d["components"].append({"type": "library", "name": "ok", "licenses": [{"license": {"url": "https://ok/1"}}]})
            rec = fsn.normalize(d, SHA)
            self.assertEqual(rec["unnormalized"], [{"rule": "license-without-id-or-name", "at": "/components/0/licenses/1",
                                                    "reason": "元件的 properties 不是陣列，沒有地方放"}], repr(bad))
            self.assertEqual(d["components"][0]["properties"], bad)                                  # 不是陣列的元件原樣
            self.assertEqual(len(d["components"][0]["licenses"]), 3)
            # 同一份文件其他地方照常正規化
            self.assertEqual([c["from"] for c in rec["changes"]], ["/platform", "/components/2/licenses/0"], repr(bad))
            self.assertEqual(rec["changes"][1]["to"], ["/components/2/properties/0"])
            self.assertEqual(d["components"][2]["licenses"], [])
            self.assertTrue(rec["applied"])

    def test_top_level_fields_still_normalized_without_usable_components(self):
        for comps in ("absent", None, "x", {"a": 1}, [], [None, 1, "a"]):
            d = doc14(platform="P")
            if comps == "absent":
                del d["components"]
            else:
                d["components"] = comps
            rec = fsn.normalize(d, SHA)
            self.assertTrue(rec["applied"], repr(comps))
            self.assertEqual([(c["rule"], c["from"], c["to"]) for c in rec["changes"]],
                             [("top-level-extra-field", "/platform", ["/metadata/properties/1"])], repr(comps))
            self.assertEqual(rec["unnormalized"], [], repr(comps))
            self.assertNotIn("platform", d)
            if comps != "absent":
                self.assertEqual(d["components"], comps)               # components 本身不動


class RecordShape(unittest.TestCase):
    """normalize() 回傳的紀錄：每個鍵、早退路徑的內容逐一釘死。"""

    @staticmethod
    def base(**kw):
        r = {"schema": "firmware-sbom-normalize/1", "input_sha256": SHA, "spec_version": None, "supported": False, "applied": False,
             "changes": [], "unnormalized": [], "notes": []}
        r.update(kw)
        return r

    def test_not_an_object_root(self):
        for root in (None, [], "x", 1, True):
            self.assertEqual(fsn.normalize(root, SHA), self.base(notes=["根物件不是 JSON 物件，不處理"]), repr(root))

    def test_unsupported_or_odd_spec_version(self):
        note = "specVersion 不在支援範圍（1.4, 1.5, 1.6），不處理"
        for spec, shown in (("1.3", "1.3"), ("1.7", "1.7"), ("", ""), ("1.4 ", "1.4 "), ("x" * 20, "x" * 20)):
            d = {"bomFormat": "CycloneDX", "specVersion": spec, "platform": "p"}
            before = copy.deepcopy(d)
            self.assertEqual(fsn.normalize(d, SHA), self.base(spec_version=shown, notes=[note]), repr(spec))
            self.assertEqual(d, before)
        for spec in (None, 1.4, ["1.4"], {"a": 1}, "x" * 21, "1" * 100):               # 不是字串或超過 20 字元：spec_version 記 None
            d = {"bomFormat": "CycloneDX", "specVersion": spec, "platform": "p"}
            self.assertEqual(fsn.normalize(d, SHA), self.base(notes=[note]), repr(spec))
        d = {"bomFormat": "CycloneDX", "platform": "p"}                              # 沒有 specVersion
        self.assertEqual(fsn.normalize(d, SHA), self.base(notes=[note]))

    def test_supported_without_changes_and_with_changes(self):
        for spec in ("1.4", "1.5", "1.6"):
            d = doc14()
            d["specVersion"] = spec
            self.assertEqual(fsn.normalize(d, SHA), self.base(spec_version=spec, supported=True), spec)
        d = doc14(platform="P")
        rec = fsn.normalize(d, SHA)
        self.assertEqual(set(rec), {"schema", "input_sha256", "spec_version", "supported", "applied", "changes", "unnormalized", "notes"})
        self.assertEqual((rec["schema"], rec["input_sha256"], rec["spec_version"], rec["supported"], rec["applied"], rec["notes"]),
                         ("firmware-sbom-normalize/1", SHA, "1.4", True, True, []))
        self.assertEqual(set(rec["changes"][0]), {"rule", "from", "to", "property", "value_sha256"})
        self.assertEqual(rec["changes"][0]["value_sha256"], canon("P"))

    def test_bad_metadata_is_recorded_as_supported_but_untouched(self):
        for bad in ("m", [], 5, {"properties": "x"}, {"properties": {}}, {"properties": 1}):
            d = doc14(platform="x")
            d["metadata"] = bad
            before = copy.deepcopy(d)
            self.assertEqual(fsn.normalize(d, SHA),
                             self.base(spec_version="1.4", supported=True, notes=["metadata 或 metadata.properties 型別不對，沒有地方放紀錄，整份不處理"]), repr(bad))
            self.assertEqual(d, before)
        for ok in (None, {}, {"properties": None}, {"properties": []}):             # 這些可以放：照常正規化
            d = doc14(platform="x")
            d["metadata"] = ok
            self.assertTrue(fsn.normalize(d, SHA)["applied"], repr(ok))

    def test_exception_while_planning_leaves_document_untouched(self):
        d = doc14(bad=True, platform="x")
        before = copy.deepcopy(d)
        old = fsn._plan
        self.addCleanup(setattr, fsn, "_plan", old)

        def boom(*a, **k):
            raise ValueError("boom")
        fsn._plan = boom
        rec = fsn.normalize(d, SHA)
        self.assertEqual(rec, self.base(spec_version="1.4", supported=True, notes=["規劃時發生 ValueError，整份不處理"]))
        self.assertEqual(d, before)
        fsn._plan = lambda *a, **k: 1 // 0
        self.assertEqual(fsn.normalize(d, SHA)["notes"], ["規劃時發生 ZeroDivisionError，整份不處理"])
        self.assertEqual(d, before)

    def test_name_ok_boundaries(self):
        ok = fsn._name_ok
        self.assertTrue(ok("a"))
        self.assertTrue(ok("a b"))                  # 空白（0x20）合格
        self.assertTrue(ok(" "))
        self.assertTrue(ok("~"))                    # 0x7E
        self.assertTrue(ok("\u00e9\u754c"))         # 非 ASCII 合格
        self.assertTrue(ok("a" * fsn.MAX_NAME_LEN))
        self.assertFalse(ok("a" * (fsn.MAX_NAME_LEN + 1)))
        self.assertFalse(ok(""))
        self.assertFalse(ok("a\x1fb"))              # 0x1F 是控制字元
        self.assertFalse(ok("\x00"))
        self.assertFalse(ok("a\x7fb"))              # DEL
        self.assertFalse(ok("\n"))
        self.assertFalse(ok("\ud800"))              # 單獨代理字元
        for v in (None, 1, b"a", ["a"]):
            self.assertFalse(ok(v), repr(v))
        # 端到端：空白名稱的頂層欄位會被搬移，DEL 的不會
        d = doc14(**{"a b": 1, "a\x7fb": 2})
        rec = fsn.normalize(d, SHA)
        self.assertEqual([c["from"] for c in rec["changes"]], ["/a b"])
        self.assertEqual([u["at"] for u in rec["unnormalized"]], ["/a\x7fb"])


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
        self.assertEqual(out["metadata"]["component"]["type"], "firmware")      # prep 的根元件取代照常
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
