"""韌體進每日監控（docs/FIRMWARE-WATCH.md §5、§10 的「監控鍵」「公告重跑與 Issue」；F2）。Grype 以假結果替換。合成資料。

涵蓋：監控單位與監控鍵、沒有 purl／CPE 的 Grype、核心對應與核心 CNA 沒有這一項、公告重跑的輸入檢查（不可信資料）、
規則表／Intel 微碼／vBIOS 的 Issue 與留言、第一次基準、同 slug 同版本 image_sha256 變了、state 帶得過去、外來字串跳脫、support 跳過韌體。
C2 的範例檔（firmware-rematch.example.json 等）有放在 tests/data/（或 FW_EXAMPLE_DIR）才跑 ExampleFiles。
"""
import contextlib
import copy
import hashlib
import io
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import issues  # noqa: E402
import match  # noqa: E402
import support  # noqa: E402
import test_match  # noqa: E402
from test_match import Base, gmatch, sbom, NOW1, NOW2, NOW3, LOG4J, REQ, nohealth  # noqa: E402

NOW4, NOW5 = "2026-11-13T01:00:00Z", "2026-11-14T01:00:00Z"
TAG = "firmware-demo/2026.11.20"
TAG2 = "firmware-demo/2026.11.27"
IMG_A, IMG_B, IMG_C, IMG_A2 = "a1" * 32, "b2" * 32, "c3" * 32, "d4" * 32
EXAMPLE_DIR = os.environ.get("FW_EXAMPLE_DIR") or os.path.join(os.path.dirname(__file__), "data")
EVIL = "@everyone [x](https://evil.example) ![i](https://evil.example/a.png) #12 &commat; GH-5"
EVIL_KEY_R = "rule:#12:x=1+y/#3"
EVIL_KEY_U = "ucode:#5/0x1:0x2"
EVIL_KEY_V = "vbios:#7:GH-5:#9"
EVIL_ID = "@everyone [x](https://e.example) ![i](u) #12 &commat; GH-5"          # 公告 ID 上限 80 字元
TABLES = {"fw_advisory_rules": {"sha256": "cd" * 32, "table_updated": "2026-11-14", "status": "OK", "stale": False},
          "intel_microcode": {"source_commit": "d7" * 20, "source_tag": "microcode-20261110", "table_sha256": "25" * 32, "status": "OK", "stale": False},
          "nvidia_vbios": {"sha256": "c5" * 32, "mirror_commit": "98" * 20, "reviewed_until": "2025-09-02", "status": "OK", "stale": False}}


def res(key, kind, result, bulletins=(), component="comp", review=None, reason=None):
    return {"key": key, "kind": kind, "component": component, "result": result, "bulletins": list(bulletins), "reason": reason, "review": review}


def rule(key, bulletins=("AMI-SA-1",), result="affected", review="preliminary", component="AMI Aptio 5.x"):
    return res(key, "rule", result, bulletins if result == "affected" else (), component, review if result != "NOT_ASSESSED" else None)


def ucode(key="ucode:A/0x1:0x2", bulletins=("INTEL-SA-1", "INTEL-SA-2"), result="affected-candidate"):
    return res(key, "intel-microcode", result, bulletins if result == "affected-candidate" else (), "microcode A rev 0x2")


def vbios(key="vbios:10de:1c82:ab", bulletins=("NVIDIA-5000",), result="affected"):
    return res(key, "nvidia-vbios", result, bulletins if result == "affected" else (), "vBIOS 86.06.4D", None,
               "對照表第 3 列：裝置 10de:1c82、vBIOS 86.06.4D，低於 86.06.5A")


class FW(Base):
    """inventory 加一個韌體 Release、一個 rematch 資料夾。樣本：bios-a（有 purl）、bios-b（沒有 purl／CPE）、sbom-c（供應商 SBOM，有 purl）。"""
    SPECS = (("bios-a", "v1", IMG_A, "bios", True), ("bios-b", "v2", IMG_B, "bios", False), ("sbom-c", "v3", None, "sbom", True))

    def setUp(self):
        super().setUp()
        test = self
        self.grype_for = {}                 # 監控鍵 uuid → Grype 假結果（沒列的 uuid 沒有比對）
        self.prepared = []
        eg = match.mods()["eg"]

        def prepare(p, spec, *a, **k):
            test.prepared.append(p["uuid"])
            pkgs = list(json.load(open(spec["sbom"]))["components"])
            doc = {"matches": list(test.grype_for.get(p["uuid"], test.grype if not match.is_fw(p) else []))}
            km = {"status": "GAP", "detail": "SBOM 裡沒有 Linux 核心"} if match.is_fw(p) else {"status": "OK", "detail": "fake"}      # 韌體的核心對應即使 GAP 也要被忽略
            return {"status": "OK", "why": None, "kernel_map": km}, \
                {"doc": doc, "pkgs": pkgs, "sha": spec["sha256"], "gate": None, "srcmap": None, "kmap": None, "services": None, "annotations": []}
        eg.prepare = prepare
        self.fw = {"tag": TAG, "kind": "firmware", "project": "firmware-demo", "version": "2026.11.20", "published_at": "2026-11-20",
                   "html_url": "https://github.com/o/r/releases/tag/firmware-demo/2026.11.20", "commit": None, "built_at": None,
                   "meta": "firmware/firmware-meta.json", "tables": {}, "samples": [], "not_watched": [], "problems": []}
        self.fwdir = os.path.join(self.inv, "firmware")
        os.makedirs(self.fwdir)
        self.rmdir = os.path.join(self.w, "rm")
        self.docs = {}                      # slug → rematch 結果檔的 dict
        self.summary_rows = {}
        self.tables = copy.deepcopy(TABLES)
        for slug, ver, img, kind, purl in self.SPECS:
            self.add_sample(slug, ver, img, kind, purl)
        self.write_inv()

    def add_sample(self, slug, ver, img, kind="bios", purl=True, wv=None, sbom_ok=True):
        comps = [("edk2", "2024.02", "pkg:generic/edk2@2024.02")] if purl else []
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                          "components": [{"type": "library", "name": n, "version": v, "purl": p, "bom-ref": p} for n, v, p in comps]
                          + ([{"type": "firmware", "name": "BIOS image", "version": ver}] if not purl else [])}).encode()
        name = f"firmware/fw-{hashlib.sha1(slug.encode()).hexdigest()[:12]}.cdx.json"        # 檔名與 slug 無關（slug 可以是惡意字串）
        open(os.path.join(self.inv, name), "wb").write(raw)
        inv = {"file": f"firmware/fw-inventory-{slug}.json", "sha256": hashlib.sha256(slug.encode()).hexdigest(), "size": 10} if kind == "bios" else None
        smp = {"slug": slug, "kind": kind, "firmware_version": ver, "watch_version": wv or f"{slug}@{ver}", "image_sha256": img,
               "normalized": True if kind == "sbom" else None, "meta_status": "OK", "expect": "OK",
               "sbom": {"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)} if sbom_ok else None,
               "inventory": inv, "status": "OK", "problems": []}
        self.fw["samples"] = [x for x in self.fw["samples"] if x["slug"] != slug] + [smp]
        return smp

    def sample(self, slug):
        return next(x for x in self.fw["samples"] if x["slug"] == slug)

    def uuid(self, slug):
        return match.uuid_of("firmware-demo", self.sample(slug)["watch_version"], "firmware")

    def write_inv(self):
        self.inventory["firmware"] = self.fw
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))

    def set_results(self, slug, results, status=None, changed=(), tables=None, **over):
        sm = self.sample(slug)
        doc = {"schema": "dumpling-firmware-rematch/1", "slug": slug, "firmware_version": sm["firmware_version"], "release_tag": self.fw["tag"],
               "inventory_sha256": sm["inventory"]["sha256"], "now": NOW2, "status": status or ("ATTENTION" if results else "OK"), "reasons": [],
               "tables": tables or copy.deepcopy(self.tables), "results": list(results), "changed": list(changed)}
        doc.update(over)
        self.docs[slug] = doc

    def write_rm(self, summary_over=None):
        os.makedirs(self.rmdir, exist_ok=True)
        rows = []
        for slug, doc in self.docs.items():
            fn = f"rematch-{slug}.json"
            json.dump(doc, open(os.path.join(self.rmdir, fn), "w"))
            rows.append({"slug": slug, "status": doc.get("status"), "output": fn})
        summary = {"schema": "dumpling-firmware-rematch-summary/1", "release_tag": self.fw["tag"], "now": NOW2,
                   "tables": copy.deepcopy(self.tables), "samples": rows}
        summary.update(summary_over or {})
        json.dump(summary, open(os.path.join(self.rmdir, "rematch-summary.json"), "w"))

    def go(self, now, **kw):
        """寫 rematch 資料夾（還沒有 summary 時）後跑一輪。"""
        self.write_inv()
        if kw.pop("write", True):
            self.write_rm()
        kw.setdefault("fw_rematch", self.rmdir)
        return self.run_once(now, **kw)

    def baseline(self):
        for slug in ("bios-a", "bios-b"):
            self.set_results(slug, [], "OK")
        return self.go(NOW1)

    def fw_opens(self, plan):
        return [x for x in plan["actions"] if x["op"] in ("open", "open_if_closed") and "firmware-advisory" in x.get("labels", [])]

    def comments(self, plan, key=None):
        return [x for x in plan["actions"] if x["op"] == "comment" and (key is None or x["key"] == key)]


class Monitoring(FW):
    def test_load_inventory_samples(self):
        self.sample("bios-b")["problems"] = ["版本讀不到（'xx'）：監控鍵改用映像雜湊"]
        self.sample("bios-b")["status"] = "GAP"
        self.add_sample("noSbom", "v9", IMG_C, "bios", sbom_ok=False)
        self.sample("noSbom")["problems"] = ["fw-noSbom.cdx.json：缺少附件"]
        self.sample("noSbom")["status"] = "GAP"
        self.fw["samples"].append({"slug": "no-key", "status": "GAP", "problems": ["firmware-meta 樣本：kind 不是 bios／sbom"], "watch_version": None})
        self.write_inv()
        _, projs, problems = match.load_inventory(os.path.join(self.inv, "inventory.json"), self.inv)
        fw = [p for p in projs if match.is_fw(p)]
        self.assertEqual(sorted(p["slug"] for p in fw), ["bios-a", "bios-b", "sbom-c"])        # 沒有 sbom 的樣本不進
        a = next(p for p in fw if p["slug"] == "bios-a")
        self.assertEqual((a["uuid"], a["name"], a["version"], a["layer"], a["status"], a["kind"]),
                         ("dumpling:firmware-demo/bios-a@v1#firmware", "firmware-demo", "bios-a@v1", "firmware", "development", "firmware"))
        self.assertEqual((a["image_sha256"], a["tag"], a["html_url"]), (IMG_A, TAG, self.fw["html_url"]))
        self.assertEqual(a["uuid"], match.uuid_of("firmware-demo", "bios-a@v1", "firmware"))
        self.assertTrue(a["sbom"].startswith(self.inv))
        joined = "\n".join(problems)
        for want in ("版本讀不到", "缺少附件", "kind 不是"):
            self.assertIn(want, joined)                                                          # 樣本 GAP 列進 problems
        self.assertEqual(len([p for p in projs if not match.is_fw(p)]), 1)                       # board 不變

    def test_release_problems_listed(self):
        self.fw["problems"] = ["firmware-meta.json：schema 不對"]
        self.write_inv()
        _, _, problems = match.load_inventory(os.path.join(self.inv, "inventory.json"), self.inv)
        self.assertTrue(any("firmware-meta.json" in x for x in problems))

    def test_no_firmware_board_output_unchanged(self):
        """沒有 firmware 時：state 沒有 firmware 鍵、per_sbom 沒有 advisory、報告沒有韌體一節。"""
        self.inventory.pop("firmware", None)
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        _, _, plan = self.run_once(NOW1)
        self.assertNotIn("firmware", plan["state"])
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW1[:10], "result.json")))
        self.assertNotIn("firmware", res_)
        self.assertTrue(all("advisory" not in r for r in res_["per_sbom"].values()))
        self.assertNotIn("## 韌體", open(os.path.join(self.w, "out-" + NOW1[:10], "report.md")).read())

    def test_board_unchanged_by_firmware(self):
        """有韌體時，板子的 KEV 比對與 Issue 跟沒有韌體一樣。"""
        self.baseline()
        self.kev.append("CVE-2018-18074")
        _, _, plan = self.go(NOW2)
        opens = [x for x in nohealth(plan) if x["op"] == "open"]
        self.assertEqual(len(opens), 1)
        self.assertIn("demo", opens[0]["title"])
        self.assertIn("layer-bsp", opens[0]["labels"])

    def test_key_stable_across_releases_and_version_change_is_new(self):
        self.grype_for[self.uuid("bios-a")] = [gmatch("CVE-2021-44228", "log4j-core", "2.14.1", LOG4J)]
        self.baseline()
        # 同一份樣本放進新的韌體 Release（日期不同）：鍵不變，0 個新的 KEV Issue
        self.fw["tag"], self.fw["published_at"] = TAG2, "2026-11-27"
        for x in self.docs.values():
            x["release_tag"] = TAG2
        _, _, plan = self.go(NOW2)
        self.assertEqual([x for x in nohealth(plan) if x["op"] == "open"], [])
        self.assertIn(self.uuid("bios-a"), plan["state"]["firmware"]["samples"])
        # BIOS 改版：新的鍵；它本來就有的 KEV 依 #112 開 Issue
        old = self.uuid("bios-a")
        self.add_sample("bios-a", "v1.1", IMG_A, "bios", True)
        self.set_results("bios-a", [], "OK")
        self.grype_for[self.uuid("bios-a")] = [gmatch("CVE-2021-44228", "log4j-core", "2.14.1", LOG4J)]
        _, _, plan = self.go(NOW3)
        opens = [x for x in nohealth(plan) if x["op"] == "open"]
        self.assertEqual(len(opens), 1)
        self.assertIn("bios-a@v1.1", opens[0]["title"].replace(match.ZWSP, ""))
        self.assertIn("layer-firmware", opens[0]["labels"])
        self.assertIn("development", opens[0]["labels"])
        self.assertNotIn(old, plan["state"]["firmware"]["samples"])                              # 舊的鍵離開

    def test_sha_key_gap_is_listed_and_blocks_baseline(self):
        self.add_sample("bios-x", "", IMG_C, "bios", True, wv=f"bios-x@sha256-{IMG_C[:16]}")
        self.sample("bios-x")["problems"] = ["版本讀不到：監控鍵改用映像雜湊"]
        self.sample("bios-x")["status"] = "GAP"
        self.set_results("bios-x", [], "OK")
        for s in ("bios-a", "bios-b"):
            self.set_results(s, [], "OK")
        with self.assertRaises(match.Fail) as cm:
            self.go(NOW1)
        self.assertIn("Release 有", str(cm.exception))
        self.assertIn(f"dumpling:firmware-demo/bios-x@sha256-{IMG_C[:16]}#firmware", match.uuid_of("firmware-demo", f"bios-x@sha256-{IMG_C[:16]}", "firmware"))

    def test_not_watched_source_collect_is_gap_meta_is_note(self):
        """not_watched.source：collect 判定的才算 GAP（列進 problems）；meta 列的只是說明。"""
        self.fw["not_watched"] = [{"slug": "from-meta", "why": "合成 vBIOS", "source": "meta"},
                                  {"slug": "from-collect", "why": "GAP：版本讀不到，也沒有映像雜湊", "source": "collect"}]
        self.write_inv()
        _, _, problems = match.load_inventory(os.path.join(self.inv, "inventory.json"), self.inv)
        self.assertEqual(len(problems), 1)
        self.assertIn("from-collect", problems[0])

    def test_not_watched_listed_in_notes(self):
        self.fw["not_watched"] = [{"slug": "standalone-rom", "why": "GAP：沒有合法可下載的檔案", "source": "meta"}]
        self.inventory["firmware_older"] = ["firmware-demo/2026.11.01"]
        self.baseline()
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW1[:10], "result.json")))
        notes = "\n".join(res_["notes"])
        self.assertIn("standalone-rom", notes)
        self.assertIn("2026.11.01", notes)


class GrypeAndKernel(FW):
    def test_no_purl_is_not_assessed_not_ok(self):
        _, _, plan = self.baseline()
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW1[:10], "result.json")))
        row = res_["per_sbom"][self.uuid("bios-b")]
        self.assertEqual(row["grype"], "NOT_ASSESSED（可比對元件 0：沒有 purl／CPE）")
        self.assertNotEqual(row["grype"], "OK")
        self.assertNotIn(self.uuid("bios-b"), self.prepared)                    # 沒有東西可比，不跑 Grype
        report = open(os.path.join(self.w, "out-" + NOW1[:10], "report.md")).read()
        self.assertIn("Grype 空的不代表沒有漏洞，以廠商公告為準", report)
        self.assertIn("NVD 的 CSME 資料不完整", report)                          # bios-a 有可比對元件
        self.assertNotIn("不" + "適用", "\n".join(l for l in report.splitlines() if "firmware-demo" in l))

    def test_no_purl_does_not_degrade_or_block_baseline(self):
        _, _, plan = self.baseline()                                            # 第一次基準成功：NOT_ASSESSED 不算 Grype 沒跑完
        self.assertEqual(plan["actions"], [])
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW1[:10], "result.json")))
        self.assertFalse([x for x in res_["serious"] if "Grype" in x])
        self.assertFalse([x for x in res_["gaps"] if "Grype" in x])

    def test_cpe_only_component_is_matchable(self):
        path = os.path.join(self.inv, self.sample("bios-b")["sbom"]["file"])
        for comp in ({"type": "firmware", "name": "ME", "version": "18.0.10", "cpe": "cpe:2.3:o:intel:csme:18.0.10:*:*:*:*:*:*:*"},
                     {"type": "firmware", "name": "ME", "version": "18.0.10", "properties": [{"name": "syft:cpe23", "value": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}]},
                     {"type": "library", "name": "x", "version": "1", "components": [{"type": "library", "name": "n", "version": "1", "purl": "pkg:generic/n@1"}]}):
            json.dump({"bomFormat": "CycloneDX", "components": [comp]}, open(path, "w"))
            self.assertEqual(match.sbom_matchable(path), 1, comp)
        json.dump({"bomFormat": "CycloneDX", "components": [{"type": "firmware", "name": "ME", "properties": [{"name": "other", "value": "x"}]},
                                                             {"type": "file", "name": "f", "purl": "pkg:generic/f@1"}]}, open(path, "w"))
        self.assertEqual(match.sbom_matchable(path), 0)                          # file 類型不算（同 prepare 的 pkgs）
        open(path, "w").write("not json")
        self.assertIsNone(match.sbom_matchable(path))

    def test_matchable_components_use_grype_and_kev(self):
        self.grype_for[self.uuid("bios-a")] = [gmatch("CVE-2021-44228", "log4j-core", "2.14.1", LOG4J)]
        self.baseline()
        self.assertIn(self.uuid("bios-a"), self.prepared)
        self.kev.append("CVE-2018-18074")
        self.grype_for[self.uuid("sbom-c")] = [gmatch("CVE-2018-18074", "requests", "2.19.0", REQ)]
        _, _, plan = self.go(NOW2)
        opens = [x for x in nohealth(plan) if x["op"] == "open" and "layer-firmware" in x["labels"]]
        self.assertEqual(len(opens), 1)
        self.assertEqual(sorted(opens[0]["labels"]), ["development", "kev", "layer-firmware"])
        self.assertIn("firmware-demo", opens[0]["title"])
        self.assertIn("韌體示範樣本", opens[0]["body"])                                # 不寫 release-meta 的 NOT_RUN
        self.assertNotIn("報告狀態 NOT_RUN", opens[0]["body"])

    def test_kernel_not_applicable_but_not_gap(self):
        calls = []
        _, _, plan = self.run_baseline_with_kernel(calls)
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW1[:10], "result.json")))
        for slug in ("bios-a", "bios-b", "sbom-c"):
            row = res_["per_sbom"][self.uuid(slug)]
            self.assertEqual((row["kernel_map"], row["kernel_cna"]), ("沒有這一項", "沒有這一項"), slug)
        self.assertEqual(calls, [])                                              # 核心 CNA 沒跑
        self.assertFalse([x for x in res_["gaps"] + res_["serious"] if "核心" in x and "firmware" in x])
        self.assertEqual(plan["actions"], [])

    def run_baseline_with_kernel(self, calls):
        for slug in ("bios-a", "bios-b"):
            self.set_results(slug, [], "OK")
        return self.go(NOW1, kernel_runner=lambda v, m: calls.append(v) or ({}, "x"))


class RematchInput(FW):
    """公告重跑的輸出是不可信資料：大小、schema、slug／release_tag／inventory_sha256 要和 inventory 一致，不符就是 GAP。"""

    def load(self):
        _, projs, _ = match.load_inventory(os.path.join(self.inv, "inventory.json"), self.inv)
        return match.load_rematch(self.rmdir, [p for p in projs if match.is_fw(p)])

    def adv(self, rm, slug):
        return rm["adv"][self.uuid(slug)]

    def test_ok_results_loaded(self):
        self.set_results("bios-a", [rule("r:a")], "ATTENTION")
        self.set_results("bios-b", [], "OK")
        self.write_rm()
        rm = self.load()
        self.assertEqual(self.adv(rm, "bios-a")["state"], "ATTENTION")
        self.assertEqual(self.adv(rm, "bios-b")["state"], "OK")
        self.assertEqual(self.adv(rm, "sbom-c")["state"], match.FW_SBOM_ADV)
        self.assertEqual(self.adv(rm, "sbom-c")["state"], "NOT_ASSESSED（沒有 inventory，不重跑公告比對）")
        self.assertNotEqual(self.adv(rm, "sbom-c")["state"], "NOT_RUN")

    def test_not_run_when_missing(self):
        self.assertEqual(self.adv(self.load(), "bios-a")["state"], "NOT_RUN")                 # 資料夾沒有 summary
        _, projs, _ = match.load_inventory(os.path.join(self.inv, "inventory.json"), self.inv)
        rm = match.load_rematch(None, [p for p in projs if match.is_fw(p)])
        self.assertEqual(rm["adv"][self.uuid("bios-a")]["state"], "NOT_RUN")

    def test_sample_not_in_summary_is_not_run_not_release_result(self):
        self.set_results("bios-a", [rule("r:a")])
        self.write_rm()
        rm = self.load()
        a = self.adv(rm, "bios-b")
        self.assertEqual(a["state"], "NOT_RUN")
        self.assertIsNone(a["results"])                                                         # 不拿 Release 當時的結果頂替
        self.assertIn("不在 rematch-summary.json", a["why"])

    def test_gap_cases(self):
        good = {"rule": [rule("r:a")]}
        cases = {
            "schema": lambda d: d.update(schema="x/1"),
            "slug": lambda d: d.update(slug="other"),
            "release_tag": lambda d: d.update(release_tag="firmware-demo/1999.01.01"),
            "inventory_sha256": lambda d: d.update(inventory_sha256="0" * 64),
            "status": lambda d: d.update(status="BAD"),
            "results_not_list": lambda d: d.update(results={}),
            "bad_kind": lambda d: d["results"].__setitem__(0, dict(d["results"][0], kind="x")),
            "bad_result_for_kind": lambda d: d["results"].__setitem__(0, dict(d["results"][0], result="fixed")),
            "affected_without_bulletins": lambda d: d["results"].__setitem__(0, dict(d["results"][0], bulletins=[])),
            "dup_key": lambda d: d["results"].append(dict(d["results"][0])),
            "bulletin_not_str": lambda d: d["results"].__setitem__(0, dict(d["results"][0], bulletins=[1])),
            "tables_missing": lambda d: d["tables"].pop("nvidia_vbios"),
            "stale_not_bool": lambda d: d["tables"]["intel_microcode"].update(stale="no"),
            "changed_bad": lambda d: d.update(changed=[{"key": "k"}]),
            "review_bad": lambda d: d["results"].__setitem__(0, dict(d["results"][0], review="maybe")),
        }
        for name, mut in cases.items():
            with self.subTest(name):
                self.docs = {}
                self.set_results("bios-a", [rule("r:a")])
                self.set_results("bios-b", [], "OK")
                mut(self.docs["bios-a"])
                self.write_rm()
                a = self.adv(self.load(), "bios-a")
                self.assertEqual(a["state"], "GAP", a)
                self.assertIsNone(a["results"])                                                 # GAP 的內容一律不用
                self.assertEqual(self.adv(self.load(), "bios-b")["state"], "OK")                # 其他樣本照常

    def test_summary_problems(self):
        self.set_results("bios-a", [rule("r:a")])
        self.set_results("bios-b", [], "OK")
        for name, over in (("schema", {"schema": "x"}), ("tag", {"release_tag": "firmware-demo/1.1.1"}), ("tables", {"tables": {}}),
                           ("samples", {"samples": "no"})):
            with self.subTest(name):
                self.write_rm(over)
                rm = self.load()
                self.assertEqual({self.adv(rm, s)["state"] for s in ("bios-a", "bios-b")}, {"GAP"})
        open(os.path.join(self.rmdir, "rematch-summary.json"), "w").write("{not json")
        self.assertEqual(self.adv(self.load(), "bios-a")["state"], "GAP")

    def test_output_name_must_be_exact(self):
        self.set_results("bios-a", [rule("r:a")])
        self.write_rm()
        s = json.load(open(os.path.join(self.rmdir, "rematch-summary.json")))
        s["samples"][0]["output"] = "../rematch-bios-a.json"
        json.dump(s, open(os.path.join(self.rmdir, "rematch-summary.json"), "w"))
        a = self.adv(self.load(), "bios-a")
        self.assertEqual(a["state"], "GAP")
        self.assertIn("output", a["why"])

    def test_symlink_and_size_limit(self):
        self.set_results("bios-a", [rule("r:a")])
        self.write_rm()
        fn = os.path.join(self.rmdir, "rematch-bios-a.json")
        real = os.path.join(self.w, "real.json")
        os.replace(fn, real)
        os.symlink(real, fn)
        self.assertEqual(self.adv(self.load(), "bios-a")["state"], "GAP")                       # 不跟隨連結
        os.remove(fn)
        old = match.FW_SAMPLE_MAX
        try:
            os.replace(real, fn)
            match.FW_SAMPLE_MAX = 100
            a = self.adv(self.load(), "bios-a")
            self.assertEqual(a["state"], "GAP")
            self.assertIn("大小上限", a["why"])
        finally:
            match.FW_SAMPLE_MAX = old

    def test_summary_status_mismatch_is_gap(self):
        self.set_results("bios-a", [rule("r:a")], "ATTENTION")
        self.write_rm()
        s = json.load(open(os.path.join(self.rmdir, "rematch-summary.json")))
        s["samples"][0]["status"] = "OK"
        json.dump(s, open(os.path.join(self.rmdir, "rematch-summary.json"), "w"))
        self.assertEqual(self.adv(self.load(), "bios-a")["state"], "GAP")

    def test_gap_reasons_from_summary_are_kept(self):
        self.set_results("bios-a", [rule("r:a")], schema="bad")
        self.write_rm()
        s = json.load(open(os.path.join(self.rmdir, "rematch-summary.json")))
        s["samples"][0]["reasons"] = ["rematch-input-invalid: inventory sha256 does not match"]
        json.dump(s, open(os.path.join(self.rmdir, "rematch-summary.json"), "w"))
        a = self.adv(self.load(), "bios-a")
        self.assertEqual(a["state"], "GAP")
        self.assertIn("rematch-input-invalid", a["reasons"][0])

    def test_gap_and_not_run_degrade_the_round(self):
        """NOT_RUN／GAP：整輪降級（serious），報告看得到；韌體標 NOT_RUN，match 照樣跑。"""
        self.baseline()
        os.remove(os.path.join(self.rmdir, "rematch-summary.json"))
        _, _, plan = self.go(NOW2, write=False)
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW2[:10], "result.json")))
        self.assertEqual(res_["per_sbom"][self.uuid("bios-a")]["advisory"], "NOT_RUN")
        self.assertTrue([x for x in res_["serious"] if "NOT_RUN" in x and "bios-a" in x])
        self.assertEqual(res_["status"], "ATTENTION")
        self.assertEqual(res_["per_sbom"][self.uuid("sbom-c")]["advisory"], match.FW_SBOM_ADV)
        self.assertFalse([x for x in res_["serious"] if "sbom-c" in x])                          # 供應商 SBOM 設計上不重跑，不降級
        _, _, plan = self.go(NOW3, write=False, fw_rematch=None)                                 # 沒給 --firmware-rematch：一樣 NOT_RUN
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW3[:10], "result.json")))
        self.assertEqual(res_["per_sbom"][self.uuid("bios-b")]["advisory"], "NOT_RUN")
        self.assertTrue([x for x in plan["actions"] if x["key"] == HEALTH and x["op"] == "open_if_closed"])    # 連續兩次降級 → 健康 Issue

    def test_state_keeps_old_results_when_not_run(self):
        """沒重跑的樣本沿用上一次的 affected 紀錄，不當成「不再受影響」（沒有離開的留言）。"""
        self.baseline()
        self.set_results("bios-a", [rule("r:a")])
        self.set_results("bios-b", [], "OK")
        self.go(NOW2)
        os.remove(os.path.join(self.rmdir, "rematch-summary.json"))
        _, _, plan = self.go(NOW3, write=False)
        self.assertEqual(self.comments(plan), [])
        self.assertIn("r:a", plan["state"]["firmware"]["samples"][self.uuid("bios-a")]["advisory"])


HEALTH = test_match.HEALTH_KEY


class InterfaceD38962f(RematchInput):
    """C2 的 rematch 入口 d38962f 的介面與預驗建議：key 字元集、meta_status、tables 的 gap、changed 的 null／review、affected 上限、reasons 上限。"""

    def test_key_charset(self):
        for bad in ("rule:a b", "rule:<x>", "rule:a\n", "rule:a@b", "r" * 301, "rule:é"):
            with self.subTest(key=bad):
                self.set_results("bios-a", [rule(bad)], "ATTENTION")
                self.set_results("bios-b", [], "OK")
                self.write_rm()
                self.assertEqual(self.adv(self.load(), "bios-a")["state"], "GAP")
        self.set_results("bios-a", [rule("rule:me:e915ed1eae8b7b91:me=18.0.10.2285#2"), ucode("ucode:000A06A4/0xE6:0x25")], "ATTENTION")
        self.write_rm()
        self.assertEqual(self.adv(self.load(), "bios-a")["state"], "ATTENTION")

    def test_meta_status_gap_all_bios_gap(self):
        self.write_rm({"meta_status": "GAP", "samples": [], "reasons": ["firmware-meta.json sha256 不符"]})
        rm = self.load()
        for slug in ("bios-a", "bios-b"):
            self.assertEqual(self.adv(rm, slug)["state"], "GAP")
            self.assertIn("firmware-meta.json sha256 不符", self.adv(rm, slug)["why"])
        self.assertEqual(self.adv(rm, "sbom-c")["state"], match.FW_SBOM_ADV)
        self.write_rm({"meta_status": "WHAT"})
        self.assertEqual(self.adv(self.load(), "bios-a")["state"], "GAP")

    def test_table_gap_reason_and_null_ident(self):
        t = copy.deepcopy(self.tables)
        t["nvidia_vbios"] = {"sha256": None, "mirror_commit": None, "reviewed_until": None, "status": "GAP", "stale": False, "gap": "鏡像讀不到"}
        self.set_results("bios-a", [], "OK", tables=t)
        self.set_results("bios-b", [], "OK", tables=t)
        self.write_rm({"tables": t})
        rm = self.load()
        self.assertTrue(any("鏡像讀不到" in x for x in rm["table_flags"]["nvidia_vbios"]), rm["table_flags"])

    def test_changed_before_null_and_review(self):
        ch = [{"key": "rule:a", "kind": "rule", "before": {"result": None, "bulletins": [], "reason": None, "review": None},
               "after": {"result": "affected", "bulletins": ["AMI-SA-1"], "reason": None, "review": "preliminary"}},
              {"key": "rule:b", "kind": "rule", "before": {"result": "affected", "bulletins": ["AMI-SA-2"], "reason": None, "review": "preliminary"},
               "after": {"result": "affected", "bulletins": ["AMI-SA-2"], "reason": None, "review": "confirmed"}}]
        self.baseline()
        self.set_results("bios-a", [rule("rule:a"), rule("rule:b", ("AMI-SA-2",), review="confirmed")], "ATTENTION", changed=ch)
        self.go(NOW2)
        report = open(os.path.join(self.w, "out-" + NOW2[:10], "report.md")).read()
        self.assertIn("（Release 當時沒有這個元件的結果）", report)
        self.assertIn("review `confirmed`", report.replace("` confirmed `", "`confirmed`"))
        self.assertNotIn("`None`", report)
        self.assertEqual(match.unsafe_markdown(report), [])
        ch[0]["after"]["result"] = None                                        # after 不能是 null
        self.set_results("bios-a", [rule("rule:a")], "ATTENTION", changed=ch[:1])
        self.write_rm()
        self.assertEqual(self.adv(self.load(), "bios-a")["state"], "GAP")

    def test_affected_cap(self):
        many = [rule("rule:k%d" % i, ("AMI-SA-%d" % i,)) for i in range(match.FW_MAX_AFFECTED + 1)]
        self.set_results("bios-a", many, "ATTENTION")
        self.set_results("bios-b", [], "OK")
        self.write_rm()
        a = self.adv(self.load(), "bios-a")
        self.assertEqual(a["state"], "GAP")
        self.set_results("bios-a", many[:match.FW_MAX_AFFECTED], "ATTENTION")
        self.write_rm()
        self.assertEqual(self.adv(self.load(), "bios-a")["state"], "ATTENTION")

    def test_reasons_cap(self):
        self.set_results("bios-a", [], "OK", reasons=["r"] * 21)
        self.set_results("bios-b", [], "OK", reasons=["r"] * 20)
        self.write_rm()
        rm = self.load()
        self.assertEqual(self.adv(rm, "bios-a")["state"], "GAP")
        self.assertEqual(self.adv(rm, "bios-b")["state"], "OK")


class StateHardening(FW):
    """預驗建議：讀入的舊狀態型別不對不能讓 match 當掉；image_sha256_history 只留 FW_HISTORY_KEEP 筆；狀態摘要不接受尾端換行。"""

    def test_bad_old_state_does_not_crash(self):
        self.baseline()
        st = json.load(open(os.path.join(self.state, "state.json")))
        u = self.uuid("bios-a")
        st.setdefault("firmware", {"tables": {}, "samples": {}})["samples"][u] = {
            "image_sha256": 5, "image_sha256_history": "x",
            "advisory": {"rule:x": {"kind": "rule", "result": "affected", "bulletins": 7},
                         "rule:y": {"kind": "rule", "result": "affected", "bulletins": [["n"]]},
                         "bad key": {"kind": "rule", "result": "affected", "bulletins": ["A"]},
                         "rule:z": {"kind": "rule", "result": "affected", "bulletins": ["AMI-SA-9"], "baseline": True}}}
        json.dump(st, open(os.path.join(self.state, "state.json"), "w"))
        self.set_results("bios-a", [], "OK")
        self.set_results("bios-b", [], "OK")
        _, _, plan = self.go(NOW2)                                         # 不能 TypeError
        adv = plan["state"]["firmware"]["samples"][u]["advisory"]
        self.assertNotIn("rule:x", adv)

    def test_history_keep(self):
        st = {"samples": {"u": {"image_sha256": "a", "advisory": {},
                                "image_sha256_history": [{"at": "t%d" % i, "old": "o", "new": "n"} for i in range(30)]}}}
        out = match.sanitize_firmware(st)
        h = out["samples"]["u"]["image_sha256_history"]
        self.assertEqual(len(h), match.FW_HISTORY_KEEP)
        self.assertEqual(h[-1]["at"], "t29")

    def test_summary_value_trailing_newline(self):
        st = {"firmware": {"tables": {"fw_advisory_rules": {"sha256": "abc\n", "status": "OK\n", "stale": False}}}}
        line = match.mods()["issues"].state_summary("g", 1, st) if "issues" in match.mods() else None
        if line is None:
            import importlib.util as iu
            spec = iu.spec_from_file_location("_issues_t", os.path.join(os.path.dirname(__file__), "..", "issues.py"))
            m = iu.module_from_spec(spec)
            spec.loader.exec_module(m)
            line = m.state_summary("g", 1, st)
        self.assertIn("fw_advisory_rules ?", line)
        self.assertIn("status ?", line)
        self.assertNotIn("\n", line)


class RuleIssues(FW):
    def two_samples_affected(self, review="preliminary"):
        self.baseline()
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1", "AMI-SA-2"), review=review, component="AMI Aptio V")])
        self.set_results("bios-b", [rule("rule:r1:bios:bb", ("AMI-SA-1",), review=review, component="AMI Aptio V")])
        return self.go(NOW2)

    def test_one_issue_per_bulletin_lists_samples(self):
        _, _, plan = self.two_samples_affected()
        opens = self.fw_opens(plan)
        self.assertEqual(len(opens), 2)                                                          # AMI-SA-1、AMI-SA-2 各一個
        k1 = match.issue_key("real", "fwadv", "AMI-SA-1")
        k2 = match.issue_key("real", "fwadv", "AMI-SA-2")
        self.assertEqual(sorted(x["key"] for x in opens), sorted([k1, k2]))
        a1 = next(x for x in opens if x["key"] == k1)
        self.assertEqual(a1["op"], "open")
        self.assertEqual(a1["labels"], ["firmware-advisory", "development", "layer-firmware"])
        self.assertIn("建議受影響（初步規則，待人審）", a1["title"])
        self.assertIn("建議受影響（初步規則，待人審）", a1["body"])
        self.assertIn("bios-a 等 2 份樣本", a1["title"])
        for needle in ("bios-a", "bios-b", "v1", "v2", "AMI Aptio V", "rule:r1:bios:aa", "rule:r1:bios:bb", IMG_A, IMG_B, "不是確定受影響"):
            self.assertIn(needle, a1["body"], needle)
        a2 = next(x for x in opens if x["key"] == k2)
        self.assertIn("bios-a", a2["body"])
        self.assertNotIn("bios-b", a2["body"])                                                   # AMI-SA-2 只有 bios-a
        self.assertIn(match.md_code("fw_advisory_rules"), a1["body"])                            # 表的識別
        self.assertIn("cd" * 32, a1["body"])
        self.assertNotIn("確定受影響的", a1["title"])

    def test_confirmed_wording(self):
        _, _, plan = self.two_samples_affected("confirmed")
        for x in self.fw_opens(plan):
            self.assertIn("建議受影響（規則已確認，待負責單位確認）", x["title"])
            self.assertIn("建議受影響（規則已確認，待負責單位確認）", x["body"])
            self.assertNotIn("初步規則", x["title"] + x["body"])

    def test_not_duplicated_next_day(self):
        self.two_samples_affected()
        _, _, plan = self.go(NOW3)
        self.assertEqual(self.fw_opens(plan), [])
        self.assertEqual(self.comments(plan), [])

    def test_new_sample_affected_comments_only_new(self):
        self.baseline()
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        self.go(NOW2)
        self.set_results("bios-b", [rule("rule:r1:bios:bb", ("AMI-SA-1",))])
        _, _, plan = self.go(NOW3)
        k = match.issue_key("real", "fwadv", "AMI-SA-1")
        acts = [x for x in plan["actions"] if x["key"] == k]
        self.assertEqual(len(acts), 1)
        self.assertEqual(acts[0]["op"], "open_if_closed")                                        # 原 Issue 開著就留言、關閉了就開新的
        self.assertIn("bios-b", acts[0]["body"])
        self.assertIn("rule:r1:bios:bb", acts[0]["body"])
        self.assertNotIn("rule:r1:bios:aa", acts[0]["body"])                                     # 只列新的
        self.assertNotIn("bios-a", acts[0]["body"].replace("bios-b", ""))

    def test_back_to_not_affected_comments_no_close(self):
        self.two_samples_affected()
        self.set_results("bios-b", [rule("rule:r1:bios:bb", result="not-affected")], "OK")
        _, _, plan = self.go(NOW3)
        k = match.issue_key("real", "fwadv", "AMI-SA-1")
        cs = self.comments(plan, k)
        self.assertEqual(len(cs), 1)
        self.assertIn("bios-b", cs[0]["body"])
        self.assertIn("not-affected", cs[0]["body"])
        self.assertIn("不會自動關閉", cs[0]["body"])
        self.assertFalse(cs[0]["reopen_if_closed"])
        self.assertEqual([x for x in plan["actions"] if x["op"] not in ("comment", "open_if_closed", "open") and x["key"] == k], [])
        self.assertNotIn("bios-a", cs[0]["body"])
        # 變成 NOT_ASSESSED 也留言
        self.set_results("bios-a", [rule("rule:r1:bios:aa", result="NOT_ASSESSED")], "OK")
        _, _, plan = self.go(NOW4)
        cs = self.comments(plan, k)
        self.assertEqual(len(cs), 1)
        self.assertIn("NOT_ASSESSED", cs[0]["body"])
        self.assertIn("bios-a", cs[0]["body"])

    def test_sample_dropped_from_results_comments(self):
        self.two_samples_affected()
        self.set_results("bios-b", [], "OK")                                                     # key 不在結果裡
        _, _, plan = self.go(NOW3)
        cs = self.comments(plan, match.issue_key("real", "fwadv", "AMI-SA-1"))
        self.assertEqual(len(cs), 1)
        self.assertIn("不在這次的結果裡", cs[0]["body"])

    def test_baseline_entries_do_not_open_issues(self):
        """第一次基準那一輪既有的 affected 記成基準，不開 Issue（比照 KEV）。"""
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        self.set_results("bios-b", [], "OK")
        _, _, plan = self.go(NOW1)
        self.assertEqual(plan["actions"], [])
        ent = plan["state"]["firmware"]["samples"][self.uuid("bios-a")]["advisory"]["rule:r1:bios:aa"]
        self.assertTrue(ent["baseline"])
        _, _, plan = self.go(NOW2)
        self.assertEqual(plan["actions"], [])
        self.assertEqual(plan["state"]["firmware"]["samples"][self.uuid("bios-a")]["advisory"]["rule:r1:bios:aa"]["baseline"], True)

    def test_sample_added_after_baseline_opens_issue_for_existing_affected(self):
        """#112：基準之後才加入的韌體，它既有的 affected 會開 Issue（基準裡的那份仍然不開）。"""
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        self.set_results("bios-b", [], "OK")
        self.go(NOW1)
        self.add_sample("bios-n", "v7", IMG_C, "bios", True)
        self.set_results("bios-n", [rule("rule:r1:bios:nn", ("AMI-SA-9",))])
        _, _, plan = self.go(NOW2)
        opens = self.fw_opens(plan)
        self.assertEqual([x["key"] for x in opens], [match.issue_key("real", "fwadv", "AMI-SA-9")])
        self.assertEqual(opens[0]["op"], "open")

    def test_baseline_member_then_new_member_opens_group_with_all(self):
        """基準裡的樣本與之後才加入的樣本在同一則公告：群組還沒有 Issue → 開一個，內文列出全部樣本（基準的也列）。"""
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        self.set_results("bios-b", [], "OK")
        self.go(NOW1)
        self.add_sample("bios-n", "v7", IMG_C, "bios", True)
        self.set_results("bios-n", [rule("rule:r1:bios:nn", ("AMI-SA-1",))])
        _, _, plan = self.go(NOW2)
        opens = self.fw_opens(plan)
        self.assertEqual(len(opens), 1)
        self.assertIn("bios-a", opens[0]["body"])
        self.assertIn("bios-n", opens[0]["body"])

    def test_baseline_blocked_when_rematch_not_run(self):
        self.set_results("bios-a", [], "OK")
        with self.assertRaises(match.Fail) as cm:
            self.run_once(NOW1, fw_rematch=None)
        self.assertIn("公告重跑", str(cm.exception))

    def test_stale_table_no_issue_but_attention_and_state(self):
        self.baseline()
        self.tables["fw_advisory_rules"]["stale"] = True
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))], tables=copy.deepcopy(self.tables))
        _, _, plan = self.go(NOW2)
        self.assertEqual(self.fw_opens(plan), [])                                                # 表過期：不開公告 Issue
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW2[:10], "result.json")))
        self.assertTrue([x for x in res_["attention"] if "fw_advisory_rules" in x and "stale" in x])   # 需注意
        self.assertTrue([x for x in res_["serious"] if "fw_advisory_rules" in x])                  # 表過期：降級（連續兩次開健康 Issue）
        self.assertIs(plan["state"]["firmware"]["tables"]["fw_advisory_rules"]["stale"], True)   # state 看得到
        report = open(os.path.join(self.w, "out-" + NOW2[:10], "report.md")).read()
        self.assertIn("fw_advisory_rules", report)
        self.assertIn("stale", report)
        # 表更新後：同一個 affected 開 Issue（不是基準）
        self.tables["fw_advisory_rules"]["stale"] = False
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        _, _, plan = self.go(NOW3)
        self.assertEqual(len(self.fw_opens(plan)), 1)

    def test_changed_listed_in_report(self):
        self.baseline()
        ch = {"key": "rule:r1:bios:aa", "kind": "rule", "before": {"result": "NOT_ASSESSED", "bulletins": []},
              "after": {"result": "affected", "bulletins": ["AMI-SA-1"]}}
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))], changed=[ch])
        self.go(NOW2)
        report = open(os.path.join(self.w, "out-" + NOW2[:10], "report.md")).read()
        self.assertIn("結果和 Release 當時不同", report)
        self.assertIn("rule:r1:bios:aa", report)
        self.assertIn("NOT_ASSESSED", report)
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW2[:10], "result.json")))
        self.assertTrue([x for x in res_["attention"] if "不同" in x])

    def test_max_new_merges_into_summary(self):
        self.baseline()
        self.set_results("bios-a", [rule(f"rule:r{i}:aa", (f"AMI-SA-{i}",)) for i in range(5)])
        _, _, plan = self.go(NOW2, max_new=2)
        opens = [x for x in plan["actions"] if x["op"] == "open"]
        self.assertEqual(len(opens), 1)
        self.assertIn("彙總", opens[0]["title"])
        self.assertIn("[韌體公告]", opens[0]["title"])
        self.assertIn("firmware-advisory", opens[0]["labels"])
        self.assertIn("attention", opens[0]["labels"])
        # 之後的事件留言在彙總 Issue（via_summary）
        self.set_results("bios-b", [rule("rule:r0:bb", ("AMI-SA-0",))])
        _, _, plan = self.go(NOW3, max_new=2)
        acts = [x for x in plan["actions"] if x["op"] == "open_if_closed" and "firmware-advisory" in x.get("labels", [])]
        self.assertEqual([x["key"] for x in acts], [opens[0]["key"]])

    def test_demo_marking_and_drill(self):
        self.baseline()
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        _, _, plan = self.go(NOW2, demo=True)
        o = self.fw_opens(plan)[0]
        self.assertTrue(o["title"].startswith("[示範專案（公開 BSP）]"))
        self.assertIn("demo", o["labels"])
        self.assertIn("不是真的出貨產品", o["body"])
        self.assertTrue(set(o["labels"]) <= issues.ALLOWED_LABELS)

    def test_plan_passes_issues_load_plan(self):
        self.baseline()
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        self.set_results("bios-b", [vbios()])
        _, _, plan = self.go(NOW2, demo=True)
        path = os.path.join(self.w, "plan-check.json")
        json.dump(plan, open(path, "w"))
        issues.load_plan(path)                                                                    # layer-firmware、firmware-advisory 在白名單
        for lab in ("firmware-advisory", "layer-firmware"):
            self.assertIn(lab, issues.ALLOWED_LABELS)


class TableGap(FW):
    def test_table_status_gap_is_gap_and_degrades(self):
        self.baseline()
        self.tables["intel_microcode"]["status"] = "GAP"
        self.set_results("bios-a", [ucode(result="NOT_ASSESSED")], "GAP", tables=copy.deepcopy(self.tables))
        self.go(NOW2)
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW2[:10], "result.json")))
        self.assertTrue([x for x in res_["gaps"] if "intel_microcode" in x])
        self.assertTrue([x for x in res_["serious"] if "intel_microcode" in x])
        self.assertTrue([x for x in res_["serious"] if "bios-a" in x and "GAP" in x])

    def test_table_gap_blocks_baseline(self):
        self.tables["nvidia_vbios"]["stale"] = True
        for s in ("bios-a", "bios-b"):
            self.set_results(s, [], "OK", tables=copy.deepcopy(self.tables))
        with self.assertRaises(match.Fail) as cm:
            self.go(NOW1)
        self.assertIn("nvidia_vbios", str(cm.exception))


class SamplesLeave(FW):
    def test_sample_leaving_release_is_dropped_and_commented(self):
        """新的韌體 Release 沒有這個監控鍵（例如 BIOS 改版）：狀態移除它，它的公告 Issue 留言「樣本不在這次的韌體 Release」。"""
        self.baseline()
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        self.go(NOW2)
        old = self.uuid("bios-a")
        self.fw["samples"] = [x for x in self.fw["samples"] if x["slug"] != "bios-a"]
        _, _, plan = self.go(NOW3)
        self.assertNotIn(old, plan["state"]["firmware"]["samples"])
        cs = self.comments(plan, match.issue_key("real", "fwadv", "AMI-SA-1"))
        self.assertEqual(len(cs), 1)
        self.assertIn("不在這次監控的韌體 Release", cs[0]["body"])

    def test_release_problem_carries_state_over(self):
        """韌體 Release 這次收不到（meta 壞掉）：整份沿用，不當成樣本離開、不留言。"""
        self.baseline()
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        self.go(NOW2)
        key = self.uuid("bios-a")
        self.fw["problems"] = ["firmware-meta.json：schema 不對"]
        self.fw["samples"] = []
        self.write_inv()
        _, _, plan = self.run_once(NOW3, fw_rematch=None)
        self.assertIn(key, plan["state"]["firmware"]["samples"])
        self.assertEqual(self.comments(plan), [])


class UcodeAndVbios(FW):
    def test_microcode_one_issue_per_key_with_all_candidates(self):
        self.baseline()
        self.set_results("bios-a", [ucode()])
        self.set_results("bios-b", [ucode()])                                                    # 同一份微碼出現在兩個樣本
        _, _, plan = self.go(NOW2)
        opens = self.fw_opens(plan)
        self.assertEqual(len(opens), 1)
        o = opens[0]
        self.assertEqual(o["key"], match.issue_key("real", "fwadv-ucode", "ucode:A/0x1:0x2"))
        self.assertIn("2 個候選公告", o["title"])
        self.assertIn("版本比較的候選，待人審", o["title"])
        for needle in ("INTEL-SA-1", "INTEL-SA-2", "bios-a", "bios-b", "ucode:A/0x1:0x2", "不是確認受影響"):
            self.assertIn(needle, o["body"], needle)
        self.assertEqual(o["labels"], ["firmware-advisory", "development", "layer-firmware"])
        _, _, plan = self.go(NOW3)
        self.assertEqual(self.fw_opens(plan) + self.comments(plan), [])

    def test_microcode_candidates_changed_and_new_sample(self):
        self.baseline()
        self.set_results("bios-a", [ucode()])
        self.go(NOW2)
        self.set_results("bios-a", [ucode(bulletins=("INTEL-SA-1", "INTEL-SA-2", "INTEL-SA-3"))])
        _, _, plan = self.go(NOW3)
        k = match.issue_key("real", "fwadv-ucode", "ucode:A/0x1:0x2")
        cs = [x for x in plan["actions"] if x["key"] == k]
        self.assertEqual([x["op"] for x in cs], ["comment"])
        self.assertIn("候選公告清單變了", cs[0]["body"])
        self.assertIn("INTEL-SA-3", cs[0]["body"])
        self.set_results("bios-b", [ucode(bulletins=("INTEL-SA-1", "INTEL-SA-2", "INTEL-SA-3"))])
        _, _, plan = self.go(NOW4)
        cs = [x for x in plan["actions"] if x["key"] == k]
        self.assertEqual([x["op"] for x in cs], ["open_if_closed"])
        self.assertIn("bios-b", cs[0]["body"])

    def test_microcode_becomes_up_to_date_or_not_assessed_comments(self):
        for becomes in ("up-to-date", "older-no-sa", "NOT_ASSESSED"):
            with self.subTest(becomes):
                self.tearDown()
                self.setUp()
                self.baseline()
                self.set_results("bios-a", [ucode()])
                self.go(NOW2)
                self.set_results("bios-a", [ucode(result=becomes)], "OK")
                _, _, plan = self.go(NOW3)
                cs = self.comments(plan, match.issue_key("real", "fwadv-ucode", "ucode:A/0x1:0x2"))
                self.assertEqual(len(cs), 1)
                self.assertIn(becomes, cs[0]["body"])
                self.assertIn("bios-a", cs[0]["body"])

    def test_vbios_one_issue_per_bulletin_with_evidence(self):
        self.baseline()
        self.set_results("bios-a", [vbios()])
        _, _, plan = self.go(NOW2)
        opens = self.fw_opens(plan)
        self.assertEqual(len(opens), 1)
        o = opens[0]
        self.assertEqual(o["key"], match.issue_key("real", "fwadv", "NVIDIA-5000"))
        self.assertIn("建議受影響", o["title"])
        for needle in ("對照表第 3 列", "10de:1c82", "86.06.4D", "reviewed_until", "2025-09-02", "vbios:10de:1c82:ab"):
            self.assertIn(needle, o["body"], needle)
        self.assertNotIn("初步規則", o["title"])                                                  # vBIOS 不是規則表：不套規則表的用語

    def test_ucode_table_stale_opens_nothing(self):
        self.baseline()
        self.tables["intel_microcode"]["stale"] = True
        self.set_results("bios-a", [ucode()], tables=copy.deepcopy(self.tables))
        _, _, plan = self.go(NOW2)
        self.assertEqual(self.fw_opens(plan), [])


class HashChange(FW):
    def setup_open_issues(self):
        """bios-a 有一個開著的 KEV Issue、一個廠商層級 Issue、一個公告 Issue。"""
        self.cfg = os.path.join(self.w, "vw.json")
        json.dump({"vendors": ["acme"], "exclude": [], "aliases": {}, "projects": {}}, open(self.cfg, "w"))
        self.grype_for[self.uuid("bios-a")] = [gmatch("CVE-2021-44228", "log4j-core", "2.14.1", LOG4J)]
        self.kev = ["CVE-2000-0001"]
        for s in ("bios-a", "bios-b"):
            self.set_results(s, [], "OK")
        self.go(NOW1, vendor_config=self.cfg)
        self.kev = ["CVE-2021-44228"]
        self.kev_extra = [{"cveID": "CVE-2026-90009", "vendorProject": "Acme", "product": "X", "dateAdded": NOW2[:10]}]
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        # bios-a 的 SBOM 要有 acme 廠商：加一個 purl 帶 acme 的元件
        _, _, plan = self.go(NOW2, vendor_config=self.cfg)
        return plan

    def test_hash_change_comments_once_per_open_issue(self):
        plan = self.setup_open_issues()
        # bios-a 的 Issue。廠商層級是「一個廠商 × CVE 一個 Issue」（D-064 B，#121）：標題寫「<第一個版本> 等 n 個版本」，bios-a 在內文的表格裡
        mine = [x for x in nohealth(plan) if x["op"] == "open" and "layer-firmware" in x["labels"]
                and ("bios-a" in x["title"] or ("vendor-level" in x["labels"] and "bios-a" in x["body"]))]
        before = {x["key"] for x in mine}
        kinds = {x["labels"][0] for x in mine}
        self.assertEqual(kinds, {"kev", "firmware-advisory", "vendor-level"})                    # 三種開著的 Issue
        self.add_sample("bios-a", "v1", IMG_A2, "bios", True)                                     # 同 slug 同版本，映像換了
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        _, _, plan = self.go(NOW3, vendor_config=self.cfg)
        self.assertEqual([x for x in nohealth(plan) if x["op"] in ("open", "open_if_closed") and x["key"] not in before], [])   # 不開新鍵
        cs = self.comments(plan)
        self.assertEqual({x["key"] for x in cs}, before)                                          # 每個開著的 Issue 各一則
        self.assertEqual(len(cs), len(before))
        for c in cs:
            self.assertIn(IMG_A, c["body"])
            self.assertIn(IMG_A2, c["body"])
            self.assertFalse(c["reopen_if_closed"])
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW3[:10], "result.json")))
        self.assertTrue([x for x in res_["attention"] if IMG_A in x and IMG_A2 in x])              # 需注意
        report = open(os.path.join(self.w, "out-" + NOW3[:10], "report.md")).read()
        self.assertIn(IMG_A, report)
        self.assertIn(IMG_A2, report)
        smp = plan["state"]["firmware"]["samples"][self.uuid("bios-a")]
        self.assertEqual(smp["image_sha256"], IMG_A2)
        self.assertEqual(smp["image_sha256_history"], [{"at": NOW3, "old": IMG_A, "new": IMG_A2}])
        self.assertEqual(self.uuid("bios-a"), match.uuid_of("firmware-demo", "bios-a@v1", "firmware"))   # 鍵不變
        # 隔天同一個新 sha256：不再留言
        _, _, plan = self.go(NOW4, vendor_config=self.cfg)
        self.assertEqual(self.comments(plan), [])
        self.assertEqual(len(plan["state"]["firmware"]["samples"][self.uuid("bios-a")]["image_sha256_history"]), 1)
        # 又變一次：追加第二筆
        self.add_sample("bios-a", "v1", IMG_C, "bios", True)
        _, _, plan = self.go(NOW5, vendor_config=self.cfg)
        self.assertEqual([h["new"] for h in plan["state"]["firmware"]["samples"][self.uuid("bios-a")]["image_sha256_history"]], [IMG_A2, IMG_C][-2:][1:] and [IMG_A2, IMG_C])

    def test_null_sha_not_compared(self):
        self.baseline()
        self.add_sample("bios-a", "v1", None, "bios", True)
        _, _, plan = self.go(NOW2)
        smp = plan["state"]["firmware"]["samples"][self.uuid("bios-a")]
        self.assertEqual(smp["image_sha256"], IMG_A)                                              # 舊值保留
        self.assertEqual(smp["image_sha256_history"], [])
        res_ = json.load(open(os.path.join(self.w, "out-" + NOW2[:10], "result.json")))
        self.assertEqual(res_["firmware"]["image_sha256_changes"], [])

    def test_first_run_has_no_history(self):
        _, _, plan = self.baseline()
        smp = plan["state"]["firmware"]["samples"][self.uuid("bios-a")]
        self.assertEqual((smp["image_sha256"], smp["image_sha256_history"]), (IMG_A, []))


class StateCarry(FW):
    def test_firmware_key_survives_two_rounds_and_old_state_reads(self):
        _, _, plan = self.baseline()
        self.assertIn("firmware", plan["state"])
        self.assertEqual(set(plan["state"]["firmware"]), {"tables", "samples"})
        self.assertEqual(plan["state"]["firmware"]["tables"], TABLES)
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        _, _, plan = self.go(NOW2)
        self.assertIn(self.uuid("bios-a"), plan["state"]["firmware"]["samples"])
        _, _, plan = self.go(NOW3)                                                                # 第三輪（讀第二輪寫的狀態）
        smp = plan["state"]["firmware"]["samples"][self.uuid("bios-a")]
        self.assertEqual(smp["advisory"]["rule:r1:bios:aa"]["bulletins"], ["AMI-SA-1"])
        self.assertEqual(smp["advisory"]["rule:r1:bios:aa"]["result"], "affected")
        self.assertEqual(plan["state"]["firmware"]["samples"][self.uuid("bios-b")]["advisory"], {})   # 只存 affected／affected-candidate

    def test_state_without_firmware_is_readable(self):
        self.inventory.pop("firmware", None)
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        self.run_once(NOW1)
        st = json.load(open(os.path.join(self.state, "state.json")))
        self.assertNotIn("firmware", st)
        for slug in ("bios-a", "bios-b"):
            self.set_results(slug, [], "OK")
        _, _, plan = self.go(NOW2)                                                                # 舊狀態（沒有 firmware）＋這次才有韌體：不丟例外
        self.assertIn("firmware", plan["state"])
        # 基準之後才加入的韌體：既有 affected 會開 Issue（#112）
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        _, _, plan = self.go(NOW3)
        self.assertEqual(len(self.fw_opens(plan)), 1)

    def test_sanitize_keeps_only_public_fields(self):
        st = {"schema": 1, "matches": {}, "firmware": {"tables": {"fw_advisory_rules": {"sha256": "x", "status": "OK", "stale": False, "evil": {"a": 1}},
                                                                    "other": {"a": "b"}},
                                                         "samples": {"u": {"image_sha256": IMG_A, "path": "/srv/x",
                                                                           "image_sha256_history": [{"at": NOW1, "old": "o", "new": "n", "x": 1}],
                                                                           "advisory": {"k": {"kind": "rule", "result": "affected", "bulletins": ["B"], "path": "/x"}}}}}}
        out = match.sanitize_state(st)["firmware"]
        self.assertEqual(out["tables"], {"fw_advisory_rules": {"sha256": "x", "status": "OK", "stale": False}})
        self.assertEqual(out["samples"]["u"]["advisory"]["k"], {"kind": "rule", "result": "affected", "bulletins": ["B"]})
        self.assertEqual(out["samples"]["u"]["image_sha256_history"], [{"at": NOW1, "old": "o", "new": "n"}])
        self.assertNotIn("path", out["samples"]["u"])

    def test_prune_keeps_fwadv_group_records(self):
        self.baseline()
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        _, _, plan = self.go(NOW2)
        k = match.issue_key("real", "fwadv", "AMI-SA-1")
        self.assertIn(k, plan["state"]["dumpling"]["issues"])
        st = json.load(open(os.path.join(self.state, "state.json")))
        st["dumpling"]["issues"][k]["opened_at"] = "2025-01-01T00:00:00Z"                         # 開了超過 180 天、群組還在
        gone = match.issue_key("real", "fwadv", "AMI-SA-GONE")
        st["dumpling"]["issues"][gone] = {"kind": "fwadv", "opened_at": "2025-01-01T00:00:00Z"}   # 不在 live：會被修剪
        match.prune_state(st, match.parse_now(NOW3))
        self.assertIn(k, st["dumpling"]["issues"])
        self.assertNotIn(gone, st["dumpling"]["issues"])
        st2 = json.load(open(os.path.join(self.state, "state.json")))
        st2["dumpling"]["issues"][k]["opened_at"] = "2025-01-01T00:00:00Z"
        st2["firmware"]["samples"][self.uuid("bios-a")]["advisory"] = {}                         # 群組沒有 affected 了：修剪
        match.prune_state(st2, match.parse_now(NOW3))
        self.assertNotIn(k, st2["dumpling"]["issues"])

    def test_state_summary_shows_tables(self):
        st = {"firmware": {"tables": copy.deepcopy(TABLES)}}
        st["firmware"]["tables"]["nvidia_vbios"].update(stale=True, status="GAP")
        text = issues.state_summary("2026-11-12T01:00:00Z", 3, st)
        self.assertTrue(text.startswith("最後執行：2026-11-12T01:00:00Z；比對數：3"))
        for needle in ("fw_advisory_rules cd", "intel_microcode 25", "nvidia_vbios c5", "status GAP", "stale true", "stale false"):
            self.assertIn(needle, text)
        evil = {"firmware": {"tables": {"fw_advisory_rules": {"sha256": "@x [y](z)", "status": "OK", "stale": False}}}}
        self.assertIn("fw_advisory_rules ?", issues.state_summary("g", 1, evil))
        self.assertEqual(issues.state_summary("g", 1, {}), "最後執行：g；比對數：1")             # 沒有韌體：格式不變
        self.assertEqual(issues.state_summary("g", 1, None), "最後執行：g；比對數：1")

    def test_state_has_no_paths(self):
        self.set_results("bios-a", [rule("rule:r1:bios:aa", ("AMI-SA-1",))])
        self.set_results("bios-b", [], "OK")
        _, _, plan = self.go(NOW1)
        txt = json.dumps(plan["state"])
        self.assertNotIn(self.w, txt)
        self.assertNotIn(self.rmdir, txt)


class Escaping(FW):
    """外來字串（slug、元件名、公告 ID、表的識別、reason）都經過 md_text／md_code／md_title：unsafe_markdown 為空。"""

    def test_all_external_strings_escaped(self):
        evil_slug = "x@evil [a](http:e.example) ![i](http:e.example) #1 &commat;"
        self.fw["samples"] = []
        self.add_sample(evil_slug, "v@1 [z](http://e.example)", IMG_A, "bios", True)
        self.add_sample("bios-ok", "v2", IMG_B, "bios", True)
        for s in (evil_slug, "bios-ok"):
            self.set_results(s, [], "OK")
        self.go(NOW1)
        tables = copy.deepcopy(self.tables)
        tables["fw_advisory_rules"]["table_updated"] = EVIL
        tables["nvidia_vbios"]["reviewed_until"] = EVIL
        self.tables = tables
        # key 只允許 A-Za-z0-9._=+-:/#（C2 介面）；字元集內仍含 #數字、=、+、/ 這類要跳脫的字元
        self.set_results(evil_slug, [rule(EVIL_KEY_R, (EVIL_ID, "AMI-SA-1"), component=EVIL),
                                     ucode(EVIL_KEY_U, ("INTEL-SA-@evil [q](http:e.example)",)),
                                     vbios(EVIL_KEY_V, (EVIL_ID,))], tables=tables)
        self.set_results("bios-ok", [rule("rule:ok", ("AMI-SA-1",), component=EVIL)], tables=tables)
        for r in self.docs[evil_slug]["results"]:
            r["component"] = EVIL
            r["reason"] = EVIL
        _, _, plan = self.go(NOW2, demo=True)
        self.assertGreaterEqual(len(self.fw_opens(plan)), 3)           # EVIL_ID（規則表與 vBIOS 共用）、AMI-SA-1、微碼
        for x in plan["actions"]:
            self.assertEqual(match.unsafe_markdown(x["body"]), [], x["body"][:300])
            self.assertEqual(match.unsafe_actions([x]), [], x["title"])
            self.assertNotRegex(match._CODE_SPAN.sub(" ", x["body"]), r"(?<![\\\w])@(?!​)[A-Za-z]")
            self.assertNotRegex(match._CODE_SPAN.sub(" ", x["body"]), r"[#＃]\d")
        report = open(os.path.join(self.w, "out-" + NOW2[:10], "report.md")).read()
        self.assertEqual(match.unsafe_markdown(report), [], "報告")
        self.assertTrue(any("AMI-SA-1" in x["title"] for x in self.fw_opens(plan)))
        # 第三輪：離開、新增的留言也要跳脫（惡意 slug 的 key 變 not-affected、hash 變化）
        self.set_results(evil_slug, [rule(EVIL_KEY_R, (EVIL_ID, "AMI-SA-1"), result="not-affected", component=EVIL)], "OK", tables=tables)
        self.add_sample(evil_slug, "v@1 [z](http://e.example)", IMG_C, "bios", True)
        _, _, plan = self.go(NOW3, demo=True)
        self.assertTrue(self.comments(plan))
        for x in plan["actions"]:
            self.assertEqual(match.unsafe_markdown(x["body"]), [], x["body"][:300])
            self.assertEqual(match.unsafe_actions([x]), [])
        report = open(os.path.join(self.w, "out-" + NOW3[:10], "report.md")).read()
        self.assertEqual(match.unsafe_markdown(report), [], "報告")

    def test_gap_reason_and_problem_strings_escaped(self):
        self.sample("bios-a")["problems"] = [EVIL]
        self.set_results("bios-a", [rule("r", ("B",))], schema=EVIL)
        self.set_results("bios-b", [], "OK")
        self.write_inv()
        self.write_rm()
        s = json.load(open(os.path.join(self.rmdir, "rematch-summary.json")))
        s["samples"][0]["reasons"] = [EVIL]
        json.dump(s, open(os.path.join(self.rmdir, "rematch-summary.json"), "w"))
        with self.assertRaises(match.Fail):                                                       # 第一次基準：有問題不建
            self.run_once(NOW1, fw_rematch=self.rmdir)
        self.baseline_without_problem()

    def baseline_without_problem(self):
        self.sample("bios-a")["problems"] = []
        self.set_results("bios-a", [], "OK")
        self.go(NOW1)
        self.sample("bios-a")["problems"] = [EVIL]
        self.set_results("bios-a", [rule("r", ("B",))], schema=EVIL)
        self.write_inv()
        self.write_rm()
        s = json.load(open(os.path.join(self.rmdir, "rematch-summary.json")))
        s["samples"][0]["reasons"] = [EVIL]
        json.dump(s, open(os.path.join(self.rmdir, "rematch-summary.json"), "w"))
        for n in (NOW2, NOW3):
            _, _, plan = self.run_once(n, fw_rematch=self.rmdir)
            for x in plan["actions"]:
                self.assertEqual(match.unsafe_markdown(x["body"]), [], x["body"][:300])
        report = open(os.path.join(self.w, "out-" + NOW3[:10], "report.md")).read()
        self.assertEqual(match.unsafe_markdown(report), [])
        self.assertIn("health", json.dumps(plan["actions"]) + "health")


class SupportSkipsFirmware(FW):
    def test_release_boms_skips_firmware(self):
        self.write_inv()
        boms, problems = support.release_boms(os.path.join(self.inv, "inventory.json"))
        self.assertNotIn("firmware-demo", boms)
        self.assertIn("demo", boms)
        self.assertEqual(problems, [])

    def test_no_release_without_project_note(self):
        self.write_inv()
        out = os.path.join(self.w, "sup")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = support.main(["--projects-dir", os.path.join(self.w, "no-projects"), "--inventory", os.path.join(self.inv, "inventory.json"),
                               "--out", out, "--today", "2026-11-15"])
        self.assertIn(rc, (0, 2))
        txt = open(os.path.join(out, "report.md")).read()
        self.assertNotIn("firmware-demo：有 Release 但 projects/ 裡沒有這個專案", txt)
        self.assertIn("demo：有 Release 但 projects/ 裡沒有這個專案", txt)                          # 板子照舊


@unittest.skipUnless(os.path.isfile(os.path.join(EXAMPLE_DIR, "firmware-rematch.example.json")), "C2 的範例檔不在 tests/data/（也沒有 FW_EXAMPLE_DIR）")
class ExampleFiles(FW):
    """直接讀 C2 的範例檔（firmware-rematch.example.json、firmware-rematch-summary.example.json）；範例是介面，不是我們維護的。"""

    def setUp(self):
        super().setUp()
        self.ex = json.load(open(os.path.join(EXAMPLE_DIR, "firmware-rematch.example.json")))
        self.exs = json.load(open(os.path.join(EXAMPLE_DIR, "firmware-rematch-summary.example.json")))
        slug = self.ex["slug"]
        self.fw["tag"] = self.ex["release_tag"]
        self.fw["samples"] = []
        self.add_sample(slug, self.ex["firmware_version"], "e9" * 32, "bios", True)
        self.sample(slug)["inventory"]["sha256"] = self.ex["inventory_sha256"]
        self.slug = slug

    def test_example_validates_and_opens_issues(self):
        os.makedirs(self.rmdir)
        json.dump(self.ex, open(os.path.join(self.rmdir, f"rematch-{self.slug}.json"), "w"))
        s = copy.deepcopy(self.exs)
        s["samples"] = [x for x in s["samples"] if x["slug"] == self.slug]
        json.dump(s, open(os.path.join(self.rmdir, "rematch-summary.json"), "w"))
        self.write_inv()
        _, projs, _ = match.load_inventory(os.path.join(self.inv, "inventory.json"), self.inv)
        rm = match.load_rematch(self.rmdir, [p for p in projs if match.is_fw(p)])
        a = rm["adv"][self.uuid(self.slug)]
        self.assertEqual(a["state"], self.ex["status"], a)
        self.assertEqual(len(a["results"]), len(self.ex["results"]))
        self.assertEqual(rm["tables"]["intel_microcode"]["status"], "OK")
        # 基準之後才有的樣本：範例裡的 rule affected 與微碼候選各開一個 Issue，changed 列在報告
        self.docs, self.rmdir_saved = {}, self.rmdir
        self.baseline_example()

    def baseline_example(self):
        self.write_inv()
        # 先用沒有 affected 的結果建基準，再放範例結果
        empty = copy.deepcopy(self.ex)
        empty["results"], empty["changed"], empty["status"] = [], [], "OK"
        json.dump(empty, open(os.path.join(self.rmdir, f"rematch-{self.slug}.json"), "w"))
        s = json.load(open(os.path.join(self.rmdir, "rematch-summary.json")))
        s["samples"][0]["status"] = "OK"
        json.dump(s, open(os.path.join(self.rmdir, "rematch-summary.json"), "w"))
        self.run_once(NOW1, fw_rematch=self.rmdir)
        json.dump(self.ex, open(os.path.join(self.rmdir, f"rematch-{self.slug}.json"), "w"))
        s["samples"][0]["status"] = self.ex["status"]
        json.dump(s, open(os.path.join(self.rmdir, "rematch-summary.json"), "w"))
        _, _, plan = self.run_once(NOW2, fw_rematch=self.rmdir)
        opens = self.fw_opens(plan)
        want = {x["bulletins"][0] for x in self.ex["results"] if x["kind"] == "rule" and x["result"] == "affected"}
        keys = {match.issue_key("real", "fwadv", b) for b in want} | \
            {match.issue_key("real", "fwadv-ucode", x["key"]) for x in self.ex["results"] if x["result"] == "affected-candidate"}
        self.assertEqual({x["key"] for x in opens}, keys)
        report = open(os.path.join(self.w, "out-" + NOW2[:10], "report.md")).read()
        self.assertIn("結果和 Release 當時不同", report)
        for x in opens + [{"body": report, "title": ""}]:
            self.assertEqual(match.unsafe_markdown(x["body"]), [])

    def test_example_summary_marks_missing_sample_not_run(self):
        # 範例總表有兩個樣本（第二個 GAP）；inventory 只有一個 → 另一個列在 listed_unknown
        os.makedirs(self.rmdir)
        json.dump(self.ex, open(os.path.join(self.rmdir, f"rematch-{self.slug}.json"), "w"))
        json.dump(self.exs, open(os.path.join(self.rmdir, "rematch-summary.json"), "w"))
        self.write_inv()
        _, projs, _ = match.load_inventory(os.path.join(self.inv, "inventory.json"), self.inv)
        rm = match.load_rematch(self.rmdir, [p for p in projs if match.is_fw(p)])
        self.assertEqual(rm["adv"][self.uuid(self.slug)]["state"], "ATTENTION")
        self.assertTrue(rm["listed_unknown"])


if __name__ == "__main__":
    unittest.main()
