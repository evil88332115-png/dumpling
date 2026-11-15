"""韌體 Release 的 firmware-meta.json 產生器與檢查（pipeline/lib/firmware_meta.py）、firmware.yml 的 tag 觸發與權限。

- tag 正規式（含無效日期）、測試 tag；
- 產生器：why 空、表的識別不一致、slug 不合、status 不是 ok 的樣本進 not_watched、kind sbom 的欄位、和範例檔的鍵集合一致；
- collect-check（用路徑載入 pipeline/watch/collect.py）與 rematch-check 的失敗路徑；
- 本機端到端：repo 內的真樣本（OVMF）產生 meta，再跑 pipeline/firmware-rematch.sh，changed 是空的；DUMPLING_REMATCH_ART 指到 CI artifact 時 6 份真樣本都跑；
- firmware.yml 與 release.yml：觸發、權限（只有建 Release 的 job 有 contents: write）、action 固定 SHA。
不連網、不讀映像。"""
import copy
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
import firmware_meta as fm  # noqa: E402

COLLECT = os.path.join(ROOT, "pipeline", "watch", "collect.py")
EXAMPLE = os.path.join(ROOT, "pipeline", "watch", "tests", "data", "firmware-meta.example.json")
SMALL = os.path.join(ROOT, "tools", "cra", "tests", "data", "rematch", "ubuntu-ovmf-2024.02")
REMATCH = os.path.join(ROOT, "pipeline", "firmware-rematch.sh")
COMMIT = "0123456789abcdef0123456789abcdef01234567"
BUILT = "2026-11-20T03:00:00Z"
RUN = "https://github.com/o/r/actions/runs/1"
TAG = "firmware-demo/2026.11.20"
NOW = "2026-11-21T02:00:00Z"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def inventory(status="ATTENTION", images=1, rules_sha="r" * 64, **over):
    inv = {"schema": fm.INVENTORY_SCHEMA, "status": status, "detail": "d",
           "bios": [{"file": "x.zip!x.bin", "sha256": "%064x" % (i + 1)} for i in range(images)],
           "advisory": {"status": "OK", "source": {"commit": "c" * 40, "tag": "microcode-20261110", "table_sha256": "a" * 64}},
           "vbios_advisory": {"status": "OK", "source": {"table_sha256": "b" * 64, "mirror_commit": "d" * 40, "reviewed_until": "2025-09-02"}},
           "rules_advisory": {"status": "OK", "table": {"sha256": rules_sha, "updated": "2026-11-14"}}}
    inv.update(over)
    return inv


class Env:
    """暫存資料夾：firmware/<kind>/<slug>/firmware.yml、firmware-ci 的產出、供應商 SBOM 的 prep、firmware-sbom-check 的輸出。"""

    def __init__(self, test):
        self.dir = tempfile.mkdtemp(prefix="dumpling-fwmeta-")
        test.addCleanup(shutil.rmtree, self.dir, True)
        self.ci = os.path.join(self.dir, "ci")
        self.prep = os.path.join(self.dir, "prep")
        self.out = os.path.join(self.dir, "out")
        self.manifests = []
        self.sbom_log = os.path.join(self.dir, "sbom-check.log")
        open(self.sbom_log, "w").close()

    def manifest(self, kind, slug, **over):
        doc = {"kind": kind, "vendor": "V", "model": "M", "status": "ok", "notes": "n", "firmware_version": "1.0"}
        doc.update(over)
        doc = {k: v for k, v in doc.items() if v is not None}
        d = os.path.join(self.dir, "firmware", kind, slug)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "firmware.yml")
        with open(p, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, allow_unicode=True)
        self.manifests.append(p)
        return p

    def bios(self, slug, inv=None, expect_log="FIRMWARE-EXPECT\tOK\t%s\tx\n", **over):
        self.manifest("bios", slug, **over)
        d = os.path.join(self.ci, slug)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "fw-inventory.json"), "w", encoding="utf-8") as fh:
            json.dump(inv or inventory(), fh)
        with open(os.path.join(d, "fw.cdx.json"), "w", encoding="utf-8") as fh:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, fh)
        if expect_log is not None:
            with open(os.path.join(d, "expect.log"), "w", encoding="utf-8") as fh:
                fh.write(expect_log % slug if "%s" in expect_log else expect_log)

    def sbom(self, slug, status="ATTENTION", fname="a_b.sbom.json"):
        self.manifest("sbom", slug, files=[{"name": fname, "url": "https://example.org/x", "sha256": "0" * 64, "size": 1, "role": "sbom"}])
        d = os.path.join(self.prep, slug)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "sbom.cdx.json"), "w", encoding="utf-8") as fh:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "c", "version": "1"}]}, fh)
        with open(self.sbom_log, "a", encoding="utf-8") as fh:
            fh.write("FIRMWARE-SBOM\t%s\t%s\t說明\n" % (status, fname.replace("_", "\\_")))

    def build(self, tag=TAG, **kw):
        args = dict(manifests=self.manifests, ci_out=self.ci, supplier_prep=self.prep, out=self.out, tag=tag, commit=COMMIT,
                    built_at=BUILT, workflow_run=RUN, sbom_check_log=self.sbom_log)
        args.update(kw)
        return fm.build(**args)


def full_env(test):
    e = Env(test)
    e.bios("board-a", expected={"ami_core": {"status": "not-found"}})
    e.bios("board-b", expect_log=None)
    e.sbom("vendor-sbom")
    e.manifest("vbios", "vbios-gap", status="GAP", firmware_version=None, notes="GAP：沒有檔案\n第二行",
               watch={"monitored": False, "why": "GAP：沒有檔案"})
    e.manifest("vbios", "vbios-nogpu", watch={"monitored": False, "why": "沒有 vBIOS 元件"})
    return e


# ------------------------------------------------------------------ tag

class Tags(unittest.TestCase):
    def test_valid(self):
        for t in ("firmware-demo/2026.11.20", "firmware-demo/2026.11.20.2", "firmware-demo/2026.11.20.9", "firmware-demo/2026.11.20.10",
                  "firmware-demo/2026.11.20.99", "firmware-demo/2024.02.29"):
            self.assertEqual(fm.check_tag(t), t)

    def test_invalid_format(self):
        for t in ("firmware-demo/2026.11.20.1", "firmware-demo/2026.11.20.0", "firmware-demo/2026.11.20.100", "firmware-demo/2026.11.20.02",
                  "firmware-demo/2026.11.20.", "firmware-demo/2026.1.20", "firmware-demo/26.11.20", "firmware-demo/2026-11-20",
                  "firmware-demo/v2026.11.20", "firmware-demo/2026.11.20\n", "firmware-demo/2026.11.20 ", "x/firmware-demo/2026.11.20",
                  "Firmware-demo/2026.11.20", "firmware-demo/", "firmware-demo", "dev/firmware-demo", "", "firmware-demo/2026.11.20/x",
                  "firmware-demo/2026.11.20.2.3", "firmware-demo/２０２６.11.20"):
            with self.assertRaises(fm.MetaError, msg=repr(t)):
                fm.check_tag(t)

    def test_invalid_dates(self):
        for t in ("firmware-demo/2026.02.29", "firmware-demo/2026.02.30", "firmware-demo/2026.13.01", "firmware-demo/2026.00.10",
                  "firmware-demo/2026.11.00", "firmware-demo/2026.11.31", "firmware-demo/2026.04.31", "firmware-demo/0000.00.00",
                  "firmware-demo/0000.01.01", "firmware-demo/2026.99.99"):
            with self.assertRaises(fm.MetaError, msg=t):
                fm.check_tag(t)

    def test_test_tag_only_with_the_flag(self):
        self.assertEqual(fm.check_tag(fm.TEST_TAG, allow_test=True), fm.TEST_TAG)
        with self.assertRaises(fm.MetaError):
            fm.check_tag(fm.TEST_TAG)
        with self.assertRaises(fm.MetaError):          # 旗標只放行這一個值，不放行別的壞 tag
            fm.check_tag("firmware-demo/2026.02.30", allow_test=True)

    def test_non_string(self):
        for t in (None, 5, b"firmware-demo/2026.11.20"):
            with self.assertRaises(fm.MetaError):
                fm.check_tag(t)

    def test_test_tag_passes_collect_and_rematch_tag_rules(self):
        col = fm.load_collect(COLLECT)
        kind, project, ver = col.classify(fm.TEST_TAG, False)
        self.assertEqual((kind, project, ver), ("firmware", "firmware-demo", "0000.00.00"))
        for t in ("firmware-demo/2026.11.20", "firmware-demo/2026.11.20.12"):
            self.assertEqual(col.classify(t, False)[0], "firmware")


# ------------------------------------------------------------------ 產生器

class Build(unittest.TestCase):
    def test_keys_match_the_example(self):
        meta = full_env(self).build()
        with open(EXAMPLE, encoding="utf-8") as fh:
            ex = json.load(fh)
        self.assertEqual(set(meta), set(ex) - {"_note"})
        self.assertEqual(list(meta), [k for k in ex if k != "_note"])             # 順序也相同
        ex_bios = next(x for x in ex["samples"] if x["kind"] == "bios")
        ex_sbom = next(x for x in ex["samples"] if x["kind"] == "sbom")
        for x in meta["samples"]:
            self.assertEqual(set(x), set(ex_bios if x["kind"] == "bios" else ex_sbom), x["slug"])
        self.assertEqual({k for x in meta["not_watched"] for k in x}, {k for x in ex["not_watched"] for k in x})
        self.assertEqual(set(meta["tables"]), set(ex["tables"]))
        for t in ex["tables"]:
            self.assertEqual(set(meta["tables"][t]), set(ex["tables"][t]), t)

    def test_sample_fields_and_files(self):
        e = full_env(self)
        meta = e.build()
        self.assertEqual([x["slug"] for x in meta["samples"]], ["board-a", "board-b", "vendor-sbom"])
        a = meta["samples"][0]
        self.assertEqual((a["kind"], a["firmware_version"], a["status"], a["expect"]), ("bios", "1.0", "ATTENTION", "OK"))
        self.assertEqual(a["image_sha256"], "%064x" % 1)
        self.assertEqual(a["sbom"], "fw-board-a.cdx.json")
        self.assertEqual(a["inventory"], "fw-inventory-board-a.json")
        names = sorted(os.listdir(e.out))
        self.assertEqual(names, sorted(["firmware-meta.json", "fw-board-a.cdx.json", "fw-board-b.cdx.json", "fw-vendor-sbom.cdx.json",
                                        "fw-inventory-board-a.json", "fw-inventory-board-b.json"]))
        for name in names:
            self.assertTrue(name.endswith(".json"))                                 # 只有 JSON，沒有二進位檔
        for x in meta["samples"]:
            with open(os.path.join(e.out, x["sbom"]), "rb") as fh:
                self.assertEqual(sha(fh.read()), x["sbom_sha256"])
            if x["inventory"]:
                with open(os.path.join(e.out, x["inventory"]), "rb") as fh:
                    self.assertEqual(sha(fh.read()), x["inventory_sha256"])
        with open(os.path.join(e.out, "firmware-meta.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), meta)

    def test_expect_values(self):
        e = Env(self)
        e.bios("a-none")                                                            # firmware.yml 沒寫 expected
        e.bios("b-ok", expected={"ami_core": {}}, expect_log="FIRMWARE-EXPECT\tOK\tb\tx\nFIRMWARE-EXPECT\tSUMMARY\tb\ty\n")
        e.bios("c-mismatch", expected={"ami_core": {}}, expect_log="FIRMWARE-EXPECT\tOK\tc\tx\nFIRMWARE-EXPECT\tMISMATCH\tc\ty\nFIRMWARE-EXPECT\tMISSING\tc\tz\n")
        e.bios("d-missing", expected={"ami_core": {}}, expect_log="FIRMWARE-EXPECT\tMISSING\td\ty\nFIRMWARE-EXPECT\tNOT_RUN\td\tz\n")
        e.bios("e-error", expected={"ami_core": {}}, expect_log="FIRMWARE-EXPECT\tERROR\te\t格式\n")
        e.bios("f-notrun", expected={"ami_core": {}}, expect_log="FIRMWARE-EXPECT\tNOT_RUN\tf\tx\n")
        e.bios("g-nolog", expected={"ami_core": {}}, expect_log=None)
        e.bios("h-empty-log", expected={"ami_core": {}}, expect_log="")
        got = {x["slug"]: x["expect"] for x in e.build()["samples"]}
        self.assertEqual(got, {"a-none": "NONE", "b-ok": "OK", "c-mismatch": "MISMATCH", "d-missing": "MISSING", "e-error": "ERROR",
                               "f-notrun": "NOT_RUN", "g-nolog": "NOT_RUN", "h-empty-log": "NOT_RUN"})
        self.assertTrue(set(got.values()) <= set(fm.EXPECT_VALUES))

    def test_image_sha256_only_for_exactly_one_bios_image(self):
        e = Env(self)
        e.bios("one", inv=inventory(images=1))
        e.bios("two", inv=inventory(images=2))
        e.bios("none", inv=inventory(images=0))
        got = {x["slug"]: x["image_sha256"] for x in e.build()["samples"]}
        self.assertEqual(got, {"one": "%064x" % 1, "two": None, "none": None})

    def test_kind_sbom_fields(self):
        e = Env(self)
        e.bios("b")
        e.sbom("vendor-sbom", status="OK")
        x = next(s for s in e.build()["samples"] if s["slug"] == "vendor-sbom")
        self.assertEqual((x["kind"], x["normalized"], x["inventory"], x["inventory_sha256"], x["image_sha256"], x["expect"], x["status"]),
                         ("sbom", True, None, None, None, "NONE", "OK"))
        self.assertEqual(x["sbom"], "fw-vendor-sbom.cdx.json")
        with open(os.path.join(e.out, x["sbom"]), "rb") as fh, open(os.path.join(e.prep, "vendor-sbom", "sbom.cdx.json"), "rb") as src:
            self.assertEqual(fh.read(), src.read())                                 # 附的是正規化後的上傳副本
        self.assertFalse(os.path.exists(os.path.join(e.out, "fw-inventory-vendor-sbom.json")))

    def test_sbom_check_log(self):
        e = Env(self)
        e.bios("b")
        e.sbom("vendor-sbom", status="GAP")
        self.assertEqual(next(s for s in e.build()["samples"] if s["kind"] == "sbom")["status"], "GAP")
        for bad in ("FAIL", "NOT_RUN"):
            e = Env(self)
            e.bios("b")
            e.sbom("vendor-sbom", status=bad)
            with self.assertRaises(fm.MetaError, msg=bad):
                e.build()
        e = Env(self)
        e.bios("b")
        e.sbom("vendor-sbom")
        with self.assertRaises(fm.MetaError):                                       # 沒給狀態行
            e.build(sbom_check_log=None)
        open(e.sbom_log, "w").close()
        with self.assertRaises(fm.MetaError):                                       # 狀態行裡沒有這個樣本
            e.build()

    def test_status_not_ok_goes_to_not_watched_with_reason(self):
        e = full_env(self)
        nw = {x["slug"]: x["why"] for x in e.build()["not_watched"]}
        self.assertEqual(nw, {"vbios-gap": "GAP：沒有檔案", "vbios-nogpu": "沒有 vBIOS 元件"})
        e = Env(self)
        e.bios("b")
        e.manifest("bios", "no-file", status="GAP", firmware_version=None, notes="沒有合法可下載的檔案\n第二行")      # 沒宣告 watch
        self.assertEqual({x["slug"]: x["why"] for x in e.build()["not_watched"]}, {"no-file": "GAP：沒有合法可下載的檔案"})
        e = Env(self)
        e.bios("b")
        e.manifest("sbom", "gap-sbom", status="GAP", firmware_version=None, notes="GAP：x")
        self.assertEqual({x["slug"]: x["why"] for x in e.build()["not_watched"]}, {"gap-sbom": "GAP：x"})
        self.assertEqual([x["slug"] for x in e.build(out=e.out + "2")["samples"]], ["b"])      # GAP 的樣本不在 samples

    def test_declared_unmonitored_ok_sample_goes_to_not_watched(self):
        e = Env(self)
        e.bios("b")
        e.manifest("bios", "declared", watch={"monitored": False, "why": "宣告不監控的原因"})
        self.assertEqual(e.build()["not_watched"], [{"slug": "declared", "why": "宣告不監控的原因"}])

    def test_why_is_required(self):
        for w in ({"monitored": False, "why": ""}, {"monitored": False, "why": "  "}, {"monitored": False}):
            e = Env(self)
            e.bios("b")
            e.manifest("vbios", "v", watch=w)
            with self.assertRaises(fm.MetaError, msg=repr(w)):
                e.build()
        e = Env(self)                                                               # status 不是 ok、notes 也沒有可當原因的文字
        e.bios("b")
        e.manifest("vbios", "v", status="GAP", notes="  \n")
        with self.assertRaises(fm.MetaError):
            e.build()
        meta = {"schema": fm.META_SCHEMA, "samples": [], "not_watched": [{"slug": "v", "why": ""}]}      # 產生後的自己檢查也擋
        self.assertTrue(fm.validate_meta(meta))
        meta["not_watched"][0]["why"] = "   "
        self.assertTrue(fm.validate_meta(meta))

    def test_vbios_must_be_declared_not_inferred(self):
        e = Env(self)
        e.bios("b")
        e.manifest("vbios", "v")                                                    # status ok、沒有宣告
        with self.assertRaises(fm.MetaError):
            e.build()

    def test_table_identity_must_agree(self):
        e = Env(self)
        e.bios("a", inv=inventory(rules_sha="1" * 64))
        e.bios("b", inv=inventory(rules_sha="2" * 64))
        with self.assertRaises(fm.MetaError) as cm:
            e.build()
        self.assertIn("不一致", str(cm.exception))
        self.assertFalse(os.path.exists(e.out))                                     # 失敗不留半套輸出
        for section, path in (("advisory", ("source", "commit")), ("vbios_advisory", ("source", "reviewed_until"))):
            e = Env(self)
            e.bios("a")
            inv = inventory()
            inv[section][path[0]][path[1]] = "zzz"
            e.bios("b", inv=inv)
            with self.assertRaises(fm.MetaError, msg=section):
                e.build()

    def test_table_identity_values(self):
        meta = full_env(self).build()
        self.assertEqual(meta["tables"], {
            "fw_advisory_rules": {"sha256": "r" * 64, "table_updated": "2026-11-14"},
            "intel_microcode": {"source_commit": "c" * 40, "source_tag": "microcode-20261110", "table_sha256": "a" * 64},
            "nvidia_vbios": {"sha256": "b" * 64, "mirror_commit": "d" * 40, "reviewed_until": "2025-09-02"}})

    def test_table_section_not_ok_or_missing_fails(self):
        for mut in (lambda i: i["rules_advisory"].update(status="GAP"), lambda i: i.pop("advisory"),
                    lambda i: i["vbios_advisory"]["source"].pop("mirror_commit"), lambda i: i["rules_advisory"]["table"].update(sha256=5)):
            inv = inventory()
            mut(inv)
            e = Env(self)
            e.bios("a", inv=inv)
            with self.assertRaises(fm.MetaError):
                e.build()

    def test_bad_slug(self):
        for slug in ("Bad_Slug", "UPPER", "-lead", ".lead", "a" * 64, "has space", "summary", "ä"):
            e = Env(self)
            e.bios("ok-one")
            e.manifest("vbios", slug, watch={"monitored": False, "why": "x"})
            with self.assertRaises(fm.MetaError, msg=slug):
                e.build()
        e = Env(self)
        e.bios("a" * 63)                                                             # 63 字剛好可以
        self.assertEqual(e.build()["samples"][0]["slug"], "a" * 63)

    def test_duplicate_slug_across_kinds(self):
        e = Env(self)
        e.bios("dup")
        e.manifest("vbios", "dup", watch={"monitored": False, "why": "x"})
        with self.assertRaises(fm.MetaError):
            e.build()

    def test_missing_or_bad_inputs(self):
        e = Env(self)
        e.bios("a")
        os.remove(os.path.join(e.ci, "a", "fw-inventory.json"))
        with self.assertRaises(fm.MetaError):
            e.build()
        e = Env(self)
        e.bios("a", inv=inventory(status="FAIL"))
        with self.assertRaises(fm.MetaError):
            e.build()
        e = Env(self)
        e.bios("a", inv=inventory(schema="other/1"))
        with self.assertRaises(fm.MetaError):
            e.build()
        e = Env(self)
        e.bios("a", firmware_version=3404)                                           # YAML 數字（沒加引號）
        with self.assertRaises(fm.MetaError):
            e.build()
        e = Env(self)
        e.bios("a")
        os.remove(os.path.join(e.ci, "a", "fw.cdx.json"))
        with self.assertRaises(fm.MetaError):
            e.build()
        e = Env(self)
        e.manifest("vbios", "v", watch={"monitored": False, "why": "x"})              # 沒有任何 bios 樣本
        with self.assertRaises(fm.MetaError):
            e.build()

    def test_sbom_must_be_cyclonedx_json(self):
        e = Env(self)
        e.bios("a")
        with open(os.path.join(e.ci, "a", "fw.cdx.json"), "w") as fh:
            json.dump({"bomFormat": "SPDX"}, fh)
        with self.assertRaises(fm.MetaError):
            e.build()

    def test_ci_summary_must_agree_with_inventory_status(self):
        e = Env(self)
        e.bios("a", inv=inventory(status="ATTENTION"))
        summ = os.path.join(e.dir, "summary.md")
        with open(summ, "w", encoding="utf-8") as fh:
            fh.write("| 樣本 | x |\n|---|---|\n| a | ATTENTION vBIOS 0 個、BIOS\\|x | 3 | OK | - |\n")
        self.assertEqual(e.build(ci_summary=summ)["samples"][0]["status"], "ATTENTION")
        shutil.rmtree(e.out)
        with open(summ, "w", encoding="utf-8") as fh:
            fh.write("| a | GAP（沒有）| 3 | OK | - |\n")
        with self.assertRaises(fm.MetaError):
            e.build(ci_summary=summ)
        with open(summ, "w", encoding="utf-8") as fh:
            fh.write("| other | ATTENTION x | 3 | OK | - |\n")                       # 摘要沒有這個樣本
        with self.assertRaises(fm.MetaError):
            e.build(ci_summary=summ)

    def test_header_fields_validated(self):
        e = full_env(self)
        for kw in ({"commit": "ABC"}, {"commit": COMMIT.upper()}, {"commit": COMMIT + "\n"}, {"built_at": "2026-11-20"},
                   {"built_at": "2026-11-20T03:00:00+00:00"}, {"workflow_run": "http://x/y"}, {"workflow_run": "https://x y"},
                   {"tag": "firmware-demo/2026.02.30"}, {"tag": "firmware-demo/0000.00.00"}):
            with self.assertRaises(fm.MetaError, msg=repr(kw)):
                e.build(**kw)
        self.assertFalse(os.path.exists(e.out))
        self.assertEqual(e.build(tag=fm.TEST_TAG, allow_test_tag=True)["tag"], fm.TEST_TAG)

    def test_out_must_be_empty(self):
        e = full_env(self)
        os.makedirs(e.out)
        with open(os.path.join(e.out, "x"), "w") as fh:
            fh.write("x")
        with self.assertRaises(fm.MetaError):
            e.build()

    def test_release_notes(self):
        meta = full_env(self).build()
        text = fm.release_notes(meta)
        for s in meta["samples"]:
            self.assertIn(s["slug"], text)
        for s in meta["not_watched"]:
            self.assertIn(s["why"], text)
        self.assertIn("不是產品", text)
        self.assertIn("只有 JSON", text.replace("附件只有 JSON", "只有 JSON"))
        for bad in ("安全", "不適用", "不受影響", "整體 PASS", "以前", "這一輪", "驗證後", "原本", "我們", "我 "):
            self.assertNotIn(bad, text)


# ------------------------------------------------------------------ collect-check

class CollectCheck(unittest.TestCase):
    def setUp(self):
        self.env = full_env(self)
        self.meta = self.env.build()
        self.path = os.path.join(self.env.out, "firmware-meta.json")

    def check(self, tag=TAG):
        return fm.collect_check(self.path, self.env.out, tag, COLLECT)

    def rewrite(self, mut):
        meta = copy.deepcopy(self.meta)
        mut(meta)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)

    def test_good(self):
        self.assertEqual(self.check(), [])

    def test_wrong_tag(self):
        self.assertTrue(self.check("firmware-demo/2026.11.21"))

    def test_attachment_sha_mismatch(self):
        with open(os.path.join(self.env.out, "fw-board-a.cdx.json"), "a") as fh:
            fh.write(" ")
        probs = self.check()
        self.assertTrue(any("fw-board-a.cdx.json" in p and "sha256" in p for p in probs), probs)

    def test_missing_extra_and_non_json_attachment(self):
        os.remove(os.path.join(self.env.out, "fw-inventory-board-b.json"))
        with open(os.path.join(self.env.out, "extra.bin"), "wb") as fh:
            fh.write(b"\x00")
        probs = self.check()
        self.assertTrue(any("fw-inventory-board-b.json" in p for p in probs), probs)
        self.assertTrue(any("extra.bin" in p for p in probs), probs)

    def test_collect_rules(self):
        cases = {
            "schema": lambda m: m.update(schema="x/1"),
            "commit": lambda m: m.update(commit="abc"),
            "built_at type": lambda m: m.update(built_at=5),
            "not_watched why": lambda m: m["not_watched"][0].update(why=""),
            "not_watched slug": lambda m: m["not_watched"][0].update(slug="Bad"),
            "tables": lambda m: m.update(tables=[]),
            "sbom name": lambda m: m["samples"][0].update(sbom="fw-other.cdx.json"),
            "inventory name": lambda m: m["samples"][0].update(inventory="fw-inventory-other.json"),
            "sha format": lambda m: m["samples"][0].update(sbom_sha256="A" * 64),
            "sbom inventory": lambda m: m["samples"][2].update(inventory="fw-inventory-vendor-sbom.json", inventory_sha256="a" * 64),
            "normalized": lambda m: m["samples"][2].update(normalized="yes"),
            "kind": lambda m: m["samples"][0].update(kind="vbios"),
            "too many": lambda m: m.update(samples=m["samples"] * 40),
        }
        for name, mut in cases.items():
            self.rewrite(mut)
            self.assertTrue(self.check(), name)

    def test_placeholder_version_is_a_problem(self):
        self.rewrite(lambda m: m["samples"][0].update(firmware_version="xx.xx.xx"))
        self.assertTrue(any("監控鍵" in p for p in self.check()))

    def test_loads_collect_by_path_and_requires_the_functions(self):
        d = tempfile.mkdtemp(prefix="dumpling-fwmeta-")
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "collect.py")
        with open(p, "w") as fh:
            fh.write("def check_fw_meta(m, t):\n    return None\n")
        with self.assertRaises(fm.MetaError):
            fm.load_collect(p)


# ------------------------------------------------------------------ rematch-check（合成的 rematch 輸出）

class RematchCheckSynthetic(unittest.TestCase):
    def setUp(self):
        self.env = Env(self)
        self.env.bios("board-a")
        self.env.sbom("vendor-sbom")
        self.meta = self.env.build()
        self.mp = os.path.join(self.env.out, "firmware-meta.json")
        self.rm = os.path.join(self.env.dir, "rm")
        os.makedirs(self.rm)
        x = self.meta["samples"][0]
        tables = {t: {**v, "status": "OK", "stale": False} for t, v in self.meta["tables"].items()}
        self.doc = {"slug": "board-a", "status": x["status"], "inventory_sha256": x["inventory_sha256"], "changed": [], "tables": tables}
        self.summary = {"meta_status": "OK", "release_tag": TAG, "rejected": [], "tables": tables,
                        "samples": [{"slug": "board-a", "status": x["status"], "output": "rematch-board-a.json"}]}
        self.write()

    def write(self):
        for name, d in (("rematch-board-a.json", self.doc), ("rematch-summary.json", self.summary)):
            with open(os.path.join(self.rm, name), "w") as fh:
                json.dump(d, fh)

    def test_good(self):
        self.assertEqual(fm.rematch_check(self.mp, self.rm), [])

    def test_changed_must_be_empty(self):
        self.doc["changed"] = [{"key": "k"}]
        self.write()
        self.assertTrue(any("changed" in p for p in fm.rematch_check(self.mp, self.rm)))

    def test_status_must_match(self):
        self.summary["samples"][0]["status"] = "GAP"
        self.write()
        self.assertTrue(any("狀態" in p for p in fm.rematch_check(self.mp, self.rm)))

    def test_table_identity_and_status(self):
        self.doc["tables"]["nvidia_vbios"]["mirror_commit"] = "9" * 40
        self.write()
        self.assertTrue(any("識別" in p for p in fm.rematch_check(self.mp, self.rm)))
        self.doc["tables"]["nvidia_vbios"]["mirror_commit"] = self.meta["tables"]["nvidia_vbios"]["mirror_commit"]
        self.doc["tables"]["intel_microcode"]["status"] = "GAP"
        self.write()
        self.assertTrue(fm.rematch_check(self.mp, self.rm))

    def test_missing_or_extra_sample_and_gap_meta(self):
        self.summary["samples"] = []
        self.write()
        self.assertTrue(any("NOT_RUN" in p for p in fm.rematch_check(self.mp, self.rm)))
        self.summary["samples"] = [{"slug": "board-a", "status": "ATTENTION"}, {"slug": "vendor-sbom", "status": "OK"}]
        self.write()
        self.assertTrue(any("vendor-sbom" in p for p in fm.rematch_check(self.mp, self.rm)))
        self.summary.update(meta_status="GAP", reasons=["rematch-input-invalid: x"], samples=[])
        self.write()
        self.assertTrue(fm.rematch_check(self.mp, self.rm))

    def test_rejected_and_inventory_sha(self):
        self.summary["rejected"] = [{"index": 0, "reason": "invalid-slug"}]
        self.write()
        self.assertTrue(fm.rematch_check(self.mp, self.rm))
        self.summary["rejected"] = []
        self.doc["inventory_sha256"] = "0" * 64
        self.write()
        self.assertTrue(fm.rematch_check(self.mp, self.rm))


# ------------------------------------------------------------------ 本機端到端：meta → rematch → changed 是空的

def run_rematch(meta, directory, out):
    return subprocess.run([REMATCH, "--meta", meta, "--dir", directory, "--now", NOW, "--out", out], capture_output=True, text=True)


def real_manifests():
    return sorted(glob.glob(os.path.join(ROOT, "firmware", "*", "*", "firmware.yml")))


class EndToEnd(unittest.TestCase):
    def small_env(self, mutate=None):
        e = Env(self)
        d = os.path.join(e.ci, "ubuntu-ovmf-2024.02")
        os.makedirs(d)
        with open(os.path.join(SMALL, "fw-inventory.json"), encoding="utf-8") as fh:
            inv = json.load(fh)
        if mutate:
            mutate(inv)
        with open(os.path.join(d, "fw-inventory.json"), "w", encoding="utf-8") as fh:
            json.dump(inv, fh, ensure_ascii=False, indent=1)
        shutil.copy(os.path.join(SMALL, "fw.cdx.json"), os.path.join(d, "fw.cdx.json"))
        e.manifests = [os.path.join(ROOT, "firmware", "bios", "ubuntu-ovmf-2024.02", "firmware.yml")] + \
            [p for p in real_manifests() if "/vbios/" in p]
        return e

    def test_real_sample_meta_is_accepted_by_collect_and_rematch(self):
        e = self.small_env()
        meta = e.build(tag=fm.TEST_TAG, allow_test_tag=True)
        self.assertEqual([x["slug"] for x in meta["samples"]], ["ubuntu-ovmf-2024.02"])
        self.assertEqual({x["slug"] for x in meta["not_watched"]}, {"nvidia-displayport-fw-updater-1.1", "standalone-nvidia-option-rom"})
        mp = os.path.join(e.out, "firmware-meta.json")
        self.assertEqual(fm.collect_check(mp, e.out, fm.TEST_TAG, COLLECT), [])
        rm = os.path.join(e.dir, "rematch")
        r = run_rematch(mp, e.out, rm)
        self.assertIn(r.returncode, (0, 2), r.stdout + r.stderr)
        self.assertEqual(fm.rematch_check(mp, rm), [], r.stdout)
        with open(os.path.join(rm, "rematch-ubuntu-ovmf-2024.02.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["changed"], [])

    def test_changed_is_detected(self):
        def mutate(inv):             # Release 當時記錄在元件上的規則比對結果，和今天的表算出來的不同
            hits = []

            def walk(x):
                if isinstance(x, dict):
                    if isinstance(x.get("rule_advisory"), dict):
                        hits.append(x["rule_advisory"])
                    for v in x.values():
                        walk(v)
                elif isinstance(x, list):
                    for v in x:
                        walk(v)
            walk(inv)
            self.assertTrue(hits)
            hits[0]["suggestion"] = "affected"
        e = self.small_env(mutate)
        e.build(tag=fm.TEST_TAG, allow_test_tag=True)
        mp = os.path.join(e.out, "firmware-meta.json")
        rm = os.path.join(e.dir, "rematch")
        run_rematch(mp, e.out, rm)
        probs = fm.rematch_check(mp, rm)
        self.assertTrue(any("changed" in p for p in probs), probs)

    def test_tampered_attachment_is_rejected_by_rematch(self):
        e = self.small_env()
        e.build(tag=fm.TEST_TAG, allow_test_tag=True)
        mp = os.path.join(e.out, "firmware-meta.json")
        with open(os.path.join(e.out, "fw-inventory-ubuntu-ovmf-2024.02.json"), "a") as fh:
            fh.write(" ")
        rm = os.path.join(e.dir, "rematch")
        run_rematch(mp, e.out, rm)
        self.assertTrue(fm.rematch_check(mp, rm))

    def test_real_ci_artifacts(self):
        """DUMPLING_REMATCH_ART 指到 CI artifact（每個樣本一個子資料夾：fw-inventory.json、fw.cdx.json、expect.log）時，6 份真樣本都跑；沒設就略過。"""
        art = os.environ.get("DUMPLING_REMATCH_ART")
        if not art:
            self.skipTest("DUMPLING_REMATCH_ART 沒設：只跑 repo 內的小樣本")
        e = Env(self)
        e.ci = art
        e.manifests = [p for p in real_manifests() if "/sbom/" not in p]
        meta = e.build(tag=fm.TEST_TAG, allow_test_tag=True)
        self.assertEqual(len(meta["samples"]), len([p for p in e.manifests if "/bios/" in p]))
        mp = os.path.join(e.out, "firmware-meta.json")
        self.assertEqual(fm.collect_check(mp, e.out, fm.TEST_TAG, COLLECT), [])
        rm = os.path.join(e.dir, "rematch")
        r = run_rematch(mp, e.out, rm)
        self.assertIn(r.returncode, (0, 2), r.stdout + r.stderr)
        self.assertEqual(fm.rematch_check(mp, rm), [], r.stdout)


# ------------------------------------------------------------------ workflow

def glob_to_re(pattern):
    """GitHub Actions 的 tag 過濾：* 不跨 /，** 跨 /，? 是前一個字元可有可無（這裡的 pattern 沒有 ?）。"""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out)


class Workflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, ".github", "workflows", "firmware.yml"), encoding="utf-8") as fh:
            cls.text = fh.read()
        cls.wf = yaml.safe_load(cls.text)
        cls.on = cls.wf.get("on", cls.wf.get(True))
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml"), encoding="utf-8") as fh:
            cls.release = yaml.safe_load(fh.read())

    def test_triggers(self):
        self.assertEqual(self.on["push"], {"tags": ["firmware-demo/*"]})
        self.assertIn("pull_request", self.on)
        self.assertIn("workflow_dispatch", self.on)
        self.assertNotIn("branches", self.on["push"])                                # 沒有分支的 push 觸發

    def test_release_yml_is_not_triggered_by_firmware_tags(self):
        pats = (self.release.get("on") or self.release.get(True))["push"]["tags"]
        for tag in ("firmware-demo/2026.11.20", "firmware-demo/2026.11.20.2", "firmware-demo/0000.00.00"):
            for p in pats:
                self.assertIsNone(glob_to_re(p).fullmatch(tag), (p, tag))
        self.assertIsNotNone(glob_to_re(pats[0]).fullmatch("ai-nas-demo/v1.0.0"))   # 轉換本身沒壞：板子的 tag 還是會觸發
        self.assertIsNotNone(glob_to_re("firmware-demo/*").fullmatch("firmware-demo/2026.11.20"))
        self.assertIsNone(glob_to_re("firmware-demo/*").fullmatch("firmware-demo/a/b"))

    def test_only_the_release_job_can_write(self):
        self.assertEqual(self.wf["permissions"], {"contents": "read"})
        writers = [name for name, j in self.wf["jobs"].items() if "write" in str((j.get("permissions") or {}).values())]
        self.assertEqual(writers, ["firmware-release"])
        self.assertEqual(self.wf["jobs"]["firmware-release"]["permissions"], {"contents": "write"})
        self.assertNotIn("write-all", self.text)
        self.assertNotIn("permissions: write", self.text)

    def test_release_job_runs_only_for_tag_push_after_every_check(self):
        j = self.wf["jobs"]["firmware-release"]
        cond = j["if"]
        self.assertIn("github.event_name == 'push'", cond)
        self.assertIn("github.ref_type == 'tag'", cond)
        self.assertIn("startsWith(github.ref_name, 'firmware-demo/')", cond)
        self.assertEqual(set(j["needs"]), {"firmware-fetch", "firmware-dt", "firmware-release-check"})
        for name, other in self.wf["jobs"].items():                                  # 沒有其他 job 依賴 Release job 或建 Release
            self.assertNotIn("firmware-release", [x for x in (other.get("needs") or []) if name != "firmware-release"])
            if name != "firmware-release":
                self.assertNotIn("gh release", yaml.safe_dump(other))

    def test_release_is_published_not_prerelease_not_draft(self):
        steps = "\n".join(s.get("run", "") for s in self.wf["jobs"]["firmware-release"]["steps"])
        self.assertIn("--draft", steps)                                              # 先建草稿、確認附件，之後才發布
        self.assertIn("draft=false", steps)
        self.assertIn("prerelease=false", steps)
        self.assertNotIn("--prerelease", steps)
        self.assertIn("--verify-tag", steps)

    def test_self_check_steps_run_for_every_trigger(self):
        j = self.wf["jobs"]["firmware-release-check"]
        self.assertNotIn("if", j)
        self.assertEqual(j.get("permissions"), None)
        for s in j["steps"]:
            c = s.get("if")
            self.assertTrue(c is None or c == "always()", s.get("name", s.get("uses")))                # 沒有步驟只在某種觸發才跑（摘要用 always）
        runs = "\n".join(s.get("run", "") for s in j["steps"])
        for needle in ("firmware_meta.py build", "firmware_meta.py collect-check", "firmware-rematch.sh", "firmware_meta.py rematch-check",
                       "ci/public-check.sh", "--allow-test-tag", "firmware-demo/0000.00.00"):
            self.assertIn(needle, runs)
        self.assertNotIn("gh release", runs)

    def test_actions_are_pinned_to_commit_sha(self):
        uses = re.findall(r"^\s*(?:-\s+)?uses:\s*(\S+)", self.text, re.M)
        self.assertTrue(uses)
        for u in uses:
            self.assertRegex(u, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", u)

    def test_no_untrusted_expression_inside_run(self):
        for name, j in self.wf["jobs"].items():
            for s in j["steps"]:
                for m in re.findall(r"\$\{\{[^}]*\}\}", s.get("run", "")):
                    self.assertNotRegex(m, r"github\.(ref_name|head_ref|event)", (name, s["name"]))

    def test_workflow_text_has_no_forbidden_words(self):
        # 只掃這次新增的兩個 job（既有步驟的文字不在這裡檢查）
        start = self.text.index("  firmware-release-check:")
        added = self.text[start:]
        for bad in ("安全", "不適用", "不受影響", "整體 PASS", "以前", "這一輪", "驗證後", "原本"):
            self.assertNotIn(bad, added)


if __name__ == "__main__":
    unittest.main()
