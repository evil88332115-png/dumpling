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


def slurp(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


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
                    built_at=BUILT, workflow_run=RUN, sbom_check_log=self.sbom_log, dt_result="success")
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

    def job_text(self, name):
        return yaml.safe_dump(self.wf["jobs"][name])

    def test_release_job_runs_only_for_tag_push_and_does_not_need_dt(self):
        j = self.wf["jobs"]["firmware-release"]
        cond = j["if"]
        self.assertIn("github.event_name == 'push'", cond)
        self.assertIn("github.ref_type == 'tag'", cond)
        self.assertIn("startsWith(github.ref_name, 'firmware-demo/')", cond)
        self.assertEqual(set(j["needs"]), {"firmware-fetch", "firmware-release-check"})     # 不等 firmware-dt（C0 的決定）
        self.assertNotIn("firmware-dt", j["needs"])
        for name, other in self.wf["jobs"].items():                                  # 沒有其他 job 依賴 Release job 或建 Release
            self.assertNotIn("firmware-release", [x for x in (other.get("needs") or []) if name != "firmware-release"])
            if name != "firmware-release":
                self.assertNotIn("gh release", yaml.safe_dump(other))
                self.assertNotIn("firmware-release-publish", yaml.safe_dump(other))

    def test_check_job_waits_for_dt_but_is_not_blocked_by_it(self):
        j = self.wf["jobs"]["firmware-release-check"]
        self.assertEqual(set(j["needs"]), {"firmware-fetch", "firmware-dt"})
        cond = j["if"]
        self.assertIn("!cancelled()", cond)                                         # 整個 run 被取消時不跑；有狀態函式，所以 dt 失敗、取消、略過都不會讓這個 job 被跳過
        self.assertNotIn("always()", cond)
        self.assertIn("needs.firmware-fetch.result == 'success'", cond)             # fetch 沒成功就什麼都不做
        self.assertNotIn("firmware-dt", cond)
        self.assertNotIn("continue-on-error", self.job_text("firmware-release-check"))
        build = next(s for s in j["steps"] if "firmware_meta.py build" in s.get("run", ""))
        self.assertEqual(build["env"]["FW_DT_RESULT"], "${{ needs.firmware-dt.result }}")      # dt 的結果經 env 傳進產生器
        self.assertIn('--dt-result "$FW_DT_RESULT"', build["run"])
        self.assertNotIn("needs.firmware-dt.result", build["run"])                  # 不直接把 expression 寫進 shell

    def test_release_is_published_not_prerelease_not_draft(self):
        with open(os.path.join(ROOT, "pipeline", "firmware-release-publish.sh"), encoding="utf-8") as fh:
            script = fh.read()
        self.assertIn("--draft", script)                                             # 先建草稿、確認附件，之後才發布
        self.assertIn("--latest=false", script)
        self.assertIn("--verify-tag", script)
        self.assertIn("draft=false", script)
        self.assertIn("prerelease=false", script)
        self.assertNotIn("--prerelease", script)
        steps = "\n".join(s.get("run", "") for s in self.wf["jobs"]["firmware-release"]["steps"])
        self.assertIn("firmware-release-publish.sh", steps)
        self.assertIn("prerelease=false", steps)                                     # 發布後核對
        self.assertIn("draft=false", steps)
        self.assertNotIn("--prerelease", steps)

    def test_non_json_check_and_collect_check_before_publishing(self):
        steps = self.wf["jobs"]["firmware-release"]["steps"]
        runs = [s.get("run", "") for s in steps]
        i_check = next(i for i, r in enumerate(runs) if "find \"$assets\" -type f ! -name '*.json'" in r)
        i_pub = next(i for i, r in enumerate(runs) if "firmware-release-publish.sh \"$GITHUB_REF_NAME\"" in r)
        self.assertLess(i_check, i_pub)
        self.assertIn("collect-check", runs[i_check])

    def test_release_job_only_from_main_history(self):
        steps = self.wf["jobs"]["firmware-release"]["steps"]
        self.assertEqual(steps[0]["with"]["fetch-depth"], 0)                         # origin/main 的歷史要拿得到
        runs = [s.get("run", "") for s in steps]
        i_main = next(i for i, r in enumerate(runs) if "merge-base --is-ancestor" in r)
        self.assertIn('"$GITHUB_SHA" origin/main', runs[i_main])
        i_pub = next(i for i, r in enumerate(runs) if "firmware-release-publish.sh \"$GITHUB_REF_NAME\"" in r)
        self.assertLess(i_main, i_pub)
        self.assertIn("exit 1", runs[i_main])

    def test_leftover_drafts_are_cleaned_and_api_calls_retry(self):
        steps = self.wf["jobs"]["firmware-release"]["steps"]
        cleanup = [s for s in steps if "--cleanup" in s.get("run", "")]
        self.assertEqual(len(cleanup), 1)
        self.assertEqual(cleanup[0].get("if"), "failure()")
        with open(os.path.join(ROOT, "pipeline", "firmware-release-publish.sh"), encoding="utf-8") as fh:
            script = fh.read()
        self.assertIn("ghx", script)
        self.assertIn("-X DELETE", script)
        self.assertEqual(script.count("-X DELETE"), 1)                              # 只有一處刪除，用在草稿 id 上
        with open(os.path.join(ROOT, "pipeline", "firmware-ghx.sh"), encoding="utf-8") as fh:
            self.assertIn("GHX_TRIES:-8", fh.read())
        self.assertIn("firmware-ghx.sh", "\n".join(s.get("run", "") for s in steps))

    def test_dt_lifecycle_goes_through_dt_session(self):
        # T-04：firmware-dt 的 DT 起停只經 pipeline/firmware-dt-session.sh（dt-session.sh 的 dt_begin／dt_ready／dt_end），不自己呼叫 dt-ephemeral.sh
        steps = self.wf["jobs"]["firmware-dt"]["steps"]
        runs = [s.get("run", "") for s in steps]
        for r in runs:
            self.assertNotIn("dt-ephemeral.sh", r)
            self.assertNotRegex(r, r"(^|[\s;|&])pipeline/firmware-dt\.sh")             # 只經外層呼叫
        up = [s for s in steps if "firmware-dt-session.sh" in s.get("run", "")]
        self.assertEqual(len(up), 1)
        self.assertIn('--result "$RESULT_DIR"', up[0]["run"])
        self.assertNotIn("if", up[0])
        self.assertNotIn("MIRROR_REFRESH_STATUS", str(up[0].get("env")))           # 外層自己設（resident 時由 dt_mirror_status 拿掉）
        down = [s for s in steps if "dt_end" in s.get("run", "")]
        self.assertEqual(len(down), 1)
        self.assertEqual(down[0].get("if"), "always()")
        self.assertIn(". pipeline/lib/dt-session.sh", down[0]["run"])
        self.assertGreater(steps.index(down[0]), steps.index(up[0]))
        # 不選常駐 DT（GitHub 上一律 FAIL）：這份 workflow 的任何地方都不出現常駐模式的設定
        for name in ("DUMPLING_DT_", "DT_WAIT_RC_FILE"):
            self.assertNotIn(name, self.text)
        self.assertEqual(self.wf["jobs"]["firmware-dt"]["env"], {"DT_OSV_ECOSYSTEMS": "PyPI,npm,Ubuntu"})
        for p in ("pipeline/lib/dt-session.sh", "pipeline/lib/dt_resident.py", "pipeline/firmware-*.sh"):
            self.assertIn(p, self.on["pull_request"]["paths"])                     # 改了 DT 的起停也要跑這份 workflow

    def test_pilot_env_is_outside_the_result_dir(self):
        paths = next(s["run"] for s in self.wf["jobs"]["firmware-dt"]["steps"] if s.get("name") == "路徑")
        self.assertIn("PILOT_ENV=$RUNNER_TEMP/pilot-env/pilot.env", paths)          # dt_ready 也會擋，這裡先鎖住設定
        self.assertIn("RESULT_DIR=$RUNNER_TEMP/firmware-dt-result", paths)

    def test_no_pull_request_target_and_no_continue_on_error(self):
        self.assertNotIn("pull_request_target", self.on)
        self.assertNotIn("pull_request_target", self.text)
        for name in ("firmware-release-check", "firmware-release"):
            self.assertNotIn("continue-on-error", self.job_text(name), name)
            for st in self.wf["jobs"][name]["steps"]:
                self.assertNotIn("continue-on-error", st)

    def test_test_tag_flag_never_reaches_the_tag_branch_or_release_job(self):
        self.assertNotIn("--allow-test-tag", self.job_text("firmware-release"))
        self.assertNotIn("allow-test-tag", self.job_text("firmware-release").replace("allow_test", ""))
        step = next(s for s in self.wf["jobs"]["firmware-release-check"]["steps"] if "check-tag" in s.get("run", ""))
        run = step["run"]
        tag_branch = run[run.index('if [ "$GITHUB_REF_TYPE" = tag ]; then'):run.index("else")]
        self.assertNotIn("allow-test-tag", tag_branch)
        self.assertNotIn("0000.00.00", tag_branch)
        self.assertIn('check-tag "$GITHUB_REF_NAME"', tag_branch)
        self.assertIn('FW_TAG_FLAG=" >> "$GITHUB_ENV"', tag_branch)                  # 真的 tag：旗標是空的

    def test_cancel_in_progress_only_for_non_tag(self):
        self.assertEqual(self.wf["concurrency"]["cancel-in-progress"], "${{ github.ref_type != 'tag' }}")

    def test_uploaded_artifact_is_only_the_assets_folder(self):
        ups = [s for st in self.wf["jobs"].values() for s in st["steps"]
               if s.get("with", {}).get("name") == "firmware-release" and "upload-artifact" in s.get("uses", "")]
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0]["with"]["path"], "${{ runner.temp }}/rel-assets")
        gens = [s for s in self.wf["jobs"]["firmware-release-check"]["steps"] if "firmware_meta.py build" in s.get("run", "")]
        self.assertIn('--out "$RUNNER_TEMP/rel-assets"', gens[0]["run"])
        self.assertNotIn("rel-notes", ups[0]["with"]["path"])                       # 說明文字不在 artifact 裡（Release job 從 meta 重新產生）
        down = [s for s in self.wf["jobs"]["firmware-release"]["steps"] if s.get("with", {}).get("name") == "firmware-release"]
        self.assertEqual(down[0]["with"]["path"], "${{ runner.temp }}/rel-assets")

    def test_self_check_steps_run_for_every_trigger(self):
        j = self.wf["jobs"]["firmware-release-check"]
        self.assertEqual(j.get("permissions"), None)
        for s in j["steps"]:
            c = s.get("if")
            self.assertTrue(c is None or c == "always()", s.get("name", s.get("uses")))     # 沒有步驟只在某種觸發才跑（摘要用 always）
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


# ------------------------------------------------------------------ dt 欄位、嚴格的 status、why 的共同檢查、讀檔的限制

class DtField(unittest.TestCase):
    def test_three_results(self):
        for job, want in (("success", ("OK", "OK", None)), ("failure", ("GAP", "FAIL", fm.DT_REASON)), ("cancelled", ("GAP", "FAIL", fm.DT_REASON)),
                          ("skipped", ("GAP", "NOT_RUN", fm.DT_REASON)), ("", ("GAP", "NOT_RUN", fm.DT_REASON)),
                          ("surprise", ("GAP", "NOT_RUN", fm.DT_REASON)), (None, ("GAP", "NOT_RUN", fm.DT_REASON))):
            e = full_env(self)
            meta = e.build(dt_result=job, out=e.out + "-" + str(job))
            self.assertEqual(meta["dt"], dict(zip(("status", "result", "reason"), want)), job)
            with open(os.path.join(e.out + "-" + str(job), "firmware-meta.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["dt"], meta["dt"])
            self.assertEqual(fm.dt_problem(meta["dt"]), None)

    def test_only_two_status_result_combinations_are_valid(self):
        for bad_word in ("安全", "不適用", "不受影響", "整體 PASS"):          # 固定原因句會進 meta 與 Release 說明（公開文字）
            self.assertNotIn(bad_word, fm.DT_REASON)
        good = [{"status": "OK", "result": "OK", "reason": None}, {"status": "GAP", "result": "FAIL", "reason": fm.DT_REASON},
                {"status": "GAP", "result": "NOT_RUN", "reason": fm.DT_REASON}]
        for g in good:
            self.assertIsNone(fm.dt_problem(g))
        bad = [{"status": "OK", "result": "FAIL", "reason": None}, {"status": "OK", "result": "OK", "reason": fm.DT_REASON},
               {"status": "GAP", "result": "OK", "reason": None}, {"status": "GAP", "result": "OK", "reason": fm.DT_REASON},
               {"status": "GAP", "result": "FAIL", "reason": None}, {"status": "GAP", "result": "FAIL", "reason": "別的原因"},
               {"status": "GAP", "result": "FAIL", "reason": ""}, {"status": "OK", "result": "NOT_RUN", "reason": None},
               {"status": "ATTENTION", "result": "FAIL", "reason": fm.DT_REASON}, {"status": "GAP", "result": "ERROR", "reason": fm.DT_REASON},
               {"status": "OK", "result": "OK"}, {"status": "OK", "result": "OK", "reason": None, "x": 1}, None, [], "OK"]
        for b in bad:
            self.assertTrue(fm.dt_problem(b), b)
            meta = {"schema": fm.META_SCHEMA, "samples": [], "not_watched": [], "dt": b}
            self.assertTrue(fm.validate_meta(meta), b)
        self.assertTrue(fm.validate_meta({"schema": fm.META_SCHEMA, "samples": [], "not_watched": []}))      # 沒有 dt 也不行

    def test_example_file_has_a_valid_dt(self):
        with open(EXAMPLE, encoding="utf-8") as fh:
            ex = json.load(fh)
        self.assertIsNone(fm.dt_problem(ex["dt"]))

    def test_meta_with_dt_is_accepted_by_collect_and_notes_mention_it(self):
        for job in ("success", "failure", "skipped"):
            e = full_env(self)
            meta = e.build(dt_result=job, out=e.out + job)
            self.assertEqual(fm.collect_check(os.path.join(e.out + job, "firmware-meta.json"), e.out + job, TAG, COLLECT), [])
            text = fm.release_notes(meta)
            self.assertIn("臨時 Dependency-Track（DT）上傳：", text)
            if job == "success":
                self.assertIn("DT）上傳：OK", text)
            else:
                self.assertIn("GAP（結果 %s" % meta["dt"]["result"], text)
            for bad in ("安全", "不適用", "不受影響", "整體 PASS"):
                self.assertNotIn(bad, text)

    def test_dt_result_is_required_on_the_command_line(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "lib", "firmware_meta.py"), "build", "x.yml", "--ci-out", "a",
                            "--supplier-prep", "b", "--out", "c", "--tag", TAG, "--commit", COMMIT, "--built-at", BUILT, "--workflow-run", RUN],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--dt-result", r.stderr)


class StrictStatusAndWhy(unittest.TestCase):
    def test_status_other_than_ok_or_gap_fails_instead_of_becoming_not_watched(self):
        for st in ("OK", "Ok", "ok ", "GAP ", "gap", "", None, ["ok"], {"a": 1}, True, 1, "FAIL"):
            e = Env(self)
            e.bios("b")
            e.manifest("bios", "odd", status=st, firmware_version=None, notes="GAP：x")
            with self.assertRaises(fm.MetaError, msg=repr(st)):
                e.build()
            self.assertFalse(os.path.exists(e.out))
        e = Env(self)
        e.bios("b")
        p = e.manifest("bios", "odd")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("kind: bios\nstatus: [ok]\nnotes: n\n")                          # 清單
        with self.assertRaises(fm.MetaError):
            e.build()
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("kind: bios\nnotes: n\n")                                         # 沒有 status
        with self.assertRaises(fm.MetaError):
            e.build()

    def test_kind_must_be_a_known_string(self):
        for k in (["bios"], "BIOS", None, 5):
            e = Env(self)
            e.bios("b")
            p = e.manifest("bios", "odd")
            with open(p, "w", encoding="utf-8") as fh:
                yaml.safe_dump({"kind": k, "status": "ok", "notes": "n"}, fh)
            with self.assertRaises(fm.MetaError, msg=repr(k)):
                e.build()

    def test_monitored_true_with_non_ok_status_is_a_contradiction(self):
        e = Env(self)
        e.bios("b")
        e.manifest("bios", "odd", status="GAP", firmware_version=None, notes="GAP：x", watch={"monitored": True})
        with self.assertRaises(fm.MetaError) as cm:
            e.build()
        self.assertIn("矛盾", str(cm.exception))

    def test_status_gap_with_declared_false_is_fine(self):
        e = Env(self)
        e.bios("b")
        e.manifest("bios", "odd", status="GAP", firmware_version=None, notes="x", watch={"monitored": False, "why": "沒有檔案"})
        self.assertEqual(e.build()["not_watched"], [{"slug": "odd", "why": "GAP：沒有檔案"}])

    def test_why_derived_from_notes_uses_the_same_checks(self):
        for notes in ("\u200b\u200b", "\u2028", "a\x00b", "x" * 400, "\ufeff \u200d"):
            e = Env(self)
            e.bios("b")
            e.manifest("vbios", "v", status="GAP", firmware_version=None, notes=notes)
            if notes in ("a\x00b",):
                continue                                                              # YAML 不能放 NUL；控制字元由 clean_why 的單元測試涵蓋
            with self.assertRaises(fm.MetaError, msg=repr(notes)):
                e.build()

    def test_clean_why_rules(self):
        from firmware_watch import clean_why
        self.assertEqual(clean_why("  原因  "), "原因")
        self.assertEqual(clean_why("a\u200bb"), "a\u200bb")                           # 中間有零寬字元但還有可見字元：接受
        for bad in ("", "   ", "\u200b", "\u200b\u200c\u200d\u2060\ufeff", " \u200b ", "a\nb", "a\rb", "a\tb", "a\u2028b", "a\u2029b",
                    "a\u0085b", "a\x00b", "a\x7fb", "x" * 301, None, 5, ["x"], b"x"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                clean_why(bad)
        self.assertEqual(len(clean_why("x" * 300)), 300)

    def test_watch_why_uses_clean_why(self):
        from firmware_watch import parse_watch
        for bad in ("\u200b", "a\u2028b", "a\u0085b"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                parse_watch({"watch": {"monitored": False, "why": bad}})


class ReadRegular(unittest.TestCase):
    def test_symlink_is_refused(self):
        d = tempfile.mkdtemp(prefix="dumpling-fwmeta-")
        self.addCleanup(shutil.rmtree, d, True)
        real = os.path.join(d, "real.json")
        with open(real, "w") as fh:
            fh.write("{}")
        link = os.path.join(d, "link.json")
        os.symlink(real, link)
        self.assertEqual(fm.read_regular(real, "x"), b"{}")
        with self.assertRaises(fm.MetaError):
            fm.read_regular(link, "x")
        with self.assertRaises(fm.MetaError):
            fm.read_regular(d, "x")                                                   # 資料夾
        with self.assertRaises(fm.MetaError):
            fm.read_regular(os.path.join(d, "missing"), "x")

    def test_size_cap(self):
        d = tempfile.mkdtemp(prefix="dumpling-fwmeta-")
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "big.json")
        with open(p, "wb") as fh:
            fh.write(b"x" * 11)
        old = fm.MAX_FILE
        fm.MAX_FILE = 10
        self.addCleanup(setattr, fm, "MAX_FILE", old)
        with self.assertRaises(fm.MetaError):
            fm.read_regular(p, "x")
        fm.MAX_FILE = 11
        self.assertEqual(len(fm.read_regular(p, "x")), 11)

    def test_symlinked_ci_output_is_refused_by_build(self):
        e = Env(self)
        e.bios("a")
        target = os.path.join(e.dir, "elsewhere.json")
        shutil.move(os.path.join(e.ci, "a", "fw-inventory.json"), target)
        os.symlink(target, os.path.join(e.ci, "a", "fw-inventory.json"))
        with self.assertRaises(fm.MetaError):
            e.build()


class CollectCheckMore(unittest.TestCase):
    def test_duplicate_sample_and_watch_key(self):
        e = full_env(self)
        meta = e.build()
        path = os.path.join(e.out, "firmware-meta.json")
        dup = copy.deepcopy(meta)
        dup["samples"].append(copy.deepcopy(dup["samples"][0]))                     # 同一個樣本兩次：附件名與監控鍵都重複
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(dup, fh)
        probs = fm.collect_check(path, e.out, TAG, COLLECT)
        self.assertTrue(any("重複" in p for p in probs), probs)

    def test_two_slugs_cannot_share_a_watch_key(self):
        # 監控鍵是 <slug>@<版本>：不同 slug 不會撞；這裡直接核對 collect 的函式，確認 collect_check 用的是它
        col = fm.load_collect(COLLECT)
        self.assertEqual(col.fw_watch_version("a", "1.0", None), ("a@1.0", None))
        self.assertNotEqual(col.fw_watch_version("a", "1.0", None), col.fw_watch_version("b", "1.0", None))


class RematchCheckMore(RematchCheckSynthetic):
    def test_release_tag_must_match(self):
        self.summary["release_tag"] = "firmware-demo/2026.11.21"
        self.write()
        self.assertTrue(any("release_tag" in p for p in fm.rematch_check(self.mp, self.rm)))

    def test_meta_status_must_be_ok(self):
        for st in ("GAP", None, "ok"):
            self.summary["meta_status"] = st
            self.write()
            self.assertTrue(fm.rematch_check(self.mp, self.rm), st)


# ------------------------------------------------------------------ 建 Release 的腳本（假的 gh）與 API 回應處理

API = os.path.join(ROOT, "pipeline", "lib", "firmware_release_api.py")
PUBLISH = os.path.join(ROOT, "pipeline", "firmware-release-publish.sh")
GHX = os.path.join(ROOT, "pipeline", "firmware-ghx.sh")

FAKE_GH = r"""#!/usr/bin/env python3
import json, os, sys
state_dir = os.environ["FAKE_GH_STATE"]
sp = os.path.join(state_dir, "state.json")
state = json.load(open(sp))
log = open(os.path.join(state_dir, "calls.log"), "a")
a = sys.argv[1:]
log.write(" ".join(a) + "\n"); log.close()
def save(): json.dump(state, open(sp, "w"))
def fail_once(key):
    n = state.get("fail", {}).get(key, 0)
    if n > 0:
        state["fail"][key] = n - 1; save(); return True
    return False
if a[:1] == ["api"]:
    method = "GET"; args = a[1:]
    if args[:1] == ["-X"]: method = args[1]; args = args[2:]
    path = args[0]
    parts = path.split("/")
    if method == "GET" and parts[-1] == "releases":
        if fail_once("list"): sys.stderr.write("HTTP 403\n"); sys.exit(1)
        sys.stdout.write(json.dumps(state["releases"][:1]) + json.dumps(state["releases"][1:])); sys.exit(0)
    if method == "GET" and parts[-2] == "releases":
        r = [x for x in state["releases"] if str(x["id"]) == parts[-1]]
        print(json.dumps(r[0])); sys.exit(0)
    if method == "DELETE":
        rid = parts[-1]
        state.setdefault("deleted", []).append(rid)
        state["releases"] = [x for x in state["releases"] if str(x["id"]) != rid]; save(); sys.exit(0)
    if method == "PATCH":
        rid = parts[-1]
        for x in state["releases"]:
            if str(x["id"]) == rid:
                x["draft"] = False; x["prerelease"] = False
        state.setdefault("patched", []).append(args); save(); sys.exit(0)
if a[:2] == ["release", "create"]:
    if "--notes-file" in a:
        state["notes_path"] = a[a.index("--notes-file") + 1]
        state["notes_body"] = open(state["notes_path"], encoding="utf-8").read(); save()
    if fail_once("create"):
        state["releases"].append({"id": state["next"], "tag_name": a[2], "draft": True, "assets": []}); state["next"] += 1; save()
        sys.stderr.write("upload failed\n"); sys.exit(1)
    files = []
    for x in a[3:]:
        if x.startswith("--"): break
        files.append(x)
    assets = [{"name": os.path.basename(f), "size": os.path.getsize(f) + state.get("size_skew", 0), "state": "uploaded"} for f in files]
    state["releases"].append({"id": state["next"], "tag_name": a[2], "draft": True, "assets": assets}); state["next"] += 1
    state["created_args"] = a; save(); sys.exit(0)
sys.stderr.write("fake gh: unsupported " + " ".join(a) + "\n"); sys.exit(9)
"""


class PublishScript(unittest.TestCase):
    TAGN = "firmware-demo/2026.11.20"

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="dumpling-fwpub-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.bin = os.path.join(self.dir, "bin")
        os.makedirs(self.bin)
        with open(os.path.join(self.bin, "gh"), "w") as fh:
            fh.write(FAKE_GH)
        os.chmod(os.path.join(self.bin, "gh"), 0o755)
        self.assets = os.path.join(self.dir, "assets")
        os.makedirs(self.assets)
        for n, c in (("firmware-meta.json", "{}"), ("fw-a.cdx.json", "{\"bomFormat\": \"CycloneDX\"}")):
            with open(os.path.join(self.assets, n), "w") as fh:
                fh.write(c)
        self.notes = os.path.join(self.dir, "notes.md")
        with open(self.notes, "w") as fh:
            fh.write("notes")
        self.state_dir = os.path.join(self.dir, "state")
        os.makedirs(self.state_dir)

    def state(self, releases=(), **extra):
        with open(os.path.join(self.state_dir, "state.json"), "w") as fh:
            json.dump({"releases": list(releases), "next": 100, **extra}, fh)

    def load(self):
        with open(os.path.join(self.state_dir, "state.json")) as fh:
            return json.load(fh)

    def run_script(self, *args):
        env = {"PATH": self.bin + ":" + os.environ["PATH"], "FAKE_GH_STATE": self.state_dir, "GH_REPO": "o/r", "GHX_SLEEP": "0", "GHX_TRIES": "3",
               "TMPDIR": self.dir, "HOME": self.dir}
        return subprocess.run(["bash", PUBLISH, *args], capture_output=True, text=True, env=env)

    def rel(self, rid, draft, tag=None, assets=()):
        return {"id": rid, "tag_name": tag or self.TAGN, "draft": draft, "assets": list(assets)}

    def test_publishes_when_nothing_exists(self):
        self.state()
        r = self.run_script(self.TAGN, self.assets, self.notes)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(st.get("deleted", []), [])
        self.assertEqual([(x["draft"]) for x in st["releases"]], [False])
        args = st["created_args"]
        for flag in ("--draft", "--verify-tag", "--latest=false"):
            self.assertIn(flag, args)
        self.assertEqual(sorted(os.path.basename(x) for x in args[3:] if not x.startswith("--") and x.endswith(".json")),
                         ["firmware-meta.json", "fw-a.cdx.json"])
        self.assertTrue(any("draft=false" in " ".join(p) and "prerelease=false" in " ".join(p) for p in st["patched"]))

    def test_leftover_drafts_of_the_same_tag_are_deleted_and_nothing_else(self):
        other_published = self.rel(7, False, tag="firmware-demo/2026.11.01")
        other_draft = self.rel(8, True, tag="firmware-demo/2026.11.19")
        self.state([other_published, self.rel(5, True), self.rel(6, True), other_draft])
        r = self.run_script(self.TAGN, self.assets, self.notes)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(sorted(st["deleted"]), ["5", "6"])                        # 只刪同 tag 的草稿；別的 tag 的草稿與正式版不動
        self.assertEqual({x["id"] for x in st["releases"]}, {7, 8, 100})

    def test_published_release_of_the_same_tag_stops_and_deletes_nothing(self):
        for published in (self.rel(9, False), {**self.rel(9, False), "prerelease": True}):
            self.state([self.rel(5, True), published])
            r = self.run_script(self.TAGN, self.assets, self.notes)
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            st = self.load()
            self.assertEqual(st.get("deleted", []), [])                              # 正式版與草稿都不刪
            self.assertEqual({x["id"] for x in st["releases"]}, {5, 9})
            self.assertNotIn("create", slurp(os.path.join(self.state_dir, "calls.log")))

    def test_retry_after_a_failed_upload_cleans_the_partial_draft(self):
        self.state(fail={"create": 1})
        r = self.run_script(self.TAGN, self.assets, self.notes)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(len(st["deleted"]), 1)                                      # 第一次失敗留下的草稿，第二次嘗試先清掉
        self.assertEqual([x["draft"] for x in st["releases"]], [False])

    def test_transient_api_failure_is_retried(self):
        self.state(fail={"list": 2})
        r = self.run_script(self.TAGN, self.assets, self.notes)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_persistent_failure_exits_nonzero_and_leaves_no_published_release(self):
        self.state(fail={"create": 99})
        r = self.run_script(self.TAGN, self.assets, self.notes)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertTrue(all(x["draft"] for x in self.load()["releases"]))

    def test_asset_mismatch_is_not_published(self):
        self.state(size_skew=1)
        r = self.run_script(self.TAGN, self.assets, self.notes)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        st = self.load()
        self.assertEqual(st.get("patched", []), [])
        self.assertTrue(all(x["draft"] for x in st["releases"]))

    def test_cleanup_mode_only_deletes_drafts_of_the_tag(self):
        self.state([self.rel(5, True), self.rel(7, False, tag="x/1"), self.rel(8, True, tag="x/1")])
        r = self.run_script("--cleanup", self.TAGN)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.load()["deleted"], ["5"])
        self.state([self.rel(5, True), self.rel(9, False)])                         # 同 tag 已有正式版：什麼都不刪
        r = self.run_script("--cleanup", self.TAGN)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.load().get("deleted", []), [])

    def test_notes_urls_are_rewritten_before_the_release_is_created(self):
        text = "DT：https://dt.example.org/projects/1 與 [Release](https://github.com/o/r/releases/tag/x)。\n"
        with open(self.notes, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.state()
        r = self.run_script(self.TAGN, self.assets, self.notes)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.load()
        self.assertNotEqual(st["notes_path"], self.notes)                            # 交給 gh 的是改寫過的暫存檔
        self.assertNotIn("://", st["notes_body"])
        self.assertIn("`dt.example.org/projects/1`", st["notes_body"])
        self.assertIn("Release", st["notes_body"])
        self.assertEqual(slurp(self.notes), text)                                    # 說明文字檔本身不改

    def test_notes_rewrite_failure_creates_nothing(self):
        for content in (b"", b" \n\t\n", b"\xff\xfe not utf-8"):
            with open(self.notes, "wb") as fh:
                fh.write(content)
            self.state()
            r = self.run_script(self.TAGN, self.assets, self.notes)
            self.assertEqual(r.returncode, 1, content)
            self.assertIn("FAIL", r.stdout, content)
            self.assertFalse(os.path.exists(os.path.join(self.state_dir, "calls.log")), content)   # 一個 GitHub API 都沒有呼叫

    def test_failed_or_empty_rewrite_output_creates_nothing(self):
        pipe = os.path.join(self.dir, "pipeline")
        os.makedirs(os.path.join(pipe, "lib"))
        shutil.copy(PUBLISH, pipe)
        shutil.copy(GHX, pipe)
        shutil.copy(API, os.path.join(pipe, "lib"))
        stubs = ("import sys\nopen(sys.argv[2], 'w').write(' \\n')\n",         # 回 0 但內容空白
                 "import sys\nsys.exit(0)\n",                                      # 回 0 但沒有產生檔案
                 "import sys\nopen(sys.argv[2], 'w').write('notes')\nsys.exit(1)\n")   # 有內容但回 1
        for stub in stubs:
            with open(os.path.join(pipe, "release-body.py"), "w") as fh:
                fh.write(stub)
            self.state()
            env = {"PATH": self.bin + ":" + os.environ["PATH"], "FAKE_GH_STATE": self.state_dir, "GH_REPO": "o/r", "GHX_SLEEP": "0",
                   "GHX_TRIES": "3", "TMPDIR": self.dir, "HOME": self.dir}
            r = subprocess.run(["bash", os.path.join(pipe, "firmware-release-publish.sh"), self.TAGN, self.assets, self.notes],
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 1, stub + r.stdout + r.stderr)
            self.assertIn("FAIL", r.stdout, stub)
            self.assertFalse(os.path.exists(os.path.join(self.state_dir, "calls.log")), stub)

    def test_argument_and_attachment_checks(self):
        self.state()
        self.assertEqual(self.run_script(self.TAGN, self.assets).returncode, 64)
        with open(os.path.join(self.assets, "evil.bin"), "wb") as fh:
            fh.write(b"\x00")
        r = self.run_script(self.TAGN, self.assets, self.notes)
        self.assertEqual(r.returncode, 64, r.stdout + r.stderr)                      # 非 JSON 的附件不上傳
        self.assertNotIn("create", slurp(os.path.join(self.state_dir, "calls.log")) if os.path.exists(os.path.join(self.state_dir, "calls.log")) else "")


class ReleaseApi(unittest.TestCase):
    def test_parse_paginate_output(self):
        import firmware_release_api as api
        text = json.dumps([{"id": 1, "tag_name": "t", "draft": True}]) + "\n" + json.dumps([{"id": 2, "tag_name": "t", "draft": True}, {"id": 3, "tag_name": "u", "draft": False}])
        self.assertEqual(api.plan(text, "t"), (False, ["1", "2"]))
        self.assertEqual(api.plan(text, "u"), (True, []))
        self.assertEqual(api.plan("[]", "t"), (False, []))
        with self.assertRaises(ValueError):
            api.plan("not json", "t")

    def test_non_draft_ids_are_never_listed(self):
        import firmware_release_api as api
        text = json.dumps([{"id": 1, "tag_name": "t", "draft": False}, {"id": 2, "tag_name": "t", "draft": True},
                           {"id": "3", "tag_name": "t", "draft": True}, {"id": True, "tag_name": "t", "draft": True},
                           {"id": 4, "tag_name": "t", "draft": "true"}, "junk", None])
        published, drafts = api.plan(text, "t")
        self.assertTrue(published)
        self.assertEqual(drafts, ["2"])                                              # 1 是正式版：不會出現在待刪清單

    def test_verify_assets(self):
        import firmware_release_api as api
        d = tempfile.mkdtemp(prefix="dumpling-fwapi-")
        self.addCleanup(shutil.rmtree, d, True)
        for n, c in (("a.json", "12345"), ("b.json", "1")):
            with open(os.path.join(d, n), "w") as fh:
                fh.write(c)
        ok = {"assets": [{"name": "a.json", "size": 5, "state": "uploaded"}, {"name": "b.json", "size": 1, "state": "uploaded"}]}
        self.assertEqual(api.verify_assets(json.dumps(ok), d), [])
        for mut in (lambda r: r["assets"].pop(), lambda r: r["assets"][0].update(size=6), lambda r: r["assets"][0].update(state="starter"),
                    lambda r: r["assets"].append({"name": "c.json", "size": 1, "state": "uploaded"}), lambda r: r["assets"].append(dict(r["assets"][0]))):
            r = copy.deepcopy(ok)
            mut(r)
            self.assertTrue(api.verify_assets(json.dumps(r), d))
        self.assertTrue(api.verify_assets("[]", d))
        self.assertTrue(api.verify_assets("x", d))


class Ghx(unittest.TestCase):
    def run_ghx(self, body, tries="4"):
        d = tempfile.mkdtemp(prefix="dumpling-ghx-")
        self.addCleanup(shutil.rmtree, d, True)
        script = ". '%s'\n%s\n" % (GHX, body.replace("@D@", d))
        env = {"PATH": os.environ["PATH"], "GHX_SLEEP": "0", "GHX_TRIES": tries, "GH_REPO": "o/r"}
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, cwd=d)
        return r, d

    def test_retries_until_success(self):
        r, d = self.run_ghx('n=0; flaky() { n=$((n+1)); echo "$n" > @D@/n; [ "$n" -ge 3 ]; }\nghx flaky; echo rc=$?')
        self.assertIn("rc=0", r.stdout)
        self.assertEqual(slurp(os.path.join(d, "n")).strip(), "3")

    def test_gives_up_after_the_limit(self):
        r, d = self.run_ghx('always() { echo x >> @D@/n; false; }\ngh() { echo "gh-called" >&2; }\nghx always; echo rc=$?', tries="3")
        self.assertIn("rc=1", r.stdout)
        self.assertEqual(len(slurp(os.path.join(d, "n")).split()), 3)
        self.assertIn("診斷", r.stdout)

    def test_exit_code_3_is_not_retried(self):
        r, d = self.run_ghx('three() { echo x >> @D@/n; return 3; }\nghx three; echo rc=$?')
        self.assertIn("rc=3", r.stdout)
        self.assertEqual(len(slurp(os.path.join(d, "n")).split()), 1)


# ------------------------------------------------------------------ 整串相等的比對（tag、檔名、slug）

class ExactMatching(unittest.TestCase):
    """firmware-demo/2026.11.20 是 firmware-demo/2026.11.20.2 的前綴（.2 也是 .20 的前綴）：比對 tag、檔名一律要整串相等。"""

    def test_plan_tag_must_equal_not_prefix_suffix_or_substring(self):
        import firmware_release_api as api
        def rel(tag, draft, rid):
            return {"id": rid, "tag_name": tag, "draft": draft}
        pairs = (("firmware-demo/2026.11.20", "firmware-demo/2026.11.20.2"),       # 要查的 tag 是別人的前綴
                 ("firmware-demo/2026.11.20.2", "firmware-demo/2026.11.20.20"),
                 ("firmware-demo/2026.11.20.2", "firmware-demo/2026.11.20"),       # 別人是要查的 tag 的前綴
                 ("firmware-demo/2026.11.20", "xfirmware-demo/2026.11.20"),        # 後綴、子字串
                 ("firmware-demo/2026.11.20", "firmware-demo/2026.11.20 "),
                 ("firmware-demo/2026.11.20", "FIRMWARE-DEMO/2026.11.20"),
                 ("firmware-demo/2026.11.20", "firmware-demo/2026.11.2"))          # 查的 tag 比別人長
        for want, other in pairs:
            text = json.dumps([rel(other, False, 1), rel(other, True, 2)])
            self.assertEqual(api.plan(text, want), (False, []), (want, other))
            self.assertEqual(api.plan(text, other), (True, ["2"]), (want, other))    # 反過來查它自己：照常找得到
        # 同時有兩個 tag：只算整串相等的那一個
        text = json.dumps([rel("firmware-demo/2026.11.20.2", False, 1), rel("firmware-demo/2026.11.20", True, 2), rel("firmware-demo/2026.11.20.20", True, 3)])
        self.assertEqual(api.plan(text, "firmware-demo/2026.11.20"), (False, ["2"]))
        self.assertEqual(api.plan(text, "firmware-demo/2026.11.20.2"), (True, []))
        self.assertEqual(api.plan(text, "firmware-demo/2026.11.20.20"), (False, ["3"]))

    def run_plan(self, text, tag):
        r = subprocess.run([sys.executable, "-I", API, "releases-plan", "--tag", tag], input=text, capture_output=True, text=True)
        return r.returncode, r.stdout

    def test_releases_plan_cli_does_not_stop_or_delete_for_a_neighbouring_tag(self):
        text = json.dumps([{"id": 1, "tag_name": "firmware-demo/2026.11.20.2", "draft": False},
                           {"id": 2, "tag_name": "firmware-demo/2026.11.20.2", "draft": True}])
        self.assertEqual(self.run_plan(text, "firmware-demo/2026.11.20"), (0, ""))   # 不停下來（結束碼 3）、不列出別人的草稿
        self.assertEqual(self.run_plan(text, "firmware-demo/2026.11.20.2"), (3, "PUBLISHED\n"))
        self.assertEqual(self.run_plan(text, "firmware-demo/2026.11.20.20"), (0, ""))

    def test_verify_assets_names_must_equal(self):
        import firmware_release_api as api
        d = tempfile.mkdtemp(prefix="dumpling-fwapi-")
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "fw-a.cdx.json"), "w") as fh:
            fh.write("12345")
        def rel(name):
            return json.dumps({"assets": [{"name": name, "size": 5, "state": "uploaded"}]})
        self.assertEqual(api.verify_assets(rel("fw-a.cdx.json"), d), [])
        for other in ("fw-a.cdx.json.bak", "xfw-a.cdx.json", "fw-a.cdx.jso", "FW-A.cdx.json", "fw-a.cdx.json "):
            probs = api.verify_assets(rel(other), d)
            self.assertTrue(any("沒有上傳" in x for x in probs), other)             # 本機的檔案沒有同名的附件
            self.assertTrue(any("多出來的附件" in x for x in probs), other)

    def test_ci_summary_status_slug_must_equal(self):
        summary = "| board-a-2 | ATTENTION x |\n| xboard-a | GAP y |\n| board-a- | FAIL z |\n"
        for line in summary.splitlines():
            self.assertIsNone(fm.ci_summary_status(line, "board-a"), line)
        self.assertEqual(fm.ci_summary_status("| board-a | OK ok |", "board-a"), "OK")
        self.assertEqual(fm.ci_summary_status(summary + "| board-a | GAP g |", "board-a"), "GAP")

    def test_sbom_check_status_file_name_must_equal(self):
        doc = {"files": [{"name": "a.sbom.json", "role": "sbom"}]}
        for other in ("a.sbom.json.old", "xa.sbom.json", "a.sbom.jso", "A.sbom.json"):
            with self.assertRaises(fm.MetaError, msg=other):
                fm.sbom_check_status("FIRMWARE-SBOM\tOK\t%s\tx\n" % other, doc, "s")
        self.assertEqual(fm.sbom_check_status("FIRMWARE-SBOM\tGAP\ta.sbom.json\tx\nFIRMWARE-SBOM\tFAIL\ta.sbom.json.old\tx\n", doc, "s"), "GAP")

    def test_post_publish_state_check_compares_the_whole_line_as_a_fixed_string(self):
        steps = yaml.safe_load(slurp(os.path.join(ROOT, ".github", "workflows", "firmware.yml")))["jobs"]["firmware-release"]["steps"]
        run = next(s["run"] for s in steps if "release-state.txt" in s.get("run", ""))
        line = next(x for x in run.splitlines() if x.lstrip().startswith("grep "))
        self.assertRegex(line, r"grep -q[xF]{2} ")                                   # -x 整行相等；-F 不把 tag 裡的 . 當萬用字元


# ------------------------------------------------------------------ tag 的 commit 必須在 origin/main 的歷史裡（實際執行 workflow 的那一步）

class AncestorStep(unittest.TestCase):
    NEEDLE = "merge-base --is-ancestor"

    @classmethod
    def setUpClass(cls):
        wf = yaml.safe_load(slurp(os.path.join(ROOT, ".github", "workflows", "firmware.yml")))
        steps = [s for s in wf["jobs"]["firmware-release"]["steps"] if cls.NEEDLE in s.get("run", "")]
        assert len(steps) == 1, "找不到唯一的 ancestor 檢查步驟"
        cls.script = steps[0]["run"]
        cls.job_steps = wf["jobs"]["firmware-release"]["steps"]

    def git(self, *args):
        env = dict(self.env, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.org", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.org")
        r = subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=self.repo, env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="dumpling-fwanc-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.repo = os.path.join(self.dir, "repo")
        os.makedirs(self.repo)
        self.env = {"PATH": os.environ["PATH"], "HOME": self.dir, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C.UTF-8"}
        self.git("init", "-q", "-b", "main")
        self.git("commit", "-q", "--allow-empty", "-m", "c1")
        self.c1 = self.git("rev-parse", "HEAD")
        self.git("commit", "-q", "--allow-empty", "-m", "c2")
        self.c2 = self.git("rev-parse", "HEAD")                                      # main 的最新
        self.git("update-ref", "refs/remotes/origin/main", self.c2)
        self.git("checkout", "-q", "-b", "side", self.c1)                            # 沒有合併進 main 的分支
        self.git("commit", "-q", "--allow-empty", "-m", "side")
        self.side = self.git("rev-parse", "HEAD")
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--no-ff", "--no-edit", self.c1)                     # main 還是 c2（已包含 c1）

    def run_script(self, sha, script=None):
        sf = os.path.join(self.dir, "step.sh")
        with open(sf, "w", encoding="utf-8") as fh:
            fh.write(self.script if script is None else script)
        # Actions 的 shell：bash --noprofile --norc -eo pipefail {0}
        r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", sf], cwd=self.repo, capture_output=True, text=True,
                           env=dict(self.env, GITHUB_SHA=sha))
        return r.returncode, r.stdout + r.stderr

    def test_commit_on_main_passes(self):
        for sha in (self.c2, self.c1):                                               # main 的最新與較早的 commit
            rc, out = self.run_script(sha)
            self.assertEqual(rc, 0, out)

    def test_commit_not_on_main_fails(self):
        rc, out = self.run_script(self.side)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("不在 origin/main 的歷史裡", out)
        self.assertIn(self.side, out)

    def test_main_that_moved_past_the_commit_still_fails_for_the_other_branch(self):
        self.git("update-ref", "refs/remotes/origin/main", self.c1)                  # origin/main 落後：c2 不在它的歷史裡
        rc, out = self.run_script(self.c2)
        self.assertNotEqual(rc, 0, out)
        rc, out = self.run_script(self.c1)
        self.assertEqual(rc, 0, out)

    def test_missing_origin_main_fails(self):
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        rc, out = self.run_script(self.c1)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("找不到 origin/main", out)

    def test_unknown_or_garbage_sha_fails(self):
        for sha in ("0" * 40, "", "not-a-sha"):
            rc, out = self.run_script(sha)
            self.assertNotEqual(rc, 0, repr(sha))

    def test_step_sits_before_anything_is_downloaded_or_published(self):
        runs = [(s.get("uses", ""), s.get("run", "")) for s in self.job_steps]
        i = next(i for i, (_, r) in enumerate(runs) if self.NEEDLE in r)
        j = next(i2 for i2, (u, r) in enumerate(runs) if "download-artifact" in u)
        k = next(i3 for i3, (_, r) in enumerate(runs) if "firmware-release-publish.sh" in r)
        self.assertLess(i, j)
        self.assertLess(j, k)
        self.assertNotIn("continue-on-error", self.job_steps[i])


# ------------------------------------------------------------------ check job 的條件（不被 DT 阻擋、整個 run 被取消時不跑）

def eval_job_if(cond, needs, run_cancelled=False):
    """GitHub 的 job 條件（只支援 firmware.yml 用到的寫法）→ 這個 job 會不會跑。
    條件裡沒有狀態函式（success()、always()、cancelled()、failure()）時，GitHub 會自動加上 success()：
    run 沒被取消，而且 needs 的 job 全部 success。"""
    expr = cond.strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", expr, re.S)
    if m:
        expr = m.group(1).strip()
    status_fn, ok = False, True
    for clause in (c.strip() for c in expr.split("&&")):
        if clause == "always()":
            status_fn = True
        elif clause == "!cancelled()":
            status_fn, ok = True, ok and not run_cancelled
        elif clause == "success()":
            status_fn, ok = True, ok and not run_cancelled and all(v == "success" for v in needs.values())
        else:
            m = re.fullmatch(r"needs\.([\w-]+)\.result == '(\w+)'", clause)
            if not m:
                raise AssertionError("測試不認得的條件：%s" % clause)
            ok = ok and needs[m.group(1)] == m.group(2)
    if not status_fn:
        ok = ok and not run_cancelled and all(v == "success" for v in needs.values())
    return ok


class CheckJobCondition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = slurp(os.path.join(ROOT, ".github", "workflows", "firmware.yml"))
        cls.job = yaml.safe_load(cls.text)["jobs"]["firmware-release-check"]
        cls.cond = cls.job["if"]

    def test_runs_when_dt_failed_was_cancelled_or_skipped(self):
        for dt in ("success", "failure", "cancelled", "skipped"):
            self.assertTrue(eval_job_if(self.cond, {"firmware-fetch": "success", "firmware-dt": dt}), dt)

    def test_does_not_run_when_fetch_did_not_succeed(self):
        for fetch in ("failure", "cancelled", "skipped"):
            for dt in ("success", "failure"):
                self.assertFalse(eval_job_if(self.cond, {"firmware-fetch": fetch, "firmware-dt": dt}), (fetch, dt))

    def test_does_not_run_when_the_whole_run_is_cancelled(self):
        for dt in ("success", "failure", "cancelled"):
            self.assertFalse(eval_job_if(self.cond, {"firmware-fetch": "success", "firmware-dt": dt}, run_cancelled=True), dt)

    def test_uses_cancelled_not_always(self):
        self.assertIn("!cancelled()", self.cond)
        self.assertNotIn("always()", self.cond)

    def test_the_evaluator_tells_the_old_and_a_bare_condition_apart(self):
        # 測試用的求值器本身：always() 在取消時照跑；沒有狀態函式時 DT 失敗就被跳過
        self.assertTrue(eval_job_if("always() && needs.firmware-fetch.result == 'success'", {"firmware-fetch": "success", "firmware-dt": "failure"}, run_cancelled=True))
        self.assertFalse(eval_job_if("needs.firmware-fetch.result == 'success'", {"firmware-fetch": "success", "firmware-dt": "failure"}))

    def test_comment_says_release_waits_for_dt_but_is_not_blocked(self):
        start = self.text.index("  firmware-release:\n")
        comment = self.text[self.text.rindex("# 建 Release", 0, start):start]
        self.assertIn("不被臨時 DT 的結果阻擋", comment)
        self.assertIn("會等 DT 跑完", comment)
        self.assertNotIn("Release 不等臨時 DT", self.text)

    def test_download_artifact_pin_is_the_same_as_the_other_workflows(self):
        pins = {}
        for path in sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))):
            for m in re.finditer(r"uses:\s*actions/download-artifact@([0-9a-f]{40}) # (v[0-9.]+)", slurp(path)):
                pins.setdefault(m.groups(), []).append(os.path.basename(path))
        self.assertEqual(len(pins), 1, pins)                                         # 所有 workflow 用同一個 SHA 與同一個版本註解
        self.assertIn("firmware.yml", next(iter(pins.values())))


# ------------------------------------------------------------------ not_watched 的原因：長度、雙向控制字元；附件檔名不能撞

FWMETA = os.path.join(ROOT, "pipeline", "lib", "firmware_meta.py")


class WhyErrorsAndBidi(unittest.TestCase):
    def cli_build(self, env):
        r = subprocess.run([sys.executable, "-I", FWMETA, "build", *env.manifests, "--ci-out", env.ci, "--supplier-prep", env.prep, "--out", env.out,
                            "--tag", TAG, "--commit", COMMIT, "--built-at", BUILT, "--workflow-run", RUN, "--sbom-check-log", env.sbom_log,
                            "--dt-result", "success"], capture_output=True, text=True)
        return r

    def test_status_prefix_pushing_why_over_the_limit_is_a_meta_error(self):
        e = Env(self)
        e.bios("b")
        e.manifest("vbios", "v", status="GAP", firmware_version=None, notes="x", watch={"monitored": False, "why": "y" * 297})   # 「GAP：」4 字加 297 字＝301
        with self.assertRaises(fm.MetaError) as cm:
            e.build()
        self.assertIn("v", str(cm.exception))
        self.assertIn("300", str(cm.exception))
        self.assertFalse(os.path.exists(e.out))
        # 剛好 300 字可以
        e = Env(self)
        e.bios("b")
        e.manifest("vbios", "v", status="GAP", firmware_version=None, notes="x", watch={"monitored": False, "why": "y" * 296})
        self.assertEqual(len(e.build()["not_watched"][0]["why"]), 300)

    def test_cli_prints_the_fail_line_not_a_traceback(self):
        e = Env(self)
        e.bios("b")
        e.manifest("vbios", "v", status="GAP", firmware_version=None, notes="x", watch={"monitored": False, "why": "y" * 297})
        r = self.cli_build(e)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(r.stderr, "")
        lines = r.stdout.splitlines()
        self.assertEqual(len(lines), 1, r.stdout)
        self.assertRegex(lines[0], r"FIRMWARE-META\tFAIL\t-\t[^\t\n]+")
        self.assertFalse(os.path.exists(e.out))

    def test_not_watched_why_converts_every_clean_why_error(self):
        def doc(**kw):
            return dict({"status": "GAP", "notes": "n"}, **kw)
        for d, mon, why in ((doc(), False, "y" * 297), (doc(notes="y" * 301), None, None), (doc(notes="a\u202eb"), None, None),
                            (doc(), False, "a\u202eb")):
            with self.assertRaises(fm.MetaError, msg=repr((d, mon, why[:5] if why else why))):
                fm.not_watched_why("v", d, mon, why)
        self.assertEqual(fm.not_watched_why("v", doc(), False, "原因"), "GAP：原因")

    def test_clean_why_rejects_bidi_controls(self):
        from firmware_watch import clean_why
        bidi = [chr(c) for c in range(0x202A, 0x202F)] + [chr(c) for c in range(0x2066, 0x206A)] + ["\u200e", "\u200f", "\u061c"]
        self.assertEqual(len(bidi), 5 + 4 + 3)
        for ch in bidi:
            for raw in (ch, "a" + ch + "b", ch + "原因", "原因" + ch):
                with self.assertRaises(ValueError, msg="U+%04X %r" % (ord(ch), raw)):
                    clean_why(raw)
        self.assertEqual(clean_why("a​b"), "a​b")                           # 零寬字元（不是方向控制）還是可以在文字中間
        self.assertEqual(clean_why("العربية و English"), "العربية و English")         # 阿拉伯文、英文本身不是控制字元

    def test_bidi_in_why_fails_the_build_and_the_cli(self):
        for ch in ("\u202e", "\u2066", "\u200f", "\u061c"):
            for kw in ({"watch": {"monitored": False, "why": "沒有%s元件" % ch}}, {"status": "GAP", "firmware_version": None, "notes": "沒有%s檔案" % ch}):
                e = Env(self)
                e.bios("b")
                e.manifest("vbios", "v", **kw)
                with self.assertRaises(fm.MetaError, msg=repr((ch, kw))):
                    e.build()
                r = self.cli_build(e)
                self.assertEqual(r.returncode, 1)
                self.assertRegex(r.stdout, r"FIRMWARE-META\tFAIL\t-\t")
                self.assertNotIn(ch, r.stdout)                                       # 輸出裡不回顯控制字元
                self.assertNotIn("Traceback", r.stderr)

    def test_validate_meta_also_rejects_bidi(self):
        meta = {"schema": fm.META_SCHEMA, "samples": [], "not_watched": [{"slug": "v", "why": "a\u202eb"}]}
        self.assertTrue(fm.validate_meta(meta))

    def test_watch_why_rejects_bidi(self):
        from firmware_watch import parse_watch
        for ch in ("\u202a", "\u202e", "\u2069", "\u200e", "\u061c"):
            with self.assertRaises(ValueError, msg=hex(ord(ch))):
                parse_watch({"watch": {"monitored": False, "why": "a%sb" % ch}})

    def test_docs_state_the_bidi_rule(self):
        doc = slurp(os.path.join(ROOT, "docs", "notes", "c2-firmware-release.md"))
        for needle in ("雙向控制字元", "U+202A", "U+2066", "U+200E", "U+200F", "U+061C"):
            self.assertIn(needle, doc)


class AttachmentNameCollisions(unittest.TestCase):
    """附件名（fw-<slug>.cdx.json、fw-inventory-<slug>.json、firmware-meta.json）在同一個 Release 裡必須唯一；build 自己擋，不靠後面的 collect-check。"""

    def test_slugs_that_produce_the_same_file_name_fail(self):
        # bios `a.cdx` 的 inventory ＝ fw-inventory-a.cdx.json ＝ 樣本 `inventory-a` 的 SBOM
        self.assertEqual("fw-inventory-%s.json" % "a.cdx", "fw-%s.cdx.json" % "inventory-a")
        for order in (("a.cdx", "inventory-a"), ("inventory-a", "a.cdx")):
            for second_kind in ("bios", "sbom"):
                e = Env(self)
                kinds = {"a.cdx": "bios", "inventory-a": second_kind}
                for slug in order:
                    (e.bios if kinds[slug] == "bios" else e.sbom)(slug)
                with self.assertRaises(fm.MetaError, msg=repr((order, second_kind))) as cm:
                    e.build()
                self.assertIn("fw-inventory-a.cdx.json", str(cm.exception))
                self.assertIn("重複", str(cm.exception))
                self.assertFalse(os.path.exists(e.out))                              # 不留半套輸出

    def test_cli_prints_the_fail_line(self):
        e = Env(self)
        e.bios("a.cdx")
        e.bios("inventory-a")
        r = subprocess.run([sys.executable, "-I", FWMETA, "build", *e.manifests, "--ci-out", e.ci, "--supplier-prep", e.prep, "--out", e.out,
                            "--tag", TAG, "--commit", COMMIT, "--built-at", BUILT, "--workflow-run", RUN, "--dt-result", "success"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertRegex(r.stdout, r"FIRMWARE-META\tFAIL\t-\t附件檔名重複：fw-inventory-a\.cdx\.json")
        self.assertNotIn("Traceback", r.stderr)

    def test_similar_but_different_names_are_fine(self):
        e = Env(self)
        e.bios("a")
        e.bios("a.cdx")
        e.bios("inventory-a-x")
        e.sbom("inventory")
        meta = e.build()
        names = [x["sbom"] for x in meta["samples"]] + [x["inventory"] for x in meta["samples"] if x["inventory"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(sorted(os.listdir(e.out)), sorted(names + ["firmware-meta.json"]))

    def test_add_file_rejects_duplicates_and_the_meta_name(self):
        files = {}
        fm.add_file(files, "fw-a.cdx.json", b"1")
        with self.assertRaises(fm.MetaError):
            fm.add_file(files, "fw-a.cdx.json", b"2")
        self.assertEqual(files, {"fw-a.cdx.json": b"1"})                             # 先寫的內容沒被蓋掉
        with self.assertRaises(fm.MetaError):
            fm.add_file(files, fm.META_NAME, b"3")

    def test_docs_state_the_collision_rule(self):
        doc = slurp(os.path.join(ROOT, "docs", "notes", "c2-firmware-release.md"))
        self.assertIn("附件名在同一個 Release 裡必須唯一", doc)
        self.assertIn("fw-inventory-a.cdx.json", doc)


class OperationsDocs(unittest.TestCase):
    def setUp(self):
        self.doc = slurp(os.path.join(ROOT, "docs", "notes", "c2-firmware-release.md"))

    def section(self, title):
        i = self.doc.index(title)
        level = len(title) - len(title.lstrip("#"))
        m = re.compile(r"\n#{1,%d} " % level).search(self.doc, i + 1)             # 同層或更上層的下一個標題
        return self.doc[i:m.start() if m else len(self.doc)]

    def test_post_publish_check_failure_steps(self):
        s = self.section("### 發布之後的核對失敗")
        for needle in ("確認失敗原因", "不覆寫已發布的 Release", "由人決定", ".2"):
            self.assertIn(needle, s)

    def test_rerun_stopping_at_an_existing_release_steps(self):
        s = self.section("### 重跑停在「同一個 tag 已有正式版」")
        for needle in ("結束碼 2", "不覆寫", "由人決定", ".2"):
            self.assertIn(needle, s)

    def test_docs_describe_waiting_for_dt_and_the_published_text_has_no_forbidden_words(self):
        self.assertIn("會等 DT 結束", self.doc)
        self.assertIn("!cancelled()", self.doc)
        added = self.section("## 出問題時的處理")
        for bad in ("安全", "不適用", "不受影響", "整體 PASS", "以前", "這一輪", "驗證後", "原本", "我們", "我"):
            self.assertNotIn(bad, added)


if __name__ == "__main__":
    unittest.main()
