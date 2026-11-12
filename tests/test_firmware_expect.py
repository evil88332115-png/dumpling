"""firmware-expect 與 firmware_plan 的單元測試。用假的 inventory／SBOM，不連網、不含真實映像。"""
import importlib.util
import json
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


fe = load("firmware_expect", "pipeline/firmware-expect.py")
fp = load("firmware_plan", "pipeline/lib/firmware_plan.py")

INV = {"bios": [{
    "me": {"version": "14.0.47.1558"},
    "microcode": [{"cpuid": "000806EC", "platform_id": "0x94", "revision": "0xF8"},
                  {"cpuid": "000A0660", "platform_id": "0x80", "revision": "0xF8"}],
    "cbfs": {"coreboot": [{"version": "board_v0.9.2", "git_revision": "add9d7206e30", "dasharo_version": "v1.2.0",
                           "build_time": "2024-03-13T15:18:26Z",
                           "config": {"keys": {"CONFIG_EDK2_TAG_OR_REV": "2a15268b36cc732aa9d0a34a33965de6b0fca122"}}}],
             "fsp": [{"revision": "9.0.123.32"}, {"revision": "9.2.123.32"}]}}]}


def comp(name, version, **props):
    return {"name": name, "version": version, "properties": [{"name": k.replace("_", "-"), "value": v} for k, v in props.items()]}


SBOM = {"components": [
    comp("Intel CSE firmware", "14.0.47.1558"),
    {"name": "Intel CPU microcode 000806EC", "version": "0xF8",
     "properties": [{"name": "sca-center:cpuid", "value": "000806EC"}, {"name": "sca-center:platform-id", "value": "0x94"}]},
    comp("Intel FSP-M ($CMLFSP$)", "9.0.123.32"), comp("Intel FSP-S ($CMLFSP$)", "9.2.123.32")]}


def statuses(exp, inv=INV, sbom=SBOM):
    return [s for s, _ in fe.compare(exp, inv, sbom)]


class CompareTest(unittest.TestCase):
    def test_all_ok(self):
        exp = {"intel_me": "14.0.47.1558",
               "microcode": [{"cpuid": "000806ec", "platform_mask": "0x94", "revision": "0xf8"}],
               "fsp": ["9.0.123.32", "9.2.123.32"], "coreboot_version": "board_v0.9.2", "coreboot_revision": "add9d7206e30",
               "dasharo_version": "v1.2.0", "coreboot_build_date": "2024-03-13", "edk2_revision": "2a15268b36cc"}
        self.assertEqual(statuses(exp), ["OK"] * 9)

    def test_gfx_keys(self):
        sb = {"components": SBOM["components"] + [comp("Intel GOP driver", "1070"), comp("Intel GOP driver", "1071"),
                                                   comp("Intel legacy VBIOS (option ROM)", "1003 PC 14.34"),
                                                   comp("Intel VBT (Video BIOS Table)", "1.00")]}
        ok = {"intel_gop": "1070", "intel_legacy_vbios": "1003 PC 14.34"}
        self.assertEqual(statuses(ok, INV, sb), ["OK", "OK"])
        self.assertEqual(statuses({"intel_gop": "1072", "intel_legacy_vbios": "1003 PC 14.35"}, INV, sb), ["MISMATCH", "MISMATCH"])
        self.assertEqual(statuses(ok), ["MISSING", "MISSING"])           # SBOM 沒有元件
        nov = {"components": [{"name": "Intel GOP driver"}]}              # 有元件但沒讀到版本
        self.assertEqual(statuses({"intel_gop": "1070"}, INV, nov), ["MISSING"])
        self.assertEqual(statuses(ok, None, None), ["NOT_RUN", "NOT_RUN"])
        with self.assertRaises(fe.FormatError):
            fe.compare({"intel_vbt": "1.00"}, INV, sb)

    def test_mismatch(self):
        r = dict(fe.compare({"intel_me": "14.0.47.1559"}, INV, SBOM))
        self.assertEqual(list(r), ["MISMATCH"])
        self.assertIn("預期 14.0.47.1559", r["MISMATCH"])
        self.assertIn("實際 14.0.47.1558", r["MISMATCH"])
        self.assertEqual(statuses({"microcode": [{"cpuid": "000806EC", "platform_mask": "0x94", "revision": "0xF9"}]}), ["MISMATCH"])
        self.assertEqual(statuses({"coreboot_revision": "bbbbbbbbbbbb"}), ["MISMATCH"])
        self.assertEqual(statuses({"edk2_revision": "ffffffffffff"}), ["MISMATCH"])
        self.assertEqual(statuses({"coreboot_build_date": "2024-03-14"}), ["MISMATCH"])
        self.assertEqual(statuses({"fsp": ["9.1.123.32"]}), ["MISMATCH"])

    def test_short_prefix_is_not_enough(self):
        self.assertEqual(statuses({"coreboot_revision": "add9"}), ["MISMATCH"])

    def test_missing(self):
        inv = {"bios": [{"me": None, "microcode": [], "cbfs": None}]}
        s = statuses({"intel_me": "1.2.3.4", "microcode": [{"cpuid": "000806EC", "platform_mask": "0x94", "revision": "0xF8"}],
                      "fsp": ["9.0.123.32"], "coreboot_version": "x", "edk2_revision": "abcdef1234"}, inv, None)
        self.assertEqual(s, ["MISSING"] * 5)
        # 有微碼但 cpuid／platform 對不上也是 MISSING，不是 MISMATCH
        self.assertEqual(statuses({"microcode": [{"cpuid": "000806EC", "platform_mask": "0x80", "revision": "0xF8"}]}), ["MISSING"])

    def test_sbom_must_agree(self):
        sb = {"components": []}
        self.assertEqual(statuses({"intel_me": "14.0.47.1558"}, INV, sb), ["MISMATCH"])
        self.assertEqual(statuses({"fsp": ["9.0.123.32"]}, INV, sb), ["MISMATCH"])
        self.assertEqual(statuses({"microcode": [{"cpuid": "000A0660", "platform_mask": "0x80", "revision": "0xF8"}]}, INV, SBOM), ["MISMATCH"])

    def test_not_run(self):
        self.assertEqual(statuses({"intel_me": "1", "fsp": ["2"]}, None, None), ["NOT_RUN", "NOT_RUN"])

    def test_format_errors(self):
        for bad in ("字串", ["a"], {"intel_mee": "1"}, {"intel_me": ""}, {"intel_me": ["1"]}, {"microcode": []},
                    {"microcode": [{"cpuid": "000806EC"}]},
                    {"microcode": [{"cpuid": "ZZ", "platform_mask": "0x94", "revision": "0xF8"}]},
                    {"fsp": "9.0"}, {"coreboot_build_date": "20240313"}, {"intel_me": True}):
            with self.assertRaises(fe.FormatError, msg=repr(bad)):
                fe.compare(bad, INV, SBOM)
        # 格式錯誤在沒有輸出檔時也要報（不能被 NOT_RUN 蓋掉）
        with self.assertRaises(fe.FormatError):
            fe.compare({"intel_mee": "1"}, None, None)

    def test_bad_inventory(self):
        with self.assertRaises(fe.FormatError):
            fe.compare({"intel_me": "1"}, {"nope": 1}, SBOM)


class RunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.slug = os.path.join(self.tmp.name, "m", "sample-1")
        os.makedirs(self.slug)
        self.out = os.path.join(self.tmp.name, "out")
        os.makedirs(self.out)
        self.lines = []

    def manifest(self, text):
        p = os.path.join(self.slug, "firmware.yml")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def outputs(self, inv=INV, sbom=SBOM):
        for n, d in (("fw-inventory.json", inv), ("fw.cdx.json", sbom)):
            with open(os.path.join(self.out, n), "w", encoding="utf-8") as fh:
                fh.write(d if isinstance(d, str) else json.dumps(d))

    def go(self, text, strict=False):
        self.lines = []
        return fe.run(self.manifest(text), self.out, strict, self.lines.append)

    def test_ok_exit0_and_last_line_not_pass(self):
        self.outputs()
        rc = self.go("expected:\n  intel_me: 14.0.47.1558\n")
        self.assertEqual(rc, 0)
        self.assertEqual(self.lines[0].split("\t")[:3], ["FIRMWARE-EXPECT", "OK", "sample-1"])
        last = self.lines[-1]
        self.assertIn("比對 1 項、0 項不符", last)
        self.assertNotIn("PASS", "\n".join(self.lines))

    def test_mismatch_exit1(self):
        self.outputs()
        rc = self.go("expected:\n  intel_me: 14.0.47.1559\n  fsp: ['9.0.123.32']\n")
        self.assertEqual(rc, 1)
        self.assertIn("比對 2 項、1 項不符", self.lines[-1])

    def test_missing_exit1(self):
        self.outputs({"bios": [{}]}, {"components": []})
        self.assertEqual(self.go("expected:\n  intel_me: 14.0.47.1558\n"), 1)
        self.assertEqual(self.lines[0].split("\t")[1], "MISSING")

    def test_not_run(self):
        self.assertEqual(self.go("expected:\n  intel_me: 14.0.47.1558\n"), 0)
        self.assertEqual(self.lines[0].split("\t")[1], "NOT_RUN")
        self.assertEqual(self.go("expected:\n  intel_me: 14.0.47.1558\n", strict=True), 1)

    def test_empty_expected(self):
        for text in ("kind: bios\n", "expected: {}\n", "expected:\n"):
            self.assertEqual(self.go(text), 0)
            self.assertEqual(len(self.lines), 1)
            self.assertIn("比對 0 項", self.lines[0])

    def test_format_errors_exit64(self):
        self.outputs()
        self.assertEqual(self.go("expected:\n  intel_mee: 1\n"), 64)
        self.assertEqual(self.go("- 清單不是 mapping\n"), 64)
        self.assertEqual(self.go(": : :\n  - [\n"), 64)
        self.outputs("not json", SBOM)
        self.assertEqual(self.go("expected:\n  intel_me: 14.0.47.1558\n"), 64)
        self.outputs(INV, SBOM)
        os.unlink(os.path.join(self.out, "fw.cdx.json"))
        self.assertEqual(self.go("expected:\n  intel_me: 14.0.47.1558\n"), 64)
        self.assertEqual(fe.run(os.path.join(self.tmp.name, "沒有.yml"), self.out, False, self.lines.append), 64)

    def test_real_manifests_parse(self):
        # repo 裡每個 firmware.yml 的 expected 格式都要合法（用空輸出時只會是 NOT_RUN）
        import glob
        for p in glob.glob(os.path.join(ROOT, "firmware", "*", "*", "firmware.yml")):
            self.lines = []
            self.assertEqual(fe.run(p, self.tmp.name, False, self.lines.append), 0, p)


class PlanTest(unittest.TestCase):
    def doc(self, **kw):
        d = {"kind": "bios", "status": "ok", "_slug": "s1",
             "files": [{"name": "a.deb", "role": "package"}, {"name": "b.rom", "role": "image"}, {"name": "c.tgz", "role": "source"}]}
        d.update(kw)
        return d

    def test_plain(self):
        self.assertEqual(fp.plan(self.doc(), "/dl", "/w"), ["/dl/bios/s1/a.deb", "/dl/bios/s1/b.rom"])

    def test_extract(self):
        calls = []
        ex = lambda src, m, d: calls.append((src, m, d)) or d + "/" + m
        r = fp.plan(self.doc(analyze=[{"from": "a.deb", "member": "usr/x.fd"}]), "/dl", "/w", ex)
        self.assertEqual(r, ["/w/s1/a.deb.d/usr/x.fd", "/dl/bios/s1/b.rom"])
        self.assertEqual(calls[0][:2], ("/dl/bios/s1/a.deb", "usr/x.fd"))

    def test_skip_and_errors(self):
        self.assertEqual(fp.plan(self.doc(status="GAP"), "/dl", "/w"), [])
        self.assertEqual(fp.plan(self.doc(kind="vbios"), "/dl", "/w"), [])
        for bad in ([{"from": "nope.deb", "member": "x"}], [{"from": "b.rom", "member": "x"}], [{"from": "a.deb"}], "x"):
            with self.assertRaises(ValueError):
                fp.plan(self.doc(analyze=bad), "/dl", "/w")

    def test_member_validation(self):
        with tempfile.TemporaryDirectory() as t:
            for m in ("../x", "/etc/passwd", "a/../b", "a b", ""):
                with self.assertRaises(ValueError):
                    fp.extract_member("/nonexistent.deb", m, t)


if __name__ == "__main__":
    unittest.main()
