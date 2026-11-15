"""firmware.yml 的選用欄位 watch（pipeline/lib/firmware_watch.py）：格式檢查，以及讀 firmware.yml 的程式都接受並驗證它。"""
import importlib.util
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    return mod


fw = load("pipeline/lib/firmware_watch.py", "t_firmware_watch")
fplan = load("pipeline/lib/firmware_plan.py", "t_firmware_plan")
ffetch = load("pipeline/lib/firmware_fetch.py", "t_firmware_fetch")
fdt = load("pipeline/lib/firmware_dt.py", "t_firmware_dt")

GOOD_FALSE = {"monitored": False, "why": "沒有 vBIOS 元件"}


def sample(**over):
    d = {"kind": "bios", "vendor": "V", "model": "M", "status": "ok", "notes": "n", "firmware_version": "1", "ibv": "AMI",
         "license": {"name": "n", "url": "https://example.org/", "note": "n"},
         "files": [{"name": "a.bin", "url": "https://example.org/a.bin", "sha256": "0" * 64, "size": 1, "role": "image"}]}
    d.update(over)
    return d


class ParseWatch(unittest.TestCase):
    def test_absent_means_not_declared(self):
        self.assertEqual(fw.parse_watch({"kind": "bios"}), (None, None))

    def test_declared_false_with_why(self):
        self.assertEqual(fw.parse_watch({"watch": GOOD_FALSE}), (False, "沒有 vBIOS 元件"))

    def test_why_is_trimmed(self):
        self.assertEqual(fw.parse_watch({"watch": {"monitored": False, "why": "  原因  "}}), (False, "原因"))

    def test_true_without_why_is_fine(self):
        self.assertEqual(fw.parse_watch({"watch": {"monitored": True}}), (True, None))

    def test_false_requires_a_nonempty_why(self):
        for w in ({"monitored": False}, {"monitored": False, "why": ""}, {"monitored": False, "why": "   "},
                  {"monitored": False, "why": None}, {"monitored": True, "why": ""}):
            with self.assertRaises(ValueError, msg=repr(w)):
                fw.parse_watch({"watch": w})

    def test_bad_shapes(self):
        for w in (None, "false", [], {"why": "x"}, {"monitored": "false", "why": "x"}, {"monitored": 0, "why": "x"},
                  {"monitored": False, "why": 5}, {"monitored": False, "why": "a\nb"}, {"monitored": False, "why": "a\x00b"},
                  {"monitored": False, "why": "x", "extra": 1}, {"monitored": False, "why": "x" * 301}):
            with self.assertRaises(ValueError, msg=repr(w)):
                fw.parse_watch({"watch": w})


class Readers(unittest.TestCase):
    def test_plan_accepts_and_rejects(self):
        fplan.plan(sample(watch=GOOD_FALSE, kind="vbios"), "/dl", "/work")      # kind 不是 bios：回空清單，不丟例外
        with self.assertRaises(ValueError):
            fplan.plan(sample(watch={"monitored": False, "why": ""}), "/dl", "/work")
        self.assertEqual(fplan.plan(sample(watch={"monitored": True}, _slug="s"), "/dl", "/work")[0].endswith("a.bin"), True)

    def test_fetch_validate(self):
        self.assertEqual(ffetch.validate(sample(watch=GOOD_FALSE)), [])
        self.assertEqual(ffetch.validate(sample()), [])
        errs = ffetch.validate(sample(watch={"monitored": False, "why": " "}))
        self.assertTrue(errs and "watch" in errs[0])
        # status: GAP 的樣本也要檢查（validate 在 status 不是 ok 時提早結束，watch 的檢查要在那之前）
        errs = ffetch.validate({"kind": "vbios", "vendor": "V", "model": "M", "status": "GAP", "notes": "n", "watch": {"monitored": False}})
        self.assertTrue(any("watch" in e for e in errs))

    def test_dt_load_sample(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "firmware.yml")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("kind: vbios\nwatch:\n  monitored: false\n  why: ''\n")
            with self.assertRaises(fdt.DtError):
                fdt.load_sample(p)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("kind: vbios\nwatch:\n  monitored: false\n  why: 原因\n")
            self.assertEqual(fdt.load_sample(p)["watch"]["why"], "原因")

    def test_repo_manifests_declare_the_unmonitored_vbios_samples(self):
        import glob
        import yaml
        got = {}
        for p in sorted(glob.glob(os.path.join(ROOT, "firmware", "*", "*", "firmware.yml"))):
            with open(p, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            self.assertEqual(ffetch.validate(doc), [], p)
            mon, why = fw.parse_watch(doc)
            got[os.path.basename(os.path.dirname(p))] = (doc["kind"], mon)
        self.assertEqual(got["nvidia-displayport-fw-updater-1.1"], ("vbios", False))
        self.assertEqual(got["standalone-nvidia-option-rom"], ("vbios", False))
        # 其他樣本沒有宣告不監控
        self.assertEqual({k for k, v in got.items() if v[1] is False}, {"nvidia-displayport-fw-updater-1.1", "standalone-nvidia-option-rom"})


if __name__ == "__main__":
    unittest.main()
