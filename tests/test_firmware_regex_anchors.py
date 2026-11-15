"""C2 的檔案裡，驗證不可信輸入格式用的 `^…$` 正規表示式一律用 fullmatch。

Python 的 `$` 會放行字串結尾的換行（`re.match(r"^[0-9]{4}$", "2204\\n")` 成立），所以 `.match` 配 `^…$` 會收下「2204\\n」這種永遠比不到的值。
這個測試掃描 C2 的原始碼：模組層級 `NAME = re.compile(r"^…$")` 的 NAME 不能用 `.match(` 或 `.search(`；再對各檔實際的驗證函式用結尾換行的輸入核對。
"""
import importlib.util
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["tools/cra/fw_advisory.py", "tools/cra/nvidia_vbios_advisory.py", "tools/cra/intel_ucode_releases.py", "tools/cra/x86_firmware.py",
         "tools/cra/intel_cse_layout.py", "tools/cra/amd_psp.py", "tools/cra/ami_pfat.py", "tools/cra/uefi_gfx.py", "tools/cra/ami_core.py", "tools/cra/intel_vbios.py",
         "pipeline/lib/firmware_dt.py", "pipeline/lib/firmware_fetch.py", "pipeline/lib/firmware_plan.py", "pipeline/lib/firmware_sbom_normalize.py",
         "pipeline/lib/firmware_sbom_check.py", "pipeline/lib/firmware_mdsafe.py", "pipeline/lib/firmware_advisory_cell.py"]
ANCHORED = re.compile(r"^(\w+)\s*=\s*re\.compile\(\s*r?([\"'])\^.*\$\2", re.M)


def load(rel):
    spec = importlib.util.spec_from_file_location("anchors_" + os.path.basename(rel)[:-3], os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.join(ROOT, "tools", "cra"))
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    return mod


class RegexAnchors(unittest.TestCase):
    def test_anchored_patterns_are_never_used_with_match_or_search(self):
        found = 0
        for rel in FILES:
            with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
                src = fh.read()
            for m in ANCHORED.finditer(src):
                found += 1
                name = m.group(1)
                bad = re.findall(r"\b%s\.(?:match|search)\(" % re.escape(name), src)
                self.assertEqual(bad, [], "%s：%s 是 ^…$ 的格式檢查，要用 fullmatch" % (rel, name))
        self.assertGreater(found, 10)               # 掃描本身有抓到東西（不是正規表示式壞了）

    def test_scan_would_catch_a_match_call(self):
        src = 'X_RE = re.compile(r"^[0-9]{4}$")\nok = X_RE.match(s)\n'
        m = ANCHORED.search(src)
        self.assertEqual(m.group(1), "X_RE")
        self.assertTrue(re.search(r"\bX_RE\.(?:match|search)\(", src))

    def test_validators_reject_a_trailing_newline(self):
        fa = load("tools/cra/fw_advisory.py")
        self.assertEqual(fa.fms_of("000306A9"), "06-3a-09")
        self.assertIsNone(fa.fms_of("000306A9\n"))
        self.assertEqual(fa.rev_value("0x1F"), 31)
        self.assertIsNone(fa.rev_value("0x1F\n"))
        self.assertEqual(fa.pf_value("0x94"), "94")
        self.assertIsNone(fa.pf_value("0x94\n"))
        self.assertIsNone(fa.TAG_RE.fullmatch("microcode-20240101\n"))
        self.assertIsNone(fa.SA_RE.fullmatch("INTEL-SA-01234\n"))
        ff = load("pipeline/lib/firmware_fetch.py")
        self.assertIsNone(ff.SHA256_RE.fullmatch("a" * 64 + "\n"))
        self.assertIsNotNone(ff.SHA256_RE.fullmatch("a" * 64))
        fp = load("pipeline/lib/firmware_plan.py")
        self.assertIsNotNone(fp.MEMBER_RE.fullmatch("a/b.bin"))
        self.assertIsNone(fp.MEMBER_RE.fullmatch("a/b.bin\n"))
        fd = load("pipeline/lib/firmware_dt.py")
        self.assertEqual(fd.safe_version("1.0"), "1.0")
        self.assertIsNone(fd.NAME_RE.fullmatch("a\n"))
        self.assertIsNone(fd.VERSION_RE.fullmatch("1.0\n"))


if __name__ == "__main__":
    unittest.main()
