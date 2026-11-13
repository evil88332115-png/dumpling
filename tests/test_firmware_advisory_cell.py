"""firmware_advisory_cell.py（firmware-ci.sh 摘要表的「微碼公告比對」欄）的單元測試。不連網。"""
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("firmware_advisory_cell", os.path.join(ROOT, "pipeline", "lib", "firmware_advisory_cell.py"))
fc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fc)


def uc(match):
    return {"cpuid": "000806EC", "platform_id": "0x94", "revision": "0xF8", "advisory": {"match": match}}


def intel(name="a.rom", *matches):
    return {"file": name, "platform": None, "microcode": [uc(m) for m in matches], "amd": None}


def amd(name="b.zip!b.CAP", microcode=19, parsed=True):
    return {"file": name, "platform": "amd", "microcode": [], "amd": {"microcode": [{}] * microcode, "psp_firmware": [{}] * 3, "agesa": {"values": [{}]}} if parsed else None}


def inv(*bios, status="OK"):
    return {"advisory": {"status": status, "counts": {}}, "bios": list(bios)}


class CellTests(unittest.TestCase):
    def test_intel_only(self):
        self.assertEqual(fc.cell(inv(intel("a.rom", "affected-candidate", "affected-candidate", "up-to-date"))), "affected-candidate 2、up-to-date 1")
        self.assertEqual(fc.cell(inv(intel("a.rom", "NOT_ASSESSED", "older-no-sa"))), "older-no-sa 1、NOT_ASSESSED 1")      # 固定順序
        self.assertEqual(fc.cell(inv(intel("a.rom"))), "沒有 Intel 微碼（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）")

    def test_amd_only(self):
        t = fc.cell(inv(amd(microcode=19)))
        self.assertIn("AMD 微碼已解析 19 份", t)
        self.assertIn("沒有做公告比對", t)
        self.assertIn("以 AMD 公告為準", t)
        self.assertNotIn("沒有解析", t)
        self.assertIn("已解析 0 份", fc.cell(inv(amd(microcode=0))))                       # 解析了但沒有微碼：照實寫 0 份

    def test_amd_parser_did_not_run_is_a_gap_not_zero(self):
        t = fc.cell(inv(amd(parsed=False)))
        self.assertIn("AMD PSP 目錄解析沒有執行（GAP）", t)
        self.assertIn("微碼、PSP、AGESA 都沒有列出", t)
        self.assertIn("以 AMD 公告為準", t)
        self.assertNotIn("已解析 0 份", t)
        b = amd(parsed=False)
        del b["amd"]                                                                       # 欄位不存在也一樣
        self.assertIn("解析沒有執行（GAP）", fc.cell(inv(b)))

    def test_table_gap(self):
        t = fc.cell(inv(intel("a.rom", "NOT_ASSESSED", "NOT_ASSESSED"), status="GAP"))
        self.assertEqual(t, "資料表 GAP：NOT_ASSESSED 2")
        self.assertTrue(fc.cell(inv(amd(), status="GAP")).startswith("資料表 GAP：沒有 Intel 微碼；AMD 微碼已解析"))
        self.assertEqual(fc.cell(inv(status="GAP")), "資料表 GAP：沒有 BIOS 映像（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）")

    def test_mixed_images_each_one_is_listed(self):
        t = fc.cell(inv(intel("dir/protectli.rom", "affected-candidate", "affected-candidate", "affected-candidate"), amd("x.zip!PRIME.CAP", 19)))
        self.assertIn("protectli.rom：Intel 微碼 affected-candidate 3", t)
        self.assertIn("PRIME.CAP：沒有 Intel 微碼；AMD 微碼已解析 19 份", t)
        t = fc.cell(inv(amd(parsed=False), intel("a.rom", "up-to-date")))
        self.assertIn("b.CAP：沒有 Intel 微碼；AMD PSP 目錄解析沒有執行（GAP）", t)
        self.assertIn("a.rom：Intel 微碼 up-to-date 1", t)

    def test_no_bios_and_many_images(self):
        self.assertEqual(fc.cell(inv()), "沒有 BIOS 映像（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）")
        t = fc.cell(inv(*[intel(f"{i}.rom", "up-to-date") for i in range(fc.MAX_IMAGES + 3)]))
        self.assertIn("其餘 3 個映像沒有列出", t)

    def test_nvidia_vbios_is_added_only_when_there_are_vbios(self):
        def vb(*matches, status="OK"):
            return {"vbios": [{"device": "2489", "advisory": {"match": m}} for m in matches], "vbios_advisory": {"status": status}}
        base = inv(intel("a.rom", "up-to-date"))
        self.assertEqual(fc.cell({**base, **vb()}), fc.cell(base))                          # 沒有 vBIOS：BIOS 樣本的欄位維持原樣
        self.assertEqual(fc.cell({**base, "vbios": []}), "up-to-date 1")
        t = fc.cell({**base, **vb("NOT_ASSESSED", "NOT_ASSESSED", "affected")})
        self.assertTrue(t.startswith("up-to-date 1；NVIDIA vBIOS 3 個：affected 1、NOT_ASSESSED 2"), t)
        self.assertIn("資料庫沒有資料，以廠商公告為準", t)
        self.assertIn("不代表沒有其他漏洞", t)
        t = fc.cell({**inv(), **vb("NOT_ASSESSED")})                                        # 只有 vBIOS（沒有 BIOS 映像）的樣本
        self.assertEqual(t.split("；NVIDIA")[0], "沒有 BIOS 映像（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）")
        self.assertIn("NVIDIA vBIOS 1 個：NOT_ASSESSED 1", t)
        t = fc.cell({**inv(), **vb("NOT_ASSESSED", status="GAP")})
        self.assertIn("對照表 GAP，NOT_ASSESSED 1", t)
        self.assertIn("fixed 1", fc.cell({**inv(), **vb("fixed")}))
        for w in ("PASS", "不受影響", "安全"):
            self.assertNotIn(w, fc.cell({**inv(), **vb("NOT_ASSESSED", "fixed", "affected")}))
        self.assertIn("NOT_ASSESSED 1", fc.cell({"bios": [], "vbios": [{"device": "x"}]}))   # 沒有 advisory 欄位的 vBIOS 當成 NOT_ASSESSED

    def test_cli_and_bad_input(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "i.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(inv(amd(), intel("a.rom", "up-to-date")), fh)
            r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pipeline", "lib", "firmware_advisory_cell.py"), p], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertIn("AMD 微碼已解析 19 份", r.stdout)
            for content in ("{not json", "[]", '{"bios": 3}'):
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(content)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = fc.main([p])
                self.assertEqual((rc, buf.getvalue().strip()), (1, "-"), content)
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(fc.main([os.path.join(td, "missing.json")]), 1)
                self.assertEqual(fc.main([]), 64)


if __name__ == "__main__":
    unittest.main()
