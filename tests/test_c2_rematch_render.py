"""每天重跑公告比對產生的 fw-inventory-<slug>.md：inventory 是不可信資料，每個進報告的欄位都要經過 md_esc（x86_firmware.markdown），
用 test_c2_report_render.py 的渲染器（cmark-gfm、markdown-it 的 commonmark／gfm）檢查：
- 合成的豐富 inventory（Intel 微碼與 ME、AMD PSP／微碼／AGESA、coreboot CBFS 的 FSP／VBT／payload／config、AMI PFAT 封裝、NVIDIA vBIOS）的每一個純量欄位，
  依序換成一段會被 markdown 解讀的字串（連結、圖片、@ 提及、HTML、標題、表格列、換行），重跑後的報告：沒有多出連結、圖片、script、@ 提及，
  標題、表格列、清單、引用的數量和沒有注入時相同。
- 重跑的狀態橫幅（reasons、changed 的 key／bulletins、Release tag）同樣要跳脫。
- inventory_problems 的格式檢查（FIELD_RULES）是第二道防線：同樣的欄位換成這段字串，那一份 GAP。
缺套件時 DUMPLING_REQUIRE_TEST_DATA=1（c2-x86-firmware.sh）直接失敗，不是 skip。
放在 tests/（不是 tools/）：C1 的 c1-tools.sh 跑 `pytest tools`，那個環境沒有渲染器套件。"""
import collections
import copy
import datetime
import json
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CRA = HERE.parent / "tools" / "cra"
sys.path.insert(0, str(CRA))
sys.path.insert(0, str(CRA / "tests"))
sys.path.insert(0, str(HERE))
import fw_rematch as fm  # noqa: E402
import test_c2_report_render as rr  # noqa: E402
import x86_firmware as xf  # noqa: E402
from test_amd_psp import good_image, put  # noqa: E402
from test_ami_pfat import pfat_from_spi  # noqa: E402
from test_coreboot_cbfs import flash, standard_files  # noqa: E402
from test_x86_firmware import vbios_rom  # noqa: E402

EV = ("@evilmention x@e.example https://e.example/p www.e.example [l](http://e.example) ![i](http://e.example/i.png) "
      "<script>alert(1)</script> <b>x</b> &amp;\n# H1\n| a | b |\n---\n> q\n- li\n`code` ~~s~~ **b** _i_ ‮")
NOW = datetime.datetime(2026, 11, 21, 2, tzinfo=datetime.timezone.utc)
STRUCTURE = ("h1", "h2", "h3", "h4", "h5", "h6", "table", "tr", "td", "th", "ul", "ol", "li", "blockquote", "hr", "pre", "img", "script", "p", "a")
MENTION = re.compile(r"(?<![A-Za-z0-9])[@＠][A-Za-z0-9_-]")


def rich_inventory(d):
    d = Path(d)
    amd = good_image()
    put(amd, 0x80000, b"AGESA!V9\x00ComboAM4v2PI 1.2.0.B\x00")
    (d / "amd.bin").write_bytes(bytes(amd))
    (d / "cb.rom").write_bytes(bytes(flash(standard_files(), standard_files())))
    (d / "pf.cap").write_bytes(pfat_from_spi()[1])
    (d / "gpu.rom").write_bytes(vbios_rom(0x2489, "94.04.5E.00.92"))
    inv = xf.inventory(sorted(d.iterdir()))
    return json.loads(json.dumps(inv))


def walk(x, path=()):
    yield path, x
    if isinstance(x, dict):
        for k, v in x.items():
            yield from walk(v, path + (k,))
    elif isinstance(x, list):
        for i, v in enumerate(x):
            yield from walk(v, path + (i,))


def norm(path):
    return "/".join("*" if isinstance(x, int) else str(x) for x in path)


def rr_get(x, path):
    for k in path:
        x = x[k]
    return x


def set_path(x, path, v):
    for k in path[:-1]:
        x = x[k]
    x[path[-1]] = v


SKIP_TOP = {"advisory", "vbios_advisory", "rules_advisory", "status", "detail", "limits", "schema"}   # 重跑會重寫（今天的表產生）或固定值


def scalar_paths(inv):
    seen, out = collections.Counter(), []
    for p, v in walk(inv):
        if not p or isinstance(v, (dict, list)) or p[0] in SKIP_TOP or "rule_advisory" in p or "advisory" in p:
            continue
        n = norm(p)
        seen[n] += 1
        if seen[n] == 1:
            out.append((p, n))
    return out


def shape(h):
    c = collections.Counter(re.findall(r"<(%s)[\s>]" % "|".join(STRUCTURE), h))
    return c, len(MENTION.findall(rr.visible(h)))


class RematchRender(rr.RenderCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.inv = rich_inventory(cls.tmp.name)
        cls.tabs = fm.load_tables(xf)
        cls.info = fm.table_info(xf, cls.tabs, NOW)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def md_of(self, inv):
        r = fm.rematch_inventory(xf, inv, NOW, self.tabs, self.info)
        return fm.md_banner(xf, "slug-a", "firmware-demo/2026.11.20", "2026-11-21T02:00:00Z", r["status"], r["reasons"], self.info, r["changed"]) + r["md"]

    def test_rich_inventory_covers_the_field_rules(self):
        covered = {n for _p, n in scalar_paths(self.inv)}
        missing = [k for k in fm.FIELD_RULES if k not in covered and "uefi_gfx" not in k]
        self.assertEqual(missing, [])
        self.assertGreaterEqual(len(covered), 150)
        self.assertEqual(fm.inventory_problems(copy.deepcopy(self.inv)), [])

    def test_every_scalar_field_is_escaped_in_the_report(self):
        """對照組：同一個欄位換成一個普通的字串（NEUTRAL）。注入的字串不能讓報告多出連結、圖片、script、@ 提及，
        也不能讓標題、表格列、清單、引用的數量和對照組不同（欄位換成別的值本身可能讓某一段消失，所以比對照組，不比沒有改過的報告）。"""
        bad, ran = [], 0
        for p, n in scalar_paths(self.inv):
            inj, ctl = copy.deepcopy(self.inv), copy.deepcopy(self.inv)
            set_path(inj, p, EV)
            orig = rr_get(self.inv, p)
            set_path(ctl, p, orig if isinstance(orig, int) and not isinstance(orig, bool) else "NEUTRAL")      # 旗標（bool、None）換成字串會變成「有值」：對照組也一樣
            try:
                md, md0 = self.md_of(inj), self.md_of(ctl)
            except (ValueError, TypeError, KeyError, AttributeError):        # 型別不對的欄位（例如 0x{x:x} 的整數）：重跑本身就會 GAP，不會產生報告
                continue
            ran += 1
            self.assertNotIn("\n# H1\n", md, n)
            self.assertNotIn("\n| a | b |\n", md, n)
            for rn, render in self.R.items():
                h, h0 = render(md), render(md0)
                if shape(h) != shape(h0) or [x for x in rr.problems(rn, "para", h) if x not in rr.problems(rn, "para", h0)]:
                    bad.append((n, rn))
        self.assertGreaterEqual(ran, 150)
        self.assertEqual(bad, [])

    def test_field_rules_make_the_sample_gap(self):
        checked = 0
        for p, n in scalar_paths(self.inv):
            if n not in fm.FIELD_RULES:
                continue
            inv = copy.deepcopy(self.inv)
            set_path(inv, p, EV)
            probs = fm.inventory_problems(inv)
            self.assertTrue(probs, n)
            self.assertNotIn("evilmention", " ".join(probs))
            checked += 1
        self.assertGreaterEqual(checked, 50)

    def test_banner_strings_are_escaped(self):
        reasons = [f"inventory: {EV}", "x"]
        changed = [{"key": f"rule:x:{EV}", "kind": "rule", "before": {"result": EV, "bulletins": [EV], "reason": None, "review": None},
                    "after": {"result": "affected", "bulletins": [EV, "INTEL-SA-00001"], "reason": None, "review": None}}]
        md = fm.md_banner(xf, EV, EV, EV, "ATTENTION", reasons, self.info, changed)
        clean = fm.md_banner(xf, "slug-a", "firmware-demo/2026.11.20", "2026-11-21T02:00:00Z", "ATTENTION", ["x"], self.info,
                             [{**changed[0], "key": "k", "before": {**changed[0]["before"], "result": "r", "bulletins": ["b"]},
                               "after": {**changed[0]["after"], "bulletins": ["INTEL-SA-00001"]}}])
        self.assertNotIn("\n# H1\n", md)
        for rn, render in self.R.items():
            h = render(md)
            self.assertEqual([x for x in rr.problems(rn, "para", h) if x not in rr.problems(rn, "para", render(clean))], [], rn)
            self.assertEqual(len(MENTION.findall(rr.visible(h))), 0, rn)
            self.assertEqual(h.count("<h1>"), 1, rn)
            self.assertNotIn("<script", h, rn)
            self.assertNotIn("<img", h, rn)
