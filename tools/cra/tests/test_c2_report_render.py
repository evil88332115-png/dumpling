"""C2 報告（firmware-dt.md、fw-inventory.md 的 vBIOS 段落）與 md_safe／md_esc 的渲染測試：用真正的 markdown 渲染器渲染，不是只比對字串。

渲染器（版本固定在 tests/run.d/c2-requirements.txt）：
  cmark-gfm（cmarkgfm 套件）：GitHub 實際使用的引擎（autolink、table、tagfilter 擴充）；
  markdown-it-py 的 commonmark、gfm-like＋linkify（嚴格：不開 fuzzy；寬鬆：預設，裸網域、email 都會連結，比 GitHub 更嚴）。
檢查：沒有連結（含 email、mailto、xmpp）、圖片、非白名單標籤、斜體、HTML 註解，沒有 @ 提及，表格欄數不變，可見文字還是原文。
缺套件時 skipTest：c2-x86-firmware.sh 設了 DUMPLING_REQUIRE_TEST_DATA=1，skip 會變成失敗（conftest.py），所以 CI 不會悄悄少跑。
"""
import html
import importlib.util
import random
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ms = _load("c2_render_firmware_mdsafe", "pipeline/lib/firmware_mdsafe.py")
dt_tests = _load("c2_render_dt_tests", "tests/test_firmware_dt.py")      # 只借它的輔助函式與 ReportBase（不匯入測試類別，避免重複收集）
fd = dt_tests.fd
ZWSP = ms.ZWSP

ALLOWED_TAGS = {"table", "thead", "tbody", "tr", "th", "td", "p", "ul", "li", "blockquote", "h1", "h2", "h3", "strong", "code", "ol", "hr"}
CONTEXTS = (("cell", "| h1 | h2 |\n|---|---|\n| a | %s |\n"), ("list", "- x %s\n"), ("para", "x %s y\n"), ("quote", "> x %s\n"),
            ("h2", "## x %s\n"), ("cell-first", "| x%s | b |\n|---|---|\n| c | d |\n"), ("nested", "- a\n  - x %s\n"))


def renderers():
    """name → render 函式。缺套件時 skipTest 由呼叫端處理（回 None）。"""
    try:
        import cmarkgfm
        from cmarkgfm.cmark import Options
        import linkify_it  # noqa: F401  markdown-it-py 的 linkify 需要它
        from markdown_it import MarkdownIt
    except ImportError:
        return None

    def gfm(**lk):
        m = MarkdownIt("gfm-like", {"linkify": True, "html": True})
        if lk:
            m.linkify.set(lk)
        return m
    strict = gfm(fuzzy_link=False, fuzzy_email=False, fuzzy_ip=False)
    fuzzy = gfm(fuzzy_link=True, fuzzy_email=True, fuzzy_ip=True)
    common = MarkdownIt("commonmark", {"html": True})
    return {"cmark-gfm": lambda t: cmarkgfm.github_flavored_markdown_to_html(t, Options.CMARK_OPT_UNSAFE),
            "mdit-commonmark": common.render, "mdit-gfm-strict": strict.render, "mdit-gfm-fuzzy": fuzzy.render}


def visible(h):
    return html.unescape(re.sub(r"<[^>]*>", "", h))


def link_problems(h):
    """會被 GitHub 連結的形式：mailto／xmpp，或連結文字以 scheme: 或 www. 開頭。linkify-it 專有的 `//host`、裸網域不算（GitHub 不連結）。"""
    out = []
    for href, text in re.findall(r'<a href="([^"]*)"[^>]*>(.*?)</a>', h, re.S):
        text = visible(text)
        if href.lower().startswith(("mailto:", "xmpp:")) or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", text) or text.lower().startswith("www."):
            out.append((href, text))
    return out


def problems(name, ctx, h):
    out = [("link",) + p for p in link_problems(h)]
    if name in ("cmark-gfm", "mdit-commonmark") and "<a " in h:
        out.append(("any-link",))
    extra = set(re.findall(r"</?([a-zA-Z][a-zA-Z0-9]*)", h)) - ALLOWED_TAGS - {"a"}
    if extra:
        out.append(("tags", sorted(extra)))
    if "<!--" in h:
        out.append(("comment",))
    if ctx in ("cell", "cell-first") and name != "mdit-commonmark" and (h.count("<td") != 2 or h.count("<tr") != 2):
        out.append(("table", h.count("<td"), h.count("<tr")))
    for m in re.finditer(r"(?<![A-Za-z0-9])[@＠](?=[A-Za-z0-9_-])", visible(h)):
        out.append(("mention", visible(h)[max(0, m.start() - 3):m.end() + 5]))
    return out


class RenderCase(unittest.TestCase):
    def setUp(self):
        self.R = renderers()
        if self.R is None:
            self.skipTest("沒有 markdown-it-py、linkify-it-py 或 cmarkgfm（見 tests/run.d/c2-requirements.txt）")

    def check(self, text, want_visible=None, contexts=CONTEXTS, label=""):
        """text（已經過 md_safe）放進各種位置、用每個渲染器渲染：不能有問題；want_visible 去掉零寬空白後要出現在可見文字裡。"""
        for rn, render in self.R.items():
            for ctx, tmpl in contexts:
                h = render(tmpl % text)
                self.assertEqual(problems(rn, ctx, h), [], "%s %s %s %r -> %r" % (label, rn, ctx, text, h))
                if want_visible is not None:
                    self.assertIn(want_visible, visible(h).replace(ZWSP, ""), "%s %s %s" % (label, rn, ctx))


class ControlTests(RenderCase):
    """對照組：沒有處理的原文真的會被這幾個渲染器連結或當成提及，上面的「沒有問題」才不是偵測器壞掉。"""

    def test_unprotected_text_is_detected(self):
        for raw in ("a@b.com", "mailto:a@b.com", "xmpp:a@b.com", "https://evil.example/x", "www.evil.example"):
            hits = [rn for rn, r in self.R.items() if link_problems(r("x %s y\n" % raw))]
            self.assertTrue(hits, raw)
        self.assertIn("cmark-gfm", [rn for rn, r in self.R.items() if link_problems(r("a@b.c\n"))])        # cmark-gfm 連結 a@b.c
        self.assertTrue(problems("cmark-gfm", "para", self.R["cmark-gfm"]("x @user y\n")))                    # 提及
        self.assertTrue(problems("cmark-gfm", "para", self.R["cmark-gfm"]("<img src=x>\n")))                  # 標籤


class MdSafeRenderTests(RenderCase):
    SAMPLES = [
        "a@b.c", "a@b.com", "user.name+tag@example.org", "mailto:a@b.com", "MAILTO:a@b.com", "xmpp:a@b.com", "xmpp:a/b@c.com", "mailto:name@host",
        "x-@y.zz", "a@b@c.d", "x@y.z@Z", "a@b.com_1.", "a@b.com_", "a@.b.c", "@user", "x @org/team (@u2)", "＠user", "a＠b.com", "@@u", "_@u",
        "[click](https://evil.example/x)", "![i](http://e/x.png)", "<img src=x onerror=alert(1)>", "<https://evil.example>", "`code`", "a|b",
        "&commat;everyone", "&#64;x", "&lt;img src=x&gt;", "&amp;commat;x", "1.https://evil.example", "x-ftp://evil.example", "www.evil.example",
        "https://evil.example", "ftp://u:p@evil.example/x", "https://u@evil.example", "mailto:@everyone", "a​@​b.com", "~~x~~", "**b** _i_ $x$",
        "pkg:generic/zlib@1.2.11", "pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9?arch=amd64", "pkg:deb/u/zlib@1.2.11.dfsg", "pkg:npm/%40scope/x@1.2.3",
        "name@host", "foo.bar@1.2.3.4.5", "pkg:rpm/fedora/openssl@3.0.7-1.fc37",
    ]

    def test_samples_in_every_context(self):
        for raw in self.SAMPLES:
            out = ms.md_safe(raw, 200)
            self.check(out, ms.plain(raw), label=repr(raw))

    def test_seeded_random_strings(self):
        tok = ["\\", "[", "]", "(", ")", "<", ">", "!", "*", "_", "#", "~", "|", "`", "&", "$", "@", "＠", ":", "/", ".", "-", "+", " ", "a", "Z", "9", "é",
               "http", "https", "ftp", "www", "mailto:", "xmpp:", "//", "://", "&lt;", "&#64;", "&commat;", "&amp;", "​", "evil", "user", "org/team",
               "[x](y)", "<b>", "<!--", "x@y.z", "a@b.com", "pkg:generic/zlib@1.2.11", "e.xyz", "1.2.3.4", "%2F", "\ud800", "\x00"]
        rnd = random.Random(20261114)
        for _ in range(400):
            raw = "".join(rnd.choice(tok) for _ in range(rnd.randint(1, 12)))
            out = ms.md_safe(raw, 200)
            plain = ms.plain(raw)
            want = plain if len(plain) <= 200 else None
            self.check(out, want, contexts=CONTEXTS[:4] + CONTEXTS[5:6], label=repr(raw))

    def test_purl_without_email_form_is_copied_unchanged(self):
        for purl in ("pkg:generic/zlib@1.2.11", "pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9?arch=amd64", "pkg:npm/%40scope/x@1.2.3",
                     "pkg:rpm/fedora/openssl@3.0.7-1.fc37", "name@host"):
            out = ms.md_safe(purl, 200)
            self.assertEqual(out, purl)                                      # 沒有任何跳脫、沒有零寬空白
            self.check(out, purl, label=purl)
            for rn, render in self.R.items():
                self.assertEqual(visible(render("x %s y\n" % out)).strip(), "x %s y" % purl, rn)         # 渲染後的可見文字就是原文

    def test_email_form_has_zero_width_space_and_text_is_still_readable(self):
        for raw in ("a@b.c", "user@example.org", "pkg:deb/u/zlib@1.2.11.dfsg"):
            out = ms.md_safe(raw, 200)
            self.assertIn(ZWSP, out, raw)
            self.assertEqual(out.replace(ZWSP, ""), raw)


class WholeReportRenderTests(dt_tests.ReportBase, RenderCase):
    """firmware-dt.md 整份用每個渲染器渲染。"""

    def setUp(self):
        dt_tests.ReportBase.setUp(self)
        RenderCase.setUp(self)

    def case_md(self, rows, sbom_doc=None, summ=None, kind="sbom", slug="rend"):
        info, o = self.prep(sbom_doc or dt_tests.bom(dt_tests.clean()), slug=slug, out="p-" + slug, kind=kind)
        dt = self.dt_sample(info, rows, self.SUMM if summ is None else summ, {"matches": [1]}, root="dt-" + slug)
        rc, out, md = self.run_report([o], dt)
        return out, md

    def test_fixed_text_has_no_emphasis_links_or_images(self):
        """報告裡所有固定文字（不經 md_safe 的說明）：不能出現斜體、連結、圖片；粗體只有「怎麼讀」那一行是故意的。"""
        nm = fd._norm_mod()
        self.addCleanup(setattr, nm, "MAX_CHANGES", nm.MAX_CHANGES)
        nm.MAX_CHANGES = 3
        d = dt_tests.bom(dt_tests.clean(), dt_tests.comp("g", "r2", purl="pkg:generic/g@1"), dt_tests.comp("nov", "r3", version=None))
        d["metadata"]["properties"] = [{"name": "dumpling:p%d" % i, "value": "v"} for i in range(6)]
        d["platform"] = "x"
        rows = self.GOOD + [("C-sbomgate", "NOT_ASSESSED", "x"), ("C-grype", "OK", "again"), ("", "OK", "e"), ("​", "OK", "z")]
        out, md = self.case_md(rows, d, slug="allfixed")
        self.assertTrue(out.startswith("FIRMWARE-DT\tATTENTION\t"), out)
        for want in ("status.tsv 有重複列", "看不到內容", "沒有 purl", "供應商 SBOM 自帶名稱以 dumpling: 開頭的 property", "已正規化"):
            self.assertIn(want, md)
        for rn, render in self.R.items():
            h = render(md)
            self.assertEqual(re.findall(r"<(?:em|a|img|script|iframe)[ >]", h), [], rn)
            self.assertEqual(h.count("<strong>"), 1, rn)
            self.assertNotIn("<!--", h, rn)

    def test_supplier_props_text_renders_as_code_not_emphasis(self):
        for n, left, un in ((3, 0, False), (11, 6, False), (4, 4, True)):
            for rn, render in self.R.items():
                h = render("- " + fd.supplier_props_text(n, left, un))
                self.assertNotIn("<em>", h, rn)
                self.assertNotIn("<strong>", h, rn)
                self.assertIn("<code>dumpling:normalized-*</code>", h, rn)

    def test_hostile_text_in_report_has_no_links_or_mentions(self):
        """不可信文字（階段名稱、檢查名稱、vuln-assessment 值）含 email／mailto／提及／連結語法：整份報告渲染後沒有連結、提及、標籤。"""
        evil = ["a@b.com", "mailto:x@y.zz", "xmpp:x@y.zz", "@everyone", "[x](http://e.example)", "&commat;admin", "<img src=x>", "https://e.example", "www.e.example"]
        rows = list(self.GOOD)
        for i, e in enumerate(evil):
            rows += [("X%d %s" % (i, e), "OK", "a"), ("X%d %s" % (i, e), "OK", "b")]            # 重複列：階段名稱會進說明
        comps = [dt_tests.clean()]
        c = dt_tests.comp("h", "rh", purl="pkg:github/a/b@1", va="mailto:a@b.com")
        c["properties"].append({"name": "dumpling:advisory-match", "value": "@everyone"})
        comps.append(c)
        summ = dict(self.SUMM, checks=self.CHECKS + [{"name": "chk a@b.com @everyone", "status": "FAIL", "detail": "[x](http://e)"}])
        out, md = self.case_md(rows, dt_tests.bom(*comps), summ=summ, slug="hostile")
        self.assertIn("X0", md.replace("\\", ""))
        for rn, render in self.R.items():
            h = render(md)
            self.assertEqual(problems(rn, "para", h), [], rn)
            self.assertNotIn("<img", h, rn)

    def test_blank_looking_stage_names_are_noted_and_rendered_safely(self):
        for name in ("​", "﻿", "\x00", "ㅤ", "⠀", "ᅟᅠ", "​⁠­", " 　 "):
            out, md = self.case_md(self.GOOD + [(name, "OK", "x")], slug="blank")
            self.assertTrue(out.startswith("FIRMWARE-DT\tATTENTION\t"), (name, out))
            self.assertIn("看不到內容", md)
            for rn, render in self.R.items():
                self.assertEqual(problems(rn, "para", render(md)), [], (name, rn))


class VbiosReportRenderTests(RenderCase):
    """fw-inventory.md 的 NVIDIA vBIOS 段落（md_esc）。"""

    def test_md_esc_output_has_no_links_or_mentions(self):
        import x86_firmware as xf
        for raw in MdSafeRenderTests.SAMPLES:
            if "~" in raw:
                continue                                                      # md_esc 不跳脫 ~（只會變成刪除線 <del>，不是連結或標籤）；md_safe 才跳脫
            out = xf.md_esc(raw)
            self.check(out, None, label=repr(raw))

    def test_hostile_table_fields_in_vbios_section(self):
        import x86_firmware as xf
        evil = "@everyone a@b.com mailto:x@y.zz [x](http://e) &commat;u <img src=x>"
        inv = {"vbios": [{"device": "10de:2489", "version": "94.04.5E.00.92",
                          "advisory": {"match": "affected", "bulletins": [evil], "cves": [evil], "basis": evil, "notes": [evil]}}],
               "vbios_advisory": {"status": "OK", "vbios": 1, "counts": {"affected": 1}, "stale": False,
                                  "source": {"mirror_commit": "a" * 40, "mirror_fetched_utc": "2026-11-13T16:52:04Z", "reviewed_until": evil, "table_sha256": "b" * 64,
                                             "reviewed_rows": 1, "unreviewed_rows": 0, "not_applicable": [evil], "awaiting_confirmation": [evil]}}}
        md = "\n".join(xf.nvidia_vbios_advisory_markdown(inv))
        for rn, render in self.R.items():
            self.assertEqual(problems(rn, "para", render(md)), [], rn)

    def test_vbios_report_in_each_table_state(self):
        """對照表的四種狀態（未確認、確認且有已審核列、確認但有未審核列、GAP）整份 fw-inventory.md 渲染。"""
        import tempfile
        import test_nvidia_vbios_advisory as tn
        import test_x86_firmware as tx
        import x86_firmware as xf
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rom = tmp / "rom.bin"
            rom.write_bytes(tx.vbios_rom(0x2489, "94.04.5E.00.92"))
            states = {
                "confirmed": tn.table(tmp, tn.row(vbios_affected_below="94.04.6A.00.01", vbios_fixed_in="94.04.6A.00.01")),
                "unreviewed-mix": tn.nva.load(tn.write(tmp, tn.doc(tn.row(vbios_fixed_in="94.04.00.00.01"),
                                                                   tn.row("9002", "CVE-2099-0002", reviewed=False, reviewed_by=None, reviewed_at=None,
                                                                          vbios_fixed_in="94.09.00.00.01")), "mix.json")),
                "not-reviewed": tn.table(tmp, tn.row(vbios_fixed_in="94.04.00.00.01"), reviewed_until=None),
                "gap": tn.nva.TableError("table-invalid", "x@y.zz @everyone"),
            }
            for name, adv in states.items():
                inv = xf.inventory([rom], vbios_advisory=adv, vbios_now=tn.NOW)
                md = xf.markdown(inv)
                self.assertIn("### NVIDIA vBIOS", md, name)
                for rn, render in self.R.items():
                    self.assertEqual(problems(rn, "para", render(md)), [], (name, rn))
                    self.assertNotIn("<img", render(md), (name, rn))


if __name__ == "__main__":
    unittest.main()
