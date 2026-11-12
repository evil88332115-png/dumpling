"""firmware-sbom-check 的單元測試。不連網；sbomqs 用假執行檔（環境變數 SBOMQS）取代。"""
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "firmware_sbom_check", os.path.join(ROOT, "pipeline", "lib", "firmware_sbom_check.py"))
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)

FAKE_OUT = {
    "creation_info": {"version": "v9.9.9"},
    "files": [{"sbom_quality_score": 7.25, "grade": "C",
               "comprehenssive": [{"category": "Identification", "score": 8.5},
                                  {"category": "Integrity", "score": 0.0}]}],
}


def comp(name="a", version="1.0", purl="pkg:generic/a@1.0", cpe="cpe:2.3:o:a:a:1.0:*:*:*:*:*:*:*"):
    c = {"type": "firmware", "name": name}
    if version is not None:
        c["version"] = version
    if purl is not None:
        c["purl"] = purl
    if cpe is not None:
        c["cpe"] = cpe
    return c


def cdx(*comps, spec="1.4"):
    return {"bomFormat": "CycloneDX", "specVersion": spec, "components": list(comps)}


def spdx_pkg(name, version=None, purl=None, cpe=None):
    p = {"name": name}
    if version:
        p["versionInfo"] = version
    refs = []
    if purl:
        refs.append({"referenceType": "purl", "referenceLocator": purl})
    if cpe:
        refs.append({"referenceType": "cpe23Type", "referenceLocator": cpe})
    if refs:
        p["externalRefs"] = refs
    return p


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = os.path.join(self.tmp.name, "out")
        self.old = os.environ.get("SBOMQS")
        self.addCleanup(self.restore)
        os.environ["SBOMQS"] = self.fake_sbomqs()

    def restore(self):
        if self.old is None:
            os.environ.pop("SBOMQS", None)
        else:
            os.environ["SBOMQS"] = self.old

    def fake_sbomqs(self, body=None, code=0):
        p = os.path.join(self.tmp.name, "fake-sbomqs%d" % len(os.listdir(self.tmp.name)))
        body = json.dumps(FAKE_OUT) if body is None else body
        with open(p, "w") as fh:
            fh.write("#!/bin/sh\ncat <<'EOF_JSON'\n%s\nEOF_JSON\nexit %d\n" % (body, code))
        os.chmod(p, 0o755)
        return p

    def put(self, name, obj=None, raw=None):
        p = os.path.join(self.tmp.name, name)
        with open(p, "wb") as fh:
            fh.write(raw if raw is not None else json.dumps(obj).encode())
        return p

    def check(self, *paths):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = sc.main(list(paths) + ["--out", self.out])
        lines = [l.split("\t") for l in buf.getvalue().splitlines()]
        return rc, lines

    def status(self, obj=None, raw=None):
        rc, lines = self.check(self.put("x.json", obj, raw))
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0][0], "FIRMWARE-SBOM")
        self.assertEqual(len(lines[0]), 4)
        return lines[0][1], lines[0][3], rc


class StatusTest(Base):
    def test_ok(self):
        st, msg, rc = self.status(cdx(comp("a"), comp("b")))
        self.assertEqual((st, rc), ("OK", 0))
        self.assertIn("2 個元件", msg)

    def test_dt_schema_hints(self):
        ok = sc.judge(sc.basic_check(cdx(comp("a"))))
        self.assertEqual(ok[0], "OK")
        self.assertNotIn("DT 可能拒收", ok[1])
        # license 只有 url（沒有 id 也沒有 name）、頂層有未知欄位
        bad = cdx(dict(comp("lic"), licenses=[{"license": {"id": "MIT"}}, {"license": {"url": "https://x"}}]))
        bad["platform"] = "x"
        st, msg = sc.judge(sc.basic_check(bad))
        self.assertEqual(st, "ATTENTION")
        self.assertIn("DT 可能拒收（schema 不符）", msg)
        self.assertIn("license 沒有 id 也沒有 name（lic）", msg)
        self.assertIn("platform", msg)
        # 有 id 或 name、或 expression，不提示；SPDX 不檢查
        fine = cdx(dict(comp("a"), licenses=[{"license": {"name": "Custom"}}, {"expression": "MIT OR ISC"}]))
        self.assertNotIn("DT 可能拒收", sc.judge(sc.basic_check(fine))[1])
        # 提示是說明、不是 schema 驗證：沒有提示也不代表合格
        self.assertEqual(sc.basic_check(fine)["dt_hints"], [])

    def test_missing_cpe_or_purl_is_attention(self):
        st, msg, rc = self.status(cdx(comp("a"), comp("b", cpe=None), comp("c", purl=None)))
        self.assertEqual((st, rc), ("ATTENTION", 0))
        self.assertIn("1 個缺 cpe（b）", msg)
        self.assertIn("1 個缺 purl（c）", msg)

    def test_missing_version_is_attention_and_not_guessed(self):
        st, msg, _ = self.status(cdx(comp("a"), comp("b", version=None), comp("c", version="  ")))
        self.assertEqual(st, "ATTENTION")
        self.assertIn("2 個元件缺版本（b、c）", msg)

    def test_all_without_version_is_gap(self):
        st, msg, rc = self.status(cdx(comp("a", version=None), comp("b", version=None)))
        self.assertEqual((st, rc), ("GAP", 0))
        self.assertIn("不猜", msg)

    def test_no_components_is_gap(self):
        self.assertEqual(self.status(cdx())[0], "GAP")

    def test_nested_components_counted(self):
        inner = comp("inner", version=None)
        outer = comp("outer")
        outer["components"] = [inner]
        st, msg, _ = self.status(cdx(outer))
        self.assertEqual(st, "ATTENTION")
        self.assertIn("2 個元件", msg)
        self.assertIn("inner", msg)

    def test_names_listed_up_to_limit(self):
        st, msg, _ = self.status(cdx(comp("ok"), *[comp("n%d" % i, version=None) for i in range(8)]))
        self.assertIn("8 個元件缺版本（n0、n1、n2、n3、n4 等）", msg)

    def test_spdx(self):
        doc = {"spdxVersion": "SPDX-2.3", "packages": [
            spdx_pkg("a", "1", "pkg:generic/a@1", "cpe:2.3:o:a:a:1:*:*:*:*:*:*:*"),
            spdx_pkg("b")]}
        st, msg, _ = self.status(doc)
        self.assertEqual(st, "ATTENTION")
        self.assertIn("SPDX SPDX-2.3", msg)
        self.assertIn("1 個元件缺版本（b）", msg)

    def test_spdx_ok(self):
        doc = {"spdxVersion": "SPDX-2.3", "packages": [
            spdx_pkg("a", "1", "pkg:generic/a@1", "cpe:2.3:o:a:a:1:*:*:*:*:*:*:*")]}
        self.assertEqual(self.status(doc)[0], "OK")

    def test_fail_cases(self):
        cases = {
            "bad json": dict(raw=b"{not json"),
            "not utf8": dict(raw=b"\xff\xfe\x00"),
            "empty": dict(raw=b""),
            "non-sbom object": dict(obj={"hello": "world"}),
            "list": dict(obj=[1, 2]),
            "cdx wrong format": dict(obj={"bomFormat": "Other", "specVersion": "1.4"}),
            "cdx no spec": dict(obj={"bomFormat": "CycloneDX"}),
            "spdx not spdx": dict(obj={"spdxVersion": "foo"}),
            "deep nesting": dict(raw=b"[" * 100000 + b"]" * 100000),
        }
        for label, kw in cases.items():
            with self.subTest(label):
                st, msg, rc = self.status(**kw)
                self.assertEqual((st, rc), ("FAIL", 1), msg)

    def test_oversize_fails_without_reading_parse(self):
        old = sc.MAX_SIZE
        sc.MAX_SIZE = 100
        self.addCleanup(setattr, sc, "MAX_SIZE", old)
        st, msg, rc = self.status(cdx(*[comp("n%d" % i) for i in range(20)]))
        self.assertEqual((st, rc), ("FAIL", 1))
        self.assertIn("太大", msg)

    def test_missing_file_and_symlink_fail(self):
        rc, lines = self.check(os.path.join(self.tmp.name, "nope.json"))
        self.assertEqual((rc, lines[0][1]), (1, "FAIL"))
        real = self.put("real.json", cdx(comp()))
        link = os.path.join(self.tmp.name, "link.json")
        os.symlink(real, link)
        rc, lines = self.check(link)
        self.assertEqual((rc, lines[0][1]), (1, "FAIL"))
        self.assertIn("拒絕", lines[0][3])

    def test_fail_does_not_stop_other_files(self):
        rc, lines = self.check(self.put("bad.json", raw=b"x"), self.put("good.json", cdx(comp())))
        self.assertEqual(rc, 1)
        self.assertEqual([l[1] for l in lines], ["FAIL", "OK"])


class SbomqsTest(Base):
    def test_score_in_message_but_never_decides_status(self):
        out = json.loads(json.dumps(FAKE_OUT))
        out["files"][0]["sbom_quality_score"] = 0.1
        os.environ["SBOMQS"] = self.fake_sbomqs(json.dumps(out))
        st, msg, rc = self.status(cdx(comp()))
        self.assertEqual((st, rc), ("OK", 0))
        self.assertIn("分數 0.1", msg)
        self.assertIn("僅供參考", msg)

    def test_high_score_does_not_hide_attention(self):
        out = json.loads(json.dumps(FAKE_OUT))
        out["files"][0]["sbom_quality_score"] = 10.0
        os.environ["SBOMQS"] = self.fake_sbomqs(json.dumps(out))
        self.assertEqual(self.status(cdx(comp(version=None), comp("b")))[0], "ATTENTION")

    def test_raw_json_and_md_written(self):
        p = self.put("my sbom.json", cdx(comp()))
        self.check(p)
        raw = os.path.join(self.out, "my_sbom.json.sbomqs.json")
        self.assertEqual(json.load(open(raw))["files"][0]["grade"], "C")
        md = open(os.path.join(self.out, "sbom-check.md"), encoding="utf-8").read()
        self.assertIn("| OK | my sbom.json |", md)
        self.assertIn("| Identification | 8.50 |", md)
        self.assertIn("7.25", md)

    def test_same_basename_does_not_overwrite(self):
        a = self.put("a.json", cdx(comp()))
        os.makedirs(os.path.join(self.tmp.name, "d"))
        b = os.path.join(self.tmp.name, "d", "a.json")
        with open(b, "w") as fh:
            json.dump(cdx(comp()), fh)
        self.check(a, b)
        self.assertEqual(sorted(f for f in os.listdir(self.out) if f.endswith(".sbomqs.json")),
                         ["1-a.json.sbomqs.json", "a.json.sbomqs.json"])

    def test_sbomqs_failure_is_not_run_not_fail(self):
        for label, exe in (("exit1", self.fake_sbomqs("", 1)), ("garbage", self.fake_sbomqs("not json")),
                           ("empty-files", self.fake_sbomqs('{"files": []}')),
                           ("missing", os.path.join(self.tmp.name, "no-such"))):
            with self.subTest(label):
                os.environ["SBOMQS"] = exe
                st, msg, rc = self.status(cdx(comp()))
                self.assertEqual((st, rc), ("OK", 0))
                self.assertIn("sbomqs：NOT_RUN", msg)

    def test_sbomqs_not_run_for_invalid_sbom(self):
        os.environ["SBOMQS"] = os.path.join(self.tmp.name, "must-not-run")
        marker = os.path.join(self.tmp.name, "ran")
        with open(os.environ["SBOMQS"], "w") as fh:
            fh.write("#!/bin/sh\ntouch %s\n" % marker)
        os.chmod(os.environ["SBOMQS"], 0o755)
        self.assertEqual(self.status(obj={"x": 1})[0], "FAIL")
        self.assertFalse(os.path.exists(marker))

    def test_token_env_not_passed_to_sbomqs(self):
        exe = os.path.join(self.tmp.name, "envcheck")
        marker = os.path.join(self.tmp.name, "leak")
        with open(exe, "w") as fh:
            fh.write('#!/bin/sh\n[ -n "$INTERLYNK_SECURITY_TOKEN" ] && touch %s\ncat <<\'E\'\n%s\nE\n' % (marker, json.dumps(FAKE_OUT)))
        os.chmod(exe, 0o755)
        os.environ["SBOMQS"] = exe
        os.environ["INTERLYNK_SECURITY_TOKEN"] = "secret"
        self.addCleanup(os.environ.pop, "INTERLYNK_SECURITY_TOKEN", None)
        self.status(cdx(comp()))
        self.assertFalse(os.path.exists(marker))


class OutputFormatTest(Base):
    def test_line_format_and_no_pass_or_safe_wording(self):
        ok = self.put("ok.json", cdx(comp()))
        att = self.put("att.json", cdx(comp(cpe=None)))
        gap = self.put("gap.json", cdx(comp(version=None)))
        bad = self.put("bad.json", raw=b"{")
        rc, lines = self.check(ok, att, gap, bad)
        self.assertEqual([(l[1], l[2]) for l in lines],
                         [("OK", "ok.json"), ("ATTENTION", "att.json"), ("GAP", "gap.json"), ("FAIL", "bad.json")])
        for l in lines:
            self.assertEqual(len(l), 4)
        text = "\n".join("\t".join(l) for l in lines) + open(os.path.join(self.out, "sbom-check.md"), encoding="utf-8").read()
        self.assertIn("漏洞比對：NOT_RUN（上傳 DT 待臨時 DT 工具）", lines[0][3])
        for word in ("PASS", "安全", "通過"):
            for l in text.splitlines():
                if word in l:
                    self.assertTrue("沒有" in l or "不代表" in l or "不是" in l, l)

    def test_hostile_names_sanitized(self):
        st, msg, _ = self.status(cdx(comp("evil\tname\n|`x", version=None), comp("b")))
        self.assertEqual(st, "ATTENTION")
        self.assertNotIn("\n", msg)
        self.assertEqual(msg.count("\t"), 0)

    def test_shell_wrapper_runs(self):
        p = self.put("w.json", cdx(comp()))
        r = subprocess.run([os.path.join(ROOT, "pipeline", "firmware-sbom-check.sh"), p, "--out", self.out],
                           capture_output=True, text=True, env=dict(os.environ))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("FIRMWARE-SBOM\tOK\tw.json\t"))


class InjectionTest(Base):
    """SBOM 裡的文字進 stdout 狀態行、sbom-check.md（也就是 GITHUB_STEP_SUMMARY）前要被中和。"""

    def run_check(self, doc, name="x.json"):
        rc, lines = self.check(self.put(name, doc))
        with open(os.path.join(self.out, "sbom-check.md"), encoding="utf-8") as fh:
            md = fh.read()
        return lines[0], md

    def test_markdown_link_and_html_neutralized(self):
        evil = "[click](https://evil.example/x)"
        img = "<img src=x onerror=alert(1)>"
        line, md = self.run_check(cdx(comp(evil, version=None), comp(img, version=None), comp("ok")))
        text = "\t".join(line) + md
        for bad in ("](", "[click]", "https://evil", "onerror=alert(1)>"):
            self.assertNotIn(bad, text, bad)
        self.assertNotRegex(text, r"(?<!\\)[<>\[\]]")           # 沒有未跳脫的 < > [ ]
        self.assertIn("\\[click\\]\\(https\\://evil.example/x\\)", md)
        self.assertIn("\\<img src=x onerror=alert\\(1\\)\\>", md)
        self.assertEqual(len(line), 4)

    def test_control_format_and_separator_chars_removed(self):
        name = "a\u202eb\x85c\u2028d\u2029e\u200bf\x1b[31mg\ud800h\tn\nz"
        line, md = self.run_check(cdx(comp(name, version=None), comp("ok")))
        for ch in "\u202e\x85\u2028\u2029\u200b\x1b\ud800\t":
            self.assertNotIn(ch, line[3], hex(ord(ch)))
            self.assertNotIn(ch, md, hex(ord(ch)))
        self.assertIn("a b c d e f", line[3])

    def test_hostile_file_name_and_spec_and_sbomqs_text(self):
        out = json.loads(json.dumps(FAKE_OUT))
        out["creation_info"]["version"] = "[v](http://e)"
        out["files"][0]["grade"] = "<b>"
        out["files"][0]["comprehenssive"][0]["category"] = "[c](http://e)|"
        os.environ["SBOMQS"] = self.fake_sbomqs(json.dumps(out))
        doc = cdx(comp(), spec="1.4](http://e)")
        line, md = self.run_check(doc, name="[f](http:--e) <i>.json")
        text = "\t".join(line) + md
        for bad in ("](", "<i>", "<b>", "http://e"):
            self.assertNotIn(bad, text, bad)
        self.assertNotRegex(text, r"(?<!\\)[<>\[\]]")

    def test_pipe_in_name_does_not_add_table_cells(self):
        line, md = self.run_check(cdx(comp("a|b|c", version=None), comp("ok")))
        row = [l for l in md.splitlines() if l.startswith("| ATTENTION")][0]
        self.assertEqual(len(row.replace("\\|", "").split("|")), 5)       # 開頭空 + 3 欄 + 結尾空
        self.assertIn("a\\|b\\|c", row)

    def test_name_is_truncated(self):
        line, _ = self.run_check(cdx(comp("n" * 500, version=None), comp("ok")))
        self.assertNotIn("n" * 100, line[3])
        self.assertIn("…", line[3])

    def test_lone_surrogate_in_name_does_not_crash_md_write(self):
        raw = json.dumps(cdx(comp("x\ud800y", version=None), comp("ok"))).encode()
        rc, lines = self.check(self.put("s.json", raw=raw))
        self.assertEqual((rc, lines[0][1]), (0, "ATTENTION"))

    def test_clean_is_the_shared_function(self):
        spec = importlib.util.spec_from_file_location("firmware_mdsafe", os.path.join(ROOT, "pipeline", "lib", "firmware_mdsafe.py"))
        shared = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(shared)
        for t in ("[a](b)", "x\u202ey", "https://e.x", "a|b"):
            self.assertEqual(sc.clean(t), shared.md_safe(t))

    def test_report_text_in_other_md_writers_uses_shared_function(self):
        # firmware-ci.sh 與 firmware_dt.py 的 markdown 儲存格也走同一個函式
        with open(os.path.join(ROOT, "pipeline", "firmware-ci.sh"), encoding="utf-8") as fh:
            self.assertIn("firmware_mdsafe.py", fh.read())
        with open(os.path.join(ROOT, "pipeline", "lib", "firmware_dt.py"), encoding="utf-8") as fh:
            self.assertIn("firmware_mdsafe.py", fh.read())


class DepthTest(Base):
    def nested(self, levels, leaf_version="1.0"):
        """第 1 層到第 levels 層各一個元件的巢狀鏈（最深那個的版本是 leaf_version）。"""
        node = comp("L%d" % levels, version=leaf_version)
        for i in range(levels - 1, 0, -1):
            parent = comp("L%d" % i)
            parent["components"] = [node]
            node = parent
        return cdx(node)

    def test_depth_limit_is_fully_checked(self):
        st, msg, rc = self.status(self.nested(sc.MAX_DEPTH))
        self.assertEqual((st, rc), ("OK", 0))
        self.assertIn("%d 個元件" % sc.MAX_DEPTH, msg)
        self.assertNotIn("巢狀過深", msg)

    def test_too_deep_is_attention_with_explanation(self):
        st, msg, rc = self.status(self.nested(sc.MAX_DEPTH + 10))
        self.assertEqual((st, rc), ("ATTENTION", 0))
        self.assertIn("巢狀過深，第 %d 層以下沒有檢查" % (sc.MAX_DEPTH + 1), msg)
        self.assertIn("%d 個元件" % sc.MAX_DEPTH, msg)          # 只計入有檢查的那些層
        self.assertIn("至少 1 個元件未計入", msg)

    def test_too_deep_counts_skipped_siblings(self):
        doc = self.nested(sc.MAX_DEPTH)
        node = doc["components"][0]
        while node.get("components"):
            node = node["components"][0]
        node["components"] = [comp("d1"), comp("d2"), "not-a-dict", comp("d3")]
        st, msg, _ = self.status(doc)
        self.assertEqual(st, "ATTENTION")
        self.assertIn("至少 3 個元件未計入", msg)

    def test_too_deep_does_not_hide_gap_and_shows_in_md(self):
        doc = self.nested(sc.MAX_DEPTH + 1, leaf_version=None)
        for c in doc["components"]:
            c.pop("version", None)
        st, msg, _ = self.status(doc)
        self.assertIn(st, ("GAP", "ATTENTION"))
        self.assertIn("巢狀過深", msg)

    def test_deep_chain_is_walked_without_recursion(self):
        st, msg, _ = self.status(self.nested(200))
        self.assertEqual(st, "ATTENTION")
        self.assertIn("巢狀過深，第 %d 層以下沒有檢查" % (sc.MAX_DEPTH + 1), msg)
        self.assertIn("至少 1 個元件未計入", msg)

    def test_json_too_deep_to_parse_is_fail_with_clear_message(self):
        st, msg, rc = self.status(raw=b"[" * 100000 + b"]" * 100000)
        self.assertEqual((st, rc), ("FAIL", 1))
        self.assertIn("巢狀太深", msg)


class PlaceholderTest(Base):
    VALUES = ["NOASSERTION", "noassertion", "NoAssertion", "NONE", "none", "n/a", "N/A", "unknown", "UNKNOWN", "Unknown",
              "null", "-", "  ", "", " NOASSERTION ", "\u200b", "\t-\n"]

    def test_placeholders_count_as_missing_for_version_purl_cpe(self):
        for v in self.VALUES:
            for field in ("version", "purl", "cpe"):
                with self.subTest(value=v, field=field):
                    st, msg, _ = self.status(cdx(comp("ok"), comp("p", **{field: v})))
                    self.assertEqual(st, "ATTENTION")
                    label = {"version": "缺版本", "purl": "缺 purl", "cpe": "缺 cpe"}[field]
                    self.assertIn("1 個%s（p）" % ("元件缺版本" if field == "version" else label), msg)

    def test_placeholder_only_version_everywhere_is_gap(self):
        st, msg, _ = self.status(cdx(comp("a", version="NOASSERTION"), comp("b", version="unknown")))
        self.assertEqual(st, "GAP")

    def test_real_values_that_contain_placeholder_words_are_present(self):
        doc = cdx(comp("a", version="v1-none", purl="pkg:generic/unknown@1", cpe="cpe:2.3:o:n_a:x:1:*:*:*:*:*:*:*"),
                  comp("b", version="0", purl="pkg:generic/b@0"), comp("c", version="N/A-1"))
        st, msg, _ = self.status(doc)
        self.assertEqual(st, "OK")
        self.assertNotIn("缺", msg)

    def test_spdx_versioninfo_noassertion_is_missing(self):
        doc = {"spdxVersion": "SPDX-2.3", "packages": [
            spdx_pkg("a", "1", "pkg:generic/a@1", "cpe:2.3:o:a:a:1:*:*:*:*:*:*:*"),
            spdx_pkg("b", "NOASSERTION", "pkg:generic/b@1", "cpe:2.3:o:b:b:1:*:*:*:*:*:*:*"),
            {"name": "c", "versionInfo": "NONE", "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "NOASSERTION"},
                {"referenceType": "cpe23Type", "referenceLocator": "none"}]}]}
        st, msg, _ = self.status(doc)
        self.assertEqual(st, "ATTENTION")
        self.assertIn("2 個元件缺版本（b、c）", msg)
        self.assertIn("1 個缺 purl（c）", msg)
        self.assertIn("1 個缺 cpe（c）", msg)

    def test_placeholder_name_is_unnamed(self):
        st, msg, _ = self.status(cdx(comp("ok"), comp("NOASSERTION", version=None)))
        self.assertIn("(無名稱)", msg)


class LimitsTest(Base):
    def test_limits_values(self):
        self.assertEqual(sc.MAX_SIZE, 16 * 1024 * 1024)
        self.assertEqual(sc.MAX_OBJECTS, 2_000_000)

    def test_oversize_message_states_limit(self):
        p = self.put("big.json", raw=b" " * (sc.MAX_SIZE + 1))
        rc, lines = self.check(p)
        self.assertEqual((rc, lines[0][1]), (1, "FAIL"))
        self.assertIn("太大", lines[0][3])
        self.assertIn("16 MiB", lines[0][3])

    def test_too_many_objects_fails_without_parsing(self):
        raw = b"[" + b"{}," * 2_500_000 + b"{}]"          # 約 10 MB，低於大小上限，但 { 有 250 萬個
        p = self.put("many.json", raw=raw)
        with mock.patch.object(sc.json, "loads", side_effect=AssertionError("不應該解析")):
            rc, lines = self.check(p)
        self.assertEqual((rc, lines[0][1]), (1, "FAIL"))
        self.assertIn("結構太多", lines[0][3])
        self.assertIn("2000000", lines[0][3])

    def test_brackets_count_too(self):
        p = self.put("many2.json", raw=b"[" + b"[]," * 2_500_000 + b"[]]")
        with mock.patch.object(sc.json, "loads", side_effect=AssertionError("不應該解析")):
            rc, lines = self.check(p)
        self.assertEqual(lines[0][1], "FAIL")

    def test_object_limit_is_inclusive_and_normal_sbom_passes(self):
        doc = cdx(*[comp("n%d" % i) for i in range(10)])
        text = json.dumps(doc)
        n = text.count("{") + text.count("[")
        with mock.patch.object(sc, "MAX_OBJECTS", n):
            self.assertEqual(self.status(doc)[0], "OK")
        with mock.patch.object(sc, "MAX_OBJECTS", n - 1):
            self.assertEqual(self.status(doc)[0], "FAIL")


class LoadTest(Base):
    def test_uses_o_nofollow_open_and_fstat_not_lstat(self):
        p = self.put("a.json", cdx(comp()))
        real_open = os.open
        flags = []

        def spy(path, fl, *a, **k):
            flags.append(fl)
            return real_open(path, fl, *a, **k)
        with mock.patch.object(sc.os, "open", side_effect=spy), \
                mock.patch.object(sc.os, "lstat", side_effect=AssertionError("不該用 lstat")), \
                mock.patch.object(sc.os, "stat", side_effect=AssertionError("不該用 stat")):
            doc, err = sc.load(p)
        self.assertIsNone(err)
        self.assertEqual(len(flags), 1)
        self.assertTrue(flags[0] & os.O_NOFOLLOW)
        self.assertFalse(flags[0] & (os.O_WRONLY | os.O_RDWR))

    def test_symlink_refused(self):
        real = self.put("real.json", cdx(comp()))
        link = os.path.join(self.tmp.name, "l.json")
        os.symlink(real, link)
        doc, err = sc.load(link)
        self.assertIsNone(doc)
        self.assertIn("拒絕", err)
        dangling = os.path.join(self.tmp.name, "d.json")
        os.symlink(os.path.join(self.tmp.name, "nope"), dangling)
        self.assertIn("拒絕", sc.load(dangling)[1])

    def test_directory_refused(self):
        d = os.path.join(self.tmp.name, "dir.json")
        os.mkdir(d)
        doc, err = sc.load(d)
        self.assertIsNone(doc)
        self.assertIn("不是一般檔案", err)

    def test_fifo_refused_without_blocking(self):
        f = os.path.join(self.tmp.name, "fifo.json")
        os.mkfifo(f)
        code = ("import importlib.util,sys\n"
                "s=importlib.util.spec_from_file_location('m',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n"
                "print(m.load(sys.argv[2]))\n")
        r = subprocess.run([sys.executable, "-I", "-c", code, os.path.join(ROOT, "pipeline", "lib", "firmware_sbom_check.py"), f],
                           capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("不是一般檔案", r.stdout)

    def test_missing_file(self):
        doc, err = sc.load(os.path.join(self.tmp.name, "nope.json"))
        self.assertIsNone(doc)
        self.assertIn("讀不到檔案", err)

    def test_fd_is_closed(self):
        p = self.put("a.json", cdx(comp()))
        before = set(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None
        for _ in range(50):
            sc.load(p)
            sc.load(os.path.join(self.tmp.name, "nope"))
        if before is not None:
            self.assertEqual(len(os.listdir("/proc/self/fd")), len(before))


class ExitCodeTest(Base):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), mock.patch.object(sys, "stderr", err):
            try:
                rc = sc.main(argv)
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def test_usage_errors_are_64_and_print_one_status_line(self):
        for argv in ([], ["--out", self.out], [os.path.join(self.tmp.name, "x.json")], ["--bogus", "x", "--out", self.out]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_main(argv)
                self.assertEqual(rc, 64)
                self.assertEqual(len(out.splitlines()), 1)
                self.assertTrue(out.startswith("FIRMWARE-SBOM\tFAIL\t-\t用法錯誤"), out)
                self.assertIn("usage", err)

    def test_help_is_zero(self):
        self.assertEqual(self.run_main(["--help"])[0], 0)

    def test_attention_and_gap_are_zero_fail_is_one(self):
        att = self.put("att.json", cdx(comp(cpe=None)))
        gap = self.put("gap.json", cdx())
        self.assertEqual(self.check(att, gap)[0], 0)
        self.assertEqual(self.check(att, self.put("bad.json", raw=b"{"))[0], 1)

    def test_shell_wrapper_usage_error_is_64(self):
        wrapper = os.path.join(ROOT, "pipeline", "firmware-sbom-check.sh")
        for args in ([], ["x.json"]):
            r = subprocess.run([wrapper] + args, capture_output=True, text=True)
            self.assertEqual(r.returncode, 64, r.stderr)
            self.assertTrue(r.stdout.startswith("FIRMWARE-SBOM\tFAIL\t-\t"), r.stdout)

    def test_unwritable_out_is_fail_1(self):
        blocker = self.put("file.txt", raw=b"x")
        rc, out, _ = self.run_main([self.put("a.json", cdx(comp())), "--out", os.path.join(blocker, "sub")])
        self.assertEqual(rc, 1)
        self.assertIn("FAIL", out)


class ToolVersionTest(Base):
    SCRIPT = os.path.join(ROOT, "pipeline", "check-tool-version.sh")

    def lock(self, text):
        return self.put("tools.lock", raw=text.encode())

    def exe(self, text):
        p = os.path.join(self.tmp.name, "fake-tool%d" % len(os.listdir(self.tmp.name)))
        with open(p, "w") as fh:
            fh.write("#!/bin/sh\n%s\n" % text)
        os.chmod(p, 0o755)
        return p

    def run_script(self, tool, exe, lock):
        env = dict(os.environ, TOOLS_LOCK=lock)
        return subprocess.run([self.SCRIPT, tool, exe], capture_output=True, text=True, env=env)

    def test_match_ok_mismatch_fail(self):
        lock = self.lock("sbomqs_version=v2.1.3\n")
        good = self.exe("echo 'GitVersion:    v2.1.3'; echo 'GitCommit:     abc'")
        r = self.run_script("sbomqs", good, lock)
        self.assertEqual((r.returncode, r.stdout), (0, "TOOL-VERSION\tOK\tsbomqs\tv2.1.3\n"))
        old = self.exe("echo 'GitVersion:    v2.1.2'")
        r = self.run_script("sbomqs", old, lock)
        self.assertEqual(r.returncode, 1)
        self.assertIn("版本不符", r.stdout)
        self.assertIn("v2.1.2", r.stdout)
        self.assertIn("v2.1.3", r.stdout)

    def test_prefix_or_suffix_is_not_a_match(self):
        lock = self.lock("sbomqs_version=v2.1.3\n")
        for got in ("v2.1.30", "v2.1", "2.1.3", "v2.1.3-rc1"):
            r = self.run_script("sbomqs", self.exe("echo 'GitVersion:    %s'" % got), lock)
            self.assertEqual(r.returncode, 1, got)

    def test_no_version_line_or_failing_tool_or_missing_lock_entry_fail(self):
        lock = self.lock("sbomqs_version=v2.1.3\n")
        self.assertEqual(self.run_script("sbomqs", self.exe("echo hello"), lock).returncode, 1)
        self.assertEqual(self.run_script("sbomqs", self.exe("exit 3"), lock).returncode, 1)
        self.assertEqual(self.run_script("sbomqs", os.path.join(self.tmp.name, "no-such"), lock).returncode, 1)
        self.assertEqual(self.run_script("sbomqs", self.exe("echo 'GitVersion: v2.1.3'"), self.lock("other_version=v1\n")).returncode, 1)
        self.assertEqual(self.run_script("othertool", self.exe("echo 'GitVersion: v1'"), self.lock("othertool_version=v1\n")).returncode, 1)

    def test_usage_errors_are_64(self):
        self.assertEqual(subprocess.run([self.SCRIPT], capture_output=True).returncode, 64)
        self.assertEqual(subprocess.run([self.SCRIPT, "Bad;Name", "x"], capture_output=True).returncode, 64)

    def test_real_lock_has_version_the_script_reads(self):
        with open(os.path.join(ROOT, "pipeline", "lib", "tools.lock"), encoding="utf-8") as fh:
            ver = [l.strip().split("=", 1)[1] for l in fh if l.startswith("sbomqs_version=")][0]
        r = subprocess.run([self.SCRIPT, "sbomqs", self.exe("echo 'GitVersion:    %s'" % ver)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, ".github", "workflows", "firmware.yml"), encoding="utf-8") as fh:
            self.wf = fh.read()

    def test_installed_version_is_checked_against_lock(self):
        self.assertIn("pipeline/check-tool-version.sh sbomqs", self.wf)
        self.assertIn("pipeline/check-tool-version.sh", self.wf.split("paths:")[1].split("workflow_dispatch")[0])
        # 版本檢查要在「安裝」之後、「品質檢查」之前
        self.assertLess(self.wf.index("install-tool.sh sbomqs"), self.wf.index("check-tool-version.sh sbomqs"))
        self.assertLess(self.wf.index("check-tool-version.sh sbomqs"), self.wf.index("firmware-sbom-check.sh"))

    def test_sbom_glob_uses_nullglob_and_reports_not_run(self):
        step = self.wf.split("名稱")[0] if False else self.wf[self.wf.index("供應商 SBOM 品質檢查\n"):]
        self.assertIn("shopt -s nullglob", step)
        self.assertIn("FIRMWARE-SBOM\tNOT_RUN", step)
        self.assertNotIn('firmware-sbom-check.sh "$RUNNER_TEMP"/firmware-dl', step)   # 不再直接把 glob 傳給腳本

    def test_nullglob_snippet_behaves(self):
        # 同樣的展開寫法：沒有符合的檔案時陣列是空的，不是字面的萬用字元
        r = subprocess.run(["bash", "-c", 'shopt -s nullglob; d=$(mktemp -d); files=("$d"/sbom/*/*.sbom.json); echo ${#files[@]}; rmdir "$d"'],
                           capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "0")


class RepoFilesTest(unittest.TestCase):
    def test_sbom_manifest_and_lock(self):
        import yaml
        ff_spec = importlib.util.spec_from_file_location(
            "firmware_fetch", os.path.join(ROOT, "pipeline", "lib", "firmware_fetch.py"))
        ff = importlib.util.module_from_spec(ff_spec)
        ff_spec.loader.exec_module(ff)
        with open(os.path.join(ROOT, "firmware", "sbom", "dasharo-novacustom-ns5x-tgl-v1.6.0", "firmware.yml"), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        self.assertEqual(ff.validate(doc), [])
        self.assertEqual(doc["kind"], "sbom")
        with open(os.path.join(ROOT, "pipeline", "lib", "tools.lock"), encoding="utf-8") as fh:
            lock = dict(l.strip().split("=", 1) for l in fh if "=" in l and not l.startswith("#"))
        self.assertRegex(lock["sbomqs_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(lock["sbomqs_url"].startswith("https://"))
        self.assertIn(lock["sbomqs_version"], lock["sbomqs_url"])

    def test_plan_ignores_sbom_kind(self):
        r = subprocess.run(["python3", "-I", os.path.join(ROOT, "pipeline", "lib", "firmware_plan.py"),
                            os.path.join(ROOT, "firmware", "sbom", "dasharo-novacustom-ns5x-tgl-v1.6.0", "firmware.yml"),
                            "--dl", "/nonexistent-dl", "--work", "/nonexistent-work"], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()
