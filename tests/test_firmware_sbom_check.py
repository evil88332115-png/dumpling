"""firmware-sbom-check 的單元測試。不連網；sbomqs 用假執行檔（環境變數 SBOMQS）取代。"""
import importlib.util
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
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
