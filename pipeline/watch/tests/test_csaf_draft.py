"""csaf_draft.py 與 match.py 的接線：新的 KEV 群組 → CSAF 使用者通知草稿（CRA 第 14 條第 8 項；docs/WATCH.md 第 8 節）。
資料全部是合成的。tools/cra/csaf_advisory.py 照真的跑（沒有 jsonschema 時 schema 驗證是 NOT_RUN，草稿照樣產生、狀態 ATTENTION）。"""
import datetime
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import collect  # noqa: E402
import csaf_draft  # noqa: E402
import match  # noqa: E402
from test_match import NOW1, NOW2, REQ, Base  # noqa: E402

ROWS_SCHEMA = "sca-center-vulnerability-rows/1"
NOW = datetime.datetime(2026, 11, 11, 1, 0, tzinfo=datetime.timezone.utc)


def report_zip(path, cve="CVE-2018-18074", purl=REQ, product="demo", version="v1", extra=None, skip=(), dup=None, link=None):
    """report_package 的 zip 結構（只放 csaf_draft 讀的 4 個成員；extra：多放的成員 {名稱: 內容}）。"""
    row = {"id": cve, "aliases": [], "component": "requests", "version": "2.19.0", "purl": purl, "tier": "p1", "vex": None,
           "fix_state": "fixed", "fix_versions": ["2.20.0"], "fix_next": "2.20.0", "cvss": None, "exploited": True,
           "exploitation_evidence": ["KEV (test)"]}
    files = {"vulnerability-rows.json": {"schema": ROWS_SCHEMA, "vulnerability_data_status": "OK", "rows": [row]},
             "vex.cdx.json": {"bomFormat": "CycloneDX", "metadata": {"component": {"name": product, "version": version}}, "vulnerabilities": []},
             "summary.json": {}, "sbom.cdx.json": {"bomFormat": "CycloneDX", "components": []}}
    with zipfile.ZipFile(path, "w") as z:
        for k, v in files.items():
            if k not in skip:
                z.writestr(collect.REPORT_MEMBERS[k], json.dumps(v))
        if dup:
            z.writestr(collect.REPORT_MEMBERS[dup], "{}")
        if link:
            i = zipfile.ZipInfo(collect.REPORT_MEMBERS[link])
            i.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(i, "/etc/passwd")
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return path


class Extract(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="c3-csaf-")
        self.d = self._td.name
        self.addCleanup(self._td.cleanup)

    def test_only_fixed_members_are_written(self):
        z = report_zip(os.path.join(self.d, "r.zip"), extra={"../../evil.txt": "x", "報告/內部存檔/other.json": "{}"})
        self.assertIsNone(collect.report_zip_problem(z))
        dest = os.path.join(self.d, "out")
        csaf_draft.extract_reports(z, dest)
        self.assertEqual(sorted(os.listdir(dest)), ["sbom.cdx.json", "summary.json", "vex.cdx.json", "vulnerability-rows.json"])
        self.assertFalse(os.path.exists(os.path.join(self.d, "evil.txt")))

    def test_missing_duplicate_symlink_and_oversize_are_rejected(self):
        cases = {"missing": dict(skip=("vulnerability-rows.json",)), "dup": dict(dup="vex.cdx.json"), "link": dict(link="summary.json")}
        for name, kw in cases.items():
            z = report_zip(os.path.join(self.d, f"{name}.zip"), **kw)
            self.assertIsNotNone(collect.report_zip_problem(z), name)
            with self.assertRaises(csaf_draft.ZipProblem, msg=name):
                csaf_draft.extract_reports(z, os.path.join(self.d, f"out-{name}"))
        z = report_zip(os.path.join(self.d, "big.zip"))
        old = collect.REPORT_MEMBER_MAX
        collect.REPORT_MEMBER_MAX = 10
        try:
            self.assertIn("上限", collect.report_zip_problem(z))
            with self.assertRaises(csaf_draft.ZipProblem):
                csaf_draft.extract_reports(z, os.path.join(self.d, "out-big"))
        finally:
            collect.REPORT_MEMBER_MAX = old
        bad = os.path.join(self.d, "bad.zip")
        open(bad, "wb").write(b"not a zip")
        self.assertEqual(collect.report_zip_problem(bad), "不是可讀的 zip")


class DraftsUnit(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="c3-csaf-")
        self.d = self._td.name
        self.addCleanup(self._td.cleanup)
        self.es = [{"project": "demo", "version": "v1", "cve": "CVE-2018-18074", "first_detected": "2026-11-11T01:00:00Z",
                    "sources": ["CISA KEV"], "euvd": {"date_added": "2026-01-01"}, "project_uuid": "dumpling:demo/v1#bsp"}]

    def p(self, **kw):
        return dict({"uuid": "dumpling:demo/v1#bsp", "layer": "bsp", "kind": "release", "status": "shipped", "report_zip": None}, **kw)

    def test_dev_release_is_not_run_and_no_issue_line(self):
        dr = csaf_draft.Drafts(self.d, NOW, demo=True, artifact="watch-csaf-drafts-x-1")
        rec = dr.for_group(self.es, self.p(kind="dev", status="development"))
        self.assertEqual((rec["status"], rec["dir"]), ("NOT_RUN", None))
        self.assertIn("development", rec["detail"])
        self.assertIsNone(dr.issue_line(rec))
        self.assertIsNone(dr.summary_line())
        self.assertFalse(os.path.exists(os.path.join(self.d, csaf_draft.DRAFT_DIR)))

    def test_shipped_without_report_zip_is_not_run_with_reason_in_issue(self):
        dr = csaf_draft.Drafts(self.d, NOW)
        rec = dr.for_group(self.es, self.p())
        self.assertEqual(rec["status"], "NOT_RUN")
        line = dr.issue_line(rec)
        self.assertIn("沒有產生（NOT_RUN）", line)
        self.assertIn("報告 zip", line)

    def test_shipped_with_report_zip_writes_draft_readme_and_tbc_publisher(self):
        z = report_zip(os.path.join(self.d, "report-demo-v1-bsp.zip"))
        dr = csaf_draft.Drafts(self.d, NOW, demo=True, artifact="watch-csaf-drafts-real-1")
        rec = dr.for_group(self.es, self.p(report_zip=z))
        self.assertIn(rec["status"], ("OK", "ATTENTION"), rec)
        leaf = os.path.join(self.d, rec["dir"])
        doc = json.load(open(os.path.join(leaf, "csaf-exploited-draft.json"), encoding="utf-8"))
        self.assertEqual(doc["document"]["tracking"]["status"], "draft")
        self.assertEqual(doc["document"]["tracking"]["generator"]["engine"]["name"], "dumpling csaf_advisory.py exploited")
        pub = doc["document"]["publisher"]
        self.assertEqual(pub["name"], "TO BE COMPLETED")                    # 沒有這個專案的設定：發布者全部 TO BE COMPLETED
        self.assertEqual(pub["namespace"], "https://to-be-completed.invalid")
        self.assertNotIn("contact_details", pub)                             # 沒有預設的聯絡人
        rd = open(os.path.join(leaf, "README.md"), encoding="utf-8").read().splitlines()
        self.assertTrue(rd[0].startswith("# 草稿：工具不發布"))
        self.assertTrue(any("不是真的出貨產品" in x for x in rd))
        self.assertEqual(sorted(os.listdir(os.path.join(self.d, csaf_draft.DRAFT_DIR))), [os.path.basename(rec["dir"])])   # 暫存的 Reports 已清掉
        line = dr.issue_line(rec)
        self.assertIn("watch-csaf-drafts-real-1", line)
        self.assertIn("draft", line)
        self.assertIn("保留 90 天", line)

    def test_demo_project_config_has_no_default_domain_or_contact(self):
        for name in sorted(os.listdir(os.path.join(csaf_draft.ROOT, "projects"))):
            cfg = csaf_draft.load_config(name)
            cs = cfg.get("csaf") or {}
            self.assertFalse(cs.get("publisher_namespace") or cs.get("contact") or cs.get("advisory_url_base"), name)
            self.assertFalse((cfg.get("manufacturer") or {}).get("website") or (cfg.get("manufacturer") or {}).get("email"), name)
        self.assertEqual(csaf_draft.load_config("../etc"), {})

    def test_bad_zip_is_fail_without_draft_and_limit(self):
        bad = os.path.join(self.d, "bad.zip")
        open(bad, "wb").write(b"x")
        dr = csaf_draft.Drafts(self.d, NOW)
        rec = dr.for_group(self.es, self.p(report_zip=bad))
        self.assertEqual((rec["status"], rec["dir"]), ("FAIL", None))
        z = report_zip(os.path.join(self.d, "r.zip"))
        dr = csaf_draft.Drafts(self.d, NOW)
        dr.made = csaf_draft.MAX_DRAFTS
        rec = dr.for_group(self.es, self.p(report_zip=z))
        self.assertEqual(rec["status"], "NOT_RUN")
        self.assertIn("上限", rec["detail"])

    def test_internal_error_is_recorded_not_raised(self):
        z = report_zip(os.path.join(self.d, "r.zip"))

        class Boom:
            def exploited_run(self, *a, **k):
                raise RuntimeError("boom")
        dr = csaf_draft.Drafts(self.d, NOW, tool=Boom())
        rec = dr.for_group(self.es, self.p(report_zip=z))
        self.assertEqual(rec["status"], "FAIL")
        self.assertIn("RuntimeError", rec["detail"])


class MatchWiring(Base):
    """match.run：shipped 的正式版有新的 KEV 群組 → 草稿與 Issue 內文一句；drill 不產生；彙總 Issue 一句。"""

    def add_report_zip(self, **kw):
        z = report_zip(os.path.join(self.inv, "releases", "0", "report-demo-v1-bsp.zip"), **kw)
        self.inventory["releases"][0]["report_zips"] = {"bsp": {"file": "releases/0/report-demo-v1-bsp.zip", "sha256": "x", "size": 1}}
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        return z

    def run_once(self, now, mode="real", **kw):
        out = os.path.join(self.w, "out-" + now[:10])
        vs = [{"cveID": c, "vendorProject": "x", "product": "y", "dateAdded": "2021-12-10"} for c in self.kev]
        json.dump({"dateReleased": now, "vulnerabilities": vs}, open(os.path.join(self.feeds, "cisa-kev.json"), "w"))
        import argparse
        a = argparse.Namespace(inventory=os.path.join(self.inv, "inventory.json"), state_dir=self.state, feeds=self.feeds, out=out, mode=mode,
                               kev_overlay=None, max_new_issues=kw.get("max_new", 20), run_url="https://github.com/o/r/actions/runs/1",
                               grype=None, grype_total_timeout=100, vendor_config=None, now=now, demo=True, allow_baseline=True,
                               prev_schedule=None, run_id="999", firmware_rematch=None, csaf_artifact="watch-csaf-drafts-real-1")
        match.run(a)
        plan = json.load(open(os.path.join(out, "plan.json")))
        json.dump(plan["state"], open(os.path.join(self.state, "state.json"), "w"))
        self.write_base(7, 1)
        res = json.load(open(os.path.join(out, "result.json")))
        return out, plan, res

    def test_new_kev_on_shipped_release_writes_draft_and_issue_line(self):
        self.add_report_zip()
        self.run_once(NOW1)                                     # 基準（不產生草稿）
        self.kev = ["CVE-2021-44228", "CVE-2018-18074"]
        out, plan, res = self.run_once(NOW2)
        (rec,) = res["csaf_drafts"]
        self.assertIn(rec["status"], ("OK", "ATTENTION"), rec)
        self.assertTrue(os.path.isfile(os.path.join(out, rec["dir"], "csaf-exploited-draft.json")))
        op = [x for x in plan["actions"] if x["op"] == "open" and "CVE-2018-18074" in x["title"]]
        self.assertEqual(len(op), 1)
        self.assertIn("watch-csaf-drafts-real-1", op[0]["body"])
        self.assertEqual(op[0]["body"].count("CRA 第 14 條第 8 項的使用者通知草稿"), 1)   # Issue 只寫一句
        self.assertNotIn("csaf_security_advisory", op[0]["body"])                          # 不貼草稿內容
        self.assertEqual(match.unsafe_markdown(op[0]["body"]), [])
        self.assertIn("CSAF 使用者通知草稿", open(os.path.join(out, "report.md"), encoding="utf-8").read())

    def test_dev_release_records_not_run_without_issue_line(self):
        r = self.inventory["releases"][0]
        r.update(kind="dev", tag="dev/demo", watch_version="dev", status="development")
        json.dump(self.inventory, open(os.path.join(self.inv, "inventory.json"), "w"))
        self.run_once(NOW1)
        self.kev = ["CVE-2021-44228", "CVE-2018-18074"]
        out, plan, res = self.run_once(NOW2)
        (rec,) = res["csaf_drafts"]
        self.assertEqual(rec["status"], "NOT_RUN")
        self.assertIn("development", rec["detail"])
        self.assertFalse(any("使用者通知草稿" in x["body"] for x in plan["actions"]))
        self.assertFalse(os.path.exists(os.path.join(out, csaf_draft.DRAFT_DIR)))

    def test_baseline_and_drill_do_not_make_drafts(self):
        self.add_report_zip()
        out, plan, res = self.run_once(NOW1)
        self.assertNotIn("csaf_drafts", res)                     # 建基準的那一次不產生
        self.kev = ["CVE-2021-44228", "CVE-2018-18074"]
        self.state = os.path.join(self.w, "state-drill")
        os.makedirs(self.state)
        self.write_base(None, 0)
        self.run_once(NOW1, mode="drill")
        out, plan, res = self.run_once(NOW2, mode="drill")
        self.assertNotIn("csaf_drafts", res)
        self.assertFalse(os.path.exists(os.path.join(out, csaf_draft.DRAFT_DIR)))

    def test_summary_issue_has_one_line(self):
        self.add_report_zip()
        self.run_once(NOW1)
        self.kev = ["CVE-2021-44228", "CVE-2018-18074"]
        out, plan, res = self.run_once(NOW2, max_new=0)          # 超過上限 → 併成彙總 Issue
        self.assertEqual(len(res["csaf_drafts"]), 1)
        (summ,) = [x for x in plan["actions"] if "summary" in (x.get("labels") or [])]
        self.assertEqual(summ["body"].count("CRA 第 14 條第 8 項的使用者通知草稿"), 1)
        self.assertIn("已產生 1 份", summ["body"])
        self.assertEqual(match.unsafe_markdown(summ["body"]), [])


class Workflow(unittest.TestCase):
    def test_round_uploads_drafts_and_passes_artifact_name(self):
        y = open(os.path.join(csaf_draft.ROOT, ".github", "workflows", "watch-round.yml"), encoding="utf-8").read()
        self.assertIn("--csaf-artifact \"watch-csaf-drafts-", y)
        i = y.index("name: watch-csaf-drafts-")
        block = y[y.rindex("- uses:", 0, i):y.index("\n      - ", i)]
        self.assertIn("actions/upload-artifact@", block)
        self.assertIn("/w/out/csaf-drafts", block)
        self.assertIn("retention-days: 90", block)
        self.assertIn("if: inputs.mode == 'real'", block)


if __name__ == "__main__":
    unittest.main()
