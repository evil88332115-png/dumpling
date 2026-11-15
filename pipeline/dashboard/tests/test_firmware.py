"""儀表板「韌體示範」區的測試（docs/DASHBOARD.md 第 12 節）：不連網，資料全部合成（欄位照 C2 的 firmware-meta 範例）。
涵蓋：韌體 Release 的列出與「不合規則」警告、只取最新一個、meta 壞掉整區 GAP、dt 欄位四種情況、not_watched 的 source、
對照表（識別、status、stale）、size_stopped_at、per_sbom 的 advisory、公告用語、惡意字串、trigger 的 firmware 規則。"""
import json
import os
import re
import unittest

from . import test_dashboard as td

build, check_site, render, trigger, watchlib = td.build, td.check_site, td.render, td.trigger, td.watchlib
collect, issues, REPO, HEX = td.collect, td.issues, td.REPO, td.HEX
match = watchlib.load("match")

TAG = "firmware-demo/2026.11.20"
SHA_A, SHA_B = "a" * 64, "b" * 64
IMG = "e915ed1eae8b7b91a7a94ad7a75d57a4a077c0e7c6379234755788ca72fb1cd9"
EXAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "watch", "tests", "data", "firmware-meta.example.json")
EVIL = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "javascript:alert(1)", "@everyone", "x\x00y\x1b[31mz‮\r\n\tend", "A" * 5000]
WORDS = (match.FW_WORD_PRELIM, match.FW_WORD_CONFIRMED, match.FW_WORD_UCODE, match.FW_WORD_VBIOS)


def wvk(slug, ver):
    """監控鍵的版本部分：<slug> 加上 @ 加上 <版本>（測試裡不寫成字面字串）。"""
    return slug + "@" + ver


def uuid_of(wv):
    return "dumpling:firmware-demo/%s#firmware" % wv


def bios(slug="novacustom-v540tu-mtl-v1.0.1", ver="v1.0.1", img=IMG, **over):
    x = {"slug": slug, "kind": "bios", "firmware_version": ver, "image_sha256": img, "sbom": "fw-%s.cdx.json" % slug, "sbom_sha256": SHA_A,
         "inventory": "fw-inventory-%s.json" % slug, "inventory_sha256": SHA_B, "status": "ATTENTION", "expect": "OK"}
    x.update(over)
    return x


def vendor_sbom(slug="dasharo-novacustom-ns5x-tgl-v1.6.0", ver="v1.6.0", **over):
    x = {"slug": slug, "kind": "sbom", "firmware_version": ver, "image_sha256": None, "sbom": "fw-%s.cdx.json" % slug, "sbom_sha256": SHA_A,
         "normalized": True, "inventory": None, "inventory_sha256": None, "status": "ATTENTION", "expect": "NONE"}
    x.update(over)
    return x


TABLES = {"fw_advisory_rules": {"sha256": "c" * 64, "table_updated": "2026-11-14"},
          "intel_microcode": {"source_commit": "d" * 40, "source_tag": "microcode-20261110", "table_sha256": "e" * 64},
          "nvidia_vbios": {"sha256": "f" * 64, "mirror_commit": "9" * 40, "reviewed_until": "2025-09-02"}}


def fw_meta(tag=TAG, samples=None, **over):
    m = {"schema": "dumpling-firmware-meta/1", "tag": tag, "commit": "0" * 40, "built_at": "2026-11-20T03:00:00Z",
         "workflow_run": "https://github.com/%s/actions/runs/4242" % REPO,
         "samples": samples if samples is not None else [bios(), vendor_sbom()], "not_watched": [{"slug": "standalone-nvidia-option-rom", "why": "GAP：沒有檔案"}],
         "tables": TABLES, "dt": {"status": "OK", "result": "OK", "reason": None}}
    m.update(over)
    return m


def fw_release(tag=TAG, meta_obj=None, published="2026-11-20T03:10:00Z", raw=None, size=None, drop_meta=False):
    """→ (rel, files)。meta_obj 的樣本附件名一併上架。"""
    m = meta_obj if meta_obj is not None else fw_meta(tag)
    body = raw if raw is not None else td.j(m)
    files = {} if drop_meta else {"firmware-meta.json": body}
    for x in (m.get("samples") if isinstance(m, dict) and isinstance(m.get("samples"), list) else []):
        if isinstance(x, dict):
            for k in ("sbom", "inventory"):
                if isinstance(x.get(k), str):
                    files[x[k]] = b"{}"
    r = td.rel(tag, names=list(files), published=published, sizes={n: len(v) for n, v in files.items()})
    if size is not None and not drop_meta:
        r["assets"]["firmware-meta.json"][0].size = size
    return r, {(tag, n): v for n, v in files.items()}


def per_row(wv, grype="OK", why=None, exploited=0, advisory="OK", advisory_why=None, reasons=None):
    return {"uuid": uuid_of(wv), "tag": TAG, "layer": "firmware", "grype": grype, "why": why, "report_status": "沒有這一項",
            "release_gate": "沒有這一項", "kernel_map": "沒有這一項", "kernel_cna": "沒有這一項", "exploited": exploited,
            "version_unknown": 0, "kind": "firmware", "advisory": advisory, "advisory_why": advisory_why, "advisory_reasons": reasons or [],
            "image_sha256": IMG}


def plan_with(rows):
    return {"status": "ATTENTION", "detail": "d", "per_sbom": {r["uuid"]: r for r in rows}, "notes": [], "attention": [], "gaps": [], "stats": {}}


def rec(kind="rule", result="affected", review="preliminary", component="ME 18.0.10.2285", bulletins=("INTEL-SA-01315",)):
    return {"kind": kind, "result": result, "bulletins": list(bulletins), "component": component, "review": review, "baseline": False}


def state_issue_api(fw_state):
    st = {"schema": 1, "dumpling": {"baseline_at": "2026-11-15T04:29:16Z", "mode": "real", "issues": {}}, "matches": {}, "vendor_matches": {},
          "runs": [{"at": "2026-11-15T04:29:16Z", "status": "OK", "detail": "d", "run_url": "https://github.com/%s/actions/runs/777" % REPO}]}
    if fw_state is not None:
        st["firmware"] = fw_state
    return td.FakeApi({"watch-state": [td.issue(114, "s", labels=("watch-state",), body=issues.encode_state(st, "real", "summary"))]})


def tables_state(stale=False, status="OK"):
    return {n: dict(t, status=status, stale=stale) for n, t in TABLES.items()}


def env(tc, releases=None, files=None, plan_rows=None, fw_state=None, watch=True, **kw):
    if releases is None:
        r, f = fw_release()
        releases, files = [r], f
    wk = {"plan": plan_with(plan_rows)} if plan_rows is not None else {}
    return td.Env(tc, releases, files, api=state_issue_api(fw_state), watch=watch, watch_kw={**wk, **kw.pop("watch_kw", {})}, **kw)


def fw_html(e):
    h = e.html
    return h[h.index('<section id="firmware">'):h.index('<section id="watch">')]


def text(h):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]*>", "", h))


class TestListing(unittest.TestCase):
    def test_firmware_release_listed_and_not_in_board_rows_or_warning(self):
        r, f = fw_release()
        b, bf = td.release_set()
        e = env(self, [r, b], {**f, **bf})
        self.assertEqual([x["tag"] for x in e.data["releases"]["rows"]], ["demo/v1.0"])          # 板子的版本區沒有韌體
        self.assertEqual(e.data["releases"]["skipped"], [])
        self.assertFalse([w for w in e.data["warnings"] if "不合規則" in w])
        self.assertNotIn("未分類", e.html)
        h = fw_html(e)
        for s in (TAG, "novacustom-v540tu-mtl-v1.0.1", IMG, "dasharo-novacustom-ns5x-tgl-v1.6.0", "bios", "供應商 SBOM", "expect"):
            self.assertIn(s, h)
        t = text(h)
        self.assertIn("樣本是公開的測試資料，不是出貨產品；只監控最新的一個韌體 Release（第一階段示範的限制）", t)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_sample_fields_and_download_links(self):
        e = env(self)
        s = {x["slug"]: x for x in e.data["firmware"]["samples"]}
        b = s["novacustom-v540tu-mtl-v1.0.1"]
        self.assertEqual((b["kind"], b["firmware_version"], b["image_sha256"], b["meta_status"], b["expect"]), ("bios", "v1.0.1", IMG, "ATTENTION", "OK"))
        self.assertEqual(b["watch_version"], wvk("novacustom-v540tu-mtl-v1.0.1", "v1.0.1"))
        self.assertEqual(b["uuid"], uuid_of(b["watch_version"]))
        self.assertIsNone(s["dasharo-novacustom-ns5x-tgl-v1.6.0"]["inventory"])
        h = fw_html(e)
        base = "https://github.com/%s/releases/download/firmware-demo/2026.11.20/" % REPO
        for n in ("fw-novacustom-v540tu-mtl-v1.0.1.cdx.json", "fw-inventory-novacustom-v540tu-mtl-v1.0.1.json", "fw-dasharo-novacustom-ns5x-tgl-v1.6.0.cdx.json"):
            self.assertIn('<a href="%s%s"' % (base, n), h)
        self.assertEqual(h.count("沒有 inventory"), 1)
        for m in re.finditer(r'href="([^"]*)"', h):
            self.assertIsNotNone(render.safe_href(m.group(1).replace("&amp;", "&"), REPO))

    def test_missing_attachment_is_gap_for_that_link_only(self):
        r, f = fw_release()
        del r["assets"]["fw-novacustom-v540tu-mtl-v1.0.1.cdx.json"]
        e = env(self, [r], f)
        h = fw_html(e)
        self.assertIn("Release 沒有這個附件", h)
        self.assertNotIn('releases/download/firmware-demo/2026.11.20/fw-novacustom-v540tu-mtl-v1.0.1.cdx.json"', h)
        self.assertIn("fw-inventory-novacustom-v540tu-mtl-v1.0.1.json", h)

    def test_no_firmware_release(self):
        b, bf = td.release_set()
        e = td.Env(self, [b], bf)
        self.assertIn("沒有韌體 Release（韌體不在監控）", text(fw_html(e)))
        self.assertIsNone(e.data["firmware"]["tag"])
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_releases_api_failure_firmware_is_gap(self):
        e = td.Env(self, [], {}, source=td.FakeSource([], {}, boom=collect.ApiError("HTTP 500")))
        self.assertIn("Releases API 讀不到", text(fw_html(e)))
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_firmware_prerelease_and_draft_are_not_listed_as_firmware(self):
        pre = td.rel("firmware-demo/2026.11.21", prerelease=True)
        dr = td.rel("firmware-demo/2026.11.22", draft=True)
        e = td.Env(self, [pre, dr], {})
        self.assertIsNone(e.data["firmware"]["tag"])
        self.assertEqual(len(e.data["releases"]["skipped"]), 1)         # prerelease 的 firmware-demo 照 collect 是不合規則

    def test_nav_link(self):
        self.assertIn('<a href="#firmware">韌體示範</a>', env(self).html)


class TestLatestOnly(unittest.TestCase):
    def test_latest_by_published_at(self):
        old, fo = fw_release("firmware-demo/2026.11.01", published="2026-11-01T00:00:00Z")
        new, fn = fw_release("firmware-demo/2026.11.20", published="2026-11-20T00:00:00Z")
        mid, fm = fw_release("firmware-demo/2026.12.01", published="2026-11-10T00:00:00Z")      # tag 日期比較新，但發布時間比較舊
        e = env(self, [old, new, mid], {**fo, **fn, **fm})
        fw = e.data["firmware"]
        self.assertEqual(fw["tag"], "firmware-demo/2026.11.20")
        self.assertEqual(sorted(fw["older"]), ["firmware-demo/2026.11.01", "firmware-demo/2026.12.01"])
        h = fw_html(e)
        self.assertIn("舊的韌體 Release（不監控，只留紀錄；2）", h)
        self.assertIn("firmware-demo/2026.12.01", h)

    def test_tie_broken_by_numeric_tag_version(self):
        same = "2026-11-20T03:10:00Z"
        rels, files = [], {}
        for v in ("2026.11.20.2", "2026.11.20.10", "2026.11.20.9"):
            r, f = fw_release("firmware-demo/" + v, published=same)
            rels.append(r)
            files.update(f)
        e = env(self, rels, files)
        self.assertEqual(e.data["firmware"]["tag"], "firmware-demo/2026.11.20.10")         # 字串比較會選 .9
        # 和 collect 同一個選擇
        cands = [(r, "firmware-demo", r["tag"].split("/")[1]) for r in rels]
        cands.sort(key=lambda c: (collect._date(c[0].get("published_at")) or "", collect._ver_key(c[2])), reverse=True)
        self.assertEqual(cands[0][0]["tag"], e.data["firmware"]["tag"])

    def test_only_latest_samples_listed(self):
        old, fo = fw_release("firmware-demo/2026.11.01", meta_obj=fw_meta("firmware-demo/2026.11.01", [bios("old-only-sample", "v0.1")]),
                             published="2026-11-01T00:00:00Z")
        new, fn = fw_release()
        e = env(self, [old, new], {**fo, **fn})
        self.assertNotIn("old-only-sample", e.html)


class TestMetaBad(unittest.TestCase):
    def check_gap(self, e, why=None):
        fw = e.data["firmware"]
        self.assertTrue(fw["meta_gap"])
        self.assertEqual(fw["samples"], [])
        h = fw_html(e)
        t = text(h)
        self.assertIn("整個韌體區無法列出", t)
        self.assertNotIn("<table", h)
        self.assertNotIn("novacustom", h)
        if why:
            self.assertIn(why, fw["meta_gap"])
        self.assertTrue([w for w in e.data["warnings"] if "韌體區" in w])
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_missing_meta(self):
        r, f = fw_release(drop_meta=True)
        self.check_gap(env(self, [r], f), "缺少")

    def test_not_json(self):
        r, f = fw_release(raw=b"{not json")
        self.check_gap(env(self, [r], f), "不是合法 JSON")

    def test_schema_tag_samples_wrong(self):
        for over, why in (({"schema": "x"}, "schema"), ({"tag": "firmware-demo/1999.01.01"}, "tag"), ({"samples": {}}, "samples"),
                          ({"commit": "zz"}, "commit"), ({"not_watched": [{"slug": "a", "why": ""}]}, "why"), ({"tables": []}, "tables"),
                          ({"built_at": 5}, "built_at")):
            r, f = fw_release(meta_obj=fw_meta(**over))
            self.check_gap(env(self, [r], f), why)

    def test_over_1mib(self):
        r, f = fw_release(raw=td.j(fw_meta()) + b" " * (1024 * 1024 + 1))
        self.check_gap(env(self, [r], f), "大小上限")
        r, f = fw_release(size=2 * 1024 * 1024)
        self.check_gap(env(self, [r], f), "超過大小上限")

    def test_duplicate_attachment(self):
        r, f = fw_release()
        r["assets"]["firmware-meta.json"].append(r["assets"]["firmware-meta.json"][0])
        self.check_gap(env(self, [r], f), "同名重複")

    def test_bad_sample_is_gap_only_for_that_sample(self):
        samples = [bios(), bios("bad-one", sbom="wrong.json"), vendor_sbom(), bios(), "not-an-object", bios("Bad Slug!")]
        r, f = fw_release(meta_obj=fw_meta(samples=samples))
        e = env(self, [r], f)
        self.assertIsNone(e.data["firmware"]["meta_gap"])
        gaps = [x for x in e.data["firmware"]["samples"] if x.get("gap")]
        self.assertEqual(len(gaps), 4)             # sbom 檔名不對、slug 重複、不是物件、slug 不合規則
        self.assertTrue(any("slug 重複" in x["gap"] for x in gaps))
        self.assertEqual(sum(1 for x in e.data["firmware"]["samples"] if not x.get("gap")), 2)
        self.assertEqual(check_site.check_html(e.html, REPO), [])


class TestDt(unittest.TestCase):
    def dt_text(self, dt):
        m = fw_meta()
        if dt is not ABSENT:
            m["dt"] = dt
        else:
            del m["dt"]
        r, f = fw_release(meta_obj=m)
        e = env(self, [r], f)
        self.assertEqual(check_site.check_html(e.html, REPO), [])
        h = fw_html(e)
        i = h.index("<p>DT")
        return text(h[i:h.index("</p>", i)]), e

    def test_ok(self):
        t, e = self.dt_text({"status": "OK", "result": "OK", "reason": None})
        self.assertIn("status OK", t)
        self.assertIn("result OK", t)
        self.assertEqual(e.data["firmware"]["dt"]["state"], "ok")

    def test_gap_legal(self):
        for res in ("FAIL", "NOT_RUN"):
            t, e = self.dt_text({"status": "GAP", "result": res, "reason": "dtrack 沒有回應（任意文字）"})
            self.assertIn("status GAP", t)
            self.assertIn("result " + res, t)
            self.assertIn("dtrack 沒有回應（任意文字）", t)
            self.assertEqual(e.data["firmware"]["dt"]["state"], "ok")

    def test_reason_not_fixed_string_only_type_and_length(self):
        self.assertEqual(build.dt_field({"dt": {"status": "GAP", "result": "FAIL", "reason": "x" * 200}})["state"], "ok")
        self.assertEqual(build.dt_field({"dt": {"status": "GAP", "result": "FAIL", "reason": "x" * 201}})["state"], "bad")

    def test_illegal_combinations_show_gap_not_original(self):
        bad = [{"status": "OK", "result": "FAIL", "reason": "r"}, {"status": "GAP", "result": "OK", "reason": None},
               {"status": "OK", "result": "OK", "reason": "有原因"}, {"status": "GAP", "result": "FAIL", "reason": None},
               {"status": "GAP", "result": "NOT_RUN", "reason": ""}, {"status": "GAP", "result": "NOT_RUN", "reason": "   "},
               {"status": "GAP", "result": "FAIL", "reason": 5}, {"status": 1, "result": "OK", "reason": None},
               {"status": "OK", "result": ["OK"], "reason": None}, {"status": "ATTENTION", "result": "FAIL", "reason": "r"},
               {"status": "GAP", "result": "UNKNOWN", "reason": "r"}, {"status": "OK", "result": "OK"}, {"result": "OK", "reason": None},
               "OK", None, [], 5, {}, {"status": "GAP", "result": "FAIL", "reason": "x" * 201}]
        for dt in bad:
            t, e = self.dt_text(dt)
            self.assertIn("GAP（dt 欄位格式不對）", t, dt)
            self.assertEqual(e.data["firmware"]["dt"], {"state": "bad"}, dt)
            self.assertNotIn("有原因", e.html)
            self.assertNotIn("x" * 150, e.html)

    def test_bad_dt_does_not_affect_other_fields(self):
        r, f = fw_release(meta_obj=fw_meta(dt="garbage"))
        e = env(self, [r], f)
        self.assertEqual(len(e.data["firmware"]["samples"]), 2)
        self.assertIsNone(e.data["firmware"]["meta_gap"])

    def test_absent(self):
        t, e = self.dt_text(ABSENT)
        self.assertIn("沒有 DT 結果", t)
        self.assertEqual(e.data["firmware"]["dt"], {"state": "absent"})

    def test_malicious_reason_escaped(self):
        for ev in EVIL:
            r, f = fw_release(meta_obj=fw_meta(dt={"status": "GAP", "result": "FAIL", "reason": ev[:200]}))
            e = env(self, [r], f)
            self.assertEqual(check_site.check_html(e.html, REPO), [], ev[:20])
            self.assertNotIn("<script", e.html)
            self.assertNotIn('"><img', e.html)


ABSENT = object()


class TestNotWatchedAndKeys(unittest.TestCase):
    def test_not_watched_with_source(self):
        samples = [bios(), bios("no-version", ver="TO BE COMPLETED", img=None), bios("sha-key", ver="xx.xx", img=SHA_B)]
        r, f = fw_release(meta_obj=fw_meta(samples=samples))
        e = env(self, [r], f)
        nw = {x["slug"]: x for x in e.data["firmware"]["not_watched"]}
        self.assertEqual(nw["standalone-nvidia-option-rom"]["source"], "meta")
        self.assertEqual(nw["no-version"]["source"], "collect")
        self.assertTrue(nw["no-version"]["why"].startswith("GAP："))
        h = fw_html(e)
        self.assertIn("firmware.yml 依設計不監控", text(h))
        self.assertIn("collect 判定監控不了", text(h))
        self.assertIn("standalone-nvidia-option-rom", h)
        # 版本是佔位字串但有映像雜湊：監控鍵用雜湊、標 GAP（和 collect 的 fw_watch_version 一樣）
        s = {x["slug"]: x for x in e.data["firmware"]["samples"]}
        self.assertEqual(s["sha-key"]["watch_version"], wvk("sha-key", "sha256-" + SHA_B[:16]))
        self.assertTrue(s["sha-key"]["key_gap"])
        self.assertIn(wvk("sha-key", "sha256-" + SHA_B[:16]), h)
        self.assertNotIn("no-version@", h)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_uses_collect_functions(self):
        for v, img in (("v1.0.1", IMG), ("", SHA_B), (None, None), ("0.0", SHA_A), ("unknown", None)):
            wv, why = collect.fw_watch_version("s", v, img)
            r, f = fw_release(meta_obj=fw_meta(samples=[bios("s", v if v is not None else None, img)]))
            e = env(self, [r], f)
            smp = [x for x in e.data["firmware"]["samples"] if x["slug"] == "s"]
            if wv is None:
                self.assertEqual(smp, [])
                self.assertTrue([x for x in e.data["firmware"]["not_watched"] if x["slug"] == "s" and x["source"] == "collect"])
            else:
                self.assertEqual(smp[0]["watch_version"], wv)


class TestDailyAndAdvisory(unittest.TestCase):
    WV1 = wvk("novacustom-v540tu-mtl-v1.0.1", "v1.0.1")
    WV2 = wvk("dasharo-novacustom-ns5x-tgl-v1.6.0", "v1.6.0")

    def rows(self):
        return [per_row(self.WV1, grype="NOT_ASSESSED（可比對元件 0：沒有 purl／CPE）", exploited=0, advisory="ATTENTION",
                        advisory_why=None, reasons=["規則表建議 affected：1 個元件（規則 INTEL-SA-01315），待人審"]),
                per_row(self.WV2, grype="OK", exploited=3, advisory="NOT_ASSESSED（沒有 inventory，不重跑公告比對）")]

    def state(self, **over):
        fw = {"tables": tables_state(), "samples": {uuid_of(self.WV1): {"image_sha256": IMG, "image_sha256_history": [],
                                                                         "advisory": {"rule:intel_csme:e915ed1eae8b7b91:me=18.0.10.2285": rec()}}}}
        fw.update(over)
        return fw

    def test_advisory_status_and_why_shown_next_to_numbers(self):
        e = env(self, plan_rows=self.rows(), fw_state=self.state())
        h = fw_html(e)
        t = text(h)
        self.assertIn("NOT_ASSESSED （可比對元件 0：沒有 purl／CPE）", t)
        self.assertIn("NOT_ASSESSED （沒有 inventory，不重跑公告比對）", t)
        self.assertNotIn("不明", t)                           # 帶說明的狀態不會被當成不認得的狀態值
        self.assertEqual([w for w in e.data["warnings"] if "狀態值不認得" in w], [])
        self.assertNotIn("狀態值不認得", e.html)
        # KEV 命中數一定和 grype 狀態在同一格
        for m in re.finditer(r'<div class="vcell"><div class="vnum">([^<]*)</div><div class="vstat">(.*?)</div></div>', h):
            self.assertIn("grype", m.group(2))
            self.assertRegex(m.group(2), r'class="st st-')
        self.assertIn('<div class="vnum">3</div>', h)
        self.assertIn("公告比對 ", t)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_not_run_gap_not_assessed_shown_as_is(self):
        rows = [per_row(self.WV1, advisory="NOT_RUN", advisory_why="沒有 rematch-summary.json"),
                per_row(self.WV2, advisory="GAP", advisory_why="公告重跑讀不了 firmware-meta.json")]
        e = env(self, plan_rows=rows, fw_state=self.state())
        h = fw_html(e)
        self.assertIn('<span class="st st-NOT_RUN">NOT_RUN</span>', h)
        self.assertIn('<span class="st st-GAP">GAP</span>', h)
        self.assertIn("沒有 rematch-summary.json", h)
        self.assertIn('<span class="st st-NOT_ASSESSED">NOT_ASSESSED</span>', fw_html(env(self, plan_rows=self.rows(), fw_state=self.state())))

    def test_generic_per_sbom_table_excludes_firmware_rows(self):
        rows = self.rows()
        plan = plan_with(rows)
        plan["per_sbom"]["u1"] = {"uuid": "u1", "tag": "demo/v1.0", "layer": "bsp", "grype": "OK", "why": None, "report_status": "GAP",
                                  "release_gate": "GAP", "kernel_map": "OK", "exploited": 5, "kernel_cna": "OK"}
        e = env(self, watch_kw={"plan": plan}, fw_state=self.state())
        w = e.html[e.html.index('<section id="watch">'):]
        self.assertIn("demo/v1.0", w)
        self.assertNotIn("沒有這一項", e.html)
        self.assertIn("韌體樣本（2 列）不在這張表", w)

    def test_no_row_for_sample_is_gap(self):
        e = env(self, plan_rows=[self.rows()[0]], fw_state=self.state())
        self.assertIn("最近一輪沒有這份樣本的監控紀錄", text(fw_html(e)))

    def test_no_watch_dir_is_gap(self):
        e = env(self, watch=False)
        t = text(fw_html(e))
        self.assertIn("每日比對結果（watch-plan result.json）", t)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_all_four_wordings_once_and_every_affected_has_wording(self):
        samples = [bios(), bios("sample-two", "v2"), bios("sample-three", "v3"), bios("sample-four", "v4")]
        r, f = fw_release(meta_obj=fw_meta(samples=samples))
        recs = {wvk("novacustom-v540tu-mtl-v1.0.1", "v1.0.1"): rec("rule", "affected", "preliminary"),
                wvk("sample-two", "v2"): rec("rule", "affected", "confirmed"),
                wvk("sample-three", "v3"): rec("intel-microcode", "affected-candidate", None, "microcode 0x1", ("INTEL-SA-1", "INTEL-SA-2")),
                wvk("sample-four", "v4"): rec("nvidia-vbios", "affected", None, "vBIOS 95.07", ("NVIDIA-1",))}
        rows = [per_row(wv, advisory="ATTENTION", reasons=["元件 affected 的說明"]) for wv in recs]
        fw = {"tables": tables_state(), "samples": {uuid_of(wv): {"image_sha256": None, "image_sha256_history": [], "advisory": {"k%d" % i: rc}}
                                                    for i, (wv, rc) in enumerate(recs.items())}}
        e = env(self, [r], f, plan_rows=rows, fw_state=fw)
        h = fw_html(e)
        for w in WORDS:
            self.assertEqual(text(h).count(w), 2, w)       # 每個用語各出現在 reasons 旁與公告結果旁（同一列）
        self.assertEqual(sorted(x["word"] for l in e.data["firmware"]["daily"]["state"]["advisory"].values() for x in l["recs"]), sorted(WORDS))
        for cell in re.findall(r"<td>(.*?)</td>", h, re.S):
            if re.search(r"affected|受影響|candidate", text(cell), re.I):
                self.assertTrue(any(w in text(cell) for w in WORDS), text(cell)[:200])
        # 用語取自 match.py 的常數，不是寫死
        self.assertEqual(match.FW_WORD_PRELIM, "建議受影響（初步規則，待人審）")
        self.assertEqual(match.FW_WORD_UCODE, "版本比較的候選，待人審")
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_missing_wording_is_gap_not_bare_affected(self):
        e = env(self, plan_rows=self.rows(), fw_state=self.state())
        e.data["firmware"]["daily"]["state"]["advisory"][uuid_of(self.WV1)]["recs"][0]["word"] = None
        h = render.render(e.data)
        h = h[h.index('<section id="firmware">'):h.index('<section id="watch">')]
        self.assertIn("用語缺少", text(h))

    def test_reasons_mention_affected_without_state_record_is_gap(self):
        e = env(self, plan_rows=self.rows(), fw_state=self.state(samples={}))
        t = text(fw_html(e))
        self.assertIn("無法附上用語", t)
        e2 = env(self, plan_rows=self.rows(), fw_state=None)
        self.assertIn("無法附上用語", text(fw_html(e2)))

    def test_state_without_firmware_is_gap(self):
        e = env(self, plan_rows=self.rows(), fw_state=None)
        self.assertIn("沒有 firmware 欄位", text(fw_html(e)))
        api = td.FakeApi({"watch-state": []})
        e = td.Env(self, *map(lambda z: z, (lambda r, f: ([r], f))(*fw_release())), api=api, watch_kw={"plan": plan_with(self.rows())})
        self.assertIn("沒有 watch-state 標籤的 Issue", text(fw_html(e)))

    def test_state_records_whitelisted(self):
        fw = self.state()
        fw["samples"][uuid_of(self.WV1)]["advisory"]["bad1"] = {"kind": "zzz", "result": "affected", "bulletins": []}
        fw["samples"][uuid_of(self.WV1)]["advisory"]["bad2"] = "str"
        fw["samples"]["not-a-uuid"] = {"advisory": {"k": rec()}}
        e = env(self, plan_rows=self.rows(), fw_state=fw)
        recs = e.data["firmware"]["daily"]["state"]["advisory"]
        self.assertEqual(list(recs), [uuid_of(self.WV1)])
        self.assertEqual(len(recs[uuid_of(self.WV1)]["recs"]), 1)
        self.assertEqual(recs[uuid_of(self.WV1)]["bad"], 2)             # 丟掉的筆數要記下來，頁面寫 GAP
        self.assertEqual(e.data["firmware"]["daily"]["state"]["bad_unattributed"], 1)
        t = text(fw_html(e))
        self.assertIn("狀態裡有 2 筆紀錄格式不對（不顯示）", t)
        self.assertIn("狀態裡有 1 筆樣本條目格式不對（不顯示）", t)


class TestTables(unittest.TestCase):
    def fw_state(self, stale=False, status="OK", **over):
        fw = {"tables": tables_state(stale, status), "samples": {}}
        fw.update(over)
        return fw

    def test_identity_status_stale_listed(self):
        e = env(self, plan_rows=[], fw_state=self.fw_state())
        h = fw_html(e)
        t = text(h)
        for s in ("fw_advisory_rules", "intel_microcode", "nvidia_vbios", "c" * 64, "microcode-20261110", "reviewed_until：2025-09-02", "stale", "status"):
            self.assertIn(s, t)
        self.assertNotIn("對照表過期", t)
        self.assertEqual(h.count("否（stale false）"), 3)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_stale_marked(self):
        st = self.fw_state()
        st["tables"]["nvidia_vbios"]["stale"] = True
        e = env(self, plan_rows=[], fw_state=st)
        h = fw_html(e)
        self.assertEqual(h.count("對照表過期"), 1)
        self.assertTrue([w for w in e.data["warnings"] if "過期" in w and "nvidia_vbios" in w])
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_table_status_gap_shown_as_is(self):
        e = env(self, plan_rows=[], fw_state=self.fw_state(status="GAP"))
        h = fw_html(e)
        self.assertEqual(h[h.index("<h4>對照表</h4>"):].count('<span class="st st-GAP">GAP</span>'), 3)

    def test_stale_missing_or_not_bool_is_gap(self):
        st = self.fw_state()
        del st["tables"]["intel_microcode"]["stale"]
        del st["tables"]["nvidia_vbios"]
        e = env(self, plan_rows=[], fw_state=st)
        t = text(fw_html(e))
        self.assertIn("狀態裡沒有 stale", t)
        self.assertIn("狀態裡沒有這張表", t)

    def test_state_gap_shown_for_tables(self):
        e = env(self, plan_rows=[], fw_state=None)
        self.assertIn("狀態 Issue 的內容沒有 firmware 欄位", text(fw_html(e)))
        self.assertIn("c" * 64, fw_html(e))           # Release 當時的識別仍然列出

    def test_size_stopped_at(self):
        e = env(self, plan_rows=[], fw_state=self.fw_state(size_stopped_at="2026-11-15T04:00:00Z"))
        t = text(fw_html(e))
        self.assertIn("韌體因狀態大小上限停止（2026-11-15T04:00:00Z）", t)
        self.assertTrue([w for w in e.data["warnings"] if "韌體因狀態大小上限停止" in w])
        e2 = env(self, plan_rows=[], fw_state=self.fw_state())
        self.assertNotIn("韌體因狀態大小上限停止", text(fw_html(e2)))
        self.assertEqual(check_site.check_html(e.html, REPO), [])


def cells(h):
    return re.findall(r"<td>(.*?)</td>", h, re.S)


def big_state(n_recs, n_bullets, wv=None):
    wv = wv or wvk("novacustom-v540tu-mtl-v1.0.1", "v1.0.1")
    adv = {"k%03d" % i: rec("intel-microcode", "affected-candidate", None, "ucode %d" % i, ["INTEL-SA-%05d-%d" % (j, i) for j in range(n_bullets)])
           for i in range(n_recs)}
    return {"tables": tables_state(), "samples": {uuid_of(wv): {"image_sha256": None, "image_sha256_history": [], "advisory": adv}}}


class TestLimitsNoSilentTruncation(unittest.TestCase):
    def test_limits_come_from_match(self):
        self.assertEqual((match.FW_MAX_AFFECTED, match.REMATCH_MAX_BULLETINS, match.REMATCH_MAX_BULLETIN_CHARS), (100, 64, 80))

    def rows(self):
        return [per_row(wvk("novacustom-v540tu-mtl-v1.0.1", "v1.0.1"), advisory="ATTENTION")]

    def test_at_limit_everything_shown(self):
        e = env(self, plan_rows=self.rows(), fw_state=big_state(match.FW_MAX_AFFECTED, match.REMATCH_MAX_BULLETINS))
        h = fw_html(e)
        t = text(h)
        self.assertEqual(len(re.findall(r"ucode \d+", t)), match.FW_MAX_AFFECTED)
        self.assertEqual(len(re.findall(r"INTEL-SA-\d{5}-\d+", t)), 100 * 64)         # 100 筆、每筆 64 個公告：全部都在
        self.assertIn("INTEL-SA-00063-99", t)
        self.assertNotIn("只列前", t)
        self.assertEqual(e.data["firmware"]["daily"]["state"]["advisory"][uuid_of(wvk("novacustom-v540tu-mtl-v1.0.1", "v1.0.1"))]["total"], 100)
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_over_limit_records_gap_with_total(self):
        e = env(self, plan_rows=self.rows(), fw_state=big_state(match.FW_MAX_AFFECTED + 1, 1))
        t = text(fw_html(e))
        self.assertIn("GAP（只列前 100 筆，共 101 筆）", t)
        self.assertEqual(len(re.findall(r"ucode \d+", t)), 100)

    def test_over_limit_bulletins_gap_with_total(self):
        e = env(self, plan_rows=self.rows(), fw_state=big_state(1, match.REMATCH_MAX_BULLETINS + 1))
        t = text(fw_html(e))
        self.assertIn("GAP（公告只列前 64 個，共 65 個）", t)
        self.assertEqual(len(re.findall(r"INTEL-SA-\d{5}-0", t)), 64)

    def test_bulletin_id_chars_limit(self):
        ok = "A" * match.REMATCH_MAX_BULLETIN_CHARS
        fw = big_state(1, 0)
        next(iter(fw["samples"].values()))["advisory"]["k000"]["bulletins"] = [ok]
        e = env(self, plan_rows=self.rows(), fw_state=fw)
        self.assertIn(ok, fw_html(e))                      # 80 字的 ID 完整顯示（以前截成 60）


class TestStateEntries(unittest.TestCase):
    WV1 = wvk("novacustom-v540tu-mtl-v1.0.1", "v1.0.1")

    def test_missing_entry_is_gap_but_empty_entry_is_not(self):
        fw = {"tables": tables_state(), "samples": {uuid_of(self.WV1): {"advisory": {}}}}
        rows = [per_row(self.WV1), per_row(wvk("dasharo-novacustom-ns5x-tgl-v1.6.0", "v1.6.0"), advisory="NOT_ASSESSED（沒有 inventory，不重跑公告比對）")]
        e = env(self, plan_rows=rows, fw_state=fw)
        c = cells(fw_html(e))
        daily = [x for x in c if "grype" in text(x)]
        recs_cells = [c[i + 2] for i, x in enumerate(c) if x in daily]
        self.assertIn("沒有這份樣本的 affected 紀錄", text(recs_cells[0]))
        self.assertNotIn("沒有這份樣本的條目", text(recs_cells[0]))
        self.assertIn("狀態裡沒有這份樣本的條目", text(recs_cells[1]))

    def test_bad_records_counted(self):
        fw = {"tables": tables_state(), "samples": {uuid_of(self.WV1): {"advisory": {
            "a": rec(), "b": {"kind": "zzz", "result": "affected", "bulletins": []}, "c": {"kind": "rule", "result": 5, "bulletins": []},
            "d": {"kind": "rule", "result": "affected", "bulletins": "x"}, "e": 7}}}}
        e = env(self, plan_rows=[per_row(self.WV1)], fw_state=fw)
        self.assertEqual(e.data["firmware"]["daily"]["state"]["advisory"][uuid_of(self.WV1)]["bad"], 4)
        self.assertIn("狀態裡有 4 筆紀錄格式不對（不顯示）", text(fw_html(e)))

    def test_bad_uuid_entries_counted(self):
        fw = {"tables": tables_state(), "samples": {"nope": {"advisory": {}}, uuid_of(self.WV1): "str"}}
        e = env(self, plan_rows=[per_row(self.WV1)], fw_state=fw)
        self.assertIn("狀態裡有 2 筆樣本條目格式不對（不顯示）", text(fw_html(e)))

    def test_records_column_shows_state_gap(self):
        e = env(self, plan_rows=[per_row(self.WV1)], fw_state=None)
        h = fw_html(e)
        sec = h[h.index("<h4>每日監控（最近一輪）</h4>"):h.index("<h4>不監控的項目</h4>")]
        rows = re.findall(r"<tr>(.*?)</tr>", sec, re.S)[1:]
        self.assertTrue(rows)
        for r in rows:
            last = cells(r)[-1]
            self.assertIn("狀態 Issue 的內容沒有 firmware 欄位", text(last))


class TestOrphanRows(unittest.TestCase):
    WV1 = wvk("novacustom-v540tu-mtl-v1.0.1", "v1.0.1")

    def board_plan(self, rows):
        plan = plan_with(rows)
        plan["per_sbom"]["u1"] = {"uuid": "u1", "tag": "demo/v1.0", "layer": "bsp", "grype": "OK", "why": None, "report_status": "GAP",
                                  "release_gate": "GAP", "kernel_map": "OK", "exploited": 5, "kernel_cna": "OK"}
        return plan

    def test_row_not_in_samples_is_listed(self):
        orphan = per_row(wvk("old-sample", "v0.9"), grype="ATTENTION", exploited=7, advisory="OK")
        rows = [per_row(self.WV1), orphan]
        e = env(self, fw_state={"tables": tables_state(), "samples": {}}, watch_kw={"plan": self.board_plan(rows)})
        h = fw_html(e)
        t = text(h)
        self.assertIn("每日結果裡有、但最新韌體 Release 的樣本沒有的列", t)
        self.assertIn("dumpling:firmware-demo/" + wvk("old-sample", "v0.9") + "#firmware", t)
        self.assertIn("不在最新的韌體 Release 樣本裡（可能是舊 Release 或新 tag 還沒跑過監控）", t)
        i = h.index("每日結果裡有、但最新韌體 Release 的樣本沒有的列")
        sec = h[i:]
        self.assertIn('<div class="vnum">7</div>', sec)
        self.assertRegex(sec, r'grype <span class="st st-ATTENTION">ATTENTION</span>')
        self.assertEqual(check_site.check_html(e.html, REPO), [])

    def test_count_in_board_note_matches_firmware_section(self):
        wv2 = wvk("dasharo-novacustom-ns5x-tgl-v1.6.0", "v1.6.0")
        rows = [per_row(self.WV1), per_row(wv2), per_row(wvk("old-a", "1")), per_row(wvk("old-b", "2"), exploited=9)]
        plan = self.board_plan(rows)
        e = env(self, fw_state={"tables": tables_state(), "samples": {}}, watch_kw={"plan": plan})
        w = e.html[e.html.index('<section id="watch">'):]
        n = int(re.search(r"韌體樣本（(\d+) 列）不在這張表", text(w)).group(1))
        h = fw_html(e)
        self.assertEqual(n, 4)
        shown = len(re.findall(r'<div class="vnum">', h))
        self.assertEqual(shown, n)                                          # 韌體區實際顯示的列數
        self.assertIn("每日結果的韌體列共 4 列，全部列在上面（對到樣本 2 列、對不到 2 列）", text(h))

    def test_duplicate_uuid_row_not_dropped(self):
        rows = [per_row(self.WV1, exploited=1), per_row(self.WV1, exploited=2)]
        plan = plan_with(rows[:1])
        plan["per_sbom"]["dup"] = rows[1]
        e = env(self, fw_state={"tables": tables_state(), "samples": {}}, watch_kw={"plan": plan})
        h = fw_html(e)
        self.assertIn('<div class="vnum">1</div>', h)
        self.assertIn('<div class="vnum">2</div>', h)
        self.assertIn("uuid 和前一列重複", text(h))

    def test_state_only_records_listed(self):
        fw = {"tables": tables_state(), "samples": {uuid_of(wvk("gone", "v1")): {"advisory": {"k": rec()}}}}
        e = env(self, plan_rows=[per_row(self.WV1)], fw_state=fw)
        t = text(fw_html(e))
        self.assertIn(uuid_of(wvk("gone", "v1")), t)
        self.assertIn(match.FW_WORD_PRELIM, t)
        self.assertIn("最近一輪沒有這個監控鍵的每日結果", t)


class TestWordingScanWholeCell(unittest.TestCase):
    WV1 = wvk("novacustom-v540tu-mtl-v1.0.1", "v1.0.1")

    def cell_with(self, h, needle):
        found = [x for x in cells(h) if needle in text(x)]
        self.assertEqual(len(found), 1, needle)
        return text(found[0])

    def test_each_text_field_mention_needs_wording_or_gap(self):
        for field, val, marker in (("grype", "NOT_ASSESSED（QA1 affected）", "QA1"), ("why", "QA2 candidate", "QA2"), ("advisory_why", "QA3 受影響", "QA3"),
                                   ("advisory", "ATTENTION（QA4 affected）", "QA4"), ("reasons", ["QA5 affected"], "QA5")):
            kw = {"reasons": val} if field == "reasons" else {field: val}
            row = per_row(self.WV1, **kw)
            # 沒有狀態紀錄：同一格要有 GAP
            e = env(self, plan_rows=[row], fw_state={"tables": tables_state(), "samples": {}})
            self.assertIn("無法附上用語", self.cell_with(fw_html(e), marker), field)
            # 有狀態紀錄：同一格要有用語
            fw = {"tables": tables_state(), "samples": {uuid_of(self.WV1): {"advisory": {"k": rec()}}}}
            e = env(self, plan_rows=[row], fw_state=fw)
            self.assertIn(match.FW_WORD_PRELIM, self.cell_with(fw_html(e), marker), field)

    def test_no_mention_no_note(self):
        e = env(self, plan_rows=[per_row(self.WV1)], fw_state={"tables": tables_state(), "samples": {uuid_of(self.WV1): {"advisory": {}}}})
        self.assertNotIn("無法附上用語", e.html)


class TestSharedPick(unittest.TestCase):
    def test_pick_latest_firmware_function(self):
        mk = lambda tag, pub: ({"tag": tag, "published_at": pub}, "firmware-demo", tag.split("/")[1])
        a, b, c = mk("firmware-demo/2026.11.20.2", "2026-11-20T00:00:00Z"), mk("firmware-demo/2026.11.20.10", "2026-11-20T00:00:00Z"), mk("firmware-demo/2026.12.01", "2026-11-01T00:00:00Z")
        latest, others = collect.pick_latest_firmware([a, c, b])
        self.assertIs(latest, b)
        self.assertEqual([x[0]["tag"] for x in others], ["firmware-demo/2026.11.20.2", "firmware-demo/2026.12.01"])
        self.assertEqual(collect.pick_latest_firmware([]), (None, []))

    def test_dashboard_uses_the_shared_function(self):
        from unittest import mock
        r1, f1 = fw_release("firmware-demo/2026.11.01", published="2026-11-01T00:00:00Z")
        r2, f2 = fw_release("firmware-demo/2026.11.20", published="2026-11-20T00:00:00Z")
        with mock.patch.object(collect, "pick_latest_firmware", side_effect=lambda cands: (cands[0], cands[1:])):
            e = env(self, [r1, r2], {**f1, **f2})
        self.assertEqual(e.data["firmware"]["tag"], "firmware-demo/2026.11.01")        # 選取真的由共用函式決定


class TestWordConsistency(unittest.TestCase):
    def test_fw_word_matches_match_fw_wording(self):
        for kind, review in (("rule", "preliminary"), ("rule", None), ("rule", "confirmed"), ("nvidia-vbios", None)):
            self.assertEqual(build.fw_word(match, kind, review), match.fw_wording([{"kind": kind, "review": review}]), (kind, review))
        self.assertEqual(build.fw_word(match, "intel-microcode", None), match.FW_WORD_UCODE)


class TestStatusTextEvil(unittest.TestCase):
    def test_status_with_note_is_escaped(self):
        wv = wvk("novacustom-v540tu-mtl-v1.0.1", "v1.0.1")
        for ev in EVIL:
            rows = [per_row(wv, grype="NOT_ASSESSED（%s）" % ev, advisory="ATTENTION（%s）" % ev, advisory_why=ev, why=ev)]
            e = env(self, plan_rows=rows, fw_state=None)
            h = e.html
            self.assertEqual(check_site.check_html(h, REPO), [], ev[:30])
            self.assertNotIn("<script", h.lower())
            self.assertNotIn('"><img', h)
            self.assertNotIn("A" * 1000, h)


class TestSmallGaps(unittest.TestCase):
    def test_duplicate_attachment_name_link_is_gap(self):
        r, f = fw_release()
        n = "fw-novacustom-v540tu-mtl-v1.0.1.cdx.json"
        r["assets"][n].append(r["assets"][n][0])
        e = env(self, [r], f)
        h = fw_html(e)
        self.assertIn("Release 沒有這個附件（或同名重複）", text(h))
        self.assertNotIn('releases/download/firmware-demo/2026.11.20/%s"' % n, h)

    def test_sample_without_status_shows_gap(self):
        x = bios()
        del x["status"]
        r, f = fw_release(meta_obj=fw_meta(samples=[x]))
        e = env(self, [r], f)
        self.assertIn("meta 沒有 status", text(fw_html(e)))
        self.assertEqual(check_site.check_html(e.html, REPO), [])


class TestMalicious(unittest.TestCase):
    def test_everywhere(self):
        for ev in EVIL:
            slug = "a" + "".join(ch for ch in ev.lower() if ch.isalnum() or ch in ".-")[:40]
            m = fw_meta(samples=[bios(slug, "v1"), vendor_sbom()], not_watched=[{"slug": "x-slug", "why": ev}],
                        tables={"fw_advisory_rules": {"sha256": ev, "table_updated": ev}, "intel_microcode": {"source_tag": ev}, "nvidia_vbios": {"reviewed_until": ev}},
                        built_at=ev, workflow_run=ev, dt={"status": "GAP", "result": "FAIL", "reason": ev[:200]})
            r, f = fw_release(meta_obj=m)
            wv = wvk(slug, "v1")
            rows = [per_row(wv, grype=ev, why=ev, advisory=ev, advisory_why=ev, reasons=[ev, "affected " + ev], exploited=ev)]
            st = {"tables": {"fw_advisory_rules": {"sha256": ev, "status": ev, "stale": True}, "intel_microcode": {"source_tag": ev, "status": "OK", "stale": False}},
                  "size_stopped_at": ev,
                  "samples": {uuid_of(wv): {"advisory": {ev[:100] or "k": {"kind": "rule", "result": ev, "bulletins": [ev], "component": ev, "review": ev}}}}}
            e = env(self, [r], f, plan_rows=rows, fw_state=st)
            h = e.html
            self.assertEqual(check_site.check_html(h, REPO), [], ev[:30])
            self.assertNotIn("<script", h.lower())
            self.assertNotIn("<img", h.lower())
            self.assertNotIn('"><img', h)
            self.assertNotIn("A" * 1000, h)
            self.assertNotRegex(h, r"[\x00-\x08\x0b-\x1f‮]")
            self.assertNotIn("javascript:", re.sub(r'<span class="ext">.*?</span>', "", h, flags=re.S))

    def test_evil_slug_cannot_be_a_listed_sample(self):
        r, f = fw_release(meta_obj=fw_meta(samples=[bios("<script>alert(1)</script>")]))
        e = env(self, [r], f)
        self.assertIn("slug 不合規則", e.html)
        self.assertNotIn("<script>alert", e.html)

    def test_evil_tag_and_attachment_names(self):
        r, f = fw_release("firmware-demo/2026.11.20")
        r["assets"]["fw-<x>.json"] = r["assets"]["fw-novacustom-v540tu-mtl-v1.0.1.cdx.json"]
        e = env(self, [r], f)
        self.assertEqual(check_site.check_html(e.html, REPO), [])


class TestExample(unittest.TestCase):
    @unittest.skipUnless(os.path.isfile(EXAMPLE), "沒有 C2 的範例檔（pipeline/watch/tests/data/firmware-meta.example.json）")
    def test_example_meta_renders(self):
        with open(EXAMPLE, "rb") as fh:
            raw = fh.read()
        m = json.loads(raw)
        r, f = fw_release(m["tag"], meta_obj=m, raw=raw)
        e = env(self, [r], f)
        fw = e.data["firmware"]
        self.assertIsNone(fw["meta_gap"], fw["meta_gap"])
        self.assertEqual(len(fw["samples"]), len(m["samples"]))
        self.assertEqual({x["slug"] for x in fw["not_watched"]}, {x["slug"] for x in m["not_watched"]})
        self.assertEqual(fw["dt"]["state"], "ok" if "dt" in m else "absent")
        self.assertEqual(set(fw["meta_tables"]), set(m["tables"]))
        self.assertEqual(check_site.check_html(e.html, REPO), [])


class TestTriggerFirmware(unittest.TestCase):
    def go(self, event):
        return trigger.decide("workflow_run", event, REPO, "refs/heads/main")[0]

    def test_tag_push_updates(self):
        for tag in ("firmware-demo/2026.11.20", "firmware-demo/2026.11.20.2", "firmware-demo/v1"):
            self.assertTrue(self.go(td.wr("firmware", "push", tag)), tag)
            self.assertEqual(collect.classify(tag, False)[0], "firmware")

    def test_pr_dispatch_schedule_skipped(self):
        for ev in ("pull_request", "workflow_dispatch", "schedule", "pull_request_target", None, "workflow_run"):
            self.assertFalse(self.go(td.wr("firmware", ev, "firmware-demo/2026.11.20")), ev)
        self.assertFalse(self.go(td.wr("firmware", "pull_request", "wp3/fw-release")))

    def test_fork_skipped(self):
        self.assertFalse(self.go(td.wr("firmware", "push", "firmware-demo/2026.11.20", repo="evil/demo")))
        self.assertFalse(self.go(td.wr("firmware", "push", "firmware-demo/2026.11.20", repo=REPO + "x")))
        e = td.wr("firmware", "push", "firmware-demo/2026.11.20")
        del e["workflow_run"]["head_repository"]
        self.assertFalse(self.go(e))

    def test_cancelled_skipped_failure_updates(self):
        self.assertFalse(self.go(td.wr("firmware", "push", "firmware-demo/2026.11.20", conclusion="cancelled")))
        self.assertTrue(self.go(td.wr("firmware", "push", "firmware-demo/2026.11.20", conclusion="failure")))

    def test_branch_not_firmware_tag_skipped(self):
        for br in ("main", "feature/x", "dev/orin-nano-demo", "orin-nano-demo/v39.2.1-demo1", "firmware-demo/", "firmware-demo", "firmware-demo/a/b",
                   "firmware-demo/bad version", "", None, "firmware/2026.11.20", "wp3/fw-release"):
            self.assertFalse(self.go(td.wr("firmware", "push", br)), br)

    def test_uses_collect_classify(self):
        for tag in ("firmware-demo/2026.11.20", "firmware-demo/", "x/y", "orin-nano-demo/v1", "dev/x", "firmware-demo/-bad", "firmware-demo/" + "a" * 70):
            self.assertEqual(self.go(td.wr("firmware", "push", tag)), collect.classify(tag, False)[0] == "firmware", tag)

    def test_firmware_tag_does_not_trigger_via_release_workflow_name(self):
        for tag in ("firmware-demo/2026.11.20", "firmware-demo/v1.0"):          # v 開頭的版本也不能走 release 的規則（那會讓 release 規則接受 firmware tag）
            self.assertFalse(self.go(td.wr("release", "push", tag)), tag)

    def test_reason_fixed_strings(self):
        for ev, br in (("push", "firmware-demo/2026.11.20"), ("pull_request", "x"), ("push", "main")):
            reason = trigger.decide("workflow_run", td.wr("firmware", ev, br + "<script>"), REPO, "")[1]
            self.assertNotIn("script", reason)

    def test_pages_yml_lists_firmware_workflow(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", ".github", "workflows", "pages.yml")
        with open(path, encoding="utf-8") as fh:
            y = fh.read()
        m = re.search(r"^\s*workflows:\s*\[([^\]]*)\]", y, re.M)
        self.assertEqual([x.strip() for x in m.group(1).split(",")], ["watch", "dev", "release", "firmware"])
        self.assertIn("github.event.workflow_run.head_repository.full_name == github.repository", y)
        self.assertIn("github.event.workflow_run.conclusion != 'cancelled'", y)


if __name__ == "__main__":
    unittest.main()


class PerSbomCap(unittest.TestCase):
    def test_over_200_rows_is_gap_not_silent(self):
        row = {"uuid": "u1", "tag": "demo/v1.0", "layer": "bsp", "grype": "OK", "report_status": "GAP", "release_gate": "GAP",
               "kernel_map": "OK", "exploited": 1, "kernel_cna": "OK"}
        plan = {"per_sbom": [row], "per_sbom_cut": 5}
        ctx = render.Ctx(REPO)
        html = render.render_per_sbom(ctx, plan)
        self.assertIn("另有 5 份沒有列出", html)
        self.assertNotIn("另有", render.render_per_sbom(render.Ctx(REPO), {"per_sbom": [row], "per_sbom_cut": 0}))

    def test_only_firmware_rows_early_return_still_shows_cut(self):
        """全部是韌體列時 render_per_sbom 提前 return：截斷說明也要在。"""
        html = render.render_per_sbom(render.Ctx(REPO), {"per_sbom": [{"uuid": "u", "fw": True}], "per_sbom_cut": 3})
        self.assertIn("另有 3 份沒有列出", html)

    def test_firmware_daily_cut_is_gap_not_all_listed(self):
        fw = {"daily": {"rows": [], "state": {"gap": "x"}, "per_sbom_cut": 3, "per_sbom_read": 200}, "samples": []}
        html = render.render_fw_daily(render.Ctx(REPO), fw)
        self.assertIn("共 203 份，只讀了前 200 份，另有 3 份沒有讀", html)
        self.assertNotIn("全部列在上面", html)
        fw["daily"]["per_sbom_cut"] = 0
        self.assertIn("全部列在上面", render.render_fw_daily(render.Ctx(REPO), fw))

    def test_state_samples_over_cap_is_gap(self):
        fw = {"daily": {"rows": [], "state": {"advisory": {}, "samples_read": 200, "samples_total": 250}, "per_sbom_cut": 0}, "samples": []}
        self.assertIn("只讀狀態裡前 200 個樣本條目，共 250 個", render.render_fw_daily(render.Ctx(REPO), fw))


class OlderReleasesCap(unittest.TestCase):
    def test_older_over_50_says_gap_with_total(self):
        older = ["firmware-demo/2026.01.%02d" % i for i in range(1, 51)]
        data = {"firmware": {"gap": None, "tag": "firmware-demo/2026.11.20", "older": older, "older_total": 73, "meta_gap": "x"}}
        html = render.render_firmware(render.Ctx(REPO), data)
        self.assertIn("只列前 50 筆，共 73 筆", html)
        data["firmware"]["older_total"] = 50
        self.assertNotIn("只列前", render.render_firmware(render.Ctx(REPO), data))

    def test_build_older_total_is_real_count(self):
        """build 的 older_total 是實際份數，不是截斷後的（截斷後的數字會讓上面的 GAP 說明消失）。"""
        cands = [({"tag": "firmware-demo/2026.01.%02d" % i, "published_at": "2026-01-%02dT00:00:00Z" % i, "assets": {}},
                  "firmware-demo", "2026.01.%02d" % i) for i in range(1, 62)]
        fw = build.gather_firmware(td.collect, td.FakeSource([], {}), cands, True)
        self.assertEqual(fw["older_total"], 60)
        self.assertEqual(len(fw["older"]), build.FW_OLDER_MAX)

