"""pipeline/lib/previous_release.py（S4 接線）：前一個正式 Release 的選法、附件下載與 zip 檢查、依層組資料夾、狀態（OK／NOT_RUN／GAP）、
和精靈（previous_from_env）與 report_package（--csaf-previous）的銜接。GitHub 用替身（函式）或本機 HTTP 伺服器，附件是合成的；不連網。"""
import hashlib
import http.server
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import warnings
import zipfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
LIB = os.path.join(ROOT, "pipeline", "lib")
sys.path.insert(0, LIB)
import previous_release as pr  # noqa: E402
import step_rows as sr  # noqa: E402

SCRIPT = os.path.join(LIB, "previous_release.py")
WIZ = os.path.join(ROOT, "tools", "wizard", "cra-scan.py")
PROJ = "acme-board"
TAG_ENV = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF_TYPE": "tag", "GITHUB_REPOSITORY": "example-org/example-repo"}


def tag_env(version):
    return dict(TAG_ENV, GITHUB_REF="refs/tags/%s/%s" % (PROJ, version))


def vex_doc(version, n=2):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"type": "firmware", "name": "ACME Board", "version": version}},
            "vulnerabilities": [{"id": "CVE-2026-%04d" % i, "analysis": {"state": "exploitable"}} for i in range(n)]}


def make_zip(members, extra=None):
    """members：{名稱: bytes}；extra：[ZipInfo, bytes]（符號連結、路徑穿越等）。→ bytes"""
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in members.items():
            z.writestr(n, d)
        for zi, d in extra or []:
            z.writestr(zi, d)
    return b.getvalue()


def report_zip(version, vex=None, summary=True, **kw):
    v = json.dumps(vex if vex is not None else vex_doc(version)).encode()
    m = {pr.VEX_MEMBER: v, "報告/交給PM/SBOM/sbom.cdx.json": b"{}"}
    if summary:
        m[pr.SUMMARY_MEMBER] = json.dumps({"vex": {"files": {"vex.cdx.json": {"sha256": hashlib.sha256(v).hexdigest()}}}}).encode()
    return make_zip(m, **kw)


def release(tag, assets=None, draft=False, prerelease=False, rid=1):
    return {"id": rid, "tag_name": tag, "draft": draft, "prerelease": prerelease, "created_at": "2026-11-01T00:00:00Z", "assets": assets or []}


class Fake:
    """GitHub 替身：list_releases／download。blobs：{asset id: bytes}；size 可以和內容不同（測 API 說謊）。"""
    def __init__(self, releases, blobs=None):
        self.releases, self.blobs, self.calls, self.downloads = releases, blobs or {}, [], []

    def list_releases(self):
        self.calls.append("list")
        return self.releases

    def download(self, asset_id, dest, max_size):
        self.downloads.append(asset_id)
        data = self.blobs[asset_id]
        if len(data) > max_size:
            raise pr.PrevError("附件太大（超過上限 %d 位元組）" % max_size)
        with open(dest, "xb") as f:
            f.write(data)
        return len(data), hashlib.sha256(data).hexdigest()


def prev_release(version, layers=("", "-bsp", "-os"), rid=10, blob_start=100, **zkw):
    """前一版的 Release（附件是各層報告 zip）＋ blobs。"""
    assets, blobs = [], {}
    for i, sfx in enumerate(layers):
        data = report_zip(version, **zkw)
        aid = blob_start + i
        assets.append({"id": aid, "name": "report-%s-%s%s.zip" % (PROJ, version, sfx), "size": len(data), "state": "uploaded"})
        blobs[aid] = data
    return release("%s/%s" % (PROJ, version), assets, rid=rid), blobs


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dumpling-prev-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def p(self, *a):
        return os.path.join(self.tmp, *a)

    def run_prepare(self, fake, version="v1.1.0", env=None, limits=None, out="out"):
        return pr.prepare(PROJ, version, self.p(out), env=tag_env(version) if env is None else env, client=fake, limits=limits)


# ---------------------------------------------------------------- 版本排序與選法

class Versions(unittest.TestCase):
    def test_compare_table(self):
        T = [("v39.2.1-demo1", "v39.2.0-demo1", 1), ("v39.2.0-demo1", "v39.2.1-demo1", -1), ("v1.10.0", "v1.9.0", 1),       # 數字比大小，不是字串
             ("v1.0.1", "v1.0", 1), ("v1.0", "v1.0.1", -1), ("v1.0.0-demo2", "v1.0.0-demo1", 1), ("v1.0", "V1.0", 0), ("v1.0", "v1.00", 0),
             ("v1.rc", "v1.2", None), ("v1.0.0", "v1.0.0", 0)]
        for a, b, want in T:
            self.assertEqual(pr.compare(a, b), want, (a, b))
            self.assertEqual(pr.compare(b, a), None if want is None else -want, (b, a))

    def test_compare_suffix_rules(self):
        """有後綴 < 沒有後綴；後綴逐段比（純數字比數值、含字母的先比字母再比數字、數字段在字母段前、段落少的在前）。"""
        T = [("v39.2.1-demo1", "v39.2.1", -1), ("v1.0-rc1", "v1.0", -1), ("v1.0.0-rc.1", "v1.0.0", -1),                         # demo／rc 轉正式版
             ("v1.0.0-demo1", "v1.0.0-demo2", -1), ("v1.0.0-rc.1", "v1.0.0-rc.2", -1), ("v1.0.0-alpha", "v1.0.0-beta", -1),       # 兩個後綴互比
             ("v1.0.0-rc", "v1.0.0-rc.1", -1), ("v1.0.0-1", "v1.0.0-alpha", -1), ("v1.0.0-rc.1", "v1.0.0-rc.alpha", -1),            # 段落少的在前、數字段在字母段前
             ("v1.0.0-demo2", "v1.0.0-demo10", -1), ("v1.0.0-rc9", "v1.0.0-rc10", -1),                                              # 字母加數字：自然排序（純 semver 會相反）
             ("v1.0.0-demo3", "v1.0.0-rc1", -1), ("v1.0.0-rc1", "v1.0.0-demo99", 1),                                               # 字母部分不同：照 ASCII（demo < rc）
             ("v1.0.0-rc", "v1.0.0-rc1", -1), ("v1.0.0-rc.2", "v1.0.0-rc.10", -1), ("v1.0.0-2", "v1.0.0-10", -1),
             ("v1.0.1-rc1", "v1.0.0", 1), ("v1.0-rc1", "v1.0.1", -1),                                                              # 主版本先決定
             ("v1.0.0-rc1", "v1.0.0-RC1", 0), ("v1.0.0-demo01", "v1.0.0-demo1", 0), ("v1.0.0-rc.01", "v1.0.0-rc.1", 0),           # 寫法不同的同一版：0（呼叫端記 GAP）
             ("v1.0.0+a", "v1.0.0+b", 0), ("v1.0.0-1a", "v1.0.0-1a", 0),
             ("v1.0.0-1a", "v1.0.0-1b", None), ("v1.0.0-a1b", "v1.0.0-a2b", None), ("v1.0.0-1a", "v1.0.0-5", None),               # 不是純數字／純字母／字母加數字：排不出
             ("v1.0.0-a1b", "v1.0.0-rc1", None), ("v1.0.0-a1b", "v1.0.0", -1),                                                      # 只有比到那一段才排不出
             ("v1.0.0-rc1", "v1.0-rc1", 1), ("v1.0.0-", "v1.0.0", None), ("v1.0.0--x", "v1.0.0", -1), ("v1.0.0-rc..1", "v1.0.0", None)]
        for a, b, want in T:
            self.assertEqual(pr.compare(a, b), want, (a, b))
            self.assertEqual(pr.compare(b, a), None if want is None else -want, (b, a))

    def sel(self, rels, ver="v1.1.0"):
        return pr.select_previous(rels, PROJ, ver)

    def tag(self, v, **kw):
        return release("%s/%s" % (PROJ, v), **kw)

    def test_picks_highest_version_below_current(self):
        r, note, st = self.sel([self.tag("v1.0.0"), self.tag("v0.9.0"), self.tag("v1.2.0"), self.tag("v1.0.5")])
        self.assertEqual(r["tag_name"], "acme-board/v1.0.5")
        self.assertEqual(st["newer"], 1)

    def test_numeric_not_string_order(self):
        r, _, _ = self.sel([self.tag("v1.9.0"), self.tag("v1.10.0")], "v1.11.0")
        self.assertEqual(r["tag_name"], "acme-board/v1.10.0")

    def test_patch_on_old_line_compares_to_its_predecessor_not_latest_published(self):
        # v1.0.1 在 v1.1.0 之後才發：前一版是 v1.0.0，不是時間上最近的 v1.1.0
        r, _, _ = self.sel([self.tag("v1.1.0"), self.tag("v1.0.0"), self.tag("v0.9.0")], "v1.0.1")
        self.assertEqual(r["tag_name"], "acme-board/v1.0.0")

    def test_skips_drafts_prereleases_other_projects_and_dev_tags(self):
        rels = [self.tag("v1.0.5", draft=True), self.tag("v1.0.4", prerelease=True), release("other-board/v1.0.3"), release("dev/%s" % PROJ, prerelease=True),
                release("firmware-demo/2026.11.15"), self.tag("v1.0.0")]
        r, _, st = self.sel(rels)
        self.assertEqual(r["tag_name"], "acme-board/v1.0.0")
        self.assertEqual((st["drafts"], st["prereleases"]), (1, 1))

    def test_same_tag_is_never_the_previous(self):
        # 同名 tag 被重打（這次的版本已經有正式 Release）：不拿自己比
        r, note, st = self.sel([self.tag("v1.1.0"), self.tag("v1.0.0")])
        self.assertEqual(r["tag_name"], "acme-board/v1.0.0")
        self.assertEqual(st["same_tag"], 1)
        r, note, _ = self.sel([self.tag("v1.1.0")])
        self.assertIsNone(r)

    def test_no_previous_cases(self):
        self.assertIsNone(self.sel([])[0])
        self.assertIsNone(self.sel([self.tag("v1.0.0", draft=True), self.tag("v1.0.1", prerelease=True)])[0])
        self.assertIsNone(self.sel([self.tag("v2.0.0")])[0])                      # 只有比較新的
        self.assertIn("沒有前一個正式 Release", self.sel([])[1])

    def test_other_project_tag_with_same_length_name_is_not_a_candidate(self):
        """別的專案的名稱和本專案一樣長（acme-boarx／acme-board）：只看長度切字串會把它的 tag 當成候選。"""
        other = "acme-boarx/v1.0.0"
        self.assertEqual(len(other.split("/")[0]), len(PROJ))
        r, _, st = self.sel([release(other), release("acme-boar/v1.0.0"), release("acme-board-x/v1.0.0")])
        self.assertIsNone(r)
        self.assertEqual(st["other_projects"], 3)
        r, _, _ = self.sel([release(other), release("%s/v0.9.0" % PROJ)])
        self.assertEqual(r["tag_name"], "acme-board/v0.9.0")

    def test_non_bool_flags_are_not_trusted(self):
        r = self.tag("v1.0.0")
        r["draft"] = "false"                                                         # 字串不是 bool：不當成正式 Release
        res, _, st = self.sel([r])
        self.assertIsNone(res)
        self.assertEqual(st["malformed"], 1)

    def test_duplicate_published_tag_is_gap(self):
        with self.assertRaises(pr.PrevError):
            self.sel([self.tag("v1.0.0", rid=1), self.tag("v1.0.0", rid=2)])
        # 草稿重複不算（GitHub 允許同 tag 多個草稿）
        r, _, _ = self.sel([self.tag("v1.0.0", rid=1), self.tag("v1.0.0", rid=2, draft=True)])
        self.assertEqual(r["id"], 1)

    def test_demo_and_rc_to_final(self):
        """demo／rc 轉正式版：沒有後綴的版本比有後綴的大，前一版是那個有後綴的版本（不再是 GAP）。"""
        r, _, _ = self.sel([self.tag("v39.2.1-demo1"), self.tag("v39.2.0-demo1")], "v39.2.1")
        self.assertEqual(r["tag_name"], "acme-board/v39.2.1-demo1")
        r, _, _ = self.sel([self.tag("v1.0-rc1"), self.tag("v0.9")], "v1.0")
        self.assertEqual(r["tag_name"], "acme-board/v1.0-rc1")
        r, _, _ = self.sel([self.tag("v39.2.0-demo1"), self.tag("v39.2.1-demo1")], "v39.2.1-demo2")           # 同一版的下一個 demo
        self.assertEqual(r["tag_name"], "acme-board/v39.2.1-demo1")
        r, _, st = self.sel([self.tag("v39.2.1"), self.tag("v39.2.0-demo1")], "v39.2.1-demo1")                 # 較新的是正式版：不是前一版
        self.assertEqual((r["tag_name"], st["newer"]), ("acme-board/v39.2.0-demo1", 1))

    def test_existing_demo_sequence_unchanged(self):
        r, _, _ = self.sel([self.tag("v39.2.0-demo1"), self.tag("v39.1.0-demo1")], "v39.2.1-demo1")
        self.assertEqual(r["tag_name"], "acme-board/v39.2.0-demo1")

    def test_suffix_ordering_in_selection(self):
        r, _, _ = self.sel([self.tag("v1.0.0-demo1"), self.tag("v1.0.0-demo2"), self.tag("v1.0.0-demo10")], "v1.0.0-demo11")
        self.assertEqual(r["tag_name"], "acme-board/v1.0.0-demo10")               # demo10 > demo2（自然排序）
        r, _, _ = self.sel([self.tag("v1.0.0-rc.1"), self.tag("v1.0.0-rc")], "v1.0.0")
        self.assertEqual(r["tag_name"], "acme-board/v1.0.0-rc.1")
        r, _, _ = self.sel([self.tag("v1.0.0-alpha"), self.tag("v1.0.0-demo3")], "v1.0.0-rc1")                  # demo3 < rc1，alpha < demo3
        self.assertEqual(r["tag_name"], "acme-board/v1.0.0-demo3")
        self.assertIsNone(self.sel([self.tag("v1.0.0-rc1")], "v1.0.0-demo1")[0])   # demo1 對 rc1 排得出（rc1 較新）：不是 GAP，只是沒有前一版

    def test_unorderable_versions_are_gap_not_guess(self):
        with self.assertRaises(pr.PrevError):
            self.sel([self.tag("v1.0.0-1a"), self.tag("v0.9.0")], "v1.0.0-5")        # 不是純數字／純字母／字母加數字：排不出，也可能比 v0.9.0 更前，不能略過
        with self.assertRaises(pr.PrevError):
            self.sel([self.tag("v1.00"), self.tag("v0.9.0")], "v1.0")                # 寫法不同的同一版（前導零）
        with self.assertRaises(pr.PrevError):
            self.sel([self.tag("v1.0.0-RC1")], "v1.0.0-rc1")                         # 寫法不同的同一版（大小寫）
        with self.assertRaises(pr.PrevError):
            self.sel([self.tag("v1.0.0rc1"), self.tag("v0.9.0")], "v1.0.0")          # 不是 <數字>-<後綴> 的形式

    def test_odd_suffix_on_an_older_version_does_not_block(self):
        # v0.5.0-1a 和 v0.9.0 的主版本就分得出先後（5 < 9），後綴怪不怪都不影響
        r, _, _ = self.sel([self.tag("v0.9.0"), self.tag("v0.5.0-1a")], "v1.0.0")
        self.assertEqual(r["tag_name"], "acme-board/v0.9.0")
        # 兩個都比這次小、主版本相同、後綴都是排不出的形式：不猜
        with self.assertRaises(pr.PrevError):
            self.sel([self.tag("v0.9.0-1a"), self.tag("v0.9.0-1b")], "v1.0.0")
        # 不是 <數字>-<後綴> 形式的 tag（v0.9.0rc1）和 v0.9.0 排不出先後：不猜
        with self.assertRaises(pr.PrevError):
            self.sel([self.tag("v0.9.0"), self.tag("v0.9.0rc1")], "v1.0.0")


# ---------------------------------------------------------------- 是不是正式 Release

class Official(Tmp):
    def test_guard(self):
        T = [({"GITHUB_EVENT_NAME": "push", "GITHUB_REF_TYPE": "tag", "GITHUB_REF": "refs/tags/acme-board/v1.1.0"}, True),
             ({"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF_TYPE": "tag", "GITHUB_REF": "refs/tags/acme-board/v1.1.0"}, False),
             ({"GITHUB_EVENT_NAME": "push", "GITHUB_REF_TYPE": "branch", "GITHUB_REF": "refs/heads/dev/x"}, False),     # dev/** 分支的 push
             ({"GITHUB_EVENT_NAME": "schedule", "GITHUB_REF_TYPE": "branch", "GITHUB_REF": "refs/heads/main"}, False),
             ({"GITHUB_EVENT_NAME": "push", "GITHUB_REF_TYPE": "tag", "GITHUB_REF": "refs/tags/acme-board/v9.9.9"}, False),     # tag 不是這次要掃的
             ({}, False)]
        for env, want in T:
            self.assertEqual(pr.official_tag_push(env, PROJ, "v1.1.0")[0], want, env)

    def test_not_official_is_not_run_and_never_calls_api(self):
        fake = Fake([])
        for env in ({}, {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF_TYPE": "branch"},
                    {"GITHUB_EVENT_NAME": "push", "GITHUB_REF_TYPE": "branch", "GITHUB_REF": "refs/heads/dev/x"}):
            st, note, doc = self.run_prepare(fake, env=env)
            self.assertEqual(st, "NOT_RUN", env)
            self.assertTrue(note.startswith("僅供參考"))
            self.assertEqual(fake.calls, [])
        self.assertTrue(os.path.isfile(self.p("out", pr.MANIFEST)))
        self.assertEqual(json.load(open(self.p("out", pr.MANIFEST), encoding="utf-8"))["status"], "NOT_RUN")

    def test_non_official_never_connects_even_with_a_real_client(self):
        """真的 GitHub 用戶端、指到不通的位址：不是正式 Release 時一次連線都不會試（沒有例外、沒有等待）。"""
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.listen(1)
        s.settimeout(0.3)
        env = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "example-org/example-repo", "GITHUB_API_URL": "http://127.0.0.1:%d" % port,
               pr.ENV_DELAYS: "0"}
        old = pr.TIMEOUT
        pr.TIMEOUT = 0.3                                                              # 萬一真的連線，快速失敗（不是等 120 秒）
        self.addCleanup(setattr, pr, "TIMEOUT", old)
        try:
            st, _, _ = pr.prepare(PROJ, "v1.1.0", self.p("out"), env=env)
            self.assertEqual(st, "NOT_RUN")
            with self.assertRaises(socket.timeout):
                s.accept()
        finally:
            s.close()

    def test_out_dir_is_not_overwritten_unless_ours(self):
        os.makedirs(self.p("out"))
        open(self.p("out", "x"), "w").close()
        with self.assertRaises(ValueError):
            self.run_prepare(Fake([]))
        shutil.rmtree(self.p("out"))
        self.run_prepare(Fake([]))
        self.run_prepare(Fake([]))                                                   # 自己上一次的輸出可以蓋掉


# ---------------------------------------------------------------- 組資料夾

class Prepare(Tmp):
    def test_ok_three_layers(self):
        rel, blobs = prev_release("v1.0.0")
        fake = Fake([rel, release("acme-board/v0.9.0")], blobs)
        st, note, doc = self.run_prepare(fake)
        self.assertEqual(st, "OK", note)
        self.assertEqual(sorted(doc["layers"]), [PROJ, PROJ + "-bsp", PROJ + "-os"])
        for name in doc["layers"]:
            d = self.p("out", name)
            self.assertEqual(sorted(os.listdir(d)), ["summary.json", "vex.cdx.json"])
            v = open(os.path.join(d, "vex.cdx.json"), "rb").read()
            self.assertEqual(doc["layers"][name]["vex_sha256"], hashlib.sha256(v).hexdigest())
            self.assertEqual(oct(os.stat(os.path.join(d, "vex.cdx.json")).st_mode & 0o777), "0o600")
        self.assertEqual(doc["previous_tag"], "acme-board/v1.0.0")
        self.assertEqual(os.listdir(self.p("out")).count(".work"), 0)                # zip 暫存已清掉
        self.assertEqual(json.load(open(self.p("out", pr.MANIFEST), encoding="utf-8"))["status"], "OK")
        self.assertNotIn(("sbom.cdx.json"), os.listdir(self.p("out", PROJ)))         # 舊版的 SBOM 不用

    def test_first_release_is_not_run_informational(self):
        st, note, doc = self.run_prepare(Fake([release("dev/%s" % PROJ, prerelease=True)]))
        self.assertEqual(st, "NOT_RUN")
        self.assertTrue(note.startswith("僅供參考") and "沒有前一個正式 Release" in note)
        self.assertEqual(doc["layers"], {})

    def test_only_drafts_and_prereleases_is_not_run(self):
        fake = Fake([release("%s/v1.0.0" % PROJ, draft=True), release("%s/v1.0.1" % PROJ, prerelease=True)])
        st, note, _ = self.run_prepare(fake)
        self.assertEqual(st, "NOT_RUN")
        self.assertEqual(fake.downloads, [])

    def test_previous_without_report_assets_is_informational_not_run(self):
        """前一版只有 SBOM、沒有報告 zip（報告格式導入前的舊版）：NOT_RUN，說明以「僅供參考」開頭，步驟列不降級。"""
        rel = release("%s/v1.0.0" % PROJ, [{"id": 1, "name": "sbom-%s-v1.0.0.cdx.json" % PROJ, "size": 5, "state": "uploaded"}])
        fake = Fake([rel])
        st, note, doc = self.run_prepare(fake)
        self.assertEqual(st, "NOT_RUN")
        self.assertEqual(note, "僅供參考：前一版 acme-board/v1.0.0 沒有報告 zip（舊格式），無法產生版本間公告")
        self.assertEqual((doc["status"], doc["previous_tag"], doc["layers"], fake.downloads), ("NOT_RUN", "acme-board/v1.0.0", {}, []))
        self.assertEqual(json.load(open(self.p("out", pr.MANIFEST), encoding="utf-8"))["status"], "NOT_RUN")
        # 附件清單是空的、tag 帶控制字元以外的怪字元：照樣 NOT_RUN，tag 經過 _c
        self.assertEqual(self.run_prepare(Fake([release("%s/v1.0.0" % PROJ)]), out="o2")[0], "NOT_RUN")
        # 步驟列：recorded 的 NOT_RUN，整體不降級
        rows = self.p("steps.tsv")
        sr.append_row(rows, pr.STEP, st, pr.EXIT[st], note, recorded=True)
        self.assertEqual(sr.overall(sr.read_rows(rows)), "OK")

    def test_assets_field_not_a_list_is_gap_not_old_format(self):
        """API 回應的 assets 欄位壞掉（不是清單）是資料問題，不能當成「舊格式沒有報告 zip」。"""
        for bad in (None, "x", {"a": 1}):
            rel = release("%s/v1.0.0" % PROJ)
            rel["assets"] = bad
            self.assertEqual(self.run_prepare(Fake([rel]), out="o")[0], "GAP", bad)
        rel = release("%s/v1.0.0" % PROJ)
        del rel["assets"]
        self.assertEqual(self.run_prepare(Fake([rel]), out="o3")[0], "GAP")

    def test_zip_without_vex_member_is_not_run_not_gap(self):
        """zip 好好的，但沒有 VEX 成員（舊格式）：每一層都這樣 → 整體 NOT_RUN（僅供參考）。"""
        rel, blobs = prev_release("v1.0.0", layers=("", "-bsp"))
        for i in (100, 101):
            blobs[i] = make_zip({"報告/其他.txt": b"x"})
            rel["assets"][i - 100]["size"] = len(blobs[i])
        st, note, doc = self.run_prepare(Fake([rel], blobs))
        self.assertEqual(st, "NOT_RUN", note)
        self.assertTrue(note.startswith("僅供參考：前一版 acme-board/v1.0.0") and "沒有 VEX" in note and "舊格式" in note)
        self.assertEqual({k: v["status"] for k, v in doc["layers"].items()}, {PROJ: "NOT_RUN", PROJ + "-bsp": "NOT_RUN"})
        self.assertTrue(all(v["note"].startswith("僅供參考") for v in doc["layers"].values()))
        self.assertEqual(os.listdir(self.p("out")), [pr.MANIFEST])                  # 沒有層的資料夾、暫存檔

    def test_one_layer_missing_vex_others_ok_is_ok_with_that_layer_not_run(self):
        """其他層 OK、這層缺 VEX（舊格式）：整體 OK（沒有任何一層是 GAP），那一層在 manifest 是 NOT_RUN，說明裡列出。"""
        rel, blobs = prev_release("v1.0.0")
        blobs[101] = make_zip({"報告/其他.txt": b"x"})
        rel["assets"][1]["size"] = len(blobs[101])
        st, note, doc = self.run_prepare(Fake([rel], blobs))
        self.assertEqual(st, "OK", note)
        self.assertEqual({k: v["status"] for k, v in doc["layers"].items()}, {PROJ: "OK", PROJ + "-bsp": "NOT_RUN", PROJ + "-os": "OK"})
        self.assertIn("2 層：%s, %s-os" % (PROJ, PROJ), note)
        self.assertIn("%s-bsp" % PROJ, note.split("；", 1)[1])
        self.assertTrue(note.split("；", 1)[1].startswith("僅供參考"))
        self.assertTrue(os.path.isfile(self.p("out", PROJ, "vex.cdx.json")))
        self.assertFalse(os.path.exists(self.p("out", PROJ + "-bsp")))

    def test_broken_zip_or_bad_vex_stays_gap_other_layers_still_built(self):
        """zip 壞掉、大小不符、VEX 格式不對維持 GAP；有 GAP 時就算別的層是缺 VEX 的 NOT_RUN，整體也是 GAP，NOT_RUN 的層維持 NOT_RUN。"""
        rel, blobs = prev_release("v1.0.0")
        blobs[101] = b"not a zip at all"                                             # -bsp：壞掉
        rel["assets"][1]["size"] = len(blobs[101])
        blobs[102] = make_zip({"報告/其他.txt": b"x"})                               # -os：舊格式
        rel["assets"][2]["size"] = len(blobs[102])
        st, note, doc = self.run_prepare(Fake([rel], blobs))
        self.assertEqual(st, "GAP")
        self.assertEqual({k: v["status"] for k, v in doc["layers"].items()}, {PROJ: "OK", PROJ + "-bsp": "GAP", PROJ + "-os": "NOT_RUN"})
        self.assertIn("1／3 層組不起來", note)
        self.assertNotIn("%s-os：" % PROJ, note)                                    # 說明只列 GAP 的層
        self.assertTrue(os.path.isfile(self.p("out", PROJ, "vex.cdx.json")))
        self.assertFalse(os.path.exists(self.p("out", PROJ + "-bsp")))              # 壞的那層不留半成品
        rel, blobs = prev_release("v1.0.0", layers=("",), vex={"bomFormat": "CycloneDX"})   # VEX 格式不對（沒有 vulnerabilities）
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o2")[0], "GAP")
        rel, blobs = prev_release("v1.0.0", layers=("",))
        rel["assets"][0]["size"] += 1                                               # 大小不符
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o3")[0], "GAP")
        rel, blobs = prev_release("v1.0.0", layers=("",))
        blobs[100] = blobs[100][:-30]                                               # 下載不完整的 zip
        rel["assets"][0]["size"] = len(blobs[100])
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o4")[0], "GAP")

    def test_unexpected_error_midway_does_not_make_other_layers_look_missing(self):
        """處理到一半意外中斷：還沒處理的層在 manifest 是 GAP（不是不存在，不會被精靈當成「前一版沒有這一層」）。"""
        class Bug(Fake):
            def download(self, asset_id, dest, max_size):
                if asset_id == 101:
                    raise KeyError("x")
                return super().download(asset_id, dest, max_size)
        rel, blobs = prev_release("v1.0.0")
        st, note, doc = self.run_prepare(Bug([rel], blobs))
        self.assertEqual(st, "GAP")
        self.assertEqual({k: v["status"] for k, v in doc["layers"].items()}, {PROJ: "OK", PROJ + "-bsp": "GAP", PROJ + "-os": "GAP"})

    def test_ok_note_has_no_absolute_path(self):
        rel, blobs = prev_release("v1.0.0")
        st, note, doc = self.run_prepare(Fake([rel], blobs))
        self.assertEqual(st, "OK")
        text = note + json.dumps(doc, ensure_ascii=False) + open(self.p("out", pr.MANIFEST), encoding="utf-8").read()
        self.assertNotIn(self.tmp, text)
        self.assertNotIn(os.path.dirname(self.tmp) + os.sep, text)
        self.assertIsNone(re.search(r"(?<![A-Za-z0-9_.])/[A-Za-z0-9._-]+/|[A-Za-z]:\\", text), text)               # 沒有 /x/ 開頭的路徑、也沒有 Windows 路徑

    def test_asset_not_uploaded_or_zero_size_or_duplicate_is_gap(self):
        for mut in (lambda r: r["assets"][0].update(state="starter"), lambda r: r["assets"][0].update(size=0),
                    lambda r: r["assets"][0].update(size="12"), lambda r: r["assets"].append(dict(r["assets"][0], id=999))):
            rel, blobs = prev_release("v1.0.0", layers=("",))
            mut(rel)
            blobs[999] = blobs[100]
            st, note, doc = self.run_prepare(Fake([rel], blobs))
            self.assertEqual(st, "GAP", note)

    def test_too_large_asset_is_gap_without_downloading(self):
        rel, blobs = prev_release("v1.0.0", layers=("",))
        fake = Fake([rel], blobs)
        st, note, _ = self.run_prepare(fake, limits={"zip": 50})
        self.assertEqual(st, "GAP")
        self.assertIn("太大", note)
        self.assertEqual(fake.downloads, [])

    def test_lying_size_is_caught_by_actual_download(self):
        rel, blobs = prev_release("v1.0.0", layers=("",))
        n = len(blobs[100])
        rel["assets"][0]["size"] = 10                                                 # API 說 10 位元組，實際比較大
        st, note, _ = self.run_prepare(Fake([rel], blobs), limits={"zip": n - 1, "total": n - 1})
        self.assertEqual(st, "GAP")
        st, note, _ = self.run_prepare(Fake([rel], blobs))
        self.assertEqual(st, "GAP")
        self.assertIn("大小", note)                                                   # 下載的大小和 Release 記的不同

    def test_total_limit_across_layers(self):
        rel, blobs = prev_release("v1.0.0")
        one = len(blobs[100])
        st, note, doc = self.run_prepare(Fake([rel], blobs), limits={"total": one * 2})
        self.assertEqual(st, "GAP")
        self.assertEqual(sorted(k for k, v in doc["layers"].items() if v["status"] == "OK"), [PROJ, PROJ + "-bsp"])
        self.assertIn("加起來超過上限", doc["layers"][PROJ + "-os"]["note"])

    def test_unsafe_zips_are_gap_and_write_nothing_outside(self):
        sym = zipfile.ZipInfo("報告/交給PM/VEX/link")
        sym.create_system = 3
        sym.external_attr = (0o120777 << 16)
        trav = zipfile.ZipInfo("../../evil.txt")
        absn = zipfile.ZipInfo("/etc/evil.txt")
        back = zipfile.ZipInfo("a\\..\\evil")
        dup_members = {pr.VEX_MEMBER: json.dumps(vex_doc("v1.0.0")).encode()}
        cases = {"symlink": [(sym, b"/etc/passwd")], "traversal": [(trav, b"x")], "absolute": [(absn, b"x")], "backslash": [(back, b"x")]}
        for label, extra in cases.items():
            rel, blobs = prev_release("v1.0.0", layers=("",))
            blobs[100] = report_zip("v1.0.0", extra=extra)
            rel["assets"][0]["size"] = len(blobs[100])
            st, note, doc = self.run_prepare(Fake([rel], blobs), out="o-" + label)
            self.assertEqual(st, "GAP", label)
            self.assertFalse(os.path.exists(self.p("o-" + label, PROJ)), label)
            self.assertFalse(os.path.exists(self.p("evil.txt")) or os.path.exists("/etc/evil.txt"), label)
        # 重複名稱
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr(pr.VEX_MEMBER, json.dumps(vex_doc("v1.0.0")))
            with self.assertWarns(UserWarning):
                z.writestr(pr.VEX_MEMBER, json.dumps(vex_doc("v1.0.0", 5)))
        rel, blobs = prev_release("v1.0.0", layers=("",))
        blobs[100] = b.getvalue()
        rel["assets"][0]["size"] = len(blobs[100])
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o-dup")[0], "GAP")

    def test_not_a_zip_or_member_too_big_or_bomb(self):
        rel, blobs = prev_release("v1.0.0", layers=("",))
        blobs[100] = b"not a zip" * 10
        rel["assets"][0]["size"] = len(blobs[100])
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o1")[0], "GAP")
        rel, blobs = prev_release("v1.0.0", layers=("",))
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o2", limits={"member": 20})[0], "GAP")
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o3", limits={"unpacked": 20})[0], "GAP")
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o4", limits={"entries": 1})[0], "GAP")

    def test_vex_must_be_cyclonedx_vex_and_summary_json_object(self):
        for label, kw in {"not-json": {"vex": None}, "wrong-format": {"vex": {"bomFormat": "SPDX"}}, "no-vulns": {"vex": {"bomFormat": "CycloneDX"}}}.items():
            rel, blobs = prev_release("v1.0.0", layers=("",))
            if label == "not-json":
                blobs[100] = make_zip({pr.VEX_MEMBER: b"{ not json"})
            else:
                blobs[100] = report_zip("v1.0.0", vex=kw["vex"])
            rel["assets"][0]["size"] = len(blobs[100])
            self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o-" + label)[0], "GAP", label)
        # 不是 CycloneDX 卻帶著 vulnerabilities 清單：只看清單會放行，bomFormat 一定要是 CycloneDX（SPDX、沒有 bomFormat、大小寫不同、別的值）
        vulns = vex_doc("v1.0.0")["vulnerabilities"]
        for label, doc in {"spdx": {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "vulnerabilities": vulns},
                           "bomformat-spdx": {"bomFormat": "SPDX", "vulnerabilities": vulns},
                           "no-bomformat": {"specVersion": "1.5", "vulnerabilities": vulns},
                           "lowercase": {"bomFormat": "cyclonedx", "vulnerabilities": vulns},
                           "non-string": {"bomFormat": ["CycloneDX"], "vulnerabilities": vulns},
                           "vulns-not-list": {"bomFormat": "CycloneDX", "vulnerabilities": {"a": 1}},
                           "top-list": [{"bomFormat": "CycloneDX", "vulnerabilities": []}]}.items():
            rel, blobs = prev_release("v1.0.0", layers=("",))
            blobs[100] = report_zip("v1.0.0", vex=doc)
            rel["assets"][0]["size"] = len(blobs[100])
            st, note, d = self.run_prepare(Fake([rel], blobs), out="o20-" + label)
            self.assertEqual(st, "GAP", label)
            self.assertIn("CycloneDX", note, label)
            self.assertFalse(os.path.exists(self.p("o20-" + label, PROJ)), label)             # 沒有半成品
        rel, blobs = prev_release("v1.0.0", layers=("",), vex={"bomFormat": "CycloneDX", "vulnerabilities": []})      # 對照：空清單的 CycloneDX 可以用
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o20-ok")[0], "OK")
        rel, blobs = prev_release("v1.0.0", layers=("",))
        blobs[100] = make_zip({pr.VEX_MEMBER: json.dumps(vex_doc("v1.0.0")).encode(), pr.SUMMARY_MEMBER: b"[1]"})
        rel["assets"][0]["size"] = len(blobs[100])
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o-sum")[0], "GAP")
        # 沒有 summary.json：可以用（csaf_advisory 會在公告的 notes 寫舊版沒有 summary），不是 GAP
        rel, blobs = prev_release("v1.0.0", layers=("",), summary=False)
        st, _, doc = self.run_prepare(Fake([rel], blobs), out="o-nosum")
        self.assertEqual(st, "OK")
        self.assertEqual(os.listdir(self.p("o-nosum", PROJ)), ["vex.cdx.json"])

    def test_nested_json_does_not_crash(self):
        rel, blobs = prev_release("v1.0.0", layers=("",))
        blobs[100] = make_zip({pr.VEX_MEMBER: b"[" * 200000})
        rel["assets"][0]["size"] = len(blobs[100])
        self.assertEqual(self.run_prepare(Fake([rel], blobs), out="o")[0], "GAP")

    def test_api_failure_and_unexpected_exception_are_gap_with_manifest(self):
        class Boom(Fake):
            def list_releases(self):
                raise pr.PrevError("GitHub API 失敗（HTTP 403）")
        st, note, _ = self.run_prepare(Boom([]), out="o1")
        self.assertEqual((st, "403" in note), ("GAP", True))
        self.assertEqual(json.load(open(self.p("o1", pr.MANIFEST), encoding="utf-8"))["status"], "GAP")

        class Bug(Fake):
            def list_releases(self):
                raise KeyError("x")
        st, note, _ = self.run_prepare(Bug([]), out="o2")
        self.assertEqual(st, "GAP")
        self.assertIn("KeyError", note)

    def test_zip_member_names_are_sanitized_in_notes(self):
        """zip 成員名稱進說明前只留 [A-Za-z0-9._/-] 和中文，其他字元換成 ?：Markdown、HTML、控制字元、其他文字都不會進 notes.md／Release 說明。"""
        self.assertEqual(pr._zn("報告/交給PM/VEX/vex.cdx.json"), "報告/交給PM/VEX/vex.cdx.json")
        for ch in " |`*[]()<>&\"'$#!~\n\t\r\x00\x1b\u202e\u200b\uff1c\u3000\u00e9\u0430\u2028":
            self.assertEqual(pr._zn("a" + ch + "b"), "a?b", repr(ch))
        self.assertEqual(pr._zn("x" * 200, 80), "x" * 80)
        evil = ["![x](https://example.invalid/p.png)", "<img src=x onerror=alert(1)>", "[a](javascript:alert(1))", "a|b\nc", "..\u202egpj.exe", "x`y`", "a\u0430b"]
        for i, name in enumerate(evil):
            rel, blobs = prev_release("v1.0.0", layers=("",))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")                                                  # zipfile 對重複名稱的警告
                blobs[100] = make_zip({}, extra=[(zipfile.ZipInfo(name), b"x"), (zipfile.ZipInfo(name), b"y")])      # 重複的名稱
            rel["assets"][0]["size"] = len(blobs[100])
            st, note, doc = self.run_prepare(Fake([rel], blobs), out="o-evil%d" % i)
            self.assertEqual(st, "GAP", name)
            m = re.search(r"重複的成員名稱（([^）]*)）", note)
            self.assertTrue(m and re.fullmatch(r"[A-Za-z0-9._/?\-\u3400-\u4dbf\u4e00-\u9fff]*", m.group(1)), (name, note))
            self.assertNotIn("\n", note)
        for label, zi in {"traversal": zipfile.ZipInfo("../<b>evil</b>"), "backslash": zipfile.ZipInfo("a\\b|c"), "abs": zipfile.ZipInfo("/etc/`x`")}.items():
            rel, blobs = prev_release("v1.0.0", layers=("",))
            blobs[100] = make_zip({}, extra=[(zi, b"x")])
            rel["assets"][0]["size"] = len(blobs[100])
            st, note, _ = self.run_prepare(Fake([rel], blobs), out="o-p-" + label)
            self.assertEqual(st, "GAP", label)
            for bad in "<>`|":
                self.assertNotIn(bad, note, (label, bad))
        # 符號連結名稱
        zi = zipfile.ZipInfo("link|`x`.txt")
        zi.external_attr = 0o120777 << 16
        rel, blobs = prev_release("v1.0.0", layers=("",))
        blobs[100] = make_zip({}, extra=[(zi, b"/etc/passwd")])
        rel["assets"][0]["size"] = len(blobs[100])
        st, note, _ = self.run_prepare(Fake([rel], blobs), out="o-sym")
        self.assertEqual(st, "GAP")
        self.assertIn("link??x?.txt", note)

    def test_layer_names_only_match_project_and_version(self):
        rel, blobs = prev_release("v1.0.0", layers=("", "-bsp"))
        rel["assets"] += [{"id": 7, "name": "report-other-board-v1.0.0.zip", "size": 1, "state": "uploaded"},
                          {"id": 8, "name": "report-%s-v0.9.0.zip" % PROJ, "size": 1, "state": "uploaded"},
                          {"id": 9, "name": "report-%s-v1.0.0-../x.zip" % PROJ, "size": 1, "state": "uploaded"},
                          {"id": 10, "name": "report-%s-v1.0.0-bsp-extra-long-suffix-name.zip" % PROJ, "size": 1, "state": "uploaded"},
                          {"id": 11, "name": "vex-%s-v1.0.0.cdx.json" % PROJ, "size": 1, "state": "uploaded"}]
        fake = Fake([rel], blobs)
        st, _, doc = self.run_prepare(fake)
        self.assertEqual((st, sorted(doc["layers"])), ("OK", [PROJ, PROJ + "-bsp"]))
        self.assertEqual(sorted(fake.downloads), [100, 101])


# ---------------------------------------------------------------- pipeline-steps.tsv

class Steps(Tmp):
    def run_cli(self, env_extra, version="v1.1.0", steps=True):
        env = {"PATH": os.environ.get("PATH", ""), **env_extra}
        args = [sys.executable, "-I", SCRIPT, "prepare", "--project", PROJ, "--version", version, "--out", self.p("out")]
        if steps:
            args += ["--steps", self.p("steps.tsv")]
        return subprocess.run(args, capture_output=True, text=True, env=env)

    def test_not_run_row_does_not_lower_overall(self):
        r = self.run_cli({})
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertTrue(r.stdout.strip().startswith("previous-release: NOT_RUN（僅供參考"))
        rows = sr.read_rows(self.p("steps.tsv"))
        self.assertEqual([(x["step"], x["status"], x["exit"], x.get("recorded")) for x in rows], [("pipeline-previous-release", "NOT_RUN", 4, True)])
        self.assertEqual(sr.overall(rows), "OK")                                     # 資訊，不是 GAP
        self.assertEqual(subprocess.run([sys.executable, "-I", os.path.join(LIB, "step_rows.py"), "status", self.p("steps.tsv")], capture_output=True, text=True).stdout.strip(), "OK")

    def test_not_run_text_without_recorded_marker_still_lowers_overall(self):
        """只看文字會被步驟輸出繞過：一般步驟（沒有 recorded）說明寫「僅供參考」也照樣是 GAP。"""
        sr.append_row(self.p("s.tsv"), "scan", "NOT_RUN", 4, "僅供參考：假的")
        self.assertEqual(sr.overall(sr.read_rows(self.p("s.tsv"))), "GAP")

    def test_gap_row_lowers_overall_to_gap(self):
        for st, d in (("GAP", "找到了但失敗"),):
            sr.append_row(self.p("g.tsv"), "previous-release", st, 3, d)
        self.assertEqual(sr.overall(sr.read_rows(self.p("g.tsv"))), "GAP")

    def test_gap_exit_code_is_3(self):
        """GAP 的結束碼是 3（和 run-step.sh 一致；workflow 靠它分辨 GAP 與用法錯誤）：API 失敗、不可寫的 steps 檔都是 3。"""
        self.assertEqual(pr.EXIT, {"OK": 0, "GAP": 3, "NOT_RUN": 4})
        s = Server([], {})
        self.addCleanup(s.close)
        s.fail["/repos/example-org/example-repo/releases"] = 403
        r = self.run_cli(dict(tag_env("v1.1.0"), GITHUB_API_URL=s.url))
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertTrue(r.stdout.startswith("previous-release: GAP（"))
        rows = sr.read_rows(self.p("steps.tsv"))
        self.assertEqual([(x["status"], x["exit"], x.get("recorded")) for x in rows], [("GAP", 3, None)])
        self.assertEqual(sr.overall(rows), "GAP")
        shutil.rmtree(self.p("out"))
        r = self.run_cli(dict(tag_env("v1.1.0"), GITHUB_API_URL=s.url), steps=False)                    # 沒給 --steps 也是 3
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        shutil.rmtree(self.p("out"))
        s.fail.clear()                                                                                    # 成功 0、第一個正式 Release 4
        self.assertEqual(self.run_cli(dict(tag_env("v1.1.0"), GITHUB_API_URL=s.url), steps=False).returncode, 4)
        shutil.rmtree(self.p("out"))
        args = [sys.executable, "-I", SCRIPT, "prepare", "--project", PROJ, "--version", "v1.1.0", "--out", self.p("out"), "--steps", self.p("no-such-dir", "s.tsv")]
        r = subprocess.run(args, capture_output=True, text=True, env={"PATH": os.environ.get("PATH", "")})      # steps 檔寫不進去：3
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)

    def test_bad_args_exit_64_and_unwritable_steps_is_gap_not_crash(self):
        r = subprocess.run([sys.executable, "-I", SCRIPT, "prepare", "--project", PROJ], capture_output=True, text=True)
        self.assertEqual(r.returncode, 64)
        os.makedirs(self.p("out"))
        open(self.p("out", "x"), "w").close()
        r = self.run_cli({})
        self.assertEqual(r.returncode, 64)                                           # 不是自己的輸出：不覆蓋


# ---------------------------------------------------------------- 真的 HTTP 用戶端（本機伺服器）

class Server:
    def __init__(self, releases, blobs, pages=None):
        self.releases, self.blobs, self.log, self.fail, self.nolen = releases, blobs, [], {}, False
        self.fail_hdrs = {}       # 失敗回應多帶的標頭（例如 Retry-After）
        self.flaky = {}           # {路徑: [狀態碼, …]}：前幾次回這些狀態碼，之後正常
        self.drip = None          # (每次送幾個位元組, 間隔秒)：附件內容慢慢送
        self.redirect_to = None   # 附件轉址到這個網址（預設轉到自己的 /blob/<id>）
        self.list_drip = None     # (每次送幾個位元組, 間隔秒)：Release 清單慢慢送
        self.cl_header = None     # 附件的 Content-Length 標頭值（預設是真的長度；測試放怪值）
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.log.append((self.path, self.headers.get("Authorization")))
                code = outer.fail.get(self.path.split("?")[0])
                if not code and outer.flaky.get(self.path.split("?")[0]):
                    code = outer.flaky[self.path.split("?")[0]].pop(0)
                if code:
                    self.send_response(code)
                    for k, v in outer.fail_hdrs.items():
                        self.send_header(k, v)
                    self.end_headers()
                    return
                m = re.fullmatch(r"/repos/example-org/example-repo/releases\?per_page=100&page=(\d+)", self.path)
                if m:
                    page = int(m.group(1))
                    body = json.dumps(outer.releases[(page - 1) * 100:page * 100]).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if outer.list_drip:
                        step, gap = outer.list_drip
                        try:
                            for i in range(0, len(body), step):
                                self.wfile.write(body[i:i + step])
                                self.wfile.flush()
                                time.sleep(gap)
                        except OSError:
                            pass
                        return
                    self.wfile.write(body)
                    return
                m = re.fullmatch(r"/repos/example-org/example-repo/releases/assets/(\d+)", self.path)
                if m:                                                                # 附件：轉址到別的路徑（模擬簽名網址）
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_to or "/blob/%s" % m.group(1))
                    self.end_headers()
                    return
                m = re.fullmatch(r"/blob/(\d+)", self.path)
                if m and int(m.group(1)) in outer.blobs:
                    body = outer.blobs[int(m.group(1))]
                    self.send_response(200)
                    if not outer.nolen:                                              # 沒有 Content-Length：只能靠實際讀到的位元組數擋
                        self.send_header("Content-Length", outer.cl_header or str(len(body)))
                    self.end_headers()
                    if outer.drip:
                        step, gap = outer.drip
                        try:
                            for i in range(0, len(body), step):
                                self.wfile.write(body[i:i + step])
                                self.wfile.flush()
                                time.sleep(gap)
                        except OSError:                                              # 用戶端中止了
                            pass
                        return
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class Http(Tmp):
    def server(self, releases, blobs):
        s = Server(releases, blobs)
        self.addCleanup(s.close)
        return s

    def env(self, s, version="v1.1.0", token="tok-123"):
        e = dict(tag_env(version), GITHUB_API_URL=s.url)
        if token:
            e["GITHUB_TOKEN"] = token
        return e

    def test_end_to_end_over_http_with_pagination_and_redirect(self):
        rel, blobs = prev_release("v1.0.0")
        rels = [release("%s/v0.%d.0" % (PROJ, i), draft=True, rid=1000 + i) for i in range(150)] + [rel]      # 第二頁才有
        s = self.server(rels, blobs)
        st, note, doc = pr.prepare(PROJ, "v1.1.0", self.p("out"), env=self.env(s))
        self.assertEqual(st, "OK", note)
        paths = [p for p, _ in s.log]
        self.assertIn("/repos/example-org/example-repo/releases?per_page=100&page=2", paths)
        auth = dict(s.log)
        self.assertEqual(auth["/repos/example-org/example-repo/releases/assets/100"], "Bearer tok-123")
        self.assertIsNone(auth["/blob/100"])                                          # 轉址後不帶 Authorization

    def test_no_token_is_fine(self):
        rel, blobs = prev_release("v1.0.0", layers=("",))
        s = self.server([rel], blobs)
        st, _, _ = pr.prepare(PROJ, "v1.1.0", self.p("out"), env=self.env(s, token=None))
        self.assertEqual(st, "OK")
        self.assertTrue(all(a is None for _, a in s.log))

    def test_download_url_in_response_is_never_used(self):
        rel, blobs = prev_release("v1.0.0", layers=("",))
        rel["assets"][0]["browser_download_url"] = "http://127.0.0.1:1/evil"
        rel["assets"][0]["url"] = "http://127.0.0.1:1/evil"
        s = self.server([rel], blobs)
        self.assertEqual(pr.prepare(PROJ, "v1.1.0", self.p("out"), env=self.env(s))[0], "OK")
        self.assertFalse([p for p, _ in s.log if "evil" in p])

    def test_http_errors_are_gap(self):
        rel, blobs = prev_release("v1.0.0", layers=("",))
        s = self.server([rel], blobs)
        s.fail["/repos/example-org/example-repo/releases"] = 403
        st, note, _ = pr.prepare(PROJ, "v1.1.0", self.p("o1"), env=self.env(s))
        self.assertEqual(st, "GAP")
        self.assertIn("403", note)
        self.assertEqual(len([p for p, _ in s.log if p.startswith("/repos/example-org/example-repo/releases?")]), 1)      # 4xx 不重試
        s.fail.clear()
        s.fail["/repos/example-org/example-repo/releases/assets/100"] = 404
        self.assertEqual(pr.prepare(PROJ, "v1.1.0", self.p("o2"), env=self.env(s))[0], "GAP")

    def test_server_error_is_retried(self):
        s = self.server([], {})
        s.fail["/repos/example-org/example-repo/releases"] = 502
        c = pr.GitHub("example-org/example-repo", None, s.url, retries=3, delay=0)
        with self.assertRaises(pr.PrevError):
            c.list_releases()
        self.assertEqual(len(s.log), 3)

    def client(self, s, **kw):
        return pr.GitHub("example-org/example-repo", None, s.url, **kw)

    def test_transient_errors_retry_five_times_with_backoff(self):
        """5xx、429：預設最多 5 次，退避 10、30、60、60 秒（這裡把 sleep 換掉，不真的等）；4xx（429 除外）不重試。"""
        slept = []
        old = pr._sleep
        pr._sleep = slept.append
        self.addCleanup(setattr, pr, "_sleep", old)
        s = self.server([], {})
        for code in (500, 502, 503, 429):
            slept.clear()
            del s.log[:]
            s.fail["/repos/example-org/example-repo/releases"] = code
            with self.assertRaises(pr.PrevError):
                self.client(s, environ={}).list_releases()
            self.assertEqual((len(s.log), slept), (5, [10, 30, 60, 60]), code)
        for code in (400, 401, 403, 404, 422):
            slept.clear()
            del s.log[:]
            s.fail["/repos/example-org/example-repo/releases"] = code
            with self.assertRaises(pr.PrevError):
                self.client(s, environ={}).list_releases()
            self.assertEqual((len(s.log), slept), (1, []), code)

    def test_transient_then_success_recovers(self):
        rel, blobs = prev_release("v1.0.0", layers=("",))
        s = self.server([rel], blobs)
        s.flaky["/repos/example-org/example-repo/releases"] = [502, 429, 503, 500]       # 第 5 次才成功
        s.flaky["/repos/example-org/example-repo/releases/assets/100"] = [503, 503]
        env = dict(self.env(s), **{pr.ENV_DELAYS: "0"})
        st, note, _ = pr.prepare(PROJ, "v1.1.0", self.p("out"), env=env)
        self.assertEqual(st, "OK", note)

    def test_retry_after_is_followed_but_capped(self):
        slept = []
        old = pr._sleep
        pr._sleep = slept.append
        self.addCleanup(setattr, pr, "_sleep", old)
        s = self.server([], {})
        s.fail["/repos/example-org/example-repo/releases"] = 429
        s.fail_hdrs["Retry-After"] = "7"
        with self.assertRaises(pr.PrevError):
            self.client(s, environ={}).list_releases()
        self.assertEqual(slept, [7, 7, 7, 7])                                          # 照 Retry-After，不是 10、30、60
        slept.clear()
        s.fail_hdrs["Retry-After"] = "99999"
        with self.assertRaises(pr.PrevError):
            self.client(s, environ={}).list_releases()
        self.assertEqual(slept, [120] * 4)                                            # 上限
        slept.clear()
        with self.assertRaises(pr.PrevError):
            self.client(s, environ={pr.ENV_AFTER_MAX: "3"}).list_releases()
        self.assertEqual(slept, [3] * 4)                                              # 上限可用環境變數改
        slept.clear()
        for bad in ("soon", "-5", "1e9999", ""):                                      # 不認得的值：照退避清單
            s.fail_hdrs["Retry-After"] = bad
            slept.clear()
            with self.assertRaises(pr.PrevError):
                self.client(s, environ={}).list_releases()
            self.assertEqual(slept, [10, 30, 60, 60], bad)
        s.fail_hdrs["Retry-After"] = "Wed, 21 Oct 2015 07:28:00 GMT"                   # 過去的日期：0 秒
        slept.clear()
        with self.assertRaises(pr.PrevError):
            self.client(s, environ={}).list_releases()
        self.assertEqual(slept, [0] * 4)

    def test_retry_settings_come_from_environment(self):
        s = self.server([], {})
        s.fail["/repos/example-org/example-repo/releases"] = 502
        slept = []
        old = pr._sleep
        pr._sleep = slept.append
        self.addCleanup(setattr, pr, "_sleep", old)
        c = self.client(s, environ={pr.ENV_RETRIES: "2", pr.ENV_DELAYS: "1,2,3"})
        with self.assertRaises(pr.PrevError):
            c.list_releases()
        self.assertEqual((len(s.log), slept), (2, [1]))
        del s.log[:]
        slept.clear()
        with self.assertRaises(pr.PrevError):
            self.client(s, environ={pr.ENV_DELAYS: "0"}).list_releases()                 # 測試用：全部 0 秒
        self.assertEqual((len(s.log), slept), (5, [0, 0, 0, 0]))
        for bad in ({pr.ENV_RETRIES: "abc"}, {pr.ENV_RETRIES: "0"}, {pr.ENV_DELAYS: "x,y"}, {pr.ENV_DELAYS: "-1"}, {pr.ENV_DEADLINE: "nan"}):
            c = self.client(s, environ=bad)                                                # 設錯不當機，用預設
            self.assertEqual((c.retries, c.delays, c.deadline), (5, (10, 30, 60), 600), bad)

    def test_content_length_must_be_ascii_digits(self):
        """Content-Length 是 ² 這類 isdigit() 為真但 int() 會失敗的字元：不當成數字，不是「意外」，照實際讀到的位元組數走。"""
        rel, blobs = prev_release("v1.0.0", layers=("",))
        s = self.server([rel], blobs)
        s.cl_header = "²"
        c = self.client(s)
        dest = self.p("x.zip")
        self.assertEqual(c.download(100, dest, 1 << 20)[0], len(blobs[100]))
        os.unlink(dest)
        with self.assertRaises(pr.PrevError) as cm:
            c.download(100, dest, 20)                                                      # 仍然擋得住過大的內容（實際讀到的位元組數）
        self.assertIn("太大", str(cm.exception))
        self.assertFalse(os.path.exists(dest))
        st, note, doc = pr.prepare(PROJ, "v1.1.0", self.p("out"), env=self.env(s))
        self.assertEqual(st, "OK", note)

    def test_list_releases_has_overall_deadline(self):
        """列出 Release 的整體時間上限：涓滴的回應、分頁、重試等待加起來超過就是 GAP（不是卡住）。"""
        rel, blobs = prev_release("v1.0.0", layers=("",))
        s = self.server([rel], blobs)
        s.list_drip = (20, 0.1)
        t0 = time.monotonic()
        with self.assertRaises(pr.PrevError) as cm:
            self.client(s, list_deadline=0.5, delay=0).list_releases()
        self.assertIn("時間上限", str(cm.exception))
        self.assertLess(time.monotonic() - t0, 4)
        env = dict(self.env(s), **{pr.ENV_LIST_DEADLINE: "0.4", pr.ENV_DELAYS: "0"})
        st, note, doc = pr.prepare(PROJ, "v1.1.0", self.p("out"), env=env)
        self.assertEqual(st, "GAP")
        self.assertIn("時間上限", note)
        self.assertEqual(json.load(open(self.p("out", pr.MANIFEST), encoding="utf-8"))["status"], "GAP")
        s.list_drip = None
        self.assertEqual(len(self.client(s, list_deadline=5).list_releases()), 1)           # 沒有涓滴就正常

    def test_list_deadline_also_bounds_retry_waits_and_has_default(self):
        s = self.server([], {})
        s.fail["/repos/example-org/example-repo/releases"] = 503
        t0 = time.monotonic()
        with self.assertRaises(pr.PrevError):
            self.client(s, list_deadline=1, delay=30).list_releases()
        self.assertLess(time.monotonic() - t0, 5)
        self.assertEqual(len(s.log), 1)
        self.assertEqual(self.client(s, environ={}).list_deadline, 300)
        self.assertEqual(self.client(s, environ={pr.ENV_LIST_DEADLINE: "42"}).list_deadline, 42)
        for bad in ("abc", "nan", "0", "-5", "inf"):
            self.assertEqual(self.client(s, environ={pr.ENV_LIST_DEADLINE: bad}).list_deadline, 300, bad)

    def test_slow_drip_download_hits_deadline_and_leaves_no_file(self):
        rel, blobs = prev_release("v1.0.0", layers=("",))
        s = self.server([rel], blobs)
        s.drip = (20, 0.1)                                                                # 一個 zip 要送好幾秒
        dest = self.p("slow.zip")
        t0 = time.monotonic()
        with self.assertRaises(pr.PrevError) as cm:
            self.client(s, deadline=0.5, delay=0).download(100, dest, 1 << 20)
        self.assertIn("時間上限", str(cm.exception))
        self.assertLess(time.monotonic() - t0, 3)
        self.assertFalse(os.path.exists(dest))                                            # 暫存檔刪掉
        s.drip = None
        self.assertEqual(self.client(s, deadline=5).download(100, dest, 1 << 20)[0], len(blobs[100]))   # 沒有涓滴就正常

    def test_slow_drip_is_a_layer_gap_in_prepare(self):
        rel, blobs = prev_release("v1.0.0", layers=("", "-bsp"))
        s = self.server([rel], blobs)
        s.drip = (20, 0.1)
        env = dict(self.env(s), **{pr.ENV_DEADLINE: "0.4", pr.ENV_DELAYS: "0"})
        t0 = time.monotonic()
        st, note, doc = pr.prepare(PROJ, "v1.1.0", self.p("out"), env=env)
        self.assertEqual(st, "GAP")
        self.assertIn("時間上限", note)
        self.assertEqual(sorted(v["status"] for v in doc["layers"].values()), ["GAP", "GAP"])
        self.assertLess(time.monotonic() - t0, 6)
        self.assertEqual(os.listdir(self.p("out")), [pr.MANIFEST])                         # 沒有半成品、暫存檔
        self.assertEqual(json.load(open(self.p("out", pr.MANIFEST), encoding="utf-8"))["status"], "GAP")

    def test_deadline_also_bounds_retry_waits(self):
        """要等的時間會超過時間上限就不等了：直接記 GAP（不睡過頭）。"""
        s = self.server([], {})
        s.fail["/repos/example-org/example-repo/releases/assets/100"] = 503
        t0 = time.monotonic()
        with self.assertRaises(pr.PrevError):
            self.client(s, deadline=1, delay=30).download(100, self.p("x.zip"), 100)
        self.assertLess(time.monotonic() - t0, 5)
        self.assertEqual(len(s.log), 1)

    def test_redirect_to_plain_http_non_loopback_is_refused(self):
        """轉址到 http 但不是 loopback 的主機：拒絕（不連線、不帶 Authorization）。https 以外只有測試用的 loopback http。"""
        rel, blobs = prev_release("v1.0.0", layers=("",))
        for target in ("http://example.invalid/blob/100", "http://192.0.2.1/blob/100", "http://127.0.0.1.example.invalid/blob/100",
                       "ftp://127.0.0.1/blob/100", "file:///etc/passwd"):
            s = self.server([rel], blobs)
            s.redirect_to = target
            with self.assertRaises(pr.PrevError, msg=target):
                self.client(s, delay=0).download(100, self.p("r.zip"), 1 << 20)
            self.assertFalse(os.path.exists(self.p("r.zip")))
        s = self.server([rel], blobs)                                                      # 對照：轉到 loopback http（測試伺服器本身）可以
        self.assertEqual(self.client(s).download(100, self.p("ok.zip"), 1 << 20)[0], len(blobs[100]))

    def test_redirect_handler_scheme_and_host_rules(self):
        import urllib.request
        req = urllib.request.Request("http://127.0.0.1:1/a", headers={"Authorization": "Bearer t"})
        for allow, url, ok in ((False, "http://127.0.0.1:2/b", False), (False, "https://example.invalid/b", True),
                               (True, "http://127.0.0.1:2/b", True), (True, "http://localhost:2/b", True),
                               (True, "http://example.invalid/b", False), (True, "http://192.0.2.7/b", False), (True, "ftp://127.0.0.1/b", False)):
            h = pr._Redirect(allow)
            if ok:
                new = h.redirect_request(req, None, 302, "Found", {}, url)
                self.assertIsNotNone(new, (allow, url))
                self.assertNotIn("authorization", [k.lower() for k in list(new.headers) + list(new.unredirected_hdrs)])
            else:
                with self.assertRaises(urllib.error.URLError, msg=(allow, url)):
                    h.redirect_request(req, None, 302, "Found", {}, url)

    def test_api_url_must_be_https_or_loopback(self):
        for bad in ("http://example.invalid", "ftp://127.0.0.1", "https://user:pw@example.invalid", "http://127.0.0.1@example.invalid"):
            with self.assertRaises(pr.PrevError, msg=bad):
                pr.GitHub("example-org/example-repo", None, bad)
        pr.GitHub("example-org/example-repo", None, "https://api.github.com")
        with self.assertRaises(pr.PrevError):
            pr.GitHub("bad repo", None, "https://api.github.com")

    def test_oversize_response_and_download_stop(self):
        rel, blobs = prev_release("v1.0.0", layers=("",))
        s = self.server([rel], blobs)
        c = pr.GitHub("example-org/example-repo", None, s.url, limits={"api": 10})
        with self.assertRaises(pr.PrevError):
            c.list_releases()
        c = pr.GitHub("example-org/example-repo", None, s.url)
        dest = self.p("big.zip")
        with self.assertRaises(pr.PrevError):
            c.download(100, dest, 20)
        self.assertFalse(os.path.exists(dest))                                        # 超過上限的半成品要刪掉
        n, sha = c.download(100, dest, 1 << 20)
        self.assertEqual(sha, hashlib.sha256(blobs[100]).hexdigest())

    def test_download_cap_without_content_length(self):
        """伺服器不給 Content-Length（或說謊）：照實際讀到的位元組數擋，超過就停止並刪掉檔案。"""
        rel, blobs = prev_release("v1.0.0", layers=("",))
        s = self.server([rel], blobs)
        s.nolen = True
        c = pr.GitHub("example-org/example-repo", None, s.url)
        dest = self.p("big.zip")
        with self.assertRaises(pr.PrevError):
            c.download(100, dest, 20)
        self.assertFalse(os.path.exists(dest))
        self.assertEqual(c.download(100, dest, 1 << 20)[0], len(blobs[100]))

    def test_cli_official_over_http(self):
        rel, blobs = prev_release("v1.0.0")
        s = self.server([rel], blobs)
        env = {"PATH": os.environ.get("PATH", ""), **self.env(s)}
        r = subprocess.run([sys.executable, "-I", SCRIPT, "prepare", "--project", PROJ, "--version", "v1.1.0", "--out", self.p("out"), "--steps", self.p("s.tsv")],
                           capture_output=True, text=True, env=env)
        self.assertEqual((r.returncode, r.stdout.startswith("previous-release: OK（前一個正式 Release acme-board/v1.0.0，3 層")), (0, True), r.stdout + r.stderr)
        rows = sr.read_rows(self.p("s.tsv"))
        self.assertEqual([(x["status"], x.get("recorded")) for x in rows], [("OK", None)])
        self.assertNotIn("tok-123", r.stdout + r.stderr + open(self.p("out", pr.MANIFEST), encoding="utf-8").read())


# ---------------------------------------------------------------- 精靈讀資料夾、report_package 真的產生草稿

def wiz_module():
    spec = importlib.util.spec_from_file_location("cra_scan_wizard_prev_env", WIZ)
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    return w


class Wizard(Tmp):
    def prepared(self, fake=None, **kw):
        rel, blobs = prev_release("v1.0.0", **kw)
        st, note, doc = self.run_prepare(fake or Fake([rel], blobs))
        return st, doc

    def test_each_layer_gets_its_own_folder(self):
        w = wiz_module()
        st, doc = self.prepared()
        env = {w.PREVIOUS_ENV: self.p("out")}
        for name in (PROJ, PROJ + "-bsp", PROJ + "-os"):
            r, note, status = w.previous_from_env(name, env)
            self.assertEqual((status, r), ("ok", __import__("pathlib").Path(self.p("out", name))), name)
        self.assertEqual(w.resolve_previous(None, self.tmp, PROJ + "-bsp", True, env)[2], "ok")

    def test_env_not_set_is_none_and_cli_wins(self):
        w = wiz_module()
        self.assertIsNone(w.previous_from_env(PROJ, {}))
        self.assertIsNone(w.previous_from_env(PROJ, {w.PREVIOUS_ENV: ""}))
        self.prepared()
        r, note, status = w.resolve_previous(None, self.tmp, PROJ, True, {})              # 沒有環境變數、--yes：不猜，NOT_RUN
        self.assertEqual((r, status), (None, "not_run"))
        other = self.p("cli", "cra-project", "CRA", "Reports")
        os.makedirs(other)
        open(os.path.join(other, "vex.cdx.json"), "w").write("{}")
        r, _, status = w.resolve_previous(self.p("cli"), self.tmp, PROJ, True, {w.PREVIOUS_ENV: self.p("out")})
        self.assertEqual((str(r), status), (other, "ok"))                                   # 命令列優先

    def test_not_run_states_are_not_gap(self):
        w = wiz_module()
        env = {w.PREVIOUS_ENV: self.p("out")}
        self.run_prepare(Fake([]))                                                            # 第一個正式 Release
        r, note, status = w.previous_from_env(PROJ, env)
        self.assertEqual((r, status), (None, "not_run"))
        self.assertIn("沒有前一個正式 Release", note)
        shutil.rmtree(self.p("out"))
        self.run_prepare(Fake([]), env={})                                                    # 不是正式 Release
        self.assertEqual(w.previous_from_env(PROJ, env)[2], "not_run")
        shutil.rmtree(self.p("out"))
        self.prepared(layers=("", "-bsp"))                                                    # 前一版沒有 -os 這一層：不能比，不是 GAP
        r, note, status = w.previous_from_env(PROJ + "-os", env)
        self.assertEqual((r, status), (None, "not_run"))
        self.assertIn("-os", note)

    def test_gap_states_are_not_silent(self):
        w = wiz_module()
        env = {w.PREVIOUS_ENV: self.p("out")}
        # 前一版有，但這層的 zip 壞了
        rel, blobs = prev_release("v1.0.0")
        blobs[101] = b"broken"
        rel["assets"][1]["size"] = 6
        self.run_prepare(Fake([rel], blobs))
        self.assertEqual(w.previous_from_env(PROJ, env)[2], "ok")
        r, note, status = w.previous_from_env(PROJ + "-bsp", env)
        self.assertEqual((r, status), (None, "gap"))
        self.assertIn("讀不了", note)
        # 整個 API 失敗
        shutil.rmtree(self.p("out"))

        class Boom(Fake):
            def list_releases(self):
                raise pr.PrevError("GitHub API 失敗（HTTP 403）")
        self.run_prepare(Boom([]))
        r, note, status = w.previous_from_env(PROJ, env)
        self.assertEqual((r, status), (None, "gap"))
        self.assertIn("403", note)
        # 資料夾不存在、沒有 manifest、manifest 壞掉、層的資料夾被清掉、符號連結
        self.assertEqual(w.previous_from_env(PROJ, {w.PREVIOUS_ENV: self.p("nowhere")})[2], "gap")
        os.makedirs(self.p("empty"))
        self.assertEqual(w.previous_from_env(PROJ, {w.PREVIOUS_ENV: self.p("empty")})[2], "gap")
        open(self.p("empty", pr.MANIFEST), "w").write("[not json")
        self.assertEqual(w.previous_from_env(PROJ, {w.PREVIOUS_ENV: self.p("empty")})[2], "gap")
        shutil.rmtree(self.p("out"))
        self.prepared()
        shutil.rmtree(self.p("out", PROJ))
        self.assertEqual(w.previous_from_env(PROJ, env)[2], "gap")                           # manifest 說 OK、資料夾卻不見
        os.symlink(self.p("out"), self.p("link"))
        self.assertEqual(w.previous_from_env(PROJ + "-os", {w.PREVIOUS_ENV: self.p("link")})[2], "gap")

    def test_missing_layer_is_not_run_even_when_another_layer_is_broken(self):
        """前一版沒有 -os 這一層、-bsp 的 zip 壞了（整體 GAP）：-os 是 NOT_RUN（僅供參考），壞的 -bsp 才是 GAP，好的那層照常 OK。"""
        w = wiz_module()
        env = {w.PREVIOUS_ENV: self.p("out")}
        rel, blobs = prev_release("v1.0.0", layers=("", "-bsp"))
        blobs[101] = b"broken"
        rel["assets"][1]["size"] = 6
        st, _, doc = self.run_prepare(Fake([rel], blobs))
        self.assertEqual(st, "GAP")
        self.assertEqual(w.previous_from_env(PROJ + "-os", env)[2:], ("not_run",))
        r, note, status = w.previous_from_env(PROJ + "-os", env)
        self.assertIsNone(r)
        self.assertIn("-os", note)
        self.assertEqual(w.previous_from_env(PROJ + "-bsp", env)[2], "gap")
        self.assertEqual(w.previous_from_env(PROJ, env)[2], "ok")

    def test_missing_layer_stays_gap_when_nothing_was_enumerated(self):
        """整體 GAP 不是因為某一層（沒找到前一版、沒列出任何層）：每一層都照整體記 GAP，不能因為「不在 layers 裡」就變成 NOT_RUN。"""
        w = wiz_module()
        env = {w.PREVIOUS_ENV: self.p("out")}
        self.run_prepare(Fake([release("%s/v1.0.0" % PROJ), release("%s/v1.0.0" % PROJ, rid=2)]))      # 同 tag 兩個正式 Release：排不出
        self.assertEqual(w.previous_from_env(PROJ + "-os", env)[2], "gap")
        doc = json.load(open(self.p("out", pr.MANIFEST), encoding="utf-8"))
        doc.update(status="GAP", previous_tag="acme-board/v1.0.0", layers={})                         # 找到前一版、但沒有列出任何層
        json.dump(doc, open(self.p("out", pr.MANIFEST), "w", encoding="utf-8"))
        self.assertEqual(w.previous_from_env(PROJ, env)[2], "gap")
        doc.update(previous_tag=None, layers={PROJ: {"status": "OK"}})                                 # 沒有前一版 tag 卻有層：不可信，照整體
        json.dump(doc, open(self.p("out", pr.MANIFEST), "w", encoding="utf-8"))
        self.assertEqual(w.previous_from_env(PROJ + "-os", env)[2], "gap")

    def test_old_format_states_are_not_run_for_the_wizard(self):
        """前一版沒有報告 zip（整體 NOT_RUN），或某一層缺 VEX（那一層 NOT_RUN）：精靈記 not_run（僅供參考），不是 gap。"""
        w = wiz_module()
        env = {w.PREVIOUS_ENV: self.p("out")}
        self.run_prepare(Fake([release("%s/v1.0.0" % PROJ)]))
        r, note, status = w.previous_from_env(PROJ, env)
        self.assertEqual((r, status), (None, "not_run"))
        self.assertIn("舊格式", note)
        shutil.rmtree(self.p("out"))
        rel, blobs = prev_release("v1.0.0")
        blobs[101] = make_zip({"報告/其他.txt": b"x"})
        rel["assets"][1]["size"] = len(blobs[101])
        self.assertEqual(self.run_prepare(Fake([rel], blobs))[0], "OK")
        self.assertEqual(w.previous_from_env(PROJ + "-bsp", env)[2], "not_run")
        self.assertIn("舊格式", w.previous_from_env(PROJ + "-bsp", env)[1])
        self.assertEqual(w.previous_from_env(PROJ, env)[2], "ok")

    def test_layer_folder_must_be_exactly_that_layer(self):
        """manifest 的 layers 鍵與資料夾名稱不可帶路徑；名稱 .、.. 不接受。"""
        w = wiz_module()
        self.prepared()
        for bad in ("..", ".", ""):
            r, note, status = w.previous_from_env(bad, {w.PREVIOUS_ENV: self.p("out")})
            self.assertIsNone(r)
            self.assertNotEqual(status, "ok", bad)

    def test_reports_dir_of_does_not_follow_symlinks(self):
        """精靈的 reports_dir_of：符號連結的資料夾、符號連結的 vex.cdx.json 都不採用（M25）；一般資料夾的三種給法都可以。"""
        w = wiz_module()
        P = __import__("pathlib").Path
        real = self.p("real", "CRA", "Reports")
        os.makedirs(real)
        open(os.path.join(real, "vex.cdx.json"), "w").write("{}")
        self.assertEqual(w.reports_dir_of(real), P(real))                                    # 對照：一般資料夾可以
        self.assertEqual(w.reports_dir_of(self.p("real")), P(real))
        os.symlink(real, self.p("link-reports"))
        self.assertIsNone(w.reports_dir_of(self.p("link-reports")))                          # 本身是符號連結
        os.makedirs(self.p("proj", "CRA"))
        os.symlink(real, self.p("proj", "CRA", "Reports"))
        self.assertIsNone(w.reports_dir_of(self.p("proj")))                                  # CRA/Reports 是符號連結
        os.makedirs(self.p("proj2", "cra-project", "CRA"))
        os.symlink(real, self.p("proj2", "cra-project", "CRA", "Reports"))
        self.assertIsNone(w.reports_dir_of(self.p("proj2")))                                 # cra-project/CRA/Reports 是符號連結
        os.makedirs(self.p("vl", "CRA", "Reports"))
        os.symlink(os.path.join(real, "vex.cdx.json"), self.p("vl", "CRA", "Reports", "vex.cdx.json"))
        self.assertIsNone(w.reports_dir_of(self.p("vl")))                                    # vex.cdx.json 是符號連結
        self.assertIsNone(w.reports_dir_of(self.p("nowhere")))
        # 用在前一版資料夾：<資料夾>/<層名稱> 是符號連結 → GAP，不採用
        self.prepared()
        shutil.rmtree(self.p("out", PROJ))
        os.symlink(real, self.p("out", PROJ))
        r, note, status = w.previous_from_env(PROJ, {w.PREVIOUS_ENV: self.p("out")})
        self.assertEqual((r, status), (None, "gap"))

    def test_report_package_produces_pm_csaf_from_prepared_folder(self):
        """前一版的 zip → previous_release → 精靈的 previous_from_env → report_package --csaf-previous：交給PM/CSAF/ 真的產生。"""
        cra = os.path.join(ROOT, "tools", "cra")
        sys.path[:0] = [cra, os.path.join(cra, "tests")]
        try:
            import csaf_advisory as ca
            import report_package as rp
            from test_csaf_advisory import CFG, NEW, OLD, SBOM_NEW, csaf_validator, reports as csaf_reports
            from test_report_package import MIX, project
        finally:
            del sys.path[:2]
        old = csaf_reports(__import__("pathlib").Path(self.p("oldsrc")), "1.0.0", OLD)
        vex, summ = (old / "vex.cdx.json").read_bytes(), (old / "summary.json").read_bytes()
        zdata = make_zip({pr.VEX_MEMBER: vex, pr.SUMMARY_MEMBER: summ})
        rel = release("%s/v1.0.0" % PROJ, [{"id": 5, "name": "report-%s-v1.0.0.zip" % PROJ, "size": len(zdata), "state": "uploaded"}])
        st, note, doc = self.run_prepare(Fake([rel], {5: zdata}))
        self.assertEqual(st, "OK", note)
        w = wiz_module()
        prev, _, status = w.previous_from_env(PROJ, {w.PREVIOUS_ENV: self.p("out")})
        self.assertEqual(status, "ok")
        P = __import__("pathlib").Path
        p = project(P(self.p("proj")), MIX)
        src = csaf_reports(P(self.p("newsrc")), "1.1.0", NEW, 3, SBOM_NEW)
        for n in ("vex.cdx.json", "sbom.cdx.json", "summary.json"):
            shutil.copyfile(src / n, p / "CRA" / "Reports" / n)
        (p / "CRA" / "Config" / "config.json").write_text(json.dumps(dict(CFG, product={"name": "ACME-X100", "version": "1.1.0"})), encoding="utf-8")
        out = P(self.p("report"))
        code, msgs = rp.build(p, out, allow_tmp=True, csaf_previous=prev)
        f = out / "交給PM" / "CSAF" / "csaf-fix-advisory-ACME-X100-1.1.0.json"
        self.assertTrue(f.is_file(), msgs)
        d = json.loads(f.read_text(encoding="utf-8"))
        self.assertEqual(d["document"]["tracking"]["status"], "draft")
        self.assertFalse(list(csaf_validator().iter_errors(d)))
        self.assertTrue(any(m.startswith("CSAF 修補公告草稿：") for m in msgs), msgs)
        # 沒有資料時（NOT_RUN）report_package 不給 --csaf-previous：訊息寫 NOT_RUN，也沒有「未產生的項目」
        out2 = P(self.p("report2"))
        code2, msgs2 = rp.build(p, out2, allow_tmp=True)
        self.assertTrue(any("CSAF 修補公告：未產生（NOT_RUN" in m for m in msgs2))
        self.assertFalse((out2 / "交給PM" / "未產生的項目.md").exists())


    def test_gap_step_is_listed_and_not_run_step_is_not(self):
        """精靈記的步驟：gap（有前一版但資料不能用）→ report_package 列在「未產生的項目」（GAP）；not_run（僅供參考）→ 不列。"""
        cra = os.path.join(ROOT, "tools", "cra")
        sys.path[:0] = [cra, os.path.join(cra, "tests")]
        try:
            import report_package as rp
            from test_csaf_advisory import CFG, NEW, SBOM_NEW, reports as csaf_reports
            from test_report_package import MIX, project
        finally:
            del sys.path[:2]
        P = __import__("pathlib").Path
        w = wiz_module()
        p = project(P(self.p("proj")), MIX)
        src = csaf_reports(P(self.p("newsrc")), "1.1.0", NEW, 3, SBOM_NEW)
        for n in ("vex.cdx.json", "sbom.cdx.json", "summary.json"):
            shutil.copyfile(src / n, p / "CRA" / "Reports" / n)
        (p / "CRA" / "Config" / "config.json").write_text(json.dumps(dict(CFG, product={"name": "ACME-X100", "version": "1.1.0"})), encoding="utf-8")
        d = P(self.p("ic"))
        d.mkdir()
        w.add_info_step(d, w.csaf_previous_plan(None, "GitHub API 失敗（HTTP 403）", "gap", "both", True)[1])
        code, msgs = rp.build(p, P(self.p("o-gap")), allow_tmp=True, inputs_check=d / "inputs-check.json")
        text = (P(self.p("o-gap")) / "交給PM" / "未產生的項目.md").read_text(encoding="utf-8")
        self.assertEqual(code, 2)
        self.assertIn("CSAF 修補公告草稿", text)
        self.assertIn("HTTP 403", text)
        self.assertIn("GAP", text)
        w.add_info_step(d, w.csaf_previous_plan(None, "沒有前一個正式 Release", "not_run", "both", True)[1])
        code, msgs = rp.build(p, P(self.p("o-nr")), allow_tmp=True, inputs_check=d / "inputs-check.json")
        self.assertEqual(code, 0, msgs)
        self.assertFalse((P(self.p("o-nr")) / "交給PM" / "未產生的項目.md").exists())
        self.assertTrue(any("NOT_RUN" in m and "CSAF" in m for m in msgs))


# ---------------------------------------------------------------- workflow（靜態檢查）

class Workflow(unittest.TestCase):
    def setUp(self):
        self.text = open(os.path.join(ROOT, ".github", "workflows", "pipeline.yml"), encoding="utf-8").read()

    def step(self, name_part):
        parts = re.split(r"\n      - ", self.text)
        got = [p for p in parts if p.startswith("name: ") and name_part in p.splitlines()[0]]
        self.assertEqual(len(got), 1, name_part)
        return got[0]

    def test_token_only_on_tag_push_and_only_in_that_step(self):
        s = self.step("前一個正式 Release 的報告")
        self.assertIn("GITHUB_TOKEN: ${{ (github.event_name == 'push' && github.ref_type == 'tag') && github.token || '' }}", s)
        self.assertIn("previous_release.py prepare", s)
        self.assertIn("DUMPLING_PREVIOUS_REPORTS=", s)
        scan = self.step("scan（臨時 DT")
        self.assertNotIn("GITHUB_TOKEN", scan)
        self.assertNotIn("github.token", scan)

    def test_runs_before_scan_and_after_assemble(self):
        i = self.text.index("previous_release.py prepare")
        self.assertLess(self.text.index("name: assemble"), i)
        self.assertLess(i, self.text.index("pipeline/run-step.sh scan"))

    def test_github_env_write_refuses_newline_and_cr_in_path(self):
        """路徑會寫進 $GITHUB_ENV（一行一個變數）：含換行或 CR 就多寫出別的變數 → 寫入前要擋、不能默默寫。這裡真的跑那一步的 shell 檢查。"""
        s = self.step("前一個正式 Release 的報告")
        self.assertRegex(s, r"(?s)\$'\\n'.*\$'\\r'.*::error::.*exit 1")
        i = s.index('o="$DUMPLING_OUT_BASE')
        pre = s[i:s.index('mkdir -p "$o"')]                                         # o= 與檢查
        w = s.index('echo "DUMPLING_PREVIOUS_REPORTS=')
        self.assertLess(s.index("case \"$o\" in"), s.index('mkdir -p "$o"'))              # 檢查在建資料夾、呼叫腳本之前，也就在寫 GITHUB_ENV 之前
        self.assertLess(s.index('mkdir -p "$o"'), w)
        tmp = tempfile.mkdtemp(prefix="dumpling-wf-")
        self.addCleanup(shutil.rmtree, tmp, True)
        for label, proj, ok in (("normal", "acme-board", True), ("lf", "acme\nINJECT=1", False), ("cr", "acme\rINJECT=1", False), ("trailing-lf", "acme-board\n", False)):
            genv = os.path.join(tmp, "env-" + label)
            script = pre + 'echo reached\necho "DUMPLING_PREVIOUS_REPORTS=$o/previous-release" >> "$GITHUB_ENV"\n'
            r = subprocess.run(["bash", "-e", "-c", script], capture_output=True, text=True, cwd=tmp,
                               env={"PATH": os.environ.get("PATH", ""), "DUMPLING_OUT_BASE": tmp + "/out", "DUMPLING_IN_PROJECT": proj,
                                    "DUMPLING_IN_VERSION": "v1.0.0", "GITHUB_ENV": genv})
            if ok:
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(open(genv, encoding="utf-8").read(), "DUMPLING_PREVIOUS_REPORTS=%s/out/acme-board/v1.0.0/previous-release\n" % tmp)
            else:
                self.assertEqual(r.returncode, 1, label)
                self.assertIn("::error::", r.stdout, label)
                self.assertNotIn("reached", r.stdout, label)
                self.assertFalse(os.path.exists(genv), label)                                # 什麼都沒寫
                self.assertNotIn("INJECT", r.stdout + r.stderr)

    def test_no_platform_scan_script_mentions_it(self):
        for rel in ("pipeline/platforms/jetson/scan.sh", "pipeline/platforms/_shared/scan-disk.sh"):
            self.assertNotIn("previous", open(os.path.join(ROOT, rel), encoding="utf-8").read().lower().replace("previous release", ""), rel)


if __name__ == "__main__":
    unittest.main()
