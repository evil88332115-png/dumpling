"""WP7 三個平台（raspberrypi、rockchip、ai-nas）的 notes.md（＝Release 說明）不帶 http(s):// 網址。
2026-11-17 ai-nas 草稿：body 帶「https://github.com/openmediavault/openmediavault.git」時 POST /releases 連續 16 次 403
（run 44040129677 兩次），同一份 scan 拿掉 https:// 後一次成功（run 44051748503）。原因沒有查出來；網址照樣寫，只是不帶 scheme。
所有平台共用的最後一道防線在 Release 說明的寫入端（C1，release-meta.py）；這裡鎖住 WP7 自己產生的段落。合成資料、不連網。"""
import os
import re
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "platforms", "_shared"))
import wp7_scan  # noqa: E402

SCHEME = re.compile(r"https?://", re.I)
URL = "https://example.org/x"   # 塞進每一個自由文字欄位（精靈或上游工具的說明文字可能帶網址）


def ai_nas_repo():
    """projects/ai-nas-demo/sources.yml 的 app_repo（實際會進 notes 的那個值）。"""
    with open(os.path.join(ROOT, "projects", "ai-nas-demo", "sources.yml"), encoding="utf-8") as fh:
        m = re.search(r"^\s*app_repo:\s*(\S+)\s*$", fh.read(), re.M)
    return m.group(1)


def extras(platform):
    """各平台 collect 交給 Wp7Hooks 的欄位（形狀照 wp7_scan.main 的 collect）；自由文字欄位都帶網址。"""
    x = {"services": {"status": "NOT_ASSESSED", "reason": "平台沒有定義清單 " + URL}}
    if platform == "raspberrypi":
        x["services"] = {"status": "LISTED", "reason": "r " + URL,
                         "items": [{"name": "rpi-connect-lite", "version": "2.13.0", "layer": "os", "why": "遠端連線 " + URL}]}
    if platform == "rockchip":
        x["raw_sectors"] = {"status": "GAP", "gaps": ["讀不到 " + URL],
                            "regions": [{"start_lba": 64, "slot": "idbloader", "identity": {"versions": [{"component": "u-boot", "version": "2017.09"}]},
                                         "corroboration": [{"source": URL, "state": "match"}]}]}
        x["kernel_upstream"] = {"status": "OK", "requested_upstream": "6.1.84", "kernel_release": "6.1.84-8-rk2410",
                                "sources": {"image_modules": {"upstream_from_release": "6.1.84"}, "source_makefile": {"version": "6.1.84"}},
                                "gaps": ["來源 " + URL], "shipped_config": {"path": "/boot/config"}}
        x["kernel_cna_count"] = 1
    if platform == "ai-nas":
        x["source"] = {"repo": ai_nas_repo(), "commit": "9d8530ffa6912ece116bc6c74d0f3d06045b6c26", "line": "OK " + URL,
                       "app_name": "openmediavault", "app_version": "8.6.1-1", "cdxgen_root_name": "openmediavault-workbench",
                       "cdxgen_root_version": "0.0.0", "version_vs_commit": "NOT_ASSESSED"}
        x["kernel_source"] = {"status": "GAP", "basis": "上游 orig " + URL, "debian_version": "6.12.116-1",
                              "image_versions": ["6.12.116-1"], "reason": "下載失敗 " + URL}
    return x


def notes(platform, os_resp="customer"):
    h = wp7_scan.Wp7Hooks(extras(platform))
    ctx = {"asm": {"image_file": "img", "image_sha256": "0" * 64, "method": "串流 " + URL, "disk_sha256": "1" * 64},
           "runs": {"": {"report_status": "GAP", "release_gate": "GAP"}},
           "main_run": {"kernel_versions": {"shipped": ["k"], "requested": ["k"], "judged": [],
                                            "not_judged": [{"version": "k", "reason": "見 " + URL}]}},
           "layers": {"os_responsibility": os_resp}, "project": "p", "version": "v1"}
    return "\n".join(h.notes_build(ctx) + h.notes_after_vulnerabilities(ctx) + h.notes_attachments(ctx))


class DisplayUrl(unittest.TestCase):
    def test_scheme_and_dot_git_removed(self):
        self.assertEqual(wp7_scan.display_url("https://github.com/openmediavault/openmediavault.git"), "github.com/openmediavault/openmediavault")
        self.assertEqual(wp7_scan.display_url("http://example.org/a"), "example.org/a")
        self.assertEqual(wp7_scan.display_url("HTTPS://Example.org/a.git"), "Example.org/a")
        self.assertEqual(wp7_scan.display_url("github.com/x/y"), "github.com/x/y")
        self.assertIsNone(wp7_scan.display_url(None))

    def test_no_url_scheme_keeps_the_rest_of_the_line(self):
        self.assertEqual(wp7_scan.no_url_scheme(["a https://b/c d", "http://e", "沒有網址"]), ["a b/c d", "e", "沒有網址"])
        self.assertEqual(wp7_scan.no_url_scheme(["見https://b/c（`HTTPS://d`）"]), ["見b/c（`d`）"])   # 中文字後面緊接網址也要拿掉


class NotesHaveNoUrlScheme(unittest.TestCase):
    def test_each_wp7_platform(self):
        for plat in ("raspberrypi", "rockchip", "ai-nas"):
            for resp in ("customer", "ours"):
                with self.subTest(platform=plat, os_responsibility=resp):
                    t = notes(plat, resp)
                    self.assertIsNone(SCHEME.search(t), (plat, SCHEME.findall(t)))
                    self.assertIn("example.org/x", t)          # 網址照樣寫，只是不帶 scheme

    def test_ai_nas_source_line_uses_code_span_without_scheme(self):
        t = notes("ai-nas")
        self.assertTrue(ai_nas_repo().startswith("https://"))     # 前提：sources.yml 的值本身帶 https（collect 拿到的就是它）
        self.assertIn("- `github.com/openmediavault/openmediavault` commit `9d8530ffa6912ece116bc6c74d0f3d06045b6c26`：", t)

    def test_sections_are_still_there(self):
        for plat, heading in (("raspberrypi", "## 要特別注意的對外連線服務"), ("rockchip", "## 開機程式（分割區之前的原始磁區）"),
                              ("rockchip", "## 廠商 BSP 核心的上游版本（D-038）"), ("ai-nas", "## NAS 應用的原始碼"), ("ai-nas", "## 核心原始碼（D-035）")):
            self.assertIn(heading, notes(plat), plat)


if __name__ == "__main__":
    unittest.main()
