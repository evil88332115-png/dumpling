"""pages.yml 的 deploy 開關：Pages 目前不開（使用者決定，2026-11-17），deploy 只在 repo 變數 DASHBOARD_PAGES=on 時跑。

沒有這個條件時，每次 trigger 判斷要更新，deploy 就會因為 Pages 沒開而失敗（404），Actions 上的紅色 run 會蓋掉真正的失敗。
build 不能有這個條件：儀表板照樣在 CI 產生、照樣當 artifact。用文字切出 job 區塊（不依賴 PyYAML）。
"""
import os
import re
import unittest

PAGES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", ".github", "workflows", "pages.yml")
GATE = "vars.DASHBOARD_PAGES == 'on'"


def jobs(text):
    """jobs: 底下每個 job（兩格縮排的鍵）→ 它的區塊文字。"""
    body = text.split("\njobs:\n", 1)[1]
    out, name = {}, None
    for line in body.split("\n"):
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            name = m.group(1)
            out[name] = []
        elif re.match(r"^\S", line):          # 回到頂層：jobs 結束
            break
        elif name:
            out[name].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


class PagesDeployGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(PAGES, encoding="utf-8") as fh:
            cls.text = fh.read()
        cls.jobs = jobs(cls.text)

    def test_jobs_found(self):
        self.assertEqual(sorted(self.jobs), ["build", "deploy"])

    def test_deploy_requires_variable(self):
        ifs = [l.strip() for l in self.jobs["deploy"].split("\n") if re.match(r"^    if:", l)]
        self.assertEqual(ifs, ["if: needs.build.outputs.go == 'true' && " + GATE])

    def test_deploy_is_the_only_job_with_pages_write(self):
        self.assertIn("pages: write", self.jobs["deploy"])
        self.assertIn("deploy-pages@", self.jobs["deploy"])
        self.assertNotIn("deploy-pages@", self.jobs["build"])

    def test_build_and_artifact_not_gated(self):
        self.assertNotIn("DASHBOARD_PAGES", self.jobs["build"])
        self.assertIn("upload-pages-artifact@", self.jobs["build"])

    def test_gate_only_on_deploy(self):
        # 只出現在 deploy 的 if 與檔頭說明：別的地方（例如 build 的步驟）不能拿它當條件
        lines = [l for l in self.text.split("\n") if "DASHBOARD_PAGES" in l and not l.lstrip().startswith("#")]
        self.assertEqual(len(lines), 1, lines)


if __name__ == "__main__":
    unittest.main()
