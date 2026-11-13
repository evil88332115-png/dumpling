"""watch.yml／watch-round.yml 的靜態測試：D-040 的「排程的 real 預設只算不寫」與「第一次基準要手動指定」（#49 驗證應修 1）。

不只比對字串：把 real job 的 `dry_run`／`allow_baseline` 運算式翻成 Python，對各種觸發情況求值（真值表），
運算式被改掉一段（例如拿掉 `WATCH_REAL_ISSUES != 'on'`）就會失敗。只用標準庫。
"""
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
WATCH = os.path.join(ROOT, ".github", "workflows", "watch.yml")
ROUND = os.path.join(ROOT, ".github", "workflows", "watch-round.yml")

_TOKEN = re.compile(r"\s*(\(|\)|&&|\|\||==|!=|'[^']*'|true|false|null|github\.event_name|vars\.[A-Z_]+|inputs\.[a-z_]+)")


def job_block(text, name):
    m = re.search(r"(?m)^  %s:\n((?:    .*\n|\s*\n)+)" % re.escape(name), text)
    if not m:
        raise AssertionError("watch.yml 沒有 job %s" % name)
    return m.group(1)


def expr_of(block, key):
    m = re.search(r"(?m)^\s+%s:\s*\$\{\{\s*(.+?)\s*\}\}\s*$" % re.escape(key), block)
    if not m:
        raise AssertionError("找不到 %s 的運算式" % key)
    return m.group(1)


def to_python(expr):
    """GitHub Actions 運算式（只允許這裡用得到的語法）→ Python 運算式；其他符號一律拒絕。"""
    out, pos = [], 0
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            raise AssertionError("運算式有不認得的語法：%r" % expr[pos:])
        t = m.group(1)
        if t.startswith("'"):
            t = t.lower()           # GitHub 比較字串不分大小寫：字面值與 ctx 的字串都轉小寫再比
        out.append({"&&": " and ", "||": " or ", "true": "True", "false": "False", "null": "None"}.get(t)
                   or (f"ctx[{t!r}]" if "." in t and not t.startswith("'") else t))
        pos = m.end()
    return "".join(out)


def evaluate(expr, ctx):
    # 規則與 GitHub 相同的部分：不存在的 vars／inputs 是空字串；字串比較不分大小寫；'' == true 是 false（這裡的組合只會遇到字串與布林）
    low = {k: (v.lower() if isinstance(v, str) else v) for k, v in ctx.items()}
    return bool(eval(to_python(expr), {"__builtins__": {}}, {"ctx": low}))  # noqa: S307（輸入只來自 repo 裡的 workflow，已限定語法）


def ctx(event, real_issues="", dry_run="", baseline=""):
    return {"github.event_name": event, "vars.WATCH_REAL_ISSUES": real_issues, "inputs.dry_run": dry_run, "inputs.baseline": baseline}


class WatchWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = open(WATCH, encoding="utf-8").read()
        cls.real = job_block(cls.text, "real")
        cls.round = open(ROUND, encoding="utf-8").read()

    def test_schedule_runs_real(self):
        self.assertIn("schedule:", self.text)
        cond = re.search(r"(?m)^\s+if:\s*(.+)$", self.real).group(1)
        self.assertTrue(evaluate(cond, ctx("schedule")))
        self.assertIn("mode: real", self.real)

    def test_scheduled_real_is_dry_run_unless_variable_is_on(self):
        e = expr_of(self.real, "dry_run")
        # 排程（inputs 都是空的）：變數不是 on 一律只算不寫
        for v in ("", "off", "true", "1", "yes", " on", "on "):
            self.assertTrue(evaluate(e, ctx("schedule", real_issues=v)), "排程、WATCH_REAL_ISSUES=%r 必須是 dry_run" % v)
        for v in ("on", "ON", "On"):        # GitHub 的字串比較不分大小寫
            self.assertFalse(evaluate(e, ctx("schedule", real_issues=v)), "WATCH_REAL_ISSUES=%r 時排程才真的寫" % v)
        # 手動：照輸入（變數不影響）
        for v in ("", "on"):
            self.assertTrue(evaluate(e, ctx("workflow_dispatch", real_issues=v, dry_run=True)))
            self.assertFalse(evaluate(e, ctx("workflow_dispatch", real_issues=v, dry_run=False)))

    def test_baseline_only_when_manually_requested(self):
        e = expr_of(self.real, "allow_baseline")
        for v in ("", "on"):
            self.assertFalse(evaluate(e, ctx("schedule", real_issues=v)), "排程不能自己建基準")
        self.assertFalse(evaluate(e, ctx("workflow_dispatch", baseline=False)))
        self.assertTrue(evaluate(e, ctx("workflow_dispatch", baseline=True)))

    def test_round_passes_dry_run_to_apply(self):
        # watch-round：dry_run 的值傳到 notify，apply 帶 --dry-run（不開 Issue、不寫狀態；test_issues 的 test_dry_run_writes_nothing 測 apply 本身）
        notify = re.search(r"(?ms)^  notify:\n(.*)", self.round).group(1)
        self.assertRegex(notify, r"DRY:\s*\$\{\{\s*inputs\.dry_run\s*\}\}")
        self.assertIn('if [ "$DRY" = true ]; then d=(--dry-run); fi', notify)
        self.assertRegex(notify, r'issues\.py apply [^\n]*"\$\{d\[@\]\}"')

    def test_feeds_step_has_own_timeout_and_report_still_runs(self):
        # 資料源卡住時：這一步自己逾時、job 繼續，後面照樣比對並留下報告；不完整的鏡像刪掉
        m = re.search(r"(?ms)^      - name: 資料源（[^\n]*\n(.*?)^      - name:", self.round)
        step = m.group(1)
        t = int(re.search(r"timeout-minutes:\s*(\d+)", step).group(1))
        job_t = int(re.search(r"(?ms)^  compute:.*?timeout-minutes:\s*(\d+)", self.round).group(1))
        self.assertLess(t, job_t - 30, "資料源的逾時要留時間給比對與報告")
        self.assertIn("continue-on-error: true", step)
        self.assertIn("if: steps.feeds.outcome != 'success'", self.round)
        self.assertIn('[ -f "$w/$n.result" ] || rm -rf', self.round)
        self.assertRegex(self.round, r"id: kcve-fresh\n\s+if: inputs\.mode == 'real' && steps\.feeds\.outcome == 'success'")

    def test_translator_rejects_unknown_syntax(self):
        with self.assertRaises(AssertionError):
            to_python("github.event_name == 'schedule' || format('x')")


if __name__ == "__main__":
    unittest.main()
