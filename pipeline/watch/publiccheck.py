#!/usr/bin/env python3
"""publiccheck.py：寫進公開 Issue 之前的文字檢查（ci/public-check.sh 的通用規則與信箱規則，給 Python 用）。

用法（程式內）：problems = check_text(text)  → [說明, …]；空清單＝可以寫。
指令：python3 -I pipeline/watch/publiccheck.py <檔案>…  → 每個命中一行，最後一行 PUBLICCHECK<TAB>OK|FAIL<TAB>說明；結束碼 0／1。
規則：
  - ci/public-patterns.txt 的每一條（ERE、不分大小寫；POSIX 字元類 [:space:] 換成 \\s）。
    **不放行 /home/runner/**（ci/public-check.sh 對 repo 檔案放行它；Issue 內文不應出現任何 runner 路徑）。
  - 信箱：與 ci/public-check.sh 相同的白名單（noreply、example、保留 TLD）。
  - ci/public-allow.txt：完整字串白名單，命中的那一行含白名單字串（前後不緊接 [A-Za-z0-9._%+@-]）就不報；項目少於 6 字元或以 @／. 開頭 → 規則檔錯誤（FAIL）。
本機禁用字（~/.config/dumpling/forbidden.txt）CI 沒有，這裡不檢查；本機推送時由 pre-push hook 檢查。
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PATTERNS = os.path.join(ROOT, "ci", "public-patterns.txt")
ALLOW = os.path.join(ROOT, "ci", "public-allow.txt")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
EMAIL_ALLOW = re.compile(r"(noreply@anthropic\.com|@users\.noreply\.github\.com|noreply@github\.com|@example\.(com|org|net)"
                         r"|@([A-Za-z0-9-]+\.)*[A-Za-z0-9-]+\.(example|invalid|test|localhost)|git@github\.com)$", re.I)
TOK = "A-Za-z0-9._%+@-"


class RuleError(Exception):
    pass


def _lines(path):
    with open(path, encoding="utf-8") as f:
        return [x.rstrip("\n") for x in f if x.strip() and not x.lstrip().startswith("#")]


def load_rules(patterns=PATTERNS, allow=ALLOW):
    pats = []
    for p in _lines(patterns):
        try:
            pats.append(re.compile(p.replace("[:space:]", r"\s"), re.I))
        except re.error as e:
            raise RuleError(f"public-patterns 規則無法編譯：{p!r}（{e}）")
    allows = []
    if os.path.isfile(allow):
        for line in _lines(allow):
            s = line.split("\t", 1)[0]
            if len(s) < 6 or s[0] in "@.":
                raise RuleError(f"public-allow 有不允許的項目：{s!r}")
            allows.append(re.compile(r"(^|[^" + TOK + r"])" + re.escape(s) + r"($|[^" + TOK + r"])"))
    return pats, allows


def check_text(text, rules=None):
    pats, allows = rules or load_rules()
    out = []
    for n, line in enumerate(str(text).splitlines() or [""], 1):
        if any(a.search(line) for a in allows):
            continue
        for p in pats:
            m = p.search(line)
            if m:
                out.append(f"第 {n} 行命中通用規則 {p.pattern!r}：{m.group(0).strip()[:60]!r}")
        for m in EMAIL_RE.finditer(line):
            if not EMAIL_ALLOW.search(m.group(0)):
                out.append(f"第 {n} 行有不允許的信箱")
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("用法：publiccheck.py <檔案>…", file=sys.stderr)
        return 64
    try:
        rules = load_rules()
    except (OSError, RuleError) as e:
        print(f"PUBLICCHECK\tFAIL\t{e}")
        return 1
    bad = 0
    for f in argv:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                probs = check_text(fh.read(), rules)
        except OSError as e:
            probs = [f"讀不到（{type(e).__name__}）"]
        for p in probs:
            print(f"{os.path.basename(f)}: {p}")
        bad += len(probs)
    print(f"PUBLICCHECK\t{'FAIL' if bad else 'OK'}\t{bad} 筆命中")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
