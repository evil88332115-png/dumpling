"""gitlab/.gitlab-ci.yml 的載入與 extends 展開（測試與 schema 驗證共用）。需要 PyYAML。"""
import copy
import re
from pathlib import Path

import yaml

CI_FILE = Path(__file__).resolve().parent.parent / ".gitlab-ci.yml"
RESERVED = {"stages", "variables", "default", "workflow", "include", "image", "services", "cache", "before_script", "after_script"}


class _Loader(yaml.SafeLoader):
    pass


def _reference(loader, node):
    # !reference [job, key] → 轉成字串陣列（與 GitLab 官方 schema 的寫法一致）
    return loader.construct_sequence(node)


_Loader.add_constructor("!reference", _reference)


def load(path=CI_FILE):
    with open(path, encoding="utf-8") as fh:
        return yaml.load(fh, Loader=_Loader)  # noqa: S506 — 自訂的 SafeLoader 子類


def _merge(base, over):
    """GitLab 的 extends 合併：hash 深度合併，其他（含陣列）由子項覆蓋。"""
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def resolve(doc, name, _seen=()):
    job = doc[name]
    ext = job.get("extends")
    if ext is None:
        return copy.deepcopy(job)
    if name in _seen:
        raise ValueError("extends 循環：" + name)
    parents = [ext] if isinstance(ext, str) else list(ext)
    merged = {}
    for p in parents:
        merged = _merge(merged, resolve(doc, p, _seen + (name,)))
    own = {k: v for k, v in job.items() if k != "extends"}
    return _merge(merged, own)


def jobs(doc):
    """(名稱 → 展開後的設定)，只含實際的 job（不含以 . 開頭的隱藏 job 與全域關鍵字）。"""
    return {n: resolve(doc, n) for n, v in doc.items() if n not in RESERVED and not n.startswith(".") and isinstance(v, dict)}


def hidden(doc):
    return {n: v for n, v in doc.items() if n.startswith(".")}


def expand_vars(text, variables):
    """展開 $VAR 與 ${VAR}（只用頂層 variables 的預設值）；找不到的保留原樣。"""
    def rep(m):
        k = m.group(1) or m.group(2)
        v = variables.get(k)
        return str(v) if v is not None else m.group(0)
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", rep, text)


if __name__ == "__main__":
    # python3 -I gitlab/tests/gitlabci.py tojson <yml> <out.json>：轉成 JSON（給 venv 裡的 schema 驗證用；venv 沒有 PyYAML）
    import json
    import sys
    if len(sys.argv) != 4 or sys.argv[1] != "tojson":
        print("用法：gitlabci.py tojson <yml> <out.json>", file=sys.stderr)
        sys.exit(2)
    print("PyYAML %s" % yaml.__version__)
    with open(sys.argv[3], "w", encoding="utf-8") as fh:
        json.dump(load(sys.argv[2]), fh, ensure_ascii=False)


# ---------- rules:if 的小型求值器（只支援範本用到的語法；其他語法一律拒絕） ----------
import re as _re

_TOK = _re.compile(r'\s*(\(|\)|&&|\|\||==|!=|=~|\$[A-Za-z_][A-Za-z0-9_]*|"[^"]*"|\'[^\']*\'|/(?:\\/|[^/])*/)')


def _tokens(expr):
    out, pos = [], 0
    while pos < len(expr):
        m = _TOK.match(expr, pos)
        if not m:
            if expr[pos:].strip() == "":
                break
            raise ValueError("rules:if 有不認得的語法：%r" % expr[pos:])
        out.append(m.group(1))
        pos = m.end()
    return out


def rule_matches(expr, ctx):
    """GitLab rules:if → bool。ctx：{變數名: 值}；沒有的變數是「未定義」（== "" 不成立、=~ 不成立、單獨出現是 false）。"""
    toks = _tokens(expr)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        t = peek()
        pos[0] += 1
        return t

    def value(t):
        if t.startswith("$"):
            return ctx.get(t[1:])
        if t[0] in "\"'":
            return t[1:-1]
        raise ValueError("比較的右邊要是變數或字串：%r" % t)

    def atom():
        t = take()
        if t == "(":
            v = disj()
            if take() != ")":
                raise ValueError("括號不成對")
            return v
        if not t or not t.startswith("$"):
            raise ValueError("要是變數：%r" % t)
        left = ctx.get(t[1:])
        op = peek()
        if op in ("==", "!="):
            take()
            right = value(take())
            eq = (left == right) if right is not None else (left is None)
            return eq if op == "==" else not eq
        if op == "=~":
            take()
            r = take()
            if not (r and r.startswith("/") and r.endswith("/")):
                raise ValueError("=~ 右邊要是 /regex/")
            return left is not None and _re.search(r[1:-1].replace("\\/", "/"), left) is not None
        return bool(left)

    def conj():
        v = atom()
        while peek() == "&&":
            take()
            v = atom() and v
        return v

    def disj():
        v = conj()
        while peek() == "||":
            take()
            v = conj() or v
        return v

    v = disj()
    if peek() is not None:
        raise ValueError("多餘的語法：%r" % toks[pos[0]:])
    return v


def job_when(job, ctx):
    """job 在這個 pipeline 的 when（第一條符合的規則；沒有符合 → never；沒有 rules → on_success）。"""
    rules = job.get("rules")
    if rules is None:
        return job.get("when", "on_success")
    for r in rules:
        if "if" not in r or rule_matches(r["if"], ctx):
            if "changes" in r and ctx.get("CI_PIPELINE_SOURCE") not in ("push", "merge_request_event"):
                pass        # 官方：tag、排程、手動 pipeline 的 changes 一律成立
            return r.get("when", job.get("when", "on_success"))
    return "never"


def pipeline_when(doc, ctx):
    """workflow:rules → 這條 pipeline 會不會建立（第一條符合的規則的 when；都不符合 → never）。"""
    for r in (doc.get("workflow") or {}).get("rules") or []:
        if "if" not in r or rule_matches(r["if"], ctx):
            return r.get("when", "always")
    return "never"
