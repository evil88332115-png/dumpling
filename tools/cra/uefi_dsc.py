#!/usr/bin/env python3
"""平台 DSC：內建的 OpenSSL／Mbed TLS 有沒有被「編進」韌體的模組用到（盡力判斷，保守；只被 uefi_source.py 載入）。

輸入：樹（uefi_source.Tree，只讀、不跟隨樹外的符號連結）與實際使用的平台 DSC（樹內的相對路徑）、建置用的巨集
（`build -D NAME=VALUE`、-b/-t/-a；來自 Build/BUILDLOG_*.txt 或 --platform-define）。靜態文字分析，不執行任何東西，不解析 FDF。
做法：
  1. 把 DSC 與它的 !include 攤平，邊讀邊用巨集算 !if／!ifdef／!ifndef／!else／!elseif：**確定不生效**的行丟掉，
     **確定生效**的行標 active，算不出來（沒有給巨集、運算式看不懂）的標 maybe。DEFINE 與 `NAME = 值` 只在確定生效時記；
     maybe 的行裡定義的巨集記成「值不明」（用到它的條件就是 maybe）。
  2. 取出 [LibraryClasses*] 與 <LibraryClasses> 的「類別|INF」對應，以及 [Components*] 的模組 INF。
  3. 從每個模組 INF 讀它用到的函式庫類別（INF 的 [LibraryClasses*]），沿著對應走：
     reach_all＝active 與 maybe 的行、所有對應都算（超集）；reach_sure＝只用 active 的行，而且類別只對應到一個 INF。
結論（每個函式庫只有兩種）：
  yes      reach_sure 裡有該函式庫的 INF：證據是 Components 行 → 類別對應行 → … 的鏈（檔案:行）。
  unknown  其他一切。**沒有「no」**：靜態分析證明不了「沒有編進去」（FDF 不解析、巨集與環境不一定完整、INF 可能缺、有讀取上限…），
           所以「沒有走到」只記成事實提示（reached=False、unresolved 清單），**絕對不改變任何列的狀態或層級**。
"""
import os
import re

CAP = 4 * 1024 * 1024
MAX_FILES = 600
MAX_LINES = 600_000
MAX_INFS = 6000
MAX_INCLUDE_DEPTH = 16
EVIDENCE_MAX = 12

# 函式庫 → INF 路徑裡的標記（CryptoPkg/Library/OpensslLib/…、…/MbedTlsLib/…）
MARKERS = {"openssl": "/OpensslLib/", "mbedtls": "/MbedTlsLib/"}

IF_RE = re.compile(r"^!\s*(if|ifdef|ifndef)\b\s*(.*)$", re.I)
ELSE_RE = re.compile(r"^!\s*(else|elseif)\b\s*(.*)$", re.I)
ENDIF_RE = re.compile(r"^!\s*endif\b", re.I)
INC_RE = re.compile(r"^!\s*include\s+(.+)$", re.I)
MACRO_RE = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)")
SECTION_RE = re.compile(r"^\[([^\]]*)\]")
DEF_RE = re.compile(r"^(?:DEFINE\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", re.I)
UNKNOWN = object()          # 值不明的巨集


def _strip(s):
    for c in ("#", "//"):
        i = s.find(c)
        if i >= 0:
            s = s[:i]
    return s.strip()


def and3(a, b):
    if a is False or b is False:
        return False
    return True if (a is True and b is True) else None


def or3(a, b):
    if a is True or b is True:
        return True
    return False if (a is False and b is False) else None


def not3(a):
    return None if a is None else (not a)


class Cond:
    """!if 的運算式（三值：True／False／None＝算不出來）。支援 $(巨集)、==、!=、&&、||、!、括號、TRUE／FALSE、數字、字串。"""
    TOK = re.compile(r'\s*(&&|\|\||==|!=|<=|>=|<|>|\(|\)|!|"[^"]*"|\$\([A-Za-z_][A-Za-z0-9_]*\)|[^\s()&|!=<>]+)')

    def __init__(self, st, expr):
        self.st, self.t, self.i = st, [], 0
        pos = 0
        expr = expr.strip()
        while pos < len(expr):
            m = self.TOK.match(expr, pos)
            if not m:
                self.t = None
                return
            self.t.append(m.group(1))
            pos = m.end()

    def value(self):
        if self.t is None:
            return None
        try:
            v = self.or_()
        except (IndexError, ValueError):
            return None
        return v if self.i == len(self.t) else None

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def or_(self):
        v = self.and_()
        while self.peek() in ("||", "OR", "or"):
            self.i += 1
            v = or3(v, self.and_())
        return v

    def and_(self):
        v = self.not_()
        while self.peek() in ("&&", "AND", "and"):
            self.i += 1
            v = and3(v, self.not_())
        return v

    def not_(self):
        if self.peek() in ("!", "NOT", "not"):
            self.i += 1
            return not3(self.not_())
        return self.cmp_()

    def atom(self):
        t = self.peek()
        if t is None:
            raise ValueError
        self.i += 1
        if t == "(":
            v = self.or_()
            if self.peek() != ")":
                raise ValueError
            self.i += 1
            return ("b", v)
        m = MACRO_RE.fullmatch(t)
        if m:
            val = self.st.macros.get(m.group(1), None)
            if val is None and m.group(1) not in self.st.macros:
                return ("b", False) if (self.st.defines_known or (self.st.config_complete and m.group(1).startswith("CONFIG_"))) else ("b", None)
            if val is UNKNOWN:
                return ("b", None)
            return ("s", val)
        if "$(" in t:
            return ("b", None)
        return ("s", t.strip('"'))

    def truth(self, a):
        if a[0] == "b":
            return a[1]
        s = a[1].strip().strip('"').upper()
        if s in ("TRUE", "1", "Y"):
            return True
        if s in ("FALSE", "0", "N", ""):
            return False
        return None

    def cmp_(self):
        a = self.atom()
        op = self.peek()
        if op in ("==", "!=", "<", ">", "<=", ">="):
            self.i += 1
            b = self.atom()
            if a[0] == "b" or b[0] == "b":
                if (a[0] == "b" and a[1] is None) or (b[0] == "b" and b[1] is None):
                    return None
                a, b = ("s", str(a[1])) if a[0] == "b" else a, ("s", str(b[1])) if b[0] == "b" else b
            x, y = a[1].strip().strip('"'), b[1].strip().strip('"')
            if op in ("==", "!="):
                return (x == y) if op == "==" else (x != y)
            try:
                xi, yi = int(x, 0), int(y, 0)
            except ValueError:
                return None
            return {"<": xi < yi, ">": xi > yi, "<=": xi <= yi, ">=": xi >= yi}[op]
        return self.truth(a)


class State:
    def __init__(self, tree, defines, defines_known):
        self.tree = tree
        self.macros = dict(defines)
        self.defines_known = defines_known
        self.files = 0
        self.lines = []            # (file, lineno, text, act) act: True／None
        self.stack = []            # [parent_act, prev_taken, current_branch_act]
        self.problems = []
        self.blocking = []         # 讀不到的 DSC／include、沒解析成功而且「確定或可能生效」的 !include、超過上限：可能漏掉對應行，所以會擋住 uefi_image 的 DSC 佐證
        self.config_complete = False     # Kconfig 的設定檔（config.dsc.inc）完整列出所有 CONFIG_ 符號：沒列出的 CONFIG_ 就是沒定義
        self.read_files = []
        self.dirs = None

    def act(self):
        return self.stack[-1][2] if self.stack else True

    def roots(self):
        """INF／include 的搜尋根：樹、樹下的資料夾（套件路徑）、它們的下一層。"""
        if self.dirs is None:
            out = [""]
            top = self.tree.listdir("", 500) or []
            for d in top:
                if self.tree.isdir(d):
                    out.append(d)
            for d in list(out[1:]):
                for e in (self.tree.listdir(d, 300) or []):
                    if self.tree.isdir(f"{d}/{e}") and not e.startswith("."):
                        out.append(f"{d}/{e}")
            self.dirs = out
        return self.dirs

    def find(self, rel, near=None):
        """相對路徑 → 樹內存在的候選（去重）。near：include 它的檔案所在資料夾，有就優先只用它。"""
        rel = rel.strip().strip('"').replace("\\", "/").lstrip("/")
        if not rel or ".." in rel.split("/"):
            return []
        if near is not None:
            c = os.path.normpath(f"{near}/{rel}" if near else rel).replace(os.sep, "/")
            if self.tree.exists(c) and self.tree.resolve(c, record=False):
                return [c]
        found = []
        for r in self.roots():
            c = os.path.normpath(f"{r}/{rel}" if r else rel).replace(os.sep, "/")
            if c not in found and self.tree.exists(c) and self.tree.resolve(c, record=False):
                found.append(c)
        return found

    def expand(self, s):
        for _ in range(8):
            m = MACRO_RE.search(s)
            if not m:
                return s, True
            v = self.macros.get(m.group(1), None)
            if v is None or v is UNKNOWN:
                return s, False
            s = s[:m.start()] + v + s[m.end():]
        return s, False

    def branch(self, kind, expr, first):
        if kind in ("ifdef", "ifndef"):
            name, ok = self.expand(expr.strip())
            if not ok:
                v = None
            elif name in self.macros:
                v = self.macros[name] is not UNKNOWN or None
            else:
                v = False if (self.defines_known or (self.config_complete and name.startswith("CONFIG_"))) else None
            if kind == "ifndef":
                v = not3(v)
            return v
        return Cond(self, expr).value()

    def load(self, rel, depth, why):
        if depth > MAX_INCLUDE_DEPTH or self.files >= MAX_FILES or len(self.lines) > MAX_LINES:
            self.problems.append(f"{rel}: 超過讀取上限（include 深度、檔案數或行數）")
            self.blocking.append(f"{rel}: read limit exceeded (include depth, file count or line count)")
            return
        txt, err = self.tree.text(rel, CAP)
        self.files += 1
        if txt is None:
            self.problems.append(f"{rel}（{why}）: 讀不到（{err}）")
            self.blocking.append(f"{rel} ({why}): cannot be read")
            return
        self.read_files.append(rel)
        if os.path.basename(rel) == "config.dsc.inc" and re.search(r"^CONFIG_[A-Za-z0-9_]+=", txt, re.M):
            self.config_complete = True      # NVIDIA 的建置把完整的 Kconfig .config 轉成這個檔（沒列出的符號＝沒定義）
        near = os.path.dirname(rel)
        base = len(self.stack)
        for n, raw in enumerate(txt.splitlines(), 1):
            t = _strip(raw)
            if not t:
                continue
            m = IF_RE.match(t)
            if m:
                parent = self.act()
                cond = self.branch(m.group(1).lower(), m.group(2), True)
                self.stack.append([parent, cond, and3(parent, cond)])
                continue
            m = ELSE_RE.match(t)
            if m and self.stack:
                fr = self.stack[-1]
                if m.group(1).lower() == "else":
                    cond = True
                else:
                    cond = self.branch("if", m.group(2), False)
                # 前面的分支有任何一個確定成立 → 這個分支不成立；前面都確定不成立 → 看這個條件
                taken_before = fr[1]
                cur = and3(fr[0], and3(cond, not3(taken_before)))
                fr[1] = or3(taken_before, cond)
                fr[2] = cur
                continue
            if ENDIF_RE.match(t):
                if len(self.stack) > base:
                    self.stack.pop()
                continue
            a = self.act()
            if a is False:
                continue
            m = DEF_RE.match(t)
            if m and not t.startswith("!") and not re.search(r"[|:*]", t.split("=", 1)[0]):
                self.macros[m.group(1)] = m.group(2).strip().strip('"') if a is True else UNKNOWN
            inc = INC_RE.match(t)
            if inc:
                target, ok = self.expand(inc.group(1).strip())
                if not ok:
                    self.problems.append(f"{rel}:{n}: !include {inc.group(1).strip()}：巨集展開不了")
                    self.blocking.append(f"{rel}:{n}: !include {inc.group(1).strip()}: macro cannot be expanded ({'active' if a is True else 'maybe active'})")
                    continue
                if target == "/dev/null":
                    continue
                found = self.find(target, near)
                if not found:
                    self.problems.append(f"{rel}:{n}: !include {target}：樹裡找不到")
                    if not (self.config_complete and os.path.basename(target) == "config.dsc.inc"):      # 建置時產生的 Kconfig 檔，內容已由 --platform-defines 給了
                        self.blocking.append(f"{rel}:{n}: !include {target}: not found in the tree ({'active' if a is True else 'maybe active'})")
                    continue
                if len(found) > 1:       # 同名檔案在多處：全部讀（超集），而且都算 maybe
                    self.problems.append(f"{rel}:{n}: !include {target}：樹裡有 {len(found)} 個同名檔案（{', '.join(found[:3])}）")
                for f in found:
                    if len(found) > 1:
                        self.stack.append([a, None, None])
                    self.load(f, depth + 1, f"{rel}:{n}")
                    if len(found) > 1:
                        self.stack.pop()
                continue
            self.lines.append((rel, n, t, a))
        del self.stack[base:]


def _parse(lines):
    """行 → (對應 [(類別, 路徑, 檔, 行, act)], 元件 [(路徑, 檔, 行, act)])。"""
    maps, comps, section, blk = [], [], "", None
    for f, n, t, act in lines:
        if t.startswith("!") or t.upper().startswith("DEFINE "):
            continue
        m = SECTION_RE.match(t)
        if m:
            section = m.group(1).split(",")[0].split(".")[0].strip().lower()
            blk = None
            continue
        if section == "libraryclasses" and "|" in t:
            c, p = [x.strip() for x in t.split("|")[:2]]
            maps.append((c, p, f, n, act))
        elif section == "components":
            if t.startswith("}"):
                blk = None
            elif t == "{":
                blk = "other"
            elif t.startswith("<"):
                blk = "lc" if t.strip("<> ").lower() == "libraryclasses" else "other"
            elif blk == "lc":
                if "|" in t:
                    c, p = [x.strip() for x in t.split("|")[:2]]
                    maps.append((c, p, f, n, act))
            elif blk is None:
                p = t.rstrip("{").strip().split("|")[0].strip()
                if p.lower().endswith(".inf"):
                    comps.append((p, f, n, act))
                    if t.endswith("{"):
                        blk = "other"
    return maps, comps


def _inf_classes(tree, rel, cache):
    """INF → 用到的函式庫類別集合（[LibraryClasses*]）。讀不到 → None。"""
    if rel in cache:
        return cache[rel]
    txt, err = tree.text(rel, CAP)
    if txt is None:
        cache[rel] = None
        return None
    classes, sec = set(), ""
    for raw in txt.splitlines():
        t = _strip(raw)
        if not t:
            continue
        m = SECTION_RE.match(t)
        if m:
            sec = m.group(1).split(",")[0].split(".")[0].strip().lower()
            continue
        if sec == "libraryclasses":
            classes.add(t.split("|")[0].strip())
    cache[rel] = classes
    return classes


def analyze(tree, dsc_rels, defines=None, defines_known=False, config_complete=False):
    """→ {"dsc": [...], "problems": [...], "libs": {kind: {"state", "evidence", "reasons"}}}。
    defines：建置時的巨集（-D、TARGET、TOOL_CHAIN_TAG、ARCH…）；defines_known：這份巨集是完整的（沒有的名稱＝沒定義）。"""
    out = {"dsc": list(dsc_rels), "problems": [], "libs": {}, "defines_known": bool(defines_known)}
    if not dsc_rels:
        why = ["no platform DSC was given or found (--platform-dsc; Build/BUILDLOG_*.txt names the active platform)"]
        out["libs"] = {k: {"state": "unknown", "evidence": [], "reasons": why} for k in MARKERS}
        return out
    st = State(tree, defines or {}, defines_known)
    st.config_complete = bool(config_complete)
    for d in dsc_rels:
        st.load(d, 0, "platform DSC")
    maps, comps = _parse(st.lines)
    out["files_read"], out["components"], out["mappings"] = len(st.read_files), len(comps), len(maps)
    out["blocking_problems"] = list(st.blocking)[:20]       # 可能漏掉函式庫類別對應的未解析項目（uefi_image.corroborate 用）
    out["config_complete"] = st.config_complete
    # 密碼函式庫相關的類別對應（uefi_image.corroborate 用：DSC 把 OpensslLib／BaseCryptLib／TlsLib 對應到哪個 INF；active＝確定生效的行）
    out["class_mappings"] = [{"class": c, "path": st.expand(p)[0], "file": f, "line": n, "active": act}
                             for c, p, f, n, act in maps if re.search(r"OpensslLib|MbedTls|CryptLib|TlsLib", c + p, re.I)][:200]
    cache, problems = {}, list(st.problems)

    rcache = {}

    def resolve(path, f, n):
        """INF の相対パス → 樹内のパス。解けないと、その行は「使われたとき」に問題として記録される（呼び出し側で）。"""
        p, ok = st.expand(path)
        if not ok:
            return None, f"{f}:{n}: {path}：巨集展開不了"
        if p not in rcache:
            found = st.find(p)
            rcache[p] = found[0] if found else None
        return rcache[p], (None if rcache[p] else f"{f}:{n}: {p}：樹裡找不到")

    # 対応は生のパス（巨集展開後）で持つ。実在の確認は「その INF に辿り着いたとき」にやる（使われない対応の INF が無くても結論に影響しない）
    by_class, by_class_sure = {}, {}
    for c, p, f, n, act in maps:
        key = st.expand(p)[0]
        cur = by_class.setdefault(c, {})
        if key not in cur or (act is True and cur[key][2] is not True):
            cur[key] = (f, n, act, p)
    for c, targets in by_class.items():
        if len(targets) == 1:
            key, (f, n, act, p) = next(iter(targets.items()))
            if act is True:
                by_class_sure[c] = (key, f, n, p)
    roots = []
    for p, f, n, act in comps:
        r, why = resolve(p, f, n)
        if r is None:
            problems.append(why)         # 元件は必ず「使われる」ので、見つからなければ問題
        else:
            roots.append((r, f, n, act))
    null_infs = [(key, v) for c, ts in by_class.items() if c.upper() == "NULL" for key, v in ts.items()]

    def reach(sure):
        seen, parent, queue = {}, {}, []

        def add(r, f, n, kind, prev):
            if r not in seen:
                seen[r] = (f, n)
                parent[r] = (kind, f, n, prev)
                queue.append(r)
        for r, f, n, act in roots:
            if not (sure and act is not True):
                add(r, f, n, "component", None)
        if not sure:
            for key, (f, n, act, p) in null_infs:
                r, why = resolve(p, f, n)
                if r is None:
                    problems.append(why)
                else:
                    add(r, f, n, "NULL library", None)
        while queue:
            if len(seen) >= MAX_INFS:
                problems.append(f"INF 數量超過上限 {MAX_INFS}：沒有走完")
                break
            cur = queue.pop(0)
            cls = _inf_classes(tree, cur, cache)
            if cls is None:
                problems.append(f"{cur}: INF 讀不到")
                continue
            for c in sorted(cls):
                if sure:
                    t = by_class_sure.get(c)
                    targets = [(t[3], t[1], t[2])] if t else []
                else:
                    targets = [(v[3], v[0], v[1]) for v in by_class.get(c, {}).values()]
                for p, f, n in targets:
                    r, why = resolve(p, f, n)
                    if r is None:
                        problems.append(why + f"（類別 {c}，被 {cur} 用到）")
                    else:
                        add(r, f, n, c, cur)
        return seen, parent

    all_seen, all_parent = reach(False)
    sure_seen, sure_parent = reach(True)
    out["missing_inf"] = sorted({x for x in problems if x not in set(st.problems)})[:200]       # INF 找不到／讀不到（不是 include）
    problems = sorted(set(problems))
    out["problems"], out["problems_count"] = problems[:50], len(problems)
    out["inf_reachable"] = len(all_seen)

    def chain(parent, r):
        lines = []
        while r is not None and len(lines) < EVIDENCE_MAX:
            kind, f, n, prev = parent[r]
            lines.append(f"{f}:{n}: " + ("module " if kind == "component" else f"class {kind} -> ") + r)
            r = prev
        return list(reversed(lines))

    for kind, mark in MARKERS.items():
        hit_sure = sorted(r for r in sure_seen if mark in "/" + r)
        hit_all = sorted(r for r in all_seen if mark in "/" + r)
        e = {"state": "unknown", "evidence": [], "reasons": []}
        if hit_sure:
            e.update(state="yes", evidence=[f"platform DSC {', '.join(dsc_rels)}: reached through lines that are certainly active"]
                     + chain(sure_parent, hit_sure[0]))
        elif hit_all:
            e["reasons"].append(f"referenced only through lines that may or may not be active, or through ambiguous class mappings ({hit_all[0]})")
            e["evidence"] = chain(all_parent, hit_all[0])
        else:
            crypto = [(c, next(iter(ts.items()))) for c, ts in sorted(by_class.items()) if c in ("BaseCryptLib", "OpensslLib", "MbedTlsLib")]
            name = mark.strip("/")
            e["reasons"].append(
                f"No path to {name} was found through the analysed DSC; absence is not proven (FDF not parsed, build macros and environment"
                f"{' known only from the build log' if defines_known else ' not fully known'}, "
                + (f"{len(problems)} unresolved item(s), first: {problems[0]}, " if problems else "")
                + "static analysis only)")
            e["evidence"] = [f"fact only, not a conclusion: platform DSC {', '.join(dsc_rels)}: {out['files_read']} DSC file(s) read (incl. !include), "
                             f"{len(comps)} component(s), {len(all_seen)} INF(s) reachable through the class mappings; none of them is under {name}/"]\
                + [f"{v[1][0]}:{v[1][1]}: {c}|{v[1][3]}" for c, v in crypto][:6]
            e["reached"] = False
        e.setdefault("reached", bool(hit_all))
        e["unresolved"] = problems[:10]
        out["libs"][kind] = e
    return out
