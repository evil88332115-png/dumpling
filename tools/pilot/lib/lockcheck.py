#!/usr/bin/env python3
"""lockcheck.py：依生態系判斷依賴樹是否可宣告為完整（CLAUDE.md 規則 11），給 sbomgate 的 --tree 與 --manifest 用。

用法：python3 -I lockcheck.py <原始碼資料夾> <輸出.json>
只讀檔名與 go.mod 的 require 行，不執行任何東西。

規則：
- 找出每個清單檔（遞迴；略過 .git、node_modules、vendor、虛擬環境），依生態系分組。
- 一個清單檔有「對應的鎖定檔」＝**同一資料夾**有該生態系的鎖定檔。上層資料夾的鎖定檔只在確認是工作區成員時才算
  （2026-10-23 複審：往上層找會把 docs/requirements.txt 之類的清單檔誤判為有鎖定檔）：
    npm／yarn：上層 package.json 的 "workspaces"（陣列或 {"packages": [...]}，glob）列入，且該層有 package-lock.json、
               npm-shrinkwrap.json、yarn.lock 或 bun.lock（npm/cli docs using-npm/workspaces.md；yarnpkg/berry docs features/workspaces）
    pnpm：上層 pnpm-workspace.yaml 的 packages（glob，「!」開頭為排除）列入，且該層有 pnpm-lock.yaml（pnpm.io docs/workspaces.md）
    Cargo：上層 Cargo.toml 的 [workspace] members（glob）列入、exclude 未排除，且該層有 Cargo.lock（Cargo Book 的 workspaces 章節，未逐字核對）
    uv：上層 pyproject.toml 的 [tool.uv.workspace] members 列入、exclude 未排除，且該層有 uv.lock（astral-sh/uv docs/concepts/projects/workspaces.md）
    Go：上層 go.work 的 use（單行或區塊）列入這個模組的資料夾，且該層有 go.work.sum（golang/go src/cmd/go/internal/workcmd/work.go）
  其他情況（無法判斷是否為成員、宣告格式讀不懂）一律 missing。
- Python 的鎖定檔與清單檔類型一一配對（2026-10-23 第三次審查）：
    pyproject.toml ↔ poetry.lock／uv.lock／pdm.lock／pylock.toml；能從 [tool.poetry]／[tool.pdm]／[tool.uv] 判斷工具時只認那個工具的鎖定檔
    Pipfile ↔ Pipfile.lock
    requirements*.txt、setup.py、setup.cfg → 一律 missing（同資料夾有別的鎖定檔也不算；全 == 釘選的 pip-compile 輸出之後再支援）
- 每個偵測到的生態系都要每個清單檔都有鎖定檔才算 lock；任一生態系缺鎖定檔 → tree=unknown（sbomgate 最多 PARTIAL），並列出缺的生態系。
- 沒有標準鎖定檔的生態系（Maven pom.xml）一律算缺。
- go.mod 沒有 require（沒有依賴）時不需要 go.sum。
- 一個清單檔都沒有時 tree=unknown（無法宣告完整；例如只有 vendored 原始碼的 C 專案）。
- sbomgate 只會核對 package.json 與 requirements*.txt；其他清單檔列在 manifests_not_checked（未比對）。
"""
import json
import os
import re
import sys
import tomllib

# 生態系：(清單檔判定, 鎖定檔名稱)
ECOSYSTEMS = {
    "npm": (lambda n: n == "package.json", ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")),
    "pypi": (lambda n: n in ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile") or (n.startswith("requirements") and n.endswith(".txt")),
             ("poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "pylock.toml")),
    "golang": (lambda n: n == "go.mod", ("go.sum",)),
    "composer": (lambda n: n == "composer.json", ("composer.lock",)),
    "cargo": (lambda n: n == "Cargo.toml", ("Cargo.lock",)),
    "maven": (lambda n: n == "pom.xml", ()),
    "gradle": (lambda n: n in ("build.gradle", "build.gradle.kts"), ("gradle.lockfile",)),
    "gem": (lambda n: n == "Gemfile" or n.endswith(".gemspec"), ("Gemfile.lock",)),
    "nuget": (lambda n: n.endswith((".csproj", ".fsproj", ".vbproj")), ("packages.lock.json",)),
    "pub": (lambda n: n == "pubspec.yaml", ("pubspec.lock",)),
    "swift": (lambda n: n == "Package.swift", ("Package.resolved",)),
    "cocoapods": (lambda n: n == "Podfile", ("Podfile.lock",)),
    "hex": (lambda n: n == "mix.exs", ("mix.lock",)),
}
SBOMGATE_MANIFEST = lambda n: n == "package.json" or (n.startswith("requirements") and n.endswith(".txt"))
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", ".tox", "bower_components"}


def go_has_requires(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return any(re.match(r"\s*require\b", l) for l in f)
    except OSError:
        return True   # 讀不到就保守視為有依賴


def glob_re(pattern):
    """工作區 glob → 正規表示式（以「/」分段：* 與 ? 不跨段，** 可跨段）。"""
    pat = pattern.strip().strip("/")
    while pat.startswith("./"):
        pat = pat[2:]
    out, i = "", 0
    while i < len(pat):
        if pat.startswith("**", i):
            out += ".*"
            i += 2
            if i < len(pat) and pat[i] == "/":
                i += 1
                out = out[:-2] + "(?:.*/)?"
        elif pat[i] == "*":
            out += "[^/]*"
            i += 1
        elif pat[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pat[i])
            i += 1
    return re.compile(out + r"\Z")


def matches(rel, includes, excludes=()):
    rel = rel.replace(os.sep, "/").strip("/")
    return any(glob_re(p).match(rel) for p in includes if isinstance(p, str)) and \
        not any(glob_re(p).match(rel) for p in excludes if isinstance(p, str))


def read_json(path):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, ValueError, RecursionError):
        return None


def read_toml(path):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return None


def pnpm_patterns(path):
    """pnpm-workspace.yaml 的 packages 清單（只讀簡單的 YAML 清單；讀不懂回 None → 不算成員）。"""
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    pats, inside = [], False
    for l in lines:
        if re.match(r"^packages\s*:\s*$", l):
            inside = True
            continue
        if inside:
            m = re.match(r"^\s+-\s*['\"]?([^'\"#]+?)['\"]?\s*(#.*)?$", l)
            if m:
                pats.append(m.group(1).strip())
            elif l.strip() and not l.startswith((" ", "\t")):
                break
    return pats or None


def go_work_uses(path):
    try:
        text = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        return None
    text = re.sub(r"//.*", "", text)
    uses = re.findall(r"^\s*use\s+([^\s(]+)\s*$", text, flags=re.M)
    for block in re.findall(r"^\s*use\s*\((.*?)\)", text, flags=re.M | re.S):
        uses += [x.strip().strip('"') for x in block.split() if x.strip()]
    return [u.strip('"') for u in uses]


def workspace_lock(eco, mdir, root, files_by_dir):
    """mdir 是否為上層工作區的成員且該工作區有鎖定檔；是 → 回傳鎖定檔路徑與說明，否則 None。"""
    d = os.path.dirname(mdir)
    while d.startswith(root):
        fs = files_by_dir.get(d, set())
        rel = os.path.relpath(mdir, d)
        if eco == "npm" and "package.json" in fs:
            j = read_json(os.path.join(d, "package.json"))
            ws = j.get("workspaces") if isinstance(j, dict) else None
            if isinstance(ws, dict):
                ws = ws.get("packages")
            if isinstance(ws, list) and matches(rel, ws):
                lk = [x for x in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lock", "bun.lockb") if x in fs]
                return (os.path.join(d, lk[0]), "npm／yarn workspaces 成員") if lk else None
        if eco == "npm" and "pnpm-workspace.yaml" in fs:
            pats = pnpm_patterns(os.path.join(d, "pnpm-workspace.yaml")) or []
            inc = [x for x in pats if not x.startswith("!")]
            exc = [x[1:] for x in pats if x.startswith("!")]
            if matches(rel, inc, exc):
                return (os.path.join(d, "pnpm-lock.yaml"), "pnpm workspace 成員") if "pnpm-lock.yaml" in fs else None
        if eco == "cargo" and "Cargo.toml" in fs:
            t = read_toml(os.path.join(d, "Cargo.toml")) or {}
            w = t.get("workspace") if isinstance(t.get("workspace"), dict) else None
            if w and matches(rel, w.get("members") or [], w.get("exclude") or []):
                return (os.path.join(d, "Cargo.lock"), "Cargo workspace 成員") if "Cargo.lock" in fs else None
        if eco == "pypi" and "pyproject.toml" in fs:
            t = read_toml(os.path.join(d, "pyproject.toml")) or {}
            w = ((t.get("tool") or {}).get("uv") or {}).get("workspace") if isinstance(t.get("tool"), dict) else None
            if isinstance(w, dict) and matches(rel, w.get("members") or [], w.get("exclude") or []):
                return (os.path.join(d, "uv.lock"), "uv workspace 成員") if "uv.lock" in fs else None
        if eco == "golang" and "go.work" in fs:
            uses = go_work_uses(os.path.join(d, "go.work")) or []
            if any(os.path.normpath(os.path.join(d, u)) == mdir for u in uses):
                return (os.path.join(d, "go.work.sum"), "go.work 的 use 列入") if "go.work.sum" in fs else None
        if d == root:
            break
        d = os.path.dirname(d)
    return None


PY_TOOL_LOCK = (("poetry", "poetry.lock"), ("pdm", "pdm.lock"), ("uv", "uv.lock"))


def manifest_locks(eco, path):
    """這個清單檔可接受的鎖定檔名稱與說明；空 tuple 表示一律 missing。"""
    n = os.path.basename(path)
    if eco != "pypi":
        return ECOSYSTEMS[eco][1], ""
    if n == "Pipfile":
        return ("Pipfile.lock",), ""
    if n == "pyproject.toml":
        tool = (read_toml(path) or {}).get("tool")
        tool = tool if isinstance(tool, dict) else {}
        named = tuple(lock for t, lock in PY_TOOL_LOCK if isinstance(tool.get(t), dict))
        if named:
            return named, f"依 [tool.*] 只認 {'、'.join(named)}"
        return ("poetry.lock", "uv.lock", "pdm.lock", "pylock.toml"), ""
    return (), "requirements*.txt、setup.py、setup.cfg 不視為有鎖定檔（尚未支援全 == 釘選的 pip-compile 輸出）"


def check(root):
    root = os.path.abspath(root)
    files_by_dir = {}
    for d, ds, fs in os.walk(root):
        ds[:] = sorted(x for x in ds if x not in SKIP_DIRS)
        files_by_dir[d] = set(fs)
    ecos = {}
    for d in sorted(files_by_dir):
        for n in sorted(files_by_dir[d]):
            for eco, (is_man, _) in ECOSYSTEMS.items():
                if is_man(n):
                    ecos.setdefault(eco, []).append(os.path.join(d, n))
    result, missing = [], []
    for eco, mans in sorted(ecos.items()):
        locks = ECOSYSTEMS[eco][1]
        entries = []
        for m in mans:
            rel = os.path.relpath(m, root)
            if eco == "golang" and not go_has_requires(m):
                entries.append({"manifest": rel, "lockfile": None, "status": "no-deps"})
                continue
            mdir = os.path.dirname(m)
            mlocks, why = manifest_locks(eco, m)
            hit = [l for l in mlocks if l in files_by_dir.get(mdir, ())]
            if hit:    # 同一資料夾、且是這種清單檔對應的鎖定檔
                e = {"manifest": rel, "lockfile": os.path.relpath(os.path.join(mdir, hit[0]), root), "status": "lock"}
                if why:
                    e["note"] = why
                entries.append(e)
                continue
            # 上層工作區只對工作區成員的清單檔類型成立（uv 只看 pyproject.toml；requirements 之類一律不算）
            ws = workspace_lock(eco, mdir, root, files_by_dir) if mlocks and mdir != root and (eco != "pypi" or os.path.basename(m) == "pyproject.toml") else None
            if ws:
                entries.append({"manifest": rel, "lockfile": os.path.relpath(ws[0], root), "status": "lock", "via": ws[1]})
            else:
                e = {"manifest": rel, "lockfile": None, "status": "missing"}
                if why:
                    e["note"] = why
                entries.append(e)
        st = "missing" if any(e["status"] == "missing" for e in entries) else "lock"
        if st == "missing":
            missing.append(eco)
        result.append({"ecosystem": eco, "status": st, "manifests": entries,
                       "note": "沒有標準鎖定檔（例如 pom.xml）" if not locks else ""})
    all_mans = [os.path.relpath(m, root) for ms in ecos.values() for m in ms]
    checked = sorted(m for m in all_mans if SBOMGATE_MANIFEST(os.path.basename(m)))
    summary = "；".join(
        f"{e['ecosystem']}：{'有鎖定檔' if e['status'] == 'lock' else '缺鎖定檔'}（"
        + "、".join(m["manifest"] + (f"→{m['lockfile']}" + (f"（{m['via']}）" if m.get("via") else "") if m["lockfile"] else ("（沒有依賴）" if m["status"] == "no-deps" else ("（不視為鎖定）" if m.get("note") else "（沒有）")))
                   for m in e["manifests"]) + "）" for e in result) or "沒有清單檔"
    return {
        "summary": summary,
        "tree": "full" if ecos and not missing else "unknown",
        "reason": ("沒有偵測到任何清單檔，無法宣告依賴樹完整" if not ecos else
                   ("缺鎖定檔的生態系：" + "、".join(missing) if missing else "每個生態系的每個清單檔都有對應的鎖定檔")),
        "ecosystems": result,
        "missing_ecosystems": missing,
        "manifests_for_sbomgate": checked,
        "manifests_not_checked": sorted(set(all_mans) - set(checked)),
    }


def main(argv=None):
    a = sys.argv[1:] if argv is None else argv
    if len(a) != 2 or not os.path.isdir(a[0]):
        print("用法：lockcheck.py <原始碼資料夾> <輸出.json>", file=sys.stderr)
        return 3
    r = check(a[0])
    with open(a[1], "w", encoding="utf-8") as f:
        json.dump(r, f, ensure_ascii=False, indent=1)
    print(f"{r['tree']}\t{r['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
