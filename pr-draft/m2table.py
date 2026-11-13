"""M2 PR 的逐檔對照表（D-020）：相對 origin/main 改到的每個檔。
tools/ 底下：依 PROVENANCE C1 節的來源，實際比對 sca-center 25fa89a 原檔＋M2 改了幾行；其他：dumpling 自己寫，附檔頭第一行說明。
用法：python3 -I m2table.py <worktree> <sca-center repo>"""
import difflib, re, subprocess, sys
wt, sca = sys.argv[1], sys.argv[2]
def git(*a, cwd=wt):
    return subprocess.run(["git", "-C", cwd, *a], capture_output=True).stdout
prov = open(f"{wt}/docs/PROVENANCE.md", encoding="utf-8").read()
sec = prov.split("## C1 工具（WP1）", 1)[1].split("\n### ", 1)[0]
provrow = {}
for line in sec.splitlines():
    if not (line.startswith("| `") and line.endswith(" |")): continue
    cols = line[2:-2].split(" | ", 3)
    if len(cols) == 4 and cols[0].startswith("`") and cols[0].endswith("`"):
        provrow[cols[0].strip("`")] = (cols[1], cols[3])
numstat = {}
for l in git("diff", "--numstat", "origin/main...HEAD").decode().splitlines():
    a, d, p = l.split("\t"); numstat[p] = (a, d)
status = dict((l.split("\t")[1], l.split("\t")[0]) for l in git("diff", "--name-status", "origin/main...HEAD").decode().splitlines())
def changed(a, b):
    return sum(1 for x in difflib.unified_diff(a, b, lineterm="", n=0) if x[:1] in "+-" and not x.startswith(("+++", "---")))
def headline(p):
    try: t = open(f"{wt}/{p}", encoding="utf-8").read()
    except (OSError, UnicodeDecodeError): return "（二進位或讀不到）"
    for line in t.splitlines()[:12]:
        s = line.strip().lstrip("#").strip().strip('"').strip()
        if not s or s.startswith(("!", "-*-", "shellcheck", "set -")) or s in ("---",): continue
        s = re.sub(r"^(name|description):\s*", "", s)
        return (s[:110] + "…") if len(s) > 110 else s
    return ""
tools_rows, own_rows = [], []
for p in sorted(status):
    a, d = numstat.get(p, ("?", "?"))
    kind = "新增" if status[p] == "A" else "修改"
    if p.startswith("tools/"):
        src, note = provrow.get(p, ("", "（PROVENANCE 沒有這一列）"))
        srcs = re.findall(r"`(scripts/[^`]+|tests/[^`]+)`", src)
        mine = open(f"{wt}/{p}", "rb").read()
        if not srcs or "做法參考" in src or "自己寫" in src:
            vs = "dumpling 自己寫"
        else:
            r = subprocess.run(["git", "-C", sca, "show", f"25fa89a:{srcs[0]}"], capture_output=True)
            if r.returncode: vs = "原檔讀不到"
            elif r.stdout == mine: vs = "跟 25fa89a 相同"
            else: vs = "有修改（%d 行增刪）" % changed(r.stdout.decode("utf-8", "replace").splitlines(), mine.decode("utf-8", "replace").splitlines())
        note = note.replace("|", "／")
        # 只留 M2 期間加的說明：PROVENANCE 每列的最後一段（「；M2：」之後）優先
        i = min([j for j in (note.find("**行為修改（M2"), note.find("新增（M2"), note.find("M2 J 軌"), note.find("M2：")) if j >= 0] or [0])
        note = note[i:]
        if len(note) > 220: note = note[:217] + "…"
        tools_rows.append(f"| `{p}` | {kind}（+{a}／−{d}） | {vs} | {note} |")
    else:
        own_rows.append(f"| `{p}` | {kind}（+{a}／−{d}） | {headline(p).replace('|', '／')} |")
print(f"相對 main 共 {len(status)} 個檔（新增 {sum(1 for s in status.values() if s == 'A')}、修改 {sum(1 for s in status.values() if s != 'A')}）。\n")
print(f"#### `tools/`（從 sca-center 複製的工具，{len(tools_rows)} 個檔；改動原因摘自 `docs/PROVENANCE.md`）\n")
print("| 檔案 | 這個 PR | 對照 25fa89a | M2 改了什麼、為什麼 |\n|---|---|---|---|")
print("\n".join(tools_rows))
print(f"\n#### 其他（dumpling 自己寫，{len(own_rows)} 個檔；說明取自檔頭）\n")
print("| 檔案 | 這個 PR | 用途 |\n|---|---|---|")
print("\n".join(own_rows))
