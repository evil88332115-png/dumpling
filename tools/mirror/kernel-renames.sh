#!/usr/bin/env bash
# 更新主機角色：從本機的 Linux 主線 git clone 產生「核心檔案改名對照表」，給 tools/pilot/lib/kernel_config.py 的 --rename-map（K1）用。
# 問題：Linux 核心 CNA 紀錄的 programFiles 是「現在主線」的路徑；舊核心（例如 5.15）的同一個檔案常常是另一個名字
#   （fs/ksmbd/ → fs/smb/server/、fs/cifs/ → fs/smb/client/、drivers/net/team/team.c → team_core.c …）。沒有對照表時 K1 只能說「這個核心看不出有這個檔案」（unknown）。
# 做法：git log -M<相似度> --diff-filter=R --name-status <基準>..<HEAD>，只收「整個檔案改名」（R；檔案拆成多個、複製 C、刪除 D 都不是改名），
#   而且新舊路徑都是程式檔或標頭檔（.c .h .S .rs）。基準 commit 用「提交標題等於 Linux 4.19」找（這種 clone 可能沒有 tag）。
#   對照表是 mainline 的歷史，不依賴任何產品；比基準更舊的核心（< 4.19）不涵蓋（kernel_config.py 會標 GAP）。
# 輸出（一個 JSON 檔，原子寫入：先寫暫存檔再 mv）：
#   {"schema":"kernel-renames/1","source":{"head_commit","head_date","base_commit","base_subject","base_version","range","min_similarity",
#     "generated_utc","fetched"},"count":N,"renames":[{"new","old","commit","similarity"}…]}   renames 依 git log 的順序（新的在前）
#   不寫本機路徑。kernel_config.py 以 generated_utc 判斷新舊，並檢查 schema、筆數與每一筆的型別。
# 用法：kernel-renames.sh [--fetch] <主線 clone 資料夾（bare 或一般）> <輸出 JSON>
#       kernel-renames.sh --check <JSON>
#   --fetch：先 git fetch（只在明確要求時才連網；只收 origin 的 HEAD，不收 tag）；沒有 --fetch 時完全不連網，用 clone 現有的 HEAD。
# 環境變數：
#   KERNEL_RENAMES_BASE_SUBJECT  基準 commit 的標題（預設 "Linux 4.19"）；KERNEL_RENAMES_BASE_VERSION（預設 4.19，寫進 JSON 給 kernel_config.py 判斷適用的核心）
#   KERNEL_RENAMES_MIN_SIMILARITY git 的 -M 門檻（預設 50，也是 git 的預設）
#   KERNEL_RENAMES_MIN_COUNT      至少幾筆改名（預設 5000），防止拿到空的或一部分；KERNEL_RENAMES_GIT_TIMEOUT git log 的時間上限秒數（預設 3600）
#   KERNEL_RENAME_MAP_MAX_AGE_DAYS  --check 的新舊上限（預設 60；過期只會少收新的改名，不會產生錯的對照，但舊核心看不到的檔案只和主線新改名有關，影響很小）
# 注意：clone 的內容不可信，只讀：不 checkout、hooks 指到 /dev/null、fsmonitor 關閉；只執行 git log／rev-parse／fetch；--fetch 只允許 https 與 file 協定。
set -euo pipefail
GITC=(git -c core.hooksPath=/dev/null -c core.fsmonitor=false -c core.quotePath=false -c protocol.allow=never -c protocol.https.allow=always -c protocol.file.allow=always)
for v in KERNEL_RENAMES_MIN_SIMILARITY KERNEL_RENAMES_MIN_COUNT KERNEL_RENAMES_GIT_TIMEOUT KERNEL_RENAME_MAP_MAX_AGE_DAYS; do
  [ -z "${!v:-}" ] || [[ "${!v}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "FAIL $v 必須是數字" >&2; exit 3; }; done
[[ "${KERNEL_RENAMES_BASE_VERSION:-4.19}" =~ ^[0-9]+\.[0-9]+$ ]] || { echo "FAIL KERNEL_RENAMES_BASE_VERSION 必須是 主.次" >&2; exit 3; }

check() {
  python3 -I - "$1" "${KERNEL_RENAME_MAP_MAX_AGE_DAYS:-60}" "${KERNEL_RENAMES_MIN_COUNT:-5000}" <<'PY'
import datetime, json, os, re, sys
p, max_age, min_n = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
def fail(m):
    print(f"FAIL {m}"); sys.exit(1)
if os.path.islink(p) or not os.path.isfile(p):
    fail(f"不是一般檔案：{p}")
try:
    d = json.load(open(p, encoding="utf-8"))
except (OSError, ValueError) as ex:
    fail(f"讀不出 JSON（{type(ex).__name__}）")
if not isinstance(d, dict) or d.get("schema") != "kernel-renames/1":
    fail("schema 不是 kernel-renames/1")
s, r = d.get("source"), d.get("renames")
if not isinstance(s, dict) or not isinstance(r, list):
    fail("缺少 source 或 renames")
for k in ("head_commit", "base_commit"):
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(s.get(k, ""))):
        fail(f"source.{k} 不是 git 的雜湊")
if not re.fullmatch(r"\d+\.\d+", str(s.get("base_version", ""))):
    fail("source.base_version 不是 主.次")
try:
    gen = datetime.datetime.fromisoformat(str(s["generated_utc"]).replace("Z", "+00:00"))
except (KeyError, ValueError):
    fail("source.generated_utc 無法解析")
age = (datetime.datetime.now(datetime.timezone.utc) - gen).total_seconds() / 86400
if age > max_age:
    fail(f"過期：產生後 {age:.1f} 天 > {max_age:g}（generated_utc={s['generated_utc']}）")
if d.get("count") != len(r) or len(r) < min_n:
    fail(f"筆數 {len(r)}（count={d.get('count')}）不符或少於 {min_n}")
for e in r:
    if not (isinstance(e, dict) and isinstance(e.get("new"), str) and isinstance(e.get("old"), str) and e["new"] != e["old"]
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(e.get("commit", ""))) and isinstance(e.get("similarity"), int)):
        fail(f"有格式不對的改名紀錄：{str(e)[:120]}")
print(f"OK head={s['head_commit']} head_date={s.get('head_date')} base={s['base_version']} generated_utc={s['generated_utc']} age_days={age:.1f} renames={len(r)}")
PY
}
if [ "${1:-}" = "--check" ]; then check "${2:?缺少 JSON}"; exit $?; fi
FETCH=0
if [ "${1:-}" = "--fetch" ]; then FETCH=1; shift; fi
REPO="${1:?用法見檔頭}"; OUT="${2:?用法見檔頭}"
[ -d "$REPO" ] && [ ! -L "$REPO" ] || { echo "FAIL 不是資料夾（或是符號連結）：$REPO" >&2; exit 3; }
G=("${GITC[@]}" -C "$REPO")
"${G[@]}" rev-parse --git-dir >/dev/null 2>&1 || { echo "FAIL 不是 git clone：$REPO" >&2; exit 3; }
TIP=HEAD
if [ "$FETCH" = 1 ]; then
  timeout 900 "${G[@]}" fetch -q --no-tags origin HEAD || { echo "FAIL git fetch 失敗" >&2; exit 1; }
  TIP=FETCH_HEAD
fi
TIPC=$("${G[@]}" rev-parse --verify -q "$TIP^{commit}") || { echo "FAIL 取不到 $TIP（clone 是空的或還沒下載完）" >&2; exit 1; }
SUBJ="${KERNEL_RENAMES_BASE_SUBJECT:-Linux 4.19}"
# 基準：標題完全等於 $SUBJ 的 commit（有多個時取最舊的；沒有 tag 的 clone 也找得到）
BASE=$("${G[@]}" log --format='%H%x09%s' --fixed-strings --grep="$SUBJ" "$TIPC" | awk -F'\t' -v s="$SUBJ" '$2==s{h=$1} END{print h}')
[ -n "$BASE" ] || { echo "FAIL 找不到標題為 \"$SUBJ\" 的基準 commit（clone 的歷史不夠舊？）" >&2; exit 1; }
"${G[@]}" merge-base --is-ancestor "$BASE" "$TIPC" || { echo "FAIL 基準 $BASE 不在 $TIPC 的歷史裡" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"
work=$(mktemp -d "$(dirname "$OUT")/.kernel-renames.XXXXXX"); trap 'rm -rf "$work"' EXIT
SIM="${KERNEL_RENAMES_MIN_SIMILARITY:-50}"
HDATE=$("${G[@]}" log -1 --format=%cI "$TIPC")
timeout "${KERNEL_RENAMES_GIT_TIMEOUT:-3600}" "${G[@]}" log -M"${SIM}%" --diff-filter=R --name-status --topo-order --format='@@%H' "$BASE..$TIPC" > "$work/log" \
  || { echo "FAIL git log 失敗或超過 ${KERNEL_RENAMES_GIT_TIMEOUT:-3600} 秒" >&2; exit 1; }
python3 -I - "$work/log" "$work/out.json" "$TIPC" "$HDATE" "$BASE" "$SUBJ" "${KERNEL_RENAMES_BASE_VERSION:-4.19}" "$SIM" "$FETCH" "${KERNEL_RENAMES_MIN_COUNT:-5000}" <<'PY'
import datetime, json, re, sys
log, out, tip, hdate, base, subj, bver, sim, fetched, min_n = sys.argv[1:11]
CODE = (".c", ".h", ".S", ".rs")
ren, commit, skipped = [], None, 0
for ln in open(log, encoding="utf-8", errors="replace"):
    ln = ln.rstrip("\n")
    if ln.startswith("@@"):
        commit = ln[2:]
        continue
    f = ln.split("\t")
    if len(f) != 3 or not re.fullmatch(r"R\d{1,3}", f[0]) or commit is None:
        continue
    old, new = f[1], f[2]
    if old.startswith('"') or new.startswith('"') or not old.endswith(CODE) or not new.endswith(CODE) or old == new:
        skipped += 1
        continue
    ren.append({"new": new, "old": old, "commit": commit, "similarity": int(f[0][1:])})
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
doc = {"schema": "kernel-renames/1",
       "source": {"head_commit": tip, "head_date": hdate, "base_commit": base, "base_subject": subj, "base_version": bver,
                  "range": f"{base}..{tip}", "min_similarity": int(float(sim)), "generated_utc": now, "fetched": fetched == "1",
                  "kind": "whole-file renames (git log -M --diff-filter=R) of .c/.h/.S/.rs files"},
       "count": len(ren), "renames": ren}
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))
print(f"{len(ren)} 筆改名（略過 {skipped} 筆不是程式檔或路徑含特殊字元）")
PY
check "$work/out.json" || exit 1
mv -f "$work/out.json" "$OUT"
echo "OK renames=$OUT head=$TIPC"
