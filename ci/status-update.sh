#!/usr/bin/env bash
# 讀寫 status 分支上的 docs/STATUS.md（C0–C4 各一節）。status 分支不走 PR，推送前會自動重試避免互蓋。
# 用法：
#   ci/status-update.sh --get C1            印出 C1 節目前內容（含標題，不含標記）
#   ci/status-update.sh C1 my-section.md    用檔案內容取代 C1 節（檔案要含 "## C1 ..." 標題）
# 只改自己那一節；不 force-push。
set -euo pipefail
top=$(git rev-parse --show-toplevel)
if [ "${1:-}" = "--get" ]; then
  sec=${2:?節名}
  git fetch -q origin status
  git show origin/status:docs/STATUS.md | sed -n "/^<!-- BEGIN $sec -->$/,/^<!-- END $sec -->$/p" | sed '1d;$d'
  exit 0
fi
sec=${1:?節名 C0–C4}
body=$(realpath "${2:?內容檔}")
case "$sec" in C[0-4]) ;; *) echo "status-update: 節名要是 C0–C4" >&2; exit 2 ;; esac
grep -q "^## $sec" "$body" || { echo "status-update: 內容檔要以 '## $sec' 標題開頭" >&2; exit 2; }
wt=$(mktemp -d "${TMPDIR:-/tmp}/dumpling-status.XXXXXX")
# shellcheck disable=SC2317  # 由 trap 呼叫
cleanup() { git worktree remove --force "$wt" >/dev/null 2>&1 || rm -rf "$wt"; }
trap cleanup EXIT
git fetch -q origin status
git worktree add -q --detach "$wt" origin/status
for try in 1 2 3 4 5; do
  git -C "$wt" fetch -q origin status
  git -C "$wt" checkout -q --detach origin/status
  python3 -I - "$wt/docs/STATUS.md" "$sec" "$body" <<'PY'
import sys, re, datetime
path, sec, body = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(path, encoding="utf-8").read()
new = open(body, encoding="utf-8").read().strip("\n")
b, e = f"<!-- BEGIN {sec} -->", f"<!-- END {sec} -->"
if t.count(b) != 1 or t.count(e) != 1:
    sys.exit(f"status-update: STATUS.md 找不到 {sec} 的標記")
pre, rest = t.split(b, 1)
_, post = rest.split(e, 1)
t = pre + b + "\n" + new + "\n" + e + post
now = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %z")
t = re.sub(r"^最後更新：.*$", f"最後更新：{now}（{sec}）", t, count=1, flags=re.M)
open(path, "w", encoding="utf-8").write(t)
PY
  if git -C "$wt" diff --quiet; then echo "status-update: $sec 沒有變動"; exit 0; fi
  (cd "$wt" && bash "$top/ci/public-check.sh" --rev HEAD --patterns "$top/ci/public-patterns.txt" >/dev/null) || {
    git -C "$wt" stash -q; echo "status-update: 內容沒過公開檢查，未推送" >&2; exit 1; }
  git -C "$wt" commit -q -am "status($sec): 更新" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
  if git -C "$wt" push -q origin HEAD:status; then
    echo "status-update: $sec 已推送（$(git -C "$wt" rev-parse --short HEAD)）"
    exit 0
  fi
  echo "status-update: 推送被拒（別人剛更新），第 $try 次重試" >&2
  sleep $((try * 2))
done
echo "status-update: 重試 5 次仍失敗" >&2
exit 1
