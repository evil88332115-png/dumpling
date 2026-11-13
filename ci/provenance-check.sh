#!/usr/bin/env bash
# PROVENANCE 檢查（docs/PROVENANCE.md）：
#   1. 「C1 工具」節列的每個 dumpling 路徑都要存在。
#   2. tools/ 底下（以及 tests/expected、tests/fixtures 第一層）每個檔案，都要出現在 C1 節的表格或其他 C<n> 節裡（C2、C4… 的檔案由各自的 PR 登記）。
# 用法：ci/provenance-check.sh [PROVENANCE 檔案，預設 docs/PROVENANCE.md]
# 輸出：問題逐行列出，最後一行 "provenance-check: OK（N 筆）" 或 "provenance-check: FAIL（M 個問題）"。
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
doc=${1:-$root/docs/PROVENANCE.md}
[ -f "$doc" ] || { echo "provenance-check: FAIL（找不到 $doc）"; exit 1; }
cd "$root" || exit 1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# C1 節：表格列的第一欄（反引號包住的路徑）。其他 C<n> 節（C2 韌體工具、C4 其他平台…）：整節出現的所有反引號路徑（含「dumpling 自己寫的」那句）。
# 以 / 結尾的路徑代表整個資料夾。
section_text() {  # $1 = 節標題的開頭
  awk -v want="$1" '/^## / { insec = (index($0, "## " want) == 1); next } insec { print }' "$doc"
}
# C1 節的主表格在第一個 ### 子節之前；子節（沒帶進來的相依等）裡的表格不算
section_text "C1 工具" | awk '/^### / { exit } /^\| *`/ { sub(/^\| *`/, ""); sub(/`.*/, ""); print }' | sort > "$tmp/c1"
# shellcheck disable=SC2016  # 反引號是 Markdown 的字面符號
awk '/^## / { insec = ($0 ~ /^## C[0-9]+ / && $0 !~ /^## C1 /); next } insec { print }' "$doc" | grep -oE '`[^`]*/[^`]*`' | tr -d '`' | sed 's/[（(].*//' | sort -u > "$tmp/c2"
sort -u "$tmp/c1" "$tmp/c2" > "$tmp/all"

covered() {  # $1 = 檔案路徑；完全相同或落在某個「資料夾/」底下
  grep -qxF -- "$1" "$tmp/all" && return 0
  while IFS= read -r d; do
    case $d in */) case $1 in "$d"*) return 0;; esac;; esac
  done < "$tmp/all"
  return 1
}

problems=0
dups=$(uniq -d "$tmp/c1")
if [ -n "$dups" ]; then
  while IFS= read -r f; do echo "重複登記：$f"; problems=$((problems + 1)); done <<< "$dups"
fi
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case $f in */) [ -d "$f" ] && continue;; esac
  if [ ! -f "$f" ]; then echo "PROVENANCE 列了但檔案不存在：$f"; problems=$((problems + 1)); fi
done < "$tmp/c1"
{ find tools tests/expected -type f ! -path '*/__pycache__/*' ! -name '*.pyc' ! -path '*/.pytest_cache/*' 2> /dev/null
  find tests/fixtures -maxdepth 1 -type f 2> /dev/null; } | sort > "$tmp/files"
while IFS= read -r f; do
  if ! covered "$f"; then echo "檔案沒有登記在 PROVENANCE：$f"; problems=$((problems + 1)); fi
done < "$tmp/files"

if [ "$problems" -gt 0 ]; then
  echo "provenance-check: FAIL（$problems 個問題）"
  exit 1
fi
echo "provenance-check: OK（C1 節 $(wc -l < "$tmp/c1") 筆、其他節 $(wc -l < "$tmp/c2") 筆、檢查 $(wc -l < "$tmp/files") 個檔）"
