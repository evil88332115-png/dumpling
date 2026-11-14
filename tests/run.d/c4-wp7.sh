#!/usr/bin/env bash
# C4 WP7（Raspberry Pi、Rockchip、AI NAS 轉接器）的單元測試：不連網，全部用合成資料。
# 用標準庫 unittest；需要 PyYAML（runner 內建 python3-yaml）。Python 程式要能在 3.12 跑，用 `python3 -I`。
# 最後一行：c4-wp7: OK／FAIL（測試數）。
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root" || exit 1
if ! python3 -c 'import yaml' 2> /dev/null; then echo "c4-wp7: FAIL（缺少 PyYAML：apt install python3-yaml）"; exit 1; fi
log=$(mktemp "${TMPDIR:-/tmp}/c4-wp7.XXXXXX")
trap 'rm -f "$log"' EXIT
if python3 -B -m unittest discover -s tests -p 'test_wp7_*.py' -v > "$log" 2>&1; then
  n=$(sed -n 's/^Ran \([0-9]*\) tests\{0,1\} in .*/\1/p' "$log" | tail -1)
  echo "c4-wp7: OK（$n 項，python $(python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])')）"
else
  tail -40 "$log"
  echo "c4-wp7: FAIL"
  exit 1
fi
