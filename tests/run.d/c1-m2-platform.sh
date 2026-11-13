#!/usr/bin/env bash
# C1 M2 平台介面與開案範本（pipeline/platform.sh、new-project.sh、project-info.py、lib/*）的單元測試：不連網。
# 用標準庫 unittest；需要 PyYAML（runner 內建 python3-yaml）。Python 程式要能在 3.12 跑，用 `python3 -I`。
# 最後一行：c1-m2-platform: OK／FAIL（測試數）。
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root" || exit 1
if ! python3 -c 'import yaml' 2> /dev/null; then echo "c1-m2-platform: FAIL（缺少 PyYAML：apt install python3-yaml）"; exit 1; fi
log=$(mktemp "${TMPDIR:-/tmp}/c1-m2-platform.XXXXXX")
trap 'rm -f "$log"' EXIT
if python3 -B -m unittest discover -s tests -p 'test_platform_*.py' -v > "$log" 2>&1; then
  n=$(grep -c ' ok$' "$log" || true)
  echo "c1-m2-platform: OK（$n 項，python $(python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])')）"
else
  tail -40 "$log"
  echo "c1-m2-platform: FAIL"
  exit 1
fi
