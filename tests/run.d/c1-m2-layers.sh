#!/usr/bin/env bash
# C1 M2 分層（pipeline/lib/layers.py、pipeline/sbom-layers.py）的單元測試：不連網。含 Jetson R39.2.1 base 的標準答案數量。
# 用標準庫 unittest；需要 PyYAML（runner 內建 python3-yaml）。cra_report／report_package 的分層測試在 tools/cra/tests/test_layers_report.py（c1-tools.sh 跑）。
# 最後一行：c1-m2-layers: OK／FAIL（測試數）。
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root" || exit 1
if ! python3 -c 'import yaml' 2> /dev/null; then echo "c1-m2-layers: FAIL（缺少 PyYAML：apt install python3-yaml）"; exit 1; fi
log=$(mktemp "${TMPDIR:-/tmp}/c1-m2-layers.XXXXXX")
trap 'rm -f "$log"' EXIT
if python3 -B -m unittest discover -s tests -p 'test_layers*.py' -v > "$log" 2>&1; then
  n=$(grep -c ' ok$' "$log" || true)
  echo "c1-m2-layers: OK（$n 項，python $(python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])')）"
else
  tail -40 "$log"
  echo "c1-m2-layers: FAIL"
  exit 1
fi
