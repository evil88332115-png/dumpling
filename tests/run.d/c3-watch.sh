#!/usr/bin/env bash
# C3（每日監控）單元測試：不連網。用標準庫 unittest（同 c2-firmware.sh 的理由：不必在 CI 安裝 pytest）。
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
python3 -B -m unittest discover -s pipeline/watch/tests -t "$root" -p 'test_*.py' -v
