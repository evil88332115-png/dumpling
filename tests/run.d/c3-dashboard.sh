#!/usr/bin/env bash
# C3（儀表板，docs/DASHBOARD.md）單元測試：不連網。用標準庫 unittest（同 c3-watch.sh 的理由：不必在 CI 安裝 pytest）。
# 觸發條件、惡意字串、href 白名單、狀態值、CSP、漏洞數附狀態、draft／演練不列、GAP、token 不外洩、check_site 的突變。
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
python3 -B -I -W ignore -m unittest discover -s pipeline/dashboard/tests -t "$root" -p 'test_*.py' -v
