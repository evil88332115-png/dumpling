#!/usr/bin/env bash
# C2（韌體）單元測試：不連網。
# 用標準庫 unittest，不用 pytest：ubuntu-24.04 runner 與本機都不一定有 pytest，
# 用 unittest 就不必在 CI 安裝、也不必固定外部套件版本；測試只依賴 python3-yaml（runner 內建）。
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
python3 -c 'import yaml' || { echo "缺少 PyYAML（apt install python3-yaml）" >&2; exit 1; }
python3 -B -m unittest discover -s tests -p 'test_firmware*.py' -v
