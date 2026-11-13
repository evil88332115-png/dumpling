#!/usr/bin/env bash
# 開案：從 templates/project/ 產生 projects/<專案名>/（project.yml、sources.yml、patches/、CRA/Config/）。
#   pipeline/new-project.sh <專案名> --platform <平台> --company-role <manufacturer|supplier|both>
#       --os-responsibility <ours|customer|upstream-vendor> [--product-name …] [--brand …] [--status development|shipped]
#       [--version v0.1.0-dev1] [--markets EU,…] [--support-until YYYY-MM-DD] [--projects-dir <資料夾>]
# 最後印一行 "new-project: OK|FAIL（…）"；結束碼 0＝OK、1＝FAIL、64＝用法錯誤。欄位說明見 docs/PLATFORM-INTERFACE.md。
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
exec python3 -I "$here/lib/new_project.py" "$@"
