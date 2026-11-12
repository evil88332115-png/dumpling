#!/usr/bin/env bash
# 供應商 BIOS SBOM 品質檢查。用法：
#   pipeline/firmware-sbom-check.sh <sbom.json>... --out <資料夾>
# SBOM 只當資料讀取；sbomqs 路徑由環境變數 SBOMQS 指定（安裝方式見 pipeline/install-tool.sh）。
# 實作在 pipeline/lib/firmware_sbom_check.py。結束碼：0＝沒有 FAIL（OK／ATTENTION／GAP 都是 0）；1＝有 FAIL；64＝用法錯誤。
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
exec python3 -I "$here/lib/firmware_sbom_check.py" "$@"
