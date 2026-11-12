#!/usr/bin/env bash
# 下載韌體公開樣本並核對 sha256／大小。用法：
#   pipeline/firmware-fetch.sh <firmware.yml>... --out <目錄>
# 只下載、不解開、不執行。實作在 pipeline/lib/firmware_fetch.py。
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
exec python3 -I "$here/lib/firmware_fetch.py" "$@"
