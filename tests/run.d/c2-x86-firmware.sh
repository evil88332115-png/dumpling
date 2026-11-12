#!/usr/bin/env bash
# C2 x86 韌體（BIOS／vBIOS → CycloneDX）的單元測試：tools/cra/tests/test_x86_firmware*.py、test_coreboot_cbfs.py。
# 在 venv 裡裝固定版本的 pytest、jsonschema、referencing（tools/cra/tests/requirements.txt）；
# 不用 --user／系統 python，因為 ubuntu-24.04 的系統 python 有 PEP 668 限制（pip install 會被拒絕），
# 本機也不能污染使用者的全域 Python。DUMPLING_REQUIRE_TEST_DATA=1：任何 skip 都算失敗（缺 jsonschema 不能靜默少跑）。
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/dumpling-c2-x86fw.XXXXXX")
trap 'rm -rf "$work"' EXIT

python3 -m venv "$work/venv" || { echo "c2-x86-firmware: FAIL（建不起 venv）"; exit 1; }
"$work/venv/bin/python" -m pip install -q --disable-pip-version-check -r "$root/tools/cra/tests/requirements.txt" \
  || { echo "c2-x86-firmware: FAIL（裝不起測試套件）"; exit 1; }

export DUMPLING_REQUIRE_TEST_DATA=1
"$work/venv/bin/python" -m pytest -q -p no:cacheprovider --basetemp="$work/pytest" \
  "$root/tools/cra/tests/test_x86_firmware.py" "$root/tools/cra/tests/test_x86_firmware_sbom.py" \
  "$root/tools/cra/tests/test_coreboot_cbfs.py"
