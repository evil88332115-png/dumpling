#!/usr/bin/env bash
# C2 x86 韌體（BIOS／vBIOS → CycloneDX）的單元測試：tools/cra/tests/test_x86_firmware*.py、test_coreboot_cbfs.py、test_ami_pfat.py、test_vbios_synthetic.py、test_vbios_intel.py、test_amd_psp.py、test_uefi_gfx.py、test_intel_cse_layout.py、test_uefi_image_contract.py（對 C1 uefi_image 的介面契約）、test_fw_advisory.py（Intel 微碼公告比對與發佈資料表產生器）、test_nvidia_vbios_advisory.py（NVIDIA vBIOS 公告比對）。
# 在 venv 裡裝固定版本的 pytest、jsonschema、referencing（tools/cra/tests/requirements.txt）；
# 不用 --user／系統 python，因為 ubuntu-24.04 的系統 python 有 PEP 668 限制（pip install 會被拒絕），
# 本機也不能污染使用者的全域 Python。DUMPLING_REQUIRE_TEST_DATA=1：任何 skip 都算失敗（缺 jsonschema 不能靜默少跑）。
#
# venv 快取：DUMPLING_VENV_CACHE 指到一個資料夾時，venv 放在 <資料夾>/c2-x86fw-<python 版本>-<requirements 雜湊前 16 碼>，
# requirements.txt 與 python 版本都沒變就沿用（標記檔 .stamp 記完整雜湊，裝完才寫；半途失敗的 venv 不會被沿用）。
# 沒設就照舊：每次建在暫存、結束時刪掉。
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
req="$root/tools/cra/tests/requirements.txt"
work=$(mktemp -d "${TMPDIR:-/tmp}/dumpling-c2-x86fw.XXXXXX")
trap 'rm -rf "$work"' EXIT

fail() { echo "c2-x86-firmware: FAIL（$1）"; exit 1; }

build_venv() {   # build_venv <目錄>：建 venv 並裝測試套件
  python3 -m venv "$1" || return 1
  "$1/bin/python" -m pip install -q --disable-pip-version-check -r "$req" || return 2
}

if [ -n "${DUMPLING_VENV_CACHE:-}" ]; then
  pyver=$(python3 -c 'import sys; print("py%d.%d" % sys.version_info[:2])') || fail "找不到 python3"
  full=$(sha256sum "$req" | cut -d' ' -f1)
  venv="$DUMPLING_VENV_CACHE/c2-x86fw-$pyver-${full:0:16}"
  stamp_ok() { [ -x "$venv/bin/python" ] && [ "$(cat "$venv/.stamp" 2>/dev/null)" = "$pyver $full" ] \
                 && "$venv/bin/python" -c 'import pytest, jsonschema, referencing' 2>/dev/null; }
  if stamp_ok; then
    echo "c2-x86-firmware: 沿用快取的 venv（requirements.txt 雜湊 ${full:0:16}）"
  else
    mkdir -p "$DUMPLING_VENV_CACHE" || fail "建不起快取資料夾"
    # 直接建在最後的位置（venv 內的腳本寫死建立時的路徑，不能建好再搬）；標記檔最後才寫，失敗或中斷的 venv 下次會被重建
    rm -rf "$venv"
    build_venv "$venv"; rc=$?
    [ $rc -eq 0 ] || { rm -rf "$venv"; fail "$([ $rc -eq 1 ] && echo 建不起 venv || echo 裝不起測試套件)"; }
    echo "$pyver $full" > "$venv/.stamp"
  fi
else
  venv="$work/venv"
  build_venv "$venv"; rc=$?
  [ $rc -eq 0 ] || fail "$([ $rc -eq 1 ] && echo 建不起 venv || echo 裝不起測試套件)"
fi

export DUMPLING_REQUIRE_TEST_DATA=1
"$venv/bin/python" -m pytest -q -p no:cacheprovider --basetemp="$work/pytest" \
  "$root/tools/cra/tests/test_x86_firmware.py" "$root/tools/cra/tests/test_x86_firmware_sbom.py" \
  "$root/tools/cra/tests/test_coreboot_cbfs.py" "$root/tools/cra/tests/test_ami_pfat.py" \
  "$root/tools/cra/tests/test_vbios_synthetic.py" "$root/tools/cra/tests/test_vbios_intel.py" \
  "$root/tools/cra/tests/test_uefi_gfx.py" "$root/tools/cra/tests/test_intel_cse_layout.py" "$root/tools/cra/tests/test_uefi_image_contract.py" \
  "$root/tools/cra/tests/test_amd_psp.py" "$root/tools/cra/tests/test_fw_advisory.py" "$root/tools/cra/tests/test_nvidia_vbios_advisory.py"
