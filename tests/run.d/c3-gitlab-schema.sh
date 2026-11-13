#!/usr/bin/env bash
# gitlab/.gitlab-ci.yml 對 GitLab 官方 CI JSON schema 的驗證（C3，M5）。每次都跑，執行時不連網；
# schema 檔在 repo 裡（gitlab/tests/data/gitlab-ci-schema/ci.json，來源、授權見同資料夾 SOURCE.md、LICENSE.md）。
#
# 做法照 tests/run.d/c2-x86-firmware.sh：在 venv 裡裝 tools/cra/tests/requirements.txt 固定的版本（本腳本不另外選版本），
# 用 jsonschema（Draft7Validator）驗證。venv 的位置與快取規則與 c2 相同（DUMPLING_VENV_CACHE 同一個資料夾、同一個命名，兩邊可共用）；
# 建不起 venv 或裝不起套件（例如沒有網路）→ FAIL，與 c2 一致。
# YAML 用系統 python3 的 PyYAML 轉成 JSON（requirements.txt 沒有 PyYAML，也不另外選版本）；缺 PyYAML：
# DUMPLING_REQUIRE_TEST_DATA=1 算失敗，沒設就印 NOT_RUN（不能印 OK）。
#
# 重要：官方 schema 驗證通過，只代表語法與欄位型別符合 schema，**不保證範本在 GitLab 上一定跑得起來**；
# 搬到 GitLab 後，要用該 GitLab 實例的 CI Lint 再檢查一次（docs/GITLAB-PORT.md 的搬移檢查清單）。
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
req="$root/tools/cra/tests/requirements.txt"
schema="$root/gitlab/tests/data/gitlab-ci-schema/ci.json"
ci="$root/gitlab/.gitlab-ci.yml"
PIN_SHA256=1c6eeb7d3a34c39996afbfe1ade220480eb05bbeae674e86d3c745dfeeded7fd
work=$(mktemp -d "${TMPDIR:-/tmp}/dumpling-c3-gitlab-schema.XXXXXX")
trap 'rm -rf "$work"' EXIT
fail() { echo "c3-gitlab-schema: FAIL（$1）"; exit 1; }

[ "$(sha256sum "$schema" | cut -d' ' -f1)" = "$PIN_SHA256" ] || fail "ci.json 的 sha256 與固定值不符（SOURCE.md）"

if ! python3 -I -c 'import yaml' 2>/dev/null; then
  if [ "${DUMPLING_REQUIRE_TEST_DATA:-}" = 1 ]; then fail "系統 python3 沒有 PyYAML，且 DUMPLING_REQUIRE_TEST_DATA=1"; fi
  echo "c3-gitlab-schema: NOT_RUN（系統 python3 沒有 PyYAML，無法把 .gitlab-ci.yml 轉成 JSON）"; exit 0
fi
python3 -I "$root/gitlab/tests/gitlabci.py" tojson "$ci" "$work/ci.instance.json" || fail "YAML 轉 JSON 失敗"

build_venv() {   # build_venv <目錄>：建 venv 並裝測試套件（同 c2-x86-firmware.sh）
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
    echo "c3-gitlab-schema: 沿用快取的 venv（requirements.txt 雜湊 ${full:0:16}）"
  else
    mkdir -p "$DUMPLING_VENV_CACHE" || fail "建不起快取資料夾"
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

out=$("$venv/bin/python" "$root/gitlab/tests/validate_schema.py" "$schema" "$work/ci.instance.json" 2>&1); rc=$?
echo "$out"
[ "$rc" -eq 0 ] || fail ".gitlab-ci.yml 不符官方 schema（或驗證器出錯，結束碼 $rc）"

# 反向測試：故意弄壞的檔案必須被擋下（確認驗證真的有作用）
cat > "$work/bad.yml" <<'YML'
stages: [a]
job:
  stage: a
  scrpt: [echo]
  rules: nope
YML
python3 -I "$root/gitlab/tests/gitlabci.py" tojson "$work/bad.yml" "$work/bad.json" >/dev/null || fail "反向測試檔轉換失敗"
if "$venv/bin/python" "$root/gitlab/tests/validate_schema.py" "$schema" "$work/bad.json" >/dev/null 2>&1; then
  fail "壞檔案竟然通過 schema"
fi
echo "c3-gitlab-schema: 反向測試 OK（壞檔案被擋下）"
echo "c3-gitlab-schema: OK（官方 schema commit 28aa2bf9…；只代表語法與型別符合 schema，不保證在 GitLab 跑得起來；搬移後要用該實例的 CI Lint 再檢查）"
