# OpenVEX 0.2.0 JSON schema（測試用）

`test_vex_export.py`、`test_vex_rules.py`、`tools/vexconv/tests/test_vexconv.py` 用來驗證產生的 OpenVEX。官方檔案，未修改：
https://raw.githubusercontent.com/openvex/spec/61b5f885d0f481f48683c93345e49ef1a6e9fdff/openvex_json_schema.json（openvex/spec，授權 Apache-2.0）

| 檔案 | SHA-256 |
|---|---|
| openvex_json_schema.json | 9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238 |

sca-center 的做法是 CI 用 `scripts/ci/fetch-test-data.sh` 連網取得；dumpling 直接把這個小檔放進 repo，測試就不需要網路。
