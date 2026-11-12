# CycloneDX 1.5 JSON schema（測試用）

`tools/vexconv/tests/test_vexconv.py` 用來驗證 vexconv 轉出的 CycloneDX 1.5 VEX。官方檔案，未修改：
https://raw.githubusercontent.com/CycloneDX/specification/ad83dae28b236b8760286399da4daba77592de86/schema/bom-1.5.schema.json（CycloneDX/specification，授權 Apache-2.0）

| 檔案 | SHA-256 |
|---|---|
| bom-1.5.schema.json | 2d956c1d05c092695457a91f3b5c57c749793c013ec224a0935807cfc8ae4480 |

它引用的 `spdx.schema.json`、`jsf-0.82.schema.json` 用 `../cyclonedx-1.6.1/` 裡的同名檔（測試登錄時指定）。
