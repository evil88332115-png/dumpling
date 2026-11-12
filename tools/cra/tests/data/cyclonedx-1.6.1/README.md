# CycloneDX 1.6.1 JSON schema（測試用）

測試（`cdx_schema.py`）用來驗證產生的 SBOM。官方檔案，**除 jsf-0.82.schema.json 外未修改**（見下）：
https://raw.githubusercontent.com/CycloneDX/specification/1.6.1/schema/<檔名>（2026-11-03 下載）

| 檔案 | SHA-256 |
|---|---|
| bom-1.6.schema.json | efc54d749e32a6e16abd19394b80b4c67d846e12c782e04505130375f94ea541 |
| spdx.schema.json | c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6 |
| jsf-0.82.schema.json（修改過，見下） | cd9529ddca66cecc5139201543a324aa22c7a2f9a91286946a2d5bc000192722 |

jsf-0.82.schema.json 只改了第 6 行 `$comment` 裡作者的個人信箱（改成 `email address omitted`；`$comment` 不影響驗證），因為公開檢查不允許 repo 內出現個人信箱。官方原檔的 SHA-256 是 8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae。
