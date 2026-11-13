# CycloneDX 1.4 JSON schema（測試用）

測試（`cdx_schema.py` 的 `cdx_validator_14()`）用來驗證供應商 SBOM（CycloneDX 1.4）經 `pipeline/lib/firmware_sbom_normalize.py` 正規化後的副本。
官方檔案，**除 jsf-0.82.schema.json 外未修改**（見下）：
https://raw.githubusercontent.com/CycloneDX/specification/1.4/schema/<檔名>
（tag `1.4`，annotated tag 物件 043b2cf1abc229c5c736888c4ade8d979687f7df，指向的 commit 是 ccbf7b5781ef534cd62616e3c4221004c7c82a66；`git ls-remote https://github.com/CycloneDX/specification 'refs/tags/1.4*'` 的 `refs/tags/1.4^{}` 那一列；2026-11-12 下載）

該 commit 的 `schema/` 下三個檔案的 SHA-256 與下表相同（jsf 是官方原檔的值，見下）。

授權 Apache-2.0（CycloneDX/specification）。依據：`bom-1.4.schema.json` 與 `jsf-0.82.schema.json` 的 `$comment` 都寫 published under the terms of the Apache License 2.0；`spdx.schema.json` 檔內沒有授權標示，隨同一個 repo 的 Apache-2.0（授權檔：https://raw.githubusercontent.com/CycloneDX/specification/1.4/LICENSE）。

| 檔案 | SHA-256 |
|---|---|
| bom-1.4.schema.json | 51b79463558376e6397802cce4fd792037a941cda89f9a7cc0abd1b5cbeb67b7 |
| spdx.schema.json | 07e151d41d749e81b868634c8b2b39d65798f1db0356fd98c9591e953c9f24ea |
| jsf-0.82.schema.json（修改過，見下） | 2e6fbbf66cad524780d3ae96ce74a8ec8e0bbfc27e8767df3e1586fa2efc7cc2 |

jsf-0.82.schema.json 只改了第 6 行 `$comment` 裡作者的個人信箱（改成 `email address omitted`；`$comment` 不影響驗證），因為公開檢查不允許 repo 內出現個人信箱（和 `../cyclonedx-1.6.1/` 的做法相同）。官方原檔的 SHA-256 是 a517f9e483e2252debd23d5c62edb72805b6d3932935a6ebb8196745052d2dc3。
bom-1.4.schema.json 內的 `firstname.lastname@example.com` 是範例（保留網域），未修改。
