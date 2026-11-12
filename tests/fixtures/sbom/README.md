# 測試 SBOM

`smoke.cdx.json` 是手寫的 CycloneDX 1.5，全部是公開套件資料，用來驗證「臨時 DT 能收下 SBOM、OSV 鏡像有比對出漏洞」。
`smoke.expected.json` 是驗證腳本（`pipeline/dt-verify.py`）讀的預期值。

| 元件 | 為什麼選它 | 預期 |
|---|---|---|
| `pkg:pypi/jinja2@2.10` | 舊版，OSV 的 PyPI 有多筆公開通報（例如 CVE-2019-10906、CVE-2020-28493、CVE-2024-22195） | 至少 1 筆（驗證要求） |
| `pkg:npm/lodash@4.17.15` | 舊版，OSV 的 npm 有多筆公開通報（例如 CVE-2020-8203、CVE-2021-23337、CVE-2020-28500） | 至少 1 筆（驗證要求） |
| `pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=ubuntu-22.04` | 之後 Jetson 流程比對 Ubuntu 套件要走的路徑；先看 DT 對 deb purl 有沒有結果 | 只記錄筆數，不設門檻（還不確定 DT 5.2.0 的 OSV 比對對 deb 的行為） |

驗證門檻：元件數 3；漏洞總數至少 4；PyPI、npm 各至少 1。門檻故意保守（實際通常遠多於此），目的是抓出「完全沒有比對」的失敗，而不是釘住漏洞資料庫的內容。
