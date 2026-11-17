# CSAF 草稿（修補公告與被利用漏洞的使用者通知）

`tools/cra/csaf_advisory.py` 產生兩種 CSAF 2.0（`csaf_security_advisory`）文件。**兩種都只是草稿**：`document.tracking.status` 固定是 `draft`、版本 `0`，工具沒有任何參數能改成 `final`，也不會發布或自動放進客戶資料包。要不要發、怎麼發由負責人決定。

來源：同步 sca-center edac554（D-066 的 S4），移植與清理內容見 `docs/PROVENANCE.md` 的「C3 CSAF 草稿」節。

| | A：版本間的修補公告 | B：被利用漏洞的使用者通知 |
|---|---|---|
| 對應 | CRA Annex I Part II(4)：修補**可用之後**公開已修補漏洞的資訊 | CRA 第 14 條第 8 項：已被積極利用、**修補還沒有**時通知受影響的使用者 |
| 指令 | `csaf_advisory.py --old <前一版 Reports> --new <這一版 Reports> --config <config.json> --out <資料夾>` | `csaf_advisory.py exploited --report <Reports> --cve CVE-… [--cve …] [--config <config.json>] --out <資料夾>` |
| 輸出 | `csaf.json`、`advisory.md`、`csaf-summary.json` | `csaf-exploited-draft.json`、`csaf-exploited-summary.json` |
| 狀態行 | `CSAF<TAB>OK｜ATTENTION｜FAIL<TAB>說明` | `CSAF-EXPLOITED<TAB>OK｜ATTENTION｜GAP｜FAIL<TAB>說明` |

同一個 CVE 通常先有 B（還沒修補），修補釋出後才有 A。官網的公告文字仍是對外的主要管道，CSAF JSON 是它的機器可讀版本；向主管機關的通報（第 14 條的單一通報平台、24／72 小時）是另一件事，不用這兩份檔案。

## 共同規則

- **發布者欄位**（`config.json` 的 `csaf` 區塊，見 `tools/cra/config.schema.json`）：`publisher_name`、`publisher_namespace`、`tracking_id_prefix`、`contact`、`advisory_url_base`、`tlp`。沒填時退回 `manufacturer.*`（聯絡方式另外退回 `vulnerability_contact.contact`），再沒有就寫 `TO BE COMPLETED`（網址佔位 `https://to-be-completed.invalid`；聯絡方式不寫，列在缺的欄位），狀態 ATTENTION。`tlp` 要寫大寫。**工具沒有內建任何預設的網域或聯絡人**；範例值（example.com 等）也當成沒填。
- **驗證**：每份輸出都跑兩層檢查，不符就 FAIL、不產生（並刪掉上一次的輸出）。
  - 完整的 OASIS CSAF 2.0 JSON schema（`tools/cra/data/csaf-2.0/`，官方原檔，來源與授權見同資料夾 `NOTICE.md`），需要 `jsonschema` 與 `referencing`。沒有這兩個套件時，summary 的 `schema_validation.status` 是 `NOT_RUN`，notes 寫明「這不是通過」，狀態 ATTENTION。
  - 內建檢查（不依賴套件，一定會跑）：document 必要欄位與列舉值、security_advisory 設定檔的必要欄位、產品 ID 都有定義、同一產品不同時在互斥的狀態裡。結果寫在 summary 的 `builtin_checks`。
- **輸入是不可信資料**：不跟隨符號連結、單一檔案有大小上限，字串去掉控制字元與 Unicode 格式字元並截斷。
- 工具只帶入判定（VEX）的狀態與元件；漏洞描述、嚴重度說明、修補方式的文字要人補。

## A：版本間的修補公告

比對兩版的 `vex.cdx.json`（只有「有判定」的列），每一筆歸成一類：

- `fixed`：舊版受影響，這一版判定已修補，或元件已經不在這一版的 SBOM。只有這一類會寫 `vendor_fix`。
- `new`：這一版才受影響。`still`：兩版都受影響或還在評估。`changed`：其他狀態改變。
- `reassessed`：重新評估成 not_affected。**這不是修補**，不寫 `vendor_fix`。
- `not_stated`：舊版受影響、這一版沒有判定而元件還在，或新版本已修但舊版本還在。**不當成已修**，要先判定。

接進報告：`tools/cra/report_package.py --csaf-previous <前一版的 CRA/Reports、專案資料夾或精靈輸出資料夾>`。

- 草稿放 `交給PM/CSAF/csaf-fix-advisory-<名稱>-<版本>.json`，旁邊的 `README.md` 寫明這是草稿、各分類的意思、發布前要補的欄位。完整輸出放 `內部存檔/csaf-fix-advisory/`。兩者都進 `SHA256SUMS.txt`。
- **不放進客戶資料包**（有測試檢查客戶資料包裡沒有 CSAF 檔案或內容）。
- 沒給 `--csaf-previous`：訊息寫 NOT_RUN（沒有前一版可比較），不算 GAP。給了但產生不了（找不到前一版、前後版是同一份、版本順序反了、驗證失敗等）：原因寫進 `交給PM/未產生的項目.md`（GAP）。
- 發 Release 時自動找同一專案的前一個正式 Release 來比較：還沒接（D-066 後續，C1）。

## B：被利用漏洞的使用者通知

- 輸入：報告的 `vulnerability-rows.json`（必要），`vex.cdx.json`／`sbom.cdx.json` 用來取產品名稱與版本。
- **關卡**：要通知的 CVE 在報告裡沒有任何被利用的證據（KEV、EUVD、Grype 的 knownExploited、人工證據）時不產生，狀態 GAP。有報告以外的證據時加 `--assume-exploited "<證據說明>"`，說明會寫進草稿。
- 產品狀態依這一版目前的判定：沒有判定或 in_triage → `under_investigation`；exploitable → `known_affected`；not_affected／false_positive → `known_not_affected`；這一版判定 resolved → `fixed`。上游或發行版有修補版本**不算**這個產品已修補。判定是 not_affected 或已修補時會警告「可能不需要通知」。
- 緩解措施預設是 `TO BE COMPLETED by RD`；受影響的元件底下不放 `vendor_fix`。

`tools/cra/exploited_watch.py`（以 Dependency-Track 為來源的監控）在有新的比對時，可以替 `--shipped` 清單裡帶 `cra_project` 的已出貨版本寫草稿到 `<輸出資料夾>/csaf-drafts/<UTC 時間>/`（`--csaf-draft`／`--no-csaf-draft`、`EW_CSAF_DRAFT`；不覆寫既有的草稿；失敗只記在報告的 `csaf_drafts`，不改變監控狀態）。dumpling 在 GitHub 上的每日監控是 `pipeline/watch/`（`docs/WATCH.md`），接上草稿是另一個 PR。
