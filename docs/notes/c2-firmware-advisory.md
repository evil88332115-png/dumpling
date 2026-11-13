# C2：韌體 SBOM 的公告比對（Intel 微碼）與 Intel CSME 的 CPE（分支 wp3/fw-advisory）

只用公開樣本與公開資料。這份是工作紀錄，不是驗證結論；數字都是 2026-11-13 對固定來源與公開樣本量的。
比對結果是**候選**，不是漏洞判定：`dumpling:vuln-assessment` 仍然是 `NOT_ASSESSED`，沒有任何狀態或文字表示「沒有漏洞」。

## 檔案

| 檔案 | 內容 |
|---|---|
| `tools/cra/intel_ucode_releases.py` | 資料表產生器：固定來源（tag、commit、sha256）→ 解析 → JSON。`generate`、`verify` 兩個子命令 |
| `tools/cra/data/intel-microcode-releases.json` | 產生出來的資料表（約 80 KB，進 repo）。每個 release 的 tag、日期、INTEL-SA 清單、各 F-M-S／platform id 的 revision 變化、人工對照 `prose_rules`；附來源 URL、tag、commit、sha256、產生時間、看不懂的段落（`unparsed`，只有行號與原因）。只放事實性欄位（見「授權」） |
| `tools/cra/fw_advisory.py` | 離線比對：載入資料表（核對 sha256 與結構）、CPUID → F-M-S、revision 比較、結果分類 |
| `tools/cra/x86_firmware.py` | 呼叫比對、SBOM property（`dumpling:advisory-*`）、`fw-inventory.md` 的「公告比對」一節、資料表不能用時 ATTENTION；ME 的 CPE 與 `dumpling:cpe-*` |
| `pipeline/firmware-ci.sh`、`pipeline/lib/firmware_dt.py` | CI 摘要表多一欄「微碼公告比對」；DT 報告的說明與每個樣本的 `advisory-match` 計數 |
| `tools/cra/tests/test_fw_advisory.py`、`test_x86_firmware_sbom.py`、`tests/test_firmware_dt.py` | 測試（合成資料，不連網） |

## 資料來源（固定）

| 項目 | 值 |
|---|---|
| 倉庫 | https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files |
| tag | `microcode-20261110`（輕量 tag，指向 commit） |
| commit | `d71fe4e2f0f70a49ebbac7f2c7e915f181361974` |
| 檔案 | `releasenote.md`，157503 bytes |
| 網址（以 commit SHA 為準） | https://raw.githubusercontent.com/intel/Intel-Linux-Processor-Microcode-Data-Files/d71fe4e2f0f70a49ebbac7f2c7e915f181361974/releasenote.md |
| sha256 | `338b556b2e8788e68f542361d2835f1344b2ad42b40991756beb1fc8a5cf11f3` |
| 取得日期 | 2026-11-13 |

不用動態封存檔（雜湊可能變）；raw 檔案以 commit SHA 定址，內容固定。

**授權**：倉庫的 `license` 是 Intel 對微碼二進位的再散布條款，`releasenote.md` 沒有明確授權。所以本 repo 不放微碼二進位、也不放 `releasenote.md`，資料表只取事實性欄位：
tag、日期（取自 tag 名稱）、INTEL-SA 編號、F-M-S、platform 遮罩、revision、Processor 代號與 stepping。看不懂或不是公告的項目與散文（`unparsed`、`other`、`purpose_other`）
只記行號與我們自己的分類（`removed-platform`、`revert`、`release-note-correction`、`note`…），不抄原文；人工對照 `prose_rules` 引一句原文（做為對照依據）。

## releasenote.md 的格式（逐段核對）

- 每個 release 一段：`# Release Notes`、`## [<標題>](…/releases/tag/<tag>)`。共 46 個 `##`，其中 45 個是 release（最新 `microcode-20261110`、最舊 `microcode-20190312`），
  1 個是 release 內的小標題（`## Update: Corrected the MCU file for 06-a5-03`，在 20240813）。**tag 以連結網址為準**：一段標題寫 `microcode-2022027`、網址是 `microcode-20220207`。
  段落由新到舊。標題沒有日期，日期只能取自 tag 名稱（`-rev2`、`a` 後綴照記）。GitHub 上另有 `microcode-20260210-rev1` tag，release notes 沒有那一段（資料表不涵蓋它；
  它與 `microcode-20260210` 之間的差異看不到）。
- `### Purpose`（一段叫 `### Functional Updates`，在 20230512）：項目符號。`Security updates for [INTEL-SA-xxxxx](…)` 是 release 列的公告，**只在 release 層級，不分 CPUID**。
  看到的寫法：`[INTEL-SA-INTEL-SA-00972]`（重複前綴，20240312 的五項）、`[INTEL-SA-000617]`（六位數，20220510，網址是 `intel-sa-00617`）、
  `Update to SA00270.`（沒有前綴，20191112、20200520）、`Updated security updates for … [INTEL-SA-01083](…)`（更新先前的公告，20241112、20260210）、
  `Security updates for [INTEL-SA-NA]`（沒有適用的公告，20230512，底下有一行斜體說明）。編號一律正規化成 `INTEL-SA-NNNNN`；`how` 記 `security`／`updated`／`update-to`。
  其他項目：`Update for functional issues. Refer to …`（只計數；有一項的網址換行）、`Removed <名稱>/<F-M-S>/<PI> due to …`、`Revert to previous versions …`、`Correction in release notes …`、`Resolved errors …`。
- 表格 `Processor | Stepping | F-M-S/PI | Old Ver | New Ver | Products`，區段：`New Platforms`（Old Ver 空）、`Updated Platforms`（一段拼成 `Updated Platforms0`，20190618）、
  `Removed Platforms`（New Ver 空）、`New Disclosures Updated in Prior Releases`（20241112、20250211 有表，New Ver 可以是 `N/A`；20250812 只有一句散文）、`Change History`（只有 20251111，一句散文）。
  沒有內容時寫 `None`。`F-M-S` 是十六進位 family-model-stepping（`06-8e-0c`＝CPUID `000806EC`），`PI` 是 8 位元 platform id **遮罩**（Intel 倉庫 README：「Platform ID(s) supported by an MCU is an 8bit mask」），
  就是微碼檔頭的 processor flags；版本是 8 位十六進位 revision。Products 欄沒有收（人類讀的產品名）。
- 表格資料列共 920 列（對原檔用獨立的 grep 計數：920），解析後 921 列＝920＋1 列「只有文字的移除」（20260812 只在 Purpose 寫 `Removed MTL/06-aa-04/c0 …`，沒有 Removed 表；解析器從文字補一列，Old Ver 與 Stepping 留空）。
- **資料本身的怪處**（照記，不修正）：同一個 F-M-S／PI 在同一個 release 有兩列且 Old Ver 不同（SKX-SP／SKX-D 的 06-55-04/b7，20230808）；Old Ver 與上一個 release 的 New Ver 對不起來（173 處，例如 SPR 在 20230512）；
  New Ver 比 Old Ver 小（20200616 的 revert、20191112 等 SKX 幾列）；`microcode-20230512` 與 `-rev2` 重複列同樣的更新；20260811 與 20260925 的 MTL 06-aa-04/e6 Old Ver 都是 0x28。
  比對規則因此不依賴「Old Ver 串得起來」，只用各 release 的 New Ver（見下）。

### 解析器看不懂、記進 `unparsed` 的段落（目前 4 處，不是靜默略過；每處為什麼會、不會影響判定）

1. **20250812 第 346 行**（`### New Disclosures Updated in Prior Releases` 底下只有一句散文：「All ADL, RPL, SPR, EMR, MTL, ARL Microcode patches previously released in May 2025.」）：
   **會影響候選**，所以不是只放在 `unparsed`：產生器內有一份人工對照 `PROSE_RULES`（記行號、原文一句、解讀），從固定來源重現（行號與原文對不上就失敗），結果寫在資料表的 `prose_rules`（見下一節）。`unparsed` 的那一筆標 `handled: prose_rules`。
2. **20250512 第 357 行**：Purpose 裡 `# Note: INTEL-SA-01244 and INTEL-SA-01247 will be published on May 13th 2025`（不是項目符號）。**不影響判定**：這兩個編號在同一段的項目符號已經列了（`security` 有），這行只是公佈日期的備註，不當成公告。
3. **20230512 第 1066 行**：斜體說明「Microcode 20230512 … does not contain any security updates and the note, [INTEL-SA-NA] …」。**不影響判定**：`[INTEL-SA-NA]` 本來就解析成 `security_na`（沒有適用的公告），這行只是解釋。
4. **20190618 第 1905 行**：`### Updated Platforms0`（多了尾碼 0），當成 `Updated Platforms` 讀。**不影響判定**：底下的表格格式與其他 Updated 表相同，列照收。

另外 `purpose_other`／`other` 只記行號與分類（沒有原文）；`Update: Corrected the MCU file for 06-a5-03`（20240813 的 `##` 小標題）、`Change History` 的一句（20251111，更正產品名稱）、`Removed …`／`Revert …`／`Correction …`／`Resolved …` 項目都屬這類。
`Removed <名稱>/<F-M-S>/<PI>` 的文字會補成 removed 列（見上）；其餘不影響判定。解析器的其他保護：表格列欄數不是 6、F-M-S／PI 或版本格式不對、Processor 空白、New／Updated 沒有 New Ver → 該列不收並記進 `unparsed`；
公告項目讀不到編號、文字與連結網址的編號不同 → 記進 `unparsed`（以文字為準）；不認得的小標題底下的內容不當成資料；超過 20000 字元的行不解析；重複的 release tag、沒有任何 release → 產生器失敗。
INTEL-SA 的 regex 沒有巢狀量詞（`INTEL-SA-INTEL-SA-00972` 直接從後面那個編號比到），重複 tag 用 set 檢查，都是線性。

### 缺 release notes 的 tag

GitHub 上共 49 個 tag，release notes 只有 45 段。沒有段落的是 `microcode-20230516`、`microcode-20230516a`、`microcode-20230613`、`microcode-20260210-rev1`。資料表不涵蓋它們（它們改了什麼、有沒有列公告，看不到）；
這是資料表「最新」可能落後的另一個原因，所以結果一律是候選／待人審。

### 人工對照 `prose_rules`（20250812 的那句散文）

解讀（這是我們對原文的判斷）：20250812 列的公告（INTEL-SA-01249、01308、01310、01311、01313、01367）涵蓋「2025 年 5 月 release 已發佈」的這幾個平台的微碼；
所以這些平台的 revision 比它們在 `microcode-20250512` 的 revision 舊時，把 20250812 的公告列為候選（`how=prose`）。
對照 key 的規則（產生器可重現）：成員 ＝ 在 20250812 以前（含）的 new／updated 列、Processor 欄第一個字詞（`ADL-N` 取 `ADL`）屬於 ADL／RPL／SPR／EMR／MTL／ARL 的 key；
基準 revision ＝該 key 在 20250512 的 New Ver（有兩個以上不同 → GAP）；沒有那一列就用 20250512 以前最新的 New Ver；都沒有 → GAP。
一個 key 的 Processor 字詞同時有代號內與代號外的（`06-be-00/19`：ADL-N 與 TWL）→ GAP，只加註、不推。結果：29 個 key 有基準、1 個 GAP。
SBOM 的 revision 不低於基準時不加 20250812 的公告。

## 比對規則（`fw_advisory.py`）

輸入：SBOM 裡每一份 Intel 微碼的 CPUID、platform id（遮罩）、revision，加上它的 extended signature（每個 signature 各算一次）。

1. 資料表讀不到、不是一般檔案、超過 4 MiB、sha256 與程式裡固定的 `TABLE_SHA256` 不符、JSON 或結構不對（`how` 不是 security／updated／update-to、release 沒有由新到舊、`prose_rules` 格式不對…）→ **NOT_ASSESSED**（`table-unreadable`／`table-sha-mismatch`），`fw-inventory.json` 的 `advisory.status` 是 `GAP`；有 Intel 微碼時整份狀態 ATTENTION（沒有微碼時狀態不變，報告一節仍寫 GAP）。比對本身丟出例外 → 那一份微碼 NOT_ASSESSED（`match-error`），不中斷流程。
2. revision 讀不到（要 `0x` 加 1～8 位十六進位）、platform id 讀不到、CPUID 不是 8 位十六進位 → NOT_ASSESSED。
3. CPUID → F-M-S（family＝base family，base family 0xF 時加 extended family；model＝extended model:model，family 6 或 0xF 時；stepping 在最低 4 位元）。F-M-S 不在表裡 → NOT_ASSESSED（`cpuid-not-in-table`）；
   F-M-S 在、但沒有**相同的** platform 遮罩 → NOT_ASSESSED（`platform-mismatch`，列出表裡有的遮罩；不做子集推論）。
4. 該 (F-M-S, 遮罩) 的事件（new／updated／removed；`disclosed` 不當成 revision 事件）：最新的事件是 removed → NOT_ASSESSED（`removed`）；最新的 release 對這個鍵有不同的 New Ver → NOT_ASSESSED（`ambiguous`）；只有 disclosed、也沒有候選 → NOT_ASSESSED（`no-revision-history`）。
5. 最新 revision ＝最新 release 的 New Ver。SBOM revision 比它新 → NOT_ASSESSED（`revision-newer-than-table`：資料表可能比韌體舊，或是 BIOS 專用／OEM revision；被 revert 掉的版本也走這條，不猜）。
6. **候選公告**（release 層級、取聯集，每個公告記 `how`）：
   - a. SBOM revision 低於最新時，New Ver 大於它的 release 的公告（含曾被 revert 的）；`how` 是來源的 security／updated／update-to。
   - b. **「New Disclosures Updated in Prior Releases」表**：這個鍵在揭露表有一列，而且 revision ≤ 那一列 Old／New 中有值的較大者 → 揭露那個 release 的公告列為候選（`how=disclosed`）。
     對原文的判斷：這個表列的是「先前 release 已發佈、現在才揭露有公告涵蓋」的微碼（20241112 的 ICL-D 06-6c-01/10 Old 0x010002b0、ICX-SP 06-6a-06/87 Old 0x0d0003e7，New 是 N/A；20250211 的 CFL-H/S 06-9e-0c/22 0xf6→0xf8）；
     Old／New 的確切語意原文沒有說明（N/A 沒有對應的新 revision），所以用保守規則：不高於上界的 revision 都列，寧可多列、不少列。revision 等於最新、但不高於揭露上界時也是 affected-candidate（例如 06-9e-0c/22 的 0xf8）。
   - c. **人工對照的散文**：鍵在 `prose_rules` 裡、revision 低於基準 → 20250812 的公告（`how=prose`，basis 寫明來源是散文、對照由人整理）。對照的 GAP 只加註。
   - d. **被取代的 platform 遮罩**：同一個 F-M-S 另有遮罩與 SBOM 的遮罩有交集（`a & b ≠ 0`），而且那個鍵在 SBOM 這個鍵最後一次更新之後的 release 還有 new／updated → 那些 release 的公告（`how=superseded-mask`）。
7. SBOM revision ＝最新：沒有 6.b 候選、而且 6.d 成立 → **NOT_ASSESSED**（`superseded-platform-mask`；basis 列出較新的遮罩、它的最新 revision、之後各 release 的公告當參考候選，不是發現）。
   例（資料表 `microcode-20261110`）：06-97-02/03 的最新 0x22（20220809）而 06-97-02/07 到 20260210 還在更新（0x03 ⊂ 0x07）；06-be-00/01 與 /11 對 /19；06-cc-02/90 對 /94（0x90 ⊂ 0x94，核對過）；06-b7-01/32 對 /36（0x32 ⊂ 0x36）。
   遮罩互不相交（如 06-ba-02/07 對 /e0：0x07 & 0xe0 ＝ 0）→ 結果不變，加註「同 F-M-S 的其他 platform 在 <release> 之後仍有更新」。沒有交集的新更新時 → **up-to-date**：「以資料表 <tag> 為準沒有更新的 revision；不代表沒有漏洞，以 Intel 公告為準」（不寫成「不受影響」）。
   資料表所有鍵以最新 revision 逐一代入檢查：9 個鍵是 `superseded-platform-mask`、3 個是 `removed`、2 個是 affected-candidate（06-9e-0c/22 因揭露表、06-3e-04/ed 因曾被 revert 的 release）、其餘 up-to-date。
8. SBOM revision 低於最新：有任何候選公告 → **affected-candidate**；沒有 → **older-no-sa**（有較新的 revision、但沒有列公告；不是「沒有漏洞」）。
9. 有 extended signature：每個 signature 各算一次；任何一個 affected-candidate → affected-candidate；否則任何一個 NOT_ASSESSED → NOT_ASSESSED（有一個比不到就不能寫 up-to-date）；否則有 older-no-sa → older-no-sa；否則 up-to-date；候選取聯集。
10. 候選的 basis 一定寫「公告在來源裡是 release 層級，不是逐 CPUID；候選不一定影響這個 CPUID；不是確定的發現」。NOT_ASSESSED 的 basis 一律以「資料庫沒有資料，以廠商公告為準」收尾（SBOM 內是英文 `no data in the database; the vendor advisory (Intel INTEL-SA) is authoritative`）。
    revision 出現在揭露表（Old／New 任一欄）→ 另外在 `dumpling:advisory-note` 與報告加註。

資料表只涵蓋 Intel 公開的 Linux 微碼套件。Intel 倉庫 README：「Certain MCUs must only be applied from the BIOS. Such MCUs are never packaged in this package」，OEM 拿到的是超集。所以 BIOS 映像裡的 revision 比表新或表裡沒有，是預期會發生的情況，一律 NOT_ASSESSED 或加註，不猜。

### SBOM property（微碼元件）

`dumpling:advisory-match`（四種值之一）、`dumpling:advisory-candidates`（只有 affected-candidate：以逗號分隔的 INTEL-SA）、`dumpling:advisory-basis`、`dumpling:advisory-latest-revision`（`0x… (<tag>)`，有就寫）、
`dumpling:advisory-source`（倉庫、tag、commit 前 12 碼、來源與資料表 sha256 前 16 碼）、`dumpling:advisory-note`（可多筆）。`dumpling:vuln-assessment` 維持 `NOT_ASSESSED`，note 換成 `ASSESS_NOTES["intel-microcode"]`
（說明候選在 `dumpling:advisory-*`、是 release 層級候選、不是確定的發現、需要人工對 Intel 公告）。Intel ME 元件也有 `advisory-match: NOT_ASSESSED` 與 basis（沒有機器可讀的 CSME 公告資料表）。
其他元件（FSP、GOP／VBT／legacy VBIOS、coreboot、edk2、BIOS 映像、NVIDIA vBIOS）沒有比對，仍只有 `vuln-assessment: NOT_ASSESSED` 與各自的說明；`fw-inventory.md` 的「公告比對」一節每次輸出都有，逐一寫明這些項目沒有比對（NVIDIA vBIOS 的公告比對這一版沒有做）。

## Intel CSME 的 CPE

查證日 2026-11-13，NVD 公開 API（不需金鑰）。

- `…/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:o:intel:converged_security_management_engine_firmware:*`：**53 筆**（vendor `intel`、product `converged_security_management_engine_firmware`、part `o`）。
  預期的拼法 `converged_security_and_management_engine_firmware`（含 `and`）：**0 筆**；`and` 的拼法只出現在 part `a` 的 `converged_security_and_management_engine`（18 筆，是軟體元件，不是韌體）。程式用的是 53 筆那個。
- 版本字串：只有 `major.minor` 或 `major.minor.hotfix`（例如 `11.8.50`、`12.0.45`、`13.0.10`、`14.0.10`、`14.5.11`，另有 `-`、edition 欄位 `iot`），**沒有四段**，字典最大到 `14.5.11`。
  我們從 `$MN2` 讀到的是 `major.minor.hotfix.build`（例如 `14.0.47.1558`）。
- CVE 的 configurations（`…/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:intel:converged_security_management_engine_firmware`）：**36 筆 CVE**，最新是 CVE-2022-38102；
  比對條件是 `cpe:…:converged_security_management_engine_firmware:*:…` 加三段的 `versionStartIncluding`（`11.0`、`12.0.0`）與 `versionEndExcluding`（`12.0.6`…最高 `16.1.27`）。
  所以 **NVD 對 CSME 的資料止於 2022**，字典也沒有 14.5.11 之後的版本；之後 Intel 公告的 CSME 弱點，NVD 沒有用這個 CPE 設定。這就是「NVD 資料不完整」的依據，寫進 `dumpling:cpe-note`。
- 同為 `o` 的其他韌體是不同的 product：TXE ＝ `trusted_execution_engine_firmware`（版本 3.0～4.0.x）、SPS ＝ `server_platform_services_firmware`（3.0.6.267.4～5.00.04.012，版本字串格式很雜）。`o` 類 product 裡 major 版本 11 以上只有 CSME。
- AMT（`active_management_technology_firmware`，part o）是另一個 product，版本也有 11.x～14.5.x（89 筆，2026-11-13）；CSME 的 CPE 比不到 AMT 的 CVE 設定。所以不能說「11 以上只有 CSME」，只能說 TXE、SPS 的版本都低於 11。
- **轉換**：CPE 版本只放 `$MN2` 版本的前三段（`14.0.47.1558` → `14.0.47`），build 號丟掉（NVD 沒有、範圍比較也只用三段）；元件的 `version` 維持四段。三段以下或非純數字的版本不帶 CPE。
- **family**：映像分不出 CSME／TXE／SPS（`sca-center:me-family` 仍寫 `unknown`）。帶 CPE 的條件：版本清單的 me 列寫明 `CSME`（不看版本範圍）；或映像沒有清單、major 版本在 **11～30** → 由版本推定為 CSME（`dumpling:cpe-basis` 寫「inferred from the version」與依據，報告寫「family 是由版本推定的，比對結果待人審」）。
  依據：NVD 上 TXE（`trusted_execution_engine_firmware`）與 SPS（`server_platform_services_firmware`）的版本都低於 11，AMT 是另一個 product 不會被這個 CPE 比到。
  上限 30 是判斷：CSME 大約每年加一個 major（目前最高約 20），`$MN2` 裡雜散的欄位值是幾百到幾萬，超過 30 就不是版本欄位。清單寫 ME／TXE／SPS → 不帶；major < 11 或 > 30 且 family 不明、少於三段、非數字 → 不帶，`dumpling:cpe-gap` 寫原因（GAP）。
  這個推定由 C0 的決定 D-051 採用；要退回「一律不推定」，把 `csme_cpe_info` 的 11～30 那個分支拿掉即可。
- 帶 CPE 時一定同時帶 `dumpling:cpe-note`：「NVD 對 Intel CSME 的 CPE 與版本範圍資料不完整；Grype 沒比到不代表沒有漏洞（臨時 DT 關閉 NVD 資料源，只有 CPE 的元件在 DT 比不到）；以 Intel 公告（INTEL-SA）為準」。
  臨時 DT 的設定（`pipeline/dt-ephemeral.sh`）：NVD 資料源關閉、只開 OSV 與 KEV，所以 CPE 是給 Grype（`sca-scan` 的 C-grype，使用它自己的 NVD 資料庫）用的，不是給臨時 DT 用的。
- `firmware_dt.py prep`：「不加猜的 purl／cpe」的意思是 prep 自己不加、不改、不拿掉元件內容（元件原樣上傳）；`tests/test_firmware_dt.py` 新增測試確認帶 CPE 與 `dumpling:advisory-*` 的元件經過 prep 完全不變、`with_cpe` 計入。規則不用改。

## 重新產生資料表（人工步驟，CI 不抓 Intel 的檔案）

1. 到上面的倉庫找要用的 tag，記下它指到的 commit；改 `intel_ucode_releases.py` 的 `TAG`、`COMMIT`、`RETRIEVED`。
2. 下載 `releasenote.md`（用 commit SHA 的 raw 網址）到一個新的空資料夾，算 sha256 與大小，填進 `SOURCE_SHA256`、`SOURCE_BYTES`。檔案只當文字讀、不執行。
3. `python3 -I tools/cra/intel_ucode_releases.py generate --source <檔案> --out tools/cra/data/intel-microcode-releases.json`（不給 `--source` 會自己下載固定網址）；輸出一行含資料表的 sha256。
4. 把那個 sha256 填進 `fw_advisory.py` 的 `TABLE_SHA256`；看 `unparsed` 有沒有新的看不懂的段落（逐項判斷會不會影響候選，必要時加進 `PROSE_RULES`；`prose_rules` 的行號與原文對不上時產生器會失敗），更新這份 notes 與 `test_committed_table_matches_pinned_sha256_and_generator_constants` 的預期。
5. `python3 -I tools/cra/intel_ucode_releases.py verify --source <檔案> --table tools/cra/data/intel-microcode-releases.json`：重新解析固定來源，與資料表逐項比對（`generated_at` 不比），確認表可由來源重現。
6. 跑 `tests/run.d/c2-x86-firmware.sh`；對公開樣本重跑 `pipeline/firmware-bios.sh`，抽幾筆對原始 `releasenote.md` 人工核對。

## 公開樣本的結果（2026-11-13，資料表 `microcode-20261110`）

| 樣本 | CPUID／platform／revision | F-M-S／PI | 結果 | 資料表最新 |
|---|---|---|---|---|
| Protectli VP46xx（Dasharo v1.2.0） | 000806EC／0x94／0xF8 | 06-8e-0c／94 | affected-candidate：20240312、20240813、20250512 三個 release 的 14 個 INTEL-SA | 0x100（20250512） |
| 同上 | 000A0660／0x80／0xF8 | 06-a6-00／80 | affected-candidate（同樣 14 個） | 0x102（20250512） |
| 同上 | 000A0661／0x80／0xF8 | 06-a6-01／80 | affected-candidate（同樣 14 個） | 0x100（20250512） |
| NUC11（PATGL357.0059） | 000806C2／0xC2／0x16 | 06-8c-02／c2 | affected-candidate：11 個 release、24 個 INTEL-SA | 0x3e（20260210） |
| 同上 | 000806C1／0x80／0xBE | 06-8c-01／80 | up-to-date（不代表沒有漏洞） | 0xbe（20260210） |
| Novacustom（V540TU-MTL v1.0.1） | 000A06A4／0xE6／0x25 | 06-aa-04／e6 | affected-candidate：20260210、20260811、20260925，10 個 INTEL-SA | 0x2b（20260925） |

（審查後的修正：揭露表、散文對照、被取代的遮罩三項加進規則，三個樣本重跑結果與上表相同：它們的鍵都不在揭露表與散文對照，也沒有與較新的遮罩重疊的鍵。）

ME：Protectli 是 `14.0.47.1558`，family 讀不出來、major 14 在 11～30 → 由版本推定 CSME（待人審），CPE `cpe:2.3:o:intel:converged_security_management_engine_firmware:14.0.47:*:*:*:*:*:*:*`（basis 與 NVD 不完整的 note 都在元件上）。
NUC11 的檔案沒有 flash descriptor／`$FPT`／FTPR（ME 讀不到）、Novacustom 的 ME 版本 unknown（`$MN2` 候選不確定屬於哪個分割區）→ 都沒有 CPE，報告寫明原因。

人工核對（對 commit `d71fe4e2…` 的 `releasenote.md`，行號是該檔的行號）：
- 000806EC／0x94／0xF8：`06-8e-0c/94` 在 963–966 行（20230808，`000000f6 → 000000f8`，Purpose 897–899 行：INTEL-SA-00828／00836／00837）＝0xF8 是那個 release 的 New Ver；
  之後 797–836 行（20240312：f8→fa；Purpose 748–752：00972、00982、00898、00960、01045）、648–676 行（20240813：fa→fc；Purpose 612–616：01083、01118、01100、01038、01046）、
  401–433 行（20250512：fc→100；Purpose 353–356：01153、01244、01247、01322）；20250512 之後沒有更新的列。與工具輸出的 14 個 INTEL-SA、三個 release 一致。
- 000806C1／0x80／0xBE：`06-8c-01/80` 在 237 行（20260210：bc→be），再沒有更新的列 → up-to-date。
- 000806C2／0xC2／0x16：`06-8c-02/c2` 在 1402 行（20220207：16→22）起每個 release 一列，到 239 行（20260210：3c→3e）。

## 限制與刻意保守的地方

- 公告只在 release 層級：候選清單是 superset，不是「這個 CPUID 受哪些公告影響」。Intel 公告頁面（INTEL-SA）才有受影響的處理器清單；本工具沒有去抓。
- `up-to-date`、`older-no-sa` 都不代表沒有漏洞：資料表的「最新」是 Intel Linux 套件在 `microcode-20261110` 為止的最新；BIOS 專用的微碼不在裡面。
- 不做 CPUID 的 platform 子集推論（只在「同 F-M-S 的遮罩有交集且較新的鍵還有更新」時降成 NOT_ASSESSED 或加候選）、不猜被 revert／移除的 revision；New Disclosures 表只用保守的上界規則（見規則 6.b），不判斷它的確切語意。
- 20250812 的散文對照由人整理，GAP 的鍵只加註。
- 微碼只比 Intel；AMD 微碼沒有解析（原本就是 GAP）。ME／TXE／SPS 的公告沒有機器可讀資料，NVIDIA vBIOS 的公告比對這一版沒有做。
- 資料表不隨 CI 更新：它會變舊。`microcode-20261110` 之後的 release 不在裡面（比表新的 revision 會是 `revision-newer-than-table`，不會被當成 up-to-date）。
