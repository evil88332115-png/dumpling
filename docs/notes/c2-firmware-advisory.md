# C2：韌體 SBOM 的公告比對（Intel 微碼、NVIDIA vBIOS）與 Intel CSME 的 CPE（分支 wp3/fw-advisory、wp3/nvidia-vbios-advisory）

只用公開樣本與公開資料。這份是工作紀錄，不是驗證結論；數字都是 2026-11-13 對固定來源與公開樣本量的。
比對結果是**候選**，不是漏洞判定：`dumpling:vuln-assessment` 仍然是 `NOT_ASSESSED`，沒有任何狀態或文字表示「沒有漏洞」。

## 檔案

| 檔案 | 內容 |
|---|---|
| `tools/cra/intel_ucode_releases.py` | 資料表產生器：固定來源（tag、commit、sha256）→ 解析 → JSON。`generate`、`verify` 兩個子命令 |
| `tools/cra/data/intel-microcode-releases.json` | 產生出來的資料表（約 80 KB，進 repo）。每個 release 的 tag、日期、INTEL-SA 清單、各 F-M-S／platform id 的 revision 變化、人工對照 `prose_rules`；附來源 URL、tag、commit、sha256、產生時間、看不懂的段落（`unparsed`，只有行號與原因）。只放事實性欄位（見「授權」） |
| `tools/cra/fw_advisory.py` | 離線比對：載入資料表（核對 sha256 與結構）、CPUID → F-M-S、revision 比較、結果分類 |
| `tools/cra/x86_firmware.py` | 呼叫比對、SBOM property（`dumpling:advisory-*`）、`fw-inventory.md` 的「公告比對」一節、資料表不能用時 ATTENTION；ME 的 CPE 與 `dumpling:cpe-*` |
| `pipeline/firmware-ci.sh`、`pipeline/lib/firmware_advisory_cell.py`、`pipeline/lib/firmware_dt.py` | CI 摘要表有一欄「公告比對」（微碼，有 NVIDIA vBIOS 時加一段；文字由 `firmware_advisory_cell.py` 從 `fw-inventory.json` 產生：每個 BIOS 映像各一段，Intel 計數、AMD 已解析份數或 PSP 解析沒有執行的 GAP、資料表 GAP）；DT 報告的說明與每個樣本的 `advisory-match` 計數（標籤中性，含 AMD 元件） |
| `tools/cra/tests/test_fw_advisory.py`、`test_x86_firmware_sbom.py`、`tests/test_firmware_dt.py` | 測試（合成資料，不連網） |
| `tools/cra/nvidia_vbios_advisory.py`、`tools/cra/tests/test_nvidia_vbios_advisory.py`、`tools/pilot/lib/nvidia-bulletins-gpu-firmware.json` | NVIDIA vBIOS 的離線比對、測試、公告對照表（是否已經負責人確認見最後一節） |

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
一個 key 的任何一列（≤ 20250812）的 Processor 字詞屬於代號清單就納入（保守；多列可以）：`06-be-00/19` 的 Processor 欄是 ADL-N 加 TWL，納入，基準是 20250512 的 0x1d。
同 F-M-S 的其他 platform、但原文沒提到的 key 不納入，記進 `unlisted`、比對時加註：`06-9a-04/40`（AZB，與 ADL 的 06-9a-04/80 同 F-M-S）。結果：30 個 key 有基準、0 個 GAP、1 個 `unlisted`。
基準有歧義（兩個不同的 New Ver）或沒有任何基準的 key 才是 GAP（只加註、不推）；清單的代號沒有任何 key 時也記 GAP。
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
   - c. **人工對照的散文**：鍵在 `prose_rules` 裡、revision 低於基準 → 20250812 的公告（`how=prose`，basis 寫明來源是散文、對照由人整理）。對照的 GAP 與 `unlisted` 只加註。
   - d. **被取代的 platform 遮罩**：同一個 F-M-S 另有遮罩與 SBOM 的遮罩有交集（`a & b ≠ 0`），而且那個鍵在 SBOM 這個鍵最後一次更新之後的 release 還有 new／updated → 那些 release 的公告（`how=superseded-mask`）。
7. SBOM revision ＝最新：沒有 6.b 候選、而且 6.d 成立 → **NOT_ASSESSED**（`superseded-platform-mask`；basis 列出較新的遮罩、它的最新 revision、之後各 release 的公告當參考候選，不是發現）。
   例（資料表 `microcode-20261110`）：06-97-02/03 的最新 0x22（20220809）而 06-97-02/07 到 20260210 還在更新（0x03 ⊂ 0x07）；06-be-00/01 與 /11 對 /19；06-cc-02/90 對 /94（0x90 ⊂ 0x94，核對過）；06-b7-01/32 對 /36（0x32 ⊂ 0x36）。
   遮罩互不相交（如 06-ba-02/07 對 /e0：0x07 & 0xe0 ＝ 0）→ 結果不變，加註「同 F-M-S 的其他 platform 在 <release> 之後仍有更新」。沒有交集的新更新時 → **up-to-date**：「以資料表 <tag> 為準沒有更新的 revision；不代表沒有漏洞，以 Intel 公告為準」（不寫成「不受影響」）。
   資料表所有鍵以最新 revision 逐一代入檢查：9 個鍵是 `superseded-platform-mask`、3 個是 `removed`、1 個是 affected-candidate（06-9e-0c/22，因揭露表）、其餘 up-to-date。06-3e-04/ed 的 0x42e 等於最新（20190514 列過 0x42f，20190514a 退回 0x42e），結果是 up-to-date，並加一則 note 說明這段歷史。
8. SBOM revision 低於最新：有任何候選公告 → **affected-candidate**；沒有 → **older-no-sa**（有較新的 revision、但沒有列公告；不是「沒有漏洞」）。
9. 有 extended signature：每個 signature 各算一次；任何一個 affected-candidate → affected-candidate；否則任何一個 NOT_ASSESSED → NOT_ASSESSED（有一個比不到就不能寫 up-to-date）；否則有 older-no-sa → older-no-sa；否則 up-to-date；候選取聯集。
10. 候選的 basis 一定寫「公告在來源裡是 release 層級，不是逐 CPUID；候選不一定影響這個 CPUID；不是確定的發現」。NOT_ASSESSED 的 basis 一律以「資料庫沒有資料，以廠商公告為準」收尾（SBOM 內是英文 `no data in the database; the vendor advisory (Intel INTEL-SA) is authoritative`）。
    revision 出現在揭露表（Old／New 任一欄）→ 另外在 `dumpling:advisory-note` 與報告加註。

資料表只涵蓋 Intel 公開的 Linux 微碼套件。Intel 倉庫 README：「Certain MCUs must only be applied from the BIOS. Such MCUs are never packaged in this package」，OEM 拿到的是超集。所以 BIOS 映像裡的 revision 比表新或表裡沒有，是預期會發生的情況，一律 NOT_ASSESSED 或加註，不猜。

### SBOM property（微碼元件）

`dumpling:advisory-match`（四種值之一）、`dumpling:advisory-candidates`（只有 affected-candidate：以逗號分隔的 INTEL-SA）、`dumpling:advisory-basis`、`dumpling:advisory-latest-revision`（`0x… (<tag>)`，有就寫）、
`dumpling:advisory-source`（倉庫、tag、commit 前 12 碼、來源與資料表 sha256 前 16 碼）、`dumpling:advisory-note`（可多筆）。`dumpling:vuln-assessment` 維持 `NOT_ASSESSED`，note 換成 `ASSESS_NOTES["intel-microcode"]`
（說明候選在 `dumpling:advisory-*`、是 release 層級候選、不是確定的發現、需要人工對 Intel 公告）。Intel ME 元件也有 `advisory-match: NOT_ASSESSED` 與 basis（沒有機器可讀的 CSME 公告資料表）。
其他元件（FSP、GOP／VBT／legacy VBIOS、coreboot、edk2、BIOS 映像）沒有比對，仍只有 `vuln-assessment: NOT_ASSESSED` 與各自的說明；`fw-inventory.md` 的「公告比對」一節每次輸出都有，逐一寫明這些項目沒有比對（NVIDIA vBIOS 另有自己的比對，見「NVIDIA vBIOS 的公告比對」一節）。

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
- **family**：映像分不出 CSME／TXE／SPS（`sca-center:me-family` 仍寫 `unknown`）。帶 CPE 的條件：版本清單的 me 列寫明 `CSME`（這時**不套** major 11～30 的範圍：清單是人寫明的 family，只要版本是三段以上的數字就帶）；或映像沒有清單、major 版本在 **11～30** → 由版本推定為 CSME（`dumpling:cpe-basis` 的值固定是 `listed` 或 `inferred`，說明文字在 `dumpling:cpe-basis-note`；報告寫「family 是由版本推定的，比對結果待人審」）。
  依據：NVD 上 TXE（`trusted_execution_engine_firmware`）與 SPS（`server_platform_services_firmware`）的版本都低於 11，AMT 是另一個 product 不會被這個 CPE 比到。
  上限 30 是判斷：CSME 大約每年加一個 major（目前最高約 20），`$MN2` 裡雜散的欄位值是幾百到幾萬，超過 30 就不是版本欄位。清單寫 ME／TXE／SPS → 不帶；清單對同一個 ME 版本同時寫了不同 family（例如 CSME 與 TXE，自相矛盾）→ 不推定、不帶 CPE，`dumpling:cpe-gap` 寫「版本清單 family 矛盾」，狀態 ATTENTION；major < 11 或 > 30 且 family 不明、少於三段、非數字 → 不帶，`dumpling:cpe-gap` 寫原因（GAP）。
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

## 公開樣本的結果（資料表 `microcode-20261110`，四個公開樣本：Protectli、NUC11、Novacustom、B550M）

| 樣本 | CPUID／platform／revision | F-M-S／PI | 結果 | 資料表最新 |
|---|---|---|---|---|
| Protectli VP46xx（Dasharo v1.2.0） | 000806EC／0x94／0xF8 | 06-8e-0c／94 | affected-candidate：20240312、20240813、20250512 三個 release 的 14 個 INTEL-SA | 0x100（20250512） |
| 同上 | 000A0660／0x80／0xF8 | 06-a6-00／80 | affected-candidate（同樣 14 個） | 0x102（20250512） |
| 同上 | 000A0661／0x80／0xF8 | 06-a6-01／80 | affected-candidate（同樣 14 個） | 0x100（20250512） |
| NUC11（PATGL357.0059） | 000806C2／0xC2／0x16 | 06-8c-02／c2 | affected-candidate：11 個 release、24 個 INTEL-SA | 0x3e（20260210） |
| 同上 | 000806C1／0x80／0xBE | 06-8c-01／80 | up-to-date（不代表沒有漏洞） | 0xbe（20260210） |
| Novacustom（V540TU-MTL v1.0.1） | 000A06A4／0xE6／0x25 | 06-aa-04／e6 | affected-candidate：20260210、20260811、20260925，10 個 INTEL-SA | 0x2b（20260925） |

ME：Protectli 是 `14.0.47.1558`，family 讀不出來、major 14 在 11～30 → 由版本推定 CSME（待人審），CPE `cpe:2.3:o:intel:converged_security_management_engine_firmware:14.0.47:*:*:*:*:*:*:*`（basis 與 NVD 不完整的 note 都在元件上）。
Novacustom 的 ME 是 `18.0.10.2285`（intel_cse_layout 讀到），major 18 在 11～30，同樣由版本推定 CSME，CPE `…:18.0.10:*:*:*:*:*:*:*`。NUC11 的檔案沒有 flash descriptor／`$FPT`／FTPR（ME 讀不到）→ 沒有 CPE，報告寫明原因。
B550M（AMD）沒有 Intel 微碼與 ME；AMD 微碼 19 份、PSP 韌體 78 項、AGESA 1 個都已解析，每個元件有 `dumpling:advisory-match=NOT_ASSESSED`（AMD-SB 的規則表還沒有做，以 AMD 公告為準）。

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
- 微碼只比 Intel。AMD 的微碼、PSP 韌體、AGESA 已由 `amd_psp.py` 解析，每個元件有 `advisory-match=NOT_ASSESSED`（資料庫沒有資料，以 AMD 公告為準；AMD-SB 的規則表還沒有做）。ME／TXE／SPS 的公告沒有機器可讀資料。NVIDIA vBIOS 的比對見最後一節。
- 資料表不隨 CI 更新：它會變舊。`microcode-20261110` 之後的 release 不在裡面（比表新的 revision 會是 `revision-newer-than-table`，不會被當成 up-to-date）。

## NVIDIA vBIOS 的公告比對（決定 D-043 的 (1)）

查證日 2026-11-14。只用公開資料（NVIDIA product-security 公開倉庫）；表只放事實性欄位（公告編號、CVE、產品名稱、版本），不抄公告原文。

### 檔案與資料流

| 檔案 | 內容 |
|---|---|
| `tools/mirror/nvidia-bulletins.sh`（C1，沒改） | 更新主機下載公告鏡像（人工步驟用；CI 不連網） |
| `tools/pilot/lib/nvidia_bulletins.py`（C1，沒改） | `validate_table`（C2 的比對先用它驗表）、`candidates --group gpu-firmware`（列出待審公告） |
| `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json` | 對照表（內容依 D-043 整理，需經負責人確認；確認前一律 NOT_ASSESSED）。目前沒有可比對的列，有一筆 `not_applicable`（5674） |
| `tools/cra/nvidia_vbios_advisory.py` | 離線比對：讀上面的表、驗證、依 vBIOS 版本與 PCI vendor／device ID 判斷（規則在檔頭與下面） |
| `tools/cra/x86_firmware.py` | 每個 NVIDIA vBIOS 比對一次（`inv["vbios"][i]["advisory"]`、`inv["vbios_advisory"]`）、SBOM 的 `dumpling:advisory-*`、`fw-inventory.md` 的 vBIOS 段落、表不能用時狀態 ATTENTION |
| `pipeline/lib/firmware_advisory_cell.py`、`pipeline/lib/firmware_dt.py` | CI 摘要欄加 vBIOS 一段；DT 報告「怎麼讀」寫明 vBIOS 的 `advisory-match` |

CI 與一般使用都只讀 repo 裡的表，不連網；鏡像只在人工審核表的時候用。

### 審核了什麼（鏡像 commit `98dc5d70d87f6f068c38161930fcda2ae3193bb3`，commit 日期 2026-11-10，下載 2026-11-13）

鏡像：倉庫 204 則公告，選入 36 則（jetson 15、gpu-firmware 1、gpu-driver 20）；`--check` OK。gpu-firmware 群組（標題或 CSAF 產品名稱有 VBIOS、GPU firmware）**只有 1 則**：

| 公告 | 日期 | 結論 | 依據（CSAF 欄位與公告表格） |
|---|---|---|---|
| 5674「NVIDIA HGX and DGX VBIOS and LS10 - September 2025」（CVE-2025-23301、CVE-2025-23302，CWE-1244，CVSS 4.2） | 2025-09-02（沒有修訂） | **初審意見：無法對應到顯卡 option ROM 的 vBIOS**（`not_applicable` 項、`reviewed`＝false、初審者「韌體分析（C2 角色）初審，待負責人確認」；尚未經負責人確認，所以 `candidates` 仍列為待審） | `product_tree`：產品只有「HGX, DGX Hopper」「HGX, DGX Blackwell」（CPE `cpe:2.3:a:nvidia:hgx_dgx_hopper`、`…hgx_dgx_blackwell`），`architecture` 分支是 VBIOS 與 LS10（NVSwitch）。`vulnerabilities[].product_status`：`known_affected`＝「All versions prior to and including 1.7.1」（Hopper）／「…1.2.0」（Blackwell），`fixed`＝1.8.0／1.2.1。`remediations` 空。版本是 HGX／DGX 平台韌體的三段十進位版本，不是顯卡 option ROM 的 `XX.XX.XX.XX.XX`；公告與 CSAF 都沒有 PCI vendor／device ID 或型號清單，沒有兩種版本的對應。這不是「不影響」的結論，只是無法機器對應：範圍看不出來，所以不猜、不放進 `rows` |

順帶看過 gpu-driver 群組（20 則，標題都是顯示驅動、GeForce Experience 等）：全文找 `vbios`、`gpu firmware`，只有 5674 與 5861（2026-10-13，GPU Display Driver）有字串；5861 的符合是 vGPU Manager 的「GPU System Processor (GSP)」元件，不是 vBIOS。這 20 則屬於驅動的對照表（`--group gpu-driver`），這次沒有審核，也沒有放進 gpu-firmware 的表。

另外在搜尋時看到公告 5561（Hopper HGX 8-GPU HMC，CVE-2024-0141 的描述提到 GPU vBIOS）：它不在 gpu-firmware 群組（群組選取是 C1 的規則，只看標題、CSAF 產品名稱與 CVE_index），不在這份鏡像的選入清單裡；版本是 HMC 版本、沒有 PCI 裝置 ID，同樣無法對應到 option ROM 版本，沒有放進表。

表的內容：`reviewed_until` ＝ **null**（尚未經負責人確認）、`mirror`（commit、commit_date、fetched_utc；初審用的鏡像）、`not_applicable`＝[5674 的初審意見，`reviewed=false`，`reviewed_by`／`reviewed_at` 是 null，初審者寫在 `preliminary_by`]、`rows`＝[]。`candidates --group gpu-firmware` 對這個鏡像是 **ATTENTION**（5674：`unreviewed_not_applicable`、`after_reviewed_until`），直到負責人確認。確認後把 5674 項改成 `reviewed=true` 並填 `reviewed_by`（角色）與 `reviewed_at`，`reviewed_until` 填 gpu-firmware 群組看過的最新公告日期（目前是 5674 的 **2025-09-02**）。`reviewed_until` 是審核者看過的最新公告日期；鏡像的時間點另記在頂層 `mirror.commit_date`（2026-11-10），兩者分開。

**結論：目前沒有任何顯卡 vBIOS 的公開公告可以機器比對。** 所有 NVIDIA vBIOS 的結果都是 NOT_ASSESSED（`table-not-reviewed`：表尚未經負責人確認）；負責人確認 5674 之後會是 `no-row`。這不代表 vBIOS 沒有漏洞：NVIDIA 對消費型與專業型顯卡的 vBIOS 幾乎沒有公開公告，主要管道是 NVIDIA 的合作夥伴通知。

### 列的格式（表有可比對的列時）

沿用 C1 的 `sca-nvidia-bulletins-table/1`；C1 的程式只認它自己的欄位（版本欄位只收點分十進位），C2 的比對在 `tools/cra/` 讀以下額外欄位（C1 的 `validate_table` 不檢查、也不拒絕它們；C2 的比對自己再驗已審核的列）。`line` 寫 `vbios`，C1 的 `fixed_in`、`affected_below`、`affected_max` 留 `null`。

| 欄位 | 說明 |
|---|---|
| `pci_vendor` | `10de` |
| `pci_devices` | PCI device ID 清單，每個 4 位小寫十六進位（來自公告的型號對照；公告沒有給裝置範圍就不能審核成列） |
| `vbios_affected_below`／`vbios_affected_max` | 受影響版本「低於」／「最高到（含）」（二選一） |
| `vbios_fixed_in` | 修正版本；至少要有這三個欄位的其中一個 |
| 其他 | `bulletin`、`cve`、`reviewed`、`reviewed_by`（角色）、`reviewed_at`、`source`、`note` 同 `nvidia-bulletins.md` |

版本寫成 option ROM 的 `XX.XX.XX.XX.XX`（每段兩位十六進位，按數值比，不分大小寫），可只寫前幾段（例如 `94.04`），比較時只比 SBOM 版本的前幾段。已審核的列欄位不對 → 整張表 NOT_ASSESSED（`table-invalid`），不是靜默少算。

### 比對規則（`nvidia_vbios_advisory.py`，依序，第一個成立的就是結果）

輸入：inventory 裡每個 NVIDIA vBIOS（`x86_firmware.is_vbios`：vendor 0x10DE 且有 x86 或 EFI 影像）的版本、PCI vendor、各開機影像的 device ID。

1. 表讀不到、不是一般檔案（symlink 也拒絕）、超過 4 MiB、不是 JSON、C1 的 `validate_table` 失敗、已審核的列欄位不對 → NOT_ASSESSED（`table-unreadable`／`table-invalid`），`vbios_advisory.status` ＝ GAP，狀態 ATTENTION。
2. `reviewed_until` 是 null，或表裡還有只有初審意見（`reviewed=false`）的公告（即使 `reviewed_until` 已填）→ 表尚未經負責人確認 → NOT_ASSESSED（`table-not-reviewed`；basis 寫「表尚未經負責人確認」並列出只有初審意見的公告）。
3. 版本讀不到、不是五段兩位十六進位（`XX.XX.XX.XX.XX` 佔位、四或六段、多餘空白）→ NOT_ASSESSED（`version-unreadable`）；ROM 裡有兩個以上不同的 `XX.XX.XX.XX.XX` 字串（`x86_firmware` 數出來記在 `other_versions`，只有這時才有這個鍵，SBOM 元件加 `sca-center:note`）→ `version-ambiguous`，不給 fixed。
4. vendor 不是 10de（ROM 與每個 x86／EFI 開機影像都要是 10de）→ `vendor-mismatch`；device ID 讀不到（空、非 4 位十六進位、0000、ffff）→ `device-unreadable`；x86／EFI 影像的 device ID 不一致 → `device-ambiguous`。
5. option ROM 鏈沒有正常結束（輸入沒有 `terminated` 這個鍵也算）或開頭不確定 → NOT_ASSESSED（`rom-incomplete`）：版本字串可能不是這個 ROM 的。
6. 找表裡「已審核、vendor 與 device ID 都對得上」的列。沒有 → NOT_ASSESSED（`no-row`）。表裡有任何未審核的列（`rows[].reviewed=false`）時，整張表算未經負責人確認，結果是 `table-not-reviewed`（和只有初審意見的公告一樣），不會只用已審核的列給 fixed。裝置不符就是沒有對應的列，不拿別的裝置的列套用。
7. 逐列比版本：版本 ≥ `vbios_fixed_in` → fixed；低於 `vbios_affected_below`（或不高於 `vbios_affected_max`）→ affected；落在受影響範圍與修正版本之間的空隙、或列沒有可比較的版本 → gap。
   整份：任何 affected → **affected**（有 gap 的列、已修補的列另加註）；沒有 affected、有 gap → NOT_ASSESSED（`range-gap`）；全部 fixed → **fixed**。
8. 已審核的表，`mirror` 整個沒寫或是 null（日期不明）、`mirror.fetched_utc` 超過 90 天（正好 90 天不算）或在未來（比現在晚超過一天）：fixed 降成 NOT_ASSESSED（`table-stale`，表可能漏了較新的公告）；affected 與其他結果照舊但加註「重新審核表」；有 vBIOS 元件時 `fw-inventory` 狀態 ATTENTION（`vbios_advisory.stale`）。
   `mirror` 有寫就三個鍵 `commit`（40 碼小寫十六進位）、`commit_date`、`fetched_utc` 都要有；缺一個、不是物件、或時間格式不對（沒有時區也算）：載入時就是 `table-invalid`，不是 `table-stale`。時間只收 `YYYY-MM-DDTHH:MM:SS`，秒後面可以有 3 或 6 位小數，時區寫 `Z` 或 `±HH:MM`（不靠 `fromisoformat`：Python 3.10 與 3.12 能讀的格式不同；`+0000`、空白分隔、沒有秒、其他位數的小數都不收）。
   現在時間由呼叫端傳入（`inventory(vbios_now=…)`、`match_vbios(now=…)`；沒給才用牆上時鐘，沒有時區的時間當成 UTC），測試一律傳固定時間，不吃時鐘。

公告編號（`bulletins[].id`、`rows[].bulletin`、`not_applicable[].bulletin`，含未審核的）只收 1～8 位 ASCII 數字（`^[0-9]{1,8}$`，與 C1 `nvidia_bulletins.py` 的 `BULLETIN_ID_RE` 相同，用 `fullmatch`，`$` 不放行結尾換行）：這些編號會寫進 fw-inventory.md 與 SBOM 的 property，不合整張表 `table-invalid`。
報告的「對照表」那一行與 `Table.confirmed` 同一個判斷：`reviewed_until` 有值、沒有只有初審意見的公告、沒有未審核的列，缺一個就寫「表尚未經負責人確認」並列出原因與未審核的筆數。
fw-inventory.md 的字串經 `md_esc`：`@` 提及與 email 形式、裸網址、`mailto:`／`xmpp:` 與 `firmware_mdsafe` 同一份規則（載入 `pipeline/lib/firmware_mdsafe.py` 的 `defang_at`／`defang_links`）；公告編號的格式限制是第二道防線，兩道都留著：表是 repo 內審核過的檔案，但報告輸出不該依賴表一定乾淨。

表驗證另外擋下自相矛盾的列：`vbios_fixed_in` 低於 `vbios_affected_below`，或不高於 `vbios_affected_max`（缺的段補 00／FF 後比）→ 整張表 `table-invalid`（`affected_below` 等於 `fixed_in` 是正常的「prior to X、fixed in X」，不擋）。

NOT_ASSESSED 的 basis 一律以「no data in the database; the vendor advisory is authoritative」收尾，並說明消費型 vBIOS 幾乎沒有公開公告、要問顯卡團隊或 NVIDIA 的合作夥伴管道（報告的中文是「資料庫沒有資料，以廠商公告為準」）。
affected 與 fixed 的 basis 寫「只比對表裡已審核的列、不是完整的漏洞判定、以廠商公告為準」，fixed 另寫「不代表沒有其他漏洞」，並加註「PCI device ID 取自 option ROM 的 PCIR 標頭，板子執行時回報的 ID 可能不同（沒有檢查）；版本是 ROM 裡第一個 `XX.XX.XX.XX.XX` 字串」。
`dumpling:vuln-assessment` 仍是 `NOT_ASSESSED`（沒有充分理由改：表只涵蓋被審核的公告）；不出現「安全」「不受影響」或整體 PASS。

SBOM 的 vBIOS 元件：`dumpling:advisory-match`（affected／fixed／NOT_ASSESSED）、`dumpling:advisory-bulletins` 與 `dumpling:advisory-cves`（只有 affected／fixed）、`dumpling:advisory-basis`、`dumpling:advisory-source`
（NVIDIA product-security 鏡像 commit 前 12 碼、下載時間、表的 `reviewed_until` 與 sha256 前 16 碼、已審核與未審核的列數、已確認無法對應的公告、初審無法對應（待確認）的公告）、`dumpling:advisory-note`（可多筆）。
`fw-inventory.md` 的「公告比對」一節有「NVIDIA vBIOS」段落（表格加每個 vBIOS 的 basis）；沒有 BIOS 也沒有 vBIOS 時寫「沒有找到 NVIDIA vBIOS，沒有可比對的項目」。

### 樣本結果（2026-11-14）

- **公開樣本 `vbios/nvidia-displayport-fw-updater-1.1`**（`NVIDIA_DisplayPort_Firmware_Updater_1.1-x64.exe`，sha256 `c96c319b…26a5161`）：`firmware-bios.sh` 的狀態是 GAP「沒有找到 NVIDIA vBIOS 或 BIOS 結構」，`vbios` 是 0 個。
  原因同 `c2-vbios.md` 的判定乙：內嵌的三個 EFI 影像 PCIR vendor／device 都是 0，版本是 `xx.xx.xx.xx.xx` 佔位字串，不是 vBIOS 元件，所以**沒有元件可以掛 `advisory-match`**。
  報告（`fw-inventory.md` 的「公告比對」）寫「沒有找到 NVIDIA vBIOS，沒有可比對的項目（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）」，CI 欄寫「沒有 BIOS 映像（NOT_ASSESSED：…）」。沒有任何文字表示沒有漏洞。
- **合成 option ROM**（`tools/cra/tests/synthetic_vbios.py`，預設版本 `00.00.00.00.01`、裝置 `fffe`）：`dumpling:advisory-match` ＝ NOT_ASSESSED（`table-not-reviewed`：表尚未經負責人確認），basis 與 source 如上，SBOM 通過 CycloneDX 1.6 schema，`vuln-assessment` ＝ NOT_ASSESSED。
  版本是佔位字串（`XX.XX.XX.XX.XX`，讀不到十六進位版本）的 ROM 用測試自己組的假 ROM 驗證：`version-unreadable`。
- **BIOS 公開樣本（對 main dde7467 與這個分支各跑一次 `firmware-bios.sh`）**：狀態行與 `fw.cdx.json`（排除 serialNumber 與 timestamp）全部相同；`fw-inventory.json` 只多一個頂層鍵 `vbios_advisory`（沒有 vBIOS 時 `vbios` ＝ 0、`counts` ＝ {}）。`fw-inventory.md` 在找到 BIOS 映像的樣本相同；沒有 BIOS 映像也沒有 vBIOS 的樣本（OVMF 的 deb、DisplayPort 更新工具）多出「沒有找到 NVIDIA vBIOS，沒有可比對的項目（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）」一行。

### 與 C1 的表格式與工具的介面

C2 沒有改 C1 的程式；下面是現行規則與格式上的需求：
- C1 的 `validate_table` 不認得 vBIOS 的裝置範圍與十六進位版本：版本欄位只收點分十進位（`vkey`），沒有 PCI vendor／device 欄位。這張表用額外欄位（上表）表達，`tools/cra/nvidia_vbios_advisory.py` 在 `validate_table` 之後自己驗已審核的列。C1 的 `match` 只讀 jetson 群組的表，不讀這張。
  若 `validate_table` 要原生檢查這些欄位，需要接收 `pci_vendor`、`pci_devices`、`vbios_*`，以及可替換的版本比較函式。
- `reviewed_until` 是審核者看過的最新公告日期（`candidates` 把日期比它晚的公告列為待審）；鏡像的時間點記在頂層 `mirror`（commit、commit_date、fetched_utc），`candidates` 目前不讀它。
  `mirror` 整個沒寫或是 null、過期、在未來：這張表的比對把 fixed 降成 NOT_ASSESSED（`table-stale`），affected 與其他結果照舊但加註；`mirror` 有寫但缺 `commit`、`commit_date`、`fetched_utc` 任一個，或格式不對（含沒有時區）是 `table-invalid`。
- 沒有 `fixed_in` 以外範圍欄位的列（只有 `vbios_fixed_in`）表示「低於這個版本都受影響」，不分版本線：審核時列的範圍要涵蓋到版本線，只適用某一條版本線的公告要寫成有 `vbios_affected_below`／`vbios_affected_max`（加 `pci_devices`）的列。

### 更新表（人工步驟）

1. 更新主機（需連網）：`tools/mirror/nvidia-bulletins.sh <新資料夾> <manifest>`，再 `tools/mirror/nvidia-bulletins.sh --check <新資料夾>`。記下 `SOURCE` 的 commit、commit_date、fetched_utc。下載的檔案只當資料讀，不執行（Python 用 `-I`）。
2. `python3 -I tools/pilot/lib/nvidia_bulletins.py candidates --mirror <新資料夾> --table tools/pilot/lib/nvidia-bulletins-gpu-firmware.json --group gpu-firmware --draft <草稿.json>`：列出待審公告與草稿列（`reviewed=false`，版本與元件是程式推測的）。
3. 逐則讀 `<年>/<編號>/<編號>.md` 與 `<編號>.json`（CSAF 的 `product_tree`、`vulnerabilities[].product_status`、`remediations`）：
   - 涉及顯卡 option ROM 的 vBIOS、而且公告有可機器判斷的版本線與裝置範圍 → 填 `bulletins`（編號、CVE 的嚴重度等，來自 CSAF）與 `rows`（`line: vbios`、`pci_vendor`、`pci_devices`、`vbios_*`、`source`、`reviewed: true`、`reviewed_by` 只寫角色、`reviewed_at`）。
   - 只涉及 HGX／DGX 等伺服器韌體、或範圍看不懂 → `not_applicable`（`current_release_date`、`reason` 寫技術理由、`csaf_fields`）；初審意見用 `reviewed=false`，由負責人確認後才改 `reviewed=true`。**看不懂、範圍不明的不要猜**，寫成「無法對應」並註明原因，不要寫成「不影響」，或留在待審。
4. 更新 `mirror`（鏡像的 commit、commit_date、fetched_utc）；`reviewed_until` 填看過的最新公告日期，只有負責人確認後才填，沒確認前維持 null。
5. `python3 -I tools/pilot/lib/nvidia_bulletins.py candidates …`（同第 2 步，不加 `--draft`）應該是 OK；再跑 `tests/run.d/c2-x86-firmware.sh`。有新的 `rows` 時在 `test_nvidia_vbios_advisory.py` 加對應的測試。
   負責人確認表（5674 改 `reviewed=true`、`reviewed_until` 有值）之後，下列測試描述的是「尚未確認」的狀態，必須一起改成確認後的預期（`table-not-reviewed` 變成 `no-row`、`candidates` 變成 OK、報告寫「已確認無法對應」）：
   `test_committed_table_passes_c1_validation_and_is_not_yet_confirmed`、`test_committed_table_stays_pending_for_c1_candidates`、`test_committed_table_gives_not_assessed_not_reviewed_for_every_vbios`、`test_default_table_is_the_committed_one`、`test_unconfirmed_table_report_says_preliminary`、`test_synthetic_rom_end_to_end`（都在 `test_nvidia_vbios_advisory.py`）。
   其他測試用固定時間（`tools/cra/tests/conftest.py` 的 `_fixed_vbios_clock`）與合成表，不隨表的內容或牆上時鐘改變。
6. 超過 90 天沒有重新審核，`fixed` 會降成 NOT_ASSESSED（`table-stale`）：定期重跑第 1～5 步。

### 限制與刻意保守的地方

- 目前表沒有任何可比對的列，而且尚未經負責人確認，所以每個 vBIOS 都是 NOT_ASSESSED。沒有 affected 或 fixed 的真實案例；規則靠合成表測試。
- 公告只涵蓋 NVIDIA 公開的；消費型顯卡的 vBIOS 修補由 NVIDIA 通知合作夥伴（板卡廠），不在這張表。
- vBIOS 版本是 ROM 裡第一個 `XX.XX.XX.XX.XX` 字串；NVIDIA 的版本最後一段是各板卡廠自己的修訂，公告若只寫前幾段，表裡的版本也只寫前幾段。PCI device ID 取自 PCIR 標頭，板子的實際 ID 可能不同（沒有檢查）。
- 不跟隨公告以外的資料（NVD、廠商網站）；不判斷「已修補」以外的狀態；沒有「不受影響」這個結果。
- HGX／DGX 的 vBIOS 版本（`1.7.1` 這種）與 option ROM 版本的對應不明：如果之後 SBOM 出現那類韌體，要由負責單位提供對應再補列。
