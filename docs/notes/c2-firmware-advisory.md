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
| `tools/cra/fw_advisory_rules.py`、`tools/cra/data/fw-advisory-rules.json`、`tools/cra/tests/test_fw_advisory_rules.py` | 廠商公告規則表（AMD-SB、INTEL-SA、AMI-SA）的比對、規則與測試；見最後的「規則表」一節 |
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
B550M（AMD）沒有 Intel 微碼與 ME；AMD 微碼 19 份、PSP 韌體 78 項、AGESA 1 個都已解析，每個元件有 `dumpling:advisory-match=NOT_ASSESSED`（沒有機器可讀的 AMD 公告資料表，以 AMD 公告為準；規則表的建議見最後的「規則表」一節）。

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
- 微碼只比 Intel。AMD 的微碼、PSP 韌體、AGESA 已由 `amd_psp.py` 解析，每個元件有 `advisory-match=NOT_ASSESSED`（資料庫沒有資料，以 AMD 公告為準；規則表的建議見「規則表」一節）。ME／TXE／SPS 的公告沒有機器可讀資料。NVIDIA vBIOS 的比對見最後一節。
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

## 規則表（決定 D-043 (2)）

廠商公告（INTEL-SA、AMD-SB、AMI-SA）沒有機器可讀的資料庫可以比對，所以用**半自動的規則表**：人從廠商官方公告頁讀出「哪個元件、哪個版本以前受影響、修正版本是什麼」，
整理成一個公告一筆規則；程式依元件版本比對，**結果只是建議**，由負責單位確認。格式比照 D-039 的規則庫（`tools/cra/vex-rules.example.json`：`schema`、`rules[]`、`id`、`match`、日期、`reason`）。
`dumpling:vuln-assessment` 維持 `NOT_ASSESSED`，沒有任何狀態或文字表示「沒有漏洞」。

### 檔案

| 檔案 | 內容 |
|---|---|
| `tools/cra/data/fw-advisory-rules.json` | 規則表（schema `dumpling-fw-advisory-rules/1`）。只放事實性欄位，不抄公告原文 |
| `tools/cra/fw_advisory_rules.py` | 載入、schema 驗證、版本比較、建議的合併規則（離線，CI 不連網）。`python3 tools/cra/fw_advisory_rules.py sha256｜verify [檔]` 給維護用 |
| `tools/cra/x86_firmware.py` | `rules_section`（每個元件比對一次，結果記在 inventory 各元件的 `rule_advisory`）、`rule_props`（SBOM property）、`rules_markdown`（fw-inventory.md 的「規則表比對」一節）、`status_of`（affected → ATTENTION） |
| `pipeline/lib/firmware_advisory_cell.py`、`pipeline/lib/firmware_dt.py` | CI 摘要欄與 DT 報告的「怎麼讀」反映規則表建議 |
| `pipeline/firmware-expect.py` | `expected.advisory_rule`：真樣本的建議（元件名稱、版本、建議、規則編號）逐項比對 |
| `tools/cra/tests/test_fw_advisory_rules.py` | 測試（合成資料，不連網） |

### 規則的欄位

```
{"schema": "dumpling-fw-advisory-rules/1", "table_updated": "2026-11-14", "orderings": [...], "rules": [ <規則>… ]}
規則：{"id", "vendor", "title", "published", ["revised"], "cves": [...], "sources": [{"url", "read_at"}], "match": [<條件>…],
       "review": {"state", "preliminary_by", "preliminary_at", ["confirmed_by", "confirmed_at"]}, ["note"]}
```

- `id`：用 `fullmatch` 驗證。`AMD-SB-[0-9]{4,5}`、`INTEL-SA-[0-9]{5}`、`AMI-SA-[0-9]{7}`。依據：AMD 的公告頁網址是 `…/product-security/bulletin/amd-sb-7014.html`（2026-11-14 讀到的編號都是 4 位數，位數沒有公開規定，所以允許 4～5 位）；
  Intel 的是 `…/security-center/advisory/intel-sa-01372.html`（`INTEL-SA-` 加 5 位數，例如 00391、01372）；AMI 的 `https://www.ami.com/security-advisories/` 列 `AMI-SA-2026003`（4 位西元年加 3 位流水號，共 7 位數），每一則連到一份 PDF。
  `vendor` 要與 `id` 的前綴一致（`AMD`、`Intel`、`AMI`）。
- `sources[]`：`{url, read_at, verification}`，網址只收廠商官方公告頁（AMD 與 Intel 的網址必須是 `id` 對應的那一頁；AMI 是 PDF，或公告列表頁）；`read_at` 是人讀那一頁的日期，不能晚於 `table_updated`。
  `verification`（必填）是**版本值怎麼讀到的**：`direct`＝直接下載官方頁面或 PDF 的原文解析；`summary-tool`＝只經網頁摘要工具讀到、沒有第二個獨立來源（版本值**未獨立核對**）；
  `independent:nvd`＝除了讀官方頁面，版本門檻另經 NVD 的 CPE 版本範圍核對相符。一條規則有幾個出處時取最弱的。報告的「規則表內容」表有一欄「版本值核對」，`summary-tool` 的規則用到建議時（affected、not-affected 的說明）寫「版本值未獨立核對，請負責單位對照原頁面」，SBOM 元件加 `dumpling:advisory-rule-verification`。
- `match[]`：條件，每個有 `component`，必須在固定清單內（`amd_agesa`、`amd_psp`、`amd_microcode`、`intel_csme`、`intel_fsp`、`ami_core`、`bios_image`），`amd_*` 只能在 AMD 公告、`intel_*` 只能在 Intel 公告、`ami_core` 只能在 AMI 公告。
  版本條件依元件分開（見下）。同一條規則的幾個條件是「或」：不同產品線各列一條。
- `review`：`state` 是 `preliminary`（初審）或 `confirmed`（已確認）；`preliminary_by`／`confirmed_by` 只寫**角色**（驗證會拒收 `@`、連結、Markdown 符號）；`confirmed` 必須有 `confirmed_by`、`confirmed_at`（不早於 `preliminary_at`），`preliminary` 不能有。
- `orderings[]`：AGESA 的版本順序（見下）。
- 每一層都**只收列出的欄位**，不認得的欄位（含打錯字）整張表拒收；JSON 重複的鍵、`NaN`、超過 1 MiB、符號連結都拒收；自由文字欄位（標題、備註、角色）不能有控制字元、雙向覆寫與零寬字元。

### 版本比較（每一種格式一個函式）

| 元件 | 條件欄位 | 比較 |
|---|---|---|
| `amd_agesa` | `family`（映像 AGESA 字串的名稱，例如 `ComboAM4v2PI`）、`fixed_in`、可選 `affected_from` | **依規則表的順序序列**（下一節）；family 不同 → 這條規則不適用；版本不在序列 → NOT_ASSESSED（`agesa-order-unknown`）；字串不是 `<名稱> <a.b.c.d>`（例如少一個點的 `1.2.0Cb`）→ `version-unreadable` |
| `intel_csme` | `line`（`major.minor`，例如 `18.1`）、`fixed_in`（三或四段，開頭必須是 `line`）、可選 `affected_from` | 數字逐段比（不是字串比）；`fixed_in` 三段就只比前三段（build 號不比），四段就比四段，映像版本段數不夠 → `version-too-short`；`major.minor` 不是 `line` → 這條規則不適用（版本線是整段比，`14.1` 不會比到 `14.10`）。family 是 CSME（版本清單寫明）或由版本推定（major 11～30，結果加註）才比；TXE／SPS／ME、family 矛盾、讀不出來 → NOT_ASSESSED |
| `intel_fsp` | `line`（前兩段）、`fixed_in`（四段）、可選 `affected_from` | 同 CSME，四段；ExtendedImageRevision 不是 0 時（版本可能偏低）不比 |
| `amd_psp` | `psp_type`（0–255）、`fixed_in`（四個小寫十六進位 byte，與 SBOM 同格式） | 逐 byte 比；type 不同 → 不適用 |
| `amd_microcode` | `equiv_id`（`0x` ＋ 4 位）或 `cpuid`（8 位大寫十六進位）二選一、`fixed_in`（patch level，`0x` ＋ 8 位） | 無號整數；用 `cpuid` 但映像沒有等價表（CPUID 未知）→ `cpuid-unknown`，不猜 |
| `bios_image` | `name_prefix`（映像檔名開頭）、`fixed_in`（數字或點分數字） | 用版本清單宣告的 BIOS 版本，數字逐段比；沒宣告 → `no-declared-version`，格式怪異 → `version-unreadable` |
| `ami_core` | `product`、可選 `fixed_in`（只記錄） | **不比較**：SBOM 沒有 AMI 核心版本，一律 NOT_ASSESSED（`no-ami-core-version`） |

`affected_from`（可選）：映像版本低於它 → NOT_ASSESSED（`below-affected-from`），因為公告沒有說比起點更舊的版本怎麼樣。

### AGESA 的版本順序與依據

AGESA 的版本不能用數字或字串順序比：AMD 公告裡 `ComboAM4v2PI` 的順序是 `1.2.0.8`、`1.2.0.9`、`1.2.0.B`、`1.2.0.C`、`1.2.0.Ca`、`1.2.0.Cb`、`1.2.0.Cc`、`1.2.0.D`、`1.2.0.F`，**之後才是 `1.2.0.10`**（字母是十六進位的 A～F，10 在 F 之後）；
`ComboAM5PI` 的 `1.0.0.7a` 比 `1.0.7.0` 晚發佈（2023-05-05 對 2023-04-18）。所以順序**只用 AMD 公告頁列出的發佈日期**證明：規則表的 `orderings[]` 每個 family 一份版本序列，每個版本附 AMD 公告列的日期與出處網址，
驗證要求日期**嚴格遞增**（同一天不能證明先後）。`fixed_in`、`affected_from` 必須在序列裡（否則整張表拒收）；映像的版本不在序列裡（例如規則表沒有 `1.2.0.A`、`1.2.0.E`）→ NOT_ASSESSED，不從字母或數字推測。
比較不分大小寫（AMD 的頁面同一版本有 `1.2.0.Ca` 與 `1.2.0.CA` 兩種寫法，日期相同；7014 把 Cc 寫成沒有點的 `1.2.0Cc`，規則表寫成 `1.2.0.Cc`）。
新增序列時：版本與日期一定要來自 AMD 公告頁的同一個表格列，出處網址記在該筆；兩個頁面對同一版本寫了不同日期（不同 CPU 的列）時取較早的，並且只收日期能嚴格排序的。

### 建議的合併規則

一個元件對所有規則逐一比對（`out-of-scope` 的不算），然後：

1. 規則表不能用（讀不到、sha256 不符、schema 驗證失敗）→ **所有元件 NOT_ASSESSED**（`table-unreadable`／`table-sha-mismatch`／`table-invalid`），報告與狀態都標 GAP／ATTENTION；不會悄悄少算幾筆。
2. 任何一條規則是 `affected` → `affected`（`rule_ids` 是判 affected 的規則；同時判 `not-affected` 的規則只寫在依據裡）。
3. 否則有 NOT_ASSESSED（版本讀不懂、順序不確定、段數不夠、family 不確定…）→ NOT_ASSESSED：有一條讀不懂就不能說 `not-affected`。
4. 否則有 `not-affected`（版本不低於 `fixed_in`）→ `not-affected`，同時記 `dumpling:evidence=vendor-statement` 與 `dumpling:evidence-location`（公告網址；D-035）。
5. 否則沒有任何規則適用 → NOT_ASSESSED（`no-rule`；同元件種類的規則都是別的 family／版本線時 `no-rule-for-line`）：資料庫沒有資料，以廠商公告為準。

SBOM 元件的 property：`dumpling:advisory-rule-suggestion`、`dumpling:advisory-rule-ids`、`dumpling:advisory-rule-state`（`preliminary`、`confirmed`，兩種都有時 `preliminary+confirmed`）、`dumpling:advisory-rule-basis`（每條規則的結果與原因）、
`dumpling:advisory-rule-reason`（NOT_ASSESSED 的原因代碼）、`dumpling:advisory-rule-source`（規則表、最後整理日期、sha256 前綴）、`dumpling:advisory-rule-related`（BIOS 映像：可能相關的 AMI 公告）。
**沒有規則元件種類的元件**（Intel 微碼、coreboot、edk2、GOP／VBT、NVIDIA vBIOS）不帶這些 property（Intel 微碼與 NVIDIA 有自己的比對）。

### 報告與狀態

- fw-inventory.md 的「規則表比對」一節：規則表的最後整理日期與「之後的新公告沒有收錄，以廠商公告為準」、規則清單（含審核狀態）、建議計數、**建議 affected（待人審）**、**建議 not-affected（單獨列出，依據類型 vendor-statement 與公告網址）**、可能相關的 AMI 公告、各元件的建議與依據。
  文字：規則還是初審時寫「依初審規則的建議（待負責單位確認）」，確認後寫「依已確認規則的建議」；兩種都寫「是否受影響以廠商公告為準」。不出現「不受影響」、「安全」、「不適用」。
  對不到任何規則的元件維持「資料庫沒有資料，以廠商公告為準」。
- **狀態**：任何元件的建議是 `affected`，即使規則還是初審，`FW-INVENTORY` 狀態就是 ATTENTION，說明裡列規則編號與「待人審」；`not-affected` 不會讓狀態變好或變差；NOT_ASSESSED 照舊；規則表不能用 → ATTENTION。
- CI 摘要欄（`firmware_advisory_cell.py`）多一段「規則表建議（整理日期）affected N、not-affected N、NOT_ASSESSED N：affected N 個待人審（規則；依初審規則的建議，待負責單位確認）」；DT 報告的「怎麼讀」與每個樣本的計數行也一樣。
- **AMI-SA**：SBOM 目前沒有 AMI 核心版本，`ami_core` 的條件一律 NOT_ASSESSED（原因寫「SBOM 沒有 AMI 核心版本」，代碼 `no-ami-core-version`）。映像有 AMI 的線索（`ibv_hint` 有 AMI，或是 AMI PFAT 封裝）時，報告列出「可能相關的 AMI 公告」請負責單位對照，**不給建議**。
  公告列的 `Fix Version`（例如 `AptioV_5.044`）只記在規則裡；等 SBOM 讀得到 AMI 核心版本（`AptioV_5.0xx` 形式）再加比較函式。

### 完整性：為什麼固定 sha256

規則表的檔案 sha256 固定在 `fw_advisory_rules.py` 的 `TABLE_SHA256`（做法與 `fw_advisory.TABLE_SHA256` 相同；`.gitattributes` 讓 `tools/cra/data/*.json` 不做換行轉換）。理由：
(1) 這張表只有人會改，改動要同時改資料與程式裡的常數，審查的人在同一個 diff 看得到「哪些規則變了、是不是故意的」；
(2) 檔案被截斷、少一筆規則、換行被轉換或換成別的內容時，比對一律 NOT_ASSESSED（`table-sha-mismatch`）加 ATTENTION，不會悄悄少算；
(3) 驗證（schema）擋的是格式，sha256 擋的是「格式合法但內容被改」。限制：它擋不住「資料與常數一起被改」的 PR，那只能靠審查；而且確認規則時（`review.state` 改成 `confirmed`）也要重新計算。

### 人工新增規則的步驟

1. 讀廠商官方公告頁（AMD：`https://www.amd.com/en/resources/product-security/bulletin/amd-sb-NNNN.html`；Intel：`https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-NNNNN.html`；AMI：`https://www.ami.com/security-advisories/` 與該則 PDF）。**表格看不懂、版本欄的意思不確定（是「受影響」、「修正」還是「建議更新」）、儲存格對不起來的，不收**。
2. 在 `rules` 加一筆：`id`、`vendor`、`title`、`published`（公告頁的原始發佈日）、`revised`（最後修訂日）、`cves`、`sources`（網址與你讀的日期 `read_at`）、`match`（一個產品線一個條件；`fixed_in` 抄公告列的修正版本；映像字串與公告的寫法不同時，把差異寫在條件的 `note`）、
   `review`：`state: "preliminary"`、`preliminary_by`（角色，例如「韌體分析（C2 角色）初審」）、`preliminary_at`。AGESA 的版本若不在 `orderings[]`，先依上一節補序列（版本、AMD 公告列的日期、出處網址）。
3. 更新 `table_updated`（今天的日期）。
4. `python3 tools/cra/fw_advisory_rules.py verify tools/cra/data/fw-advisory-rules.json` 驗 schema；通過後 `python3 tools/cra/fw_advisory_rules.py sha256` 取得雜湊，寫進 `TABLE_SHA256`。
5. 對公開樣本跑 `pipeline/firmware-bios.sh` 看結果；要鎖住的結果寫進樣本 `firmware.yml` 的 `expected.advisory_rule`；跑 `tests/run.d/c2-x86-firmware.sh`。

### 確認規則的步驟（負責單位）

1. 對照公告頁逐條核對 `match`（`fixed_in`、`line`／`family`、`note`）與 `cves`、`sources`；有疑問的條件改成 NOT_ASSESSED 的寫法（刪掉那個條件）或整筆刪掉。
   **`verification` 是 `summary-tool` 的規則（目前是 INTEL-SA-01280、INTEL-SA-01372）：確認時必須直接開 Intel 的頁面對照每一個版本值**（Intel 對一般下載回 403，要用瀏覽器開），對照完把該出處改成 `direct`（或另有獨立來源時 `independent:nvd`）；沒有直接對照過就不能改成 `confirmed`（schema 也擋：`confirmed` 的規則有 `summary-tool` 出處時整張表拒收）。
2. 把該筆的 `review` 改成 `state: "confirmed"`，加 `confirmed_by`（**角色**，不寫姓名或信箱）與 `confirmed_at`；`preliminary_by`、`preliminary_at` 保留。
3. 更新 `table_updated`，重算 `TABLE_SHA256`，跑測試。確認之前的建議都標「依初審規則的建議（待負責單位確認）」，確認之後才標「依已確認規則的建議」；一個元件同時有兩種規則時寫 `preliminary+confirmed`。
4. 規則表不會自己更新：`table_updated` 之後的新公告沒有收錄，報告每次都寫明這一點。

### 第一批規則（2026-11-14 讀官方頁面查證）

只收「頁面上看得懂、版本欄意思確定」的條件；每一筆都是 `preliminary`，`preliminary_by` 是「韌體分析（C2 角色）初審」。

| 規則 | 網址（`read_at` 2026-11-14） | 收錄的條件 | 為什麼這樣解讀 |
|---|---|---|---|
| AMD-SB-7005 Return Address Security Bulletin（CVE-2023-20569；發佈 2023-08-08，最後修訂 2024-12-05） | https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7005.html | AGESA：`ComboAM4v2PI` `fixed_in` 1.2.0.B（Ryzen 5000 桌上型）；`ComboAM5PI` `fixed_in` 1.0.8.0（Ryzen 7000 桌上型） | 頁面桌上型表格的標題是「Update to listed versions or higher」，欄位寫 `ComboAM4v2PI 1.2.0.B (2023-08-25)`、`ComboAM5 1.0.8.0 (2023-08-25)`；Ryzen 3000 的格子是 Not applicable。頁面寫 `ComboAM5`，映像字串是 `ComboAM5PI`，規則用映像的寫法（見規則的 `note`）。頁面另說可以用獨立微碼代替 AGESA 更新，規則不評估這一條 |
| AMD-SB-7014 SMM Lock Bypass（CVE-2023-31315；發佈 2024-08-09，最後修訂 2024-11-07） | https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7014.html | AGESA：`ComboAM4v2PI` `fixed_in` 1.2.0.Cc；`ComboAM5PI` `fixed_in` 1.2.0.1（客戶端桌上型表） | 頁面桌上型表：Matisse 的 `ComboAM4v2PI` 是 `1.2.0Cc (2024-08-16)`、Vermeer／Cezanne／Renoir 是 `1.2.0.cb (2024-07-30)`、Raphael 的 `ComboAM5PI` 是 `1.2.0.1 (2024-08-07)`；映像不知道是給哪顆 CPU，取同表最高的 Cc（所以停在 Cb 的映像也建議 affected，偏保守）。伺服器與嵌入式的表沒收 |
| INTEL-SA-00391 2020.2 IPU（發佈 2020-11-10，修訂 2022-05-12） | https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00391.html | CSME：版本線 `14.0` `fixed_in` 14.0.45、版本線 `14.5` `fixed_in` 14.5.25（`verification: independent:nvd`） | 受影響產品只有一句話：「Intel CSME and Intel AMT versions before 11.8.82, 11.12.82, 11.22.82, 12.0.70, 13.0.40, 13.30.10, 14.0.45 and 14.5.25」。只收 14.x 兩條。NVD 的 CPE 版本範圍（有 Intel CPE 的 CVE）的 14.x 上界是 14.0.45 與 14.5.25，相符；**11.x 的門檻兩邊不同**：Intel 頁面這句寫 11.8.82（同頁的某些 CVE 描述寫 11.8.80），NVD 寫 11.8.80，兩邊都記在這裡，規則不用 11.x。25 個 CVE 裡 CVE-2020-27336、-27337、-27338 在 NVD 沒有 Intel 的 CPE 設定也沒有連到這則公告，這三個沒有獨立核對 |
| INTEL-SA-01280 2025.3 IPU（2025-08-12） | https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01280.html | CSME：`14.1`→14.1.77、`14.5`→14.5.57、`18.1`→18.1.18（`verification: summary-tool`） | 表格欄位標題 `Versions Before`（CVE-2025-20037、-20067、-22392）；只收 14.x、18.x 的列。**版本值只經網頁摘要工具讀到，NVD 對這些 CVE 沒有 CPE 版本範圍，無法獨立核對** |
| INTEL-SA-01372（2026-08-11，修訂 2026-09-09；CVE-2026-6726） | https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01372.html | CSME：`14.1`→14.1.80、`14.5`→14.5.62、`18.1`→18.1.21 | 同上，`Versions Before`；只收 14.x、18.x 的列（`verification: summary-tool`，同樣無法獨立核對）。Intel 的表依產品列，規則只看版本線，**沒有核對平台是不是那一列的產品**（寫在規則的 `note`） |
| AMI-SA-2026001（2026-09-08；CVE-2026-33197）、AMI-SA-2026002（2026-10-13；CVE-2025-58771／-58772／-58773／-58774、CVE-2026-0893）；兩份的標題都是 PDF 的「Security Audit Reported Vulnerabilities」，產品（Aptio V）寫在 `note` 與條件的 `product` | 該則 PDF（`go.ami.com/hubfs/Security%20Advisories/2026/AMI-SA-2026001.pdf`、`…002.pdf`）與 https://www.ami.com/security-advisories/ | `ami_core`：Aptio V，`Fix Version` 欄 `AptioV_5.044`（2026002 同一份文件裡另有 `AptioV_5.043`，取最高） | 文件寫「If the fix version includes "Aptio," … AptioV, was affected」，沒有受影響版本範圍，只有修正版本；SBOM 沒有 AMI 核心版本，所以只列「可能相關」，不比較 |

AGESA 的 `orderings[]` 的日期出處（AMD-SB-4002、4012、4018、7005、7008、7009、7014 的表格列，2026-11-14 讀）：`ComboAM4v2PI`：1.2.0.8（2022-07-29）、1.2.0.9（2023-01-24）、1.2.0.B（2023-08-25）、1.2.0.C（2024-02-07）、1.2.0.Ca（2024-03-14）、1.2.0.Cb（2024-07-30）、
1.2.0.Cc（2024-08-16）、1.2.0.D（2024-11-07）、1.2.0.F（2025-04-30）、1.2.0.10（2025-10-31）；`ComboAM5PI`（Raphael 的列）：1.0.0.7a（2023-05-05）、1.0.8.0（2023-08-25）、1.1.0.2（2024-01-09）、1.2.0.0（2024-06-13）、1.2.0.1（2024-08-07）、1.2.0.2a（2024-10-05）。

**查證過但沒收的公告**：

| 公告 | 原因 |
|---|---|
| INTEL-SA-00473（14.0.48） | 頁面的 `Version` 欄是「建議更新到」的版本，頁面沒有「受影響範圍」的敘述，所以不能判受影響；不收 |
| INTEL-SA-01209（Core Ultra `18.0.10`） | 取得的頁面文字把表格壓成一行一格，Core Ultra 與 `18.0.10` 的配對只靠相鄰，頁面沒有確認；表格看不清楚，不收（NovaCustom 的 18.0.10.2285 因此沒有適用的規則） |
| INTEL-SA-00241（14.0.10）、00295（14.0.33）、00307（14.0.11） | 只在搜尋結果的摘錄看到版本，沒有讀過頁面；14.0 版本線的閾值都低於 14.0.47，不影響這批樣本；不收 |
| AMD-SB-4002、4007、4008、4012、4013、4018、7008、7009 | 讀過，只用來證明 AGESA 的版本順序與發佈日期；每份是多個 CVE、逐 CPU 的表，沒有逐 CVE 整理成規則（範圍），不是查不到 |
| AMI-SA-2024001…2025009、2026003 | 讀過 PDF（Aptio V 的 `Fix Version` 都是 `AptioV_5.0xx`），這批只收 1～2 則（2026001、2026002） |

**資料取得的限制**：AMD 與 AMI 的頁面直接下載後解析（`verification: direct`）。Intel 的官方頁面對一般的下載（curl）回 403，只能透過網頁擷取工具（它會先做摘要）讀頁面文字，不是逐字的原始 HTML。INTEL-SA-00391 的 14.0.45、14.5.25 另用 NVD 的 CPE 版本範圍核對相符（`independent:nvd`，涵蓋 NVD 有 Intel CPE 的 22 個 CVE）；**INTEL-SA-01280、INTEL-SA-01372 的版本值沒有獨立來源**（NVD 對這些 CVE 沒有 CPE 版本範圍），標 `summary-tool`，報告與 SBOM 都會標示，負責單位確認時必須直接對照 Intel 的頁面。
負責單位確認規則時請直接對照 Intel 的頁面。

### 公開樣本的結果（規則表 2026-11-14、7 筆）

| 樣本 | 元件 | 建議 | 規則 |
|---|---|---|---|
| ASUS PRIME B550M-A 3404、ASRock B550 PG4 3.40 | AGESA `ComboAM4v2PI 1.2.0.B` | affected | AMD-SB-7014（AMD-SB-7005 的 1.2.0.B 不低於，記在依據） |
| ASUS PRIME B650M-A 1807 | AGESA `ComboAM5PI 1.0.8.0` | affected | AMD-SB-7014（AMD-SB-7005 的 1.0.8.0 不低於） |
| Protectli VP46xx（Dasharo v1.2.0） | ME 14.0.47.1558 | **not-affected**（依據 vendor-statement：INTEL-SA-00391 的 14.0.45） | INTEL-SA-00391；FSP 9.x 沒有規則 |
| NovaCustom NUC box ARL v0.9.2 | ME 18.1.18.2724 | affected | INTEL-SA-01372（INTEL-SA-01280 的 18.1.18 不低於，記在依據） |
| NovaCustom V540TU MTL v1.0.1 | ME 18.0.10.2285 | NOT_ASSESSED（`no-rule-for-line`：規則只有 14.x、18.1 版本線） | — |
| Intel NUC11 PATGL357.0059 | BIOS 映像 | NOT_ASSESSED（`no-ami-core-version`；列出可能相關的 AMI-SA-2026001、2026002） | — |

AMI 的線索（`ibv_hint` 有 AMI）也出現在 ASUS B550M、ASRock B550、ASUS B650M 的映像：這三個的 BIOS 映像元件同樣是 NOT_ASSESSED（`no-ami-core-version`），報告同樣列出可能相關的 AMI-SA-2026001、2026002，不給建議（上表只在 NUC11 列出是因為其他列在講別的元件）。

每個樣本的狀態一直是 ATTENTION（既有原因：沒有版本清單、解析缺口等）；有 affected 建議的樣本多一句「規則表建議 affected：… 待人審」。`expected.advisory_rule` 鎖住 B550M、Protectli、NovaCustom ARL 三個樣本。

### 限制與沒做的事

- 規則表只有 7 筆，**不是完整的公告資料庫**；沒有規則的元件、版本線、family 一律 NOT_ASSESSED（`no-rule`、`no-rule-for-line`）。
- AGESA 取同表最高的修正版本、CSME 只看版本線、不知道映像是給哪顆 CPU 或哪個產品，所以 `affected` 偏保守；`not-affected` 只是「版本不低於公告列的修正版本」。
- AMI 核心版本讀不到（沒有 AMI 的版本字串解析器），`ami_core` 只列相關公告；之後讀得到了再加比較函式與規則。
- 沒有規則的元件種類：Intel 微碼（另有發佈資料表的比對）、coreboot、edk2、GOP／VBT、NVIDIA vBIOS。
- 規則表不隨 CI 更新；Intel 頁面的內容要人工對照。
