# C2：AMD 平台的 PSP／BIOS 目錄、微碼與 AGESA（分支 wp3/amd-psp）

擴充 `x86_firmware.py` 對 AMD 平台 BIOS 映像的解析範圍：解析 Embedded Firmware Structure（EFS）→ PSP／BIOS 目錄 → 條目，讀 AMD 微碼與 AGESA 版本字串。**不是漏洞比對**：所有新元件仍是
`dumpling:vuln-assessment=NOT_ASSESSED`（note：AMD 安全公告無法機器比對，需公告對照）。

## 檔案

| 檔案 | 內容 |
|---|---|
| `tools/cra/amd_psp.py` | 解析本體（只依賴標準函式庫與 C1 的 `uefi_image.py`）；`analyze(data, budget, soft)` 永遠回傳 dict，不丟例外 |
| `tools/cra/x86_firmware.py` | 最小接線：`bios_image()` 在辨識出 AMD 平台時呼叫 `amd_psp.analyze`，結果放 `bios[].amd`；`amd_components()` 產 SBOM 元件；`status_of()`、`markdown()` 各一小段；`ASSESS_NOTES["amd"]` |
| `tools/cra/tests/test_amd_psp.py` | 映像全部當場合成（D-028）；包含不丟例外、壓縮與 size 0、競爭的讀法（採用／不採用／歧義）、AGESA 邊界與涵蓋、EFS 位置表、位元位置等針對變異測試補的案例 |
| `firmware/bios/asus-prime-b550m-a-3404/firmware.yml` | 公開樣本與 expected（見下） |
| `pipeline/firmware-expect.py` | 新鍵 `amd_agesa`、`amd_microcode`（說明見 `firmware/README.md`） |

## 解析流程

1. **EFS**：位置表照 coreboot `amdfwread.c` 依 ROM 大小分的三張（視窗 ≤ 4 MiB、≤ 8 MiB、其餘），每個 16 MiB 視窗各查一次簽章 `0x55AA55AA`。更新包有標頭（例如 4 KiB）而讓 EFS 不在固定位置時，
   掃全檔的簽章候選（上限 `MAX_SIG_HITS`），位移是 4 KiB 的整數倍、不超過 `MAX_SHIFT`，而且指標之一真的指到目錄 cookie 才採用。
2. **目錄**：EFS 的 `psp_directory`（+0x10）、`new_psp_directory`（+0x14）、`psp_bak_directory`（+0x2C）、`bios0`–`bios3` 指標；cookie `$PSP`、`$PL2`、`$BHD`、`$BL2`、combo `2PSP`／`2BHD`。
   標頭 checksum 是 coreboot `amdfwtool.c` 的 `fletcher32`（初值 0xFFFF、16 位元小端字、每 359 個字與最後各折疊一次），涵蓋 +8 到最後一個項目結尾。
   三個公開 BIOS 的所有目錄（42 個）checksum 都相符，所以算法與涵蓋範圍是實測確認的（用 coreboot 的算法；「模 65535」的等價寫法在某一半剛好是 0 或 0xFFFF 時會和 coreboot 不同，所以不用）。
3. **往下走**：combo 項目（lvl2 位址）、PSP 的 0x40（L2）、BIOS 的 0x70（L2）、其他解出位置開頭是目錄 cookie 的項目、A/B 復原的 Image Slot Header
   （PSP 的 0x48／0x4A，項目 size 為 0 或 0x100（coreboot 寫 `BLOB_ALIGNMENT`），指到 0x20 bytes 的 slot header；header 的 checksum 是同一個 `fletcher32`，涵蓋 +4 到 +0x20，
   對了才採用裡面的 `pl2_location`（L2 目錄），不對記 `ish-checksum`）。其他 size 的 0x48／0x4A 不解讀（`ish-size`）。深度、目錄數、項目總數有上限；每個（位置，基底）只解析一次，循環只是一條指向已存在目錄的邊。
4. **位址**：目錄標頭的 address mode（0 實體、1 相對視窗）優先，只有目錄是 2（相對目錄）或 3（相對 slot）才看項目自己的 mode（PSPTool 的做法）；
   mode 3 的 slot 起點未知，不解。值在 `2^32−W` 以上是映射在 4 GB 頂端的位置（W＝視窗大小，最大 16 MiB，所以大於 16 MiB 的映像相當於遮成 24 bits），其餘是視窗內偏移。
5. **競爭的讀法（`resolve_readings`）**：EFS 有位移時，指標值可以讀成「視窗座標」（加視窗開頭）或「整個檔案的偏移」（加 0），combo 項目也一樣；
   兩種讀法都在目標位置看到目錄 cookie，或同一個位置被不同的視窗基底讀到（條目位址依基底會讀到不同的地方），就有一組互相競爭的讀法。兩邊都解析、都列在 inventory
   （目錄紀錄以（位置，基底）為單位）。每一組用**各自的結構檢查**決定，不靠猜哪個是硬體實際使用的。原則：**只有結構上的正面證據才算不通過；沒有被完整檢查過的讀法不可以被採用，也不可以替另一邊背書。**
   - **證據**（`reading_state`，只收「讀錯基底時才會出現、讀對時不該出現」的結構性反證）：(1) 目錄表超出檔案、checksum 不符；(2) 條目的位址解不出來（超過 4 GiB、負的）、條目範圍或壓縮條目的起點超出檔案、
     指標條目沒指到目錄；(3) A/B 復原的 Image Slot Header：checksum 不符、或 checksum 相符但 `pl2_location` 沒指到目錄；(4) combo 目錄有位址的項目沒指到目錄；
     (5) 目錄表本身落在自己某個（未壓縮）條目的範圍裡。**不含**條目內容的判斷（版本標頭對不對、type 認不認得）。
   - **限制（無法判斷，不是證據）**：解析被超時或例外打斷、項目數超過 `MAX_DIR_ENTRIES`、項目總數超過 `MAX_ENTRIES_TOTAL`、目錄數或深度超過上限（那一種讀法根本沒有紀錄）、address mode 3、條目大小超過 `MAX_BLOB`、
     A/B 復原條目的大小不是 0 或 0x100、條目解析出錯。有任何限制、又沒有證據的讀法 → 整組維持歧義。條目的 `limit` 欄位（True＝限制、False＝證據）記這兩類。
   - **結果**（`verdict`）：每一種讀法都有被完整檢查、而且恰好一種通過 → 採用它，有證據不通過的標「未採用」（`rejected`，`rejected_because`＝證據，`used_instead`＝改用哪個；記 `reading-rejected`，ATTENTION，所以報告不會乾淨）；
     通過的有兩種以上、而且解讀結果完全相同（條目逐項相同——type、subprogram、instance、旗標、大小、destination、值型條目的值、壓縮條目的位置、指到的內容的 SHA-256、子目錄位置、slot header 欄位、combo 的 id 與子目錄位置）
     → 都採用（用哪一個都一樣；記 `reading-equivalent`）；**內容的 SHA-256 相同但位置不同時，兩邊都採用，SBOM 元件的 locations 會列兩處**；拿不到雜湊（雜湊上限）不算相同。
     通過的有兩種以上但內容不同、都沒通過、有任何一種無法判斷、或一組裡有讀法沒有紀錄 → 整組維持歧義（GAP；`pointer-ambiguous`／`dir-ambiguous`；三種以上時只要有兩種內容不同，三種都不採用），
     條目只列在 `amd.ambiguous`、不進 SBOM。沒有任何一種被採用時，沒通過的也不標「未採用」（沒有讀法可以改用）。
   - **全域保險**：碰到目錄數／深度／項目數／項目總數／EFS 數上限（`dir-limit`、`dir-too-many-entries`、`efs-limit`）、發現目錄循環（`dir-loop`）、或比較內容時雜湊上限用完（`hash-limit`），所有競爭的讀法一律維持歧義
     （不去判斷哪一組「牽涉到」）。目錄階段沒走完（超時或例外）時不做任何採用或拒絕：所有紀錄維持歧義。
   - **作用範圍**：指標那一組只作用在那一個指標的邊（同一個目錄若也從別的、單一讀法的指標到得了，仍然確定）；同一位置不同基底那一組作用在紀錄本身。確定的目錄＝從 EFS 出發只走
     「通過的邊」（單一讀法的指標，或指標的讀法被採用的那一邊）到得了的；子目錄沿用被採用那一讀法的基底。被拒絕的讀法底下、只能經由它到得了的子目錄跟著標 `rejected`
     （`reading-rejected`，說明「只經由不採用的讀法到得」；只有進來的邊全都被拒絕才算，有一條來自歧義的就是歧義）；經由歧義的讀法才到得了的子目錄是歧義。
   - **與處理順序無關的範圍**：走訪依深度逐層（`walk`）：每個（位置，基底）只解析一次，用它最淺的深度；同一層內依（位置，基底）排序；指標只登記邊，不遞迴；循環只是一條指向已存在節點的邊
     （`dir-loop` 事後在圖上找）；`child`／`children`／`directories_seen` 只由 cookie 判斷的位置算出，不看目錄有沒有被解析。紀錄、問題、`reached_via`、`readings`、版本清單、EFS 的 `directories_found`
     （沿著邊算到得了的紀錄數）都用穩定的鍵排序。在合成的隨機映像（含循環、各種上限、競爭的讀法、壞 checksum、超界）上，把 EFS 與指標的處理順序打亂，整份結果（JSON）逐字相同；
     範圍只限「EFS 與指標的處理順序」，不含輸入映像本身的差異，也不含超時（超時發生的位置由時間決定）。上限造成的「沒解析的紀錄」是由內容與排序決定的，所以也不依賴順序；即使如此，碰到上限就全部維持歧義。
   - 被拒絕讀法讀錯基底時產生的雜訊問題（`pointer-unresolved`、`entry-overlap`、`ish-checksum` 之類）仍照原樣列在 `problems`，沒有被濾掉；它們是「用那種基底讀」的後果，不代表映像壞了。
6. **條目**：type 對照（coreboot `psp_directory.h`／`bios_directory.h`，名稱沿用上游識別字）、subprogram、instance、rom id、writable、位置、大小。
   `size=0xFFFFFFFF`（例如 soft fuse chain）的位址欄位是值，不是位置。BIOS 目錄 `compressed` 旗標的條目：size 不一定是儲存範圍（可能是解壓後大小），所以只檢查起點在檔案內
   （不在 → `entry-range`），內容**不解壓、不解析**（包括 type 0x66，不會把壓縮內容剛好像明文的東西列成微碼），一律記 `entry-compressed`。
   size 0 的條目：BIOS 的 APOB（type 0x61）有 destination 時是「只有 destination」——coreboot `amdfwtool.c` 要求 APOB 一定要有 destination（"APOB destination not provided"），source／size 可以是 0——
   不算缺口（destination 必須不是 0 也不是全 1，coreboot 的條件是 `!dest`；只對 type 0x61、只在 size 0 時放行）；其他 size 0 的條目一律記 `entry-empty`（意義不明）。
7. **版本**：PSP 韌體條目有 `amd_fw_header`（0x100 bytes）時，`fw_type`（+0x7C）要等於目錄 type、`size_total`（+0x6C）要在 0x100 到項目大小之間，
   通過才讀 +0x60 的 4 bytes，顯示成 byte 反序的十六進位 `aa.bb.cc.dd`（amdfwtool、PSPTool 的顯示方式）；欄位全 0 或全 1 當作沒有。這是**標頭裡的版本欄位原值**，
   不是 AMD 公告用的版本名稱（例如 SMU 版本的十進位寫法），沒有轉換、不猜。
8. **微碼**：BIOS 目錄 type 0x66。項目開頭是 `DMA\0` container（Linux 核心 `amd.c` 的格式）就讀等價表（CPUID ↔ equivalence id）與 patch 區段；
   否則當成單一 patch 標頭：BCD 日期（mmddyyyy，年 2000–2099）、`patch_id`（patch level）、`processor_rev_id`（equivalence id）都要合理。**單獨的 patch 沒有等價表，
   只列 equivalence id，不猜 CPUID**（記 GAP `ucode-cpuid`）。
9. **AGESA**：走訪 firmware volume（`uefi_image.parse_fvs`，LZMA 等解開，FV 以外的非空白位元組它也送進來），在每塊內容找 `AGESA!V` 標記：`V` 加 1–4 個英數字當 tag，
   後面一定要接一個 NUL 或空白當分隔，再讀最多 64 個可列印字元。**沒有分隔符（tag 和字串黏在一起，切不出來）、分隔後是空的、字串超過 64 字元被截斷**都不當成版本：
   記 GAP，截斷的值在 SBOM 的 `AMD AGESA` 元件不寫 `version`（`dumpling:version-status=GAP`，原值前綴放在 `sca-center:note`）。
   **涵蓋規則（不依賴 uefi_image 對外介面約定以外的東西——只用 `Scan`／`scan_bytes`／`parse_fvs`／`Stop`／`MAX_*` 與原本就在用的 `fvs`、`files`、`undecoded`、`notes`、`parse_errors`；
   不讀它呼叫端的區域變數，不用 frame／inspect／`Scan.layers`）**：另外找整個映像原始位元組裡的標記。走訪的 `scan_bytes` 只收到內容，沒有辦法分辨它是原始位元組的切片還是解壓縮出來的，
   解壓縮出來的內容也可能和原始位元組裡另一處沒被搜尋的複本（UI section、被刪除的複本、空白區）位元組完全相同。沒有正式介面可以證明原始位元組的某個位置有被走訪搜尋過，所以規則是：
   - **原始位元組裡只要有任何 AGESA 標記，搜尋就標為不完整**（問題訊息寫明沒有正式介面可以證明，M7 再補精確的位置涵蓋；M7 由 C1 提供回呼介面）。
   - 原始位元組裡有、走訪結果裡沒有的 `(tag, value)`：加進結果，位置寫 `image (raw bytes)`；走訪結果裡已經有的值：只標不完整，不加位置、不重複計數。
   - 標記只在解壓縮內容裡、原始位元組裡沒有 → 不影響完整性（其他條件都滿足時可以完整）。
   - 代價：原始位元組裡有 AGESA 模組（沒有壓縮）的映像，AGESA 搜尋一律不完整；這是刻意保守的（不會多出「完整」，只可能多出「不完整」）。三個公開樣本的原始位元組標記數都是 0，結果不受影響。
   - 實作比 D-047 的字面更保守：原始位元組有任何標記就標不完整，理由是沒有正式介面可以證明那個位置有被走訪過（不嘗試用內容出現次數去換算）。
   - 走訪回報的任何沒解開的部分（`Scan.undecoded`）一律讓搜尋不完整，包括最上層 FV 以外的非空白位元組：uefi_image 只把它們當原始內容搜尋，裡面的壓縮串流不會被解開。
   不同的完整值全部列出，超過一個就 ATTENTION。`uefi_image` 載入不了或走訪失敗時只有原始位元組的結果（不完整）。走訪沒有完整（有沒解開的部分、結構警告、沒有 FV、上限）→ 搜尋不完整，
   GAP「沒找到不代表不存在」。同一句問題訊息只記一次。

## GAP 規則（一律列出、不猜；SBOM 不能比實際完整）

`amd.problems`（逐筆，每種最多列 `MAX_PROBLEMS_SHOWN` 筆，其餘只計數）與 `bios[].gaps`（彙整成每種一行：件數與前幾個例子）：

| code | 意思 | 狀態 |
|---|---|---|
| `no-directory` | 沒有任何可解析的目錄 | GAP |
| `efs-no-pointer`、`pointer-unresolved` | EFS／combo／項目的指標沒有指到目錄 cookie | GAP |
| `dir-checksum` | checksum 不符：條目照列但**不用於**版本、雜湊、微碼 | ATTENTION |
| `dir-too-many-entries`、`dir-truncated`、`dir-limit` | 項目數超過上限、項目表超出檔案、目錄數／深度／項目總數超過上限：該目錄的條目不解析 | GAP（`dir-limit` ATTENTION） |
| `dir-loop` | 目錄圖上有循環（一個目錄的指標回到能走到它的目錄）：不重複走；所有競爭的讀法維持歧義 | ATTENTION |
| `type-unknown` | type 不在公開清單：照列位置與大小，不解讀 | GAP |
| `entry-address`、`entry-range`、`entry-size` | 位址解不出（mode 3、大於 2^32）、範圍超出檔案、大小超過 `MAX_BLOB`：不讀、不雜湊 | GAP（`entry-range` ATTENTION） |
| `entry-overlap` | 同一目錄內條目範圍部分重疊、目錄表與任何條目重疊、目錄表互相重疊（不同目錄指到完全相同的範圍是共用，不算；L1 保留較大區間而 L2 條目在裡面也不算） | ATTENTION |
| `version-unverified` | PSP 條目沒有可驗證的標頭版本（彙整一行，列 type 與數量） | GAP |
| `ucode-unrecognised`、`ucode-cpuid`、`ucode-limit` | 微碼條目看不懂、只有 equivalence id、超過上限 | GAP |
| `efs-pointer-unparsed` | EFS 的 imc／gec／xhci／Promontory 指標有值但沒有解析 | GAP |
| `ish-checksum`、`ish-size` | Image Slot Header 的 checksum 不符（不採用它的 `pl2_location`）；0x48／0x4A 項目的 size 不是 0 或 0x100（不解讀） | ATTENTION（`ish-checksum`）／GAP |
| `pointer-ambiguous`、`dir-ambiguous` | 競爭的讀法（同一個指標的兩種讀法、同一個位置的不同基底）都通過結構檢查而內容不同、或都沒通過：兩邊都列、都不進 SBOM（工具不判斷哪個是硬體實際使用的）；只經由這種讀法到得了的目錄標 ambiguous | ATTENTION |
| `reading-rejected` | 一組競爭的讀法裡恰好另一種通過：這一種「未採用」（附證據：checksum 不符的值、哪個條目超出範圍…），只經由它到得了的子目錄也不採用。條目只列在目錄清單，不進 SBOM | ATTENTION |
| `reading-equivalent` | 競爭的讀法都通過、解讀結果完全相同：都採用 | GAP 列（說明用） |
| `entry-compressed` | BIOS 目錄壓縮旗標的條目：不解壓、不解析（含 type 0x66），只檢查起點在檔案內 | GAP |
| `entry-empty` | size 0 的條目（有 destination 的 APOB 除外，依據見上面第 6 點） | GAP |
| `entry-error`、`internal-error` | 單一條目／整個階段的解析出錯（不該發生）：只影響那個條目／階段，其餘結果照給 | ATTENTION |
| `hash-limit`、`efs-limit` | 雜湊總量／EFS 數超過上限 | GAP |
| AGESA 問題 | 標記後沒有分隔符或字串、字串被截斷、值太多、走訪不完整或原始位元組裡有標記（沒有正式介面可以證明走訪搜尋過那個位置） | GAP；多個不同的完整值＝ATTENTION |

另外：沒有讀到任何微碼時固定記一行「不是沒有微碼」；`amd_psp` 載入失敗時 `bios[].amd` 是 `None`，gaps 寫「parser did not run」。

## 上限

| 常數 | 值 | 用途 |
|---|---|---|
| `MAX_EFS`、`MAX_SIG_HITS`、`MAX_SHIFT` | 8、4096、0x10000 | EFS 數、全檔簽章候選數、標頭位移 |
| `MAX_DIRS`、`MAX_DEPTH`、`MAX_DIR_ENTRIES`、`MAX_ENTRIES_TOTAL` | 64、4、256、4096 | 目錄數、巢狀深度、單一目錄項目數、全部目錄項目總數（跨巢狀累計） |
| `MAX_BLOB`、`MAX_HASH_TOTAL` | 64 MiB、256 MiB | 單一條目大小；雜湊總量（同一段 offset＋size 只算一次，所以多個目錄共用的條目不會放大） |
| `MAX_UCODE`、`MAX_EQUIV`、`MAX_PATCHES` | 64、256、16 | 微碼數、container 等價表項目數、container 的 patch 數 |
| `MAX_AGESA_MARKERS`、`MAX_AGESA_VALUES`、`MAX_AGESA_INSPECT`、`AGESA_VALUE_LEN` | 4096、16、1 GiB、64 | AGESA 標記總數、不同值數（超過時搜尋不完整）、走訪送進搜尋的內容總量（每次 `scan_bytes` 的內容都算，不去重）、字串長度 |

沒有用 regex 找 AGESA（`bytes.find` 固定字面值）；目錄 checksum 的計算量上限是 256 項 × 24 bytes。

## 公開樣本：`asus-prime-b550m-a-3404`

ASUS PRIME B550M-A BIOS 3404（2023/10/31，AMI），16.7 MB zip，裡面一個 33558528 位元組的 CAP（4 KiB 標頭＋兩個 16 MiB 視窗）。選它的技術理由：
EFS 因標頭位移不在固定位置（0x21000、0x1021000）；EFS 指向 combo 目錄（`2PSP`／`2BHD`），再指到多個 L1；新世代的 L1 有 0x40／0x70 指標到 L2（`$PL2`、`$BL2`）；
AGESA 字串在壓縮的 firmware volume 裡；release notes 有 AGESA 版本可當出處。

2026-11-13 的解析結果（`python3 -I x86_firmware.py inventory --in PRIME-B550M-A-ASUS-3404.CAP`，約 2.5 秒）：

- 2 個 EFS（視窗位移 0x1000）→ 19 個目錄紀錄（17 個位置：2 個 combo PSP、1 個 combo BIOS、5 個 L1 PSP、2 個 L2 PSP、5 個 L1 BIOS、2 個 L2 BIOS；0x131000 與 0x15a000 各有兩種基底的讀法），
  checksum 全部相符。
- **競爭的讀法與結果**（規則見流程第 5 點）：19 個紀錄中 17 個採用、2 個不採用、0 個歧義。
  - 第二個 EFS 的 `new_psp_directory`（0x131000）讀成視窗座標是 0x1132000（combo，基底 0x1001000），讀成檔案偏移是 0x131000（基底 0）。基底 0 的讀法裡，combo 的三個項目（指標 0xff2a9000、0xff2a9000、0xff159000）
    讀成 0x2a9000、0x159000，那裡都沒有目錄 cookie → 沒通過；視窗讀法的三個項目都指到目錄 → 採用視窗讀法。同一個位置 0x131000 也被第一個 EFS 用基底 0x1000 讀過（單一讀法），基底 0 的紀錄同樣不採用。
  - 0x1132000 的第三個項目（指標 0x15a000）又有兩種讀法：視窗讀法 0x115b000（基底 0x1001000）通過；檔案偏移讀法 0x15a000（基底 0）的目錄表 [0x15a000, 0x15a190) 落在自己的條目 1（type 0x01）的範圍
    [0x159700, 0x165c80) 裡 → 沒通過（結構檢查第 5 項）→ 不採用。同一個位置 0x15a000 用基底 0x1000 讀（從第一個視窗的 combo 單一讀法到得了）的紀錄通過，採用。
  - 兩個被拒絕的紀錄各記一筆 `reading-rejected`（ATTENTION，訊息含證據與改用哪個讀法）。另外 `pointer-unresolved`（3）與 `entry-overlap`（3）是讀錯基底那一側的雜訊，照原樣列在 problems。
  - **第 5 項檢查是這個樣本的 PSP 版本能不能全進 SBOM 的關鍵**：沒有它，0x15a000（基底 0）與 0x115b000（基底 0x1001000）都通過、內容不同 → 維持歧義，3 個目錄歧義，47 個 PSP 版本確定、31 個列在 `amd.ambiguous`。
- PSP 版本：78 個（全部確定，進 SBOM）；63 個條目沒有可驗證的標頭版本（公鑰、NVRAM、SECURED_DEBUG、IKEK、token 等）。
- 19 份 AMD 微碼（BIOS 目錄 type 0x66，全是單獨的 patch）：patch level、日期、equivalence id，例如 `0x0800820d`／2019-04-16／`0x8082`。
- AGESA：`AGESA!V9` + `ComboAM4v2PI 1.2.0.B`（6 處，只有這一個值）；原始位元組裡的 AGESA 標記數是 0（所以涵蓋規則沒有影響這個樣本）。
- GAP：2 個 Promontory 指標沒解析、5 個壓縮的 BIOS 條目（type 0x62）不解析、3 個未知 type（BIOS 0x67、PSP 0x43、0x4E）、63 個條目沒有版本、微碼只有 equivalence id、
  AGESA 搜尋不完整（2 個 GUID-defined section `CE3233F5-…` 需要處理但不支援，另有一個 FFS 檔的 section 串不乾淨）。狀態 ATTENTION。
- SBOM 元件：99（映像 1、PSP 韌體 78、微碼 19、AGESA 1）。
- 競爭的讀法結果依賴結構檢查的定義（尤其是證據第 5 項）；檢查項目是保守地只收讀錯基底時才會出現的證據，沒有拿版本欄位來選邊。沒有第 5 項時 0x15a000（基底 0）與 0x115b000（基底 0x1001000）都通過、內容不同，
  會維持歧義（47 個 PSP 版本確定、31 個歧義）。這個樣本沒有目錄循環，也沒有碰到任何上限。

### expected（只寫有公開出處的值）

| 鍵 | 值 | 出處 |
|---|---|---|
| `amd_agesa` | `1.2.0.B` | ASUS 官方下載頁 BIOS 3404 的 release notes：「Update AGESA version to ComboV2PI 1.2.0.B」（2026-11-13 查）。映像字串的名稱寫法不同（`ComboAM4v2PI`），所以只比 PI 版本號 |
| `amd_microcode` | `0x8082`／`0x0800820d`、`0x8012`／`0x08001250` | 映像裡這兩份 patch 與 linux-firmware（AMD 提供，`LICENSE.amd-ucode` 允許散布）commit `c4586ffaac0c`（2019-12-18）的 `amd-ucode/microcode_amd_fam17h.bin` **位元組相同**（patch 區段 SHA-256 `c00b6b19fd5c…`、`689883cd220d…`）。該檔的等價表把 `0x8012` 對到 CPUID `00800F12`、`0x8082` 對到 `00800F82` |

用 linux-firmware 的真實 container 也順便驗證了 `parse_ucode` 的 container 路徑（10 個歷史版本的檔案都解得開、等價表對得出 CPUID）；CI 的樣本只有單獨 patch，container 路徑靠合成測試。

### 已讀出但沒有佐證（不寫進 expected）

- PSP 韌體條目的標頭版本（bootloader、SMU、ABL…）：沒有找到可對照的公開來源；顯示的是欄位原值，不是公告用的名稱。
- 其他 17 份微碼 patch（不在上述 linux-firmware 版本裡）。
- equivalence id 對應的 CPUID：映像裡的微碼沒有等價表。
- 目錄結構（17 個目錄、244 項）：這是解析結果，不是別人公布的值。

## 另外做過的只讀驗證（不在樣本清單、不在 CI）

可用公開網址重現（下載物當不可信資料，只讀）：

- ASRock B550 Phantom Gaming 4 BIOS 3.40：`https://download.asrock.com/BIOS/AM4/B550%20Phantom%20Gaming%204(3.40)ROM.zip`，15513528 位元組，SHA-256 `7128bf8417924b93b509915cfdfaedecba470f4885d7fb802c906a0ebee5e985`；
  zip 內一個 33554432 位元組的 `B550PG43.40`（SHA-256 `19cd0d852086227e4e85e7f184baa5c23eed93abe1718462dd1079e14a6db692`）。結果：2 個 EFS（0x20000、0x1020000）、17 個目錄、246 項，沒有競爭的讀法
  （17 個目錄都確定，SBOM 101 個元件＝映像 1、PSP 韌體 80、微碼 19、AGESA 1）；AGESA 同樣是 `ComboAM4v2PI 1.2.0.B`；19 份微碼，其中同兩份與 linux-firmware 位元組相同。
  ASRock 的下載頁要 JavaScript 驗證，抓不到 release notes，也無法確認授權頁網址，所以沒有列為樣本。
- ASUS PRIME B650M-A BIOS 1807（AM5）：`https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/PRIME-B650M-A-ASUS-1807.zip`，11601928 位元組，SHA-256 `8f9202f9c88ca6124b45951b2745f9eabaa8af87d1a290ffd908a39394985cbc`。
  結果：`psp_bak_directory` 的指標有兩種讀法（視窗座標 0x83000＝基底 0x1000、檔案偏移 0x82000＝基底 0）；0x82000 也從 `new_psp_directory` 用基底 0x1000 讀過。基底 0 的 0x82000 讀法裡
  A/B slot header 的 checksum 不符（條目 0：0x00000048、條目 1：0x0000004a 不是 slot header 的 checksum，位址讀錯了）→ 沒通過 → 不採用；0x83000（基底 0x1000）與 0x82000（基底 0x1000）都通過，採用。
  9 個目錄紀錄：8 個採用、1 個不採用、0 個歧義；21 個 PSP 版本與 2 份微碼進 SBOM（元件數 2 → 25：映像 1、PSP 韌體 21、微碼 2、AGESA 1，AGESA 是 `ComboAM5PI 1.0.8.0`）。
  另有 2 份微碼條目的格式不同（開頭是 `$PS1` 簽署標頭），記 GAP。
  這個驗證抓到並修正了「size 0 的 0x48／0x4A 項目被當成沒有資料」的錯誤。
- linux-firmware 的 `amd-ucode/microcode_amd_fam17h.bin`：`https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/amd-ucode/microcode_amd_fam17h.bin?id=<commit>`，
  commit 取 `git log` 該檔的前 10 筆（含 `c4586ffaac0ca0d7045e06140b6426f2e79e96e6`）；10 個版本的 container 都解得開。

## 限制與不確定

- 只認得 coreboot 公開標頭列出的 type；沒有列的（例如 BIOS 0x67、PSP 0x43、0x4E、0x93）只記位置與大小，名稱和意義不猜。
- PSP 版本是標頭欄位原值的十六進位顯示，不同 type 的欄位意義可能不同（ABL 的欄位看起來像日期，沒有佐證所以不解讀）。
- 位址視窗假設是 16 MiB（或更小的映像整體）。映像大小不是 2 的次方又小於 16 MiB、或截斷的檔案，頂端映射的位置會算錯，結果是 `pointer-unresolved` GAP，不會誤讀。
- **競爭的讀法只靠結構檢查決定**（見流程第 5 點）：恰好一種通過才採用；都通過但內容不同、或都沒通過，工具不判斷哪一個是硬體實際使用的，兩邊都列、都不進 SBOM。結構檢查沒有涵蓋的錯誤
  （例如兩種讀法都結構完整、內容不同，其實只有一種是硬體用的）仍是 GAP；結構檢查通過不等於「硬體一定用這個」，只代表另一種讀法在結構上站不住。沒有做「同一個 EFS 的其他指標只在某種座標說得通」這類推論。
- 沒有簽章驗證（Image Slot Header 只驗 checksum）；Promontory 晶片組韌體、IMC／GEC／XHCI 沒有解析；壓縮的 BIOS 目錄條目（type 0x62）不解開。
- AGESA 搜尋依賴 `uefi_image` 能解開的部分；EFI 標準壓縮與需要處理的 GUID-defined section 解不開（會讓搜尋不完整，沒找到不代表不存在）。
  **`complete` 的語意**：只代表「走訪沒有回報沒解開的部分（含 FV 以外的非空白位元組）、沒有結構警告、沒有碰到標記數／內容量／不同值數的上限、沒有被超時或例外打斷、有解出 FV，而且原始位元組裡沒有 AGESA 標記」。
  uefi_image 本來就不掃的位置不在保證範圍內：FV 標頭與 extended header、GUID-defined section 的標頭到 DataOffset 之間、RAW section 裡的 LZMA 串流（不會被當容器解開）；
  這些位置裡的標記搜尋不到也不會讓 `complete` 變 False。這一塊要等正式的回呼介面（M7）才能補。
- **競爭的讀法的兩個取捨**：
  - 被拒絕的讀法和被採用的讀法各有子目錄、落在同一個位置但不同基底，而且兩邊都通過結構檢查、內容不同時，被採用那一邊的子目錄也會標歧義（同一位置的不同基底讀法是一組競爭的讀法；
    被拒絕那邊的子目錄不會替另一邊背書）。結果是保守的：少採用，不多採用。
  - 「條目範圍超出檔案」的證據假設映像是完整的（沒有被截斷）；截斷的檔案會讓正確的讀法被當成有證據不通過。slot header 整塊是 0 時 checksum 不符，算證據；整塊是 0xFF 時 checksum 剛好相符
    （`pl2_location` 是 0xFFFFFFFF＝沒有指標），不算證據、也不會往下走。
- 微碼的 `patch_size` 是目錄項目的大小（單獨 patch 時等於 patch 區段大小）；patch 內部的 checksum、簽章沒驗證。
