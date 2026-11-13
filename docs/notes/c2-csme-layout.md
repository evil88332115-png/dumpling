# C2：擴充新世代 Intel CSME 的解析範圍（分支 wp3/csme-new）

x86_firmware.py 原本只有一條路找 CSE 版本：`$FPT` 分割區表 → FTPR → `$CPD` 的 FTPR.man →
`$MN2`（退路：名稱是 FTPR 的 `$CPD`）。新世代的 ME 區域配置沒有這兩樣，結果是 unknown。這份是工作紀錄，不是驗證結論；
數字是 2026-11-13 對公開樣本量的，樣本不進 repo（D-028）。

## 檔案

| 檔案 | 內容 |
|---|---|
| `tools/cra/intel_cse_layout.py` | 新模組：CSE layout table → BPDT → FTPR／RBEP／NFTP 分割區的 `$CPD` → `<名稱>.man` 的 `$MN2`。只讀、無全檔掃描、無 regex、全部有固定上限 |
| `tools/cra/x86_firmware.py` | 只動 ME 那段的接線：原來的 `me_info` 改名 `me_info_fpt`（內容沒改），新的 `me_info` 先呼叫它，結果不是 found 才試新模組；AMD 相關程式沒動 |
| `tools/cra/tests/test_intel_cse_layout.py` | 105 個測試（pytest 計數，含參數化），測資全由測試當場合成 |
| `firmware/bios/novacustom-v540tu-mtl-v1.0.1/firmware.yml` | 公開真樣本（Size 0x58）與 `expected.intel_me` |
| `firmware/bios/novacustom-nuc-box-arl-v0.9.2/firmware.yml` | 公開真樣本（Size 0x60）與 `expected.intel_me`、微碼 |

## 格式（逐欄對公開出處核對）

出處（只引用欄位定義，程式是自己寫的，沒有複製或改寫 GPL 程式碼）：
coreboot `util/cbfstool/ifwitool.c`（BPDT、子分割區目錄、類型表）、`src/soc/intel/common/block/include/intelblocks/cse_layout.h`
（BPDT version 1.7、`$CPD` header version 2、layout table）、MEAnalyzer 的 `CPD_Header_R1`／`R2`、`MN2_Manifest`。

- **CSE layout table layout 1.7**（ME 區域開頭；MEAnalyzer 的 `CSE_Layout_Table_17`）：+0 ROM bypass 16 bytes、+0x10 Size(u16)、+0x12 Flags(u8，bit 0＝CSE redundancy，開啟時 BP2 是 BP1 的備份)、
  +0x14 checksum(u32)、+0x18 data(offset,size)、+0x20…+0x44 BP1…BP5(offset,size)、+0x48 temp pages、+0x50 external error log；全是 u32，offset 相對區域開頭。
  **Size 從 +0x10 起算**：表的總長是 0x10＋Size。MEAnalyzer 的註解寫 Size 是 0x40（沒有 ELog）或 0x48（有 ELog）；公開真樣本（Meteor Lake 兩個版本）是 0x58（表總長 0x68，+0x58 起 16 bytes 全 0）。
  **checksum 是 CRC-32**，範圍＝d[+0x10:+0x14] ＋ 4 個 0（checksum 欄位本身不入算）＋ d[+0x18:+0x10+Size]（MEAnalyzer 的驗證程式碼；
  登記的樣本 v1.0.1 與同系列 v1.0.0（btg_provisioned.rom）的 stored 值都是 0x7123699e，計算結果相符）。**這一版先前的說法「算法沒查到」是錯的，已更正。**
  本模組逐值認 Size 0x40、0x48、0x58、0x60；CRC 不符 → GAP；Size 是其他值 → 不認（none，維持原結果）。
  0x40、0x48 只有 MEAnalyzer 的欄位定義與驗證程式為依據，沒有真樣本核對（測試用合成資料）。0x58 與 0x60 各有公開真樣本（0x60 見下一節）。0x58 的樣本（Meteor Lake）讀到 data=(0x3A2000,0xA4000)、
  BP1=(0x1000,0x3A1000)、BP3=(0x446000,0x441000)，兩個 BP 的起點確實是 BPDT 簽章。另外一律檢查「每個非空 BPn 都真的指到 BPDT、範圍不重疊、不超出區域、不壓到表本身」。
- **layout 1.6**（較舊；MEAnalyzer 的 `CSE_Layout_Table_16`，表長 0x48）：+0 ROM bypass 16 bytes、+0x10 data(offset,size)、+0x18…+0x3C BP1…BP5(offset,size)、+0x40 u64 checksum；
  表後面到 0x1000 全是 0xFF（1.6 沒有標記，MEAnalyzer 也用這個填充當辨識條件之一，本模組照做）。BP1…BP5 都讀、都納入矛盾檢查。
  u64 checksum：MEAnalyzer 註解說是整張表（不含 ROM bypass）的二補數和；唯一的公開樣本（Comet Lake）存的是 0x22，我試過位元組、u32、u64 的加總都湊不成 0，
  算法沒有確認，**不驗證**（測試明確寫這是限制）。因為沒有標記，矛盾（範圍重疊、超出、填充不是 0xFF）時當作「不是 layout table」（none）。
- **BPDT**（每個 BP 的開頭）：0x18 bytes 表頭（簽章 0x000055AA、項目數 u16、version u8、flags u8、…）。項目 12 bytes：version 2＝type(u32)、offset、size；
  version 1＝type(u16)、flags(u16)、offset、size。offset 相對 BPDT 開頭（樣本：RBEP 項目 offset 0x1000，絕對位置 = BP1 0x1000 + 0x1000，確實是 `$CPD`）。
  類型：1＝RBEP（CSE_RBE）、2＝FTPR（CSE_BUP）、5＝S-BPDT、7＝NFTP（CSE_MAIN）…
- **`$CPD`**：header version 1＝長度 0x10、+0xB 是 8 位元 checksum（header 加項目的總和為 0）；
  **header version 2＝長度 0x14、+0xB 保留、+0x10 是 u32 checksum**（版本 2 的欄位位移與版本 1 不同）。名稱都在 +0xC。
  v2 的 checksum 是「欄位當 0，對 header＋全部項目算 CRC-32」：樣本兩份映像共 27 個 `$CPD` 全部相符；v1 的 8 位元和在 Comet Lake 樣本 6 個全部為 0。
  項目 0x18 bytes：名稱 12、+0xC offset（低 25 bits，相對 `$CPD` 開頭；高位元是壓縮旗標，manifest 有旗標就拒絕）、+0x10 長度。
- **`$MN2`**：vendor 0x8086、+0x14 BCD 日期、+0x1C 簽章、+0x24 的 major.minor.hotfix.build。

## 新世代配置的樣本（真樣本）

Dasharo NovaCustom V540TU（Meteor Lake）v1.0.1 的 `btg_prod.rom`（32 MiB，sha256 見 firmware.yml）：

| 項目 | 內容 |
|---|---|
| 區域 | descriptor＋ME 區域（0x6000–0x88CFFF）＋BIOS 區域；ME 區域開頭是 layout table |
| `$FPT` | 只有 1 個，在 data partition（區域 +0x3A2000，11 個分割區：RSTR、IMDP、HVMP、MFS、UTOK、FLOG、ELOG、EFS、FITC、CDMD、UEP），沒有 FTPR 項目 |
| 名稱是 FTPR 的 `$CPD` | 沒有 |
| `$CPD`／`$MN2` | 14 個 `$CPD` 分割區（都是 header version 2）、15 個 `$MN2`，各分割區版本不同（PMCP、IOMP、NPHY、TBTP、PCHC、SPHY、EFWP、DCOD、PCOD、ISHC、ADSP…） |
| 主程式 | BP1 的 RBEP.man＝18.0.10.2285；BP3 的 NFTP.man＝18.0.10.2285（日期欄位也相同）。BPDT 表頭的 fit_tool_version 也是 18.0.10.2285 但那是 FIT 工具版本，不當依據 |

改動前（main 26a6377）：ME 版本 unknown（「no $FPT at the ME region start or +0x10; no $CPD names the FTPR partition」，候選 13 個版本）。
改動後：found 18.0.10.2285，basis「BPDT (CSE layout table 1.7): BP1 RBEP.man 18.0.10.2285 at 0x83ec, BP3 NFTP.man 18.0.10.2285 at 0x44d1ac; no FTPR partition, RBEP and NFTP agree」。
`expected.intel_me: 18.0.10.2285` 的出處是 Dasharo 的 release notes（v1.0.1、v1.0.0 都寫 "Intel Management Engine version v18.0.10.2285"）。
同系列 v0.9.0（release notes 沒有列 ME 版本）讀到 18.0.5.2040（RBEP＋NFTP 相符）：**已讀出但沒有佐證**，不寫進 expected、也沒有登記成樣本。
微碼也寫進 expected：映像讀到 000A06A4／platform 0xE6／revision 0x25，Dasharo v1.0.1 release notes 的 SBOM 寫 "MTL C0 0x00000025 0x25 19/03/2025"（連結指到 `intel-ucode/06-aa-04`），Intel 微碼倉庫 microcode-20250812 的 releasenote.md 寫 "MTL | C0 | 06-aa-04/e6 | 00000024 | 00000025"（platform mask e6）。FSP、coreboot 資訊：release notes 沒有可比對的值（FSP 寫的是 "2024/04/30 v4122_12"，與映像的 FSPH ImageRevision 不同格式），**已讀出但沒有佐證**，不寫。

交叉驗證（不改變任何既有結果）：Comet Lake 的 Dasharo 映像（`dasharo-protectli-vp46xx-v1.2.0`，layout 1.6、BPDT version 1、`$CPD` header version 1）用新模組讀到
FTPR.man、RBEP.man、NFTP.man 全部是 14.0.47.1558，與既有 expected 一致。那份映像原本就由舊的退路（名稱是 FTPR 的 `$CPD`）找到，新模組不會被呼叫。

## layout 1.7 的 Size 0x60 變體

更新世代（Arrow Lake-U/H FSP）的 Dasharo NovaCustom NUC BOX v0.9.2（`firmware/bios/novacustom-nuc-box-arl-v0.9.2`，32 MiB 完整映像，sha256 見 firmware.yml）：

| 項目 | 內容（位置相對 ME 區域開頭；ME 區域在檔案 0x4000–0x9FFFFF） |
|---|---|
| Size／Flags／CRC | +0x10 Size＝**0x60**（表總長 0x70）、+0x12 Flags＝0、+0x14 stored＝0xB8EFACAF；用現有算法（範圍到 +0x70）算出 0xB8EFACAF，相符 |
| 指標 | data＝(0x3A1000, 0xA4000)、BP1＝(0x1000, 0x3A0000)、BP3＝(0x445000, 0x3CA000)、BP2／BP4／BP5 與 temp pages 空、external error log＝(0x423000, 0x1000) |
| +0x58…+0x6F | 24 bytes 全 0 |
| BPDT | BP1、BP3 開頭都是 BPDT（version 2；項目數 9 與 5）。BP1 的 type 1（RBEP）→ RBEP.man 18.1.18.2724；BP3 的 type 7（NFTP）→ NFTP.man 18.1.18.2724；沒有 FTPR（type 2）。BPDT 表頭的 FIT 工具版本是 18.1.18.2749，不當依據 |
| `$FPT` | 只在 data partition（區域 +0x3A1000，11 個分割區），區域開頭沒有 |

改動前：ME 版本 unknown（Size 0x60 不認，被當成不是 layout table）。改動後：found 18.1.18.2724（basis：BP1 RBEP＋BP3 NFTP 一致）。
`expected.intel_me: 18.1.18.2724` 的出處是 Dasharo 的 v0.9.2 release notes（"Intel Management Engine version v18.1.18.2724"）；
微碼 000A06A4／0xE6／0x28 的出處是同份 release notes 的 SBOM 與 Intel 微碼倉庫 microcode-20260512 的 releasenote.md。檔名與目錄仍叫 mtl，
同目錄 v0.9.0／v0.9.1 是 Meteor Lake FSP（ME 18.0.5.2028），沒有用。

**Size 的取捨**：只逐值接受有依據的 Size（0x40、0x48 依 MEAnalyzer 欄位定義；0x58、0x60 依公開真樣本）。不用「≥ 0x40 且 8 的倍數、上限 N」這類規則，因為：
(1) CRC-32 只能擋隨機資料（32 位元，單獨一個不認識的 Size 值配上對的 CRC 的機率約 2^-32，但輸入是對手可控的，CRC 不是密碼學保護，可以刻意算出來）；
(2) Size 決定 CRC 的涵蓋範圍與表的長度，也決定 `head`（BP 不得壓到表）；放寬 Size 等於讓不認識的欄位排列也被當成已知結構；
(3) 比 0x60 更大的值沒有任何公開依據。測試明確列出 0x5C、0x64、0x68、0x70、0x78、0x80、0xA0、0x100，即使 CRC 用同樣算法算對也回 none。

**0x60 多出來的欄位**：公開定義（MEAnalyzer 的 `CSE_Layout_Table_17`、coreboot `cse_layout.h` 的 `struct cse_layout`）都只到 +0x58（external error log 結尾）；
Size 0x58 的 +0x58…+0x67 與 Size 0x60 的 +0x58…+0x6F 都沒有公開欄位名稱。三個真樣本這段全是 0。本模組不解讀它，但要求這段全是 0
（CRC 之後檢查）：有任何非 0 的 byte 就不採用這張表，回 GAP（原因寫在 me_note），因為不知道它是不是另一個 boot partition 指標，
照讀會漏掉主程式分割區的來源、或讓「RBEP 與 NFTP 兩個來源一致」的判斷出錯。BP1…BP5 的位置固定在 +0x20…+0x44，與 Size 無關；樣本的 BP 都指到 BPDT，且 RBEP 與 NFTP 版本相同。
這是保守選擇，不是「新欄位一定是 0」的主張；未來若出現非 0 的樣本，要有公開的欄位定義才放寬。
Size 0x58 的 +0x58…+0x67 原本沒有檢查，這次一起納入同一條規則（既有真樣本都是 0，結果不變）。

## 判定規則（不猜）

只看 BPDT 的 type 2（FTPR）、1（RBEP）、7（NFTP）；分割區名稱必須對應、`$CPD` 表頭與 checksum、`<名稱>.man`、`$MN2`、版本不是 0.0.0.0 都要過。

| 情況 | 結果 |
|---|---|
| 沒有 layout table、區域開頭也不是 BPDT | `none`：呼叫端維持原來的結果 |
| 有 FTPR，版本全部一致 | found，取 FTPR.man |
| 沒有 FTPR，RBEP 與 NFTP 各至少一份、版本全部一致 | found，取第一個 RBEP；basis 寫「no FTPR partition, RBEP and NFTP agree」 |
| 沒有 FTPR，缺 RBEP 或缺 NFTP（包括同一類型有多份拷貝，例如 redundancy 的 BP2 備份） | GAP（unknown）：同一類型的拷貝不算獨立來源，不採用 |
| 讀得到的主程式 manifest 版本互相不同 | GAP：列出全部，不報任何版本 |
| 任何 BPDT 或主程式分割區不一致：越界、重疊、重複項目、名稱不符、checksum 不符、manifest 壞、壓縮旗標、項目數超過上限 | GAP：原因接在 me_note 後面 |
| 配置了、整個 boot partition 都是 0xFF（清除過）的 BP | 略過（不算問題）；全部都空 → GAP。只有開頭 4 bytes 或 BPDT 表頭是 0xFF、後面有內容 → 結構壞（GAP） |

不會「退回第一個 `$MN2`」。GAP 時 me_status 維持 unknown（ATTENTION）。有 descriptor 時範圍是 ME 區域；沒有 descriptor 時 layout table 或 BPDT 要在檔案開頭，
而且新模組給 GAP 時不把 no-me-region 改成 unknown（避免檔案開頭碰巧的 0x0058 誤判成有 ME）。

上限：boot partition 5 個、每個 BPDT 48 項、每個 `$CPD` 256 項，只讀三種分割區；工作量與檔案大小無關（測試用 1.6 MB 的垃圾尾巴驗證沒有全檔掃描）。
S-BPDT 項目不往下追（沒有遞迴，也就沒有循環）。

## 限制與不確定

- 只處理 CSE 區域本身。IFWI 整個放在 BIOS 區域裡的平台（沒有獨立 ME 區域）、capsule 包著的 ME 區域、layout table 之外的配置不處理（維持原來的 unknown 或 no-me-region）。
- 新世代的公開真樣本：Meteor Lake（Size 0x58，兩個版本讀過）與 Arrow Lake-U/H FSP（Size 0x60，一個版本）；layout 1.6、BPDT version 1、`$CPD` header version 1 只有 Comet Lake 一個樣本交叉驗證，其餘靠合成測資與格式說明。
- 「RBEP 與 NFTP 版本相同才採用」是依樣本的觀察（兩代樣本都符合）加上保守原則；沒有查到 Intel 文件保證 CSE 版本等於這兩個 manifest 的版本。
- BPDT 表頭的 checksum 沒驗證（算法沒查到）；layout 1.7 的 CRC-32 與 `$CPD` 的 checksum 都有驗；layout 1.6 的 u64 checksum 不驗（算法沒確認）。
- 版本字串是 manifest 的 major.minor.hotfix.build，是 CSME、TXE 還是 SPS 不猜（family 維持 unknown，沒有 cpe）。
