# C2：擴充新世代 Intel CSME 的解析範圍（分支 wp3/csme-new）

x86_firmware.py 原本只有一條路找 CSE 版本：`$FPT` 分割區表 → FTPR → `$CPD` 的 FTPR.man →
`$MN2`（退路：名稱是 FTPR 的 `$CPD`）。新世代的 ME 區域配置沒有這兩樣，結果是 unknown。這份是工作紀錄，不是驗證結論；
數字是 2026-11-13 對公開樣本量的，樣本不進 repo（D-028）。

## 檔案

| 檔案 | 內容 |
|---|---|
| `tools/cra/intel_cse_layout.py` | 新模組：CSE layout table → BPDT → FTPR／RBEP／NFTP 分割區的 `$CPD` → `<名稱>.man` 的 `$MN2`。只讀、無全檔掃描、無 regex、全部有固定上限 |
| `tools/cra/x86_firmware.py` | 只動 ME 那段的接線：原來的 `me_info` 改名 `me_info_fpt`（內容沒改），新的 `me_info` 先呼叫它，結果不是 found 才試新模組；AMD 相關程式沒動 |
| `tools/cra/tests/test_intel_cse_layout.py` | 59 個測試，測資全由測試當場合成 |
| `firmware/bios/novacustom-v540tu-mtl-v1.0.1/firmware.yml` | 公開真樣本與 `expected.intel_me` |

## 格式（逐欄對公開出處核對）

出處（只引用欄位定義，程式是自己寫的，沒有複製或改寫 GPL 程式碼）：
coreboot `util/cbfstool/ifwitool.c`（BPDT、子分割區目錄、類型表）、`src/soc/intel/common/block/include/intelblocks/cse_layout.h`
（BPDT version 1.7、`$CPD` header version 2、layout table）、MEAnalyzer 的 `CPD_Header_R1`／`R2`、`MN2_Manifest`。

- **CSE layout table**（ME 區域開頭，layout 1.7，0x58 bytes）：0x10 bytes ROM bypass、+0x10 size(u16)=0x58、redundancy(u16)、checksum(u32)、
  data(offset,size)、bp1…bp5(offset,size)、temp、flog；全是 u32，offset 相對區域開頭。樣本讀到 data=(0x3A2000,0xA4000)、
  BP1=(0x1000,0x3A1000)、BP3=(0x446000,0x441000)，兩個 BP 的起點確實是 BPDT 簽章。checksum 的算法沒查到（試過 CRC-32、位元組加總、XOR 都不符），**不驗證**，
  改以「每個 BPn 都指到 BPDT、範圍不重疊、不超出區域」確認。
- **layout 1.6**（較舊，沒有 size／redundancy／checksum）：只有一個公開樣本（Comet Lake 的 Dasharo 映像）的觀察：ROM bypass 後直接是 data、bp1、bp2 的 (offset,size)。
  後面欄位意義沒讀到，不用。因為沒有標記，矛盾時當作「不是 layout table」。
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
改動後：found 18.0.10.2285，basis「BPDT (CSE layout table 1.7): BP1 RBEP.man 18.0.10.2285 at 0x83ec, BP3 NFTP.man 18.0.10.2285 at 0x44d1ac; no FTPR partition, the manifests agree」。
`expected.intel_me: 18.0.10.2285` 的出處是 Dasharo 的 release notes（v1.0.1、v1.0.0 都寫 "Intel Management Engine version v18.0.10.2285"）。
同系列 v0.9.0（release notes 沒有列 ME 版本）讀到 18.0.5.2040（RBEP＋NFTP 相符）：**已讀出但沒有佐證**，不寫進 expected、也沒有登記成樣本。
映像另外讀出的微碼（000A06A4／0xE6／0x25）、FSP、coreboot 資訊：release notes 沒有可比對的值（FSP 寫的是 "2024/04/30 v4122_12"，與映像的 FSPH ImageRevision 不同格式），**已讀出但沒有佐證**，不寫。

交叉驗證（不改變任何既有結果）：Comet Lake 的 Dasharo 映像（`dasharo-protectli-vp46xx-v1.2.0`，layout 1.6、BPDT version 1、`$CPD` header version 1）用新模組讀到
FTPR.man、RBEP.man、NFTP.man 全部是 14.0.47.1558，與既有 expected 一致。那份映像原本就由舊的退路（名稱是 FTPR 的 `$CPD`）找到，新模組不會被呼叫。

## 判定規則（不猜）

只看 BPDT 的 type 2（FTPR）、1（RBEP）、7（NFTP）；分割區名稱必須對應、`$CPD` 表頭與 checksum、`<名稱>.man`、`$MN2`、版本不是 0.0.0.0 都要過。

| 情況 | 結果 |
|---|---|
| 沒有 layout table、區域開頭也不是 BPDT | `none`：呼叫端維持原來的結果 |
| 有 FTPR，版本全部一致 | found，取 FTPR.man |
| 沒有 FTPR，RBEP 與 NFTP（或兩份 RBEP）版本一致 | found，取第一個 RBEP；basis 寫「no FTPR partition, the manifests agree」 |
| 沒有 FTPR，只有一個來源 | GAP（unknown）：沒有第二個獨立來源可以佐證，不採用 |
| 讀得到的主程式 manifest 版本互相不同 | GAP：列出全部，不報任何版本 |
| 任何 BPDT 或主程式分割區不一致：越界、重疊、重複項目、名稱不符、checksum 不符、manifest 壞、壓縮旗標、項目數超過上限 | GAP：原因接在 me_note 後面 |
| 配置了但是被清成 0xFF 的 BP | 略過（不算問題）；全部都空 → GAP |

不會「退回第一個 `$MN2`」。GAP 時 me_status 維持 unknown（ATTENTION）。有 descriptor 時範圍是 ME 區域；沒有 descriptor 時 layout table 或 BPDT 要在檔案開頭，
而且新模組給 GAP 時不把 no-me-region 改成 unknown（避免檔案開頭碰巧的 0x0058 誤判成有 ME）。

上限：boot partition 5 個、每個 BPDT 48 項、每個 `$CPD` 256 項，只讀三種分割區；工作量與檔案大小無關（測試用 1.6 MB 的垃圾尾巴驗證沒有全檔掃描）。
S-BPDT 項目不往下追（沒有遞迴，也就沒有循環）。

## 限制與不確定

- 只處理 CSE 區域本身。IFWI 整個放在 BIOS 區域裡的平台（沒有獨立 ME 區域）、capsule 包著的 ME 區域、layout table 之外的配置不處理（維持原來的 unknown 或 no-me-region）。
- 新世代只有一個公開真樣本（Meteor Lake，兩個版本讀過）；layout 1.6、BPDT version 1、`$CPD` header version 1 只有 Comet Lake 一個樣本交叉驗證，其餘靠合成測資與格式說明。
- 「RBEP 與 NFTP 版本相同才採用」是依樣本的觀察（兩代樣本都符合）加上保守原則；沒有查到 Intel 文件保證 CSE 版本等於這兩個 manifest 的版本。
- layout table 與 BPDT 的 checksum 沒驗證（算法沒查到）。
- 版本字串是 manifest 的 major.minor.hotfix.build，是 CSME、TXE 還是 SPS 不猜（family 維持 unknown，沒有 cpe）。
