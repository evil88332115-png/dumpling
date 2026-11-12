# C2：vBIOS（NVIDIA 工具判定、合成 ROM、Intel legacy VBIOS 與 GOP 驅動）（分支 wp4/vbios）

M3 的 vBIOS 部分；BIOS 映像的 UEFI FV 走訪靠 C1 的 `uefi_image.py`（見「接線」一節）。只讀、不執行、不寫磁碟；輸入視為不可信。
這份是工作紀錄，不是驗證結論（驗證代理與 CI 的結果另記）。數字都是 2026-11-12 對公開樣本量的，樣本本身不進 repo。

## 檔案

| 檔案 | 內容 |
|---|---|
| `tools/cra/intel_vbt.py` | 新模組：`parse_vbt()`（從 `coreboot_cbfs.py` 搬來，行為不變）、`find_vbt()`（在一塊資料裡找 `$VBT` 並過標頭檢查） |
| `tools/cra/intel_vbios.py` | 新模組：Intel legacy VBIOS 辨識（`is_legacy_vbios`、`legacy_info`）、UEFI GOP 驅動辨識（`gop_driver`、`pe_info`） |
| `tools/cra/coreboot_cbfs.py` | `parse_vbt` 改成從 `intel_vbt` 取得（同名匯出，既有測試不變） |
| `tools/cra/x86_firmware.py` | 加 Intel legacy VBIOS 的收集／元件／狀態／markdown（見「x86_firmware 的改動」），以及 UEFI 顯示韌體的接線（`uefi_gfx_*`） |
| `tools/cra/uefi_gfx.py` | 新模組：`Scan` 子類別走訪 FV，找 GOP 驅動、獨立 VBT、含 `PCIR` 的內容（見「接線」） |
| `tools/cra/tests/test_uefi_gfx.py`、`test_uefi_image_contract.py` | 合成 FV 測試；對 C1 uefi_image 介面的契約測試 |
| `tools/cra/tests/synthetic_vbios.py` | 合成 NVIDIA option ROM 的產生器（函式與 CLI） |
| `tools/cra/tests/test_vbios_synthetic.py`、`test_vbios_intel.py` | 測試（假資料，不含真實映像的位元組）；已加進 `tests/run.d/c2-x86-firmware.sh` |
| `firmware/vbios/*/firmware.yml`、`firmware/README.md` | NVIDIA 工具的判定寫進 notes；獨立 vBIOS 維持 GAP，註明 CI 用合成 ROM |

## 1. NVIDIA DisplayPort 韌體更新工具 1.1：沒有完整 vBIOS（判定乙）

樣本：`NVIDIA_DisplayPort_Firmware_Updater_1.1-x64.exe`（14422952 位元組，sha256 見 firmware.yml，`firmware-fetch.sh` 核對通過）。
`python3 -I`、標準庫、只讀；Tiano 解壓縮是暫存裡自寫的分析用腳本，不進 repo。

- PE32+ x64、6 個區段（.text／.rdata／.data／.pdata／.rsrc／.reloc）。.data 虛擬大小約 9.7 MB，但檔案裡有內容的部分約 0.5 MB（其餘全是 0）。
  資源只有圖示、對話框、字串表、快捷鍵表、版本資訊、manifest；檔尾 10152 位元組是 security 目錄（數位簽章）。
- 內容是以 nvflash 為基礎的更新工具：OpenSSL 1.0.2l、nvflash 的 Windows 核心驅動（內嵌一個 x64 PE，存取實體記憶體用）。
- 壓縮資料：全檔掃 zlib／gzip／xz／lzma-alone／bzip2 簽章，試解（輸出上限 64 MiB）→ 只有 2 個 zlib 區塊，在資源區（圖示），內容全 0。
  沒有 7z／cab／zip／rar／LZ4／zstd 簽章。
- option ROM：全檔掃 `55 AA`（共 32 處）並檢查 0x18 指到的 `PCIR`：
  - **3 處有效**，在 .data 連續排列（檔案 offset 0x4490E0、0x4598E0、0x46B0E0）：EFI 影像（code type 3、EFI 簽章 0x0EF1、subsystem 11、
    machine 0x8664、壓縮類型 1＝EFI 標準壓縮），PCIR vendor／device 都是 0，影像長度 0x84／0x8C／0x88 個 512 bytes，之後有 NPDE。
    從 offset +0x50 起是 Tiano 壓縮資料（前 8 bytes＝壓縮大小、解壓後大小）。用暫存裡的 Tiano 解碼器解開 → 129888／138464／134528 位元組的 PE32+ x64 EFI 驅動，
    UTF-16 字串有 `nvgop-gp1xx`／`nvgop-gm2xx`／`nvgop-gmxxx`、`NVIDIA GPU UEFI Driver`、`NVIDIA Graphics Display Controller (xx.xx.xx.xx.xx)`。
    版本是 `xx.xx.xx.xx.xx` 佔位字串：這是三組 GPU 家族的 GOP **範本**，更新時由工具填入 vendor／device／版本再寫進顯示卡的 ROM。
    沒有 legacy x86 影像，沒有實際版本。
  - 之前只讀檢查看到的「vendor 0x10DE、device 0、PCIR 指標 0」兩處（offset 0x343AB8 在 .rdata、0xD1DEB8 在 .data）：是工具資料裡的結構範本，
    指標是 0，後面接的不是 ROM 內容（.rdata 那處緊接 OpenSSL 的 `Salted__` 字串與 AES 表）。其他 `PCIR`／`NPDS`／`RGIS` 出現處是 nvflash 解析 ROM 時比對簽章的常數。
  - 其餘 `55 AA` 是機器碼、表格裡的巧合。
- 版本字串：全檔沒有 `XX.XX.XX.XX.XX`（十六進位）格式的字串。
- 反向確認：對全檔 6743 個「長度欄位像 Tiano 壓縮串流標頭」的位置全部試解，解出 PE 或 option ROM 的只有上面那 3 個。

結論（乙）：工具裡沒有可確認的完整 vBIOS；x86_firmware 對這個檔案找不到 NVIDIA vBIOS（`other_roms` 也不會列：三個 EFI 影像的 vendor 是 0，不是 0x10DE）。
所以 NVIDIA vBIOS 的版本／雜湊讀取靠合成 ROM 測流程，實際檔案由負責單位提供（獨立 vBIOS 仍是 GAP）。

## 2. 合成 NVIDIA option ROM

`tools/cra/tests/synthetic_vbios.py`：legacy x86 影像（不是最後一個）＋EFI 影像（最後一個），各 1024 位元組；PCIR（vendor 0x10DE、device 預設 0xFFFE、
class 030000）、NPDE（影像長度與最後一個旗標，x86_firmware 以 NPDE 為準）、`Version XX.XX.XX.XX.XX` 字串、legacy 影像加起來 mod 256 ＝ 0。
內容是自己組的位元組，沒有 NVIDIA 的程式碼或資料，ROM 裡有 `SYNTHETIC` 字樣，沒有 PE 或可執行內容。決定性（同參數同位元組）。
CLI：`python3 -I tools/cra/tests/synthetic_vbios.py --out synthetic-nvidia-option-rom.rom [--version …] [--device …] [--no-efi]`；不跟隨 symlink 寫檔。
「看得出是合成的」靠：輸入檔名（SBOM 的 `bsi:component:filename`、`sca-center:found-in` 都記輸入檔名，請保留 `synthetic`）與 ROM 內文字。
端到端測試（`test_vbios_synthetic.py`）：合成 ROM → `pipeline/firmware-bios.sh` → 狀態 ATTENTION（沒有版本清單）→ SBOM 有 `NVIDIA VBIOS fffe`、version、
SHA-256／SHA-512、`dumpling:vuln-assessment`＝NOT_ASSESSED＋note、`dumpling:version-status`＝OK，通過 `cdx_validator()`。

## 3. Intel NUC 11（PATGL357.0059）樣本：GOP FFS 檔案裡有什麼

取得方式（暫存裡，不進 repo）：zip → `.CAP`（AMI PFAT）→ `ami_pfat.py` 的 `parse()` 取 `FV_MAIN_WRAPPER`（5562368 位元組）→ GUID-defined section
`EE4E5898-3914-4259-9D6E-DC7BD79403CF`（section 在 wrapper 的 offset 0x10C0，size 4290841，DataOffset 24）→ 資料是 LZMA alone，
標準庫 `lzma` 解出 18104336 位元組（SHA-256 `ffe4e70f…0575`）。解開後的 FV 裡，FFS 檔案 `A0327FE0-1FDA-4E5B-905D-B510C45A61D0` 在 offset 0x10DDE20
（type 0x02 FREEFORM、416616 位元組、沒有壓縮的 section）。這個 GUID 的位元組在解開的資料裡出現 5 次，其餘 4 次是別的程式碼裡的 GUID 常數、
不是 FFS 檔案頭，所以實作要走 FV／FFS，不能用位元組搜尋。

FFS 檔案裡 4 個 FREEFORM_SUBTYPE_GUID（section type 0x18）section：

| 子類型 GUID | 大小 | 內容 | SHA-256（section 內容） |
|---|---|---|---|
| `C5A4306E-E247-4ECD-A9D8-5B1985D3DCDA` | 65536 | **Intel legacy VBIOS**：`55 AA`、PCIR vendor 0x8086 device 0x0406 class 030000、code type 0、單一 x86 影像 | `da4b25ad…7d53` |
| `380B6B4F-1454-41F2-A6D3-61D1333E8CB4` | 160000 | **Intel GOP 驅動**：PE32+ x64、subsystem 11（EFI boot service driver） | `6c23a165…ddb5` |
| `50339D20-C90A-4BB2-9AFF-D8A11B23BC15` | 69120 | Intel Boot Agent CL v0.1.14 的 PXE option ROM（8086:15E2、class 020000）；不是 vBIOS | `17c4480b…3bfd` |
| `D46346CA-82A1-4CDE-9546-77C86F893888` | 121856 | Intel RAID for SATA option ROM（8086:2822、class 010400，`Intel(R) RAID for SATA - v17.3.0.4067`）；不是 vBIOS | `6b595464…6b13` |

（子類型 GUID 是這份樣本裡看到的；沒有查到官方名稱，所以只當「觀察」，不拿來當辨識條件。）

### Intel legacy VBIOS 的讀法

- ROM 開頭：`55 AA 80`（128×512＝65536 位元組）、`E9` 跳轉、+0x1E 起 `IBM VGA Compatible BIOS.`、+0x40 `PCIR`：vendor 0x8086、device 0x0406、class 030000
  （PCIR 的三個 bytes 是 `00 00 03`）、revision level 0、code type 0、indicator 0x80（最後一個）。
  PCIR 的 device 0x0406 不是任何 Ice Lake／Tiger Lake 顯示裝置的 ID，是範本值，**不拿來辨識**。
- ROM 裡的字串（offset 都相對 ROM 開頭）：
  - 0xAE0 `$VBT ICELAKE`：內嵌 VBT（vbt_header 版本 1.00、header 48、大小 3945；BDB 版本 223＝2.23）。注意這是 Ice Lake 的 VBT，不是 GOP 用的 `$VBT TIGERLAKE`
    （後者在另一個 FV，見 `docs/notes/c2-ami-pfat.md`）。
  - 0xB10 `BIOS_DATA_BLOCK `，接著一個 id 0xFE（i915 的 BDB_SKIP，VBIOS 私有區塊）的區塊，裡面是下面三行文字。
  - 0xB33 `Intel(R) ICL Mobile/Desktop PCI Accelerated SVGA BIOS`（橫幅；前面緊接 `1003`）
  - 0xB6A `Build Number: 1003 PC 14.34  11/15/2018  02:15:39`（建置編號 1003、「PC 14.34」、日期時間；欄位之間兩個空白）
  - 之後 `DECOMPILATION OR DISASSEMBLY PROHIBITED`、`Copyright (C) 2000-2011 Intel Corp. All Rights Reserved.`
- x86_firmware 的做法：version＝`1003 PC 14.34`（Build Number 行的「編號 PC 版本」），建置時間 `11/15/2018 02:15:39` 原樣記（日期順序沒有標示，只有這個樣本的 15 能推出是 月/日；
  不轉格式），橫幅記 `dumpling:vbios-banner`。Build Number 行格式不符、或有多個內容不同的行 → 版本 GAP（元件仍列出，不猜）。
- **只有這一份樣本核對過**。不同世代的 Intel VBIOS 橫幅與 Build Number 行是否同格式沒有查證。元件的 `sca-center:version-basis` 與程式說明都寫明這點。
- 這份樣本的 legacy VBIOS 是 Ice Lake 世代（2018 年建置）、放在 Tiger Lake 機器的 BIOS 裡（CSM 用）；GOP 與 VBT（TIGERLAKE）才是這台機器 UEFI 開機用的顯示韌體。

### Intel GOP 驅動的讀法

- PE：machine 0x8664、5 個區段、subsystem 11、時間戳 0、PE 標頭的 image／subsystem 版本都是 0、debug 目錄只有一項（type 13，不是 CodeView，沒有 PDB 路徑）、**沒有資源目錄**，所以沒有 PE 版本資源可讀。
- .data 裡有 UTF-16 字串：`Intel(R) GOP Driver`（offset 0x25290）、隔 0x60 位元組的 NUL 填充後 `1070`（0x25318）、`Intel(R) Graphics Controller`（0x25330）。
  三個字串都被程式碼用 `lea`（RIP 相對）引用：驅動名稱在 0x6B7，`1070` 在 0x722、0x799、0x7E2，控制器名稱在 0x7AA，每次後面接著呼叫函式。
  沒有逆向確認這些呼叫的用途（可能是註冊顯示名稱的字串），所以 `1070` 的角色靠 release notes 對照，不是靠程式碼確認。
- release notes（zip 裡的 PDF）寫 `Integrated Graphics GOP UEFI Driver: 17.0.1070`，所以 `1070` 是 build 編號。`17.0` 在 PE 裡找不到（搜過 u16／u32 的 1070 與
  常見的版本打包法，沒有結果）。
- `intel_vbios.gop_driver()` 因此回傳 `version="1070"`（只有 build 編號），`version_basis` 寫明；完整的 `17.0.1070` 只能靠 release notes（版本清單）。
- 辨識規則：EFI subsystem 的 PE（10～13）＋UTF-16 的 `Intel(R) GOP Driver\0`（2 bytes 對齊）；名稱後 0x200 bytes 內第一個非空字串必須只有數字與點（最多 4 段），否則 version 為 None（附原因）。**只對這份樣本核對過**。

## 接線：BIOS 映像的 UEFI 內容裡找 GOP、VBT、legacy VBIOS（`uefi_gfx.py`，分支 wp3/m3-gop）

走訪靠 C1 的 `tools/cra/uefi_image.py`（專案決定 D-016：不改、不複製）。`tools/cra/uefi_gfx.py` 定義 `uefi_image.Scan` 的子類別，覆寫 `scan_bytes`：
`uefi_image.parse_fvs()` 解開 FV／FFS／section（GUID-defined LZMA、CRC32、壓縮 section、嵌套 FV）後，**每一塊葉節點內容**（PE32 等 section 的內容、
LZMA 解開後不是 section 串的內容、FV 以外的位元組）都會呼叫 `sc.scan_bytes(data, module)`；子類別**不呼叫 super**（那是函式庫指紋掃描，用不到），改成：

1. `intel_vbios.gop_driver(pe)`：內容開頭是 `MZ`，或前面有 16 bytes 子類型 GUID（FREEFORM_SUBTYPE_GUID section，樣本就是這樣）時從 offset 16 起算。
2. `intel_vbt.find_vbt(body)`：只收 offset 0（或 16）的，也就是內容本身就是 VBT 的獨立檔案；嵌在別的內容裡的（legacy VBIOS 內的 `$VBT ICELAKE`）不另列。
   雜湊只涵蓋 `vbt_size` 個 bytes。
3. 內容含 `PCIR` 才呼叫 `x86_firmware.option_roms(body)` → `intel_gfx_collect(roms, body, label, store)`，label＝`<映像的位置>!uefi/<FFS GUID 或 UI 名稱>`（`UEFI_GFX_SEP`）。

`x86_firmware.inventory()` 只在 `bios_image()` 之後、同一個映像（雜湊相同）第一次出現時呼叫 `uefi_gfx_search()`（`uefi["volumes"]` > 0 才走訪），結果放 `bios[].uefi_gfx`，
缺口加進 `bios[].gaps`（SBOM 的 `sca-center:gap`）。`intel_gfx_components()` 的 parents 改成前綴比對（`loc == 映像位置` 或 `loc` 以 `映像位置 + "!uefi/"` 開頭，多個符合取最長），
所以 `a.bin` 不是 `a.bin2!uefi/…` 的父。

SBOM 元件（全部掛在 BIOS 映像底下，每個元件都有 `dumpling:vuln-assessment`＝NOT_ASSESSED 與 note、`dumpling:version-status`）：

| 元件 | version | 依據（`sca-center:version-basis`） | 備註 |
|---|---|---|---|
| `Intel GOP driver` | `gop_driver()` 的 version（build 編號，例如 `1070`）；None 時省略並標 `sca-center:gap` 與 GAP | PE 裡 `Intel(R) GOP Driver` 之後的 UTF-16 數字字串（只對一份樣本核對） | hashes SHA-256／SHA-512（PE 內容）；`sca-center:found-in`＝FFS GUID（與 UI 名稱）＋section 內容裡的 offset |
| `Intel VBT (Video BIOS Table)` | VBT header version（`1.00`） | `$VBT` header 的 version 欄位（×100）與 signature | 與 coreboot 的 VBT 元件同名同格式；BDB 版本、大小另記 |
| `Intel legacy VBIOS (option ROM)` | `Build Number: <n> PC <x.y>` | 同前（既有元件） | 同一個 ROM 的所有位置都記（整檔掃描與 FV 走訪各一） |

**位置資訊的限制**：`scan_bytes` 只給 `module`（FFS 檔的 GUID；FFS 內 UI section 在內容之前時是 UI 名稱）與內容，**拿不到 FV offset 與 section 位置**
（要改 C1 的檔才有）。所以 found-in 只寫「FFS GUID、UI 名稱（walk 結束後用 `sc.modules` 的 guid→ui_name 對回，同一個 GUID 有兩個名稱時不寫）、在 section 內容裡的 offset」。

### 完整性與 GAP（不能把沒找到說成不存在）

`result["complete"]` 只有在下面都沒發生時才是 True；不完整時 BIOS 映像元件有 `sca-center:gap`（文字都帶 `not found does not mean absent`）、狀態至少 ATTENTION：
- `sc.undecoded` 有東西（EFI 標準壓縮 section 不支援、超過 MAX_LAYER／MAX_TOTAL、嵌套比 MAX_DEPTH 深、FV 標頭不一致、FFS 大小不合理…）。
  例外：**最上層** FV 以外的非空白位元組（descriptor、ME、微碼、NVRAM…）C1 也記成 undecoded，這裡當資訊（`stats.outside_fv_nonblank_bytes`，摘要有寫），不算不完整；
  巢狀層（LZMA 解開後）FV 以外的位元組照常算不完整。
- `sc.notes`（結構警告）、`Stop`（MAX_FILES 等）、其他例外、時間上限（`OverBudget`→也記 partial）。
- 沒有 FV 的 UEFI／coreboot 映像：不走訪，記「not searched」。有 coreboot CBFS 的映像：CBFS 裡的檔案（例如壓縮的 edk2 payload）沒有展開，一律不完整。
- 去重後累計送進辨識的位元組超過 `MAX_INSPECT`（1 GiB）。
- `uefi_image.py` 載入不了：記 `not performed`，不是錯誤。

### 放大控制

同一份內容（長度＋BLAKE2b）只辨識一次（重複的內容只補記新位置；有 `PCIR` 的重複內容重跑 ROM 搜尋，總量上限 32 MiB，超過記 gap）；辨識前先用便宜條件擋
（`MZ` 開頭、`$VBT `、`PCIR`）；辨識函式本身對輸入是線性的（`find_banner`、`find_vbt` 的候選上限、`option_roms` 的既有上限）；
解壓縮炸彈由 C1 的 MAX_* 擋。測試：raw 內容滿是特徵、重複 FV、深層 LZMA、MAX_INSPECT。

### 依賴 C1 `uefi_image.py` 的內部名稱

C1 改了這些就要跟著改 `uefi_gfx.py`；`tools/cra/tests/test_uefi_image_contract.py`（`tests/run.d/c2-x86-firmware.sh` 的清單裡）會在簽章變動時紅燈，
訊息寫明「先通知 C2 和 C1」。

| 名稱 | 怎麼用 | 契約測試檢查 |
|---|---|---|
| `Scan` | 子類別化、無參數建構 | 是 class、`Scan()` 沒有參數 |
| `Scan.scan_bytes(self, data, module=None)` | 覆寫；`data` 是 bytes、`module` 是 FFS GUID 字串或 UI 名稱 | `inspect.signature`；真的跑一次合成 FV，確認子類別被呼叫、拿到葉節點內容與 GUID |
| `parse_fvs(data, sc, depth, where="image")` | `parse_fvs(bytes, sc, 0)` | 前三個參數名稱與順序、其餘有預設值 |
| `Stop` | `except uefi_image.Stop` | 是 `Exception` 的子類別 |
| `MAX_DEPTH`／`MAX_LAYER`／`MAX_TOTAL`／`MAX_FILES` | 寫進說明與測試（沒有直接讀值，測試用 `MAX_DEPTH`／`MAX_FILES` 造情境） | 存在、是正整數 |
| `Scan.undecoded`（list of `{where, reason}`）、`notes`、`modules`（`{guid, ui_name…}`）、`fvs`、`files`、`total`、`parse_errors` | 判斷完整性、統計、UI 名稱對回 | 型別；合成 FV 的 `modules` 有 guid／ui_name |
| 最上層 FV 以外位元組的 undecoded：`where == "image"`、reason 含 `outside any valid firmware volume` | 不算不完整 | 合成資料驗證；文字改了會變成「不完整」（安全的方向），測試會紅燈提醒 |

## 真樣本結果（2026-11-12，`pipeline/firmware-bios.sh`，秒數與記憶體是整個指令，含啟動）

| 樣本 | 結果 | 秒數／最大記憶體 |
|---|---|---|
| Intel NUC 11 PATGL357.0059（zip → AMI PFAT） | `Intel GOP driver` 版本 `1070`（FFS `A0327FE0-1FDA-4E5B-905D-B510C45A61D0`，section 內容 offset 0x10，160000 bytes，SHA-256 `6c23a165…ddb5`，與前面「GOP 檔案裡有什麼」一節相符）；`Intel legacy VBIOS` 版本 `1003 PC 14.34`（SHA-256 `da4b25ad…`，位置：FFS `76646656-…` 與 `A0327FE0-…`，掛在 BIOS 映像下）；獨立 VBT 3 份（`$VBT TIGERLAKE`、1.00、BDB 2.43，大小 9004／8608／8608，三個不同的 FFS，其中一個 UI 名稱 `IntelGopVbt2`）。走訪：25 個 FV、738 個 FFS 檔、解壓 25458170 bytes、去重後辨識 1327 塊（重複 938 塊）。**不完整**：30 個部分沒解開（FSP-S 與尾端資料的 EFI 標準壓縮、一個 FFS 大小不合理、一個 PAD 有內容…）與 27 個結構警告，SBOM 有 `sca-center:gap`，狀態 ATTENTION | 約 3.2 s／約 140 MB |
| Dasharo Protectli VP46xx v1.2.0（coreboot＋edk2 payload） | 沒有 GOP；VBT 只有既有的 CBFS `vbt.bin` 元件。走訪 4 個 FV（44 個 FFS，沒有壓縮）；CBFS 裡的壓縮 payload 沒展開 → 記**不完整**（不是「沒有 GOP」） | 約 0.5 s／約 58 MB |
| Ubuntu OVMF 2024.02（`OVMF_CODE_4M.fd`） | 沒有 GOP、VBT、Intel legacy VBIOS；4 個 FV、142 個 FFS，解壓 16122000 bytes，全部解開（走訪完整，已解開的內容裡沒有） | 約 0.35 s／約 79 MB |

`firmware.yml` 的 `expected` 目前沒有 GOP／VBIOS 的欄位（`pipeline/firmware-expect.py` 的 KEYS 只有 intel_me、microcode、fsp、coreboot_*、dasharo_version、edk2_revision），所以沒有加；
要加就得先擴 `firmware-expect.py`（NUC 的預期值：GOP `1070`、legacy VBIOS `1003 PC 14.34`）。

## x86_firmware 的改動（之後要跟 `wp3/ami-pfat` 合併）

只加不改的新函式（放在 `bom()` 之前）：`intel_gfx_collect()`、`intel_gfx_components()`、`intel_gfx_status()`、`intel_gfx_markdown()`。
既有函式裡的插入（每處 1～4 行）：

- `inventory()`：`vb, other, bios = {}, {}, {}` 下一行加 `intel_vb = {}`；`for r in roms:` 前一行加 `intel_gfx_collect(roms, data, label, intel_vb)`；
  回傳的 `inv` 加一個鍵 `"intel_vbios"`（接在 `"vbios"` 之後）。**迴圈本身沒動。**
- `components()`：`return comps, deps` 前一行加 `intel_gfx_components(inv, comps, deps)`。
- `status_of()`：「沒有 NVIDIA vBIOS 或 BIOS」的條件加 `and not inv["intel_vbios"]`；`if inv["skipped"]:` 前加 `att += intel_gfx_status(inv)`；`detail` 加 Intel legacy VBIOS 個數。
- `markdown()`：vBIOS 一節之後加 `L += intel_gfx_markdown(inv)`。
- 檔頭說明加一段 Intel legacy VBIOS。

沒有碰 `bios_image()`、`inputs()`、PFAT 相關段落。
