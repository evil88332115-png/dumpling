# AMI PFAT 解封裝：格式依據與公開樣本觀察（C2）

分支 `wp3/ami-pfat`。程式在 `tools/cra/ami_pfat.py`，`tools/cra/x86_firmware.py` 只加一個 hook。
這份是給後面的 PR（M3 的 Intel GOP／VBT、BIOS 內容解析）用的筆記；數字都是對公開樣本 Intel NUC 11 PATGL357.0059
（`firmware/bios/intel-nuc11-patgl357-0059/firmware.yml`）量的，樣本本身不進 repo。

## 格式依據

- 欄位位置與意義核對自 platomav/BIOSUtilities 的 `biosutilities/ami_pfat_extract.py`（結構 `AmiBiosGuardHeader`、`IntelBiosGuardHeader`、
  `IntelBiosGuardSignature*`）與 `common/patterns.py` 的 `PAT_AMI_PFAT`。只讀原始碼，沒有執行、沒有複製程式碼。
  該專案授權文字是 BSD-2-Clause-Patent 型條款（Copyright (c) 2019-2025 Plato Mavropoulos；GitHub 偵測不到 SPDX 標籤），
  這裡只引用欄位位置的事實描述，並在 `ami_pfat.py` 檔頭寫明出處。
- 用公開樣本核對過（見下面），不是只照原始碼猜。
- 結構（小端，偏移相對封裝開頭 P；P＝`_AMIPFAT` 標記位置 − 8）：
  - P+0 `Size` u32（標頭總長）、P+4 `Checksum` u32（用途不明，不使用）、P+8 `_AMIPFAT`、P+0x10 `Flags` u8（樣本是 0x63，用途不明，只記錄）。
  - P+0x11 起到 P+Size 是 UTF-8 文字：第 1 行 `AMI_BIOS_GUARD_FLASH_CONFIGURATIONS`（可接 `II` 加每個檔案 4 位十六進位的 flash 順序），
    之後每行 `<flags> <param> <count>;<name>`，一行一個檔案、`count` 個 block。
  - 接著是連續的 block，依檔案行順序。每個 block：0x30 位元組 Intel BIOS Guard header（BGVer、PlatformID[16]、Attributes（bit0＝SFAM）、
    ScriptVer、ScriptSize、DataSize、BIOSSVN、ECSVN、VendorInfo）、script（8 位元組 opcode，begin 開頭、end 結尾）、資料；
    SFAM 為 1 時再接簽章區（8 位元組標頭 + RSA-2048：516 位元組，或 RSA-3072：772 位元組）。
  - 最後一個 block 之後是尾端資料（OOB）。
- 不驗證簽章；script 只檢查長度與 begin／end，不解讀。

## 公開樣本 PATGL357.0059.CAP 的實際結構

- zip 裡 4 個 `.CAP`／`.cap`（Linux、UEFI、F7、Recovery）內容完全相同，原檔 SHA-256
  `7e6601ad25d99ac4cbf93c05b1ff1357aa2a69cf2842510e0f02fe7cda7a154d`（26279936 位元組）。
- 封裝標頭 579 位元組、沒有 `II` 順序欄位、21 個檔案（NVRAM、NVRAM_BACKUP、GPNV、OA_TABLE、FV_OEM_LOGO、FV_MAIN_WRAPPER（6 block）、
  FV_NETWORK_WRAPPER（4）、FV_BB_AFTER_MEMORY_WRAPPER、FV_FSP_S／M／T、FV_BB、FV_DATA、FV_DATA_BACKUP、FV_BB1、FV_BB1_BACKUP 與 4 個 `*_BACKUP`），
  共 29 個 block，每個 block 都有簽章（RSA-2048），BIOS Guard 版本 2.0、平台 ID `TIGERLAKE`、BIOS SVN 0x57000。
- 區段資料加起來 17235968 位元組，尾端資料 9012161 位元組（開頭是 0xFF 填充，後面是含 firmware volume 的資料）。
  組回的映像（區段依清單順序 + 尾端）26248129 位元組，SHA-256 `c71bc09831bbb690acd48cbe441c6b68818c5a5c54ef98fc87173f75f972949c`。
- **這不是 SPI 位址對應的映像**：每個區段是獨立的 FV／NVRAM 區域，封裝沒有給 flash 位址（script 沒解讀），所以 FIT（在 4 GB 下方）找不到、
  沒有 flash descriptor、沒有 ME 區域。這是 BIOS 區域更新，不含 ME；ME 版本只能從 release notes 看到（15.0.56.2834），映像裡沒有。

## 本機真實樣本驗證（`pipeline/firmware-bios.sh` 對 zip）

- 狀態行：`FIRMWARE-BIOS ATTENTION vBIOS 0 個、BIOS 映像 1 個；…沒有 flash descriptor；42 個壓縮的 UEFI section 沒有解析…；沒有版本清單（無法核對）`，
  退出碼 2。4 個相同 CAP 去重成一個 BIOS 元件（4 個位置都記在 locations）；`EBU.EXE`（Windows 一鍵刷新）沒有解析。
- ME：no-me-region（沒有 ME 區域、沒有 `$FPT`、沒有 FTPR 的 `$CPD`）。
- 微碼（2 份）：CPUID `000806C2` platform 0xC2 revision 0x16（2021-04-07）、CPUID `000806C1` platform 0x80 revision 0xBE（2025-07-24）。
  in FIT 都是 unknown（FIT 不適用）。release notes 列的微碼是 `M80806C1_000000BE`，與第二份相符；第一份 release notes 沒列。
- IBV：AMI（明文字串沒有；是由 PFAT 封裝本身判定，SBOM `sca-center:ibv-hint`＝AMI）。
- UEFI：22 個 firmware volume、237 個 FFS 檔案、568 個 section；壓縮 section：efi-standard 35、lzma 7，其餘沒有（沒有 brotli、沒有 GUID 不認得的）。
- Dasharo VP46xx v1.2.0 回歸：ME 14.0.47.1558、3 份微碼 0xF8，SBOM 與改動前位元組相同。

## 給 GOP／VBT 的觀察（只記錄，沒有實作）

- 解開 PFAT 後，**明文（未壓縮）的組回映像裡沒有 `$VBT`，也沒有 Intel GOP 的名稱**（ASCII 與 UTF-16 的 `IntelGop`、`GopDriver` 都沒有；
  `GOP` 只有 3 個隨機位元組命中）。要找得先解壓。
- 壓縮方式：
  - 主要 FV（`FV_MAIN_WRAPPER`，封裝裡 6 個 block、5562368 位元組）是一個 **LZMA** GUID-defined section（GUID `EE4E5898-3914-4259-9D6E-DC7BD79403CF`），
    標準庫 `lzma`（FORMAT_ALONE，13 位元組標頭）解得開，解開後 18104336 位元組、內含 32 個 `_FVH`（巢狀 FV）。
  - `FV_BB_AFTER_MEMORY_WRAPPER`（含 `*_BACKUP`）、`FV_NETWORK_WRAPPER`、`FV_OEM_LOGO` 也是 LZMA。
  - **efi-standard（Tiano）**：`FV_FSP_S` 與 `FV_FSP_S_BACKUP` 各 13 個、尾端資料 9 個（合計 35），標準庫沒有解碼器。
- Intel GOP：在主要 FV 解壓後的 FFS 檔案 `A0327FE0-1FDA-4E5B-905D-B510C45A61D0`（type 0x02 FREEFORM，約 407 KB，內部 section 沒有再壓縮）。
  裡面是 4 個 FREEFORM_SUBTYPE_GUID（0x18）section：3 個 `55AA` option ROM（字串有 IBM VGA…、UNDI、Intel(R) RAID…）和 1 個 PE32+ x64
  （subsystem 11＝boot service driver，UTF-16 字串 `Intel(R) GOP Driver`、`Intel(R) Graphics Controller`，旁邊有 `1070`）。
  release notes 寫 Integrated Graphics GOP UEFI Driver 17.0.1070；版本字串怎麼從 PE 讀要在 GOP 的 PR 確認，這裡沒有核對。
  所以 GOP 在 **LZMA 解開之後、不需要 Tiano 解碼器** 就拿得到。
- VBT：`$VBT TIGERLAKE` 在 `FV_BB_AFTER_MEMORY_WRAPPER`（LZMA，解開後 495632 位元組）裡，檔案 UI 名稱 `IntelGopVbt2`；有 3 份
  （VBT 總長 8608、9004、8608 位元組；header 版本欄位 u16@0x14＝100，header 長度 48）。備份那份（`FV_BB_AFTER_MEMORY_BACKUP`）解開後位元組完全相同，所以 `$VBT TIGERLAKE` 在映像裡出現在兩個位置（各 3 份）。
  主要 FV 解壓後另有 2 份 `$VBT ICELAKE`（總長 3945）和一個內容不是 VBT 的命中，要用 header 檢查過濾（`$VBT ` 後接平台名稱、20 位元組標頭）。
- 結論：下一個 PR 做 GOP／VBT 只需要「GUID-defined LZMA section 解壓（標準庫）+ 走 FV／FFS／section」，不需要 Tiano 解碼器；
  但 FSP-S 與尾端資料的 efi-standard 內容（可能有 FSP 版本等）仍然看不到。

## 還沒做或不確定

- 封裝 script 沒解讀，所以拿不到每個區段在 SPI flash 的位址（FIT、`$FPT` 位置、ME 區域因此不適用）。
- `Checksum`、`Flags` 欄位意義不明，只記錄。
- 簽章不驗證（記在 SBOM `dumpling:pfat-signature`＝`not verified` 與 inventory 的 notes）。
- 簽章區長度：標頭第 1 個 u32 是 1／2／3 時照對照表；其他值用「下一個 block header 標記的位置」推，推不出來就當錯誤（公開樣本都是 1，沒遇過其他值）。
- `EBU.EXE`（Windows 一鍵刷新）沒有解析；ME 更新檔是否在裡面沒有查證。
