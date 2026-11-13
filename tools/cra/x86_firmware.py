#!/usr/bin/env python3
"""x86 產品的 BIOS 與顯卡 vBIOS：只讀解析版本與雜湊，和 BIOS／顯卡團隊填的版本清單互相比對。

用法：
  python3 -I x86_firmware.py inventory --in <檔案｜資料夾｜.zip> [--in …] [--manifest <版本清單.csv>] --out <資料夾>
  輸出 <資料夾>/fw-inventory.json（解析結果與比對）、<資料夾>/fw.cdx.json（CycloneDX 1.6 的韌體元件）、
  <資料夾>/fw-inventory.md（給人看的 BIOS 元件版本與 vBIOS 摘要，內容同 JSON），stdout 一行 `FW-INVENTORY<TAB>OK|ATTENTION|GAP|FAIL<TAB>說明`。

輸入是不可信資料（官網下載的更新包、廠商或團隊提供的映像）：
- 只讀；**不執行**任何東西（更新包裡的 .exe、.efi、.nsh 都只當資料讀），不解開到磁碟。
- 資料夾不跟隨符號連結；ZIP 只讀一般檔案成員到記憶體，宣告大小與實際讀到的都有上限（MAX_FILE），不展開巢狀壓縮檔（記在 skipped）。
- 上限：單檔 MAX_FILE、全部輸入（含 ZIP 成員解壓後）MAX_TOTAL、時間 TIME_LIMIT（--time-limit）、每個檔案的 microcode checksum 總量
  MAX_CHECKSUM。超過的檔案或部分記下來（ATTENTION），不會中斷其他檔案。損壞的 ZIP 成員（zlib、lzma、CRC 錯誤）只略過那個成員。
  fw-inventory.json 的 skipped：完全沒有解析的檔案，或內容沒有展開的壓縮檔（巢狀壓縮檔、讀不了的 ZIP；這兩種檔案本身的 bytes 仍當一般資料掃過，
  裡面的檔案沒有）；partial：讀進來、解析到一半的檔案（中途超時、達到上限、某一段失敗）。狀態的數字兩邊都以檔案數計。

vBIOS（NVIDIA；例如更新包裡 nvflash 加內嵌 ROM 的 .exe，或直接的 .rom）：
- 找 PCI option ROM：0x55AA 開頭、0x18 指到 "PCIR" 結構（vendor、device、影像長度 ×512、code type、最後一個影像的旗標），
  串起同一組的影像（legacy、EFI…）當一個 ROM。NVIDIA 的影像有 NPDE 延伸時，影像長度與「最後一個」旗標以 NPDE 為準（nouveau 的做法）。
  鏈沒有正常結束（還沒標最後一個、下一個位置卻不是有效影像 → invalid-next-image；影像長度超出檔案 → truncated）→ vBIOS 會 ATTENTION，
  SBOM 元件加 sca-center:rom-terminated、sca-center:incomplete（雜湊可能不完整）。
  PCIR 屬於哪個影像開頭（前方或標頭裡雜散的特徵碼不算；細節見 ImageStarts）：0x18 指標正好指到它、自己也是合法影像的開頭、
  而且不在已經接受的 ROM 範圍裡的才是候選。選離 PCIR 最近的；最近的影像鏈在檔案裡就斷了、另一個候選的鏈正常結束時改選那個
  （鏈的檢查：每條最多 64 個影像、最近的之外最多再試 8 個候選、每個檔案總共 MAX_CHAIN_CHECK 個影像，用完記在 partial，
  之後有多個候選的選擇都記 start_note）。只有一個候選，或選的是最近的、標頭第 2 個 byte（影像大小）和 PCIR／NPDE 長度唯一相符、
  而且鏈的檢查沒有用完時，不加說明；其他情況記 start_note（vBIOS ATTENTION，SBOM 元件加 sca-center:note）。
  開頭不確定的 ROM 之後從它最後一個影像之後重找（它的範圍可能蓋到下一個 ROM），開頭在它範圍裡的 ROM 也記 start_note；
  選定的開頭被別的 ROM 蓋過、這個 PCIR 最後沒有任何 ROM 時，記在 partial（選定的開頭已經是接受的 ROM 鏈裡的影像開頭的不算，
  只是落在別的 ROM 範圍裡仍然記；逐一列出最多 MAX_LOST_NOTES 個，其餘合成一筆）。仍然可能靜默的情況：分不出來的巧合——
  兩個候選的鏈都正常結束，而且最近的（雜散的）剛好是唯一大小相符的（真 ROM 標頭的大小欄位不符時）；這時雜散開頭的範圍
  如果蓋到緊接著的下一個 ROM 的開頭，下一個 ROM 也不會回報（先前的版本也一樣）。另外，構造的排法讓雜散的開頭剛好落在已接受 ROM 的
  影像鏈上（被當成已經用掉）時，也可能藏住一個 ROM（先前的版本也一樣）。開頭確定、正常結束的 ROM 宣告的長度蓋到下一個真 ROM 的開頭時，
  下一個 ROM 從它的結尾之後才找，會靜默不見（先前的版本也一樣）。
  每個檔案線性掃一次特徵碼，已接受的 ROM 範圍不掃（不是平方時間，記憶體不隨檔案成長）。
  沒有正常結束或開頭不確定的 ROM 每個檔案合計最多 MAX_BROKEN_ROMS 個，超過就不再找，檔案記在 partial（解析到一半，ATTENTION）。
  vendor 0x10DE、而且有 x86（code type 0）或 EFI（3）影像的才算顯卡 vBIOS。
  只有其他類型（例如 0xE0 NVIDIA 韌體）的是燒錄工具自帶的映像：列在 other_roms（裝置 ID、雜湊、found_at 的檔案與位置），不是產品元件、不進 SBOM。
- Intel legacy VBIOS（vendor 0x8086、PCIR class code 0x03xxxx、有 x86 影像；細節與樣本依據見 intel_vbios.py）：列在 inv["intel_vbios"]，
  version＝ROM 裡 `Build Number: <n> PC <x.y> …` 行的「n PC x.y」（沒有或格式不符 → 版本 GAP），橫幅、建置時間、內嵌 VBT 另記；
  SBOM 元件掛在所在的 BIOS 映像底下（檔案本身是 BIOS 映像時）。UEFI GOP 驅動的辨識函式在 intel_vbios.gop_driver()，由 BIOS 映像的 UEFI 走訪呼叫（見下面「UEFI 內的 Intel 顯示韌體」）。
- 版本：ROM 範圍內第一個 `XX.XX.XX.XX.XX`（十六進位）字串。ROM 範圍外的不算（nvflash 自己的表格也有同格式的字串）。
- 同一個 ROM（雜湊相同）在多個檔案出現時記一次、列出所有位置；不同板型的 ROM 各自一個元件。BIOS 映像也一樣依雜湊去重。

BIOS（Intel 平台的完整 SPI 映像）：
- Intel flash descriptor（0x10 的 0x0FF0A55A）→ 區域表（FLMAP0 → FRBA，每個區域的起訖與雜湊）。
- CSME／ME／TXE 版本（`$MN2` manifest header：vendor 0x8086、+0x24 的 major.minor.hotfix.build、+0x14 的 BCD 日期）：
  ME 區域開頭（或 +0x10）的 `$FPT` 分割區表 → FTPR 那一項的範圍 → 開頭是 `$CPD`（ME 11 以後）就取目錄裡 FTPR.man 那一項，
  不是（ME 10 以前）就是分割區開頭的 manifest（basis「FTPR partition ($FPT…)」；+0 的表壞了再試 +0x10）。沒有 `$FPT` 或 FTPR 拿不到時
  退回舊的做法，但只接受前面最近的 `$CPD` 名稱是 FTPR 的 manifest（原因記在 me_note）；沒有 `$CPD` 指出 FTPR → unknown（「第一個
  `$MN2`」可能是別的分割區，候選版本只記在 me_note）。其他分割區的不同版本另列（other_versions）。`$MN2` 每個範圍最多記 MAX_MN2 個。
  me_status 分三種：found；no-me-region（descriptor 沒有 ME 區域，或沒有 descriptor、也沒有任何 ME 的結構）；
  unknown（有 ME 的結構，但沒有可用的 manifest → ATTENTION）。沒有 descriptor 時（見 me_info）：有 FTPR 那一項的 `$FPT`
  → 照上面解析（在 0／0x10 是單獨的 ME 更新檔，後面的例如 capsule，basis 寫明）；沒有 → 名稱是 FTPR 的 `$CPD` 目錄的 FTPR.man
  （CSME 12 以後：$FPT 在 +0x1000、沒有 FTPR 那一項）；都拿不到但有表頭像真的 `$FPT`、FTPR 的 `$CPD` 或候選數用完 → unknown；
  只有雜散的標記仍是 no-me-region。有兩個以上版本不同的 FTPR manifest（例如 capsule 裡兩個 ME 映像）時報第一個，
  me_conflict 列出全部、ATTENTION。沒有 ME 區域的檔案裡零散的 `$MN2`
  不當成 CSE 版本（只記在 me_note）。新世代的配置（CSME 18 這類：區域開頭是 CSE layout table，`$FPT` 只在 data partition、沒有 FTPR 那一項）
  上面的做法都拿不到、結果是 unknown 時，再走 intel_cse_layout.py：layout table → BP 的 BPDT → FTPR（type 2）、RBEP（1）、NFTP（7）三種分割區的
  `$CPD` → `<名稱>.man` 的 `$MN2`；有 FTPR 取它，沒有就要 RBEP 與 NFTP 兩種類型各至少一份、版本相同才採用（同一類型的拷貝不算獨立來源）（basis「BPDT (CSE layout table …): …」），
  讀得到的版本互相矛盾、結構不一致、只有一個來源 → 維持 unknown（原因接在 me_note）。上面的做法有結果時完全不動。沒有 descriptor 時
  layout table 或 BPDT 要在檔案開頭。格式與出處見 intel_cse_layout.py、docs/notes/c2-csme-layout.md。是 CSME、TXE 還是 SPS 不猜（family unknown），版本清單 me 列的 identifier 寫了、而且那一列的版本相符才帶；SBOM 的 ME 元件的 cpe：清單寫明 CSME，或映像讀不出 family 但 major 版本在 11～30（NVD 上 TXE、SPS 的版本都低於 11；推定寫在 dumpling:cpe-basis，比對結果待人審）才帶，版本只放前三段（見 CSME_CPE、csme_cpe_info）；清單寫 ME／TXE／SPS、版本不是三段以上的數字、major 在 11～30 以外且 family 不明時不填，原因在 dumpling:cpe-gap。
  格式依 me_cleaner、MEAnalyzer 的結構定義（只讀它們的原始碼核對欄位位置，沒有用它們的程式）。
- 公告比對（fw_advisory.py，離線）：每份 Intel 微碼對 tools/cra/data/intel-microcode-releases.json（Intel 公開的微碼發佈說明，由 intel_ucode_releases.py 產生）
  比對，結果記在 inv["bios"][i]["microcode"][j]["advisory"]、SBOM 的 dumpling:advisory-* property 與 fw-inventory.md 的「公告比對」一節；
  規則與限制見 fw_advisory.py 檔頭與 docs/notes/c2-firmware-advisory.md。結果是候選，不是漏洞判定；dumpling:vuln-assessment 仍是 NOT_ASSESSED。
- CPU microcode：Intel microcode header（header version 1、loader revision 1、BCD 日期、CPUID、platform id、大小），
  先檢查 header 欄位再算整份 checksum（為 0 才算）；每個（CPUID、platform id）一列；extended signature table 的 CPUID 另外記。
  全檔掃描照舊（找 FIT 沒列的備援或 OS／UEFI 階段才載入的）；另外讀 FIT（見 fit_table）：每份 microcode 記 in_fit
  （重置時 CPU 會載入的那幾份；true／false，FIT 沒找到或不能用時是 null＝不知道）。FIT 指到的位置不是有效 microcode → incomplete。
  認出 AMD 平台（Embedded Firmware Structure，或兩種不同的 PSP／BIOS 目錄 cookie）時：Intel 格式的 microcode 清單不適用（不是「沒有 microcode」），
  改交 amd_psp.py 解析（見下面「AMD 平台」）。有 Intel descriptor 或 Intel microcode 時不判斷；NVIDIA vBIOS 更新包裡只有 AMD 標記時不當成 BIOS 映像。
  這個辨識規則的代價（都不會靜默）：只有一種 cookie 的 AMD 檔案（例如 capsule 標頭讓 EFS 不在固定位置、只剩一種 cookie，或兩個都是 $PSP）
  認不出來，沒有其他結構時是 GAP；構造的情況：AMD 映像裡剛好有一份 checksum 對的 Intel 格式 microcode → platform 不是 amd，
  沒有 microcode 的 Intel BIOS 區域檔在 0x20000 剛好是 0x55AA55AA → 誤判 AMD；兩種都是 ATTENTION。
- AMD 平台（解析在 amd_psp.py，格式與出處見該檔檔頭與 docs/notes/c2-amd-psp.md；結果在 bios[].amd）：EFS（每個 16 MiB 視窗各找、容許 capsule 標頭造成的位移）
  → PSP 目錄（L1 `$PSP`、L2 `$PL2`、combo `2PSP`）與 BIOS 目錄（`$BHD`、`$BL2`、`2BHD`）→ 每個項目的 type、subprogram、instance、位置、大小；
  PSP 韌體標頭（fw_type 與 size_total 和目錄項目相符）通過才讀版本，BIOS 目錄 type 0x66 的 AMD 微碼列 patch level、日期、equivalence id
  （前面有 `DMA\\0` container 的等價表才對出 CPUID，沒有就不猜），AGESA 字串（`AGESA!V<n>` 後面的字串，整個映像與解開的 firmware volume 都找，不同值全部列出並 ATTENTION）。
  看不懂的（未知 type、版本欄位無法驗證、checksum 不符、超出範圍、指標找不到目錄、範圍重疊、循環、超過上限、壓縮或 size 0 的條目、slot header checksum 不符、
  Promontory 指標、AGESA 搜尋不完整或字串被截斷）一律進 b["gaps"]（SBOM 的 sca-center:gap）與 amd.problems；checksum 不符（或沒有完整解析）的目錄不採用它的條目，只經由它到得了的子目錄也不採用（untrusted-path）；
  指標在兩種座標解讀下都指到目錄（或同一個位置被不同基底讀到）時，兩邊都列出並各自做結構檢查：只有結構上的正面證據（checksum 不符、位址或範圍超出檔案、指標沒指到目錄…）才算不通過；
  每一種都完整檢查過而且恰好一邊通過就採用它、另一邊標「未採用」（rejected，附證據）；兩邊都通過而內容相同 → 都採用；都通過但內容不同、都沒通過、有任何一邊無法判斷（工具的限制：上限、不解的 address mode、超時…）、
  或碰到上限／循環／超時 → 全部維持歧義，不判斷哪個是硬體實際使用的，只經由它到得了的目錄的條目、版本、微碼（amd.ambiguous）不進 SBOM。
  SBOM：有版本的 PSP 韌體條目、AMD 微碼 patch、AGESA 字串各一個元件（掛在 BIOS 映像底下），dumpling:vuln-assessment 同樣是 NOT_ASSESSED（note: ASSESS_NOTES["amd"]）。
  amd_psp 載入不了或丟錯 → b["amd"] 是 None，gaps 寫「parser did not run」。
- coreboot 類映像（例如 Dasharo）的 CBFS（見 coreboot_cbfs.py）：找到 FMAP（或 `LARCHIVE`）的 CBFS 區域時，讀 `revision`／`build_info`
  （coreboot 版本、git 修訂、建置時間）、`config`（關鍵設定欄位與雜湊）、FSP（`FSPH` 標頭的 ImageRevision、M／S 類型）、`vbt.bin`（`$VBT` 版本）、
  SELF payload（身分與雜湊，不展開裡面的 firmware volume）。每個 CBFS 區域（RO、RW_A…）分開記，相同內容只記一次、列出所有位置。
  CBFS 結構壞掉、壓縮解不開、超過解壓縮上限 → 記在 incomplete（ATTENTION），不影響其他部分。沒有 CBFS（例如 OVMF）時什麼都不加。
  microcode 在 `cpu_microcode_blob.bin` 裡時加 found-in（不重複產元件）。
- UEFI 內的 Intel 顯示韌體（uefi_gfx.py，走訪靠 C1 的 uefi_image.py：FV／FFS／section、LZMA、嵌套 FV 都會解開）：映像有未壓縮的 firmware volume 時，
  找 Intel GOP 驅動（intel_vbios.gop_driver）、獨立 VBT（intel_vbt）、legacy VBIOS option ROM（掛在 `<映像位置>!uefi/<FFS GUID>` 位置）；
  結果在 bios[].uefi_gfx，SBOM 元件掛在 BIOS 映像底下。沒解開的部分（EFI 標準壓縮等）、FV 結構警告、coreboot CBFS、上限、走訪失敗、uefi_image.py 載入不了
  → 記 sca-center:gap 與狀態 ATTENTION（沒找到不代表不存在）。細節與依賴的 uefi_image 內部名稱見 docs/notes/c2-vbios.md。
- IBV 線索：BIOS 區域裡未壓縮的字串（AMI：American Megatrends、ALASKA；Insyde：InsydeH2O；Phoenix）。只是線索，以版本清單為準。
- UEFI 壓縮統計（**不解壓**，見 FvStats）：走未壓縮的 firmware volume／FFS 檔案／section，依壓縮方式計數（efi-standard、lzma、
  lzma-f86、brotli、tiano-custom，其他需要處理的 GUID-defined 依 GUID），記在 uefi 與 GAP（「N 個壓縮 section 沒有解析」）。
  工具知道自己略過了這些內容，所以有壓縮 section 或需要處理、GUID 不認得的
  GUID-defined section（例如簽章）時狀態至少 ATTENTION（不能顯示完整）；結構不對的記在 uefi.notes（數量可能偏少），
  達到上限記 incomplete（ATTENTION）。
- 拿不到（壓縮的 firmware volume 裡）：IBV 核心版本、UEFI 模組清單、FSP、EC → 標「只有版本清單、映像無法核對」，等第 2b 步。
- 沒有 descriptor（capsule 或只有 BIOS 區域的檔案）→ 仍掃 microcode、`$FPT`、FIT（檔尾對到 4 GB），狀態 ATTENTION。

AMI PFAT（AMI BIOS Guard 封裝，例如 Intel NUC 的 .CAP；解封裝在 ami_pfat.py）：每個輸入檔的 bytes 在解析前先偵測 `_AMIPFAT`，
有的話把 block 資料依封裝順序組回映像（只在記憶體），之後照常解析；BIOS 映像記 pfat（原檔雜湊、組回雜湊、檔案清單、說明）。不驗證簽章。
組回的映像是各區段（firmware volume、NVRAM…）依封裝順序串接再接封裝尾端資料，不是 SPI 位址對應的映像（封裝裡的 script 沒有解讀）。
解不開（格式不認得、截斷、長度矛盾）→ 該檔記在 partial（ATTENTION），原 bytes 照一般資料掃過。

SBOM 的 dumpling: property（每個元件都有）：
- dumpling:vuln-assessment＝NOT_ASSESSED、dumpling:vuln-assessment-note＝原因。這個工具不比對漏洞：Intel ME／microcode 是「Intel 公告無法機器比對，
  需公告對照」，NVIDIA vBIOS 是「漏洞靠 NVIDIA 合作夥伴通知，工具只確認版本與雜湊」；BIOS 映像與其他區域是「這一層沒有漏洞比對」。
- dumpling:version-status＝OK（元件有 version，是映像或版本清單來的）或 GAP（讀不到：version 省略，不留空、不猜）。
- 既有的 sca-center: 命名空間 property 不變。

版本清單（CSV，UTF-8；範本 tools/cra/data/fw-manifest-template.csv）：一個元件一列，product 以 # 開頭的列（範例）不讀。欄位：
  product, firmware, firmware_version, component, identifier, version, date, vendor, note
  component：bios（整個映像；identifier 留空）、ibv-core、me、fsp、agesa、psp、microcode（identifier＝CPUID）、ec、gbe、module（identifier＝模組名稱）、
  vbios（identifier＝PCI device ID）、vbios-base（NVIDIA 給的基礎版本）。不知道就填「不知道」，不要空著。
  microcode 的 identifier 可以寫成 CPUID/platform id（例如 000906EA/0x22），只比那個 platform id；只寫 CPUID 就比所有 platform id。
  比對：一致 match、不一致 mismatch、只有清單 declared-only（verifiable=false 表示映像目前拆不出這個元件）、只有映像 extracted-only。
  **逐份比對**：每個解析出來的映像（不同雜湊）都要對到清單上的某一列；某一份符合不能蓋掉另一份（另一份列成 mismatch）。
  ME 版本可以只填到 hotfix（16.1.30 對 16.1.30.2307）。mismatch 或可核對卻只有一邊 → ATTENTION（「待確認」）。
  清單的 firmware_version 只有一個（不是「不知道」）、而且只有一個完整 SPI 映像時，才當成那個映像的版本（version-basis 記來源）。

狀態：FAIL（輸入讀不到、輸出寫不進去、版本清單格式錯；會刪掉 --out 裡上一次的輸出；參數錯誤也是，退出碼 64：
包括 --time-limit 不是大於 0 的有限秒數；參數不接受縮寫）；
GAP（沒有找到任何 vBIOS 或 BIOS 結構，包括全部檔案都因上限或損壞被略過）；
ATTENTION（沒有 descriptor、版本對不上、清單有「不知道」、檔案略過、超過上限沒解析完、區域超出檔案、vBIOS 開頭不確定、
ME 版本 unknown、FIT 不能用或指到無效的 microcode、AMD 平台有 GAP 或要確認的項目（見上面）、有壓縮或 GUID 不認得的 UEFI section 沒有解析、有不同版本的 FTPR manifest）；OK。FAIL 時刪掉的輸出包括 fw-inventory.md。
"""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
import lzma
import math
import os
import re
import stat
import struct
import sys
import time
import uuid
import zipfile
import zlib
from pathlib import Path

MAX_FILE = 512 << 20                   # 單一檔案（或 ZIP 成員）讀進記憶體的上限
MAX_TOTAL = 4 << 30                    # 這次執行全部輸入（含 ZIP 成員解壓後）讀進來的總量上限
TIME_LIMIT = 900                       # 秒；超過後剩下的檔案不解析（ATTENTION）
MAX_CHECKSUM = 256 << 20               # 每個檔案驗 microcode checksum 的總量上限（刻意構造的大量候選）
MAX_BROKEN_ROMS = 64                   # 每個檔案沒有正常結束的 option ROM 上限（每個都從最後一個影像之後重找、重算雜湊，構造的輸入會是平方級）
MAX_LOST_NOTES = 8                     # 每個檔案逐一列出「PCIR 沒有變成 ROM」的上限，其餘合成一筆（構造的輸入可以有幾十萬個）
MAX_CHAIN_CHECK = 1 << 16              # 每個檔案為了選 PCIR 的影像開頭（ImageStarts）試串影像鏈的影像總數上限；用完記在 partial，之後的選擇都記 start_note
REF = "sca-center:fw:"
OUTPUTS = ("fw-inventory.json", "fw.cdx.json", "fw-inventory.md")   # FAIL 時三個都刪掉
NVIDIA_VID = 0x10DE
VBIOS_CODE_TYPES = {0: "x86", 3: "EFI"}   # 含這兩種影像之一的 ROM 才算顯卡 vBIOS；只有 0xE0（NVIDIA 韌體）等的是燒錄工具自帶的其他映像
FIRMWARE_IMAGE = ("executable", "no archive", "unstructured")      # BSI TR-03183-2 表 7 的韌體映像
BSI_FLAGS = ("bsi:component:executable", "bsi:component:archive", "bsi:component:structured")
VBIOS_VER = re.compile(rb"(?<![0-9A-Fa-f.])([0-9A-F]{2}(?:\.[0-9A-F]{2}){4})(?![0-9A-Fa-f.])")
FD_SIG = b"\x5a\xa5\xf0\x0f"           # 0x0FF0A55A（little endian）
REGION_NAMES = {0: "descriptor", 1: "bios", 2: "me", 3: "gbe", 4: "pdr", 5: "devexp", 6: "bios2", 8: "ec", 9: "devexp2",
                10: "ie", 11: "10gbe-a", 12: "10gbe-b", 15: "ptt"}
IBV_HINTS = (("AMI", (b"American Megatrends", b"ALASKA")), ("Insyde", (b"InsydeH2O", b"Insyde Software")),
             ("Phoenix", (b"Phoenix Technologies", b"SecureCore")))
ARCHIVES = ((b"PK\x03\x04", "zip"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"), (b"MSCF", "cab"),
            (b"\x1f\x8b\x08", "gzip"), (b"\xfd7zXZ\x00", "xz"))
DOC_EXT = (".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp")   # 更新包裡的文件：ZIP 格式但不是要展開的壓縮檔
ME_FAMILIES = ("CSME", "ME", "TXE", "SPS")   # 版本清單 me 列的 identifier 可以寫這些（映像分不出來，不猜）
COMPONENTS = ("bios", "ibv-core", "me", "fsp", "agesa", "psp", "microcode", "ec", "gbe", "module", "vbios", "vbios-base")
EXTRACTABLE = {"me", "microcode", "vbios"}          # 目前映像拆得出來、可以核對的
MANIFEST_COLS = ("product", "firmware", "firmware_version", "component", "identifier", "version", "date", "vendor", "note")
UNKNOWN = {"不知道", "unknown", "?"}
ZIP_ERRORS = (ValueError, OSError, EOFError, RuntimeError, NotImplementedError, struct.error, zlib.error, lzma.LZMAError,
              zipfile.BadZipFile)              # 損壞的 deflate／lzma／bzip2 成員、加密、不支援的壓縮方式
PARSE_ERRORS = (struct.error, IndexError, ValueError, OverflowError)
UCODE_HDR = re.compile(rb"\x01\x00\x00\x00(?=.{16}\x01\x00\x00\x00)", re.S)    # header version 1，+20 的 loader revision 也是 1
# BIOS 第 2a 步（$FPT、FIT、AMD 標記、UEFI 壓縮統計）的上限：都是每個檔案
MAX_MN2 = 64                           # 每個範圍記下的 `$MN2` manifest 數（實際一個 ME 區域約 10–30 個）
MN2_RE = re.compile(rb"\$MN2")
CPD_RE = re.compile(rb"\$CPD")
MAX_FPT_ENTRIES = 128                  # $FPT 分割區數（實際約 10–30 個）
MAX_FPT_SCAN = 64                      # 沒有 descriptor 時全檔找 $FPT 的候選數
MAX_CPD_ENTRIES = 256                  # FTPR 的 $CPD 目錄項目數
MAX_FIT_ENTRIES = 512                  # FIT 項目數（header 的 size 欄位是 24 bits，構造的輸入可以很大）
MAX_AMD_SCAN = 4096                    # 找 AMD PSP／BIOS 目錄標記的候選數
MAX_FV = 512                           # 走訪的 firmware volume 數
MAX_FVH_SCAN = 1 << 16                 # `_FVH` 候選數（每個候選要算一次 header checksum；HeaderLength 也限 0x1000 以內）
MAX_FFS_ITEMS = 1 << 17                # 走訪的 FFS 檔案＋section 總數
MAX_SECTION_DEPTH = 8                  # 不用解壓就能往下走的封裝 section（不壓縮、不需處理的 GUID-defined）巢狀深度
FIT_POINTER = 0xFFFFFFC0               # 4 GB − 0x40（edk2-platforms FirmwareInterfaceTable.h、coreboot fit.md）
FIT_LOWEST = (1 << 32) - (16 << 20)    # FIT 要在 4 GB 以下 16 MB 內（同上；coreboot cbfstool/fit.c 也這樣檢查）
AMD_EFS_OFFSETS = (0xFA0000, 0xF20000, 0xE20000, 0xC20000, 0x820000, 0x020000, 0x7A0000, 0x720000, 0x620000, 0x420000,
                   0x3A0000, 0x320000, 0x220000)        # coreboot util/amdfwtool/amdfwread.c 的 fw_header_offsets（16／8／4 MB）
AMD_EFS_SIG = b"\xaa\x55\xaa\x55"      # EMBEDDED_FW_SIGNATURE 0x55AA55AA（little endian）
AMD_DIR_RE = re.compile(rb"\$PSP|\$PL2|\$BHD|\$BL2|2PSP|2BHD")   # PSP／BIOS 目錄（L1、L2）與 combo 目錄的 cookie（coreboot vendorcode/amd/psp）
FVH_RE = re.compile(rb"_FVH")
FFS_FS = {"8C8CE578-8A3D-4F1C-9935-896185C32DD3": 2, "5473C07A-3DCB-4DCA-BD6F-1E9689E7349A": 3}   # EFI_FIRMWARE_FILE_SYSTEM2／3_GUID
COMPRESSION_GUIDS = {"EE4E5898-3914-4259-9D6E-DC7BD79403CF": "lzma", "D42AE6BD-1352-4BFB-909A-CA72A6EAE889": "lzma-f86",
                     "3D532050-5CDA-4FD0-879E-0F7F630D5AFB": "brotli", "A31280AD-481E-41B6-95E8-127F4C984779": "tiano-custom"}
STANDARD_COMPRESSION = "efi-standard"  # EFI_COMPRESSION_SECTION 的 CompressionType 1（EFI／Tiano 標準壓縮）


class Fail(Exception):
    pass


def load_sibling(name):
    """同目錄的模組（coreboot_cbfs、ami_pfat）。python3 -I 不把腳本目錄放進 sys.path，所以用檔案路徑載入；測試 import 過就共用同一個。"""
    mod = sys.modules.get(name)
    if mod is None:
        path = Path(__file__).resolve().with_name(name + ".py")
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
        except (OSError, ImportError, AttributeError) as e:
            sys.modules.pop(name, None)
            raise Fail(f"找不到或載入不了 {name}.py（{type(e).__name__}）")
    return mod


def cbfs_where(loc):
    """CBFS 檔案位置的文字（found-in 用）。"""
    reg = loc["role"] + (f" [{loc['region']}]" if loc["region"] != loc["role"] else "")
    return f"CBFS {reg}: {loc['file']} @0x{loc['offset']:x}"


class OverBudget(Exception):
    pass


class TooBig(ValueError):
    pass


class Budget:
    """一次執行的上限：時間（deadline）與讀進來的總量。None＝不限（單元測試直接呼叫解析函式時）。"""

    def __init__(self, time_limit=None, max_total=None):
        self.time_limit = TIME_LIMIT if time_limit is None else time_limit
        self.deadline = time.monotonic() + self.time_limit
        self.total_left = MAX_TOTAL if max_total is None else max_total

    def check(self):
        if time.monotonic() > self.deadline:
            raise OverBudget(f"超過時間上限 {self.time_limit} 秒，沒有解析完")


def tick(budget, i):
    if budget is not None and i % 1024 == 0:
        budget.check()


def archive_kind(data, label=""):
    """壓縮檔的種類；Office／ODF 文件（副檔名，或 ZIP 開頭就是 [Content_Types].xml、mimetype）不算。"""
    kind = next((k for sig, k in ARCHIVES if data.startswith(sig)), None)
    if kind == "zip" and len(data) >= 30:
        first = data[30:30 + struct.unpack_from("<H", data, 26)[0]]       # 第一個成員的檔名
        if label.lower().endswith(DOC_EXT) or first in (b"[Content_Types].xml", b"mimetype"):
            return None
    return kind


# ---------- 讀輸入（不可信資料） ----------

def read_limited(f, size, what, cap=MAX_FILE):
    limit = max(0, min(MAX_FILE, cap))
    if size is not None and size > limit:
        raise TooBig(f"{what} 太大（{size} bytes，上限 {limit}）" if limit == MAX_FILE else
                         f"{what} 超過這次執行的總量上限（{MAX_TOTAL} bytes），沒有讀")
    data = f.read(limit + 1)
    if len(data) > limit:
        raise TooBig(f"{what} 太大（上限 {limit}）" if limit == MAX_FILE else f"{what} 超過這次執行的總量上限，沒有讀")
    return data


def inputs(paths, budget=None):
    """→ 逐一產生 (顯示名稱, bytes)；略過的記在 skipped。不跟隨符號連結，不執行，不寫磁碟。
    單一檔案或 ZIP 成員有 MAX_FILE 上限；有 budget 時另有總量（含 ZIP 成員解壓後）與時間上限。"""
    budget = budget or Budget(time_limit=float("inf"), max_total=float("inf"))
    skipped = []

    def gen():
        for p in paths:
            p = Path(p)
            try:
                st = os.lstat(p)
            except OSError as e:
                raise Fail(f"讀不到 {p}（{type(e).__name__}）")
            if stat.S_ISDIR(st.st_mode):
                def walk_error(e, top=p):
                    skipped.append((str(Path(e.filename).relative_to(top.parent)) if e.filename else str(top),
                                    f"讀不到資料夾（{type(e).__name__}）"))
                for root, dirs, files in os.walk(p, followlinks=False, onerror=walk_error):
                    dirs.sort()
                    for n in sorted(files):
                        yield from one(Path(root) / n, str((Path(root) / n).relative_to(p.parent)))
            else:
                yield from one(p, p.name)

    def take(label, data, note=None):
        """讀進來以後：扣總量；巢狀或其他壓縮檔記下來（不展開）。note：已知的原因（例如損壞的 ZIP），取代「沒有展開」。"""
        budget.total_left -= len(data)
        kind = archive_kind(data, label)
        if note:
            skipped.append((label, note))
        elif kind:
            skipped.append((label, f"壓縮檔（{kind}）沒有展開，裡面的檔案沒有解析"))
        return label, data

    def one(p, label):
        try:
            budget.check()
        except OverBudget as e:
            skipped.append((label, str(e)))
            return
        try:
            st = os.lstat(p)
        except OSError:
            skipped.append((label, "讀不到"))
            return
        if not stat.S_ISREG(st.st_mode):
            skipped.append((label, "不是一般檔案（不跟隨連結）"))
            return
        if st.st_size > MAX_FILE:
            skipped.append((label, f"太大（{st.st_size} bytes）"))
            return
        try:
            with open(p, "rb") as f:
                head = f.read(4)
                f.seek(0)
                is_zip = head == b"PK\x03\x04" and not label.lower().endswith(DOC_EXT)
                if is_zip and zipfile.is_zipfile(f):
                    f.seek(0)
                    yield from zip_members(f, label)
                    return
                f.seek(0)
                data = read_limited(f, st.st_size, label, budget.total_left)
        except (OSError, ValueError) as e:
            skipped.append((label, str(e) if isinstance(e, TooBig) else type(e).__name__))
            return
        yield take(label, data, "ZIP 讀不到（格式損壞），只當一般檔案掃描" if is_zip else None)

    def zip_members(f, label):
        try:
            z = zipfile.ZipFile(f)
            infos = sorted(z.infolist(), key=lambda i: i.filename)
        except ZIP_ERRORS as e:
            skipped.append((label, f"ZIP 讀不到（{type(e).__name__}）"))
            return
        for info in infos:
            name = f"{label}!{info.filename}"
            if info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:     # 目錄、符號連結
                continue
            try:
                budget.check()
            except OverBudget as e:
                skipped.append((name, str(e)))
                continue
            try:
                with z.open(info) as m:
                    data = read_limited(m, info.file_size, name, budget.total_left)
            except ZIP_ERRORS as e:          # 損壞的成員：記這個成員，其他照讀
                skipped.append((name, str(e) if isinstance(e, TooBig) else f"ZIP 成員讀不到（{type(e).__name__}）"))
                continue
            yield take(name, data)

    return gen(), skipped


def hashes(b):
    return {"sha256": hashlib.sha256(b).hexdigest(), "sha512": hashlib.sha512(b).hexdigest()}


# ---------- vBIOS：PCI option ROM ----------

IMAGE_SIGS = (b"\x55\xaa", b"\x77\xbb", b"\x56\x4e")   # 影像開頭：nouveau shadow.c 也接受 0xBB77、0x4E56（樣本上有 0x4E56）
IMAGE_SIG_RE = re.compile(rb"\x55\xaa|\x77\xbb|\x56\x4e")


def pci_image(data, p, q):
    """q 位置的一個影像（ROM 從 p 開始）→ (dict, None) 或 (None, 為什麼不是影像)。
    PCIR（或 NVIDIA 的 NPDS）結構：0x18 的指標要在影像自己的長度內（沒有 0x1000 上限；實際樣本有超過 0x1000 的）。
    影像長度超出檔案時仍回傳讀得到的部分，標 truncated。
    NVIDIA 的 NPDE 延伸（PCIR 之後、以 ROM 起點對齊 16 bytes；只對 vendor 0x10DE）：有的話影像長度與「最後一個」旗標以 NPDE 為準
    （nouveau nvkm/subdev/bios/shadow.c、npde.c 的做法；NPDE 長度 0 時退回 PCIR）。code type 0x70 不用 NPDE，而且一定是最後一個。"""
    n = len(data)
    if q + 0x1A > n:
        return None, f"0x{q - p:x}: past the end of the file"
    if data[q:q + 2] not in IMAGE_SIGS:
        return None, f"0x{q - p:x}: no option ROM signature"
    po = struct.unpack_from("<H", data, q + 0x18)[0]
    r = q + po
    if po < 0x1A or r + 0x18 > n or data[r:r + 4] not in (b"PCIR", b"NPDS"):
        return None, f"0x{q - p:x}: no PCIR/NPDS structure"
    vid, did = struct.unpack_from("<HH", data, r + 4)
    plen = struct.unpack_from("<H", data, r + 0x0A)[0]
    ilen = struct.unpack_from("<H", data, r + 0x10)[0] * 512
    ctype, ind = data[r + 0x14], data[r + 0x15]
    basis = "PCIR"
    e = p + ((r - p + plen + 0x0F) & ~0x0F)
    if ctype == 0x70:
        ind |= 0x80
    elif vid == NVIDIA_VID and 0x18 <= plen <= 0x100 and e + 0x0B <= n and data[e:e + 4] == b"NPDE":
        nlen = struct.unpack_from("<H", data, e + 0x08)[0] * 512
        if nlen:
            ilen, ind, basis = nlen, data[e + 0x0A], "NPDE"
    if ilen == 0:
        return None, f"0x{q - p:x}: image length 0"
    if po + 0x18 > ilen:                 # PCIR 要在影像自己的範圍內（雜散的 55AA 指到別的影像的 PCIR 不算）
        return None, f"0x{q - p:x}: PCIR pointer 0x{po:x} outside the image ({ilen} bytes)"
    img = {"offset": q, "pcir": r, "vendor": vid, "device": did, "class": data[r + 0x0D:r + 0x10][::-1].hex(), "length": ilen,
           "code_type": ctype, "last": bool(ind & 0x80), "length_basis": basis,
           # PCIR 與採用的長度（512 bytes 為單位），ImageStarts 決勝用；0 不算（標頭的 0 不能當成相符）
           "units": {u for u in (struct.unpack_from("<H", data, r + 0x10)[0], ilen // 512) if u}}
    if q + ilen > n:                     # 被截斷：留下讀得到的部分，ROM 標 truncated
        img.update(length=n - q, truncated=f"0x{q - p:x}: image length {ilen} ({basis}) goes past the end of the file")
    return img, None


class _Pcir:
    """ImageStarts 對一個 PCIR 記的東西。cands：候選開頭（依位置排列；大小相符記 q、不符記 ~q），head 之前的已經不算（在 pos 之前）；
    nok：head 之後大小相符的個數；decision：(開頭, 說明或 None)；claimed：選定的開頭已經被 option_roms 接受成 ROM。"""
    __slots__ = ("head", "nok", "cands", "decision", "claimed")

    def __init__(self):
        self.head, self.nok, self.cands, self.decision, self.claimed = 0, 0, [], None, False


class ImageStarts:
    """每個 PCIR（或 NPDS）結構屬於哪一個影像開頭。候選：0x18 的指標正好指到它、自己就是合法影像（pci_image 以它為起點成功）、
    而且不在已經接受的 ROM 範圍裡（option_roms 的 pos 之前）的開頭。
    - 選離 PCIR 最近的候選（規則：雜散的特徵碼在真 ROM 前方時，指標也可能剛好落在真 ROM 的 PCIR）；
      但最近的那個串起來的影像鏈在檔案裡就斷了、另一個候選的鏈正常結束時，選那個（雜散的特徵碼在真 ROM 的標頭裡時常見），一定記 start_note。
      影像鏈的檢查有上限：每條鏈最多 64 個影像、最近的之外最多再試 8 個候選、每個檔案總共 MAX_CHAIN_CHECK 個影像；
      總數用完以後記在 notes（檔案記在 partial），之後有多個候選的選擇都記 start_note（沒有檢查鏈，不能靜默）。
    - 只有一個候選，或選的是最近的、它是唯一「標頭第 2 個 byte（影像大小，512 bytes 為單位）和 PCIR／NPDE 長度相符」的、
      而且鏈的檢查沒有用完上限 → 不加說明；其他情況記 start_note（vBIOS 會 ATTENTION、SBOM 加 sca-center:note）。
      大小只是線索（PCI 3.0 的 init size 可以小於影像長度），不拿來改選。分不出來的巧合仍然可能靜默：兩個候選的鏈都正常結束、
      而且最近的（雜散的）剛好是唯一大小相符的；雜散開頭的範圍蓋到緊接著的下一個 ROM 時，那個 ROM 也會不見（舊版本也一樣）。
      構造的排法讓雜散的開頭剛好落在已接受 ROM 的影像鏈上時，它被當成已經用掉，也可能藏住一個 ROM 而不記（先前的版本也一樣）。
    - 每個 PCIR 第一次被問到時決定（之後同一個 PCIR 的其他候選得到同一個答案，不會變成兩個 ROM）；選定的開頭後來被別的 ROM 蓋過、
      沒有被看到時，下一個來問的候選重新決定；最後還是沒有任何 ROM 用到這個 PCIR（有候選因為它被丟掉）→ 記在 notes，不會無聲消失。
      選定的開頭已經是接受的 ROM 鏈裡的影像開頭時不算沒有用到（只是落在別的 ROM 範圍裡仍然算：那個 ROM 可能是雜散開頭靜默勝出、
      範圍蓋到下一個真 ROM 的開頭）；
      逐一列出最多 MAX_LOST_NOTES 個，其餘合成一筆（構造的輸入可以有幾十萬個，輸出大小要有上限）。
    依位置線性掃一次特徵碼（以前每個候選都重掃最多 64 KB 的特徵碼，構造的輸入是平方時間）；已經接受的 ROM 範圍直接跳過不掃；
    PCIR 一定在開頭之後 0x1A–0xFFFF，只保留目前位置之後的 PCIR，記憶體不隨檔案大小成長。"""

    def __init__(self, data, budget=None):
        self.data, self.budget = data, budget
        self.sigs = IMAGE_SIG_RE.finditer(data)
        self.pending = None            # 已經從 finditer 拿出來、但還在掃描範圍之後的特徵碼
        self.scanned = -1              # 已經看過 <= scanned 的特徵碼
        self.pos = 0                   # pos 之前是已經接受的 ROM（或已經走過的位置），不掃、不算候選
        self.by_pcir = {}              # PCIR 位置 → _Pcir
        self.floor = 0                 # 上一次清掉 by_pcir 舊資料時的位置
        self.i = 0
        self.chain_left = MAX_CHAIN_CHECK
        self.capped = False
        self.notes = []                # 給 option_roms 的 notes（檔案記在 partial）；all_notes() 另加「其餘 N 個」
        self.lost = 0                  # 「PCIR 沒有變成 ROM」的個數（只列出前 MAX_LOST_NOTES 個）
        self.acc_starts = set()        # 已經接受的 ROM 裡每個影像的開頭（絕對位置；只留目前位置附近）

    def consumed(self, pos):
        """pos 之前已經被接受的 ROM 用掉（option_roms 往後跳）：那裡的開頭不算候選，也不用掃。"""
        if pos > self.pos:
            self.pos = pos
            if pos > self.scanned + 1:  # 跳過長的 ROM：不掃裡面的特徵碼（不然記憶體、時間都隨被跳過的範圍成長）
                self.sigs, self.pending, self.scanned = IMAGE_SIG_RE.finditer(self.data, pos), None, pos - 1

    def _scan_to(self, end):
        """看過所有 pos 到 end 之間的特徵碼。"""
        while True:
            m = self.pending or next(self.sigs, None)
            if m is None or m.start() > end:
                self.pending = m
                self.scanned = max(self.scanned, end)
                return
            self.pending = None
            tick(self.budget, self.i)
            self.i += 1
            q = m.start()
            img, _ = pci_image(self.data, q, q)
            if img is None:
                continue
            ok = self.data[q + 2] in img["units"]
            e = self.by_pcir.get(img["pcir"])
            if e is None:
                e = self.by_pcir[img["pcir"]] = _Pcir()
            e.cands.append(q if ok else ~q)
            e.nok += ok

    def accept(self, rom):
        """option_roms 接受了一個 ROM：記下它每個影像的開頭（選定的開頭是其中之一 → 已經用掉，不是「沒有變成 ROM」）。
        只是落在別的 ROM 範圍裡不算用掉：雜散開頭靜默勝出、範圍蓋到下一個真 ROM 的開頭時，要靠這個說明才不會無聲消失。"""
        self.acc_starts.update(rom["offset"] + i["offset"] for i in rom["images"])

    def _lost(self, r, e):
        """決定過、但選定的開頭沒有變成 ROM、也不在已經接受的 ROM 裡：有候選因為它被丟掉，記下來（前 MAX_LOST_NOTES 個逐一列出）。"""
        if e.decision is not None and not e.claimed and e.decision[0] not in self.acc_starts:
            self.lost += 1
            if self.lost <= MAX_LOST_NOTES:
                self.notes.append(f"PCIR 0x{r:x}：選定的影像開頭 0x{e.decision[0]:x} 沒有變成 ROM（被別的 ROM 蓋過，"
                                  "或沒有被看到），指到這個 PCIR 的影像都沒有回報")

    def _trim(self, limit):
        """位置在 limit 之前的已接受 ROM 資料不會再用到（之後檢查的開頭都在 limit 之後）。"""
        self.acc_starts = {x for x in self.acc_starts if x >= limit}

    def finish(self):
        """option_roms 正常掃完：還沒用到的決定記下來。"""
        for r, e in self.by_pcir.items():
            self._lost(r, e)
        self.by_pcir = {}

    def all_notes(self):
        extra = self.lost - MAX_LOST_NOTES
        return self.notes + ([f"另外還有 {extra} 個 PCIR 也一樣沒有變成 ROM（沒有逐一列出）"] if extra > 0 else [])

    def owner(self, p, r):
        """p 開始的影像、PCIR 在 r → (r 的影像開頭, 說明或 None)。p 依序遞增呼叫，p >= pos；回傳 p 時就當成 p 會被接受。"""
        if p - self.floor > 0x20000:   # r > p：位置在 p 之前的 PCIR 不會再被問到
            keep = {}
            for k, e in self.by_pcir.items():
                if k > p:
                    keep[k] = e
                else:
                    self._lost(k, e)
            self.by_pcir, self.floor = keep, p
            self._trim(p - 0x10000)    # 之後檢查的 PCIR 都在 p 之後，選定的開頭在 PCIR 前 0xFFFF 以內
        self._scan_to(r - 0x1A)        # 指到 r 的開頭都在 r - 0x1A 之前（指標至少 0x1A）
        e = self.by_pcir.get(r)
        if e is None:                  # 不該發生（p 自己就是候選）
            return p, None
        if e.decision is None or (not e.claimed and e.decision[0] < self.pos):   # 選定的被別的 ROM 蓋過了：重新決定
            e.decision = self._decide(r, e)
        if e.decision[0] == p:
            e.claimed = True
        return e.decision

    def _ends_normally(self, q):
        """q 開始串起來的影像鏈：True＝正常結束（最後一個影像標了 last）；False＝在檔案裡就斷了（下一個位置不是有效影像，或 64 個影像還沒完）；
        None＝不知道（影像超出檔案結尾：只是檔案被截斷，不能證明這個開頭是錯的；或這個檔案的檢查總數用完，self.capped）。"""
        x = q
        for _ in range(64):
            if self.chain_left <= 0:
                if not self.capped:
                    self.capped = True
                    self.notes.append(f"選 PCIR 的影像開頭時試串影像鏈的次數達上限 {MAX_CHAIN_CHECK}，"
                                      "之後有多個候選的選擇沒有檢查影像鏈（都記 start_note）")
                return None
            self.chain_left -= 1
            img, _ = pci_image(self.data, q, x)
            if img is None:
                return False
            if img.get("truncated"):
                return None
            if img["last"]:
                return True
            x += img["length"]
        return False

    def _decide(self, r, e):
        c = e.cands
        while e.head < len(c) and (c[e.head] if c[e.head] >= 0 else ~c[e.head]) < self.pos:   # 已經接受的 ROM 範圍裡的不算
            e.nok -= c[e.head] >= 0
            e.head += 1
        n = len(c) - e.head
        near_ok = c[-1] >= 0
        near = c[-1] if near_ok else ~c[-1]
        if n == 1:
            return near, None
        head = f"{n} image starts point at the PCIR at file offset 0x{r:x}; "
        if self._ends_normally(near) is False:          # 最近的鏈斷了：往前找鏈正常結束的候選（最多 8 個）
            for k in range(len(c) - 2, max(e.head, len(c) - 10) - 1, -1):
                q = c[k] if c[k] >= 0 else ~c[k]
                if self._ends_normally(q):
                    return q, (head + f"chose 0x{q:x}, whose image chain ends normally; the nearest (0x{near:x}) does not")
        if near_ok and e.nok == 1 and not self.capped:
            return near, None
        why = []
        if not near_ok:
            why.append("its header image size does not match the PCIR/NPDE length")
        elif e.nok > 1:
            why.append(f"{e.nok} of them have a header image size matching the PCIR/NPDE length")
        if self.capped:
            why.append("the image chains were not checked (check limit reached)")
        return near, head + f"chose the nearest (0x{near:x}), but " + "; ".join(why)


def option_roms(data, budget=None, notes=None):
    """bytes → [ROM]：每組串起來的 option ROM 影像（從影像開頭 55AA／77BB／564E 開始，到標了最後一個的影像為止；長度與最後一個以 NPDE 優先）。
    terminated：last-flag（正常結束）；invalid-next-image（還沒標最後一個，但下一個位置不是有效影像）；truncated（影像長度超出檔案，
    只留讀得到的部分）。後兩種 ROM 可能不完整，雜湊只涵蓋一部分；terminated_note 寫原因。開頭不確定的 ROM 有 start_note（見 ImageStarts）；
    開頭在這種 ROM 範圍裡的 ROM 也加 start_note（兩個之中可能有一個是錯的）。
    每個 ROM 都檢查一次時間上限（沒有正常結束或開頭不確定時會從最後一個影像之後重找，雜湊的工作量可能很大）；這兩種 ROM 合計超過
    MAX_BROKEN_ROMS 個就不再找。原因（含 ImageStarts 的 notes）記在 notes（list，有給的話）。
    超過時間上限時 OverBudget 的 partial 是已經找到的 ROM。"""
    out, pos, uncertain = [], 0, 0
    shadow, shadow_from = -1, None     # 開頭不確定的 ROM 範圍的結尾：從裡面開始的 ROM 也標出來（可能其中一個是錯的）
    starts = ImageStarts(data, budget)
    try:
        for i, m in enumerate(IMAGE_SIG_RE.finditer(data)):
            tick(budget, i)
            p = m.start()
            if p < pos:
                continue
            starts.consumed(pos)
            r = rom_at(data, p, budget, starts)
            if r is None:
                continue
            if p < shadow and not r.get("start_note"):
                r["start_note"] = (f"starts inside the range of the ROM at file offset 0x{shadow_from:x}, whose start is uncertain; "
                                   "one of them may be wrong")
            if r.get("start_note") and p + r["length"] > shadow:
                shadow, shadow_from = p + r["length"], p
            out.append(r)
            starts.accept(r)
            sure = r["terminated"] == "last-flag" and not r.get("start_note")
            if not sure:
                uncertain += 1
                if uncertain >= MAX_BROKEN_ROMS:
                    starts.notes.append(f"沒有正常結束（或開頭不確定）的 option ROM 達 {MAX_BROKEN_ROMS} 個，0x{r['offset']:x} 之後沒有再找")
                    break
            # 正常結束、開頭確定：下一個 ROM 從結尾找。沒有正常結束：最後一個影像說的長度不可信（實際樣本有下一個影像就在它的範圍裡）；
            # 開頭不確定：這個範圍可能是錯的（例如從真 ROM 標頭裡的雜散特徵碼算起，會蓋到下一個 ROM 的開頭）→ 從最後一個影像之後重新找
            pos = p + r["length"] if sure else p + r["images"][-1]["offset"] + 2
        else:
            starts.finish()
    except OverBudget as e:
        e.partial = out
        raise
    finally:
        if notes is not None:
            notes.extend(starts.all_notes())
    return out


def rom_at(data, p, budget=None, starts=None):
    """p 開始的一組影像 → ROM dict；不是 ROM（或 p 是雜散的特徵碼：第一個影像的 PCIR 屬於別的開頭，見 ImageStarts）→ None。
    starts：同一個檔案共用的 ImageStarts（option_roms 傳進來；沒給就自己建一個）。"""
    images, q, why, start_note = [], p, None, None
    while True:
        img, why = pci_image(data, p, q)
        if img is None:
            break
        if not images:                   # 先判斷 p 是不是這個 PCIR 的開頭，雜散的不用串後面的影像
            starts = starts or ImageStarts(data, budget)
            owner, start_note = starts.owner(p, img["pcir"])
            if owner != p:
                return None
        images.append(img)
        q += img["length"]
        if img["last"] or img.get("truncated"):
            break
    if not images:
        return None
    if budget is not None:
        budget.check()
    rom = data[p:q]
    first = images[0]
    vm = VBIOS_VER.search(rom)
    r = {"offset": p, "length": q - p, "vendor": f"{first['vendor']:04x}", "device": f"{first['device']:04x}",
         "class": first["class"], "version": vm.group(1).decode() if vm else None,
         "terminated": ("truncated" if images[-1].get("truncated") else "last-flag" if images[-1]["last"] else "invalid-next-image"),
         "images": [{"offset": i["offset"] - p, "code_type": i["code_type"], "length": i["length"],
                     "length_basis": i["length_basis"], "vendor": f"{i['vendor']:04x}", "device": f"{i['device']:04x}"}
                    for i in images], **hashes(rom)}
    if r["terminated"] != "last-flag":
        r["terminated_note"] = images[-1].get("truncated") or why
    if start_note:
        r["start_note"] = start_note
    return r


def is_vbios(rom):
    """顯卡 vBIOS：NVIDIA，而且有 x86 或 EFI 影像（顯卡開機用的）。"""
    return rom["vendor"] == f"{NVIDIA_VID:04x}" and any(i["code_type"] in VBIOS_CODE_TYPES for i in rom["images"])


# ---------- BIOS：Intel SPI 映像 ----------

def descriptor(data):
    """→ (區域清單, 說明, 超出檔案的區域)；沒有 descriptor → (None, 說明, [])。"""
    if len(data) < 0x1000 or data[0x10:0x14] != FD_SIG:
        return None, "no Intel flash descriptor at 0x10 (capsule or BIOS-region-only image)", []
    flmap0 = struct.unpack_from("<I", data, 0x14)[0]
    frba = ((flmap0 >> 16) & 0xFF) << 4
    regions, beyond = [], []
    for i in range(16):
        o = frba + 4 * i
        if o + 4 > 0x1000:
            break
        v = struct.unpack_from("<I", data, o)[0]
        base, limit = (v & 0x7FFF) << 12, (((v >> 16) & 0x7FFF) << 12) | 0xFFF
        if (v == 0 and i != 0) or v == 0xFFFFFFFF or base > limit:      # FLREG0＝0 是 0–0xFFF 的 descriptor；其他是沒用到
            continue
        name = REGION_NAMES.get(i, f"region-{i}")
        if limit >= len(data):
            beyond.append(f"{name} 0x{base:x}-0x{limit:x}")
            continue
        regions.append({"index": i, "name": name, "base": base, "limit": limit, **hashes(data[base:limit + 1])})
    return regions, None, beyond


def bcd_date(v, order):
    """BCD 日期 → YYYY-MM-DD；order 'ymd'（0xYYYYMMDD）或 'mdy'（0xMMDDYYYY）；不合法 → None。"""
    h = f"{v:08x}"
    if not h.isdigit():
        return None
    y, m, d = (h[0:4], h[4:6], h[6:8]) if order == "ymd" else (h[4:8], h[0:2], h[2:4])
    return f"{y}-{m}-{d}" if 1990 <= int(y) <= 2100 and 1 <= int(m) <= 12 and 1 <= int(d) <= 31 else None


def me_manifests(data, base=0, end=None, budget=None, notes=None):
    """ME 區域裡的 `$MN2`（vendor 0x8086）。partition：manifest 前面最近的 `$CPD` 目錄記的分割區名稱（FTPR 是 ME 主程式）。
    最多記 MAX_MN2 個（構造的輸入每 0x30 bytes 就能有一個，每個一筆 dict 會讓記憶體隨檔案成長）；達到上限時原因加進 notes（有給的話）。"""
    end = len(data) if end is None else end
    out = []
    for i, m in enumerate(MN2_RE.finditer(data, base, end)):
        tick(budget, i)
        p = m.start()
        h = p - 0x1C
        if h < 0 or p + 0x10 > len(data):
            continue
        if struct.unpack_from("<I", data, h + 0x10)[0] != 0x8086:
            continue
        major, minor, hotfix, build = struct.unpack_from("<4H", data, p + 8)
        cpd = data.rfind(b"$CPD", max(base, h - 0x2000), h)
        part = data[cpd + 0x0C:cpd + 0x10].rstrip(b"\x00").decode("ascii", "replace") if cpd >= 0 else None
        if len(out) >= MAX_MN2:
            if notes is not None:
                notes.append(f"more than {MAX_MN2} $MN2 manifests in 0x{base:x}-0x{end:x}; the rest were not read")
            break
        out.append({"offset": h, "version": f"{major}.{minor}.{hotfix}.{build}", "partition": part,
                    "date": bcd_date(struct.unpack_from("<I", data, h + 0x14)[0], "ymd")})
    return out


def ucode_size(data, p):
    """p 位置像不像 Intel microcode header（還沒算 checksum）→ 整份大小或 None。
    header version 1、loader revision 1、BCD 日期、大小對齊而且在檔案內（coreboot cbfstool/fit.c 的 microcode_header 欄位）。"""
    if p < 0 or p % 16 or p + 48 > len(data):
        return None
    hv, _rev, date, _cpuid, _ck, ldr, _pf, dsize, tsize = struct.unpack_from("<IiIIIIIII", data, p)
    if hv != 1 or ldr != 1 or not bcd_date(date, "mdy"):
        return None
    dsize = dsize or 2000                      # data size 0 → 舊格式，固定 2000＋48
    tsize = tsize or 2048
    if dsize % 4 or tsize < 48 + dsize or tsize % 1024 or p + tsize > len(data) or tsize > (16 << 20):
        return None
    return tsize


def ucode_entry(data, p, tsize):
    """checksum 對（整份 32-bit 加總為 0）→ microcode dict；不對 → None。"""
    blob = data[p:p + tsize]
    if sum(struct.unpack_from(f"<{tsize // 4}I", blob)) & 0xFFFFFFFF:
        return None
    _hv, rev, date, cpuid, _ck, _ldr, pf, dsize, _ts = struct.unpack_from("<IiIIIIIII", blob, 0)
    ext = []
    e = 48 + (dsize or 2000)
    if tsize >= e + 20:                         # extended signature table：同一份 microcode 也適用的其他 CPUID／platform id
        cnt = struct.unpack_from("<I", blob, e)[0]
        if 0 < cnt <= (tsize - e - 20) // 12:
            ext = [{"cpuid": f"{s:08X}", "platform_id": f"0x{f:02X}"}
                   for s, f, _ in struct.iter_unpack("<III", blob[e + 20:e + 20 + 12 * cnt])]
    return {"offset": p, "cpuid": f"{cpuid:08X}", "revision": f"0x{rev & 0xFFFFFFFF:X}", "date": bcd_date(date, "mdy"),
            "platform_id": f"0x{pf:02X}", "size": tsize, "extended_signatures": ext, **hashes(blob)}


def microcodes(data, budget=None, checksum_cap=None):
    """Intel microcode。先檢查 header 欄位（loader、BCD 日期、大小對齊）再算 checksum；checksum 總量有上限。
    → (清單, 沒做完的原因或 None)。"""
    cap = MAX_CHECKSUM if checksum_cap is None else checksum_cap
    out, spent, skip_to = [], 0, 0
    for i, m in enumerate(UCODE_HDR.finditer(data)):
        tick(budget, i)
        p = m.start()
        if p < skip_to:
            continue
        tsize = ucode_size(data, p)
        if tsize is None:
            continue
        spent += tsize
        if spent > cap:
            return out, f"microcode 候選太多（checksum 總量超過 {cap} bytes），沒有找完"
        u = ucode_entry(data, p, tsize)
        if u is None:
            continue
        out.append(u)
        skip_to = p + tsize                     # microcode 不會重疊
    return out, None


def ibv_hints(data):
    return sorted({name for name, pats in IBV_HINTS if any(x in data for x in pats)})


# ---------- BIOS 第 2a 步：CSME（$FPT）、FIT、AMD、UEFI 壓縮統計 ----------

def u32(data, o):
    return struct.unpack_from("<I", data, o)[0]


def mn2_at(data, h, end):
    """h 是不是 `$MN2` manifest header 的開頭（+0x1C 的 tag、+0x10 vendor 0x8086；me_cleaner check_mn2_tag 與 MEAnalyzer MN2_Manifest）。"""
    return 0 <= h and h + 0x2C <= min(end, len(data)) and data[h + 0x1C:h + 0x20] == b"$MN2" and u32(data, h + 0x10) == 0x8086


def mn2_version(data, h):
    major, minor, hotfix, build = struct.unpack_from("<4H", data, h + 0x24)
    return f"{major}.{minor}.{hotfix}.{build}", bcd_date(u32(data, h + 0x14), "ymd")


def fpt_entries(data, fpt, end):
    """$FPT 分割區表 → ([(名稱, offset, size)], 問題或 None)。表頭 0x20 bytes、+4 是分割區數，之後每項 0x20 bytes：
    名稱 4 bytes、+8 offset、+0xC size（相對 ME 區域開頭）。依 me_cleaner.py 與 MEAnalyzer 的 FPT_Header／FPT_Entry。"""
    n = u32(data, fpt + 4)
    if not 1 <= n <= MAX_FPT_ENTRIES:
        return [], f"$FPT at 0x{fpt:x} declares {n} partitions (accepted 1-{MAX_FPT_ENTRIES})"
    out = []
    for i in range(n):
        e = fpt + 0x20 + 0x20 * i
        if e + 0x20 > end:
            return out, f"$FPT at 0x{fpt:x}: partition entries go past the end of the ME region"
        off, size = struct.unpack_from("<II", data, e + 8)
        out.append((data[e:e + 4].rstrip(b"\x00").decode("ascii", "replace"), off, size))
    return out, None


def cpd_manifest(data, part, pend):
    """part 開頭的 `$CPD` 目錄（MEAnalyzer CPD_Header_R1 0x10／R2 0x14；每項 0x18：名稱 12 bytes、+0xC offset 的 bit 0–24，
    相對目錄開頭）裡 FTPR.man 那一項的 `$MN2` → (manifest 位置, None) 或 (None, 為什麼找不到)。"""
    cnt, hl = u32(data, part + 4), data[part + 0x0A]
    hl = hl if hl in (0x10, 0x14) else 0x10
    if cnt > MAX_CPD_ENTRIES:
        return None, f"$CPD at 0x{part:x} declares {cnt} entries (accepted up to {MAX_CPD_ENTRIES})"
    for k in range(cnt):
        ce = part + hl + 0x18 * k
        if ce + 0x18 > pend:
            break
        if data[ce:ce + 12].rstrip(b"\x00") == b"FTPR.man":
            h = part + (u32(data, ce + 0x0C) & 0x1FFFFFF)
            if mn2_at(data, h, pend):
                return h, None
            return None, f"FTPR.man at 0x{h:x} is not a valid $MN2 manifest"
    return None, f"$CPD at 0x{part:x} (FTPR partition) has no FTPR.man entry"


def ftpr_manifest(data, base, end, fpt):
    """$FPT 的 FTPR 分割區裡的 `$MN2` → (manifest 位置, basis) 或 (None, 為什麼找不到)。
    FTPR 開頭是 `$CPD`（ME 11 以後）→ 目錄裡 FTPR.man 那一項的 offset（相對分割區開頭）；不是（ME 10 以前）→ manifest 就在分割區開頭。"""
    entries, why = fpt_entries(data, fpt, end)
    ftpr = next((x for x in entries if x[0] == "FTPR"), None)
    if ftpr is None:
        if any(x[0] == "CODE" for x in entries):
            return None, "$FPT has a CODE partition (ME generation 1, $MAN manifest; not supported)"
        return None, why or f"$FPT at 0x{fpt:x} has no FTPR partition"
    _, off, size = ftpr
    part, pend = base + off, base + off + size
    if size == 0 or pend > end:
        return None, f"FTPR partition 0x{part:x}+0x{size:x} is outside the ME region (ends 0x{end:x})"
    if data[part:part + 4] == b"$CPD" and part + 0x10 <= pend:
        h, why = cpd_manifest(data, part, pend)
        return (h, "FTPR partition ($FPT, $CPD FTPR.man)") if h is not None else (None, why)
    if mn2_at(data, part, pend):
        return part, "FTPR partition ($FPT, manifest at the partition start, no $CPD)"
    return None, f"no $CPD and no valid $MN2 manifest at the start of the FTPR partition (0x{part:x})"


def fpt_at(data, base, end):
    """ME 區域開頭與 +0x10 的 `$FPT`（+0x10 前面是 ROM bypass 向量；me_cleaner 的做法）→ 位置的清單（兩個都試：+0 的表壞了還有 +0x10）。"""
    return [base + o for o in (0, 0x10) if base + o + 0x20 <= end and data[base + o:base + o + 4] == b"$FPT"]


def fpt_plausible(data, base, f):
    """沒有 descriptor 時，f 的 `$FPT` 像不像真的分割區表：表本身沒有問題，而且有 FTPR（或 CODE）那一項、
    範圍不是空的、以 base 為 ME 區域開頭時落在檔案裡。只有標記與合理數字的雜散 `$FPT`（例如只有 BIOS 區域的檔案裡）不算 ME 區域。"""
    entries, why = fpt_entries(data, f, len(data))
    return why is None and any(n in ("FTPR", "CODE") and s and base + o + s <= len(data) for n, o, s in entries)


def fpt_header_ok(data, f):
    """f 的 `$FPT` 表頭像真的（MEAnalyzer FPT_Header：HeaderVersion 0x10／0x20／0x21、HeaderLength 0x20），分割區表沒有問題、
    名稱都是可印字元。CSME 12 以後單獨的 ME 映像的 `$FPT`（在 +0x1000）沒有 FTPR 那一項，FTPR 只能從 `$CPD` 找；
    這種表仍然表示檔案裡有 ME（不能報 no-me-region）。"""
    if f + 0x20 > len(data) or data[f + 8] not in (0x10, 0x20, 0x21) or data[f + 0x0A] != 0x20:
        return False
    entries, why = fpt_entries(data, f, len(data))
    return why is None and all(re.fullmatch(r"[\x21-\x7e]{1,4}", n) for n, _, _ in entries)


def find_fpt(data, budget=None):
    """沒有 descriptor 時全檔找 `$FPT`（單獨的 ME 更新檔在 0 或 0x10，CSME 12 以後在 0x1000；capsule 包著的完整映像在後面）。
    → {"plausible": (ME 區域開頭, $FPT 位置, 區域結尾) 或 None（有 FTPR 那一項的表；FTPR 找得到 manifest 的優先），
       "valid": [表頭像真的 $FPT 位置], "capped": 候選數用完了沒有}。區域結尾取分割區表裡最遠的結尾（不超過檔案）；
    開頭試 $FPT 本身與 $FPT−0x10。候選數上限 MAX_FPT_SCAN，用完時呼叫端記 incomplete、沒找到就是 unknown。"""
    out = {"plausible": None, "valid": [], "capped": False, "resolved": []}   # resolved：FTPR 找得到的 manifest 位置（全部）
    first_ok = False
    for i, m in enumerate(re.finditer(rb"\$FPT", data)):
        tick(budget, i)
        if i >= MAX_FPT_SCAN:
            out["capped"] = True
            break
        f = m.start()
        if f + 0x20 > len(data):
            continue
        if fpt_header_ok(data, f):
            out["valid"].append(f)
        entries, _ = fpt_entries(data, f, len(data))
        for base in (f, f - 0x10):
            if base < 0 or not fpt_plausible(data, base, f):
                continue
            ends = [base + o + s for _, o, s in entries if s and o != 0xFFFFFFFF and base + o + s <= len(data)]
            end = max(ends + [f + 0x20 + 0x20 * len(entries)])
            h = ftpr_manifest(data, base, end, f)[0]
            if h is not None:
                out["resolved"].append(h)
                if not first_ok:                 # 第一個 FTPR 找得到 manifest 的表優先（之後的只用來檢查版本有沒有不同）
                    out["plausible"], first_ok = (base, f, end), True
                break
            out["plausible"] = out["plausible"] or (base, f, end)
    return out


def find_ftpr_cpd(data, budget=None, lo=0, hi=None):
    """沒有 descriptor、也沒有可用的 $FPT FTPR 時，全檔找名稱是 FTPR 的 `$CPD` 目錄（表頭 HeaderVersion 1 或 2、長度 0x10／0x14）。
    → {"manifest": 第一個 (目錄位置, manifest 位置) 或 None, "all": [全部找得到的 (目錄位置, manifest 位置)], "seen": [目錄位置],
       "why": 第一個找不到的原因, "capped": 候選數用完了沒有}。"""
    hi = len(data) if hi is None else hi
    out = {"manifest": None, "all": [], "seen": [], "why": None, "capped": False}
    for i, m in enumerate(CPD_RE.finditer(data, lo, hi)):
        tick(budget, i)
        if i >= MAX_FPT_SCAN:
            out["capped"] = True
            break
        p = m.start()
        if p + 0x10 > hi or data[p + 0x0C:p + 0x10] != b"FTPR" or data[p + 8] not in (1, 2) or data[p + 0x0A] not in (0x10, 0x14):
            continue
        out["seen"].append(p)
        h, why = cpd_manifest(data, p, hi)
        if h is not None:
            out["all"].append((p, h))
            out["manifest"] = out["manifest"] or (p, h)
        else:
            out["why"] = out["why"] or why
    return out


def ftpr_conflict(data, h, others):
    """選定的 FTPR manifest（h）以外，還有版本不同的 FTPR manifest（例如 capsule 裡兩個 ME 映像）→ 說明（列出全部、選了哪一個、為什麼）或 None。"""
    by_ver = {}
    for x in sorted({h, *others}):
        by_ver.setdefault(mn2_version(data, x)[0], []).append(x)
    if len(by_ver) < 2:
        return None
    ver = mn2_version(data, h)[0]
    return (f"{len(by_ver)} different FTPR manifest versions in the file: "
            + ", ".join(f"{v} at " + "/".join(f"0x{x:x}" for x in xs) for v, xs in sorted(by_ver.items(), key=lambda kv: kv[1][0]))
            + f"; reported {ver} at 0x{h:x} (the first one found by the method in basis); the others are only in other_versions")


def me_info_fpt(data, regs, me_r, beyond, budget=None):
    """（$FPT、FTPR 的 `$CPD` 這條路；外面的 me_info 在這條路沒有結果時才試新世代的 BPDT 配置。）
    CSME／ME／TXE（不分是哪一種：family 不猜）→ {me（dict 或 None）, status, note, loose, standalone, incomplete}。
    status：found；no-me-region（descriptor 沒有 ME 區域，或沒有 descriptor、也沒有任何 ME 的結構）；unknown（有 ME 的結構但沒有可用的 manifest）。
    有 ME 區域：先用 $FPT（區域開頭與 +0x10 都試）→ FTPR 分割區（basis「FTPR partition ($FPT…)」）；沒有 $FPT 或 FTPR 拿不到時，
    退回舊的 `$CPD` 做法：區域裡前面最近的 `$CPD` 目錄名稱是 FTPR 的 `$MN2` → found（basis「FTPR partition manifest」，原因記在 note）。
    沒有任何 `$CPD` 指出 FTPR 時是 unknown：「第一個 `$MN2`」可能是別的分割區（ME 10 型的 RBEP 等），候選版本只記在 note，不當成 CSE 版本。
    沒有 descriptor（單獨的 ME 更新檔、capsule）：
    1. 有 FTPR 那一項的 $FPT → 照上面解析（$FPT 在 0、0x10 是 standalone），FTPR 拿不到時也接受 `$CPD` 指出 FTPR 的退路，basis 寫明；
    2. 沒有 → 全檔找名稱是 FTPR 的 `$CPD` 目錄、取 FTPR.man（CSME 12 以後：$FPT 在 +0x1000、沒有 FTPR 那一項）→ found，basis 寫明；
    3. 都拿不到，但檔案裡有表頭像真的 $FPT 或 FTPR 的 `$CPD`（或找 $FPT／$CPD 的候選數用完）→ unknown（不能說沒有 ME）；
    4. 什麼都沒有 → no-me-region：零散的 `$MN2` 不當成 CSE 版本，只記在 note（loose 是個數）。
    `$MN2` 的掃描最多記 MAX_MN2 個；$FPT／$CPD 的候選數上限 MAX_FPT_SCAN；達到上限都記在 incomplete。
    同一個檔案裡有兩個以上版本不同的 FTPR manifest（例如 capsule 裡兩個 ME 映像）：報第一個（依 basis 的方法找到的），
    conflict 列出全部、寫在 note，狀態 ATTENTION（不能靜默選一個）。"""
    r = {"me": None, "status": "unknown", "note": None, "loose": 0, "standalone": False, "incomplete": [], "conflict": None}
    prefix = ""
    if regs is not None:
        if me_r is None:
            if any(x.startswith("me ") for x in beyond):
                return {**r, "note": "the ME region goes past the end of the file (truncated image?)"}
            return {**r, "status": "no-me-region", "note": "the flash descriptor has no ME region"}
        base, end = me_r["base"], me_r["limit"] + 1
        fpts = fpt_at(data, base, end)
    else:
        ff = find_fpt(data, budget)
        if ff["capped"]:
            r["incomplete"].append(f"more than {MAX_FPT_SCAN} $FPT candidates; the rest were not checked")
        if ff["plausible"] is None:
            return me_without_fpt(data, r, ff, budget)
        base, fpt, end = ff["plausible"]
        fpts = [fpt]
        r["standalone"] = fpt <= 0x10
        prefix = (f"standalone ME image (no flash descriptor; $FPT at file offset 0x{fpt:x})" if fpt <= 0x10 else
                  f"no flash descriptor at 0x10; $FPT at file offset 0x{fpt:x} (e.g. a capsule)")
    mn = me_manifests(data, base, end, budget, notes=r["incomplete"])
    h, whys = None, []
    for fpt in fpts:                            # +0 的表壞了（例如分割區數不合理）時再試 +0x10
        h, why = ftpr_manifest(data, base, end, fpt)
        if h is not None:
            break
        whys.append(why)
    why = why if h is not None else ("; ".join(whys) or "no $FPT at the ME region start or +0x10")
    main = next((x for x in mn if x["partition"] == "FTPR"), None)
    if h is not None:
        basis = why
        ver, date = mn2_version(data, h)
    elif main:                                  # 退回舊的做法，只接受 `$CPD` 指出 FTPR 的
        basis = "FTPR partition manifest"
        h, ver, date = main["offset"], main["version"], main["date"]
        r["note"] = f"{why}; fell back to the $MN2 after the nearest $CPD named FTPR"
    else:
        cands = sorted({x["version"] for x in mn})
        return {**r, "note": (f"{prefix}: " if prefix else "") + why
                + (f"; no $CPD names the FTPR partition; $MN2 manifest(s) in the ME region ({', '.join(cands)}) "
                   "may belong to other partitions and are not reported as the CSE version" if cands else "")}
    if prefix:
        basis = f"{basis}; {prefix}"
    # 版本不同的 FTPR manifest：只看確實解析出來的（$FPT 的 FTPR、名稱是 FTPR 的 $CPD 的 FTPR.man）；
    # 「前面最近的 $CPD」只是標籤，FTPR 之後其他分割區的 manifest 也會被標成 FTPR，不拿來判斷
    others = [x for _, x in find_ftpr_cpd(data, budget, *((base, end) if regs is not None else (0, len(data))))["all"]]
    others += ff["resolved"] if regs is None else []
    r["conflict"] = ftpr_conflict(data, h, others)
    if r["conflict"]:
        r["note"] = "; ".join(x for x in (r["note"], r["conflict"]) if x)
    r["me"] = {"version": ver, "date": date, "basis": basis, "offset": h, "family": None,
               "other_versions": sorted({x["version"] for x in mn} - {ver})}
    return {**r, "status": "found"}


def me_info(data, regs, me_r, beyond, budget=None):
    """ME 版本。先走 me_info_fpt（$FPT、名稱是 FTPR 的 `$CPD`；有結果就不動，既有世代的行為不變）；那條路是 unknown
    （或沒有 descriptor 時是 no-me-region）時，再試新世代的 CSE 配置（intel_cse_layout.py：CSE layout table → BPDT → FTPR／RBEP／NFTP 的 manifest）。
    只在那邊找到一致的版本才 found（basis 寫明走哪一條路）；認得出配置但版本不可用或互相矛盾 → 維持 unknown，原因接在 note 後面；
    不是這種配置 → 原樣回傳。範圍：有 descriptor 時是 ME 區域，沒有時是整個檔案（layout table 或 BPDT 要在檔案開頭）。"""
    r = me_info_fpt(data, regs, me_r, beyond, budget)
    if r["status"] == "found" or (regs is not None and (me_r is None or r["status"] == "no-me-region")):
        return r                                        # descriptor 沒有 ME 區域、或 ME 區域超出檔案（me_r 不存在）：沒有範圍可看
    if regs is not None:
        base, end = me_r["base"], min(me_r["limit"] + 1, len(data))
    else:
        base, end = 0, len(data)
    cse = load_sibling("intel_cse_layout").find_cse(data, base, end, budget)
    if cse["status"] == "none":
        return r
    if cse["status"] == "gap":
        if r["status"] == "no-me-region":              # 沒有 descriptor、其他 ME 結構也沒有：開頭碰巧像 layout table 不算有 ME
            return r
        return {**r, "status": "unknown", "note": "; ".join(x for x in (r["note"], "CSE layout/BPDT: " + cse["note"]) if x)}
    mn = me_manifests(data, base, end, budget, notes=r["incomplete"])
    return {**r, "status": "found", "standalone": regs is None,
            "note": "no usable $FPT or FTPR $CPD; the version comes from the BPDT main-program partitions (see basis)",
            "me": {"version": cse["version"], "date": bcd_date(cse["date_raw"], "ymd"), "basis": cse["basis"], "offset": cse["offset"],
                   "family": None, "other_versions": sorted({x["version"] for x in mn} - {cse["version"]})}}


def me_without_fpt(data, r, ff, budget=None):
    """me_info 的 2–4 步：沒有 descriptor、也沒有有 FTPR 那一項的 $FPT。"""
    fpt_txt = (f"$FPT at file offset 0x{ff['valid'][0]:x} has no FTPR entry" if ff["valid"] else "no $FPT with an FTPR entry")
    cpd = find_ftpr_cpd(data, budget)
    if cpd["capped"]:
        r["incomplete"].append(f"more than {MAX_FPT_SCAN} $CPD candidates; the rest were not checked")
    if cpd["manifest"]:
        p, h = cpd["manifest"]
        start = min([p] + ff["valid"])
        r["standalone"] = bool(ff["valid"]) and ff["valid"][0] <= 0x1010    # CSME 12 以後的單獨 ME 映像：$FPT 在 0x1000
        ver, date = mn2_version(data, h)
        mn = me_manifests(data, start, len(data), budget, notes=r["incomplete"])
        r["conflict"] = ftpr_conflict(data, h, [x for _, x in cpd["all"]])
        r["note"] = r["conflict"]
        r["me"] = {"version": ver, "date": date, "offset": h, "family": None,
                   "basis": f"FTPR $CPD FTPR.man ($CPD at file offset 0x{p:x}; no flash descriptor; {fpt_txt})",
                   "other_versions": sorted({x["version"] for x in mn} - {ver})}
        return {**r, "status": "found"}
    loose = me_manifests(data, budget=budget, notes=r["incomplete"])
    vers = f" ({', '.join(sorted({x['version'] for x in loose}))})" if loose else ""
    if ff["valid"] or cpd["seen"] or ff["capped"] or cpd["capped"]:
        what = "; ".join(x for x in (
            fpt_txt if ff["valid"] else None,
            (f"FTPR $CPD at file offset 0x{cpd['seen'][0]:x}: {cpd['why']}") if cpd["seen"] else "no $CPD named FTPR",
            "candidate limit reached" if ff["capped"] or cpd["capped"] else None) if x)
        return {**r, "loose": len(loose),
                "note": f"no flash descriptor; ME structures found but no usable FTPR manifest ({what})"
                + (f"; {len(loose)} $MN2 manifest(s){vers} are not reported as the CSE version" if loose else "")}
    return {**r, "status": "no-me-region", "loose": len(loose),
            "note": "no flash descriptor, no $FPT and no $CPD named FTPR (BIOS-region-only or capsule file)"
            + (f"; {len(loose)} $MN2 manifest(s) in the file are not reported as the CSE version{vers}" if loose else "")}


def fit_table(data, lo, hi, budget=None, where="file"):
    """FIT（Firmware Interface Table）→ dict。lo–hi 是對到 4 GB 以下的範圍（完整 SPI 映像是 BIOS 區域，結尾對到 4 GB；
    只有 BIOS 區域的檔案是整個檔案）。指標在 4 GB−0x40（8 bytes，高 32 bits 要是 0、位址在 4 GB 以下 16 MB 內），
    表頭 Address 欄位是 "_FIT_   "、type 0；表頭的 size 是項目數（含表頭），每項 16 bytes，type 0x01 是 microcode
    （位址指到 microcode header）。依 edk2-platforms IntelSiliconPkg FirmwareInterfaceTable.h、coreboot cbfstool/fit.c 與
    Documentation/soc/intel/fit.md；Intel FIT 規格本身沒有讀到（未核對），top swap 的配置不處理。
    status：found；not-found（沒有像 FIT 的指標，例如舊平台或 capsule）；invalid（指標像 FIT、但指到檔案外或不是 FIT 表頭）。"""
    out = {"status": "not-found", "offset": None, "entries": 0, "microcode": [], "note": None, "incomplete": []}

    def off(addr, need):
        o = hi - ((1 << 32) - addr)
        return o if lo <= o and o + need <= hi else None
    if hi - lo < 0x40:
        out["note"] = "file too small for a FIT pointer"
        return out
    ptr, high = struct.unpack_from("<II", data, hi - 0x40)
    if high != 0 or not FIT_LOWEST <= ptr < FIT_POINTER:
        out["note"] = f"no FIT pointer at 4 GB - 0x40 (file offset 0x{hi - 0x40:x}: 0x{high:08x}{ptr:08x})"
        return out
    t = off(ptr, 16)
    if t is None:
        out.update(status="invalid", note=f"FIT pointer 0x{ptr:08x} maps outside the {where}")
        out["incomplete"].append(f"FIT: {out['note']}; in_fit unknown")
        return out
    if data[t:t + 8] != b"_FIT_   " or data[t + 14] & 0x7F != 0:
        out.update(status="invalid", offset=t, note=f"FIT pointer 0x{ptr:08x} (file offset 0x{t:x}) has no _FIT_ header")
        out["incomplete"].append(f"FIT: {out['note']}; in_fit unknown")
        return out
    n = (u32(data, t + 8) & 0xFFFFFF) - 1
    out.update(status="found", offset=t, entries=max(n, 0))
    if struct.unpack_from("<H", data, t + 12)[0] != 0x0100:
        out["note"] = f"FIT header version 0x{struct.unpack_from('<H', data, t + 12)[0]:04x} (expected 0x0100)"
    if n > MAX_FIT_ENTRIES:
        out["incomplete"].append(f"FIT declares {n} entries; only the first {MAX_FIT_ENTRIES} were read")
        n = MAX_FIT_ENTRIES
    if t + 16 * (n + 1) > hi:
        n = max((hi - t) // 16 - 1, 0)
        out["incomplete"].append(f"FIT entries go past the end of the {where}; read {n}")
    spent = 0
    for i in range(1, n + 1):
        tick(budget, i)
        e = t + 16 * i
        if data[e + 14] & 0x7F != 0x01:
            continue
        a_lo, a_hi = struct.unpack_from("<II", data, e)
        o = off(a_lo, 48) if a_hi == 0 else None
        rec = {"entry": i, "address": f"0x{a_hi:08x}{a_lo:08x}" if a_hi else f"0x{a_lo:08x}", "offset": o, "valid": False}
        if o is None:
            rec["note"] = f"address outside the {where}"
        else:
            tsize = ucode_size(data, o)
            spent += tsize or 0
            if tsize is None:
                rec["note"] = "no valid microcode header at the address"
            elif spent > MAX_CHECKSUM:
                rec["note"] = f"not checked (checksum limit {MAX_CHECKSUM} bytes reached)"
            elif ucode_entry(data, o, tsize) is None:
                rec["note"] = "microcode checksum does not match"
            else:
                rec["valid"] = True
        if not rec["valid"]:
            out["incomplete"].append(f"FIT entry {i} (type 0x01 microcode, address {rec['address']}): {rec['note']}")
        out["microcode"].append(rec)
    return out


def amd_markers(data, budget=None):
    """AMD 平台的標記 → 依據的清單（空＝沒認出）。Embedded Firmware Structure（0x55AA55AA，在 coreboot amdfwread.c 列的固定位置）
    一個就算；PSP／BIOS 目錄的 cookie（$PSP、$PL2、$BHD、$BL2、combo 的 2PSP、2BHD，+8 的項目數要在 1–256）要有兩種不同的才算
    （單一個 cookie 在 Intel 映像或 nvflash 裡也可能巧合出現）。只是辨識平台，不解析內容。有 Intel descriptor 或 Intel microcode 時
    呼叫端不叫這個（見 bios_image）。"""
    efs = [f"AMD embedded firmware structure at 0x{o:x}" for o in AMD_EFS_OFFSETS if data[o:o + 4] == AMD_EFS_SIG]
    dirs = {}
    for i, m in enumerate(AMD_DIR_RE.finditer(data)):
        tick(budget, i)
        if i >= MAX_AMD_SCAN or len(dirs) >= 4:
            break
        p = m.start()
        if p + 16 <= len(data) and 1 <= u32(data, p + 8) <= 256:
            dirs.setdefault(m.group(), f"AMD {m.group().decode()} directory at 0x{p:x}")
    return efs + list(dirs.values()) if efs or len(dirs) >= 2 else []


def guid_str(b):
    return str(uuid.UUID(bytes_le=bytes(b))).upper()


class FvStats:
    """未壓縮的 UEFI firmware volume（`_FVH`）→ FFS 檔案 → section，統計壓縮的 section（**不解壓**）。
    依 edk2 MdePkg/Include/Pi/PiFirmwareVolume.h、PiFirmwareFile.h；壓縮方式的 GUID 依 MdeModulePkg.dec 與 BaseTools tools_def.template。
    - FV：header checksum（HeaderLength 範圍的 16-bit 加總為 0）要對；檔案系統是 FFS2／FFS3 才走訪（NVRAM 等其他的只計數）。
      檔案從 ext header 之後（沒有就 HeaderLength）開始、8 bytes 對齊；遇到空白（erase polarity 的值）就停。
    - 檔案：state 的最高位是 DATA_VALID 或 MARKED_FOR_UPDATE 的才算；type 0x02–0x0F（有 section 的類型）才走 section。
    - section（4 bytes 對齊）：COMPRESSION 的 type 1 → efi-standard（EFI／Tiano 標準壓縮），type 0（沒壓縮）往下走；
      GUID-defined：LZMA、LZMA F86、Brotli、Tiano custom 依 GUID 計數，其他「需要處理」的依 GUID 另計（沒有解析），
      不需要處理的（例如 CRC32）往下走。FV image section 不往下走：每個 FV 都由全檔的 `_FVH` 掃描各算一次（巢狀的也是），不會重複。
    上限：MAX_FV 個 FV、MAX_FFS_ITEMS 個檔案＋section、巢狀 MAX_SECTION_DEPTH；用完記 incomplete。結構不對（大小超出範圍等）
    只停那一個 FV 或 section 串，記在 notes（數量可能偏少）。"""

    def __init__(self, data, lo, hi, budget=None):
        self.data, self.budget = data, budget
        self.r = {"volumes": 0, "volumes_other_fs": 0, "files": 0, "sections": 0, "compressed": {}, "guided_other": {},
                  "notes": [], "incomplete": []}
        self.items = 0
        self.full = False
        for i, m in enumerate(FVH_RE.finditer(data, lo, hi)):
            tick(budget, i)
            if self.full:
                break
            if i >= MAX_FVH_SCAN:
                self.r["incomplete"].append(f"UEFI: more than {MAX_FVH_SCAN} _FVH candidates; the rest were not checked")
                break
            p = m.start() - 0x28
            if p >= lo:
                self.volume(p, hi)

    def note(self, x):
        if len(self.r["notes"]) < 16:
            self.r["notes"].append(x)

    def count(self):
        self.items += 1
        tick(self.budget, self.items)
        if self.items > MAX_FFS_ITEMS and not self.full:
            self.full = True
            self.r["incomplete"].append(f"UEFI: more than {MAX_FFS_ITEMS} FFS files and sections; the rest were not counted")
        return not self.full

    def volume(self, p, hi):
        d = self.data
        if p + 0x48 > hi:
            return
        fvlen = struct.unpack_from("<Q", d, p + 0x20)[0]
        hlen, _ck, ext_off = struct.unpack_from("<HHH", d, p + 0x30)
        if not 0x48 <= hlen <= 0x1000 or hlen % 2 or p + hlen > hi or fvlen < hlen or sum(struct.unpack_from(f"<{hlen // 2}H", d, p)) & 0xFFFF:
            return
        if self.r["volumes"] + self.r["volumes_other_fs"] >= MAX_FV:
            self.full = True
            self.r["incomplete"].append(f"UEFI: more than {MAX_FV} firmware volumes; the rest were not counted")
            return
        if FFS_FS.get(guid_str(d[p + 0x10:p + 0x20])) is None:
            self.r["volumes_other_fs"] += 1
            return
        self.r["volumes"] += 1
        end = p + fvlen
        if end > hi:
            self.note(f"FV at 0x{p:x}: length 0x{fvlen:x} goes past the end; walked to 0x{hi:x}")
            end = hi
        erase = 0xFF if u32(d, p + 0x2C) & 0x800 else 0x00
        q = p + hlen
        if ext_off and p + ext_off + 0x14 <= end and u32(d, p + ext_off + 0x10) >= 0x14:   # EFI_FIRMWARE_VOLUME_EXT_HEADER 之後
            q = p + ext_off + u32(d, p + ext_off + 0x10)
        while True:
            q = p + ((q - p + 7) & ~7)
            if q + 0x18 > end or d[q:q + 0x18] == bytes([erase]) * 0x18:
                return
            if not self.count():
                return
            attr, size, hs = d[q + 0x13], int.from_bytes(d[q + 0x14:q + 0x17], "little"), 0x18
            if attr & 0x01:                      # FFS_ATTRIB_LARGE_FILE：EFI_FFS_FILE_HEADER2，64-bit ExtendedSize
                if q + 0x20 > end:
                    return self.note(f"FV at 0x{p:x}: large-file header at 0x{q:x} goes past the end")
                size, hs = struct.unpack_from("<Q", d, q + 0x18)[0], 0x20
            if size < hs or q + size > end:
                return self.note(f"FV at 0x{p:x}: FFS file at 0x{q:x} has an invalid size 0x{size:x}; rest of the FV not walked")
            st = d[q + 0x17] ^ erase              # erase polarity 1 時 state 位元是反的
            if st and st.bit_length() - 1 in (2, 3):     # 最高位 EFI_FILE_DATA_VALID 0x04 或 EFI_FILE_MARKED_FOR_UPDATE 0x08
                self.r["files"] += 1
                if 0x02 <= d[q + 0x12] <= 0x0F:
                    self.sections(q + hs, q + size, 0)
            q += size

    def sections(self, lo, hi, depth):
        d = self.data
        if depth > MAX_SECTION_DEPTH:
            self.r["incomplete"].append(f"UEFI: sections nested deeper than {MAX_SECTION_DEPTH} at 0x{lo:x} were not walked")
            return
        s = lo
        while s + 4 <= hi:
            if not self.count():
                return
            size, typ, hs = int.from_bytes(d[s:s + 3], "little"), d[s + 3], 4
            if size == 0xFFFFFF:                  # EFI_COMMON_SECTION_HEADER2
                if s + 8 > hi:
                    return self.note(f"section at 0x{s:x}: extended header goes past the file")
                size, hs = u32(d, s + 4), 8
            if size < hs or s + size > hi:
                return self.note(f"section at 0x{s:x} has an invalid size 0x{size:x}; rest of the file not walked")
            self.r["sections"] += 1
            if typ == 0x01 and size >= hs + 5:     # EFI_COMPRESSION_SECTION：UncompressedLength、CompressionType
                ctype = d[s + hs + 4]
                if ctype == 0:
                    self.sections(s + hs + 5, s + size, depth + 1)
                else:
                    k = STANDARD_COMPRESSION if ctype == 1 else f"compression-type-0x{ctype:02x}"
                    self.r["compressed"][k] = self.r["compressed"].get(k, 0) + 1
            elif typ == 0x02 and size >= hs + 20:  # EFI_GUID_DEFINED_SECTION：GUID、DataOffset、Attributes
                g = guid_str(d[s + hs:s + hs + 16])
                doff, attr = struct.unpack_from("<HH", d, s + hs + 16)
                if g in COMPRESSION_GUIDS:
                    k = COMPRESSION_GUIDS[g]
                    self.r["compressed"][k] = self.r["compressed"].get(k, 0) + 1
                elif attr & 0x01:                  # EFI_GUIDED_SECTION_PROCESSING_REQUIRED：不認得的處理，沒有解析
                    self.r["guided_other"][g] = self.r["guided_other"].get(g, 0) + 1
                elif hs + 20 <= doff <= size:
                    self.sections(s + doff, s + size, depth + 1)
                else:
                    self.note(f"GUID-defined section at 0x{s:x}: data offset 0x{doff:x} outside the section")
            s = lo + ((s + size - lo + 3) & ~3)


def uefi_stats(data, lo, hi, budget=None):
    return FvStats(data, lo, hi, budget).r


def bios_image(data, budget=None):
    regs, why, beyond = descriptor(data)
    me_r = next((r for r in regs or () if r["name"] == "me"), None)
    bios_r = next((r for r in regs or () if r["name"] == "bios"), None)
    mi = me_info(data, regs, me_r, beyond, budget)
    lo, hi = (bios_r["base"], bios_r["limit"] + 1) if bios_r else (0, len(data))
    mc, mc_note = microcodes(data[lo:hi], budget) if bios_r else microcodes(data, budget)
    for x in mc:
        x["offset"] += lo
    if mi["standalone"]:               # 單獨的 ME 更新檔：沒有 BIOS 區域，FIT 不適用
        fit = {"status": "not-applicable", "offset": None, "entries": 0, "microcode": [], "incomplete": [],
               "note": "standalone ME image (no BIOS region)"}
    else:
        fit = fit_table(data, lo, hi, budget, "BIOS region" if bios_r else "file")
    by_off = {x["offset"]: x for x in mc}
    for e in fit["microcode"]:         # FIT 指到、但全檔掃描沒有列的（例如 checksum 上限）：照樣列出
        if e["valid"] and e["offset"] not in by_off:
            u = ucode_entry(data, e["offset"], ucode_size(data, e["offset"]))
            mc.append(u)
            by_off[u["offset"]] = u
    fit_offs = {e["offset"] for e in fit["microcode"] if e["valid"]}
    try:
        cbfs = load_sibling("coreboot_cbfs").analyze(data, lo, hi, budget)
        cbfs_err = None
    except PARSE_ERRORS as e:             # 有檢查邊界，不該發生；發生就記下來，其他部分照跑
        cbfs, cbfs_err = None, f"CBFS parse failed ({type(e).__name__})"
    seen, ucodes = {}, []
    # 同一個 microcode 在映像裡可能有兩份（例如備援），記一次；任一份在 FIT 就算 in_fit（fit_offset 是 FIT 指到的那份）。
    # FIT 沒找到或不能用 → in_fit 是 None（不知道），不是 False
    for x in sorted(mc, key=lambda x: x["offset"]):
        k = (x["cpuid"], x["platform_id"], x["revision"], x["sha256"])
        u = seen.setdefault(k, x)
        if u is x:
            x["in_fit"] = False if fit["status"] == "found" else None
            ucodes.append(x)
        if x["offset"] in fit_offs:
            u["in_fit"] = True
            u.setdefault("fit_offset", x["offset"])
        for l in (cbfs["microcode_files"] if cbfs else ()):     # microcode 在 CBFS 的 cpu_microcode_blob.bin 裡：加 found-in（不另產元件）
            w = cbfs_where(l)
            if l["offset"] <= x["offset"] < l["offset"] + l["length"] and w not in u.setdefault("cbfs_files", []):
                u["cbfs_files"].append(w)
    amd = [] if regs is not None or ucodes else amd_markers(data, budget)     # 有 Intel descriptor 或 Intel microcode：不是 AMD
    amd_r, amd_err = None, None
    if amd:                            # AMD 平台：PSP／BIOS 目錄、微碼、AGESA（解析在 amd_psp.py；沒有 Intel descriptor，所以範圍是整個檔案）
        try:
            amd_r = load_sibling("amd_psp").analyze(data, budget, (OverBudget,))
        except (Fail, *PARSE_ERRORS) as e:
            amd_err = str(e) if isinstance(e, Fail) else f"AMD PSP parse failed ({type(e).__name__})"
    uefi = uefi_stats(data, lo, hi, budget)
    ibv = ibv_hints(data[lo:hi] if bios_r else data)
    evidence = [k for k, v in (("descriptor", regs is not None), ("me", mi["me"] or mi["status"] == "unknown" or mi["loose"]),
                               ("microcode", ucodes or mc_note), ("fit", fit["status"] == "found"), ("uefi", uefi["volumes"] or uefi["incomplete"]), ("cbfs", cbfs or cbfs_err),
                               ("amd", amd)) if v]
    if not evidence:
        return None                    # microcode 沒找完也要記下來（不能變成「沒有 BIOS 結構」）
    incomplete = ([f"region beyond the end of the file (truncated image?): {x}" for x in beyond] + ([mc_note] if mc_note else [])
                  + [f"ME: {x}" for x in mi["incomplete"]]
                  + fit.pop("incomplete") + uefi.pop("incomplete")
                  + ([cbfs_err] if cbfs_err else []) + [f"CBFS: {x}" for x in (cbfs["incomplete"] if cbfs else ())]
                  + (amd_r["incomplete"] if amd_r else []))
    gaps = list(cbfs["gaps"]) if cbfs else []
    if amd_r:
        gaps += amd_r["gaps"]
    elif amd:
        gaps.append("AMD platform recognised (" + "; ".join(amd[:2]) + f"): the PSP/BIOS directory parser did not run ({amd_err}); "
                    "AMD microcode, PSP firmware and AGESA are not listed (this is not 'no microcode')")
    n_comp, n_other = sum(uefi["compressed"].values()), sum(uefi["guided_other"].values())
    if n_comp:
        gaps.append(f"{n_comp} compressed UEFI sections not parsed (" +
                    ", ".join(f"{k} {v}" for k, v in sorted(uefi["compressed"].items())) + "); modules and versions inside are not listed"
                    + ("; counts may be low (see uefi.notes)" if uefi["notes"] else ""))
    if n_other:
        gaps.append(f"{n_other} GUID-defined UEFI sections that need processing (unknown GUID) not parsed")
    return {"descriptor": regs is not None, "descriptor_note": why, "regions": regs or [], "me": mi["me"], "me_status": mi["status"],
            "me_note": mi["note"], "me_conflict": mi["conflict"], "microcode": ucodes, "fit": fit, "platform": "amd" if amd else None, "amd_markers": amd, "amd": amd_r,
            "uefi": uefi, "cbfs": cbfs, "ibv_hint": ibv, "incomplete": incomplete, "gaps": gaps, "evidence": evidence}


# ---------- 版本清單 ----------

def norm(component, field, v):
    v = str(v or "").strip()
    if v.lower() in {u.lower() for u in UNKNOWN}:
        return "?"
    if component == "microcode" and field == "identifier":
        parts = re.split(r"\s*[/:]\s*", v, maxsplit=1)
        cpuid = parts[0].upper().removeprefix("0X").zfill(8)
        if len(parts) == 2 and parts[1]:
            try:
                return f"{cpuid}/0x{int(parts[1], 16):02X}"      # 有寫 platform id：只比這個 platform id
            except ValueError:
                return f"{cpuid}/{parts[1]}"
        return cpuid
    if component == "microcode" and field == "version":
        try:
            return f"0x{int(v, 16):X}"
        except ValueError:
            return v
    if component == "vbios" and field == "identifier":
        return v.lower().removeprefix("0x").zfill(4)
    return v.upper() if component == "vbios" else v


def read_manifest(path):
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise Fail(f"讀不到版本清單 {path}（{type(e).__name__}）")
    lines = list(csv.reader(io.StringIO(text)))
    # 欄名那一列之前可以有標題列（Excel 另存 CSV 時的分組標題）
    hi = next((k for k, ln in enumerate(lines) if set(MANIFEST_COLS) <= {x.strip() for x in ln}), None)
    if hi is None:
        have = max(lines[:5], key=lambda ln: len(set(ln) & set(MANIFEST_COLS)), default=[])
        missing = [c for c in MANIFEST_COLS if c not in {x.strip() for x in have}]
        raise Fail(f"版本清單少了欄位：{', '.join(missing)}（範本 tools/cra/data/fw-manifest-template.csv）")
    names = [x.strip() for x in lines[hi]]
    rows = []
    for i, ln in enumerate(lines[hi + 1:], start=hi + 2):
        r = dict(zip(names, ln))
        if not any((r.get(c) or "").strip() for c in MANIFEST_COLS) or (r.get("product") or "").strip().startswith("#"):
            continue                    # 空白列、# 開頭的範例或註解列
        comp = (r.get("component") or "").strip().lower()
        if comp not in COMPONENTS:
            raise Fail(f"版本清單第 {i} 列：component「{comp}」不是 {', '.join(COMPONENTS)} 之一")
        rows.append({"line": i, **{c: (r.get(c) or "").strip() for c in MANIFEST_COLS}, "component": comp})
    return rows


def extracted_items(inv):
    """解析結果 → 每一份（不同雜湊的映像或 ROM）一筆 {component, identifier, platform_id, version, source}。
    逐份比對：不能因為「某一份符合」就把其他份蓋掉。"""
    items = []
    for v in inv["vbios"]:
        items.append({"component": "vbios", "identifier": norm("vbios", "identifier", v["device"]), "platform_id": None,
                      "version": norm("vbios", "version", v["version"]), "sources": v["locations"]})
    for b in inv["bios"]:
        if b["me"]:
            items.append({"component": "me", "identifier": "", "platform_id": None, "version": b["me"]["version"], "sources": b["locations"]})
        for u in b["microcode"]:
            items.append({"component": "microcode", "identifier": u["cpuid"], "platform_id": u["platform_id"],
                          "version": u["revision"], "sources": b["locations"]})
            for x in u["extended_signatures"]:     # 同一份 microcode 也適用的 CPUID：清單有填才比，沒填不算「只有映像」
                items.append({"component": "microcode", "identifier": x["cpuid"], "platform_id": x["platform_id"],
                              "version": u["revision"], "sources": b["locations"], "extended": True})
    return items


def ident_matches(comp, ident, item):
    if item["component"] != comp:
        return False
    if comp == "microcode" and "/" in ident:
        cpuid, pf = ident.split("/", 1)
        return item["identifier"] == cpuid and item["platform_id"] == pf
    return item["identifier"] == ident


def version_matches(comp, declared, extracted):
    """ME 可以只填到 hotfix（16.1.30 對 16.1.30.2307）；其他要完全相同（已正規化）。"""
    if not extracted:
        return False
    return declared == extracted or (comp == "me" and extracted.startswith(declared + "."))


def compare(inv, rows):
    items = extracted_items(inv)
    out, accounted = [], set()          # accounted：有清單列對應到的那幾份（符合、或清單填「不知道」）
    declared_keys = []
    for r in rows:
        comp = r["component"]
        ident = norm(comp, "identifier", r["identifier"]) if comp in ("microcode", "vbios", "module") else ""
        ver = norm(comp, "version", r["version"])
        base = {"component": comp, "identifier": ident or None, "declared": r["version"] or None, "line": r["line"],
                "firmware": r["firmware"] or None, "firmware_version": r["firmware_version"] or None}
        cands = [k for k, it in enumerate(items) if ident_matches(comp, ident, it)] if comp in EXTRACTABLE else []
        found = [{"version": items[k]["version"], "file": f} for k in cands for f in items[k]["sources"]]
        extracted = ", ".join(sorted({f["version"] for f in found if f["version"]})) or None
        if ver == "?" or not ver:
            accounted.update(cands)
            out.append({**base, "result": "unknown", "extracted": extracted, "found": found, "verifiable": comp in EXTRACTABLE})
            continue
        if comp not in EXTRACTABLE:
            out.append({**base, "result": "declared-only", "extracted": None, "found": [], "verifiable": False})
            continue
        declared_keys.append((comp, ident))
        if not cands:
            out.append({**base, "result": "declared-only", "extracted": None, "found": [], "verifiable": True})
            continue
        hits = [k for k in cands if version_matches(comp, ver, items[k]["version"])]
        accounted.update(hits or cands)         # 整列 mismatch 時這幾份已經在這一列報了，不再另列
        out.append({**base, "result": "match" if hits else "mismatch", "extracted": extracted, "found": found, "verifiable": True})
    # 沒有被任何清單列對應到的那幾份：清單有這個元件、別份符合但這份的版本不在清單上 → mismatch（例如兩個 BIOS 檔的 ME 不同、
    # 清單只填了其中一個）；清單沒有這個元件 → extracted-only
    left = {}
    for k, it in enumerate(items):
        if k in accounted or it.get("extended"):
            continue
        listed = any(ident_matches(c, i, it) for c, i in declared_keys)
        key = (it["component"], it["identifier"] + (f"/{it['platform_id']}" if listed and it["platform_id"] else ""), it["version"], listed)
        left.setdefault(key, []).extend(it["sources"])
    for (comp, ident, ver, listed), files in sorted(left.items(), key=lambda x: tuple(str(y) for y in x[0])):
        out.append({"component": comp, "identifier": ident or None, "declared": None, "line": None, "firmware": None,
                    "firmware_version": None, "result": "mismatch" if listed else "extracted-only", "extracted": ver,
                    "found": [{"version": ver, "file": f} for f in sorted(set(files))], "verifiable": True,
                    **({"note": "this image's version is not in the version list"} if listed else {})})
    return out


# ---------- CycloneDX ----------

def prop(n, v):
    return {"name": n, "value": str(v)}


def hlist(x):
    return [{"alg": "SHA-256", "content": x["sha256"]}, {"alg": "SHA-512", "content": x["sha512"]}]


def fname(label):
    return label.rsplit("/", 1)[-1].rsplit("!", 1)[-1]


ME_NAME = "Intel CSE firmware"          # CSME、TXE、SPS 分不出來（manifest 沒有可靠欄位），不猜；family 另記

# dumpling 加的 property（命名空間 dumpling:；既有的 sca-center: 維持不變，下游報告工具依賴它）。
# 這個工具只做版本與雜湊的解析，不比對漏洞：每個元件都是 NOT_ASSESSED，note 寫原因（下游不要把它讀成「沒有漏洞」）。
VULN_ASSESSMENT = "dumpling:vuln-assessment"
VULN_NOTE = "dumpling:vuln-assessment-note"
VERSION_STATUS = "dumpling:version-status"          # OK＝版本從映像（或版本清單）讀到；GAP＝元件沒有 version（省略，不猜）
NOT_ASSESSED = "NOT_ASSESSED"
ASSESS_NOTES = {
    "intel": "Intel advisories cannot be matched by machine; manual cross-check against Intel advisories is required",
    "intel-microcode": "advisory candidates (if any) are in the dumpling:advisory-* properties: they are release-level candidates from Intel's public "
                       "microcode release notes, not confirmed findings; manual cross-check against Intel advisories is required",
    "nvidia-vbios": "vBIOS vulnerabilities are communicated by NVIDIA through partner notifications; this tool only confirms version and hash; "
                    "the version and PCI device ID are also looked up in a reviewed table of NVIDIA product-security bulletins "
                    "(dumpling:advisory-*), and no match does not mean no vulnerability",
    "coreboot": "NVD has almost no coreboot data (its CPE and version forms do not match coreboot or vendor forks such as Dasharo); "
                "no vulnerability matching is possible, and no finding would not mean no vulnerability",
    "edk2-payload": "the edk2 version is not known (only the build configuration's git revision of the vendor fork was read), so vulnerability "
                    "matching by version is not possible",
    "vbt": "Intel advisories cannot be matched by machine; manual cross-check against Intel advisories is required "
           "(the VBT is a display configuration data table, not executable code)",
    "amd": "AMD security bulletins cannot be matched by machine; manual cross-check against AMD product security bulletins is required "
           "(the version is the one read from the image: PSP firmware header, microcode patch level or AGESA string)",
    "image": "no vulnerability matching at this level; this tool only reports the parsed structure, versions and hashes",
}
# Intel CSME 的 CPE。查證（NVD 公開 API，2026-11-13）：
# - CPE 字典（https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:o:intel:converged_security_management_engine_firmware:*）
#   有 53 筆，part 是 o、vendor intel、product converged_security_management_engine_firmware；版本只有 major.minor 或 major.minor.hotfix
#   （例如 11.8.50、12.0.45、14.5.11；沒有四段、字典沒有 14.5.11 之後的版本）。拼成 converged_security_and_management_engine_firmware 的 o 類 CPE 是 0 筆
#   （`and` 的拼法只出現在 part a 的 converged_security_and_management_engine）。
# - CVE 的 configurations（https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:intel:converged_security_management_engine_firmware）
#   36 筆 CVE，最新是 CVE-2022-38102：用 cpe:…:* 加三段的 versionStart／End（如 versionEndExcluding 16.1.27、versionStartIncluding 11.0）。
#   所以 NVD 的 CSME 資料止於 2022，之後 Intel 公告的 CSME 弱點 NVD 沒有這個 CPE 的設定；Grype 沒比到不代表沒有漏洞（臨時 DT 關閉 NVD 資料源，只有 CPE 的元件在 DT 比不到）。
# - 其他 firmware 是不同的 product：TXE ＝ trusted_execution_engine_firmware（版本 3.0～4.0.x）、SPS ＝ server_platform_services_firmware
#   （3.0.6～5.x，版本字串格式很雜），兩者的版本都低於 11。AMT ＝ active_management_technology_firmware（part o，版本也有 11.x～14.5.x）是另一個 product，
#   CSME 的 CPE 比不到 AMT 的 CVE 設定。
# 版本轉換：$MN2 的版本是 major.minor.hotfix.build 四段；NVD 只有前三段，所以 CPE 只放前三段（14.0.47.1558 → 14.0.47），元件的 version 維持四段。
# family：映像分不出來。版本清單的 me 列寫明 CSME → 帶；寫 ME／TXE／SPS → 不帶；映像沒有清單時，major 版本在 11～30 之間推定為 CSME
# （TXE、SPS 的版本都低於 11；上限 30 是我們的判斷：CSME 大約每年加一個 major，目前最高約 20；$MN2 裡雜散的欄位值會有幾百到幾萬，超過 30 就不是這個欄位）。
# dumpling:cpe-basis 的值固定是 listed（版本清單寫明）或 inferred（由版本推定，比對結果待人審），說明在 dumpling:cpe-basis-note；
# major 小於 11 或大於 30（11 與 30 本身都帶）分不出來或不合理 → 不帶、標 GAP（dumpling:cpe-gap）。
# microcode、NVIDIA vBIOS 沒有標準的 purl／CPE，不自己發明。
CSME_CPE = "cpe:2.3:o:intel:converged_security_management_engine_firmware:{}:*:*:*:*:*:*:*"
CSME_MIN_MAJOR = 11
CSME_MAX_MAJOR = 30
CPE_VERSION = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.[0-9]+)?")
CPE_NOTE = ("NVD CPE and version-range data for Intel CSME is incomplete (the NVD CPE dictionary stops at CSME 14.5.11 and the CVE "
            "configurations at CVE-2022-38102); no Grype match does not mean there are no vulnerabilities (the temporary Dependency-Track "
            "has the NVD source disabled, so a component with only a CPE is not matched there); the Intel advisories (INTEL-SA) are authoritative")
CPE_PROPS = ("dumpling:cpe-basis", "dumpling:cpe-basis-note", "dumpling:cpe-note", "dumpling:cpe-gap")


def csme_cpe_info(me):
    """ME 的 NVD CPE 判斷 → (cpe 或 None, basis（listed／inferred）或 None, gap 原因或 None)。
    要有三段以上的純數字版本；family 要是 CSME（版本清單），或 major 在 11～30（推定）；其他一律不帶並寫 gap 原因。"""
    if not me:
        return None, None, None
    if me.get("family_conflict"):
        return None, None, ("the version list gives conflicting families for this version (版本清單 family 矛盾): "
                            + ", ".join(me["family_conflict"]) + "; nothing is inferred, no CPE")
    m = CPE_VERSION.fullmatch(me.get("version") or "")
    if not m:
        return None, None, "ME version is not a plain major.minor.hotfix[.build] number; no CPE"
    major, minor, hotfix = (int(x) for x in m.groups())
    fam = me.get("family")
    ver = f"{major}.{minor}.{hotfix}"
    if fam == "CSME":
        return CSME_CPE.format(ver), "listed", None
    if fam:
        return None, None, f"family {fam} (version list) is not CSME; NVD uses a different product for it, no CPE"
    if CSME_MIN_MAJOR <= major <= CSME_MAX_MAJOR:
        return CSME_CPE.format(ver), "inferred", None
    if major > CSME_MAX_MAJOR:
        return None, None, f"major version {major} is above {CSME_MAX_MAJOR}, which is not plausible for a CSME version field; no CPE"
    return None, None, f"family not readable from the image and major version {major} < {CSME_MIN_MAJOR} could be ME, TXE, SPS or CSME; no CPE"


def csme_cpe(me):
    """ME 的 CPE；判斷不了（family 不是 CSME 且推定不了、版本不是點分數字）時是 None（不填）。"""
    return csme_cpe_info(me)[0]


def csme_basis_note(me, basis):
    """dumpling:cpe-basis 的說明文字（值本身只有 listed／inferred）。"""
    m = CPE_VERSION.fullmatch(me["version"])
    ver = f"{int(m.group(1))}.{int(m.group(2))}.{int(m.group(3))}"
    drop = "" if m.group(0) == ver else f"; the build number is dropped (NVD CSME versions are major.minor.hotfix): {me['version']} -> {ver}"
    if basis == "listed":
        return "family CSME is declared in the version list" + drop
    return (f"family is not readable from the image and is inferred from the version: major {m.group(1)} is in {CSME_MIN_MAJOR}..{CSME_MAX_MAJOR} "
            "(on NVD the TXE trusted_execution_engine_firmware and SPS server_platform_services_firmware versions are all below 11; "
            "AMT active_management_technology_firmware is a different product that this CPE does not match); the match result needs human review" + drop)


def cpe_props(me):
    """ME 元件的 CPE 相關 property：有 CPE → basis（listed／inferred）、basis-note、note；沒有 → gap 原因。"""
    cpe, basis, gap = csme_cpe_info(me)
    if cpe:
        return [prop("dumpling:cpe-basis", basis), prop("dumpling:cpe-basis-note", csme_basis_note(me, basis)), prop("dumpling:cpe-note", CPE_NOTE)]
    return [prop("dumpling:cpe-gap", gap)] if gap else []


def assessed(c, kind):
    """加漏洞比對狀態與版本狀態的 property（每個元件都要有）。版本讀不到時 version 本來就省略（CycloneDX 規則），這裡標 GAP。"""
    c["properties"] += [prop(VULN_ASSESSMENT, NOT_ASSESSED), prop(VULN_NOTE, ASSESS_NOTES[kind]),
                        prop(VERSION_STATUS, "OK" if c.get("version") else "GAP")]
    return c


def in_fit_text(u):
    return {True: "true", False: "false", None: "unknown"}[u["in_fit"]]


def in_fit_basis(b, u):
    f = b["fit"]
    if u["in_fit"]:
        return f"FIT type 0x01 entry points at file offset 0x{u['fit_offset']:x} (FIT at file offset 0x{f['offset']:x})"
    if u["in_fit"] is False:
        return f"no FIT type 0x01 entry points at this microcode (FIT at file offset 0x{f['offset']:x})"
    return f"FIT {f['status']}" + (f": {f['note']}" if f["note"] else "")


# coreboot 的 purl：只有確定上游時才填，而且 commit 必須是從映像讀到的完整 40 碼。
# Dasharo 的 coreboot 是 github.com/Dasharo/coreboot 的 fork；revision 檔有 DASHARO_VERSION 才算 Dasharo。短碼（例如 12 碼）不填。
# edk2：config 的 CONFIG_EDK2_REPOSITORY 是 https://github.com/Dasharo/edk2 而且 CONFIG_EDK2_TAG_OR_REV 是完整 40 碼才填。
FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
DASHARO_EDK2_URL = re.compile(r"https://github\.com/dasharo/edk2(?:\.git)?/?", re.I)


def coreboot_purl(it):
    """→ (purl 或 None, 沒填的原因或 None)。"""
    rev, dasharo = it.get("git_revision"), it.get("dasharo_version")
    if not rev:
        return None, None
    if not dasharo:
        return None, "purl omitted: the upstream of this coreboot build cannot be determined from the image"
    if not FULL_COMMIT.fullmatch(rev):
        return None, f"purl omitted: the git revision in the image is abbreviated ({len(rev)} characters), not a full 40-character commit"
    return f"pkg:github/dasharo/coreboot@{rev}", None


def edk2_purl(keys):
    rev, repo = keys.get("CONFIG_EDK2_TAG_OR_REV"), keys.get("CONFIG_EDK2_REPOSITORY")
    if rev and repo and DASHARO_EDK2_URL.fullmatch(repo) and FULL_COMMIT.fullmatch(rev):
        return f"pkg:github/dasharo/edk2@{rev}"
    return None


def cbfs_components(b, img, comps, sub):
    """b["cbfs"]（coreboot_cbfs.analyze 的結果）→ coreboot、payload、FSP、VBT 元件，都掛在 BIOS 映像底下。"""
    cb = b.get("cbfs")
    if not cb:
        return
    where = lambda it: [prop("sca-center:found-in", cbfs_where(l)) for l in it["locations"]]
    for n, it in enumerate(cb["coreboot"]):
        cfg = it["config"]
        ref = f"{img}:coreboot:{n}:{(it['hash'] or {'sha256': 'nohash'})['sha256'][:12]}"
        c = {"type": "firmware", "bom-ref": ref, "name": "coreboot", "properties": [
            prop("sca-center:cbfs-evidence", ", ".join(it["evidence_files"]) or "bootblock/romstage only")]}
        if it["hash"]:
            c["hashes"] = hlist(it["hash"])
            c["properties"].append(prop("sca-center:hash-basis", "CBFS file(s): " + ", ".join(it["evidence_files"])))
        if it["version"]:
            c["version"] = it["version"]
            c["properties"].append(prop("sca-center:version-basis", f"COREBOOT_VERSION in the CBFS file '{it['version_basis']}'"))
        for k, v in (("git-revision", it["git_revision"]), ("dasharo-version", it["dasharo_version"]), ("extra-version", it["extra_version"]),
                     ("build", it["build"]), ("build-time", it["build_time"]), ("dmi-date", it["dmi_date"]),
                     ("mainboard-vendor", it["mainboard_vendor"]), ("mainboard-part", it["mainboard_part"])):
            if v:
                c["properties"].append(prop(f"sca-center:coreboot-{k}", v))
        purl, why = coreboot_purl(it)
        if purl:
            c["purl"] = purl
        if why:
            c["properties"].append(prop("sca-center:note", why))
        if cfg:
            c["properties"] += [prop("sca-center:coreboot-config-sha256", cfg["sha256"]), prop("sca-center:coreboot-config-size", cfg["size"])]
            c["properties"] += [prop("sca-center:coreboot-config", f"{k}={v}") for k, v in sorted(cfg["keys"].items())]
            if cfg["soc"]:
                c["properties"].append(prop("sca-center:coreboot-config-soc", ", ".join(x[len("CONFIG_"):] for x in cfg["soc"])
                                            + (f" (and {cfg['soc_total'] - len(cfg['soc'])} more)" if cfg["soc_total"] > len(cfg["soc"]) else "")))
        c["properties"] += where(it)
        comps.append(assessed(c, "coreboot"))
        sub.append(ref)
    for it in cb["payloads"]:
        cfg = it["config"]
        keys = cfg["keys"] if cfg else {}
        pl = cfg["payload"] if cfg else []
        edk2 = "CONFIG_PAYLOAD_EDK2" in pl
        ref = f"{img}:payload:{it['hash']['sha256'][:12]}"
        name = "edk2 payload" if edk2 else (f"coreboot payload ({pl[0][len('CONFIG_PAYLOAD_'):].lower()})" if len(pl) == 1 else "coreboot payload")
        c = {"type": "firmware", "bom-ref": ref, "name": name, "hashes": hlist(it["hash"]),
             "properties": [prop("sca-center:payload-file", it["file"]), prop("sca-center:payload-format", "SELF"),
                            prop("sca-center:payload-size", it["length"]),
                            *([prop("sca-center:payload-entry", it["entry"])] if it["entry"] else []),
                            *[prop("sca-center:payload-segment", f"{x['type']} {x['compression']} offset={x['offset']} load={x['load_address']} "
                                                                 f"length={x['length']} memory={x['memory_length']}") for x in it["segments"]],
                            *[prop("sca-center:coreboot-config", f"{k}={keys[k]}") for k in sorted(keys) if k.startswith("CONFIG_EDK2")],
                            *[prop("sca-center:coreboot-config", f"{k}=y") for k in pl]]}
        if cfg and it.get("config_source") == "other CBFS region":
            c["properties"].append(prop("sca-center:note", "build config taken from another CBFS region (this payload's region has no 'config')"))
        if not cfg:
            c["properties"].append(prop("sca-center:note", "no CBFS 'config' file: the payload's identity (edk2 or other) is not known"))
        purl = edk2_purl(keys) if edk2 else None
        if purl:
            c["purl"] = purl
        c["properties"] += where(it)
        comps.append(assessed(c, "edk2-payload" if edk2 else "image"))
        sub.append(ref)
    for it in cb["fsp"]:
        ref = f"{img}:fsp:{it['hash']['sha256'][:12]}"
        c = {"type": "firmware", "bom-ref": ref, "name": f"Intel FSP-{it['type']} ({it['image_id']})", "version": it["revision"],
             "manufacturer": {"name": "Intel Corporation"}, "hashes": hlist(it["hash"]),
             "properties": [prop("sca-center:version-basis", "FSP_INFO_HEADER ImageRevision (FSPH)"), prop("sca-center:fsp-type", it["type"]),
                            prop("sca-center:fsp-image-id", it["image_id"]), prop("sca-center:fsp-spec-version", it["spec_version"]),
                            prop("sca-center:fsp-header-revision", it["header_revision"]), prop("sca-center:fsp-image-base", it["image_base"]),
                            prop("sca-center:fsp-image-size", it["image_size"]), prop("sca-center:fsp-component-attribute", it["component_attribute"]),
                            prop("sca-center:fsp-build", f"{it['build_type']}, {it['release_type']}"), prop("sca-center:cbfs-file", it["file"]),
                            prop("sca-center:cbfs-stored-sha256", it["stored_sha256"]), *where(it)]}
        if it.get("extended_image_revision"):
            c["properties"] += [prop("sca-center:fsp-extended-image-revision", it["extended_image_revision"]),
                                prop("sca-center:note", "FSP ExtendedImageRevision is non-zero: the high bytes of the revision/build fields "
                                                        "are there, so the version above (from ImageRevision only) may be too low")]
        comps.append(assessed(c, "intel"))
        sub.append(ref)
    for it in cb["vbt"]:
        ref = f"{img}:vbt:{it['hash']['sha256'][:12]}"
        c = {"type": "firmware", "bom-ref": ref, "name": "Intel VBT (Video BIOS Table)", "version": it["version"],
             "manufacturer": {"name": "Intel Corporation"}, "hashes": hlist(it["hash"]),
             "properties": [prop("sca-center:version-basis", f"$VBT header version {it['version_raw']} (x100) of '{it['signature']}'"),
                            prop("sca-center:vbt-signature", it["signature"]), prop("sca-center:vbt-size", it["vbt_size"]),
                            *([prop("sca-center:vbt-bdb-version", f"{it['bdb_version']} ({it['bdb_version_raw']} x100)")] if it["bdb_version"] else []),
                            prop("sca-center:cbfs-file", it["file"]), prop("sca-center:cbfs-stored-sha256", it["stored_sha256"]), *where(it)]}
        comps.append(assessed(c, "vbt"))
        sub.append(ref)


AMD_VENDOR = {"name": "Advanced Micro Devices, Inc."}


def amd_where(x):
    return f"{x['directory']} entry {x['index']} (instance {x['instance']}) @0x{x['offset']:x}"


def amd_components(b, img, comps, sub):
    """AMD 平台（amd_psp.analyze 的結果 b["amd"]）：有版本的 PSP 韌體條目、微碼 patch、AGESA 字串各一個元件，掛在 BIOS 映像底下。
    版本都是映像裡讀到的原值（PSP 標頭的版本欄位、patch_id、AGESA 標記後的字串）；讀不到的不產元件（GAP 在 BIOS 映像元件的 sca-center:gap）。"""
    a = b.get("amd")
    if not a:
        return
    n = 0
    for p in a["psp_firmware"]:
        n += 1
        ref = f"{img}:amd-psp:{p['type']:02x}:{p['subprogram']:02x}:{(p['sha256'] or 'nohash')[:12]}:{n}"
        c = {"type": "firmware", "bom-ref": ref, "name": f"AMD PSP firmware {p['type_name'] or ''} (type 0x{p['type']:02x}, subprogram {p['subprogram']})".replace("  ", " "),
             "version": p["version"], "manufacturer": AMD_VENDOR,
             "properties": [prop("sca-center:version-basis", "PSP firmware header (amd_fw_header) version field at +0x60; fw_type and size_total agree with the directory entry. The version is a field the image declares about itself: the only check is the directory checksum (self-consistency, no signature verification), and the directory reading was chosen by structural checks that assume the image was not tampered with"),
                            prop("sca-center:amd-psp-type", f"0x{p['type']:02x}"), prop("sca-center:amd-psp-subprogram", p["subprogram"]),
                            prop("sca-center:size", p["size"]), *[prop("sca-center:found-in", amd_where(x)) for x in p["locations"]]]}
        if p["sha256"]:
            c["hashes"] = hlist(p)
        c["properties"] += amd_advisory_props()
        comps.append(assessed(c, "amd"))
        sub.append(ref)
    for m in a["microcode"]:
        n += 1
        ref = f"{img}:amd-microcode:{m['equiv_id']}:{m['patch_id']}:{(m['sha256'] or 'nohash')[:12]}:{n}"
        c = {"type": "firmware", "bom-ref": ref, "name": f"AMD CPU microcode (equivalence id {m['equiv_id']})", "version": m["patch_id"], "manufacturer": AMD_VENDOR,
             "properties": [prop("sca-center:version-basis", "microcode patch header patch_id (patch level)"), prop("sca-center:amd-equivalence-id", m["equiv_id"]),
                            prop("sca-center:build-date", m["date"]), prop("sca-center:size", m["patch_size"]),
                            *([prop("sca-center:cpuid", x) for x in m["cpuids"]] if m["cpuids"] else
                              [prop("sca-center:cpuid-status", "not determined: the patch is not inside a container with an equivalence table (the mapping is not guessed)")]),
                            *[prop("sca-center:found-in", amd_where(x)) for x in m["locations"]]]}
        if m["sha256"]:
            c["hashes"] = hlist(m)
        c["properties"] += amd_advisory_props()
        comps.append(assessed(c, "amd"))
        sub.append(ref)
    ag = a["agesa"]
    for g in ag["values"]:
        n += 1
        ref = f"{img}:amd-agesa:{hashlib.sha256((g['tag'] + g['value']).encode()).hexdigest()[:12]}:{n}"
        c = {"type": "firmware", "bom-ref": ref, "name": "AMD AGESA", "manufacturer": AMD_VENDOR,
             "properties": [prop("sca-center:agesa-marker", g["tag"]),
                            prop("sca-center:count", g["count"]),
                            *[prop("sca-center:found-in", f"{w['where']} +0x{w['offset']:x}") for w in g["found"]],
                            *([prop("sca-center:note", f"{len(ag['values'])} different AGESA strings were found in this image; all are listed")] if len(ag["values"]) > 1 else []),
                            *([prop("sca-center:incomplete", "the AGESA search did not cover all UEFI content (see sca-center:gap)")] if not ag["complete"] else [])]}
        if g.get("truncated"):         # 字串超過讀取上限被截斷：前綴不是完整版本，不寫 version（dumpling:version-status 會是 GAP）
            c["properties"].append(prop("sca-center:note", f"the AGESA string is longer than the read limit; only this prefix was read and it is not used as a version: {g['value']}"))
        else:
            c["version"] = g["value"]
            c["properties"].insert(0, prop("sca-center:version-basis", f"string after the {g['tag']} marker in the image"))
        c["properties"] += amd_advisory_props()
        comps.append(assessed(c, "amd"))
        sub.append(ref)


def pfat_props(p):
    """BIOS 映像元件的 AMI PFAT 來源 property（原檔與組回映像的雜湊；元件本身的 hashes 是組回的映像）。"""
    if not p:
        return []
    return [prop("dumpling:unwrapped-from", p["format"]), prop("dumpling:container-sha256", p["container_sha256"]),
            prop("dumpling:unwrapped-image-sha256", p["image_sha256"]),
            prop("dumpling:pfat-signature", "not verified"),
            prop("dumpling:pfat-layout", f"{len(p['files'])} files from {p['info'].get('blocks', '?')} blocks concatenated in package order "
                                         f"({p['image_label']}), then {p['info'].get('oob_size', 0)} trailing bytes; not an SPI address map")]


ME_ADVISORY_BASIS = ("Intel CSME/TXE/SPS advisories (INTEL-SA) are not machine-matched by this tool: the public release notes used for microcode "
                     "do not cover them and NVD CPE data for CSME is incomplete; " + "no data in the database; the vendor advisory (Intel INTEL-SA) is authoritative")


def me_advisory_props():
    """ME 元件的公告比對：沒有機器可讀的 Intel CSME 公告資料 → NOT_ASSESSED（不是沒有漏洞）。"""
    return [prop("dumpling:advisory-match", NOT_ASSESSED), prop("dumpling:advisory-basis", ME_ADVISORY_BASIS)]


AMD_ADVISORY_BASIS = ("AMD security bulletins (AMD-SB) are not matched by this tool: the AMD-SB rule table has not been built; "
                      "no data in the database; the vendor advisory (AMD-SB) is authoritative")


def amd_advisory_props():
    """AMD 的微碼、PSP 韌體、AGESA 元件的公告比對：AMD-SB 的規則表還沒有，NOT_ASSESSED（不是沒有漏洞）。"""
    return [prop("dumpling:advisory-match", NOT_ASSESSED), prop("dumpling:advisory-basis", AMD_ADVISORY_BASIS)]


def advisory_props(res):
    """微碼元件的公告比對 property（fw_advisory.match_microcode 的結果；沒有結果 → 不加）。"""
    if not res:
        return []
    out = [prop("dumpling:advisory-match", res["match"])]
    if res["match"] == "affected-candidate":
        out.append(prop("dumpling:advisory-candidates", ", ".join(c["id"] for c in res["candidates"])))
    out.append(prop("dumpling:advisory-basis", res["basis"]))
    if res.get("latest_revision"):
        out.append(prop("dumpling:advisory-latest-revision", f"{res['latest_revision']} ({res['latest_release']})"))
    out.append(prop("dumpling:advisory-source", res["source"] or "advisory table not available"))
    out += [prop("dumpling:advisory-note", n) for n in res.get("notes", [])]
    return out


def vbios_advisory_props(res):
    """NVIDIA vBIOS 元件的公告比對 property（nvidia_vbios_advisory.match_vbios 的結果；沒有結果 → 不加）。"""
    if not res:
        return []
    out = [prop("dumpling:advisory-match", res["match"])]
    if res["match"] in ("affected", "fixed") and res.get("bulletins"):
        out.append(prop("dumpling:advisory-bulletins", ", ".join(res["bulletins"])))
        out.append(prop("dumpling:advisory-cves", ", ".join(res["cves"])))
    out.append(prop("dumpling:advisory-basis", res["basis"]))
    out.append(prop("dumpling:advisory-source", res["source"] or "advisory table not available"))
    out += [prop("dumpling:advisory-note", n) for n in res.get("notes", [])]
    return out


def components(inv):
    comps, deps = [], {}
    for v in inv["vbios"]:
        ref = f"{REF}vbios:{v['sha256'][:16]}"
        c = {"type": "firmware", "bom-ref": ref, "name": f"NVIDIA VBIOS {v['device']}", "hashes": hlist(v),
             "properties": [prop("bsi:component:filename", fname(v["locations"][0])),
                            *[prop(k, x) for k, x in zip(BSI_FLAGS, FIRMWARE_IMAGE)],
                            prop("sca-center:pci-vendor-id", v["vendor"]), prop("sca-center:pci-device-id", v["device"]),
                            prop("sca-center:rom-images", ", ".join(VBIOS_CODE_TYPES.get(i["code_type"], f"0x{i['code_type']:02x}")
                                                                   for i in v["images"])),
                            *[prop("sca-center:found-in", f"{x['file']} @0x{x['offset']:x}") for x in v["found_at"]]]}
        if v["version"]:
            c["version"] = v["version"]
            c["properties"].append(prop("sca-center:version-basis", "first XX.XX.XX.XX.XX string inside the option ROM"))
        if v["terminated"] != "last-flag":          # 下游只看得到 SBOM：雜湊不是完整 ROM 要寫在元件上
            c["properties"] += [prop("sca-center:rom-terminated", v["terminated"]),
                                prop("sca-center:incomplete", f"option ROM chain did not end normally ({v['terminated_note']}); "
                                                              "the hash may cover only part of the ROM")]
        if v.get("start_note"):                   # 開頭有兩個以上的候選、分不出來：offset 與雜湊可能不對
            c["properties"].append(prop("sca-center:note", f"option ROM start is ambiguous ({v['start_note']}); "
                                                           "the offset and hash may be wrong"))
        c["properties"] += vbios_advisory_props(v.get("advisory"))
        comps.append(assessed(c, "nvidia-vbios"))
    for b in inv["bios"]:
        img = f"{REF}bios:{b['sha256'][:16]}"
        sub = []
        c = {"type": "firmware", "bom-ref": img, "name": fname(b["file"]), "hashes": hlist(b),
             "properties": [prop("bsi:component:filename", fname(b["file"])),
                            *[prop(k, x) for k, x in zip(BSI_FLAGS, FIRMWARE_IMAGE)],
                            *[prop("sca-center:found-in", loc) for loc in b["locations"]],
                            *([prop("sca-center:ibv-hint", ", ".join(b["ibv_hint"]))] if b["ibv_hint"] else []),
                            *pfat_props(b.get("pfat")),
                            *([prop("sca-center:note", b["descriptor_note"])] if b["descriptor_note"] else []),
                            *[prop("sca-center:incomplete", x) for x in b["incomplete"]],
                            prop("sca-center:me-status", b["me_status"]),
                            *([prop("sca-center:me-note", b["me_note"])] if b["me_note"] else []),
                            prop("sca-center:fit", b["fit"]["status"] + (f" @0x{b['fit']['offset']:x}" if b["fit"]["offset"] is not None else "")),
                            *([prop("sca-center:platform", b["platform"])] if b["platform"] else []),
                            *([prop("sca-center:uefi-compressed-sections",
                                    ", ".join(f"{k}={v}" for k, v in sorted(b["uefi"]["compressed"].items())))]
                              if b["uefi"]["compressed"] else []),
                            *[prop("sca-center:gap", x) for x in b["gaps"]],
                            *([prop("sca-center:uefi-gfx-search", uefi_gfx_summary(b["uefi_gfx"]))] if b.get("uefi_gfx") else [])]}
        if b.get("declared_version"):
            c["version"] = b["declared_version"]
            c["properties"].append(prop("sca-center:version-basis", "version list (declared by the BIOS team)"))
        comps.append(assessed(c, "image"))
        me_props = [prop("sca-center:me-status", b["me_status"])]
        if b["me"]:
            me_props += ([prop("sca-center:version-basis", b["me"]["basis"]), prop("sca-center:offset", f"0x{b['me']['offset']:x}"),
                          prop("sca-center:me-family", b["me"]["family"] or "unknown")]
                         + ([prop("sca-center:me-family-basis", b["me"]["family_basis"])] if b["me"].get("family_basis") else [])
                         + ([prop("sca-center:build-date", b["me"]["date"])] if b["me"]["date"] else [])
                         + ([prop("sca-center:me-note", b["me_conflict"])] if b.get("me_conflict") else []))
        elif b["me_note"]:
            me_props.append(prop("sca-center:me-note", b["me_note"]))
        for r in b["regions"]:
            if r["name"] in ("descriptor", "bios", "me", "gbe", "ec"):
                ref = f"{img}:region:{r['name']}"
                rc = {"type": "firmware", "bom-ref": ref, "name": f"{r['name']} region", "hashes": hlist(r),
                      "properties": [prop("sca-center:spi-region", f"{r['name']} 0x{r['base']:x}-0x{r['limit']:x}")]}
                if r["name"] == "me":
                    rc["properties"] += me_props
                    if b["me"]:
                        rc["properties"] += cpe_props(b["me"]) + me_advisory_props()
                        rc["name"], rc["version"] = ME_NAME, b["me"]["version"]
                        rc["manufacturer"] = {"name": "Intel Corporation"}
                        if csme_cpe(b["me"]):
                            rc["cpe"] = csme_cpe(b["me"])
                comps.append(assessed(rc, "intel" if r["name"] == "me" else "image"))
                sub.append(ref)
        if b["me"] and not any(r["name"] == "me" for r in b["regions"]):
            ref = f"{img}:me"
            mc = {"type": "firmware", "bom-ref": ref, "name": ME_NAME, "version": b["me"]["version"],
                  "manufacturer": {"name": "Intel Corporation"}, "properties": me_props + cpe_props(b["me"]) + me_advisory_props()}
            if csme_cpe(b["me"]):
                mc["cpe"] = csme_cpe(b["me"])
            comps.append(assessed(mc, "intel"))
            sub.append(ref)
        for u in b["microcode"]:
            ref = f"{img}:microcode:{u['cpuid']}:{u['platform_id']}:{u['revision']}:{u['sha256'][:12]}"
            comps.append(assessed({"type": "firmware", "bom-ref": ref, "name": f"Intel CPU microcode {u['cpuid']}", "version": u["revision"],
                          "manufacturer": {"name": "Intel Corporation"}, "hashes": hlist(u),
                          "properties": [prop("sca-center:cpuid", u["cpuid"]), prop("sca-center:platform-id", u["platform_id"]),
                                         prop("sca-center:build-date", u["date"]), prop("sca-center:offset", f"0x{u['offset']:x}"),
                                         prop("sca-center:in-fit", in_fit_text(u)), prop("sca-center:in-fit-basis", in_fit_basis(b, u)),
                                         *[prop("sca-center:extended-signature", f"{x['cpuid']} {x['platform_id']}")
                                           for x in u["extended_signatures"]],
                                         *[prop("sca-center:found-in", w) for w in u.get("cbfs_files", [])],
                                         *advisory_props(u.get("advisory"))]}, "intel-microcode"))
            sub.append(ref)
        cbfs_components(b, img, comps, sub)
        amd_components(b, img, comps, sub)
        uefi_gfx_components(b, img, comps, sub)
        deps[img] = sub
    intel_gfx_components(inv, comps, deps)
    return comps, deps


def intel_gfx_collect(roms, data, label, store):
    """option_roms() 的結果裡的 Intel legacy VBIOS（intel_vbios.is_legacy_vbios）→ store（以 ROM 雜湊為鍵，同一個 ROM 多處出現記所有位置）。"""
    iv = None
    for r in roms:
        if r["vendor"] != "8086":                       # 先用便宜的條件擋掉，不為了沒有 Intel ROM 的檔案載入模組
            continue
        iv = iv or load_sibling("intel_vbios")
        if not iv.is_legacy_vbios(r):
            continue
        e = store.get(r["sha256"])
        if e is None:
            e = store[r["sha256"]] = {**{k: r.get(k) for k in ("vendor", "device", "class", "length", "images", "terminated", "terminated_note",
                                                              "sha256", "sha512")},
                                      **iv.legacy_info(data[r["offset"]:r["offset"] + r["length"]]),
                                      **({"start_note": r["start_note"]} if r.get("start_note") else {}),
                                      "locations": [], "found_at": []}
        if label not in e["locations"]:
            e["locations"].append(label)
        e["found_at"].append({"file": label, "offset": r["offset"]})


def intel_gfx_components(inv, comps, deps):
    """Intel legacy VBIOS → 元件。ROM 所在的檔案同時是 BIOS 映像時，掛在那個 BIOS 映像底下。"""
    parents = {loc: f"{REF}bios:{b['sha256'][:16]}" for b in inv["bios"] for loc in b["locations"]}

    def parent_of(loc):      # 從 BIOS 映像解開的內容，位置是 `<映像的位置>!uefi/<模組>`（UEFI_GFX_SEP）：前綴要接分隔符，a.bin 不是 a.bin2 的前綴
        hit = [p for p in parents if loc == p or loc.startswith(p + UEFI_GFX_SEP)]
        return parents[max(hit, key=len)] if hit else None
    for v in inv.get("intel_vbios", ()):
        ref = f"{REF}vbios-intel:{v['sha256'][:16]}"
        c = {"type": "firmware", "bom-ref": ref, "name": "Intel legacy VBIOS (option ROM)", "manufacturer": {"name": "Intel Corporation"},
             "hashes": hlist(v),
             "properties": [prop("bsi:component:filename", fname(v["locations"][0])),
                            *[prop(k, x) for k, x in zip(BSI_FLAGS, FIRMWARE_IMAGE)],
                            prop("sca-center:pci-vendor-id", v["vendor"]), prop("sca-center:pci-device-id", v["device"]),
                            prop("sca-center:rom-images", ", ".join(VBIOS_CODE_TYPES.get(i["code_type"], f"0x{i['code_type']:02x}")
                                                                   for i in v["images"])),
                            *([prop("dumpling:vbios-banner", v["banner"])] if v["banner"] else []),
                            *([prop("dumpling:vbios-build-time", v["build_time"])] if v["build_time"] else []),
                            *([prop("dumpling:vbios-vbt", f"{v['vbt']['signature']} v{v['vbt']['version']}, BDB {v['vbt']['bdb_version']}, "
                                                          f"{v['vbt']['vbt_size']} bytes @0x{v['vbt']['offset']:x} in the ROM")]
                              if v["vbt"] else []),
                            *[prop("sca-center:found-in", f"{x['file']} @0x{x['offset']:x}") for x in v["found_at"]]]}
        if v["version"]:
            c["version"] = v["version"]
            c["properties"].append(prop("sca-center:version-basis",
                                        "'Build Number: <n> PC <x.y>' line inside the legacy VBIOS (checked against one public sample only)"))
        else:
            c["properties"].append(prop("sca-center:gap", f"version not read: {v['version_note']}"))
        if v["terminated"] != "last-flag":
            c["properties"] += [prop("sca-center:rom-terminated", v["terminated"]),
                                prop("sca-center:incomplete", f"option ROM chain did not end normally ({v['terminated_note']}); "
                                                              "the hash may cover only part of the ROM")]
        if v.get("start_note"):
            c["properties"].append(prop("sca-center:note", f"option ROM start is ambiguous ({v['start_note']}); the offset and hash may be wrong"))
        comps.append(assessed(c, "intel"))
        for loc in v["locations"]:
            par = parent_of(loc)
            if par and ref not in deps.get(par, ()):
                deps.setdefault(par, []).append(ref)


def intel_gfx_status(inv):
    att = []
    for v in inv.get("intel_vbios", ()):
        who = f"Intel legacy VBIOS（{v['device']}）"
        if not v["version"]:
            att.append(f"{who}：ROM 裡讀不到版本（{v['version_note']}）")
        if v["terminated"] != "last-flag":
            att.append(f"{who}：ROM 鏈沒有正常結束（{v['terminated_note']}），雜湊可能只涵蓋一部分")
        if v.get("start_note"):
            att.append(f"{who}：ROM 開頭不確定（{v['start_note']}），offset 與雜湊可能不對")
    return att


def intel_gfx_markdown(inv):
    if not inv.get("intel_vbios"):
        return []
    e = md_esc
    L = ["", "## Intel legacy VBIOS", "", "| 橫幅 | 版本 | 建置時間 | 內嵌 VBT | 來源 |", "|---|---|---|---|---|"]
    for v in inv["intel_vbios"]:
        vbt = f"{v['vbt']['signature']} v{v['vbt']['version']}（BDB {v['vbt']['bdb_version']}）" if v["vbt"] else ""
        L.append(f"| {e(v['banner'] or '')} | {e(v['version'] or '找不到')} | {e(v['build_time'] or '')} | {e(vbt)} | "
                 + "、".join(e(x) for x in v["locations"]) + " |")
    L.append("\n版本只有 Intel 公告無法機器比對的身分資訊（NOT_ASSESSED）；格式只對一份公開樣本核對過。")
    return L


UEFI_GFX_SEP = "!uefi/"                 # 從 BIOS 映像的 UEFI 內容解開的位置：`<映像的位置>!uefi/<FFS GUID 或 UI 名稱>`（fname() 取最後一段）
MAX_GFX_NOTES = 8                       # 每個映像逐一列出「PCIR 沒有變成 ROM」等 option ROM 說明的上限


def uefi_gfx_search(b, label, data, budget, intel_vb, partial):
    """BIOS 映像 b（bios_image() 的結果，之後會變成 inv["bios"] 的一項）的 UEFI 內容裡找 Intel GOP 驅動、獨立 VBT、legacy VBIOS
    （走訪在 uefi_gfx.py，用 C1 的 uefi_image.py 解開 FV／LZMA）。結果放 b["uefi_gfx"]，缺口（沒解開、沒走訪）加進 b["gaps"]；
    legacy VBIOS 進 intel_vb（位置是 `<label>!uefi/<模組>`）。沒有未壓縮的 firmware volume 的 UEFI／coreboot 映像：記「沒有搜尋」。"""
    if not b["uefi"]["volumes"]:
        if "uefi" in b["evidence"] or "cbfs" in b["evidence"]:
            why = ("Intel GOP / VBT / legacy VBIOS inside UEFI firmware volumes: not searched (no uncompressed UEFI firmware volume with FFS files "
                   "was found in the image; compressed containers such as CBFS payloads are not unpacked for this search)")
            b["uefi_gfx"] = {"performed": False, "complete": False, "reason": why, "gaps": [why], "gop": [], "vbt": [], "stats": {}}
            b["gaps"].append(why)
        return
    notes = []

    def find_roms(body, module):
        lab = label + UEFI_GFX_SEP + module
        try:
            roms = option_roms(body, budget, notes if len(notes) < MAX_GFX_NOTES else None)
        except OverBudget as e:
            intel_gfx_collect(getattr(e, "partial", []), body, lab, intel_vb)
            raise
        except PARSE_ERRORS as e:
            if len(notes) < MAX_GFX_NOTES:
                notes.append(f"{module}: option ROM parse failed ({type(e).__name__})")
            return
        intel_gfx_collect(roms, body, lab, intel_vb)

    g = load_sibling("uefi_gfx").scan(data, find_roms, budget, (OverBudget,))
    if b.get("cbfs"):      # coreboot：CBFS 的檔案（例如壓縮的 edk2 payload）不在這次走訪裡，沒找到不能說不存在
        g["gaps"].append("coreboot CBFS found: files inside the CBFS (for example a compressed UEFI payload) were not unpacked for this search; "
                         "the Intel GOP / VBT / legacy VBIOS search is incomplete (not found does not mean absent)")
        g["complete"] = False
    b["uefi_gfx"] = g
    b["gaps"] += g["gaps"]
    if g["stopped"] and g["stopped"].startswith("stopped early"):
        partial.append((label, f"UEFI 顯示韌體走訪：{g['stopped']}"))
    if notes:
        g["rom_notes"] = notes[:MAX_GFX_NOTES]
        b["gaps"].append(f"{len(g['rom_notes'])} option ROM notes inside UEFI content (see fw-inventory.json uefi_gfx.rom_notes); "
                         "an Intel legacy VBIOS next to them may be missing or uncertain")


def uefi_gfx_summary(g):
    if not g["performed"]:
        return "not performed"
    s = g["stats"]
    return (f"{'complete (all firmware volumes found were decoded)' if g['complete'] else 'incomplete (not found does not mean absent)'}: "
            f"{s['fvs']} firmware volumes, {s['ffs_files']} FFS files, {s['decompressed_total']} bytes decompressed, {s['undecoded']} parts not decoded, "
            f"{s.get('outside_fv_nonblank_bytes', 0)} bytes outside firmware volumes searched only as raw blocks; "
            f"{len(g['gop'])} GOP driver(s), {len(g['vbt'])} standalone VBT(s)")


def uefi_gfx_where(w):
    return (f"UEFI module {w['module']}" + (f" ({w['ui_name']})" if w.get("ui_name") else "")
            + f", offset 0x{w['offset']:x} in the section content")


def uefi_gfx_components(b, img, comps, sub):
    """b["uefi_gfx"] 的 GOP 驅動與獨立 VBT → 元件，掛在 BIOS 映像底下（legacy VBIOS 在 intel_gfx_components）。"""
    g = b.get("uefi_gfx") or {}
    for it in g.get("gop", ()):
        ref = f"{img}:uefi-gop:{it['sha256'][:12]}"
        w0 = it["found"][0]
        c = {"type": "firmware", "bom-ref": ref, "name": "Intel GOP driver", "manufacturer": {"name": "Intel Corporation"}, "hashes": hlist(it),
             "properties": [prop("bsi:component:filename", w0.get("ui_name") or w0["module"]),
                            *[prop(k, x) for k, x in zip(BSI_FLAGS, FIRMWARE_IMAGE)],
                            prop("sca-center:pe-machine", it["machine"]), prop("sca-center:pe-subsystem", it["subsystem_name"]),
                            prop("sca-center:size", it["size"]),
                            *[prop("sca-center:found-in", uefi_gfx_where(w)) for w in it["found"]]]}
        if it["version"]:
            c["version"] = it["version"]
            c["properties"].append(prop("sca-center:version-basis", it["version_basis"] + "; checked against one public sample only"))
        else:
            c["properties"].append(prop("sca-center:gap", f"version not read: {it['version_note']}"))
        comps.append(assessed(c, "intel"))
        sub.append(ref)
    for it in g.get("vbt", ()):
        ref = f"{img}:uefi-vbt:{it['sha256'][:12]}"
        w0 = it["found"][0]
        c = {"type": "firmware", "bom-ref": ref, "name": "Intel VBT (Video BIOS Table)", "version": it["version"],
             "manufacturer": {"name": "Intel Corporation"}, "hashes": hlist(it),
             "properties": [prop("bsi:component:filename", w0.get("ui_name") or w0["module"]),
                            *[prop(k, x) for k, x in zip(BSI_FLAGS, FIRMWARE_IMAGE)],
                            prop("sca-center:version-basis", f"$VBT header version {it['version_raw']} (x100) of '{it['signature']}'"),
                            prop("sca-center:vbt-signature", it["signature"]), prop("sca-center:vbt-size", it["vbt_size"]),
                            *([prop("sca-center:vbt-bdb-version", f"{it['bdb_version']} ({it['bdb_version_raw']} x100)")] if it["bdb_version"] else []),
                            *[prop("sca-center:found-in", uefi_gfx_where(w)) for w in it["found"]]]}
        comps.append(assessed(c, "vbt"))
        sub.append(ref)


def uefi_gfx_status(b):
    g = b.get("uefi_gfx")
    if g and not g["complete"]:
        return [f"{b['file']}：UEFI 內的 Intel GOP／VBT／legacy VBIOS 搜尋不完整（GAP，沒找到不代表不存在；原因見 SBOM 的 sca-center:gap）"]
    return []


def uefi_gfx_markdown(b):
    g = b.get("uefi_gfx")
    if not g:
        return []
    e = md_esc
    L = ["", "### UEFI 內的 Intel 顯示韌體（GOP／VBT／legacy VBIOS）", "",
         e(uefi_gfx_summary(g)) + "。legacy VBIOS 另列在「Intel legacy VBIOS」一節。", ""]
    if g["gop"] or g["vbt"]:
        L += ["| 元件 | 版本 | SHA-256 | 位置 |", "|---|---|---|---|"]
        L += [f"| Intel GOP driver | {e(it['version'] or '找不到')} | `{it['sha256']}` | " + "、".join(e(uefi_gfx_where(w)) for w in it["found"]) + " |"
              for it in g["gop"]]
        L += [f"| {e(it['signature'])} | {it['version']} | `{it['sha256']}` | " + "、".join(e(uefi_gfx_where(w)) for w in it["found"]) + " |"
              for it in g["vbt"]]
    else:
        L.append("沒有找到 Intel GOP 驅動或獨立 VBT" + ("（找到的 firmware volume 都解開了，裡面沒有；FV 以外的位元組只當原始內容掃）。" if g["complete"] else "（走訪不完整，不代表不存在）。"))
    return L + [f"- GAP：{e(x)}" for x in g["gaps"]]


def bom(comps, deps):
    refs = [c["bom-ref"] for c in comps]
    dup = sorted({r for r in refs if refs.count(r) > 1})
    if dup:                              # 去重以後不該發生；發生就不要寫出不合 schema 的 SBOM
        raise Fail(f"內部錯誤：bom-ref 重複（{', '.join(dup[:3])}）")
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": "dumpling x86_firmware.py"}]}},
            "components": comps,
            "dependencies": [{"ref": c["bom-ref"], "dependsOn": deps.get(c["bom-ref"], [])} for c in comps]}


# ---------- 主流程 ----------

def pfat_unwrap(label, data, budget, partial):
    """AMI PFAT 偵測 → (pfat 資訊或 None, 要解析的 bytes)。不是 PFAT：原樣回傳。解不開：記 partial，原 bytes 照一般資料掃。"""
    mod = load_sibling("ami_pfat")
    try:
        pf = mod.unwrap(data, budget)
    except OverBudget as e:
        partial.append((label, f"AMI PFAT 解封裝：{e}"))
        return None, data
    if pf is None:
        return None, data
    if not pf["ok"] or len(pf["image"]) > budget.total_left:
        partial.append((label, "AMI PFAT 解封裝失敗：" + (pf["error"] or "組回的映像超過這次執行的總量上限")))
        return None, data
    budget.total_left -= len(pf["image"])
    partial += [(label, f"AMI PFAT：{x}") for x in pf["unparsed"]]
    return {"format": "AMI PFAT (AMI BIOS Guard)", "container_sha256": pf["orig_sha256"], "container_size": len(data),
            "image_sha256": pf["image_sha256"], "image_size": len(pf["image"]), "image_label": pf["image_label"], "files": pf["files"],
            "info": pf["info"], "notes": pf["notes"], "signature_verified": False}, pf["image"]


def inventory(paths, manifest=None, budget=None, advisory=None, vbios_advisory=None):
    """advisory：測試用，Table 或 TableError（fw_advisory）；沒給就載入 repo 內的 Intel 微碼發佈資料表。
    vbios_advisory：測試用，Table 或 TableError（nvidia_vbios_advisory）；沒給就載入 repo 內的 NVIDIA 公告對照表。"""
    rows = read_manifest(manifest) if manifest else None
    budget = budget or Budget()
    gen, skipped = inputs(paths, budget)
    partial = []                        # 讀進來、解析到一半（上限、超時、某一段失敗）的檔案；skipped 是沒有解析或內容沒展開的
    vb, other, bios = {}, {}, {}
    intel_vb = {}                       # Intel legacy VBIOS（intel_vbios.py）
    for label, data in gen:
        pfat, data = pfat_unwrap(label, data, budget, partial)     # AMI PFAT 封裝 → 組回的映像（之後照常解析）
        roms, b = [], None
        for stage in ("vBIOS", "BIOS"):     # 兩段分開：BIOS 那段超時或失敗，已找到的 vBIOS 照樣保留
            try:
                budget.check()
                if stage == "vBIOS":
                    notes = []
                    try:
                        roms = option_roms(data, budget, notes)
                    finally:                    # 超時或解析失敗時，已經記下的原因也要保留
                        partial += [(label, f"vBIOS 解析：{x}") for x in notes]
                else:
                    b = bios_image(data, budget)
            except OverBudget as e:
                if stage == "vBIOS":          # 中途超時：已經找到的 vBIOS 照樣列出，檔案記在 partial（ATTENTION）
                    roms = getattr(e, "partial", [])
                # vBIOS 那段還沒開始就超時 → 整個檔案沒有解析（skipped）；否則是解析到一半（partial）
                (partial if stage == "BIOS" or hasattr(e, "partial") else skipped).append((label, f"{stage} 解析：{e}"))
                break
            except PARSE_ERRORS as e:      # 不該發生（都有檢查邊界）；發生就記下來，另一段照跑（只有超過上限才中止）
                partial.append((label, f"{stage} 解析失敗（{type(e).__name__}）"))
        intel_gfx_collect(roms, data, label, intel_vb)
        for r in roms:
            if r["vendor"] != f"{NVIDIA_VID:04x}":
                continue
            target = vb if is_vbios(r) else other
            e = target.setdefault(r["sha256"], {**{k: r.get(k) for k in ("vendor", "device", "class", "version", "length", "images",
                                                                      "terminated", "terminated_note", "sha256", "sha512")},
                                                **({"start_note": r["start_note"]} if r.get("start_note") else {}),   # 沒有說明時不寫這個鍵
                                                "locations": [], "found_at": []})
            if label not in e["locations"]:             # 同一個檔裡出現兩次：檔名記一次，位置都記
                e["locations"].append(label)
            e["found_at"].append({"file": label, "offset": r["offset"]})
        if b and b.get("evidence") == ["amd"] and any(is_vbios(r) for r in roms):
            b = None                   # NVIDIA vBIOS 更新包（nvflash）裡只有 AMD 標記：當成巧合，不當成 BIOS 映像；
            #                            其他廠商的 option ROM（例如 AMD BIOS 裡的 PXE ROM）不算
        if b and pfat:
            b["pfat"] = pfat
            if "AMI" not in b["ibv_hint"]:
                b["ibv_hint"] = sorted(b["ibv_hint"] + ["AMI"])      # AMI BIOS Guard 封裝本身就是 AMI 的線索
        if b:
            h = hashes(data)
            e = bios.get(h["sha256"])
            if e is None:
                e = bios[h["sha256"]] = {"file": label, "locations": [], "size": len(data), **h, **b}
                uefi_gfx_search(e, label, data, budget, intel_vb, partial)     # 同一個映像（雜湊相同）只走訪一次
            if label not in e["locations"]:               # 同一個映像（雜湊相同）在多個檔案出現：一個元件、記所有來源
                e["locations"].append(label)
    inv = {"schema": "sca-center-fw-inventory/1",
           "vbios": sorted(vb.values(), key=lambda x: (x["device"], x["version"] or "", x["sha256"])),
           "intel_vbios": sorted(intel_vb.values(), key=lambda x: (x["sha256"])),
           "other_roms": [{"vendor": x["vendor"], "device": x["device"], "code_types": [i["code_type"] for i in x["images"]],
                           "length": x["length"], "terminated": x["terminated"],
                           **({"terminated_note": x["terminated_note"]} if x["terminated_note"] else {}),
                           **({"start_note": x["start_note"]} if x.get("start_note") else {}),
                           "sha256": x["sha256"], "locations": x["locations"], "found_at": x["found_at"]}
                          for x in sorted(other.values(), key=lambda x: (x["device"], x["sha256"]))],
           "bios": list(bios.values()), "skipped": [{"file": f, "reason": r} for f, r in skipped],
           "partial": [{"file": f, "reason": r} for f, r in partial],
           "limits": {"time_limit_s": budget.time_limit if math.isfinite(budget.time_limit) else None, "max_file": MAX_FILE, "max_total": MAX_TOTAL, "max_checksum": MAX_CHECKSUM,
                      "max_fit_entries": MAX_FIT_ENTRIES, "max_fpt_entries": MAX_FPT_ENTRIES, "max_fv": MAX_FV, "max_ffs_items": MAX_FFS_ITEMS}}
    inv["advisory"] = advisory_section(inv, advisory)
    inv["vbios_advisory"] = vbios_advisory_section(inv, vbios_advisory)
    if rows is not None:
        bv = sorted({r["firmware_version"] for r in rows if r["component"] == "bios" and r["firmware_version"]
                     and norm("bios", "version", r["firmware_version"]) != "?"})
        full = [b for b in inv["bios"] if b["descriptor"]]
        if len(bv) == 1 and len(full) == 1:          # 清單只有一個 BIOS 版本、也只有一個完整映像，才把版本記到映像上
            full[0]["declared_version"] = bv[0]
        # ME 是 CSME、TXE 還是 SPS：映像分不出來（不猜）。清單的 me 列 identifier 寫了、而且那一列的版本和這個映像的 ME 版本相符時才帶；
        # 相符的列寫了兩種以上就不帶
        for b in inv["bios"]:
            if not b["me"]:
                continue
            fam = {r["identifier"].strip().upper() for r in rows if r["component"] == "me"
                   and r["identifier"].strip().upper() in ME_FAMILIES
                   and version_matches("me", norm("me", "version", r["version"]), b["me"]["version"])}
            if len(fam) == 1:
                b["me"].update(family=fam.pop(), family_basis="version list")
            elif len(fam) > 1:            # 清單對同一個版本寫了不同的 family（自相矛盾）：不推定，不帶 CPE
                b["me"]["family_conflict"] = sorted(fam)
        inv["comparison"] = compare(inv, rows)
    return inv


def advisory_section(inv, advisory=None):
    """每份微碼比對一次（結果記在 u["advisory"]，SBOM 與報告共用）→ inv["advisory"]：資料表來源與狀態（OK／GAP）、各結果的數量。"""
    mod = load_sibling("fw_advisory")
    if advisory is None:
        table, err = mod.load_default()
    elif isinstance(advisory, mod.TableError):
        table, err = None, advisory
    else:
        table, err = advisory, None
    n = 0
    results = []
    for b in inv["bios"]:
        for u in b["microcode"]:
            try:
                u["advisory"] = mod.match_microcode(table if table is not None else err, u)
            except Exception as e:           # 比對本身出錯（資料表內容異常等）：這一份是 NOT_ASSESSED，不讓整個流程中斷
                u["advisory"] = {**mod._na("match-error", f"the advisory matching failed ({type(e).__name__})"), "signatures": [],
                                 "source": table.label() if table is not None else None, "notes": []}
            results.append(u["advisory"])
            n += 1
    sec = {"status": "OK" if table is not None else "GAP", "microcodes": n, "counts": mod.counts(results)}
    if table is not None:
        sec["source"] = {k: table.source[k] for k in ("repo", "tag", "commit", "path", "sha256")}
        sec["source"]["table_sha256"] = table.sha256
        sec["source"]["releases"] = len(table.releases)
        sec["source"]["oldest"] = table.releases[-1]["tag"]
    else:
        sec["gap"] = f"{err.reason}: {err.detail}"
    return sec


def vbios_advisory_section(inv, advisory=None):
    """每個 NVIDIA vBIOS 比對一次（結果記在 v["advisory"]，SBOM 與報告共用）→ inv["vbios_advisory"]：對照表來源與狀態（OK／GAP）、各結果的數量。"""
    mod = load_sibling("nvidia_vbios_advisory")
    if advisory is None:
        table, err = mod.load_default()
    elif isinstance(advisory, mod.TableError):
        table, err = None, advisory
    else:
        table, err = advisory, None
    results = []
    for v in inv["vbios"]:
        try:
            v["advisory"] = mod.match_vbios(table if table is not None else err, v)
        except Exception as e:           # 比對本身出錯（對照表內容異常等）：這一個是 NOT_ASSESSED，不讓整個流程中斷
            v["advisory"] = mod._na("match-error", f"the advisory matching failed ({type(e).__name__})",
                                    source=table.label() if table is not None else None)
        results.append(v["advisory"])
    sec = {"status": "OK" if table is not None else "GAP", "vbios": len(results), "counts": mod.counts(results)}
    if table is not None:
        sec["source"] = {"mirror_commit": table.mirror_commit, "mirror_fetched_utc": table.mirror_fetched_text, "reviewed_until": table.reviewed_until,
                         "table_sha256": table.sha256, "reviewed_rows": len(table.rows), "unreviewed_rows": len(table.unreviewed),
                         "not_applicable": list(table.not_applicable)}
    else:
        sec["gap"] = f"{err.reason}: {err.detail}"
    return sec


def status_of(inv):
    att = []
    n_skipped = len({x["file"] for x in inv["skipped"]})          # 兩邊都以檔案數計（同一個檔案可能有多筆原因）
    n_partial = len({x["file"] for x in inv.get("partial", [])})
    partial_txt = f"{n_partial} 個檔案只解析了一部分" if n_partial else ""
    if not inv["vbios"] and not inv["bios"] and not inv.get("intel_vbios"):
        return "GAP", ("沒有找到 NVIDIA vBIOS 或 BIOS 結構"
                       + (f"（只有其他內嵌 NVIDIA 映像 {len(inv['other_roms'])} 個，沒有 x86／EFI 影像）" if inv["other_roms"] else "")
                       + (f"；略過 {n_skipped} 個檔案" if n_skipped else "")
                       + (f"；{partial_txt}" if partial_txt else ""))
    for b in inv["bios"]:
        if not b["descriptor"]:
            att.append(f"{b['file']}：沒有 flash descriptor")
        if b["incomplete"]:
            att.append(f"{b['file']}：" + "；".join(b["incomplete"]))
        if b.get("me_status") == "unknown":
            att.append(f"{b['file']}：有 ME 區域但 ME 版本 unknown（{b['me_note']}）")
        if (b.get("me") or {}).get("family_conflict"):
            att.append(f"{b['file']}：版本清單 family 矛盾（同一個 ME 版本寫了 {'、'.join(b['me']['family_conflict'])}），不推定 family、不帶 CPE")
        if b.get("me_conflict"):
            att.append(f"{b['file']}：有不同版本的 FTPR manifest，ME 版本要確認（{b['me_conflict']}）")
        if b.get("platform") == "amd":
            a = b.get("amd")
            if a is None:
                att.append(f"{b['file']}：AMD 平台，PSP／BIOS 目錄解析沒有執行（GAP，不是沒有 microcode）")
            elif a["gaps"] or a["attention"] or a["incomplete"]:
                att.append(f"{b['file']}：AMD 平台（" + load_sibling("amd_psp").summary_text(a) + f"）；{len(a['gaps'])} 項 GAP"
                           + ("；" + "、".join(a["attention"]) if a["attention"] else "") + "（見 fw-inventory.json 的 amd）")
        att += uefi_gfx_status(b)
        n = sum(b.get("uefi", {}).get("compressed", {}).values())
        g = sum(b.get("uefi", {}).get("guided_other", {}).values())
        if n:                              # 工具知道自己略過了內容：不能顯示完整，至少 ATTENTION
            att.append(f"{b['file']}：{n} 個壓縮的 UEFI section 沒有解析（GAP，裡面的模組與版本沒有列出）")
        if g:                              # 需要處理、GUID 不認得的（例如簽章 section）：內容一樣被略過
            att.append(f"{b['file']}：{g} 個需要處理的 GUID-defined UEFI section（GUID 不認得）沒有解析（GAP，裡面的模組與版本沒有列出）")
    adv = inv.get("advisory")
    if adv and adv["status"] == "GAP" and adv["microcodes"]:
        att.append(f"Intel 微碼公告比對的資料表不能用（GAP，{adv['gap']}）；{adv['microcodes']} 份微碼都是 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準")
    va = inv.get("vbios_advisory")
    if va and va["status"] == "GAP" and va["vbios"]:
        att.append(f"NVIDIA vBIOS 公告比對的對照表不能用（GAP，{va['gap']}）；{va['vbios']} 個 vBIOS 都是 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準")
    for v in inv["vbios"]:
        if not v["version"]:
            att.append(f"vBIOS {v['device']}：ROM 裡找不到版本")
        if v["terminated"] != "last-flag":
            att.append(f"vBIOS {v['device']}：ROM 鏈沒有正常結束（{v['terminated_note']}），雜湊可能只涵蓋一部分")
        if v.get("start_note"):
            att.append(f"vBIOS {v['device']}：ROM 開頭不確定（{v['start_note']}），offset 與雜湊可能不對")
    att += intel_gfx_status(inv)
    if inv["skipped"]:
        att.append(f"略過 {n_skipped} 個檔案")
    if partial_txt:
        att.append(partial_txt)
    cmp_ = inv.get("comparison")
    if cmp_ is None:
        att.append("沒有版本清單（無法核對）")
    else:
        bad = [c for c in cmp_ if c["result"] == "mismatch" or (c["verifiable"] and c["result"] in ("declared-only", "extracted-only"))]
        unk = [c for c in cmp_ if c["result"] == "unknown"]
        if bad:
            att.append(f"待確認 {len(bad)} 項（版本對不上或只有一邊）")
        if unk:
            att.append(f"清單填「不知道」{len(unk)} 項")
    detail = f"vBIOS {len(inv['vbios'])} 個、BIOS 映像 {len(inv['bios'])} 個"
    if inv.get("intel_vbios"):
        detail += f"、Intel legacy VBIOS {len(inv['intel_vbios'])} 個"
    if inv["other_roms"]:                 # 燒錄工具自帶的其他 NVIDIA 映像：不算產品元件，只列出來
        detail += (f"、其他內嵌 NVIDIA 映像 {len(inv['other_roms'])} 個（裝置 ID "
                   f"{', '.join(sorted({x['device'] for x in inv['other_roms']}))}，沒有 x86／EFI 影像，不列入 SBOM）")
    return ("ATTENTION" if att else "OK"), detail + "".join("；" + x for x in att)


def md_esc(x):
    """表格與內文用：檔名、字串都是不可信資料，不能變成 markdown／HTML 結構。"""
    s = " ".join(str(x).split())
    for a, b in (("&", "&amp;"), ("\\", "\\\\"), ("|", "\\|"), ("`", "\\`"), ("*", "\\*"), ("_", "\\_"), ("[", "\\["), ("]", "\\]"),
                 ("<", "&lt;"), (">", "&gt;"), ("#", "\\#")):
        s = s.replace(a, b)
    return s


ME_STATUS_TEXT = {"found": "found（找到）", "no-me-region": "no-me-region（沒有 ME 區域）", "unknown": "unknown（有 ME 區域，版本拿不到）"}


def cbfs_markdown(cb):
    """### CBFS（coreboot）：區域、版本、payload、FSP、VBT。"""
    e = md_esc
    f = cb["fmap"]
    L = ["", "### CBFS（coreboot）", "",
         f"找到方式：{cb['method']}" + (f"（FMAP `{e(f['name'])}` 版本 {f['version']}，{f['areas']} 個區域，file offset 0x{f['offset']:x}）" if f else "（沒有可用的 FMAP，掃 `LARCHIVE`）"), "",
         "| 區域 | 角色 | offset | 大小 | 檔案數（空的） |", "|---|---|---|---|---|"]
    L += [f"| {e(r['name'])} | {e(r['role'])} | 0x{r['offset']:x} | 0x{r['size']:x} | {r['entries'] - r['empty']}（{r['empty']}） |" for r in cb["regions"]]
    where = lambda it: "、".join(e(cbfs_where(l)) for l in it["locations"])
    if cb["coreboot"]:
        L += ["", "| coreboot 版本 | git 修訂 | Dasharo | 建置時間 | 主機板 | 位置 |", "|---|---|---|---|---|---|"]
        L += [f"| {e(it['version'] or '找不到')} | {e(it['git_revision'] or '')} | {e(it['dasharo_version'] or '')} | {e(it['build_time'] or '')} | "
              f"{e(' '.join(x for x in (it['mainboard_vendor'], it['mainboard_part']) if x))} | {where(it)} |" for it in cb["coreboot"]]
    for it in cb["coreboot"]:
        if it["config"]:
            k = it["config"]["keys"]
            L.append(f"\nconfig（SHA-256 `{it['config']['sha256']}`，{it['config']['size']} bytes）："
                     + e("、".join(f"{a}={b}" for a, b in sorted(k.items()))) + f"；payload {e(', '.join(it['config']['payload']))}")
    if cb["payloads"]:
        L += ["", "| payload | 大小 | segment | SHA-256 | 位置 |", "|---|---|---|---|---|"]
        L += [f"| {e(it['file'])} | {it['length']} | " + e(", ".join(f"{x['type']}/{x['compression']}" for x in it["segments"]))
              + f" | `{it['hash']['sha256']}` | {where(it)} |" for it in cb["payloads"]]
    if cb["fsp"]:
        L += ["", "| FSP | ImageId | 版本 | spec | ImageBase | SHA-256 | 位置 |", "|---|---|---|---|---|---|---|"]
        L += [f"| {it['type']} | {e(it['image_id'])} | {it['revision']} | {it['spec_version']} | {it['image_base']} | `{it['hash']['sha256'][:16]}…` | {where(it)} |"
              for it in cb["fsp"]]
    if cb["vbt"]:
        L += ["", "| VBT | 版本 | BDB 版本 | 大小 | 位置 |", "|---|---|---|---|---|"]
        L += [f"| {e(it['signature'])} | {it['version']} | {it['bdb_version'] or ''} | {it['vbt_size']} | {where(it)} |" for it in cb["vbt"]]
    return L


ADV_TEXT = {"affected-candidate": "affected-candidate（有較新的 release，列出候選公告；不是確定受影響）",
            "older-no-sa": "older-no-sa（有較新的 revision，但那些 release 沒有列公告；不代表沒有漏洞）",
            "up-to-date": "up-to-date（資料表沒有更新的 revision；不代表沒有漏洞）",
            "NOT_ASSESSED": "NOT_ASSESSED（資料庫沒有資料，以廠商公告為準）"}


VB_ADV_TEXT = {"affected": "affected（對照表列為受影響；不是完整的漏洞判定）",
               "fixed": "fixed（對照表列為已修補；不代表沒有其他漏洞）",
               "NOT_ASSESSED": "NOT_ASSESSED（資料庫沒有資料，以廠商公告為準）"}


def nvidia_vbios_advisory_markdown(inv):
    """### NVIDIA vBIOS：依 vBIOS 版本與 PCI vendor／device ID 查人工審核過的 NVIDIA 公告對照表（離線）。"""
    e = md_esc
    va = inv.get("vbios_advisory") or {"status": "GAP", "gap": "沒有比對（inventory 沒有 vbios_advisory 欄位）", "vbios": 0, "counts": {}}
    L = ["", f"### NVIDIA vBIOS（{len(inv['vbios'])} 個）", "",
         "- **這一段不是漏洞判定，沒有任何一項代表「沒有漏洞」。** NVIDIA 對消費型與專業型顯卡的 vBIOS 幾乎沒有公開公告（主要管道是 NVIDIA 的合作夥伴通知），"
         "所以多數 vBIOS 的結果是 `NOT_ASSESSED` ＝ 資料庫沒有資料，以廠商公告（NVIDIA 的合作夥伴通知或 product-security 公告）為準；請向顯卡團隊或 NVIDIA 的合作夥伴管道確認。",
         "- 比對方式：用 vBIOS 版本（`XX.XX.XX.XX.XX`）與 option ROM 的 PCI vendor／device ID 查 `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json`"
         "（人工審核過的 NVIDIA product-security gpu-firmware 群組公告）；版本讀不到（例如佔位字串）、裝置 ID 讀不到、表裡沒有對應的列、表不能用都是 NOT_ASSESSED。"
         "`fixed` 只表示表裡某一則已審核的公告把這個版本列為已修補，`affected` 只表示表裡有已審核的列把它列為受影響。比對在本機離線完成，沒有連網。"]
    if va["status"] == "OK":
        s = va["source"]
        L.append(f"- 對照表：審核到 {e(s['reviewed_until'] or '未審核')}、NVIDIA product-security 鏡像 commit `{e(s['mirror_commit'] or '未記錄')}`"
                 f"（下載 {e(s['mirror_fetched_utc'] or '未記錄')}）；已審核的 vBIOS 列 {s['reviewed_rows']} 筆、未審核 {s['unreviewed_rows']} 筆；"
                 + (f"審核後判定不適用的公告：{e('、'.join(s['not_applicable']))}（原因見對照表的 not_applicable）；" if s["not_applicable"] else "")
                 + f"對照表檔案 SHA-256 `{s['table_sha256']}`。")
    else:
        L.append(f"- 對照表：**GAP（不能用）**：{e(va['gap'])}。所有 NVIDIA vBIOS 都是 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準。")
    c = va["counts"]
    L.append(f"- NVIDIA vBIOS {va['vbios']} 個：" + ("、".join(f"{k} {c[k]}" for k in ("affected", "fixed", "NOT_ASSESSED") if k in c) or "無"))
    L += ["", "| PCI device | 版本 | 比對結果 | 公告 | CVE |", "|---|---|---|---|---|"]
    for v in inv["vbios"]:
        r = v.get("advisory")
        if not r:
            L.append(f"| {e(v['device'])} | {e(v['version'] or '找不到')} | NOT_ASSESSED（沒有比對結果） | | |")
            continue
        L.append(f"| {e(v['device'])} | {e(v['version'] or '找不到')} | {VB_ADV_TEXT[r['match']]} | "
                 f"{e('、'.join(r['bulletins']) if r['match'] in ('affected', 'fixed') else '')} | {e('、'.join(r['cves']) if r['match'] in ('affected', 'fixed') else '')} |")
    L.append("")
    for v in inv["vbios"]:
        r = v.get("advisory")
        if r:
            L.append(f"- `{e(v['device'])}/{e(v['version'] or '-')}`：{e(r['basis'])}")
            L += [f"  - {e(n)}" for n in r.get("notes", [])]
    return L


def advisory_markdown(inv):
    """## 公告比對：每份 SBOM（這次輸出）都有這一節。微碼用 Intel 公開的微碼發佈資料表離線比對；其他元件寫明沒有比對。"""
    e = md_esc
    adv = inv.get("advisory") or {"status": "GAP", "gap": "沒有比對（inventory 沒有 advisory 欄位）", "microcodes": 0, "counts": {}}
    L = ["", "## 公告比對", "",
         "- **這一節不是漏洞判定，沒有任何一項代表「沒有漏洞」。** 候選公告是資料表裡「比映像的微碼 revision 更新的 release」所列的 INTEL-SA："
         "來源只在 release 層級列公告、沒有逐 CPUID 列出，所以候選不一定影響這個 CPUID；資料表只涵蓋 Intel 公開的 Linux 微碼套件"
         "（不含只能由 BIOS 載入的微碼與 OEM 專用版本）。",
         "- `up-to-date` 只表示資料表裡沒有更新的 revision；`NOT_ASSESSED` ＝ 資料庫沒有資料，以廠商公告（Intel INTEL-SA）為準。"]
    if adv["status"] == "OK":
        s = adv["source"]
        L.append(f"- 資料表：Intel `{e(s['repo'].split('github.com/')[-1])}` 的 `{e(s['path'])}`，tag `{e(s['tag'])}`、commit `{s['commit']}`、"
                 f"來源 SHA-256 `{s['sha256']}`；資料表檔案 SHA-256 `{s['table_sha256']}`；涵蓋 {s['releases']} 個 release（最舊 `{e(s['oldest'])}`）。"
                 "比對在本機離線完成，沒有連網。")
    else:
        L.append(f"- 資料表：**GAP（不能用）**：{e(adv['gap'])}。所有微碼都是 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準。")
    c = adv["counts"]
    L.append(f"- Intel 微碼 {adv['microcodes']} 份：" + ("、".join(f"{k} {c[k]}" for k in ("affected-candidate", "older-no-sa", "up-to-date", "NOT_ASSESSED") if k in c) or "無"))
    for b in inv["bios"]:
        L += ["", f"### {e(fname(b['file']))}", ""]
        if b["microcode"]:
            L += ["| CPUID | platform id | revision | 比對結果 | 資料表最新 revision | 候選 INTEL-SA |", "|---|---|---|---|---|---|"]
            for u in b["microcode"]:
                r = u.get("advisory")
                if not r:
                    L.append(f"| {u['cpuid']} | {u['platform_id']} | {u['revision']} | NOT_ASSESSED（沒有比對結果） | | |")
                    continue
                late = f"{r['latest_revision']}（{e(r['latest_release'])}）" if r.get("latest_revision") else ""
                sa = "、".join(x["id"] for x in r["candidates"])
                L.append(f"| {u['cpuid']} | {u['platform_id']} | {u['revision']} | {ADV_TEXT[r['match']]} | {late} | {sa} |")
            L.append("")
            for u in b["microcode"]:
                r = u.get("advisory")
                if r:
                    L.append(f"- `{u['cpuid']}/{u['platform_id']}/{u['revision']}`：{e(r['basis'])}")
                    L += [f"  - {e(n)}" for n in r.get("notes", [])]
        elif b["platform"] == "amd":
            a = b.get("amd")
            if a:
                L.append(f"AMD 平台：AMD 微碼已解析 {len(a['microcode'])} 份、PSP 韌體 {len(a['psp_firmware'])} 項、AGESA 字串 {len(a['agesa']['values'])} 個，"
                         "沒有做公告比對（NOT_ASSESSED：資料庫沒有資料，以 AMD 公告為準；AMD-SB 的規則表還沒有做）。映像裡沒有 Intel 微碼。")
            else:
                L.append("AMD 平台：PSP 目錄解析沒有執行（GAP，原因見映像元件的 sca-center:gap），AMD 微碼、PSP 韌體、AGESA 都沒有列出，"
                         "沒有比對（NOT_ASSESSED：資料庫沒有資料，以 AMD 公告為準）。")
        else:
            L.append("微碼：映像裡沒有找到 Intel microcode，沒有可比對的項目（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）。")
        m = b["me"]
        cpe, _basis, gap = csme_cpe_info(m)
        if m:
            L += ["", f"- ME {e(m['version'])}：{ADV_TEXT['NOT_ASSESSED']}。Intel CSME／TXE／SPS 的公告沒有機器可讀的資料表。"
                  + (f"SBOM 帶 NVD 的 CPE `{e(cpe)}`，讓 Grype 比對（臨時 DT 關閉 NVD 資料源，只有 CPE 的元件在 DT 比不到）；NVD 對 Intel CSME 的 CPE 與版本範圍資料不完整，比不到不代表沒有漏洞，以 Intel 公告（INTEL-SA）為準。{'family 是由版本推定的（映像讀不出來），比對結果待人審。' if _basis == 'inferred' else ''}"
                     if cpe else f"沒有 CPE（GAP）：{e(gap)}。")]
        else:
            L += ["", f"- ME：{e(b['me_note'] or '沒有讀到 ME 版本')}；沒有 ME 版本可比對（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準），SBOM 不帶 CPE。"]
        L.append("- 其他元件（FSP、GOP／VBT／legacy VBIOS、coreboot、edk2、BIOS 映像本身）：沒有公告比對，NOT_ASSESSED：資料庫沒有資料，以廠商公告為準。")
    if not inv["bios"]:
        L += ["", "沒有 BIOS 映像，沒有微碼與 ME 可比對（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）。"]
    if inv["vbios"]:
        L += nvidia_vbios_advisory_markdown(inv)
    elif not inv["bios"]:
        L += ["", "沒有找到 NVIDIA vBIOS，沒有可比對的項目（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）。"]
    if inv.get("intel_vbios"):
        L += ["", f"### Intel legacy VBIOS（{len(inv['intel_vbios'])} 個）", "",
              "公告比對：沒有做（NOT_ASSESSED）：資料庫沒有資料，以廠商公告為準。"]
    return L


def markdown(inv):
    """fw-inventory.md：給人看的 BIOS 元件版本（與 vBIOS 摘要）。內容和 fw-inventory.json 相同來源，以 JSON 為準。"""
    e = md_esc
    L = ["# x86 韌體清點（BIOS 元件版本）", "",
         f"- 狀態：**{inv.get('status', '')}**；{e(inv.get('detail', ''))}",
         "- 只讀解析（不執行）；UEFI 壓縮 section 不解壓，coreboot CBFS 的 revision／config／FSP／VBT 只在記憶體內解壓讀取；結構化資料見 `fw-inventory.json`、SBOM 見 `fw.cdx.json`。"
         "版本以 BIOS／顯卡團隊的版本清單為準，這裡是映像裡讀得到的部分。", ""]
    L += ["## ME（CSME／TXE／SPS）狀態總覽", ""]
    for st in ("found", "no-me-region", "unknown"):
        bs = [b for b in inv["bios"] if b.get("me_status") == st]
        L.append(f"- {ME_STATUS_TEXT[st]}：{len(bs)} 個" + ("：" + "、".join(e(fname(b["file"])) for b in bs) if bs else ""))
    L.append("")
    for b in inv["bios"]:
        L += [f"## BIOS 映像 {e(fname(b['file']))}", "",
              f"- SHA-256 `{b['sha256']}`，{b['size']} bytes；來源：" + "、".join(e(x) for x in b["locations"]),
              "- flash descriptor：" + ("有（區域：" + "、".join(f"{r['name']} 0x{r['base']:x}-0x{r['limit']:x}" for r in b["regions"]) + "）"
                                        if b["descriptor"] else f"沒有（{e(b['descriptor_note'])}）")]
        if b.get("declared_version"):
            L.append(f"- BIOS 版本（版本清單）：{e(b['declared_version'])}")
        if b.get("pfat"):
            p = b["pfat"]
            L.append(f"- 來自 {e(p['format'])} 封裝：原檔 SHA-256 `{p['container_sha256']}`（{p['container_size']} bytes），"
                     f"組回映像 SHA-256 `{p['image_sha256']}`（{p['image_size']} bytes，{len(p['files'])} 個區段依封裝順序串接）；" + e("；".join(p["notes"])))
        if b["platform"]:
            L.append(f"- 平台：{e(b['platform'])}（" + "；".join(e(x) for x in b["amd_markers"]) + "）")
        L += ["", "### ME", "", "| 狀態 | 版本 | 日期 | family | 位置 | 依據 |", "|---|---|---|---|---|---|"]
        m = b["me"]
        if m:
            fam = m["family"] + "（版本清單）" if m.get("family") else "family unknown"
            L.append(f"| {ME_STATUS_TEXT[b['me_status']]} | {m['version']} | {m['date'] or ''} | {e(fam)} | 0x{m['offset']:x} | {e(m['basis'])} |")
        else:
            L.append(f"| {ME_STATUS_TEXT[b['me_status']]} | | | | | {e(b['me_note'] or '')} |")
        if m and m["other_versions"]:
            L.append(f"\n其他 `$MN2` 版本（其他分割區）：{', '.join(m['other_versions'])}")
        if m and b["me_note"]:
            L.append(f"\n說明：{e(b['me_note'])}")
        f = b["fit"]
        L += ["", "### CPU microcode", "",
              f"FIT：{f['status']}" + (f"（file offset 0x{f['offset']:x}，{f['entries']} 項）" if f["offset"] is not None else "")
              + (f"；{e(f['note'])}" if f["note"] else ""), ""]
        if b["platform"] == "amd":
            L += ["AMD 平台：下面是 Intel 格式的 microcode 掃描；AMD 微碼（BIOS 目錄 type 0x66）見後面的 AMD 區段。", ""]
        if b["microcode"]:
            L += ["| CPUID | platform id | revision | 日期 | in FIT | 位置 |", "|---|---|---|---|---|---|"]
            L += [f"| {u['cpuid']} | {u['platform_id']} | {u['revision']} | {u['date']} | {in_fit_text(u)} | 0x{u['offset']:x} |"
                  for u in b["microcode"]]
        else:
            L.append("映像裡沒有找到 Intel microcode" + ("（AMD 平台，見後面的 AMD 區段）" if b["platform"] == "amd" else "") + "。")
        if b.get("amd"):
            L += load_sibling("amd_psp").markdown_lines(b["amd"], e)
        elif b["platform"] == "amd":
            L += ["", "### AMD", "", "**GAP**：PSP／BIOS 目錄解析沒有執行，AMD 微碼、PSP 韌體與 AGESA 沒有列出，不代表沒有。"]
        L += ["", "### IBV 線索", "", ("、".join(b["ibv_hint"]) + "（未壓縮的字串，只是線索）") if b["ibv_hint"] else "沒有找到（不代表不是這些 IBV）"]
        u = b["uefi"]
        L += ["", "### UEFI 壓縮 section（沒有解壓）", "",
              f"firmware volume {u['volumes']} 個（其他檔案系統 {u['volumes_other_fs']} 個）、FFS 檔案 {u['files']} 個、section {u['sections']} 個。", ""]
        if u["compressed"] or u["guided_other"]:
            L += ["| 壓縮方式 | 數量 |", "|---|---|"]
            L += [f"| {e(k)} | {v} |" for k, v in sorted(u["compressed"].items())]
            L += [f"| GUID-defined（需要處理，不認得）{e(k)} | {v} |" for k, v in sorted(u["guided_other"].items())]
            L.append("\nefi-standard 是 EFI／Tiano 標準壓縮、tiano-custom 是 edk2 TianoCompress，Python 標準庫都沒有解碼器；"
                     "lzma、lzma-f86 標準庫有；brotli 沒有。數量決定第 2b 步要不要自己寫 Tiano 解碼器。")
        else:
            L.append("沒有壓縮的 section" + ("（也沒有找到 firmware volume）" if not u["volumes"] else "") + "。")
        L += [f"- 走訪說明：{e(x)}" for x in u["notes"]]
        if b.get("cbfs"):
            L += cbfs_markdown(b["cbfs"])
        L += uefi_gfx_markdown(b)
        if b["gaps"] or b["incomplete"]:
            L += ["", "### 缺口與不完整", ""] + [f"- GAP：{e(x)}" for x in b["gaps"]] + [f"- 不完整：{e(x)}" for x in b["incomplete"]]
        L.append("")
    if not inv["bios"]:
        L += ["## BIOS", "", "沒有找到 BIOS 結構。", ""]
    L += ["## vBIOS", ""]
    if inv["vbios"]:
        L += ["| device | 版本 | 結束 | 來源 | 說明 |", "|---|---|---|---|---|"]
        L += [f"| {v['device']} | {e(v['version'] or '找不到')} | {v['terminated']} | " + "、".join(e(x) for x in v["locations"])
              + " | " + e("；".join(x for x in (v.get("terminated_note"), v.get("start_note")) if x)) + " |" for v in inv["vbios"]]
    else:
        L.append("沒有找到 NVIDIA vBIOS。")
    if inv["other_roms"]:
        L.append(f"\n其他內嵌 NVIDIA 映像（燒錄工具自帶，不是產品元件）{len(inv['other_roms'])} 個。")
    L += intel_gfx_markdown(inv)
    if inv.get("comparison") is not None:
        L += ["", "## 版本清單比對", "", "| 元件 | identifier | 清單 | 映像 | 結果 |", "|---|---|---|---|---|"]
        L += [f"| {c['component']} | {e(c['identifier'] or '')} | {e(c['declared'] or '')} | {e(c['extracted'] or '')} | {c['result']}"
              + ("" if c["verifiable"] else "（映像拆不出來）") + " |" for c in inv["comparison"]]
    L += advisory_markdown(inv)
    if inv["skipped"] or inv["partial"]:
        L += ["", "## 略過與只解析一部分", ""] + [f"- 略過 {e(x['file'])}：{e(x['reason'])}" for x in inv["skipped"]] \
            + [f"- 只解析一部分 {e(x['file'])}：{e(x['reason'])}" for x in inv["partial"]]
    return "\n".join(L) + "\n"


def clear(out):
    """FAIL 時刪掉 --out 裡上一次的輸出，不要被當成這次的結果。"""
    for name in OUTPUTS:
        try:
            (Path(out) / name).unlink(missing_ok=True)
        except OSError:
            pass


class ArgError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    """參數錯誤不要 exit 2（和 ATTENTION 同碼）：改成 FAIL 那一行、退出碼 64、清掉上一次的輸出。"""

    def error(self, message):
        raise ArgError(message)


def out_arg(argv):
    """參數解析失敗時，從原始參數找 --out（找不到 → None）。"""
    argv = list(sys.argv[1:] if argv is None else argv)
    for i, x in enumerate(argv):
        if x == "--out" and i + 1 < len(argv):
            return argv[i + 1]
        if x.startswith("--out="):
            return x[len("--out="):]
    return None


def seconds(v):
    """--time-limit：大於 0 的有限秒數；其他（abc、0、負數、inf、nan）都是參數錯誤（退出碼 64）。"""
    try:
        x = float(v)
    except ValueError:
        raise argparse.ArgumentTypeError(f"要是秒數（{v}）")
    if not (math.isfinite(x) and x > 0):
        raise argparse.ArgumentTypeError(f"要是大於 0 的有限秒數（{v}）")
    return x


def main(argv=None):
    # allow_abbrev=False：不接受縮寫（例如 --ou）。否則縮寫的 --out 能用，但參數錯誤時 out_arg 找不到它，上一次的輸出不會被清掉
    ap = Parser(description=__doc__.splitlines()[0], allow_abbrev=False)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("inventory", allow_abbrev=False)
    a.add_argument("--in", dest="inputs", action="append", required=True)
    a.add_argument("--manifest")
    a.add_argument("--out", required=True)
    a.add_argument("--time-limit", type=seconds, default=TIME_LIMIT, help=f"秒（預設 {TIME_LIMIT}）；超過後剩下的檔案不解析，ATTENTION")
    try:
        a = ap.parse_args(argv)
    except ArgError as e:
        out = out_arg(argv)
        if out:
            clear(out)
        print(f"FW-INVENTORY\tFAIL\t參數錯誤：{e}")
        return 64                       # 和 cra_report 等一樣：參數錯誤 64（argparse 的 2 會和 ATTENTION 撞）
    try:
        inv = inventory(a.inputs, a.manifest, Budget(time_limit=a.time_limit))
        st, detail = status_of(inv)
        inv["status"], inv["detail"] = st, detail
        comps, deps = components(inv)
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        docs = {"fw-inventory.json": json.dumps(inv, ensure_ascii=False, indent=1) + "\n",
                "fw.cdx.json": json.dumps(bom(comps, deps), ensure_ascii=False, indent=1) + "\n", "fw-inventory.md": markdown(inv)}
        for name in OUTPUTS:
            tmp = out / f".{name}.tmp"
            tmp.write_text(docs[name], encoding="utf-8")
            os.replace(tmp, out / name)
    except Fail as e:
        clear(a.out)
        print(f"FW-INVENTORY\tFAIL\t{e}")
        return 1
    except OSError as e:
        clear(a.out)                    # 寫到一半失敗：不要留下新舊混合
        print(f"FW-INVENTORY\tFAIL\t寫不進 {a.out}（{type(e).__name__}）")
        return 1
    print(f"FW-INVENTORY\t{st}\t{detail}")
    return 0 if st == "OK" else 2


if __name__ == "__main__":
    sys.exit(main())
