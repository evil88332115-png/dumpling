# C2：程式碼完整性／驗證開機檢查的評估（D-060 M7f (c)）

分支 `wp3/code-integrity-survey`。這份是調查與設計筆記，沒有程式改動。範圍是 WP3＋WP4 的韌體報告（BIOS、vBIOS）；
Jetson 與其他 Linux 映像是 C1 的範圍，只寫「那一邊能不能判斷、判斷什麼」，做不做、怎麼做由 C1 決定。
查證日期 2026-11-15；樣本觀察都是對公開樣本做的小範圍只讀檢查，樣本本身不進 repo。

## 0. 結論

1. ETSI EN 304 623 草稿取得 v0.0.12（2025-12，來自 `labs.etsi.org` 的公開專案，沒有登入）；`etsi.org/deliver` 回 HTTP 403 阻擋頁、docbox 要登入，所以 docbox 與 deliver 列出的較新版（V0.1.1、V0.1.3）是 GAP（第 1.1 節）。
   草稿不進 repo。第 2.4 節把每個 CI 項目對到 v0.0.12 的條款編號；條款編號在較新版可能不同，取得後要重核。
2. 清單的來源是 shipcheck 的四種機制（UEFI 簽章、FIT 簽章、dm-verity、IMA/EVM）加上這個 repo 的解析器已經讀得到的
   結構（Intel Boot Guard 的 FIT 項目、BIOS Guard 簽章、AMD PSP 金鑰項目、UEFI 變數、coreboot vboot 設定），再加上條款對照時補的 3 項（CI-24 至 CI-26）。共 26 項：
   **可以 5 項、部分 16 項、不行 5 項**（定義見第 2 節開頭）。
3. 映像能回答的只有「結構有沒有出現」；「平台有沒有開啟驗證」「金鑰是不是正式金鑰」多數要看熔絲、上機狀態或公開對照資料。
   所以設計的是**結構證據**（observed／not-found／GAP）：每一項的生效與否一律 NOT_ASSESSED，但不讓整份報告因此變 ATTENTION；摘要欄顯示各狀態的計數，報告不出現「驗證開機已啟用」這類結論（第 4 節）。
4. PR 切法在第 5 節；Jetson／OS 層的項目列在第 2.3 節，由 C1 決定。

## 1. 來源

### 1.1 ETSI EN 304 623（Boot Managers）公開草稿：取得 v0.0.12（較舊版），較新版 GAP

取得日期 2026-11-15。全程沒有登入、沒有接受條款、沒有換 User-Agent、沒有用第三方鏡像；被擋或要求登入就停止，不重試。

各位置的嘗試與結果：

| 位置 | 請求 | 結果 |
|---|---|---|
| docbox（V0.1.1 的 PDF，檔名 `EN_304-623_V0.1.1_2026-05-04_Boot_Managers_Mature-draft.pdf`；網址來自搜尋結果清單） | 命令列下載；網頁擷取工具 | 命令列得到 HTTP 403，內容是 Web Application Firewall 的 HTML 阻擋頁（不是 PDF）；網頁擷取工具被 HTTP 302 導向 ETSI 入口網站的登入頁（`LoginRedirection`）。上層資料夾也是 403。**要登入，停止，不再取用** |
| `etsi.org/deliver` 的草稿資料夾（`.../etsi_en/304600_304699/304623/`）與上層（`.../304600_304699/`） | 命令列 GET（資料夾另用 HEAD 看標頭，結果相同） | 兩個都是 HTTP 403，內容是 HTML 阻擋頁，沒有導向登入頁。**被擋，停止** |
| `etsi.org/deliver` 的 V0.1.3 PDF（搜尋結果列出的 `.../304623/00.01.03_20/en_304623v000103ev.pdf`） | 命令列 GET，一次 | HTTP 403，同上的 HTML 阻擋頁。**被擋，停止，沒有重試** |
| `labs.etsi.org`（ETSI 的程式碼託管站）專案 `stan4cra/en-304-623` | 匿名的公開 REST 介面與檔案原始內容；專案可見度是 public | HTTP 200，不需要登入。讀了 `README.md`、`LICENSE`、`EN-304-623.md`，以及標籤與提交清單 |

取得的草稿：

| 項目 | 內容 |
|---|---|
| 文件編號、標題 | EN 304 623；內文標題 CRA; Essential cybersecurity requirements for boot managers（Boot Managers 是 README 的標題） |
| 版本、日期 | **前置資料與內文寫 v0.0.12、2025-12**；取用的標籤名稱是 `v0.0.12.1`（提交 `2b263e57bfeccb05a93a76db495dbca6018b468b`，提交日 2025-12-19）。標籤名稱多一段 `.1`，前置資料沒有跟著改；檔名 `EN-304-623.md` 不帶版本。以內文為準：v0.0.12 |
| 另一份（不採用） | 預設分支 `main` 頂端（提交 `b1611ce61b4e879cf446f0376b0653a9161dd3d1`，2026-04-21，只改了 README）的 `EN-304-623.md` 封面寫 0.0.10（2025-11），比標籤舊。API 只列出 `main` 一個分支，較新的 v0.0.12 內容只在標籤上 |
| 比較 | 搜尋結果列出的 V0.1.1（2026-05-04，docbox）、V0.1.3（2026-06，etsi.org/deliver 與 EVS 頁面）比 v0.0.12 新，這兩版沒有取得。條款編號與內容可能不同：v0.0.10 與 v0.0.12 之間，第 5 節的條款數就有增刪（例如 5.6 節 24 條變 23 條）。第 2.4 節的條款編號只對 v0.0.12 成立 |
| 網址 | 專案頁 https://labs.etsi.org/rep/stan4cra/en-304-623；檔案原始內容 `https://labs.etsi.org/rep/api/v4/projects/stan4cra%2Fen-304-623/repository/files/EN-304-623.md/raw?ref=v0.0.12.1` |
| sha256 | `EN-304-623.md`（標籤 v0.0.12.1）`3c79effe01be926ca30895138b28417432ee72e67e785730e47c1dff850fc616`；`EN-304-623.md`（main，0.0.10）`fbd38d4cfa7d0bdad1673e0ada75316c52c5670d536d58ec3f74d71d4fe1be1b`；`LICENSE` `a4680a1ae0215cbcf02b2e62ac08f0ba3c849aadde752329c9905c2d9dfabc46`；`README.md`（main）`fa4bfe8443fda5458a0d5955ebe7f6d302ad4a7735feebe253523c8612070d22` |
| 授權與使用條件 | 專案的 `LICENSE` 是三條款的 BSD 型授權（Copyright 2025 ETSI），是否涵蓋草稿本文，授權檔沒有寫明（不確定）。`README.md` 的免責聲明：這些是過渡草稿，只供資訊與 CYBER-EUSR 日後開發工作使用，ETSI 與成員不為進一步的使用或實作負責；正式文件要向 ETSI 文件服務取得。草稿內文自己寫「前言的內容不要當真」（DRAFT FOREWORD），`README.md` 說內容在目標發布日前會大幅修改。main 版封面另有禁止未經書面授權複製的聲明（v0.0.12 的檔案沒有這一段）。`README.md` 另請意見提供者不要用大型語言模型產生意見；這份筆記不提交意見 |
| 使用方式 | **草稿不進 repo**（只放在本機暫存資料夾）。筆記只用自己的話摘要，並引用條款編號，不照抄條文 |
| 狀態 | v0.0.12：已取得，條款對照見第 2.4 節。V0.1.1、V0.1.3：**GAP**（docbox 要登入、`etsi.org/deliver` 回 403 阻擋頁）。使用者可以手動下載較新版後放在本機提供，草稿不進 repo；取得後重核第 2.4 節的條款編號（第 7 節第 1 項） |

搜尋摘要提到草稿的要求數量互相不一致；v0.0.12 的第 5 節共 92 個編號條款（第 2.4 節逐條列出）。其他版本的數量沒有核對，筆記不引用。

### 1.2 jetm/shipcheck（Apache-2.0）

| 項目 | 內容 |
|---|---|
| 網址 | `https://github.com/jetm/shipcheck` |
| 讀的 commit | `4621b3ab49f673221bdeb944f022829ccd8587af`（預設分支最新，commit 日期 2026-05-31） |
| 授權檔 | repo 根目錄 `LICENSE`，Apache License 2.0 全文 |
| 讀的範圍 | `README.md`（code-integrity 的說明、限制、後續項目）；`src/shipcheck/checks/code_integrity/` 的 `__init__.py`、`uefi.py`、`fit.py`、`dm_verity.py`、`ima_evm.py` 的模組說明、常數與檢查項目定義；`src/shipcheck/cra/requirements.yaml` 裡四個對應條目的標題 |
| 沒讀 | `pilots/0005-*/REPORT.md`、測試與 fixtures、其餘檢查（SBOM、CVE、授權等） |
| 借用方式 | **只借概念，不照抄原文，不搬程式碼**。shipcheck 的輸入是 Yocto 建置資料夾（`conf/local.conf`、`tmp/deploy/images`），這裡的輸入是已出貨的映像，所以只對應到「要看哪一類證據」 |

shipcheck 的 code-integrity 把四種機制合成一個檢查（用自己的話整理）：

| 機制 | 它看什麼 | 它自己寫明的限制 |
|---|---|---|
| UEFI 簽章 | 建置設定有沒有啟用簽章類別；簽章金鑰的設定值與檔案是否存在；金鑰路徑名稱像測試／範例就標出；有 `.efi` 卻沒設簽章就標出 | 不驗 PE/COFF 簽章、不驗 PK／KEK／db 的註冊 |
| FIT 簽章（U-Boot） | `.itb`／`.fit` 檔開頭是 FDT 魔術字，內文有 `signature` 字樣算已簽；有 FIT 卻沒簽標出；也看建置設定的簽章開關 | 不做密碼學驗證 |
| dm-verity | 建置設定有 verity 映像開關，或輸出資料夾有 `.verity`／`.hashtree` | 不驗雜湊樹 |
| IMA/EVM | 核心設定有 IMA、IMA_APPRAISE、EVM；套件清單有 `ima-evm-utils`；有 policy 套件；開機參數有 `ima_policy=`；依訊號組合給信心等級 | 不驗 rootfs 的 xattr |

兩個要注意的差異：

- shipcheck 在四種機制都沒偵測到時回 FAIL。這和硬性限制 5 衝突（沒資料或沒做到只能是 GAP／NOT_ASSESSED），這裡不沿用。
- shipcheck 用路徑名稱樣式（`test`、`sample`、`debug`、`ovmf`、`edk2` 等）判斷測試金鑰。名稱不是公開依據，這裡不沿用（第 3.3 節）。
- shipcheck 的 CRA 對應標示 Annex I 第一部分 (c)(d)(f)(k)；這個 repo 的 `tools/cra/cra_report.py` 已有 (a)–(m) 的逐項表，(f) 是「完整性」，第 4 節說明接法。

### 1.3 公開原始碼依據（樣本附的原始碼）

Boot Guard 在 FIT 裡的項目編號，依據是樣本 `dasharo-protectli-vp46xx-v1.2.0` 附的 coreboot 原始碼封存（`coreboot-add9d7206e30.tar.gz`，
sha256 見該 `firmware.yml`）裡的 `util/cbfstool/fit.h`（GPL-2.0-or-later）：type 0x02 BIOS ACM、0x0B Key Manifest、0x0C Boot Policy Manifest、
0x10 CSE secure boot、0x2F JMP debug policy。同一份封存的 `src/security/intel/cbnt/Kconfig` 說明 KM 與 BPM 是加進 CBFS 並更新 FIT 的項目。
Intel 的 FIT 與 Boot Guard 規格本身沒有讀到（未核對）；`x86_firmware.py` 的 `fit_table()` 說明也寫同樣的限制。
映像裡看到的結構識別字串（`__KEYM__`、`__ACBP__`）不在 coreboot 的原始碼裡，對應的公開文件沒有核對，下面只當觀察值。

## 2. 要求清單

### 2.1 欄位與分類定義

- **判斷**：這一項「能不能從現有公開樣本（只有映像、沒有機器）自動判斷」。
  - **可以**：項目本身就是映像裡的一個結構，讀得到就是答案（仍受第 3 節限制）。
  - **部分**：結構或字串讀得到，但答案要加上不在映像裡的資料（公開對照表、容器格式、完整解析）才完整，或只能給啟發式結果。
  - **不行**：答案不在映像裡。
- **狀態**：判斷不了的部分一律 `NOT_ASSESSED`（有機制但判斷不了生效與否、金鑰性質）或 `GAP`（解析不完整、沒有樣本、格式沒有公開依據），不顯示成已驗證，也沒有整體通過的說法。
  可以判斷的部分，結構狀態用 `observed`（看到結構）／`not-found`（解析完整、沒有看到）／`GAP`（解析不完整，不能寫 not-found；
  比照 `uefi_image.py` 的 present／absent／not_assessed 規則：absent 只在完整解開時成立）。
- **ETSI 條款**：對照在第 2.4 節（v0.0.12 的條款編號）。沒有本文條款的項目用 `ci-etsi-clause-gap`。
- **適用情形**：x86 BIOS／vBIOS／Jetson 三欄。「沒有對應結構」只表示這個平台的映像裡沒有這種機制的結構，不表示平台沒有用別的機制。
- **現有涵蓋**：列出現有報告哪個檔案、哪個 property 已經處理。

### 2.2 總表

| ID | 項目 | 判斷 | 範圍 |
|---|---|---|---|
| CI-01 | Intel Boot Guard 結構（FIT 的 Key Manifest／Boot Policy Manifest／startup ACM） | 可以 | x86 BIOS |
| CI-02 | Boot Guard 是否生效（熔絲、金鑰雜湊） | 不行 | x86 BIOS |
| CI-03 | BIOS Guard（AMI PFAT）簽章結構與 SVN | 部分 | x86 BIOS |
| CI-04 | Intel CSME 韌體 manifest 的簽章欄位 | 部分 | x86 BIOS |
| CI-05 | AMD PSP 目錄的金鑰與簽章項目 | 可以 | x86 BIOS（AMD） |
| CI-06 | AMD Platform Secure Boot 是否生效 | 不行 | x86 BIOS（AMD） |
| CI-07 | 除錯與解鎖相關項目 | 部分 | x86 BIOS |
| CI-08 | UEFI Secure Boot 程式能力 | 部分 | x86 BIOS（UEFI） |
| CI-09 | PK／KEK／db／dbx 變數的存在與內容 | 部分 | x86 BIOS（UEFI） |
| CI-10 | Secure Boot 即時狀態（SecureBoot、SetupMode…） | 不行 | x86 BIOS、Jetson |
| CI-11 | 金鑰是測試金鑰或已公開外洩金鑰 | 部分 | x86 BIOS、Jetson |
| CI-12 | coreboot 驗證開機（vboot） | 部分 | x86 BIOS（coreboot） |
| CI-13 | 回滾保護（SVN、版本計數器） | 部分 | x86 BIOS |
| CI-14 | 韌體更新包的簽章 | 部分 | x86 BIOS |
| CI-15 | 度量開機（TPM、Tcg2） | 部分 | x86 BIOS |
| CI-16 | 選項 ROM 內 EFI 影像的 Authenticode 簽章 | 部分 | vBIOS |
| CI-17 | NVIDIA vBIOS 本身的廠商簽章 | 不行 | vBIOS |
| CI-18 | 開機載入程式與核心的 UEFI 簽章（sbsign、Authenticode） | 可以 | Jetson／OS（C1） |
| CI-19 | FIT 簽章（U-Boot） | 可以 | OS（C1） |
| CI-20 | dm-verity | 部分 | Jetson／OS（C1） |
| CI-21 | IMA／EVM | 部分 | Jetson／OS（C1） |
| CI-22 | 核心模組簽章與 lockdown 設定 | 可以 | Jetson／OS（C1） |
| CI-23 | Jetson 熔絲與簽署流程 | 不行 | Jetson（C1） |
| CI-24 | 驗證用密碼演算法與金鑰強度 | 部分 | x86 BIOS、vBIOS、OS（C1） |
| CI-25 | 除錯建置與非必要功能的殘留 | 部分 | x86 BIOS（UEFI、coreboot） |
| CI-26 | SPI 快閃寫入保護與區域存取權 | 部分 | x86 BIOS（Intel） |

統計：可以 5（CI-01、05、18、19、22）；部分 16（CI-03、04、07、08、09、11、12、13、14、15、16、20、21、24、25、26）；不行 5（CI-02、06、10、17、23）。共 26 項。

### 2.3 逐項說明

來源欄的「S」是 shipcheck 的機制；沒有 S 的是這個 repo 的解析器已經讀得到結構、由 C2 整理的項目，或依 ETSI 條款補的項目（CI-24 至 CI-26）。每項對到的條款見第 2.4 節。

#### x86 BIOS 與 UEFI 韌體

**CI-01 Intel Boot Guard 結構**（可以）
- 摘要：映像的 FIT 裡有沒有 Key Manifest（type 0x0B）、Boot Policy Manifest（0x0C）、startup ACM（0x02）項目，以及它們指到的位置是否在映像內。
- 來源：無 S 對應；公開依據見第 1.3 節。
- 判斷：FIT 的項目類型可以讀。`fit_table()` 目前只處理 type 0x01（microcode），其他類型被略過；擴充只要記錄每個類型的筆數與位址。
- 狀態：`observed`／`not-found`；FIT 找不到或映像是 capsule、被 PFAT 解封裝過的檔案時是 GAP（`ci-container-unsupported`），不能寫 not-found。
  observed 時生效與否另列 CI-02。
- 樣本觀察（2026-11-15，唯讀）：`novacustom-v540tu-mtl-v1.0.1` 的 `..._btg_prod.rom` 有 type 0x01 一筆、0x02 一筆、0x0B 一筆、0x0C 一筆，
  KM 位置開頭是 `__KEYM__`、BPM 位置開頭是 `__ACBP__`；`dasharo-protectli-vp46xx-v1.2.0` 只有 type 0x01 三筆；
  `novacustom-nuc-box-arl-v0.9.2` 只有 type 0x01 一筆；`intel-nuc11-patgl357-0059` 的 `.CAP` 檔 FIT 指標找不到（capsule 檔，非完整 SPI 映像，不能當作沒有 Boot Guard）。
  檔名的 `btg_prod` 只是檔名，不是依據。
- 適用：x86 Intel 平台有對應；AMD 平台沒有 FIT（走 CI-05）；vBIOS、Jetson 沒有對應結構。
- 現有涵蓋：`x86_firmware.py` 的 `fit_table()` 與 `sca-center:fit` property 只報 FIT 狀態與 microcode 的 in_fit；Boot Guard 項目沒有報。

**CI-02 Boot Guard 是否生效**（不行）
- 摘要：Boot Guard 的啟用與 OEM 金鑰雜湊存在晶片組的熔絲（platform fuse），映像裡的 KM／BPM 只是「如果啟用，驗證用的資料」。
- 判斷：映像讀不到熔絲。要看上機工具輸出或廠商文件。
- 狀態：`NOT_ASSESSED`，`ci-needs-fuse-state`。若日後收到上機取得的結果，依 D-035 屬 `on-device` 類依據，另設欄位。
- 適用：同 CI-01。
- 現有涵蓋：無。

**CI-03 BIOS Guard（AMI PFAT）簽章結構與 SVN**（部分）
- 摘要：AMI 的更新包裡，每個 block 帶 Intel BIOS Guard 標頭（版本、平台 ID、BIOS SVN、EC SVN）與 RSA 簽章區。
- 判斷：結構已解析；簽章沒驗，也不能驗：公鑰雜湊在晶片組，不在映像（`ci-root-of-trust-not-in-image`）。只有 AMI PFAT 容器讀得到，
  其他廠商或格式的 BIOS Guard 資料沒有解析（`ci-container-unsupported`）。
- 狀態：`observed`（PFAT）＋ 簽章 `NOT_ASSESSED`（`ci-signature-not-verified`）。
- 樣本觀察：`intel-nuc11-patgl357-0059`：29 個 block、每個有 RSA-2048 簽章、BIOS Guard 版本 2.0、平台 ID `TIGERLAKE`、BIOS SVN 0x57000、EC SVN 1（與 `docs/notes/c2-ami-pfat.md` 相同）。
- 適用：AMI 的 Intel 平台；其他 x86 要看有沒有被 PFAT 包裝；vBIOS、Jetson 沒有對應結構。
- 現有涵蓋：`ami_pfat.py`、`x86_firmware.py` 的 `pfat_props()`：`dumpling:pfat-signature` ＝ `not verified`；`fw-inventory.json` 的 `pfat.info`（`signature_bits`、`bg_version`、`bios_svn`、`ec_svn`）與 `signature_verified: false`。
  已涵蓋結構與「沒驗」的聲明；沒有彙整成一個完整性區段。

**CI-04 Intel CSME 韌體 manifest 的簽章欄位**（部分）
- 摘要：CSME 的 `$CPD`／`$MN2` manifest 帶廠商公鑰與簽章欄位。
- 判斷：目前只讀 `$MN2` 的版本與日期；公鑰與簽章欄位沒有解析，欄位位置的公開文件沒有讀到（`ci-no-public-basis`）。就算解析，驗簽要的根金鑰雜湊在 ROM／熔絲，不在映像。
- 狀態：`GAP`（`ci-no-public-basis`）。
- 適用：Intel 完整 SPI 映像（有 ME 區域）；其他沒有對應結構。
- 現有涵蓋：`docs/notes/c2-csme-layout.md`、`intel_cse_layout.py`、`x86_firmware.py` 的 `me_manifests()`：只有版本。
  D-050 的限制（版本是映像自述的欄位）已寫在 SBOM 的 `sca-center:version-basis`。

**CI-05 AMD PSP 目錄的金鑰與簽章項目**（可以）
- 摘要：PSP／BIOS 目錄裡有哪些金鑰項目（PUBKEY、ABL_PUBKEY、RTM_PUBKEY、KEYDB_*、BIOS 目錄的 SIG、VERSTAGE_SIG）。
- 判斷：`amd_psp.py` 已把每個目錄項目依 type 命名；缺的只是彙整。
- 狀態：`observed`／`not-found`（目錄解析完整時）；有 GAP 或被拒絕的目錄時 `GAP`（沿用 D-050 的「遇到上限、不支援一律 GAP」）。
- 樣本觀察：`asus-prime-b550m-a-3404`：PUBKEY 8 筆（psp 6、psp-l2 2）、ABL_PUBKEY 3 筆、KEYDB_BL 3 筆、KEYDB_TOS 3 筆、TOS_SEC_POLICY 5 筆；
  沒有 RTM_PUBKEY、SIG、VERSTAGE_SIG 的項目。這是「目錄裡有哪些項目」，不是「簽章有效」。該次解析另有 10 項 GAP、2 個 EFS 指標沒解析（Promontory）。
- 適用：AMD 平台；Intel 沒有對應結構。
- 現有涵蓋：`fw-inventory.json` 的 `amd.directories[].entries[]` 有 type 名稱；報告沒有彙整、沒有單獨的 property。
  `docs/notes/c2-amd-psp.md` 寫明「沒有簽章驗證，PSP 條目版本是映像自述的欄位」。

**CI-06 AMD Platform Secure Boot（PSB）是否生效**（不行）
- 摘要：PSB 是否啟用、驗證用的 OEM 金鑰是否熔入，在處理器熔絲。
- 判斷：映像裡的 FUSE_CHAIN 項目（type 0x0B，位址欄位是值）是軟熔絲設定，不是硬體熔絲狀態；各位元的意義沒有公開文件可引用（`ci-no-public-basis`），不解讀。
- 狀態：`NOT_ASSESSED`，`ci-needs-fuse-state`。
- 適用：AMD 平台。
- 現有涵蓋：無。

**CI-07 除錯與解鎖相關項目**（部分）
- 摘要：映像裡有沒有除錯政策或解鎖權杖項目（AMD：SECURED_DEBUG、DEBUG_UNLOCK、TOKEN_UNLOCK；Intel：FIT type 0x2F JMP debug policy）。
- 判斷：項目是否存在可以讀；除錯是否被鎖住要看熔絲或上機。
- 狀態：`observed`／`not-found` ＋ 鎖定狀態 `NOT_ASSESSED`（`ci-needs-fuse-state`）。
- 樣本觀察：`asus-prime-b550m-a-3404` 的 SECURED_DEBUG、DEBUG_UNLOCK、TOKEN_UNLOCK 各 6 筆；三個 Dasharo／NovaCustom 完整映像的 FIT 沒有 0x2F。
- 現有涵蓋：無。

**CI-08 UEFI Secure Boot 程式能力**（部分）
- 摘要：韌體的 DXE 裡有沒有映像驗證與 Secure Boot 設定的程式。
- 判斷：目前只能用字串啟發式；GUID 對應的模組身分沒有建表。字串存在不等於啟用。
- 狀態：`observed`（啟發式）／`not-found`（完整解開時）／`GAP`（有壓縮區段沒解開，例如 EFI 標準壓縮）。
- 樣本觀察：`ubuntu-ovmf-2024.02` 的 `OVMF_CODE_4M.secboot.fd`（完整解開）有 `SecureBootEnable`（2 次）、`SecureBootConfig`（1 次）、`certdb`（2 次）；
  同一套件的 `OVMF_CODE_4M.fd` 沒有這三個字串。兩者都有 `SecureBoot`、`KEK`、`dbx`、`SetupMode`（變數處理程式本來就會出現）。所以只有「設定介面與 certdb」字串能區分這兩個建置。
  `intel-nuc11-patgl357-0059` 有 42 個壓縮 UEFI 區段沒解析、30 個 UEFI 部分沒解碼，這一項對它是 GAP。
- 適用：所有有 UEFI 的 x86 映像；coreboot＋edk2 的映像在 CBFS 的 payload 裡，要先解 CBFS 與壓縮；vBIOS 沒有對應結構；Jetson 的 UEFI 在 BSP 的 `uefi_*.bin`（C1）。
- 現有涵蓋：`uefi_image.py`（C1）是函式庫指紋；`x86_firmware.py` 的 `FvStats` 只統計；沒有 Secure Boot 項目。

**CI-09 PK／KEK／db／dbx 變數的存在與內容**（部分）
- 摘要：映像或 NVRAM 範本裡有沒有 Secure Boot 變數、裡面註冊了哪些憑證或雜湊。
- 判斷：變數名稱讀得到（UTF-16 字串）；內容是驗證變數的簽章清單（EFI_SIGNATURE_LIST），解析規格公開（UEFI 規格；本專案未讀，未核對）。
  廠商 BIOS 把預設金鑰放在映像哪裡，各家不同，沒有公開文件的不解讀（D-058 的原則：只用公開映像反推、不用非公開資料）。
- 狀態：`observed`（名稱）／`GAP`（內容沒解析）；有解析時內容列為自述值（`ci-self-declared`），不寫「有效」。
- 樣本觀察：`ubuntu-ovmf-2024.02` 的 `OVMF_VARS_4M.ms.fd` 與 `OVMF_VARS_4M.snakeoil.fd` 都有 `PK`、`KEK`、`db`（2 筆名稱）、`dbx`、`SecureBootEnable`、`certdb`；
  `OVMF_VARS_4M.fd` 一個都沒有。名稱出現不代表變數有資料。目前 `firmware.yml` 的 `analyze` 只取 `OVMF_CODE_4M.fd`，VARS 檔不在分析範圍。
- 適用：UEFI x86 映像與 OVMF；vBIOS 沒有對應結構；Jetson 的預設金鑰在 BSP（C1）。
- 現有涵蓋：無。

**CI-10 Secure Boot 即時狀態**（不行）
- 摘要：`SecureBoot`、`SetupMode`、`AuditMode`、`DeployedMode` 這類執行期變數的值。
- 判斷：映像裡沒有；只有上機讀得到。
- 狀態：x86 目前沒有收集：`NOT_RUN`（`ci-needs-board`）。Jetson 的上機收集已經存在：`board_import.py` 讀 `efivar-SecureBoot`、`efivar-SetupMode`，
  `runtime_evidence.py` 把它們列為「reported」（只報值，不判斷，也沒有進 Annex I）。
- 適用：x86 要另有上機收集流程；Jetson 已有（C1）。
- 現有涵蓋：見上；`image_check.py` 的 `NEEDS_BOARD` 清單提到「secure boot and disk encryption state」需要板子。

**CI-11 金鑰是測試金鑰或已公開外洩金鑰**（部分）
- 摘要：註冊或使用的金鑰是否屬於公開已知的測試金鑰（私鑰隨套件公開，或廠商公告外洩）。
- 來源：S（UEFI 簽章）有這個概念，但它用路徑名稱樣式判斷；本專案要的是公開依據。
- 判斷：只有在有公開依據時才能判斷。映像裡的憑證（或憑證雜湊）與一份公開的對照表（憑證指紋、出處、核對日期）比對。
  已確認的公開依據例：`ubuntu-ovmf-2024.02` 的套件說明（`ovmf.README.Debian`）明寫 `snakeoil` 映像僅供測試、PK／KEK／DB 內含只能用於測試的金鑰（原文用 insecure 形容）、私鑰與憑證隨同套件提供。
  其他候選依據（例如 AMI 測試 Platform Key 事件的公告）沒有讀；收錄規則在第 3.3 節：只收公告本身公布的憑證主體字串與指紋，外洩或非公開的資料（例如外洩的 Boot Guard 金鑰、外洩的 AMI 資料）不收。
- 狀態：比對到表內項目 → `observed`＋依據編號；沒比到 → `NOT_ASSESSED`（`ci-key-class-unknown`，沒有比到不代表是正式金鑰）；沒有解析憑證 → `GAP`。
- 適用：有 db／PK 的 UEFI 映像；Jetson 的預設金鑰（C1）；vBIOS 沒有對應結構。
- 現有涵蓋：無。

**CI-12 coreboot 驗證開機（vboot）**（部分）
- 摘要：coreboot 設定是否啟用 vboot，FMAP 有沒有 vboot 用的區域。
- 判斷：`CONFIG_VBOOT` 已由 CBFS 的 config 讀出；它是建置選項，不等於簽章驗證在執行。
- 狀態：`observed`（設定值）＋ 生效與否 `NOT_ASSESSED`。
- 樣本觀察：`dasharo-protectli-vp46xx-v1.2.0` 與 `novacustom-v540tu-mtl-v1.0.1` 的 config 都是 `CONFIG_VBOOT=y`；兩者的 FMAP 區域名單是 COREBOOT、FW_MAIN_A、BOOTSPLASH，
  沒有看到 GBB 或 VBLOCK 一類名稱。這代表什麼不確定（沒有讀 Dasharo 的 vboot 設計文件）。
- 適用：coreboot 韌體；其他 x86 沒有對應結構。
- 現有涵蓋：`coreboot_cbfs.py` 的 `CONFIG_KEYS` 保留 `VBOOT`，`fw-inventory.json` 的 `cbfs.coreboot[].config.keys`；其他 vboot、measured boot 的選項沒有保留。

**CI-13 回滾保護**（部分）
- 摘要：映像宣告的 SVN（Security Version Number）與更新時拒絕舊版的機制。
- 判斷：SVN 欄位讀得到（PFAT 的 BIOS SVN、EC SVN；其他格式的 SVN 位置沒有公開依據就不讀）。是否強制拒絕舊版在熔絲或計數器，映像裡沒有。
- 狀態：`observed`（自述值，`ci-self-declared`）＋ 強制與否 `NOT_ASSESSED`（`ci-needs-fuse-state`）。
- 現有涵蓋：`fw-inventory.json` 的 `pfat.info.bios_svn`、`ec_svn`；沒有進 SBOM 或報告文字。

**CI-14 韌體更新包的簽章**（部分）
- 摘要：兩個層次：(1) 取得端：下載的映像有沒有官方簽章或雜湊；(2) 更新包本身（capsule、廠商更新程式）有沒有簽章結構。
- 判斷：(1) 已有設計與實作（D-059）；(2) capsule 內的簽章結構（UEFI capsule 的認證標頭、廠商私有格式）沒有解析，格式文件沒有讀（`ci-container-unsupported`）。
- 狀態：(1) `signed`／`same-origin`／`none`（既有欄位 `provenance`）；(2) `GAP`。
- 現有涵蓋：`docs/notes/c2-bios-discovery.md` 第 5 節（OpenPGP 驗簽、固定金鑰、過期金鑰一律 FAIL）與 `pipeline/firmware-fetch.sh`（sha256 核對）。簽章只證明檔案由金鑰持有者簽出，不證明內容正確（該筆記已寫明）。

**CI-15 度量開機（TPM、Tcg2）**（部分）
- 摘要：韌體有沒有 TPM 度量的程式與設定。
- 判斷：Tcg2 模組字串、coreboot 的 `TPM_MEASURED_BOOT`、`INTEL_CBNT_SUPPORT` 設定讀得到；PCR 實際值是執行期，映像沒有。
- 狀態：`observed`（啟發式）／`GAP`；PCR 值 `NOT_RUN`（`ci-needs-board`）。
- 樣本觀察：`OVMF_CODE_4M.fd` 與 `.secboot.fd` 都有 `Tcg2` 字串（8、7 次）。
- 現有涵蓋：無。

**CI-24 驗證用密碼演算法與金鑰強度**（部分）
- 摘要：映像裡的簽章、雜湊與憑證用什麼演算法、多長的金鑰。
- 判斷：映像自述的欄位讀得到才記。AMI PFAT 的 RSA 簽章長度已讀；Boot Guard KM／BPM、CSME、PSP 金鑰項目的演算法欄位沒有公開文件可引用，不解讀（`ci-no-public-basis`）；
  UEFI 的憑證解析後（CI-09）可讀 X.509 的簽章演算法與公鑰長度。ETSI 5.6.21 引用的 ECCG 核可機制清單本身沒有讀（未核對），所以不判斷符不符合，只記觀察值。
- 狀態：`observed`（自述值，`ci-self-declared`）／`GAP`；與核可清單的比對 `NOT_ASSESSED`。
- 樣本觀察：`intel-nuc11-patgl357-0059` 的 PFAT 簽章是 RSA-2048（同 CI-03）；其他沒有量過。
- 適用：同 CI-03、CI-09；vBIOS 與 OS 映像看 PE 簽章的演算法（CI-16、CI-18）。
- 現有涵蓋：`fw-inventory.json` 的 `pfat.info.signature_bits`；其餘沒有。

**CI-25 除錯建置與非必要功能的殘留**（部分）
- 摘要：映像有沒有除錯建置的標記或可能用不到的功能：coreboot 設定裡的除錯主控台與詳細記錄選項、UEFI 的除錯字串與 UEFI Shell、網路開機（PXE、HTTP 開機）驅動。
  網路開機有沒有，也決定 ETSI 一批條件式條款（5.6.14 至 5.6.16、5.8.9、5.8.10、5.9.1 等）是否適用。
- 判斷：字串與模組的存在讀得到（啟發式，同 CI-08）。「非必要」取決於產品用途，映像判斷不了。coreboot 設定目前只保留少數 `CONFIG_KEYS`，除錯相關選項沒有保留。
- 狀態：`observed`（啟發式）／`not-found`（完整解開時）／`GAP`（有壓縮區段沒解開）；是否非必要 `NOT_ASSESSED`。
- 樣本觀察：沒有量過。
- 適用：UEFI x86 映像（同 CI-08）與 coreboot 韌體（同 CI-12）；vBIOS 沒有對應結構；Jetson 的 UEFI 在 BSP（C1）。
- 現有涵蓋：`coreboot_cbfs.py` 的 `CONFIG_KEYS` 只保留 `VBOOT` 等；payload 清單（`PAYLOAD_*`）已有，其他選項沒有。

**CI-26 SPI 快閃寫入保護與區域存取權**（部分）
- 摘要：Intel 完整映像的 flash descriptor 除了區域表，還記錄各主控端對各區域的讀寫權限，這會影響軟體能不能改寫 BIOS 區域。
- 判斷：區域表已讀；權限欄位與保護範圍暫存器的位置與意義，這份筆記沒有讀公開文件（可能的依據如 coreboot 的 `util/ifdtool`，未讀），標 `GAP`（`ci-no-public-basis`）。
  映像裡的 descriptor 只是設定值，實際鎖定看晶片組暫存器，要上機。
- 狀態：區域表 `observed`；權限欄位 `GAP`；實際鎖定 `NOT_ASSESSED`（`ci-needs-board`）。
- 樣本觀察：沒有量過。
- 適用：有 Intel descriptor 的完整 SPI 映像；AMD 平台與 capsule 檔沒有對應結構。
- 現有涵蓋：`x86_firmware.py` 讀 descriptor 的區域表（用在 ME 區域判斷）；權限欄位沒有讀。

#### vBIOS

**CI-16 選項 ROM 內 EFI 影像的 Authenticode 簽章**（部分）
- 摘要：選項 ROM 的 EFI 影像是 PE；PE 的 Certificate Table（資料目錄第 4 項）有內容代表帶 Authenticode 簽章。
- 判斷：結構可讀；`intel_vbios.pe_info()` 已讀 PE 標頭但沒讀資料目錄。真實樣本不足：NVIDIA 獨立 vBIOS 是 GAP（沒有官方可下載的檔案），
  更新工具裡的 EFI 影像是壓縮的範本，需要 Tiano 解碼器（本 repo 沒有）。Intel 的 GOP 在 BIOS 映像裡，它的完整性靠映像層級機制（CI-01、CI-03）。
- 狀態：`observed`／`not-found`（有解開 PE 時）／`GAP`（`ci-no-sample` 或 `ci-container-unsupported`）。簽章有效性 `NOT_ASSESSED`；
  要被 Secure Boot 接受還要看平台的 db，映像不含（CI-10）。
- 適用：vBIOS 與 PCI 選項 ROM；BIOS 內嵌的 GOP 不單獨驗；Jetson 沒有對應結構。
- 現有涵蓋：`docs/notes/c2-vbios.md` 只記錄 NVIDIA 工具本體（nvflash 類的 exe）有 Authenticode 目錄，那不是 vBIOS 的簽章。

**CI-17 NVIDIA vBIOS 本身的廠商簽章**（不行）
- 摘要：NVIDIA 的 ROM 可能含廠商簽章與內容校驗區段。
- 判斷：沒有公開格式文件、沒有真實樣本（`ci-no-public-basis`、`ci-no-sample`）。依 D-058 的原則不使用非公開資料。
- 狀態：`GAP`。
- 現有涵蓋：`firmware/vbios/standalone-nvidia-option-rom/firmware.yml` 已標 GAP；CI 用合成 ROM 只測流程，不代表任何真實 vBIOS。

#### Jetson 與 OS 映像（C1 範圍；以下只寫能不能判斷）

**CI-18 開機載入程式與核心的 UEFI 簽章**（可以）
- S 機制：UEFI 簽章。映像內 `.efi` 的 PE Certificate Table 有沒有內容；簽章金鑰的設定不在已出貨映像。
- 判斷：PE 結構可讀（同 CI-16）；簽章有效與信任鏈要看 db（CI-09、CI-10）。
- 適用：有 EFI 開機分割區的映像；Jetson 是否用 BSP 的 `l4t_uefi_sign_image.sh` 簽的檔案（BSP 主機端工具，`platform.yml` 的 host-tool 清單已列）要由 C1 確認檔案型態。
- 現有涵蓋：無。

**CI-19 FIT 簽章（U-Boot）**（可以）
- S 機制：FIT。FDT 魔術字加簽章節點。shipcheck 用「內文含 `signature` 字樣」判斷，這是子字串比對；若要做，應解析 FDT 節點結構。
- 適用：用 U-Boot FIT 的 OS 映像。Jetson 的 BSP 用 UEFI 與 extlinux，映像裡預期沒有 `.itb`；找不到時是 `not-found`（解析完整才成立），不是平台層級的結論。
- 現有涵蓋：無。

**CI-20 dm-verity**（部分）
- S 機制：dm-verity。可讀的證據：核心 `CONFIG_DM_VERITY`、映像裡的 verity 超級區塊或雜湊樹檔案、開機參數或 initrd 腳本的 verity 設定。
  是否在執行、根雜湊由誰簽，要上機或看簽章。
- 狀態：`observed`／`not-found`／`GAP`＋生效 `NOT_ASSESSED`（`ci-needs-board`）。
- 現有涵蓋：無（C1 已讀核心 `.config` 做漏洞可利用性，見 `tools/pilot/lib/kernel_config.py`，沒有 verity 項目）。

**CI-21 IMA／EVM**（部分）
- S 機制：IMA/EVM。可讀的證據：核心 `CONFIG_IMA`、`CONFIG_IMA_APPRAISE`、`CONFIG_EVM`；套件 `ima-evm-utils`；policy 檔；rootfs 檔案的 `security.ima` xattr（取決於 rootfs 封存是否保留 xattr）。
  shipcheck 自己把「只有套件」標為低信心。
- 狀態：同 CI-20。
- 現有涵蓋：無。

**CI-22 核心模組簽章與 lockdown 設定**（可以）
- 不在 shipcheck 內；`image_check.py` 的 `NEEDS_BOARD` 提到 module signing 需要板子。核心 `.config` 的 `CONFIG_MODULE_SIG`、`CONFIG_MODULE_SIG_FORCE`、`CONFIG_SECURITY_LOCKDOWN_LSM` 是建置期設定，讀得到；
  執行期是否 lockdown 要上機。可以判斷的是建置設定。
- 現有涵蓋：`scan/kernel-config.json`（D-057 提到的建置依據）已有 `.config` 的來源，項目要不要加由 C1 決定。

**CI-23 Jetson 熔絲與簽署流程**（不行）
- 摘要：Jetson 的簽章開機靠熔絲（金鑰雜湊與開機驗證相關的熔絲）與主機端簽署流程，不在已出貨的 rootfs 或公開 BSP 檔案裡。
- 判斷：熔絲要用 BSP 的主機端工具在板子進復原模式時讀（`odmfuseread.sh` 在 `platform.yml` 的 host-tool 清單；怎麼讀、輸出格式本專案沒有讀文件，未核對）。
  公開 BSP 的 bootloader 檔名樣式（例如 `sb_bl1*_prod`）已被 `bootloader_coverage.py` 分到「Secure boot firmware」，只是分類，不是驗證。
- 狀態：`NOT_ASSESSED`（`ci-needs-fuse-state`／`ci-needs-board`）。
- 現有涵蓋：`bootloader_coverage.py`、`cra_report.py` 的 `B-bootloader-coverage`（D-054：閉源韌體以廠商公告為準，進報告狀態、不擋閘門）。

### 2.4 ETSI 條款對照

依據是第 1.1 節取得的 v0.0.12（2025-12）第 5 節，共 92 個編號條款（5.2 至 5.12；5.13 只是指向第 6 節與附錄 C 的說明，不計）。條款文字不複製，摘要都是自己的話。

對照只表示「這條說的機制，在映像裡會留下哪一類結構」，不表示條款已滿足或未滿足。條款的適用條件（風險等級 LOW／MEDIUM／HIGH、有沒有驗證開機、更新、設定、網路開機等能力）取決於產品，映像判斷不了，報告不判斷哪些條款適用。

統計：92 條中，41 條對得到至少一個 CI 項目，51 條沒有對應項目。26 個 CI 項目中，22 個至少對到一條本文條款；4 個沒有本文條款，原因碼 `ci-etsi-clause-gap`：CI-11（只有資訊性附錄 B 間接關聯）、CI-20、CI-21、CI-22（草稿範圍止於交棒給開機目標）。

#### 2.4.1 CI 項目對條款

| CI | 項目 | 對應條款（v0.0.12） | 原因碼 |
|---|---|---|---|
| CI-01 | Intel Boot Guard 結構 | 5.6.1、5.6.5、5.12.4 | — |
| CI-02 | Boot Guard 是否生效 | 5.3.1、5.6.2、5.6.18、5.12.8 | — |
| CI-03 | BIOS Guard（AMI PFAT）簽章結構與 SVN | 5.6.4、5.6.5、5.12.4、5.12.6、5.12.8 | — |
| CI-04 | Intel CSME 韌體 manifest 的簽章欄位 | 5.6.1、5.6.3 | — |
| CI-05 | AMD PSP 目錄的金鑰與簽章項目 | 5.6.1 | — |
| CI-06 | AMD PSB 是否生效 | 5.3.1、5.6.2 | — |
| CI-07 | 除錯與解鎖相關項目 | 5.2.3、5.3.2、5.10.2 | — |
| CI-08 | UEFI Secure Boot 程式能力 | 5.3.1、5.6.1 | — |
| CI-09 | PK／KEK／db／dbx 變數 | 5.4.1、5.4.5、5.4.7、5.5.1、5.6.3、5.6.19、5.6.20 | — |
| CI-10 | Secure Boot 即時狀態 | 5.3.1、5.6.2 | — |
| CI-11 | 測試金鑰或已公開外洩金鑰 | 本文沒有條款；資訊性的附錄 B 把威脅 T-SUPPLY-6（預設或外洩的平台金鑰）對到 5.4.1 | `ci-etsi-clause-gap`（僅限本文層級） |
| CI-12 | coreboot 驗證開機（vboot） | 5.3.1、5.6.1、5.6.5、5.6.6、5.8.2、5.8.7、5.12.4 | — |
| CI-13 | 回滾保護 | 5.6.17、5.6.18 | — |
| CI-14 | 韌體更新包的簽章 | 5.6.4、5.12.6、5.12.7 | — |
| CI-15 | 度量開機 | 5.6.23、5.11.1、5.11.2、5.11.3 | — |
| CI-16 | 選項 ROM 的 Authenticode 簽章 | 5.6.1、5.6.3（附錄 E.5：選項 ROM 只有和開機有關時才在範圍） | — |
| CI-17 | NVIDIA vBIOS 廠商簽章 | 5.6.1、5.6.3（同 CI-16） | — |
| CI-18 | 開機載入程式與核心的 UEFI 簽章 | 5.6.1、5.6.3、5.6.19（開機載入程式驗核心屬範圍內；核心之後的防護不是） | — |
| CI-19 | FIT 簽章（U-Boot） | 5.6.1 | — |
| CI-20 | dm-verity | 沒有條款：草稿範圍到把控制權交給開機目標為止（1.1），交棒後的作業系統層防護由開機目標負責（4.5.4） | `ci-etsi-clause-gap` |
| CI-21 | IMA／EVM | 沒有條款，理由同 CI-20 | `ci-etsi-clause-gap` |
| CI-22 | 核心模組簽章與 lockdown | 沒有條款，理由同 CI-20 | `ci-etsi-clause-gap` |
| CI-23 | Jetson 熔絲與簽署流程 | 5.3.1、5.6.1 | — |
| CI-24 | 驗證用密碼演算法與金鑰強度 | 5.2.5、5.6.7、5.6.8、5.6.21、5.6.22、5.6.23 | — |
| CI-25 | 除錯建置與非必要功能的殘留 | 5.6.14、5.6.15、5.6.16、5.10.1、5.10.2、5.10.3 | — |
| CI-26 | SPI 快閃寫入保護與區域存取權 | 5.4.2、5.4.7、5.6.5、5.6.12、5.8.14 | — |

#### 2.4.2 條款對 CI 項目

「沒有對應項目」的條款逐條重新評估是否缺項。評估結果：

- 新增 3 項，補在第 2.2、2.3 節：CI-24（5.2.5、5.6.7、5.6.8、5.6.21 至 5.6.23：演算法與金鑰強度）、CI-25（5.6.14 至 5.6.16、5.10.1 至 5.10.3：除錯建置與網路開機等非必要功能的殘留）、CI-26（5.4.2、5.4.7、5.6.5、5.6.12、5.8.14：SPI 寫入保護與區域存取權）。
- 其餘 51 條沒有新增項目。原因分三類：執行期或功能行為，映像沒有證據（占大多數）；證據在映像之外（5.10.4 的模糊測試證據在附錄 C）；映像沒有可判斷的內容（5.8.13 的時間表示）。
- 5.12.1（版本資訊）：映像自述的版本由既有的版本讀取處理（D-050），屬版本與 SBOM 工作，不是完整性證據，不新增 CI 項目。

| 條款 | 摘要（自己的話） | 對應 CI 項目 |
|---|---|---|
| 5.2.1 `RQ-SBD-001` | 開機元件之間要用記憶體保護、權限分離或硬體隔離互相隔開。 | 沒有對應項目；執行期隔離；映像沒有可讀的證據。不新增 |
| 5.2.2 `RQ-SBD-002` | 金鑰材料只能讓被授權的開機元件取用。 | 沒有對應項目；存取控制在執行期與硬體。不新增 |
| 5.2.3 `RQ-SBD-003` | 把控制權交給開機目標之前，只留下目標需要的資源（備註舉例含除錯介面）。 | CI-07 |
| 5.2.4 `RQ-SBD-004` | 不同開機階段之間要有權限界線，低階段不能取得高階段的權限。 | 沒有對應項目；執行期。不新增 |
| 5.2.5 `RQ-SBD-005` | 對稱金鑰的驗證開機或度量開機要用每台裝置各自的金鑰，禁止全域共用的對稱金鑰。 | CI-24；只能看出用對稱或非對稱，看不出金鑰是否每台唯一 |
| 5.3.1 `RQ-DEFAULT-001` | 出廠預設要開啟密碼學驗證。 | CI-02、CI-06、CI-08、CI-10、CI-12、CI-23；預設值只有結構與範本，生效看熔絲或上機 |
| 5.3.2 `RQ-DEFAULT-002` | 不得留有未文件化、可繞過認證或控制的機制。 | CI-07；解鎖權杖與除錯政策項目是可讀的跡象 |
| 5.3.3 `RQ-DEFAULT-003` | 使用密碼時，密碼要在首次部署時由使用者建立。 | 沒有對應項目；設定狀態在執行期。不新增 |
| 5.3.4 `RQ-DEFAULT-004` | 不得自動退回較弱的開機模式。 | 沒有對應項目；執行期行為。不新增 |
| 5.3.5 `RQ-DEFAULT-005` | 有使用者介面時，防護被降低要有看得見的提示。 | 沒有對應項目；執行期行為。不新增 |
| 5.3.6 `RQ-DEFAULT-006` | 要能把設定還原成預設的防護狀態。 | 沒有對應項目；功能行為。不新增 |
| 5.4.1 `RQ-AUTH-001` | 變更受信任金鑰、憑證或信任錨資料庫，只能經實體在場，或經開機管理器驗過簽章的檔案。 | CI-09；附錄 B 的威脅 T-SUPPLY-6（預設或外洩的平台金鑰）對到這一條，CI-11 只有這個間接關聯 |
| 5.4.2 `RQ-AUTH-002` | 開機流程相關的設定要防未授權修改。 | CI-26 |
| 5.4.3 `RQ-AUTH-003` | 修改關鍵設定前要有使用者明確動作與認證。 | 沒有對應項目；執行期。不新增 |
| 5.4.4 `RQ-AUTH-004` | 使用密碼時，要用硬體綁定的方式限制嘗試次數或拉長間隔。 | 沒有對應項目；執行期。不新增 |
| 5.4.5 `RQ-AUTH-005` | 套用開機防護的設定政策之前，要先驗證政策的真偽與完整。 | CI-09；政策以簽章變數存放時，映像裡才有結構 |
| 5.4.6 `RQ-AUTH-006` | 以被改過的政策運作時，要用常駐畫面提示或記錄事件。 | 沒有對應項目；執行期。不新增 |
| 5.4.7 `RQ-AUTH-007` | 受信任的憑證儲存要防未授權修改。 | CI-09、CI-26 |
| 5.5.1 `RQ-CONFID-001` | 金鑰只能用在指定的用途。 | CI-09；憑證解析後才讀得到用途欄位；目前沒解析 |
| 5.5.2 `RQ-CONFID-002` | 崩潰傾印與記錄不得含敏感資料。 | 沒有對應項目；執行期。不新增 |
| 5.5.3 `RQ-CONFID-003` | 儲存的憑證要用無法還原原值的方式保護。 | 沒有對應項目；執行期資料。不新增 |
| 5.5.4 `RQ-CONFID-004` | 含認證資訊的網路開機參數要防洩漏。 | 沒有對應項目；執行期資料。不新增 |
| 5.5.5 `RQ-CONFID-005` | 報廢時要以密碼學方式抹除敏感資料並清掉防護設定。 | 沒有對應項目；功能行為。不新增 |
| 5.5.6 `RQ-CONFID-006` | 支援報廢清除時，完成後要有提示。 | 沒有對應項目；功能行為。不新增 |
| 5.5.7 `RQ-CONFID-007` | 經網路傳送的開機設定要保護機密與完整。 | 沒有對應項目；執行期。不新增 |
| 5.5.8 `RQ-CONFID-008` | 用完的機密資料要覆寫，交棒前清掉暫存的憑證，不跨開機週期保存。 | 沒有對應項目；執行期。不新增 |
| 5.6.1 `RQ-INTEGRITY-001` | 每個開機階段都要用核可的密碼機制驗完整與真偽，並建立到根信任錨的信任鏈，驗過才交出控制權。 | CI-01、CI-04、CI-05、CI-08、CI-12、CI-16、CI-17、CI-18、CI-19、CI-23 |
| 5.6.2 `RQ-INTEGRITY-002` | 驗證失敗的元件不得繼續開機。 | CI-02、CI-06、CI-10；只有結構；是否強制看熔絲或上機 |
| 5.6.3 `RQ-INTEGRITY-003` | 用憑證驗元件出處，並檢查元件相容與版本一致。 | CI-04、CI-09、CI-16、CI-17、CI-18 |
| 5.6.4 `RQ-INTEGRITY-004` | 更新包在安裝前與網路傳輸後要驗真偽與完整。 | CI-03、CI-14 |
| 5.6.5 `RQ-INTEGRITY-005` | 要用多層驗證機制偵測韌體被改。 | CI-01、CI-03、CI-12、CI-26；映像看得到幾種機制的結構；機制之間是否獨立判斷不了 |
| 5.6.6 `RQ-INTEGRITY-006` | 沒有硬體資安元件時，要用軟體密碼驗證，金鑰放在受保護的儲存。 | CI-12；vboot 屬軟體驗證的一種 |
| 5.6.7 `RQ-INTEGRITY-007` | 要有可設定的核可簽章演算法清單。 | CI-24 |
| 5.6.8 `RQ-INTEGRITY-008` | 要支援多種簽章演算法。 | CI-24 |
| 5.6.9 `RQ-INTEGRITY-009` | 略過驗證之前要先通過認證。 | 沒有對應項目；執行期。不新增 |
| 5.6.10 `RQ-INTEGRITY-010` | 驗證完成到執行之間，元件不得被改。 | 沒有對應項目；執行期（時間差問題）。不新增 |
| 5.6.11 `RQ-INTEGRITY-011` | 硬體支援時，元件要先載入受保護記憶體再驗證。 | 沒有對應項目；執行期。不新增 |
| 5.6.12 `RQ-INTEGRITY-012` | 敏感設定要放硬體保護儲存，或用具新鮮性的認證加密保護。 | CI-26；其餘是執行期 |
| 5.6.13 `RQ-INTEGRITY-013` | 偵測到設定損壞時，可行的話還原預設設定。 | 沒有對應項目；執行期。不新增 |
| 5.6.14 `RQ-INTEGRITY-014` | 授權伺服器可啟動動作或提供未認證資料時，要用憑證認證網路開機伺服器。 | CI-25；映像只能看網路開機驅動在不在，決定這條適用與否；憑證行為在執行期 |
| 5.6.15 `RQ-INTEGRITY-015` | 拒絕憑證無效、過期或被撤銷的網路開機連線。 | CI-25；同 5.6.14 |
| 5.6.16 `RQ-INTEGRITY-016` | 網路設定與開機回應要確認來自授權的基礎設施。 | CI-25；同 5.6.14 |
| 5.6.17 `RQ-INTEGRITY-017` | 預設就要對韌體與防護設定做回滾保護。 | CI-13 |
| 5.6.18 `RQ-INTEGRITY-018` | 防回滾計數器放硬體支援或防篡改儲存，接受更新前驗簽章的版本資料。 | CI-13、CI-02；計數器在熔絲或晶片組，映像只有自述的 SVN |
| 5.6.19 `RQ-INTEGRITY-019` | 使用憑證前，先驗證到受信任根的憑證鏈。 | CI-09、CI-18 |
| 5.6.20 `RQ-INTEGRITY-020` | 要能撤銷被破壞的金鑰與憑證（撤銷資料庫或設定更新）。 | CI-09；dbx 一類變數的存在與內容 |
| 5.6.21 `RQ-INTEGRITY-021` | 密碼演算法、金鑰長度與參數，要在 ECCG 核可機制清單內，或能證明等效。 | CI-24；清單本身沒有讀，不判斷符合與否 |
| 5.6.22 `RQ-INTEGRITY-022` | 要有密碼敏捷性（演算法可以更換）。 | CI-24 |
| 5.6.23 `RQ-INTEGRITY-023` | 來源認證與出處驗證要用抗碰撞、抗原像的單向函式。 | CI-24、CI-15 |
| 5.7.1 `RQ-MINIMAL-001` | 網路上只傳開機必需的資料。 | 沒有對應項目；執行期。不新增 |
| 5.7.2 `RQ-MINIMAL-002` | 不外洩敏感的裝置資訊，臨時網路憑證用完即丟。 | 沒有對應項目；執行期。不新增 |
| 5.7.3 `RQ-MINIMAL-003` | 設定儲存只留開機與防護需要的資訊。 | 沒有對應項目；要讀 NVRAM 實際內容才知道；不新增 |
| 5.8.1 `RQ-AVAIL-001` | 要能回到上一個已知良好的設定。 | 沒有對應項目；功能行為。不新增 |
| 5.8.2 `RQ-AVAIL-002` | 高風險等級要有備援開機路徑。 | CI-12；FMAP 有沒有 A／B 區域是可讀的跡象 |
| 5.8.3 `RQ-AVAIL-003` | 開機相關操作要有逾時，避免無限卡住。 | 沒有對應項目；執行期。不新增 |
| 5.8.4 `RQ-AVAIL-004` | 限制簽章驗證與網路操作的重試次數與資源用量。 | 沒有對應項目；執行期。不新增 |
| 5.8.5 `RQ-AVAIL-005` | 正常運作時不得讓驗證步驟被未授權繞過。 | 沒有對應項目；執行期。不新增 |
| 5.8.6 `RQ-AVAIL-006` | 偵測並修正關鍵資料的錯誤（平台支援時）。 | 沒有對應項目；映像內的 checksum 只證明自洽（第 3.2 節），不是這條的證據。不新增 |
| 5.8.7 `RQ-AVAIL-007` | 儲存損壞或失效時，仍要有可用的核心開機碼（非不可變記憶體）。 | CI-12；同 5.8.2 |
| 5.8.8 `RQ-AVAIL-008` | 復原模式的敏感動作要認證或實體在場。 | 沒有對應項目；執行期。不新增 |
| 5.8.9 `RQ-AVAIL-009` | 網路開機失敗時要維持開機可用。 | 沒有對應項目；執行期。不新增 |
| 5.8.10 `RQ-AVAIL-010` | 網路不可用或遭阻斷服務時，要保有本機開機能力。 | 沒有對應項目；執行期。不新增 |
| 5.8.11 `RQ-AVAIL-011` | 對資安相關的失敗情形要產生記錄。 | 沒有對應項目；執行期。不新增 |
| 5.8.12 `RQ-AVAIL-012` | 資安相關記錄要防竄改。 | 沒有對應項目；執行期。不新增 |
| 5.8.13 `RQ-AVAIL-013` | 時間表示要在 2038 年之後仍然正確。 | 沒有對應項目；要看程式內部型別，映像沒有可判斷的證據。不新增 |
| 5.8.14 `RQ-AVAIL-014` | 復原機制要防未授權修改或停用。 | CI-26 |
| 5.8.15 `RQ-AVAIL-015` | 驗證沒完成時，不得部分執行開機元件。 | 沒有對應項目；執行期。不新增 |
| 5.8.16 `RQ-AVAIL-016` | 需要的密碼元件或服務不可用時，不做敏感操作。 | 沒有對應項目；執行期。不新增 |
| 5.8.17 `RQ-AVAIL-017` | 處理違規或驗證失敗時，不得繞過控制。 | 沒有對應項目；執行期。不新增 |
| 5.8.18 `RQ-AVAIL-018` | 韌體或設定更新後，要保留復原能力。 | 沒有對應項目；執行期。不新增 |
| 5.9.1 `RQ-IMPACT-001` | 網路開機不得產生有害或擾亂網路的行為。 | 沒有對應項目；執行期。不新增 |
| 5.10.1 `RQ-SURFACE-001` | 正式建置要排除非必要的程式碼。 | CI-25；備註舉例含測試碼、除錯碼、覆蓋率工具 |
| 5.10.2 `RQ-SURFACE-002` | 停用或保護不是給正式運作用的介面與功能。 | CI-07、CI-25；備註舉例含除錯介面、診斷主控台、測試與製造模式 |
| 5.10.3 `RQ-SURFACE-003` | 移除用不到的介面與協定，縮小攻擊面。 | CI-25 |
| 5.10.4 `RQ-SURFACE-004` | 所有輸入都要驗證符合預期格式。 | 沒有對應項目；程式行為，證據在模糊測試（附錄 C），不在映像。不新增 |
| 5.10.5 `RQ-SURFACE-005` | 關鍵操作要偵測錯誤、拒絕不合規輸入並轉入錯誤處理（網路開機）。 | 沒有對應項目；執行期。不新增 |
| 5.10.6 `RQ-SURFACE-006` | 偵測設定資料被未授權修改。 | 沒有對應項目；執行期。不新增 |
| 5.10.7 `RQ-SURFACE-007` | 可設定的選項只留正常運作需要的。 | 沒有對應項目；功能行為。不新增 |
| 5.11.1 `RQ-LOG-001` | 執行或交棒之前，把開機元件與關鍵設定的度量記入防篡改儲存。 | CI-15 |
| 5.11.2 `RQ-LOG-002` | 度量記錄要防未授權修改或刪除。 | CI-15 |
| 5.11.3 `RQ-LOG-003` | 度量記錄要能供遠端證明，並有防重放的新鮮性機制。 | CI-15；映像只能看有沒有度量相關模組或設定；記錄格式是執行期產物 |
| 5.11.4 `RQ-LOG-004` | 要指示資安相關的失敗與狀態變化。 | 沒有對應項目；執行期。不新增 |
| 5.11.5 `RQ-LOG-005` | 度量記錄傳給外部驗證者時要保護完整。 | 沒有對應項目；執行期。不新增 |
| 5.12.1 `RQ-VULN-001` | 要讓作業系統或管理系統取得版本資訊。 | 沒有對應項目；映像自述的版本由既有的版本讀取處理（D-050），屬版本與 SBOM 工作，不是完整性證據。不新增 |
| 5.12.2 `RQ-VULN-002` | 有使用者介面時，顯示有更新可用的狀態。 | 沒有對應項目；功能行為。不新增 |
| 5.12.3 `RQ-VULN-003` | 有網路時，要能檢查更新是否可用。 | 沒有對應項目；功能行為。不新增 |
| 5.12.4 `RQ-VULN-004` | 沒有更新能力時，要用多個獨立機制做縱深防護。 | CI-01、CI-03、CI-12；同 5.6.5 |
| 5.12.5 `RQ-VULN-005` | 要能用設定更新政策、停用功能來處理弱點。 | 沒有對應項目；功能行為。不新增 |
| 5.12.6 `RQ-VULN-006` | 更新提交之前要先驗證。 | CI-03、CI-14 |
| 5.12.7 `RQ-VULN-007` | 只收來自已認證且授權來源的更新。 | CI-14 |
| 5.12.8 `RQ-VULN-008` | 有硬體資安元件時，用它存放更新驗證金鑰。 | CI-02、CI-03；金鑰雜湊在晶片組，不在映像（`ci-root-of-trust-not-in-image`） |
| 5.12.9 `RQ-VULN-009` | 更新邏輯要與正常開機路徑隔離。 | 沒有對應項目；執行期。不新增 |

## 3. 明確的限制

### 3.1 結構不等於生效

映像裡有 Boot Guard 的 KM／BPM、BIOS Guard 簽章、PSP 金鑰項目、Secure Boot 變數，只代表「平台若啟用這個機制，會用到這些資料」。
是否啟用在熔絲、晶片組暫存器或執行期變數，映像讀不到。報告的措辭固定為「structure observed; enforcement not assessed」，
任何欄位、property 或摘要列都不寫「驗證開機已啟用」「已簽章」這類結論。

### 3.2 自述值不等於驗過（D-050、D-058）

- 映像裡的版本、SVN、簽章長度、金鑰項目都是映像自己宣告的欄位，沒有簽章佐證；checksum 對得上只證明內容自洽，不證明沒被竄改。
  這套判斷假設映像沒被改過，要寫在 notes 與報告依據裡（沿用 D-050 的寫法）。
- 本工具不做簽章的密碼學驗證，這一點要明寫（現有 `dumpling:pfat-signature = not verified` 的做法）。
  即使日後做驗證，用映像內附的公鑰去驗映像內附的簽章只證明自洽；信任根（金鑰雜湊）在熔絲或 ROM，不在映像（`ci-root-of-trust-not-in-image`）。
- 結構是從公開映像與公開原始碼反推（D-058），不使用非公開或外洩的廠商資料；欄位意義沒有公開依據的（例如 Boot Guard KM／BPM 的政策旗標、PSP 軟熔絲位元）只記存在與數量，不解讀。

### 3.3 測試金鑰表只收公開、有明確出處的識別資訊

- 判斷「是測試金鑰」不用路徑或檔名的樣式（shipcheck 的做法），只用對照表。
- 表裡只存識別資訊：憑證主體字串與指紋（SHA-256）。**不存金鑰本身**（私鑰、公鑰檔、憑證檔都不放進 repo）。
- 收錄條件：資料已由廠商公告或 CVE 公告公開，或套件說明明寫是測試金鑰（例如上面的 `snakeoil`，只收它的憑證主體與指紋），而且有明確出處。
- 不收：外洩或非公開的資料，例如外洩的 Boot Guard 金鑰、外洩的 AMI 資料。資料在網路上流傳也不收。
- 每一筆記：出處網址、讀取日期、授權（資料的使用條件；讀不到就寫「不確定」，並不收錄到確認為止）、憑證主體、指紋、依據類型 `vendor-statement`（D-035）、核對者角色。
- 格式比照 `fw-advisory-rules.json`：一筆一個依據。比對結果只給建議並待人審。
- 比對不到只能是 `NOT_ASSESSED`；「不在表內」不是「是正式金鑰」。

### 3.4 沒找到不等於沒有

- `not-found` 只在解析完整時成立：FIT 指標找不到而映像是 capsule 或被解封裝的檔案、有壓縮區段沒解開、結構警告多，一律 `GAP`。
- CI-01 的 NUC 11 例子：`.CAP` 檔的 FIT 找不到，原因是容器不是完整 SPI 映像，不是平台沒有 Boot Guard。

### 3.5 上機狀態要有上機依據

CI-10、CI-02、CI-06、CI-23 的答案只能來自上機或熔絲讀取。依 D-035／D-057，這類依據是 `on-device`，位置必須是專案資料夾內實際存在的檔案，報告只檢查存在、不驗內容。
沒有附的就維持 `NOT_ASSESSED`，不能由結構證據代替。

### 3.6 其他

- ETSI 條款對照（第 2.4 節）只對 v0.0.12；沒有本文條款的項目（CI-11、CI-20、21、22）不能宣稱「對應某條要求」；有對應的項目也只表示結構與條款的機制有關，不表示條款滿足與否。
- shipcheck 的信心等級（high／medium／low）不沿用；這裡只有三種結構狀態加 GAP／NOT_ASSESSED。
- 工具輸出的是證據清單，不替客戶或稽核做符合性判斷；Annex I (f) 的措施與理由仍由人寫（第 4 節）。
- 客戶版文字要中性英文、不帶內部名稱（沿用 D-057 的做法）。

## 4. 接進現有報告的方式（設計，未實作）

資料模型（x86 BIOS／vBIOS，C2 範圍）：

- `fw-inventory.json` 每個 BIOS 映像加一個 `integrity` 物件：`items[]`，每項 `{id, state, evidence, basis, reason}`；`state` 是 `observed`／`not-found`／`GAP`／`NOT_ASSESSED`／`NOT_RUN`；
  `reason` 用第 6 節的代碼；`basis` 寫「自述值、沒有簽章、假設映像未被改過」這類固定句。容器不支援時 `GAP`，不留空。
- SBOM：映像層級的元件加 `dumpling:integrity-*` property（每個 CI 項目一個，值是 state）；不放進 `sca-center:` 命名空間（C1 的報告工具可能依賴舊名稱，見 `docs/PROVENANCE.md`）。
- `fw-inventory.md` 加一節「Code integrity (structure evidence)」，表格列出每項 state、依據、限制句；固定寫「enforcement not assessed」。
- `status_of()`：結構 `observed` 或 `not-found` 不改狀態；解析不完整已經由既有的 incomplete 與 GAP 帶出 ATTENTION。
  「生效與否」永遠判斷不了，所以每一項仍寫 `NOT_ASSESSED`，但這個狀態**不**讓整份報告變 ATTENTION（否則每份報告都是 ATTENTION，沒有資訊量）。
  摘要欄（`firmware-ci.sh` 的摘要）顯示各狀態的計數（`observed`、`not-found`、`GAP`、`NOT_ASSESSED`、`NOT_RUN` 各幾項）。報告裡沒有「驗證開機已啟用」這類結論，也沒有整體通過的說法。
- `firmware.yml` 的 `expected` 加 `integrity` 鍵（例如 `boot_guard_structure: observed`），`pipeline/firmware-expect.py` 的 `KEYS` 與格式檢查同步；
  只寫有佐證的值，沒寫的不比。
- 供應商 SBOM 路徑（`pipeline/lib/firmware_sbom_check.py`）：供應商 SBOM 的完整性項目只能是供應商自述，列為自述值，不併入映像結構證據。

Annex I (f)（`cra_report.py` 的 `annex_i_table()`）：目前 (b)–(m) 全由 `risk_assessment.annex_i_applicability.<字母>` 的人工內容填寫，(f) 沒有工具證據。
建議沿用已有的 `sec_evidence`（資安測試的一句證據，接在人寫的內容後面、不取代）這個接口，而不是新增判定欄位。
這是 `cra_report.py` 的改動，屬 C1 檔案，且 D-056 要求 M7f 開工前先劃清 `cra_report.py` 的改動範圍，所以只建議，由 C1 決定。

Jetson／OS 層（CI-18 至 CI-23）：C2 沒有設計；建議 C1 決定要不要做、放在哪個報告段落、需要哪些上機收集。C2 能提供的是 PE Certificate Table 的讀法（CI-16 的同一段程式）。

## 5. 建議的 PR 切法

| PR | 範圍 | 主要檔案 | 規模 | 等什麼 |
|---|---|---|---|---|
| PR-1 | 本筆記（含第 2.4 節的 ETSI 條款對照）與 PROVENANCE 一列 | `docs/notes/c2-code-integrity-survey.md`、`docs/PROVENANCE.md` | 小（文件） | 排隊合併 |
| PR-2 | Intel：FIT 全部項目類型（KM、BPM、ACM、0x2F）→ `integrity.boot_guard`；CI-01、CI-07（Intel 部分）；樣本 expected | `tools/cra/x86_firmware.py`（約 +120）、測試與合成 FIT（約 +150）、`pipeline/firmware-expect.py`（約 +40）、三個 `firmware.yml`、`docs/notes/c2-code-integrity.md` | 中（約 400 行） | 無外部依賴；只動 C2 的韌體檔案，不等 M7d。要獨立驗證代理（high），因為「not-found」的條件（容器、完整性）是判斷邏輯 |
| PR-3 | AMD：PSP 金鑰、除錯、解鎖項目彙整（CI-05、CI-07 AMD 部分） | `tools/cra/amd_psp.py`（約 +60）、`tools/cra/tests/test_amd_psp.py`（約 +80）、`firmware.yml` | 小至中（約 200 行） | 無；D-050 的 GAP 規則要沿用 |
| PR-4 | PFAT 的 SVN 與簽章欄位進 SBOM property；CBFS 的 vboot、measured boot、CBnT 設定鍵與除錯相關選項（CI-03、CI-12、CI-13、CI-15 的 coreboot 部分、CI-24 的 PFAT 部分、CI-25 的 coreboot 部分）；Intel descriptor 的權限欄位（CI-26）先讀公開依據，讀不到就只報區域表 | `tools/cra/x86_firmware.py`、`tools/cra/coreboot_cbfs.py`（`CONFIG_KEYS`）、測試 | 小至中（約 200 行） | 無 |
| PR-5 | UEFI：Secure Boot 程式能力、PK／KEK／db／dbx 變數存在、憑證演算法（CI-08、CI-09、CI-15 的 Tcg2 部分、CI-24 的憑證部分、CI-25 的 UEFI 部分）；OVMF 的 VARS 檔納入 `analyze` | 新模組（`Scan` 子類別，比照 `uefi_gfx.py`）約 +250、測試約 +200、`firmware.yml`（OVMF 的 `analyze`） | 中至大（約 500 行） | **C1** 的 `uefi_image.Scan` 介面（已有 `test_uefi_image_contract.py`，介面變動會讓它紅燈，要先確認）；`efi-standard` 壓縮沒有解碼器時 NUC 11 這類映像只能是 GAP |
| PR-6 | 測試金鑰對照表（CI-11）：資料檔、比對、人審流程 | `tools/cra/data/` 新資料檔（約 +30）、比對程式（約 +150）、測試 | 中（約 300 行） | PR-5 的憑證解析。收錄規則已定（第 3.3 節）：只收公開、有明確出處的主體字串與指紋，每筆記出處網址、讀取日期、授權；外洩或非公開資料不收 |
| PR-7 | PE Authenticode 目錄檢查（CI-16；也供 CI-18 使用） | `tools/cra/intel_vbios.py`（`pe_info` 加資料目錄，約 +40）、合成 ROM 與測試（約 +100） | 小（約 150 行） | 無；真實 NVIDIA 樣本仍 GAP |
| PR-8 | 報告接線：`fw-inventory.md` 一節、SBOM property、`firmware-ci.sh` 摘要欄（各狀態的計數）、`status_of` 的語意（第 4 節） | `tools/cra/x86_firmware.py`、`pipeline/firmware-ci.sh`、`pipeline/lib/`（摘要欄）、渲染測試 | 中（約 300 行） | PR-2 至 PR-5 的資料欄位定案；`status_of` 與摘要欄的語意已定（第 4 節） |
| PR-9 | Jetson／OS 層（CI-18 至 CI-23） | `cra_report.py`、`image_check.py`、`tools/pilot/lib/kernel_config.py` 等（C1 檔案） | 未估 | **C1** 決定；D-056 要求先劃清 `cra_report.py` 的改動範圍 |

順序：PR-1（這份筆記）排隊合併。實作一次一個 PR，先做 PR-2（Intel FIT）。PR-2 之後預設依 PR-3、PR-4、PR-7、PR-5、PR-6、PR-8 的順序，一次一個；PR-9 由 C1 排。
所有改動到判斷邏輯的 PR 照 D-020 的格式（驗收 run、作者驗證、C0 獨立驗證）；產生物維持「看到結構、不判生效」，不新增任何整體通過的狀態。

## 6. 原因代碼草案

| 代碼 | 意思 | 使用處 |
|---|---|---|
| `ci-structure-observed-enforcement-unknown` | 看到結構，生效與否判斷不了 | CI-01、03、05、07、12、13 的生效欄位 |
| `ci-not-found-parse-complete` | 解析完整、沒有這個結構（不是結論，只是觀察） | 各項 `not-found` |
| `ci-not-found-parse-incomplete` | 解析不完整，不能寫沒有（狀態 GAP） | 各項 |
| `ci-container-unsupported` | 容器或格式沒有解析（capsule、PFAT 以外的 BIOS Guard、Tiano 壓縮） | CI-01、03、14、16 |
| `ci-needs-fuse-state` | 答案在熔絲 | CI-02、06、07、13、23 |
| `ci-needs-board` | 答案要上機 | CI-10、15、20、21、23、26 |
| `ci-root-of-trust-not-in-image` | 驗證用的金鑰雜湊不在映像 | CI-03、04、05 |
| `ci-signature-not-verified` | 簽章結構看到，沒有做密碼學驗證 | CI-03、04、16、18 |
| `ci-self-declared` | 值是映像自述，沒有簽章（D-050、D-058） | CI-03、09、13、24 |
| `ci-key-class-unknown` | 對照表沒有這把金鑰，不能判斷是否測試金鑰 | CI-11 |
| `ci-no-public-basis` | 格式沒有公開文件可引用 | CI-04、06、17、24（Boot Guard、CSME、PSP 的演算法欄位）、26 |
| `ci-no-sample` | 沒有真實的公開樣本 | CI-16、17 |
| `ci-etsi-clause-gap` | 讀到的草稿版本（v0.0.12）沒有條款涵蓋這一項；草稿沒有取得時也用這個代碼 | CI-11（本文層級）、CI-20、21、22 |

## 7. 需要 C2 自己核對的地方

各項在對應的實作 PR 裡核對，核對不了就照實標成還沒核對。

1. 條款對照依據的是 `labs.etsi.org` 的 v0.0.12（標籤 `v0.0.12.1`），比 V0.1.1、V0.1.3 舊；這兩版沒有取得，條款編號與內容可能不同。草稿封面版本（v0.0.12）與標籤名稱（`v0.0.12.1`）也不完全一致（第 1.1 節）。**PR-1**：較新版由使用者手動下載後放在本機提供，到時重核第 2.4 節。
2. Boot Guard 的 `__KEYM__`、`__ACBP__` 識別字串是在映像裡看到的值，沒有對照 Intel 文件；FIT type 編號的依據是 coreboot 的 `fit.h`，不是 Intel 規格。**PR-2**。
3. OVMF 的字串計數是啟發式（UTF-16 與 ASCII 都數）；`SecureBootEnable` 等字串在其他 edk2 建置的意義沒有逐一確認。**PR-5**。
4. `CONFIG_VBOOT=y` 與 FMAP 區域名單在 Dasharo 的實際意義沒有查證。**PR-4**。
5. CSME `$MN2` 簽章欄位、AMD 軟熔絲位元、NVIDIA vBIOS 簽章的格式文件沒有讀（本筆記一律標 GAP）。CSME 沒有對應的實作 PR，維持 GAP；AMD 軟熔絲位元 **PR-3**；NVIDIA vBIOS **PR-7**（真實樣本仍 GAP）。
6. 「AMI 測試 Platform Key」事件只是候選依據，原始公告沒有讀。依第 3.3 節，只有公告本身公布的憑證主體字串與指紋可以收，外洩或非公開的資料不收。**PR-6**。
7. shipcheck 的 `pilots/0005-*/REPORT.md` 沒讀；如果它有對映像層級偵測的補充說明，可能影響第 1.2 節的摘要。**PR-1**。
8. 樣本觀察的數字是 2026-11-15 對公開樣本在本機只讀量的（`firmware-bios.sh` 單一樣本、`uefi_image.Scan` 子類別、FIT 項目計數），沒有對所有樣本跑，也沒有經過獨立驗證代理。FIT 項目計數 **PR-2**；OVMF 字串與 `uefi_image.Scan` 的計數 **PR-5**。
9. CI-24 引用的 ECCG 核可機制清單、CI-26 可能的公開依據（coreboot 的 `util/ifdtool`）都沒有讀；CI-24、CI-25、CI-26 沒有量過樣本。**PR-5**（CI-24、CI-25 的 UEFI 部分）、**PR-4**（CI-26、CI-25 的 coreboot 部分）。
