# 韌體公開樣本清單

每個樣本一個資料夾，內有一個 `firmware.yml`：`firmware/bios/<型號 slug>/`、`firmware/vbios/<型號 slug>/`、`firmware/sbom/<slug>/`。
**二進位檔不進 git**。`pipeline/firmware-fetch.sh` 從官方網址下載並核對 sha256 與大小；
CI（`firmware.yml` 工作流程的 `firmware-fetch` job）每次都真的下載，這就是「網址仍可用」的驗證。
下載的檔案一律當不可信資料：只下載，不解開、不執行。

## 用法

    pipeline/firmware-fetch.sh firmware/*/*/firmware.yml --out firmware-dl

每個樣本印一行 `FIRMWARE-FETCH<TAB>OK|GAP|FAIL<TAB><型號><TAB>說明`，有 FAIL 就以非 0 結束。
需要 `curl` 與 PyYAML（Ubuntu：`python3-yaml`）。檔案放在 `<out>/<kind>/<slug>/<name>`；
已存在且核對相符的檔案會直接視為 OK；已存在的 symlink／非一般檔案一律拒絕。

## 欄位

| 欄位 | 說明 |
|---|---|
| `kind` | `bios`、`vbios` 或 `sbom`（供應商提供的 SBOM；只能搭 `role: sbom`） |
| `vendor`、`model` | 廠商與型號 |
| `firmware_version` | 版本（`status: ok` 必填） |
| `ibv` | 韌體核心廠商：`AMI`、`coreboot+edk2`、`edk2`…；不知道寫 `unknown` |
| `status` | `ok`（可下載）或 `GAP`（沒有合法可下載的檔案；不下載，印 GAP） |
| `files[]` | `name`（只能是檔名）、`url`（https）、`sha256`（小寫 64 位十六進位）、`size`（位元組）、`role`（`image` 映像／`source` 原始碼／`package` 套件或更新包／`sbom` 供應商 SBOM） |
| `license` | `name`、`url`、`note`：條款名稱、網址、一句說明（本專案只在 CI 下載、不重新散布） |
| `notes` | 挑選理由與限制 |
| `analyze[]` | 選填；`{from, member}`：`from` 是 `files` 裡 `role: package` 的 .deb 檔名，`member` 是要取出的成員路徑（例如 `usr/share/OVMF/OVMF_CODE_4M.fd`）。CI 只取出這一個一般檔案、不執行；沒列的 `image`／`package` 整檔解析 |
| `expected` | 選填；解析結果要跟它一致，CI 逐項比對（`pipeline/firmware-expect.py`）。只寫有佐證的，不猜；沒寫的項目不比，寫了不認得的鍵會報格式錯誤 |
| `expected_dt` | 選填；樣本自己宣告上傳臨時 DT 的預期結果（`pipeline/lib/firmware_dt.py`，說明見 `docs/notes/c2-firmware-dt.md`）。目前只有 `{upload: rejected, reason: <依據，必填>}`＝DT 會拒收這份 SBOM（例如供應商 SBOM 不符 CycloneDX schema，DT 回 http=400「The uploaded BOM is invalid／Schema validation failed」；dumpling 不修改供應商的檔案）。真的被拒收（只認這個回應，其他 400 不算）：report 仍標 FAIL、註明與宣告一致、不讓 job 失敗；宣告了卻上傳成功＝MISMATCH（job 失敗，請更新樣本）；沒宣告卻被拒收＝一般 FAIL。宣告了卻沒有上傳結果（NOT_RUN／GAP）＝report 以 1 結束。其他失敗不受宣告影響。寫了不認得的鍵或值會報格式錯誤 |

### `expected` 的鍵

| 鍵 | 內容 | 比對規則 |
|---|---|---|
| `intel_me` | ME 版本字串 | 映像的 ME 版本相同，且 SBOM 有同版本的 `Intel CSE firmware` 元件 |
| `microcode` | `[{cpuid, platform_mask, revision}]` | 映像有同 cpuid、同 platform、同 revision 的微碼（十六進位不分大小寫），SBOM 也有；沒有該 cpuid／platform＝MISSING，revision 不同＝MISMATCH；映像多出來的微碼不比 |
| `fsp` | 版本字串清單 | 每個版本都要在映像的 FSP 找得到；多出來的版本不比 |
| `coreboot_version`、`dasharo_version` | 字串 | 與 CBFS `revision` 讀到的相同 |
| `coreboot_revision`、`edk2_revision` | git 修訂（縮寫即可） | 一方是另一方的前綴就算相符（至少 7 碼）；edk2 取 coreboot config 的 `CONFIG_EDK2_TAG_OR_REV` |
| `coreboot_build_date` | `YYYY-MM-DD` | 與 CBFS `build_info` 的建置日期（UTC）相同 |
| `intel_gop`、`intel_legacy_vbios` | 字串 | 與 SBOM 的 `Intel GOP driver`／`Intel legacy VBIOS (option ROM)` 元件 version 相同；同名元件多個時任一個相符就 OK；沒有元件或都沒讀到版本＝MISSING。GOP 的 version 只有 build 編號（如 `1070`）。VBT 不提供此鍵（version 是表頭格式版本） |
| `amd_agesa` | 字串（PI 版本號，例如 `1.2.0.B`） | SBOM 的 `AMD AGESA` 元件 version 的最後一個以空白分隔的符記相同（不分大小寫），或整串相同；映像有好幾個不同的 AGESA 字串時任一個相符就 OK；沒有元件或沒讀到版本＝MISSING。前面的名稱（`ComboAM4v2PI`、`ComboV2PI`…）各廠商寫法不同，不比 |
| `amd_microcode` | `[{equiv_id, patch_id}]`（十六進位） | SBOM 有 `AMD CPU microcode` 元件，其 `sca-center:amd-equivalence-id` 與 `version`（patch level）相符；同 equivalence id 但 patch level 不同＝MISMATCH，沒有該 equivalence id＝MISSING；映像多出來的微碼不比 |

每項印一行 `FIRMWARE-EXPECT<TAB>OK|MISMATCH|MISSING|NOT_RUN<TAB><樣本><TAB>…`，最後一行只是計數（不是整體通過）；有 MISMATCH 或 MISSING 就以非 0 結束。

## 樣本與挑選理由

| 樣本 | 為什麼挑 |
|---|---|
| `bios/ubuntu-ovmf-2024.02` | PLAN B 段第一個樣本：edk2 成品（deb 內的 OVMF）加完整原始碼包與 Ubuntu patch，Launchpad 網址長期不變 |
| `bios/dasharo-protectli-vp46xx-v1.2.0` | coreboot＋edk2，含 Intel ME、FSP、微碼；已有試掃結果可當預期值（`expected`）。附 coreboot、edk2 原始碼封存（GitHub 動態產生，雜湊可能變動，見該檔 notes） |
| `bios/intel-nuc11-patgl357-0059` | AMI Aptio 平台、Intel 內顯（之後找 Intel GOP／VBT）。選 ASUS 的靜態 CDN 網址，因為 Intel 下載中心的 downloadmirror 網址會被導成小寫路徑而回 403；ASUS 下載頁本身是動態頁面，但頁面指向的 `dlcdnets.asus.com` 檔案網址是靜態的，可用 curl 下載 |
| `bios/asus-prime-b550m-a-3404` | AMD AM4 平台、AMI：EFS 因更新包標頭不在固定位置、combo 目錄指到多個 L1、新世代的 L1 指到 L2（`$PL2`／`$BL2`）、AMD 微碼與壓縮 firmware volume 裡的 AGESA 字串；release notes 有 AGESA 版本可當出處（解析見 `docs/notes/c2-amd-psp.md`） |
| `bios/novacustom-v540tu-mtl-v1.0.1` | Dasharo coreboot 完整 32 MiB SPI 映像，ME 區域是新世代配置：區域開頭是 CSE layout table → BPDT（version 2），`$FPT` 只在 data partition、沒有 FTPR 項目、`$CPD` header version 2。用來驗證 `tools/cra/intel_cse_layout.py`（`expected.intel_me` 依 Dasharo release notes，見該檔註解與 `docs/notes/c2-csme-layout.md`） |
| `bios/novacustom-nuc-box-arl-v0.9.2` | Dasharo coreboot 完整 32 MiB SPI 映像（Arrow Lake-U/H FSP），ME 區域開頭的 CSE layout table 是 layout 1.7 的 Size 0x60 變體（CRC-32 相符），RBEP＋NFTP 版本一致、沒有 FTPR。用來驗證 `tools/cra/intel_cse_layout.py` 的 Size 0x60（`expected.intel_me`、微碼依 Dasharo release notes，見該檔註解與 `docs/notes/c2-csme-layout.md`） |
| `vbios/nvidia-displayport-fw-updater-1.1` | NVIDIA 官方公開的 DisplayPort 韌體更新工具。只讀分析確認**沒有完整 vBIOS**：內嵌的是三組 GPU 家族的 UEFI（GOP）驅動範本，版本是 `xx.xx.xx.xx.xx` 佔位（見 notes） |
| `vbios/standalone-nvidia-option-rom` | **GAP**：沒有官方可合法下載的獨立 vBIOS；CI 用合成 option ROM（`tools/cra/tests/synthetic_vbios.py`）測流程，實際檔案由負責單位提供 |

## 公告比對（Intel 微碼）

`pipeline/firmware-bios.sh` 的輸出（`fw.cdx.json`、`fw-inventory.json`、`fw-inventory.md`）對每份 Intel 微碼離線比對 `tools/cra/data/intel-microcode-releases.json`
（Intel 公開的微碼發佈說明，固定 tag／commit／sha256，由 `tools/cra/intel_ucode_releases.py` 產生；CI 不重新抓）：

| `dumpling:advisory-match` | 意思 |
|---|---|
| `affected-candidate` | 有候選公告：資料表裡比映像的 revision 更新的 release 所列的 INTEL-SA、「New Disclosures」表涵蓋這個 revision 的 release、人工對照的散文（20250812）、同 F-M-S 重疊遮罩的較新更新。`dumpling:advisory-candidates` 是**候選**（來源只在 release 層級列公告，不一定影響這個 CPUID），不是確定受影響 |
| `older-no-sa` | 有較新的 revision，但那些 release 沒列公告；不代表沒有漏洞 |
| `up-to-date` | 資料表沒有更新的 revision；**不代表沒有漏洞**，以 Intel 公告為準 |
| `NOT_ASSESSED` | 資料庫沒有資料，以廠商公告為準（資料表讀不到或 sha256 不符＝GAP、CPUID／platform 不在表、revision 讀不到或比表新、已被移除、同 F-M-S 另有重疊的 platform 遮罩在之後還有更新＝`superseded-platform-mask`…） |

AMD 的微碼、PSP 韌體、AGESA 元件（`amd_psp.py` 解析）與 Intel ME 一樣有 `dumpling:advisory-match=NOT_ASSESSED`：AMD-SB 的規則表還沒有做，以 AMD 公告為準。

`dumpling:vuln-assessment` 仍是 `NOT_ASSESSED`。`fw-inventory.md` 每次都有「公告比對」一節；CI 摘要表有「微碼公告比對」欄。
Intel ME 的 NVD CPE（`dumpling:cpe-*`）見 `docs/notes/c2-firmware-advisory.md`：只放前三段版本，NVD 對 CSME 的資料不完整，Grype 比不到不代表沒有漏洞（臨時 DT 關閉 NVD 資料源，只有 CPE 的元件在 DT 比不到）；family 讀不出來時由版本推定（major 11～30），比對結果待人審。
規則、資料來源、重新產生資料表的步驟與限制都在那份 notes。

## 第二條路：供應商 BIOS SBOM 匯入（品質檢查）

樣本 `sbom/dasharo-novacustom-ns5x-tgl-v1.6.0`：3mdeb 的 Dasharo 每個版本旁都放 CycloneDX 1.4 SBOM
（9940 位元組、10 個元件、sha256 `5c42344d…6a44ae`，2026-11-12 量測）。
授權：檔案沒有授權欄位、Dasharo 文件站未見明確聲明；只在 CI 下載讀取、不重新散布。
其他候選：CycloneDX `bom-examples` 倉庫（CC0-1.0，非韌體專用）。

    pipeline/install-tool.sh sbomqs "$dir/bin"        # 版本與 sha256 固定在 pipeline/lib/tools.lock，核對後才安裝
    SBOMQS="$dir/bin/sbomqs" pipeline/firmware-sbom-check.sh firmware-dl/sbom/*/*.sbom.json --out sbom-check

每個 SBOM 印一行 `FIRMWARE-SBOM<TAB>OK|ATTENTION|GAP|FAIL<TAB><檔名><TAB>說明`，有 FAIL 以 1 結束：

| 狀態 | 條件 |
|---|---|
| FAIL | 讀不到、超過 50 MiB、不是合法 JSON、不是 CycloneDX／SPDX JSON |
| GAP | 沒有元件，或全部元件都沒有版本（讀不到版本不猜） |
| ATTENTION | 有元件缺版本，或缺 purl／cpe（說明列數量與前幾個名稱） |
| OK | 以上都沒有；不代表安全 |

sbomqs 分數與各類別存在 `--out`（`<檔名>.sbomqs.json`、`sbom-check.md`），分數只寫在說明裡當參考，**不決定狀態**（門檻是政策問題，尚未決定）。
漏洞比對這一步未做：說明固定寫 `漏洞比對：NOT_RUN（上傳 DT 待臨時 DT 工具）`。

## 上傳臨時 DT 前的整理與報告（`pipeline/lib/firmware_dt.py`）

    python3 -I pipeline/lib/firmware_dt.py prep     --sbom fw.cdx.json --sample firmware/bios/<slug>/firmware.yml --out prep/<slug>
    python3 -I pipeline/lib/firmware_dt.py expected --prep prep/<slug>
    python3 -I pipeline/lib/firmware_dt.py report   --prep prep/* [--dt-result <資料夾>] --out <資料夾>

`prep` 產出 `sbom.cdx.json`（要上傳的）與 `dt-project.json`；`expected` 產出 `expected.json`（給 `dt-verify.py verify`）與 `firmware-dt-expected.json`；
`report` 產出 `firmware-dt.md`，每個樣本一行 `FIRMWARE-DT<TAB>OK|ATTENTION|GAP|NOT_RUN|FAIL<TAB>…`（沒有 DT 結果＝NOT_RUN；有 FAIL 以 1 結束）。
流程與接 workflow 的草稿見 `docs/notes/c2-firmware-dt.md`。

### DT 專案名稱與版本

| 項目 | 規則 |
|---|---|
| 名稱 | `firmware-<kind>-<slug>`；合成樣本為 `firmware-<kind>-synthetic-<slug>`。`slug` 取 `firmware.yml` 所在資料夾名稱；只含英數字與 `. _ -`，最長 100 字元（和 `sca-scan --name` 的過濾一致，不需要被改寫；不用 `/`，因為 sca-scan 會把它換成 `-`） |
| 版本 | `firmware_version`，不合規字元換成 `_`（和 `sca-scan --version` 接受的字元一致：英數字開頭，英數字與空白 `. _ + ~ ( ) -`，最長 100）；沒有版本寫 `unknown` |
| 合成判定 | 命令列 `--synthetic`、`firmware.yml` 的 `status` 不是 `ok`（沒有真實檔案）、或元件的來源檔名含 `synthetic`，任一成立 |
| `metadata.component` | `type: firmware`、`name` 取 `model`、`version` 取專案版本、`bom-ref: dumpling:fw-root:<slug>`，附 `dumpling:sample-kind`／`sample-slug`／`synthetic` property；原本的 `metadata.component` 會被取代（舊值記在 `dt-project.json`） |
