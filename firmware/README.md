# 韌體公開樣本清單

每個樣本一個資料夾，內有一個 `firmware.yml`：`firmware/bios/<型號 slug>/`、`firmware/vbios/<型號 slug>/`。
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
| `kind` | `bios` 或 `vbios` |
| `vendor`、`model` | 廠商與型號 |
| `firmware_version` | 版本（`status: ok` 必填） |
| `ibv` | 韌體核心廠商：`AMI`、`coreboot+edk2`、`edk2`…；不知道寫 `unknown` |
| `status` | `ok`（可下載）或 `GAP`（沒有合法可下載的檔案；不下載，印 GAP） |
| `files[]` | `name`（只能是檔名）、`url`（https）、`sha256`（小寫 64 位十六進位）、`size`（位元組）、`role`（`image` 映像／`source` 原始碼／`package` 套件或更新包） |
| `license` | `name`、`url`、`note`：條款名稱、網址、一句說明（本專案只在 CI 下載、不重新散布） |
| `notes` | 挑選理由與限制 |
| `expected` | 選填；給之後解析 PR 用的預期值，只寫已知的，不猜 |

## 樣本與挑選理由

| 樣本 | 為什麼挑 |
|---|---|
| `bios/ubuntu-ovmf-2024.02` | PLAN B 段第一個樣本：edk2 成品（deb 內的 OVMF）加完整原始碼包與 Ubuntu patch，Launchpad 網址長期不變 |
| `bios/dasharo-protectli-vp46xx-v1.2.0` | coreboot＋edk2，含 Intel ME、FSP、微碼；已有試掃結果可當預期值（`expected`）。附 coreboot、edk2 原始碼封存（GitHub 動態產生，雜湊可能變動，見該檔 notes） |
| `bios/intel-nuc11-patgl357-0059` | AMI Aptio 平台、Intel 內顯（之後找 Intel GOP／VBT）。選 ASUS 的靜態 CDN 網址，因為 Intel 下載中心的 downloadmirror 網址會被導成小寫路徑而回 403；ASUS 下載頁本身是動態頁面，但頁面指向的 `dlcdnets.asus.com` 檔案網址是靜態的，可用 curl 下載 |
| `vbios/nvidia-displayport-fw-updater-1.1` | NVIDIA 官方公開的 DisplayPort 韌體更新工具。只讀檢查看得到 vendor 0x10DE 的 PCIR 結構，但不是可確認的完整 option ROM（見 notes） |
| `vbios/standalone-nvidia-option-rom` | **GAP**：沒有官方可合法下載的獨立 vBIOS；之後用合成 option ROM 測流程，實際檔案由負責單位提供 |

## 第二條路的候選（之後的 PR 才用，這次不下載）

公開的韌體 SBOM 範例：3mdeb 的 Dasharo 每個版本旁都放 CycloneDX 1.4 SBOM，
例如 `https://dl.3mdeb.com/open-source-firmware/Dasharo/novacustom_ns5x_tgl/uefi/v1.6.0/novacustom_ns5x_tgl_v1.6.0.sbom.json`
（9940 位元組、10 個元件、sha256 `5c42344d09932c809b5968552842e0ff540a749c11f0e199ed0858d6e76a44ae`，2026-11-12 量測）。
授權：檔案本身沒有授權欄位，Dasharo 文件站未見明確聲明，使用前要向 3mdeb 確認或只在 CI 讀取、不散布。
其他候選：CycloneDX `bom-examples` 倉庫（CC0-1.0，非韌體專用）。
