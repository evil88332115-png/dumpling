# C2：每天重跑韌體公告比對（`pipeline/firmware-rematch.sh`）

只用公開樣本與公開資料。重跑的結果是**建議與候選**，不是漏洞判定：`dumpling:vuln-assessment` 仍然是 `NOT_ASSESSED`，沒有任何狀態或文字表示「沒有漏洞」。
設計見 `docs/FIRMWARE-WATCH.md` 的第 4 節；這份是入口、輸入驗證、key、狀態規則與限制的說明。

## 做什麼

Release 上有每個 BIOS 樣本的 `fw-inventory-<slug>.json`（解析結果，不含映像）。三個公告比對只吃 inventory：

| 比對 | 函式（`tools/cra/x86_firmware.py`） | 表 |
|---|---|---|
| Intel 微碼 | `advisory_section(inv)` | `tools/cra/data/intel-microcode-releases.json` |
| NVIDIA vBIOS | `vbios_advisory_section(inv, advisory, now)` | `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json` |
| 廠商公告規則 | `rules_section(inv)` | `tools/cra/data/fw-advisory-rules.json` |

重跑＝讀 inventory，清掉舊的比對結果，用 repo 當下的三張表重跑這三個比對，再重新產生狀態（`status_parts`）、SBOM（`components`、`bom`）與報告（`markdown`）。
**完全離線**：不下載、不連網、不讀映像、不重新解析。邏輯在 `tools/cra/fw_rematch.py`（由 `x86_firmware.py --rematch` 呼叫）。

## 入口

```
pipeline/firmware-rematch.sh --meta firmware-meta.json --dir <附件目錄> --now <UTC> --out <目錄>
# 內部：python3 -I tools/cra/x86_firmware.py --rematch --meta … --dir … --now … --out …
```

- 四個參數都要給。`--now` 是這次執行的時間，格式 `YYYY-MM-DDTHH:MM:SSZ`（只收 Z、時只收 00～23；沒有時區、小數、24 時都是參數錯誤，退出碼 64）。
  `--now` 只用在 NVIDIA 對照表的過期判斷（鏡像日期超過 90 天），不從牆上時鐘取。
- `--out` 必須不存在或是空資料夾（不覆蓋、不刪除別人的檔案）；不能是符號連結。
- 退出碼：0＝每個樣本都是 OK；2＝有 ATTENTION 或 GAP（輸出照寫）；1＝FAIL（寫不出輸出或內部錯誤；已寫的輸出全部刪掉，不留 `rematch-summary.json`）；64＝參數錯誤。
- stdout：每個樣本一行 `FIRMWARE-REMATCH<TAB>OK|ATTENTION|GAP<TAB><slug><TAB>說明`；meta 壞掉時一行 `FIRMWARE-REMATCH<TAB>GAP<TAB>-<TAB>…`；FAIL 時 `FIRMWARE-REMATCH<TAB>FAIL<TAB>-<TAB>原因`。
  說明只有結果數、changed 數、原因數與表不能用的原因（全文在 `rematch-<slug>.json`）；control 字元與換行換成空白，不會多出狀態行。
- **rematch 不輸出 NOT_RUN**：沒跑、沒有輸出、執行前失敗，由呼叫端（watch-round）標 NOT_RUN。`rematch-summary.json` 最後才寫，沒有它就是沒有輸出。

### 輸出（`--out`）

| 檔案 | 內容 |
|---|---|
| `rematch-<slug>.json` | schema `dumpling-firmware-rematch/1`：今天的 `results[]`、和 Release 當時的差異 `changed[]`、三張表的識別、status 與 reasons、now、release_tag、inventory_sha256。每個 `kind: bios` 的樣本都有（GAP 的也有，`results` 是空的） |
| `rematch-summary.json` | schema `dumpling-firmware-rematch-summary/1`：release_tag、now、`meta_status`、三張表、每個樣本一列（slug、status、輸出檔名；GAP 另有 reasons）。**沒在這裡的樣本，watch-round 標 NOT_RUN** |
| `fw-<slug>.cdx.json` | 重新產生的 CycloneDX 1.6：`dumpling:advisory-*` 是今天的結果，`dumpling:vuln-assessment` 仍是 `NOT_ASSESSED`（GAP 的樣本沒有） |
| `fw-inventory-<slug>.md` | 重跑的狀態與差異（開頭），接著是和 `fw-inventory.md` 同一份的內容（GAP 的樣本沒有） |

範例檔（C3 的測試讀）在 `pipeline/watch/tests/data/`：`firmware-meta.example.json`、`firmware-rematch.example.json`、`firmware-rematch-summary.example.json`。範例檔的內容是實際輸出。

`rematch-<slug>.json` 的欄位：

- `status`：`OK`｜`ATTENTION`｜`GAP`；`reasons`：原因（字串清單；OK 時是空的）。
- `tables`：每張表的識別加 `status`（`OK`｜`GAP`）與 `stale`（只有 NVIDIA 對照表會過期）。表不能用時識別欄位是 null，另有 `gap`（原因）。
  - `fw_advisory_rules`：`sha256`、`table_updated`。
  - `intel_microcode`：`source_commit`、`source_tag`、`table_sha256`。
  - `nvidia_vbios`：`sha256`、`mirror_commit`、`reviewed_until`。
- `results[]`：`key`、`kind`（`rule`｜`intel-microcode`｜`nvidia-vbios`）、`component`（人看的名稱）、`result`、`bulletins`、`reason`、`review`。
  - 規則表：`result` 是 `affected`｜`not-affected`｜`NOT_ASSESSED`，`bulletins` 是規則 ID，`review` 是 `preliminary`｜`confirmed`｜null（同一個建議有初審與已確認的規則時是 `preliminary`）。
  - 微碼：`affected-candidate`｜`older-no-sa`｜`up-to-date`｜`NOT_ASSESSED`，`bulletins` 是候選 INTEL-SA。
  - vBIOS：`affected`｜`fixed`｜`NOT_ASSESSED`，`bulletins` 是對照表的公告編號。
  - `reason` 是比對的原因代碼（只有 `NOT_ASSESSED` 有，例如 `no-rule`、`no-row`、`table-stale`），其他是 null。
- `changed[]`：結果和 Release 當時（inventory 裡記的）不同的元件：`key`、`kind`、`before`、`after`，兩邊都是 `{result, bulletins, reason, review}`。
  `result`、`bulletins`、`reason`、`review` 任何一個不同都算（規則從初審變成已確認也算）。Release 當時沒有那個元件的結果（舊版程式沒有這類元件的比對）時，`before` 的 `result` 是 null。

`rematch-summary.json` 的 `meta_status`：`OK`｜`GAP`。`GAP` 時 `samples` 是空的，`reasons` 寫原因，只有這一個檔案（整份 GAP）。

## key

`key` 在一個樣本內唯一，而且穩定：只由 inventory 的內容組成（不含比對結果、不含時間）。同一份 inventory 重跑多次，key 與順序都相同。

| 種類 | 格式 | 說明 |
|---|---|---|
| 規則表 | `rule:<元件種類>:<映像 sha256 前 16 碼>:<元件識別>` | 元件種類是規則表的元件名：`bios_image`、`ami_core`、`intel_csme`、`intel_fsp`、`amd_psp`、`amd_microcode`、`amd_agesa` |
| Intel 微碼 | `ucode:<cpuid>/<platform_id>:<revision>` | 例如 `ucode:000A06A4/0xE6:0x25` |
| NVIDIA vBIOS | `vbios:<vendor>:<device>:<ROM sha256 前 16 碼>` | 例如 `vbios:10de:2489:<16 碼>` |

規則表的元件識別：

| 元件種類 | 識別 |
|---|---|
| `bios_image` | `image` |
| `ami_core` | `core=<核心版本>` |
| `intel_csme` | `me=<ME 版本>` |
| `intel_fsp` | `fsp=<revision>:<FSP 內容的 sha256 前 12 碼>`（同一個映像常有好幾個同名的 FSP，例如 V540TU 三個） |
| `amd_psp` | `psp=0x<type>:<版本>:<內容 sha256 前 12 碼>` |
| `amd_microcode` | `amdmc=<equiv_id>:<patch_id>:<內容 sha256 前 12 碼>` |
| `amd_agesa` | `agesa=<字串>` |

- 同名的先用內容區分（上表的 sha256）；內容也相同的（例如同一份 FSP 在兩個區域各一份）整組加 `#<序號>`（1 起算、依 inventory 的順序）。微碼的 `ucode:…` 重複時，先加 `:<微碼 sha256 前 12 碼>`，仍然重複才加序號。
- 來自 inventory 的字串只留 `A-Za-z0-9._=+-`，其餘換成底線（最長 64 字元）：key 不會帶空白、`#`、`@`、反引號或換行。`#` 只會是序號的開頭。
- 微碼的 key 不含映像：同一份微碼在同一個樣本的兩個映像出現、內容相同時，加 `#<序號>`。呼叫端要依「微碼＋revision」合併時，取 `ucode:<cpuid>/<platform_id>:<revision>` 的前綴。

## 輸入驗證（不可信資料）

repo 是公開的，Release 附件與 meta 都當不可信資料處理。

- `firmware-meta.json`：大小上限 1 MiB；schema 必須是 `dumpling-firmware-meta/1`；`tag` 要是 release tag 的格式；`samples` 是清單（最多 64 筆）；重複的 JSON 鍵、`NaN`／`Infinity`、不是 UTF-8 都算壞掉。最後一段是符號連結也不收。
  **meta 壞掉：整份 GAP，只輸出 `rematch-summary.json`**（`meta_status: GAP`、`samples: []`）。
- 附件：只收 meta 的 `samples[]` 列的檔案，不收沒列的。
  - `slug` 要 fullmatch `[a-z0-9][a-z0-9.-]{0,62}`（`summary` 保留給 `rematch-summary.json`，不收）；附件名必須是 `fw-inventory-<slug>.json`，而且等於 meta 的 `inventory`；不跟隨符號連結（`O_NOFOLLOW`）、不接受路徑分隔符號與 `..`（名稱 fullmatch 上面的格式，不可能有）、一定要是一般檔案。
  - 大小上限 32 MiB；核對 meta 的 `inventory_sha256`（collect 之後的第二道防線）；`firmware_version` 要是可印出的 ASCII 字串或 null。
  - `kind: sbom` 的樣本跳過：不讀、不輸出、不列在總表。`kind` 不是 `bios`、`sbom` 的樣本 GAP。
  - 同一個 slug 出現不只一次：那個 slug GAP（一份輸出）。
- inventory：不是 JSON、schema 不是 `sca-center-fw-inventory/1`、必要的鍵缺了或型別不對（檢查的鍵見 `fw_rematch.py` 的 `*_SPEC`）、內容怪到重跑丟例外、寫不出 UTF-8：**那一份 GAP**（`rematch-input-invalid: …`），其他樣本照常，不丟例外。原因文字只寫鍵的路徑，不帶 inventory 裡的字串。
- **舊版程式產生的 inventory 缺新的鍵時是 GAP**，不猜預設值（要重新打 Release）。
- 重跑前清掉 inventory 裡舊的比對結果：頂層的 `advisory`、`vbios_advisory`、`rules_advisory`、`status`、`detail`，微碼與 vBIOS 的 `advisory`，任何位置的 `rule_advisory`。舊結果先記下來，只出現在 `changed[].before`。
- 報告裡來自 inventory 的字串都經過 `md_esc`（和 `fw-inventory.md` 同一個函式）。

## 狀態規則

沿用現有規則（`status_parts`／`status_of`），另加：

1. 任何一張表讀不到或驗證不過：那一類元件 `NOT_ASSESSED`（原因寫在 `reason`），**整份 GAP**，`reasons` 寫是哪一張表與原因。不論這個樣本有沒有那一類元件。
2. NVIDIA 對照表已確認、鏡像超過 90 天（`stale: true`）：`fixed` 降成 `NOT_ASSESSED`（`table-stale`），樣本有 vBIOS 時 ATTENTION（沒有 vBIOS 的樣本只在 `tables` 與總表看得到 `stale`）。
3. 規則表建議 `affected`：ATTENTION（即使規則還是初審）。Intel 微碼照現有規則：`affected-candidate` 本身不改變狀態。
4. **結果和 Release 當時不同（`changed` 不是空的）：整份至少 ATTENTION**（`reasons` 寫 `changed since release: N result(s)`）。
5. inventory 本身讓 `status_of` 變 ATTENTION 的原因（沒有 flash descriptor、壓縮的 UEFI section 沒解析、沒有版本清單…）逐項列在 `reasons`，前綴 `inventory:`。
6. 沒有 BIOS、vBIOS 結構：GAP。其他 OK。

## 限制

- 重跑**只反映表的更新**，不重新解析映像。解析器的改進要重新跑 firmware.yml、打新的 Release 才會反映。
- inventory 是 Release 當時那一版程式產生的。日後欄位變了、舊 inventory 缺鍵就是 GAP，不猜預設值。
- 程式之後新增的元件種類（例如規則表多了一種元件）在舊 inventory 沒有 Release 當時的結果：`changed` 的 `before.result` 是 null，狀態至少 ATTENTION。
- ME、微碼、AGESA、PSP、AMI 核心、vBIOS 照舊靠規則表或對照表，比不到就 `NOT_ASSESSED`（資料庫沒有資料，以廠商公告為準）。
- 規則表的 `affected` 是建議（多數還是初審），不是漏洞判定；`affected-candidate` 是 release 層級的候選，不一定影響該 CPUID。
- `--now` 只影響 NVIDIA 對照表的過期判斷；Intel 微碼表與規則表沒有過期判斷。
- 表是 repo 當下的版本（執行這個入口的那個 commit），不是 Release 當時的；`rematch-<slug>.json` 的 `tables` 記的是這次用的表。

## 測試

`tools/cra/tests/test_fw_rematch.py`（在 `tests/run.d/c2-x86-firmware.sh` 的清單裡）：合成 meta 與 inventory，涵蓋 meta 壞掉、sha256 不符、路徑穿越、符號連結、大小上限、不在 meta 裡的檔案、`kind: sbom`、inventory 壞掉與缺鍵、表壞掉、表過期、結果有變化（改過的合成規則表與 vBIOS 表）、舊結果清掉；一致性：同一份 inventory 用同樣的表重跑，results、inventory 的比對結果與 SBOM（逐位元組）都相同
（合成映像；repo 內一份很小的真樣本 `tools/cra/tests/data/rematch/ubuntu-ovmf-2024.02/`，來自 CI 產物；環境變數 `DUMPLING_REMATCH_ART` 指到 CI 產物資料夾時，全部樣本都對照）。
真樣本的 inventory 記的三張表識別和 repo 當下的表不同時（Release 之後表更新過），只檢查結構與 changed，不比 SBOM 位元組。
