# 板子檢查：完整性、更新通道、記錄（匯入端）

`tools/cra/board_import.py` 讀板子檢查壓縮檔裡的三個檔案：`integrity.txt`、`update-channel.txt`、`logging.txt`。
對應 CRA 附件 I 第 I 部分 (2)(f)（完整性）、(2)(c)（更新）、(2)(l)（記錄），以及 EN 303 645 5.7、5.3 和 EN 18031 的 SUM、LGM。
程式是從 sca-center 手動移植的（25fa89a、79d11ba，見 `docs/PROVENANCE.md`）。

## dumpling 只有匯入端

- 這三個檔案由**板上收集腳本**產生。dumpling **沒有帶**這支腳本（見 `docs/PROVENANCE.md` 的「沒帶進來的相依」）。
- 所以 dumpling 自己的掃描、dev run、Release 都**不會有**這三組結果。
  - 沒有板子結果檔時，精靈的 `board-import` 是 NOT_RUN。
  - 報告上這三款仍然是「沒有證據」。
- 要有結果，必須在板子上跑收集腳本，再用 `tools/demo/board-import.sh` 把壓縮檔匯入。
- 舊的壓縮檔沒有這三個檔案時，不會產生對應的 finding。這**不代表那些項目沒問題**，只代表沒有測。
- `summary.txt` 寫某一項 OK、檔案卻不在壓縮檔裡時，記一條 note（ATTENTION）。

## 輸入格式

三個檔案都是純文字，以 `== <項目>` 分段。每段是 `鍵=值` 的行，每個欄位有三種結果：

| 結果 | 寫法 | 匯入後 |
|---|---|---|
| 找到 | `present`、`yes`，或一個值 | 依規則判斷 |
| 沒找到 | `absent`、`no` | 最多出 info |
| 沒量到 | `NOT_RUN (<原因>)`、缺這一段、讀不懂 | 列進 `not_run`，最多出 info |

匯入端只認下面列出的段落和鍵。其他內容不收，每段最多 200 行（`update-channel.txt` 是 400 行），每行最多 300 字。

- **`integrity.txt`** 的段落：
  - `uefi`：`efi`、`SecureBoot`、`SetupMode`，以及 `PK`／`KEK`／`db`／`dbx` 有沒有。
  - `dt-secure-boot`、`dmesg-secureboot`。
  - `tegra-fuse`：Jetson，只收白名單節點。
  - `lockdown`、`modsig`、`tpm`、`ima`、`dm-verity`。
  - `lockdown` 段：只有 securityfs 讀得到時才能寫 `lockdown=absent`（表示核心沒有 lockdown）；securityfs 不在、或讀不到時一律寫 `lockdown=NOT_RUN (<原因>)`，匯入後是沒量到，不出 finding。
- **`update-channel.txt`** 的段落：
  - `apt-sources`：每個來源只有協定、主機、路徑第一段；本機來源只有協定。
  - `apt-config`：只收白名單的鍵。
  - `apt-keys`：只有數量與有沒有。
  - `ota-tools`、`esrt`。
- **`logging.txt`** 的段落：`journald`、`daemons`、`rotation`、`remote-logging`（只有 yes／no）、`auth-logging`（只有有沒有與行數）。

範例（虛構的值）：

```
== uefi
efi=present
SecureBoot=0
SetupMode=0
PK=present
== lockdown
lockdown=none [integrity] confidentiality
== ima
ima=NOT_RUN (no securityfs)
```

## 判定規則

- 只有**找到弱點**才出 low、medium 或 high 的 finding。
- **沒找到保護機制**、**沒量到**，最多出 info。這兩種都不當作通過。
  - 測試 `test_not_found_or_not_measured_is_at_most_info` 和 `test_not_found_or_not_measured_end_to_end_is_info` 檢查這條規則。
- 來源互相矛盾時（例如 efivar 和 dmesg 不一致）不下結論，記一條 note。
- **例外：`lockdown=absent` 出 low**（C0 決定，與上游一致）。
  - absent 的意思是 securityfs 讀得到，但沒有 `/sys/kernel/security/lockdown`，也就是**量到了**核心沒編進 lockdown，屬於「找到弱點」，不是「沒量到」。
  - IMA、dm-verity 沒找到只算 info，因為完整性可能用別的機制做（簽章更新包、唯讀 rootfs 等）。
  - 測試：`test_integrity_secure_boot_off_and_jetson_fuse_unreadable`（absent → low）、`test_lockdown_not_run_when_securityfs_missing`（securityfs 不在 → NOT_RUN，不出 finding）。

| finding ID | 條件 | 嚴重度 |
|---|---|---|
| `board:secureboot-disabled` | UEFI Secure Boot 關閉：efivar、device-tree、dmesg 裡有量到的都指向關閉。只代表 UEFI 這一層 | medium |
| `board:secureboot-fuse-not-burned` | Jetson 的 `odm_production_mode` 是 0（開發狀態） | medium |
| `board:secureboot-fuse-not-assessed` | Jetson，但讀不到 fuse 節點 | info |
| `board:secureboot-not-assessed` | 沒有任何 UEFI 或 fuse 的證據 | info |
| `board:lockdown-none` | 核心 lockdown 是 none，或核心沒有 lockdown（`absent`：securityfs 讀得到但沒有 lockdown 檔；**例外**，見上面） | low |
| `board:integrity-verification-not-found` | 沒找到 dm-verity，也沒找到 IMA | info |
| `board:apt-insecure-allowed` | apt 允許沒有簽章的套件或來源（`AllowUnauthenticated` 等，或網路來源有 `trusted=yes`） | high（只有本機來源時 medium） |
| `board:apt-tls-verify-off` | `Verify-Peer`／`Verify-Host` 設成 false | medium |
| `board:apt-source-http` | 啟用的來源用 http（索引仍有簽章） | low |
| `board:update-channel-not-found` | 沒有網路 apt 來源、沒有 OTA 工具、沒有 UEFI capsule（ESRT）。意思是「沒找到」，不是「不能更新」 | info |
| `board:no-log-service` | journald、rsyslog、syslog-ng、auditd 都沒在跑；狀態讀不到時不下結論 | medium |
| `board:journal-not-persistent` | journal 不持久，而且沒有其他記錄程式寫到磁碟 | low |
| `board:log-rotation-missing` | rsyslog 寫 `/var/log`，但沒有輪替 | low |
| `board:remote-logging-not-configured` | 沒有遠端記錄目標 | info |
| `board:auth-logging-not-found` | 沒找到登入記錄 | info |

解析結果放在 `board-test.json` 的 `runs[].info.integrity`、`.update_channel`、`.logging`。schema 仍是 `sca-center-board-test/1`，只加欄位。
`summary.txt` 的 `script-version` 列會進 `info.script_version`，`security-findings.md` 的測試工具欄會顯示它。

## 不收的內容

- efivar 的內容：只看 PK、KEK、db、dbx 有沒有。
- 原始的 fuse 陣列。
- apt 來源的帳密與查詢字串。
  - 收集端照規則先遮掉。
  - 匯入端也只取協定與主機；主機不合格式時記 `INVALID`。
  - 帳密不會進 finding 或 info，有測試檢查。
- 遠端記錄的目標位址、登入記錄的內容。

注意：`board-import.sh` 會把壓縮檔裡的文字檔原樣解開到結果資料夾（`<rootfs>/board-test/<名稱>/`），這是既有的行為。所以收集端沒遮掉的內容會留在那裡，但不會進報告。

## Jetson fuse 節點的出處與限制

- `odm_production_mode` 是 NVIDIA tegra 核心原始碼（android.googlesource.com 上的鏡像）裡 tegra-fuse 驅動的 sysfs 屬性：`drivers/misc/tegra-fuse/tegra_fuse.c` 的 `DEVICE_ATTR(odm_production_mode, 0440, …)`，
  <https://android.googlesource.com/kernel/tegra.git/+/8a95a1a8e5817af21188ad74872b768d5d1ebe35/drivers/misc/tegra-fuse/tegra_fuse.c>。
- Jetson Linux Developer Guide 的 Secure Boot 一節列出 `odm_production_mode`（tegraflash 別名 SecurityMode）與 Security_info（BootSecurityInfo）這兩個 fuse，
  例如 <https://docs.nvidia.com/jetson/archives/l4t-archived/l4t-3273/Tegra%20Linux%20Driver%20Package%20Development%20Guide/bootloader_secure_boot.html>。
- `security_mode`、`boot_security_info` 這兩個 sysfs 節點名稱沿用收集腳本的白名單，**沒有找到 NVIDIA 的正式文件**。讀不到時就是沒量到。
- 較新的 Jetson（例如 R36）可能沒有這些 sysfs 節點。這時 fuse 型的 Secure Boot 在執行中的系統讀不到，只出 info。
  要確認，得看燒錄紀錄，或在 recovery mode 用 NVIDIA 的工具讀。
- `odm_production_mode` 是 1 不代表 Secure Boot 已經開了（PKC 雜湊要另外確認），所以不出 finding。
