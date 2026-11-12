# PROVENANCE：從 sca-center 複製的檔案

每個從 sca-center 複製進來的檔案記一列：dumpling 路徑、sca-center 原路徑、來源 commit、清理了什麼。
目錄對應規則（D-015）：sca-center 的 `scripts/<子目錄>/<檔名>` → dumpling 的 `tools/<子目錄>/<檔名>`；測試 `scripts/<子目錄>/tests/` → `tools/<子目錄>/tests/`。
各節只由負責的對話修改，避免衝突。

## C1 工具（WP1）

| dumpling 路徑 | sca-center 原路徑 | 來源 commit | 清理內容 |
|---|---|---|---|
| `pipeline/dt-compose.yaml` | `scripts/e2e/dt-compose.yaml` | 25fa89a | 改名 e2e-dt→dumpling-dt；埠改成 `${DT_PORT:-8080}`；註解改寫；映像 digest 與其餘設定不變 |
| `pipeline/dt-ephemeral.sh` | `scripts/e2e/dtlib.sh`（做法參考，重寫） | 25fa89a | 改寫成 up／wait／env／down 四個子指令；狀態檔取代 sca-center 的 status／secret 函式；關 NVD、開 OSV 與 KEV、API key 流程沿用；新增 KEV 與 OSV 鏡像等待與逾時 GAP、`::add-mask::` |
| `pipeline/dt-verify.py` | `scripts/e2e/dtread.py`（分頁與 X-Total-Count 核對的做法） | 25fa89a | 重寫：專案、元件數、依生態系漏洞數的驗證與摘要；另含直接上傳的後備模式 |

## C2 韌體工具（WP3＋WP4）

| dumpling 路徑 | sca-center 原路徑 | 來源 commit | 清理內容 |
|---|---|---|---|
