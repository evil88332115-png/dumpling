# C2：BIOS／vBIOS／供應商 SBOM 的「發現新版本」（決定 D-046、D-059；設計，尚未實作）

D-046 的四步（發現新版本、共用工具下載與核對、每日監控、人審後合併）裡，C2 負責 BIOS 這一部分。D-046 的順序是 Jetson（C1）先做，所以這份只是設計：
轉接器的函式與輸出格式要等 C1 的發現介面定案後對齊（見第 7 節）。資料是 2026-11-14 讀公開頁面整理的，沒有登入，也沒有接受任何條款。

## 1. 每個來源

「雜湊類型」：signed＝官方雜湊有簽章，可以用固定的金鑰驗；same-origin＝雜湊和檔案來自同一個來源，只防傳輸錯誤；none＝沒有官方雜湊，下載後記 TOFU（首次下載記錄）。
「自動」：auto＝可以自動發現與下載；manual＝工具不碰，只標「需人工」。

| 來源（firmware.yml 樣本） | 新版本來源（機器可讀） | 官方雜湊 | 雜湊類型 | 自動 | 取得限制 |
|---|---|---|---|---|---|
| Dasharo 映像：Protectli VP46xx、NovaCustom V540TU、NovaCustom NUC BOX、NovaCustom NS5x（供應商 SBOM） | dl.3mdeb.com 的目錄索引（HTML，格式固定，每個版本一個資料夾，有檔名、日期、大小）；版本與日期另見 docs.dasharo.com 各機型的 releases 頁（原始檔是 GitHub Dasharo/docs 的 `releases.md`） | 每個檔案旁有 `.sha256` 與 `.sha256.sig`（OpenPGP 分離簽章） | signed（金鑰依第 5 節固定並核對後才算；之前算 same-origin） | auto | 不需登入、沒有 CAPTCHA；dl.3mdeb.com 沒有 robots.txt；3mdeb 對自動下載的條款沒有找到明文（不確定） |
| Dasharo 的 GitHub 原始碼封存（Protectli 的 coreboot、edk2） | commit 由 Dasharo 公布的 revision 決定 | GitHub 動態封存沒有官方雜湊 | none（以 commit SHA 為準，D-027 (5)） | auto | 公開；封存的 sha256 記 TOFU，不符時用 clone 加 checkout 核對，或標 GAP |
| Ubuntu OVMF（edk2 套件） | Launchpad API 的 `getPublishedSources`（JSON，有版本、pocket、日期）；或 archive.ubuntu.com 的 `Sources.gz`／`Packages.gz` | archive 的 `InRelease`（OpenPGP 簽章）→ Sources／Packages 的 sha256 → 檔案 | signed（Ubuntu archive 金鑰依第 5 節固定） | auto | 公開；Launchpad API 有速率限制（細節不確定） |
| ASUS PRIME B550M-A | 支援頁的 HTML 內嵌資料（版本、日期、下載路徑、sha256 欄位），沒有文件化的公開 API | 頁面有部分版本的 SHA-256（3404 這筆沒有） | same-origin，而且不是每版都有 | **manual** | ASUS 的使用條款限制用自動工具蒐集網站資料；採保守解讀，自動流程不讀這個頁面（D-059） |
| Intel NUC 11（BIOS PATGL357，現由 ASUS 提供） | 同上（ASUS 的 supportonly 頁） | 頁面有 SHA-256（0059 與 firmware.yml 相符） | same-origin | **manual** | 同上 |
| NVIDIA DisplayPort 韌體更新工具 | 下載頁的 HTML 固定欄位（版本、發佈日期、大小），沒有 JSON 或 RSS | 頁面沒有雜湊 | none（TOFU） | **manual** | 官方下載鈕先經過授權確認頁；自動流程不代為接受，也不用繞過確認頁的直接網址 |
| 獨立 NVIDIA vBIOS（`standalone-nvidia-option-rom`） | 沒有官方公開檔案 | 無 | — | 不支援自動發現（GAP） | — |

公開網址：
- https://dl.3mdeb.com/open-source-firmware/Dasharo/
- https://docs.dasharo.com/variants/protectli_vp46xx/releases/ 、https://docs.dasharo.com/variants/novacustom_v540tu/releases/ 、https://docs.dasharo.com/variants/novacustom_nuc_box/releases/
- https://docs.dasharo.com/guides/signature-verification/ 、https://github.com/3mdeb/3mdeb-secpack 、https://github.com/Dasharo/docs
- https://api.launchpad.net/devel/ubuntu/+archive/primary 、https://archive.ubuntu.com/ubuntu/dists/noble-updates/InRelease
- https://www.asus.com/motherboards-components/motherboards/prime/prime-b550m-a/helpdesk_bios/ 、https://www.asus.com/supportonly/nuc11pahi7/helpdesk_bios 、https://www.asus.com/terms_of_use_notice_privacy_policy/official-site/
- https://www.nvidia.com/en-us/drivers/nv-uefi-update-x64/

格式上要注意的地方：
- Dasharo 的目錄路徑每個機型都不同，同一機型的不同版本也可能不同（例如 V540TU 的 v0.9.0 與 v1.0.x 在不同的上層目錄）。所以每個樣本要寫一個「版本索引網址」，由人維護；只在同一個目錄裡找版本號比較大的資料夾是不夠的。
- Launchpad 會列出所有 Ubuntu 序列的版本：發現步驟要限定序列（noble）與 pocket（security、updates）。

## 2. 發現步驟的輸出（C2 的需求，介面待和 C1 對齊）

每個來源輸出一份：

    discover:
      source_id: <樣本 slug 或來源 id>
      supported: true|false                 # false 一定附 reason
      reason: terms | eula | no-public-source | no-machine-source
      index_url: <版本索引網址>
      checked_utc: <ISO 8601>
      candidates:                           # 比 repo 已登記的版本新的；沒有就是空清單
        - version: <版本>
          released: <YYYY-MM-DD；讀不到就省略，不猜>
          files:
            - name, url, role, size
              hash: {type: sha256, value, source_url, provenance: signed|same-origin|none, signature_url}
          license_url: <授權頁>

- `provenance: signed`：由共用的 OpenPGP 驗簽工具驗（第 5 節）。驗不過、金鑰過期、指紋不符一律 FAIL，不降級成 same-origin 或 TOFU。
- `provenance: same-origin`：PR 說明與 yml 註解寫明「雜湊與檔案同源，只防傳輸錯誤」。
- `provenance: none`：下載後記 TOFU，不寫成「官方核對」。
- `supported: false` 的來源：報告與監控標「需人工追蹤」並寫明原因；自動流程不碰這些頁面，不登入，也不接受條款。

| 來源 | supported | reason |
|---|---|---|
| Dasharo 映像與 SBOM、Dasharo 的 GitHub 封存、Ubuntu OVMF | true | — |
| ASUS B550M-A、Intel NUC 11 | false | terms |
| NVIDIA DisplayPort 工具 | false | eula |
| 獨立 NVIDIA vBIOS | false | no-public-source |

## 3. 新版本與 firmware.yml（D-059 (3)）

- 一個版本一個資料夾（`firmware/<kind>/<slug-版本>/firmware.yml`）。BIOS 樣本是互相獨立的測試資料，和 Jetson 的產品多版本不同，所以新版本是**新增一個資料夾**；既有資料夾（含 sha256 與 expected）永遠不被工具修改，目標路徑已存在就停止並回報。
- 新資料夾的 `status` 是 `candidate`。`pipeline/lib/firmware_plan.py` 遇到 `candidate` 報 GAP「預期值未審」，不會是 OK。人審通過後才改成 `ok`。
- 下載與核對用共用工具（`pipeline/lib/fetch_verify.py`）；C2 只提供各來源的發現步驟。
- PR 附下載記錄：每個檔案的網址、大小、sha256、雜湊類型與來源、下載時間（UTC）。

## 4. expected（預期值）

- 新版本資料夾不自動產生 `expected`。工具只輸出 `expected_candidate` 草稿：從來源頁讀得到的值（例如 Dasharo release notes 列的 ME、FSP、微碼版本、coreboot revision），每一項附出處網址。草稿放在 PR 說明或另一個不被 `pipeline/firmware-expect.py` 讀的檔案，不放進 `expected:`（那個鍵不認得的內容會被當成格式錯誤）。
- 人審時把確認過的項目搬進 `expected:`，驗證代理獨立核對後才合併（D-046 第 4 步）。

## 5. 簽章驗證與金鑰（D-059 (1)、(2)）

- 要固定的金鑰全部列在 repo 的單一檔案，每把寫明：指紋、用途、出處、核對日期、核對者角色。指紋要由人對照兩個獨立來源核對後才能寫入；核對之前，那個來源只算 same-origin，不能標 signed。
- Dasharo 的 master key：docs.dasharo.com 的簽章驗證頁寫的到期日是 2026-02-02；現行指紋要人工對照 3mdeb-secpack 確認，列入人工核對項目。每個平台的 release signing key 寫在各版本的 release notes，所以驗簽也是每個版本都要做的步驟，用到的指紋寫進 PR 說明。
- OpenPGP 驗簽是共用工具，放在 `pipeline/lib`：用 `gpgv`，keyring 只放固定的金鑰，不讀系統預設的 keyring，失敗就擋下。介面先給 C1 看；C4 的 apt `InRelease` 之後也會用。
- 簽章只證明檔案由金鑰持有者簽出，不證明內容正確；ME、微碼等版本仍然靠 expected 的獨立佐證。

## 6. 每日監控（C3）需要的資料

每個來源每天一筆：`source_id`、`supported`、`reason`、`checked_utc`、`latest_seen`（版本、日期）、`registered_latest`（repo 已登記的最新版）、`new_candidates`（空清單表示沒有）、`error`。
- 發現失敗（連不上、索引格式不認得）是錯誤或 GAP，不能當成「沒有新版」。
- `supported: false` 的來源每天輸出「需人工追蹤」並附原因；Issue 附上給人點開的公開頁網址，工具不抓那些頁面。
- 偵測到 `new_candidates` 才開 Issue；內容同第 2 節的 candidates。

## 7. 要等 C1 的發現介面才能定的部分

- 轉接器的函式名稱與輸入輸出格式（第 2 節只是 C2 的需求）。
- `provenance` 的值與 TOFU 的標記方式（Jetson 的 `sources.yml` 目前用註解記 TOFU，是否改成結構欄位）。
- 共用 OpenPGP 驗簽工具的介面（誰先需要誰寫，介面先給 C1 看）。
- PR 與 Issue 範本、監控輸出的格式（C3）。

## 8. 已知限制

- 目錄索引、ASUS 與 NVIDIA 的頁面都是 HTML，改版就會解析失敗；解析器在格式不認得時要回報錯誤，不猜。
- Dasharo 的 `.sha256` 與映像在同一台主機：簽章通過才算 signed；沒有驗簽只算 same-origin。
- 3mdeb 對 dl.3mdeb.com 自動下載的條款不確定；Dasharo docs 站沒有逐頁確認有沒有限制。
- 不支援自動發現的來源，D-046 第 2 步以後的流程都由人手動做（手動步驟手冊涵蓋）。
- 新版本的解析結果要另跑 `pipeline/firmware-bios.sh`；發現步驟不保證新版本能被 C2 的解析器處理。
