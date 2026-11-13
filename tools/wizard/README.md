# CRA 掃描精靈（tools/wizard/cra-scan.py）

互動式前端：輸入刷機包與 SourceCode 資料夾，自動完成核對 MD5、安全解開原始碼、找核心／UEFI／樹外模組／建置紀錄、
列計畫請你確認、取工具（對目前 checkout 的 HEAD 做 `git archive`，乾淨副本；`--tools-rev` 可指定其他版本）、掃描、套用規則產生 CRA 文件、整理報告。

## 站台設定（只放本機，不進版本庫）

所有和機器有關的路徑都在一個 JSON 設定檔裡。範本：`tools/wizard/wizard.example.json`（只有假路徑）。

```
mkdir -p ~/.config/sca-center
cp tools/wizard/wizard.example.json ~/.config/sca-center/wizard.json   # 然後改成本機的值
```

設定檔位置，依序：`--site-config <檔案>` → 環境變數 `SCA_WIZARD_CONFIG` → `~/.config/sca-center/wizard.json`
（預設位置可以不存在，全部用預設值；明確指定的檔案不存在會報錯。不認得的鍵會報錯，`_` 開頭的鍵當註解忽略）。

| 鍵 | 意義 | 預設 |
|---|---|---|
| `repo` | 工具的 git checkout；每次掃描對它的 `HEAD`（預設）或 `--tools-rev`／`DUMPLING_TOOLS_REV` 指定的版本做 `git archive`，取乾淨副本（沒 commit 的修改不會混進去）。實際用的 commit 寫進 `<輸出>/tools-version.json` | 這個腳本所在的 checkout |
| `root` | 精靈的工作根目錄 | `~/cra-scan` |
| `outroot` | 每次掃描的輸出資料夾放這裡（每次新資料夾，舊的不動） | `<root>/輸出` |
| `python` | 跑 `cra_report.py`、`report_package.py` 的 Python | 目前這個 Python |
| `tools_bin` | 放 syft、grype、sca-scan 等工具的資料夾，會加到 PATH 前面 | 不加 |
| `pilot_env` | 掃描設定檔（鏡像路徑），以環境變數 `PILOT_ENV` 傳給掃描。**真正掃描時必須有**：設定檔這一項或環境變數 `PILOT_ENV` 要指到存在的檔案，否則掃描前就停止（`--plan-only` 不需要） | 無 |
| `grype_seed` | Grype 資料庫的種子；`grype_cache` 不存在時複製過去 | 無 |
| `grype_cache` | Grype 資料庫快取（`GRYPE_DB_CACHE_DIR`） | `<root>/grype-db` |
| `stable_git` | 物件：核心主次版號 → Linux 穩定版 git 資料夾（核心判斷用） | `{}` |
| `upstream` | 物件：組名 → {鍵: 路徑}，放上游基準檔（輸入清單用組名＋鍵引用，不寫死路徑），例如 `{"jetson-r39.2.0": {"public_sources": "…/public_sources.tbz2", "bsp": "…/Jetson_Linux_R39.2.0_aarch64.tbz2"}}` | `{}` |
| `rules_template` | 沒有產品設定包時套用的通用 `vex-rules.json` | 無。沒設定卻要求通用規則時，計畫與步驟 5 會明說「沒有套用」，`plan.json` 的 `generic_rules` 為 `no`、`generic_rules_requested` 為 `yes` |

路徑可用 `~`。

## 執行

一律用 `python3 -I`（隔離模式；腳本的 shebang 不帶 -I，直接執行不會隔離）。

```
python3 -I tools/wizard/cra-scan.py
python3 -I tools/wizard/cra-scan.py --site-config /path/to/wizard.json
# 非互動：--archive A --source S [--name N --version V --config C --role both|manufacturer|supplier --yes --plan-only]
```

`--plan-only` 只解開、找輸入、寫 `plan.json`，不掃描。測試：`python3 -m pytest -q tools/demo/tests/test_wizard_plan.py`。

核心建置紀錄請用 `tools/demo/pack-build-record.sh` 打包（見 `tools/demo/flash-package.md`）。

## 輸入清單（每個產品／平台「掃描前要先匯入什麼」）

找到輸入之後，精靈讀清單、逐項檢查，列出 ✓ 找到（路徑）／✗ 缺少（影響）／－ 無法自動檢查。清單位置，依序：`--inputs <檔>` → 產品設定包裡的 `inputs.json` → `--platform <名稱>`（`tools/wizard/platforms/<名稱>.json`：jetson、rockchip、raspberrypi；後兩個是草稿）。都沒有時印「這個產品沒有輸入清單」並照原流程。
範例：`tools/wizard/inputs.example.json`；真正的設定包放自己的 `inputs.json`（從平台範本複製修改）。

格式（JSON）：`{"schema":1, "platform":"…", "draft":false, "upstream_set":"jetson-r39.2.0", "inputs":[…]}`。每項：

| 欄位 | 意義 |
|---|---|
| `id`、`label` | 識別字（不可重複）、中文名稱 |
| `provider` | 誰提供（RD／CRA掃描／MCU owner…） |
| `required` | 必要（true）或選用 |
| `kind` | flash_package、source_archive、build_record、extra_deliverable、upstream_source、upstream_bsp、upstream_uefi、vendor_bulletin、board_test、product_config、other |
| `locate` | 怎麼找，剛好一種：`{"plan":"<plan.json 的鍵>","companion":".md5"}`、`{"glob":"<相對 SourceCode 資料夾的萬用字元>","base":"source 或 flash"}`、`{"upstream":"<站台設定 upstream.<upstream_set> 的鍵>"}`、`{"config_file":"<設定包內檔名>"}`、`{"manual":true}`（無法自動檢查） |
| `affects` | 缺少時影響什麼（印出並寫進報告） |
| `note` | 備註（選填） |

注意：站台設定加了 `upstream` 之後，舊版精靈會因為「不認得的鍵」拒絕這份設定檔；舊版要一起更新，或另用一份不含 `upstream` 的設定檔。
`glob`、`config_file` 只能找來源資料夾／設定包裡面：不可是絕對路徑、不可含 `..`，符號連結與解析後跑到外面的結果不算找到。`required` 必須是 true／false。
`required: true` 且 `manual` 的項目不會悄悄通過：精靈印「未確認」，`inputs-check.json` 記在 `unconfirmed_required`，報告在第一頁設定警告出一行（只是警告，不算 GAP，因為只是沒辦法自動確認，不等於缺少）。

結果：輸出資料夾的 `inputs-check.json`（每項 status＝found／missing／unchecked）；`plan.json` 多 `inputs_check`、`upstream_set`、`upstream_bsp`、`upstream_source`（站台設定解析出的上游路徑，檔案存在才填；掃描後精靈用它們跑 `upstream_baseline.py`，見下節）。必要輸入缺少時問是否繼續（`--yes` 直接繼續並記錄 `continued_with_missing_required`）。
報告：精靈把 `inputs-check.json` 交給 `report_package.py --inputs-check`；每個缺少的必要輸入在第一頁的設定警告出一行、列入「未產生的項目.md」（整體狀態 GAP），檔案複製到內部存檔。

## 產品設定包：版本與刷機包識別由精靈覆寫

設定包不要寫死版本；精靈會覆寫 `config.json` 的 `product.version` 與刷機包識別（`product.identification`），避免換版後 SBOM、VEX、客戶資料包與報告掛著舊版名稱。只改輸出資料夾裡的複本（製造商與供應商兩份），`--config` 指的原資料夾不動。

- 版本：改成精靈的計畫版本。設定包的值結尾若有括號後綴（例如 `V39.2.0.2_a (rootfs)` 的 ` (rootfs)`）且後綴本身不是版本號，保留後綴 → `<計畫版本> (rootfs)`；否則直接是 `<計畫版本>`。
- 版本的括號後綴可以有多個（`V1 (rootfs)(gui)` → `V9 (rootfs)(gui)`）；`config.json` 讀不了或 `product.version` 不是字串時不猜，記 ATTENTION。**dumpling 在地（D-039、D-055）**：`product.version` 沒寫時直接填入這次的版本（不記 ATTENTION）；`identification` 沒寫而 provenance 有 32 碼 MD5 時填入 `Flash package <檔名> (MD5 <md5>)`；`support.end_date` 沒寫時由 `DUMPLING_SUPPORT_UNTIL`（project.yml 的 `support_until`）產生 YYYY-MM，已寫而月份不同記 ATTENTION。
- 識別：掃描後，若 `identification` 以 `Flash package <檔名> (MD5 <md5>)` 開頭，換成 `scan/provenance.json` 的 `source.file`、`source.md5`，句子其餘部分不動。格式認不得，或 provenance 沒有可用的 MD5（缺少或不是 32 碼十六進位），就不改（不會拼出新檔名加舊 MD5），印 `ATTENTION` 請人自行修改。
- 每項覆寫印一行（舊 → 新），並記進 `inputs-check.json` 的步驟（`pack-version-override`、`pack-identification-override`），報告看得到。
- 過期檢查（只警告、不改任何結果，記為步驟 `pack-stale-files`）：`kernel-modules.json` 的 `source` 提到別的刷機包檔名、`image_sha256` 和這次掃描的映像不同；`exposed-services.json` 的 `source` 提到和計畫版本同形（同樣段數）、且彼此不是前綴的版本號（`V2.0.0.1` 與 `V2.0.0.1_a` 視為同一版，`Linux V5.10` 不抓）。`image_sha256` 去掉 `sha256:` 前綴、轉小寫後比對；讀不到掃描的 `meta.json`（或 `.xz`）時記 `NOT_RUN`（沒比對），不是靜默略過。
- 交付以 `<OUT>/cra-project` 與 `<OUT>/報告/` 為準。掃描內部的 `scan/rootfs/cra-project` 是草稿（識別在掃描後才覆寫），不要使用。

## 掃描時串進來的既有工具（一次跑完）

| 步驟 | 輸入怎麼來 | 做什麼 | 缺輸入時 |
|---|---|---|---|
| OP-TEE／TF-A／OP-TEE 內建 Mbed TLS | `--tee-source <資料夾>`，或站台設定 `upstream.<組>.public_sources_dir`，再不然 `public_sources` 旁邊已解開的 `extract/`（裡面要找得到 `arm-trusted-firmware*/Makefile` 與 `optee_os/mk/config.mk`，tarball 要先解開） | 傳給 `scan-flash-package.sh --tee-source`（B-tee-source-*、B-tee-grype-*）；`cra_report.py` 自動讀 `<rootfs>/tee-source/` | 計畫與 `plan.json`（`tee_source_gap`）記 GAP，不中止 |
| UEFI 平台設定（G1） | 核心建置紀錄（`pack-build-record.sh --uefi=`）裡的 `uefi/nvidia-config/*/config.dsc.inc`；只讀一般檔案（連結、裝置檔、超過 4 MB 不收，最多 8 份），放進輸出資料夾 `uefi-platform-defines/` | 傳給 `--uefi-platform-defines`（需要有 UEFI 原始碼與平台 DSC）；優先於原始碼包裡的 | 計畫印「建置紀錄裡沒有」，UEFI 映像檢查那幾列維持 not_assessed |
| A0 上游基準 | `plan.json` 的 `upstream_bsp`、`upstream_source` | 掃描後跑 `upstream_baseline.py artifacts`（刷機包對 BSP）與 `source`（sources/ 對 public_sources），輸出 `<rootfs>/upstream-baseline-{artifacts,source}.{json,md}`（`cra_report.py` 找 `<scan>/../`）；各 3600 秒上限，耗時記在 `wizard-steps.json` | GAP／FAIL 只印一行並記入 `wizard-steps.json`，不中止 |
| 板子檢查結果 | `--board-test <board-test-*.tar.gz｜board-net-*.tar.gz>`（可重複；互動模式問「有板子檢查結果檔嗎？」） | 掃描後 `board-import.sh --result <rootfs> --no-cra <檔案…>`（`SCA_PYTHON` 用站台設定的 python），在 CRA 步驟之前；檔案內容由 `board_import.py` 驗證 | 沒給 → `board-import` 記 NOT_RUN，對外服務欄維持「不明」；輸入清單的 `board_test`（kind＝board_test）依此判斷 found／missing |

A-provenance 的 sca-center commit：精靈跑的是 `git archive`（沒有 `.git`），所以把「取工具」那個 commit 以環境變數 `SCA_CENTER_COMMIT`（40 位十六進位）告訴掃描；`provenance.json` 記 `from: wizard-archive`、`dirty: false`。有 `.git` 或部署資料夾時以它們為準，這個變數不會蓋過。
