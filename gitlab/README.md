# gitlab/：內部 GitLab 的 CI 範本

對照與搬移檢查清單在 `docs/GITLAB-PORT.md`，這裡只講怎麼用這個資料夾。

| 檔案 | 用途 |
|---|---|
| `.gitlab-ci.yml` | CI 範本。呼叫 repo 裡同一套 `pipeline/` 腳本（`run-step.sh`、`project-info.py`、`release-meta.py`、`watch/*`）。**尚未在內部 GitLab 實際執行**，只通過語法檢查與規則測試 |
| `release-payload.py` | 產生 Releases API 的 JSON（附件 assets links 指向 Generic Package） |
| `fetch-ci-schema.sh` | **只在更新 schema 時由人手動執行**：下載官方 CI JSON schema 到暫存資料夾、核對 sha256、印出新舊 sha256，不覆蓋 repo 裡的檔 |
| `tests/data/gitlab-ci-schema/` | 官方 CI JSON schema（`ci.json`，固定 commit 與 sha256）、`NOTICE`、`LICENSE.md`（MIT Expat＋Apache-2.0）、`SOURCE.md` |
| `tests/` | `test_gitlab_ci.py`（不連網的規則測試）、`validate_schema.py`（官方 schema 驗證）、`gitlabci.py`（共用的載入與 extends 展開） |

## 用法

1. 把 `gitlab/.gitlab-ci.yml` 複製成產品 repo 根目錄的 `.gitlab-ci.yml`（`release:sign` 的 `id_tokens` 必須在被簽署的專案本身，**不能用 include 或 child pipeline 引入**）。
2. 換掉下面「要換的變數」。
3. 建立 runner 標籤、CI/CD 變數、protected tag、pipeline schedule（`docs/GITLAB-PORT.md` 第 5、7、8 節）。
4. 本機檢查：

```
bash tests/run.sh          # 含 c3-gitlab（規則測試）與 c3-gitlab-schema（官方 schema 驗證）
```

- `c3-gitlab-schema.sh` 照 `c2-x86-firmware.sh` 的做法開 venv，裝 `tools/cra/tests/requirements.txt` 固定的 jsonschema；建不起 venv 或裝不起套件就 FAIL（要有 `python3-venv` 與網路，可用 `DUMPLING_VENV_CACHE` 快取）。YAML 用系統 python3 的 PyYAML。
- **官方 schema 驗證通過，只代表語法與欄位型別符合 schema，不保證範本在 GitLab 上一定跑得起來。搬到 GitLab 後，要用該 GitLab 實例的 CI Lint 再檢查一次。**

## 要換的變數

`.gitlab-ci.yml` 最上面的 `variables:`，以及 CI/CD 設定頁（Settings > CI/CD > Variables）：

| 名稱 | 在哪裡設 | 說明 |
|---|---|---|
| `DUMPLING_IMAGE` | `.gitlab-ci.yml` | 預設是固定版本的公開映像，**換成 RD 的編譯／掃描映像**（固定 digest 或版本，不可用 `latest`） |
| `DUMPLING_APT` | `.gitlab-ci.yml` | 映像裡沒有的套件；映像已含就清成空字串 |
| `DUMPLING_DEV_PROJECTS` | `.gitlab-ci.yml` | 目前未使用，保留給動態 matrix（T-02）；專案清單目前寫在 `dev:*` 的 `parallel:matrix` |
| `DUMPLING_SIGN_MODE` | `.gitlab-ci.yml` | `none`（預設，不簽章）或 `cosign-keyless`（需自架 Sigstore，見 GITLAB-PORT 第 9 節） |
| `tags:`（`dumpling`、`dumpling-build`、`dumpling-scan`） | `.gitlab-ci.yml` | 換成內部 runner 的標籤 |
| `PILOT_ENV` | 目前由範本設定（`$DUMPLING_OUT_BASE/pilot-env/pilot.env`，臨時 DT 寫入）；**T-14 之後**改成 CI/CD 變數，File 類型、protected | 常駐 DT 的連線設定（含 `$INTERNAL_DT_URL` 與 API key），格式待內部驗證 |
| `WATCH_GITLAB_TOKEN` | CI/CD 變數，**protected＋masked** | 每日監控通知用的 project access token（scope `api`，只給一個專案）；只有 `watch:notify` 使用 |
| `WATCH_GITLAB_READ_TOKEN` | CI/CD 變數，**protected＋masked** | 每日監控讀取用的 project access token（scope `read_api`、角色 Planner：confidential Issue 要 Planner 以上）；只有 `watch:compute` 使用 |
| `DUMPLING_JOB` | Pipeline schedule 的變數 | `watch`（每日監控）或 `dev`（每日開發版） |
| `INTERNAL_MIRROR_URL` | `watch:compute` 的 `variables`，或 CI/CD 變數 | 內部資料源鏡像網址（T-06）；公開 repo 裡只放空字串 |

不要把任何內部主機名、IP、token、信箱寫進這個資料夾；公開 repo 的 pre-push 與 `public-check` 會擋。

## 目前不能自動跑的部分（不要假裝能跑）

- `watch:compute`、`watch:notify`：`pipeline/watch/issues.py`、`collect.py` 目前只支援 GitHub API，GitLab 後端是待辦 T-05。這兩個 job 是 `when: manual`，沒有後端時會印 `NOT_RUN` 並失敗。
- `dev:publish`（T-03）、`firmware:dt`（T-04）：同樣印 `NOT_RUN`。
- `release:sign`：預設 `DUMPLING_SIGN_MODE=none` 就印 `NOT_RUN`；`cosign` 執行檔尚未進 `tools.lock`（T-09）。
- M2 的指令（`project-info.py`、`run-step.sh`、`release-meta.py`…）已對照 M2 合併後的 main 核對（T-01，2026-11-13）。
- runner 前提同 GitHub 代管 runner：非 root 要免密碼 sudo、掃描 runner 要有 docker（scan.sh 目前一定開臨時 DT，常駐 DT 模式是 T-14）；`DUMPLING_APT` 清空時，映像要自己含 platform.yml 的 `build.apt`／`scan.apt`（見 GITLAB-PORT 第 5 節）。

## 內部版本核對表

用內部 GitLab 的版本文件確認以下語法都支援，再上線：`workflow:rules`、`rules:changes`、`needs:parallel:matrix`、`parallel:matrix`、`!reference`、`id_tokens`、`resource_group`、`artifacts:expire_in`、Generic Package Registry、Releases API（`assets.links`）、`GET/POST /projects/:id/issues` 的 `confidential`。
