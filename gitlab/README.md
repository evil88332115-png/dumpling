# gitlab/：內部 GitLab 的 CI 範本

對照與搬移檢查清單在 `docs/GITLAB-PORT.md`，這裡只講怎麼用這個資料夾。

| 檔案 | 用途 |
|---|---|
| `.gitlab-ci.yml` | CI 範本。呼叫 repo 裡同一套 `pipeline/` 腳本（`run-step.sh`、`project-info.py`、`release-meta.py`、`watch/*`）。**尚未在內部 GitLab 實際執行**，只通過語法檢查與規則測試 |
| `release-payload.py` | 產生 Releases API 的 JSON（附件 assets links 指向 Generic Package） |
| `fetch-ci-schema.sh` | 下載 GitLab 官方 CI JSON schema（固定 commit），核對 sha256 才輸出路徑 |
| `tests/` | `test_gitlab_ci.py`（不連網的規則測試）、`validate_schema.py`（官方 schema 驗證）、`gitlabci.py`（共用的載入與 extends 展開） |

## 用法

1. 把 `gitlab/.gitlab-ci.yml` 複製成產品 repo 根目錄的 `.gitlab-ci.yml`（`release:sign` 的 `id_tokens` 必須在被簽署的專案本身，**不能用 include 或 child pipeline 引入**）。
2. 換掉下面「要換的變數」。
3. 建立 runner 標籤、CI/CD 變數、protected tag、pipeline schedule（`docs/GITLAB-PORT.md` 第 5、7、8 節）。
4. 本機檢查：

```
bash tests/run.sh                                  # 含 c3-gitlab（不連網，沒有 GITLAB_CI_SCHEMA 時 schema 驗證印 NOT_RUN）
schema=$(bash gitlab/fetch-ci-schema.sh "$TMPDIR/gitlab-schema" | tail -n 1)     # 需要網路；sha256 不符會失敗
GITLAB_CI_SCHEMA="$schema" bash tests/run.d/c3-gitlab.sh                         # 含官方 schema 驗證與反向測試
```

schema 驗證需要 `jsonschema`（Python）；CI 裡請用 `pip install --require-hashes` 安裝固定版本，不要在本機測試裡連網安裝。

## 要換的變數

`.gitlab-ci.yml` 最上面的 `variables:`，以及 CI/CD 設定頁（Settings > CI/CD > Variables）：

| 名稱 | 在哪裡設 | 說明 |
|---|---|---|
| `DUMPLING_IMAGE` | `.gitlab-ci.yml` | 預設是固定版本的公開映像，**換成 RD 的編譯／掃描映像**（固定 digest 或版本，不可用 `latest`） |
| `DUMPLING_APT` | `.gitlab-ci.yml` | 映像裡沒有的套件；映像已含就清成空字串 |
| `DUMPLING_DEV_PROJECTS` | `.gitlab-ci.yml` | 目前未使用，保留給動態 matrix（T-02）；專案清單目前寫在 `dev:*` 的 `parallel:matrix` |
| `DUMPLING_SIGN_MODE` | `.gitlab-ci.yml` | `none`（預設，不簽章）或 `cosign-keyless`（需自架 Sigstore，見 GITLAB-PORT 第 9 節） |
| `tags:`（`dumpling`、`dumpling-build`、`dumpling-scan`） | `.gitlab-ci.yml` | 換成內部 runner 的標籤 |
| `PILOT_ENV` | CI/CD 變數，**File 類型、protected** | 常駐 DT 的連線設定（含 `$INTERNAL_DT_URL` 與 API key），格式待內部驗證 |
| `WATCH_GITLAB_TOKEN` | CI/CD 變數，**protected＋masked** | 每日監控通知用的 project access token（scope `api`，只給一個專案）；只有 `watch:notify` 使用 |
| `DUMPLING_JOB` | Pipeline schedule 的變數 | `watch`（每日監控）或 `dev`（每日開發版） |
| `INTERNAL_MIRROR_URL` | `watch:compute` 的 `variables`，或 CI/CD 變數 | 內部資料源鏡像網址（T-06）；公開 repo 裡只放空字串 |

不要把任何內部主機名、IP、token、信箱寫進這個資料夾；公開 repo 的 pre-push 與 `public-check` 會擋。

## 目前不能自動跑的部分（不要假裝能跑）

- `watch:compute`、`watch:notify`：`pipeline/watch/issues.py`、`collect.py` 目前只支援 GitHub API，GitLab 後端是待辦 T-05。這兩個 job 是 `when: manual`，沒有後端時會印 `NOT_RUN` 並失敗。
- `dev:publish`（T-03）、`firmware:dt`（T-04）：同樣印 `NOT_RUN`。
- `release:sign`：預設 `DUMPLING_SIGN_MODE=none` 就印 `NOT_RUN`；`cosign` 執行檔尚未進 `tools.lock`（T-09）。
- M2 的指令（`project-info.py`、`run-step.sh`、`release-meta.py`…）以 `origin/wp1/m2-jetson` 為準，M2 合併後要再核對一次（T-01）。

## 內部版本核對表

用內部 GitLab 的版本文件確認以下語法都支援，再上線：`workflow:rules`、`rules:changes`、`needs:parallel:matrix`、`parallel:matrix`、`!reference`、`id_tokens`、`resource_group`、`artifacts:expire_in`、Generic Package Registry、Releases API（`assets.links`）、`GET/POST /projects/:id/issues` 的 `confidential`。
