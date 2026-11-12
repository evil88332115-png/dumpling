# STATUS

每個對話一節，**每做完一步就更新並推送**（`ci/status-update.sh`，見 main 的 `docs/HANDOFF.md`）。只改自己那節，`<!-- BEGIN/END -->` 標記不要動。

最後更新：2026-11-12 08:16 -0500（C2）

<!-- BEGIN C0 -->
## C0 協調（WP0）

- 目前在做：看 PR、合併、驗收，回覆 C1–C4
- 分支／PR／commit：main 4700739（C2 的 PR #7 樣本清單、#8 BIOS／vBIOS→CycloneDX 已合併；WP0 的 #1–#5、#10 已合併）；本機累積分支 `wp0/docs-batch-1`（D-019＋HANDOFF 修正，還沒推，等累積成批再開 PR）
- 代理：PR #8 驗證代理已完成（通過，留言在 PR #8）；目前沒有 C0 代理在跑
- 代理總數（全部對話）：C1 寫程式 2、C2 寫程式約 2，約 4／上限 8
- CI：無進行中
- 下一步：等 C1 的 M1（A merge main 取得 D-017 共用檔 → 正式 PR）→ C0 派獨立驗證代理 → 合併 → M1；C2 接著做 PR 2b／vBIOS
- 規則提醒：更新 PR 分支用本機 `git merge origin/main`，不用 `gh pr update-branch`（已通知 C1、C2，D-019 待合併）
- 卡住／等決定：無
<!-- END C0 -->

<!-- BEGIN C1 -->
## C1 流程核心（WP1＋WP6）

- 目前在做：M1（PLAN「里程碑」M1、「可以沿用的東西」）——工具複製＋PROVENANCE、臨時 DT＋上傳測試 SBOM；依 D-014 合成一個 PR
- 分支／PR／commit：
  - `wp1/m1-tools`（工具複製＋PROVENANCE＋tests/run.d/c1-tools.sh；最後要合併的 PR）——draft PR #9，WIP 3121fd8
  - `wp1/m1-dt`（臨時 DT＋測試 SBOM＋dt-smoke workflow；只用 draft PR 跑 CI，最後併進 `wp1/m1-tools`，#6 之後關掉不合併）——draft PR #6，f88ebd6；dt-smoke 綠燈（run 43223829151，約 6 分鐘，OSV／CISA／ENISA 鏡像 318 秒；測試 SBOM 元件 3、漏洞 83）
  - 來源：sca-center `origin/main` 25fa89a
- 代理：
  - 寫程式 A：工具清理複製進 `tools/`＋`docs/PROVENANCE.md`＋單元測試，分支 `wp1/m1-tools`，Sonnet 5.5／high，進行中
  - 寫程式 B：`pipeline/dt-ephemeral.sh`＋`pipeline/dt-compose.yaml`＋`tests/fixtures/sbom/`＋`.github/workflows/dt-smoke.yml`，分支 `wp1/m1-dt`，Sonnet 5.5／medium，完成（尚未整合 tools/，`sca-scan --sbom` 待整合後實跑）
  - 驗證：尚未開（兩個寫程式代理完成、合併分支後開）
- CI：#6、#9 的 tests／dt-smoke（`gh pr checks 6`、`gh pr checks 9`）
- 下一步：等 A 完成 → 把 `wp1/m1-dt` 併進 `wp1/m1-tools`（同時調整：ENISA 鏡像未完成改報 GAP 不判失敗；deb 漏洞設保守下限 ≥1）→ 實跑 `sca-scan --sbom` → 開驗證代理 → 交 C0 合併 → M1 完成通知 C0（C2 的上傳 DT 等這個）
- 卡住／等決定：
  - 等 C2 的 PR 2a（`wp3/bios-sbom`）合併：M1 的 cra 測試要用它的 `cdx_schema.py`、CycloneDX schema、`conftest.py`（D-017，C0 決定先合併 2a；2a＝PR #8，C0 驗證中，合併後 A merge main）
  - （已解決）`/media/` 規則誤擋 `drivers/media/`：C0 已修（D-018，main 631646e），A merge main 後補推 `kernel-included-c-6.{1,8}.json`
<!-- END C1 -->

<!-- BEGIN C2 -->
## C2 韌體（WP3＋WP4）

- 目前在做：B 段。已合併：PR #7（樣本清單＋下載核對）、PR #8（x86_firmware → CycloneDX），main 4700739。進行中：PR 2c（coreboot CBFS／FSP／VBT）、PR 3a（AMI PFAT 解封裝）
- 分支／PR／commit：
  - `wp3/coreboot-cbfs`（PR 2c，worktree `$AGENT_TMP/dumpling-wt-c2-cbfs`，PR 尚未開）
  - `wp3/ami-pfat`（PR 3a，從 main 4700739 開出，worktree `$AGENT_TMP/dumpling-wt-c2-pfat`，PR 尚未開）
- 預定 PR（D-014）：
  - ✅ #7 樣本清單＋下載核對；✅ #8 x86_firmware → CycloneDX（NOT_ASSESSED、GAP、CSME CPE）
  - 2c. `wp3/coreboot-cbfs`：CBFS（FMAP、LZMA／LZ4）、coreboot 版本／config、FSP、VBT、SELF payload 身分 → SBOM
  - 3a. `wp3/ami-pfat`：AMI PFAT 解封裝（Intel NUC BIOS 能讀 ME／微碼）；併入 #7、#8 驗證建議（fetch 測試補強、run.d venv 快取）
  - 2b. BIOS 成品端 UEFI 解開（D-016：等 C1 M1 合併後用 `tools/cra/uefi_image.py`）
  - 3b. `wp4/vbios`：Intel GOP（要 uefi_image）／VBT／legacy VBIOS、獨立 vBIOS（合成 option ROM）、NVIDIA gpu-firmware 公告比對 NOT_ASSESSED
  - 4. `wp3/firmware-dt`：firmware workflow 上傳臨時 DT＋Grype、真實樣本對 expected 的 CI 驗收、供應商 SBOM 匯入（等 C1 M1）
- 代理：
  - 代理 A（寫程式）：PR #7，完成；代理 B（寫程式）：PR #8，完成；PR #7 驗證代理：完成（通過）；PR #8 由 C0 驗證：通過
  - 代理 C（寫程式，Sonnet 5.5 high）：PR 2c，分支 `wp3/coreboot-cbfs`，狀態：進行中
  - 代理 D（寫程式，Sonnet 5.5 high）：PR 3a，分支 `wp3/ami-pfat`，狀態：進行中
- CI：無進行中
- 下一步：2c、3a 開 PR、綠燈後派驗證代理（一次一個）→ 通知 C0；C1 M1 合併後做 2b、3b
- 卡住／等決定：2b、3b 的 GOP 部分等 C1 M1（uefi_image.py）。規則提醒：不用 `gh pr update-branch`，一律 `git merge origin/main`
<!-- END C2 -->

<!-- BEGIN C3 -->
## C3 監控＋GitLab（WP2＋WP5）

- 目前在做：尚未開始（開始條件：C1 的 M2）
- 分支／PR／commit：—
- 代理：無
- CI：無
- 下一步：等 M2
- 卡住／等決定：無
<!-- END C3 -->

<!-- BEGIN C4 -->
## C4 其他平台（WP7）

- 目前在做：尚未開始（開始條件：C1 的 M2，平台介面與開案範本完成）
- 分支／PR／commit：—
- 代理：無
- CI：無
- 下一步：等 M2
- 卡住／等決定：無
<!-- END C4 -->
