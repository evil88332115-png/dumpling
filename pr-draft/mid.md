### M2 期間吸收的契約修改（D-036 凍結之後的例外）

| 項目 | 誰提、為什麼 | 對外介面的改變 |
|---|---|---|
| `scan.tools: sbom-only｜full` | C4（擋 C4：AI NAS 要 cdxgen） | platform.yml 新欄位；`full`＝install-tools.sh 完整模式 |
| 核心 CVE 鏡像 cache 與退回 | C4（擋 C4：runner 連 git.kernel.org 偶爾逾時） | `pipeline/lib/mirrors.sh`；退回時 `pipeline-steps.tsv` ATTENTION、Release 說明標示（不擋發佈，同 D-033） |
| `kernel-versions.json` schema `/2`（上游版本與依據） | C3（每日監控的核心 CNA 比對要上游版本） | `shipped[].upstream_version／upstream_basis／upstream_note`；讀取端 /1、/2 都收；Release 附件 `kernel-versions-<專案>-<版本>.json` |
| `platform_params.kernel_upstream_version` | C4 | sources.yml；`project-info.py --kernel-args` → 精靈 `--kernel-upstream-version` |
| release-meta 的產品結論 | C4 提、C0 決定放 M2 | `report_status`、`release_gate`、`reports`、`kernel_versions`；`result` 改名 `pipeline_result` |
| scan_plan 用 0x1F 分隔 | C4 在 AI NAS 踩到（ours 的空後綴被 TAB 吃掉） | `platform_scan.scan_plan_lines`／`jetson_scan.py plan`；collect 同一後綴兩次取後面那次 |
| 分層報告的核心不適用、核心不在發行版序列上的防護 | C4（rpi 的 -os 多出約 2700 列；bsp 漏報約 2400 個 CVE），D-044 | `--kernel-in-other-report`；`platform_params.kernel_not_distro`、platform.yml `scan.kernel_not_distro`；C-kernel-coverage 新的 GAP 條件 |
| 沒有宣告自有軟體 → GAP | C0（C4 的示範專案也會遇到） | config `sbom.own_software_none_reason`；scan.json `own_software` |
| scan.json 的 `p1_rows` 依 layer_todo | C4（ours 的 P1 少算） | ours 時 os 層的 P1 也算 |
| `scan.platform_arg` 真的傳到工具 | 第一輪獨立驗證 | `DUMPLING_SCAN_PLATFORM_ARG`；platform_arg 只能是 jetson／raspberrypi／rockchip／generic，`scan.rootfs` 只能是 rootfs |

排到 M7（D-035、D-036、D-038、D-039、D-044）：逐顆核心判定與合併、上游版本對核心 CNA 並補 Grype 沒有的 CVE（`kernel_cna_rows`）、出貨的 `/boot/config-*` 優先、「核心覆蓋 OK」的判斷條件、new-project.sh 不帶範本值、C4 的缺口 7、20、22、23。
