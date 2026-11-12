# dumpling

可執行的 CRA（EU Cyber Resilience Act）自動化掃描流程，**只用公開資料**在 GitHub Actions 上跑：

- Jetson BSP 的 git 流程：打 tag → CI 編譯核心與樹外模組 → 掃描 → 臨時 Dependency-Track → GitHub Release 附報告、SBOM、VEX
- mini PC 的 BIOS（含 Intel 內顯 GOP／VBT）與顯示卡／獨顯的 vBIOS：解析、身分 SBOM、比對公告
- 每日監控：CISA KEV、EUVD、廠商層級提醒 → GitHub Issue
- 開案範本與平台轉接器（Jetson、Raspberry Pi、Rockchip、x86 NAS），新增專案不必改 workflow
- 之後搬到 GitLab（見 `docs/GITLAB-PORT.md`）

狀態原則：缺資料、沒跑、過期一律標 `GAP`／`NOT_RUN`／`NOT_ASSESSED`，不顯示「安全」或整體 PASS。

## 文件

| 檔案 | 內容 |
|---|---|
| [docs/PLAN.md](docs/PLAN.md) | 規劃（工作包、里程碑、驗收方式） |
| [docs/STATUS.md](docs/STATUS.md) | 進度指標；實際進度表在 [`status` 分支](https://github.com/evil88332115-png/dumpling/blob/status/docs/STATUS.md) |
| [docs/DECISIONS.md](docs/DECISIONS.md) | 決定紀錄 |
| [docs/HANDOFF.md](docs/HANDOFF.md) | 中斷後重開的接手步驟與工作規則 |

## 授權

Apache-2.0，見 [LICENSE](LICENSE)。下載的 BSP、BIOS、vBIOS 檔不在本 repo 內，各自依原廠授權。
