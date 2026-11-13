### M2 新增的資料檔與測試資料的來源

（判定只有公開、合成、內部三種，**內部的一律不帶**；M1 已審過的資料檔見 `docs/PROVENANCE.md`「資料檔與測試資料的來源」。）

| 檔案 | 來源 | 判定 |
|---|---|---|
| `projects/orin-nano-demo/sources.yml` | NVIDIA 公開下載網址（`developer.download.nvidia.com/embedded/L4T/r39_Release_v2.{0,1}/…`）：BSP、範例 rootfs、`public_sources.tbz2`、`public_sources_sha.txt`。BSP 與 rootfs 的 sha256 是 SHA-1 相符後記下的值；`public_sources.tbz2` NVIDIA 沒有公布整包雜湊，sha256 是首次下載記錄（TOFU，2026-11-12），元件 SHA-1 對 NVIDIA 的 `public_sources_sha.txt` | 公開 |
| `projects/orin-nano-demo/patches/0001-tcp-Fix-potential-UAF-in-reqsk_timer_handler.patch` | Linux 上游 commit（linux-stable `f7fba81b…`，主線 `97c8a3c1…`），選法與驗證見 `patches/README.md`；作者信箱已移掉，只留名字與 commit 編號 | 公開（GPL 上游 patch） |
| `projects/orin-nano-demo/CRA/Config/config.json` | 手寫；只留 schema 必填欄位，製造商名稱寫明不是真實製造商 | 合成 |
| `projects/orin-nano-demo/CRA/Config/inputs.json`、`vex-rules.json` | 由 `new-project.sh` 從 `tools/wizard/platforms/jetson.json` 與 `tools/cra/vex-rules.example.json` 帶入 | 合成（範本） |
| `tests/expected/orin-nano-demo/*.json` | 標準答案：元件數、核心版本、狀態用 equals；漏洞數是第一次 CI 跑出的實際值上下抓寬鬆的範圍（資料庫每天變），每項附理由 | 合成（依公開來源的掃描結果訂） |
| `tools/pilot/lib/data/distro-kernel-sources.json` | Debian 建核心用的原始碼套件名稱（`linux`、`linux-latest`、`linux-signed-{amd64,arm64,i386}`）與 `linux-upstream`（核心 `make deb-pkg` 的預設名稱）；依據是 Debian package tracker 的套件頁（`tracker.debian.org/pkg/<名稱>`，未連網逐頁核對） | 公開（套件名稱） |
| `tools/pilot/lib/nvidia-bulletins-gpu-firmware.json` | 手寫的空對照表（沒有任何公告資料） | 合成 |
| 新測試的資料（`tools/pilot/tests/test_kernel_off_series.py`、`test_kernel_in_other_report.py`、`test_kernel_versions.py`，`tools/cra/tests/test_layers_report.py`、`test_kernel_scope.py`，`tests/test_*.py`） | 測試當場組的假 SBOM、purl、status.tsv、rootfs tar。核心套件的名稱與版本形狀取自公開的 Raspberry Pi OS、Radxa、Debian、Ubuntu、Jetson Linux 套件（版本字串是公開發行的） | 合成（公開套件的形狀） |
