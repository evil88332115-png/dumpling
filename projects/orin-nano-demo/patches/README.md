# patches/

模擬「RD 把上游已修的 CVE 修補 backport 進 NVIDIA 公開核心」。build 步驟（`pipeline/platforms/jetson/prepare-source.sh`）在 `nvbuild.sh`
之前套用，assemble 步驟交給精靈的原始碼樹也是套好的（上游比對因此會看到被修改的檔案）。

## 哪個 patch 套在哪個版本

寫在 `sources.yml` 該版本的 `platform_params.patches`（清單，依序套用）：

```yaml
platform_params:
  patches:
    - 0001-xxx.patch                      # 字串：檔名（只收檔名，不含路徑），套在核心樹 kernel/kernel-noble，patch -p1
    - {file: 0002-yyy.patch, dir: nvidia-oot}   # 或指定原始碼根底下的相對資料夾
```
- 先 `patch --dry-run --fuzz=0` 確認乾淨套用才真的套；套不上 = build 失敗。
- 沒列在任何版本的 patch 不會套用（build 會警告）；`tests/test_jetson_pipeline.py` 要求專案裡的 patch 都有被某個版本列出。
- 這個資料夾的檔案是公開的：patch 的作者信箱、Link 裡的信箱要移掉（只留名字與 commit 編號）。

## 現有 patch

| 檔案 | 套用的版本 | 上游 | CVE | 為什麼選它 |
|---|---|---|---|---|
| `0001-tcp-Fix-potential-UAF-in-reqsk_timer_handler.patch` | `v39.2.1-demo1`（`v39.2.0-demo1` 不套，當對照） | linux-stable `f7fba81b00699360f96ed7d9a47b8c801e74c6f9`（主線 `97c8a3c1f73d828de43a5a88e8a9a143efb2b661`） | CVE-2026-99270 | 只改 1 個檔案（`net/ipv4/inet_connection_sock.c`，1 行）；TCP 一定編進核心；2026-11-12 對 R39.2.1 的 `kernel_src.tbz2` 用 `patch --dry-run --fuzz=0` 乾淨套用，反向則不能套（代表尚未含修補） |

選法：從 Linux 核心 CNA（`git.kernel.org/pub/scm/linux/security/vulns.git`）的 CVE 紀錄找「programFiles 只有 1 個檔案」的，
取紀錄裡列出的 linux-stable 修補 commit，下載該 commit 的 patch，對 R39.2.1 的核心原始碼樹做 `--dry-run`（順向成功、反向失敗）。
驗收：精靈的上游比對（`upstream-baseline-source`）在 `v39.2.1-demo1` 顯示 **1 個檔案被修改**、`v39.2.0-demo1` 顯示 0 個。
