"""平台無關的 scan 後處理：收集精靈（tools/wizard/cra-scan.py）各次執行的結果 → Release 附件、scan.json、notes.md、manifest.tsv。
Jetson 以外的平台（Raspberry Pi、Rockchip、AI NAS…）的 `scan.sh` 也呼叫這裡；平台特有的部分用 `Hooks` 子類別提供，其餘全部共用。
全部用 `python3 -I` 執行（`sys.path.insert(0, "pipeline/lib")` 之後 import）。

## 其他平台怎麼用

1. `scan.sh` 先跑精靈（完整掃描一次；分層時每個 `layers.json` 的 `scan_plan` 項目再用 `--rescan-from` 跑一次），每次的輸出資料夾是 `<名稱後綴>=<資料夾>`
   （完整掃描的後綴是空字串；用 `newest_dir` 找出精靈剛產生的資料夾）。
2. 寫一個很小的 Python 檔（參考 `pipeline/lib/jetson_scan.py`）：

       import platform_scan as ps

       class MyHooks(ps.Hooks):
           def run_summary_fields(self, paths, status):      # 每次精靈執行的平台特有欄位（放進 scan.json 的 runs[後綴]）
               return {"bootloader": ps.read_json(paths["rootfs"] + "/bootloader-coverage.json", {}).get("status")}
           def scan_tail(self, ctx):                         # 放進 scan.json 最上層的平台特有欄位（取完整掃描那次）
               return {"bootloader": ctx["main_run"].get("bootloader")}
           def notes_build(self, ctx):                       # notes.md 的平台段落（Markdown 行）
               return ["## 建置", "", "- …"]

       # args 要有：out、project、version、layers（sbom-layers.py 的輸出資料夾；沒分層給 None）、build_json、assemble_json（沒有就給 None）、
       #            scan_json、run（["<後綴>=<資料夾>", …]）、official（bool）；
       #            選用：steps（pipeline-steps.tsv 的路徑，pipeline/run-step.sh 寫的各步驟結果）、steps_md（把步驟表另存成 Markdown 的路徑，給 summary.md 用）
       ps.collect(args, MyHooks())

   不需要的 hook 不用寫（預設都是空的）。`collect` 的輸出（都在 `args.out`）：
   - `sbom-<專案>-<版本>.cdx.json`（`layers/sbom.product.cdx.json`）、`-bsp`／`-os` 分層 SBOM、`layers.json`（有分層時）
   - 每個 run：`report-<專案>-<版本><後綴>.zip`、`vex-…`、`vuln-list-….xlsx`、`p1-table-….xlsx`（檔名、來源路徑、顯示名稱由 `Hooks.report_files` 決定）
   - `scan-summary-<專案>-<版本>.json`（＝scan.json，標準答案比對用，見 `pipeline/check-expected.py`）、`notes.md`、`manifest.tsv`（檔名 TAB 顯示名稱）
3. **步驟紀錄**：給 `args.steps` 時，`collect` 把每個 workflow 步驟的結果（OK｜GAP｜NOT_RUN｜FAIL）放進 scan.json 的 `pipeline_steps`、`pipeline_status`
   （有 FAIL → FAIL；有 GAP → GAP；其他 OK；檔案不存在 → GAP）、notes.md 的「流程步驟」表，並寫 `args.steps_md`。整體狀態有 GAP 或 FAIL 時不是 OK——
   平台的 scan 沒有去讀 raw-sectors.json 之類的檔案，GAP 也不會消失。呼叫端（scan.sh）據此至少回報 GAP。
4. 標準答案（`tests/expected/<專案>/<版本>.json`）的路徑是 scan.json 的點分路徑；平台特有欄位由 hook 放進去。

規則：缺的項目在 scan.json 記 null，**不推測**，標準答案比對會因此失敗而不是通過；附件檔名一律 ASCII（GitHub 會改掉非 ASCII 字元），中文名稱放在 manifest 的顯示標籤。
"""
import csv
import json
import os
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import step_rows  # noqa: E402

LAYER_PROP = "dumpling:layer"
DETAIL_STAGES = ("C-kernel-boot", "C-kernel-config", "C-kernel-cve-list", "A-md5", "C-nvidia-bulletins")
# 報告包裡要單獨放成 Release 附件的檔案：(報告包內的相對路徑, 附件檔名樣式, 顯示名稱樣式)；{p}＝專案、{v}＝版本、{s}＝後綴
REPORT_FILES = (("交給PM/VEX/vex.cdx.json", "vex-{p}-{v}{s}.cdx.json", "VEX{s}"),
                ("交給PM/漏洞清單.xlsx", "vuln-list-{p}-{v}{s}.xlsx", "漏洞清單{s}.xlsx"),
                ("給RD/P1判斷表.xlsx", "p1-table-{p}-{v}{s}.xlsx", "P1判斷表{s}.xlsx"))


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


# ---------------------------------------------------------------- 精靈的站台設定

def site_config(out, repo, root, outroot, pilot_env, grype_cache, upstream, python):
    """寫精靈的站台設定檔（--site-config）。upstream：{組名: {鍵: 路徑}}（上游基準檔，輸入清單用組名＋鍵引用）。"""
    doc = {"repo": repo, "root": root, "outroot": outroot, "python": python, "pilot_env": pilot_env, "grype_cache": grype_cache,
           "upstream": upstream}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    return doc


# ---------------------------------------------------------------- 讀精靈的輸出

def newest_dir(root, prefix):
    """root 底下以 prefix 開頭的資料夾，名稱最大（時間戳在名稱裡）的那個；沒有回傳 None。"""
    if not os.path.isdir(root):
        return None
    c = sorted(d for d in os.listdir(root) if d.startswith(prefix) and os.path.isdir(os.path.join(root, d)))
    return os.path.join(root, c[-1]) if c else None


def read_status_tsv(path):
    out = {}
    try:
        with open(path, encoding="utf-8", newline="") as f:
            for row in csv.reader(f, delimiter="\t"):
                if len(row) >= 3 and row[0] != "stage":
                    out[row[0]] = {"status": row[1], "detail": row[2]}
    except OSError:
        pass
    return out


def run_paths(w, rootfs="rootfs"):
    """精靈輸出資料夾 w → 各處路徑。rootfs：scan-flash-package.sh 的 --rootfs 名稱（結果放在 scan/<rootfs>/）。
    scan：sca-scan 的輸出資料夾（status.tsv 在這裡；各階段的 JSON 在它底下的 scan/）。"""
    rd = os.path.join(w, "scan", rootfs)
    return {"rootfs": rd, "scan": os.path.join(rd, "scan"), "reports": os.path.join(w, "cra-project", "CRA", "Reports"),
            "package": os.path.join(w, "報告")}


def vuln_metrics(rows_doc):
    """vulnerability-rows.json → 列數、CVE 數、各 tier、各層、P1 判斷表列數（bsp＋unknown，沒有層標記時全部）。"""
    if not isinstance(rows_doc, dict) or not isinstance(rows_doc.get("rows"), list):
        return None
    rows = rows_doc["rows"]
    tiers, layers = {}, {}
    for r in rows:
        tiers[str(r.get("tier"))] = tiers.get(str(r.get("tier")), 0) + 1
        layers[str(r.get("layer"))] = layers.get(str(r.get("layer")), 0) + 1
    p1 = {r.get("id") for r in rows if r.get("tier") == "p1" and (r.get("layer") in (None, "bsp", "unknown"))}
    return {"rows_total": len(rows), "cves_total": len({r.get("id") for r in rows}), "tiers": tiers, "layers": layers, "p1_rows": len(p1)}


def sbom_layer_counts(path, package_purl_prefix="pkg:deb/"):
    """標好層的 SBOM → ({層: 元件數}, {層: 套件元件數})（子元件跟著父元件，不重複算）；package_purl_prefix 決定哪些算「套件」。"""
    doc = read_json(path)
    if not isinstance(doc, dict):
        return None, None
    n, pk = {}, {}
    for c in doc.get("components") or []:
        layer = next((p.get("value") for p in c.get("properties") or [] if p.get("name") == LAYER_PROP), "none")
        n[layer] = n.get(layer, 0) + 1
        if str(c.get("purl", "")).startswith(package_purl_prefix):
            pk[layer] = pk.get(layer, 0) + 1
    return n, pk


def run_summary(w, hooks=None, rootfs="rootfs", detail_stages=DETAIL_STAGES):
    """一次精靈執行的摘要：各階段狀態、幾個階段的說明、漏洞統計；平台特有的欄位由 hooks.run_summary_fields(paths, status) 提供（放在中間）。"""
    hooks = hooks or Hooks()
    p = run_paths(w, rootfs)
    st = read_status_tsv(os.path.join(p["scan"], "status.tsv"))
    out = {"stages": {k: v["status"] for k, v in st.items()},
           "stage_details": {k: v["detail"][:300] for k, v in st.items() if k in detail_stages}}
    out.update(hooks.run_summary_fields(p, st))
    out["vulnerabilities"] = vuln_metrics(read_json(os.path.join(p["reports"], "vulnerability-rows.json")))
    return out


def zip_dir(src, dst):
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(src):
            dirs.sort()
            for f in sorted(files):
                full = os.path.join(root, f)
                if os.path.islink(full):
                    continue
                z.write(full, os.path.relpath(full, os.path.dirname(src)))


def add(manifest, out, name, label):
    manifest.append((name, label))


# ---------------------------------------------------------------- collect

class Hooks:
    """平台特有的部分；全部有預設（空的），子類別只覆寫需要的。ctx 是 dict：project、version、out、args、build、asm、layers、runs、scan、main_run。"""

    rootfs = "rootfs"                  # scan-flash-package.sh 的 --rootfs 名稱
    detail_stages = DETAIL_STAGES      # scan.json 的 stage_details 收哪些階段的說明
    package_purl_prefix = "pkg:deb/"   # 哪些元件算「套件」（components.deb_bsp／deb_os 的計數）
    report_files = REPORT_FILES

    def run_summary_fields(self, paths, status):
        """每次精靈執行的平台特有欄位（dict）。paths：run_paths 的結果；status：status.tsv（{階段: {status, detail}}）。"""
        return {}

    def scan_head(self, ctx):
        """scan.json 最上層、`os_responsibility` 後面的平台特有欄位。"""
        return {}

    def scan_mid(self, ctx):
        """scan.json 最上層、`layers_gaps` 後面（`runs` 前面）的平台特有欄位。"""
        return {}

    def scan_tail(self, ctx):
        """scan.json 最上層、`runs` 後面的平台特有欄位（通常取 ctx["main_run"]，完整掃描那次）。"""
        return {}

    def extra_attachments(self, ctx, manifest):
        """寫平台特有的附件到 ctx["out"] 並 add(manifest, …)。"""

    def notes_build(self, ctx):
        """notes.md 的「建置」之類的平台段落（Markdown 行清單，放在標題之後、元件與分層之前）。"""
        return []

    def notes_after_vulnerabilities(self, ctx):
        """notes.md 漏洞表之後的平台段落（例如雜湊的依據）。"""
        return []

    def notes_attachments(self, ctx):
        """notes.md「附件」段的平台特有說明行。"""
        return []


def collect(a, hooks=None):
    hooks = hooks or Hooks()
    out = a.out
    os.makedirs(out, exist_ok=True)
    manifest = []
    proj, ver = a.project, a.version
    layers = (read_json(os.path.join(a.layers, "layers.json"), {}) or {}) if a.layers else {}
    build = (read_json(a.build_json, {}) or {}) if getattr(a, "build_json", None) else {}
    asm = (read_json(a.assemble_json, {}) or {}) if getattr(a, "assemble_json", None) else {}
    # --- SBOM（完整的是標好層、沒有 host-tool 的產品 SBOM）與分層 ---
    pairs = [("sbom.product.cdx.json", "sbom-%s-%s.cdx.json" % (proj, ver), "SBOM（完整，標好層）"),
             ("sbom.bsp.cdx.json", "sbom-%s-%s-bsp.cdx.json" % (proj, ver), "SBOM（bsp＋unknown）"),
             ("sbom.os.cdx.json", "sbom-%s-%s-os.cdx.json" % (proj, ver), "SBOM（os）"),
             ("layers.json", "layers.json", "分層摘要")]
    for src, dst, label in pairs:
        if a.layers and os.path.isfile(os.path.join(a.layers, src)):
            shutil.copy2(os.path.join(a.layers, src), os.path.join(out, dst))
            add(manifest, out, dst, label)
    # --- 每個報告 ---
    runs = {}
    for spec in a.run:
        suffix, _, w = spec.partition("=")
        p = run_paths(w, hooks.rootfs)
        runs[suffix] = run_summary(w, hooks, hooks.rootfs, hooks.detail_stages)
        if os.path.isdir(p["package"]):
            zname = "report-%s-%s%s.zip" % (proj, ver, suffix)
            zip_dir(p["package"], os.path.join(out, zname))
            add(manifest, out, zname, "報告包%s（漏洞清單、P1 判斷表、SBOM、VEX、內部存檔）" % suffix)
            for rel, dst_pat, label_pat in hooks.report_files:
                dst = dst_pat.format(p=proj, v=ver, s=suffix)
                if os.path.isfile(os.path.join(p["package"], rel)):
                    shutil.copy2(os.path.join(p["package"], rel), os.path.join(out, dst))
                    add(manifest, out, dst, label_pat.format(p=proj, v=ver, s=suffix))
    # --- scan.json（標準答案比對用） ---
    full_name = "" if "" in runs else next(iter(runs), "")
    _, pk_all = sbom_layer_counts(os.path.join(a.layers, "sbom.product.cdx.json"), hooks.package_purl_prefix) if a.layers else (None, None)
    comp = layers.get("components") or {}
    ctx = {"project": proj, "version": ver, "out": out, "args": a, "build": build, "asm": asm, "layers": layers, "runs": runs,
           "main_run": runs.get(full_name) or {}}
    scan = {"schema": 1, "project": proj, "version": ver, "platform": layers.get("platform"), "os_responsibility": layers.get("os_responsibility")}
    scan.update(hooks.scan_head(ctx))
    scan["components"] = {"total": layers.get("components_total"), "bsp": comp.get("bsp"), "os": comp.get("os"),
                          "unknown": comp.get("unknown"), "host_tool": comp.get("host-tool"),
                          "deb_bsp": (pk_all or {}).get("bsp"), "deb_os": (pk_all or {}).get("os")}
    scan["unknown_by_purl_type"] = (layers.get("unknown") or {}).get("by_purl_type")
    scan["unknown_by_reason"] = (layers.get("unknown") or {}).get("by_reason")
    scan["layers_gaps"] = layers.get("gaps")
    ctx["scan"] = scan
    scan.update(hooks.scan_mid(ctx))
    scan["runs"] = runs
    scan.update(hooks.scan_tail(ctx))
    steps_path = getattr(a, "steps", None)
    srows = step_rows.read_rows(steps_path) if steps_path else None
    if steps_path:
        scan["pipeline_steps"] = srows
        scan["pipeline_status"] = step_rows.overall(srows)
        scan["pipeline_attention"] = step_rows.attention_lines(srows)
    scan["vulnerabilities"] = {("full" if k == "" else k.lstrip("-")): v.get("vulnerabilities") for k, v in runs.items()}
    with open(a.scan_json, "w", encoding="utf-8") as f:
        json.dump(scan, f, ensure_ascii=False, indent=1)
    shutil.copy2(a.scan_json, os.path.join(out, "scan-summary-%s-%s.json" % (proj, ver)))
    add(manifest, out, "scan-summary-%s-%s.json" % (proj, ver), "掃描摘要（標準答案比對用）")
    hooks.extra_attachments(ctx, manifest)
    # --- notes.md ---
    cb = scan["components"]
    L = ["# %s %s" % (proj, ver), "",
         "由 GitHub Actions 自動建置與掃描（%s）。缺資料、沒跑、過期一律標 GAP／NOT_RUN／NOT_ASSESSED，沒有整體 PASS。" % ("正式 Release" if a.official else "手動觸發的草稿"), ""]
    if steps_path and scan.get("pipeline_attention"):
        # ATTENTION：這次用了舊資料頂替（例如 git.kernel.org 連不上，沿用上一份核心 CVE 鏡像）。不擋 Release，但要讓讀的人一眼看到
        L += ["> **ATTENTION（用了舊資料頂替，結果照樣產生，不是 OK）**", ">"] + ["> - " + t.replace("\n", " ") for t in scan["pipeline_attention"]] + [""]
    L += hooks.notes_build(ctx)
    L += ["", "## 元件與分層", "",
          "元件 %s 個：bsp %s、os %s、unknown %s、host-tool %s（unknown 的原因見 `layers.json`）。" % (cb["total"], cb["bsp"], cb["os"], cb["unknown"], cb["host_tool"]),
          "", "## 漏洞（資料庫會變動；各份報告的數字）", "", "| 報告 | 列數 | CVE 數 | P1 判斷表列數 |", "|---|---:|---:|---:|"]
    for k, v in sorted(scan["vulnerabilities"].items()):
        v = v or {}
        L.append("| %s | %s | %s | %s |" % ({"full": "完整（全部層）"}.get(k, k), v.get("rows_total"), v.get("cves_total"), v.get("p1_rows")))
    L += hooks.notes_after_vulnerabilities(ctx)
    if steps_path:
        L += ["", "## 流程步驟（workflow 每一步的結果；整體狀態 **%s**）" % scan["pipeline_status"], ""]
        L += step_rows.markdown_table(srows) if srows is not None else ["（沒有 pipeline-steps.tsv：不能當成沒問題，整體狀態 GAP）"]
        sm = getattr(a, "steps_md", None)
        if sm:
            with open(sm, "w", encoding="utf-8") as f:
                f.write("\n".join(["### 流程步驟（整體狀態 %s）" % scan["pipeline_status"], ""]
                                  + (["**ATTENTION**：" + t for t in scan["pipeline_attention"]] + [""] if scan["pipeline_attention"] else [])
                                  + (step_rows.markdown_table(srows) if srows is not None else ["（沒有 pipeline-steps.tsv）"])) + "\n")
    L += ["", "## 附件", "",
          "- 檔名固定、機器可讀：`sbom-<專案>-<版本>.cdx.json`（完整，標好層；分層加 `-bsp`／`-os`）、`layers.json`、`release-meta.json`。",
          "- `report-*.zip`：報告包（漏洞清單、P1 判斷表、SBOM、VEX、內部存檔）；`vuln-list-*.xlsx`＝漏洞清單、`p1-table-*.xlsx`＝P1 判斷表、`vex-*.cdx.json`＝VEX。"]
    L += hooks.notes_attachments(ctx) or ["- `scan-summary-*.json`：標準答案比對用的掃描摘要。"]
    with open(os.path.join(out, "notes.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    with open(os.path.join(out, "manifest.tsv"), "w", encoding="utf-8") as f:
        for name, label in manifest:
            f.write("%s\t%s\n" % (name, label))
    return scan
