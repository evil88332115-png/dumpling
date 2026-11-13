"""平台無關的 scan 後處理：收集精靈（tools/wizard/cra-scan.py）各次執行的結果 → Release 附件、scan.json、notes.md、manifest.tsv。
Jetson 以外的平台（Raspberry Pi、Rockchip、AI NAS…）的 `scan.sh` 也呼叫這裡；平台特有的部分用 `Hooks` 子類別提供，其餘全部共用。
全部用 `python3 -I` 執行（`sys.path.insert(0, "pipeline/lib")` 之後 import）。

## 其他平台怎麼用

1. `scan.sh` 先跑精靈（完整掃描一次；分層時每個 `layers.json` 的 `scan_plan` 項目再用 `--rescan-from` 跑一次），每次的輸出資料夾是 `<名稱後綴>=<資料夾>`
   （完整掃描的後綴是空字串；用 `newest_dir` 找出精靈剛產生的資料夾）。`scan_plan` 用 `scan_plan_lines` 讀（每行「後綴 0x1F SBOM 檔名」，
   shell 用 `IFS=$'\x1f' read -r suffix sfile`；**不要用 TAB**：TAB 是 IFS 空白字元，開頭的空欄位會被吃掉，os_responsibility: ours 的後綴是空字串）。
   ours 的計畫只有一項、後綴是空字串（產品 SBOM 重跑一次）：同一個後綴出現兩次時 `collect` 取**後面那次**當報告
   （kernel-versions 仍取第一次，也就是完整掃描）。
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
   - `kernel-versions-<專案>-<版本>.json`：完整掃描那次 sca-scan 的 `scan/kernel-versions.json`（有而且 schema 對才放）
   - scan.json 的 `own_software`：完整掃描那次 scan-flash-package.sh 的 B-own-software 狀態（沒有宣告自有軟體 → GAP；明確宣告沒有 → OK；
     沒有那一列 → null）；每個 run 也有 `runs[後綴].own_software`
   - scan.json 的產品結論：`reports`（每份報告的 `report_status`＝cra_report summary.json 的 status、`release_gate`＝vex.gate.verdict）、
     整體的 `report_status`／`release_gate`（最差的那份）；讀不到是 NOT_RUN。notes.md 開頭依序印 report_status、release_gate、pipeline_result
3. **步驟紀錄**：給 `args.steps` 時，`collect` 把每個 workflow 步驟的結果（OK｜GAP｜NOT_RUN｜FAIL）放進 scan.json 的 `pipeline_steps`、`pipeline_status`
   （有 FAIL → FAIL；有 GAP → GAP；其他 OK；檔案不存在 → GAP）、notes.md 的「流程步驟」表，並寫 `args.steps_md`。整體狀態有 GAP 或 FAIL 時不是 OK——
   平台的 scan 沒有去讀 raw-sectors.json 之類的檔案，GAP 也不會消失。呼叫端（scan.sh）據此至少回報 GAP。
   沒給 `args.steps`（平台自己的收集腳本沒有 `--steps` 參數，例如 `_shared/wp7_scan.py`）時，用環境變數 `DUMPLING_OUT`（`pipeline/platform.sh` 替每個轉接器設定）
   底下的 `pipeline-steps.tsv`，所以 notes.md 的 pipeline_result 不會因為腳本漏傳參數變成 NOT_RUN（adapter-gaps #26）；兩個都沒有（單元測試、手動呼叫）才是 NOT_RUN。
   collect 執行時 `scan` 這一步自己的列還沒寫（run-step.sh 在步驟結束後才記）：release 工作的 `pipeline/release-meta.py --notes` 會用完整的步驟紀錄重寫 notes.md
   開頭的 pipeline_result 與「流程步驟」一節（`refresh_notes`），讓 notes.md 與 release-meta.json 一致。
4. 標準答案（`tests/expected/<專案>/<版本>.json`）的路徑是 scan.json 的點分路徑；平台特有欄位由 hook 放進去。
5. **版本核對（D-055 (3)）**：每個 run 的輸出資料夾裡，精靈覆寫後的設定包（`cra-project/CRA/Config/config.json`，有供應商資料包時再加 `supplier/cra-project/…`）
   的 `product.version` 必須等於 Release tag 的版本（`args.version`；括號後綴如 ` (rootfs)` 不算）；不一致 → scan.json 的 `product_version_check.status` 是 FAIL，
   collect 把所有輸出寫完之後丟 `ProductVersionMismatch`（ValueError 的子類別，各平台的收集腳本都把它當 FAIL 結束）。設定包沒有 `product.version`（精靈沒有東西可覆寫，
   報告裡版本是 TO BE COMPLETED）是 NOT_SET，不擋；找不到設定檔（沒有跑到報告）是 NOT_RUN。

規則：缺的項目在 scan.json 記 null，**不推測**，標準答案比對會因此失敗而不是通過；附件檔名一律 ASCII（GitHub 會改掉非 ASCII 字元），中文名稱放在 manifest 的顯示標籤。
"""
import csv
import json
import os
import re
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import step_rows  # noqa: E402

LAYER_PROP = "dumpling:layer"
# 報告結論的值，由最差到最好（同 tools/cra/cra_report.py 的 ORDER）；讀不到或不在這裡面 → NOT_RUN（不留空、不當成 OK）
VERDICTS = ("FAIL", "NOT_ASSESSED", "GAP", "NOT_RUN", "ATTENTION", "OK")
KV_SCHEMA_PREFIX = "sca-center-kernel-versions/"
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

PLAN_SEP = "\x1f"
PLAN_SUFFIX_RE = re.compile(r"^(-[a-z0-9][a-z0-9_-]{0,38})?$")
PLAN_SBOM_RE = re.compile(r"^sbom\.[a-z0-9][a-z0-9_-]{0,39}\.cdx\.json$")


def scan_plan_lines(layers_json):
    """layers.json 的 scan_plan → ["<後綴>\x1f<SBOM 檔名>", …]（給 scan.sh 的 `IFS=$'\x1f' read -r suffix sfile`）。
    後綴可以是空字串（ours）；後綴或檔名格式不對、重複的後綴 → ValueError（不讓奇怪的值進 shell）。"""
    doc = read_json(layers_json)
    plan = doc.get("scan_plan") if isinstance(doc, dict) else None
    if not isinstance(plan, list):
        raise ValueError("%s 沒有 scan_plan 清單" % os.path.basename(layers_json))
    lines, seen = [], set()
    for it in plan:
        suffix = it.get("name_suffix") if isinstance(it, dict) else None
        sbom = it.get("sbom") if isinstance(it, dict) else None
        if not (isinstance(suffix, str) and PLAN_SUFFIX_RE.match(suffix)):
            raise ValueError("scan_plan 的 name_suffix 不合法：%r" % str(suffix)[:60])
        if not (isinstance(sbom, str) and PLAN_SBOM_RE.match(sbom)):
            raise ValueError("scan_plan 的 sbom 不合法：%r" % str(sbom)[:60])
        if suffix in seen:
            raise ValueError("scan_plan 的 name_suffix 重複：%r" % suffix)
        seen.add(suffix)
        lines.append(suffix + PLAN_SEP + sbom)
    return lines


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
    """vulnerability-rows.json → 列數、CVE 數、各 tier、各層、P1 判斷表列數（＝我們的待辦：每列的 layer_todo，cra_report 依
    os_responsibility 給——bsp、unknown 一定算，os 只有 ours 或沒給時算；舊資料沒有 layer_todo 時 bsp＋unknown；沒有層標記時全部）。"""
    if not isinstance(rows_doc, dict) or not isinstance(rows_doc.get("rows"), list):
        return None
    rows = rows_doc["rows"]
    tiers, layers = {}, {}
    for r in rows:
        tiers[str(r.get("tier"))] = tiers.get(str(r.get("tier")), 0) + 1
        layers[str(r.get("layer"))] = layers.get(str(r.get("layer")), 0) + 1
    def todo(r):
        v = r.get("layer_todo")
        return v if isinstance(v, bool) else r.get("layer") in (None, "bsp", "unknown")
    p1 = {r.get("id") for r in rows if r.get("tier") == "p1" and todo(r)}
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
    # 產品自有軟體（scan-flash-package.sh 的 B-own-software-<rootfs>，在刷機包那一層的 status.tsv）：沒有宣告時也有這一列（GAP），
    # 沒有這一列（沒經過 scan-flash-package.sh、或舊版）→ None
    pst = read_status_tsv(os.path.join(w, "scan", "status.tsv"))
    own = [v["status"] for k, v in pst.items() if k.startswith("B-own-software")]
    out["own_software"] = worst_verdict(verdict(s) for s in own) if own else None
    out["report_status"], out["release_gate"] = report_verdicts(read_json(os.path.join(p["reports"], "summary.json")))
    out["vulnerabilities"] = vuln_metrics(read_json(os.path.join(p["reports"], "vulnerability-rows.json")))
    return out


def verdict(v):
    return v if isinstance(v, str) and v in VERDICTS else "NOT_RUN"


def worst_verdict(values):
    """結論清單 → 最差的一個；清單是空的 → NOT_RUN。"""
    vals = [verdict(v) for v in values]
    return min(vals, key=VERDICTS.index) if vals else "NOT_RUN"


def report_verdicts(summary):
    """cra_report 的 summary.json（dict 或 None）→ (report_status, release_gate)。
    report_status＝summary.json 的整體 status（每份文件最差的那個）；release_gate＝vex.gate.verdict（VEX 發行閘門）。讀不到 → NOT_RUN。"""
    if not isinstance(summary, dict):
        return "NOT_RUN", "NOT_RUN"
    gate = (summary.get("vex") or {}).get("gate") if isinstance(summary.get("vex"), dict) else None
    return verdict(summary.get("status")), verdict(gate.get("verdict") if isinstance(gate, dict) else None)


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


# ---------------------------------------------------------------- 版本核對（D-055 (3)）

_VER_LIKE = re.compile(r"^[Vv]?\d+(\.\d+)+")      # 同 tools/wizard/cra-scan.py：括號裡是版本號的不是「後綴」


class ProductVersionMismatch(ValueError):
    """精靈覆寫後的 product.version 與 Release tag 的版本不一致（D-055 (3)）。collect 在輸出都寫完之後才丟。"""


def version_base(value):
    """設定包的 product.version → 去掉尾端非版本號的括號後綴（精靈 override_pack_version 保留的 " (rootfs)"、"(rootfs)(gui)"）之後的版本。
    "V1 (rootfs)(gui)" → "V1"；"1.0 (2.0.1)" 的括號是版本號，不當後綴 → 整串留著。"""
    base = value.strip()
    while True:
        m = re.fullmatch(r"(.*?)\s*(\([^()]+\))", base)
        if not m or _VER_LIKE.match(m.group(2)[1:-1].strip()):
            return base
        base = m.group(1).rstrip()


def product_version_status(config_path, tag_version):
    """一份設定檔 → (狀態, product.version 或 None)：OK｜MISMATCH｜NOT_SET（沒有 product.version）｜UNREADABLE（讀不了、不是 JSON 物件、或 product.version 不是字串）｜
    NOT_FOUND（沒有這個檔）。"""
    if not os.path.isfile(config_path):
        return "NOT_FOUND", None
    cfg = read_json(config_path)
    prod = cfg.get("product") if isinstance(cfg, dict) else None
    if not isinstance(prod, dict):
        return "UNREADABLE", None
    v = prod.get("version")
    if v is None or (isinstance(v, str) and not v.strip()):
        return "NOT_SET", None
    if not isinstance(v, str):
        return "UNREADABLE", None
    return ("OK" if version_base(v) == tag_version else "MISMATCH"), v


def check_product_versions(runs, tag_version):
    """runs：{後綴: 精靈輸出資料夾}。→ {"tag_version", "status": OK｜FAIL｜NOT_SET｜NOT_RUN, "checked": [{run, role, product_version, status}], "failures": [說明]}。
    FAIL：任何一份是 MISMATCH 或 UNREADABLE。其餘：有 OK 且沒有 NOT_SET → OK；有 NOT_SET → NOT_SET（沒有東西可核對，不擋）；一份都沒找到 → NOT_RUN。"""
    checked, failures = [], []
    for suffix, w in sorted(runs.items()):
        for role, rel in (("manufacturer", "cra-project"), ("supplier", os.path.join("supplier", "cra-project"))):
            st, v = product_version_status(os.path.join(w, rel, "CRA", "Config", "config.json"), tag_version)
            if st == "NOT_FOUND":
                continue
            run = "full" if suffix == "" else suffix.lstrip("-")
            checked.append({"run": run, "role": role, "product_version": v, "status": st})
            if st == "MISMATCH":
                failures.append("%s 報告（%s）的 product.version 是 %r，Release tag 的版本是 %r" % (run, role, v, tag_version))
            elif st == "UNREADABLE":
                failures.append("%s 報告（%s）的設定檔讀不了或 product.version 不是字串，不能確認版本是 %r" % (run, role, tag_version))
    sts = {c["status"] for c in checked}
    status = "FAIL" if failures else "NOT_RUN" if not checked else "NOT_SET" if "NOT_SET" in sts else "OK"
    return {"tag_version": tag_version, "status": status, "checked": checked, "failures": failures}


# ---------------------------------------------------------------- 流程步驟：notes.md 與 release-meta.json 一致（adapter-gaps #26）

STEPS_HEADING = "## 流程步驟"
_NOTES_HEAD = re.compile(r"^(\*\*report_status \S+?\*\*｜\*\*release_gate \S+?\*\*｜\*\*pipeline_result )\S+?(\*\*)$", re.M)


def steps_section(rows):
    """notes.md 的「流程步驟」一節（Markdown 行；rows 是 step_rows.read_rows 的結果，None＝沒有紀錄檔）。collect 與 refresh_notes 共用。"""
    return ["", "%s（workflow 每一步的結果；整體狀態 **%s**）" % (STEPS_HEADING, step_rows.overall(rows)), ""] + \
        (step_rows.markdown_table(rows) if rows is not None else ["（沒有 pipeline-steps.tsv：不能當成沒問題，整體狀態 GAP）"])


def default_steps_path():
    """平台的收集腳本沒給 --steps 時的預設：$DUMPLING_OUT/pipeline-steps.tsv（run-step.sh 寫的那個檔）；沒有 DUMPLING_OUT → None。"""
    out = os.environ.get("DUMPLING_OUT")
    return os.path.join(out, "pipeline-steps.tsv") if out else None


def refresh_notes(notes_path, rows):
    """用完整的步驟紀錄 rows 重寫 notes.md：開頭一行的 pipeline_result，以及「流程步驟」一節（沒有就插在「附件」前）。
    collect 在 scan 步驟自己的列寫進去之前就產生 notes.md，所以兩者可能差一列；release-meta.py 以同一份紀錄、同一個算法（step_rows.overall）重寫，
    notes.md 與 release-meta.json 就一致。→ True＝內容有改、False＝本來就一致、None＝開頭那行找不到（不是 collect 寫的 notes.md），不動。"""
    with open(notes_path, encoding="utf-8") as f:
        text = f.read()
    new, n = _NOTES_HEAD.subn(lambda m: m.group(1) + step_rows.overall(rows) + m.group(2), text, count=1)
    if not n:
        return None
    sec = "\n".join(steps_section(rows))
    m = re.search(r"\n%s[^\n]*\n.*?(?=\n## |\Z)" % re.escape(STEPS_HEADING), new, re.S)
    if m:
        new = new[:m.start()] + sec + "\n" + new[m.end():]
    elif "\n## 附件" in new:
        i = new.index("\n## 附件")
        new = new[:i] + sec + "\n" + new[i:]
    else:
        new = new.rstrip("\n") + "\n" + sec + "\n"
    if new == text:
        return False
    with open(notes_path, "w", encoding="utf-8") as f:
        f.write(new)
    return True


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
    last = {}   # 同一個後綴出現兩次（ours：完整掃描之後用產品 SBOM 重跑，後綴都是空字串）→ 報告取後面那次
    for spec in a.run:
        suffix, _, w = spec.partition("=")
        last[suffix] = w
    for suffix, w in last.items():
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
    # 映像出貨的核心（sca-scan 的 scan/kernel-versions.json，取完整掃描那次）→ Release 附件 kernel-versions-<專案>-<版本>.json（每日監控的核心 CNA 比對讀它）
    kv_name = None
    kv_spec = next((s_ for s_ in a.run if s_.partition("=")[0] == full_name), None)
    if kv_spec is not None:
        kv_src = os.path.join(run_paths(kv_spec.partition("=")[2], hooks.rootfs)["scan"], "scan", "kernel-versions.json")
        kv = read_json(kv_src) if os.path.isfile(kv_src) and not os.path.islink(kv_src) else None
        if isinstance(kv, dict) and str(kv.get("schema", "")).startswith(KV_SCHEMA_PREFIX):
            kv_name = "kernel-versions-%s-%s.json" % (proj, ver)
            shutil.copy2(kv_src, os.path.join(out, kv_name))
            add(manifest, out, kv_name, "映像出貨的核心與上游版本")
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
    # 產品結論：每份報告的 report_status／release_gate，整體取最差的那份（release-meta.json 照抄；讀不到是 NOT_RUN）
    scan["reports"] = [{"report": "full" if k == "" else k.lstrip("-"), "report_status": v["report_status"], "release_gate": v["release_gate"]}
                       for k, v in runs.items()]
    scan["report_status"] = worst_verdict(r["report_status"] for r in scan["reports"])
    scan["release_gate"] = worst_verdict(r["release_gate"] for r in scan["reports"])
    scan["kernel_versions_file"] = kv_name
    scan["own_software"] = (runs.get(full_name) or {}).get("own_software")   # 完整掃描那次的 B-own-software（標準答案可以固定它）
    scan.update(hooks.scan_tail(ctx))
    steps_path = getattr(a, "steps", None) or default_steps_path()
    srows = step_rows.read_rows(steps_path) if steps_path else None
    if steps_path:
        scan["pipeline_steps"] = srows
        scan["pipeline_status"] = step_rows.overall(srows)
        scan["pipeline_attention"] = step_rows.attention_lines(srows)
    scan["vulnerabilities"] = {("full" if k == "" else k.lstrip("-")): v.get("vulnerabilities") for k, v in runs.items()}
    scan["product_version_check"] = pvc = check_product_versions(last, ver)       # D-055 (3)：精靈覆寫後的版本要等於 Release tag 的版本
    with open(a.scan_json, "w", encoding="utf-8") as f:
        json.dump(scan, f, ensure_ascii=False, indent=1)
    shutil.copy2(a.scan_json, os.path.join(out, "scan-summary-%s-%s.json" % (proj, ver)))
    add(manifest, out, "scan-summary-%s-%s.json" % (proj, ver), "掃描摘要（標準答案比對用）")
    hooks.extra_attachments(ctx, manifest)
    # --- notes.md ---
    cb = scan["components"]
    presult = scan["pipeline_status"] if steps_path else "NOT_RUN"
    L = ["# %s %s" % (proj, ver), "",
         "**report_status %s**｜**release_gate %s**｜**pipeline_result %s**" % (scan["report_status"], scan["release_gate"], presult), "",
         "- report_status：報告的整體狀態（cra_report `summary.json`；分層時每份報告各一個，這裡取最差的那份）。release_gate：VEX 發行閘門（`vex.gate`）。"
         "pipeline_result：workflow 各步驟的結果，不是產品結論。`release-meta.json` 的 `status`（shipped／development）是生命週期，也不是結論。", ""]
    if len(scan["reports"]) > 1:
        L += ["| 報告 | report_status | release_gate |", "|---|---|---|"]
        L += ["| %s | %s | %s |" % ({"full": "完整（全部層）"}.get(r["report"], r["report"]), r["report_status"], r["release_gate"]) for r in scan["reports"]] + [""]
    L += ["由 GitHub Actions 自動建置與掃描（%s）。缺資料、沒跑、過期一律標 GAP／NOT_RUN／NOT_ASSESSED，沒有整體 PASS。" % ("正式 Release" if a.official else "手動觸發的草稿"), ""]
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
        L += steps_section(srows)
        sm = getattr(a, "steps_md", None)
        if sm:
            with open(sm, "w", encoding="utf-8") as f:
                f.write("\n".join(["### 流程步驟（整體狀態 %s）" % scan["pipeline_status"], ""]
                                  + (["**ATTENTION**：" + t for t in scan["pipeline_attention"]] + [""] if scan["pipeline_attention"] else [])
                                  + (step_rows.markdown_table(srows) if srows is not None else ["（沒有 pipeline-steps.tsv）"])) + "\n")
    L += ["", "## 附件", "",
          "- 檔名固定、機器可讀：`sbom-<專案>-<版本>.cdx.json`（完整，標好層；分層加 `-bsp`／`-os`）、`layers.json`、`release-meta.json`。",
          "- `report-*.zip`：報告包（漏洞清單、P1 判斷表、SBOM、VEX、內部存檔）；`vuln-list-*.xlsx`＝漏洞清單、`p1-table-*.xlsx`＝P1 判斷表、`vex-*.cdx.json`＝VEX。"]
    if kv_name:
        L.append("- `%s`：映像出貨的核心、有沒有判定、上游版本（每日監控的核心 CNA 比對用）。" % kv_name)
    L += hooks.notes_attachments(ctx) or ["- `scan-summary-*.json`：標準答案比對用的掃描摘要。"]
    with open(os.path.join(out, "notes.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    with open(os.path.join(out, "manifest.tsv"), "w", encoding="utf-8") as f:
        for name, label in manifest:
            f.write("%s\t%s\n" % (name, label))
    if pvc["status"] == "FAIL":      # 輸出都寫完才丟：留著附件與 scan.json 可以查是哪一份、什麼值
        raise ProductVersionMismatch("版本與 Release tag 不一致（D-055 (3)）：" + "；".join(pvc["failures"]))
    return scan
