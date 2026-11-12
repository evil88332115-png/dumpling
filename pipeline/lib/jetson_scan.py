"""Jetson 轉接器 scan 步驟的 Python 部分（pipeline/platforms/jetson/scan.sh 呼叫；全部用 `python3 -I`）。

子命令：
  site-config  寫精靈的站台設定檔（SCA_WIZARD_CONFIG）
  inputs       複製專案的 CRA/Config，並把 inputs.json 的 upstream_set／版本字樣換成這個版本
  collect      收集各次精靈執行的結果 → Release 附件（ASCII 檔名＋中文標籤）、scan.json（標準答案比對用的摘要）、notes.md、manifest.tsv

collect 讀的是精靈的輸出資料夾（<輸出>/報告、scan/rootfs/scan/status.tsv、kernel-config.json、upstream-baseline-source.json、
cra-project/CRA/Reports/vulnerability-rows.json）；缺的項目在 scan.json 記 null，**不推測**，標準答案比對會因此失敗而不是通過。
"""
import argparse
import csv
import json
import os
import re
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

LAYER_PROP = "dumpling:layer"


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


# ---------------------------------------------------------------- site-config / inputs

def site_config(out, repo, root, outroot, pilot_env, grype_cache, upstream_set, public_sources, bsp, python):
    doc = {"repo": repo, "root": root, "outroot": outroot, "python": python, "pilot_env": pilot_env, "grype_cache": grype_cache,
           "upstream": {upstream_set: {"public_sources": public_sources, "bsp": bsp}}}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    return doc


def rewrite_inputs(src_dir, dst_dir, release):
    """複製 CRA/Config 到 dst_dir；inputs.json 的 upstream_set 與字樣裡的 r39.x.y 換成 release（例如 39.2.1）。"""
    if not re.fullmatch(r"\d+\.\d+(\.\d+)?", release):
        raise ValueError("l4t_release 格式不合法：%r" % release)
    if os.path.lexists(dst_dir):
        raise ValueError("目的資料夾已存在：%s" % dst_dir)
    shutil.copytree(src_dir, dst_dir, symlinks=False)
    p = os.path.join(dst_dir, "inputs.json")
    doc = read_json(p)
    if doc is None:
        raise ValueError("CRA/Config/inputs.json 讀不了")
    doc["upstream_set"] = "jetson-r" + release
    text = json.dumps(doc, ensure_ascii=False, indent=1)
    text = re.sub(r"r?39\.\d+\.\d+(?=[^0-9.]|$)", lambda m: ("r" if m.group(0).startswith("r") else "") + release, text)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    return doc["upstream_set"]


# ---------------------------------------------------------------- collect

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


def run_paths(w):
    rd = os.path.join(w, "scan", "rootfs")
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


def sbom_layer_counts(path):
    """標好層的 SBOM → ({層: 元件數}, {層: deb 套件數})（子元件跟著父元件，不重複算）。"""
    doc = read_json(path)
    if not isinstance(doc, dict):
        return None, None
    n, deb = {}, {}
    for c in doc.get("components") or []:
        layer = next((p.get("value") for p in c.get("properties") or [] if p.get("name") == LAYER_PROP), "none")
        n[layer] = n.get(layer, 0) + 1
        if str(c.get("purl", "")).startswith("pkg:deb/"):
            deb[layer] = deb.get(layer, 0) + 1
    return n, deb


def run_summary(w):
    p = run_paths(w)
    st = read_status_tsv(os.path.join(p["scan"], "status.tsv"))
    kc = read_json(os.path.join(p["scan"], "scan", "kernel-config.json"), {}) or {}      # sca-scan 的輸出資料夾是 rootfs/scan，裡面的 scan/ 才有各階段的 JSON
    br = ((kc.get("kernel") or {}).get("build_record") or {})
    src = read_json(os.path.join(p["rootfs"], "upstream-baseline-source.json"), {}) or {}
    art = read_json(os.path.join(p["rootfs"], "upstream-baseline-artifacts.json"), {}) or {}
    v = vuln_metrics(read_json(os.path.join(p["reports"], "vulnerability-rows.json")))
    tot = src.get("totals") or {}
    return {
        "stages": {k: v_["status"] for k, v_ in st.items()},
        "stage_details": {k: v_["detail"][:300] for k, v_ in st.items() if k in ("C-kernel-boot", "C-kernel-config", "C-kernel-cve-list", "A-md5", "C-nvidia-bulletins")},
        "build_record_status": br.get("status"),
        "kernel_boot": st.get("C-kernel-boot", {}).get("status"),
        "upstream_source": {"status": src.get("status"), "modified": tot.get("modified"), "ours_only": tot.get("ours_only"),
                            "upstream_only": tot.get("upstream_only"), "same": tot.get("same"),
                            "modified_files": [m["path"] for c in src.get("components", []) for m in c.get("modified", [])][:20]} if src else None,
        "upstream_artifacts": {"status": art.get("status"), "detail": art.get("detail")} if art else None,
        "vulnerabilities": v,
    }


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


def collect(a):
    out = a.out
    os.makedirs(out, exist_ok=True)
    manifest = []
    proj, ver = a.project, a.version
    layers = read_json(os.path.join(a.layers, "layers.json"), {}) or {}
    build = read_json(a.build_json, {}) or {}
    asm = read_json(a.assemble_json, {}) or {}
    # --- SBOM（完整的是標好層、沒有 host-tool 的產品 SBOM）與分層 ---
    pairs = [("sbom.product.cdx.json", "sbom-%s-%s.cdx.json" % (proj, ver), "SBOM（完整，標好層）"),
             ("sbom.bsp.cdx.json", "sbom-%s-%s-bsp.cdx.json" % (proj, ver), "SBOM（bsp＋unknown）"),
             ("sbom.os.cdx.json", "sbom-%s-%s-os.cdx.json" % (proj, ver), "SBOM（os）"),
             ("layers.json", "layers.json", "分層摘要")]
    for src, dst, label in pairs:
        if os.path.isfile(os.path.join(a.layers, src)):
            shutil.copy2(os.path.join(a.layers, src), os.path.join(out, dst))
            add(manifest, out, dst, label)
    # --- 每個報告 ---
    runs = {}
    for spec in a.run:
        suffix, _, w = spec.partition("=")
        p = run_paths(w)
        runs[suffix] = run_summary(w)
        if os.path.isdir(p["package"]):
            zname = "report-%s-%s%s.zip" % (proj, ver, suffix)
            zip_dir(p["package"], os.path.join(out, zname))
            add(manifest, out, zname, "報告包%s（漏洞清單、P1 判斷表、SBOM、VEX、內部存檔）" % suffix)
            for rel, dst, label in (("交給PM/VEX/vex.cdx.json", "vex-%s-%s%s.cdx.json" % (proj, ver, suffix), "VEX%s" % suffix),
                                    ("交給PM/漏洞清單.xlsx", "vuln-list-%s-%s%s.xlsx" % (proj, ver, suffix), "漏洞清單%s.xlsx" % suffix),
                                    ("給RD/P1判斷表.xlsx", "p1-table-%s-%s%s.xlsx" % (proj, ver, suffix), "P1判斷表%s.xlsx" % suffix)):
                if os.path.isfile(os.path.join(p["package"], rel)):
                    shutil.copy2(os.path.join(p["package"], rel), os.path.join(out, dst))
                    add(manifest, out, dst, label)
    # --- scan.json（標準答案比對用） ---
    full_name = "" if "" in runs else next(iter(runs), "")
    n_all, deb_all = sbom_layer_counts(os.path.join(a.layers, "sbom.product.cdx.json"))
    comp = layers.get("components") or {}
    scan = {"schema": 1, "project": proj, "version": ver, "platform": layers.get("platform"), "os_responsibility": layers.get("os_responsibility"),
            "kernel_release": build.get("kernel_release"), "image_sha256": build.get("image_sha256"),
            "components": {"total": layers.get("components_total"), "bsp": comp.get("bsp"), "os": comp.get("os"),
                           "unknown": comp.get("unknown"), "host_tool": comp.get("host-tool"),
                           "deb_bsp": (deb_all or {}).get("bsp"), "deb_os": (deb_all or {}).get("os")},
            "unknown_by_purl_type": (layers.get("unknown") or {}).get("by_purl_type"),
            "unknown_by_reason": (layers.get("unknown") or {}).get("by_reason"),
            "layers_gaps": layers.get("gaps"),
            "assemble": {k: asm.get(k) for k in ("kernel_image_replaced", "rootfs_boot_image_replaced", "ci_modules_in_tree",
                                                 "ci_modules_out_of_tree", "nvidia_modules_dropped", "package_sha256", "dtb_replaced")},
            "build": {"patches": build.get("patches"), "components": build.get("components"), "nvbuild_seconds": build.get("nvbuild_seconds")},
            "runs": runs}
    main_run = runs.get(full_name) or {}
    scan["build_record_status"] = main_run.get("build_record_status")
    scan["kernel_boot"] = main_run.get("kernel_boot")
    scan["upstream_source"] = main_run.get("upstream_source")
    scan["upstream_artifacts"] = main_run.get("upstream_artifacts")
    scan["vulnerabilities"] = {("full" if k == "" else k.lstrip("-")): v.get("vulnerabilities") for k, v in runs.items()}
    with open(a.scan_json, "w", encoding="utf-8") as f:
        json.dump(scan, f, ensure_ascii=False, indent=1)
    shutil.copy2(a.scan_json, os.path.join(out, "scan-summary-%s-%s.json" % (proj, ver)))
    add(manifest, out, "scan-summary-%s-%s.json" % (proj, ver), "掃描摘要（標準答案比對用）")
    # --- 建置紀錄的雜湊摘要 ---
    src_files = []
    if a.project_dir:
        import project_config as pc
        rel = pc.load_sources(os.path.join(a.project_dir, "sources.yml"))["releases"].get(ver) or {}
        for f in rel.get("files", []):
            if f.get("gap"):
                basis = "GAP：沒有可核對的雜湊"
            elif f.get("sha1"):
                basis = "sha256 固定在 sources.yml；SHA-1 對照 NVIDIA 公布的 release_sha_hashes.txt"
            elif f["name"] == "public_sources.tbz2":
                basis = "首次下載記錄（TOFU），NVIDIA 沒有公布整包雜湊"
            else:
                basis = "sha256 固定在 sources.yml"
            src_files.append({"name": f["name"], "role": f.get("role"), "sha256": f.get("sha256"), "basis": basis})
    brs = {"schema": 1, "project": proj, "version": ver, "kernel_release": build.get("kernel_release"), "image_sha256": build.get("image_sha256"),
           "build_record_file": os.path.basename(a.build_record) if a.build_record else None,
           "build_record_sha256": build.get("build_record_sha256"),
           "build_record_identity": {"status": scan["build_record_status"], "kernel_boot": scan["kernel_boot"],
                                     "meaning": "OK＝CI 自編的建置紀錄與刷機包裡的核心和模組身分相符（kernel.build_record.status）"},
           "built_by": "GitHub Actions（CI 自編）", "uefi": build.get("uefi"), "reproducible": False,
           "reproducible_note": "同一份原始碼編兩次，Image 的 SHA-256 不同；建置紀錄與刷機包來自同一次編譯",
           "patches": build.get("patches"),
           "component_sha1": {"basis": "對照 NVIDIA 公布的 public_sources_sha.txt", **(build.get("components") or {})},
           "public_sources_sha256": {"basis": "首次下載記錄（TOFU），不是 NVIDIA 公布的整包雜湊", "files": src_files},
           "flash_package_sha256": asm.get("package_sha256")}
    bname = "build-record-%s-%s.json" % (proj, ver)
    with open(os.path.join(out, bname), "w", encoding="utf-8") as f:
        json.dump(brs, f, ensure_ascii=False, indent=1)
    add(manifest, out, bname, "建置紀錄雜湊摘要")
    # --- notes.md ---
    us = scan["upstream_source"] or {}
    cb = scan["components"]
    L = ["# %s %s" % (proj, ver), "",
         "由 GitHub Actions 自動建置與掃描（%s）。缺資料、沒跑、過期一律標 GAP／NOT_RUN／NOT_ASSESSED，沒有整體 PASS。" % ("正式 Release" if a.official else "手動觸發的草稿"), "",
         "## 建置", "",
         "- 核心 `%s`；Image SHA-256 `%s`（建置不可重現：同一份原始碼編兩次，Image 的 SHA-256 不同）" % (build.get("kernel_release"), build.get("image_sha256")),
         "- 建置紀錄（CI 自編）狀態：**%s**（OK＝與刷機包的核心和模組身分相符）；C-kernel-boot（刷機包有兩顆核心？）：**%s**" % (scan["build_record_status"], scan["kernel_boot"]),
         "- UEFI 未自編，使用 BSP 內建（D-002）",
         "- patch：%s" % ("、".join(x.get("file", "?") for x in (build.get("patches") or [])) or "無"),
         "- 上游比對（原始碼 vs NVIDIA public_sources）：狀態 %s，**%s 個檔案被修改**%s；只有我們有 %s、只有 NVIDIA 有 %s（NOT_ASSESSED 的元件不算相同）" % (
             us.get("status"), us.get("modified"), ("（" + "、".join(us.get("modified_files") or []) + "）") if us.get("modified_files") else "", us.get("ours_only"), us.get("upstream_only")),
         "- 上游比對（成品 vs NVIDIA BSP）：%s" % json.dumps(scan["upstream_artifacts"], ensure_ascii=False),
         "", "## 元件與分層", "",
         "元件 %s 個：bsp %s、os %s、unknown %s、host-tool %s（unknown 的原因見 `layers.json`）。" % (cb["total"], cb["bsp"], cb["os"], cb["unknown"], cb["host_tool"]),
         "", "## 漏洞（資料庫會變動；各份報告的數字）", "", "| 報告 | 列數 | CVE 數 | P1 判斷表列數 |", "|---|---:|---:|---:|"]
    for k, v in sorted(scan["vulnerabilities"].items()):
        v = v or {}
        L.append("| %s | %s | %s | %s |" % ({"full": "完整（全部層）"}.get(k, k), v.get("rows_total"), v.get("cves_total"), v.get("p1_rows")))
    L += ["", "## 雜湊的依據", "",
          "- `public_sources.tbz2` 的整包雜湊依據是**首次下載記錄（TOFU，2026-11-12）**，不是 NVIDIA 公布的值；包內元件的 SHA-1 才是對照 NVIDIA 公布的 `public_sources_sha.txt`（`build-record-*.json`）。",
          "", "## 附件", "",
          "- 檔名固定、機器可讀：`sbom-<專案>-<版本>.cdx.json`（完整，標好層；分層加 `-bsp`／`-os`）、`layers.json`、`release-meta.json`。",
          "- `report-*.zip`：報告包（漏洞清單、P1 判斷表、SBOM、VEX、內部存檔）；`vuln-list-*.xlsx`＝漏洞清單、`p1-table-*.xlsx`＝P1 判斷表、`vex-*.cdx.json`＝VEX。",
          "- `build-record-*.json`：建置紀錄的雜湊摘要；`scan-summary-*.json`：標準答案比對用的掃描摘要。"]
    with open(os.path.join(out, "notes.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    with open(os.path.join(out, "manifest.tsv"), "w", encoding="utf-8") as f:
        for name, label in manifest:
            f.write("%s\t%s\n" % (name, label))
    return scan


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("site-config")
    for k in ("out", "repo", "root", "outroot", "pilot-env", "grype-cache", "upstream-set", "public-sources", "bsp", "python"):
        s.add_argument("--" + k, required=True)
    i = sub.add_parser("inputs")
    for k in ("src", "dst", "release"):
        i.add_argument("--" + k, required=True)
    n = sub.add_parser("newest")
    n.add_argument("--root", required=True)
    n.add_argument("--prefix", required=True)
    c = sub.add_parser("collect")
    for k in ("out", "project", "version", "layers", "build-json", "assemble-json", "scan-json"):
        c.add_argument("--" + k, required=True)
    c.add_argument("--run", action="append", required=True, help="<名稱後綴>=<精靈輸出資料夾>（完整掃描的後綴是空字串）")
    c.add_argument("--build-record", default=None)
    c.add_argument("--project-dir", default=None, help="專案資料夾（讀 sources.yml，把下載檔的 sha256 與依據寫進建置紀錄摘要）")
    c.add_argument("--official", action="store_true")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "site-config":
            site_config(a.out, a.repo, a.root, a.outroot, a.pilot_env, a.grype_cache, a.upstream_set, a.public_sources, a.bsp, a.python)
            print("jetson_scan: OK（站台設定 %s）" % a.out)
        elif a.cmd == "inputs":
            name = rewrite_inputs(a.src, a.dst, a.release)
            print("jetson_scan: OK（inputs.json 的 upstream_set＝%s）" % name)
        elif a.cmd == "newest":
            d = newest_dir(a.root, a.prefix)
            if not d:
                raise ValueError("%s 底下沒有 %s* 資料夾" % (a.root, a.prefix))
            print(d)
        else:
            collect(a)
            print("jetson_scan: OK（附件 %s）" % a.out)
    except (OSError, ValueError) as e:
        print("jetson_scan: FAIL（%s）" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
