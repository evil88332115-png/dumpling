"""Jetson 轉接器 scan 步驟的 Python 部分（pipeline/platforms/jetson/scan.sh 呼叫；全部用 `python3 -I`）。

子命令：
  site-config  寫精靈的站台設定檔（SCA_WIZARD_CONFIG）
  inputs       複製專案的 CRA/Config，並把 inputs.json 的 upstream_set／版本字樣換成這個版本
  plan         印 layers.json 的 scan_plan（每行「後綴 0x1F SBOM 檔名」，後綴可以是空字串）
  collect      收集各次精靈執行的結果 → Release 附件（ASCII 檔名＋中文標籤）、scan.json（標準答案比對用的摘要）、notes.md、manifest.tsv

平台無關的部分（讀精靈的輸出、報告包、scan.json、notes.md、manifest）在 `pipeline/lib/platform_scan.py`（那裡的 docstring 說明其他平台怎麼呼叫）；
這個檔只留 Jetson 特有的：`rewrite_inputs`（inputs.json 的 upstream_set）、`jetson_site_config`、`JetsonHooks`（核心、建置紀錄、C-kernel-boot、上游比對、刷機包、patch、元件 SHA-1）。

collect 讀的是精靈的輸出資料夾（<輸出>/報告、scan/rootfs/scan/status.tsv、kernel-config.json、upstream-baseline-source.json、
cra-project/CRA/Reports/vulnerability-rows.json）；缺的項目在 scan.json 記 null，**不推測**，標準答案比對會因此失敗而不是通過。
"""
import argparse
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from platform_scan import (Hooks, add, newest_dir, read_json, read_status_tsv, run_paths, site_config, sbom_layer_counts, vuln_metrics,  # noqa: E402,F401
                           zip_dir)
from platform_scan import collect as _collect  # noqa: E402
from platform_scan import scan_plan_lines  # noqa: E402
from platform_scan import run_summary as _run_summary  # noqa: E402

# ---------------------------------------------------------------- Jetson 特有：inputs.json

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


def jetson_site_config(out, repo, root, outroot, pilot_env, grype_cache, upstream_set, public_sources, bsp, python):
    """Jetson 的站台設定：上游基準檔是 public_sources.tbz2 與 BSP（輸入清單的 upstream.<組>.public_sources／bsp）。"""
    return site_config(out, repo, root, outroot, pilot_env, grype_cache, {upstream_set: {"public_sources": public_sources, "bsp": bsp}}, python)


# ---------------------------------------------------------------- collect（Jetson 特有的欄位與說明）

class JetsonHooks(Hooks):
    """核心、建置紀錄、C-kernel-boot、上游比對（原始碼與成品）、刷機包組裝、patch、元件 SHA-1；檔名與欄位都和 M2 第一次跑通時相同。"""

    def run_summary_fields(self, paths, status):
        kc = read_json(os.path.join(paths["scan"], "scan", "kernel-config.json"), {}) or {}      # sca-scan 的輸出資料夾是 rootfs/scan，裡面的 scan/ 才有各階段的 JSON
        br = ((kc.get("kernel") or {}).get("build_record") or {})
        src = read_json(os.path.join(paths["rootfs"], "upstream-baseline-source.json"), {}) or {}
        art = read_json(os.path.join(paths["rootfs"], "upstream-baseline-artifacts.json"), {}) or {}
        tot = src.get("totals") or {}
        return {
            "build_record_status": br.get("status"),
            "kernel_boot": status.get("C-kernel-boot", {}).get("status"),
            "upstream_source": {"status": src.get("status"), "modified": tot.get("modified"), "ours_only": tot.get("ours_only"),
                                "upstream_only": tot.get("upstream_only"), "same": tot.get("same"),
                                "modified_files": [m["path"] for c in src.get("components", []) for m in c.get("modified", [])][:20]} if src else None,
            "upstream_artifacts": {"status": art.get("status"), "detail": art.get("detail")} if art else None,
        }

    def scan_head(self, ctx):
        b = ctx["build"]
        return {"kernel_release": b.get("kernel_release"), "image_sha256": b.get("image_sha256")}

    def scan_mid(self, ctx):
        b, asm = ctx["build"], ctx["asm"]
        return {"assemble": {k: asm.get(k) for k in ("kernel_image_replaced", "rootfs_boot_image_replaced", "ci_modules_in_tree",
                                                      "ci_modules_out_of_tree", "nvidia_modules_dropped", "package_sha256", "dtb_replaced")},
                "build": {"patches": b.get("patches"), "components": b.get("components"), "nvbuild_seconds": b.get("nvbuild_seconds")}}

    def scan_tail(self, ctx):
        m = ctx["main_run"]
        return {k: m.get(k) for k in ("build_record_status", "kernel_boot", "upstream_source", "upstream_artifacts")}

    def extra_attachments(self, ctx, manifest):
        a, proj, ver, build, asm, scan = ctx["args"], ctx["project"], ctx["version"], ctx["build"], ctx["asm"], ctx["scan"]
        src_files = []
        if getattr(a, "project_dir", None):
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
               "build_record_file": os.path.basename(a.build_record) if getattr(a, "build_record", None) else None,
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
        with open(os.path.join(ctx["out"], bname), "w", encoding="utf-8") as f:
            json.dump(brs, f, ensure_ascii=False, indent=1)
        add(manifest, ctx["out"], bname, "建置紀錄雜湊摘要")

    def notes_build(self, ctx):
        scan, build = ctx["scan"], ctx["build"]
        us = scan["upstream_source"] or {}
        return ["## 建置", "",
                "- 核心 `%s`；Image SHA-256 `%s`（建置不可重現：同一份原始碼編兩次，Image 的 SHA-256 不同）" % (build.get("kernel_release"), build.get("image_sha256")),
                "- 建置紀錄（CI 自編）狀態：**%s**（OK＝與刷機包的核心和模組身分相符）；C-kernel-boot（刷機包有兩顆核心？）：**%s**" % (scan["build_record_status"], scan["kernel_boot"]),
                "- UEFI 未自編，使用 BSP 內建（D-002）",
                "- patch：%s" % ("、".join(x.get("file", "?") for x in (build.get("patches") or [])) or "無"),
                "- 上游比對（原始碼 vs NVIDIA public_sources）：狀態 %s，**%s 個檔案被修改**%s；只有我們有 %s、只有 NVIDIA 有 %s（NOT_ASSESSED 的元件不算相同）" % (
                    us.get("status"), us.get("modified"), ("（" + "、".join(us.get("modified_files") or []) + "）") if us.get("modified_files") else "", us.get("ours_only"), us.get("upstream_only")),
                "- 上游比對（成品 vs NVIDIA BSP）：%s" % json.dumps(scan["upstream_artifacts"], ensure_ascii=False)]

    def notes_after_vulnerabilities(self, ctx):
        return ["", "## 雜湊的依據", "",
                "- `public_sources.tbz2` 的整包雜湊依據是**首次下載記錄（TOFU，2026-11-12）**，不是 NVIDIA 公布的值；包內元件的 SHA-1 才是對照 NVIDIA 公布的 `public_sources_sha.txt`（`build-record-*.json`）。"]

    def notes_attachments(self, ctx):
        return ["- `build-record-*.json`：建置紀錄的雜湊摘要；`scan-summary-*.json`：標準答案比對用的掃描摘要。"]


def collect(a):
    return _collect(a, JetsonHooks())


def run_summary(w):
    return _run_summary(w, JetsonHooks())


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
    pl = sub.add_parser("plan")
    pl.add_argument("--layers-json", required=True)
    c = sub.add_parser("collect")
    for k in ("out", "project", "version", "layers", "build-json", "assemble-json", "scan-json"):
        c.add_argument("--" + k, required=True)
    c.add_argument("--run", action="append", required=True, help="<名稱後綴>=<精靈輸出資料夾>（完整掃描的後綴是空字串）")
    c.add_argument("--build-record", default=None)
    c.add_argument("--project-dir", default=None, help="專案資料夾（讀 sources.yml，把下載檔的 sha256 與依據寫進建置紀錄摘要）")
    c.add_argument("--official", action="store_true")
    c.add_argument("--steps", default=None, help="pipeline-steps.tsv（pipeline/run-step.sh 寫的各步驟結果）")
    c.add_argument("--steps-md", default=None, help="把步驟表另存成 Markdown（給 summary.md）")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "site-config":
            jetson_site_config(a.out, a.repo, a.root, a.outroot, a.pilot_env, a.grype_cache, a.upstream_set, a.public_sources, a.bsp, a.python)
            print("jetson_scan: OK（站台設定 %s）" % a.out)
        elif a.cmd == "inputs":
            name = rewrite_inputs(a.src, a.dst, a.release)
            print("jetson_scan: OK（inputs.json 的 upstream_set＝%s）" % name)
        elif a.cmd == "newest":
            d = newest_dir(a.root, a.prefix)
            if not d:
                raise ValueError("%s 底下沒有 %s* 資料夾" % (a.root, a.prefix))
            print(d)
        elif a.cmd == "plan":
            for line in scan_plan_lines(a.layers_json):
                print(line)
        else:
            collect(a)
            print("jetson_scan: OK（附件 %s）" % a.out)
    except (OSError, ValueError) as e:
        print("jetson_scan: FAIL（%s）" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
