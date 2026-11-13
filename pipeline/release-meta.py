#!/usr/bin/env python3
"""產生 release-meta.json（Release 與 dev/<專案> 滾動 pre-release 的機器可讀中繼資料，給每日監控讀）。

用法：python3 -I pipeline/release-meta.py --project <專案名> --version <版本> --commit <40 位 commit> --run-id <數字> [--built-at <UTC ISO 8601>] [--tag <tag>] --out <檔案>
         [--steps <pipeline-steps.tsv>] [--scan-summary <scan-summary-<專案>-<版本>.json>]
欄位：project、version、tag、status、platform、os_responsibility、commit、built_at、workflow_run，以及三個結果欄位（一律有值，讀不到是 NOT_RUN，不留空）：
- status：**生命週期**（project.yml 的 shipped｜development），不是掃描結論。
- report_status：**產品結論**，報告（cra_report summary.json）的整體狀態；分層時每份報告各一個（reports），這裡取最差的那份。
- release_gate：VEX 發行閘門（summary.json 的 vex.gate.verdict），同樣取最差的那份。
- pipeline_result：workflow 流程步驟的結果（--steps；FAIL > GAP（含沒能執行的 NOT_RUN：不是 run-step.sh --record 記的「不適用」那種）> ATTENTION > OK，檔案不存在是 GAP，沒給是 NOT_RUN），不是產品結論。
另有 reports（[{report: full｜bsp｜os…, report_status, release_gate}]）、kernel_versions（Release 附件 kernel-versions-<專案>-<版本>.json 的檔名或 null）、
steps（每個 workflow 步驟）、attention（用了舊資料頂替的說明，有才放）。值的範圍：OK｜ATTENTION｜NOT_RUN｜GAP｜NOT_ASSESSED｜FAIL。
tag 沒給時是 <專案>/<版本>（dev 版本沒有 tag 時由呼叫端傳 dev/<專案>）。專案或版本不合法 → 不寫檔、結束碼 1。
"""
import argparse
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
import project_config as pc  # noqa: E402
import step_rows  # noqa: E402
from platform_scan import verdict, worst_verdict  # noqa: E402

REPORT_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")


def conclusions(scan, project, version):
    """scan-summary（platform_scan.collect 寫的 scan.json；dict 或 None）→ report_status、release_gate、reports、kernel_versions。"""
    reports = []
    if isinstance(scan, dict) and isinstance(scan.get("reports"), list):
        for r in scan["reports"]:
            if isinstance(r, dict) and isinstance(r.get("report"), str) and REPORT_NAME_RE.fullmatch(r["report"]):
                reports.append({"report": r["report"], "report_status": verdict(r.get("report_status")), "release_gate": verdict(r.get("release_gate"))})
    kv = scan.get("kernel_versions_file") if isinstance(scan, dict) else None
    kv_ok = kv == "kernel-versions-%s-%s.json" % (project, version)
    return {"report_status": worst_verdict(r["report_status"] for r in reports),
            "release_gate": worst_verdict(r["release_gate"] for r in reports),
            "reports": reports, "kernel_versions": kv if kv_ok else None}


def build_meta(projects_dir, project, version, commit, run_id, built_at=None, tag=None):
    if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
        raise pc.ConfigError("commit 必須是 40 位小寫十六進位")
    if not re.fullmatch(r"[0-9]{1,20}", str(run_id or "")):
        raise pc.ConfigError("run-id 必須是數字")
    if built_at is None:
        built_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", built_at):
        raise pc.ConfigError("built_at 必須是 UTC ISO 8601（YYYY-MM-DDTHH:MM:SSZ）")
    if not pc.PROJECT_RE.match(project) or not pc.VERSION_RE.match(version):
        raise pc.ConfigError("專案或版本格式不合法")
    pdir = os.path.join(projects_dir, project)
    p, s = pc.load_project_all(pdir)
    if version not in s["releases"]:
        raise pc.ConfigError("sources.yml 沒有版本 %s" % version)
    return {"schema": 1, "project": project, "version": version, "tag": tag or "%s/%s" % (project, version),
            "status": p["status"], "platform": p["platform"], "os_responsibility": p["os_responsibility"],
            "commit": commit, "built_at": built_at, "workflow_run": str(run_id)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--built-at")
    ap.add_argument("--tag")
    ap.add_argument("--steps", help="pipeline-steps.tsv（pipeline/run-step.sh 寫的各步驟結果）：寫進 steps，整體結果寫進 pipeline_result（有 FAIL／GAP／ATTENTION 或沒能執行的 NOT_RUN 不是 OK；規則在 lib/step_rows.py）")
    ap.add_argument("--scan-summary", help="scan-summary-<專案>-<版本>.json（platform_scan.collect 寫的 scan.json）：產品結論 report_status、release_gate、reports、kernel_versions；"
                                           "沒給、不存在或讀不到 → NOT_RUN")
    ap.add_argument("--out", required=True)
    ap.add_argument("--projects-dir", default=os.environ.get("DUMPLING_PROJECTS_DIR", os.path.join(HERE, "..", "projects")))
    a = ap.parse_args(argv)
    try:
        meta = build_meta(a.projects_dir, a.project, a.version, a.commit, a.run_id, a.built_at, a.tag)
        scan = None
        if a.scan_summary:
            try:
                with open(a.scan_summary, encoding="utf-8") as f:
                    scan = json.load(f)
            except (OSError, ValueError):
                scan = None
        meta.update(conclusions(scan, a.project, a.version))
        meta["pipeline_result"] = "NOT_RUN"
        if a.steps:
            rows = step_rows.read_rows(a.steps)
            meta["steps"] = rows if rows is not None else []
            meta["pipeline_result"] = step_rows.overall(rows)
            att = step_rows.attention_lines(rows)
            if att:
                meta["attention"] = att   # 用了舊資料頂替的說明（例如核心 CVE 鏡像上游連不上）；不擋 Release，但 result 不是 OK
    except pc.ConfigError as e:
        print("release-meta: FAIL（%s）" % e)
        return 1
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("release-meta: OK（%s %s，status %s（生命週期）；report_status %s、release_gate %s、pipeline_result %s）"
          % (a.project, a.version, meta["status"], meta["report_status"], meta["release_gate"], meta["pipeline_result"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
