#!/usr/bin/env python3
"""產生 release-meta.json（Release 與 dev/<專案> 滾動 pre-release 的機器可讀中繼資料，給每日監控讀）。

用法：python3 -I pipeline/release-meta.py --project <專案名> --version <版本> --commit <40 位 commit> --run-id <數字> [--built-at <UTC ISO 8601>] [--tag <tag>] --out <檔案>
欄位：project、version、tag、status（取自 project.yml：shipped｜development）、platform、os_responsibility、commit、built_at、workflow_run。
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
    ap.add_argument("--out", required=True)
    ap.add_argument("--projects-dir", default=os.environ.get("DUMPLING_PROJECTS_DIR", os.path.join(HERE, "..", "projects")))
    a = ap.parse_args(argv)
    try:
        meta = build_meta(a.projects_dir, a.project, a.version, a.commit, a.run_id, a.built_at, a.tag)
    except pc.ConfigError as e:
        print("release-meta: FAIL（%s）" % e)
        return 1
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("release-meta: OK（%s %s，status %s）" % (a.project, a.version, meta["status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
