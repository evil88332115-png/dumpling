#!/usr/bin/env python3
"""build.py：收資料 → 組成 data dict → 輸出 site/index.html、site/style.css、site/data.json（docs/DASHBOARD.md）。

用法：
  python3 -I pipeline/dashboard/build.py --repo <owner/repo> [--api <API 網址>] [--watch-dir <資料夾>] [--projects-dir projects]
      [--out site] [--now <UTC ISO>] [--commit <sha>] [--backend github]
  token 從環境變數 GITHUB_TOKEN 讀（只放 Authorization 標頭，不進任何輸出）；API 預設 $GITHUB_API_URL。
  --watch-dir：最近一次 watch 成功 run 的 artifact 解開的資料夾（裡面有 run.json、watch-plan-real-N/result.json、watch-support-real-N/result.json）。

分三層（之後搬 GitLab 只換第一層，docs/DASHBOARD.md 第 8 節）：
  1. 取資料：source（collect.GitHubSource：list_releases／fetch，沿用它的大小上限與轉址檢查）、api（issues.Api 的 list_issues）、
     專案（support.load_projects）、watch 資料夾。每一筆來源都有「抓不到」的處理：那一格寫 GAP（原因），整頁照常產生。
  2. 組 data dict（build_data）：只放白名單欄位；字串清掉控制字元、限制長度；不放環境變數、不放 API 回應原文。
  3. 輸出 HTML（render.py，純函式）。
Releases API 與 Issues API 都抓不到 → 結束碼 1、不產生 site（避免用空頁蓋掉舊頁；專案清單讀 checkout，一定成功，不算）。結束碼：OK 0、失敗 1、用法 64。
"""
import argparse
import collections
import datetime
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import render  # noqa: E402
import watchlib  # noqa: E402

SCHEMA = "dumpling-dashboard/1"
LABELS = {"state": "watch-state", "kev": "dumpling-watch", "support": "support-period", "health": "watch-health"}
DRILL_RE = re.compile(r"(^drill$|-drill$|-drill-done$)")
STALE_HOURS = 48
MAX_RELEASES = 200
MAX_META = 1024 * 1024
MAX_SCAN = 8 * 1024 * 1024
MAX_VEX = 32 * 1024 * 1024
MAX_WATCH_FILE = 4 * 1024 * 1024
MAX_ISSUES = 500
DOWNLOAD_RE = re.compile(r"^(report-.+\.zip|vuln-list-.+\.xlsx|p1-table-.+\.xlsx|sbom-.+\.cdx\.json|vex-.+\.cdx\.json|"
                         r"build-record-.+\.json|release-meta\.json|scan-summary-.+\.json)\Z", re.S)
SCAN_RE = re.compile(r"^scan-summary-.+\.json\Z", re.S)
VEX_RE = re.compile(r"^vex-.+\.cdx\.json\Z", re.S)
RUN_KEY = {"": "full", "-bsp": "bsp", "-os": "os"}
# CycloneDX 1.6 的 vulnerability analysis 列舉值（其他值一律歸成「不明」）
VEX_STATES = ("resolved", "resolved_with_pedigree", "exploitable", "in_triage", "false_positive", "not_affected")
VEX_JUSTIFICATIONS = ("code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
                      "requires_environment", "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter",
                      "protected_by_mitigating_control")
UNKNOWN = "不明"
UNSET = "（未填）"


_SCRUB = [""]      # run() 設成 token；c() 會把它從所有外來字串裡拿掉（錯誤訊息、Issue 標題…），token 不能進任何輸出


class Gap(Exception):
    """某一格抓不到或格式不對；訊息會寫成 GAP（原因）。"""


def c(s, n=200):
    """外來字串進 data dict 前的清理（render.esc 會再做一次；這裡讓 data.json 也乾淨）。"""
    s = str(s)
    if _SCRUB[0]:
        s = s.replace(_SCRUB[0], "***")
    return render.clean(s, n)


def cs(v, n=60):
    """狀態類欄位：字串照原值（清理後），其他型別 → None（render 會顯示成不明）。"""
    return c(v, n) if isinstance(v, str) else None


def ci(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 10 ** 12 else None


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_time(s):
    if not isinstance(s, str):
        return None
    try:
        d = datetime.datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


# ---------------------------------------------------------------- 第 1 層：讀檔

def read_json_file(path, limit, what):
    """讀本機 JSON（不跟隨符號連結、一般檔、有大小上限）。失敗丟 Gap。"""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise Gap("%s 讀不到" % what)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Gap("%s 不是一般檔" % what)
        data = f.read(limit + 1)
    if len(data) > limit:
        raise Gap("%s 超過大小上限" % what)
    try:
        return json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        raise Gap("%s 不是合法 JSON" % what)


def fetch_json(source, assets, name, limit, tmp, what):
    """依檔名取附件並解析 JSON。不存在、重複、太大、下載失敗、不是 JSON → Gap。"""
    lst = assets.get(name)
    if not lst:
        raise Gap("%s 缺少" % what)
    if len(lst) > 1:
        raise Gap("%s 附件同名重複" % what)
    a = lst[0]
    if a.size is not None and a.size > limit:
        raise Gap("%s 超過大小上限（%d bytes）" % (what, a.size))
    dest = os.path.join(tmp, "asset.json")
    try:
        source.fetch(a, tmp, "asset.json")
    except Exception as e:         # AssetError 的訊息是 collect 的固定說明；其他例外只留型別名
        if type(e).__name__ == "AssetError":
            raise Gap("%s 下載失敗：%s" % (what, c(e, 120)))
        raise Gap("%s 下載失敗（%s）" % (what, type(e).__name__))
    try:
        return read_json_file(dest, limit, what)
    finally:
        try:
            os.unlink(dest)
        except OSError:
            pass


# ---------------------------------------------------------------- 第 2 層：各區塊

def meta_row(collect, meta, tag, kind, project, tagver):
    err = collect.check_meta(meta, tag, kind, project, tagver)
    if err:
        raise Gap(err)
    reports = []
    for r in meta.get("reports") if isinstance(meta.get("reports"), list) else []:
        if isinstance(r, dict) and isinstance(r.get("report"), str) and collect.REPORT_NAME_RE.fullmatch(r["report"]):
            reports.append({"report": r["report"], "report_status": cs(r.get("report_status")), "release_gate": cs(r.get("release_gate"))})
    att = [c(x, 300) for x in meta.get("attention") if isinstance(x, str) and x.strip()] if isinstance(meta.get("attention"), list) else []
    wr = meta.get("workflow_run")
    return {"gap": None, "status": cs(meta.get("status")), "platform": cs(meta.get("platform"), 40), "commit": cs(meta.get("commit"), 40),
            "built_at": cs(meta.get("built_at"), 40), "workflow_run": c(wr, 20) if isinstance(wr, (str, int)) and not isinstance(wr, bool) else None,
            "report_status": cs(meta.get("report_status")), "release_gate": cs(meta.get("release_gate")),
            "pipeline_result": cs(meta.get("pipeline_result")), "reports": reports[:10], "attention": att[:5]}


def scan_row(scan):
    if not isinstance(scan, dict):
        raise Gap("scan-summary 不是 JSON 物件")
    runs = scan.get("runs")
    if not isinstance(runs, dict) or not runs:
        raise Gap("scan-summary 沒有 runs（schema 不認得）")
    top_vul = scan.get("vulnerabilities") if isinstance(scan.get("vulnerabilities"), dict) else {}
    reports = {}
    for key, name in RUN_KEY.items():
        r = runs.get(key)
        if not isinstance(r, dict):
            continue
        stages = r.get("stages") if isinstance(r.get("stages"), dict) else {}
        non_ok = [[c(k, 60), cs(v, 40)] for k, v in sorted(stages.items(), key=lambda kv: str(kv[0])) if v != "OK"][:100]
        vul = r.get("vulnerabilities") if isinstance(r.get("vulnerabilities"), dict) else top_vul.get(name)
        vul = vul if isinstance(vul, dict) else {}
        tiers = vul.get("tiers") if isinstance(vul.get("tiers"), dict) else {}
        us = r.get("upstream_source")
        reports[name] = {"report_status": cs(r.get("report_status")), "release_gate": cs(r.get("release_gate")),
                         "build_record_status": cs(r.get("build_record_status")),
                         "upstream_source_status": cs(us.get("status")) if isinstance(us, dict) else None,
                         "non_ok_stages": non_ok,
                         "tiers": {k: ci(tiers.get(k)) for k in ("p1", "p2", "p3", "accepted", "nvidia_bulletin") if ci(tiers.get(k)) is not None},
                         "cves_total": ci(vul.get("cves_total"))}
    if not reports:
        raise Gap("scan-summary 的 runs 裡沒有 full／-bsp／-os")
    comp = scan.get("components") if isinstance(scan.get("components"), dict) else {}
    return {"gap": None, "components": {k: ci(comp.get(k)) for k in ("total", "bsp", "os", "unknown") if ci(comp.get(k)) is not None},
            "reports": reports}


def vex_counts(vex):
    """vulnerabilities[].analysis.state × justification 計數。兩者都只認 CycloneDX 1.6 的列舉值，其他歸成「不明」。"""
    if not isinstance(vex, dict) or vex.get("bomFormat") != "CycloneDX":
        raise Gap("VEX 不是 CycloneDX")
    vs = vex.get("vulnerabilities", [])
    if not isinstance(vs, list):
        raise Gap("VEX 的 vulnerabilities 不是陣列")
    cnt = collections.Counter()
    for v in vs:
        a = v.get("analysis") if isinstance(v, dict) else None
        a = a if isinstance(a, dict) else {}
        s, j = a.get("state"), a.get("justification")
        s = UNSET if s is None else s if s in VEX_STATES else UNKNOWN
        j = "—" if j is None else j if j in VEX_JUSTIFICATIONS else UNKNOWN
        cnt[(s, j)] += 1
    rows = [[s, j, n] for (s, j), n in sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))][:40]
    return {"gap": None, "total": len(vs), "counts": rows}


def pick_vex(assets):
    """附件名 vex-*.cdx.json：-bsp.cdx.json 是 bsp、-os.cdx.json 是 os、其他是 full。同一類有兩份就不挑（GAP）。"""
    found = {"full": [], "bsp": [], "os": []}
    for name in sorted(assets):
        if VEX_RE.match(name):
            kind = "bsp" if name.endswith("-bsp.cdx.json") else "os" if name.endswith("-os.cdx.json") else "full"
            found[kind].append(name)
    return found


def read_release(collect, source, rel, kind, project, tagver, tmp):
    tag = rel["tag"]
    assets = rel["assets"]
    row = {"tag": c(tag, 120), "kind": kind, "project": c(project, 63), "version": c(tagver, 64) if tagver else None,
           "published_at": cs(rel.get("published_at"), 40), "prerelease": bool(rel["prerelease"]),
           "meta": None, "scan": None, "vex": {}, "downloads": [], "problems": []}
    for name in sorted(assets)[:300]:
        if DOWNLOAD_RE.match(name):
            lst = assets[name]
            row["downloads"].append({"name": c(name, 220), "size": lst[0].size if lst else None})
    row["downloads"] = row["downloads"][:80]
    # release-meta.json
    try:
        row["meta"] = meta_row(collect, fetch_json(source, assets, "release-meta.json", MAX_META, tmp, "release-meta.json"),
                               tag, kind, project, tagver)
    except Gap as e:
        row["meta"] = {"gap": str(e)}
    # scan-summary：唯一一個
    names = [n for n in sorted(assets) if SCAN_RE.match(n)]
    try:
        if not names:
            raise Gap("沒有 scan-summary-*.json 附件")
        if len(names) > 1:
            raise Gap("有 %d 個 scan-summary-*.json，不挑" % len(names))
        row["scan"] = scan_row(fetch_json(source, assets, names[0], MAX_SCAN, tmp, "scan-summary"))
    except Gap as e:
        row["scan"] = {"gap": str(e)}
    # VEX
    found = pick_vex(assets)
    for kind_name in ("full", "bsp", "os"):
        files = found[kind_name]
        try:
            if not files:
                raise Gap("沒有這份報告的 vex 附件")
            if len(files) > 1:
                raise Gap("有 %d 個同類的 vex 附件，不挑" % len(files))
            row["vex"][kind_name] = vex_counts(fetch_json(source, assets, files[0], MAX_VEX, tmp, "vex（%s）" % kind_name))
        except Gap as e:
            row["vex"][kind_name] = {"gap": str(e)}
    return row


def gather_releases(collect, source, now):
    """→ (section, ok)。draft 一律不列（連 tag 都不記）。"""
    try:
        listing = source.list_releases()
    except Exception as e:
        return {"gap": "Releases API 讀不到：%s" % (c(e, 150) if type(e).__name__ == "ApiError" else type(e).__name__), "rows": [], "skipped": []}, False
    rows, skipped, seen = [], [], set()
    tmp = tempfile.mkdtemp(prefix="dash-")
    try:
        for rel in listing:
            if not isinstance(rel, dict):
                continue
            tag = c(rel.get("tag", "?"), 120)
            if rel.get("malformed"):
                skipped.append({"tag": tag, "why": c(rel["malformed"], 100)})
                continue
            if rel.get("draft") is not False:        # draft（或欄位不是布林）：不列
                continue
            kind, project, tagver = collect.classify(rel["tag"], rel["prerelease"])
            if kind is None:
                skipped.append({"tag": tag, "why": c(project, 100)})
                continue
            if rel["tag"] in seen:
                continue
            seen.add(rel["tag"])
            if len(rows) >= MAX_RELEASES:
                skipped.append({"tag": tag, "why": "超過 %d 個 Release 的上限，不列" % MAX_RELEASES})
                continue
            rows.append(read_release(collect, source, rel, kind, project, tagver, tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    rows.sort(key=lambda r: (r["published_at"] or "", r["tag"]), reverse=True)
    return {"gap": None, "rows": rows, "skipped": skipped[:50]}, True


def issue_rows(raw):
    out = []
    for i in raw[:MAX_ISSUES]:
        if not isinstance(i, dict) or not isinstance(i.get("number"), int) or isinstance(i.get("number"), bool) or i["number"] <= 0:
            continue
        labels = []
        for l in i.get("labels") or []:
            n = l.get("name") if isinstance(l, dict) else l
            if isinstance(n, str):
                labels.append(c(n, 40))
        if any(DRILL_RE.search(n) for n in labels):          # 演練（drill、*-drill、*-drill-done）不列
            continue
        out.append({"number": i["number"], "title": c(i.get("title"), 300),
                    "state": i.get("state") if i.get("state") in ("open", "closed") else "?",
                    "created_at": cs(i.get("created_at"), 40), "labels": labels[:10], "_body": i.get("body")})
    out.sort(key=lambda r: -r["number"])
    return out


def state_issue(issues_mod, rows, repo):
    if not rows:
        return {"gap": "沒有 watch-state 標籤的 Issue"}
    if len(rows) > 1:
        return {"gap": "有 %d 個狀態 Issue（%s）：不挑" % (len(rows), "、".join("#%d" % r["number"] for r in rows[:5]))}
    r = rows[0]
    out = {"gap": None, "number": r["number"], "state": r["state"], "created_at": r["created_at"],
           "baseline_at": None, "matches": None, "vendor_matches": None, "last_run": None}
    try:
        st = issues_mod.decode_state(r["_body"], "real")
    except Exception as e:
        out["gap"] = "狀態 Issue #%d 解不開：%s" % (r["number"], c(e, 120))
        return out
    d = st.get("dumpling")
    out["baseline_at"] = cs(d.get("baseline_at"), 40) if isinstance(d, dict) else None
    out["matches"] = len(st["matches"]) if isinstance(st.get("matches"), dict) else None
    out["vendor_matches"] = len(st["vendor_matches"]) if isinstance(st.get("vendor_matches"), dict) else None
    runs = st.get("runs")
    if isinstance(runs, list) and runs and isinstance(runs[-1], dict):
        last = runs[-1]
        m = re.fullmatch(re.escape("https://github.com/%s/actions/runs/" % repo) + r"([0-9]{1,19})", str(last.get("run_url") or ""))
        out["last_run"] = {"at": cs(last.get("at"), 40), "status": cs(last.get("status")), "detail": c(last.get("detail"), 300),
                           "run_id": m.group(1) if m else None}
    return out


def gather_issues(issues_mod, api, repo):
    """→ (issues 區塊 dict, state_issue 區塊, ok)。每個標籤各自失敗各自 GAP。"""
    sections, ok_any, state = {}, False, {"gap": "沒有讀"}
    for key, label in LABELS.items():
        try:
            raw = issues_mod.list_issues(api, repo, label)
            rows = issue_rows(raw if isinstance(raw, list) else [])
            ok_any = True
        except Exception as e:
            gap = "Issues API 讀不到（%s）：%s" % (label, c(e, 150) if type(e).__name__ == "Fail" else type(e).__name__)
            if key == "state":
                state = {"gap": gap}
            else:
                sections[key] = {"gap": gap, "rows": []}
            continue
        if key == "state":
            state = state_issue(issues_mod, rows, repo)
        else:
            for r in rows:
                r.pop("_body", None)
            sections[key] = {"gap": None, "rows": rows}
    return sections, state, ok_any


def gather_projects(projects_dir, loader, now):
    try:
        if loader is None:
            loader = watchlib.load("support").load_projects
        found = loader(projects_dir)
    except Exception as e:
        return {"gap": "專案清單讀不到（%s）" % type(e).__name__, "rows": []}, False
    rows = []
    for name, _d, proj, err in found:
        row = {"key": c(name, 63), "product_name": None, "status": None, "support_until": None, "days_left": None,
               "error": None, "support_check": None, "latest_release": None, "dev_release": None, "open_issues": None}
        if err or not isinstance(proj, dict):
            row["error"] = "project.yml 不合格：%s" % c(err or "沒有內容", 200)
        else:
            row["product_name"] = c(proj.get("product_name"), 80)
            row["status"] = cs(proj.get("status"))
            su = proj.get("support_until")
            su = su.isoformat() if isinstance(su, (datetime.date, datetime.datetime)) else su
            row["support_until"] = c(su, 40) if isinstance(su, str) else None
            try:
                row["days_left"] = (datetime.date.fromisoformat(su) - now.date()).days if isinstance(su, str) else None
            except ValueError:
                row["days_left"] = None
        rows.append(row)
    if not rows:
        return {"gap": "projects/ 底下沒有 project.yml", "rows": []}, False
    return {"gap": None, "rows": rows}, True


def latest_numbered(names, prefix):
    best = None
    for n in names:
        m = re.fullmatch(re.escape(prefix) + r"([0-9]{1,3})", n)
        if m and (best is None or int(m.group(1)) > best[0]):
            best = (int(m.group(1)), n)
    return best[1] if best else None


def coverage_lines(path):
    """report.md 的「## 每日沒有涵蓋的項目」那一段（列點原文）。"""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            text = f.read(MAX_WATCH_FILE + 1)
    except OSError:
        raise Gap("report.md 讀不到")
    if len(text) > MAX_WATCH_FILE:
        raise Gap("report.md 超過大小上限")
    out, on = [], False
    for line in text.decode("utf-8", "replace").splitlines():
        if line.startswith("## "):
            on = line.strip() == "## 每日沒有涵蓋的項目"
            continue
        if on and line.startswith("- "):
            out.append(c(line[2:], 400))
    if not out:
        raise Gap("report.md 沒有「每日沒有涵蓋的項目」")
    return out[:30]


def plan_result(d):
    if not isinstance(d, dict) or not isinstance(d.get("status"), str):
        raise Gap("result.json 格式不認得")
    per = []
    ps = d.get("per_sbom") if isinstance(d.get("per_sbom"), dict) else {}
    for r in list(ps.values())[:200]:
        if isinstance(r, dict):
            per.append({"tag": c(r.get("tag"), 100), "layer": c(r.get("layer"), 20), "grype": cs(r.get("grype")),
                        "report_status": cs(r.get("report_status")), "release_gate": cs(r.get("release_gate")),
                        "kernel_map": cs(r.get("kernel_map")), "kernel_cna": cs(r.get("kernel_cna")), "exploited": ci(r.get("exploited")),
                        "why": c(r.get("why"), 200) if r.get("why") else None})

    def strs(k):
        v = d.get(k)
        return [c(x, 600) for x in v if isinstance(x, str)][:50] if isinstance(v, list) else []
    stats = d.get("stats") if isinstance(d.get("stats"), dict) else {}
    return {"gap": None, "status": cs(d.get("status")), "detail": c(d.get("detail"), 400), "per_sbom": per, "notes": strs("notes"),
            "attention": strs("attention"), "gaps": strs("gaps"),
            "stats": {k: ci(v) for k, v in stats.items() if isinstance(k, str) and ci(v) is not None and len(k) < 40}}


def support_result(d):
    if not isinstance(d, dict) or not isinstance(d.get("status"), str) or not isinstance(d.get("rows"), list):
        raise Gap("result.json 格式不認得")
    rows = [[c(r[0], 100), cs(r[1]), c(r[2], 400)] for r in d["rows"] if isinstance(r, list) and len(r) == 3][:100]
    return {"gap": None, "status": cs(d.get("status")), "detail": c(d.get("detail"), 200), "today": cs(d.get("today"), 20), "rows": rows}


def gather_watch(watch_dir):
    """→ (watch 區塊, ok)。run.json、watch-plan-real-N、watch-support-real-N 各自缺就各自 GAP。"""
    w = {"run": None, "run_gap": None, "plan": None, "support": None, "coverage": None, "coverage_gap": None}
    if not watch_dir:
        for k in ("run_gap", "coverage_gap"):
            w[k] = "沒有指定 --watch-dir"
        w["plan"] = {"gap": "沒有指定 --watch-dir"}
        w["support"] = {"gap": "沒有指定 --watch-dir"}
        return w, False
    try:
        names = os.listdir(watch_dir)
    except OSError:
        names = []
    ok = False
    try:
        r = read_json_file(os.path.join(watch_dir, "run.json"), MAX_WATCH_FILE, "run.json")
        rid = r.get("id") if isinstance(r, dict) else None
        rid = str(rid) if isinstance(rid, (int, str)) and not isinstance(rid, bool) and re.fullmatch(r"[0-9]{1,19}", str(rid)) else None
        if rid is None:
            raise Gap("run.json 的 id 不是數字")
        w["run"] = {"id": rid, "created_at": cs(r.get("created_at"), 40), "event": cs(r.get("event"), 30), "conclusion": cs(r.get("conclusion"), 30)}
        ok = True
    except Gap as e:
        w["run_gap"] = str(e)
    pdir = latest_numbered(names, "watch-plan-real-")
    sdir = latest_numbered(names, "watch-support-real-")
    for key, dirname, fn in (("plan", pdir, plan_result), ("support", sdir, support_result)):
        try:
            if dirname is None or os.path.islink(os.path.join(watch_dir, dirname)):
                raise Gap("沒有 watch-%s-real-N 的 artifact" % key)
            w[key] = fn(read_json_file(os.path.join(watch_dir, dirname, "result.json"), MAX_WATCH_FILE, "result.json"))
            ok = True
        except Gap as e:
            w[key] = {"gap": str(e)}
    try:
        if pdir is None:
            raise Gap("沒有 watch-plan-real-N 的 artifact")
        w["coverage"] = coverage_lines(os.path.join(watch_dir, pdir, "report.md"))
    except Gap as e:
        w["coverage_gap"] = str(e)
    return w, ok


def build_data(source, api, repo, projects_dir="projects", watch_dir=None, now=None, commit=None, load_projects=None):
    """組成 data dict。source：collect 的來源（list_releases／fetch）；api：issues.Api（list_issues）。
    回 (data, sources_ok)；sources_ok 是 {"releases", "issues", "projects", "watch"} 各自有沒有讀到。"""
    collect, issues_mod = watchlib.load("collect"), watchlib.load("issues")
    now = now or datetime.datetime.now(datetime.timezone.utc)
    releases, ok_rel = gather_releases(collect, source, now)
    iss, state, ok_iss = gather_issues(issues_mod, api, repo)
    projects, ok_proj = gather_projects(projects_dir, load_projects, now)
    watch, ok_watch = gather_watch(watch_dir)
    watch["state_issue"] = state
    warnings = []
    run = watch.get("run")
    created = parse_time(run.get("created_at")) if run else None
    if run is None:
        warnings.append("GAP：沒有找到最近一輪監控資料（%s）" % (watch.get("run_gap") or "不明原因"))
    elif created is None:
        warnings.append("GAP：最近一輪監控的時間讀不出來")
    elif now - created > datetime.timedelta(hours=STALE_HOURS):
        warnings.append("GAP：監控資料超過 48 小時沒更新")
    if releases.get("skipped"):
        warnings.append("有 %d 個已發布的 Release 不合規則，沒有列入（見版本區塊最下方）" % len(releases["skipped"]))
    # 專案列：補上最新正式版、開發版、支援期限檢查結果、開著的監控 Issue 數
    sup_rows = {r[0]: r for r in (watch.get("support") or {}).get("rows", [])} if isinstance(watch.get("support"), dict) else {}
    open_titles = [i["title"] for k in ("kev", "support", "health") for i in iss.get(k, {}).get("rows", []) if i.get("state") == "open"]
    for p in projects.get("rows", []):
        mine = [r for r in releases.get("rows", []) if r["project"] == p["key"]]
        rel = [r for r in mine if r["kind"] == "release"]
        dev = [r for r in mine if r["kind"] == "dev"]
        p["latest_release"] = rel[0]["tag"] if rel else None          # rows 已經新的在前
        p["dev_release"] = dev[0]["tag"] if dev else None
        r = sup_rows.get(p["key"])
        p["support_check"] = {"status": r[1], "detail": r[2]} if r else None
        names = [p["key"]] + ([p["product_name"]] if p.get("product_name") else [])
        p["open_issues"] = sum(1 for t in open_titles if any(n in t for n in names)) if all(not iss.get(k, {}).get("gap") for k in ("kev", "support", "health")) else None
    oks = {"releases": ok_rel, "issues": ok_iss, "projects": ok_proj, "watch": ok_watch}
    commit = commit if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{7,64}", commit) else None
    data = {"schema": SCHEMA, "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "commit": commit, "repo": repo,
            "sources": {k: "OK" if v else "GAP" for k, v in oks.items()}, "warnings": warnings,
            "projects": projects, "releases": releases, "watch": watch, "issues": iss}
    return data, oks


# ---------------------------------------------------------------- 第 3 層：輸出

def write_site(data, out_dir, token=""):
    html_text = render.render(data)
    json_text = json.dumps(data, ensure_ascii=False, indent=1) + "\n"
    if token and (token in html_text or token in json_text):
        raise RuntimeError("輸出裡有 token，不寫檔")
    os.makedirs(out_dir, exist_ok=True)
    for name, text in (("index.html", html_text), ("data.json", json_text)):
        fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".part-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(out_dir, name))
    shutil.copyfile(os.path.join(HERE, "style.css"), os.path.join(out_dir, "style.css"))
    os.chmod(os.path.join(out_dir, "style.css"), 0o644)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write("用法錯誤：%s\n" % message)
        raise SystemExit(64)


def parse_args(argv, env):
    ap = _Parser(prog="build.py", description="產生儀表板 site/（docs/DASHBOARD.md）")
    ap.add_argument("--repo", required=True, help="owner/repo")
    ap.add_argument("--backend", choices=["github"], default="github", help="資料來源（GitLab 之後再做，docs/DASHBOARD.md 第 8 節）")
    ap.add_argument("--api", default=env.get("GITHUB_API_URL") or "https://api.github.com", help="API 網址（預設 $GITHUB_API_URL）")
    ap.add_argument("--watch-dir", dest="watch_dir", default=None)
    ap.add_argument("--projects-dir", dest="projects_dir", default="projects")
    ap.add_argument("--out", default="site")
    ap.add_argument("--now", default=None, help="UTC ISO 時間（測試用）")
    ap.add_argument("--commit", default=None)
    a = ap.parse_args(argv)
    if not render.valid_repo(a.repo):
        ap.error("--repo 格式要是 owner/repo")
    if a.now is not None and parse_time(a.now) is None:
        ap.error("--now 不是 ISO 時間")
    return a


def run(argv, env=None, source=None, api=None, load_projects=None):
    """source／api／load_projects 給測試注入；正式執行由 --repo／--api 與 GITHUB_TOKEN 建立。"""
    env = os.environ if env is None else env
    try:
        a = parse_args(argv, env)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 64
    token = (env.get("GITHUB_TOKEN") or "").strip()
    _SCRUB[0] = token

    def scrub(s):
        return str(s).replace(token, "***") if token else str(s)
    try:
        if source is None or api is None:
            collect, issues_mod = watchlib.load("collect"), watchlib.load("issues")
            if token and not collect.TOKEN_RE.match(token):
                raise ValueError("GITHUB_TOKEN 格式不合法")
            source = source or collect.GitHubSource(a.repo, a.api, token, collect.make_opener(), MAX_VEX)
            api = api or issues_mod.Api(base=a.api, token=token)
    except Exception as e:
        sys.stderr.write("用法錯誤：%s\n" % scrub(c(e, 200)))
        return 64
    now = parse_time(a.now) if a.now else datetime.datetime.now(datetime.timezone.utc)
    try:
        data, oks = build_data(source, api, a.repo, a.projects_dir, a.watch_dir, now, a.commit, load_projects)
    except Exception as e:
        sys.stdout.write("DASHBOARD\tFAIL\t%s\n" % scrub("未預期的錯誤（%s）" % type(e).__name__))
        return 1
    # 兩個 API 來源（releases、issues）都抓不到 → 不產生 site（避免用空頁蓋掉舊頁）。
    # 專案清單讀 checkout 的 projects/（在 CI 一定成功）、watch 缺時頁面寫 GAP，都不算（預驗必修 1）。
    if not oks["releases"] and not oks["issues"]:
        sys.stdout.write("DASHBOARD\tFAIL\tReleases API 與 Issues API 都抓不到：不產生 site，避免用空頁蓋掉舊頁\n")
        return 1
    try:
        write_site(data, a.out, token)
    except Exception as e:
        sys.stdout.write("DASHBOARD\tFAIL\t%s\n" % scrub("寫檔失敗（%s）" % type(e).__name__))
        return 1
    gaps = [k for k, v in oks.items() if not v]
    sys.stdout.write("DASHBOARD\tOK\t已產生 %s（Release %d、專案 %d%s）\n" % (
        os.path.basename(os.path.normpath(a.out)) or "site", len(data["releases"].get("rows", [])), len(data["projects"].get("rows", [])),
        "；GAP 的來源：" + "、".join(gaps) if gaps else ""))
    return 0


def main():
    try:
        rc = run(sys.argv[1:])
    finally:
        _SCRUB[0] = ""
    sys.exit(rc)


if __name__ == "__main__":
    main()
