#!/usr/bin/env python3
"""每日的支援期限與 EOL 檢查（M8 B2；docs/WATCH.md 第 7 節）。不連網，只讀 project.yml、Release 的 SBOM 與資料表。

  python3 -I pipeline/watch/support.py --projects-dir projects --out <資料夾> [--inventory <inventory.json>]
         [--table tools/cra/data/support-lifecycle.json] [--today YYYY-MM-DD] [--run-url URL] [--demo]

對 projects/ 裡每個 status 是 shipped／development 的專案：
1. 產品支援期限（project.yml 的 support_until，D-055 以它為準）：期限前 180／90／30 天各開一次提醒 Issue（只開當下最近的那一級），
   過了期限 → EOL（開一次 Issue；狀態 EOL，報告標 GAP「支援期已結束」）。沒填（development 才可能）→ NOT_ASSESSED。
2. 元件的維護期：每個 Release（collect.py 收集的 inventory，各層 SBOM 合併）用 tools/cra/support_check.py 比對資料表，
   元件比產品先停止維護、維護期沒有公開、或需要的訂閱沒設定 → ATTENTION，開一次 Issue。資料表沒有的版本 → NOT_ASSESSED（只寫報告）。
3. 我們自己的 OS（os_responsibility: ours）：project.yml 的 os.distro／os.release 當成 operating-system 元件比對；
   資料表沒有對應項目 → ATTENTION（開一次 Issue），不推估日期。
4. 資料表的查核日期超過 max_age_days（或在未來）→ 開一次提醒 Issue。

輸出 <out>/report.md、<out>/result.json；有要開的 Issue 時另有 <out>/plan.json（dumpling-watch-plan/1，stateless：
issues.py apply 不碰狀態 Issue，同一個 key 已經有 Issue（含已關閉）就不重複開）。
stdout 最後一行 `SUPPORT<TAB>狀態<TAB>說明`；結束碼 OK 0、ATTENTION／NOT_ASSESSED 2、FAIL 1、用法 64。
"""
import argparse
import datetime
import glob
import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
import match  # noqa: E402（md_text／md_code／md_title、unsafe_actions、mark_demo、load_inventory）
import publiccheck  # noqa: E402

TABLE = os.path.join(ROOT, "tools", "cra", "data", "support-lifecycle.json")
THRESHOLDS = (30, 90, 180)            # 天；只開當下最近的那一級（第一次跑時已經剩 20 天，不補開 180／90 天的）
ORDER = ("OK", "ATTENTION", "NOT_ASSESSED", "FAIL")     # 同 support_check.py
LABEL = "support-period"
ISSUE_VERDICTS = ("ends before the product support period", "end of maintenance not published",
                  "no maintenance phase applies (subscription not configured)")
VERDICT_TODO = {"ends before the product support period": "確認元件在產品支援期後段怎麼取得安全更新（換版本、付費維護並寫進 support.subscriptions、或縮短支援期並寫明依據）",
                "end of maintenance not published": "向廠商確認維護期（取得書面說明後更新資料表的 end 與來源），在那之前不能假設維護到產品支援期結束",
                "no maintenance phase applies (subscription not configured)": "確認有沒有買需要的維護（有的話寫進 config.json 的 support.subscriptions）"}
VERDICT_ZH = {"ends before the product support period": "比產品先停止維護",
              "end of maintenance not published": "維護期沒有公開",
              "no maintenance phase applies (subscription not configured)": "需要的訂閱沒有設定，沒有可算的維護期"}


class Fail(Exception):
    pass


def _support_check():
    spec = importlib.util.spec_from_file_location("support_check", os.path.join(ROOT, "tools", "cra", "support_check.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def key_of(*parts):
    return hashlib.sha256(("dumpling-support/1|real|" + "|".join(str(p) for p in parts)).encode("utf-8")).hexdigest()


def worst(sts):
    return max(list(sts) or ["OK"], key=ORDER.index)


def read_config(project_dir):
    """CRA/Config/config.json（為了 support.subscriptions）；讀不到就空的。load_project 已經核對過和 project.yml 一致。"""
    try:
        with open(os.path.join(project_dir, "CRA", "Config", "config.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except (OSError, ValueError):
        return {}


def check_config(cfg, support_until):
    """support_check 用的設定複本：support.end_date 由 project.yml 的 support_until 產生（D-055；跟精靈的做法一樣），訂閱照原設定。"""
    sup = dict(cfg.get("support") or {}) if isinstance(cfg.get("support"), dict) else {}
    if support_until:
        sup["end_date"] = support_until[:7]
    else:
        sup.pop("end_date", None)
    return {"support": sup}


def product_deadline(support_until, today):
    """→ (狀態, 剩幾天或 None, 門檻：'eol'｜30｜90｜180｜None)。support_until 是 YYYY-MM-DD 或 None（沒填）；當天仍在支援期內。"""
    if not support_until:
        return "NOT_ASSESSED", None, None
    days = (datetime.date.fromisoformat(support_until) - today).days
    if days < 0:
        return "EOL", days, "eol"
    for t in THRESHOLDS:
        if days <= t:
            return "OK", days, t
    return "OK", days, None


def load_projects(projects_dir):
    """→ [(專案名, 資料夾, project dict 或 None, 錯誤或 None)]。用 project_config.load_project（含一致性檢查）。"""
    import project_config as pc     # noqa: E402（需要 PyYAML）
    out = []
    for py in sorted(glob.glob(os.path.join(projects_dir, "*", "project.yml"))):
        d = os.path.dirname(py)
        name = os.path.basename(d)
        try:
            out.append((name, d, pc.load_project(d), None))
        except Exception as e:     # ConfigError 等：這個專案 FAIL，其他照做
            out.append((name, d, None, match._plain(str(e), 300)))
    return out


def release_boms(inventory):
    """inventory.json → {專案: [(watch_version, tag, 合併各層元件的 bom, 讀不到的層)]}。"""
    if not inventory:
        return {}, []
    _, projs, problems = match.load_inventory(inventory, os.path.dirname(os.path.abspath(inventory)))
    rel = {}
    for p in projs:
        rel.setdefault((p["name"], p["version"], p["tag"]), []).append(p)
    out = {}
    for (name, ver, tag), layers in sorted(rel.items()):
        comps, missing = [], []
        for p in layers:
            try:
                with open(p["sbom"], encoding="utf-8") as f:
                    bom = json.load(f)
                comps += bom.get("components") or [] if isinstance(bom, dict) else []
            except (OSError, ValueError):
                missing.append(p["layer"])
        out.setdefault(name, []).append((ver, tag, {"components": comps}, missing))
    return out, problems


def run(a):
    today = datetime.date.fromisoformat(a.today) if a.today else datetime.datetime.now(datetime.timezone.utc).date()
    sc = _support_check()
    try:
        table, table_sha = sc.load_table(a.table)
    except sc.TableError as e:
        raise Fail(f"資料表讀不到或格式不對：{e}")
    boms, inv_problems = release_boms(a.inventory)
    actions, rows, notes, sts = [], [], [], []
    seen_projects = set()

    def act(key, title, body, labels):
        actions.append({"op": "open", "key": key, "title": title, "body": body, "labels": [LABEL] + labels})

    run_line = [f"執行紀錄：{a.run_url}"] if a.run_url else []
    t = match.md_text            # 資料表與 project.yml 的值寫進 Issue 前一律淨化

    def check_one(name, d, proj):
        pname = proj.get("product_name") if proj.get("product_name") not in (None, "", "TO BE COMPLETED") else name
        su = proj.get("support_until")
        if isinstance(su, datetime.date):          # 沒加引號的 YAML 日期：project_config 接受，讀進來是 date（M8 預驗應修 2）
            su = su.isoformat()
        su = su if isinstance(su, str) and su not in ("", "TO BE COMPLETED") else None
        # 1. 產品支援期限
        st, days, thr = product_deadline(su, today)
        if st == "NOT_ASSESSED":
            sts.append("NOT_ASSESSED")
            rows.append((name, "NOT_ASSESSED", "support_until 還沒填（TO BE COMPLETED）：沒有產品支援期限，不檢查"))
        elif thr == "eol":
            sts.append("ATTENTION")
            rows.append((name, "EOL", f"支援期已結束（{su}，已過 {-days} 天）：報告的支援期一節標 GAP「支援期已結束」"))
            act(key_of(name, "eol", su), f"[支援期限][ATTENTION] {match.md_title(pname)}：支援期已結束（{su}）",
                "\n".join([f"**{t(pname)}**（專案 {match.md_code(name)}，{t(proj['status'])}）的支援期限 {su} 已經過了（{-days} 天）。", "",
                           "- 狀態：EOL。報告的支援期一節標 GAP「支援期已結束」。",
                           "- 要人處理：確認是否延長支援（改 project.yml 的 support_until，config.json 的 support.end_date 跟著改），"
                           "或依產品的支援政策公告停止支援。", "", *run_line]), ["attention"])
        else:
            rows.append((name, "OK", f"支援期限 {su}，剩 {days} 天" + (f"（{thr} 天提醒）" if thr else "")))
            if thr:
                act(key_of(name, f"due-{thr}", su), f"[支援期限] {match.md_title(pname)}：支援期 {su} 結束，剩 {days} 天（{thr} 天提醒）",
                    "\n".join([f"**{t(pname)}**（專案 {match.md_code(name)}，{t(proj['status'])}）的支援期限是 {su}，剩 {days} 天。", "",
                               f"- 提醒：期限前 {'／'.join(str(x) for x in reversed(THRESHOLDS))} 天各開一次（這是 {thr} 天的那一次）。",
                               "- 要人處理：確認是否延長支援，或準備停止支援的公告。", "", *run_line]), [])
        cfg = check_config(read_config(d), su)
        pend = cfg["support"].get("end_date")
        # 2. 元件的維護期：每個 Release 都比，同一個元件問題在同一個專案只開一個 Issue（列出受影響的版本；新版本有同樣問題不重開）
        rels = boms.get(name, [])
        if not rels:
            notes.append(f"{name}：沒有可讀的 Release SBOM（每日監控收集到的），元件的維護期沒有比對")
        groups = {}
        for ver, tag, bom, missing in rels:
            if missing:
                sts.append("NOT_ASSESSED")
                rows.append((f"{name}@{ver}", "NOT_ASSESSED", f"SBOM 讀不到（{'、'.join(missing)} 層）"))
            res = sc.check(bom, cfg, table, table_sha, today)
            sts.append(res["status"])
            rows.append((f"{name}@{ver}", res["status"], "；".join(res["reasons"]) or "元件都維護到產品支援期結束或更晚"))
            for x in res["entries"]:
                if not x["informational"] and x["verdict"] in ISSUE_VERDICTS:
                    g = groups.setdefault((x["id"], x["verdict"], x["end"]), {"x": x, "rels": []})
                    g["rels"].append((ver, tag, x["matched"]))
        for (eid, verdict, end), g in sorted(groups.items(), key=lambda kv: kv[0][0]):
            x, vz = g["x"], VERDICT_ZH[verdict]
            act(key_of(name, "component", eid, verdict, end, pend),
                f"[支援期限][ATTENTION] {match.md_title(pname)}：{match.md_title(x['name'])} {vz}",
                "\n".join([f"**{t(pname)}**（專案 {match.md_code(name)}）的 **{t(x['name'])}**：{vz}。", "",
                           f"- 產品支援期限：{t(pend or '—')}（project.yml 的 support_until）",
                           f"- 元件的維護期：{t(x['end'] or '沒有公開') + '（' + t(x['phase']) + '）' if x['phase'] else '—'}",
                           "- 受影響的 Release（這次比對到的）：",
                           *[f"  - {match.md_code(tag)}：{'、'.join(match.md_code(m) for m in matched)}" for _, tag, matched in g["rels"][:20]],
                           f"- 資料表來源（查核 {t(x['checked'])}）：{'；'.join(match.md_code(u) for u in x['sources'])}",
                           *([f"- 涵蓋範圍：{t(x['coverage'])}"] if x.get("coverage") else []),
                           f"- 要人處理：{VERDICT_TODO[verdict]}。", "", *run_line]), ["attention"])
        # 3. 我們自己的 OS
        if proj.get("os_responsibility") == "ours":
            os_ = proj.get("os") if isinstance(proj.get("os"), dict) else {}
            dist, rel = os_.get("distro"), os_.get("release")
            if dist in (None, "", "TO BE COMPLETED") or rel in (None, "", "TO BE COMPLETED"):
                sts.append("NOT_ASSESSED")
                rows.append((f"{name}（OS）", "NOT_ASSESSED", "os.distro／os.release 還沒填"))
                return
            res = sc.check({"components": [{"type": "operating-system", "name": dist, "version": str(rel)}]}, cfg, table, table_sha, today)
            hit = [x for x in res["entries"] if not x["informational"]]
            if not hit:
                sts.append("ATTENTION")
                rows.append((f"{name}（OS）", "ATTENTION", f"{dist} {rel} 不在資料表：維護期不明（不推估）"))
                act(key_of(name, "os-missing", dist, rel), f"[支援期限][ATTENTION] {match.md_title(pname)}：OS {match.md_title(dist)} {match.md_title(rel)} 不在資料表",
                    "\n".join([f"**{t(pname)}** 的 OS（project.yml 的 os：{match.md_code(dist)} {match.md_code(rel)}）不在 "
                               f"{match.md_code('tools/cra/data/support-lifecycle.json')}，維護期不明。工具不推估日期。", "",
                               "- 要人處理：在資料表加這個版本（附來源網址與查核日期；沒有公開資料就寫 null）。", "", *run_line]), ["attention"])
                return
            sts.append(res["status"])
            rows.append((f"{name}（OS）", res["status"], "；".join(res["reasons"]) or "OS 維護到產品支援期結束或更晚"))
            for x in hit:
                if x["verdict"] in ISSUE_VERDICTS:
                    vz = VERDICT_ZH[x["verdict"]]
                    act(key_of(name, "os", x["id"], x["verdict"], x["end"], pend),
                        f"[支援期限][ATTENTION] {match.md_title(pname)}：OS {match.md_title(x['name'])} {vz}",
                        "\n".join([f"**{t(pname)}** 的 OS {match.md_code(dist)} {match.md_code(rel)}（{t(x['name'])}）：{vz}。", "",
                                   f"- 產品支援期限：{t(pend or '—')}；OS 的維護期：{t(x['end'] or '沒有公開')}",
                                   f"- 資料表來源（查核 {t(x['checked'])}）：{'；'.join(match.md_code(u) for u in x['sources'])}",
                                   f"- 要人處理：{VERDICT_TODO[x['verdict']]}。", "", *run_line]), ["attention"])

    for name, d, proj, err in load_projects(a.projects_dir):
        seen_projects.add(name)
        if err:
            sts.append("FAIL")
            rows.append((name, "FAIL", f"project.yml 不合格：{err}"))
            continue
        if proj.get("status") not in ("shipped", "development"):
            continue
        n_act = len(actions)
        try:
            check_one(name, d, proj)
        except Exception as e:     # 一個專案出錯不擋其他專案；這個專案記 FAIL，它這次的 Issue 動作不送出
            del actions[n_act:]
            sts.append("FAIL")
            rows.append((name, "FAIL", f"檢查時出錯：{type(e).__name__}: {match._plain(str(e), 200)}"))
    for name in sorted(set(boms) - seen_projects):
        notes.append(f"{name}：有 Release 但 projects/ 裡沒有這個專案，沒有支援期限可比")
    notes += [f"Release 問題（每日監控另外處理）：{x}" for x in inv_problems[:10]]
    # 4. 資料表的查核日期：過期（或在未來）的項目併成一個 Issue；key 含這些項目與查核日期，之後又有項目過期才會再開
    stale = []
    for e in table["entries"]:
        age = (today - datetime.date.fromisoformat(e["checked"])).days
        why = (f"查核日期 {e['checked']} 已經超過 {table['max_age_days']} 天" if age > table["max_age_days"] else
               f"查核日期 {e['checked']} 在未來（多半是打錯）" if age < 0 else None)
        if why:
            stale.append((e, why))
            rows.append((f"資料表 {e['id']}", "ATTENTION", why))
    if stale:
        sts.append("ATTENTION")
        act(key_of("table", *sorted(f"{e['id']}@{e['checked']}" for e, _ in stale)),
            f"[支援期限] 資料表有 {len(stale)} 筆要重新查核",
            "\n".join([f"{match.md_code('tools/cra/data/support-lifecycle.json')} 有 {len(stale)} 筆的查核日期過期或不合理：", "",
                       *[f"- **{match.md_text(e['name'])}**（{match.md_code(e['id'])}）：{match.md_text(why)}；來源 {'；'.join(match.md_code(u) for u in e['sources'])}"
                         for e, why in stale],
                       "", "- 要人處理：重新查核來源，更新 end 與 checked（沒有公開資料就寫 null）。", "", *run_line]), [])
    status = worst(sts)
    return status, actions, rows, notes, today, table_sha


def render_report(status, rows, notes, actions, today, table_sha):
    L = [f"# 支援期限與 EOL 檢查：{status}", "", f"日期 {today.isoformat()}；資料表 SHA-256 {table_sha[:12]}", "",
         "| 對象 | 結果 | 說明 |", "|---|---|---|"]
    L += [f"| {match.md_code(a)} | {b} | {match.md_text(c, 500)} |" for a, b, c in rows]
    if notes:
        L += ["", "說明：", *[f"- {match.md_text(n, 400)}" for n in notes]]
    L += ["", f"要開的 Issue（已經有的不重複開）：{len(actions)}", *[f"- {x['title']}" for x in actions]]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="每日的支援期限與 EOL 檢查")
    ap.add_argument("--projects-dir", default=os.path.join(ROOT, "projects"))
    ap.add_argument("--inventory")
    ap.add_argument("--table", default=TABLE)
    ap.add_argument("--today")
    ap.add_argument("--out", required=True)
    ap.add_argument("--run-url")
    ap.add_argument("--demo", action="store_true", help="公開 repo：Issue 標明示範專案、加 demo 標籤（D-040）")
    try:
        a = ap.parse_args(argv)
        if a.today:
            datetime.date.fromisoformat(a.today)
    except (SystemExit, ValueError):
        print("SUPPORT\tFAIL\t參數錯誤")
        return 64
    os.makedirs(a.out, exist_ok=True)
    for n in ("plan.json", "result.json", "report.md"):
        try:
            os.remove(os.path.join(a.out, n))
        except FileNotFoundError:
            pass
    try:
        status, actions, rows, notes, today, table_sha = run(a)
        if a.demo:
            match.mark_demo(actions)
        probs = [x for act in actions for x in publiccheck.check_text(act["title"] + "\n" + act["body"])]
        if probs:
            raise Fail(f"要寫進公開 Issue 的內容沒過公開檢查（{probs[0]}）")
        bad = match.unsafe_actions(actions)
        if bad:
            raise Fail(f"要寫進公開 Issue 的內容有沒淨化的 Markdown（例如 {bad[0]!r}）")
    except Exception as e:      # Fail 以外的例外也要留下 result.json 與一行結果（不讓 traceback 吞掉輸出）
        e = e if isinstance(e, (Fail, match.Fail)) else f"{type(e).__name__}: {match._plain(str(e), 300)}"
        print(f"SUPPORT\tFAIL\t{e}")
        with open(os.path.join(a.out, "result.json"), "w", encoding="utf-8") as f:
            json.dump({"status": "FAIL", "detail": str(e)}, f, ensure_ascii=False, indent=1)
        return 1
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
        f.write(render_report(status, rows, notes, actions, today, table_sha))
    detail = f"{len(rows)} 項；要開的 Issue {len(actions)}"
    with open(os.path.join(a.out, "result.json"), "w", encoding="utf-8") as f:
        json.dump({"status": status, "detail": detail, "today": today.isoformat(), "rows": [list(r) for r in rows], "notes": notes,
                   "issues": [{"key": x["key"], "title": x["title"]} for x in actions]}, f, ensure_ascii=False, indent=1)
    if actions:
        plan = {"schema": "dumpling-watch-plan/1", "mode": "real", "stateless": True, "generated_at": today.isoformat(),
                "run_url": a.run_url, "state_base": None, "state": None, "actions": actions, "status": status, "detail": detail}
        with open(os.path.join(a.out, "plan.json"), "w", encoding="utf-8") as f:
            json.dump(plan, f, ensure_ascii=False, indent=1)
    print(f"SUPPORT\t{status}\t{detail}")
    return {"OK": 0, "FAIL": 1}.get(status, 2)


if __name__ == "__main__":
    sys.exit(main())
