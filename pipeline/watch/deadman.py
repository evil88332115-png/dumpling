#!/usr/bin/env python3
"""deadman.py：每日監控的「沒結果就告警」（死人開關，GITLAB-PORT T-12、第 8 節）。只做偵測與開 Issue；寄信等 T-08（還沒做）。

用法：
  python3 -I pipeline/watch/deadman.py (--repo O/R | --backend gitlab --gitlab-url <…/api/v4> --project <數字 ID>)
         --out <資料夾> [--max-age-hours 36] [--mode real|drill] [--schedules] [--now YYYY-MM-DDTHH:MM:SSZ]
  token 從環境變數讀（不收 argv）：GitLab 是 GITLAB_TOKEN，GitHub 是 GH_TOKEN／GITHUB_TOKEN（同 issues.py）。HTTP 一律走 issues.py 的 Api／GitLabApi。
  GitHub 版另有 keepalive 防排程停用，GitHub 後端只用在測試與演練；--schedules 只在 GitLab 後端（排程 API 是 GitLab 的）。

檢查 1（一律做）：狀態 Issue 的新舊。issues.find_state_issue 找狀態 Issue、decode_state 解開；
  最後更新時間＝state 的 runs 最後一筆的 at（match.py 每輪 append {at, status, run_url, mode, detail}，格式 YYYY-MM-DDTHH:MM:SSZ）；
  state 沒有 runs（或是空的）才退回 Issue 的 updated_at；runs 最後一筆有、但 at 讀不出來 → 不退回（資料壞了，不掩蓋）、ALERT。
  現在減最後更新時間「超過」--max-age-hours（預設 36，和儀表板 pipeline/dashboard/build.py 的 STALE_HOURS 一致，測試鎖住）才 ALERT；剛好等於不算。
  找不到狀態 Issue、解不開、時間讀不出來（或在未來超過 1 小時）也是 ALERT，各自寫明原因。API 失敗是 FAIL。
檢查 2（只有 GitLab 後端而且有 --schedules）：GET /projects/:id/pipeline_schedules 列出全部排程，再對每一個 GET …/pipeline_schedules/:id 取 variables
  （variables 只在單筆回應，而且只給 Maintainer、Owner 或排程擁有者看），挑出 variables 有 DUMPLING_JOB=watch 的排程。ALERT 的情況：
  一個都沒有；active 是 false；owner.state 不是 active；next_run_at 已經過了超過 --max-age-hours（排程卡住）。
  單筆回應拿不到 variables（HTTP 403／404，或回應沒有 variables 欄位）→ GAP「token 角色不夠，看不到排程的 variables」，算 ALERT 並寫明，不當成「沒有排程」。
  官方依據（2026-11-15 C3 讀過）：docs.gitlab.com/api/pipeline_schedules/；官方頁沒寫最低角色，待內部驗證（GITLAB-PORT T-12）。

輸出：stdout 一行 WATCH-DEADMAN<TAB>OK|ALERT|FAIL<TAB>說明；結束碼 OK 0、ALERT 2、FAIL 1、用法 64。
  <out>/result.json 一定寫：{status, checks:[{name,status,detail}], last_update, age_hours, max_age_hours, schedules:[摘要，不含 variables 的值], …}。
  有要開的 Issue 或要留的「已恢復」留言時另寫 <out>/plan.json（dumpling-watch-plan/1，stateless、stateless_kind=deadman；交給 issues.py apply）。

Issue 與恢復：
  - 每一個「停擺」一個 key＝sha256("dumpling-watch/1|<mode>|deadman|<停擺的識別>")（同 match.issue_key 的算法，這裡自己實作、不 import match 的函式；測試核對兩邊相同）。
    停擺的識別：狀態停擺＝state-stale:<最後更新時間>；其他狀態問題＝state:missing／state:undecodable／state:no-time；
    排程＝schedule:<id>:<inactive|owner-not-active|next-run-stale|next-run-unreadable>、schedule:none:missing、schedule:all:gap。
    同一次停擺（最後更新時間沒變）每天都是同一個 key，issues.py apply 看到已有 Issue（含已關閉）就不重複開；恢復後又停（最後更新時間變了）→ 新的 key → 新的 Issue。
  - 恢復：狀態或排程恢復時，在「那一次停擺的 Issue」留言「已恢復，時間 …」，不自動關閉（由人關）。deadman 先列出開著、帶 watch-deadman 標籤的 Issue，
    從標記解出 key，Issue 內文第二行的範圍標記（<!-- dumpling-deadman-scope … -->）說明它屬於哪個檢查；該範圍這輪有檢查、而且沒有任何警告 → 恢復。
    只對開著的 Issue 留言（issues.py apply 對已關閉的跳過、不重開）。同一次停擺只留一則：留言的第一行是機器標記
    <!-- dumpling-deadman-recovered key=<64 hex> -->，下一輪看到可信作者寫的這則就跳過。
    標記放在留言（不用標籤）的理由：標籤 Reporter／Planner 就能改，留言有作者可以核對；留言的作者要可信（art14.Trust：GitLab 要是專案成員、等級 >= Developer（30），
    GitHub 要是 OWNER／MEMBER／COLLABORATOR 或 github-actions[bot]；system 留言不算），不然別人貼一則偽造的標記就能讓真的恢復通知永遠不出現。
  - 外來字串（排程 description、owner username、ref、cron…）寫進 Issue 前一律用 match.md_text 淨化（標題用 match.md_title）。理由：md_text ＝ firmware_mdsafe.md_safe
    （跳脫 Markdown、@ 提及、自動連結、HTML 實體）再加上 Issue 參照（#123、GH-123）斷開，後者在 Issue 內文才需要，所以選 match.md_text 而不是裸的 md_safe。
    淨化結果是單行，所以不會產生以 / 開頭的行（GitLab quick action）；issues.py apply 另有 quick action 與公開檢查。公開檢查命中外來字串時（例如描述裡有信箱），
    改用不含外來字串的內文，警告不能因此開不出來。
標籤：watch-health、watch-deadman；--mode drill 另加 drill。Token 不進任何輸出（stdout、result.json、plan.json 都會把 token 字樣換成 ***）。
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import issues  # noqa: E402  後端（Api／GitLabApi）、狀態 Issue、標記
import art14  # noqa: E402  只用 Trust（誰寫的留言可信）
import match  # noqa: E402  只用 md_text／md_title／unsafe_actions（淨化與最後一道檢查）
import publiccheck  # noqa: E402

DEFAULT_MAX_AGE_HOURS = 36           # 和 pipeline/dashboard/build.py 的 STALE_HOURS 一致（test_deadman 鎖住）
FUTURE_SLACK = datetime.timedelta(hours=1)      # 最後更新時間比現在晚超過這麼多＝壞資料（否則一個未來的時間會讓死人開關永遠不響）
KEY_PREFIX = "dumpling-watch/1"      # 同 match.KEY_PREFIX；key 的算法同 match.issue_key（不 import，測試核對）
LABELS = ["watch-health", issues.DEADMAN_LABEL]
SCOPE_RE = re.compile(r"<!-- dumpling-deadman-scope (state|schedule:[0-9]+|schedule:none|schedule:all) -->")
RECOVERED_RE = re.compile(r"<!-- dumpling-deadman-recovered key=([0-9a-f]{64}) -->")
TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})$")
GAP_WHY = "token 角色不夠，看不到排程的 variables"
SCHEDULE_PROBLEM_ZH = {"inactive": "已停用（Inactive）", "owner-not-active": "擁有者不是 active（被封鎖或移出專案）",
                       "next-run-stale": "next_run_at 已經過期（排程卡住）", "next-run-unreadable": "next_run_at 讀不出來"}
TODO = ["到 Build > Pipeline schedules 看每日監控的排程（變數 DUMPLING_JOB=watch）是不是 **Inactive**；是的話，Maintainer 或 Owner 按 **Take ownership** 接手，"
        "並確認原擁有者沒被封鎖或移出專案（排程用擁有者的權限執行）。",
        "看最近一次 `watch:compute` 的 artifact（`watch-out/result.json`、`report.md`）與 job log，找出為什麼狀態 Issue 沒有更新。",
        "排除之後，狀態 Issue 更新、排程恢復正常時，下一輪 deadman 會在這個 Issue 留言「已恢復」；Issue 不會自動關閉，請人確認後關閉。"]


class Fail(Exception):
    pass


class Usage(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Usage("參數不認得、缺少或格式不對")      # argparse 的訊息會原樣回顯參數的值（例如誤把 token 放進 argv），所以不轉述


# ---------- 小工具 ----------
def key_of(mode, ident):
    """同 match.issue_key(mode, "deadman", ident)：sha256("dumpling-watch/1|<mode>|deadman|<ident>")。"""
    return hashlib.sha256("|".join((KEY_PREFIX, mode, "deadman", ident)).encode("utf-8")).hexdigest()


def parse_ts(s):
    """ISO 8601（有時區：Z 或 ±hh:mm，可有小數秒）→ UTC aware datetime；讀不出來回傳 None。"""
    if not isinstance(s, str):
        return None
    m = TS_RE.match(s.strip())
    if not m:
        return None
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    try:
        t = datetime.datetime(y, mo, d, h, mi, se, tzinfo=datetime.timezone.utc)
        z = m.group(8)
        if z != "Z":
            sign = 1 if z[0] == "+" else -1
            digits = z[1:].replace(":", "")
            t -= sign * datetime.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        return t
    except (ValueError, OverflowError):
        return None


def fmt(t):
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_now(s):
    if not s:
        return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", s):
        raise Usage("--now 必須是 UTC ISO 8601（YYYY-MM-DDTHH:MM:SSZ）")
    t = parse_ts(s)
    if t is None:
        raise Usage("--now 不是合法的時間")
    return t


def num(h):
    return str(int(h)) if float(h) == int(h) else str(h)


def plain(x, limit=120):
    """result.json 用：去控制字元、壓空白、截短（不跳脫 Markdown：這不是 Markdown）。"""
    return " ".join(re.sub(r"[\x00-\x1f\x7f-\x9f  ​-‏‪-‮]", " ", str(x if x is not None else "")).split())[:limit]


# ---------- 檢查 1：狀態 Issue ----------
def check_state(api, target, mode, now, max_age_h):
    """→ (check dict, alerts, info)；API 失敗（issues.Fail）由呼叫端處理成 FAIL。"""
    info = {"last_update": None, "age_hours": None}
    max_age = datetime.timedelta(hours=max_age_h)

    def alert(ident, title, why, status_detail):
        return ({"name": "state", "status": "ALERT", "detail": status_detail},
                [{"scope": "state", "ident": ident, "title": title, "why": why}], info)
    si = issues.find_state_issue(api, target, mode)
    if si is None:
        return alert("state:missing", "[監控健康] 找不到每日監控的狀態 Issue",
                     "找不到狀態 Issue（標籤 watch-state%s）：每日監控從來沒有建立基準，或狀態 Issue 被刪／被拿掉標籤" % ("" if mode == "real" else "-drill"),
                     "找不到狀態 Issue")
    try:
        state = issues.decode_state(si.get("body"), mode)
    except issues.Fail as e:
        return alert("state:undecodable", "[監控健康] 每日監控的狀態 Issue 解不開",
                     f"狀態 Issue（編號 {si.get('number')}）解不開：{e}", f"狀態 Issue（編號 {si.get('number')}）解不開")
    runs = state.get("runs")
    src = None
    if isinstance(runs, list) and runs:
        last = runs[-1]
        at = last.get("at") if isinstance(last, dict) else None
        t = parse_ts(at) if isinstance(at, str) and at.endswith("Z") else None
        src = "runs 最後一筆的 at"
        if t is None:
            return alert("state:no-time", "[監控健康] 每日監控的狀態讀不出最後更新時間",
                         "狀態的 runs 最後一筆沒有合法的 at（YYYY-MM-DDTHH:MM:SSZ）：資料可能壞了", "runs 最後一筆的時間讀不出來")
    else:
        t = parse_ts(si.get("updated_at"))
        src = "Issue 的 updated_at（狀態沒有 runs）"
        if t is None:
            return alert("state:no-time", "[監控健康] 每日監控的狀態讀不出最後更新時間",
                         "狀態沒有 runs，Issue 的 updated_at 也讀不出來", "沒有 runs，updated_at 也讀不出來")
    info["last_update"] = fmt(t)
    age = now - t
    info["age_hours"] = round(age.total_seconds() / 3600, 2)
    if age < -FUTURE_SLACK:
        return alert("state:no-time", "[監控健康] 每日監控的狀態讀不出最後更新時間",
                     f"最後更新時間 {fmt(t)} 比現在（{fmt(now)}）晚超過 1 小時：資料或時鐘有問題", f"最後更新時間在未來（{fmt(t)}）")
    if age > max_age:
        return alert(f"state-stale:{fmt(t)}",
                     f"[監控健康] 每日監控超過 {num(max_age_h)} 小時沒有結果（最後一次 {match.md_title(fmt(t))}）",
                     f"最後更新時間 {fmt(t)}（{src}），已經 {info['age_hours']} 小時，超過門檻 {num(max_age_h)} 小時",
                     f"最後更新 {fmt(t)}，已 {info['age_hours']} 小時，超過 {num(max_age_h)} 小時")
    return ({"name": "state", "status": "OK", "detail": f"最後更新 {fmt(t)}（{src}），{info['age_hours']} 小時前，門檻 {num(max_age_h)} 小時"}, [], info)


# ---------- 檢查 2：GitLab pipeline schedules ----------
def check_schedules(api, project, now, max_age_h):
    """→ (check dict, alerts, summaries, watch_ids, had_gap)。"""
    max_age = datetime.timedelta(hours=max_age_h)
    rows = api.get_all(f"/projects/{project}/pipeline_schedules?per_page=100")
    summaries, alerts, watch_ids, gaps = [], [], [], []
    for row in rows:
        sid = row.get("id") if isinstance(row, dict) else None
        if type(sid) is not int:
            raise issues.Fail("排程列表的項目沒有整數 id")
        try:
            one, _ = api.request("GET", f"/projects/{project}/pipeline_schedules/{sid}")
        except issues.Fail as e:
            if getattr(e, "status", None) in (403, 404):
                one = None       # 看不到單筆（權限不夠）：GAP，不是 FAIL
            else:
                raise
        sm = {"id": sid, "description": plain(row.get("description"), 80), "ref": plain(row.get("ref"), 60), "cron": plain(row.get("cron"), 40),
              "active": row.get("active"), "next_run_at": plain(row.get("next_run_at"), 40),
              "owner": plain((row.get("owner") or {}).get("username") if isinstance(row.get("owner"), dict) else None, 40),
              "owner_state": plain((row.get("owner") or {}).get("state") if isinstance(row.get("owner"), dict) else None, 20),
              "variables_visible": False, "watch": None}
        summaries.append(sm)
        vs = one.get("variables") if isinstance(one, dict) else None
        if not isinstance(vs, list):
            gaps.append(sid)
            continue
        sm["variables_visible"] = True
        sm["watch"] = any(isinstance(v, dict) and v.get("key") == "DUMPLING_JOB" and str(v.get("value")) == "watch" for v in vs)
        if not sm["watch"]:
            continue
        watch_ids.append(sid)
        lp = one.get("last_pipeline") if isinstance(one.get("last_pipeline"), dict) else {}
        sm["last_pipeline_status"] = plain(lp.get("status"), 20)
        owner = row.get("owner") if isinstance(row.get("owner"), dict) else {}
        probs = []
        if row.get("active") is not True:
            probs.append("inactive")
        if owner.get("state") != "active":
            probs.append("owner-not-active")
        if row.get("active") is True:      # 停用的排程 next_run_at 本來就可能是空的或舊的：已經報 inactive，不重複
            nr = parse_ts(row.get("next_run_at"))
            if nr is None:
                probs.append("next-run-unreadable")
            elif now - nr > max_age:
                probs.append("next-run-stale")
        for p in probs:
            alerts.append({"scope": f"schedule:{sid}", "ident": f"schedule:{sid}:{p}", "kind": p, "sid": sid,
                           "title": f"[監控健康] 每日監控的排程 ID {sid} {SCHEDULE_PROBLEM_ZH[p]}",
                           "why": f"排程 ID {sid}：{SCHEDULE_PROBLEM_ZH[p]}", "row": row})
    if gaps:
        alerts.append({"scope": "schedule:all", "ident": "schedule:all:gap", "kind": "gap", "sid": None,
                       "title": "[監控健康] 看不到排程的 variables（token 角色不夠），無法確認每日監控的排程",
                       "why": f"GAP：{GAP_WHY}（排程 {sorted(gaps)}）；不能把它當成「沒有排程」，每日監控的排程狀態沒有被檢查", "row": None})
    elif not watch_ids:
        alerts.append({"scope": "schedule:none", "ident": "schedule:none:missing", "kind": "missing", "sid": None,
                       "title": "[監控健康] 找不到每日監控的 pipeline 排程（DUMPLING_JOB=watch）",
                       "why": f"專案有 {len(rows)} 個排程，沒有一個的 variables 有 DUMPLING_JOB=watch"
                              "（token 的角色看不到 variables 時，也可能表現成空的 variables：待內部驗證）", "row": None})
    status = "ALERT" if alerts else "OK"
    if gaps:
        detail = f"GAP：{GAP_WHY}（{len(gaps)} 個排程）；" + (f"另有 {len(alerts) - 1} 個排程問題" if len(alerts) > 1 else "沒有其他問題")
    elif alerts:
        detail = f"{len(watch_ids)} 個 watch 排程；" + "；".join(a["why"] for a in alerts)
    else:
        detail = f"{len(watch_ids)} 個 watch 排程（共 {len(rows)} 個排程）：active、擁有者 active、next_run_at 沒有過期"
    return {"name": "schedules", "status": status, "detail": detail}, alerts, summaries, watch_ids, bool(gaps)


# ---------- Issue 內文 ----------
def md(x, limit=200):
    return match.md_text(x, limit)


def build_body(a, checks, info, now, max_age_h, summaries, foreign):
    """foreign＝False 時不放排程的 description／owner／ref／cron（公開檢查命中外來字串時的後備內文）。"""
    t = md
    lines = [f"<!-- dumpling-deadman-scope {a['scope']} -->", "",
             "**每日監控的死人開關**（`deadman.py`）發出警告：", "", f"- 本次問題：{t(a['why'], 400)}", "- 檢查結果："]
    lines += [f"  - {t(c['name'])}：**{t(c['status'])}**（{t(c['detail'], 400)}）" for c in checks]
    lines += [f"- 狀態最後更新時間：{t(info['last_update'] or '讀不到')}；檢查時間：{t(fmt(now))}；門檻：{t(num(max_age_h))} 小時"]
    if summaries:
        lines.append("- 排程摘要（variables 的值不列）：")
        for s in summaries[:30]:
            tag = "watch" if s["watch"] else ("無法確認（看不到 variables）" if not s["variables_visible"] else "非 watch")
            extra = f"；說明 {t(s['description'], 80)}；ref {t(s['ref'], 60)}；cron {t(s['cron'], 40)}；擁有者 {t(s['owner'], 40)}" if foreign else ""
            lines.append(f"  - 排程 ID {s['id']}（{t(tag)}）：active={t(s['active'])}；擁有者狀態 {t(s['owner_state'], 20)}；next_run_at {t(s['next_run_at'] or '無', 40)}{extra}")
    lines += ["", "要人做的事：", *[f"{n}. {x}" for n, x in enumerate(TODO, 1)],
              "", "寄信提醒還沒做（T-08）：現在只靠這個 Issue 與 job 的狀態，沒有 email。"]
    return "\n".join(lines) + "\n"


def recovered_body(key, scope_desc, now):
    return "\n".join([f"<!-- dumpling-deadman-recovered key={key} -->",
                      f"已恢復，時間 {md(fmt(now))}。{md(scope_desc, 300)}", "",
                      "這個 Issue 不會自動關閉，請人確認後關閉。"]) + "\n"


# ---------- 恢復 ----------
def find_recoveries(api, target, mode, now, alerts, evaluated, info, recover_desc):
    """列出開著的 deadman Issue，找出已恢復、而且還沒有可信的「已恢復」留言的 → [(key, issue 編號, 說明)]。"""
    cur_scopes = {a["scope"] for a in alerts}
    trust = art14.Trust(api, target)
    out = []
    for i in issues.list_issues(api, target, issues.DEADMAN_LABEL, "open"):
        mk = issues.parse_marker(i.get("body"), issues.DEADMAN_MARK_RE)
        if not mk or mk[1] != mode:
            continue
        lines = (i.get("body") or "").splitlines()
        sm = SCOPE_RE.fullmatch(lines[1]) if len(lines) > 1 else None
        if not sm:
            continue             # 沒有範圍標記：不知道它屬於哪個檢查，不亂說「已恢復」
        scope = sm.group(1)
        if scope not in evaluated or scope in cur_scopes:
            continue
        notes = api.list_notes(target, i["number"])
        done = False
        for n in notes:
            first = (n.get("body") or "").splitlines()[:1]
            rm = RECOVERED_RE.fullmatch(first[0]) if first else None
            if rm and rm.group(1) == mk[0] and not n.get("system") and trust.ok(n):
                done = True
                break
        if not done:
            out.append((mk[0], i["number"], recover_desc(scope)))
    return out


# ---------- 組裝 ----------
def run(args, api, target, now):
    checks, alerts, summaries, info = [], [], [], {"last_update": None, "age_hours": None}
    evaluated, watch_ids, had_gap = set(), [], False
    failed = False
    try:
        c, al, info = check_state(api, target, args.mode, now, args.max_age_hours)
        checks.append(c)
        alerts += al
        evaluated.add("state")
    except issues.Fail as e:
        checks.append({"name": "state", "status": "FAIL", "detail": f"API 失敗：{e}"})
        failed = True
    if args.schedules:
        try:
            c, al, summaries, watch_ids, had_gap = check_schedules(api, target, now, args.max_age_hours)
            checks.append(c)
            alerts += al
            evaluated.add("schedule:all")
            if not had_gap:
                evaluated.add("schedule:none")
            evaluated.update(f"schedule:{s}" for s in watch_ids)
        except issues.Fail as e:
            checks.append({"name": "schedules", "status": "FAIL", "detail": f"API 失敗：{e}"})
            failed = True

    def recover_desc(scope):
        if scope == "state":
            return f"每日監控的狀態恢復更新，恢復後的最後更新時間：{info['last_update']}。"
        if scope == "schedule:none":
            return f"現在找得到 DUMPLING_JOB=watch 的排程（{len(watch_ids)} 個）。"
        if scope == "schedule:all":
            return "現在看得到排程的 variables 了。"
        return f"排程 {scope.split(':')[1]} 恢復正常（active、擁有者 active、next_run_at 沒有過期）。"
    recoveries = []
    try:
        recoveries = find_recoveries(api, target, args.mode, now, alerts, evaluated, info, recover_desc)
    except issues.Fail as e:
        checks.append({"name": "recovery", "status": "FAIL", "detail": f"列出舊的 deadman Issue 或留言失敗：{e}（這一輪不留恢復通知；警告照常）"})
        failed = True

    # 主要檢查失敗＝FAIL（沒辦法判斷）；只有「恢復查詢」失敗時，已經確定的警告照報（ALERT），沒有警告才 FAIL
    main_fail = any(c["status"] == "FAIL" for c in checks if c["name"] != "recovery")
    status = "FAIL" if main_fail else ("ALERT" if alerts else ("FAIL" if failed else "OK"))
    return status, checks, alerts, summaries, info, recoveries


def build_actions(args, alerts, checks, info, now, summaries, recoveries):
    actions = []
    drill = ["drill"] if args.mode == "drill" else []
    rules = publiccheck.load_rules()
    for a in alerts:
        title = a["title"]
        body = build_body(a, checks, info, now, args.max_age_hours, summaries, True)
        if publiccheck.check_text(title + "\n" + body, rules):
            body = build_body(a, checks, info, now, args.max_age_hours, summaries, False)      # 外來字串命中公開檢查：換成不含外來字串的內文
        actions.append({"op": "open", "key": key_of(args.mode, a["ident"]), "title": title, "body": body, "labels": LABELS + drill})
    for key, number, desc in recoveries:
        actions.append({"op": "comment", "key": key, "body": recovered_body(key, desc, now)})
    return actions


def write_json(path, obj, token):
    s = json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True)
    if token:
        s = s.replace(token, "***")
    with open(path, "w", encoding="utf-8") as f:
        f.write(s + "\n")


def main(argv=None, api=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("--help", "-h"):
        print(__doc__)
        return 0
    p = Parser(prog="deadman.py", add_help=False)
    p.add_argument("--backend", choices=["github", "gitlab"], default="github")
    p.add_argument("--repo")
    p.add_argument("--gitlab-url", dest="gitlab_url")
    p.add_argument("--project")
    p.add_argument("--out", required=True)
    p.add_argument("--max-age-hours", dest="max_age_hours", type=float, default=float(DEFAULT_MAX_AGE_HOURS))
    p.add_argument("--mode", choices=["real", "drill"], default="real")
    p.add_argument("--schedules", action="store_true")
    p.add_argument("--now")
    try:
        args = p.parse_args(argv)
        if not (0 < args.max_age_hours <= 24 * 365):
            raise Usage("--max-age-hours 要大於 0")
        now = parse_now(args.now)
        if args.backend == "github":
            if not args.repo or not issues.REPO_RE.fullmatch(args.repo):
                raise Usage("需要合法的 --repo")
            if args.gitlab_url or args.project:
                raise Usage("--gitlab-url／--project 只能搭配 --backend gitlab")
            if args.schedules:
                raise Usage("--schedules 只能搭配 --backend gitlab（排程 API 是 GitLab 的）")
            target = args.repo
        else:
            if args.repo:
                raise Usage("--backend gitlab 不用 --repo，用 --project")
            if not args.gitlab_url or not args.project or not issues.PROJECT_ID_RE.fullmatch(args.project):
                raise Usage("--backend gitlab 需要 --gitlab-url 與數字的 --project")
            why = issues.gitlab_url_problem(args.gitlab_url)
            if why:
                raise Usage(why)
            target = args.project
    except (Usage, SystemExit) as e:
        print("用法：deadman.py (--repo O/R | --backend gitlab --gitlab-url … --project N) --out 資料夾 [--max-age-hours 36] [--mode real|drill] [--schedules] [--now UTC]（見檔頭）", file=sys.stderr)
        print(f"WATCH-DEADMAN\tFAIL\t用法錯誤：{e}" if isinstance(e, Usage) else "WATCH-DEADMAN\tFAIL\t用法錯誤")
        return 64
    os.makedirs(args.out, exist_ok=True)
    for n in ("plan.json", "result.json"):
        try:
            os.remove(os.path.join(args.out, n))
        except FileNotFoundError:
            pass
    token = ""
    result = {"status": "FAIL", "checks": [], "last_update": None, "age_hours": None, "max_age_hours": args.max_age_hours,
              "mode": args.mode, "now": fmt(now), "schedules": [], "alerts": [], "recovered": []}
    try:
        if api is None:
            api = issues.Api() if args.backend == "github" else issues.GitLabApi(args.gitlab_url)
            if args.backend == "gitlab" and not api.token:
                raise Fail("沒有 GITLAB_TOKEN（環境變數；範本用 DEADMAN_GITLAB_TOKEN 對應，protected＋masked）")
        token = getattr(api, "token", "") or ""
        status, checks, alerts, summaries, info, recoveries = run(args, api, target, now)
        actions = build_actions(args, alerts, checks, info, now, summaries, recoveries)
        probs = [x for a in actions for x in publiccheck.check_text(a.get("title", "") + "\n" + a["body"])]
        if probs:
            raise Fail(f"要寫進 Issue 的內容沒過公開檢查（{probs[0]}）")
        bad = match.unsafe_actions(actions)
        if bad:
            raise Fail(f"要寫進 Issue 的內容有沒淨化的 Markdown（例如 {bad[0]!r}）")
    except (Fail, issues.Fail, publiccheck.RuleError, OSError) as e:
        msg = str(e)
        if token:
            msg = msg.replace(token, "***")
        result.update(checks=result["checks"] or [{"name": "deadman", "status": "FAIL", "detail": msg}])
        write_json(os.path.join(args.out, "result.json"), result, token)
        print(f"WATCH-DEADMAN\tFAIL\t{msg}")
        return 1
    detail = "；".join(f"{c['name']}={c['status']}" for c in checks)
    if alerts:
        detail += "；" + "；".join(a["why"] for a in alerts)[:600]
    result.update(status=status, checks=checks, last_update=info["last_update"], age_hours=info["age_hours"], schedules=summaries,
                  alerts=[{"scope": a["scope"], "ident": a["ident"], "key": key_of(args.mode, a["ident"])} for a in alerts],
                  recovered=[{"key": k, "issue": n} for k, n, _ in recoveries])
    write_json(os.path.join(args.out, "result.json"), result, token)
    if actions:
        plan = {"schema": issues.PLAN_SCHEMA, "mode": args.mode, "stateless": True, "stateless_kind": "deadman", "generated_at": fmt(now),
                "run_url": None, "state_base": None, "state": None, "actions": actions, "status": status, "detail": detail[:300]}
        write_json(os.path.join(args.out, "plan.json"), plan, token)
    line = f"WATCH-DEADMAN\t{status}\t{detail}"
    print(line.replace(token, "***") if token else line)
    return {"OK": 0, "FAIL": 1}.get(status, 2)


if __name__ == "__main__":
    sys.exit(main())
