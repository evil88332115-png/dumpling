#!/usr/bin/env python3
"""art14.py：CRA 第 14 條通報工作流程的 GitHub 演練版（M8 B1，WP2；契約與流程見 docs/ART14.md）。

用法：
  python3 -I pipeline/watch/art14.py open-drill       --repo O/R --match 合成命中.json [--project projects/<專案>] [--result 結果.json]
  python3 -I pipeline/watch/art14.py countdown        --repo O/R [--drill] [--now UTC時間] [--result 結果.json]
  python3 -I pipeline/watch/art14.py fill-drill-aware --repo O/R --at UTC時間 [--result 結果.json]
  python3 -I pipeline/watch/art14.py close-drill      --repo O/R [--result 結果.json]
  python3 -I pipeline/watch/art14.py check            --result 結果.json --expect 路徑=值 …
GitLab 後端（GITLAB-PORT T-10；只用假 API 測過，沒有對真實 GitLab 驗證）：
  把 --repo O/R 換成 --backend gitlab --gitlab-url <…/api/v4> --gitlab-project <數字 ID>（token 從環境變數 GITLAB_TOKEN 讀，不收 argv；
  注意 --project 仍然是「專案資料夾」）。多一個指令：
  python3 -I pipeline/watch/art14.py open-real        --backend gitlab … --match 命中.json [--project projects/<專案>] [--result 結果.json]   （只有 GitLab；GitHub 一律拒絕）
  GitLab 的 countdown 不加 --drill ＝ 真實案件（標籤 art14）；加 --drill ＝ 演練（標籤 art14-drill）。
  信任：作者與留言者要是專案成員且存取等級 >= Developer（30）；system 留言不算；Issue 不是 confidential 就 FAIL、不寫入。
stdout 最後一行 ART14<TAB>OK|FAIL<TAB>說明；結束碼 OK 0、FAIL 1、用法 64。

安全與範圍：
  - （GitHub）公開 repo 只有演練：沒有任何指令會在 GitHub 開或改 `art14`（真實案件）Issue。不加 --drill 的 countdown 找到 art14 Issue 就 FAIL、不修改。
  - 只處理作者是 repo 的 OWNER／MEMBER／COLLABORATOR（或 github-actions[bot]）的 Issue；公開 repo 任何人都能開 Issue。
  - 寫進 Issue 的文字一律先過 publiccheck.check_text()；演練的文字一定要有「演練」字樣，否則不寫。
  - GitHub API 用 issues.Api（token 只放標頭、不跟隨轉址、http 只限本機、rate limit 重試），不另寫一套。
  - 期限是保守值；法定期限的精確解釋交給法務（docs/ART14.md）。SRP 沒有 API，這裡沒有任何自動提交。
"""
import argparse
import calendar
import datetime as dt
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")   # project_config（只在有 --project 時才 import）
import issues  # noqa: E402
import match  # noqa: E402（md_text／md_title／unsafe_markdown：寫進公開 Issue 的外部字串）
import publiccheck  # noqa: E402

Fail = issues.Fail
Usage = issues.Usage

MATCH_SCHEMA = "dumpling-art14-drill-match/1"
RESULT_SCHEMA = "dumpling-art14-result/1"
DRILL_LABEL = "art14-drill"
DRILL_DONE_LABEL = "art14-drill-done"
REAL_LABEL = "art14"
STAGE_LABELS = {"24h": "art14-24h", "72h": "art14-72h", "final": "art14-final"}
GITLAB_MIN_LEVEL = 30   # Developer（官方 Project members API 的存取等級表：Guest 10、Planner 15、Reporter 20、Security Manager 25、Developer 30、Maintainer 40、Owner 50）
TRUSTED_ASSOC = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
BOT_LOGIN = "github-actions[bot]"
MARK_RE = re.compile(r"<!-- dumpling-art14 key=([0-9a-f]{64}) kind=(vulnerability|incident) mode=(real|drill) -->")
COMMENT_MARK = "<!-- dumpling-art14-countdown -->"
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
DRILL_LINE = "演練，不是真實通報"
# D-040 (3)（C0 決定，#69 之後）：公開 repo 的演練 Issue 也寫明示範專案、加 demo 標籤，不會被當成真實出貨產品
DEMO_LABEL = "demo"
DEMO_TITLE = match.DEMO_TITLE
DEMO_LINE = "> **示範專案（公開 BSP）**：dumpling 公開 repo 的示範專案與合成命中，以公開 BSP／公開資料建置，不是真的出貨產品，也不是真實通報。"
BLANK = "未填"
MAX_BODY_READ = 60000
KINDS = ("vulnerability", "incident")
LAYERS = ("bsp", "os", "product")
SOURCES = {"KEV": "CISA KEV", "EUVD": "EUVD", "vendor": "廠商公告"}

F_AWARE = "知悉時間（UTC）"
F_MEASURE = "修正或緩解措施可用時間（UTC）"
F_NOTIF = "事件通報送出時間（UTC）"
F_DETECTED = "first_detected（候選，不是知悉時間）"
F_SUBMIT_NO = "SRP 提交編號"
F_SUBMIT_BY = "提交人"
F_SUBMIT_AT = "提交時間（UTC）"

REG_NOTE = ("Regulation (EU) 2024/2847（CRA）第 14 條；OJ L 2024/2847, 20.11.2024；EUR-Lex CELEX:32024R2847；"
            "2026-11-13 從 EUR-Lex 核對。第 71 條：第 14 條自 2026-09-11 適用。")


class DeadlineError(ValueError):
    pass


# ---------- 時間 ----------
def utc(t, name="時間"):
    """帶時區的 datetime 轉 UTC；沒時區的拒絕（不猜時區）。"""
    if not isinstance(t, dt.datetime):
        raise DeadlineError(f"{name}不是 datetime")
    if t.tzinfo is None or t.utcoffset() is None:
        raise DeadlineError(f"{name}沒有時區：一律要帶時區（再轉成 UTC）")
    return t.astimezone(dt.timezone.utc)


def fmt(t):
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s):
    """嚴格格式 YYYY-MM-DDTHH:MM:SSZ（UTC）；不合回傳 None。"""
    if not isinstance(s, str) or not TS_RE.fullmatch(s):
        return None
    try:
        return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def add_one_month(t):
    """下個月同一日同一時刻；那一天不存在就取該月最後一天同一時刻（保守值）。"""
    y, m = divmod(t.year * 12 + (t.month - 1) + 1, 12)
    m += 1
    day = min(t.day, calendar.monthrange(y, m)[1])
    return t.replace(year=y, month=m, day=day)


def fmt_span(seconds):
    s = int(abs(seconds))
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d} 天 {h} 小時 {m} 分"
    if h:
        return f"{h} 小時 {m} 分"
    return f"{m} 分"


# ---------- 期限（保守值）----------
STAGE_DEFS = {
    "vulnerability": [
        ("24h", "早期預警", "14(2)(a)", "知悉時間 + 24 小時"),
        ("72h", "漏洞通報", "14(2)(b)", "知悉時間 + 72 小時"),
        ("final", "最終報告", "14(2)(c)", "修正或緩解措施可用時間 + 14 × 24 小時"),
    ],
    "incident": [
        ("24h", "早期預警", "14(4)(a)", "知悉時間 + 24 小時"),
        ("72h", "事件通報", "14(4)(b)", "知悉時間 + 72 小時"),
        ("final", "最終報告", "14(4)(c)", "事件通報送出時間的下個月同一日同一時刻"),
    ],
}


def deadlines(kind, aware_at, measure_at=None, notification_at=None):
    """三階段期限（全部 UTC、保守值）。回傳 {"kind", "stages": [{id, name, article, basis, due, reason}]}。
    沒有起算點的階段 due 是 None，reason 寫原因。時間沒時區 → DeadlineError。
    措施可用時間（或事件通報時間）早於知悉時間 → DeadlineError（呼叫端決定怎麼標示；countdown 會標示並不起算最終報告）。
    保守值：24h／72h 就是整點秒數；14 天是 14×24h；1 個月是「下個月同一日同一時刻，沒有那一天就取該月最後一天」。
    法定期限的精確解釋（期間計算規則等）交給法務，這裡不宣稱。"""
    if kind not in KINDS:
        raise DeadlineError(f"kind 要是 {KINDS}")
    aware = utc(aware_at, "知悉時間") if aware_at is not None else None
    measure = utc(measure_at, "措施可用時間") if measure_at is not None else None
    notif = utc(notification_at, "事件通報送出時間") if notification_at is not None else None
    out = []
    for sid, name, art, basis in STAGE_DEFS[kind]:
        due, reason = None, None
        if aware is None:
            reason = "知悉時間未填，時鐘未起算"
        elif sid == "24h":
            due = aware + dt.timedelta(hours=24)
        elif sid == "72h":
            due = aware + dt.timedelta(hours=72)
        elif kind == "vulnerability":
            if measure is None:
                reason = "修正或緩解措施可用時間未填"
            elif measure < aware:
                raise DeadlineError("措施可用時間早於知悉時間")
            else:
                due = measure + dt.timedelta(days=14)
        else:
            if notif is None:
                reason = "事件通報送出時間未填"
            elif notif < aware:
                raise DeadlineError("事件通報送出時間早於知悉時間")
            else:
                due = add_one_month(notif)
        out.append({"id": sid, "name": name, "article": art, "basis": basis, "due": due, "reason": reason})
    return {"kind": kind, "stages": out}


# ---------- 命中（合成）→ Issue ----------
def clean(s, limit=400):
    """單行文字：去控制字元與 < >，壓縮空白，限制長度（避免偽造標記或欄位行）。"""
    s = re.sub(r"[\x00-\x1f\x7f<>]", " ", str(s))
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


def load_match(path):
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        raise Fail(f"命中檔讀不到或不是 JSON（{type(e).__name__}）")
    if not isinstance(raw, dict) or raw.get("schema") != MATCH_SCHEMA:
        raise Fail(f"命中檔 schema 不是 {MATCH_SCHEMA}")
    kind = raw.get("kind")
    if kind not in KINDS:
        raise Fail(f"命中檔 kind 要是 {KINDS}")

    def need(name, pattern=None):
        v = raw.get(name)
        if not isinstance(v, str) or not v.strip():
            raise Fail(f"命中檔缺 {name}")
        v = clean(v)
        if pattern and not re.fullmatch(pattern, v):
            raise Fail(f"命中檔 {name} 格式不合")
        return v
    m = {"kind": kind, "product": need("product", r"[A-Za-z0-9._ -]{1,80}"),
         "version": need("version", r"[A-Za-z0-9._+-]{1,40}"), "description": need("description" if kind == "vulnerability" else "summary")}
    ft = raw.get("first_detected")
    if parse_ts(ft) is None:
        raise Fail("命中檔 first_detected 要是 YYYY-MM-DDTHH:MM:SSZ")
    m["first_detected"] = ft
    if kind == "vulnerability":
        m["layer"] = need("layer", "|".join(LAYERS))
        m["cve"] = need("cve", r"CVE-\d{4}-\d{4,}")
        m["affected_versions"] = need("affected_versions")
        ev = raw.get("exploited_evidence")
        if not isinstance(ev, list) or not ev:
            raise Fail("命中檔缺 exploited_evidence（被利用的依據）")
        m["evidence"] = []
        for e in ev:
            if not isinstance(e, dict) or e.get("source") not in SOURCES:
                raise Fail(f"exploited_evidence 的 source 要是 {sorted(SOURCES)}")
            m["evidence"].append((SOURCES[e["source"]], clean(e.get("note", "")), clean(e.get("ref", ""), 200)))
        m["id"] = m["cve"]
        m["key_parts"] = [m["product"], m["version"], m["layer"], m["cve"]]
    else:
        m["incident_id"] = need("incident_id", r"[A-Za-z0-9._-]{1,60}")
        m["id"] = m["incident_id"]
        m["key_parts"] = [m["product"], m["version"], m["incident_id"]]
    sev = raw.get("severity")
    m["severity"] = clean(sev, 60) if isinstance(sev, str) and sev.strip() else None
    m["severity_source"] = clean(raw.get("severity_source", ""), 120)
    return m


# ---------- 專案資訊（project.yml，D-055；欄位由 C1 在 M7a 實作：pipeline/lib/project_config.py）----------
MARKETS_NO_PROJECT = "GAP：沒有指定專案（--project），讀不到 project.yml 的 markets；請人工填寫已知販售的會員國"
MARKETS_TODO = "GAP：project.yml 的 markets 還沒填（TO BE COMPLETED）；請人工填寫已知販售的會員國"
MARKETS_UNKNOWN = "GAP：銷售市場不明（project.yml 的 markets 是 UNKNOWN），早期預警不能依會員國通知；請人工確認後填寫"


def markets_text(project):
    """(狀態, 文字)。狀態：codes｜eu-all｜unknown｜todo｜no-project。不明與還沒填都是 GAP，而且寫法不同；EU-ALL 不展開成 27 國。"""
    if project is None:
        return "no-project", MARKETS_NO_PROJECT
    if LIB not in sys.path:
        sys.path.insert(0, LIB)
    import project_config as pc  # noqa: E402（只在有 --project 時才需要 PyYAML）
    if "markets" in (project.get("_todo") or []):
        return "todo", MARKETS_TODO
    if project.get("_markets_unknown"):
        return "unknown", MARKETS_UNKNOWN
    mk = project.get("markets") or []
    if mk == [pc.MARKET_EU_ALL]:
        return "eu-all", "全歐盟（EU-ALL，不逐一列出會員國；來源 project.yml）"
    if mk and all(isinstance(c, str) and c in pc.EU_MEMBER_CODES for c in mk):
        return "codes", "、".join(mk) + "（ISO 3166-1 alpha-2；來源 project.yml）"
    raise Fail("project.yml 的 markets 不是 D-055 認得的值（load_project 應該已經擋下）")


def load_project_info(project_dir):
    """用 project_config.load_project 讀 project.yml（含和 config.json 的一致性檢查）；錯誤一律 Fail。"""
    if LIB not in sys.path:
        sys.path.insert(0, LIB)
    try:
        import project_config as pc  # noqa: E402
        return pc.load_project(project_dir)
    except Exception as e:      # ConfigError、缺 PyYAML、檔案讀不到
        raise Fail(f"project.yml 讀不到或不合格：{clean(str(e), 300)}")


def apply_project(m, project):
    """產品名稱以 project.yml 為準（D-055 (3)）；版本照命中（＝Release tag 的版本）。key 不變（同一個命中不因改名而重開）。"""
    m["market_state"], m["markets"] = markets_text(project)
    m["role_note"] = None
    m["project_warnings"] = []
    if project is None:
        return m
    name = clean(project.get("product_name") or "", 120)
    if name and name != "TO BE COMPLETED":
        m["product"] = name
    role = project.get("company_role")
    if role == "supplier":
        m["role_note"] = "supplier（project.yml）：第 14 條是製造商的義務，供應商的角色怎麼適用交給法務判斷"
    elif role in ("manufacturer", "both"):
        m["role_note"] = f"{role}（project.yml）"
    m["project_warnings"] = [clean(w, 200) for w in project.get("_warnings") or []]
    return m


def issue_key(kind, mode, parts):
    return hashlib.sha256(("dumpling-art14/1|" + mode + "|" + kind + "|" + "|".join(parts)).encode("utf-8")).hexdigest()


def render_issue(m, drill=True, gitlab=False):
    """回傳 (key, 標題, 內文, 標籤)。內文第一行是機器標記，drill 的第二行固定是「演練，不是真實通報」。"""
    kind, mode = m["kind"], "drill" if drill else "real"
    key = issue_key(kind, mode, m["key_parts"])
    inc = kind == "incident"
    # 產品名稱來自 project.yml（任意字串，不像命中檔的 product 有白名單）：標題用 md_title、內文用 md_text（M8 預驗應修 3）
    head = (f"[演練] {DEMO_TITLE} " if drill else "") + ("第 14 條通報（嚴重事件）：" if inc else "第 14 條通報：") + f"{match.md_title(m['product'])} {m['version']} {m['id']}"
    if "markets" not in m:
        apply_project(m, None)
    L = [f"<!-- dumpling-art14 key={key} kind={kind} mode={mode} -->"]
    if drill:
        L += [DRILL_LINE, "", DEMO_LINE]      # 第二行固定是 DRILL_LINE（解析與檢查的契約），示範專案說明接在後面
    note = ("倒數只是輔助，GitLab 排程可能延遲，期限由負責人自己掌握。本 Issue 是私密（confidential）Issue，仍不放金鑰、密碼或個資。"
            if gitlab and not drill else "倒數只是輔助，GitHub 排程可能延遲，期限由負責人自己掌握。不在公開 Issue 放任何機密。")
    L += ["", note, "",
          "## 預填欄位（工具帶入，請核對）", f"- 產品名稱與版本：{match.md_text(m['product'])} {m['version']}"]
    if inc:
        L += [f"- 事件代號：{m['incident_id']}", f"- 事件說明：{m['description']}",
              f"- 嚴重度（對產品安全的影響）：{m['severity'] + '（來源：' + m['severity_source'] + '）' if m['severity'] and m['severity_source'] else '待填'}"]
    else:
        L += [f"- 層：{m['layer']}", f"- CVE：{m['cve']}", f"- 說明：{m['description']}"]
        for src, note, ref in m["evidence"]:
            L.append(f"- 被利用的依據：{src}" + (f"（{note}）" if note else "") + (f" {ref}" if ref else ""))
        L += [f"- 受影響版本：{m['affected_versions']}",
              f"- 嚴重度：{m['severity'] + '（來源：' + m['severity_source'] + '）' if m['severity'] and m['severity_source'] else '待填'}"]
    L += [f"- {F_DETECTED}：{m['first_detected']}",
          f"- 銷售市場（會員國）：{m['markets']}"] + ([f"- 公司角色：{m['role_note']}"] if m["role_note"] else []) + [""]
    L += ["## 要人填的欄位（負責人填，工具不會猜）", f"- {F_AWARE}：{BLANK}"]
    if inc:
        L += ["- 是否疑似非法或惡意行為造成：" + BLANK, f"- {F_NOTIF}：{BLANK}", "- 採取的措施（說明，不要放機密）：" + BLANK]
    else:
        L += [f"- {F_MEASURE}：{BLANK}", "- 修正或緩解措施（說明，不要放機密）：" + BLANK]
    L += ["- 要通知用戶的內容（不要放機密）：" + BLANK,
          "- 格式提醒：UTC 時間只接受 YYYY-MM-DDTHH:MM:SSZ 或 未填；格式不對會被當成未填，倒數留言會寫明", ""]
    for n, (sid, name, art, basis) in enumerate(STAGE_DEFS[kind], 1):
        L += [f"## 階段 {n}：{name}（第 {art} 條）", f"- 期限（保守值）：{basis}"]
        if n == 1:
            L.append("- 要寫明：" + ("是否疑似非法或惡意行為造成" if inc else "已知產品在哪些會員國販售（適用時）"))
        L += [f"- {F_SUBMIT_NO}：{BLANK}", f"- {F_SUBMIT_BY}：{BLANK}", f"- {F_SUBMIT_AT}：{BLANK}", ""]
    L += ["## SRP 人工提交檢查清單（SRP 沒有 API，工具不會自動提交）",
          "- [ ] 登入 SRP（ENISA 單一通報平台，第 16 條）",
          "- [ ] 選擇協調 CSIRT（產品製造商主要營業地所在的會員國）",
          "- [ ] 把上面的預填欄位貼進該階段的通報",
          "- [ ] 把 SRP 提交編號、提交人、提交時間（UTC）填回本 Issue 對應的階段", ""]
    L += ["## 期限與出處",
          f"- 法規出處（核對）：{REG_NOTE}",
          "- 期限是工具算的保守值，法定期限的精確解釋交給法務；倒數留言只維護一則，標籤 art14-24h／art14-72h／art14-final 跟著下一個未完成的階段。"]
    body = "\n".join(L) + "\n"
    labels = ([DRILL_LABEL, DEMO_LABEL] if drill else [REAL_LABEL]) + [STAGE_LABELS["24h"]]
    return key, head, body, labels


# ---------- 解析 Issue 內文 ----------
FIELD_RE = re.compile(r"^- (.+?)：(.*)$")


def parse_marker(body):
    if not isinstance(body, str):
        return None
    lines = body.splitlines()
    m = MARK_RE.fullmatch(lines[0]) if lines else None
    return (m.group(1), m.group(2), m.group(3)) if m else None


def scan_fields(body):
    """{(階段編號或 0, 欄位名): [值, …]}。階段由「## 階段 N」標題決定，其他標題回到 0。"""
    out, sec = {}, 0
    for line in body[:MAX_BODY_READ].splitlines():
        h = re.match(r"^## 階段 ([1-3])[：:]", line)
        if h:
            sec = int(h.group(1))
            continue
        if line.startswith("## "):
            sec = 0
            continue
        m = FIELD_RE.match(line.rstrip())
        if m:
            out.setdefault((sec, m.group(1)), []).append(m.group(2).strip())
    return out


def get_ts(fields, sec, label):
    """回傳 (狀態, datetime｜None, 原文)：ok｜blank｜bad。欄位不見或重複也算 bad。"""
    vals = fields.get((sec, label), [])
    if len(vals) != 1:
        return "bad", None, ("欄位不見了" if not vals else "欄位重複")
    v = vals[0]
    if v == BLANK:
        return "blank", None, v
    t = parse_ts(v)
    return ("ok", t, v) if t else ("bad", None, v)


def evaluate(kind, body, now):
    """解析內文與算倒數狀態（純函式）。回傳 dict，見 render_comment／countdown。"""
    fields = scan_fields(body)
    problems = []

    def ts(sec, label, name):
        st, t, raw = get_ts(fields, sec, label)
        if st == "bad":
            problems.append(f"格式不對：{name}（讀到 {clean(raw, 40)!r}），當成未填；格式要是 YYYY-MM-DDTHH:MM:SSZ 或 未填")
        return t
    aware = ts(0, F_AWARE, "知悉時間")
    measure = ts(0, F_MEASURE, "措施可用時間") if kind == "vulnerability" else None
    notif = ts(0, F_NOTIF, "事件通報送出時間") if kind == "incident" else None
    detected = ts(0, F_DETECTED, "first_detected")
    submits = [ts(n, F_SUBMIT_AT, f"階段 {n} 提交時間") for n in (1, 2, 3)]
    try:
        dl = deadlines(kind, aware, measure, notif)
    except DeadlineError as e:
        problems.append(f"{e}：最終報告的期限不起算，請確認時間是否填錯（若確實如此，期限交給法務判斷）")
        dl = deadlines(kind, aware, None, None)
        for s in dl["stages"]:
            if s["id"] == "final":
                s["reason"] = str(e) + "，請確認"
    stages = []
    for s, sub in zip(dl["stages"], submits):
        s = dict(s, submitted=sub)
        if sub is not None:
            s["state"] = "done"
            s["late"] = bool(s["due"] and sub > s["due"])
        elif s["due"] is None:
            s["state"] = "not_started"
        elif now > s["due"]:
            s["state"] = "overdue"
        else:
            s["state"] = "pending"
        stages.append(s)
    nxt = next((s["id"] for s in stages if s["state"] != "done"), None)
    hours = None
    if detected is not None:
        if now < detected:
            problems.append("first_detected 比現在還晚，請確認")
        else:
            hours = int((now - detected).total_seconds() // 3600)
    return {"kind": kind, "aware": aware, "clock_started": aware is not None, "first_detected": detected,
            "hours_since_detected": hours, "stages": stages, "next_stage": nxt, "problems": problems}


def render_comment(ev, now, drill, gitlab=False):
    L = [COMMENT_MARK]
    if drill:
        L += [DRILL_LINE, DEMO_LINE]
    L += [f"倒數更新（UTC）：{fmt(now)}", ""]
    if ev["clock_started"]:
        L.append(f"時鐘已起算：知悉時間 {fmt(ev['aware'])}（負責人填寫）。")
    else:
        extra = (f"first_detected（候選，不是知悉時間）{fmt(ev['first_detected'])} 起已經過 {ev['hours_since_detected']} 小時，請盡快確認是否已知悉。"
                 if ev["hours_since_detected"] is not None else "first_detected 讀不到，請確認。")
        L.append(f"時鐘未起算（待確認）：知悉時間還沒填。{extra}")
    L += ["", "| 階段 | 期限（UTC，保守值） | 狀態 |", "|---|---|---|"]
    for n, s in enumerate(ev["stages"], 1):
        due = fmt(s["due"]) if s["due"] else "—"
        if s["state"] == "done":
            st = f"完成（SRP 提交 {fmt(s['submitted'])}" + ("，晚於期限）" if s["late"] else "）")
        elif s["state"] == "overdue":
            st = f"已逾期 {fmt_span((now - s['due']).total_seconds())}"
        elif s["state"] == "pending":
            st = f"剩 {fmt_span((s['due'] - now).total_seconds())}"
        else:
            st = f"未起算：{s['reason']}"
        L.append(f"| {n} {s['name']}（第 {s['article']} 條） | {due} | {st} |")
    L.append("")
    if ev["next_stage"]:
        L.append(f"下一個未完成的階段：{STAGE_LABELS[ev['next_stage']]}。")
    else:
        L.append("三個階段都已有 SRP 提交時間。")
    for p in ev["problems"]:
        L.append(f"- 注意：{p}")
    L += ["", f"倒數只是輔助，{'GitLab' if gitlab and not drill else 'GitHub'} 排程可能延遲，期限由負責人自己掌握。期限是保守值，法定期限的精確解釋交給法務。"]
    return "\n".join(L) + "\n"


# ---------- 寫入前的檢查 ----------
def is_gitlab(api):
    return getattr(api, "kind", "github") == "gitlab"


def guard_text(texts, drill, internal=False):
    """texts: [(名稱, 文字)]。公開檢查命中或演練缺「演練」字樣 → Fail，什麼都不寫。
    internal：GitLab 的真實案件（私密 Issue，內部儲存）不需要公開檢查與「演練」字樣；沒淨化的 Markdown 檢查照做。"""
    if drill:
        for name, t in texts:
            if "演練" not in t:
                raise Fail(f"{name}沒有「演練」字樣（演練的內容一定要有），不寫")
    if not internal:
        issues.public_check(texts)
    # 最後一道：沒淨化的 @提及、連結、圖片、HTML 實體（標題不是 Markdown，只算 @ 與實體）
    bad = [(name, x) for name, t in texts for x in match.unsafe_markdown(t) if "標題" not in name or x[0] in "@＠&"]
    if bad:
        raise Fail(f"{bad[0][0]}有沒淨化的 Markdown（{bad[0][1]!r}），不寫")


def pre_write(api, texts, drill):
    """任何寫入之前的檢查：guard_text；GitLab 另外檢查 quick action（標題、內文、留言都算）。真實案件在 GitLab 才會有（internal）。"""
    guard_text(texts, drill, internal=is_gitlab(api) and not drill)
    if is_gitlab(api):
        issues.GitLabApi.precheck(texts)


def trusted_author(issue):
    u = issue.get("user") or {}
    if issue.get("author_association") in TRUSTED_ASSOC:
        return True
    return u.get("type") == "Bot" and u.get("login") == BOT_LOGIN


def trusted_commenter(c):
    return trusted_author(c)


class Trust:
    """誰寫的 Issue／留言可信。GitHub：author_association＋github-actions[bot]（同以前）。
    GitLab：作者是專案成員、存取等級 >= Developer（30）；查 GET /projects/:id/members/all/:user_id，同一個 user id 一輪只查一次。
    token 自己的使用者（project access token 的 bot 使用者）也是成員，所以工具寫的留言也算在內。"""

    def __init__(self, api, repo):
        self.api, self.repo, self.cache = api, repo, {}

    def ok(self, obj):
        if not is_gitlab(self.api):
            return trusted_author(obj)
        uid = (obj.get("user") or {}).get("id")
        if type(uid) is not int:
            return False
        if uid not in self.cache:
            self.cache[uid] = self.api.member_access(self.repo, uid)
        lvl = self.cache[uid]
        return lvl is not None and lvl >= GITLAB_MIN_LEVEL


def write_result(path, obj):
    if path:
        issues.write_json(path, dict(obj, schema=RESULT_SCHEMA))


def find_issues(api, repo, label, mode, trust, state="open"):
    """回傳 (可處理的 [(issue, marker)], 略過的 [(編號, 原因)], 外洩疑慮的 [編號])。
    外洩疑慮（只有 GitLab）：有這個標籤、卻不是 confidential 的 Issue——不處理、不寫入，呼叫端要 FAIL 並請人處理。"""
    ok, skipped, leaks = [], [], []
    for i in issues.list_issues(api, repo, label, state):
        if state == "open" and i.get("state") != "open":
            # 依標籤列 Issue 剛關閉後有索引延遲（2026-11-13 實測 #37）：不更新已關閉的
            skipped.append((i["number"], "已關閉（列表索引延遲）"))
            continue
        if is_gitlab(api) and i.get("confidential") is not True:
            leaks.append(i["number"])
            continue
        if not trust.ok(i):
            skipped.append((i["number"], "作者不是 OWNER／MEMBER／COLLABORATOR" if not is_gitlab(api)
                            else f"作者不是專案成員或存取等級低於 Developer（{GITLAB_MIN_LEVEL}）"))
            continue
        mk = parse_marker(i.get("body"))
        if not mk or mk[2] != mode:
            skipped.append((i["number"], f"第一行標記不合法或不是 {mode}"))
            continue
        ok.append((i, mk))
    return ok, skipped, leaks


def find_drill_issues(api, repo, state="open"):
    ok, skipped, _leaks = find_issues(api, repo, DRILL_LABEL, "drill", Trust(api, repo), state)
    return ok, skipped


def leak_message(leaks):
    return (f"Issue {sorted(leaks)} 有 art14 標籤但不是 confidential（可能已經外洩）：不處理、不寫入；"
            "請立刻人工改成 confidential 或刪除，並評估是否已被不該看的人看到")


# ---------- 指令 ----------
def cmd_open(api, repo, match_path, result, project_dir=None, drill=True):
    """開案：drill＝演練（GitHub、GitLab 都可）；真實案件只有 GitLab（私密 Issue）。"""
    cmd = "open-drill" if drill else "open-real"
    if not drill and not is_gitlab(api):
        raise Fail("公開 repo（GitHub）不開真實案件：open-real 只能搭配 --backend gitlab")
    m = apply_project(load_match(match_path), load_project_info(project_dir) if project_dir else None)
    for w in m["project_warnings"]:
        print(f"WARN\tproject.yml：{w}", file=sys.stderr)
    key, title, body, labels = render_issue(m, drill=drill, gitlab=is_gitlab(api))
    pre_write(api, [("標題", title), ("內文", body)], drill)
    mode = "drill" if drill else "real"
    for i in issues.list_issues(api, repo, DRILL_LABEL if drill else REAL_LABEL, "all"):
        mk = parse_marker(i.get("body"))
        if mk and mk[0] == key and mk[2] == mode:
            if is_gitlab(api) and i.get("confidential") is not True:     # T-10 驗證建議 1：已經有、但不是 confidential → 外洩疑慮，FAIL
                write_result(result, {"cmd": cmd, "result": "leak", "issue": i["number"], "key": key})
                raise Fail(leak_message([i["number"]]))
            write_result(result, {"cmd": cmd, "result": "skipped", "issue": i["number"], "key": key, "markets": m["market_state"]})
            return f"已有同一個命中的{'演練' if drill else '真實'} Issue #{i['number']}，不重複開"
    issues.Labels(api, repo, False).ensure(labels)
    d = api.create_issue(repo, title, body, labels)
    write_result(result, {"cmd": cmd, "result": "opened", "issue": d["number"], "key": key, "markets": m["market_state"]})
    return f"開了{'演練' if drill else '真實案件'} Issue #{d['number']}"


def cmd_open_drill(api, repo, match_path, result, project_dir=None):
    return cmd_open(api, repo, match_path, result, project_dir, True)


def comments_of(api, repo, number):
    return api.list_notes(repo, number)


def update_comment(api, repo, number, text, problems, trust=None):
    """只維護一則：用固定標記找（只認可信的留言者，system 留言不算），找到就編輯，沒有才新增。"""
    trust = trust or Trust(api, repo)
    mine = [c for c in comments_of(api, repo, number)
            if not c.get("system") and isinstance(c.get("body"), str) and c["body"].splitlines()[:1] == [COMMENT_MARK] and trust.ok(c)]
    mine.sort(key=lambda c: c["id"])
    if len(mine) > 1:
        problems.append(f"Issue #{number} 有 {len(mine)} 則倒數留言，只更新最早的一則")
    if not mine:
        api.create_note(repo, number, text)
        return "created"
    if mine[0]["body"] == text:
        return "unchanged"
    api.edit_note(repo, number, mine[0]["id"], text)
    return "updated"


def update_stage_label(api, repo, issue, want):
    names = issues.label_names(issue)
    new = [n for n in names if n not in STAGE_LABELS.values()] + ([STAGE_LABELS[want]] if want else [])
    if set(new) == set(names):
        return False
    if want:
        issues.Labels(api, repo, False).ensure([STAGE_LABELS[want]])
    api.edit_issue(repo, issue["number"], labels=new, was=issue.get("state"))
    return True


def cmd_countdown(api, repo, drill, now, result):
    gl = is_gitlab(api)
    if not drill and not gl:
        found = issues.list_issues(api, repo, REAL_LABEL, "open")
        if found:
            raise Fail(f"公開 repo 不該有真實案件：找到 {len(found)} 個開著的 art14 Issue {sorted(i['number'] for i in found)}，"
                       "不處理、不修改（真實案件只在 GitLab 的私密 Issue）")
        write_result(result, {"cmd": "countdown", "count": 0, "issues": [], "skipped": []})
        return "沒有 art14 Issue"
    trust = Trust(api, repo)
    what = "演練" if drill else "真實"
    cases, skipped, leaks = find_issues(api, repo, DRILL_LABEL if drill else REAL_LABEL, "drill" if drill else "real", trust)
    if gl:
        # T-10 驗證建議 2：另一種標籤（演練／真實）的 Issue 也看有沒有不是 confidential 的——不處理、不寫入，只報警
        other = REAL_LABEL if drill else DRILL_LABEL
        leaks = sorted(set(leaks) | {i["number"] for i in issues.list_issues(api, repo, other, "open")
                                     if i.get("state") == "open" and i.get("confidential") is not True})
    for n, why in skipped:
        print(f"skip\t#{n}\t{why}")
    for n in leaks:
        print(f"leak\t#{n}\t不是 confidential，不寫入")
    out, errors, problems = [], [], []
    if leaks:
        errors.append(leak_message(leaks))
    if gl and not drill:
        # T-10 驗證建議 3：真實案件被略過（作者不可信、標記不合）時倒數就停了——不能靜默，FAIL 請人確認
        # （成員 API 異常時也會全部變成「不是成員」）。剛關閉的索引延遲不算
        stuck = [(n, why) for n, why in skipped if not why.startswith("已關閉")]
        if stuck:
            errors.append(f"有 {len(stuck)} 個 art14 Issue 沒有倒數（" + "；".join(f"#{n} {why}" for n, why in stuck[:5]) +
                          "）：法定期限沒有被追蹤，請人工確認作者權限與 Issue 第一行的標記")
    for i, (key, kind, _mode) in cases:
        ev = evaluate(kind, i.get("body") or "", now)
        text = render_comment(ev, now, drill, gitlab=gl)
        try:
            pre_write(api, [("倒數留言", text)], drill)
        except Fail as e:
            errors.append(f"#{i['number']}：{e}")
            continue
        cres = update_comment(api, repo, i["number"], text, problems, trust)
        lab = update_stage_label(api, repo, i, ev["next_stage"])
        clock = "started" if ev["clock_started"] else "not_started"
        rec = {"number": i["number"], "kind": kind, "clock": clock, "comment": cres, "label_changed": lab,
               "stage_label": STAGE_LABELS[ev["next_stage"]] if ev["next_stage"] else None,
               "hours_since_detected": ev["hours_since_detected"], "problems": ev["problems"],
               "stages": {s["id"]: {"due": fmt(s["due"]) if s["due"] else None, "state": s["state"]} for s in ev["stages"]}}
        out.append(rec)
        print(f"case\t#{i['number']}\t{clock}\t下一階段 {rec['stage_label']}\t留言 {cres}")
    for p in problems:
        print("problem\t" + p)
    res = {"cmd": "countdown", "now": fmt(now), "count": len(out), "issues": out,
           "skipped": [{"number": n, "why": w} for n, w in skipped]}
    if gl:
        res["leaks"] = sorted(leaks)
    write_result(result, res)
    if errors:
        raise Fail("；".join(errors))
    if not cases:
        return f"沒有可處理的{what}案件，立刻結束" + (f"（略過 {len(skipped)} 個：" + "；".join(f"#{n} {why}" for n, why in skipped[:5]) + "）" if skipped else "")
    return f"更新 {len(out)} 個{what}案件的倒數"


def cmd_fill_drill_aware(api, repo, at, result):
    cases, _skipped, leaks = find_issues(api, repo, DRILL_LABEL, "drill", Trust(api, repo))
    if leaks:
        raise Fail(leak_message(leaks))
    if not cases:
        raise Fail("找不到可處理的 art14-drill Issue（只允許改演練 Issue）")
    done = []
    for i, _mk in cases:
        body = i.get("body") or ""
        pat = re.compile(r"^(- " + re.escape(F_AWARE) + r"：).*$", re.M)
        if len(pat.findall(body)) != 1:
            raise Fail(f"#{i['number']} 的知悉時間欄位不是剛好一行")
        new = pat.sub(lambda mo: mo.group(1) + fmt(at), body)
        pre_write(api, [("內文", new)], True)
        api.edit_issue(repo, i["number"], body=new, was=i.get("state"))
        done.append(i["number"])
    write_result(result, {"cmd": "fill-drill-aware", "updated": done, "at": fmt(at)})
    return f"填入合成的知悉時間 {fmt(at)}：{done}"


def cmd_close_drill(api, repo, result):
    """關閉演練 Issue，art14-drill 換成 art14-drill-done、拿掉階段標籤（下一次演練從頭開始）。GitLab：不是 confidential 的不碰、最後 FAIL。"""
    closed, leaks = [], []
    labels = issues.Labels(api, repo, False)
    for i in issues.list_issues(api, repo, DRILL_LABEL, "open"):
        if is_gitlab(api) and i.get("confidential") is not True:
            leaks.append(i["number"])
            continue
        new = list(dict.fromkeys(DRILL_DONE_LABEL if n == DRILL_LABEL else n
                                 for n in issues.label_names(i) if n not in STAGE_LABELS.values()))
        labels.ensure([DRILL_DONE_LABEL])
        api.create_note(repo, i["number"], "演練結束，自動關閉")
        api.edit_issue(repo, i["number"], state="closed", labels=new, was=i.get("state"))
        closed.append(i["number"])
    res = {"cmd": "close-drill", "closed": len(closed), "numbers": closed}
    if is_gitlab(api):
        res["leaks"] = sorted(leaks)
    write_result(result, res)
    if leaks:
        raise Fail(f"關閉 {len(closed)} 個演練 Issue：{closed}；" + leak_message(leaks))
    return f"關閉 {len(closed)} 個演練 Issue：{closed}"


def cmd_check(result_path, expects):
    """驗收：結果 JSON 的路徑（點分隔，數字是陣列索引）要等於預期值（字串比較；null 寫 null）。"""
    try:
        with open(result_path, encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError) as e:
        raise Fail(f"結果檔讀不到（{type(e).__name__}）")
    bad = []
    for e in expects:
        path, _, want = e.partition("=")
        cur = obj
        try:
            for part in path.split("."):
                cur = cur[int(part)] if isinstance(cur, list) else cur[part]
        except (KeyError, IndexError, ValueError, TypeError):
            bad.append(f"{path}：不存在")
            continue
        got = "null" if cur is None else (str(cur).lower() if isinstance(cur, bool) else str(cur))
        if got != want:
            bad.append(f"{path}：預期 {want}，實際 {got}")
    if bad:
        raise Fail("驗收不符：" + "；".join(bad))
    return f"驗收 {len(expects)} 項符合"


# ---------- 進入點 ----------
class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Usage(message)


def _now(s):
    t = parse_ts(s)
    if t is None:
        raise Usage("時間要是 YYYY-MM-DDTHH:MM:SSZ（UTC）")
    return t


def build_parser():
    p = Parser(prog="art14.py", add_help=False)
    sub = p.add_subparsers(dest="cmd")

    def repo_cmd(name):
        c = sub.add_parser(name, add_help=False)
        c.add_argument("--repo")                                    # github：O/R（必填）
        c.add_argument("--backend", choices=["github", "gitlab"], default="github")
        c.add_argument("--gitlab-url", dest="gitlab_url")           # gitlab：…/api/v4（CI_API_V4_URL）
        c.add_argument("--gitlab-project", dest="gitlab_project")   # gitlab：數字 ID（CI_PROJECT_ID）；--project 是專案資料夾，不是這個
        c.add_argument("--result")
        return c
    o = repo_cmd("open-drill")
    o.add_argument("--match", required=True)
    o.add_argument("--project", help="專案資料夾（讀 project.yml 的產品名稱、銷售市場、公司角色；沒給時銷售市場標 GAP）")
    r = repo_cmd("open-real")
    r.add_argument("--match", required=True)
    r.add_argument("--project", help="專案資料夾（同 open-drill）")
    c = repo_cmd("countdown")
    c.add_argument("--drill", action="store_true")
    c.add_argument("--now")
    repo_cmd("fill-drill-aware").add_argument("--at", required=True)
    repo_cmd("close-drill")
    k = sub.add_parser("check", add_help=False)
    k.add_argument("--result", required=True)
    k.add_argument("--expect", action="append", required=True)
    return p


def main(argv=None, api=None, clock=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = build_parser().parse_args(argv)
        if not args.cmd:
            raise Usage("需要子指令")
        target = None
        if args.cmd != "check":
            if args.backend == "github":
                if not args.repo or not issues.REPO_RE.fullmatch(args.repo):
                    raise Usage("--repo 要是 owner/repo")
                if args.gitlab_url or args.gitlab_project:
                    raise Usage("--gitlab-url／--gitlab-project 只能搭配 --backend gitlab")
                target = args.repo
            else:
                if args.repo:
                    raise Usage("--backend gitlab 不用 --repo，用 --gitlab-project")
                if not args.gitlab_url or not args.gitlab_project or not issues.PROJECT_ID_RE.fullmatch(args.gitlab_project):
                    raise Usage("--backend gitlab 需要 --gitlab-url 與數字的 --gitlab-project")
                why = issues.gitlab_url_problem(args.gitlab_url)
                if why:
                    raise Usage(why)
                target = args.gitlab_project
        now = at = None
        if args.cmd == "countdown":
            now = _now(args.now) if args.now else (clock() if clock else dt.datetime.now(dt.timezone.utc))
        if args.cmd == "fill-drill-aware":
            at = _now(args.at)
    except (Usage, SystemExit) as e:
        print("用法：art14.py open-drill|open-real|countdown|fill-drill-aware|close-drill|check …（見檔頭）", file=sys.stderr)
        print(f"ART14\tFAIL\t用法錯誤：{e}" if isinstance(e, Usage) else "ART14\tFAIL\t用法錯誤")
        return 64
    try:
        if args.cmd == "check":
            msg = cmd_check(args.result, args.expect)
        else:
            if api is None:
                if args.backend == "github":
                    api = issues.Api()
                else:
                    api = issues.GitLabApi(args.gitlab_url)
                    if not api.token:
                        raise Fail("沒有 GITLAB_TOKEN（環境變數；範本用 ART14_GITLAB_TOKEN 對應，protected＋masked）")
            if args.cmd == "open-drill":
                msg = cmd_open(api, target, args.match, args.result, args.project, True)
            elif args.cmd == "open-real":
                msg = cmd_open(api, target, args.match, args.result, args.project, False)
            elif args.cmd == "countdown":
                msg = cmd_countdown(api, target, args.drill, now, args.result)
            elif args.cmd == "fill-drill-aware":
                msg = cmd_fill_drill_aware(api, target, at, args.result)
            else:
                msg = cmd_close_drill(api, target, args.result)
    except Fail as e:
        print(f"ART14\tFAIL\t{e}")
        return 1
    print(f"ART14\tOK\t{msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
