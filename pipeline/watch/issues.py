#!/usr/bin/env python3
"""issues.py：每日監控 4d（契約見 docs/WATCH.md 3.3～3.5）。讀狀態 Issue、依 plan.json 開 Issue／留言、寫回狀態 Issue、關閉演練 Issue。

用法：
  python3 -I pipeline/watch/issues.py read-state  --repo O/R --mode real|drill --out 資料夾
  python3 -I pipeline/watch/issues.py apply       --repo O/R --plan plan.json [--dry-run]
  python3 -I pipeline/watch/issues.py close-drill --repo O/R
GitLab 後端（GITLAB-PORT T-05）：把 --repo O/R 換成 --backend gitlab --gitlab-url <…/api/v4> --project <數字 ID> [--confidential]；
  token 從環境變數 GITLAB_TOKEN 讀（不收 argv）。GitLab 建的 Issue 一律 confidential（寫死，--confidential 只是範本相容旗標、關不掉）。
stdout 最後一行 WATCH-ISSUES<TAB>OK|FAIL<TAB>說明；結束碼 OK 0、FAIL 1、用法 64。

去重規則（同一個 key 出現在多個 Issue 時選哪一個）：有開著的取開著的（多個開著的取編號最大的）；都已關閉則取編號最大的。
這條覆蓋「取編號最小」的舊想法，因為 open_if_closed 會替同一個 key 再開新 Issue。同一個 key 有兩個以上開著的 Issue 時記 problem。

安全：Token（GH_TOKEN／GITHUB_TOKEN；GitLab 是 GITLAB_TOKEN，放 PRIVATE-TOKEN 標頭）只放標頭，不進任何輸出；不經 proxy；不跟隨轉址（轉址算錯誤）；回應大小有上限。
"""
import argparse
import base64
import gzip
import hashlib
import http.client
import json
import os
import re
import sys
import time
import urllib.parse
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import publiccheck  # noqa: E402

PLAN_SCHEMA = "dumpling-watch-plan/1"
MAX_BODY = 60000
MAX_RESPONSE = 8 * 1024 * 1024
MAX_STATE_RAW = 32 * 1024 * 1024
WRITE_GAP = 1.0
MAX_WAIT = 60
RETRIES = 3
MARK_RE = re.compile(r"<!-- dumpling-watch key=([0-9a-f]{64}) mode=(real|drill) -->")
# 支援期限檢查（support.py，stateless plan）的 Issue：自己的標記與標籤，不是監控 Issue——
# 不能讓 read-state 算進 watch_keys（沒有狀態 Issue 時會擋住第一次基準，M8 預驗應修 1）
SUPPORT_MARK_RE = re.compile(r"<!-- dumpling-support key=([0-9a-f]{64}) mode=(real|drill) -->")
SUPPORT_LABEL = "support-period"
STATE_MARK_RE = re.compile(r"<!-- dumpling-watch-state mode=(real|drill) schema=1 -->")
KEY_RE = re.compile(r"[0-9a-f]{64}")
REPO_RE = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+")
LABEL_COLORS = {"kev": "d73a4a", "vendor-level": "d93f0b", "drill": "6e7781",
                "watch-state": "0075ca", "watch-state-drill": "0075ca"}
DEFAULT_COLOR = "ededed"


class Fail(Exception):
    pass


class Usage(Exception):
    pass


# ---------- GitHub API ----------
class Api:
    """所有 GitHub 呼叫都在這裡。測試只要覆寫 _raw()（回傳 (狀態碼, 標頭 dict, bytes)）。
    後端抽象：下面「Issue 層」的 list_issues／create_issue／edit_issue／add_comment／list_labels／create_label 是各後端要實作的介面；
    指令函式（cmd_*）只用這一層，不直接拼路徑。GitLabApi 繼承這個類別，覆寫標頭、分頁、rate limit 與這一層。"""

    kind = "github"
    url_label = "GITHUB_API_URL"

    def __init__(self, base=None, token=None, sleep=time.sleep, clock=time.monotonic, wall=time.time):
        self.base = (base or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        self.token = token if token is not None else (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or "")
        self.sleep, self.clock, self.wall = sleep, clock, wall
        self._last_write = None
        u = urllib.parse.urlsplit(self.base)
        if u.scheme not in ("https", "http") or not u.hostname:
            raise Fail(f"{self.url_label} 不是合法的網址")
        if u.scheme == "http" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise Fail(f"{self.url_label} 只有本機（測試）可以用 http：token 不能以明文送到別台")
        self.origin = (u.scheme, u.netloc)

    def _scrub(self, s):
        s = str(s)
        return s.replace(self.token, "***") if self.token else s

    def _raw(self, method, url, headers, body):
        u = urllib.parse.urlsplit(url)
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = cls(u.hostname, u.port, timeout=30)  # http.client 不看 proxy 環境變數
        try:
            path = u.path + ("?" + u.query if u.query else "")
            conn.request(method, path, body=body, headers=headers)
            r = conn.getresponse()
            data = r.read(MAX_RESPONSE + 1)
            return r.status, {k.lower(): v for k, v in r.getheaders()}, data
        finally:
            conn.close()

    def request(self, method, path_or_url, payload=None):
        url = path_or_url if path_or_url.startswith("http") else self.base + path_or_url
        u = urllib.parse.urlsplit(url)
        if (u.scheme, u.netloc) != self.origin:
            raise Fail("拒絕連到別的主機")
        headers = self._headers()
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        write = method != "GET"
        for attempt in range(RETRIES + 1):
            if write:
                self._space_write()
            try:
                status, hdr, data = self._raw(method, url, headers, body)
            except Fail:
                raise
            except Exception as e:
                raise Fail(self._scrub(f"{method} {u.path} 連線失敗（{type(e).__name__}）"))
            if write:
                self._last_write = self.clock()
            if len(data) > MAX_RESPONSE:
                raise Fail(f"{method} {u.path} 回應超過大小上限")
            if status in (301, 302, 303, 307, 308):
                raise Fail(f"{method} {u.path} 收到轉址（{status}），不跟隨")
            if status in (403, 429):
                wait = self._rate_wait(status, hdr, data)
                if wait is not None:
                    if attempt >= RETRIES:
                        raise Fail(f"{method} {u.path} 遇到 rate limit，重試 {RETRIES} 次仍失敗")
                    self.sleep(wait)
                    continue
            if status >= 400:
                msg = ""
                try:
                    msg = str(json.loads(data.decode("utf-8", "replace")).get("message", ""))[:120]
                except Exception:
                    pass
                err = Fail(self._scrub(f"{method} {u.path} 失敗：HTTP {status} {msg}".strip()))
                err.status = status          # 呼叫端要判斷狀態碼時用這個，不要比對訊息文字（訊息含伺服器回的 message）
                raise err
            if not data:
                return None, hdr
            try:
                return json.loads(data.decode("utf-8")), hdr
            except ValueError:
                raise Fail(f"{method} {u.path} 回應不是 JSON")
        raise Fail("不可能到這裡")

    def _headers(self):
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "dumpling-watch",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        return headers

    def _rate_wait(self, status, hdr, data):
        """是 rate limit 就回傳要等的秒數（最多 60），不是就回傳 None。"""
        ra = hdr.get("retry-after")
        if ra is not None:
            try:
                return min(MAX_WAIT, max(0, int(ra)))
            except ValueError:
                return MAX_WAIT
        if hdr.get("x-ratelimit-remaining") == "0":
            try:
                return min(MAX_WAIT, max(0, int(hdr.get("x-ratelimit-reset", "")) - int(self.wall())))
            except ValueError:
                return MAX_WAIT
        if status == 429 or b"rate limit" in data.lower():
            return MAX_WAIT
        return None

    def _space_write(self):
        if self._last_write is not None:
            d = WRITE_GAP - (self.clock() - self._last_write)
            if d > 0:
                self.sleep(d)

    def get_all(self, path):
        """跟 Link: rel="next" 分頁（只接受同主機）。"""
        out, url, pages = [], path, 0
        while url:
            data, hdr = self.request("GET", url)
            if not isinstance(data, list):
                raise Fail("列表回應不是陣列")
            out.extend(data)
            pages += 1
            if pages > 500:
                raise Fail("分頁過多")
            url = None
            for m in re.finditer(r'<([^>]+)>\s*;\s*rel="([^"]+)"', hdr.get("link", "")):
                if m.group(2) == "next":
                    url = m.group(1)
        return out

    # ---- Issue 層（GitHub 實作；GitLabApi 覆寫）。state 一律用 "open"／"closed"／"all"；Issue 一律回 GitHub 形狀的 dict
    # （number、title、body、state、updated_at、labels）。
    def list_issues(self, repo, label, state="all"):
        q = urllib.parse.urlencode({"labels": label, "state": state, "per_page": 100})
        return [i for i in self.get_all(f"/repos/{repo}/issues?{q}") if "pull_request" not in i]

    def create_issue(self, repo, title, body, labels):
        d, _ = self.request("POST", f"/repos/{repo}/issues", {"title": title, "body": body, "labels": labels})
        return d

    def edit_issue(self, repo, number, body=None, state=None, labels=None, was=None):
        """was＝呼叫端知道的目前狀態（GitLab 用它避免對已開著的 Issue 送 reopen）；GitHub 不用。"""
        payload = {}
        if body is not None:
            payload["body"] = body
        if state is not None:
            payload["state"] = state
        if labels is not None:
            payload["labels"] = labels
        d, _ = self.request("PATCH", f"/repos/{repo}/issues/{number}", payload)
        return d

    def add_comment(self, repo, number, body):
        self.create_note(repo, number, body)

    def create_note(self, repo, number, body):
        self.request("POST", f"/repos/{repo}/issues/{number}/comments", {"body": body})

    def list_notes(self, repo, number):
        """Issue 的留言（GitHub 原樣：id、body、user、author_association；沒有 system 欄位）。"""
        return self.get_all(f"/repos/{repo}/issues/{number}/comments?per_page=100")

    def edit_note(self, repo, number, note_id, body):
        self.request("PATCH", f"/repos/{repo}/issues/comments/{note_id}", {"body": body})

    def list_labels(self, repo):
        return [l["name"] for l in self.get_all(f"/repos/{repo}/labels?per_page=100")]

    def create_label(self, repo, name, color):
        self.request("POST", f"/repos/{repo}/labels", {"name": name, "color": color})


# ---------- GitLab API ----------
# 只用官方文件（docs.gitlab.com）有寫的端點與欄位；各頁對照見 docs/GITLAB-PORT.md T-05：
#   Issues：/api/issues/（列表 labels 逗號字串、state=opened|closed|all、回傳 iid／description／labels 字串陣列／updated_at；
#           新增 title／description／labels 逗號字串／confidential 預設 false；修改 description／state_event=close|reopen／labels 整組取代）
#   Notes：/api/notes/（POST …/issues/:issue_iid/notes，body 必填）　Labels：/api/labels/（POST name＋color，color 要 # 開頭）
#   分頁：/api/rest/（per_page 最大 100；Link rel=next；x-next-page）　rate limit：/administration/settings/user_and_ip_rate_limits/（429、Retry-After、RateLimit-Reset 是 epoch 秒）
# 行首（允許縮排：官方只說要「獨立一行」，沒說縮排行算不算）是 /指令 的行。驗證 S1：放寬到縮排也擋
# 行首的判定從嚴（#74 驗證建議 4）：\n 以外，\r、\v、\f、NEL、U+2028／U+2029 之後也算行首；縮排可以是空白、tab、NBSP、全形空白。
# 寧可誤擋。零寬字元、全形 ／ 開頭會不會被 GitLab 當成 quick action 沒有核對（GITLAB-PORT T-05 的內部驗證清單）
QUICK_ACTION_RE = re.compile(r"(?:^|[\r\x0b\x0c\x85\u2028\u2029])[ \t\u00a0\u3000]*/[A-Za-z_]+(\s|$)", re.M)
GITLAB_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*/api/v4$")
LOOPBACK_URL_RE = re.compile(r"^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*/api/v4$")


def gitlab_url_problem(url):
    """--gitlab-url 的格式檢查（同 collect.py 的規則：https，或測試用的本機 http；不收 userinfo、query、fragment；結尾是 /api/v4）。
    回傳問題說明，沒問題回傳 None。用法錯誤（結束碼 64），在連線之前就擋下。"""
    if not isinstance(url, str) or not (GITLAB_URL_RE.fullmatch(url) or LOOPBACK_URL_RE.fullmatch(url)):
        return "--gitlab-url 要是 https://<主機>[:埠][/路徑]/api/v4（即 CI_API_V4_URL；不含帳密、?、#）"
    return None


class GitLabApi(Api):
    kind = "gitlab"
    url_label = "--gitlab-url"
    # 每個 Issue 一律 confidential：寫死，沒有參數可以關（官方：confidential 預設 false，不帶就是專案成員都看得到）
    CONFIDENTIAL = True

    def __init__(self, base=None, token=None, **kw):
        if not base:
            raise Fail("GitLab 後端需要 --gitlab-url")
        token = token if token is not None else os.environ.get("GITLAB_TOKEN", "")
        super().__init__(base=base, token=token, **kw)
        if not urllib.parse.urlsplit(self.base).path.endswith("/api/v4"):
            raise Fail("--gitlab-url 要是 API 網址（…/api/v4，即 CI_API_V4_URL）")

    def _headers(self):
        headers = {"Accept": "application/json", "User-Agent": "dumpling-watch"}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token
        return headers

    def _rate_wait(self, status, hdr, data):
        # GitLab 的限流是 429（官方）；403 是權限不足，不重試。
        if status != 429:
            return None
        ra = hdr.get("retry-after")
        if ra is not None:
            try:
                return min(MAX_WAIT, max(0, int(ra)))
            except ValueError:
                return MAX_WAIT
        try:
            return min(MAX_WAIT, max(0, int(hdr.get("ratelimit-reset", "")) - int(self.wall())))
        except ValueError:
            return MAX_WAIT

    def get_all(self, path):
        """官方分頁：x-next-page（下一頁的頁碼）優先——只改 page 參數、不用伺服器給的網址（反向代理後 Link 可能是別的主機）；
        沒有 x-next-page 才用 Link rel=next（request() 仍會拒絕別的主機）。"""
        out, url, pages = [], path, 0
        while url:
            data, hdr = self.request("GET", url)
            if not isinstance(data, list):
                raise Fail("列表回應不是陣列")
            out.extend(data)
            pages += 1
            if pages > 500:
                raise Fail("分頁過多")
            url = None
            nxt = (hdr.get("x-next-page") or "").strip()
            if nxt:
                if not nxt.isdigit() or int(nxt) < 2:
                    raise Fail("x-next-page 不合法")
                u = urllib.parse.urlsplit(path)
                q = [(k, v) for k, v in urllib.parse.parse_qsl(u.query) if k != "page"] + [("page", nxt)]
                url = urllib.parse.urlunsplit(("", "", u.path, urllib.parse.urlencode(q), ""))
                continue
            for m in re.finditer(r'<([^>]+)>\s*;\s*rel="([^"]+)"', hdr.get("link", "")):
                if m.group(2) == "next":
                    url = m.group(1)
        return out

    @staticmethod
    def _text(s, what):
        """description／note 的 body：GitLab 會執行以 / 開頭的 quick action（官方 notes 頁：送出時執行並移除）。
        文件沒說程式碼區塊內會不會執行，所以含有這種行就不送（fail closed），不靠猜。"""
        if QUICK_ACTION_RE.search(s):
            raise Fail(f"{what}有以 / 開頭的行（GitLab quick action，可能被執行）：不送")
        return s

    @staticmethod
    def precheck(texts):
        """apply 在任何寫入之前呼叫：要送出的標題與內文都不能有 quick action 行（dry-run 也檢查；驗證 F1、#74 驗證應修 1）。"""
        for what, t in texts:
            if isinstance(t, str) and QUICK_ACTION_RE.search(t):
                raise Fail(f"{what}有以 / 開頭的行（GitLab quick action，可能被執行）：什麼都沒寫")

    @staticmethod
    def _labels(labels):
        for l in labels:
            if "," in l:
                raise Fail("標籤名稱不能含逗號（GitLab 的 labels 參數是逗號分隔）")
        return ",".join(labels)

    @staticmethod
    def _issue(d):
        if not isinstance(d, dict) or type(d.get("iid")) is not int:
            raise Fail("GitLab Issue 回應格式不符（沒有整數 iid）")
        return {"number": d["iid"], "title": d.get("title"), "body": d.get("description"),
                "state": "open" if d.get("state") == "opened" else "closed", "updated_at": d.get("updated_at"),
                "labels": d.get("labels") or [], "confidential": d.get("confidential"),
                "user": d.get("author") if isinstance(d.get("author"), dict) else {}}

    def list_issues(self, repo, label, state="all"):
        st = {"open": "opened", "closed": "closed", "all": "all"}[state]
        q = urllib.parse.urlencode({"labels": label, "state": st, "per_page": 100})
        return [self._issue(i) for i in self.get_all(f"/projects/{repo}/issues?{q}")]

    def search_issues(self, repo, text, state="all"):
        """GET /projects/:id/issues?search=…（官方 /api/issues/ 的 List project issues：search＝「Search project issues against their title and description」；
        不依標籤找，用來找標籤被拿掉的案件）。比對方式（子字串、斷詞、大小寫）文件沒寫，呼叫端要自己再過濾；confidential Issue 會不會列出來待內部驗證。"""
        st = {"open": "opened", "closed": "closed", "all": "all"}[state]
        q = urllib.parse.urlencode({"search": text, "state": st, "per_page": 100})
        return [self._issue(i) for i in self.get_all(f"/projects/{repo}/issues?{q}")]

    def get_issue(self, repo, number):
        """GET /projects/:id/issues/:issue_iid（官方 issues 頁；不存在或看不到時的狀態碼文件沒寫，呼叫端用 e.status == 404 判斷，待內部驗證）。"""
        if type(number) is not int or number <= 0:
            raise Fail("Issue 編號不合法")
        d, _ = self.request("GET", f"/projects/{repo}/issues/{number}")
        i = self._issue(d)
        if i["number"] != number:
            raise Fail(f"GitLab 回的 Issue 編號不符（要 #{number}）")
        return i

    def create_issue(self, repo, title, body, labels):
        d, _ = self.request("POST", f"/projects/{repo}/issues",
                            {"title": self._text(title, "Issue 標題"), "description": self._text(body, "Issue 內文"),
                             "labels": self._labels(labels), "confidential": True})
        # 伺服器沒照做（例如參數被忽略）就不能當作沒事：Issue 已建立但不是 confidential → FAIL，讓人去處理（驗證 S4）
        if not isinstance(d, dict) or d.get("confidential") is not True:
            raise Fail(f"GitLab 建立的 Issue #{d.get('iid') if isinstance(d, dict) else '?'} 不是 confidential：請立刻手動改成 confidential 或刪除")
        return self._issue(d)

    def edit_issue(self, repo, number, body=None, state=None, labels=None, was=None):
        payload = {}
        if body is not None:
            payload["description"] = self._text(body, "Issue 內文")
        if state is not None and state != was:
            payload["state_event"] = {"open": "reopen", "closed": "close"}[state]
        if labels is not None:
            payload["labels"] = self._labels(labels)
        if not payload:
            return None
        payload["confidential"] = True      # 改既有 Issue 時也確保是 confidential（例如狀態 Issue 是別人手動建的；驗證 S4）
        d, _ = self.request("PUT", f"/projects/{repo}/issues/{number}", payload)
        if not isinstance(d, dict) or d.get("confidential") is not True:      # 同建立：回應不是 confidential 就 FAIL（#74 驗證應修 3）
            raise Fail(f"GitLab Issue #{number} 修改後不是 confidential：請立刻手動改成 confidential")
        return self._issue(d)

    def create_note(self, repo, number, body):
        self.request("POST", f"/projects/{repo}/issues/{number}/notes", {"body": self._text(body, "留言")})

    # Notes：/api/notes/（GET／PUT …/issues/:issue_iid/notes[/:note_id]；回傳 id／body／author{id,username}／system／internal）。
    # 文件的列表參數只有 activity_filter、sort、order_by；per_page 靠 /api/rest/ 的通用分頁（沒有在 notes 頁列出，待內部驗證）。
    def list_notes(self, repo, number):
        out = []
        for n in self.get_all(f"/projects/{repo}/issues/{number}/notes?sort=asc&order_by=created_at&per_page=100"):
            if not isinstance(n, dict) or type(n.get("id")) is not int:
                raise Fail("GitLab 留言回應格式不符（沒有整數 id）")
            out.append({"id": n["id"], "body": n.get("body"), "user": n.get("author") if isinstance(n.get("author"), dict) else {},
                        "system": n.get("system") is True})
        return out

    def edit_note(self, repo, number, note_id, body):
        self.request("PUT", f"/projects/{repo}/issues/{number}/notes/{note_id}", {"body": self._text(body, "留言")})

    # Project members：/api/project_members/ 的 GET /projects/:id/members/all/:user_id（含繼承與受邀；回傳 access_level、state）。
    # 存取等級（同頁表格）：Guest 10、Planner 15、Reporter 20、Security Manager 25、Developer 30、Maintainer 40、Owner 50。
    # 不是成員時的狀態碼文件沒寫：404 當成「不是成員」（待內部驗證）；其他錯誤一律 FAIL（不猜）。
    def current_user(self):
        """GET /user（官方 /api/users/ 的 Get the current user）：token 自己的使用者。project access token 能不能用，文件沒寫（待內部驗證）。"""
        d, _ = self.request("GET", "/user")
        if not isinstance(d, dict) or type(d.get("id")) is not int:
            raise Fail("GET /user 的回應沒有整數 id")
        return d

    def member_access(self, repo, user_id):
        if type(user_id) is not int or user_id <= 0:
            return None
        try:
            d, _ = self.request("GET", f"/projects/{repo}/members/all/{user_id}")
        except Fail as e:
            if getattr(e, "status", None) == 404:      # T-10 驗證建議 5：用狀態碼判斷，不比對訊息
                return None
            raise
        if not isinstance(d, dict) or d.get("id") != user_id or type(d.get("access_level")) is not int or d.get("state") != "active":
            return None
        return d["access_level"]

    def list_labels(self, repo):
        return [l["name"] for l in self.get_all(f"/projects/{repo}/labels?per_page=100")]

    def create_label(self, repo, name, color):
        self.request("POST", f"/projects/{repo}/labels", {"name": name, "color": "#" + color.lstrip("#")})


# ---------- 標記、狀態 ----------
def parse_marker(body, mark_re=MARK_RE):
    """第一行必須完全符合標記；回傳 (key, mode) 或 None。"""
    if not isinstance(body, str):
        return None
    lines = body.splitlines()
    if not lines:
        return None
    m = mark_re.fullmatch(lines[0])
    return (m.group(1), m.group(2)) if m else None


def label_names(issue):
    return [l["name"] if isinstance(l, dict) else str(l) for l in issue.get("labels", [])]


def list_issues(api, repo, label, state="all"):
    return api.list_issues(repo, label, state)


def _note(problems, msg):
    if msg not in problems:
        problems.append(msg)


def watch_index(api, repo, problems, label="dumpling-watch", mark_re=MARK_RE):
    """回傳 {key: [{number,state,mode}, …]}（依編號排序）。標記不合的 Issue 記 problem、不納入。
    預設是監控 Issue（dumpling-watch）；支援期限的 Issue 用 label=support-period、mark_re=SUPPORT_MARK_RE。"""
    idx = {}
    for i in list_issues(api, repo, label):
        mk = parse_marker(i.get("body"), mark_re)
        if not mk:
            _note(problems, f"Issue #{i.get('number')} 有 {label} 標籤但第一行標記不合法，略過")
            continue
        idx.setdefault(mk[0], []).append({"number": i["number"], "state": i.get("state"), "mode": mk[1]})
    for key, lst in idx.items():
        lst.sort(key=lambda e: e["number"])
        if sum(1 for e in lst if e["state"] == "open") >= 2:
            _note(problems, f"key {key[:12]}… 同時有多個開著的 Issue：{[e['number'] for e in lst]}")
    return idx


def pick(entries):
    """去重：開著的優先，再取編號最大的。"""
    if not entries:
        return None
    opened = [e for e in entries if e["state"] == "open"]
    return max(opened or entries, key=lambda e: e["number"])


def state_label(mode):
    return "watch-state" if mode == "real" else "watch-state-drill"


def find_state_issue(api, repo, mode):
    found = list_issues(api, repo, state_label(mode))
    if len(found) > 1:
        raise Fail(f"同一個 mode 有 {len(found)} 個狀態 Issue：{sorted(i['number'] for i in found)}")
    return found[0] if found else None


def encode_state(state, mode, summary, urlsafe=False):
    """urlsafe：GitLab 用 URL-safe base64（- _ 取代 + /）：標準 base64 的行可能以 / 開頭，會被當成 quick action（驗證 F1）。
    GitHub 照舊用標準 base64（狀態格式不變）。decode_state 兩種都讀。"""
    raw = json.dumps(state, sort_keys=True, ensure_ascii=False).encode("utf-8")
    comp = gzip.compress(raw, mtime=0)
    b = (base64.urlsafe_b64encode(comp) if urlsafe else base64.b64encode(comp)).decode("ascii")
    block = "\n".join(b[i:i + 76] for i in range(0, len(b), 76))
    body = f"<!-- dumpling-watch-state mode={mode} schema=1 -->\n{summary}\n\n```\n{block}\n```\n"
    if len(body) > MAX_BODY:
        raise Fail(f"狀態內容 {len(body)} 字元，超過 {MAX_BODY} 上限（不截斷）")
    return body


def decode_state(body, mode=None):
    if not isinstance(body, str):
        raise Fail("狀態 Issue 內文是空的")
    lines = body.splitlines()
    m = STATE_MARK_RE.fullmatch(lines[0]) if lines else None
    if not m or (mode and m.group(1) != mode):
        raise Fail("狀態 Issue 第一行標記不合法或 mode 不符")
    blocks = re.findall(r"^```[^\n]*\n(.*?)\n```[ \t]*$", body, re.S | re.M)
    if len(blocks) != 1:
        raise Fail("狀態 Issue 內文要剛好一個程式碼區塊")
    try:
        enc = "".join(blocks[0].split())
        if re.search(r"[-_]", enc):         # URL-safe（GitLab 寫的）：不能同時有標準字母表的 + /
            if re.search(r"[+/]", enc):
                raise ValueError("混用兩種 base64 字母表")
            enc = enc.translate(str.maketrans("-_", "+/"))
        comp = base64.b64decode(enc, validate=True)
        d = zlib.decompressobj(31)
        raw = d.decompress(comp, MAX_STATE_RAW + 1)
        if len(raw) > MAX_STATE_RAW or not d.eof:
            raise ValueError("size")
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise Fail(f"狀態 Issue 內容解不開（{type(e).__name__}）")
    if not isinstance(obj, dict):
        raise Fail("狀態 JSON 不是物件")
    return obj


def sha(s):
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True, ensure_ascii=False, indent=1)
        f.write("\n")


# ---------- 標籤 ----------
class Labels:
    def __init__(self, api, repo, dry):
        self.api, self.repo, self.dry, self.known = api, repo, dry, None

    def ensure(self, names):
        if self.known is None:
            self.known = set(self.api.list_labels(self.repo))
        for n in names:
            if n not in self.known:
                if not self.dry:
                    self.api.create_label(self.repo, n, LABEL_COLORS.get(n, DEFAULT_COLOR))
                self.known.add(n)


# ---------- plan ----------
ACTION_OPS = ("open", "comment", "open_if_closed")      # plan 的 action 認得的 op；stateless plan 只能用 open
MAX_ACTIONS = 200       # match.py 一次最多：20 個 open＋1 個彙總＋留言＋健康 Issue；超過代表 compute 有問題
ALLOWED_LABELS = frozenset({"dumpling-watch", "kev", "vendor-level", "shipped", "development", "layer-bsp", "layer-os", "layer-product",
                            "demo", "summary", "attention", "drill", "watch-health", "support-period"})


def load_plan(path, want_mode=None):
    try:
        with open(path, encoding="utf-8") as f:
            plan = json.load(f)
    except (OSError, ValueError) as e:
        raise Fail(f"plan 讀不到或不是 JSON（{type(e).__name__}）")

    def bad(why):
        raise Fail("plan 不合契約：" + why)
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        bad("schema")
    if plan.get("mode") not in ("real", "drill"):
        bad("mode")
    if want_mode is not None and plan["mode"] != want_mode:
        bad(f"mode 是 {plan['mode']}，這一輪是 {want_mode}")
    st = plan.get("state")
    if isinstance(st, dict) and (st.get("schema") != 1 or (st.get("dumpling") or {}).get("mode") not in (None, plan["mode"])):
        bad("state 的 schema 或 dumpling.mode 不符")
    if plan.get("state") is not None and not isinstance(plan.get("state"), dict):
        bad("state")
    if plan.get("state") is None and plan.get("state_base") is not None:
        bad("state 是 null（不寫狀態）時 state_base 也必須是 null")
    # stateless：跟監控狀態無關的 plan（支援期限檢查 support.py，M8 B2）：不寫狀態、不做樂觀鎖，只執行 open（已經有含已關閉就不重複）；
    # Issue 用 dumpling-support 標記與 support-period 標籤（不是監控 Issue）
    if "demo" in plan and not isinstance(plan["demo"], bool):
        bad("demo")
    if "stateless" in plan and not isinstance(plan["stateless"], bool):
        bad("stateless")
    if plan.get("stateless"):
        if plan.get("state") is not None:
            bad("stateless 的 plan 不能帶 state")
        if any(not isinstance(a, dict) or a.get("op") != "open" for a in plan.get("actions") or []):
            bad("stateless 的 plan 只能有 open")
        if any(isinstance(a, dict) and isinstance(a.get("labels"), list) and "dumpling-watch" in a["labels"] for a in plan.get("actions") or []):
            bad("stateless 的 plan 不能用 dumpling-watch 標籤（支援期限的 Issue 不是監控 Issue）")
    sb = plan.get("state_base")
    if sb is not None:
        if (not isinstance(sb, dict) or type(sb.get("issue")) is not int
                or not isinstance(sb.get("updated_at"), str) or not isinstance(sb.get("body_sha256"), str)):
            bad("state_base")
    acts = plan.get("actions")
    if not isinstance(acts, list):
        bad("actions")
    if len(acts) > MAX_ACTIONS:
        bad(f"actions 有 {len(acts)} 個，超過上限 {MAX_ACTIONS}")
    for n, a in enumerate(acts):
        if not isinstance(a, dict) or a.get("op") not in ACTION_OPS:
            bad(f"actions[{n}].op")
        if not isinstance(a.get("key"), str) or not KEY_RE.fullmatch(a["key"]):
            bad(f"actions[{n}].key")
        if not isinstance(a.get("body"), str):
            bad(f"actions[{n}].body")
        if a["op"] == "comment":
            if not isinstance(a.get("reopen_if_closed", False), bool):
                bad(f"actions[{n}].reopen_if_closed")
        else:
            if not isinstance(a.get("title"), str) or not a["title"].strip():
                bad(f"actions[{n}].title")
            if not isinstance(a.get("labels"), list) or not all(isinstance(x, str) and x for x in a["labels"]):
                bad(f"actions[{n}].labels")
            extra = sorted(set(a["labels"]) - ALLOWED_LABELS)
            if extra:
                bad(f"actions[{n}].labels 有不在白名單的標籤 {extra[:3]}")
    return plan


def public_check(texts):
    try:
        rules = publiccheck.load_rules()
    except (OSError, publiccheck.RuleError) as e:
        raise Fail(f"公開檢查規則載入失敗：{e}")
    hits = []
    for name, t in texts:
        hits += [f"{name}: {p}" for p in publiccheck.check_text(t, rules)]
    if hits:
        raise Fail(f"公開檢查命中 {len(hits)} 筆，什麼都沒寫：" + "；".join(hits[:3]))


# ---------- 指令 ----------
def cmd_read_state(api, repo, mode, out):
    problems = []
    idx = watch_index(api, repo, problems)
    keys = {k for k, lst in idx.items() if any(e["mode"] == mode for e in lst)}
    n = len(keys)
    si = find_state_issue(api, repo, mode)
    base = {"issue": None, "updated_at": None, "body_sha256": None, "watch_issues": n, "watch_keys": sorted(keys)}
    state = None
    if si:
        state = decode_state(si.get("body"), mode)  # 解不開就 FAIL，不寫任何檔
        base.update(issue=si["number"], updated_at=si.get("updated_at"), body_sha256=sha(si.get("body")))
    os.makedirs(out, exist_ok=True)
    sp = os.path.join(out, "state.json")
    if os.path.exists(sp):
        os.remove(sp)
    if state is not None:
        write_json(sp, state)
    write_json(os.path.join(out, "state-base.json"), base)
    for p in problems:
        print("problem\t" + p)
    return f"狀態 Issue {'#' + str(si['number']) if si else '不存在'}；監控 Issue {n} 個"


def cmd_apply(api, repo, plan_path, dry, want_mode=None):
    plan = load_plan(plan_path, want_mode)
    mode = plan["mode"]
    problems, results = [], []
    # 樂觀鎖
    stateless = plan.get("stateless") is True
    cur = None if stateless else find_state_issue(api, repo, mode)
    sb = plan["state_base"]
    if stateless:
        pass                    # 不碰狀態 Issue（支援期限檢查和每日監控各自獨立，狀態 Issue 有沒有都不影響）
    elif sb is None:
        if cur:
            raise Fail(f"樂觀鎖：plan 說沒有狀態 Issue，現在有 #{cur['number']}")
    else:
        if not cur:
            raise Fail("樂觀鎖：plan 有狀態 Issue，現在找不到")
        if (cur["number"], cur.get("updated_at"), sha(cur.get("body"))) != (sb["issue"], sb["updated_at"], sb["body_sha256"]):
            raise Fail("樂觀鎖：狀態 Issue 的編號、updated_at 或內容已改變")
    # 先組好所有要寫的文字並檢查
    gen = plan.get("generated_at") if isinstance(plan.get("generated_at"), str) else ""
    st = plan["state"]
    no_state = st is None       # match.py 在「沒有基準」時只開提醒 Issue、不寫狀態（#32 驗證 F4）
    nm = len(st["matches"]) if not no_state and isinstance(st.get("matches"), (dict, list)) else 0
    summary = f"最後執行：{gen}；比對數：{nm}"
    too_big, state_body = None, None
    try:
        if not no_state:
            state_body = encode_state(st, mode, summary, urlsafe=getattr(api, "kind", "github") == "gitlab")
    except Fail as e:
        # 狀態太大：Issue 動作照樣執行（新的 KEV 與彙總 Issue 要開得出來），狀態不寫，最後明確 FAIL（PR #28 驗證應修 2）。
        # 下一輪從舊狀態重算：open 會因標記跳過，不會重複開；留言類可能重複。
        too_big, state_body = str(e), None
    texts = [] if no_state else [("狀態JSON", json.dumps(st, sort_keys=True, ensure_ascii=False)), ("狀態摘要", summary)]
    prepared = []
    mark_name, base_label, mark_re = ("dumpling-support", SUPPORT_LABEL, SUPPORT_MARK_RE) if stateless else ("dumpling-watch", "dumpling-watch", MARK_RE)
    for n, a in enumerate(plan["actions"]):
        a = dict(a)
        if a["op"] != "comment":
            a["body"] = f"<!-- {mark_name} key={a['key']} mode={mode} -->\n{a['body']}"
            names = list(a["labels"]) + [base_label] + (["drill"] if mode == "drill" else [])
            a["labels"] = list(dict.fromkeys(names))
            texts.append((f"actions[{n}].title", a["title"]))
            texts.append((f"actions[{n}].labels", "\n".join(a["labels"])))
        texts.append((f"actions[{n}].body", a["body"]))
        prepared.append(a)
    public_check(texts)
    if getattr(api, "kind", "github") == "gitlab":      # quick action：寫入前全部檢查（狀態內文＋每個動作的內文；dry-run 也是）
        GitLabApi.precheck([("狀態 Issue 內文", state_body)] + [(f"actions[{n}].body", a["body"]) for n, a in enumerate(prepared)]
                           + [(f"actions[{n}].title", a.get("title")) for n, a in enumerate(prepared)])

    labels = Labels(api, repo, dry)
    created = set()  # dry-run 用：本次「會建立」的 key
    ok = True
    try:
        for a in prepared:
            op, key = a["op"], a["key"]
            r = {"op": op, "key": key}
            results.append(r)
            if op in ("open", "open_if_closed"):
                idx = watch_index(api, repo, problems, base_label, mark_re)  # 開之前再列一次
                ent = pick([e for e in idx.get(key, []) if e["mode"] == mode])
                if key in created:
                    ent = {"number": None, "state": "open"}
                if op == "open" and ent:
                    r.update(result="skipped", reason="已有 Issue", issue=ent["number"])
                elif op == "open_if_closed" and ent and ent["state"] == "open":
                    if not dry and ent["number"]:
                        api.add_comment(repo, ent["number"], a["body"].split("\n", 1)[1])
                    r.update(result="commented", reason="已有開著的 Issue，改留言", issue=ent["number"])
                else:
                    labels.ensure(a["labels"])
                    num = None
                    if not dry:
                        d = api.create_issue(repo, a["title"], a["body"], a["labels"])
                        num = d["number"]
                    created.add(key)
                    r.update(result="would_open" if dry else "opened", issue=num)
            else:
                idx = watch_index(api, repo, problems)
                ent = pick([e for e in idx.get(key, []) if e["mode"] == mode])
                if not ent:
                    problems.append(f"comment 找不到 key {key[:12]}… 的 Issue")
                    r.update(result="problem", reason="找不到原 Issue")
                    continue
                if a.get("reopen_if_closed") and ent["state"] == "closed":
                    if not dry:
                        api.edit_issue(repo, ent["number"], state="open", was=ent["state"])
                    r["reopened"] = True
                if not dry:
                    api.add_comment(repo, ent["number"], a["body"])
                r.update(result="would_comment" if dry else "commented", issue=ent["number"])
        # 全部做完才寫狀態 Issue
        sres = {}
        if stateless:
            sres = {"result": "skipped", "reason": "stateless 的 plan：不寫狀態"}
        elif no_state:
            sres = {"result": "skipped", "reason": "plan 的 state 是 null（還沒有基準）：不寫狀態"}
        elif too_big:
            sres = {"result": "not_written", "reason": too_big}
            raise Fail(f"{too_big}：Issue 動作已執行，狀態沒有寫入（請修剪狀態或改成分段存放）")
        elif dry:
            sres = {"result": "would_update" if cur else "would_create"}
        elif cur:
            labels.ensure([state_label(mode)] + (["drill"] if mode == "drill" else []))
            api.edit_issue(repo, cur["number"], body=state_body, state="open", was=cur.get("state"))
            sres = {"result": "updated", "issue": cur["number"]}
        else:
            # 公開 repo（plan 的 demo）：狀態 Issue 也加 demo 標籤；標題與內文格式不變（read-state 靠 watch-state 標籤與第一行標記找）
            nl = [state_label(mode)] + (["drill"] if mode == "drill" else []) + (["demo"] if plan.get("demo") is True else [])
            labels.ensure(nl)
            d = api.create_issue(repo, f"dumpling-watch 狀態（{mode}）", state_body, nl)
            sres = {"result": "created", "issue": d["number"]}
    except Fail as e:
        ok = False
        problems.append("中斷：" + str(e))
        raise
    finally:
        res = {"schema": "dumpling-watch-apply-result/1", "mode": mode, "dry_run": dry, "ok": ok,
               "actions": results, "problems": problems, "state_issue": locals().get("sres", {})}
        try:
            write_json(os.path.join(os.path.dirname(os.path.abspath(plan_path)), "apply-result.json"), res)
        except OSError:
            pass
        for r in results:
            print("action\t" + json.dumps(r, sort_keys=True, ensure_ascii=False))
        for p in problems:
            print("problem\t" + p)
    cnt = {}
    for r in results:
        cnt[r["result"]] = cnt.get(r["result"], 0) + 1
    return ("（dry-run）" if dry else "") + "動作 " + "、".join(f"{k}={v}" for k, v in sorted(cnt.items())) + \
        f"；狀態 Issue {sres.get('result')}；problem {len(problems)}"


def cmd_close_drill(api, repo):
    """關閉演練 Issue，並把 dumpling-watch／watch-state-drill 標籤換成 *-done，讓下一次演練完全看不到這次的痕跡。
    只碰有 drill 標籤的 Issue；沒有 drill 標籤的絕不改標籤。"""
    closed = []
    targets = list_issues(api, repo, "dumpling-watch", "open")
    targets += list_issues(api, repo, "watch-state-drill", "open")
    swap = {"dumpling-watch": "dumpling-watch-drill-done", "watch-state-drill": "watch-state-drill-done"}
    labels = Labels(api, repo, False)
    seen = set()
    for i in targets:
        names = label_names(i)
        if i["number"] in seen or "drill" not in names:
            continue
        seen.add(i["number"])
        new = list(dict.fromkeys(swap.get(n, n) for n in names))
        labels.ensure([n for n in new if n.endswith("-done")])
        api.add_comment(repo, i["number"], "演練結束，自動關閉")
        api.edit_issue(repo, i["number"], state="closed", labels=new, was=i.get("state"))
        closed.append(i["number"])
    return f"關閉 {len(closed)} 個演練 Issue：{closed}"


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Usage(message)


PROJECT_ID_RE = re.compile(r"[0-9]{1,18}")


def main(argv=None, api=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("--help", "-h"):
        print(__doc__)      # 範本的 watch:* 用 `issues.py --help | grep -- --backend` 判斷有沒有 GitLab 後端
        return 0
    p = Parser(prog="issues.py", add_help=False)
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--backend", choices=["github", "gitlab"], default="github")
        sp.add_argument("--repo")                          # github：O/R（必填）
        sp.add_argument("--gitlab-url", dest="gitlab_url")  # gitlab：…/api/v4（CI_API_V4_URL）
        sp.add_argument("--project")                       # gitlab：數字 ID（CI_PROJECT_ID）
        sp.add_argument("--confidential", action="store_true")  # 範本相容旗標；GitLab 一律 confidential，這個旗標關不掉也不需要
    a = sub.add_parser("read-state", add_help=False)
    common(a)
    a.add_argument("--mode", required=True, choices=["real", "drill"])
    a.add_argument("--out", required=True)
    b = sub.add_parser("apply", add_help=False)
    common(b)
    b.add_argument("--plan", required=True)
    b.add_argument("--dry-run", action="store_true")
    b.add_argument("--mode", choices=["real", "drill"], help="這一輪的 mode：plan 的 mode 不同就 FAIL（workflow 一律給）")
    c = sub.add_parser("close-drill", add_help=False)
    common(c)
    try:
        args = p.parse_args(argv)
        if not args.cmd:
            raise Usage("需要子指令")
        if args.backend == "github":
            if not args.repo or not REPO_RE.fullmatch(args.repo):
                raise Usage("需要合法的 --repo")
            if args.gitlab_url or args.project:
                raise Usage("--gitlab-url／--project 只能搭配 --backend gitlab")
            target = args.repo
        else:
            if args.repo:
                raise Usage("--backend gitlab 不用 --repo，用 --project")
            if not args.gitlab_url or not args.project or not PROJECT_ID_RE.fullmatch(args.project):
                raise Usage("--backend gitlab 需要 --gitlab-url 與數字的 --project")
            why = gitlab_url_problem(args.gitlab_url)
            if why:
                raise Usage(why)
            target = args.project
    except (Usage, SystemExit) as e:
        print("用法：issues.py read-state|apply|close-drill [--backend github|gitlab] …（見檔頭）", file=sys.stderr)
        print(f"WATCH-ISSUES\tFAIL\t用法錯誤：{e}" if isinstance(e, Usage) else "WATCH-ISSUES\tFAIL\t用法錯誤")
        return 64
    try:
        if api is None:
            api = Api() if args.backend == "github" else GitLabApi(args.gitlab_url)
        if args.cmd == "read-state":
            msg = cmd_read_state(api, target, args.mode, args.out)
        elif args.cmd == "apply":
            msg = cmd_apply(api, target, args.plan, args.dry_run, args.mode)
        else:
            msg = cmd_close_drill(api, target)
    except Fail as e:
        print(f"WATCH-ISSUES\tFAIL\t{e}")
        return 1
    print(f"WATCH-ISSUES\tOK\t{msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
