#!/usr/bin/env python3
"""正式 Release 時，取得「同一個專案的前一個正式 Release」的報告，組成 CSAF 修補公告草稿要比較的資料夾（S4 接線，D-066）。

用法（python3 -I）：
  previous_release.py prepare --project <專案> --version <版本> --out <新資料夾> [--steps <pipeline-steps.tsv>]
環境變數：GITHUB_EVENT_NAME、GITHUB_REF_TYPE、GITHUB_REF（判斷是不是正式 Release 的 tag push）、GITHUB_REPOSITORY（<擁有者>/<repo>）、
  GITHUB_TOKEN（唯讀即可；沒有也行，只是 API 次數限制較低）、GITHUB_API_URL（預設 https://api.github.com；只有 https，或 127.0.0.1／localhost 的 http 才接受，給測試用）。
最後一行輸出 `previous-release: OK｜NOT_RUN｜GAP（說明）`，結束碼 0＝OK、4＝NOT_RUN、3＝GAP（和 run-step.sh 的步驟結束碼一致；這個腳本不會因為資料問題而 FAIL，
  意外的例外也當成 GAP，不擋 build／scan）。有給 --steps 時記一列 `pipeline-previous-release`（NOT_RUN 是 recorded 且說明以「僅供參考」開頭：不降低整體狀態；GAP 會降成 GAP）。

什麼時候是什麼狀態：
  NOT_RUN  不是正式 Release 的 tag push（dev、草稿、手動觸發；**不呼叫 API**）；或列出 Release 後沒有符合條件的前一個正式 Release（第一個正式 Release）。
  OK       找到前一個正式 Release，每一層的報告 zip 都下載、檢查、組好。
  GAP      找到了，但列出／下載／檢查／組裝失敗（附件缺、太大、zip 不合規則、VEX 格式不對、同一個版本排不出先後…）。**不當成沒有前一版**。

選前一版的規則（只看版本，不看建立時間）：
  - 同一個專案的 tag `<專案>/v…`；不是草稿、不是 prerelease、不是這次的 tag（同名 tag 被重打、這次的版本已經有 Release 時不會拿自己比）。
  - 版本比這次小的之中取最大的（比較「前一個」，不是「最近發布的」：補丁版在舊版本線上發時，前一版是它的上一個版本）。
  - 版本字串拆成數字與字母段：數字段比大小；多出來的段落是數字（v1.0 < v1.0.1）算較大；字母段不同（demo 與 rc）、一邊數字一邊字母、
    完全相同寫法不同（v1.0 與 v1.00）、同一個 tag 有多個正式 Release → **排不出先後 → GAP**，不猜。
資料夾版面（--out）：
  previous-release.json            狀態、說明、前一版的 tag、每一層的狀態（精靈 tools/wizard/cra-scan.py 讀它）
  <名稱>/vex.cdx.json、summary.json  <名稱> ＝精靈的 --name（<專案>、<專案>-bsp、<專案>-os…），取自 report-<專案>-<版本><後綴>.zip 裡的
                                   `報告/交給PM/VEX/vex.cdx.json`、`報告/內部存檔/summary.json`（csaf_advisory 只讀舊版的這兩個檔；舊版的 SBOM 不用，所以不下載）。
下載的內容一律當成不可信資料：附件與 zip 有大小上限、API 回應有大小上限；zip 只用名稱精確比對的兩個成員（讀進記憶體、寫成固定檔名），
  zip 裡有路徑穿越、絕對路徑、符號連結、特殊檔案、重複名稱、加密成員就整個不用（GAP）；GitHub 的下載網址不從回應取，用 API 路徑自己組；
  轉址到別的主機時不帶 Authorization。每個附件有整體時間上限（慢速涓滴的下載會中止、刪掉暫存檔、該層記 GAP）。
暫時性錯誤（5xx、429、連線錯誤）最多試 5 次，間隔 10、30、60、60 秒；回應有 Retry-After 時照它（有上限）。4xx（429 除外）不重試。
  正式 Release 不能重跑：一次失敗那個 tag 就永久記 GAP，所以寧可多等。這些值都能用環境變數覆寫（測試設成 0）：
  DUMPLING_PREV_DOWNLOAD_DEADLINE（每個附件的整體時間上限，秒，預設 600）、DUMPLING_PREV_RETRIES（嘗試次數，預設 5）、
  DUMPLING_PREV_RETRY_DELAYS（逗號分隔的退避秒數，預設 10,30,60；次數比清單長時沿用最後一個）、DUMPLING_PREV_RETRY_AFTER_MAX（Retry-After 的上限秒數，預設 120）。
"""
import argparse
import datetime
import email.utils
import hashlib
import http.client
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import step_rows  # noqa: E402

STEP = "previous-release"
MANIFEST = "previous-release.json"
SCHEMA = "dumpling-previous-release/1"
VEX_MEMBER = "報告/交給PM/VEX/vex.cdx.json"
SUMMARY_MEMBER = "報告/內部存檔/summary.json"
EXIT = {"OK": 0, "GAP": 3, "NOT_RUN": 4}
LIMITS = {
    "zip": 300 << 20,          # 單一報告 zip（Jetson 完整版約 12 MB）
    "total": 900 << 20,        # 所有層的 zip 加起來
    "member": 128 << 20,       # zip 裡 vex.cdx.json／summary.json 單一檔案（同 csaf_advisory 的 MAX_INPUT）
    "entries": 20000,          # zip 的成員數
    "unpacked": 2 << 30,       # zip 宣告的解開後總大小（只讀兩個成員，但太大的 zip 一律不用）
    "api": 20 << 20,           # 列出 Release 的單頁回應
    "pages": 30,               # 每頁 100 個 Release
}
TIMEOUT = 120              # 單一 socket 操作的逾時
DOWNLOAD_DEADLINE = 600    # 每個附件（含重試與等待）的整體時間上限，秒；實際最多再多一個 TIMEOUT（卡在一次 recv 時）
RETRIES = 5                # 暫時性錯誤（5xx、429、連線錯誤）嘗試次數
RETRY_DELAYS = (10, 30, 60)    # 第 n 次失敗後等的秒數；次數比清單長時沿用最後一個
RETRY_AFTER_MAX = 120      # 回應的 Retry-After 最多照這麼多秒
ENV_DEADLINE, ENV_RETRIES = "DUMPLING_PREV_DOWNLOAD_DEADLINE", "DUMPLING_PREV_RETRIES"
ENV_DELAYS, ENV_AFTER_MAX = "DUMPLING_PREV_RETRY_DELAYS", "DUMPLING_PREV_RETRY_AFTER_MAX"
_sleep = time.sleep                                  # 測試換掉它（不真的等；不能換 time.sleep，那是全域的）
LOOPBACK = ("127.0.0.1", "localhost", "::1")      # 測試用：只有這幾個主機可以用 plain http
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
VERSION_RE = re.compile(r"v[A-Za-z0-9][A-Za-z0-9._+-]{0,79}")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")


class PrevError(Exception):
    """這次的狀態是 GAP（找到了前一版，但資料取不到或不能用）；說明寫進狀態行與 manifest。"""


# ---------------------------------------------------------------- 是不是正式 Release

def official_tag_push(env, project, version):
    """正式 Release ＝ 這個 tag 的 push（release.yml 的 push 觸發）。dev 分支的 push、排程、手動觸發（包括手動輸入 tag 名稱建草稿）都不是。
    → (bool, 說明)。"""
    ev, rt, ref = env.get("GITHUB_EVENT_NAME", ""), env.get("GITHUB_REF_TYPE", ""), env.get("GITHUB_REF", "")
    if ev != "push" or rt != "tag":
        return False, "不是正式 Release 的 tag push（event=%s、ref_type=%s）" % (_c(ev, 30) or "沒有", _c(rt, 30) or "沒有")
    if ref != "refs/tags/%s/%s" % (project, version):
        return False, "觸發的 tag 不是這次要掃描的 %s/%s" % (project, version)
    return True, ""


def _c(v, n=200):
    """外部字串進輸出前：去掉控制字元、截斷。"""
    return "".join(ch for ch in str(v) if ch.isprintable())[:n]


_ZIP_NAME_OK = re.compile(r"[A-Za-z0-9._/\-\u3400-\u4dbf\u4e00-\u9fff]")


def _zn(v, n=80):
    """來自 zip 的成員名稱進輸出（步驟說明、notes.md、Release 說明）前：只留 [A-Za-z0-9._/-] 和中文，其他字元（Markdown、HTML、控制字元、其他文字）換成 ?，再截斷。"""
    return "".join(ch if _ZIP_NAME_OK.fullmatch(ch) else "?" for ch in str(v))[:n]


def _env_num(environ, name, default, cast=float, lo=0):
    """環境變數的數字覆寫：沒設、不是數字、小於 lo → 預設值（不因為設錯就整個失敗）。"""
    v = (environ or {}).get(name)
    if v is None or str(v).strip() == "":
        return default
    try:
        x = cast(str(v).strip())
    except ValueError:
        return default
    return x if x >= lo and x == x and x != float("inf") else default


def _env_delays(environ, default):
    v = (environ or {}).get(ENV_DELAYS)
    if v is None or str(v).strip() == "":
        return tuple(default)
    try:
        out = tuple(float(t) for t in str(v).split(",") if t.strip())
    except ValueError:
        return tuple(default)
    return out if out and all(0 <= x < float("inf") for x in out) else tuple(default)


# ---------------------------------------------------------------- 版本排序

def _tokens(v):
    v = re.sub(r"^[vV](?=\d)", "", str(v))
    return [int(t) if t.isdigit() else t.lower() for t in re.findall(r"\d+|[A-Za-z]+", v)]


def compare(a, b):
    """版本字串比較 → -1（a 較小）、0（相同）、1（a 較大）、None（排不出先後：不猜）。
    數字段比大小；一邊多出來的段落是數字才算較大（v1.0 < v1.0.1），是字母（demo、rc…）就排不出；兩邊不同的字母段、一邊數字一邊字母也排不出。
    段落完全相同但字串不同（v1.0 與 v1.00、V1.0）→ 0，由呼叫端當成重複。"""
    ta, tb = _tokens(a), _tokens(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        return None
    if len(ta) == len(tb):
        return 0
    longer = ta[len(tb):] if len(ta) > len(tb) else tb[len(ta):]
    if not isinstance(longer[0], int):
        return None
    return 1 if len(ta) > len(tb) else -1


def select_previous(releases, project, version):
    """GitHub 的 Release 清單（不可信資料）→ (previous release dict 或 None, 說明, 統計 dict)。
    排不出先後、同一個 tag 有多個正式 Release → 丟 PrevError（GAP）。"""
    cur_tag = "%s/%s" % (project, version)
    prefix = project + "/"
    stats = {"total": 0, "drafts": 0, "prereleases": 0, "other_projects": 0, "malformed": 0, "same_tag": 0, "newer": 0}
    by_tag, ambiguous = {}, []
    for r in releases:
        stats["total"] += 1
        tag = r.get("tag_name") if isinstance(r, dict) else None
        if not isinstance(tag, str) or not tag.startswith(prefix):
            stats["other_projects"] += 1
            continue
        ver = tag[len(prefix):]
        if not VERSION_RE.fullmatch(ver):
            stats["other_projects"] += 1          # dev/<專案> 之類不是 <專案>/v… 的 tag
            continue
        if not isinstance(r.get("draft"), bool) or not isinstance(r.get("prerelease"), bool):
            stats["malformed"] += 1               # 草稿／預發行的旗標讀不出來：不當成正式 Release，也不默默略過（統計裡有）
            continue
        if r["draft"]:
            stats["drafts"] += 1
            continue
        if r["prerelease"]:
            stats["prereleases"] += 1
            continue
        if tag == cur_tag:
            stats["same_tag"] += 1
            continue
        by_tag.setdefault(tag, []).append(r)
    for tag, rs in by_tag.items():
        if len(rs) > 1:
            raise PrevError("同一個 tag %s 有 %d 個正式 Release，不猜哪一個是前一版" % (_c(tag, 100), len(rs)))
    best = None
    for tag, (r,) in sorted(by_tag.items()):
        ver = tag[len(prefix):]
        c = compare(version, ver)
        if c == 1:
            if best is None:
                best = (ver, r)
                continue
            cb = compare(ver, best[0])
            if cb is None or cb == 0:
                raise PrevError("版本 %s 與 %s 排不出先後，不猜哪一個是前一版" % (_c(ver, 80), _c(best[0], 80)))
            if cb == 1:
                best = (ver, r)
        elif c == -1:
            stats["newer"] += 1
        else:                                     # None（排不出）或 0（寫法不同的同一版）：之後看它會不會比目前選的前一版更前
            ambiguous.append(ver)
    for ver in ambiguous:
        if best is None or compare(ver, best[0]) != -1:
            raise PrevError("版本 %s 與這次的 %s 排不出先後（或寫法不同的同一版），不猜哪一個是前一版" % (_c(ver, 80), _c(version, 80)))
    if best is None:
        return None, "沒有前一個正式 Release（共 %d 個 Release：草稿 %d、預發行 %d、這個專案其他版本比這次新 %d、同一個 tag %d）" % (
            stats["total"], stats["drafts"], stats["prereleases"], stats["newer"], stats["same_tag"]), stats
    return best[1], "前一個正式 Release：%s/%s" % (project, best[0]), stats


# ---------------------------------------------------------------- GitHub API

class _Redirect(urllib.request.HTTPRedirectHandler):
    """轉址（GitHub 的附件下載會轉到簽名網址）：換主機就不帶 Authorization；只接受 https（或測試用、而且轉去的主機是 loopback 的 http）。"""
    def __init__(self, allow_http):
        self.allow_http = allow_http

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        if u.scheme != "https" and not (self.allow_http and u.scheme == "http" and u.hostname in LOOPBACK):
            raise urllib.error.URLError("轉址到不接受的網址（scheme %s）" % _c(u.scheme, 10))
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            for h in [k for k in new.headers if k.lower() == "authorization"]:
                del new.headers[h]
            new.unredirected_hdrs.pop("Authorization", None)
        return new


class GitHub:
    """唯讀 GitHub API 用戶端。下載網址用 API 路徑自己組，不用回應裡的網址。"""
    def __init__(self, repo, token=None, base="https://api.github.com", limits=None, retries=None, delay=None, deadline=None,
                 retry_after_max=None, environ=None):
        if not REPO_RE.fullmatch(repo or ""):
            raise PrevError("GITHUB_REPOSITORY 格式不對")
        u = urllib.parse.urlsplit(base)
        loop = u.scheme == "http" and u.hostname in LOOPBACK
        if not (u.scheme == "https" or loop) or not u.hostname or u.username or u.password or u.query or u.fragment:
            raise PrevError("GITHUB_API_URL 只接受 https（測試用：127.0.0.1／localhost 的 http）")
        self.repo, self.token, self.base = repo, token or None, base.rstrip("/")
        self.limits = dict(LIMITS, **(limits or {}))
        env = os.environ if environ is None else environ
        self.retries = retries if retries is not None else _env_num(env, ENV_RETRIES, RETRIES, int, 1)
        self.delays = (delay,) if delay is not None else _env_delays(env, RETRY_DELAYS)
        self.deadline = deadline if deadline is not None else (_env_num(env, ENV_DEADLINE, DOWNLOAD_DEADLINE) or DOWNLOAD_DEADLINE)
        self.retry_after_max = retry_after_max if retry_after_max is not None else _env_num(env, ENV_AFTER_MAX, RETRY_AFTER_MAX)
        self.opener = urllib.request.build_opener(_Redirect(loop))

    def _wait_for(self, n, headers):
        """第 n 次失敗（從 0 算）之後要等幾秒：有 Retry-After（秒數或 HTTP 日期）就照它、不超過上限；沒有就照退避清單。"""
        ra = headers.get("Retry-After") if headers is not None else None
        if ra:
            ra, secs = ra.strip(), None
            if ra.isascii() and ra.isdigit() and len(ra) < 10:
                secs = int(ra)
            else:
                try:
                    secs = email.utils.parsedate_to_datetime(ra).timestamp() - time.time()
                except (TypeError, ValueError, IndexError, OverflowError):
                    secs = None
            if secs is not None:
                return max(0.0, min(secs, self.retry_after_max))
        return self.delays[min(n, len(self.delays) - 1)]

    def _open(self, url, accept, deadline=None):
        """開啟網址；暫時性錯誤（5xx、429、連線錯誤）重試。deadline（time.monotonic 的時間點）到了就不再等、不再試。"""
        h = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "dumpling-previous-release"}
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        last = None
        for n in range(self.retries):
            hdrs = None
            try:
                return self.opener.open(urllib.request.Request(url, headers=h), timeout=TIMEOUT)
            except urllib.error.HTTPError as e:
                last, hdrs = "HTTP %d" % e.code, e.headers
                e.close()
                if e.code < 500 and e.code != 429:
                    break
            except (urllib.error.URLError, OSError) as e:
                last = type(e).__name__
            if n + 1 < self.retries:
                wait = self._wait_for(n, hdrs)
                if deadline is not None and time.monotonic() + wait >= deadline:
                    raise PrevError("GitHub API 失敗（%s），再等下去會超過時間上限" % last)
                _sleep(wait)
        raise PrevError("GitHub API 失敗（%s）" % last)

    def list_releases(self):
        """所有 Release（分頁）。頁數用完還有下一頁、回應太大、不是 JSON 清單 → PrevError。"""
        out = []
        for page in range(1, self.limits["pages"] + 1):
            url = "%s/repos/%s/releases?per_page=100&page=%d" % (self.base, self.repo, page)
            try:
                with self._open(url, "application/vnd.github+json") as resp:
                    raw = resp.read(self.limits["api"] + 1)
            except (OSError, http.client.HTTPException) as e:
                raise PrevError("讀取 Release 清單中斷（%s）" % type(e).__name__)
            if len(raw) > self.limits["api"]:
                raise PrevError("列出 Release 的回應太大")
            try:
                doc = json.loads(raw)
            except (ValueError, RecursionError):
                raise PrevError("列出 Release 的回應不是 JSON")
            if not isinstance(doc, list):
                raise PrevError("列出 Release 的回應不是清單")
            out += doc
            if len(doc) < 100:
                return out
        raise PrevError("Release 超過 %d 個，沒有列完" % (self.limits["pages"] * 100))

    def download(self, asset_id, dest, max_size):
        """附件 → dest（新檔，O_EXCL、0600）；超過 max_size 就停止並刪掉。→ (位元組數, sha256)。"""
        if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0:
            raise PrevError("附件 id 不合規則")
        url = "%s/repos/%s/releases/assets/%d" % (self.base, self.repo, asset_id)
        try:
            return self._download(url, dest, max_size)
        except (OSError, http.client.HTTPException) as e:
            raise PrevError("下載附件中斷（%s）" % type(e).__name__)

    def _download(self, url, dest, max_size):
        h, n = hashlib.sha256(), 0
        deadline = time.monotonic() + self.deadline
        with self._open(url, "application/octet-stream", deadline) as resp:
            cl = resp.headers.get("Content-Length")
            if cl and cl.isdigit() and int(cl) > max_size:
                raise PrevError("附件太大（%s 位元組，上限 %d）" % (cl, max_size))
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as f:
                    while True:
                        if time.monotonic() >= deadline:
                            raise PrevError("下載附件超過時間上限（%g 秒），中止" % self.deadline)
                        b = resp.read1(1 << 16)       # read1：一次 recv 就回來，涓滴的下載才有機會檢查時間（read 會等到湊滿才回）
                        if not b:
                            break
                        n += len(b)
                        if n > max_size:
                            raise PrevError("附件太大（超過上限 %d 位元組）" % max_size)
                        h.update(b)
                        f.write(b)
            except BaseException:
                try:
                    os.unlink(dest)
                except OSError:
                    pass
                raise
        return n, h.hexdigest()


# ---------------------------------------------------------------- 報告 zip（不可信）

def check_zip(zf, limits):
    """zip 整個不合規則就丟 PrevError。只看名稱與屬性，不解開。"""
    infos = zf.infolist()
    if len(infos) > limits["entries"]:
        raise PrevError("zip 的成員太多（%d）" % len(infos))
    seen, total = set(), 0
    for i in infos:
        n = i.filename
        if not n or "\x00" in n or "\\" in n or n.startswith("/") or re.match(r"^[A-Za-z]:", n) or ".." in n.split("/"):
            raise PrevError("zip 有不合規則的路徑（%s）" % _zn(n, 80))
        if n in seen:
            raise PrevError("zip 有重複的成員名稱（%s）" % _zn(n, 80))
        seen.add(n)
        kind = (i.external_attr >> 16) & 0o170000
        if kind == 0o120000:
            raise PrevError("zip 有符號連結（%s）" % _zn(n, 80))
        if kind in (0o020000, 0o060000, 0o010000, 0o140000):
            raise PrevError("zip 有特殊檔案（%s）" % _zn(n, 80))
        if i.flag_bits & 0x1:
            raise PrevError("zip 有加密的成員")
        total += i.file_size
    if total > limits["unpacked"]:
        raise PrevError("zip 解開後太大（宣告 %d 位元組）" % total)


def read_member(zf, name, cap):
    """名稱精確相同的成員 → bytes；沒有 → None；超過 cap → PrevError。"""
    try:
        info = zf.getinfo(name)
    except KeyError:
        return None
    if info.file_size > cap:
        raise PrevError("zip 裡的 %s 太大（%d 位元組，上限 %d）" % (name.rsplit("/", 1)[-1], info.file_size, cap))
    with zf.open(info) as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise PrevError("zip 裡的 %s 太大" % name.rsplit("/", 1)[-1])
    return data


def load_json(data, what):
    try:
        return json.loads(data)
    except (ValueError, RecursionError, UnicodeDecodeError):
        raise PrevError("%s 不是 JSON" % what)


def build_layer(zip_path, dest_dir, limits):
    """報告 zip → dest_dir/vex.cdx.json（必要）、summary.json（有的話）。→ (說明 dict)。不合規則 → PrevError，dest_dir 不留半成品。"""
    try:
        with zipfile.ZipFile(zip_path) as zf:
            check_zip(zf, limits)
            vex = read_member(zf, VEX_MEMBER, limits["member"])
            summ = read_member(zf, SUMMARY_MEMBER, limits["member"])
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, OSError, ValueError) as e:
        raise PrevError("報告 zip 讀不了（%s）" % type(e).__name__)
    if vex is None:
        raise PrevError("報告 zip 裡沒有 %s" % VEX_MEMBER)
    v = load_json(vex, "zip 裡的 vex.cdx.json")
    if not isinstance(v, dict) or v.get("bomFormat") != "CycloneDX" or not isinstance(v.get("vulnerabilities"), list):
        raise PrevError("zip 裡的 vex.cdx.json 不是 CycloneDX VEX（沒有 vulnerabilities 清單）")
    if summ is not None and not isinstance(load_json(summ, "zip 裡的 summary.json"), dict):
        raise PrevError("zip 裡的 summary.json 不是物件")
    os.mkdir(dest_dir, 0o700)
    try:
        info = {"vex_sha256": hashlib.sha256(vex).hexdigest(), "statements": len(v["vulnerabilities"]), "summary": summ is not None}
        for fname, data in (("vex.cdx.json", vex), ("summary.json", summ)):
            if data is None:
                continue
            fd = os.open(os.path.join(dest_dir, fname), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        if summ is not None:
            info["summary_sha256"] = hashlib.sha256(summ).hexdigest()
    except BaseException:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise
    return info


# ---------------------------------------------------------------- 主流程

def layer_assets(release, project, prev_version):
    """前一版 Release 的附件 → {層名稱: asset dict}。附件名稱是 report-<專案>-<版本><後綴>.zip（後綴空白、-bsp、-os…；platform_scan.collect 的命名），
    層名稱 ＝ <專案><後綴>（也就是精靈的 --name）。同一個層名稱有多個附件 → 值是 None（呼叫端記 GAP）。"""
    pat = re.compile(r"report-%s-%s(-[A-Za-z0-9]{1,20})?\.zip" % (re.escape(project), re.escape(prev_version)))
    out = {}
    assets = release.get("assets")
    for a in assets if isinstance(assets, list) else []:
        m = pat.fullmatch(a.get("name")) if isinstance(a, dict) and isinstance(a.get("name"), str) else None
        if m:
            key = project + (m.group(1) or "")
            out[key] = None if key in out else a
    return out


def _write_manifest(out, doc):
    tmp = os.path.join(out, MANIFEST + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(tmp, os.path.join(out, MANIFEST))


def prepare(project, version, out, env=None, client=None, limits=None):
    """→ (狀態 OK｜NOT_RUN｜GAP, 說明, manifest dict)。out 會建起來並寫 previous-release.json（NOT_RUN、GAP 也寫，精靈靠它分辨）。"""
    env = os.environ if env is None else env
    lim = dict(LIMITS, **(limits or {}))
    if os.path.lexists(out):
        if os.path.islink(out) or not os.path.isdir(out) or (os.listdir(out) and not os.path.isfile(os.path.join(out, MANIFEST))):
            raise ValueError("%s 已存在而且不是這個腳本上一次的輸出，不覆蓋" % out)
        shutil.rmtree(out)
    os.makedirs(out, mode=0o700)
    doc = {"schema": SCHEMA, "status": "GAP", "note": "", "project": project, "version": version, "previous_tag": None,
           "previous_version": None, "release_id": None, "layers": {},
           "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    work = os.path.join(out, ".work")
    try:
        ok, why = official_tag_push(env, project, version)
        if not ok:
            doc.update(status="NOT_RUN", note="僅供參考：%s，沒有找前一個正式 Release（不呼叫 GitHub API）" % why)
            return "NOT_RUN", doc["note"], doc
        if not NAME_RE.fullmatch(project or "") or not VERSION_RE.fullmatch(version or ""):
            raise PrevError("專案或版本的格式不對（%s／%s），沒辦法找前一版" % (_c(project, 40), _c(version, 40)))
        if client is None:
            client = GitHub(env.get("GITHUB_REPOSITORY", ""), env.get("GITHUB_TOKEN") or env.get("GH_TOKEN"),
                            env.get("GITHUB_API_URL") or "https://api.github.com", lim, environ=env)
        rel, note, stats = select_previous(client.list_releases(), project, version)
        if rel is None:
            doc.update(status="NOT_RUN", note="僅供參考：" + note)
            return "NOT_RUN", doc["note"], doc
        prev_ver = rel["tag_name"][len(project) + 1:]
        doc.update(previous_tag=rel["tag_name"], previous_version=prev_ver, release_id=rel.get("id") if isinstance(rel.get("id"), int) else None)
        assets = layer_assets(rel, project, prev_ver)
        if not assets:
            raise PrevError("%s 沒有 report-%s-%s….zip 這類的報告附件，無法和它比較" % (_c(rel["tag_name"], 100), project, prev_ver))
        os.mkdir(work, 0o700)
        total, bad = 0, 0
        for name in sorted(assets):
            a = assets[name]
            ent = {"asset": a.get("name") if isinstance(a, dict) else None}
            doc["layers"][name] = ent
            try:
                if a is None:
                    raise PrevError("同名的附件有好幾個")
                size = a.get("size")
                if a.get("state") != "uploaded" or not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                    raise PrevError("附件還沒上傳完或大小不對")
                if size > lim["zip"]:
                    raise PrevError("附件太大（%d 位元組，上限 %d）" % (size, lim["zip"]))
                if total + size > lim["total"]:
                    raise PrevError("所有層的報告加起來超過上限 %d 位元組" % lim["total"])
                zp = os.path.join(work, name + ".zip")
                n, sha = client.download(a.get("id"), zp, min(lim["zip"], lim["total"] - total))
                total += n
                ent["zip_sha256"] = sha
                if n != size:
                    raise PrevError("下載的大小（%d）和 Release 記的（%d）不同" % (n, size))
                ent.update(build_layer(zp, os.path.join(out, name), lim))
                ent.update(status="OK", note="")
            except PrevError as e:
                ent.update(status="GAP", note=str(e))
                bad += 1
            finally:
                try:
                    os.unlink(os.path.join(work, name + ".zip"))
                except OSError:
                    pass
        names = ", ".join(sorted(assets))
        if bad:
            bads = "；".join("%s：%s" % (k, v["note"]) for k, v in sorted(doc["layers"].items()) if v["status"] != "OK")
            raise PrevError("%s 有 %d／%d 層組不起來（%s）" % (_c(rel["tag_name"], 100), bad, len(assets), bads))
        doc.update(status="OK", note="前一個正式 Release %s，%d 層：%s" % (_c(rel["tag_name"], 100), len(assets), names))
        return "OK", doc["note"], doc
    except PrevError as e:
        doc.update(status="GAP", note=str(e))
        return "GAP", doc["note"], doc
    except Exception as e:      # 意外的錯誤也要照實記成 GAP：這個步驟不擋 build／scan，但不能默默當成沒有前一版
        doc.update(status="GAP", note="取得前一個正式 Release 時發生意外（%s）" % type(e).__name__)
        return "GAP", doc["note"], doc
    finally:
        shutil.rmtree(work, ignore_errors=True)
        _write_manifest(out, doc)


def main(argv=None):
    ap = argparse.ArgumentParser(description="取得前一個正式 Release 的報告（CSAF 修補公告草稿的比較對象）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--project", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--steps", help="pipeline-steps.tsv：記一列 pipeline-previous-release")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    try:
        status, note, _ = prepare(a.project, a.version, a.out)
    except ValueError as e:
        print("previous-release: FAIL（%s）" % e, file=sys.stderr)
        return 64
    except OSError as e:      # 資料夾建不起來、manifest 寫不進去：不擋 build／scan，但照實記 GAP（精靈沒有 manifest 時也會記 GAP）
        status, note = "GAP", "前一個正式 Release 的資料夾寫不出來（%s）" % type(e).__name__
    line = "previous-release: %s（%s）" % (status, note)
    print(line)
    if a.steps:
        try:
            step_rows.append_row(a.steps, STEP, status, EXIT[status], note, recorded=status == "NOT_RUN")
        except (OSError, ValueError) as e:
            print("previous-release: GAP（pipeline-steps.tsv 寫不進去：%s）" % type(e).__name__, file=sys.stderr)
            return 3
    return EXIT[status]


if __name__ == "__main__":
    sys.exit(main())
