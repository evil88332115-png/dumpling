#!/usr/bin/env python3
"""collect.py（每日監控 4a）：收集 GitHub Release 附件，輸出 inventory.json。契約見 docs/WATCH.md 3.1。

用法：
  python3 -I pipeline/watch/collect.py (--repo <owner/repo> | --from-dir <資料夾> | --backend gitlab --gitlab-url <…/api/v4> --project <數字 ID>)
      --out <工作資料夾> [--max-asset-mb 200]
  GitLab 後端（GITLAB-PORT T-05）：token 從環境變數 GITLAB_TOKEN 讀（PRIVATE-TOKEN 標頭），不收 argv。

stdout 一行：WATCH-COLLECT<TAB>狀態<TAB>說明。結束碼：OK 0、FAIL 1、GAP 3、用法 64。

安全重點（附件是不可信資料）：
  - Token（GH_TOKEN／GITHUB_TOKEN）只放 Authorization: Bearer 標頭，只送給 API 主機；不進輸出、錯誤訊息、檔案。
  - 不經 proxy；API 本身不跟隨轉址；分頁網址必須同主機。
  - 附件用 asset 的 API 網址下載；GitHub 轉址到 *.githubusercontent.com 時拿掉 Authorization，
    只允許 https 的 githubusercontent.com 子網域，其他轉址一律算該附件的 problem。
  - 檔名由規則組出（專案、版本都過正規式），不用 API 回的檔名當路徑；先寫暫存檔再 rename；大小有上限。
  - inventory.json 只放相對路徑。
  - GitLab：只下載「這個專案的 Generic Package 檔案」（…/api/v4/projects/<ID>/packages/generic/<套件>/<版本>/<檔名>，同一個 API 主機），
    不跟隨任何轉址；其他連結（別的主機、別的專案、不是 Generic Package）不下載，記成該 Release 的 problem。
"""
import argparse
import hashlib
import http.client
import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = "dumpling-watch-inventory/1"
# pipeline/lib/project_config.py 在 main 上還不存在，先用保守的正規式（之後有了再改成 import）。
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
TOKEN_RE = re.compile(r"^[\x21-\x7e]+$")
LABEL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
STATUSES = ("shipped", "development")
DEFAULT_API = "https://api.github.com"
TIMEOUT = 30
MAX_PAGES = 100
MAX_API_BYTES = 64 * 1024 * 1024
MAX_REDIRECTS = 3
EXIT = {"OK": 0, "FAIL": 1, "GAP": 3}
UA = "dumpling-watch-collect"


class ApiError(Exception):
    """列不出 Release（整次 FAIL）。"""


class AssetError(Exception):
    """單一附件的問題（記進該 Release 的 problems）。"""


def _clean(s, n=200):
    """輸出用文字：去控制字元、截斷。"""
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(s))
    return s[:n]


class Asset:
    __slots__ = ("name", "size", "handle", "bad")

    def __init__(self, name, size, handle, bad=None):
        self.name = name
        self.size = size
        self.handle = handle
        self.bad = bad


# ---------------------------------------------------------------- 網址檢查

def _origin(url):
    p = urllib.parse.urlsplit(url)
    port = p.port or {"https": 443, "http": 80}.get(p.scheme)
    return (p.scheme.lower(), (p.hostname or "").lower(), port)


def allowed_download_url(url):
    """附件轉址目標：只允許 https 的 githubusercontent.com 或其子網域。"""
    if not isinstance(url, str) or re.search(r"[\x00-\x20\x7f\\]", url):
        return False
    try:
        p = urllib.parse.urlsplit(url)
        host = p.hostname or ""
        port = p.port
    except ValueError:
        return False
    if p.scheme != "https" or p.username is not None or p.password is not None:
        return False
    if port not in (None, 443):
        return False
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return False
    return host == "githubusercontent.com" or host.endswith(".githubusercontent.com")


def check_api_base(url, name="GITHUB_API_URL"):
    try:
        p = urllib.parse.urlsplit(url)
        host = p.hostname
        p.port
    except ValueError:
        raise ApiError("%s 不合法" % name)
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not host or p.username is not None or p.query or p.fragment or \
            not (p.scheme == "https" or (p.scheme == "http" and loopback)):
        raise ApiError("%s 不合法（要 https；測試才允許本機 http）" % name)
    return url.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # 轉址交給呼叫端自己檢查


def make_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


# ---------------------------------------------------------------- 寫檔

def write_stream(reader, dest_dir, final_name, limit):
    """邊讀邊算 sha256 與大小，超過 limit 就中止。先寫暫存檔再 rename。回 (sha256, size)。"""
    os.makedirs(dest_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest_dir, prefix=".part-")
    h = hashlib.sha256()
    n = 0
    try:
        with os.fdopen(fd, "wb") as f:
            while True:
                chunk = reader.read(65536)
                if not chunk:
                    break
                n += len(chunk)
                if n > limit:
                    raise AssetError("超過大小上限")
                h.update(chunk)
                f.write(chunk)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(dest_dir, final_name))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return h.hexdigest(), n


# ---------------------------------------------------------------- GitHub 來源

class GitHubSource:
    name_prefix = "github:"

    def __init__(self, repo, api_base, token, opener, max_bytes):
        self.repo = repo
        self.api_base = check_api_base(api_base)
        self.token = token
        self.opener = opener
        self.max_bytes = max_bytes

    @property
    def label(self):
        return "github:" + self.repo

    def _headers(self, accept, auth):
        h = {"Accept": accept, "User-Agent": UA}
        if auth and self.token:
            h["Authorization"] = "Bearer " + self.token
        return h

    def _get_page(self, url):
        if _origin(url) != _origin(self.api_base):
            raise ApiError("分頁網址不在 API 主機")
        req = urllib.request.Request(url, headers=self._headers("application/vnd.github+json", True))
        try:
            resp = self.opener.open(req, timeout=TIMEOUT)
        except urllib.error.HTTPError as e:
            code = e.code
            e.close()
            if 300 <= code < 400:
                raise ApiError("API 回 HTTP %d 轉址（不跟隨）" % code)
            raise ApiError("API 回 HTTP %d" % code)
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            raise ApiError("API 連線失敗（%s）" % type(e).__name__)
        try:
            with resp:
                body = resp.read(MAX_API_BYTES + 1)
                link = resp.headers.get("Link") if resp.headers is not None else None
        except (OSError, http.client.HTTPException) as e:
            raise ApiError("API 讀取失敗（%s）" % type(e).__name__)
        if len(body) > MAX_API_BYTES:
            raise ApiError("API 回應過大")
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, RecursionError):
            raise ApiError("API 回應不是 JSON")
        if not isinstance(data, list):
            raise ApiError("API 回應不是陣列")
        return data, link

    @staticmethod
    def _next_link(link, cur):
        if not link:
            return None
        for m in re.finditer(r"<([^>]*)>([^,<]*)", link):
            if re.search(r'rel\s*=\s*"?next"?(\s|;|,|"|$)', m.group(2)):
                return urllib.parse.urljoin(cur, m.group(1))
        return None

    def list_releases(self):
        url = "%s/repos/%s/releases?per_page=100" % (self.api_base, urllib.parse.quote(self.repo, safe="/"))
        out, seen = [], set()
        for _ in range(MAX_PAGES):
            seen.add(url)
            data, link = self._get_page(url)
            out.extend(self._convert(x) for x in data)
            nxt = self._next_link(link, url)
            if not nxt:
                return out
            if _origin(nxt) != _origin(self.api_base):
                raise ApiError("下一頁網址不在同一個主機")
            if nxt in seen:
                raise ApiError("分頁網址重複（迴圈）")
            url = nxt
        raise ApiError("分頁超過 %d 頁上限" % MAX_PAGES)

    @staticmethod
    def _convert(x):
        bad = {"malformed": "Release 資料格式不符", "tag": "?"}
        if not isinstance(x, dict) or not isinstance(x.get("tag_name"), str):
            return bad
        tag = x["tag_name"]
        if not isinstance(x.get("draft"), bool) or not isinstance(x.get("prerelease"), bool):
            return {"malformed": "draft／prerelease 欄位不是布林", "tag": tag}
        assets = {}
        for a in x.get("assets") or []:
            if not isinstance(a, dict) or not isinstance(a.get("name"), str) or not isinstance(a.get("url"), str):
                continue
            size = a.get("size")
            size = size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else None
            assets.setdefault(a["name"], []).append(Asset(a["name"], size, a["url"]))
        return {"tag": tag, "draft": x["draft"], "prerelease": x["prerelease"],
                "published_at": x.get("published_at"), "html_url": x.get("html_url"),
                "assets": assets, "malformed": None}

    def fetch(self, asset, dest_dir, final_name):
        if asset.size is not None and asset.size > self.max_bytes:
            raise AssetError("超過大小上限（API 標示 %d bytes）" % asset.size)
        url = asset.handle
        try:
            if _origin(url) != _origin(self.api_base):
                raise AssetError("附件網址不在 API 主機")
        except ValueError:
            raise AssetError("附件網址不合法")
        auth, hops = True, 0
        while True:
            req = urllib.request.Request(url, headers=self._headers("application/octet-stream", auth))
            try:
                resp = self.opener.open(req, timeout=TIMEOUT)
                break
            except urllib.error.HTTPError as e:
                code = e.code
                loc = e.headers.get("Location") if e.headers is not None else None
                e.close()
                if code in (301, 302, 303, 307, 308):
                    if hops >= MAX_REDIRECTS:
                        raise AssetError("轉址次數過多")
                    nxt = urllib.parse.urljoin(url, loc) if loc else ""
                    if not allowed_download_url(nxt):
                        raise AssetError("轉址目標不允許（只允許 https 的 githubusercontent.com）")
                    url, auth, hops = nxt, False, hops + 1
                    continue
                raise AssetError("下載回 HTTP %d" % code)
            except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
                raise AssetError("下載連線失敗（%s）" % type(e).__name__)
        return self._read_response(resp, asset, dest_dir, final_name)

    def _read_response(self, resp, asset, dest_dir, final_name):
        try:
            with resp:
                st = getattr(resp, "status", 200)
                if st != 200:
                    raise AssetError("下載回 HTTP %s" % st)
                cl = resp.headers.get("Content-Length") if resp.headers is not None else None
                if cl and cl.isdigit() and int(cl) > self.max_bytes:
                    raise AssetError("超過大小上限（Content-Length %s）" % cl)
                sha, n = write_stream(resp, dest_dir, final_name, self.max_bytes)
        except (OSError, http.client.HTTPException) as e:
            raise AssetError("下載讀取失敗（%s）" % type(e).__name__)
        if asset.size is not None and n != asset.size:
            _rm(os.path.join(dest_dir, final_name))
            raise AssetError("下載大小與 API 標示不符")
        return sha, n


# ---------------------------------------------------------------- GitLab 來源
# 官方文件對照（docs/GITLAB-PORT.md T-05）：
#   Releases：docs.gitlab.com/api/releases/（GET /projects/:id/releases；tag_name、released_at、assets.links[]；
#     「upcoming_release」＝released_at 在未來的 Release，文件只說「回傳會多一個 upcoming_release: true」）
#   Generic Package：docs.gitlab.com/user/packages/generic_packages/（GET /projects/:id/packages/generic/:package_name/:package_version/:file_name；
#     PRIVATE-TOKEN 標頭；檔名可用字元 A-Za-z0-9 . _ - + ~ @ /，不能以 ~ 或 @ 開頭／結尾）
#   分頁：docs.gitlab.com/api/rest/（per_page 最大 100；Link rel=next）
# GitLab 沒有 draft Release、也沒有 prerelease：upcoming_release 當 draft（列在 drafts、不監控）；prerelease 一律 False
# （所以 dev/<專案> 的滾動 Release 會被 classify 略過並列在 skipped——開發版 SBOM 怎麼收是 T-03 的決定，這裡不先發明）。
PKG_SEG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
PKG_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$")
PROJECT_ID_RE = re.compile(r"^[0-9]{1,18}$")
MAX_LINK_PROBLEMS = 10


class GitLabSource(GitHubSource):
    name_prefix = "gitlab:"

    def __init__(self, project, api_base, token, opener, max_bytes):
        self.project = project
        self.api_base = check_api_base(api_base, "--gitlab-url")
        self.token = token
        self.opener = opener
        self.max_bytes = max_bytes
        if not urllib.parse.urlsplit(self.api_base).path.endswith("/api/v4"):
            raise ApiError("--gitlab-url 要是 API 網址（…/api/v4，即 CI_API_V4_URL）")
        self._pkg_prefix = urllib.parse.urlsplit(self.api_base).path + "/projects/%s/packages/generic/" % project

    @property
    def label(self):
        return "gitlab:" + self.project

    def _headers(self, accept, auth):
        h = {"Accept": accept, "User-Agent": UA}
        if auth and self.token:
            h["PRIVATE-TOKEN"] = self.token
        return h

    def list_releases(self):
        url = "%s/projects/%s/releases?per_page=100" % (self.api_base, self.project)
        out, seen = [], set()
        for _ in range(MAX_PAGES):
            seen.add(url)
            data, link = self._get_page(url)
            out.extend(self._convert(x) for x in data)
            nxt = self._next_link(link, url)
            if not nxt:
                return out
            if _origin(nxt) != _origin(self.api_base):
                raise ApiError("下一頁網址不在同一個主機")
            if nxt in seen:
                raise ApiError("分頁網址重複（迴圈）")
            url = nxt
        raise ApiError("分頁超過 %d 頁上限" % MAX_PAGES)

    def _package_file(self, url):
        """連結網址若是「這個專案的 Generic Package 檔案（同一個 API 主機）」回檔名，否則回 None。不解碼、不接受 query／fragment。"""
        if not isinstance(url, str) or re.search(r"[\x00-\x20\x7f\\%]", url):
            return None
        try:
            if _origin(url) != _origin(self.api_base):
                return None
            p = urllib.parse.urlsplit(url)
        except ValueError:
            return None
        if p.query or p.fragment or p.username is not None or not p.path.startswith(self._pkg_prefix):
            return None
        parts = p.path[len(self._pkg_prefix):].split("/")
        if len(parts) != 3 or not PKG_SEG_RE.match(parts[0]) or not PKG_SEG_RE.match(parts[1]) or not PKG_FILE_RE.match(parts[2]):
            return None
        return parts[2]

    def _convert(self, x):
        bad = {"malformed": "Release 資料格式不符", "tag": "?"}
        if not isinstance(x, dict) or not isinstance(x.get("tag_name"), str):
            return bad
        tag = x["tag_name"]
        up = x.get("upcoming_release", False)
        if not isinstance(up, bool):
            return {"malformed": "upcoming_release 欄位不是布林", "tag": tag}
        assets, probs = {}, []
        links = (x.get("assets") or {}).get("links") if isinstance(x.get("assets"), dict) else None
        for a in links if isinstance(links, list) else []:
            fname = self._package_file(a.get("url")) if isinstance(a, dict) else None
            if fname is None:
                if len(probs) < MAX_LINK_PROBLEMS:
                    nm = _clean(a.get("name"), 60) if isinstance(a, dict) else "?"
                    probs.append("附件連結 %s：不是本專案 Generic Package 的檔案（同一個 API 主機），不下載" % nm)
                continue
            assets.setdefault(fname, []).append(Asset(fname, None, a["url"]))
        return {"tag": tag, "draft": up, "prerelease": False, "published_at": x.get("released_at"),
                "html_url": None, "assets": assets, "asset_problems": probs, "malformed": None}

    def fetch(self, asset, dest_dir, final_name):
        url = asset.handle
        if self._package_file(url) is None:
            raise AssetError("附件網址不是本專案的 Generic Package 檔案")
        req = urllib.request.Request(url, headers=self._headers("application/octet-stream", True))
        try:
            resp = self.opener.open(req, timeout=TIMEOUT)
        except urllib.error.HTTPError as e:
            code = e.code
            e.close()
            if 300 <= code < 400:
                raise AssetError("下載收到 HTTP %d 轉址（不跟隨）" % code)
            raise AssetError("下載回 HTTP %d" % code)
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            raise AssetError("下載連線失敗（%s）" % type(e).__name__)
        return self._read_response(resp, asset, dest_dir, final_name)


# ---------------------------------------------------------------- 資料夾來源（演練、測試）

class DirSource:
    def __init__(self, root, max_bytes):
        self.root = root
        self.max_bytes = max_bytes

    @property
    def label(self):
        return "dir"

    @staticmethod
    def _read_small_json(path):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise ValueError("不是一般檔")
            data = f.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("過大")
        return json.loads(data.decode("utf-8"))

    def list_releases(self):
        try:
            names = sorted(os.listdir(self.root))
        except OSError:
            raise ApiError("無法讀取 --from-dir 資料夾")
        out = []
        for d in names:
            p = os.path.join(self.root, d)
            try:
                if not stat.S_ISDIR(os.lstat(p).st_mode):
                    continue
            except OSError:
                continue
            out.append(self._one(d, p))
        return out

    def _one(self, d, p):
        label = _clean(d, 100)
        try:
            rj = self._read_small_json(os.path.join(p, "release.json"))
        except (OSError, ValueError, RecursionError):
            return {"malformed": "缺 release.json 或格式不符", "tag": label}
        if not isinstance(rj, dict) or not isinstance(rj.get("tag_name"), str) \
                or not isinstance(rj.get("prerelease"), bool) or not isinstance(rj.get("draft", False), bool):
            return {"malformed": "release.json 欄位不符", "tag": label}
        assets = {}
        try:
            with os.scandir(p) as it:
                for e in it:
                    if e.is_symlink():
                        bad = "是符號連結"
                    elif not e.is_file(follow_symlinks=False):
                        bad = "不是一般檔"
                    else:
                        bad = None
                    size = None
                    if bad is None:
                        try:
                            size = e.stat(follow_symlinks=False).st_size
                        except OSError:
                            bad = "無法讀取"
                    assets[e.name] = [Asset(e.name, size, e.path, bad)]
        except OSError:
            return {"malformed": "無法列出資料夾", "tag": label}
        return {"tag": rj["tag_name"], "draft": rj.get("draft", False), "prerelease": rj["prerelease"],
                "published_at": rj.get("published_at"), "html_url": rj.get("html_url"),
                "assets": assets, "malformed": None}

    def fetch(self, asset, dest_dir, final_name):
        if asset.bad:
            raise AssetError("附件" + asset.bad)
        if asset.size is not None and asset.size > self.max_bytes:
            raise AssetError("超過大小上限（%d bytes）" % asset.size)
        try:
            fd = os.open(asset.handle, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            raise AssetError("附件無法開啟（可能是符號連結）")
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise AssetError("附件不是一般檔")
            return write_stream(f, dest_dir, final_name, self.max_bytes)


def _rm(path):
    try:
        os.unlink(path)
    except OSError:
        pass


# ---------------------------------------------------------------- 分類與驗證

def classify(tag, prerelease):
    """回 (kind, project, tag 內的版本｜None) 或 (None, 原因, None)。"""
    parts = tag.split("/")
    if len(parts) != 2 or not all(parts):
        return None, "tag 格式不是 <專案>/<版本> 或 dev/<專案>", None
    a, b = parts
    if a == "dev":
        if not PROJECT_RE.match(b):
            return None, "dev/<專案> 的專案名不合規則", None
        if not prerelease:
            return None, "dev/<專案> 但不是 prerelease", None
        return "dev", b, None
    if not PROJECT_RE.match(a) or not VERSION_RE.match(b):
        return None, "tag 的專案名或版本不合規則", None
    if prerelease:
        return None, "<專案>/<版本> 但是 prerelease", None
    return "release", a, b


def check_meta(meta, tag, kind, project, tagver):
    """回 (問題｜None)。通過時 meta["version"] 一定符合 VERSION_RE。"""
    if not isinstance(meta, dict):
        return "release-meta.json 不是 JSON 物件"
    if meta.get("schema") != 1 or isinstance(meta.get("schema"), bool):
        return "release-meta schema 不是 1"
    if meta.get("project") != project:
        return "release-meta project 與 tag 不一致"
    v = meta.get("version")
    if not isinstance(v, str) or not VERSION_RE.match(v):
        return "release-meta version 缺少或格式不符"
    if kind == "release" and v != tagver:
        return "release-meta version 與 tag 不一致"
    if meta.get("tag") != tag:
        return "release-meta tag 與 Release 的 tag 不一致"
    if meta.get("status") not in STATUSES:
        return "release-meta status 只能是 shipped 或 development"
    c = meta.get("commit")
    if not isinstance(c, str) or not COMMIT_RE.match(c):
        return "release-meta commit 不是 40 位小寫 hex"
    for k in ("platform", "os_responsibility"):
        if k in meta and meta[k] is not None and not (isinstance(meta[k], str) and LABEL_RE.match(meta[k])):
            return "release-meta %s 格式不符" % k
    return None


def _load_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def _json_ok(path):
    try:
        _load_json(path)
    except (OSError, ValueError, RecursionError):
        return "不是合法 JSON"
    return None


def _sbom_ok(path):
    try:
        obj = _load_json(path)
    except (OSError, ValueError, RecursionError):
        return "不是合法 JSON"
    if not isinstance(obj, dict) or obj.get("bomFormat") != "CycloneDX":
        return "不是 CycloneDX（bomFormat 不符）"
    return None


def _http_url(u):
    if isinstance(u, str) and u.startswith("https://") and not re.search(r"[\x00-\x20\x7f]", u):
        return u[:500]
    return None


def _date(s):
    return _clean(s, 40) if isinstance(s, str) else None


# ---------------------------------------------------------------- release-meta 的結論欄位

RESULT_VALUES = ("OK", "ATTENTION", "NOT_RUN", "GAP", "NOT_ASSESSED", "FAIL")     # C1 的 release-meta（wp1/m2 9f1d2f0）
REPORT_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,19}$")
CTRL_RE = re.compile(r"[\x00-\x1f\x7f<>]")


def _result(v):
    """report_status／release_gate／pipeline_result 的值：六種合法值照原值；其他（缺少、型別不對、別的字）一律 NOT_RUN。"""
    return v if isinstance(v, str) and v in RESULT_VALUES else "NOT_RUN"


def meta_results(meta):
    """release-meta 的結論欄位（C1 在 M2 新增；`status` 是生命週期 development／shipped，不是掃描結論）。只讀 C1 的實際格式：
    report_status（字串，最差那一份報告）、release_gate（字串，vex.gate）、pipeline_result（字串，流程步驟的結果，不是產品結論）、
    reports（[{report, report_status, release_gate}]，每份報告一筆；report 是 full／bsp／os…）、
    attention（字串清單，用了舊資料頂替的說明，例如核心 CVE 鏡像上游連不上；有才有）。其他形狀一律 NOT_RUN／略過。"""
    reps = []
    for r in meta.get("reports") if isinstance(meta.get("reports"), list) else []:
        if isinstance(r, dict) and isinstance(r.get("report"), str) and REPORT_NAME_RE.fullmatch(r["report"]):
            reps.append({"report": r["report"], "report_status": _result(r.get("report_status")), "release_gate": _result(r.get("release_gate"))})
    att = []
    for x in meta.get("attention") if isinstance(meta.get("attention"), list) else []:
        if isinstance(x, str) and x.strip():
            att.append(CTRL_RE.sub(" ", x).strip()[:300])
    return {"report_status": _result(meta.get("report_status")), "release_gate": _result(meta.get("release_gate")),
            "pipeline_result": _result(meta.get("pipeline_result")), "reports": reps[:10], "attention": att[:5]}


# ---------------------------------------------------------------- 單一 Release

def collect_release(source, rel, kind, project, tagver, out, n):
    tag = rel["tag"]
    e = {"tag": tag, "kind": kind, "project": project, "version": tagver,
         "watch_version": tagver if kind == "release" else "dev",
         "status": None, "platform": None, "os_responsibility": None, "commit": None,
         "published_at": _date(rel.get("published_at")), "html_url": _http_url(rel.get("html_url")),
         "sboms": {}, "kernel_versions": None, "scan_summary": None, "layers": None, "problems": [],
         "report_status": "NOT_RUN", "release_gate": "NOT_RUN", "pipeline_result": "NOT_RUN", "reports": [], "attention": []}
    probs = e["problems"]
    reldir = os.path.join(out, "releases", str(n))
    relpath = "releases/%d" % n
    assets = rel["assets"]
    probs.extend(rel.get("asset_problems") or [])

    def grab(name, check):
        """依規則檔名取附件。不存在回 None（不算問題，由呼叫端決定）；有問題記 problem 回 None。"""
        lst = assets.get(name)
        if not lst:
            return None
        if len(lst) > 1:
            probs.append("%s：附件同名重複" % name)
            return None
        try:
            sha, size = source.fetch(lst[0], reldir, name)
        except AssetError as ex:
            probs.append("%s：%s" % (name, ex))
            return None
        err = check(os.path.join(reldir, name)) if check else None
        if err:
            _rm(os.path.join(reldir, name))
            probs.append("%s：%s" % (name, err))
            return None
        return {"file": "%s/%s" % (relpath, name), "sha256": sha, "size": size}

    # 1. release-meta.json（必要）
    got = grab("release-meta.json", _json_ok)
    if got is None:
        if "release-meta.json" not in assets:
            probs.append("release-meta.json：缺少")
        if kind == "dev":
            e["version"] = None
        return e
    meta = _load_json(os.path.join(reldir, "release-meta.json"))
    err = check_meta(meta, tag, kind, project, tagver)
    if err:
        _rm(os.path.join(reldir, "release-meta.json"))
        probs.append("release-meta.json：" + err)
        if kind == "dev":
            e["version"] = None
        return e
    version = meta["version"]
    e["version"] = version
    e["status"] = meta["status"]
    e["platform"] = meta.get("platform")
    e["os_responsibility"] = meta.get("os_responsibility")
    e["commit"] = meta["commit"]
    e.update(meta_results(meta))

    # 2. SBOM：有分層（bsp、os）就只收分層，沒有才用整份（層名 product）
    base = "sbom-%s-%s" % (project, version)
    layered = [l for l in ("bsp", "os") if "%s-%s.cdx.json" % (base, l) in assets]
    if layered:
        for l in ("bsp", "os"):
            name = "%s-%s.cdx.json" % (base, l)
            if l not in layered:
                probs.append("%s：缺少分層 SBOM" % name)
                continue
            s = grab(name, _sbom_ok)
            if s:
                e["sboms"][l] = s
    elif base + ".cdx.json" in assets:
        s = grab(base + ".cdx.json", _sbom_ok)
        if s:
            e["sboms"]["product"] = s
    else:
        probs.append("沒有 SBOM（%s-bsp／-os／整份都不存在）" % base)

    # 3. 其他附件
    s = grab("layers.json", _json_ok)
    e["layers"] = s["file"] if s else None
    # kernel-versions：release-meta 的 kernel_versions 欄位是附件檔名或 null（C1）；只接受規則檔名，不用欄位值當路徑
    kvname = "kernel-versions-%s-%s.json" % (project, version)
    kvmeta = meta.get("kernel_versions")
    s = None
    if kvmeta is None:
        pass                                     # Release 沒有附核心版本（match 標 GAP）
    elif kvmeta != kvname:
        probs.append("release-meta 的 kernel_versions 不是規則檔名 %s：不讀" % kvname)
    else:
        s = grab(kvname, _json_ok)
        if s is None and kvname not in assets:
            probs.append("release-meta 列了 %s，但 Release 沒有這個附件" % kvname)
    e["kernel_versions"] = s["file"] if s else None
    s = grab("scan-summary-%s-%s.json" % (project, version), _json_ok)  # 選填
    e["scan_summary"] = s["file"] if s else None
    return e


# ---------------------------------------------------------------- 整體

def build(source, out, now):
    inv = {"schema": SCHEMA, "generated_at": now, "source": source.label, "status": "OK", "detail": "",
           "releases": [], "skipped": [], "drafts": []}
    releases, skipped = inv["releases"], inv["skipped"]
    rdir = os.path.join(out, "releases")
    if os.path.islink(rdir):
        os.unlink(rdir)
    else:
        shutil.rmtree(rdir, ignore_errors=True)
    gap_extra = False
    drafts = 0
    seen = set()
    for rel in source.list_releases():
        tag = _clean(rel["tag"])
        if rel.get("malformed"):
            skipped.append({"tag": tag, "why": rel["malformed"]})
            gap_extra = True
            continue
        if rel["draft"]:
            drafts += 1
            if len(inv["drafts"]) < 50:
                inv["drafts"].append(tag)       # 正常略過（還沒發布）：match.py 只列出、不降級
            continue
        kind, project, tagver = classify(rel["tag"], rel["prerelease"])
        if kind is None:
            skipped.append({"tag": tag, "why": project})
            continue
        if rel["tag"] in seen:
            skipped.append({"tag": tag, "why": "tag 重複（只收第一個）"})
            continue
        seen.add(rel["tag"])
        releases.append(collect_release(source, rel, kind, project, tagver, out, len(releases)))
    nprob = sum(len(r["problems"]) for r in releases)
    nbad = sum(1 for r in releases if r["problems"])
    nrel = sum(1 for r in releases if r["kind"] == "release")
    ndev = len(releases) - nrel
    notes = []
    if not releases:
        inv["status"] = "GAP"
        notes.append("沒有可監控的 Release")
    if nbad:
        inv["status"] = "GAP"
        notes.append("%d 個 Release 有 problem（共 %d 項）" % (nbad, nprob))
    if gap_extra:
        inv["status"] = "GAP"
        notes.append("有資料格式不符的 Release（見 skipped）")
    if any(not x["why"].startswith("tag 重複") for x in skipped) and not gap_extra:
        notes.append("有 tag 不合規則的 Release 被略過（見 skipped）")
    summary = "正式版 %d、開發版 %d、略過 %d、draft %d" % (nrel, ndev, len(skipped), drafts)
    inv["detail"] = "；".join(notes + [summary]) if notes else summary
    return inv


def write_json(path, obj):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".part-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=False)
            f.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        _rm(tmp)
        raise


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write("用法錯誤：%s\n" % message)
        raise SystemExit(64)


def parse_args(argv):
    ap = _Parser(prog="collect.py", description="收集 Release 附件（每日監控 4a；GitHub 或 GitLab）")
    ap.add_argument("--backend", choices=["github", "gitlab"], default="github")
    ap.add_argument("--repo", help="owner/repo（github）")
    ap.add_argument("--from-dir", dest="from_dir", help="合成 Release 資料夾（演練、測試）")
    ap.add_argument("--gitlab-url", dest="gitlab_url", help="GitLab API 網址（…/api/v4，即 CI_API_V4_URL）")
    ap.add_argument("--project", help="GitLab 專案的數字 ID（CI_PROJECT_ID）")
    ap.add_argument("--out", required=True, help="工作資料夾")
    ap.add_argument("--max-asset-mb", type=float, default=200, help="單一附件大小上限（MiB，預設 200）")
    a = ap.parse_args(argv)
    if a.backend == "gitlab":
        if a.repo is not None or a.from_dir is not None:
            ap.error("--backend gitlab 不能搭配 --repo／--from-dir")
        if not a.gitlab_url or not a.project or not PROJECT_ID_RE.match(a.project):
            ap.error("--backend gitlab 需要 --gitlab-url 與數字的 --project")
        try:
            p = urllib.parse.urlsplit(a.gitlab_url)
            p.port
        except ValueError:
            ap.error("--gitlab-url 不合法")
        if not (p.scheme == "https" or (p.scheme == "http" and p.hostname in ("127.0.0.1", "localhost", "::1"))) \
                or not p.hostname or p.username is not None or p.query or p.fragment \
                or not p.path.rstrip("/").endswith("/api/v4"):
            ap.error("--gitlab-url 要是 https 的 …/api/v4（測試才允許本機 http）")
    else:
        if (a.repo is None) == (a.from_dir is None):
            ap.error("要給 --repo 或 --from-dir 其中一個")
        if a.gitlab_url is not None or a.project is not None:
            ap.error("--gitlab-url／--project 只能搭配 --backend gitlab")
    if a.repo is not None and (not REPO_RE.match(a.repo) or a.repo.split("/")[0] in (".", "..")
                               or a.repo.split("/")[1] in (".", "..")):
        ap.error("--repo 格式要是 owner/repo")
    if not (math.isfinite(a.max_asset_mb) and a.max_asset_mb > 0):
        ap.error("--max-asset-mb 要大於 0")
    return a


def finish(status, detail):
    detail = re.sub(r"\s+", " ", detail).strip()
    sys.stdout.write("WATCH-COLLECT\t%s\t%s\n" % (status, detail))
    sys.stdout.flush()
    return EXIT[status]


def run(argv, env=None, opener=None, now=None):
    env = os.environ if env is None else env
    try:
        a = parse_args(argv)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 64
    max_bytes = int(a.max_asset_mb * 1024 * 1024)
    if a.backend == "gitlab":
        token = (env.get("GITLAB_TOKEN") or "").strip()
    else:
        token = (env.get("GH_TOKEN") or env.get("GITHUB_TOKEN") or "").strip()
    now = now or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = os.path.abspath(a.out)

    def scrub(s):
        return s.replace(token, "***") if token else s

    try:
        os.makedirs(out, exist_ok=True)
        source = None
        try:
            if a.backend == "gitlab":
                if token and not TOKEN_RE.match(token):
                    raise ApiError("token 格式不合法")
                source = GitLabSource(a.project, a.gitlab_url, token, opener or make_opener(), max_bytes)
            elif a.repo:
                if token and not TOKEN_RE.match(token):
                    raise ApiError("token 格式不合法")
                source = GitHubSource(a.repo, env.get("GITHUB_API_URL") or DEFAULT_API, token,
                                      opener or make_opener(), max_bytes)
            else:
                source = DirSource(a.from_dir, max_bytes)
            inv = build(source, out, now)
        except ApiError as ex:
            inv = {"schema": SCHEMA, "generated_at": now,
                   "source": ("gitlab:" + a.project) if a.backend == "gitlab" else ("github:" + a.repo) if a.repo else "dir",
                   "status": "FAIL", "detail": _clean(scrub(str(ex))), "releases": [], "skipped": []}
        write_json(os.path.join(out, "inventory.json"), inv)
    except Exception as ex:  # 不讓例外訊息（可能含路徑、token）直接出去
        return finish("FAIL", scrub("未預期的錯誤（%s）" % type(ex).__name__))
    return finish(inv["status"], scrub(inv["detail"]))


def main():
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
