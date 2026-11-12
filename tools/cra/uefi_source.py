#!/usr/bin/env python3
"""從 UEFI 原始碼樹讀出 edk2／廠商 UEFI（edk2-nvidia）的版本與內建的加密函式庫（OpenSSL、Mbed TLS），
輸出可以比對漏洞的 CycloneDX 1.6 元件、報告，以及一行狀態。

用法：
  python3 -I tools/cra/uefi_source.py --tree <原始碼樹> --out <資料夾>
      [--manifest <edkrepo 或 repo 的 manifest .xml>] [--combination <edkrepo combination 名稱>]
      [--bulletin-mirror <nvidia-bulletins.sh 的鏡像>] [--bulletin-table <對照表，預設 tools/pilot/lib/nvidia-bulletins.json>]
      [--platform-dsc <樹內的平台 DSC>]（可重複）[--platform-define NAME=VALUE]（可重複）[--time-limit <秒>]
  --platform-dsc：實際用來建置的平台 DSC；沒給時從 <樹>/Build/BUILDLOG_*.txt 的 "Edk2 build parameters are -p … -D …" 找。
  有 DSC 時（tools/cra/uefi_dsc.py）盡力判斷 OpenSSL／Mbed TLS 有沒有被編進韌體的模組用到：built-in yes（有 檔案:行 的證據鏈）或 unknown，**沒有 no，不排除任何列**，證據（檔案:行）
  寫在報告與 CycloneDX 的 sca-center:built-in、sca-center:built-in-evidence。算不出來一律 unknown（ATTENTION），不猜成 no。
  沒有 DSC（沒給、也找不到建置記錄）時不判斷，不輸出這兩個屬性（cra_report 當成 unknown）。
  輸出 <資料夾>/uefi-source.cdx.json（CycloneDX 1.6，只含這裡找到的元件）、uefi-source.json（報告）、uefi-source.md（同內容給人看），
  stdout 一行 `X-uefi-source<TAB>OK|ATTENTION|GAP|FAIL<TAB>說明`。
  退出碼：OK 0；ATTENTION／GAP 2；FAIL 1；參數錯誤 64（也印 FAIL 那一行，清掉上一次的輸出）。

原始碼樹的形狀（只認這兩種，不往下猜）：
  - edk2 本身（最上層有 MdePkg/）；
  - 工作區（edkrepo 的形狀）：<樹>/edk2/MdePkg/，另有 <樹>/edk2-nvidia/ 時當成 NVIDIA 的廠商 UEFI。
  manifest 的項目以相對於 --tree 的路徑對應（edkrepo 的 localRoot、repo 的 path）。

版本的來源（每個都記在報告的 evidence，衝突時並列、不互相覆蓋）：
  1. .git（不執行 git，也就不會執行輸入裡的 hook）：HEAD（ref 或 commit）→ loose ref 或 packed-refs → commit；
     指到這個 commit 的 tag（packed-refs 的 ^peeled 行、loose 的輕量 tag，或 loose 的附註 tag 物件用 zlib 解開讀 object 行）。
     .git 是檔案（submodule、worktree）時，gitdir 要在樹裡面，否則不讀。附註 tag 物件在 pack 檔裡讀不到 → 記數量，不猜。
  2. manifest：edkrepo（<Manifest>，Combination 的 Source：localRoot、tag／branch／commit）或 repo（<manifest>，project 的
     revision；refs/tags/X 才算 tag，沒有 refs/ 前綴的名稱分不出 branch 或 tag）。west（YAML）不支援。
     只收 UTF-8；含 DOCTYPE／ENTITY 時不解析（避免實體展開攻擊；文字比對加上 expat 的宣告處理器）。
  3. 原始碼與建置產物裡的版本字串：DSC 的 PcdFirmwareVersionString／PcdUefiVersionString（字面值才記；edk2-nvidia 是建置時的
     $(BUILDID_STRING)），edk2-nvidia 建置後的 images/buildid_*.txt。只當參考，不拿來決定版本。
  版本＝指到 HEAD 的 tag。.git 存在就以 .git 為準：manifest 的 tag 指到別的 commit、在 .git 裡沒有或讀不到、commit 不同
  → GAP；.git 存在但讀不到 HEAD 的 commit → GAP（manifest 的 tag 只記成「可能是」）。沒有 .git 時才用 manifest 的 tag（ATTENTION）。
  只有 branch、只有 commit → 版本不明，GAP（commit 仍記在元件的 property）。

加密函式庫：
  - OpenSSL：edk2 的 submodule CryptoPkg/Library/OpensslLib/openssl。3.x 讀 VERSION.dat（MAJOR、MINOR、PATCH、PRE_RELEASE_TAG、
    BUILD_METADATA），1.x 讀 include/openssl/opensslv.h 的 OPENSSL_VERSION_TEXT（與 OPENSSL_VERSION_NUMBER 互相核對）。
    版本檔互相矛盾 → 不挑一個（版本不明、不給 CPE、GAP）。submodule 是空資料夾（沒有取出）或不存在（.gitmodules 有宣告、
    或上一層資料夾存在）→ GAP；**不從 edk2 版本推**。edk2 自己的 OpensslGen/include/openssl/opensslv.h
    （edk2 產生的標頭）只拿來和 submodule 核對，不能代替 submodule。
  - Mbed TLS：CryptoPkg/Library/MbedTlsLib/mbedtls 的 include/mbedtls/build_info.h（3.x）或 version.h（2.x）的 MBEDTLS_VERSION_STRING。
  - 整棵樹走一次（lstat，不跟隨符號連結），在其他位置找到的 OpenSSL／Mbed TLS 也列出（role other-copy；有沒有編進韌體不判斷）。
  purl 與 CPE：pkg:generic/openssl@x.y.z ＋ cpe:2.3:a:openssl:openssl:x.y.z；pkg:generic/mbedtls@x.y.z ＋ cpe:2.3:a:arm:mbed_tls:x.y.z；
  開發中或預發行版本（-dev、-alpha…）不給 CPE（GAP）。
  edk2：tag 是 upstream 的 edk2-stableYYYYMM（或 .NN）時給 cpe:2.3:a:tianocore:edk2:YYYYMM[.NN]（NVD 的寫法）；fork 的 tag
  （例如 NVIDIA 的 r36.4.3）NVD 沒有對應版本，不給 CPE（GAP），tag 名稱裡的 edk2-stable 只記成 upstream-base。

NVIDIA 公告（只在找到 edk2-nvidia 時做）：edk2-nvidia 的 tag 是 rX.Y[.Z]（或 jetson-rX.Y）→ Jetson Linux X.Y[.Z]，
  用 tools/pilot/lib/nvidia_bulletins.py 的鏡像檢查與對照表，比對對照表 component=UEFI 的列：
  同版本線、在受影響範圍 → 命中（已審核的列）或「未審核列會命中」；已達修正分已審核／未審核；範圍空隙、公告沒列這個版本線、
  元件未寫明、未審核且元件是推測的（flash／unknown）→ 無法判定；同版本線有未審核的相關列 → 至少 ATTENTION。
  鏡像沒給、過期、讀不到，或鏡像有對照表還沒收的公告 → GAP。都不寫「不受影響」。

不可信輸入：只讀，不執行任何東西。每個要讀的檔案先 realpath，必須在樹裡面（逃出樹外的符號連結 → 拒讀，記在 walk.refused），
  必須是一般檔案，大小有上限（MAX_*）；走訪不跟隨符號連結、有項目數、深度、時間上限，超過 → 不完整（GAP）。
輸出穩定：沒有時間戳記、亂數與絕對路徑（只寫最後一段），清單都排序；同一份輸入兩次輸出相同（鏡像的新舊判定除外，那是依當下時間）。
  走訪時讀不到的資料夾記數量與範例，算不完整（GAP）。
"""
import argparse
import importlib.util
import json
import math
import os
import re
import stat
import sys
import time
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from urllib.parse import quote, urlsplit
import pyexpat

STAGE = "X-uefi-source"
SCHEMA = "sca-uefi-source/1"
ROOT = Path(__file__).resolve().parents[2]
DSC_PATH = ROOT / "tools" / "cra" / "uefi_dsc.py"
NB_PATH = ROOT / "tools" / "pilot" / "lib" / "nvidia_bulletins.py"
DEFAULT_TABLE = ROOT / "tools" / "pilot" / "lib" / "nvidia-bulletins.json"
OUTPUTS = ("uefi-source.cdx.json", "uefi-source.json", "uefi-source.md")
REF = "uefi-source:"

# 上限（不可信輸入）
MAX_SMALL = 64 * 1024              # HEAD、ref、VERSION.dat、.git 檔、buildid
MAX_HEADER = 1024 * 1024           # opensslv.h、build_info.h、version.h、.gitmodules、git config
MAX_MANIFEST = 4 * 1024 * 1024
MAX_PACKED_REFS = 16 * 1024 * 1024
MAX_TABLE = 16 * 1024 * 1024
MAX_DSC = 2 * 1024 * 1024
MAX_DSC_FILES = 5000
MAX_DSC_TOTAL = 256 * 1024 * 1024
MAX_GIT_OBJECT = 1024 * 1024       # 壓縮後
MAX_GIT_OBJECT_INFLATED = 64 * 1024
MAX_LOOSE_TAGS = 20000
MAX_MANIFEST_ELEMENTS = 200000
MAX_ENTRIES = 2_000_000            # 走訪的目錄項目
MAX_DEPTH = 64
MAX_EVENTS = 100                   # 報告裡逐一列出的拒讀／過大項目
MAX_BULLETIN_SCAN = 4 * 1024 * 1024
TIME_LIMIT = 900.0

OPENSSL_SUB = "CryptoPkg/Library/OpensslLib/openssl"
OPENSSL_GEN = "CryptoPkg/Library/OpensslLib/OpensslGen"
MBEDTLS_SUB = "CryptoPkg/Library/MbedTlsLib/mbedtls"
HEX_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REF_NAME = re.compile(r"^refs/[A-Za-z0-9._/+@-]{1,240}$")
EDK2_STABLE = re.compile(r"^edk2-stable(\d{6}(?:\.\d{2})?)$")
EDK2_BASE_IN = re.compile(r"edk2-stable(\d{6}(?:\.\d{2})?)")
JETSON_TAG = re.compile(r"^(?:jetson-)?r(\d+(?:\.\d+)+)$")
NV_SERVER_TAG = re.compile(r"^uefi-(\d{6}(?:\.\d+)+)$")
REL_VERSION = re.compile(r"^\d+\.\d+\.\d+[a-z]{0,2}$")
NOT_COVERED = [
    "原始碼樹裡有不等於編進韌體：OpenSSL 與 Mbed TLS 是否被平台 DSC 選用，只有給了平台 DSC（--platform-dsc 或 Build/BUILDLOG_*.txt）時才盡力判斷（built-in），"
    "不解析 FDF；報告的 dsc_references 只是線索。",
    "本機修改（未 commit 的變更、patch）不檢查；tag 相同不代表內容與發行版相同。",
    "其他 submodule 與第三方程式碼（brotli、oniguruma、jansson、libfdt、libspdm、SoftFloat…）不建元件，只在報告列出。",
    "廠商 UEFI 只認 NVIDIA edk2-nvidia；其他 IBV（AMI、Insyde、Phoenix）的版本不讀。",
    "flash 裡實際刷的 UEFI 映像不讀；這裡只看原始碼樹。",
    "west（YAML）manifest、repo manifest 的 include／extend-project 不展開。",
]


class Fail(Exception):
    pass


class ArgError(Exception):
    pass


class OverBudget(Exception):
    pass


class Budget:
    def __init__(self, time_limit=TIME_LIMIT):
        self.deadline = time.monotonic() + time_limit
        self.time_limit = time_limit

    def check(self):
        if time.monotonic() > self.deadline:
            raise OverBudget(f"超過時間上限 {self.time_limit:g} 秒")


def unsurrogate(s):
    """不是 UTF-8 的檔名（os.scandir 以 surrogateescape 表示）→ 可以寫成 UTF-8 的文字（\\xff 形式）。"""
    s = str(s)
    try:
        s.encode("utf-8")
        return s
    except UnicodeEncodeError:
        pass
    try:
        return s.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    except UnicodeEncodeError:            # 不是 surrogateescape 來的單獨 surrogate
        return s.encode("utf-8", "backslashreplace").decode("utf-8")


def scrub(x):
    """整份報告的字串都轉成可以寫成 UTF-8 的文字（輸出前呼叫）。"""
    if isinstance(x, str):
        return unsurrogate(x)
    if isinstance(x, list):
        return [scrub(v) for v in x]
    if isinstance(x, dict):
        return {scrub(k): scrub(v) for k, v in x.items()}
    return x


def clean(s, n=200):
    """不可信的文字：去掉控制字元、限制長度。"""
    s = re.sub(r"[\x00-\x1f\x7f]", " ", unsurrogate(s))
    return s if len(s) <= n else s[:n - 1] + "…"


def label(path):
    """輸出裡不放絕對路徑（換一台機器或資料夾，輸出要相同）：只留最後一段。"""
    if path is None:
        return None
    p = str(path).rstrip("/\\")
    return clean(os.path.basename(p) or p, 200)


def md(s, n=300):
    """放進 Markdown 表格：控制字元、| 與 < 都處理掉（不變成表格或 HTML）。"""
    s = clean("" if s is None else s, n)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|").replace("`", "'")


def safe_url(u):
    """只重組 scheme、host、port、path：帳號密碼（含密碼裡的 @）、query（例如 ?private_token=）、fragment 都去掉。
    只收 https／http／ssh／git；其他（例如 scp 形式 git@host:x）→ None。"""
    if not isinstance(u, str) or re.search(r"\s", u.strip()):
        return None
    try:
        sp = urlsplit(u.strip())
        host, port = sp.hostname, sp.port
    except ValueError:
        return None
    if sp.scheme.lower() not in ("https", "http", "ssh", "git") or not host or not re.fullmatch(r"[A-Za-z0-9.:\[\]-]{1,253}", host):
        return None
    if ":" in host:
        host = f"[{host}]"
    path = sp.path if re.fullmatch(r"[A-Za-z0-9._~/%+-]*", sp.path or "") else ""
    return clean(f"{sp.scheme.lower()}://{host}{f':{port}' if port else ''}{path}", 300)


# ---------- 樹的安全讀取 ----------

class Tree:
    def __init__(self, root):
        self.given = root
        self.root = os.path.realpath(root)
        self.refused = []        # 逃出樹外的符號連結、不是一般檔案
        self.too_large = []
        self.refused_count = 0
        self.too_large_count = 0

    def _event(self, kind, rel, why):
        if kind == "refused":
            self.refused_count += 1
            if len(self.refused) < MAX_EVENTS and not any(x["path"] == rel for x in self.refused):
                self.refused.append({"path": clean(rel, 300), "reason": why})
        else:
            self.too_large_count += 1
            if len(self.too_large) < MAX_EVENTS and not any(x["path"] == rel for x in self.too_large):
                self.too_large.append({"path": clean(rel, 300), "reason": why})

    def inside(self, real):
        return real == self.root or real.startswith(self.root + os.sep)

    def resolve(self, rel, record=True):
        """相對路徑 → 真實路徑（要在樹裡面）；不存在 → None；逃出樹外 → None 並記錄。"""
        p = os.path.join(self.root, rel) if rel else self.root
        if not os.path.lexists(p):
            return None
        real = os.path.realpath(p)
        if not self.inside(real):
            if record:
                self._event("refused", rel, "符號連結指到樹外，不跟隨")
            return None
        return real

    def exists(self, rel):
        return self.resolve(rel, record=False) is not None or os.path.lexists(os.path.join(self.root, rel))

    def isdir(self, rel):
        r = self.resolve(rel)
        return bool(r) and os.path.isdir(r)

    def listdir(self, rel, cap=1000):
        r = self.resolve(rel)
        if not r or not os.path.isdir(r):
            return None
        out = []
        try:
            with os.scandir(r) as it:
                for e in it:
                    out.append(e.name)
                    if len(out) >= cap:
                        break
        except OSError:
            return None
        return sorted(out)

    def read(self, rel, cap):
        """回傳 (bytes, None) 或 (None, 原因)。原因：missing、escape、not-regular、too-large、unreadable。"""
        p = os.path.join(self.root, rel)
        if not os.path.lexists(p):
            return None, "missing"
        real = self.resolve(rel)
        if real is None:
            return None, "escape"
        try:
            st = os.lstat(real)
            if not stat.S_ISREG(st.st_mode):
                self._event("refused", rel, "不是一般檔案")
                return None, "not-regular"
            if st.st_size > cap:
                self._event("too_large", rel, f"{st.st_size} bytes > 上限 {cap}")
                return None, "too-large"
            fd = os.open(real, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return None, "not-regular"
                with os.fdopen(fd, "rb") as f:
                    fd = None
                    data = f.read(cap + 1)
            finally:
                if fd is not None:
                    os.close(fd)
        except OSError:
            return None, "unreadable"
        if len(data) > cap:
            self._event("too_large", rel, f"讀到超過上限 {cap} bytes")
            return None, "too-large"
        return data, None

    def text(self, rel, cap):
        data, err = self.read(rel, cap)
        return (data.decode("utf-8", "replace"), None) if data is not None else (None, err)

    def head(self, rel, n):
        """檔案開頭最多 n bytes（檔案可以比 n 大；建置記錄很大，要的參數在開頭）。回傳 (文字, None) 或 (None, 原因)。"""
        real = self.resolve(rel)
        if real is None:
            return None, "missing" if not os.path.lexists(os.path.join(self.root, rel)) else "escape"
        try:
            fd = os.open(real, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return None, "not-regular"
                with os.fdopen(fd, "rb") as f:
                    fd = None
                    return f.read(n).decode("utf-8", "replace"), None
            finally:
                if fd is not None:
                    os.close(fd)
        except OSError:
            return None, "unreadable"


READ_ERR = {"missing": "不存在", "escape": "符號連結指到樹外，拒讀", "not-regular": "不是一般檔案", "too-large": "檔案過大",
            "unreadable": "讀不到"}


def join(*parts):
    return "/".join(p.strip("/") for p in parts if p not in ("", ".", None))


# ---------- git（不執行 git） ----------

def git_info(tree, rel):
    """讀 <rel>/.git：HEAD、branch、commit、指到 commit 的 tag、origin 網址。"""
    g = empty_git()
    dot = join(rel, ".git")
    p = os.path.join(tree.root, dot)
    if not os.path.lexists(p):
        return g
    g["present"] = True
    real = tree.resolve(dot)
    if real is None:
        g["notes"].append(".git 是指到樹外的符號連結，不讀")
        return g
    if os.path.isdir(real):
        gitdir = os.path.relpath(real, tree.root)
    else:
        txt, err = tree.text(dot, MAX_SMALL)
        m = re.match(r"^gitdir:\s*(.+?)\s*$", txt or "", re.M)
        if not m:
            g["notes"].append(f".git 檔案無法讀取或格式不對（{READ_ERR.get(err, '沒有 gitdir')}）")
            return g
        target = m.group(1)
        absd = os.path.normpath(target if os.path.isabs(target) else os.path.join(tree.root, rel, target))
        rd = os.path.realpath(absd)
        if not tree.inside(rd):
            g["notes"].append("gitdir 指到樹外（worktree 或外部 submodule），不讀")
            return g
        gitdir = os.path.relpath(rd, tree.root)
    common = gitdir
    cd, _ = tree.text(join(gitdir, "commondir"), MAX_SMALL)
    if cd and cd.strip():
        c = os.path.realpath(os.path.join(tree.root, gitdir, cd.strip()))
        if not tree.inside(c):
            g["notes"].append("commondir 指到樹外，不讀 refs")
            return g
        common = os.path.relpath(c, tree.root)
    head, err = tree.text(join(gitdir, "HEAD"), MAX_SMALL)
    if head is None:
        g["notes"].append(f"讀不到 HEAD（{READ_ERR.get(err, err)}）")
        return g
    head = head.strip()
    packed, peeled, fully = read_packed_refs(tree, common, g)
    if head.startswith("ref:"):
        ref = head[4:].strip()
        if not REF_NAME.match(ref) or ".." in ref:
            g["notes"].append("HEAD 的 ref 名稱不合法")
            return g
        g["branch"] = ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref
        sha, _ = tree.text(join(common, ref), MAX_SMALL)
        sha = (sha or "").strip() or packed.get(ref)
        if not sha or not HEX_SHA.match(sha):
            g["notes"].append(f"branch {clean(g['branch'], 80)} 沒有 commit（沒有 git 歷史或 ref 讀不到）")
            return g
        g["commit"] = sha
    elif HEX_SHA.match(head):
        g["commit"] = head
    else:
        g["notes"].append("HEAD 格式不對")
        return g
    tags = {r[len("refs/tags/"):]: s for r, s in packed.items() if r.startswith("refs/tags/")}
    loose = loose_tags(tree, join(common, "refs/tags"), g)
    for name, sha in loose.items():
        tags[name] = sha
        peeled.pop("refs/tags/" + name, None)        # loose 覆蓋 packed：packed 的 peeled 不再適用
    # 每個 tag 指到哪個 commit：packed 的 ^peeled、packed-refs 有 peeled 特性（沒有 ^ 行＝不是附註 tag）、
    # 等於 HEAD、loose 物件（tag 物件取 object 行；commit 物件就是它自己）；都不行 → None（讀不到，不猜）
    targets = {}
    for name, sha in tags.items():
        ref = "refs/tags/" + name
        if ref in peeled:
            targets[name] = peeled[ref]
        elif fully and name not in loose:
            targets[name] = sha
        elif sha == g["commit"]:
            targets[name] = sha
        else:
            obj = read_loose_object(tree, common, sha)
            m = re.match(rb"^tag \d+\x00object ([0-9a-f]{40,64})\n", obj or b"")
            targets[name] = m.group(1).decode() if m else (sha if (obj or b"").startswith(b"commit ") else None)
    g["tag_targets"] = targets
    g["tags"] = sorted(clean(t, 200) for t, c in targets.items() if c == g["commit"])
    g["unpeeled_tags"] = sum(1 for c in targets.values() if c is None)
    cfg, _ = tree.text(join(common, "config"), MAX_HEADER)
    if cfg:
        m = re.search(r'^\s*\[remote\s+"origin"\]\s*$(.*?)(?=^\s*\[|\Z)', cfg, re.M | re.S)
        if m:
            u = re.search(r"^\s*url\s*=\s*(\S+)\s*$", m.group(1), re.M)
            g["remote_url"] = safe_url(u.group(1)) if u else None
    return g


def empty_git():
    return {"present": False, "branch": None, "commit": None, "tags": [], "tag_targets": {}, "unpeeled_tags": 0,
            "remote_url": None, "notes": []}


def read_packed_refs(tree, common, g):
    txt, err = tree.text(join(common, "packed-refs"), MAX_PACKED_REFS)
    refs, peeled, fully = {}, {}, False
    if txt is None:
        if err not in ("missing",):
            g["notes"].append(f"packed-refs {READ_ERR.get(err, err)}，沒有讀")
        return refs, peeled, fully
    last = None
    for ln in txt.splitlines():
        if ln.startswith("#"):
            # 「peeled」：refs/tags 下的附註 tag 都有 ^ 行；「fully-peeled」：所有 ref 都有（兩者對 tag 都夠）
            fully = fully or bool({"peeled", "fully-peeled"} & set(ln.split()))
            continue
        if ln.startswith("^"):
            if last and HEX_SHA.match(ln[1:].strip()):
                peeled[last] = ln[1:].strip()
            continue
        parts = ln.split(" ", 1)
        if len(parts) == 2 and HEX_SHA.match(parts[0]) and REF_NAME.match(parts[1].strip()):
            last = parts[1].strip()
            refs[last] = parts[0]
        else:
            last = None
    return refs, peeled, fully


def loose_tags(tree, rel, g):
    out = {}
    base = tree.resolve(rel)
    if not base or not os.path.isdir(base):
        return out
    stack = [("", 0)]
    while stack:
        sub, depth = stack.pop()
        try:
            with os.scandir(os.path.join(base, sub)) as it:
                ents = list(it)
        except OSError:
            g["notes"].append(f"refs/tags/{clean(sub, 80)} 讀不到，裡面的 tag 沒有讀")
            g["tags_incomplete"] = True
            continue
        for e in ents:
            name = f"{sub}/{e.name}" if sub else e.name
            if e.is_dir(follow_symlinks=False):
                if depth < 8:
                    stack.append((name, depth + 1))
            elif e.is_file(follow_symlinks=False):
                if len(out) >= MAX_LOOSE_TAGS:
                    g["notes"].append(f"loose tag 超過 {MAX_LOOSE_TAGS} 個，其餘沒有讀")
                    return out
                txt, _ = tree.text(join(rel, name), MAX_SMALL)
                if txt and HEX_SHA.match(txt.strip()) and REF_NAME.match("refs/tags/" + name):
                    out[name] = txt.strip()
    return out


def read_loose_object(tree, common, sha):
    data, _ = tree.read(join(common, "objects", sha[:2], sha[2:]), MAX_GIT_OBJECT)
    if data is None:
        return None
    try:
        d = zlib.decompressobj()
        return d.decompress(data, MAX_GIT_OBJECT_INFLATED)
    except zlib.error:
        return None


# ---------- manifest ----------

def read_manifest(path, combination):
    """回傳 {"format", "combination", "combination_basis", "entries": {相對路徑: {...}}, "error", "notes"}。"""
    m = {"path": label(path), "format": None, "combination": None, "combination_basis": None, "entries": {}, "other": [],
         "error": None, "notes": []}
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                m["error"] = "manifest 不是一般檔案"
                return m
            data = f.read(MAX_MANIFEST + 1)
    except OSError as e:
        m["error"] = f"manifest 讀不到（{type(e).__name__}）"
        return m
    if len(data) > MAX_MANIFEST:
        m["error"] = f"manifest 過大（> {MAX_MANIFEST} bytes）"
        return m
    if b"\x00" in data or data.startswith((b"\xff\xfe", b"\xfe\xff")):
        m["error"] = "manifest 不是 UTF-8（含 NUL 或 UTF-16 BOM），不解析"
        return m
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        m["error"] = "manifest 不是 UTF-8，不解析"
        return m
    decl = re.match(r"\s*<\?xml[^>]*\bencoding\s*=\s*[\"']([^\"']+)[\"']", text)
    if decl and decl.group(1).strip().lower().replace("_", "-") not in ("utf-8", "utf8"):
        m["error"] = f"manifest 宣告的編碼是 {clean(decl.group(1), 20)}，只收 UTF-8，不解析"
        return m
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        m["error"] = "manifest 含 DOCTYPE／ENTITY，不解析"
        return m
    if not text.lstrip().startswith("<"):
        m["error"] = "manifest 不是 XML（west 的 YAML 不支援）"
        return m
    try:                                  # 再用 expat 擋一次：任何 DOCTYPE 或實體宣告都中止（不靠位元組比對）
        px = pyexpat.ParserCreate()

        def no_dtd(*_):
            raise ValueError("DOCTYPE／ENTITY")
        px.StartDoctypeDeclHandler = no_dtd
        px.EntityDeclHandler = no_dtd
        px.Parse(data, True)
    except (pyexpat.ExpatError, ValueError) as e:
        m["error"] = f"manifest XML 解析失敗或含 DOCTYPE／ENTITY（{clean(e, 120)}）"
        return m
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError) as e:
        m["error"] = f"manifest XML 解析失敗（{clean(e, 120)}）"
        return m
    n = 0
    for _ in root.iter():
        n += 1
        if n > MAX_MANIFEST_ELEMENTS:
            m["error"] = f"manifest 元素超過 {MAX_MANIFEST_ELEMENTS} 個"
            return m
    if root.tag == "Manifest":
        edkrepo(root, combination, m)
    elif root.tag == "manifest":
        repo(root, m)
    else:
        m["error"] = f"不認得的 manifest 格式（根元素 {clean(root.tag, 40)}）"
    return m


def ref_entry(path, url, tag=None, branch=None, commit=None, ambiguous=None):
    e = {"path": clean(path, 300), "url": safe_url(url), "tag": None, "branch": None, "commit": None, "ambiguous": None}
    if commit:
        c = commit.strip().lower()
        e["commit"] = c if HEX_SHA.match(c) else None
        if not e["commit"]:
            e["ambiguous"] = clean(commit, 120)
    if tag:
        e["tag"] = clean(tag.strip(), 200)
    if branch:
        e["branch"] = clean(branch.strip(), 200)
    if ambiguous:
        e["ambiguous"] = clean(ambiguous.strip(), 200)
    return e


def edkrepo(root, combination, m):
    m["format"] = "edkrepo"
    remotes = {r.get("name"): (r.text or "").strip() for r in root.iter("Remote")}
    name, basis = combination, "argument"
    if not name:
        cur = root.find("GeneralConfig/CurrentClonedCombo")
        name, basis = (cur.get("combination") if cur is not None else None), "CurrentClonedCombo"
    if not name:
        m["error"] = "manifest 沒有 CurrentClonedCombo，請用 --combination 指定（不改用 DefaultCombo）"
        return
    m["combination"], m["combination_basis"] = clean(name, 120), basis
    combo = next((c for c in root.iter("Combination") if c.get("name") == name), None)
    if combo is None:
        m["error"] = f"manifest 沒有 combination {clean(name, 120)}"
        return
    for s in combo.iter("Source"):
        lr = (s.get("localRoot") or "").strip().strip("/")
        if not lr or ".." in lr.split("/"):
            continue
        m["entries"][lr] = ref_entry(lr, remotes.get(s.get("remote")), s.get("tag"), s.get("branch"), s.get("commit"))


def repo(root, m):
    m["format"] = "repo"
    remotes = {r.get("name"): r for r in root.findall("remote")}
    default = root.find("default")
    dflt_rev = default.get("revision") if default is not None else None
    dflt_remote = default.get("remote") if default is not None else None
    if root.findall("include") or root.findall("extend-project") or root.findall("remove-project"):
        m["notes"].append("manifest 有 include／extend-project／remove-project，沒有展開（revision 可能不同）")
    for p in root.findall("project"):
        path = (p.get("path") or p.get("name") or "").strip().strip("/")
        if not path or ".." in path.split("/"):
            continue
        rem = remotes.get(p.get("remote") or dflt_remote)
        rev = p.get("revision") or (rem.get("revision") if rem is not None else None) or dflt_rev
        url = None
        if rem is not None and rem.get("fetch"):
            url = rem.get("fetch").rstrip("/") + "/" + (p.get("name") or "")
        rev = (rev or "").strip()
        if HEX_SHA.match(rev.lower()):
            e = ref_entry(path, url, commit=rev)
        elif rev.startswith("refs/tags/"):
            e = ref_entry(path, url, tag=rev[len("refs/tags/"):])
        elif rev.startswith("refs/heads/"):
            e = ref_entry(path, url, branch=rev[len("refs/heads/"):])
        elif rev:
            e = ref_entry(path, url, ambiguous=rev)
        else:
            e = ref_entry(path, url)
        m["entries"][path] = e


# ---------- 版本判定 ----------

def tag_key(t):
    return [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.split(r"(\d+)", t) if x]


def prefer_tag(tags, kind):
    """多個 tag 指到同一個 commit 時選哪個：edk2 先選 edk2-stable*，edk2-nvidia 先選 rX.Y／uefi-；同一類有多個時取版本最低的
    （內容相同，取最低的比對公告比較保守），回傳 (tag, 同一類的其他 tag)。"""
    if not tags:
        return None, []
    order = [EDK2_STABLE, JETSON_TAG, NV_SERVER_TAG] if kind == "edk2" else [JETSON_TAG, NV_SERVER_TAG, EDK2_STABLE]
    for rx in order:
        hit = sorted((t for t in tags if rx.match(t)), key=tag_key)
        if hit:
            return hit[0], hit[1:]
    hit = sorted(tags, key=tag_key)
    return hit[0], hit[1:]


def decide(kind, git, man):
    """回傳 (version, basis, evidence, gaps, attention)。
    規則（保守）：.git 存在就以 .git 為準；manifest 和 .git 有任何不一致（tag 指到別的 commit、tag 在 .git 裡沒有或讀不到、
    commit 不同）→ GAP；.git 存在但讀不到 HEAD 的 commit → GAP（manifest 的 tag 只記成「可能是」）；
    沒有 .git 時才用 manifest 的 tag（ATTENTION：沒有核對）。"""
    ev, gaps, att = [], [], []
    if git["present"]:
        for t in git["tags"]:
            ev.append({"source": "git", "kind": "tag", "value": t})
        if git["commit"]:
            ev.append({"source": "git", "kind": "commit", "value": git["commit"]})
        if git["branch"]:
            ev.append({"source": "git", "kind": "branch", "value": clean(git["branch"], 200)})
        for n in git["notes"]:
            ev.append({"source": "git", "kind": "note", "value": n})
    mtag = (man or {}).get("tag")
    mcommit = (man or {}).get("commit")
    if man:
        for k in ("commit", "branch"):
            if man.get(k):
                ev.append({"source": "manifest", "kind": k, "value": man[k]})
        if man.get("ambiguous"):
            ev.append({"source": "manifest", "kind": "ref (branch or tag?)", "value": man["ambiguous"]})

    def maybe():
        if mtag:
            ev.append({"source": "manifest", "kind": "tag (possible version, not confirmed by .git)", "value": mtag})

    if git["present"] and not git["commit"]:
        maybe()
        notes = git["notes"]
        if git["branch"]:
            notes = [f"只有 branch 名稱 {clean(git['branch'], 80)}、沒有 git 歷史或 ref 讀不到"] + \
                    [n for n in notes if not n.startswith("branch ")]
        why = "；".join(notes) or "讀不到 HEAD 的 commit"
        gaps.append(f".git 存在但讀不到 HEAD 的 commit（{why}）：無法確認樹的版本，版本不明"
                    + (f"（manifest 的 tag {mtag} 只是「可能是」）" if mtag else ""))
        return None, None, ev, gaps, att
    if git["commit"]:
        head = git["commit"][:12]
        if mcommit and mcommit != git["commit"]:
            maybe()
            gaps.append(f"manifest 的 commit {mcommit[:12]} 與 .git 的 HEAD {head} 不同：manifest 與 .git 不一致，版本不明")
            return None, None, ev, gaps, att
        if mtag:
            targets = git.get("tag_targets", {})
            if mtag not in targets:
                maybe()
                at = f"（HEAD 上的 tag：{', '.join(git['tags'][:3])}）" if git["tags"] else ""
                gaps.append(f"manifest 的 tag {mtag} 在 .git 裡沒有{at}：無法確認 HEAD {head} 是這個 tag，版本不明")
                return None, None, ev, gaps, att
            t = targets[mtag]
            if t is None:
                maybe()
                gaps.append(f"manifest 的 tag {mtag} 在 .git 裡指到的物件讀不到（附註 tag 在 pack 檔）：無法確認 HEAD {head} 是這個 tag，版本不明")
                return None, None, ev, gaps, att
            if t != git["commit"]:
                maybe()
                gaps.append(f"manifest 的 tag {mtag} 指到 {t[:12]}，.git 的 HEAD 是 {head}：manifest 與 .git 不一致，版本不明")
                return None, None, ev, gaps, att
            ev.append({"source": "manifest", "kind": "tag (confirmed by .git)", "value": mtag})
            return mtag, "manifest tag confirmed by .git (tag points to HEAD)", ev, gaps, att
        gtag, others = prefer_tag(git["tags"], kind)
        if gtag:
            if others:
                att.append(f"同一個 commit 有多個 tag（{', '.join([gtag] + others[:5])}），版本取最低的 {gtag}（保守）")
            return gtag, "git tag at HEAD", ev, gaps, att
        extra = ""
        if git["unpeeled_tags"]:
            extra = f"；另有 {git['unpeeled_tags']} 個 tag 指到的物件在 pack 檔讀不到（附註 tag 在 pack 檔），可能其中之一指到 HEAD"
        elif git.get("tags_incomplete"):
            extra = "；有 tag 資料夾讀不到"
        on = f"branch {clean(git['branch'], 80)} 的 " if git["branch"] else ""
        gaps.append(f"{on}commit {head} 沒有對到任何 tag：版本不明（不猜）{extra}")
        return None, None, ev, gaps, att
    # 沒有 .git
    if mtag:
        ev.append({"source": "manifest", "kind": "tag", "value": mtag})
        att.append("版本只來自 manifest（沒有 .git），沒有核對樹的內容")
        return mtag, "manifest tag (no .git; not verified)", ev, gaps, att
    if mcommit:
        gaps.append(f"manifest 只有 commit {mcommit[:12]}，沒有 tag：版本不明（不猜）")
    elif man and man.get("branch"):
        gaps.append(f"只有 branch 名稱 {clean(man['branch'], 80)}、沒有可對應的 commit 或 tag：branch 會移動，版本不明")
    elif man and man.get("ambiguous"):
        gaps.append(f"manifest 的 revision {man['ambiguous']} 沒有 refs/tags/ 前綴，分不出 branch 或 tag：版本不明")
    else:
        gaps.append("沒有 .git、也沒有 manifest 的項目：版本不明")
    return None, None, ev, gaps, att


# ---------- 加密函式庫 ----------

def openssl_number(n):
    """OPENSSL_VERSION_NUMBER → (版本, 狀態)。
    1.x／0.9.x：0xMNNFFPPS（PP 是字母修補號、S 是狀態：0 dev、1–e beta、f release）。
    3.x 起：0xMNN00PP0L（PP 是 patch；狀態位元一律 0，不帶預發行資訊）→ 狀態 "unknown"。"""
    major = (n >> 28) & 0xF
    if major >= 3:
        return f"{major}.{(n >> 20) & 0xFF}.{(n >> 4) & 0xFF}", "unknown"
    minor, fix, patch, status = (n >> 20) & 0xFF, (n >> 12) & 0xFF, (n >> 4) & 0xFF, n & 0xF
    letters = "" if patch == 0 else (chr(96 + patch) if patch <= 26 else "z" + chr(96 + patch - 26))
    return f"{major}.{minor}.{fix}{letters}", ("release" if status == 0xF else "dev" if status == 0 else "beta")


def ascii_int(v):
    """只收 ASCII 數字（int() 會收全形數字與底線，例如「１５」「1_5」）。"""
    if not re.fullmatch(r"[0-9]{1,6}", v or ""):
        raise ValueError(v)
    return int(v)


def read_openssl(tree, rel):
    """回傳 {"version", "basis", "prerelease", "notes", "files"} 或 version None。"""
    r = {"version": None, "basis": None, "prerelease": None, "build_metadata": None, "notes": [], "conflict": None}
    vd, verr = tree.text(join(rel, "VERSION.dat"), MAX_SMALL)
    hv, herr = tree.text(join(rel, "include/openssl/opensslv.h"), MAX_HEADER)
    for f, err in (("VERSION.dat", verr), ("include/openssl/opensslv.h", herr)):
        if err and err != "missing":
            r["notes"].append(f"{f}：{READ_ERR.get(err, err)}")
    v_dat = v_text = v_num = None
    if vd is not None:
        kv = {}
        for ln in vd.splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                kv[k.strip()] = v.strip().strip('"')
        try:
            base = f"{ascii_int(kv['MAJOR'])}.{ascii_int(kv['MINOR'])}.{ascii_int(kv['PATCH'])}"
            pre, meta = kv.get("PRE_RELEASE_TAG", ""), kv.get("BUILD_METADATA", "")
            if pre and not re.fullmatch(r"[A-Za-z0-9.]{1,40}", pre, re.A):
                raise ValueError
            if meta and not re.fullmatch(r"[A-Za-z0-9.+-]{1,40}", meta.lstrip("+"), re.A):
                raise ValueError
            v_dat = base + (f"-{pre}" if pre else "")
            r["prerelease"] = pre or None
            r["build_metadata"] = meta.lstrip("+") or None
        except (KeyError, ValueError):
            r["notes"].append("VERSION.dat 格式不對（MAJOR／MINOR／PATCH）")
    if hv is not None:
        texts = [a + b for a, b in re.findall(
            r'^\s*#\s*define\s+OPENSSL_VERSION_TEXT\s+"OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]{0,2})(-[A-Za-z0-9.]+)?[\s"]', hv, re.M | re.A)]
        # 1.0.2 的標頭有 #ifdef OPENSSL_FIPS 的「-fips」與一般兩個定義：取一般的
        plain = [t for t in texts if not t.endswith("-fips")]
        if texts:
            v_text = (plain or texts)[0]
        m = re.search(r"^\s*#\s*define\s+OPENSSL_VERSION_NUMBER\s+0x([0-9a-fA-F]{8,9})L?\b", hv, re.M)
        if m:
            v_num = openssl_number(int(m.group(1), 16))
    # 互相矛盾時不挑一個（版本不明、不給 CPE），兩個值都寫在 conflict
    if v_dat:
        if v_text and v_text != v_dat:
            r["conflict"] = f"VERSION.dat 是 {v_dat}，include/openssl/opensslv.h 的 OPENSSL_VERSION_TEXT 是 {v_text}"
            return r
        r["version"], r["basis"] = v_dat, "VERSION.dat"
        return r
    if v_text:
        if v_num:
            nv, nst = v_num
            if nv != v_text.split("-", 1)[0]:
                r["conflict"] = f"OPENSSL_VERSION_TEXT 是 {v_text}，OPENSSL_VERSION_NUMBER 是 {nv}"
                return r
            if nst in ("dev", "beta") and "-" not in v_text:
                r["prerelease"] = nst
        r["version"], r["basis"] = v_text, "include/openssl/opensslv.h OPENSSL_VERSION_TEXT"
        if "-" in v_text:
            r["prerelease"] = v_text.split("-", 1)[1]
        return r
    if v_num:
        nv, nst = v_num
        r["basis"] = "include/openssl/opensslv.h OPENSSL_VERSION_NUMBER"
        if nst == "unknown":            # 3.x 的 NUMBER 不帶預發行資訊：版本記下，但不能當正式發行版
            r["version"], r["prerelease"] = nv, "unknown (3.x OPENSSL_VERSION_NUMBER has no pre-release information)"
        else:
            r["version"] = nv + ("" if nst == "release" else f"-{nst}")
            r["prerelease"] = None if nst == "release" else nst
        return r
    if tree.exists(join(rel, "include/openssl/opensslv.h.in")):
        r["notes"].append("只有 opensslv.h.in（範本）、沒有 VERSION.dat：讀不到版本")
    return r


def read_mbedtls(tree, rel):
    r = {"version": None, "basis": None, "prerelease": None, "build_metadata": None, "notes": [], "conflict": None}
    found = {}
    for f in ("include/mbedtls/build_info.h", "include/mbedtls/version.h"):
        txt, err = tree.text(join(rel, f), MAX_HEADER)
        if err and err != "missing":
            r["notes"].append(f"{f}：{READ_ERR.get(err, err)}")
        if txt:
            m = re.search(r'^\s*#\s*define\s+MBEDTLS_VERSION_STRING\s+"([0-9]+\.[0-9]+\.[0-9]+)"', txt, re.M | re.A)
            if m:
                found[f] = m.group(1)
    if found:
        if len(set(found.values())) > 1:
            r["conflict"] = "；".join(f"{k} 是 {v}" for k, v in sorted(found.items()))
            return r
        f0 = sorted(found)[0]
        r["version"], r["basis"] = found[f0], f"{f0} MBEDTLS_VERSION_STRING"
    return r


LIBS = {
    "openssl": {"name": "openssl", "label": "OpenSSL", "reader": read_openssl, "cpe": "cpe:2.3:a:openssl:openssl:{v}:*:*:*:*:*:*:*"},
    "mbedtls": {"name": "mbedtls", "label": "Mbed TLS", "reader": read_mbedtls, "cpe": "cpe:2.3:a:arm:mbed_tls:{v}:*:*:*:*:*:*:*"},
}


def submodule_state(tree, rel, declared):
    """known 位置的狀態：absent（沒有、也沒宣告）、missing（.gitmodules 有宣告、資料夾不存在）、empty（沒取出）、
    escape（符號連結到樹外）、present。"""
    p = os.path.join(tree.root, rel)
    if not os.path.lexists(p):
        return "missing" if declared else "absent"
    real = tree.resolve(rel)
    if real is None:
        return "escape"
    if not os.path.isdir(real):
        return "not-dir"
    names = tree.listdir(rel, cap=10)
    if names is None:
        return "unreadable"
    if not [n for n in names if n != ".git"]:
        return "empty"
    return "present"


def lib_component(tree, kind, rel, role, declared):
    spec = LIBS[kind]
    c = {"id": f"{kind}:{rel}", "kind": kind, "name": spec["name"], "label": spec["label"], "path": rel, "role": role,
         "version": None, "version_basis": None, "cpe": None, "purl": f"pkg:generic/{spec['name']}", "cpe_note": None,
         "commit": None, "evidence": [], "gaps": [], "attention": [], "notes": []}
    st = submodule_state(tree, rel, declared) if role == "edk2-submodule" else "present"
    c["state"] = st
    if st == "absent":
        return None
    if st in ("missing", "empty"):
        c["gaps"].append(f"{spec['label']} submodule（{rel}）{'沒有取出（空資料夾）' if st == 'empty' else '不存在（.gitmodules 有宣告，或上一層資料夾存在）'}：版本不明，"
                         "不從 edk2 版本推")
        return c
    if st in ("escape", "not-dir", "unreadable"):
        c["gaps"].append(f"{spec['label']}（{rel}）{'是指到樹外的符號連結，拒讀' if st == 'escape' else '不是可讀的資料夾'}：版本不明")
        return c
    r = spec["reader"](tree, rel)
    c["notes"] += r["notes"]
    g = git_info(tree, rel)
    if g["commit"]:
        c["commit"] = g["commit"]
        c["evidence"].append({"source": "git", "kind": "commit", "value": g["commit"]})
    if r["conflict"]:
        c["gaps"].append(f"{spec['label']}（{rel}）版本檔互相矛盾：{r['conflict']}：不挑一個，版本不明、不給 CPE")
        return c
    if not r["version"]:
        c["gaps"].append(f"{spec['label']}（{rel}）讀不到版本檔" + (f"（{'；'.join(r['notes'])}）" if r["notes"] else ""))
        return c
    v = r["version"]
    c["version"], c["version_basis"] = v, r["basis"]
    c["evidence"].append({"source": "file", "kind": r["basis"], "value": v})
    c["purl"] = f"pkg:generic/{spec['name']}@{quote(v, safe='.-_~')}"
    if r["prerelease"] or not REL_VERSION.match(v):
        c["cpe_note"] = (f"{v} 是開發中或預發行版本（{clean(r['prerelease'] or '版本格式', 80)}），不是正式發行版，NVD 沒有對應版本：不給 CPE")
        c["gaps"].append(f"{spec['label']} {v} 不是正式發行版：不給 CPE，無法比對漏洞")
    else:
        c["cpe"] = spec["cpe"].format(v=v)
    if r.get("build_metadata"):
        c["notes"].append(f"VERSION.dat 有 BUILD_METADATA「{clean(r['build_metadata'], 40)}」（非 OpenSSL 官方的建置），CPE 用基礎版本")
    return c


# ---------- 走訪 ----------

def walk(tree, budget):
    """lstat 走訪整棵樹（不進 .git、不跟隨符號連結），找其他位置的 OpenSSL／Mbed TLS、DSC、buildid。"""
    w = {"entries": 0, "incomplete": None, "symlinks_not_followed": 0, "symlinks_outside_tree": 0, "symlinks_outside_tree_examples": [],
         "unreadable_dirs": 0, "unreadable_dir_examples": [], "too_deep": 0, "too_deep_example": None, "openssl_roots": set(), "mbedtls_roots": set(),
         "dsc": [], "buildid": []}
    stack = [("", 0)]
    try:
        while stack:
            rel, depth = stack.pop()
            budget.check()
            try:
                with os.scandir(os.path.join(tree.root, rel) if rel else tree.root) as it:
                    ents = sorted(it, key=lambda e: e.name)
            except OSError as e:          # 讀不到的資料夾：不能靜默跳過（裡面可能有其他加密函式庫）
                w["unreadable_dirs"] += 1
                if len(w["unreadable_dir_examples"]) < MAX_EVENTS:
                    w["unreadable_dir_examples"].append(f"{clean(rel or '.', 300)}（{type(e).__name__}）")
                continue
            for e in ents:
                w["entries"] += 1
                if w["entries"] > MAX_ENTRIES:
                    raise OverBudget(f"目錄項目超過 {MAX_ENTRIES} 個")
                r = f"{rel}/{e.name}" if rel else e.name
                if e.is_symlink():
                    w["symlinks_not_followed"] += 1
                    real = os.path.realpath(os.path.join(tree.root, r))
                    if not tree.inside(real):     # 逃出樹外的記下來（不跟隨、不讀；沒有要讀它，只列出）
                        w["symlinks_outside_tree"] += 1
                        if len(w["symlinks_outside_tree_examples"]) < MAX_EVENTS:
                            w["symlinks_outside_tree_examples"].append(clean(r, 300))
                    continue
                try:
                    is_dir, is_file = e.is_dir(follow_symlinks=False), e.is_file(follow_symlinks=False)
                except OSError:
                    w["unreadable_dirs"] += 1
                    continue
                if is_dir:
                    if e.name == ".git":
                        continue
                    if depth + 1 > MAX_DEPTH:
                        w["too_deep"] += 1
                        w["too_deep_example"] = w["too_deep_example"] or clean(r, 200)
                        continue
                    stack.append((r, depth + 1))
                    continue
                if not is_file:
                    continue
                if r.endswith("/include/openssl/opensslv.h") or r == "include/openssl/opensslv.h":
                    w["openssl_roots"].add(r[:-len("include/openssl/opensslv.h")].rstrip("/"))
                elif e.name == "VERSION.dat" and os.path.isdir(os.path.join(tree.root, rel, "include", "openssl")):
                    w["openssl_roots"].add(rel)
                elif r.endswith(("include/mbedtls/build_info.h", "include/mbedtls/version.h")):
                    w["mbedtls_roots"].add(r.rsplit("/include/mbedtls/", 1)[0] if "/include/mbedtls/" in r else "")
                elif e.name.endswith((".dsc", ".dsc.inc")):
                    w["dsc"].append(r)
                elif re.fullmatch(r"buildid_[A-Za-z0-9_.-]{1,100}\.txt", e.name) and rel.split("/")[-1] == "images" and depth <= 3:
                    w["buildid"].append(r)
    except OverBudget as e:
        w["incomplete"] = f"走訪沒有完成：{e}"
    more = []
    if w["too_deep"]:
        more.append(f"{w['too_deep']} 個資料夾深度超過 {MAX_DEPTH}，沒有走進去（例如 {w['too_deep_example']}）")
    if w["unreadable_dirs"]:
        more.append(f"{w['unreadable_dirs']} 個資料夾讀不到（例如 {', '.join(w['unreadable_dir_examples'][:3])}）")
    if more:
        w["incomplete"] = "；".join(([w["incomplete"]] if w["incomplete"] else []) + more)
    w["unreadable_dir_examples"].sort()
    w["dsc"].sort()
    w["buildid"].sort()
    return w


def dsc_info(tree, files):
    """DSC 的版本字串 PCD（字面值）與選用 OpensslLib／MbedTlsLib 的 DSC（只是線索）。"""
    strings, refs, total, skipped = [], {"openssl": [], "mbedtls": []}, 0, 0
    rx = re.compile(r"\.(PcdFirmwareVersionString|PcdUefiVersionString)\s*\|\s*L?\"([^\"\r\n]{0,200})\"")
    for f in files[:MAX_DSC_FILES]:
        txt, err = tree.text(f, MAX_DSC)
        if txt is None:
            skipped += 1
            continue
        total += len(txt)
        if total > MAX_DSC_TOTAL:
            skipped += 1
            break
        for m in rx.finditer(txt):
            val = m.group(2)
            strings.append({"file": clean(f, 300), "pcd": m.group(1), "value": clean(val, 200),
                            "kind": "build-time macro" if "$(" in val else "literal"})
        if not f.startswith(("CryptoPkg/", "edk2/CryptoPkg/")):
            if re.search(r"OpensslLib[A-Za-z]*\.inf", txt):
                refs["openssl"].append(f)
            if re.search(r"MbedTlsLib[A-Za-z]*\.inf", txt):
                refs["mbedtls"].append(f)
    skipped += max(0, len(files) - MAX_DSC_FILES)
    return strings, {k: v[:20] for k, v in refs.items()}, skipped


def gitmodules_paths(tree, edk2):
    txt, _ = tree.text(join(edk2, ".gitmodules"), MAX_HEADER)
    return sorted({clean(m.group(1).strip(), 300) for m in re.finditer(r"^\s*path\s*=\s*(.+?)\s*$", txt or "", re.M)})


# ---------- NVIDIA 公告 ----------

def load_nb():
    spec = importlib.util.spec_from_file_location("sca_center_nvidia_bulletins", NB_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_dsc():
    spec = importlib.util.spec_from_file_location("sca_center_uefi_dsc", DSC_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BUILD_PARAMS = re.compile(r"Edk2 build parameters are (.+)")


def build_runs(tree, explicit, defines):
    """要分析的平台 DSC：[{dsc, defines, known, source}]（known＝巨集是完整的，來自建置記錄）與備註。
    explicit：--platform-dsc；沒有就從 Build/BUILDLOG_*.txt 找。"""
    import shlex
    runs, notes, logs, unread = [], [], [], []
    for n in (tree.listdir("Build", 200) or []):
        if n.startswith("BUILDLOG_") and n.endswith(".txt"):
            txt, err = tree.head(f"Build/{n}", 1024 * 1024)
            m = BUILD_PARAMS.search(txt) if txt else None
            if not m or len(logs) >= 16:
                unread.append(n)
            if m and len(logs) < 16:
                try:
                    tok = shlex.split(m.group(1))
                except ValueError:
                    unread.append(n)
                    continue
                d, dsc = {}, None
                i = 0
                while i < len(tok):
                    a, v = tok[i], tok[i + 1] if i + 1 < len(tok) else None
                    if a == "-p" and v:
                        dsc = v
                    elif a in ("-b", "--buildtarget") and v:
                        d["TARGET"] = v
                    elif a in ("-t", "--tagname") and v:
                        d["TOOL_CHAIN_TAG"] = v
                    elif a in ("-a", "--arch") and v:
                        d.setdefault("ARCH", v)
                        d.setdefault("TARGET_ARCH", v)
                    elif a in ("-D", "--define") and v:
                        k, _, val = v.partition("=")
                        d[k] = val or "TRUE"
                    i += 1
                if dsc:
                    logs.append((f"Build/{n}", dsc, d))
                else:
                    unread.append(n)
    # Build/<名稱>/ 每個建置資料夾都要有一份讀得懂的 BUILDLOG_<名稱>.txt，否則不知道有沒有漏掉的平台
    parsed = {Path(l[0]).name for l in logs}
    for d_ in tree.listdir("Build", 200) or []:
        if tree.isdir(f"Build/{d_}") and f"BUILDLOG_{d_}.txt" not in parsed:
            unread.append(f"{d_}/（沒有讀得懂的 BUILDLOG_{d_}.txt）")
    def rel(x):
        x = x.replace("\\", "/")
        if os.path.isabs(x):
            r = os.path.realpath(x)
            if tree.inside(r):
                x = os.path.relpath(r, tree.root).replace(os.sep, "/")
            else:       # 建置記錄是別台機器寫的絕對路徑：取最長的、在樹裡存在的尾段
                parts = x.strip("/").split("/")
                x = next(("/".join(parts[k:]) for k in range(len(parts)) if tree.exists("/".join(parts[k:]))), x)
        return x[2:] if x.startswith("./") else x
    want = [rel(x) for x in explicit] if explicit else [rel(d) for _, d, _ in logs]
    for dsc in dict.fromkeys(want):
        if not tree.exists(dsc) or not dsc.endswith((".dsc", ".dsc.inc")):
            notes.append(f"平台 DSC {clean(dsc, 200)} 不在樹裡或不是 .dsc：沒有分析")
            continue
        lg = next((l for l in logs if rel(l[1]) == dsc), None)
        d = dict(lg[2]) if lg else {}
        d.update(defines)
        runs.append({"dsc": dsc, "defines": d, "known": bool(lg), "source": f"{lg[0]} (-p, -D)" if lg else
                     ("--platform-dsc（沒有對應的建置記錄：巨集不完整，依賴沒給的巨集的條件算 maybe）")})
    if unread and not explicit:
        notes.append(f"建置記錄 {', '.join(clean(x, 80) for x in unread[:5])} 讀不到建置參數（-p）：不知道還有哪些平台，built-in 不下 no 的結論")
    return runs, notes, bool(unread) and not explicit


def built_in_analysis(tree, explicit, defines):
    """→ (rep["build_analysis"] 或 None, {kind: {state, evidence, reasons}})。沒有 DSC 可分析 → (None, {})（不輸出任何 built-in）。"""
    runs, notes, incomplete = build_runs(tree, explicit, defines)
    if not runs:
        return ({"runs": [], "notes": notes}, {}) if notes else (None, {})
    dsc = load_dsc()
    results = []
    for r in runs:
        a = dsc.analyze(tree, [r["dsc"]], r["defines"], r["known"])
        results.append((r, a))
    out = {}
    for kind in dsc.MARKERS:
        sts = [a["libs"][kind]["state"] for _, a in results]
        state = "yes" if "yes" in sts else "unknown"      # 沒有 no：證明不了沒有編進去
        ev, why = [], []
        for r, a in results:
            e = a["libs"][kind]
            if e["state"] == state or state == "unknown":
                ev += [f"[{r['dsc']}] {x}" for x in e["evidence"]]
            why += [f"[{r['dsc']}] {x}" for x in e["reasons"]]
        if incomplete and state == "unknown":
            why.append("some build logs could not be read, so the list of platforms may be incomplete")
        if len(runs) != len(results) or notes:
            why.append("at least one requested or logged platform DSC was not analysed")
        out[kind] = {"state": state, "evidence": [clean(x, 400) for x in ev[:12]], "reasons": [clean(x, 500) for x in why[:6]]}
    # 建置產物（參考，不決定結論）：Build/<名稱>/<TARGET>_<TOOL>/<ARCH>/CryptoPkg/Library/ 底下有哪些函式庫的資料夾
    marks = {"openssl": "OpensslLib", "mbedtls": "MbedTlsLib"}
    outs = []
    for b in tree.listdir("Build", 200) or []:
        for y in tree.listdir(f"Build/{b}", 50) or []:
            for ar in tree.listdir(f"Build/{b}/{y}", 100) or []:
                names = tree.listdir(f"Build/{b}/{y}/{ar}/CryptoPkg/Library", 100)
                if names:
                    outs.append({"path": clean(f"Build/{b}/{y}/{ar}/CryptoPkg/Library", 300), "libraries": [clean(n, 80) for n in names]})
    for kind, e in out.items():
        for o in outs[:3]:
            e["evidence"].append(f"build output {o['path']}: {'has' if marks[kind] in o['libraries'] else 'has no'} {marks[kind]}/ (reference only, not used for the conclusion)")
    return {"runs": [{"dsc": r["dsc"], "source": r["source"], "defines_known": a["defines_known"], "files_read": a.get("files_read"),
                      "components": a.get("components"), "inf_reachable": a.get("inf_reachable"), "problems": a.get("problems", [])[:10],
                      "problems_count": a.get("problems_count", 0)} for r, a in results],
            "notes": notes, "build_output": outs[:10]}, out


def mentions_uefi(mirror, b):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", str(b.get("id"))) or not re.fullmatch(r"\d{4}", str(b.get("year") or "")):
        return None                      # index.json 的編號或年份不像路徑元件：不拼路徑
    base = os.path.join(mirror, str(b.get("year") or ""), str(b["id"]))
    for ext in (".md", ".json"):
        p = os.path.join(base, f"{b['id']}{ext}")
        try:
            if not stat.S_ISREG(os.lstat(p).st_mode):
                continue
            with open(p, "rb") as f:
                if re.search(rb"\bUEFI\b", f.read(MAX_BULLETIN_SCAN)):
                    return True
        except OSError:
            continue
    return False


def table_label(path):
    """對照表的標籤：repo 內建的寫相對路徑，其他只留檔名。"""
    try:
        if Path(path).resolve() == DEFAULT_TABLE.resolve():
            return "tools/pilot/lib/nvidia-bulletins.json"
    except OSError:
        pass
    return label(path)


def bulletin_check(nvidia, mirror_dir, table_path):
    """回傳 dict：status（NOT_RUN／GAP／ATTENTION／OK）、detail 與各清單。"""
    out = {"status": "NOT_RUN", "detail": None, "jetson_linux_version": None, "mirror": None, "table": None,
           "hits": [], "unreviewed_would_match": [], "fixed_per_table": [], "fixed_unreviewed": [], "undetermined": [],
           "other_components_unreviewed": [], "same_line_unreviewed_rows": 0, "pending_bulletins": [], "gaps": []}
    if nvidia is None:
        out["detail"] = "沒有 edk2-nvidia：不是 Jetson UEFI，不比對 NVIDIA 公告"
        return out
    v = nvidia.get("version")
    m = JETSON_TAG.match(v or "")
    if not m:
        out["status"] = "GAP"
        out["detail"] = ("edk2-nvidia 版本不明，無法判定落在哪些公告的受影響範圍" if not v else
                         f"edk2-nvidia {v} 不是 Jetson 發行 tag（rX.Y[.Z]），對應不到 Jetson Linux 版本：無法判定")
        return out
    jl = m.group(1)
    out["jetson_linux_version"] = jl
    nb = load_nb()
    line = str(nb.vkey(jl)[0])
    if not mirror_dir:
        out["gaps"].append("沒有指定 NVIDIA 公告鏡像（--bulletin-mirror），無法確認對照表涵蓋最新公告")
        mirror = None
    else:
        mirror = nb.mirror_state(mirror_dir)
        # nvidia_bulletins 的說明含鏡像的完整路徑：輸出只留資料夾名稱（輸出不放絕對路徑）
        reason = (mirror.get("reason") or "").replace(str(mirror_dir), label(mirror_dir)) or None
        out["mirror"] = {"path": label(mirror_dir), "ok": mirror.get("ok"), "reason": reason, "commit": mirror.get("commit"),
                         "fetched_utc": mirror.get("fetched_utc"), "max_age_days": mirror.get("max_age_days")}
        if not mirror["ok"]:
            out["gaps"].append(f"{reason}，無法確認對照表涵蓋最新公告")
    table = None
    try:
        tp = str(table_path)
        if not os.path.isfile(tp) or os.path.getsize(tp) > MAX_TABLE:
            raise nb.InputError("不存在或過大")
        with open(tp, "rb") as f:
            table = nb.validate_table(json.loads(f.read(MAX_TABLE + 1)))
    except (OSError, ValueError, RecursionError, nb.InputError) as e:
        out["gaps"].append(f"NVIDIA 公告對照表（{table_label(table_path)}）無法使用（{clean(str(e).replace(str(table_path), table_label(table_path)), 120)}）")
    if table is None:
        out["status"], out["detail"] = "GAP", "；".join(out["gaps"])
        return out
    rows = table.get("rows", [])
    buls = {b["id"]: b for b in table.get("bulletins", [])}
    out["table"] = {"path": table_label(table_path), "reviewed_until": table.get("reviewed_until"), "rows": len(rows),
                    "uefi_rows": sum(1 for r in rows if r.get("component") == "UEFI")}

    def entry(r, why=None):
        e = {"bulletin": r["bulletin"], "cve": r["cve"], "line": r["line"], "affected_text": r.get("affected_text"),
             "fixed_text": r.get("fixed_text"), "reviewed": r["reviewed"], "title": (buls.get(r["bulletin"]) or {}).get("title")}
        if why:
            e["reason"] = why
        return e

    # 哪些列要看（M3）：component=UEFI 的列；未審核、元件是推測的（COMPONENT_HINTS 從描述猜的）而且在 flash 或位置不明的列；
    # 元件未寫明的列。只有「已審核、元件明確不是 UEFI」的列才排除；未審核、推測在 rootfs 套件的列只計數列出。
    def candidate(r):
        comp, where = r.get("component"), r.get("where_it_lives") or "unknown"
        if comp == "UEFI":
            return "uefi"
        if comp in (None, "", "未寫明"):
            return "unspecified"
        if not r["reviewed"] and where in ("flash", "unknown"):
            return "unreviewed-guess"
        if not r["reviewed"]:
            return "unreviewed-rootfs"
        return None

    uefi_keys, named = set(), {}
    for r in rows:
        if r.get("component") == "UEFI":
            uefi_keys.add((r["bulletin"], r["cve"]))
            named.setdefault((r["bulletin"], r["cve"]), set()).add(r["line"])
    for r in rows:
        if r["line"] != line:
            continue
        kind = candidate(r)
        if kind in ("uefi", "unspecified", "unreviewed-guess") and not r["reviewed"]:
            out["same_line_unreviewed_rows"] += 1
        if kind == "uefi":
            res = nb.evaluate(r, jl)
            if res == "affected":
                (out["hits"] if r["reviewed"] else out["unreviewed_would_match"]).append(entry(r))
            elif res == "fixed":
                (out["fixed_per_table"] if r["reviewed"] else out["fixed_unreviewed"]).append(entry(r))
            else:
                out["undetermined"].append(entry(r, f"Jetson Linux {jl} 不在受影響範圍內、也沒有達到修正版本（範圍空隙）"))
        elif kind == "unspecified" and (r["bulletin"], r["cve"]) not in uefi_keys:
            out["undetermined"].append(entry(r, "對照表沒有寫明元件，可能是 UEFI"))
        elif kind == "unreviewed-guess" and (r["bulletin"], r["cve"]) not in uefi_keys:
            out["undetermined"].append(entry(r, f"未審核的列，元件「{clean(r.get('component'), 40)}」是推測的、位置 "
                                                f"{clean(r.get('where_it_lives') or 'unknown', 40)}：可能是 UEFI"))
        elif kind == "unreviewed-rootfs":
            out["other_components_unreviewed"].append(entry(r, f"未審核，元件推測為 {clean(r.get('component'), 40)}"
                                                               f"（{clean(r.get('where_it_lives'), 40)}，rootfs 套件）：不當成 UEFI"))
    for (bid, cve), ls in sorted(named.items()):
        if line not in ls:
            r = next(x for x in rows if x["bulletin"] == bid and x["cve"] == cve and x.get("component") == "UEFI")
            e = entry(r, f"公告的 UEFI 列只列版本線 {', '.join(sorted(ls))}，沒有列 {line}")
            e["line"] = None
            out["undetermined"].append(e)
    for k in ("hits", "unreviewed_would_match", "fixed_per_table", "fixed_unreviewed", "undetermined", "other_components_unreviewed"):
        seen, keep = set(), []
        for x in sorted(out[k], key=lambda x: (x["bulletin"], x["cve"], x.get("reason") or "")):
            key = (x["bulletin"], x["cve"], x.get("reason"))
            if key not in seen:
                seen.add(key)
                keep.append(x)
        out[k] = keep
    if mirror and mirror["ok"]:
        pend = nb.pending_bulletins(mirror["bulletins"], table)
        stale = [p for p in pend if {"not_in_table", "revised"} & set(p["reasons"])]
        byid = {b["id"]: b for b in mirror["bulletins"]}
        for p in stale:
            out["pending_bulletins"].append({"id": p["id"], "title": p.get("title"), "reasons": p["reasons"],
                                             "mentions_uefi": mentions_uefi(mirror_dir, byid[p["id"]])})
        if stale:
            nu = sum(1 for p in out["pending_bulletins"] if p["mentions_uefi"])
            out["gaps"].append(f"鏡像有 {len(stale)} 則 Jetson／IGX 公告對照表還沒有或已被修訂（其中 {nu} 則提到 UEFI；"
                               f"{', '.join(p['id'] for p in stale[:6])}）：這些公告無法判定")
    parts = [f"Jetson Linux {jl}（edk2-nvidia {v}）"]
    if out["hits"]:
        parts.append(f"落在 {len(out['hits'])} 筆公告的受影響範圍（{', '.join(sorted({x['cve'] for x in out['hits']})[:4])}）")
    if out["unreviewed_would_match"]:
        parts.append(f"未審核的列會命中 {len(out['unreviewed_would_match'])} 筆（不算發現）")
    if out["undetermined"]:
        parts.append(f"無法判定 {len(out['undetermined'])} 筆")
    if out["fixed_per_table"]:
        parts.append(f"已達修正版本 {len(out['fixed_per_table'])} 筆（已審核的列）")
    if out["fixed_unreviewed"]:
        parts.append(f"依未審核的列已達修正版本 {len(out['fixed_unreviewed'])} 筆（未確認）")
    if out["same_line_unreviewed_rows"]:
        parts.append(f"{line} 版本線有 {out['same_line_unreviewed_rows']} 列可能相關的列未審核")
    if out["other_components_unreviewed"]:
        parts.append(f"另有 {len(out['other_components_unreviewed'])} 列未審核、元件推測為 rootfs 套件的列（推測未經確認，不當成排除依據）")
    if not (out["hits"] or out["unreviewed_would_match"] or out["undetermined"] or out["fixed_per_table"] or out["fixed_unreviewed"]):
        parts.append("對照表沒有這個版本線的 UEFI 列")
    if out["gaps"]:
        out["status"] = "GAP"
    elif (out["hits"] or out["unreviewed_would_match"] or out["undetermined"] or out["fixed_unreviewed"]
          or out["same_line_unreviewed_rows"] or out["other_components_unreviewed"]):
        # 和 nvidia_bulletins.match 的 unrev_same 一樣：同版本線有任何未審核的列（含推測為 rootfs 套件的列）至少 ATTENTION
        # 元件推測（COMPONENT_HINTS）沒有人看過，不能當成「與 UEFI 無關」的依據
        out["status"] = "ATTENTION"
    else:
        out["status"] = "OK"
    out["detail"] = "；".join(out["gaps"] + parts)
    return out


# ---------- 主流程 ----------

def uefi_component(tree, kind, rel, man_entry):
    git = git_info(tree, rel) if rel is not None and tree.isdir(rel) else empty_git()
    v, basis, ev, gaps, att = decide(kind, git, man_entry)
    name = "edk2" if kind == "edk2" else "edk2-nvidia"
    c = {"id": kind, "kind": kind, "name": name, "label": name, "path": rel if rel is not None else None, "role": "uefi",
         "version": v, "version_basis": basis, "cpe": None, "purl": f"pkg:generic/{name}", "cpe_note": None,
         "commit": git["commit"] or (man_entry or {}).get("commit"), "evidence": ev, "gaps": gaps, "attention": att, "notes": [],
         "vcs": (man_entry or {}).get("url") or git["remote_url"], "upstream_base": None, "state": "present" if rel is not None else "manifest-only"}
    if v:
        c["purl"] = f"pkg:generic/{name}@{quote(v, safe='.-_~')}"
    if kind == "edk2":
        m = EDK2_STABLE.match(v or "")
        if m:
            c["cpe"] = f"cpe:2.3:a:tianocore:edk2:{m.group(1)}:*:*:*:*:*:*:*"
        elif v:
            b = EDK2_BASE_IN.search(v)
            c["upstream_base"] = f"edk2-stable{b.group(1)}" if b else None
            c["cpe_note"] = (f"{v} 不是 upstream 的 edk2-stableYYYYMM tag（是 fork 的 tag），NVD 的 tianocore:edk2 版本寫法是 YYYYMM，對不上：不給 CPE"
                             + (f"；tag 名稱指出 upstream 基礎是 {c['upstream_base']}，但 fork 可能另有修補，不拿來比對" if b else ""))
            c["gaps"].append(f"edk2 {v} 沒有可比對的 CPE（fork 的 tag），Grype／DT 不會比對 edk2 本身的漏洞")
    else:
        c["cpe_note"] = ("NVD 沒有 edk2-nvidia 的 CPE；Jetson 的 UEFI 漏洞由 NVIDIA 公告（cpe:2.3:o:nvidia:jetson_linux 是整個 OS，"
                         "加在這裡會把核心等漏洞也算到 UEFI）比對，見報告的 bulletins")
    return c


def analyse(tree_path, manifest=None, combination=None, mirror=None, table=None, budget=None, platform_dsc=(), platform_define=None):
    budget = budget or Budget()
    if not os.path.isdir(tree_path):
        raise Fail(f"--tree 不是資料夾（{label(tree_path)}）")
    tree = Tree(tree_path)
    if tree.isdir("MdePkg"):
        edk2, layout = "", "edk2-root"
    elif tree.isdir("edk2/MdePkg"):
        edk2, layout = "edk2", "workspace"
    else:
        edk2, layout = None, "unknown"
    nvidia_rel = "edk2-nvidia" if layout == "workspace" and tree.isdir("edk2-nvidia") else None
    man = read_manifest(manifest, combination) if manifest else None
    entries = (man or {}).get("entries", {})
    gaps, att = [], []
    if man and man["error"]:
        gaps.append(f"manifest 無法使用：{man['error']}")
    for n in (man or {}).get("notes", []):
        att.append(n)
    comps = []
    if edk2 is None:
        gaps.append("樹裡找不到 edk2（沒有 MdePkg/，也沒有 edk2/MdePkg/）：edk2 版本與內建加密函式庫都無法判定")
    else:
        comps.append(uefi_component(tree, "edk2", edk2, entries.get(edk2 or "edk2") if edk2 else entries.get("edk2")))
    if nvidia_rel or "edk2-nvidia" in entries:
        comps.append(uefi_component(tree, "edk2-nvidia", nvidia_rel, entries.get("edk2-nvidia")))
        if not nvidia_rel:
            comps[-1]["gaps"].append("manifest 有 edk2-nvidia，但樹裡沒有 edk2-nvidia/ 資料夾")
    w = walk(tree, budget)
    if w["incomplete"]:
        gaps.append(f"{w['incomplete']}：其他位置的加密函式庫可能漏掉")
    submods = gitmodules_paths(tree, edk2) if edk2 is not None else []
    libs = []
    if edk2 is not None:
        for kind, sub in (("openssl", OPENSSL_SUB), ("mbedtls", MBEDTLS_SUB)):
            # .gitmodules 有宣告，或 submodule 的上一層（CryptoPkg/Library/OpensslLib/、MbedTlsLib/）存在 → 應該要有，沒有就是 missing
            parent = sub.rsplit("/", 1)[0]
            declared = sub in submods or os.path.lexists(os.path.join(tree.root, join(edk2, parent)))
            c = lib_component(tree, kind, join(edk2, sub), "edk2-submodule", declared)
            if c:
                libs.append(c)
    known = {c["path"] for c in libs}
    gen_root = join(edk2, OPENSSL_GEN) if edk2 is not None else None
    for kind in ("openssl", "mbedtls"):
        for rel in sorted(w[f"{kind}_roots"]):
            if rel in known or rel == gen_root:
                continue
            c = lib_component(tree, kind, rel, "other-copy", False)
            if c:
                c["notes"].append("不是 edk2 的 CryptoPkg submodule：有沒有編進韌體不判斷")
                libs.append(c)
    # OpensslGen（edk2 產生的標頭）只拿來核對
    gen = None
    if gen_root is not None:
        r = read_openssl(tree, gen_root)
        if r["version"]:
            gen = r["version"]
            sub = next((c for c in libs if c["role"] == "edk2-submodule" and c["kind"] == "openssl"), None)
            if sub and sub["version"] and sub["version"] != gen:
                sub["attention"].append(f"edk2 的 OpensslGen 標頭是 {gen}，submodule 是 {sub['version']}（OpensslGen 過期，或 submodule 不是 edk2 預期的 commit）")
            elif sub and not sub["version"]:
                sub["notes"].append(f"edk2 的 OpensslGen 標頭寫 {gen}；這是 edk2 產生的檔案，不代表 submodule 的內容，沒有拿來當版本")
    banal, built = built_in_analysis(tree, list(platform_dsc), dict(platform_define or {}))
    for n in (banal or {}).get("notes", []):
        att.append(n)
    for c in libs:
        b = built.get(c["kind"]) if c["role"] == "edk2-submodule" else None
        if b:
            c["built_in"], c["built_in_evidence"], c["built_in_reasons"] = b["state"], b["evidence"], b["reasons"]
            if b["state"] == "unknown":
                c["attention"].append(f"{c['label']}：有沒有編進韌體判定不了（built-in: unknown）：{'；'.join(b['reasons']) or '見證據'}；弱點照常列出")
    comps += libs
    strings, refs, dsc_skipped = dsc_info(tree, w["dsc"])
    buildids = []
    for f in w["buildid"]:
        txt, _ = tree.text(f, MAX_SMALL)
        if txt:
            buildids.append({"file": clean(f, 300), "value": clean(txt.strip().splitlines()[0] if txt.strip() else "", 200)})
    nv = next((c for c in comps if c["kind"] == "edk2-nvidia"), None)
    if nv:
        for b in buildids:
            nv["evidence"].append({"source": "build-id", "kind": "images/buildid (FIRMWARE_VERSION_BASE can override; reference only)",
                                   "value": b["value"]})
            base = b["value"].split("-", 1)[0]
            if nv["version"] and JETSON_TAG.match(nv["version"]) and base and base != nv["version"]:
                nv["attention"].append(f"建置產物 {b['file']} 的版本 {b['value']} 與 {nv['version']} 不同（建置後換過版本？）")
    edk2c = next((c for c in comps if c["kind"] == "edk2"), None)
    if edk2c and nv and nv["version"] and edk2c["version"] and JETSON_TAG.match(edk2c["version"]) and edk2c["version"] != nv["version"]:
        att.append(f"edk2（{edk2c['version']}）與 edk2-nvidia（{nv['version']}）的 tag 不同")
    bul = bulletin_check(nv, mirror, table or DEFAULT_TABLE)
    if bul["status"] == "GAP":
        gaps.append(f"NVIDIA 公告：{bul['detail']}")
    elif bul["status"] == "ATTENTION":
        att.append(f"NVIDIA 公告：{bul['detail']}")
    for c in comps:
        gaps += [f"{c['label']}：{x}" if not x.startswith(c["label"]) else x for x in c["gaps"]]
        att += c["attention"]
    if tree.refused_count:
        att.append(f"{tree.refused_count} 個要讀的檔案是指到樹外的符號連結或不是一般檔案，拒讀")
    if tree.too_large_count:
        att.append(f"{tree.too_large_count} 個檔案超過大小上限，沒有讀")
    if dsc_skipped:
        att.append(f"{dsc_skipped} 個 DSC 沒有讀（上限或讀不到）")
    comps.sort(key=lambda c: ({"edk2": 0, "edk2-nvidia": 1, "openssl": 2, "mbedtls": 3}[c["kind"]], c["role"] != "edk2-submodule", c["path"] or ""))
    rep = {"schema": SCHEMA, "stage": STAGE, "status": None, "detail": None,
           "tree": {"path": label(tree_path), "layout": layout, "edk2": edk2, "vendor": nvidia_rel},
           "manifest": man, "components": comps, "edk2_generated_openssl_header": gen, "source_strings": strings,
           "build_ids": buildids, "dsc_references": refs, "build_analysis": banal, "edk2_submodules": submods,
           "other_submodules_not_covered": [s for s in submods if s not in (OPENSSL_SUB, MBEDTLS_SUB)],
           "bulletins": bul,
           "walk": {"entries": w["entries"], "incomplete": w["incomplete"], "symlinks_not_followed": w["symlinks_not_followed"],
                    "symlinks_outside_tree": w["symlinks_outside_tree"],
                    "symlinks_outside_tree_examples": sorted(w["symlinks_outside_tree_examples"]),
                    "unreadable_dirs": w["unreadable_dirs"], "unreadable_dir_examples": w["unreadable_dir_examples"],
                    "too_deep_dirs": w["too_deep"],
                    "refused": tree.refused, "refused_count": tree.refused_count, "too_large": tree.too_large,
                    "too_large_count": tree.too_large_count, "dsc_files": len(w["dsc"])},
           "limits": {"max_entries": MAX_ENTRIES, "max_depth": MAX_DEPTH, "max_header_bytes": MAX_HEADER,
                      "max_manifest_bytes": MAX_MANIFEST, "max_packed_refs_bytes": MAX_PACKED_REFS, "time_limit_s": budget.time_limit},
           "not_covered": NOT_COVERED, "gaps": gaps, "attention": att}
    rep = scrub(rep)          # 不是 UTF-8 的檔名 → \xff 形式，輸出一定寫得出來
    rep["status"], rep["detail"] = status_of(rep)
    return rep


def summary(c):
    v = c["version"] or "版本不明"
    return f"{c['label']} {v}" + ("（CPE）" if c["cpe"] else "（無 CPE）")


def status_of(rep):
    gaps, att = rep["gaps"], rep["attention"]
    main = [c for c in rep["components"] if c["role"] != "other-copy"]
    others = [c for c in rep["components"] if c["role"] == "other-copy"]
    parts = [summary(c) for c in main]
    if others:
        parts.append(f"其他位置的加密函式庫 {len(others)} 份")
    if rep["bulletins"]["status"] != "NOT_RUN":
        parts.append(f"公告 {rep['bulletins']['status']}")
    head = "；".join(parts) or "沒有元件"
    if gaps:
        return "GAP", f"{head}。GAP：{'；'.join(gaps)}" + (f"。另有 {len(att)} 項待確認" if att else "")
    if att:
        return "ATTENTION", f"{head}。待確認：{'；'.join(att)}"
    return "OK", f"{head}。只涵蓋 UEFI 版本與內建加密函式庫（其他 submodule 見報告）；OK 不代表沒有漏洞"


# ---------- 輸出 ----------

def prop(k, v):
    return {"name": k, "value": str(v)}


def bom(rep):
    comps, deps = [], {}
    refs = {}
    for c in rep["components"]:
        ref = REF + (c["kind"] if c["role"] == "uefi" else f"{c['kind']}:{c['path']}")
        refs[c["id"]] = ref
        x = {"type": "firmware" if c["role"] == "uefi" else "library", "bom-ref": ref, "name": c["name"], "purl": c["purl"]}
        if c["version"]:
            x["version"] = c["version"]
        if c["cpe"]:
            x["cpe"] = c["cpe"]
        if c.get("vcs"):
            x["externalReferences"] = [{"type": "vcs", "url": c["vcs"]}]
        ps = [prop("sca-center:uefi:role", c["role"])]
        if c["path"] is not None:
            ps.append(prop("sca-center:uefi:path", c["path"] or "."))
        if c["version_basis"]:
            ps.append(prop("sca-center:version-basis", c["version_basis"]))
        if c["commit"]:
            ps.append(prop("sca-center:uefi:git-commit", c["commit"]))
        if c.get("upstream_base"):
            ps.append(prop("sca-center:uefi:upstream-base", c["upstream_base"]))
        if c["cpe_note"]:
            ps.append(prop("sca-center:cpe-note", c["cpe_note"]))
        if c.get("built_in"):
            ps.append(prop("sca-center:built-in", c["built_in"]))
            ps += [prop("sca-center:built-in-evidence", e) for e in c["built_in_evidence"][:8]]
            ps += [prop("sca-center:built-in-reason", e) for e in c["built_in_reasons"][:3]]
        ps += [prop("sca-center:gap", g) for g in c["gaps"]]
        ps += [prop("sca-center:note", n) for n in c["attention"] + c["notes"]]
        x["properties"] = ps
        comps.append(x)
    ed = next((c for c in rep["components"] if c["kind"] == "edk2"), None)
    nv = next((c for c in rep["components"] if c["kind"] == "edk2-nvidia"), None)
    if ed:
        deps[refs[ed["id"]]] = [refs[c["id"]] for c in rep["components"] if c["role"] == "edk2-submodule"]
    if nv and ed:
        deps[refs[nv["id"]]] = [refs[ed["id"]]]
    allrefs = [x["bom-ref"] for x in comps]
    if len(set(allrefs)) != len(allrefs):
        raise Fail("內部錯誤：bom-ref 重複")
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": "sca-center uefi_source.py"}]},
                         "properties": [prop("sca-center:uefi:status", rep["status"])]},
            "components": comps,
            "dependencies": [{"ref": x["bom-ref"], "dependsOn": deps.get(x["bom-ref"], [])} for x in comps]}


def markdown(rep):
    L = ["# UEFI source versions", "", f"Status: **{rep['status']}**", "", md(rep["detail"], 4000), "",
         f"Tree: `{md(rep['tree']['path'])}` (layout {rep['tree']['layout']})", ""]
    if rep["manifest"]:
        m = rep["manifest"]
        L += [f"Manifest: `{md(m['path'])}` format {md(m['format'])}, combination {md(m['combination'])} ({md(m['combination_basis'])})"
              + (f" — **error**: {md(m['error'])}" if m["error"] else ""), ""]
    L += ["## Components", "", "| Component | Path | Version | Basis | CPE | purl | Gaps / notes |", "|---|---|---|---|---|---|---|"]
    for c in rep["components"]:
        notes = c["gaps"] + c["attention"] + c["notes"] + ([c["cpe_note"]] if c["cpe_note"] else [])
        L.append(f"| {md(c['label'])} ({md(c['role'])}) | {md(c['path'] if c['path'] is not None else '(manifest only)')} | "
                 f"{md(c['version'] or 'UNKNOWN')} | {md(c['version_basis'] or '-')} | {md(c['cpe'] or '-')} | {md(c['purl'])} | "
                 f"{'<br>'.join(md(n) for n in notes) or '-'} |")
    ba = rep.get("build_analysis")
    if ba:
        L += ["", "## Built into the firmware? (platform DSC, best effort)", ""]
        L += [f"- DSC `{md(r['dsc'])}` ({md(r['source'])}): {r['files_read']} file(s) read, {r['components']} components, "
              f"{r['inf_reachable']} INF(s) reachable, {r['problems_count']} unresolved" for r in ba["runs"]]
        L += [f"- {md(n)}" for n in ba["notes"]]
        for c in rep["components"]:
            if c.get("built_in"):
                L += [f"- **{md(c['label'])}: built-in {c['built_in']}**"] + [f"  - {md(e, 400)}" for e in c["built_in_evidence"]] + \
                     [f"  - reason: {md(e, 500)}" for e in c["built_in_reasons"]]
    L += ["", "### Evidence", ""]
    for c in rep["components"]:
        if c["evidence"]:
            L.append(f"- {md(c['label'])} `{md(c['path'])}`: " + "; ".join(f"{md(e['source'])} {md(e['kind'])} = {md(e['value'])}"
                                                                           for e in c["evidence"]))
    b = rep["bulletins"]
    L += ["", "## NVIDIA bulletins (UEFI)", "", f"Status: **{b['status']}** — {md(b['detail'], 2000)}", ""]
    for k, title in (("hits", "In affected range (reviewed rows)"), ("unreviewed_would_match", "Unreviewed rows that would match (not findings)"),
                     ("undetermined", "Cannot be determined"), ("fixed_unreviewed", "At or above the fixed version per UNREVIEWED rows (not confirmed)"),
                     ("fixed_per_table", "At or above the fixed version (reviewed rows)"),
                     ("other_components_unreviewed", "Unreviewed rows guessed to be rootfs packages (not treated as UEFI)")):
        if b[k]:
            L += [f"### {title}", "", "| Bulletin | CVE | Line | Affected | Fixed | Reason |", "|---|---|---|---|---|---|"]
            L += [f"| {md(x['bulletin'])} | {md(x['cve'])} | {md(x['line'] or '-')} | {md(x['affected_text'])} | {md(x['fixed_text'])} | "
                  f"{md(x.get('reason') or '-')} |" for x in b[k]]
            L.append("")
    if b["pending_bulletins"]:
        L += ["### Bulletins in the mirror not yet in the table", ""]
        L += [f"- {md(p['id'])} {md(p['title'])} ({', '.join(p['reasons'])}; mentions UEFI: {p['mentions_uefi']})" for p in b["pending_bulletins"]]
        L.append("")
    if rep["source_strings"]:
        L += ["## Version strings in DSC files (reference only)", ""]
        L += [f"- `{md(s['file'])}` {md(s['pcd'])} = `{md(s['value'])}` ({s['kind']})" for s in rep["source_strings"][:50]]
        L.append("")
    if rep["build_ids"]:
        L += ["## Build IDs (reference only)", ""] + [f"- `{md(x['file'])}`: `{md(x['value'])}`" for x in rep["build_ids"]] + [""]
    wk = rep["walk"]
    L += ["## Walk", "", f"- entries: {wk['entries']}; symlinks not followed: {wk['symlinks_not_followed']}; incomplete: {md(wk['incomplete'] or 'no')}"]
    L += [f"- symlinks pointing outside the tree (not followed): {wk['symlinks_outside_tree']}"]
    L += [f"- unreadable folders: {wk['unreadable_dirs']}; folders deeper than the limit: {wk['too_deep_dirs']}"]
    L += [f"  - `{md(x)}`" for x in wk["unreadable_dir_examples"][:20]]
    L += [f"  - `{md(x)}`" for x in wk["symlinks_outside_tree_examples"][:20]]
    L += [f"- refused: `{md(x['path'])}` ({md(x['reason'])})" for x in wk["refused"]]
    L += [f"- too large: `{md(x['path'])}` ({md(x['reason'])})" for x in wk["too_large"]]
    if rep["other_submodules_not_covered"]:
        L += ["", "## Other edk2 submodules (no components)", ""] + [f"- `{md(s)}`" for s in rep["other_submodules_not_covered"]]
    L += ["", "## Not covered", ""] + [f"- {md(x, 1000)}" for x in rep["not_covered"]] + [""]
    return "\n".join(L)


def clear(out):
    """刪掉上一次的輸出與寫到一半的 .tmp。"""
    if not out:
        return
    for n in OUTPUTS:
        for f in (n, f".{n}.tmp"):
            try:
                os.unlink(os.path.join(out, f))
            except OSError:
                pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgError(message)


def out_arg(argv):
    argv = list(sys.argv[1:] if argv is None else argv)
    for i, x in enumerate(argv):
        if x == "--out" and i + 1 < len(argv):
            return argv[i + 1]
        if x.startswith("--out="):
            return x[len("--out="):]
    return None


def seconds(v):
    try:
        x = float(v)
    except ValueError:
        raise argparse.ArgumentTypeError(f"要是秒數（{v}）")
    if not (math.isfinite(x) and x > 0):
        raise argparse.ArgumentTypeError(f"要是大於 0 的有限秒數（{v}）")
    return x


def line(st, detail):
    detail = unsurrogate(detail)
    b = detail.replace("\t", " ").replace("\n", " ").encode("utf-8")
    d = detail if len(b) <= 470 else b[:470].decode("utf-8", "ignore") + "…"
    print(f"{STAGE}\t{st}\t{d}")


def main(argv=None):
    ap = Parser(description=__doc__.splitlines()[0], allow_abbrev=False)
    ap.add_argument("--tree", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--manifest")
    ap.add_argument("--combination")
    ap.add_argument("--bulletin-mirror")
    ap.add_argument("--bulletin-table")
    ap.add_argument("--platform-dsc", action="append", default=[])
    ap.add_argument("--platform-define", action="append", default=[], metavar="NAME=VALUE")
    ap.add_argument("--time-limit", type=seconds, default=TIME_LIMIT)
    try:
        a = ap.parse_args(argv)
    except ArgError as e:
        clear(out_arg(argv))
        line("FAIL", f"參數錯誤：{e}")
        return 64
    try:
        defs = {}
        for x in a.platform_define:
            k, eq, v = x.partition("=")
            if not eq or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                raise ArgError(f"--platform-define 要是 NAME=VALUE（{clean(x, 80)}）")
            defs[k] = v
        rep = analyse(a.tree, a.manifest, a.combination, a.bulletin_mirror, a.bulletin_table, Budget(a.time_limit), a.platform_dsc, defs)
        docs = {"uefi-source.cdx.json": json.dumps(bom(rep), ensure_ascii=False, indent=1) + "\n",
                "uefi-source.json": json.dumps(rep, ensure_ascii=False, indent=1) + "\n",
                "uefi-source.md": markdown(rep)}
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        for n in OUTPUTS:
            tmp = out / f".{n}.tmp"
            tmp.write_text(docs[n], encoding="utf-8")
            os.replace(tmp, out / n)
    except Fail as e:
        clear(a.out)
        line("FAIL", str(e))
        return 1
    except OSError as e:
        clear(a.out)
        line("FAIL", f"寫不進 {label(a.out)}（{type(e).__name__}）")
        return 1
    except Exception as e:      # 結構意外：記 FAIL，不印 traceback
        clear(a.out)
        line("FAIL", f"uefi_source.py 無法判定（{type(e).__name__}）")
        return 1
    line(rep["status"], rep["detail"])
    return 0 if rep["status"] == "OK" else 2


if __name__ == "__main__":
    sys.exit(main())
