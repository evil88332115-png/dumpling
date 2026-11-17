#!/usr/bin/env python3
"""board_import.py：把板子安全檢查的結果（tools/demo/board-on-device.sh、board-from-network.sh 的 .tar.gz）匯入
scan-flash-package 的結果資料夾，寫出 CRA 文件用的 board-test.json（Annex I Part II (3)、Annex VII 6）。

用法：
  python3 -I board_import.py --result <結果資料夾>/<rootfs> [--replace] <board-test-*.tar.gz | board-net-*.tar.gz> …
  python3 -I board_import.py --result <結果資料夾>/<rootfs>        （不給壓縮檔：只依已匯入的結果重寫 board-test.json）

每個壓縮檔解到 <rootfs>/board-test/<壓縮檔名稱去掉 .tar.gz>/，再讀 board-test/ 底下全部已匯入的結果寫 board-test/board-test.json：
  每個結果（板子上、網路）的檢查狀態、工具版本、檔案 sha256，以及待檢視項目 findings（和 image_check.py 的 findings 同樣的欄位：
  id、severity、annex、evidence、text、confirm，另加 source：board｜network）。同一種檢查、同一個對象（主機名稱或 IP）只用最新的一次
  （名稱裡的 UTC 時間），舊的保留但標 superseded、不產生 findings。印一行 D-board-test<TAB>狀態<TAB>說明
  （有 high／medium 或有讀不懂、失敗的檢查 → ATTENTION；沒有任何結果 → NOT_RUN；有壓縮檔被拒絕 → ATTENTION；參數或寫入錯誤 → FAIL）。

核心模組清單（證據規則 K2 的輸入，tools/cra/kernel_modules.py；要 Python 3.12 以上）：
  python3 -I board_import.py --result <結果資料夾>/<rootfs> [壓縮檔…] --kernel-modules-from <rootfs 資料夾｜rootfs tar｜刷機包 tbz2>
      [--kernel-modules-prefix <rootfs 在刷機包裡的路徑>] [--kernel-version <版本>] [--image-sha256 sha256:<hex>] [--lsmod <檔案>]
      --owner <負責人> [--captured YYYY-MM-DD] [--accept-unread-initramfs] [--replace]
  寫 <rootfs>/cra-project/CRA/Config/kernel-modules.json 與旁邊的 kernel-modules.sources.json（每行 modprobe 設定的來源檔等），
  另印一行 D-kernel-modules<TAB>狀態<TAB>說明（GAP＝輸入不足，沒有寫檔）。映像雜湊取自 <rootfs>/scan/meta.json（cra_report 比對 K2
  用的值）；loaded 取自 --lsmod，沒給時取自已匯入、最新的板子結果的 lsmod.txt（核心版本要相同；os.txt 的 uname），
  modules_disabled 取自它們的 sysctl.txt。已有內容不同的 kernel-modules.json 時要加 --replace 才取代。

壓縮檔是不可信資料（從板子或別台電腦帶回來）：
  - 串流讀（tarfile r|），不呼叫 extractall；壓縮檔、解壓後總量、單檔、成員數都有上限。
  - 只收一般檔案，而且名稱是 <最上層資料夾>/<檔名>，最上層資料夾要和壓縮檔名稱相同，檔名要在兩支腳本會寫的清單裡（ALLOWED）；
    符號連結、硬連結、裝置檔、絕對路徑、..、其他名稱、有 NUL 位元組的內容 → 不收，記在 notes。
  - 寫入只用 O_CREAT|O_EXCL|O_NOFOLLOW，先寫到 board-test/ 底下的暫存資料夾再改名；board-test/ 是符號連結時拒絕。
解析只取固定欄位（帳號只取 passwd -S 的狀態代號；不認得的值只計數、不照抄）：報告裡不會出現檔案的原文、密碼雜湊、金鑰。
"""
import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path

SCHEMA = "sca-center-board-test/1"
TOOL_VERSION = "2026-11-13.2"
LIMITS = {"archive": 64 << 20, "file": 16 << 20, "total": 128 << 20, "members": 400, "list": 200, "lines": 200_000}
RESERVED = {"board-test.json", "import.json"}      # board-test/ 底下保留的名稱：不能當結果資料夾的名稱
STEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,150}$")
TIME_RE = re.compile(r"-(\d{8}T\d{6}Z)$")
BOARD_FILES = {"summary.txt", "os.txt", "listening.txt", "services-enabled.txt", "services-running.txt", "sshd-effective.txt",
               "accounts.txt", "sysctl.txt", "firewall.txt", "setuid.txt", "world-writable.txt", "auto-updates.txt",
               "secure-boot.txt", "lynis.txt", "lynis-report.dat", "lynis.log", "lsmod.txt",
               "firmware.txt", "runtime-files.txt", "runtime-modules.txt", "integrity.txt", "update-channel.txt", "logging.txt"}
NET_FILES = {"summary.txt", "open-tcp.txt"} | {f"nmap-{p}.{e}" for p in ("tcp", "udp") for e in ("nmap", "gnmap", "xml")}
NET_RE = re.compile(r"^(?:ssh-audit|testssl)-\d{1,5}\.json$")
ERR_RE = re.compile(r"^(?:[a-z-]+\.txt|nmap-(?:tcp|udp)|ssh-audit-\d{1,5}|testssl-\d{1,5})\.err$")
# 板子上每次都該有的結果檔 → summary.txt 的檢查名稱
EXPECTED_BOARD = {"listening.txt": "listening", "sshd-effective.txt": "sshd-effective", "accounts.txt": "accounts",
                  "sysctl.txt": "sysctl", "firewall.txt": "firewall", "auto-updates.txt": "auto-updates"}
BOARD_MARK = {"os.txt", "listening.txt", "sshd-effective.txt", "accounts.txt", "sysctl.txt"}
NET_MARK = {"nmap-tcp.gnmap", "nmap-tcp.nmap", "open-tcp.txt", "nmap-udp.gnmap"}
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
IMPORT_META = "import.json"       # 匯入時寫的來源紀錄（壓縮檔名稱、sha256、略過的成員）；不在 ALLOWED，壓縮檔裡不會有這個名稱

NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}\$?$")        # 帳號名稱
PROC_RE = re.compile(r"^[A-Za-z0-9_.@:+-]{1,64}$")                    # 程式名稱、unit 名稱
PATH_RE = re.compile(r"^/[\x21-\x7e ]{0,300}$")                       # 路徑（可見的 ASCII 與空白）
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.+:-]{1,64}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
LYNIS_ID = re.compile(r"^[A-Z]{2,8}-\d{4}$")
ALGO_RE = re.compile(r"^[A-Za-z0-9@._+-]{1,100}$")
VERSION_RE = re.compile(r"[^A-Za-z0-9 ._:;()+~,/-]")

# 監聽或對外開著的服務：明文或舊的遠端登入 → high；測試、除錯工具（不該在出貨的產品裡）→ medium；其他 → low（要有理由）
CLEAR_PROCS = re.compile(r"^(?:in\.)?(?:telnetd?|ftpd|vsftpd|proftpd|pure-ftpd|tftpd|in\.tftpd|rshd|rlogind|rexecd|x11vnc|vncserver|Xvnc)$")
CLEAR_SVCS = {"telnet", "ftp", "tftp", "shell", "login", "exec", "rsh", "rlogin", "vnc"}
CLEAR_PORTS = {21, 23, 69, 512, 513, 514}
TEST_PROCS = re.compile(r"^(?:iperf3?|gdbserver|nc|nc\.openbsd|nc\.traditional|ncat|netcat|socat)$")
TEST_SVCS = re.compile(r"^(?:iperf3?|gdbserver)\??$")
TEST_PORTS = {5201}
SYS_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/lib/", "/lib64/")
CLEAR_UNITS = re.compile(r"^(?:telnet|inetutils-telnetd|tftpd-hpa|tftp|vsftpd|proftpd|rsh|rlogin|xrdp|x11vnc|vncserver)[@.]")
TEST_UNITS = re.compile(r"^(?:iperf3?|gdbserver)[@.]")
# kernel／網路 sysctl：（不好的值的判斷、嚴重度、Annex I、說明）
SYSCTL = {
    "kernel.randomize_va_space": (lambda v: v != "2", "medium", ("I-2k",), "ASLR is not fully enabled (expected 2)"),
    "fs.protected_symlinks": (lambda v: v == "0", "medium", ("I-2k",), "symlink protection is off (expected 1)"),
    "fs.protected_hardlinks": (lambda v: v == "0", "medium", ("I-2k",), "hardlink protection is off (expected 1)"),
    "kernel.kptr_restrict": (lambda v: v == "0", "low", ("I-2k",), "kernel pointers are visible to users (expected 1 or 2)"),
    "kernel.dmesg_restrict": (lambda v: v == "0", "low", ("I-2k",), "kernel log readable by unprivileged users (expected 1)"),
    "kernel.unprivileged_bpf_disabled": (lambda v: v == "0", "low", ("I-2k",), "unprivileged BPF is allowed (expected 1 or 2)"),
    "kernel.yama.ptrace_scope": (lambda v: v == "0", "low", ("I-2k",), "any process can ptrace other processes of the same user (expected 1 or more)"),
    "fs.suid_dumpable": (lambda v: v not in ("0",), "low", ("I-2k",), "setuid programs can dump core (expected 0)"),
    "fs.protected_fifos": (lambda v: v == "0", "low", ("I-2k",), "FIFO protection in sticky directories is off (expected 1 or 2)"),
    "fs.protected_regular": (lambda v: v == "0", "low", ("I-2k",), "regular-file protection in sticky directories is off (expected 1 or 2)"),
    "net.ipv4.conf.all.accept_redirects": (lambda v: v != "0", "low", ("I-2b", "I-2h"), "ICMP redirects are accepted (expected 0)"),
    "net.ipv6.conf.all.accept_redirects": (lambda v: v != "0", "low", ("I-2b", "I-2h"), "IPv6 ICMP redirects are accepted (expected 0)"),
    "net.ipv4.conf.all.send_redirects": (lambda v: v != "0", "low", ("I-2i",), "the device sends ICMP redirects (expected 0 unless it is a router)"),
    "net.ipv4.ip_forward": (lambda v: v != "0", "low", ("I-2i",), "IP forwarding is on (expected 0 unless the product routes traffic)"),
    "net.ipv4.tcp_syncookies": (lambda v: v == "0", "low", ("I-2h",), "TCP SYN cookies are off (expected 1)"),
}


class ImportError_(Exception):
    """參數、寫入位置有問題（整次 FAIL，不寫任何東西）。"""


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_version(s, n=80):
    return VERSION_RE.sub("", s or "").strip()[:n]


def allowed(name):
    return name in BOARD_FILES or name in NET_FILES or bool(NET_RE.match(name)) or bool(ERR_RE.match(name))


def stem_of(archive):
    n = Path(archive).name
    for ext in (".tar.gz", ".tgz"):
        if n.endswith(ext):
            return n[:-len(ext)]
    return None


# ---------- 讀壓縮檔 ----------

class Limited(io.RawIOBase):
    """解壓後的位元組數超過上限就停（避免壓縮炸彈：跳過大成員也要解壓）。"""

    def __init__(self, f, limit):
        self.f, self.left = f, limit

    def readable(self):
        return True

    def readinto(self, b):
        if self.left <= 0:
            raise ValueError("解壓後超過總量上限")
        n = self.f.readinto(memoryview(b)[:min(len(b), self.left)]) if hasattr(self.f, "readinto") else 0
        self.left -= n
        return n


def read_archive(path, stem, limits=LIMITS):
    """回傳 ({檔名: 內容}, notes, 壓縮檔資訊)。整個壓縮檔不能用時 files 是空的、notes 寫原因。"""
    notes, files = [], {}
    st = os.stat(path)
    info = {"name": Path(path).name, "size": st.st_size, "sha256": None}
    if not stat.S_ISREG(st.st_mode):
        return files, ["不是一般檔案"], info
    if st.st_size > limits["archive"]:
        return files, [f"壓縮檔超過 {limits['archive']} bytes"], info
    raw = Path(path).read_bytes()
    info["sha256"] = hashlib.sha256(raw).hexdigest()
    seen = 0
    try:
        gz = gzip.GzipFile(fileobj=io.BytesIO(raw))
        with tarfile.open(fileobj=io.BufferedReader(Limited(gz, limits["total"])), mode="r|") as tf:
            for m in tf:
                seen += 1
                if seen > limits["members"]:
                    notes.append(f"成員超過 {limits['members']} 個，其餘不讀")
                    break
                name = m.name
                shown_ = shown(name)
                parts = name.split("/")
                if name.startswith("/") or ".." in parts or "\\" in name:
                    notes.append(f"{shown_}：絕對路徑或 ..，不收")
                    continue
                parts = [p for p in parts if p not in ("", ".")]
                if m.isdir():
                    if parts != [stem]:
                        notes.append(f"{shown_}：資料夾不在預期的位置，不收")
                    continue
                if not m.isreg():
                    notes.append(f"{shown_}：不是一般檔案（連結、裝置等），不收")
                    continue
                if len(parts) != 2 or parts[0] != stem:
                    notes.append(f"{shown_}：要在 {stem}/ 底下第一層，不收")
                    continue
                fn = parts[1]
                if not allowed(fn):
                    notes.append(f"{shown_}：不是板子檢查腳本會寫的檔名，不收")
                    continue
                if fn in files:
                    notes.append(f"{shown_}：重複的成員，只收第一個")
                    continue
                if m.size > limits["file"]:
                    notes.append(f"{shown_}：超過單檔上限 {limits['file']} bytes，不收")
                    continue
                data = tf.extractfile(m).read(limits["file"] + 1)
                if len(data) > limits["file"]:
                    notes.append(f"{shown_}：超過單檔上限，不收")
                    continue
                if b"\0" in data:
                    notes.append(f"{shown_}：內容不是文字（有 NUL），不收")
                    continue
                files[fn] = data
    except (tarfile.TarError, OSError, EOFError, ValueError, gzip.BadGzipFile, zlib.error) as e:
        return {}, notes + [f"壓縮檔讀不了（{type(e).__name__}：{str(e)[:120]}），整個不收"], info
    if not files:
        notes.append("沒有任何可用的檔案，整個不收")
    return files, notes, info


def kind_of(stem, names):
    """內容優先（板子上的檔案或 nmap 的檔案）；都沒有時（例如 nmap 失敗、只有 summary.txt）看名稱的開頭。"""
    b, n = bool(BOARD_MARK & set(names)), bool(NET_MARK & set(names))
    if b and not n:
        return "board"
    if n and not b:
        return "network"
    if not b and not n and "summary.txt" in names:
        return "board" if stem.startswith("board-test-") else "network" if stem.startswith("board-net-") else None
    return None


def shown(name, n=120):
    """不可信的名稱只留可見的 ASCII（寫進 notes 用）。"""
    return re.sub(r"[^\x21-\x7e]", "?", name)[:n]


def open_dir_nofollow(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    return fd


def board_dir(result, create):
    result = Path(result)
    try:
        rst = os.lstat(result)
    except FileNotFoundError:
        raise ImportError_(f"結果資料夾不存在：{result}")
    if not stat.S_ISDIR(rst.st_mode):
        raise ImportError_(f"--result 要是資料夾（不能是符號連結）：{result}")
    bd = result / "board-test"
    try:
        st = os.lstat(bd)
        if not stat.S_ISDIR(st.st_mode):
            raise ImportError_(f"{bd} 不是資料夾（可能是符號連結），拒絕寫入")
    except FileNotFoundError:
        if not create:
            return bd
        os.mkdir(bd, 0o700)
    return bd


def write_run(bd, stem, files, meta, replace):
    """寫到 board-test/.<stem>.XXXX/ 再改名成 board-test/<stem>/。回傳說明。"""
    dest = bd / stem
    if os.path.lexists(dest):
        if not replace:
            old = read_meta(dest)
            same = old and old.get("archive", {}).get("sha256") == meta["archive"]["sha256"]
            return ("skip", "已經匯入過同一個壓縮檔（內容相同，沒有變更）") if same else \
                ("conflict", "沒有匯入：已經有同名、內容不同的結果（要取代加 --replace）")
        st = os.lstat(dest)
        if not stat.S_ISDIR(st.st_mode):
            raise ImportError_(f"{dest} 不是資料夾，拒絕取代")
    tmp = tempfile.mkdtemp(prefix=f".{stem}.", dir=bd)
    try:
        dfd = open_dir_nofollow(tmp)
        try:
            for fn, data in sorted(files.items()) + [(IMPORT_META, (json.dumps(meta, ensure_ascii=False, indent=1) + "\n").encode())]:
                fd = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
        finally:
            os.close(dfd)
        if os.path.lexists(dest):
            shutil.rmtree(dest)
        os.rename(tmp, dest)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return "ok", ("取代" if replace else "匯入")


def read_meta(d):
    try:
        fd = os.open(Path(d) / IMPORT_META, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            m = json.loads(f.read(1 << 20).decode("utf-8"))
        return m if isinstance(m, dict) else None
    except (OSError, ValueError):
        return None


def read_run_files(d, limits=LIMITS):
    """已匯入的結果：只讀允許的檔名、一般檔案、不跟隨連結。"""
    files, notes = {}, []
    dfd = open_dir_nofollow(d)
    try:
        for fn in sorted(os.listdir(dfd)):
            if fn == IMPORT_META:
                continue
            if not allowed(fn):
                notes.append(f"{shown(fn, 80)}：不認得的檔名，不讀")
                continue
            try:
                fd = os.open(fn, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
            except OSError:
                notes.append(f"{fn}：打不開（可能是符號連結），不讀")
                continue
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    notes.append(f"{fn}：不是一般檔案，不讀")
                    continue
                data = f.read(limits["file"] + 1)
            if len(data) > limits["file"]:
                notes.append(f"{fn}：超過單檔上限，不讀")
                continue
            files[fn] = data
    finally:
        os.close(dfd)
    return files, notes


# ---------- 解析（只取固定欄位） ----------

def text_of(data, limit=None):
    """解碼成文字，最多 LIMITS["lines"] 行（超過的不解析；呼叫端用 too_long 記 note）。所有解析都逐行做，不在整份文字上跑
    會回溯的正規表示式（不可信的檔案可能是 16 MB 的空白或換行）。"""
    if data is None:
        return None
    limit = limit or LIMITS["lines"]
    t = data.decode("utf-8", "replace")
    if t.count("\n") > limit:
        t = "\n".join(t.split("\n", limit)[:limit])
    return t


def too_long(data, limit=None):
    return data is not None and data.count(b"\n") > (limit or LIMITS["lines"])


def finding(fid, source, check, sev, title, text, annex, evidence, confirm, action=""):
    ev = list(evidence)
    return {"id": fid, "source": source, "check": check, "severity": sev, "title": title, "text": text, "annex": list(annex),
            "evidence": ev[:LIMITS["list"]], "evidence_total": len(ev), "confirm": confirm, "action": action}


def addr_scope(addr):
    a = addr.strip("[]").split("%", 1)[0]
    if a in ("0.0.0.0", "*", "::", ""):
        return "all"
    if a.startswith("127.") or a == "::1":
        return "loopback"
    return "address"


def listen_severity(proc, port, svc=""):
    if (proc and CLEAR_PROCS.match(proc)) or port in CLEAR_PORTS or svc in CLEAR_SVCS:
        return "high", "a cleartext or legacy remote-access service"
    if (proc and TEST_PROCS.match(proc)) or port in TEST_PORTS or (svc and TEST_SVCS.match(svc)):
        return "medium", "a test or debugging tool that should not run in the shipped product"
    return "low", None


def parse_listening(t, stem, notes):
    """ss -H -tulpn：每個（協定、埠）一個 finding；只看不是 loopback 的位址。"""
    socks, bad = {}, 0
    for line in t.splitlines():
        f = line.split()
        if not f:
            continue
        if len(f) < 5 or f[0] not in ("tcp", "udp") or f[1] not in ("LISTEN", "UNCONN"):
            bad += 1
            continue
        addr, _, port = f[4].rpartition(":")
        if not port.isdigit() or not 0 < int(port) < 65536:
            bad += 1
            continue
        scope = addr_scope(addr)
        if scope == "loopback":
            continue
        m = re.search(r'users:\(\("([^"]{1,64})"', line)
        proc = m.group(1) if m and PROC_RE.match(m.group(1)) else None
        k = (f[0], int(port))
        x = socks.setdefault(k, {"procs": set(), "scopes": set()})
        if proc:
            x["procs"].add(proc)
        x["scopes"].add(scope)
    if bad:
        notes.append(f"{stem}/listening.txt：{bad} 行格式不認得，略過")
    out = []
    for (proto, port), x in sorted(socks.items()):
        procs = sorted(x["procs"])
        sev, why = max((listen_severity(p, port) for p in procs or [None]), key=lambda s: -SEV_ORDER[s[0]])
        where = "all interfaces" if "all" in x["scopes"] else "a non-loopback address"
        who = ", ".join(procs) or "an unknown process"
        out.append(finding(
            f"board:listen-{proto}:{port}", "board", "listening", sev, f"Listening on {proto}/{port} ({who})",
            f"{who} listens on {proto}/{port} on {where}" + (f"; this is {why}." if why else "."),
            ("I-2b", "I-2j"), [f"{stem}/listening.txt: {proto}/{port} {who} ({where})"],
            "Check `ss -tulpn` on a freshly flashed board.",
            "Confirm the product needs this service and record why; otherwise disable or remove it, or bind it to the "
            "interface that needs it."))
    return out


def parse_sshd(t, stem):
    v = {}
    for line in t.splitlines():
        p = line.strip().split(None, 1)
        if len(p) == 2 and re.match(r"^[a-z0-9]{2,40}$", p[0]) and p[0] not in v:
            v[p[0]] = p[1].strip().lower() if TOKEN_RE.match(p[1].strip()) else "?"
    ev = lambda k: [f"{stem}/sshd-effective.txt: {k} {v.get(k)}"]
    out = []
    prl = v.get("permitrootlogin")
    if prl == "yes":
        out.append(finding("board:ssh-permit-root-login", "board", "sshd", "high", "SSH allows root login with a password",
                           "sshd -T reports PermitRootLogin yes: root can log in over the network with a password.",
                           ("I-2b", "I-2d"), ev("permitrootlogin"), "Run `sshd -T | grep -i permitrootlogin` on the board.",
                           "Set PermitRootLogin no (or prohibit-password if root key login is required and documented)."))
    elif prl and prl != "no":
        out.append(finding("board:ssh-permit-root-login", "board", "sshd", "low", "SSH allows root login with a key",
                           f"sshd -T reports PermitRootLogin {prl}: root can log in over the network with a key.",
                           ("I-2d",), ev("permitrootlogin"), "Run `sshd -T | grep -i permitrootlogin` on the board.",
                           "Set PermitRootLogin no unless root key login is required; record the reason."))
    if v.get("passwordauthentication") == "yes":
        out.append(finding("board:ssh-password-auth", "board", "sshd", "medium", "SSH password authentication is enabled",
                           "sshd -T reports PasswordAuthentication yes: password login over the network is exposed to guessing.",
                           ("I-2b", "I-2d"), ev("passwordauthentication"),
                           "Run `sshd -T | grep -i passwordauthentication` on the board.",
                           "Use key-based login, or document why passwords are needed and how they are unique per device."))
    if v.get("permitemptypasswords") == "yes":
        out.append(finding("board:ssh-permit-empty-passwords", "board", "sshd", "high", "SSH permits empty passwords",
                           "sshd -T reports PermitEmptyPasswords yes.", ("I-2b", "I-2d"), ev("permitemptypasswords"),
                           "Run `sshd -T` on the board.", "Set PermitEmptyPasswords no."))
    kbd = v.get("kbdinteractiveauthentication") or v.get("challengeresponseauthentication")
    if kbd == "yes" and v.get("usepam") == "yes" and v.get("passwordauthentication") != "yes":
        out.append(finding("board:ssh-kbd-interactive-pam", "board", "sshd", "medium", "SSH keyboard-interactive (PAM) login is enabled",
                           "sshd -T reports KbdInteractiveAuthentication yes with UsePAM yes: password login through PAM is possible "
                           "even though PasswordAuthentication is no.", ("I-2d",),
                           ev("kbdinteractiveauthentication") + ev("usepam"), "Run `sshd -T` on the board.",
                           "Set KbdInteractiveAuthentication no unless it is needed."))
    if v.get("x11forwarding") == "yes":
        out.append(finding("board:ssh-x11-forwarding", "board", "sshd", "low", "SSH X11 forwarding is enabled",
                           "sshd -T reports X11Forwarding yes.", ("I-2j",), ev("x11forwarding"), "Run `sshd -T` on the board.",
                           "Set X11Forwarding no unless the product needs it."))
    return out, bool(v)


def parse_accounts(t, stem, notes):
    """accounts.txt：第一段「名稱<TAB>uid=N<TAB>shell=…」（有登入 shell 的帳號），第二段「名稱<TAB>狀態」（passwd -S）。只取狀態代號。"""
    login, status, bad, unknown = {}, {}, 0, 0
    for line in t.splitlines():
        if not line.strip():
            continue
        f = line.split("\t")
        if len(f) == 3 and f[1].startswith("uid=") and f[2].startswith("shell="):
            if NAME_RE.match(f[0]) and f[1][4:].isdigit() and PATH_RE.match(f[2][6:]) and len(f[2]) < 120:
                login[f[0]] = (int(f[1][4:]), f[2][6:])
            else:
                bad += 1
        elif len(f) == 2 and NAME_RE.match(f[0]):
            s = f[1].strip()
            if s in ("P", "PS", "L", "LK", "NP"):
                status.setdefault(f[0], s)
            else:
                unknown += 1
        else:
            bad += 1
    if bad:
        notes.append(f"{stem}/accounts.txt：{bad} 行格式不認得，略過")
    if unknown:
        notes.append(f"{stem}/accounts.txt：{unknown} 個不認得的密碼狀態，略過（不照抄內容）")
    out = []
    for name, (uid, shell) in sorted(login.items()):
        st = status.get(name)
        e = [f"{stem}/accounts.txt: {name} (uid {uid}, shell {shell}, password status {st or 'unknown'})"]
        if uid == 0 and name != "root":
            out.append(finding(f"board:account-uid0:{name}", "board", "accounts", "high", f"Account {name} has UID 0",
                               f"{name} is a second superuser account (UID 0).", ("I-2d",), e, "Check /etc/passwd on the board.",
                               "Remove the account or give it a normal UID."))
        if st == "NP":
            out.append(finding(f"board:account-empty-password:{name}", "board", "accounts", "high",
                               f"Login account {name} has no password",
                               f"{name} has a login shell ({shell}) and no password (passwd -S: NP).", ("I-2b", "I-2d"), e,
                               "Run `sudo passwd -S " + name + "` on the board.", "Lock the account or set a unique password per device."))
        elif st in ("P", "PS"):
            out.append(finding(f"board:account-password:{name}", "board", "accounts", "medium",
                               f"Login account {name} has a password",
                               f"{name} has a login shell ({shell}) and a usable password (passwd -S: P). If every device ships with "
                               "the same password, one leaked password opens all devices.", ("I-2b", "I-2d"), e,
                               "Compare with a second board flashed from the same image (the password must not be shared).",
                               "Use a unique password per device or force a change at first use, or lock the account."))
    return out


def parse_sysctl(t, stem):
    out, seen = [], set()
    for line in t.splitlines():
        k, sep, v = line.partition(" = ")
        k, v = k.strip(), v.strip()
        if not sep or k not in SYSCTL or k in seen or not re.match(r"^-?\d{1,6}$", v):
            continue
        seen.add(k)
        bad, sev, annex, what = SYSCTL[k]
        if bad(v):
            out.append(finding(f"board:sysctl:{k}", "board", "sysctl", sev, f"Kernel setting {k} = {v}", f"{k} = {v}: {what}.",
                               annex, [f"{stem}/sysctl.txt: {k} = {v}"], f"Run `sysctl {k}` on the board.",
                               f"Set {k} in /etc/sysctl.d/ or record why the current value is needed."))
    return out


LOOPBACK_ONLY = re.compile(r'(?:^|\s)(?:-i lo\b|iifname "?lo"?(?:\s|$)|iif "?lo"?(?:\s|$))')
VERDICT_BLOCK = re.compile(r"\b(?:drop|reject)\b")


def firewall_state(t):
    """回傳 {"ipv4": filtering|none, "ipv6": filtering|none, "format": ok|unknown}。逐行解析（不可信的檔案不跑會回溯的正規表示式）。
    filtering：INPUT（nft 的 hook input）的 policy 是 drop／reject，或有一條不是只針對 loopback 的 drop／reject 規則。
    只有 accept、jump 的規則（例如 -i lo -j ACCEPT、-j KUBE-FIREWALL）而 policy 是 accept 不算（自訂 chain 不追）。
    iptables-legacy -S 只有 IPv4（board-on-device.sh 沒有收 ip6tables）；nft 的 inet 兩個都算，ip 是 IPv4，ip6 是 IPv6。"""
    st = {"ipv4": "none", "ipv6": "none", "format": "ok"}
    if "沒有載入" in t or "not loaded" in t:
        return st
    fams = {"ip": ("ipv4",), "ip6": ("ipv6",), "inet": ("ipv4", "ipv6")}
    seen, fam, in_chain, hook_input = False, None, False, False
    for raw in t.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("-P "):
            seen = True
            f = line.split()
            if len(f) >= 3 and f[1] == "INPUT" and f[2] in ("DROP", "REJECT"):
                st["ipv4"] = "filtering"
            continue
        if line.startswith("-A ") or line.startswith("-N "):
            seen = True
            f = line.split()
            if len(f) >= 2 and f[0] == "-A" and f[1] == "INPUT" and not LOOPBACK_ONLY.search(line):
                m = re.search(r"(?:^|\s)-j (\S+)", line)
                if m and m.group(1) in ("DROP", "REJECT"):
                    st["ipv4"] = "filtering"
            continue
        if line.startswith("table "):
            seen = True
            f = line.split()
            fam = fams.get(f[1]) if len(f) >= 2 else None
            in_chain = hook_input = False
            continue
        if line.startswith("chain ") and line.endswith("{"):
            in_chain, hook_input = True, False
            continue
        if not in_chain or fam is None:
            continue
        if line == "}":
            in_chain = hook_input = False
            continue
        if line.startswith("type ") and " hook " in line:
            hook_input = " hook input " in f" {line} "
            if hook_input and re.search(r"policy (?:drop|reject)\b", line):
                for x in fam:
                    st[x] = "filtering"
            continue
        if hook_input and VERDICT_BLOCK.search(line) and not LOOPBACK_ONLY.search(line):
            for x in fam:
                st[x] = "filtering"
    if not seen and t.strip():
        st["format"] = "unknown"
    return st


def parse_paths(t, stem, fn, notes):
    paths, bad = [], 0
    for line in t.splitlines():
        if not line.strip():
            continue
        f = line.split("\t")
        if len(f) == 3 and PATH_RE.match(f[2]):
            paths.append(f[2])
        else:
            bad += 1
    if bad:
        notes.append(f"{stem}/{fn}：{bad} 行格式不認得，略過")
    return paths


def parse_auto_updates(t, stem):
    """APT::Periodic::Unattended-Upgrade 不是 0、unattended-upgrades 服務 enabled、apt-daily-upgrade.timer enabled 三個都要。"""
    uu = svc = timer = None
    for raw in t.splitlines():
        line = raw.strip()
        if uu is None and line.startswith("APT::Periodic::Unattended-Upgrade"):
            m = re.match(r'^APT::Periodic::Unattended-Upgrade\s+"(\d{1,4})"', line[:200])
            uu = m.group(1) if m else "?"
        elif svc is None and line.startswith("unattended-upgrades:"):
            v = line.split(":", 1)[1].strip()
            svc = v if TOKEN_RE.match(v) else "?"
        elif timer is None and line.startswith("apt-daily-upgrade.timer:"):
            v = line.split(":", 1)[1].strip()
            timer = v if TOKEN_RE.match(v) else "?"
    if uu not in (None, "0", "?") and svc == "enabled" and timer == "enabled":
        return []
    state = f"Unattended-Upgrade {uu or 'not set'}, unattended-upgrades {svc or 'unknown'}, apt-daily-upgrade.timer {timer or 'unknown'}"
    return [finding("board:no-auto-updates", "board", "auto-updates", "medium", "Automatic security updates are not enabled",
                    f"{state}: all three must be on for apt to install security updates automatically. Annex I Part I (2)(c) expects "
                    "security updates to be installed automatically by default, with an opt-out.",
                    ("I-2c",), [f"{stem}/auto-updates.txt: {state}"],
                    "Check /etc/apt/apt.conf.d/20auto-upgrades, `systemctl is-enabled unattended-upgrades apt-daily-upgrade.timer` on the board.",
                    "Enable automatic security updates, or record how updates reach the device (for example an OTA mechanism) "
                    "and how the user can opt out.")]


def parse_services(t, stem):
    out = []
    for line in t.splitlines():
        f = line.split()
        if len(f) < 2 or not PROC_RE.match(f[0]) or f[1] != "enabled":
            continue
        sev = "high" if CLEAR_UNITS.match(f[0]) else "medium" if TEST_UNITS.match(f[0]) else None
        if sev:
            out.append(finding(f"board:service-enabled:{f[0]}", "board", "services", sev, f"{f[0]} is enabled at boot",
                               f"{f[0]} is enabled at boot; it is " + ("a cleartext or legacy remote-access service."
                                                                         if sev == "high" else "a test or debugging tool."),
                               ("I-2b", "I-2j"), [f"{stem}/services-enabled.txt: {f[0]} enabled"],
                               f"Run `systemctl is-enabled {f[0]}` on the board.", "Disable or remove it in the shipped image."))
    return out


def parse_os(t):
    info = {}
    for line in t.splitlines():
        if "os" not in info and line.startswith("PRETTY_NAME="):
            info["os"] = clean_version(line[12:120].strip().strip('"'))
        elif "l4t" not in info and line.startswith("# R"):
            m = re.match(r"^# R(\d{2,3}) \(release\), REVISION: (\d{1,3}(?:\.\d{1,3})?)", line[:100])
            if m:
                info["l4t"] = f"R{m.group(1)}.{m.group(2)}"
    return info


def parse_lynis(t, stem):
    info, warns = {}, []
    for line in t.splitlines():
        k, _, v = line.partition("=")
        if k == "lynis_version" and "lynis_version" not in info:
            info["lynis_version"] = clean_version(v, 20)
        elif k == "hardening_index" and v.strip().isdigit():
            info["lynis_hardening_index"] = int(v.strip())
        elif k == "warning[]":
            tid = v.split("|", 1)[0]
            if LYNIS_ID.match(tid) and tid not in warns:
                warns.append(tid)
        elif k == "suggestion[]":
            info["lynis_suggestions"] = info.get("lynis_suggestions", 0) + 1
    out = [finding(f"board:lynis:{w}", "board", "lynis", "low", f"Lynis warning {w}",
                   f"Lynis reported a warning for test {w} (text in lynis-report.dat).", ("I-2b",),
                   [f"{stem}/lynis-report.dat: warning {w}"], "Read the warning in lynis-report.dat.",
                   "Fix the configuration or record why the warning does not apply.") for w in warns]
    return out, info


FW_SECTIONS = {"dmi", "nv_tegra_release", "nvbootctrl", "nvbootctrl-rootfs", "dmesg-optee", "dmesg-bpmp", "efivar-SecureBoot", "efivar-SetupMode"}
RUNTIME_MAX_PATHS = 100_000
RUNTIME_HDR = re.compile(r"^# ok (\d{1,7}) paths$")


def parse_firmware(t, notes, stem):
    """firmware.txt（board-on-device.sh 的「== 項目」分段）→ {欄位: 值或 None}、not_run: [項目]。NOT_RUN 的項目是 None（未量測），
    不是空字串；讀不懂的項目也是 None。只取固定欄位，值清掉不可見字元並截短。"""
    sec, body = None, {}
    for line in t.splitlines():
        if line.startswith("== "):
            sec = line[3:].strip()
            body[sec] = [] if sec in FW_SECTIONS else None
        elif sec in body and body[sec] is not None and len(body[sec]) < 40:
            body[sec].append(line.rstrip()[:300])
    out, not_run = {}, []

    def first(sec, rx=None):
        lines = [x for x in body.get(sec) or [] if x.strip()]
        if not lines or any(x.startswith("NOT_RUN") for x in lines):
            not_run.append(sec)
            return None
        if rx is None:
            return clean_version(lines[0], 120)
        for x in lines:
            m = re.search(rx, x)
            if m:
                return clean_version(m.group(1), 80)
        not_run.append(sec)
        return None
    kv = {}
    for x in body.get("dmi") or []:
        k, _, v = x.partition("=")
        if k in ("bios_version", "bios_date", "bios_vendor"):
            kv[k] = None if v.startswith("NOT_RUN") else clean_version(v, 80)
    for k in ("bios_version", "bios_date", "bios_vendor"):
        out[k] = kv.get(k)
        if kv.get(k) is None:
            not_run.append(k)
    raw = next((x for x in body.get("nv_tegra_release") or [] if x.startswith("# R")), "")
    out["nv_tegra_release"] = clean_version(raw.lstrip("# "), 120) if raw else None
    if raw is None or not raw:
        not_run.append("nv_tegra_release")
    m = re.match(r"^# R(\d{2,3}) \(release\), REVISION: (\d{1,3}(?:\.\d{1,3})?)", raw)
    out["l4t"] = f"R{m.group(1)}.{m.group(2)}" if m else None
    for sec, key in (("nvbootctrl", "nvbootctrl_slots"), ("nvbootctrl-rootfs", "nvbootctrl_rootfs")):
        lines = [clean_version(x, 120) for x in body.get(sec) or [] if x.strip()]
        if not lines or any(x.startswith("NOT_RUN") for x in lines):
            out[key] = None
            not_run.append(sec)
        else:
            out[key] = lines[:12]
    out["nvbootctrl_version"] = next((m.group(1) for x in body.get("nvbootctrl") or [] for m in [re.match(r"^Current version: (\S{1,30})", x)] if m), None)
    out["optee"] = first("dmesg-optee", r"optee: (revision [0-9A-Za-z. ()]{1,40})")
    out["bpmp"] = first("dmesg-bpmp", r"firmware: (\S{1,80})")
    for sec, key in (("efivar-SecureBoot", "secure_boot"), ("efivar-SetupMode", "setup_mode")):
        lines = body.get(sec) or []
        m = next((re.match(r"^\w+=(\d)$", x.strip()) for x in lines if re.match(r"^\w+=\d$", x.strip())), None)
        out[key] = int(m.group(1)) if m else None
        if not m:
            not_run.append(sec)
    out["not_run"] = sorted(set(not_run))
    if not any(v for k, v in out.items() if k != "not_run"):
        notes.append(f"{stem}/firmware.txt：讀不出任何韌體版本")
    return out


# ---------- 完整性、更新通道、記錄（board-on-device.sh 的 integrity.txt、update-channel.txt、logging.txt） ----------
# 規則：每個欄位三種結果——找到（yes／present／值）、沒找到（absent／no）、沒量到（NOT_RUN、缺段落、讀不懂）；
# 只有「找到弱點」才出 medium／low 的 finding，「沒找到保護機制」與「沒量到」最多出 info，絕不當成通過。
# 嚴重度（保守）：medium＝直接讓未授權的軟體或不受驗證的套件進得來（Secure Boot 關閉、fuse 未燒）；high＝apt 明確允許未驗證的來源；
# low＝縱深防禦或可用性的弱點（沒有 lockdown、http 來源但索引有簽章、日誌不持久、沒有輪替）；info＝沒找到／沒量到。
INTEG_SECTIONS = {"uefi", "dt-secure-boot", "dmesg-secureboot", "tegra-fuse", "lockdown", "modsig", "tpm", "ima", "dm-verity"}
UPDATE_SECTIONS = {"apt-sources", "apt-config", "apt-keys", "ota-tools", "esrt"}
LOG_SECTIONS = {"journald", "daemons", "rotation", "remote-logging", "auth-logging"}
KV_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
TRUTHY = {"true", "1", "yes", "on", "with", "enable"}        # apt 的布林值：yes／true／with／on／enable／1
FALSY = {"false", "0", "no", "off", "without", "disable"}
LOCAL_SCHEMES = {"file", "cdrom", "copy"}
BOOL_VALUES = TRUTHY | FALSY
APT_CFG_KEY = re.compile(r"^(?:APT::Get::Allow-?Unauthenticated|Acquire::(?:AllowInsecureRepositories|AllowDowngradeToInsecureRepositories|"
                         r"AllowWeakRepositories|Check-Valid-Until)|Acquire::(?:http|https)::(?:[A-Za-z0-9.-]{1,60}::)?Verify-(?:Peer|Host))$", re.I)
DAEMON_ENABLED = {"enabled", "enabled-runtime", "disabled", "static", "masked", "masked-runtime", "indirect", "generated", "alias", "linked",
                  "linked-runtime", "transient", "not-found", "bad", "unknown"}
DAEMON_ACTIVE = {"active", "inactive", "failed", "activating", "deactivating", "unknown", "reloading"}
DM_KINDS = {"CRYPT-VERITY", "CRYPT-LUKS1", "CRYPT-LUKS2", "CRYPT-PLAIN", "CRYPT-INTEGRITY", "LVM", "mpath", "DMRAID", "stratis"}
OTA_UPDATERS = ("nv_update_engine", "nv_bootloader_payload_updater", "swupdate", "rauc", "mender", "fwupdmgr")


def sections_of(t, names, maxlines=200):
    """「== 項目」分段的文字 → {項目: [行] 或 None（沒有這一段）}。只取已知的段落名稱，每段最多 maxlines 行、每行最多 300 字。"""
    body = {n: None for n in names}
    sec = None
    for line in t.splitlines():
        if line.startswith("== "):
            sec = line[3:].strip()
            if sec in names and body[sec] is None:
                body[sec] = []
            elif sec not in names:
                sec = None
        elif sec is not None and body[sec] is not None and len(body[sec]) < maxlines:
            body[sec].append(line.rstrip()[:300])
    return body


def kv_of(lines):
    """['k=v', ...] → {k: v}（第一個為準）；沒有這一段 → {}。"""
    d = {}
    for x in lines or []:
        k, sep, v = x.partition("=")
        if sep and KV_KEY.match(k) and k not in d:
            d[k] = v.strip()
    return d


def measured(v):
    """欄位有量到（不是缺少、不是 NOT_RUN）。"""
    return v is not None and not v.startswith("NOT_RUN")


def pick(v, allowed_values):
    return v if v in allowed_values else None


def parse_integrity(t, stem, notes):
    """integrity.txt → (findings, info)。info 的每個欄位：值、"absent"、或 None（沒量到）；not_run 列出沒量到的項目。"""
    body = sections_of(t, INTEG_SECTIONS)
    fn = f"{stem}/integrity.txt"
    info, nrun, out = {}, [], []
    for sec, lines in body.items():
        if lines is None:
            nrun.append(sec)
    u, fu = kv_of(body["uefi"]), kv_of(body["tegra-fuse"])
    efi = pick(u.get("efi"), ("present", "absent"))
    info["uefi"] = efi
    vals = {}
    for k in ("SecureBoot", "SetupMode"):
        v = u.get(k)
        vals[k] = int(v) if v in ("0", "1") else None
        if vals[k] is None:
            nrun.append("efivar-" + k)
    info["setup_mode"] = vals["SetupMode"]
    keys = {k: pick(u.get(k), ("present", "absent")) for k in ("PK", "KEK", "db", "dbx")}
    info["uefi_keys"] = keys
    if any(v is None for v in keys.values()):
        nrun.append("uefi-keys")
    # 三個證據來源（efivar、device-tree、dmesg）：全部指向同一方向才下結論；互相矛盾時列 note，不下結論
    dtv = next((l.split("=", 1)[1].strip() for l in body["dt-secure-boot"] or [] if l.startswith("value=")), "")
    dtm = {2: "off", 3: "on"}.get(int(dtv, 16)) if re.match(r"^[0-9a-f]{8}$", dtv) else None
    dm = None
    for l in body["dmesg-secureboot"] or []:
        m = re.search(r"(?i)secure ?boot\W+(?:secure ?boot\W+)?(enabled|disabled)", l)
        if m:
            dm = "on" if m.group(1).lower() == "enabled" else "off"
            break
    sb = {"efivar": {0: "off", 1: "on"}.get(vals["SecureBoot"]), "device-tree": dtm, "dmesg": dm}
    seen = {v for v in sb.values() if v}
    ev = []
    if vals["SecureBoot"] is not None:
        ev.append(f"{fn}: SecureBoot={vals['SecureBoot']}" + (f", SetupMode={vals['SetupMode']}" if vals["SetupMode"] is not None else ""))
    if dtm:
        ev.append(f"{fn}: device-tree linux,uefi-secure-boot={dtv} ({'disabled' if dtm == 'off' else 'enabled'})")
    if dm:
        ev.append(f"{fn}: dmesg reports Secure Boot {'disabled' if dm == 'off' else 'enabled'}")
    if len(seen) > 1:
        info["secure_boot_uefi"] = "conflict"
        notes.append(f"{fn}：UEFI Secure Boot 的來源互相矛盾（{', '.join(f'{k}={v}' for k, v in sb.items() if v)}），沒有下結論")
    elif seen == {"off"}:
        info["secure_boot_uefi"] = "disabled"
        sm = (" SetupMode=1 means no Platform Key is enrolled, so the firmware accepts new keys without authentication from software that can "
              "write the UEFI variables." if vals["SetupMode"] == 1 else "")
        out.append(finding("board:secureboot-disabled", "board", "integrity", "medium", "UEFI Secure Boot is disabled",
                           "The UEFI firmware does not verify the boot loader and kernel signatures (Secure Boot is off). Software that is not signed "
                           "by the product vendor can be started at boot, which weakens the integrity of programs (Annex I Part I (2)(f); "
                           "EN 303 645 5.7-1 expects the device to verify its software with a secure boot mechanism)." + sm +
                           " This finding is about the UEFI layer only; a vendor boot chain verified by fuses or a boot ROM is not visible here.",
                           ("I-2f", "I-2d"), ev,
                           "On the board: `od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-*` (0 = off) and `dmesg | grep -i secureboot`.",
                           "Enable and enroll Secure Boot keys in the shipped image (and sign the boot loader and kernel), or document the boot-chain "
                           "verification that replaces it (for example fused secure boot) and why this one stays off."))
    elif seen == {"on"}:
        info["secure_boot_uefi"] = "enabled"
    else:
        info["secure_boot_uefi"] = "no_uefi" if efi == "absent" else None
    # Jetson：boot chain 的 Secure Boot 由 fuse 決定。只讀 sysfs 的少數白名單節點；原始 fuse 陣列不讀
    # 節點名稱的公開出處：odm_production_mode 是 NVIDIA tegra 核心原始碼（android.googlesource.com 上的鏡像）裡 tegra-fuse 驅動的 sysfs 屬性
    # （drivers/misc/tegra-fuse/tegra_fuse.c 的 DEVICE_ATTR(odm_production_mode, 0440, …)；
    #  https://android.googlesource.com/kernel/tegra.git/+/8a95a1a8e5817af21188ad74872b768d5d1ebe35/drivers/misc/tegra-fuse/tegra_fuse.c），
    # Jetson Linux Developer Guide 的 Secure Boot 一節列出 odm_production_mode（tegraflash 別名 SecurityMode）與 Security_info（BootSecurityInfo）這兩個 fuse。
    # security_mode、boot_security_info 這兩個 sysfs 節點名稱沿用板上收集腳本的白名單，沒有找到 NVIDIA 的正式文件；讀不到就是沒量到（None）。
    # 這裡只解析數字，值不進 finding 的說明以外的地方；測試資料只用虛構值。
    tegra = pick(fu.get("tegra"), ("yes", "no"))
    info["jetson"] = None if tegra is None else tegra == "yes"
    fuse = {}
    for k in ("odm_production_mode", "security_mode", "boot_security_info"):
        v = fu.get(k, "")
        m = re.match(r"^(?:0[xX]([0-9a-fA-F]{1,8})|(\d{1,10}))$", v)
        fuse[k] = (int(m.group(1), 16) if m.group(1) else int(m.group(2))) if m else None
    info["jetson_fuse"] = fuse if any(v is not None for v in fuse.values()) else None
    if tegra == "yes":
        odm = fuse["odm_production_mode"]
        if odm == 0:
            out.append(finding("board:secureboot-fuse-not-burned", "board", "integrity", "medium",
                               "Jetson ODM production mode fuse is not burned",
                               "odm_production_mode is 0: the SoC is still in its development state. The boot ROM then does not enforce a "
                               "fused secure boot key (PKC hash / SB_ENABLE), so the early boot stages are not verified against a vendor key "
                               "(Annex I Part I (2)(f); EN 303 645 5.7-1). The fuse state of other secure boot settings is not read by this check.",
                               ("I-2f", "I-2d"), [f"{fn}: odm_production_mode=0"],
                               "On the board: `cat /sys/devices/platform/tegra-fuse/odm_production_mode`; or read the fuses in recovery mode with NVIDIA's flashing tools.",
                               "Burn the production fuses (PKC hash, SB_ENABLE, ODM production mode) on shipped units and keep the flashing record, "
                               "or document why they stay unburned."))
        elif odm is None:
            out.append(finding("board:secureboot-fuse-not-assessed", "board", "integrity", "info",
                               "Jetson fuse-based secure boot state could not be read",
                               "Jetson boot-chain secure boot is controlled by SoC fuses. The sysfs nodes that report them were not found on this "
                               "board, and the raw fuse array is deliberately not read, so the fuse state is NOT_RUN: this is not evidence that "
                               "secure boot is on or off.",
                               ("I-2f",), [f"{fn}: tegra-fuse odm_production_mode NOT_RUN"],
                               "Check the flashing record, or read the fuses in recovery mode with NVIDIA's tools.",
                               "Record the fuse state of the shipped units (for example from the flashing log) in the technical documentation."))
    if info["secure_boot_uefi"] in (None, "no_uefi") and not (tegra == "yes" and info["jetson_fuse"]):
        out.append(finding("board:secureboot-not-assessed", "board", "integrity", "info", "Secure Boot state could not be determined",
                           "No UEFI Secure Boot variable, device-tree flag or kernel message was found" +
                           (" (the board does not boot through UEFI)" if efi == "absent" else "") + ", and no fuse state was readable. "
                           "Secure boot of a vendor boot chain (U-Boot verified boot, boot ROM keys, fuses) cannot be read from the running system "
                           "by this check, so the result is NOT_RUN: it does not show that the boot chain is verified or unverified.",
                           ("I-2f",), [f"{fn}: no Secure Boot evidence"],
                           "Check the boot loader configuration and the flashing/signing record for the product.",
                           "Document how the boot chain is verified (EN 303 645 5.7-1) in the technical documentation."))
    # kernel lockdown
    ld = (body["lockdown"] and kv_of(body["lockdown"]).get("lockdown")) or None
    if ld == "absent":
        info["lockdown"] = "absent"
    elif ld and measured(ld):
        m = re.search(r"\[(none|integrity|confidentiality)\]", ld)
        info["lockdown"] = m.group(1) if m else None
    else:
        info["lockdown"] = None
    if info["lockdown"] is None:
        nrun.append("lockdown")
    elif info["lockdown"] in ("none", "absent"):
        what = ("The kernel was built without the lockdown feature (no /sys/kernel/security/lockdown)." if info["lockdown"] == "absent"
                else "Kernel lockdown is set to none.")
        out.append(finding("board:lockdown-none", "board", "integrity", "low", "Kernel lockdown is not active",
                           what + " Root can then modify the running kernel (for example by loading unsigned modules or writing to /dev/mem), "
                           "which weakens software integrity (Annex I Part I (2)(f), (k)). It is defence in depth; it matters most together with Secure Boot.",
                           ("I-2f", "I-2k"), [f"{fn}: lockdown={info['lockdown']}"],
                           "On the board: `cat /sys/kernel/security/lockdown`.",
                           "Build the kernel with the lockdown LSM and enable at least integrity mode, or record why it is not used."))
    sg = kv_of(body["modsig"]).get("sig_enforce")
    info["module_sig_enforce"] = {"Y": True, "N": False, "absent": "absent"}.get(sg)
    tp = [l for l in body["tpm"] or [] if l.startswith("tpm=")]
    tpms = [f"{m.group(1)} (version {m.group(2) or 'unknown'})" for m in (re.match(r"^tpm=(tpm\d{1,2}) version_major=(\d?)$", l) for l in tp) if m]
    info["tpm"] = None if body["tpm"] is None else ("absent" if any(l == "tpm=absent" for l in tp) else tpms[:4] or None)
    iv = (body["ima"] or [""])[0] if body["ima"] else ""
    info["ima"] = "present" if iv.startswith("ima=present") else "absent" if iv == "ima=absent" else None
    if info["ima"] is None:
        nrun.append("ima")
    d = kv_of(body["dm-verity"])
    cv = pick(d.get("cmdline_verity"), ("yes", "no"))
    # dm 裝置的 uuid 前綴（板子上只輸出前兩段，例如 CRYPT-VERITY）：只留已知的種類，其他只留第一段
    dms = sorted({(l[3:] if l[3:] in DM_KINDS else l[3:].split("-", 1)[0]) for l in body["dm-verity"] or []
                  if l.startswith("dm=") and re.match(r"^[A-Za-z0-9-]{1,30}$", l[3:])})[:10]
    if body["dm-verity"] is None or cv is None:
        info["dm_verity"] = None
        nrun.append("dm-verity")
    else:
        info["dm_verity"] = "found" if cv == "yes" or any("VERITY" in x.upper() for x in dms) else "not_found"
    info["dm_devices"] = dms
    if info["dm_verity"] == "not_found" and info["ima"] == "absent":
        out.append(finding("board:integrity-verification-not-found", "board", "integrity", "info",
                           "No runtime integrity verification found (dm-verity, IMA)",
                           "No dm-verity device or kernel command line option and no IMA were found. This only says this check found no such mechanism; "
                           "the product may protect its software in another way (signed update packages, read-only root file system, vendor tools) "
                           "that is not visible from here.",
                           ("I-2f",), [f"{fn}: dm-verity not found, ima=absent"],
                           "On the board: `cat /proc/cmdline`, `ls /sys/kernel/security/ima`.",
                           "Document how the integrity of the installed software is protected (EN 303 645 5.7)."))
    info["not_run"] = sorted(set(nrun))
    return out, info


def source_uris(lines):
    """update-channel.txt 的 apt-sources 段（板子上已經只輸出協定＋主機＋路徑第一段與少數欄位）→
    {srcs: [{scheme, host, signed_by, trusted, insecure_opts, file}], seen: 看到的來源行／段數（含停用的）, files: 檔案數, truncated, errors}。
    deb822 的欄位順序不固定：以空行（或下一個 @file）分段，整段收完才解析。"""
    r = {"srcs": [], "seen": 0, "files": 0, "truncated": False, "errors": 0}
    fname, stanza = "", {}

    def parse_uri(u):
        m = re.match(r"^(?:[a-z0-9]+\+)?([a-z][a-z0-9.+-]*):(?://([A-Za-z0-9.:\[\]-]{1,100})(?:/[A-Za-z0-9._~+-]{0,60})?)?$", u, re.I)
        if not m:
            return ("unknown", "INVALID")
        return (m.group(1).lower(), (m.group(2) or "").lower())

    def add(uri, signed, trusted, opts, f):
        sch, host = parse_uri(uri)
        r["srcs"].append({"scheme": sch, "host": clean_version(host, 100), "signed_by": signed, "trusted": trusted, "insecure_opts": opts,
                          "file": clean_version(f, 60)})

    def flush():
        nonlocal stanza
        if stanza.get("uris"):
            r["seen"] += 1
            if stanza.get("enabled", True):
                opts = [k for k in ("allow-insecure", "allow-weak", "allow-downgrade-to-insecure") if stanza.get(k)]
                for u in stanza["uris"]:
                    add(u, stanza.get("signed_by", False), stanza.get("trusted", False), opts, stanza.get("file", ""))
        stanza = {}
    for line in lines:
        if line.startswith("@file "):
            flush()
            fname = line[6:].strip()
            r["files"] += 1
            continue
        if line.startswith("@truncated"):
            r["truncated"] = True
            continue
        if line.startswith("@error"):
            r["errors"] += 1
            continue
        if not line.strip():
            flush()
            continue
        m = re.match(r"^deb(?:-src)? \[([a-z=\- ]{0,120})\] (\S+)(?: .*)?$", line)
        if m:
            flush()
            r["seen"] += 1
            o = m.group(1).split()
            add(m.group(2), "signed-by=yes" in o, "trusted=yes" in o,
                [x.split("=")[0] for x in o if x.split("=")[0] in ("allow-insecure", "allow-weak", "allow-downgrade-to-insecure")], fname)
            continue
        if line.startswith("deb "):
            r["seen"] += 1
            r["errors"] += 1                 # 「deb ?」：板子上看不懂的來源行
            continue
        k, sep, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if not sep:
            continue
        if k == "uris":
            stanza["uris"] = v.split()[:12]
            stanza["file"] = fname
        elif k == "signed-by":
            stanza["signed_by"] = True
        elif k in ("trusted", "allow-insecure", "allow-weak", "allow-downgrade-to-insecure"):
            stanza[k] = v.lower() == "yes"
        elif k == "enabled":
            stanza["enabled"] = v.lower() != "no"
    flush()
    return r


def parse_update_channel(t, stem, notes):
    """update-channel.txt → (findings, info)。不連網、不執行 apt；只看設定。"""
    body = sections_of(t, UPDATE_SECTIONS, maxlines=400)
    fn = f"{stem}/update-channel.txt"
    info, nrun, out = {}, [], []
    for sec, lines in body.items():
        if lines is None:
            nrun.append(sec)
    sl = body["apt-sources"] or []
    asrc = kv_of([l for l in sl if not l.startswith("@")][:3])
    apt = pick(asrc.get("apt"), ("present", "absent"))
    parsed = source_uris(sl) if apt == "present" else None
    srcs = parsed["srcs"] if parsed else []
    # 來源有沒有量到：解析器沒跑（沒有 awk）、被截斷、有看不懂的行、有 @file 卻一個來源行都沒有 → 沒量到（不出「沒有更新通道」，也不下結論）
    srcs_measured = body["apt-sources"] is not None and apt is not None
    if apt == "present":
        why = ("parser" if asrc.get("parser") != "ok" else "truncated" if parsed["truncated"] else "errors" if parsed["errors"]
               else "no-source-lines" if parsed["files"] and not parsed["seen"] else None)
        if why:
            srcs_measured = False
            nrun.append("apt-sources")
            if why in ("truncated", "errors"):            # 來源檔裡只有註解（沒有來源行）是常見的設定，不算注意事項，只是沒量到
                notes.append(f"{fn}：apt 來源讀不完整（{'輸出被截斷' if why == 'truncated' else '有看不懂的來源行'}），沒有下結論")
    net = [s_ for s_ in srcs if s_["scheme"] not in LOCAL_SCHEMES]
    http = [s_ for s_ in net if s_["scheme"] != "https"]
    cfg_lines = body["apt-config"]
    cfg_ok = cfg_lines is not None and "dump=ok" in cfg_lines
    cfg = {}
    for l in (cfg_lines or []):
        m = re.match(r'^([A-Za-z0-9:.-]{1,120}) "([^"]{0,20})";$', l)
        if m and APT_CFG_KEY.match(m.group(1)):
            cfg.setdefault(m.group(1), m.group(2).lower() if m.group(2).lower() in BOOL_VALUES else "?")
    if body["apt-config"] is not None and not cfg_ok:
        nrun.append("apt-config")
    insecure, insecure_local = [], []
    for k, v in sorted(cfg.items()):
        if v in TRUTHY and re.search(r"Allow(Unauthenticated|InsecureRepositories|DowngradeToInsecureRepositories|WeakRepositories)$", k, re.I):
            insecure.append(f"{k} = {v}")
    for s_ in srcs:
        what = ["trusted=yes (signature check skipped)"] * bool(s_["trusted"]) + [f"{o}=yes" for o in s_["insecure_opts"]]
        for w in what:
            line = f"source {s_['scheme']}://{s_['host']} ({s_['file']}) has {w}" if s_["scheme"] not in LOCAL_SCHEMES else \
                f"local source {s_['scheme']}: ({s_['file']}) has {w}"
            (insecure_local if s_["scheme"] in LOCAL_SCHEMES else insecure).append(line)
    tls_off = [f"{k} = {v}" for k, v in sorted(cfg.items()) if re.search(r"Verify-(Peer|Host)$", k, re.I) and v in FALSY]
    info["apt"] = None if apt is None else apt
    if apt == "present" and srcs_measured:
        info["apt_sources"] = {"active_network": len(net), "https": len(net) - len(http), "not_https": len(http), "local": len(srcs) - len(net),
                               "with_signed_by": sum(1 for s_ in net if s_["signed_by"]), "trusted_yes": sum(1 for s_ in srcs if s_["trusted"])}
    else:
        info["apt_sources"] = None
    kd = kv_of(body["apt-keys"])
    info["apt_keys"] = ({"legacy_trusted_gpg": pick(kd.get("legacy_trusted_gpg"), ("present", "absent")),
                         "trusted_gpg_d": int(kd["trusted.gpg.d_count"]) if re.match(r"^\d{1,5}$", kd.get("trusted.gpg.d_count", "")) else None,
                         "keyrings": int(kd["keyrings_count"]) if re.match(r"^\d{1,5}$", kd.get("keyrings_count", "")) else None}
                        if body["apt-keys"] is not None else None)
    info["apt_config"] = {k: v for k, v in sorted(cfg.items())[:20]} if cfg_ok else None
    if insecure or insecure_local:
        # 全域設定或網路來源不檢查簽章＝high；只有本機來源（file:／cdrom:）不檢查簽章＝medium（風險在於誰能寫那個資料夾，不是網路攻擊者）
        sev = "high" if insecure else "medium"
        allx = insecure + insecure_local
        out.append(finding("board:apt-insecure-allowed", "board", "update-channel", sev, "apt is configured to accept unverified packages or repositories",
                           "apt accepts packages or repository indexes without a valid signature (" + "; ".join(allx[:5]) + "). " +
                           ("A network attacker or a compromised mirror could then deliver modified software as an update"
                            if insecure else "The unsigned source is local (file: or cdrom:), so the risk is whoever can write to that location, not a network attacker")
                           + " (Annex I Part I (2)(c), (f); EN 303 645 5.3; EN 18031 SUM).",
                           ("I-2c", "I-2f"), [f"{fn}: {x}" for x in allx],
                           "On the board: `apt-config dump | grep -i -E 'Unauthenticated|Insecure|Weak'`, and look for `trusted=yes` in /etc/apt/sources.list*.",
                           "Remove the option and make every repository signed (Signed-By with a keyring), or record why the setting is needed."))
    if tls_off:
        out.append(finding("board:apt-tls-verify-off", "board", "update-channel", "medium", "apt does not verify the TLS certificate of its repositories",
                           "apt is configured not to verify the TLS peer or host (" + "; ".join(tls_off[:4]) + "). Packages are still checked by signature, "
                           "but the repository connection can be intercepted or redirected (EN 303 645 5.3, EN 18031 SUM).",
                           ("I-2c", "I-2e"), [f"{fn}: {x}" for x in tls_off],
                           "On the board: `apt-config dump | grep -i Verify`.", "Remove the option, or pin the repository certificate."))
    if http:
        hosts = sorted({f"{s['scheme']}://{s['host']}" for s in http})
        out.append(finding("board:apt-source-http", "board", "update-channel", "low", "apt repositories are reached without TLS",
                           f"{len(http)} active apt source(s) use plain http ({', '.join(hosts[:5])}{', …' if len(hosts) > 5 else ''}). "
                           "The repository index is still protected by its signature, so packages cannot be swapped without the signing key, "
                           "but what is installed is visible to a network observer and downgrade/replay of old indexes is only limited by the validity dates "
                           "(EN 303 645 5.3). Distribution mirrors over http are common; this is low.",
                           ("I-2c", "I-2e"), [f"{fn}: {x}" for x in hosts],
                           "On the board: `grep -rh '^deb\\|^URIs' /etc/apt/sources.list*`.",
                           "Use https mirrors where the vendor offers them, or record that the signed index is the integrity protection."))
    ota = kv_of(body["ota-tools"])
    tools = sorted(k for k in OTA_UPDATERS if ota.get(k) == "present")
    info["ota_tools"] = None if body["ota-tools"] is None else tools
    info["nvbootctrl"] = pick(ota.get("nvbootctrl"), ("present", "absent"))
    units = [l[5:] for l in body["ota-tools"] or [] if l.startswith("unit=")]
    info["ota_units"] = sorted({clean_version(u.split()[0], 60) for u in units if u.split()})[:12]
    es = kv_of(body["esrt"])
    esrt = pick(es.get("esrt"), ("present", "absent"))
    entries = sum(1 for l in body["esrt"] or [] if l.startswith("entry "))
    info["esrt"] = {"present": esrt == "present", "entries": entries} if esrt else None
    if body["esrt"] is not None and esrt is None:
        nrun.append("esrt")
    have_channel = bool(net or tools or info["ota_units"] or entries)
    if srcs_measured and body["ota-tools"] is not None and not have_channel:
        out.append(finding("board:update-channel-not-found", "board", "update-channel", "info", "No software update channel found",
                           "No active network apt source, no OTA update client (nv_update_engine, swupdate, rauc, mender, fwupd) and no UEFI capsule "
                           "resource table was found. The product may use an update mechanism this check does not know; the result is 'not found', "
                           "not 'no updates possible'.",
                           ("I-2c",), [f"{fn}: no apt network source, no OTA tool, no ESRT entry"],
                           "Ask the product team how security updates reach the device.",
                           "Document the update mechanism and its signature verification (EN 303 645 5.3, EN 18031 SUM)."))
    info["not_run"] = sorted(set(nrun))
    return out, info


def parse_logging(t, stem, notes):
    """logging.txt → (findings, info)。"""
    body = sections_of(t, LOG_SECTIONS)
    fn = f"{stem}/logging.txt"
    info, nrun, out = {}, [], []
    for sec, lines in body.items():
        if lines is None:
            nrun.append(sec)
    j = kv_of(body["journald"])
    pdir = pick(j.get("persistent_dir"), ("yes", "no"))
    stor = (j.get("storage_conf") or "").lower()
    stor = stor if stor in ("persistent", "volatile", "auto", "none") else "unset"
    jact = j.get("active", "")
    jact = jact if jact in ("active", "inactive", "failed", "activating", "deactivating") else None
    persist = None if pdir is None else False if stor in ("volatile", "none") else True if stor == "persistent" else pdir == "yes"
    info["journal"] = {"persistent": persist, "storage_conf": stor, "active": jact}
    dm = {}
    for l in body["daemons"] or []:
        m = re.match(r"^(rsyslog|syslog-ng|auditd|systemd-journal-remote|systemd-journal-upload) enabled=(\S{1,30}) active=(\S{1,30})$", l)
        if m:
            dm[m.group(1)] = (m.group(2) if m.group(2) in DAEMON_ENABLED else "?", m.group(3) if m.group(3) in DAEMON_ACTIVE else "?")
    info["daemons"] = {k: {"enabled": v[0], "active": v[1]} for k, v in sorted(dm.items())} if dm else None
    if not dm:
        nrun.append("daemons")

    def active(n):
        v = dm.get(n)
        return None if v is None or v[1] not in ("active", "inactive", "failed") else v[1] == "active"
    syslog, audit = active("rsyslog"), active("auditd")
    syslog_ng = active("syslog-ng")
    other_store = [x for x in (syslog, syslog_ng, audit) if x]
    unknown_other = any(x is None for x in (syslog, syslog_ng, audit))
    evj = f"{fn}: journald active={jact}, persistent_dir={pdir}, Storage={stor}"
    if jact is None or persist is None:
        nrun.append("journald")
    elif jact != "active" and not other_store and not unknown_other:
        out.append(finding("board:no-log-service", "board", "logging", "medium", "No logging service is running",
                           "systemd-journald is not active and neither rsyslog, syslog-ng nor auditd is active. Security-relevant events are then not "
                           "recorded (Annex I Part I (2)(l); EN 18031 LGM).",
                           ("I-2l",), [evj, f"{fn}: rsyslog/syslog-ng/auditd not active"],
                           "On the board: `systemctl status systemd-journald rsyslog auditd`.",
                           "Enable a logging service, or document how security events are recorded."))
    elif persist is False and not other_store and not unknown_other:
        out.append(finding("board:journal-not-persistent", "board", "logging", "low", "Logs are kept only in memory",
                           "The journal is volatile (no /var/log/journal and Storage= is not persistent) and no other logging daemon writes logs to disk, "
                           "so the record of security-relevant events is lost at every reboot or power cycle (Annex I Part I (2)(l); EN 18031 LGM). "
                           "On a device without writable storage or with flash-wear limits this can be a deliberate choice.",
                           ("I-2l",), [evj], "On the board: `ls /var/log/journal`, `grep -i Storage /etc/systemd/journald.conf*`.",
                           "Create /var/log/journal (or set Storage=persistent) with a size limit, or forward logs to a remote collector and document it."))
    rt = kv_of(body["rotation"])
    lr = pick(rt.get("logrotate"), ("present", "absent"))
    lt = rt.get("logrotate_timer", "")
    lt = lt if re.match(r"^[a-z-]{1,30}$", lt) else None
    cron = pick(rt.get("logrotate_cron"), ("yes", "no"))
    rconf = pick(rt.get("rsyslog_logrotate_conf"), ("yes", "no"))
    info["rotation"] = {"logrotate": lr, "timer": lt, "cron": cron, "rsyslog_conf": rconf} if body["rotation"] is not None else None
    if body["rotation"] is None or lr is None or lt is None or cron is None or rconf is None:
        nrun.append("rotation")
    elif syslog:
        sched = lt == "enabled" or cron == "yes"
        if not (lr == "present" and sched and rconf == "yes"):
            miss = [x for x, ok in (("logrotate is not installed", lr == "present"), ("no logrotate timer or cron job", sched),
                                    ("no /etc/logrotate.d/rsyslog", rconf == "yes")) if not ok]
            out.append(finding("board:log-rotation-missing", "board", "logging", "low", "Text logs written by rsyslog are not rotated",
                               "rsyslog writes log files under /var/log but " + "; ".join(miss) + ". The files grow without limit and can fill the storage "
                               "(Annex I Part I (2)(h), (l); EN 18031 LGM). The journal has its own size limits and is not affected.",
                               ("I-2l", "I-2h"), [f"{fn}: logrotate={lr}, logrotate.timer={lt}, cron={cron}, rsyslog conf={rconf}"],
                               "On the board: `dpkg -l logrotate`, `systemctl is-enabled logrotate.timer`, `ls /etc/logrotate.d`.",
                               "Install and enable logrotate with a rule for the rsyslog files, or limit the size another way."))
    rm = kv_of(body["remote-logging"])
    rr, ar = pick(rm.get("rsyslog_remote"), ("yes", "no", "absent")), pick(rm.get("auditd_remote"), ("yes", "no", "absent"))
    jup = dm.get("systemd-journal-upload")
    jup_on = None if jup is None else (jup[0] == "enabled" or jup[1] == "active")
    if body["remote-logging"] is None or rr is None or ar is None or jup_on is None:
        info["remote_logging"] = "yes" if "yes" in (rr, ar) or jup_on else None
        if info["remote_logging"] is None:
            nrun.append("remote-logging")
    else:
        info["remote_logging"] = "yes" if "yes" in (rr, ar) or jup_on else "no"
    if info["remote_logging"] == "no":
        out.append(finding("board:remote-logging-not-configured", "board", "logging", "info", "No remote log forwarding configured",
                           "No remote target was found in the rsyslog configuration, the audit remote plugin or systemd-journal-upload. A stand-alone "
                           "product can keep its logs locally; this is recorded so the choice is visible (Annex I Part I (2)(l)).",
                           ("I-2l",), [f"{fn}: rsyslog_remote={rr}, auditd_remote={ar}, journal-upload={'on' if jup_on else 'off'}"],
                           "On the board: `grep -rn '@\\|omfwd' /etc/rsyslog.conf /etc/rsyslog.d`.",
                           "Document where security logs can be read by the user or operator."))
    au = kv_of(body["auth-logging"])
    af, ar2 = pick(au.get("auth_log_file"), ("present", "absent")), pick(au.get("rsyslog_auth_rule"), ("yes", "no", "absent"))
    jn = au.get("journal_ssh_entries", "")
    jn = int(jn) if re.match(r"^\d{1,3}$", jn) else None
    found = af == "present" or ar2 == "yes" or (jn or 0) > 0
    info["auth_logging"] = ("found" if found else None if af is None or ar2 is None or jn is None else "not_found") if body["auth-logging"] is not None else None
    if info["auth_logging"] is None:
        nrun.append("auth-logging")
    elif info["auth_logging"] == "not_found":
        out.append(finding("board:auth-logging-not-found", "board", "logging", "info", "No authentication log found",
                           "No /var/log/auth.log, no rsyslog auth rule and no sshd entries in the journal of this boot were found. This can also mean nobody "
                           "has logged in since boot; it is recorded as 'not found', not as a pass (Annex I Part I (2)(l)).",
                           ("I-2l",), [f"{fn}: auth_log_file={af}, rsyslog_auth_rule={ar2}, journal_ssh_entries={jn}"],
                           "On the board: `ls -l /var/log/auth.log`, `journalctl -u ssh -b`.", "Make sure login events are logged (rsyslog auth rule or journald)."))
    info["audit"] = None if audit is None else audit
    info["not_run"] = sorted(set(nrun))
    return out, info


def parse_runtime(files, stem, notes, when):
    """runtime-files.txt、runtime-modules.txt（board-on-device.sh）→ {files, modules, uptime, processes, captured, ...}。
    一塊板子、一次量測的狀態：沒出現在清單裡不代表沒用到。沒有這兩個檔案 → None（未量測）。"""
    ft, mt = text_of(files.get("runtime-files.txt")), text_of(files.get("runtime-modules.txt"))
    if ft is None and mt is None:
        return None
    out = {"captured": when, "files": None, "modules": None, "uptime": None, "processes": None, "ignored_lines": 0}
    if ft is not None:
        paths, bad, n_hdr, problem = [], 0, None, None
        lines = ft.splitlines()
        if too_long(files.get("runtime-files.txt")):
            problem = f"the list exceeds {LIMITS['lines']} lines (truncated)"
        m = RUNTIME_HDR.match(lines[0].strip()) if lines else None
        if m:
            n_hdr = int(m.group(1))
        else:
            problem = problem or "no '# ok <N> paths' header (the board script did not finish, or an old script version)"
        for line in lines[1:] if m else lines:
            line = line.rstrip("\r")
            if not line:
                continue
            if PATH_RE.match(line) and ".." not in line.split("/"):
                paths.append(line)
            else:
                bad += 1
        out["ignored_lines"] += bad
        if problem is None and bad:
            problem = f"{bad} line(s) are not plain absolute paths (the list may be damaged)"
        if problem is None and n_hdr != len(paths):
            problem = f"the header says {n_hdr} paths, the file has {len(paths)}"
        if problem is None and len(paths) > RUNTIME_MAX_PATHS:
            problem = f"more than {RUNTIME_MAX_PATHS} paths (truncated)"
        if problem is None and not paths:
            problem = "the list is empty"
        if problem is None and not (any(re.search(r"/libc(\.so\.6|-[0-9.]+\.so)$", x) for x in paths) and any(x.startswith("/usr/lib/") or x.startswith("/lib/") for x in paths)):
            problem = "the list is implausible (no libc and nothing under /usr/lib: the capture was probably incomplete)"
        if problem is None:
            out["files"] = sorted(set(paths))
        else:
            out["files_problem"] = problem
            notes.append(f"{stem}/runtime-files.txt：{problem}；執行中使用的檔案未量測（not measured）")
    else:
        notes.append(f"{stem}：沒有 runtime-files.txt（執行中使用的檔案未量測）")
    mods = None
    if mt is not None:
        head, sep, tail = mt.partition("\n===\n")
        mods = sorted({ln.strip().replace("-", "_") for ln in head.splitlines() if re.match(r"^[A-Za-z0-9_-]{1,64}$", ln.strip())})
        tl = [x for x in tail.splitlines() if x.strip()]
        if sep and tl:
            out["uptime"] = clean_version(tl[0].strip(), 120) or None
            if len(tl) > 1 and tl[-1].strip().isdigit():
                out["processes"] = int(tl[-1].strip())
        elif not sep:
            notes.append(f"{stem}/runtime-modules.txt：沒有 === 分隔線，uptime 與程序數未量測")
    if mods is None and files.get("lsmod.txt") is not None:      # 舊版腳本沒有 runtime-modules.txt：用 lsmod.txt 的第一欄
        lt = text_of(files.get("lsmod.txt")) or ""
        mods = sorted({ln.split()[0].replace("-", "_") for ln in lt.splitlines()[1:] if ln.split() and re.match(r"^[A-Za-z0-9_-]{1,64}$", ln.split()[0])}) \
            if lt.startswith("Module") else sorted({ln.split()[0].replace("-", "_") for ln in lt.splitlines() if ln.split() and re.match(r"^[A-Za-z0-9_-]{1,64}$", ln.split()[0])})
    out["modules"] = mods
    return out


def parse_summary(t, stem, notes):
    checks = {}
    for line in t.splitlines()[1:]:
        f = line.split("\t")
        if len(f) >= 2 and re.match(r"^[a-z0-9-]{1,40}$", f[0]) and f[1] in ("OK", "FAIL", "NOT_RUN") and f[0] != "script-version":
            checks[f[0]] = f[1]
    return checks


def script_version(t):
    """summary.txt 的 script-version 列（board-on-device.sh 2026-11-13.1 起）→ 版本字串或 None。"""
    for line in t.splitlines()[1:]:
        f = line.split("\t")
        if len(f) >= 3 and f[0] == "script-version":
            return f[2].strip() if re.match(r"^\d{4}-\d{2}-\d{2}(?:\.\d{1,3})?$", f[2].strip()) else None
    return None


PORT_RE = re.compile(r"(\d{1,5})/(open|open\|filtered|filtered|closed|unfiltered|closed\|filtered)/(tcp|udp)/[^/]*/([^/]*)/[^/]*/([^/,]*)/?")


def parse_ports(t):
    ports = []
    for line in t.splitlines():
        if line.startswith("Host:") and "Ports:" in line:
            seg = line.split("Ports:", 1)[1].split("\tIgnored State:", 1)[0]
            ports += PORT_RE.findall(seg)
        elif re.match(r"^\d{1,5}/open/(tcp|udp)/", line):
            ports += PORT_RE.findall(line)
    return ports


def parse_network(files, stem, notes):
    info, out = {}, []
    open_ports = {}
    filtered = 0
    for proto in ("tcp", "udp"):
        g = text_of(files.get(f"nmap-{proto}.gnmap"))
        if g is None:
            continue
        if too_long(files.get(f"nmap-{proto}.gnmap")):
            notes.append(f"{stem}/nmap-{proto}.gnmap：超過 {LIMITS['lines']} 行，後面的沒有解析")
        for line in g.splitlines()[:5]:
            m = re.match(r"^# Nmap ([0-9A-Za-z.]{1,20}) scan initiated ([A-Za-z0-9 :]{10,40}?) as:", line[:200])
            if m:
                info["nmap_version"] = m.group(1)
                info.setdefault("nmap_started", " ".join(m.group(2).split()))
                break
        info[f"nmap_{proto}"] = "run"
        for port, state, pr, svc, ver in parse_ports(g):
            if state == "open":
                open_ports[(pr, int(port))] = (svc if re.match(r"^[A-Za-z0-9._|?-]{0,40}$", svc) else "?", clean_version(ver))
            elif "filtered" in state:
                filtered += 1
    if "nmap_tcp" not in info and files.get("open-tcp.txt") is not None:
        info["nmap_tcp"] = "open-tcp.txt only"
        for port, state, pr, svc, ver in parse_ports(text_of(files["open-tcp.txt"])):
            if state == "open":
                open_ports[(pr, int(port))] = (svc if re.match(r"^[A-Za-z0-9._|?-]{0,40}$", svc) else "?", clean_version(ver))
    if "nmap_tcp" not in info:
        notes.append(f"{stem}：沒有 nmap-tcp.gnmap 也沒有 open-tcp.txt，看不出對外開的 TCP 埠")
    elif not any(pr == "tcp" for pr, _ in open_ports):
        # -Pn 時 IP 打錯或板子沒開也是「0 個開著的埠、全部 filtered」，不能當成乾淨
        notes.append(f"{stem}：nmap 沒有看到任何開著的 TCP 埠（IP 錯、板子沒開或被擋住時也是這樣）：確認掃描對象後重掃")
    info["open_ports"] = len(open_ports)
    info["open_or_filtered_udp"] = filtered
    for (pr, port), (svc, ver) in sorted(open_ports.items()):
        if not 0 < port < 65536:
            continue
        sev, why = listen_severity(None, port, svc.rstrip("?"))
        out.append(finding(
            f"net:open-{pr}:{port}", "network", "nmap", sev, f"Open {pr}/{port} from the network ({svc or 'unknown service'})",
            f"nmap found {pr}/{port} open ({svc or 'unknown service'}{', ' + ver if ver else ''})" + (f"; this is {why}." if why else "."),
            ("I-2b", "I-2j"), [f"{stem}/nmap-{pr}.gnmap: {port}/{pr} {svc}"],
            f"Repeat `nmap -Pn -p {port}` against a freshly flashed board.",
            "Confirm the product needs this port and record why; otherwise close it."))
    for fn in sorted(files):
        m = re.match(r"^ssh-audit-(\d{1,5})\.json$", fn)
        if m:
            out += parse_ssh_audit(files[fn], int(m.group(1)), stem, fn, notes, info)
        m = re.match(r"^testssl-(\d{1,5})\.json$", fn)
        if m:
            out += parse_testssl(files[fn], int(m.group(1)), stem, fn, notes, info)
    return out, info


def load_doc(data, stem, fn, notes):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        notes.append(f"{stem}/{fn}：不是 JSON，略過")
        return None


def parse_ssh_audit(data, port, stem, fn, notes, info):
    doc = load_doc(data, stem, fn, notes)
    if isinstance(doc, list):
        doc = next((x for x in doc if isinstance(x, dict)), None)
    if not isinstance(doc, dict):
        if doc is not None:
            notes.append(f"{stem}/{fn}：格式不認得，略過")
        return []
    info.setdefault("ssh_audit_ports", []).append(port)
    fail, warn, cves = [], [], []
    algos = with_notes = 0
    for cat in ("kex", "key", "enc", "mac"):
        v = doc.get(cat)
        for a in v if isinstance(v, list) else []:
            algos += 1
            if not isinstance(a, dict) or not isinstance(a.get("algorithm"), str) or not ALGO_RE.match(a["algorithm"]):
                continue
            if not isinstance(a.get("notes"), dict):
                continue
            with_notes += 1
            n = a["notes"]
            if n.get("fail"):
                fail.append(f"{cat} {a['algorithm']}")
            elif n.get("warn"):
                warn.append(f"{cat} {a['algorithm']}")
    for c in doc.get("cves") if isinstance(doc.get("cves"), list) else []:
        if isinstance(c, dict) and isinstance(c.get("name"), str) and CVE_RE.match(c["name"]):
            cves.append(c["name"])
    # ssh-audit 2.x（Ubuntu 22.04）的 JSON 沒有逐個演算法的 notes（enc、mac 是字串清單）：判斷不了 fail／warn，不能當成沒問題
    if not algos or not with_notes:
        notes.append(f"{stem}/{fn}：" + ("沒有演算法清單" if not algos else "演算法沒有 notes（可能是 ssh-audit 2.x 的格式）")
                     + "，判斷不了哪些演算法不建議；用 ssh-audit 3.x 重掃")
    out = []
    if fail:
        out.append(finding(f"net:ssh-audit-fail:{port}", "network", "ssh-audit", "medium", f"SSH on port {port} offers weak algorithms",
                           f"ssh-audit marks {len(fail)} algorithm(s) as fail: {', '.join(fail[:20])}.", ("I-2d", "I-2e"),
                           [f"{stem}/{fn}: {x}" for x in fail], f"Run `ssh-audit -p {port}` against the board.",
                           "Remove these algorithms from the sshd configuration (KexAlgorithms, HostKeyAlgorithms, Ciphers, MACs)."))
    if warn:
        out.append(finding(f"net:ssh-audit-warn:{port}", "network", "ssh-audit", "low", f"SSH on port {port} offers discouraged algorithms",
                           f"ssh-audit warns about {len(warn)} algorithm(s): {', '.join(warn[:20])}.", ("I-2e",),
                           [f"{stem}/{fn}: {x}" for x in warn], f"Run `ssh-audit -p {port}` against the board.",
                           "Remove them where clients do not need them."))
    if cves:
        out.append(finding(f"net:ssh-audit-cve:{port}", "network", "ssh-audit", "medium", f"SSH server on port {port} matches known CVEs",
                           f"ssh-audit lists {len(cves)} CVE(s) for the server version: {', '.join(cves[:20])}.", ("I-2a", "I-2d"),
                           [f"{stem}/{fn}: {c}" for c in cves], "Compare with the vulnerability list (section 8).",
                           "Update the SSH server or record the assessment in the VEX annotations."))
    return out


def parse_testssl(data, port, stem, fn, notes, info):
    doc = load_doc(data, stem, fn, notes)
    if isinstance(doc, dict):
        doc = doc.get("scanResult") if isinstance(doc.get("scanResult"), list) else None
    if not isinstance(doc, list):
        return []
    info.setdefault("testssl_ports", []).append(port)
    by = {"high": [], "medium": [], "low": []}
    for x in doc:
        if not isinstance(x, dict) or not isinstance(x.get("id"), str) or not re.match(r"^[A-Za-z0-9_.-]{1,60}$", x["id"]):
            continue
        s = str(x.get("severity") or "").upper()
        k = "high" if s in ("HIGH", "CRITICAL") else "medium" if s == "MEDIUM" else "low" if s == "LOW" else None
        if k and x["id"] not in by[k]:
            by[k].append(x["id"])
    return [finding(f"net:tls-{k}:{port}", "network", "testssl", k, f"TLS on port {port}: {k} issues",
                    f"testssl.sh reports {len(ids)} {k}-severity item(s): {', '.join(ids[:20])}.", ("I-2e",),
                    [f"{stem}/{fn}: {i}" for i in ids], f"Run `testssl.sh {{board}}:{port}`.",
                    "Fix the TLS configuration (protocols, ciphers, certificate) of this service.")
            for k, ids in by.items() if ids]


def parse_run(stem, kind, files, notes, when=None):
    """一個結果資料夾 → (findings, info, checks)。"""
    info, out = {}, []
    checks = parse_summary(text_of(files["summary.txt"]), stem, notes) if "summary.txt" in files else {}
    if "summary.txt" not in files:
        notes.append(f"{stem}：沒有 summary.txt（不知道哪些檢查有做）")
    # FAIL 才記 notes（ATTENTION）；NOT_RUN 多半是預期的（沒給 --lynis、沒有 SSH 或 TLS 服務、沒有 sudo 不做 UDP），只在 checks 列出
    for c, s in sorted(checks.items()):
        if s == "FAIL":
            notes.append(f"{stem}：{c} 是 {s}")
    if kind == "network":
        f, i = parse_network(files, stem, notes)
        return f, i, checks
    texts = {}
    if "summary.txt" in files and script_version(text_of(files["summary.txt"]) or ""):
        info["script_version"] = script_version(text_of(files["summary.txt"]))

    def t(fn):
        if fn not in texts:
            texts[fn] = text_of(files.get(fn))
            if too_long(files.get(fn)):
                notes.append(f"{stem}/{fn}：超過 {LIMITS['lines']} 行，後面的沒有解析")
        return texts[fn]
    # 該有的檔案：沒有時記 note（ATTENTION），不當作沒有問題。summary.txt 寫 NOT_RUN 的（例如沒有 sshd）不算；FAIL 上面已記
    missing = []
    for fn, check in EXPECTED_BOARD.items():
        if fn in files:
            continue
        st = checks.get(check)
        if st == "NOT_RUN" or st == "FAIL":
            continue
        missing.append(fn)
        notes.append(f"{stem}：沒有 {fn}（" + ("summary.txt 寫 OK，檔案卻不在：匯入時被略過或被刪掉" if st == "OK" else
                                               "summary.txt 沒有這一項") + f"），{check} 沒有檢查")
    if missing:
        info["missing"] = missing
    if t("os.txt") is not None:
        info.update(parse_os(t("os.txt")))
    if t("listening.txt") is not None:
        out += parse_listening(t("listening.txt"), stem, notes)
    if t("sshd-effective.txt") is not None:
        f, ok = parse_sshd(t("sshd-effective.txt"), stem)
        out += f
        if not ok:
            notes.append(f"{stem}/sshd-effective.txt：讀不出任何設定")
    if t("accounts.txt") is not None:
        out += parse_accounts(t("accounts.txt"), stem, notes)
    if t("sysctl.txt") is not None:
        out += parse_sysctl(t("sysctl.txt"), stem)
    if t("firewall.txt") is not None:
        fw = firewall_state(t("firewall.txt"))
        info["firewall"] = f"IPv4 {fw['ipv4']}, IPv6 {fw['ipv6']}"
        if fw["format"] == "unknown":
            notes.append(f"{stem}/firewall.txt：格式看不懂，看不出有沒有過濾進來的流量")
        else:
            gone = [x for x in ("ipv4", "ipv6") if fw[x] == "none"]
            fid = "board:firewall-none" if len(gone) == 2 else f"board:firewall-{gone[0]}-none" if gone else None
            if fid:
                what = "IPv4 and IPv6" if len(gone) == 2 else {"ipv4": "IPv4", "ipv6": "IPv6"}[gone[0]]
                out.append(finding(fid, "board", "firewall", "medium", f"No firewall filtering of incoming {what} traffic",
                                   f"No packet filter drops or rejects incoming {what} traffic (no nf_tables/ip_tables rules, or the "
                                   "input policy is accept with only accept/jump rules or loopback rules). Every listening service is "
                                   "reachable from the network" + (" over " + what if len(gone) == 1 else "") + ".",
                                   ("I-2b", "I-2d", "I-2h"), [f"{stem}/firewall.txt: {info['firewall']}"],
                                   "Run `sudo nft list ruleset`, `sudo iptables -S` and `sudo ip6tables -S` on the board.",
                                   "Add a default-deny input policy that allows only the ports the product needs, or record why "
                                   "the product relies on not running unneeded services instead."))
    for fn, fid, title, sev, annex, act in (
            ("setuid.txt", "board:setuid-nonstandard", "setuid/setgid programs outside the system directories", "medium", ("I-2d", "I-2k"),
             "Remove the setuid/setgid bit unless it is needed; record why it is needed."),
            ("world-writable.txt", "board:world-writable-dirs", "World-writable directories without the sticky bit", "medium",
             ("I-2d", "I-2k"), "Remove write access for others or set the sticky bit.")):
        if t(fn) is None:
            continue
        paths = parse_paths(t(fn), stem, fn, notes)
        if fn == "setuid.txt":
            paths = [p for p in paths if not p.startswith(SYS_DIRS)]
        if paths:
            out.append(finding(fid, "board", fn[:-4], sev, title, f"{len(paths)} path(s): {', '.join(paths[:10])}"
                               + (", …" if len(paths) > 10 else "") + ".", annex, [f"{stem}/{fn}: {p}" for p in paths],
                               f"Check the listed paths on the board (`ls -ld`).", act))
    if t("auto-updates.txt") is not None:
        out += parse_auto_updates(t("auto-updates.txt"), stem)
    if t("services-enabled.txt") is not None:
        out += parse_services(t("services-enabled.txt"), stem)
    if t("firmware.txt") is not None:
        info["firmware"] = parse_firmware(t("firmware.txt"), notes, stem)
    for fn, check, key, parser in (("integrity.txt", "integrity", "integrity", parse_integrity),
                                   ("update-channel.txt", "update-channel", "update_channel", parse_update_channel),
                                   ("logging.txt", "logging", "logging", parse_logging)):
        if t(fn) is not None:
            f, i = parser(t(fn), stem, notes)
            out += f
            info[key] = i
        elif checks.get(check) == "OK" and fn not in files:
            notes.append(f"{stem}：summary.txt 寫 {check} OK，{fn} 卻不在：匯入時被略過或被刪掉，沒有檢查")
    if "runtime-files.txt" in files or "runtime-modules.txt" in files:
        info["runtime"] = parse_runtime(files, stem, notes, when)
    if t("lynis-report.dat") is not None:
        f, i = parse_lynis(t("lynis-report.dat"), stem)
        out += f
        info.update(i)
    return out, info, checks


def merge(findings):
    """同一個 id 合併成一筆：嚴重度取最高、證據合併（不重複）。"""
    by = {}
    for f in findings:
        g = by.get(f["id"])
        if g is None:
            by[f["id"]] = dict(f, evidence=list(f["evidence"]))
            continue
        if SEV_ORDER[f["severity"]] < SEV_ORDER[g["severity"]]:
            g.update({k: f[k] for k in ("severity", "title", "text")})
        for e in f["evidence"]:
            if e not in g["evidence"]:
                g["evidence"].append(e)
        g["evidence_total"] = max(g["evidence_total"], len(g["evidence"]))
        g["annex"] = sorted(set(g["annex"]) | set(f["annex"]))
    return sorted(by.values(), key=lambda f: (SEV_ORDER[f["severity"]], f["id"]))


def rebuild(bd, limits=LIMITS):
    """讀 board-test/ 底下所有已匯入的結果，寫 board-test.json。回傳 (狀態, 說明, 文件)。"""
    runs, notes = [], []
    names = sorted(os.listdir(bd)) if os.path.isdir(bd) else []
    for n in names:
        p = bd / n
        if n.startswith("."):
            continue
        if n == "board-test.json" and not os.path.islink(p) and os.path.isfile(p):
            continue
        if n in RESERVED:
            notes.append(f"board-test/{n}：保留的名稱卻不是預期的檔案，略過（請刪掉）")
            continue
        if not STEM_RE.match(n) or os.path.islink(p) or not p.is_dir():
            notes.append(f"board-test/{shown(n, 80)}：不是匯入的結果資料夾，略過")
            continue
        meta = read_meta(p)
        if meta is None:
            notes.append(f"board-test/{n}：沒有 {IMPORT_META}（不是用 board-import 匯入的），略過")
            continue
        files, fnotes = read_run_files(p, limits)
        kind = kind_of(n, files)
        if kind is None:
            notes.append(f"board-test/{n}：看不出是板子上還是網路的檢查，略過")
            continue
        m = TIME_RE.search(n)
        when = (datetime.datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").strftime("%Y-%m-%dT%H:%M:%SZ") if m else None)
        target = n[:m.start()] if m else n
        for pre in ("board-test-", "board-net-"):
            if target.startswith(pre):
                target = target[len(pre):]
        runs.append({"stem": n, "kind": kind, "target": target, "time": when or str(meta.get("imported") or "")[:40],
                     "time_source": "name" if when else "import", "archive": meta.get("archive"), "imported": meta.get("imported"),
                     "import_notes": [str(x)[:200] for x in meta.get("skipped") or []][:50],
                     "files": [{"path": f"board-test/{n}/{fn}", "size": len(d), "sha256": hashlib.sha256(d).hexdigest()}
                               for fn, d in sorted(files.items())],
                     "_files": files, "_notes": fnotes})
    # 同一種檢查、同一個對象只用最新的一次。名稱裡沒有 UTC 時間的只有匯入時間（不是測試時間）：永遠排在有時間的後面
    def rank(r):
        return (r["time_source"] == "name", r["time"] or "")
    latest = {}
    for r in runs:
        k = (r["kind"], r["target"])
        if k not in latest or rank(r) > rank(latest[k]):
            latest[k] = r
    findings = []
    for r in runs:
        r["current"] = latest[(r["kind"], r["target"])] is r
        rn = list(r.pop("_notes"))
        files = r.pop("_files")
        if r["import_notes"]:
            rn.append(f"{r['stem']}：匯入時略過 {len(r['import_notes'])} 個成員（見 {r['stem']}/{IMPORT_META} 的 skipped）")
        if r["time_source"] != "name":
            rn.append(f"{r['stem']}：名稱沒有 UTC 時間（board-…-YYYYmmddTHHMMSSZ），用匯入時間排序；有時間的結果優先")
        if r["current"]:
            f, info, checks = parse_run(r["stem"], r["kind"], files, rn, r["time"])
            findings += f
            r["info"], r["checks"] = info, checks
        else:
            r["superseded_by"] = latest[(r["kind"], r["target"])]["stem"]
        r["notes"] = rn
        notes += rn if r["current"] else []
    findings = merge(findings)
    cur = [r for r in runs if r["current"]]
    n = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    kinds = {r["kind"] for r in cur}
    if not cur:
        st = "NOT_RUN"
    elif n["high"] or n["medium"] or notes:
        st = "ATTENTION"
    else:
        st = "OK"
    summ = (f"on-device: {sum(1 for r in cur if r['kind'] == 'board')} run(s), network: {sum(1 for r in cur if r['kind'] == 'network')} run(s); "
            f"to review: high {n['high']}, medium {n['medium']}, low {n['low']}")
    doc = {"schema": SCHEMA, "tool_version": TOOL_VERSION, "generated": now_utc(), "status": st, "summary": summ,
           "kinds": sorted(kinds), "runs": runs, "findings": findings, "notes": notes[:200]}
    if os.path.lexists(bd / "board-test.json") and (os.path.islink(bd / "board-test.json") or not os.path.isfile(bd / "board-test.json")):
        raise ImportError_(f"{bd / 'board-test.json'} 不是一般檔案（資料夾或連結），不覆寫；請刪掉後重跑")
    tmp = tempfile.NamedTemporaryFile("w", dir=bd, prefix=".board-test.", suffix=".json", delete=False, encoding="utf-8")
    try:
        with tmp:
            json.dump(doc, tmp, ensure_ascii=False, indent=1)
            tmp.write("\n")
        os.chmod(tmp.name, 0o600)
        os.replace(tmp.name, bd / "board-test.json")
    except BaseException:
        Path(tmp.name).unlink(missing_ok=True)
        raise
    detail = (f"板子上 {sum(1 for r in cur if r['kind'] == 'board')} 次、網路 {sum(1 for r in cur if r['kind'] == 'network')} 次"
              f"（另有 {len(runs) - len(cur)} 次較舊的不用）；待檢視 high {n['high']}、medium {n['medium']}、low {n['low']}"
              + (f"；注意 {len(notes)} 項（見 board-test.json 的 notes）" if notes else ""))
    return st, detail, doc


def run(result, archives, replace=False, limits=LIMITS):
    """回傳 (狀態, 說明)。"""
    bd = board_dir(result, create=True)
    msgs, rejected = [], 0
    for a in archives:
        stem = stem_of(a)
        if stem is None or not STEM_RE.match(stem) or stem in RESERVED or stem.endswith(".json"):
            msgs.append(f"{Path(a).name}：檔名要是 <名稱>.tar.gz（英數字與 ._-，不能是 {'、'.join(sorted(RESERVED))} 或 .json 結尾），不收")
            rejected += 1
            continue
        try:
            files, notes, info = read_archive(a, stem, limits)
        except OSError as e:
            msgs.append(f"{Path(a).name}：讀不到（{type(e).__name__}）")
            rejected += 1
            continue
        kind = kind_of(stem, files) if files else None
        if files and kind is None:
            notes.append("看不出是 board-on-device.sh 還是 board-from-network.sh 的結果，整個不收")
            files = {}
        if not files:
            msgs.append(f"{Path(a).name}：不收（{'；'.join(notes[-3:])}）")
            rejected += 1
            continue
        meta = {"archive": info, "imported": now_utc(), "kind": kind, "tool_version": TOOL_VERSION, "skipped": notes[:100]}
        r, why = write_run(bd, stem, files, meta, replace)
        msgs.append(f"{Path(a).name}：{why}" + (f"（{len(files)} 個檔案，略過 {len(notes)} 個成員）" if r == "ok" else "")
                    + (f"：{'；'.join(notes[:3])}" if notes and r == "ok" else ""))
        # 有略過的成員、或同名但內容不同而沒有匯入：ATTENTION（同一個壓縮檔重匯是沒有變更，不算）
        if (notes and r == "ok") or r == "conflict":
            rejected += 1
    st, detail, _ = rebuild(bd, limits)
    if rejected and st == "OK":
        st = "ATTENTION"
    return st, "；".join(msgs + [detail])


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"參數錯誤：{message}", file=sys.stderr)
        sys.exit(64)


# ---------- 核心模組清單（kernel-modules.json，K2 的輸入） ----------

KMOD_OPTS = ("kernel_modules_prefix", "kernel_version", "image_sha256", "lsmod", "owner", "captured")
UNAME_RE = re.compile(r"^Linux\s+\S+\s+([A-Za-z0-9._+~-]{1,128})\s")


def kernel_modules_lib():
    return _load_sibling("sca_center_kernel_modules", "kernel_modules.py")


def _load_sibling(name, fn):
    """python3 -I 不把這個資料夾放進 sys.path：依路徑載入同一份程式。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent / fn)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def board_module_runs(bd, km):
    """已匯入、最新（current）的板子結果 → [{"stem", "kernel", "loaded", "bad", "modules_disabled"}]（kernel_modules.board_inputs 用）。
    最新的判斷沿用 rebuild 剛寫的 board-test.json。"""
    try:
        fd = os.open(bd / "board-test.json", os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            doc = json.loads(f.read(64 << 20).decode("utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for r in doc.get("runs") or []:
        if not isinstance(r, dict) or r.get("kind") != "board" or not r.get("current") or not STEM_RE.match(str(r.get("stem"))):
            continue
        files, _ = read_run_files(bd / r["stem"])
        kern = None
        for ln in (text_of(files.get("os.txt")) or "").splitlines():
            m = UNAME_RE.match(ln[:300] + " ")
            if m:
                kern = m.group(1)
        loaded, bad = km.parse_lsmod(text_of(files.get("lsmod.txt")) or "") if "lsmod.txt" in files else (None, 0)
        md = None
        for ln in (text_of(files.get("sysctl.txt")) or "").splitlines():
            k, sep, v = ln.partition(" = ")
            if sep and k.strip() == "kernel.modules_disabled" and v.strip() in ("0", "1"):
                md = v.strip() == "1"
        out.append({"stem": r["stem"], "kernel": kern, "loaded": loaded or None, "bad": bad, "modules_disabled": md})
    return out


def run_kernel_modules(result, a):
    """→ (狀態, 說明)。"""
    km = kernel_modules_lib()
    result = Path(result)
    loaded = loaded_from = None
    notes = []
    if a.lsmod:
        loaded, loaded_from, notes = km.read_lsmod_file(a.lsmod)
    board = board_module_runs(board_dir(result, create=False), km) if not a.lsmod else None
    out = result / "cra-project" / "CRA" / "Config" / "kernel-modules.json"
    try:
        return km.generate(out, a.kernel_modules_from, a.kernel_modules_prefix, a.kernel_version, a.owner, a.captured,
                           scan=None if a.image_sha256 else result / "scan", image_sha256=a.image_sha256, loaded=loaded,
                           loaded_from=loaded_from, accept_unread_initramfs=a.accept_unread_initramfs, replace=a.replace,
                           input_notes=notes, board=board, base=result)
    except km.InputError as e:
        return "FAIL", str(e)


def main(argv=None):
    ap = Parser(description="匯入板子安全檢查的結果（board-on-device.sh、board-from-network.sh 的 .tar.gz），寫 board-test.json；"
                            "給 --kernel-modules-from 時另寫 CRA/Config/kernel-modules.json（K2 的輸入）")
    ap.add_argument("--result", required=True, help="scan-flash-package 結果資料夾裡的 <rootfs> 資料夾")
    ap.add_argument("--replace", action="store_true", help="同名的結果（或內容不同的 kernel-modules.json）已經有了時取代")
    ap.add_argument("--version", action="version", version=f"{SCHEMA} {TOOL_VERSION}")
    ap.add_argument("--kernel-modules-from", help="映像的 rootfs：資料夾、rootfs tar 或刷機包 tbz2（配 --kernel-modules-prefix）")
    ap.add_argument("--kernel-modules-prefix", help="rootfs 在刷機包裡的路徑，例如 Linux_for_Tegra/rootfs_no_gui")
    ap.add_argument("--kernel-version", help="/usr/lib/modules/<版本>/；映像只有一個時可以不給")
    ap.add_argument("--image-sha256", help="掃描的映像雜湊；預設取自 <rootfs>/scan/meta.json（給了也要是其中一個）")
    ap.add_argument("--lsmod", help="板子的 lsmod 輸出；預設取自已匯入的板子結果的 lsmod.txt")
    ap.add_argument("--owner", help="kernel-modules.json 的負責人（必填，不能是佔位字）")
    ap.add_argument("--captured", help="YYYY-MM-DD；預設今天（UTC）")
    ap.add_argument("--accept-unread-initramfs", action="store_true", help="initramfs 讀不了時照寫（限制寫進 source）；預設 GAP")
    ap.add_argument("archives", nargs="*", help="board-test-*.tar.gz、board-net-*.tar.gz；不給時只重寫 board-test.json")
    a = ap.parse_args(argv)
    if not a.kernel_modules_from and (any(getattr(a, k) for k in KMOD_OPTS) or a.accept_unread_initramfs):
        ap.error("--kernel-modules-prefix、--kernel-version、--image-sha256、--lsmod、--owner、--captured、--accept-unread-initramfs "
                 "要和 --kernel-modules-from 一起用")
    if a.kernel_modules_from and not a.owner:
        ap.error("--kernel-modules-from 要給 --owner（kernel-modules.json 的負責人）")
    os.umask(0o077)
    try:
        st, detail = run(a.result, a.archives, a.replace)
    except (ImportError_, OSError) as e:
        print(f"D-board-test\tFAIL\t{e}")
        return 1
    print(f"D-board-test\t{st}\t{detail}")
    sts = [st]
    if a.kernel_modules_from:
        try:
            kst, kd = run_kernel_modules(a.result, a)
        except (ImportError_, OSError) as e:
            kst, kd = "FAIL", f"{type(e).__name__}: {e}"
        except Exception as e:          # 載入 kernel_config.py 失敗（Python 版本）等：不印 traceback
            kst, kd = "FAIL", f"{type(e).__name__}: {str(e)[:300]}"
        print(f"D-kernel-modules\t{kst}\t" + re.sub(r"[\t\r\n]+", " ", str(kd))[:1500])
        sts.append(kst)
    return 1 if "FAIL" in sts else 0 if all(s == "OK" for s in sts) else 2


if __name__ == "__main__":
    sys.exit(main())
