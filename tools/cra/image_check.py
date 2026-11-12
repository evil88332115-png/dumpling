#!/usr/bin/env python3
"""image_check.py：根檔案系統映像的靜態安全檢查（不需要板子），給 CRA 技術文件當安全測試的證據
（Annex I Part I (2)(b)(d)(j)(k)、Part II (3)、Annex VII 6）。

用法：
  python3 -I image_check.py --from <rootfs tar｜刷機包 tbz2｜rootfs 資料夾> [--prefix <rootfs 在刷機包裡的路徑>] --out <資料夾>

寫出 --out/image-check.json 與 image-check.md（英文，給技術文件），印一行：D-image-check<TAB>狀態<TAB>說明
（OK；有 high／medium 的待檢視項目或檢查不完整 → ATTENTION；不像 rootfs → GAP；讀取失敗或檢查出錯 → FAIL）。

檢查（每項標 Annex I 的對應、嚴重度、證據路徑）：
  1. 開機啟動的服務：systemd 的 *.wants／*.requires 連結、預設 target 往下展開、socket／timer、SysV 的 rcN.d、inetd；
     常見的網路服務（LISTENERS 表）另外標出。systemd preset：/etc/machine-id 空的（第一次開機）時 preset 會啟用的 unit
     算開機啟動（machine-id 不存在或是 uninitialized；空檔案不算）；其他情況另列「第一次開機會被打開」（low）。
  2. sshd 設定：sshd_config 與 Include（第一個值有效、Match 區塊另列）、預設值；映像裡的 SSH 主機私鑰（每台板子相同）。
  3. 帳號：passwd／shadow 推導出的狀態（空密碼、鎖定、已設定、雜湊種類）、root 以外的 uid 0、sudoers 的 NOPASSWD。
  4. setuid／setgid、所有人可寫的檔案與沒有 sticky 的資料夾。
  5. 映像裡的私鑰與帳密：PEM／OpenSSH 私鑰、AWS 樣式的金鑰 ID、.netrc 等；只寫路徑與種類。
  6. ELF 強化：PIE、NX、RELRO、stack canary（自己解析 ELF）；不屬於任何 dpkg 套件的檔案先列。
  7. 腳本裡的核心模組名稱：映像裡沒有的模組名稱（打錯字）→ 檢查永遠「沒載入」、blacklist 擋不到東西。
     模組清單：/lib/modules/<版本>/ 與 /usr/lib/modules/<版本>/（兩個各自存在時合在一起）的 *.ko（含 .xz／.zst／.gz）檔名、
     modules.dep、modules.order、modules.builtin、modules.alias（- 與 _ 視為相同，和核心一樣）；映像其他地方的 *.ko 也算存在。
     .ko 要是 ELF ET_REL 才算模組（vim 的 tutor.ko 不算；zstd 等判斷不了的照樣算，偏保守）；modprobe.d 的 alias 名稱對 modprobe 有效。
     沒有任何模組清單 → 不執行（NOT RUN；有引用時記不完整），不標任何項目。只認明確的寫法：grep 讀 /proc/modules 或接在 lsmod
     後面（樣式要是乾淨的名稱，可加 ^、結尾空白等錨點；雙引號裡的 $(…)、`…` 也看）、modprobe [-r]、rmmod、insmod …/NAME.ko、
     sudo／env／timeout／nice 前綴、同檔案裡讀 /proc/modules 的函式的呼叫（引數代進函式裡 grep 的那一行，真的是 grep 才算）、
     modprobe.d 的 blacklist／install NAME /bin/false、modules-load.d 與 /etc/modules 的名稱。註解、echo 的字串、heredoc 的內容
     （只認引號外的 <<；找不到結尾就不跳）、變數不算；不支援的寫法列在 method。範圍：etc、usr/local/bin、usr/local/sbin、usr/bin、
     usr/sbin、bin、sbin、opt、systemd 的資料夾、modprobe.d、modules-load.d 底下的 shell 腳本（shebang 或 .sh）、systemd unit 的
     Exec*= 與上述設定檔。只看第一個 NUL 之前（自解壓檔）；沒有 NUL 又超過單檔上限 → 記不完整，不默默略過。引用總數有上限
     （硬連結的名稱也算）。
     有相近的現有名稱（多半打錯字）：腳本不屬於套件（或來源不明）→ medium、套件的 → low；modprobe.d 不屬於套件 → medium（緩解措施
     擋不到真正的模組）、套件的 → info。沒有相近的名稱（這個核心沒有這個模組，可能沒編進核心；檢查不會有作用但也沒有風險）：
     腳本 low、套件腳本 info、modprobe.d info。
     只輸出路徑、行號、名稱與最接近的現有名稱（difflib，最多 3 個），不輸出檔案內容。
  看不到的（核心強化、實際監聽的埠、第一次開機才產生的金鑰與帳號）列在報告的「needs board test」，不推測。

映像是不可信資料：tar 只用串流讀（tools/demo/flash_package.py 的讀法），不解開到磁碟；符號連結只在記憶體裡的映像
命名空間解析（有跳躍上限），不碰主機的檔案；資料夾來源用 lstat 走訪、O_NOFOLLOW 打開；不執行映像裡的任何東西；
每個檔案與總量都有上限。輸出絕不包含密碼雜湊、私鑰內容或任何帳密的值：只有推導出的狀態、種類、路徑與行號。
"""
import argparse
import base64
import collections
import contextlib
import datetime
import difflib
import fnmatch
import importlib.util
import json
import lzma
import os
import re
import shlex
import stat
import struct
import sys
import tarfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = "sca-center-image-check/1"
TOOL_VERSION = "2026-11-08.3"     # 檢查的內容改了就更新：scan-flash-package.sh --rescan-from 只沿用同一版的結果

# ---------- 上限（測試會調小） ----------
MAX_ENTRIES = 3_000_000       # 映像裡的項目數
TEXT_MAX = 1 << 20            # 留在記憶體的設定檔：單檔
TEXT_LIST_MAX = 16 << 20      # dpkg 清單：單檔（kernel headers 的清單超過 1 MiB）
SNIFF = 8192                  # 超過上限的檔案：看開頭多少判斷是不是二進位檔
# 只認 /usr 底下套件的測試資料（還要屬於某個套件，見 check_secrets）；/opt、/etc、/home、/srv、/var 底下的一律算真的私鑰。
# /etc/ssl/private/ssl-cert-snakeoil.key 不算：它是安裝時產生、可能被服務（網頁、郵件）拿來用的真金鑰，每台一樣是真的風險
TEST_KEY_RE = re.compile(r"^/usr/(?:libexec|lib|share)/(?:[^/]+/)*(?:installed-tests|tests?|test-data)/|^/usr/share/(?:[^/]+/)*[^/]*snakeoil[^/]*$", re.I)
# wpa_supplicant 原始碼範例檔的網路名稱（全部都是這些才算範例檔；有任何一個別的名稱就是真的設定）
WPA_EXAMPLE_SSIDS = {b"simple", b"second ssid", b"example", b"eap-sim-test", b"eap-psk-test", b"1x-test", b"leap-example",
                     b"ikev2-example", b"eap-fast-test", b"plaintext-test", b"static-wep-test", b"static-wep-test2", b"test adhoc",
                     b"00010203"}
TEXT_TOTAL = 256 << 20        # 留在記憶體的設定檔與 dpkg 清單：總量
SECRET_MAX = 1 << 20          # 掃描私鑰與帳密：單檔
SECRET_TOTAL = 1 << 30        # 掃描私鑰與帳密：總量
SECRET_ELF_MAX = 512 << 20    # ELF 裡嵌入的私鑰：單檔掃描的上限（串流本來就要讀過）
SECRET_ELF_TOTAL = 16 << 30   # ELF 裡嵌入的私鑰：總量
SECRET_LARGE_MAX = 64 << 20   # 超過 SECRET_MAX 的非 ELF 檔案（資料、媒體、靜態庫）：單檔分段掃的上限
SECRET_LARGE_TOTAL = 2 << 30  # 同上：總量（不跟 ELF 共用，不會吃掉 ELF 的額度）
ELF_MAX_FILES = 200_000       # 檢查 ELF 的檔案數
ELF_RETAIN = 16 << 20         # 串流讀 ELF 時保留的開頭（.dynstr 通常在這裡）
ELF_PH_MAX = 1 << 16          # program header 表
ELF_DYN_MAX = 1 << 20         # PT_DYNAMIC
MAX_HOPS = 40                 # 解析一個路徑最多跟幾次符號連結
LINK_MAX = 4096               # 符號連結目標的長度
PATH_MAX = 4096               # 成員名稱的長度與層數（PATH_MAX；超過的拒絕，避免很深的名稱塞滿記憶體）
DEPTH_MAX = 256
INCLUDE_DEPTH = 8             # sshd_config 的 Include 層數
GLOB_MAX = 256                # Include 一個樣式最多展開幾個
INCLUDE_WORK = 200_000        # sshd_config 的 Include：樣式數＋看過的名稱數的總量（超過就停，記不完整）
LIST_MAX = 200                # 報告每種清單最多列幾筆（數量另計）
SCRIPT_MAX = 1 << 20          # 找模組名稱的腳本與設定檔：單檔（超過的自解壓檔只看第一個 NUL 之前的腳本部分）
SCRIPT_TOTAL = 128 << 20      # 同上：總量
MODREF_MAX = 50_000           # 模組名稱的引用：總數

ANNEX = {"I-2b": "Annex I Part I (2)(b) secure by default configuration",
         "I-2d": "Annex I Part I (2)(d) protection from unauthorised access",
         "I-2e": "Annex I Part I (2)(e) confidentiality of stored data",
         "I-2j": "Annex I Part I (2)(j) limit attack surfaces",
         "I-2k": "Annex I Part I (2)(k) exploitation mitigation"}
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# 常見的網路服務：unit 名稱（去掉 .service 等與 @…）或 ExecStart 的程式名稱 → (標籤, 說明, 嚴重度)
# 只是提示「這個服務會對外」，實際監聽的位址與埠要在板子上確認（ss -tulpn）。
LISTENERS = [
    (("ssh", "sshd", "dropbear"), "ssh", "SSH server (TCP 22)", "medium"),
    (("smbd", "nmbd", "samba", "samba-ad-dc", "winbind"), "samba", "Samba / SMB file sharing (TCP 139/445, UDP 137/138)", "medium"),
    (("isc-dhcp-server", "isc-dhcp-server6", "dhcpd", "kea-dhcp4-server", "kea-dhcp6-server", "udhcpd", "dnsmasq"), "dhcp",
     "DHCP / DNS server (UDP 67, 53)", "medium"),
    (("avahi-daemon",), "avahi", "mDNS / DNS-SD (UDP 5353)", "medium"),
    (("cups", "cupsd", "cups-browsed"), "cups", "printing service (TCP 631)", "medium"),
    (("xrdp", "xrdp-sesman"), "rdp", "RDP remote desktop (TCP 3389)", "medium"),
    (("vncserver", "x11vnc", "vino-server", "tigervnc", "tigervncserver", "wayvnc"), "vnc", "VNC remote desktop (TCP 5900+)", "medium"),
    (("nfs-server", "nfs-kernel-server", "rpcbind", "rpc-statd", "nfs-mountd", "rpc.mountd"), "nfs", "NFS / RPC (TCP/UDP 111, 2049)", "medium"),
    (("telnet", "telnetd", "in.telnetd", "inetd", "openbsd-inetd", "inetutils-inetd", "xinetd", "rsh", "rlogin", "rexec"),
     "telnet-inetd", "telnet / r-services / inetd super-server (cleartext)", "high"),
    (("vsftpd", "proftpd", "pure-ftpd", "tftpd-hpa", "atftpd", "in.tftpd", "ftpd"), "ftp", "FTP / TFTP server (cleartext)", "high"),
    (("snmpd",), "snmp", "SNMP agent (UDP 161)", "medium"),
    (("mosquitto",), "mqtt", "MQTT broker (TCP 1883)", "medium"),
    (("apache2", "httpd", "nginx", "lighttpd"), "web", "web server (TCP 80/443)", "medium"),
    (("docker", "dockerd", "containerd"), "container", "container engine (root-equivalent API socket)", "medium"),
    (("rsync",), "rsync", "rsync daemon (TCP 873)", "medium"),
    (("cockpit",), "cockpit", "Cockpit web console (TCP 9090)", "medium"),
    (("mysql", "mysqld", "mariadb", "postgresql", "redis-server", "mongod"), "database", "database server", "medium"),
    (("ntp", "ntpd", "ntpsec"), "ntp", "NTP server (UDP 123)", "low"),
    (("bluetooth", "bluetoothd"), "bluetooth", "Bluetooth stack (radio interface)", "low"),
    # 測試與除錯工具：出貨映像不該開著（iperf3 會讓任何人灌流量；gdbserver 可遠端控制程式）
    (("iperf3", "iperf"), "iperf", "network performance test server (TCP 5201 / 5001)", "medium"),
    (("gdbserver",), "gdbserver", "remote debugger (gdbserver)", "high"),
]
# 清單裡沒有的服務：ExecStart 帶 --listen／--bind（含 -address、-addr、-port、-host）的也當成可能對外的服務
# （例如廠商程式 --listen 0.0.0.0:8080）。--server 不算：很多是用戶端參數（puppet agent --server host、--server=https://…）
SERVER_FLAG = re.compile(r"""(?:^|[\s"'])--(?:listen|bind)(?:-(?:address|addr|port|host))?(?=[=\s"']|$)""")
LISTENER_BY_NAME = {n: (tag, desc, sev) for names, tag, desc, sev in LISTENERS for n in names}
INETD_CLEARTEXT = {"telnet", "ftp", "tftp", "shell", "login", "exec", "rsh", "rlogin", "rexec"}

UNIT_DIRS = ("etc/systemd/system", "usr/local/lib/systemd/system", "usr/lib/systemd/system", "lib/systemd/system")
PRESET_DIRS = ("etc/systemd/system-preset", "usr/local/lib/systemd/system-preset", "usr/lib/systemd/system-preset",
               "lib/systemd/system-preset")
NOT_AT_BOOT = ("masked", "enabled, not", "not started")    # 服務狀態的開頭：這些不會在開機時啟動
BOOT_SEED = ("sysinit.target", "basic.target", "sockets.target", "timers.target", "paths.target")
NOLOGIN = {"/bin/false", "/usr/bin/false", "/sbin/nologin", "/usr/sbin/nologin", "/bin/sync", "/usr/bin/sync",
           "/sbin/shutdown", "/usr/sbin/shutdown", "/sbin/halt", "/usr/sbin/halt"}
TMP_DIRS = ("tmp", "var/tmp", "dev/shm", "run/lock", "var/lock", "var/crash", "var/spool/cron/crontabs")

ELF_DIRS = ("usr/bin", "usr/sbin", "bin", "sbin", "usr/lib", "lib", "lib64", "usr/lib64", "usr/libexec", "opt", "usr/local")
ELF_SKIP = ("usr/lib/debug", "usr/lib/firmware", "lib/firmware", "usr/lib/modules", "lib/modules", "usr/src")
VENDOR_DIRS = ("opt/", "usr/local/", "home/", "root/", "srv/")
SECRET_DIRS = ("etc/", "root/", "home/", "opt/", "usr/local/", "srv/", "var/lib/", "var/opt/")
SECRET_SKIP = ("var/lib/dpkg/", "var/lib/apt/", "usr/share/doc/", "etc/ssl/certs/")
SECRET_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", ".netrc", "_netrc",
                ".git-credentials", ".pgpass", "credentials", "config.json"}
TEXT_PREFIX = ("etc/", "usr/lib/systemd/system/", "lib/systemd/system/", "usr/local/lib/systemd/system/",
               "usr/lib/systemd/system-preset/", "lib/systemd/system-preset/", "usr/local/lib/systemd/system-preset/")

PEM_RE = re.compile(rb"-----BEGIN ((?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----")
AWS_RE = re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")
# 核心模組（檢查 7）
MOD_BASES = ("lib/modules", "usr/lib/modules")
MOD_LIST_RE = re.compile(r"^(?:usr/)?lib/modules/([^/]+)/(modules\.(?:dep|order|builtin|alias|builtin\.alias))$")
KO_RE = re.compile(r"(?:^|/)([^/]+?)\.ko(?:\.(?:xz|zst|gz))?$")
SCRIPT_DIRS = ("etc", "usr/local/bin", "usr/local/sbin", "usr/bin", "usr/sbin", "bin", "sbin", "opt", "lib/systemd", "usr/lib/systemd",
               "usr/local/lib/systemd", "lib/modprobe.d", "usr/lib/modprobe.d", "lib/modules-load.d", "usr/lib/modules-load.d")
MODPROBE_CONF_RE = re.compile(r"^(?:(?:etc|run|lib|usr/lib|usr/local/lib)/modprobe\.d/[^/]+\.conf|etc/modprobe\.conf)$")
MODLOAD_CONF_RE = re.compile(r"^(?:(?:etc|run|lib|usr/lib|usr/local/lib)/modules-load\.d/[^/]+\.conf|etc/modules)$")
UNIT_FILE_RE = re.compile(r"^(?:etc|run|lib|usr/lib|usr/local/lib)/systemd/system/(?:[^/]+\.service|[^/]+\.service\.d/[^/]+\.conf)$")
MOD_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
MOD_TRIGGERS = (b"modprobe", b"rmmod", b"insmod", b"lsmod", b"/proc/modules")
SHELLS = {"sh", "bash", "dash", "ash", "ksh", "mksh", "zsh", "busybox"}
CMD_PREFIX = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time", "exec", "command", "nohup", "builtin", "sudo",
              "env", "doas"}
MOD_CTX = {"proc-modules": "grep of /proc/modules", "lsmod": "lsmod | grep", "modprobe": "modprobe", "modprobe-r": "modprobe -r",
           "rmmod": "rmmod", "insmod": "insmod", "function": "call of a function that reads /proc/modules",
           "modules-load": "modules-load list", "blacklist": "modprobe.d blacklist", "install": "modprobe.d install (disabled)"}
MOD_ALIAS_OK = {"modprobe", "modprobe-r", "modules-load"}     # modprobe 會解析 alias；/proc/modules 與 lsmod 只有真正的名稱
EM = {3: "x86", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm", 62: "x86-64", 183: "aarch64", 243: "riscv"}


class Fail(Exception):
    pass


def flash_package():
    spec = importlib.util.spec_from_file_location("sca_center_flash_package", ROOT / "tools" / "demo" / "flash_package.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def clean(s, limit=300):
    """映像裡的名稱是不可信的：去掉控制字元與無法編碼的字元，限制長度（輸出到 JSON、Markdown、status.tsv 都安全）。"""
    s = str(s).encode("utf-8", "backslashreplace").decode("utf-8")
    s = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in s)
    return s if len(s) <= limit else s[:limit] + "…"


def under(path, dirs):
    return any(path == d or path.startswith(d + "/") for d in dirs)


# ---------- 映像的命名空間（只在記憶體裡） ----------

class Image:
    def __init__(self):
        self.nodes = {}           # 路徑 → [kind, mode, size, link, uid]（kind：file／dir／symlink／hardlink／device／fifo／other）
        self.children = collections.defaultdict(set)
        self.content = {}         # 路徑 → bytes（設定檔、unit、dpkg 清單）
        self.elf = {}             # 路徑 → ELF 檢查結果
        self.secrets = []         # {path, type, line?, note?}
        self.modrefs = {}         # 路徑 → [模組名稱的引用]：腳本與設定檔裡的模組名稱（檢查 7；硬連結共用同一份清單）
        self.modref_count = 0     # 引用的總數（硬連結的名稱也算，上限 MODREF_MAX）
        self.mod_aliases = set()  # modprobe.d 的 alias NAME module
        self.ko_kind = {}         # 名稱是 .ko* 的檔 → module／not_module／unknown（ELF ET_REL 才算核心模組）
        self.script_files = set() # 找過模組名稱的檔案
        self.hard = {}            # 硬連結：路徑 → 目標（映像裡的路徑；目標在 rootfs 外時是壓縮檔裡的名稱）
        self.done = set()         # 已經讀過內容的檔案
        self.text_total = self.secret_total = self.secret_elf_total = self.secret_large_total = self.script_total = 0
        self.cov = collections.Counter()      # 涵蓋範圍：rejected、unreadable、cap_* …
        self.examples = collections.defaultdict(list)
        self.owners_known = False  # tar 標頭的擁有者可信嗎（只有刷機包本身；flash_package.py 寫的 rootfs tar 都是 0）

    def note(self, key, example=None):
        self.cov[key] += 1
        if example is not None and len(self.examples[key]) < 10:
            self.examples[key].append(clean(example))

    def add(self, path, kind, mode, size=0, link=None, uid=None):
        if len(self.nodes) >= MAX_ENTRIES:
            raise Fail(f"映像的項目超過 {MAX_ENTRIES} 個")
        if path in self.nodes and self.nodes[path][0] == "dir" and kind == "dir":
            self.nodes[path][1] = mode
            return
        self.nodes[path] = [kind, mode, size, link, uid]
        self.content.pop(path, None)
        self.elf.pop(path, None)
        self.hard.pop(path, None)
        child = path
        while "/" in child:                       # 沒有明列的上層資料夾
            parent, name = child.rsplit("/", 1)
            self.children[parent].add(name)
            if parent in self.nodes:
                break
            self.nodes[parent] = ["dir", None, 0, None, None]
            child = parent
        else:
            self.children[""].add(child)

    def resolve(self, path, follow_last=True):
        """映像裡的路徑 → 實際的路徑（只查記憶體裡的命名空間；絕對連結從映像的根開始，.. 停在根）。
        中間層不存在、不是資料夾、跳太多次（迴圈）→ None。最後一層不存在時照樣回傳（呼叫端用 nodes 判斷）。"""
        queue = collections.deque(p for p in path.split("/") if p not in ("", "."))
        out, hops = [], 0
        while queue:
            c = queue.popleft()
            if c == "..":
                if out:
                    out.pop()
                continue
            cand = "/".join(out + [c])
            node = self.nodes.get(cand)
            if node is None:
                if queue:
                    return None
                out.append(c)
                break
            if node[0] == "symlink" and (queue or follow_last):
                hops += 1
                tgt = node[3] or ""
                if hops > MAX_HOPS or len(tgt) > LINK_MAX or not tgt:
                    return None
                if tgt.startswith("/"):
                    out = []
                queue.extendleft(reversed([p for p in tgt.split("/") if p not in ("", ".")]))
                continue
            if queue and node[0] != "dir":
                return None
            out.append(c)
        return "/".join(out)

    def lookup(self, path):
        """(實際路徑, node) 或 (None, None)。"""
        p = self.resolve(path)
        if p is None or p not in self.nodes:
            return None, None
        return p, self.nodes[p]

    def read(self, path):
        p, n = self.lookup(path)
        if n is None or n[0] not in ("file", "hardlink"):
            return None
        return self.content.get(p)

    def text(self, path):
        b = self.read(path)
        return None if b is None else b.decode("utf-8", "replace")

    def listdir(self, path):
        p, n = self.lookup(path)
        if n is None or n[0] != "dir":
            return p, []
        return p, sorted(self.children.get(p, ()))

    def glob(self, pattern, budget):
        """sshd_config 的 Include：每一層的萬用字元都在映像的命名空間裡展開。
        budget：[剩下的工作量]，每看一個名稱扣 1，用完就停；每層最多 GLOB_MAX 個（在迴圈裡就截，不先建完整的清單）。
        回傳 (路徑, 是否截斷)。"""
        parts = [p for p in pattern.split("/") if p not in ("", ".")][:DEPTH_MAX]
        cur, cut = [""], False
        for part in parts:
            nxt = []
            wild = any(ch in part for ch in "*?[")
            for base in cur:
                if budget[0] <= 0:
                    cut = True
                    break
                if not wild:
                    budget[0] -= 1
                    nxt.append(f"{base}/{part}" if base else part)
                    continue
                p, node = self.lookup(base) if base else ("", None)
                names = self.children.get(p, ()) if (not base or (node is not None and node[0] == "dir")) else ()
                budget[0] -= 1 + len(names)
                for n in names:
                    if not n.startswith(".") and fnmatch.fnmatchcase(n, part):
                        if len(nxt) >= GLOB_MAX:
                            cut = True
                            break
                        nxt.append(f"{base}/{n}" if base else n)
                if cut:
                    break
            cur = nxt
        return sorted(p for p in cur if self.lookup(p)[1] is not None), cut

    def copy_results(self, src, dst):
        """硬連結：同一份內容的檢查結果也記在另一個名稱下。"""
        if src in self.content:
            self.content[dst] = self.content[src]
        if src in self.elf:
            self.elf[dst] = dict(self.elf[src], hardlink_of="/" + clean(src))
        self.secrets += [dict(s, path=dst) for s in self.secrets if s["path"] == src]
        if src in self.script_files:
            self.script_files.add(dst)
            refs = self.modrefs.get(src)
            if refs:
                # 另一個名稱共用同一份清單（不複製、不掃整個清單）；照樣算進總數的上限
                if self.modref_count + len(refs) > MODREF_MAX:
                    self.note("cap_modrefs", dst)
                else:
                    self.modrefs[dst] = refs
                    self.modref_count += len(refs)
        if src in self.ko_kind:
            self.ko_kind[dst] = self.ko_kind[src]
        self.done.add(dst)


# ---------- 讀取來源 ----------

def iter_tar(fp, t, prefix, img):
    """(路徑, kind, mode, size, link, uid, opener)；rootfs 外的成員略過、不合法的名稱計數。"""
    n = len(prefix)
    for m in fp.members(t):
        parts = fp.split_name(m.name)
        if parts is None:
            img.note("rejected", m.name)
            continue
        if tuple(parts[:n]) != prefix or len(parts) == n:
            continue
        path = "/".join(parts[n:])
        k = fp.tar_kind(m)
        link = None
        if k == "symlink":
            link = m.linkname
        elif k == "hardlink":
            lp = fp.split_name(m.linkname)
            if lp is None:
                img.note("rejected", m.name)
                continue
            link = "/".join(lp[n:]) if tuple(lp[:n]) == prefix and len(lp) > n else "\0" + "/".join(lp)  # \0：rootfs 外
        yield path, k, m.mode & 0o7777, (m.size if k == "file" else 0), link, m.uid, (lambda m=m: t.extractfile(m))


def iter_dir(fp, src, prefix, img):
    base = os.path.abspath(src)
    for part in prefix:
        base = os.path.join(base, part)
        st = os.lstat(base)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise Fail(f"--prefix 的 {part} 是符號連結或不是資料夾（不跟隨）")
    for e in fp.dir_entries(base):
        if e.kind in ("unreadable", "unreadable_dir"):
            img.note("unreadable", "/".join(e.parts))
            continue
        yield "/".join(e.parts), e.kind, e.mode, e.size, e.link, None, e.open


def classify(path, size):
    """要讀內容的目的：text（留在記憶體）、elf、secret。"""
    want = set()
    name = path.rsplit("/", 1)[-1]
    if path.startswith(TEXT_PREFIX) or (path.startswith("var/lib/dpkg/info/") and name.endswith(".list")):
        want.add("text")
    if under(path, ELF_DIRS) and not under(path, ELF_SKIP):
        want.add("elf")
    if (path.startswith(SECRET_DIRS) or name in SECRET_NAMES or name.endswith((".pem", ".key"))) \
            and not path.startswith(SECRET_SKIP) and not path.startswith("etc/ssh/ssh_host_"):
        want.add("secret")
    if MOD_LIST_RE.match(path):
        want.add("text")
    if under(path, SCRIPT_DIRS):
        want.add("script")
    return want


def process_file(img, path, size, opener, seekable):
    want = classify(path, size)
    ko = KO_RE.search(path) is not None
    if not want and not ko:
        return
    if want:
        img.done.add(path)
    try:
        f = opener()
    except OSError as e:
        img.note("unreadable", f"{path}（{e.strerror or type(e).__name__}）")
        if ko:
            img.ko_kind[path] = "unknown"
        return
    with contextlib.closing(f):
        head = f.read(64)
        if ko:
            img.ko_kind[path] = ko_kind(f, head, consume=not want)
            if not want:
                return
        if "elf" in want and head[:4] == b"\x7fELF":
            if len(img.elf) >= ELF_MAX_FILES:
                img.note("cap_elf_files", path)
                return
            sc = None
            if "secret" in want:
                if img.secret_elf_total < SECRET_ELF_TOTAL:
                    sc = BinScan()
                else:
                    img.note("cap_secret_elf", path)          # 總量用完：沒有掃，記不完整
            rd = Reader(f, head, size, seekable, sc.feed if sc else None)
            try:
                img.elf[path] = elf_check(rd)
            except (struct.error, ValueError, IndexError, OverflowError) as e:
                img.elf[path] = {"malformed": clean(e, 120)}
            if sc:
                limit = min(SECRET_ELF_MAX, SECRET_ELF_TOTAL - img.secret_elf_total)
                if seekable:
                    f.seek(0)
                    while sc.seen < min(size, limit):
                        c = f.read(min(1 << 20, limit - sc.seen))
                        if not c:
                            break
                        sc.feed(c)
                else:
                    rd.drain(limit)
                img.secret_elf_total += sc.seen
                if sc.seen < size:
                    img.note("cap_secret_elf", path)
                img.secrets += [dict(h, path=path) for h in sc.hits]
            return
        if not want & {"text", "secret", "script"}:
            return
        if "script" in want and not want & {"text", "secret"}:
            head += f.read(256 - len(head))
            if not script_kind(path, head):           # 只為了找模組名稱：不是 shell 腳本或已知的設定檔就不讀
                return
        tmax = TEXT_LIST_MAX if path.startswith("var/lib/dpkg/info/") or MOD_LIST_RE.match(path) else TEXT_MAX
        cap = max(tmax if "text" in want else 0, SECRET_MAX if "secret" in want else 0)
        scap = SCRIPT_MAX if "script" in want else 0
        if size > max(cap, scap):
            # 二進位檔（例如 /etc 底下的測試資料）不是設定檔，讀不完不算不完整；私鑰照樣分段掃
            head += f.read(SNIFF - len(head))
            if "text" in want and not is_binary(head):
                img.note("cap_text_file", path)
            if "script" in want and script_kind(path, head):
                head += f.read(max(0, SCRIPT_MAX + 1 - len(head)))      # +1：看得出超過上限
                script_part(img, path, head)
            if "secret" in want:
                stream_secrets(img, path, f, head, size)
            return
        data = head + f.read(max(cap, scap) + 1 - len(head))
    if "script" in want:
        script_part(img, path, data)
    if "text" in want:
        if len(data) > tmax:
            img.note("cap_text_file", path)
        elif img.text_total + len(data) > TEXT_TOTAL:
            img.note("cap_text_total", path)
        else:
            img.content[path] = data
            img.text_total += len(data)
    if "secret" in want and len(data) <= SECRET_MAX:
        if img.secret_total + len(data) > SECRET_TOTAL:
            img.note("cap_secret_total", path)
        else:
            img.secret_total += len(data)
            scan_secrets(img, path, data)


def script_kind(path, head):
    """找模組名稱的檔案種類：modprobe（modprobe.d）、load（modules-load.d、/etc/modules）、unit（systemd 的 .service 與 drop-in）、
    shell（shebang 是 shell，或 .sh）；其他 → None。"""
    if MODPROBE_CONF_RE.match(path):
        return "modprobe"
    if MODLOAD_CONF_RE.match(path):
        return "load"
    if UNIT_FILE_RE.match(path):
        return "unit"
    if head.startswith(b"#!"):
        w = head[2:].split(b"\n", 1)[0].decode("utf-8", "replace").split()
        if w and os.path.basename(w[0]) == "env":
            w = [x for x in w[1:] if not x.startswith("-") and "=" not in x]
        if w and os.path.basename(w[0]) in SHELLS:
            return "shell"
        return None
    if path.endswith(".sh") and b"\0" not in head[:256]:
        return "shell"
    return None


def script_part(img, path, data):
    """找模組名稱的範圍：第一個 NUL 之前（自解壓檔：腳本後面接二進位資料；不管檔案大小都一樣切），最多 SCRIPT_MAX。
    沒有 NUL 又超過 SCRIPT_MAX → 太大的腳本，記不完整（不默默略過）。data 最多 SCRIPT_MAX + 1 個位元組就夠判斷。"""
    kind = script_kind(path, data[:256])
    if not kind:
        return
    nul = data.find(b"\0", 0, SCRIPT_MAX + 1)
    if nul >= 0:
        data = data[:nul]
    elif len(data) > SCRIPT_MAX:
        img.note("cap_script_file", path)
        return
    scan_modrefs(img, path, data, kind)


ELF_REL = 1


def ko_kind(f, head, consume):
    """名稱是 .ko* 的檔 → module（ELF ET_REL，核心只載入可重定位檔）／not_module（不是 ELF，例如 vim 的 tutor.ko；
    或 ELF 但不是 ET_REL）／unknown（判斷不了，照樣當作模組：偏保守）。只看開頭；gzip、xz 在記憶體裡只解出開頭
    （consume：這個檔沒有別的檢查要讀，可以往下讀壓縮資料）；zstd 只有 Python 3.14 的 compression.zstd 才解，否則 unknown。"""
    def elf(h):
        if not h.startswith(b"\x7fELF"):
            return "not_module" if len(h) >= 4 or not b"\x7fELF".startswith(h) else "unknown"
        if len(h) < 18 or h[5] not in (1, 2):
            return "unknown"
        return "module" if int.from_bytes(h[16:18], "little" if h[5] == 1 else "big") == ELF_REL else "not_module"
    if head[:2] == b"\x1f\x8b":
        dec = (lambda: zlib.decompressobj(31))
    elif head[:6] == b"\xfd7zXZ\x00":
        dec = (lambda: lzma.LZMADecompressor(lzma.FORMAT_XZ))
    elif head[:4] == b"\x28\xb5\x2f\xfd":
        try:
            from compression import zstd as _zstd     # Python 3.14
            dec = _zstd.ZstdDecompressor
        except ImportError:
            return "unknown"
    else:
        return elf(head)
    if not consume:
        return "unknown"
    try:
        d, buf, out, total = dec(), head, b"", len(head)
        while True:
            out += d.decompress(buf, 64 - len(out)) if buf else b""
            if len(out) >= 64 or getattr(d, "eof", False) or total >= (1 << 20):
                break
            buf = f.read(min(64 << 10, (1 << 20) - total))
            if not buf:
                break
            total += len(buf)
        return elf(out) if out else "unknown"
    except Exception:            # 壞掉的壓縮資料：判斷不了
        return "unknown"


def is_binary(head):
    """開頭有 NUL 才算二進位（隨機或壓縮的資料 8 KiB 內幾乎一定有；Latin-1 等非 UTF-8 的設定檔沒有）。"""
    return b"\0" in head


def stream_secrets(img, path, f, head, size):
    """超過 SECRET_MAX 的非 ELF 檔案：分段掃嵌入的私鑰與 AWS 金鑰 ID（自己的額度）。以前完全不掃；沒掃完的另外計數，
    不算檢查不完整（多半是資料、媒體檔）。"""
    if img.secret_large_total >= SECRET_LARGE_TOTAL:
        img.note("cap_secret_large", path)
        return
    sc = BinScan("in a large file (scanned as a stream)")
    limit = min(SECRET_LARGE_MAX, SECRET_LARGE_TOTAL - img.secret_large_total)
    sc.feed(head[:limit])
    while sc.seen < min(size, limit):
        c = f.read(min(1 << 20, limit - sc.seen))
        if not c:
            break
        sc.feed(c)
    img.secret_large_total += sc.seen
    if sc.seen < size:
        img.note("cap_secret_large", path)
    img.secrets += [dict(h, path=path) for h in sc.hits]


def load_image(src, prefix=None):
    fp = flash_package()
    pp = ()
    if prefix:
        pp = tuple(fp.split_name(prefix) or ())
        if not pp:
            raise Fail(f"--prefix 不合法：{prefix}")
    img = Image()
    pending = collections.defaultdict(list)       # rootfs 外（或還沒讀到）的硬連結目標 → 映像裡的名稱

    def feed(it, seekable):
        for path, kind, mode, size, link, uid, opener in it:
            if len(path) > PATH_MAX or path.count("/") >= DEPTH_MAX:
                img.note("rejected", path[:200])
                continue
            img.add(path, kind, mode, size, link, uid)
            if kind == "file":
                process_file(img, path, size, opener, seekable)
            elif kind == "hardlink":
                if link.startswith("\0"):
                    tgt = link[1:]
                    img.hard[path] = tgt
                    pending[tgt].append(path)
                else:
                    img.hard[path] = link
                    tn = img.nodes.get(link)
                    if tn is None or tn[0] not in ("file", "hardlink"):
                        img.note("hardlink_missing", path)
                        continue
                    img.nodes[path][2] = tn[2]
                    want = classify(path, tn[2])
                    if link in img.done and want <= classify(link, tn[2]):
                        img.copy_results(link, path)
                    elif want:
                        pending["/".join(pp + (link,))].append(path)   # 目標沒有讀需要的內容：第二次讀取

    if os.path.isdir(src):
        kind = "dir"
        feed(iter_dir(fp, src, pp, img), True)
    elif os.path.isfile(src):
        kind = "archive" if pp else "rootfs-tar"
        img.owners_known = bool(pp)
        try:
            with fp.open_stream(src) as t:
                feed(iter_tar(fp, t, pp, img), False)
                # tarfile 的串流模式遇到截斷（標頭不完整、略過內容時資料不夠）會當成正常結束：
                # 實際讀到的位置要超過最後一個標頭的位置一整個區塊（結尾的空白區塊），否則是不完整的 tar
                pos = getattr(getattr(t, "fileobj", None), "pos", None)
                if isinstance(pos, int) and pos < t.offset + tarfile.BLOCKSIZE:
                    raise Fail(f"tar 在中途結束（讀到 {pos} bytes，最後一個標頭在 {t.offset}）：檔案不完整")
            if pending:
                # 硬連結到選定 rootfs 以外的檔案（rootfs_gui 連到 rootfs_no_gui）或目標沒有讀需要的內容：再讀一次壓縮檔
                def cb(name, e):
                    names = pending.pop(name, [])
                    if not names:
                        return
                    for a in names:
                        img.nodes[a][2] = e.size
                    process_file(img, names[0], e.size, e.open, False)
                    for a in names[1:]:
                        img.copy_results(names[0], a)
                fp.fetch_members(src, sorted(pending), cb)
                for tgt, names in pending.items():
                    for a in names:
                        img.note("hardlink_missing", a)
        except fp.Fail as e:
            raise Fail(str(e))
        except (tarfile.TarError, EOFError) as e:
            raise Fail(f"tar 讀取失敗：{clean(e, 200)}")
    else:
        raise Fail(f"--from 不是檔案也不是資料夾：{src}")
    if not img.nodes:
        raise Fail("來源裡沒有任何項目" + (f"（--prefix {'/'.join(pp)}）" if pp else ""))
    return img, {"type": kind, "file": clean(os.path.basename(os.path.abspath(src))), "prefix": "/".join(pp) or None}


# ---------- ELF ----------

class Reader:
    """ELF 用的讀取：資料夾來源的檔案可以 seek；tar 成員只能往前讀，保留開頭 ELF_RETAIN bytes。讀不到 → None。"""

    def __init__(self, f, head, size, seekable, sink=None):
        self.f, self.size, self.seekable = f, size, seekable
        self.buf = bytearray(head)
        self.pos = len(head)
        self.sink = sink if not seekable else None     # 串流讀過的每一段依序交給 sink（ELF 裡的私鑰掃描）
        if self.sink:
            self.sink(head)

    def _read(self, n):
        c = self.f.read(n)
        if self.sink and c:
            self.sink(c)
        return c

    def drain(self, limit):
        """串流：把剩下的內容讀過（交給 sink），最多讀到 limit。"""
        while self.pos < min(self.size, limit):
            c = self._read(min(1 << 20, min(self.size, limit) - self.pos))
            if not c:
                break
            self.pos += len(c)

    def _fill(self, upto):
        upto = min(upto, ELF_RETAIN)
        while self.pos < upto and self.pos == len(self.buf):
            c = self._read(min(1 << 20, upto - self.pos))
            if not c:
                break
            self.buf += c
            self.pos += len(c)

    def read_at(self, off, n):
        if off < 0 or n <= 0 or off >= self.size:
            return b""
        n = min(n, self.size - off)
        if self.seekable:
            self.f.seek(off)
            return self.f.read(n)
        end = off + n
        if end <= ELF_RETAIN:
            self._fill(end)
            return bytes(self.buf[off:end])
        self._fill(ELF_RETAIN)
        if off < self.pos:
            return None
        while self.pos < off:
            c = self._read(min(1 << 20, off - self.pos))
            if not c:
                return b""
            self.pos += len(c)
        d = self._read(n)
        self.pos += len(d)
        return d


def elf_check(rd):
    """PIE／NX／RELRO／canary。格式錯誤 → ValueError（呼叫端記 malformed）。"""
    h = rd.read_at(0, 64)
    if len(h) < 52 or h[:4] != b"\x7fELF" or h[4] not in (1, 2) or h[5] not in (1, 2):
        raise ValueError("ELF header 不完整或不認得")
    is64, e = h[4] == 2, "<" if h[5] == 1 else ">"
    etype, machine = struct.unpack_from(e + "HH", h, 16)
    if is64:
        if len(h) < 64:
            raise ValueError("ELF64 header 不完整")
        phoff, = struct.unpack_from(e + "Q", h, 32)
        phentsize, phnum = struct.unpack_from(e + "HH", h, 54)
    else:
        phoff, = struct.unpack_from(e + "I", h, 28)
        phentsize, phnum = struct.unpack_from(e + "HH", h, 42)
    r = {"bits": 64 if is64 else 32, "machine": EM.get(machine, str(machine))}
    if etype not in (2, 3):
        r["kind"] = "other"
        return r
    need = 56 if is64 else 32
    if phnum == 0 or phnum == 0xFFFF or phentsize < need or phnum * phentsize > ELF_PH_MAX:
        raise ValueError(f"program header 不合理（{phnum} × {phentsize}）")
    ph = rd.read_at(phoff, phnum * phentsize)
    if ph is None or len(ph) < phnum * phentsize:
        raise ValueError("program header 超出檔案")
    loads, interp, stack, relro, dyn = [], False, None, False, None
    for i in range(phnum):
        o = i * phentsize
        if is64:
            pt, pf, off, va, _pa, fsz = struct.unpack_from(e + "IIQQQQ", ph, o)
        else:
            pt, off, va, _pa, fsz, _msz, pf = struct.unpack_from(e + "IIIIIII", ph, o)
        if pt == 1:
            loads.append((va, off, fsz))
        elif pt == 2:
            dyn = (off, fsz)
        elif pt == 3:
            interp = True
        elif pt == 0x6474E551:
            stack = bool(pf & 1)
        elif pt == 0x6474E552:
            relro = True
    flags = flags1 = 0
    bind_now = False
    strtab = strsz = None
    if dyn is not None:
        d = rd.read_at(dyn[0], min(dyn[1], ELF_DYN_MAX))
        if d is None:
            raise ValueError("PT_DYNAMIC 讀不到")
        step = 16 if is64 else 8
        fmt = e + ("qQ" if is64 else "iI")
        for o in range(0, len(d) - step + 1, step):
            tag, val = struct.unpack_from(fmt, d, o)
            if tag == 0:
                break
            if tag == 5:
                strtab = val
            elif tag == 10:
                strsz = val
            elif tag == 24:
                bind_now = True
            elif tag == 30:
                flags = val
            elif tag == 0x6FFFFFFB:
                flags1 = val
    pie_flag = bool(flags1 & 0x08000000)
    exe = interp or etype == 2 or pie_flag
    r["kind"] = "exe" if exe else "lib"
    r["static"] = dyn is None
    if exe:
        r["pie"] = etype == 3
    r["nx"] = "unknown" if stack is None else ("no" if stack else "yes")
    now = bind_now or bool(flags & 0x8) or bool(flags1 & 0x1)
    r["relro"] = "full" if relro and now else ("partial" if relro else "none")
    canary = "unknown"
    if strtab is not None and strsz:
        off = next((o + (strtab - va) for va, o, fsz in loads if va <= strtab < va + fsz), None)
        if off is not None:
            s = rd.read_at(off, min(strsz, ELF_RETAIN))
            if s:
                canary = "yes" if b"\0__stack_chk_fail\0" in b"\0" + s + b"\0" else "no"
    r["canary"] = canary
    return r


def elf_issues(r):
    if "malformed" in r or r.get("kind") not in ("exe", "lib"):
        return []
    out = []
    if r["kind"] == "exe" and not r.get("pie"):
        out.append("no-PIE")
    if r["nx"] == "no":
        out.append("exec-stack")
    elif r["nx"] == "unknown":
        out.append("no-GNU_STACK")
    if r["relro"] == "none":
        out.append("no-RELRO")
    elif r["relro"] == "partial":
        out.append("partial-RELRO")
    if r["canary"] == "no":
        out.append("no-canary")
    return out


STRONG_ISSUES = {"no-PIE", "exec-stack", "no-RELRO"}


# ---------- 私鑰與帳密（只記種類，不留內容） ----------

PEM_BODY_RE = re.compile(rb"\r?\n(?:Proc-Type:[^\n]*\n(?:[^\n]*\n){0,3})?[A-Za-z0-9+/=]{40,}")


class BinScan:
    """ELF 內容裡嵌入的私鑰（PEM 標頭後面要接著 base64，排除程式裡只當字串常數用的標頭）與 AWS 金鑰 ID。
    分段餵進來，前後段重疊 8 KiB；同一種只記一次，不記行號、不留內容。"""

    def __init__(self, where="embedded in an ELF binary"):
        self.tail, self.seen, self.hits, self.kinds, self.where = b"", 0, [], set(), where

    def feed(self, chunk):
        self.seen += len(chunk)
        w = self.tail + chunk
        if b"PRIVATE KEY" in w or b"AKIA" in w or b"ASIA" in w:
            for h in pem_hits(w, need_body=True) + aws_hits(w):
                h.pop("line", None)
                h["where"] = self.where
                k = (h["type"], h.get("protection"))
                if k not in self.kinds:
                    self.kinds.add(k)
                    self.hits.append(h)
        self.tail = w[-8192:]


def aws_hits(data):
    for m in AWS_RE.finditer(data):
        return [{"type": "AWS-style access key ID", "line": data.count(b"\n", 0, m.start()) + 1}]
    return []


def pem_hits(data, need_body=False):
    hits = []
    if b"PRIVATE KEY" in data:
        for m in PEM_RE.finditer(data):
            if need_body and not PEM_BODY_RE.match(data, m.end()):
                continue
            label = m.group(1).decode()
            typ = {"RSA PRIVATE KEY": "PEM RSA private key", "DSA PRIVATE KEY": "PEM DSA private key",
                   "EC PRIVATE KEY": "PEM EC private key", "OPENSSH PRIVATE KEY": "OpenSSH private key",
                   "ENCRYPTED PRIVATE KEY": "PKCS#8 private key", "PRIVATE KEY": "PKCS#8 private key",
                   "PGP PRIVATE KEY BLOCK": "PGP private key"}.get(label, "private key")
            body = data[m.end():m.end() + 400]
            if label == "ENCRYPTED PRIVATE KEY" or b"Proc-Type: 4,ENCRYPTED" in body:
                prot = "passphrase-protected"
            elif label == "OPENSSH PRIVATE KEY":
                prot = openssh_cipher(body)
            elif label == "PGP PRIVATE KEY BLOCK":
                prot = "protection not determined"
            else:
                prot = "not passphrase-protected"
            hits.append({"type": typ, "protection": prot, "line": data.count(b"\n", 0, m.start()) + 1})
    return hits


def scan_secrets(img, path, data):
    name = path.rsplit("/", 1)[-1]
    hits = pem_hits(data)
    if b"AKIA" in data or b"ASIA" in data:
        hits += aws_hits(data)
    low = data.lower()
    if name in (".netrc", "_netrc") and re.search(rb"(^|\s)password\s+\S", low):
        hits.append({"type": "netrc with password field"})
    if name == ".git-credentials" and re.search(rb"://[^\s/:@]+:[^\s/@]+@", data):
        hits.append({"type": "git credential store"})
    if name == ".pgpass" and data.strip():
        hits.append({"type": "PostgreSQL password file"})
    if name == "credentials" and "/.aws/" in "/" + path and b"aws_secret_access_key" in low:
        hits.append({"type": "AWS credentials file"})
    if name == "config.json" and "/.docker/" in "/" + path and b'"auth"' in low:
        hits.append({"type": "container registry credential"})
    if (path.startswith("etc/NetworkManager/system-connections/") or (path.startswith("etc/wpa_supplicant") and name.endswith(".conf"))) \
            and re.search(rb"(?m)^\s*(psk|password|wep-key\d)\s*=\s*\S", data):
        # wpa_supplicant 原始碼附的範例設定檔（Ubuntu 會放一份）：網路名稱都是 example、simple 這類示範值，不是真的帳密
        ssids = [m.group(1).strip().strip(b'"').lower() for m in re.finditer(rb"(?m)^\s*ssid\s*=\s*(.+?)\s*$", data)]
        if b"Example wpa_supplicant configuration file" in data and ssids and all(x in WPA_EXAMPLE_SSIDS for x in ssids):
            hits.append({"type": "wpa_supplicant upstream example file (sample networks only)", "example": True})
        else:
            hits.append({"type": "network credential (Wi-Fi PSK or password)"})
    for h in hits:
        img.secrets.append(dict(h, path=path))


def openssh_cipher(body):
    """OpenSSH 私鑰的加密方式（openssh-key-v1 開頭的 cipher 名稱；none = 沒有密碼保護）。不解出金鑰本身。"""
    b64 = b"".join(body.split()[:3])[:96]
    try:
        raw = base64.b64decode(b64 + b"=" * (-len(b64) % 4))
    except (ValueError, TypeError):
        return "protection not determined"
    if raw.startswith(b"openssh-key-v1\0") and len(raw) >= 19:
        n, = struct.unpack_from(">I", raw, 15)
        c = raw[19:19 + n]
        if 0 < n <= 32 and len(c) == n:
            return "not passphrase-protected" if c == b"none" else "passphrase-protected"
    return "protection not determined"


# ---------- 檢查 ----------

def finding(fid, check, sev, title, text, annex, evidence=(), confirm=""):
    return {"id": fid, "check": check, "severity": sev, "title": title, "text": text, "annex": list(annex),
            "evidence": [clean(x) for x in list(evidence)[:LIST_MAX]], "evidence_total": len(evidence), "confirm_on_board": confirm}


class Owners:
    """dpkg 的檔案清單（var/lib/dpkg/info/*.list）→ 實際路徑 → 套件名稱。"""

    def __init__(self, img):
        self.map, self.available = {}, False
        cache = {}
        _, names = img.listdir("var/lib/dpkg/info")
        for n in names:
            if not n.endswith(".list"):
                continue
            data = img.read(f"var/lib/dpkg/info/{n}")
            if data is None:
                continue
            self.available = True
            pkg = n[:-5].split(":", 1)[0]
            for line in data.decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line.startswith("/") or line == "/.":
                    continue
                parent, base = line.rsplit("/", 1)
                if parent not in cache:
                    cache[parent] = img.resolve(parent) if parent else ""
                cp = cache[parent]
                if cp is not None and base:
                    self.map.setdefault(f"{cp}/{base}" if cp else base, pkg)

    def origin(self, path):
        if not self.available:
            return "unknown (no dpkg file lists)"
        p = self.map.get(path)
        return f"package {p}" if p else "not from a package"

    def vendor(self, path):
        """排序用：0 不屬於任何套件、1 在 /opt 等非發行版位置、2 發行版套件。"""
        if self.available and path not in self.map:
            return 0
        return 1 if path.startswith(VENDOR_DIRS) else 2


def unit_lookup(img, name, dirs):
    """unit 名稱 → (實際的 unit 檔路徑 | None, masked)。依 systemd 的順序找；樣板 foo@<實例>.service → foo@.service。"""
    cands = [name]
    m = re.match(r"^([^@]+)@[^.]+(\.\w+)$", name)
    if m:
        cands.append(f"{m.group(1)}@{m.group(2)}")
    for d in dirs:
        for n in cands:
            ln = img.nodes.get(f"{d}/{n}")
            if ln is not None and ln[0] == "symlink" and os.path.normpath("/" + (ln[3] or "").lstrip("/")) == "/dev/null":
                return None, True             # 指向 /dev/null：masked（映像裡通常沒有 /dev/null）
            p = img.resolve(f"{d}/{n}")
            if p is None:
                continue
            if p == "dev/null":
                return None, True
            node = img.nodes.get(p)
            if node is not None and node[0] in ("file", "hardlink"):
                return p, False
    return None, False


def parse_unit(text):
    """unit 檔 → {鍵: [值, …]}（不分段落，只取需要的鍵）。"""
    out = collections.defaultdict(list)
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s[0] in "#;[" or "=" not in s:
            continue
        k, v = s.split("=", 1)
        k = k.strip()
        if k in ("Description", "ExecStart", "Wants", "Requires", "BindsTo", "ListenStream", "ListenDatagram",
                 "ListenSequentialPacket", "Service", "Unit", "WantedBy", "RequiredBy", "UpheldBy", "Also"):
            out[k].append(v.strip())
    return out


def exec_binary(execstart):
    for v in execstart or ():
        tok = v.lstrip("-@:+!|").split()
        if tok:
            return tok[0]
    return None


UNIT_NAME = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,255}$")


def load_presets(img):
    """systemd preset 檔 → [(檔案, 行號, 動作, 樣式)]：所有資料夾的 *.preset 依檔名排序，同名的檔案前面的資料夾優先
    （/etc 蓋過 /usr/lib；指向 /dev/null 的檔案讓同名的失效）。第一個符合的規則決定；都不符合時 systemd 預設 enable。"""
    files, seen_dirs = {}, set()
    for d in PRESET_DIRS:
        p, names = img.listdir(d)
        if p is None or p in seen_dirs:
            continue
        seen_dirs.add(p)
        for n in names:
            if n.endswith(".preset") and n not in files:
                files[n] = f"{p}/{n}"
    rules = []
    for n in sorted(files):
        ln = img.nodes.get(files[n])
        if ln is not None and ln[0] == "symlink" and os.path.normpath("/" + (ln[3] or "").lstrip("/")) == "/dev/null":
            continue                                   # 指向 /dev/null：讓同名的檔案失效
        text = img.text(files[n])
        if text is None and img.lookup(files[n])[1] is not None:
            img.note("preset_unreadable", files[n])     # 檔案在但沒讀到內容：規則不見會變成預設 enable，記不完整（懸空的連結 systemd 也跳過）
        for i, line in enumerate((text or "").splitlines(), 1):
            w = line.split()
            if len(w) >= 2 and w[0] in ("enable", "disable", "ignore"):
                rules.append(("/" + files[n], i, w[0], w[1]))
    return rules, sorted("/" + f for f in files.values())


def preset_rule(rules, name):
    for r in rules:
        if fnmatch.fnmatchcase(name, r[3]):
            return r
    return None


def machine_id_state(img):
    """machine-id(5)：/etc/machine-id 不存在或內容是 uninitialized → 第一次開機，systemd 依 preset 啟用服務；
    空檔案不算第一次開機（systemd 照樣產生每台的 ID，但不套用 preset）。"""
    p, n = img.lookup("etc/machine-id")
    if n is None:
        return "missing"
    data = img.read("etc/machine-id")
    if data is None:
        return "unreadable"
    v = data.strip()
    return "empty" if not v else "uninitialized" if v == b"uninitialized" else "set"


def check_services(img, owners):
    dirs = []
    for d in UNIT_DIRS:
        p = img.resolve(d)
        if p is not None and p in img.nodes and p not in dirs:
            dirs.append(p)
    etc_dir = img.resolve("etc/systemd/system")
    edges = collections.defaultdict(set)
    links = collections.defaultdict(list)          # unit → [連結的路徑]
    for d in dirs:
        _, names = img.listdir(d)
        for n in names:
            m = re.match(r"^(.+)\.(wants|requires)$", n)
            if not m:
                continue
            _, units = img.listdir(f"{d}/{n}")
            for u in units:
                edges[m.group(1)].add(u)
                links[u].append((f"{d}/{n}/{u}", d == etc_dir))
    info = {}

    def unit(name):
        if name not in info:
            path, masked = unit_lookup(img, name, dirs)
            u = parse_unit(img.text(path)) if path else {}
            info[name] = {"path": path, "masked": masked, "u": u}
        return info[name]

    dt = img.resolve("etc/systemd/system/default.target")
    if dt is None or dt not in img.nodes:
        dt = next((p for p in (img.resolve(f"{d}/default.target") for d in dirs) if p and p in img.nodes), None)
    default = dt.rsplit("/", 1)[-1] if dt else None

    def walk(extra):
        seen, queue, via = set(), collections.deque(), {}
        # 沒有 default.target：當成 graphical.target（Ubuntu 的預設），寧可多列不漏列
        for s in ([default] if default else ["graphical.target", "multi-user.target"]) + list(BOOT_SEED):
            if s not in seen:
                seen.add(s)
                queue.append(s)
        while queue and len(seen) < 20000:
            n = queue.popleft()
            i = unit(n)
            if i["masked"]:
                continue
            deps = set(edges.get(n, ())) | set(extra.get(n, ()))
            if n == (default or "graphical.target"):          # WantedBy=default.target、default.target.wants/
                deps |= set(edges.get("default.target", ())) | set(extra.get("default.target", ()))
            for k in ("Wants", "Requires", "BindsTo"):
                for v in i["u"].get(k, []):
                    deps.update(v.split())
            for dep in sorted(deps):
                if dep not in seen and UNIT_NAME.match(dep) and not dep.startswith("."):
                    seen.add(dep)
                    via[dep] = n
                    queue.append(dep)
        return seen, via

    # 第一次開機（machine-id 空的）systemd 依 preset 啟用有 [Install] 的 unit（只啟用、不停用已經有連結的）：
    # 還沒有連結、preset 是 enable（或沒有符合的規則）的 unit 當成會被掛到 WantedBy／RequiredBy 的 target 底下
    rules, preset_files = load_presets(img)
    mid = machine_id_state(img)
    first_boot = mid in ("missing", "uninitialized")
    pedges, preset_by = collections.defaultdict(set), {}
    cand = sorted({n for d in dirs for n in img.listdir(d)[1]
                   if re.search(r"\.(service|socket|timer|path|target)$", n) and "@" not in n and UNIT_NAME.match(n)})
    # 已有連結的也算（只啟用模式照樣補上 [Install] 的連結）；別名（解析後檔名不同）不算；preset 啟用的 unit 的 Also= 一起啟用。
    # 樣板（foo@.service）不處理：DefaultInstance 與 preset 的 instance 清單沒有模擬（限制）
    def targets_of(n):
        i = unit(n)
        if i["masked"] or not i["path"] or i["path"].rsplit("/", 1)[-1] != n:
            return []
        return [t for k in ("WantedBy", "RequiredBy", "UpheldBy") for v in i["u"].get(k, []) for t in v.split()]

    todo = []
    for n in cand:
        r = preset_rule(rules, n)
        if (r is None or r[2] == "enable") and targets_of(n):
            todo.append((n, f"preset {r[0]}:{r[1]} ({r[2]} {r[3]})" if r else "preset: no matching rule (systemd default is enable)"))
        elif r is None or r[2] == "enable":
            todo.append((n, None))           # 沒有 [Install] 目標：只看 Also=
    done, queued = set(), {(n, bool(w)) for n, w in todo}
    while todo:
        if len(done) >= 20000:
            img.note("cap_preset", f"{len(todo)} unit(s) not expanded")
            break
        n, why = todo.pop()
        if (n, bool(why)) in done or n in preset_by:
            continue
        done.add((n, bool(why)))
        i = unit(n)
        if i["masked"] or not i["path"] or i["path"].rsplit("/", 1)[-1] != n:
            continue                                    # 別名、找不到、masked：systemd 整個跳過（含 Also=）
        ts = targets_of(n)
        if why and ts:
            preset_by[n] = why
            for t in ts:
                pedges[t].add(n)
        for v in i["u"].get("Also", []):
            for a in v.split():
                if UNIT_NAME.match(a) and "@" not in a and a not in preset_by and (a, True) not in queued:
                    queued.add((a, True))
                    todo.append((a, f"Also= of {n}"))
    seen0, via0 = walk({})
    seen1, via1 = walk(pedges) if pedges else (seen0, via0)
    seen, via = (seen1, via1) if first_boot else (seen0, via0)
    by_preset = seen1 - seen0                     # 只有第一次開機套用 preset 才會帶起來的
    activated = {}
    for n in list(seen):
        i = unit(n)
        if i["masked"]:
            continue
        if n.endswith(".socket"):
            svc = (i["u"].get("Service") or [n[:-7] + ".service"])[0]
            if svc.startswith(n[:-7] + "@") or "@" in svc:
                svc = n[:-7] + "@.service"
            activated.setdefault(svc, ("socket-activated", n))
        elif n.endswith(".timer"):
            activated.setdefault((i["u"].get("Unit") or [n[:-6] + ".service"])[0], ("timer", n))
    rows = []
    names = set(n for n in seen | by_preset if n.endswith((".service", ".socket", ".timer"))) | set(activated) | \
        set(u for u in links if u.endswith((".service", ".socket", ".timer")))
    for n in sorted(names):
        i = unit(n)
        if n in by_preset and first_boot:
            state = "enabled at first boot by a systemd preset"
        elif n in seen:
            state = "started at boot"
        elif n in activated:
            state = f"{activated[n][0]} ({activated[n][1]})"
        elif n in by_preset and links.get(n):
            state = "enabled, not reached from the default target (a systemd preset adds its [Install] links at first boot)"
        elif n in by_preset:
            state = "not started at boot; a systemd preset enables it at first boot if /etc/machine-id is removed or set to 'uninitialized'"
        else:
            state = "enabled, not reached from the default target"
        if i["masked"]:
            state = "masked"
        exe = exec_binary(i["u"].get("ExecStart"))
        stem = re.sub(r"(@.*)?\.(service|socket|timer)$", "", n)
        lst = LISTENER_BY_NAME.get(stem) or (LISTENER_BY_NAME.get(exe.rsplit("/", 1)[-1]) if exe else None)
        if lst is None and any(SERVER_FLAG.search(x) for x in i["u"].get("ExecStart", [])):
            lst = ("server-flag", "possible network server (ExecStart has --listen/--bind)", "medium")
        listen = [v for k in ("ListenStream", "ListenDatagram", "ListenSequentialPacket") for v in i["u"].get(k, [])]
        ep = img.resolve(exe) if exe and exe.startswith("/") else None
        if ep is not None and ep not in img.nodes:
            ep = None
        rows.append({"unit": n, "state": state, "admin_enabled": any(e for _, e in links.get(n, [])),
                     "enabled_by": ["/" + p for p, _ in links.get(n, [])][:5] or ([preset_by[n]] if n in preset_by and n in by_preset else [])
                     or ([f"dependency of {via[n]}"] if n in via else [f"dependency of {via1[n]}"] if n in via1 else []),
                     "unit_file": ("/" + i["path"]) if i["path"] else None, "description": (i["u"].get("Description") or [None])[0],
                     "exec": exe, "package": owners.origin(ep) if ep else None, "listen": listen[:8],
                     "network_service": lst[1] if lst else None, "_tag": lst[0] if lst else None, "_sev": lst[2] if lst else None,
                     "_tcp_api": bool(exe) and any("tcp://" in x for x in i["u"].get("ExecStart", []))})
    # SysV：rc2–5.d 的 S 連結，而且沒有同名的 systemd unit（systemd-sysv-generator 會啟動它）
    sysv = set()
    for lvl in "2345":
        _, ns = img.listdir(f"etc/rc{lvl}.d")
        for n in ns:
            m = re.match(r"^S\d\d(.+)$", n)
            if m:
                sysv.add(m.group(1))
    for s in sorted(sysv):
        path, masked = unit_lookup(img, s + ".service", dirs)
        if path or masked:
            continue
        lst = LISTENER_BY_NAME.get(s)
        rows.append({"unit": s, "state": "SysV init script (started via systemd-sysv-generator)", "admin_enabled": True,
                     "enabled_by": [f"/etc/rc{{2..5}}.d/S??{s}"], "unit_file": f"/etc/init.d/{s}", "description": None,
                     "exec": None, "package": owners.origin(img.resolve(f"etc/init.d/{s}") or ""), "listen": [],
                     "network_service": lst[1] if lst else None, "_tag": lst[0] if lst else None, "_sev": lst[2] if lst else None,
                     "_tcp_api": False})
    inetd = []
    for i, line in enumerate((img.text("etc/inetd.conf") or "").splitlines(), 1):
        s = line.strip()
        if s and not s.startswith("#"):
            inetd.append({"service": clean(s.split()[0], 60), "line": i})
    masked = sorted(n for n, i in info.items() if i["masked"])
    findings = []
    started = [r for r in rows if r["network_service"] and not r["state"].startswith(NOT_AT_BOOT)]
    by_tag = collections.defaultdict(list)
    for r in started:
        by_tag[r["_tag"]].append(r)
    for tag, rs in sorted(by_tag.items()):
        sev = rs[0]["_sev"]
        api = [r for r in rs if r["_tcp_api"]]
        if api:
            sev = "high"
        units = ", ".join(r["unit"] for r in rs)
        pre = [r["unit"] for r in rs if r["state"].startswith("enabled at first boot") and not links.get(r["unit"])]
        findings.append(finding(
            f"service:{tag}", "services", sev, f"Network service enabled at boot: {rs[0]['network_service']}",
            f"{units} {'is' if len(rs) == 1 else 'are'} enabled in the image and start{'s' if len(rs) == 1 else ''} "
            f"(or {'is' if len(rs) == 1 else 'are'} socket-activated) at boot"
            + ("; the ExecStart line exposes a TCP API (tcp://)" if api else "")
            + (f"; {', '.join(pre)} {'is' if len(pre) == 1 else 'are'} not linked in the image but enabled by a systemd preset "
               f"at first boot (/etc/machine-id is {mid})" if pre else "")
            + ". Confirm this service is needed in the shipped product and that its default configuration is secure; "
              "otherwise disable or remove it.",
            ("I-2b", "I-2j"), [e for r in rs for e in ([r["unit_file"] or r["unit"]] + r["enabled_by"])],
            "Run `ss -tulpn` on a freshly flashed board and list every listening socket and the process behind it."))
    later = [r for r in rows if r["network_service"] and r["state"].startswith("not started")]
    if later:
        findings.append(finding(
            "service:preset-first-boot", "services", "low", "Network services that a systemd preset enables at first boot",
            ", ".join(r["unit"] for r in later) + " are not started at boot in the image, but the systemd presets enable them "
            "when systemd treats a boot as the first boot (/etc/machine-id missing or containing 'uninitialized'; an empty "
            "file is not a first boot). Add a `disable` line for each to a product preset file in /etc/systemd/system-preset/, "
            "or remove the package, so that a later change to how machine-id is prepared does not turn them on.", ("I-2b", "I-2j"),
            [f"{r['unit']}: {e}" for r in later for e in r["enabled_by"]],
            "Run `systemctl is-enabled` for each unit on a freshly flashed board."))
    off = [r for r in rows if r["network_service"] and r["state"].startswith("enabled, not")]
    if off:
        findings.append(finding("service:enabled-not-reached", "services", "low", "Network services enabled for a non-default target",
                                ", ".join(r["unit"] for r in off) + " are enabled but not pulled in by the default boot target. "
                                "Confirm they cannot be started in normal operation.", ("I-2j",),
                                [e for r in off for e in r["enabled_by"]], "Check `systemctl list-units --all` on the board."))
    if inetd:
        clear = [x for x in inetd if x["service"] in INETD_CLEARTEXT]
        findings.append(finding("service:inetd", "services", "high" if clear else "medium", "inetd services configured",
                                "/etc/inetd.conf has active entries: " + ", ".join(x["service"] for x in inetd[:20])
                                + ". These run when an inetd daemon is installed and enabled.", ("I-2b", "I-2j"),
                                [f"/etc/inetd.conf:{x['line']}" for x in inetd],
                                "Check whether an inetd daemon runs on the board and which ports it opens."))
    for r in rows:
        for k in ("unit", "unit_file", "description", "exec", "package", "network_service"):
            if r.get(k) is not None:
                r[k] = clean(r[k])
        r["enabled_by"] = [clean(x) for x in r["enabled_by"]]
        r["listen"] = [clean(x, 80) for x in r["listen"]]
        for k in ("_tag", "_sev", "_tcp_api"):
            r.pop(k, None)
    data = {"default_target": clean(default) if default else "not found (assumed graphical.target)", "units": rows,
            "machine_id": mid, "first_boot_presets": first_boot, "preset_files": [clean(f) for f in preset_files[:LIST_MAX]],
            "preset_enabled": [clean(n) for n in sorted(by_preset)[:LIST_MAX]],
            "masked": [clean(m) for m in masked],
            "inetd": inetd, "systemd": bool(dirs)}
    return data, findings


SSHD_DEFAULTS = {"port": "22", "permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
                 "kbdinteractiveauthentication": "yes", "permitemptypasswords": "no", "usepam": "no", "pubkeyauthentication": "yes"}
SSHD_SHOW = ("port", "listenaddress", "permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication",
             "permitemptypasswords", "usepam", "pubkeyauthentication")


ALL = object()


def sshd_tokens(v):
    """sshd_config 一行的值 → 去掉行內 # 註解與引號後的字串清單（shlex 失敗，例如引號沒關 → 退回以 # 截斷再切空白）。"""
    try:
        return shlex.split(v, comments=True)
    except ValueError:
        return v.split("#")[0].replace('"', "").split()


def sshd_config(img):
    eff, allm, cond, files, notes = {}, {}, [], [], []    # allm：Match all 區塊裡的值（sshd 套用 Match 的值蓋過全域值）
    budget = [64]                     # 讀幾個檔案（Include 迴圈或大量萬用字元時停下）
    work = [INCLUDE_WORK]             # Include 的樣式數與展開時看過的名稱數

    def parse(path, depth, match):
        budget[0] -= 1
        if budget[0] < 0:
            if budget[0] == -1:
                notes.append("too many Include files; stopped after 64")
            return
        if depth > INCLUDE_DEPTH:
            notes.append(f"Include deeper than {INCLUDE_DEPTH} levels: /{path}")
            return
        p, node = img.lookup(path)
        t = img.text(path)
        if t is None:
            notes.append(f"/{path} " + ("not found" if node is None else "not read"))
            return
        files.append("/" + p)
        cur = match
        for i, line in enumerate(t.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r"^(\S+?)(?:\s*=\s*|\s+)(.*)$", s)
            if not m:
                continue
            k, toks = m.group(1).lower(), sshd_tokens(m.group(2))
            v = " ".join(toks)                    # 去掉行內註解與引號；只看第一個值的地方用 toks[0]
            if k == "challengeresponseauthentication":
                k = "kbdinteractiveauthentication"
            if k == "match":
                cur = ALL if v.lower() == "all" else v        # Match all：對所有連線都有效
                continue
            if k == "include":
                cut = False
                for pat in toks:
                    work[0] -= 1
                    if work[0] <= 0:
                        cut = True
                        break
                    qs, c = img.glob(pat if pat.startswith("/") else f"etc/ssh/{pat}", work)
                    cut = cut or c
                    for q in qs:
                        parse(q, depth + 1, cur)
                if cut and not any(n.startswith("Include expansion") for n in notes):
                    notes.append(f"Include expansion truncated (at most {GLOB_MAX} files per pattern level, "
                                 f"{INCLUDE_WORK} patterns/names in total)")
                    img.note("cap_include", f"/{p}:{i}")
                continue
            where = f"/{p}:{i}"
            if cur is ALL:
                allm.setdefault(k, (v, where))
            elif cur and k in SSHD_SHOW:
                cond.append({"keyword": k, "value": (v.split() or [""])[0].lower(), "where": where, "match": cur})
            elif not cur and k not in eff:
                eff[k] = (v, where)

    parse("etc/ssh/sshd_config", 0, None)
    out = {}
    for k in SSHD_SHOW:
        if k in allm:
            out[k] = {"value": clean(allm[k][0], 80), "source": clean(allm[k][1]) + " (Match all)"}
            if k in eff:
                out[k]["overrides"] = clean(eff[k][1])
        elif k in eff:
            out[k] = {"value": clean(eff[k][0], 80), "source": clean(eff[k][1])}
        elif k in SSHD_DEFAULTS:
            out[k] = {"value": SSHD_DEFAULTS[k], "source": "OpenSSH default"}
    return out, [dict((k, clean(v, 120)) for k, v in c.items()) for c in cond[:LIST_MAX]], files, notes


def check_ssh(img, services):
    sshd = img.lookup("usr/sbin/sshd")[1] is not None
    units = [u for u in services["units"] if (u["network_service"] or "").startswith("SSH")]
    running = [u for u in units if not u["state"].startswith(NOT_AT_BOOT)]
    _, keys = img.listdir("etc/ssh")
    host = [f"etc/ssh/{k}" for k in keys
            if re.match(r"^ssh_host_\w+_key$", k) and (img.lookup(f"etc/ssh/{k}")[1] or [None])[0] in ("file", "hardlink")]
    regen = [u["unit"] for u in services["units"] if re.search(r"(regen|keygen|host-?keys?)", u["unit"], re.I)]
    findings = []
    data = {"sshd_installed": sshd, "enabled_at_boot": [u["unit"] for u in running], "host_private_keys": ["/" + h for h in host],
            "possible_key_regeneration_units": regen}
    if not sshd and not units:
        data["note"] = "OpenSSH server (/usr/sbin/sshd) is not in the image"
    else:
        eff, cond, files, notes = sshd_config(img)
        data.update(effective=eff, conditional=cond, files=files, notes=notes)
        live = bool(running)
        ctx = "sshd is enabled at boot" if live else "sshd is installed but not enabled at boot (lower priority)"

        def sev(s):
            return s if live else "low"
        v = {k: ((x["value"].split() or [""])[0]).lower() for k, x in eff.items()}
        src = {k: x["source"] for k, x in eff.items()}
        ev = {k: [x["source"]] + ([f"{x['overrides']} (overridden)"] if x.get("overrides") else []) for k, x in eff.items()}
        if v.get("permitrootlogin") == "yes":
            findings.append(finding("ssh:permit-root-login", "ssh", sev("high"), "SSH allows root login with a password",
                                    f"PermitRootLogin yes ({src['permitrootlogin']}); {ctx}. Root can log in over the network "
                                    "with a password. Use prohibit-password or no.", ("I-2b", "I-2d"), ev["permitrootlogin"],
                                    "Try `ssh root@<board>` with a password on a freshly flashed board; it should be refused."))
        if v.get("passwordauthentication") == "yes":
            findings.append(finding("ssh:password-auth", "ssh", sev("medium"), "SSH password authentication is enabled",
                                    f"PasswordAuthentication yes ({src['passwordauthentication']}); {ctx}. Password login over "
                                    "the network is exposed to guessing; prefer keys, or document why passwords are needed and "
                                    "how they are unique per device.", ("I-2b", "I-2d"), ev["passwordauthentication"],
                                    "Run `sshd -T | grep -i passwordauthentication` on the board."))
        if v.get("kbdinteractiveauthentication") == "yes" and v.get("usepam") == "yes":
            findings.append(finding("ssh:kbd-interactive-pam", "ssh", sev("medium"), "SSH keyboard-interactive (PAM) login is enabled",
                                    f"KbdInteractiveAuthentication yes ({src['kbdinteractiveauthentication']}) with UsePAM yes "
                                    f"({src['usepam']}); {ctx}. Password login through PAM is possible even if "
                                    "PasswordAuthentication is no.", ("I-2d",), ev["kbdinteractiveauthentication"] + ev["usepam"],
                                    "Run `sshd -T` on the board and try a keyboard-interactive login."))
        if v.get("permitemptypasswords") == "yes":
            findings.append(finding("ssh:permit-empty-passwords", "ssh", sev("high"), "SSH permits empty passwords",
                                    f"PermitEmptyPasswords yes ({src['permitemptypasswords']}); {ctx}.", ("I-2b", "I-2d"),
                                    ev["permitemptypasswords"], "Run `sshd -T` on the board."))
        risky = [c for c in cond if (c["keyword"], c["value"]) in (("permitrootlogin", "yes"), ("passwordauthentication", "yes"),
                                                                    ("permitemptypasswords", "yes"))]
        if risky:
            findings.append(finding("ssh:match-blocks", "ssh", "low", "SSH Match blocks relax authentication",
                                    "Match blocks set " + ", ".join(f"{c['keyword']} {c['value']} (Match {c['match']})" for c in risky)
                                    + ". Confirm which clients these apply to.", ("I-2d",), [c["where"] for c in risky],
                                    "Run `sshd -T -C user=…,host=…,addr=…` on the board for the matching clients."))
    if host:
        # 每台都一樣的 SSH 主機金鑰（CVE-2019-5672 是同一類）；第一次開機的產生程式只在金鑰不存在時才產生，所以不降級
        findings.append(finding("ssh:baked-host-keys", "ssh", "high" if (running or sshd) else "low",
                                "SSH host private keys are baked into the image",
                                f"{len(host)} SSH host private key file(s) are in the image. Unless they are regenerated on first boot, "
                                "every device shipped from this image has the same host key, so one extracted key allows "
                                "impersonating any device." + (f" Possible regeneration unit(s): {', '.join(regen)}." if regen else ""),
                                ("I-2b", "I-2d"), ["/" + h for h in host],
                                "Flash two boards and compare `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`; the fingerprints must differ."))
    return data, findings


def pw_status(field):
    """密碼欄位 → 推導出的狀態（不輸出雜湊本身）。"""
    if field == "":
        return "empty", None
    if field in ("*", "!", "!!", "!*", "*LK*", "x"):
        return ("locked (no password)" if field != "x" else "in shadow"), None
    if field.startswith(("!", "*")):
        return "locked (password set)", scheme(field.lstrip("!*"))
    return "set", scheme(field)


def scheme(h):
    m = re.match(r"^\$([0-9a-z]+)\$", h)
    if not m:
        return "DES (weak)" if len(h) == 13 else "unknown"
    return {"1": "MD5 (weak)", "2a": "bcrypt", "2b": "bcrypt", "2y": "bcrypt", "5": "SHA-256", "6": "SHA-512",
            "y": "yescrypt", "gy": "gost-yescrypt", "7": "scrypt"}.get(m.group(1), "unknown")


def check_accounts(img):
    pw = img.text("etc/passwd")
    sh = img.read("etc/shadow")
    _, sn = img.lookup("etc/shadow")
    shadow_note = None
    if sn is None:
        shadow_note = "/etc/shadow not in the image"
    elif sh is None:
        shadow_note = "/etc/shadow not readable"
    shadow = {}
    for line in (sh or b"").decode("utf-8", "replace").splitlines():
        f = line.split(":")
        if len(f) >= 2 and f[0]:
            shadow.setdefault(f[0], f[1])
    rows, findings, bad = [], [], 0
    for line in (pw or "").splitlines():
        f = line.split(":")
        if len(f) < 7 or not f[0] or not f[2].isdigit():
            if line.strip():
                bad += 1
            continue
        name, pfield, uid, shell = f[0], f[1], int(f[2]), f[6].strip()
        if pfield == "x":
            if name in shadow:
                st, sch = pw_status(shadow[name])
            else:
                st, sch = "unknown (no shadow entry)", None
            where = "shadow"
        else:
            st, sch = pw_status(pfield)
            where = "passwd"
        login = shell not in NOLOGIN and not shell.endswith(("/nologin", "/false"))
        rows.append({"name": clean(name, 64), "uid": uid, "shell": clean(shell, 80) or "(empty: /bin/sh)", "login_shell": login,
                     "password": st, "hash_scheme": sch, "password_field_in": where})
    if pw is None:
        findings.append(finding("accounts:no-passwd", "accounts", "low", "No /etc/passwd in the image",
                                "Accounts could not be checked; they may be created at first boot.", ("I-2d",), [],
                                "List accounts with `getent passwd` on the board after first boot."))
    empty = [r for r in rows if r["password"] == "empty"]
    if empty:
        lg = [r for r in empty if r["login_shell"]]
        findings.append(finding("accounts:empty-password", "accounts", "high" if lg else "low", "Accounts with an empty password",
                                "Accounts: " + ", ".join(r["name"] for r in empty) + ". The password field is empty: anyone can "
                                "log in as these accounts where password login is allowed (console, su, and SSH if PermitEmptyPasswords).",
                                ("I-2b", "I-2d"), [f"/etc/{r['password_field_in']}: {r['name']}" for r in empty],
                                "Try logging in on the console as these accounts on a freshly flashed board."))
    uid0 = [r for r in rows if r["uid"] == 0 and r["name"] != "root"]
    if uid0:
        findings.append(finding("accounts:extra-uid0", "accounts", "high", "Accounts other than root with UID 0",
                                "Accounts: " + ", ".join(r["name"] for r in uid0) + ". UID 0 gives full root rights.", ("I-2d",),
                                [f"/etc/passwd: {r['name']}" for r in uid0], "`awk -F: '$3==0' /etc/passwd` lists only root."))
    setpw = [r for r in rows if r["password"] == "set" and r["login_shell"]]
    if setpw:
        # 每台都一樣的預設密碼（no universal default password；ETSI EN 303 645 5.1-1）：run() 依 SSH 是否能用密碼登入定 high／medium
        findings.append(finding("accounts:password-in-image", "accounts", "medium", "Login accounts have a password set in the image",
                                "Accounts: " + ", ".join(r["name"] for r in setpw) + ". They have a usable password in the image. Every device "
                                "flashed from this image has the same password unless it is changed or forced to change on "
                                "first boot (no universal default passwords).", ("I-2b", "I-2d"),
                                [f"/etc/{r['password_field_in']}: {r['name']}" for r in setpw],
                                "Check on a freshly flashed board whether these passwords must be changed at first login "
                                "(`chage -l <user>`) or are set per device."))
    inpw = [r for r in rows if r["password_field_in"] == "passwd" and r["password"] in ("set", "locked (password set)")]
    if inpw:
        findings.append(finding("accounts:hash-in-passwd", "accounts", "medium", "Password hash stored in /etc/passwd",
                                "Accounts: " + ", ".join(r["name"] for r in inpw) + ". The password hash is in the world-readable "
                                "/etc/passwd instead of /etc/shadow.", ("I-2d",), [f"/etc/passwd: {r['name']}" for r in inpw], ""))
    weak = [r for r in rows if r["hash_scheme"] and "weak" in r["hash_scheme"]]
    if weak:
        findings.append(finding("accounts:weak-hash", "accounts", "medium", "Weak password hash scheme",
                                "Accounts: " + ", ".join(f"{r['name']} ({r['hash_scheme']})" for r in weak) + ".", ("I-2d",),
                                [f"/etc/{r['password_field_in']}: {r['name']}" for r in weak], ""))
    if rows and shadow_note and any(r["password_field_in"] == "shadow" for r in rows):
        findings.append(finding("accounts:shadow-missing", "accounts", "low", "Password status unknown",
                                shadow_note + ": the password status of the accounts could not be derived.", ("I-2d",), [],
                                "Check `passwd -S -a` on the board."))
    nopw = []
    sudo_files = ["etc/sudoers"] + [f"etc/sudoers.d/{n}" for n in img.listdir("etc/sudoers.d")[1]]
    for sf in sudo_files:
        for i, line in enumerate((img.text(sf) or "").splitlines(), 1):
            s = line.strip()
            if s and not s.startswith("#") and "NOPASSWD" in s:
                nopw.append({"where": f"/{sf}:{i}", "who": clean(s.split()[0], 64)})
    if nopw:
        findings.append(finding("accounts:sudo-nopasswd", "accounts", "medium", "sudo without password",
                                "sudoers grants commands without a password to " + ", ".join(sorted({x["who"] for x in nopw}))
                                + ". Anyone who gets a shell as these users gets root.", ("I-2d", "I-2k"),
                                [x["where"] for x in nopw], "Run `sudo -l` as these users on the board."))
    root = next((r for r in rows if r["name"] == "root"), None)
    data = {"accounts": rows, "malformed_lines": bad, "shadow": shadow_note or "read", "sudo_nopasswd": nopw,
            "root_password": root["password"] if root else None,
            "login_accounts": [r["name"] for r in rows if r["login_shell"]]}
    return data, findings


def check_permissions(img, owners):
    suid, ww_files, ww_dirs = [], [], []
    for p, (kind, mode, _size, _link, uid) in img.nodes.items():
        if mode is None:
            continue
        if kind in ("file", "hardlink"):
            if mode & 0o6000:
                suid.append({"path": "/" + clean(p), "mode": f"{mode:04o}", "bits": "+".join(
                    b for b, v in (("setuid", 0o4000), ("setgid", 0o2000)) if mode & v),
                    "owner_uid": uid if img.owners_known else None, "origin": owners.origin(p), "_v": owners.vendor(p)})
            if mode & 0o002 and not under(p, TMP_DIRS):
                ww_files.append({"path": "/" + clean(p), "mode": f"{mode:04o}", "origin": owners.origin(p), "_v": owners.vendor(p)})
        elif kind == "dir" and mode & 0o002 and not mode & 0o1000:
            ww_dirs.append({"path": "/" + clean(p), "mode": f"{mode:04o}", "origin": owners.origin(p), "_v": owners.vendor(p)})
    for lst in (suid, ww_files, ww_dirs):
        lst.sort(key=lambda r: (r["_v"], r["path"]))
    findings = []
    vend = [r for r in suid if r["_v"] < 2]
    if vend:
        findings.append(finding("perm:setuid-vendor", "permissions", "medium", "setuid/setgid programs outside distribution packages",
                                f"{len(vend)} setuid/setgid file(s) are not from a distribution package (or are in /opt, /usr/local). "
                                "Each one runs with elevated rights; confirm it is needed and reviewed.", ("I-2d", "I-2k"),
                                [f"{r['path']} ({r['bits']} {r['mode']})" for r in vend], ""))
    pk = [r for r in suid if r["_v"] == 2]
    if pk:
        findings.append(finding("perm:setuid-packages", "permissions", "low", "setuid/setgid programs from distribution packages",
                                f"{len(pk)} setuid/setgid file(s) come from distribution packages. Remove the packages that "
                                "the product does not need.", ("I-2j", "I-2k"),
                                [f"{r['path']} ({r['bits']}, {r['origin']})" for r in pk], ""))
    if ww_files or ww_dirs:
        findings.append(finding("perm:world-writable", "permissions", "medium", "World-writable files or directories",
                                f"{len(ww_files)} world-writable file(s) and {len(ww_dirs)} world-writable director(ies) without the "
                                "sticky bit. Any local user or compromised service can change them.", ("I-2d", "I-2k"),
                                [f"{r['path']} ({r['mode']})" for r in ww_files + ww_dirs],
                                "Check that first-boot scripts do not change these permissions back."))
    for lst in (suid, ww_files, ww_dirs):
        for r in lst:
            r.pop("_v")
    return {"setuid_setgid": suid[:LIST_MAX], "setuid_setgid_total": len(suid), "world_writable_files": ww_files[:LIST_MAX],
            "world_writable_files_total": len(ww_files), "world_writable_dirs": ww_dirs[:LIST_MAX],
            "world_writable_dirs_total": len(ww_dirs),
            "owner_info": "from the flash package tar headers" if img.owners_known else
            "unknown for this source (a rootfs tar written by scan-flash-package.sh records every owner as root; a directory "
            "source shows whoever unpacked it), so setuid files are not claimed to be setuid-root"}, findings


def check_secrets(img, owners):
    rows = []
    for s in img.secrets:
        rows.append(dict({k: v for k, v in s.items() if k != "path"}, path="/" + clean(s["path"]), origin=owners.origin(s["path"]),
                         _v=owners.vendor(s["path"])))
    rows.sort(key=lambda r: (r["_v"], r["path"]))
    findings = []
    # 測試套件附的測試金鑰（installed-tests、tests 資料夾、snakeoil）：每台一樣但不保護任何東西，處理方式是移除測試套件
    test = [r for r in rows if "private key" in r["type"] and TEST_KEY_RE.search(r["path"])
            and str(r.get("origin") or "").startswith("package ")]
    keys = [r for r in rows if "private key" in r["type"] and r not in test]
    examples = [r for r in rows if r.get("example")]
    creds = [r for r in rows if "private key" not in r["type"] and not r.get("example")]

    def ev(r):
        return (r["path"] + (f":{r['line']}" if r.get("line") else "") + f" ({r['type']}"
                + (f", {r['protection']}" if r.get("protection") else "") + (f", {r['where']}" if r.get("where") else "") + ")")
    if keys:
        unprot = [r for r in keys if r.get("protection") != "passphrase-protected"]
        findings.append(finding("secrets:private-keys", "secrets", "high" if unprot else "medium", "Private keys in the image",
                                f"{len(keys)} private key(s) found ({len(unprot)} without passphrase protection). Every device "
                                "flashed from this image has the same key. Confirm whether each key is a test or sample key, is "
                                "replaced on first boot, or must be removed. Key material is not copied into this report.",
                                ("I-2d", "I-2e"), [ev(r) for r in keys],
                                "Compare the key fingerprints on two freshly flashed boards."))
    if test:
        findings.append(finding("secrets:test-keys", "secrets", "low", "Test keys shipped with test packages",
                                f"{len(test)} private key(s) belong to test suites or sample configurations (installed tests, "
                                "snakeoil keys). They do not protect anything on the product but show that test packages are "
                                "shipped; remove the packages. Key material is not copied into this report.",
                                ("I-2j",), [ev(r) for r in test], "Check that the owning test packages are not needed and remove them."))
    if examples:
        findings.append(finding("secrets:example-config", "secrets", "info", "Upstream example configuration with sample credentials",
                                f"{len(examples)} file(s) are the upstream example configuration (sample network names such as "
                                "\"example\"); they hold no real credentials. Optional cleanup.", ("I-2j",), [ev(r) for r in examples],
                                "Confirm the service does not load this file (e.g. wpa_supplicant started without -c)."))
    if creds:
        findings.append(finding("secrets:credentials", "secrets", "high", "Credentials in the image",
                                f"{len(creds)} file(s) look like they contain credentials. Values are not copied into this report.",
                                ("I-2d", "I-2e"), [ev(r) for r in creds], "Confirm whether the credential is valid and remove it."))
    for r in rows:
        r.pop("_v")
    return {"items": rows[:LIST_MAX], "total": len(rows),
            "scope": "PEM/OpenSSH private key headers, AWS-style key IDs, .netrc/.git-credentials/.pgpass, Docker/AWS credential "
                     f"files, NetworkManager/wpa_supplicant PSKs; files up to {SECRET_MAX >> 10} KiB (ELF binaries up to "
                     f"{SECRET_ELF_MAX >> 20} MiB: PEM keys with a base64 body and AWS key IDs only) under "
                     + ", ".join("/" + d for d in SECRET_DIRS) + " and well-known names anywhere; SSH host keys are reported "
                     "under the SSH check"}, findings


def check_elf(img, owners):
    counts = collections.Counter()
    weak = []
    for p, r in img.elf.items():
        if "malformed" in r:
            counts["malformed"] += 1
            continue
        if r.get("kind") not in ("exe", "lib"):
            counts["other_type"] += 1
            continue
        counts[r["kind"]] += 1
        if r["kind"] == "exe":
            counts["exe_pie" if r["pie"] else "exe_no_pie"] += 1
        counts[f"nx_{r['nx']}"] += 1
        counts[f"relro_{r['relro']}"] += 1
        counts[f"canary_{r['canary']}"] += 1
        if r["static"]:
            counts["static"] += 1
        iss = elf_issues(r)
        v = owners.vendor(p)
        if (v < 2 and iss) or STRONG_ISSUES & set(iss):
            weak.append({"path": "/" + clean(p), "kind": r["kind"], "machine": r["machine"], "issues": iss,
                         "origin": owners.origin(p), "_v": v, **({"hardlink_of": r["hardlink_of"]} if "hardlink_of" in r else {})})
    weak.sort(key=lambda r: (r["_v"], -len(STRONG_ISSUES & set(r["issues"])), r["path"]))
    findings = []
    vend = [r for r in weak if r["_v"] < 2]
    pk = [r for r in weak if r["_v"] == 2]

    def ev(r):
        return f"{r['path']} ({', '.join(r['issues'])})"
    if vend:
        strong = [r for r in vend if STRONG_ISSUES & set(r["issues"])]
        findings.append(finding("elf:vendor", "elf", "medium" if strong else "low",
                                "Product / vendor binaries without full exploit mitigations",
                                f"{len(vend)} ELF file(s) not from a distribution package (or in /opt, /usr/local) lack some "
                                f"mitigations; {len(strong)} miss PIE, a non-executable stack or RELRO. These are usually the "
                                "product team's to rebuild (-fPIE -pie, -Wl,-z,relro,-z,now, -fstack-protector-strong, -z noexecstack).",
                                ("I-2k",), [ev(r) for r in vend], ""))
    if pk:
        findings.append(finding("elf:packages", "elf", "low", "Distribution package binaries without PIE, NX or RELRO",
                                f"{len(pk)} ELF file(s) from distribution packages miss PIE, a non-executable stack or RELRO. "
                                "Usually not fixable by the product team; remove the package if it is not needed.",
                                ("I-2j", "I-2k"), [ev(r) for r in pk], ""))
    xs = [r for r in weak if "exec-stack" in r["issues"]]
    if xs:
        findings.append(finding("elf:exec-stack", "elf", "medium", "Executable stack",
                                f"{len(xs)} ELF file(s) request an executable stack (PT_GNU_STACK with X), which disables NX for "
                                "the whole process that loads them.", ("I-2k",), [ev(r) for r in xs], ""))
    if counts["malformed"]:
        findings.append(finding("elf:malformed", "elf", "low", "ELF files that could not be parsed",
                                f"{counts['malformed']} file(s) start with the ELF magic but could not be parsed.", ("I-2k",),
                                ["/" + clean(p) for p, r in img.elf.items() if "malformed" in r], ""))
    for r in weak:
        r.pop("_v")
    return {"counts": dict(counts), "checked": len(img.elf), "listed": weak[:LIST_MAX], "listed_total": len(weak),
            "listed_vendor": len(vend),
            "scope": "regular files with the ELF magic under " + ", ".join("/" + d for d in ELF_DIRS)
                     + " (not " + ", ".join("/" + d for d in ELF_SKIP) + ")",
            "method": "PIE: ET_DYN executable (PT_INTERP or DF_1_PIE); NX: PT_GNU_STACK without PF_X; RELRO: PT_GNU_RELRO "
                      "(full with BIND_NOW / DF_BIND_NOW / DF_1_NOW); canary: __stack_chk_fail in .dynstr (unknown for static "
                      "binaries)"}, findings


# ---------- 核心模組名稱（檢查 7） ----------

def mod_norm(name):
    """核心的模組名稱：- 與 _ 相同（/proc/modules 一律顯示 _）。"""
    return name.replace("-", "_")


def mod_name_ok(name):
    return bool(MOD_NAME_RE.match(name)) and any(c.isalpha() for c in name)


def ko_name(token):
    """…/NAME.ko[.xz|.zst|.gz] → NAME；不是 .ko 的 → None。"""
    m = KO_RE.search(token)
    return m.group(1) if m and mod_name_ok(m.group(1)) else None


def scan_modrefs(img, path, data, kind):
    """串流讀取時找模組名稱的引用（只記名稱、行號、寫法；不留檔案內容）。data 是 script_part 切好的範圍（第一個 NUL 之前）。"""
    if img.script_total + len(data) > SCRIPT_TOTAL:
        img.note("cap_script_total", path)
        return
    img.script_total += len(data)
    img.script_files.add(path)
    if kind in ("shell", "unit") and not any(t in data for t in MOD_TRIGGERS):
        return
    text = data.decode("utf-8", "replace")
    if kind == "modprobe":
        refs, aliases = modprobe_conf_refs(text)
        img.mod_aliases |= aliases
    else:
        refs = {"load": modload_refs, "unit": unit_refs, "shell": shell_refs}[kind](text)
    seen, out = set(), []
    for r in refs:
        k = (r["line"], r["name"], r["ctx"])
        if k in seen:
            continue
        seen.add(k)
        if img.modref_count >= MODREF_MAX:
            img.note("cap_modrefs", path)
            break
        out.append(r)
        img.modref_count += 1
    if out:
        img.modrefs[path] = out


def ref(line, name, ctx, mode="exact", icase=False):
    return {"line": line, "name": name, "ctx": ctx, "mode": mode, "icase": icase}


def conf_lines(text):
    """modprobe.d 的行（# 註解、行尾 \\ 接下一行）→ (行號, 內容)。"""
    lines, i = text.split("\n"), 0
    while i < len(lines):
        start, buf = i, lines[i]
        i += 1
        while buf.endswith("\\") and i < len(lines) and i - start < 50:
            buf = buf[:-1] + " " + lines[i]
            i += 1
        buf = buf.strip()
        if buf and not buf.startswith("#"):
            yield start + 1, buf


def modprobe_conf_refs(text):
    """→ (引用, alias 名稱的集合)：alias NAME module 定義的名稱，modprobe NAME 照樣有效。"""
    out, aliases = [], set()
    for n, line in conf_lines(text):
        w = line.split()
        if len(w) >= 3 and w[0] == "alias" and ":" not in w[1] and not any(c in w[1] for c in "*?["):
            aliases.add(mod_norm(w[1]))
        elif len(w) >= 2 and w[0] == "blacklist" and mod_name_ok(w[1]):
            out.append(ref(n, w[1], "blacklist"))
        elif len(w) >= 3 and w[0] == "install" and mod_name_ok(w[1]):
            # 只認「停用」的 install（/bin/false、/bin/true、exit）：其他 install 指令可能是刻意的虛擬模組
            if os.path.basename(w[2]) in ("false", "true") or w[2] == "exit":
                out.append(ref(n, w[1], "install"))
    return out, aliases


def modload_refs(text):
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        w = line.split()
        if mod_name_ok(w[0]):
            out.append(ref(n, w[0], "modules-load"))
    return out


EXEC_RE = re.compile(r"^\s*Exec(?:Start|StartPre|StartPost|Stop|StopPost|Reload|Condition)\s*=\s*(.*)$")
TRIGGER_STR = tuple(t.decode() for t in MOD_TRIGGERS)


def unit_refs(text):
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        m = EXEC_RE.match(line)
        if not m:
            continue
        v = m.group(1).lstrip("@-:+!")
        if any(t in v for t in TRIGGER_STR):
            out += [ref(n, *r) for r in line_refs(v, {})]
    return out


FUNC_RE = re.compile(r"^\s*(?:function\s+([A-Za-z_][\w:.-]*)\s*(?:\(\s*\))?|([A-Za-z_][\w:.-]*)\s*\(\s*\))\s*(\{.*)?$")
ASSIGN_RE = re.compile(r"(?:^|[\s;])(?:(?:local|declare|readonly|typeset)\s+)?([A-Za-z_]\w*)=[\"']?\$\{?([1-9])\}?[\"']?(?=$|[\s;])")
PROBE = ("/proc/modules", "lsmod")
NOT_A_TEST = {"echo", "printf", "print", "cat", ":", "true", "false", "test", "[", "[[", "logger", "read"}


def shell_tokens(line):
    lex = shlex.shlex(line.replace("`", " ( "), posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    return list(lex)


def shell_logical_lines(text):
    """shell 的邏輯行 → (第一行的行號, 內容, tokens 或 None)。接起行尾的 \\ 與跨行的引號；heredoc 的內容（資料，不是指令）
    跳過；50 行內引號沒有關的 → tokens 是 None（不判斷）。"""
    lines, i = text.split("\n"), 0
    while i < len(lines):
        start, buf = i, lines[i]
        i += 1
        toks = None
        while True:
            while buf.endswith("\\") and i < len(lines) and i - start < 50:
                buf = buf[:-1] + lines[i]
                i += 1
            try:
                toks = shell_tokens(buf)
                break
            except ValueError:
                if i >= len(lines) or i - start >= 50:
                    break
                buf += "\n" + lines[i]
                i += 1
        yield start + 1, buf, toks
        if toks is None:
            continue
        # heredoc：只認引號外的 << token（引號裡、$((1<<2)) 的不算）；找不到結尾 → 不跳（不藏住檔案其他部分）
        for dash, delim in heredocs(toks):
            k = i
            while k < len(lines):
                cur = lines[k].lstrip("\t") if dash else lines[k]
                k += 1
                if cur.rstrip() == delim:
                    i = k
                    break


def heredocs(toks):
    """tokens 裡引號外的 <<WORD、<<-WORD → [(是否 <<-, WORD)]；WORD 全是數字的（多半是 $((1<<2))）不算。"""
    out = []
    for j, t in enumerate(toks):
        if t != "<<" or j + 1 >= len(toks):
            continue
        d = toks[j + 1]
        dash = d.startswith("-")
        if d == "-" and j + 2 < len(toks):
            d = toks[j + 2]
        elif dash:
            d = d[1:]
        if d and not d.isdigit() and re.match(r"^[\w.-]+$", d):
            out.append((dash, d))
    return out


def shell_commands(toks):
    """tokens → [(指令的 tokens, 由管線接過來的前一個指令 | None, < 的輸入檔 | None)]。"""
    cmds, st = [], {"cur": [], "stdin": None, "prev": None}

    def close(sep):
        c = None
        if st["cur"]:
            c = (st["cur"], st["prev"], st["stdin"])
            cmds.append(c)
        st["prev"] = c[0] if (c and sep in ("|", "|&")) else None
        st["cur"], st["stdin"] = [], None
    i = 0
    while i < len(toks):
        t = toks[i]
        if t and all(ch in "();<>|&" for ch in t):
            if ("<" in t or ">" in t) and set(t) <= set("<>&"):
                if st["cur"] and st["cur"][-1].isdigit():
                    st["cur"].pop()                            # 2>/dev/null 的 2
                if t == "<" and i + 1 < len(toks):
                    st["stdin"] = toks[i + 1]
                i += 2
                continue
            close(t)
            i += 1
            continue
        st["cur"].append(t)
        i += 1
    close(";")
    return cmds


PREFIX_ARG_OPTS = {"sudo": {"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D", "-R", "-T"}, "doas": {"-u", "-C"},
                   "env": {"-u", "-C", "-S"}, "timeout": {"-s", "-k"}, "nice": {"-n"}}


def strip_prefix(cmd):
    """去掉指令前面的 if、!、sudo、VAR=…、env、timeout N、nice -n N 等；回傳 (指令名稱, 引數)。
    sudo -u／-g 等帶值的選項連值一起跳過。"""
    i = 0
    while i < len(cmd):
        t = os.path.basename(cmd[i])
        if re.match(r"^[A-Za-z_]\w*=", cmd[i]) or (t in CMD_PREFIX and t not in PREFIX_ARG_OPTS):
            i += 1
            continue
        if t in PREFIX_ARG_OPTS:
            opts, i = PREFIX_ARG_OPTS[t], i + 1
            while i < len(cmd) and cmd[i].startswith("-") and cmd[i] != "-":
                if cmd[i] == "--":
                    i += 1
                    break
                i += 2 if cmd[i] in opts else 1
            if t == "env":
                while i < len(cmd) and re.match(r"^[A-Za-z_]\w*=", cmd[i]):
                    i += 1
            if t == "timeout" and i < len(cmd):
                i += 1                                     # 時間長度
            continue
        break
    if i >= len(cmd):
        return None, []
    name, args = os.path.basename(cmd[i]), cmd[i + 1:]
    if name == "busybox" and args:
        name, args = os.path.basename(args[0]), args[1:]
    return name, args


GREP_LONG = {"extended-regexp": "E", "fixed-strings": "F", "word-regexp": "w", "line-regexp": "x", "ignore-case": "i"}


def grep_args(args):
    """grep 的引數 → (樣式清單, 檔案清單, 旗標集合)；-f、-v（不明確）→ None。"""
    pats, files, flags, i = [], [], set(), 0
    while i < len(args):
        a = args[i]
        if a == "--":
            rest = args[i + 1:]
            if not pats and rest:
                pats, rest = [rest[0]], rest[1:]
            files += rest
            break
        if a.startswith("--"):
            k, eq, v = a[2:].partition("=")
            if k in ("file", "invert-match"):
                return None
            if k == "regexp":
                if eq:
                    pats.append(v)
                elif i + 1 < len(args):
                    pats.append(args[i + 1])
                    i += 1
            elif k in GREP_LONG:
                flags.add(GREP_LONG[k])
            elif k in ("max-count", "after-context", "before-context", "context") and not eq:
                i += 1
            i += 1
            continue
        if a.startswith("-") and len(a) > 1:
            j = 1
            while j < len(a):
                c = a[j]
                if c in "fv":
                    return None
                if c == "e":
                    if a[j + 1:]:
                        pats.append(a[j + 1:])
                    elif i + 1 < len(args):
                        pats.append(args[i + 1])
                        i += 1
                    break
                if c in "mABC":
                    if not a[j + 1:]:
                        i += 1
                    break
                flags.add(c)
                j += 1
            i += 1
            continue
        if not pats:
            pats.append(a)
        else:
            files.append(a)
        i += 1
    return (pats, files, flags) if pats else None


START_ANCHORS = ("^", "\\<", "\\b")
END_ANCHORS = ("[[:space:]]", "[[:blank:]]", "[ \\t]", "[ ]", "\\s", "\\b", "\\>", "\\t", " ", "$")


def grep_pattern(pat, flags):
    """乾淨的樣式 → [(名稱, mode)]，mode：exact／prefix／suffix／substring；含其他正規表示式字元的 → None（不猜）。"""
    if "F" in flags:
        p = pat.strip()
        if not mod_name_ok(p):
            return None
        return [(p, "exact" if flags & {"w", "x"} else ("suffix" if pat.endswith(" ") else "substring"))]
    if "E" not in flags:                       # BRE（GNU）：\| \( \) 才是語法，| ( ) 是字面（名稱裡不會有）
        pat = (pat.replace("\\|", "\0").replace("\\(", "\2").replace("\\)", "\3").replace("|", "\1").replace("(", "\1")
               .replace(")", "\1").replace("\0", "|").replace("\2", "(").replace("\3", ")"))
    alts, depth, cur = [], 0, ""
    for ch in pat:
        depth += (ch == "(") - (ch == ")")
        if ch == "|" and depth == 0:
            alts.append(cur)
            cur = ""
        else:
            cur += ch
    alts.append(cur)
    out = []
    for a in alts:
        start = end = bool(flags & {"w", "x"})
        changed = True
        while changed:
            changed = False
            for s in START_ANCHORS:
                if a.startswith(s):
                    a, start, changed = a[len(s):], True, True
                    break
        changed = True
        while changed:
            changed = False
            if a.endswith(".*"):
                a, changed = a[:-2], True
                continue
            if a.endswith(("+", "*")) and a[:-1].endswith(END_ANCHORS):
                a, changed = a[:-1], True
                continue
            for e in END_ANCHORS:
                if a.endswith(e) and len(a) > len(e):
                    a, end, changed = a[:-len(e)], True, True
                    break
        names = a[1:-1].split("|") if a.startswith("(") and a.endswith(")") else [a]
        if not all(mod_name_ok(n) for n in names):
            return None
        mode = "exact" if start and end else "prefix" if start else "suffix" if end else "substring"
        out += [(n, mode) for n in names]
    return out


def modprobe_names(args):
    """modprobe 的引數 → (模組名稱清單, 是否 -r)；-S／-d（別的核心或根目錄）、-c、-l → []。"""
    remove = every = False
    pos, i = [], 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            k, eq, _v = a[2:].partition("=")
            if k in ("set-version", "dirname", "showconfig", "show-config", "list", "dump-modversions"):
                return [], False
            if k == "config" and not eq:
                i += 1
            remove |= k == "remove"
            every |= k == "all"
        elif a.startswith("-") and len(a) > 1:
            if any(c in a for c in "Sdcl"):
                return [], False
            if a.endswith("C"):
                i += 1
            remove |= "r" in a
            every |= "a" in a
        else:
            pos.append(a)
        i += 1
    names = [p for p in pos if "=" not in p] if (remove or every) else pos[:1]
    return [n for n in names if mod_name_ok(n)], remove


def cmd_refs(name, args, prev, stdin, funcs, depth):
    """一個指令 → [(名稱, ctx, mode, icase)]。"""
    out = []
    if name == "modprobe":
        names, remove = modprobe_names(args)
        out += [(n, "modprobe-r" if remove else "modprobe", "exact", False) for n in names]
    elif name == "rmmod":
        for a in args:
            if not a.startswith("-"):
                n = ko_name(a) or (a if mod_name_ok(a) else None)
                if n:
                    out.append((n, "rmmod", "exact", False))
    elif name == "insmod":
        pos = [a for a in args if not a.startswith("-")]
        if pos and ko_name(pos[0]):
            out.append((ko_name(pos[0]), "insmod", "exact", False))
    elif name in ("grep", "egrep", "fgrep"):
        g = grep_args(args)
        if g:
            pats, files, flags = g
            flags |= {"egrep": {"E"}, "fgrep": {"F"}}.get(name, set())
            ctx = None
            if "/proc/modules" in files or stdin == "/proc/modules":
                ctx = "proc-modules"
            elif prev and not files and stdin is None:
                pn, pa = strip_prefix(prev)
                if pn == "lsmod" and not pa:
                    ctx = "lsmod"
                elif pn == "cat" and pa == ["/proc/modules"]:
                    ctx = "proc-modules"
            if ctx:
                for p in pats:
                    out += [(n, ctx, mode, "i" in flags) for n, mode in grep_pattern(p, flags) or []]
    elif name in ("sh", "bash", "dash", "ash") and "-c" in args and depth < 2:
        k = args.index("-c")
        if k + 1 < len(args):
            out += line_refs(args[k + 1], funcs, depth + 1)
    elif name in funcs and depth < 2:
        for idx, probes in funcs[name].items():
            if idx - 1 < len(args) and mod_name_ok(args[idx - 1]):
                arg = args[idx - 1]
                got = []
                # 引數代進函式裡的那一行，照一般的行解析：真的是 grep /proc/modules（或 lsmod | grep）才算；
                # 只是提到 lsmod（lsmod > "$1"、echo "see lsmod for $1"）不算，不猜
                for probe, rx in probes:
                    got += [r for r in line_refs(rx.sub(arg, probe), {}, depth + 1) if r[0] == arg]
                out += [(n, "function", mode, ic) for n, _c, mode, ic in got]
    return out


def quoted_substitutions(line):
    """雙引號裡的 $(…) 與 `…`（照樣會執行）→ 內容清單；單引號裡的是字面、引號外的由 tokens 處理。"""
    out, i, q = [], 0, None
    while i < len(line):
        c = line[i]
        if c == "\\" and q != "'":
            i += 2
            continue
        if q is None and c == "#" and (i == 0 or line[i - 1] in " \t;"):
            break
        if c in "'\"" and (q is None or q == c):
            q = None if q == c else c
        elif q == '"' and line.startswith("$(", i) and not line.startswith("$((", i):
            depth, j = 1, i + 2
            while j < len(line) and depth:
                depth += (line[j] == "(") - (line[j] == ")")
                j += 1
            if depth == 0:
                out.append(line[i + 2:j - 1])
                i = j
                continue
        elif q == '"' and c == "`":
            j = line.find("`", i + 1)
            if j > 0:
                out.append(line[i + 1:j])
                i = j + 1
                continue
        i += 1
    return out


def line_refs(line, funcs, depth=0, toks=None):
    if toks is None:
        try:
            toks = shell_tokens(line)
        except ValueError:
            return []
    out = []
    for cmd, prev, stdin in shell_commands(toks):
        name, args = strip_prefix(cmd)
        if name and name not in NOT_A_TEST:
            out += cmd_refs(name, args, prev, stdin, funcs, depth)
    if depth < 3 and ("$(" in line or "`" in line):
        for sub in quoted_substitutions(line):
            out += line_refs(sub, funcs, depth + 1)
    return out


def shell_functions(lines):
    """同一個檔案裡讀 /proc/modules（或 lsmod）的函式 → {名稱: {第幾個引數: [(那一行, 代換用的正規表示式)]}}。
    只認函式裡讀 /proc/modules 的那一行用到 $N（或 local x=$N 的 $x）的引數。"""
    funcs, i = {}, 0
    while i < len(lines):
        m = FUNC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        fname, depth, opened, body, j = m.group(1) or m.group(2), 0, False, [], i
        while j < len(lines) and j - i < 300:
            text = lines[j] if j > i else (m.group(3) or "")
            depth += text.count("{") - text.count("}")
            opened |= "{" in text
            body.append(text)
            j += 1
            if opened and depth <= 0:
                break
        i = max(j, i + 1)
        assign = {}
        for b in body:
            for var, n in ASSIGN_RE.findall(b):
                assign[var] = int(n)
        probes = {}
        for b in body:
            if b.lstrip().startswith("#") or not any(p in b for p in PROBE):
                continue
            for n in range(1, 10):
                pats = [r"\$\{?%d\}?(?![0-9])" % n] + [r"\$\{?%s\}?(?!\w)" % re.escape(v) for v, k in assign.items() if k == n]
                rx = re.compile("|".join(pats))
                if rx.search(b):
                    probes.setdefault(n, []).append((b, rx))
        if probes:
            funcs[fname] = probes
    return funcs


def shell_refs(text):
    funcs = shell_functions(text.split("\n")) if any(p in text for p in PROBE) else {}
    out = []
    for n, line, toks in shell_logical_lines(text):
        if toks is None or not (any(t in line for t in TRIGGER_STR) or any(f in line for f in funcs)):
            continue
        out += [ref(n, *r) for r in line_refs(line, funcs, 0, toks)]
    return out


def kernel_modules(img):
    """映像裡的核心模組：{版本: {loadable, builtin, aliases, alias_globs, lists, dirs}}、核心資料夾以外的 .ko 名稱、
    名稱是 .ko 卻不是核心模組（不是 ELF ET_REL，例如 vim 的 tutor.ko）的個數。
    /lib/modules/<版本>/ 與 /usr/lib/modules/<版本>/ 是兩個各自存在的資料夾時（L4T）合在一起；連結到同一個資料夾的只看一次。"""
    kernels, other, not_mod = {}, set(), 0
    for base in MOD_BASES:
        p, vers = img.listdir(base)
        if p != base:
            continue                                  # lib → usr/lib 的連結：同一個資料夾只看一次
        for v in vers:
            vp, node = img.lookup(f"{base}/{v}")
            if node is None or node[0] != "dir":
                continue
            K = kernels.setdefault(v, {"loadable": set(), "builtin": set(), "aliases": set(), "alias_globs": set(), "lists": [],
                                       "dirs": []})
            if vp not in K["dirs"]:
                K["dirs"].append(vp)
    for p, node in img.nodes.items():
        if ".ko" not in p or node[0] not in ("file", "hardlink", "symlink"):
            continue
        n = ko_name(p)
        if not n:
            continue
        kind = img.ko_kind.get(p)
        if kind is None and node[0] == "symlink":
            kind = img.ko_kind.get(img.resolve(p) or "")
        if kind is None and node[0] == "hardlink":
            kind = img.ko_kind.get(img.hard.get(p) or "")
        if kind == "not_module":                      # 判斷不了的（unknown、沒讀到）照樣算模組：偏保守
            not_mod += 1
            continue
        parts = p.split("/")
        k = 2 if parts[0] == "lib" else 3 if parts[:2] == ["usr", "lib"] else None
        if k is not None and len(parts) > k + 1 and parts[k - 1] == "modules" and parts[k] in kernels:
            kernels[parts[k]]["loadable"].add(mod_norm(n))
        else:
            other.add(mod_norm(n))
    for K in kernels.values():
        for d in K["dirs"]:
            for lst in ("modules.dep", "modules.order", "modules.builtin", "modules.alias", "modules.builtin.alias"):
                data = img.read(f"{d}/{lst}")
                if data is None:
                    continue
                if lst not in K["lists"]:
                    K["lists"].append(lst)
                dest = K["builtin"] if lst.startswith("modules.builtin") else K["loadable"]
                for line in data.decode("utf-8", "replace").splitlines():
                    if lst.endswith("alias"):
                        w = line.split()
                        if len(w) >= 3 and w[0] == "alias" and mod_name_ok(w[2]):
                            a = mod_norm(w[1])
                            if ":" not in a:              # pci:、usb:、of: 等硬體 alias 不會出現在腳本裡
                                (K["alias_globs"] if any(c in a for c in "*?[") else K["aliases"]).add(a)
                            dest.add(mod_norm(w[2]))
                        continue
                    for tok in (line.replace(":", " ").split() if lst == "modules.dep" else [line.strip()]):
                        n = ko_name(tok)
                        if n:
                            dest.add(mod_norm(n))
    return kernels, other, not_mod


def mod_exists(r, pool, aliases, globs):
    """pool：現有的名稱（icase 的引用傳小寫的集合）。"""
    n = mod_norm(r["name"])
    if r["icase"]:
        n = n.lower()
    mode = r["mode"]
    if mode == "exact":
        return n in pool or (r["ctx"] in MOD_ALIAS_OK and (n in aliases or any(fnmatch.fnmatchcase(n, g) for g in globs)))
    if mode == "prefix":
        return any(x.startswith(n) for x in pool)
    if mode == "suffix":
        return any(x.endswith(n) for x in pool)
    return any(n in x for x in pool)


# 有沒有相近的現有名稱分開：有 → 多半是打錯字（檢查或 blacklist 沒有作用，真正的模組沒被檢查到）；
# 沒有 → 這個核心沒有這個模組（可能沒編進核心）：檢查不會有作用但也沒有風險，嚴重度降一級
MOD_GROUPS = [  # (種類, 套件的檔案, 有相近名稱（None：不分）, id, 嚴重度, 標題, 說明, Annex, 板子上確認)
    ("script", False, True, "modules:name-not-in-image", "medium",
     "Kernel module name in a script does not exist in this image (likely a typo)",
     "reference(s) in shell scripts, systemd units or modules-load lists that are not from a distribution package name a kernel "
     "module that this image does not have, and a close existing name exists", ("I-2b", "I-2k"),
     "Run the script on a flashed board with the intended module loaded (lsmod, modinfo) and check that it reports it."),
    ("script", False, False, "modules:module-not-built", "low",
     "Script checks a kernel module this kernel does not have",
     "reference(s) in shell scripts, systemd units or modules-load lists that are not from a distribution package name a kernel "
     "module that this image does not have, and no existing name is close", ("I-2b",),
     "Confirm in the kernel configuration that the module is not built (=n), not built in."),
    ("script", True, True, "modules:name-not-in-image-packages", "low",
     "Kernel module name in a distribution package script does not exist in this image (likely a typo)",
     "reference(s) in files from distribution packages name a kernel module that this image does not have, and a close "
     "existing name exists", ("I-2b",), ""),
    ("script", True, False, "modules:module-not-built-packages", "info",
     "Distribution package script names a kernel module this kernel does not have",
     "reference(s) in files from distribution packages name a kernel module that this image does not have, and no existing "
     "name is close (usually a driver this kernel does not build)", ("I-2b",), ""),
    # 廠商的 blacklist／install … /bin/false 打錯字：緩解措施擋不到真正的模組 → 和腳本一樣是 medium
    ("config", False, True, "modules:blacklist-not-in-image", "medium",
     "modprobe.d blacklist for a module name that does not exist (likely a typo)",
     "modprobe.d blacklist or install-disable line(s) that are not from a distribution package name a kernel module that this "
     "image does not have, and a close existing name exists", ("I-2b", "I-2j", "I-2k"),
     "On a flashed board, check with modprobe -n -v that the module meant is really blocked."),
    ("config", False, False, "modules:blacklist-module-not-built", "info",
     "modprobe.d blacklist for a kernel module this kernel does not have",
     "modprobe.d blacklist or install-disable line(s) that are not from a distribution package name a kernel module that this "
     "image does not have, and no existing name is close", ("I-2j",),
     "Confirm in the kernel configuration that the module is not built (=n), not built in."),
    ("config", True, None, "modules:blacklist-not-in-image-packages", "info",
     "Distribution modprobe.d blacklist for module names this kernel does not have",
     "modprobe.d blacklist or install-disable line(s) from distribution packages name kernel modules that this image does not "
     "have (usually drivers this kernel does not build)", ("I-2j",), ""),
]
MOD_EFFECT = {
    ("script", True): "A check such as grep \"^NAME \" /proc/modules then never matches and always reports \"not loaded\", and "
                      "modprobe or rmmod of the name does nothing: the check or mitigation silently has no effect, so the security "
                      "test it performs gives a wrong result and the module that was meant (see the closest existing names) is "
                      "not checked. Usually a typo.",
    ("script", False): "This kernel does not have the module (probably not built). The check has no effect but there is no risk "
                       "either: remove it, or check the kernel configuration instead.",
    ("config", True): "A blacklist for a name that is not a module protects nothing: if it is a typo, the module that was meant "
                      "(see the closest existing names) can still be loaded.",
    ("config", False): "This kernel does not have the module (probably not built). The blacklist has no effect but there is no "
                       "risk either: remove it, or check the kernel configuration instead.",
}


MOD_METHOD = ("clear references only: grep of /proc/modules (file, < or cat |) or after lsmod | with a plain-name pattern "
              "(anchors and (a|b) allowed), also inside a double-quoted $(...) or `...`; modprobe [-r]; rmmod; insmod NAME.ko; sh -c; "
              "sudo/env/timeout/nice prefixes; calls of a same-file function whose /proc/modules or lsmod grep line uses the "
              "argument ($N or local x=$N); modprobe.d blacklist and install NAME /bin/false|/bin/true|exit (modprobe.d alias "
              "names count as existing for modprobe); modules-load.d and /etc/modules names. '-' and '_' are the same name; "
              ".ko files count only if they are ELF ET_REL (or cannot be checked, e.g. zstd). Not supported (not checked, never "
              "guessed): comments, echo/printf strings, heredoc bodies, variables and loops (modprobe $m, for m in ...), patterns "
              "with other regex characters, grep -v / -f, awk/sed/cut/[ -d /sys/module/NAME ] checks, functions defined in "
              "another file, modprobe -S / -d (another kernel or root)")


def check_modules(img, owners):
    kernels, other, not_mod = kernel_modules(img)
    names, aliases, globs = set(other), set(img.mod_aliases), set()
    for K in kernels.values():
        names |= K["loadable"] | K["builtin"]
        aliases |= K["aliases"]
        globs |= K["alias_globs"]
    kinfo = [{"version": clean(v), "dirs": ["/" + clean(d) for d in K["dirs"]], "loadable": len(K["loadable"]),
              "builtin": len(K["builtin"]), "aliases": len(K["aliases"]) + len(K["alias_globs"]), "lists": K["lists"]}
             for v, K in sorted(kernels.items())]
    refs = sorted(((p, r) for p, rs in img.modrefs.items() for r in rs), key=lambda x: (x[0], x[1]["line"], x[1]["name"]))
    data = {"status": "ran", "kernels": kinfo, "ko_outside_kernel_dirs": len(other), "ko_not_modules": not_mod,
            "modprobe_d_aliases": len(img.mod_aliases), "files_scanned": len(img.script_files),
            "references": len(refs), "unknown": [], "unknown_total": 0,
            "scope": "shell scripts (shebang or .sh), systemd .service Exec*= lines, modprobe.d, modules-load.d and /etc/modules under "
                     + ", ".join("/" + d for d in SCRIPT_DIRS) + f"; up to {SCRIPT_MAX >> 10} KiB per file (self-extracting "
                     "scripts: the part before the first NUL)",
            "method": MOD_METHOD}
    if not names:
        data["status"] = "not run"
        data["note"] = "no kernel module directory or module lists (/lib/modules/<version>/) in the image"
        data["_result"] = "NOT RUN (no kernel module lists in the image)"
        if refs:
            img.note("modules_unchecked", f"{len(refs)} reference(s)")
        return data, []
    missing = [K["version"] for K in kinfo if "modules.builtin" not in K["lists"]]
    pool, lower = sorted(names), {x.lower() for x in names}
    rows, close, known = [], {}, {}
    for path, r in refs:
        # 同一個引用（名稱、寫法）只判斷一次：硬連結的許多名稱、重複的呼叫都共用結果
        key = (mod_norm(r["name"]), r["mode"], r["icase"], r["ctx"] in MOD_ALIAS_OK)
        if key not in known:
            known[key] = mod_exists(r, lower if r["icase"] else names, aliases, globs)
        if known[key]:
            continue
        n = mod_norm(r["name"])
        if n not in close:
            close[n] = difflib.get_close_matches(n, pool, n=3, cutoff=0.6)
        rows.append({"path": "/" + clean(path), "line": r["line"], "name": clean(r["name"], 80), "context": MOD_CTX[r["ctx"]],
                     "closest": close[n],
                     "origin": owners.origin(path), "kind": "config" if r["ctx"] in ("blacklist", "install") else "script",
                     "_pkg": owners.available and path in owners.map})
    data["unknown_total"] = len(rows)

    def ev(r):
        return f"{r['path']}:{r['line']} {r['name']} ({r['context']}; closest existing: {', '.join(r['closest']) or 'none'})"
    vers = ", ".join(K["version"] for K in kinfo)
    note = f" modules.builtin is missing for kernel {', '.join(missing)}: a name may be built in." if missing else ""
    findings = []
    for kind, pkg, close, fid, sev, title, what, annex, confirm in MOD_GROUPS:
        g = [r for r in rows if r["kind"] == kind and r["_pkg"] == pkg and close in (None, bool(r["closest"]))]
        if not g:
            continue
        effect = (MOD_EFFECT[(kind, True)] + " If no close name is listed, the kernel does not have the module." if close is None
                  else MOD_EFFECT[(kind, close)])
        findings.append(finding(fid, "modules", sev, title,
                                f"{len(g)} {what} (no .ko file and not in modules.dep, modules.order, modules.builtin or "
                                f"modules.alias of kernel {vers}). {effect}{note}", annex, [ev(r) for r in g], confirm))
    for r in rows:
        r.pop("_pkg")
    data["unknown"] = rows[:LIST_MAX]
    return data, findings


NEEDS_BOARD = [
    "Listening sockets and their processes on a freshly flashed board (`ss -tulpn`), including services started by "
    "first-boot setup (oem-config), udev, cron, containers or vendor scripts that are not systemd units.",
    "Accounts, passwords and SSH host keys created or changed at first boot or by flash.sh (this check sees the image only).",
    "Kernel hardening (KASLR, lockdown, module signing, effective sysctl values such as kptr_restrict, ptrace_scope); "
    "secure boot and disk encryption state.",
    "Firewall rules actually loaded (nftables/iptables), Wi-Fi and Bluetooth exposure.",
    "Strength of passwords and keys; whether the keys found here are actually used.",
]


# ---------- 報告 ----------

def md_cell(x):
    s = clean(x if x is not None else "")
    return s.replace("|", "\\|").replace("`", "'")


def code(x):
    return f"`{md_cell(x)}`" if x else ""


def write_report(res, out):
    L = ["# Image static security check", "",
         f"Source: {md_cell(res['source']['type'])} `{md_cell(res['source']['file'])}`"
         + (f", root filesystem at `{md_cell(res['source']['prefix'])}`" if res["source"].get("prefix") else "")
         + f"; generated {res['generated']} by `tools/cra/image_check.py`.", "",
         "This is a static, offline check of the root filesystem image (nothing in the image was executed and no board was "
         "used). Findings are **items to review**, not verdicts: each one names the Annex I Part I (2) requirement it informs "
         "and what to confirm on a real board. It is security test evidence for the technical documentation "
         "(Annex VII point 6, Annex I Part II (3)). No password hash, key material or credential value is copied into this report.", "",
         f"Overall: **{res['status']}**. {md_cell(res['summary'])}", "",
         "## Summary", "", "| Check | Result | Informs |", "|---|---|---|"]
    for c in res["checks"]:
        L.append(f"| {md_cell(c['title'])} | {md_cell(c['result'])} | {', '.join(c['annex'])} |")
    L += ["", "## Findings to review", ""]
    if not res["findings"]:
        L += ["None.", ""]
    for f in res["findings"]:
        L += [f"### [{f['severity']}] {md_cell(f['title'])}", "",
              f"Informs: {'; '.join(ANNEX[a] for a in f['annex'])}.", "", md_cell(f["text"]), ""]
        if f["evidence"]:
            more = f["evidence_total"] > len(f["evidence"])
            L.append("Evidence" + (f" (first {len(f['evidence'])} of {f['evidence_total']})" if more else "") + ":")
            L += [f"- {code(e)}" for e in f["evidence"][:30]]
            if len(f["evidence"]) > 30:
                L.append(f"- … {f['evidence_total'] - 30} more in image-check.json")
            L.append("")
        if f["confirm_on_board"]:
            L += [f"Confirm on a board: {md_cell(f['confirm_on_board'])}", ""]
    s = res["services"]
    L += ["## Services enabled at boot", "",
          f"Default target: {code(s['default_target']) or 'not found'}. Listed: units enabled in /etc/systemd/system, network "
          "services from any location, SysV scripts without a systemd unit. All units reached from the default target are in "
          "image-check.json.", "", "| Unit | State | Executable | Package | Network service |", "|---|---|---|---|---|"]
    shown = [u for u in s["units"] if u["admin_enabled"] or u["network_service"]]
    for u in shown[:LIST_MAX]:
        L.append(f"| {code(u['unit'])} | {md_cell(u['state'])} | {code(u['exec'])} | {md_cell(u['package'])} | "
                 f"{md_cell(u['network_service'] or '')}{(' — ' + md_cell(', '.join(u['listen']))) if u['listen'] else ''} |")
    if s["masked"]:
        L += ["", "Masked: " + ", ".join(code(m) for m in s["masked"][:50])]
    if s.get("preset_files") or s.get("preset_enabled"):
        L += ["", f"/etc/machine-id: {s['machine_id']} ("
              + ("systemd applies the presets at first boot" if s["first_boot_presets"] else
                 "presets are applied only if the file is removed or set to 'uninitialized'; an empty file is not a first boot") + "). "
              + f"Units the presets would add: {', '.join(code(n) for n in s['preset_enabled'][:50]) or 'none'}. "
              + f"Preset files: {', '.join(code(f) for f in s['preset_files'][:20]) or 'none'}."]
    L.append("")
    ss = res["ssh"]
    L += ["## SSH server", ""]
    if ss.get("note"):
        L += [md_cell(ss["note"]) + ".", ""]
    else:
        L += [f"Enabled at boot: {', '.join(code(u) for u in ss['enabled_at_boot']) or 'no'}. Config files read: "
              + (", ".join(code(f) for f in ss["files"]) or "none") + ".", "", "| Setting | Effective value | Source |", "|---|---|---|"]
        L += [f"| {k} | {code(v['value'])} | {md_cell(v['source'])}{('; overrides ' + md_cell(v['overrides'])) if v.get('overrides') else ''} |"
              for k, v in ss["effective"].items()]
        if ss["conditional"]:
            L += ["", "Conditional (Match blocks): " + "; ".join(f"{md_cell(c['keyword'])} {md_cell(c['value'])} (Match {md_cell(c['match'])}, "
                                                                f"{md_cell(c['where'])})" for c in ss["conditional"][:20])]
        if ss["notes"]:
            L += ["", "Notes: " + "; ".join(md_cell(n) for n in ss["notes"])]
        L.append("")
    L += [f"Host private keys in the image: {', '.join(code(h) for h in ss['host_private_keys']) or 'none'}.", ""]
    a = res["accounts"]
    L += ["## Accounts", "", f"Password status is derived from /etc/shadow ({md_cell(a['shadow'])}); hashes are never copied. "
          "Accounts without a login shell are listed only if their password is not locked.", "",
          "| Account | UID | Shell | Password |", "|---|---|---|---|"]
    for r in a["accounts"]:
        if r["login_shell"] or r["uid"] == 0 or r["password"] in ("empty", "set"):
            L.append(f"| {code(r['name'])} | {r['uid']} | {code(r['shell'])} | {md_cell(r['password'])}"
                     f"{(' (' + md_cell(r['hash_scheme']) + ')') if r['hash_scheme'] else ''} |")
    L.append("")
    p = res["permissions"]
    L += ["## setuid / setgid and world-writable", "",
          f"{p['setuid_setgid_total']} setuid/setgid file(s); {p['world_writable_files_total']} world-writable file(s) outside "
          f"temporary directories; {p['world_writable_dirs_total']} world-writable director(ies) without the sticky bit. "
          f"File owners: {md_cell(p['owner_info'])}.", "", "| Path | Mode | Origin |", "|---|---|---|"]
    L += [f"| {code(r['path'])} | {r['mode']} {md_cell(r.get('bits', 'world-writable'))} | {md_cell(r['origin'])} |"
          for r in (p["setuid_setgid"] + p["world_writable_files"] + p["world_writable_dirs"])[:100]]
    L.append("")
    sc = res["secrets"]
    L += ["## Private keys and credentials", "", f"Scope: {md_cell(sc['scope'])}. Found {sc['total']}.", ""]
    if sc["items"]:
        L += ["| Path | Type | Origin |", "|---|---|---|"]
        L += [f"| {code(r['path'] + (':' + str(r['line']) if r.get('line') else ''))} | {md_cell(r['type'])}"
              f"{(', ' + md_cell(r['protection'])) if r.get('protection') else ''}{(', ' + md_cell(r['where'])) if r.get('where') else ''}"
              f" | {md_cell(r['origin'])} |" for r in sc["items"][:100]]
        L.append("")
    e = res["elf"]
    c = e["counts"]
    L += ["## ELF hardening", "", f"Scope: {md_cell(e['scope'])}. Method: {md_cell(e['method'])}.", "",
          "| | Count |", "|---|---|",
          f"| Executables | {c.get('exe', 0)} (PIE {c.get('exe_pie', 0)}, not PIE {c.get('exe_no_pie', 0)}) |",
          f"| Shared libraries | {c.get('lib', 0)} |",
          f"| NX stack: yes / no / no PT_GNU_STACK | {c.get('nx_yes', 0)} / {c.get('nx_no', 0)} / {c.get('nx_unknown', 0)} |",
          f"| RELRO: full / partial / none | {c.get('relro_full', 0)} / {c.get('relro_partial', 0)} / {c.get('relro_none', 0)} |",
          f"| Stack canary: yes / no / unknown | {c.get('canary_yes', 0)} / {c.get('canary_no', 0)} / {c.get('canary_unknown', 0)} |",
          f"| Static / other ELF types / malformed | {c.get('static', 0)} / {c.get('other_type', 0)} / {c.get('malformed', 0)} |", "",
          "Listed below: files not from a distribution package (or in /opt, /usr/local) with any missing mitigation first, then "
          "package files missing PIE, NX or RELRO. A missing canary is normal for code without local arrays.", "",
          "| Path | Type | Missing | Origin |", "|---|---|---|---|"]
    L += [f"| {code(r['path'])} | {r['kind']} {md_cell(r['machine'])} | {md_cell(', '.join(r['issues']))} | {md_cell(r['origin'])} |"
          for r in e["listed"][:100]]
    if e["listed_total"] > 100:
        L.append(f"| … {e['listed_total'] - 100} more in image-check.json | | | |")
    mo = res["modules"]
    L += ["", "## Kernel module names in scripts", "", f"Scope: {md_cell(mo['scope'])}. Method: {md_cell(mo['method'])}.", ""]
    if mo["status"] != "ran":
        L += [f"Not run: {md_cell(mo.get('note') or mo['status'])}; {mo['references']} reference(s) in "
              f"{mo['files_scanned']} file(s) were not checked.", ""]
    else:
        L += ["Kernel module lists: " + "; ".join(
            f"{code(k['version'])} ({k['loadable']} loadable, {k['builtin']} built-in, {k['aliases']} aliases; "
            f"{', '.join(k['lists']) or 'no lists, .ko files only'})" for k in mo["kernels"])
              + f". .ko files elsewhere: {mo['ko_outside_kernel_dirs']}. Files read: {mo['files_scanned']}; references: "
              f"{mo['references']}; names not in this image: {mo['unknown_total']}.", ""]
        if mo["unknown"]:
            L += ["| File:line | Name | Context | Closest existing | Origin |", "|---|---|---|---|---|"]
            L += [f"| {code(r['path'] + ':' + str(r['line']))} | {code(r['name'])} | {md_cell(r['context'])} | "
                  f"{', '.join(code(c) for c in r['closest']) or 'none'} | {md_cell(r['origin'])} |" for r in mo["unknown"][:100]]
            if mo["unknown_total"] > 100:
                L.append(f"| … {mo['unknown_total'] - 100} more in image-check.json | | | | |")
            L.append("")
    L += ["## Not checked here (needs board test)", ""] + [f"- {md_cell(x)}" for x in NEEDS_BOARD] + [""]
    cv = res["coverage"]
    L += ["## Coverage", "", f"Entries in the image: {cv['entries']}. " + ("; ".join(f"{md_cell(k)}: {v}" for k, v in cv["counts"].items())
                                                                           or "Nothing skipped.") + ""]
    Path(out).write_text("\n".join(L) + "\n", encoding="utf-8")


COV_LABEL = {"rejected": "rejected members (absolute, .., or path too long)", "unreadable": "unreadable entries",
             "hardlink_missing": "hardlinks whose content was not available", "cap_text_file": "config files over the size limit",
             "cap_text_total": "config files over the total limit", "cap_secret_total": "files not scanned for keys (total limit)",
             "cap_elf_files": "ELF files not checked (count limit)",
             "cap_secret_elf": "ELF files not fully scanned for embedded keys (size limit)",
             "cap_include": "sshd_config Include expansion stopped (limit)",
             "cap_secret_large": "large non-ELF files not fully scanned for keys (size limit)",
             "preset_unreadable": "systemd preset files that could not be read",
             "cap_preset": "systemd preset Also= expansion stopped (limit)",
             "cap_script_file": "shell scripts over the size limit (kernel module names not checked)",
             "cap_script_total": "scripts not checked for kernel module names (total limit)",
             "cap_modrefs": "kernel module name references over the limit (not checked)",
             "modules_unchecked": "kernel module names in scripts not checked (no module lists in the image)"}
COV_INFO = {"cap_secret_large"}      # 只記數量，不算不完整：這些檔案以前完全不掃


def run(src, prefix, out):
    img, source = load_image(src, prefix)
    owners = Owners(img)
    res = {"schema": SCHEMA, "tool_version": TOOL_VERSION, "source": source,
           "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "limits": {"text_file": TEXT_MAX, "secret_file": SECRET_MAX, "script_file": SCRIPT_MAX, "elf_files": ELF_MAX_FILES, "symlink_hops": MAX_HOPS}}
    findings, checks, errors = [], [], []
    spec = [("services", "Services enabled at boot", ("I-2b", "I-2j"), lambda: check_services(img, owners)),
            ("ssh", "SSH server configuration and host keys", ("I-2b", "I-2d"), lambda: check_ssh(img, res["services"])),
            ("accounts", "Accounts and passwords", ("I-2b", "I-2d"), lambda: check_accounts(img)),
            ("permissions", "setuid/setgid and world-writable", ("I-2d", "I-2k"), lambda: check_permissions(img, owners)),
            ("secrets", "Private keys and credentials", ("I-2d", "I-2e"), lambda: check_secrets(img, owners)),
            ("elf", "ELF hardening", ("I-2k",), lambda: check_elf(img, owners)),
            ("modules", "Kernel module names in scripts and modprobe.d", ("I-2b", "I-2j", "I-2k"), lambda: check_modules(img, owners))]
    empty = {"services": {"default_target": None, "units": [], "masked": [], "inetd": [], "systemd": False},
             "ssh": {"note": "check failed", "host_private_keys": [], "enabled_at_boot": []},
             "accounts": {"accounts": [], "shadow": "check failed", "sudo_nopasswd": [], "login_accounts": []},
             "permissions": {"setuid_setgid": [], "setuid_setgid_total": 0, "world_writable_files": [], "world_writable_files_total": 0,
                             "world_writable_dirs": [], "world_writable_dirs_total": 0, "owner_info": "check failed"},
             "secrets": {"items": [], "total": 0, "scope": "check failed"},
             "elf": {"counts": {}, "checked": 0, "listed": [], "listed_total": 0, "scope": "check failed", "method": ""},
             "modules": {"status": "check failed", "kernels": [], "ko_outside_kernel_dirs": 0, "files_scanned": 0, "references": 0,
                         "unknown": [], "unknown_total": 0, "scope": "check failed", "method": ""}}
    for key, title, annex, fn in spec:
        try:
            data, fs = fn()
        except Exception as e:          # 一項檢查出錯：其他照樣寫，整體 FAIL
            errors.append(f"{key}: {type(e).__name__}: {clean(e, 200)}")
            data, fs = empty[key], []
            result = f"FAIL ({type(e).__name__})"
        else:
            n = collections.Counter(f["severity"] for f in fs)
            result = data.pop("_result", None) or ", ".join(f"{n[s]} {s}" for s in SEV_ORDER if n[s]) or "nothing to review"
        res[key] = data
        findings += fs
        checks.append({"id": key, "title": title, "annex": list(annex), "result": result})
    # 映像裡的預設密碼：SSH 開著而且允許密碼登入 → 網路上就能用同一組密碼登入每一台 → high；只能從 console 登入 → medium；
    # SSH 的結果讀不到 → 不降級（high）
    pw = next((f for f in findings if f["id"] == "accounts:password-in-image"), None)
    if pw is not None:
        eff = ((res.get("ssh") or {}).get("effective") or {}).get("passwordauthentication") or {}
        ssh_on = any(f["id"] == "service:ssh" for f in findings)
        if "ssh" not in res or not eff:
            pw["severity"] = "high"
        elif ssh_on and (str(eff.get("value")).lower().split() or [""])[0] == "yes":
            pw["severity"] = "high"
            pw["text"] += " SSH is enabled with password login, so the same password works over the network on every device."
        else:
            pw["text"] += " SSH password login is off or SSH is not enabled at boot: console login only."
        # 嚴重度改了：帳號檢查那一列的結果字串跟著重算
        acc = [f for f in findings if f["check"] == "accounts"]
        for c in checks:
            if c["id"] == "accounts" and not c["result"].startswith("FAIL"):
                n = collections.Counter(f["severity"] for f in acc)
                c["result"] = ", ".join(f"{n[s]} {s}" for s in SEV_ORDER if n[s]) or "nothing to review"
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["check"], f["id"]))
    res["findings"] = findings
    res["checks"] = checks
    res["needs_board_test"] = NEEDS_BOARD
    # counts：不完整的項目（security_findings 也依它判斷）；info：只記數量、不算不完整（COV_INFO）
    res["coverage"] = {"entries": len(img.nodes),
                       "counts": {COV_LABEL.get(k, k): v for k, v in img.cov.items() if k not in COV_INFO},
                       "info": {COV_LABEL.get(k, k): v for k, v in img.cov.items() if k in COV_INFO},
                       "examples": {COV_LABEL.get(k, k): v for k, v in img.examples.items()}}
    n = collections.Counter(f["severity"] for f in findings)
    looks = img.lookup("etc/passwd")[1] is not None or res["services"]["systemd"]
    gaps = [f"{COV_LABEL.get(k, k)} {v}" for k, v in img.cov.items() if k not in COV_INFO]
    if errors:
        st = "FAIL"
    elif not looks:
        st = "GAP"
    elif n["high"] or n["medium"] or gaps:
        st = "ATTENTION"
    else:
        st = "OK"
    svc = [f["id"].split(":", 1)[1] for f in findings if f["check"] == "services" and f["id"].startswith("service:")
           and f["id"] not in ("service:enabled-not-reached", "service:preset-first-boot")]
    e, mo = res["elf"], res["modules"]
    summ = (f"To review: high {n['high']}, medium {n['medium']}, low {n['low']}, info {n['info']}. Network services at boot: {', '.join(svc) or 'none'}; "
            f"login accounts: {len(res['accounts']['login_accounts'])}; setuid/setgid: {res['permissions']['setuid_setgid_total']}; "
            f"keys/credentials: {res['secrets']['total']}; ELF checked: {e['checked']}; kernel module names not in the image: "
            + (str(mo["unknown_total"]) if mo["status"] == "ran" else "NOT RUN") + ".")
    res["status"], res["summary"], res["errors"] = st, summ, errors
    detail = (f"待檢視 high {n['high']}、medium {n['medium']}、low {n['low']}、info {n['info']}；開機啟動的網路服務：{'、'.join(svc) or '無'}；"
              f"可登入帳號 {len(res['accounts']['login_accounts'])}；setuid/setgid {res['permissions']['setuid_setgid_total']}；"
              f"私鑰／帳密 {res['secrets']['total']}；ELF {e['checked']} 個（列出 {e['listed_total']}，非套件或 /opt 等 {e.get('listed_vendor', 0)}）；"
              "腳本裡映像沒有的模組名稱 " + (str(mo["unknown_total"]) if mo["status"] == "ran" else "沒執行"))
    if not looks:
        detail = "不像 rootfs（沒有 etc/passwd 也沒有 systemd）；" + detail
    if gaps:
        detail += "；不完整：" + "、".join(gaps)
    if errors:
        detail += "；檢查出錯：" + "；".join(errors)
    os.makedirs(out, exist_ok=True)
    for name in ("image-check.json", "image-check.md"):
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(out, name))           # 不留上一次的檔案冒充這次的
    with open(os.path.join(out, "image-check.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    write_report(res, os.path.join(out, "image-check.md"))
    return st, detail


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", action="version", version=f"{SCHEMA} {TOOL_VERSION}")
    ap.add_argument("--from", dest="from_", required=True)
    ap.add_argument("--prefix")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        st, detail = run(a.from_, a.prefix, a.out)
    except Exception as e:              # 不可信的輸入：任何錯誤都要留下 FAIL 那一行
        print(f"D-image-check\tFAIL\t{clean(type(e).__name__ + ': ' + str(e), 400)}")
        return 3
    print(f"D-image-check\t{st}\t{detail[:480]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
