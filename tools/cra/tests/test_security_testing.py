"""安全測試接進 CRA 文件：board_import.py（板子結果的匯入與解析）、security_findings.py（整理、人工決定檔）、cra_report.py 的
第 9 節、技術文件第 6 項、security-findings.md、summary.json 的 security_testing。全部是合成的資料（虛構的主機名稱、私有 IP）。"""
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from test_cra_report import MIN_CFG, finding, make_project, make_scan, run, write_json

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import board_import as bi  # noqa: E402
import image_check as ic  # noqa: E402
import security_findings as sf  # noqa: E402

ROOT = HERE.parents[2]
BI = HERE.parent / "board_import.py"
SF = HERE.parent / "security_findings.py"
WRAPPER = ROOT / "tools" / "demo" / "board-import.sh"
HASH_MARK = "$6$Zq9HASHMARK$abcdefghijklmnopqrstuv"
KEY_MARK = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEKEYMARKAAAAAAAAAA\n-----END OPENSSH PRIVATE KEY-----"
PSK_MARK = "psk=WIFIPSKMARK123"
TOKEN_MARK = "glpat-" + "TOKENMARKabcdefghij12345"
SECRETS = ("Zq9HASHMARK", "KEYMARK", "WIFIPSKMARK", "TOKENMARK", "BEGIN OPENSSH")
BOARD = "board-test-exdev-20261103T010203Z"
NET = "board-net-192.0.2.20-20261103T020304Z"

BOARD_FILES = {
    "summary.txt": "check\tstatus\tdetail\nos\tOK\tos.txt\nlistening\tOK\tlistening.txt\nlynis\tNOT_RUN\t沒給 --lynis\n",
    "os.txt": 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 22.04.5 LTS"\n\n# R36 (release), REVISION: 4.3, GCID: 1, BOARD: generic\n\nLinux exdev 5.15\n',
    "listening.txt": ("tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=801,fd=3))\n"
                      "tcp   LISTEN 0 128 [::]:22 [::]:* users:((\"sshd\",pid=801,fd=4))\n"
                      "tcp   LISTEN 0 5 *:5201 *:* users:((\"iperf3\",pid=900,fd=3))\n"
                      "tcp   LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=600,fd=14))\n"
                      "udp   UNCONN 0 0 0.0.0.0%eth0:68 0.0.0.0:* users:((\"dhclient\",pid=700,fd=6))\n"
                      "garbage line\n"),
    "services-enabled.txt": "ssh.service enabled enabled\niperf3.service enabled enabled\ncron.service enabled enabled\n",
    "sshd-effective.txt": "port 22\npermitrootlogin without-password\npasswordauthentication yes\nx11forwarding yes\nusepam yes\n"
                          + KEY_MARK + "\n",
    "accounts.txt": (f"root\tuid=0\tshell=/bin/bash\nexuser\tuid=1000\tshell=/bin/bash\nopr\tuid=0\tshell=/bin/sh\n\n"
                     f"root\tL\nexuser\tP\nopr\tNP\nleak\t{HASH_MARK}\n"),
    "sysctl.txt": ("kernel.randomize_va_space = 2\nnet.ipv4.conf.all.accept_redirects = 1\nnet.ipv4.conf.all.send_redirects = 1\n"
                   "kernel.kptr_restrict = unavailable\n"),
    "firewall.txt": "沒有載入 nf_tables／ip_tables 模組\n" + PSK_MARK + "\n",
    "setuid.txt": "4755\troot\t/usr/bin/passwd\n4755\troot\t/opt/exvendor/bin/helper\n",
    "world-writable.txt": "777\troot\t/var/exdata\n",
    "auto-updates.txt": "沒有 20auto-upgrades\nunattended-upgrades: disabled\napt-daily-upgrade.timer: enabled\n" + TOKEN_MARK + "\n",
    "secure-boot.txt": "（Jetson 的 Secure Boot 以 fuse 為準）\n",
}
GNMAP = ("# Nmap 7.94SVN scan initiated Tue Nov  3 02:03:04 2026 as: nmap -Pn -sS -sV --top-ports 1000 -oA x 192.0.2.20\n"
         "Host: 192.0.2.20 ()\tStatus: Up\n"
         "Host: 192.0.2.20 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)/, "
         "5201/open/tcp//iperf3?///, 23/open/tcp//telnet//Linux telnetd/\tIgnored State: closed (997)\n"
         "# Nmap done at Tue Nov  3 02:04:00 2026 -- 1 IP address (1 host up) scanned in 56.00 seconds\n")
SSH_AUDIT = {"banner": {"software": "OpenSSH_8.9p1"},
             "cves": [{"name": "CVE-2023-38408", "cvssv2": 9.8, "description": "planted " + TOKEN_MARK}],
             "kex": [{"algorithm": "diffie-hellman-group1-sha1", "notes": {"fail": ["weak"]}},
                     {"algorithm": "curve25519-sha256", "notes": {"info": ["ok"]}}],
             "enc": [{"algorithm": "aes128-cbc", "notes": {"warn": ["cbc"]}}],
             "mac": [{"algorithm": "bad algo with spaces", "notes": {"fail": ["x"]}}]}
NET_FILES = {"summary.txt": "check\tstatus\tdetail\nnmap-tcp\tOK\tSYN\nnmap-udp\tNOT_RUN\t沒有 sudo\n",
             "nmap-tcp.gnmap": GNMAP, "nmap-tcp.nmap": "Nmap scan report\n", "open-tcp.txt": "22/open/tcp//ssh//OpenSSH 8.9p1/\n",
             "ssh-audit-22.json": json.dumps(SSH_AUDIT),
             "testssl-443.json": json.dumps([{"id": "TLS1", "severity": "HIGH", "finding": "offered"},
                                            {"id": "cipherlist_3DES", "severity": "MEDIUM", "finding": "x"}])}


def targz(path, stem, files, extra=()):
    """files：{檔名: 文字}；extra：(TarInfo, bytes|None) 直接加進去（惡意的成員）。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        d = tarfile.TarInfo(stem)
        d.type, d.mode = tarfile.DIRTYPE, 0o700
        t.addfile(d)
        for n, v in files.items():
            data = v.encode() if isinstance(v, str) else v
            ti = tarfile.TarInfo(f"{stem}/{n}")
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        for ti, data in extra:
            t.addfile(ti, io.BytesIO(data) if data is not None else None)
    p = Path(path) / f"{stem}.tar.gz"
    p.write_bytes(buf.getvalue())
    return p


def rootfs_result(tmp, cfg=None):
    """scan-flash-package 的結果資料夾（只有這次需要的部分）：<out>/rootfs_x/{scan,cra-project}。"""
    rd = tmp / "res" / "rootfs_x"
    make_scan(rd / "scan", findings=[finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2025-0003", "NVD", "LOW")],
              grype={"matches": [{"vulnerability": {"id": "CVE-2025-0003", "fix": {"state": "fixed", "versions": ["3.0.13-0ubuntu3.13"]}},
                                  "artifact": {"name": "openssl", "version": "3.0.13-0ubuntu3.11", "type": "deb"}}]})
    make_project(rd / "cra-project", cfg)
    return rd


def image_rootfs(d, ssh_password=True):
    """很小的 rootfs 資料夾（給 image_check.py）；shadow 裡放了要確認不會外洩的雜湊。"""
    (d / "etc" / "ssh").mkdir(parents=True)
    (d / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\nexuser:x:1000:1000::/home/exuser:/bin/bash\n")
    (d / "etc" / "shadow").write_text(f"root:!:19000::::::\nexuser:{HASH_MARK}:19000:0:99999:7:::\n")
    (d / "etc" / "ssh" / "sshd_config").write_text("PasswordAuthentication yes\n" if ssh_password else "PasswordAuthentication no\n")
    (d / "usr" / "sbin").mkdir(parents=True)
    (d / "usr" / "sbin" / "sshd").write_bytes(b"#!/bin/sh\n")
    return d


def run_image_check(tmp, rd, **kw):
    st, _ = ic.run(str(image_rootfs(tmp / "img", **kw)), None, str(rd / "image-check"))
    return st


def import_(rd, *archives, replace=False):
    r = subprocess.run([sys.executable, "-I", str(BI), "--result", str(rd), *(["--replace"] if replace else []), *map(str, archives)],
                       capture_output=True, text=True, timeout=60)
    doc = json.loads((rd / "board-test" / "board-test.json").read_text()) if (rd / "board-test" / "board-test.json").exists() else None
    return r, doc


def cra(rd, *extra):
    return run(rd / "cra-project", rd / "scan", *extra)


def all_text(*dirs):
    out = ""
    for d in dirs:
        for p in Path(d).rglob("*"):
            if p.is_file():
                out += p.read_text(encoding="utf-8", errors="replace")
    return out


# ---------- board_import.py ----------

def test_board_import_parses_board_and_network(tmp_path):
    rd = rootfs_result(tmp_path)
    a = targz(tmp_path, BOARD, BOARD_FILES)
    n = targz(tmp_path, NET, NET_FILES)
    r, doc = import_(rd, a, n)
    assert r.returncode == 2 and r.stdout.startswith("D-board-test\tATTENTION\t"), r.stdout
    ids = {f["id"]: f for f in doc["findings"]}
    assert len(ids) == len(doc["findings"])
    # 監聽：0.0.0.0 與 [::] 的 22 合成一筆；loopback 的 53 不列；iperf3 是 medium；介面限定的 0.0.0.0%eth0 也算所有位址
    assert ids["board:listen-tcp:22"]["severity"] == "low" and ids["board:listen-tcp:5201"]["severity"] == "medium"
    assert "board:listen-tcp:53" not in ids and ids["board:listen-udp:68"]["severity"] == "low"
    assert ids["board:ssh-password-auth"]["severity"] == "medium" and ids["board:ssh-permit-root-login"]["severity"] == "low"
    assert ids["board:ssh-x11-forwarding"]["severity"] == "low"
    assert ids["board:account-password:exuser"]["severity"] == "medium"
    assert ids["board:account-empty-password:opr"]["severity"] == "high" and ids["board:account-uid0:opr"]["severity"] == "high"
    assert "board:account-password:root" not in ids          # 鎖住的 root
    assert {"board:sysctl:net.ipv4.conf.all.accept_redirects", "board:sysctl:net.ipv4.conf.all.send_redirects"} <= set(ids)
    assert "board:sysctl:kernel.randomize_va_space" not in ids
    assert ids["board:firewall-none"]["severity"] == "medium" and ids["board:no-auto-updates"]["annex"] == ["I-2c"]
    assert ids["board:setuid-nonstandard"]["evidence"] == [f"{BOARD}/setuid.txt: /opt/exvendor/bin/helper"]
    assert "board:world-writable-dirs" in ids and ids["board:service-enabled:iperf3.service"]["severity"] == "medium"
    # 網路：telnet high、iperf3 medium、ssh low；ssh-audit 的 fail／warn／CVE；testssl
    assert ids["net:open-tcp:23"]["severity"] == "high" and ids["net:open-tcp:5201"]["severity"] == "medium"
    assert ids["net:open-tcp:22"]["severity"] == "low" and ids["net:open-tcp:22"]["source"] == "network"
    assert ids["net:ssh-audit-fail:22"]["evidence"] == [f"{NET}/ssh-audit-22.json: kex diffie-hellman-group1-sha1"]
    assert "net:ssh-audit-warn:22" in ids and ids["net:ssh-audit-cve:22"]["text"].count("CVE-2023-38408") == 1
    assert ids["net:tls-high:443"]["severity"] == "high" and "net:tls-medium:443" in ids
    runs = {r["stem"]: r for r in doc["runs"]}
    assert runs[BOARD]["kind"] == "board" and runs[BOARD]["info"] == {"os": "Ubuntu 22.04.5 LTS", "l4t": "R36.4.3", "firewall": "IPv4 none, IPv6 none"}
    assert runs[NET]["info"]["nmap_version"] == "7.94SVN" and runs[NET]["time"] == "2026-11-03T02:03:04Z"
    assert runs[BOARD]["checks"]["lynis"] == "NOT_RUN" and not any("lynis" in x for x in doc["notes"])   # NOT_RUN 不是 note
    assert any("accounts.txt：1 個不認得的密碼狀態" in x for x in doc["notes"]) and any("listening.txt：1 行" in x for x in doc["notes"])
    for f in doc["findings"]:
        assert {"id", "severity", "annex", "evidence", "text", "confirm", "source"} <= set(f)


def test_board_secrets_never_reach_outputs(tmp_path):
    """板子的檔案裡放了密碼雜湊、私鑰、PSK、token：board-test.json 與 CRA 文件都不能出現。"""
    rd = rootfs_result(tmp_path)
    run_image_check(tmp_path, rd)
    import_(rd, targz(tmp_path, BOARD, BOARD_FILES), targz(tmp_path, NET, NET_FILES))
    r, s, reports = cra(rd)
    assert s["status"] != "FAIL", r.stdout
    text = (rd / "board-test" / "board-test.json").read_text() + (rd / "image-check" / "image-check.json").read_text() + all_text(reports)
    for m in SECRETS:
        assert m not in text, m


def test_malicious_archives_rejected_nothing_outside(tmp_path):
    rd = rootfs_result(tmp_path)
    stem = "board-test-evil-20261103T000000Z"

    def ti(name, typ=tarfile.REGTYPE, size=0, link=""):
        x = tarfile.TarInfo(name)
        x.type, x.size, x.linkname = typ, size, link
        return x
    bad = [(ti(f"{stem}/listening.txt", tarfile.SYMTYPE, link="/etc/shadow"), None),
           (ti(f"{stem}/accounts.txt", tarfile.LNKTYPE, link="/etc/passwd"), None),
           (ti("../escape.txt", size=3), b"bad"), (ti("/tmp/abs.txt", size=3), b"bad"),
           (ti(f"{stem}/../../escape2.txt", size=3), b"bad"), (ti(f"{stem}/evil.sh", size=3), b"bad"),
           (ti(f"{stem}/sub/os.txt", size=3), b"bad"), (ti("other/os.txt", size=3), b"bad"),
           (ti(f"{stem}/secure-boot.txt", tarfile.CHRTYPE), None),
           (ti(f"{stem}/lynis.log", size=8), b"ab\0cdefg")]
    files = dict(BOARD_FILES)
    files.pop("listening.txt")
    files.pop("accounts.txt")
    a = targz(tmp_path, stem, files, bad)
    before = {p for p in tmp_path.rglob("*")}
    r, doc = import_(rd, a)
    after = {p for p in tmp_path.rglob("*")} - before
    assert all(rd / "board-test" in p.parents or p == rd / "board-test" for p in after), after
    assert not (tmp_path / "escape.txt").exists() and not Path("/tmp/abs.txt").exists()
    got = sorted(os.listdir(rd / "board-test" / stem))
    assert "listening.txt" not in got and "accounts.txt" not in got and "evil.sh" not in got and "lynis.log" not in got
    assert all(not (rd / "board-test" / stem / g).is_symlink() for g in got)
    meta = json.loads((rd / "board-test" / stem / "import.json").read_text())
    reasons = " ".join(meta["skipped"])
    for frag in ("不是一般檔案", "絕對路徑或 ..", "不是板子檢查腳本會寫的檔名", "要在", "有 NUL"):
        assert frag in reasons, frag
    assert r.stdout.startswith("D-board-test\tATTENTION\t")
    # 不是 gzip、名稱不對、只有怪東西的壓縮檔：整個不收
    junk = tmp_path / "board-test-junk-20261103T000000Z.tar.gz"
    junk.write_bytes(b"not a gzip at all")
    weird = tmp_path / "weird name.tar.gz"
    weird.write_bytes(b"x")
    only_bad = targz(tmp_path, "board-test-bad2-20261103T000000Z", {}, [(ti("board-test-bad2-20261103T000000Z/x.sh", size=1), b"x")])
    r2, _ = import_(rd, junk, weird, only_bad)
    assert "壓縮檔讀不了" in r2.stdout and "檔名要是" in r2.stdout and "沒有任何可用的檔案" in r2.stdout
    assert not (rd / "board-test" / "board-test-junk-20261103T000000Z").exists()
    assert not (rd / "board-test" / "board-test-bad2-20261103T000000Z").exists()


def test_size_limits_and_board_dir_symlink(tmp_path):
    rd = rootfs_result(tmp_path)
    big = targz(tmp_path, BOARD, dict(BOARD_FILES, **{"lynis.log": "x" * 5000}))
    lim = dict(bi.LIMITS, file=4000)
    st, detail = bi.run(rd, [big], limits=lim)
    assert "超過單檔上限" in json.loads((rd / "board-test" / BOARD / "import.json").read_text())["skipped"][0]
    lim = dict(bi.LIMITS, total=2000)
    (tmp_path / "other").mkdir()
    st, detail = bi.run(tmp_path / "other", [big], limits=lim)
    assert "整個不收" in detail and not (tmp_path / "other" / "board-test" / BOARD).exists()
    # board-test 是符號連結：拒絕（不寫到連結指向的地方）
    rd2 = tmp_path / "rd2"
    rd2.mkdir()
    (tmp_path / "elsewhere").mkdir()
    (rd2 / "board-test").symlink_to(tmp_path / "elsewhere")
    r = subprocess.run([sys.executable, "-I", str(BI), "--result", str(rd2), str(big)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 1 and r.stdout.startswith("D-board-test\tFAIL\t") and os.listdir(tmp_path / "elsewhere") == []


def test_latest_run_per_target_and_reimport(tmp_path):
    rd = rootfs_result(tmp_path)
    old = targz(tmp_path, "board-test-exdev-20261001T000000Z", dict(BOARD_FILES, **{"sshd-effective.txt": "permitrootlogin yes\n"}))
    new = targz(tmp_path, BOARD, dict(BOARD_FILES, **{"sshd-effective.txt": "permitrootlogin no\npasswordauthentication no\n"}))
    r, doc = import_(rd, old, new)
    ids = {f["id"] for f in doc["findings"]}
    assert "board:ssh-permit-root-login" not in ids and "board:ssh-password-auth" not in ids
    runs = {r["stem"]: r for r in doc["runs"]}
    assert runs[BOARD]["current"] and runs["board-test-exdev-20261001T000000Z"]["superseded_by"] == BOARD
    # 同一個壓縮檔再匯入：跳過；不同內容同名：要 --replace
    r2, doc2 = import_(rd, new)
    assert "已經匯入過同一個壓縮檔" in r2.stdout and [f["id"] for f in doc2["findings"]] == [f["id"] for f in doc["findings"]]
    (tmp_path / "x").mkdir()
    other = targz(tmp_path / "x", BOARD, dict(BOARD_FILES, **{"sshd-effective.txt": "permitrootlogin yes\n"}))
    r3, doc3 = import_(rd, other)
    assert "要取代加 --replace" in r3.stdout and "board:ssh-permit-root-login" not in {f["id"] for f in doc3["findings"]}
    r4, doc4 = import_(rd, other, replace=True)
    assert "board:ssh-permit-root-login" in {f["id"] for f in doc4["findings"]}
    # 不給壓縮檔：只重寫 board-test.json，ID 不變
    r5, doc5 = import_(rd)
    assert r5.returncode == 2 and [f["id"] for f in doc5["findings"]] == [f["id"] for f in doc4["findings"]]


def test_malformed_board_files_tolerated(tmp_path):
    rd = rootfs_result(tmp_path)
    junk = {k: "\x01\x02 garbage ::: [[[ \n" * 3 for k in BOARD_FILES}
    junk["summary.txt"] = "check\tstatus\tdetail\n"
    junk["ssh-audit-22.json"] = "{not json"
    a = targz(tmp_path, BOARD, junk)
    st, detail = bi.run(rd, [a])
    doc = json.loads((rd / "board-test" / "board-test.json").read_text())
    assert st == "ATTENTION" and isinstance(doc["findings"], list) and doc["notes"]
    n = targz(tmp_path, NET, {"summary.txt": "check\tstatus\tdetail\nnmap-tcp\tFAIL\tx\n", "nmap-tcp.err": "boom\n",
                              "ssh-audit-22.json": "[1, 2]", "testssl-443.json": "{\"x\": 1}"})
    st, detail = bi.run(rd, [n])
    doc = json.loads((rd / "board-test" / "board-test.json").read_text())
    run_ = [r for r in doc["runs"] if r["stem"] == NET][0]
    assert run_["kind"] == "network" and any("看不出對外開的 TCP 埠" in x for x in doc["notes"])


NFT_IN = "table {fam} filter {{\n\tchain input {{\n\t\ttype filter hook input priority filter; policy {pol};\n{rules}\t}}\n}}\n"


def fw(t):
    x = bi.firewall_state(t)
    return x["ipv4"], x["ipv6"], x["format"]


def test_firewall_and_updates_rules():
    assert fw("沒有載入 nf_tables／ip_tables 模組") == ("none", "none", "ok")
    assert fw("\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n") == ("none", "none", "ok")
    assert fw("-P INPUT DROP\n") == ("filtering", "none", "ok")          # iptables-legacy -S 只有 IPv4
    assert fw("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 23 -j DROP\n") == ("filtering", "none", "ok")
    assert fw(NFT_IN.format(fam="inet", pol="drop", rules="")) == ("filtering", "filtering", "ok")
    assert fw(NFT_IN.format(fam="ip6", pol="accept", rules="\t\ttcp dport 23 reject\n")) == ("none", "filtering", "ok")
    assert fw(NFT_IN.format(fam="inet", pol="accept", rules="")) == ("none", "none", "ok")
    assert fw("something else") == ("none", "none", "unknown")
    on = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\nunattended-upgrades: enabled\napt-daily-upgrade.timer: enabled\n'
    assert bi.parse_auto_updates(on, "s") == [] and bi.parse_auto_updates(on.replace('"1";\nunatt', '"0";\nunatt'), "s")


# ---------- 審查（PR #124）指出的問題，每項一個測試 ----------

def test_r1_long_whitespace_files_parse_fast():
    """16 MB 的換行或空白（gzip 後只有幾 KB）：逐行解析、行數上限，不能卡住。"""
    import time
    nl, sp = b"\n" * (16 << 20), b" " * (16 << 20)
    files = {f: nl for f in BOARD_FILES} | {"firewall.txt": nl, "sysctl.txt": sp, "summary.txt": sp, "accounts.txt": b"\t\n" * (4 << 20)}
    t0 = time.monotonic()
    notes = []
    bi.parse_run(BOARD, "board", files, notes)
    notes2 = []
    bi.parse_run(NET, "network", {"summary.txt": nl, "nmap-tcp.gnmap": nl, "ssh-audit-22.json": sp}, notes2)
    assert time.monotonic() - t0 < 20
    assert any("行，後面的沒有解析" in n for n in notes) and any("nmap-tcp.gnmap：超過" in n for n in notes2)


def test_r2_firewall_accept_or_jump_only_is_not_filtering(tmp_path):
    for t in ("-P INPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n",
              "-P INPUT ACCEPT\n-N KUBE-FIREWALL\n-A INPUT -j KUBE-FIREWALL\n-A KUBE-FIREWALL -j DROP\n",
              "-P INPUT ACCEPT\n-A INPUT -i lo -j DROP\n",
              NFT_IN.format(fam="inet", pol="accept", rules='\t\tiifname "lo" accept\n\t\ttcp dport 22 accept\n'),
              NFT_IN.format(fam="inet", pol="accept", rules='\t\tiifname "lo" drop\n')):
        assert fw(t)[:2] == ("none", "none"), t
    # IPv4 只有 iptables（DROP）、IPv6 沒有：分開報告
    rd = rootfs_result(tmp_path)
    bi.run(rd, [targz(tmp_path, BOARD, dict(BOARD_FILES, **{"firewall.txt": "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n"}))])
    ids = {f["id"] for f in json.loads((rd / "board-test" / "board-test.json").read_text())["findings"]}
    assert "board:firewall-ipv6-none" in ids and "board:firewall-none" not in ids and "board:firewall-ipv4-none" not in ids


def test_r3_auto_updates_needs_timer():
    base = 'APT::Periodic::Unattended-Upgrade "1";\nunattended-upgrades: enabled\n'
    for timer in ("masked", "disabled", None):
        f = bi.parse_auto_updates(base + (f"apt-daily-upgrade.timer: {timer}\n" if timer else ""), "s")
        assert [x["id"] for x in f] == ["board:no-auto-updates"] and f"apt-daily-upgrade.timer {timer or 'unknown'}" in f[0]["evidence"][0]


def test_r4_missing_or_skipped_expected_files_count(tmp_path):
    rd = rootfs_result(tmp_path)
    clean_inputs(rd)
    files = dict(CLEAN_BOARD)
    files.pop("firewall.txt")
    files.pop("auto-updates.txt")
    files["summary.txt"] += "firewall\tOK\tfirewall.txt\nauto-updates\tOK\tauto-updates.txt\n"
    # firewall.txt 以符號連結放進壓縮檔：匯入時略過
    link = tarfile.TarInfo(f"{BOARD}/firewall.txt")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/hosts"
    bi.run(rd, [targz(tmp_path, BOARD, files, [(link, None)])], replace=True)
    doc = json.loads((rd / "board-test" / "board-test.json").read_text())
    notes = " ".join(doc["notes"])
    assert "沒有 firewall.txt（summary.txt 寫 OK，檔案卻不在" in notes and "沒有 auto-updates.txt" in notes
    assert "匯入時略過 1 個成員" in notes
    r, s, _ = cra(rd)
    st = s["security_testing"]
    assert st["status"] == "ATTENTION" and any("notes in the board test results" in x for x in st["reasons"])
    sec = (rd / "cra-project" / "CRA" / "Reports" / "risk-assessment.md").read_text()
    assert "files missing: auto-updates.txt, firewall.txt" in sec


def test_r5_network_scan_that_saw_nothing_is_not_clean(tmp_path):
    rd = rootfs_result(tmp_path)
    clean_inputs(rd)
    gn = ("# Nmap 7.94 scan initiated Tue Nov  3 02:03:04 2026 as: nmap\n"
          "Host: 192.0.2.20 ()\tStatus: Up\nHost: 192.0.2.20 ()\tPorts:\tIgnored State: filtered (1000)\n")
    bi.run(rd, [targz(tmp_path, NET, {"summary.txt": "check\tstatus\tdetail\nnmap-tcp\tOK\tx\n", "nmap-tcp.gnmap": gn})], replace=True)
    doc = json.loads((rd / "board-test" / "board-test.json").read_text())
    assert any("沒有看到任何開著的 TCP 埠" in n for n in doc["notes"]) and doc["status"] == "ATTENTION"
    r, s, _ = cra(rd)
    assert s["security_testing"]["status"] == "ATTENTION"


def test_r6_decision_does_not_cover_changed_content(tmp_path):
    rd = rootfs_result(tmp_path)
    clean_inputs(rd)
    one = dict(CLEAN_BOARD, **{"setuid.txt": "4755\troot\t/opt/exvendor/bin/a\n", "sshd-effective.txt": "permitrootlogin prohibit-password\n"})
    bi.run(rd, [targz(tmp_path, BOARD, one)], replace=True)
    cra(rd)
    proj = str(rd / "cra-project")
    for i in ("board:setuid-nonstandard", "board:ssh-permit-root-login"):
        assert sf.main(["decide", "--project", proj, "--id", i, "--status", "accepted", "--reason", "Needed.", "--author", "Example Owner"]) == 0
    dec = json.loads((rd / "cra-project" / "CRA" / "Config" / "security-findings.json").read_text())["decisions"]
    assert all(sf.FP_RE.match(d["fingerprint"]) for d in dec)
    r, s, _ = cra(rd)
    assert s["security_testing"]["status"] == "OK" and s["security_testing"]["decisions"]["used"] == sorted(d["id"] for d in dec)
    # 重測（新的資料夾名稱）內容相同：決定照樣有效
    later = "board-test-exdev-20261104T000000Z"
    (tmp_path / "b").mkdir()
    bi.run(rd, [targz(tmp_path / "b", later, one)])
    r, s, _ = cra(rd)
    assert s["security_testing"]["status"] == "OK", s["security_testing"]["reasons"]
    # 內容變了（多一個 setuid 路徑、root 可以用密碼登入）：決定不套用，回到 open
    worse = dict(one, **{"setuid.txt": one["setuid.txt"] + "4755\troot\t/opt/exvendor/bin/b\n", "sshd-effective.txt": "permitrootlogin yes\n"})
    (tmp_path / "c").mkdir()
    bi.run(rd, [targz(tmp_path / "c", "board-test-exdev-20261105T000000Z", worse)])
    r, s, reports = cra(rd)
    st = s["security_testing"]
    assert st["decisions"]["changed"] == ["board:ssh-permit-root-login", "board:setuid-nonstandard"]
    assert {f["id"]: f["status"] for f in st["findings"]}["board:setuid-nonstandard"] == "open" and st["open"]["high"] == 1
    assert "was made for different content" in (reports / "security-findings.md").read_text()


def test_r7_old_ssh_audit_format_is_a_note():
    old = {"banner": {"software": "OpenSSH_8.9p1"}, "enc": ["aes128-ctr", "3des-cbc"], "mac": ["hmac-sha1"],
           "kex": [{"algorithm": "diffie-hellman-group1-sha1", "keysize": 1024}]}
    notes = []
    out = bi.parse_ssh_audit(json.dumps(old).encode(), 22, NET, "ssh-audit-22.json", notes, {})
    assert out == [] and any("演算法沒有 notes" in n for n in notes)
    notes = []
    bi.parse_ssh_audit(b"{}", 22, NET, "ssh-audit-22.json", notes, {})
    assert any("沒有演算法清單" in n for n in notes)


def test_r8_fixed_still_reported_stays_open(tmp_path):
    rd = rootfs_result(tmp_path)
    clean_inputs(rd)
    bi.run(rd, [targz(tmp_path, BOARD, dict(CLEAN_BOARD, **{"sshd-effective.txt": "passwordauthentication yes\n"}))], replace=True)
    write_json(rd / "cra-project" / "CRA" / "Config" / "security-findings.json", {"schema": sf.SCHEMA, "decisions": [
        {"id": "board:ssh-password-auth", "status": "fixed", "author": "Example Owner", "date": "2026-11-03"},
        {"id": "net:ssh-audit-fail:22", "status": "fixed", "author": "Example Owner", "date": "2026-11-03"},
        {"id": "img:ssh:password-auth", "status": "fixed", "author": "Example Owner", "date": "2026-11-03"}]})
    os.remove(rd / "image-check" / "image-check.json")
    r, s, reports = cra(rd)
    st = s["security_testing"]
    assert st["open"]["medium"] == 1 and st["decisions"]["fixed_not_confirmed"] == ["board:ssh-password-auth"]
    md = (reports / "security-findings.md").read_text()
    assert "fix not confirmed by a re-test" in md
    assert "fix confirmed by this re-test): net:ssh-audit-fail:22" in md       # 網路掃描有跑、沒有報 → 確認
    assert "did not run: img:ssh:password-auth" in md                          # 映像檢查沒跑 → 不能說確認


def test_r9_reserved_archive_names(tmp_path):
    rd = rootfs_result(tmp_path)
    bad = targz(tmp_path, "board-test.json", CLEAN_BOARD)
    r, doc = import_(rd, bad)
    assert "不收" in r.stdout and (rd / "board-test" / "board-test.json").is_file()
    # 舊版留下的 board-test.json 資料夾：清楚的 FAIL，不是 traceback
    os.remove(rd / "board-test" / "board-test.json")
    (rd / "board-test" / "board-test.json").mkdir()
    r = subprocess.run([sys.executable, "-I", str(BI), "--result", str(rd)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 1 and r.stdout.startswith("D-board-test\tFAIL\t") and "不是一般檔案" in r.stdout


def test_r10_same_name_different_content_is_attention(tmp_path):
    rd = rootfs_result(tmp_path)
    clean_inputs(rd)
    r, _ = import_(rd, targz(tmp_path, BOARD, CLEAN_BOARD))
    assert "已經匯入過同一個壓縮檔" in r.stdout and r.returncode == 0        # 同一個壓縮檔：沒有變更
    (tmp_path / "x").mkdir()
    r, _ = import_(rd, targz(tmp_path / "x", BOARD, dict(CLEAN_BOARD, **{"sysctl.txt": "fs.suid_dumpable = 2\n"})))
    assert r.returncode == 2 and r.stdout.startswith("D-board-test\tATTENTION\t") and "沒有匯入：已經有同名、內容不同" in r.stdout


def test_r11_undated_run_never_supersedes_dated(tmp_path):
    rd = rootfs_result(tmp_path)
    dated = targz(tmp_path, BOARD, dict(CLEAN_BOARD, **{"sshd-effective.txt": "passwordauthentication yes\n"}))
    undated = targz(tmp_path, "board-test-exdev", CLEAN_BOARD)
    r, doc = import_(rd, dated, undated)      # 沒有時間的後匯入（匯入時間比較新）
    runs = {x["stem"]: x for x in doc["runs"]}
    assert runs[BOARD]["current"] and not runs["board-test-exdev"]["current"]
    assert "board:ssh-password-auth" in {f["id"] for f in doc["findings"]}
    assert runs["board-test-exdev"]["superseded_by"] == BOARD and runs["board-test-exdev"]["time_source"] == "import"


# ---------- cra_report ----------

def test_cra_report_with_security_results(tmp_path):
    rd = rootfs_result(tmp_path)
    run_image_check(tmp_path, rd)
    import_(rd, targz(tmp_path, BOARD, BOARD_FILES), targz(tmp_path, NET, NET_FILES))
    r, s, reports = cra(rd)
    st = s["security_testing"]
    assert st["ran"] == {"image": True, "board": True, "network": True} and st["status"] == "ATTENTION"
    assert st["inputs"]["image_check"]["file"] == "rootfs_x/image-check/image-check.json"
    assert st["inputs"]["board_test"]["runs"] == [NET, BOARD]
    ids = [f["id"] for f in st["findings"]]
    assert len(ids) == len(set(ids)) and "img:ssh:password-auth" in ids and "board:ssh-password-auth" in ids and "net:open-tcp:23" in ids
    ra = (reports / "risk-assessment.md").read_text()
    sec = ra.split("## 9. Security testing (Annex I Part II point (3))")[1].split("## 10. Residual risk")[0]
    assert "**Security testing status: ATTENTION**" in sec and "**Security testing status (section 9): ATTENTION**" in ra
    assert "| Image static check" in sec and "nmap 7.94SVN" in sec and "system tested: Ubuntu 22.04.5 LTS, L4T R36.4.3" in sec
    assert "checks not OK: lynis NOT_RUN" in sec
    for i in ids:
        assert sec.count(f"| `{i}` |") == 1, i
    assert s["documents"]["risk-assessment"]["status"] == "ATTENTION"
    assert any(d.startswith("security testing: open findings: high") for d in s["documents"]["risk-assessment"]["detail"])
    # security-findings.md：每個 finding 剛好一次、依嚴重度分組
    sfm = (reports / "security-findings.md").read_text()
    for i in ids:
        assert sfm.count(f"| `{i}` |") == 1, i
    assert sfm.index("### High") < sfm.index("### Medium") < sfm.index("### Low")
    assert s["documents"]["security-findings"]["status"] == "ATTENTION"
    # 技術文件第 6 項：報告檔（相對於結果資料夾）、日期、sha256
    td = (reports / "technical-documentation.md").read_text()
    item6 = td.split("## 6. Reports of the tests carried out")[1].split("## 7.")[0]
    img_sha = st["inputs"]["image_check"]["sha256"]
    assert f"`rootfs_x/image-check/image-check.json`" in item6 and img_sha in item6
    assert "`rootfs_x/image-check/image-check.md`" in item6 and "`rootfs_x/board-test/board-test.json`" in item6
    assert f"`rootfs_x/board-test/{BOARD}/`" in item6 and "2026-11-03T01:02:03Z" in item6
    assert "| 6 | Test reports: security testing (image, board, network) | Generated: `security-findings.md` | ATTENTION |" in td
    # Annex I：人寫的內容保留，後面接安全測試的證據
    row = ra.split("| (d) |")[1].split("\n")[0]
    assert "Security testing (section 9):" in row and row.index("Security testing (section 9)") > 20


def test_no_security_inputs_not_run(tmp_path):
    rd = rootfs_result(tmp_path)
    r, s, reports = cra(rd)
    st = s["security_testing"]
    assert st["ran"] == {"image": False, "board": False, "network": False} and st["status"] == "ATTENTION"
    assert st["findings"] == [] and st["inputs"] == {"image_check": None, "board_test": None}
    ra = (reports / "risk-assessment.md").read_text()
    assert "security testing NOT RUN" in ra and ra.count("**NOT RUN**") == 3 and "Findings by severity" not in ra
    assert s["documents"]["risk-assessment"]["status"] == "ATTENTION" and r.returncode == 2
    assert "No security testing results were found" in (reports / "security-findings.md").read_text()
    td = (reports / "technical-documentation.md").read_text()
    assert "No security test reports were found (NOT RUN)." in td
    # Annex I 沒有證據可加：和以前一樣
    assert "(section 9)" not in ra.split("## 6. Applicability")[1].split("### How Annex I")[0]


CLEAN_BOARD = {"summary.txt": "check\tstatus\tdetail\nlistening\tOK\tlistening.txt\n", "listening.txt": "", "sysctl.txt": "",
               "os.txt": "", "accounts.txt": "", "sshd-effective.txt": "passwordauthentication no\n",
               "auto-updates.txt": 'APT::Periodic::Unattended-Upgrade "1";\nunattended-upgrades: enabled\napt-daily-upgrade.timer: enabled\n',
               "firewall.txt": NFT_IN.format(fam="inet", pol="drop", rules="")}
CLEAN_NET = {"summary.txt": "check\tstatus\tdetail\nnmap-tcp\tOK\tx\n",
             "nmap-tcp.gnmap": "# Nmap 7.94 scan initiated Tue Nov  3 02:03:04 2026 as: nmap\n"
                               "Host: 192.0.2.20 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1/\tIgnored State: closed (999)\n"}


def clean_inputs(rd):
    """全部三種測試都有、沒有 high／medium 的輸入（板子的每個該有的檔案都在；網路掃描看得到一個開著的埠）。"""
    write_json(rd / "image-check" / "image-check.json", {"schema": "sca-center-image-check/1", "tool_version": "t", "generated": "2026-11-03T00:00:00Z",
                                                         "status": "OK", "findings": [], "coverage": {"counts": {}}})
    bi.run(rd, [targz(rd.parent, BOARD, CLEAN_BOARD), targz(rd.parent, NET, CLEAN_NET)])


def test_all_three_clean_is_ok_and_partial_is_attention(tmp_path):
    rd = rootfs_result(tmp_path)
    clean_inputs(rd)
    r, s, reports = cra(rd)
    assert s["security_testing"]["status"] == "OK" and s["status"] == "OK" and r.returncode == 0, s["security_testing"]
    os.remove(rd / "image-check" / "image-check.json")
    r, s, _ = cra(rd)
    assert s["security_testing"]["status"] == "ATTENTION" and s["security_testing"]["reasons"] == ["image static check NOT RUN"]
    # 讀不了的輸入：GAP，不當作沒有問題
    (rd / "image-check" / "image-check.json").write_text("{broken")
    r, s, _ = cra(rd)
    assert s["security_testing"]["status"] == "GAP" and "could not be read" in s["security_testing"]["reasons"][0]


def test_decisions_change_status(tmp_path):
    rd = rootfs_result(tmp_path)
    clean_inputs(rd)
    a = targz(tmp_path, BOARD, dict(CLEAN_BOARD, **{"sshd-effective.txt": "passwordauthentication yes\nx11forwarding yes\n"}))
    bi.run(rd, [a], replace=True)
    r, s, _ = cra(rd)
    assert s["security_testing"]["status"] == "ATTENTION" and s["security_testing"]["open"]["medium"] == 1
    write_json(rd / "cra-project" / "CRA" / "Config" / "security-findings.json", {"schema": sf.SCHEMA, "decisions": [
        {"id": "board:ssh-password-auth", "status": "accepted", "reason": "Passwords are unique per device (set at provisioning).",
         "author": "Example Owner", "date": "2026-11-03"},
        {"id": "board:ssh-x11-forwarding", "status": "fixed", "author": "Example Owner", "date": "2026-11-03"},
        {"id": "net:open-tcp:8080", "status": "false_positive", "reason": "Old port.", "author": "Example Owner", "date": "2026-11-03"}]})
    r, s, reports = cra(rd)
    st = s["security_testing"]
    # 手寫、沒有 fingerprint 的 accepted 照樣套用（表格註明），但狀態 ATTENTION（見 test_decision_without_fingerprint_is_attention）；
    # fixed 但這次還看得到 → 仍是 open（low）
    assert st["status"] == "ATTENTION" and st["reasons"][0].startswith("decision without fingerprint") and st["open"] == {"high": 0, "medium": 0, "low": 2, "info": 0}, st   # x11 與 net:open-tcp:22
    assert st["decisions"]["used"] == ["board:ssh-password-auth"] and st["decisions"]["unused"] == ["net:open-tcp:8080"]
    assert st["decisions"]["fixed_not_confirmed"] == ["board:ssh-x11-forwarding"] and st["decisions"]["without_fingerprint"] == ["board:ssh-password-auth"]
    assert st["counts"]["medium"]["accepted"] == 1 and st["counts"]["low"]["fixed"] == 1
    ra = (reports / "risk-assessment.md").read_text()
    assert "accepted (Example Owner, 2026-11-03): Passwords are unique per device" in ra and "no fingerprint" in ra
    assert "marked fixed (Example Owner, 2026-11-03) but still reported" in ra and "net:open-tcp:8080 (false_positive)" in ra
    assert "## Findings with a decision (1)" in (reports / "security-findings.md").read_text()


@pytest.mark.parametrize("bad, msg", [
    ({"id": "board:x", "status": "accepted", "author": "A", "date": "2026-11-03"}, "一定要寫理由"),
    ({"id": "board:x", "status": "ignored", "author": "A", "date": "2026-11-03"}, "status"),
    ({"id": "CVE-2024-1", "status": "fixed", "author": "A", "date": "2026-11-03"}, ".id"),
    ({"id": "board:x", "status": "fixed", "author": "專案負責人", "date": "2026-11-03"}, "佔位字"),
    ({"id": "board:x", "status": "fixed", "author": "A", "date": "2026/11/03"}, "YYYY-MM-DD"),
    ({"id": "board:x", "status": "fixed", "author": "A", "date": "2026-11-03", "extra": 1}, "不認得的鍵"),
])
def test_bad_decisions_fail(tmp_path, bad, msg):
    rd = rootfs_result(tmp_path)
    write_json(rd / "cra-project" / "CRA" / "Config" / "security-findings.json", {"schema": sf.SCHEMA, "decisions": [bad]})
    r, s, reports = cra(rd)
    assert r.returncode == 1 and s["status"] == "FAIL" and msg in s["error"] and not (reports / "security-findings.md").exists()


def test_decide_cli(tmp_path):
    rd = rootfs_result(tmp_path)
    clean_inputs(rd)
    bi.run(rd, [targz(tmp_path, BOARD, dict(CLEAN_BOARD, **{"sshd-effective.txt": "passwordauthentication yes\n"}))], replace=True)
    cra(rd)
    proj = rd / "cra-project"

    def cli(*a):
        return subprocess.run([sys.executable, "-I", str(SF), *a], capture_output=True, text=True, timeout=60)
    base = ["decide", "--project", str(proj), "--author", "Example Owner"]
    r = cli(*base, "--id", "board:ssh-password-auth", "--status", "accepted")
    assert r.returncode == 1 and "一定要寫理由" in r.stdout
    r = cli(*base, "--id", "board:ssh-pasword-auth", "--status", "fixed")
    assert r.returncode == 1 and "--allow-unknown" in r.stdout
    r = cli(*base, "--id", "board:ssh-password-auth", "--status", "accepted", "--reason", "Unique per device.")
    assert r.returncode == 0 and r.stdout.startswith("OK\t新增"), r.stdout
    r = cli(*base, "--id", "board:ssh-password-auth", "--status", "fixed")
    assert r.returncode == 1 and "--replace" in r.stdout
    r = cli(*base, "--id", "board:ssh-password-auth", "--status", "accepted", "--reason", "Unique per device, rotated.", "--replace",
            "--date", "2026-11-04")
    assert r.returncode == 0 and "取代" in r.stdout
    r = cli(*base, "--id", "net:open-tcp:9", "--status", "fixed", "--allow-unknown")
    assert r.returncode == 0
    doc = json.loads((proj / "CRA" / "Config" / "security-findings.json").read_text())
    assert [d["id"] for d in doc["decisions"]] == ["board:ssh-password-auth", "net:open-tcp:9"] and doc["decisions"][0]["date"] == "2026-11-04"
    assert cli("check", "--project", str(proj)).stdout.startswith("OK\t")
    assert "board:ssh-password-auth\tmedium\tboard\topen" in cli("list", "--project", str(proj)).stdout
    r, s, _ = cra(rd)
    assert s["security_testing"]["status"] == "OK"


def test_explicit_paths_and_template_without_section(tmp_path):
    rd = rootfs_result(tmp_path)
    clean_inputs(rd)
    other = tmp_path / "elsewhere"
    other.mkdir()
    os.rename(rd / "image-check" / "image-check.json", other / "ic.json")
    r, s, _ = cra(rd, "--image-check", str(other / "ic.json"))
    assert s["security_testing"]["ran"]["image"] and s["security_testing"]["inputs"]["image_check"]["file"] == "ic.json"
    r = subprocess.run([sys.executable, "-I", str(HERE.parent / "cra_report.py"), "--project", str(rd / "cra-project"), "--scan",
                        str(rd / "scan"), "--board-test", str(other / "missing.json")], capture_output=True, text=True, timeout=60)
    assert r.returncode == 64
    tpl = (HERE.parent / "templates" / "risk-assessment.md").read_text().replace("{{ text.security_testing }}", "")
    make_project(rd / "cra-project", MIN_CFG, {"risk-assessment": tpl})
    r, s, reports = cra(rd)
    assert any("text.security_testing" in w for w in s["config_warnings"]) and (reports / "security-findings.md").exists()


def test_annex_evidence_keeps_human_text(tmp_path):
    rd = rootfs_result(tmp_path)
    run_image_check(tmp_path, rd)
    cfg = dict(MIN_CFG, risk_assessment={"annex_i_applicability": {"d": {"applies": True, "measures": "Key-only SSH login."}}})
    make_project(rd / "cra-project", cfg)
    r, s, reports = cra(rd)
    ra = (reports / "risk-assessment.md").read_text()
    row = ra.split("| (d) |")[1].split("\n")[0]
    assert "| Applies | Key-only SSH login. Security testing (section 9):" in row and "see `security-findings.md`" in row
    # 沒有人寫的項目仍是 TO BE COMPLETED（缺的欄位照算），證據接在後面
    row = ra.split("| (b) |")[1].split("\n")[0]
    assert "**TO BE COMPLETED**" in row and "Security testing (section 9):" in row
    assert "risk_assessment.annex_i_applicability.b" in s["missing_fields"]


def test_board_import_wrapper_regenerates_cra(tmp_path):
    rd = rootfs_result(tmp_path)
    cra(rd)
    a = targz(tmp_path, BOARD, BOARD_FILES)
    env = dict(os.environ, CRA_COMPANY_CONFIG="none")
    r = subprocess.run(["bash", str(WRAPPER), "--result", str(rd), str(a)], capture_output=True, text=True, timeout=120, env=env)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    assert "D-board-test\tATTENTION" in r.stdout and "CRA 文件已重新產生" in r.stdout, r.stdout
    s = json.loads((rd / "cra-project" / "CRA" / "Reports" / "summary.json").read_text())
    assert s["security_testing"]["ran"]["board"] and "board:ssh-password-auth" in [f["id"] for f in s["security_testing"]["findings"]]
    r = subprocess.run(["bash", str(WRAPPER), "--result", str(tmp_path / "nope")], capture_output=True, text=True, timeout=60)
    assert r.returncode == 64
    # 匯入有時間上限（R1）：逾時是 FAIL，不會一直卡著
    shim = tmp_path / "shim"
    shim.mkdir()
    # board-import.sh 用 pick_python 挑 Python（SCA_PYTHON 優先）：版本檢查（-c）馬上通過，匯入本身卡住
    (shim / "python3").write_text('#!/bin/sh\ncase "$3" in *version_info*) exit 0;; esac\nsleep 30\n')
    (shim / "python3").chmod(0o755)
    r = subprocess.run(["bash", str(WRAPPER), "--result", str(rd), "--no-cra"], capture_output=True, text=True, timeout=60,
                       env=dict(env, BOARD_IMPORT_TIMEOUT="1", SCA_PYTHON=str(shim / "python3"), PATH=f"{shim}:{os.environ['PATH']}"))
    assert r.returncode == 1 and "逾時" in r.stdout, r.stdout


def test_malformed_result_files_do_not_crash(tmp_path):
    """結果檔的欄位型別不對（手改或壞掉）：cra_report 不當掉，照樣產生文件。"""
    rd = rootfs_result(tmp_path)
    write_json(rd / "image-check" / "image-check.json", {"schema": "sca-center-image-check/1", "status": 3, "coverage": [],
                                                         "findings": [1, {"id": "x:y", "severity": "weird", "annex": "I-2b", "evidence": "/a"}]})
    write_json(rd / "board-test" / "board-test.json", {"schema": "sca-center-board-test/1", "findings": [{"id": "board:z", "evidence": None}],
                                                       "runs": [{"kind": "board", "current": True, "checks": [], "notes": "x", "info": 5}, 7]})
    r, s, reports = cra(rd)
    st = s["security_testing"]
    assert r.returncode == 2 and st["ran"] == {"image": True, "board": True, "network": False}
    assert {f["id"]: f["severity"] for f in st["findings"]} == {"img:x:y": "high", "board:z": "high"}   # 不認得的嚴重度不降級


def test_decision_without_fingerprint_is_attention(tmp_path):
    """手寫、沒有 fingerprint 的決定：照樣套用，但 ATTENTION；用 decide --replace 綁到現在的內容後 OK。"""
    rd = rootfs_result(tmp_path)
    clean_inputs(rd)
    bi.run(rd, [targz(tmp_path, BOARD, dict(CLEAN_BOARD, **{"sshd-effective.txt": "passwordauthentication yes\n"}))], replace=True)
    write_json(rd / "cra-project" / "CRA" / "Config" / "security-findings.json", {"schema": sf.SCHEMA, "decisions": [
        {"id": "board:ssh-password-auth", "status": "accepted", "reason": "Unique per device.", "author": "Example Owner", "date": "2026-11-03"}]})
    r, s, reports = cra(rd)
    st = s["security_testing"]
    assert st["status"] == "ATTENTION" and st["open"]["medium"] == 0 and st["decisions"]["used"] == ["board:ssh-password-auth"]
    assert st["reasons"] == ["decision without fingerprint: re-run `decide` to bind it to the current content (board:ssh-password-auth)"]
    assert "decision without fingerprint" in (reports / "risk-assessment.md").read_text()
    assert sf.main(["decide", "--project", str(rd / "cra-project"), "--id", "board:ssh-password-auth", "--status", "accepted",
                    "--reason", "Unique per device.", "--author", "Example Owner", "--replace"]) == 0
    r, s, _ = cra(rd)
    assert s["security_testing"]["status"] == "OK" and s["security_testing"]["decisions"]["without_fingerprint"] == []
