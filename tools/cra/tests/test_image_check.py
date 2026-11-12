"""image_check.py：合成的 rootfs（tar、刷機包、資料夾）→ 開機服務、sshd 設定、帳號、權限、私鑰、ELF 強化；
輸出不含雜湊、私鑰、帳密的值；惡意的映像（指向主機的連結、..、超大成員、壞掉的 ELF、連結迴圈）不讀主機檔案、不卡住、出錯有 FAIL。"""
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import image_check as ic  # noqa: E402

CLI = HERE.parent / "image_check.py"
HASH_MARK = "Zq9HASHMARKx7"
KEY_MARK = "KEYMATERIALMARKb64"
NETRC_MARK = "NETRCSECRETMARK"
AWS_ID = "AKIA" + "ABCDEFGHIJKLMNOP"
PSK_MARK = "WIFIPSKMARK"


def elf(bits=64, le=True, etype=2, interp=True, stack="rw", relro=False, now=False, canary=False, dynamic=True, machine=183):
    """最小的 ELF：ehdr | phdrs | dynamic | dynstr，一個 PT_LOAD 從位移 0 對到位址 0。"""
    e = "<" if le else ">"
    is64 = bits == 64
    ehsize, phent, dent = (64, 56, 16) if is64 else (52, 32, 8)
    strtab = b"\0libc.so.6\0" + (b"__stack_chk_fail\0" if canary else b"puts\0")
    types = [1] + ([3] if interp else []) + ([0x6474E551] if stack else []) + ([0x6474E552] if relro else []) + ([2] if dynamic else [])
    dyn_off = ehsize + len(types) * phent
    nd = 3 + (1 if now else 0)
    str_off = dyn_off + (nd * dent if dynamic else 0)
    total = str_off + len(strtab)
    dyn = [(5, str_off), (10, len(strtab))] + ([(30, 8)] if now else []) + [(0, 0)]
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1 if le else 2, 1]) + b"\0" * 9
    if is64:
        hdr = ident + struct.pack(e + "HHIQQQIHHHHHH", etype, machine, 1, 0, ehsize, 0, 0, ehsize, phent, len(types), 0, 0, 0)
    else:
        hdr = ident + struct.pack(e + "HHIIIIIHHHHHH", etype, machine, 1, 0, ehsize, 0, 0, ehsize, phent, len(types), 0, 0, 0)
    ph = b""
    for t in types:
        off, sz, fl = {1: (0, total, 5), 3: (str_off, 1, 4), 2: (dyn_off, nd * dent, 6)}.get(t, (0, 0, 6))
        if t == 0x6474E551:
            fl = 7 if stack == "rwx" else 6
        if is64:
            ph += struct.pack(e + "IIQQQQQQ", t, fl, off, off, off, sz, sz, 8)
        else:
            ph += struct.pack(e + "IIIIIIII", t, off, off, off, sz, sz, fl, 4)
    body = b"".join(struct.pack(e + ("qQ" if is64 else "iI"), a, b) for a, b in dyn) if dynamic else b""
    return hdr + ph + body + strtab


PIE_FULL = elf(etype=3, relro=True, now=True, canary=True)


def add(t, name, v, mode=None, uid=0):
    """v：bytes | ('dir',) | ('sym', 目標) | ('lnk', 目標)"""
    ti = tarfile.TarInfo(name)
    ti.uid = uid
    if isinstance(v, tuple):
        ti.type = {"dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE, "lnk": tarfile.LNKTYPE}[v[0]]
        if len(v) > 1:
            ti.linkname = v[1]
        ti.mode = mode if mode is not None else (0o755 if v[0] == "dir" else 0o777)
        t.addfile(ti)
    else:
        ti.size = len(v)
        ti.mode = mode if mode is not None else 0o644
        t.addfile(ti, io.BytesIO(v))


def unit(desc, exe):
    return f"[Unit]\nDescription={desc}\n[Service]\nExecStart={exe}\n[Install]\nWantedBy=multi-user.target\n".encode()


def rootfs(p=""):
    """合成的 rootfs（merged-usr）：sshd（Include 先設 PermitRootLogin yes）、smbd、dhcp、被 mask 的 cups、
    沒有被預設 target 帶到的 avahi、連結迴圈、主機私鑰、帳號、sudoers、setuid、可寫資料夾、私鑰與帳密、ELF。"""
    S, W = f"{p}usr/lib/systemd/system", f"{p}etc/systemd/system"
    return [
        (f"{p}lib", ("sym", "usr/lib")), (f"{p}bin", ("sym", "usr/bin")), (f"{p}sbin", ("sym", "usr/sbin")),
        (f"{p}tmp", ("dir",), 0o1777), (f"{p}var/www", ("dir",), 0o777),
        (f"{S}/ssh.service", unit("OpenBSD Secure Shell server", "/usr/sbin/sshd -D $SSHD_OPTS")),
        (f"{S}/smbd.service", unit("Samba SMB Daemon", "/usr/sbin/smbd --foreground")),
        (f"{S}/isc-dhcp-server.service", unit("ISC DHCP IPv4 server", "/usr/sbin/dhcpd -4")),
        (f"{S}/cups.service", unit("CUPS", "/usr/sbin/cupsd -l")),
        (f"{S}/avahi-daemon.service", unit("Avahi", "/usr/sbin/avahi-daemon -s")),
        (f"{S}/vendor-app.service", unit("Vendor app", "/opt/vendor/bin/app")),
        (f"{S}/multi-user.target", b"[Unit]\nRequires=basic.target\n"),
        (f"{S}/graphical.target", b"[Unit]\nWants=multi-user.target ../../../etc/shadow\n"),
        (f"{W}/default.target", ("sym", "/lib/systemd/system/graphical.target")),
        (f"{W}/multi-user.target.wants/ssh.service", ("sym", "/lib/systemd/system/ssh.service")),
        (f"{W}/multi-user.target.wants/smbd.service", ("sym", "/lib/systemd/system/smbd.service")),
        (f"{W}/multi-user.target.wants/isc-dhcp-server.service", ("sym", "/lib/systemd/system/isc-dhcp-server.service")),
        (f"{W}/multi-user.target.wants/vendor-app.service", ("sym", "/usr/lib/systemd/system/vendor-app.service")),
        (f"{W}/multi-user.target.wants/cups.service", ("sym", "/lib/systemd/system/cups.service")),
        (f"{W}/cups.service", ("sym", "/dev/null")),
        (f"{W}/custom.target.wants/avahi-daemon.service", ("sym", "../../../../lib/systemd/system/avahi-daemon.service")),
        (f"{W}/multi-user.target.wants/loop.service", ("sym", "loop.service")),
        (f"{p}usr/sbin/sshd", PIE_FULL),
        (f"{p}etc/ssh/sshd_config", b"Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\nPasswordAuthentication no\n"
                                    b"UsePAM yes\nKbdInteractiveAuthentication no\nInclude sshd_config\nMatch User guest\n"
                                    b"  PermitEmptyPasswords yes\n"),
        (f"{p}etc/ssh/sshd_config.d/10-vendor.conf", b"PermitRootLogin yes\nPasswordAuthentication=yes\n"),
        (f"{p}etc/ssh/ssh_host_ed25519_key", f"-----BEGIN OPENSSH PRIVATE KEY-----\n{KEY_MARK}\n-----END OPENSSH PRIVATE KEY-----\n".encode(), 0o600),
        (f"{p}etc/ssh/ssh_host_ed25519_key.pub", b"ssh-ed25519 AAAA host\n"),
        (f"{p}etc/machine-id", b"0123456789abcdef0123456789abcdef\n"),
        (f"{p}etc/passwd", b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                           b"nvidia:x:1000:1000:,,,:/home/nvidia:/bin/bash\nguest:x:1001:1001::/home/guest:/bin/bash\n"
                           b"toor:x:0:0::/root:/bin/sh\nbroken line\n"),
        (f"{p}etc/shadow", f"root:$6$salt${HASH_MARK}root:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n"
                           f"nvidia:$y$j9T${HASH_MARK}nv:19000:0:99999:7:::\nguest::19000:0:99999:7:::\ntoor:!:19000::::::\n".encode(), 0o640),
        (f"{p}etc/sudoers.d/nvidia", b"nvidia ALL=(ALL) NOPASSWD: ALL\n", 0o440),
        (f"{p}opt/vendor/bin/app", elf(etype=2, stack="rwx"), 0o4755),
        (f"{p}opt/vendor/lib/libv.so", elf(etype=3, interp=False, relro=True, now=True, canary=True)),
        (f"{p}usr/bin/tool", PIE_FULL),
        (f"{p}usr/bin/passwd", PIE_FULL, 0o4755),
        (f"{p}usr/bin/old32", elf(bits=32, le=False, etype=2, machine=8, stack=None)),
        (f"{p}etc/ssl/private/ssl-cert-snakeoil.key", f"-----BEGIN PRIVATE KEY-----\n{KEY_MARK}\n-----END PRIVATE KEY-----\n".encode(), 0o600),
        (f"{p}home/nvidia/.netrc", f"machine example.com login u password {NETRC_MARK}\n".encode(), 0o600),
        (f"{p}opt/vendor/aws.cfg", f"key={AWS_ID}\n".encode()),
        (f"{p}etc/NetworkManager/system-connections/wifi.nmconnection", f"[wifi-security]\npsk={PSK_MARK}\n".encode(), 0o600),
        (f"{p}var/lib/dpkg/info/openssh-server.list", b"/.\n/usr\n/usr/sbin\n/usr/sbin/sshd\n/lib/systemd/system/ssh.service\n"),
        (f"{p}var/lib/dpkg/info/passwd:arm64.list", b"/usr/bin/passwd\n"),
        (f"{p}var/lib/dpkg/info/coreutils.list", b"/bin/tool\n"),
    ]


def write_tar(path, members, mode="w"):
    with tarfile.open(path, mode, format=tarfile.PAX_FORMAT) as t:
        for m in members:
            add(t, *m)
    return path


def run(tmp_path, src, *extra):
    out = tmp_path / "out"
    st, detail = ic.run(str(src), extra[0] if extra else None, str(out))
    return st, detail, json.loads((out / "image-check.json").read_text()), (out / "image-check.md").read_text()


def fids(res):
    return {f["id"]: f for f in res["findings"]}


def test_test_tools_and_server_flags_are_network_services(tmp_path):
    """iperf3（實際案例：出貨映像開機就以 --server 監聽 5201）與清單外、ExecStart 帶 --listen 的廠商服務都要列出；一般服務不算。"""
    S, W = "./usr/lib/systemd/system", "./etc/systemd/system"
    extra = [(f"{S}/iperf3.service", unit("iperf3 server", "/usr/bin/iperf3 --server --interval 0")),
             (f"{S}/vendor-api.service", unit("Vendor API", "/opt/vendor/bin/api --listen=0.0.0.0:8080")),
             (f"{S}/vendor-worker.service", unit("Vendor worker", "/opt/vendor/bin/worker --serverless-mode")),
             (f"{W}/multi-user.target.wants/iperf3.service", ("sym", "/lib/systemd/system/iperf3.service")),
             (f"{W}/multi-user.target.wants/vendor-api.service", ("sym", "/lib/systemd/system/vendor-api.service")),
             (f"{W}/multi-user.target.wants/vendor-worker.service", ("sym", "/lib/systemd/system/vendor-worker.service"))]
    src = write_tar(tmp_path / "rootfs.tar", rootfs("./") + extra)
    st, detail, res, md = run(tmp_path, src)
    f = fids(res)
    assert f["service:iperf"]["severity"] == "medium" and "iperf3.service" in " ".join(f["service:iperf"]["evidence"])
    assert "iperf" in detail
    units = {u["unit"]: u for u in res["services"]["units"]}
    assert units["vendor-api.service"]["network_service"].startswith("possible network server")
    assert units["vendor-worker.service"]["network_service"] is None          # --serverless-mode 不是 --server
    assert "service:server-flag" in f
    hit = lambda line: bool(ic.SERVER_FLAG.search(line))
    for yes in ("/opt/a --listen-address=0.0.0.0:80", "/opt/a --bind-address 0.0.0.0", '/opt/a "--listen" 8080', "/opt/a --bind=:9000",
                "/opt/a --listen-port 1883"):
        assert hit(yes), yes
    for no in ("/usr/bin/puppet agent --server host", "/opt/a --server=https://u", "java -server -jar a.jar", "/opt/a --serverless-mode",
               "/opt/a --listener-count 4", "/opt/a --no-listen"):
        assert not hit(no), no


def test_severity_calibration_for_shared_secrets(tmp_path):
    """實際案例校正，而且不能把真的秘密降級：
    - 每台一樣的預設密碼：SSH 開著＋允許密碼登入 → high；只能 console → medium；每台一樣的 SSH 主機金鑰（sshd 開著）→ high。
    - wpa_supplicant 原始碼範例檔（網路名稱全是範例名稱）→ info；保留範例標頭但加了真實網路的 → 照舊 high。
    - /usr 底下、屬於套件的測試資料（installed-tests、/usr/share 下的 snakeoil）→ low；/opt、/etc、/home、/srv 底下名稱含 test 的、
      不屬於任何套件的、/etc/ssl/private 的 snakeoil → 照舊是真的私鑰。"""
    hdr = b"##### Example wpa_supplicant configuration file ###############################\n"
    ex = hdr + b'network={\n\tssid="simple"\n\tpsk="very secret passphrase"\n}\nnetwork={\n\tssid="example"\n\tpsk="x"\n}\n'
    edited = hdr + b'network={\n\tssid="example"\n\tpsk="x"\n}\nnetwork={\n\tssid="CorpWiFi"\n\tpsk="real corp passphrase"\n}\n'
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_MARK}\n-----END RSA PRIVATE KEY-----\n".encode()
    T, Q = "./usr/libexec/installed-tests/glib/cert-tests/key.pem", "./usr/share/qemu-efi-aarch64/PkKek-1-snakeoil.key"
    extra = [("./etc/wpa_supplicant.conf", ex), ("./etc/wpa_supplicant/wpa_supplicant-wlan0.conf", edited), (T, pem), (Q, pem),
             ("./usr/share/vendor-untracked/tests/k.pem", pem),
             ("./opt/vendor/tests/id_rsa", pem), ("./etc/app/tests/tls.key", pem), ("./home/x/test/id_rsa", pem), ("./srv/test-data/k.pem", pem),
             ("./var/lib/dpkg/info/libglib2.0-tests.list", b"/usr/libexec/installed-tests/glib/cert-tests/key.pem\n"),
             ("./var/lib/dpkg/info/qemu-efi-aarch64.list", b"/usr/share/qemu-efi-aarch64/PkKek-1-snakeoil.key\n")]
    src = write_tar(tmp_path / "rootfs.tar", rootfs("./") + extra)
    st, detail, res, md = run(tmp_path, src)
    f = fids(res)
    # 合成 rootfs：sshd 開著、PasswordAuthentication yes → 預設密碼是 high
    assert f["accounts:password-in-image"]["severity"] == "high" and "over the network" in f["accounts:password-in-image"]["text"]
    assert f["ssh:baked-host-keys"]["severity"] == "high"
    assert f["secrets:example-config"]["severity"] == "info" and f["secrets:example-config"]["evidence"][0].startswith("/etc/wpa_supplicant.conf")
    cred = " ".join(f["secrets:credentials"]["evidence"])
    assert f["secrets:credentials"]["severity"] == "high" and "wpa_supplicant-wlan0.conf" in cred and "/etc/wpa_supplicant.conf " not in cred
    t = " ".join(f["secrets:test-keys"]["evidence"])
    assert f["secrets:test-keys"]["severity"] == "low" and "installed-tests" in t and "PkKek-1-snakeoil" in t
    real = " ".join(f["secrets:private-keys"]["evidence"])
    for p in ("/etc/ssl/private/ssl-cert-snakeoil.key", "/opt/vendor/tests/id_rsa", "/etc/app/tests/tls.key", "/home/x/test/id_rsa",
              "/srv/test-data/k.pem", "/usr/share/vendor-untracked/tests/k.pem"):
        assert p in real and p not in t, p
    assert f["secrets:private-keys"]["severity"] == "high" and "info 1" in detail
    for secret in ("very secret passphrase", "real corp passphrase"):
        assert secret not in json.dumps(res) and secret not in md
    # 只能 console 登入（沒有 sshd 開機啟動）→ 預設密碼是 medium
    nossh = [m for m in rootfs("./") if "ssh.service" not in m[0]]
    st, detail, res, md = run(tmp_path / "b", write_tar(tmp_path / "nossh.tar", nossh))
    f = fids(res)
    assert f["accounts:password-in-image"]["severity"] == "medium" and "console login only" in f["accounts:password-in-image"]["text"]
    assert next(c for c in res["checks"] if c["id"] == "accounts")["result"].count("medium") == 1
    # sshd_config 寫成大寫 Yes：照樣是 high（sshd 不分大小寫），帳號檢查那一列的結果也跟著改
    upper = [(m[0], m[1].replace(b"PasswordAuthentication=yes", b"PasswordAuthentication=Yes")) if isinstance(m[1], bytes) else m
             for m in rootfs("./")]
    assert any(isinstance(m[1], bytes) and b"PasswordAuthentication=Yes" in m[1] for m in upper)
    st, detail, res, md = run(tmp_path / "c", write_tar(tmp_path / "upper.tar", upper))
    assert fids(res)["accounts:password-in-image"]["severity"] == "high"
    assert "high" in next(c for c in res["checks"] if c["id"] == "accounts")["result"]


def test_findings_from_rootfs_tar(tmp_path):
    src = write_tar(tmp_path / "rootfs.tar", rootfs("./"))
    st, detail, res, md = run(tmp_path, src)
    f = fids(res)
    assert st == "ATTENTION" and "high" in detail and "ssh" in detail and "samba" in detail
    # 開機啟動的網路服務：ssh、smbd、dhcp；cups 被 mask；avahi 沒有被預設 target 帶到
    for k in ("service:ssh", "service:samba", "service:dhcp"):
        assert f[k]["severity"] == "medium" and set(f[k]["annex"]) == {"I-2b", "I-2j"}, k
    assert "service:cups" not in f and "avahi-daemon.service" in f["service:enabled-not-reached"]["text"]
    units = {u["unit"]: u for u in res["services"]["units"]}
    assert units["ssh.service"]["unit_file"] == "/usr/lib/systemd/system/ssh.service" and units["ssh.service"]["package"] == "package openssh-server"
    assert units["cups.service"]["state"] == "masked" and res["services"]["default_target"] == "graphical.target"
    assert units["vendor-app.service"]["package"] == "not from a package"
    assert not any("shadow" in u for u in units)            # Wants=../../../etc/shadow 不當成 unit
    # sshd：Include 的檔案先出現 → 第一個值有效；Match 另列；主機私鑰
    eff = res["ssh"]["effective"]
    assert eff["permitrootlogin"] == {"value": "yes", "source": "/etc/ssh/sshd_config.d/10-vendor.conf:1"}
    assert eff["passwordauthentication"]["value"] == "yes" and eff["permitemptypasswords"]["source"] == "OpenSSH default"
    assert f["ssh:permit-root-login"]["severity"] == "high" and f["ssh:password-auth"]["severity"] == "medium"
    assert f["ssh:match-blocks"]["evidence"] and res["ssh"]["conditional"][0]["match"] == "User guest"
    assert f["ssh:baked-host-keys"]["evidence"] == ["/etc/ssh/ssh_host_ed25519_key"]
    assert any("Include" in n for n in res["ssh"]["notes"])          # sshd_config Include 自己：有上限、不會無限遞迴
    # 帳號：空密碼、root 以外的 uid 0、映像裡設定好的密碼、NOPASSWD
    assert f["accounts:empty-password"]["severity"] == "high" and "guest" in f["accounts:empty-password"]["text"]
    assert "toor" in f["accounts:extra-uid0"]["text"]
    assert set(f["accounts:password-in-image"]["text"].split(". ")[0].removeprefix("Accounts: ").split(", ")) == {"root", "nvidia"}
    acc = {a["name"]: a for a in res["accounts"]["accounts"]}
    assert acc["root"]["password"] == "set" and acc["root"]["hash_scheme"] == "SHA-512" and acc["toor"]["password"].startswith("locked")
    assert acc["daemon"]["password"] == "locked (no password)" and res["accounts"]["malformed_lines"] == 1
    assert f["accounts:sudo-nopasswd"]["evidence"] == ["/etc/sudoers.d/nvidia:1"]
    # 權限：/opt 的 setuid（不屬於套件）、套件的 setuid、可寫資料夾（/tmp 有 sticky 不算）
    assert f["perm:setuid-vendor"]["evidence"] == ["/opt/vendor/bin/app (setuid 4755)"]
    assert "/usr/bin/passwd" in f["perm:setuid-packages"]["evidence"][0] and "package passwd" in f["perm:setuid-packages"]["evidence"][0]
    assert f["perm:world-writable"]["evidence"] == ["/var/www (0777)"]
    # 私鑰與帳密：種類、行號；snakeoil 私鑰、.netrc、AWS 金鑰 ID、Wi-Fi PSK
    sec = {r["path"]: r for r in res["secrets"]["items"]}
    assert sec["/etc/ssl/private/ssl-cert-snakeoil.key"]["type"] == "PKCS#8 private key"
    assert sec["/home/nvidia/.netrc"]["type"] == "netrc with password field" and sec["/opt/vendor/aws.cfg"]["line"] == 1
    assert "Wi-Fi" in sec["/etc/NetworkManager/system-connections/wifi.nmconnection"]["type"]
    assert "/etc/ssh/ssh_host_ed25519_key" not in sec and f["secrets:private-keys"]["severity"] == "high"
    # ELF：/opt 的非 PIE、可執行 stack 先列；套件的 PIE 不列
    elf_ = res["elf"]
    assert elf_["listed"][0]["path"] == "/opt/vendor/bin/app" and {"no-PIE", "exec-stack", "no-RELRO"} <= set(elf_["listed"][0]["issues"])
    assert f["elf:vendor"]["severity"] == "medium" and "/opt/vendor/bin/app" in f["elf:exec-stack"]["evidence"][0]
    assert not any(r["path"] in ("/usr/bin/tool", "/usr/sbin/sshd") for r in elf_["listed"])
    assert elf_["counts"]["exe_pie"] >= 3 and elf_["counts"]["lib"] == 1
    # 報告：英文、每項標 Annex I 與板子上要確認的事
    assert "## Findings to review" in md and "Annex I Part I (2)(b)" in md and "Confirm on a board" in md and "needs board test" in md


def test_no_secret_values_in_outputs(tmp_path):
    src = write_tar(tmp_path / "rootfs.tar", rootfs())
    out = tmp_path / "o"
    p = subprocess.run([sys.executable, "-I", str(CLI), "--from", str(src), "--out", str(out)], capture_output=True, text=True, timeout=120)
    assert p.returncode == 0 and p.stdout.startswith("D-image-check\tATTENTION\t"), p.stdout + p.stderr
    blob = p.stdout + p.stderr + "".join(x.read_text() for x in out.iterdir())
    for mark in (HASH_MARK, KEY_MARK, NETRC_MARK, AWS_ID, PSK_MARK, "$6$", "$y$"):
        assert mark not in blob, mark
    assert "\n" not in p.stdout.rstrip("\n")


def test_malicious_image_stays_inside(tmp_path):
    host = tmp_path / "host-secret"
    host.write_text("PermitRootLogin yes\nroot::0:0::/root:/bin/bash\nHOSTFILEMARK\n")
    old = ic.TEXT_MAX
    ic.TEXT_MAX = 2000
    try:
        src = write_tar(tmp_path / "evil.tar", [
            ("etc/ssh/sshd_config", ("sym", str(host))),                 # 指向主機的絕對路徑：在映像裡解析
            ("etc/passwd", ("sym", "../../../../../../etc/passwd")),     # .. 停在映像的根 → 指回自己（迴圈）
            ("usr/sbin/sshd", PIE_FULL), ("usr/sbin/evil", ("sym", "../../" + "../" * 50 + str(tmp_path))),
            ("etc/a", ("sym", "b")), ("etc/b", ("sym", "a")),
            ("etc/systemd/system/multi-user.target.wants/x.service", ("sym", "/etc/a")),
            ("etc/systemd/system/default.target", ("sym", "default.target")),
            ("../escape", b"x"), ("/abs/escape", b"x"), ("/".join(["d"] * 3000) + "/deep", b"x"),
            ("etc/big.conf", b"A" * 5000),
            ("usr/bin/trunc", b"\x7fELF"),
            ("usr/bin/badph", b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, 0, 64, 0, 0, 64, 56, 0xFFFF, 0, 0, 0)),
            ("usr/bin/farph", b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, 1 << 60, 0, 0, 64, 56, 3, 0, 0, 0)),
            ("usr/bin/bigdyn", elf()[:120]),
            ("usr/lib/libok.so", elf(etype=3, interp=False, relro=True, now=True, canary=True)),
        ])
        st, detail, res, md = run(tmp_path, src)
    finally:
        ic.TEXT_MAX = old
    blob = json.dumps(res) + md
    assert "HOSTFILEMARK" not in blob and res["accounts"]["accounts"] == []
    assert res["ssh"]["effective"]["permitrootlogin"]["source"] == "OpenSSH default"
    cov = res["coverage"]["counts"]
    assert cov["rejected members (absolute, .., or path too long)"] == 3 and cov["config files over the size limit"] == 1
    assert res["coverage"]["entries"] < 100
    mal = [p for p in ("/usr/bin/trunc", "/usr/bin/badph", "/usr/bin/farph", "/usr/bin/bigdyn") if p in fids(res)["elf:malformed"]["evidence"]]
    assert len(mal) >= 3, fids(res)["elf:malformed"]
    assert res["elf"]["counts"]["lib"] == 1 and st == "ATTENTION" and "不完整" in detail


def test_broken_archive_prints_fail(tmp_path):
    bad = tmp_path / "bad.tar"
    bad.write_bytes(os.urandom(4096))
    good = write_tar(tmp_path / "g.tar", rootfs())
    cut = tmp_path / "cut.tar"
    cut.write_bytes(good.read_bytes()[:3000])            # 成員內容讀到一半就結束
    for src in (bad, cut, tmp_path / "missing"):
        p = subprocess.run([sys.executable, "-I", str(CLI), "--from", str(src), "--out", str(tmp_path / "o")],
                           capture_output=True, text=True, timeout=60)
        assert p.returncode == 3 and p.stdout.startswith("D-image-check\tFAIL\t"), (src, p.stdout, p.stderr)


def test_check_error_gives_fail_but_writes_rest(tmp_path):
    src = write_tar(tmp_path / "rootfs.tar", rootfs())
    old = ic.check_elf

    def boom(img, owners):
        raise RuntimeError("synthetic")
    ic.check_elf = boom
    try:
        st, detail, res, md = run(tmp_path, src)
    finally:
        ic.check_elf = old
    assert st == "FAIL" and "elf: RuntimeError" in detail and "service:ssh" in fids(res)
    assert next(c for c in res["checks"] if c["id"] == "elf")["result"].startswith("FAIL")


def test_dir_source_does_not_follow_symlinks(tmp_path):
    host = tmp_path / "hostdir"
    host.mkdir()
    (host / "sshd_config").write_text("PermitRootLogin yes\n")
    (host / "id_rsa").write_text(f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_MARK}\n")
    r = tmp_path / "flash" / "L4T" / "rootfs_no_gui"
    for m in rootfs():
        name, v = m[0], m[1]
        if name.startswith("etc/ssh/sshd_config"):
            continue
        q = r / name
        q.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(v, tuple):
            if v[0] == "dir":
                q.mkdir(exist_ok=True)
            else:
                os.symlink(v[1], q)
        else:
            q.write_bytes(v)
        if len(m) > 2 and not isinstance(v, tuple) or (len(m) > 2 and v[0] == "dir"):
            os.chmod(q, m[2])
    (r / "etc/ssh/sshd_config").symlink_to(host / "sshd_config")
    (r / "root").mkdir()
    (r / "root/.ssh").symlink_to(host)                     # 資料夾連結到主機：不走進去
    st, detail, res, md = run(tmp_path, tmp_path / "flash", "L4T/rootfs_no_gui")
    assert res["source"]["type"] == "dir" and res["ssh"]["effective"]["permitrootlogin"]["source"] == "OpenSSH default"
    assert not any("/root/" in s["path"] for s in res["secrets"]["items"]) and KEY_MARK not in md
    assert "service:samba" in fids(res) and res["elf"]["listed"][0]["path"] == "/opt/vendor/bin/app"
    assert "setuid" in fids(res)["perm:setuid-vendor"]["evidence"][0]
    # --prefix 的某一層是符號連結：拒絕
    (tmp_path / "flash" / "link").symlink_to(tmp_path / "flash" / "L4T")
    p = subprocess.run([sys.executable, "-I", str(CLI), "--from", str(tmp_path / "flash"), "--prefix", "link/rootfs_no_gui",
                        "--out", str(tmp_path / "o2")], capture_output=True, text=True, timeout=60)
    assert p.returncode == 3 and "FAIL" in p.stdout and "符號連結" in p.stdout


def test_archive_prefix_hardlinks_second_pass(tmp_path):
    a, g = "product-a/Linux_for_Tegra/rootfs_no_gui/", "product-a/Linux_for_Tegra/rootfs_gui/"
    m = rootfs(a)
    m += [(f"{g}etc/ssh/sshd_config", ("lnk", f"{a}etc/ssh/sshd_config")),
          (f"{g}etc/ssh/sshd_config.d/10-vendor.conf", ("lnk", f"{a}etc/ssh/sshd_config.d/10-vendor.conf")),
          (f"{g}usr/sbin/sshd", ("lnk", f"{a}usr/sbin/sshd")),
          (f"{g}opt/vendor/bin/app", ("lnk", f"{a}opt/vendor/bin/app"), 0o4755),
          (f"{g}etc/x", ("lnk", "../outside")), (f"{g}etc/y", ("lnk", f"{a}nothing"))]
    src = write_tar(tmp_path / "product-a.tbz2", m, "w:bz2")
    st, detail, res, md = run(tmp_path, src, g)
    assert res["source"] == {"type": "archive", "file": "product-a.tbz2", "prefix": g.rstrip("/")}
    assert res["ssh"]["effective"]["permitrootlogin"]["value"] == "yes" and res["ssh"]["sshd_installed"]
    assert res["elf"]["listed"][0]["path"] == "/opt/vendor/bin/app" and "no-PIE" in res["elf"]["listed"][0]["issues"]
    cov = res["coverage"]["counts"]
    assert cov["rejected members (absolute, .., or path too long)"] == 1 and cov["hardlinks whose content was not available"] == 1
    # rootfs 裡的硬連結（同一個前綴內）：結果記在兩個名稱下
    m2 = rootfs() + [("usr/bin/app2", ("lnk", "opt/vendor/bin/app"), 0o755)]
    st2, _, res2, _ = run(tmp_path, write_tar(tmp_path / "r2.tar", m2))
    assert {"/opt/vendor/bin/app", "/usr/bin/app2"} <= {r["path"] for r in res2["elf"]["listed"]}


def test_elf_parser_variants():
    def chk(b):
        return ic.elf_check(ic.Reader(io.BytesIO(b), b"", len(b), False))
    r = chk(PIE_FULL)
    assert (r["kind"], r["pie"], r["nx"], r["relro"], r["canary"], r["machine"]) == ("exe", True, "yes", "full", "yes", "aarch64")
    r = chk(elf(bits=32, le=False, etype=2, relro=True, machine=40))
    assert (r["bits"], r["pie"], r["relro"], r["canary"], r["machine"]) == (32, False, "partial", "no", "arm")
    assert ic.elf_issues(r) == ["no-PIE", "partial-RELRO", "no-canary"]
    r = chk(elf(etype=3, interp=False, dynamic=False, stack=None))
    assert r["kind"] == "lib" and r["static"] and r["nx"] == "unknown" and r["canary"] == "unknown"
    assert chk(elf(etype=1))["kind"] == "other"
    seek = ic.elf_check(ic.Reader(io.BytesIO(PIE_FULL), b"", len(PIE_FULL), True))
    assert seek == chk(PIE_FULL)
    for bad in (b"\x7fELF", PIE_FULL[:70], b"\x7fELF\x03\x01" + b"\0" * 60):
        try:
            chk(bad)
        except (ValueError, ic.struct.error):
            pass
        else:
            raise AssertionError(bad[:8])
    # 串流讀取：開頭保留區以外、已經讀過的位置 → 讀不到（None），不往回讀
    old = ic.ELF_RETAIN
    ic.ELF_RETAIN = 16
    try:
        rd = ic.Reader(io.BytesIO(bytes(range(100))), b"", 100, False)
        assert rd.read_at(50, 4) == bytes([50, 51, 52, 53]) and rd.read_at(20, 4) is None and rd.read_at(2, 2) == b"\x02\x03"
    finally:
        ic.ELF_RETAIN = old


def test_sshd_defaults_and_not_installed(tmp_path):
    st, detail, res, _ = run(tmp_path, write_tar(tmp_path / "a.tar", [("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"),
                                                                      ("etc/shadow", b"root:!:1::::::\n")]))
    assert st == "OK" and res["ssh"]["note"].startswith("OpenSSH server") and res["findings"] == []
    assert res["accounts"]["root_password"] == "locked (no password)"
    # sshd 有安裝但沒有開機啟動：sshd 的項目降成 low；shadow 讀不到 → 狀態未知
    st, _, res, _ = run(tmp_path, write_tar(tmp_path / "b.tar", [
        ("usr/sbin/sshd", PIE_FULL), ("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"),
        ("etc/ssh/sshd_config", b"PermitRootLogin yes\nChallengeResponseAuthentication yes\nUsePAM yes\n")]))
    f = fids(res)
    assert f["ssh:permit-root-login"]["severity"] == "low" and f["ssh:kbd-interactive-pam"]["severity"] == "low"
    assert res["ssh"]["effective"]["kbdinteractiveauthentication"]["source"] == "/etc/ssh/sshd_config:2"
    assert "accounts:shadow-missing" in f and res["accounts"]["accounts"][0]["password"].startswith("unknown")


def test_not_a_rootfs_is_gap(tmp_path):
    st, detail, res, _ = run(tmp_path, write_tar(tmp_path / "a.tar", [("README", b"hello\n")]))
    assert st == "GAP" and "不像 rootfs" in detail


def test_password_status_never_returns_hash():
    for field, want in (("", "empty"), ("*", "locked (no password)"), ("!", "locked (no password)"),
                        (f"!$6$s${HASH_MARK}", "locked (password set)"), (f"$1$s${HASH_MARK}", "set"), ("abcdefghijklm", "set")):
        st, sch = ic.pw_status(field)
        assert st == want and HASH_MARK not in (st + str(sch))
    assert ic.scheme("$1$x$y") == "MD5 (weak)" and ic.scheme("abcdefghijklm") == "DES (weak)" and ic.scheme("$y$j9T$x") == "yescrypt"


def test_secret_types_and_openssh_cipher():
    import base64
    img = ic.Image()
    none = base64.b64encode(b"openssh-key-v1\0" + struct.pack(">I", 4) + b"none" + b"\0" * 40).decode()
    aes = base64.b64encode(b"openssh-key-v1\0" + struct.pack(">I", 10) + b"aes256-ctr" + b"\0" * 40).decode()
    ic.scan_secrets(img, "etc/a", f"-----BEGIN OPENSSH PRIVATE KEY-----\n{none}\n".encode())
    ic.scan_secrets(img, "etc/b", f"-----BEGIN OPENSSH PRIVATE KEY-----\n{aes}\n".encode())
    ic.scan_secrets(img, "etc/c", b"x\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n")
    ic.scan_secrets(img, "root/.git-credentials", b"https://u:tok@example.com\n")
    ic.scan_secrets(img, "etc/d", b"no secrets here AKIA123\n")
    got = {s["path"]: s for s in img.secrets}
    assert got["etc/a"]["protection"] == "not passphrase-protected" and got["etc/b"]["protection"] == "passphrase-protected"
    assert got["etc/c"]["type"] == "PEM RSA private key" and got["etc/c"]["line"] == 2 and got["etc/c"]["protection"] == "passphrase-protected"
    assert got["root/.git-credentials"]["type"] == "git credential store" and "etc/d" not in got
    assert all(set(s) <= {"path", "type", "line", "protection"} for s in img.secrets)


def test_resolve_stays_in_image():
    img = ic.Image()
    img.add("lib", "symlink", 0o777, link="usr/lib")
    img.add("usr/lib/x", "file", 0o644)
    img.add("a", "symlink", 0o777, link="/b")
    img.add("b", "symlink", 0o777, link="a")
    img.add("up", "symlink", 0o777, link="../../../../usr")
    img.add("f", "file", 0o644)
    assert img.resolve("lib/x") == "usr/lib/x" and img.resolve("/lib/../lib/x") == "usr/lib/x"
    assert img.resolve("a") is None and img.resolve("a/x") is None          # 迴圈
    assert img.resolve("up/lib/x") == "usr/lib/x" and img.resolve("f/x") is None
    assert img.resolve("lib", follow_last=False) == "lib"
    assert img.glob("usr/*/x", [100]) == (["usr/lib/x"], False)


# ---------- 審查後的修正 ----------

def test_include_glob_is_bounded(tmp_path):
    """Include 的萬用字元與樣式數有總量上限：大量連結到同一個大資料夾、一行很多樣式，不會卡住或吃光記憶體。"""
    import time
    m = [("usr/sbin/sshd", PIE_FULL), ("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"), ("etc/shadow", b"root:!:1::::::\n")]
    m += [(f"x/l{i}", ("sym", "/b")) for i in range(256)]
    m += [(f"b/f{i}", b"") for i in range(20000)]
    m.append(("etc/ssh/sshd_config", b"Include /x/*/*\nInclude " + b" ".join([b"/b/*"] * 50000) + b"\nPermitRootLogin yes\n"))
    src = write_tar(tmp_path / "glob.tar", m)
    t0 = time.monotonic()
    st, detail, res, _ = run(tmp_path, src)
    assert time.monotonic() - t0 < 60
    assert any(n.startswith("Include expansion truncated") for n in res["ssh"]["notes"])
    assert res["coverage"]["counts"]["sshd_config Include expansion stopped (limit)"] == 1 and st == "ATTENTION"
    assert res["ssh"]["effective"]["permitrootlogin"]["value"] == "yes"      # 後面的設定照樣讀
    img = ic.Image()
    for i in range(1000):
        img.add(f"d/f{i}", "file", 0o644)
    budget = [10**6]
    got, cut = img.glob("d/*", budget)
    assert len(got) == ic.GLOB_MAX and cut and budget[0] < 10**6 - 1
    assert img.glob("d/*", [0]) == ([], True)


def test_empty_shell_means_bin_sh(tmp_path):
    """passwd 的 shell 欄位空白 = /bin/sh：可以登入。"""
    src = write_tar(tmp_path / "a.tar", [
        ("etc/passwd", b"root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:\ncarol:x:1001:1001::/home/carol:\n"),
        ("etc/shadow", f"root:!:1::::::\nbob::1::::::\ncarol:$6$s${HASH_MARK}:1::::::\n".encode())])
    st, _, res, md = run(tmp_path, src)
    f = fids(res)
    assert f["accounts:empty-password"]["severity"] == "high" and "bob" in f["accounts:empty-password"]["text"]
    assert "carol" in f["accounts:password-in-image"]["text"]
    acc = {a["name"]: a for a in res["accounts"]["accounts"]}
    assert acc["bob"]["login_shell"] and acc["bob"]["shell"] == "(empty: /bin/sh)" and HASH_MARK not in md


def sshd_image(tmp_path, cfg):
    return write_tar(tmp_path / "s.tar", [
        ("usr/sbin/sshd", PIE_FULL), ("usr/lib/systemd/system/ssh.service", unit("ssh", "/usr/sbin/sshd -D")),
        ("etc/systemd/system/multi-user.target.wants/ssh.service", ("sym", "/usr/lib/systemd/system/ssh.service")),
        ("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"), ("etc/shadow", b"root:!:1::::::\n"), ("etc/ssh/sshd_config", cfg)])


def test_match_all_applies_globally(tmp_path):
    st, _, res, _ = run(tmp_path, sshd_image(tmp_path, b"Match User x\n  PasswordAuthentication no\nMatch all\nPermitRootLogin yes\n"))
    eff = res["ssh"]["effective"]
    assert eff["permitrootlogin"] == {"value": "yes", "source": "/etc/ssh/sshd_config:4 (Match all)"}
    assert eff["passwordauthentication"]["source"] == "OpenSSH default"          # Match User x 的不算全域
    assert fids(res)["ssh:permit-root-login"]["severity"] == "high"
    assert res["ssh"]["conditional"] == [{"keyword": "passwordauthentication", "value": "no", "where": "/etc/ssh/sshd_config:2",
                                          "match": "User x"}]


def test_malformed_sshd_value_does_not_break_check(tmp_path):
    st, _, res, _ = run(tmp_path, sshd_image(tmp_path, b'Match User guest\n  PasswordAuthentication " "\n  PermitRootLogin\nMatch all\n'
                                                       b'PasswordAuthentication " "\n'))
    ssh = next(c for c in res["checks"] if c["id"] == "ssh")
    assert st != "FAIL" and not ssh["result"].startswith("FAIL") and res["errors"] == []
    assert res["ssh"]["conditional"][0]["value"] == ""


def test_owner_only_from_flash_package_headers(tmp_path):
    """flash_package.py 寫的 rootfs tar 擁有者都是 0：不列擁有者、不說 setuid-root；刷機包本身的標頭才列。"""
    st, _, res, md = run(tmp_path, write_tar(tmp_path / "r.tar", rootfs()))
    p = res["permissions"]
    assert all(r["owner_uid"] is None for r in p["setuid_setgid"]) and p["owner_info"].startswith("unknown")
    m = [("L/rootfs_no_gui/etc/passwd", b"root:x:0:0::/root:/bin/bash\n"), ("L/rootfs_no_gui/opt/x", b"x", 0o4755, 1000)]
    st, _, res, _ = run(tmp_path, write_tar(tmp_path / "a.tbz2", m, "w:bz2"), "L/rootfs_no_gui")
    assert res["permissions"]["setuid_setgid"][0]["owner_uid"] == 1000 and res["permissions"]["owner_info"].startswith("from the flash")


def test_private_key_embedded_in_elf(tmp_path):
    """/opt 的 ELF 裡嵌入的 PEM 私鑰（標頭後面接 base64）要列出；只有標頭字串常數的不算；內容不輸出。"""
    body = ("MIIEow" + KEY_MARK + "A" * 64 + "\n").encode()
    key_elf = elf(etype=3, relro=True, now=True, canary=True) + b"\0" * 5000 + b"-----BEGIN RSA PRIVATE KEY-----\n" + body
    const_elf = elf(etype=3, relro=True, now=True, canary=True) + b"\0-----BEGIN RSA PRIVATE KEY-----\0%s\0"
    old = ic.ELF_RETAIN
    ic.ELF_RETAIN = 64                     # 金鑰在保留區之外：串流讀取時照樣掃到
    try:
        src = write_tar(tmp_path / "e.tar", [("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"),
                                             ("opt/v/bin/agent", key_elf, 0o755), ("opt/v/lib/libpem.so", const_elf)])
        st, _, res, md = run(tmp_path, src)
    finally:
        ic.ELF_RETAIN = old
    sec = {r["path"]: r for r in res["secrets"]["items"]}
    assert sec["/opt/v/bin/agent"]["type"] == "PEM RSA private key" and sec["/opt/v/bin/agent"]["where"] == "embedded in an ELF binary"
    assert "/opt/v/lib/libpem.so" not in sec and res["elf"]["checked"] == 2
    assert KEY_MARK not in json.dumps(res) + md and "embedded in an ELF binary" in md
    # 資料夾來源（可以 seek）：一樣掃到
    d = tmp_path / "root"
    (d / "opt/v/bin").mkdir(parents=True)
    (d / "opt/v/bin/agent").write_bytes(key_elf)
    (d / "etc").mkdir()
    (d / "etc/passwd").write_text("root:x:0:0::/root:/bin/bash\n")
    st, _, res, _ = run(tmp_path, d)
    assert any(r["path"] == "/opt/v/bin/agent" for r in res["secrets"]["items"])


# ---------- 第二次審查後的修正 ----------

def test_match_all_overrides_global(tmp_path):
    """sshd 套用 Match 的值蓋過全域值：全域 no、Match all yes → 有效值 yes，兩行都列為證據。"""
    st, _, res, md = run(tmp_path, sshd_image(tmp_path, b"PermitRootLogin no\nPasswordAuthentication no\nMatch all\n"
                                                       b"PermitRootLogin yes\nPermitRootLogin no\n"))
    eff = res["ssh"]["effective"]
    assert eff["permitrootlogin"] == {"value": "yes", "source": "/etc/ssh/sshd_config:4 (Match all)",
                                      "overrides": "/etc/ssh/sshd_config:1"}
    assert eff["passwordauthentication"] == {"value": "no", "source": "/etc/ssh/sshd_config:2"}
    f = fids(res)["ssh:permit-root-login"]
    assert f["severity"] == "high" and f["evidence"] == ["/etc/ssh/sshd_config:4 (Match all)", "/etc/ssh/sshd_config:1 (overridden)"]
    assert "overrides /etc/ssh/sshd_config:1" in md


def test_include_glob_cap_is_recorded(tmp_path):
    """一個樣式展開超過 GLOB_MAX 個檔案：截斷要記不完整（ATTENTION），不是靜默少讀。"""
    m = [("etc/ssh/sshd_config", b"Include sshd_config.d/*.conf\n"), ("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"),
         ("etc/shadow", b"root:!:1::::::\n"), ("usr/sbin/sshd", PIE_FULL)]
    m += [(f"etc/ssh/sshd_config.d/{i:03d}.conf", b"Port 22\n") for i in range(ic.GLOB_MAX + 20)]
    st, detail, res, _ = run(tmp_path, write_tar(tmp_path / "g.tar", m))
    assert res["coverage"]["counts"]["sshd_config Include expansion stopped (limit)"] == 1 and st == "ATTENTION"
    assert any(n.startswith("Include expansion truncated") for n in res["ssh"]["notes"])
    assert len(res["ssh"]["files"]) == 64            # 另有讀 64 個檔案的上限


def test_elf_secret_total_cap_is_recorded(tmp_path):
    """ELF 私鑰掃描的總量用完：沒有掃的 ELF 記不完整（ATTENTION）。"""
    old = ic.SECRET_ELF_TOTAL
    ic.SECRET_ELF_TOTAL = 1
    try:
        st, detail, res, _ = run(tmp_path, write_tar(tmp_path / "e.tar", [
            ("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"), ("etc/shadow", b"root:!:1::::::\n"),
            ("opt/v/a", PIE_FULL, 0o755), ("opt/v/b", PIE_FULL, 0o755)]))
    finally:
        ic.SECRET_ELF_TOTAL = old
    k = "ELF files not fully scanned for embedded keys (size limit)"
    assert res["coverage"]["counts"][k] == 1 and res["coverage"]["examples"][k] == ["opt/v/b"] and st == "ATTENTION"   # a 已經整個讀過


def preset_image(tmp_path, name, machine_id, presets=()):
    """iperf3 有 [Install] 但映像裡沒有連結；ssh 有連結。presets：(路徑, 內容)。"""
    S, W = "usr/lib/systemd/system", "etc/systemd/system"
    m = [("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"), ("etc/shadow", b"root:!:1::::::\n"),
         (f"{S}/multi-user.target", b"[Unit]\n"), (f"{S}/iperf3.service", unit("iperf3 server", "/usr/bin/iperf3 --server")),
         (f"{S}/ssh.service", unit("OpenBSD Secure Shell server", "/usr/sbin/sshd -D")),
         (f"{S}/plain.service", b"[Service]\nExecStart=/usr/bin/true\n"),
         (f"{W}/default.target", ("sym", "/usr/lib/systemd/system/multi-user.target")),
         (f"{W}/multi-user.target.wants/ssh.service", ("sym", "/usr/lib/systemd/system/ssh.service"))]
    if machine_id is not None:
        m.append(("etc/machine-id", machine_id))
    m += list(presets)
    return run(tmp_path, write_tar(tmp_path / name, m))


def test_preset_enables_service_at_first_boot(tmp_path):
    """machine-id 是 uninitialized：systemd 第一次開機依 preset 啟用（沒有符合的規則 = enable）→ iperf3 算開機啟動；沒有 [Install] 的不算。"""
    st, detail, res, md = preset_image(tmp_path, "a.tar", b"uninitialized\n")
    f = fids(res)
    assert "service:iperf" in f and "preset at first boot (/etc/machine-id is uninitialized)" in f["service:iperf"]["text"]
    u = {x["unit"]: x for x in res["services"]["units"]}
    assert u["iperf3.service"]["state"] == "enabled at first boot by a systemd preset"
    assert u["iperf3.service"]["enabled_by"] == ["preset: no matching rule (systemd default is enable)"]
    assert "plain.service" not in u and res["services"]["first_boot_presets"] is True
    assert "iperf" in detail and "/etc/machine-id: uninitialized" in md
    (tmp_path / "b").mkdir()
    st, detail, res, md = preset_image(tmp_path / "b", "b.tar", None)          # 沒有 machine-id 也是第一次開機
    assert "service:iperf" in fids(res) and res["services"]["machine_id"] == "missing"


def test_preset_with_machine_id_set_or_empty_is_low(tmp_path):
    """machine-id 有值或是空檔案（machine-id(5)：空檔案不算第一次開機）：preset 不會套用 → 不算開機啟動，另列 low；ssh 不受影響；
    ssh 的別名 sshd.service 不是候選。"""
    for i, mid in enumerate((b"0123456789abcdef0123456789abcdef\n", b"")):
        (tmp_path / f"c{i}").mkdir()
        st, detail, res, md = preset_image(tmp_path / f"c{i}", "c.tar", mid, [
            ("usr/lib/systemd/system/ssh.service", unit("OpenBSD Secure Shell server", "/usr/sbin/sshd -D") + b"Alias=sshd.service\n"),
            ("etc/systemd/system/sshd.service", ("sym", "/usr/lib/systemd/system/ssh.service"))])
        f = fids(res)
        assert "service:iperf" not in f and f["service:preset-first-boot"]["severity"] == "low", i
        assert "iperf3.service" in f["service:preset-first-boot"]["text"] and "sshd" not in f["service:preset-first-boot"]["text"]
        assert res["ssh"]["enabled_at_boot"] == ["ssh.service"]
        assert "iperf" not in detail.split("開機啟動的網路服務：")[1].split("；")[0]
        u = {x["unit"]: x for x in res["services"]["units"]}
        assert u["iperf3.service"]["state"].startswith("not started at boot") and "sshd.service" not in u


def test_preset_default_target_also_and_unreadable(tmp_path):
    """WantedBy=default.target 照樣算；preset 啟用的 unit 的 Also= 一起啟用（就算它自己的 preset 是 disable）；Also= 互相指也會結束；
    讀不到的 preset 檔記不完整（規則不見會變成預設 enable）。"""
    S, U = "usr/lib/systemd/system", "usr/lib/systemd/system-preset"
    _, _, res, _ = preset_image(tmp_path, "d.tar", None, [
        (f"{S}/telnet.socket", b"[Socket]\nListenStream=23\n[Install]\nWantedBy=default.target\n"),
        (f"{S}/a.service", b"[Service]\nExecStart=/usr/bin/a\n[Install]\nWantedBy=multi-user.target\nAlso=smbd.service\n"),
        (f"{S}/smbd.service", unit("Samba", "/usr/sbin/smbd") + b"Also=b.service\n"),
        (f"{S}/b.service", b"[Service]\nExecStart=/usr/bin/b\n[Install]\nAlso=smbd.service\n"),
        (f"{U}/50-x.preset", b"enable a.service\nenable telnet.socket\ndisable *\n")])
    f = fids(res)
    assert any(k.startswith("service:telnet") for k in f) and "service:samba" in f and "service:iperf" not in f
    u = {x["unit"]: x for x in res["services"]["units"]}
    assert u["smbd.service"]["enabled_by"] == ["Also= of a.service"]
    (tmp_path / "e").mkdir()
    _, _, res, _ = preset_image(tmp_path / "e", "e.tar", None, [(f"{U}/99-default.preset", ("sym", "/opt/x/99.preset")),
                                                               ("opt/x/99.preset", b"disable *\n"),
                                                               (f"{U}/98-gone.preset", ("sym", "/run/98.preset"))])
    assert res["coverage"]["counts"]["systemd preset files that could not be read"] == 1 and res["status"] == "ATTENTION"   # 懸空的不算
    assert res["coverage"]["examples"]["systemd preset files that could not be read"] == ["usr/lib/systemd/system-preset/99-default.preset"]
    (tmp_path / "f").mkdir()                     # 別名的 Also= 不算；已有連結（rescue）的不說「沒有連結」
    S, W = "usr/lib/systemd/system", "etc/systemd/system"
    _, _, res, _ = preset_image(tmp_path / "f", "f.tar", None, [
        (f"{S}/ssh.service", unit("OpenBSD Secure Shell server", "/usr/sbin/sshd -D") + b"Alias=sshd.service\nAlso=ssh.socket\n"),
        (f"{S}/ssh.socket", b"[Socket]\nListenStream=22\n[Install]\nWantedBy=sockets.target\n"),
        (f"{W}/sshd.service", ("sym", "/usr/lib/systemd/system/ssh.service")),
        (f"{W}/rescue.target.wants/iperf3.service", ("sym", "/usr/lib/systemd/system/iperf3.service")),
        (f"{U}/50-x.preset", b"disable ssh.service\ndisable ssh.socket\n")])
    u = {x["unit"]: x for x in res["services"]["units"]}
    assert "ssh.socket" not in u and "not linked" not in fids(res)["service:iperf"]["text"]
    big = ic.SECRET_LARGE_MAX
    ic.SECRET_LARGE_MAX = 16
    try:
        (tmp_path / "g").mkdir()
        st, _, res, _ = preset_image(tmp_path / "g", "g.tar", b"0123456789abcdef0123456789abcdef\n",
                                     [("opt/data/big.bin", b"\0" * (ic.SECRET_MAX + 10))])
    finally:
        ic.SECRET_LARGE_MAX = big
    assert res["coverage"]["info"] == {"large non-ELF files not fully scanned for keys (size limit)": 1}
    assert not res["coverage"]["counts"]


def test_preset_rules_order_and_override(tmp_path):
    """依檔名排序、第一個符合的規則決定；/etc 的同名檔蓋過 /usr/lib；disable 不會拿掉已經有的連結（只啟用）。"""
    U, E = "usr/lib/systemd/system-preset", "etc/systemd/system-preset"
    for i, (presets, on) in enumerate([
            ([(f"{E}/80-product.preset", b"disable iperf3.service\n"), (f"{U}/90-vendor.preset", b"enable *\n")], False),
            ([(f"{U}/90-vendor.preset", b"disable iperf*\n")], False),
            ([(f"{U}/90-vendor.preset", b"disable iperf*\n"), (f"{E}/90-vendor.preset", b"# overrides\n")], True),
            ([(f"{U}/99-default.preset", b"disable *\n")], False),
            ([(f"{U}/50-x.preset", b"  enable iperf3.service\n"), (f"{U}/99-default.preset", b"disable *\n"),
              (f"{E}/10-ssh.preset", b"disable ssh.service\n")], True)]):
        (tmp_path / str(i)).mkdir()
        _, _, res, _ = preset_image(tmp_path / str(i), "p.tar", None, presets)
        assert ("service:iperf" in fids(res)) is on, (i, presets)
        assert res["ssh"]["enabled_at_boot"] == ["ssh.service"], i
    u = {x["unit"]: x for x in res["services"]["units"]}
    assert u["iperf3.service"]["enabled_by"] == ["preset /usr/lib/systemd/system-preset/50-x.preset:1 (enable iperf3.service)"]


def test_large_files_binary_and_streamed_key_scan(tmp_path):
    """超過大小上限：二進位檔不算「設定檔太大」；文字檔照樣記；兩種都分段掃私鑰。dpkg 清單上限比較大（套件歸屬照樣查得到）。"""
    big = ic.TEXT_MAX + 4096
    key = f"-----BEGIN RSA PRIVATE KEY-----\n{'A' * 64}\n-----END RSA PRIVATE KEY-----\n".encode()
    noisy = bytes((i * 7 + 1) % 255 + 1 for i in range(200)) + b"\xff\xfe"          # 開頭沒有 NUL、不是 UTF-8
    binary = noisy + b"\0" * (big // 2) + key + b"\0" * (big // 2)
    text = b"# conf\n" * (big // 7) + key
    lst = b"".join(f"/usr/share/x/f{i}\n".encode() for i in range(ic.TEXT_MAX // 16)) + b"/opt/v/tool\n"
    st, detail, res, _ = run(tmp_path, write_tar(tmp_path / "big.tar", [
        ("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"), ("etc/shadow", b"root:!:1::::::\n"),
        ("etc/skel/tools/out.bin", binary), ("etc/vendor/huge.conf", text),
        ("var/lib/dpkg/info/vendor-tool.list", lst), ("opt/v/tool", PIE_FULL, 0o4755)]))
    ex = res["coverage"]["examples"].get("config files over the size limit", [])
    assert ex == ["etc/vendor/huge.conf"] and len(lst) > ic.TEXT_MAX
    paths = {s["path"] for s in res["secrets"]["items"]}
    assert {"/etc/skel/tools/out.bin", "/etc/vendor/huge.conf"} <= paths, res["secrets"]["items"]
    assert any(s.get("where") == "in a large file (scanned as a stream)" for s in res["secrets"]["items"])
    assert "vendor-tool" in json.dumps(res["permissions"]["setuid_setgid"])
    assert ic.is_binary(binary[:ic.SNIFF]) and not ic.is_binary(noisy) and not ic.is_binary(b"caf\xe9 = 1\n")   # Latin-1 設定檔不算


@pytest.mark.parametrize("line,key", [
    (b"PermitRootLogin yes # debug", "ssh:permit-root-login"),
    (b"PermitRootLogin\tyes\t# debug", "ssh:permit-root-login"),
    (b'PermitRootLogin "yes"', "ssh:permit-root-login"),
    (b"PermitRootLogin=yes #x", "ssh:permit-root-login"),
    (b"PermitRootLogin yes extra tokens", "ssh:permit-root-login"),
    (b"PasswordAuthentication yes # temporary", "ssh:password-auth"),
    (b"PasswordAuthentication\t\"yes\"\t# t", "ssh:password-auth"),
    (b"PermitEmptyPasswords yes #debug", "ssh:permit-empty-passwords"),
    (b"PermitEmptyPasswords 'yes'", "ssh:permit-empty-passwords"),
])
def test_sshd_config_inline_comment_and_quotes(tmp_path, line, key):
    """主行的值要取去掉行內 # 註解、引號後的第一個值：`PermitRootLogin yes # debug` 不能漏報。"""
    st, _, res, _ = run(tmp_path, write_tar(tmp_path / "b.tar", [
        ("usr/sbin/sshd", PIE_FULL), ("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"), ("etc/ssh/sshd_config", line + b"\n")]))
    assert key in fids(res), res["ssh"]["effective"]


def test_sshd_config_comment_does_not_create_false_finding(tmp_path):
    st, _, res, _ = run(tmp_path, write_tar(tmp_path / "b.tar", [
        ("usr/sbin/sshd", PIE_FULL), ("etc/passwd", b"root:x:0:0::/root:/bin/bash\n"),
        ("etc/ssh/sshd_config", b"PermitRootLogin no # was yes\nPasswordAuthentication no #yes\nPermitEmptyPasswords no # yes\n")]))
    f = fids(res)
    assert not {"ssh:permit-root-login", "ssh:password-auth", "ssh:permit-empty-passwords"} & set(f)
    assert res["ssh"]["effective"]["permitrootlogin"]["value"] == "no"
