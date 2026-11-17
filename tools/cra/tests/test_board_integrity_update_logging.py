"""板子檢查的三組新檢查（integrity.txt、update-channel.txt、logging.txt）的匯入端：解析、finding 的 ID 與嚴重度、沒找到／沒量到最多是 info
（不當成通過）、舊壓縮檔（沒有這三個檔案）照舊、不收機敏內容。全部是合成資料（虛構的主機名稱與 example.invalid 位址，fuse 的值是虛構的）。
dumpling 沒有帶板上收集腳本（docs/PROVENANCE.md「沒帶進來的相依」），所以這裡的輸入都是固定的文字，格式見 docs/references/board-integrity-update-logging.md；
上游另有用收集腳本片段實跑的測試，這裡改成同樣情境的固定輸入。"""
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import board_import as bi  # noqa: E402
from test_security_testing import BOARD_FILES, BOARD, import_, rootfs_result, targz  # noqa: E402

SUMMARY = ("check\tstatus\tdetail\nscript-version\tOK\t2026-11-13.2\nintegrity\tOK\tintegrity.txt\n"
           "update-channel\tOK\tupdate-channel.txt\nlogging\tOK\tlogging.txt\n")

INTEG_OFF = """== uefi
efi=present
SecureBoot=0
SetupMode=1
PK=absent
KEK=absent
db=absent
dbx=absent
== dt-secure-boot
value=00000002
== dmesg-secureboot
[    0.000000] secureboot: Secure boot disabled
== tegra-fuse
tegra=yes
fuse_node=present
odm_production_mode=NOT_RUN (no odm_production_mode sysfs node)
security_mode=NOT_RUN (no security_mode sysfs node)
boot_security_info=NOT_RUN (no boot_security_info sysfs node)
note=raw fuse array (nvmem) is not read
== lockdown
lockdown=absent
== modsig
sig_enforce=N
== tpm
tpm=tpm0 version_major=2
== ima
ima=absent
== dm-verity
cmdline_verity=no
dm_verity_module=no
"""
INTEG_ON = """== uefi
efi=present
SecureBoot=1
SetupMode=0
PK=present
KEK=present
db=present
dbx=present
== dt-secure-boot
value=00000003
== dmesg-secureboot
[    0.000000] secureboot: Secure boot enabled
== tegra-fuse
tegra=no
fuse_node=absent
odm_production_mode=NOT_RUN (no odm_production_mode sysfs node)
== lockdown
lockdown=none [integrity] confidentiality
== modsig
sig_enforce=Y
== tpm
tpm=absent
== ima
ima=present count=12
== dm-verity
cmdline_verity=yes
dm_verity_module=yes
dm=CRYPT-VERITY
"""
UPD_BAD = """== apt-sources
apt=present
parser=ok
@file sources.list
deb [] http://mirror.example.invalid/ubuntu jammy main
deb [trusted=yes] https://repo.example.invalid/x jammy main
@file vendor.sources
Types: deb
URIs: https://vendor.example.invalid/apt
Suites: stable
Signed-By: yes

Types: deb
URIs: http://off.example.invalid/apt
Suites: stable
Enabled: no
== apt-config
dump=ok
APT::Get::AllowUnauthenticated "true";
Acquire::AllowInsecureRepositories "0";
Acquire::https::Verify-Peer "false";
== apt-keys
legacy_trusted_gpg=present
trusted.gpg.d_count=1
key=trusted.gpg.d/vendor.gpg
keyrings_count=0
== ota-tools
nv_update_engine=absent
nvbootctrl=absent
swupdate=absent
units=ok
== esrt
esrt=absent
"""
UPD_GOOD = """== apt-sources
apt=present
parser=ok
@file sources.list
deb [] https://mirror.example.invalid/ubuntu jammy main
== apt-config
dump=ok
Acquire::AllowInsecureRepositories "0";
== apt-keys
legacy_trusted_gpg=absent
trusted.gpg.d_count=2
keyrings_count=0
== ota-tools
swupdate=present
units=ok
== esrt
esrt=NOT_RUN (no UEFI firmware interface)
"""
UPD_NONE = """== apt-sources
apt=absent
parser=ok
== apt-config
dump=NOT_RUN (no apt-config, or it failed)
== apt-keys
legacy_trusted_gpg=absent
== ota-tools
nv_update_engine=absent
swupdate=absent
units=ok
== esrt
esrt=absent
"""
LOG_BAD = """== journald
persistent_dir=no
storage_conf=
max_use_conf=
retention_conf=
active=active
== daemons
rsyslog enabled=disabled active=inactive
syslog-ng enabled=not-found active=inactive
auditd enabled=not-found active=inactive
systemd-journal-remote enabled=not-found active=inactive
systemd-journal-upload enabled=not-found active=inactive
== rotation
logrotate=absent
logrotate_timer=not-found
logrotate_cron=no
rsyslog_logrotate_conf=no
== remote-logging
rsyslog_remote=absent
auditd_remote=absent
== auth-logging
auth_log_file=absent
rsyslog_auth_rule=absent
journal_ssh_entries=0
"""
LOG_ROT = LOG_BAD.replace("rsyslog enabled=disabled active=inactive", "rsyslog enabled=enabled active=active")
LOG_GOOD = """== journald
persistent_dir=yes
storage_conf=persistent
active=active
== daemons
rsyslog enabled=enabled active=active
syslog-ng enabled=not-found active=inactive
auditd enabled=enabled active=active
systemd-journal-remote enabled=not-found active=inactive
systemd-journal-upload enabled=not-found active=inactive
== rotation
logrotate=present
logrotate_timer=enabled
logrotate_cron=no
rsyslog_logrotate_conf=yes
== remote-logging
rsyslog_remote=yes
auditd_remote=no
== auth-logging
auth_log_file=present
rsyslog_auth_rule=yes
journal_ssh_entries=5
"""


def run(files):
    notes = []
    f, info, checks = bi.parse_run("s", "board", {k: v.encode() if isinstance(v, str) else v for k, v in files.items()}, notes)
    return {x["id"]: x for x in f}, info, [n for n in notes if "summary.txt 沒有這一項" not in n]     # 其他既有檢查的檔案沒給：不是這裡要測的


def only(**kw):
    names = {k.replace("_", "-") for k in kw}
    summ = "".join(l + "\n" for l in SUMMARY.splitlines() if l.split("\t")[0] in names | {"check", "script-version"})
    return {"summary.txt": summ, **{k.replace("_", "-") + ".txt": v for k, v in kw.items()}}


def new_ids(ids):
    return {i: f["severity"] for i, f in ids.items() if i.startswith(("board:secureboot", "board:lockdown", "board:integrity", "board:apt",
                                                                      "board:update", "board:journal", "board:log", "board:no-log",
                                                                      "board:remote", "board:auth"))}


def test_integrity_secure_boot_off_and_jetson_fuse_unreadable():
    ids, info, notes = run(only(integrity=INTEG_OFF))
    assert new_ids(ids) == {"board:secureboot-disabled": "medium", "board:secureboot-fuse-not-assessed": "info", "board:lockdown-none": "low",
                            "board:integrity-verification-not-found": "info"}
    f = ids["board:secureboot-disabled"]
    assert f["annex"] == ["I-2d", "I-2f"] or set(f["annex"]) == {"I-2d", "I-2f"}
    assert "EN 303 645 5.7-1" in f["text"] and "SetupMode=1" in f["text"] and len(f["evidence"]) == 3
    i = info["integrity"]
    assert i["secure_boot_uefi"] == "disabled" and i["setup_mode"] == 1 and i["jetson"] is True and i["jetson_fuse"] is None
    assert i["uefi_keys"]["PK"] == "absent" and i["tpm"] == ["tpm0 (version 2)"] and i["ima"] == "absent" and i["dm_verity"] == "not_found"
    assert i["lockdown"] == "absent" and i["module_sig_enforce"] is False and not notes
    assert info["script_version"] == "2026-11-13.2"


def test_integrity_everything_on_has_no_findings():
    ids, info, notes = run(only(integrity=INTEG_ON))
    assert new_ids(ids) == {}
    i = info["integrity"]
    assert i["secure_boot_uefi"] == "enabled" and i["lockdown"] == "integrity" and i["ima"] == "present" and i["dm_verity"] == "found"
    assert i["dm_devices"] == ["CRYPT-VERITY"] and i["tpm"] == "absent" and not notes


def test_jetson_fuse_values():
    fuse = INTEG_OFF.replace("odm_production_mode=NOT_RUN (no odm_production_mode sysfs node)", "odm_production_mode=0x00000000")
    ids, info, _ = run(only(integrity=fuse))
    assert ids["board:secureboot-fuse-not-burned"]["severity"] == "medium" and "board:secureboot-fuse-not-assessed" not in ids
    assert info["integrity"]["jetson_fuse"]["odm_production_mode"] == 0
    ids, info, _ = run(only(integrity=fuse.replace("0x00000000", "1")))
    assert "board:secureboot-fuse-not-burned" not in ids and "board:secureboot-fuse-not-assessed" not in ids
    assert info["integrity"]["jetson_fuse"]["odm_production_mode"] == 1
    # 其他字串不當成數值
    ids, info, _ = run(only(integrity=fuse.replace("0x00000000", "garbage; rm -rf")))
    assert info["integrity"]["jetson_fuse"] is None and "board:secureboot-fuse-not-assessed" in ids


def test_no_uefi_no_fuse_is_not_assessed_not_pass():
    t = INTEG_ON.replace("SecureBoot=1", "SecureBoot=NOT_RUN (x)").replace("value=00000003", "value=NOT_RUN (x)").replace(
        "[    0.000000] secureboot: Secure boot enabled", "NOT_RUN (no matching dmesg line)").replace("efi=present", "efi=absent")
    ids, info, notes = run(only(integrity=t))
    assert ids["board:secureboot-not-assessed"]["severity"] == "info" and "board:secureboot-disabled" not in ids
    assert info["integrity"]["secure_boot_uefi"] == "no_uefi" and "efivar-SecureBoot" in info["integrity"]["not_run"]


def test_conflicting_secure_boot_sources_is_a_note():
    t = INTEG_ON.replace("secureboot: Secure boot enabled", "secureboot: Secure boot disabled")
    ids, info, notes = run(only(integrity=t))
    assert "board:secureboot-disabled" not in ids and info["integrity"]["secure_boot_uefi"] == "conflict"
    assert any("互相矛盾" in n for n in notes)


def test_integrity_truncated_file_is_not_run():
    ids, info, _ = run(only(integrity="== uefi\nefi=present\n"))
    i = info["integrity"]
    assert i["secure_boot_uefi"] is None and "lockdown" in i["not_run"] and "ima" in i["not_run"] and i["dm_verity"] is None
    assert "board:secureboot-disabled" not in ids and "board:integrity-verification-not-found" not in ids
    assert "board:secureboot-not-assessed" in ids


def test_update_channel_bad():
    ids, info, notes = run(only(update_channel=UPD_BAD))
    assert new_ids(ids) == {"board:apt-insecure-allowed": "high", "board:apt-tls-verify-off": "medium", "board:apt-source-http": "low"}
    ev = " ".join(ids["board:apt-insecure-allowed"]["evidence"])
    assert "AllowUnauthenticated = true" in ev and "trusted=yes" in ev and "AllowInsecureRepositories" not in ev
    assert ids["board:apt-source-http"]["evidence"] == ["s/update-channel.txt: http://mirror.example.invalid"]    # 停用的 off.example.invalid 不算
    a = info["update_channel"]["apt_sources"]
    assert a == {"active_network": 3, "https": 2, "not_https": 1, "local": 0, "with_signed_by": 1, "trusted_yes": 1}
    assert info["update_channel"]["apt_keys"]["legacy_trusted_gpg"] == "present" and info["update_channel"]["esrt"] == {"present": False, "entries": 0}
    assert "user" not in json.dumps(ids)


def test_update_channel_good_and_unknown():
    ids, info, _ = run(only(update_channel=UPD_GOOD))
    assert new_ids(ids) == {} and info["update_channel"]["ota_tools"] == ["swupdate"]
    assert info["update_channel"]["esrt"] is None            # NOT_RUN：不是 absent
    # 沒有任何通道：info（找不到），不是通過也不是問題
    ids, info, _ = run(only(update_channel=UPD_NONE))
    assert new_ids(ids) == {"board:update-channel-not-found": "info"} and "apt-config" in info["update_channel"]["not_run"]
    assert info["update_channel"]["apt_config"] is None


def test_update_channel_unknown_apt_config_never_passes():
    ids, info, _ = run(only(update_channel=UPD_GOOD.replace("dump=ok", "dump=NOT_RUN (no apt-config, or it failed)")))
    assert info["update_channel"]["apt_config"] is None and "apt-config" in info["update_channel"]["not_run"]


def test_logging_findings():
    ids, info, _ = run(only(logging=LOG_BAD))
    assert new_ids(ids) == {"board:journal-not-persistent": "low", "board:remote-logging-not-configured": "info", "board:auth-logging-not-found": "info"}
    # journald 壞了（failed）、rsyslog 沒在跑、auditd 沒有：沒有任何記錄在寫
    ids, _, _ = run(only(logging=LOG_BAD.replace("active=active\n== daemons", "active=failed\n== daemons")))
    assert ids["board:no-log-service"]["severity"] == "medium" and ids["board:no-log-service"]["annex"] == ["I-2l"]
    assert "board:journal-not-persistent" not in ids
    # 守護程式的狀態讀不到（unknown）：不下結論
    ids, _, _ = run(only(logging=LOG_BAD.replace("rsyslog enabled=disabled active=inactive", "rsyslog enabled=unknown active=unknown")))
    assert "board:no-log-service" not in ids and "board:journal-not-persistent" not in ids


def test_journal_not_persistent_only_when_nothing_else_persists():
    base = LOG_GOOD.replace("persistent_dir=yes", "persistent_dir=no").replace("storage_conf=persistent", "storage_conf=")
    ids, info, _ = run(only(logging=base))
    assert "board:journal-not-persistent" not in ids and info["logging"]["journal"]["persistent"] is False     # rsyslog／auditd 有寫
    only_journal = base.replace("rsyslog enabled=enabled active=active", "rsyslog enabled=disabled active=inactive").replace(
        "auditd enabled=enabled active=active", "auditd enabled=not-found active=inactive")
    ids, _, _ = run(only(logging=only_journal))
    assert ids["board:journal-not-persistent"]["severity"] == "low" and ids["board:journal-not-persistent"]["annex"] == ["I-2l"]
    # Storage=persistent 會建立資料夾：視為持久
    ids, info, _ = run(only(logging=only_journal.replace("storage_conf=", "storage_conf=persistent")))
    assert "board:journal-not-persistent" not in ids and info["logging"]["journal"]["persistent"] is True
    # Storage=volatile 蓋過資料夾
    ids, info, _ = run(only(logging=only_journal.replace("persistent_dir=no", "persistent_dir=yes").replace("storage_conf=", "storage_conf=volatile")))
    assert "board:journal-not-persistent" in ids


def test_log_rotation_missing_only_when_rsyslog_writes():
    ids, info, _ = run(only(logging=LOG_ROT))
    assert ids["board:log-rotation-missing"]["severity"] == "low" and "logrotate is not installed" in ids["board:log-rotation-missing"]["text"]
    ids, _, _ = run(only(logging=LOG_BAD))
    assert "board:log-rotation-missing" not in ids          # rsyslog 沒在寫
    ids, _, _ = run(only(logging=LOG_GOOD))
    assert new_ids(ids) == {}


def test_logging_good_and_not_run():
    ids, info, _ = run(only(logging=LOG_GOOD))
    l = info["logging"]
    assert l["remote_logging"] == "yes" and l["auth_logging"] == "found" and l["audit"] is True and l["journal"]["persistent"] is True
    ids, info, _ = run(only(logging="== journald\nactive=NOT_RUN (no systemctl)\npersistent_dir=no\n"))
    assert new_ids(ids) == {} and info["logging"]["journal"]["active"] is None
    assert {"journald", "daemons", "rotation", "remote-logging", "auth-logging"} <= set(info["logging"]["not_run"])
    assert info["logging"]["remote_logging"] is None and info["logging"]["auth_logging"] is None


def test_old_archive_without_new_files_unchanged_and_missing_file_is_note():
    ids, info, notes = run({"summary.txt": "check\tstatus\tdetail\nos\tOK\tos.txt\n", "os.txt": "PRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\n"})
    assert "integrity" not in info and "update_channel" not in info and "logging" not in info and "script_version" not in info and not new_ids(ids)
    # summary 說 OK 但檔案不在 → note（ATTENTION），不當作沒問題
    ids, info, notes = run({"summary.txt": SUMMARY, "os.txt": "PRETTY_NAME=\"x\"\n"})
    assert sum("沒有檢查" in n for n in notes) == 3


def test_garbage_and_hostile_values_do_not_crash():
    junk = "== uefi\nSecureBoot=2\nefi=\x00\n== dt-secure-boot\nvalue=zz\n== lockdown\nlockdown=[x]\n== tpm\ntpm=../../x version_major=9\n" * 3
    for k in ("integrity", "update_channel", "logging"):
        run(only(**{k: junk + "\n== apt-sources\n@file x\nURIs: \nTypes: \n" + "A" * 5000 + "\n"}))


def test_import_end_to_end_and_no_secrets(tmp_path):
    rd = rootfs_result(tmp_path)
    files = dict(BOARD_FILES)
    files["summary.txt"] = BOARD_FILES["summary.txt"] + SUMMARY.split("\n", 1)[1]
    files.update({"integrity.txt": INTEG_OFF, "update-channel.txt": UPD_BAD, "logging.txt": LOG_ROT})
    r, doc = import_(rd, targz(tmp_path, BOARD, files))
    assert doc is not None, r.stdout + r.stderr
    ids = {f["id"]: f for f in doc["findings"]}
    for want in ("board:secureboot-disabled", "board:apt-insecure-allowed", "board:log-rotation-missing", "board:lockdown-none"):
        assert want in ids, sorted(ids)
    run_ = next(x for x in doc["runs"] if x["stem"] == BOARD)
    assert run_["info"]["script_version"] == "2026-11-13.2" and set(run_["checks"]) >= {"integrity", "update-channel", "logging"}
    assert "script-version" not in run_["checks"]
    text = (rd / "board-test" / "board-test.json").read_text()
    assert json.loads(text)["runs"][0]["info"]["update_channel"]["apt_sources"]["trusted_yes"] == 1
    assert (rd / "board-test" / BOARD / "integrity.txt").exists()




# ---------- 上游用收集腳本片段實跑的情境：這裡改成板子會輸出的固定文字 ----------

def test_unmasked_credentials_in_input_never_reach_findings():
    """收集端照規則會先遮掉帳密與查詢字串；就算收到沒遮的輸入，匯入端也只取協定＋主機（主機不合格式就記 INVALID），帳密不進 finding 與 info。"""
    raw = UPD_BAD.replace("deb [] http://mirror.example.invalid/ubuntu jammy main",
                          "deb [] http://exuser:SECRETPW@mirror.example.invalid/ubuntu?token=SECRETQ jammy main")
    ids, info, _ = run(only(update_channel=raw))
    blob = json.dumps(ids) + json.dumps(info)
    for secret in ("SECRETPW", "SECRETQ", "exuser", "token"):
        assert secret not in blob, secret
    assert ids["board:apt-insecure-allowed"]["severity"] == "high"


def test_no_awk_on_board_is_not_run_not_not_found():
    out = "== apt-sources\napt=present\nparser=NOT_RUN (no awk)\n== apt-config\ndump=ok\n== apt-keys\nlegacy_trusted_gpg=absent\n" \
          "== ota-tools\nswupdate=absent\nunits=ok\n== esrt\nesrt=absent\n"
    ids, info, _ = run(only(update_channel=out))
    assert "board:update-channel-not-found" not in ids and "apt-sources" in info["update_channel"]["not_run"]
    assert info["update_channel"]["apt_sources"] is None


def test_source_file_without_source_lines_is_not_run():
    out = UPD_NONE.replace("apt=absent", "apt=present").replace("parser=ok", "parser=ok\n@file sources.list")
    ids, info, notes = run(only(update_channel=out))
    assert "board:update-channel-not-found" not in ids and "apt-sources" in info["update_channel"]["not_run"] and not notes
    # 來源行看不懂（deb ?）或輸出被截斷：不下結論，並記 note
    ids, info, notes = run(only(update_channel=out.replace("@file sources.list", "@file sources.list\ndeb ?")))
    assert "board:update-channel-not-found" not in ids and any("apt 來源讀不完整" in n for n in notes)
    ids, info, notes = run(only(update_channel=out.replace("@file sources.list", "@file sources.list\ndeb [] https://a.example.invalid/x s c\n@truncated")))
    assert info["update_channel"]["apt_sources"] is None and any("截斷" in n for n in notes)


def upd(sources):
    return UPD_NONE.replace("apt=absent\nparser=ok", "apt=present\nparser=ok\n" + sources.rstrip("\n"))


def test_deb822_field_order_is_free():
    ids, info, _ = run(only(update_channel=upd("@file v.sources\nURIs: http://first.example.invalid/x\nSuites: stable\nTrusted: yes\nTypes: deb\n")))
    assert ids["board:apt-insecure-allowed"]["severity"] == "high" and "first.example.invalid" in " ".join(ids["board:apt-insecure-allowed"]["evidence"])
    assert info["update_channel"]["apt_sources"]["not_https"] == 1
    # Enabled: no 在 URIs 之後：這一段整個不算；兩段之間以空行分開，不互相影響
    two = "@file v.sources\nURIs: https://ok.example.invalid\nEnabled: no\nTrusted: yes\n\nTypes: deb\nURIs: https://ok2.example.invalid\n"
    ids, info, _ = run(only(update_channel=upd(two)))
    assert "board:apt-insecure-allowed" not in ids and info["update_channel"]["apt_sources"]["active_network"] == 1
    # 一行式的 allow-insecure 選項
    ids, _, _ = run(only(update_channel=upd("@file sources.list\ndeb [allow-insecure=yes] http://x.example.invalid/ a b\n")))
    assert ids["board:apt-insecure-allowed"]["severity"] == "high"


def test_apt_config_case_and_boolean_words():
    cfg = ('acquire::allowinsecurerepositories "true";\nAcquire::https::Verify-Peer "with";\nAcquire::https::Verify-Host "enable";\n'
           'Acquire::http::Verify-Peer "without";\nAPT::Get::AllowUnauthenticated "0";\nAcquire::Evil::Key "true";')
    out = upd("@file sources.list\ndeb [] https://x.example.invalid/ a b\n").replace(
        "dump=NOT_RUN (no apt-config, or it failed)", "dump=ok\n" + cfg)
    ids, info, _ = run(only(update_channel=out))
    assert "acquire::allowinsecurerepositories = true" in " ".join(ids["board:apt-insecure-allowed"]["evidence"])
    tls = " ".join(ids["board:apt-tls-verify-off"]["evidence"])
    assert "Acquire::http::Verify-Peer = without" in tls and "with" not in tls.replace("without", "") and "enable" not in tls
    assert "Acquire::Evil::Key" not in json.dumps(info)       # 白名單以外的鍵不收


def test_local_unsigned_source_is_medium():
    # 板上收集腳本對本機來源（file:、cdrom:、copy:）只輸出協定，不輸出路徑
    ids, info, _ = run(only(update_channel=upd("@file sources.list\ndeb [trusted=yes] file: ./\ndeb [trusted=yes] cdrom: stable main\n")))
    f = ids["board:apt-insecure-allowed"]
    assert f["severity"] == "medium" and "local" in f["text"] and info["update_channel"]["apt_sources"]["local"] == 2
    assert info["update_channel"]["apt_sources"]["active_network"] == 0
    # 網路來源 trusted=yes 在場時仍是 high
    ids, _, _ = run(only(update_channel=upd("@file sources.list\ndeb [trusted=yes] file: ./\ndeb [trusted=yes] http://n.example.invalid/ a b\n")))
    assert ids["board:apt-insecure-allowed"]["severity"] == "high"


# ---------- C0 要求的規則：沒找到保護機制、沒量到，最多出 info，不當成通過 ----------

NOTHING_INTEG = ("== uefi\nefi=absent\nSecureBoot=NOT_RUN (no efivar)\nSetupMode=NOT_RUN (no efivar)\n== dt-secure-boot\nvalue=NOT_RUN (x)\n"
                 "== dmesg-secureboot\nNOT_RUN (no matching dmesg line)\n== tegra-fuse\ntegra=no\n== lockdown\nlockdown=NOT_RUN (no securityfs)\n"
                 "== modsig\nsig_enforce=NOT_RUN (x)\n== tpm\ntpm=absent\n== ima\nima=absent\n== dm-verity\ncmdline_verity=no\n")
NOTHING_LOG = ("== journald\nactive=NOT_RUN (no systemctl)\npersistent_dir=no\n== daemons\n== rotation\nlogrotate=NOT_RUN (x)\n"
               "== remote-logging\nrsyslog_remote=no\nauditd_remote=no\n== auth-logging\nauth_log_file=absent\nrsyslog_auth_rule=absent\n"
               "journal_ssh_entries=0\n")


@pytest.mark.parametrize("files", [
    {"integrity": NOTHING_INTEG},
    {"update_channel": UPD_NONE},
    {"logging": NOTHING_LOG},
    {"integrity": "", "update_channel": "", "logging": ""},           # 檔案是空的：每一項都沒量到
    {"integrity": NOTHING_INTEG, "update_channel": UPD_NONE, "logging": NOTHING_LOG},
])
def test_not_found_or_not_measured_is_at_most_info(files):
    ids, info, _ = run(only(**files))
    sev = new_ids(ids)
    assert all(v == "info" for v in sev.values()), sev
    for k in files:
        i = info[k]
        assert i["not_run"], k                       # 沒量到的項目要列出來，不是空的（不是「全部通過」）
        assert "pass" not in json.dumps(i).lower() and '"ok"' not in json.dumps(i).lower()
    if "integrity" in files:
        assert info["integrity"]["secure_boot_uefi"] in (None, "no_uefi")
        assert sev.get("board:secureboot-not-assessed") == "info"     # 沒有證據：記 info（NOT_RUN），不是沒有 finding


def test_not_found_or_not_measured_end_to_end_is_info(tmp_path):
    rd = rootfs_result(tmp_path)
    files = dict(BOARD_FILES)
    files["summary.txt"] = BOARD_FILES["summary.txt"] + SUMMARY.split("\n", 1)[1]
    files.update({"integrity.txt": NOTHING_INTEG, "update-channel.txt": UPD_NONE, "logging.txt": NOTHING_LOG})
    r, doc = import_(rd, targz(tmp_path, BOARD, files))
    assert doc is not None, r.stdout + r.stderr
    new = {f["id"]: f["severity"] for f in doc["findings"] if f["id"] in (
        "board:secureboot-not-assessed", "board:update-channel-not-found", "board:remote-logging-not-configured",
        "board:auth-logging-not-found", "board:integrity-verification-not-found")}
    assert new and set(new.values()) == {"info"}, new


def test_security_findings_shows_script_version(tmp_path):
    """security_findings.py 的測試工具欄：summary.txt 有 script-version 時顯示版本，沒有時照舊寫 not recorded。"""
    sys.path.insert(0, str(HERE.parent))
    import security_findings as sf
    for with_version, want in ((True, "board-on-device.sh 2026-11-13.2"), (False, "board-on-device.sh (script version not recorded)")):
        rd = rootfs_result(tmp_path / str(with_version))
        files = dict(BOARD_FILES)
        if with_version:
            files["summary.txt"] = BOARD_FILES["summary.txt"] + SUMMARY.split("\n", 1)[1]
        r, doc = import_(rd, targz(tmp_path / str(with_version), BOARD, files))
        assert doc is not None, r.stdout + r.stderr
        res = sf.evaluate(None, str(rd / "board-test" / "board-test.json"), {}, {})
        board = next(t for t in res["tests"] if t["key"] == "board")
        assert board["tool"].startswith(want), board["tool"]
