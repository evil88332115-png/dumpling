"""板子執行中使用的證據：board-on-device.sh 新增的收集、board_import.py 的解析、pkg_why.py 的檔案擁有者清單、
runtime_evidence.py 的欄位，以及 cra_report.py 的 vulnerability-rows.json／VEX 說明／安全測試小節。全部是合成的資料。
原則：只加欄位，不改 tier、不改 VEX 狀態；沒有資料 → not measured，不猜。"""
import json
import subprocess
import sys
from pathlib import Path

from test_cra_report import MIN_CFG, finding, make_project, make_scan, run, write_json
from test_security_testing import cra, import_, rootfs_result, targz
from test_pkg_why import STATUS, cli, tar_with

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import board_import as bi  # noqa: E402
import pkg_why as pw  # noqa: E402
import report_package as rp  # noqa: E402
import runtime_evidence as re_  # noqa: E402

ROOT = HERE.parents[2]
ON = ROOT / "tools" / "demo" / "board-on-device.sh"
STEM = "board-test-exdev-20261111T010203Z"
FIRMWARE = """== dmi
bios_version=EX_Board_R39.2.0-2
bios_date=10/28/2026
bios_vendor=EDK II
== nv_tegra_release
# R39 (release), REVISION: 2.0, GCID: 1, BOARD: generic, EABI: aarch64, DATE: Mon Jun  1 2026
== nvbootctrl
Current version: 39.2.0
Current bootloader slot: A
== nvbootctrl-rootfs
NOT_RUN (no nvbootctrl, or it failed)
== dmesg-optee
optee: revision 4.6 (565c76420cf641dd)
== dmesg-bpmp
NOT_RUN (no bpmp firmware line in dmesg, or dmesg not readable)
== efivar-SecureBoot
SecureBoot=0
== efivar-SetupMode
SetupMode=NOT_RUN (efivars not readable)
"""
GOOD_FILES = ["/usr/bin/bash", "/usr/lib/aarch64-linux-gnu/libc.so.6", "/usr/lib/aarch64-linux-gnu/libssl.so.3",
              "/lib/aarch64-linux-gnu/libz.so.1", "/etc/ld.so.cache"]


def rtfile(paths, n=None, extra=""):
    return f"# ok {len(paths) if n is None else n} paths\n" + "\n".join(paths) + "\n" + extra


RUNTIME_FILES = rtfile(GOOD_FILES)
RUNTIME_MODULES = "iptable_filter\nusb-f-ncm\n===\n 11:47:55 up 2 days, 11:08,  2 users,  load average: 0.02\n222\n"
BOARD_FILES = {"summary.txt": "check\tstatus\tdetail\nos\tOK\tos.txt\nfirmware\tOK\tfirmware.txt\n", "os.txt": "PRETTY_NAME=\"Ubuntu 24.04\"\n",
               "firmware.txt": FIRMWARE, "runtime-files.txt": RUNTIME_FILES, "runtime-modules.txt": RUNTIME_MODULES}
OWNERS = "libssl3t64\t/usr/lib/aarch64-linux-gnu/libssl.so.3\nlibssl3t64\t/usr/share/doc/libssl3t64\nbash\t/usr/bin/bash\nzlib1g\t/usr/lib/aarch64-linux-gnu/libz.so.1\nopenssl\t/usr/bin/openssl\nbusybox\t/bin/busybox\n"


# ---------- board-on-device.sh ----------





# ---------- board_import.py ----------

def test_import_parses_firmware_and_runtime(tmp_path):
    rd = rootfs_result(tmp_path)
    r, doc = import_(rd, targz(tmp_path, STEM, BOARD_FILES))
    assert r.returncode in (0, 2), r.stderr
    info = doc["runs"][0]["info"]
    fw = info["firmware"]
    assert fw["bios_version"] == "EX_Board_R39.2.0-2" and fw["l4t"] == "R39.2.0" and fw["nvbootctrl_version"] == "39.2.0"
    assert fw["optee"] == "revision 4.6 (565c76420cf641dd)" and fw["secure_boot"] == 0
    # NOT_RUN 的項目是 None（未量測），不是 0 或空字串
    assert fw["bpmp"] is None and fw["setup_mode"] is None and fw["nvbootctrl_rootfs"] is None
    assert {"dmesg-bpmp", "efivar-SetupMode", "nvbootctrl-rootfs"} <= set(fw["not_run"])
    rt = info["runtime"]
    assert rt["files"] == sorted(GOOD_FILES) and rt["ignored_lines"] == 0 and "files_problem" not in rt
    assert rt["modules"] == ["iptable_filter", "usb_f_ncm"]
    assert rt["processes"] == 222 and "up 2 days" in rt["uptime"] and rt["captured"] == "2026-11-11T01:02:03Z"
    assert doc["schema"] == "sca-center-board-test/1"       # 舊版讀取端不會因為新欄位而拒絕


def test_old_archive_without_new_files_still_imports(tmp_path):
    rd = rootfs_result(tmp_path)
    files = {k: v for k, v in BOARD_FILES.items() if not k.startswith(("firmware", "runtime"))}
    r, doc = import_(rd, targz(tmp_path, STEM, dict(files, **{"lsmod.txt": "Module Size Used by\nnf_tables 1 0\n"})))
    info = doc["runs"][0]["info"]
    assert "firmware" not in info and "runtime" not in info
    assert re_.pick_runtime(doc) is None


def runtime_of(tmp_path, text, **more):
    rd = rootfs_result(tmp_path)
    r, doc = import_(rd, targz(tmp_path, STEM, dict(BOARD_FILES, **{"runtime-files.txt": text}, **more)))
    return doc["runs"][0]["info"]["runtime"], doc


def test_unusable_file_lists_are_not_measured(tmp_path):
    for name, text, why in (
            ("empty", "", "header"), ("header only", "# ok 0 paths\n", "empty"),
            ("no header", "\n".join(GOOD_FILES) + "\n", "header"),
            ("count mismatch", rtfile(GOOD_FILES, n=99), "header says 99"),
            ("bad line", rtfile(GOOD_FILES, extra="relative/bad\n"), "not plain absolute"),
            ("no libc", rtfile(["/usr/bin/bash", "/etc/x"]), "implausible"),
            ("nothing under usr/lib", rtfile(["/usr/bin/bash", "/etc/libc.so.6"]), "implausible")):
        sub = tmp_path / name.replace(" ", "_").replace("/", "_")
        sub.mkdir()
        rt, doc = runtime_of(sub, text)
        assert rt["files"] is None and why in rt["files_problem"], (name, rt)
        assert any("not measured" in n for n in doc["notes"]), name
        # Evidence: not measured, not "not observed"
        ev = re_.Evidence(re_.pick_runtime(doc), {"/usr/bin/x": {"bash"}}, None, FakeDB(["bash"]), None)
        f = ev.fields(deb("bash"))
        assert f["runtime_observed"] == re_.NOT_MEASURED and "cannot be used" in f["runtime_evidence"], name


def test_over_limit_file_list_is_not_measured(monkeypatch):
    data = rtfile(GOOD_FILES).encode()
    notes = []
    assert bi.parse_runtime({"runtime-files.txt": data}, "s", notes, "t")["files"] == sorted(GOOD_FILES)
    monkeypatch.setattr(bi, "RUNTIME_MAX_PATHS", 3)
    rt = bi.parse_runtime({"runtime-files.txt": data}, "s", notes, "t")
    assert rt["files"] is None and "truncated" in rt["files_problem"] and any("not measured" in n for n in notes)
    monkeypatch.setattr(bi, "RUNTIME_MAX_PATHS", 100_000)
    monkeypatch.setitem(bi.LIMITS, "lines", 2)
    rt = bi.parse_runtime({"runtime-files.txt": data}, "s", [], "t")
    assert rt["files"] is None and "truncated" in rt["files_problem"]


def test_nvbootctrl_failure_block_is_none(tmp_path):
    fw = FIRMWARE.replace("Current version: 39.2.0\nCurrent bootloader slot: A\n", "Current version: 39.2.0\nNOT_RUN (no nvbootctrl, or it failed)\n")
    rd = rootfs_result(tmp_path)
    r, doc = import_(rd, targz(tmp_path, STEM, dict(BOARD_FILES, **{"firmware.txt": fw})))
    f = doc["runs"][0]["info"]["firmware"]
    assert f["nvbootctrl_slots"] is None and "nvbootctrl" in f["not_run"]


def test_firmware_unreadable_is_noted(tmp_path):
    rd = rootfs_result(tmp_path)
    r, doc = import_(rd, targz(tmp_path, STEM, dict(BOARD_FILES, **{"firmware.txt": "garbage\n"})))
    fw = doc["runs"][0]["info"]["firmware"]
    assert fw["bios_version"] is None and any("讀不出任何韌體版本" in n for n in doc["notes"])


# ---------- pkg_why.py extract：檔案擁有者清單 ----------

def test_extract_writes_file_owners_from_dir_and_tar(tmp_path):
    root = tmp_path / "rootfs"
    (root / "var/lib/dpkg/info").mkdir(parents=True)
    (root / "var/lib/apt").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text(STATUS)
    (root / "var/lib/dpkg/info/libssl3t64:arm64.list").write_text("/.\n/usr/lib/aarch64-linux-gnu/libssl.so.3\n")
    (root / "var/lib/dpkg/info/bash.list").write_text("/usr/bin/bash\n")
    (root / "var/lib/dpkg/info/bash.md5sums").write_text("abc  usr/bin/bash\n")
    r = cli("extract", "--from", str(root), "--out", str(tmp_path / "a"))
    assert r.returncode == 0 and "PKGDB\tOK" in r.stdout, r.stdout + r.stderr
    got = (tmp_path / "a" / "dpkg-file-owners").read_text()
    assert got == "bash\t/usr/bin/bash\nlibssl3t64\t/usr/lib/aarch64-linux-gnu/libssl.so.3\n"
    tar = tmp_path / "r.tar"
    tar_with(tar, [("./var/lib/dpkg/status", STATUS), ("./var/lib/dpkg/info/bash.list", "/usr/bin/bash\n"),
                   ("./var/lib/dpkg/info/bash.md5sums", "x\n")])
    r = cli("extract", "--from", str(tar), "--out", str(tmp_path / "b"))
    assert r.returncode == 0 and (tmp_path / "b" / "dpkg-file-owners").read_text() == "bash\t/usr/bin/bash\n"
    # 沒有 .list：照樣 OK（dpkg-status 才是必要的），不留上一次的擁有者檔
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "dpkg-file-owners").write_text("stale\t/x\n")
    tar2 = tmp_path / "r2.tar"
    tar_with(tar2, [("./var/lib/dpkg/status", STATUS)])
    r = cli("extract", "--from", str(tar2), "--out", str(tmp_path / "c"))
    assert "PKGDB\tOK" in r.stdout and not (tmp_path / "c" / "dpkg-file-owners").exists()


# ---------- runtime_evidence.py ----------

class FakeDB:
    def __init__(self, pkgs, by_source=None):
        self.pkgs = {p: {} for p in pkgs}
        self.by_source = by_source or {}


def runtime(files=("/usr/bin/bash", "/usr/lib/aarch64-linux-gnu/libssl.so.3", "/lib/aarch64-linux-gnu/libz.so.1"), modules=("iptable_filter",)):
    return {"files": list(files), "modules": list(modules), "processes": 222, "when": "2026-11-11T01:02:03Z"}


def owners(tmp_path, text=OWNERS):
    d = tmp_path / "pkgdb"
    d.mkdir(exist_ok=True)
    (d / "dpkg-file-owners").write_text(text)
    return re_.load_owners(d)


def deb(name, **kw):
    return dict({"id": "CVE-2026-1", "component": name, "version": "1", "purl": f"pkg:deb/ubuntu/{name}@1?arch=arm64", "kernel": False}, **kw)


def test_userland_in_use_not_observed_not_measured(tmp_path):
    own, prob = owners(tmp_path)
    ev = re_.Evidence(runtime(), own, prob, FakeDB(["libssl3t64", "openssl", "bash", "zlib1g", "busybox"], {"zlib": {"zlib1g"}}), None)
    f = ev.fields(deb("libssl3t64"), [(9.8, "CVSS:3.1/AV:N/AC:L", "x")])
    assert f["runtime_observed"] == re_.IN_USE and "libssl.so.3" in f["runtime_evidence"] and f["attack_vector"] == "N"
    assert ev.fields(deb("openssl"))["runtime_observed"] == re_.NOT_SEEN                   # 套件有裝、檔案沒被用到
    assert ev.fields(deb("zlib1g"))["runtime_observed"] == re_.IN_USE                        # /lib 與 /usr/lib 合併的寫法
    src = ev.fields(deb("zlib", purl="pkg:deb/ubuntu/zlib@1?arch=source"))                 # 來源套件的列：看它的二進位套件
    assert src["runtime_observed"] == re_.IN_USE and src["runtime_via_source"] is True and "1 of 1 binaries in use" in src["runtime_evidence"]
    assert ev.fields(deb("ghost"))["runtime_observed"] == re_.NOT_MEASURED                   # 映像裡找不到這個套件：不猜
    py = ev.fields(deb("brotli", purl="pkg:pypi/brotli@1"))
    assert py["runtime_observed"] == re_.NOT_MEASURED and "not a dpkg package" in py["runtime_evidence"]
    assert ev.fields(deb("bash"), None)["attack_vector"] == "unknown"
    # 沒有板子資料、沒有擁有者清單 → not measured（不是 not observed）
    none = re_.Evidence(None, own, prob, FakeDB(["bash"]), None).fields(deb("bash"))
    assert none["runtime_observed"] == re_.NOT_MEASURED and "no runtime data" in none["runtime_evidence"]
    no_own = re_.Evidence(runtime(), None, "the scanned image has no dpkg file lists", FakeDB(["bash"]), None).fields(deb("bash"))
    assert no_own["runtime_observed"] == re_.NOT_MEASURED and "file lists" in no_own["runtime_evidence"]


def test_source_name_equals_binary_name_looks_at_library_binaries(tmp_path):
    """openssl 是來源套件也是命令列工具的名稱：命令列工具沒被用到、libssl 有被用到 → in use（經由來源套件），不是 not observed。"""
    own, prob = owners(tmp_path)
    db = FakeDB(["openssl", "libssl3t64", "libssl-dev", "openssl-doc"], {"openssl": {"openssl", "libssl3t64", "libssl-dev", "openssl-doc"}})
    own = dict(own, **{"/usr/include/openssl/ssl.h": {"libssl-dev"}})
    ev = re_.Evidence(runtime(), own, prob, db, None)
    f = ev.fields(deb("openssl"))
    assert f["runtime_observed"] == re_.IN_USE and f["runtime_via_source"] is True
    assert f["runtime_binaries"] == "1 of 2 binaries in use"            # -dev、-doc 不算
    note = ev.vex_note(f)
    assert "a binary package built from the same source package was in use" in note and "1 of 2 binaries in use" in note
    # 一個都沒用到：not observed，說明是「來源套件的二進位套件」
    ev2 = re_.Evidence(runtime(files=["/usr/bin/bash"]), own, prob, db, None)
    g = ev2.fields(deb("openssl"))
    assert g["runtime_observed"] == re_.NOT_SEEN and g["runtime_binaries"] == "0 of 2 binaries in use"
    assert "binary packages built from this source package" in ev2.vex_note(g)
    # 命令列工具自己被用到：不是 via_source
    own2 = dict(own, **{"/usr/bin/openssl": {"openssl"}})
    ev3 = re_.Evidence(runtime(files=["/usr/bin/openssl"]), own2, prob, db, None)
    h = ev3.fields(deb("openssl"))
    assert h["runtime_observed"] == re_.IN_USE and h["runtime_via_source"] is False


def test_other_guards_not_measured(tmp_path):
    own, prob = owners(tmp_path)
    assert re_.Evidence(runtime(), own, prob, None, None).fields(deb("bash"))["runtime_observed"] == re_.NOT_MEASURED       # 沒有 dpkg-status
    # 板子的 L4T 和被掃描的映像不同
    rt = dict(runtime(), l4t="R39.2.0")
    ev = re_.Evidence(rt, own, prob, FakeDB(["bash"]), kcfg(kres("CVE-2", [("d.c", "module", "iptable_filter", True)])), "R38.4.0")
    f = ev.fields(deb("bash"))
    assert f["runtime_observed"] == re_.NOT_MEASURED and "R39.2.0" in f["runtime_evidence"] and "R38.4.0" in f["runtime_evidence"]
    assert ev.fields({"id": "CVE-2", "kernel": True})["module_state"] == re_.MOD_UNMEASURED
    assert re_.Evidence(rt, own, prob, FakeDB(["bash"]), None, "R39.2.0").fields(deb("bash"))["runtime_observed"] == re_.IN_USE
    # 檔案擁有者清單被截斷（#partial）→ 不用
    d = tmp_path / "partial"
    d.mkdir()
    (d / "dpkg-file-owners").write_text("#partial\n" + OWNERS)
    o, why = re_.load_owners(d)
    assert o is None and "partial" in why


def test_attack_vector_picks_highest_score_with_a_vector():
    cv = [(9.8, None, "a"), (7.5, "CVSS:3.1/AV:L/AC:L", "b"), (5.0, "AV:N/AC:L/Au:N", "c")]
    assert re_.attack_vector(cv) == "L"
    assert re_.attack_vector([(5.0, "(AV:P/AC:L)", "v2")]) == "P" and re_.attack_vector([(9, "CVSS:4.0/AV:A/AC:L", "v4")]) == "A"
    assert re_.attack_vector([]) == "unknown" and re_.attack_vector([(9.0, None, "x")]) == "unknown"


def kcfg(*results):
    return {"schema": "sca-center-kernel-config/1", "results": list(results)}


def kres(cve, files, decision="affected"):
    return {"cve": cve, "decision": decision, "files": [{"path": p, "built": b, "built_as": a, "module": m} for p, a, m, b in files]}


def test_kernel_module_state(tmp_path):
    k = kcfg(kres("CVE-1", [("net/a.c", "builtin", None, True), ("include/h.h", None, None, True)]),
             kres("CVE-2", [("drivers/x.c", "module", "iptable-filter", True)]),
             kres("CVE-3", [("drivers/y.c", "module", "nope", True)]),
             kres("CVE-4", [("include/only.h", None, None, True)]),
             kres("CVE-5", [("drivers/z.c", "module", "nope", False)], decision="not_affected"),
             kres("CVE-6", [], decision="unknown"),
             kres("CVE-7", [("a.c", "module", None, True)]))
    ev = re_.Evidence(runtime(), None, "x", None, k)
    st = lambda cve: ev.fields({"id": cve, "kernel": True, "cves": [cve]})["module_state"]
    assert st("CVE-1") == re_.BUILT_IN and st("CVE-2") == re_.MOD_LOADED and st("CVE-3") == re_.MOD_NOT_LOADED
    assert st("CVE-4") == re_.UNKNOWN and st("CVE-5") is None and st("CVE-6") == re_.UNKNOWN and st("CVE-7") == re_.UNKNOWN
    assert st("CVE-99") == re_.UNKNOWN                                                          # kernel-config 沒有這個 CVE
    # 沒有板子的模組清單：只有 built-in 能確定
    ev2 = re_.Evidence(None, None, "x", None, k)
    assert ev2.fields({"id": "CVE-2", "kernel": True})["module_state"] == re_.MOD_UNMEASURED
    assert ev2.fields({"id": "CVE-1", "kernel": True})["module_state"] == re_.BUILT_IN
    assert ev.fields({"id": "CVE-2", "kernel": True})["runtime_observed"] is None


def test_vex_note_wording():
    ev = re_.Evidence(runtime(), None, "x", None, None)
    n = ev.vex_note({"runtime_observed": re_.IN_USE})
    assert "in use on the tested board" in n and "one board, measured 2026-11-11, 222 processes" in n
    n = ev.vex_note({"runtime_observed": re_.NOT_SEEN})
    assert "not observed in use on the tested board" in n and "not evidence that the component is unused" in n
    assert ev.vex_note({"runtime_observed": re_.NOT_MEASURED}) == "" and ev.vex_note({"module_state": re_.UNKNOWN}) == ""
    assert "loaded" in ev.vex_note({"module_state": re_.MOD_LOADED}) and "on demand" in ev.vex_note({"module_state": re_.MOD_NOT_LOADED})


def test_firmware_rows_compare_version_strings():
    doc = {"runs": [{"kind": "board", "current": True, "time": "2026-11-11T00:00:00Z", "info": {"firmware": {
        "bios_version": "EX_R39.2.0-2", "l4t": "R39.2.0", "optee": "revision 4.6", "bpmp": None, "secure_boot": 0, "setup_mode": 1,
        "nvbootctrl_slots": ["Current version: 39.2.0"]}}}]}
    chk = {"images": [{"version_found": [{"found": "EX_R39.2.0-2"}]}, {"version_found": []}]}
    rows = {r[0].split(" (")[0]: r for r in re_.firmware_rows(doc, chk, "39.2.0-20260601")}
    assert rows["UEFI version"][3] == "same" and "in 1 of 2" in rows["UEFI version"][2]
    assert rows["L4T release"][3] == "same"
    assert re_.firmware_rows(doc, {"images": [{"version_found": [{"found": "OTHER"}]}]}, "39.1.0-1")[0][3] == "different"
    assert re_.firmware_rows(doc, None, None)[0][3] == "not comparable" and re_.firmware_rows(doc, None, None)[1][3] == "not comparable"
    assert rows["BPMP firmware"][1] == "NOT_RUN"
    assert re_.firmware_rows({"runs": []}, chk, None) is None


# ---------- cra_report.py（合成的小型掃描） ----------

def test_cra_report_adds_runtime_fields_without_changing_tiers(tmp_path):
    rd = rootfs_result(tmp_path)
    plain_r, plain_s, plain_reports = cra(rd)
    plain = json.loads((plain_reports / "vulnerability-rows.json").read_text())["rows"]
    # 沒有板子的執行資料 → 欄位在，值是 not measured；其他欄位完全不變
    assert plain and all(x["runtime_observed"] == re_.NOT_MEASURED for x in plain if not x["is_kernel"])
    d = rd / "pkgdb"
    d.mkdir()
    (d / "dpkg-status").write_text("Package: openssl\nStatus: install ok installed\nArchitecture: arm64\nVersion: 3.0.13-0ubuntu3.11\n\n")
    (d / "dpkg-file-owners").write_text("openssl\t/usr/bin/openssl\nopenssl\t/usr/lib/aarch64-linux-gnu/libssl.so.3\n")
    files = dict(BOARD_FILES, **{"runtime-files.txt": rtfile(["/usr/bin/openssl", "/usr/lib/aarch64-linux-gnu/libc.so.6"])})
    import_(rd, targz(tmp_path, STEM, files))
    r, s, reports = cra(rd)
    rows = json.loads((reports / "vulnerability-rows.json").read_text())["rows"]
    for a, b in zip(plain, rows):
        for k in ("id", "tier", "vex", "severity", "fix_state", "exposed"):
            assert a[k] == b[k], k
    o = next(x for x in rows if x["component"] == "openssl")
    assert o["runtime_observed"] == re_.IN_USE and "openssl: /usr/bin/openssl" in o["runtime_evidence"] and o["attack_vector"] == "unknown"
    # 安全測試小節：板子韌體版本 vs 刷機包
    ra = (reports / "risk-assessment.md").read_text()
    assert "Firmware versions: tested board vs flash package" in ra and "EX_Board_R39.2.0-2" in ra and "NOT_RUN" in ra


def test_vex_detail_gets_runtime_note_only_for_affected_states(tmp_path):
    import vex_export as vx
    row = {"id": "CVE-1", "component": "openssl", "version": "1", "purl": "pkg:deb/ubuntu/openssl@1", "tier": "p3",
           "vex": {"state": "exploitable", "source": "rule", "detail": "Affected by version; exploitability not assessed."},
           "runtime_note": "Runtime observation (one board, measured 2026-11-11): component in use on the tested board."}
    other = dict(row, id="CVE-2", vex={"state": "not_affected", "source": "rule", "justification": "code_not_present", "detail": "not built"})
    pbom = {"serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000", "version": 1,
            "metadata": {"component": {"name": "p", "bom-ref": "p"}}, "components": [{"bom-ref": "c1", "name": "openssl", "version": "1", "purl": "pkg:deb/ubuntu/openssl@1"}]}
    cdx, _ = vx.cdx_vex([row, dict(other, runtime_note=row["runtime_note"])], pbom, {}, {"name": "p", "version": "1"}, "OK")
    by = {v["id"]: v["analysis"]["detail"] for v in cdx["vulnerabilities"]}
    assert by["CVE-1"] == "Affected by version; exploitability not assessed. " + row["runtime_note"]
    assert by["CVE-2"] == "not built"           # 不受影響的陳述不附這句，狀態也不變
    assert {v["id"]: v["analysis"]["state"] for v in cdx["vulnerabilities"]} == {"CVE-1": "exploitable", "CVE-2": "not_affected"}


def test_report_package_columns_are_additive():
    r = {"id": "CVE-1", "tier": "p3", "component": "x", "attack_vector": "N", "runtime_observed": re_.NOT_SEEN, "module_state": re_.BUILT_IN}
    assert rp.HEADER[-3:] == ["攻擊向量", "板子上使用情形", "核心模組狀態"]
    assert rp.RUNTIME_ZH[re_.NOT_SEEN].endswith("（不代表沒用到）") and set(rp.MODULE_ZH) >= {re_.BUILT_IN, re_.MOD_LOADED, re_.MOD_NOT_LOADED}
    assert set(rp.AV_ZH) == {"N", "A", "L", "P", "unknown"}


def test_extract_marks_truncated_file_lists_partial(tmp_path, monkeypatch):
    root = tmp_path / "rootfs"
    (root / "var/lib/dpkg/info").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text(STATUS)
    for n in ("a", "b", "c"):
        (root / f"var/lib/dpkg/info/{n}.list").write_text("/usr/bin/" + n + "\n")
    monkeypatch.setattr(pw, "MAX_LISTS", 10)
    st, _ = pw.do_extract(str(root), None, str(tmp_path / "out"))
    assert st == "OK" and (tmp_path / "out" / "dpkg-file-owners").read_text().startswith("#partial\n")
    owners, why = re_.load_owners(tmp_path / "out")
    assert owners is None and "partial" in why
