"""tools/mirror/ubuntu-cve-status.sh：Ubuntu CVE Tracker 的狀態鏡像（建立、--check、上限、解析規則）。

假的 tracker 倉庫照 2026-11-05 的 git.launchpad.net/ubuntu-cve-tracker（commit a93f076c）的格式：
active/、retired/ 底下每個 CVE 一個檔（Candidate:、Priority: 與縮排的理由、Priority_<套件>[_<發行版>]:、
<發行版>_<來源套件>: <狀態> (<版本或說明>)、Patches_<套件>: 區塊、# 開頭的註解行）；狀態的定義取自同一個倉庫的 README「Package Status」，
解析的意思取自同一個倉庫 scripts/cve_lib.py 的 load_cve、parse_cve_release_package_field（只參考行為，沒有複製程式碼）。
"""
import datetime
import gzip
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
MIRROR_SH = ROOT / "tools" / "mirror" / "ubuntu-cve-status.sh"
SCHEMA = "sca-ubuntu-cve-status/1"
FILES = {"main": "ubuntu-cve-status.json.gz", "linux": "ubuntu-cve-status-linux.json.gz"}

CVE1 = """Candidate: CVE-2024-0001
PublicDate: 2024-03-29 17:15:00 UTC
References:
 https://example.invalid/CVE-2024-0001
Description:
 jammy_fake: released (this is a continuation line, not a status)
Notes:
 someone> noble_fake: needed (also not a status)
Priority: high
 Remote code execution in a default install
Discovered-by:
Assigned-to:
CVSS:
 nvd: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H [9.8 CRITICAL]

Patches_foo:
 upstream: https://example.invalid/patch
upstream_foo: released (1.3)
focal_foo: needed
jammy_foo: not-affected (code not present)
noble_foo: not-affected (1.2-3)
devel_foo: not-affected (1.2-3)
esm-apps/jammy_foo: released (1.1-1ubuntu0.1~esm1)
#jammy_foo: released (commented out)

Patches_bar:
Priority_bar: low
Priority_bar_noble: negligible
jammy_bar: ignored (end of standard support)
noble_bar: deferred (2024-06-17)

Patches_baz:
Tags_baz: pie
jammy_baz: needs-triage
noble_baz: needed something without parentheses

Patches_qux:
jammy_qux: pending (2.0-1ubuntu0.1)
noble_qux: released (2.0-2)

Patches_dne:
jammy_dne: DNE
noble_dne: DNE

Patches_weird:
jammy_weird: frobnicated (kept verbatim)
noble_weird: ignored
jammy_Bad_Pkg: needed

Patches_linux:
jammy_linux: needed
noble_linux: ignored (superseded by linux-hwe-6.8)
noble_linux-hwe-6.8: released (6.8.0-1.1)
noble_linuxptp: not-affected
"""

CVE2 = """Candidate: CVE-2023-0002
PublicDate: 2023-01-01
Priority: low
 Needs local access

Patches_old:
noble_old: released (0.9-1)
"""

CVE_ONLY_DNE = """Candidate: CVE-2024-0003
Priority: medium

Patches_gone:
focal_gone: needed
jammy_gone: DNE
noble_gone: DNE
"""

CVE_ONLY_FOCAL = """Candidate: CVE-2024-0004
Priority: medium

Patches_old:
focal_old: needed
"""

# 解析規則（tracker 的 load_cve／parse_cve_release_package_field 的意思）：每一行旁邊是預期結果
SEMANTICS = ("Candidate: CVE-2025-0010\r\n"          # CRLF：行尾的 \r 去掉
             "Priority: medium  # was high\r\n"      # 只取第一個詞
             "Notes:\n"
             " someone> text\u2028jammy_g: not-affected\n"   # 續行裡的 U+2028：不分行（不會變成狀態），只計數
             "jammy_a:\n"                            # 沒有狀態 = needs-triage
             "noble_a: 1.2-3\n"                      # 只有版本號 = released（舊寫法）
             "jammy_b : needed\n"                    # 冒號前的空白：欄位名稱去頭尾空白
             "\tnoble_b: not-affected (tab-led)\n"   # tab 開頭不是續行，照欄位解析
             "jammy_c: needed (abc\n"                # 只有開頭的括號：去掉
             "noble_c:\u00a0needed (nbsp)\n"         # 冒號後的 NBSP：值去頭尾空白時一起去掉
             "jammy_d: needed [bracket]\n"           # 說明以 [ 開頭：tracker 不接受 → 格式不符
             "Priority_e: low  # per-package comment\n"
             "jammy_e: needed\n"
             "jammy_e: not-affected (1.0)\n"         # 重複且不同：留第一行，標 conflict
             "noble_e: released (1.1)\n"
             "noble_e: released (1.1)\n"             # 重複但相同：只計數
             "jammy_f: DNE\n"
             "jammy_f: not-affected (2.0)\n"         # DNE 之後又有別的狀態：留 DNE，標 conflict（不收 DNE 時也保留）
             "noble_h: needed\r\n"
             "no colon here\n")                      # 沒有冒號：格式不符


def now(days=0.0):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(r, *args, env=None):
    e = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x",
         **(env or {})}
    return subprocess.run(["git", "-C", str(r), *args], check=True, env=e, capture_output=True)


def tracker(tmp_path, files=None, commit_date=None, extra=None):
    """假的 ubuntu-cve-tracker 倉庫。files 的值可以是 str 或 bytes；extra(r) 可以在 commit 前多放東西。"""
    r = tmp_path / "uct"
    files = files if files is not None else {"active/CVE-2024-0001": CVE1, "retired/CVE-2023-0002": CVE2,
                                             "active/CVE-2024-0003": CVE_ONLY_DNE, "active/CVE-2024-0004": CVE_ONLY_FOCAL}
    for name, text in files.items():
        (r / name).parent.mkdir(parents=True, exist_ok=True)
        (r / name).write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    (r / "active").mkdir(parents=True, exist_ok=True)
    (r / "active" / "Makefile").write_text("all:\n")
    (r / "active" / "CVE-2024-0005.orig").write_text(CVE_ONLY_FOCAL.replace("focal_old", "jammy_old"))
    (r / "active" / "sub").mkdir()
    (r / "active" / "sub" / "CVE-2024-0006").write_text(CVE_ONLY_FOCAL.replace("focal_old", "jammy_old"))
    os.symlink("/etc/passwd", r / "active" / "CVE-2024-0007")                  # 符號連結：不收、不讀
    x = r / "active" / "CVE-2024-0008"
    x.write_text(CVE_ONLY_FOCAL.replace("0004", "0008").replace("focal_old", "jammy_old"))
    x.chmod(0o755)                                                             # mode 100755：不收
    (r / "ignored").mkdir(parents=True, exist_ok=True)
    (r / "ignored" / "not-for-us.txt").write_text("CVE-2024-9999 # windows\n")
    (r / ".gitattributes").write_text("* export-subst\n")
    (r / "README").write_text("tracker\n")
    if extra:
        extra(r)
    env = {"GIT_COMMITTER_DATE": commit_date, "GIT_AUTHOR_DATE": commit_date} if commit_date else None
    for c in (["init", "-q", "-b", "master"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
        git(r, *c, env=env)
    return r


def run_mirror(*args, env=None):
    e = {**os.environ, "UBUNTU_CVE_MIN_CVES": "1", "UBUNTU_CVE_GIT_RETRY_SLEEP": "0", **(env or {})}
    return subprocess.run(["bash", str(MIRROR_SH), *map(str, args)], capture_output=True, text=True, timeout=120, env=e)


def load(m, part="main"):
    return json.loads(gzip.decompress((m / FILES[part]).read_bytes()))


def merged(m):
    """兩個檔合起來的 cves（同一個 CVE 的套件合併）。"""
    out = {}
    for part in FILES:
        for c, r in load(m, part)["cves"].items():
            out.setdefault(c, {**r, "packages": {}})["packages"].update(r["packages"])
    return out


def source(m):
    return dict(l.split("=", 1) for l in (m / "SOURCE").read_text().splitlines())


def build(tmp_path, name="m", repo=None, env=None):
    repo = repo or tracker(tmp_path)
    r = run_mirror(tmp_path / name, tmp_path / f"{name}.man", env={"UBUNTU_CVE_GIT_URL": repo.as_uri(), **(env or {})})
    assert r.returncode == 0, r.stdout + r.stderr
    return tmp_path / name, r


def E(status, note="", **kw):
    return {"status": status, "note": note, **kw}


def test_build_check_and_schema(tmp_path):
    m, r = build(tmp_path)
    assert sorted(p.name for p in m.iterdir()) == ["SOURCE", FILES["linux"], FILES["main"]]
    assert not list(tmp_path.glob(".ubuntu-cve-clone.*"))
    src = source(m)
    for part, fn in FILES.items():
        assert src[f"{part}_sha256"] == hashlib.sha256((m / fn).read_bytes()).hexdigest()
        assert src[f"{part}_bytes"] == str((m / fn).stat().st_size)
    assert src["releases"] == "jammy noble" and src["keep_dne"] == "0" and len(src["commit"]) == 40
    assert src["count_cve_files"] == "4" and src["cves"] == "2" and src["entries"] == "15"
    assert src["main_cves"] == "2" and src["main_entries"] == "12" and src["linux_cves"] == "1" and src["linux_entries"] == "3"
    idx, lx = load(m), load(m, "linux")
    for i, part in ((idx, "main"), (lx, "linux")):
        assert i["schema"] == SCHEMA and i["part"] == part and i["releases"] == ["jammy", "noble"] and i["keep_dne"] is False
        assert i["commit"] == src["commit"] and i["commit_date"] == src["commit_date"] and i["source"] == src["source"]
        assert "in-progress" in i["known_statuses"] and i["linux_part_rule"] == "^linux($|-)"
    # 只有 jammy／noble 有非 DNE 狀態的 CVE；只有 DNE 或只有 focal 的不收；檔名不符、符號連結、可執行檔都不收
    assert sorted(idx["cves"]) == ["CVE-2023-0002", "CVE-2024-0001"] and sorted(lx["cves"]) == ["CVE-2024-0001"]
    c = idx["cves"]["CVE-2024-0001"]
    assert c["priority"] == "high" and c["tracker_dir"] == "active"
    assert c["packages"] == {
        "foo": {"jammy": E("not-affected", "code not present"), "noble": E("not-affected", "1.2-3")},
        "bar": {"jammy": E("ignored", "end of standard support", priority="low"),
                "noble": E("deferred", "2024-06-17", priority="negligible")},                  # 發行版專屬的優先
        "baz": {"jammy": E("needs-triage"), "noble": E("needed", "something without parentheses")},
        "qux": {"jammy": E("pending", "2.0-1ubuntu0.1"), "noble": E("released", "2.0-2")},
        "weird": {"jammy": E("frobnicated", "kept verbatim"), "noble": E("ignored")},
        "linuxptp": {"noble": E("not-affected")},                                             # linux- 開頭才進 linux 檔
    }
    assert lx["cves"]["CVE-2024-0001"] == {"priority": "high", "tracker_dir": "active", "packages": {
        "linux": {"jammy": E("needed"), "noble": E("ignored", "superseded by linux-hwe-6.8")},
        "linux-hwe-6.8": {"noble": E("released", "6.8.0-1.1")}}}
    assert idx["cves"]["CVE-2023-0002"] == {"priority": "low", "tracker_dir": "retired",
                                            "packages": {"old": {"noble": E("released", "0.9-1")}}}
    cnt = idx["counts"]
    assert cnt == {**lx["counts"], "part": cnt["part"]}                                       # 全體的計數兩個檔相同
    assert cnt["cve_files"] == 4 and cnt["dne_not_kept"] == 4 and cnt["malformed_lines"] == 1 and cnt["skipped_names"] == 3
    assert cnt["duplicate_lines"] == 0 and cnt["conflicting_entries"] == 0 and cnt["non_utf8_files"] == 0
    assert cnt["part"]["cves"] == 2 and cnt["part"]["entries"] == 12 and lx["counts"]["part"]["entries"] == 3
    assert cnt["part"]["by_release"]["jammy"]["frobnicated"] == 1 and "DNE" not in cnt["part"]["by_release"]["noble"]
    man = (tmp_path / "m.man").read_text()
    assert "# releases: jammy noble" in man and "# commit=" in man and FILES["main"] in man and FILES["linux"] in man
    c = run_mirror("--check", m)
    assert c.returncode == 0, c.stdout
    assert c.stdout.startswith("OK commit=") and "releases=jammy,noble" in c.stdout and "cves=2 entries=15" in c.stdout
    assert "main_cves=2 linux_cves=1" in c.stdout and "not-affected=3 ignored=3 deferred=1" in c.stdout
    assert "unknown_status=1" in c.stdout and c.stdout.rstrip().endswith("unknown_values=(frobnicated)") and "both_files=1" in c.stdout
    assert "conflicting_entries=0 duplicate_lines=0 malformed_lines=1 non_utf8_files=0 odd_line_breaks=0 unknown_priorities=0 " \
        "truncated_fields=0 unknown_status=1" \
        in c.stdout[:300]                                                 # 異常的計數在開頭（ci-run.sh 只取前面一段）
    # 拒絕覆蓋
    assert run_mirror(m, tmp_path / "other.man", env={"UBUNTU_CVE_GIT_URL": "file:///nothere"}).returncode == 3
    assert run_mirror(tmp_path / "new", tmp_path / "m.man", env={"UBUNTU_CVE_GIT_URL": "file:///nothere"}).returncode == 3
    # 同一個 commit 建兩次，索引完全相同（gzip 不記時間）
    m2, _ = build(tmp_path, "m2", repo=tmp_path / "uct")
    for fn in FILES.values():
        assert (m2 / fn).read_bytes() == (m / fn).read_bytes()


def test_parsing_follows_tracker_semantics(tmp_path):
    files = {"active/CVE-2025-0010": SEMANTICS,
             "active/CVE-2025-0011": b"Candidate: CVE-2025-0011\nPriority: low\nDescription:\n caf\xe9 \xff\njammy_x: needed (caf\xe9)\n"}
    m, r = build(tmp_path, repo=tracker(tmp_path, files=files))
    cves = merged(m)
    c = cves["CVE-2025-0010"]
    assert c["priority"] == "medium"
    assert c["packages"] == {
        "a": {"jammy": E("needs-triage"), "noble": E("released", "1.2-3")},
        "b": {"jammy": E("needed"), "noble": E("not-affected", "tab-led")},
        "c": {"jammy": E("needed", "abc"), "noble": E("needed", "nbsp")},
        "e": {"jammy": E("needed", priority="low", conflict=[E("not-affected", "1.0")]), "noble": E("released", "1.1", priority="low")},
        "f": {"jammy": E("DNE", conflict=[E("not-affected", "2.0")])},
        "h": {"noble": E("needed")},
    }
    assert "g" not in c["packages"] and "d" not in c["packages"]
    assert cves["CVE-2025-0011"]["packages"] == {"x": {"jammy": E("needed", "caf\ufffd")}}       # 非 UTF-8：以 U+FFFD 取代
    cnt = load(m)["counts"]
    assert cnt["duplicate_lines"] == 3 and cnt["conflicting_entries"] == 2 and cnt["malformed_lines"] == 2
    assert cnt["odd_line_breaks"] == 1 and cnt["non_utf8_files"] == 1 and cnt["dne_not_kept"] == 0
    assert "conflicting_entries=2" in r.stdout and "non_utf8_files=1" in r.stdout
    src = source(m)
    assert src["count_conflicting_entries"] == "2" and src["main_conflicting_entries"] == "2" and src["count_duplicate_lines"] == "3"
    c = run_mirror("--check", m)
    assert c.returncode == 0 and "conflicting_entries=2 duplicate_lines=3 malformed_lines=2 non_utf8_files=1 odd_line_breaks=1" \
        in c.stdout, c.stdout


PRIO_AND_CAPS = ("Candidate: CVE-2025-0020\n"
                 "Candidate: CVE-2025-9999\n"              # 第二個 Candidate：第一次的為準（與 tracker 相同），不會失敗
                 "Priority:\n"                             # 空的 Priority = null
                 "Priority_x: bogus\n"                     # 認得的值以外：原樣保留、計數
                 "Priority_y:\n"                           # 空的 Priority_<套件>：不覆寫
                 "jammy_x: needed\n"
                 "noble_y: needed\n"
                 f"jammy_long: needed ({'n' * 5000})\n"     # 說明超過 4096 字：截斷、計數
                 f"noble_long: {'s' * 70}\n"                # 狀態超過 64 字：截斷、計數
                 f"jammy_{'p' * 129}: needed\n")            # 套件名稱超過 128 字：格式不符
PRIO2 = "Candidate: CVE-2025-0021\nPriority: urgent\n\njammy_z: needed\n"


def test_priority_values_truncation_and_candidate(tmp_path):
    m, r = build(tmp_path, repo=tracker(tmp_path, files={"active/CVE-2025-0020": PRIO_AND_CAPS, "active/CVE-2025-0021": PRIO2}))
    cves = merged(m)
    c = cves["CVE-2025-0020"]
    assert c["priority"] is None
    assert c["packages"]["x"] == {"jammy": E("needed", priority="bogus")} and c["packages"]["y"] == {"noble": E("needed")}
    assert c["packages"]["long"] == {"jammy": E("needed", "n" * 4096), "noble": E("s" * 64)}
    assert not any(len(k) > 128 for k in c["packages"])
    assert cves["CVE-2025-0021"]["priority"] == "urgent"
    cnt = load(m)["counts"]
    assert cnt["unknown_priorities"] == 2 and cnt["truncated_fields"] == 2 and cnt["malformed_lines"] == 1
    c = run_mirror("--check", m)
    assert c.returncode == 0 and "unknown_priorities=2 truncated_fields=2" in c.stdout[:300], c.stdout


def test_release_without_data_fails(tmp_path):
    repo = tracker(tmp_path)
    r = run_mirror(tmp_path / "t", tmp_path / "t.man", env={"UBUNTU_CVE_GIT_URL": repo.as_uri(), "UBUNTU_CVE_RELEASES": "jammy nobel"})
    assert r.returncode == 1 and "發行版 nobel 沒有任何非 DNE 的狀態" in r.stderr and not (tmp_path / "t" / "SOURCE").exists(), r.stderr
    # 只有 DNE 也算沒有資料
    (tmp_path / "d").mkdir()
    dne_only = tracker(tmp_path / "d", files={"active/CVE-2024-0003": CVE_ONLY_DNE, "retired/CVE-2023-0002": CVE2})
    r = run_mirror(tmp_path / "u", tmp_path / "u.man", env={"UBUNTU_CVE_GIT_URL": dne_only.as_uri(), "UBUNTU_CVE_KEEP_DNE": "1"})
    assert r.returncode == 1 and "發行版 jammy 沒有任何非 DNE 的狀態" in r.stderr, r.stderr
    # --check：鏡像的設定多了一個沒有資料的發行版（兩個檔與 SOURCE 一致）也要失敗
    m, _ = build(tmp_path, repo=repo)
    for part in FILES:
        idx = load(m, part)
        idx["releases"].append("nobel")
        idx["counts"]["part"]["by_release"]["nobel"] = {}
        rewrite(m, part, idx=idx)
    rewrite(m, releases="jammy noble nobel")
    c = run_mirror("--check", m)
    assert c.returncode == 1 and "發行版 nobel 沒有任何非 DNE 的狀態" in c.stdout, c.stdout


def test_keep_dne_and_more_releases(tmp_path):
    m, _ = build(tmp_path, env={"UBUNTU_CVE_KEEP_DNE": "1", "UBUNTU_CVE_RELEASES": "jammy noble esm-apps/jammy upstream"})
    idx = load(m)
    assert idx["releases"] == ["jammy", "noble", "esm-apps/jammy", "upstream"] and idx["keep_dne"] is True
    foo = idx["cves"]["CVE-2024-0001"]["packages"]["foo"]
    assert foo["esm-apps/jammy"] == E("released", "1.1-1ubuntu0.1~esm1")
    assert foo["upstream"] == E("released", "1.3") and "focal" not in foo and "devel" not in foo
    assert idx["cves"]["CVE-2024-0003"]["packages"] == {"gone": {"jammy": E("DNE"), "noble": E("DNE")}}
    assert "CVE-2024-0004" not in idx["cves"]
    c = run_mirror("--check", m)
    assert c.returncode == 0 and "keep_dne=1" in c.stdout and "releases=jammy,noble,esm-apps/jammy,upstream" in c.stdout, c.stdout


@pytest.mark.parametrize("env", [
    {"UBUNTU_CVE_GIT_URL": "ssh://evil/x"},
    {"UBUNTU_CVE_GIT_URL": "http://plain/x"},
    {"UBUNTU_CVE_RELEASES": "../../etc"},
    {"UBUNTU_CVE_RELEASES": "jammy ../x"},
    {"UBUNTU_CVE_RELEASES": "jammy;rm"},
    {"UBUNTU_CVE_RELEASES": "esm-apps//jammy"},
    {"UBUNTU_CVE_RELEASES": "/jammy"},
    {"UBUNTU_CVE_RELEASES": "  "},
    {"UBUNTU_CVE_KEEP_DNE": "yes"},
    {"UBUNTU_CVE_MAX_RECORD_KB": "1;rm"},
    {"UBUNTU_CVE_MAX_AGE_DAYS": "-1"},
    {"UBUNTU_CVE_MAX_AGE_DAYS": "0.5"},
    {"UBUNTU_CVE_MAX_DOWNLOAD_MB": "1.5"},
    {"UBUNTU_CVE_MIN_CVES": "1.5"},
    {"UBUNTU_CVE_MAX_RECORD_KB": "2.5"},
    {"UBUNTU_CVE_MAX_INDEX_MB": "0.5"},
    {"UBUNTU_CVE_MAX_UNPACKED_MB": "0"},
    {"UBUNTU_CVE_GIT_TIMEOUT": "01"},
    {"UBUNTU_CVE_GIT_TRIES": "0"},
    {"UBUNTU_CVE_GIT_TRIES": "x"},
    {"UBUNTU_CVE_GIT_RETRY_SLEEP": "1;rm"},
    {"UBUNTU_CVE_GIT_RETRY_SLEEP": "0.5"},
])
def test_env_validation(tmp_path, env):
    r = run_mirror(tmp_path / "x", tmp_path / "x.man", env={"UBUNTU_CVE_GIT_URL": "file:///nothere", **env})
    assert r.returncode == 3 and r.stderr.startswith("FAIL") and "Traceback" not in r.stderr, r.stderr
    assert not (tmp_path / "x").exists() and not (tmp_path / "x.man").exists()
    if any(k in env for k in ("UBUNTU_CVE_MIN_CVES", "UBUNTU_CVE_MAX_INDEX_MB", "UBUNTU_CVE_MAX_AGE_DAYS")):
        c = run_mirror("--check", tmp_path, env=env)          # --check 也在開始前就拒絕
        assert c.returncode == 3 and "Traceback" not in c.stderr, c.stderr


def big_record(r):
    (r / "active" / "CVE-2024-0009").write_text("Candidate: CVE-2024-0009\nDescription:\n" + " x\n" * 600_000)


def big_index(r):
    (r / "active" / "CVE-2024-0012").write_text("Candidate: CVE-2024-0012\n" + "".join(
        f"jammy_pkg{i}: needed ({'x' * 50})\n" for i in range(15_000)))


def big_pack(r):
    (r / "blob.bin").write_bytes(os.urandom(3 << 20))


@pytest.mark.parametrize("var,val,extra", [("UBUNTU_CVE_MAX_RECORD_KB", "1", None),
                                           ("UBUNTU_CVE_MAX_UNPACKED_MB", "1", big_record),
                                           ("UBUNTU_CVE_MAX_INDEX_MB", "1", big_index),
                                           ("UBUNTU_CVE_MAX_DOWNLOAD_MB", "1", big_pack)])
def test_size_caps(tmp_path, var, val, extra):
    repo = tracker(tmp_path, extra=extra)
    r = run_mirror(tmp_path / "y", tmp_path / "y.man", env={"UBUNTU_CVE_GIT_URL": repo.as_uri(), var: val, "UBUNTU_CVE_GIT_TRIES": "1"})
    assert r.returncode == 1 and var in r.stderr and "Traceback" not in r.stderr, r.stdout + r.stderr
    assert not (tmp_path / "y.man").exists() and not (tmp_path / "y" / "SOURCE").exists()
    assert not list(tmp_path.glob(".ubuntu-cve-clone.*"))
    ok = run_mirror(tmp_path / "z", tmp_path / "z.man", env={"UBUNTU_CVE_GIT_URL": repo.as_uri()})    # 預設上限下同一個倉庫可以建
    assert ok.returncode == 0, ok.stdout + ok.stderr


def test_clone_retries_then_fails(tmp_path):
    r = run_mirror(tmp_path / "z", tmp_path / "z.man", env={"UBUNTU_CVE_GIT_URL": (tmp_path / "nothere").as_uri()})
    assert r.returncode == 1 and r.stderr.count("後重試") == 2 and "FAIL git clone 失敗 3 次" in r.stderr, r.stderr
    assert not (tmp_path / "z.man").exists() and not list(tmp_path.glob(".ubuntu-cve-clone.*"))
    r = run_mirror(tmp_path / "w", tmp_path / "w.man", env={"UBUNTU_CVE_GIT_URL": (tmp_path / "nothere").as_uri(), "UBUNTU_CVE_GIT_TRIES": "1"})
    assert r.returncode == 1 and "後重試" not in r.stderr and "失敗 1 次" in r.stderr, r.stderr


def test_stale_clone_dirs_from_killed_runs_are_removed(tmp_path):
    repo = tracker(tmp_path)
    old, new = tmp_path / ".ubuntu-cve-clone.old123", tmp_path / ".ubuntu-cve-clone.new123"
    for d in (old, new):
        (d / "t").mkdir(parents=True)
        (d / "t" / "pack").write_text("x")
    t = time.time() - 2 * 86400
    os.utime(old, (t, t))
    other = tmp_path / "keepme.old"            # 名稱不符：不動
    other.mkdir()
    os.utime(other, (t, t))
    r = run_mirror(tmp_path / "m", tmp_path / "m.man", env={"UBUNTU_CVE_GIT_URL": repo.as_uri()})
    assert r.returncode == 0, r.stderr
    assert not old.exists() and new.exists() and other.exists() and "刪掉上一次留下的 clone 資料夾" in r.stderr
    assert "trap 'rm -rf \"$work\"' EXIT" in MIRROR_SH.read_text(encoding="utf-8")


def test_tracker_inconsistencies_fail(tmp_path):
    dup = tracker(tmp_path, files={"active/CVE-2024-0001": CVE1, "retired/CVE-2024-0001": CVE1})
    r = run_mirror(tmp_path / "a", tmp_path / "a.man", env={"UBUNTU_CVE_GIT_URL": dup.as_uri()})
    assert r.returncode == 1 and "同時在 active/ 與 retired/" in r.stderr, r.stderr
    (tmp_path / "b").mkdir()
    bad = tracker(tmp_path / "b", files={"active/CVE-2024-0001": CVE1.replace("Candidate: CVE-2024-0001", "Candidate: CVE-2024-9")})
    r = run_mirror(tmp_path / "c", tmp_path / "c.man", env={"UBUNTU_CVE_GIT_URL": bad.as_uri()})
    assert r.returncode == 1 and "與檔名不符" in r.stderr, r.stderr


def test_unknown_status_with_control_chars_kept_but_not_printed_raw(tmp_path):
    text = CVE2.replace("noble_old: released (0.9-1)", "noble_old: \x1b[31mfixed? (see \x1b]0;x\x07notes)")
    m, r = build(tmp_path, repo=tracker(tmp_path, files={"retired/CVE-2023-0002": text}), env={"UBUNTU_CVE_RELEASES": "noble"})
    e = load(m)["cves"]["CVE-2023-0002"]["packages"]["old"]["noble"]
    assert e == E("\x1b[31mfixed?", "see \x1b]0;x\x07notes")                    # 索引裡原樣保留
    assert "\x1b" not in r.stdout and "?[31mfixed?=1" in r.stdout, r.stdout
    c = run_mirror("--check", m)
    assert c.returncode == 0 and "unknown_values=(?[31mfixed?)" in c.stdout and "\x1b" not in c.stdout, c.stdout


def test_old_upstream_commit_fails(tmp_path):
    repo = tracker(tmp_path, commit_date="2026-01-01T00:00:00+00:00")
    r = run_mirror(tmp_path / "m", tmp_path / "m.man", env={"UBUNTU_CVE_GIT_URL": repo.as_uri()})
    assert r.returncode == 1 and "FAIL 上游太久沒有更新" in r.stdout and not (tmp_path / "m.man").exists(), r.stdout


def rewrite(m, part="main", idx=None, raw=None, **source_kv):
    """改索引（或直接給 bytes）後把 SOURCE 的 sha256 與大小一起改對，只留下要測的那個錯。"""
    gz = m / FILES[part]
    if idx is not None or raw is not None:
        gz.write_bytes(gzip.compress(raw if raw is not None else json.dumps(idx).encode(), mtime=0))
    s = source(m)
    s[f"{part}_sha256"] = hashlib.sha256(gz.read_bytes()).hexdigest()
    s[f"{part}_bytes"] = str(gz.stat().st_size)
    s.update(source_kv)
    (m / "SOURCE").write_text("".join(f"{k}={v}\n" for k, v in s.items()))


@pytest.mark.parametrize("what,msg", [
    ("stale", "過期"), ("future_fetched", "在未來"), ("future_commit", "在未來"), ("commit_old", "上游太久沒有更新"),
    ("no_tz", "沒有時區"), ("sha", "sha256 或大小與 SOURCE 不符"), ("sha_linux", "linux.json.gz 的 sha256"),
    ("nosource", "缺少 SOURCE"), ("noindex", "缺少 ubuntu-cve-status-linux.json.gz"), ("commit", "不是 git 的雜湊"),
    ("symlink", "一般檔案與資料夾以外"), ("fifo", "一般檔案與資料夾以外"), ("notgz", "無法讀取"), ("bomb", "UBUNTU_CVE_MAX_INDEX_MB"),
    ("schema", "schema"), ("part", "part 不是 main"), ("releases", "releases 與 SOURCE 不符"),
    ("src_source", "source 與 SOURCE 不符"), ("src_commit_date", "commit_date 與 SOURCE 不符"),
    ("src_count", "counts.malformed_lines"), ("idx_count", "counts.duplicate_lines"), ("idx_part_count", "counts.part 與內容不符"),
    ("count", "筆數與 SOURCE 不符"), ("few", "可能只下載到一部分"), ("cvekey", "不是 CVE 編號"), ("pkgkey", "套件名稱或格式不對"),
    ("relkey", "不在 releases 裡"), ("dne", "不收 DNE"), ("nostatus", "狀態格式不對"), ("extrakey", "狀態格式不對"),
    ("badconflict", "狀態格式不對"), ("empty", "沒有任何套件狀態"), ("keepdne", "keep_dne"), ("tdir", "tracker_dir"),
    ("wrongpart", "放錯檔"), ("ctrlkey", "不是 CVE 編號"),
    ("xpriority", "在兩個檔的 priority 或 tracker_dir 不同"), ("xtdir", "在兩個檔的 priority 或 tracker_dir 不同"),
    ("src_prio", "count_unknown_priorities"), ("src_trunc", "counts.truncated_fields"),
])
def test_check_failures(tmp_path, what, msg):
    m, _ = build(tmp_path)
    idx = load(m)
    c1 = idx["cves"]["CVE-2024-0001"]
    env = {}
    if what == "stale":
        rewrite(m, fetched_utc=now(4))
    elif what == "future_fetched":
        rewrite(m, fetched_utc=now(-2))
    elif what == "future_commit":
        rewrite(m, commit_date=now(-2))
    elif what == "commit_old":
        rewrite(m, commit_date="2026-01-01T00:00:00-03:00")
    elif what == "no_tz":
        rewrite(m, fetched_utc="2026-11-05T00:00:00")
    elif what == "sha":
        with open(m / FILES["main"], "ab") as f:
            f.write(b"x")
    elif what == "sha_linux":
        lx = load(m, "linux")
        (m / FILES["linux"]).write_bytes(gzip.compress(json.dumps(lx).encode(), mtime=0))   # 內容相同、位元組不同
    elif what == "nosource":
        (m / "SOURCE").unlink()
    elif what == "noindex":
        (m / FILES["linux"]).unlink()
    elif what == "commit":
        rewrite(m, commit="nothex")
    elif what == "symlink":
        os.symlink("/etc/passwd", m / "leak")
    elif what == "fifo":
        os.mkfifo(m / "hang")
    elif what == "notgz":
        (m / FILES["main"]).write_bytes(b"not gzip")
        rewrite(m)
    elif what == "bomb":
        rewrite(m, raw=b" " * (2 << 20) + json.dumps(idx).encode())
        env = {"UBUNTU_CVE_MAX_INDEX_MB": "1"}
    elif what == "schema":
        rewrite(m, idx={**idx, "schema": "sca-ubuntu-cve-status/0"})
    elif what == "part":
        rewrite(m, idx={**idx, "part": "linux"})
    elif what == "releases":
        rewrite(m, idx={**idx, "releases": ["jammy"]})
    elif what == "src_source":
        rewrite(m, source="https://evil.invalid/x")
    elif what == "src_commit_date":
        rewrite(m, commit_date=now(1))
    elif what == "src_count":
        rewrite(m, count_malformed_lines="7")
    elif what == "idx_count":
        idx["counts"]["duplicate_lines"] = 5
        rewrite(m, idx=idx)
    elif what == "idx_part_count":
        idx["counts"]["part"]["by_release"]["jammy"]["needed"] = 99
        rewrite(m, idx=idx)
    elif what == "count":
        rewrite(m, main_cves="3")
    elif what == "few":
        env = {"UBUNTU_CVE_MIN_CVES": "3"}
    elif what == "cvekey":
        idx["cves"]["../../etc/passwd"] = c1
        rewrite(m, idx=idx)
    elif what == "pkgkey":
        c1["packages"]["../x"] = c1["packages"]["foo"]
        rewrite(m, idx=idx)
    elif what == "relkey":
        c1["packages"]["foo"]["focal"] = E("needed")
        rewrite(m, idx=idx)
    elif what == "dne":
        c1["packages"]["foo"]["jammy"]["status"] = "DNE"
        rewrite(m, idx=idx)
    elif what == "nostatus":
        del c1["packages"]["foo"]["jammy"]["status"]
        rewrite(m, idx=idx)
    elif what == "extrakey":
        c1["packages"]["foo"]["jammy"]["safe"] = True
        rewrite(m, idx=idx)
    elif what == "badconflict":
        c1["packages"]["foo"]["jammy"]["conflict"] = []
        rewrite(m, idx=idx)
    elif what == "empty":
        c1["packages"] = {}
        rewrite(m, idx=idx)
    elif what == "keepdne":
        rewrite(m, keep_dne="1")
    elif what == "tdir":
        c1["tracker_dir"] = "../active"
        rewrite(m, idx=idx)
    elif what == "wrongpart":
        c1["packages"]["linux-oem"] = {"jammy": E("needed")}
        rewrite(m, idx=idx)
    elif what == "src_prio":
        rewrite(m, count_unknown_priorities="1")
    elif what == "src_trunc":
        rewrite(m, count_truncated_fields="1")
    elif what in ("xpriority", "xtdir"):
        lx = load(m, "linux")                       # 只改 linux 檔裡同一個 CVE 的 CVE 層級欄位
        lx["cves"]["CVE-2024-0001"]["priority" if what == "xpriority" else "tracker_dir"] = "low" if what == "xpriority" else "retired"
        rewrite(m, "linux", idx=lx)
    elif what == "ctrlkey":
        idx["cves"]["CVE-\x1b[31m-x"] = c1
        rewrite(m, idx=idx)
    c = run_mirror("--check", m, env=env)
    assert c.returncode == 1 and c.stdout.startswith("FAIL") and msg in c.stdout, c.stdout
    assert "\x1b" not in c.stdout


def test_check_not_a_directory(tmp_path):
    c = run_mirror("--check", tmp_path / "nothere")
    assert c.returncode == 1 and "不是資料夾" in c.stdout


def test_script_safety_and_docs():
    s = MIRROR_SH.read_text(encoding="utf-8")
    body = s.split("set -euo pipefail", 1)[1]
    assert "core.hooksPath=/dev/null" in s and "--no-checkout" in s and "ulimit -f" in s and "protocol.allow=never" in s
    assert "cat-file" in body and "git archive" not in body
    assert "python3 -I" in body and "https://git.launchpad.net/ubuntu-cve-tracker" in s
    assert "\u2028" not in s and "\u2029" not in s                    # 換行字元以跳脫寫，不放原字元
    ci = (ROOT / "tools" / "mirror" / "ci-run.sh").read_text(encoding="utf-8")
    assert " ubtcve" in ci and "ubuntu-cve-status.sh" in ci
    doc = (ROOT / "docs" / "offline-mirrors.md").read_text(encoding="utf-8")
    assert "ubuntu-cve-status.sh" in doc and SCHEMA in doc and "UBUNTU_CVE_MAX_AGE_DAYS" in doc
    assert FILES["linux"] in doc and "conflict" in doc and "解析規則" in doc
    assert "ubuntu-cve-tracker" in (ROOT / "deploy" / "versions.md").read_text(encoding="utf-8")
