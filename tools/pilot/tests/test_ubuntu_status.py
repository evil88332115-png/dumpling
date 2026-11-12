"""tools/pilot/lib/ubuntu_status.py（sca-scan 的 D-ubuntu-status）：從 Ubuntu CVE Tracker 狀態鏡像（schema sca-ubuntu-cve-status/1，
的格式）只取出映像要的 (CVE, 原始碼套件, 發行版)。
鏡像照 tools/pilot/tests/test_ubuntu_cve_status.py 的建法：假的 tracker 倉庫（active/、retired/ 每個 CVE 一個檔）
用 git commit 之後，以真的 tools/mirror/ubuntu-cve-status.sh 建出來；要測壞掉的鏡像時，建好之後改檔，再把 SOURCE 的 sha256 與大小改對
（同那份測試的 rewrite），只留下要測的那個錯。"""
import gzip
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

PILOT = Path(__file__).resolve().parents[1]
ROOT = PILOT.parents[1]
sys.path.insert(0, str(PILOT / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ubuntu_status as us  # noqa: E402
from test_distro_recheck import finding, now  # noqa: E402

LIB = PILOT / "lib" / "ubuntu_status.py"
MIRROR_SH = ROOT / "tools" / "mirror" / "ubuntu-cve-status.sh"
FILES = {"main": "ubuntu-cve-status.json.gz", "linux": "ubuntu-cve-status-linux.json.gz"}
U24 = "distro=ubuntu-24.04"
SSL = f"pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.11?arch=arm64&upstream=openssl&{U24}"
XZ = f"pkg:deb/ubuntu/liblzma5@5.4.5-0.3?arch=arm64&{U24}"
SRC = f"pkg:deb/ubuntu/curl@8.5.0-2ubuntu10.6?arch=source&{U24}"
KERN = f"pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&{U24}"
FINDINGS = [
    finding("libssl3t64", "3.0.13-0ubuntu3.11", "CVE-2026-1001", purl=SSL),
    finding("libssl3t64", "3.0.13-0ubuntu3.11", "UBUNTU-CVE-2026-1002", "OSV", purl=SSL),
    finding("liblzma5", "5.4.5-0.3", "CVE-2024-3094", purl=XZ),
    finding("curl", "8.5.0-2ubuntu10.6", "CVE-2026-1003", purl=SRC),
    finding("curl", "8.5.0-2ubuntu10.6", "CVE-2026-1009", purl=SRC),                 # Tracker 沒有
    finding("linux-nvidia-tegra", "6.8.0-1021.21", "CVE-2026-2001", purl=KERN),       # 核心：不讀
    finding("brotli", "1.1.0", "CVE-2026-3001", purl="pkg:pypi/brotli@1.1.0"),        # 不是 Ubuntu 套件
]
SBOM = {"components": [{"name": "liblzma5", "version": "5.4.5-0.3", "purl": XZ,
                        "properties": [{"name": "syft:metadata:source", "value": "xz-utils"}]}]}


def E(status, note="", **kw):
    return {"status": status, "note": note, **kw}


# 假的 ubuntu-cve-tracker 倉庫（同 test_ubuntu_cve_status.py 的建法：active/、retired/ 每個 CVE 一個檔，git commit 之後用真的
# tools/mirror/ubuntu-cve-status.sh 建鏡像）。每個檔旁邊寫鏡像裡的結果。
TRACKER = {
    "active/CVE-2026-1001": ("Candidate: CVE-2026-1001\nPriority: medium\n\nPatches_openssl:\n"
                             "jammy_openssl: needed\n"
                             "noble_openssl: not-affected (3.0.13-0ubuntu3.4)\n"),           # noble：not-affected＋版本註記
    "active/CVE-2026-1002": ("Candidate: CVE-2026-1002\nPriority:\n\nPatches_openssl:\n"      # 空的 Priority → null
                             "noble_openssl: needed\n"
                             "noble_openssl: released (3.0.13-0ubuntu3.12)\n"),              # 重複且不同 → 留第一行＋conflict
    "retired/CVE-2024-3094": ("Candidate: CVE-2024-3094\nPriority: critical\n\nPatches_xz-utils:\n"
                              "noble_xz-utils: not-affected (5.4.5-0.3)\n"),
    "active/CVE-2026-1003": ("Candidate: CVE-2026-1003\nPriority: high\n\nPatches_curl:\nPriority_curl: low\n"
                             f"noble_curl: weird-status ({'x' * 5000})\n"),                  # 認得以外的狀態原樣；說明截斷到 4096
    "active/CVE-2026-2001": ("Candidate: CVE-2026-2001\nPriority: high\n\nPatches_zlib:\n"
                             "noble_zlib: released (1:1.3.dfsg-3.1ubuntu2.1)\n\n"
                             "Patches_linux-nvidia-tegra:\n"
                             "noble_linux-nvidia-tegra: not-affected (6.8.0-1021.21)\n"),    # 核心 → linux 檔（不讀）
}


def git(r, *args, env=None):
    e = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x",
         **(env or {})}
    return subprocess.run(["git", "-C", str(r), *args], check=True, env=e, capture_output=True)


def tracker(d, files=None, commit_date=None):
    r = d / "uct"
    for name, text in (files if files is not None else TRACKER).items():
        (r / name).parent.mkdir(parents=True, exist_ok=True)
        (r / name).write_text(text, encoding="utf-8")
    env = {"GIT_COMMITTER_DATE": commit_date, "GIT_AUTHOR_DATE": commit_date} if commit_date else None
    for c in (["init", "-q", "-b", "master"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
        git(r, *c, env=env)
    return r


def source(m):
    return dict(ln.split("=", 1) for ln in (m / "SOURCE").read_text(encoding="utf-8").splitlines())


def rewrite(m, idx=None, **source_kv):
    """（同 test_ubuntu_cve_status.py 的 rewrite）改一般檔的索引後把 SOURCE 的 sha256 與大小改對，再改 SOURCE 的鍵：只留下要測的那個錯。"""
    gz = m / FILES["main"]
    if idx is not None:
        gz.write_bytes(gzip.compress(json.dumps(idx).encode(), mtime=0))
    s = source(m)
    s["main_sha256"], s["main_bytes"] = hashlib.sha256(gz.read_bytes()).hexdigest(), str(gz.stat().st_size)
    s.update(source_kv)
    (m / "SOURCE").write_text("".join(f"{k}={v}\n" for k, v in s.items()), encoding="utf-8")


def make_mirror(d, files=None, fetched=None, commit_date=None, releases="jammy noble", tamper=None, idx_patch=None):
    """真的 ubuntu-cve-status.sh 建的鏡像。commit_date：上游 commit 的時間；fetched：之後改 SOURCE 的 fetched_utc；
    idx_patch(idx)：之後改一般檔的索引（模擬壞掉或舊格式，sha256 與大小照樣改對）；tamper：最後直接改 SOURCE 的鍵。"""
    d.mkdir(parents=True, exist_ok=True)
    repo = tracker(d, files, commit_date or now(1))
    m = d / "m"
    r = subprocess.run(["bash", str(MIRROR_SH), str(m), str(d / "m.man")], capture_output=True, text=True, timeout=120,
                       env={**os.environ, "UBUNTU_CVE_MIN_CVES": "1", "UBUNTU_CVE_GIT_RETRY_SLEEP": "0",
                            "UBUNTU_CVE_GIT_URL": repo.as_uri(), "UBUNTU_CVE_RELEASES": releases,
                            "UBUNTU_CVE_MAX_COMMIT_AGE_DAYS": "30"})          # 建置最後的 --check：要測「上游太久沒有更新」的鏡像也要建得出來
    assert r.returncode == 0, r.stdout + r.stderr
    if idx_patch:
        idx = json.loads(gzip.decompress((m / FILES["main"]).read_bytes()))
        idx_patch(idx)
        rewrite(m, idx)
    if fetched:
        rewrite(m, fetched_utc=fetched)
    if tamper:
        rewrite(m, **tamper)
    return m


def test_fixture_is_the_real_mirror_format(tmp_path):
    """建出來的鏡像通過真的 --check；內容就是讀取端假設的格式（conflict、null priority、截斷、核心分檔）。"""
    m = make_mirror(tmp_path / "x")
    r = subprocess.run(["bash", str(MIRROR_SH), "--check", str(m)], capture_output=True, text=True, timeout=120,
                       env={**os.environ, "UBUNTU_CVE_MIN_CVES": "1"})
    assert r.returncode == 0 and r.stdout.startswith("OK commit="), r.stdout + r.stderr
    idx = json.loads(gzip.decompress((m / FILES["main"]).read_bytes()))
    c = idx["cves"]
    assert c["CVE-2026-1002"]["priority"] is None
    assert c["CVE-2026-1002"]["packages"]["openssl"]["noble"] == E("needed", conflict=[E("released", "3.0.13-0ubuntu3.12")])
    assert c["CVE-2026-1003"]["packages"]["curl"]["noble"] == E("weird-status", "x" * 4096, priority="low")
    assert "linux-nvidia-tegra" not in c["CVE-2026-2001"]["packages"] and c["CVE-2024-3094"]["tracker_dir"] == "retired"
    cnt = idx["counts"]
    assert (cnt["duplicate_lines"], cnt["conflicting_entries"], cnt["unknown_priorities"], cnt["truncated_fields"]) == (1, 1, 0, 1)


def test_extracts_only_the_images_entries(tmp_path):
    m = make_mirror(tmp_path / "m")
    st, detail, out = us.ubuntu_status(FINDINGS, SBOM, str(m), 3, 14)
    assert st == "OK" and out["status"] == "OK" and out["schema"] == "sca-center-ubuntu-status/1" and out["mirror"]["ok"]
    assert out["components"] == {SSL: {"source": "openssl", "source_version": "3.0.13-0ubuntu3.11", "release": "noble"},
                                 XZ: {"source": "xz-utils", "source_version": "5.4.5-0.3", "release": "noble"},
                                 SRC: {"source": "curl", "source_version": "8.5.0-2ubuntu10.6", "release": "noble"}}
    e = out["entries"]
    assert e["CVE-2026-1001"] == {"openssl": {"noble": E("not-affected", "3.0.13-0ubuntu3.4")}}     # 只有映像的發行版
    assert e["CVE-2026-1002"]["openssl"]["noble"]["conflict"] == [E("released", "3.0.13-0ubuntu3.12")]   # 原樣：[{status, note}]
    assert e["CVE-2024-3094"]["xz-utils"]["noble"]["status"] == "not-affected"                                       # SBOM 的 Source
    c = e["CVE-2026-1003"]["curl"]["noble"]
    assert c["status"] == "weird-status" and len(c["note"]) == us.MAX_TEXT and c["priority"] == "low"              # 原樣保留
    assert "CVE-2026-2001" not in e and "CVE-2026-3001" not in json.dumps(out)                                     # 核心不讀
    assert out["counts"]["pairs"] == 5 and out["counts"]["with_entry"] == 4 and out["counts"]["no_entry"] == 1
    assert out["counts"]["kernel_skipped"] == 1 and out["counts"]["conflict"] == 1
    assert out["mirror_counts"] == {"duplicate_lines": 1, "conflicting_entries": 1, "malformed_lines": 0, "skipped_names": 0,
                                    "non_utf8_files": 0, "odd_line_breaks": 0, "unknown_priorities": 0, "truncated_fields": 1,
                                    "part_conflicting_entries": 1, "unknown_status": 1}
    assert "conflict 1" in detail and "要人看的計數" in detail and "truncated_fields=1" in detail


def test_not_run_without_usable_mirror(tmp_path):
    assert us.ubuntu_status(FINDINGS[5:], SBOM, None, 3, 14) == ("NOT_RUN", "DT findings 沒有 Ubuntu 套件（核心以外）上的 CVE", None)

    def drop(*keys):
        def f(idx):
            for k in keys:
                idx["counts"].pop(k)
        return f
    cases = [
        (None, "沒有設定鏡像"),
        (str(tmp_path / "nope"), "鏡像資料夾不存在"),
        (str(make_mirror(tmp_path / "old", fetched=now(3.5))), "鏡像過期"),
        (str(make_mirror(tmp_path / "stale", commit_date=now(14.5))), "上游太久沒有更新"),
        (str(make_mirror(tmp_path / "future", fetched=now(-1.5))), "在未來"),
        (str(make_mirror(tmp_path / "sha", tamper={"main_sha256": "0" * 64})), "sha256 與 SOURCE 不符"),
        (str(make_mirror(tmp_path / "size", tamper={"main_bytes": "1"})), "大小與 SOURCE 不符"),
        (str(make_mirror(tmp_path / "commit", tamper={"commit": "e" * 40})), "commit 與 SOURCE 不符"),
        (str(make_mirror(tmp_path / "keep", tamper={"keep_dne": "1"})), "keep_dne 與 SOURCE 不符"),
        (str(make_mirror(tmp_path / "cnt", tamper={"count_duplicate_lines": "7"})), "counts.duplicate_lines 與 SOURCE"),
        (str(make_mirror(tmp_path / "part", tamper={"main_entries": "99"})), "counts.part.entries 與 SOURCE 的 main_entries"),
        (str(make_mirror(tmp_path / "oldfmt", idx_patch=drop("unknown_priorities", "truncated_fields"))), "counts.unknown_priorities"),
        (str(make_mirror(tmp_path / "rule", idx_patch=lambda i: i.update(linux_part_rule="^linux"))), "linux_part_rule"),
        (str(make_mirror(tmp_path / "linuxpart", idx_patch=lambda i: i.update(part="linux"))), "一般套件索引"),
        (str(make_mirror(tmp_path / "rel", releases="jammy",
                         files={"active/CVE-2026-1001": "Candidate: CVE-2026-1001\nPriority: medium\n\njammy_openssl: needed\n"})),
         "映像的發行版 noble 不在鏡像裡"),
    ]
    for m, msg in cases:
        st, detail, out = us.ubuntu_status(FINDINGS, SBOM, m, 3, 14)
        assert st == "NOT_RUN" and out["status"] == "NOT_RUN" and out["entries"] == {} and msg in detail, (msg, detail)
    # 時間在 1 天的誤差內：可以
    assert us.ubuntu_status(FINDINGS, SBOM, str(make_mirror(tmp_path / "skew", fetched=now(-0.5))), 3, 14)[0] == "OK"
    # 索引是符號連結：不跟隨
    m = make_mirror(tmp_path / "link")
    (m / us.INDEX).rename(m / "real.gz")
    (m / us.INDEX).symlink_to(m / "real.gz")
    assert "一般檔案與資料夾以外的東西" in us.ubuntu_status(FINDINGS, SBOM, str(m), 3, 14)[1]


def test_reader_checks_the_content_like_the_mirror_check(tmp_path):
    """sha256 與 SOURCE 都改對、只有內容不對時，讀取端和 --check 一樣不收（驗證代理的重現）。"""
    def clean_conflict(idx):
        e = idx["cves"]["CVE-2026-1002"]["packages"]["openssl"]["noble"]
        e.pop("conflict")
        e["status"] = "not-affected"                          # counts.part 不動：和內容不符
    def bad_note(idx):
        idx["cves"]["CVE-2026-1001"]["packages"]["openssl"]["noble"]["note"] = 3
    def extra_key(idx):
        idx["cves"]["CVE-2026-1001"]["packages"]["openssl"]["noble"]["x"] = "y"
    def bad_rel(idx):
        idx["cves"]["CVE-2026-1001"]["packages"]["openssl"]["focal"] = E("needed")
    def dne(idx):
        idx["cves"]["CVE-2026-1001"]["packages"]["openssl"]["jammy"] = E("DNE")
    def kernel_in_main(idx):
        idx["cves"]["CVE-2026-1001"]["packages"]["linux-foo"] = {"noble": E("needed")}
    def bad_key(idx):
        idx["cves"]["CVE-X"] = idx["cves"].pop("CVE-2026-1001")
    for f, msg in ((clean_conflict, "counts.part 與內容不符"), (bad_note, "狀態格式不對"), (extra_key, "狀態格式不對"),
                   (bad_rel, "發行版或狀態格式不對"), (dne, "不收 DNE"), (kernel_in_main, "核心套件放在一般檔"), (bad_key, "不是 CVE 編號")):
        m = make_mirror(tmp_path / f.__name__, idx_patch=f)
        st, detail, out = us.ubuntu_status(FINDINGS, SBOM, str(m), 3, 14)
        assert st == "NOT_RUN" and msg in detail and out["entries"] == {}, (f.__name__, detail)
    # linux 檔：不見了、換成符號連結、內容被換掉
    m = make_mirror(tmp_path / "nolinux")
    (m / FILES["linux"]).unlink()
    assert "缺少 ubuntu-cve-status-linux.json.gz" in us.ubuntu_status(FINDINGS, SBOM, str(m), 3, 14)[1]
    m = make_mirror(tmp_path / "linuxlink")
    (m / FILES["linux"]).rename(tmp_path / "real-linux.gz")
    (m / FILES["linux"]).symlink_to(tmp_path / "real-linux.gz")
    assert "一般檔案與資料夾以外的東西" in us.ubuntu_status(FINDINGS, SBOM, str(m), 3, 14)[1]
    m = make_mirror(tmp_path / "linuxsha")
    (m / FILES["linux"]).write_bytes(gzip.compress(b"{}", mtime=0))
    assert "linux.json.gz 的 sha256 或大小與 SOURCE 不符" in us.ubuntu_status(FINDINGS, SBOM, str(m), 3, 14)[1]


def test_age_limits_must_be_finite(tmp_path, monkeypatch):
    fp, out = tmp_path / "f.json", tmp_path / "o.json"
    fp.write_text(json.dumps(FINDINGS), encoding="utf-8")
    m = make_mirror(tmp_path / "x", fetched=now(30))
    for v in ("nan", "inf", "-1", "abc"):
        r = subprocess.run([sys.executable, "-I", str(LIB), "--findings", str(fp), "--mirror", str(m), "--out", str(out)],
                           capture_output=True, text=True, timeout=60, env={**os.environ, "UBUNTU_CVE_MAX_AGE_DAYS": v})
        assert r.returncode == 3 and "UBUNTU_CVE_MAX_AGE_DAYS" in r.stdout, (v, r.stdout)


def test_cli_writes_file_and_status_line(tmp_path):
    m = make_mirror(tmp_path / "m")
    fp, sb, out = tmp_path / "f.json", tmp_path / "s.json", tmp_path / "o.json"
    fp.write_text(json.dumps(FINDINGS), encoding="utf-8")
    sb.write_text(json.dumps(SBOM), encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(LIB), "--findings", str(fp), "--sbom", str(sb), "--mirror", str(m), "--out", str(out)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.startswith("D-ubuntu-status\tOK\t"), r.stdout + r.stderr
    assert json.loads(out.read_text(encoding="utf-8"))["entries"]["CVE-2024-3094"]
    fp.write_text("{not json", encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(LIB), "--findings", str(fp), "--out", str(out)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 3 and r.stdout.startswith("D-ubuntu-status\tFAIL\t")


def test_sca_scan_runs_the_stage():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    assert 'ubuntu_status.py" --findings "$OUT/dt/findings.json"' in s and "UBUNTU_CVE_STATUS_MIRROR" in s
    assert 'rm -f "$US" "$US.xz"' in s


def test_source_is_not_guessed_from_the_binary_name(tmp_path):
    """purl 沒有 upstream、SBOM 裡也沒有這個元件：不知道原始碼套件，不用二進位名稱猜（U1 不套用）。"""
    lone = f"pkg:deb/ubuntu/libfoo1@1.0-1?arch=arm64&{U24}"
    st, detail, out = us.ubuntu_status(FINDINGS + [finding("libfoo1", "1.0-1", "CVE-2026-1001", purl=lone)], SBOM, str(make_mirror(tmp_path / "x")), 3, 14)
    assert out["components"][lone]["source"] is None and out["counts"]["source_unknown"] == 1
    # SBOM 裡有這個元件、沒有 source 屬性：就是二進位本身（dpkg 只在不同時才寫 Source）
    bom = {"components": SBOM["components"] + [{"name": "libfoo1", "version": "1.0-1", "purl": lone}]}
    st, detail, out = us.ubuntu_status(FINDINGS + [finding("libfoo1", "1.0-1", "CVE-2026-1001", purl=lone)], bom, str(make_mirror(tmp_path / "y")), 3, 14)
    assert out["components"][lone]["source"] == "libfoo1"


def test_other_releases_of_the_same_cve_and_source_are_kept(tmp_path):
    files = dict(TRACKER)
    files["active/CVE-2026-1001"] = ("Candidate: CVE-2026-1001\nPriority: medium\n\nPatches_openssl:\n"
                                     "jammy_openssl: released (3.0.2-0ubuntu1.18)\nnoble_openssl: not-affected (3.0.13-0ubuntu3.4)\n")
    st, detail, out = us.ubuntu_status(FINDINGS, SBOM, str(make_mirror(tmp_path / "x", files=files)), 3, 14)
    assert st == "OK" and out["other_releases"]["CVE-2026-1001"]["openssl"] == {"jammy": E("released", "3.0.2-0ubuntu1.18")}
    assert "jammy" not in out["entries"]["CVE-2026-1001"]["openssl"]


def test_deb_packaged_python_modules_bring_their_owning_deb(tmp_path):
    """DT findings 裡 Ubuntu 打包的 Python 模組（dist-packages 的 pypi 元件，SBOM 裡唯一的擁有者 python3-pil）：也收擁有它的 deb 與
    (CVE, 原始碼套件 pillow, noble)，cra_report 沒有 Grype 修補狀態時依 Tracker 推修補狀態用。沒有 --sbom、擁有者不明、pip 裝的 → 不收。"""
    files = dict(TRACKER)
    files["active/CVE-2026-4001"] = "Candidate: CVE-2026-4001\nPriority: medium\n\nPatches_pillow:\nnoble_pillow: released (10.2.0-1ubuntu1.3)\n"
    pil = f"pkg:deb/ubuntu/python3-pil@10.2.0-1ubuntu1?arch=arm64&{U24}&upstream=pillow"
    bom = {"components": SBOM["components"] + [
        {"type": "library", "name": "pillow", "version": "10.2.0", "purl": "pkg:pypi/pillow@10.2.0",
         "properties": [{"name": "syft:location:0:path", "value": "/usr/lib/python3/dist-packages/pillow-10.2.0.dist-info/METADATA"}]},
        {"type": "library", "name": "python3-pil", "version": "10.2.0-1ubuntu1", "purl": pil},
        {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0",
         "properties": [{"name": "syft:location:0:path", "value": "/usr/local/lib/python3.12/dist-packages/requests-2.31.0.dist-info/METADATA"}]}]}
    fs = FINDINGS + [finding("pillow", "10.2.0", "GHSA-pppp-pppp-pppp", "GITHUB", purl="pkg:pypi/pillow@10.2.0", aliases=[{"cveId": "CVE-2026-4001"}]),
                     finding("requests", "2.31.0", "CVE-2026-4002", purl="pkg:pypi/requests@2.31.0")]
    m = str(make_mirror(tmp_path / "x", files=files))
    st, detail, out = us.ubuntu_status(fs, bom, m, 3, 14)
    assert st == "OK" and out["components"][pil] == {"source": "pillow", "source_version": "10.2.0-1ubuntu1", "release": "noble"}
    assert out["entries"]["CVE-2026-4001"] == {"pillow": {"noble": E("released", "10.2.0-1ubuntu1.3")}}
    assert out["counts"]["deb_python_owners"] == 1 and out["counts"]["pairs"] == 6 and "CVE-2026-4002" not in json.dumps(out)
    assert "pkg:pypi/pillow@10.2.0" not in out["components"]
    # 沒有 SBOM：不知道擁有者，不收（其他照舊）
    st, detail, out = us.ubuntu_status(fs, None, m, 3, 14)
    assert pil not in out["components"] and out["counts"]["deb_python_owners"] == 0 and "CVE-2026-4001" not in out["entries"]
