"""deploy/pilot/ubuntu-cve-status-mirror.sh（Ubuntu CVE Tracker 狀態鏡像的部署：update、check、info）與它的接線：
install.sh 的 N-ubuntu-status-mirror、每日的 nvd-refresh.sh、GitLab runner 的 mirror-sync.sh ubuntu-cve-status／G-ubuntu-status、status.sh、文件。
鏡像照 test_ubuntu_status.py（#150 的測試）的建法：假的 tracker 倉庫用 git commit 之後，以 file:// 網址跑真的 tools/mirror/ubuntu-cve-status.sh，不連網。"""
import getpass
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_ubuntu_status import FILES, ROOT, tracker  # noqa: E402
from test_distro_recheck import now  # noqa: E402
from test_euvd_dt_feed import env as euvd_env, euvd_api  # noqa: E402

SH = ROOT / "deploy" / "pilot" / "ubuntu-cve-status-mirror.sh"
LIB = ROOT / "deploy" / "pilot" / "lib.sh"
SYNC = ROOT / "deploy" / "gitlab-runner" / "mirror-sync.sh"
EUVD_SH = ROOT / "deploy" / "pilot" / "euvd-mirror.sh"
NAME = re.compile(r"^[0-9]{6}-[0-9]{8}T[0-9]{6}Z$")


def rd(*p):
    return ROOT.joinpath(*p).read_text(encoding="utf-8")


@pytest.fixture
def site(tmp_path):
    """state（.env、pilot.env）、假的 tracker 倉庫、鏡像資料夾（環境變數指定）。"""
    state = tmp_path / "state"
    state.mkdir()
    (state / ".env").write_text("PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=./data/ubuntu-cve-status\n", encoding="utf-8")
    (state / "pilot.env").write_text("DT_URL=http://x\n", encoding="utf-8")
    repo = tracker(tmp_path, commit_date=now(1))
    mdir = tmp_path / "persist" / "ucs"
    env = {**os.environ, "PILOT_STATE_DIR": str(state), "PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR": str(mdir),
           "UBUNTU_CVE_GIT_URL": repo.as_uri(), "UBUNTU_CVE_MIN_CVES": "1", "UBUNTU_CVE_GIT_RETRY_SLEEP": "0",
           "UBUNTU_CVE_STATUS_MIN_MEM_MB": "0", "UBUNTU_CVE_STATUS_MIN_FREE_MB": "1", "UBUNTU_CVE_STATUS_CHECK_MIN_MEM_MB": "0"}
    env.pop("PILOT_PROJECT", None)
    return {"tmp": tmp_path, "state": state, "mdir": mdir, "env": env}


def run(site, *args, **extra):
    return subprocess.run(["bash", str(SH), *args], env={**site["env"], **extra}, capture_output=True, text=True, timeout=300)


def last(r):
    return r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""


def releases(mdir):
    return sorted(p.name for p in (mdir / "releases").iterdir()) if (mdir / "releases").is_dir() else []


def tree(root):
    """整個檔案樹：路徑 → (型別, 大小, mtime_ns, 權限, 連結目標)。"""
    out = {}
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            p = os.path.join(dp, n)
            st = os.lstat(p)
            out[os.path.relpath(p, root)] = (stat.S_IFMT(st.st_mode), st.st_size, st.st_mtime_ns, stat.S_IMODE(st.st_mode),
                                             os.readlink(p) if stat.S_ISLNK(st.st_mode) else None)
    return out


def update_ok(site, **extra):
    r = run(site, "update", **extra)
    assert r.returncode == 0 and last(r).startswith("RESULT OK 切換 current → releases/"), r.stdout + r.stderr
    return r


def rels(mdir):
    return [n for n in releases(mdir) if NAME.match(n)]


def fake_date(site, ts):
    """PATH 裡的假 date：只有 release 名稱用的格式（+%Y%m%dT%H%M%SZ）印 ts 檔的內容，其他照真的 date。"""
    b = site["tmp"] / "datebin"
    b.mkdir(exist_ok=True)
    (b / "ts").write_text(ts + "\n", encoding="utf-8")
    (b / "date").write_text(f'#!/bin/sh\nfor a in "$@"; do [ "$a" = "+%Y%m%dT%H%M%SZ" ] && exec cat "{b}/ts"; done\n'
                            f'exec "{shutil.which("date")}" "$@"\n', encoding="utf-8")
    (b / "date").chmod(0o755)
    return {"PATH": f"{b}:{os.environ['PATH']}"}


def slow_git(site, marker):
    """clone 卡住的假 git（不寫任何東西）：被 ubuntu-cve-status.sh 的 timeout 放在自己的行程群組（外層的訊號收不到）。"""
    b = site["tmp"] / f"slow-{marker}"
    b.mkdir()
    (b / "git").write_text(f"#!/bin/sh\nexec sleep {marker}\n", encoding="utf-8")
    (b / "git").chmod(0o755)
    return {"PATH": f"{b}:{os.environ['PATH']}", "UBUNTU_CVE_GIT_TRIES": "1"}   # 只試一次：測試收尾殺掉 sleep 後不會再起一個


def sleepers(marker):
    r = subprocess.run(["pgrep", "-f", f"^sleep {marker}$"], capture_output=True, text=True)
    return r.stdout.split()


def kill_sleepers(marker):
    """收尾：卡住的 git 與它的整個 session（被 KILL 的 update 留下的 ubuntu-cve-status.sh）都結束。"""
    for pid in sleepers(marker):
        try:
            sid = os.getsid(int(pid))
            qs = [pid] if sid == os.getsid(0) else \
                subprocess.run(["pgrep", "-s", str(sid)], capture_output=True, text=True).stdout.split()   # 不殺到 pytest 自己的 session
            for q in qs:
                os.kill(int(q), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def lock_free(mdir):
    return subprocess.run(["flock", "-n", str(mdir / ".lock"), "true"]).returncode == 0


# ---------- update ----------

def test_update_switches_current_writes_env_and_cleans_leftovers(site):
    mdir = site["mdir"]
    c = run(site, "check")
    assert c.returncode == 1 and last(c) == f"RESULT MISSING 沒有鏡像：{mdir}/current"
    (mdir / "releases" / "000007-20200101T000000Z").mkdir(parents=True)    # 上一次被中斷：沒有 manifest
    (mdir / "releases" / ".ubuntu-cve-clone.old").mkdir()                   # 上一次被 KILL 留下的 clone 暫存
    r = update_ok(site)
    assert "000007-20200101T000000Z" not in releases(mdir) and not [n for n in releases(mdir) if n.startswith(".ubuntu-cve-clone")]
    assert os.readlink(mdir / "current").startswith("releases/000001-")   # 序號：刪掉殘留後現有最大的加 1
    cur = mdir / "current"
    assert cur.is_symlink() and os.readlink(cur).startswith("releases/")
    for f in (*FILES.values(), "SOURCE"):
        assert (cur / f).is_file(), f
        assert (cur / f).stat().st_mode & 0o004                              # world-readable：runner 以別的帳號複製
    rel = Path(os.path.realpath(cur))
    assert (rel.parent / f"{rel.name}.manifest").is_file()
    penv = (site["state"] / "pilot.env").read_text(encoding="utf-8")
    assert f"UBUNTU_CVE_STATUS_MIRROR={cur}\n" in penv and "DT_URL=http://x" in penv   # current（連結）的絕對路徑
    assert f"PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR={mdir}" in (site["state"] / ".env").read_text(encoding="utf-8")   # 環境變數寫回 state/.env
    assert "fetched_utc=" in last(r) and "commit=" in last(r)
    c = run(site, "check")
    assert c.returncode == 0, c.stdout
    assert last(c).startswith(f"RESULT OK release={rel.name} ") and "age_days=" in last(c) and "commit_date=" in last(c) and "cves=5 " in last(c)
    i = run(site, "info")
    assert i.returncode == 0 and i.stdout.startswith(f"release={rel.name} fetched_utc=") and "age_days=0.0" in i.stdout
    # 不帶環境變數（每日的 nvd-refresh.sh）：讀 state/.env，同一個資料夾
    e = {k: v for k, v in site["env"].items() if k != "PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR"}
    c = subprocess.run(["bash", str(SH), "check"], env=e, capture_output=True, text=True, timeout=120)
    assert c.returncode == 0 and f"release={rel.name}" in last(c), c.stdout


def test_update_keeps_only_the_newest_releases(site):
    """名稱以序號開頭：不靠時鐘（同一秒連跑三次，不睡）。"""
    mdir = site["mdir"]
    for _ in range(3):
        update_ok(site, UBUNTU_CVE_STATUS_KEEP="2")
    r = rels(mdir)
    assert [n[:6] for n in r] == ["000002", "000003"] and os.readlink(mdir / "current") == f"releases/{r[-1]}"
    assert sorted(n for n in releases(mdir) if n.endswith(".manifest")) == [f"{n}.manifest" for n in r]
    assert [n for n in releases(mdir) if not n.endswith(".manifest")] == r
    update_ok(site, UBUNTU_CVE_STATUS_KEEP="1")
    assert rels(mdir) == [os.readlink(mdir / "current")[len("releases/"):]] and rels(mdir)[0].startswith("000004-")
    r = run(site, "update", UBUNTU_CVE_STATUS_KEEP="0")
    assert r.returncode == 1 and "UBUNTU_CVE_STATUS_KEEP" in last(r)


@pytest.mark.parametrize("clock", [["20261106T120000Z"] * 3,                                          # 同一秒
                                   ["20261106T120059Z", "20261106T120058Z", "20261106T115959Z"]])   # 時鐘往回調（WSL 負載高時）
def test_release_order_does_not_depend_on_the_clock(site, clock):
    """第二輪：負載高時 rels 是 [..58, ..59]、current 卻指向 ..58（release 名稱只有秒，時鐘被往回調）。"""
    mdir = site["mdir"]
    for i, ts in enumerate(clock, 1):
        update_ok(site, UBUNTU_CVE_STATUS_KEEP="2", **fake_date(site, ts))
        assert os.readlink(mdir / "current") == f"releases/{i:06d}-{ts}"
    r = rels(mdir)
    assert r == [f"{2:06d}-{clock[1]}", f"{3:06d}-{clock[2]}"] and os.readlink(mdir / "current") == f"releases/{r[-1]}"
    assert run(site, "check").returncode == 0


@pytest.mark.parametrize("how,msg", [
    ({"UBUNTU_CVE_GIT_URL": "file:///nonexistent/uct", "UBUNTU_CVE_GIT_TRIES": "1"}, "ubuntu-cve-status.sh 失敗"),   # 下載失敗
    ({"UBUNTU_CVE_MIN_CVES": "100000"}, "ubuntu-cve-status.sh 失敗"),                                              # 下載到了、檢查不過
    ({"UBUNTU_CVE_RELEASES": "focal"}, "ubuntu-cve-status.sh 失敗"),                                               # 設定的發行版沒有任何狀態
    ({"UBUNTU_CVE_STATUS_MIN_FREE_MB": "9999999"}, "UBUNTU_CVE_STATUS_MIN_FREE_MB"),                              # 空間不夠：不下載
])
def test_failed_update_leaves_current_unchanged(site, how, msg):
    mdir = site["mdir"]
    update_ok(site)
    before_link, before = os.readlink(mdir / "current"), releases(mdir)
    penv = (site["state"] / "pilot.env").read_text(encoding="utf-8")
    r = run(site, "update", **how)
    assert r.returncode == 1 and last(r).startswith("RESULT FAIL ") and msg in last(r) and "current 不變" in last(r), r.stdout + r.stderr
    assert os.readlink(mdir / "current") == before_link
    assert releases(mdir) == before                                         # 新資料夾、manifest、clone 暫存都刪掉了
    assert (site["state"] / "pilot.env").read_text(encoding="utf-8") == penv
    assert run(site, "check").returncode == 0


def test_low_memory_does_not_download(site):
    if not os.access("/proc/meminfo", os.R_OK):
        pytest.skip("沒有 /proc/meminfo")
    r = run(site, "update", UBUNTU_CVE_STATUS_MIN_MEM_MB="9999999")
    assert r.returncode == 1 and "可用記憶體" in last(r) and "沒有下載" in last(r)
    assert not (site["mdir"] / "current").exists() and releases(site["mdir"]) == []


def start_stuck_update(site, marker, *prefix):
    """update 卡在 clone（假的 git 在跑）才回傳。"""
    p = subprocess.Popen([*prefix, "bash", str(SH), "update"], env={**site["env"], **slow_git(site, marker)},
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    t0 = time.time()
    while not sleepers(marker) and time.time() - t0 < 60 and p.poll() is None:
        time.sleep(0.2)
    assert sleepers(marker), "假的 git 沒有開始"
    return p


def test_update_interrupted_by_timeout_leaves_no_half_release_and_frees_the_lock(site):
    """timeout 送 TERM：這次的資料夾刪掉、current 不變；ubuntu-cve-status.sh 的整個 session（含內層 timeout 的 git，
    它在自己的行程群組）一起結束，鎖立刻拿得到（中 M1）。"""
    mdir, marker = site["mdir"], "29.731"
    update_ok(site)
    before_link, before = os.readlink(mdir / "current"), releases(mdir)
    try:
        p = start_stuck_update(site, marker, "timeout", "300")
        p.send_signal(signal.SIGTERM)                                       # timeout 把 TERM 轉給 update（同外層 timeout 到時）
        out, _ = p.communicate(timeout=60)
        assert p.returncode != 0
        assert lock_free(mdir)                                              # 立刻：不等內層的 timeout
        assert sleepers(marker) == []                                       # 卡住的 git 也結束了
        assert os.readlink(mdir / "current") == before_link
        # 第三輪 低 L-d：最後一行是 RESULT FAIL，這次的 clone 暫存當場刪掉（不留到下一次）
        assert out.strip().splitlines()[-1].startswith("RESULT FAIL 被中斷（TERM）；current 不變"), out
        assert releases(mdir) == before
        update_ok(site)                                                     # 不會「另一個更新正在執行」；留下的 clone 暫存這次刪掉
        assert not [n for n in releases(mdir) if n.startswith(".ubuntu-cve-clone")]
    finally:
        kill_sleepers(marker)


def test_update_killed_does_not_keep_the_lock(site):
    """KILL 沒有 trap：留下的 ubuntu-cve-status.sh（卡住的 git）還在跑，但鎖沒有傳給它，下一次 update 立刻拿得到（中 M1）。"""
    mdir, marker = site["mdir"], "28.419"
    update_ok(site)
    before_link = os.readlink(mdir / "current")
    try:
        p = start_stuck_update(site, marker)
        p.send_signal(signal.SIGKILL)
        p.wait(timeout=30)
        assert sleepers(marker)                                             # 留下的還在跑
        assert lock_free(mdir)
        assert os.readlink(mdir / "current") == before_link
        update_ok(site)
        assert os.readlink(mdir / "current") != before_link
    finally:
        kill_sleepers(marker)


@pytest.mark.parametrize("bad", ["/", "//", "/x/../y"])
def test_bad_mirror_dir_is_refused_before_any_write(site, bad):
    r = run(site, "update", PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=bad)
    assert r.returncode == 1 and last(r).startswith("RESULT FAIL 鏡像資料夾")
    assert (site["state"] / ".env").read_text(encoding="utf-8") == "PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=./data/ubuntu-cve-status\n"



# ---------- 只動自己建的東西（第二輪 高 H1） ----------

def euvd_site(tmp_path):
    a = euvd_api(tmp_path)
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    (state / "pilot.env").write_text("DT_URL=http://x\n", encoding="utf-8")
    e = euvd_env(PILOT_STATE_DIR=str(state), EUVD_API_URL=f"file://{a}", DT_KEV_ENISA_URL=f"file://{a}/eukev.json")
    e.pop("PILOT_PROJECT", None)
    return e


def run_euvd(e, mdir):
    r = subprocess.run(["bash", str(EUVD_SH), "update"], env={**e, "PILOT_EUVD_MIRROR_DIR": str(mdir)}, capture_output=True, text=True,
                       timeout=180)
    return r, r.stdout + r.stderr


@pytest.mark.parametrize("which", ["ubuntu", "euvd"])
def test_releases_symlink_is_refused_and_nothing_elsewhere_is_deleted(site, which):
    """releases 是指向別處的符號連結：原本會刪掉那裡的資料夾（還回 OK）。現在 RESULT FAIL，那裡什麼都沒少。"""
    other = site["tmp"] / "other"
    victims = ["000001-20200101T000000Z", "20200101T000000Z", "keepme"]
    for v in victims:
        (other / v).mkdir(parents=True)
        (other / v / "f").write_text("x", encoding="utf-8")
    mdir = site["tmp"] / f"m-{which}"
    mdir.mkdir()
    (mdir / "releases").symlink_to(other)
    snap = tree(other)
    if which == "ubuntu":
        r = run(site, "update", PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=str(mdir))
        out = r.stdout + r.stderr
    else:
        r, out = run_euvd(euvd_site(site["tmp"]), mdir)
    assert r.returncode == 1 and "RESULT FAIL" in out and "releases 是符號連結" in out, out
    assert tree(other) == snap and not (mdir / "current").exists()


@pytest.mark.parametrize("which", ["ubuntu", "euvd"])
def test_other_names_under_releases_are_never_deleted(site, which):
    """鏡像資料夾指到本來就有 releases/v1.0 的地方：只刪自己建的名稱，v1.0 留著。"""
    mdir = site["tmp"] / f"m-{which}"
    for n in ("v1.0", "notes", "v1.0.manifest"):
        p = mdir / "releases" / n
        (p.mkdir(parents=True) if n != "v1.0.manifest" else p.write_text("x", encoding="utf-8"))
    if which == "ubuntu":
        for _ in range(3):
            update_ok(site, PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=str(mdir), UBUNTU_CVE_STATUS_KEEP="1")
    else:
        e = euvd_site(site["tmp"])
        for i in range(3):
            if i:
                time.sleep(1.1)   # euvd-mirror.sh 的名稱仍是秒（只是不同秒；這個測試要的是「不刪別人的」）
            r, out = run_euvd(e, mdir)
            assert r.returncode == 0, out
    for n in ("v1.0", "notes", "v1.0.manifest"):
        assert (mdir / "releases" / n).exists(), n


@pytest.mark.parametrize("which", ["ubuntu", "euvd"])
@pytest.mark.parametrize("how", ["snapshot-link", "real-dir"])
def test_foreign_current_is_refused_and_left_alone(site, which, how):
    """鏡像資料夾指到 $SCA_PERSIST_DIR：current 是程式快照（app-<commit>）的連結，原本會被換掉。現在 RESULT FAIL，current 不動。"""
    mdir = site["tmp"] / f"persist-{which}"
    (mdir / "app-abc123").mkdir(parents=True)
    (mdir / "app-abc123" / "deploy").mkdir()
    if how == "snapshot-link":
        (mdir / "current").symlink_to("app-abc123")
    else:
        (mdir / "current").mkdir()
    snap = tree(mdir)
    if which == "ubuntu":
        r = run(site, "update", PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=str(mdir))
        out = r.stdout + r.stderr
        c = run(site, "check", PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=str(mdir))
        assert c.returncode == 1 and last(c).startswith("RESULT FAIL ") and "不是這個腳本建的" in last(c)
    else:
        r, out = run_euvd(euvd_site(site["tmp"]), mdir)
    assert r.returncode == 1 and "RESULT FAIL" in out and "不是這個腳本建的" in out, out
    assert tree(mdir) == snap                                               # 沒有建 releases、沒有 .lock、current 沒換
    assert "UBUNTU_CVE_STATUS_MIRROR" not in (site["state"] / "pilot.env").read_text(encoding="utf-8")


# ---------- 記憶體不夠時不跑 --check（第二輪 低 L2） ----------

def test_check_is_skipped_when_memory_is_short(site):
    if not os.access("/proc/meminfo", os.R_OK):
        pytest.skip("沒有 /proc/meminfo")
    update_ok(site)
    snap = tree(site["tmp"])
    r = run(site, "check", UBUNTU_CVE_STATUS_CHECK_MIN_MEM_MB="9999999")
    assert r.returncode == 3 and last(r).startswith("RESULT SKIPPED 可用記憶體 ") and "沒有檢查" in last(r) and "release=" in last(r)
    assert tree(site["tmp"]) == snap
    inst = rd("deploy", "pilot", "install.sh")
    blk = inst[inst.index('ubuntu-cve-status-mirror.sh" check'):inst.index('kv_set "$PILOTENV" UBUNTU_CVE_STATUS_MIRROR')]
    assert "elif [ $ucx = 3 ]; then" in blk and "N-ubuntu-status-mirror GAP \"沒有檢查也沒有更新" in blk
    assert blk.index("elif [ $ucx = 3 ]") < blk.index('ubuntu-cve-status-mirror.sh" update')   # 記憶體不夠時也不下載
    stt = rd("deploy", "pilot", "status.sh")
    assert '3) status ubuntu-status-mirror GAP "沒有檢查' in stt


def test_runner_copy_is_skipped_when_memory_is_short(site):
    if not os.access("/proc/meminfo", os.R_OK):
        pytest.skip("沒有 /proc/meminfo")
    update_ok(site)
    dst = site["tmp"] / "runner" / "ucs"
    s = subprocess.run(["bash", str(SYNC), "ubuntu-cve-status", str(site["state"] / "pilot.env"), getpass.getuser(), str(site["tmp"])],
                       env={**site["env"], "UBUNTU_CVE_STATUS_SYNC_DEST": str(dst), "MIRROR_SYNC_HEADROOM_MB": "1",
                            "UBUNTU_CVE_STATUS_SYNC_MIN_MEM_MB": "9999999"}, capture_output=True, text=True, timeout=120)
    assert s.returncode == 1 and s.stdout == "" and "可用記憶體" in s.stderr and "沒有換上" in s.stderr, s.stderr
    assert not dst.exists()


def test_runner_copy_checks_memory_before_copying(site):
    """第三輪 低 L-f：記憶體不夠時在複製之前就停（不建資料夾、不複製）。"""
    if not os.access("/proc/meminfo", os.R_OK):
        pytest.skip("沒有 /proc/meminfo")
    update_ok(site)
    dst, probe = site["tmp"] / "runner" / "ucs", site["tmp"] / "probe"
    s = subprocess.run(["bash", str(SYNC), "ubuntu-cve-status", str(site["state"] / "pilot.env"), getpass.getuser(), str(site["tmp"])],
                       env={**site["env"], "UBUNTU_CVE_STATUS_SYNC_DEST": str(dst), "MIRROR_SYNC_HEADROOM_MB": "1",
                            "UBUNTU_CVE_STATUS_SYNC_MIN_MEM_MB": "9999999", "MIRROR_SYNC_TEST_PROBE": str(probe)},
                       capture_output=True, text=True, timeout=120)
    assert s.returncode == 1 and "沒有複製" in s.stderr, s.stderr
    assert not probe.exists() and not (dst.parent / "ucs.releases").exists()
    ms = rd("deploy", "gitlab-runner", "mirror-sync.sh")
    assert ms.index('if [ "$NEEDMEM" -gt 0 ]') < ms.index('stage=$(mktemp -d') < ms.index('rd | head -c')


# ---------- 訊息不重複 FAIL（第二輪 低 L3） ----------

def test_fail_is_printed_once(site):
    update_ok(site)
    (site["mdir"] / "current" / FILES["linux"]).write_bytes(b"x")
    r = run(site, "check")
    assert r.returncode == 1 and last(r).startswith("RESULT FAIL ") and "FAIL FAIL" not in last(r) and "sha256" in last(r), last(r)
    s = SH.read_text(encoding="utf-8")
    assert 'fail "--check 失敗：$(firstfail "$r")"' in s and 'echo "RESULT FAIL $(firstfail "$r")（$(info)）"' in s


def test_check_reads_one_resolved_release():
    """低 L1：check 先把 current 解成 releases/<名稱> 再檢查那一份（中途切換不會混到兩份）；剩下的誤報只會是 FAIL，寫在文件。"""
    s = SH.read_text(encoding="utf-8")
    assert 'rel=$(readlink "$cur"); rel=${rel#releases/}; rp=$MDIR/releases/$rel' in s and 'r=$(bash "$MIRROR" --check "$rp" 2>&1)' in s
    for doc in (rd("deploy", "pilot", "README.md"), rd("docs", "offline-mirrors.md"), s):
        assert "不會誤報 OK" in doc


# ---------- 第三輪 ----------

def test_term_right_after_the_switch_keeps_the_new_release(site):
    """低 L-a：TERM 落在 mv -T 之後、旗標之前：EXIT trap 原本會刪掉剛切換過去的 release（current 指到不存在的資料夾）。
    現在看 current 本身：已指向這次的就留著。"""
    b = site["tmp"] / "mvbin"
    b.mkdir()
    (b / "mv").write_text(f'#!/bin/sh\n"{shutil.which("mv")}" "$@"; rc=$?\n'
                          'case "$*" in *current.tmp*) kill -TERM "$PPID"; sleep 1;; esac\nexit $rc\n', encoding="utf-8")
    (b / "mv").chmod(0o755)
    r = run(site, "update", PATH=f"{b}:{os.environ['PATH']}")
    cur = site["mdir"] / "current"
    assert r.returncode != 0 and last(r).startswith("RESULT FAIL 被中斷（TERM，切換之後）；current 已是 releases/"), r.stdout + r.stderr
    assert cur.is_symlink() and (cur / "SOURCE").is_file() and (cur / FILES["linux"]).is_file()
    assert run(site, "check").returncode == 0
    s = SH.read_text(encoding="utf-8")
    assert "SWITCHED" not in s and 'switched(){ [ "$(readlink "$cur" 2>/dev/null)" = "releases/$TS" ]; }' in s


@pytest.mark.parametrize("cmd", ["update", "check"])
def test_first_version_layout_fails_with_a_hint(site, cmd):
    """低 L-b：第一版（名稱只有 UTC 時間）建的鏡像：FAIL，訊息提示 rm -rf 鏡像資料夾後再跑 update。"""
    mdir = site["mdir"]
    (mdir / "releases" / "20261105T010203Z").mkdir(parents=True)
    (mdir / "current").symlink_to("releases/20261105T010203Z")
    snap = tree(site["tmp"])
    r = run(site, cmd)
    assert r.returncode == 1 and last(r).startswith("RESULT FAIL ") and "第一版" in last(r) and f"rm -rf {mdir}" in last(r), last(r)
    assert tree(site["tmp"]) == snap
    readme = rd("deploy", "pilot", "README.md")
    assert "**舊格式要先 `rm -rf <鏡像資料夾>` 再跑 `update`**" in readme


def test_install_writes_pilot_env_only_after_ok():
    """低 L-c：版面不對、update 拒絕時不把 current 寫進 pilot.env。"""
    inst = rd("deploy", "pilot", "install.sh")
    blk = inst[inst.index("UCS_OK=0"):inst.index("# ======================= C. compose")]
    assert blk.count("UCS_OK=1; status N-ubuntu-status-mirror OK") == 2
    assert '[ $UCS_OK = 1 ] && [ -e "$ud/current" ] && kv_set "$PILOTENV" UBUNTU_CVE_STATUS_MIRROR "$ud/current"' in blk
    assert blk.count('kv_set "$PILOTENV" UBUNTU_CVE_STATUS_MIRROR') == 1


def test_term_and_kill_are_documented():
    """低 L-d、L-f：文件寫 TERM 與 KILL 的差別、驗證指令的 SKIPPED（結束碼 3）。"""
    readme = rd("deploy", "pilot", "README.md")
    assert "- **TERM／INT／HUP**" in readme and "- **KILL**：沒有 trap，什麼都不印" in readme
    assert "SKIPPED：可用記憶體不到 UBUNTU_CVE_STATUS_CHECK_MIN_MEM_MB，沒有檢查（結束碼 3）" in readme
    assert "被 KILL 時沒有 trap" in SH.read_text(encoding="utf-8")


def test_euvd_name_collision_changes_nothing(site):
    """低 L-e：euvd-mirror.sh 的名稱撞到現有的 release（同一秒內重跑或時鐘往回調）：原本 fail() 會刪掉那一份（可能就是 current）。"""
    e = euvd_site(site["tmp"])
    mdir = site["tmp"] / "m-euvd"
    fd = fake_date(site, "20261106T120000Z")
    r, out = run_euvd({**e, **fd}, mdir)
    assert r.returncode == 0, out
    cur = mdir / "current"
    before, snap = os.readlink(cur), tree(mdir)
    r, out = run_euvd({**e, **fd}, mdir)
    assert r.returncode == 1 and "RESULT FAIL" in out and "已存在" in out and "什麼都沒動" in out, out
    assert os.readlink(cur) == before and (cur / "index.tsv").is_file()
    nolock = lambda t: {k: v for k, v in t.items() if k != ".lock"}   # noqa: E731  .lock 每次 update 都會重開
    assert nolock(tree(mdir)) == nolock(snap)
    c = subprocess.run(["bash", str(EUVD_SH), "check"], env={**e, "PILOT_EUVD_MIRROR_DIR": str(mdir)}, capture_output=True, text=True,
                       timeout=120)
    assert c.returncode == 0, c.stdout


# ---------- 第四輪：常駐環境的預設資料夾（中）、每日排程的 timeout（低） ----------

def persist_env(tmp_path):
    """常駐環境的版面：<P>/state、<P>/app-1、<P>/app-2（程式快照，各有 deploy/pilot 與 scripts/mirror）、<P>/current -> app-1。"""
    P = tmp_path / "sca-persist"
    for app in ("app-1", "app-2"):
        shutil.copytree(ROOT / "deploy" / "pilot", P / app / "deploy" / "pilot", ignore=shutil.ignore_patterns("state", "data"))
        shutil.copytree(ROOT / "tools" / "mirror", P / app / "scripts" / "mirror")
    (P / "current").symlink_to("app-1")
    (P / "state").mkdir()
    (P / "state" / "pilot.env").write_text("DT_URL=http://x\n", encoding="utf-8")
    return P


def resolve(P, via, *fns, env=None):
    lib = P / via / "deploy" / "pilot" / "lib.sh"
    e = {**os.environ, "PILOT_STATE_DIR": str(P / "state"), **(env or {})}
    e.pop("PILOT_PROJECT", None)
    if not env or "PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR" not in env:
        e.pop("PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR", None)
    r = subprocess.run(["bash", "-c", f'. "{lib}"; ' + "".join(f"{f}; " for f in fns) + "ubuntu_status_mirror_dir"], env=e, capture_output=True, text=True,
                       check=True)
    return r.stdout.strip()


def test_persistent_default_is_outside_the_snapshot_and_shared(tmp_path):
    P = persist_env(tmp_path)
    want = str(P / "mirrors" / "ubuntu-cve-status")
    envf = P / "state" / ".env"
    # 第一次 install 之前就跑的每日排程（current = app-1，state/.env 還沒有）
    assert resolve(P, "current") == want
    envf.write_text("PILOT_PROJECT=sca-persist\n", encoding="utf-8")
    assert resolve(P, "current") == want
    # workflow 的 install（新的快照 app-2）：下載之前就把絕對路徑寫進 state/.env
    assert resolve(P, "app-2", "ubuntu_status_mirror_dir_setdef") == want
    assert f"PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR={want}\n" in envf.read_text(encoding="utf-8")
    assert resolve(P, "current") == want and resolve(P, "app-1") == want   # 每日排程（舊的快照）讀到同一個
    assert not want.startswith(str(P / "app-"))                          # 不在 app-* 底下（workflow 的 rm -rf "$app" 與 app-* 清理）


def test_first_version_relative_default_is_migrated(tmp_path):
    P = persist_env(tmp_path)
    want = str(P / "mirrors" / "ubuntu-cve-status")
    envf = P / "state" / ".env"
    envf.write_text("PILOT_PROJECT=sca-persist\nPILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=./data/ubuntu-cve-status\n", encoding="utf-8")
    assert resolve(P, "current") == want and resolve(P, "app-2") == want   # 改寫之前，兩邊就已算出同一個
    assert resolve(P, "app-2", "ubuntu_status_mirror_dir_setdef") == want
    t = envf.read_text(encoding="utf-8")
    assert f"PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR={want}\n" in t and "./data/ubuntu-cve-status" not in t
    # 環境變數優先：明確設成 ./data/ubuntu-cve-status 也照用，setdef 不蓋掉
    envf.write_text("PILOT_PROJECT=sca-persist\n", encoding="utf-8")
    got = resolve(P, "app-2", "ubuntu_status_mirror_dir_sync", "ubuntu_status_mirror_dir_setdef",
                  env={"PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR": "./data/ubuntu-cve-status"})
    assert got == str(P / "app-2" / "deploy" / "pilot" / "data" / "ubuntu-cve-status")
    assert "PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=./data/ubuntu-cve-status\n" in envf.read_text(encoding="utf-8")
    # 自己設的其他值不動
    envf.write_text("PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=/srv/ucs\n", encoding="utf-8")
    assert resolve(P, "app-2", "ubuntu_status_mirror_dir_setdef") == "/srv/ucs"


def test_plain_pilot_keeps_the_old_default(tmp_path):
    """state 在 deploy/pilot 底下（一般的 pilot）：預設照舊是 deploy/pilot/data/ubuntu-cve-status，setdef 寫相對路徑。"""
    app = tmp_path / "repo"
    shutil.copytree(ROOT / "deploy" / "pilot", app / "deploy" / "pilot", ignore=shutil.ignore_patterns("state", "data"))
    st = app / "deploy" / "pilot" / "state"
    st.mkdir()
    (st / ".env").write_text("PILOT_PROJECT=sca-pilot\n", encoding="utf-8")
    e = {k: v for k, v in os.environ.items() if k not in ("PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR", "PILOT_PROJECT", "PILOT_STATE_DIR")}
    r = subprocess.run(["bash", "-c", f'. "{app}/deploy/pilot/lib.sh"; ubuntu_status_mirror_dir_setdef; ubuntu_status_mirror_dir'],
                       env=e, capture_output=True, text=True, check=True)
    assert r.stdout.strip() == str(app / "deploy" / "pilot" / "data" / "ubuntu-cve-status")
    assert "PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=./data/ubuntu-cve-status\n" in (st / ".env").read_text(encoding="utf-8")


def test_install_and_daily_share_one_folder_one_lock_and_pass_layout_and_sync(site, tmp_path):
    """常駐環境的預設資料夾：install（app-2）建的鏡像，每日排程（current = app-1）的 check 讀得到；同一把 .lock；
    <P>/current（程式快照的連結）不會觸發 layout()；mirror-sync.sh 的 inside() 接受它。"""
    P = persist_env(tmp_path)
    (P / "state" / ".env").write_text("PILOT_PROJECT=sca-persist\n", encoding="utf-8")
    e = {k: v for k, v in site["env"].items() if k != "PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR"}
    e.update(PILOT_STATE_DIR=str(P / "state"), PILOT_PROJECT="sca-persist")
    mdir = P / "mirrors" / "ubuntu-cve-status"
    u = subprocess.run(["bash", "-c", f'. "{P}/app-2/deploy/pilot/lib.sh"; ubuntu_status_mirror_dir_setdef; '
                        f'bash "{P}/app-2/deploy/pilot/ubuntu-cve-status-mirror.sh" update'], env=e, capture_output=True, text=True, timeout=300)
    assert u.returncode == 0 and "RESULT OK" in u.stdout.splitlines()[-1], u.stdout + u.stderr
    assert (mdir / "current").is_symlink() and os.readlink(P / "current") == "app-1"   # 常駐環境的 current 沒動
    assert f"UBUNTU_CVE_STATUS_MIRROR={mdir}/current\n" in (P / "state" / "pilot.env").read_text(encoding="utf-8")
    c = subprocess.run(["bash", str(P / "current" / "deploy" / "pilot" / "ubuntu-cve-status-mirror.sh"), "check"], env=e,
                       capture_output=True, text=True, timeout=120)
    assert c.returncode == 0 and os.readlink(mdir / "current")[len("releases/"):] in c.stdout, c.stdout
    # 同一把鎖：install 那邊拿著鎖時，每日排程那邊的 update 拿不到
    holder = subprocess.Popen(["flock", str(mdir / ".lock"), "sleep", "30"])
    try:
        t0 = time.time()
        while lock_free(mdir) and time.time() - t0 < 10:
            time.sleep(0.1)
        d = subprocess.run(["bash", str(P / "current" / "deploy" / "pilot" / "ubuntu-cve-status-mirror.sh"), "update"], env=e,
                           capture_output=True, text=True, timeout=120)
        assert d.returncode == 1 and "另一個更新正在執行" in d.stdout, d.stdout
    finally:
        holder.kill()
        holder.wait()
    # GitLab runner 的複本：mirror-sync.sh 的 inside()（來源要在常駐帳號的家目錄或常駐環境裡）
    dst = tmp_path / "runner" / "ucs"
    s = subprocess.run(["bash", str(SYNC), "ubuntu-cve-status", str(P / "state" / "pilot.env"), getpass.getuser(), str(P)],
                       env={**e, "UBUNTU_CVE_STATUS_SYNC_DEST": str(dst), "MIRROR_SYNC_HEADROOM_MB": "1", "HOME": "/nonexistent"},
                       capture_output=True, text=True, timeout=120)
    assert s.returncode == 0 and s.stdout.strip() == str(dst), s.stderr


def test_workflow_cleanup_never_reaches_the_default_folder():
    """workflow 只刪 $app、$app.tmp 與 $base/app-*：<sca-persist>/mirrors 不在裡面。"""
    wf = rd(".github", "workflows", "sca-persistent.yml")
    rms = [ln.strip() for ln in wf.splitlines() if "rm -rf" in ln]
    assert rms and all(('rm -rf "$app' in ln) or ('"$base"/app-*' in ln and 'rm -rf "$d"' in ln) for ln in rms), rms
    assert 'base="$HOME/sca-persist"; app="$base/app-$GITHUB_SHA"' in wf and 'PILOT_STATE_DIR="$HOME/sca-persist/state"' in wf


def test_daily_timeouts_leave_time_for_the_trap():
    """低：timeout 放在 runuser 裡面、加 -k 30（runuser 收到 TERM 約 2 秒就 KILL 子行程，trap 來不及清理）；EUVD 那一行也一樣。"""
    ref = rd("deploy", "gitlab-runner", "nvd-refresh.sh")
    assert 'runuser -u "$U" -- timeout -k 30 900 env PILOT_STATE_DIR="$PSTATE" PILOT_PROJECT=sca-persist bash "$P/current/deploy/pilot/euvd-mirror.sh" update --trigger-dt' in ref
    assert 'runuser -u "$U" -- timeout -k 30 3600 env PILOT_STATE_DIR="$PSTATE" PILOT_PROJECT=sca-persist bash "$P/current/deploy/pilot/ubuntu-cve-status-mirror.sh" update' in ref
    for ln in ref.splitlines():
        if "euvd-mirror.sh\" update" in ln or "ubuntu-cve-status-mirror.sh\" update" in ln:
            assert not re.match(r"\s*timeout \d+ runuser", ln), ln
    readme = rd("deploy", "pilot", "README.md")
    lim = readme[readme.index("這個部署另外的限制："):]
    # 審查 L3、L4：寫在「限制」那一節，變數名稱與預設值和程式一致
    assert "**Ubuntu CVE Tracker 狀態鏡像：`update` 被 KILL 之後**" in lim and "永遠不會變成" in lim and "2.1 GB" in lim
    assert "`runuser -u \"$U\" -- timeout -k 30 3600 …`" in lim and "5520 秒" in lim
    for v, d in (("UBUNTU_CVE_GIT_TIMEOUT", "1800"), ("UBUNTU_CVE_GIT_TRIES", "3"), ("UBUNTU_CVE_GIT_RETRY_SLEEP", "60")):
        assert f"`{v}`（{d}）" in lim or f"`{v}`（預設 {d}）" in lim, v
        assert f'{v}:-{d}' in rd("scripts", "mirror", "ubuntu-cve-status.sh"), v

# ---------- check、info 唯讀 ----------

@pytest.mark.parametrize("prepared", [False, True])
def test_check_and_info_write_nothing(site, prepared):
    """整個檔案樹（state 與鏡像資料夾）在 check、info 前後不變；沒有鏡像時也不建資料夾、不寫回 state/.env。"""
    if prepared:
        update_ok(site)
    snap = tree(site["tmp"])
    for cmd in ("check", "info"):
        r = run(site, cmd)
        assert (r.returncode == 0) == prepared, r.stdout
        assert tree(site["tmp"]) == snap, cmd
    if prepared:   # 壞掉的鏡像：FAIL，同樣不寫
        cur = site["mdir"] / "current"
        (cur / FILES["linux"]).write_bytes(b"x")
        snap = tree(site["tmp"])
        r = run(site, "check")
        assert r.returncode == 1 and last(r).startswith("RESULT FAIL ") and "sha256" in last(r) and "release=" in last(r)
        assert tree(site["tmp"]) == snap
    else:
        assert not site["mdir"].exists()
        assert "persist" not in (site["state"] / ".env").read_text(encoding="utf-8")


def test_stale_mirror_fails_check(site):
    update_ok(site)
    r = run(site, "check", UBUNTU_CVE_MAX_COMMIT_AGE_DAYS="1")            # 假倉庫的 commit 是 1 天前
    assert r.returncode == 1 and "上游太久沒有更新" in last(r)


def test_usage_and_unknown_command(site):
    r = run(site, "nope")
    assert r.returncode == 2 and "update" in r.stdout and "check" in r.stdout and "info" in r.stdout
    assert "set -uo pipefail" not in r.stdout


# ---------- 解析順序（同 EUVD） ----------

def test_mirror_dir_resolution(site):
    base = {**os.environ, "PILOT_STATE_DIR": str(site["state"])}
    base.pop("PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR", None)
    base.pop("PILOT_PROJECT", None)
    r = subprocess.run(["bash", "-c", f'. "{LIB}"; ubuntu_status_mirror_dir'], env=base, capture_output=True, text=True, check=True)
    # state 不在 deploy/pilot 底下（常駐環境的版面）：第一版的 ./data/ubuntu-cve-status 當成沒有設定，用 <state 的上一層>/mirrors/…
    assert r.stdout.strip() == str(site["tmp"] / "mirrors" / "ubuntu-cve-status")
    (site["state"] / ".env").write_text("PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=./x/ucs\n", encoding="utf-8")
    r = subprocess.run(["bash", "-c", f'. "{LIB}"; ubuntu_status_mirror_dir'], env=base, capture_output=True, text=True, check=True)
    assert r.stdout.strip() == str(ROOT / "deploy" / "pilot" / "x" / "ucs")   # 其他相對路徑以 deploy/pilot 為基準
    new = site["tmp"] / "cache" / "ucs"
    r = subprocess.run(["bash", "-c", f'. "{LIB}"; ubuntu_status_mirror_dir_sync; ubuntu_status_mirror_dir'],
                       env={**base, "PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR": f"{new}//"}, capture_output=True, text=True, check=True)
    assert r.stdout.strip() == str(new)                                     # 環境變數優先；結尾的 / 去掉
    r = subprocess.run(["bash", "-c", f'. "{LIB}"; ubuntu_status_mirror_dir'], env=base, capture_output=True, text=True, check=True)
    assert r.stdout.strip() == str(new)                                     # 已寫回 state/.env


# ---------- GitLab runner 的複本 ----------

def test_runner_copy_has_both_indexes_and_passes_check(site):
    update_ok(site)
    dst = site["tmp"] / "runner" / "ucs"
    s = subprocess.run(["bash", str(SYNC), "ubuntu-cve-status", str(site["state"] / "pilot.env"), getpass.getuser(), str(site["tmp"])],
                       env={**site["env"], "UBUNTU_CVE_STATUS_SYNC_DEST": str(dst), "MIRROR_SYNC_HEADROOM_MB": "1"},
                       capture_output=True, text=True, timeout=120)
    assert s.returncode == 0 and s.stdout.strip() == str(dst), s.stderr
    assert dst.is_symlink()
    for f in (*FILES.values(), "SOURCE"):
        assert (dst / f).read_bytes() == (site["mdir"] / "current" / f).read_bytes(), f
    r = subprocess.run(["bash", str(ROOT / "tools" / "mirror" / "ubuntu-cve-status.sh"), "--check", str(dst)],
                       env=site["env"], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout
    # 大小上限
    s = subprocess.run(["bash", str(SYNC), "ubuntu-cve-status", str(site["state"] / "pilot.env"), getpass.getuser(), str(site["tmp"])],
                       env={**site["env"], "UBUNTU_CVE_STATUS_SYNC_DEST": str(dst), "UBUNTU_CVE_STATUS_SYNC_MAX_MB": "0",
                            "MIRROR_SYNC_HEADROOM_MB": "1"}, capture_output=True, text=True, timeout=120)
    assert s.returncode == 1 and s.stdout == "" and "鏡像太大" in s.stderr


# ---------- 接線（文字檢查） ----------

def test_script_safety():
    s = SH.read_text(encoding="utf-8")
    assert "\nset -uo pipefail\n" in s
    body = s.split("\nset -uo pipefail\n", 1)[1]
    # rm -rf 只在 safe_rm 裡（確認不是空的、在 releases/ 底下、沒有 . 或 ..）
    rm = [ln for ln in body.splitlines() if "rm -rf" in ln and not ln.lstrip().startswith(("#", "echo "))]
    assert rm == ['    rm -rf -- "$p"'], rm
    assert 'case $p in "$MDIR"/releases/?*) ;;' in s and "*/../*|*/./*" in s
    assert "/tmp" not in body and "mktemp" not in body
    assert 'ln -sfn "releases/$TS" "$MDIR/current.tmp" && mv -T "$MDIR/current.tmp" "$cur"' in s
    assert 'r=$(bash "$MIRROR" --check "$REL" 2>&1 9>&-) || fail' in s
    assert '( umask 022; exec setsid -w bash "$MIRROR" "$@" ) 9>&- &' in s   # 鎖不傳給 ubuntu-cve-status.sh（中 M1）
    assert body.index('r=$(bash "$MIRROR" --check "$REL"') < body.index('mv -T "$MDIR/current.tmp"')   # 先 check 才切換
    assert 'kv_set "$PILOTENV" UBUNTU_CVE_STATUS_MIRROR "$cur"' in s
    # check、info 在任何寫入之前就結束
    first_write = min(body.index(x) for x in ("ubuntu_status_mirror_dir_sync", "mkdir -p", "exec 9>", "kv_set"))
    assert body.index("  check) do_check; exit $?;;") < first_write and body.index("  info) info; exit $?;;") < first_write
    mir = rd("scripts", "mirror", "ubuntu-cve-status.sh")
    assert 'work=$(mktemp -d "$PARENT/.ubuntu-cve-clone.XXXXXX")' in mir   # clone 暫存在輸出資料夾的同一層（鏡像資料夾底下）


def test_install_wiring():
    inst = rd("deploy", "pilot", "install.sh")
    assert 'timeout 600 "$PILOT_DIR/ubuntu-cve-status-mirror.sh" check' in inst
    assert 'timeout 2400 "$PILOT_DIR/ubuntu-cve-status-mirror.sh" update' in inst
    assert inst.index('ubuntu-cve-status-mirror.sh" check') < inst.index('ubuntu-cve-status-mirror.sh" update')
    assert inst.count("status N-ubuntu-status-mirror OK") == 2 and "status N-ubuntu-status-mirror GAP" in inst
    assert "ud=$(ubuntu_status_mirror_dir)" in inst and "ubuntu_status_mirror_dir_sync" in inst
    assert 'kv_set "$PILOTENV" UBUNTU_CVE_STATUS_MIRROR "$ud/current"' in inst
    assert "ubuntu_status_mirror_dir_setdef" in inst and "setdef PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR" not in inst
    assert inst.index("ubuntu_status_mirror_dir_sync") < inst.index("ubuntu_status_mirror_dir_setdef") < inst.index("ud=$(ubuntu_status_mirror_dir)") \
        < inst.index('ubuntu-cve-status-mirror.sh" check')                  # 第一次部署、下載之前就生效
    assert inst.index("N-euvd-mirror GAP") < inst.index("N-ubuntu-status-mirror") < inst.index("# ======================= C. compose")
    assert "MDIR=$(ubuntu_status_mirror_dir)" in SH.read_text(encoding="utf-8")


def test_status_wiring():
    stt = rd("deploy", "pilot", "status.sh")
    assert '"$PILOT_DIR/ubuntu-cve-status-mirror.sh" check' in stt
    assert "status ubuntu-status-mirror OK" in stt and "status ubuntu-status-mirror GAP" in stt
    assert "req_fail ubuntu-status-mirror" not in stt                      # 不影響結束碼


def test_daily_refresh_and_runner_wiring():
    ref = rd("deploy", "gitlab-runner", "nvd-refresh.sh")
    i = ref.index('ubuntu-cve-status-mirror.sh" update')
    assert 'runuser -u "$U" -- timeout -k 30 3600 env PILOT_STATE_DIR="$PSTATE" PILOT_PROJECT=sca-persist bash "$P/current/deploy/pilot/ubuntu-cve-status-mirror.sh" update' in ref
    assert ref.index("NVD_MIRROR_MODIFIED NVD_MIRROR_RELEASE; do kv_set") < ref.index('euvd-mirror.sh" update') < i   # 不擋住 NVD 與 EUVD
    assert 'mirror-sync.sh" ubuntu-cve-status "$PILOTENV" "$U" "$P"' in ref and 'kv_set "$t6" UBUNTU_CVE_STATUS_MIRROR "$usm"' in ref
    assert ref.rstrip().endswith('exit "$x"')                                # 失敗只記 WARN，不改結束碼
    assert "|| ux=$?" in ref and 'chown root:gitlab-runner "$t6"' in ref
    gr = rd("deploy", "gitlab-runner", "install.sh")
    assert 'mirror-sync.sh" ubuntu-cve-status "$PILOTENV" "$OWNER" "$PERSIST"' in gr
    assert 'kv_set "$GENV" UBUNTU_CVE_STATUS_MIRROR "$usm"' in gr and "st G-ubuntu-status OK" in gr and "st G-ubuntu-status WARN" in gr
    assert gr.index('kv_set "$GENV" UBUNTU_CVE_STATUS_MIRROR') < gr.index('chown root:gitlab-runner "$GENV"; chmod 640 "$GENV"')
    assert "Ubuntu CVE Tracker 狀態鏡像，並同步給 GitLab runner" in gr
    ms = rd("deploy", "gitlab-runner", "mirror-sync.sh")
    assert "ubuntu-cve-status) KEY=UBUNTU_CVE_STATUS_MIRROR" in ms and "CHECK=$CODE/tools/mirror/ubuntu-cve-status.sh" in ms
    assert "CHECKMEM=${UBUNTU_CVE_STATUS_SYNC_CHECK_MEM_MB:-4096}" in ms and "ulimit -v $(( CHECKMEM * 1024 ))" in ms
    scan = rd("scripts", "pilot", "sca-scan")
    case = next(ln for ln in scan.splitlines() if ln.strip().startswith("case $k in DT_URL|"))
    assert "|UBUNTU_CVE_STATUS_MIRROR)" in case                              # job 讀得到 runner 的 pilot.env 裡這個鍵


def test_docs():
    eg = rd("docs", "offline-egress.md")
    row = next(ln for ln in eg.splitlines() if ln.startswith("| Ubuntu CVE Tracker"))
    assert "git.launchpad.net" in row and "https" in row and "shallow clone" in row and "D-ubuntu-status" in row and "U1" in row
    om = rd("docs", "offline-mirrors.md")
    assert "### 部署（`deploy/pilot/ubuntu-cve-status-mirror.sh`）" in om and "1 GB" in om and "2.5 GB" in om
    readme = rd("deploy", "pilot", "README.md")
    sec = readme[readme.index("## Ubuntu CVE Tracker 狀態鏡像"):readme.index("## 連外清單")]
    for want in ("ubuntu-cve-status-mirror.sh update|check|info", "N-ubuntu-status-mirror", "**磁碟與記憶體需求**", "**驗證**",
                 "ubuntu-cve-status-mirror.sh\" check", "/etc/sca-gitlab/pilot.env", "UBUNTU_CVE_STATUS_MIN_FREE_MB", "UBUNTU_CVE_STATUS_MIN_MEM_MB",
                 "PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR"):
        assert want in sec, want
    assert "| `ubuntu-cve-status-mirror.sh`（主機） | git.launchpad.net" in readme
    assert "PILOT_UBUNTU_CVE_STATUS_MIRROR_DIR=./data/ubuntu-cve-status" in rd("deploy", "pilot", "env.example")
    assert "ubuntu-cve-status-mirror.sh" in rd("deploy", "versions.md")
    gr = rd("deploy", "gitlab-runner", "README.md")
    assert "/var/lib/sca-gitlab/ubuntu-cve-status" in gr
    row = next(ln for ln in gr.splitlines() if ln.startswith("| NVD 每日更新"))           # 低 L4
    assert "ENISA EUVD" in row and "Ubuntu CVE Tracker" in row
    assert "同一個實體資料夾、同一把 `.lock`" in sec and "**`<sca-persist>/mirrors/ubuntu-cve-status`**" in sec   # 第四輪：預設不在快照裡
    assert "兩個不同的實體資料夾" not in sec
