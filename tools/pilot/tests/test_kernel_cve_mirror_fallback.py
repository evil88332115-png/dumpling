"""tools/mirror/kernel-cve.sh 的備援來源：主來源失敗時改用 KERNEL_CVE_GIT_FALLBACK_URLS，SOURCE 記用了哪一個；
備援的資料比上一份舊時不換（有可沿用的上一份就沿用＝ATTENTION，沒有就 FAIL）。只用本機 file:// 的 git 庫，不連網。"""
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "mirror" / "kernel-cve.sh"
ORG = "f4215fc3-5b6b-47ff-a258-f7189bd81038"


def make_repo(path, date, ids=("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003")):
    """有 cve/published/<年>/CVE-….json 的 git 庫；commit 日期固定為 date。"""
    for cid in ids:
        f = path / "cve" / "published" / cid.split("-")[1] / f"{cid}.json"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({"cveMetadata": {"cveId": cid, "assignerOrgId": ORG},
                                 "containers": {"cna": {"affected": [{"programFiles": ["net/x.c"]}]}}}), encoding="utf-8")
    env = dict(os.environ, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
    g = ["git", "-c", "init.defaultBranch=main", "-c", "core.hooksPath=/dev/null", "-C", str(path)]
    subprocess.run(g + ["init", "-q"], check=True, env=env)
    subprocess.run(g + ["add", "-A"], check=True, env=env)
    subprocess.run(g + ["commit", "-q", "-m", "records"], check=True, env=env)
    return subprocess.run(g + ["rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()


def run(tmp, primary, fallback, reuse=None, name="out", extra=None):
    env = dict(os.environ, KERNEL_CVE_GIT_URL=primary, KERNEL_CVE_MIN_RECORDS="1", KERNEL_CVE_GIT_TIMEOUT="120",
               KERNEL_CVE_GIT_RETRY_DELAY="0")
    for k in ("KERNEL_CVE_GIT_FALLBACK_URLS", "KERNEL_CVE_REUSE_FROM", "KERNEL_CVE_FALLBACK_FROM", "KERNEL_CVE_TOTAL_TIMEOUT"):
        env.pop(k, None)
    if fallback is not None:
        env["KERNEL_CVE_GIT_FALLBACK_URLS"] = fallback
    if reuse:
        env["KERNEL_CVE_REUSE_FROM"] = str(reuse)
    env.update(extra or {})
    dest = tmp / name
    p = subprocess.run(["bash", str(SCRIPT), str(dest), str(tmp / f"{name}.manifest")], env=env, capture_output=True, text=True, timeout=300)
    src = {}
    if (dest / "SOURCE").exists():
        src = dict(l.split("=", 1) for l in (dest / "SOURCE").read_text(encoding="utf-8").splitlines() if "=" in l)
    return p, src, dest


@pytest.fixture
def repos(tmp_path):
    new = tmp_path / "new"
    new.mkdir()
    old = tmp_path / "old"
    old.mkdir()
    c_new = make_repo(new, "2026-11-16T10:00:00+00:00")
    c_old = make_repo(old, "2026-11-10T10:00:00+00:00", ids=("CVE-2024-0001", "CVE-2024-0002"))
    return {"new": (f"file://{new}", c_new), "old": (f"file://{old}", c_old), "bad": f"file://{tmp_path}/missing"}


def test_default_fallback_is_public_kernel_mirror():
    s = SCRIPT.read_text(encoding="utf-8")
    assert "${KERNEL_CVE_GIT_FALLBACK_URLS-https://kernel.googlesource.com/pub/scm/linux/security/vulns}" in s


def test_primary_ok_does_not_use_fallback(tmp_path, repos):
    p, src, _ = run(tmp_path, repos["new"][0], repos["bad"])
    assert p.returncode == 0, p.stderr
    assert src["source"] == repos["new"][0] and src["source_role"] == "primary" and src["commit"] == repos["new"][1]
    assert "WARN" not in p.stderr
    assert p.stdout.strip().splitlines()[-1].startswith("OK mirror=")


def test_primary_down_uses_fallback_and_records_it(tmp_path, repos):
    p, src, dest = run(tmp_path, repos["bad"], repos["new"][0])
    assert p.returncode == 0, p.stderr
    assert src["source"] == repos["new"][0] and src["source_role"] == "fallback" and src["records"] == "3"
    assert "WARN" in p.stderr and repos["bad"] in p.stderr
    assert f"# source: {repos['new'][0]} (fallback)" in (tmp_path / "out.manifest").read_text(encoding="utf-8")
    assert "fallback=yes" not in (dest / "SOURCE").read_text(encoding="utf-8")       # 備援來源的新資料不是「沿用舊資料」
    c = subprocess.run(["bash", str(SCRIPT), "--check", str(dest)], env=dict(os.environ, KERNEL_CVE_MIN_RECORDS="1"),
                       capture_output=True, text=True)
    assert c.returncode == 0 and c.stdout.startswith("OK "), c.stdout


def test_all_sources_down_fails_and_lists_each(tmp_path, repos):
    p, _, _ = run(tmp_path, repos["bad"], repos["bad"] + "2", extra={"KERNEL_CVE_GIT_TRIES": "1"})
    assert p.returncode == 1
    assert "所有來源都失敗（2 個" in p.stderr and repos["bad"] + "2" in p.stderr and repos["bad"] + "：" in p.stderr


def test_rounds_retry_every_source(tmp_path, repos):
    """一輪＝每個來源各試一次；試完 KERNEL_CVE_GIT_TRIES 輪才 FAIL。"""
    p, _, _ = run(tmp_path, repos["bad"], repos["bad"] + "2", extra={"KERNEL_CVE_GIT_TRIES": "2"})
    assert p.returncode == 1 and "第 1 輪都失敗" in p.stderr and "試了 2 次都失敗" in p.stderr
    assert p.stderr.count(repos["bad"] + "2：git clone 失敗") == 2


def test_empty_fallback_keeps_single_source_behaviour(tmp_path, repos):
    p, _, _ = run(tmp_path, repos["bad"], "", extra={"KERNEL_CVE_GIT_TRIES": "1"})
    assert p.returncode == 1 and "所有來源都失敗（1 個" in p.stderr


def test_fallback_older_than_current_is_refused(tmp_path, repos):
    p, _, cur = run(tmp_path, repos["new"][0], "", name="cur")
    assert p.returncode == 0, p.stderr
    p, _, nxt = run(tmp_path, repos["bad"], repos["old"][0], reuse=cur, name="next", extra={"KERNEL_CVE_GIT_TRIES": "1"})
    assert p.returncode == 1 and "比上一份" in p.stderr and "不換" in p.stderr
    assert not (tmp_path / "next.manifest").exists()


def test_fallback_older_uses_previous_copy_when_allowed(tmp_path, repos):
    """dumpling 的 KERNEL_CVE_FALLBACK_FROM：備援資料比上一份舊時沿用上一份（ATTENTION），來源照上一份記。"""
    p, cur_src, cur = run(tmp_path, repos["new"][0], "", name="cur")
    assert p.returncode == 0, p.stderr
    p, src, dest = run(tmp_path, repos["bad"], repos["old"][0], reuse=cur, name="next",
                       extra={"KERNEL_CVE_GIT_TRIES": "1", "KERNEL_CVE_FALLBACK_FROM": str(cur)})
    assert p.returncode == 0, p.stderr
    last = p.stdout.strip().splitlines()[-1]
    assert last.startswith("ATTENTION mirror=") and "比上一份" in last, last
    assert src["commit"] == repos["new"][1] and src["source"] == repos["new"][0] and src["source_role"] == "primary"
    assert src["fetched_utc"] == cur_src["fetched_utc"] and src["fallback"] == "yes"
    assert (dest / "kernel-cves.zip").read_bytes() == (cur / "kernel-cves.zip").read_bytes()


def test_primary_older_is_not_checked(tmp_path, repos):
    """主來源不做新舊檢查（上游改寫歷史時仍要能更新）。"""
    p, _, cur = run(tmp_path, repos["new"][0], "", name="cur")
    assert p.returncode == 0, p.stderr
    p, src, _ = run(tmp_path, repos["old"][0], "", reuse=cur, name="next")
    assert p.returncode == 0, p.stderr
    assert src["commit"] == repos["old"][1] and src["source_role"] == "primary"


def test_fallback_same_commit_reuses(tmp_path, repos):
    p, _, cur = run(tmp_path, repos["new"][0], "", name="cur")
    assert p.returncode == 0, p.stderr
    p, src, _ = run(tmp_path, repos["bad"], repos["new"][0], reuse=cur, name="next")
    assert p.returncode == 0, p.stderr
    assert "沿用" in p.stdout and src["source_role"] == "fallback" and src["commit"] == repos["new"][1]


@pytest.mark.parametrize("fb", ["http://example.invalid/vulns", "ssh://example.invalid/vulns", "file:///x git://example.invalid/v"])
def test_bad_fallback_scheme_rejected(tmp_path, repos, fb):
    p, _, _ = run(tmp_path, repos["new"][0], fb)
    assert p.returncode == 3 and "只接受" in p.stderr


def test_fallback_list_is_not_glob_expanded(tmp_path, repos):
    p, _, _ = run(tmp_path, repos["new"][0], "*")
    assert p.returncode == 3 and "：*" in p.stderr


@pytest.mark.parametrize("v", ["1.5", "x", "-1"])
def test_total_timeout_must_be_integer(tmp_path, repos, v):
    p, _, _ = run(tmp_path, repos["new"][0], "", extra={"KERNEL_CVE_TOTAL_TIMEOUT": v})
    assert p.returncode == 3


def test_total_timeout_exhausted_stops_trying(tmp_path, repos):
    p, _, _ = run(tmp_path, repos["new"][0], "", extra={"KERNEL_CVE_TOTAL_TIMEOUT": "5"})
    assert p.returncode == 1 and "KERNEL_CVE_TOTAL_TIMEOUT=5 秒快用完" in p.stderr


@pytest.mark.parametrize("tmo", ["30", "0.5"])
def test_small_git_timeout_still_clones(tmp_path, repos, tmo):
    """KERNEL_CVE_GIT_TIMEOUT 小於 60（含小數）時照舊用它當 clone 的上限，不會因為合計時間的檢查而不 clone。"""
    p, src, _ = run(tmp_path, repos["new"][0], "", extra={"KERNEL_CVE_GIT_TIMEOUT": tmo})
    assert p.returncode == 0, p.stderr
    assert src["source_role"] == "primary"


def test_fallback_without_previous_commit_date_warns(tmp_path, repos):
    p, _, cur = run(tmp_path, repos["new"][0], "", name="cur")
    assert p.returncode == 0, p.stderr
    s = (cur / "SOURCE").read_text(encoding="utf-8")
    (cur / "SOURCE").write_text("".join(l + "\n" for l in s.splitlines() if not l.startswith("commit_date=")), encoding="utf-8")
    p, _, _ = run(tmp_path, repos["bad"], repos["old"][0], reuse=cur, name="next")
    assert p.returncode == 0 and "沒有檢查備援資料是否比上一份舊" in p.stderr, p.stderr


def test_ls_remote_failure_skips_clone_when_more_sources(tmp_path, repos):
    """主來源 ls-remote 失敗、後面還有備援：主來源不 clone，直接換備援（不白白等 clone 逾時）。"""
    import shutil
    real = shutil.which("git")
    fake = tmp_path / "fakebin"
    fake.mkdir()
    log = tmp_path / "clones.log"
    (fake / "git").write_text(f"""#!/bin/bash
is_ls=0; is_clone=0
for a in "$@"; do case $a in ls-remote) is_ls=1;; clone) is_clone=1;; esac; done
[ "$is_clone" = 1 ] && printf '%s\\n' "$*" >> {log}
if [ "$is_ls" = 1 ]; then case $* in *{repos['bad']}*) exit 128;; esac; fi
exec {real} "$@"
""")
    (fake / "git").chmod(0o755)
    # 主來源用一個 clone 其實拿得到的庫，但 ls-remote 被擋：確認沒有對它 clone
    primary = repos["bad"]
    p, src, _ = run(tmp_path, primary, repos["new"][0], extra={"PATH": f"{fake}:{os.environ['PATH']}"})
    assert p.returncode == 0, p.stderr
    assert src["source_role"] == "fallback" and "git ls-remote 失敗" in p.stderr
    clones = log.read_text().splitlines()
    assert len(clones) == 1 and repos["new"][0] in clones[0] and primary not in clones[0]
