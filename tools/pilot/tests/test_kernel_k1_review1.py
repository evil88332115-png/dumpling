"""PR #185 第 1 輪審查的修正：clone 的設定不可執行程式、樹外模組的 srcversion 核對不可被繞過、短雜湊至少 12 位。"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402
import test_kernel_k1_improve as t1  # noqa: E402
import test_kernel_vendor_flow as tvf  # noqa: E402

kc = tkc.kc
repo = t1.repo
IMG = [(f"usr/lib/modules/{tkc.KVER}/updates/nv/foo.ko", tvf.fake_ko_bytes(srcversion="AAAA"), None)]


def test_signature_and_external_programs_in_clone_config_do_not_run(tmp_path, repo):
    marker = tmp_path / "ran"
    prog = tmp_path / "evil.sh"
    prog.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n")
    prog.chmod(0o755)
    h = t1.commit(repo, ["drivers/foo/ok.c"], "ok")
    # 帶 gpgsig 標頭的 commit（內容不必是真的簽章）
    body = t1.git(repo, "cat-file", "commit", h)
    head, msg = body.split("\n\n", 1)
    sig = "gpgsig -----BEGIN PGP SIGNATURE-----\n \n abcd\n -----END PGP SIGNATURE-----"
    new = subprocess.run(["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"], input=head + "\n" + sig + "\n\n" + msg,
                         capture_output=True, text=True, check=True, env={**os.environ, **t1.GIT_ENV}).stdout.strip()
    for k, v in (("log.showSignature", "true"), ("gpg.program", str(prog)), ("gpg.ssh.program", str(prog)), ("gpg.x509.program", str(prog)),
                 ("core.pager", str(prog)), ("diff.external", str(prog)), ("core.fsmonitor", str(prog)), ("core.hooksPath", str(tmp_path)),
                 ("log.decorate", "full"), ("format.pretty", "oneline")):
        t1.git(repo, "config", k, v)
    got = kc.kernel_git_files().StableGit(str(repo)).files([new])
    assert got[new] == ["drivers/foo/ok.c"]
    assert not marker.exists()


def test_short_hashes_need_12_digits():
    gf = kc.kernel_git_files()
    h = "0123456789abcdef0123456789abcdef01234567"
    assert gf.commit_hashes_in_text(f"https://git.kernel.org/stable/c/{h[:12]}") == [h[:12]]
    for n in (7, 10, 11):
        assert gf.commit_hashes_in_text(f"https://git.kernel.org/stable/c/{h[:n]}\nhttps://github.com/torvalds/linux/commit/{h[:n]}") == []


def oot_case(tmp_path, roots, extra_ko=IMG):
    return t1.oot_run(tmp_path, [], roots, extra_ko=extra_ko)


def check_unused(out):
    oo = out["kernel"]["build_record"]["out_of_tree_records"]
    assert oo["used"] is False and oo["uncovered"] == 1, oo
    assert t1.by_cve(out)["CVE-2024-1003"]["decision"] == "unknown"


def test_oot_truncated_record_ko_is_not_name_only(tmp_path):
    root = tmp_path / "oot"
    t1.oot_module(root, "foo", ko_bytes=tvf.fake_ko_bytes(srcversion="AAAA")[:70])        # 被截斷
    check_unused(oot_case(tmp_path, [root])[2])


def test_oot_symlinked_record_ko_is_not_name_only(tmp_path):
    root = tmp_path / "oot"
    t1.oot_module(root, "foo")
    real = tmp_path / "real.ko"
    real.write_bytes(tvf.fake_ko_bytes(srcversion="AAAA"))
    os.symlink(real, root / "foo" / "foo.ko")
    check_unused(oot_case(tmp_path, [root])[2])


def test_oot_one_mismatching_candidate_rejects_the_module_even_with_a_cmd_only_record(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    t1.oot_module(a, "foo", ko_bytes=tvf.fake_ko_bytes(srcversion="BBBB"))                # 有 .ko 但 srcversion 不符
    t1.oot_module(b, "foo")                                                                 # 只有 .cmd
    check_unused(oot_case(tmp_path, [a, b])[2])
    # 順序相反也一樣
    sub = tmp_path / "r"
    sub.mkdir()
    a2, b2 = sub / "a", sub / "b"
    t1.oot_module(a2, "foo", ko_bytes=tvf.fake_ko_bytes(srcversion="BBBB"))
    t1.oot_module(b2, "foo")
    check_unused(oot_case(sub, [b2, a2])[2])


def test_oot_record_ko_present_but_image_srcversion_unreadable_is_not_verified(tmp_path):
    root = tmp_path / "oot"
    t1.oot_module(root, "foo", ko_bytes=tvf.fake_ko_bytes(srcversion="AAAA"))
    junk = [(f"usr/lib/modules/{tkc.KVER}/updates/nv/foo.ko", b"\x7fELF", None)]
    check_unused(oot_case(tmp_path, [root], extra_ko=junk)[2])


def test_oot_matching_srcversion_still_works(tmp_path):
    root = tmp_path / "oot"
    t1.oot_module(root, "foo", ko_bytes=tvf.fake_ko_bytes(srcversion="AAAA"))
    out = oot_case(tmp_path, [root])[2]
    assert out["kernel"]["build_record"]["out_of_tree_records"]["used"] is True
    assert t1.by_cve(out)["CVE-2024-1003"]["decision"] == "not_affected"
