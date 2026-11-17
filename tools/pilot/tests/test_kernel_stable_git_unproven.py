"""K1 --stable-git：修補 commit 改的檔案「查不到」時的處理。
只有檔案名稱來自完整的核心原始碼樹（--source-tree）時，查不到才算證明沒有、才丟掉；
映像裡只有部分 headers 時（驅動自己的標頭檔不在裡面），查不到＝未證明，一律保留（只會更保守，不會多出 not_affected）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402
import test_kernel_k1_improve as t1  # noqa: E402
import test_kernel_vendor_flow as tvf  # noqa: E402

repo = t1.repo                      # fixture：空的 linux-stable clone

PRIV = "drivers/foo/foo_priv.h"


def mk(repo):
    h_priv = t1.commit(repo, [PRIV], "backport touching a driver-local header")
    h_gone = t1.commit(repo, ["drivers/foo/gone.c"], "backport touching a file this kernel does not have")
    return {"CVE-2024-9001": t1.cna("CVE-2024-9001", ["drivers/foo/a.c"], [h_priv]),
            "CVE-2024-9002": t1.cna("CVE-2024-9002", ["drivers/foo/a.c"], [h_gone])}


def go(tmp_path, recs, repo_path, *extra, src):
    mirror = t1.full_mirror(tmp_path / "gm", recs)
    f = tmp_path / "findings.json"
    f.write_text("[]")
    args = ["--stable-git", str(repo_path)] if repo_path is not None else []
    return tkc.run(tmp_path, *args, *extra, "--findings", str(f), grype_doc=t1.grype_with_urls(list(recs)), src=src, mirror=mirror)


def test_partial_headers_keep_unproven_driver_header(tmp_path, repo):
    """(a) 映像的 headers 只有部分檔案：fix commit 改的 drivers/foo/foo_priv.h 不在裡面，但不能證明這個核心沒有 → 保留，不是 not_affected。"""
    recs = mk(repo)
    assert PRIV not in str(tkc.rootfs_members())
    p, st, out = go(tmp_path, recs, repo, src=tkc.write_tar(tmp_path / "rootfs.tar", tkc.rootfs_members()))
    by = t1.by_cve(out)
    assert by["CVE-2024-9001"]["decision"] != "not_affected"
    assert by["CVE-2024-9001"]["stable_git_added_files"] == [PRIV]
    assert by["CVE-2024-9002"]["stable_git_added_files"] == ["drivers/foo/gone.c"]      # 部分 headers：這個也只是未證明，保留
    assert out["kernel"]["stable_git"]["kept_not_proven_absent"] == 2
    # 沒有 --stable-git 的對照：兩筆都是 not_affected（保留只會更保守）
    (tmp_path / "n").mkdir()
    p0, st0, base = go(tmp_path / "n", recs, None, src=tkc.write_tar(tmp_path / "n" / "rootfs.tar", tkc.rootfs_members()))
    assert {c: r["decision"] for c, r in t1.by_cve(base).items()} == {c: "not_affected" for c in recs}
    assert "stable_git" not in base["kernel"]


def test_complete_source_tree_drops_file_that_is_truly_missing(tmp_path, repo):
    """(b) 完整核心原始碼樹（--source-tree）：樹裡沒有的檔案＝證明沒有 → 丟掉（和以前一樣）；樹裡有的標頭檔照舊保留。"""
    recs = mk(repo)
    files = dict(tvf.TREE_FILES)
    files[PRIV] = "/* private */\n"
    tree = tvf.write_tree(tmp_path / "tree", files)
    p, st, out = go(tmp_path, recs, repo, "--source-tree", str(tree), src=tvf.thin_rootfs(tmp_path))
    by = t1.by_cve(out)
    assert by["CVE-2024-9001"]["decision"] == "unknown" and by["CVE-2024-9001"]["stable_git_added_files"] == [PRIV]
    assert by["CVE-2024-9002"]["decision"] == "not_affected" and "stable_git_added_files" not in by["CVE-2024-9002"]
    assert out["kernel"]["stable_git"]["kept_not_proven_absent"] == 0


def test_no_stable_git_output_has_no_new_keys(tmp_path, repo):
    """(c) 沒有 --stable-git：輸出沒有 kernel.stable_git，判定不變。"""
    recs = mk(repo)
    p, st, out = go(tmp_path, recs, None, src=tkc.write_tar(tmp_path / "rootfs.tar", tkc.rootfs_members()))
    assert "stable_git" not in out["kernel"]
    assert all(r["decision"] == "not_affected" and "stable_git_added_files" not in r for r in out["results"])


def test_helper_states():
    m = tkc.model()
    info = tkc.kc.BuildInfo({}, tkc.CONFIG, "/x/.config", tkc.KVER, {"label": "t"})
    info.tree_names = {"include/linux/foo.h"}
    assert tkc.kc.kernel_file_state(m, info, "include/linux/foo.h") == "present"
    assert tkc.kc.kernel_file_state(m, info, PRIV) == "unproven"
    info.tree_complete = True
    assert tkc.kc.kernel_file_state(m, info, PRIV) == "absent"
    info.tree_names = None                                  # 名稱超過上限：不知道
    assert tkc.kc.kernel_file_state(m, info, PRIV) == "unproven"
