"""K1（kernel_config.py）減少「無法判斷」：樹外模組的建置紀錄（--oot-build-record）與本機 linux-stable（--stable-git）。
全部用合成資料（測試裡產生的假核心樹、假建置紀錄、暫時的 git 倉庫）。原則：排除一定要有證據，判斷不了就是 unknown；
每一項都附「不可以誤判成 not_affected」的反例。"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402
import test_kernel_vendor_flow as tvf  # noqa: E402

kc = tkc.kc
PY = sys.executable


# =====================================================================================================
# 樹外模組的建置紀錄
# =====================================================================================================

KDEP = "/build/kernel"                       # 建置機器上的核心樹（紀錄裡是絕對路徑）


def oot_module(root, name, deps=(), complete=True, with_mod_o=True, ko_bytes=None, build="/build/oot"):
    """root/<name>/ 底下一個 kbuild 風格的樹外模組紀錄：.<name>.o.cmd、.<name>.mod.o.cmd、.<name>.ko.cmd。"""
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    t_o, t_mod, t_ko = f"{build}/{name}/{name}.o", f"{build}/{name}/{name}.mod.o", f"{build}/{name}/{name}.ko"
    o_text = tkc.cmd_text(t_o, f"{build}/{name}/{name}.c", [f"{KDEP}/include/linux/module.h", *deps])
    if not complete:
        o_text = o_text.rsplit("\n\n$(deps_", 1)[0]                  # 被截斷：沒有結尾的兩行
    (d / f".{name}.o.cmd").write_text(o_text)
    if with_mod_o:
        (d / f".{name}.mod.o.cmd").write_text(tkc.cmd_text(t_mod, f"{build}/{name}/{name}.mod.c", [f"{KDEP}/include/linux/module.h"]))
    (d / f".{name}.ko.cmd").write_text(f"savedcmd_{t_ko} := ld -r -o {t_ko} {t_o} {t_mod}\n")
    if ko_bytes is not None:
        (d / f"{name}.ko").write_bytes(ko_bytes)
    return d


def oot_run(tmp_path, oot_names, oot_records, extra_ko=(), records=None, record_args=()):
    """映像有 updates/ 底下的樹外模組（oot_names），--oot-build-record 給 oot_records（資料夾清單）。"""
    ko = [(f"usr/lib/modules/{tkc.KVER}/updates/nv/{n}.ko", b"\x7fELF", None) for n in oot_names] + list(extra_ko)
    src = tkc.br_rootfs(tmp_path, extra=ko, name="oot.tar")
    args = []
    for r in oot_records:
        args += ["--oot-build-record", str(r)]
    mirror = tkc.make_mirror(tmp_path / "m", records=records or tkc.BR_RECORDS)
    rec = tkc.write_record_dir(tmp_path / "rec", tkc.record_members())
    return tkc.run(tmp_path, "--build-record", str(rec), *args, *record_args, grype_doc=tkc.grype(list(records or tkc.BR_RECORDS)),
                   src=src, mirror=mirror)


def by_cve(out):
    return {r["cve"]: r for r in out["results"]}


def test_oot_header_not_listed_by_any_module_is_not_built(tmp_path):
    root = tmp_path / "oot"
    oot_module(root, "foo")
    p, st, out = oot_run(tmp_path, ["foo"], [root])
    oo = out["kernel"]["build_record"]["out_of_tree_records"]
    assert oo["used"] is True and oo["image_modules"] == 1 and oo["covered"] == 1 and oo["uncovered"] == 0, oo
    assert oo["identity"] == {"srcversion": 0, "sections": 0, "sections_masked": 0, "name_only": 1} and oo["records"][0]["status"] == "OK"
    by = by_cve(out)
    # absent.h（核心 headers 有、沒有任何核心物件讀它）：樹外模組的紀錄也沒有列它 → not_affected
    d = by["CVE-2024-1003"]
    assert d["decision"] == "not_affected", d
    ev = d["files"][0]["evidence"]
    assert "nor in the deps of any of the 1 out-of-tree module(s)" in ev
    assert out["kernel"]["build_record"]["file_judgements"]["header_not_built_oot_checked"] == 2   # absent.h 與只有主機程式讀的 hostonly.h
    # 其他 CVE 不變
    assert by["CVE-2024-1002"]["decision"] == "affected" and by["CVE-2024-1001"]["decision"] == "not_affected"
    assert "樹外模組建置紀錄：採用" in st[2]


def test_oot_header_without_records_stays_unknown(tmp_path):
    p, st, out = oot_run(tmp_path, ["foo"], [])
    d = by_cve(out)["CVE-2024-1003"]
    assert d["decision"] == "unknown" and "may include it" in d["files"][0]["evidence"]
    assert "out_of_tree_records" not in out["kernel"]["build_record"]


def test_oot_header_listed_in_module_deps_is_affected_never_not_affected(tmp_path):
    root = tmp_path / "oot"
    oot_module(root, "foo", deps=[f"{KDEP}/include/linux/absent.h"])
    p, st, out = oot_run(tmp_path, ["foo"], [root])
    d = by_cve(out)["CVE-2024-1003"]
    assert d["decision"] == "affected", d
    assert "out-of-tree build record: in the deps of foo.o" in d["files"][0]["evidence"]
    assert out["kernel"]["build_record"]["file_judgements"]["header_in_out_of_tree_deps"] == 1


def test_oot_header_path_suffix_needs_a_path_boundary(tmp_path):
    mod = kc.kernel_oot_record()
    root = tmp_path / "oot"
    oot_module(root, "foo", deps=["/x/Xinclude/linux/absent.h", "/x/include/linux/absent.hh"])
    rec = mod.read_oot_record(str(root), kc)
    assert rec.error is None and mod.header_hit(rec, "include/linux/absent.h") is None
    oot_module(tmp_path / "o2", "bar", deps=["/x/include/linux/absent.h"])
    assert mod.header_hit(mod.read_oot_record(str(tmp_path / "o2"), kc), "include/linux/absent.h") == "bar.o"


def test_oot_module_without_record_keeps_header_unknown(tmp_path):
    root = tmp_path / "oot"
    oot_module(root, "foo")
    p, st, out = oot_run(tmp_path, ["foo", "bar"], [root])                 # bar.ko 在映像裡、沒有紀錄
    oo = out["kernel"]["build_record"]["out_of_tree_records"]
    assert oo["used"] is False and oo["uncovered"] == 1 and "bar.ko" in oo["reason"], oo
    d = by_cve(out)["CVE-2024-1003"]
    assert d["decision"] == "unknown" and "may include it" in d["files"][0]["evidence"]
    assert "不採用" in st[2]


@pytest.mark.parametrize("what", ["truncated", "no_mod_o", "no_ko_cmd"])
def test_oot_incomplete_records_are_not_used(tmp_path, what):
    root = tmp_path / "oot"
    oot_module(root, "foo", complete=what != "truncated", with_mod_o=what != "no_mod_o")
    if what == "no_ko_cmd":
        (root / "foo" / ".foo.ko.cmd").unlink()
    p, st, out = oot_run(tmp_path, ["foo"], [root])
    oo = out["kernel"]["build_record"]["out_of_tree_records"]
    assert oo["used"] is False and oo["reason"]
    assert by_cve(out)["CVE-2024-1003"]["decision"] == "unknown"
    if what == "truncated":
        assert oo["records"][0]["status"] == "GAP" and "truncated" in oo["records"][0]["reason"]


def test_oot_symlinks_and_oversize_are_not_followed(tmp_path, monkeypatch):
    root = tmp_path / "oot"
    oot_module(root, "foo")
    outside = tmp_path / "outside.cmd"
    outside.write_text((root / "foo" / ".foo.ko.cmd").read_text())
    (root / "foo" / ".foo.ko.cmd").unlink()
    os.symlink(outside, root / "foo" / ".foo.ko.cmd")                     # .cmd 是符號連結 → 不讀
    p, st, out = oot_run(tmp_path, ["foo"], [root])
    oo = out["kernel"]["build_record"]["out_of_tree_records"]
    assert oo["used"] is False and by_cve(out)["CVE-2024-1003"]["decision"] == "unknown"
    assert oo["records"][0]["status"] == "GAP" and "not a regular file" in oo["records"][0]["reason"]
    # 資料夾連結不走進去
    root2 = tmp_path / "oot2"
    oot_module(tmp_path / "real", "foo")
    root2.mkdir()
    os.symlink(tmp_path / "real", root2 / "linked")
    rec = kc.kernel_oot_record().read_oot_record(str(root2), kc)
    assert rec.error and rec.links == 1 and not rec.kos
    # 路徑本身是符號連結
    os.symlink(tmp_path / "real", tmp_path / "lnk")
    assert "directory" in kc.kernel_oot_record().read_oot_record(str(tmp_path / "lnk"), kc).error
    # 單一 .cmd 超過上限
    monkeypatch.setattr(kc.kernel_oot_record(), "MAX_OOT_CMD", 100)
    assert "larger than" in kc.kernel_oot_record().read_oot_record(str(tmp_path / "real"), kc).error


def test_oot_srcversion_must_match_when_both_known(tmp_path):
    root = tmp_path / "oot"
    oot_module(root, "foo", ko_bytes=tvf.fake_ko_bytes(srcversion="BBBB"))
    img = [(f"usr/lib/modules/{tkc.KVER}/updates/nv/foo.ko", tvf.fake_ko_bytes(srcversion="AAAA"), None)]
    p, st, out = oot_run(tmp_path, [], [root], extra_ko=img)
    oo = out["kernel"]["build_record"]["out_of_tree_records"]
    assert oo["used"] is False and "srcversion" in oo["reason"], oo
    assert by_cve(out)["CVE-2024-1003"]["decision"] == "unknown"
    # 相同 → 採用，identity 記 srcversion
    sub = tmp_path / "ok"
    sub.mkdir()
    root2 = sub / "oot"
    oot_module(root2, "foo", ko_bytes=tvf.fake_ko_bytes(srcversion="AAAA"))
    p, st, out = oot_run(sub, [], [root2], extra_ko=img)
    oo = out["kernel"]["build_record"]["out_of_tree_records"]
    assert oo["used"] is True and oo["identity"] == {"srcversion": 1, "sections": 0, "sections_masked": 0, "name_only": 0}
    assert by_cve(out)["CVE-2024-1003"]["decision"] == "not_affected"


def test_oot_records_need_a_usable_build_record_and_modules(tmp_path):
    root = tmp_path / "oot"
    oot_module(root, "foo")
    # --build-record なし
    p, st, out = tkc.run(tmp_path, "--oot-build-record", str(root), grype_doc=tkc.grype(list(tkc.BR_RECORDS)),
                         src=tkc.br_rootfs(tmp_path), mirror=tkc.make_mirror(tmp_path / "m", records=tkc.BR_RECORDS))
    assert out["kernel"]["build_record"]["out_of_tree_records"]["used"] is False
    assert "needs --build-record" in out["kernel"]["build_record"]["out_of_tree_records"]["reason"]
    # 映像沒有樹外模組：不需要紀錄，標頭檔照建置紀錄本來的規則
    sub = tmp_path / "s2"
    sub.mkdir()
    p, st, out = oot_run(sub, [], [root])
    oo = out["kernel"]["build_record"]["out_of_tree_records"]
    assert oo["used"] is False and "no out-of-tree module" in oo["reason"]
    assert by_cve(out)["CVE-2024-1003"]["decision"] == "not_affected"
    # 建置紀錄本身是 GAP：不使用
    sub = tmp_path / "s3"
    sub.mkdir()
    bad = tmp_path / "bad-record"
    bad.mkdir()
    ko = [(f"usr/lib/modules/{tkc.KVER}/updates/nv/foo.ko", b"\x7fELF", None)]
    p, st, out = tkc.run(sub, "--build-record", str(bad), "--oot-build-record", str(root), grype_doc=tkc.grype(list(tkc.BR_RECORDS)),
                         src=tkc.br_rootfs(sub, extra=ko), mirror=tkc.make_mirror(sub / "m", records=tkc.BR_RECORDS))
    assert out["kernel"]["build_record"]["status"] == "GAP"
    assert out["kernel"]["build_record"]["out_of_tree_records"]["used"] is False


def test_oot_no_option_output_unchanged(tmp_path):
    p, st, out = tkc.br_run(tmp_path, tkc.write_record_dir(tmp_path / "r", tkc.record_members()))
    assert "out_of_tree_records" not in out["kernel"]["build_record"] and "stable_git" not in out["kernel"]
    assert "header_in_out_of_tree_deps" not in out["kernel"]["build_record"]["file_judgements"]


# =====================================================================================================
# --stable-git：本機 linux-stable（唯讀）
# =====================================================================================================

GIT_ENV = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
           "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}


def git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env={**os.environ, **GIT_ENV}, check=True)
    return r.stdout.strip()


def commit(repo, files, msg="c"):
    for f in files:
        p = repo / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(p.read_text() + "x\n" if p.exists() else "x\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    if shutil.which("git") is None:
        pytest.fail("git is needed for these tests")
    r = tmp_path / "linux-stable"
    r.mkdir()
    git(r, "init", "-q", "-b", "linux-6.8.y")
    commit(r, ["README"], "root")
    return r


def full_mirror(d, recs):
    """recs: {cve: record dict}。"""
    d.mkdir(parents=True, exist_ok=True)
    zp = d / "kernel-cves.zip"
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
        for cve, rec in sorted(recs.items()):
            z.writestr(f"cve/published/{cve[4:8]}/{cve}.json", json.dumps(rec))
    sha = hashlib.sha256(zp.read_bytes()).hexdigest()
    (d / "SOURCE").write_text(f"source=file:///test\nfetched_utc={tkc.now()}\nzip_sha256={sha}\nzip_bytes={zp.stat().st_size}\n"
                              f"commit={'a' * 40}\ncommit_date=2026-11-01T13:42:14+01:00\nrecords={len(recs)}\nunpacked_bytes=1\n")
    return d


def cna(cve, files, fixes=()):
    versions = [{"version": "1" * 40, "lessThan": h, "status": "affected", "versionType": "git"} for h in fixes]
    aff = [{"product": "Linux", "vendor": "Linux", "defaultStatus": "unaffected", "programFiles": files, "versions": versions}]
    return {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": cve, "assignerOrgId": tkc.ORG, "state": "PUBLISHED"},
            "containers": {"cna": {"affected": aff}}}


def grype_with_urls(cves, urls=None, name="linux-nvidia-tegra"):
    g = tkc.grype(cves, name=name)
    for m in g["matches"]:
        m["vulnerability"]["urls"] = (urls or {}).get(m["vulnerability"]["id"], [])
    return g


def git_run(tmp_path, recs, cves, repo_path, urls=None, findings=None, extra=()):
    mirror = full_mirror(tmp_path / "gm", recs)
    f = tmp_path / "findings.json"
    f.write_text(json.dumps(findings or []))
    args = ["--stable-git", str(repo_path)] if repo_path is not None else []
    return tkc.run(tmp_path, *args, "--findings", str(f), grype_doc=grype_with_urls(cves, urls), src=tkc.br_rootfs(tmp_path), mirror=mirror)


def kurl(h):
    return f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={h}"


def test_backport_files_are_unioned_with_program_files(tmp_path, repo):
    """(b) mainline 的 programFiles 是沒編的 drivers/foo/a.c，但產品分支的 backport 改的是有編的 drivers/foo/always.c → 聯集後 affected。"""
    h_built = commit(repo, ["drivers/foo/always.c"], "backport touching a built file")
    h_same = commit(repo, ["drivers/foo/a.c"], "backport touching only the mainline file")
    recs = {"CVE-2024-2001": cna("CVE-2024-2001", ["drivers/foo/a.c"], [h_built]),
            "CVE-2024-2002": cna("CVE-2024-2002", ["drivers/foo/a.c"], [h_same]),
            "CVE-2024-2003": cna("CVE-2024-2003", ["drivers/foo/a.c"], ["2" * 40]),          # clone 裡沒有這個 commit
            "CVE-2024-2004": cna("CVE-2024-2004", ["drivers/foo/a.c"], [])}
    cves = list(recs)
    (tmp_path / "n").mkdir()
    p0, st0, base = git_run(tmp_path / "n", recs, cves, None)
    assert {r["cve"]: r["decision"] for r in base["results"]} == {c: "not_affected" for c in cves}
    p, st, out = git_run(tmp_path, recs, cves, repo)
    by = by_cve(out)
    assert by["CVE-2024-2001"]["decision"] == "affected" and by["CVE-2024-2001"]["files_origin"] == "cna+commits"
    assert by["CVE-2024-2001"]["stable_git_added_files"] == ["drivers/foo/always.c"]
    assert by["CVE-2024-2002"]["decision"] == "not_affected" and "stable_git_added_files" not in by["CVE-2024-2002"]
    assert by["CVE-2024-2003"]["decision"] == "not_affected" and by["CVE-2024-2004"]["decision"] == "not_affected"
    sg = out["kernel"]["stable_git"]
    assert sg["ok"] is True and sg["cves_with_added_files"] == 1 and sg["decision_changes"] == {"not_affected->affected": 1}
    assert sg["commits_resolved"] >= 2 and st[1] == "OK"
    assert "--stable-git" in st[2] and any("--stable-git" in l for l in out["limitations"])


def test_backport_added_files_must_exist_in_the_kernel_and_be_code(tmp_path, repo):
    """聯集只加「程式檔與標頭檔、而且這個核心有的檔案」：
    沒有的檔案不加（本來就不可能編進這個核心）、MAINTAINERS／Documentation 不加；有的標頭檔加進去 → unknown（標頭檔不用來宣告沒編）；
    有的、沒編的程式檔加進去 → 仍是 not_affected（記下加了哪個檔案）。"""
    h_gone = commit(repo, ["drivers/foo/renamed_away.c", "MAINTAINERS", "Documentation/x.rst", "drivers/foo/Kconfig"], "files the kernel does not have")
    h_hdr = commit(repo, ["include/linux/absent.h"], "backport also touching a header the kernel has")
    h_unbuilt = commit(repo, ["drivers/bar/baz_main.c"], "backport touching an unbuilt file that the kernel has")
    recs = {"CVE-2024-2011": cna("CVE-2024-2011", ["drivers/foo/a.c"], [h_gone]),
            "CVE-2024-2012": cna("CVE-2024-2012", ["drivers/foo/a.c"], [h_hdr]),
            "CVE-2024-2013": cna("CVE-2024-2013", ["drivers/foo/a.c"], [h_unbuilt])}
    p, st, out = git_run(tmp_path, recs, list(recs), repo)
    by = by_cve(out)
    assert by["CVE-2024-2011"]["decision"] == "not_affected" and "stable_git_added_files" not in by["CVE-2024-2011"]
    assert by["CVE-2024-2012"]["decision"] == "unknown" and by["CVE-2024-2012"]["stable_git_added_files"] == ["include/linux/absent.h"]
    assert by["CVE-2024-2013"]["decision"] == "not_affected" and by["CVE-2024-2013"]["stable_git_added_files"] == ["drivers/bar/baz_main.c"]
    assert out["kernel"]["stable_git"]["decision_changes"] == {"not_affected->unknown": 1, "not_affected->not_affected": 1}


def test_references_commits_for_cves_without_cna_record(tmp_path, repo):
    """(a) 沒有 CNA 紀錄：References 的上游 commit 都查得到才判；一個查不到就整個 unknown。"""
    h_off = commit(repo, ["drivers/foo/a.c"], "fix in an unbuilt file")
    h_on = commit(repo, ["drivers/foo/always.c"], "fix in a built file")
    h_multi_off = commit(repo, ["drivers/foo/a.c", "drivers/bar/baz_main.c"], "two unbuilt files")
    cves = ["CVE-2019-3001", "CVE-2019-3002", "CVE-2019-3003", "CVE-2019-3004", "CVE-2019-3005", "CVE-2019-3006", "CVE-2019-3007"]
    urls = {"CVE-2019-3001": [kurl(h_off)],
            "CVE-2019-3002": [kurl(h_on)],
            "CVE-2019-3003": [kurl(h_off), kurl("3" * 40)],                                # 其中一個 commit 不在 clone → unknown
            "CVE-2019-3004": [f"https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble/commit/?id={h_off}"],   # 不是上游
            "CVE-2019-3005": [f"https://git.kernel.org/stable/c/{h_multi_off[:12]}", f"https://github.com/torvalds/linux/commit/{h_off}"],
            "CVE-2019-3006": [],
            "CVE-2019-3007": [f"https://github.com/someone/linux/commit/{h_off}"]}        # 個人 fork：不認
    # CNA 鏡像要有至少一筆紀錄（Mirror 才有 zip）：放一筆無關的
    recs = {"CVE-2024-9999": cna("CVE-2024-9999", ["drivers/foo/a.c"])}
    p, st, out = git_run(tmp_path, recs, cves, repo, urls=urls)
    by = by_cve(out)
    assert by["CVE-2019-3001"]["decision"] == "not_affected" and by["CVE-2019-3001"]["files_origin"] == "commits-from-references"
    assert by["CVE-2019-3001"]["stable_git_commits"] == [h_off[:12]]
    assert "no CNA record; commits from references" in by["CVE-2019-3001"]["detail"]
    assert by["CVE-2019-3002"]["decision"] == "affected"
    for c in ("CVE-2019-3003", "CVE-2019-3004", "CVE-2019-3006", "CVE-2019-3007"):
        assert by[c]["decision"] == "unknown" and by[c]["detail"] == "no Linux kernel CNA record in the mirror", c
    assert by["CVE-2019-3005"]["decision"] == "not_affected" and by["CVE-2019-3005"]["stable_git_commits"] == [h_multi_off[:12], h_off[:12]]
    sg = out["kernel"]["stable_git"]
    assert sg["cves_from_references_only"] == 3 and sg["decision_changes"] == {"unknown->affected": 1, "unknown->not_affected": 2}


def test_references_from_dt_findings_text(tmp_path, repo):
    h = commit(repo, ["drivers/foo/a.c"], "fix")
    f = [{"component": {"name": "linux-nvidia-tegra", "version": "6.8.0-1021.21", "purl": tkc.TEGRA["purl"]},
          "vulnerability": {"source": "OSV", "vulnId": "CVE-2019-3101", "aliases": [],
                            "references": f"* [x]({kurl(h)})\n* [y](https://example.org/{h})\n"}}]
    recs = {"CVE-2024-9999": cna("CVE-2024-9999", ["drivers/foo/a.c"])}
    p, st, out = git_run(tmp_path, recs, ["CVE-2019-3101"], repo, findings=f)
    assert by_cve(out)["CVE-2019-3101"]["decision"] == "not_affected"


def test_stable_git_unusable_changes_nothing(tmp_path, repo):
    recs = {"CVE-2024-2021": cna("CVE-2024-2021", ["drivers/foo/a.c"], ["4" * 40])}
    (tmp_path / "a").mkdir()
    base = git_run(tmp_path / "a", recs, list(recs), None)
    p, st, out = git_run(tmp_path, recs, list(recs), tmp_path / "not-a-repo")
    assert out["kernel"]["stable_git"]["ok"] is False and out["kernel"]["stable_git"]["reason"]
    assert out["counts"] == base[2]["counts"] and p.returncode == 0
    assert "不能用" in st[2]
    # 符號連結的 clone 不收
    os.symlink(repo, tmp_path / "lnk")
    assert kc.kernel_git_files().StableGit(str(tmp_path / "lnk")).ok is False


def test_git_module_is_read_only_and_strict(tmp_path, repo):
    gf = kc.kernel_git_files()
    before = subprocess.run(["find", str(repo), "-type", "f", "-newer", str(repo / ".git" / "HEAD")], capture_output=True, text=True).stdout
    h = commit(repo, ["drivers/foo/ok.c"], "ok")
    (repo / "weird name.c").write_text("x")                                           # 有空白的檔名：整個 commit 不用
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "weird")
    hw = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-q", "-b", "side", h)
    hs = commit(repo, ["side.c"], "side")
    git(repo, "checkout", "-q", "linux-6.8.y")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
    hm = git(repo, "rev-parse", "HEAD")
    s = gf.StableGit(str(repo))
    got = s.files([h, hw, hm, hs, h[:10], "0" * 40, "zz"])
    assert got[h] == ["drivers/foo/ok.c"] and got[h[:10]] == ["drivers/foo/ok.c"] and got[hs] == ["side.c"]
    assert got[hw] is None and got[hm] is None and got["0" * 40] is None and got["zz"] is None
    assert gf.commit_hashes_in_text(f"{kurl(h)}\nhttps://git.kernel.org/stable/c/{h[:12]}\nhttps://git.kernel.org/linus/{h}\n"
                                    f"https://github.com/torvalds/linux/commit/{h}\nhttps://example.org/{h}\nhttps://git.kernel.org/x/{h}") == [h, h[:12]]
    # 沒有被改：不寫入（HEAD、refs 的內容不因為查詢而變）
    assert git(repo, "rev-parse", "HEAD") == hm and "weird" not in before


def test_sca_scan_and_flash_package_wiring():
    s = (tkc.PILOT / "sca-scan").read_text(encoding="utf-8")
    assert 'KSRC+=(--source-tree "$(readlink -m -- "$KERNEL_SOURCE_DIR")")' in s
    # 追加的選項：環境變數給 kernel_config.py（--oot-build-record 可重複、--stable-git）
    assert 'KERNEL_OOT_BUILD_RECORDS' in s and '--oot-build-record' in s and 'KERNEL_STABLE_GIT' in s and '--stable-git' in s
    fp = (tkc.ROOT / "tools" / "demo" / "scan-flash-package.sh").read_text(encoding="utf-8")
    # 完整掃描（Jetson）也把刷機包交給 C-kernel-config：才讀得到燒錄的 kernel/Image
    assert 'elif [ ${#SRC[@]} -gt 0 ]; then kb=(--kernel-build "${ARCHIVE:-$SRCDIR}" --kernel-build-prefix "$prefix"); fi' in fp
    assert "--kernel-source)" in fp and "KERNEL_SOURCE_DIR" in fp
