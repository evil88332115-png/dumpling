"""K1（kernel_config.py）--rename-map：主線的整個檔案改名對照表，找回舊核心上的舊路徑再判斷；
tools/mirror/kernel-renames.sh 的 JSON 形狀（用測試裡建的暫時 git 倉庫）。全部用合成資料。"""
import datetime
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_config as tkc  # noqa: E402

kc = tkc.kc
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCRIPT = os.path.join(ROOT, "tools", "mirror", "kernel-renames.sh")
C1, C2, C3 = "1" * 40, "2" * 40, "3" * 40


def utc(days_ago=0):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ren(new, old, commit=C1, sim=100):
    return {"new": new, "old": old, "commit": commit, "similarity": sim}


def write_map(path, renames, days_ago=0, base="4.19", **over):
    doc = {"schema": "kernel-renames/1",
           "source": {"head_commit": "a" * 40, "head_date": "2026-11-01T00:00:00+00:00", "base_commit": "b" * 40, "base_version": base,
                      "generated_utc": utc(days_ago)},
           "count": len(renames), "renames": renames}
    doc.update(over)
    path.write_text(json.dumps(doc))
    return path


def go(tmp_path, records, rmap, *extra):
    """建置紀錄（tkc 的合成紀錄）＋ --rename-map；rmap 是 JSON 檔路徑或 None（不給參數）。"""
    mirror = tkc.make_mirror(tmp_path / "m", records=records)
    rec = tkc.write_record_dir(tmp_path / "rec", tkc.record_members())
    args = ["--build-record", str(rec)] + (["--rename-map", str(rmap)] if rmap is not None else []) + list(extra)
    return tkc.run(tmp_path, *args, grype_doc=tkc.grype(list(records)), src=tkc.br_rootfs(tmp_path), mirror=mirror)


def dec(out):
    return {r["cve"]: r["decision"] for r in out["results"]}


def res(out, cve):
    return next(r for r in out["results"] if r["cve"] == cve)


R = {"CVE-2024-3001": ["drivers/foo/new_name.c"], "CVE-2024-3002": ["drivers/foo/new_always.c"], "CVE-2024-3003": ["drivers/zz/newer.c"],
     "CVE-2024-3004": ["drivers/zz/split_b.c"], "CVE-2024-3005": ["drivers/zz/both.c"], "CVE-2024-3006": ["drivers/zz/nowhere.c"]}


def base_map(tmp_path, **kw):
    return write_map(tmp_path / "renames.json", [
        ren("drivers/foo/new_name.c", "drivers/foo/a.c", C3, 97),           # a.c：Makefile 與紀錄都沒編 → not_affected
        ren("drivers/foo/new_always.c", "drivers/foo/always.c", C2, 90),    # always.c 有編 → affected
        ren("drivers/zz/newer.c", "drivers/zz/mid.c", C3, 80),              # 兩步：newer ← mid ← a.c
        ren("drivers/zz/mid.c", "drivers/foo/a.c", C1, 100),
        ren("drivers/zz/both.c", "drivers/foo/a.c", C2),                    # 同一個新路徑有兩個舊名 → 不確定
        ren("drivers/zz/both.c", "drivers/foo/always.c", C1),
        ren("drivers/zz/split_a.c", "drivers/foo/a.c", C1),                 # 只有拆分的一份被 git 認成改名；split_b.c 不在表裡
    ], **kw)


def test_without_map_the_files_are_unknown(tmp_path):
    p, st, out = go(tmp_path, R, None)
    assert all(v == "unknown" for v in dec(out).values()), dec(out)
    assert "rename_map" not in out["kernel"] and "--rename-map" not in st[2]


def test_rename_resolves_to_not_built_and_built(tmp_path):
    p, st, out = go(tmp_path, R, base_map(tmp_path))
    assert st[1] == "OK", p.stdout + p.stderr
    d = dec(out)
    assert d["CVE-2024-3001"] == "not_affected" and d["CVE-2024-3002"] == "affected", d
    r1 = res(out, "CVE-2024-3001")
    ev = r1["files"][0]["evidence"]
    assert "renamed upstream: drivers/foo/a.c -> drivers/foo/new_name.c (commit " + C3[:12] + ", similarity 97%)" in ev and "judged as drivers/foo/a.c" in ev, ev
    assert r1["files"][0]["renamed_from"] == "drivers/foo/a.c" and r1["rename_resolved"][0]["chain"][0]["commit"] == C3[:12]
    r2 = res(out, "CVE-2024-3002")
    assert "drivers/foo/always.c" in r2["detail"] and r2["files"][0]["built"] is True


def test_two_step_chain(tmp_path):
    p, st, out = go(tmp_path, R, base_map(tmp_path))
    r = res(out, "CVE-2024-3003")
    assert r["decision"] == "not_affected", r
    ev = r["files"][0]["evidence"]
    # 舊的在前：a.c → mid.c（舊 commit）→ newer.c（新 commit）
    assert ev.index("drivers/foo/a.c -> drivers/zz/mid.c") < ev.index("drivers/zz/mid.c -> drivers/zz/newer.c"), ev
    assert [x["new"] for x in r["rename_resolved"][0]["chain"]] == ["drivers/zz/mid.c", "drivers/zz/newer.c"]


def test_split_missing_and_ambiguous_stay_unknown(tmp_path):
    p, st, out = go(tmp_path, R, base_map(tmp_path))
    d = dec(out)
    assert d["CVE-2024-3004"] == d["CVE-2024-3005"] == d["CVE-2024-3006"] == "unknown", d
    assert "a split file is not a rename" in res(out, "CVE-2024-3004")["files"][0]["evidence"]
    assert "several possible old names" in res(out, "CVE-2024-3005")["files"][0]["evidence"]
    rm = out["kernel"]["rename_map"]
    assert rm["ok"] is True and rm["files_resolved"] == 3 and rm["files_ambiguous"] == 1 and rm["files_not_resolved"] == 2, rm
    assert rm["cves_with_renamed_files"] == 3 and rm["decision_changes"] == {"unknown->affected": 1, "unknown->not_affected": 2}, rm
    assert "--rename-map renames.json" in st[2] and "3 個檔案找回舊路徑" in st[2]
    # 比較用的「沒有改名表」呼叫不計入 file_judgements：不編的檔案數與沒有表時一樣多（改名解出來的 3 個檔案另外算在一般的 built／not_built 裡）
    (tmp_path / "b").mkdir()
    base = go(tmp_path / "b", R, None)[2]
    fj, fb = out["kernel"]["build_record"]["file_judgements"], base["kernel"]["build_record"]["file_judgements"]
    assert fj["not_shown_to_exist"] == fb["not_shown_to_exist"] - 3 and fj["built"] == fb["built"] + 1, (fj, fb)


def test_target_path_that_exists_is_not_renamed(tmp_path):
    # 新路徑本身就是這個核心有的檔案：改名表不能搶走它的判斷（drivers/foo/a.c 不編 → 照舊 not_affected，也不走改名）
    recs = {"CVE-2024-3010": ["drivers/foo/a.c"]}
    m = write_map(tmp_path / "renames.json", [ren("drivers/foo/a.c", "drivers/foo/always.c")])
    p, st, out = go(tmp_path, recs, m)
    assert dec(out) == {"CVE-2024-3010": "not_affected"} and out["kernel"]["rename_map"]["files_resolved"] == 0


def test_missing_stale_unreadable_or_too_old_map_is_gap_and_changes_nothing(tmp_path):
    (tmp_path / "base").mkdir()
    base = go(tmp_path / "base", R, None)
    cases = {"missing": (tmp_path / "nope.json", "不存在"),
             "stale": (write_map(tmp_path / "stale.json", [ren("a/b.c", "a/c.c")], days_ago=200), "過期"),
             "unreadable": (tmp_path / "bad.json", "無法讀取"),
             "schema": (tmp_path / "schema.json", "格式不對"),
             "kernel-older": (write_map(tmp_path / "old.json", [ren("a/b.c", "a/c.c")], base="7.0"), "比改名對照表的起點"),
             "bad-entry": (write_map(tmp_path / "be.json", [{"new": "../x.c", "old": "y.c", "commit": C1, "similarity": 90}]), "格式不對")}
    cases["unreadable"][0].write_text("{not json")
    cases["schema"][0].write_text(json.dumps({"schema": "other", "source": {}, "renames": []}))
    for name, (path, why) in cases.items():
        d = tmp_path / name
        d.mkdir()
        p, st, out = go(d, R, path)
        rm = out["kernel"]["rename_map"]
        assert rm["ok"] is False and rm["status"] == "GAP" and why in rm["reason"], (name, rm)
        assert dec(out) == dec(base[2]) and out["counts"] == base[2]["counts"], name
        assert "不能用（GAP" in st[2], name
        assert not any("rename_resolved" in r for r in out["results"])


def test_map_needs_build_record(tmp_path):
    mirror = tkc.make_mirror(tmp_path / "m", records=R)
    m = base_map(tmp_path)
    p, st, out = tkc.run(tmp_path, "--rename-map", str(m), grype_doc=tkc.grype(list(R)), src=tkc.br_rootfs(tmp_path), mirror=mirror)
    rm = out["kernel"]["rename_map"]
    assert rm["ok"] is False and "--build-record" in rm["reason"] and all(v == "unknown" for v in dec(out).values())


def test_max_age_option(tmp_path):
    m = write_map(tmp_path / "renames.json", [ren("drivers/foo/new_name.c", "drivers/foo/a.c")], days_ago=5)
    p, st, out = go(tmp_path, R, m, "--rename-map-max-age-days", "2")
    assert out["kernel"]["rename_map"]["ok"] is False and "過期" in out["kernel"]["rename_map"]["reason"]
    (tmp_path / "x").mkdir()
    p, st, out = go(tmp_path / "x", R, m, "--rename-map-max-age-days", "10")
    assert out["kernel"]["rename_map"]["ok"] is True and dec(out)["CVE-2024-3001"] == "not_affected"


def test_chain_length_is_bounded():
    mod = kc.kernel_renames()
    n = mod.MAX_CHAIN + 3
    rs = [ren(f"p{i}.c", f"p{i + 1}.c", C1) for i in range(n)]       # p0 ← p1 ← … ← pN（新的在前）
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        m = write_map(__import__("pathlib").Path(td) / "m.json", rs)
        rm = mod.RenameMap(str(m), 60, (6, 8))
        assert rm.state["ok"], rm.state
        assert rm.resolve("p0.c", lambda q: q == f"p{n}.c")[0] == "none"
        assert rm.resolve("p0.c", lambda q: q == f"p{mod.MAX_CHAIN}.c")[0] == "found"


# ---------------------------------------------------------------------------------------------------
# kernel-renames.sh：暫時的 git 倉庫（有基準 commit、一次改名、一次拆分、一個複製）
# ---------------------------------------------------------------------------------------------------

def git(repo, *a, env=None):
    e = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org", "GIT_COMMITTER_NAME": "t",
         "GIT_COMMITTER_EMAIL": "t@example.org", **(env or {})}
    return subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", *a], check=True, capture_output=True, text=True, env=e).stdout.strip()


def make_repo(tmp_path):
    r = tmp_path / "linux.git-work"
    r.mkdir()
    git(r, "init", "-q", "-b", "master")
    body = "".join(f"int line_{i}(void) {{ return {i}; }}\n" for i in range(60))
    (r / "fs").mkdir()
    (r / "fs" / "ksmbd").mkdir()
    (r / "fs" / "ksmbd" / "smb2pdu.c").write_text(body)
    (r / "kernel").mkdir()
    (r / "kernel" / "futex.c").write_text(body.replace("line", "fx"))
    (r / "README").write_text("x\n")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "Linux 4.19")
    base = git(r, "rev-parse", "HEAD")
    (r / "fs" / "smb" / "server").mkdir(parents=True)
    git(r, "mv", "fs/ksmbd/smb2pdu.c", "fs/smb/server/smb2pdu.c")
    git(r, "commit", "-q", "-m", "move ksmbd")
    ren_commit = git(r, "rev-parse", "HEAD")
    # 拆分：futex.c 變成 futex/core.c（整個檔案移動、相似）＋新檔 futex/syscalls.c（從舊內容切出，不是改名）
    (r / "kernel" / "futex").mkdir()
    git(r, "mv", "kernel/futex.c", "kernel/futex/core.c")
    (r / "kernel" / "futex" / "syscalls.c").write_text("".join(f"int sys_{i}(void) {{ return {i}; }}\n" for i in range(30)))
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "split futex")
    (r / "README").write_text("y\n")
    git(r, "mv", "README", "README.md")                                    # 不是程式檔：不收
    git(r, "commit", "-q", "-m", "doc rename")
    return r, base, ren_commit


def run_script(*args, env=None):
    return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, env={**os.environ, "KERNEL_RENAMES_MIN_COUNT": "1", **(env or {})})


def test_mirror_script_json_shape(tmp_path):
    repo, base, ren_commit = make_repo(tmp_path)
    out = tmp_path / "o" / "renames.json"
    p = run_script(str(repo), str(out))
    assert p.returncode == 0 and "OK renames=" in p.stdout, p.stdout + p.stderr
    d = json.loads(out.read_text())
    s = d["source"]
    assert d["schema"] == "kernel-renames/1" and s["base_commit"] == base and s["base_version"] == "4.19" and s["base_subject"] == "Linux 4.19"
    assert s["head_commit"] == git(repo, "rev-parse", "HEAD") and s["head_date"] and s["generated_utc"].endswith("Z") and s["fetched"] is False
    assert s["range"] == f"{base}..{s['head_commit']}" and s["min_similarity"] == 50
    by = {e["new"]: e for e in d["renames"]}
    assert by["fs/smb/server/smb2pdu.c"] == {"new": "fs/smb/server/smb2pdu.c", "old": "fs/ksmbd/smb2pdu.c", "commit": ren_commit, "similarity": 100}
    assert by["kernel/futex/core.c"]["old"] == "kernel/futex.c"             # git 認成改名的那一份
    assert "kernel/futex/syscalls.c" not in by                               # 新檔不是改名
    assert "README.md" not in by and d["count"] == len(d["renames"]) == 2
    assert str(tmp_path) not in out.read_text()                              # 不寫本機路徑
    assert not [x for x in (tmp_path / "o").iterdir() if x.name.startswith(".")]      # 暫存資料夾已清掉
    # --check 與 kernel_config 的讀取都接受
    c = run_script("--check", str(out))
    assert c.returncode == 0 and c.stdout.startswith("OK "), c.stdout
    rm = kc.kernel_renames().RenameMap(str(out), 60, (5, 15))
    assert rm.state["ok"] and rm.resolve("fs/smb/server/smb2pdu.c", lambda q: q == "fs/ksmbd/smb2pdu.c")[0] == "found"


def test_mirror_script_refuses_bad_input_and_stale_check(tmp_path):
    repo, _, _ = make_repo(tmp_path)
    out = tmp_path / "r.json"
    p = run_script(str(repo), str(out), env={"KERNEL_RENAMES_BASE_SUBJECT": "Linux 9.9"})
    assert p.returncode != 0 and not out.exists() and "找不到" in p.stderr
    p = run_script(str(tmp_path / "nope"), str(out))
    assert p.returncode == 3 and not out.exists()
    p = run_script(str(repo), str(out), env={"KERNEL_RENAMES_MIN_COUNT": "99"})
    assert p.returncode != 0 and not out.exists()                                # 筆數太少：不寫出
    assert run_script(str(repo), str(out)).returncode == 0
    d = json.loads(out.read_text())
    d["source"]["generated_utc"] = utc(400)
    out.write_text(json.dumps(d))
    c = run_script("--check", str(out))
    assert c.returncode == 1 and "過期" in c.stdout
    d["source"]["generated_utc"] = utc(0)
    d["count"] = 7
    out.write_text(json.dumps(d))
    assert run_script("--check", str(out)).returncode == 1


def test_cna_introduced_after_kernel_keeps_precedence_over_rename():
    """CNA 紀錄說問題在比核心新的版本才出現（new_code）而且核心樹完整：檔案不在 → not_affected（原本的規則）。
    舊名存在不代表有問題的那段程式在，所以這種情況不改用改名判斷；沒有 new_code 時才用。"""
    import types
    model = types.SimpleNamespace(obj_refs=set(), obj_built=lambda o: kc.Res(None))
    rj = kc.RecordJudge({"fs/old/x.c": ("fs/old/x.o", "source")}, {}, {"fs/old/x.c"}, 0)
    rj.full_tree = True

    class M:
        stats = {"files_resolved": 0}
        def resolve(self, p, exists, quiet=False):
            assert exists("fs/old/x.c")
            return "found", [("fs/old/x.c", "fs/new/x.c", C1, 100)]
    rj.renames = M()
    r, ev = rj.judge(model, "fs/new/x.c", "fs/new/x.o", new_code="6.10")
    assert r.value is False and "introduced in 6.10" in ev and not rj.cve_renames
    # 判定不變，但證據寫明舊名存在於這個核心、為什麼仍判 not_affected，以及看不出 backport
    assert "the old name fs/old/x.c exists in this kernel (built)" in ev and "still judged not affected" in ev and "backported" in ev, ev
    assert rj.cve_skipped == [{"new": "fs/new/x.c", "old": "fs/old/x.c", "old_name": "built"}]
    r, ev = rj.judge(model, "fs/new/x.c", "fs/new/x.o", new_code=None)
    assert r.value is True and ev.startswith("renamed upstream: fs/old/x.c -> fs/new/x.c") and rj.cve_renames[0]["old"] == "fs/old/x.c"


def test_invalid_age_inputs_are_gap_not_failure(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    b = go(base, R, None)[2]
    (tmp_path / "a").mkdir(), (tmp_path / "b").mkdir(), (tmp_path / "c").mkdir()
    nz = write_map(tmp_path / "nz.json", [ren("drivers/foo/new_name.c", "drivers/foo/a.c")])
    d = json.loads(nz.read_text())
    d["source"]["generated_utc"] = "2026-11-01T00:00:00"                      # 沒有時區
    nz.write_text(json.dumps(d))
    p, st, out = go(tmp_path / "a", R, nz)
    assert p.returncode == 0 and out["kernel"]["rename_map"]["ok"] is False and "沒有時區" in out["kernel"]["rename_map"]["reason"]
    assert out["counts"] == b["counts"]
    fut = write_map(tmp_path / "fut.json", [ren("drivers/foo/new_name.c", "drivers/foo/a.c")], days_ago=-5)
    p, st, out = go(tmp_path / "b", R, fut)
    assert out["kernel"]["rename_map"]["ok"] is False and "未來" in out["kernel"]["rename_map"]["reason"] and out["counts"] == b["counts"]
    good = write_map(tmp_path / "good.json", [ren("drivers/foo/new_name.c", "drivers/foo/a.c")])
    mirror = tkc.make_mirror(tmp_path / "c" / "m", records=R)
    rec = tkc.write_record_dir(tmp_path / "c" / "rec", tkc.record_members())
    p, st, out = tkc.run(tmp_path / "c", "--build-record", str(rec), "--rename-map", str(good), grype_doc=tkc.grype(list(R)),
                         src=tkc.br_rootfs(tmp_path / "c"), mirror=mirror, env={"KERNEL_RENAME_MAP_MAX_AGE_DAYS": "abc"})
    rm = out["kernel"]["rename_map"]
    assert p.returncode == 0 and st[1] in ("OK", "ATTENTION") and rm["ok"] is False and "不是數字" in rm["reason"] and out["counts"] == b["counts"], (st, rm)


def test_same_old_name_from_two_commits_is_not_ambiguous(tmp_path):
    mod = kc.kernel_renames()
    m = write_map(tmp_path / "m.json", [ren("n.c", "o.c", C3), ren("n.c", "o.c", C1), ren("m.c", "o.c", C1), ren("m.c", "p.c", C2)])
    rm = mod.RenameMap(str(m), 60, (5, 15))
    st, chain = rm.resolve("n.c", lambda q: q == "o.c")
    assert st == "found" and chain[0][2] == C3                              # 取最新的那一筆
    assert rm.resolve("m.c", lambda q: q in ("o.c", "p.c"))[0] == "ambiguous"       # 不同的舊名才是不確定
