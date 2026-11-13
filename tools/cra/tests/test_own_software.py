"""own_software.py 的測試：設定 sbom.own_software 列出的自有軟體 → own-software.json → 產品 SBOM 的 pkg:generic 元件
（合成的小型 rootfs，不用任何產品資料）。"""
import datetime
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import cra_report as cr  # noqa: E402
import own_software as ow  # noqa: E402
from test_cra_report import EXAMPLE, MIN_CFG, make_project, make_scan, run, write_json  # noqa: E402
from test_firmware_bom import INV, MODINFO, SBOM, cdx_validator, elf, flash_result  # noqa: E402

CLI = HERE.parent / "own_software.py"
ELF_BIN = b"\x7fELF\x02\x01\x01" + b"\0" * 57 + b"binary"
CFG = dict(MIN_CFG, manufacturer={"name": "Example Co.", "website": "https://www.example.com"})


def sha(b):
    return hashlib.sha256(b).hexdigest()


def tar_of(path, members):
    """members：(名稱, 內容 bytes) 或 (名稱, ("sym"|"hard", 目標)) 或 (名稱, None)＝資料夾。"""
    with tarfile.open(path, "w") as t:
        for name, x in members:
            ti = tarfile.TarInfo(name)
            if x is None:
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            elif isinstance(x, tuple):
                ti.type, ti.linkname = (tarfile.SYMTYPE if x[0] == "sym" else tarfile.LNKTYPE), x[1]
                t.addfile(ti)
            else:
                ti.size = len(x)
                t.addfile(ti, io.BytesIO(x))
    return path


ROOTFS = [
    ("usr", None), ("usr/bin", None), ("bin", ("sym", "usr/bin")),
    ("usr/bin/acme-agent", ELF_BIN),
    ("usr/bin/other-tool", b"#!/bin/sh\necho not ours\n"),
    ("opt/acme/bin/zeta.sh", b"#!/bin/sh\necho zeta\n"),
    ("opt/acme/bin/alpha", ELF_BIN + b"alpha"),
    ("opt/acme/bin/libacme.so.1", ELF_BIN + b"lib"),
    ("opt/acme/bin/.hidden", b"hidden"),
    ("opt/acme/bin/sub", None),
    ("opt/acme/bin/sub/inner", b"inner"),
    ("usr/lib/modules/6.8.0/extra/acme_drv.ko", elf(MODINFO.replace(b"name=nvgpu", b"name=acme_drv"))),
    ("usr/lib/modules/6.8.0/extra/acme_nover.ko", elf(b"license=GPL\0name=acme_nover\0")),
    ("lib", ("sym", "usr/lib")),
]


def cfg_with(own, base=CFG):
    return dict(base, sbom={"own_software": own})


def write_cfg(tmp_path, own, base=CFG):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(cfg_with(own, base)), encoding="utf-8")
    return p


def cli(*args):
    return subprocess.run([sys.executable, "-I", str(CLI), *map(str, args)], capture_output=True, text=True, timeout=60)


def collect(tmp_path, own, members=ROOTFS, name="r.tar", extra=()):
    src = tar_of(tmp_path / name, members)
    p = cli("--from", src, "--config", write_cfg(tmp_path, own), "--out", tmp_path / "out", *extra)
    doc = json.loads((tmp_path / "out" / "own-software.json").read_text()) if (tmp_path / "out" / "own-software.json").exists() else None
    return p, doc


def files(doc):
    return {f["path"]: f for f in doc["files"]}


# ---------- 設定 ----------

def test_config_entries_and_errors():
    es, errs = ow.entries(cfg_with(["/usr/bin/x", {"path": "opt//./a/*", "version": " 1.0 "}, "../etc/x", "a/**/b", "", "/",
                                    {"path": "usr/bin/x", "version": "2"}]))
    assert [e["pattern"] for e in es] == ["usr/bin/x", "opt/a/*"]
    assert es[1]["version"] == "1.0" and es[0]["version"] == "2"
    assert len(errs) == 4 and any(".." in e for e in errs) and any("**" in e for e in errs)
    assert not ow.configured(MIN_CFG) and not ow.configured(cfg_with([])) and ow.configured(cfg_with(["a"]))


def test_example_config_documents_own_software():
    """config.example.json 的 own_software 符合 schema（jsonschema 與內建的小型驗證器）。"""
    ex = json.loads((HERE.parent / "config.example.json").read_text(encoding="utf-8"))
    assert ow.configured(ex) and not ow.entries(ex)[1]
    errors, warnings = cr.validate(ex)
    assert not errors and not warnings
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(ex, cr.SCHEMA)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(dict(ex, sbom={"own_software": [{"name": "no path"}]}), cr.SCHEMA)
    assert "own_software" not in str(cr.report_fields(ex).keys())         # 不是報告欄位：沒寫時不算缺


# ---------- 讀 rootfs ----------

def test_glob_matches_several_files(tmp_path):
    p, doc = collect(tmp_path, ["/opt/acme/bin/*"])
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.startswith("B-own-software\tOK\t")
    f = files(doc)
    # . 開頭的名稱不對到萬用字元；子資料夾不是檔案，略過（不算 GAP）
    assert sorted(f) == ["opt/acme/bin/alpha", "opt/acme/bin/libacme.so.1", "opt/acme/bin/zeta.sh"]
    assert f["opt/acme/bin/zeta.sh"]["sha256"] == sha(b"#!/bin/sh\necho zeta\n") and f["opt/acme/bin/alpha"]["elf"] is True
    assert doc["patterns"] == [{"pattern": "opt/acme/bin/*", "matched": 3, "status": "OK", "reasons": []}]
    assert doc["second_read"] is False


def test_missing_path_is_gap(tmp_path):
    p, doc = collect(tmp_path, ["/usr/bin/acme-agent", "/usr/bin/not-there", "/opt/none/*"])
    assert p.returncode == 2
    lines = p.stdout.splitlines()
    assert lines[0].startswith("B-own-software\tGAP\t")
    assert "GAP\tusr/bin/not-there\tlisted but not found: no file in the root file system matches" in lines
    assert any(x.startswith("GAP\topt/none/*\t") for x in lines)
    st = {x["pattern"]: x["status"] for x in doc["patterns"]}
    assert st == {"usr/bin/acme-agent": "OK", "usr/bin/not-there": "GAP", "opt/none/*": "GAP"} and doc["status"] == "GAP"


def test_symlinks_resolved_inside_the_image(tmp_path):
    """bin → usr/bin（合併 /usr）：列出的路徑經過符號連結 → 實際的檔案（第二次讀取 tar 才取到內容）；同一個檔案只算一次。"""
    p, doc = collect(tmp_path, ["/bin/acme-agent", "/usr/bin/acme-agent", "/lib/modules/*/extra/acme_*.ko"])
    assert p.returncode == 0, p.stdout
    f = files(doc)
    assert sorted(f) == ["usr/bin/acme-agent", "usr/lib/modules/6.8.0/extra/acme_drv.ko", "usr/lib/modules/6.8.0/extra/acme_nover.ko"]
    assert f["usr/bin/acme-agent"]["listed_as"] == ["bin/acme-agent", "usr/bin/acme-agent"]
    assert f["usr/bin/acme-agent"]["patterns"] == ["bin/acme-agent", "usr/bin/acme-agent"]
    assert f["usr/lib/modules/6.8.0/extra/acme_drv.ko"]["modinfo"]["version"] == "1.2.3"
    assert doc["second_read"] is True


def make_dir(root, members):
    for name, x in members:
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if x is None:
            p.mkdir(exist_ok=True)
        elif isinstance(x, tuple):
            p.symlink_to(x[1])
        else:
            p.write_bytes(x)
    return root


def test_dir_source_second_read_through_symlink(tmp_path):
    """資料夾來源：經過符號連結才對到的檔案，從 rootfs 一層一層 openat（O_NOFOLLOW）讀；結果和 tar 來源相同。"""
    own = ["/bin/acme-agent", "/lib/modules/*/extra/acme_drv.ko"]
    root = make_dir(tmp_path / "rootfs", ROOTFS)
    p = cli("--from", root, "--config", write_cfg(tmp_path, own), "--out", tmp_path / "o-dir")
    assert p.returncode == 0, p.stdout + p.stderr
    d = json.loads((tmp_path / "o-dir" / "own-software.json").read_text())
    t = tmp_path / "t"
    t.mkdir()
    _, dt = collect(t, own)
    assert d["second_read"] is True and d["files"] == dt["files"]
    assert files(d)["usr/bin/acme-agent"]["sha256"] == sha(ELF_BIN)
    # 讀的時候中間層被換成指到 rootfs 外的符號連結：openat 的 O_NOFOLLOW 擋下來（不讀到外面的檔案）
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "acme-agent").write_bytes(b"outside")
    (root / "usr" / "bin").rename(root / "usr" / "bin.real")
    (root / "usr" / "bin").symlink_to(tmp_path / "outside")
    with pytest.raises(OSError):
        ow.open_under(str(root), "usr/bin/acme-agent")


def test_dir_source_swapped_during_walk_not_read(tmp_path, monkeypatch):
    """走訪（lstat）之後、讀取之前，中間層被換成指到 rootfs 外的符號連結：第一次讀取也用 open_under（每層 O_NOFOLLOW），
    讀不到外面的檔案，記 GAP。（反例：以前第一次讀取用 image_check.iter_dir 的 opener，只有最後一層 O_NOFOLLOW。）"""
    root = make_dir(tmp_path / "rootfs", [("usr/bin/agent", b"inside")])
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "agent").write_bytes(b"HOST FILE OUTSIDE ROOTFS")
    fp = ow.icmod().flash_package()
    orig = fp.dir_entries

    def racing(base):
        for e in orig(base):
            if e.parts == ("usr", "bin", "agent"):
                os.rename(root / "usr" / "bin", root / "usr" / "bin.real")
                os.symlink(tmp_path / "outside", root / "usr" / "bin")
            yield e
    monkeypatch.setattr(fp, "dir_entries", racing)
    monkeypatch.setattr(ow.icmod(), "flash_package", lambda: fp)     # image_check.flash_package() 每次載入新的模組
    doc = ow.collect(str(root), None, ow.entries(cfg_with(["/usr/bin/agent"]))[0])
    assert doc["status"] == "GAP" and doc["files"] == []
    assert doc["problems"][0]["path"] == "usr/bin/agent" and "unreadable" in doc["problems"][0]["reason"]
    assert sha(b"HOST FILE OUTSIDE ROOTFS") not in json.dumps(doc)


def test_open_under_checks_identity(tmp_path):
    """open_under 用 fstat 的 (st_dev, st_ino, st_size) 和走訪時的 lstat 比對：檔案被換掉（另一個 inode）→ 不讀。"""
    root = make_dir(tmp_path / "rootfs", [("usr/bin/agent", b"inside")])
    st = os.lstat(root / "usr" / "bin" / "agent")
    ident = (st.st_dev, st.st_ino, st.st_size)
    with ow.open_under(str(root), "usr/bin/agent", ident) as f:
        assert f.read() == b"inside"
    (root / "usr" / "bin" / "new").write_bytes(b"swapped")
    os.replace(root / "usr" / "bin" / "new", root / "usr" / "bin" / "agent")
    with pytest.raises(ow.Changed):
        ow.open_under(str(root), "usr/bin/agent", ident)
    r = ow.Reading(1 << 20, 1 << 30).digest("usr/bin/agent", 6, lambda: ow.open_under(str(root), "usr/bin/agent", ident))
    assert "file changed between the directory walk and the read" in r["error"]


def test_dir_source_hard_links_are_one_file(tmp_path):
    """資料夾來源的硬連結依 (st_dev, st_ino) 合併成一個檔案，和 tar 來源一樣（反例：以前資料夾來源算成兩個元件）。"""
    root = make_dir(tmp_path / "rootfs", [("opt/acme/tool", b"tool")])
    (root / "usr" / "bin").mkdir(parents=True)
    os.link(root / "opt" / "acme" / "tool", root / "usr" / "bin" / "tool-link")
    own = ["/usr/bin/tool-link", "/opt/acme/tool"]
    p = cli("--from", root, "--config", write_cfg(tmp_path, own), "--out", tmp_path / "o-dir")
    dd = json.loads((tmp_path / "o-dir" / "own-software.json").read_text())
    t = tmp_path / "t"
    t.mkdir()
    _, dt = collect(t, own, [("opt/acme/tool", b"tool"), ("usr/bin/tool-link", ("hard", "opt/acme/tool"))])
    assert p.returncode == 0, p.stdout
    assert [(f["path"], f.get("hard_links")) for f in dd["files"]] == [("opt/acme/tool", ["usr/bin/tool-link"])]
    assert dd["files"] == dt["files"]
    assert len(ow.build(dd, cfg_with(own), "1.6")[0]) == len(ow.build(dt, cfg_with(own), "1.6")[0]) == 1


@pytest.mark.parametrize("own", [["/lib/modules/*/extra/example.ko"], ["/usr/lib/modules/*/extra/example.ko"]])
def test_merged_usr_glob_not_a_false_gap(tmp_path, own):
    """合併 /usr（lib → usr/lib）：穿過有效連結之後才缺的層（6.8.1 沒有 extra/）是一般的找不到，不是「連結目標不存在」，
    不算 GAP（反例：以前跟過一次連結之後缺任何一層都報連結目標不存在）。"""
    m = [("lib", ("sym", "usr/lib")), ("usr/lib/modules/6.8.0/extra/example.ko", b"\x7fELFko"), ("usr/lib/modules/6.8.1/kernel/x.ko", b"k")]
    p, doc = collect(tmp_path, own, m)
    assert p.returncode == 0 and doc["status"] == "OK" and doc["problems"] == [], p.stdout
    assert [f["path"] for f in doc["files"]] == ["usr/lib/modules/6.8.0/extra/example.ko"]


def test_glob_through_directory_links(tmp_path):
    """萬用字元對到指向資料夾的有效連結、裡面沒有那個檔案 → 略過；指不到東西的連結在中間層 → 略過；
    逃出 rootfs 的連結照樣記 GAP；列出的名稱本身是指不到東西的連結 → 記原因。"""
    m = [("opt/acme/bin/tool", b"a"), ("var/lib/data/x", b"x"), ("opt/data", ("sym", "/var/lib/data")), ("opt/plain/readme", b"r"),
         ("opt/dang", ("sym", "/nonexist"))]
    p, doc = collect(tmp_path, ["/opt/*/bin/tool"], m)
    assert p.returncode == 0 and doc["problems"] == [] and [f["path"] for f in doc["files"]] == ["opt/acme/bin/tool"], p.stdout
    (tmp_path / "x").mkdir()
    p, doc = collect(tmp_path / "x", ["/opt/*/bin/tool"], m + [("opt/evil", ("sym", "../../.."))])
    assert p.returncode == 2 and [x["reason"] for x in doc["problems"]] == [
        "symbolic link points outside the root file system (.. above /): rejected"]
    (tmp_path / "y").mkdir()
    p, doc = collect(tmp_path / "y", ["/opt/dang", "/opt/data/missing"], m)
    pr = {x["pattern"]: x for x in doc["patterns"]}
    assert pr["opt/dang"]["reasons"] == ["opt/dang: symbolic link target not in the root file system"]
    assert pr["opt/data/missing"]["reasons"] == ["listed but not found: no file in the root file system matches"]


@pytest.mark.parametrize("extra", [[("opt/README.txt", b"readme")], [("opt/loop", ("sym", "loop"))],
                                   [("opt/dir-link", ("sym", "/var/empty")), ("var/empty/x", b"x")]])
def test_glob_middle_level_keeps_only_directories(tmp_path, extra):
    """中間層的萬用字元只留解析後是資料夾的候選：/opt/*/bin/tool 遇到 /opt/README.txt（檔案）或 /opt/loop → loop（迴圈）
    不是 GAP（反例 e24、e26：以前會報「不是資料夾」或「連結迴圈」）。"""
    p, doc = collect(tmp_path, ["/opt/*/bin/tool", "/opt/*/bin/*"], [("opt/acme/bin/tool", b"a")] + extra)
    assert p.returncode == 0 and doc["status"] == "OK" and doc["problems"] == [], p.stdout
    assert [f["path"] for f in doc["files"]] == ["opt/acme/bin/tool"]


def test_literal_level_problems_still_reported(tmp_path):
    """字面寫出的那一層不是資料夾、或是連結迴圈 → 照樣記原因（GAP）。"""
    m = [("opt/acme/bin/tool", b"a"), ("opt/README.txt", b"readme"), ("opt/loop", ("sym", "loop"))]
    p, doc = collect(tmp_path, ["/opt/README.txt/bin/tool", "/opt/loop/bin/tool", "/opt/README.txt/*"], m)
    pr = {x["pattern"]: x["reasons"] for x in doc["patterns"]}
    assert pr["opt/README.txt/bin/tool"] == ["opt/README.txt/bin/tool: a path component is not a directory"]
    assert pr["opt/loop/bin/tool"] == ["opt/loop/bin/tool: too many symbolic links (loop?)"]
    assert pr["opt/README.txt/*"] == ["opt/README.txt: a path component is not a directory"]


def hard_case(tmp_path, members, own, name="a.tar"):
    p, doc = collect(tmp_path, own, members, name=name)
    return p, doc, {f["path"]: f for f in doc["files"]}


@pytest.mark.parametrize("own,path,content", [(["/usr/bin/link"], "usr/bin/link", b"v1 at link time"),
                                              (["/opt/tool"], "opt/tool", b"v2 later!!")])
def test_hard_link_target_redefined_later(tmp_path, own, path, content):
    """rootfs 內的硬連結，目標在硬連結之後被重新定義：硬連結的內容是硬連結之前那一份（GNU tar 解開後也是 v1），
    不合併到目標（反例 e22 A：以前硬連結合併到最後一個 opt/tool，拿到 v2）。"""
    m = [("opt/tool", b"v1 at link time"), ("usr/bin/link", ("hard", "opt/tool")), ("opt/tool", b"v2 later!!")]
    p, doc, f = hard_case(tmp_path, m, own)
    assert p.returncode == 0, p.stdout
    if shutil.which("tar"):           # 和 GNU tar 解開的結果對照（只解開這個合成的小 tar，在測試的暫存資料夾裡）
        x = tmp_path / "x"
        x.mkdir()
        subprocess.run(["tar", "-xf", str(tmp_path / "a.tar"), "-C", str(x)], check=True)
        assert (x / path).read_bytes() == content
    assert list(f) == [path] and f[path]["sha256"] == sha(content)
    if path == "usr/bin/link":
        assert f[path]["hardlink_of"] == "opt/tool" and doc["second_read"] is True
    # 兩個都列：兩個元件、兩份內容
    (tmp_path / "both").mkdir()
    _, _, f2 = hard_case(tmp_path / "both", m, ["/usr/bin/link", "/opt/tool"])
    assert {k: v["sha256"] for k, v in f2.items()} == {"usr/bin/link": sha(b"v1 at link time"), "opt/tool": sha(b"v2 later!!")}


def test_hard_link_target_later_replaced_by_symlink(tmp_path):
    """反向：目標在硬連結之後被換成符號連結 → 硬連結照樣是那個一般檔案的內容，不是 GAP。"""
    m = [("opt/tool", b"real tool"), ("usr/bin/link", ("hard", "opt/tool")), ("opt/tool", ("sym", "/elsewhere"))]
    p, doc, f = hard_case(tmp_path, m, ["/usr/bin/link"])
    assert p.returncode == 0 and doc["problems"] == [], p.stdout
    assert f["usr/bin/link"]["sha256"] == sha(b"real tool")


def test_hard_link_to_a_symlink_is_gap(tmp_path):
    """硬連結之前目標已經是符號連結（硬連結到符號連結本身）→ 不是一般檔案，GAP。"""
    m = [("opt/tool", ("sym", "x")), ("usr/bin/link", ("hard", "opt/tool"))]
    p, doc, f = hard_case(tmp_path, m, ["/usr/bin/link"])
    assert p.returncode == 2 and f == {} and "not a regular file" in doc["problems"][0]["reason"]


def test_hard_link_outside_rootfs_last_occurrence_not_a_file(tmp_path):
    """rootfs 外的硬連結：目標名稱在硬連結之前最後一次是符號連結（更早有一個一般檔案）→ GAP，不拿更早的那個檔案
    （反例 e22 B）。最後一次是一般檔案 → 用那一份。"""
    pre, oth = "P/rootfs_gui", "P/rootfs_no_gui"
    for label, members, ok in (
            ("sym-last", [(f"{oth}/usr/bin/agent", b"old file"), (f"{oth}/usr/bin/agent", ("sym", "elsewhere"))], False),
            ("file-last", [(f"{oth}/usr/bin/agent", ("sym", "elsewhere")), (f"{oth}/usr/bin/agent", b"new file")], True)):
        src = tar_of(tmp_path / f"{label}.tar", members + [(f"{pre}/usr/bin/agent", ("hard", f"{oth}/usr/bin/agent")),
                                                           (f"{oth}/usr/bin/agent", b"after the link")])
        out = tmp_path / f"o-{label}"
        p = cli("--from", src, "--prefix", pre, "--config", write_cfg(tmp_path, ["/usr/bin/agent"]), "--out", out)
        doc = json.loads((out / "own-software.json").read_text())
        if ok:
            assert p.returncode == 0 and files(doc)["usr/bin/agent"]["sha256"] == sha(b"new file"), p.stdout
        else:
            assert p.returncode == 2 and doc["files"] == [], p.stdout
            assert doc["problems"][0]["reason"] == "the hard link's target is a symlink at that point of the archive (not a regular file)"


def test_same_size_rewrite_detected_by_ctime(tmp_path, monkeypatch):
    """第二次讀取前，tar 被原地改寫成同樣大小、mtime 也改回去：source_id 含 st_ctime_ns，照樣看得出來 → GAP（反例 e2n）。
    （同一個時間刻度內的改寫看不出來：見 PR 的 Not verified。這裡先等時間前進，讓 ctime 一定不同。）"""
    import time
    src = tmp_path / "r.tar"
    tar_of(src, [("usr/bin/agent", b"first read content"), ("bin", ("sym", "usr/bin"))])
    orig = ow.second_read_tar

    def swapped(fp, s, *a):
        st = os.stat(src)
        new = tar_of(tmp_path / "new.tar", [("usr/bin/agent", b"FIRST READ CONTENT"), ("bin", ("sym", "usr/bin"))]).read_bytes()
        deadline = time.monotonic() + 5
        while os.stat(src).st_ctime_ns == st.st_ctime_ns and time.monotonic() < deadline:
            with open(src, "r+b") as f:
                f.write(new)
                f.truncate()
            os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))
            time.sleep(0.01)
        assert os.stat(src).st_size == st.st_size and os.stat(src).st_mtime_ns == st.st_mtime_ns
        return orig(fp, s, *a)
    monkeypatch.setattr(ow, "second_read_tar", swapped)
    doc = ow.collect(str(src), None, ow.entries(cfg_with(["/bin/agent"]))[0])
    assert doc["status"] == "GAP" and doc["files"] == []
    assert doc["problems"][0]["reason"] == "the source archive changed during the second read: not used"
    assert len(ow.source_id(str(src))) == 5


@pytest.mark.parametrize("own", [["/usr/bin/agent"], ["/bin/agent"]])
def test_duplicate_tar_members_last_wins(tmp_path, own):
    """tar 裡同一個名稱出現兩次：命名空間與雜湊都用最後一個（字面上對到時第一次讀取就是；經過連結時第二次讀取用序號取同一個成員）。"""
    m = [("usr/bin/agent", b"OLD v1"), ("bin", ("sym", "usr/bin")), ("usr/bin/agent", b"NEW v2")]
    p, doc = collect(tmp_path, own, m)
    assert p.returncode == 0, p.stdout
    assert doc["files"][0]["sha256"] == sha(b"NEW v2") and doc["second_read"] is (own == ["/bin/agent"])


@pytest.mark.parametrize("keep_id", [False, True])
def test_archive_changed_between_reads_is_gap(tmp_path, monkeypatch, keep_id):
    """第二次讀 tar 時檔案被換掉：來源檔的 (st_dev, st_ino, st_size, mtime) 讀完後不同 → GAP；就算這些相同（keep_id），
    同一個序號的成員名稱、型別、大小對不上 → GAP，不用那份內容。"""
    src = tmp_path / "r.tar"
    tar_of(src, [("usr/bin/agent", b"first read content"), ("bin", ("sym", "usr/bin"))])
    fp = ow.icmod().flash_package()
    orig, calls = fp.open_stream, []

    def swapping(path):
        calls.append(path)
        if len(calls) == 2:
            tar_of(src, [("usr/bin/agent", b"DIFFERENT CONTENT, other size!!"), ("bin", ("sym", "usr/bin")),
                         ("pad", b"x" * 20000)])            # tar 檔變大：來源檔的 st_size 不同
        return orig(path)
    monkeypatch.setattr(fp, "open_stream", swapping)
    monkeypatch.setattr(ow.icmod(), "flash_package", lambda: fp)
    if keep_id:
        monkeypatch.setattr(ow, "source_id", lambda p: "same")
    doc = ow.collect(str(src), None, ow.entries(cfg_with(["/bin/agent"]))[0])
    assert len(calls) == 2 and doc["status"] == "GAP" and doc["files"] == []
    assert doc["problems"][0]["reason"] == ("content changed between the two reads of the archive (member name, type or size differ): not used"
                                            if keep_id else "the source archive changed during the second read: not used")


def test_escaped_name_collision_not_duplicated(tmp_path):
    """名稱有控制字元：clean() 之後會和另一個真的叫 x\\x01y 的檔案相同 → 不當元件（GAP），bom-ref 不重複。"""
    p, doc = collect(tmp_path, ["/opt/a/*"], [("opt/a/x\x01y", b"one"), ("opt/a/x\\x01y", b"two")])
    assert p.returncode == 2
    assert [f["path"] for f in doc["files"]] == ["opt/a/x\\x01y"] and files(doc)["opt/a/x\\x01y"]["sha256"] == sha(b"two")
    assert "control or non-UTF-8 characters" in doc["problems"][0]["reason"]
    refs = [c["bom-ref"] for c in ow.build(doc, cfg_with(["/opt/a/*"]), "1.6")[0]]
    assert refs == ["sca-center:own:opt/a/x\\x01y"]
    dup = dict(doc, files=doc["files"] * 2)
    comps, _, info = ow.build(dup, cfg_with(["/opt/a/*"]), "1.6")
    assert len(comps) == 1 and any("listed twice" in g for g in info["gaps"])


def test_symlink_escaping_rootfs_rejected(tmp_path):
    """相對連結的 .. 超出 rootfs 的根 → 拒絕（GAP），不讀主機的檔案；絕對連結在映像的命名空間裡解析（主機的檔案不會被讀）。"""
    secret = tmp_path / "host-secret.txt"
    secret.write_bytes(b"host secret")
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr" / "bin").mkdir(parents=True)
    (rootfs / "usr" / "bin" / "ok").write_bytes(b"ok")
    (rootfs / "usr" / "bin" / "up").symlink_to("../../../host-secret.txt")     # 主機上真的指到 rootfs 外的檔案
    (rootfs / "usr" / "bin" / "abs").symlink_to(str(secret))                  # 絕對路徑：映像裡沒有這個路徑
    (rootfs / "usr" / "bin" / "viadir").symlink_to("../..")                   # 指到根（合法）
    for src in (rootfs, tar_of(tmp_path / "r.tar", [("usr/bin/ok", b"ok"), ("usr/bin/up", ("sym", "../../../host-secret.txt")),
                                                      ("usr/bin/abs", ("sym", str(secret))), ("usr/bin/viadir", ("sym", "../.."))])):
        out = tmp_path / ("o-" + Path(src).name)
        p = cli("--from", src, "--config", write_cfg(tmp_path, ["/usr/bin/*", "/usr/bin/up", "/usr/bin/viadir/usr/bin/ok"]), "--out", out)
        doc = json.loads((out / "own-software.json").read_text())
        assert p.returncode == 2, p.stdout
        assert sorted(files(doc)) == ["usr/bin/ok"], doc
        assert files(doc)["usr/bin/ok"]["listed_as"] == ["usr/bin/ok", "usr/bin/viadir/usr/bin/ok"]
        reasons = {(x["path"], x["reason"]) for x in doc["problems"]}
        assert ("usr/bin/up", "symbolic link points outside the root file system (.. above /): rejected") in reasons
        assert ("usr/bin/abs", "symbolic link target not in the root file system") in reasons
        assert "GAP\tusr/bin/up\tusr/bin/up: symbolic link points outside the root file system (.. above /): rejected" in p.stdout
        assert sha(b"host secret") not in (out / "own-software.json").read_text()


def test_size_limit(tmp_path):
    p, doc = collect(tmp_path, ["/usr/bin/acme-agent", "/opt/acme/bin/alpha"], extra=("--max-file-size", len(ELF_BIN)))
    assert p.returncode == 2
    assert sorted(files(doc)) == ["usr/bin/acme-agent"]
    pr = {x["pattern"]: x for x in doc["patterns"]}["opt/acme/bin/alpha"]
    assert pr["status"] == "GAP" and pr["matched"] == 0 and "larger than the size limit" in pr["reasons"][0]
    assert "GAP\topt/acme/bin/alpha\topt/acme/bin/alpha: larger than the size limit" in p.stdout


def test_hard_links_and_rejected_members(tmp_path):
    members = [("opt/acme/tool", b"tool"), ("usr/bin/tool-link", ("hard", "opt/acme/tool")), ("../evil", b"x"), ("/abs", b"y")]
    p, doc = collect(tmp_path, ["/usr/bin/tool-link", "/opt/acme/tool"], members=members)
    assert p.returncode == 0, p.stdout
    f = files(doc)
    assert list(f) == ["opt/acme/tool"] and f["opt/acme/tool"]["hard_links"] == ["usr/bin/tool-link"]
    assert doc["rejected_members"] == 2 and "拒絕的成員 2 個" in p.stdout


def test_output_order_stable(tmp_path):
    """tar 成員的順序不同、資料夾來源 → 同樣的檔案清單；own-software.json 逐位元組相同（不含時間與本機路徑）。"""
    own = ["/opt/acme/bin/*", "/usr/bin/acme-agent", "/lib/modules/*/extra/*.ko"]
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    collect(a, own, ROOTFS)
    collect(b, own, list(reversed([m for m in ROOTFS if m[1] is not None])))
    ja, jb = (d / "out" / "own-software.json" for d in (a, b))
    assert ja.read_bytes() == jb.read_bytes()
    paths = [f["path"] for f in json.loads(ja.read_text())["files"]]
    assert paths == sorted(paths)
    # 資料夾來源：同樣的檔案清單（source 以外的內容逐位元組相同），重跑也一樣
    root = make_dir(tmp_path / "rootfs", ROOTFS)
    outs = []
    for i in (1, 2):
        cli("--from", root, "--config", write_cfg(tmp_path, own), "--out", tmp_path / f"d{i}")
        outs.append((tmp_path / f"d{i}" / "own-software.json").read_bytes())
    assert outs[0] == outs[1]
    dj, tj = json.loads(outs[0]), json.loads(ja.read_bytes())
    assert {k: v for k, v in dj.items() if k != "source"} == {k: v for k, v in tj.items() if k != "source"}


def test_not_configured_writes_nothing(tmp_path):
    src = tar_of(tmp_path / "r.tar", ROOTFS)
    (tmp_path / "c.json").write_text(json.dumps(MIN_CFG))
    p = cli("--from", src, "--config", tmp_path / "c.json", "--out", tmp_path / "out")
    assert p.returncode == 0 and p.stdout.startswith("B-own-software\tSKIP\t") and not (tmp_path / "out").exists()
    assert cli("--config", tmp_path / "c.json", "--configured").returncode == 1
    assert cli("--config", write_cfg(tmp_path, ["a"]), "--configured").returncode == 0


def test_declaration_kinds():
    """沒有列自有軟體時的宣告：沒宣告 → undeclared；空陣列＋理由 → none；空陣列沒有理由 → undeclared；列了又寫理由 → conflict。"""
    R = ow.NONE_REASON_KEY
    assert ow.declaration(None)[0] == "undeclared" and "no product configuration" in ow.declaration(None)[1]
    assert ow.declaration(MIN_CFG)[0] == "undeclared"
    assert ow.declaration(dict(MIN_CFG, sbom={"own_software": []}))[0] == "undeclared"
    assert ow.declaration(dict(MIN_CFG, sbom={"own_software": [], R: "  "}))[0] == "undeclared"
    assert ow.declaration(dict(MIN_CFG, sbom={"own_software": [], R: "only  distro\npackages"})) == ("none", "only distro packages")   # 空白正規化
    assert ow.declaration(dict(MIN_CFG, sbom={"own_software": [], R: "only distro packages"})) == ("none", "only distro packages")
    assert ow.declaration(dict(MIN_CFG, sbom={"own_software": [], R: "x" * 501}))[0] == "undeclared"
    assert ow.declaration(dict(MIN_CFG, sbom={"own_software": ["a"], R: "none"}))[0] == "conflict"
    assert ow.declaration(dict(MIN_CFG, sbom={"own_software": ["a"]})) == ("listed", None)
    assert ow.declaration(dict(MIN_CFG, sbom={"own_software": "a"}))[0] == "undeclared"


def test_declaration_cli(tmp_path):
    """--declaration：沒宣告 → GAP（exit 2）、明確宣告沒有 → OK（exit 0），都寫只有宣告結果的 own-software.json；有列 → 參數錯誤。"""
    p = cli("--declaration", "--out", tmp_path / "o1")
    assert p.returncode == 2 and p.stdout.startswith("B-own-software\tGAP\t沒有產品設定：沒有宣告自有軟體"), p.stdout + p.stderr
    d = json.loads((tmp_path / "o1" / "own-software.json").read_text())
    assert d["status"] == "GAP" and d["declaration"]["kind"] == "undeclared" and "patterns" not in d
    c = tmp_path / "none.json"
    c.write_text(json.dumps(dict(MIN_CFG, sbom={"own_software": [], ow.NONE_REASON_KEY: "only distribution packages"})))
    p = cli("--config", c, "--declaration", "--out", tmp_path / "o2")
    assert p.returncode == 0 and p.stdout.startswith("B-own-software\tOK\t製造商宣告沒有自有軟體：only distribution packages"), p.stdout
    assert cli("--config", write_cfg(tmp_path, ["a"]), "--declaration", "--out", tmp_path / "o3").returncode == 64
    assert cli("--declaration").returncode == 64
    assert cli("--from", "x", "--out", tmp_path / "o4").returncode == 64          # 其他模式仍要 --config


def test_conflicting_declaration_is_a_config_error(tmp_path):
    src = tar_of(tmp_path / "r.tar", ROOTFS)
    c = tmp_path / "c.json"
    c.write_text(json.dumps(dict(CFG, sbom={"own_software": ["/usr/bin/acme-agent"], ow.NONE_REASON_KEY: "none"})))
    p = cli("--from", src, "--config", c, "--out", tmp_path / "out")
    assert p.returncode == 2 and p.stdout.startswith("B-own-software\tGAP\t") and "contradicts" in p.stdout


def test_cra_report_reads_the_declaration(tmp_path):
    """cra_report：沒有列自有軟體時，只有 --declaration 寫的檔案存在才在 SBOM 文件標出來；沒有那個檔案時照舊。"""
    proj, scan = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "res" / "scan")
    r, s0, rep = run(proj, scan)
    assert "own_software" not in s0["product_sbom"]                                    # 沒有宣告檔：輸出照舊
    assert cli("--config", proj / "CRA" / "Config" / "config.json", "--declaration", "--out", scan.parent / "own-software").returncode == 2
    r, s, rep = run(proj, scan)
    assert s["product_sbom"]["own_software"]["status"] == "GAP" and s["product_sbom"]["own_software"]["declaration"] == "undeclared"
    assert s["documents"]["sbom"]["status"] == "GAP" and any("no own software declared" in x for x in s["documents"]["sbom"]["detail"])
    assert "no own software declared" in (rep / "sbom.md").read_text(encoding="utf-8")
    # 明確宣告沒有：OK，sbom.md 寫出理由與「掃描沒有驗證」
    cfg = dict(MIN_CFG, sbom={"own_software": [], ow.NONE_REASON_KEY: "only distribution packages"})
    proj2 = make_project(tmp_path / "p2", cfg)
    r, s2, rep2 = run(proj2, scan)
    assert s2["product_sbom"]["own_software"]["status"] == "OK" and s2["product_sbom"]["own_software"]["none_reason"] == "only distribution packages"
    md = (rep2 / "sbom.md").read_text(encoding="utf-8")
    assert "only distribution packages" in md and "the scan did not verify it" in md


def test_bad_source_fails(tmp_path):
    (tmp_path / "r.tar").write_bytes(tar_of(tmp_path / "x.tar", ROOTFS).read_bytes()[:1500])   # 截斷
    p = cli("--from", tmp_path / "r.tar", "--config", write_cfg(tmp_path, ["/usr/bin/acme-agent"]), "--out", tmp_path / "out")
    assert p.returncode == 1 and p.stdout.startswith("B-own-software\tFAIL\t")


@pytest.mark.parametrize("case", ["no-source", "bad-config", "unreadable-config"])
def test_fail_message_has_no_host_path(tmp_path, case):
    """FAIL 的說明不寫主機的絕對路徑（只留檔名）。"""
    cfg = write_cfg(tmp_path, ["/usr/bin/acme-agent"])
    src = tar_of(tmp_path / "r.tar", ROOTFS)
    if case == "no-source":
        src = tmp_path / "missing" / "rootfs.tar"
    elif case == "bad-config":
        cfg.write_text("[1, 2]")
    else:
        cfg = tmp_path / "nope" / "config.json"
    p = cli("--from", src, "--config", cfg, "--out", tmp_path / "out")
    line = p.stdout.splitlines()[0]
    assert line.startswith("B-own-software\tFAIL\t") and p.returncode in (1, 64), p.stdout + p.stderr
    assert str(tmp_path) not in p.stdout and ("rootfs.tar" in line or "config.json" in line), line


def test_flash_package_prefix(tmp_path):
    """刷機包（tbz2）裡的 rootfs：--prefix；rootfs 外的成員不算。"""
    pre = "PKG/Linux_for_Tegra/rootfs_no_gui"
    src = tmp_path / "pkg.tbz2"
    with tarfile.open(src, "w:bz2") as t:
        for name, data in ((f"{pre}/usr/bin/acme-agent", ELF_BIN), ("PKG/Linux_for_Tegra/usr/bin/acme-agent", b"outside")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    p = cli("--from", src, "--prefix", pre, "--config", write_cfg(tmp_path, ["/usr/bin/acme-agent"]), "--out", tmp_path / "out")
    doc = json.loads((tmp_path / "out" / "own-software.json").read_text())
    assert p.returncode == 0, p.stdout
    assert doc["source"] == {"type": "archive", "file": "pkg.tbz2", "prefix": pre}
    assert files(doc)["usr/bin/acme-agent"]["sha256"] == sha(ELF_BIN)

    # 另一個 rootfs 的檔案以硬連結指到這個 rootfs 以外（刷機包裡的 rootfs_gui → rootfs_no_gui）：第二次讀取取那個成員
    gui = "PKG/Linux_for_Tegra/rootfs_gui"
    src2 = tmp_path / "pkg2.tbz2"
    with tarfile.open(src2, "w:bz2") as t:
        ti = tarfile.TarInfo(f"{pre}/usr/bin/acme-agent")
        ti.size = len(ELF_BIN)
        t.addfile(ti, io.BytesIO(ELF_BIN))
        ti = tarfile.TarInfo(f"{gui}/usr/bin/acme-agent")
        ti.type, ti.linkname = tarfile.LNKTYPE, f"{pre}/usr/bin/acme-agent"
        t.addfile(ti)
    p = cli("--from", src2, "--prefix", gui, "--config", write_cfg(tmp_path, ["/usr/bin/acme-agent"]), "--out", tmp_path / "out2")
    f = files(json.loads((tmp_path / "out2" / "own-software.json").read_text()))["usr/bin/acme-agent"]
    assert p.returncode == 0, p.stdout
    assert f["sha256"] == sha(ELF_BIN) and f["hardlink_of"] == f"{pre}/usr/bin/acme-agent"


# ---------- 元件 ----------

def doc_for(tmp_path, own, members=ROOTFS):
    p, doc = collect(tmp_path, own, members)
    return doc


def test_build_components_versions_and_supplier(tmp_path):
    own = [{"path": "/usr/bin/acme-agent", "version": "2.3.0", "name": "Acme Agent"}, "/opt/acme/bin/*", "/lib/modules/*/extra/acme_*.ko"]
    doc = doc_for(tmp_path, own)
    comps, top, info = ow.build(doc, cfg_with(own), "1.6")
    n = {c["name"]: c for c in comps}
    assert list(n) == ["alpha", "libacme.so.1", "zeta.sh", "Acme Agent", "acme_drv", "acme_nover"]       # 依路徑排序
    assert top == [c["bom-ref"] for c in comps]
    a = n["Acme Agent"]
    assert a["version"] == "2.3.0" and a["type"] == "application" and a["bom-ref"] == "sca-center:own:usr/bin/acme-agent"
    assert a["supplier"] == {"name": "Example Co.", "url": ["https://www.example.com"]} and a["manufacturer"] == a["supplier"]
    assert a["purl"] == f"pkg:generic/Acme%20Agent@2.3.0?checksum=sha256:{sha(ELF_BIN)}"
    assert [h["alg"] for h in a["hashes"]] == ["SHA-256", "SHA-512"] and a["hashes"][0]["content"] == sha(ELF_BIN)
    pa = {p["name"]: p["value"] for p in a["properties"]}
    assert pa["bsi:component:executable"] == "executable" and pa["sca-center:version-basis"] == "configuration sbom.own_software"
    assert n["libacme.so.1"]["type"] == "library"
    drv = n["acme_drv"]
    assert drv["type"] == "device-driver" and drv["version"] == "1.2.3" and drv["licenses"][0]["license"]["name"] == "GPL v2"
    assert {p["name"]: p["value"] for p in drv["properties"]}["sca-center:version-basis"] == "modinfo version"
    # 版本未知：不填 version、標 version-status；不從檔名猜（libacme.so.1 的 1 不是版本）
    for name in ("alpha", "libacme.so.1", "zeta.sh", "acme_nover"):
        c = n[name]
        pc = {p["name"]: p["value"] for p in c["properties"]}
        assert "version" not in c and pc["sca-center:version-status"] == "unknown" and "@" not in c["purl"], name
        assert pc["sca-center:version-basis"].startswith("version unknown")
    assert info["version_unknown"] == 4 and info["status"] == "OK" and info["components"] == 6
    t = ow.text(info, lambda h, r: "\n".join(" | ".join(map(str, x)) for x in [h] + r))
    assert "**version unknown**" in t and "Version unknown for 4 file(s)" in t and "not assessed" in t


def test_name_only_for_single_match_and_version_conflict(tmp_path):
    own = [{"path": "/opt/acme/bin/*", "name": "Suite", "version": "1"}, {"path": "/opt/acme/bin/alpha", "version": "2"}]
    doc = doc_for(tmp_path, own)
    comps, _, info = ow.build(doc, cfg_with(own), "1.6")
    n = {c["name"]: c for c in comps}
    assert "Suite" not in n and set(n) == {"alpha", "libacme.so.1", "zeta.sh"}           # name 只給剛好對到一個檔案的筆
    assert "version" not in n["alpha"] and n["zeta.sh"]["version"] == "1"                 # 兩筆給不同版本 → 未知，不選一個
    assert "different versions" in {p["name"]: p["value"] for p in n["alpha"]["properties"]}["sca-center:version-basis"]


def test_version_unknown_printed_by_cli(tmp_path):
    p, _ = collect(tmp_path, ["/opt/acme/bin/zeta.sh", {"path": "/usr/bin/acme-agent", "version": "1.0"}])
    assert "INFO\t/opt/acme/bin/zeta.sh\t版本未知" in p.stdout and "/usr/bin/acme-agent\t版本未知" not in p.stdout
    assert "版本未知 1 個" in p.stdout.splitlines()[0]


def test_build_without_inventory_is_gap():
    comps, top, info = ow.build(None, cfg_with(["/usr/bin/x"]), "1.6")
    assert comps == [] and info["status"] == "GAP" and "own-software.json not found" in info["gaps"][0]


def test_build_pattern_not_in_inventory_is_gap(tmp_path):
    doc = doc_for(tmp_path, ["/usr/bin/acme-agent"])
    comps, _, info = ow.build(doc, cfg_with(["/usr/bin/acme-agent", "/usr/bin/new-one"]), "1.6")
    assert len(comps) == 1 and info["status"] == "GAP" and any("usr/bin/new-one" in g and "different list" in g for g in info["gaps"])
    # 設定拿掉了某一筆：那一筆的檔案不加
    (tmp_path / "x").mkdir()
    doc2 = doc_for(tmp_path / "x", ["/usr/bin/acme-agent", "/opt/acme/bin/*"])
    comps, _, info = ow.build(doc2, cfg_with(["/usr/bin/acme-agent"]), "1.6")
    assert [c["name"] for c in comps] == ["acme-agent"] and info["status"] == "OK"


# ---------- cra_report.py ----------

def own_doc(tmp_path, own, members=ROOTFS):
    d = tmp_path / "collect"
    d.mkdir()
    return doc_for(d, own, members)


def test_cra_report_adds_own_software(tmp_path):
    own = [{"path": "/usr/bin/acme-agent", "version": "2.3.0"}, "/opt/acme/bin/*", "/usr/bin/missing"]
    proj, scan = make_project(tmp_path / "p", cfg_with(own, MIN_CFG)), make_scan(tmp_path / "res" / "scan")
    write_json(scan.parent / "own-software" / "own-software.json", own_doc(tmp_path, own))
    r, s, rep = run(proj, scan)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    bom = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
    mine = [c for c in bom["components"] if str(c.get("bom-ref", "")).startswith(ow.REF)]
    assert [c["name"] for c in mine] == ["alpha", "libacme.so.1", "zeta.sh", "acme-agent"]
    assert all(c["supplier"]["name"] == "Example Co." and c["purl"].startswith("pkg:generic/") for c in mine)
    root = bom["metadata"]["component"]["bom-ref"]
    assert {c["bom-ref"] for c in mine} <= set(next(d["dependsOn"] for d in bom["dependencies"] if d["ref"] == root))
    os_ = s["product_sbom"]["own_software"]
    assert os_["status"] == "GAP" and os_["components"] == 4 and len(os_["sha256"]) == 64
    md = (rep / "sbom.md").read_text(encoding="utf-8")
    assert "Manufacturer's own software" in md and "`usr/bin/missing`: listed but not found" in md and "**version unknown**" in md
    # 列了但找不到 → SBOM 文件 GAP（不顯示為完整）
    assert s["documents"]["sbom"]["status"] == "GAP"
    assert any("own software" in x for x in s["documents"]["sbom"]["detail"])
    # 重跑：同樣的序號與元件順序
    run(proj, scan)
    bom2 = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert bom2["serialNumber"] == bom["serialNumber"] and bom2["components"] == bom["components"]


def test_cra_report_configured_without_inventory_is_gap(tmp_path):
    proj, scan = make_project(tmp_path / "p", cfg_with(["/usr/bin/acme-agent"], MIN_CFG)), make_scan(tmp_path / "scan")
    r, s, rep = run(proj, scan)
    assert s["product_sbom"]["own_software"]["status"] == "GAP" and s["documents"]["sbom"]["status"] == "GAP"
    assert "own-software.json not found" in (rep / "sbom.md").read_text(encoding="utf-8")
    r, s, rep = run(proj, scan, "--own-software", str(tmp_path / "nope.json"))
    assert r.returncode == 64


def test_cra_report_explicit_option_and_bad_file(tmp_path):
    own = ["/usr/bin/acme-agent"]
    proj, scan = make_project(tmp_path / "p", cfg_with(own, MIN_CFG)), make_scan(tmp_path / "scan")
    write_json(tmp_path / "elsewhere.json", own_doc(tmp_path, own))
    r, s, _ = run(proj, scan, "--own-software", str(tmp_path / "elsewhere.json"))
    assert s["product_sbom"]["own_software"]["components"] == 1 and s["product_sbom"]["own_software"]["status"] == "OK", r.stdout
    write_json(tmp_path / "bad.json", {"patterns": "x", "files": 3})
    r, s, _ = run(proj, scan, "--own-software", str(tmp_path / "bad.json"))
    assert r.returncode in (0, 2) and s["product_sbom"]["own_software"]["status"] == "GAP"


def merged_case(tmp_path, same_sha):
    rel = "usr/lib/modules/6.8.12-tegra/updates/nvgpu.ko"
    own = ["/lib/modules/*/updates/nvgpu.ko"]
    cfg = dict(MIN_CFG, sbom={"flash_package_supplier": {"name": "Vendor Ltd"}, "own_software": own})
    proj, scan = flash_result(tmp_path, cfg=cfg)
    if same_sha:              # 清點檔記的是同一份內容
        inv = json.loads(json.dumps(INV))
        for x in next(iter(inv["kernel_modules"].values())):
            if x["path"] == rel:
                x["sha256"] = sha(elf(MODINFO))
        write_json(scan.parent.parent / "flash-inventory.json", inv)
    members = [("lib", ("sym", "usr/lib")), (rel, elf(MODINFO))]
    write_json(scan.parent / "own-software" / "own-software.json", own_doc(tmp_path, own, members))
    r, s, rep = run(proj, scan)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    bom = json.loads((rep / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert not [c for c in bom["components"] if str(c.get("bom-ref", "")).startswith(ow.REF)]
    nv = [c for c in bom["components"] if c["name"] == "nvgpu"]
    assert len(nv) == 1
    return rel, nv[0], {p["name"]: p["value"] for p in nv[0]["properties"]}, s, rep


def test_cra_report_own_module_merged_with_flash_module(tmp_path):
    """同一個 .ko（SHA-256 相同）已經是刷機包 updates/ 的 kernel 模組（firmware_bom）：不重複列；那個元件標成自有軟體。"""
    rel, nv, pv, s, rep = merged_case(tmp_path, True)
    assert nv["supplier"]["name"] == "Example Co." and nv["manufacturer"]["name"] == "Example Co."
    assert pv["sca-center:flash-package-supplier"] == "Vendor Ltd"
    assert pv["sca-center:own-software"] == "listed in sbom.own_software: lib/modules/*/updates/nvgpu.ko" and nv["version"] == "1.2.3"
    sha256 = next(h["content"] for h in nv["hashes"] if h["alg"] == "SHA-256")
    assert sha256 == sha(elf(MODINFO)) and nv["purl"] == f"pkg:generic/nvgpu@1.2.3?checksum=sha256:{sha256}"
    assert "sca-center:own-software-sha256" not in pv
    o = s["product_sbom"]["own_software"]
    assert o["merged_with_flash_modules"] == ["/" + rel] and o["components"] == 0 and o["status"] == "OK", o
    assert "not listed twice" in (rep / "sbom.md").read_text(encoding="utf-8")


def test_cra_report_own_module_sha_mismatch_not_merged(tmp_path):
    """SHA-256 不同（清點檔是合成的 aaaa…）：不能確定是同一個檔案 → 元件維持刷機包清點的樣子（supplier、hashes、版本不動，
    不加帶 checksum 的 purl），只記兩個雜湊與 GAP（反例：以前 purl 帶 own 的 checksum、hashes 是清點檔的、supplier 被改寫）。"""
    rel, nv, pv, s, rep = merged_case(tmp_path, False)
    assert nv["supplier"]["name"] == "Vendor Ltd" and "manufacturer" not in nv and "purl" not in nv
    assert [h["content"] for h in nv["hashes"] if h["alg"] == "SHA-256"] == ["a" * 64]
    assert pv["sca-center:own-software-sha256"] == sha(elf(MODINFO)) and "sca-center:flash-package-supplier" not in pv
    # 沒有合併：屬性名稱寫明 unmerged，不出現 sca-center:own-software（反例：以前會讓人以為已經標成自有軟體）
    assert "sca-center:own-software" not in pv and "not merged" in pv["sca-center:own-software-unmerged"]
    assert s["product_sbom"]["own_software"]["merged_with_flash_modules"] == []
    assert s["product_sbom"]["own_software"]["unmerged_flash_modules"] == ["/" + rel]
    o = s["product_sbom"]["own_software"]
    assert o["status"] == "GAP" and any("SHA-256 differs" in g for g in o["gaps"])
    assert "**SHA-256 differs**: not merged" in (rep / "sbom.md").read_text(encoding="utf-8")
    assert s["documents"]["sbom"]["status"] == "GAP"


def test_product_sbom_with_own_software_valid_cyclonedx(tmp_path):
    sbom = json.loads(json.dumps(SBOM))
    sbom["metadata"]["tools"]["components"][0]["type"] = "application"
    own = ["/opt/acme/bin/*", "/lib/modules/*/extra/*.ko"]
    proj, scan = make_project(tmp_path / "p", cfg_with(own, MIN_CFG)), make_scan(tmp_path / "res" / "scan", sbom=sbom)
    write_json(scan.parent / "own-software" / "own-software.json", own_doc(tmp_path, own))
    run(proj, scan)
    bom = json.loads((proj / "CRA" / "Reports" / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert any(str(c.get("bom-ref", "")).startswith(ow.REF) for c in bom["components"])
    errs = sorted(cdx_validator().iter_errors(bom), key=lambda e: list(e.path))
    assert not errs, [f"{list(e.path)}: {e.message[:200]}" for e in errs[:5]]


class FixedClock(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 11, 9, 12, 0, 0, tzinfo=tz)


def run_fixed(monkeypatch, proj, scan, *extra):
    """在同一個行程裡跑 cra_report.main，時鐘固定：輸出檔可以逐位元組比較（不用遮掉時間，產品 SBOM 的 sha256 也一樣）。"""
    monkeypatch.setenv("CRA_COMPANY_CONFIG", "none")
    monkeypatch.setattr(datetime, "datetime", FixedClock)
    rc = cr.main(["--project", str(proj), "--scan", str(scan), *extra])
    rep = proj / "CRA" / "Reports"
    return rc, {p.name: p.read_bytes() for p in sorted(rep.iterdir()) if p.is_file()}


@pytest.mark.parametrize("flash", [False, True])
def test_not_configured_output_unchanged(tmp_path, monkeypatch, capsys, flash):
    """沒有設定 sbom.own_software：own-software.json 就算存在也不讀，每個輸出檔逐位元組相同，summary 沒有新的鍵。"""
    if flash:
        proj, scan = flash_result(tmp_path)
    else:
        proj, scan = make_project(tmp_path / "p", MIN_CFG), make_scan(tmp_path / "res" / "scan")
    rc, before = run_fixed(monkeypatch, proj, scan)
    assert rc in (0, 2), capsys.readouterr()
    s = json.loads(before["summary.json"])
    assert "own_software" not in s["product_sbom"] and "own software" not in before["sbom.md"].decode().lower()
    rc, again = run_fixed(monkeypatch, proj, scan)
    assert again == before                                     # 固定時鐘下本來就可重現
    own = ["/opt/acme/bin/*"]
    write_json(scan.parent / "own-software" / "own-software.json", own_doc(tmp_path, own))
    rc, after = run_fixed(monkeypatch, proj, scan)
    assert after == before
    # 有設定時才有差別（對照）
    cfg = json.loads((proj / "CRA" / "Config" / "config.json").read_text())
    cfg.setdefault("sbom", {})["own_software"] = own
    write_json(proj / "CRA" / "Config" / "config.json", cfg)
    rc, configured = run_fixed(monkeypatch, proj, scan)
    assert configured["sbom.cdx.json"] != before["sbom.cdx.json"] and b"sca-center:own:opt/acme/bin/alpha" in configured["sbom.cdx.json"]


def test_shared_example_fixture_has_no_own_software():
    """其他測試共用的 EXAMPLE 拿掉了 own_software（那些測試沒有 own-software.json；自有軟體在這個檔案測）。"""
    assert "own_software" not in EXAMPLE.get("sbom", {})
