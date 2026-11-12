"""pkg_why.py：從 rootfs tar／刷機包／資料夾取出 dpkg status 與 extended_states（不跟隨連結、硬連結讀目標），
依 summary.json 的 vex.gate.open_components 寫「套件為什麼在映像裡」（最短路徑、Recommends、開發套件、基本套件、dpkg 找不到）。"""
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pkg_why as pw  # noqa: E402
import vex_export as vx  # noqa: E402
from test_vex_export import row  # noqa: E402

CLI = HERE.parent / "pkg_why.py"


def para(name, ver="1.0", depends=None, recommends=None, source=None, priority="optional", provides=None, status="install ok installed"):
    lines = [f"Package: {name}", f"Status: {status}", f"Priority: {priority}", "Architecture: arm64", f"Version: {ver}"]
    if source:
        lines.append(f"Source: {source}")
    if provides:
        lines.append(f"Provides: {provides}")
    if depends:
        lines.append(f"Depends: {depends}")
    if recommends:
        lines.append(f"Recommends: {recommends}")
    lines += ["Description: test", " continuation line: not a field"]
    return "\n".join(lines)


STATUS = "\n\n".join([
    para("myapp", depends="libc6"),
    para("libopencv-dev", depends="libopencv-contrib406t64 | libopencv-other"),
    para("libopencv-contrib406t64", source="opencv (4.6.0+dfsg-13)", depends="libhdf5-103-1t64:arm64 (>= 1.10)"),
    para("libhdf5-103-1t64", "1.10.10+repack-3.1ubuntu4", source="hdf5"),
    para("libhdf5-hl-100t64", "1.10.10+repack-3.1ubuntu4", source="hdf5", depends="libhdf5-103-1t64"),
    para("cups", "2.4.7-1.2ubuntu7"),
    para("desktop", recommends="libsoup-3.0-0"),
    para("libsoup-3.0-0", "3.4.4-5ubuntu0.1", source="libsoup3"),
    para("python3.12", "3.12.3-1ubuntu0.1", priority="important"),
    para("libc6", "2.39-0ubuntu8", source="glibc", priority="required"),
    para("gcc-13", depends="binutils-aarch64"),
    para("build-essential", depends="gcc-13"),
    para("binutils-aarch64", source="binutils", provides="binutils-target"),
    para("removed-pkg", status="deinstall ok config-files"),
]) + "\n"
EXT = "\n\n".join(f"Package: {n}\nArchitecture: arm64\nAuto-Installed: 1" for n in (
    "libopencv-contrib406t64", "libhdf5-103-1t64", "libhdf5-hl-100t64", "libsoup-3.0-0", "libc6", "gcc-13",
    "binutils-aarch64")) + "\n"


def comp(name, rows, purl=None, typ="deb", installed_as=(), states=None, tiers=None):
    return {"component": name, "version": "1", "purl": purl if purl is not None else f"pkg:deb/ubuntu/{name}@1?arch=source&distro=ubuntu-24.04",
            "type": typ, "installed_as": list(installed_as), "rows": rows, "states": states or {"untriaged": rows},
            "tiers": tiers or {"p3": rows}}


SUMMARY = {"generated": "2026-11-03T00:00:00Z", "vex": {"gate": {"open_components": [
    comp("hdf5", 108, states={"exploitable": 10, "untriaged": 98}, tiers={"p2": 52, "p3": 56}),
    comp("linux-nvidia-tegra", 50, typ="kernel"),
    comp("cups", 11), comp("libsoup3", 9), comp("python3.12", 8), comp("binutils", 7), comp("ghost", 3),
    comp("glibc", 2), comp("brotli", 1, purl="pkg:pypi/brotli@1.1.0", typ="pypi")]}}}


def tar_with(path, members, mode="w"):
    with tarfile.open(path, mode) as t:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            if isinstance(data, tuple):
                ti.type, ti.linkname = data
                t.addfile(ti)
            else:
                b = data.encode()
                ti.size = len(b)
                t.addfile(ti, io.BytesIO(b))


def cli(*args):
    return subprocess.run([sys.executable, "-I", str(CLI), *args], capture_output=True, text=True)


def pkgdb(tmp_path, ext=True):
    d = tmp_path / "pkgdb"
    d.mkdir()
    (d / "dpkg-status").write_text(STATUS, encoding="utf-8")
    if ext:
        (d / "extended_states").write_text(EXT, encoding="utf-8")
    (d / "pkgdb.json").write_text(json.dumps({"source": {"type": "rootfs-tar", "file": "rootfs.tar", "prefix": None}}), encoding="utf-8")
    s = tmp_path / "summary.json"
    s.write_text(json.dumps(SUMMARY), encoding="utf-8")
    return d, s


def test_extract_rootfs_tar_and_archive(tmp_path):
    rt = tmp_path / "rootfs.tar"
    tar_with(rt, [("./etc/hostname", "x"), ("./var/lib/dpkg/status", STATUS), ("./var/lib/apt/extended_states", EXT)])
    r = cli("extract", "--from", str(rt), "--out", str(tmp_path / "a"))
    assert r.returncode == 0 and r.stdout.startswith("PKGDB\tOK\tdpkg status 14 個套件段落；extended_states 有"), r.stdout + r.stderr
    assert (tmp_path / "a" / "dpkg-status").read_text(encoding="utf-8") == STATUS
    meta = json.loads((tmp_path / "a" / "pkgdb.json").read_text(encoding="utf-8"))
    assert meta["source"] == {"type": "rootfs-tar", "file": "rootfs.tar", "prefix": None} and set(meta["files"]) == {"dpkg-status", "extended_states", "rootfs-files"}
    # 刷機包（bz2）＋前綴：別的 rootfs 的同名檔案不算；extended_states 是硬連結 → 讀目標的內容
    ar = tmp_path / "flash.tbz2"
    tar_with(ar, [("Linux_for_Tegra/rootfs_other/var/lib/dpkg/status", "Package: wrong\nStatus: install ok installed\n"),
                  ("Linux_for_Tegra/rootfs/var/lib/dpkg/status", STATUS),
                  ("Linux_for_Tegra/rootfs_other/var/lib/apt/extended_states", EXT),
                  ("Linux_for_Tegra/rootfs/var/lib/apt/extended_states", (tarfile.LNKTYPE, "Linux_for_Tegra/rootfs_other/var/lib/apt/extended_states"))],
            mode="w:bz2")
    r = cli("extract", "--from", str(ar), "--prefix", "Linux_for_Tegra/rootfs", "--out", str(tmp_path / "b"))
    assert r.returncode == 0 and "PKGDB\tOK" in r.stdout, r.stdout + r.stderr
    assert (tmp_path / "b" / "dpkg-status").read_text(encoding="utf-8") == STATUS
    assert (tmp_path / "b" / "extended_states").read_text(encoding="utf-8") == EXT
    assert json.loads((tmp_path / "b" / "pkgdb.json").read_text(encoding="utf-8"))["source"]["type"] == "archive"


def test_extract_symlink_not_followed_and_missing(tmp_path):
    rt = tmp_path / "rootfs.tar"
    tar_with(rt, [("./var/lib/dpkg/status", (tarfile.SYMTYPE, "/etc/shadow"))])
    out = tmp_path / "o"
    out.mkdir()
    (out / "dpkg-status").write_text("old", encoding="utf-8")       # 上一次的檔案不能留下來
    r = cli("extract", "--from", str(rt), "--out", str(out))
    assert r.returncode == 0 and r.stdout.startswith("PKGDB\tGAP\t映像裡沒有 var/lib/dpkg/status") and "symlink" in r.stdout
    assert not (out / "dpkg-status").exists()
    # 資料夾來源：上層是符號連結 → 不跟隨
    root = tmp_path / "rootfs"
    (root / "var" / "lib").mkdir(parents=True)
    real = tmp_path / "elsewhere" / "dpkg"
    real.mkdir(parents=True)
    (real / "status").write_text(STATUS, encoding="utf-8")
    (root / "var" / "lib" / "dpkg").symlink_to(real)
    r = cli("extract", "--from", str(root), "--out", str(tmp_path / "d"))
    assert "PKGDB\tGAP" in r.stdout and "符號連結" in r.stdout


def test_pkgdb_paths_and_hints(tmp_path):
    db = pw.PkgDB(STATUS, EXT)
    assert "removed-pkg" not in db.pkgs and db.by_source["hdf5"] == {"libhdf5-103-1t64", "libhdf5-hl-100t64"}
    assert db.by_source["opencv"] == {"libopencv-contrib406t64"}
    roots, ((path, weak),) = db.why("libhdf5-103-1t64")
    assert roots == ["libopencv-dev"] and path == ["libopencv-dev", "libopencv-contrib406t64", "libhdf5-103-1t64"] and weak is False
    roots, ((path, weak),) = db.why("libsoup-3.0-0")
    assert path == ["desktop", "libsoup-3.0-0"] and weak is True
    assert db.why("cups") == (["cups"], [(["cups"], False)])
    # Provides：binutils-target 由 binutils-aarch64 提供；只被開發套件帶進來
    assert db.rdeps["binutils-aarch64"] == {"gcc-13": "depends"}
    h = lambda *bins: pw.hint(db, list(bins), {b: db.why(b) for b in bins})
    assert "只被開發套件帶進來（build-essential, gcc-13）" in h("binutils-aarch64")
    assert "只被開發套件帶進來（libopencv-dev）" in h("libhdf5-103-1t64")
    assert "Recommends" in h("libsoup-3.0-0") and "基本套件" in h("libc6")
    # 沒有 extended_states：沒有套件依賴它的才當頂層
    db2 = pw.PkgDB(STATUS)
    assert not db2.has_ext and db2.manual("myapp") and db2.manual("libopencv-dev") and not db2.manual("libopencv-contrib406t64")


def hints(status, ext, *bins):
    db = pw.PkgDB("\n\n".join(status) + "\n", "\n\n".join(f"Package: {n}\nArchitecture: arm64\nAuto-Installed: 1" for n in ext) + "\n")
    return db, pw.hint(db, list(bins), {b: db.why(b) for b in bins})


def test_hints_do_not_overclaim_removal():
    # Recommends 之外還有一條只用 Depends 的路徑（r → y → x）：不能說「只因 Recommends」
    db, h = hints([para("r", recommends="x", depends="y"), para("y", depends="x"), para("x")], ("y", "x"), "x")
    assert "Recommends" not in h and "被 r 帶進來" in h
    # 被三個開發套件和一個執行期套件需要：不能說「只被開發套件帶進來」（頂層超過顯示的數量也一樣）
    db, h = hints([para(n, depends="x") for n in ("a-dev", "b-dev", "c-dev", "zapp")] + [para("x")], ("x",), "x")
    assert "開發套件" not in h and h.startswith("被 zapp, a-dev, b-dev 等 4 個 帶進來")
    # 只靠循環留著（沒有手動安裝的上層）：不給「可以拿掉」類的提示
    db, h = hints([para("p", depends="q"), para("q", depends="p")], ("p", "q"), "p")
    assert "循環" in h
    # 多架構：第二個架構的依賴也算；兩個架構都要是連帶安裝才算連帶
    st = [para("x"), para("app"), "\n".join(["Package: app", "Status: install ok installed", "Architecture: armhf", "Version: 1",
                                             "Depends: x"])]
    db = pw.PkgDB("\n\n".join(st) + "\n", "Package: x\nArchitecture: arm64\nAuto-Installed: 1\n\n"
                  "Package: app\nArchitecture: arm64\nAuto-Installed: 1\n")
    assert db.rdeps["x"] == {"app": "depends"} and db.manual("app") and db.archs["app"] == {"arm64", "armhf"}
    assert "被 app 帶進來" in pw.hint(db, ["x"], {"x": db.why("x")})
    # 執行期套件直接依賴開發名稱的套件，或經過開發套件依賴它：不能說「只被開發套件帶進來」
    for st, ext, b in (([para("dkms", depends="make, gcc"), para("make"), para("gcc")], ("make", "gcc"), "make"),
                       ([para("app", depends="libfoo-dev"), para("libfoo-dev")], ("libfoo-dev",), "libfoo-dev"),
                       ([para("nvidia-jetpack", depends="nvidia-jetpack-dev"), para("nvidia-jetpack-dev", depends="x"), para("x")],
                        ("nvidia-jetpack-dev", "x"), "x")):
        db, h = hints(st, ext, b)
        assert "開發套件" not in h and "帶進來：要拿掉得先確認" in h, (b, h)
    # triggers-pending 的套件在磁碟上、滿足依賴
    db = pw.PkgDB(para("t", status="install ok triggers-pending") + "\n")
    assert "t" in db.pkgs


def test_report_markdown(tmp_path):
    d, s = pkgdb(tmp_path)
    out = tmp_path / "deps.md"
    r = cli("report", "--pkgdb", str(d), "--summary", str(s), "--out", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.startswith("D-pkg-why\tATTENTION\t7 個 deb 套件（共 7 個有未處理的列）；非 deb 2 個；dpkg 找不到 1 個")
    md = out.read_text(encoding="utf-8")
    assert "| hdf5 1 | 108 | libhdf5-103-1t64, libhdf5-hl-100t64 | libopencv-dev | 只被開發套件帶進來（libopencv-dev）" in md
    assert "裝進來的路徑：libopencv-dev → libopencv-contrib406t64 → libhdf5-103-1t64" in md
    assert "### hdf5 1（108 列：受影響 10、沒有判定 98；P2 52、P3 56）" in md
    assert "| glibc 1 | 2 | libc6 | myapp | 系統基本套件" in md
    assert "| cups 1 | 11 | cups | cups | 被直接指定安裝，沒有其他套件以 Depends／Recommends 需要它" in md
    assert "只因為 Recommends 被裝進來" in md and "（經過 Recommends）" in md
    assert "| python3.12 1 | 8 | python3.12 | python3.12 | 系統基本套件" in md
    assert "只被開發套件帶進來（build-essential, gcc-13）" in md
    assert "| ghost 1 | 3 | （dpkg 裡找不到） |" in md
    assert "| linux-nvidia-tegra 1 | kernel | 50 |" in md and "| brotli 1 | pypi | 1 |" in md
    # --top 限制每個表的數量
    r = cli("report", "--pkgdb", str(d), "--summary", str(s), "--out", str(out), "--top", "1")
    assert "1 個 deb 套件（共 7 個" in r.stdout and "cups" not in out.read_text(encoding="utf-8").split("## 不是 deb")[0]


def test_report_without_ext_states_and_errors(tmp_path):
    d, s = pkgdb(tmp_path, ext=False)
    r = cli("report", "--pkgdb", str(d), "--summary", str(s), "--out", str(tmp_path / "m.md"))
    assert "D-pkg-why\tATTENTION" in r.stdout and "沒有 extended_states" in r.stdout
    assert "沒有其他套件依賴它" in (tmp_path / "m.md").read_text(encoding="utf-8")
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"vex": {"gate": {}}}), encoding="utf-8")
    r = cli("report", "--pkgdb", str(d), "--summary", str(old), "--out", str(tmp_path / "x.md"))
    assert r.returncode == 3 and "open_components" in r.stdout
    (d / "dpkg-status").unlink()
    r = cli("report", "--pkgdb", str(d), "--summary", str(s), "--out", str(tmp_path / "y.md"))
    assert r.returncode == 0 and r.stdout.startswith("D-pkg-why\tGAP")


def test_gate_open_components():
    allr, conf, _ = vx.assess([row("CVE-1", "hdf5", "1.10", installed_as=["libhdf5-103-1t64"], tier="p2"),
                               row("CVE-2", "hdf5", "1.10", installed_as=["libhdf5-103-1t64"], tier="p3"),
                               row("CVE-3", "cups", "2.4", analysis=[{"state": "NOT_AFFECTED", "suppressed": False,
                                                                       "justification": "CODE_NOT_PRESENT", "response": "", "details": "x"}]),
                               row("CVE-4", "linux", "6.8", kernel=True)])
    oc = vx.gate(allr, conf, grype_checked=True, not_assessed=[])["open_components"]
    assert [(c["component"], c["type"], c["rows"]) for c in oc] == [("hdf5", "deb", 2), ("linux", "kernel", 1)]
    assert oc[0]["installed_as"] == ["libhdf5-103-1t64"] and oc[0]["states"] == {"untriaged": 2} and oc[0]["tiers"] == {"p2": 1, "p3": 1}
    json.dumps(oc)


# ---------- rank：拿掉套件／換基底的效益排行 ----------

def mkdb(d, status=STATUS, ext=EXT):
    d.mkdir(parents=True, exist_ok=True)
    (d / "dpkg-status").write_text(status, encoding="utf-8")
    if ext is not None:
        (d / "extended_states").write_text(ext, encoding="utf-8")
    return d


def rank(tmp_path, summary=SUMMARY, **kw):
    s = tmp_path / "summary.json"
    s.write_text(json.dumps(summary), encoding="utf-8")
    db = mkdb(tmp_path / "db", **{k: kw.pop(k) for k in ("status", "ext") if k in kw})
    return pw.do_rank(db, s, tmp_path / "rank.md", tmp_path / "rank.json", 20, **kw)


def test_rank_single_packages_and_scenarios(tmp_path):
    st, detail, res = rank(tmp_path)
    by = {o["option"]: o for o in res["ranking"]}
    assert [o["option"] for o in res["ranking"]] == ["libopencv-dev", "cups", "desktop", "build-essential"]
    o = by["libopencv-dev"]
    # hdf5 的兩個二進位套件：103 跟著 opencv 走；hl 本來就沒有套件需要（autoremove）→ 整個 hdf5 少掉，但 hl 不算這個選項拿掉的
    assert (o["rows"], o["exploitable"], o["tiers"]) == (108, 10, {"p2": 52, "p3": 56})
    assert o["removed"] == ["libhdf5-103-1t64", "libopencv-contrib406t64", "libopencv-dev"] and o["partial"] == []
    assert by["cups"]["partial"] == [] and by["cups"]["removed"] == ["cups"]
    assert by["build-essential"]["components"] == ["binutils 1"]
    sc = {o["kind"]: o for o in res["scenarios"]}
    assert sc["autoremove"]["removed"] == ["libhdf5-hl-100t64"] and sc["autoremove"]["rows"] == 0
    assert sc["no-recommends"]["removed"] == ["libsoup-3.0-0"] and sc["no-recommends"]["rows"] == 9
    assert sc["no-dev"]["rows"] == 115 and "libc6" not in sc["no-dev"]["removed"]      # 基本套件不會被 autoremove
    assert st == "ATTENTION" and res["not_in_dpkg"] == ["ghost"]                        # ghost：dpkg 裡找不到
    md = (tmp_path / "rank.md").read_text(encoding="utf-8")
    assert "| libopencv-dev | 108 | 10 | P2 52、P3 56 | 3 |" in md and "不是**實際測過" in md
    assert json.loads((tmp_path / "rank.json").read_text(encoding="utf-8"))["schema"] == "sca-center-pkg-rank/1"


def test_rank_alternatives_and_essential():
    """Depends: a | b：只拿掉 a 時 b 還在，依賴沒壞；Essential 套件依賴的被拿掉 → 不可行。"""
    status = "\n\n".join([
        para("app", depends="liba | libb"), para("liba", source="srca"), para("libb", source="srcb"),
        para("tool", source="srct"),
        "Package: ess\nStatus: install ok installed\nPriority: required\nEssential: yes\nArchitecture: arm64\nVersion: 1\nDepends: tool",
    ]) + "\n"
    db = pw.PkgDB(status, "")
    assert db.removal({"liba"}) == {"liba"}
    assert db.removal({"liba", "libb"}) >= {"liba", "libb", "app"}
    ben = pw.Benefit(db, [comp("srct", 4), comp("srca", 2)])
    o = pw.option(db, ben, "tool", "remove", {"tool"}, db.removal({"tool"}))
    assert not o["feasible"] and o["blocked_by_essential"] == ["ess"] and o["rows"] == 4


def test_rank_rebase(tmp_path):
    base = mkdb(tmp_path / "base", status="\n\n".join([para("libc6", "2.39", source="glibc", priority="required"),
                                                        para("python3.12", priority="important"), para("busybox")]) + "\n", ext=None)
    keep = tmp_path / "keep.txt"
    keep.write_text("# 產品要的\nmyapp\ncups:arm64\nnot-installed\n", encoding="utf-8")
    st, _, res = rank(tmp_path, base_pkgdb=base, keep=keep)
    r = res["rebase"]
    assert r["kind"] == "rebase" and r["feasible"] and r["added"] == ["busybox"] and r["keep_not_installed"] == ["not-installed"]
    assert {"desktop", "libsoup-3.0-0", "libopencv-dev", "gcc-13"} <= set(r["removed"]) and not {"myapp", "cups", "libc6"} & set(r["removed"])
    assert r["rows"] == 108 + 9 + 7          # hdf5、libsoup3、binutils；cups 留著
    md = (tmp_path / "rank.md").read_text(encoding="utf-8")
    assert "## 換基底" in md and "busybox" in md and "not-installed" in md


def test_rank_without_ext_and_cli_errors(tmp_path):
    st, detail, res = rank(tmp_path, ext=None)
    assert st == "ATTENTION" and "推定" in detail and not res["has_extended_states"]
    assert "沒有 extended_states" in (tmp_path / "rank.md").read_text(encoding="utf-8")
    s = tmp_path / "summary.json"
    r = cli("rank", "--pkgdb", str(tmp_path / "db"), "--summary", str(s), "--out", str(tmp_path / "x.md"), "--base-pkgdb", str(tmp_path / "db"))
    assert r.returncode == 3 and r.stdout.startswith("D-pkg-rank\tFAIL\t") and "--keep" in r.stdout
    r = cli("rank", "--pkgdb", str(tmp_path / "nope"), "--summary", str(s), "--out", str(tmp_path / "x.md"))
    assert r.returncode == 0 and r.stdout.startswith("D-pkg-rank\tGAP\t")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"vex": {"gate": {"open_components": [1, {"component": "x", "rows": True}]}}}), encoding="utf-8")
    r = cli("rank", "--pkgdb", str(tmp_path / "db"), "--summary", str(bad), "--out", str(tmp_path / "x.md"))
    assert r.stdout.startswith("D-pkg-rank\tATTENTION\t"), r.stdout


def test_rank_no_recommends_keeps_base_dependencies(tmp_path):
    """基本套件被標成連帶安裝（debootstrap 常見）：它依賴的套件不能算成「不裝 Recommends 就少掉」。"""
    status = "\n\n".join([para("app"), para("netutil", priority="important", depends="libnet"),
                          para("libnet", source="net"), para("libextra", source="extra"), para("gui", recommends="libextra")]) + "\n"
    ext = "\n\n".join(f"Package: {n}\nArchitecture: arm64\nAuto-Installed: 1" for n in ("netutil", "libnet", "libextra")) + "\n"
    summary = {"vex": {"gate": {"open_components": [comp("net", 5), comp("extra", 2)]}}}
    _, _, res = rank(tmp_path, summary=summary, status=status, ext=ext)
    sc = {o["kind"]: o for o in res["scenarios"]}
    assert sc["no-recommends"]["removed"] == ["libextra"] and sc["no-recommends"]["rows"] == 2


def test_rank_rebase_version_changed_and_scope(tmp_path):
    """候選基底有同名不同版本的套件：不算少掉也不算留下、另列；摘要寫明新映像的列沒有評估；keep 有沒裝的 → ATTENTION。"""
    base = mkdb(tmp_path / "base", status="\n\n".join([para("libc6", "2.39", source="glibc", priority="required"),
                                                      para("cups", "2.5.0-1"), para("python3.12", priority="important")]) + "\n", ext=None)
    keep = tmp_path / "keep.txt"
    keep.write_text("myapp\n", encoding="utf-8")
    st, detail, res = rank(tmp_path, base_pkgdb=base, keep=keep)
    r = res["rebase"]
    assert r["version_changed"] == ["cups", "libc6", "python3.12"] and {"component": "cups 1", "rows": 11} in r["version_changed_rows"]
    assert "cups" not in r["removed"] and "新映像的列未評估" in detail and st == "ATTENTION"     # ghost 不在 dpkg
    md = (tmp_path / "rank.md").read_text(encoding="utf-8")
    assert "同名、不同版本的套件 3 個" in md and "新映像自己的列沒有評估" in md
    assert res["open_rows_not_deb"] == 51 and "另有 51 列" in md and "不是去重的 CVE 數" in md
    keep.write_text("myapp\nnot-installed\n", encoding="utf-8")
    good = {"vex": {"gate": {"open_components": [comp("cups", 11)]}}}
    (tmp_path / "k").mkdir()
    st, _, res = rank(tmp_path / "k", summary=good, base_pkgdb=base, keep=keep)
    assert st == "ATTENTION" and res["rebase"]["keep_not_installed"] == ["not-installed"]


def test_read_db_file_nonblocking_open_rejects_swapped_fifo(tmp_path, monkeypatch):
    # lstat 看到一般檔案、open 時已換成 FIFO：O_NONBLOCK 讓 open 不會卡住等寫入端，fstat 再擋下（不讀）
    import os
    import signal
    import stat as st_mod
    import pytest
    reg = tmp_path / "reg"
    reg.write_text("Package: a\n", encoding="utf-8")
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    real_lstat, real_open, flags = os.lstat, os.open, []
    monkeypatch.setattr(pw.os, "lstat", lambda p: real_lstat(reg) if Path(p) == fifo else real_lstat(p))

    def spy(p, f, *a):
        flags.append(f)
        return real_open(p, f, *a)
    monkeypatch.setattr(pw.os, "open", spy)
    old = signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(TimeoutError("open blocked on FIFO")))
    signal.alarm(5)
    try:
        with pytest.raises(pw.Fail, match="不是一般檔案"):
            pw.read_db_file(fifo)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    assert flags and flags[0] & os.O_NONBLOCK and flags[0] & os.O_NOFOLLOW
    assert st_mod.S_ISFIFO(real_lstat(fifo).st_mode)
    # 一般檔案照常讀得到（O_NONBLOCK 不影響一般檔案）
    assert pw.read_db_file(reg) == "Package: a\n"


def test_extract_writes_complete_rootfs_listing(tmp_path):
    ar = tmp_path / "flash.tbz2"
    tar_with(ar, [("Linux_for_Tegra/rootfs_other/usr/bin/other", "x"), ("Linux_for_Tegra/rootfs/var/lib/dpkg/status", STATUS),
                  ("Linux_for_Tegra/rootfs/usr/bin/tool", "x"), ("Linux_for_Tegra/rootfs/bin", (tarfile.SYMTYPE, "usr/bin")),
                  ("Linux_for_Tegra/rootfs/usr/bin/alias", (tarfile.LNKTYPE, "Linux_for_Tegra/rootfs/usr/bin/tool"))], mode="w:bz2")
    r = cli("extract", "--from", str(ar), "--prefix", "Linux_for_Tegra/rootfs", "--out", str(tmp_path / "o"))
    assert r.returncode == 0, r.stdout + r.stderr
    lines = (tmp_path / "o" / "rootfs-files").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "#complete" and "file\t/usr/bin/tool\t" in lines and "symlink\t/bin\tusr/bin" in lines
    assert "hardlink\t/usr/bin/alias\t/usr/bin/tool" in lines and not any("/rootfs_other" in x or "usr/bin/other" in x for x in lines)
    # 資料夾來源：包含不是 dpkg 管理的檔案
    root = tmp_path / "rootfs"
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text(STATUS, encoding="utf-8")
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/handmade").write_text("x")
    r = cli("extract", "--from", str(root), "--out", str(tmp_path / "d"))
    d = (tmp_path / "d" / "rootfs-files").read_text(encoding="utf-8").splitlines()
    assert d[0] == "#complete" and "file\t/usr/bin/handmade\t" in d
