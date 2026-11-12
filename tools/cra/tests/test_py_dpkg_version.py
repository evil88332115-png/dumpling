"""py_dpkg_version.py：Debian 打包的 Python 模組 egg-info 版本是佔位值（0.0.0）時，用擁有它的 dpkg 套件的上游版本。

合成的 rootfs（資料夾與 tar 兩種來源）：dpkg status、info/*.list（含 :arch 後綴）、egg-info／dist-info、__init__.py。
情況：解出來（含 epoch 與 Debian revision 去掉）、與 __version__ 不一致 → 仍然未知、沒有 dpkg 擁有 → 仍然未知（規則 13 不變）、
真實版本不動、SBOM 副本只改 RESOLVED。
"""
import io
import json
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cra_report as cr  # noqa: E402
import pkg_why  # noqa: E402
import py_dpkg_version as pv  # noqa: E402

DP = "usr/lib/python3/dist-packages"

STATUS = """Package: python3-mpmath
Status: install ok installed
Architecture: all
Version: 1.2.1-3

Package: python3-epoch
Status: install ok installed
Architecture: all
Version: 2:3.4.5+dfsg-1ubuntu2

Package: python3-clash
Status: install ok installed
Architecture: all
Version: 9.9.9-1

Package: python3-kiwisolver
Status: install ok installed
Architecture: arm64
Version: 1.4.4-2build1

Package: python3-removed
Status: deinstall ok config-files
Architecture: all
Version: 1.0-1
"""
FILES = {
    # 解出來：egg-info 是資料夾（PKG-INFO），__init__.py 的 __version__ 與 dpkg 一致
    f"{DP}/mpmath-0.0.0.egg-info/PKG-INFO": "Metadata-Version: 1.2\nName: mpmath\nVersion: 0.0.0\n",
    f"{DP}/mpmath/__init__.py": "'''doc'''\n__version__ = '1.2.1'\n",
    # epoch 與 revision：2:3.4.5+dfsg-1ubuntu2 → 3.4.5；沒有 __init__ → 不能交叉核對
    f"{DP}/epoch-0.egg-info": "Metadata-Version: 1.1\nName: epoch\nVersion: 0\n",
    # 不一致：dpkg 說 9.9.9，__version__ 是 9.9.8
    f"{DP}/clash-0.0.egg-info/PKG-INFO": "Name: clash\nVersion: 0.0\n",
    f"{DP}/clash/__init__.py": "__version__ = \"9.9.8\"\n",
    # 沒有 dpkg 擁有（pip 另裝）
    f"{DP}/pipped-0.0.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: pipped\nVersion: 0.0.0\n",
    f"{DP}/pipped/__init__.py": "__version__ = '1.0.0'\n",
    # 擁有者在 dpkg status 是 deinstall → 不算
    f"{DP}/removed-0.0.0.egg-info/PKG-INFO": "Name: removed\nVersion: 0.0.0\n",
    # 真實版本：不處理
    f"{DP}/real-1.5.egg-info/PKG-INFO": "Name: real\nVersion: 1.5\n",
    # dist-info + :arch 後綴的 list
    f"{DP}/kiwisolver-0.0.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: kiwisolver\nVersion: 0.0.0\n",
}
LISTS = {
    "python3-mpmath.list": [f"/{DP}/mpmath-0.0.0.egg-info/PKG-INFO"],
    "python3-epoch.list": [f"/{DP}/epoch-0.egg-info"],
    "python3-clash.list": [f"/{DP}/clash-0.0.egg-info/PKG-INFO"],
    "python3-removed.list": [f"/{DP}/removed-0.0.0.egg-info/PKG-INFO"],
    "python3-kiwisolver:arm64.list": [f"/{DP}/kiwisolver-0.0.0.dist-info/METADATA"],
    "python3-real.list": [f"/{DP}/real-1.5.egg-info/PKG-INFO"],
}


def make_rootfs(root, with_lists=True):
    for rel, text in FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    info = root / "var/lib/dpkg/info"
    info.mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text(STATUS)
    if with_lists:
        for n, paths in LISTS.items():
            (info / n).write_text("\n".join(["/.", "/usr"] + paths) + "\n")
    return root


def make_pkgdb(tmp, rootfs):
    out = tmp / "pkgdb"
    r = pkg_why.do_extract(str(rootfs), None, str(out))
    assert r[0] == "OK"
    return out


def by_name(doc):
    return {c["name"]: c for c in doc["components"]}


def test_resolve_directory(tmp_path):
    rootfs = make_rootfs(tmp_path / "rootfs")
    pk = make_pkgdb(tmp_path, rootfs)
    doc = pv.scan(str(rootfs), None, pk, tmp_path / "pv.json")
    c = by_name(doc)
    assert doc["counts"]["metadata_files"] == 7 and doc["counts"]["placeholder"] == 6      # real-1.5 不算
    assert "real" not in c
    assert c["mpmath"]["state"] == "RESOLVED" and c["mpmath"]["version"] == "1.2.1"
    assert c["mpmath"]["dpkg"] == {"name": "python3-mpmath", "version": "1.2.1-3", "upstream": "1.2.1"}
    assert c["mpmath"]["init_version"] == "1.2.1" and c["mpmath"]["original_version"] == "0.0.0"
    # epoch + revision + +dfsg 去掉；版本 "0"（單一檔案 egg-info）也是佔位值；沒有 __init__ 就只靠 dpkg
    assert c["epoch"]["state"] == "RESOLVED" and c["epoch"]["version"] == "3.4.5" and c["epoch"]["init_version"] is None
    # :arch 後綴
    assert c["kiwisolver"]["state"] == "RESOLVED" and c["kiwisolver"]["version"] == "1.4.4"
    # 不一致 → 仍然未知，兩個值都記
    assert c["clash"]["state"] == "DISAGREE" and c["clash"]["version"] is None
    assert c["clash"]["dpkg"]["upstream"] == "9.9.9" and c["clash"]["init_version"] == "9.9.8"
    # 沒有 dpkg 擁有、或擁有者不是已安裝 → 仍然未知
    assert c["pipped"]["state"] == "NOT_OWNED" and c["pipped"]["version"] is None
    assert c["removed"]["state"] == "NOT_OWNED" and c["removed"]["version"] is None
    assert json.loads((tmp_path / "pv.json").read_text())["schema"] == pv.SCHEMA


def test_no_owner_list_is_gap_not_resolved(tmp_path):
    rootfs = make_rootfs(tmp_path / "rootfs", with_lists=False)
    pk = make_pkgdb(tmp_path, rootfs)
    doc = pv.scan(str(rootfs), None, pk, tmp_path / "pv.json")
    assert doc["counts"]["resolved"] == 0 and doc["counts"]["no_owner_data"] == doc["counts"]["placeholder"] == 6
    assert all(c["version"] is None for c in doc["components"])


def test_tar_source_same_result(tmp_path):
    rootfs = make_rootfs(tmp_path / "rootfs")
    pk = make_pkgdb(tmp_path, rootfs)
    tp = tmp_path / "rootfs.tar"
    with tarfile.open(tp, "w") as t:
        for rel in FILES:
            data = (rootfs / rel).read_bytes()
            ti = tarfile.TarInfo("./" + rel)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        ti = tarfile.TarInfo("./" + DP + "/evil.egg-info")      # 符號連結：不讀
        ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/shadow"
        t.addfile(ti)
    doc = pv.scan(str(tp), None, pk, tmp_path / "pv2.json")
    d2 = pv.scan(str(rootfs), None, pk, tmp_path / "pv1.json")
    assert {(c["name"], c["state"], c["version"]) for c in doc["components"]} == {(c["name"], c["state"], c["version"]) for c in d2["components"]}
    assert "evil" not in by_name(doc)


def test_upstream_version_rules():
    assert pv.deb_upstream("1.2.1-3") == "1.2.1"
    assert pv.deb_upstream("1:1.2.1-3") == "1.2.1"
    assert pv.deb_upstream("2.31.0+dfsg-1ubuntu1") == "2.31.0"
    assert pv.deb_upstream("1.4.4-2build1") == "1.4.4"
    assert pv.deb_upstream("3.0") == "3.0"          # 沒有 revision（native）
    assert all(pv.is_placeholder(x) for x in ("", "0", "0.0", "0.0.0", None)) and not pv.is_placeholder("0.1.0")


def sbom():
    def py(name, ver, path):
        return {"type": "library", "name": name, "version": ver, "purl": f"pkg:pypi/{name}@{ver}", "bom-ref": f"pkg:pypi/{name}@{ver}?package-id=x",
                "cpe": f"cpe:2.3:a:{name}:{name}:{ver}:*:*:*:*:*:*:*",
                "properties": [{"name": "syft:cpe23", "value": f"cpe:2.3:a:{name}:{name}:{ver}:*:*:*:*:*:*:*"},
                               {"name": "syft:location:0:path", "value": "/" + path}]}
    return {"components": [py("mpmath", "0.0.0", f"{DP}/mpmath-0.0.0.egg-info/PKG-INFO"),
                           py("clash", "0.0", f"{DP}/clash-0.0.egg-info/PKG-INFO"),
                           py("pipped", "0.0.0", f"{DP}/pipped-0.0.0.dist-info/METADATA"),
                           py("real", "1.5", f"{DP}/real-1.5.egg-info/PKG-INFO")]}


def test_patch_sbom_only_resolved(tmp_path):
    rootfs = make_rootfs(tmp_path / "rootfs")
    pk = make_pkgdb(tmp_path, rootfs)
    doc = pv.scan(str(rootfs), None, pk, tmp_path / "pv.json")
    bom = sbom()
    n = pv.patch_sbom(bom, doc)
    assert n == {"RESOLVED": 1, "DISAGREE": 1, "NOT_OWNED": 1}
    c = {x["name"]: x for x in bom["components"]}
    pr = lambda x: {p["name"]: p["value"] for p in x["properties"] if p["name"].startswith("sca:")}      # noqa: E731
    assert c["mpmath"]["version"] == "1.2.1" and c["mpmath"]["purl"] == "pkg:pypi/mpmath@1.2.1" and "0.0.0" not in c["mpmath"]["cpe"]
    assert not any("0.0.0" in str(p["value"]) for p in c["mpmath"]["properties"] if p["name"] == "syft:cpe23")
    assert pr(c["mpmath"])["sca:version-source"] == "dpkg:python3-mpmath 1.2.1-3" and pr(c["mpmath"])["sca:original-version"] == "0.0.0"
    # 不一致與沒有擁有者：版本、purl 不動（規則 13：版本仍然未知，不猜），只記判定
    assert c["clash"]["version"] == "0.0" and c["clash"]["purl"] == "pkg:pypi/clash@0.0"
    assert list(pr(c["clash"])) == ["sca:version-resolution"] and pr(c["clash"])["sca:version-resolution"].startswith("DISAGREE")
    assert c["pipped"]["version"] == "0.0.0" and pr(c["pipped"])["sca:version-resolution"].startswith("NOT_OWNED")
    assert c["real"]["version"] == "1.5" and not pr(c["real"])


def test_deb_python_index_uses_file_ownership():
    """名稱對不到（deb 叫 python3-mpm，不是 python3-mpmath）也能靠 dpkg 的 .list 找到擁有者；DISAGREE 不改擁有者判斷。"""
    comps = [{"type": "library", "name": "python3-mpm", "version": "1.2.1-3", "purl": "pkg:deb/ubuntu/python3-mpm@1.2.1-3?arch=all&distro=ubuntu-24.04"}]
    comps += sbom()["components"][:1]
    base = cr.deb_python_index(comps)[0]
    assert base["pkg:pypi/mpmath@0.0.0"]["owner"] is None            # 名稱邏輯找不到
    doc = {"schema": pv.SCHEMA, "components": [{"path": f"/{DP}/mpmath-0.0.0.egg-info/PKG-INFO", "state": "RESOLVED", "version": "1.2.1",
                                                "original_version": "0.0.0", "dpkg": {"name": "python3-mpm", "version": "1.2.1-3"}}]}
    got = cr.deb_python_index(comps, pv.by_path(doc))[0]["pkg:pypi/mpmath@0.0.0"]
    assert got["owner"]["name"] == "python3-mpm" and got["owner"]["version"] == "1.2.1-3"
    assert got["version_resolution"]["version"] == "1.2.1"
    doc["components"][0]["state"] = "DISAGREE"
    got = cr.deb_python_index(comps, pv.by_path(doc))[0]["pkg:pypi/mpmath@0.0.0"]
    assert got["owner"] is None and got["version_resolution"]["state"] == "DISAGREE"
    r = {"version": "0.0.0", "deb_python": {"owner": None, "version_resolution": dict(doc["components"][0], reason="x")}}
    assert cr.version_text(r).startswith("unknown (")
    r["deb_python"]["version_resolution"]["state"] = "RESOLVED"
    assert cr.version_text(r).startswith("1.2.1 (from dpkg python3-mpm 1.2.1-3; Python metadata said 0.0.0; presumed")


def test_patch_sbom_updates_dependencies_and_empty_version():
    """bom-ref 換了，dependencies[].ref 與 dependsOn、compositions 的參照要跟著換（不留懸空參照）；原本沒有版本的 purl 要插入 @版本。"""
    ref = "pkg:pypi/mpmath@0.0.0?package-id=aa"
    c1 = {"type": "library", "name": "mpmath", "version": "0.0.0", "purl": "pkg:pypi/mpmath@0.0.0", "bom-ref": ref,
          "properties": [{"name": "syft:location:0:path", "value": f"/{DP}/mpmath-0.0.0.egg-info/PKG-INFO"}]}
    c2 = {"type": "library", "name": "empty", "version": "", "purl": "pkg:pypi/empty?arch=x", "bom-ref": "pkg:pypi/empty?package-id=bb",
          "properties": [{"name": "syft:location:0:path", "value": f"/{DP}/empty.egg-info/PKG-INFO"}]}
    c3 = {"type": "library", "name": "scipy", "version": "1.0", "purl": "pkg:pypi/scipy@1.0", "bom-ref": "pkg:pypi/scipy@1.0?package-id=cc"}
    bom = {"components": [c1, c2, c3],
           "dependencies": [{"ref": c3["bom-ref"], "dependsOn": [ref, c2["bom-ref"]]}, {"ref": ref, "dependsOn": []}, {"ref": c2["bom-ref"]}],
           "compositions": [{"assemblies": [ref]}]}
    doc = {"schema": pv.SCHEMA, "components": [
        {"path": f"/{DP}/mpmath-0.0.0.egg-info/PKG-INFO", "state": "RESOLVED", "version": "1.2.1", "original_version": "0.0.0",
         "reason": "dpkg:python3-mpmath 1.2.1-3", "init_version": "1.2.1"},
        {"path": f"/{DP}/empty.egg-info/PKG-INFO", "state": "RESOLVED", "version": "2.0", "original_version": None, "reason": "dpkg:python3-empty 2.0-1"}]}
    assert pv.patch_sbom(bom, doc) == {"RESOLVED": 2}
    assert c1["purl"] == "pkg:pypi/mpmath@1.2.1" and c1["bom-ref"] == "pkg:pypi/mpmath@1.2.1?package-id=aa"
    assert c2["purl"] == "pkg:pypi/empty@2.0?arch=x" and c2["bom-ref"] == "pkg:pypi/empty@2.0?package-id=bb" and c2["version"] == "2.0"
    refs = {c["bom-ref"] for c in bom["components"]}
    for d in bom["dependencies"]:
        assert d["ref"] in refs and all(x in refs for x in d.get("dependsOn", []))
    assert bom["compositions"][0]["assemblies"][0] in refs
    assert dict(pv.purl_pairs(bom)) == {"pkg:pypi/mpmath@0.0.0": "pkg:pypi/mpmath@1.2.1", "pkg:pypi/empty?arch=x": "pkg:pypi/empty@2.0?arch=x"}


def test_unsafe_or_placeholder_dpkg_versions_stay_unknown():
    cases = {"2.0+really1.9-1": "UNSURE", "1:2.0.0+really1.9.2-1": "UNSURE", "1.0~rc1-1": "UNSURE", "1.0+git20200101-1": "UNSURE",
             "0.0.0-1": "UNSURE", "0.0.0+dfsg-1": "UNSURE", "1.0rc1-1": "RESOLVED", "1:3.4.5+dfsg-2": "RESOLVED"}
    for i, (dv, want) in enumerate(cases.items()):
        path = f"{DP}/m{i}-0.0.0.egg-info/PKG-INFO"
        out = pv.resolve({path: f"Name: m{i}\nVersion: 0.0.0\n"}, {}, {f"python3-m{i}": {dv}}, {"/" + path: {f"python3-m{i}"}})
        assert out[0]["state"] == want, dv
        assert (out[0]["version"] is None) == (want != "RESOLVED")
        if want == "UNSURE":
            assert out[0]["reason"] and "unknown" in out[0]["reason"]
