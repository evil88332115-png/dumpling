"""C-pyver／B-pyver 的接線：改過版本（Debian 打包的 Python 模組的佔位值版本 → dpkg 擁有者的上游版本）的 SBOM 副本才是 Grype 與 DT 收到的；
失敗 → GAP 並照用沒有改過的 SBOM（不靜默）；原始 SBOM 原樣保留。
做法：把 sca-scan／scan-flash-package.sh 裡的區塊原文抽出來，用假的 status 函式在 bash 裡真的執行（py_dpkg_version.py 是真的）。"""
import json
import re
import subprocess
import sys
from pathlib import Path

PILOT = Path(__file__).resolve().parents[1]
ROOT = PILOT.parents[1]
sys.path.insert(0, str(PILOT / "lib"))
sys.path.insert(0, str(ROOT / "tools" / "cra"))
import distro_recheck as dr  # noqa: E402
import py_dpkg_version as pv  # noqa: E402
import ubuntu_status as us  # noqa: E402

SCAN = (PILOT / "sca-scan").read_text(encoding="utf-8")
FLASH = (ROOT / "tools" / "demo" / "scan-flash-package.sh").read_text(encoding="utf-8")
DP = "usr/lib/python3/dist-packages"


def block(text, start, end):
    i = text.index(start)
    return text[i:text.index(end, i)]


def bom():
    def py(name, ver):
        return {"type": "library", "name": name, "version": ver, "purl": f"pkg:pypi/{name}@{ver}",
                "properties": [{"name": "syft:location:0:path", "value": f"/{DP}/{name}-{ver}.egg-info/PKG-INFO"}]}
    return {"bomFormat": "CycloneDX", "components": [py("mpmath", "0.0.0"), py("orphan", "0.0.0")]}


def resolved_doc():
    return {"schema": pv.SCHEMA, "components": [
        {"path": f"/{DP}/mpmath-0.0.0.egg-info/PKG-INFO", "name": "mpmath", "state": "RESOLVED", "version": "1.2.1", "original_version": "0.0.0",
         "dpkg": {"name": "python3-mpmath", "version": "1.2.1-3", "upstream": "1.2.1"}, "reason": "dpkg:python3-mpmath 1.2.1-3; __version__ 1.2.1 agrees"},
        {"path": f"/{DP}/orphan-0.0.0.egg-info/PKG-INFO", "name": "orphan", "state": "NOT_OWNED", "version": None,
         "original_version": "0.0.0", "dpkg": None, "reason": "no dpkg package lists this file"}]}


def run_scan_block(tmp, resolved_path):
    out, work = tmp / "out", tmp / "work"
    (out / "sbom").mkdir(parents=True)
    work.mkdir()
    sbom = out / "sbom" / "sbom.cdx.json"
    sbom.write_text(json.dumps(bom()))
    (work / "bom.cdx.json").write_text(sbom.read_text())
    code = block(SCAN, 'rm -f "$OUT/sbom/sbom.pyver.cdx.json"', "# Jetson Linux（L4T）的核心")
    script = f'status(){{ printf "%s\\t%s\\t%s\\n" "$@" >> {tmp}/status.tsv; }}\nROOT={ROOT}; OUT={out}; WORK={work}; SBOM_OK=1\nBOMW={work}/bom.cdx.json; PYVERS={resolved_path}\n{code}\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    rows = [line.split("\t") for line in (tmp / "status.tsv").read_text().splitlines()]
    return sbom, work / "bom.cdx.json", out / "sbom" / "sbom.pyver.cdx.json", rows


def test_patched_sbom_is_what_grype_and_dt_get(tmp_path):
    rp = tmp_path / "pv.json"
    rp.write_text(json.dumps(resolved_doc()))
    sbom, bomw, kept, rows = run_scan_block(tmp_path, rp)
    # 原始 SBOM 原樣保留（證據）；$BOMW（Grype、sbomgate、DT 上傳都用它）是改過版本的副本；另存一份給人看
    assert json.loads(sbom.read_text()) == bom()
    w = {c["name"]: c for c in json.loads(bomw.read_text())["components"]}
    assert w["mpmath"]["version"] == "1.2.1" and w["mpmath"]["purl"] == "pkg:pypi/mpmath@1.2.1"
    assert {p["name"]: p["value"] for p in w["mpmath"]["properties"]}["sca:original-version"] == "0.0.0"
    assert w["orphan"]["version"] == "0.0.0"                      # NOT_OWNED：版本不動（規則 13）
    assert json.loads(kept.read_text()) == json.loads(bomw.read_text())
    assert len(rows) == 1 and rows[0][0] == "C-pyver" and rows[0][1] == "GAP"      # 還有 orphan 是佔位值 → GAP，不是 OK
    assert "orphan" in rows[0][2] and "resolved 1" in rows[0][2]


def test_all_resolved_is_ok(tmp_path):
    d = resolved_doc()
    d["components"] = d["components"][:1]
    b = bom()
    b["components"] = b["components"][:1]
    rp = tmp_path / "pv.json"
    rp.write_text(json.dumps(d))
    out = tmp_path / "x"
    (out / "sbom").mkdir(parents=True)
    # 同 run_scan_block，但只有 mpmath
    work = tmp_path / "w"
    work.mkdir()
    (work / "bom.cdx.json").write_text(json.dumps(b))
    code = block(SCAN, 'rm -f "$OUT/sbom/sbom.pyver.cdx.json"', "# Jetson Linux（L4T）的核心")
    script = f'status(){{ printf "%s\\t%s\\n" "$1" "$2"; }}\nROOT={ROOT}; OUT={out}; WORK={work}; SBOM_OK=1\nBOMW={work}/bom.cdx.json; PYVERS={rp}\n{code}\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.stdout.strip() == "C-pyver\tOK"


def test_failure_is_gap_and_unpatched_sbom_continues(tmp_path):
    rp = tmp_path / "pv.json"
    rp.write_text("not json")
    sbom, bomw, kept, rows = run_scan_block(tmp_path, rp)
    assert json.loads(bomw.read_text()) == bom()                  # 沒有改過的 SBOM 繼續比對
    assert not kept.exists()
    assert len(rows) == 1 and rows[0][:2] == ["C-pyver", "GAP"] and "照原本的 SBOM 比對" in rows[0][2]


def test_sca_scan_order_and_consumers():
    """C-pyver 在 Grype 與 DT 上傳之前；Grype、sbomgate、上傳用的都是 $BOMW；選項只接受 --image／--sbom。"""
    i = SCAN.index("C-pyver")
    assert i < SCAN.index('grype "sbom:$BOMW"') and i < SCAN.index("C-upload-sbom") and i < SCAN.index("l4t_kernel.py")
    assert 'grype "sbom:$BOMW"' in SCAN and "strip_versions.py\" \"$BOMW\"" in SCAN
    assert "--py-versions 只用於 --image 或 --sbom" in SCAN
    assert '--py-versions "$PYVERS"' in SCAN                       # ubuntu_status 也收到


def run_pyver_step(tmp, script_path, make_db=True):
    out = tmp / "out"
    (out / "rootfs" / "pkgdb").mkdir(parents=True)
    (out / "rootfs" / "logs").mkdir(parents=True)
    (out / "rootfs" / "pkgdb" / "python-versions.json").write_text("stale")
    if make_db:
        (out / "rootfs" / "pkgdb" / "dpkg-status").write_text("Package: x\nStatus: install ok installed\nVersion: 1\n")
    code = block(FLASH, "pyver_step(){", "\nimgcheck_step(){")
    script = (f'status(){{ printf "%s\\t%s\\t%s\\n" "$@" >> {tmp}/status.tsv; }}\nROOT={ROOT}; OUT={out}\n{code}\n'
              f'pyver_step rootfs {script_path}\n')
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    f = tmp / "status.tsv"
    return out, [x.split("\t") for x in f.read_text().splitlines()] if f.exists() else []


def test_pyver_step_failure_is_gap_and_removes_stale_file(tmp_path):
    out, rows = run_pyver_step(tmp_path, tmp_path / "does-not-exist")
    assert not (out / "rootfs" / "pkgdb" / "python-versions.json").exists()      # 不留上一次的檔案冒充這次的
    assert len(rows) == 1 and rows[0][:2] == ["B-pyver-rootfs", "GAP"] and "沒有改過的 SBOM" in rows[0][2]


def test_pyver_step_ok_keeps_json(tmp_path):
    rootfs = tmp_path / "src"
    (rootfs / "var/lib/dpkg").mkdir(parents=True)
    (rootfs / "var/lib/dpkg/status").write_text("")
    out, rows = run_pyver_step(tmp_path, rootfs)
    d = json.loads((out / "rootfs" / "pkgdb" / "python-versions.json").read_text())
    assert d["schema"] == pv.SCHEMA and rows[0][0] == "B-pyver-rootfs"
    # 沒有 Python metadata → 沒有可解析的東西，但狀態是照實回報（GAP：沒有 dpkg-file-owners 的 metadata 檔數是 0）
    assert rows[0][1] in ("OK", "GAP")


def test_sca_args_passes_py_versions_when_file_exists(tmp_path):
    code = block(FLASH, "sca_args(){", "\n\n# ---------- A.")
    d = tmp_path / "d"
    (d / "pkgdb").mkdir(parents=True)
    script = f'LICENSE=1; NOUP=0; D={d}\n{code}\nsca_args; echo "${{SCA_ARGS[*]}}"\n'
    assert "--py-versions" not in subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout
    (d / "pkgdb" / "python-versions.json").write_text("{}")
    assert f"--py-versions {d}/pkgdb/python-versions.json" in subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout


# ---------- pyres 給另外兩個 deb_python_index 呼叫端 ----------

U24 = "distro=ubuntu-24.04"


def test_ubuntu_status_links_python_module_by_file_ownership():
    deb = f"pkg:deb/ubuntu/python3-mpm@1.2.1-3?arch=all&upstream=mp-src&{U24}"
    sbom = {"components": [{"type": "library", "name": "python3-mpm", "version": "1.2.1-3", "purl": deb},
                           bom()["components"][0]]}
    finding = {"component": {"purl": "pkg:pypi/mpmath@0.0.0"}, "vulnerability": {"vulnId": "CVE-2021-29063", "source": "NVD"}}
    d = dr
    comps, pairs, cnt = us.wanted([finding], sbom, us.drc())
    assert not comps and cnt["deb_python_owners"] == 0            # deb 名稱和 Python 名稱對不起來
    doc = resolved_doc()
    doc["components"][0]["dpkg"]["name"] = "python3-mpm"
    comps, pairs, cnt = us.wanted([finding], sbom, us.drc(), pv.by_path(doc))
    assert deb in comps and cnt["deb_python_owners"] == 1 and ("CVE-2021-29063", "mp-src", "noble") in pairs
    assert d is not None


def test_exploited_grype_passes_pyres():
    s = (ROOT / "tools" / "cra" / "exploited_grype.py").read_text(encoding="utf-8")
    assert 'cr.deb_python_index(pkgs, ctx.get("pyres"))' in s and "python-versions.json" in s
