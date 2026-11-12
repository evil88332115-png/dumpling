"""Jetson Linux（L4T）核心對應的 Canonical 核心元件（C-kernel-l4t-map，lib/l4t_kernel.py）、下游（kernelcheck、deb_sources、scio_prep）
與 sca-scan 的接線。偵測用已提交的真實 SBOM（tests/fixtures/jetson-r39.2.1-base.cdx.json.xz，Syft 1.55.0）。"""
import importlib.util
import json
import lzma
import re
import subprocess

import pytest

from pilot_fixtures import ALL_OK, PILOT, ROOT, assert_no_conclusion, gmatch, make_out, run_report

LIB = PILOT / "lib" / "l4t_kernel.py"
MAP = PILOT / "lib" / "l4t-kernel-map.json"
FIXTURE = ROOT / "tests" / "fixtures" / "jetson-r39.2.1-base.cdx.json.xz"
KVER = "6.8.12-1021-tegra"
PKGVER = "6.8.12-tegra-39.2.1-20260806224157"
L4T_PURL = f"pkg:deb/ubuntu/nvidia-l4t-kernel@{PKGVER}?arch=arm64&distro=ubuntu-24.04"
CANON = "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"


def deb(name, ver, purl=None):
    return {"type": "library", "name": name, "version": ver,
            "purl": purl or f"pkg:deb/ubuntu/{name}@{ver}?arch=arm64&distro=ubuntu-24.04",
            "properties": [{"name": "syft:package:type", "value": "deb"}]}


def module(name, kver=KVER):
    return {"type": "library", "name": name, "version": "UNKNOWN", "purl": f"pkg:generic/{name}",
            "properties": [{"name": "syft:package:type", "value": "linux-kernel-module"},
                           {"name": "syft:location:0:path", "value": f"/usr/lib/modules/{kver}/kernel/net/{name}.ko"}]}


def jetson(*extra, kver=KVER):
    return {"bomFormat": "CycloneDX", "components": [deb("nvidia-l4t-kernel", PKGVER), deb("nvidia-l4t-kernel-dtbs", PKGVER),
                                                     module("8021q", kver), module("act_gact", kver), deb("openssl", "3.0.13-0ubuntu3.5"),
                                                     *extra]}


def entry(version="6.8.0-1021.21", purl=CANON, evidence="tag jetson_39.2.1", checked="2026-11-02 test", modules=KVER):
    e = {"component": {"name": "linux-nvidia-tegra", "version": version, "purl": purl,
                       "properties": [{"name": "syft:package:type", "value": "deb"}]},
         "evidence": evidence, "checked": checked}
    if modules is not None:
        e["modules_kernel_version"] = modules
    return e


def lib_module():
    spec = importlib.util.spec_from_file_location("l4t_kernel", LIB)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run(tmp_path, sbom=None, mapping=None, raw_sbom=None, raw_map=None, args=None):
    s, m = tmp_path / "sbom.json", tmp_path / "map.json"
    s.write_text(raw_sbom if raw_sbom is not None else json.dumps(sbom), encoding="utf-8")
    if raw_map is not None:
        m.write_text(raw_map, encoding="utf-8")
    elif mapping is None:
        m = MAP                                   # 提交的對應檔
    else:
        m.write_text(json.dumps({"releases": mapping}), encoding="utf-8")
    out, summ = tmp_path / "out.json", tmp_path / "summary.json"
    a = args if args is not None else ["--sbom", str(s), "--map", str(m), "--out-sbom", str(out), "--summary", str(summ)]
    r = subprocess.run(["python3", "-I", str(LIB), *a], capture_output=True, text=True)
    lines = r.stdout.splitlines()
    assert len(lines) == 1, r
    stage, st, detail = lines[0].split("\t")
    assert stage == "C-kernel-l4t-map"
    assert len(detail.encode()) < 480        # status() 說明欄只留 500 位元組
    ev = json.loads(summ.read_text(encoding="utf-8")) if r.returncode == 0 else None
    bom = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
    return r, st, detail, ev, bom


def added(bom):
    return [c for c in bom["components"] if any(p["name"] == "sca-center:matching-only" for p in c.get("properties") or [])]


def test_real_jetson_sbom_detected_and_mapped_with_committed_map(tmp_path):
    sb = json.loads(lzma.decompress(FIXTURE.read_bytes()))
    r, st, detail, ev, bom = run(tmp_path, sb)
    assert r.returncode == 0 and st == "OK"
    assert ev["release"] == "39.2.1" and ev["modules_kernel_versions"] == {KVER: 1468}
    assert ev["l4t_kernel"] == [{"name": "nvidia-l4t-kernel", "version": PKGVER, "purl": L4T_PURL, "release": "39.2.1",
                                 "kernel_version": "6.8.12", "timestamp": "20260806224157"}]
    assert "L4T 39.2.1" in detail and "linux-nvidia-tegra 6.8.0-1021.21" in detail and f"模組目錄 {KVER} 相符" in detail
    (c,) = added(bom)
    assert c["purl"] == CANON and c["version"] == "6.8.0-1021.21"
    pr = {p["name"]: p["value"] for p in c["properties"]}
    assert pr["sca-center:kernel-mapped-from"] == L4T_PURL and pr["sca-center:kernel-map-release"] == "39.2.1"
    assert pr["sca-center:matching-only"] == "true" and pr["syft:metadata:sourceVersion"] == "6.8.0-1021.21"
    assert len(bom["components"]) == len(sb["components"]) + 1
    m = json.loads(MAP.read_text(encoding="utf-8"))["releases"]["39.2.1"]   # 對應檔有出處與核對紀錄
    assert m["evidence"] and m["checked"] and "TODO" not in json.dumps(m)


def test_input_sbom_not_modified(tmp_path):
    sb = jetson()
    run(tmp_path, sb, {"39.2.1": entry()})
    assert json.loads((tmp_path / "sbom.json").read_text(encoding="utf-8")) == sb


@pytest.mark.parametrize("mapping,why", [
    ({}, "l4t-kernel-map.json 沒有 L4T 39.2.1"),
    ({"36.4.3": entry()}, "l4t-kernel-map.json 沒有 L4T 39.2.1"),
    ({"39.2.1": entry(version="TODO", purl="pkg:deb/ubuntu/linux-nvidia-tegra@TODO?arch=source")}, "version、purl 是空的或 TODO"),
    ({"39.2.1": entry(evidence="TODO")}, "evidence 是空的或 TODO"),
    ({"39.2.1": entry(checked="")}, "checked 是空的或 TODO"),
    ({"39.2.1": entry(version="todo", purl="pkg:deb/ubuntu/linux-nvidia-tegra@todo?arch=source")}, "version、purl 是空的或 TODO"),   # 不分大小寫
    ({"39.2.1": entry(modules="Todo")}, "modules_kernel_version 是空的或 TODO"),
])
def test_unmapped_or_todo_release_is_gap(tmp_path, mapping, why):
    (tmp_path / "out.json").write_text("stale", encoding="utf-8")      # 舊的輸出要刪掉
    r, st, detail, ev, bom = run(tmp_path, jetson(), mapping)
    assert r.returncode == 0 and st == "GAP" and why in detail and "L4T 39.2.1" in detail and "C-kernel-coverage" in detail
    assert bom is None and ev["added"] is None and ev["release"] == "39.2.1"


def test_modules_dir_mismatch_is_gap_and_no_modules_is_not_checked(tmp_path):
    r, st, detail, _, bom = run(tmp_path, jetson(kver="6.8.12-1022-tegra"), {"39.2.1": entry()})
    assert st == "GAP" and "6.8.12-1022-tegra" in detail and f"預期 {KVER}" in detail and bom is None
    sb = jetson()
    sb["components"] = [c for c in sb["components"] if c["purl"].startswith("pkg:deb/")]
    r, st, detail, _, bom = run(tmp_path, sb, {"39.2.1": entry()})
    assert st == "OK" and "沒有核心模組，未核對模組目錄" in detail and len(added(bom)) == 1


def test_already_present_is_not_duplicated(tmp_path):
    r, st, detail, ev, bom = run(tmp_path, jetson(deb("linux-nvidia-tegra", "6.8.0-1021.21", CANON)), {"39.2.1": entry()})
    assert st == "OK" and "不重複加" in detail and ev["already_present"] and ev["added"] is None
    assert [c["name"] for c in bom["components"]].count("linux-nvidia-tegra") == 1 and not added(bom)


@pytest.mark.parametrize("binary", [
    # 映像另外裝了 Canonical 的核心：Syft 記下原始碼套件（syft:metadata:source／sourceVersion）
    dict(deb("linux-image-6.8.0-1021-nvidia-tegra", "6.8.0-1021.21"),
         properties=[{"name": "syft:package:type", "value": "deb"}, {"name": "syft:metadata:source", "value": "linux-nvidia-tegra"},
                     {"name": "syft:metadata:sourceVersion", "value": "6.8.0-1021.21"}]),
    # 或只有 purl 的 upstream qualifier（版本沒寫時同二進位版本）
    deb("linux-modules-6.8.0-1021-nvidia-tegra", "6.8.0-1021.21",
        "pkg:deb/ubuntu/linux-modules-6.8.0-1021-nvidia-tegra@6.8.0-1021.21?arch=arm64&upstream=linux-nvidia-tegra&distro=ubuntu-24.04"),
])
def test_binary_built_from_mapped_source_is_not_double_counted(tmp_path, binary):
    _, st, detail, ev, bom = run(tmp_path, jetson(binary), {"39.2.1": entry()})
    assert st == "OK" and "已有從它建的套件" in detail and binary["name"] in detail
    assert ev["already_present"] and ev["built_from_source"] == [binary["name"]] and not added(bom)
    # 其他版本建的不算
    other = dict(binary, purl=binary["purl"].replace("1021.21", "1020.20"), version="6.8.0-1020.20",
                 properties=[p for p in binary["properties"] if not p["name"].startswith("syft:metadata:source")])
    _, st, _, _, bom = run(tmp_path, jetson(other), {"39.2.1": entry()})
    assert st == "OK" and len(added(bom)) == 1


def test_committed_map_entries_are_complete_and_valid():
    m = lib_module()
    releases = m.load_map(json.loads(MAP.read_text(encoding="utf-8")))
    assert releases
    for rel, e in releases.items():
        assert re.fullmatch(r"\d+\.\d+\.\d+", rel)
        assert m.entry_problem(rel, e) is None, rel                    # 沒有 TODO、purl 與 name、version 一致、有 arch=source 與 distro
        assert re.fullmatch(r"\d+\.\d+\.\d+-\d+-tegra", e["modules_kernel_version"])
        abi = e["modules_kernel_version"].split("-")[1]                # 模組目錄的 Ubuntu ABI 要和 Canonical 版本相同
        assert re.fullmatch(rf"\d+\.\d+\.\d+-{abi}\.\d+", e["component"]["version"]), rel


@pytest.mark.parametrize("comps", [
    [deb("openssl", "3.0.13"), module("8021q")],
    [deb("nvidia-l4t-kernel-dtbs", PKGVER), deb("nvidia-l4t-kernel-headers", PKGVER)],      # 名稱要正好是 nvidia-l4t-kernel
    [{"type": "library", "name": "nvidia-l4t-kernel", "version": PKGVER, "purl": f"pkg:generic/nvidia-l4t-kernel@{PKGVER}"}],
])
def test_no_l4t_kernel_is_not_run(tmp_path, comps):
    r, st, detail, ev, bom = run(tmp_path, {"components": comps}, {"39.2.1": entry()})
    assert r.returncode == 0 and st == "NOT_RUN" and "SBOM 沒有 nvidia-l4t-kernel" in detail and bom is None


def test_unknown_version_format_or_several_versions_is_gap(tmp_path):
    sb = {"components": [deb("nvidia-l4t-kernel", "6.8.12-tegra-39.2-20260806224157")]}
    _, st, detail, ev, _ = run(tmp_path, sb, {"39.2.1": entry()})
    assert st == "GAP" and "版本格式不認得" in detail and ev["release"] is None
    sb = jetson(deb("nvidia-l4t-kernel", "6.8.12-tegra-39.2.2-20261006224157"))
    _, st, detail, _, bom = run(tmp_path, sb, {"39.2.1": entry()})
    assert st == "GAP" and "2 個不同版本" in detail and bom is None


@pytest.mark.parametrize("raw_sbom,raw_map", [
    ("{not json", None),
    ("[1, 2]", None),
    (json.dumps({"components": "x"}), None),
    (json.dumps(jetson()), "{bad"),
    (json.dumps(jetson()), json.dumps({"releases": []})),
    (json.dumps(jetson()), json.dumps({"releases": {"39.2.1": {"component": "x", "evidence": "e", "checked": "c"}}})),
    (json.dumps(jetson()), json.dumps({"releases": {"39.2.1": dict(entry(), component={"name": "x", "properties": "y"})}})),
    # purl 的名稱或版本和 name、version 不一致：對應檔錯誤
    (json.dumps(jetson()), json.dumps({"releases": {"39.2.1": entry(purl=CANON.replace("1021.21", "1021.22"))}})),
    (json.dumps(jetson()), json.dumps({"releases": {"39.2.1": entry(purl="pkg:generic/linux-nvidia-tegra@6.8.0-1021.21")}})),
    (json.dumps(jetson()), json.dumps({"releases": {"39.2.1": entry(purl=CANON.replace("/ubuntu/", "/debian/"))}})),
    (json.dumps(jetson()), json.dumps({"releases": {"39.2.1": entry(purl=CANON.replace("arch=source&", "arch=arm64&"))}})),
    (json.dumps(jetson()), json.dumps({"releases": {"39.2.1": entry(purl=CANON.split("&")[0])}})),            # 沒有 distro=
    (json.dumps(jetson()), json.dumps({"releases": {"39.2.1": entry(modules=None)}})),                        # modules_kernel_version 必填
])
def test_bad_input_prints_fail_line_exit_3(tmp_path, raw_sbom, raw_map):
    for f in ("summary.json", "out.json"):        # 上一次的輸出：FAIL 時不能留著給 kernelcheck、cra_report 讀
        (tmp_path / f).write_text('{"status": "OK"}', encoding="utf-8")
    r, st, detail, _, bom = run(tmp_path, raw_sbom=raw_sbom, raw_map=raw_map if raw_map is not None else json.dumps({"releases": {"39.2.1": entry()}}))
    assert r.returncode == 3 and st == "FAIL" and "l4t_kernel.py" in detail
    assert "Traceback" not in r.stderr + r.stdout
    assert bom is None and not (tmp_path / "summary.json").exists()


def test_missing_argument_is_exit_3(tmp_path):
    r, st, detail, _, _ = run(tmp_path, jetson(), args=["--sbom", str(tmp_path / "x.json")])
    assert r.returncode == 3 and st == "FAIL" and "參數錯誤" in detail


# ---------- 下游：kernelcheck（讀原始 SBOM）、deb_sources（上傳 DT）、scio_prep（ScanCode.io 不收） ----------

def test_kernelcheck_counts_matches_on_mapped_component_absent_from_original_sbom(tmp_path):
    sb = jetson()
    _, st, _, ev, bom = run(tmp_path, sb, {"39.2.1": entry()})
    assert st == "OK"
    grype = {"matches": [gmatch("CVE-2024-1086", "linux-nvidia-tegra", "6.8.0-1021.21", CANON, "deb"),
                         gmatch("CVE-2024-0001", "openssl", "3.0.13-0ubuntu3.5", "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5", "deb")]}
    (tmp_path / "grype.json").write_text(json.dumps(grype), encoding="utf-8")
    base = ["python3", "-I", str(PILOT / "lib" / "kernelcheck.py"), "--sbom", str(tmp_path / "sbom.json"), "--grype", str(tmp_path / "grype.json"),
            "--out", str(tmp_path / "kc.json")]
    r = subprocess.run(base + ["--kernel-map", str(tmp_path / "summary.json")], capture_output=True, text=True)
    _, kst, kd = r.stdout.strip().split("\t")
    kc = json.loads((tmp_path / "kc.json").read_text(encoding="utf-8"))
    assert kst == "OK" and "核心有比對，1 筆" in kd and "對應的 Canonical 核心 linux-nvidia-tegra 6.8.0-1021.21" in kd
    assert kc["matches"]["grype"]["by_artifact"] == {"linux-nvidia-tegra": 1} and kc["mapped_kernel"]["release"] == "39.2.1"
    assert len(kd.encode()) < 480
    # 沒有 --kernel-map 也照樣算進核心（名稱符合 linux-*-tegra*），只是說明不寫比對對象
    r = subprocess.run(base, capture_output=True, text=True)
    assert r.stdout.split("\t")[1] == "OK" and "Canonical" not in r.stdout
    # 對應了但 Grype 0 筆 → GAP，原因寫出已加上的元件
    (tmp_path / "grype.json").write_text(json.dumps({"matches": []}), encoding="utf-8")
    r = subprocess.run(base + ["--kernel-map", str(tmp_path / "summary.json")], capture_output=True, text=True)
    kc = json.loads((tmp_path / "kc.json").read_text(encoding="utf-8"))
    assert r.stdout.split("\t")[1] == "GAP" and any("linux-nvidia-tegra 6.8.0-1021.21" in x for x in kc["possible_reasons"])


def test_deb_sources_keeps_mapped_component_once_and_scio_prep_drops_it(tmp_path):
    _, st, _, _, bom = run(tmp_path, jetson(deb("libssl3t64", "3.0.13-0ubuntu3.5",
                                                "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.5?arch=arm64&upstream=openssl&distro=ubuntu-24.04")),
                           {"39.2.1": entry()})
    assert st == "OK"
    lib = PILOT / "lib"
    r = subprocess.run(["python3", "-I", str(lib / "deb_sources.py"), str(tmp_path / "out.json"), str(tmp_path / "dt.json"), str(tmp_path / "ds.json")],
                       capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.startswith("OK\t")
    dt = json.loads((tmp_path / "dt.json").read_text(encoding="utf-8"))
    assert [c.get("purl") for c in dt["components"]].count(CANON) == 1           # 不丟掉、不重複
    assert not any("linux-nvidia-tegra" in x["purl"] for x in json.loads((tmp_path / "ds.json").read_text(encoding="utf-8"))["added"])
    r = subprocess.run(["python3", "-I", str(lib / "scio_prep.py"), str(tmp_path / "out.json"), str(tmp_path / "scio.json"), str(tmp_path / "sp.json")],
                       capture_output=True, text=True)
    sp = json.loads((tmp_path / "sp.json").read_text(encoding="utf-8"))
    scio = json.loads((tmp_path / "scio.json").read_text(encoding="utf-8"))
    assert r.stdout.startswith("OK\t") and "只供弱點比對的合成元件 1 個" in r.stdout      # 不是缺少：仍是 OK
    assert sp["removed_matching_only"] == [CANON] and not any(c.get("name") == "linux-nvidia-tegra" for c in scio["components"])
    assert sp["components_out"] == len(bom["components"]) - 1


def test_sca_scan_scio_prep_fallback_drops_matching_only(tmp_path):
    """scio_prep.py 失敗時 sca-scan 退回上傳未轉換的 SBOM：只供比對的元件仍要移除（含巢狀）。"""
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    code = re.search(r"if python3 -I -c '(.*?)' \"\$UPLOAD\" \"\$SCIO_UP\"", s, re.S).group(1)
    _, st, _, _, bom = run(tmp_path, jetson(), {"39.2.1": entry()})
    bom["components"][0]["components"] = [dict(added(bom)[0], name="nested")]
    (tmp_path / "up.json").write_text(json.dumps(bom), encoding="utf-8")
    r = subprocess.run(["python3", "-I", "-c", code, str(tmp_path / "up.json"), str(tmp_path / "scio.json")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = json.loads((tmp_path / "scio.json").read_text(encoding="utf-8"))
    assert len(out["components"]) == len(bom["components"]) - 1 and out["components"][0]["components"] == []
    assert "sca-center:matching-only" not in json.dumps(out)


def test_report_labels_mapped_kernel_and_license_chain(tmp_path):
    l4t = {"status": "OK", "release": "39.2.1", "l4t_kernel": [{"name": "nvidia-l4t-kernel", "version": PKGVER, "purl": L4T_PURL}],
           "map_entry": {"component": {"name": "linux-nvidia-tegra", "version": "6.8.0-1021.21", "purl": CANON}}}
    grype = [gmatch("CVE-2024-1086", "linux-nvidia-tegra", "6.8.0-1021.21", CANON, "deb"),
             gmatch("CVE-2024-0001", "openssl", "3.0.13", "pkg:deb/ubuntu/openssl@3.0.13", "deb")]
    sbom = {"components": [deb("nvidia-l4t-kernel", PKGVER), deb("openssl", "3.0.13")]}
    out = make_out(tmp_path, ALL_OK + [("C-kernel-l4t-map", "OK", "x")], grype=grype, sbom=sbom, comp={"packages": 2, "counts": {}, "rows": []})
    (out / "scan" / "l4t-kernel-map.json").write_text(json.dumps(l4t), encoding="utf-8")
    (out / "dejacode" / "scio-prep.json").write_text(json.dumps({"components_in": 3, "components_out": 2, "removed_file_components": 0,
                                                                  "removed_too_long": [], "removed_matching_only": [CANON]}), encoding="utf-8")
    rep, page = run_report(out)
    ch = rep["license_chain"]
    assert (ch["removed_matching_only"], ch["removed_other"]) == (1, 0)          # 不算「其他」
    assert "另移除只供比對的元件 1 個" in page
    assert f"只供比對的 Canonical 核心（C-kernel-l4t-map），產品裡安裝的是 nvidia-l4t-kernel {PKGVER}" in page
    assert page.count("只供比對的 Canonical 核心（C-kernel-l4t-map）") == 1      # 只有核心那一列，openssl 沒有
    assert_no_conclusion(page)


def test_sca_scan_wiring():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    i = s.index('tools/pilot/lib/l4t_kernel.py" --sbom "$BOMW"')
    assert s.index('BOMW=$WORK/bom.cdx.json; [ -s "$SBOM" ] && cp "$SBOM" "$BOMW"') < i < s.index("# ---------- C. Grype")
    block = s[s.rindex("\nif ", 0, i):i]
    assert 'if [[ "$MODE" =~ ^(image|sbom)$ ]] && [ $SBOM_OK = 1 ]' in block              # 原始碼模式不寫這一列
    assert '--summary "$OUT/scan/l4t-kernel-map.json"' in s and 'NOT_RUN) rm -f "$OUT/scan/l4t-kernel-map.json";;' in s
    assert s.rindex('rm -f "$OUT/scan/l4t-kernel-map.json"', 0, i) > s.index('BOMW=$WORK/bom.cdx.json')   # 呼叫前先刪掉上一次的摘要
    assert 'mv "$WORK/bom.kmap.cdx.json" "$BOMW"' in s and "C-kernel-l4t-map NOT_RUN" not in s
    assert 'status C-kernel-l4t-map FAIL "l4t_kernel.py 失敗' in s
    # Grype、sbomgate、上傳都用 $BOMW；kernelcheck 讀原始 SBOM 並拿到摘要
    assert 'grype "sbom:$BOMW"' in s and s.count('sbomgate.py" --sbom "$BOMW"') == 2 and 'sbomgate.py" --sbom "$SBOM"' not in s
    assert 'strip_versions.py" "$BOMW"' in s and 'ka+=(--kernel-map "$OUT/scan/l4t-kernel-map.json")' in s
