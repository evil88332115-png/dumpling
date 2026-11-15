"""kernelcheck.py：只有上游版本範圍的比對（M7d-5，D-063）。

SBOM 有發行版的核心 deb，所有核心比對都落在 generic／NVD 的核心元件（pkg:generic/linux-kernel、CPE linux_kernel），deb 一筆都沒有比對到
→ C-kernel-coverage 是 GAP（沒有用到發行版的修補與回移資訊：可能有誤報，也可能漏報）。證據在 kernel-coverage.json 的 distro_data_unused。
條件用結構化的欄位判斷（Grype artifact 的型別、purl；DT 元件的 purl、CPE），不解析說明文字。全部合成資料。

Jetson 形狀的基準（test_jetson_shape_output_is_byte_identical_to_pre_change）：data/kernelcheck-jetson-baseline.json 是改前的程式（main 33da59c）
對同一份輸入產生的輸出；改後必須逐位元組相同。
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from pilot_fixtures import PILOT, gmatch

sys.path.insert(0, str(PILOT / "lib"))
import kernelcheck as kc  # noqa: E402

LIB = PILOT / "lib" / "kernelcheck.py"
BASELINE = Path(__file__).resolve().parent / "data" / "kernelcheck-jetson-baseline.json"
KVER = "6.12.116+deb13-amd64"
DEB_IMG = "linux-image-6.12.116+deb13-amd64"
DEB_PURL = ("pkg:deb/debian/linux-image-6.12.116%2Bdeb13-amd64@6.12.116-1?arch=amd64&distro=debian-13"
            "&upstream=linux-signed-amd64%406.12.116%2Bdeb13")
GEN_PURL = f"pkg:generic/linux-kernel@{KVER}"


def debian_kernel_deb(name=DEB_IMG, ver="6.12.116-1", purl=DEB_PURL):
    return {"type": "library", "name": name, "version": ver, "purl": purl, "properties": [{"name": "syft:package:type", "value": "deb"}]}


def generic_kernel():
    return {"type": "library", "name": "linux-kernel", "version": KVER, "purl": GEN_PURL,
            "cpe": f"cpe:2.3:o:linux:linux_kernel:{KVER}:*:*:*:*:*:*:*", "properties": [{"name": "syft:package:type", "value": "linux-kernel"}]}


def g_generic(vid="CVE-2024-0001"):
    return gmatch(vid, "linux-kernel", KVER, GEN_PURL, "linux-kernel")


def g_deb(vid="CVE-2024-0002", purl=DEB_PURL, name=DEB_IMG):
    return gmatch(vid, name, "6.12.116-1", purl, "deb")


def run(tmp_path, comps, matches=None, ignored=None, dt=None, extra=()):
    s = tmp_path / "sbom.json"
    s.write_text(json.dumps({"components": comps}), encoding="utf-8")
    args = ["python3", "-I", str(LIB), "--sbom", str(s), "--out", str(tmp_path / "kc.json"), *extra]
    if matches is not None:
        g = tmp_path / "grype.json"
        g.write_text(json.dumps({"matches": matches, **({"ignoredMatches": ignored} if ignored else {})}), encoding="utf-8")
        args += ["--grype", str(g)]
    if dt is not None:
        d = tmp_path / "dt.json"
        d.write_text(json.dumps(dt), encoding="utf-8")
        args += ["--dt-findings", str(d)]
    r = subprocess.run(args, capture_output=True, text=True)
    lines = r.stdout.splitlines()
    assert len(lines) == 1, r
    stage, st, detail = lines[0].split("\t")
    assert stage == "C-kernel-coverage"
    ev = json.loads((tmp_path / "kc.json").read_text(encoding="utf-8")) if r.returncode == 0 else None
    return r, st, detail, ev


# ---------- 規則成立 ----------

def test_debian_kernel_deb_with_generic_only_matches_is_gap(tmp_path):
    """AI NAS 的形狀：Debian 13 核心 deb（來源套件 linux-signed-amd64）＋ Syft 從 bzImage 抓出的 pkg:generic/linux-kernel；比對只在 generic。"""
    r, st, detail, ev = run(tmp_path, [debian_kernel_deb(), generic_kernel()], [g_generic("CVE-2024-0001"), g_generic("CVE-2024-0003")])
    assert (r.returncode, st) == (0, "GAP")
    assert "只有上游版本範圍（NVD" in detail and DEB_IMG in detail and "沒有比對到發行版的安全資料" in detail
    assert "修補（含回移）資訊" in detail and "可能有誤報，也可能漏報" in detail
    assert len(detail) < 500                                  # status() 說明欄只留 500 字元
    du = ev["distro_data_unused"]
    assert du["rule"] == "generic-only-no-distro-package-match"
    assert du["distro_kernel_packages"] == [{"name": DEB_IMG, "version": "6.12.116-1", "purl": DEB_PURL}]
    assert du["matches"] == {"distro_packages": 0, "generic_components": 2, "grype_generic_by_component": {"linux-kernel": 2}, "dt_generic": 0}
    assert ev["off_series"] == []                             # Debian 的 linux-signed-amd64 是發行版的來源套件：不是 off-series
    assert ev["status"] == "GAP" and ev["detail"] == detail
    assert ev["matches"]["grype"]["matches"] == 2             # 既有欄位照舊


def test_decision_does_not_parse_detail_text(tmp_path):
    """判斷只看結構欄位：Grype 的 artifact.name 帶 deb 的樣子但 type／purl 是 generic → 仍是 generic；deb 的 artifact 一筆都沒有。"""
    odd = gmatch("CVE-2024-0009", DEB_IMG, KVER, GEN_PURL, "linux-kernel")      # 名稱像核心 deb，purl 是 pkg:generic
    r, st, detail, ev = run(tmp_path, [debian_kernel_deb(), generic_kernel()], [odd])
    assert st == "GAP" and ev["distro_data_unused"]["matches"]["distro_packages"] == 0


def test_dt_findings_generic_only_also_counts(tmp_path):
    dt = [{"component": {"name": "linux-kernel", "version": KVER, "purl": GEN_PURL, "cpe": f"cpe:2.3:o:linux:linux_kernel:{KVER}:*:*:*:*:*:*:*"},
           "vulnerability": {"vulnId": "CVE-2024-0001"}}]
    r, st, detail, ev = run(tmp_path, [debian_kernel_deb(), generic_kernel()], None, dt=dt)
    assert st == "GAP" and ev["distro_data_unused"]["matches"]["generic_components"] == 1 and ev["distro_data_unused"]["matches"]["dt_generic"] == 1


def test_ignored_deb_matches_do_not_count_as_matched(tmp_path):
    ign = [{"artifact": {"name": DEB_IMG, "type": "deb", "purl": DEB_PURL}, "vulnerability": {"id": "CVE-2024-0007"}}]
    r, st, detail, ev = run(tmp_path, [debian_kernel_deb(), generic_kernel()], [g_generic()], ignored=ign)
    assert st == "GAP" and "distro_data_unused" in ev


# ---------- 規則不成立：照舊 ----------

def test_deb_also_matched_is_ok_as_before(tmp_path):
    r, st, detail, ev = run(tmp_path, [debian_kernel_deb(), generic_kernel()], [g_generic(), g_deb()])
    assert st == "OK" and "distro_data_unused" not in ev and "核心有比對，2 筆" in detail


def test_deb_matched_in_dt_is_ok(tmp_path):
    dt = [{"component": {"name": DEB_IMG, "version": "6.12.116-1", "purl": DEB_PURL}, "vulnerability": {"vulnId": "CVE-2024-0002"}}]
    r, st, detail, ev = run(tmp_path, [debian_kernel_deb(), generic_kernel()], [g_generic()], dt=dt)
    assert st == "OK" and "distro_data_unused" not in ev


def test_generic_only_without_distro_deb_is_unchanged(tmp_path):
    """沒有發行版核心 deb（Yocto／廠商核心：只有 generic 的 linux-kernel）：照舊 OK。"""
    r, st, detail, ev = run(tmp_path, [generic_kernel()], [g_generic()])
    assert st == "OK" and "distro_data_unused" not in ev
    assert detail.startswith("核心有比對，1 筆（Grype 1）")


def test_no_matches_at_all_is_the_old_zero_match_gap(tmp_path):
    r, st, detail, ev = run(tmp_path, [debian_kernel_deb(), generic_kernel()], [])
    assert st == "GAP" and "distro_data_unused" not in ev and "核心沒有做漏洞比對" in detail


def test_kernel_headers_deb_is_not_a_distro_kernel_deb(tmp_path):
    hdr = debian_kernel_deb("linux-headers-6.12.116+deb13-amd64", purl="pkg:deb/debian/linux-headers-6.12.116%2Bdeb13-amd64@6.12.116-1?distro=debian-13")
    r, st, detail, ev = run(tmp_path, [hdr, generic_kernel()], [g_generic()])
    assert st == "OK" and "distro_data_unused" not in ev


# ---------- Jetson：不能被影響 ----------

PKGVER = "6.8.12-tegra-39.2.1-20260806224157"
CANON = "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"
KMAP = {"status": "OK", "release": "39.2.1", "l4t_kernel": [{"name": "nvidia-l4t-kernel", "version": PKGVER}],
        "map_entry": {"component": {"name": "linux-nvidia-tegra", "version": "6.8.0-1021.21", "purl": CANON}}}


def l4t_deb(name, ver=PKGVER):
    return {"type": "library", "name": name, "version": ver, "purl": f"pkg:deb/ubuntu/{name}@{ver}?arch=arm64&distro=ubuntu-24.04",
            "properties": [{"name": "syft:package:type", "value": "deb"}]}


def module(name):
    return {"type": "library", "name": name, "version": "UNKNOWN", "purl": f"pkg:generic/{name}",
            "properties": [{"name": "syft:package:type", "value": "linux-kernel-module"},
                           {"name": "syft:location:0:path", "value": f"/usr/lib/modules/6.8.12-1021-tegra/kernel/net/{name}.ko"}]}


def jetson_inputs():
    """Jetson 形狀：nvidia-l4t-kernel 套件＋模組；Grype 對 C-kernel-l4t-map 加上的 Canonical 核心（deb 原始碼元件）有比對。"""
    sbom = {"components": [module("act_gact"), module("sch_fq"), l4t_deb("nvidia-l4t-kernel"), l4t_deb("nvidia-l4t-kernel-dtbs"),
                           l4t_deb("openssl", "3.0.13-0ubuntu3.5")]}
    grype = {"matches": [gmatch("CVE-2025-0101", "linux-nvidia-tegra", "6.8.0-1021.21", CANON, "deb", fix=["6.8.0-1030.30"]),
                         gmatch("CVE-2025-0102", "linux-nvidia-tegra", "6.8.0-1021.21", CANON, "deb"),
                         gmatch("CVE-2025-0003", "openssl", "3.0.13-0ubuntu3.5", "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5", "deb")]}
    return sbom, grype


def run_files(tmp_path, sbom, grype, kmap=None):
    (tmp_path / "sbom.json").write_text(json.dumps(sbom), encoding="utf-8")
    (tmp_path / "grype.json").write_text(json.dumps(grype), encoding="utf-8")
    args = ["python3", "-I", str(LIB), "--sbom", str(tmp_path / "sbom.json"), "--grype", str(tmp_path / "grype.json"), "--out", str(tmp_path / "kc.json")]
    if kmap:
        (tmp_path / "kmap.json").write_text(json.dumps(kmap), encoding="utf-8")
        args += ["--kernel-map", str(tmp_path / "kmap.json")]
    r = subprocess.run(args, capture_output=True, text=True)
    assert r.returncode == 0, r
    return r.stdout, (tmp_path / "kc.json").read_text(encoding="utf-8")


def test_jetson_shape_output_is_byte_identical_to_pre_change(tmp_path):
    sbom, grype = jetson_inputs()
    stdout, out = run_files(tmp_path, sbom, grype, KMAP)
    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert stdout == base["stdout"] and out == base["out"]
    assert json.loads(out)["status"] == "OK" and "distro_data_unused" not in json.loads(out)


def test_jetson_with_generic_nvd_matches_is_not_affected(tmp_path):
    """Jetson 另外有 generic 的 NVD 比對、而 Canonical 核心沒有比對：nvidia-l4t-kernel* 不算發行版核心 deb，有 C-kernel-l4t-map 的對應也不套用 → 照舊 OK。"""
    sbom, grype = jetson_inputs()
    sbom["components"].append(generic_kernel())
    grype["matches"] = [g_generic("CVE-2025-0900")]
    for km in (None, KMAP):
        stdout, out = run_files(tmp_path, sbom, grype, km)
        assert json.loads(out)["status"] == "OK" and "distro_data_unused" not in json.loads(out)


def test_l4t_mapped_kernel_blocks_rule_even_with_a_distro_looking_deb(tmp_path):
    """有 C-kernel-l4t-map 的對應元件（mapped_kernel）時一律不套用：即使 SBOM 另有一個像發行版核心的 deb。"""
    sbom, grype = jetson_inputs()
    sbom["components"] += [debian_kernel_deb(), generic_kernel()]
    grype["matches"] = [g_generic("CVE-2025-0900")]
    stdout, out = run_files(tmp_path, sbom, grype, KMAP)
    assert json.loads(out)["status"] == "OK" and "distro_data_unused" not in json.loads(out)


# ---------- 和不在序列上的 GAP 同時成立：兩個原因都記 ----------

def test_off_series_and_generic_only_both_recorded(tmp_path):
    """Raspberry Pi 形狀的核心 deb（epoch、+rpt）又只有 generic 比對：off_series 與 distro_data_unused 都記，說明兩個原因都寫。"""
    rpi = debian_kernel_deb("linux-image-6.18.50+rpt-rpi-v8", "1:6.18.50-1+rpt1",
                            "pkg:deb/debian/linux-image-6.18.50%2Brpt-rpi-v8@1%3A6.18.50-1%2Brpt1?arch=arm64&distro=debian-13")
    r, st, detail, ev = run(tmp_path, [rpi, generic_kernel()], [g_generic()])
    assert st == "GAP" and ev["off_series"] and ev["distro_data_unused"]["matches"]["generic_components"] == 1
    assert "核心不在發行版的核心序列上" in detail and "只有上游版本範圍（NVD" in detail and "沒有用到發行版的修補（含回移）資訊" in detail
    # status() 說明欄只留 500 字元（超過的截掉）：兩個原因都要在截斷之後還看得到
    cut = detail[:500]
    assert "只有上游版本範圍（NVD" in cut and "核心不在發行版的核心序列上" in cut and "規則 a" in cut
    assert "distro_data_unused" in detail and "off_series" in detail


def test_not_distro_declaration_and_generic_only_both_recorded(tmp_path):
    r, st, detail, ev = run(tmp_path, [debian_kernel_deb(), generic_kernel()], [g_generic()], extra=["--not-distro-kernel", "廠商自建核心"])
    assert st == "GAP" and ev["off_series"][0]["reasons"][0].startswith("規則 c") and ev["distro_data_unused"]
    assert "規則 c" in detail and "只有上游版本範圍（NVD" in detail


def test_off_series_alone_unchanged_and_without_m7_wording(tmp_path):
    """Raspberry Pi：deb 有比對（Debian 的 linux）→ 只有 off_series 的原因；沒有 distro_data_unused；說明不含內部里程碑用語。"""
    rpi = debian_kernel_deb("linux-image-6.18.50+rpt-rpi-v8", "1:6.18.50-1+rpt1",
                            "pkg:deb/debian/linux-image-6.18.50%2Brpt-rpi-v8@1%3A6.18.50-1%2Brpt1?arch=arm64&distro=debian-13")
    r, st, detail, ev = run(tmp_path, [rpi], [g_deb(name=rpi["name"], purl=rpi["purl"])])
    assert st == "GAP" and ev["off_series"] and "distro_data_unused" not in ev
    assert "核心 CVE 沒有以上游版本對核心 CNA 列出" in detail
    for bad in ("M7", "尚未實作"):
        assert bad not in detail


def test_no_milestone_wording_in_any_detail_or_module_doc_output(tmp_path):
    outs = [run(tmp_path, [debian_kernel_deb(), generic_kernel()], [g_generic()])[2],
            run(tmp_path, [debian_kernel_deb(), generic_kernel()], [g_generic()], extra=["--not-distro-kernel", "x"])[2]]
    for d in outs:
        assert "M7" not in d and "尚未實作" not in d


def test_evidence_function_is_pure_structure():
    """distro_data_unused 只看 comps／比對數：直接呼叫，不經說明文字。"""
    comps = {"kernel_packages": [{"name": DEB_IMG, "version": "1", "purl": DEB_PURL, "purl_type": "deb"}]}
    assert kc.distro_data_unused(comps, {}, None, None, (0, 3, {"linux-kernel": 3}), None)["matches"]["generic_components"] == 3
    assert kc.distro_data_unused(comps, {}, None, None, (1, 3, {}), None) is None           # deb 有比對
    assert kc.distro_data_unused(comps, {}, None, None, (0, 0, {}), None) is None           # 沒有 generic 比對（走 0 筆的舊規則）
    assert kc.distro_data_unused(comps, {}, None, {"name": "x"}, (0, 3, {}), None) is None  # 有 C-kernel-l4t-map 的對應
    assert kc.distro_data_unused({"kernel_packages": []}, {}, None, None, (0, 3, {}), None) is None   # 沒有發行版核心 deb
    exempt = {"kernel_packages": [{"name": "nvidia-l4t-kernel", "version": "1", "purl": "pkg:deb/ubuntu/nvidia-l4t-kernel@1", "purl_type": "deb"}]}
    assert kc.distro_data_unused(exempt, {}, None, None, (0, 3, {}), None) is None          # NVIDIA 核心套件不算
    rpm = {"kernel_packages": [{"name": "kernel-core", "version": "1", "purl": "pkg:rpm/redhat/kernel-core@1", "purl_type": "rpm"}]}
    assert kc.distro_data_unused(rpm, {}, None, None, (0, 3, {}), None) is None              # 只看 deb（規則的範圍）
