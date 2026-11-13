"""作業系統核心的比對涵蓋（C-kernel-coverage，lib/kernelcheck.py）、報告弱點節的註記、sca-scan 的接線。
證據：Jetson Linux R39.2.1 映像（Jetson R39.2.1 示範映像）的 SBOM 有 nvidia-l4t-kernel 與 1468 個 linux-kernel-module、沒有 linux-kernel 元件，
Grype 與 DT 對核心都是 0 筆，報告卻沒有說。欄位格式取自該次的 Syft 1.55.0 CycloneDX 與 Grype 0.121.0 JSON。"""
import json
import subprocess

import pytest

from pilot_fixtures import ALL_OK, PILOT, assert_no_conclusion, gmatch, make_out, run_report

LIB = PILOT / "lib" / "kernelcheck.py"
KVER = "6.8.12-1021-tegra"
PKGVER = "6.8.12-tegra-39.2.1-20260806224157"


def module(name, ver="UNKNOWN", path=True):
    p = [{"name": "syft:package:foundBy", "value": "linux-kernel-cataloger"},
         {"name": "syft:package:type", "value": "linux-kernel-module"},
         {"name": "syft:metadata:kernelVersion", "value": KVER}]
    if path:
        p.append({"name": "syft:location:0:path", "value": f"/usr/lib/modules/{KVER}/kernel/net/sched/{name}.ko"})
    return {"type": "library", "name": name, "version": ver, "purl": f"pkg:generic/{name}", "properties": p}


def deb(name, ver):
    return {"type": "library", "name": name, "version": ver,
            "purl": f"pkg:deb/ubuntu/{name}@{ver}?arch=arm64&distro=ubuntu-24.04",
            "properties": [{"name": "syft:package:type", "value": "deb"}]}


def kernel(ver="6.8.12"):
    return {"type": "library", "name": "linux-kernel", "version": ver, "purl": f"pkg:generic/linux-kernel@{ver}",
            "cpe": f"cpe:2.3:o:linux:linux_kernel:{ver}:*:*:*:*:*:*:*",
            "properties": [{"name": "syft:package:type", "value": "linux-kernel"}]}


# 不是核心：使用者空間標頭、韌體、名稱含 kernel 的工具、kernel 的 headers 套件
NON_KERNEL = [deb("linux-libc-dev", "6.8.0-87.88"), deb("linux-firmware", "20240318.git3b128b60-0ubuntu2"),
              deb("kerneloops", "0.12+git20140509-6ubuntu8"), deb("libdrm-tegra0", "2.4.125-1ubuntu0.1~24.04.2"),
              deb("linux-headers-6.8.0-1021-nvidia-tegra", "6.8.0-1021.21")]


def run(tmp_path, sbom, grype=None, dt=None, raw_sbom=None):
    s = tmp_path / "sbom.json"
    s.write_text(raw_sbom if raw_sbom is not None else json.dumps(sbom), encoding="utf-8")
    args = ["python3", "-I", str(LIB), "--sbom", str(s), "--out", str(tmp_path / "kernel-coverage.json")]
    if grype is not None:
        g = tmp_path / "grype.json"
        g.write_text(grype if isinstance(grype, str) else json.dumps(grype), encoding="utf-8")
        args += ["--grype", str(g)]
    if dt is not None:
        d = tmp_path / "findings.json"
        d.write_text(json.dumps(dt), encoding="utf-8")
        args += ["--dt-findings", str(d)]
    r = subprocess.run(args, capture_output=True, text=True)
    lines = r.stdout.splitlines()
    assert len(lines) == 1, r
    stage, st, detail = lines[0].split("\t")
    assert stage == "C-kernel-coverage"
    ev = json.loads((tmp_path / "kernel-coverage.json").read_text(encoding="utf-8")) if r.returncode == 0 else None
    return r, st, detail, ev


def jetson_sbom():
    return {"components": [module("act_gact"), module("8021q", "1.8"), module("sch_fq", path=False),
                           deb("nvidia-l4t-kernel", PKGVER), deb("nvidia-l4t-kernel-dtbs", PKGVER),
                           deb("nvidia-l4t-kernel-headers", PKGVER), deb("openssl", "3.0.13-0ubuntu3.5")] + NON_KERNEL}


def test_kernel_present_without_matches_is_gap_with_version_from_modules_path(tmp_path):
    grype = {"matches": [gmatch("CVE-2024-0001", "openssl", "3.0.13-0ubuntu3.5", "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5", "deb"),
                         gmatch("CVE-2024-0002", "linux-firmware", "20240318", "pkg:deb/ubuntu/linux-firmware@20240318", "deb")],
             "ignoredMatches": [{"artifact": {"name": "linux-libc-dev", "type": "deb", "purl": "pkg:deb/ubuntu/linux-libc-dev@6.8.0-87.88",
                                              "upstreams": [{"name": "linux"}]}, "vulnerability": {"id": "CVE-2024-0003"}}]}
    r, st, detail, ev = run(tmp_path, jetson_sbom(), grype)
    assert r.returncode == 0 and st == "GAP"
    assert f"版本 {KVER}" in detail and f"/usr/lib/modules/{KVER}/" in detail and "核心的 CVE 未評估" in detail
    assert len(detail.encode()) < 480        # status() 說明欄只留 500 位元組
    assert ev["kernel_present"] and ev["version_source"] == "modules_path"
    assert ev["versions"][0] == {"version": KVER, "source": "modules_path", "modules": 3, "from": f"/usr/lib/modules/{KVER}/"}
    assert ev["components"]["linux_kernel_modules"] == 3 and ev["components"]["linux_kernel"] == []
    # headers 套件不算核心；nvidia-l4t-kernel 與 -dtbs 算
    assert sorted(p["name"] for p in ev["components"]["kernel_packages"]) == ["nvidia-l4t-kernel", "nvidia-l4t-kernel-dtbs"]
    assert ev["matches"]["grype"]["matches"] == 0                         # linux-firmware 的比對不算核心
    assert ev["matches"]["grype"]["ignored_upstream_linux"] == {"linux-libc-dev": 1}
    assert ev["possible_reasons"] and ev["not_counted"]


def test_module_metadata_then_package_version_fallback(tmp_path):
    sb = {"components": [module("sch_fq", path=False)]}
    _, st, detail, ev = run(tmp_path, sb, {"matches": []})
    assert st == "GAP" and ev["version_source"] == "module_metadata" and ev["versions"][0]["version"] == KVER
    rpm = {"type": "library", "name": "kernel-core", "version": "5.14.0-427.13.1.el9_4",
           "purl": "pkg:rpm/redhat/kernel-core@5.14.0-427.13.1.el9_4?arch=x86_64"}
    _, st, detail, ev = run(tmp_path, {"components": [rpm]}, {"matches": []})
    assert st == "GAP" and ev["version_source"] == "kernel_package" and "版本 5.14.0-427.13.1.el9_4" in detail


@pytest.mark.parametrize("artifact", [
    {"name": "linux-kernel", "version": "6.8.12", "type": "linux-kernel", "purl": "pkg:generic/linux-kernel@6.8.12"},
    {"name": "vmlinux", "version": "6.8.12", "type": "binary", "cpes": ["cpe:2.3:o:linux:linux_kernel:6.8.12:*:*:*:*:*:*:*"]},
])
def test_kernel_component_with_kernel_match_is_ok(tmp_path, artifact):
    grype = {"matches": [{"vulnerability": {"id": "CVE-2024-1086", "severity": "High"}, "artifact": artifact},
                         gmatch("CVE-2024-0001", "openssl", "3.0.13", "pkg:deb/ubuntu/openssl@3.0.13", "deb")]}
    r, st, detail, ev = run(tmp_path, {"components": [kernel(), module("act_gact")]}, grype)
    assert r.returncode == 0 and st == "OK" and "核心有比對，1 筆" in detail and "版本 6.8.12" in detail
    assert ev["version_source"] == "linux_kernel_component" and ev["matches"]["grype"]["matches"] == 1


def test_kernel_package_match_counts(tmp_path):
    sb = {"components": [deb("linux-image-6.8.0-87-generic", "6.8.0-87.88")]}
    grype = {"matches": [gmatch("CVE-2024-1086", "linux-image-6.8.0-87-generic", "6.8.0-87.88",
                                "pkg:deb/ubuntu/linux-image-6.8.0-87-generic@6.8.0-87.88?arch=amd64", "deb")]}
    assert run(tmp_path, sb, grype)[1] == "OK"


def test_dt_findings_interface(tmp_path):
    dt = [{"component": {"name": "nvidia-l4t-kernel", "version": PKGVER, "purl": f"pkg:deb/ubuntu/nvidia-l4t-kernel@{PKGVER}"},
           "vulnerability": {"vulnId": "CVE-2024-1086"}}]
    _, st, detail, ev = run(tmp_path, jetson_sbom(), {"matches": []}, dt=dt)
    assert st == "OK" and "DT 1" in detail and ev["matches"]["dt"]["matches"] == 1


def test_no_grype_result_with_kernel_is_gap(tmp_path):
    _, st, detail, _ = run(tmp_path, jetson_sbom())
    assert st == "GAP" and "沒有 Grype 結果" in detail


def test_no_kernel_is_not_run(tmp_path):
    sb = {"components": NON_KERNEL + [deb("openssl", "3.0.13"), {"type": "file", "name": "/etc/passwd"}]}
    r, st, detail, ev = run(tmp_path, sb, {"matches": []})
    assert r.returncode == 0 and st == "NOT_RUN" and "SBOM 沒有作業系統核心" in detail
    assert ev["kernel_present"] is False and ev["components"]["kernel_packages"] == []


@pytest.mark.parametrize("raw_sbom,grype", [
    ("{not json", None),
    ("[1, 2]", None),
    (json.dumps({"components": "x"}), None),
    (json.dumps({"components": [deb("nvidia-l4t-kernel", PKGVER)]}), "{bad"),
    (json.dumps({"components": [deb("nvidia-l4t-kernel", PKGVER)]}), json.dumps({"matches": "x"})),
    (json.dumps({"components": [dict(module("act_gact"), evidence="x")]}), None),     # 結構意外（AttributeError）
])
def test_malformed_inputs_print_fail_line_not_traceback(tmp_path, raw_sbom, grype):
    r, st, detail, _ = run(tmp_path, None, grype, raw_sbom=raw_sbom)
    assert r.returncode == 3 and st == "FAIL" and "kernelcheck.py" in detail
    assert "Traceback" not in r.stderr + r.stdout


def test_report_notes_kernel_gap_in_vulnerability_section(tmp_path):
    out = make_out(tmp_path / "gap", ALL_OK + [("C-kernel-coverage", "GAP", f"偵測到作業系統核心，版本 {KVER}")], grype=[], meta={"mode": "image"})
    (out / "scan" / "kernel-coverage.json").write_text(json.dumps({"versions": [{"version": KVER, "source": "modules_path"}]}), encoding="utf-8")
    rep, page = run_report(out)
    assert rep["kernel_coverage"] == {"status": "GAP", "versions": [KVER]}
    assert f"作業系統核心（版本 {KVER}）沒有做漏洞比對，核心的漏洞不在下面的數字裡" in page
    assert page.index("核心的漏洞不在下面的數字裡") > page.index("<h2>弱點</h2>")
    assert any(s["stage"] == "C-kernel-coverage" for s in rep["incomplete"])
    assert_no_conclusion(page)
    # 沒有 kernel-coverage.json 時版本寫「未知」，不猜
    out2 = make_out(tmp_path / "nojson", ALL_OK + [("C-kernel-coverage", "GAP", "x")], grype=[])
    assert "作業系統核心（版本 未知）沒有做漏洞比對" in run_report(out2)[1]
    # OK、NOT_RUN 或沒有這一列（原始碼模式）：不加註記
    for extra in ([("C-kernel-coverage", "OK", "核心有比對，3 筆")], [("C-kernel-coverage", "NOT_RUN", "SBOM 沒有作業系統核心")], []):
        rep, page = run_report(make_out(tmp_path / f"o{len(extra)}{extra[0][1] if extra else ''}", ALL_OK + extra, grype=[]))
        assert "核心的漏洞不在下面的數字裡" not in page


def test_sca_scan_runs_kernelcheck_after_grype_for_image_and_sbom_only():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    i = s.index('kernelcheck.py" --sbom "$SBOM"')
    assert s.index('status C-grype OK') < i < s.index("# sbomgate（規則 11–14）")
    block = s[s.rindex("\nif ", 0, i):i]
    assert 'if [[ "$MODE" =~ ^(image|sbom)$ ]]; then' in block            # 原始碼模式不寫這一列
    # 沒有核心（kernelcheck 回 NOT_RUN）或沒有 SBOM 時不寫這一列：一般容器映像不該因此從 OK 變成非 OK
    assert '[ "$s2" = NOT_RUN ] || { status "$s1" "$s2" "$s3"; KSEEN=1; }' in s and 'C-kernel-coverage NOT_RUN' not in s   # KSEEN：SBOM 有核心
    assert '--out "$OUT/scan/kernel-coverage.json"' in s and 'ka=(--grype "$GR")' in s
    assert 'status C-kernel-coverage FAIL "kernelcheck.py 失敗' in s     # 沒有狀態列（例如崩潰）時記 FAIL，不中斷掃描
