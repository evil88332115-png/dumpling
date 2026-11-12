import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import deb_sources as ds  # noqa: E402

PILOT = Path(__file__).resolve().parents[1]
D = "distro=ubuntu-24.04"


def run(tmp_path, comps):
    src = tmp_path / "in.json"
    src.write_text(json.dumps({"bomFormat": "CycloneDX", "components": comps}))
    rc = ds.main([str(src), str(tmp_path / "out.json"), str(tmp_path / "s.json")])
    out = json.loads((tmp_path / "out.json").read_text()) if rc == 0 else None
    return rc, out, json.loads((tmp_path / "s.json").read_text()) if rc == 0 else None


def test_adds_one_source_per_package(tmp_path, capsys):
    comps = [
        {"name": "libfreerdp3-3", "purl": f"pkg:deb/ubuntu/libfreerdp3-3@3.5.1%2Bdfsg1-0ubuntu1.6?arch=arm64&upstream=freerdp3&{D}"},
        {"name": "libwinpr3-3", "purl": f"pkg:deb/ubuntu/libwinpr3-3@3.5.1%2Bdfsg1-0ubuntu1.6?arch=arm64&upstream=freerdp3&{D}"},
        {"name": "bsdutils", "purl": f"pkg:deb/ubuntu/bsdutils@1%3A2.39.3-9ubuntu6?arch=arm64&upstream=util-linux%402.39.3-9ubuntu6&{D}"},
        {"name": "openssl", "purl": f"pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.11?arch=arm64&{D}"},            # 名稱相同：不加
        {"name": "libssl3t64", "purl": f"pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.11?arch=arm64&upstream=openssl&{D}"},  # 已有同名同版本
        {"name": "x", "purl": "pkg:npm/x@1", "components": [
            {"name": "nested", "purl": f"pkg:deb/ubuntu/libnested1@2.0?arch=arm64&upstream=nested&{D}"}]},
        {"name": "foo", "purl": f"pkg:deb/debian/foo@1.0-1%2Bb1?arch=amd64&upstream=foo%401.0-1"},            # binNMU：同名不加
        {"name": "linux-libc-dev", "purl": f"pkg:deb/ubuntu/linux-libc-dev@6.8.0-134.134?arch=arm64&upstream=linux&{D}"},   # 核心：不加
        {"name": "linux-headers-6.8.0-134", "purl": f"pkg:deb/ubuntu/linux-headers-6.8.0-134@6.8.0-134.134?arch=all&upstream=linux&{D}"},
        {"name": "bpftool", "purl": f"pkg:deb/ubuntu/bpftool@7.4.0%2B6.8.0-134.134?arch=arm64&upstream=linux%406.8.0-134.134&{D}"},  # 原始碼 linux：不加
        {"name": "linux-apfs-rw-dkms", "purl": "pkg:deb/debian/linux-apfs-rw-dkms@0.3.8-1?arch=all&upstream=linux-apfs-rw"},  # dkms：照補
        {"name": "libatm1t64", "purl": f"pkg:deb/ubuntu/libatm1t64@1%3A2.5.1-5.1?arch=arm64&upstream=linux-atm%402.5.1-5.1&{D}"},  # 不是 linux- 開頭：照補
    ]
    rc, out, s = run(tmp_path, comps)
    assert rc == 0 and capsys.readouterr().out.startswith("OK\t")
    added = {c["purl"]: c for c in out["components"] if c.get("bom-ref", "").startswith("sca-center-deb-source:")}
    assert sorted(added) == [
        "pkg:deb/debian/linux-apfs-rw@0.3.8-1?arch=source",
        f"pkg:deb/ubuntu/freerdp3@3.5.1%2Bdfsg1-0ubuntu1.6?arch=source&distro=ubuntu-24.04",
        "pkg:deb/ubuntu/linux-atm@2.5.1-5.1?arch=source&distro=ubuntu-24.04",
        "pkg:deb/ubuntu/nested@2.0?arch=source&distro=ubuntu-24.04",
        "pkg:deb/ubuntu/util-linux@2.39.3-9ubuntu6?arch=source&distro=ubuntu-24.04",   # 原始碼版本取 upstream（沒有 epoch）
    ]
    fr = added["pkg:deb/ubuntu/freerdp3@3.5.1%2Bdfsg1-0ubuntu1.6?arch=source&distro=ubuntu-24.04"]
    assert fr["properties"] == [{"name": "sca-center:deb-source-of", "value": "libfreerdp3-3, libwinpr3-3"}]
    assert s["deb_components"] == 12 and s["source_components_added"] == 5 and s["binaries_covered"] == 6
    assert s["kernel_binaries_skipped"] == ["bpftool", "linux-headers-6.8.0-134", "linux-libc-dev"]
    fr_s = next(x for x in s["added"] if x["purl"].startswith("pkg:deb/ubuntu/freerdp3@"))
    assert fr_s["binary_purls"] == sorted(comps[i]["purl"] for i in (0, 1))
    assert s["shared_sources"] == [{"purl": "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.11", "binary_purls": [comps[4]["purl"]]}]
    assert not any("_binary_purls" in c for c in out["components"])
    assert len(out["components"]) == 12 + 5                       # 原本的元件不動


def test_no_deb(tmp_path, capsys):
    rc, out, s = run(tmp_path, [{"name": "x", "purl": "pkg:npm/x@1"}])
    assert rc == 0 and capsys.readouterr().out.startswith("NOT_RUN") and s["source_components_added"] == 0


def test_bad_input(tmp_path, capsys):
    (tmp_path / "in.json").write_text("{not json")
    assert ds.main([str(tmp_path / "in.json"), str(tmp_path / "o"), str(tmp_path / "s")]) == 1
    assert capsys.readouterr().out.startswith("FAIL\t")


def test_sca_scan_uploads_dt_copy_only():
    """原始碼套件只給 DT：上傳 DT 用 $DT_UP，ScanCode.io 仍用 $UPLOAD。"""
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    assert '"$ROOT/tools/pilot/lib/deb_sources.py" "$UPLOAD" "$WORK/bom.dt.cdx.json"' in s
    assert '-F "bom=@$DT_UP;type=application/json"' in s and '-F "bom=@$UPLOAD;type=application/json"' not in s
    assert '"$ROOT/tools/pilot/lib/scio_prep.py" "$UPLOAD"' in s
