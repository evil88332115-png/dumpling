"""kernelcheck.py：核心不在發行版的核心序列上（off-series）時，C-kernel-coverage 是 GAP，即使 Grype 對核心有比對。

規則 a（epoch ≥ 1）、b（廠商後綴 +rpt／+rpi、名稱 +rpt／-rpt-）、c（--not-distro-kernel 明確宣告）、d（purl 的 upstream= 來源套件，
清單在 lib/data/distro-kernel-sources.json）。全部合成資料：套件名稱與版本只取公開的樣子（Raspberry Pi OS、Radxa、Debian、Ubuntu、Jetson 的命名）。
"""
import json
import shutil
import subprocess
import sys

import pytest

from pilot_fixtures import PILOT, gmatch

sys.path.insert(0, str(PILOT / "lib"))
import kernelcheck as kc  # noqa: E402

LIB = PILOT / "lib" / "kernelcheck.py"


def pkg(name, ver, purl_tail="", typ="deb", ns="debian"):
    purl = f"pkg:{typ}/{ns}/{name}@{ver}{purl_tail}"
    return {"type": "library", "name": name, "version": ver, "purl": purl, "properties": [{"name": "syft:package:type", "value": typ}]}


def run(tmp_path, comps, grype=True, extra=(), lib=LIB):
    s = tmp_path / "sbom.json"
    s.write_text(json.dumps({"components": comps}), encoding="utf-8")
    args = ["python3", "-I", str(lib), "--sbom", str(s), "--out", str(tmp_path / "kc.json"), *extra]
    if grype:
        k = comps[0]
        g = tmp_path / "grype.json"
        g.write_text(json.dumps({"matches": [gmatch("CVE-2024-0001", k["name"], k["version"], k["purl"], "deb")]}), encoding="utf-8")
        args += ["--grype", str(g)]
    r = subprocess.run(args, capture_output=True, text=True)
    st, detail = r.stdout.strip().split("\t")[1:]
    ev = json.loads((tmp_path / "kc.json").read_text(encoding="utf-8")) if r.returncode == 0 else None
    return r, st, detail, ev


def flagged(ev):
    return [(x["name"], x["version"]) for x in ev["off_series"]]


# ---------- 規則 a：epoch ----------

@pytest.mark.parametrize("ver", ["1:6.18.50-1+rpt1", "1:6.12.43-1", "2:6.1.0-1", "01:6.1.0-1"])
def test_epoch_at_least_one_is_gap_even_with_matches(tmp_path, ver):
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.18.50-x", ver)])
    assert (r.returncode, st) == (0, "GAP")
    assert "核心不在發行版的核心序列上" in detail and f"linux-image-6.18.50-x {ver}" in detail and "規則" in detail
    assert "可能漏報" in detail and "上游版本對核心 CNA" in detail and "M7" in detail
    assert flagged(ev) == [("linux-image-6.18.50-x", ver)] and ev["matches"]["grype"]["matches"] == 1


def test_explicit_zero_epoch_is_not_flagged_by_itself(tmp_path):
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.12.43-x", "0:6.12.43-1")])
    assert st == "OK" and ev["off_series"] == []


def test_epoch_in_purl_qualifier_is_flagged(tmp_path):
    """有些產生器把 epoch 放在 purl 的 epoch= 限定詞，版本本身不帶 N:（第二輪驗證）。"""
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.18.50-x", "6.18.50-1", "?arch=arm64&epoch=1&distro=debian-13")])
    assert st == "GAP" and "epoch=1" in detail
    (tmp_path / "z").mkdir()
    r, st, detail, ev = run(tmp_path / "z", [pkg("linux-image-6.12.43-x", "6.12.43-1", "?arch=arm64&epoch=0&upstream=linux&distro=debian-13")])
    assert st == "OK" and ev["off_series"] == []


def test_bare_debian_distro_applies_rule_d(tmp_path):
    """distro=debian（沒有版本號，sid／testing）也是 Debian：自訂的來源套件 → off-series；raspbian-* 不看規則 d（靠 a、b）。"""
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.1.84-8-x", "6.1.84-8", "?arch=arm64&distro=debian&upstream=mycorp-linux")])
    assert st == "GAP" and "mycorp-linux" in detail
    (tmp_path / "r").mkdir()
    r, st, detail, ev = run(tmp_path / "r", [pkg("linux-image-6.1.84-8-x", "6.1.84-8", "?arch=arm64&distro=raspbian-12&upstream=mycorp-linux")])
    assert st == "OK"                                                     # 已知的盲點（文件寫明）


# ---------- 規則 b：廠商後綴 ----------

@pytest.mark.parametrize("ver", ["6.18.50-1+rpt1", "6.12.25+rpt-rpi-v8", "1:6.6.51-1+rpt3", "6.12.25-1+RPT2", "6.1.0-1+rpi1", "6.12.25+Rpt"])
def test_vendor_suffix_in_version(tmp_path, ver):
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.12.25-x", ver)])
    assert st == "GAP" and "規則 b" in ev["off_series"][0]["reason"] and "+rp" in ev["off_series"][0]["reason"].lower()


@pytest.mark.parametrize("name", ["linux-image-6.18.50+rpt-rpi-v8", "linux-image-6.12.25-rpt-rpi-2712", "linux-image-6.12.25+RPT-rpi-v8"])
def test_vendor_marker_in_name_even_with_clean_version(tmp_path, name):
    r, st, detail, ev = run(tmp_path, [pkg(name, "6.12.25-1")])
    assert st == "GAP" and flagged(ev) == [(name, "6.12.25-1")]


def test_similar_but_not_vendor_suffix_not_flagged(tmp_path):
    """+rptx 這類後面接字母的不算已知後綴；名稱只有 rpt 沒有 + 或前後 - 的也不算（不模糊比對）。"""
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.1.0-rptx", "6.1.0-1+rptx")])
    assert st == "OK" and ev["off_series"] == []


# ---------- 規則 c：明確宣告 ----------

def test_explicit_declaration_is_gap_with_reason(tmp_path):
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.1.84-8-x", "6.1.84-8")], extra=["--not-distro-kernel", "廠商核心，版本字串看不出來"])
    assert st == "GAP" and "廠商核心，版本字串看不出來" in detail and "核心不在發行版的核心序列上" in detail
    assert ev["not_distro_declared"] == "廠商核心，版本字串看不出來" and ev["off_series"][0]["name"] is None


def test_explicit_declaration_without_kernel_stays_not_run(tmp_path):
    r, st, detail, ev = run(tmp_path, [pkg("openssl", "3.0.13-0ubuntu3.5")], grype=False, extra=["--not-distro-kernel", "x"])
    assert st == "NOT_RUN" and "SBOM 沒有作業系統核心" in detail and ev["off_series"] == []


@pytest.mark.parametrize("bad", ["", "   ", "a\nb", "a\tb", "x" * 301])
def test_explicit_declaration_bad_reason_is_fail(tmp_path, bad):
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.1.84-8-x", "6.1.84-8")], extra=["--not-distro-kernel", bad])
    assert r.returncode == 3 and st == "FAIL" and "--not-distro-kernel" in detail


# ---------- 規則 d：purl 的 upstream= ----------

RADXA = "?arch=arm64&distro=debian-12.15&upstream=linux-upstream"


def test_radxa_shape_flagged(tmp_path):
    comps = [pkg("linux-image-6.1.84-8-rk2410", "6.1.84-8", RADXA)]
    r, st, detail, ev = run(tmp_path, comps)
    assert st == "GAP" and "規則 d" in ev["off_series"][0]["reason"] and "linux-upstream" in ev["off_series"][0]["reason"]
    # 中介套件：來源 linux-rk2410，Debian purl、來源不是 Debian 建核心的來源 → 也算
    meta = [pkg("linux-image-rock-5b", "1.0.0", "?arch=arm64&distro=debian-12.15&upstream=linux-rk2410")]
    r, st, detail, ev = run(tmp_path, meta)
    assert st == "GAP" and "linux-rk2410" in ev["off_series"][0]["reason"]


def test_upstream_qualifier_is_parsed_properly(tmp_path):
    """upstream=name%40version（URL 編碼的 name@version）取名稱。"""
    enc = "?arch=arm64&distro=debian-12.15&upstream=linux-upstream%401.2"
    assert kc.purl_upstream_name(f"pkg:deb/debian/x@1{enc}") == "linux-upstream"
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-x", "6.1.84-8", enc)])
    assert st == "GAP"
    ok = "?arch=arm64&distro=debian-13&upstream=linux%406.12.43-1"
    assert kc.purl_upstream_name(f"pkg:deb/debian/x@1{ok}") == "linux"
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.12.43+deb13-arm64", "6.12.43-1", ok)])
    assert st == "OK" and ev["off_series"] == []


@pytest.mark.parametrize("name,ver,tail", [
    ("linux-image-6.12.43+deb13-arm64", "6.12.43-1", "?arch=arm64&distro=debian-13&upstream=linux"),
    ("linux-image-6.12.43+deb13-arm64", "6.12.43-1", "?arch=arm64&distro=debian-13"),          # 沒有 upstream：規則 d 不適用
    ("linux-image-6.12.43+deb13-arm64", "6.12.43-1", ""),                                       # 沒有任何限定詞
    ("linux-signed-arm64", "6.12.43+1", "?arch=arm64&distro=debian-13&upstream=linux-signed-arm64"),
    ("linux-image-arm64", "6.12.43-1", "?arch=arm64&distro=debian-13&upstream=linux-latest"),
    ("linux-image-6.12.43+deb13-amd64", "6.12.43-1", "?arch=amd64&distro=debian-13&upstream=linux-signed-amd64%406.12.43%2B1"),
])
def test_debian_kernels_not_flagged(tmp_path, name, ver, tail):
    r, st, detail, ev = run(tmp_path, [pkg(name, ver, tail)])
    assert st == "OK" and ev["off_series"] == [], detail


@pytest.mark.parametrize("name,ver,src", [
    ("linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux"),
    ("linux-image-6.8.0-1021-nvidia-tegra", "6.8.0-1021.21", "linux-nvidia-tegra"),
    ("linux-nvidia-tegra", "6.8.0-1021.21", "linux-nvidia-tegra"),
    ("linux-image-6.8.0-1015-raspi", "6.8.0-1015.16", "linux-raspi"),
    ("linux-image-6.8.0-1012-aws", "6.8.0-1012.13", "linux-aws"),
])
def test_ubuntu_flavor_kernels_not_flagged(tmp_path, name, ver, src):
    r, st, detail, ev = run(tmp_path, [pkg(name, ver, f"?arch=arm64&distro=ubuntu-24.04&upstream={src}", ns="ubuntu")])
    assert st == "OK" and ev["off_series"] == [], detail


def test_ubuntu_with_linux_upstream_is_flagged(tmp_path):
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.1.0-x", "6.1.0-1", "?arch=arm64&distro=ubuntu-24.04&upstream=linux-upstream", ns="ubuntu")])
    assert st == "GAP" and "linux-upstream" in ev["off_series"][0]["reason"]


# ---------- 不該被標的：Jetson、一般 Debian／Ubuntu、沒有核心 ----------

def test_jetson_kernel_packages_not_flagged(tmp_path):
    tegra = "?arch=arm64&distro=ubuntu-24.04&upstream=nvidia-l4t-kernel"
    comps = [pkg("linux-nvidia-tegra", "6.8.0-1021.21", "?arch=arm64&distro=ubuntu-24.04&upstream=linux-nvidia-tegra", ns="ubuntu"),
             pkg("nvidia-l4t-kernel", "6.8.12-tegra-39.2.0-20260806224157", tegra, ns="ubuntu"),
             pkg("nvidia-l4t-kernel-dtbs", "6.8.12-tegra-39.2.0-20260806224157", tegra, ns="ubuntu")]
    r, st, detail, ev = run(tmp_path, comps)
    assert st == "OK" and ev["off_series"] == [] and "核心有比對" in detail
    # 即使 purl 長得像 Debian 的（來源套件不是 linux），nvidia-l4t-kernel* 也例外
    d = [pkg("nvidia-l4t-kernel", "6.8.12-tegra-39.2.0-20260806224157", "?arch=arm64&distro=debian-12&upstream=nvidia-l4t-kernel")]
    r, st, detail, ev = run(tmp_path, d)
    assert st == "OK" and ev["off_series"] == []


def test_plain_debian_ubuntu_unchanged(tmp_path):
    for comps in ([pkg("linux-image-6.12.43+deb13-arm64", "6.12.43-1", "?arch=arm64&distro=debian-13&upstream=linux")],
                  [pkg("linux-image-6.8.0-45-generic", "6.8.0-45.45", "?arch=amd64&distro=ubuntu-24.04&upstream=linux", ns="ubuntu")]):
        r, st, detail, ev = run(tmp_path, comps)
        assert st == "OK" and "核心有比對" in detail and ev["off_series"] == []
        assert ev["not_distro_declared"] is None


def test_off_series_without_matches_is_gap_and_says_so(tmp_path):
    r, st, detail, ev = run(tmp_path, [pkg("linux-image-6.18.50-x", "1:6.18.50-1+rpt1")], grype=False)
    assert st == "GAP" and "核心不在發行版的核心序列上" in detail and "0 筆" in detail


def test_only_deb_packages_are_judged_by_rules(tmp_path):
    c = pkg("kernel-core", "1:6.1.0-1+rpt1", typ="rpm", ns="fedora")
    r, st, detail, ev = run(tmp_path, [c])
    assert st == "OK" and ev["off_series"] == []


def test_no_kernel_not_run_unchanged(tmp_path):
    r, st, detail, ev = run(tmp_path, [pkg("openssl", "1:3.0.13-1+rpt1")], grype=False)
    assert st == "NOT_RUN" and "SBOM 沒有作業系統核心" in detail


# ---------- 資料檔壞了：不靜默通過 ----------

def lib_copy(tmp_path, data):
    d = tmp_path / "lib"
    (d / "data").mkdir(parents=True)
    shutil.copy(LIB, d / "kernelcheck.py")
    if data is not None:
        (d / "data" / "distro-kernel-sources.json").write_text(data, encoding="utf-8")
    return d / "kernelcheck.py"


@pytest.mark.parametrize("data", [None, "{not json", "[]", json.dumps({"schema": "x"}),
                                  json.dumps({"schema": "sca-pilot-distro-kernel-sources/1", "debian": {"sources": []}, "ubuntu": {}, "always_off_series": []})])
def test_missing_or_malformed_data_file_is_fail(tmp_path, data):
    work = tmp_path / "w"
    work.mkdir()
    r, st, detail, ev = run(work, [pkg("linux-image-6.12.43+deb13-arm64", "6.12.43-1", "?distro=debian-13&upstream=linux")], lib=lib_copy(tmp_path, data))
    assert r.returncode == 3 and st == "FAIL" and "資料檔" in detail and "規則 d" in detail


def test_data_file_is_valid_and_documents_sources():
    doc = json.loads((PILOT / "lib" / "data" / "distro-kernel-sources.json").read_text(encoding="utf-8"))
    assert doc["schema"] == kc.DISTRO_SOURCES_SCHEMA and "linux" in doc["debian"]["sources"]
    assert "tracker.debian.org/pkg/" in doc["debian"]["evidence"] and doc["ubuntu"]["rule"] == "not applied"
    assert doc["always_off_series"] == ["linux-upstream"]


# ---------- 規則是「或」，purl 先解碼 ----------

RPI_PURL = "pkg:deb/debian/linux-image-6.18.50%2Brpt-rpi-2712@1%3A6.18.50-1%2Brpt1?arch=arm64&distro=debian-13.7&upstream=linux"


def raw(name, version, purl):
    return {"type": "library", "name": name, "version": version, "purl": purl, "properties": [{"name": "syft:package:type", "value": "deb"}]}


def test_real_raspberry_pi_purl_flagged_by_epoch_and_rpt_despite_debian_upstream(tmp_path):
    """upstream=linux 在 Debian 的清單裡，但不能取消 epoch 與 +rpt。"""
    r, st, detail, ev = run(tmp_path, [raw("linux-image-6.18.50+rpt-rpi-2712", "1:6.18.50-1+rpt1", RPI_PURL)])
    assert (r.returncode, st) == (0, "GAP")
    rs = ev["off_series"][0]["reasons"]
    assert any(x.startswith("規則 a") for x in rs) and any(x.startswith("規則 b") and "+rpt" in x for x in rs)
    assert not any(x.startswith("規則 d") for x in rs)
    assert "epoch" in detail and "+rpt" in detail


def test_purl_alone_is_decoded_and_enough(tmp_path):
    """SBOM 元件的 version 欄位乾淨、名稱乾淨，只有 purl（URL 編碼）帶線索 → 解碼後照樣成立。"""
    r, st, detail, ev = run(tmp_path, [raw("linux-image-x", "6.18.50-1", RPI_PURL.replace("linux-image-6.18.50%2Brpt-rpi-2712", "linux-image-x"))])
    assert st == "GAP"
    assert any(x.startswith("規則 a") for x in ev["off_series"][0]["reasons"])
    # 反過來：欄位有線索、purl 乾淨
    r, st, detail, ev = run(tmp_path, [raw("linux-image-x", "1:6.18.50-1", "pkg:deb/debian/linux-image-x@6.18.50-1?arch=arm64&distro=debian-13&upstream=linux")])
    assert st == "GAP" and any(x.startswith("規則 a") for x in ev["off_series"][0]["reasons"])


def test_epoch_only_and_rpt_only_variants(tmp_path):
    only_epoch = "pkg:deb/debian/linux-image-6.18.50-rpi-2712@1%3A6.18.50-1?arch=arm64&distro=debian-13.7&upstream=linux"
    r, st, detail, ev = run(tmp_path, [raw("linux-image-6.18.50-rpi-2712", "1:6.18.50-1", only_epoch)])
    assert st == "GAP" and [x[:4] for x in ev["off_series"][0]["reasons"]] == ["規則 a"]
    only_rpt = "pkg:deb/debian/linux-image-6.18.50-rpi-2712@6.18.50-1%2Brpt1?arch=arm64&distro=debian-13.7&upstream=linux"
    r, st, detail, ev = run(tmp_path, [raw("linux-image-6.18.50-rpi-2712", "6.18.50-1+rpt1", only_rpt)])
    assert st == "GAP" and [x[:4] for x in ev["off_series"][0]["reasons"]] == ["規則 b"]


def test_reasons_are_collected_not_first_match():
    rs = kc.off_series_reasons("linux-image-6.18.50+rpt-rpi-2712", "1:6.18.50-1+rpt1", RPI_PURL, kc.load_distro_sources())
    assert [x[:4] for x in rs] == ["規則 a", "規則 b", "規則 b"]          # epoch、版本的 +rpt、名稱的 +rpt
    assert kc.off_series_reasons("linux-image-6.12.43+deb13-arm64", "6.12.43-1", "pkg:deb/debian/linux-image-6.12.43%2Bdeb13-arm64@6.12.43-1?distro=debian-13&upstream=linux") == []
    assert kc.purl_version(RPI_PURL) == "1:6.18.50-1+rpt1"
