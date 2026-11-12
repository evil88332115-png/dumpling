"""D-distro-recheck（lib/distro_recheck.py）與 tools/mirror/osv-distro.sh。（常駐環境的 deploy 腳本與 mirror-sync 的測試沒有帶進來，見 docs/PROVENANCE.md。）

紀錄的形狀取自 2026-11-02 下載的 OSV 資料桶（Ubuntu/all.zip 的 UBUNTU-CVE-2024-6119、USN-6986-1；Debian/all.zip 的
DEBIAN-CVE-2024-6119、DSA-*）；DT finding 的形狀取自 round14 Jetson R39.2.1 基礎版（run 41376872500）。
"""
import datetime
import hashlib
import http.server
import json
import lzma
import os
import subprocess
import sys
import tarfile
import threading
import zipfile
from pathlib import Path

import pytest

PILOT = Path(__file__).resolve().parents[1]
ROOT = PILOT.parents[1]
sys.path.insert(0, str(PILOT / "lib"))
import distro_recheck as dr  # noqa: E402

LIB = PILOT / "lib" / "distro_recheck.py"
MIRROR_SH = ROOT / "tools" / "mirror" / "osv-distro.sh"
U24 = "distro=ubuntu-24.04"
OSSL = "3.0.13-0ubuntu3.11"


def now(days=0.0):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- 假資料 ----------

def finding(name, version, vid, source="NVD", purl=None, aliases=(), kev=False, severity="HIGH", cpe=None):
    return {"component": {"name": name, "version": version, "purl": purl or f"pkg:deb/ubuntu/{name}@{version}?arch=arm64&{U24}",
                          **({"cpe": cpe} if cpe else {})},
            "vulnerability": {"source": source, "vulnId": vid, "severity": severity, "isKev": kev, "aliases": list(aliases)},
            "analysis": {"isSuppressed": False}}


def aff(name, eco, fixed=None, introduced="0", versions=(), last_affected=None):
    ev = [{"introduced": introduced}] + ([{"fixed": fixed}] if fixed else []) + ([{"last_affected": last_affected}] if last_affected else [])
    return {"package": {"name": name, "ecosystem": eco, "purl": f"pkg:deb/ubuntu/{name}?arch=source"},
            "ranges": [{"type": "ECOSYSTEM", "events": ev}], "versions": list(versions)}


def rec(rid, affected, upstream=None, modified="2026-04-22T15:27:29Z", **kw):
    return {"id": rid, "modified": modified, "published": "2024-09-03T00:00:00Z", "upstream": upstream or [], "affected": affected, **kw}


UBUNTU = [
    rec("UBUNTU-CVE-2024-6119", [aff("openssl", "Ubuntu:22.04:LTS", "3.0.2-0ubuntu1.18"), aff("openssl", "Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.4"),
                                 aff("openssl-fips", "Ubuntu:Pro:FIPS-updates:24.04:LTS", "3.0.13-0ubuntu3.6+Fips1")], ["CVE-2024-6119"]),
    rec("UBUNTU-CVE-2026-45447", [aff("openssl", "Ubuntu:24.04:LTS", OSSL)], ["CVE-2026-45447"], modified="2026-10-17T12:55:37Z"),
    rec("UBUNTU-CVE-2026-63076", [aff("openssl", "Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.15")], ["CVE-2026-63076"]),       # 還沒修到
    rec("UBUNTU-CVE-2026-11111", [aff("openssl", "Ubuntu:24.04:LTS")], ["CVE-2026-11111"]),                               # 沒有修補
    rec("UBUNTU-CVE-2026-22222", [aff("openssl", "Ubuntu:22.04:LTS", "3.0.2-0ubuntu1.25"),
                                  aff("openssl", "Ubuntu:Pro:24.04:LTS", "3.0.13-0ubuntu3.1")], ["CVE-2026-22222"]),        # 沒列 24.04 主生態系
    rec("UBUNTU-CVE-2026-33333", [aff("openssl", "Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.1")], ["CVE-2026-33333"], withdrawn="2026-10-01T00:00:00Z"),
    rec("UBUNTU-CVE-2025-30258", [aff("gnupg2", "Ubuntu:24.04:LTS", "2.4.4-2ubuntu17.2")], ["CVE-2025-30258"]),
    rec("UBUNTU-CVE-2026-44444", [aff("linux-nvidia-tegra", "Ubuntu:24.04:LTS", "6.8.0-1001.1"), aff("linux", "Ubuntu:24.04:LTS", "6.8.0-1.1")],
        ["CVE-2026-44444"]),
    rec("UBUNTU-CVE-2026-55555", [aff("openssl", "Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.2")], ["CVE-2026-55555"]),
    rec("UBUNTU-CVE-2026-66666", [aff("openssl", "Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.20")], ["CVE-2026-66666"]),
    # 公告：USN 說 3.0.13-0ubuntu3.3 修好 CVE-2026-77777，每個 CVE 一筆的紀錄說要 3.0.13-0ubuntu3.12（之後才修完整）
    rec("UBUNTU-CVE-2026-77777", [aff("openssl", "Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.12")], ["CVE-2026-77777"]),
    rec("USN-9000-1", [aff("openssl", "Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.3")], ["CVE-2026-77777", "UBUNTU-CVE-2026-77777"]),
    # 只有公告、沒有每個 CVE 一筆的紀錄
    rec("USN-9001-1", [aff("openssl", "Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.5")], ["CVE-2026-88888", "UBUNTU-CVE-2026-88888"]),
    # 審查的實例（2026-11-02 的資料）：USN-8820-1 列了 CVE-2026-80229 與 noble 的 curl 修補版本，UBUNTU-CVE-2026-80229 只列 26.04、26.10
    rec("UBUNTU-CVE-2026-80229", [aff("curl", "Ubuntu:26.10", "8.20.0-2ubuntu11"), aff("curl", "Ubuntu:26.04:LTS", "8.18.0-1ubuntu2.7")], ["CVE-2026-80229"]),
    rec("USN-8820-1", [aff("curl", "Ubuntu:22.04:LTS", "7.81.0-1ubuntu1.29"), aff("curl", "Ubuntu:24.04:LTS", "8.5.0-2ubuntu10.15")],
        ["CVE-2026-80229", "UBUNTU-CVE-2026-80229"]),
    # CVE-2025-9086：UBUNTU-CVE 只列 25.10（不完整），USN-8062-1 有 noble 的修補
    rec("UBUNTU-CVE-2025-9086", [aff("curl", "Ubuntu:25.10", "8.14.1-2ubuntu1.1")], ["CVE-2025-9086"]),
    rec("USN-8062-1", [aff("curl", "Ubuntu:24.04:LTS", "8.5.0-2ubuntu10.7")], ["CVE-2025-9086", "UBUNTU-CVE-2025-9086"]),
    # 只在 related 列 CVE 的公告（多半是 regression 公告）：不算
    rec("USN-9002-2", [aff("openssl", "Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.1")], [], related=["CVE-2026-90000", "UBUNTU-CVE-2026-90000"]),
]
DEBIAN = [
    rec("DEBIAN-CVE-2024-6119", [aff("openssl", "Debian:12", "3.0.14-1~deb12u2"), aff("openssl", "Debian:13", "3.3.2-1")], ["CVE-2024-6119"]),
    rec("DEBIAN-CVE-2026-12345", [aff("glibc", "Debian:12", "2.36-9+deb12u10")], ["CVE-2026-12345"]),
    rec("DSA-6000-1", [aff("glibc", "Debian:12", "2.36-9+deb12u4")], ["CVE-2026-12345", "DEBIAN-CVE-2026-12345"]),
    rec("DLA-4000-1", [aff("openssl", "Debian:11", "1.1.1w-0+deb11u2")], ["CVE-2024-6119", "DEBIAN-CVE-2024-6119"]),
]


def write_zip(p, records, pad=0):
    p.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        for r in records:
            z.writestr(r["id"] + ".json", json.dumps(r))
        prefix = "UBUNTU-CVE-" if "Ubuntu" in str(p) else "DEBIAN-CVE-"
        eco = "Ubuntu:24.04:LTS" if prefix.startswith("UBUNTU") else "Debian:12"
        for i in range(pad):                # 補到 --check 的最低筆數
            z.writestr(f"{prefix}2000-{i:05d}.json", json.dumps(rec(f"{prefix}2000-{i:05d}", [aff("x", eco, "1")])))


def make_mirror(d, ubuntu=UBUNTU, debian=DEBIAN, fetched=None, pad=0):
    srcl = [f"source=file://test", f"ecosystems=Ubuntu Debian", f"fetched_utc={fetched or now()}"]
    for e, recs in (("Ubuntu", ubuntu), ("Debian", debian)):
        p = d / e / "all.zip"
        write_zip(p, recs, pad)
        srcl += [f"{e.lower()}_sha256={hashlib.sha256(p.read_bytes()).hexdigest()}", f"{e.lower()}_bytes={p.stat().st_size}",
                 f"{e.lower()}_last_modified=Sat, 31 Oct 2026 03:33:15 GMT"]
    (d / "SOURCE").write_text("\n".join(srcl) + "\n", encoding="utf-8")
    return d


def gmatch(vid, name, version, purl, related=(), upstreams=()):
    return {"vulnerability": {"id": vid, "fix": {"state": "fixed", "versions": []}}, "relatedVulnerabilities": [{"id": r} for r in related],
            "artifact": {"name": name, "version": version, "type": "deb", "purl": purl, "upstreams": [{"name": u} for u in upstreams]}}


def run_recheck(findings, mirror, grype=None, bom=None, dsj=None, kmap=None, max_age=3):
    return dr.recheck(findings, {"matches": grype or []}, bom, dsj, kmap, str(mirror) if mirror else None, max_age)


def by_cve(out):
    return {r["key"][0]: r for r in out["rows"]}


# ---------- 版本比較與範圍 ----------

@pytest.mark.parametrize("a,b,want", [
    (OSSL, "3.0.13-0ubuntu3.4", 1),                      # 數字段以數值比（11 > 4），字串比較會錯
    ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.4", 0),
    ("1:1.0-1", "2.0-1", 1),                              # epoch 優先
    ("1.0~rc1-1", "1.0-1", -1),                           # ~ 比結尾小
    ("1.0~~-1", "1.0~-1", -1),
    ("1.0-1+b1", "1.0-1", 1),                             # binNMU
    ("1.01", "1.1", 0),                                   # 前導 0 不算
    ("1.0a", "1.0+", -1),                                 # 字母排在符號前面
    ("2.4.4-2ubuntu17.4", "2.4.4-2ubuntu17.2", 1),
    ("3.0.13-0ubuntu3.6+Fips1", "3.0.13-0ubuntu3.6", 1),
    ("1.0", "1.0-0", 0),                                  # 沒有 revision 等於 revision 0
    ("2.36-9+deb12u10", "2.36-9+deb12u4", 1),
])
def test_deb_vercmp_edge_cases(a, b, want):
    assert dr.vercmp(a, b) == want and dr.vercmp(b, a) == -want


@pytest.mark.parametrize("entry,ver,affected,passed", [
    (aff("p", "e", "3.0.13-0ubuntu3.4"), OSSL, False, "3.0.13-0ubuntu3.4"),
    (aff("p", "e", OSSL), OSSL, False, OSSL),                                    # 剛好等於修補版本：已修補
    (aff("p", "e", "3.0.13-0ubuntu3.15"), OSSL, True, None),
    (aff("p", "e"), OSSL, True, None),                                            # 沒有修補版本
    (aff("p", "e", "2.0", introduced="1.5"), "1.0", False, None),                 # 早於 introduced：不受影響，也不是「修好」
    (aff("p", "e", last_affected="1.0"), "1.1", False, None),
    (aff("p", "e", last_affected="1.0"), "1.0", True, None),
    (aff("p", "e", "1.0", versions=["2.0"]), "2.0", True, "1.0"),                # versions 清單裡有安裝的版本：受影響
    ({"package": {"name": "p", "ecosystem": "e"}}, "1.0", True, None),            # 沒有可判斷的範圍：保守當作受影響
    ({"package": {"name": "p", "ecosystem": "e"}, "ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.5"}]}]}, "2.3", True, "1.0"),   # 第二段又受影響
])
def test_evaluate_osv_ranges(entry, ver, affected, passed):
    r = dr.evaluate(entry, ver)
    assert r["affected"] is affected and r["fixed_passed"] == passed


@pytest.mark.parametrize("ns,distro,want", [
    ("ubuntu", "ubuntu-24.04", ("Ubuntu", "24.04", "noble", ["Ubuntu:24.04:LTS", "Ubuntu:24.04"])),
    ("ubuntu", "noble", ("Ubuntu", "24.04", "noble", ["Ubuntu:24.04:LTS", "Ubuntu:24.04"])),
    ("ubuntu", "ubuntu-noble", ("Ubuntu", "24.04", "noble", ["Ubuntu:24.04:LTS", "Ubuntu:24.04"])),
    ("ubuntu", "22.04", ("Ubuntu", "22.04", "jammy", ["Ubuntu:22.04:LTS", "Ubuntu:22.04"])),
    ("ubuntu", "ubuntu-25.10", ("Ubuntu", "25.10", "questing", ["Ubuntu:25.10:LTS", "Ubuntu:25.10"])),
    ("debian", "debian-12", ("Debian", "12", "bookworm", ["Debian:12"])),
    ("debian", "debian-12.5", ("Debian", "12", "bookworm", ["Debian:12"])),
    ("debian", "bookworm", ("Debian", "12", "bookworm", ["Debian:12"])),
    ("debian", "debian-trixie", ("Debian", "13", "trixie", ["Debian:13"])),
    ("debian", "debian-unstable", None), ("ubuntu", "ubuntu-99.04", None), ("ubuntu", "", None), ("alpine", "alpine-3.20", None),
    ("ubuntu", "bookworm", None),                       # 別的發行版的代號
])
def test_release_mapping(ns, distro, want):
    r = dr.release_of(ns, distro)
    assert (r and (r["distro"], r["version"], r["codename"], r["ecosystems"])) == want


# ---------- 判定 ----------

def test_decisions_on_ubuntu(tmp_path):
    m = make_mirror(tmp_path / "m")
    fs = [finding("openssl", OSSL, c) for c in ("CVE-2024-6119", "CVE-2026-45447", "CVE-2026-63076", "CVE-2026-11111", "CVE-2026-22222",
                                                "CVE-2026-33333", "CVE-2026-99999", "CVE-2026-77777", "CVE-2026-88888")]
    st, detail, out = run_recheck(fs, m)
    assert st == "OK" and out["status"] == "OK" and out["schema"] == "sca-distro-recheck/1"
    r = by_cve(out)
    want = {"CVE-2024-6119": "distro_fixed", "CVE-2026-45447": "distro_fixed", "CVE-2026-63076": "distro_affected",
            "CVE-2026-11111": "distro_affected", "CVE-2026-22222": "distro_not_listed", "CVE-2026-33333": "no_distro_record",
            "CVE-2026-99999": "no_distro_record", "CVE-2026-77777": "distro_affected",
            "CVE-2026-88888": "distro_fixed_advisory_only"}                     # 只有公告：不算已修補，照常保留
    assert {k: v["decision"] for k, v in r.items()} == want
    ev = r["CVE-2024-6119"]["evidence"]
    assert ev == [{"record": "UBUNTU-CVE-2024-6119", "kind": "per_cve", "modified": "2026-04-22T15:27:29Z", "published": "2024-09-03T00:00:00Z",
                   "upstream": ["CVE-2024-6119"], "cve": "CVE-2024-6119", "ecosystem": "Ubuntu:24.04:LTS", "package": "openssl",
                   "installed_version": OSSL, "fixed_versions": ["3.0.13-0ubuntu3.4"], "fixed_version": "3.0.13-0ubuntu3.4",
                   "affected": False, "no_fix": False}]
    assert r["CVE-2024-6119"]["release"] == {"distro": "Ubuntu", "version": "24.04", "codename": "noble"}
    assert r["CVE-2024-6119"]["key"] == ["CVE-2024-6119", "ubuntu/openssl", OSSL] and r["CVE-2024-6119"]["source_ids"] == ["NVD:CVE-2024-6119"]
    assert r["CVE-2026-11111"]["evidence"][0]["no_fix"] is True and "沒有修補版本" in r["CVE-2026-11111"]["reason"]
    # 有每個 CVE 一筆的紀錄時只看它；公告（說 3.3 就修好）只記在 advisory_evidence
    assert [e["record"] for e in r["CVE-2026-77777"]["evidence"]] == ["UBUNTU-CVE-2026-77777"]
    assert [e["record"] for e in r["CVE-2026-77777"]["advisory_evidence"]] == ["USN-9000-1"]
    assert r["CVE-2026-88888"]["evidence"][0]["record"] == "USN-9001-1" and "只有公告" in r["CVE-2026-88888"]["reason"]
    assert "UBUNTU-CVE-2026-22222" in r["CVE-2026-22222"]["reason"]
    c = out["counts"]
    assert (c["distro_fixed"], c["distro_affected"], c["distro_not_listed"], c["distro_fixed_advisory_only"], c["no_distro_record"],
            c["rows"]) == (2, 3, 1, 1, 2, 9)
    assert out["mirror"]["ok"] and out["mirror"]["ecosystems"]["Ubuntu"]["upstream_last_modified"].startswith("Sat")
    assert "發行版已修補（backport）2" in detail and "只有公告說已修補 1" in detail and "Debian" not in out["mirror"]["ecosystems"]   # 只開需要的生態系


def test_advisory_does_not_override_per_cve_record(tmp_path):
    """審查的兩個實例：公告的 CVE 清單涵蓋整份公告，不能單獨判「已修補」。"""
    m = make_mirror(tmp_path / "m")
    curl = "8.5.0-2ubuntu10.15"
    r = by_cve(run_recheck([finding("curl", curl, "CVE-2026-80229"), finding("curl", curl, "CVE-2025-9086"),
                            finding("openssl", OSSL, "CVE-2026-90000")], m)[2])
    # CVE-2026-80229：USN-8820-1 說 noble 已修補，但 UBUNTU-CVE-2026-80229 沒列 noble → distro_not_listed（保留）
    x = r["CVE-2026-80229"]
    assert x["decision"] == "distro_not_listed" and x["evidence"] == [] and "USN-8820-1" in x["reason"] and "不採用" in x["reason"]
    assert [e["record"] for e in x["advisory_evidence"]] == ["USN-8820-1"]
    # CVE-2025-9086：UBUNTU-CVE 只列 25.10（紀錄不完整），USN-8062-1 有 noble 的修補 → 仍是 distro_not_listed（保守，保留）
    assert r["CVE-2025-9086"]["decision"] == "distro_not_listed"
    # 只在 related 列的 CVE 不建索引 → 沒有紀錄
    assert r["CVE-2026-90000"]["decision"] == "no_distro_record"


def test_skips_grype_kernel_distro_source_and_unknown_release(tmp_path):
    m = make_mirror(tmp_path / "m")
    kpurl = "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"
    fs = [
        # Grype 對二進位套件 libssl3t64（原始碼 openssl）比對到同一個 CVE：照 Grype
        finding("openssl", OSSL, "CVE-2026-63076"),
        # 同一列也有 DT 的 Ubuntu 紀錄
        finding("openssl", OSSL, "CVE-2024-6119"), finding("openssl", OSSL, "UBUNTU-CVE-2024-6119", source="OSV"),
        # 核心：C-kernel-l4t-map 加上的元件、linux-libc-dev（原始碼 linux）
        finding("linux-nvidia-tegra", "6.8.0-1021.21", "CVE-2026-44444", purl=kpurl),
        finding("linux-libc-dev", "6.8.0-134.134", "CVE-2026-44444", purl=f"pkg:deb/ubuntu/linux-libc-dev@6.8.0-134.134?arch=arm64&upstream=linux&{U24}"),
        # 認不得發行版本
        finding("openssl", "3.0.17-1", "CVE-2024-6119", purl="pkg:deb/debian/openssl@3.0.17-1?arch=amd64&distro=debian-unstable"),
        # 只有發行版的 finding：不是候選，不出現
        finding("curl", "8.5.0-2ubuntu10.6", "UBUNTU-CVE-2026-1", source="OSV"),
        # 不是 deb：不出現
        finding("pillow", "10.0.0", "CVE-2024-6119", purl="pkg:pypi/pillow@10.0.0"),
    ]
    g = [gmatch("CVE-2026-63076", "libssl3t64", OSSL, f"pkg:deb/ubuntu/libssl3t64@{OSSL}?arch=arm64&upstream=openssl&{U24}",
                related=["CVE-2026-63076"], upstreams=["openssl"])]
    kmap = {"status": "OK", "map_entry": {"component": {"purl": kpurl, "name": "linux-nvidia-tegra"}}}
    st, detail, out = run_recheck(fs, m, grype=g, kmap=kmap)
    dec = sorted((r["key"][0], r["component"], r["decision"]) for r in out["rows"])
    assert dec == [("CVE-2024-6119", "openssl", "skipped_distro_source"), ("CVE-2024-6119", "openssl", "skipped_release_unknown"),
                   ("CVE-2026-44444", "linux-libc-dev", "skipped_kernel"), ("CVE-2026-44444", "linux-nvidia-tegra", "skipped_kernel"),
                   ("CVE-2026-63076", "openssl", "skipped_grype_matched")]
    assert st == "OK" and out["mirror"] is None          # 沒有要查鏡像的列：不開鏡像
    # Grype 以 GHSA 為主編號、CVE 在 related：同樣算比對到
    g2 = [gmatch("GHSA-xxxx-yyyy-zzzz", "openssl", OSSL, f"pkg:deb/ubuntu/openssl@{OSSL}?arch=arm64&{U24}", related=["CVE-2024-6119"])]
    st, _, out = run_recheck([finding("openssl", OSSL, "CVE-2024-6119")], m, grype=g2)
    assert out["rows"][0]["decision"] == "skipped_grype_matched"


def test_only_kernel_or_nothing_is_not_run(tmp_path):
    kpurl = "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"
    st, detail, out = run_recheck([finding("linux-nvidia-tegra", "6.8.0-1021.21", "CVE-2026-44444", purl=kpurl)], None)
    assert st == "NOT_RUN" and out is None and "核心 1 列" in detail
    st, detail, out = run_recheck([finding("curl", "8.5.0", "UBUNTU-CVE-2026-1", source="OSV"), finding("x", "1", "CVE-1-1", purl="pkg:npm/x@1")], None)
    assert st == "NOT_RUN" and out is None


def test_binary_to_source_mapping(tmp_path):
    m = make_mirror(tmp_path / "m")
    # libssl3t64 → openssl：purl 的 upstream qualifier
    fs = [finding("libssl3t64", OSSL, "CVE-2024-6119", purl=f"pkg:deb/ubuntu/libssl3t64@{OSSL}?arch=arm64&upstream=openssl&{U24}")]
    out = run_recheck(fs, m)[2]
    assert out["rows"][0]["source_package"] == "openssl" and out["rows"][0]["decision"] == "distro_fixed"
    # purl 沒有 upstream（DT 有時去掉 qualifier）：用 SBOM 的 syft:metadata:source；gnupg → gnupg2
    bom = {"components": [{"name": "gnupg", "version": "2.4.4-2ubuntu17.4", "purl": f"pkg:deb/ubuntu/gnupg@2.4.4-2ubuntu17.4?arch=all&{U24}",
                           "properties": [{"name": "syft:metadata:source", "value": "gnupg2"}]},
                          {"name": "libssl3t64", "version": OSSL, "purl": f"pkg:deb/ubuntu/libssl3t64@{OSSL}?arch=arm64&upstream=openssl&{U24}"}]}
    fs = [finding("gnupg", "2.4.4-2ubuntu17.4", "CVE-2025-30258"),
          finding("libssl3t64", OSSL, "CVE-2024-6119", purl=f"pkg:deb/ubuntu/libssl3t64@{OSSL}?arch=arm64&{U24}")]
    r = {x["component"]: x for x in run_recheck(fs, m, bom=bom)[2]["rows"]}
    assert (r["gnupg"]["source_package"], r["gnupg"]["decision"]) == ("gnupg2", "distro_fixed")
    assert (r["libssl3t64"]["source_package"], r["libssl3t64"]["decision"]) == ("openssl", "distro_fixed")
    # 原始碼版本取 upstream 的 <名稱>@<版本>（binNMU：二進位 +b1）
    s = dr.sbom_sources({"components": [{"name": "libfoo1", "purl": "pkg:deb/debian/libfoo1@1.0-1%2Bb1?arch=amd64&upstream=foo%401.0-1&distro=debian-12"}]})
    assert s[("debian", "libfoo1", "1.0-1+b1")] == ("foo", "1.0-1")
    # DT 對到 deb_sources 加上的原始碼元件（arch=source）：名稱就是原始碼；deb-sources.json 列出安裝的二進位套件（核心判斷與 Grype 用）
    dsj = {"added": [{"purl": f"pkg:deb/ubuntu/gnupg2@2.4.4-2ubuntu17.4?arch=source&{U24}", "binaries": "gnupg",
                      "binary_purls": [f"pkg:deb/ubuntu/gnupg@2.4.4-2ubuntu17.4?arch=all&upstream=gnupg2&{U24}"]}]}
    fs = [finding("gnupg2", "2.4.4-2ubuntu17.4", "CVE-2025-30258", purl=f"pkg:deb/ubuntu/gnupg2@2.4.4-2ubuntu17.4?arch=source&{U24}")]
    row = run_recheck(fs, m, dsj=dsj)[2]["rows"][0]
    assert row["installed_as"] == ["gnupg"] and row["decision"] == "distro_fixed"
    g = [gmatch("CVE-2025-30258", "gnupg", "2.4.4-2ubuntu17.4", f"pkg:deb/ubuntu/gnupg@2.4.4-2ubuntu17.4?arch=all&{U24}")]
    assert run_recheck(fs, m, dsj=dsj, grype=g)[2]["rows"][0]["decision"] == "skipped_grype_matched"   # Grype 對安裝的二進位套件


def test_debian_release_and_advisories(tmp_path):
    m = make_mirror(tmp_path / "m")
    deb = lambda n, v, rel="debian-12": f"pkg:deb/debian/{n}@{v}?arch=amd64&distro={rel}"   # noqa: E731
    fs = [finding("openssl", "3.0.15-1~deb12u1", "CVE-2024-6119", purl=deb("openssl", "3.0.15-1~deb12u1")),
          finding("openssl", "1.1.1w-0+deb11u1", "CVE-2024-6119", purl=deb("openssl", "1.1.1w-0+deb11u1", "debian-11")),
          finding("openssl", "1.1.1w-0+deb11u3", "CVE-2024-6119", purl=deb("openssl", "1.1.1w-0+deb11u3", "bullseye")),
          # DSA 說 deb12u4 修好，DEBIAN-CVE 說要 deb12u10：取保守的（受影響）
          finding("libc6", "2.36-9+deb12u7", "CVE-2026-12345", purl=deb("libc6", "2.36-9+deb12u7") + "&upstream=glibc")]
    r = {(x["component"], x["version"]): x for x in run_recheck(fs, m)[2]["rows"]}
    assert r[("openssl", "3.0.15-1~deb12u1")]["decision"] == "distro_fixed"
    # DEBIAN-CVE-2024-6119 沒列 Debian 11，只有 DLA 列了：每個 CVE 一筆的紀錄說了算 → distro_not_listed（保留）
    assert r[("openssl", "1.1.1w-0+deb11u1")]["decision"] == "distro_not_listed"
    assert r[("openssl", "1.1.1w-0+deb11u3")]["decision"] == "distro_not_listed"
    assert [e["record"] for e in r[("openssl", "1.1.1w-0+deb11u3")]["advisory_evidence"]] == ["DLA-4000-1"]
    x = r[("libc6", "2.36-9+deb12u7")]
    assert x["decision"] == "distro_affected" and [e["record"] for e in x["evidence"]] == ["DEBIAN-CVE-2026-12345"]


def test_multi_cve_row_is_conservative(tmp_path):
    m = make_mirror(tmp_path / "m")
    # GHSA 有兩個 CVE 別名：cra_report 以第一個 CVE 為鍵；兩個都要已修補才算 distro_fixed
    f = finding("openssl", OSSL, "GHSA-aaaa-bbbb-cccc", source="GITHUB", aliases=[{"cveId": "CVE-2026-55555"}, {"cveId": "CVE-2026-66666"}])
    row = run_recheck([f], m)[2]["rows"][0]
    assert row["key"][0] == "CVE-2026-55555" and row["decision"] == "distro_affected"
    assert [p["decision"] for p in row["per_cve"]] == ["distro_fixed", "distro_affected"]
    f = finding("openssl", OSSL, "GHSA-aaaa-bbbb-cccc", source="GITHUB", aliases=[{"cveId": "CVE-2026-55555"}, {"cveId": "CVE-2024-6119"}])
    assert run_recheck([f], m)[2]["rows"][0]["decision"] == "distro_fixed"
    # OSV 的非發行版紀錄（GO-、PYSEC-）也算非發行版資料；沒有 CVE 的列 → no_distro_record
    row = run_recheck([finding("golang-1.22", "1.22.2-2ubuntu0.3", "GO-2026-1234", source="OSV")], m)[2]["rows"][0]
    assert row["decision"] == "no_distro_record" and "沒有 CVE" in row["reason"]


@pytest.mark.parametrize("what", ["none", "missing", "stale", "sha", "fifo_source", "no_debian"])
def test_mirror_problems_are_gap(tmp_path, what):
    m = make_mirror(tmp_path / "m", fetched=now(5) if what == "stale" else None)
    if what == "sha":
        with open(m / "Ubuntu" / "all.zip", "ab") as f:
            f.write(b"x")
    elif what == "fifo_source":
        (m / "SOURCE").unlink()
        os.mkfifo(m / "SOURCE")
    elif what == "no_debian":
        s = (m / "SOURCE").read_text().replace("ecosystems=Ubuntu Debian", "ecosystems=Ubuntu")
        (m / "SOURCE").write_text(s)
    path = {"none": None, "missing": tmp_path / "nope"}.get(what, m)
    fs = [finding("openssl", OSSL, "CVE-2024-6119"),
          finding("openssl", "3.0.15-1~deb12u1", "CVE-2024-6119", purl="pkg:deb/debian/openssl@3.0.15-1~deb12u1?arch=amd64&distro=debian-12")]
    st, detail, out = run_recheck(fs, path)
    assert st == "GAP" and out["status"] == "GAP" and not out["mirror"]["ok"]
    assert {r["decision"] for r in out["rows"]} == {"not_rechecked"} and out["counts"]["distro_fixed"] == 0
    reason = {"none": "沒有設定鏡像", "missing": "不存在", "stale": "過期", "sha": "sha256", "fifo_source": "不是一般檔案", "no_debian": "鏡像沒有 Debian"}[what]
    assert reason in out["mirror"]["reason"] and "沒有再判" in detail


def test_cli_writes_output_and_never_changes_inputs(tmp_path):
    m = make_mirror(tmp_path / "m")
    fpath = tmp_path / "findings.json.xz"
    fpath.write_bytes(lzma.compress(json.dumps([finding("openssl", OSSL, "CVE-2024-6119")]).encode()))
    gpath = tmp_path / "grype.json"
    gpath.write_text(json.dumps({"matches": []}))
    before = {p: p.read_bytes() for p in (fpath, gpath)}
    out = tmp_path / "distro-recheck.json"
    r = subprocess.run([sys.executable, "-I", str(LIB), "--findings", str(fpath), "--grype", str(gpath), "--mirror", str(m), "--out", str(out)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.startswith("D-distro-recheck\tOK\t") and r.stdout.count("\n") == 1
    assert json.loads(out.read_text())["rows"][0]["decision"] == "distro_fixed"
    assert {p: p.read_bytes() for p in before} == before
    # 鏡像過期：環境變數的上限
    r = subprocess.run([sys.executable, "-I", str(LIB), "--findings", str(fpath), "--mirror", str(m), "--out", str(out)],
                       capture_output=True, text=True, timeout=60, env={**os.environ, "OSV_DISTRO_MAX_AGE_DAYS": "-1"})
    assert r.returncode == 0 and r.stdout.startswith("D-distro-recheck\tGAP\t") and "沒有 Grype 結果" in r.stdout


@pytest.mark.parametrize("content,msg", [("{not json", "無法讀取"), ('{"a": 1}', "不是清單"), (None, "無法讀取")])
def test_cli_bad_input_exit_3(tmp_path, content, msg):
    f = tmp_path / "f.json"
    if content is not None:
        f.write_text(content)
    r = subprocess.run([sys.executable, "-I", str(LIB), "--findings", str(f), "--out", str(tmp_path / "o.json")],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 3 and r.stdout.startswith("D-distro-recheck\tFAIL\t") and msg in r.stdout and "Traceback" not in r.stdout + r.stderr
    assert not (tmp_path / "o.json").exists()
    r = subprocess.run([sys.executable, "-I", str(LIB), "--bogus"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 3 and "FAIL" in r.stdout


def test_real_jetson_shape_openssl(tmp_path):
    """round14 R39.2.1 基礎版的三個 openssl 例子（NVD 才有、Grype 沒比對到）都是 distro_fixed；CVE-2026-63076（DT 也有 Ubuntu 紀錄）不動。"""
    m = make_mirror(tmp_path / "m", ubuntu=UBUNTU + [rec("UBUNTU-CVE-2025-15467", [aff("openssl", "Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.7"),
                                                                                    aff("edk2", "Ubuntu:24.04:LTS")], ["CVE-2025-15467"])])
    fs = [finding("openssl", OSSL, c) for c in ("CVE-2024-6119", "CVE-2026-45447", "CVE-2025-15467")]
    fs += [finding("openssl", OSSL, "CVE-2026-63076"), finding("openssl", OSSL, "UBUNTU-CVE-2026-63076", source="OSV")]
    r = by_cve(run_recheck(fs, m)[2])
    assert {k: (v["decision"], v["evidence"][0]["fixed_version"] if v["evidence"] else None) for k, v in r.items()} == {
        "CVE-2024-6119": ("distro_fixed", "3.0.13-0ubuntu3.4"), "CVE-2026-45447": ("distro_fixed", OSSL),
        "CVE-2025-15467": ("distro_fixed", "3.0.13-0ubuntu3.7"), "CVE-2026-63076": ("skipped_distro_source", None)}


# ---------- 鏡像腳本 ----------

def bucket(tmp_path, pad=3):
    b = tmp_path / "bucket"
    write_zip(b / "Ubuntu" / "all.zip", UBUNTU, pad)
    write_zip(b / "Debian" / "all.zip", DEBIAN, pad)
    return b


def run_mirror(*args, env=None):
    e = {**os.environ, "OSV_DISTRO_MIN_RECORDS": "3", **(env or {})}
    return subprocess.run(["bash", str(MIRROR_SH), *map(str, args)], capture_output=True, text=True, timeout=120, env=e)


def test_mirror_script_builds_and_checks(tmp_path):
    b = bucket(tmp_path)
    r = run_mirror(tmp_path / "m", tmp_path / "man.txt", env={"OSV_DISTRO_BASE_URL": b.as_uri()})
    assert r.returncode == 0, r.stdout + r.stderr
    src = dict(l.split("=", 1) for l in (tmp_path / "m" / "SOURCE").read_text().splitlines())
    assert src["ecosystems"] == "Ubuntu Debian" and src["ubuntu_sha256"] == hashlib.sha256((b / "Ubuntu" / "all.zip").read_bytes()).hexdigest()
    man = (tmp_path / "man.txt").read_text()
    assert "# fetched_utc:" in man and "./Ubuntu/all.zip" in man and "./SOURCE" in man
    c = run_mirror("--check", tmp_path / "m")
    assert c.returncode == 0 and c.stdout.startswith("OK fetched_utc=") and "per_cve=" in c.stdout
    # 拒絕覆蓋
    r = run_mirror(tmp_path / "m", tmp_path / "man2.txt", env={"OSV_DISTRO_BASE_URL": b.as_uri()})
    assert r.returncode == 3 and "拒絕覆蓋" in r.stderr
    # distro_recheck 讀得了這份鏡像
    st, _, out = run_recheck([finding("openssl", OSSL, "CVE-2024-6119")], tmp_path / "m")
    assert st == "OK" and out["rows"][0]["decision"] == "distro_fixed"
    s = MIRROR_SH.read_text(encoding="utf-8")
    assert "--connect-timeout 30" in s and "--max-time" in s and "--max-filesize" in s and "OSV_DISTRO_MAX_TOTAL_MB" in s


@pytest.mark.parametrize("kind", ["symlink", "fifo", "dir_symlink"])
def test_mirror_check_rejects_non_regular_entries(tmp_path, kind):
    m = make_mirror(tmp_path / "m", pad=3)
    assert run_mirror("--check", m).returncode == 0
    secret = tmp_path / "secret.txt"
    secret.write_text("TOKEN=glrt-xyz")
    if kind == "symlink":
        os.symlink(secret, m / "Ubuntu" / "leak.json")
    elif kind == "fifo":
        os.mkfifo(m / "Debian" / "hang")
    else:
        os.symlink(tmp_path, m / "up")
    c = run_mirror("--check", m)
    assert c.returncode == 1 and "一般檔案與資料夾以外" in c.stdout


@pytest.mark.parametrize("what,msg", [("stale", "過期"), ("sha", "sha256"), ("few", "可能只下載到一部分"), ("nosource", "缺少 SOURCE"),
                                      ("badzip", "不是可讀的 zip"), ("format", "格式不是預期"), ("bomb", "OSV_DISTRO_MAX_UNPACKED_MB")])
def test_mirror_check_failures(tmp_path, what, msg):
    m = make_mirror(tmp_path / "m", fetched=now(4) if what == "stale" else None, pad=0 if what == "few" else 3)
    env = {}
    if what == "sha":
        with open(m / "Debian" / "all.zip", "ab") as f:
            f.write(b"x")
    elif what == "nosource":
        (m / "SOURCE").unlink()
    elif what == "badzip":
        (m / "Debian" / "all.zip").write_bytes(b"not a zip")
        s = (m / "SOURCE").read_text().splitlines()
        (m / "SOURCE").write_text("\n".join(l if not l.startswith("debian_sha256=") else
                                            "debian_sha256=" + hashlib.sha256(b"not a zip").hexdigest() for l in s) + "\n")
    elif what == "format":
        m = make_mirror(tmp_path / "m2", debian=[rec(f"DEBIAN-CVE-2026-{i}", [aff("x", "Ubuntu:24.04:LTS", "1")]) for i in range(5)])
    elif what == "bomb":
        env = {"OSV_DISTRO_MAX_UNPACKED_MB": "0"}
    c = run_mirror("--check", m, env={"OSV_DISTRO_MIN_RECORDS": "5" if what == "few" else "3", **env})
    assert c.returncode == 1 and msg in c.stdout, c.stdout


def test_mirror_script_size_cap_and_ecosystem_whitelist(tmp_path):
    b = bucket(tmp_path)
    r = run_mirror(tmp_path / "m", tmp_path / "man.txt", env={"OSV_DISTRO_BASE_URL": b.as_uri(), "OSV_DISTRO_MAX_TOTAL_MB": "0"})
    assert r.returncode != 0 and "OSV_DISTRO_MAX_TOTAL_MB" in r.stdout + r.stderr and not (tmp_path / "man.txt").exists()
    r = run_mirror(tmp_path / "m2", tmp_path / "man2.txt", env={"OSV_DISTRO_ECOSYSTEMS": "Ubuntu ../etc"})
    assert r.returncode == 3 and "只接受" in r.stderr


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def test_mirror_reuse_when_upstream_unchanged(tmp_path):
    """OSV_DISTRO_REUSE_FROM：上游的 Last-Modified 與大小沒變（HEAD）時沿用上一份，不重新下載；變了就下載。"""
    b = bucket(tmp_path)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), lambda *a, **k: _Quiet(*a, directory=str(b), **k))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        r1 = run_mirror(tmp_path / "r1", tmp_path / "r1.man", env={"OSV_DISTRO_BASE_URL": url})
        assert r1.returncode == 0 and "Ubuntu: 下載" in r1.stdout, r1.stdout + r1.stderr
        src1 = (tmp_path / "r1" / "SOURCE").read_text()
        assert "ubuntu_last_modified=未取得" not in src1
        write_zip(b / "Debian" / "all.zip", DEBIAN[:2], 4)            # Debian 換了一份（大小不同）
        r2 = run_mirror(tmp_path / "r2", tmp_path / "r2.man", env={"OSV_DISTRO_BASE_URL": url, "OSV_DISTRO_REUSE_FROM": str(tmp_path / "r1")})
        assert r2.returncode == 0 and "Ubuntu: 沿用" in r2.stdout and "Debian: 下載" in r2.stdout, r2.stdout + r2.stderr
        assert (tmp_path / "r2" / "Ubuntu" / "all.zip").read_bytes() == (tmp_path / "r1" / "Ubuntu" / "all.zip").read_bytes()
        # 上一份被改過（sha256 與它的 SOURCE 不符）：不沿用
        with open(tmp_path / "r2" / "Ubuntu" / "all.zip", "ab") as f:
            f.write(b"x")
        r3 = run_mirror(tmp_path / "r3", tmp_path / "r3.man", env={"OSV_DISTRO_BASE_URL": url, "OSV_DISTRO_REUSE_FROM": str(tmp_path / "r2")})
        assert r3.returncode == 0 and "Ubuntu: 下載" in r3.stdout
    finally:
        srv.shutdown()


# ---------- 部署：常駐環境的更新與 GitLab runner 的複本 ----------

# ---------- 接線 ----------

def test_sca_scan_wiring():
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    i = s.index('distro_recheck.py" --findings')
    assert s.index('dtread.py" findings "$DT_UUID"') < i < s.index("# ---------- E. ScanCode.io")      # D-dt-findings 之後
    assert s.index("GR=$OUT/scan/grype.json") < i                                                     # Grype 的結果已經寫好
    assert s.rindex('rm -f "$DRC" "$DRC.xz"', 0, i) > s.index('dtread.py" findings "$DT_UUID"')       # 先刪掉上一次的結果（含 .xz）
    assert 'da+=(--mirror "$OSV_DISTRO_MIRROR")' in s and 'NOT_RUN) rm -f "$DRC";;' in s and "D-distro-recheck NOT_RUN" not in s
    assert "timeout 900 python3 -I" in s and 'status D-distro-recheck FAIL "distro_recheck.py 失敗' in s
    case = next(l for l in s.splitlines() if l.strip().startswith("case $k in DT_URL|"))
    assert "|OSV_DISTRO_MIRROR|" in case and 'secret "$OSV_DISTRO_MIRROR"' not in s


# ---------- sudo 重設 PATH ----------

FAKE_TOOL = """#!/bin/sh
case "$1" in version) echo "Version: $FAKE_VER";; *) exit 9;; esac
"""


def test_sca_scan_path_fallback(tmp_path):
    tools = tmp_path / "tools"
    (tools / "bin").mkdir(parents=True)
    for t, v in (("grype", "0.121.0"), ("syft", "1.55.0")):
        (tools / "bin" / t).write_text(FAKE_TOOL.replace("$FAKE_VER", v))
        (tools / "bin" / t).chmod(0o755)
    sb = tmp_path / "s.cdx.json"
    sb.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}))
    base = "/usr/bin:/bin"                    # sudo 的 secure_path 一樣沒有工具資料夾
    env = {"PATH": base, "HOME": str(tmp_path / "home"), "PILOT_ENV": str(tmp_path / "none.env"), "SCA_TOOLS_DIR": str(tools)}
    out = tmp_path / "out"
    subprocess.run(["bash", str(PILOT / "sca-scan"), "--sbom", str(sb), "--out", str(out), "--no-upload", "--no-license"],
                   env=env, capture_output=True, timeout=300)
    st = {l.split("\t")[0]: l.split("\t") for l in (out / "status.tsv").read_text(encoding="utf-8").splitlines()[1:]}
    detail = st["A-tools"][2]
    assert "已把" in detail and str(tools / "bin") in detail and "找不到：grype" not in detail and "grype 0.121.0" in detail
    # 資料夾不存在：不改 PATH，照常回報找不到
    out2 = tmp_path / "out2"
    subprocess.run(["bash", str(PILOT / "sca-scan"), "--sbom", str(sb), "--out", str(out2), "--no-upload", "--no-license"],
                   env={**env, "SCA_TOOLS_DIR": str(tmp_path / "nope")}, capture_output=True, timeout=300)
    d2 = next(l for l in (out2 / "status.tsv").read_text(encoding="utf-8").splitlines() if l.startswith("A-tools\t"))
    assert "找不到：grype" in d2 and "已把" not in d2
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    assert "tools_dir_ok" in s and "(8#${m##* } & 8#022) == 0" in s and '[ "${m%% *}" = 0 ]' in s   # root 只收 root 擁有、不可寫的資料夾
    assert 'r=$(readlink -f -- "$1")' in s and 'p=$(dirname -- "$p")' in s                          # 上層與連結指向的上層也要檢查


def test_tools_dir_ok_walks_parents(tmp_path):
    """把 tools_dir_ok 拿出來、假裝是 root：每一層上層資料夾（含連結指向的路徑）都要 root 擁有、群組與其他人不可寫。"""
    s = (PILOT / "sca-scan").read_text(encoding="utf-8")
    fn = s[s.index("tools_dir_ok(){"):s.index("\nif { ! command -v grype")]
    def ok(path, fake_stat):
        sh = f"id(){{ echo 0; }}\nstat(){{ {fake_stat}; }}\n{fn}\ntools_dir_ok {path} && echo yes || echo no"
        return subprocess.run(["bash", "-c", sh], capture_output=True, text=True, timeout=30).stdout.strip()
    (tmp_path / "opt" / "t" / "bin").mkdir(parents=True)
    p = tmp_path / "opt" / "t" / "bin"
    assert ok(p, 'echo "0 755"') == "yes"
    assert ok(p, f'case "${{@: -1}}" in {tmp_path}/opt) echo "1000 755";; *) echo "0 755";; esac') == "no"     # 上層是別人的
    assert ok(p, f'case "${{@: -1}}" in {tmp_path}) echo "0 777";; *) echo "0 755";; esac') == "no"            # 上層所有人可寫
    os.symlink(p, tmp_path / "link")
    assert ok(tmp_path / "link", f'case "${{@: -1}}" in {tmp_path}/opt/t) echo "0 775";; *) echo "0 755";; esac') == "no"   # 連結指向的上層


# ---------- R1：安裝的不是發行版建置的（廠商後綴）→ 不判為已修補 ----------

@pytest.mark.parametrize("ver,vendor", [
    ("2.4.114-1+rk1", True), ("2.4.114-1+rockchip2", True), ("2.4.114-1~ppa1", True), ("1.2-3l4t1", True), ("1.2-3+l4t-35", True),
    ("2.0-0nvidia1", True), ("1.0+rk1-1", True), ("1:2.4.114-1+rk1", True), ("2.4.114-1ubuntu1+custom1", True),
    ("6.8.12-tegra-39.2.1-20260101000000", True), ("6.1-rockchip", True), ("2.4.114-1local2", True),
    # L-1：實際的發行版版本（上游版本有 +tests、+samba、+gitXXX、~r495、prealpha），不是廠商重建
    ("2.7.0+tests-0ubuntu3", False), ("2:2.8.0+samba4.19.5+dfsg-4ubuntu9.8", False), ("2:0.1~r495-2build1", False), ("2:0.1~r495-2", False),
    ("0.8+5prealpha+1-17build2", False), ("2:0.164.3095+gitbaee400-3", False),
    ("2.4.114-1+deb12u1.1", False),      # 沒有任何標記的第三方重建偵測不到（啟發式的限制）
    ("2.4.114-1+deb12u1", False), ("2.4.114-1+deb12u1+b1", False), ("3.0.13-0ubuntu3.11", False), ("3.0.13-0ubuntu0.24.04.1~esm1", False),
    ("1:1.2.11.dfsg-2ubuntu9.2", False), ("7.88.1-10+deb12u5", False), ("1.0~rc1-1", False), ("2.0+ds-1", False),
    ("20230311+git20230311-1", False), ("2.39-0ubuntu8", False), ("1.4.4-3~bpo12+1", False), ("5.15+really5.14-2", False),
])
def test_is_vendor_build(ver, vendor):
    assert dr.is_vendor_build(ver) is vendor


def test_decide_vendor_build_is_not_distro_fixed():
    rec = {"record": "DEBIAN-CVE-2026-1", "kind": "per_cve", "modified": None, "published": None, "upstream": ["CVE-2026-1"], "cve": "CVE-2026-1"}
    ent = [(rec, aff("libdrm", "Debian:12", "2.4.114-1+deb12u1"))]
    # 2.4.114-1+rk1 比 2.4.114-1+deb12u1 大，但不是 Debian 建置的：照常保留（不是已修補）
    dec, ev, why = dr.decide(ent, "2.4.114-1+rk1")
    assert dec == "distro_not_listed" and "不是發行版建置" in why and ev[0]["fixed_version"] == "2.4.114-1+deb12u1"
    # 發行版自己的版本：已修補
    assert dr.decide(ent, "2.4.114-1+deb12u1")[0] == "distro_fixed"
    assert dr.decide(ent, "2.4.114-1+deb12u2")[0] == "distro_fixed"
    # 廠商重建但比修補版本舊：照樣 distro_affected（廠商後綴不讓已知受影響的版本變安全）
    assert dr.decide(ent, "2.4.113-1+rk1")[0] == "distro_affected"
