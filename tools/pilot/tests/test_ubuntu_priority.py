"""tools/pilot/lib/ubuntu_priority.py（sca-scan 的 D-ubuntu-priority）：Ubuntu 套件上的 CVE → Ubuntu OSV 紀錄裡的 Ubuntu priority。"""
import json
import subprocess
import sys
from pathlib import Path

PILOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PILOT / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ubuntu_priority as up  # noqa: E402
from test_distro_recheck import aff, finding, make_mirror, now, rec  # noqa: E402

LIB = PILOT / "lib" / "ubuntu_priority.py"
DEBP = "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.11?arch=arm64&distro=ubuntu-24.04"
KERN = "pkg:deb/ubuntu/linux-nvidia-tegra@6.8.0-1021.21?arch=source&distro=ubuntu-24.04"


def sev(*xs):
    return [{"type": t, "score": s} for t, s in xs]


V3 = ("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
RECS = [
    rec("UBUNTU-CVE-2026-1001", [aff("openssl", "Ubuntu:24.04:LTS")], ["CVE-2026-1001"], severity=sev(V3, ("Ubuntu", "medium"))),
    rec("UBUNTU-CVE-2026-1002", [aff("openssl", "Ubuntu:24.04:LTS")], ["CVE-2026-1002"], severity=sev(V3, ("Ubuntu", "untriaged"))),
    rec("UBUNTU-CVE-2026-1003", [aff("openssl", "Ubuntu:24.04:LTS")], ["CVE-2026-1003"], severity=sev(V3)),            # 沒有 Ubuntu priority
    rec("UBUNTU-CVE-2026-1004", [aff("openssl", "Ubuntu:24.04:LTS")], ["CVE-2026-1004"], severity=sev(("Ubuntu", "negligible")),
        withdrawn="2026-10-01T00:00:00Z"),
    rec("UBUNTU-CVE-2026-2001", [aff("linux-nvidia-tegra", "Ubuntu:24.04:LTS")], ["CVE-2026-2001"], severity=sev(("Ubuntu", "High"))),
    rec("UBUNTU-CVE-2026-3001", [aff("brotli", "Ubuntu:24.04:LTS")], ["CVE-2026-3001"], severity=sev(("Ubuntu", "critical"))),
]
FINDINGS = [
    finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2026-1001", "NVD", purl=DEBP),
    finding("openssl", "3.0.13-0ubuntu3.11", "UBUNTU-CVE-2026-1002", "OSV", purl=DEBP),
    finding("openssl", "3.0.13-0ubuntu3.11", "GHSA-xxxx-yyyy-zzzz", "GITHUB", purl=DEBP, aliases=[{"cveId": "CVE-2026-1003"}]),
    finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2026-1004", "NVD", purl=DEBP),
    finding("openssl", "3.0.13-0ubuntu3.11", "CVE-2026-1005", "NVD", purl=DEBP),                    # 鏡像沒有
    finding("linux-nvidia-tegra", "6.8.0-1021.21", "UBUNTU-CVE-2026-2001", "OSV", purl=KERN),        # Canonical 核心
    finding("brotli", "1.1.0", "CVE-2026-3001", "NVD", purl="pkg:pypi/brotli@1.1.0"),               # 不是 Ubuntu 套件：不查
]


def test_priorities_from_mirror(tmp_path):
    m = make_mirror(tmp_path / "m", ubuntu=RECS)
    st, detail, out = up.ubuntu_priority(FINDINGS, str(m), 3)
    assert st == "OK" and out["status"] == "OK" and out["schema"] == "sca-center-ubuntu-priority/1"
    assert out["cves"] == {"CVE-2026-1001": {"priority": "medium", "record": "UBUNTU-CVE-2026-1001", "modified": "2026-04-22T15:27:29Z"},
                           "CVE-2026-2001": {"priority": "high", "record": "UBUNTU-CVE-2026-2001", "modified": "2026-04-22T15:27:29Z"}}
    assert out["untriaged"] == ["CVE-2026-1002", "CVE-2026-1003"] and out["withdrawn"] == ["CVE-2026-1004"]
    assert out["not_found"] == ["CVE-2026-1005"] and "CVE-2026-3001" not in json.dumps(out)
    assert out["counts"]["cves"] == 6 and out["counts"]["by_priority"]["medium"] == 1 and out["mirror"]["ok"]
    assert "有 Ubuntu priority 2" in detail


def test_without_mirror_or_ubuntu_findings(tmp_path):
    assert up.ubuntu_priority(FINDINGS[6:], None, 3) == ("NOT_RUN", "DT findings 沒有 Ubuntu 套件上的 CVE", None)
    st, detail, out = up.ubuntu_priority(FINDINGS, None, 3)
    assert st == "NOT_RUN" and out["status"] == "NOT_RUN" and out["cves"] == {} and "沒有設定鏡像" in detail
    m = make_mirror(tmp_path / "m", ubuntu=RECS, fetched=now(10))
    st, detail, out = up.ubuntu_priority(FINDINGS, str(m), 3)
    assert st == "NOT_RUN" and "過期" in detail
    f, o = tmp_path / "findings.json", tmp_path / "ubuntu-priority.json"
    f.write_text(json.dumps(FINDINGS), encoding="utf-8")
    m2 = make_mirror(tmp_path / "m2", ubuntu=RECS)
    r = subprocess.run([sys.executable, "-I", str(LIB), "--findings", str(f), "--mirror", str(m2), "--out", str(o)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.startswith("D-ubuntu-priority\tOK\t"), r.stdout + r.stderr
    assert json.loads(o.read_text(encoding="utf-8"))["cves"]["CVE-2026-1001"]["priority"] == "medium"
    f.write_text("{bad", encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(LIB), "--findings", str(f), "--out", str(o)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 3 and r.stdout.startswith("D-ubuntu-priority\tFAIL\t") and "Traceback" not in r.stderr
