"""tools/pilot/lib/usn_cves.py（sca-scan 的 D-usn-cves）：沒有 CVE 別名的 USN → Ubuntu OSV 鏡像列的 CVE。"""
import json
import subprocess
import sys
from pathlib import Path

PILOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PILOT / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import usn_cves as uc  # noqa: E402
from test_distro_recheck import UBUNTU, aff, finding, make_mirror, now, rec  # noqa: E402

LIB = PILOT / "lib" / "usn_cves.py"
SRC = "pkg:deb/ubuntu/brotli@1.1.0-2build2?arch=source&distro=ubuntu-24.04"
USNS = [
    rec("USN-8956-1", [aff("brotli", "Ubuntu:24.04:LTS", "1.1.0-2ubuntu0.1"), aff("brotli", "Ubuntu:22.04:LTS", "1.0.9-2ubuntu0.1"),
                       aff("brotli", "Ubuntu:Pro:20.04:LTS", "1.0.7-6ubuntu0.1+esm1"),          # Pro（ESM）不收
                       aff("brotli", "Ubuntu:24.04:LTS"),                                        # 沒有 fixed 的範圍不收
                       aff("Bad Name", "Ubuntu:24.04:LTS", "1")], ["CVE-2026-111497"],
        aliases=["UBUNTU-CVE-2026-111498"], related=["CVE-2026-777777"]),       # related 不算
    rec("USN-8957-1", [aff("curl", "Ubuntu:24.04:LTS", "1")], ["CVE-2026-10001"], withdrawn="2026-10-01T00:00:00Z"),
    rec("USN-8958-1", [aff("curl", "Ubuntu:24.04:LTS", "1")], [], related=["CVE-2026-20002"]),
]
FINDINGS = [
    finding("brotli", "1.1.0-2build2", "USN-8956-1", "OSV", purl=SRC),
    finding("brotli", "1.1.0-2build2", "USN-8957-1", "OSV", purl=SRC),
    finding("brotli", "1.1.0-2build2", "USN-8958-1", "OSV", purl=SRC),
    finding("brotli", "1.1.0-2build2", "USN-8959-1", "OSV", purl=SRC),                     # 鏡像沒有
    finding("brotli", "1.1.0-2build2", "USN-8000-1", "OSV", purl=SRC, aliases=[{"cveId": "CVE-2026-50001"}]),   # 已有 CVE：不查
    finding("brotli", "1.1.0-2build2", "UBUNTU-CVE-2026-111497", "OSV", purl=SRC),
]


def test_usn_cves_from_mirror(tmp_path):
    m = make_mirror(tmp_path / "m", ubuntu=UBUNTU + USNS)
    st, detail, out = uc.usn_cves(FINDINGS, str(m), 3)
    assert st == "OK" and out["status"] == "OK" and out["schema"] == "sca-center-usn-cves/1"
    assert out["usns"] == {"USN-8956-1": {"cves": ["CVE-2026-111497", "CVE-2026-111498"], "modified": "2026-04-22T15:27:29Z"}}
    assert out["withdrawn"] == ["USN-8957-1"] and out["no_cve"] == ["USN-8958-1"] and out["not_found"] == ["USN-8959-1"]
    assert out["counts"] == {"usns": 4, "mapped": 1, "not_found": 1, "withdrawn": 1, "no_cve": 1, "with_fixed": 2}
    # 修補版本（cra_report 推自成一列的 USN 的修補狀態用）：一般 Ubuntu 版本的原始碼套件；沒有 CVE 的 USN 也記，撤回的不記
    assert out["fixed"] == {"USN-8956-1": [{"ecosystem": "Ubuntu:22.04:LTS", "package": "brotli", "fixed": ["1.0.9-2ubuntu0.1"]},
                                           {"ecosystem": "Ubuntu:24.04:LTS", "package": "brotli", "fixed": ["1.1.0-2ubuntu0.1"]}],
                            "USN-8958-1": [{"ecosystem": "Ubuntu:24.04:LTS", "package": "curl", "fixed": ["1"]}]}
    assert out["mirror"]["ok"] and out["mirror"]["ecosystems"]["Ubuntu"]["sha256"]          # 鏡像的來源資料
    assert "對到 CVE 1" in detail


def test_usn_cves_without_mirror_or_usns(tmp_path):
    assert uc.usn_cves(FINDINGS[5:], None, 3) == ("NOT_RUN", "沒有不帶 CVE 別名的 USN", None)
    st, detail, out = uc.usn_cves(FINDINGS, None, 3)
    assert st == "NOT_RUN" and out["status"] == "NOT_RUN" and out["usns"] == {} and "沒有設定鏡像" in detail
    m = make_mirror(tmp_path / "m", ubuntu=UBUNTU + USNS, fetched=now(10))                  # 過期 → 不用
    st, detail, out = uc.usn_cves(FINDINGS, str(m), 3)
    assert st == "NOT_RUN" and out["usns"] == {} and "過期" in detail
    # CLI：python3 -I，印一行 status，寫檔案
    f, o = tmp_path / "findings.json", tmp_path / "usn-cves.json"
    f.write_text(json.dumps(FINDINGS), encoding="utf-8")
    m2 = make_mirror(tmp_path / "m2", ubuntu=UBUNTU + USNS)
    r = subprocess.run([sys.executable, "-I", str(LIB), "--findings", str(f), "--mirror", str(m2), "--out", str(o)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.startswith("D-usn-cves\tOK\t"), r.stdout + r.stderr
    assert json.loads(o.read_text(encoding="utf-8"))["usns"]["USN-8956-1"]["cves"][0] == "CVE-2026-111497"
    f.write_text("{bad", encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(LIB), "--findings", str(f), "--out", str(o)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 3 and r.stdout.startswith("D-usn-cves\tFAIL\t") and "Traceback" not in r.stderr
