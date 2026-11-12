"""測試用的小型假資料：模擬 sca-scan 的輸出資料夾（欄位格式取自真實輸出：Grype 0.121.0 JSON、DT 5.2.0 finding、sbomgate、djread）。"""
import importlib.util
import json
from pathlib import Path

PILOT = Path(__file__).resolve().parents[1]
ROOT = PILOT.parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


report = load_module("pilot_report", PILOT / "report.py")


def gmatch(vid, name, version, purl, typ, severity="High", related=(), fix=(), kev=False, epss=None, pct=None):
    v = {"id": vid, "severity": severity, "namespace": "test", "fix": {"versions": list(fix), "state": "fixed" if fix else "not-fixed"}}
    if kev:
        v["knownExploited"] = [{"cve": vid, "knownRansomwareCampaignUse": "Unknown"}]
    if epss is not None:
        v["epss"] = [{"cve": vid, "epss": epss, "percentile": pct, "date": "2026-10-22"}]
    return {"vulnerability": v, "relatedVulnerabilities": [{"id": r} for r in related],
            "artifact": {"name": name, "version": version, "type": typ, "purl": purl}}


def dfind(vid, name, version, purl, severity="HIGH", aliases=(), source="NVD", kev=False, epss=None, pct=None, suppressed=False):
    v = {"vulnId": vid, "source": source, "severity": severity, "isKev": kev, "aliases": [dict(a) for a in aliases]}
    if epss is not None:
        v["epssScore"], v["epssPercentile"] = epss, pct
    return {"component": {"name": name, "version": version, "purl": purl}, "vulnerability": v, "analysis": {"isSuppressed": suppressed}}


def make_out(tmp, stages, grype=None, findings=None, gate=None, comp=None, meta=None, sbom=None, govuln=None):
    """建一個 sca-scan 輸出資料夾。stages：[(stage, status, detail)]。"""
    out = Path(tmp)
    for d in ("sbom", "scan", "dt", "dejacode"):
        (out / d).mkdir(parents=True, exist_ok=True)
    (out / "status.tsv").write_text("stage\tstatus\tdetail\n" + "".join(f"{a}\t{b}\t{c}\n" for a, b, c in stages), encoding="utf-8")
    m = {"name": "demo", "mode": "dir", "source": "/src/demo", "version": "dir-sha256:abc", "started": "2026-10-23T00:00:00Z",
         "finished": "2026-10-23T00:01:00Z", "tools": {"grype": "0.121.0"}, "network": {"sbom_resolution_online": False, "data_sources_online": True}}
    m.update(meta or {})
    (out / "meta.json").write_text(json.dumps(m), encoding="utf-8")
    if grype is not None:
        (out / "scan" / "grype.json").write_text(json.dumps({"matches": grype}), encoding="utf-8")
    if findings is not None:
        (out / "dt" / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    if gate is not None:
        (out / "scan" / "sbomgate.json").write_text(json.dumps(gate), encoding="utf-8")
    if comp is not None:
        (out / "dejacode" / "compliance.json").write_text(json.dumps(comp), encoding="utf-8")
    if sbom is not None:
        (out / "sbom" / "sbom.cdx.json").write_text(json.dumps(sbom), encoding="utf-8")
    if govuln is not None:
        (out / "scan" / "govulncheck.json").write_text("\n".join(json.dumps(o) for o in govuln), encoding="utf-8")
    return out


def run_report(out):
    assert report.main(["--out", str(out)]) == 0
    return json.loads((out / "report.json").read_text(encoding="utf-8")), (out / "report.html").read_text(encoding="utf-8")


ALL_OK = [("A-source", "OK", ""), ("B-sbom-cdxgen", "OK", "3 components"), ("C-grype", "OK", ""), ("C-sbomgate", "OK", "COMPLETE"),
          ("D-dt-data-sources", "OK", "NVD COMPLETED；OSV COMPLETED"), ("D-dt-findings", "OK", ""), ("E-dejacode-licenses", "OK", "")]
FORBIDDEN = report.FORBIDDEN_WORDS


def visible_text(page):
    import html as _h
    import re as _re
    return _h.unescape(_re.sub(r"<[^>]+>", " ", _re.sub(r"<style>.*?</style>", " ", page, flags=_re.S)))


def assert_no_conclusion(page):
    """頁面上不可有肯定句的結論字樣（否定句型「不代表…」「不可當作…」的工具原文放行）。"""
    hits = report.conclusion_hits(visible_text(page))
    assert not hits, hits
