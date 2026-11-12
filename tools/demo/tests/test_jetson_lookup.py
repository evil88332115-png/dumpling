import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import jetson_lookup as jl  # noqa: E402

KEY = "test-key-not-a-secret"


def write(d, rel, obj):
    p = os.path.join(d, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def scan_dir(tmp, name, version, comps, matches, findings):
    d = str(tmp / name)
    write(d, "sbom/sbom.cdx.json", {"bomFormat": "CycloneDX", "components": [
        {"type": "library", "name": n, "version": v, "purl": p} for n, v, p in comps] + [{"type": "file", "name": "/etc/x"}]})
    write(d, "scan/grype.json", {"matches": [{"vulnerability": {"id": i}, "artifact": {"type": t, "name": n, "version": v}}
                                             for i, t, n, v in matches]})
    write(d, "meta.json", {"name": f"jetson-r39.2.1-{name}", "version": version, "dt_project_uuid": f"u-{name}"})
    write(d, "dt/findings.json", findings)
    with open(os.path.join(d, "status.tsv"), "w", encoding="utf-8") as f:
        f.write("stage\tstatus\tdetail\nD-dt-upload\tOK\tx\nD-dt-findings\tOK\tx\n")
    return d


DEB = ("nvidia-l4t-core", "39.2.1-1", "pkg:deb/ubuntu/nvidia-l4t-core@39.2.1-1?arch=arm64")
LIBC = ("libc6", "2.39-0ubuntu8", "pkg:deb/ubuntu/libc6@2.39-0ubuntu8?arch=arm64")
PIL = ("Pillow", "10.0.0", "pkg:pypi/pillow@10.0.0")
F_LIBC = {"component": {"name": "libc6", "purl": LIBC[2]}, "vulnerability": {"source": "NVD", "vulnId": "CVE-2025-0001", "cvssV3BaseScore": 7.5}}
F_LIBC_LOW = {"component": {"name": "libc6", "purl": LIBC[2]}, "vulnerability": {"source": "NVD", "vulnId": "CVE-2025-0002", "cvssV3BaseScore": 3.1}}
F_PIL = {"component": {"name": "Pillow", "purl": PIL[2]}, "vulnerability": {"source": "GITHUB", "vulnId": "GHSA-3f63-hfp8-52jq", "cvssV3BaseScore": 9.8}}
P_BASE = {"name": "jetson-r39.2.1-base", "version": "sha256:b"}
P_CUST = {"name": "jetson-r39.2.1-custom", "version": "sha256:c"}


@pytest.fixture
def dirs(tmp_path):
    b = scan_dir(tmp_path, "base", "sha256:b", [DEB, LIBC], [("CVE-2025-0001", "deb", "libc6", LIBC[1])], [F_LIBC, F_LIBC_LOW])
    c = scan_dir(tmp_path, "custom", "sha256:c", [DEB, LIBC, PIL],
                 [("CVE-2025-0001", "deb", "libc6", LIBC[1]), ("GHSA-3f63-hfp8-52jq", "python", "Pillow", "10.0.0")],
                 [F_LIBC, F_LIBC_LOW, F_PIL])
    return b, c


@pytest.fixture
def dt(tmp_path):
    seen = []
    routes = {
        "/api/v1/component/identity?name=nvidia-l4t-core": [
            {"name": "nvidia-l4t-core", "classifier": "LIBRARY", "version": "39.2.1-1", "project": P_BASE},
            {"name": "/usr/share/doc/nvidia-l4t-core/copyright", "classifier": "FILE", "project": P_BASE},
            {"name": "/usr/share/doc/nvidia-l4t-core/copyright", "classifier": "FILE", "project": {"name": "other", "version": "1"}},
            {"name": "nvidia-l4t-core", "classifier": "LIBRARY", "version": "39.2.1-1", "project": P_CUST}],
        "/api/v1/vulnerability/source/GITHUB/vuln/GHSA-3f63-hfp8-52jq/projects": [P_CUST],
        "/api/v1/vulnerability/source/NVD/vuln/CVE-2025-0001/projects": [P_BASE, P_CUST, {"name": "other", "version": "1"}],
    }

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("X-Api-Key")))
            body = routes.get(self.path)
            self.send_response(200 if body is not None else 404)
            self.end_headers()
            self.wfile.write(json.dumps(body).encode() if body is not None else b"")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env = tmp_path / "pilot.env"
    env.write_text(f'DT_URL="http://127.0.0.1:{srv.server_port}/api"\nDT_API_KEY={KEY}\nOTHER=x\n', encoding="utf-8")
    yield str(env), seen, routes
    srv.shutdown()


def run(dirs, out, env=""):
    b, c = dirs
    args = ["--scan", f"base={b}", "--scan", f"custom={c}", "--out", str(out)]
    if env:
        args += ["--pilot-env", env]
    jl.main(args)
    d = json.loads((out / "lookup.json").read_text(encoding="utf-8"))
    return {s: (k, t) for s, k, t in d["stages"]}, d, (out / "summary.md").read_text(encoding="utf-8")


def test_all_ok(dirs, dt, tmp_path, capsys):
    env, seen, _ = dt
    st, d, md = run(dirs, tmp_path / "o", env)
    assert {k: v[0] for k, v in st.items()} == {"G-diff": "OK", "G-lookup-component": "OK", "G-lookup-vuln-custom": "OK",
                                                "G-lookup-vuln-shared": "OK"}
    assert d["diff"]["components_added"] == [["pypi", "Pillow", "10.0.0"]]
    assert list(d["diff"]["grype_only_custom"]) == ["GHSA-3f63-hfp8-52jq"]
    assert d["lookup_vuln_shared"]["vuln"] == "CVE-2025-0001"        # CVSS 最高的 deb finding
    assert len(d["lookup_component"]["packages"]) == 2 and "另有 2 筆" in st["G-lookup-component"][1]
    assert all(k == KEY for _, k in seen)
    out = capsys.readouterr().out
    assert KEY not in out and KEY not in md and KEY not in json.dumps(d)
    assert "| SBOM 元件 | 2 | 3 |" in md and "pypi Pillow 10.0.0" in md


def test_no_dt(dirs, tmp_path):
    st, _, _ = run(dirs, tmp_path / "o")
    assert st["G-diff"][0] == "OK" and all(st[s][0] == "NOT_RUN" for s in ("G-lookup-component", "G-lookup-vuln-custom", "G-lookup-vuln-shared"))


def test_component_lookup_ignores_files(dirs, dt, tmp_path):
    env, _, routes = dt
    routes["/api/v1/component/identity?name=nvidia-l4t-core"] = [
        {"name": "nvidia-l4t-core", "classifier": "LIBRARY", "version": "39.2.1-1", "project": P_BASE},
        {"name": "/usr/share/doc/nvidia-l4t-core/copyright", "classifier": "FILE", "project": P_CUST}]
    st, _, _ = run(dirs, tmp_path / "o", env)
    assert st["G-lookup-component"][0] == "ATTENTION"     # 客製版只有檔案、沒有套件：不能算找到


def test_dt_missing_deb_findings_and_wrong_projects(dirs, dt, tmp_path):
    env, _, routes = dt
    b, c = dirs
    write(b, "dt/findings.json", [])
    routes["/api/v1/vulnerability/source/GITHUB/vuln/GHSA-3f63-hfp8-52jq/projects"] = [P_BASE, P_CUST]
    del routes["/api/v1/component/identity?name=nvidia-l4t-core"]
    st, _, _ = run(dirs, tmp_path / "o", env)
    assert st["G-lookup-vuln-shared"][0] == "GAP" and "Grype 有 1 個" in st["G-lookup-vuln-shared"][1]
    assert st["G-lookup-vuln-custom"][0] == "ATTENTION"
    assert st["G-lookup-component"][0] == "FAIL"


def test_dt_not_uploaded(dirs, dt, tmp_path):
    env, seen, _ = dt
    _, c = dirs
    with open(os.path.join(c, "status.tsv"), "w", encoding="utf-8") as f:
        f.write("stage\tstatus\tdetail\nD-dt-upload\tNOT_RUN\t--no-upload\nD-dt-findings\tNOT_RUN\t--no-upload\n")
    st, _, _ = run(dirs, tmp_path / "o", env)
    for s in ("G-lookup-component", "G-lookup-vuln-custom", "G-lookup-vuln-shared"):
        assert st[s][0] == "NOT_RUN" and "custom 的 D-dt-findings=NOT_RUN" in st[s][1]
    assert seen == []                                          # 沒有去查 DT


def test_empty_sbom_fails(dirs, tmp_path):
    b, _ = dirs
    write(b, "sbom/sbom.cdx.json", {"bomFormat": "CycloneDX", "components": []})
    st, _, _ = run(dirs, tmp_path / "o")
    assert st["G-diff"][0] == "FAIL"
