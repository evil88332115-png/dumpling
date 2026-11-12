"""evidence_bundle.py：凍結證據包（白名單、不收刷機包與 rootfs、秘密 → FAIL、決定性的 tar、verify 抓出改過／缺少／多出的檔案）。"""
import contextlib
import errno
import io
import json
import lzma
import os
import subprocess
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import evidence_bundle as eb  # noqa: E402
from test_cra_report import META, MIN_CFG, make_project, make_scan, write_json  # noqa: E402

CLI = HERE.parent / "evidence_bundle.py"
MD5 = "0123456789abcdef0123456789abcdef"
SECRET = "odt_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE12"   # 合成的值，只在測試裡


def ustar(name="etc/passwd", data=b"root:x:0:0\n"):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.USTAR_FORMAT) as t:
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    return b.getvalue()


def make_reports(proj, status="OK", vex=True):
    r = proj / "CRA" / "Reports"
    r.mkdir(parents=True, exist_ok=True)
    docs = {"risk-assessment": {"status": status}, "sbom": {"status": "OK"}}
    write_json(r / "summary.json", {"tool": "cra_report", "status": status, "documents": docs, "vex": {"gate": {"verdict": "NOT_READY"}}})
    (r / "risk-assessment.md").write_text("# Risk assessment\n", encoding="utf-8")
    write_json(r / "sbom.cdx.json", {"bomFormat": "CycloneDX"})
    (r / "scan-status.tsv").write_text("stage\tstatus\tdetail\n", encoding="utf-8")
    if vex:
        write_json(r / "vex.cdx.json", {"bomFormat": "CycloneDX", "vulnerabilities": []})
        write_json(r / "vex.openvex.json", {"statements": []})


def make_target(res, v="rootfs_no_gui", status="OK", vex=True):
    d = res / v
    meta = dict(META, version=f"V1.0 ({v})", tools={"grype": "0.121.0", "syft": "1.55.0", "bwrap": "0.9.0"},
                grype_db_built="2026-11-02T04:00:00Z", grype_db_schema="v6.0.2")
    make_scan(d / "scan", meta=meta)
    write_json(d / "scan" / "dt" / "data-sources.json", {"sources": [{"label": "NVD", "status": "COMPLETED", "completed_at": "2026-11-02T01:00:00Z"}],
                                                         "nvd_mirror": {"mode": "1", "modified": "2026-11-01T23:00:00Z"}, "vuln_status": "OK"})
    write_json(d / "scan" / "scan" / "kernel-config.json", {"cve_data": {"source": "kernel.org vulns.git", "commit_or_date": "abc123 (2026-11-01)",
                                                                         "fetched_utc": "2026-11-02T00:00:00Z"}})
    write_json(d / "scan" / "scan" / "kernel-module-map.json", {"schema": "sca-center-kernel-module-map/1", "status": "OK", "cves": {}})
    (d / "scan" / "commands.tsv").write_text("cmd\tsyft scan\n", encoding="utf-8")
    (d / "scan" / "sbom" / "syft.stderr.txt").write_text("log\n", encoding="utf-8")
    (d / "logs").mkdir(parents=True)
    (d / "logs" / "pkgdb.err").write_text("log\n", encoding="utf-8")
    (d / "rootfs.tar").write_bytes(ustar())                    # 暫存的 rootfs tar：不能收
    (d / "pkgdb").mkdir()
    (d / "pkgdb" / "dpkg-status").write_text("Package: openssl\nVersion: 3.0\n", encoding="utf-8")
    write_json(d / "pkgdb" / "pkgdb.json", {"source": "rootfs.tar"})
    (d / "package-dependencies.md").write_text("# deps\n", encoding="utf-8")
    write_json(d / "rootfs-tar.json", {"written": 1})
    cfg = dict(MIN_CFG, product={"name": "EX-J100", "version": f"V1.0 ({v})"})
    p = make_project(d / "cra-project", cfg=cfg)
    write_json(p / "CRA" / "Config" / "vex-rules.json", {"rules": []})
    make_reports(p, status, vex)
    return d


SHA = "ab" * 32
COMMIT = "c0ffee" + "0" * 34


def make_flash(tmp, md5_status="OK", provenance=True, **kw):
    res = tmp / "res"
    res.mkdir(parents=True)
    (res / "status.tsv").write_text(f"stage\tstatus\tdetail\nA-md5\t{md5_status}\tmd5 {MD5}：相符\nB-list\tOK\t1 個 rootfs\n", encoding="utf-8")
    write_json(res / "list.json", {"source": {"type": "archive", "file": "EX_V1.0.tbz2", "bytes": 4242},
                                   "archive": {"file": "EX_V1.0.tbz2", "bytes": 4242}})
    write_json(res / "flash-inventory.json", {"bootloader": []})
    write_json(res / "summary.json", {"variants": ["rootfs_no_gui"]})
    (res / "summary.md").write_text("# 摘要\n", encoding="utf-8")
    (res / "EX_V1.0.tbz2").write_bytes(b"BZh91AY&SY" + b"\0" * 64)    # 刷機包本身：不能收
    (res / "pid").write_text("123\n")
    if provenance:
        write_json(res / "provenance.json", {"schema": "sca-center-flash-provenance/1", "generated_utc": "2026-11-02T05:00:00Z",
                                             "sca_center": {"commit": COMMIT, "from": "deploy-dir", "dirty": None},
                                             "source": {"type": "archive", "file": "EX_V1.0.tbz2", "bytes": 4242, "md5": MD5, "sha256": SHA},
                                             "carried_from": None})
    make_target(res, **kw)
    return res


def secrets(tmp, vals=(SECRET,)):
    p = tmp / "secrets.txt"
    p.write_text("".join(v + "\n" for v in vals), encoding="utf-8")
    return p


def create(tmp, res, out="out", **kw):
    if "secrets_file" not in kw:
        kw["secrets_file"] = secrets(tmp)
    return eb.create(res, tmp / out, allow_tmp=True, **kw)


def members(arch):
    with tarfile.open(arch, "r:xz") as t:
        return {m.name.split("/", 1)[1]: t.extractfile(m).read() for m in t}


def bundle_files(out):
    return sorted(p.name for p in out.iterdir())


# ---------- create ----------

def test_create_flash_ok_contents_and_identity(tmp_path):
    res = make_flash(tmp_path)
    st, detail, man = create(tmp_path, res)
    assert st == "OK", detail
    out = tmp_path / "out"
    base = man["bundle"]
    assert base.startswith("evidence-EX-J100-V1.0-") and bundle_files(out) == sorted([f"{base}.tar.xz", f"{base}.manifest.json", f"{base}.tar.xz.sha256"])
    got = members(out / f"{base}.tar.xz")
    for want in ("status.tsv", "list.json", "flash-inventory.json", "summary.md", "rootfs_no_gui/scan/sbom/sbom.cdx.json",
                 "rootfs_no_gui/scan/dt/findings.json", "rootfs_no_gui/scan/scan/grype.json", "rootfs_no_gui/scan/scan/kernel-config.json",
                 "rootfs_no_gui/scan/scan/kernel-module-map.json",
                 "rootfs_no_gui/cra-project/CRA/Config/config.json", "rootfs_no_gui/cra-project/CRA/Config/vex-rules.json",
                 "rootfs_no_gui/cra-project/CRA/Reports/vex.openvex.json", "rootfs_no_gui/cra-project/CRA/Reports/summary.json",
                 "rootfs_no_gui/pkgdb/dpkg-status", "rootfs_no_gui/package-dependencies.md", "manifest.json"):
        assert want in got, want
    # 刷機包、rootfs tar、logs、commands.tsv、stderr、pid 都不收
    assert not [n for n in got if n.endswith((".tbz2", ".tar", ".err", "stderr.txt", "commands.tsv", "pid")) or "/logs/" in n]
    assert got["manifest.json"] == (out / f"{base}.manifest.json").read_bytes()
    assert {f["path"] for f in man["files"]} == set(got) - {"manifest.json"}
    assert man["product"] == {"name": "EX-J100", "version": "V1.0"}
    fp = man["flash_package"]
    assert fp["file"] == "EX_V1.0.tbz2" and fp["bytes"] == 4242 and fp["md5"] == MD5 and fp["included"] is False and fp["sha256"] == SHA
    assert man["sca_center"]["scan_commit"] == COMMIT and man["sca_center"]["from"] == "deploy-dir" and "provenance.json" in got
    assert fp["sha256_source"] == "computed"
    t = man["targets"][0]
    assert t["tools"]["grype"] == "0.121.0" and t["tools"]["dependency_track"] == "5.2.0" and t["tools"]["sbom_generator"] == "syft 1.55.0"
    assert t["data"]["grype_db"] == {"built": "2026-11-02T04:00:00Z", "schema": "v6.0.2"}
    assert t["data"]["nvd_mirror"]["modified"] == "2026-11-01T23:00:00Z" and t["data"]["kernel_cna"]["commit_or_date"].startswith("abc123")
    assert t["data"]["nvidia_bulletins"] == "unknown" and t["cra"]["vex_gate"] == "NOT_READY"
    assert man["status"] == "OK" and man["checks"] == []


def test_create_twice_byte_identical_and_verify_ok(tmp_path):
    res = make_flash(tmp_path)
    _, _, m1 = create(tmp_path, res, out="o1")
    _, _, m2 = create(tmp_path, res, out="o2")
    b = m1["bundle"]
    assert b == m2["bundle"]
    for suf in (".tar.xz", ".manifest.json", ".tar.xz.sha256"):
        assert (tmp_path / "o1" / (b + suf)).read_bytes() == (tmp_path / "o2" / (b + suf)).read_bytes(), suf
    with tarfile.open(tmp_path / "o1" / f"{b}.tar.xz", "r:xz") as t:
        ms = t.getmembers()
    assert [m.name for m in ms] == sorted(m.name for m in ms)
    assert {(m.uid, m.gid, m.mode, m.mtime) for m in ms} == {(0, 0, 0o644, eb.parse_time(m1["frozen_utc"]))}
    st, detail = eb.verify(tmp_path / "o1" / f"{b}.tar.xz")
    assert st == "OK" and "manifest、sha256 也相符" in detail, detail
    # --time 固定凍結時間（也進名稱）
    _, _, m3 = create(tmp_path, res, out="o3", time="2026-11-03T08:00:00Z")
    assert m3["frozen_utc"] == "2026-11-03T08:00:00Z" and m3["bundle"].endswith("-20261103T080000Z")
    assert eb.slug("x" * 200) == "x" * 40 and eb.slug(None) == "unknown" and eb.slug("a b/../c") == "a-b-..-c"


def repack(src, dst, change=None, drop=None, add=None):
    with tarfile.open(src, "r:xz") as t, tarfile.open(dst, "w:xz", format=tarfile.PAX_FORMAT) as o:
        base = None
        for m in t:
            base = m.name.split("/", 1)[0]
            data = t.extractfile(m).read()
            if drop and m.name.endswith(drop):
                continue
            if change and m.name.endswith(change):
                data += b" "
            m.size = len(data)
            o.addfile(m, io.BytesIO(data))
        if add:
            ti = tarfile.TarInfo(f"{base}/{add}")
            ti.size = 1
            o.addfile(ti, io.BytesIO(b"x"))


def test_verify_detects_changed_missing_extra(tmp_path):
    res = make_flash(tmp_path)
    _, _, man = create(tmp_path, res)
    arch = tmp_path / "out" / f"{man['bundle']}.tar.xz"
    cases = {"changed": ({"change": "dt/findings.json"}, "內容不同 1"), "missing": ({"drop": "Reports/vex.cdx.json"}, "缺少 1"),
             "extra": ({"add": "rootfs_no_gui/rootfs.tar"}, "多出 1")}
    for k, (kw, want) in cases.items():
        d = tmp_path / k
        d.mkdir()
        repack(arch, d / "x.tar.xz", **kw)
        st, detail = eb.verify(d / "x.tar.xz")
        assert st == "FAIL" and want in detail, (k, detail)
    # 旁邊的 manifest 被改、或 sha256 不符
    mp = arch.with_name(f"{man['bundle']}.manifest.json")
    mp.write_bytes(mp.read_bytes().replace(b'"OK"', b'"ok"', 1))
    st, detail = eb.verify(arch)
    assert st == "FAIL" and "與包內的 manifest.json 不同" in detail
    d = tmp_path / "sha"
    d.mkdir()
    repack(arch, d / "y.tar.xz")
    (d / "y.tar.xz.sha256").write_text("0" * 64 + "  y.tar.xz\n")
    st, detail = eb.verify(d / "y.tar.xz")
    assert st == "FAIL" and "sha256 不符" in detail
    # 旁邊沒有檔、沒有 --sha256 → ATTENTION；另外保存的 sha256 是可信的錨點
    (d / "y.tar.xz.sha256").unlink()
    st, detail = eb.verify(d / "y.tar.xz")
    assert st == "ATTENTION" and "--sha256" in detail
    assert eb.verify(d / "y.tar.xz", expect_sha256=eb.sha256_file(d / "y.tar.xz"))[0] == "OK"
    st, detail = eb.verify(d / "y.tar.xz", expect_sha256="0" * 64)
    assert st == "FAIL" and "--sha256 不符" in detail
    # 兩個 manifest.json 成員
    repack(arch, d / "z.tar.xz", add="manifest.json")
    st, detail = eb.verify(d / "z.tar.xz")
    assert st == "FAIL" and "manifest.json（重複）" in detail


def test_secret_value_or_pattern_fail_nothing_written(tmp_path):
    res = make_flash(tmp_path)
    f = res / "rootfs_no_gui" / "cra-project" / "CRA" / "Reports" / "risk-assessment.md"
    f.write_text(f"leaked {SECRET[:4]}{SECRET[4:]}\n", encoding="utf-8")
    st, detail, man = create(tmp_path, res, secrets_file=secrets(tmp_path, ["not-in-files", SECRET]))
    assert st == "FAIL" and "risk-assessment.md" in detail and SECRET not in detail and man is None
    assert bundle_files(tmp_path / "out") == []
    assert not list(tmp_path.glob(".evidence-work.*"))   # 暫存區在結果資料夾旁邊（不在 --out），也刪了
    # 只靠樣式：PILOT_ENV 裡的金鑰值不在清單裡、私鑰區塊
    f.write_text("-----BEGIN RSA PRIVATE KEY-----\n" + "QUJD" * 20 + "\n-----END RSA PRIVATE KEY-----\n", encoding="utf-8")
    st, detail, _ = create(tmp_path, res, out="o2", secrets_file=secrets(tmp_path, ["unrelated"]))
    assert st == "FAIL" and "private-key" in detail and bundle_files(tmp_path / "o2") == []
    # PILOT_ENV 的金鑰（只讀已知鍵）
    f.write_text("value pilotkey-1234 here\n", encoding="utf-8")
    pe = tmp_path / "pilot.env"
    pe.write_text("DT_URL=http://x\nDT_API_KEY='pilotkey-1234'\n", encoding="utf-8")
    st, detail, _ = eb.create(res, tmp_path / "o3", pilot_env=pe, allow_tmp=True)
    assert st == "FAIL" and "risk-assessment.md" in detail


def test_symlinks_not_followed(tmp_path):
    res = make_flash(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.md").write_text("confidential\n", encoding="utf-8")
    write_json(outside / "grype.json", {"matches": ["outside"]})
    rep = res / "rootfs_no_gui" / "cra-project" / "CRA" / "Reports"
    (rep / "extra.md").symlink_to(outside / "secret.md")
    g = res / "rootfs_no_gui" / "scan" / "scan" / "grype.json"
    g.unlink()
    g.symlink_to(outside / "grype.json")
    # 整個 rootfs 資料夾是連結：不跟隨
    other = tmp_path / "other"
    make_target(other, v="rootfs_gui")
    (res / "rootfs_gui").symlink_to(other / "rootfs_gui")
    st, detail, man = create(tmp_path, res)
    assert st == "ATTENTION" and "符號連結" in detail, detail
    got = members(tmp_path / "out" / f"{man['bundle']}.tar.xz")
    assert not any("extra.md" in n or n.startswith("rootfs_gui/") for n in got)
    assert "rootfs_no_gui/scan/scan/grype.json" not in got
    assert {s["path"] for s in man["skipped"]} >= {"rootfs_no_gui/cra-project/CRA/Reports/extra.md",
                                                  "rootfs_no_gui/scan/scan/grype.json", "rootfs_gui"}


def test_archive_like_and_oversize_files_not_included(tmp_path):
    res = make_flash(tmp_path)
    # 白名單的名字，內容卻是 tar 或 bzip2（例如被換成 rootfs）：不收
    (res / "rootfs_no_gui" / "scan" / "dt" / "findings.json").write_bytes(ustar())
    (res / "rootfs_no_gui" / "pkgdb" / "extended_states").write_bytes(b"BZh91AY&SY" + b"\0" * 32)
    (res / "rootfs_no_gui" / "rootfs-tar.json").unlink()
    os.mkfifo(res / "rootfs_no_gui" / "rootfs-tar.json")          # FIFO：不開（開了會卡住）
    write = lambda rel, b: (res / "rootfs_no_gui" / rel).write_bytes(b)  # noqa: E731
    write("scan/dt/data-sources.json", b"\x28\xb5\x2f\xfd" + b"\0" * 64)                   # zstd
    write("pkgdb/pkgdb.json", b"\0" * 1080 + b"\x53\xef\x01\x00" + b"\0" * 100)            # ext4 超級區塊
    write("scan/scan/kernel-config.json", lzma.compress(b"{}"))                               # 名稱不是 .xz 的 xz
    (res / "rootfs_no_gui" / "cra-project" / "CRA" / "Reports" / "risk-assessment.md").write_bytes(
        ("中" * 400).encode() + b"S" + "（".encode() * 300)                                     # 中文：不能誤判成 ext4
    big = res / "rootfs_no_gui" / "package-dependencies.md"
    big.write_bytes(b"x" * 20000)
    st, detail, man = create(tmp_path, res, limits={"file": 16384})
    assert st == "ATTENTION"
    reasons = {s["path"]: s["reason"] for s in man["skipped"]}
    assert "封存檔" in reasons["rootfs_no_gui/scan/dt/findings.json"] and "封存檔" in reasons["rootfs_no_gui/pkgdb/extended_states"]
    for rel in ("scan/dt/data-sources.json", "pkgdb/pkgdb.json", "scan/scan/kernel-config.json"):
        assert "封存檔" in reasons[f"rootfs_no_gui/{rel}"], rel
    assert "rootfs_no_gui/cra-project/CRA/Reports/risk-assessment.md" not in reasons
    assert "太大" in reasons["rootfs_no_gui/package-dependencies.md"] and "不是一般檔案" in reasons["rootfs_no_gui/rootfs-tar.json"]
    got = members(tmp_path / "out" / f"{man['bundle']}.tar.xz")
    assert "rootfs_no_gui/scan/dt/findings.json" not in got and "rootfs_no_gui/package-dependencies.md" not in got
    # 總量上限 → FAIL，不寫
    try:
        create(tmp_path, res, out="o3", limits={"total": 1000})
        raise AssertionError("應該 FAIL")
    except eb.Fail as e:
        assert "總量" in str(e)
    assert bundle_files(tmp_path / "o3") == []


def test_missing_inputs_attention_bundle_still_written(tmp_path):
    res = make_flash(tmp_path, md5_status="GAP", status="GAP", vex=False)
    st, detail, man = create(tmp_path, res, secrets_file=secrets(tmp_path, ["short"]))   # 太短的值不比對（會比對到一般文字）
    assert st == "ATTENTION"
    items = {c["item"] for c in man["checks"]}
    assert {"cra-documents:rootfs_no_gui", "cra-reports:rootfs_no_gui", "flash-package-md5", "secret-list", "secret-list-short"} <= items, items
    assert "vex.cdx.json" in detail and "risk-assessment GAP" in detail
    assert man["flash_package"]["md5"] == "unknown"
    assert (tmp_path / "out" / f"{man['bundle']}.tar.xz").is_file()
    assert eb.verify(tmp_path / "out" / f"{man['bundle']}.tar.xz")[0] == "OK"


def test_sca_scan_layout_with_and_without_project(tmp_path):
    scan = make_scan(tmp_path / "scanout", meta=dict(META, tools={}))
    proj = make_project(tmp_path / "proj", cfg=dict(MIN_CFG, product={"name": "Web App", "version": "2.3.0"}))
    make_reports(proj)
    st, detail, man = create(tmp_path, scan, project=proj)
    # 讀不到 Grype 版本與 DB 建立時間 → ATTENTION（證據包照樣寫出）
    assert st == "ATTENTION" and [c["item"] for c in man["checks"]] == ["tools:scan"], man["checks"]
    assert "Grype 版本、Grype DB 建立時間" in detail
    got = members(tmp_path / "out" / f"{man['bundle']}.tar.xz")
    assert "scan/meta.json" in got and "cra-project/CRA/Reports/vex.cdx.json" in got and "cra-project/CRA/Config/config.json" in got
    assert man["layout"] == "sca-scan" and man["flash_package"] is None and man["bundle"].startswith("evidence-Web-App-2.3.0-")
    t = man["targets"][0]
    assert t["tools"]["grype"] == "unknown" and t["data"]["grype_db"] == {"built": "unknown", "schema": "unknown"}   # 沒有就寫 unknown，不猜
    st, detail, man = create(tmp_path, scan, out="o2")
    assert st == "ATTENTION" and "--project" in detail and man["product"]["name"] == META["name"]
    try:
        create(tmp_path, tmp_path / "proj", out="o3")
        raise AssertionError("應該 FAIL")
    except eb.Fail as e:
        assert "不是 scan-flash-package" in str(e)


def test_existing_bundle_same_ok_different_fail(tmp_path):
    res = make_flash(tmp_path)
    st, _, man = create(tmp_path, res)
    arch = tmp_path / "out" / f"{man['bundle']}.tar.xz"
    before = arch.read_bytes()
    st, detail, _ = create(tmp_path, res)
    assert st == "OK" and "內容相同，沒有重寫" in detail
    os.utime(res / "summary.md", (eb.parse_time(man["frozen_utc"]) - 10,) * 2)     # 時間不變，內容改
    (res / "summary.md").write_text("# 改過\n", encoding="utf-8")
    os.utime(res / "summary.md", (eb.parse_time(man["frozen_utc"]) - 10,) * 2)
    st, detail, _ = create(tmp_path, res)
    assert st == "FAIL" and "不覆寫" in detail and arch.read_bytes() == before
    assert len(bundle_files(tmp_path / "out")) == 3


def test_cli_status_lines_and_exit_codes(tmp_path):
    res = make_flash(tmp_path)
    env = dict(os.environ, EVIDENCE_ALLOW_TMP_OUT="1", PILOT_ENV=str(tmp_path / "none.env"))
    run = lambda *a: subprocess.run([sys.executable, "-I", str(CLI), *a], capture_output=True, text=True, timeout=120, env=env)  # noqa: E731
    r = run("create", "--result", str(res), "--out", str(tmp_path / "out"), "--secrets-file", str(secrets(tmp_path)))
    assert r.returncode == 0 and r.stdout.startswith("EVIDENCE\tOK\t"), r.stdout + r.stderr
    arch = next((tmp_path / "out").glob("*.tar.xz"))
    r = run("verify", str(arch))
    assert r.returncode == 0 and r.stdout.startswith("EVIDENCE-VERIFY\tOK\t")
    r = run("create", "--result", str(res), "--out", str(tmp_path / "o2"))           # 沒有秘密清單 → ATTENTION
    assert r.returncode == 2 and r.stdout.startswith("EVIDENCE\tATTENTION\t") and "秘密清單" in r.stdout
    r = run("create", "--result", str(tmp_path / "nope"), "--out", str(tmp_path / "o3"))
    assert r.returncode == 1 and r.stdout.startswith("EVIDENCE\tFAIL\t")
    env.pop("EVIDENCE_ALLOW_TMP_OUT")
    r = run("create", "--result", str(res), "--out", "/tmp/evidence-test-out")
    assert r.returncode == 1 and "暫存區" in r.stdout and not Path("/tmp/evidence-test-out").exists()
    assert eb.in_shared_tmp("/tmp") and eb.in_shared_tmp("/dev/shm") and eb.in_shared_tmp("/var/tmp/x")
    assert not eb.in_shared_tmp("/tmpx/y") and not eb.in_shared_tmp("/mnt/data/x")
    r = run("verify", str(tmp_path / "secrets.txt"))
    assert r.returncode == 1 and r.stdout.startswith("EVIDENCE-VERIFY\tFAIL\t")


def test_secret_inside_xz_or_manifest_fail(tmp_path):
    """.xz 解壓後的內容與 manifest.json 也比對秘密（審查：壓縮過的 grype.json.xz 帶金鑰原本會 OK）。"""
    res = make_flash(tmp_path)
    g = res / "rootfs_no_gui" / "scan" / "scan" / "grype.json"
    g.unlink()
    Path(str(g) + ".xz").write_bytes(lzma.compress(json.dumps({"matches": [], "note": SECRET}).encode()))
    st, detail, man = create(tmp_path, res)
    assert st == "FAIL" and "grype.json.xz（解壓後）" in detail and man is None and bundle_files(tmp_path / "out") == []
    # 不在任何檔案、只出現在 manifest 的值（結果資料夾的名稱）
    Path(str(g) + ".xz").write_bytes(lzma.compress(b'{"matches": []}'))
    named = res.rename(tmp_path / f"res-{SECRET}")
    st, detail, _ = create(tmp_path, named, out="o2")
    assert st == "FAIL" and "manifest.json" in detail and bundle_files(tmp_path / "o2") == []


def cli(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        try:
            rc = eb.main(list(argv))
        except SystemExit as e:
            rc = e.code
    return rc, buf.getvalue()


def test_cli_bad_args_exit_64(tmp_path):
    for argv in ((), ("create",), ("create", "--out", str(tmp_path)), ("verify",), ("bogus",)):
        assert cli(*argv)[0] == 64, argv


def test_bad_types_no_traceback_and_unexpected_error_fail(tmp_path):
    res = make_flash(tmp_path)
    d = res / "rootfs_no_gui"
    write_json(d / "cra-project" / "CRA" / "Config" / "config.json", dict(MIN_CFG, product={"name": ["x"], "version": 1.5}))
    write_json(d / "scan" / "meta.json", ["not", "a", "dict"])
    write_json(d / "scan" / "sbom" / "sbom.cdx.json", {"metadata": ["x"], "components": []})
    write_json(d / "cra-project" / "CRA" / "Reports" / "summary.json", {"status": {"x": 1}, "documents": [], "vex": []})
    os.environ["EVIDENCE_ALLOW_TMP_OUT"] = "1"
    try:
        rc, out = cli("create", "--result", str(res), "--out", str(tmp_path / "out"), "--secrets-file", str(secrets(tmp_path)))
        assert rc == 2 and out.startswith("EVIDENCE\tATTENTION\t"), out
        man = json.loads(next((tmp_path / "out").glob("*.manifest.json")).read_text(encoding="utf-8"))
        assert man["product"] == {"name": None, "version": "1.5"} and "tools:rootfs_no_gui" in {c["item"] for c in man["checks"]}
        orig = eb.tools_of
        eb.tools_of = lambda *a: 1 / 0
        try:
            rc, out = cli("create", "--result", str(res), "--out", str(tmp_path / "o2"), "--secrets-file", str(secrets(tmp_path)))
        finally:
            eb.tools_of = orig
        assert rc == 1 and out.startswith("EVIDENCE\tFAIL\tZeroDivisionError") and bundle_files(tmp_path / "o2") == []
        assert not list(tmp_path.glob(".evidence-work.*"))
    finally:
        os.environ.pop("EVIDENCE_ALLOW_TMP_OUT", None)


def test_sbom_xz_accepted(tmp_path):
    res = make_flash(tmp_path)
    sb = res / "rootfs_no_gui" / "scan" / "sbom" / "sbom.cdx.json"
    data = sb.read_bytes()
    sb.unlink()
    Path(str(sb) + ".xz").write_bytes(lzma.compress(data))
    st, detail, man = create(tmp_path, res)
    assert st == "OK", detail
    assert man["targets"][0]["tools"]["sbom_generator"] == "syft 1.55.0"
    assert "rootfs_no_gui/scan/sbom/sbom.cdx.json.xz" in {f["path"] for f in man["files"]}


def test_hardlink_skipped(tmp_path):
    res = make_flash(tmp_path)
    (tmp_path / "outside.md").write_text("# not from the result\n", encoding="utf-8")
    dep = res / "rootfs_no_gui" / "package-dependencies.md"
    dep.unlink()
    os.link(tmp_path / "outside.md", dep)
    st, detail, man = create(tmp_path, res)
    assert st == "ATTENTION"
    assert "硬連結" in {s["path"]: s["reason"] for s in man["skipped"]}["rootfs_no_gui/package-dependencies.md"]
    assert "rootfs_no_gui/package-dependencies.md" not in {f["path"] for f in man["files"]}


def test_publish_without_hardlinks_and_rollback(tmp_path):
    res = make_flash(tmp_path)
    orig_link = eb._link

    def no_link(*a, **k):
        raise OSError(errno.EPERM, "no hardlinks on this filesystem")
    eb._link = no_link                    # NAS 不支援硬連結：退回 rename，照樣寫得出來
    try:
        st, _, man = create(tmp_path, res)
    finally:
        eb._link = orig_link
    assert st == "OK" and len(bundle_files(tmp_path / "out")) == 3

    def fail_on_archive(src, dst):
        if str(dst).endswith(".tar.xz"):
            raise OSError(errno.ENOSPC, "disk full")
        orig_link(src, dst)
    eb._link = fail_on_archive            # 封存檔放不上去：已經放上去的旁邊的檔也刪掉
    try:
        create(tmp_path, res, out="o2")
        raise AssertionError("應該失敗")
    except OSError:
        pass
    finally:
        eb._link = orig_link
    assert bundle_files(tmp_path / "o2") == [] and not list(tmp_path.glob(".evidence-work.*"))


def test_publish_never_overwrites_concurrent_file(tmp_path):
    """放上去之前另一次執行剛好寫了同名的檔：不覆寫、也不刪它（有硬連結與退回 rename 兩條路）。"""
    out = tmp_path / "out"
    out.mkdir()
    src = tmp_path / "src"
    src.write_bytes(b"mine")
    orig_link = eb._link
    for link in (orig_link, None):
        if link is None:
            def link(*a, **k):
                raise OSError(errno.EOPNOTSUPP, "no hardlinks")
        (out / "b.tar.xz").write_bytes(b"theirs")
        eb._link = link
        try:
            eb.publish(out, [(out / "a.manifest.json", src), (out / "b.tar.xz", src)])
            raise AssertionError("應該失敗")
        except eb.Fail as e:
            assert "不覆寫" in str(e)
        finally:
            eb._link = orig_link
        assert (out / "b.tar.xz").read_bytes() == b"theirs" and bundle_files(out) == ["b.tar.xz"]   # 自己放的已刪、暫存檔也刪
        (out / "b.tar.xz").unlink()


def test_leftover_sidecars_after_crash(tmp_path):
    """放上旁邊的檔之後、封存檔之前中斷：內容相同就沿用；不同就 FAIL 並寫明是哪個檔。"""
    res = make_flash(tmp_path)
    st, _, man = create(tmp_path, res)
    out = tmp_path / "out"
    arch = out / f"{man['bundle']}.tar.xz"
    before = arch.read_bytes()
    arch.unlink()
    st, detail, _ = create(tmp_path, res)
    assert st == "OK" and "沿用上一次沒寫完留下的" in detail and arch.read_bytes() == before
    assert eb.verify(arch)[0] == "OK"
    arch.unlink()
    mp = out / f"{man['bundle']}.manifest.json"
    mp.write_bytes(b"{}")
    st, detail, _ = create(tmp_path, res)
    assert st == "FAIL" and mp.name in detail and "沒寫完" in detail and not arch.exists()


def test_xz_bomb_counts_against_total_limit(tmp_path):
    res = make_flash(tmp_path)
    g = res / "rootfs_no_gui" / "scan" / "scan" / "grype.json"
    g.unlink()
    Path(str(g) + ".xz").write_bytes(lzma.compress(b"{" + b" " * 300000 + b"}"))   # 壓縮後很小、解開很大
    try:
        create(tmp_path, res, limits={"total": 100000})
        raise AssertionError("應該 FAIL")
    except eb.Fail as e:
        assert "解壓後的總量" in str(e)
    assert bundle_files(tmp_path / "out") == [] and not list(tmp_path.glob(".evidence-work.*"))


def test_verify_sha256_must_be_hex(tmp_path):
    """--sha256 給空字串或格式不對：參數錯（64），不能默默變成沒有錨點。"""
    res = make_flash(tmp_path)
    _, _, man = create(tmp_path, res)
    arch = tmp_path / "out" / f"{man['bundle']}.tar.xz"
    for bad in ("", "abc", "z" * 64, "0" * 63, " " + "0" * 64):
        assert cli("verify", str(arch), "--sha256", bad)[0] == 64, bad
        assert eb.verify(arch, expect_sha256=bad)[0] == "FAIL", bad
    good = eb.sha256_file(arch).upper()
    rc, out = cli("verify", str(arch), "--sha256", good)
    assert rc == 0 and out.startswith("EVIDENCE-VERIFY\tOK\t") and "--sha256" in out


def test_security_testing_results_included(tmp_path):
    """映像靜態檢查、板子檢查（board_import.py 匯入的結果）與安全測試的決定、清單都收；.err、怪檔名、連結不收。"""
    import board_import as bi
    from test_security_testing import BOARD, BOARD_FILES, targz
    res = make_flash(tmp_path)
    d = res / "rootfs_no_gui"
    write_json(d / "image-check" / "image-check.json", {"schema": "sca-center-image-check/1", "findings": []})
    (d / "image-check" / "image-check.md").write_text("# Image check\n", encoding="utf-8")
    # 板子的檔案裡有 token（test_security_testing 的 BOARD_FILES 放的）：證據包的秘密檢查擋下來，什麼都不寫
    bi.run(d, [targz(tmp_path, BOARD, BOARD_FILES)])
    st, detail, _ = create(tmp_path, res, out="out0")
    assert st == "FAIL" and "gitlab-token" in detail
    assert not (tmp_path / "out0").exists() or not os.listdir(tmp_path / "out0")
    clean = {k: BOARD_FILES[k] for k in ("summary.txt", "os.txt", "listening.txt", "sysctl.txt")}
    clean.update({"sshd-effective.txt": "passwordauthentication yes\n", "lynis.txt.err": "stderr\n"})
    (tmp_path / "clean").mkdir()
    bi.run(d, [targz(tmp_path / "clean", BOARD, clean)], replace=True)
    p = d / "cra-project" / "CRA"
    write_json(p / "Config" / "security-findings.json", {"schema": "sca-center-security-findings/1", "decisions": []})
    (p / "Reports" / "security-findings.md").write_text("# Security findings\n", encoding="utf-8")
    st, detail, man = create(tmp_path, res)
    assert st == "OK", detail
    got = members(tmp_path / "out" / f"{man['bundle']}.tar.xz")
    for want in ("image-check/image-check.json", "image-check/image-check.md", "board-test/board-test.json",
                 f"board-test/{BOARD}/listening.txt", f"board-test/{BOARD}/sshd-effective.txt", f"board-test/{BOARD}/import.json",
                 "cra-project/CRA/Config/security-findings.json", "cra-project/CRA/Reports/security-findings.md"):
        assert f"rootfs_no_gui/{want}" in got, want
    assert not [n for n in got if n.endswith(".err")]
    # 不是 board_import 會寫的檔名、符號連結：不收，記在 skipped（ATTENTION）
    (d / "board-test" / BOARD / "evil.sh").write_text("x\n")
    os.symlink(d / "board-test" / BOARD, d / "board-test" / "board-test-link-20261103T000000Z")
    st, detail, man = create(tmp_path, res, out="out2")
    reasons = {s["path"]: s["reason"] for s in man["skipped"]}
    assert st == "ATTENTION" and f"rootfs_no_gui/board-test/{BOARD}/evil.sh" in reasons
    assert "rootfs_no_gui/board-test/board-test-link-20261103T000000Z" in reasons


def test_provenance_missing_or_mismatched(tmp_path):
    """沒有 provenance.json（較舊的掃描）：sha256 與掃描時的 commit 寫 unknown、ATTENTION；檔名或大小和 list.json 不同：sha256 不用。"""
    res = make_flash(tmp_path / "a", provenance=False)
    st, _, man = create(tmp_path / "a", res)
    assert st == "ATTENTION" and man["flash_package"]["sha256"] == "unknown" and man["sca_center"]["scan_commit"] == "unknown"
    assert {c["item"] for c in man["checks"]} >= {"scan-commit", "flash-package-sha256"}
    res = make_flash(tmp_path / "b")
    pv = json.loads((res / "provenance.json").read_text())
    pv["source"]["bytes"] = 9999
    write_json(res / "provenance.json", pv)
    st, _, man = create(tmp_path / "b", res)
    assert man["flash_package"]["sha256"] == "unknown" and "和 list.json／A-md5 不同" in man["flash_package"]["note"]
    assert man["sca_center"]["scan_commit"] == COMMIT and "flash-package-sha256" in {c["item"] for c in man["checks"]}


def test_provenance_dirty_md5_mismatch_and_carried(tmp_path):
    """掃描時有未提交的改動（或狀態不明）→ ATTENTION；provenance 的 md5 和 A-md5 不同 → sha256 不用；沿用的 → sha256_source carried。"""
    def with_pv(d, **upd):
        res = make_flash(d)
        pv = json.loads((res / "provenance.json").read_text())
        for k, v in upd.items():
            pv[k] = dict(pv[k], **v) if isinstance(v, dict) else v
        write_json(res / "provenance.json", pv)
        return res
    for name, dirty in (("dirty", True), ("unknown", None)):
        res = with_pv(tmp_path / name, sca_center={"from": "git", "dirty": dirty})
        st, _, man = create(tmp_path / name, res)
        assert st == "ATTENTION" and "scan-commit" in {c["item"] for c in man["checks"]}, man["checks"]
    res = with_pv(tmp_path / "md5", source={"md5": "0" * 32})
    _, _, man = create(tmp_path / "md5", res)
    assert man["flash_package"]["sha256"] == "unknown" and "flash-package-sha256" in {c["item"] for c in man["checks"]}
    res = with_pv(tmp_path / "carried", carried_from="product-a-old")
    _, _, man = create(tmp_path / "carried", res)
    assert man["flash_package"]["sha256"] == SHA and man["flash_package"]["sha256_source"] == "carried" and "product-a-old" in man["flash_package"]["note"]
