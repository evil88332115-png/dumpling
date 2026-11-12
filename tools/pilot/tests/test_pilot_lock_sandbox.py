"""規則 11 的鎖定檔判定（lockcheck.py＋sbomgate）、規則 13 的上傳用 SBOM（strip_versions.py）、外洩檢查（leakscan.py）、
沙箱遮蔽家目錄與 runner 憑證（sandbox.sh 的 bwrap 參數），以及 compare_expected 的「預期 0 筆」判定。不需要網路或掃描工具。"""
import json
import os
import pwd
import subprocess
import sys

import pytest

from pilot_fixtures import ALL_OK, PILOT, ROOT, load_module, make_out, run_report

lock = load_module("pilot_lockcheck", PILOT / "lib" / "lockcheck.py")
strip = load_module("pilot_strip_versions", PILOT / "lib" / "strip_versions.py")
leak = load_module("pilot_leakscan", PILOT / "lib" / "leakscan.py")
SBOMGATE = ROOT / "tools" / "sbomgate" / "sbomgate.py"


def touch(base, *names, text="{}"):
    for n in names:
        p = base / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


# ---------- 規則 11：依生態系判斷 ----------

def test_lock_for_npm_but_requirements_without_lock_is_unknown(tmp_path):
    touch(tmp_path, "package.json", "package-lock.json")
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    r = lock.check(tmp_path)
    assert r["tree"] == "unknown"
    assert r["missing_ecosystems"] == ["pypi"]
    assert {e["ecosystem"]: e["status"] for e in r["ecosystems"]} == {"npm": "lock", "pypi": "missing"}
    assert r["manifests_for_sbomgate"] == ["package.json", "requirements.txt"]   # 每個清單檔都傳給 sbomgate
    assert "pypi" in r["reason"]


def test_lock_mixed_project_must_be_partial_in_sbomgate(tmp_path):
    """package-lock.json＋沒有鎖定檔的 requirements.txt → sbomgate 必須是 PARTIAL（GAP），不可 COMPLETE。"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}))
    (src / "package-lock.json").write_text("{}")
    (src / "requirements.txt").write_text("requests==2.19.0\n")
    r = lock.check(src)
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"components": [
        {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
        {"type": "library", "name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"}]}))
    gr = tmp_path / "grype.json"
    gr.write_text(json.dumps({"matches": [], "descriptor": {"db": {"status": {"built": "2026-10-23T00:00:00Z"}}}}))
    args = [sys.executable, "-I", str(SBOMGATE), "--sbom", str(sbom), "--grype", str(gr), "--tree", r["tree"], "--now", "2026-10-23T06:00:00Z",
            "--out", str(tmp_path / "gate.json")]
    for m in r["manifests_for_sbomgate"]:
        args += ["--manifest", str(src / m)]
    p = subprocess.run(args, capture_output=True, text=True)
    assert p.returncode == 1, p.stdout + p.stderr          # PARTIAL
    g = json.loads((tmp_path / "gate.json").read_text())
    assert g["vulnerability_analysis"]["status"] == "PARTIAL"
    assert len(g["sbom"]["manifests"]) == 2
    # 同資料夾再放 poetry.lock 也不算：requirements.txt 不與任何鎖定檔配對（第三次審查）
    (src / "poetry.lock").write_text("")
    assert lock.check(src)["missing_ecosystems"] == ["pypi"]
    # 改成 pyproject.toml＋poetry.lock（類型配對）→ 兩個生態系都有鎖定檔 → full → COMPLETE
    (src / "requirements.txt").unlink()
    (src / "pyproject.toml").write_text('[tool.poetry]\nname = "x"\n')
    r2 = lock.check(src)
    assert r2["tree"] == "full", r2
    args2 = [sys.executable, "-I", str(SBOMGATE), "--sbom", str(sbom), "--grype", str(gr), "--tree", r2["tree"], "--now", "2026-10-23T06:00:00Z"]
    for m in r2["manifests_for_sbomgate"]:
        args2 += ["--manifest", str(src / m)]
    p2 = subprocess.run(args2, capture_output=True, text=True)
    assert p2.returncode == 0, p2.stdout + p2.stderr


def test_lock_parent_lockfile_does_not_count_without_workspace(tmp_path):
    """上層的鎖定檔不算，除非確認是工作區成員（2026-10-23 複審）。"""
    touch(tmp_path, "pyproject.toml", "poetry.lock")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "requirements.txt").write_text("sphinx==7.0\n")
    r = lock.check(tmp_path)
    assert r["tree"] == "unknown" and r["missing_ecosystems"] == ["pypi"]
    st = {m["manifest"]: m["status"] for e in r["ecosystems"] for m in e["manifests"]}
    assert st == {"pyproject.toml": "lock", "docs/requirements.txt": "missing"}


def test_lock_python_lockfile_must_match_manifest_type(tmp_path):
    """同資料夾 pyproject.toml＋poetry.lock＋requirements-docs.txt（範圍版本）→ pypi missing 並列出 requirements-docs.txt。"""
    (tmp_path / "pyproject.toml").write_text('[tool.poetry]\nname = "x"\n')
    touch(tmp_path, "poetry.lock", text="")
    (tmp_path / "requirements-docs.txt").write_text("sphinx>=7\n")
    r = lock.check(tmp_path)
    assert r["tree"] == "unknown" and r["missing_ecosystems"] == ["pypi"]
    st = {m["manifest"]: m["status"] for e in r["ecosystems"] for m in e["manifests"]}
    assert st == {"pyproject.toml": "lock", "requirements-docs.txt": "missing"}
    assert "requirements-docs.txt（不視為鎖定）" in r["summary"]


@pytest.mark.parametrize("files,pyproject,want", [
    (["poetry.lock"], "[tool.poetry]\nname='x'\n", "lock"),
    (["uv.lock"], "[tool.poetry]\nname='x'\n", "missing"),          # 工具是 poetry，只認 poetry.lock
    (["pdm.lock"], "[tool.pdm]\n[project]\nname='x'\n", "lock"),
    (["poetry.lock"], "[tool.pdm]\n", "missing"),
    (["uv.lock"], "[tool.uv]\ndev-dependencies=[]\n", "lock"),
    (["pylock.toml"], "[project]\nname='x'\n", "lock"),               # 看不出工具：四種都認
    ([], "[project]\nname='x'\n", "missing"),
])
def test_lock_pyproject_tool_specific(tmp_path, files, pyproject, want):
    (tmp_path / "pyproject.toml").write_text(pyproject)
    touch(tmp_path, *files, text="")
    st = [m["status"] for e in lock.check(tmp_path)["ecosystems"] for m in e["manifests"]]
    assert st == [want]


@pytest.mark.parametrize("manifest,lockf,want", [("Pipfile", "Pipfile.lock", "lock"), ("Pipfile", "poetry.lock", "missing"),
                                                 ("setup.py", "poetry.lock", "missing"), ("setup.cfg", "Pipfile.lock", "missing"),
                                                 ("requirements.txt", "Pipfile.lock", "missing")])
def test_lock_other_python_manifests(tmp_path, manifest, lockf, want):
    touch(tmp_path, manifest, lockf, text="")
    st = {m["manifest"]: m["status"] for e in lock.check(tmp_path)["ecosystems"] for m in e["manifests"]}
    assert st[manifest] == want


def test_lock_go_submodule_with_only_root_gosum_is_missing(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/x\nrequire a.b/c v1.0.0\n")
    (tmp_path / "go.sum").write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "go.mod").write_text("module example.com/x/sub\nrequire a.b/d v1.0.0\n")
    r = lock.check(tmp_path)
    assert r["missing_ecosystems"] == ["golang"]
    # go.work 的 use 列入且有 go.work.sum → 成員
    (tmp_path / "go.work").write_text("go 1.22\n\nuse (\n\t.\n\t./sub\n)\n")
    assert lock.check(tmp_path)["missing_ecosystems"] == ["golang"]        # 還沒有 go.work.sum
    (tmp_path / "go.work.sum").write_text("")
    r = lock.check(tmp_path)
    assert r["tree"] == "full"
    assert [m.get("via") for e in r["ecosystems"] for m in e["manifests"] if m["manifest"] == "sub/go.mod"] == ["go.work 的 use 列入"]
    # 單行 use 但沒列這個模組 → missing
    (tmp_path / "go.work").write_text("go 1.22\nuse .\n")
    assert lock.check(tmp_path)["missing_ecosystems"] == ["golang"]


def test_lock_npm_workspaces(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "root", "workspaces": ["packages/*"]}))
    touch(tmp_path, "package-lock.json", "packages/a/package.json", "examples/foo/package.json")
    r = lock.check(tmp_path)
    st = {m["manifest"]: m["status"] for e in r["ecosystems"] for m in e["manifests"]}
    assert st == {"package.json": "lock", "packages/a/package.json": "lock", "examples/foo/package.json": "missing"}
    assert r["missing_ecosystems"] == ["npm"]
    # yarn 的 {"packages": [...]} 寫法、** glob
    (tmp_path / "package.json").write_text(json.dumps({"workspaces": {"packages": ["packages/*", "examples/**"]}}))
    (tmp_path / "package-lock.json").unlink()
    touch(tmp_path, "yarn.lock")
    assert lock.check(tmp_path)["tree"] == "full"
    # 有 workspaces 但根目錄沒有鎖定檔 → 成員也是 missing
    (tmp_path / "yarn.lock").unlink()
    assert lock.check(tmp_path)["tree"] == "unknown"


def test_lock_pnpm_workspace(tmp_path):
    (tmp_path / "pnpm-workspace.yaml").write_text("packages:\n  - 'packages/*'\n  - '!packages/skip'\n")
    touch(tmp_path, "package.json", "pnpm-lock.yaml", "packages/a/package.json", "packages/skip/package.json")
    st = {m["manifest"]: m["status"] for e in lock.check(tmp_path)["ecosystems"] for m in e["manifests"]}
    assert st == {"package.json": "lock", "packages/a/package.json": "lock", "packages/skip/package.json": "missing"}


def test_lock_cargo_workspace(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/old"]\n')
    touch(tmp_path, "Cargo.lock", "crates/a/Cargo.toml", "crates/old/Cargo.toml", text="")
    touch(tmp_path, "tools/x/Cargo.toml", text="")
    st = {m["manifest"]: m["status"] for e in lock.check(tmp_path)["ecosystems"] for m in e["manifests"]}
    assert st == {"Cargo.toml": "lock", "crates/a/Cargo.toml": "lock", "crates/old/Cargo.toml": "missing", "tools/x/Cargo.toml": "missing"}


def test_lock_uv_workspace(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="r"\n[tool.uv.workspace]\nmembers = ["packages/*"]\n')
    touch(tmp_path, "uv.lock", "packages/a/pyproject.toml", text="")
    (tmp_path / "packages" / "a" / "pyproject.toml").write_text('[project]\nname="a"\n')
    r = lock.check(tmp_path)
    assert r["tree"] == "full", r
    # 成員資料夾內的 requirements 不被工作區涵蓋（requirements 一律不視為鎖定）
    (tmp_path / "packages" / "a" / "requirements-dev.txt").write_text("pytest==8\n")
    assert lock.check(tmp_path)["missing_ecosystems"] == ["pypi"]
    (tmp_path / "packages" / "a" / "requirements-dev.txt").unlink()
    (tmp_path / "uv.lock").unlink()
    touch(tmp_path, "poetry.lock", text="")                       # 非 uv 的鎖定檔不能涵蓋成員
    assert lock.check(tmp_path)["missing_ecosystems"] == ["pypi"]


def test_lock_unreadable_workspace_declaration_is_missing(tmp_path):
    (tmp_path / "package.json").write_text("{not json")
    touch(tmp_path, "package-lock.json", "packages/a/package.json")
    st = {m["manifest"]: m["status"] for e in lock.check(tmp_path)["ecosystems"] for m in e["manifests"]}
    assert st["packages/a/package.json"] == "missing"


def test_lock_go_without_requires_needs_no_gosum(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/x\n\ngo 1.22\n")
    assert lock.check(tmp_path)["tree"] == "full"
    (tmp_path / "go.mod").write_text("module example.com/x\n\nrequire golang.org/x/text v0.3.6\n")
    r = lock.check(tmp_path)
    assert r["tree"] == "unknown" and r["missing_ecosystems"] == ["golang"]
    assert r["manifests_not_checked"] == ["go.mod"]          # sbomgate 不支援 → 記錄為未比對


def test_lock_maven_has_no_lockfile_and_no_manifest_is_unknown(tmp_path):
    touch(tmp_path, "pom.xml")
    assert lock.check(tmp_path)["missing_ecosystems"] == ["maven"]
    empty = tmp_path / "e"
    empty.mkdir()
    r = lock.check(empty)
    assert r["tree"] == "unknown" and "沒有偵測到任何清單檔" in r["reason"]


def test_lock_skips_node_modules_and_vendor(tmp_path):
    touch(tmp_path, "package.json", "package-lock.json", "node_modules/x/package.json", "vendor/y/composer.json")
    r = lock.check(tmp_path)
    assert r["tree"] == "full" and [e["ecosystem"] for e in r["ecosystems"]] == ["npm"]


def test_report_identity_lists_lockfile_verdicts(tmp_path):
    touch(tmp_path / "src", "package.json", "package-lock.json")
    (tmp_path / "src" / "requirements.txt").write_text("a==1\n")
    out = make_out(tmp_path / "out", ALL_OK)
    (out / "scan" / "lockfiles.json").write_text(json.dumps(lock.check(tmp_path / "src")), encoding="utf-8")
    rep, page = run_report(out)
    assert "鎖定檔判定（規則 11）" in page and "缺鎖定檔" in page and "package.json → package-lock.json" in page
    assert rep["lockfiles"]["missing_ecosystems"] == ["pypi"]


# ---------- 規則 13：上傳用 SBOM ----------

def test_strip_versions_removes_only_unknown(tmp_path):
    sbom = {"components": [
        {"type": "library", "name": "requests", "version": "2.0", "purl": "pkg:pypi/requests@2.0", "bom-ref": "pkg:pypi/requests@2.0"},
        {"type": "library", "name": "idna", "version": "3.20", "purl": "pkg:pypi/idna@3.20"},
        {"type": "library", "name": "x", "version": "1.0", "purl": "pkg:deb/debian/x@1.0?arch=amd64",
         "components": [{"type": "library", "name": "inner", "version": ">=1"}]}]}
    gate = {"component_details": [
        {"name": "requests", "version": "2.0", "purl": "pkg:pypi/requests@2.0", "class": "VERSION_FROM_RANGE"},
        {"name": "idna", "version": "3.20", "purl": "pkg:pypi/idna@3.20", "class": "RESOLVED"},
        {"name": "x", "version": "1.0", "purl": "pkg:deb/debian/x@1.0?arch=amd64", "class": "NO_VERSION"},
        {"name": "inner", "version": ">=1", "purl": "", "class": "VERSION_FROM_RANGE"}]}
    (tmp_path / "s.json").write_text(json.dumps(sbom))
    (tmp_path / "g.json").write_text(json.dumps(gate))
    assert strip.main([str(tmp_path / "s.json"), str(tmp_path / "g.json"), str(tmp_path / "o.json")]) == 0
    o = json.loads((tmp_path / "o.json").read_text())
    req, idna, x = o["components"]
    assert "version" not in req and req["purl"] == "pkg:pypi/requests" and req["bom-ref"] == "pkg:pypi/requests@2.0"
    assert any(p["name"] == "sca-pilot:version-removed" and p["value"].startswith("2.0") for p in req["properties"])
    assert idna["version"] == "3.20" and idna["purl"] == "pkg:pypi/idna@3.20"
    assert x["purl"] == "pkg:deb/debian/x?arch=amd64"
    assert "version" not in x["components"][0]
    assert json.loads((tmp_path / "s.json").read_text()) == sbom        # 原始 SBOM 不動


def test_strip_purl_version_forms():
    f = strip.strip_purl_version
    assert f("pkg:npm/%40scope/name@1.0.0") == "pkg:npm/%40scope/name"
    assert f("pkg:golang/golang.org/x/text@v0.3.6#sub") == "pkg:golang/golang.org/x/text#sub"
    assert f("pkg:maven/org.a/b@1.0?type=jar") == "pkg:maven/org.a/b?type=jar"
    assert f("pkg:pypi/requests") == "pkg:pypi/requests"


# ---------- 外洩檢查：秘密從檔案讀 ----------

def test_leakscan_reads_secrets_from_file(tmp_path):
    (tmp_path / "secrets").write_text("\nsuper-secret-1\n")
    d = tmp_path / "out"
    (d / "a").mkdir(parents=True)
    (d / "a" / "x.json").write_text('{"k":"super-secret-1"}')
    (d / "y.txt").write_text("clean")
    assert leak.scan(str(tmp_path / "secrets"), [str(d)]) == [str(d / "a" / "x.json")]
    (tmp_path / "empty").write_text("\n")
    assert leak.scan(str(tmp_path / "empty"), [str(d)]) == []


def test_sca_scan_does_not_pass_secrets_on_command_lines():
    t = (PILOT / "sca-scan").read_text(encoding="utf-8")
    assert 'grep -rlF -- "$s"' not in t and 'grep -qF -- "$s"' not in t
    assert "leakscan.py" in t
    assert '"X-Api-Key: $DT_API_KEY"' in t and "-H @\"$DT_HDR\"" in t     # 金鑰只寫進標頭檔


# ---------- 沙箱：家目錄與 runner 憑證 ----------

def bwrap_args(script, env=None, args=()):
    s = f'. "{ROOT}/tools/e2e/sandbox.sh"; bwrap(){{ printf "%s\\n" "$@"; }}; {script}'
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run(["bash", "-c", s, "_", *args], capture_output=True, text=True, env=e, timeout=60)
    return r.stdout.splitlines(), r.stderr


def pairs(out, flag):
    return [out[i + 1] for i, a in enumerate(out) if a == flag]


REAL_HOME = os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)


@pytest.mark.parametrize("net", ["", "--net"])
def test_sandbox_masks_real_home_with_and_without_network(net):
    out, _ = bwrap_args(f"sbx {net} -- true")
    if os.path.isdir(REAL_HOME) and REAL_HOME != "/":
        assert REAL_HOME in pairs(out, "--tmpfs")


def test_sandbox_masks_env_home_too_when_different(tmp_path):
    fake_home = tmp_path / "h"
    fake_home.mkdir()
    out, _ = bwrap_args("sbx -- true", {"HOME": str(fake_home)})
    assert str(fake_home.resolve()) in pairs(out, "--tmpfs")


def test_sandbox_rebinds_ro_paths_and_hides_secrets_after(tmp_path):
    h = tmp_path / "home"
    work = h / "work"
    (work / "secrets").mkdir(parents=True)
    (work / "secrets" / "k").write_text("x")
    out, _ = bwrap_args('SBX_RO=("$1"); SBX_HIDE=("$2"); sbx "$3" -- true', {"HOME": str(h)}, [str(work), str(work / "secrets"), str(work / "o")])
    ro = [out[i + 1] for i, a in enumerate(out) if a == "--ro-bind"]
    assert str(work.resolve()) in ro
    i_mask = out.index(str(h.resolve()))
    i_ro = out.index(str(work.resolve()))
    i_hide = max(i for i, a in enumerate(out) if a == str(work / "secrets"))
    i_rw = out.index("--bind")
    assert i_mask < i_ro < i_hide < i_rw          # 遮蔽 → 掛回 → 遮秘密 → 可寫


def test_sandbox_refuses_to_rebind_home_itself(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    (h / ".ssh").mkdir()
    out, err = bwrap_args('SBX_RO=("$HOME" "$HOME/.ssh"); sbx -- true', {"HOME": str(h)})
    assert str(h.resolve()) not in [out[i + 1] for i, a in enumerate(out) if a == "--ro-bind"]
    assert str((h / ".ssh").resolve()) not in [out[i + 1] for i, a in enumerate(out) if a == "--ro-bind"]
    assert "拒絕掛回" in err


def test_sandbox_rebinds_only_tool_dirs_and_recreates_symlinks(tmp_path):
    h = tmp_path / "home"
    pkg = h / "npm" / "lib" / "node_modules" / "@cyclonedx" / "cdxgen" / "bin"
    pkg.mkdir(parents=True)
    (pkg / "cdxgen.js").write_text("#!/bin/sh\n")
    (pkg / "cdxgen.js").chmod(0o755)
    (h / "npm" / "bin").mkdir()
    (h / "npm" / "etc").mkdir()
    (h / "npm" / "etc" / "npmrc").write_text("//registry.npmjs.org/:_authToken=fake")
    os.symlink(pkg / "cdxgen.js", h / "npm" / "bin" / "cdxgen")
    (h / "tools" / "go" / "bin").mkdir(parents=True)
    (h / "tools" / "go" / "bin" / "go").write_text("#!/bin/sh\n")
    (h / "tools" / "go" / "bin" / "go").chmod(0o755)
    env = {"HOME": str(h), "PATH": f"{h}/npm/bin:{h}/tools/go/bin:/usr/bin:/bin", "SBX_TOOLS": "cdxgen go"}
    out, _ = bwrap_args("sbx -- true", env)
    ro = pairs(out, "--ro-bind")
    hr = str(h.resolve())
    assert f"{hr}/npm/lib/node_modules/@cyclonedx/cdxgen" in ro                 # npm 全域套件：套件根目錄
    assert f"{hr}/tools/go/bin" in ro and f"{hr}/tools/go" not in ro            # 其他工具：只掛 dirname(readlink -f)
    assert f"{hr}/npm/bin" not in ro and f"{hr}/npm" not in ro and hr not in ro
    i = out.index("--symlink")
    assert out[i + 1:i + 3] == [f"{hr}/npm/lib/node_modules/@cyclonedx/cdxgen/bin/cdxgen.js", f"{hr}/npm/bin/cdxgen"]   # 重建 PATH 上的連結
    assert f"{hr}/npm/etc/npmrc" not in ro


@pytest.mark.parametrize("rel", [".cargo", ".pyenv", ".nvm", ".config/anything", ".config", "npm/etc", "x/etc/npmrc"])
def test_sandbox_unsafe_paths_are_refused(tmp_path, rel):
    h = tmp_path / "home"
    (h / rel).mkdir(parents=True)
    out, err = bwrap_args('SBX_RO=("$1"); sbx -- true', {"HOME": str(h)}, [str(h / rel)])
    assert str((h / rel).resolve()) not in pairs(out, "--ro-bind") and "拒絕掛回" in err


def test_sandbox_runner_temp_and_runner_root_masked_and_not_rebindable(tmp_path):
    rr = tmp_path / "runners" / "repo"
    ws = rr / "_work" / "sca-center"
    temp = rr / "_work" / "_temp"
    (ws).mkdir(parents=True)
    (temp / "e2e" / "work").mkdir(parents=True)
    env = {"RUNNER_WORKSPACE": str(ws), "RUNNER_TEMP": str(temp)}
    out, err = bwrap_args('SBX_RO=("$1" "$2" "$3"); sbx -- true', env, [str(temp), str(rr), str(temp / "e2e" / "work")])
    assert str(rr.resolve()) in pairs(out, "--tmpfs")                     # RUNNER_WORKSPACE 的上兩層
    ro = pairs(out, "--ro-bind")
    assert str(temp.resolve()) not in ro and str(rr.resolve()) not in ro   # RUNNER_TEMP、runner 根目錄本身不可掛回
    assert str((temp / "e2e" / "work").resolve()) in ro                    # 底下的工作資料夾可以


def test_sandbox_auto_hides_python_and_ro_root_configs(tmp_path):
    base = tmp_path / "py"
    (base / "etc").mkdir(parents=True)
    (base / "pip.conf").write_text("[global]\nindex-url=https://u:token@x/simple")
    (base / ".condarc").write_text("x")
    py = tmp_path / "bin" / "python3"
    py.parent.mkdir()
    py.write_text(f"#!/bin/sh\necho {base}\necho {base}\n")
    py.chmod(0o755)
    goroot = tmp_path / "goroot"
    (goroot / "etc").mkdir(parents=True)
    (goroot / "pip.conf").write_text("x")
    out, _ = bwrap_args('SBX_RO=("$1"); sbx -- true', {"PATH": f"{tmp_path}/bin:/usr/bin:/bin", "SBX_TOOLS": "none"}, [str(goroot)])
    for f in (base / "pip.conf", base / ".condarc", goroot / "pip.conf"):
        i = out.index(str(f))
        assert out[i - 2] == "--ro-bind" and "/sbx-stubs." in out[i - 1], f
    for d in (base / "etc", goroot / "etc"):
        assert out[out.index(str(d)) - 1] == "--tmpfs", d


def test_sandbox_auto_hides_npm_global_config(tmp_path):
    prefix = tmp_path / "prefix"
    (prefix / "etc").mkdir(parents=True)
    (prefix / "etc" / "npmrc").write_text("x")
    fake_npm = tmp_path / "bin" / "npm"
    fake_npm.parent.mkdir()
    fake_npm.write_text(f'#!/bin/sh\n[ "$1 $2" = "prefix -g" ] && echo {prefix}\n')
    fake_npm.chmod(0o755)
    out, _ = bwrap_args("sbx -- true", {"PATH": f"{tmp_path}/bin:/usr/bin:/bin", "SBX_TOOLS": "none"})
    i = out.index(str(prefix / "etc" / "npmrc"))
    assert out[i - 2] == "--ro-bind" and "/sbx-stubs." in out[i - 1]


def test_sandbox_probe_reports_home_credentials_as_checked():
    t = (ROOT / "tools" / "e2e" / "sandbox.sh").read_text(encoding="utf-8")
    for p in (".ssh", ".docker/config.json", ".config/gh", ".git-credentials", ".netrc", ".npmrc", "/home/runner/runners/*/.credentials"):
        assert p in t
    assert "getent passwd" in t




def test_sca_scan_hides_whole_pilot_env_folder():
    t = (PILOT / "sca-scan").read_text(encoding="utf-8")
    assert 'PENV_HIDE=("$PENV_DIR")' in t and 'SBX_HIDE=("$SECDIR" "${PENV_HIDE[@]}"' in t


# ---------- compare_expected：預期 0 筆 ----------



# ---------- 2026-10-23 實機回歸（petclinic 163 → 19）：工具鏈與元件數檢查 ----------

def test_toolchain_roots_include_maven_home_and_java_home(tmp_path):
    mh = tmp_path / "tool" / "maven" / "3.9"
    (mh / "bin").mkdir(parents=True)
    (mh / "boot").mkdir()
    (mh / "bin" / "mvn").write_text("#!/bin/sh\n")
    (mh / "bin" / "mvn").chmod(0o755)
    jh = tmp_path / "jdk"
    (jh / "bin").mkdir(parents=True)
    (jh / "bin" / "java").write_text("#!/bin/sh\n")
    (jh / "bin" / "java").chmod(0o755)
    e = dict(os.environ)
    e.pop("JAVA_HOME", None)
    e["PATH"] = f"{mh}/bin:{jh}/bin:/usr/bin:/bin"
    r = subprocess.run(["bash", "-c", f'. "{ROOT}/tools/e2e/sandbox.sh"; sbx_toolchain_roots'], capture_output=True, text=True, env=e)
    lines = r.stdout.splitlines()
    assert str(mh) in lines and str(jh) in lines        # mvn 需要 boot／lib／conf：要掛整個 Maven 目錄，不能只掛 bin




def _st(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("stage\tstatus\tdetail\n" + "".join("\t".join(r) + "\n" for r in rows), encoding="utf-8")


REGRESS = ROOT / "tools" / "e2e" / "cdxgen_regression.py"




def test_cdxgen_regression_ignores_runs_with_failed_sandbox(tmp_path):
    res = tmp_path / "results"
    _st(res / "round8-actions-20261022-run100" / "status.tsv", [("B-sandbox", "FAIL", ""), ("B-cdxgen-x", "OK", "100 components")])
    cur = tmp_path / "cur.tsv"
    _st(cur, [("B-cdxgen-x", "OK", "10 components")])
    r = subprocess.run([sys.executable, "-I", str(REGRESS), str(res), str(cur), "x"], capture_output=True, text=True)
    assert r.stdout == ""








def test_sandbox_hides_maven_and_gradle_global_configs_with_valid_stubs(tmp_path):
    mh = tmp_path / "maven"
    (mh / "conf").mkdir(parents=True)
    (mh / "conf" / "settings.xml").write_text("<settings><servers><server><password>FAKE</password></server></servers></settings>")
    (mh / "conf" / "settings-security.xml").write_text("<settingsSecurity><master>FAKE</master></settingsSecurity>")
    gh = tmp_path / "gradle"
    (gh / "init.d").mkdir(parents=True)
    (gh / "init.d" / "repo.gradle").write_text("token")
    (gh / "gradle.properties").write_text("systemProp.https.proxyPassword=FAKE")
    out, _ = bwrap_args('SBX_RO=("$1" "$2"); sbx -- true', {"SBX_TOOLS": "none"}, [str(mh), str(gh)])
    src = {out[i + 2]: out[i + 1] for i, a in enumerate(out) if a == "--ro-bind"}
    assert src[str(mh / "conf" / "settings.xml")].endswith("/settings.xml")
    assert open(src[str(mh / "conf" / "settings.xml")]).read().strip() == "<settings/>"          # 合法的空設定，Maven 仍可啟動
    assert open(src[str(mh / "conf" / "settings-security.xml")]).read().strip() == "<settingsSecurity/>"
    assert src[str(gh / "gradle.properties")].endswith("/empty")
    assert str(gh / "init.d") in pairs(out, "--tmpfs")


def test_probe_treats_stub_content_as_hidden():
    t = (ROOT / "tools" / "e2e" / "sandbox.sh").read_text(encoding="utf-8")
    assert "sbx_stub_sums" in t and "只讀到空的替代檔" in t


def _fake_maven(tmp_path, good=True, pinned=None, gha=False):
    """假的 curl：依網址回傳預先做好的 Maven tarball 與 .sha512（不連網）。"""
    import hashlib
    import tarfile
    srv = tmp_path / "srv"
    (srv / "apache-maven-3.10.0" / "bin").mkdir(parents=True)
    (srv / "apache-maven-3.10.0" / "bin" / "mvn").write_text("#!/bin/sh\n")
    tgz = tmp_path / "apache-maven-3.10.0-bin.tar.gz"
    with tarfile.open(tgz, "w:gz") as t:
        t.add(srv / "apache-maven-3.10.0", arcname="apache-maven-3.10.0")
    h = hashlib.sha512(tgz.read_bytes()).hexdigest()
    (tmp_path / "apache-maven-3.10.0-bin.tar.gz.sha512").write_text((h if good else "0" * 128) + "\n")
    bin_ = tmp_path / "fakebin"
    bin_.mkdir()
    (bin_ / "curl").write_text(f'#!/bin/sh\nwhile [ $# -gt 0 ]; do case $1 in -o) o=$2; shift 2;; -*) shift;; *) u=$1; shift;; esac; done\n'
                               f'cp "{tmp_path}/$(basename "$u")" "$o"\n')
    (bin_ / "curl").chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_ACTIONS", "MAVEN_SHA512")}   # CI 本身是 GitHub Actions
    env["PATH"] = f"{bin_}:/usr/bin:/bin"
    if gha:
        env["GITHUB_ACTIONS"] = "true"
    if pinned:
        env["MAVEN_SHA512"] = h if pinned == "same" else pinned
    r = subprocess.run(["bash", str(ROOT / "tools" / "e2e" / "install-maven.sh"), str(tmp_path / "dest"), str(tmp_path / "rec.txt"), "3.10.0"],
                       capture_output=True, text=True, env=env)
    return r, h








MAVEN_3_10_0_SHA512 = "908b1501bfb420bf7c8affb855534a9c407fd6099367bfb9f2f2dcb8e9799102bffb84518cde74c679bd76870247c6528683abdd620581bffa90f95d92d175aa"






