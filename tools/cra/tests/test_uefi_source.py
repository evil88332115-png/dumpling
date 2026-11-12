"""uefi_source.py：從 UEFI 原始碼樹讀 edk2／edk2-nvidia 與內建 OpenSSL、Mbed TLS 的版本。
全部用測試自己組出來的假樹（只放需要的幾個檔案），不含任何產品資料。"""
import datetime
import hashlib
import json
import os
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import uefi_source as us  # noqa: E402

CLI = HERE.parent / "uefi_source.py"
C1 = "1" * 40
C2 = "2" * 40
VERSION_DAT = 'MAJOR=3\nMINOR=0\nPATCH=15\nPRE_RELEASE_TAG=\nBUILD_METADATA=\nRELEASE_DATE="3 Sep 2024"\nSHLIB_VERSION=3\n'
OPENSSLV_111 = ('# define OPENSSL_VERSION_NUMBER  0x1010117fL\n'
                '# define OPENSSL_VERSION_TEXT    "OpenSSL 1.1.1w  11 Sep 2023"\n')
GEN_HDR = '# define OPENSSL_VERSION_TEXT "OpenSSL 3.0.15 3 Sep 2024"\n'


# ---------- 假資料 ----------

def w(p, text):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    (p.write_bytes if isinstance(text, bytes) else p.write_text)(text)
    return p


def git(d, head=None, branch=None, commit=C1, tags=(), packed=None, annotated=(), origin=None):
    """d/.git：HEAD（branch 或 detached commit）、loose 輕量 tag、packed-refs、loose 附註 tag 物件。"""
    g = Path(d) / ".git"
    g.mkdir(parents=True, exist_ok=True)
    if branch:
        w(g / "HEAD", f"ref: refs/heads/{branch}\n")
        if commit:
            w(g / "refs" / "heads" / branch, commit + "\n")
    else:
        w(g / "HEAD", (head or commit) + "\n")
    for t in tags:
        w(g / "refs" / "tags" / t, commit + "\n")
    for name, target in annotated:            # loose 附註 tag：refs/tags/<name> 指到 tag 物件
        body = f"object {target}\ntype commit\ntag {name}\ntagger x <x> 0 +0000\n\nmsg\n".encode()
        raw = b"tag %d\x00" % len(body) + body
        sha = hashlib.sha1(raw).hexdigest()
        w(g / "objects" / sha[:2] / sha[2:], zlib.compress(raw))
        w(g / "refs" / "tags" / name, sha + "\n")
    if packed is not None:
        w(g / "packed-refs", packed)
    if origin:
        w(g / "config", f'[core]\n\tbare = false\n[remote "origin"]\n\turl = {origin}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n')
    return g


def edk2(d, openssl="3", mbedtls=None, gen=True, gitmodules=True):
    d = Path(d)
    (d / "MdePkg").mkdir(parents=True, exist_ok=True)
    w(d / "MdePkg" / "MdePkg.dec", "[Defines]\n")
    ossl = d / us.OPENSSL_SUB
    if gitmodules:
        mods = [us.OPENSSL_SUB] + ([us.MBEDTLS_SUB] if mbedtls is not None else []) + ["MdePkg/Library/BaseFdtLib/libfdt"]
        w(d / ".gitmodules", "".join(f'[submodule "{m}"]\n\tpath = {m}\n\turl = https://example.invalid/x\n' for m in mods))
    if openssl == "3":
        w(ossl / "VERSION.dat", VERSION_DAT)
        w(ossl / "include" / "openssl" / "opensslv.h.in", "/* template */\n")
    elif openssl == "1.1":
        w(ossl / "include" / "openssl" / "opensslv.h", OPENSSLV_111)
    elif openssl == "empty":
        ossl.mkdir(parents=True, exist_ok=True)
    if gen:
        w(d / us.OPENSSL_GEN / "include" / "openssl" / "opensslv.h", GEN_HDR)
    if mbedtls == "empty":
        (d / us.MBEDTLS_SUB).mkdir(parents=True, exist_ok=True)
    elif mbedtls:
        w(d / us.MBEDTLS_SUB / "include" / "mbedtls" / "build_info.h", f'#define MBEDTLS_VERSION_STRING         "{mbedtls}"\n')
    return d


def run(tree, out, *extra, env=None):
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(tree), "--out", str(out), *map(str, extra)],
                       capture_output=True, text=True, env={**os.environ, **(env or {})})
    lines = r.stdout.splitlines()
    assert len(lines) == 1, r
    stage, st, detail = lines[0].split("\t")
    assert stage == "X-uefi-source"
    rep = json.loads((Path(out) / "uefi-source.json").read_text(encoding="utf-8")) if (Path(out) / "uefi-source.json").exists() else None
    bom = json.loads((Path(out) / "uefi-source.cdx.json").read_text(encoding="utf-8")) if rep else None
    return r.returncode, st, detail, rep, bom


def comp(rep, kind, role=None):
    xs = [c for c in rep["components"] if c["kind"] == kind and (role is None or c["role"] == role)]
    assert len(xs) == 1, [c["path"] for c in xs]
    return xs[0]


def bcomp(bom, name):
    xs = [c for c in bom["components"] if c["name"] == name]
    assert len(xs) == 1
    return xs[0]


# ---------- OpenSSL 3.x／1.1.x ----------

def test_openssl3_and_upstream_edk2_tag(tmp_path):
    t = edk2(tmp_path / "t", openssl="3", mbedtls="3.3.0")
    git(t, branch="main", tags=["edk2-stable202411"], origin="https://user:secret@github.com/tianocore/edk2.git")
    rc, st, detail, rep, bom = run(t, tmp_path / "o")
    assert (rc, st) == (0, "OK"), detail
    e = comp(rep, "edk2")
    assert e["version"] == "edk2-stable202411" and e["cpe"] == "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:*"
    assert e["version_basis"] == "git tag at HEAD"
    o = comp(rep, "openssl")
    assert o["version"] == "3.0.15" and o["version_basis"] == "VERSION.dat"
    assert o["cpe"] == "cpe:2.3:a:openssl:openssl:3.0.15:*:*:*:*:*:*:*" and o["purl"] == "pkg:generic/openssl@3.0.15"
    m = comp(rep, "mbedtls")
    assert m["cpe"] == "cpe:2.3:a:arm:mbed_tls:3.3.0:*:*:*:*:*:*:*" and m["purl"] == "pkg:generic/mbedtls@3.3.0"
    b = bcomp(bom, "openssl")
    assert b["type"] == "library" and b["version"] == "3.0.15" and b["cpe"].startswith("cpe:2.3:a:openssl:openssl:3.0.15")
    eb = bcomp(bom, "edk2")
    assert eb["type"] == "firmware" and eb["externalReferences"][0]["url"] == "https://github.com/tianocore/edk2.git"
    assert "secret" not in (tmp_path / "o" / "uefi-source.cdx.json").read_text() + (tmp_path / "o" / "uefi-source.json").read_text()
    dep = next(d for d in bom["dependencies"] if d["ref"] == eb["bom-ref"])
    assert sorted(dep["dependsOn"]) == sorted([bcomp(bom, "openssl")["bom-ref"], bcomp(bom, "mbedtls")["bom-ref"]])
    # OpensslGen 的標頭不是另一份 OpenSSL
    assert len([c for c in rep["components"] if c["kind"] == "openssl"]) == 1
    assert rep["other_submodules_not_covered"] == ["MdePkg/Library/BaseFdtLib/libfdt"]


def test_openssl111_from_opensslv_h(tmp_path):
    t = edk2(tmp_path / "t", openssl="1.1", gen=False)
    git(t, commit=C1, tags=["edk2-stable202208"])
    rc, st, detail, rep, bom = run(t, tmp_path / "o")
    assert st == "OK", detail
    o = comp(rep, "openssl")
    assert o["version"] == "1.1.1w" and o["cpe"] == "cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"
    assert "OPENSSL_VERSION_TEXT" in o["version_basis"]
    assert comp(rep, "edk2")["cpe"] == "cpe:2.3:a:tianocore:edk2:202208:*:*:*:*:*:*:*"


def test_openssl_number_decoding_and_conflict(tmp_path):
    assert us.openssl_number(0x1010117F) == ("1.1.1w", "release")
    assert us.openssl_number(0x101010B0) == ("1.1.1k", "dev")
    assert us.openssl_number(0x100020BF)[0] == "1.0.2k"
    assert us.openssl_number(0x0090822F)[0] == "0.9.8zh"
    assert us.openssl_number(0x300000F0) == ("3.0.15", "unknown")       # L13：3.x 是 0xMNN00PP0
    # M7（e14）：TEXT 1.1.1w、NUMBER 1.1.1c → 不挑一個：沒有版本、沒有 CPE、GAP，兩個值都寫出來
    t = edk2(tmp_path / "t", openssl=None, gen=False)
    w(t / us.OPENSSL_SUB / "include/openssl/opensslv.h", OPENSSLV_111.replace("0x1010117fL", "0x1010103fL"))
    git(t, tags=["edk2-stable202208"])
    rc, st, detail, rep, bom = run(t, tmp_path / "o")
    o = comp(rep, "openssl")
    assert st == "GAP" and o["version"] is None and o["cpe"] is None and "cpe" not in bcomp(bom, "openssl")
    assert any("1.1.1w" in g and "1.1.1c" in g and "互相矛盾" in g for g in o["gaps"])
    # VERSION.dat 與產生的 opensslv.h 不同、Mbed TLS 兩個標頭不同 → 一樣 GAP
    t2 = edk2(tmp_path / "t2", openssl="3", gen=False, mbedtls="3.3.0")
    w(t2 / us.OPENSSL_SUB / "include/openssl/opensslv.h", GEN_HDR.replace("3.0.15", "3.0.14"))
    w(t2 / us.MBEDTLS_SUB / "include/mbedtls/version.h", '#define MBEDTLS_VERSION_STRING "3.2.0"\n')
    git(t2, tags=["edk2-stable202411"])
    _, st, _, rep, _ = run(t2, tmp_path / "o2")
    assert st == "GAP" and comp(rep, "openssl")["version"] is None and comp(rep, "mbedtls")["version"] is None


def test_openssl_version_file_variants(tmp_path):
    """e10：全形數字、底線不算數字；3.x 只有 NUMBER 時不知道是不是預發行 → 不給 CPE；3.x 的 TEXT 與 NUMBER 一致。"""
    D = 'MAJOR=3\nMINOR=0\nPATCH={p}\nPRE_RELEASE_TAG=\nBUILD_METADATA=\n'
    tr = us.Tree(str(tmp_path))
    for name, files, want in (
            ("crlf", {"VERSION.dat": D.format(p=15).replace("\n", "\r\n")}, "3.0.15"),
            ("underscore", {"VERSION.dat": D.format(p="1_5")}, None),
            ("fullwidth", {"VERSION.dat": D.format(p="１５")}, None),
            ("textnum3", {"include/openssl/opensslv.h": '# define OPENSSL_VERSION_NUMBER 0x300000f0L\n'
                                                       '# define OPENSSL_VERSION_TEXT "OpenSSL 3.0.15 3 Sep 2024"\n'}, "3.0.15")):
        for f, text in files.items():
            w(tmp_path / name / f, text)
        r = us.read_openssl(tr, name)
        assert r["version"] == want and r["conflict"] is None, (name, r)
    w(tmp_path / "numonly3" / "include/openssl/opensslv.h", "# define OPENSSL_VERSION_NUMBER 0x300000f0L\n")
    r = us.read_openssl(tr, "numonly3")
    assert r["version"] == "3.0.15" and r["prerelease"].startswith("unknown")
    t = edk2(tmp_path / "t", openssl=None, gen=False)
    w(t / us.OPENSSL_SUB / "include/openssl/opensslv.h", "# define OPENSSL_VERSION_NUMBER 0x300000f0L\n")
    git(t, tags=["edk2-stable202411"])
    _, st, _, rep, _ = run(t, tmp_path / "o")
    assert st == "GAP" and comp(rep, "openssl")["cpe"] is None


def test_openssl_fips_header_uses_plain_text(tmp_path):
    t = edk2(tmp_path / "t", openssl=None, gen=False)
    w(t / us.OPENSSL_SUB / "include/openssl/opensslv.h",
      '# ifdef OPENSSL_FIPS\n#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2u-fips  20 Dec 2019"\n# else\n'
      '#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2u  20 Dec 2019"\n# endif\n')
    git(t, tags=["edk2-stable202208"])
    _, st, detail, rep, _ = run(t, tmp_path / "o")
    assert comp(rep, "openssl")["version"] == "1.0.2u" and comp(rep, "openssl")["cpe"]


def test_openssl_dev_version_has_no_cpe(tmp_path):
    t = edk2(tmp_path / "t", openssl=None, gen=False)
    w(t / us.OPENSSL_SUB / "VERSION.dat", VERSION_DAT.replace("PATCH=15", "PATCH=16").replace("PRE_RELEASE_TAG=", "PRE_RELEASE_TAG=dev"))
    git(t, tags=["edk2-stable202411"])
    rc, st, detail, rep, bom = run(t, tmp_path / "o")
    o = comp(rep, "openssl")
    assert st == "GAP" and o["version"] == "3.0.16-dev" and o["cpe"] is None and "不是正式發行版" in detail
    assert "cpe" not in bcomp(bom, "openssl") and bcomp(bom, "openssl")["version"] == "3.0.16-dev"


# ---------- GAP ----------

def test_empty_submodule_is_gap_not_inferred(tmp_path):
    t = edk2(tmp_path / "t", openssl="empty", mbedtls="empty")
    git(t, tags=["edk2-stable202411"])
    rc, st, detail, rep, bom = run(t, tmp_path / "o")
    assert (rc, st) == (2, "GAP")
    o = comp(rep, "openssl")
    assert o["version"] is None and o["cpe"] is None and o["state"] == "empty"
    assert any("沒有取出" in g and "不從 edk2 版本推" in g for g in o["gaps"])
    assert any("OpensslGen" in n and "沒有拿來當版本" in n for n in o["notes"])
    assert comp(rep, "mbedtls")["state"] == "empty"
    b = bcomp(bom, "openssl")
    assert "version" not in b and "cpe" not in b and b["purl"] == "pkg:generic/openssl"
    assert any(p["name"] == "sca-center:gap" for p in b["properties"])


def test_declared_submodule_missing_dir_is_gap(tmp_path):
    t = edk2(tmp_path / "t", openssl=None, gen=False)
    git(t, tags=["edk2-stable202411"])
    _, st, _, rep, _ = run(t, tmp_path / "o")
    assert st == "GAP" and comp(rep, "openssl")["state"] == "missing"


def test_branch_only_is_gap(tmp_path):
    t = edk2(tmp_path / "t")
    git(t, branch="main", commit=None)          # 只有 branch 名稱，沒有歷史
    rc, st, detail, rep, bom = run(t, tmp_path / "o")
    e = comp(rep, "edk2")
    assert st == "GAP" and e["version"] is None and e["cpe"] is None
    assert any("只有 branch 名稱 main" in g for g in e["gaps"])
    assert "version" not in bcomp(bom, "edk2")


def test_commit_without_tag_is_gap(tmp_path):
    t = edk2(tmp_path / "t")
    git(t, branch="main", tags=[])
    _, st, detail, rep, _ = run(t, tmp_path / "o")
    e = comp(rep, "edk2")
    assert st == "GAP" and e["version"] is None and e["commit"] == C1 and "沒有對到任何 tag" in detail


def test_manifest_branch_only_is_gap(tmp_path):
    t = tmp_path / "ws"
    edk2(t / "edk2")
    (t / "edk2-nvidia").mkdir()
    man = w(tmp_path / "m.xml", MANIFEST.format(combo="r36.4.3-updates"))
    _, st, detail, rep, _ = run(t, tmp_path / "o", "--manifest", man)
    assert st == "GAP"
    assert any("只有 branch 名稱 r36.4.3-updates" in g for g in comp(rep, "edk2-nvidia")["gaps"])


# ---------- tag 讀法 ----------

def test_annotated_tags_packed_and_loose(tmp_path):
    t = edk2(tmp_path / "t")
    git(t, commit=C1, packed=f"# pack-refs with: peeled fully-peeled sorted\n{'a' * 40} refs/tags/edk2-stable202405\n^{C1}\n"
                             f"{C2} refs/tags/other\n")
    _, st, _, rep, _ = run(t, tmp_path / "o")
    assert comp(rep, "edk2")["version"] == "edk2-stable202405"
    t2 = edk2(tmp_path / "t2")
    git(t2, commit=C1, annotated=[("edk2-stable202502", C1), ("edk2-stable202411", C2)])
    _, st, _, rep, _ = run(t2, tmp_path / "o2")
    e = comp(rep, "edk2")
    assert e["version"] == "edk2-stable202502" and e["cpe"].split(":")[5] == "202502"


def test_unpeelable_annotated_tag_is_gap(tmp_path):
    t = edk2(tmp_path / "t")
    git(t, commit=C1)
    w(t / ".git" / "refs" / "tags" / "edk2-stable202405", "b" * 40 + "\n")     # 物件不在 loose（在 pack 檔）
    _, st, detail, rep, _ = run(t, tmp_path / "o")
    assert st == "GAP" and "附註 tag 在 pack 檔" in detail and comp(rep, "edk2")["version"] is None


def test_gitdir_outside_tree_not_read(tmp_path):
    outside = tmp_path / "outside"
    git(outside, tags=["edk2-stable202411"])
    t = edk2(tmp_path / "t")
    w(t / ".git", f"gitdir: {outside / '.git'}\n")
    _, st, detail, rep, _ = run(t, tmp_path / "o")
    e = comp(rep, "edk2")
    assert st == "GAP" and e["version"] is None
    assert any("gitdir 指到樹外" in x["value"] for x in e["evidence"])


def test_fork_tag_has_no_edk2_cpe(tmp_path):
    t = edk2(tmp_path / "t")
    git(t, tags=["r35.2.1-edk2-stable202208"])
    _, st, detail, rep, bom = run(t, tmp_path / "o")
    e = comp(rep, "edk2")
    assert st == "GAP" and e["version"] == "r35.2.1-edk2-stable202208" and e["cpe"] is None
    assert e["upstream_base"] == "edk2-stable202208" and "NVD" in e["cpe_note"]
    assert "cpe" not in bcomp(bom, "edk2")


# ---------- manifest ----------

MANIFEST = """<?xml version="1.0" encoding="UTF-8"?>
<Manifest>
  <GeneralConfig><DefaultCombo combination="main" /><CurrentClonedCombo combination="{combo}" /></GeneralConfig>
  <RemoteList>
    <Remote name="Edk2Repo">https://example.invalid/edk2.git</Remote>
    <Remote name="NvRepo">https://example.invalid/edk2-nvidia.git</Remote>
  </RemoteList>
  <CombinationList>
    <Combination name="main"><Source localRoot="edk2" remote="Edk2Repo" branch="main" /></Combination>
    <Combination name="r36.4.0">
      <Source localRoot="edk2" remote="Edk2Repo" tag="r36.4.0" enableSubmodule="true" />
      <Source localRoot="edk2-nvidia" remote="NvRepo" tag="r36.4.0"/>
    </Combination>
    <Combination name="r36.4.3-updates">
      <Source localRoot="edk2" remote="Edk2Repo" branch="r36.4.3-updates" enableSubmodule="true" />
      <Source localRoot="edk2-nvidia" remote="NvRepo" branch="r36.4.3-updates"/>
    </Combination>
  </CombinationList>
</Manifest>
"""


def test_edkrepo_manifest_without_git(tmp_path):
    t = tmp_path / "ws"
    edk2(t / "edk2")
    (t / "edk2-nvidia").mkdir()
    man = w(tmp_path / "m.xml", MANIFEST.format(combo="r36.4.0"))
    _, st, detail, rep, bom = run(t, tmp_path / "o", "--manifest", man)
    nv = comp(rep, "edk2-nvidia")
    assert nv["version"] == "r36.4.0" and nv["version_basis"].startswith("manifest tag")
    assert any("沒有核對" in a for a in nv["attention"])
    assert rep["manifest"]["combination_basis"] == "CurrentClonedCombo"
    assert bcomp(bom, "edk2-nvidia")["externalReferences"][0]["url"] == "https://example.invalid/edk2-nvidia.git"
    # --combination 覆寫
    _, _, _, rep2, _ = run(t, tmp_path / "o2", "--manifest", man, "--combination", "main")
    assert any("只有 branch 名稱 main" in g for g in comp(rep2, "edk2")["gaps"])


def test_manifest_disagrees_with_git(tmp_path):
    t = tmp_path / "ws"
    edk2(t / "edk2")
    git(t / "edk2", tags=["r36.4.3"])
    man = w(tmp_path / "m.xml", MANIFEST.format(combo="r36.4.0"))
    _, st, detail, rep, _ = run(t, tmp_path / "o", "--manifest", man)
    e = comp(rep, "edk2")
    # 不一致 → GAP、版本不明（保守）；兩邊的值都並列在 evidence
    assert st == "GAP" and e["version"] is None and e["cpe"] is None
    assert any("manifest 的 tag r36.4.0" in g for g in e["gaps"])
    srcs = {(x["source"], x["value"]) for x in e["evidence"]}
    assert ("git", "r36.4.3") in srcs and ("manifest", "r36.4.0") in srcs
    # commit 不一致也是 GAP
    t2 = tmp_path / "ws2"
    edk2(t2 / "edk2")
    git(t2 / "edk2", tags=["edk2-stable202411"])
    man2 = w(tmp_path / "m2.xml", MANIFEST.format(combo="x").replace("<CombinationList>",
             f'<CombinationList><Combination name="x"><Source localRoot="edk2" remote="Edk2Repo" commit="{C2}"/></Combination>'))
    _, st, _, rep, _ = run(t2, tmp_path / "o2", "--manifest", man2)
    assert st == "GAP" and comp(rep, "edk2")["version"] is None
    # manifest 的 tag 也指到 HEAD → 用它（basis 寫明已核對）
    man3 = w(tmp_path / "m3.xml", MANIFEST.format(combo="x").replace("<CombinationList>",
             '<CombinationList><Combination name="x"><Source localRoot="edk2" remote="Edk2Repo" tag="edk2-stable202411"/></Combination>'))
    _, st, _, rep, _ = run(t2, tmp_path / "o3", "--manifest", man3)
    e = comp(rep, "edk2")
    assert e["version"] == "edk2-stable202411" and e["version_basis"].startswith("manifest tag confirmed")


def test_repo_manifest_revisions(tmp_path):
    t = tmp_path / "ws"
    edk2(t / "edk2")
    (t / "edk2-nvidia").mkdir()
    man = w(tmp_path / "default.xml", """<manifest>
  <remote name="o" fetch="https://example.invalid" /><default remote="o" revision="main" />
  <project name="edk2" path="edk2" revision="refs/tags/edk2-stable202411" />
  <project name="edk2-nvidia" revision="r36.4.3" />
</manifest>""")
    _, st, detail, rep, _ = run(t, tmp_path / "o", "--manifest", man)
    assert comp(rep, "edk2")["version"] == "edk2-stable202411" and comp(rep, "edk2")["cpe"]
    nv = comp(rep, "edk2-nvidia")
    assert nv["version"] is None and any("分不出 branch 或 tag" in g for g in nv["gaps"])


def test_manifest_with_entities_is_rejected(tmp_path):
    t = edk2(tmp_path / "t")
    git(t, tags=["edk2-stable202411"])
    man = w(tmp_path / "m.xml", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><Manifest>&a;</Manifest>')
    _, st, detail, rep, _ = run(t, tmp_path / "o", "--manifest", man)
    assert st == "GAP" and "DOCTYPE" in rep["manifest"]["error"]
    w(tmp_path / "west.yml", "manifest:\n  projects: []\n")
    _, st, _, rep, _ = run(t, tmp_path / "o2", "--manifest", tmp_path / "west.yml")
    assert "west" in rep["manifest"]["error"]


# ---------- 不可信輸入 ----------

def test_symlink_escaping_tree_is_refused(tmp_path):
    secret = w(tmp_path / "outside" / "VERSION.dat", VERSION_DAT)
    t = edk2(tmp_path / "t", openssl=None, gen=False)
    (t / us.OPENSSL_SUB).mkdir(parents=True)
    (t / us.OPENSSL_SUB / "include" / "openssl").mkdir(parents=True)
    os.symlink(secret, t / us.OPENSSL_SUB / "VERSION.dat")
    git(t, tags=["edk2-stable202411"])
    _, st, detail, rep, _ = run(t, tmp_path / "o")
    o = comp(rep, "openssl")
    assert st == "GAP" and o["version"] is None
    assert any(x["path"].endswith("VERSION.dat") for x in rep["walk"]["refused"])
    # 整個 submodule 資料夾是指到樹外的連結
    t2 = edk2(tmp_path / "t2", openssl=None, gen=False)
    (t2 / us.OPENSSL_SUB).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(secret.parent, t2 / us.OPENSSL_SUB)
    git(t2, tags=["edk2-stable202411"])
    _, st, detail, rep, _ = run(t2, tmp_path / "o2")
    o = comp(rep, "openssl")
    assert st == "GAP" and o["state"] == "escape" and o["version"] is None
    # 樹內的連結可以讀
    t3 = edk2(tmp_path / "t3", openssl=None, gen=False)
    w(t3 / "real" / "VERSION.dat", VERSION_DAT)
    (t3 / us.OPENSSL_SUB / "include" / "openssl").mkdir(parents=True)
    os.symlink(t3 / "real" / "VERSION.dat", t3 / us.OPENSSL_SUB / "VERSION.dat")
    git(t3, tags=["edk2-stable202411"])
    _, st, _, rep, _ = run(t3, tmp_path / "o3")
    assert comp(rep, "openssl")["version"] == "3.0.15"


def test_oversized_file_not_read(tmp_path):
    t = edk2(tmp_path / "t", openssl=None, gen=False)
    w(t / us.OPENSSL_SUB / "VERSION.dat", VERSION_DAT + "#" * (us.MAX_SMALL + 10))
    git(t, tags=["edk2-stable202411"])
    _, st, detail, rep, _ = run(t, tmp_path / "o")
    assert st == "GAP" and comp(rep, "openssl")["version"] is None
    assert rep["walk"]["too_large_count"] >= 1 and any("過大" in n for n in comp(rep, "openssl")["notes"])


def test_walk_limits_make_gap(tmp_path, monkeypatch):
    t = edk2(tmp_path / "t")
    git(t, tags=["edk2-stable202411"])
    monkeypatch.setattr(us, "MAX_ENTRIES", 3)
    rep = us.analyse(str(t))
    assert rep["status"] == "GAP" and rep["walk"]["incomplete"] and "漏掉" in rep["detail"]


def test_other_openssl_copy_found_by_walk(tmp_path):
    t = tmp_path / "ws"
    edk2(t / "edk2")
    git(t / "edk2", tags=["edk2-stable202411"])
    w(t / "vendor" / "lib" / "openssl" / "include" / "openssl" / "opensslv.h", OPENSSLV_111)
    _, st, _, rep, bom = run(t, tmp_path / "o")
    other = comp(rep, "openssl", "other-copy")
    assert other["path"] == "vendor/lib/openssl" and other["version"] == "1.1.1w" and other["cpe"]
    assert any(p["value"] == "other-copy" for c in bom["components"] if c.get("version") == "1.1.1w" for p in c["properties"])


def test_no_edk2_is_gap(tmp_path):
    (tmp_path / "t").mkdir()
    _, st, detail, rep, _ = run(tmp_path / "t", tmp_path / "o")
    assert st == "GAP" and "找不到 edk2" in detail


def test_bad_args_exit_64_and_clear(tmp_path):
    out = tmp_path / "o"
    w(out / "uefi-source.json", "{}")
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(tmp_path), "--out", str(out), "--time-limit", "0"],
                       capture_output=True, text=True)
    assert r.returncode == 64 and r.stdout.startswith("X-uefi-source\tFAIL\t") and not (out / "uefi-source.json").exists()
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(tmp_path / "nope"), "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 1 and "\tFAIL\t" in r.stdout


# ---------- NVIDIA 公告 ----------

NOW = datetime.datetime.now(datetime.timezone.utc)


def mirror(d, fetched=None, extra=()):
    d = Path(d)
    d.mkdir(parents=True)
    w(d / "SOURCE", f"commit={'a' * 40}\nfetched_utc={(fetched or NOW).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
    idx = [{"id": "5617", "year": "2025", "title": "Security Bulletin: NVIDIA Jetson - January 2025",
            "initial_release_date": "2025-01-28T00:00:00Z", "current_release_date": "2025-01-28T00:00:00Z", "selected": True}]
    for bid, text in extra:
        idx.append({"id": bid, "year": "2026", "title": f"Security Bulletin: NVIDIA Jetson {bid}",
                    "initial_release_date": "2026-03-01T00:00:00Z", "current_release_date": "2026-03-01T00:00:00Z", "selected": True})
        w(d / "2026" / bid / f"{bid}.md", text)
    w(d / "index.json", json.dumps({"bulletins": idx}))
    return d


def table(p, reviewed=True, rows=None):
    rows = rows or [{"bulletin": "5617", "cve": "CVE-2024-0148", "line": "36", "affected_text": "All versions prior to 36.4.3",
                     "fixed_text": "36.4.3", "affected_below": "36.4.3", "fixed_in": "36.4.3", "component": "UEFI"},
                    {"bulletin": "5617", "cve": "CVE-2024-0150", "line": "35", "affected_text": "All versions prior to 35.6.1",
                     "fixed_text": "35.6.1", "affected_below": "35.6.1", "fixed_in": "35.6.1", "component": "UEFI"}]
    for r in rows:
        r.update(reviewed=reviewed, reviewed_by="tester" if reviewed else None, reviewed_at="2026-11-01" if reviewed else None)
    t = {"schema": "sca-nvidia-bulletins-table/1", "reviewed_until": "2026-11-01",
         "bulletins": [{"id": "5617", "year": "2025", "title": "Security Bulletin: NVIDIA Jetson - January 2025",
                        "current_release_date": "2025-01-28T00:00:00Z", "cves": {}}],
         "not_applicable": [], "rows": rows}
    return w(p, json.dumps(t))


def jetson_ws(d, tag):
    t = Path(d)
    edk2(t / "edk2")
    git(t / "edk2", tags=[tag])
    (t / "edk2-nvidia" / "Silicon" / "NVIDIA").mkdir(parents=True)
    git(t / "edk2-nvidia", tags=[tag], commit=C2)
    return t


def test_bulletin_hit(tmp_path):
    t = jetson_ws(tmp_path / "ws", "r36.4.0")
    _, st, detail, rep, _ = run(t, tmp_path / "o", "--bulletin-mirror", mirror(tmp_path / "m"), "--bulletin-table", table(tmp_path / "t.json"))
    b = rep["bulletins"]
    assert b["status"] == "ATTENTION" and b["jetson_linux_version"] == "36.4.0"
    assert [x["cve"] for x in b["hits"]] == ["CVE-2024-0148"]
    # 公告只列 35 的 UEFI 列：無法判定，不是不受影響
    assert any(x["cve"] == "CVE-2024-0150" and "沒有列 36" in x["reason"] for x in b["undetermined"])
    # 只列 35 的 CVE 不能出現在「已修正」或命中裡（不能被當成不受影響），只在「無法判定」
    for k in ("hits", "fixed_per_table", "fixed_unreviewed", "unreviewed_would_match"):
        assert "CVE-2024-0150" not in {x["cve"] for x in b[k]}, k
    assert "Cannot be determined" in (tmp_path / "o" / "uefi-source.md").read_text(encoding="utf-8")
    # edk2 是 fork 的 tag（沒有 CPE）→ 整體 GAP，公告的結果照樣列出
    assert st == "GAP" and "公告 ATTENTION" in detail


def test_bulletin_miss_fixed(tmp_path):
    t = jetson_ws(tmp_path / "ws", "r36.4.3")
    _, st, _, rep, _ = run(t, tmp_path / "o", "--bulletin-mirror", mirror(tmp_path / "m"), "--bulletin-table", table(tmp_path / "t.json"))
    b = rep["bulletins"]
    assert b["hits"] == [] and [x["cve"] for x in b["fixed_per_table"]] == ["CVE-2024-0148"]
    assert b["status"] == "ATTENTION"            # CVE-2024-0150 只列 35：無法判定


def test_bulletin_unreviewed_rows_not_findings(tmp_path):
    t = jetson_ws(tmp_path / "ws", "r36.4.0")
    _, _, _, rep, _ = run(t, tmp_path / "o", "--bulletin-mirror", mirror(tmp_path / "m"),
                          "--bulletin-table", table(tmp_path / "t.json", reviewed=False))
    b = rep["bulletins"]
    assert b["hits"] == [] and [x["cve"] for x in b["unreviewed_would_match"]] == ["CVE-2024-0148"]


def test_bulletin_mirror_stale_or_missing_is_gap(tmp_path):
    t = jetson_ws(tmp_path / "ws", "r36.4.3")
    old = NOW - datetime.timedelta(days=30)
    _, st, detail, rep, _ = run(t, tmp_path / "o", "--bulletin-mirror", mirror(tmp_path / "m", fetched=old),
                                "--bulletin-table", table(tmp_path / "t.json"))
    assert rep["bulletins"]["status"] == "GAP" and "過期" in rep["bulletins"]["detail"] and st == "GAP"
    _, st, _, rep, _ = run(t, tmp_path / "o2", "--bulletin-table", table(tmp_path / "t2.json"))
    assert rep["bulletins"]["status"] == "GAP" and "沒有指定" in rep["bulletins"]["detail"]
    _, st, detail, rep, _ = run(t, tmp_path / "o3", "--bulletin-mirror", tmp_path / "nope", "--bulletin-table", table(tmp_path / "t3.json"))
    assert rep["bulletins"]["status"] == "GAP" and "nope" in rep["bulletins"]["mirror"]["reason"]
    assert str(tmp_path) not in rep["bulletins"]["mirror"]["reason"] and str(tmp_path) not in detail


def test_bulletin_not_in_table_is_gap(tmp_path):
    t = jetson_ws(tmp_path / "ws", "r36.4.3")
    m = mirror(tmp_path / "m", extra=[("5800", "| CVE | x |\nUEFI boot issue\n"), ("5801", "kernel only\n")])
    _, st, _, rep, _ = run(t, tmp_path / "o", "--bulletin-mirror", m, "--bulletin-table", table(tmp_path / "t.json"))
    b = rep["bulletins"]
    assert b["status"] == "GAP"
    assert {p["id"]: p["mentions_uefi"] for p in b["pending_bulletins"]} == {"5800": True, "5801": False}


def test_bulletin_needs_jetson_tag(tmp_path):
    t = jetson_ws(tmp_path / "ws", "uefi-202512.1")
    _, st, _, rep, _ = run(t, tmp_path / "o", "--bulletin-mirror", mirror(tmp_path / "m"), "--bulletin-table", table(tmp_path / "t.json"))
    assert rep["bulletins"]["status"] == "GAP" and "無法判定" in rep["bulletins"]["detail"]
    t2 = edk2(tmp_path / "plain")
    git(t2, tags=["edk2-stable202411"])
    _, _, _, rep, _ = run(t2, tmp_path / "o2")
    assert rep["bulletins"]["status"] == "NOT_RUN"


def test_buildid_and_dsc_strings_are_reference_only(tmp_path):
    t = jetson_ws(tmp_path / "ws", "r36.4.3")
    w(t / "images" / "buildid_jetson_RELEASE.txt", "r36.4.4-gdeadbee\n")
    w(t / "edk2-nvidia" / "Platform" / "NVIDIA" / "NVIDIA.common.dsc.inc",
      'gEfiMdeModulePkgTokenSpaceGuid.PcdFirmwareVersionString|L"$(BUILDID_STRING)"\n  MbedTlsLib|CryptoPkg/Library/MbedTlsLib/MbedTlsLib.inf\n')
    _, st, _, rep, _ = run(t, tmp_path / "o")
    nv = comp(rep, "edk2-nvidia")
    assert nv["version"] == "r36.4.3"
    assert any("buildid" in a for a in nv["attention"])
    assert rep["source_strings"][0]["kind"] == "build-time macro"
    assert rep["dsc_references"]["mbedtls"] == ["edk2-nvidia/Platform/NVIDIA/NVIDIA.common.dsc.inc"]


# ---------- 輸出 ----------

def test_output_is_stable(tmp_path):
    t = jetson_ws(tmp_path / "ws", "r36.4.0")
    w(t / "edk2" / "vendorcopy" / "include" / "openssl" / "opensslv.h", OPENSSLV_111)
    m, tb = mirror(tmp_path / "m"), table(tmp_path / "t.json")
    run(t, tmp_path / "o1", "--bulletin-mirror", m, "--bulletin-table", tb)
    run(t, tmp_path / "o2", "--bulletin-mirror", m, "--bulletin-table", tb)
    for n in us.OUTPUTS:
        assert (tmp_path / "o1" / n).read_bytes() == (tmp_path / "o2" / n).read_bytes(), n
    s = (tmp_path / "o1" / "uefi-source.cdx.json").read_text()
    assert "timestamp" not in s and "serialNumber" not in s


def test_cyclonedx_schema(tmp_path):
    from test_firmware_bom import cdx_validator
    t = jetson_ws(tmp_path / "ws", "r36.4.0")
    edk2(t / "edk2", mbedtls="3.3.0")
    _, _, _, _, bom = run(t, tmp_path / "o")
    errs = list(cdx_validator().iter_errors(bom))
    assert not errs, [e.message[:200] for e in errs[:5]]
    t2 = edk2(tmp_path / "gap", openssl="empty")
    _, _, _, _, bom = run(t2, tmp_path / "o2")
    assert not list(cdx_validator().iter_errors(bom))


def test_markdown_escapes_untrusted_text(tmp_path):
    t = tmp_path / "ws"
    edk2(t / "edk2")
    man = w(tmp_path / "m.xml", MANIFEST.format(combo="r36.4.0").replace('tag="r36.4.0" enableSubmodule', 'tag="evil|&lt;script&gt;x" enableSubmodule'))
    run(t, tmp_path / "o", "--manifest", man)
    text = (tmp_path / "o" / "uefi-source.md").read_text(encoding="utf-8")
    assert "<script>" not in text and "evil\\|&lt;script&gt;x" in text


def test_several_tags_on_one_commit(tmp_path):
    """同一個 commit 有多個發行 tag（fork 在兩個發行之間沒有變）：取版本最低的並提醒；manifest 指定的 tag 也在上面時用它。"""
    t = tmp_path / "ws"
    edk2(t / "edk2")
    git(t / "edk2", tags=["r36.10", "r36.4.3", "r36.4.0", "uefi-202405.1"])
    _, st, _, rep, _ = run(t, tmp_path / "o")
    e = comp(rep, "edk2")
    assert e["version"] == "r36.4.0" and any("多個 tag" in a for a in e["attention"])
    man = w(tmp_path / "m.xml", MANIFEST.format(combo="r36.4.0").replace('tag="r36.4.0" enableSubmodule', 'tag="r36.4.3" enableSubmodule'))
    _, _, _, rep, _ = run(t, tmp_path / "o2", "--manifest", man)
    e = comp(rep, "edk2")
    assert e["version"] == "r36.4.3" and not any("多個 tag" in a for a in e["attention"])


def test_unrelated_symlink_outside_tree_is_listed_not_flagged(tmp_path):
    t = edk2(tmp_path / "t", mbedtls="3.3.0")
    git(t, tags=["edk2-stable202411"])
    (t / "EmulatorPkg").mkdir()
    os.symlink("/nonexistent/include", t / "EmulatorPkg" / "IncludeHack")
    _, st, _, rep, _ = run(t, tmp_path / "o")
    assert st == "OK" and rep["walk"]["symlinks_outside_tree"] == 1
    assert rep["walk"]["symlinks_outside_tree_examples"] == ["EmulatorPkg/IncludeHack"]



# ---------- 驗證代理的反例（e1–e14） ----------

def manifest_tag(p, tag="edk2-stable202411", commit=None):
    attr = f'commit="{commit}"' if commit else f'tag="{tag}"'
    return w(p, MANIFEST.format(combo="x").replace("<CombinationList>",
             f'<CombinationList><Combination name="x"><Source localRoot="edk2" remote="Edk2Repo" {attr}/></Combination>'))


def test_h1_manifest_tag_peeled_elsewhere_is_gap(tmp_path):
    """e1：manifest 的 tag 在 packed-refs 已 peel 到 C2、HEAD 是 C1；另有一個讀不到的無關 tag → 仍然 GAP、沒有 CPE。"""
    ws = tmp_path / "ws"
    edk2(ws / "edk2")
    git(ws / "edk2", commit=C1, packed=f"# pack-refs with: peeled fully-peeled sorted\n{'c' * 40} refs/tags/edk2-stable202411\n^{C2}\n")
    w(ws / "edk2/.git/refs/tags/unrelated", "d" * 40 + "\n")
    man = manifest_tag(tmp_path / "m.xml")
    _, st, _, rep, bom = run(ws, tmp_path / "o", "--manifest", man)
    e = comp(rep, "edk2")
    assert st == "GAP" and e["version"] is None and e["cpe"] is None and "cpe" not in bcomp(bom, "edk2")
    assert any("指到 222222222222" in g and "不一致" in g for g in e["gaps"])
    assert any("possible version" in x["kind"] for x in e["evidence"])
    # manifest 的 tag 本身指到讀不到的物件 → GAP，evidence 只寫「可能是」
    ws2 = tmp_path / "ws2"
    edk2(ws2 / "edk2")
    git(ws2 / "edk2", commit=C1)
    w(ws2 / "edk2/.git/refs/tags/edk2-stable202411", "e" * 40 + "\n")
    _, st, _, rep, _ = run(ws2, tmp_path / "o2", "--manifest", man)
    e = comp(rep, "edk2")
    assert st == "GAP" and e["version"] is None and any("讀不到" in g for g in e["gaps"])
    # manifest 的 tag 在 .git 裡沒有 → GAP
    ws3 = tmp_path / "ws3"
    edk2(ws3 / "edk2")
    git(ws3 / "edk2", commit=C1, tags=["other"])
    _, st, _, rep, _ = run(ws3, tmp_path / "o3", "--manifest", man)
    assert st == "GAP" and comp(rep, "edk2")["version"] is None


def test_m4_git_present_but_no_commit_is_gap(tmp_path):
    """e9：.git 存在但讀不到 HEAD 的 commit（gitdir 在樹外、branch 的 ref 不存在）＋ manifest 的 tag → GAP，不給 CPE。"""
    man = manifest_tag(tmp_path / "m.xml")
    outside = tmp_path / "outside"
    git(outside, commit=C2)
    ws = tmp_path / "wsa"
    edk2(ws / "edk2")
    w(ws / "edk2/.git", f"gitdir: {outside / '.git'}\n")
    _, st, _, rep, _ = run(ws, tmp_path / "oa", "--manifest", man)
    e = comp(rep, "edk2")
    assert st == "GAP" and e["version"] is None and e["cpe"] is None and any("gitdir 指到樹外" in g for g in e["gaps"])
    ws = tmp_path / "wsb"
    edk2(ws / "edk2")
    git(ws / "edk2", branch="main", commit=None)
    _, st, _, rep, _ = run(ws, tmp_path / "ob", "--manifest", man)
    e = comp(rep, "edk2")
    assert st == "GAP" and e["version"] is None and any("只有 branch 名稱 main" in g for g in e["gaps"])


def test_m2_unreviewed_fixed_rows_are_not_ok(tmp_path):
    """e2：同版本線只有未審核的 UEFI 列、判定已達修正 → 不能 OK（至少 ATTENTION），放在 fixed_unreviewed。"""
    ws = tmp_path / "ws"
    edk2(ws / "edk2", mbedtls="3.3.0")
    git(ws / "edk2", tags=["edk2-stable202411"])
    (ws / "edk2-nvidia").mkdir()
    git(ws / "edk2-nvidia", tags=["r36.4.3"], commit=C2)
    rows = [{"bulletin": "5617", "cve": "CVE-2024-0148", "line": "36", "affected_text": "All versions prior to 36.4.3",
             "fixed_text": "36.4.3", "affected_below": "36.4.3", "fixed_in": "36.4.3", "component": "UEFI"}]
    rc, st, _, rep, _ = run(ws, tmp_path / "o", "--bulletin-mirror", mirror(tmp_path / "m"),
                            "--bulletin-table", table(tmp_path / "t.json", reviewed=False, rows=rows))
    b = rep["bulletins"]
    assert (rc, st) == (2, "ATTENTION") and b["status"] == "ATTENTION"
    assert b["fixed_per_table"] == [] and [x["cve"] for x in b["fixed_unreviewed"]] == ["CVE-2024-0148"]
    assert b["same_line_unreviewed_rows"] == 1
    # 同一列審核過 → OK
    rows[0].pop("reviewed", None)
    rc, st, _, rep, _ = run(ws, tmp_path / "o2", "--bulletin-mirror", mirror(tmp_path / "m2"),
                            "--bulletin-table", table(tmp_path / "t2.json", reviewed=True, rows=rows))
    assert (rc, st) == (0, "OK") and [x["cve"] for x in rep["bulletins"]["fixed_per_table"]] == ["CVE-2024-0148"]


def test_m3_guessed_components_are_undetermined(tmp_path):
    """e3：未審核、元件是推測的列（system init／bootloader，位置 unknown／flash）→ 無法判定；推測在 rootfs 套件的只列出；
    已審核、明確不是 UEFI 的才排除。"""
    t = jetson_ws(tmp_path / "ws", "r36.4.3")
    base = {"bulletin": "5617", "line": "36", "affected_text": "prior to 36.5", "fixed_text": "36.5", "affected_below": "36.5", "fixed_in": "36.5"}
    rows = [dict(base, cve="CVE-2026-24148", component="system init", where_it_lives="unknown"),
            dict(base, cve="CVE-2026-24149", component="bootloader", where_it_lives="flash"),
            dict(base, cve="CVE-2026-24154", component="initrd", where_it_lives="nvidia-l4t-initrd")]
    tb = table(tmp_path / "t.json", reviewed=False, rows=rows)
    _, _, _, rep, _ = run(t, tmp_path / "o", "--bulletin-mirror", mirror(tmp_path / "m"), "--bulletin-table", tb)
    b = rep["bulletins"]
    assert {x["cve"] for x in b["undetermined"]} == {"CVE-2026-24148", "CVE-2026-24149"}
    assert [x["cve"] for x in b["other_components_unreviewed"]] == ["CVE-2026-24154"]
    assert b["status"] == "ATTENTION"
    rows2 = [dict(base, cve="CVE-2026-24149", component="bootloader", where_it_lives="flash")]
    _, _, _, rep, _ = run(t, tmp_path / "o2", "--bulletin-mirror", mirror(tmp_path / "m2"),
                          "--bulletin-table", table(tmp_path / "t2.json", reviewed=True, rows=rows2))
    b = rep["bulletins"]
    assert b["undetermined"] == [] and b["status"] == "OK"


def test_unreviewed_rootfs_guess_is_not_an_exclusion(tmp_path):
    """第二輪 M1（e16）：已審核的 UEFI 列已達修正、另有一列未審核、元件推測為 rootfs 套件的列 → 不可以 OK：
    元件推測沒有人看過，不能當成「與 UEFI 無關」的依據（和 nvidia_bulletins.match 的 unrev_same 一致）。"""
    t = jetson_ws(tmp_path / "ws", "r36.4.3")
    fixed = {"bulletin": "5617", "cve": "CVE-2024-0148", "line": "36", "affected_text": "All versions prior to 36.4.3",
             "fixed_text": "36.4.3", "affected_below": "36.4.3", "fixed_in": "36.4.3", "component": "UEFI"}
    for comp_, where in (("kernel", "nvidia-l4t-kernel"), ("initrd", "nvidia-l4t-initrd")):
        guess = {"bulletin": "5617", "cve": "CVE-2026-24154", "line": "36", "affected_text": "prior to 36.5", "fixed_text": "36.5",
                 "affected_below": "36.5", "fixed_in": "36.5", "component": comp_, "where_it_lives": where}
        tb = json.loads(table(tmp_path / f"t-{comp_}.json", reviewed=True, rows=[fixed]).read_text())
        tb["rows"].append(dict(guess, reviewed=False, reviewed_by=None, reviewed_at=None))
        tbp = w(tmp_path / f"t2-{comp_}.json", json.dumps(tb))
        rc, st, _, rep, _ = run(t, tmp_path / f"o-{comp_}", "--bulletin-mirror", mirror(tmp_path / f"m-{comp_}"), "--bulletin-table", tbp)
        b = rep["bulletins"]
        assert [x["cve"] for x in b["fixed_per_table"]] == ["CVE-2024-0148"]
        assert [x["cve"] for x in b["other_components_unreviewed"]] == ["CVE-2026-24154"]
        assert b["status"] == "ATTENTION" and st != "OK" and rc != 0, (comp_, rc, st, b["status"])
        assert "rootfs 套件" in b["detail"]


def test_m5_missing_submodule_without_gitmodules(tmp_path):
    """e11：沒有 .gitmodules、沒有 openssl 資料夾，但 OpensslLib/（含 OpensslGen）與 MbedTlsLib/ 存在 → missing、GAP。"""
    t = edk2(tmp_path / "t", openssl=None, gen=True, gitmodules=False)
    w(t / "CryptoPkg/Library/OpensslLib/OpensslLib.inf", "[Sources]\n")
    w(t / "CryptoPkg/Library/MbedTlsLib/MbedTlsLib.inf", "[Sources]\n")
    git(t, tags=["edk2-stable202411"])
    rc, st, _, rep, _ = run(t, tmp_path / "o")
    assert (rc, st) == (2, "GAP")
    assert comp(rep, "openssl")["state"] == "missing" and comp(rep, "mbedtls")["state"] == "missing"
    # 連 CryptoPkg/Library/OpensslLib/ 都沒有（很舊或裁過的樹）→ 沒有這個元件
    t2 = edk2(tmp_path / "t2", openssl=None, gen=False, gitmodules=False)
    git(t2, tags=["edk2-stable202411"])
    _, st, _, rep, _ = run(t2, tmp_path / "o2")
    assert st == "OK" and not [c for c in rep["components"] if c["kind"] in ("openssl", "mbedtls")]


@pytest.mark.skipif(os.geteuid() == 0, reason="root 讀得到權限 000 的資料夾")
def test_m6_unreadable_folder_is_gap(tmp_path):
    """e12：讀不到的資料夾不能靜默跳過：記數量與範例、incomplete、GAP。"""
    t = edk2(tmp_path / "t", mbedtls="3.3.0")
    git(t, tags=["edk2-stable202411"])
    w(t / "Vendor/locked/openssl/include/openssl/opensslv.h", OPENSSLV_111)
    os.chmod(t / "Vendor/locked", 0)
    try:
        _, st, _, rep, _ = run(t, tmp_path / "o")
    finally:
        os.chmod(t / "Vendor/locked", 0o755)
    assert st == "GAP" and rep["walk"]["unreadable_dirs"] == 1 and rep["walk"]["incomplete"]
    assert rep["walk"]["unreadable_dir_examples"][0].startswith("Vendor/locked")


def test_walk_depth_and_time_limits(tmp_path, monkeypatch):
    t = edk2(tmp_path / "t", mbedtls="3.3.0")
    git(t, tags=["edk2-stable202411"])
    (t / "a" / "b" / "c" / "d").mkdir(parents=True)
    monkeypatch.setattr(us, "MAX_DEPTH", 2)
    rep = us.analyse(str(t))
    assert rep["status"] == "GAP" and rep["walk"]["too_deep_dirs"] >= 1 and "深度超過 2" in rep["walk"]["incomplete"]
    monkeypatch.setattr(us, "MAX_DEPTH", 64)
    rep = us.analyse(str(t), budget=us.Budget(time_limit=1e-9))
    assert rep["status"] == "GAP" and "時間上限" in rep["walk"]["incomplete"]
    _, st, detail, _, _ = run(t, tmp_path / "o", "--time-limit", "0.000000001")
    assert st == "GAP" and "時間上限" in detail


def test_l8_non_utf8_manifest_rejected(tmp_path):
    """e4：UTF-16 的 manifest（沒有 BOM）帶 DOCTYPE／ENTITY → 不解析，實體不展開。"""
    x = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE M [<!ENTITY t "edk2-stable202411">]>'
         '<Manifest><GeneralConfig><CurrentClonedCombo combination="c"/></GeneralConfig>'
         '<CombinationList><Combination name="c"><Source localRoot="edk2" tag="&t;"/></Combination></CombinationList></Manifest>')
    p = w(tmp_path / "m.xml", x.encode("utf-16-le"))
    m = us.read_manifest(str(p), None)
    assert m["error"] and m["entries"] == {}
    p2 = w(tmp_path / "m2.xml", x.encode("utf-16"))           # 有 BOM
    assert us.read_manifest(str(p2), None)["error"]
    p3 = w(tmp_path / "m3.xml", x.replace("UTF-16", "ISO-8859-1").encode("latin-1"))
    assert "UTF-8" in us.read_manifest(str(p3), None)["error"] or "DOCTYPE" in us.read_manifest(str(p3), None)["error"]
    ok = w(tmp_path / "ok.xml", x.replace(' encoding="UTF-16"', "").replace('<!DOCTYPE M [<!ENTITY t "edk2-stable202411">]>', "")
           .replace("&t;", "edk2-stable202411").encode())
    assert us.read_manifest(str(ok), None)["entries"]["edk2"]["tag"] == "edk2-stable202411"


def test_l9_non_utf8_file_names(tmp_path):
    """e6：檔名不是 UTF-8 → 不 FAIL、不留 .tmp；路徑以 \\xff 形式寫出。"""
    t = edk2(tmp_path / "t", mbedtls="3.3.0")
    git(t, tags=["edk2-stable202411"])
    os.symlink("/nonexistent", os.fsencode(t) + b"/link\xff")
    d = os.fsencode(t) + b"/vendor\xfe/openssl/include/openssl"
    os.makedirs(d)
    with open(d + b"/opensslv.h", "w") as f:
        f.write(OPENSSLV_111)
    rc, st, _, rep, _ = run(t, tmp_path / "o")
    assert st == "OK" and rc == 0
    assert comp(rep, "openssl", "other-copy")["path"] == "vendor\\xfe/openssl"
    assert rep["walk"]["symlinks_outside_tree_examples"] == ["link\\xff"]
    assert sorted(os.listdir(tmp_path / "o")) == sorted(us.OUTPUTS)


def test_l9_clear_removes_tmp(tmp_path):
    out = tmp_path / "o"
    for n in us.OUTPUTS:
        w(out / f".{n}.tmp", "x")
        w(out / n, "x")
    us.clear(str(out))
    assert os.listdir(out) == []


def test_l10_safe_url():
    assert us.safe_url("https://user:p@ss@host.example/x/y.git") == "https://host.example/x/y.git"
    assert us.safe_url("https://host.example/x.git?private_token=abc#frag") == "https://host.example/x.git"
    assert us.safe_url("ssh://git@host.example:2222/a/b.git") == "ssh://host.example:2222/a/b.git"
    assert us.safe_url("git@host.example:a/b.git") is None and us.safe_url("file:///etc/passwd") is None
    assert us.safe_url("https://host.example/a b") is None


def test_l11_output_has_no_absolute_paths(tmp_path):
    """兩組不同的上層資料夾、同樣的輸入 → 三個輸出與狀態行完全相同（不含絕對路徑，也不含 repo 對照表的路徑）。"""
    outs = []
    for side in ("left", "right-side"):
        base = tmp_path / side
        t = jetson_ws(base / "ws", "r36.4.0")
        man = w(base / "m.xml", MANIFEST.format(combo="r36.4.0"))
        rc, st, detail, _, _ = run(t, base / "o", "--manifest", man, "--bulletin-mirror", mirror(base / "mirror"),
                                   "--bulletin-table", table(base / "t.json"))
        outs.append((detail, [(base / "o" / n).read_bytes() for n in us.OUTPUTS]))
        for blob in outs[-1][1] + [detail.encode()]:
            assert str(tmp_path).encode() not in blob and str(us.ROOT).encode() not in blob
    assert outs[0] == outs[1]
    # 預設對照表（repo 內）寫相對路徑；鏡像過期的說明也不含完整路徑
    base = tmp_path / "third"
    t = jetson_ws(base / "ws", "r36.4.0")
    _, _, detail, rep, _ = run(t, base / "o", "--bulletin-mirror", mirror(base / "mirror", fetched=NOW - datetime.timedelta(days=30)))
    assert rep["bulletins"]["table"]["path"] == "tools/pilot/lib/nvidia-bulletins.json"
    assert str(base) not in json.dumps(rep, ensure_ascii=False) and "過期" in rep["bulletins"]["mirror"]["reason"]
    assert str(base) not in detail


def test_l12_edk2_root_state(tmp_path):
    t = edk2(tmp_path / "t")
    git(t, tags=["edk2-stable202411"])
    _, _, _, rep, _ = run(t, tmp_path / "o")
    assert comp(rep, "edk2")["state"] == "present"


def test_fifo_inputs_do_not_hang(tmp_path):
    """e13：工具會讀的位置放 FIFO → 不卡住，當成不是一般檔案。"""
    ws = jetson_ws(tmp_path / "ws", "r36.4.3")
    e = ws / "edk2"
    os.unlink(e / us.OPENSSL_SUB / "VERSION.dat")
    os.mkfifo(e / us.OPENSSL_SUB / "VERSION.dat")
    os.mkfifo(e / ".git" / "packed-refs")
    os.mkfifo(tmp_path / "man.xml")
    r = subprocess.run([sys.executable, "-I", str(CLI), "--tree", str(ws), "--out", str(tmp_path / "o"), "--manifest", str(tmp_path / "man.xml")],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "\tGAP\t" in r.stdout
