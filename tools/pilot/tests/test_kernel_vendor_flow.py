"""廠商核心（不是套件安裝的核心，例如 SoC 廠商的 BSP 核心）能完整判定所需的四件事，全部用合成資料：
A 核心 CVE 清單（Grype／DT 都沒有核心 CVE 時，依產品核心版本從 CNA 鏡像產生，或明確給 KERNEL_CVES）、
B 6.1 的 #include 的 .c 清單（來自公開上游）、C Makefile 的來源（--source-tree）、D 建置紀錄與出貨模組不一致。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import test_kernel_cna_version as tcv  # noqa: E402
import test_kernel_config as tkc  # noqa: E402

kc = tkc.kc
PILOT = tkc.PILOT
SCAN = PILOT / "sca-scan"


# ---------- B：6.1 的 included-c 清單 ----------

def test_included_c_list_for_6_1_is_from_public_upstream():
    doc = json.loads((PILOT / "lib" / "data" / "kernel-included-c-6.1.json").read_text(encoding="utf-8"))
    assert doc["schema"] == kc.INCLUDED_C_SCHEMA and doc["kernel"] == "6.1" and doc["files"]
    src = doc["source"]
    assert src["git_tag"] == "v6.1.118" and len(src["git_commit"]) == 40 and src["type"] == "directory"
    assert "vendor" in doc["note"] and "public upstream" in doc["note"]
    assert "6.1" in kc.included_c_versions() and "6.8" in kc.included_c_versions()
    assert "6.1 and 6.8" in kc.LIMITATIONS[0] and "vendor-added #include" in kc.LIMITATIONS[0]
    # 上游 6.1 已知的例子：sound/pci/ens1371.c 被 ens1370.c 之類 #include
    assert any(k.startswith("lib/decompress_") or k.startswith("sound/") for k in doc["files"])


def test_limitations_mention_backport_gap():
    text = " ".join(kc.LIMITATIONS)
    assert "programFiles are taken from the mainline fix" in text and "No file comparison with the stable-branch fix (backport)" in text


# ---------- A：核心版本與 CVE 清單 ----------

def sub(tmp_path, name):
    d = tmp_path / name
    d.mkdir()
    return d


def probe(tmp_path, members, *extra):
    src = tkc.write_tar(tmp_path / "p.tar", members)
    p = subprocess.run([sys.executable, "-I", str(tkc.LIB), "--probe-kernel-version", "--from", str(src), *extra],
                       capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout.strip().split("\t")


def test_probe_kernel_version(tmp_path):
    rc, got = probe(tmp_path, tkc.rootfs_members(kver="6.1.118"))
    assert rc == 0 and got == ["KERNEL-VERSION", "OK", "6.1.118"]
    # 沒有核心：什麼都沒有（一般容器映像）
    rc, got = probe(tmp_path, [("etc/passwd", b"root:x:0:0\n", None)])
    assert rc == 0 and got[:2] == ["KERNEL-VERSION", "NONE"]
    # 兩個模組資料夾：不猜
    m = tkc.rootfs_members(kver="6.1.118") + [("usr/lib/modules/6.1.120/kernel/x.ko", b"x", None)]
    rc, got = probe(tmp_path, m)
    assert got[:2] == ["KERNEL-VERSION", "GAP"] and "2 個核心模組目錄" in got[2]
    # 指定版本
    rc, got = probe(tmp_path, m, "--kernel-version", "6.1.120")
    assert got == ["KERNEL-VERSION", "OK", "6.1.120"]
    # 沒有模組資料夾，只有 Image：用版本字串；沒有版本字串 → GAP
    img = tkc.fake_image() + b"Linux version 6.1.118 (b@h) (gcc) #1 SMP\n" + b"\x00" * 16
    rc, got = probe(tmp_path, [("boot/Image", img, None)])
    assert got == ["KERNEL-VERSION", "OK", "6.1.118"]
    rc, got = probe(tmp_path, [("boot/Image", tkc.fake_image(), None)])
    assert got[:2] == ["KERNEL-VERSION", "GAP"] and "linux_banner" in got[2]
    # 模組資料夾和 Image 的版本字串不同：不是同一個核心
    m = tkc.rootfs_members(kver="6.1.118") + [("boot/Image", tkc.fake_image() + b"Linux version 6.1.99 (b@h) (gcc) #1\n" + b"\x00" * 16, None)]
    rc, got = probe(tmp_path, m)
    assert got[:2] == ["KERNEL-VERSION", "GAP"] and "不同" in got[2]


def test_probe_rejects_source_tree_and_missing_from(tmp_path):
    p = subprocess.run([sys.executable, "-I", str(tkc.LIB), "--probe-kernel-version"], capture_output=True, text=True, timeout=60)
    assert p.returncode == 3 and p.stdout.startswith("KERNEL-VERSION\tGAP")


def extract_fn(name="kernel_cve_list"):
    s = SCAN.read_text(encoding="utf-8")
    i = s.index(name + "(){")
    return s[i:s.index("\n}\n", i) + 3]


def list_harness(tmp_path, members, mirror=None, cves_file=None):
    """sca-scan 的 kernel_cve_list 函式（Grype、DT 都沒有核心 CVE 時的清單來源）單獨執行：真的 kernel_config.py／kernel_cna_version.py。"""
    src = tkc.write_tar(tmp_path / "h.tar", members)
    out = tmp_path / "out"
    (out / "scan").mkdir(parents=True)
    pybin = Path(sys.executable).parent
    script = f"""set -u
ROOT={tkc.ROOT}
OUT={out}; ST=$OUT/status.tsv
status(){{ printf '%s\\t%s\\t%s\\n' "$1" "$2" "${{3:-}}" >> "$ST"; }}
KSRC=(--from {src}); KLABEL="rootfs tar"; KCVL=; KCVO=
KERNEL_CVE_MIRROR={mirror or ''}
{'KERNEL_CVES=' + str(cves_file) if cves_file else 'KERNEL_CVES='}
KSHIP_OK=0; KSHIP=()
{extract_fn('kernel_ship_from')}
{extract_fn()}
kernel_cve_list; echo "rc=$?"; echo "KCVL=$KCVL"; echo "KCVO=$KCVO"
"""
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120, env={**os.environ, "PATH": f"{pybin}:{os.environ['PATH']}"})
    rows = {}
    if (out / "status.tsv").exists():
        for l in (out / "status.tsv").read_text(encoding="utf-8").splitlines():
            a = l.split("\t")
            rows[a[0]] = (a[1], a[2])
    vals = dict(l.split("=", 1) for l in p.stdout.splitlines() if "=" in l)
    return int(vals["rc"]), rows, vals, out, p


def test_cve_list_from_cna_version(tmp_path):
    mirror = tcv.make_mirror(tmp_path / "m")
    rc, rows, vals, out, p = list_harness(tmp_path, tkc.rootfs_members(kver="6.1.118"), mirror=mirror)
    assert rc == 0, p.stdout + p.stderr
    # 狀態列記清單的來源（CNA 版本比對；不是 Grype／DT）；CNA 只涵蓋 2024-02 起的核心團隊 CVE → GAP
    st, detail = rows["C-kernel-cve-list"]
    assert st == "GAP" and "CNA" in detail and "不是 Grype／DT" in detail and "6.1.118" in detail
    assert vals["KCVO"].startswith("kernel-cna-version") and vals["KCVL"].endswith("kernel-cve-list.txt")
    lst = Path(vals["KCVL"]).read_text().split()
    # 6.1.118：CVE-2025-38001（6.1.142 才修好）受影響；CVE-2024-50264（6.1.117 已修好）、CVE-2024-26600 不受影響；git 範圍的是 unknown
    assert "CVE-2025-38001" in lst and "CVE-2024-40000" in lst and "CVE-2024-50999" in lst
    assert "CVE-2024-50264" not in lst and "CVE-2024-26600" not in lst
    assert (out / "scan" / "kernel-cve-list.json").exists()


@pytest.mark.parametrize("kver,why", [("6.8.0-1021-tegra", "ABI"), ])
def test_cve_list_version_rejected_is_gap(tmp_path, kver, why):
    """kernel_cna_version 拒絕的版本格式（發行版 ABI）→ GAP，三列都寫，不猜；沒有清單檔。"""
    mirror = tcv.make_mirror(tmp_path / "m")
    rc, rows, vals, out, p = list_harness(tmp_path, tkc.rootfs_members(kver=kver), mirror=mirror)
    assert rc == 1, p.stdout + p.stderr
    assert {k: v[0] for k, v in rows.items()} == {"C-kernel-cve-list": "GAP", "C-kernel-config": "GAP", "C-kernel-module-map": "GAP"}
    assert not (out / "scan" / "kernel-cve-list.txt").exists() and vals["KCVL"] == ""


def test_cve_list_version_unreadable_is_gap(tmp_path):
    mirror = tcv.make_mirror(tmp_path / "m")
    m = tkc.rootfs_members(kver="6.1.118") + [("usr/lib/modules/6.1.120/kernel/x.ko", b"x", None)]
    rc, rows, vals, out, p = list_harness(tmp_path, m, mirror=mirror)
    assert rc == 1 and rows["C-kernel-cve-list"][0] == "GAP" and "不猜" in rows["C-kernel-cve-list"][1]
    assert rows["C-kernel-config"][0] == "GAP" and rows["C-kernel-module-map"][0] == "GAP"


def test_cve_list_without_source_writes_not_run_rows(tmp_path):
    """有核心、Grype／DT 沒有核心 CVE、沒有 CNA 鏡像也沒有 KERNEL_CVES：NOT_RUN 要寫狀態列（以前靜默消失）。"""
    rc, rows, vals, out, p = list_harness(tmp_path, tkc.rootfs_members(kver="6.1.118"))
    assert rc == 1
    assert {k: v[0] for k, v in rows.items()} == {"C-kernel-cve-list": "NOT_RUN", "C-kernel-config": "NOT_RUN", "C-kernel-module-map": "NOT_RUN"}
    assert "KERNEL_CVE_MIRROR" in rows["C-kernel-cve-list"][1] and "6.1.118" in rows["C-kernel-config"][1]


def test_cve_list_no_kernel_in_image_writes_nothing(tmp_path):
    """映像裡看不到核心（一般容器映像）：照舊不寫這幾列（多一列 NOT_RUN 會讓整體退出碼從 0 變 2）。"""
    rc, rows, vals, out, p = list_harness(tmp_path, [("etc/passwd", b"root:x:0:0\n", None)], mirror=tcv.make_mirror(tmp_path / "m"))
    assert rc == 2 and rows == {}


def test_cve_list_from_explicit_file(tmp_path):
    f = tmp_path / "cves.txt"
    f.write_text("# 明確給的清單\nCVE-2024-0001\nCVE-2025-0005 CVE-2024-0001\nnot a cve\n")
    rc, rows, vals, out, p = list_harness(tmp_path, tkc.rootfs_members(kver="6.1.118"), cves_file=f)
    assert rc == 0 and rows["C-kernel-cve-list"][0] == "OK" and "KERNEL_CVES" in rows["C-kernel-cve-list"][1]
    assert Path(vals["KCVL"]).read_text().split() == ["CVE-2024-0001", "CVE-2025-0005"] and vals["KCVO"].startswith("KERNEL_CVES")
    # 讀不到、沒有 CVE 編號 → GAP，三列
    f2 = tmp_path / "empty.txt"
    f2.write_text("nothing here\n")
    for bad in (f2, tmp_path / "missing.txt"):
        rc, rows, vals, out, p = list_harness(sub(tmp_path, "bad-" + bad.stem), tkc.rootfs_members(kver="6.1.118"), cves_file=bad)
        assert rc == 1 and {v[0] for v in rows.values()} == {"GAP"} and len(rows) == 3


def test_sca_scan_wiring_of_cve_list_and_source_tree():
    s = SCAN.read_text(encoding="utf-8")
    # 先照舊執行；只有 NOT_RUN（Grype、DT 都沒有核心 CVE）才找清單來源，有清單帶 --cves／--cves-origin 重跑
    assert 'kernel_config.py" "${ka[@]+"${ka[@]}"}" "${KSRC[@]}" --out "$KCF" "${KREC[@]+"${KREC[@]}"}"' in s
    assert 'if [ "$s2" = NOT_RUN ] && [ $kcl_tried = 0 ]; then' in s
    assert 'kernel_cve_list && { ka+=(--cves "$KCVL" --cves-origin "$KCVO"); continue; }' in s
    assert "NOT_RUN) rm -f \"$KCF\";;" in s
    # 同一份 --cves 也給 kernel_module_map.py（ka 是兩邊共用的）
    i = s.index('kernel_module_map.py" "${ka[@]+"${ka[@]}"}" "${KSRC[@]}"')
    assert i > s.index("kcl_tried=1")
    # 核心原始碼樹：放進 KSRC，兩個階段都收到
    assert 'KSRC+=(--source-tree "$(readlink -m -- "$KERNEL_SOURCE_DIR")")' in s
    # KERNEL_CVES 明確給的清單：和 Grype／DT 合併
    assert 'ka+=(--cves "$KCVL" --cves-origin "$KCVO")' in s and "KERNEL_CVES" in s


# ---------- A：--cves-origin ----------

def test_cves_origin_is_recorded_only_when_given(tmp_path):
    lst = tmp_path / "list.txt"
    lst.write_text("CVE-2024-0001\n")
    p, st, out = tkc.run(tmp_path, "--cves", str(lst), "--cves-origin", "kernel-cna-version（核心 6.8.12）")
    assert out["inputs"]["cves_origin"].startswith("kernel-cna-version") and st[2].startswith("CVE 清單來源：kernel-cna-version")
    p0, st0, out0 = tkc.run(sub(tmp_path, "x"), "--cves", str(lst))
    assert "cves_origin" not in out0["inputs"] and "CVE 清單來源" not in st0[2]


def test_vendor_kernel_cves_only_from_list_runs_k1(tmp_path):
    """Grype 沒有核心 CVE（廠商核心），清單經 --cves 進來：K1 照常判定（以前 NOT_RUN）。"""
    lst = tmp_path / "list.txt"
    lst.write_text("CVE-2024-0001\nCVE-2024-0002\n")
    empty = {"matches": []}
    p, st, out = tkc.run(tmp_path, "--cves", str(lst), "--cves-origin", "kernel-cna-version", grype_doc=empty)
    assert st[1] == "OK" and out["inputs"]["from_grype_matches"] == 0 and out["inputs"]["from_list"] == 2
    assert {r["cve"] for r in out["results"]} == {"CVE-2024-0001", "CVE-2024-0002"}
    # 清單也沒有 → 照舊 NOT_RUN（kernel_config.py 不寫檔；sca-scan 現在會寫狀態列）
    p, st, out = tkc.run(sub(tmp_path, "n"), grype_doc=empty)
    assert st[1] == "NOT_RUN" and out is None


# ---------- C：Makefile 來源（--source-tree） ----------

TREE_FILES = dict(tkc.TREE)
TREE_FILES["Makefile"] = ("VERSION = 6\nPATCHLEVEL = 8\nSUBLEVEL = 12\nEXTRAVERSION =\n"
                          + tkc.TREE["Makefile"].replace("VERSION = 6\n", "", 1))


def write_tree(d, files=None, config=tkc.CONFIG):
    for k, v in (files or TREE_FILES).items():
        p = d / k
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(v)
    if config is not None:
        (d / ".config").write_text(config)
    return d


def thin_rootfs(tmp_path):
    """headers 只有 .config 和一個 Makefile（廠商核心的刷機包／rootfs 的樣子）：沒有 --source-tree 就是 GAP。"""
    return tkc.write_tar(tmp_path / "thin.tar", tkc.rootfs_members(tree={"Makefile": "VERSION = 6\n"}))


def test_source_tree_supplies_makefiles(tmp_path):
    tree = write_tree(tmp_path / "tree")
    src = thin_rootfs(tmp_path)
    p, st, base = tkc.run(sub(tmp_path, "a"), src=src)
    assert st[1] == "GAP" and "Makefile" in st[2]                       # 沒有樹：headers 不完整
    p, st, out = tkc.run(tmp_path, "--source-tree", str(tree), src=src)
    assert st[1] == "OK", st
    k = out["kernel"]
    assert k["makefiles_from"] == "source-tree" and k["source_tree"]["type"] == "source-tree" and k["source_tree"]["version"] == "6.8.12"
    assert k["source_tree"]["path_label"] == "tree" and str(tree) not in json.dumps(out)           # 路徑不寫進輸出
    assert k["source_tree"]["config_compare"]["result"] == "same" and "來自核心原始碼樹 tree" in st[2]
    # 判定和「headers 本來就完整」時相同
    p, st, full = tkc.run(tmp_path, src=tkc.write_tar(tmp_path / "full.tar", tkc.rootfs_members()))
    assert [(r["cve"], r["decision"]) for r in out["results"]] == [(r["cve"], r["decision"]) for r in full["results"]]
    assert "makefiles_from" not in full["kernel"] and "source_tree" not in full["kernel"]          # 沒給時輸出不多欄位


def test_source_tree_config_differs_is_recorded_attention(tmp_path):
    tree = write_tree(tmp_path / "tree", config=tkc.CONFIG.replace("CONFIG_FOO=y", "# CONFIG_FOO is not set"))
    p, st, out = tkc.run(tmp_path, "--source-tree", str(tree), src=thin_rootfs(tmp_path))
    cc = out["kernel"]["source_tree"]["config_compare"]
    assert st[1] == "ATTENTION" and cc["result"] == "differs" and cc["differences_total"] == 1 and cc["examples"] == ["CONFIG_FOO"]
    assert "不同" in st[2]
    # 只差工具鏈 → 照舊 OK
    tree2 = write_tree(tmp_path / "tree2", config=tkc.CONFIG + "CONFIG_GCC_VERSION=130200\n")
    p, st, out = tkc.run(tmp_path, "--source-tree", str(tree2), src=thin_rootfs(tmp_path))
    assert st[1] == "OK" and out["kernel"]["source_tree"]["config_compare"]["result"] == "same_except_toolchain"
    # 樹沒有 .config → no_config，不算不同
    tree3 = write_tree(tmp_path / "tree3", config=None)
    p, st, out = tkc.run(tmp_path, "--source-tree", str(tree3), src=thin_rootfs(tmp_path))
    assert st[1] == "OK" and out["kernel"]["source_tree"]["config_compare"] == {"result": "no_config"}


def test_source_tree_version_mismatch_and_too_small_are_gap(tmp_path):
    files = dict(TREE_FILES)
    files["Makefile"] = files["Makefile"].replace("PATCHLEVEL = 8", "PATCHLEVEL = 6")
    p, st, out = tkc.run(tmp_path, "--source-tree", str(write_tree(tmp_path / "t1", files)), src=thin_rootfs(tmp_path))
    assert st[1] == "GAP" and "主.次版本不同" in st[2] and out["results"] == []
    files["Makefile"] = "# no version here\n"
    p, st, out = tkc.run(tmp_path, "--source-tree", str(write_tree(tmp_path / "t2", files)), src=thin_rootfs(tmp_path))
    assert st[1] == "GAP" and "讀不出核心版本" in st[2]
    small = {"Makefile": TREE_FILES["Makefile"], "Kbuild": "obj-y += init/\n", "init/Makefile": "obj-y := main.o\n"}
    p, st, out = tkc.run(tmp_path, "--source-tree", str(write_tree(tmp_path / "t3", small)), src=thin_rootfs(tmp_path))
    assert st[1] == "GAP" and "不像核心原始碼樹" in st[2]


def test_source_tree_is_read_only_and_links_stay_inside(tmp_path):
    """樹裡的符號連結不跟隨（連到樹外的 Makefile 不會被讀）；樹裡的檔案不會被執行或改動。"""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Makefile").write_text("obj-y += evil.o\n")
    tree = write_tree(tmp_path / "tree")
    (tree / "drivers" / "evil").mkdir()
    os.symlink(outside / "Makefile", tree / "drivers" / "evil" / "Makefile")
    os.symlink(outside, tree / "linkdir")
    before = {str(p): p.stat().st_mtime_ns for p in tree.rglob("*") if p.is_file()}
    col, base = kc.collect_tree(str(tree))
    assert ("usr", "src", "linux-tree", "drivers", "evil", "Makefile") not in col.files
    assert not any("evil" in "/".join(k) and k in col.files for k in col.files)
    p, st, out = tkc.run(tmp_path, "--source-tree", str(tree), src=thin_rootfs(tmp_path))
    assert st[1] == "OK" and out["kernel"]["source_tree"]["links_not_followed"] >= 2
    assert {str(p): p.stat().st_mtime_ns for p in tree.rglob("*") if p.is_file()} == before


def test_source_tree_argument_rules(tmp_path):
    tree = write_tree(tmp_path / "tree")
    # --source-tree 只配 --from 的映像／刷機包
    p, st, out = tkc.run(tmp_path, "--source-tree", str(tree), "--config", "x", "--makefiles-dir", str(tree), src=None)
    assert p.returncode == 3 and st[1] == "FAIL"
    p, st, out = tkc.run(tmp_path, "--source-tree", str(tmp_path / "nope"), src=thin_rootfs(tmp_path))
    assert p.returncode == 3 and "--source-tree 不是資料夾" in st[2]
    p, st, out = tkc.run(tmp_path, "--source-tree", str(tree), src=tree)       # --from 本身就是核心原始碼樹
    assert p.returncode == 3 and "已經是樹" in st[2]


def test_module_map_uses_source_tree_too(tmp_path):
    import test_kernel_module_map as tkm
    tree = write_tree(tmp_path / "tree")
    src = thin_rootfs(tmp_path)
    g = tmp_path / "grype.json"
    g.write_text(json.dumps(tkc.grype(list(tkc.RECORDS))))
    km = tmp_path / "kmap.json"
    km.write_text(json.dumps(tkc.KMAP))
    mirror = tkc.make_mirror(tmp_path / "m")
    out = tmp_path / "kmm.json"
    lib = PILOT / "lib" / "kernel_module_map.py"
    def go(*extra):
        p = subprocess.run([sys.executable, "-I", str(lib), "--grype", str(g), "--kernel-map", str(km), "--mirror", str(mirror),
                            "--from", str(src), "--out", str(out), *extra], capture_output=True, text=True, timeout=120)
        return p, p.stdout.strip().split("\t"), (json.loads(out.read_text()) if out.exists() else None)
    p, st, doc = go()
    assert st[1] == "GAP" and "Makefile" in st[2]
    p, st, doc = go("--source-tree", str(tree), "--cves-origin", "kernel-cna-version")
    assert st[1] == "OK", st
    assert doc["kernel"]["makefiles_from"] == "source-tree" and doc["inputs"]["cves_origin"] == "kernel-cna-version"
    assert doc["kernel"]["source_tree"]["config_compare"]["result"] == "same" and "核心原始碼樹" in st[2]
    assert tkm is not None


# ---------- D：建置紀錄與出貨模組不一致 ----------

EXTRA_RECORDS = dict(tkc.BR_RECORDS)
EXTRA_RECORDS.update({
    "CVE-2024-1013": ["drivers/bar/baz_main.c"],        # 樹內模組 baz（CONFIG_BAZ 沒開）的組成檔案：多出的模組 → unknown
    "CVE-2024-1014": ["drivers/bar/baz_main.c", "drivers/foo/a.c"],
})


def fake_ko_bytes(intree=False, big_endian=False, **fields):
    """最小的 ELF64（只有 .modinfo 和 .shstrtab 兩個區段）：.modinfo 是 key=value 以 NUL 結尾。"""
    import struct
    e = ">" if big_endian else "<"
    items = ([b"intree=Y"] if intree else []) + [f"{k}={v}".encode() for k, v in fields.items()]
    mi = b"\0".join(items) + b"\0"
    names = b"\0.modinfo\0.shstrtab\0"
    off_mi, off_st = 64, 64 + len(mi)
    shoff = off_st + len(names)
    hdr = bytearray(64)
    hdr[:4] = b"\x7fELF"
    hdr[4], hdr[5], hdr[6] = 2, 2 if big_endian else 1, 1
    struct.pack_into(e + "Q", hdr, 0x28, shoff)
    struct.pack_into(e + "HHH", hdr, 0x3A, 64, 3, 2)

    def sh(name, off, size):
        b = bytearray(64)
        struct.pack_into(e + "I", b, 0, name)
        struct.pack_into(e + "Q", b, 0x18, off)
        struct.pack_into(e + "Q", b, 0x20, size)
        return bytes(b)
    return bytes(hdr) + mi + names + bytes(64) + sh(1, off_mi, len(mi)) + sh(10, off_st, len(names))


def ko(name, kver=tkc.KVER, top="kernel", data=b"\x7fELF"):
    return (f"usr/lib/modules/{kver}/{top}/{name}", data, None)


def ko_in(name, **kw):
    """modinfo つきの模組（intree=…、author…）。"""
    return ko(name, data=fake_ko_bytes(**kw))


def run_extra(tmp_path, extra=(), record=None, records=EXTRA_RECORDS):
    src = tkc.br_rootfs(tmp_path, extra=list(extra), name="x.tar")
    return tkc.br_run(tmp_path, tkc.write_record_dir(tmp_path / "rec", record or tkc.record_members()), src=src, records=records)


def test_extra_in_tree_module_files_are_unknown_not_not_affected(tmp_path):
    # 基準：映像沒有多出的模組，baz_main.c 的 CVE 因為 Makefile 與紀錄都說沒編 → not_affected
    base = run_extra(sub(tmp_path, "b"))[2]
    by0 = {r["cve"]: r for r in base["results"]}
    assert by0["CVE-2024-1013"]["decision"] == "not_affected" and by0["CVE-2024-1014"]["decision"] == "not_affected"
    assert "image_modules_not_in_record" not in base["kernel"]["build_record"]
    assert "image_module_not_in_record" not in base["kernel"]["build_record"]["file_judgements"]      # 沒有多出模組：輸出不多欄位
    # 映像有 baz.ko（樹內，Makefile 的 baz-objs := baz_main.o），紀錄的 modules.order 沒有
    p, st, out = run_extra(tmp_path, [ko("drivers/bar/baz.ko")])
    br = out["kernel"]["build_record"]
    assert br["status"] == "OK" and st[1] == "OK", br
    ex = br["image_modules_not_in_record"]
    assert ex["count"] == 1 and ex["in_tree"] == 1 and ex["not_found"] == 0
    m = ex["modules"][0]
    assert m["module"] == "kernel/drivers/bar/baz.ko" and m["source"] == "in_tree" and m["object"] == "drivers/bar/baz.o"
    assert set(m["object_list"]) == {"drivers/bar/baz.o", "drivers/bar/baz_main.o"} and "建置紀錄沒有" in m["reason"]
    by = {r["cve"]: r for r in out["results"]}
    for c in ("CVE-2024-1013", "CVE-2024-1014"):
        assert by[c]["decision"] == "unknown", by[c]
    ev = by["CVE-2024-1013"]["files"][0]["evidence"]
    assert "the shipped image has this module, but the build record does not" in ev and "出貨映像有這個模組，但建置紀錄沒有" in ev
    assert br["file_judgements"]["image_module_not_in_record"] == 2
    # 其他 CVE 不受影響（含標頭檔以外的 not_affected、affected）
    assert by["CVE-2024-1001"]["decision"] == "not_affected" and by["CVE-2024-1002"]["decision"] == "affected"
    # 標頭檔：多出的模組可能 include 它 → unknown（沒有多出模組時是 not_affected）
    assert by0["CVE-2024-1003"]["decision"] == "not_affected" and by["CVE-2024-1003"]["decision"] == "unknown"
    assert "may include it" in by["CVE-2024-1003"]["files"][0]["evidence"]
    # limitations 與說明列出
    assert any("not in the record's modules.order" in l and "baz.ko" in l for l in out["limitations"])
    assert "出貨映像有 1 個模組不在建置紀錄的 modules.order" in st[2] and "樹內 1、找不到來源 0" in st[2]
    assert br["decision_changes"].get("not_affected->unknown", 0) >= 2


def test_extra_vendor_module_without_intree_is_gap_and_does_not_protect_tree_files(tmp_path):
    """分類 5：沒有 intree、名稱也對不到樹內模組 → GAP（未評估），列出 author／description／vermagic／srcversion，不做全面保護。"""
    oot = ko_in("net/vendor/oot.ko", author="Vendor Inc.", description="Vendor Wireless Driver", vermagic="6.8.12 SMP", srcversion="ABC123")
    p, st, out = run_extra(tmp_path, [oot, ko_in("drivers/bar/baz.ko", intree=True)])
    br = out["kernel"]["build_record"]
    ex = br["image_modules_not_in_record"]
    assert br["status"] == "OK" and ex["count"] == 2 and ex["in_tree"] == 1 and ex["not_found"] == 1 and ex["classes"] == {"2": 0, "3": 1, "4": 0, "5": 1}
    m = next(m for m in ex["modules"] if m["module"].endswith("oot.ko"))
    assert (m["class"], m["intree"], m["status"], m["source"]) == (5, None, "GAP", "not_found")
    assert m["modinfo"] == {"author": "Vendor Inc.", "description": "Vendor Wireless Driver", "vermagic": "6.8.12 SMP", "srcversion": "ABC123"}
    assert "not assessed" in m["reason"]
    b3 = next(x for x in ex["modules"] if x["module"].endswith("baz.ko"))
    assert (b3["class"], b3["intree"], b3["status"]) == (3, "Y", "UNKNOWN")
    assert any("class 5 (out-of-tree vendor module, not assessed, GAP) 1" in l and "can be forged" in l for l in out["limitations"])
    assert "找不到來源 1" in st[2]
    # 樹外廠商模組不保護樹內檔案；baz 的檔案 unknown
    by = {r["cve"]: r["decision"] for r in out["results"]}
    assert by["CVE-2024-1013"] == "unknown" and by["CVE-2024-1001"] == "not_affected"


def test_extra_module_classes_2_to_5(tmp_path):
    """五種情況各一個（1＝讀 modinfo）：2 intree 但 Makefile 對不到、3 intree 且對得到、4 樹外同名、5 樹外不同名。"""
    base = dict(EXTRA_RECORDS)
    cases = {
        "c2": ([ko_in("drivers/zzz/ghost.ko", intree=True)], 2),
        "c3": ([ko_in("drivers/bar/baz.ko", intree=True)], 3),
        "c4": ([ko_in("drivers/bar/baz.ko", description="forked baz")], 4),
        "c5": ([ko_in("net/vendor/oot.ko", description="vendor")], 5),
    }
    for name, (mods, want) in cases.items():
        d = sub(tmp_path, name)
        p, st, out = run_extra(d, mods, records=base)
        ex = out["kernel"]["build_record"]["image_modules_not_in_record"]
        assert ex["modules"][0]["class"] == want and ex["classes"][str(want)] == 1, (name, ex)
        by = {r["cve"]: r["decision"] for r in out["results"]}
        if want == 2:         # 全面保護：沒被紀錄證明有編的檔案都 unknown
            assert by["CVE-2024-1001"] == "unknown" and by["CVE-2024-1013"] == "unknown" and by["CVE-2024-1002"] == "affected"
            assert out["kernel"]["build_record"]["file_judgements"]["image_unsourced_module"] >= 2
        elif want in (3, 4):  # 組成物件 unknown，其他不動
            assert by["CVE-2024-1013"] == "unknown" and by["CVE-2024-1001"] == "not_affected"
        else:                 # 5：不保護
            assert by["CVE-2024-1013"] == "not_affected" and by["CVE-2024-1001"] == "not_affected"
    c4 = run_extra(sub(tmp_path, "c4b"), cases["c4"][0])[2]["kernel"]["build_record"]["image_modules_not_in_record"]["modules"][0]
    assert "same name as an in-tree module" in c4["reason"] and c4["status"] == "UNKNOWN"


def test_extra_module_unreadable_modinfo_is_conservative(tmp_path):
    """讀不到 modinfo（不是 ELF、壞掉的壓縮檔、這個 Python 沒有 zstd）→ 當成 intree：Makefile 對不到是分類 2（全面保護），對得到是分類 3。"""
    garbage = ko("drivers/zzz/ghost.ko", data=b"not an elf at all")
    zst = (f"usr/lib/modules/{tkc.KVER}/kernel/drivers/zzz/ghost2.ko.zst", b"\x28\xb5\x2f\xfd" + b"\0" * 20, None)
    broken_xz = (f"usr/lib/modules/{tkc.KVER}/kernel/drivers/zzz/ghost3.ko.xz", b"\xfd7zXZ\0broken", None)
    for i, mod in enumerate([garbage, zst, broken_xz]):
        p, st, out = run_extra(sub(tmp_path, f"u{i}"), [mod])
        m = out["kernel"]["build_record"]["image_modules_not_in_record"]["modules"][0]
        assert m["class"] == 2 and m["intree"] == "unreadable" and m["modinfo_unreadable"], m
        assert {r["cve"]: r["decision"] for r in out["results"]}["CVE-2024-1001"] == "unknown"
    p, st, out = run_extra(sub(tmp_path, "u3"), [ko("drivers/bar/baz.ko", data=b"junk")])
    assert out["kernel"]["build_record"]["image_modules_not_in_record"]["modules"][0]["class"] == 3


def test_modinfo_parser_limits_and_formats():
    ok = kc.parse_ko_modinfo(fake_ko_bytes(intree=True, author="a", description="d", vermagic="v", srcversion="s"))
    assert ok["ok"] and ok["intree"] == "Y" and ok["author"] == "a" and ok["srcversion"] == "s"
    assert kc.parse_ko_modinfo(fake_ko_bytes(big_endian=True, description="be"))["description"] == "be"
    assert kc.parse_ko_modinfo(fake_ko_bytes(description="x"))["intree"] is None
    assert not kc.parse_ko_modinfo(b"")["ok"] and not kc.parse_ko_modinfo(b"\x7fELF" + b"\0" * 100)["ok"]
    bad = bytearray(fake_ko_bytes(description="x"))
    bad[0x28:0x30] = (10 ** 12).to_bytes(8, "little")          # 區段表在檔案外
    assert not kc.parse_ko_modinfo(bytes(bad))["ok"]
    import gzip, lzma
    raw = fake_ko_bytes(intree=True)
    for ext, comp in ((".ko.gz", gzip.compress(raw)), (".ko.xz", lzma.compress(raw))):
        r = kc.read_modinfo(lambda c=comp: __import__("io").BytesIO(c), len(comp), "x" + ext)
        assert r["ok"] and r["intree"] == "Y", ext
    big = lzma.compress(raw + b"\0" * (2 << 20))
    old = kc.MAX_KO_UNPACKED
    try:
        kc.MAX_KO_UNPACKED = 1 << 20
        r = kc.read_modinfo(lambda: __import__("io").BytesIO(big), len(big), "x.ko.xz")
    finally:
        kc.MAX_KO_UNPACKED = old
    assert not r["ok"] and "limit" in r["reason"]


def test_vmod_reproduction_intree_vs_out_of_tree(tmp_path):
    """第一輪驗證的重現：Makefile 的 obj-$(CONFIG_VEN) += vmod_drv.o、vmod_drv-objs := vmod_main.o，映像多出 drivers/vendor/vmod.ko（名稱對不到）。
    intree=Y → 分類 2：vmod_main.c 的 CVE 判 unknown；沒有 intree → 分類 5：列為樹外 GAP，不全面保護。"""
    add = [(f"{tkc.HDR}/drivers/vendor/Makefile", b"obj-$(CONFIG_VEN) += vmod_drv.o\nvmod_drv-objs := vmod_main.o\n", None),
           (f"{tkc.HDR}/drivers/Makefile", (tkc.TREE["drivers/Makefile"] + "obj-y += vendor/\n").encode(), None)]
    recs = dict(EXTRA_RECORDS)
    recs["CVE-2024-1020"] = ["drivers/vendor/vmod_main.c"]
    for name, intree, want_cls, want_dec in (("v1", True, 2, "unknown"), ("v2", False, 5, "not_affected")):
        d = sub(tmp_path, name)
        p, st, out = run_extra(d, add + [ko_in("drivers/vendor/vmod.ko", intree=intree, description="Vendor driver")], records=recs)
        ex = out["kernel"]["build_record"]["image_modules_not_in_record"]
        assert ex["modules"][0]["class"] == want_cls and ex["modules"][0]["status"] == "GAP"
        assert {r["cve"]: r["decision"] for r in out["results"]}["CVE-2024-1020"] == want_dec, name


def test_extra_modules_with_mismatched_lists_still_rejected(tmp_path):
    """modules.builtin 或身分不符時照舊整份拒收（多出的模組不改變這一點）。"""
    rec = tkc.record_members(builtin=b"kernel/drivers/foo/always.ko\nkernel/drivers/foo/other.ko\n")
    p, st, out = run_extra(tmp_path, [ko("drivers/bar/baz.ko")], record=rec)
    br = out["kernel"]["build_record"]
    assert br["status"] == "GAP" and "modules.builtin differs" in br["reason"] and out["counts"]["not_affected"] > 0
    assert "image_modules_not_in_record" not in br
    rec = tkc.record_members(order=b"drivers/bar/bar.o\ndrivers/bar/other.o\n")      # modules.order 與映像不同
    p, st, out = run_extra(sub(tmp_path, "o"), [ko("drivers/bar/baz.ko")], record=rec)
    assert out["kernel"]["build_record"]["status"] == "GAP"
    # 身分（.config）不符
    rec = tkc.record_members(config=tkc.CONFIG.replace("CONFIG_FOO=y", "CONFIG_FOO=n"))
    p, st, out = run_extra(sub(tmp_path, "c"), [ko("drivers/bar/baz.ko")], record=rec)
    assert out["kernel"]["build_record"]["status"] == "GAP" and "not the configuration K1 judges with" in out["kernel"]["build_record"]["reason"]


def test_out_of_tree_modules_outside_kernel_dir_unchanged(tmp_path):
    """updates/ 等 kernel/ 以外的模組照舊（out_of_tree_modules；不算多出的模組）。"""
    p, st, out = run_extra(tmp_path, [ko("nvidia/oot.ko", top="updates")])
    br = out["kernel"]["build_record"]
    assert br["out_of_tree_modules"] == 1 and "image_modules_not_in_record" not in br


def test_confirmation_item_lists_modinfo_of_unassessed_vendor_modules():
    sys.path.insert(0, str(tkc.ROOT / "tools" / "cra"))
    import confirm_items as ci
    kcfg = {"status": "OK", "kernel": {"build_record": {"status": "OK", "image_modules_not_in_record": {
        "count": 1, "in_tree": 0, "not_found": 1, "truncated": False,
        "modules": [{"module": "kernel/net/o.ko", "source": "not_found", "class": 5, "intree": None,
                     "modinfo": {"author": "Vendor Inc.", "description": "Vendor Wireless", "vermagic": "6.1.118 SMP", "srcversion": "ABC"}}]}}}}
    e = [i for i in ci.kernel_items([{"x": 1}], None, kcfg, {"C-kernel-config": ("OK", "")}) if i["key"] == "kernel:extra-modules"][0]
    for w in ("Vendor Inc.", "Vendor Wireless", "6.1.118 SMP", "ABC", "未評估"):
        assert w in e["finding"], w


def test_confirmation_item_for_extra_modules():
    sys.path.insert(0, str(tkc.ROOT / "tools" / "cra"))
    import confirm_items as ci
    kcfg = {"status": "OK", "kernel": {"build_record": {"status": "OK", "image_modules_not_in_record": {
        "count": 2, "in_tree": 1, "not_found": 1, "truncated": False,
        "modules": [{"module": "kernel/drivers/bluetooth/x.ko", "source": "in_tree"}, {"module": "kernel/net/o.ko", "source": "not_found"}]}}}}
    its = ci.kernel_items([{"x": 1}], None, kcfg, {"C-kernel-config": ("OK", "")})
    e = [i for i in its if i["key"] == "kernel:extra-modules"]
    assert len(e) == 1 and "x.ko" in e[0]["finding"] and "o.ko" in e[0]["finding"] and e[0]["ask"] == ci.ENG
    assert "建置紀錄" in e[0]["finding"] and "來源" in e[0]["question"]
    # 沒有多出的模組：不產生
    kcfg["kernel"]["build_record"].pop("image_modules_not_in_record")
    assert not [i for i in ci.kernel_items([{"x": 1}], None, kcfg, {"C-kernel-config": ("OK", "")}) if i["key"] == "kernel:extra-modules"]
