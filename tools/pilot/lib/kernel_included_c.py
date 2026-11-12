#!/usr/bin/env python3
"""從 Linux 核心原始碼產生「會被別的檔案 #include 進去的 .c」清單（kernel_config.py 用，只用標準函式庫）。

為什麼：drivers/firmware/efi/libstub/zboot.c 會 #include lib/decompress_*.c，sound/pci/ens1371.c 會 #include "ens1370.c"。
這些檔案就算自己的 obj- 規則沒開也可能被編進核心；Makefile 看不出來，產品的 headers 套件也沒有 .c 可以查，所以事先從上游原始碼
產生清單，kernel_config.py 把清單裡的檔案一律判 unknown（不判 not_affected）。

用法：
  python3 -I tools/pilot/lib/kernel_included_c.py --source <linux-X.Y.tar.xz 或解開的資料夾> --kernel 6.8 \\
      --out tools/pilot/lib/data/kernel-included-c-6.8.json [--source-sha256 <kernel.org sha256sums.asc 的值>]
      [--source-tag <git tag> --source-commit <commit>]（來源是公開上游 git 用 git archive 取出的資料夾時）
  清單只能從公開上游產生，不可以用廠商的核心樹（那是公司資料）；廠商自己加的 #include 不在清單裡。

原始碼是不可信資料：只讀一般檔案的內容（tar 以串流方式讀，不解壓到磁碟、不跟隨連結、不執行任何東西），單一檔案上限 8 MiB。
只看 `#include "….c"`（引號；角括號的 .c 也收，依 include/ 與各架構的 include/ 解析）。tools/、scripts/、Documentation/、samples/、
usr/ 底下的檔案是使用者空間或建置工具，不算（它們 include 的 .c 不會進核心）。
"""
import argparse
import datetime
import hashlib
import json
import os
import posixpath
import re
import stat
import sys
import tarfile
from pathlib import Path

SCHEMA = "sca-center-kernel-included-c/1"
MAX_FILE = 8 << 20
SKIP_TOP = ("tools", "scripts", "Documentation", "samples", "usr")
INC_RE = re.compile(rb'^[ \t]*#[ \t]*include[ \t]*(["<])([^">\n]+\.c)[">]', re.M)
SRC_EXT = (".c", ".h", ".S")


def clean(name):
    """tar 成員或相對路徑 → 樹內路徑（去掉 linux-X.Y/ 這一層）；不合法 → None。"""
    parts = [x for x in name.split("/") if x not in ("", ".")]
    if not parts or any(x == ".." for x in parts):
        return None
    return "/".join(parts)


def scan_tar(path):
    files, incs = set(), []
    with tarfile.open(path, "r|*") as t:
        for m in t:
            n = clean(m.name)
            if n is None or "/" not in n:
                continue
            n = n.split("/", 1)[1]          # linux-6.8/…
            if not m.isreg():
                continue
            files.add(n)
            if n.endswith(SRC_EXT) and n.split("/", 1)[0] not in SKIP_TOP and m.size <= MAX_FILE:
                f = t.extractfile(m)
                if f is not None:
                    incs += [(n, q.decode(), x.decode("utf-8", "replace")) for q, x in INC_RE.findall(f.read(MAX_FILE + 1))]
    return files, incs


def scan_dir(root):
    root = Path(root)
    files, incs = set(), []
    for dp, dns, fns in os.walk(root, followlinks=False):
        rel = Path(dp).relative_to(root).as_posix()
        for fn in fns:
            p = Path(dp) / fn
            st = p.lstat()
            if not stat.S_ISREG(st.st_mode):
                continue
            n = clean((Path(rel) / fn).as_posix() if rel != "." else fn)
            if n is None:
                continue
            files.add(n)
            if n.endswith(SRC_EXT) and n.split("/", 1)[0] not in SKIP_TOP and st.st_size <= MAX_FILE:
                with open(p, "rb") as f:
                    incs += [(n, q.decode(), x.decode("utf-8", "replace")) for q, x in INC_RE.findall(f.read(MAX_FILE + 1))]
    return files, incs


def resolve(files, includer, quote, target):
    """#include 的 .c → [樹內路徑]（存在的檔案）；找不到 → []。引號先找 includer 的資料夾，再找 include 路徑，最後以路徑結尾比對。"""
    cands = []
    if quote == '"':
        cands.append(posixpath.normpath(posixpath.join(posixpath.dirname(includer), target)))
    parts = includer.split("/")
    arch = parts[1] if parts[0] == "arch" and len(parts) > 1 else None
    cands += [posixpath.normpath(posixpath.join(d, target)) for d in
              ["include", "."] + ([f"arch/{arch}/include"] if arch else [])]
    for c in cands:
        if not c.startswith("..") and c in files:
            return [c]
    # 建置時的 -I 路徑不同（arch/s390/boot 的 "../../../../lib/x.c"、powerpc boot 複製進來的 decompress_inflate.c）：
    # 去掉開頭的 ../，取路徑結尾相同的檔案（可能不只一個；多算只會讓結果偏向 unknown）
    tail = "/".join(x for x in target.split("/") if x not in ("..", "."))
    return sorted(f for f in files if (f == tail or f.endswith("/" + tail)) and f.split("/", 1)[0] not in SKIP_TOP)


def build(files, incs):
    out, unresolved = {}, set()
    for includer, quote, target in incs:
        ps = [p for p in resolve(files, includer, quote, target) if p.split("/", 1)[0] not in SKIP_TOP]
        if not ps:
            unresolved.add(f"{includer}: {target}")
        for p in ps:
            out.setdefault(p, set()).add(includer)
    return {k: sorted(v) for k, v in sorted(out.items())}, sorted(unresolved)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", required=True, help="linux-X.Y.tar.* 或解開的原始碼資料夾")
    ap.add_argument("--kernel", required=True, help="核心版本（例如 6.8）")
    ap.add_argument("--out", required=True)
    ap.add_argument("--source-sha256", help="kernel.org sha256sums.asc 記的值（有給時核對 tar 檔）")
    ap.add_argument("--source-tag", help="公開上游的 git tag（例如 v6.1.118；來源是用 git archive 取出的資料夾時，記在 source 欄）")
    ap.add_argument("--source-commit", help="上面那個 tag 的 commit（git rev-parse <tag>^{commit}）")
    a = ap.parse_args(argv)
    src = Path(a.source)
    prov = {"name": src.name}
    if src.is_file():
        h = hashlib.sha256()
        with open(src, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        prov["sha256"] = h.hexdigest()
        if a.source_sha256 and a.source_sha256.lower() != prov["sha256"]:
            print(f"FAIL\t{src.name} 的 sha256 {prov['sha256']} 和 --source-sha256 不同", file=sys.stderr)
            return 1
        prov["sha256_checked_against"] = "kernel.org sha256sums.asc (value given with --source-sha256; PGP signature not verified)" \
            if a.source_sha256 else "not checked"
        files, incs = scan_tar(src)
    elif src.is_dir():
        prov["type"] = "directory"
        if a.source_tag:
            prov["git_tag"] = a.source_tag
        if a.source_commit:
            prov["git_commit"] = a.source_commit
        files, incs = scan_dir(src)
    else:
        print(f"FAIL\t找不到 {src}", file=sys.stderr)
        return 64
    got, unresolved = build(files, incs)
    doc = {"schema": SCHEMA, "kernel": a.kernel, "source": prov,
           "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
           "generator": "tools/pilot/lib/kernel_included_c.py",
           "note": "C files #included by other kernel source files (outside tools/, scripts/, Documentation/, samples/, usr/). "
                   "kernel_config.py never judges these not_affected. Generated from the public upstream source only (the generated date is the UTC date): "
                   "#include of .c files added by a vendor are not included.",
           "files": got, "unresolved": unresolved}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"OK\t{len(got)} 個檔案會被 #include（{len(unresolved)} 個 include 找不到檔案）→ {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
