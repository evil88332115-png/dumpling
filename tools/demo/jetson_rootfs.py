"""Jetson Linux 範例根檔案系統＋BSP 的 NVIDIA 套件 → 兩個可以 docker import 的 tar（基礎版、模擬客製版）。

用法：python3 -I jetson_rootfs.py --bsp <Jetson_Linux_*.tbz2> --rootfs <Tegra_Linux_Sample-Root-Filesystem_*.tbz2>
        --work <暫存資料夾> --out-base <base.tar> --out-custom <custom.tar> --report <prep.json>

取代 apply_binaries.sh 的「把 nv_tegra/l4t_deb_packages、kernel 底下的 .deb 裝進 rootfs」這一步，但**不執行任何套件內容**：
- 下載的檔案都是不可信資料。這裡只讀 tar 與 deb（ar）的結構，不解開到主機的檔案系統，不跑 preinst／postinst，不 chroot。
- deb 的 data.tar 成員直接寫進輸出的 tar；control 的欄位加上 `Status: install ok installed` 併進 /var/lib/dpkg/status，
  另寫 /var/lib/dpkg/info/<套件>.list 與 .md5sums（Syft 用來判斷檔案屬於哪個套件）。
- 結果是近似值：apply_binaries.sh 依板子挑套件、維護者腳本會產生的檔案與設定都沒有；這裡把所有 arm64／all 的套件都放進去。
- Ubuntu 24.04 是 usrmerge（/bin、/lib… 是指向 usr/ 的連結）：deb 裡的 lib/… 改寫成 usr/lib/…，和 dpkg 跟著連結寫入的結果相同；
  rootfs 沒有這些連結時中止。
- 硬連結一律改成一般檔案（避免指向沒有寫出的成員）；路徑含 `..`、絕對路徑的成員略過並記錄。
- 模擬客製版另加一個假的客戶套件 acme-inspector（dpkg 紀錄＋/opt 底下的檔案＋一個 Python 套件的 dist-info，版本故意用舊的），
  只有中繼資料，沒有程式。用來示範「客製版多了什麼、哪些版本受某個弱點影響」。
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

DEB_DIRS = ("Linux_for_Tegra/nv_tegra/l4t_deb_packages/", "Linux_for_Tegra/kernel/")
DEB_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]*\.deb$")
USRMERGE = ("bin", "sbin", "lib", "lib32", "lib64", "libx32")
ARCHES = ("arm64", "all")
STATUS = "var/lib/dpkg/status"
SPOOL = 64 << 20
PKG_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")
ARCH_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# 模擬客製版：客戶自己的套件（假的，只有中繼資料）。Pillow 10.0.0 故意用舊版：GHSA-3f63-hfp8-52jq（CVE-2023-50447）在 10.2.0 修正。
ACME_PKG = "acme-inspector"
ACME_VER = "1.0.0"
ACME_PY = ("Pillow", "10.0.0")


def norm(name):
    """tar 成員名稱 → 不含開頭 ./ 與 / 的相對路徑；含 .. 或空的回傳 None。"""
    n = name.replace("\\", "/")
    while n.startswith("./"):
        n = n[2:]
    n = n.lstrip("/").rstrip("/")
    if n in ("", "."):
        return ""
    parts = n.split("/")
    if any(p in ("..", "") for p in parts):
        return None
    return "/".join(p for p in parts if p != ".")


def usr_rewrite(path):
    first, _, rest = path.partition("/")
    return f"usr/{first}/{rest}".rstrip("/") if first in USRMERGE else path


def ar_members(f):
    """deb（ar 格式）→ {名稱: (位移, 大小)}。大小是負的或超出檔案時丟 ValueError（避免無窮迴圈）。"""
    end = f.seek(0, 2)
    f.seek(0)
    if f.read(8) != b"!<arch>\n":
        raise ValueError("不是 ar 檔")
    out = {}
    while True:
        h = f.read(60)
        if not h:
            break
        if len(h) < 60 or h[58:60] != b"`\n":
            raise ValueError("ar 標頭損壞")
        name = h[:16].decode("ascii", "replace").strip().rstrip("/")
        size = int(h[48:58].decode("ascii").strip())
        if size < 0 or f.tell() + size > end:
            raise ValueError("ar 成員大小不合理")
        out[name] = (f.tell(), size)
        f.seek(size + (size & 1), 1)
    return out


def decompress(src, name, dst, work):
    """deb 內的 control／data tar → 解壓後寫到 dst。zstd 用 Python 3.14 的 compression.zstd，沒有時用 zstd 指令（壓縮檔先存到 work）。"""
    if name.endswith(".tar"):
        shutil.copyfileobj(src, dst)
    elif name.endswith(".tar.gz"):
        import gzip
        shutil.copyfileobj(gzip.GzipFile(fileobj=src), dst)
    elif name.endswith(".tar.xz"):
        import lzma
        shutil.copyfileobj(lzma.LZMAFile(src), dst)
    elif name.endswith(".tar.zst"):
        try:
            from compression import zstd  # Python 3.14
            shutil.copyfileobj(zstd.ZstdFile(src), dst)
        except ImportError:
            if not shutil.which("zstd"):
                raise RuntimeError(f"{name} 是 zstd 壓縮，需要 Python 3.14 或 zstd 指令")
            with tempfile.NamedTemporaryFile(dir=work, suffix=".zst") as tmp:
                shutil.copyfileobj(src, tmp)
                tmp.flush()
                with tempfile.TemporaryFile(dir=work) as err:
                    p = subprocess.Popen(["zstd", "-dc", "--", tmp.name], stdout=subprocess.PIPE, stderr=err)
                    shutil.copyfileobj(p.stdout, dst)
                    if p.wait():
                        err.seek(0)
                        raise RuntimeError(f"zstd 解壓失敗：{err.read().decode(errors='replace')[-200:]}")
    else:
        raise ValueError(f"不認得的壓縮格式：{name}")


class Slice(io.RawIOBase):
    def __init__(self, f, off, size):
        self.f, self.pos, self.end = f, off, off + size

    def readable(self):
        return True

    def readinto(self, b):
        n = min(len(b), self.end - self.pos)
        if n <= 0:
            return 0
        self.f.seek(self.pos)
        data = self.f.read(n)
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


def parse_control(text):
    """control 段落 → [(欄位, 值)]（值保留續行）。"""
    fields = []
    for line in text.splitlines():
        if line[:1] in (" ", "\t") and fields:
            fields[-1] = (fields[-1][0], fields[-1][1] + "\n" + line)
        elif ":" in line:
            k, _, v = line.partition(":")
            fields.append((k.strip(), v.strip()))
    return fields


def paragraphs(text):
    return [parse_control(p) for p in re.split(r"\n\s*\n", text) if p.strip()]


def fmt(fields):
    return "".join(f"{k}: {v}\n" if v else f"{k}:\n" for k, v in fields)


def pkey(fields):
    d = dict(fields)
    return (d.get("Package", ""), d.get("Architecture", ""))


def merge_status(base_text, added):
    """dpkg status 文字＋要加的段落 → 新的文字、(取代數, 新增數)。同名同架構的取代。"""
    paras = paragraphs(base_text)
    idx = {pkey(p): i for i, p in enumerate(paras)}
    rep = new = 0
    for p in added:
        k = pkey(p)
        if k in idx:
            paras[idx[k]] = p
            rep += 1
        else:
            idx[k] = len(paras)
            paras.append(p)
            new += 1
    return "\n".join(fmt(p) for p in paras), (rep, new)


def with_status(fields):
    out = []
    for k, v in fields:
        if k == "Status":
            continue
        out.append((k, v))
        if k == "Package":
            out.append(("Status", "install ok installed"))
    return out


class Deb:
    def __init__(self, path, work):
        self.path = path
        with open(path, "rb") as f:
            mem = ar_members(f)
            ctl = next((n for n in mem if n.startswith("control.tar")), None)
            dat = next((n for n in mem if n.startswith("data.tar")), None)
            if not ctl or not dat:
                raise ValueError("缺 control.tar 或 data.tar")
            cbuf = io.BytesIO()
            decompress(io.BufferedReader(Slice(f, *mem[ctl])), ctl, cbuf, work)
            cbuf.seek(0)
            self.control = self.md5sums = None
            with tarfile.open(fileobj=cbuf, mode="r:") as t:
                for m in t.getmembers():
                    n = norm(m.name)
                    if m.isfile() and n == "control":
                        self.control = t.extractfile(m).read().decode("utf-8", "replace")
                    elif m.isfile() and n == "md5sums":
                        self.md5sums = t.extractfile(m).read()
            if self.control is None:
                raise ValueError("control.tar 沒有 control")
            self.data_path = os.path.join(work, os.path.basename(path) + ".data.tar")
            with open(self.data_path, "wb") as out:
                decompress(io.BufferedReader(Slice(f, *mem[dat])), dat, out, work)
        self.fields = paragraphs(self.control)[0]
        d = dict(self.fields)
        self.package, self.version, self.arch = d.get("Package", ""), d.get("Version", ""), d.get("Architecture", "")
        # 名稱會用在 /var/lib/dpkg/info/<套件>.list：只接受 Debian 套件名稱與架構的字元（Debian Policy 5.6.1、5.6.8）
        if not PKG_NAME.match(self.package) or not ARCH_NAME.match(self.arch):
            raise ValueError(f"Package／Architecture 不合法：{self.package[:40]!r} {self.arch[:20]!r}")
        self.multiarch_same = d.get("Multi-Arch", "") == "same"
        self.tar = tarfile.open(self.data_path, mode="r:")
        self.members = self.tar.getmembers()

    def info_name(self):
        return f"{self.package}:{self.arch}" if self.multiarch_same else self.package


def extract_debs(bsp, work, report):
    """BSP tbz2 → work/debs/*.deb（只取 DEB_DIRS 底下的一般檔案，名稱只留安全的檔名）。"""
    d = os.path.join(work, "debs")
    os.makedirs(d, exist_ok=True)
    found = []
    with tarfile.open(bsp, mode="r|bz2") as t:
        for m in t:
            n = norm(m.name)
            if not n or not m.isfile() or not n.endswith(".deb"):
                continue
            if not any(n.startswith(p) and "/" not in n[len(p):] for p in DEB_DIRS):
                continue
            base = os.path.basename(n)
            if not DEB_NAME.match(base) or os.path.exists(os.path.join(d, base)):
                report["deb_rejected"].append(n)
                continue
            with open(os.path.join(d, base), "wb") as out:
                shutil.copyfileobj(t.extractfile(m), out)
            found.append(os.path.join(d, base))
    return sorted(found)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def add_bytes(outs, name, data, mode=0o644, mtime=0):
    ti = tarfile.TarInfo("./" + name)
    ti.size, ti.mode, ti.mtime, ti.uname, ti.gname = len(data), mode, mtime, "root", "root"
    for o in outs:
        o.addfile(ti, io.BytesIO(data))


def add_dir(outs, name, mode=0o755):
    ti = tarfile.TarInfo("./" + name)
    ti.type, ti.mode, ti.uname, ti.gname = tarfile.DIRTYPE, mode, "root", "root"
    for o in outs:
        o.addfile(ti)


def acme_overlay():
    """模擬客製版的檔案：{路徑: 內容}、dpkg 段落。"""
    note = ("模擬的客戶套件（sca-center 示範用，不是真的產品）。只有中繼資料，沒有程式。\n"
            "Simulated customer package for the sca-center demo. Metadata only, no code.\n").encode()
    py, pv = ACME_PY
    di = f"opt/{ACME_PKG}/lib/python3.12/site-packages/{py.lower()}-{pv}.dist-info"
    meta = f"Metadata-Version: 2.1\nName: {py}\nVersion: {pv}\nSummary: simulated vendored copy (demo)\nLicense: HPND\n".encode()
    files = {
        f"opt/{ACME_PKG}/README.txt": note,
        f"usr/share/doc/{ACME_PKG}/copyright": b"Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
                                               b"Files: *\nCopyright: 2026 ACME (simulated)\nLicense: LicenseRef-ACME-Proprietary\n",
        f"{di}/METADATA": meta,
        f"{di}/INSTALLER": b"pip\n",
        f"{di}/RECORD": f"{di.split('site-packages/')[1]}/METADATA,,\n".encode(),
    }
    para = [("Package", ACME_PKG), ("Status", "install ok installed"), ("Priority", "optional"), ("Section", "misc"),
            ("Installed-Size", "1"), ("Maintainer", "ACME (simulated) <noreply@example.com>"), ("Architecture", "arm64"),
            ("Version", ACME_VER), ("Depends", "python3, nvidia-l4t-core"),
            ("Description", "simulated customer application (sca-center demo, metadata only)")]
    return files, para


def build(args):
    report = {"inputs": {}, "deb_rejected": [], "deb_skipped_arch": [], "deb_errors": [], "debs": [],
              "skipped_members": [], "conflicts_between_debs": 0, "conflicts": []}
    for k in ("bsp", "rootfs"):
        p = getattr(args, k)
        report["inputs"][k] = {"file": os.path.basename(p), "sha256": sha256(p), "bytes": os.path.getsize(p)}
    work = tempfile.mkdtemp(prefix="jetson-", dir=args.work)
    ok = False
    try:
        _build(args, report, work)
        ok = True
    finally:
        shutil.rmtree(work, ignore_errors=True)   # deb 解開的 data.tar（實機數 GB）
        if not ok:
            for f in (args.out_base, args.out_custom):
                try:
                    os.remove(f)
                except OSError:
                    pass


def _build(args, report, work):
    debs = []
    for p in extract_debs(args.bsp, work, report):
        try:
            d = Deb(p, work)
        except Exception as e:  # noqa: BLE001 — 每個 deb 的錯誤都記下來，不中止
            report["deb_errors"].append(f"{os.path.basename(p)}: {e}")
            continue
        if d.arch not in ARCHES:
            report["deb_skipped_arch"].append(f"{d.package} {d.version} {d.arch}")
            d.tar.close()
            continue
        debs.append(d)
    if not debs:
        raise SystemExit("BSP 裡沒有可用的 arm64／all 套件（DEB_DIRS 底下）")

    # 每個路徑由最後一個提供它的 deb 負責（同名檔案在多個 deb 中只寫一次）
    owner, dirs, lists = {}, {}, {}
    for d in debs:
        lst = ["/."]
        for m in d.members:
            n = norm(m.name)
            if n is None:
                report["skipped_members"].append(f"{d.package}: {m.name}")
                continue
            if n == "":
                continue
            lst.append("/" + n)
            t = usr_rewrite(n)
            if m.isdir():
                dirs.setdefault(t, m)
            elif m.isfile() or m.islnk() or m.issym():
                if t in owner and owner[t][0] is not d:
                    report["conflicts_between_debs"] += 1
                    report["conflicts"].append(f"{t}：{owner[t][0].package} → {d.package}")
                owner[t] = (d, m)
            else:
                report["skipped_members"].append(f"{d.package}: {m.name}（類型 {m.type!r}）")
        lists[d] = lst
        report["debs"].append({"package": d.package, "version": d.version, "arch": d.arch,
                               "file": os.path.basename(d.path), "sha256": sha256(d.path)})

    acme_files, acme_para = acme_overlay()
    base_out = tarfile.open(args.out_base, "w", format=tarfile.PAX_FORMAT)
    cust_out = tarfile.open(args.out_custom, "w", format=tarfile.PAX_FORMAT)
    both = (base_out, cust_out)
    seen, status_text, links = set(), None, {}
    n_base = n_over = n_info = 0
    info_names = {d.info_name() for d in debs}
    with tarfile.open(args.rootfs, mode="r|bz2") as t:
        for m in t:
            n = norm(m.name)
            if n is None:
                report["skipped_members"].append(f"rootfs: {m.name}")
                continue
            if n == STATUS and m.isfile():
                status_text = t.extractfile(m).read().decode("utf-8", "replace")
                continue
            if n and "/" not in n and m.issym():
                links[n] = m.linkname
            if n in owner:
                n_over += 1
                continue
            if n.startswith("var/lib/dpkg/info/") and n[len("var/lib/dpkg/info/"):].rsplit(".", 1)[0] in info_names:
                n_info += 1          # 套件的舊紀錄（.list、.md5sums、.conffiles…）：dpkg 安裝新版時會換掉
                continue
            if n:
                seen.add(n)
            n_base += 1
            if m.isfile():
                with tempfile.SpooledTemporaryFile(SPOOL, dir=work) as sp:
                    shutil.copyfileobj(t.extractfile(m), sp)
                    for o in both:
                        sp.seek(0)
                        o.addfile(m, sp)
            elif m.islnk():
                # 硬連結指向 rootfs 自己較早的成員；目標被 deb 取代（之後才寫出）或是 dpkg status 時不寫，記錄下來
                tn = norm(m.linkname)
                if tn in owner or tn == STATUS or tn not in seen:
                    report["skipped_members"].append(f"rootfs: {m.name}（硬連結的目標被取代或不存在）")
                    continue
                for o in both:
                    o.addfile(m)
            else:
                for o in both:
                    o.addfile(m)
    if status_text is None:
        raise SystemExit(f"rootfs 沒有 {STATUS}")
    bad = [x for x in USRMERGE if x in seen and links.get(x) != f"usr/{x}"]
    if bad or "lib" not in links:
        raise SystemExit(f"rootfs 不是 usrmerge（{', '.join(bad) or 'lib 不是連結'}）：deb 路徑改寫的前提不成立")
    report["usrmerge_links"] = {k: links[k] for k in sorted(links) if k in USRMERGE}

    # 套件的資料夾（rootfs 已有的不寫）；套件沒列出的上層資料夾補上（root、755）
    for t_ in sorted({"/".join(p.split("/")[:i]) for p in owner for i in range(1, p.count("/") + 1)} - set(dirs)):
        dirs[t_] = None
    for t_, m in sorted(dirs.items()):
        if t_ in owner:            # 另一個套件把它當檔案或連結：只寫檔案，記錄下來
            report["conflicts_between_debs"] += 1
            report["conflicts"].append(f"{t_}：資料夾與檔案衝突（寫檔案）")
            continue
        if t_ in seen or t_.split("/")[0] in links:
            continue
        seen.add(t_)
        ti = tarfile.TarInfo("./" + t_)
        ti.type, ti.mode, ti.uname, ti.gname = tarfile.DIRTYPE, 0o755, "root", "root"
        if m is not None:
            ti.mode, ti.uid, ti.gid, ti.mtime = m.mode, m.uid, m.gid, m.mtime
        for o in both:
            o.addfile(ti)
    for t_, (d, m) in owner.items():
        ti = tarfile.TarInfo("./" + t_)
        ti.mode, ti.uid, ti.gid, ti.mtime, ti.uname, ti.gname = m.mode, m.uid, m.gid, m.mtime, m.uname, m.gname
        if m.issym():
            ti.type, ti.linkname = tarfile.SYMTYPE, m.linkname
            for o in both:
                o.addfile(ti)
            continue
        try:
            f = d.tar.extractfile(m)  # 硬連結：tarfile 回傳目標的內容 → 寫成一般檔案
        except KeyError:              # 硬連結的目標不在 deb 裡
            f = None
        if f is None:
            report["skipped_members"].append(f"{d.package}: {m.name}（讀不到內容）")
            continue
        with tempfile.SpooledTemporaryFile(SPOOL, dir=work) as sp:
            shutil.copyfileobj(f, sp)
            ti.size = sp.tell()
            for o in both:
                sp.seek(0)
                o.addfile(ti, sp)

    added = [with_status(d.fields) for d in debs]
    base_status, (rep, new) = merge_status(status_text, added)
    cust_status, _ = merge_status(base_status, [acme_para])
    add_bytes([base_out], STATUS, base_status.encode())
    add_bytes([cust_out], STATUS, cust_status.encode())
    if "var/lib/dpkg/info" not in seen:
        seen.add("var/lib/dpkg/info")
        add_dir(both, "var/lib/dpkg/info")
    for d in debs:
        add_bytes(both, f"var/lib/dpkg/info/{d.info_name()}.list", ("\n".join(lists[d]) + "\n").encode())
        if d.md5sums:
            add_bytes(both, f"var/lib/dpkg/info/{d.info_name()}.md5sums", d.md5sums)
    for dd in sorted({os.path.dirname(p) for p in acme_files}):
        parts = dd.split("/")
        for i in range(1, len(parts) + 1):
            sub = "/".join(parts[:i])
            if sub not in seen:
                seen.add(sub)
                add_dir([cust_out], sub)
    for p, data in acme_files.items():
        add_bytes([cust_out], p, data)
    add_bytes([cust_out], f"var/lib/dpkg/info/{ACME_PKG}.list",
              ("/.\n" + "\n".join("/" + p for p in acme_files) + "\n").encode())
    for o in both:
        o.close()
    for d in debs:
        d.tar.close()

    report.update({
        "rootfs_members_kept": n_base, "rootfs_files_replaced_by_debs": n_over, "rootfs_dpkg_info_replaced": n_info,
        "deb_files_written": len(owner),
        "dpkg_status": {"base_packages": len(paragraphs(status_text)), "replaced": rep, "added": new,
                        "custom_added": [f"{ACME_PKG} {ACME_VER}"]},
        "custom_extra": {"python": f"{ACME_PY[0]} {ACME_PY[1]}", "files": sorted(acme_files)},
        "outputs": {"base": {"file": os.path.basename(args.out_base), "sha256": sha256(args.out_base)},
                    "custom": {"file": os.path.basename(args.out_custom), "sha256": sha256(args.out_custom)}},
    })
    for k in ("deb_rejected", "skipped_members", "conflicts"):
        report[k + "_count"] = len(report[k])
        report[k] = report[k][:200]
    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    print(f"NVIDIA 套件 {len(debs)} 個（略過架構不符 {len(report['deb_skipped_arch'])}、錯誤 {len(report['deb_errors'])}）；"
          f"dpkg 紀錄 {len(paragraphs(status_text))} → 新增 {new}、取代 {rep}；rootfs 檔案被套件取代 {n_over}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for k in ("--bsp", "--rootfs", "--work", "--out-base", "--out-custom", "--report"):
        ap.add_argument(k, required=True)
    args = ap.parse_args(argv)
    build(args)


if __name__ == "__main__":
    sys.exit(main())
