"""Jetson 刷機包組裝：BSP ＋ 範例 rootfs（已合併 NVIDIA 套件的 tar）＋ CI 編出來的核心與模組 → 一個 tar（Linux_for_Tegra/ 形式）。

用法：python3 -I jetson_assemble.py --bsp <Jetson_Linux_*.tbz2> --rootfs-tar <base.tar> --deliver <deliverables.tar 解開的資料夾>
        --kernel-release <字串> --out <刷機包.tar> --report <assemble.json> [--prefix Linux_for_Tegra]

只讀 tar 結構、不解開 BSP 與 rootfs、不執行任何東西（下載的檔案是不可信資料）：
- BSP 的成員原樣串流寫進輸出，除了：
    Linux_for_Tegra/rootfs/…       不收（BSP 的 rootfs 是空的，只有 README；rootfs 來自 --rootfs-tar）
    Linux_for_Tegra/kernel/Image   換成 CI 編的 Image
    Linux_for_Tegra/kernel/dtb/<名稱>.dtb  CI 也編出同名 dtb（只有一個）時換成 CI 的
- rootfs（jetson_rootfs.py 的基礎版 tar）寫在 Linux_for_Tegra/rootfs/ 底下，除了：
    boot/Image                     換成同一顆 CI 的 Image（避免「兩顆核心」，C-kernel-boot 才會是 OK）
    usr/lib/modules/               NVIDIA 的核心模組整個不收；改放 CI 編的模組（樹內 kernel/…、樹外 updates/…，路徑取自編譯輸出）
    ＋ modules.order、modules.builtin、modules.builtin.modinfo（CI 的核心建置資料夾）
  NVIDIA 的 dpkg 紀錄（nvidia-l4t-kernel 等）原樣保留：真實出貨的刷機包也是 apply_binaries.sh 裝了 NVIDIA 的核心套件、再換成自己編的核心。
- 成員名稱、連結、裝置檔的檢查同 safe_extract.py；不安全的 BSP 成員略過並記錄，rootfs-tar 是我們自己產生的，有不安全成員就中止。
輸出報告 assemble.json：換了什麼、丟了什麼（NVIDIA 模組數、CI 模組數）、成員數、輸出的 sha256。
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import safe_extract as se  # noqa: E402

REL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


class AssembleError(Exception):
    pass


def norm(name):
    n = name.replace("\\", "/")
    while n.startswith("./"):
        n = n[2:]
    return n.strip("/")


def sha256_path(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def scan_deliver(deliver, kname_dir):
    """交付資料夾 → ({樹內/樹外 .ko 相對路徑 → 檔案}, {dtb 檔名 → [檔案]}, 核心建置資料夾裡的 modules.* 檔)。"""
    kos, dtbs, meta = {}, {}, {}
    kroot = os.path.join(deliver, kname_dir)
    for root, dirs, files in os.walk(deliver):
        for f in files:
            full = os.path.join(root, f)
            if os.path.islink(full):
                raise AssembleError("交付資料夾裡有符號連結：%s" % full)
            rel = os.path.relpath(full, deliver).replace(os.sep, "/")
            if f.endswith(".ko"):
                if rel.startswith(kname_dir + "/"):
                    kos["kernel/" + rel[len(kname_dir) + 1:]] = full
                else:
                    kos["updates/" + rel] = full
            elif f.endswith(".dtb"):
                dtbs.setdefault(f, []).append(full)
    for f in ("modules.order", "modules.builtin", "modules.builtin.modinfo"):
        p = os.path.join(kroot, f)
        if os.path.isfile(p):
            meta[f] = p
    return kos, dtbs, meta


def _add_file(out, name, path, mode=0o644, mtime=0):
    ti = tarfile.TarInfo(name)
    ti.size = os.path.getsize(path)
    ti.mode, ti.mtime, ti.uname, ti.gname = mode, mtime, "root", "root"
    with open(path, "rb") as f:
        out.addfile(ti, f)


def _add_dir(out, name, mode=0o755):
    ti = tarfile.TarInfo(name)
    ti.type, ti.mode, ti.uname, ti.gname = tarfile.DIRTYPE, mode, "root", "root"
    out.addfile(ti)


LIST_RE = re.compile(r"^var/lib/dpkg/info/([a-z0-9][a-z0-9+.-]*)(?::[a-z0-9-]+)?\.list$")


def assemble(bsp, rootfs_tar, deliver, kernel_release, out_path, prefix="Linux_for_Tegra", kernel_subdir="kernel/kernel-noble", owners_out=None):
    if not REL_RE.match(kernel_release):
        raise AssembleError("kernel_release 格式不合法：%r" % kernel_release[:40])
    image = os.path.join(deliver, kernel_subdir, "arch/arm64/boot/Image")
    if not os.path.isfile(image):
        raise AssembleError("交付資料夾沒有 %s" % image.replace(deliver, "", 1))
    kos, dtbs, meta = scan_deliver(deliver, kernel_subdir)
    if not kos:
        raise AssembleError("交付資料夾沒有任何 .ko")
    rep = {"schema": 1, "kernel_release": kernel_release, "image_sha256": sha256_path(image),
           "bsp_members": 0, "bsp_skipped": [], "bsp_rootfs_members_dropped": 0,
           "kernel_image_replaced": False, "rootfs_boot_image_replaced": False,
           "dtb_replaced": [], "dtb_kept_from_bsp": 0,
           "rootfs_members": 0, "nvidia_modules_dropped": 0, "ci_modules_in_tree": 0, "ci_modules_out_of_tree": 0}
    pfx = prefix + "/"
    dest_probe = "/__dest__"
    owners = {}
    with tarfile.open(out_path, "w", format=tarfile.PAX_FORMAT) as out:
        # ---- BSP ----
        with tarfile.open(bsp, "r|*") as t:
            for m in t:
                n = norm(m.name)
                try:
                    se.check_member(m, dest_probe)
                except se.UnsafeArchive as e:
                    rep["bsp_skipped"].append("%s（%s）" % (n[:120], e))
                    continue
                if not (n == prefix or n.startswith(pfx)):
                    rep["bsp_skipped"].append("%s（不在 %s/ 底下）" % (n[:120], prefix))
                    continue
                if n == prefix + "/rootfs" or n.startswith(pfx + "rootfs/"):
                    rep["bsp_rootfs_members_dropped"] += 1
                    continue
                rep["bsp_members"] += 1
                if n == pfx + "kernel/Image" and m.isreg():
                    _add_file(out, n, image, mode=m.mode, mtime=m.mtime)
                    rep["kernel_image_replaced"] = True
                    continue
                if n.startswith(pfx + "kernel/dtb/") and n.endswith(".dtb") and m.isreg():
                    cands = dtbs.get(os.path.basename(n), [])
                    if len(cands) == 1:
                        _add_file(out, n, cands[0], mode=m.mode, mtime=m.mtime)
                        rep["dtb_replaced"].append(os.path.basename(n))
                        continue
                    rep["dtb_kept_from_bsp"] += 1
                m.name = n + ("/" if m.isdir() else "")
                if m.islnk():
                    m.linkname = norm(m.linkname)
                if m.isreg():
                    out.addfile(m, t.extractfile(m))
                else:
                    out.addfile(m)
        if not rep["kernel_image_replaced"]:
            raise AssembleError("BSP 裡沒有 %skernel/Image 可以換" % pfx)
        _add_dir(out, prefix + "/rootfs")
        # ---- rootfs ----
        rp = pfx + "rootfs/"
        seen_dirs = {prefix + "/rootfs"}
        mods_prefix = "usr/lib/modules"
        with tarfile.open(rootfs_tar, "r|") as t:
            for m in t:
                n = norm(m.name)
                try:
                    # rootfs 裡的絕對符號連結是正常的（751 個）；這個 tar 不會解開到主機，只是寫進另一個 tar，所以不檢查連結目標
                    se.check_member(m, dest_probe, allow_symlinks_anywhere=True)
                except se.UnsafeArchive as e:
                    raise AssembleError("rootfs tar 有不安全的成員：%s" % e)
                if n == "":
                    continue
                if n == mods_prefix or n.startswith(mods_prefix + "/"):
                    if n.endswith(".ko") or ".ko." in n:
                        rep["nvidia_modules_dropped"] += 1
                    continue
                if n == "boot/Image":
                    continue
                rep["rootfs_members"] += 1
                new = rp + n
                if m.isdir():
                    seen_dirs.add(new)
                lm = LIST_RE.match(n) if m.isreg() and m.size <= (64 << 20) else None
                m.name = new + ("/" if m.isdir() else "")
                if m.islnk():
                    m.linkname = rp + norm(m.linkname)
                if lm:      # dpkg 的 .list：記下「檔案 → 擁有它的套件」（分層用：Syft 的檔案紀錄靠它找層）；內容照常寫進刷機包
                    data = t.extractfile(m).read()
                    for line in data.decode("utf-8", "replace").splitlines():
                        if line.startswith("/") and line != "/.":
                            owners.setdefault(line, set()).add(lm.group(1))
                    out.addfile(m, io.BytesIO(data))
                elif m.isreg():
                    out.addfile(m, t.extractfile(m))
                else:
                    out.addfile(m)
        # ---- CI 的核心與模組 ----
        def ensure_dirs(path):
            parts = path.split("/")
            for i in range(2, len(parts)):
                d = "/".join(parts[:i])
                if d not in seen_dirs:
                    seen_dirs.add(d)
                    _add_dir(out, d)
        ensure_dirs(rp + "boot/Image")
        _add_file(out, rp + "boot/Image", image, mode=0o644)
        rep["rootfs_boot_image_replaced"] = True
        base = rp + mods_prefix + "/" + kernel_release + "/"
        for rel, full in sorted(kos.items()):
            ensure_dirs(base + rel)
            _add_file(out, base + rel, full)
            rep["ci_modules_in_tree" if rel.startswith("kernel/") else "ci_modules_out_of_tree"] += 1
        for f, full in sorted(meta.items()):
            ensure_dirs(base + f)
            _add_file(out, base + f, full)
        rep["modules_meta"] = sorted(meta)
    if owners_out:
        # 一個路徑有多個擁有者時用名稱排序的第一個（分層時只用來找層；NVIDIA 與 Ubuntu 同時擁有的路徑很少見，記數量）
        flat = {k: sorted(v)[0] for k, v in owners.items()}
        with open(owners_out, "w", encoding="utf-8") as f:
            json.dump(flat, f, ensure_ascii=False, sort_keys=True)
        rep["owners"] = {"paths": len(flat), "multi_owner_paths": sum(1 for v in owners.values() if len(v) > 1)}
    rep["package_sha256"] = sha256_path(out_path)
    rep["package_bytes"] = os.path.getsize(out_path)
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for k in ("--bsp", "--rootfs-tar", "--deliver", "--kernel-release", "--out", "--report"):
        ap.add_argument(k, required=True)
    ap.add_argument("--prefix", default="Linux_for_Tegra")
    ap.add_argument("--owners-out", default=None, help="寫出 {路徑: 擁有它的套件} 的 JSON（取自 rootfs 的 dpkg .list）")
    ap.add_argument("--kernel-subdir", default="kernel/kernel-noble")
    a = ap.parse_args(argv)
    try:
        rep = assemble(a.bsp, a.rootfs_tar, a.deliver, a.kernel_release, a.out, a.prefix, a.kernel_subdir, a.owners_out)
    except (AssembleError, OSError, tarfile.TarError, EOFError) as e:
        print("jetson_assemble: FAIL（%s）" % (e if isinstance(e, AssembleError) else type(e).__name__))
        return 1
    with open(a.report, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1)
    print("jetson_assemble: OK（BSP %d 個成員、rootfs %d 個；Image×2 已換；CI 模組 樹內 %d／樹外 %d，丟掉 NVIDIA 模組 %d；dtb 換 %d）" % (
        rep["bsp_members"], rep["rootfs_members"], rep["ci_modules_in_tree"], rep["ci_modules_out_of_tree"],
        rep["nvidia_modules_dropped"], len(rep["dtb_replaced"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
