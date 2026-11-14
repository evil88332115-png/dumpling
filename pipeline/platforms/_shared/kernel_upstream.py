#!/usr/bin/env python3
"""廠商 BSP 核心的上游版本核對（D-038）。一律 `python3 -I`。

  kernel_upstream.py check --image <disk.img> --source <核心原始碼 tar.gz/xz> --upstream <X.Y.Z> --release <模組資料夾名稱> --out <json>
最後一行 `kernel-upstream: OK｜GAP｜FAIL（說明）`；結束碼 OK 0、FAIL 1、GAP 3、用法錯誤 64。

為什麼：廠商的核心套件（例如 Radxa 的 linux-image-6.1.84-8-rk2410，原始碼套件 linux-rk2410）不在發行版的弱點資料裡，
Grype 對核心是 0 筆；kernel_cna_version.py 也不把 `6.1.84-8-rk2410` 當成上游版本（像發行版的 ABI 版本號，不猜）。
所以由專案在 sources.yml 給上游版本（platform_params.kernel_upstream_version），這裡用兩個**獨立**的來源核對，兩者都相同才 OK：
  1. 映像 rootfs 的 /usr/lib/modules/<release>/ 存在，而且 <release> 是 `<上游版本>-…`、`<上游版本>+…`、`<上游版本>~…`（或等於上游版本）。
  2. sources.yml 固定的核心原始碼裡最上層 Makefile 的 VERSION.PATCHLEVEL.SUBLEVEL。
不一致 → GAP，訊息同時列出兩個值。另外記錄映像 /boot/config-<release> 是否存在（實際出貨的 .config；沒有就是沒有，
不拿原始碼的 defconfig 代替 —— defconfig 不是出貨的設定）。依它排除的 CVE，依據類型是 shipped-config（不是建置紀錄）。
映像與原始碼都是不可信資料：只讀，tar 只串流讀最上層的 Makefile 一個成員（大小有上限），不解到磁碟。
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import tarfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
OK, FAIL, GAP, USAGE = 0, 1, 3, 64
VER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
REL_RE = re.compile(r"^[0-9][A-Za-z0-9.+_~-]{0,80}$")
REL_UP_RE = re.compile(r"^([0-9]+\.[0-9]+\.[0-9]+)(?:[-+~].*)?$")
MAKEFILE_MAX = 1 << 20
CONFIG_MAX = 8 << 20
TAR_SCAN_MAX = 200000          # 找 Makefile 時最多看幾個成員


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def makefile_version(src):
    """原始碼壓縮檔最上層的 Makefile（<頂層資料夾>/Makefile）→ 'X.Y.Z'。找不到或格式不對 → (None, 原因)。"""
    mode = "r|xz" if src.endswith((".xz", ".txz")) else "r|gz" if src.endswith((".gz", ".tgz")) else "r|*"
    with tarfile.open(src, mode=mode) as t:
        for i, m in enumerate(t):
            if i > TAR_SCAN_MAX:
                return None, "前 %d 個成員裡沒有最上層的 Makefile" % TAR_SCAN_MAX
            parts = m.name.lstrip("./").split("/")
            if len(parts) == 2 and parts[1] == "Makefile" and m.isfile() and m.size <= MAKEFILE_MAX:
                text = t.extractfile(m).read(MAKEFILE_MAX).decode("utf-8", "replace")
                vals = {}
                for k in ("VERSION", "PATCHLEVEL", "SUBLEVEL"):
                    mm = re.search(r"^%s\s*=\s*([0-9]+)\s*$" % k, text, re.M)
                    if not mm:
                        return None, "Makefile 沒有 %s" % k
                    vals[k] = mm.group(1)
                return "%s.%s.%s" % (vals["VERSION"], vals["PATCHLEVEL"], vals["SUBLEVEL"]), None
    return None, "原始碼壓縮檔裡沒有最上層的 Makefile"


def image_facts(img, release):
    """映像 rootfs：/usr/lib/modules 底下的資料夾、/boot/config-<release>（存在與 sha256）。"""
    rpi = _load("dumpling_rpi_img", os.path.join(ROOT, "tools", "demo", "rpi_img.py"))
    im = rpi.RpiImage(img)
    try:
        root, why = im.rootfs()
        if root is None:
            return None, None, "rootfs 讀不到（%s）" % why
        fs = rpi.rk().Ext4(im.fd, root["offset_in_file"], root["size"])

        def lookup(comps):
            ino = 2
            for c in comps:
                ents, _bad = fs.entries(fs.inode(ino))
                nxt = dict(ents).get(c.encode())
                if nxt is None:
                    return None
                ino = nxt
            return fs.inode(ino)

        mods = lookup(("usr", "lib", "modules"))
        if mods is None or (mods.mode & 0o170000) != 0o040000:
            return None, None, "rootfs 沒有 /usr/lib/modules"
        ents, _bad = fs.entries(mods)
        dirs = sorted(n.decode("utf-8", "replace") for n, i in ents if (fs.inode(i).mode & 0o170000) == 0o040000)
        cfg = None
        ci = lookup(("boot", "config-" + release))
        if ci is not None and (ci.mode & 0o170000) == 0o100000 and ci.size <= CONFIG_MAX:
            with fs.open(ci) as f:
                data = f.read(ci.size)
            cfg = {"path": "/boot/config-" + release, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        return dirs, cfg, None
    finally:
        im.close()


def check(a):
    doc = {"schema": 1, "requested_upstream": a.upstream, "kernel_release": a.release, "status": None, "gaps": [],
           "sources": {"image_modules": {"dirs": None, "upstream_from_release": None, "match": None},
                       "source_makefile": {"file": os.path.basename(a.source), "version": None, "match": None, "error": None}},
           "shipped_config": None, "config_basis": "shipped-config",
           "note": "廠商 BSP 核心：CVE 清單依上游版本範圍列出，是候選（廠商可能已回移修補），一律進待人審（D-038，同 D-034 的原則）。"
                   "依 .config 排除的依據是映像裡實際出貨的 config（shipped-config），不是建置紀錄。"}
    dirs, cfg, err = image_facts(a.image, a.release)
    im = doc["sources"]["image_modules"]
    if err:
        doc["gaps"].append(err)
    else:
        im["dirs"] = dirs
        if a.release not in dirs:
            doc["gaps"].append("映像的 /usr/lib/modules 沒有 %s（有：%s）" % (a.release, "、".join(dirs) or "無"))
        else:
            # 模組資料夾名稱開頭的 X.Y.Z，後面接 -（Radxa 的 6.1.84-8-rk2410）、+（Raspberry Pi 的 6.18.50+rpt-rpi-2712）或 ~ 才算；
            # 只切 "-" 會把 6.18.50+rpt-rpi-2712 讀成 6.18.50+rpt
            m = REL_UP_RE.match(a.release)
            up = m.group(1) if m else None
            im["upstream_from_release"] = up
            im["match"] = up == a.upstream
        doc["shipped_config"] = cfg
    sm = doc["sources"]["source_makefile"]
    try:
        sm["version"], sm["error"] = makefile_version(a.source)
    except (tarfile.TarError, OSError, EOFError, ValueError) as e:
        sm["error"] = "%s: %s" % (type(e).__name__, str(e)[:200])
    if sm["version"]:
        sm["match"] = sm["version"] == a.upstream
    if im["match"] is not True or sm["match"] is not True:
        doc["gaps"].append("上游版本核對不一致：指定 %s；映像模組資料夾 %s → %s；原始碼 Makefile %s" % (
            a.upstream, a.release, im["upstream_from_release"], sm["version"] or ("讀不到：" + str(sm["error"]))))
    if cfg is None and not err:
        doc["gaps"].append("映像沒有 /boot/config-%s：C-kernel-config 不能依實際出貨的 .config 判定（不拿 defconfig 代替）" % a.release)
    ver_ok = im["match"] is True and sm["match"] is True
    doc["status"] = "OK" if not doc["gaps"] else "GAP"
    doc["upstream_verified"] = ver_ok
    with open(a.out + ".part", "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(a.out + ".part", a.out)
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check")
    for k in ("image", "source", "upstream", "release", "out"):
        c.add_argument("--" + k, required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        print("kernel-upstream: FAIL（參數錯誤）")
        return USAGE
    if a.cmd != "check" or not VER_RE.match(a.upstream) or not REL_RE.match(a.release):
        print("kernel-upstream: FAIL（--upstream 要是 X.Y.Z、--release 要是模組資料夾名稱）")
        return USAGE
    try:
        doc = check(a)
    except Exception as e:      # noqa: BLE001  映像讀不了等：FAIL
        print("kernel-upstream: FAIL（%s: %s）" % (type(e).__name__, getattr(e, "strerror", None) or str(e)[:200]))
        return FAIL
    if doc["status"] == "OK":
        print("kernel-upstream: OK（上游 %s：映像模組資料夾 %s 與原始碼 Makefile 一致；出貨 config %s）" % (
            a.upstream, a.release, doc["shipped_config"]["path"]))
        return OK
    print("kernel-upstream: GAP（%s）" % "；".join(doc["gaps"])[:400])
    return GAP


if __name__ == "__main__":
    sys.exit(main())
