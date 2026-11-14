#!/usr/bin/env python3
"""Debian 核心原始碼：orig（上游）＋ debian.tar.xz 的修補 → 精靈要的原始碼壓縮檔（D-035）。一律 `python3 -I`。

  debian_kernel_source.py prepare --orig <linux_X.orig.tar.xz> --debian <linux_X-N.debian.tar.xz> --work <資料夾> --out <tar.gz> --json <報告>
最後一行 `kernel-source: OK｜GAP｜FAIL（說明）`；結束碼 OK 0、FAIL 1、GAP 3、用法錯誤 64。

做法（修補檔當資料套用，**不執行**任何腳本：不用 dpkg-source、不用 debian/rules）：
1. 用 pipeline/lib/safe_extract.py 解開 orig 與 debian.tar.xz（不可信資料；路徑、連結、特殊檔都檢查）。
2. 依 debian/patches/series 的順序，用 `patch -p1 --batch --forward` 逐一套用。series 的每一行必須只有一個相對路徑
   （不能有 `..`、選項或其他欄位），檔案要在 debian/patches 底下、是一般檔案。任何一個套不上 → GAP（停在那裡，不跳過）。
3. 套完再檢查一次整棵樹（不能有特殊檔案、符號連結不能跳出去）。
4. debian/changelog 第一行的版本（例如 6.12.116-1）寫進報告；scan 拿它跟映像裡 linux-image 套件的版本比，不同 → GAP。
5. 打包成 tar.gz（擁有者一律 0）給精靈的 --source。
GAP 時不產生壓縮檔；scan 改用上游 orig，並把核心原始碼判斷標成 PARTIAL（只有上游、未含 Debian 修補）。
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
import safe_extract as se  # noqa: E402

OK, FAIL, GAP, USAGE = 0, 1, 3, 64
MAX_PATCHES = 5000
PATCH_TIMEOUT = 120
CHANGELOG_RE = re.compile(r"^linux(?:-signed-[a-z0-9]+)? \(([0-9][A-Za-z0-9.+~:-]*)\) ")
SERIES_LINE_RE = re.compile(r"^[A-Za-z0-9._+/-]+$")


class SrcGap(Exception):
    pass


def single_top(d):
    ents = [e for e in os.listdir(d) if not e.startswith(".")]
    if len(ents) != 1 or not os.path.isdir(os.path.join(d, ents[0])) or os.path.islink(os.path.join(d, ents[0])):
        raise SrcGap("orig 解開後不是單一的最上層資料夾（%d 個項目）" % len(ents))
    return os.path.join(d, ents[0])


def read_series(tree):
    pdir = os.path.join(tree, "debian", "patches")
    sp = os.path.join(pdir, "series")
    if not os.path.isfile(sp) or os.path.islink(sp):
        raise SrcGap("debian/patches/series 不存在或不是一般檔案")
    with open(sp, encoding="utf-8") as f:
        lines = [l.split("#", 1)[0].strip() for l in f]
    out = []
    for l in lines:
        if not l:
            continue
        if not SERIES_LINE_RE.match(l) or ".." in l.split("/") or l.startswith("/"):
            raise SrcGap("series 有不支援的行（只接受單一個相對路徑）：%r" % l[:80])
        p = os.path.join(pdir, l)
        if not os.path.isfile(p) or os.path.islink(p) or not se._inside(pdir, p):
            raise SrcGap("series 列的 patch 不存在或不是一般檔案：%s" % l)
        out.append((l, p))
        if len(out) > MAX_PATCHES:
            raise SrcGap("patch 超過 %d 個" % MAX_PATCHES)
    if not out:
        raise SrcGap("series 是空的")
    return out


def changelog_version(tree):
    cp = os.path.join(tree, "debian", "changelog")
    if not os.path.isfile(cp) or os.path.islink(cp):
        raise SrcGap("debian/changelog 不存在")
    with open(cp, encoding="utf-8", errors="replace") as f:
        first = f.readline()
    m = CHANGELOG_RE.match(first)
    if not m:
        raise SrcGap("debian/changelog 第一行讀不出版本")
    return m.group(1)


def apply(tree, patches):
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    for i, (name, path) in enumerate(patches, 1):
        try:
            r = subprocess.run(["patch", "-p1", "--batch", "--forward", "--no-backup-if-mismatch", "--silent", "-d", tree, "-i", path],
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=PATCH_TIMEOUT, env=env)
        except subprocess.TimeoutExpired:
            raise SrcGap("第 %d 個 patch（%s）套用逾時" % (i, name))
        if r.returncode != 0:
            raise SrcGap("第 %d 個 patch（%s）套不上：%s" % (i, name, (r.stdout + r.stderr).strip().splitlines()[-1:] or ""))
    return len(patches)


def prepare(a):
    work = os.path.abspath(a.work)
    if os.path.lexists(work) and os.listdir(work):
        raise ValueError("--work 必須不存在或是空的")
    os.makedirs(work, exist_ok=True)
    doc = {"schema": 1, "orig": os.path.basename(a.orig), "debian": os.path.basename(a.debian), "status": None,
           "basis": None, "debian_version": None, "patches_total": None, "patches_applied": 0, "archive": None, "reason": None}
    try:
        se.extract(a.orig, os.path.join(work, "orig"))
        tree = single_top(os.path.join(work, "orig"))
        if os.path.lexists(os.path.join(tree, "debian")):
            raise SrcGap("orig 裡已經有 debian/ 資料夾")
        se.extract(a.debian, os.path.join(work, "deb"))
        dsrc = os.path.join(work, "deb", "debian")
        if not os.path.isdir(dsrc) or os.path.islink(dsrc):
            raise SrcGap("debian.tar.xz 裡沒有 debian/ 資料夾")
        os.rename(dsrc, os.path.join(tree, "debian"))
        doc["debian_version"] = changelog_version(tree)
        patches = read_series(tree)
        doc["patches_total"] = len(patches)
        doc["patches_applied"] = apply(tree, patches)
        se.verify_tree(tree)
        out = os.path.abspath(a.out)
        r = subprocess.run(["tar", "--owner=0", "--group=0", "--numeric-owner", "--sort=name", "-czf", out, "-C", os.path.dirname(tree),
                            os.path.basename(tree)], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3600)
        if r.returncode != 0:
            raise RuntimeError("打包失敗：%s" % r.stderr.strip()[-200:])
        doc.update(status="OK", basis="上游 orig ＋ Debian 修補（debian/patches/series 依序套用）", archive=os.path.basename(out))
    except (SrcGap, se.UnsafeArchive) as e:
        doc.update(status="GAP", basis="只有上游 orig、未含 Debian 修補", reason=str(e)[:300])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    with open(a.json + ".part", "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(a.json + ".part", a.json)
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("prepare")
    for k in ("orig", "debian", "work", "out", "json"):
        p.add_argument("--" + k, required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        print("kernel-source: FAIL（參數錯誤）")
        return USAGE
    if a.cmd != "prepare":
        print("kernel-source: FAIL（要給子指令 prepare）")
        return USAGE
    try:
        doc = prepare(a)
    except ValueError as e:
        print("kernel-source: FAIL（%s）" % e)
        return USAGE
    except Exception as e:      # noqa: BLE001  解開或打包錯誤：FAIL
        print("kernel-source: FAIL（%s: %s）" % (type(e).__name__, getattr(e, "strerror", None) or str(e)[:200]))
        return FAIL
    if doc["status"] == "OK":
        print("kernel-source: OK（Debian %s：%d 個 patch 依序套用）" % (doc["debian_version"], doc["patches_applied"]))
        return OK
    print("kernel-source: GAP（%s；scan 改用上游 orig，核心原始碼判斷標 PARTIAL）" % doc["reason"])
    return GAP


if __name__ == "__main__":
    sys.exit(main())
