#!/usr/bin/env python3
"""WP7 平台（raspberrypi、rockchip、ai-nas）共用：讀 sources.yml 的參數、把官方映像解成未壓縮的磁碟映像（只解開、不執行）。

這個資料夾名稱以底線開頭，不符合平台名稱規則，dispatcher 不會把它當成平台。一律用 `python3 -I`。

  disk_image.py param   <專案資料夾> <版本> <鍵>          → 印出 sources.yml 的 platform_params.<鍵>（沒有 → 結束碼 3）
  disk_image.py files   <專案資料夾> <版本> [--role R]    → 每行「role<TAB>name」
  disk_image.py prepare <專案資料夾> <版本> --downloads <資料夾> --work <資料夾> --json <assemble.json>
最後一行（prepare）：`assemble: OK｜GAP｜FAIL（說明）`；結束碼 OK 0、FAIL 1、GAP 3、用法錯誤 64。

prepare：
- 映像檔名取自 platform_params.image，必須是 sources.yml 裡 role: image 的檔案，而且已經由 fetch 下載核對過（在 --downloads）。
- `.img.xz`／`.img.gz`：用 tools/demo/rpi_img.py 的 extract_image 串流解壓（大小上限、剩餘空間檢查、O_EXCL、0600）。
- `.tar.xz`（Debian 雲端映像）：串流讀 tar，只取 platform_params.image_member（預設 disk.raw）這一個一般檔案，
  其他成員只記名稱與大小；同樣有大小上限與空間檢查。不用 tarfile.extract（不建立任何路徑、不處理連結）。
- `.img`（未壓縮）：直接使用，不複製。
- 結果：<work>/disk.img 與 assemble.json（映像檔、解壓後的大小與 sha256、做法）。磁碟映像的內容由 scan 步驟唯讀解析。
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
MAX_IMAGE = 64 << 30
MIN_FREE_AFTER = 1 << 30
OK, FAIL, GAP, USAGE = 0, 1, 3, 64


class PrepError(Exception):
    pass


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def project_config():
    sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
    import project_config as pc      # noqa: E402
    return pc


def release(proj, ver):
    pc = project_config()
    doc = pc.load_sources(os.path.join(proj, "sources.yml"))
    rel = doc["releases"].get(ver)
    if rel is None:
        raise PrepError("sources.yml 沒有版本 %s" % ver)
    return rel


def extract_member(src, member, out, max_bytes=MAX_IMAGE):
    """串流讀 .tar.xz，只把名稱等於 member 的一般檔案寫到 out。→ (bytes, sha256, 其他成員清單)。"""
    d = os.path.dirname(os.path.abspath(out))
    others, found = [], None
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as e:
        raise PrepError("無法建立 %s（%s）；檔案不能已經存在" % (os.path.basename(out), e.strerror))
    ok = False
    try:
        with tarfile.open(src, mode="r|xz") as t, os.fdopen(fd, "wb") as dst:
            for m in t:
                name = m.name[2:] if m.name.startswith("./") else m.name
                if name != member:
                    if len(others) < 200:
                        others.append({"name": m.name[:200], "size": m.size, "type": m.type.decode("ascii", "replace")})
                    continue
                if found is not None:
                    raise PrepError("tar 裡有兩個 %s" % member)
                if not m.isreg():
                    raise PrepError("%s 不是一般檔案" % member)
                if m.size > max_bytes:
                    raise PrepError("%s 的大小 %d 超過上限 %d" % (member, m.size, max_bytes))
                st = os.statvfs(d)
                if st.f_bavail * st.f_frsize < m.size + MIN_FREE_AFTER:
                    raise PrepError("%s 的剩餘空間不夠解出 %d bytes" % (d, m.size))
                f = t.extractfile(m)
                h, n = hashlib.sha256(), 0
                while True:
                    b = f.read(4 << 20)
                    if not b:
                        break
                    n += len(b)
                    if n > m.size:
                        raise PrepError("%s 的內容比標頭的大小長" % member)
                    h.update(b)
                    dst.write(b)
                if n != m.size:
                    raise PrepError("%s 讀不完整" % member)
                found = (n, h.hexdigest())
        if found is None:
            raise PrepError("tar 裡沒有 %s" % member)
        ok = True
        return found[0], found[1], others
    except (tarfile.TarError, OSError, EOFError) as e:
        raise PrepError("解開失敗：%s: %s" % (type(e).__name__, e))
    finally:
        if not ok:
            try:
                os.remove(out)
            except OSError:
                pass


def prepare(proj, ver, downloads, work, jpath):
    rel = release(proj, ver)
    params = rel.get("platform_params") or {}
    name = params.get("image")
    if not name:
        raise PrepError("sources.yml 的 %s 沒有 platform_params.image" % ver)
    entry = next((f for f in rel["files"] if f.get("name") == name), None)
    if entry is None or entry.get("role") != "image":
        raise PrepError("platform_params.image（%s）不是 sources.yml 裡 role: image 的檔案" % name)
    if entry.get("gap"):
        return GAP, "映像 %s 沒有可核對的雜湊（%s），不使用" % (name, entry["gap"]), None
    src = os.path.join(downloads, name)
    if not os.path.isfile(src) or os.path.islink(src):
        raise PrepError("%s 不在 downloads（先執行 fetch）" % name)
    os.makedirs(work, exist_ok=True)
    out = os.path.join(work, "disk.img")
    doc = {"schema": 1, "image_file": name, "image_sha256": entry.get("sha256"), "disk_image": out}
    if name.endswith((".img.xz", ".img.gz")):
        rpi = _load("dumpling_rpi_img", os.path.join(ROOT, "tools", "demo", "rpi_img.py"))
        try:
            n, sha = rpi.extract_image(src, out)
        except rpi.RpiError as e:
            raise PrepError(str(e))
        doc.update(method="串流解壓（rpi_img.extract_image）", disk_bytes=n, disk_sha256=sha)
    elif name.endswith(".tar.xz"):
        member = params.get("image_member", "disk.raw")
        n, sha, others = extract_member(src, member, out)
        doc.update(method="從 tar.xz 只取出 %s（串流，不建立其他路徑）" % member, disk_bytes=n, disk_sha256=sha,
                   other_members=others)
    elif name.endswith(".img"):
        out = src
        doc.update(method="未壓縮，直接使用", disk_image=out, disk_bytes=os.path.getsize(src), disk_sha256=entry.get("sha256"))
    else:
        raise PrepError("不認得的映像格式：%s" % name)
    with open(jpath + ".part", "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(jpath + ".part", jpath)
    return OK, "%s → %s（%d bytes）" % (name, os.path.basename(out), doc["disk_bytes"]), doc


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("param")
    p.add_argument("proj"); p.add_argument("ver"); p.add_argument("key")
    f = sub.add_parser("files")
    f.add_argument("proj"); f.add_argument("ver"); f.add_argument("--role")
    r = sub.add_parser("prepare")
    r.add_argument("proj"); r.add_argument("ver")
    r.add_argument("--downloads", required=True); r.add_argument("--work", required=True); r.add_argument("--json", required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return USAGE
    if a.cmd is None:
        ap.print_usage(sys.stderr)
        return USAGE
    try:
        if a.cmd == "param":
            v = (release(a.proj, a.ver).get("platform_params") or {}).get(a.key)
            if v is None:
                print("disk_image: GAP（platform_params 沒有 %s）" % a.key, file=sys.stderr)
                return GAP
            print(v if isinstance(v, str) else json.dumps(v, ensure_ascii=False))
            return OK
        if a.cmd == "files":
            for e in release(a.proj, a.ver)["files"]:
                if a.role is None or e.get("role") == a.role:
                    print("%s\t%s" % (e.get("role"), e.get("name")))
            return OK
        rc, msg, _doc = prepare(a.proj, a.ver, a.downloads, a.work, a.json)
        print("assemble: %s（%s）" % ({OK: "OK", GAP: "GAP"}[rc], msg))
        return rc
    except Exception as e:      # noqa: BLE001  設定錯誤、讀檔錯誤：FAIL 並寫原因
        tag = "assemble" if a.cmd == "prepare" else "disk_image"
        print("%s: FAIL（%s: %s）" % (tag, type(e).__name__, str(e)[:300]))
        return FAIL


if __name__ == "__main__":
    sys.exit(main())
