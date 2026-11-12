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
import lzma
import re
import sys

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


TAR_META_MAX = 1 << 20          # GNU longname／longlink、PAX 標頭的內容上限
TAR_MAX_MEMBERS = 100000
TAR_TOTAL_MAX = MAX_IMAGE + (4 << 30)   # 整個 tar（解壓後）的總量上限，包含略過的成員


def _tar_num(field):
    """tar 標頭的數字欄位：八進位文字，或 base-256（最高位元設 1）。"""
    if field and field[0] & 0x80:
        if field[0] != 0x80:
            raise PrepError("tar 的 base-256 數字是負數或太大")
        v = 0
        for b in field[1:]:
            v = (v << 8) | b
        return v
    t = field.split(b"\0", 1)[0].strip(b" ")
    if not t:
        return 0
    if not all(48 <= c <= 55 for c in t):
        raise PrepError("tar 標頭的數字欄位格式錯")
    return int(t, 8)


def _pax(data):
    """PAX 擴充標頭（"<長度> <鍵>=<值>\n" 的串接）→ dict。格式錯 → PrepError。"""
    out, o = {}, 0
    while o < len(data):
        sp = data.find(b" ", o, o + 21)
        if sp < 0:
            raise PrepError("PAX 標頭格式錯")
        try:
            n = int(data[o:sp])
        except ValueError:
            raise PrepError("PAX 標頭的長度格式錯")
        if n <= sp - o or o + n > len(data) or data[o + n - 1:o + n] != b"\n":
            raise PrepError("PAX 標頭的長度不對")
        k, eq, v = data[sp + 1:o + n - 1].partition(b"=")
        if not eq:
            raise PrepError("PAX 紀錄沒有 =")
        out[k.decode("utf-8", "replace")] = v
        o += n
    return out


SPARSE_MAX_ENTRIES = 1 << 20     # GNU 稀疏表的項目上限
ZERO = bytes(4 << 20)


class _XzReader:
    """串流解 .xz（LZMADecompressor）：只接受單一 xz 串流，串流結束後不能有任何其他資料（包含 xz 層級的尾端垃圾）。"""

    def __init__(self, path):
        self.f = open(path, "rb")
        self.d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        self.buf = b""

    def read(self, n):
        out = b""
        while len(out) < n and not self.d.eof:
            if self.d.needs_input:
                chunk = self.f.read(1 << 20)
                if not chunk:
                    raise PrepError("xz 串流不完整（截斷）")
            else:
                chunk = b""
            out += self.d.decompress(chunk, max_length=n - len(out))
        if self.d.eof and (self.d.unused_data or self.f.read(1)):
            raise PrepError("xz 串流之後還有其他資料")
        return out

    def close(self):
        self.f.close()


class _Counted:
    """包住解壓串流：計算總讀取量，超過上限就停。"""

    def __init__(self, f, limit):
        self.f, self.n, self.limit = f, 0, limit

    def read(self, n):
        b = self.f.read(n)
        self.n += len(b)
        if self.n > self.limit:
            raise PrepError("tar 解壓後超過總量上限 %d bytes" % self.limit)
        return b

    def exact(self, n):
        out = bytearray()
        while len(out) < n:
            b = self.read(min(n - len(out), 4 << 20))
            if not b:
                raise PrepError("tar 在成員中間結束（截斷）")
            out += b
        return bytes(out)

    def skip(self, n):
        while n > 0:
            b = self.read(min(n, 4 << 20))
            if not b:
                raise PrepError("tar 在成員中間結束（截斷）")
            n -= len(b)


def _sparse_map(hdr, t):
    """GNU 舊式稀疏（型別 S）：標頭 386 起 4 筆 (offset, numbytes)，482 isextended，483 realsize；延伸區塊每塊 21 筆、504 isextended。
    → (realsize, [(offset, numbytes)…])。表要遞增、不重疊、不超過 realsize。"""
    def entries(block, start, count):
        out = []
        for k in range(count):
            o = start + 24 * k
            off, n = _tar_num(block[o:o + 12]), _tar_num(block[o + 12:o + 24])
            if off == 0 and n == 0 and not block[o:o + 24].strip(b"\0"):
                continue
            out.append((off, n))
        return out
    sp = entries(hdr, 386, 4)
    ext = hdr[482]
    real = _tar_num(hdr[483:495])
    while ext:
        blk = t.exact(512)
        sp += entries(blk, 0, 21)
        ext = blk[504]
        if len(sp) > SPARSE_MAX_ENTRIES:
            raise PrepError("稀疏表項目太多")
    pos = 0
    for off, n in sp:
        if off < pos or off + n > real:
            raise PrepError("稀疏表不是遞增、有重疊或超過實際大小")
        pos = off + n
    return real, sp


def _hash_zeros(h, n):
    while n > 0:
        k = min(n, len(ZERO))
        h.update(ZERO[:k])
        n -= k


def extract_member(src, member, out, max_bytes=MAX_IMAGE):
    """串流讀 .tar.xz，只把名稱等於 member 的一般檔案寫到 out。→ (bytes, sha256, 其他成員清單)。
    不用 tarfile：自己讀 512 bytes 的標頭（ustar／GNU／PAX），longname 與 PAX 內容有上限，整個 tar 的解壓總量有上限，
    並且一路讀到 tar 結尾與 xz 串流結尾（xz 的完整性檢查才會做完；尾端截斷或垃圾 → 錯誤）。"""
    d = os.path.dirname(os.path.abspath(out))
    others, found = [], None
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as e:
        raise PrepError("無法建立 %s（%s）；檔案不能已經存在" % (os.path.basename(out), e.strerror))
    ok, xf = False, None
    try:
        xf = _XzReader(src)
        with os.fdopen(fd, "wb") as dst:
            t = _Counted(xf, TAR_TOTAL_MAX)
            longname, pax, members, zeros = None, {}, 0, 0
            while True:
                hdr = t.read(512)
                if len(hdr) == 0:
                    raise PrepError("tar 沒有結尾的兩個空區塊（截斷）")
                if len(hdr) < 512:
                    hdr += t.exact(512 - len(hdr))
                if hdr == b"\0" * 512:
                    zeros += 1
                    if zeros == 2:
                        break
                    continue
                if zeros:
                    raise PrepError("tar 的空區塊後面又有資料")
                members += 1
                if members > TAR_MAX_MEMBERS:
                    raise PrepError("tar 成員超過 %d 個" % TAR_MAX_MEMBERS)
                chk = _tar_num(hdr[148:156])
                if chk != sum(hdr[:148]) + 8 * 32 + sum(hdr[156:]):
                    raise PrepError("tar 標頭的檢查碼不符")
                typ = hdr[156:157]
                size = _tar_num(hdr[124:136])
                padded = (size + 511) & ~511
                if typ in (b"L", b"K", b"x", b"g"):
                    if size > TAR_META_MAX:
                        raise PrepError("tar 的 longname／PAX 標頭太大（%d bytes）" % size)
                    data = t.exact(padded)[:size]
                    if typ == b"L":
                        longname = data.split(b"\0", 1)[0]
                    elif typ == b"x":
                        pax = _pax(data)
                    continue
                name = hdr[0:100].split(b"\0", 1)[0]
                # prefix 只在 POSIX ustar（magic "ustar\0"＋版本 "00"）才有；GNU（"ustar  \0"）的 345 以後是時間與稀疏表
                if hdr[257:265] == b"ustar\x0000" and hdr[345:500].strip(b"\0"):
                    name = hdr[345:500].split(b"\0", 1)[0] + b"/" + name
                if longname is not None:
                    name = longname
                if "path" in pax:
                    name = pax["path"]
                if any(k.startswith("GNU.sparse") for k in pax):
                    raise PrepError("不支援 PAX 格式的稀疏檔（GNU.sparse）")
                if "size" in pax:
                    if not re.fullmatch(rb"[0-9]{1,20}", pax["size"]):
                        raise PrepError("PAX 的 size 格式錯")
                    size = int(pax["size"])
                    padded = (size + 511) & ~511
                longname, pax = None, {}
                n = name.decode("utf-8", "replace")
                n = n[2:] if n.startswith("./") else n
                if n != member:
                    if len(others) < 200:
                        others.append({"name": n[:200], "size": size, "type": typ.decode("ascii", "replace")})
                    t.skip(padded)
                    continue
                if found is not None:
                    raise PrepError("tar 裡有兩個 %s" % member)
                if typ not in (b"0", b"\0", b"S"):
                    raise PrepError("%s 不是一般檔案" % member)
                real, sp = (size, [(0, size)]) if typ != b"S" else _sparse_map(hdr, t)
                if typ == b"S" and sum(n for _o, n in sp) != size:
                    raise PrepError("稀疏表的資料量與標頭的大小不符")
                if real <= 0:
                    raise PrepError("%s 是空檔" % member)
                if real > max_bytes:
                    raise PrepError("%s 的大小 %d 超過上限 %d" % (member, real, max_bytes))
                st = os.statvfs(d)
                if st.f_bavail * st.f_frsize < real + MIN_FREE_AFTER:
                    raise PrepError("剩餘空間不夠解出 %d bytes" % real)
                h, pos = hashlib.sha256(), 0
                for off, n in sp:
                    _hash_zeros(h, off - pos)         # 洞：雜湊算零，檔案用 seek 留洞（不實際寫零）
                    dst.seek(off)
                    left = n
                    while left > 0:
                        b = t.read(min(left, 4 << 20))
                        if not b:
                            raise PrepError("%s 讀不完整（截斷）" % member)
                        h.update(b)
                        dst.write(b)
                        left -= len(b)
                    pos = off + n
                _hash_zeros(h, real - pos)
                dst.truncate(real)
                t.skip(padded - size)
                found = (real, h.hexdigest())
            # tar 結尾之後（通常是補齊的零）一路讀到 xz 串流結尾：xz 的檢查碼與尾端完整性在這時才驗證
            while True:
                b = t.read(4 << 20)
                if not b:
                    break
                if any(b):
                    raise PrepError("tar 結尾之後有非零資料")
        if found is None:
            raise PrepError("tar 裡沒有 %s" % member)
        ok = True
        return found[0], found[1], others
    except (lzma.LZMAError, OSError, EOFError) as e:
        raise PrepError("解開失敗：%s" % type(e).__name__)
    finally:
        if xf is not None:
            xf.close()
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
    base = os.path.dirname(os.path.abspath(jpath))
    doc = {"schema": 1, "image_file": name, "image_sha256": entry.get("sha256")}
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
        doc.update(method="未壓縮，直接使用", disk_bytes=os.path.getsize(src), disk_sha256=entry.get("sha256"))
    else:
        raise PrepError("不認得的映像格式：%s" % name)
    rel = os.path.relpath(os.path.abspath(out), base)
    if rel.startswith(".."):
        raise PrepError("磁碟映像不在輸出資料夾底下")
    doc["disk_image"] = rel                       # 相對於 assemble.json 所在的資料夾（不寫絕對路徑）
    with open(jpath + ".part", "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(jpath + ".part", jpath)
    return OK, "%s → %s（%d bytes）" % (name, os.path.basename(out), doc["disk_bytes"]), doc


def disk_path(jpath):
    """assemble.json 記的磁碟映像（相對路徑）→ 絕對路徑；不能跳出 assemble.json 所在的資料夾、必須是一般檔案。"""
    with open(jpath, encoding="utf-8") as f:
        doc = json.load(f)
    rel = doc.get("disk_image")
    if not isinstance(rel, str) or os.path.isabs(rel) or ".." in rel.split(os.sep):
        raise PrepError("assemble.json 的 disk_image 不合法")
    p = os.path.join(os.path.dirname(os.path.abspath(jpath)), rel)
    if not os.path.isfile(p) or os.path.islink(p):
        raise PrepError("assemble.json 記的磁碟映像不存在（先執行 assemble）")
    return p


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("param")
    p.add_argument("proj"); p.add_argument("ver"); p.add_argument("key")
    f = sub.add_parser("files")
    f.add_argument("proj"); f.add_argument("ver"); f.add_argument("--role")
    k = sub.add_parser("disk")
    k.add_argument("json")
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
        if a.cmd == "disk":
            print(disk_path(a.json))
            return OK
        rc, msg, _doc = prepare(a.proj, a.ver, a.downloads, a.work, a.json)
        print("assemble: %s（%s）" % ({OK: "OK", GAP: "GAP"}[rc], msg))
        return rc
    except Exception as e:      # noqa: BLE001  設定錯誤、讀檔錯誤：FAIL 並寫原因
        tag = "assemble" if a.cmd == "prepare" else "disk_image"
        if isinstance(e, OSError):          # 不印完整路徑（可能含家目錄名稱）
            why = "%s（%s）" % (e.strerror or type(e).__name__, os.path.basename(e.filename or ""))
        else:
            why = str(e)[:300]
        print("%s: FAIL（%s: %s）" % (tag, type(e).__name__, why))
        return FAIL


if __name__ == "__main__":
    sys.exit(main())
