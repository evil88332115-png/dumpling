"""下載韌體公開樣本並核對 sha256／大小（只下載，不解開、不執行）。

用法：python3 -I firmware_fetch.py <firmware.yml>... --out <目錄>
每個樣本印一行：FIRMWARE-FETCH<TAB>OK|GAP|FAIL<TAB><型號><TAB>說明；有 FAIL 就以非 0 結束。
"""
import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys

try:
    import yaml
except ImportError:  # 在 main() 回報 FAIL
    yaml = None

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
KINDS = ("bios", "vbios", "sbom")
STATUSES = ("ok", "GAP")
ROLES = ("image", "source", "package", "sbom")
ALWAYS_REQUIRED = ("kind", "vendor", "model", "status", "notes")
OK_REQUIRED = ("firmware_version", "ibv", "files", "license")
FILE_REQUIRED = ("name", "url", "sha256", "size", "role")
LICENSE_REQUIRED = ("name", "url", "note")


def validate(doc):
    """回傳錯誤訊息清單；空清單代表欄位齊全。"""
    if not isinstance(doc, dict):
        return ["清單不是 mapping"]
    errs = []
    for k in ALWAYS_REQUIRED:
        if not doc.get(k):
            errs.append("缺欄位 " + k)
    if doc.get("kind") and doc["kind"] not in KINDS:
        errs.append("kind 必須是 " + "/".join(KINDS))
    status = doc.get("status")
    if status and status not in STATUSES:
        errs.append("status 必須是 " + "/".join(STATUSES))
    if status != "ok":
        return errs
    for k in OK_REQUIRED:
        if not doc.get(k):
            errs.append("缺欄位 " + k)
    lic = doc.get("license")
    if isinstance(lic, dict):
        for k in LICENSE_REQUIRED:
            if not lic.get(k):
                errs.append("license 缺 " + k)
    elif lic:
        errs.append("license 必須是 mapping")
    files = doc.get("files")
    if files and not isinstance(files, list):
        errs.append("files 必須是清單")
        files = None
    names = set()
    for i, f in enumerate(files or []):
        if not isinstance(f, dict):
            errs.append("files[%d] 不是 mapping" % i)
            continue
        for k in FILE_REQUIRED:
            if f.get(k) in (None, ""):
                errs.append("files[%d] 缺 %s" % (i, k))
        name = f.get("name")
        if name:
            if not isinstance(name, str) or not NAME_RE.match(name):
                errs.append("files[%d] name 不合法" % i)
            elif name in names:
                errs.append("files[%d] name 重複" % i)
            names.add(name)
        url = f.get("url")
        if url and not (isinstance(url, str) and url.startswith("https://")):
            errs.append("files[%d] url 必須是 https" % i)
        sha = f.get("sha256")
        if sha and not (isinstance(sha, str) and SHA256_RE.match(sha)):
            errs.append("files[%d] sha256 必須是 64 位小寫十六進位" % i)
        size = f.get("size")
        if size not in (None, "") and (not isinstance(size, int) or isinstance(size, bool) or size <= 0):
            errs.append("files[%d] size 必須是正整數" % i)
        if f.get("role") and f["role"] not in ROLES:
            errs.append("files[%d] role 必須是 %s" % (i, "/".join(ROLES)))
        # sbom 只能搭 role: sbom，其他 kind 不能用 role: sbom（不放寬其他規則）
        if f.get("role") and doc.get("kind") in KINDS and (doc["kind"] == "sbom") != (f["role"] == "sbom"):
            errs.append("files[%d] role: sbom 只能用在 kind: sbom，kind: sbom 只能用 role: sbom" % i)
    return errs


def curl_download(url, dest, max_size):
    """用 curl 下載到 dest；回傳錯誤訊息或 None。"""
    cmd = ["curl", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
           "--silent", "--show-error", "--max-filesize", str(max_size),
           "--retry", "2", "--connect-timeout", "30", "--max-time", "1800",
           "--output", dest, "--", url]
    r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if r.returncode != 0:
        return "curl 失敗（exit %d）%s" % (r.returncode, r.stderr.strip()[:200])
    return None


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_file(path, size, sha):
    """核對大小與 sha256；回傳錯誤訊息或 None。path 必須是一般檔案。"""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        return "不是一般檔案"
    if st.st_size != size:
        return "大小不符（實際 %d，預期 %d）" % (st.st_size, size)
    got = sha256_of(path)
    if got != sha:
        return "sha256 不符（實際 %s）" % got
    return None


def _lstat(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def fetch_one(entry, dest_dir, downloader=curl_download):
    """處理 files 的一項；回傳 (ok, 說明)。"""
    name, url, sha, size = entry["name"], entry["url"], entry["sha256"], entry["size"]
    final = os.path.join(dest_dir, name)
    tmp = os.path.join(dest_dir, "." + name + ".part")
    st = _lstat(final)
    if st is not None:
        if not stat.S_ISREG(st.st_mode):
            return False, "%s 已存在且不是一般檔案（拒絕）" % name
        if check_file(final, size, sha) is None:
            return True, "%s 已存在且核對相符" % name
        os.unlink(final)
    st = _lstat(tmp)
    if st is not None:
        if not stat.S_ISREG(st.st_mode):
            return False, "%s 暫存名已存在且不是一般檔案（拒絕）" % name
        os.unlink(tmp)
    err = downloader(url, tmp, size)
    if err is None and _lstat(tmp) is None:
        err = "下載後沒有檔案"
    if err is None:
        err = check_file(tmp, size, sha)
    if err is not None:
        if _lstat(tmp) is not None:
            os.unlink(tmp)
        return False, "%s %s" % (name, err)
    os.replace(tmp, final)
    return True, "%s 已下載並核對（%d 位元組）" % (name, size)


def process(path, out_root, downloader=curl_download):
    """處理一份清單；回傳 (狀態, 型號, 說明)。"""
    model = os.path.basename(os.path.dirname(os.path.abspath(path)))
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except Exception as e:  # 格式錯誤一律 FAIL
        return "FAIL", model, "讀不到清單：%s" % type(e).__name__
    if isinstance(doc, dict) and doc.get("model"):
        model = str(doc["model"])
    errs = validate(doc)
    if errs:
        return "FAIL", model, "清單欄位錯誤：" + "；".join(errs)
    if doc["status"] == "GAP":
        return "GAP", model, str(doc["notes"]).strip().splitlines()[0]
    slug = os.path.basename(os.path.dirname(os.path.abspath(path)))
    dest_dir = os.path.join(out_root, doc["kind"], slug)
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except OSError as e:
        return "FAIL", model, "無法建立輸出目錄：%s" % e.strerror
    if os.path.islink(dest_dir):
        return "FAIL", model, "輸出目錄是 symlink（拒絕）"
    msgs, ok = [], True
    for f in doc["files"]:
        good, msg = fetch_one(f, dest_dir, downloader)
        ok = ok and good
        msgs.append(msg)
    return ("OK" if ok else "FAIL"), model, "；".join(msgs)


def main(argv=None, downloader=curl_download):
    ap = argparse.ArgumentParser(description="下載韌體樣本並核對 sha256")
    ap.add_argument("manifests", nargs="+")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    if yaml is None:
        print("FIRMWARE-FETCH\tFAIL\t-\t缺少 PyYAML（Ubuntu：apt install python3-yaml）")
        return 1
    failed = False
    for m in args.manifests:
        status, model, msg = process(m, args.out, downloader)
        print("FIRMWARE-FETCH\t%s\t%s\t%s" % (status, model, msg.replace("\t", " ").replace("\n", " ")), flush=True)
        failed = failed or status == "FAIL"
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
