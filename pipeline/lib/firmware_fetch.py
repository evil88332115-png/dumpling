"""下載韌體公開樣本並核對 sha256／大小（只下載，不解開、不執行）。

用法：python3 -I firmware_fetch.py <firmware.yml>... --out <目錄>
下載與核對（只允許 https、先寫 .part、核對大小與 sha256 才改名、拒絕 symlink）用共用的 pipeline/lib/fetch_verify.py；
這裡只負責清單欄位檢查（size 一定要有）與輸出格式。
每個樣本印一行：FIRMWARE-FETCH<TAB>OK|GAP|FAIL<TAB><型號><TAB>說明；有 FAIL 就以非 0 結束。
"""
import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # Python 3.11 起 -I 含 -P，不會自動把腳本所在目錄放進 sys.path
import fetch_verify  # noqa: E402  共用實作（C1）
from fetch_verify import check_file, curl_download, fetch_one, sha256_of  # noqa: E402,F401

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
            if not isinstance(name, str) or not NAME_RE.fullmatch(name):
                errs.append("files[%d] name 不合法" % i)
            elif name in names:
                errs.append("files[%d] name 重複" % i)
            names.add(name)
        url = f.get("url")
        if url and not (isinstance(url, str) and url.startswith("https://")):
            errs.append("files[%d] url 必須是 https" % i)
        sha = f.get("sha256")
        if sha and not (isinstance(sha, str) and SHA256_RE.fullmatch(sha)):
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
