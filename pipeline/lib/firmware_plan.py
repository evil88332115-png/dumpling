"""列出某個樣本要交給 firmware-bios.sh 的輸入檔（CI 用）。只讀、不執行下載檔的內容。

用法：python3 -I firmware_plan.py <firmware.yml> --dl <下載資料夾> --work <工作資料夾>
輸出：每行一個輸入檔路徑；沒有可解析的檔案（status 不是 ok、kind 不是 bios、沒有 image／package）就什麼都不印。
firmware.yml 的 analyze 欄位：[{from: <files 裡的 package 檔名>, member: <deb 內的成員路徑>}]，
該 package 會先用 dpkg-deb --fsys-tarfile 搭配 tar 只取出這一個成員（拒絕 symlink／非一般檔案）到 work 資料夾，改用取出的檔案。
"""
import argparse
import os
import re
import stat
import subprocess
import sys

try:
    import yaml
except ImportError:
    yaml = None

MEMBER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]*$")


def extract_member(deb, member, dest_dir, run=subprocess.run):
    """從 deb 取出單一成員；回傳取出的路徑。失敗 raise ValueError。"""
    if not MEMBER_RE.match(member) or ".." in member.split("/"):
        raise ValueError("member 不合法：%s" % member)
    os.makedirs(dest_dir, exist_ok=True)
    tar_in = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", deb], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
    try:
        r = run(["tar", "-x", "--no-same-owner", "--no-same-permissions", "-C", dest_dir, "./" + member],
                stdin=tar_in.stdout, capture_output=True, text=True)
    finally:
        tar_in.stdout.close()
        tar_in.wait()
    if tar_in.returncode != 0 or r.returncode != 0:
        raise ValueError("取出 %s 失敗：%s" % (member, (r.stderr or "").strip()[:200]))
    path = os.path.join(dest_dir, member)
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("%s 不是一般檔案" % member)
    return path


def plan(doc, dl_dir, work_dir, extract=extract_member):
    if doc.get("kind") != "bios" or doc.get("status") != "ok":
        return []
    files = doc.get("files") or []
    an = doc.get("analyze") or []
    if not isinstance(an, list):
        raise ValueError("analyze 必須是清單")
    by_name = {f["name"]: f for f in files if isinstance(f, dict) and f.get("name")}
    ex = {}
    for i, a in enumerate(an):
        if not isinstance(a, dict) or set(a) != {"from", "member"} or not all(isinstance(v, str) for v in a.values()):
            raise ValueError("analyze[%d] 必須剛好有 from、member（字串）" % i)
        if a["from"] not in by_name or by_name[a["from"]].get("role") != "package":
            raise ValueError("analyze[%d].from 必須是 files 裡 role: package 的檔名" % i)
        ex.setdefault(a["from"], []).append(a["member"])
    out = []
    for f in files:
        if f.get("role") not in ("image", "package"):
            continue
        src = os.path.join(dl_dir, doc["kind"], doc["_slug"], f["name"])
        if f["name"] in ex:
            for m in ex[f["name"]]:
                out.append(extract(src, m, os.path.join(work_dir, doc["_slug"], f["name"] + ".d")))
        else:
            out.append(src)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument("manifest")
    ap.add_argument("--dl", required=True)
    ap.add_argument("--work", required=True)
    a = ap.parse_args(argv)
    if yaml is None:
        print("缺少 PyYAML", file=sys.stderr)
        return 64
    try:
        with open(a.manifest, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict):
            raise ValueError("firmware.yml 不是 mapping")
        doc["_slug"] = os.path.basename(os.path.dirname(os.path.abspath(a.manifest)))
        for p in plan(doc, a.dl, a.work):
            print(p)
    except (ValueError, OSError, yaml.YAMLError) as e:
        print("firmware_plan：%s" % e, file=sys.stderr)
        return 64
    return 0


if __name__ == "__main__":
    sys.exit(main())
