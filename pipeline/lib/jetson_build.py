"""Jetson 轉接器 build 步驟的 Python 部分（pipeline/platforms/jetson/build.sh 呼叫）。

子命令（都用 `python3 -I` 執行；下載的壓縮檔是不可信資料，這裡只算雜湊、列清單，解壓一律交給 safe_extract.py）：

  components <public_sources_sha.txt> <元件資料夾> [--require 名稱 ...]
      核對元件包（<名稱>.tbz2）的 SHA-1 與 NVIDIA 公布的清單（public_sources_sha.txt）。清單裡每個「檔案存在於元件資料夾」的項目都核對；
      --require 指定的元件（編核心要用的四個）一定要存在而且相符。清單列自己（public_sources_sha.txt）那一行不核對（自己的雜湊不可能寫在自己裡面）。
      輸出一行 JSON（checked、matched、required）；不符退出 1。

  patches <專案資料夾> <版本>
      讀 sources.yml 該版本的 platform_params.patches，檢查檔案都在 patches/ 底下（只允許檔名、不含路徑）、依序印出
      「<目錄>TAB<檔案路徑>TAB<sha256>」。patches 不存在或是空清單 = 這個版本沒有 patch。
      patches 的項目：字串（檔名；套在核心樹 kernel/kernel-noble）或 {file: 檔名, dir: 原始碼根底下的相對資料夾}。
      patches/ 底下有 .patch 檔沒被任何版本列出 → 只警告（stderr），不失敗。

  files <專案資料夾> <版本>
      印出 sources.yml 該版本每個檔案的「role<TAB>name」（assemble 用它找 BSP 與範例 rootfs 的檔名）。
"""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import project_config as pc  # noqa: E402

DEFAULT_PATCH_DIR = "kernel/kernel-noble"
PATCH_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,120}\.(patch|diff)$")
DIR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,120}$")
COMP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*\.tbz2$")


class BuildError(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def sha1_file(path):
    h = hashlib.sha1()  # noqa: S324 — NVIDIA 公布的是 SHA-1，要和它核對
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def parse_sha_list(text):
    """public_sources_sha.txt（sha1sum 格式「雜湊 *檔名」）→ {檔名: sha1}。格式不對的行忽略；同名重複是錯誤。"""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([0-9a-f]{40})\s+\*?(\S+)$", line.strip())
        if not m:
            continue
        name = m.group(2)
        if name in out:
            raise BuildError("清單裡 %s 重複" % name)
        out[name] = m.group(1)
    return out


def check_components(sha_text, comp_dir, required=()):
    """回傳 dict(checked, matched, mismatched[], missing_required[])；任何不符或必要元件缺少就丟 BuildError。"""
    listed = parse_sha_list(sha_text)
    checked = matched = 0
    bad = []
    for name, want in sorted(listed.items()):
        if not COMP_RE.match(name):
            continue  # .sha1sum、.sh、清單自己
        p = os.path.join(comp_dir, name)
        if not os.path.isfile(p) or os.path.islink(p):
            continue
        checked += 1
        got = sha1_file(p)
        if got == want:
            matched += 1
        else:
            bad.append("%s（算出 %s，公布 %s）" % (name, got, want))
    missing = [r for r in required if r not in listed or not os.path.isfile(os.path.join(comp_dir, r))]
    if missing:
        raise BuildError("必要元件缺少或不在清單：%s" % "、".join(missing))
    if bad:
        raise BuildError("元件 SHA-1 和 NVIDIA 公布的不符：%s" % "；".join(bad))
    if checked == 0:
        raise BuildError("沒有任何元件可核對")
    return {"checked": checked, "matched": matched, "required": list(required)}


def release_patches(project_dir, version):
    """→ [(目錄, 檔案絕對路徑, sha256)]。錯誤丟 BuildError。"""
    try:
        sources = pc.load_sources(os.path.join(project_dir, "sources.yml"))
    except pc.ConfigError as e:
        raise BuildError(str(e))
    rel = sources["releases"].get(version)
    if rel is None:
        raise BuildError("sources.yml 沒有版本 %s" % version)
    entries = (rel.get("platform_params") or {}).get("patches") or []
    if not isinstance(entries, list):
        raise BuildError("platform_params.patches 必須是清單")
    pdir = os.path.join(project_dir, "patches")
    out, seen = [], set()
    for e in entries:
        if isinstance(e, str):
            fname, d = e, DEFAULT_PATCH_DIR
        elif isinstance(e, dict) and set(e) <= {"file", "dir"} and isinstance(e.get("file"), str):
            fname, d = e["file"], e.get("dir", DEFAULT_PATCH_DIR)
        else:
            raise BuildError("patches 的項目必須是檔名字串，或 {file, dir}")
        if not PATCH_NAME_RE.match(fname):
            raise BuildError("patch 檔名不合法（只收檔名，不含路徑）：%r" % fname[:60])
        if not (isinstance(d, str) and DIR_RE.match(d) and ".." not in d.split("/") and not d.startswith("/")):
            raise BuildError("patch 的 dir 不合法：%r" % str(d)[:60])
        p = os.path.join(pdir, fname)
        if os.path.islink(p) or not os.path.isfile(p):
            raise BuildError("patches/ 裡沒有 %s（或是符號連結）" % fname)
        if fname in seen:
            raise BuildError("patch %s 重複列出" % fname)
        seen.add(fname)
        out.append((d, p, sha256_file(p)))
    return out


def unlisted_patches(project_dir):
    """patches/ 底下沒有被任何版本列出的 .patch／.diff 檔名。"""
    try:
        sources = pc.load_sources(os.path.join(project_dir, "sources.yml"))
    except pc.ConfigError:
        return []
    listed = set()
    for rel in sources["releases"].values():
        for e in (rel.get("platform_params") or {}).get("patches") or []:
            listed.add(e if isinstance(e, str) else (e.get("file") if isinstance(e, dict) else None))
    pdir = os.path.join(project_dir, "patches")
    if not os.path.isdir(pdir):
        return []
    return sorted(f for f in os.listdir(pdir) if PATCH_NAME_RE.match(f) and f not in listed)


def main(argv):
    if not argv:
        print(__doc__)
        return 64
    cmd = argv[0]
    try:
        if cmd == "components" and len(argv) >= 3:
            req = []
            if "--require" in argv:
                i = argv.index("--require")
                req = argv[i + 1:]
                argv = argv[:i]
            with open(argv[1], encoding="utf-8", errors="replace") as f:
                res = check_components(f.read(), argv[2], req)
            print(json.dumps(res))
            return 0
        if cmd == "files" and len(argv) == 3:
            sources = pc.load_sources(os.path.join(argv[1], "sources.yml"))
            rel = sources["releases"].get(argv[2])
            if rel is None:
                raise BuildError("sources.yml 沒有版本 %s" % argv[2])
            for f in rel["files"]:
                print("%s\t%s" % (f.get("role", ""), f["name"]))
            return 0
        if cmd == "patches" and len(argv) == 3:
            for d, p, h in release_patches(argv[1], argv[2]):
                print("%s\t%s\t%s" % (d, p, h))
            for f in unlisted_patches(argv[1]):
                print("警告：patches/%s 沒有被任何版本列出，不會套用" % f, file=sys.stderr)
            return 0
    except (BuildError, pc.ConfigError) as e:
        print("jetson_build: FAIL（%s）" % e)
        return 1
    except OSError as e:
        print("jetson_build: FAIL（%s）" % type(e).__name__)
        return 1
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
