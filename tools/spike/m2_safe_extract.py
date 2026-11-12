"""M2 spike：安全解開不可信的 tar（.tbz2／.tar.*）到全新的資料夾，不執行裡面任何東西。

用法：python3 -I m2_safe_extract.py <壓縮檔> <目的資料夾（不存在或空的）> [--list-only]

規則（任何一條違反就停止，退出碼 1）：
- 成員名稱不能是絕對路徑、不能含 `..`
- 不收裝置檔、FIFO；符號連結與硬連結必須指向目的資料夾以內
- 用 tarfile 的 `data` 過濾器解開（不還原擁有者，清掉 setuid／setgid、群組與其他人的寫入權限）
- 解完再走一遍目的資料夾：不能有特殊檔案、符號連結不能跳出目的資料夾
最後印一行 JSON：成員數、總位元組、符號連結數、硬連結數。
"""
import json
import os
import stat as S
import sys
import tarfile


def inside(root, path):
    root = os.path.realpath(root)
    p = os.path.realpath(path)
    return p == root or p.startswith(root + os.sep)


def check_member(m, dest):
    n = m.name
    if n.startswith("/") or ".." in n.replace("\\", "/").split("/"):
        raise SystemExit(f"拒絕：路徑不安全 {n!r}")
    if m.isdev() or m.isfifo():
        raise SystemExit(f"拒絕：裝置檔或 FIFO {n!r}")
    if m.issym():
        t = m.linkname
        full = t if os.path.isabs(t) else os.path.join(os.path.dirname(os.path.join(dest, n)), t)
        if os.path.isabs(t) or not inside(dest, os.path.normpath(full)):
            raise SystemExit(f"拒絕：符號連結跳出目的資料夾 {n!r} -> {t!r}")
    if m.islnk():
        t = m.linkname
        if t.startswith("/") or ".." in t.split("/"):
            raise SystemExit(f"拒絕：硬連結目標不安全 {n!r} -> {t!r}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    list_only = "--list-only" in sys.argv
    if len(args) != 2:
        raise SystemExit(__doc__)
    arc, dest = args
    if os.path.exists(dest) and os.listdir(dest):
        raise SystemExit(f"目的資料夾不是空的：{dest}")
    os.makedirs(dest, exist_ok=True)
    dest = os.path.realpath(dest)
    stats = {"members": 0, "bytes": 0, "symlinks": 0, "hardlinks": 0}
    with tarfile.open(arc, "r|*") as tf:
        for m in tf:
            check_member(m, dest)
            stats["members"] += 1
            stats["bytes"] += m.size if m.isreg() else 0
            stats["symlinks"] += m.issym()
            stats["hardlinks"] += m.islnk()
            if not list_only:
                tf.extract(m, dest, filter="data")
    if not list_only:
        for root, dirs, files in os.walk(dest):
            for name in dirs + files:
                p = os.path.join(root, name)
                st = os.lstat(p)
                if not (S.S_ISREG(st.st_mode) or S.S_ISDIR(st.st_mode) or S.S_ISLNK(st.st_mode)):
                    raise SystemExit(f"拒絕：解開後出現特殊檔案 {p!r}")
                if S.S_ISLNK(st.st_mode):
                    t = os.readlink(p)
                    if os.path.isabs(t) or not inside(dest, os.path.join(os.path.dirname(p), t)):
                        raise SystemExit(f"拒絕：解開後的符號連結跳出目的資料夾 {p!r} -> {t!r}")
    print(json.dumps(stats))


if __name__ == "__main__":
    main()
