"""安全解開不可信的 tar（.tbz2／.tar.*）到全新的資料夾，不執行裡面任何東西。

用法：python3 -I safe_extract.py <壓縮檔> <目的資料夾> [--list-only] [--allow-nonempty]
      （目的資料夾預設要不存在或是空的；--allow-nonempty 給「把幾個元件包解到同一個資料夾」用）

規則（任何一條違反就停止，結束碼 1，不留下半成品以外的承諾）：
- 成員名稱不能是絕對路徑、不能含 `..`
- 不收裝置檔、FIFO；符號連結與硬連結必須指向目的資料夾以內（絕對路徑的符號連結也拒絕）
- 用 tarfile 的 `data` 過濾器解開（不還原擁有者，清掉 setuid／setgid、群組與其他人的寫入權限）
- 解完再走一遍目的資料夾：不能有特殊檔案、符號連結不能跳出目的資料夾
最後印一行 JSON：成員數、總位元組、符號連結數、硬連結數。

來源：M2 試驗（wp1/m2-spike）的 tools/spike/m2_safe_extract.py，改成可 import 的函式並加測試。
"""
import json
import os
import stat as S
import sys
import tarfile


class UnsafeArchive(Exception):
    """壓縮檔含有不安全的成員，或目的資料夾不合規則。"""


def _inside(root, path):
    root = os.path.realpath(root)
    p = os.path.realpath(path)
    return p == root or p.startswith(root + os.sep)


def check_member(m, dest):
    """檢查一個 tar 成員；不安全就丟 UnsafeArchive。dest 是已 realpath 的目的資料夾。"""
    n = m.name
    if n.startswith("/") or ".." in n.replace("\\", "/").split("/"):
        raise UnsafeArchive("路徑不安全 %r" % n)
    if m.isdev() or m.isfifo():
        raise UnsafeArchive("裝置檔或 FIFO %r" % n)
    if m.issym():
        t = m.linkname
        full = t if os.path.isabs(t) else os.path.join(os.path.dirname(os.path.join(dest, n)), t)
        if os.path.isabs(t) or not _inside(dest, os.path.normpath(full)):
            raise UnsafeArchive("符號連結跳出目的資料夾 %r -> %r" % (n, t))
    if m.islnk():
        t = m.linkname
        if t.startswith("/") or ".." in t.split("/"):
            raise UnsafeArchive("硬連結目標不安全 %r -> %r" % (n, t))


def verify_tree(dest):
    """解開之後再走一遍：只能有一般檔案、資料夾、不跳出的符號連結。"""
    dest = os.path.realpath(dest)
    for root, dirs, files in os.walk(dest):
        for name in dirs + files:
            p = os.path.join(root, name)
            st = os.lstat(p)
            if not (S.S_ISREG(st.st_mode) or S.S_ISDIR(st.st_mode) or S.S_ISLNK(st.st_mode)):
                raise UnsafeArchive("解開後出現特殊檔案 %r" % p)
            if S.S_ISLNK(st.st_mode):
                t = os.readlink(p)
                if os.path.isabs(t) or not _inside(dest, os.path.join(os.path.dirname(p), t)):
                    raise UnsafeArchive("解開後的符號連結跳出目的資料夾 %r -> %r" % (p, t))


def extract(archive, dest, list_only=False, allow_nonempty=False):
    """串流讀 archive，逐一檢查並解開到 dest；回傳統計 dict。"""
    if os.path.lexists(dest) and os.path.islink(dest):
        raise UnsafeArchive("目的資料夾是符號連結")
    if os.path.isdir(dest) and os.listdir(dest) and not allow_nonempty:
        raise UnsafeArchive("目的資料夾不是空的：%s" % dest)
    os.makedirs(dest, exist_ok=True)
    dest = os.path.realpath(dest)
    stats = {"members": 0, "bytes": 0, "symlinks": 0, "hardlinks": 0}
    with tarfile.open(archive, "r|*") as tf:
        for m in tf:
            check_member(m, dest)
            stats["members"] += 1
            stats["bytes"] += m.size if m.isreg() else 0
            stats["symlinks"] += int(m.issym())
            stats["hardlinks"] += int(m.islnk())
            if not list_only:
                tf.extract(m, dest, filter="data")
    if not list_only:
        verify_tree(dest)
    return stats


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 2 or any(a.startswith("--") and a not in ("--list-only", "--allow-nonempty") for a in argv):
        print(__doc__)
        return 64
    try:
        stats = extract(args[0], args[1], list_only="--list-only" in argv, allow_nonempty="--allow-nonempty" in argv)
    except UnsafeArchive as e:
        print("拒絕：%s" % e)
        return 1
    except (OSError, tarfile.TarError, EOFError) as e:
        print("解開失敗：%s" % type(e).__name__)
        return 1
    print(json.dumps(stats))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
