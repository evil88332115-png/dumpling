"""M2 spike：只讀 tar 的成員清單（串流，不解開、不寫檔），統計刷機包組裝要注意的項目。

用法：python3 -I m2_tar_stats.py <壓縮檔>
印一行 JSON：成員數、一般檔案總位元組、目錄／符號連結／硬連結數、裝置檔／FIFO 數、
絕對路徑或含 .. 的成員數、指向目的資料夾以外的符號連結數（絕對連結不算跳出：rootfs 內的絕對連結是正常的，另外計）、
setuid／setgid 檔案數、擁有者不是 root 的成員數。
"""
import json
import os
import sys
import tarfile


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    st = dict(members=0, reg_bytes=0, dirs=0, symlinks=0, hardlinks=0, devices=0, fifos=0,
              bad_names=0, symlink_escape_relative=0, symlink_absolute=0, setuid_setgid=0, non_root_owner=0)
    with tarfile.open(sys.argv[1], "r|*") as tf:
        for m in tf:
            st["members"] += 1
            n = m.name
            if n.startswith("/") or ".." in n.split("/"):
                st["bad_names"] += 1
            if m.isreg():
                st["reg_bytes"] += m.size
            elif m.isdir():
                st["dirs"] += 1
            elif m.issym():
                st["symlinks"] += 1
                t = m.linkname
                if os.path.isabs(t):
                    st["symlink_absolute"] += 1
                else:
                    full = os.path.normpath(os.path.join(os.path.dirname(n), t))
                    if full.startswith("..") or full.startswith("/"):
                        st["symlink_escape_relative"] += 1
            elif m.islnk():
                st["hardlinks"] += 1
            elif m.isdev():
                st["devices"] += 1
            elif m.isfifo():
                st["fifos"] += 1
            if m.mode & 0o6000:
                st["setuid_setgid"] += 1
            if m.uid != 0 or m.gid != 0:
                st["non_root_owner"] += 1
    print(json.dumps(st))


if __name__ == "__main__":
    main()
