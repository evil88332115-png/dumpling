#!/usr/bin/env python3
"""leakscan.py：找出含有秘密字串的檔案。秘密從檔案讀（一行一個），不放在指令列（避免出現在 ps 與 /proc/*/cmdline）。

用法：python3 -I leakscan.py <秘密清單檔> <檔案或資料夾...>
印出含有任一秘密的檔案路徑（一行一個）；退出碼 0。秘密清單檔讀不到 → 退出碼 3。
"""
import os
import sys


def scan(secret_file, paths):
    with open(secret_file, "rb") as f:
        secrets = [l.rstrip(b"\r\n") for l in f if l.strip()]
    hits = []
    if not secrets:
        return hits
    files = []
    for p in paths:
        if os.path.isdir(p):
            for d, _, fs in os.walk(p):
                files += [os.path.join(d, x) for x in fs]
        elif os.path.isfile(p):
            files.append(p)
    for fp in sorted(files):
        try:
            with open(fp, "rb") as f:
                data = f.read()
        except OSError:
            continue
        if any(s in data for s in secrets):
            hits.append(fp)
    return hits


def main(argv=None):
    a = sys.argv[1:] if argv is None else argv
    if len(a) < 2:
        print("用法：leakscan.py <秘密清單檔> <檔案或資料夾...>", file=sys.stderr)
        return 3
    try:
        for h in scan(a[0], a[1:]):
            print(h)
    except OSError:
        print("讀不到秘密清單檔", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
