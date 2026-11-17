#!/usr/bin/env python3
"""斷網驗收（T-06 第 2 層，.github/workflows/offline-scan.yml）的判定：scan 期間 runner 帳號有沒有任何對外連線。

用法：python3 -I pipeline/offline-check.py --strace <connect.log> --block on|off --out <offline-check.json>
         [--iptables <封鎖規則的計數檔>] [--docker-events <docker events 的輸出>] [--mirrors <MIRRORS_DIR>]

輸入：
- --strace：`strace -f -e trace=connect -o <檔>` 的紀錄（每行「PID connect(…) = …」）。依位址分類：
  AF_UNIX（本機 socket）、loopback（127.0.0.0/8、::1；systemd-resolved 的 127.0.0.53:53 另外算「名稱查詢」）、其他＝對外。
  紀錄讀不到或是空的 → NOT_RUN（沒有證據，不算 OK）。
- --iptables：`iptables -L DUMPLING_OFFLINE -v -n -x` 與 ip6tables 的輸出（block on 才有）：REJECT 的封包數加總。
- --docker-events：`docker events --filter type=image` 在 scan 期間的輸出：有任何一行（例如 pull）＝映像在 scan 期間被下載。
  docker 由 dockerd（root）執行，iptables 的 owner 比對與 strace 都看不到，所以另外查。
- --mirrors：每個 <資料夾名>.result 的第一行要有 source=internal。

結論 verdict：
- OK：對外連線 0、名稱查詢 0、REJECT 0（block on）、scan 期間沒有映像事件、每個鏡像都是 source=internal。
- FAIL：上面任何一項不符（列在 findings）。
- NOT_RUN：沒有 strace 紀錄。
只寫位址與埠，不寫 AF_UNIX 的路徑（只算數量）。最後一行印「offline-check: <verdict>（…）」；結束碼 OK＝0、FAIL＝1、NOT_RUN＝2、用法錯誤＝64。
說明：這是封住 runner 帳號的出站，不是「真的沒有外網」；DT 容器自己的連線不在範圍（等於常駐 DT 有自己的資料源，T-14）。
"""
import argparse
import ipaddress
import json
import os
import re
import sys

CONNECT_RE = re.compile(r"connect\(\d+, \{sa_family=(AF_[A-Z0-9]+)(.*?)\}, \d+\) = (-?\d+)(?: (E[A-Z]+))?")
V4_RE = re.compile(r'sin_port=htons\((\d+)\), sin_addr=inet_addr\("([0-9.]+)"\)')
V6_RE = re.compile(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([0-9a-fA-F:.]+)"')
DNS = (ipaddress.ip_address("127.0.0.53"), 53)


def classify(family, rest):
    """→ ("unix"|"loopback"|"dns"|"external"|"other", 位址, 埠)。"""
    if family == "AF_UNIX":
        return "unix", None, None
    m = V4_RE.search(rest) if family == "AF_INET" else V6_RE.search(rest) if family == "AF_INET6" else None
    if not m:
        return "other", None, None
    port = int(m.group(1))
    try:
        ip = ipaddress.ip_address(m.group(2))
    except ValueError:
        return "other", None, None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if (ip, port) == DNS:
        return "dns", str(ip), port
    if ip.is_loopback:
        return "loopback", str(ip), port
    if ip.is_unspecified:            # connect 到 0.0.0.0／:: 其實是本機
        return "loopback", str(ip), port
    return "external", str(ip), port


def read_strace(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    counts = {"unix": 0, "loopback": 0, "dns": 0, "other": 0}
    external = {}
    n = 0
    for line in lines:
        m = CONNECT_RE.search(line)
        if not m:
            continue
        n += 1
        kind, ip, port = classify(m.group(1), m.group(2))
        if kind == "external":
            key = (ip, port)
            e = external.setdefault(key, {"addr": ip, "port": port, "count": 0, "results": []})
            e["count"] += 1
            res = m.group(4) or ("ok" if m.group(3) == "0" else m.group(3))
            if res not in e["results"]:
                e["results"].append(res)
        else:
            counts[kind] += 1
    return {"connects": n, **counts, "external": sorted(external.values(), key=lambda e: (-e["count"], e["addr"], e["port"]))}


def read_rejects(path):
    """iptables -L -v -n -x 的輸出：REJECT 那幾列第一欄（封包數）加總；讀不到 → None。"""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    total, seen = 0, False
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "REJECT" and parts[0].isdigit():
            total += int(parts[0])
            seen = True
    return total if seen else None


def read_docker_events(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return [l for l in f.read().splitlines() if l.strip()]
    except OSError:
        return None


def read_mirrors(d):
    out = []
    try:
        names = sorted(n for n in os.listdir(d) if n.endswith(".result"))
    except OSError:
        return None
    for n in names:
        try:
            with open(os.path.join(d, n), encoding="utf-8", errors="replace") as f:
                first = f.readline().split()
        except OSError:
            first = []
        out.append({"mirror": n[:-len(".result")], "internal": "source=internal" in first,
                    "status": first[0] if first and first[0] in ("OK", "ATTENTION") else "UNKNOWN"})
    return out


def judge(block, st, rejects, events, mirrors):
    findings = []
    if st is None or st["connects"] == 0:
        return "NOT_RUN", ["沒有 strace 的 connect 紀錄（沒有證據）"]
    if st["external"]:
        findings.append("對外連線 %d 個目的地：%s" % (len(st["external"]), "、".join(
            "%s:%d×%d（%s）" % (e["addr"], e["port"], e["count"], "/".join(e["results"])) for e in st["external"][:20])))
    if st["dns"]:
        findings.append("名稱查詢（127.0.0.53:53）%d 次：有程式試著找外部主機" % st["dns"])
    if block == "on":
        if rejects is None:
            findings.append("讀不到封鎖規則的計數（--iptables）")
        elif rejects:
            findings.append("封鎖規則擋下 %d 個封包" % rejects)
    if events is None:
        findings.append("沒有 docker events 的紀錄（--docker-events）")
    elif events:
        findings.append("scan 期間有 %d 個映像事件（例如 docker pull）" % len(events))
    if mirrors is None:
        findings.append("讀不到鏡像資料夾（--mirrors）")
    else:
        if not mirrors:
            findings.append("鏡像資料夾裡沒有任何 .result")
        bad = [m["mirror"] for m in mirrors if not m["internal"]]
        if bad:
            findings.append("不是內部鏡像：%s" % "、".join(bad))
    return ("FAIL" if findings else "OK"), findings


def main(argv=None):
    ap = argparse.ArgumentParser(description="斷網驗收的判定（T-06 第 2 層）")
    ap.add_argument("--strace", required=True)
    ap.add_argument("--block", required=True, choices=("on", "off"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--iptables")
    ap.add_argument("--docker-events")
    ap.add_argument("--mirrors")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    st = read_strace(a.strace)
    rejects = read_rejects(a.iptables) if a.iptables else None
    events = read_docker_events(a.docker_events) if a.docker_events else None
    mirrors = read_mirrors(a.mirrors) if a.mirrors else None
    verdict, findings = judge(a.block, st, rejects, events, mirrors)
    doc = {"schema": 1, "block": a.block, "verdict": verdict, "findings": findings, "strace": st, "iptables_rejects": rejects,
           "docker_image_events": None if events is None else len(events), "mirrors": mirrors}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    s = st or {}
    print("offline-check: %s（block=%s；connect %s 次：本機 socket %s、loopback %s、名稱查詢 %s、對外 %s 個目的地；REJECT %s；映像事件 %s%s）" % (
        verdict, a.block, s.get("connects", 0), s.get("unix", 0), s.get("loopback", 0), s.get("dns", 0), len(s.get("external") or []),
        "—" if rejects is None else rejects, "—" if events is None else len(events), "；" + "；".join(findings) if findings else ""))
    return {"OK": 0, "FAIL": 1, "NOT_RUN": 2}[verdict]


if __name__ == "__main__":
    sys.exit(main())
