"""暫時的探測：從 Linux 核心 CNA 紀錄找「只改 1 個檔案、能乾淨套到這份核心原始碼、而且尚未套用」的上游修補。用法：find_patch.py <核心樹> <vulns.git 資料夾> <輸出資料夾>"""
import json, os, re, subprocess, sys, urllib.request, glob
tree, vulns, out = sys.argv[1:4]
os.makedirs(out, exist_ok=True)
files = sorted(glob.glob(os.path.join(vulns, "cve/published/202[456]/CVE-*.json")), reverse=True)
print("CNA 紀錄數", len(files))
found = 0
tried = 0
for f in files:
    d = json.load(open(f))
    cna = d.get("containers", {}).get("cna", {})
    pf = set()
    for a in cna.get("affected", []):
        pf.update(a.get("programFiles") or [])
    if len(pf) != 1:
        continue
    path = next(iter(pf))
    if not os.path.isfile(os.path.join(tree, path)):
        continue
    if not (path.startswith(("net/", "fs/", "kernel/", "mm/", "drivers/net", "drivers/usb", "drivers/tty", "lib/", "crypto/", "security/", "block/"))):
        continue
    shas = []
    for r in cna.get("references", []):
        m = re.match(r"https://git\.kernel\.org/stable/c/([0-9a-f]{40})$", r.get("url", ""))
        if m and m.group(1) not in shas:
            shas.append(m.group(1))
    for sha in shas[:6]:
        tried += 1
        if tried > 300:
            sys.exit(0)
        try:
            u = f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={sha}"
            data = urllib.request.urlopen(urllib.request.Request(u, headers={'User-Agent': 'curl/8.5.0'}), timeout=30).read()
        except Exception as e:
            print('fetch-fail', sha[:12], e)
            continue
        pth = os.path.join(out, f"{d['cveMetadata']['cveId']}-{sha[:12]}.patch")
        open(pth, "wb").write(data)
        nfiles = len(re.findall(rb"^diff --git ", data, re.M))
        if nfiles != 1:
            os.remove(pth); continue
        fw = subprocess.run(["patch", "-p1", "--dry-run", "--fuzz=0", "-d", tree, "-i", os.path.abspath(pth)], capture_output=True, text=True)
        rv = subprocess.run(["patch", "-p1", "-R", "--dry-run", "--fuzz=0", "-d", tree, "-i", os.path.abspath(pth)], capture_output=True, text=True)
        status = "forward-ok" if fw.returncode == 0 else "forward-fail"
        if rv.returncode == 0:
            status += ",already-applied"
        subj = re.search(rb"^Subject: (.*)$", data, re.M)
        print(d["cveMetadata"]["cveId"], sha, path, status, (subj.group(1).decode(errors="replace")[:90] if subj else ""))
        if fw.returncode == 0 and rv.returncode != 0:
            found += 1
        else:
            os.remove(pth)
        break
print("候選", found)
