"""pipeline/offline-check.py（T-06 第 2 層斷網驗收的判定）與 .github/workflows/offline-scan.yml 的限制（C0 2026-11-17：只能手動觸發、
GitHub hosted runner、contents: read、不用 secret）。strace 的樣本格式取自 strace 6.x 的實際輸出；位址只用文件專用的 192.0.2.0/24、2001:db8::/32。"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CHECK = os.path.join(ROOT, "pipeline", "offline-check.py")
WF = os.path.join(ROOT, ".github", "workflows", "offline-scan.yml")

LOOP4 = '101 connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0'
LOOP6 = '101 connect(3, {sa_family=AF_INET6, sin6_port=htons(9), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 ECONNREFUSED (Connection refused)'
MAPPED = '101 connect(3, {sa_family=AF_INET6, sin6_port=htons(9), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6_addr), sin6_scope_id=0}, 28) = -1 EINPROGRESS (Operation now in progress)'
UNIX = '102 connect(4, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 23) = 0'
UNSPEC = '102 connect(5, {sa_family=AF_UNSPEC, sa_data="\\0\\0\\0\\0"}, 16) = 0'
DNS = '103 connect(3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 0'
EXT4 = '104 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.10")}, 16) = -1 ECONNREFUSED (Connection refused)'
EXT6 = '104 connect(3, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)'
SIG = "101 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=104, si_uid=1001, si_status=0} ---"
IPT = """Chain DUMPLING_OFFLINE (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       %d        0 REJECT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            reject-with icmp-port-unreachable
"""


class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="t06-offline-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.mir = self.p("mirrors")
        os.makedirs(self.mir)
        for d, k in (("kcve", "kernel-cve"), ("gdb", "grype-db")):
            self.w("mirrors/%s.result" % d, "OK source=internal kind=%s fetched_utc=2026-11-17T00:00:00Z age_hours=1.0\n" % k)
        self.w("events.txt", "")
        self.w("ipt.txt", IPT % 0 + IPT.replace("DUMPLING_OFFLINE", "DUMPLING_OFFLINE6") % 0)

    def p(self, *a):
        return os.path.join(self.tmp, *a)

    def w(self, rel, text):
        with open(self.p(rel), "w", encoding="utf-8") as f:
            f.write(text)

    def run_check(self, lines, block="on", extra=None):
        self.w("c.log", "\n".join(lines) + "\n")
        args = [sys.executable, "-I", CHECK, "--strace", self.p("c.log"), "--block", block, "--out", self.p("o.json"),
                "--docker-events", self.p("events.txt"), "--mirrors", self.mir]
        if block == "on":
            args += ["--iptables", self.p("ipt.txt")]
        r = subprocess.run(args + (extra or []), capture_output=True, text=True, timeout=60)
        doc = None
        if os.path.exists(self.p("o.json")):
            with open(self.p("o.json"), encoding="utf-8") as f:
                doc = json.load(f)
        return r, doc

    def test_only_local_is_ok(self):
        r, doc = self.run_check([LOOP4, LOOP6, MAPPED, UNIX, UNSPEC, SIG])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(doc["verdict"], "OK")
        self.assertEqual((doc["strace"]["connects"], doc["strace"]["unix"], doc["strace"]["loopback"], doc["strace"]["other"]), (5, 1, 3, 1))
        self.assertTrue(r.stdout.startswith("offline-check: OK（block=on；connect 5 次"))
        self.assertNotIn("docker.sock", json.dumps(doc))              # 本機 socket 的路徑不寫

    def test_external_and_dns_fail(self):
        r, doc = self.run_check([LOOP4, EXT4, EXT4, EXT6, DNS])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(doc["verdict"], "FAIL")
        self.assertEqual(doc["strace"]["external"], [
            {"addr": "192.0.2.10", "port": 443, "count": 2, "results": ["ECONNREFUSED"]},
            {"addr": "2001:db8::1", "port": 443, "count": 1, "results": ["ENETUNREACH"]}])
        self.assertEqual(doc["strace"]["dns"], 1)
        self.assertIn("192.0.2.10:443×2（ECONNREFUSED）", r.stdout)
        self.assertIn("名稱查詢（127.0.0.53:53）1 次", r.stdout)

    def test_rejects_counted_in_block_mode(self):
        self.w("ipt.txt", IPT % 3 + IPT.replace("DUMPLING_OFFLINE", "DUMPLING_OFFLINE6") % 2)
        r, doc = self.run_check([LOOP4])
        self.assertEqual((r.returncode, doc["iptables_rejects"]), (1, 5))
        self.assertIn("封鎖規則擋下 5 個封包", doc["findings"])

    def test_block_on_needs_counters(self):
        os.remove(self.p("ipt.txt"))
        r, doc = self.run_check([LOOP4])
        self.assertEqual(r.returncode, 1)
        self.assertIn("讀不到封鎖規則的計數（--iptables）", doc["findings"])

    def test_block_off_ignores_counters(self):
        r, doc = self.run_check([LOOP4], block="off")
        self.assertEqual((r.returncode, doc["verdict"], doc["iptables_rejects"]), (0, "OK", None))

    def test_docker_image_events_fail(self):
        self.w("events.txt", "2026-11-17T01:00:00Z image pull ghcr.io/x/y:1 (name=ghcr.io/x/y)\n")
        r, doc = self.run_check([LOOP4])
        self.assertEqual((r.returncode, doc["docker_image_events"]), (1, 1))

    def test_public_mirror_fails(self):
        self.w("mirrors/euvd.result", "OK mirror=x manifest=y\n")
        r, doc = self.run_check([LOOP4])
        self.assertEqual(r.returncode, 1)
        self.assertIn("不是內部鏡像：euvd", doc["findings"])

    def test_no_evidence_is_not_run(self):
        r, doc = self.run_check([SIG])
        self.assertEqual((r.returncode, doc["verdict"]), (2, "NOT_RUN"))
        r = subprocess.run([sys.executable, "-I", CHECK, "--strace", self.p("missing.log"), "--block", "off", "--out", self.p("o2.json")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)

    def test_usage_error(self):
        r = subprocess.run([sys.executable, "-I", CHECK, "--block", "maybe"], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 64)

    def test_no_banned_words(self):
        r, _ = self.run_check([LOOP4, EXT4, DNS])
        for bad in ("不受影響", "不適用", "安全", "PASS"):
            self.assertNotIn(bad, r.stdout)


class Workflow(unittest.TestCase):
    def setUp(self):
        with open(WF, encoding="utf-8") as f:
            self.text = f.read()
        self.doc = yaml.safe_load(self.text)

    def test_only_manual_trigger(self):
        on = self.doc.get("on", self.doc.get(True))                   # PyYAML 把 on 讀成 True
        self.assertEqual(list(on), ["workflow_dispatch"])

    def test_read_only_permissions_everywhere(self):
        self.assertEqual(self.doc["permissions"], {"contents": "read"})
        for name, job in self.doc["jobs"].items():
            self.assertIn(job.get("permissions", {"contents": "read"}), ({"contents": "read"},), name)

    def test_hosted_runner_only(self):
        for name, job in self.doc["jobs"].items():
            self.assertEqual(job["runs-on"], "ubuntu-24.04", name)    # 寫死，不從輸入或變數來（會用 sudo 改 iptables）

    def test_no_secrets_and_pinned_actions(self):
        self.assertNotIn("secrets.", self.text)
        for m in re.finditer(r"uses:\s*(\S+)", self.text):
            self.assertRegex(m.group(1), r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")

    def test_inputs_not_interpolated_in_run(self):
        for name, job in self.doc["jobs"].items():
            for st in job["steps"]:
                self.assertNotIn("${{ inputs.", st.get("run", ""), (name, st.get("name")))
                self.assertNotIn("${{ github.event.inputs", st.get("run", ""), (name, st.get("name")))

    def test_block_is_removed_and_checked(self):
        # cgroup 比對（不是 owner 比對：封 runner 帳號會切斷 runner 程式和 GitHub 的連線）；IPv4、IPv6 都封；結束後拆掉
        self.assertNotIn("--uid-owner", self.text)
        self.assertEqual(self.text.count("for t in iptables ip6tables; do"), 5)
        self.assertIn('sudo "$t" -I OUTPUT 1 -m cgroup --path dumpling-offline ! -o lo -j DUMPLING_OFFLINE', self.text)
        self.assertIn('sudo "$t" -D OUTPUT -m cgroup --path dumpling-offline ! -o lo -j DUMPLING_OFFLINE', self.text)
        self.assertIn('echo "$$" | sudo tee "$cg/cgroup.procs"', self.text)
        self.assertIn("封鎖沒有生效", self.text)                     # 先確認封鎖有效才開始
        self.assertIn("pipeline/offline-check.py", self.text)
        self.assertIn("INTERNAL_MIRROR_URL", self.text)
        self.assertIn("DUMPLING_REQUIRE_INTERNAL_MIRROR=1", self.text)


if __name__ == "__main__":
    unittest.main()
