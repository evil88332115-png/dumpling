"""內部鏡像模式（T-06）測試的共用工具：假的 curl／git／grype（放在 PATH 最前面，被呼叫就留標記）、內部鏡像根目錄的合成資料、替身鏡像腳本。
不連網。標記資料夾裡只要有任何檔案，就代表有人去做了公開下載（curl、git）或 grype db update。"""
import datetime
import hashlib
import io
import json
import os
import shutil
import stat
import tempfile
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
MIRROR_SH = os.path.join(ROOT, "pipeline", "lib", "mirrors.sh")
REAL_SCRIPTS = os.path.join(ROOT, "tools", "mirror")
KCVE_ORG = "f4215fc3-5b6b-47ff-a258-f7189bd81038"

FAKE_CURL = """#!/usr/bin/env bash
echo "curl $*" >> "$MARK_DIR/curl"
exit 7
"""
FAKE_GIT = """#!/usr/bin/env bash
echo "git $*" >> "$MARK_DIR/git"
exit 128
"""
# 假的 grype：記下每次呼叫的參數與環境；db update 留標記；db import 照 FAKE_GRYPE_IMPORT 成功或失敗；db status 印 Built／Status
FAKE_GRYPE = """#!/usr/bin/env bash
echo "args=$* AUTO_UPDATE=${GRYPE_DB_AUTO_UPDATE-unset} APP_UPDATE=${GRYPE_CHECK_FOR_APP_UPDATE-unset}" >> "$FAKE_GRYPE_LOG"
if [ "${GRYPE_DB_AUTO_UPDATE-}" != false ]; then echo "auto-update-not-false: $*" >> "$MARK_DIR/grype-auto-update"; fi
case "$1 $2" in
  "db update") echo "grype $*" >> "$MARK_DIR/grype-db-update"; exit 1;;
  "db import") [ "${FAKE_GRYPE_IMPORT:-ok}" = ok ] || { echo "import failed" >&2; exit 1; }; echo "imported $3"; exit 0;;
  "db status") printf 'Path:      /x/6\\nSchema:    v6.0.2\\nBuilt:     %s\\nStatus:    valid\\n' "${FAKE_GRYPE_BUILT:-$(date -u +%FT%TZ)}"; exit 0;;
esac
exit 0
"""


def utc(hours_ago=0.0):
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class Env:
    """一個測試用的暫存世界：bin（假指令）、marks（公開下載標記）、root（內部鏡像根目錄）、out（MIRRORS_DIR 或 feeds 輸出）。"""

    def __init__(self):
        self.w = tempfile.mkdtemp(prefix="t06-", dir=os.environ.get("TMPDIR"))
        self.bin = os.path.join(self.w, "bin")
        self.marks = os.path.join(self.w, "marks")
        self.root = os.path.join(self.w, "root")
        self.out = os.path.join(self.w, "out")
        self.stubs = os.path.join(self.w, "stubs")
        self.glog = os.path.join(self.w, "grype.log")
        for d in (self.bin, self.marks, self.root, self.stubs):
            os.makedirs(d)
        for n, body in (("curl", FAKE_CURL), ("git", FAKE_GIT), ("grype", FAKE_GRYPE)):
            self.exe(os.path.join(self.bin, n), body)

    @staticmethod
    def exe(path, body):
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(path, 0o755)

    def cleanup(self):
        shutil.rmtree(self.w, ignore_errors=True)

    def env(self, **extra):
        e = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get("PATH", ""), MARK_DIR=self.marks, FAKE_GRYPE_LOG=self.glog,
                 MIRRORS_DIR=self.out, MIRRORS_RETRY_DELAY="0")
        for k in ("INTERNAL_MIRROR_URL", "DUMPLING_REQUIRE_INTERNAL_MIRROR", "INTERNAL_MIRROR_FRESH_HOURS", "KCVE_CACHE_DIR", "MIRRORS_STEPS",
                  "MIRRORS_SCRIPT_DIR", "MIRRORS_TRIES", "WATCH_KCVE_MIRROR_TRIES", "GRYPE_DB_AUTO_UPDATE", "CISA_KEV_URL", "KERNEL_CVE_MAX_AGE_DAYS"):
            e.pop(k, None)
        for k in [k for k in e if k.startswith(("INTERNAL_MIRROR_", "CISA_KEV_"))]:
            e.pop(k)
        e.update(extra)
        return e

    def url(self):
        return "file://" + self.root

    def marked(self):
        """公開下載的標記（curl、git、grype db update、auto-update 沒關）：空的才對。"""
        return sorted(os.listdir(self.marks))

    def grype_calls(self):
        try:
            with open(self.glog, encoding="utf-8") as f:
                return f.read().splitlines()
        except OSError:
            return []

    # ---- 替身鏡像腳本（MIRRORS_SCRIPT_DIR）----
    def stub(self, name, check_exit=0):
        """替身：下載模式（沒有 --check）留標記 download-ran 並成功；--check 依 STUB_CHECK（ok／fail）結束，並把看到的 REUSE／FALLBACK 變數寫進 STUB_LOG。"""
        body = """#!/usr/bin/env bash
if [ "$1" = --check ]; then
  echo "check $2 REUSE=${KERNEL_CVE_REUSE_FROM:-} FALLBACK=${KERNEL_CVE_FALLBACK_FROM:-}" >> "${STUB_LOG:-/dev/null}"
  if [ "${STUB_CHECK:-ok}" = fail ]; then echo "FAIL 替身 --check 失敗"; exit 1; fi
  echo "OK 替身 --check"; exit 0
fi
echo "download $*" >> "$MARK_DIR/download-ran"
mkdir -p "$1"; : > "$2"; echo "OK mirror=$1 manifest=$2"
"""
        self.exe(os.path.join(self.stubs, name), body)

    # ---- 內部鏡像根目錄的內容 ----
    def source_dir(self, kind):
        d = os.path.join(self.root, kind)
        os.makedirs(d, exist_ok=True)
        return d

    def write_source(self, kind, hours_ago=1.0, extra=""):
        """kernel-cve、osv-distro、nvidia-bulletins、cisa-kev 用的 SOURCE（fetched_utc）。回傳資料夾。"""
        d = self.source_dir(kind)
        with open(os.path.join(d, "SOURCE"), "w", encoding="utf-8") as f:
            f.write(f"source=x\nfetched_utc={utc(hours_ago)}\n{extra}")
        with open(os.path.join(d, "data.bin"), "w", encoding="utf-8") as f:
            f.write(kind)
        return d

    def write_euvd(self, hours_ago=1.0):
        d = self.source_dir("euvd")
        with open(os.path.join(d, "index.tsv"), "w", encoding="utf-8") as f:
            f.write(f"# euvd-index 1\tfetched_utc={utc(hours_ago)}\tcves=1\tkev_newest_date_added=2026-11-14\ncve\teuvd\n")
        return d

    def write_grype_db(self, hours_ago=1.0):
        d = self.source_dir("grype-db")
        os.makedirs(os.path.join(d, "v6"), exist_ok=True)
        with open(os.path.join(d, "v6", "vulnerability-db_v6.0.2_x.tar.zst"), "wb") as f:
            f.write(b"fake-db")
        with open(os.path.join(d, "v6", "latest.json"), "w", encoding="utf-8") as f:
            json.dump({"path": "vulnerability-db_v6.0.2_x.tar.zst", "built": utc(hours_ago), "checksum": "sha256:" + "0" * 64}, f)
        return d

    def write_real_kernel_cve(self, hours_ago=1.0):
        """真的 kernel-cve.sh --check 讀得懂的最小鏡像（要設 KERNEL_CVE_MIN_RECORDS=1）。"""
        d = self.source_dir("kernel-cve")
        rec = {"cveMetadata": {"cveId": "CVE-2024-0001", "assignerOrgId": KCVE_ORG}, "containers": {"cna": {"affected": []}}}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("cve/published/2024/CVE-2024-0001.json", json.dumps(rec))
        raw = buf.getvalue()
        with open(os.path.join(d, "kernel-cves.zip"), "wb") as f:
            f.write(raw)
        with open(os.path.join(d, "SOURCE"), "w", encoding="utf-8") as f:
            f.write(f"source=x\nfetched_utc={utc(hours_ago)}\nzip_sha256={hashlib.sha256(raw).hexdigest()}\nzip_bytes={len(raw)}\n"
                    f"commit={'a' * 40}\ncommit_date=2026-11-14T00:00:00+00:00\nrecords=1\nunpacked_bytes=10\n")
        return d

    @staticmethod
    def kev_doc(n=1200, released_hours_ago=24.0, released=None):
        rel = released if released is not None else (datetime.datetime.now(datetime.timezone.utc)
                                                     - datetime.timedelta(hours=released_hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return rel, json.dumps({"title": "t", "dateReleased": rel, "count": n,
                                "vulnerabilities": [{"cveID": "CVE-2021-%05d" % i} for i in range(n)]}).encode()

    def write_kev_file(self, path, released_hours_ago=24.0, n=1200, released=None):
        """單一 JSON 檔（沒有 SOURCE）。回傳 dateReleased。"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        rel, raw = self.kev_doc(n, released_hours_ago, released)
        with open(path, "wb") as f:
            f.write(raw)
        return rel

    def write_real_kev(self, hours_ago=1.0, n=1200, released_hours_ago=24.0, released=None):
        """cisa-kev.sh 的鏡像資料夾（SOURCE＋檔案）。hours_ago＝同步時間；released_hours_ago＝檔案裡的 dateReleased。"""
        d = self.source_dir("cisa-kev")
        rel, raw = self.kev_doc(n, released_hours_ago, released)
        with open(os.path.join(d, "known_exploited_vulnerabilities.json"), "wb") as f:
            f.write(raw)
        with open(os.path.join(d, "SOURCE"), "w", encoding="utf-8") as f:
            f.write(f"source=https://example.invalid/kev.json\nfetched_utc={utc(hours_ago)}\nsha256={hashlib.sha256(raw).hexdigest()}\n"
                    f"bytes={len(raw)}\nentries={n}\ndate_released={rel}\n")
        return d, raw


def is_fifo(path):
    return stat.S_ISFIFO(os.lstat(path).st_mode)
