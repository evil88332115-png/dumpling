#!/usr/bin/env python3
"""kernel_git_files.py：用 linux-stable 的本機 clone（唯讀）查「某個修補 commit 改了哪些檔案」（kernel_config.py 的 --stable-git）。

用途（只在 kernel_config.py 裡用）：
  (a) CNA 鏡像沒有紀錄的 CVE：從 Grype／DT 的 references 找出 git.kernel.org／github torvalds 的 commit 雜湊，查它改了哪些檔案；
  (b) CNA 的 programFiles 是主線的檔名，產品分支的 backport 可能改的是別的檔案：CNA 紀錄裡的修補 commit 若在這個 clone 裡，
      取它實際改的檔案，和 programFiles 聯集。
一律不連網、不 fetch、不寫入：只執行 `git cat-file --batch-check` 與 `git log --no-walk --name-only`，clone 的設定檔不信任
（-c 蓋掉會執行東西的設定、環境變數清掉全域與系統設定、沒有 pager、不套用 replace 物件、不跟 submodule）。
輸出的檔名要是普通的路徑字元，否則整個 commit 當作查不到；merge commit 與根 commit 也當作查不到（保守）。"""
import os
import re
import subprocess

HASH_RE = re.compile(r"[0-9a-f]{40}")
SHORT_HASH_RE = re.compile(r"[0-9a-f]{12,40}")
PATH_RE = re.compile(r"[A-Za-z0-9_.+@,=~/-]{1,400}")
# 只認上游核心的 commit 網址（不認 Ubuntu／openEuler 等發行版的倉庫、也不認個人的 fork）
URL_RES = (
    re.compile(r"https?://git\.kernel\.org/(?:pub/scm/linux/kernel/git|cgit/linux/kernel/git)/(?:torvalds|stable)/linux(?:-stable)?\.git/"
               r"(?:commit|patch)/?\?(?:[^\s#]*&)?id=([0-9a-f]{12,40})"),
    re.compile(r"https?://git\.kernel\.org/(?:stable/c|linus)/([0-9a-f]{12,40})(?![0-9a-zA-Z])"),
    re.compile(r"https?://github\.com/torvalds/linux/commit/([0-9a-f]{12,40})(?![0-9a-zA-Z])"),
)
MAX_HASHES_PER_CVE = 64
MAX_FILES_PER_COMMIT = 5000
BATCH = 1000
TIMEOUT = 300


def commit_hashes_in_text(text):
    """文字（URL 清單、markdown 的 references）→ 上游核心 commit 的雜湊（小寫、去重、依出現順序）。"""
    out = []
    if not isinstance(text, str):
        return out
    for rx in URL_RES:
        for m in rx.finditer(text):
            h = m.group(1).lower()
            if h not in out:
                out.append(h)
    return out[:MAX_HASHES_PER_CVE]


def _env():
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "HOME": "/nonexistent", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_PAGER": "cat", "GIT_ASKPASS": "/bin/false"}


class StableGit:
    """linux-stable 的本機 clone。ok False 時 error 是原因，files() 一律回 None（查不到）。"""

    def __init__(self, path):
        self.path = path
        self.label = os.path.basename(os.path.normpath(path)) or path
        self.ok, self.error, self.head, self.branch = False, None, None, None
        self.cache = {}
        self.queries = self.resolved = 0
        gd = os.path.join(path, ".git")
        if os.path.islink(path) or not os.path.isdir(path):
            self.error = "--stable-git must be a directory (not a symbolic link)"
            return
        if os.path.islink(gd) or not (os.path.isdir(gd) or os.path.isfile(os.path.join(path, "HEAD"))):
            self.error = "--stable-git is not a git clone (no .git directory, and not a bare repository)"
            return
        self.gitdir = gd if os.path.isdir(gd) else path
        try:
            self._run(["rev-parse", "--git-dir"])
            refs = self._run(["for-each-ref", "--count=8", "--format=%(refname:short)", "refs/heads", "refs/remotes"]).decode("utf-8", "replace")
            self.branch = ", ".join(r for r in refs.split() if re.fullmatch(r"[A-Za-z0-9_./-]{1,80}", r))[:300] or None
            try:
                h = self._run(["rev-parse", "--verify", "--quiet", "HEAD"]).decode("ascii", "replace").strip()
                self.head = h if HASH_RE.fullmatch(h) else None
            except ValueError:
                self.head = None             # HEAD 指向不存在的分支（例如 master）：不影響查 commit
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            self.error = f"git could not read the clone ({type(e).__name__})"
            return
        self.ok = True

    def _run(self, args, stdin=None):
        cmd = ["git", "--no-pager", "--no-optional-locks", "--git-dir", self.gitdir, "-c", "core.fsmonitor=false",
               "-c", "core.hooksPath=/dev/null", "-c", "log.showSignature=false", "-c", "gpg.program=/bin/false", "-c", "gpg.ssh.program=/bin/false", "-c", "gpg.x509.program=/bin/false", "-c", "core.pager=cat", "-c", "core.editor=/bin/false", "-c", "diff.external=", "-c", "core.attributesFile=/dev/null", "-c", "core.excludesFile=/dev/null", "-c", "format.pretty=", "-c", "log.decorate=false", "-c", "log.mailmap=false", "-c", "core.quotePath=true", "-c", "protocol.allow=never", "--no-replace-objects"] + args
        r = subprocess.run(cmd, input=stdin, capture_output=True, env=_env(), timeout=TIMEOUT, check=False, cwd="/")
        if r.returncode != 0:
            raise ValueError(f"git exited with {r.returncode}")
        return r.stdout

    def files(self, hashes):
        """雜湊（40 位或 7–40 位的短雜湊）→ {雜湊: 檔案清單（排序）或 None（clone 裡沒有、不明確、不是普通的單親 commit、檔名不尋常）}。"""
        want = [h for h in dict.fromkeys(hashes) if h not in self.cache]
        if self.ok and want:
            for i in range(0, len(want), BATCH):
                part = want[i:i + BATCH]
                try:
                    self._query(part)
                except (OSError, subprocess.SubprocessError, ValueError):
                    for h in part:
                        self.cache.setdefault(h, None)
        return {h: (self.cache.get(h) if self.ok else None) for h in hashes}

    def _query(self, part):
        self.queries += len(part)
        out = self._run(["cat-file", "--batch-check"], ("\n".join(part) + "\n").encode("ascii")).decode("ascii", "replace").splitlines()
        if len(out) != len(part):
            raise ValueError("unexpected cat-file output")
        full = {}
        for h, l in zip(part, out):
            f = l.split()
            if len(f) == 3 and f[1] == "commit" and HASH_RE.fullmatch(f[0]):
                full[h] = f[0]
            else:
                self.cache[h] = None            # missing／ambiguous／不是 commit
        if not full:
            return
        oids = sorted(set(full.values()))
        text = self._run(["log", "--no-walk=unsorted", "--stdin", "--no-color", "--format=%x01%H %P", "--no-show-signature", "--name-only"],
                         ("\n".join(oids) + "\n").encode("ascii")).decode("utf-8", "replace")
        got = {}
        for blk in text.split("\x01")[1:]:
            lines = [l for l in blk.split("\n")]
            head = lines[0].split()
            if not head or not HASH_RE.fullmatch(head[0]):
                continue
            names = [l for l in lines[1:] if l]
            ok = len(head) == 2 and len(names) <= MAX_FILES_PER_COMMIT and all(PATH_RE.fullmatch(n) for n in names)   # 單親、檔名普通
            got[head[0]] = sorted(set(names)) if ok and names else None
        for h, o in full.items():
            self.cache[h] = got.get(o)
            if self.cache[h] is not None:
                self.resolved += 1
