"""共用的 fetch 步驟：讀專案的 sources.yml，下載並核對某個版本的所有檔案（只下載，不解開、不執行）。

用法：python3 -I platform_fetch.py <專案資料夾> <版本> --out <下載資料夾>
輸出：每個檔案一行 "  - <說明>"，最後一行 "fetch: OK|GAP|FAIL（…）"。結束碼 0＝OK、3＝GAP、1＝FAIL。

規則：
- 有 gap 的檔案不下載，回報 GAP（沒有可核對的雜湊，不自動接受第一次看到的雜湊）。
- sha256 不符一律不接受。若檔案有 commit（GitHub 動態封存檔，以 commit SHA 為準），改用 git clone 取那個 commit
  並核對 `git rev-parse HEAD`，工作樹放在 <下載資料夾>/<name>.checkout；失敗就是 FAIL。
- 有 sha1（例如 NVIDIA 公布的 SHA-1）時另外核對；不符就刪檔、FAIL。
"""
import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fetch_verify  # noqa: E402
import project_config as pc  # noqa: E402


def git_clone_commit(repo, commit, dest):
    """clone 並 checkout 指定 commit，回傳錯誤訊息或 None。不跑 hook、不抓 submodule、只允許 https。"""
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
    base = ["git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "-c", "core.hooksPath=/dev/null", "-c", "advice.detachedHead=false"]
    try:
        os.makedirs(dest)
        for args in (["init", "-q", dest], ["-C", dest, "remote", "add", "origin", repo],
                     ["-C", dest, "fetch", "-q", "--depth", "1", "--no-recurse-submodules", "origin", commit],
                     ["-C", dest, "checkout", "-q", "--detach", "FETCH_HEAD"]):
            r = subprocess.run(base + args, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=1800)
            if r.returncode != 0:
                return "git %s 失敗（exit %d）" % (args[0] if args[0] != "-C" else args[2], r.returncode)
        r = subprocess.run(base + ["-C", dest, "rev-parse", "HEAD"], stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env)
        if r.returncode != 0 or r.stdout.strip() != commit:
            return "checkout 後的 commit 和預期不同"
    except (OSError, subprocess.TimeoutExpired) as e:
        return "git 執行失敗（%s）" % type(e).__name__
    return None


def _sha1_ok(path, want):
    return fetch_verify._digest_of(path, "sha1") == want


def fetch_entry(entry, dest_dir, downloader=fetch_verify.curl_download, cloner=git_clone_commit):
    """處理一個檔案；回傳 (狀態 OK|GAP|FAIL, 說明)。"""
    name = entry["name"]
    if entry.get("gap"):
        return "GAP", "%s 沒有可核對的雜湊：%s" % (name, str(entry["gap"]).strip().splitlines()[0])
    ok, msg = fetch_verify.fetch_one(entry, dest_dir, downloader)
    if not ok:
        if entry.get("commit") and "sha256 不符" in msg:
            co = os.path.join(dest_dir, name + ".checkout")
            if os.path.lexists(co):
                return "FAIL", "%s.checkout 已存在（拒絕覆寫）" % name
            err = cloner(entry["repo"], entry["commit"], co)
            if err is None:
                return "OK", "%s 封存檔 sha256 不符（未接受新雜湊），已改用 clone 核對 commit %s" % (name, entry["commit"])
            return "FAIL", "%s；clone 核對也失敗：%s" % (msg, err)
        return "FAIL", msg
    if entry.get("sha1") and not _sha1_ok(os.path.join(dest_dir, name), entry["sha1"]):
        os.unlink(os.path.join(dest_dir, name))
        return "FAIL", "%s sha256 相符但 SHA-1 和記錄不同（已刪除）" % name
    return "OK", msg


def run(project_dir, version, out, downloader=fetch_verify.curl_download, cloner=git_clone_commit):
    """回傳 (狀態, 說明, 各檔案說明清單)。"""
    try:
        sources = pc.load_sources(os.path.join(project_dir, "sources.yml"))
    except pc.ConfigError as e:
        return "FAIL", str(e), []
    rel = sources["releases"].get(version)
    if rel is None:
        return "FAIL", "sources.yml 沒有版本 %s" % version, []
    if os.path.islink(out):
        return "FAIL", "下載資料夾是 symlink（拒絕）", []
    try:
        os.makedirs(out, exist_ok=True)
    except OSError as e:
        return "FAIL", "無法建立下載資料夾：%s" % e.strerror, []
    states, lines = [], []
    for f in rel["files"]:
        st, msg = fetch_entry(f, out, downloader, cloner)
        states.append(st)
        lines.append(msg)
    n = len(states)
    if "FAIL" in states:
        return "FAIL", "%d 個檔案中有 %d 個失敗" % (n, states.count("FAIL")), lines
    if "GAP" in states:
        return "GAP", "%d 個檔案中有 %d 個沒有可核對的雜湊" % (n, states.count("GAP")), lines
    return "OK", "%d 個檔案核對相符" % n, lines


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("project_dir")
    ap.add_argument("version")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    if pc.yaml is None:
        print("fetch: FAIL（缺少 PyYAML）")
        return 1
    st, msg, lines = run(args.project_dir, args.version, args.out)
    for line in lines:
        print("  - " + line.replace("\n", " "))
    print("fetch: %s（%s）" % (st, msg))
    return {"OK": 0, "GAP": 3}.get(st, 1)


if __name__ == "__main__":
    sys.exit(main())
