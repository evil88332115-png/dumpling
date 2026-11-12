"""共用的下載核對（只下載、不解開、不執行）。

從 pipeline/lib/firmware_fetch.py 複製整理而來；`sha256_of`、`check_file`、`curl_download`、`fetch_one` 的簽名與行為
和 firmware_fetch.py 一致，之後 firmware_fetch.py 可以直接改成 import 這個模組。

行為：
- 只允許 https（curl 的 --proto／--proto-redir 都限定 =https；fetch_one 另外在呼叫下載函式前先檢查網址）。
- 先下載到 `.<名稱>.part`，核對大小與 sha256 都相符才 os.replace 成正式檔名；不符就刪除暫存檔、不留半成品。
- 拒絕 symlink／裝置檔：目標或暫存名已存在但不是一般檔案，一律拒絕。
- 下載函式可注入：`downloader(url, dest, max_size) -> 錯誤訊息或 None`（測試用，不連網）。

和 firmware_fetch.py 的差別（只放寬、不改既有行為）：entry 的 `size` 可以是 None（例如 NVIDIA 沒公布大小、
也還沒記錄），這時不核對大小，下載上限用 DEFAULT_MAX_SIZE；有 `sha1` 時另外核對 SHA-1。
"""
import hashlib
import os
import stat
import subprocess

DEFAULT_MAX_SIZE = 64 * 1024 ** 3  # size 未知時 curl --max-filesize 的上限（64 GiB）


def curl_download(url, dest, max_size):
    """用 curl 下載到 dest；回傳錯誤訊息或 None。"""
    cmd = ["curl", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
           "--silent", "--show-error", "--max-filesize", str(max_size),
           "--retry", "2", "--connect-timeout", "30", "--max-time", "1800",
           "--output", dest, "--", url]
    r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if r.returncode != 0:
        return "curl 失敗（exit %d）%s" % (r.returncode, r.stderr.strip()[:200])
    return None


def _digest_of(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_of(path):
    return _digest_of(path, "sha256")


def check_file(path, size, sha):
    """核對大小與 sha256；回傳錯誤訊息或 None。path 必須是一般檔案。size 是 None 時不核對大小。"""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        return "不是一般檔案"
    if size is not None and st.st_size != size:
        return "大小不符（實際 %d，預期 %d）" % (st.st_size, size)
    got = sha256_of(path)
    if got != sha:
        return "sha256 不符（實際 %s）" % got
    return None


def _lstat(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def fetch_one(entry, dest_dir, downloader=curl_download):
    """處理 files 的一項（需要 name、url、sha256、size）；回傳 (ok, 說明)。"""
    name, url, sha, size = entry["name"], entry["url"], entry["sha256"], entry.get("size")
    if not (isinstance(url, str) and url.startswith("https://")):
        return False, "%s 網址不是 https（拒絕）" % name
    final = os.path.join(dest_dir, name)
    tmp = os.path.join(dest_dir, "." + name + ".part")
    st = _lstat(final)
    if st is not None:
        if not stat.S_ISREG(st.st_mode):
            return False, "%s 已存在且不是一般檔案（拒絕）" % name
        if check_file(final, size, sha) is None:
            return True, "%s 已存在且核對相符" % name
        os.unlink(final)
    st = _lstat(tmp)
    if st is not None:
        if not stat.S_ISREG(st.st_mode):
            return False, "%s 暫存名已存在且不是一般檔案（拒絕）" % name
        os.unlink(tmp)
    err = downloader(url, tmp, size if size is not None else DEFAULT_MAX_SIZE)
    if err is None and _lstat(tmp) is None:
        err = "下載後沒有檔案"
    if err is None:
        err = check_file(tmp, size, sha)
    if err is not None:
        if _lstat(tmp) is not None:
            os.unlink(tmp)
        return False, "%s %s" % (name, err)
    os.replace(tmp, final)
    if size is None:
        return True, "%s 已下載並核對 sha256（大小未記錄）" % name
    return True, "%s 已下載並核對（%d 位元組）" % (name, size)
