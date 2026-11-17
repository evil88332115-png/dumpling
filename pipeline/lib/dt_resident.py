#!/usr/bin/env python3
"""常駐 DT 模式（T-14，DUMPLING_DT_MODE=resident）的連線檔檢查與權限判斷。pipeline/lib/dt-session.sh 呼叫；一律 `python3 -I`。

  check <連線檔>                  檢查格式；OK 印「OK」，不合 → 結束碼 1、印原因（不印任何值）
  write <連線檔> <PILOT_ENV>      檢查後把 DT_URL、DT_API_KEY、DT_FRONTEND_URL 寫進 PILOT_ENV（權限 600；已存在就覆寫）
  curlcfg <連線檔> <輸出檔>        curl 設定檔（權限 600）：只有 header = "X-Api-Key: …"，key 不出現在命令列
  url <連線檔>                    印 DT_URL（去掉結尾的 / 與 /api；不是秘密）
  version <JSON 檔>               /api/version 的 version（可見 ASCII、最多 64 字元；讀不到或格式不對 → 結束碼 1）
  perms <JSON 檔> <來源>           來源 user｜team：/api/v1/user/self/permissions（字串清單）或 /api/v1/team/self（{permissions:[{name}]}）
                                 → 印「OK<TAB>說明」「NOCREATE<TAB>說明」或結束碼 1「缺少必要權限…」

連線檔（GitLab 的 File 類型 CI/CD 變數，protected）：一行一個 KEY=VALUE；空行與 # 開頭的行略過。
  只收 DT_URL、DT_API_KEY（必要）與 DT_FRONTEND_URL（選用）；其他鍵、重複鍵、空值、值含空白、控制字元、引號或反斜線 → 不合。
  網址要 https://（不能帶帳號密碼；埠 1–65535；路徑不能有 . 或 .. 的段）；DUMPLING_DT_ALLOW_HTTP_LOCAL=1 時另外允許 http://127.0.0.1（本機的假常駐 DT，測試用）。
  檔案不能是連結、要是一般檔案、群組與其他人沒有任何權限（600 或更嚴）。
權限名稱依 DependencyTrack apiserver 5.2.0 的 auth/Permissions.java；必要：BOM_UPLOAD、VIEW_PORTFOLIO、VIEW_VULNERABILITY。
建立專案（sca-scan 的 PUT /api/v1/project）：PORTFOLIO_MANAGEMENT 或 PORTFOLIO_MANAGEMENT_CREATE；都沒有 → NOCREATE（不 FAIL：專案必須事先存在）。
"""
import json
import os
import re
import stat
import sys

KEYS = ("DT_URL", "DT_API_KEY", "DT_FRONTEND_URL")
REQUIRED = ("DT_URL", "DT_API_KEY")
NEED = ("BOM_UPLOAD", "VIEW_PORTFOLIO", "VIEW_VULNERABILITY")
CREATE = ("PORTFOLIO_MANAGEMENT", "PORTFOLIO_MANAGEMENT_CREATE")
VALUE_RE = re.compile(r"^[\x21-\x7e]+$")                  # 可見 ASCII，不含空白
MAX_BYTES = 1048576                                       # 讀伺服器回應的上限（和 dt-session.sh 的 --max-filesize 相同）
URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/%-]*)?$")
LOCAL_RE = re.compile(r"^http://127\.0\.0\.1(:[0-9]{1,5})?(/[A-Za-z0-9._~/%-]*)?$")


class ConnError(Exception):
    pass


def read_conn(path):
    try:
        st = os.lstat(path)
    except OSError as e:
        raise ConnError("讀不到連線檔（%s）" % type(e).__name__)
    if stat.S_ISLNK(st.st_mode):
        raise ConnError("連線檔不能是連結")
    if not stat.S_ISREG(st.st_mode):
        raise ConnError("連線檔不是一般檔案")
    if st.st_mode & 0o077:
        raise ConnError("連線檔的權限太寬（%o）：群組與其他人不能有任何權限（600 或更嚴）" % (st.st_mode & 0o777))
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError) as e:
        raise ConnError("讀不了連線檔（%s）" % type(e).__name__)
    vals = {}
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            raise ConnError("第 %d 行不是 KEY=VALUE" % n)
        k, v = s.split("=", 1)
        if k not in KEYS:
            raise ConnError("第 %d 行的鍵不收（只收 %s）" % (n, "、".join(KEYS)))
        if k in vals:
            raise ConnError("%s 重複" % k)
        if not v:
            raise ConnError("%s 是空的" % k)
        if not VALUE_RE.match(v) or "'" in v or '"' in v or "\\" in v:
            raise ConnError("%s 的值含空白、控制字元、非 ASCII 字元、引號或反斜線" % k)
        vals[k] = v
    for k in REQUIRED:
        if k not in vals:
            raise ConnError("缺少 %s" % k)
    local = os.environ.get("DUMPLING_DT_ALLOW_HTTP_LOCAL") == "1"
    for k in ("DT_URL", "DT_FRONTEND_URL"):
        if k in vals and not (URL_RE.match(vals[k]) or (local and LOCAL_RE.match(vals[k]))):
            raise ConnError("%s 要是 https:// 網址（不帶帳號密碼）%s" % (k, "或 http://127.0.0.1" if local else ""))
        if k in vals:
            rest = vals[k].split("://", 1)[1]
            host, _, path = rest.partition("/")
            port = host.rpartition(":")[2] if ":" in host else None
            if port is not None and not 1 <= int(port) <= 65535:
                raise ConnError("%s 的埠要在 1–65535 之間" % k)
            if any(seg in (".", "..") for seg in path.split("/")):
                raise ConnError("%s 的路徑不能有 . 或 .. 的段" % k)
    u = vals["DT_URL"].rstrip("/")
    vals["DT_URL"] = u[:-4] if u.endswith("/api") else u
    return vals


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def read_small_json(path):
    """伺服器回應：超過 MAX_BYTES → ConnError（不整個讀進來）。"""
    with open(path, "rb") as fh:
        raw = fh.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ConnError("常駐 DT 的回應超過 %d bytes，不處理" % MAX_BYTES)
    return json.loads(raw.decode("utf-8"))


def version(path):
    v = read_small_json(path)
    v = v.get("version") if isinstance(v, dict) else None
    if not isinstance(v, str) or not v:
        raise ConnError("/api/version 沒有 version")
    v = "".join(ch for ch in v if 0x21 <= ord(ch) <= 0x7e)[:64]
    return v or "?"


def perms(path, source):
    d = read_small_json(path)
    if source == "user":
        names = d if isinstance(d, list) else None
    else:
        names = [p.get("name") for p in d.get("permissions") or [] if isinstance(p, dict)] if isinstance(d, dict) else None
    if not isinstance(names, list) or not all(isinstance(x, str) for x in names):
        raise ConnError("權限回應的格式不對（%s）" % source)
    have = set(names)
    miss = [p for p in NEED if p not in have]
    if miss:
        raise ConnError("API key 缺少必要權限：%s（要 %s）" % ("、".join(miss), "、".join(NEED)))
    basis = "權限來自 %s" % ("/api/v1/user/self/permissions" if source == "user" else "/api/v1/team/self")
    if not have & set(CREATE):
        return "NOCREATE", "%s；沒有建立專案的權限（%s）：專案必須事先存在，請 DT 管理者先建立這次要上傳的專案（完整、-bsp、-os 各一個）" % (
            basis, "、".join(CREATE))
    return "OK", "%s；有 %s 與建立專案的權限" % (basis, "、".join(NEED))


def main(argv):
    try:
        cmd = argv[0]
        if cmd == "check" and len(argv) == 2:
            read_conn(argv[1])
            print("OK")
        elif cmd == "write" and len(argv) == 3:
            v = read_conn(argv[1])
            write_private(argv[2], "".join("%s=%s\n" % (k, v[k]) for k in KEYS if k in v))
        elif cmd == "curlcfg" and len(argv) == 3:
            v = read_conn(argv[1])
            write_private(argv[2], 'header = "X-Api-Key: %s"\n' % v["DT_API_KEY"])
        elif cmd == "url" and len(argv) == 2:
            print(read_conn(argv[1])["DT_URL"])
        elif cmd == "version" and len(argv) == 2:
            print(version(argv[1]))
        elif cmd == "perms" and len(argv) == 3 and argv[2] in ("user", "team"):
            st, msg = perms(argv[1], argv[2])
            print("%s\t%s" % (st, msg))
        else:
            print(__doc__.split("\n\n")[1])
            return 64
    except ConnError as e:
        print(str(e))
        return 1
    except (OSError, ValueError) as e:
        print("dt_resident 失敗（%s）" % type(e).__name__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
