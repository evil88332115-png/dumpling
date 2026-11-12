"""掃描時的每日鏡像新鮮度：讀 sca-nvd-refresh 的狀態檔（/var/lib/sca-gitlab/refresh-status.tsv 格式），印「狀態<TAB>說明」。
剖析與每日監控共用（tools/cra/exploited_watch.py 的 mirror_refresh），不另寫一份。只讀、不連網、不執行狀態檔內容。

用法：python3 -I mirror_freshness.py <狀態檔，空字串＝不檢查> [--max-age-hours 24.5]
狀態：
  NOT_RUN    路徑是空字串（未檢查）；不是 OK，也不代表鏡像新鮮
  OK         狀態檔的 finished 在上限內，所有鏡像最後一次成功都在各自上限內，且最近一次更新都成功
  ATTENTION  只有「最近一次更新失敗、但沿用的上一份仍在上限內」的鏡像
  GAP        狀態檔讀不到／格式不對／finished 太舊，或有鏡像過期、從沒成功、不在狀態檔裡（列出名稱）
退出碼永遠 0（結果在輸出）；程式本身出錯時印 GAP。
"""
import argparse
import datetime
import importlib.util
import math
import os
import sys

CRA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "cra", "exploited_watch.py")


def load_watch():
    spec = importlib.util.spec_from_file_location("exploited_watch_for_mirror", CRA)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def check(path, now=None, max_age_hours=24.5, watch=None):
    if not path:
        return "NOT_RUN", "未檢查每日鏡像新鮮度（狀態檔路徑是空的）"
    if not (isinstance(max_age_hours, (int, float)) and math.isfinite(max_age_hours) and max_age_hours > 0):
        return "FAIL", f"設定錯誤：鏡像狀態檔的時間上限必須是大於 0 的有限數字（收到 {max_age_hours!r}）"
    w = watch or load_watch()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    mr, _ = w.mirror_refresh(path, now, max_age_hours)
    if mr["status"] == "NOT_AVAILABLE":
        return "GAP", f"鏡像更新狀態檔不可用，無法確認每日鏡像是否新鮮：{mr['detail']}"[:400]
    fin = datetime.datetime.strptime(mr["finished"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    age_h = (now - fin).total_seconds() / 3600
    rows = {r["mirror"]: r for r in mr["mirrors"]}
    bad = []
    if age_h < -0.1:
        bad.append(f"狀態檔 finished={mr['finished']} 時間在未來（主機時鐘或資料異常）")
    elif age_h > max_age_hours:
        bad.append(f"狀態檔 finished={mr['finished']}（{age_h:.1f} 小時前，上限 {max_age_hours:g} 小時）")
    stale = [n for n, r in rows.items() if r["stale"]]
    missing = [n for n in w.REFRESH_MIRRORS if n not in rows]
    failed = [n for n, r in rows.items() if r["result"] != "OK" and not r["stale"]]
    if stale:
        bad.append("過期：" + "、".join(f"{n}（最後成功 {rows[n]['last_ok'] or '從沒成功'}"
                                          + ("，時間在未來（主機時鐘或資料異常）" if rows[n].get("future") else f"，上限 {rows[n]['max_age_days']:g} 天") + "）" for n in stale))
    if missing:
        bad.append("不在狀態檔：" + "、".join(missing))
    if bad:
        return "GAP", "；".join(bad)[:450]
    if failed:
        return "ATTENTION", f"最近一次更新失敗、沿用上一份（仍在上限內）：{'、'.join(failed)}；狀態檔 finished={mr['finished']}"
    return "OK", f"狀態檔 finished={mr['finished']}（{age_h:.1f} 小時前）；{len(rows)} 個鏡像最後成功都在各自上限內"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--max-age-hours", type=float, default=24.5)
    a = ap.parse_args()
    try:
        s, d = check(a.path, max_age_hours=a.max_age_hours)
    except Exception as e:  # 任何問題都不是 OK
        s, d = "GAP", f"鏡像新鮮度檢查本身出錯（{type(e).__name__}）"
    print(f"{s}\t{d.replace(chr(9), ' ').replace(chr(10), ' ')}")


if __name__ == "__main__":
    main()
