"""firmware.yml 的選用欄位 `watch`：樣本明確宣告「不進每日監控」與原因。

    watch:
      monitored: false
      why: "沒有 vBIOS 元件（內嵌的是 GOP 驅動範本）"

規則：
- 沒有 `watch` ＝沒有宣告（監控與否由樣本的 kind 與 status 決定，見 firmware_meta.py）。
- 有 `watch` 就必須是 mapping，鍵只能是 `monitored`（布林，必填）與 `why`（字串）。
- `monitored: false` 一定要有 `why`：單行（沒有換行與控制字元）、去掉頭尾空白後不是空的、最多 300 字。
  不能用空字串或只有空白當原因（不監控的樣本不能變成躲掉 GAP 的後門）。
- `monitored: true` 的 `why` 可以省略；寫了就要符合同一個格式。

讀 firmware.yml 的程式（firmware_fetch.py、firmware_plan.py、firmware_dt.py、firmware_meta.py）都呼叫這裡的 parse_watch，
所以格式錯誤在第一個讀到的步驟就會被擋下，不會等到產生 firmware-meta.json 才發現。
"""
import re

WATCH_KEYS = ("monitored", "why")
WHY_MAX = 300
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def parse_watch(doc):
    """→ (monitored, why)。monitored 是 True／False／None（沒有宣告）；why 是字串或 None。格式不對丟 ValueError。"""
    if not isinstance(doc, dict) or "watch" not in doc:
        return None, None
    w = doc["watch"]
    if not isinstance(w, dict):
        raise ValueError("watch 必須是 mapping（monitored、why）")
    extra = sorted(str(k) for k in w if k not in WATCH_KEYS)
    if extra:
        raise ValueError("watch 有不認得的鍵 %s（可用：%s）" % ("、".join(extra), "、".join(WATCH_KEYS)))
    mon = w.get("monitored")
    if not isinstance(mon, bool):
        raise ValueError("watch.monitored 必須是布林（true／false）")
    why = w.get("why")
    if why is not None:
        if not isinstance(why, str):
            raise ValueError("watch.why 必須是字串")
        if _CTRL.search(why):
            raise ValueError("watch.why 不能有換行或控制字元（寫成單行）")
        if not why.strip():
            raise ValueError("watch.why 不能是空字串或只有空白")
        if len(why) > WHY_MAX:
            raise ValueError("watch.why 超過 %d 字" % WHY_MAX)
        why = why.strip()
    if not mon and why is None:
        raise ValueError("watch.monitored 是 false 時，watch.why 必須是非空字串（寫明為什麼不監控）")
    return mon, why
