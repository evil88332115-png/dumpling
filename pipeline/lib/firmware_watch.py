"""firmware.yml 的選用欄位 `watch`：樣本明確宣告「不進每日監控」與原因。

    watch:
      monitored: false
      why: "沒有 vBIOS 元件（內嵌的是 GOP 驅動範本）"

規則：
- 沒有 `watch` ＝沒有宣告（監控與否由樣本的 kind 與 status 決定，見 firmware_meta.py）。
- 有 `watch` 就必須是 mapping，鍵只能是 `monitored`（布林，必填）與 `why`（字串）。
- `monitored: false` 一定要有 `why`：規則在 `clean_why`（單行：沒有控制字元、換行與 U+2028、U+0085 等分隔字元；去掉空白與零寬字元後不是空的；最多 300 字）。
  從 `notes` 推導出來的原因（`status` 不是 `ok` 的樣本）用同一個檢查。
  不能用空字串或只有空白當原因（不監控的樣本不能變成躲掉 GAP 的後門）。
- `monitored: true` 的 `why` 可以省略；寫了就要符合同一個格式。

讀 firmware.yml 的程式（firmware_fetch.py、firmware_plan.py、firmware_dt.py、firmware_meta.py）都呼叫這裡的 parse_watch，
所以格式錯誤在第一個讀到的步驟就會被擋下，不會等到產生 firmware-meta.json 才發現。
"""
import re
import unicodedata

WATCH_KEYS = ("monitored", "why")
WHY_MAX = 300


def clean_why(raw):
    """不監控的原因（watch.why，或從 notes 推導出來的文字）的共同檢查 → 去掉頭尾空白的字串；不合規丟 ValueError。
    - 必須是字串、單行：不能有控制字元（Cc，含換行、tab）與行／段落分隔字元（U+2028、U+2029、U+0085 等，Zl、Zp）；
    - 去掉空白（Zs）與不可見的格式字元（Cf，含零寬字元 U+200B～U+200D、U+2060、U+FEFF）之後不能是空的；
    - 最多 300 字。"""
    if not isinstance(raw, str):
        raise ValueError("why 必須是字串")
    for ch in raw:
        if unicodedata.category(ch) in ("Cc", "Zl", "Zp"):
            raise ValueError("why 不能有換行、控制字元或行分隔字元（寫成單行）")
    visible = "".join(ch for ch in raw if unicodedata.category(ch) not in ("Cf", "Zs"))
    if not visible:
        raise ValueError("why 不能是空字串、只有空白或只有不可見字元")
    if len(raw) > WHY_MAX:
        raise ValueError("why 超過 %d 字" % WHY_MAX)
    return raw.strip()


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
        try:
            why = clean_why(why)
        except ValueError as e:
            raise ValueError("watch.%s" % e)
    if not mon and why is None:
        raise ValueError("watch.monitored 是 false 時，watch.why 必須是非空字串（寫明為什麼不監控）")
    return mon, why
