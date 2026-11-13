"""firmware-ci.sh 摘要表的「微碼公告比對」欄：fw-inventory.json → 一行文字（每個 BIOS 映像各一段）。

用法：python3 -I firmware_advisory_cell.py <fw-inventory.json>
只讀 fw-inventory.json 的 advisory 與 bios[]（x86_firmware.py 的輸出）；文字裡有映像檔名（不可信資料），
由呼叫端（firmware-ci.sh）再經 firmware_mdsafe 跳脫。不判斷任何漏洞：這一欄只是比對結果的計數與沒有比對的原因。
"""
import json
import sys

ORDER = ("affected-candidate", "older-no-sa", "up-to-date", "NOT_ASSESSED")
AMD_NO_MATCH = "沒有做公告比對（NOT_ASSESSED：資料庫沒有資料，以 AMD 公告為準）"
MAX_IMAGES = 20


def short(name):
    return str(name).rsplit("/", 1)[-1].rsplit("!", 1)[-1][:80]


def counts_text(results):
    c = {}
    for r in results:
        m = (r or {}).get("match", "NOT_ASSESSED")
        c[m] = c.get(m, 0) + 1
    return "、".join([f"{k} {c[k]}" for k in ORDER if k in c] + [f"{k} {v}" for k, v in sorted(c.items()) if k not in ORDER])


def image_text(b):
    """一個 BIOS 映像的段落（沒有檔名前綴）。"""
    uc = b.get("microcode") or []
    if uc:
        return "Intel 微碼 " + counts_text([u.get("advisory") for u in uc])
    if b.get("platform") == "amd":
        a = b.get("amd")
        if a:
            return f"沒有 Intel 微碼；AMD 微碼已解析 {len(a.get('microcode') or [])} 份，{AMD_NO_MATCH}"
        return f"沒有 Intel 微碼；AMD PSP 目錄解析沒有執行（GAP），微碼、PSP、AGESA 都沒有列出；NOT_ASSESSED：資料庫沒有資料，以 AMD 公告為準"
    return "沒有 Intel 微碼"


def cell(inv):
    adv = inv.get("advisory") or {}
    bios = inv.get("bios") or []
    prefix = "資料表 GAP：" if adv.get("status") == "GAP" else ""
    if not bios:
        return prefix + "沒有 BIOS 映像"
    if len(bios) == 1:
        text = image_text(bios[0])
        if text.startswith("Intel 微碼 "):           # 單一映像：維持原本的「affected-candidate 3」格式
            text = text[len("Intel 微碼 "):]
        return prefix + text
    parts = [f"{short(b.get('file', '?'))}：{image_text(b)}" for b in bios[:MAX_IMAGES]]
    if len(bios) > MAX_IMAGES:
        parts.append(f"其餘 {len(bios) - MAX_IMAGES} 個映像沒有列出")
    return prefix + "；".join(parts)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("-")
        return 64
    try:
        with open(argv[0], encoding="utf-8") as fh:
            inv = json.load(fh)
        print(cell(inv))
    except (OSError, ValueError, AttributeError, TypeError):
        print("-")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
