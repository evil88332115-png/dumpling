"""firmware-ci.sh 摘要表的「公告比對」欄：fw-inventory.json → 一行文字（每個 BIOS 映像各一段，有 NVIDIA vBIOS 時再加一段）。

用法：python3 -I firmware_advisory_cell.py <fw-inventory.json>
只讀 fw-inventory.json 的 advisory、bios[]、vbios[]、vbios_advisory、rules_advisory（x86_firmware.py 的輸出）；文字裡有映像檔名（不可信資料），
由呼叫端（firmware-ci.sh）再經 firmware_mdsafe 跳脫。不判斷任何漏洞：這一欄只是比對結果的計數與沒有比對的原因。
"""
import json
import sys

ORDER = ("affected-candidate", "older-no-sa", "up-to-date", "NOT_ASSESSED")
VBIOS_ORDER = ("affected", "fixed", "NOT_ASSESSED")
AMD_NO_MATCH = "沒有做公告比對（NOT_ASSESSED：資料庫沒有資料，以 AMD 公告為準）"
MAX_IMAGES = 20
NO_MATCH = "（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準）"           # 沒有可比對的 Intel 微碼時也要寫明（和 ME、其他元件的說法一致）


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
    return "沒有 Intel 微碼" + NO_MATCH


def vbios_text(inv):
    """NVIDIA vBIOS 的一段：個數與各結果的計數（對照表不能用時寫 GAP）。沒有 vBIOS → None（BIOS 樣本的欄位維持原樣）。"""
    vb = inv.get("vbios") or []
    if not vb:
        return None
    va = inv.get("vbios_advisory") or {}
    c = {}
    for v in vb:
        m = (v.get("advisory") or {}).get("match", "NOT_ASSESSED")
        c[m] = c.get(m, 0) + 1
    counts = "、".join([f"{k} {c[k]}" for k in VBIOS_ORDER if k in c] + [f"{k} {n}" for k, n in sorted(c.items()) if k not in VBIOS_ORDER])
    gap = "對照表 GAP，" if va.get("status") == "GAP" else ""
    return f"NVIDIA vBIOS {len(vb)} 個：{gap}{counts}（NOT_ASSESSED：資料庫沒有資料，以廠商公告為準；fixed 與 affected 只是對照表的比對，不代表沒有其他漏洞）"


RULE_ORDER = ("affected", "not-affected", "NOT_ASSESSED")


def rules_text(inv):
    """廠商公告規則表（rules_advisory）的一段：各建議的計數；有 affected 的建議（即使規則還是初審）要待人審；規則表不能用寫 GAP。
    inventory 沒有 rules_advisory（舊輸出）→ None（欄位維持原樣）。這是依規則表的建議，不是漏洞判定。"""
    ra = inv.get("rules_advisory")
    if not isinstance(ra, dict):
        return None
    if ra.get("status") == "GAP":
        return f"規則表 GAP（{ra.get('gap', '')}）：{ra.get('components', 0)} 個元件的規則建議都是 NOT_ASSESSED：資料庫沒有資料，以廠商公告為準"
    c = ra.get("counts") or {}
    counts = "、".join([f"{k} {c[k]}" for k in RULE_ORDER if k in c] + [f"{k} {v}" for k, v in sorted(c.items()) if k not in RULE_ORDER]) or "無元件"
    items = ra.get("items") or []
    aff = [x for x in items if x.get("suggestion") == "affected"]
    t = f"規則表建議（{(ra.get('table') or {}).get('updated', '?')} 整理）{counts}"
    if aff:
        pre = any("preliminary" in str(x.get("state")) for x in aff)
        ids = sorted({i for x in aff for i in x.get("rule_ids", [])})
        t += f"：affected {len(aff)} 個待人審（{'、'.join(ids)}；" + ("依初審規則的建議，待負責單位確認" if pre else "依已確認規則的建議") + "）"
    return t + "；是否受影響以廠商公告為準，之後的新公告沒有收錄"


def cell(inv):
    text = bios_cell(inv)
    vt = vbios_text(inv)
    if vt is not None:
        text = text + "；" + vt
    rt = rules_text(inv)
    return text if rt is None else text + "；" + rt


def bios_cell(inv):
    adv = inv.get("advisory") or {}
    bios = inv.get("bios") or []
    prefix = "資料表 GAP：" if adv.get("status") == "GAP" else ""
    if not bios:
        return prefix + "沒有 BIOS 映像" + NO_MATCH
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
