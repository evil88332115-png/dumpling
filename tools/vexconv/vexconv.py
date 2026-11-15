#!/usr/bin/env python3
"""OpenVEX <-> CycloneDX VEX 雙向轉換（整合項 b）。

為什麼需要：Grype 只讀 OpenVEX/CSAF，Dependency-Track 只收發 CycloneDX VEX。
規則：
- 狀態與理由盡量對映；對不上的理由記在屬性裡，轉回去時還原，不遺失。
- 不認得的狀態或欄位直接報錯，不猜。
用法：vexconv.py to-cdx in.openvex.json out.cdx.json
      vexconv.py to-openvex in.cdx.json out.openvex.json [--author NAME]
"""
import argparse, json, re, sys, unicodedata, uuid
from datetime import datetime, timezone

STATUS_OV_TO_CDX = {"not_affected": "not_affected", "affected": "exploitable",
                    "fixed": "resolved", "under_investigation": "in_triage"}
STATUS_CDX_TO_OV = {"not_affected": "not_affected", "exploitable": "affected",
                    "resolved": "fixed", "in_triage": "under_investigation",
                    "false_positive": "not_affected", "resolved_with_pedigree": "fixed"}
JUST_OV_TO_CDX = {
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
    "vulnerable_code_cannot_be_controlled_by_adversary": "protected_at_runtime",
    "component_not_present": "code_not_present",
}
JUST_CDX_TO_OV = {
    "code_not_present": "vulnerable_code_not_present",
    "code_not_reachable": "vulnerable_code_not_in_execute_path",
    "protected_by_mitigating_control": "inline_mitigations_already_exist",
    "protected_at_runtime": "vulnerable_code_cannot_be_controlled_by_adversary",
    # 下面五個在 OpenVEX 沒有對應，取意思最接近、而且不比原意更強的（對照 OpenVEX 規格的說明；原值以標籤寫進 impact_statement，轉回時還原）：
    # 需要某個設定／依賴／環境才能被利用，而產品裡沒有 → 弱點程式碼不會被執行（not_in_execute_path）；
    # 「inline_mitigations_already_exist」在規格裡是產品內建、使用者不能關的保護，只有編譯器的保護（protected_by_compiler）接近；
    # 網路邊界的保護不在產品內 → 攻擊者控制不了弱點程式碼（cannot_be_controlled_by_adversary）。
    "protected_by_compiler": "inline_mitigations_already_exist",
    "protected_at_perimeter": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_configuration": "vulnerable_code_not_in_execute_path",
    "requires_dependency": "vulnerable_code_not_in_execute_path",
    "requires_environment": "vulnerable_code_not_in_execute_path",
}
# 反向對映的「精確」結果；不在這裡面的 CDX 理由轉成 OpenVEX 時有損失，會在說明文字加標籤以便還原
EXACT_CDX = {"code_not_present", "code_not_reachable", "protected_by_mitigating_control", "protected_at_runtime"}
TAG_J = "[cyclonedx:justification="
TAG_S = "[cyclonedx:state=false_positive]"
TAG_P = "[cyclonedx:state=resolved_with_pedigree]"
PROP_JUST = "openvex:justification"
PROP_ACTION = "openvex:action_statement"
PROP_NOTES = "openvex:status_notes"
# 沒有評估（M7c-1，A4／D-057）：CycloneDX 沒有「沒評估」這個狀態，用 in_triage 加這個屬性；OpenVEX 用 under_investigation 加固定的 status_notes。
# 客戶版的 OpenVEX 用中性英文（不帶內部名稱）。轉換時兩種句子都認得，轉回 CycloneDX 要把屬性加回去
PROP_ASSESSMENT = "dumpling:assessment"
NOT_ASSESSED = "NOT_ASSESSED"
NOTE_NOT_ASSESSED = "dumpling: not assessed"
NOTE_NOT_ASSESSED_CUSTOMER = "Not yet assessed by the manufacturer"
NOT_ASSESSED_NOTES = (NOTE_NOT_ASSESSED, NOTE_NOT_ASSESSED_CUSTOMER)
# 內部版 CycloneDX 的 detail：寫明這是沒評估，不是有人在調查
DETAIL_NOT_ASSESSED = ("Not assessed: no VEX assessment has been recorded for this vulnerability on this component. "
                       "The state in_triage is used only because CycloneDX has no 'not assessed' state; it does not mean that "
                       "anyone is investigating it.")

# ---------- 排除的依據（M7c-2，D-035／D-057） ----------
# 內部版 CycloneDX：每一筆依據依序一組屬性 dumpling:evidence（類型）、dumpling:evidence-location（位置）、選填 dumpling:evidence-kernel
# （這一筆依據是哪一顆核心的；映像有多顆核心時每顆各一筆，D-036）。沒有類型的排除只有一個 dumpling:evidence＝none（沒有位置）。
# 內部版 OpenVEX：status_notes 每一筆依據一行，格式固定：
#     dumpling: evidence=<類型>; location=<位置>
#     dumpling: evidence=<類型>; kernel=<核心版本>; location=<位置>
#     dumpling: evidence=none
# 解析一律用 re.fullmatch、一行一筆（只以換行字元分行）；類型只收五種；位置不能有「;」、換行與控制字元、前後空白、長度 1–512（location_problem）；
# 不合格的行不轉成屬性，原樣留在一般 notes。為什麼拒收「;」而不是編碼：分隔符號與位置不會混淆、輸出的行不用跳脫規則，
# 輸入端（vex-annotations.json）與這裡用同一個檢查（縱深防禦：vexconv 單獨轉換外來檔案時也擋得住）。
PROP_EVIDENCE = "dumpling:evidence"
PROP_EVIDENCE_LOCATION = "dumpling:evidence-location"
PROP_EVIDENCE_KERNEL = "dumpling:evidence-kernel"
EVIDENCE_TYPES = ("build-record", "source", "on-device", "design-doc", "vendor-statement")
EVIDENCE_NONE = "none"
LOCATION_MAX = 512
KERNEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~:-]{0,127}")
NOTE_EVIDENCE_PREFIX = "dumpling: evidence="
_TYPES_RE = "|".join(re.escape(t) for t in EVIDENCE_TYPES)
EVIDENCE_LINE = re.compile(rf"dumpling: evidence=({_TYPES_RE})(?:; kernel=([A-Za-z0-9][A-Za-z0-9._+~:-]{{0,127}}))?; location=(.+)")
EVIDENCE_NONE_LINE = NOTE_EVIDENCE_PREFIX + EVIDENCE_NONE
NOTE_EVIDENCE_INVALID = "dumpling: evidence-invalid="
# 內部版 OpenVEX 的 status_notes 只在這兩種狀態帶依據（排除）
EVIDENCE_STATUSES = ("not_affected", "fixed")


def location_problem(loc):
    """依據位置的共同限制 → 問題（文字）或 None：要是文字、前後沒有空白、不是空的、不超過 512 字、沒有「;」、沒有換行與控制字元
    （Unicode 的 Cc、Cf〔含零寬與雙向控制字元〕、Zl、Zp）。"""
    if not isinstance(loc, str):
        return "must be a string"
    if not loc.strip():
        return "must not be empty"
    if loc != loc.strip():
        return "must not start or end with whitespace"
    if len(loc) > LOCATION_MAX:
        return f"must not be longer than {LOCATION_MAX} characters"
    if ";" in loc:
        return "must not contain ';'"
    if any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in loc):
        return "must not contain a line break or a control character"
    return None


def kernel_problem(k):
    return None if isinstance(k, str) and KERNEL_RE.fullmatch(k) else "not a kernel version (letters, digits and . _ + ~ : - only, up to 128 characters)"


def evidence_line(typ, location, kernel=None):
    """一筆依據 → OpenVEX 的一行；不合格 → None。"""
    if typ not in EVIDENCE_TYPES or location_problem(location) or (kernel is not None and kernel_problem(kernel)):
        return None
    return f"{NOTE_EVIDENCE_PREFIX}{typ}" + (f"; kernel={kernel}" if kernel else "") + f"; location={location}"


def parse_evidence_line(line):
    """一行 → (類型, 核心或 None, 位置)、("none", None, None) 或 None（不是合格的依據行）。"""
    if line == EVIDENCE_NONE_LINE:
        return (EVIDENCE_NONE, None, None)
    m = EVIDENCE_LINE.fullmatch(line)
    if not m or location_problem(m.group(3)):
        return None
    return (m.group(1), m.group(2), m.group(3))


def evidence_props(props):
    """CycloneDX 的屬性清單 → ([依據: (類型, 核心, 位置) 或 (none, None, None)], [不合格的組: 文字行])。
    依序讀：dumpling:evidence 後面緊接 dumpling:evidence-location（再緊接選填的 dumpling:evidence-kernel）算一組；孤立的位置或核心屬性、
    類型不是五種（也不是 none）、位置或核心不合格 → 不合格，改成不會被解析的一行（JSON 編碼，ASCII），留在 notes。"""
    ok, bad, i, n = [], [], 0, len(props)
    names = (PROP_EVIDENCE, PROP_EVIDENCE_LOCATION, PROP_EVIDENCE_KERNEL)

    def nm(j):
        p = props[j]
        return p.get("name") if isinstance(p, dict) else None

    def val(j):
        return props[j].get("value") if isinstance(props[j], dict) else None
    while i < n:
        name = nm(i)
        if name not in names:
            i += 1
            continue
        if name != PROP_EVIDENCE:
            bad.append({"name": name, "value": val(i)})
            i += 1
            continue
        typ, loc, ker, j = val(i), None, None, i + 1
        if typ == EVIDENCE_NONE:
            ok.append((EVIDENCE_NONE, None, None))
            i = j
            continue
        if j < n and nm(j) == PROP_EVIDENCE_LOCATION:
            loc, j = val(j), j + 1
            if j < n and nm(j) == PROP_EVIDENCE_KERNEL:
                ker, j = val(j), j + 1
        if typ in EVIDENCE_TYPES and loc is not None and not location_problem(loc) and (ker is None or not kernel_problem(ker)):
            ok.append((typ, ker, loc))
        else:
            bad.append({"type": typ, "location": loc, **({"kernel": ker} if ker is not None else {})})
        i = j
    return ok, [NOTE_EVIDENCE_INVALID + json.dumps(b, ensure_ascii=True, sort_keys=True) for b in bad]


def _escape_note_line(line):
    """一般 notes 裡長得像依據行的一行（去掉前面的反斜線後解析得出來）在前面加一個反斜線，讀回時拿掉：說明文字（例如 detail）
    不能被讀成一筆依據。解析不出來的行（包含不合格的依據行）不動，所以兩個方向都是原樣。"""
    return "\\" + line if parse_evidence_line(line.lstrip("\\")) else line


def _unescape_note_line(line):
    if line.startswith("\\") and parse_evidence_line(line.lstrip("\\")):
        return line[1:]
    return line


def join_notes(note, evidence):
    """OpenVEX 的 status_notes：原本的 notes（長得像依據行的行先跳脫）加上依據行（每筆一行，在最後）。回傳文字或 None。"""
    lines = [_escape_note_line(x) for x in note.split("\n")] if note else []
    out = "\n".join(lines + list(evidence))
    return out or None


def split_notes(notes):
    """OpenVEX 的 status_notes → (其餘的 notes 或 None, [依據])。依據行（fullmatch、類型與位置合格）轉成依據，其他行原樣保留
    （跳脫過的行還原）。只以換行字元分行。"""
    if not notes:
        return notes, []
    rest, ev = [], []
    for line in notes.split("\n"):
        e = parse_evidence_line(line)
        if e:
            ev.append(e)
        else:
            rest.append(_unescape_note_line(line))
    return ("\n".join(rest) if rest else None) or None, ev


class VexError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prod_id(p):
    if isinstance(p, str):
        return p
    pid = p.get("@id") or (p.get("identifiers") or {}).get("purl")
    if not pid:
        raise VexError(f"product without @id or purl: {p}")
    return pid


def to_cdx(ov):
    if "statements" not in ov:
        raise VexError("not an OpenVEX document: no 'statements'")
    vulns = []
    for i, st in enumerate(ov["statements"]):
        status = st.get("status")
        if status not in STATUS_OV_TO_CDX:
            raise VexError(f"statement {i}: unknown status {status!r}")
        vuln = st.get("vulnerability")
        if not isinstance(vuln, dict):
            raise VexError(f"statement {i}: vulnerability must be an object (OpenVEX spec)")
        vid = vuln.get("name")
        if not vid:
            raise VexError(f"statement {i}: no vulnerability name")
        analysis = {"state": STATUS_OV_TO_CDX[status]}
        props = []
        if status == "affected" and not st.get("action_statement"):
            raise VexError(f"statement {i}: 'affected' requires action_statement (OpenVEX spec)")
        if status == "not_affected" and not (st.get("justification") or st.get("impact_statement")):
            raise VexError(f"statement {i}: 'not_affected' requires justification or impact_statement (OpenVEX spec)")
        j = st.get("justification")
        if j:
            if j not in JUST_OV_TO_CDX:
                raise VexError(f"statement {i}: unknown justification {j!r}")
            analysis["justification"] = JUST_OV_TO_CDX[j]
            props.append({"name": PROP_JUST, "value": j})
        impact, notes = st.get("impact_statement"), st.get("status_notes")
        # 排除的依據（M7c-2）：status_notes 裡合格的依據行轉成屬性，其他行原樣留在 notes；只有 not_affected／fixed 帶依據
        evidence = []
        if status in EVIDENCE_STATUSES:
            notes, evidence = split_notes(notes)
        # 沒有評估的標記：under_investigation 加上固定的 status_notes（內部或客戶版的句子）→ 加回 dumpling:assessment
        not_assessed = status == "under_investigation" and notes in NOT_ASSESSED_NOTES and not impact
        if not_assessed:
            props.append({"name": PROP_ASSESSMENT, "value": NOT_ASSESSED})
        if notes and notes.startswith(TAG_P):
            analysis["state"] = "resolved_with_pedigree"
            notes = notes[len(TAG_P):].strip() or None
        detail = impact or notes
        if impact and notes:
            props.append({"name": PROP_NOTES, "value": notes})
        elif notes and not impact:
            props.append({"name": PROP_NOTES, "value": notes})
        if not_assessed and detail == NOTE_NOT_ASSESSED:
            detail = DETAIL_NOT_ASSESSED          # 內部句子還原成完整說明；客戶版的中性句子照留
        if detail:
            analysis["detail"] = detail
            # 還原 CDX 來源留下的標籤
            if detail.startswith(TAG_J) and "]" in detail:
                tag, _, rest = detail.partition("]")
                analysis["justification"] = tag[len(TAG_J):]
                detail = rest.strip()
                analysis["detail"] = detail
                if not detail:
                    del analysis["detail"]
                if "justification" in analysis and PROP_JUST in {p["name"] for p in props}:
                    props = [p for p in props if p["name"] != PROP_JUST]
            if detail.startswith(TAG_P):
                analysis["state"] = "resolved_with_pedigree"
                detail = detail[len(TAG_P):].strip()
                if detail: analysis["detail"] = detail
                else: analysis.pop("detail", None)
            if detail.startswith(TAG_S):
                analysis["state"] = "false_positive"
                detail = detail[len(TAG_S):].strip()
                if detail: analysis["detail"] = detail
                else: analysis.pop("detail", None)
        if st.get("action_statement"):
            props.append({"name": PROP_ACTION, "value": st["action_statement"]})
        for typ, ker, loc in evidence:
            props.append({"name": PROP_EVIDENCE, "value": typ})
            if typ != EVIDENCE_NONE:
                props.append({"name": PROP_EVIDENCE_LOCATION, "value": loc})
                if ker:
                    props.append({"name": PROP_EVIDENCE_KERNEL, "value": ker})
        if status == "affected":
            analysis["response"] = ["update"]
        v = {"id": vid, "analysis": analysis,
             "affects": [{"ref": _prod_id(p)} for p in st.get("products", [])]}
        aliases = vuln.get("aliases")
        if aliases:
            v["references"] = [{"id": a, "source": {"name": "alias"}} for a in aliases]
        if props:
            v["properties"] = props
        vulns.append(v)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
            "metadata": {"timestamp": ov.get("timestamp") or _now()},
            "vulnerabilities": vulns}


def to_openvex(cdx, author="sca-center", lenient=False):
    if cdx.get("bomFormat") != "CycloneDX":
        raise VexError("not a CycloneDX document")
    stmts = []
    for i, v in enumerate(cdx.get("vulnerabilities", [])):
        a = v.get("analysis") or {}
        state = a.get("state")
        if state is None:
            continue  # 沒有 analysis.state 就沒有 VEX 陳述（dumpling 的「沒評估」列有 in_triage 加標記屬性，不在這裡）
        if state not in STATUS_CDX_TO_OV:
            raise VexError(f"vulnerability {i}: unknown state {state!r}")
        try:
            vid = v["id"]
            refs = [x["ref"] for x in v.get("affects", [])]
        except KeyError as e:
            raise VexError(f"vulnerability {i}: missing field {e}")
        props = {p["name"]: p["value"] for p in v.get("properties", [])}
        st = {"vulnerability": {"name": vid},
              "products": [{"@id": r} for r in refs],
              "status": STATUS_CDX_TO_OV[state]}
        aliases = [r["id"] for r in v.get("references", []) if (r.get("source") or {}).get("name") == "alias"]
        if aliases:
            st["vulnerability"]["aliases"] = aliases
        detail = a.get("detail")
        cj = a.get("justification")
        # 排除的依據（M7c-2）：屬性 → status_notes 的依據行（接在其他 notes 後面）；不合格的組變成不會被解析的一行
        evlines = []
        if st["status"] in EVIDENCE_STATUSES:
            eok, ebad = evidence_props(v.get("properties", []))
            evlines = [EVIDENCE_NONE_LINE if t == EVIDENCE_NONE else evidence_line(t, loc, k) for t, k, loc in eok] + ebad
        if st["status"] == "not_affected":
            j = None
            prop_j = props.get(PROP_JUST)
            # 屬性只在 CDX 理由沒被人改過時才採用（避免舊屬性蓋掉 DT 裡的新判定）
            if prop_j and JUST_OV_TO_CDX.get(prop_j) == cj:
                j = prop_j
            elif cj:
                j = JUST_CDX_TO_OV.get(cj)
            if state == "false_positive" and not j:
                j = "vulnerable_code_not_present"
            tags = ""
            if cj and cj not in EXACT_CDX and not (prop_j and JUST_OV_TO_CDX.get(prop_j) == cj):
                tags += TAG_J + cj + "]"
            if state == "false_positive":
                tags += TAG_S
            if j:
                st["justification"] = j
            if not j and not (detail or tags):
                raise VexError(f"vulnerability {vid}: not_affected needs a justification or detail")
            impact = None if (detail and detail == props.get(PROP_NOTES)) else detail
            text = (tags + (" " + impact if impact and tags else impact or "")).strip()
            if text:
                st["impact_statement"] = text
            if props.get(PROP_NOTES) or evlines:
                st["status_notes"] = join_notes(props.get(PROP_NOTES), evlines)
        else:
            note = props.get(PROP_NOTES) or detail
            if state == "in_triage" and props.get(PROP_ASSESSMENT) == NOT_ASSESSED:
                # 沒有評估：固定的句子（原本就是客戶版的中性句子就保留）；detail 是給人讀的長說明，不放進 OpenVEX
                note = props[PROP_NOTES] if props.get(PROP_NOTES) in NOT_ASSESSED_NOTES else (
                    NOTE_NOT_ASSESSED_CUSTOMER if detail == NOTE_NOT_ASSESSED_CUSTOMER else NOTE_NOT_ASSESSED)
            if state == "resolved_with_pedigree":
                note = (TAG_P + (" " + note if note else "")).strip()
            if note or evlines:
                st["status_notes"] = join_notes(note, evlines) if st["status"] in EVIDENCE_STATUSES else note
        if st["status"] == "affected":
            act = props.get(PROP_ACTION)
            if not act:
                if not lenient:
                    raise VexError(f"vulnerability {vid}: exploitable needs an action statement "
                                   f"(property {PROP_ACTION}); use --lenient to fill a placeholder")
                act = "No action statement provided."
            st["action_statement"] = act
        stmts.append(st)
    if not stmts:
        raise VexError("no VEX statements to export (no vulnerability has an analysis state)")
    ts = (cdx.get("metadata") or {}).get("timestamp") or _now()
    return {"@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://sca-center.internal/vex/" + str(uuid.uuid4()),
            "author": author, "timestamp": ts, "version": 1, "statements": stmts}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["to-cdx", "to-openvex"])
    ap.add_argument("src"); ap.add_argument("dst")
    ap.add_argument("--author", default="sca-center")
    ap.add_argument("--lenient", action="store_true", help="exploitable 沒有 action 時填占位文字，而不是報錯")
    a = ap.parse_args(argv)
    try:
        data = json.load(open(a.src))
        out = to_cdx(data) if a.mode == "to-cdx" else to_openvex(data, a.author, a.lenient)
    except (VexError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr); return 2
    json.dump(out, open(a.dst, "w"), indent=2, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
