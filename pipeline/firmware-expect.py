#!/usr/bin/env python3
"""把 firmware.yml 的 expected 跟 firmware-bios.sh 的輸出逐項比對（只讀、不連網）。

用法：python3 -I pipeline/firmware-expect.py <firmware.yml> --out <firmware-bios.sh 的 --out 資料夾> [--strict]
每一項印一行：FIRMWARE-EXPECT<TAB>OK|MISMATCH|MISSING|NOT_RUN<TAB><樣本><TAB><項目>：預期 …、實際 …
最後一行：FIRMWARE-EXPECT<TAB>SUMMARY<TAB><樣本><TAB>比對 N 項、M 項不符 …。這一行只是計數，不代表整體通過或安全。

  OK        預期值跟輸出一致
  MISMATCH  輸出裡有這個項目，但值不一樣
  MISSING   輸出裡找不到這個項目
  NOT_RUN   沒有輸出檔（firmware-bios.sh 沒跑或沒產出），這個樣本的每一項都標這個
退出碼：有 MISMATCH 或 MISSING＝1；--strict 時 NOT_RUN 也算 1；expected 或輸出檔格式錯誤＝64；其餘 0。
expected 沒寫的項目不比；寫了不認得的鍵視為格式錯誤（避免打錯字而悄悄不比）。

expected 欄位（都選填，只寫有佐證的）：
  intel_me            字串，ME 版本（例如 14.0.47.1558）
  microcode           清單，每項 {cpuid, platform_mask, revision}；映像裡要有同 cpuid、同 platform 且 revision 相同的微碼
  fsp                 版本字串清單；每個版本都要在映像的 FSP 裡找得到（多出來的不比）
  coreboot_version    字串，COREBOOT_VERSION 原字串
  coreboot_revision   字串，git 修訂（縮寫即可，雙方其中一方是另一方的前綴就算相符，至少 7 碼）
  dasharo_version     字串，Dasharo 版本（例如 v1.2.0）
  coreboot_build_date 字串 YYYY-MM-DD，coreboot 建置日期（UTC）
  edk2_revision       字串，coreboot config 的 CONFIG_EDK2_TAG_OR_REV（前綴規則同上）
  intel_gop           字串，SBOM 裡 `Intel GOP driver` 元件的 version（目前只有 build 編號，例如 1070，不是 17.0.1070）
  intel_legacy_vbios  字串，SBOM 裡 `Intel legacy VBIOS (option ROM)` 元件的 version（例如 "1003 PC 14.34"）
  （沒有 intel_vbt：VBT 元件的 version 是 $VBT 表頭的格式版本（x100），不是顯示韌體的發行版本，不拿來比對）
"""
import argparse
import json
import os
import sys

try:
    import yaml
except ImportError:
    yaml = None

KEYS = ("intel_me", "microcode", "fsp", "coreboot_version", "coreboot_revision",
        "dasharo_version", "coreboot_build_date", "edk2_revision", "intel_gop", "intel_legacy_vbios")
GFX_NAMES = {"intel_gop": "Intel GOP driver", "intel_legacy_vbios": "Intel legacy VBIOS (option ROM)"}
STATUSES = ("OK", "MISMATCH", "MISSING", "NOT_RUN")


class FormatError(Exception):
    pass


def scalar(v, what):
    if isinstance(v, bool) or not isinstance(v, (str, int, float)) or str(v).strip() == "":
        raise FormatError("%s 必須是非空的字串" % what)
    return str(v).strip()


def hexint(v, what):
    s = scalar(v, what)
    try:
        return int(s, 16)
    except ValueError:
        raise FormatError("%s 不是十六進位數字：%s" % (what, s))


def prefix_match(a, b):
    a, b = a.lower(), b.lower()
    return len(min(a, b, key=len)) >= 7 and (a.startswith(b) or b.startswith(a)) or a == b


def sbom_components(sbom):
    return [c for c in (sbom or {}).get("components", []) if isinstance(c, dict)]


def prop(comp, name):
    return [p.get("value") for p in comp.get("properties", []) if isinstance(p, dict) and p.get("name") == name]


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except (ValueError, OSError) as e:
        raise FormatError("%s 讀不了（%s）" % (os.path.basename(path), type(e).__name__))


def bios_images(inv):
    if not isinstance(inv, dict) or not isinstance(inv.get("bios"), list):
        raise FormatError("fw-inventory.json 沒有 bios 清單")
    return [b for b in inv["bios"] if isinstance(b, dict)]


def cb_items(inv, key):
    out = []
    for b in bios_images(inv):
        cb = b.get("cbfs")
        if isinstance(cb, dict) and isinstance(cb.get(key), list):
            out += [x for x in cb[key] if isinstance(x, dict)]
    return out


def uniq(xs):
    return sorted({x for x in xs if x not in (None, "")})


def show(xs):
    return "、".join(xs) if xs else "（無）"


def result(status, label, expected, actual):
    return (status, "%s：預期 %s、實際 %s" % (label, expected, actual))


def compare(exp, inv, sbom):
    """回傳 [(status, 一行說明)]。inv／sbom 為 None 代表檔案不存在（NOT_RUN）。"""
    items = []
    if not isinstance(exp, dict):
        raise FormatError("expected 必須是 mapping")
    for k in exp:
        if k not in KEYS:
            raise FormatError("expected 有不認得的鍵 %s（可用：%s）" % (k, "、".join(KEYS)))
    # 先全部驗證格式，再比對，這樣格式錯一定報錯，不會因為 NOT_RUN 而被略過
    plan = []
    if "intel_me" in exp:
        plan.append(("intel_me", "Intel ME 版本", scalar(exp["intel_me"], "intel_me")))
    if "microcode" in exp:
        mc = exp["microcode"]
        if not isinstance(mc, list) or not mc:
            raise FormatError("microcode 必須是非空清單")
        for i, m in enumerate(mc):
            if not isinstance(m, dict) or set(m) != {"cpuid", "platform_mask", "revision"}:
                raise FormatError("microcode[%d] 必須剛好有 cpuid、platform_mask、revision" % i)
            plan.append(("microcode", "微碼 %s／platform %s" % (scalar(m["cpuid"], "cpuid").upper(), scalar(m["platform_mask"], "platform_mask")),
                         (hexint(m["cpuid"], "cpuid"), hexint(m["platform_mask"], "platform_mask"), hexint(m["revision"], "revision"),
                          scalar(m["revision"], "revision"))))
    if "fsp" in exp:
        fl = exp["fsp"]
        if not isinstance(fl, list) or not fl:
            raise FormatError("fsp 必須是非空的版本清單")
        for i, v in enumerate(fl):
            plan.append(("fsp", "FSP 版本", scalar(v, "fsp[%d]" % i)))
    for k, label in (("coreboot_version", "coreboot 版本"), ("coreboot_revision", "coreboot git 修訂"),
                     ("dasharo_version", "Dasharo 版本"), ("coreboot_build_date", "coreboot 建置日期"),
                     ("edk2_revision", "edk2 修訂")):
        if k in exp:
            v = scalar(exp[k], k)
            if k == "coreboot_build_date" and not (len(v) == 10 and v[4] == "-" and v[7] == "-"):
                raise FormatError("coreboot_build_date 必須是 YYYY-MM-DD")
            plan.append((k, label, v))
    for k, label in (("intel_gop", "Intel GOP driver 版本"), ("intel_legacy_vbios", "Intel legacy VBIOS 版本")):
        if k in exp:
            plan.append((k, label, scalar(exp[k], k)))
    if inv is None:
        return [("NOT_RUN", "%s：預期 %s、沒有 fw-inventory.json（firmware-bios.sh 沒跑或沒有輸出）" % (p[1], p[2][3] if p[0] == "microcode" else p[2]))
                for p in plan]
    bios = bios_images(inv)
    for key, label, want in plan:
        if key == "intel_me":
            got = uniq((b.get("me") or {}).get("version") for b in bios if isinstance(b.get("me"), dict))
            if not got:
                items.append(result("MISSING", label, want, "（無）"))
                continue
            st = "OK" if want in got else "MISMATCH"
            if st == "OK" and sbom is not None:      # SBOM 也要有同版本的 ME 元件
                sb = uniq(c.get("version") for c in sbom_components(sbom) if c.get("name") == "Intel CSE firmware")
                if want not in sb:
                    items.append(result("MISMATCH", label, want, "inventory %s，但 SBOM 的 Intel CSE firmware 是 %s" % (show(got), show(sb))))
                    continue
            items.append(result(st, label, want, show(got)))
        elif key == "microcode":
            cpu, plat, rev, rev_s = want
            ms = [m for b in bios for m in (b.get("microcode") or []) if isinstance(m, dict)]
            same = [m for m in ms if _hex(m.get("cpuid")) == cpu and _hex(m.get("platform_id")) == plat]
            if not same:
                items.append(result("MISSING", label, "revision " + rev_s, "（映像裡沒有這個 cpuid／platform 的微碼）"))
                continue
            revs = uniq(str(m.get("revision")) for m in same)
            if rev not in {_hex(m.get("revision")) for m in same}:
                items.append(result("MISMATCH", label, "revision " + rev_s, "revision " + show(revs)))
                continue
            if sbom is not None and not any(c.get("name", "").startswith("Intel CPU microcode") and _hex(c.get("version")) == rev
                                            and any(_hex(v) == cpu for v in prop(c, "sca-center:cpuid"))
                                            and any(_hex(v) == plat for v in prop(c, "sca-center:platform-id"))
                                            for c in sbom_components(sbom)):
                items.append(result("MISMATCH", label, "revision " + rev_s, "inventory 有，但 SBOM 沒有對應的微碼元件"))
                continue
            items.append(result("OK", label, "revision " + rev_s, "revision " + show(revs)))
        elif key == "fsp":
            got = uniq(x.get("revision") for x in cb_items(inv, "fsp"))
            if not got:
                items.append(result("MISSING", label, want, "（映像裡沒有 FSP）"))
                continue
            if want not in got:
                items.append(result("MISMATCH", label, want, show(got)))
                continue
            if sbom is not None and not any(c.get("version") == want and str(c.get("name", "")).startswith("Intel FSP") for c in sbom_components(sbom)):
                items.append(result("MISMATCH", label, want, "inventory 有，但 SBOM 沒有對應的 FSP 元件"))
                continue
            items.append(result("OK", label, want, show(got)))
        elif key in GFX_NAMES:
            # 只看 SBOM（GOP／legacy VBIOS 沒有進 inventory 的固定欄位）。映像裡可能有好幾個同名元件（例如多份 GOP），
            # 跟 fsp 一樣：任一個的 version 相符就 OK，其餘不比。元件在但沒讀到 version（GAP）→ MISSING，不猜。
            comps = [c for c in sbom_components(sbom) if c.get("name") == GFX_NAMES[key]]
            got = uniq(str(c.get("version")) for c in comps if c.get("version"))
            if not got:
                items.append(result("MISSING", label, want, "（SBOM 裡沒有 %s 元件）" % GFX_NAMES[key] if not comps
                                    else "（有 %d 個 %s 元件，但都沒讀到版本）" % (len(comps), GFX_NAMES[key])))
            else:
                items.append(result("OK" if want in got else "MISMATCH", label, want, show(got)))
        else:
            if key == "edk2_revision":
                got = uniq(((x.get("config") or {}).get("keys") or {}).get("CONFIG_EDK2_TAG_OR_REV") for x in cb_items(inv, "coreboot"))
            else:
                field = {"coreboot_version": "version", "coreboot_revision": "git_revision", "dasharo_version": "dasharo_version",
                         "coreboot_build_date": "build_time"}[key]
                got = uniq(x.get(field) for x in cb_items(inv, "coreboot"))
                if key == "coreboot_build_date":
                    got = uniq(str(g)[:10] for g in got)
            if not got:
                items.append(result("MISSING", label, want, "（映像裡沒有）"))
                continue
            same = want in got if key in ("coreboot_version", "dasharo_version", "coreboot_build_date") else any(prefix_match(want, g) for g in got)
            items.append(result("OK" if same else "MISMATCH", label, want, show(got)))
    return items


def _hex(v):
    try:
        return int(str(v), 16)
    except (TypeError, ValueError):
        return None


def run(manifest, out, strict=False, emit=print):
    """回傳退出碼。"""
    if yaml is None:
        emit("FIRMWARE-EXPECT\tERROR\t-\t缺少 PyYAML（apt install python3-yaml）")
        return 64
    sample = os.path.basename(os.path.dirname(os.path.abspath(manifest))) or "-"
    try:
        try:
            with open(manifest, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as e:
            raise FormatError("firmware.yml 讀不了（%s）" % type(e).__name__)
        if not isinstance(doc, dict):
            raise FormatError("firmware.yml 不是 mapping")
        exp = doc.get("expected")
        if exp in (None, {}):
            emit("FIRMWARE-EXPECT\tSUMMARY\t%s\t比對 0 項、0 項不符（這個樣本沒有寫 expected）；不代表整體通過" % sample)
            return 0
        inv = load_json(os.path.join(out, "fw-inventory.json"))
        sbom = load_json(os.path.join(out, "fw.cdx.json")) if inv is not None else None
        if inv is not None and sbom is None:
            raise FormatError("有 fw-inventory.json 但沒有 fw.cdx.json")
        items = compare(exp, inv, sbom)
    except FormatError as e:
        emit("FIRMWARE-EXPECT\tERROR\t%s\t%s" % (sample, str(e).replace("\n", " ").replace("\t", " ")))
        return 64
    counts = {s: 0 for s in STATUSES}
    for st, text in items:
        counts[st] += 1
        emit("FIRMWARE-EXPECT\t%s\t%s\t%s" % (st, sample, text.replace("\n", " ").replace("\t", " ")))
    bad = counts["MISMATCH"] + counts["MISSING"] + (counts["NOT_RUN"] if strict else 0)
    emit("FIRMWARE-EXPECT\tSUMMARY\t%s\t比對 %d 項、%d 項不符（OK %d、MISMATCH %d、MISSING %d、NOT_RUN %d）；不代表整體通過"
         % (sample, len(items), counts["MISMATCH"] + counts["MISSING"], counts["OK"], counts["MISMATCH"], counts["MISSING"], counts["NOT_RUN"]))
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n")[0])
    ap.add_argument("manifest")
    ap.add_argument("--out", required=True)
    ap.add_argument("--strict", action="store_true", help="NOT_RUN 也算失敗")
    a = ap.parse_args(argv)
    return run(a.manifest, a.out, a.strict)


if __name__ == "__main__":
    sys.exit(main())
