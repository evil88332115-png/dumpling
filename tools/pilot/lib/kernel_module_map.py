#!/usr/bin/env python3
"""kernel_module_map.py：核心 CVE 修補動到的每個檔案編進哪裡（sca-scan 的 C-kernel-module-map）。
寫 scan/kernel-module-map.json（schema sca-center-kernel-module-map/1，格式見 tools/pilot/README.md 的 C-kernel-module-map），
並印一行 status：
  C-kernel-module-map<TAB>狀態<TAB>說明

用法：與 kernel_config.py 相同的輸入（--grype／--findings／--cves、--kernel-map、--kernel-version、--from [--prefix]
  或 --config＋--makefiles-dir、--mirror、--max-age-days），[--kernel-config <這次的 scan/kernel-config.json>]，--out <kernel-module-map.json>。
  另外 [--source-tree <核心原始碼樹>]（Makefile／Kbuild 的來源，和 kernel_config.py 同一個讀法與規則；.config、模組、Image 照舊來自 --from）、
  [--cves-origin <文字>]（--cves 的清單來源，只記在 inputs.cves_origin）。
  --kernel-config：記下 C-kernel-config 用的 CNA 鏡像 commit；和這次讀到的不同 → GAP。
  讀取、CVE 的選取、CNA 鏡像、.config／Makefile 的解析與「有沒有編」都沿用 kernel_config.py（同一份程式，以路徑載入），
  這裡只多做「編進哪裡」：
    每個 programFile（.c／.S／.rs → .o）依 Kbuild 的文字規則找到它最後連結成的物件：
      obj-y／obj-$(CONFIG_X)=y（資料夾也是以 =y 進入）→ builtin；obj-m／obj-$(CONFIG_X)=m → 模組，名稱是那個物件的檔名；
      組合物件 foo-y／foo-objs／foo-$(CONFIG_Y) 的成員 → 跟著 foo.o 走（可多層）；foo-m 的成員（或成員條件是 =m）只在 foo 是模組時算，
      foo 是 builtin 時 → unknown；資料夾只以 =m 或 subdir- 進入時，裡面的 obj-y 不會連進 vmlinux → unknown；lib-y → builtin。
      $(subst m,y,$(CONFIG_X))／$(CONFIG_X:m=y) 在 =m 時是編進核心；同一個物件同時在 obj-y 與 obj-m → 只編進核心；
      物件或任何一層組合物件也列在 extra-／always- → 不說「只在模組」（unknown）。
    build：
      "builtin"：任何一條路徑是 builtin（只要有一條就是）；
      "module"：每一條路徑都是模組，而且「不會在 vmlinux 裡」的證明和 kernel_config.py 判「沒編」的標準相同
        （規則所在資料夾與每一層上層的 Makefile 都看得懂、沒有別的資料夾的規則直接編這個檔案、核心的主.次版本有 #include 的 .c 清單）；
      "not_built"：kernel_config.py 判 False，而且 judge_cve 的 not_affected 前提也成立（有 #include 清單、有模組目錄、
        模組目錄沒有同名的 .ko）；
      "unknown"：其他（附 reason）。標頭檔、非程式檔一律 unknown。
    交叉核對（模組目錄的 modules.order、modules.builtin）：Kbuild 說是模組，modules.order 要有同一個路徑的 .ko
      （沒有 modules.order → unknown：module 與 CVE 的 modules 只會出現通過核對、在 modules_order 裡的名稱）；Kbuild 說是 builtin，
      modules.order 不能有它（modules.builtin 有時記下 module_path）。對不上 → unknown，reason 以 "kbuild/modules.order disagree" 開頭，
      不挑一邊（Kbuild 判沒編、清單卻列了它也是）。Kbuild 判斷不了、但物件本身列在 modules.builtin → builtin（只往保守的方向補）。
      模組名稱比較時 - 與 _ 視為相同（同 modprobe），module 是正規化（_）的名稱，module_kbuild 是 Kbuild 的原名。
    in_image：模組路徑的 .ko 在 /usr/lib/modules/<版本>/ 裡（true／false），或 builtin 而 modules.builtin 有列（true）；
      沒有模組目錄、builtin 但沒有列、not_built、unknown → null。只是證據，K2 不用它判斷「模組被移除」。
  每個 CVE（cves 物件，鍵是大寫的 CVE 編號）：files、modules（build 是 module 的模組名稱）、all_in_modules
  （每個檔案都是 module）、builtin（true：有檔案是 builtin；false：每個檔案是 module 或 not_built，且至少一個 module；
  null：其他，包含全部 not_built——那是 C-kernel-config 的判定）、reason、hints（header_only_with_unbuilt_c：只是提示）。
  shadowed_by：每個模組在模組目錄裡同名、但不在 modules.order 路徑的 .ko（updates/、extra/）。最上層的 modules_present 是
  模組目錄裡每個 .ko 的名稱：K2 判斷「模組不在映像裡」要依名稱看整個模組目錄，不能只看路徑。
  這裡不做任何 not_affected 判定，只對應。
狀態：沒有核心的 CVE → NOT_RUN（不寫檔）；沒有 .config／Makefile、版本對不上、CNA 鏡像沒有或過期 → GAP（cves 為空）；
  沒有模組目錄或缺 modules.order／modules.builtin → GAP（cves 照列，in_image 為 null；沒有 modules.order 時判成模組的檔案是 unknown）；
  其他 → OK。最上層另有 modules_order／modules_builtin：模組清單裡每個名稱（modprobe 形式，排序；沒有檔案時 null）。
退出碼：0 已判定（OK／GAP／NOT_RUN）；3 輸入錯誤（同時印 FAIL 那一行）。原始輸入一律不改。
"""
import argparse
import functools
import hashlib
import importlib.util
import json
import os
import posixpath
import re
import sys
from pathlib import Path

STAGE = "C-kernel-module-map"
SCHEMA = "sca-center-kernel-module-map/1"
HERE = Path(__file__).resolve().parent
BUILDS = ("builtin", "module", "not_built", "unknown")
MAX_NEST = 8                   # 組合物件的層數上限（links、ancestors）
NEST_WHY = "composite objects nested deeper than"
DISAGREE = "kbuild/modules.order disagree"
ALL_NOT_BUILT = "all files not_built (K1 / kernel-config decides)"
METHOD = "Kbuild rules + .config map each fixed file to vmlinux or a .ko, cross-checked with modules.order/builtin; no make run"
METHOD_DETAIL = ("Kbuild text rules of the product kernel (obj-y / obj-m / obj-$(CONFIG_X) += foo.o and dir/, composite members "
          "foo-y / foo-objs / foo-$(CONFIG_Y), nested directories) evaluated against its .config, without running make; each "
          "Linux kernel CNA programFile is mapped to the object it is linked into (built-in or the .ko module) and module names "
          "are cross-checked against /usr/lib/modules/<version>/modules.order and modules.builtin ('-' and '_' compared as equal). "
          "Anything uncertain is unknown; no not_affected verdict is made here.")
LIMITATIONS = [
    "Only Makefile/Kbuild text is read; make is not run. Conditional sections (ifeq/ifdef), unexpandable entries and "
    "fragments make a file unknown, never module or not_built.",
    "'module' means every Kbuild path of the file ends in a module and none in vmlinux, with the same proof standard as "
    "kernel_config.py's 'not built' (readable Makefiles up the tree, no other directory's rule compiles the file, an "
    "#included-.c list for the kernel version). Vendor patches that #include a .c file are not covered by the list.",
    "A member listed in foo-m (or with an =m condition) of a built-in composite foo is unknown rather than excluded.",
    "Lists expanded from variables ($(foo-y)) carry the conditions of their own assignments; an =m condition there is "
    "treated as a module, and the modules.order cross-check is the safety net.",
    "in_image is evidence only (whether the .ko exists in the image's module directory, or the object is listed in "
    "modules.builtin); built-in objects without a modules.builtin entry have in_image null.",
    "A directory without its own Makefile/Kbuild, objects referenced through sibling '../' paths from another directory's "
    "Makefile, and directory symlinks inside the kernel tree are only followed as kernel_config.py does; files reached "
    "only that way are usually unknown.",
    "Directory symlinks inside the module directory (updates -> /opt/...) are followed once: .ko files the scan saw "
    "under the target are listed under the link path; when a link that points (or should point) to a directory cannot be "
    "resolved or its target does not exist, the visible names are still listed in modules_present and modules_present_gaps says why: consumers must treat "
    "a non-empty modules_present_gaps as 'presence unknown'. Links to files are not gaps. Links inside the target are not "
    "followed: a target outside the module directory (or in another kernel version's) that contains links is a gap. "
    "Each real target is expanded once, at most 10,000 names. Path existence for link targets ignores docker whiteouts, "
    "and an image with more entries than the path index holds makes directory links gaps.",
    "A docker layer whose opaque whiteout for the kernel version directory comes after files at the same level is "
    "treated as deleting the whole version directory, so the stage is GAP (conservative, never a wrong result).",
    "Symlinked .ko files count under the link name; a link whose target is outside the module directory is counted as "
    "present (it cannot be checked). Hard-linked .ko files count under every name.",
    "C-kernel-config and C-kernel-module-map read the CNA mirror separately; with --kernel-config the two mirrors' "
    "zip_sha256 (from SOURCE) are compared and a difference, or a missing value on either side, makes this map GAP.",
    "NVIDIA out-of-tree modules are not mapped from Kbuild; .ko files with the same name elsewhere in the module "
    "directory (updates/, extra/) are listed in other_same_name and per CVE in shadowed_by. Whether a module is absent "
    "must be decided by normalized name over the whole module directory (modules_present), never by path alone.",
]


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + re.sub(r"[\t\r\n]+", " ", str(detail))[:900])


@functools.lru_cache(maxsize=None)
def kconf():
    """python3 -I 不把這個資料夾放進 sys.path：依路徑載入 kernel_config.py（同一份程式，不複製）。"""
    spec = importlib.util.spec_from_file_location("sca_center_kernel_config", HERE / "kernel_config.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def norm(name):
    return name.replace("-", "_")


def strip_ko(p):
    """模組清單的一行或 .ko 路徑 → 去掉 kernel/ 與副檔名的路徑（kernel/drivers/x/foo.ko.zst → drivers/x/foo）；不是 → None。"""
    kc = kconf()
    p = p.strip()
    for ext in kc.MODULE_EXT + (".o",):
        if p.endswith(ext):
            p = p[: -len(ext)]
            break
    else:
        return None
    return p[len("kernel/"):] if p.startswith("kernel/") else p


def strip_ko_keep(p):
    """.ko 路徑 → 去掉副檔名（保留 kernel/ 等前綴）。"""
    for ext in kconf().MODULE_EXT:
        if p.endswith(ext):
            return p[: -len(ext)]
    return p


def key_of(stem):
    """路徑（不含副檔名）→ (資料夾, 正規化的檔名)。"""
    return posixpath.dirname(stem), norm(posixpath.basename(stem))


class ModList:
    """modules.order 或 modules.builtin：{(資料夾, 名稱): 原文}、{名稱: [原文]}。"""

    def __init__(self, data):
        self.by_key, self.by_name, self.raw = {}, {}, data
        for l in data.decode("utf-8", "replace").splitlines():
            s = strip_ko(l)
            if not s:
                continue
            k = key_of(s)
            self.by_key.setdefault(k, l.strip())
            self.by_name.setdefault(k[1], []).append(l.strip())

    def names(self):
        return sorted(self.by_name)

    def sha256(self):
        return hashlib.sha256(self.raw).hexdigest()


def is_m(model, conds):
    """條件裡有沒有 =m：obj-m（const "m"）或 $(CONFIG_X) 的值是 m。$(subst m,y,$(CONFIG_X)) 與 $(CONFIG_X:m=y)
    把 m 換成 y（編進核心），不算。"""
    return any((a.kind == "const" and a.value == "m") or
               (a.kind == "sym" and not getattr(a, "my", False) and model.config.get(a.value) == "m") for a in conds)


def full_norm(stem):
    """整條路徑的 - 換成 _（kernel_config.shipped_modules 的寫法）。"""
    return stem.replace("-", "_")


class Mapper:
    def __init__(self, model, mods, order, builtin):
        self.kc = kconf()
        self.model, self.mods, self.order, self.builtin = model, mods, order, builtin
        self.memo_o, self.memo_d, self.memo_a, self.memo_cap = {}, {}, {}, {}
        self.ko_by_name = {}           # 正規化的模組名稱 → [模組目錄裡的 .ko 路徑（原文，含 updates/、extra/）]
        for k in sorted(mods or ()):
            st = strip_ko(k)
            if st:
                self.ko_by_name.setdefault(norm(posixpath.basename(st)), []).append(k)
        self.ko_keys = {key_of(s) for s in (strip_ko(k) for k in mods or ()) if s}
        self.extra_objs = getattr(model, "extra_objs", set())
        self.composites = {posixpath.join(md, base + ".o") for refs in model.obj_refs.values() for md, base, _ in refs
                           if base not in self.kc.LIST_BASES}
        mm = self.kc.major_minor(getattr(model, "kver_hdr", None))
        self.inc_ok = mm in self.kc.included_c_versions()
        self.mm = mm

    # ---- Kbuild：資料夾以什麼方式進入、物件連結到哪裡 ----
    def ref_value(self, md, base, conds):
        """同 kernel_config.Model.obj_built 對一條規則的算法 → (Res, 組合物件的 .o 或 None)。"""
        m, kc = self.model, self.kc
        cs = [m.atom(a) for a in conds]
        if base in kc.LIST_BASES:
            gate, frag = m.ref_gate(md)
            return (gate if frag else kc.r_and(cs + [gate])), None
        xo = posixpath.join(md, base + ".o")
        gate, frag = m.ref_gate(md)
        if not frag:
            gate = m.obj_built(xo) if xo in m.obj_refs else kc.Res(None, why=[f"{base}-y lists it but no rule names {base}.o"])
        return (gate if frag else kc.r_and(cs + [gate])), xo

    def dir_modes(self, d):
        """資料夾 → {"y"（連進 vmlinux 的路徑）、"m"（只為模組進入：obj-m／=m 的資料夾或 subdir-）、"?"（不確定的路徑）}。"""
        if d == "":
            return {"y"}
        if d in self.memo_d:
            return self.memo_d[d] or {"?"}
        self.memo_d[d] = None
        out = set()
        m, kc = self.model, self.kc
        for pd, base, conds in m.dir_refs.get(d, []):
            g, frag = m.ref_gate(pd)
            v = g if frag else kc.r_and([m.atom(a) for a in conds] + [g])
            if v.value is False:
                continue
            if v.value is None:
                out.add("?")
                continue
            mod = base == "subdir" or is_m(m, conds)
            for pm in self.dir_modes(pd):
                out.add("?" if pm == "?" else "m" if (mod or pm == "m") else "y")
        self.memo_d[d] = out or {"?"}
        return self.memo_d[d]

    def links(self, obj, depth=0):
        """物件 → [(kind, 最上層的物件, 原因)]：kind 是 builtin／module／unknown。結果記在 memo_o；組合物件超過 MAX_NEST 層 → unknown。"""
        if obj in self.memo_o:
            return self.memo_o[obj] if self.memo_o[obj] is not None else [("unknown", obj, "cycle in composite objects")]
        if depth == 0:
            self.memo_cap = {}            # 碰到層數上限的結果只在這一次呼叫裡有效（依深度記）
        elif (obj, depth) in self.memo_cap:
            return self.memo_cap[(obj, depth)]
        if depth > MAX_NEST:
            return [("unknown", obj, f"{NEST_WHY} {MAX_NEST} levels")]
        self.memo_o[obj] = None
        out = []
        for md, base, conds in self.model.obj_refs.get(obj, []):
            v, xo = self.ref_value(md, base, conds)
            if v.value is False:
                continue
            if v.value is None:
                out.append(("unknown", obj, v.why[0] if v.why else "undetermined rule"))
                continue
            if xo is None:
                if base != "lib" and is_m(self.model, conds):
                    out.append(("module", obj, f"{md or '(root)'}/Makefile: {base}-m"))
                    continue
                modes = self.dir_modes(md)
                if "y" in modes:
                    out.append(("builtin", obj, f"{md or '(root)'}/Makefile: {base}-y"))
                elif "?" in modes:
                    out.append(("unknown", obj, f"{md}/ may be entered only for modules ({base}-y object)"))
                else:
                    out.append(("unknown", obj, f"{md}/ is entered only for modules (obj-m or subdir-): its {base}-y objects "
                                                "are not linked into vmlinux"))
            else:
                mem_m = is_m(self.model, conds)
                for kind, top, why in self.links(xo, depth + 1):
                    if kind == "builtin" and mem_m:
                        out.append(("unknown", top, f"{base}-m member of the built-in composite {xo}"))
                    else:
                        out.append((kind, top, why))
        seen, ded = set(), []
        for x in out:
            if x[:2] not in seen:
                seen.add(x[:2])
                ded.append(x)
        if any(why.startswith(NEST_WHY) for _, _, why in ded):
            del self.memo_o[obj]          # 層數上限是相對這次呼叫的深度：不跨呼叫記，從較淺的地方呼叫時重算
            self.memo_cap[(obj, depth)] = ded
        else:
            self.memo_o[obj] = ded
        return ded

    # ---- 模組目錄 ----
    def ko_present(self, stem):
        """路徑（去掉副檔名、可帶 kernel/）的 .ko 在不在模組目錄。"""
        if self.mods is None:
            return None
        return key_of(stem[len("kernel/"):] if stem.startswith("kernel/") else stem) in self.ko_keys

    def other_same_name(self, name, own_stem):
        """模組目錄裡同名、但不在 own_stem（modules.order 的路徑，或樹內的物件路徑）的 .ko（原文路徑）。
        只正規化檔名：資料夾名稱裡的 - 不換（drivers/media/v4l2-core/videodev 不能被當成別的位置）。"""
        own = key_of(own_stem[len("kernel/"):] if own_stem.startswith("kernel/") else own_stem) if own_stem else None
        return sorted(p for p in self.ko_by_name.get(name, ()) if key_of(strip_ko(p)) != own)

    def ancestors(self, obj):
        """物件本身與把它列為成員的組合物件（每一層，最多 MAX_NEST 層；links 超過時是 unknown）。記在 memo_a。"""
        if obj in self.memo_a:
            return self.memo_a[obj]
        out, seen, todo = [obj], {obj}, [(obj, 0)]
        while todo:
            o, d = todo.pop(0)
            if d >= MAX_NEST:
                continue
            for md, base, _ in self.model.obj_refs.get(o, []):
                x = posixpath.join(md, base + ".o")
                if base not in self.kc.LIST_BASES and x not in seen:
                    seen.add(x)
                    out.append(x)
                    todo.append((x, d + 1))
        self.memo_a[obj] = out
        return out

    def composite_doubt(self, xo):
        """有編的組合物件 xo 和映像的模組清單一致 → None；不一致或核對不了 → 原因。
        =m：modules.order 在同一個路徑有它，modules.builtin 沒有同名的；=y：modules.order 沒有它。modules.builtin 只列帶模組資訊
        （MODULE_*）的 built-in 物件，bool 的組合物件（thermal_sys.o、acpi.o）不在裡面是正常的，所以 =y 不要求它在 modules.builtin。
        沒有擷取到的清單不核對。"""
        ls = self.links(xo)
        bt = {top for k, top, _ in ls if k == "builtin"}
        ls = [t for t in ls if not (t[0] == "module" and t[1] in bt)]
        if not ls:
            return f"no linking rule for {xo}"
        for kind, top, why in ls:
            k = key_of(top[:-2])
            if kind == "unknown":
                return f"{top}: {why}"
            if kind == "module":
                if self.builtin is not None and k[1] in self.builtin.by_name:
                    return f"{top} is built as a module (=m) but modules.builtin lists {self.builtin.by_name[k[1]][0]}"
                if self.order is not None and k not in self.order.by_key:
                    return f"{top} is built as a module (=m) but modules.order does not list it at that path"
            else:
                if self.order is not None and k in self.order.by_key:
                    return f"{top} is built into vmlinux (=y) but modules.order lists {self.order.by_key[k]}"
        return None

    def module_entry(self, top):
        """Kbuild 說 top（drivers/x/foo.o）是模組 → (link dict, 對不上的原因或 None)。"""
        stem = top[:-2]
        kname = posixpath.basename(stem)
        e = {"kind": "module", "object": top, "module": norm(kname), "module_kbuild": kname, "module_path": None,
             "in_image": None, "cross_check": "unavailable"}
        k = key_of(stem)
        if self.order is None:
            e["in_image"] = self.ko_present(stem)
            return e, None
        bl = self.builtin.by_name.get(k[1], []) if self.builtin is not None else []
        if bl:                    # 模組名稱是單一的命名空間：同名的 builtin 模組與 .ko 不能並存
            return e, f"{DISAGREE}: Kbuild builds {top} as module {kname} (=m) but modules.builtin lists {', '.join(bl[:2])}"
        same = self.order.by_name.get(k[1], [])
        if k in self.order.by_key and len(same) == 1:
            ent = self.order.by_key[k]
            e.update(module_path=ent, cross_check="ok", in_image=self.ko_present(strip_ko(ent)))
            return e, None
        if same:
            return e, (f"{DISAGREE}: Kbuild builds module {kname} at {stem}.ko but modules.order has "
                       f"{', '.join(same[:2])}" + (" (more than one module of that name)" if len(same) > 1 else ""))
        return e, f"{DISAGREE}: Kbuild builds {top} as module {kname} (=m) but modules.order does not list it"

    def builtin_entry(self, top):
        stem = top[:-2]
        kname = posixpath.basename(stem)
        k = key_of(stem)
        e = {"kind": "builtin", "object": top, "module": None, "module_kbuild": None, "module_path": None, "in_image": None,
             "cross_check": "unavailable" if self.order is None else "ok"}
        if self.order is not None and k in self.order.by_key:
            return e, f"{DISAGREE}: Kbuild links {top} into vmlinux (=y) but modules.order lists {self.order.by_key[k]}"
        if self.builtin is not None and k in self.builtin.by_key:
            e.update(module=norm(kname), module_kbuild=kname, module_path=self.builtin.by_key[k], in_image=True)
        return e, None

    # ---- 一個檔案 ----
    def map_file(self, path):
        """programFile → 那一筆。Kbuild 判斷不了、但這個物件本身列在 modules.builtin → builtin（保守的方向）。
        只看物件本身：組合物件列在 modules.builtin 不代表每個成員都在裡面（built-in 組合物件不含 foo-m 的成員）。"""
        rec = self._map_file(path)
        if rec["build"] == "unknown" and rec["object"] and self.builtin is not None and not rec["reason"].startswith(DISAGREE):
            o = rec["object"]
            ent = self.builtin.by_key.get(key_of(o[:-2]))
            if ent:
                kname = posixpath.basename(o[:-2])
                rec.update(build="builtin", module=norm(kname), module_kbuild=kname, module_path=ent, in_image=True,
                           reason=f"listed in modules.builtin ({ent}); Kbuild alone: {rec['reason']}")
        return rec

    def _map_file(self, path):
        kc = self.kc
        rec = {"path": path, "build": "unknown", "object": None, "module": None, "module_kbuild": None, "module_path": None,
               "in_image": None, "reason": None, "configs": [], "links": [], "other_same_name": []}
        kind, x = kc.classify_file(path)
        if kind != "object":
            rec["reason"] = x
            return rec
        rec["object"] = x
        r = self.model.obj_built(x)
        rec["configs"] = sorted(s for s in r.syms if s.startswith("CONFIG_"))
        if r.value is None:
            rec["reason"] = r.why[0] if r.why else "undetermined"
            return rec
        if r.value is False:
            return self.not_built(rec, r)
        if x in self.composites:
            rec["reason"] = f"{x} is a composite object (its members are listed in <name>-y/-objs); {path} is not compiled by that rule"
            return rec
        ls = self.links(x)
        # 同一個物件同時在 obj-y 與 obj-m：Kbuild 只把它編進核心（scripts/Makefile.lib：obj-m := $(filter-out $(obj-y),$(obj-m))；
        # 例：libahci.o 由 =y 的 SATA_AHCI 與 =m 的 AHCI_DWC 共用）
        bt = {top for k, top, _ in ls if k == "builtin"}
        ls = [t for t in ls if not (t[0] == "module" and t[1] in bt)]
        if not ls:
            rec["reason"] = f"kernel_config says built, but no linking rule for {x} was found"
            return rec
        ents, bad = [], []
        for k, top, why in ls:
            if k == "builtin":
                e, err = self.builtin_entry(top)
            elif k == "module":
                e, err = self.module_entry(top)
            else:
                e, err = {"kind": "unknown", "object": top, "reason": why}, None
            e["rule"] = why
            ents.append(e)
            if err:
                bad.append(err)
        rec["links"] = ents
        kinds = {e["kind"] for e in ents}
        if bad:                              # Kbuild 與模組清單對不上：不挑一邊
            rec["reason"] = bad[0]
            return rec
        if "builtin" in kinds:
            b = [e for e in ents if e["kind"] == "builtin"]
            if len(ents) == 1:
                rec.update({k: b[0][k] for k in ("module", "module_kbuild", "module_path", "in_image")})
            rec["build"] = "builtin"
            rec["reason"] = f"linked into vmlinux ({b[0]['rule']})" + (f"; {len(ents) - 1} other path(s)" if len(ents) > 1 else "")
            return rec
        if "unknown" in kinds:
            rec["reason"] = next(e["reason"] for e in ents if e["kind"] == "unknown")
            return rec
        # 全部是模組：名稱要通過 modules.order 的核對（K2 只承認 modules_order 裡的名稱），
        # 而且「不在 vmlinux 裡」的證明要和 kernel_config 判「沒編」的標準相同
        if any(e["cross_check"] != "ok" for e in ents):
            rec["reason"] = (f"Kbuild builds it as module(s) {', '.join(sorted({e['module'] for e in ents}))}, but there is no "
                             "modules.order to cross-check the name")
            return rec
        why = self.not_in_vmlinux_doubt(x, [e["object"] for e in ents])
        if why:
            rec["reason"] = why
            return rec
        rec["build"] = "module"
        if len(ents) == 1:
            rec.update({k: ents[0][k] for k in ("module", "module_kbuild", "module_path", "in_image")})
        for e in ents:
            e["shadowed_by"] = self.other_same_name(e["module"], strip_ko(e["module_path"]))
        rec["other_same_name"] = sorted({p for e in ents for p in e["shadowed_by"]})
        rec["reason"] = f"only in module(s) {', '.join(sorted({e['module'] for e in ents}))} (listed in modules.order)"
        return rec

    def not_in_vmlinux_doubt(self, obj, tops):
        """模組的結論要排除的不確定：看不懂的 Makefile、別的資料夾的規則直接編、沒有 #include 清單 → 原因；沒有 → None。"""
        m = self.model
        if not self.inc_ok:
            return (f"no list of #included .c files for kernel {self.mm or 'of unknown version'}: the file may also be compiled "
                    "into vmlinux through #include")
        chain = self.ancestors(obj) + [t for t in tops if t not in self.ancestors(obj)]
        for o in chain:                      # 每一層組合物件所在的 Makefile 都要看得懂
            why = m.uncertain_chain(posixpath.dirname(o), m.obj_refs.get(o, []))
            if why:
                return f"{why} (another rule may build it into vmlinux)"
        ex = [o for o in chain if o in self.extra_objs]
        if ex:
            return (f"{ex[0]} is also listed in extra-/always- (built as a separate target outside the obj- lists; "
                    "another rule may link it into vmlinux)")
        other = m.compiled_elsewhere(obj)
        if other:
            return f"{other}/Makefile has a rule that compiles {obj[:-2]}.* (may be built into vmlinux from there)"
        return None

    def not_built(self, rec, r):
        """kernel_config 判 False → not_built，但 judge_cve 的 not_affected 前提（#include 清單、模組目錄、同名模組）也要成立。"""
        if not self.inc_ok:
            rec["reason"] = (f"no list of #included .c files for kernel {self.mm or 'of unknown version'}: a file not built by its "
                             "own rule may still be compiled through #include")
            return rec
        if self.mods is None:
            rec["reason"] = "not built in-tree, but there is no module directory to check for out-of-tree copies"
            return rec
        # 物件本身，或 Kbuild 也判沒編的組合物件（任何一層），列在模組清單裡：對不上（同 kernel_config.listed_contradiction）
        for o in self.ancestors(rec["object"]):
            if o != rec["object"] and self.model.obj_built(o).value is True:
                # 組合物件有編、只是這個成員依 config 沒放進去：組合物件本身要和清單一致，才能說這個成員沒編進去
                why = self.composite_doubt(o)
                if why:
                    rec["reason"] = f"{DISAGREE}: configured-out member of the composite {o}, which does not match the module lists ({why})"
                    return rec
                continue
            if o != rec["object"] and self.model.obj_built(o).value is not False:
                continue
            k = key_of(o[:-2])
            for n, ml in (("modules.order", self.order), ("modules.builtin", self.builtin)):
                if ml is not None and k in ml.by_key:
                    rec["reason"] = f"{DISAGREE}: Kbuild does not build {o} but {n} lists {ml.by_key[k]}"
                    return rec
        dup = self.kc.same_name_modules(self.model, [rec["path"]], self.mods)
        if dup:
            ds = set(dup)
            rec["other_same_name"] = sorted(p for ps in self.ko_by_name.values() for p in ps if full_norm(strip_ko_keep(p)) in ds)
            rec["reason"] = f"not built in-tree, but the module directory has a module with the same name ({', '.join(dup[:3])})"
            return rec
        rec["build"] = "not_built"
        ss = rec["configs"]
        rec["reason"] = ("not built: " + (", ".join(f"{s}={self.model.config.get(s) or 'unset'}" for s in ss) if ss else
                                         "; ".join(r.why[:1]) or "no rule builds it"))
        return rec


def map_cve(mapper, files):
    """一個 CVE 的 programFiles → 那一筆（不含 cve 鍵）。"""
    fl = [mapper.map_file(f) for f in files]
    builds = [f["build"] for f in fl]
    mods = sorted({e["module"] for f in fl if f["build"] == "module" for e in f["links"]})
    kmods = sorted({e["module_kbuild"] for f in fl if f["build"] == "module" for e in f["links"]})
    if "builtin" in builds:
        b, f0 = True, next(f for f in fl if f["build"] == "builtin")
        reason = f"{f0['path']} is built into the kernel ({f0['reason']})"
    elif fl and "module" in builds and all(x in ("module", "not_built") for x in builds):
        b = False
        reason = (f"the compiled program files are only in module(s) {', '.join(mods)}" +
                  (f"; {builds.count('not_built')} file(s) not built" if "not_built" in builds else ""))
    else:
        b = None
        if fl and all(x == "not_built" for x in builds):
            reason = ALL_NOT_BUILT
        else:
            u = [f for f in fl if f["build"] == "unknown"]
            reason = "; ".join(f"{f['path']}: {f['reason']}" for f in u[:3]) + ("; …" if len(u) > 3 else "")
    hints = []
    objs = [f for f in fl if f["object"]]
    others = [f for f in fl if not f["object"]]
    if objs and others and all(f["build"] == "not_built" for f in objs) and all(f["path"].endswith(".h") for f in others):
        hints.append("header_only_with_unbuilt_c")
    shadow = {n: [] for n in mods}
    for f in fl:
        if f["build"] == "module":
            for e in f["links"]:
                shadow[e["module"]] = sorted(set(shadow[e["module"]]) | set(e.get("shadowed_by", [])))
    return {"builtin": b, "all_in_modules": bool(fl) and all(x == "module" for x in builds), "modules": mods,
            "modules_kbuild": kmods, "shadowed_by": shadow, "reason": reason, "hints": hints, "files": fl}


def assess(a, max_age):
    """→ (狀態, 說明, 輸出 dict 或 None)。"""
    kc = kconf()
    kmap = kc.load_json(a.kernel_map, "核心對應摘要")
    cves, comp, srcn = kc.kernel_cves(kc.load_json(a.grype, "Grype JSON"), kc.load_json(a.findings, "DT findings"), a.cves, kmap)
    if not cves:
        return "NOT_RUN", "沒有核心元件上的 CVE（不是含核心的映像，或核心沒有比對）", None
    want = a.kernel_version or ((kmap or {}).get("map_entry") or {}).get("modules_kernel_version") or None
    out = {"schema": SCHEMA, "status": None, "detail": None, "method": METHOD, "method_detail": METHOD_DETAIL,
           "kernel": {"version": want, "config_source": None, "config_sha256": None, "makefiles": 0, "source": None},
           "component": comp,
           "sources": {"kernel_version": want, "config": None, "config_sha256": None, "modules_dir": None,
                       "modules_order": None, "modules_builtin": None, "modules_order_sha256": None,
                       "modules_builtin_sha256": None, "cna_mirror": None},
           "modules_order": None, "modules_builtin": None, "modules_present": None, "modules_present_gaps": [],
           "inputs": {"kernel_cves": len(cves), "from_grype_matches": srcn["grype"], "from_dt_findings": srcn["dt"], "from_list": srcn["list"]},
           "counts": {"cves": 0, "files": {k: 0 for k in BUILDS}, "builtin": {"true": 0, "false": 0, "null": 0}, "all_in_modules": 0},
           "cves": {}, "limitations": list(LIMITATIONS)}
    if getattr(a, "cves_origin", None):
        out["inputs"]["cves_origin"] = a.cves_origin
    info, gap, label = kc.build_info(a, want, images=True)        # 燒錄的核心：和 C-kernel-config 同一個判斷（kc.settle_config）
    if label:
        out["kernel"]["source"] = label
    mir = kc.Mirror(a.mirror, max_age)
    out["sources"]["cna_mirror"] = {k: mir.state.get(k) for k in ("path", "source", "commit", "commit_date", "fetched_utc", "age_days",
                                                                    "max_age_days", "zip_sha256", "ok", "reason")}
    # C-kernel-config 另外讀同一個鏡像：兩邊的 commit 都記下來，不同時（兩次讀之間鏡像換了）→ GAP
    k1 = kc.load_json(a.kernel_config, "kernel-config.json") if getattr(a, "kernel_config", None) else None
    k1cna = None
    if isinstance(k1, dict):
        cd = k1.get("cve_data") if isinstance(k1.get("cve_data"), dict) else {}
        mm_ = re.match(r"^([0-9a-f]{40})\b", str(cd.get("commit_or_date") or ""))
        k1cna = {"commit": mm_.group(1) if mm_ else None, "commit_or_date": cd.get("commit_or_date"), "fetched_utc": cd.get("fetched_utc"),
                 "zip_sha256": cd.get("zip_sha256")}
    out["sources"]["kernel_config_cna_mirror"] = k1cna
    if gap:
        return "GAP", f"{len(cves)} 個核心 CVE 沒有對應到模組：{gap}", out
    chk, ksha = kc.settle_config(info)
    if getattr(a, "cves_origin", None) and not out["component"] and (info.kernel_version or want):
        out["component"] = kc.vendor_kernel_component(info.kernel_version or want)
    nmk = sum(1 for k in info.files if k and k[-1] in ("Makefile", "Kbuild"))
    out["kernel"].update({"version": info.kernel_version or want, "config_source": info.config_path, "config_sha256": ksha,
                          "makefiles": nmk, "source": info.source.get("label")})
    if info.source_tree:
        out["kernel"]["makefiles_from"] = "source-tree"
        out["kernel"]["source_tree"] = info.source_tree
    out["sources"].update({"kernel_version": info.kernel_version or want, "config": info.config_path, "config_sha256": ksha})
    if chk:
        r = chk["record"]
        out["sources"]["config_check"] = {"result": r["result"], "config_source": info.config_path, "config_sha256": ksha,
                                          "headers_config_sha256": r["headers_config"]["sha256"],
                                          "image_config_sha256": r["image_config_sha256"],
                                          "ikconfig_complete": r["image"]["ikconfig_complete"],
                                          "differences_total": r.get("differences_total")}
        if chk["gap"]:
            return "GAP", f"{len(cves)} 個核心 CVE 沒有對應到模組：{chk['gap']}", out
        if chk["use"] is not None and not r["image"]["ikconfig_complete"]:
            return "GAP", (f"{len(cves)} 個核心 CVE 沒有對應到模組：headers .config 和燒錄的核心不同，而燒錄核心的 IKCONFIG 不完整"
                           f"（{r['image']['reason']}），沒有可用的設定"), out
    k1sha = ((k1 or {}).get("kernel") or {}).get("config_sha256") if isinstance(k1, dict) else None
    if k1sha and k1sha != ksha:
        return "GAP", (f"{len(cves)} 個核心 CVE 沒有對應到模組：C-kernel-config 用的設定（sha256 {str(k1sha)[:12]}…）和這次的"
                       f"（{info.config_path}，sha256 {ksha[:12]}…）不同，兩份結果不能並用"), out
    if nmk < 50:
        if info.source_tree:
            return "GAP", f"{len(cves)} 個核心 CVE 沒有對應到模組：--source-tree 只有 {nmk} 個 Makefile／Kbuild（不像核心原始碼樹）", out
        return "GAP", (f"{len(cves)} 個核心 CVE 沒有對應到模組：{info.config_path} 旁邊只有 {nmk} 個 Makefile／Kbuild（headers 不完整）"), out
    model = kc.Model(info)
    kv = info.kernel_version
    out["kernel"]["config_header"] = {"arch": model.srcarch, "version": model.kver_hdr}
    tgap = kc.source_tree_gap(info, model)
    if tgap:
        return "GAP", f"{len(cves)} 個核心 CVE 沒有對應到模組：{tgap}", out
    mm = kc.major_minor(model.kver_hdr)
    out["kernel"]["included_c_list"] = mm if mm in kc.included_c_versions() else None
    if out["kernel"]["included_c_list"] is None:
        out["limitations"].append(f"No list of #included .c files for kernel {mm or '(unknown version)'}: no file was mapped "
                                  "to module or not_built.")
    if kv and model.kver_hdr and not (kv == model.kver_hdr or kv.startswith(model.kver_hdr + "-") or kv.startswith(model.kver_hdr + "+")):
        return "GAP", f"{len(cves)} 個核心 CVE 沒有對應到模組：.config 是核心 {model.kver_hdr} 的，模組目錄是 {kv}（不是同一個核心）", out
    if not mir.state["ok"]:
        return "GAP", f"{len(cves)} 個核心 CVE 沒有對應到模組：{mir.state['reason']}", out
    if k1cna is not None:
        # 以鏡像的 zip_sha256（SOURCE 記的、kernel_config 讀時核對過的）比對：任何一邊沒有 → 無法證明是同一份 → GAP
        a1, a2 = k1cna.get("zip_sha256"), mir.state.get("zip_sha256")
        if not a1 or not a2 or a1 != a2:
            return "GAP", (f"{len(cves)} 個核心 CVE 沒有對應到模組：C-kernel-config 用的 CNA 鏡像（zip_sha256 {a1 or '沒有記錄'}，"
                           f"commit {k1cna['commit'] or '沒有'}）和這次讀到的（zip_sha256 {a2 or '沒有記錄'}，commit "
                           f"{mir.state.get('commit') or '沒有'}）不能證明是同一份，兩份結果不能並用"), out
    # 模組目錄
    mods = info.modules.get("ko") if info.modules else None
    mfiles = (info.modules or {}).get("files") or {}
    order = ModList(mfiles["modules.order"]) if "modules.order" in mfiles else None
    builtin = ModList(mfiles["modules.builtin"]) if "modules.builtin" in mfiles else None
    if info.modules and kv:
        out["sources"]["modules_dir"] = f"/usr/lib/modules/{kv}/"
        out["kernel"]["modules"] = len(mods or ())
    for n, ml in (("modules_order", order), ("modules_builtin", builtin)):
        if ml is not None:
            out["sources"][n] = {"path": f"/usr/lib/modules/{kv}/{n.replace('_', '.')}", "sha256": ml.sha256(), "entries": len(ml.by_key)}
            out["sources"][n + "_sha256"] = ml.sha256()
            out[n] = ml.names()          # modprobe 形式的名稱（去掉路徑與 .ko，- 換成 _），排序
    missing = []
    if mods is None:
        missing.append("沒有模組目錄（in_image 一律 null，模組名稱沒有核對，判成模組的檔案是 unknown）")
    else:
        missing += [f"模組目錄沒有 {n}（模組名稱沒有核對）" for n, ml in (("modules.order", order), ("modules.builtin", builtin)) if ml is None]
    mapper = Mapper(model, mods, order, builtin)
    gaps = list((info.modules or {}).get("present_gaps") or [])
    out["modules_present_gaps"] = gaps
    if mods is not None:
        out["modules_present"] = sorted(mapper.ko_by_name)    # 模組目錄裡看得到的每個 .ko 的名稱（含 updates/、extra/），modprobe 形式
    # 模組目錄裡指向資料夾的連結解不開或目標不存在：modules_present 照列看得到的名稱，原因在 modules_present_gaps；
    # 使用者看到 modules_present_gaps 不是空的，要當成「有沒有某個模組不知道」。null 只表示沒有模組目錄
    c = out["counts"]
    unk = {"no_cna_record": 0, "no_program_files": 0}
    for cve in cves:
        files = mir.record(cve)
        if not files:
            k = "no_cna_record" if files is None else "no_program_files"
            unk[k] += 1
            res = {"builtin": None, "all_in_modules": False, "modules": [], "modules_kbuild": [], "shadowed_by": {}, "hints": [], "files": [],
                   "reason": "no Linux kernel CNA record in the mirror" if files is None else "the CNA record lists no programFiles"}
        else:
            res = map_cve(mapper, files)
        out["cves"][cve.upper()] = res
        c["cves"] += 1
        for f in res["files"]:
            c["files"][f["build"]] += 1
        c["builtin"][{True: "true", False: "false", None: "null"}[res["builtin"]]] += 1
        c["all_in_modules"] += res["all_in_modules"]
    c["unmapped"] = unk
    fc = c["files"]
    detail = (f"核心 {kv or '?'}（{info.source.get('label')}；.config sha256 {ksha[:12]}…）的 {len(cves)} 個 CVE、{sum(fc.values())} 個檔案："
              f"builtin {fc['builtin']}、module {fc['module']}、not_built {fc['not_built']}、unknown {fc['unknown']}；"
              f"CVE 的 builtin true {c['builtin']['true']}／false {c['builtin']['false']}／null {c['builtin']['null']}，"
              f"all_in_modules {c['all_in_modules']}（沒有 CNA 紀錄 {unk['no_cna_record']}、沒有 programFiles {unk['no_program_files']}）；只對應，不判定")
    if getattr(a, "cves_origin", None):
        detail = f"CVE 清單來源：{a.cves_origin}（不是 Grype／DT）；{detail}"
    if info.source_tree:
        detail += (f"；Makefile／Kbuild 來自核心原始碼樹 {info.source_tree['path_label']}"
                   f"（.config 核對：{(info.source_tree.get('config_compare') or {}).get('result')}）")
    if missing:
        return "GAP", "；".join(missing) + "：" + detail, out
    return "OK", detail, out


def main(argv=None):
    kc = kconf()
    ap = argparse.ArgumentParser(description="核心 CVE 修補的檔案編進哪個模組或核心本體（C-kernel-module-map）")
    for o in ("--grype", "--findings", "--cves", "--kernel-map", "--kernel-version", "--prefix", "--config", "--makefiles-dir", "--mirror",
              "--kernel-config", "--source-tree", "--cves-origin"):
        ap.add_argument(o)
    ap.add_argument("--from", dest="from_")
    ap.add_argument("--prefer-rootfs-image", action="store_true")      # 同 kernel_config.py：板子跑 rootfs/boot/Image 時兩邊用同一份設定
    ap.add_argument("--max-age-days", type=float, default=None)
    ap.add_argument("--out", required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        line("FAIL", "kernel_module_map.py 參數錯誤")
        return 3
    if bool(a.config) != bool(a.makefiles_dir) or (a.config and a.from_) or not (a.config or a.from_):
        line("FAIL", "kernel_module_map.py 參數錯誤：要 --from，或同時給 --config 與 --makefiles-dir")
        return 3
    if a.prefix and not a.from_:
        line("FAIL", "kernel_module_map.py 參數錯誤：--prefix 只配 --from")
        return 3
    if a.source_tree and (a.config or not a.from_):
        line("FAIL", "kernel_module_map.py 參數錯誤：--source-tree 只配 --from")
        return 3
    try:
        os.remove(a.out)                 # 不留上一次的結果冒充這次的
    except FileNotFoundError:
        pass
    except OSError as e:
        line("FAIL", f"無法刪除舊的輸出（{type(e).__name__}）")
        return 3
    try:
        max_age = a.max_age_days if a.max_age_days is not None else float(os.environ.get("KERNEL_CVE_MAX_AGE_DAYS") or 7)
        st, detail, out = assess(a, max_age)
    except kc.InputError as e:
        line("FAIL", f"kernel_module_map.py 輸入錯誤：{e}")
        return 3
    except Exception as e:      # 結構意外：記 FAIL，不讓掃描中斷、不印 traceback
        line("FAIL", f"kernel_module_map.py 無法對應（{type(e).__name__}）")
        return 3
    if out is not None:
        out["status"], out["detail"] = st, detail
        try:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=1)
        except OSError as e:
            line("FAIL", f"無法寫入 {a.out}（{type(e).__name__}）")
            return 3
    line(st, detail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
