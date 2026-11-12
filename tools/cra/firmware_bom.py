#!/usr/bin/env python3
"""刷機包的韌體元件併進產品 SBOM，並對照 BSI TR-03183-2 v2.1.0 的欄位（計畫總表 #10，對應 II-1）。

來源（都是 tools/demo/scan-flash-package.sh 的結果資料夾最上層，cra_report.py 自動找；不是刷機包的掃描就不做）：
- flash-inventory.json（tools/demo/flash_package.py list）：
  - bootloader：路徑含 bootloader 資料夾的檔案 → 開機與燒錄韌體（.bin .efi .elf .img .fw .rom，以及 .bct .dtb .dtbo）；
  - outside_rootfs：kernel 資料夾的 Image 與 .dtb／.dtbo；
  - other_deliverables：壓縮檔旁邊的 MCU 韌體（.zip .bin .hex .fw .img .s19 .srec .dfu）；
  - kernel_modules：rootfs 的 lib/modules/<版本>/updates/ 下的 kernel 模組（NVIDIA 另外編的 OOT 模組等；版本取自 modinfo）。
- list.json：每個 rootfs 的 L4T 版本（etc/nv_tegra_release 與 dpkg 的 nvidia-l4t-core／kernel）→ 「NVIDIA Jetson Linux」邏輯元件。

規則：
- 只用清點時算好的雜湊（SHA-256；新版清點另有 SHA-512），不重讀刷機包。
- supplier（誰把刷機包交給我們）只來自設定 sbom.flash_package_supplier；沒有就不填（TR 覆蓋率會列出缺的元件）。
  元件建立者（TR 的 component creator，CycloneDX manufacturer）只有 L4T 版本元件寫 NVIDIA（來源是 NVIDIA 的版本檔）；
  個別檔案的建立者要與 NVIDIA 公開 BSP 比對後才能寫，這裡不猜。
- TR-03183-2 的 executable／archive／structured 只在表 7 有對應例子時填（韌體映像、kernel 模組、zip）；
  .dtb／.bct 等資料檔不填（不確定時寧可列為缺欄位）。
- 版本：模組用 modinfo 的 version；其他檔案沒有建立者給的版本，依 TR 5.2.2 用檔案修改時間（RFC 3339，UTC）。
- 輸出穩定：元件依路徑排序，bom-ref 由路徑決定；同一路徑出現兩次時用最後一筆（tar 解開時後面的覆蓋前面的）。

TR-03183-2 覆蓋率（tr03183）：逐欄位算有幾個元件符合（CycloneDX 1.6 對照表，TR 第 8.2 節），缺的列出元件名稱。
只回報（ATTENTION），不擋出貨。
"""
import fnmatch
import gzip
import json
import lzma
import os
import re
import struct
import sys
import time

TR_VERSION = "2.1.0"
NVIDIA = {"name": "NVIDIA Corporation", "url": ["https://www.nvidia.com"]}
FW_EXT = (".bin", ".efi", ".elf", ".img", ".fw", ".rom")
DATA_EXT = (".bct", ".dtb", ".dtbo")
MCU_EXT = (".zip", ".bin", ".hex", ".fw", ".img", ".s19", ".srec", ".dfu")
# 壓縮檔旁邊的交付檔：檔名符合 MCU 韌體樣式（mcu、fw、firmware 是獨立的詞）或設定 sbom.deliverable_firmware 的樣式才當元件；
# 其他的（原始碼包、工具包、SD 卡映像…）只列在 sbom.md 第 6 節
MCU_NAME = re.compile(r"(?:^|[^a-z0-9])(?:mcu|fw|firmware)(?:[^a-z]|$)")
SKIP_NAMES = ("system.img",)                # rootfs 的映像（rootfs 由 Syft 掃描），不當韌體
MOD_MAX = 64 << 20                          # 模組讀進記憶體（含解壓後）的上限
LZMA_MEMLIMIT = 256 << 20                   # .ko.xz 解壓器的記憶體上限（字典過大的檔案記原因，不讓清點整個失敗）
MODINFO_KEYS = ("name", "version", "srcversion", "vermagic", "license", "author", "description")
VAL_MAX = 300
REF = "sca-center:flash:"
P_LOGICAL = "sca-center:logical-component"
BSI_FLAGS = {"bsi:component:executable": ("executable", "non-executable"), "bsi:component:archive": ("archive", "no archive"),
             "bsi:component:structured": ("structured", "unstructured")}
# TR-03183-2 表 7 的例子 → (executable, archive, structured)
FIRMWARE_IMAGE = ("executable", "no archive", "unstructured")
ARCHIVE_ZIP = ("non-executable", "archive", "structured")


# ---------- kernel 模組的 modinfo（ELF 的 .modinfo 區段；輸入是不可信資料，只做有界的解析） ----------

def elf_section(data, want=b".modinfo"):
    """ELF 檔案內容 → 指定區段的內容；不是 ELF、格式不對或沒有這個區段 → (None, 原因)。"""
    if data[:4] != b"\x7fELF":
        return None, "not an ELF file"
    cls, enc = data[4:5], data[5:6]
    e = {b"\x01": "<", b"\x02": ">"}.get(enc)
    if e is None or cls not in (b"\x01", b"\x02"):
        return None, "unknown ELF class or byte order"
    try:
        if cls == b"\x02":
            shoff, = struct.unpack_from(e + "Q", data, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x3A)
            fmt, need = e + "IIQQQQ", 40
        else:
            shoff, = struct.unpack_from(e + "I", data, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", data, 0x2E)
            fmt, need = e + "IIIIII", 24
        if shentsize < need or shnum == 0 or shstrndx >= shnum or shoff + shnum * shentsize > len(data):
            return None, "bad ELF section header table"
        secs = []
        for i in range(shnum):
            v = struct.unpack_from(fmt, data, shoff + i * shentsize)
            secs.append((v[0], v[4], v[5]))           # sh_name, sh_offset, sh_size
        _, so, ss = secs[shstrndx]
        if so + ss > len(data):
            return None, "bad ELF string table"
        strtab = data[so:so + ss]
        for name, off, size in secs:
            end = strtab.find(b"\0", name)
            if name < len(strtab) and strtab[name:end if end >= 0 else None] == want:
                if off + size > len(data):
                    return None, f"{want.decode()} section outside the file"
                return data[off:off + size], None
    except struct.error:
        return None, "truncated ELF file"
    return None, f"no {want.decode()} section"


def parse_modinfo(sec):
    """.modinfo 區段（key=value\\0…）→ 只留 MODINFO_KEYS；同一個 key 多筆時（author）用「; 」接起來。"""
    out = {}
    for item in sec.split(b"\0"):
        k, sep, v = item.partition(b"=")
        k = k.decode("ascii", "replace")
        if not sep or k not in MODINFO_KEYS:
            continue
        v = v.decode("utf-8", "replace").strip()[:VAL_MAX]
        if v:
            out[k] = f"{out[k]}; {v}"[:VAL_MAX] if k in out and k == "author" else out.get(k, v)
    return out


def module_bytes(raw, name):
    """模組檔案內容 → (ELF 內容, 原因)。.ko.xz／.ko.gz 解壓（有上限）；.ko.zst 標準庫不能解壓 → None。"""
    try:
        if name.endswith(".xz"):
            d = lzma.LZMADecompressor(memlimit=LZMA_MEMLIMIT)
            data = d.decompress(raw, max_length=MOD_MAX)
            if d.eof:
                return data, None
            return None, ("decompressed module larger than the limit" if len(data) >= MOD_MAX else "cannot decompress (truncated)")
        if name.endswith(".gz"):
            d = gzip.zlib.decompressobj(16 + gzip.zlib.MAX_WBITS)
            data = d.decompress(raw, MOD_MAX)
            if d.eof:
                return data, None
            return None, ("decompressed module larger than the limit" if d.unconsumed_tail else "cannot decompress (truncated)")
    except (lzma.LZMAError, OSError, EOFError, gzip.zlib.error, MemoryError) as e:
        return None, f"cannot decompress ({type(e).__name__})"
    if name.endswith(".zst"):
        return None, "zstd-compressed module (not readable with the Python standard library)"
    return raw, None


def module_info(raw, name):
    """模組檔案內容 → {"modinfo": {...}} 或 {"modinfo": None, "modinfo_note": 原因}。"""
    data, why = module_bytes(raw, name)
    if data is not None:
        sec, why = elf_section(data)
        if sec is not None:
            return {"modinfo": parse_modinfo(sec)}
    return {"modinfo": None, "modinfo_note": why}


def is_module_path(rel):
    """rootfs 內的相對路徑是不是 lib/modules/<版本>/updates/ 底下的 kernel 模組（含 usr/lib；.ko、.ko.xz、.ko.gz、.ko.zst）。"""
    p = rel.split("/")
    if p[:1] == ["usr"]:
        p = p[1:]
    return (len(p) >= 5 and p[0] == "lib" and p[1] == "modules" and p[3] == "updates"
            and p[-1].endswith((".ko", ".ko.xz", ".ko.gz", ".ko.zst")))


# ---------- 元件 ----------

def rfc3339(mtime):
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(mtime))) if mtime and int(mtime) > 0 else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def entity(x):
    """設定的 {name, url, email} → CycloneDX organizationalEntity；沒有名稱 → None。"""
    if not isinstance(x, dict) or not str(x.get("name") or "").strip():
        return None
    o = {"name": str(x["name"]).strip()}
    if x.get("url"):
        o["url"] = [str(x["url"])]
    if x.get("email") and "@" in str(x["email"]):
        o["contact"] = [{"name": o["name"], "email": str(x["email"])}]
    return o


def prop(name, value):
    return {"name": name, "value": str(value)}


def hashes_of(item):
    h = []
    for k, alg in (("sha256", "SHA-256"), ("sha512", "SHA-512")):
        v = item.get(k)
        if isinstance(v, str) and len(v) in (64, 128) and all(c in "0123456789abcdef" for c in v):
            h.append({"alg": alg, "content": v})
    return h


def file_component(item, ctype, flags, source, supplier, l4t, extra_props=()):
    path = item["path"]
    fname = path.rsplit("/", 1)[-1]
    c = {"type": ctype, "bom-ref": REF + path, "name": fname}
    ver = rfc3339(item.get("mtime"))
    if ver:
        c["version"] = ver
    if supplier:
        c["supplier"] = supplier
    h = hashes_of(item)
    if h:
        c["hashes"] = h
    props = [prop("bsi:component:filename", fname)]
    if flags:
        props += [prop(k, v) for k, v in zip(BSI_FLAGS, flags)]
    props += [prop("sca-center:source", source), prop("sca-center:flash-package-path", path)]
    if ver:
        props.append(prop("sca-center:version-basis", "file modification time (BSI TR-03183-2 5.2.2: no version assigned by the creator)"))
    if l4t:
        props.append(prop("sca-center:l4t-release", l4t))
    props += list(extra_props)
    c["properties"] = props
    return c


def _s(v):
    """不可信的值 → 去掉前後空白、截到 VAL_MAX 的字串；不是字串或空字串 → None（不把數字、清單寫進 SBOM）。"""
    if isinstance(v, str):
        v = v.strip()[:VAL_MAX]
        return v or None
    return None


def _d(v):
    return v if isinstance(v, dict) else {}


def _dicts(v):
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _link_kind(x):
    return "hard link (content recorded under another path)" if x.get("type") == "hardlink" else "symbolic link or other non-file entry"


def last_by_path(items):
    """同一路徑多筆 → 最後一筆；回傳 (依路徑排序的清單, 重複的筆數)。"""
    seen = {}
    for x in items:
        if isinstance(x, dict) and isinstance(x.get("path"), str) and x["path"]:
            seen[x["path"]] = x
    n = sum(1 for x in items if isinstance(x, dict) and isinstance(x.get("path"), str) and x["path"]) - len(seen)
    return [seen[k] for k in sorted(seen)], n


def pick_rootfs(listdoc, variant, prefix=None):
    """list.json 的 rootfs 清單 → 這個 rootfs 的那一筆（prefix 優先；否則名稱唯一時）；找不到或不唯一 → (None, 原因)。"""
    rs = _dicts(_d(listdoc).get("rootfs"))
    if prefix:
        m = [r for r in rs if r.get("prefix") == prefix]
    else:
        m = [r for r in rs if r.get("variant") == variant]
    if len(m) == 1:
        return m[0], None
    return None, (f"list.json has no root file system {prefix or variant}" if not m
                  else f"{variant} appears {len(m)} times in list.json ({', '.join(str(r.get('prefix')) for r in m)})")


def build(inventory, listdoc, variant, prefix=None, supplier_cfg=None, spec="1.6", firmware_patterns=()):
    """→ (元件清單, 依賴 {ref: [子 ref]}, 頂層 ref 清單, info)。info 給 sbom.md 與 summary.json。"""
    supplier = entity(supplier_cfg)
    info = {"variant": variant, "prefix": prefix, "sources": [], "notes": [], "supplier": supplier["name"] if supplier else None,
            "inventory_has_sha512": False, "inventory_has_modules": False}
    comps, deps, top = [], {}, []
    inv = inventory if isinstance(inventory, dict) else {}
    new = spec_at_least(spec, (1, 6))         # component.manufacturer、licenses[].acknowledgement 是 CycloneDX 1.6 起才有
    rfs, why = pick_rootfs(listdoc, variant, prefix)
    if why:
        info["notes"].append(why)
    rel = _d(_d(rfs).get("l4t"))
    l4t = _s(rel.get("release"))
    if rfs and not l4t:
        info["notes"].append(f"L4T release not determined ({_s(rel.get('status')) or 'no data'}: {_s(rel.get('detail')) or ''})".rstrip(": "))
    prefix = prefix or _s(_d(rfs).get("prefix"))
    info["prefix"] = prefix

    # 開機與燒錄韌體、kernel 資料夾的 Image 與 dtb
    files, dup = last_by_path(_dicts(inv.get("bootloader")) + [x for x in _dicts(inv.get("outside_rootfs"))
                                                               if "kernel" in str(x.get("path", "")).split("/")[:-1]])
    skipped = dict.fromkeys(("hard link (content recorded under another path)", "symbolic link or other non-file entry",
                             "not firmware (scripts, configuration, tools)", "root file system image", "no hash (unreadable)"), 0)
    boot, kern = [], []
    for x in files:
        name = x["path"].rsplit("/", 1)[-1]
        low = name.lower()
        in_boot = "bootloader" in x["path"].split("/")[:-1]
        if x.get("type") != "file":
            skipped[_link_kind(x)] += 1
        elif low.startswith(SKIP_NAMES):
            skipped["root file system image"] += 1
        elif not (low.endswith(FW_EXT + DATA_EXT) or (not in_boot and name == "Image")):
            skipped["not firmware (scripts, configuration, tools)"] += 1
        elif not hashes_of(x):
            skipped["no hash (unreadable)"] += 1
        else:
            flags = FIRMWARE_IMAGE if (low.endswith(FW_EXT) or name == "Image") else None
            (boot if in_boot else kern).append(file_component(x, "firmware", flags, "flash-inventory: bootloader" if in_boot else
                                                              "flash-inventory: kernel", supplier, l4t))
    info["inventory_has_sha512"] = any(x.get("sha512") for x in files if isinstance(x, dict))
    info["duplicates"] = dup

    # NVIDIA 另外編的 kernel 模組（rootfs 的 lib/modules/*/updates/）
    mods = []
    km = inv.get("kernel_modules")
    if isinstance(km, dict):
        info["inventory_has_modules"] = True
        mlist, mdup = last_by_path(_dicts(km.get(prefix))) if prefix else ([], 0)
        info["duplicates"] += mdup
        dtype = "device-driver" if spec_at_least(spec, (1, 5)) else "library"
        for x in mlist:
            if x.get("type") not in ("file", "hardlink") or not hashes_of(x):
                # 硬連結沒有雜湊：內容記在 updates/ 裡的另一個路徑（那個路徑已經是元件）
                skipped[_link_kind(x) if x.get("type") != "file" else "no hash (unreadable)"] += 1
                continue
            mi = {k: _s(v) for k, v in x["modinfo"].items() if _s(v)} if isinstance(x.get("modinfo"), dict) else None
            fname = x["path"].rsplit("/", 1)[-1]
            c = file_component(x, dtype, FIRMWARE_IMAGE[:1] + ("no archive", "unstructured"), "flash-inventory: kernel module",
                               supplier, l4t)
            c["bom-ref"] = REF + f"{prefix}/{x['path']}"
            c["name"] = (mi or {}).get("name") or fname.split(".ko")[0]
            props = c["properties"]
            if mi and mi.get("version"):
                c["version"] = mi["version"]
                props[:] = [p for p in props if p["name"] != "sca-center:version-basis"]
                props.append(prop("sca-center:version-basis", "modinfo version"))
            for k in ("vermagic", "srcversion", "author"):
                if mi and mi.get(k):
                    props.append(prop(f"sca-center:modinfo-{k}", mi[k]))
            if mi is None:
                props.append(prop("sca-center:modinfo", f"not available: {_s(x.get('modinfo_note')) or 'not read'}"))
            if mi and mi.get("license"):
                # CycloneDX 1.6：acknowledgement 在 license 物件裡（和 expression 並列時在外層）
                c["licenses"] = [{"license": {"name": mi["license"], **({"acknowledgement": "declared"} if new else {})}}]
            for p in props:
                if p["name"] == "sca-center:flash-package-path":
                    p["value"] = f"{prefix}/{x['path']}"
            mods.append(c)
    else:
        info["notes"].append("flash-inventory.json has no kernel module list (made by an older flash_package.py): "
                             "kernel modules under lib/modules/*/updates/ are not in the SBOM; run a full scan (not --rescan-from) to add them")

    # L4T 版本（邏輯元件：TR-03183-2 3.2.2，沒有檔名與雜湊）
    l4t_ref = None
    if l4t:
        l4t_ref = REF + "l4t"
        c = {"type": "platform" if spec_at_least(spec, (1, 5)) else "operating-system", "bom-ref": l4t_ref, "name": "NVIDIA Jetson Linux",
             "version": l4t, **({"manufacturer": NVIDIA} if new else {"publisher": NVIDIA["name"]}),
             "properties": [prop(P_LOGICAL, "true"), prop("sca-center:source", "list.json: " + "; ".join(
                 f"{k} {_s(v)}" for k, v in sorted(_d(rel.get("sources")).items()) if _s(v))), prop("sca-center:root-file-system", prefix)]}
        if supplier:
            c["supplier"] = supplier
        comps.append(c)
        top.append(l4t_ref)
        deps[l4t_ref] = [x["bom-ref"] for x in boot + kern + mods]
    else:
        top += [x["bom-ref"] for x in boot + kern + mods]

    # MCU 韌體等其他交付檔（壓縮檔旁邊）
    mcu = []
    od = inv.get("other_deliverables")
    pats = [p for p in firmware_patterns or () if isinstance(p, str) and p]
    others = []
    for x in sorted((x for x in _dicts(od) if _s(x.get("name"))), key=lambda x: x["name"]):
        low = x["name"].lower()
        if x.get("type") != "file":
            continue
        if not (any(fnmatch.fnmatch(low, p.lower()) for p in pats) or (low.endswith(MCU_EXT) and MCU_NAME.search(low))):
            others.append(x["name"])
            continue
        if not hashes_of(x):
            skipped["no hash (unreadable)"] += 1
            continue
        y = dict(x, path=f"deliverables/{x['name']}")
        c = file_component(y, "firmware", ARCHIVE_ZIP if low.endswith(".zip") else FIRMWARE_IMAGE, "flash-inventory: other deliverables",
                           supplier, None)
        mcu.append(c)
        top.append(c["bom-ref"])
    if od is None:
        info["notes"].append("no other deliverables recorded (the scan was run without the delivery folder): MCU firmware not in the SBOM")

    # 另外交付的韌體（scan-flash-package.sh --extra-deliverable，bootloader_coverage.py extra 寫進清點檔）：沒有這個鍵時完全不動
    extra = []
    ex = inv.get("extra_deliverables")
    if ex is not None:
        for x in sorted((x for x in _dicts(ex) if _s(x.get("name"))), key=lambda x: x["name"]):
            if x.get("type") != "file" or not hashes_of(x):
                skipped["no hash (unreadable)"] += 1
                continue
            pw = _d(x.get("paired_with"))
            props = [prop("sca-center:extra-deliverable", "true"),
                     prop("sca-center:paired-with", " ".join(v for v in (_s(pw.get("name")), _s(pw.get("version"))) if v) or "unknown"),
                     prop("sca-center:version-string-found", _s(x.get("version")) or "none (version unknown)"),
                     prop("sca-center:version-vs-flash-package", _s(x.get("version_vs_flash_package")) or "unknown"),
                     prop("sca-center:scan-status", "not scanned (recorded only)")]
            c = file_component(dict(x, path=f"extra-deliverables/{x['name']}"), "firmware", FIRMWARE_IMAGE,
                               "flash-inventory: extra deliverable", supplier, None, props)
            extra.append(c)
            top.append(c["bom-ref"])
            if x.get("status") in ("ATTENTION", "NOT_ASSESSED"):
                info["notes"].append(f"extra deliverable {x['name']}: {_s(x.get('note')) or x['status']}")

    comps += boot + kern + mods + mcu + extra
    for c in comps:
        deps.setdefault(c["bom-ref"], [])
    info["sources"] = [
        {"source": "Boot and flash firmware (`bootloader/`)", "count": len(boot)},
        {"source": "Kernel image and device trees (`kernel/`)", "count": len(kern)},
        {"source": f"Kernel modules in `lib/modules/*/updates/` ({prefix or variant})", "count": len(mods),
         "no_modinfo": sum(1 for c in mods if any(p["name"] == "sca-center:modinfo" for p in c["properties"]))},
        {"source": "Jetson Linux (L4T) release", "count": 1 if l4t else 0, "detail": l4t or "not determined"},
        {"source": "MCU firmware and other deliverables next to the archive", "count": len(mcu)},
    ] + ([{"source": "Firmware delivered separately from the flash package (extra deliverables)", "count": len(extra)}] if ex is not None else [])
    info["skipped"] = {k: v for k, v in skipped.items() if v}
    # 清點不完整的地方：讀不到雜湊而沒加進 SBOM 的檔案、清點時讀不到的檔案、超過深度沒有走進去的資料夾 → notes（狀態 ATTENTION）
    if skipped["no hash (unreadable)"]:
        info["notes"].append(f"{skipped['no hash (unreadable)']} flash file(s) could not be read when the inventory was made (no hash): "
                             "they are not in the SBOM")
    fp = _d(_d(listdoc).get("flash_package"))
    for key, what in (("outside_rootfs_unreadable", "file(s) outside the root file system could not be read during the inventory"),
                      ("outside_rootfs_dirs_not_walked", "folder(s) outside the root file system were deeper than the inventory limit "
                                                         "and were not inventoried")):
        n = fp.get(key)
        if isinstance(n, int) and not isinstance(n, bool) and n > 0:
            ex = [x for x in fp.get("outside_rootfs_unreadable_examples") or [] if isinstance(x, str)][:3] \
                if key == "outside_rootfs_unreadable" else []
            info["notes"].append(f"{n} {what}" + (f" (for example {', '.join(ex)})" if ex else "") + "; firmware in them may be missing from the SBOM")
    info["other_deliverables_not_added"] = others
    info["components"] = len(comps)
    return comps, deps, top, info


def spec_at_least(spec, want):
    try:
        return tuple(int(x) for x in str(spec or "0").split(".")[:2]) >= want
    except ValueError:
        return False


def merge(bom, root_ref, comps, deps, top):
    """元件加到 SBOM（頂層 components 與 dependencies）；根元件的 dependsOn 加上 top。原地修改並回傳 bom。"""
    if not comps:
        return bom
    have = {c.get("bom-ref") for c in flatten(bom.get("components")) if isinstance(c.get("bom-ref"), str)}
    meta_ref = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")
    clash = sorted(c["bom-ref"] for c in comps if c["bom-ref"] in have or c["bom-ref"] == meta_ref)
    if clash:
        raise ValueError(f"bom-ref already in the SBOM: {', '.join(clash[:3])}")
    bom.setdefault("components", []).extend(comps)
    dl = bom.setdefault("dependencies", [])
    by = {d.get("ref"): d for d in dl if isinstance(d, dict)}
    root = by.get(root_ref)
    if root is None:
        root = {"ref": root_ref, "dependsOn": []}
        dl.append(root)
    old = [r for r in root.get("dependsOn") if isinstance(r, str)] if isinstance(root.get("dependsOn"), list) else []
    root["dependsOn"] = old + [r for r in top if r not in old]
    for ref in sorted(deps):
        dl.append({"ref": ref, "dependsOn": list(deps[ref])})
    return bom


def flatten(comps):
    for c in comps if isinstance(comps, list) else []:
        if isinstance(c, dict):
            yield c
            yield from flatten(c.get("components"))


# ---------- BSI TR-03183-2 v2.1.0 欄位覆蓋率 ----------

def _props(c):
    out = {}
    for p in _dicts(c.get("properties")):
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            out.setdefault(p["name"], []).append(p.get("value"))
    return out


def _entity_ok(e):
    """TR 對照表：manufacturer 要有 url 或 contact.email。CycloneDX 1.6 是物件；也接受陣列。"""
    es = e if isinstance(e, list) else [e]
    for x in es:
        if isinstance(x, dict) and (any(isinstance(u, str) and u for u in (x.get("url") if isinstance(x.get("url"), list) else []))
                                    or any(isinstance(k, dict) and "@" in str(k.get("email") or "") for k in _dicts(x.get("contact")))):
            return True
    return False


def version_missing(c):
    """沒有版本：空的，或用 UNKNOWN 填（核心模組等）。UNKNOWN 不是版本，不算「有版本」（專案規則：未知版本要標示，不猜）。"""
    v = str(c.get("version") or "").strip()
    return not v or v.upper() == "UNKNOWN"


def _sha512(c):
    hs = _dicts(c.get("hashes"))
    for r in _dicts(c.get("externalReferences")):
        if r.get("type") == "distribution":
            hs += _dicts(r.get("hashes"))
    return any(isinstance(h, dict) and h.get("alg") == "SHA-512" and h.get("content") for h in hs)


def _licence(c, ack):
    """CycloneDX 1.6：{"license": {..., "acknowledgement": …}} 或 {"expression": …, "acknowledgement": …}。"""
    for x in _dicts(c.get("licenses")):
        lic = _d(x.get("license"))
        if (lic and lic.get("acknowledgement") == ack and (lic.get("id") or lic.get("name"))) or \
                (x.get("expression") and x.get("acknowledgement") == ack):
            return True
    return False


# (欄位, 只對檔案元件, 檢查)；順序同 TR 表 3
COMPONENT_FIELDS = [
    ("Component creator", False, lambda c, ctx: _entity_ok(c.get("manufacturer"))),
    ("Component name", False, lambda c, ctx: bool(str(c.get("name") or "").strip())),
    ("Component version", False, lambda c, ctx: not version_missing(c)),
    ("Filename of the component", True, lambda c, ctx: bool(_props(c).get("bsi:component:filename"))),
    ("Dependencies on other components", False, lambda c, ctx: isinstance(c.get("bom-ref"), str) and c["bom-ref"] in ctx["dep_refs"]),
    ("Distribution licences", False, lambda c, ctx: _licence(c, "concluded")),
    ("Hash value of the deployable component (SHA-512)", True, lambda c, ctx: _sha512(c)),
    ("Executable property", True, lambda c, ctx: (_props(c).get("bsi:component:executable") or [None])[0] in BSI_FLAGS["bsi:component:executable"]),
    ("Archive property", True, lambda c, ctx: (_props(c).get("bsi:component:archive") or [None])[0] in BSI_FLAGS["bsi:component:archive"]),
    ("Structured property", True, lambda c, ctx: (_props(c).get("bsi:component:structured") or [None])[0] in BSI_FLAGS["bsi:component:structured"]),
]
ADDITIONAL_FIELDS = [
    ("Other unique identifiers (purl or CPE)", lambda c: bool(c.get("purl") or c.get("cpe"))),
    ("Original licences", lambda c: _licence(c, "declared")),
    ("Source code URI", lambda c: any(isinstance(r, dict) and r.get("type") == "source-distribution" and r.get("url")
                                      for r in _dicts(c.get("externalReferences")))),
    ("URI of the deployable form", lambda c: any(isinstance(r, dict) and r.get("type") == "distribution" and r.get("url")
                                                 for r in _dicts(c.get("externalReferences")))),
]
MISSING_MAX = 200


def label(c):
    v = c.get("version")
    return f"{c.get('name') or c.get('bom-ref') or '?'}" + (f" {v}" if v else "")


def _creator_value(e):
    """「Present」欄是 no 時，Value 欄不能只寫公司名（讀起來像有）：註明缺什麼（TR 要 URL 或 email）。"""
    name = e.get("name") if isinstance(e, dict) else None
    if _entity_ok(e):
        return name
    return f"{name} (name only; no URL or email address recorded)" if name else None


def tr03183(bom):
    """產品 SBOM → 覆蓋率。status：OK（必填欄位全部有）／ATTENTION（有缺）／NOT_ASSESSED（沒有 SBOM）。
    file 類型的元件（Syft 的檔案清單）不算；標成邏輯元件（sca-center:logical-component）的不檢查檔案層級的欄位（TR 3.2.2）。"""
    if not isinstance(bom, dict):
        return {"tr_version": TR_VERSION, "status": "NOT_ASSESSED", "reason": "no SBOM"}
    m = _d(bom.get("metadata"))
    primary = m.get("component") if isinstance(m.get("component"), dict) else None
    allc = ([primary] if primary else []) + list(flatten(bom.get("components")))
    files = sum(1 for c in allc if c.get("type") == "file")
    comps = [c for c in allc if c.get("type") != "file"]
    ctx = {"dep_refs": {d.get("ref") for d in _dicts(bom.get("dependencies")) if isinstance(d.get("ref"), str)}}
    spec = str(bom.get("specVersion") or "?")
    sbom_rows = [
        {"field": "Format: CycloneDX 1.6 or higher (JSON)", "ok": bom.get("bomFormat") == "CycloneDX" and spec_at_least(spec, (1, 6)),
         "value": f"{bom.get('bomFormat') or '?'} {spec}"},
        {"field": "Creator of the SBOM (metadata.manufacturer with URL or email)", "ok": _entity_ok(m.get("manufacturer")),
         "value": _creator_value(m.get("manufacturer"))},
        {"field": "Timestamp", "ok": bool(m.get("timestamp")), "value": m.get("timestamp")},
        {"field": "SBOM-URI (serialNumber; additional field)", "ok": bool(bom.get("serialNumber")), "value": bom.get("serialNumber"),
         "additional": True},
        {"field": "Completeness of dependencies stated (compositions)", "ok": bool(_dicts(bom.get("compositions"))),
         "value": f"{len(_dicts(bom.get('compositions')))} composition(s)"},
    ]
    fields = []
    for name, file_only, test in COMPONENT_FIELDS:
        scope = [c for c in comps if not (file_only and (_props(c).get(P_LOGICAL) or [None])[0] == "true")]
        miss = [label(c) for c in scope if not test(c, ctx)]
        fields.append({"field": name, "file_level": file_only, "total": len(scope), "have": len(scope) - len(miss),
                       "missing_count": len(miss), "missing": sorted(miss)[:MISSING_MAX]})
    extra = []
    for name, test in ADDITIONAL_FIELDS:
        have = sum(1 for c in comps if test(c))
        extra.append({"field": name, "total": len(comps), "have": have})
    bad = [r["field"] for r in sbom_rows if not r["ok"] and not r.get("additional")] + [f["field"] for f in fields if f["missing_count"]]
    return {"tr_version": TR_VERSION, "status": "ATTENTION" if bad else "OK", "components": len(comps), "file_components_not_counted": files,
            "sbom": sbom_rows, "fields": fields, "additional": extra, "gaps": bad}


# ---------- sbom.md 的兩節 ----------

def pct(have, total):
    """覆蓋率。有缺就不進位成 100%（2721/2730 不能寫 100%）：無條件捨去到小數一位，缺的最多顯示 99.9%，有的最少顯示 <0.1%。"""
    if not total:
        return "–"
    if have >= total:
        return "100%"
    x = int(1000 * have / total) / 10
    return "<0.1%" if x == 0 and have else f"{x:.1f}%"


def firmware_text(info, table):
    """sbom.md 第 6 節。info：build() 的 info，或 {"absent": 原因}（不是刷機包的掃描或沒有清點檔）。"""
    if info.get("absent"):
        return info["absent"]
    rows = [[s["source"], s["count"], s.get("detail") or (f"{s['no_modinfo']} without readable modinfo" if s.get("no_modinfo") else "")]
            for s in info["sources"]]
    out = [f"Added to the product SBOM from the flash package inventory (`flash-inventory.json`) and `list.json` "
           f"(root file system `{info.get('prefix') or info.get('variant')}`): **{info['components']} components**. "
           "These parts are flashed to the module but are not inside the root file system that the scanner reads.", "",
           table(["Source", "Components", "Note"], rows)]
    if info.get("skipped"):
        out += ["", "Not added: " + "; ".join(f"{k}: {v}" for k, v in sorted(info["skipped"].items())) + "."]
    if info.get("other_deliverables_not_added"):
        names = info["other_deliverables_not_added"]
        out += ["", f"Other files delivered next to the archive, not added as components ({len(names)}; only file names matching the MCU "
                "firmware pattern or the configuration `sbom.deliverable_firmware` are added): "
                + ", ".join(f"`{n}`" for n in names[:20]) + (", …" if len(names) > 20 else "") + "."]
    if info.get("duplicates"):
        out += ["", f"{info['duplicates']} duplicate path(s) in the inventory: the last entry was used."]
    out += ["", ("Supplier of these components (who delivered the flash package): " + info["supplier"]) if info.get("supplier") else
            "Supplier of these components: **TO BE COMPLETED** (configuration `sbom.flash_package_supplier`: who delivered the flash package).",
            "", "The creator of individual flash files is not stated: it is known only after comparing the files with NVIDIA's public BSP. "
            "Versions of flash files are their file modification times (BSI TR-03183-2 5.2.2, no version assigned by the creator); "
            "kernel module versions come from `modinfo`."]
    if not info.get("inventory_has_sha512"):
        out += ["", "The inventory has no SHA-512 values (made by an older flash_package.py): only SHA-256 is recorded."]
    for n in info.get("notes") or []:
        out += ["", f"Note: {n}."]
    return "\n".join(out)


def tr_text(tr, table, show=10):
    """sbom.md 第 7 節。"""
    if tr.get("status") == "NOT_ASSESSED":
        return f"**Status: NOT_ASSESSED** ({tr.get('reason')})."
    out = [f"**Status: {tr['status']}** (reported only; does not block release). Checked against BSI TR-03183-2 version {tr['tr_version']}, "
           f"section 5.2, using the CycloneDX mapping in section 8.2. Components checked: {tr['components']} "
           f"(file entries from the scanner's file catalogue not counted: {tr['file_components_not_counted']}).", "",
           "SBOM itself:", "",
           table(["Field", "Present", "Value"], [[r["field"], "yes" if r["ok"] else "**no**", r.get("value") or ""] for r in tr["sbom"]]),
           "", "Required fields for each component (file-level fields are not counted for logical components such as the "
           "Jetson Linux release, TR-03183-2 3.2.2; whether the scanner's package components are logical components is not decided "
           "by this tool):", "",
           table(["Field", "Components with the field", "Coverage", "Missing (examples)"],
                 [[f["field"], f"{f['have']} / {f['total']}", pct(f["have"], f["total"]),
                   (", ".join(f["missing"][:show]) + (f", … ({f['missing_count']} in total; full list in `summary.json`)"
                                                      if f["missing_count"] > show else "")) if f["missing_count"] else ""]
                  for f in tr["fields"]]),
           "", "Additional fields (required by TR-03183-2 5.2.4 where the information exists):", "",
           table(["Field", "Components with the field", "Coverage"], [[f["field"], f"{f['have']} / {f['total']}", pct(f["have"], f["total"])]
                                                                       for f in tr["additional"]])]
    return "\n".join(out)


def _table(head, rows):
    esc = lambda x: str(x).replace("|", "\\|").replace("\n", " ")   # noqa: E731
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(esc(x) for x in r) + " |" for r in rows])


def main(argv=None):
    """python3 -I firmware_bom.py check <sbom.cdx.json>：只印出 TR-03183-2 覆蓋率（Markdown）。"""
    a = list(sys.argv[1:] if argv is None else argv)
    if len(a) != 2 or a[0] != "check" or not os.path.isfile(a[1]):
        print("用法：python3 -I firmware_bom.py check <sbom.cdx.json>", file=sys.stderr)
        return 64
    with open(a[1], encoding="utf-8") as f:
        tr = tr03183(json.load(f))
    print(tr_text(tr, _table))
    return 0 if tr["status"] == "OK" else 2


if __name__ == "__main__":
    sys.exit(main())
