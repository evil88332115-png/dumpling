#!/usr/bin/env python3
"""kernel_boot.py：刷機包有沒有兩顆不同的核心（C-kernel-boot）。

Jetson（Linux_for_Tegra）刷機包可能同時有 <pkg>/kernel/Image（燒進 A_kernel 分割區，通常是 RD 自己編的）和
<pkg>/rootfs/boot/Image（rootfs 裡的，常是 NVIDIA 原廠的），而 rootfs/boot/extlinux/extlinux.conf 的 LINUX 指向 /boot/Image。
實際開機的是哪一顆，只有在板子上才能確認（cat /proc/version、uname -v）；也和 UEFI 的開機模式有關，從檔案無法證明。
依據（公開 BSP，NVIDIA Jetson Linux R39.2.1 的 Jetson_Linux_R39.2.1_aarch64.tbz2）：Linux_for_Tegra/apply_binaries.sh 呼叫
nv_tools/scripts/nv_apply_kernel_files.sh，把 kernel/Image 安裝成 rootfs 的 /boot/Image（該腳本的 install … Image … "${ROOTFS_DIR}/boot/Image"）；
bootloader/extlinux.conf 的 LINUX 指向 /boot/Image。所以預期燒錄後開機的是 kernel/Image；但 UEFI 開機模式可改，有板子的 uname -v（board-test 的 os.txt）時以它為準。所以預設不推翻 K1：
K1（C-kernel-config）照舊用 kernel/Image 與核心建置紀錄；這個檢查只並列兩顆核心的證據：

用法：python3 -I kernel_boot.py --from <刷機包 tbz2｜資料夾> --prefix <rootfs 在刷機包裡的路徑>
                               [--build-record <核心建置紀錄>] [--board-os-txt <板子 board-test 的 os.txt（含 uname -a 那一行）>]
                               --out <kernel-boot.json>
輸出一行 `C-kernel-boot<TAB>狀態<TAB>說明`，並寫 kernel-boot.json（schema sca-center-kernel-boot/1）。
狀態：
  OK         兩顆核心位元組相同；或兩顆不同、但板子的 uname -v 對上 kernel/Image（板子確認燒的是 kernel/Image）；
  ATTENTION  兩顆不同、沒有板子資料（資訊性：燒錄流程預期裝 kernel/Image，要在板子上確認）；板子對上 rootfs/boot/Image、兩顆都對不上、
             或兩顆的版本字串一樣讓板子分不出來；建置紀錄（BUILD-INFO.txt 的 image sha256）對不上 kernel/Image；
  NOT_RUN    刷機包裡沒有兩顆核心（只有一顆或都沒有）：沒有東西可比。
k1_kernel：K1 該用哪一顆：partition（kernel/Image，預設）或 rootfs（只有板子的 uname -v 只對上 rootfs/boot/Image 時；
sca-scan 會對 kernel_config.py 加 --prefer-rootfs-image：改用該 Image 的 IKCONFIG，核心建置紀錄除非 BUILD-INFO.txt 的 sha256 對得上，否則 GAP）。
退出碼：0 已判定；3 輸入錯誤（同時印 FAIL 那一行）。全部只讀、在記憶體裡處理、不執行任何東西。
"""
import argparse
import functools
import importlib.util
import json
import re
import sys
from pathlib import Path

STAGE = "C-kernel-boot"
SCHEMA = "sca-center-kernel-boot/1"
HERE = Path(__file__).resolve().parent
MAX_SHOW = 10                       # 列出的設定差異數
MAX_LABELS = 64
UTS_RE = re.compile(r"\)\s+(#\d+\s.*?)(?:\s*\(\))?\s*$")             # linux_banner 結尾："… ) #1 SMP PREEMPT Wed Oct 28 11:08:26 CST 2026 ()"
ARCH_RE = r"(?:aarch64|arm\w*|x86_64|i[3-6]86|riscv\w*|ppc\w*|s390x|mips\w*)"
# 板子輸出可能是 uname -a（Linux host release #… arch …）、uname -v（#1 SMP …）或 cat /proc/version（Linux version … ) #1 SMP … ）：
# 都以 "#<n>… <日期>" 的 UTS 字串比對。UTS 字串結尾到行尾，或到 uname -a 的架構欄位為止。
UTS_LINE_RE = re.compile(r"(#\d+\S*\s+.*?)(?:\s+" + ARCH_RE + r"(?:\s+\S+)*)?\s*$")
UNAME_A_RE = re.compile(r"^Linux\s+(\S+)\s+(\S+)\s+#")
WS = re.compile(r"\s+")


class InputError(Exception):
    pass


def line(st, detail):
    print(f"{STAGE}\t{st}\t" + re.sub(r"[\t\r\n]+", " ", str(detail))[:900])


def norm(s):
    return WS.sub(" ", s).strip()


def uts_of_banner(banner):
    """Image 的 linux_banner → uname -v 的字串（"#1 SMP PREEMPT <建置時間>"）或 None。"""
    m = UTS_RE.search(banner or "")
    return norm(m.group(1)) if m else None


def release_of_banner(banner):
    m = re.match(r"Linux version (\S+) \(", banner or "")
    return m.group(1) if m else None


def label_of(p):
    """Image → 短說明：<release> (<建置者@主機>) <uname -v 字串>。讀不到版本字串時明說。"""
    b = p.banner
    if not b:
        return "no version string"
    m = re.match(r"Linux version (\S+) \(([^()\s]+)\)", b)
    return f"{m.group(1)} ({m.group(2)[:60]}) {uts_of_banner(b) or 'no build timestamp'}" if m else norm(b)[:120]


def parse_board_uname(text):
    """板子 os.txt／uname 輸出 → {"host","release","uts","lines"} 或 None。接受三種格式：uname -a、uname -v、cat /proc/version。
    有好幾行時第一個有 UTS 字串的算（lines 記共幾行）。"""
    found = []
    for ln in str(text or "").splitlines():
        ln = ln.strip()
        m = re.search(r"#\d+\S*\s", ln)
        if not m or not (ln.startswith(("Linux ", "#")) or " version " in ln[:20]):
            continue
        host = release = None
        ma = UNAME_A_RE.match(ln)
        if ma:
            host, release = ma.group(1), ma.group(2)
        elif ln.startswith("Linux version "):
            release = ln.split()[2]
            ln = ln[ln.rfind(") #") + 2:] if ") #" in ln else ln[m.start():]
        mu = UTS_LINE_RE.search(ln[ln.find("#"):])
        if mu and re.search(r"\d{4}|\d:\d\d", mu.group(1)):
            found.append({"host": host, "release": release, "uts": norm(mu.group(1))})
    if not found:
        return None
    return dict(found[0], lines=len(found))


def parse_extlinux(data):
    """extlinux.conf（bytes）→ {"default","labels":{名稱:{"linux","initrd","fdt","append"}},"order","selected","selected_how","problems"}。
    不分大小寫的關鍵字；# 開頭是註解；DEFAULT 指定標籤，沒有時 MENU DEFAULT 的標籤，再沒有時第一個標籤（selected_how 記是哪一種）。"""
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    labels, order, cur, default, menu_default, problems = {}, [], None, None, None, []
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split(None, 1)
        key, val = parts[0].upper(), (parts[1].strip() if len(parts) > 1 else "")
        if key == "DEFAULT":
            default = val
        elif key == "LABEL":
            if len(order) >= MAX_LABELS:
                problems.append(f"more than {MAX_LABELS} labels: the rest are ignored")
                break
            cur = val
            if cur not in labels:
                labels[cur] = {}
                order.append(cur)
        elif cur is not None and key in ("LINUX", "KERNEL"):
            labels[cur].setdefault("linux", val)
        elif cur is not None and key == "INITRD":
            labels[cur].setdefault("initrd", val)
        elif cur is not None and key in ("FDT", "DEVICETREE"):
            labels[cur].setdefault("fdt", val)
        elif cur is not None and key in ("APPEND", "APPEND_"):
            labels[cur].setdefault("append", val)
        elif cur is not None and key == "MENU" and val.upper() == "DEFAULT":
            menu_default = cur
    sel, how = None, None
    if default is not None:
        if default in labels:
            sel, how = default, "DEFAULT"
        else:
            problems.append(f"DEFAULT {default!r} is not a LABEL in the file")
    elif menu_default is not None:
        sel, how = menu_default, "MENU DEFAULT"
    elif order:
        sel, how = order[0], "first label (no DEFAULT in the file; assumed)"
    return {"default": default, "labels": labels, "order": order, "selected": sel, "selected_how": how, "problems": problems}


def resolve_rootfs_path(path, base=("boot", "extlinux")):
    """extlinux 的路徑（絕對＝從 rootfs 根；相對＝從 boot/extlinux）→ rootfs 相對路徑 tuple，.. 不會超出根（不碰主機）。"""
    out = [] if path.startswith("/") else list(base)
    for n in path.split("/"):
        if n in ("", "."):
            continue
        if n == "..":
            if out:
                out.pop()
            continue
        out.append(n)
    return tuple(out)


def describe_image(p):
    return None if p is None else {"path": p.path, "sha256": p.sha256, "bytes": p.size, "version": p.banner,
                                   "release": release_of_banner(p.banner), "uts": uts_of_banner(p.banner), "ikconfig": p.config is not None,
                                   "ikconfig_complete": bool(p.complete) if p.config is not None else None, "reason": p.reason}


def extlinux_info(imgs, rootfs_image):
    ext = {"present": False, "reason": None}
    data = imgs.get("extlinux")
    if data is None:
        ext["reason"] = imgs.get("extlinux_reason") or "no rootfs/boot/extlinux/extlinux.conf in the package"
        return ext
    ext["present"] = True
    cf = parse_extlinux(data)
    ext.update(default=cf["default"], selected=cf["selected"], selected_how=cf["selected_how"], labels=cf["order"], problems=cf["problems"])
    sel = cf["labels"].get(cf["selected"]) if cf["selected"] else None
    if not sel or not sel.get("linux"):
        ext["reason"] = "the selected label has no LINUX line" if cf["selected"] else "no label selected"
        return ext
    ext["linux"] = sel["linux"]
    tgt = resolve_rootfs_path(sel["linux"])
    ext["resolved"] = "/" + "/".join(tgt)
    ext["points_at"] = ("rootfs/boot/Image" if rootfs_image is not None and tgt and tgt[0] == "boot" and tgt[-1] == "Image" and len(tgt) == 2
                        else "other")
    if ext["points_at"] == "other":
        ext["reason"] = f"LINUX {sel['linux']} is not /boot/Image; the file it names is not compared"
    return ext


def evaluate(imgs, diff_fn, board_text=None, build_shas=None):
    """imgs：kernel_config.image_inputs 的結果；diff_fn(a_text, b_text)->kernel_config.config_diff；board_text：os.txt 內容或 None；
    build_shas：建置紀錄 BUILD-INFO.txt 的 image sha256 集合或 None（沒給＝沒有這項資料）。→ record dict（含 status、detail、k1_kernel）。"""
    fl, rf = (imgs or {}).get("flashed"), (imgs or {}).get("rootfs")
    rec = {"schema": SCHEMA, "status": None, "detail": None, "k1_kernel": "partition", "partition_image": describe_image(fl),
           "rootfs_image": describe_image(rf), "extlinux": extlinux_info(imgs or {}, rf), "config_diff": None, "board": None,
           "build_record": None, "limitations": [
               "The kernel that actually boots can only be confirmed on a board (cat /proc/version or uname -v); files cannot prove it.",
               "With the default UEFI L4TLauncher boot mode a board boots the kernel named by extlinux.conf; flashing is expected to install "
               "kernel/Image there (public L4T BSP: apply_binaries.sh -> nv_apply_kernel_files.sh installs kernel/Image as rootfs /boot/Image, and extlinux.conf boots /boot/Image; a board's uname -v overrides it), but the UEFI boot mode may be changed; confirm per product."]}
    if fl is None or rf is None:
        rec["status"] = "NOT_RUN"
        rec["detail"] = ("the package has " + ("only kernel/Image" if fl is not None else "only rootfs/boot/Image" if rf is not None else "no Image")
                         + ": there are not two kernels to compare")
        return rec
    bad = [n for n, p in (("kernel/Image", fl), ("rootfs/boot/Image", rf)) if p.sha256 is None]
    if bad:       # 連結、特殊檔案、讀不到：不跟隨、不猜
        rec["status"] = "GAP"
        rec["detail"] = (" and ".join(bad) + " could not be read (" + "; ".join(str(p.reason) for p in (fl, rf) if p.sha256 is None)
                         + "): the two kernels cannot be compared")
        return rec
    same = fl.sha256 == rf.sha256
    notes, attention = [], False
    if build_shas is not None:
        m_part, m_root = fl.sha256 in build_shas, rf.sha256 in build_shas
        rec["build_record"] = {"image_sha256": sorted(build_shas), "matches_partition_image": m_part, "matches_rootfs_image": m_root}
        if m_part:
            notes.append("the build record's BUILD-INFO image sha256 matches kernel/Image" + (" and rootfs/boot/Image" if m_root else ""))
        else:
            attention = True
            notes.append("the build record's BUILD-INFO image sha256 does not match kernel/Image"
                         + (" (it matches rootfs/boot/Image)" if m_root else "") + ": the record may not describe the flashed kernel")
    if not same:
        names = []
        if fl.config is not None and rf.config is not None:
            _, _, _, _, raw, names, _ = diff_fn(rf.config.decode("utf-8", "replace"), fl.config.decode("utf-8", "replace"))
            rec["config_diff"] = {"differences_total": len(names), "raw_differences_total": len(raw), "shown": sorted(names)[:MAX_SHOW],
                                  "truncated": len(names) > MAX_SHOW}
        else:
            rec["config_diff"] = {"differences_total": None, "reason": "IKCONFIG not readable in "
                                  + " and ".join(n for n, p in (("kernel/Image", fl), ("rootfs/boot/Image", rf)) if p.config is None)}
    board = parse_board_uname(board_text) if board_text is not None else None
    if board_text is not None and board is None:
        rec["board"] = {"given": True, "parsed": False, "reason": "no uname -a, uname -v or /proc/version line (with `#<n> ... <date>`) found"}
    elif board is not None:
        fu, ru = uts_of_banner(fl.banner), uts_of_banner(rf.banner)
        mp, mr = fu is not None and fu == board["uts"], ru is not None and ru == board["uts"]
        rec["board"] = {"given": True, "parsed": True, "uname_v": board["uts"], "release": board["release"], "matches_partition_image": mp,
                        "matches_rootfs_image": mr, "uname_lines": board["lines"]}
        if board["lines"] > 1:
            notes.append(f"the board file has {board['lines']} uname lines; the first one is used")
    if same:
        notes.insert(0, "kernel/Image and rootfs/boot/Image are byte-identical")
        if board and rec["board"].get("parsed") and not (rec["board"]["matches_partition_image"] or rec["board"]["matches_rootfs_image"]):
            attention = True
            notes.append(f"but the board's uname -v ({board['uts']}) matches neither version string")
        st = "ATTENTION" if attention else "OK"
    else:
        head = (f"two different kernels in the package: kernel/Image sha256 {fl.sha256[:12]}… ({label_of(fl)}), "
                f"rootfs/boot/Image sha256 {rf.sha256[:12]}… ({label_of(rf)})")
        cd = rec["config_diff"] or {}
        if cd.get("differences_total") is not None:
            head += f"; {cd['differences_total']} config difference(s)" + (": " + ", ".join(cd["shown"][:5]) if cd["shown"] else "")
        notes.insert(0, head)
        ext = rec["extlinux"]
        if ext.get("points_at") == "rootfs/boot/Image":
            notes.append(f"extlinux.conf (label {ext['selected']}) boots {ext['linux']}")
        elif not ext["present"]:
            notes.append(f"extlinux.conf: {ext['reason']}")
        b = rec["board"]
        if b and b.get("parsed"):
            if b["matches_partition_image"] and not b["matches_rootfs_image"]:
                st = "OK" if not attention else "ATTENTION"
                notes.append(f"the board's uname -v ({b['uname_v']}) matches kernel/Image: the board confirms the flashed kernel")
            elif b["matches_rootfs_image"] and not b["matches_partition_image"]:
                st, attention = "ATTENTION", True
                rec["k1_kernel"] = "rootfs"
                notes.append(f"the board's uname -v ({b['uname_v']}) matches rootfs/boot/Image, NOT kernel/Image: the board runs the rootfs kernel; "
                             "K1 uses its configuration and the build record's exclusions are not applicable to it")
            elif b["matches_partition_image"] and b["matches_rootfs_image"]:
                st, attention = "ATTENTION", True
                notes.append("both images have the same version string, so the board's uname -v cannot tell them apart")
            else:
                st, attention = "ATTENTION", True
                notes.append(f"the board runs a different kernel than the package: uname -v {b['uname_v']} matches neither image")
        else:
            st, attention = "ATTENTION", True
            if b and not b.get("parsed"):
                notes.append("the board file was given but has no uname line: " + b["reason"])
            notes.append("informational: the flash process is expected to install kernel/Image as /boot/Image (public L4T BSP: apply_binaries.sh -> nv_apply_kernel_files.sh), but this "
                         "must be confirmed per product on a board (cat /proc/version); UEFI boot mode cannot be proven from files; "
                         "K1 keeps using kernel/Image and the build record")
        st = "ATTENTION" if attention else st
    rec["status"] = st
    rec["detail"] = "; ".join(notes)
    return rec


@functools.lru_cache(maxsize=None)
def kernel_config():
    p = HERE / "kernel_config.py"
    try:
        spec = importlib.util.spec_from_file_location("sca_center_kernel_config_boot", p)
        m = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = m
        spec.loader.exec_module(m)
        return m
    except Exception as e:
        raise InputError(f"cannot load {p} ({type(e).__name__})")


def main(argv=None):
    ap = argparse.ArgumentParser(description="刷機包有沒有兩顆不同的核心（C-kernel-boot）")
    ap.add_argument("--from", dest="from_")
    ap.add_argument("--prefix")
    ap.add_argument("--build-record")
    ap.add_argument("--board-os-txt")
    ap.add_argument("--out")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        line("FAIL", "kernel_boot.py 參數錯誤")
        return 3
    if not a.from_ or not a.out or not a.prefix:
        line("FAIL", "kernel_boot.py 參數錯誤：要 --from、--prefix、--out")
        return 3
    try:
        Path(a.out).unlink(missing_ok=True)        # 不留上一次的結果冒充這次的
    except OSError as e:
        line("FAIL", f"無法刪除舊的輸出（{type(e).__name__}）")
        return 3
    try:
        board_text = None
        if a.board_os_txt:
            try:
                with open(a.board_os_txt, "rb") as f:
                    board_text = f.read(1 << 20).decode("utf-8", "replace")
            except OSError as e:
                raise InputError(f"--board-os-txt 讀不到（{e.strerror}）")
        kc = kernel_config()
        col, _ = kc.collect(a.from_, a.prefix, images=True)
        if col is None:
            raise InputError("--from 要是刷機包或映像（不是核心原始碼樹）")
        imgs = kc.image_inputs(col)
        shas = None
        if a.build_record:
            rr = kc.read_build_record(a.build_record)
            if rr.error:
                raise InputError(f"建置紀錄讀不了：{rr.error}")
            shas = kc.build_info_sha256s(rr) or None          # 沒有 BUILD-INFO.txt 的雜湊＝沒有這項資料，不算對不上
        rec = evaluate(imgs, kc.config_diff, board_text, shas)
    except InputError as e:
        line("FAIL", f"kernel_boot.py 輸入錯誤：{e}")
        return 3
    except Exception as e:      # 不印 traceback；kernel_config.py 的 InputError 是另一個類別（依路徑載入），訊息照樣給
        if type(e).__name__ == "InputError":
            line("FAIL", f"kernel_boot.py 輸入錯誤：{e}")
            return 3
        line("FAIL", f"kernel_boot.py 無法判定（{type(e).__name__}）")
        return 3
    if rec["status"] != "NOT_RUN":
        try:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(rec, f, ensure_ascii=False, indent=1)
        except OSError as e:
            line("FAIL", f"無法寫入 {a.out}（{type(e).__name__}）")
            return 3
    line(rec["status"], rec["detail"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
