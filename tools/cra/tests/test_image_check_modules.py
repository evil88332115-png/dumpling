"""image_check.py 檢查 7：腳本與 modprobe.d 裡、映像沒有的核心模組名稱（實際案例：緩解檢查腳本 grep "^algif_head " /proc/modules，
模組其實叫 algif_aead → 永遠回報「沒載入」）。合成的 rootfs tar；只認明確的寫法，註解、echo、heredoc、變數不算。"""
import gzip
import json
import lzma
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import image_check as ic  # noqa: E402
import security_findings as sf  # noqa: E402
from test_image_check import elf, fids, run, write_tar  # noqa: E402

ET_REL_KO = elf(etype=1, interp=False)       # 核心模組：ELF 可重定位檔

KVER = "6.8.12-1021-tegra"
MD = f"./usr/lib/modules/{KVER}"
CONTENT_MARK = "SCRIPTCONTENTMARK"

# 實際案例的腳本結構（名稱換成合成的；第 9 行呼叫）
COPYFAIL = ('#!/bin/bash\n\ncheck_module() {\n    local module_name=$1\n'
            '    grep -qE "^${module_name} " /proc/modules && echo -en "WARNING! ${module_name} is loaded ' + CONTENT_MARK + '\\n" '
            '|| echo -en "${module_name} module is NOT loaded\\n"\n}\n\n\ncheck_module "algif_head"\n').encode()


def base(mods=True, dep=True, builtin=b"kernel/crypto/sha256_generic.ko\n"):
    m = [("./lib", ("sym", "usr/lib")), ("./bin", ("sym", "usr/bin")), ("./sbin", ("sym", "usr/sbin")),
         ("./etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n"), ("./etc/shadow", b"root:*:19000:0:99999:7:::\n", 0o640)]
    if mods:
        ko = ["kernel/crypto/algif_aead.ko.zst", "kernel/crypto/algif_hash.ko.zst", "kernel/crypto/algif_rng.ko.zst",
              "kernel/crypto/algif_skcipher.ko.zst", "kernel/crypto/af_alg.ko.zst", "kernel/drivers/net/usb/r8152.ko.zst"]
        m += [(f"{MD}/{k}", b"\x28\xb5\x2f\xfd") for k in ko]
        if dep:
            m.append((f"{MD}/modules.dep", "".join(f"{k}: kernel/crypto/af_alg.ko.zst\n" for k in ko[:4]).encode()
                      + b"kernel/crypto/af_alg.ko.zst:\nkernel/drivers/net/usb/r8152.ko.zst:\n"))
            m.append((f"{MD}/modules.order", b"kernel/crypto/af_alg.ko\n"))
        if builtin is not None:
            m.append((f"{MD}/modules.builtin", builtin))
    return m


def mods(res):
    return res["modules"]


def test_typo_in_mitigation_check_is_flagged_with_hint(tmp_path):
    good = (b'#!/bin/sh\n'
            b'grep -q "^algif_hash " /proc/modules && echo hash\n'
            b'if lsmod | grep -q algif_rng; then :; fi\n'
            b'modprobe -r algif_skcipher 2>/dev/null\n'
            b'sudo modprobe -q algif-aead\n'                    # - 與 _ 相同
            b'rmmod -f r8152\n'
            b'insmod /lib/modules/x/kernel/crypto/algif_aead.ko.zst\n'
            b'grep -qw algif_aead < /proc/modules\n'
            b'cat /proc/modules | grep -E "^(algif_hash|algif_rng) "\n')
    src = write_tar(tmp_path / "rootfs.tar", base() + [
        ("./usr/local/bin/check_CVE-0000-0001_Sample.sh", COPYFAIL, 0o755),
        ("./usr/local/bin/check_good.sh", good, 0o755),
        ("./usr/local/bin/check_good2.sh", COPYFAIL.replace(b'"algif_head"', b'"algif_aead"'), 0o755),
        # 沒有相近名稱：這個核心沒有這個模組（實際案例 esp4、esp6、rxrpc）→ low，不是打錯字
        ("./usr/local/bin/check_not_built.sh", COPYFAIL.replace(b'"algif_head"', b'"esp4"'), 0o755)])
    st, detail, res, md = run(tmp_path, src)
    nb = fids(res)["modules:module-not-built"]
    assert nb["severity"] == "low" and nb["evidence"] == [
        "/usr/local/bin/check_not_built.sh:9 esp4 (call of a function that reads /proc/modules; closest existing: none)"]
    assert "no risk" in nb["text"] and "probably not built" in nb["text"]
    f = fids(res)["modules:name-not-in-image"]
    assert f["severity"] == "medium" and f["check"] == "modules" and set(f["annex"]) == {"I-2b", "I-2k"}
    assert f["evidence"] == ["/usr/local/bin/check_CVE-0000-0001_Sample.sh:9 algif_head (call of a function that reads "
                             "/proc/modules; closest existing: algif_aead, algif_hash, algif_skcipher)"]
    m = mods(res)
    assert m["status"] == "ran" and m["unknown_total"] == 2 and m["unknown"][0]["closest"][0] == "algif_aead"
    assert m["kernels"][0]["version"] == KVER and m["kernels"][0]["loadable"] == 6 and m["references"] >= 12
    assert st == "ATTENTION" and "腳本裡映像沒有的模組名稱 2" in detail
    assert next(c for c in res["checks"] if c["id"] == "modules")["result"] == "1 medium, 1 low"
    assert "algif_head" in md and "## Kernel module names in scripts" in md
    # 不輸出檔案內容：只有路徑、行號、名稱
    assert CONTENT_MARK not in json.dumps(res) and CONTENT_MARK not in md and "WARNING!" not in md
    # security_findings：當成 open 的 finding 帶進 CRA 文件
    sec = sf.evaluate(tmp_path / "out" / "image-check.json", None, {}, {})
    g = next(x for x in sec["findings"] if x["id"] == "img:modules:name-not-in-image")
    assert g["state"] == "open" and g["severity"] == "medium" and g["annex"] == ["I-2b", "I-2k"]
    assert any("open findings: high 0, medium 1" in r for r in sec["reasons"])


def test_builtin_and_compressed_names_and_aliases(tmp_path):
    """只在 modules.builtin 的模組、只有 .ko.xz／.ko.gz 檔（沒有 modules.dep）的模組、modprobe 的 alias：都不標。"""
    script = (b'#!/bin/bash\nmodprobe sha256-generic\ngrep -q "^sha256_generic " /proc/modules\nmodprobe xz_mod\n'
              b'modprobe gz-mod\nmodprobe crypto-aes\nmodprobe char-major-10-237\nmodprobe nope_mod\n'
              b'grep -q "^crypto-aes " /proc/modules\n')
    extra = [(f"{MD}/kernel/x/xz_mod.ko.xz", lzma.compress(ET_REL_KO, format=lzma.FORMAT_XZ)),
             (f"{MD}/kernel/x/gz_mod.ko.gz", gzip.compress(ET_REL_KO)),
             (f"{MD}/modules.alias", b"alias crypto-aes aes_generic\nalias char-major-10-* misc_thing\nalias pci:v*d* r8152\n"),
             ("./usr/local/sbin/setup.sh", script, 0o755)]
    src = write_tar(tmp_path / "rootfs.tar", base(dep=False) + extra)
    st, detail, res, md = run(tmp_path, src)
    m = mods(res)
    assert m["status"] == "ran" and "modules.builtin" in m["kernels"][0]["lists"]
    names = sorted(r["name"] for r in m["unknown"])
    # alias 只對 modprobe 有效：/proc/modules 只有真正的名稱
    assert names == ["crypto-aes", "nope_mod"], names
    assert {r["context"] for r in m["unknown"]} == {"modprobe", "grep of /proc/modules"}


def test_no_module_dir_is_not_run(tmp_path):
    src = write_tar(tmp_path / "rootfs.tar", base(mods=False) + [("./usr/local/bin/c.sh", COPYFAIL, 0o755)])
    st, detail, res, md = run(tmp_path, src)
    m = mods(res)
    assert m["status"] == "not run" and m["references"] == 1 and not [f for f in res["findings"] if f["check"] == "modules"]
    assert next(c for c in res["checks"] if c["id"] == "modules")["result"].startswith("NOT RUN")
    # 有引用卻沒辦法比對：記不完整（不是 OK）
    assert st == "ATTENTION" and any("not checked (no module lists" in k for k in res["coverage"]["counts"])
    assert "沒執行" in detail and "Not run:" in md
    # 沒有模組也沒有引用：NOT RUN，但不算不完整
    src = write_tar(tmp_path / "plain.tar", base(mods=False))
    st, detail, res, md = run(tmp_path / "b", src)
    assert mods(res)["status"] == "not run" and st == "OK" and not res["coverage"]["counts"]
    assert next(c for c in res["checks"] if c["id"] == "modules")["result"].startswith("NOT RUN")


def test_modprobe_d_blacklist_typo_is_medium(tmp_path):
    conf = (b"# blacklist commented_out\nblacklist algif_heed\ninstall algif_aed /bin/false\nblacklist algif_aead\n"
            b"install algif_hash /bin/true\noptions nosuch_mod x=1\ninstall pseudo_mod /sbin/modprobe --ignore-install r8152\n"
            b"install \\\n  algif_rgn /bin/false\nblacklist zzqx_nothing\n")
    pkg = b"blacklist ath_pci\nblacklist r8152\n"
    src = write_tar(tmp_path / "rootfs.tar", base() + [
        ("./etc/modprobe.d/vendor-mitigation.conf", conf), ("./etc/modprobe.d/blacklist-ath_pci.conf", pkg),
        ("./var/lib/dpkg/info/kmod.list", b"/etc/modprobe.d/blacklist-ath_pci.conf\n")])
    st, detail, res, md = run(tmp_path, src)
    f = fids(res)
    # 廠商的 blacklist／install … /bin/false 打錯字：緩解措施擋不到真正的模組 → medium
    b = f["modules:blacklist-not-in-image"]
    assert b["severity"] == "medium" and set(b["annex"]) == {"I-2b", "I-2j", "I-2k"}
    assert [e.split(" (")[0] for e in b["evidence"]] == ["/etc/modprobe.d/vendor-mitigation.conf:2 algif_heed",
                                                         "/etc/modprobe.d/vendor-mitigation.conf:3 algif_aed",
                                                         "/etc/modprobe.d/vendor-mitigation.conf:8 algif_rgn"]
    assert "closest existing: algif_aead" in b["evidence"][0] and "modprobe.d install (disabled)" in b["evidence"][1]
    # 沒有相近名稱：這個核心沒有這個模組 → info
    nb = f["modules:blacklist-module-not-built"]
    assert nb["severity"] == "info" and nb["evidence"] == [
        "/etc/modprobe.d/vendor-mitigation.conf:10 zzqx_nothing (modprobe.d blacklist; closest existing: none)"]
    assert "no risk" in nb["text"]
    p = f["modules:blacklist-not-in-image-packages"]
    assert p["severity"] == "info" and p["evidence_total"] == 1 and "ath_pci" in p["evidence"][0]
    assert "modules:name-not-in-image" not in f
    assert st == "ATTENTION"
    # 只有沒有相近名稱的（這個核心沒有這個模組）：info，不是 ATTENTION（但項目照樣列出）
    src = write_tar(tmp_path / "nb.tar", base() + [("./etc/modprobe.d/x.conf", b"blacklist zzqx_nothing\n")])
    st, detail, res, md = run(tmp_path / "nb", src)
    assert fids(res)["modules:blacklist-module-not-built"]["severity"] == "info" and st == "OK"


def test_noise_is_not_flagged(tmp_path):
    noisy = (b'#!/bin/bash\n'
             b'# modprobe typo_in_comment\n'
             b'echo "modprobe typo_in_echo"\n'
             b"printf 'lsmod | grep typo_in_printf\\n'\n"
             b'logger "rmmod typo_in_logger"\n'
             b'cat <<EOF > /tmp/x.sh\nmodprobe typo_in_heredoc\nEOF\n'
             b'cat <<-\'END\'\n\tmodprobe typo_in_heredoc2\n\tEND\n'
             b'echo "first line\nmodprobe typo_in_multiline_string\nlast"\n'
             b'MOD=typo_in_var; modprobe $MOD; modprobe "${MOD}"\n'
             b'grep -q "typo.regex" /proc/modules\n'
             b'grep -q typo_other_file /etc/some.conf\n'
             b'lsmod | awk \'{print $1}\' | grep -v typo_inverted\n'
             b'grep -qv "^typo_inverted2 " /proc/modules\n'
             b'modprobe -c | grep typo_after_showconfig\n'
             b'modprobe -S 5.15.0 typo_other_kernel\n'
             b'x=1 # trailing comment modprobe typo_trailing\n'
             b'helper() { echo "$1"; }\nhelper "typo_helper_arg"\n'
             b'grep -q "^algif_aead " /proc/modules # modprobe typo_after_code\n')
    py = b'#!/usr/bin/python3\nimport os\nos.system("modprobe typo_in_python")\n'
    src = write_tar(tmp_path / "rootfs.tar", base() + [("./usr/local/bin/noisy.sh", noisy, 0o755),
                                                      ("./usr/bin/pytool", py, 0o755),
                                                      ("./etc/notes.txt", b"modprobe typo_in_plain_text\n")])
    st, detail, res, md = run(tmp_path, src)
    m = mods(res)
    assert m["status"] == "ran" and m["unknown_total"] == 0, m["unknown"]
    assert not [f for f in res["findings"] if f["check"] == "modules"]


def test_units_modules_load_and_package_scripts(tmp_path):
    unit = b"[Service]\nExecStartPre=-/sbin/modprobe algif_skciper\nExecStart=/bin/sh -c 'modprobe r8152 && lsmod | grep -q \"^r8125 \"'\n"
    pkg_script = b"#!/bin/sh\nmodprobe -r vendorless_driver\nmodprobe algif_hashh\n"
    src = write_tar(tmp_path / "rootfs.tar", base() + [
        ("./etc/systemd/system/mitigate.service", unit),
        ("./etc/modules-load.d/vendor.conf", b"# comment\nalgif_aead\nr8125\n"),
        ("./etc/modules", b"; comment\nr8152\n"),
        ("./usr/sbin/distro-helper", pkg_script, 0o755),
        ("./var/lib/dpkg/info/distro-helper.list", b"/usr/sbin/distro-helper\n")])
    st, detail, res, md = run(tmp_path, src)
    f = fids(res)
    ev = [e.split(" (")[0] for e in f["modules:name-not-in-image"]["evidence"]]
    assert ev == ["/etc/modules-load.d/vendor.conf:3 r8125", "/etc/systemd/system/mitigate.service:2 algif_skciper",
                  "/etc/systemd/system/mitigate.service:3 r8125"], ev
    p = f["modules:module-not-built-packages"]
    assert p["severity"] == "info" and p["evidence"][0].startswith("/usr/sbin/distro-helper:2 vendorless_driver (modprobe -r")
    assert p["evidence"][0].endswith("closest existing: none)")
    t = f["modules:name-not-in-image-packages"]
    assert t["severity"] == "low" and t["evidence"][0].startswith("/usr/sbin/distro-helper:3 algif_hashh (modprobe;")


def test_self_extracting_and_oversized_scripts_real_limits(tmp_path):
    """實際的上限（SCRIPT_MAX 1 MiB，大於 SNIFF；/opt 底下另有 SECRET_MAX）：
    - 1 MiB 以內、腳本後面接 NUL 與二進位資料 → 看 NUL 之前（以前整個檔有 NUL 就默默略過）
    - 2 MiB 的自解壓檔（/opt：也掃私鑰；/usr/local/bin：只為了找模組名稱）→ 看 NUL 之前
    - 1.8 MiB、沒有 NUL 的文字檔、打錯字在最後 → 記不完整（不默默略過）"""
    assert ic.SCRIPT_MAX == 1 << 20 and ic.SCRIPT_MAX > ic.SNIFF
    payload = bytes(range(256)) * 8192                                   # 2 MiB，含 NUL
    small = b"#!/bin/sh\nmodprobe sfx_small_typo\nexit 0\n" + payload[:100_000]
    big = b"#!/bin/sh\nmodprobe sfx_big_typo\nexit 0\n" + payload
    big2 = b"#!/bin/bash\nmodprobe sfx_usr_typo\nexit 0\n" + payload
    huge = b"#!/bin/sh\n" + b": filler line of an oversized script\n" * 50_000 + b"modprobe huge_typo\n"
    assert len(small) < ic.SCRIPT_MAX < len(big) and 1.7 * (1 << 20) < len(huge) < 1.9 * (1 << 20)
    src = write_tar(tmp_path / "rootfs.tar", base() + [
        ("./usr/local/bin/small-installer.sh", small, 0o755), ("./opt/vendor/installer.run", big, 0o755),
        ("./usr/local/bin/installer2.run", big2, 0o755), ("./usr/local/bin/huge.sh", huge, 0o755)])
    st, detail, res, md = run(tmp_path, src)
    m = mods(res)
    assert sorted(r["name"] for r in m["unknown"]) == ["sfx_big_typo", "sfx_small_typo", "sfx_usr_typo"]
    assert res["coverage"]["counts"] == {ic.COV_LABEL["cap_script_file"]: 1} and st == "ATTENTION"
    assert res["coverage"]["examples"][ic.COV_LABEL["cap_script_file"]] == ["usr/local/bin/huge.sh"]


def test_hardlinks_are_bounded(tmp_path):
    """2000 個硬連結指到同一個 50 個引用的腳本：引用總數不超過 MODREF_MAX、記不完整，而且不是平方時間。"""
    script = b"#!/bin/sh\n" + b"".join(b"modprobe hl_typo_%02d\n" % i for i in range(50))
    links = [(f"./usr/local/bin/hl/l{i:04d}", ("lnk", "./usr/local/bin/hl.sh")) for i in range(2000)]
    src = write_tar(tmp_path / "rootfs.tar", base() + [("./usr/local/bin/hl.sh", script, 0o755)] + links)
    t0 = time.monotonic()
    st, detail, res, md = run(tmp_path, src)
    elapsed = time.monotonic() - t0
    m = mods(res)
    assert m["references"] <= ic.MODREF_MAX and m["references"] == (ic.MODREF_MAX // 50) * 50
    assert res["coverage"]["counts"][ic.COV_LABEL["cap_modrefs"]] == 2001 - ic.MODREF_MAX // 50
    assert st == "ATTENTION" and elapsed < 60, elapsed


def test_separate_lib_and_usr_lib_module_dirs(tmp_path):
    """/lib/modules/V 與 /usr/lib/modules/V 是兩個各自存在的資料夾（L4T）：兩邊合在一起，不互相覆蓋。"""
    members = [m for m in base() if m[0] != "./lib"] + [
        (f"./lib/modules/{KVER}/modules.builtin", b"kernel/crypto/only_builtin_x.ko\n"),
        (f"./lib/modules/{KVER}/extra/oot_only_lib.ko", ET_REL_KO),
        ("./usr/local/bin/m.sh", b"#!/bin/sh\nmodprobe only_builtin_x\nmodprobe algif_aead\nmodprobe oot_only_lib\n"
                                 b"modprobe really_missing_q\n", 0o755)]
    st, detail, res, md = run(tmp_path, write_tar(tmp_path / "rootfs.tar", members))
    m = mods(res)
    assert [r["name"] for r in m["unknown"]] == ["really_missing_q"]
    assert len(m["kernels"]) == 1 and m["kernels"][0]["dirs"] == [f"/lib/modules/{KVER}", f"/usr/lib/modules/{KVER}"]


def test_function_needs_a_real_probe(tmp_path):
    """函式裡只是提到 lsmod（寫到檔案、echo、註解）不算 /proc/modules 的檢查：不產生引用。"""
    script = (b'#!/bin/sh\n'
              b'dump() { lsmod > "$1"; }\ndump logfile\n'
              b'usage(){ echo "see lsmod for $1"; }\nusage typo_usage_arg\n'
              b'commented() {\n    # grep -q "^$1 " /proc/modules\n    echo "$1"\n}\ncommented typo_commented_arg\n'
              b'real() { grep -q "^$1 " /proc/modules; }\nreal typo_real_arg\n')
    st, detail, res, md = run(tmp_path, write_tar(tmp_path / "rootfs.tar", base() + [("./usr/local/bin/f.sh", script, 0o755)]))
    assert [(r["name"], r["line"]) for r in mods(res)["unknown"]] == [("typo_real_arg", 12)]


def test_heredoc_marker_in_string_or_arithmetic_does_not_hide_the_rest(tmp_path):
    script = (b'#!/bin/bash\n'
              b'echo "use <<EOF here"\nmodprobe typo_after_string\n'
              b'x=$((1<<2))\nmodprobe typo_after_arith\n'
              b'y=$(( 1 << 3 ))\nmodprobe typo_after_arith2\n'
              b'cat <<END\nmodprobe typo_inside_heredoc\nEND\nmodprobe typo_after_heredoc\n')
    st, detail, res, md = run(tmp_path, write_tar(tmp_path / "rootfs.tar", base() + [("./usr/local/bin/h.sh", script, 0o755)]))
    assert [r["name"] for r in mods(res)["unknown"]] == ["typo_after_string", "typo_after_arith", "typo_after_arith2",
                                                        "typo_after_heredoc"]


def test_quoted_substitution_prefixes_and_modprobe_d_alias(tmp_path):
    script = (b'#!/bin/bash\n'
              b'if [ -n "$(lsmod | grep "^typo_quoted ")" ]; then :; fi\n'
              b'n="`grep -c typo_backtick /proc/modules`"\n'
              b"echo '$(lsmod | grep typo_single_quoted)'\n"
              b'sudo -u root modprobe typo_sudo_u\n'
              b'sudo -n -E modprobe typo_sudo_flags\n'
              b'timeout 5 modprobe typo_timeout\n'
              b'timeout -s KILL 5s modprobe typo_timeout2\n'
              b'nice -n 5 modprobe typo_nice\n'
              b'env -u FOO X=1 modprobe typo_env\n'
              b'modprobe myalias\n'
              b'grep -q "^myalias " /proc/modules\n')
    src = write_tar(tmp_path / "rootfs.tar", base() + [("./usr/local/bin/q.sh", script, 0o755),
                                                      ("./etc/modprobe.d/alias.conf", b"alias myalias algif_aead\n")])
    st, detail, res, md = run(tmp_path, src)
    m = mods(res)
    assert [r["name"] for r in m["unknown"]] == ["typo_quoted", "typo_backtick", "typo_sudo_u", "typo_sudo_flags", "typo_timeout",
                                                 "typo_timeout2", "typo_nice", "typo_env", "myalias"]
    assert m["unknown"][-1]["context"] == "grep of /proc/modules" and m["modprobe_d_aliases"] == 1
    assert "Not supported" in m["method"]


def test_only_elf_relocatable_ko_files_are_modules(tmp_path):
    """名稱是 .ko 的檔要是 ELF ET_REL 才算模組（和 kernel_modules.py 一樣）：vim 的 tutor.ko、ELF 執行檔不算。"""
    script = (b"#!/bin/sh\nmodprobe tutor\ninsmod /opt/vendor/drv/oot_ok.ko\ninsmod /opt/vendor/drv/notrel.ko\n"
              b"insmod /opt/vendor/drv/gz_ok.ko.gz\n")
    src = write_tar(tmp_path / "rootfs.tar", base() + [
        ("./usr/share/vim/vim91/tutor/tutor.ko", "===== Vim 튜토리얼 =====\n".encode()),
        ("./opt/vendor/drv/oot_ok.ko", ET_REL_KO), ("./opt/vendor/drv/notrel.ko", elf(etype=2)),
        ("./opt/vendor/drv/gz_ok.ko.gz", gzip.compress(ET_REL_KO)),
        ("./usr/local/bin/k.sh", script, 0o755)])
    st, detail, res, md = run(tmp_path, src)
    m = mods(res)
    assert [r["name"] for r in m["unknown"]] == ["tutor", "notrel"] and m["ko_not_modules"] == 2
    # 判斷不了的（zstd，沒有解壓器）照樣算模組：base() 的 .ko.zst
    assert "algif_aead" not in [r["name"] for r in m["unknown"]]


def test_directory_source_and_hardlink(tmp_path):
    """資料夾來源（lstat 走訪）一樣找得到；硬連結的另一個名稱也列出。"""
    import tarfile
    src = write_tar(tmp_path / "rootfs.tar", base() + [("./usr/local/bin/check.sh", COPYFAIL, 0o755),
                                                      ("./usr/local/sbin/check-link", ("lnk", "./usr/local/bin/check.sh"))])
    st, detail, res, md = run(tmp_path, src)
    ev = fids(res)["modules:name-not-in-image"]["evidence"]
    assert [e.split(" ")[0] for e in ev] == ["/usr/local/bin/check.sh:9", "/usr/local/sbin/check-link:9"]
    d = tmp_path / "rootfs"
    d.mkdir()
    with tarfile.open(src) as t:
        t.extractall(d, filter="tar")
    st, detail, res, md = run(tmp_path / "b", d)
    assert [r["path"] for r in mods(res)["unknown"]] == ["/usr/local/bin/check.sh", "/usr/local/sbin/check-link"]


def test_grep_pattern_forms():
    gp = ic.grep_pattern
    assert gp("^algif_aead ", set()) == [("algif_aead", "exact")]
    assert gp("^algif_aead", set()) == [("algif_aead", "prefix")]
    assert gp("algif_aead ", set()) == [("algif_aead", "suffix")]
    assert gp("algif_aead", set()) == [("algif_aead", "substring")]
    assert gp("algif_aead", {"w"}) == [("algif_aead", "exact")]
    assert gp("^algif_aead[[:space:]]", set()) == [("algif_aead", "exact")]
    assert gp("^algif_aead\\s+", {"E"}) == [("algif_aead", "exact")]
    assert gp("^(esp4|esp6) ", {"E"}) == [("esp4", "exact"), ("esp6", "exact")]
    assert gp("^esp4 \\|^esp6 ", set()) == [("esp4", "exact"), ("esp6", "exact")]
    assert gp("^esp4 |^esp6 ", set()) is None            # BRE：| 是字面
    assert gp("algif.aead", set()) is None and gp("^algif_[a-z]+ ", {"E"}) is None and gp("^$m ", set()) is None
    assert gp("algif_aead ", {"F"}) == [("algif_aead", "suffix")]
