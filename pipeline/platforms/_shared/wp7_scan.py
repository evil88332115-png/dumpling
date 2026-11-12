#!/usr/bin/env python3
"""WP7 平台（raspberrypi、rockchip、ai-nas）scan 步驟的 Python 部分（`_shared/scan-disk.sh` 呼叫；一律 `python3 -I`）。

共用的收集邏輯在 pipeline/lib/platform_scan.py（C1）；這裡只放 WP7 平台特有的 Hooks 與幾個小工具：
  site-config  寫精靈的站台設定（沒有上游基準檔：官方映像原樣使用，upstream 是空的）
  newest       精靈剛產生的輸出資料夾
  services     標好層的 SBOM 裡要特別注意的對外連線服務（D-027：rpi-connect* 歸 os，但報告要標出來）
  collect      platform_scan.collect ＋ WP7 的欄位（映像、原始磁區、OMV 原始碼、對外連線服務、開機程式涵蓋）
缺的項目記 null，不推測（標準答案比對會因此失敗而不是通過）。
"""
import argparse
import fnmatch
import json
import os
import shutil
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "lib"))
import platform_scan as ps  # noqa: E402

# 對外連線服務（D-027）：分層照名稱清單（不影響待辦歸誰），但報告要標成要特別注意的項目。
EXTERNAL_SERVICES = (("rpi-connect*", "Raspberry Pi Connect（官方遠端連線服務：裝置主動連到 Raspberry Pi 的雲端服務）"),)


def services(sbom_path):
    doc = ps.read_json(sbom_path)
    if not isinstance(doc, dict):
        return None
    hits = []
    for c in doc.get("components") or []:
        name = str(c.get("name") or "")
        for pat, why in EXTERNAL_SERVICES:
            if fnmatch.fnmatchcase(name, pat):
                layer = next((p.get("value") for p in c.get("properties") or [] if p.get("name") == ps.LAYER_PROP), None)
                hits.append({"name": name, "version": c.get("version"), "layer": layer, "why": why})
    return sorted(hits, key=lambda h: (h["name"], str(h["version"])))


class Wp7Hooks(ps.Hooks):
    def __init__(self, extras):
        self.x = extras

    def run_summary_fields(self, paths, status):
        bc = ps.read_json(os.path.join(paths["rootfs"], "bootloader-coverage.json"), {}) or {}
        return {"bootloader_coverage": bc.get("status") if isinstance(bc, dict) else None,
                "stage_bootloader_coverage": status.get("B-bootloader-coverage", {}).get("status")}

    def scan_head(self, ctx):
        asm = ctx["asm"] or {}
        return {"image": {"file": asm.get("image_file"), "sha256": asm.get("image_sha256"), "disk_sha256": asm.get("disk_sha256"),
                          "disk_bytes": asm.get("disk_bytes")}}

    def scan_mid(self, ctx):
        rs = self.x.get("raw_sectors")
        out = {"external_services": self.x.get("services")}
        if rs is not None:
            out["raw_sectors"] = {"status": rs.get("status"), "gaps": rs.get("gaps"),
                                  "regions": [{"slot": r.get("slot"), "start_lba": r.get("start_lba"), "sha256": r.get("sha256"),
                                               "kind": (r.get("identity") or {}).get("kind"),
                                               "versions": (r.get("identity") or {}).get("versions"),
                                               "corroboration": [c.get("state") for c in r.get("corroboration") or []]}
                                              for r in rs.get("regions") or []]}
        if self.x.get("source"):
            out["app_source"] = self.x["source"]
        if self.x.get("kernel_source") is not None:
            out["kernel_source"] = self.x["kernel_source"]
        return out

    def scan_tail(self, ctx):
        return {"bootloader_coverage": ctx["main_run"].get("bootloader_coverage")}

    def extra_attachments(self, ctx, manifest):
        out = ctx["out"]
        for src, name, label in ((self.x.get("raw_sectors_path"), "raw-sectors-%s-%s.json", "原始磁區清點（開機程式，以磁區為準）"),
                                 (self.x.get("assemble_path"), "assemble-%s-%s.json", "映像來源與解開方式")):
            if src and os.path.isfile(src):
                dst = name % (ctx["project"], ctx["version"])
                shutil.copy2(src, os.path.join(out, dst))
                ps.add(manifest, out, dst, label)

    def notes_build(self, ctx):
        asm = ctx["asm"] or {}
        L = ["## 映像", "",
             "- 官方映像 `%s`（sha256 `%s`，sources.yml 固定）；%s；解開後 sha256 `%s`。不編譯、不重組，只解開不執行。" % (
                 asm.get("image_file"), asm.get("image_sha256"), asm.get("method"), asm.get("disk_sha256"))]
        rs = self.x.get("raw_sectors")
        if rs is not None:
            L += ["", "## 開機程式（分割區之前的原始磁區）", "",
                  "以原始磁區為準；套件只當佐證，不拿套件版本推磁區版本（D-027）。狀態 **%s**。" % rs.get("status"), ""]
            for r in rs.get("regions") or []:
                vs = "、".join("%s %s" % (v.get("component"), v.get("version")) for v in (r.get("identity") or {}).get("versions") or []) or "讀不到版本"
                cs = "、".join("%s：%s" % (c.get("source"), c.get("state")) for c in r.get("corroboration") or [])
                L.append("- LBA %s（%s）：%s；佐證 %s" % (r.get("start_lba"), r.get("slot") or "未知", vs, cs))
            for g in rs.get("gaps") or []:
                L.append("- GAP：%s" % g)
            L.append("- 閉源成品（DDR 初始化、TF-A BL31）沒有可機器比對的安全公告：GAP。U-Boot 給上游 CPE，比對結果是候選、進待人審（D-034）。")
        ks = self.x.get("kernel_source")
        if ks is not None:
            L += ["", "## 核心原始碼（D-035）", "",
                  "- 狀態 **%s**：%s；Debian 版本 `%s`，映像裡核心套件的版本 `%s`。" % (
                      ks["status"], ks["basis"], ks.get("debian_version"), "、".join(ks.get("image_versions") or []) or "沒有找到"),
                  "- OS 層的套件比對以 Grype 的 Debian 發行版資料為準（已考慮 Debian 的修補）；原始碼判斷只是佐證。"]
            if ks.get("reason"):
                L.append("- 原因：%s" % ks["reason"])
        src = self.x.get("source")
        if src:
            L += ["", "## NAS 應用的原始碼", "",
                  "- `%s` commit `%s`：%s；元件帶 `dumpling:origin=source` 與 commit。原始碼與正式 deb 是否完全相同：**NOT_ASSESSED**（D-025）。" % (
                      src.get("repo"), src.get("commit"), src.get("line"))]
        sv = self.x.get("services")
        if sv:
            L += ["", "## 要特別注意的對外連線服務", ""]
            L += ["- `%s` %s（層 %s）：%s" % (h["name"], h["version"], h["layer"], h["why"]) for h in sv]
        elif sv is not None:
            L += ["", "## 要特別注意的對外連線服務", "", "- 清單裡的服務（%s）都不在 SBOM 裡。" % "、".join(p for p, _ in EXTERNAL_SERVICES)]
        return L

    def notes_attachments(self, ctx):
        L = ["- `scan-summary-*.json`：標準答案比對用的掃描摘要；`assemble-*.json`：映像來源與解開方式。"]
        if self.x.get("raw_sectors") is not None:
            L.append("- `raw-sectors-*.json`：分割區之前的原始磁區清點（區段的 sha256、身分、版本、佐證結果）。")
        return L


DEB_KERNEL_RE = __import__("re").compile(r"^linux-image-[0-9][^ ]*\+deb[0-9]+-[a-z0-9-]+$")


def kernel_source(ks_path, sbom_path):
    """kernel-source.json ＋ 映像 SBOM 裡 Debian 核心套件的版本 → 核心原始碼判斷的狀態（D-035）。
    OK：套好 Debian 修補、版本與映像的套件相同；PARTIAL：只有上游（修補沒套上）；GAP：版本對不上或映像裡找不到核心套件。"""
    ks = ps.read_json(ks_path)
    if not isinstance(ks, dict):
        return {"status": "GAP", "basis": None, "reason": "kernel-source.json 讀不了"}
    doc = ps.read_json(sbom_path) or {}
    vers = sorted({str(c.get("version")) for c in doc.get("components") or [] if DEB_KERNEL_RE.match(str(c.get("name") or ""))})
    out = {"basis": ks.get("basis"), "debian_version": ks.get("debian_version"), "patches_applied": ks.get("patches_applied"),
           "patches_total": ks.get("patches_total"), "image_versions": vers, "reason": ks.get("reason")}
    if ks.get("status") != "OK":
        out["status"] = "PARTIAL"
    elif not vers:
        out.update(status="GAP", reason="映像的 SBOM 裡找不到 Debian 核心套件（linux-image-*+debN-*），沒辦法核對原始碼版本")
    elif vers != [ks.get("debian_version")]:
        out.update(status="GAP", reason="原始碼版本 %s 與映像裡核心套件的版本 %s 不同" % (ks.get("debian_version"), "、".join(vers)))
    else:
        out["status"] = "OK"
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("site-config")
    for k in ("out", "repo", "root", "outroot", "pilot-env", "grype-cache", "python"):
        s.add_argument("--" + k, required=True)
    n = sub.add_parser("newest")
    n.add_argument("--root", required=True)
    n.add_argument("--prefix", required=True)
    v = sub.add_parser("services")
    v.add_argument("sbom")
    c = sub.add_parser("collect")
    for k in ("out", "project", "version", "layers", "assemble-json", "scan-json"):
        c.add_argument("--" + k, required=True)
    c.add_argument("--run", action="append", required=True, help="<名稱後綴>=<精靈輸出資料夾>（完整掃描的後綴是空字串）")
    c.add_argument("--raw-sectors", default=None)
    c.add_argument("--source-json", default=None, help="OMV 原始碼合併的摘要（repo、commit、line）")
    c.add_argument("--kernel-source-json", default=None, help="assemble 的 kernel-source.json（Debian 核心原始碼，D-035）")
    c.add_argument("--official", action="store_true")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "site-config":
            ps.site_config(a.out, a.repo, a.root, a.outroot, a.pilot_env, a.grype_cache, {}, a.python)
            print("wp7_scan: OK（站台設定）")
        elif a.cmd == "newest":
            d = ps.newest_dir(a.root, a.prefix)
            if not d:
                raise ValueError("精靈沒有產生 %s* 資料夾" % a.prefix)
            print(d)
        elif a.cmd == "services":
            print(json.dumps(services(a.sbom), ensure_ascii=False))
        else:
            a.build_json = None
            x = {"assemble_path": a.assemble_json,
                 "raw_sectors": ps.read_json(a.raw_sectors) if a.raw_sectors else None, "raw_sectors_path": a.raw_sectors,
                 "source": ps.read_json(a.source_json) if a.source_json else None,
                 "services": services(os.path.join(a.layers, "sbom.product.cdx.json")),
                 "kernel_source": kernel_source(a.kernel_source_json, os.path.join(a.layers, "sbom.product.cdx.json"))
                 if a.kernel_source_json else None}
            ps.collect(a, Wp7Hooks(x))
            print("wp7_scan: OK（附件）")
    except (OSError, ValueError) as e:
        print("wp7_scan: FAIL（%s: %s）" % (type(e).__name__, getattr(e, "strerror", None) or str(e)[:200]))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
