#!/usr/bin/env python3
"""dtsources.py：彙整 DT 5.2.0 弱點與 KEV 資料源最近一次 mirror 的狀態，寫成 data-sources.json，並印兩行 status：
  D-dt-data-sources<TAB>狀態<TAB>說明   （NVD、OSV：任一個不是 COMPLETED → GAP）
  D-dt-kev-sources<TAB>狀態<TAB>說明    （CISA、ENISA KEV：任一個不是 COMPLETED → GAP，只影響 KEV 標記；
                                         有 --enisa-config 時另判 DT 的 ENISA KEV 讀哪一份檔、那份檔是否最新，見下）

  D-dt-osv-coverage<TAB>狀態<TAB>說明   （有 --osv-config 與 --sbom 時：SBOM 的 purl 類型對應的 OSV 生態系沒有啟用 → GAP）

用法：python3 -I dtsources.py <輸出 data-sources.json> [--osv-config http碼:回應檔] [--sbom SBOM]
                               [--nvd-mirror 模式|modified] [--nvd-max-age-days 天數]
                               [--enisa-config http碼:回應檔] [--euvd-kev EUVD 鏡像資料夾] <類別:名稱:http碼:回應檔>...
  類別為 vuln 或 kev，例：vuln:nvd:200:/tmp/w/mirror-vuln-nvd.json
  --nvd-mirror：pilot.env 的 PILOT_NVD_MIRROR 與 NVD_MIRROR_MODIFIED（deploy/pilot/install.sh、status.sh、nvd-mirror.sh 寫入；
    是 NVD 鏡像 modified feed 的 lastModifiedDate）。模式 1（DT 從內部 NVD 鏡像讀）時：
    - modified 超過 NVD_MAX_AGE_DAYS（預設 3，與 dt-feeds.sh --check 相同；--nvd-max-age-days 或環境變數 NVD_MAX_AGE_DAYS 可調）→ D-dt-data-sources GAP；
    - 讀不到 modified（空白或無法解析）→ GAP，寫明「鏡像模式，NVD 新鮮度未知」。
    DT 的 mirror COMPLETED 只表示它讀完了鏡像，鏡像本身過期時資料仍是舊的。模式 0 或沒有提供時不影響判定（DT 直接連 nvd.nist.gov）。

ENISA KEV 的檔（--enisa-config：GET /api/v2/extension-points/kev-data-source/extensions/enisa/config 的回應，{"config": {enabled, feedUrl}}，
  enisa-kev-data-source-config-v1.schema.json；--euvd-kev：EUVD 鏡像資料夾，讀 dt-feeds/kev/euvd/SOURCE.json，tools/mirror/dt-feeds.sh 的 euvdkev 部分）：
  DT 的 ENISA KEV 預設讀 GitHub enisaeu/CNW 的 eukev.json，那份檔 2026-08-13 後沒有更新（2026-11-05 核對：39 個 CVE，同一天 EUVD 的
  EU KEV 有 82 個）。DT 的 mirror COMPLETED 只表示讀完了那份檔，所以：
  - feedUrl 完全等於 EUVD 產生的檔的網址（EUVD_DT_FEED_URL，預設 http://dt-nvd-mirror/kev/euvd/eukev.json；結尾相同的其他網址不算）：
    SOURCE.json 的 fetched_utc 超過 EUVD_MAX_AGE_DAYS（預設 3）天、kev/dump 最新 dateAdded 超過 EUVD_KEV_MAX_AGE_DAYS（預設 14）天、
    或掃描端讀不到 SOURCE.json → GAP（說明照樣列出下面兩種 CVE）；有條目因為沒有可用的日期沒寫進 DT 的檔（skipped_no_date）→ ATTENTION，點名 CVE
    （不補日期）；EUVD 標已遭利用而 DT 的 CISA KEV ∪ 這份檔都沒有的 CVE（euvd_not_in_dt，例如 CISA 已移除的）是來源之間的不一致、不是缺資料：
    狀態不變，只在說明以 NOTE 列出（風險評估不因此變 GAP；報告端讀 EUVD，逐筆列為 P1，#159）；
    沒有和 CISA KEV 比對（SOURCE.json 的 euvd_not_in_dt 是 null：cisa-kev.json 沒有下載或無法解析、或舊的 SOURCE.json）→ ATTENTION，
    說明寫出 cisa_problem（比對被跳過，「DT 沒有的 CVE」未知，不能顯示 OK）；
    euvd_not_in_dt 比對的是 euvd-mirror.sh（dt-feeds.sh 的 euvdkev 部分）下載的 CISA 檔，不是 DT 的 CISA 來源實際讀的那一份
    （DT 每天 02:00 UTC 直接讀 www.cisa.gov，euvd-mirror.sh update 在每日排程另抓一次），兩份通常差不到一天、更新失敗時可差幾天，說明裡會註明；
    新舊以掃描端的 EUVD 鏡像判斷（和 DT 讀的同一份 current 每日同步），不是 DT 實際讀到的那份（未核對 DT 讀的時間點）；
  - 其他網址（上游 eukev.json 等）：SOURCE.json 記的上游檔就是這個網址、而且 EUVD 的 EU KEV 沒有它缺的 CVE、SOURCE.json 也沒過期時 OK，
    其他一律 GAP（上游沒有發布日期，無法確認是最新）；
  - 讀不到設定（金鑰沒有 SYSTEM_CONFIGURATION_READ 等）或 ENISA 關閉 → GAP。

出處（DT 5.2.0 原始碼，tag 5.2.0）：
- api/src/main/openapi/openapi.yaml：/api/v2/vuln-data-sources/{name}/mirror-runs/latest、/api/v2/kev-data-sources/{name}/mirror-runs/latest
- resources/vuln-data-sources/vuln-data-source-mirror-run-latest.yaml：需 SYSTEM_CONFIGURATION 或 SYSTEM_CONFIGURATION_READ；
  沒有 mirror 紀錄（尚未觸發、已不保留）或資料源名稱不存在時回 404。
- schemas/vuln-data-source-mirror-status.yaml：status（PENDING、RUNNING、COMPLETED、FAILED，必填）、started_at、completed_at（epoch 毫秒）、failure_reason。
判定只看「最近一次」：最近一次是 RUNNING（例如例行更新）時，前一次的資料可能仍在，但這支 API 看不出來，所以仍記 GAP（未核對）。
GitHub（GHSA）依設計關閉（CLAUDE.md 修正 2），不檢查；EPSS 在 DT 5.2.0 沒有 mirror 狀態 API（未核對），不列入。

OSV 生態系涵蓋（出處：DT 5.2.0 api/src/main/openapi/openapi.yaml /extension-points/{extension_point_name}/extensions/{extension_name}/config，
GET 需 SYSTEM_CONFIGURATION 或 SYSTEM_CONFIGURATION_READ，回應 {"config": {...}}；擴充點名稱 vuln-data-source（VulnDataSource.java
@ExtensionPointSpec）；OSV 設定 vuln-data-source/osv/.../osv-vuln-data-source-config-v1.schema.json 的 enabled、ecosystems）：
示範掃描的 DT 只啟用 PyPI、npm、Go、Maven、crates.io、Packagist、RubyGems、NuGet，映像的 177 個 deb 套件在 DT 沒有 OSV 資料，
DT 0 筆、Grype 942 筆，報告上只是並列、沒有標示。purl 類型與 OSV 生態系的對應是本檔自訂（OSV schema 的 defined ecosystems），
DT 是否真的以 distro 限定詞比對 Debian 等發行版的 OSV 資料未驗證（未核對）；pkg:generic 等沒有 OSV 生態系的類型只能靠 NVD（CPE）。
"""
import datetime
import json
import math
import os
import sys

LABEL = {"nvd": "NVD", "osv": "OSV", "cisa": "CISA KEV", "enisa": "ENISA KEV"}
EUVD_FEED_URL = "http://dt-nvd-mirror/kev/euvd/eukev.json"   # deploy/pilot 的 dt-nvd-mirror；其他部署以環境變數 EUVD_DT_FEED_URL 指定
UPSTREAM_ENISA = "https://raw.githubusercontent.com/enisaeu/CNW/main/advisories/eukev/eukev.json"   # EnisaKevDataSourceFactory 的預設
REQUIRED = {"vuln": ("nvd", "osv"), "kev": ("cisa", "enisa")}
# euvd_not_in_dt 的 CISA 檔：euvd-mirror.sh 另抓的那一份，不是 DT 的 CISA 來源實際讀的（下載時間通常差不到一天，更新失敗時可差幾天）
CISA_COPY_NOTE = ("這份清單以 euvd-mirror 下載的 CISA KEV 比對，不是 DT 的 CISA 來源實際讀的那一份（DT 每天 02:00 UTC 讀 www.cisa.gov，"
                  "兩者通常差不到一天，每日更新失敗時最多可差 EUVD_MAX_AGE_DAYS 天：這段期間 CISA 新增或移除的 CVE 可能多列或漏列）")


def ts(ms):
    if not isinstance(ms, (int, float)):
        return None
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_one(kind, name, code, path):
    row = {"kind": kind, "name": name, "label": LABEL.get(name, name), "http": code,
           "status": None, "started_at": None, "completed_at": None, "failure_reason": None, "problem": None}
    if code == "200":
        try:
            d = json.load(open(path, encoding="utf-8"))
            row["status"] = d.get("status")
            row["started_at"], row["completed_at"] = ts(d.get("started_at")), ts(d.get("completed_at"))
            row["failure_reason"] = d.get("failure_reason")
            if not row["status"]:
                row["problem"] = "回應沒有 status 欄位"
        except (OSError, ValueError, AttributeError) as e:
            row["problem"] = f"回應無法解析（{type(e).__name__}）"
    elif code == "404":
        row["problem"] = "沒有 mirror 紀錄（尚未執行或資料源未啟用）"
    elif code in ("401", "403"):
        row["problem"] = f"http={code}：金鑰沒有 SYSTEM_CONFIGURATION_READ，無法得知資料源狀態"
    else:
        row["problem"] = f"http={code}：讀不到資料源狀態"
    row["complete"] = row["status"] == "COMPLETED"
    return row


def describe(r):
    if r["status"]:
        s = f"{r['label']} {r['status']}"
        if r["completed_at"]:
            s += f"（完成 {r['completed_at']}）"
        elif r["started_at"]:
            s += f"（開始 {r['started_at']}）"
        if r["failure_reason"]:
            s += f"：{str(r['failure_reason'])[:200]}"
        return s
    return f"{r['label']}：{r['problem']}"


def nvd_mirror_info(spec, max_age, now=None):
    """spec＝「模式|modified」（None 表示沒有提供）。回傳 dict：mode、modified、age_days、max_age_days、status（OK／GAP／None）、detail。"""
    if spec is None:
        return None
    mode, _, modified = spec.partition("|")
    mode, modified = mode.strip(), modified.strip()
    info = {"mode": mode, "modified": modified or None, "age_days": None, "max_age_days": max_age, "status": None, "detail": None}
    if mode != "1":
        info["detail"] = "NVD：DT 直接連 nvd.nist.gov（沒有使用內部鏡像）"
        return info
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        t = datetime.datetime.fromisoformat(modified.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
        age = (now - t).total_seconds() / 86400
    except (ValueError, AttributeError):
        info["status"] = "GAP"
        info["detail"] = "鏡像模式，NVD 新鮮度未知（pilot.env 沒有可解析的 NVD_MIRROR_MODIFIED）：DT 讀的 NVD 鏡像可能已過期"
        return info
    info["age_days"] = round(age, 1)
    if age > max_age:
        info["status"] = "GAP"
        info["detail"] = (f"NVD 鏡像過期：modified {modified}（{age:.1f} 天 > {max_age} 天）。DT 的 NVD mirror 即使 COMPLETED，"
                          f"讀到的也是舊資料，新的 CVE 可能缺漏")
    else:
        info["status"] = "OK"
        info["detail"] = f"NVD 來自內部鏡像：modified {modified}（{age:.1f} 天前，上限 {max_age} 天）"
    return info


def _age(ts, now):
    try:
        t = datetime.datetime.fromisoformat(str(ts).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=datetime.timezone.utc)
    return (now - t).total_seconds() / 86400


def _env_days(name, default):
    try:
        return float(os.environ.get(name) or default)
    except ValueError:
        return float(default)


def euvd_kev_source(d):
    """EUVD 鏡像（或 dt-feeds 的輸出）裡 euvdkev 的 SOURCE.json → (dict, None) 或 (None, 問題)。"""
    if not d:
        return None, "沒有設定 EUVD 鏡像（PILOT_ENV 的 EUVD_MIRROR）"
    for rel in ("dt-feeds/kev/euvd/SOURCE.json", "kev/euvd/SOURCE.json", "SOURCE.json"):
        p = os.path.join(d, rel)
        if os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as f:
                    doc = json.load(f)
            except (OSError, ValueError) as e:
                return None, f"{p} 無法解析（{type(e).__name__}）"
            if not isinstance(doc, dict) or doc.get("schema") != "sca-dt-enisa-kev/1":
                return None, f"{p} 不是 sca-dt-enisa-kev/1"
            return doc, None
    return None, f"EUVD 鏡像 {d} 沒有 dt-feeds/kev/euvd/SOURCE.json（DT 的 EU KEV 檔沒有產生）"


def enisa_feed_info(code, path, euvd_dir, now=None):
    """DT 的 ENISA KEV 讀哪一份檔、是否最新（模組說明）。回傳 dict：status（OK／ATTENTION／GAP）、detail、feed_url、kind（euvd／upstream／other／None）。"""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    info = {"status": "GAP", "detail": None, "feed_url": None, "kind": None, "enabled": None, "source": None,
            "expected_url": os.environ.get("EUVD_DT_FEED_URL") or EUVD_FEED_URL}
    if code != "200":
        why = "金鑰沒有 SYSTEM_CONFIGURATION_READ" if code in ("401", "403") else f"http={code}"
        info["detail"] = (f"讀不到 DT 的 ENISA KEV 設定（{why}）：不知道 DT 讀哪一份 EU KEV；DT 的 ENISA mirror 顯示 COMPLETED 也不能確認是最新")
        return info
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        info["detail"] = f"DT 的 ENISA KEV 設定無法解析（{type(e).__name__}）"
        return info
    cfg = doc.get("config") if isinstance(doc, dict) else None
    if not isinstance(cfg, dict) or not isinstance(cfg.get("feedUrl", ""), (str, type(None))):
        info["detail"] = f"DT 的 ENISA KEV 設定格式不對（{'config 不是物件' if not isinstance(cfg, dict) else 'feedUrl 不是字串'}）：不知道 DT 讀哪一份 EU KEV"
        return info
    url = str(cfg.get("feedUrl") or "").strip() or UPSTREAM_ENISA
    expected = os.environ.get("EUVD_DT_FEED_URL") or EUVD_FEED_URL
    info.update(feed_url=url, enabled=cfg.get("enabled") is True)
    if cfg.get("enabled") is not True:
        info["detail"] = "DT 的 ENISA KEV 來源沒有啟用：DT 的 isKev 不含 EU KEV"
        return info
    src, problem = euvd_kev_source(euvd_dir)
    max_age, kev_age = _env_days("EUVD_MAX_AGE_DAYS", 3), _env_days("EUVD_KEV_MAX_AGE_DAYS", 14)
    stale = []
    if src:
        info["source"] = {k: src.get(k) for k in ("fetched_utc", "dump_newest_date_added", "entries", "newest_date_reported", "upstream_url",
                                                  "skipped_no_date", "upstream_only_entries", "euvd_not_in_dt")}
        for label, ts, lim in (("EUVD kev/dump 下載於", src.get("fetched_utc"), max_age),
                               ("EUVD kev/dump 最新 dateAdded", src.get("dump_newest_date_added"), kev_age)):
            a = _age(ts, now) if ts else None
            if a is None or a > lim or a < -1:
                stale.append(f"{label} {ts or '（空白）'}" + (f"（{a:.1f} 天，上限 {lim:g} 天）" if a is not None else "（無法解析）"))
    if url == expected:
        info["kind"] = "euvd"
        skipped = [c for c in (src or {}).get("skipped_no_date") or [] if isinstance(c, str)]
        nodt = (src or {}).get("euvd_not_in_dt")
        nodt = [x for x in nodt if isinstance(x, dict) and isinstance(x.get("cve"), str)] if isinstance(nodt, list) else None
        notes = ""
        if skipped:
            notes += (f"；{len(skipped)} 個 EU KEV 條目沒有可用的日期，沒有寫進 DT 的檔（DT 缺日期會整次失敗；不補日期），"
                      f"ENISA 來源不會標（也在 CISA KEV 的仍由 DT 的 CISA 來源標）：{', '.join(skipped[:20])}")
        if nodt:   # 來源之間的不一致，不是缺資料：狀態不變（OK），只在說明列出
            notes += (f"；NOTE：EUVD 標已遭利用、DT 的 CISA KEV 與 ENISA 檔都沒有的 {len(nodt)} 個 CVE（DT 的 isKev 不會標，例如 CISA 已移除）："
                      + ", ".join(f"{x['cve']} ({'/'.join(str(y) for y in x.get('sources') or [])})" for x in nodt[:20])
                      + f"；{CISA_COPY_NOTE}；風險評估讀 EUVD，逐筆列為 P1")
        elif src and nodt is None:   # 比對被跳過：結果未知，不能顯示 OK
            notes += (f"；ATTENTION：沒有和 CISA KEV 比對（{src.get('cisa_problem') or '舊的 SOURCE.json，沒有 euvd_not_in_dt'}），"
                      "EUVD 標已遭利用、DT 的 CISA KEV 與 ENISA 檔都沒有的 CVE 未知（不代表沒有）；下一次 euvd-mirror.sh update 抓到 CISA KEV 後恢復")
        if not src:
            info["detail"] = f"DT 的 ENISA KEV 讀 EUVD 產生的檔（{url}），但新舊未知：{problem}"
        elif stale:
            info["detail"] = f"DT 的 ENISA KEV 讀 EUVD 產生的檔（{url}），但這份檔過期：" + "；".join(stale) + f"。新的 EU KEV 可能缺漏{notes}"
        else:
            info["status"] = "ATTENTION" if skipped or nodt is None else "OK"
            info["detail"] = (f"DT 的 ENISA KEV 讀 EUVD 產生的檔（{url}）：{src.get('entries')} 筆，"
                              f"EUVD kev/dump 下載於 {src.get('fetched_utc')}（以掃描端的 EUVD 鏡像判斷）{notes}")
        return info
    info["kind"] = "upstream" if url == UPSTREAM_ENISA else "other"
    up = (src or {}).get("upstream") if src else None
    if src and not stale and up and src.get("upstream_url") == url and not up.get("missing_from_upstream"):
        info["status"] = "OK"
        info["detail"] = f"DT 的 ENISA KEV 讀 {url}：與 EUVD 的 EU KEV 一致（EUVD kev/dump 下載於 {src.get('fetched_utc')}）"
        return info
    if up and src.get("upstream_url") == url and up.get("missing_from_upstream"):
        why = (f"EUVD 的 EU KEV 有 {len(up['missing_from_upstream'])} 個 CVE 這份檔沒有（EUVD 下載於 {src.get('fetched_utc')}；"
               f"這份檔最新 dateReported {up.get('newest_date_reported') or '?'}）")
    else:
        why = "這份檔沒有發布日期，無法確認是最新（GitHub enisaeu/CNW 的 eukev.json 2026-08-13 後沒有更新，2026-11-05 核對）" \
              + (f"；{problem}" if problem else "") + ("；EUVD 鏡像過期：" + "；".join(stale) if stale else "")
    info["detail"] = (f"DT 的 ENISA KEV 讀 {url}，不是 EUVD 產生的 kev/euvd/eukev.json：{why}。DT 的 isKev 可能漏掉新的 EU KEV，"
                      "DT 顯示 COMPLETED 也只表示讀完了這份檔（改法：deploy/pilot/install.sh 在 PILOT_NVD_MIRROR=1 且有 EUVD 鏡像時改 feedUrl）")
    return info


FEEDS_MAX_HOURS = 26.0   # DT 每天自己排程更新（實測約 02:00–04:00 UTC）；每天一次加約 2 小時餘裕。環境變數 DT_FEEDS_MAX_AGE_HOURS 可改


def feeds_freshness(rows, now=None, max_hours=FEEDS_MAX_HOURS):
    """DT 自己的資料源（NVD、OSV、CISA KEV、ENISA KEV；GitHub 刻意關閉不看）最近一次 mirror 的新鮮度 → (狀態, 說明)。
    OK：四個來源最近一次都是 COMPLETED 且完成時間在 max_hours 小時內。GAP：有來源 FAILED／不是 COMPLETED／過期／沒有紀錄（列出名稱）。
    NOT_RUN：金鑰沒有 SYSTEM_CONFIGURATION_READ（401／403）——無法得知，不是 OK。"""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not (isinstance(max_hours, (int, float)) and math.isfinite(max_hours) and max_hours > 0):
        return "FAIL", f"設定錯誤：DT_FEEDS_MAX_AGE_HOURS（--feeds-max-hours）必須是大於 0 的有限數字（收到 {max_hours!r}）"
    denied = [r["label"] for r in rows if r["http"] in ("401", "403")]
    if denied:
        return "NOT_RUN", f"{'、'.join(denied)}：金鑰沒有 SYSTEM_CONFIGURATION_READ，無法得知 DT 資料源是否新鮮（不代表新鮮）"
    if not rows:
        return "NOT_RUN", "沒有讀到任何 DT 資料源狀態"
    bad, good = [], []
    for r in rows:
        if not r["complete"]:
            bad.append(f"{r['label']} 最近一次 {r['status'] or r['problem']}" + (f"：{str(r['failure_reason'])[:100]}" if r.get("failure_reason") else ""))
            continue
        if not r["completed_at"]:
            bad.append(f"{r['label']} COMPLETED 但沒有完成時間（新鮮度未知）")
            continue
        done = datetime.datetime.strptime(r["completed_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        h = (now - done).total_seconds() / 3600
        if h < -0.1:
            bad.append(f"{r['label']} 完成時間 {r['completed_at']} 在未來（主機時鐘或資料異常）")
            continue
        (bad if h > max_hours else good).append(f"{r['label']} 完成 {r['completed_at']}（{h:.1f} 小時前" + (f"，上限 {max_hours:g} 小時）" if h > max_hours else "）"))
    if bad:
        return "GAP", "；".join(bad) + (f"；其餘正常：{'、'.join(good)}" if good else "")
    return "OK", f"{len(good)} 個 DT 資料源最近一次都 COMPLETED 且在 {max_hours:g} 小時內：" + "；".join(good)


def stage(rows, kind, mirror=None, enisa=None):
    rs = [r for r in rows if r["kind"] == kind]
    missing = [n for n in REQUIRED[kind] if n not in {r["name"] for r in rs}]
    bad = [r for r in rs if not r["complete"]]
    text = "；".join(describe(r) for r in rs)
    if missing:
        text = "；".join(x for x in (text, "沒有查詢：" + "、".join(LABEL[n] for n in missing)) if x)
    if kind == "vuln":
        mnote = f"；{mirror['detail']}" if mirror and mirror.get("detail") else ""
        if bad or missing:
            names = "、".join([r["label"] for r in bad] + [LABEL[n] for n in missing])
            return "GAP", f"弱點資料源不完整（{names}）：DT 的弱點結果只涵蓋已完成的資料源，缺漏不代表沒有弱點。{text}{mnote}"
        if mirror and mirror.get("status") == "GAP":
            return "GAP", f"弱點資料源不完整（NVD 鏡像）：{mirror['detail']}。{text}"
        return "OK", text + "（只表示最近一次 mirror 完成；不代表資料涵蓋所有弱點）" + mnote
    enote = f"；{enisa['detail']}" if enisa and enisa.get("detail") else ""
    if bad or missing:
        names = "、".join([r["label"] for r in bad] + [LABEL[n] for n in missing])
        return "GAP", f"KEV 資料源不完整（{names}）：DT 的 KEV 標記可能缺漏，未標 KEV 不代表不在 KEV 清單。{text}{enote}"
    if enisa and enisa.get("status") == "ATTENTION":
        return "ATTENTION", f"{enisa['detail']}。{text}"
    if enisa and enisa.get("status") != "OK":
        return "GAP", f"KEV 資料源不完整（ENISA KEV 的檔）：{enisa['detail']}。未標 KEV 不代表不在 KEV 清單。{text}"
    return "OK", text + enote


# purl 類型（與 namespace）→ OSV 生態系（https://ossf.github.io/osv-schema/#defined-ecosystems 的名稱；比較時只看「:」前）
PURL_OSV = {"pypi": "PyPI", "npm": "npm", "golang": "Go", "maven": "Maven", "cargo": "crates.io", "composer": "Packagist",
            "gem": "RubyGems", "nuget": "NuGet", "hex": "Hex", "pub": "Pub", "swift": "SwiftURL", "cran": "CRAN", "hackage": "Hackage"}
DISTRO_OSV = {("deb", "debian"): "Debian", ("deb", "ubuntu"): "Ubuntu", ("apk", "alpine"): "Alpine", ("apk", "wolfi"): "Wolfi",
              ("apk", "chainguard"): "Chainguard", ("rpm", "redhat"): "Red Hat", ("rpm", "rocky-linux"): "Rocky Linux",
              ("rpm", "almalinux"): "AlmaLinux", ("rpm", "opensuse"): "openSUSE", ("rpm", "suse"): "SUSE", ("rpm", "mageia"): "Mageia"}


def purl_ecosystem(purl):
    """回傳（purl 類型, OSV 生態系或 None）。"""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None, None
    rest = purl[4:].lstrip("/").split("?")[0].split("#")[0]
    typ, _, rest = rest.partition("/")
    typ = typ.lower()
    ns = rest.split("/")[0].lower() if "/" in rest else ""
    if typ in PURL_OSV:
        return typ, PURL_OSV[typ]
    return typ, DISTRO_OSV.get((typ, ns))


def sbom_purls(path):
    doc = json.load(open(path, encoding="utf-8"))

    def walk(cs):
        for c in cs or []:
            if isinstance(c, dict):
                yield c
                yield from walk(c.get("components"))
    return [c.get("purl") for c in walk(doc.get("components")) if c.get("purl")]


def coverage(osv_code, osv_path, sbom_path):
    """回傳（狀態, 說明, 明細 dict）。"""
    detail = {"osv_config_http": osv_code, "enabled": None, "ecosystems": None, "by_type": {}}
    try:
        purls = sbom_purls(sbom_path)
    except (OSError, ValueError, AttributeError) as e:
        return "NOT_RUN", f"讀不到 SBOM（{type(e).__name__}），無法核對 OSV 生態系涵蓋", detail
    counts = {}
    for p in purls:
        t, eco = purl_ecosystem(p)
        k = (t or "?", eco)
        counts[k] = counts.get(k, 0) + 1
    detail["by_type"] = {f"{t}→{eco or '（沒有 OSV 生態系）'}": n for (t, eco), n in sorted(counts.items(), key=lambda x: str(x))}
    if osv_code != "200":
        why = "金鑰沒有 SYSTEM_CONFIGURATION_READ" if osv_code in ("401", "403") else f"http={osv_code}"
        return "GAP", f"讀不到 DT 的 OSV 設定（{why}），無法確認 SBOM 的生態系有 OSV 資料", detail
    try:
        cfg = (json.load(open(osv_path, encoding="utf-8")) or {}).get("config") or {}
    except (OSError, ValueError, AttributeError) as e:
        return "GAP", f"DT 的 OSV 設定無法解析（{type(e).__name__}）", detail
    enabled = cfg.get("enabled") is True
    ecos = [str(x) for x in cfg.get("ecosystems") or []]
    detail["enabled"], detail["ecosystems"] = enabled, ecos
    base = {e.split(":")[0].lower() for e in ecos}
    need = {}
    nomap = {}
    for (t, eco), n in counts.items():
        if eco is None:
            nomap[t] = nomap.get(t, 0) + n
        elif not enabled or eco.lower() not in base:
            need[eco] = need.get(eco, 0) + n
    note = ""
    if nomap:
        note = "；沒有 OSV 生態系、只能經 NVD（CPE）比對的元件：" + "、".join(f"{t} {n} 個" for t, n in sorted(nomap.items()))
    if need:
        miss = "、".join(f"{e}（{n} 個元件）" for e, n in sorted(need.items()))
        head = "DT 的 OSV 資料源沒有啟用" if not enabled else "DT 的 OSV 沒有啟用這些生態系"
        return "GAP", (f"{head}：{miss}。這些元件在 DT 只能經 NVD（CPE）比對，DT 結果少於 Grype 不代表比較少弱點"
                       f"（啟用的生態系：{', '.join(ecos) or '無'}）{note}"), detail
    if not purls:
        return "NOT_ASSESSED", "SBOM 沒有帶 purl 的元件，無法核對 OSV 生態系涵蓋", detail
    return "OK", f"SBOM 的 purl 生態系都在 DT 啟用的 OSV 生態系內（{', '.join(ecos)}）{note}", detail


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 3
    rows, osv, sbom, mirror_spec, enisa_cfg, euvd_dir = [], None, None, None, None, None
    try:
        max_age = float(os.environ.get("NVD_MAX_AGE_DAYS") or 3)
    except ValueError:
        max_age = 3.0
    try:
        feeds_max = float(os.environ.get("DT_FEEDS_MAX_AGE_HOURS") or FEEDS_MAX_HOURS)
    except ValueError:
        feeds_max = float("nan")   # 不是數字：feeds_freshness 回 FAIL（設定錯誤），不退回預設值
    args = argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--nvd-mirror":
            mirror_spec = args[i + 1]
            i += 2
        elif args[i] == "--nvd-max-age-days":
            max_age = float(args[i + 1])
            i += 2
        elif args[i] == "--feeds-max-hours":
            try:
                feeds_max = float(args[i + 1])
            except ValueError:
                feeds_max = float("nan")
            i += 2
        elif args[i] == "--enisa-config":
            enisa_cfg = args[i + 1].split(":", 1)
            i += 2
        elif args[i] == "--euvd-kev":
            euvd_dir = args[i + 1]
            i += 2
        elif args[i] == "--osv-config":
            osv = args[i + 1].split(":", 1)
            i += 2
        elif args[i] == "--sbom":
            sbom = args[i + 1]
            i += 2
        else:
            kind, name, code, path = args[i].split(":", 3)
            rows.append(read_one(kind, name, code, path))
            i += 1
    out = {"source": "DT 5.2.0 /api/v2/{vuln,kev}-data-sources/{name}/mirror-runs/latest", "sources": rows}
    mirror = nvd_mirror_info(mirror_spec, max_age)
    if mirror is not None:
        out["nvd_mirror"] = mirror
    enisa = enisa_feed_info(enisa_cfg[0], enisa_cfg[1], euvd_dir) if enisa_cfg is not None else None
    if enisa is not None:
        out["enisa_feed"] = enisa
    vs, vd = stage(rows, "vuln", mirror)
    ks, kd = stage(rows, "kev", enisa=enisa)
    out["vuln_status"], out["kev_status"] = vs, ks
    lines = [("D-dt-data-sources", vs, vd), ("D-dt-kev-sources", ks, kd)]
    fs, fd = feeds_freshness(rows, max_hours=feeds_max)
    out["feeds_freshness"] = {"status": fs, "detail": fd, "max_hours": feeds_max}
    lines.append(("C-dt-feeds", fs, fd))
    if osv is not None and sbom is not None:
        cs, cd, det = coverage(osv[0], osv[1], sbom)
        out["osv_coverage"] = {"status": cs, "detail": cd, **det}
        lines.append(("D-dt-osv-coverage", cs, cd))
    with open(argv[1], "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    for st, s, d in lines:
        print(f"{st}\t{s}\t{d.replace(chr(9), ' ').replace(chr(10), ' ')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
