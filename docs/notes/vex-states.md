# VEX 的狀態對照（A4／D-057；M7c-1、M7c-1b）

`tools/cra/vex_export.py` 依每一列的判定寫 CycloneDX VEX（`vex.cdx.json`），再由 `tools/vexconv/vexconv.py` 轉成 OpenVEX（`vex.openvex.json`）。客戶資料包裡的版本由 `tools/cra/supplier_package.py` 用白名單改寫。

## 狀態對照表

| dumpling 內部的分類（`vex_export`） | CycloneDX VEX | OpenVEX |
|---|---|---|
| resolved | `resolved`／`resolved_with_pedigree` | `fixed` |
| not_affected（含 false_positive） | `not_affected`／`false_positive`，加理由 | `not_affected`，加 justification |
| exploitable | `exploitable`，加處理方式 | `affected`，加 action_statement |
| in_triage（有人判定為調查中） | `in_triage` | `under_investigation` |
| **untriaged（沒有任何判定）** | **`in_triage`，加屬性 `dumpling:assessment`＝`NOT_ASSESSED`** | **`under_investigation`，status_notes 寫「dumpling: not assessed」** |

- 沒有判定的列原本不輸出。只讀 VEX 的下游會因此分不出「沒評估」和「不在清單上」（D-043），所以 M7c-1 起照實輸出。
- `NOT_ASSESSED` 的意思是「沒有評估」，不是有人在調查。
- 發行閘門（`vex.gate`）照舊把這些列算成 `untriaged`，不算 `in_triage`，所以閘門的數字不變。
- `dt_writeback` 不把這些陳述寫回 Dependency-Track。
- vexconv 雙向轉換時會保留這個標記：`to_cdx` 遇到 `under_investigation` 加上述 status_notes，或加下面客戶版的中性句，就加回 `dumpling:assessment`。

## 客戶資料包（`supplier_package.py`）

- 客戶版也輸出沒評估的陳述（D-057 Q1）。狀態照抄內部版的 `in_triage`／`under_investigation`，說明換成中性英文 **「Not yet assessed by the manufacturer」**：CycloneDX 寫在 `analysis.detail`，OpenVEX 寫在 `status_notes`。
- **客戶版要辨識「沒有評估」，看 `in_triage` 加這句固定的 detail**（OpenVEX：`under_investigation` 加這句固定的 status_notes）。客戶版不另開屬性：照現行白名單，CycloneDX 的陳述只留 `openvex:action_statement`（只有 exploitable 才有），`dumpling:assessment` 不帶（D-057 Q1、C0 對 #105 (b) 的決定）。
- **文件內的元件**（M7c-1b）：
  - 不在產品 SBOM 的元件（例如只供比對的原始碼套件），內部版列在 VEX 自己的 `components`，`affects.ref` 指向它。客戶版也帶這些元件，只帶被參照到的，而且只留 `type`、`bom-ref`、`name`、`version`、`purl`，不帶內部屬性。
  - 其他 `affects.ref` 是 BOM-Link（`urn:cdx:…`），指向產品 SBOM。
  - 原本客戶版沒帶 `components`，那些陳述會指到不存在的元件，客戶的工具通常會直接忽略它們。
- 客戶檔不能出現內部名稱：`check_customer_text` 在 VEX 檔裡擋 `dumpling:`、`sca-center:` 等字樣。
