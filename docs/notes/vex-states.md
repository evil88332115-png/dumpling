# VEX 的狀態對照（A4／D-057；M7c-1、M7c-1b、M7c-2）

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

## 排除的依據（D-035／D-057；M7c-2）

每一筆**排除**（內部分類 resolved 或 not_affected 的陳述，含 `false_positive`、`resolved_with_pedigree`；OpenVEX 的 `fixed`、`not_affected`）要記**依據類型**與**依據位置**。沒有類型的排除報告標 ATTENTION、發行閘門不算已處理（算進 `untriaged_for_gate`，`complete` 變 false，理由以「N exclusions without evidence type」開頭）；其他數字不變。

### 類型與各來源的位置

| 來源 | 類型 | 位置 |
|---|---|---|
| 核心設定檢查（kconfig）、證據規則 K1 | `build-record` | `scan/kernel-config.json`，附核心版本與 config 的 SHA-256；`kernel` 欄位是核心版本 |
| 證據規則 K2 | `build-record` | `scan/kernel-module-map.json`、`CRA/Config/kernel-modules.json`（各附 SHA-256；有核心設定檢查時再加 `scan/kernel-config.json`）；`kernel` 欄位是模組對應的核心版本 |
| 證據規則 U1、U2 | `vendor-statement` | Ubuntu CVE Tracker 的檔案加 commit（`active/<CVE>@<commit>`）與 `https://ubuntu.com/security/<CVE>`，每個 CVE 一筆 |
| 發行版修補紀錄（`distro_fixed`） | `vendor-statement` | 紀錄編號（DSA、DLA、USN、`UBUNTU-CVE-…`），每個編號一筆；紀錄沒有編號時沒有類型 |
| annotation | 人在判定檔裡寫（五種之一） | 人寫（見下） |
| Dependency-Track 的人工判定（`source=dt`） | **一律沒有類型** | —（DT 沒有放類型的欄位；同一列又有 annotation 時見下一段） |

**同一列同時有 DT 的判定和 annotation 的判定時**：照來源的優先順序以 DT 為準，那一列的陳述是 DT 的。DT 沒有放依據類型的欄位，所以這筆排除算沒有類型（原因 `dt`），會擋發行閘門；即使 annotation 寫了依據也一樣（那筆 annotation 算已使用，不會另外提示）。要解開，請在 DT 端處理：拿掉或改掉 DT 的分析，讓 annotation 的判定生效，依據才會進陳述。

五種類型：`build-record`、`source`、`on-device`、`design-doc`、`vendor-statement`。發行版是 OS 的供應者，所以它的修補紀錄歸 `vendor-statement`，沒有第六種類型。規則本身的種類（`evidence`＝K1／K2／U1／U2）沒有改。plain 規則（match／set）不能排除，NVIDIA 推定只給 `in_triage`，所以沒有別的排除來源。

### annotation 的欄位（`CRA/Config/vex-annotations.json`）

- `evidence`：類型；`evidence_location`：位置（文字，或文字清單＝同一類型的多筆依據）。兩個要一起寫。
- 或 `evidence_basis`：`[{"type": …, "location": …, "kernel": …（選填）}]`，每筆依據自己的類型；映像有多顆核心時每顆核心各一筆（D-036）。不能和 `evidence` 一起用。
- 位置的限制：不能空、前後沒有空白、不超過 512 字、**不能有 `;`**、不能有換行與控制字元（含零寬與雙向控制字元）。拒收 `;` 而不是編碼：內部 OpenVEX 的依據行用 `;` 分隔欄位，位置沒有 `;` 就不需要跳脫規則；輸入端與 vexconv 用同一個檢查。
- `on-device`：位置必須是**專案資料夾內實際存在的檔案**：相對路徑、不能是絕對路徑、不能有 `..`、跟著符號連結之後仍在專案資料夾內（指到外面算不存在）。**只檢查檔案存在，沒有驗證內容**；不合格時這筆排除沒有類型（原因 `on_device_missing`、`on_device_unsafe_path`），閘門與報告都會標出來。一筆判定有多筆依據時，任何一筆不合格，整筆都沒有類型。
- `design-doc`：位置是自由文字（文件名稱、版本、章節），只檢查上面的共同限制，不檢查文件存在。輸出到 Markdown 時放進行內程式碼並跳脫。
- `annotate` 的參數：`--evidence`、`--evidence-location`（可給多個）、`--evidence-basis`（JSON）。

### 內部 CycloneDX（`vex.cdx.json`）

每一筆依據依序一組屬性：`dumpling:evidence`（類型）、`dumpling:evidence-location`（位置）、選填的 `dumpling:evidence-kernel`（那顆核心的版本）。沒有類型的排除只有一個 `dumpling:evidence`＝`none`（沒有位置）：明寫「沒有」，下游分得出「沒記」與「工具沒有這個功能」。沒有評估的陳述與其他狀態沒有這些屬性。

### 內部 OpenVEX（`vex.openvex.json`）

`status_notes` 每一筆依據一行，接在其他 notes 後面（沒有其他 notes 時只有這些行）：

```
dumpling: evidence=<類型>; location=<位置>
dumpling: evidence=<類型>; kernel=<核心版本>; location=<位置>
dumpling: evidence=none
```

解析一律用 `re.fullmatch`、一行一筆（只以換行字元分行）；類型只收五種；位置經上面的檢查。不合格的行不轉成屬性，原樣留在一般 notes；不合格的屬性組寫成 `dumpling: evidence-invalid=<JSON>`（不會被解析）；說明文字裡長得像依據行的行加一個反斜線跳脫、讀回時還原，不會被讀成依據。只有 `not_affected` 與 `fixed` 的陳述帶依據。依據行和 `dumpling: not assessed` 及其他 notes 互不干擾（沒評估的陳述不是排除，沒有依據行）。vexconv 雙向轉換都保留（CDX→OpenVEX→CDX、OpenVEX→CDX→OpenVEX）。

### 客戶版（`supplier_package.py`）

只帶依據**類型**、不帶位置、核心與內部名稱（位置可能是內部路徑）。每種類型一句固定的中性英文，接在 CycloneDX 的 `analysis.detail` 與 OpenVEX 的 `status_notes` 後面（OpenVEX 選 `status_notes`：`fixed` 沒有 `impact_statement`，`status_notes` 每種狀態都有）：

| 類型 | 句子 |
|---|---|
| `build-record` | `Evidence: build artifacts.`（不寫 build record：客戶版的內部用語檢查會擋這個詞） |
| `source` | `Evidence: source code.` |
| `on-device` | `Evidence: on-device check.` |
| `design-doc` | `Evidence: design documentation.` |
| `vendor-statement` | `Evidence: vendor statement.` |
| 沒有類型 | `Evidence: not recorded.`（不能省略，D-043） |

一筆排除有多種類型時，每種一句（順序固定）。沒有評估的陳述不是排除，不加這句。屬性白名單不變（客戶版 CycloneDX 的屬性仍只留 `openvex:action_statement`）。

### 其他

- `dt_writeback` 不寫回依據（它只送狀態、理由與說明）。
- `summary.json` 的 `vex.evidence`：`by_type`（五種類型各幾筆排除；一筆排除有多種類型時每種各算一次）、`without_type`（總數、各原因的筆數、前 10 筆）、`on_device` 與 `design_doc`（每一筆依據的 CVE、元件、版本、位置）。風險評估的 VEX 小節列出各類型筆數、沒有類型的排除（擋閘門）、並單獨列出靠 on-device 或 design-doc 的排除（D-035）。
