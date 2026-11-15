# patches/

放要套在上游原始碼上的 patch（例如把上游已修的 CVE 修補 backport 進核心）。每個 patch 一個檔案，
檔名開頭用數字排序（`0001-…patch`）；套用時機與順序由平台轉接器的 `build` 步驟決定。
