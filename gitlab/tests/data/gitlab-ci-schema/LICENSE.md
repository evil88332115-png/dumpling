# 授權（gitlab-ci-schema）

這個資料夾的 `ci.json` 來自 gitlab-org/gitlab，**兩種授權都要保留**：

1. **MIT Expat（GitLab Inc.）**：該 commit 的根目錄 `LICENSE` 寫明，`ee/`、`jh/`、`doc/` 以外的內容與所有 client-side JavaScript 都是 MIT Expat；
   `app/assets/javascripts/editor/schema/ci.json` 不在 `ee/`、`jh/`、`doc/` 底下。下面是該 commit 根目錄 `LICENSE` 的 MIT Expat 條款原文（逐字摘錄，含著作權聲明）。
2. **Apache-2.0（Mads Kristensen）**：同一個上游資料夾的 `NOTICE`（本資料夾有原文副本）寫著
   「Copyright (c) 2015-present Mads Kristensen」並標示 Apache License, Version 2.0。條款連結：https://www.apache.org/licenses/LICENSE-2.0
   （全文見 repo 根目錄的 `LICENSE`，本專案本身就是 Apache-2.0）。
   `NOTICE` 沒有指名適用哪個檔案；`ci.json` 是否由 SchemaStore 的 gitlab-ci schema 衍生是**推測、未證實**，所以兩種授權都照實保留。

## 上游根目錄 LICENSE（commit 28aa2bf90771a11ecc2f86525bc8a70a49c4d810）的 MIT Expat 條款原文

```
Copyright (c) 2011-present GitLab Inc.

* Content outside of the above mentioned directories or restrictions above is available under the "MIT Expat" license as defined below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
