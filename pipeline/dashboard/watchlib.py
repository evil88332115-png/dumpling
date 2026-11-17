"""載入 pipeline/watch 底下的模組（collect、issues、support、match），給儀表板重用。

不另寫一份正規式或 HTTP：Release 下載的大小上限、轉址檢查都在 collect.GitHubSource，Issue 的 API 在 issues.Api。
用檔案路徑載入，不依賴 sys.path（python3 -I 時 sys.path 不含腳本資料夾）；同一個模組只載入一次。
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WATCH = os.path.join(ROOT, "pipeline", "watch")
_cache = {}


def load(name):
    """name：collect／issues／support／match。回模組物件。match 只讀它的常數與 uuid_of（韌體公告的用語、監控鍵）。"""
    if name not in ("collect", "issues", "support", "match"):
        raise ValueError("不認得的模組：" + name)
    if name not in _cache:
        spec = importlib.util.spec_from_file_location("dumpling_dash_" + name, os.path.join(WATCH, name + ".py"))
        mod = importlib.util.module_from_spec(spec)
        # issues.py／support.py 自己會把 pipeline/watch 放進 sys.path 再 import 兄弟模組（publiccheck、match）
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        _cache[name] = mod
    return _cache[name]
