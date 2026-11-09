"""The browser bootstrap must remove every legacy token query alias."""

import json
import shutil
import subprocess
from unittest import SkipTest

from dataplane import admin


_BOOT_START = 'let TOKEN="";'
_BOOT_END = 'const H='


def _bootstrap(url):
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is unavailable for dashboard bootstrap checks")
    source = admin._HTML
    start, end = source.index(_BOOT_START), source.index(_BOOT_END)
    snippet = source[start:end]
    script = (
        'const vm=require("node:vm");'
        'const source=' + json.dumps(snippet) + ';'
        'const location={href:' + json.dumps(url) + '};'
        'const changes=[];let prompts=0;'
        'const history={replaceState(_a,_b,path){changes.push(path);'
        'location.href=new URL(path,location.href).href;}};'
        'const context={URL,location,history,sessionStorage:{removeItem(){}},'
        'prompt(){prompts++;return "MANUAL_MARKER";}};'
        'vm.createContext(context);'
        'const result=vm.runInContext(source+"\\n({memory:TOKEN})",context);'
        'process.stdout.write(JSON.stringify({...result,href:location.href,changes,prompts}));'
    )
    result = subprocess.run([node, "-e", script], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stderr[-500:]
    return json.loads(result.stdout)


def test_case_aliases_of_legacy_url_token_are_removed_before_auth_prompt():
    result = _bootstrap("http://127.0.0.1:8081/?ToKeN=OLD_MARKER&%54OKEN=OTHER_MARKER"
                        "&tab=overview#panel")
    assert result["changes"] == ["/?tab=overview#panel"], result
    assert result["href"] == "http://127.0.0.1:8081/?tab=overview#panel", result
    assert result["memory"] == "" and result["prompts"] == 0


def test_mixed_exact_and_case_aliases_are_all_removed():
    result = _bootstrap("http://127.0.0.1:8081/?token=OLD_MARKER&ToKeN=OTHER_MARKER"
                        "&tab=overview")
    assert result["changes"] == ["/?tab=overview"], result
    assert result["href"] == "http://127.0.0.1:8081/?tab=overview", result
    assert result["memory"] == "" and result["prompts"] == 0


def test_unrelated_query_keys_and_fragment_remain_untouched():
    url = "http://127.0.0.1:8081/?tab=overview&tokenized=public#panel"
    result = _bootstrap(url)
    assert result["changes"] == [], result
    assert result["href"] == url, result
    assert result["memory"] == "" and result["prompts"] == 0
