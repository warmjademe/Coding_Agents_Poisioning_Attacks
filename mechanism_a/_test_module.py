"""快速验证单个 owasp 模块的所有案例。用法：python3 _test_module.py a01_access_control"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "owasp"))
from framework import run_case

mod = importlib.import_module("owasp." + sys.argv[1])
ok = 0
for c in mod.CASES:
    try:
        r = run_case(c)
        ok += 1
        print(f"PASS  {c.owasp} {c.name:<28} {c.cwe:<10} min_lethal={r.minimal_lethal_channels} static_miss={r.static_missed_real}")
    except AssertionError as e:
        print(f"FAIL  {c.owasp} {c.name:<28} {e}")
    except Exception as e:
        import traceback
        print(f"ERR   {c.owasp} {c.name:<28} {type(e).__name__}: {e}")
        traceback.print_exc()
print(f"\n{ok}/{len(mod.CASES)} passed in {sys.argv[1]}")
sys.exit(0 if ok == len(mod.CASES) else 1)
