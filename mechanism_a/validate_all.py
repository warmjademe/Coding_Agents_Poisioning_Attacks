"""跑全部 OWASP Top 10 (2021) 案例（每类 5 个，共 50 个），逐个执行机制 A 硬断言。

机制 A 通过判据（逐案例，由 framework.run_case 断言）：
  (1) 每条单通道单独激活 → 真 exploit 打不穿（且 bug 修好）；
  (2) 存在通道组合 → 真 exploit 打穿（且 bug 修好）；
  (3) 全通道组合致命；
  (4) 最小致命组合 >= 2 条通道（证明"拆分"必要）。
真值口径 = 真实 exploit 触发，不是静态扫描。

全 50 个案例全过才退出码 0。结果写入 VALIDATION_ALL.json。
"""

import importlib
import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "owasp"))

from framework import run_case, CHANNELS

OWASP_MODULES = [
    ("A01", "Broken Access Control", "a01_access_control"),
    ("A02", "Cryptographic Failures", "a02_crypto"),
    ("A03", "Injection", "a03_injection"),
    ("A04", "Insecure Design", "a04_insecure_design"),
    ("A05", "Security Misconfiguration", "a05_misconfig"),
    ("A06", "Vulnerable & Outdated Components", "a06_vuln_components"),
    ("A07", "Identification & Authentication Failures", "a07_auth_failures"),
    ("A08", "Software & Data Integrity Failures", "a08_integrity"),
    ("A09", "Security Logging & Monitoring Failures", "a09_logging"),
    ("A10", "Server-Side Request Forgery (SSRF)", "a10_ssrf"),
]


def main():
    summary = {
        "taxonomy": "OWASP Top 10 (2021)",
        "channels": CHANNELS,
        "categories": [], "n_cases": 0, "n_passed": 0,
        "all_passed": False, "cases": [],
    }
    total = passed = 0
    print("== 机制 A × OWASP Top 10 (2021)：50 案例验证（真值=真实 exploit 触发）==\n")
    print(f"{'OWASP':<6}{'case':<28}{'cwe':<11}{'minLethal':>9}{'staticMiss':>11}  result")
    print("-" * 78)

    for code, title, modname in OWASP_MODULES:
        mod = importlib.import_module("owasp." + modname)
        cat = {"code": code, "title": title, "n": len(mod.CASES), "passed": 0}
        for case in mod.CASES:
            total += 1
            try:
                r = run_case(case)
                passed += 1; cat["passed"] += 1
                summary["cases"].append({
                    "owasp": code, "name": r.name, "cwe": r.cwe, "family": r.family,
                    "passed": True, "minimal_lethal_channels": r.minimal_lethal_channels,
                    "static_missed_real": r.static_missed_real, "rows": r.rows,
                })
                print(f"{code:<6}{case.name:<28}{case.cwe:<11}"
                      f"{r.minimal_lethal_channels:>9}{r.static_missed_real:>11}  PASS")
            except AssertionError as e:
                summary["cases"].append({"owasp": code, "name": case.name,
                                         "cwe": case.cwe, "passed": False, "error": str(e)})
                print(f"{code:<6}{case.name:<28}{case.cwe:<11}{'-':>9}{'-':>11}  FAIL: {e}")
            except Exception as e:
                summary["cases"].append({"owasp": code, "name": case.name,
                                         "passed": False, "error": f"{type(e).__name__}: {e}"})
                print(f"{code:<6}{case.name:<28}  ERROR: {type(e).__name__}: {e}")
                traceback.print_exc()
        summary["categories"].append(cat)

    summary["n_cases"] = total
    summary["n_passed"] = passed
    summary["all_passed"] = (passed == total)

    # 统计：静态完全漏报的案例数（真打穿但静态没报）
    n_static_miss = sum(1 for c in summary["cases"] if c.get("static_missed_real", 0) > 0)
    summary["n_cases_static_missed"] = n_static_miss

    with open(os.path.join(HERE, "VALIDATION_ALL.json"), "w") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("-" * 78)
    print("\n按 OWASP 类别：")
    for cat in summary["categories"]:
        print(f"  {cat['code']} {cat['title']:<42} {cat['passed']}/{cat['n']}")
    print(f"\n总计 {passed}/{total} 个案例通过。")
    print(f"其中 {n_static_miss}/{total} 个案例『真 exploit 打穿但静态扫描漏报』"
          f"（支撑：判定必须用真 exploit，不能只靠静态）。")
    print(f"\n>>> 机制 A 在 OWASP 全 10 类上"
          f"{'成立 ✓（50/50）' if summary['all_passed'] else '仍有未通过 ✗'}")
    print("结果已写入 VALIDATION_ALL.json")
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
