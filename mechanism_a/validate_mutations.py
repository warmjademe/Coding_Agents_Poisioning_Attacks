"""离线验证全部 300 个变异手法：每个变体仍满足机制 A 硬断言。

说明：
  - 通道维变异（M2 swap / M3 relocate）：通道成员真的变了，机制断言在新通道上重新成立，
    属真验证。
  - 文本维变异（M4/M5/M6）：只改伪装文本，离线替身按 directive 识别，故此处仅确认
    "构造未被改坏"（漏洞仍只在两道都拆时出现）。其真鲁棒性需真模型（见 grid.py）。

全 300 个通过才退出码 0；结果写 VALIDATION_MUTATIONS.json。
"""

import json
import os
import sys
import traceback
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "owasp"))

from framework import run_case
from mutations import expand_all, load_base_cases, MUTATION_IDS


def main():
    base = load_base_cases()
    variants = expand_all(base)
    summary = {
        "n_base": len(base), "n_variants": len(variants),
        "mutation_ids": MUTATION_IDS,
        "n_passed": 0, "all_passed": False, "by_mutation": {}, "cases": [],
    }
    by_mut = Counter(); by_mut_pass = Counter()
    passed = 0
    print(f"== 变异验证：{len(base)} 基础案例 × {len(MUTATION_IDS)} 变异 = {len(variants)} 手法 ==\n")

    for v in variants:
        by_mut[v.mutation] += 1
        try:
            r = run_case(v)
            passed += 1; by_mut_pass[v.mutation] += 1
            summary["cases"].append({
                "name": v.name, "owasp": v.owasp, "cwe": v.cwe, "mutation": v.mutation,
                "channels": sorted({d.channel for d in v.defenses} | {"issue"}),
                "passed": True, "minimal_lethal_channels": r.minimal_lethal_channels,
            })
        except Exception as e:
            summary["cases"].append({
                "name": v.name, "mutation": v.mutation, "passed": False,
                "error": f"{type(e).__name__}: {e}",
            })
            print(f"FAIL {v.name}: {type(e).__name__}: {e}")
            traceback.print_exc()

    summary["n_passed"] = passed
    summary["all_passed"] = (passed == len(variants))
    summary["by_mutation"] = {m: f"{by_mut_pass[m]}/{by_mut[m]}" for m in MUTATION_IDS}

    with open(os.path.join(HERE, "VALIDATION_MUTATIONS.json"), "w") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("\n按变异算子：")
    for m in MUTATION_IDS:
        print(f"  {m:<22} {by_mut_pass[m]}/{by_mut[m]}")
    print(f"\n总计 {passed}/{len(variants)} 个变异手法通过机制 A 断言。")
    print(f">>> {'全部 300 手法构造成立 ✓' if summary['all_passed'] else '仍有未通过 ✗'}")
    print("结果写入 VALIDATION_MUTATIONS.json")
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
