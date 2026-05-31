"""自测全部 300 个导出的 detector：对每个手法，验证内联 detector 的判定口径
与本机一致——带毒补丁(两道全拆)→True，安全补丁→False。

任一不符即报错。全 300 通过才退出码 0。
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "owasp"))

from mutations import mutate, load_base_cases

MUT_ROOT = os.path.join(HERE, "nas_export", "mutations")


def as_diff(src, module_relpath="mod.py"):
    return f"+++ b/{module_relpath}\n" + "\n".join("+" + l for l in src.splitlines()) + "\n"


def load_detector(mdir):
    spec = importlib.util.spec_from_file_location(
        "det_" + os.path.basename(mdir), os.path.join(mdir, "detector.py"))
    det = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(det)
    return det


def main():
    base = load_base_cases()
    variants = []
    for c in base:
        variants.extend(mutate(c))

    n_ok = n_fail = 0
    fails = []
    for v in variants:
        mdir = os.path.join(MUT_ROOT, v.name)
        try:
            det = load_detector(mdir)
            vuln = v.build_patch({"D1", "D2"})
            safe = v.build_patch(set())
            r_vuln = bool(det.detect([], as_diff(vuln)))
            r_safe = bool(det.detect([], as_diff(safe)))
            if r_vuln is True and r_safe is False:
                n_ok += 1
            else:
                n_fail += 1
                fails.append((v.name, f"vuln={r_vuln}(want True) safe={r_safe}(want False)"))
        except Exception as e:
            n_fail += 1
            fails.append((v.name, f"{type(e).__name__}: {e}"))

    summary = {
        "n_techniques": len(variants), "n_ok": n_ok, "n_fail": n_fail,
        "all_ok": n_fail == 0, "fails": fails[:50],
    }
    with open(os.path.join(HERE, "nas_export", "EXPORT_SELFTEST.json"), "w") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"detector self-test: {n_ok}/{len(variants)} OK, {n_fail} FAIL")
    for name, why in fails[:20]:
        print(f"  FAIL {name}: {why}")
    print(">>>", "全部 300 detector 口径一致 ✓" if n_fail == 0 else f"有 {n_fail} 个不符 ✗")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
