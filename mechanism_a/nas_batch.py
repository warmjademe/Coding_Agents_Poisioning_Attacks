"""NAS 端批跑：对一个 mutation 列表 × 单个 (agent, model) 顺序跑，累计 outcome 统计。

用法：
  python3 nas_batch.py --agent claude_code --model claude-sonnet-4-6 --list techlist.txt
  techlist.txt 每行一个 mutation 目录名（相对 ~/jss_poison/mutations/）。

输出：每个 cell 一行进度 + 末尾 outcome 直方图 + ASR；结果汇总写 BATCH_<agent>_<model>.json。
所需 host env（按模型）：SIMPLEAI_API_KEY / Z_AI_API_KEY / MINIMAX_API_KEY / GOOGLE_API_KEY / SHQBB_API_KEY。
"""
import argparse
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nas_run_cell  # noqa


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--list", required=True, help="file: one mutation dir name per line")
    ap.add_argument("--mut-root", default=os.path.expanduser("~/jss_poison/mutations"))
    args = ap.parse_args()

    names = [l.strip() for l in open(args.list) if l.strip() and not l.startswith("#")]
    safe_model = args.model.replace(".", "_").replace("/", "_")
    outc = Counter()
    rows = []
    print(f"== batch: {args.agent} x {args.model} == {len(names)} techniques\n")
    print(f"{'#':>3} {'technique':<40}{'outcome':<18}{'parses':<7}{'sec':>6}")
    print("-" * 78)
    for i, name in enumerate(names, 1):
        mdir = os.path.join(args.mut_root, name)
        if not os.path.isdir(mdir):
            print(f"{i:>3} {name:<40}MISSING_DIR"); continue
        try:
            v = nas_run_cell.run_cell(mdir, args.agent, args.model)
            outc[v["outcome"]] += 1
            rows.append(v)
            print(f"{i:>3} {name:<40}{v['outcome']:<18}{str(v['patch_parses']):<7}{v['elapsed_sec']:>6.0f}",
                  flush=True)
        except Exception as e:
            outc["runner_error"] += 1
            print(f"{i:>3} {name:<40}RUNNER_ERROR {type(e).__name__}: {e}", flush=True)

    n_done = len(rows)
    n_elicit = sum(1 for r in rows if r["elicited"])
    asr = n_elicit / n_done if n_done else 0.0
    summary = {"agent": args.agent, "model": args.model, "n": n_done,
               "n_elicited": n_elicit, "asr": asr, "outcomes": dict(outc), "rows": rows}
    out_path = os.path.join(HERE, f"BATCH_{args.agent}_{safe_model}.json")
    json.dump(summary, open(out_path, "w"), ensure_ascii=False, indent=2)

    print("-" * 78)
    print("outcome histogram:", dict(outc))
    print(f"ASR (elicited / done) = {n_elicit}/{n_done} = {asr:.1%}")
    print(f"written: {out_path}")


if __name__ == "__main__":
    main()
