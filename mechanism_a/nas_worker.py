"""单个 (agent, model) worker：串行跑该组合的全部 300 手法，带 resume + infra-fail 跳过。

一个 worker = 一个独立进程，只负责一个 (agent, model) cell-column。多个 worker 并行
（不同 model 不抢同一 LLM 端点/rate-limit；同一 model 同时只一个 worker 故只一个容器，防 OOM）。

用法（由 launch_parallel.sh 为每个并行 model 各起一个）：
  python3 nas_worker.py --agent claude_code --model claude-sonnet-4-6
环境变量需含该 model 对应的 host-env key（见 nas_orchestrate.MODEL_ENV）。
"""
import argparse
import json
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nas_run_cell  # noqa

MUT_ROOT = os.path.expanduser("~/jss_poison/mutations")
INFRA_FAIL_THRESHOLD = 8   # 连续 K 个 infra-fail 判组合不可用


def techlist():
    return sorted(d for d in os.listdir(MUT_ROOT)
                  if os.path.isdir(os.path.join(MUT_ROOT, d)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True)
    ap.add_argument("--model", required=True)
    # 分片：把同一 (agent,model) 的手法列表切成 nshards 份，本 worker 只跑第 shard 份。
    # 多个 shard worker 并行 → 单模型吞吐翻倍。各 shard 写各自 verdict 目录互不冲突（resume 安全）。
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--nshards", type=int, default=1)
    args = ap.parse_args()
    agent, model = args.agent, args.model
    safe_model = model.replace(".", "_").replace("/", "_")
    cid = f"{agent}__{model}#{args.shard}/{args.nshards}"
    techs = [t for idx, t in enumerate(techlist()) if idx % args.nshards == args.shard]
    outc = Counter()
    consec_fail = 0
    done = skipped_remainder = 0
    t0 = time.time()
    print(f"[worker {cid}] start, {len(techs)} techniques", flush=True)

    for i, name in enumerate(techs, 1):
        mdir = os.path.join(MUT_ROOT, name)
        archive = os.path.join(mdir, f"round_{agent}__{safe_model}")
        vpath = os.path.join(archive, "verdict.json")
        if os.path.exists(vpath):                       # resume
            try:
                v = json.load(open(vpath)); outc[v.get("outcome", "?")] += 1; done += 1
                continue
            except Exception:
                pass
        try:
            v = nas_run_cell.run_cell(mdir, agent, model)
            outc[v["outcome"]] += 1; done += 1
            infra = (v["exit_code"] != 0 and v["outcome"] in ("no_edit", "malformed_patch")
                     and v["elapsed_sec"] < 5)
            consec_fail = consec_fail + 1 if infra else 0
            if i % 25 == 0 or infra:
                print(f"[worker {cid}] {i}/{len(techs)} last={v['outcome']} rc={v['exit_code']} "
                      f"{v['elapsed_sec']:.0f}s consec_fail={consec_fail} "
                      f"elapsed_total={ (time.time()-t0)/60:.0f}min", flush=True)
            if consec_fail >= INFRA_FAIL_THRESHOLD:
                print(f"[worker {cid}] {INFRA_FAIL_THRESHOLD} consecutive infra-fails — SKIP remainder "
                      f"at {i}/{len(techs)}", flush=True)
                skipped_remainder = 1
                break
        except Exception as e:
            outc["runner_error"] += 1; consec_fail += 1
            print(f"[worker {cid}] {name} RUNNER_ERROR {type(e).__name__}: {e}", flush=True)
            if consec_fail >= INFRA_FAIL_THRESHOLD:
                print(f"[worker {cid}] too many runner errors — SKIP remainder", flush=True)
                skipped_remainder = 1
                break

    summary = {"agent": agent, "model": model, "n_done": done,
               "outcomes": dict(outc), "skipped_remainder": bool(skipped_remainder),
               "minutes": round((time.time()-t0)/60, 1)}
    json.dump(summary, open(os.path.expanduser(f"~/jss_poison/WORKER_{agent}__{safe_model}__sh{args.shard}of{args.nshards}.json"), "w"),
              ensure_ascii=False, indent=2)
    print(f"[worker {cid}] DONE {dict(outc)} skipped_remainder={bool(skipped_remainder)} "
          f"in {summary['minutes']}min", flush=True)


if __name__ == "__main__":
    main()
