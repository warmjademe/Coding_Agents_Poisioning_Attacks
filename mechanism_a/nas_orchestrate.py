"""NAS 端总编排：按智能体顺序跑完 (4 agent × 5 model × 300 手法) 全量矩阵。

设计：
  - 串行跑（一次一个 cell），避免容器并发抢内存触发 OOM（已实测 2g 限制致 exit 137；
    SUT 已调 4g，但仍串行以稳为先）。
  - 按 AGENT 顺序，每个 agent 内按 MODEL 顺序；claude_code 打头（用户指定）。
  - 坏 (agent, model) 组合：连续 K 个 cell 全部 infra-fail（exit_code 非 0 且 no_edit/0.x秒）
    则判定该组合不可用，跳过其余手法、记入 SKIPPED，继续下一组合。
  - 代理：需 LiteLLM 代理的 model 在跑该组合前确保代理在监听，跑完不停（复用）。
  - 断点续跑：已存在 verdict.json 的 cell 跳过（resume）。
  - 每个 cell 的 verdict 落 mutations/<mid>/round_<agent>__<model>/，全局进度写 ORCH_PROGRESS.json。

用法：python3 nas_orchestrate.py --agents claude_code --models claude-sonnet-4-6,glm-5.1
      python3 nas_orchestrate.py   # 全量默认矩阵
"""
import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nas_run_cell  # noqa

MUT_ROOT = os.path.expanduser("~/jss_poison/mutations")
PROGRESS = os.path.expanduser("~/jss_poison/ORCH_PROGRESS.json")

# 用户指定顺序：claude_code 打头
AGENTS = ["claude_code", "codex_cli", "gemini_cli", "openhands"]
MODELS = ["claude-sonnet-4-6", "glm-5.1", "MiniMax-M2.7", "gemini-3-pro", "gpt-5.3-codex"]

# 每个 model 的 host-env key（注入容器用）。值在编排启动时从环境读取。
MODEL_ENV = {
    "claude-sonnet-4-6": ["SIMPLEAI_API_KEY"],
    "glm-5.1":           ["Z_AI_API_KEY"],
    "MiniMax-M2.7":      ["MINIMAX_API_KEY"],
    "gemini-3-pro":      ["GOOGLE_API_KEY"],
    "gpt-5.3-codex":     ["SHQBB_API_KEY"],
}

# 需 LiteLLM 代理的 (agent,model) → (port, yaml, env-for-proxy)
# claude_code 对 MiniMax/Gemini/GPT5 需 Anthropic→后端 代理。
PROXY = {
    ("claude_code", "MiniMax-M2.7"): (4000, "minimax27_anthropic.yaml", "MINIMAX_API_KEY"),
    ("claude_code", "gpt-5.3-codex"): (4010, "shqbb_gpt53_anthropic.yaml", "SHQBB_API_KEY"),
    ("claude_code", "gemini-3-pro"): (4005, "gemini3pro_anthropic.yaml", "GOOGLE_API_KEY"),
}

INFRA_FAIL_THRESHOLD = 5   # 连续 K 个 cell infra-fail 即判组合不可用


def load_progress():
    if os.path.exists(PROGRESS):
        return json.load(open(PROGRESS))
    return {"cells": {}, "skipped": []}


def save_progress(p):
    json.dump(p, open(PROGRESS, "w"), ensure_ascii=False, indent=2)


def techlist():
    return sorted(d for d in os.listdir(MUT_ROOT)
                  if os.path.isdir(os.path.join(MUT_ROOT, d)))


def ensure_proxy(agent, model):
    """需代理则起 LiteLLM（已在监听则复用）。返回 True 表示就绪/不需要。"""
    key = (agent, model)
    if key not in PROXY:
        return True
    port, yaml, envvar = PROXY[key]
    # 已监听？
    r = subprocess.run(["bash", "-lc", f"ss -tln | grep -q ':{port} ' && echo UP || echo DOWN"],
                       capture_output=True, text=True)
    if "UP" in r.stdout:
        return True
    if not os.environ.get(envvar):
        print(f"[orch] proxy for {key} needs ${envvar} (missing) — SKIP combo")
        return False
    cfg = os.path.expanduser(f"~/jss_poison/litellm_proxies/{yaml}")
    litellm = os.path.expanduser("~/miniconda3/envs/EMNLP_2026_Overeage/bin/litellm")
    log = f"/tmp/litellm_{port}.log"
    env = dict(os.environ)
    if model == "gemini-3-pro":
        env["HTTPS_PROXY"] = "http://127.0.0.1:7890"  # Google 需 Clash
        env["HTTP_PROXY"] = "http://127.0.0.1:7890"
    subprocess.Popen([litellm, "--config", cfg, "--port", str(port), "--host", "0.0.0.0"],
                     stdout=open(log, "w"), stderr=subprocess.STDOUT, env=env,
                     start_new_session=True)
    # 等监听
    for _ in range(40):
        time.sleep(1)
        r = subprocess.run(["bash", "-lc", f"ss -tln | grep -q ':{port} ' && echo UP"],
                           capture_output=True, text=True)
        if "UP" in r.stdout:
            print(f"[orch] proxy :{port} ({yaml}) up for {key}")
            return True
    print(f"[orch] proxy :{port} failed to bind in 40s — SKIP combo {key}; see {log}")
    return False


def run_combo(agent, model, techs, prog):
    cid = f"{agent}__{model}"
    if cid in prog["skipped"]:
        print(f"[orch] {cid} already SKIPPED, pass")
        return
    sut_path = os.path.expanduser(f"~/jss_poison/configs_sut/{agent}__{model}.json")
    if not os.path.exists(sut_path):
        print(f"[orch] {cid}: no SUT config — SKIP")
        prog["skipped"].append(cid); save_progress(prog); return
    if not ensure_proxy(agent, model):
        prog["skipped"].append(cid); save_progress(prog); return

    print(f"\n[orch] === COMBO {cid} : {len(techs)} techniques ===")
    consec_fail = 0
    outc = Counter()
    for i, name in enumerate(techs, 1):
        mdir = os.path.join(MUT_ROOT, name)
        archive = os.path.join(mdir, f"round_{agent}__{model.replace('.', '_').replace('/', '_')}")
        vpath = os.path.join(archive, "verdict.json")
        if os.path.exists(vpath):  # resume
            try:
                v = json.load(open(vpath)); outc[v.get("outcome", "?")] += 1
                continue
            except Exception:
                pass
        try:
            v = nas_run_cell.run_cell(mdir, agent, model)
            outc[v["outcome"]] += 1
            prog["cells"][f"{cid}__{name}"] = {"outcome": v["outcome"], "elicited": v["elicited"]}
            # infra-fail 判定：exit_code 非 0 且没产出 edit 且秒退
            infra = (v["exit_code"] not in (0,) and v["outcome"] in ("no_edit", "malformed_patch")
                     and v["elapsed_sec"] < 5)
            consec_fail = consec_fail + 1 if infra else 0
            if i % 20 == 0 or infra:
                print(f"[orch] {cid} {i}/{len(techs)} last={v['outcome']} "
                      f"rc={v['exit_code']} {v['elapsed_sec']}s consec_fail={consec_fail}", flush=True)
            if consec_fail >= INFRA_FAIL_THRESHOLD:
                print(f"[orch] {cid}: {INFRA_FAIL_THRESHOLD} consecutive infra-fails — SKIP remainder")
                prog["skipped"].append(cid); save_progress(prog); return
        except Exception as e:
            outc["runner_error"] += 1
            consec_fail += 1
            print(f"[orch] {cid} {name} RUNNER_ERROR {type(e).__name__}: {e}", flush=True)
            if consec_fail >= INFRA_FAIL_THRESHOLD:
                prog["skipped"].append(cid); save_progress(prog); return
        save_progress(prog)
    n = sum(outc.values()); el = sum(1 for k in prog["cells"] if k.startswith(cid) and prog["cells"][k]["elicited"])
    print(f"[orch] COMBO {cid} done: {dict(outc)}")
    save_progress(prog)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agents", default=",".join(AGENTS))
    ap.add_argument("--models", default=",".join(MODELS))
    args = ap.parse_args()
    agents = [a.strip() for a in args.agents.split(",") if a.strip()]
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    techs = techlist()
    prog = load_progress()
    print(f"[orch] matrix: {agents} x {models} x {len(techs)} techniques")
    for agent in agents:           # 按 agent 顺序
        for model in models:       # 每 agent 内按 model 顺序
            run_combo(agent, model, techs, prog)
    print("\n[orch] ALL DONE. progress:", PROGRESS)


if __name__ == "__main__":
    main()
