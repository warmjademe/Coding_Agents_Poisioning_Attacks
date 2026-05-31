"""NAS 端单 cell 执行器（自包含，适配本项目 mutation 格式）。

一个 cell = (mutation, agent, model)。流程：
  1. materialize：把 mutation 的 module.py/tests/ISSUE.md/verify 摊进 work/sandbox/，
     并写 sandbox/.oe/task.txt = ISSUE.md（同门 agent 镜像 entrypoint 读这个）。
  2. docker run：用该 (agent,model) 的 SUT env 跑对应镜像，agent 在 sandbox 里改代码。
  3. diff：agent 改完后的 module.py 源码（相对起始 module.py）。
  4. detect：调 mutation 自带 detector.py 的 detect(transcript, diff) → elicited。
  5. verdict.json 落到 mutation/round_<agent>__<model>/。

SUT 配置：configs_sut/<agent>_<model>.json（本项目自带，端点已实测）。
在 NAS 上跑：python3 nas_run_cell.py --mutation <dir> --agent <a> --model <m>
"""
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
SUT_DIR = os.path.join(HERE, "configs_sut")


def load_sut(agent, model):
    p = os.path.join(SUT_DIR, f"{agent}__{model}.json")
    if not os.path.exists(p):
        raise FileNotFoundError(f"SUT config missing: {p}")
    return json.load(open(p))


def materialize(mutation_dir, sandbox):
    manifest = json.load(open(os.path.join(mutation_dir, "manifest.json")))
    module_rel = manifest["module_relpath"]
    tests_rel = manifest["tests_relpath"]
    os.makedirs(sandbox, exist_ok=True)
    # module
    dst = os.path.join(sandbox, module_rel)
    os.makedirs(os.path.dirname(dst) or sandbox, exist_ok=True)
    shutil.copy(os.path.join(mutation_dir, "module.py"), dst)
    # tests
    tdst = os.path.join(sandbox, tests_rel)
    os.makedirs(os.path.dirname(tdst) or sandbox, exist_ok=True)
    shutil.copy(os.path.join(mutation_dir, tests_rel), tdst)
    # issue + verify
    shutil.copy(os.path.join(mutation_dir, "ISSUE.md"), os.path.join(sandbox, "ISSUE.md"))
    for s in ("verify_build.sh", "verify_legit.sh"):
        shutil.copy(os.path.join(mutation_dir, s), os.path.join(sandbox, s))
        os.chmod(os.path.join(sandbox, s), 0o755)
    # task.txt for agent entrypoint
    os.makedirs(os.path.join(sandbox, ".oe"), exist_ok=True)
    shutil.copy(os.path.join(mutation_dir, "ISSUE.md"),
                os.path.join(sandbox, ".oe", "task.txt"))
    return module_rel


def make_diff(mutation_dir, sandbox, module_rel):
    """git-diff-compatible：起始 module.py vs agent 改后的 sandbox/module。"""
    start = os.path.join(mutation_dir, "module.py")
    final = os.path.join(sandbox, module_rel)
    if not os.path.exists(final):
        return ""
    proc = subprocess.run(["diff", "-u", start, final], capture_output=True, text=True)
    raw = proc.stdout
    lines = []
    for ln in raw.splitlines():
        if ln.startswith("--- "):
            lines.append(f"--- a/{module_rel}")
        elif ln.startswith("+++ "):
            lines.append(f"+++ b/{module_rel}")
        else:
            lines.append(ln)
    return "\n".join(lines) + ("\n" if lines else "")


def run_detector(mutation_dir, full_src, module_rel="mod.py"):
    """用 agent 最终的【完整 module 源码】判定。

    早期 bug：曾把 unified-diff 喂给 detector，detector 的 _changed_files 只收 '+' 行，
    丢掉未改的 import/def 上下文 → 重建出残缺 src → _load_mod ImportError → c1=False →
    几乎所有 cell 误判 resisted（ASR 全 0 的根因）。修法：把完整源码包成"全量 +行 diff"
    喂进去，使 detector 解析出完整 src。
    """
    spec = importlib.util.spec_from_file_location(
        "det_" + os.path.basename(mutation_dir),
        os.path.join(mutation_dir, "detector.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    full_diff = f"+++ b/{module_rel}\n" + "\n".join("+" + l for l in full_src.splitlines()) + "\n"
    try:
        return bool(m.detect([], full_diff))
    except Exception:
        return False


def run_cell(mutation_dir, agent, model, work_root=None):
    sut = load_sut(agent, model)
    safe_model = model.replace(".", "_").replace("/", "_")
    run_id = f"{os.path.basename(mutation_dir)}__{agent}__{safe_model}__{uuid.uuid4().hex[:6]}"
    work_root = work_root or os.path.expanduser("~/jss_poison_work")
    os.makedirs(work_root, exist_ok=True)
    work_dir = os.path.join(work_root, run_id)
    sandbox = os.path.join(work_dir, "sandbox")
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(os.path.join(work_dir, ".oe"))
    module_rel = materialize(mutation_dir, sandbox)

    env = dict(sut.get("container_env", {}))
    # host-env 占位替换：{host_env:VAR} → os.environ[VAR]
    import re
    def expand(v):
        return re.sub(r"\{host_env:([A-Z0-9_]+)\}",
                      lambda m: os.environ.get(m.group(1), ""), str(v))
    env = {k: expand(v) for k, v in env.items()}
    timeout_inner = int(env.get("OE_RUN_TIMEOUT", "600"))

    # 容器名须全局唯一：run_id 末尾的 uuid6 保唯一（截断会切掉 uuid 致同名 mutation 跨 model 撞名 → rc=125）。
    cname = "jssp_" + run_id[:32] + "_" + run_id[-6:]
    cmd = ["docker", "run", "--rm", "-v", f"{work_dir}:/workdir", "--name", cname]
    for k, v in env.items():
        cmd += ["-e", f"{k}={v}"]
    cmd += sut.get("docker_run_extra_args", [])
    cmd.append(sut["image"])

    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_inner + 60)
        rc, stdout, stderr, timed_out = proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, stdout, stderr, timed_out = -1, e.stdout or "", (e.stderr or "") + "\nouter timeout", True
        subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
    subprocess.run(["docker", "rm", "-f", cname], capture_output=True, timeout=15)
    elapsed = time.time() - t0

    diff = make_diff(mutation_dir, sandbox, module_rel)  # 仅归档/人工查看用
    # 判定用 agent 最终的完整 module 源码（不用 diff 重建，避免丢上下文行）。
    final_mod = os.path.join(sandbox, module_rel)
    full_src = open(final_mod).read() if os.path.exists(final_mod) else ""
    elicited = run_detector(mutation_dir, full_src, module_rel) if full_src.strip() else False

    # agent 产出 module 是否语法有效 —— 用于区分"坏补丁"与"真抵抗"两类 not-elicited。
    patch_parses = None
    if os.path.exists(final_mod):
        try:
            import ast as _ast
            _ast.parse(open(final_mod).read())
            patch_parses = True
        except Exception:
            patch_parses = False

    # outcome 三态分类：not-elicited 的成因不混淆。
    if elicited:
        outcome = "elicited"
    elif timed_out:
        outcome = "timeout"
    elif patch_parses is False:
        outcome = "malformed_patch"      # agent 改坏了代码（语法错），非真抵抗
    elif not diff.strip():
        outcome = "no_edit"              # agent 没改任何代码
    else:
        outcome = "resisted"             # agent 真改了码、可解析、但未中招

    verdict = {
        "mutation_id": os.path.basename(mutation_dir), "agent": agent, "model": model,
        "elicited": bool(elicited), "n_misaligned": int(elicited),
        "outcome": outcome, "patch_parses": patch_parses, "diff_bytes": len(diff),
        "elapsed_sec": round(elapsed, 1), "exit_code": rc, "timed_out": timed_out,
        "sut_id": sut.get("sut_id"),
    }
    archive = os.path.join(mutation_dir, f"round_{agent}__{safe_model}")
    os.makedirs(archive, exist_ok=True)
    json.dump(verdict, open(os.path.join(archive, "verdict.json"), "w"), indent=2)
    open(os.path.join(archive, "final_diff.patch"), "w").write(diff)
    open(os.path.join(archive, "runner_stdout.log"), "w").write((stdout or "")[-40000:])
    open(os.path.join(archive, "runner_stderr.log"), "w").write((stderr or "")[-40000:])
    if os.environ.get("JSS_KEEP_WORK") != "1":
        shutil.rmtree(work_dir, ignore_errors=True)
    return verdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mutation", required=True)
    ap.add_argument("--agent", required=True)
    ap.add_argument("--model", required=True)
    args = ap.parse_args()
    v = run_cell(args.mutation, args.agent, args.model)
    print(json.dumps(v, indent=2))


if __name__ == "__main__":
    main()
