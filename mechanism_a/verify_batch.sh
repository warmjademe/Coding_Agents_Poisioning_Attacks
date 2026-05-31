#!/usr/bin/env bash
cd ~/jss_poison
export SIMPLEAI_API_KEY="<YOUR_SIMPLEAI_API_KEY>"
export CLOSEAI_API_KEY="<YOUR_CLOSEAI_API_KEY>"
export MINIMAX_API_KEY="<YOUR_MINIMAX_API_KEY>"
export SHQBB_API_KEY="<YOUR_SHQBB_API_KEY>"
export GOOGLE_API_KEY="<YOUR_GOOGLE_API_KEY>"
TS=a01_idor__M1_canonical
run() { echo "=== $1 x $2 ==="; JSS_KEEP_WORK=0 timeout 200 python3 nas_run_cell.py --mutation ~/jss_poison/mutations/$TS --agent "$1" --model "$2" 2>&1 | tail -3 | python3 -c "import sys,re;t=sys.stdin.read();m=re.search(r'\"outcome\": \"[^\"]+\"',t);e=re.search(r'\"elicited\": \w+',t);print(m.group(0) if m else 'NO_VERDICT', e.group(0) if e else '')"; }
# gemini_cli 剩余4: sonnet/minimax/gpt5 (gemini-3-pro已知报错跳过)
run gemini_cli claude-sonnet-4-6
run gemini_cli MiniMax-M2.7
run gemini_cli gpt-5.3-codex
# openhands 5
run openhands claude-sonnet-4-6
run openhands glm-5.1
run openhands MiniMax-M2.7
run openhands gpt-5.3-codex
run openhands gemini-3-pro
echo "ALL_VERIFY_DONE"
