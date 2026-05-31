#!/usr/bin/env bash
# 为一个 agent 的 5 个模型各起一个并行 worker。用法: bash launch_agent_parallel.sh <agent>
set -u
AGENT="${1:?need agent}"
cd ~/jss_poison
LITELLM=~/miniconda3/envs/EMNLP_2026_Overeage/bin/litellm
export SIMPLEAI_API_KEY="<YOUR_SIMPLEAI_API_KEY>"
export Z_AI_API_KEY="<YOUR_ZAI_GLM_API_KEY>"
export MINIMAX_API_KEY="<YOUR_MINIMAX_API_KEY>"
export GOOGLE_API_KEY="<YOUR_GOOGLE_API_KEY>"
export SHQBB_API_KEY="<YOUR_SHQBB_API_KEY>"

ensure_proxy () {  # port yaml [clash]
  local port="$1" yaml="$2" clash="${3:-}"
  ss -tln | grep -q ":$port " && { echo ":$port already up"; return; }
  if [ -n "$clash" ]; then
    HTTPS_PROXY=http://127.0.0.1:7890 HTTP_PROXY=http://127.0.0.1:7890 nohup $LITELLM --config ~/jss_poison/litellm_proxies/$yaml --port $port --host 0.0.0.0 > /tmp/litellm_$port.log 2>&1 &
  else
    nohup $LITELLM --config ~/jss_poison/litellm_proxies/$yaml --port $port --host 0.0.0.0 > /tmp/litellm_$port.log 2>&1 &
  fi
  for i in $(seq 1 30); do sleep 1; ss -tln | grep -q ":$port " && break; done
  echo ":$port started"
}

# 按 agent 起对应代理。claude_code=Anthropic surface；codex_cli=OpenAI surface。
if [ "$AGENT" = "claude_code" ]; then
  ensure_proxy 4000 minimax27_anthropic.yaml          # MiniMax → anthropic
  ensure_proxy 4010 shqbb_gpt53_anthropic.yaml        # GPT5    → anthropic
  ensure_proxy 4005 gemini3pro_anthropic.yaml clash   # Gemini  → anthropic (Clash)
elif [ "$AGENT" = "codex_cli" ]; then
  ensure_proxy 4007 glm51_openai.yaml                 # GLM     → openai
  ensure_proxy 4006 gemini3pro_openai.yaml clash      # Gemini  → openai (Clash)
  # MiniMax/Sonnet/GPT5 codex 直连各自端点，无需代理
fi

# 每个模型起 NSHARDS 个并行 worker（分片跑手法列表）→ 单模型吞吐 ×NSHARDS。
# NSHARDS 默认 3（同门项目实测每模型 3 worker 稳定）。5 模型 × 3 shard = 15 并行 worker；
# agent 多在等 LLM 响应（I/O-bound），核数需求不是瓶颈，NAS 12 核 55G 可承载。
NSHARDS="${NSHARDS:-3}"
for M in claude-sonnet-4-6 glm-5.1 MiniMax-M2.7 gpt-5.3-codex gemini-3-pro; do
  SM=$(echo "$M" | tr './' '__')
  for S in $(seq 0 $((NSHARDS-1))); do
    nohup python3 nas_worker.py --agent "$AGENT" --model "$M" --shard "$S" --nshards "$NSHARDS" \
      > /tmp/worker_${AGENT}__${SM}__sh${S}.log 2>&1 &
    echo "worker $AGENT x $M shard $S/$NSHARDS pid=$!"
  done
done
echo "all $((5*NSHARDS)) workers launched for $AGENT (NSHARDS=$NSHARDS)"
