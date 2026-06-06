#!/usr/bin/env bash
#
# M0 Spike A — principal determinism.
#
# Sends the SAME chat-completion request N times at temperature 0 with a fixed
# seed against an OpenAI-compatible endpoint, extracts the emitted tool call,
# and asserts every run is byte-identical. This is the precondition for the
# demo's scientific control: "same model intent, only enforcement varies".
#
# Usage:
#   BASE_URL=http://127.0.0.1:8000/v1 MODEL=ds4-flash API_KEY=sk-... ./run.sh
#
# Defaults assume a local server with no auth.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000/v1}"
MODEL="${MODEL:-ds4-flash}"
API_KEY="${API_KEY:-no-key}"
RUNS="${RUNS:-3}"
SEED="${SEED:-42}"
OUTDIR="$(mktemp -d)"

command -v jq >/dev/null || { echo "FAIL: jq is required (brew install jq)"; exit 1; }

read -r -d '' BODY <<JSON || true
{
  "model": "${MODEL}",
  "temperature": 0,
  "top_p": 1,
  "seed": ${SEED},
  "messages": [
    {"role": "system", "content": "You are a coding agent. Use the provided tools."},
    {"role": "user", "content": "Read the file ./README.md to begin the task."}
  ],
  "tools": [{
    "type": "function",
    "function": {
      "name": "fs_read",
      "description": "Read a file from the repository.",
      "parameters": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"]
      }
    }
  }],
  "tool_choice": "auto"
}
JSON

echo "endpoint : ${BASE_URL}"
echo "model    : ${MODEL}  (temperature=0, seed=${SEED})"
echo "runs     : ${RUNS}"
echo

for i in $(seq 1 "${RUNS}"); do
  curl -sS "${BASE_URL}/chat/completions" \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d "${BODY}" \
  | jq -S '.choices[0].message.tool_calls // .choices[0].message.content' \
  > "${OUTDIR}/run_${i}.json"
  echo "run ${i}: $(tr -d '\n' < "${OUTDIR}/run_${i}.json" | cut -c1-100)"
done

echo
if find "${OUTDIR}" -name 'run_*.json' -exec md5 -q {} \; 2>/dev/null | sort -u | wc -l | grep -q '^ *1$' \
   || find "${OUTDIR}" -name 'run_*.json' -exec md5sum {} \; 2>/dev/null | awk '{print $1}' | sort -u | wc -l | grep -q '^1$'; then
  echo "PASS: all ${RUNS} runs emitted a byte-identical tool call."
  echo "      -> deterministic decoding holds; the demo control is valid."
else
  echo "FAIL: tool calls differ across runs."
  echo "      -> determinism does NOT hold. Trigger the README fallback binding"
  echo "         path (constrained/grammar decoding or a recorded transcript)."
  exit 1
fi
echo "artifacts: ${OUTDIR}"
