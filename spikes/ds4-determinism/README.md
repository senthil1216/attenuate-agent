# Spike A — principal determinism (M0)

**Question this answers:** does the chosen local principal emit a *byte-identical*
tool call when given the same prompt at temperature 0 + fixed seed?

**Why it matters:** the demo's headline is "same model intent, enforcement off vs
on → attack succeeds vs structurally denied." That comparison is only honest if
the model's tool calls don't drift between runs. Determinism is the scientific
control. If it fails, the whole off/on diff is confounded.

## Run

```sh
# point at any OpenAI-compatible endpoint (DS4 Flash, Kimi, vLLM, etc.)
BASE_URL=http://127.0.0.1:8000/v1 MODEL=ds4-flash API_KEY=sk-... ./run.sh
```

Requires `curl` and `jq`.

## Outcomes

- **PASS** → determinism holds. Proceed; the demo control is valid.
- **FAIL** → tool calls differ across runs. Trigger the README's named fallback:
  constrained/grammar decoding to pin the tool-call shape, or record one
  canonical transcript and replay it as the scripted adversary. Decide this in
  week 1 — not week 3.

## Notes / gotchas

- Not every server honours `seed`. If yours ignores it, determinism may still
  hold from temperature 0 + greedy alone — but verify, don't assume.
- This only checks *decoding* determinism. Tool-call *binding* (how the server
  maps the function call to an ID/arguments) is the second half of the README's
  "DS4 tool-binding" risk — eyeball the raw `tool_calls` array shape too.
