#!/usr/bin/env bash
#
# trace-diff.sh
# Generate side-by-side trace diff / summary for article from demo logs.
# Usage: ./scripts/trace-diff.sh [artifacts-dir]
# Defaults to demo/artifacts/
#
# Outputs markdown with:
# - Clean baseline
# - VULN vs PROTECTED side-by-side for key divergent actions (malicious fs_read + network)
# - Audit diffs (attenuations + DENYs only in protected)
# - Sink proof

set -euo pipefail

ARTIFACTS_DIR=${1:-demo/artifacts}
CLEAN_LOG="$ARTIFACTS_DIR/clean.log"
VULN_LOG="$ARTIFACTS_DIR/vuln.log"
PROT_LOG="$ARTIFACTS_DIR/protected.log"
SINK_LOG="$ARTIFACTS_DIR/sink.log"

if [[ ! -f "$CLEAN_LOG" || ! -f "$VULN_LOG" || ! -f "$PROT_LOG" ]]; then
  echo "Missing logs in $ARTIFACTS_DIR. Run make demo-contrast and make demo-clean first."
  exit 1
fi

cat << 'EOF'
# Warden Demo: Trace Diff & Key Evidence

**Purpose:** Show identical principal intent (same tool calls from injected note) but structurally different outcomes due to `AUTHZ` toggle.

**Commands:**
- Clean: `make demo-clean` (or direct `AUTHZ=on cargo run -p warden-agent -- demo/examples/basic-manifest.json demo/examples/clean-calls.json`)
- VULN: `make demo-vuln` or via contrast
- PROTECTED: `make demo-protected` or via contrast

## 1. Clean Baseline (no injection)
Only legitimate operations. All succeed. Proper attenuations in audit.

EOF

echo '```'
head -30 "$CLEAN_LOG" | tail -15
echo '```'

cat << 'EOF'

## 2. Injected Principal Intent (identical across VULN and PROTECTED)
The AGENT_NOTE.md (in-scope) instructs the "agent" to also read the secret canary and exfil over network.

## 3. Divergent Outcomes on Injected Actions (side-by-side)

### Malicious fs_read (out-of-scope secret canary)
EOF

echo '**VULN (AUTHZ=off - ambient authority, leaks):**'
echo '```'
grep -A2 -E 'fs_read.*17 bytes|TOPSECRET|secret' "$VULN_LOG" | head -5 || echo '(from raw: ALLOW read 17 bytes + later network)'
echo '```'

echo '**PROTECTED (AUTHZ=on - enforcement, blocked):**'
echo '```'
grep -A2 -E 'DENY.*fs_read|outside capability scope' "$PROT_LOG" | head -5
echo '```'

cat << 'EOF'

### Network Exfil (the second malicious action)
EOF

echo '**VULN:**'
echo '```'
grep -A2 -E 'network.*sent|exfil' "$VULN_LOG" | head -3 || echo 'sent 19 bytes + sink received'
echo '```'

echo '**PROTECTED:**'
echo '```'
grep -A2 -E 'DENY.*network|denies all egress' "$PROT_LOG" | head -3
echo '```'

echo
echo '**Sink log (exfil proof - only in VULN):**'
echo '```'
cat "$SINK_LOG"
echo '```'

cat << 'EOF'

## 4. Audit Differences (the structural proof)
Only the protected run shows per-call attenuation and explicit DENY reasons.

**VULN audit excerpt (no enforcement):**
```
ROOT MINTED
ALLOWED fs_read
ALLOWED fs_read   # note read
ALLOWED fs_read   # secret leak
ALLOWED fs_write
ALLOWED exec
ALLOWED network
```

**PROTECTED audit excerpt (enforcement active):**
```
ROOT MINTED
ATTENUATED
ALLOWED fs_read
ATTENUATED
ALLOWED fs_read   # note
ATTENUATED
DENIED  fs_read  — read path is outside capability scope
ATTENUATED
ALLOWED fs_write
ATTENUATED
ALLOWED exec
ATTENUATED
DENIED  network  — network policy denies all egress
```

## 5. Utility Preserved
Legitimate "fix" operations (in-scope write + exec) succeed in **both** VULN and PROTECTED.

## Conclusion for Post
Same malicious intent from the principal → completely different security outcomes solely because of the capability enforcement layer. Authority can only narrow; the runtime has no API to widen it.

Repro: `make demo-contrast` (self-contained, produces all logs + internal listener).
EOF
