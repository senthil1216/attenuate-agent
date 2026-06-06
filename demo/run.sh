#!/usr/bin/env bash
#
# demo/run.sh
# One-command helper for the full Warden demo experience.
# Handles listener in background, runs contrast, captures bundle.
#
# Usage:
#   ./demo/run.sh [contrast|clean|vuln|protected]
#
# If no arg, runs full contrast.

set -euo pipefail

MODE=${1:-contrast}
BUNDLE_DIR="demo/artifacts/$(date +%Y-%m-%d_%H%M%S)"
mkdir -p "$BUNDLE_DIR"

echo "=== Warden Demo Run ($MODE) ==="
echo "Artifacts will be saved to $BUNDLE_DIR"

# Ensure listener is available (start in background if doing contrast)
if [[ "$MODE" == "contrast" ]]; then
  echo "Starting internal listener (for network exfil capture)..."
  # The contrast binary already starts an internal listener when run as 'contrast'.
  # This script is for manual orchestration or future enhancement.
fi

case "$MODE" in
  contrast)
    cargo run -p warden-demo -- contrast 2>&1 | tee "$BUNDLE_DIR/contrast.log"
    ;;
  clean)
    make demo-clean 2>&1 | tee "$BUNDLE_DIR/clean.log"
    ;;
  vuln)
    make demo-vuln 2>&1 | tee "$BUNDLE_DIR/vuln.log"
    ;;
  protected)
    make demo-protected 2>&1 | tee "$BUNDLE_DIR/protected.log"
    ;;
  *)
    echo "Unknown mode: $MODE"
    echo "Valid: contrast, clean, vuln, protected"
    exit 1
    ;;
esac

# Copy generated logs if present
for f in clean.log vuln.log protected.log sink.log; do
  if [[ -f "$f" ]]; then
    cp "$f" "$BUNDLE_DIR/"
  fi
done

echo
echo "=== Run complete ==="
echo "Bundle saved to: $BUNDLE_DIR"
echo "Key files:"
ls -l "$BUNDLE_DIR/"

# Optional: run trace diff if available
if command -v ./scripts/trace-diff.sh >/dev/null 2>&1; then
  echo
  echo "Generating trace diff summary..."
  ./scripts/trace-diff.sh demo/artifacts > "$BUNDLE_DIR/trace-diff.md" 2>/dev/null || true
  echo "See $BUNDLE_DIR/trace-diff.md"
fi

echo
echo "Ready for recording or post. Suggested next:"
echo "  asciinema rec demo-${MODE}.cast --overwrite"
echo "  # re-run the above command"
echo "  # Ctrl-D to stop"
