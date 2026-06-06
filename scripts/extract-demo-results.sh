#!/usr/bin/env bash
#
# extract-demo-results.sh
#
# Helper to archive and format demo run artifacts for articles / posts.
#
# Usage:
#   ./scripts/extract-demo-results.sh [run-name]
#
# Example:
#   ./scripts/extract-demo-results.sh 2026-06-06-contrast
#
# It will:
#   - Copy the generated .log files into demo/artifacts/<run-name>/
#   - Generate a timestamped summary.md with key excerpts
#   - Optionally suggest commands for recording

set -euo pipefail

RUN_NAME=${1:-$(date +%Y-%m-%d-demo)}
ARTIFACT_DIR="demo/artifacts/${RUN_NAME}"
mkdir -p "${ARTIFACT_DIR}"

echo "Archiving demo artifacts to ${ARTIFACT_DIR}..."

# Copy logs if they exist
for log in clean.log vuln.log protected.log sink.log; do
  if [[ -f "$log" ]]; then
    cp "$log" "${ARTIFACT_DIR}/"
    echo "  copied $log"
  fi
done

# Copy any other interesting files
cp -r demo/examples "${ARTIFACT_DIR}/" 2>/dev/null || true
cp -r demo/fixtures "${ARTIFACT_DIR}/" 2>/dev/null || true

# Generate a small summary
cat > "${ARTIFACT_DIR}/summary.md" << 'SUMMARY'
# Demo Run Summary

**Run:** RUN_NAME_PLACEHOLDER  
**Date:** $(date -Iseconds)  
**Command(s):**  
- `make demo-contrast`  
- `make demo-clean`

## Key Files
- clean.log
- vuln.log
- protected.log
- sink.log

See `demo/artifacts/demo-results.md` for a polished, post-ready version of the results.

## Quick Verification
- Clean run: only in-scope operations succeeded.
- VULN: secret read + network exfil succeeded; payload reached sink.
- PROTECTED: out-of-scope actions denied with named reasons in audit; legitimate work succeeded; sink empty.

## Next
- Re-generate `demo/artifacts/demo-results.md` if logs changed.
- Update the article with the latest excerpts.
SUMMARY

# Replace placeholder
sed -i '' "s|RUN_NAME_PLACEHOLDER|${RUN_NAME}|g" "${ARTIFACT_DIR}/summary.md" 2>/dev/null || \
  sed -i "s|RUN_NAME_PLACEHOLDER|${RUN_NAME}|g" "${ARTIFACT_DIR}/summary.md"

echo "Done. Artifacts in ${ARTIFACT_DIR}"
echo "Consider committing the summary + key logs (or a subset) for the post."
echo
echo "To record:"
echo "  asciinema rec demo-${RUN_NAME}.cast --overwrite"
echo "  make demo-contrast"
echo "  # Ctrl-D to stop recording"