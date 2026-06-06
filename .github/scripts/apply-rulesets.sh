#!/usr/bin/env bash
#
# Apply repository rulesets defined in .github/rulesets/*.json to the GitHub repo.
#
# Usage:
#   ./apply-rulesets.sh
#
# Requirements:
#   - GitHub CLI (gh) authenticated with repo admin rights
#   - jq (for parsing existing rulesets)
#
# This script will:
#   - For each JSON definition, create the ruleset if it doesn't exist by name,
#     or update (PATCH) it if a ruleset with the same name already exists.
#
# After changes to a ruleset JSON, re-run this script (or call it from CI if desired).
#

set -euo pipefail

REPO="senthil1216/attenuate-agent"
RULESETS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../rulesets" && pwd)"

if ! command -v gh >/dev/null 2>&1; then
  echo "Error: gh CLI is required." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required for this script." >&2
  exit 1
fi

echo "Fetching current rulesets for ${REPO}..."
EXISTING=$(gh api "repos/${REPO}/rulesets" --jq '.[] | {id, name}' 2>/dev/null || echo "")

for file in "${RULESETS_DIR}"/*.json; do
  [ -e "$file" ] || continue

  name=$(jq -r '.name' "$file")
  echo "Processing ruleset: $name (from $(basename "$file"))"

  # Find existing id by name
  existing_id=$(echo "$EXISTING" | jq -r --arg n "$name" 'select(.name == $n) | .id' | head -n1 || true)

  if [ -n "$existing_id" ] && [ "$existing_id" != "null" ]; then
    echo "  -> Updating existing ruleset id=$existing_id"
    gh api "repos/${REPO}/rulesets/${existing_id}" \
      --method PUT \
      --input "$file" \
      --silent
    echo "  Updated."
  else
    echo "  -> Creating new ruleset"
    gh api "repos/${REPO}/rulesets" \
      --method POST \
      --input "$file" \
      --silent
    echo "  Created."
  fi
done

echo "All rulesets applied successfully."
echo "Verify at: https://github.com/${REPO}/settings/rules"
