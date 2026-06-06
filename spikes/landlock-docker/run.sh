#!/usr/bin/env bash
#
# M0 Spike B — Landlock + seccomp containment inside Docker.
set -euo pipefail
cd "$(dirname "$0")"

docker build -t warden-landlock-spike .

echo
echo "=== Run 1: Docker default seccomp profile ==="
echo "(this may FAIL at the seccomp step if Docker's default profile blocks the"
echo " seccomp() syscall itself — that's the documented gotcha, not a real failure)"
if docker run --rm warden-landlock-spike; then
  echo ">> default-profile run passed."
  exit 0
fi

echo
echo "=== Run 2: container seccomp unconfined (app installs its OWN filter) ==="
echo "(Landlock + the app's seccomp filter still apply — we only relax Docker's"
echo " OUTER profile so the app is allowed to call seccomp() at all)"
docker run --rm --security-opt seccomp=unconfined warden-landlock-spike
