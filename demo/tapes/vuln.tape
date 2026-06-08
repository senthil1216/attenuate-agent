# VHS tape — records the AUTHZ=off (vulnerable) run to assets/demo-vuln.gif
# Run from the repo root via `make demo-gifs` (needs: brew install vhs).
Output "assets/demo-vuln.gif"

Set Shell "bash"
Set FontSize 20
Set Width 1400
Set Height 760
Set Padding 28
Set TypingSpeed 55ms

# Hidden setup: prepare the fixture + a background canary listener so the
# network exfil shows "sent N bytes" rather than connection-refused.
Hide
Type "cargo run -q -p warden-demo -- setup >/dev/null 2>&1" Enter
Sleep 2s
Type "target/debug/warden-demo listener >/dev/null 2>&1 &" Enter
Sleep 800ms
Type "clear" Enter
Show

Type "# AUTHZ=off  —  the agent runs with full ambient authority"
Enter
Sleep 1s
Type "AUTHZ=off target/debug/warden-agent demo/examples/basic-manifest.json demo/examples/injected-calls.json"
Enter
Sleep 6s

Hide
Type "kill %1 2>/dev/null" Enter
Show
