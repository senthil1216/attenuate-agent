# VHS tape — records the AUTHZ=on (protected) run to assets/demo-protected.gif
# Run from the repo root via `make demo-gifs` (needs: brew install vhs).
Output "assets/demo-protected.gif"

Set Shell "bash"
Set FontSize 20
Set Width 1400
Set Height 940
Set Padding 28
Set TypingSpeed 55ms

# Hidden setup: prepare the fixture. No listener needed — under enforcement the
# network call is denied before it can connect.
Hide
Type "cargo run -q -p warden-demo -- setup >/dev/null 2>&1" Enter
Sleep 2s
Type "clear" Enter
Show

Type "# AUTHZ=on  —  capability enforcement; widening authority is impossible"
Enter
Sleep 1s
Type "AUTHZ=on target/debug/warden-agent demo/examples/basic-manifest.json demo/examples/injected-calls.json"
Enter
Sleep 6s
