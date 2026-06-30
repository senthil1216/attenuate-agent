# Warden Demo Harness Makefile
# Run `make help` for available targets.

.PHONY: help demo-setup demo-listener demo-contrast demo-contrast-live demo-contrast-live-zai demo-clean demo-vuln demo-protected clean-artifacts demo-asciinema demo-gifs

help:
	@echo "Warden Demo targets:"
	@echo "  make demo-setup       - Prepare /tmp fixture + secret canary"
	@echo "  make demo-listener    - Start the canary sink (in foreground)"
	@echo "  make demo-contrast    - Full automated contrast (clean + injected-vuln + injected-protected)"
	@echo "  make demo-contrast-live    - Live contrast: a real model emits the calls (needs BASE_URL/MODEL)"
	@echo "                           (scripted demo-contrast is the scientific control; live adds realism)"
	@echo "  make demo-contrast-live-zai - Live contrast against Z.AI GLM (needs API_KEY)"
	@echo "                           (sets BASE_URL/MODEL for you; scripted control still runs first)"
	@echo "  make demo-gifs        - Render split per-run GIFs (assets/demo-vuln.gif + demo-protected.gif; needs vhs)"
	@echo "  make demo-clean       - Run clean (no injection) scenario"
	@echo "  make demo-vuln        - Run injected + AUTHZ=off (vulnerable baseline)"
	@echo "  make demo-protected   - Run injected + AUTHZ=on (enforced)"
	@echo "  make clean-artifacts  - Remove generated .log files"
	@echo "  make demo-asciinema   - Record AUTHZ=off|on contrast (pre-LLM capability layer demo for article)"
	@echo "                        (requires 'asciinema' command; target will suggest install if missing)"

demo-setup:
	cargo run -p warden-demo -- setup

demo-listener:
	cargo run -p warden-demo -- listener

demo-contrast:
	cargo run -p warden-demo -- contrast

demo-contrast-live:
	@echo "Live contrast — drives a real model (needs BASE_URL/MODEL)."
	@echo "NOTE: scripted demo-contrast is the scientific control (byte-identical off/on)."
	@echo "This live run adds REALISM: a real model is actually prompt-injected and actually denied."
	@echo "Determinism is NOT required — the defense never inspects the principal."
	cargo run -p warden-demo -- contrast --live

# Convenience wrapper for Z.AI (Zhipu) GLM models. Sets BASE_URL/MODEL; you only
# supply API_KEY. Hosted GLM may not be byte-deterministic at temp=0 — that is
# fine: the scripted demo-contrast is the control; this run demonstrates a real
# principal being structurally contained.
demo-contrast-live-zai:
	@test -n "$$API_KEY" || { echo "Error: set API_KEY first, e.g. API_KEY=sk-... make demo-contrast-live-zai"; exit 1; }
	@echo "Live contrast against Z.AI GLM-4.6 (scripted control runs first for the clean off/on diff)."
	BASE_URL=https://api.z.ai/api/paas/v4 MODEL=glm-4.6 cargo run -p warden-demo -- contrast --live

demo-clean:
	@echo "=== CLEAN (no injection) ==="
	AUTHZ=on cargo run -p warden-agent -- demo/examples/basic-manifest.json demo/examples/clean-calls.json

demo-vuln:
	@echo "=== INJECTED VULN (AUTHZ=off) ==="
	AUTHZ=off cargo run -p warden-agent -- demo/examples/basic-manifest.json demo/examples/injected-calls.json

demo-protected:
	@echo "=== INJECTED PROTECTED (AUTHZ=on) ==="
	AUTHZ=on cargo run -p warden-agent -- demo/examples/basic-manifest.json demo/examples/injected-calls.json

clean-artifacts:
	rm -f clean.log vuln.log protected.log sink.log
	@echo "Removed generated log artifacts."

demo-asciinema:
	@command -v asciinema >/dev/null 2>&1 || { \
		echo >&2 "Error: 'asciinema' command not found."; \
		echo >&2 "Install it with:"; \
		echo >&2 "  macOS:   brew install asciinema"; \
		echo >&2 "  Linux:   sudo apt install asciinema  # or equivalent"; \
		echo >&2 "  Python:  pip install asciinema"; \
		echo >&2 "Then re-run: make demo-asciinema"; \
		exit 1; \
	}
	@echo "Recording AUTHZ=off|on contrast (capability-layer version, before LLM wiring — de-risks M3 narrative)"
	asciinema rec -c "cargo run -p warden-demo -- contrast" --overwrite demo-contrast.cast
	@echo "Recording saved to demo-contrast.cast"
	@echo "Play with: asciinema play demo-contrast.cast"
	@echo "(Tip: also record 'make demo-clean' for baseline if desired)"

demo-gifs:
	@command -v vhs >/dev/null 2>&1 || { echo "vhs not found — install with: brew install vhs"; exit 1; }
	cargo build -q -p warden-agent -p warden-demo
	vhs demo/tapes/vuln.tape
	vhs demo/tapes/protected.tape
	@echo "Wrote assets/demo-vuln.gif and assets/demo-protected.gif"
