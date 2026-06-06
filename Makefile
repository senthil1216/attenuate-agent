# Warden Demo Harness Makefile
# Run `make help` for available targets.

.PHONY: help demo-setup demo-listener demo-contrast demo-contrast-live demo-clean demo-vuln demo-protected clean-artifacts demo-asciinema

help:
	@echo "Warden Demo targets:"
	@echo "  make demo-setup       - Prepare /tmp fixture + secret canary"
	@echo "  make demo-listener    - Start the canary sink (in foreground)"
	@echo "  make demo-contrast    - Full automated contrast (clean + injected-vuln + injected-protected)"
	@echo "  make demo-contrast-live - Live contrast: a real model emits the calls (needs BASE_URL/MODEL)"
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
	@echo "Live contrast — drives a real model. Validate determinism first via spikes/ds4-determinism."
	cargo run -p warden-demo -- contrast --live

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