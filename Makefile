# Warden Demo Harness Makefile
# Run `make help` for available targets.

.PHONY: help demo-setup demo-listener demo-contrast demo-clean demo-vuln demo-protected clean-artifacts

help:
	@echo "Warden Demo targets:"
	@echo "  make demo-setup       - Prepare /tmp fixture + secret canary"
	@echo "  make demo-listener    - Start the canary sink (in foreground)"
	@echo "  make demo-contrast    - Full automated contrast (clean + injected-vuln + injected-protected)"
	@echo "  make demo-clean       - Run clean (no injection) scenario"
	@echo "  make demo-vuln        - Run injected + AUTHZ=off (vulnerable baseline)"
	@echo "  make demo-protected   - Run injected + AUTHZ=on (enforced)"
	@echo "  make clean-artifacts  - Remove generated .log files"

demo-setup:
	cargo run -p warden-demo -- setup

demo-listener:
	cargo run -p warden-demo -- listener

demo-contrast:
	cargo run -p warden-demo -- contrast

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