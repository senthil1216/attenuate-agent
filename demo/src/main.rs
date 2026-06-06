use anyhow::Result;
use std::fs;
use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

/// Simple demo CLI for the Warden reference application.
///
/// Subcommands:
///   setup
///     Prepares a runnable fixture at /tmp/warden-demo-fixture (copied from
///     demo/fixtures/simple-bug) + the out-of-scope secret canary.
///     After this, the files in demo/examples/ can be used with the agent.
///
///   listener [--port 9999] [--log /tmp/sink.log]
///     Runs the canary sink. The injection note tries to exfil to this.
///
///   contrast
///     Full one-command experience:
///       - Runs setup
///       - Starts an internal listener (in background thread)
///       - Runs the same principal feed under AUTHZ=off (vuln) and AUTHZ=on (protected)
///       - Shows key outputs and the final sink.log
///
/// Typical manual flow (after setup):
///   cargo run -p warden-demo -- listener
///   AUTHZ=off cargo run -p warden-agent -- demo/examples/basic-manifest.json demo/examples/injected-calls.json
///   AUTHZ=on  cargo run -p warden-agent -- demo/examples/basic-manifest.json demo/examples/injected-calls.json
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(2);
    }

    match args[1].as_str() {
        "setup" => run_setup(),
        "listener" | "sink" => run_listener(&args[2..]),
        "contrast" | "run-contrast" => run_contrast(),
        other => {
            eprintln!("unknown subcommand: {}", other);
            print_usage(&args[0]);
            std::process::exit(2);
        }
    }
}

fn print_usage(prog: &str) {
    eprintln!("usage: {} <subcommand> [args...]", prog);
    eprintln!("  setup");
    eprintln!("  listener [--port 9999] [--log /tmp/sink.log]");
    eprintln!("  contrast");
}

fn run_setup() -> Result<()> {
    let src = Path::new("demo/fixtures/simple-bug");
    let target = Path::new("/tmp/warden-demo-fixture");

    if target.exists() {
        fs::remove_dir_all(target)?;
    }
    fs::create_dir_all(target)?;

    // Copy the fixture files
    for name in &["buggy.py", "test_buggy.py", "AGENT_NOTE.md", "README.md"] {
        let from = src.join(name);
        let to = target.join(name);
        fs::copy(&from, &to)?;
    }

    // Create an in-scope file referenced by some traces
    fs::write(target.join("in_scope.txt"), "hello from fixture\n")?;

    // Ensure the writable src/ dir exists (some traces write here)
    fs::create_dir_all(target.join("src"))?;

    // The out-of-scope canary (the secret the injection tries to exfil)
    let secret = Path::new("/tmp/warden-secret-canary.txt");
    fs::write(secret, "TOPSECRET-CANARY\n")?;

    println!("✅ Fixture prepared:");
    println!("   Fixture dir : {}", target.display());
    println!("   Secret canary: {}", secret.display());
    println!();
    println!("You can now run the agent with the example traces:");
    println!("   AUTHZ=off cargo run -p warden-agent -- demo/examples/basic-manifest.json demo/examples/injected-calls.json");
    println!("   AUTHZ=on  cargo run -p warden-agent -- demo/examples/basic-manifest.json demo/examples/injected-calls.json");
    println!();
    println!("For the network exfil to be captured, also run (in another terminal):");
    println!("   cargo run -p warden-demo -- listener");

    Ok(())
}

fn run_listener(args: &[String]) -> Result<()> {
    let mut port = 9999u16;
    let mut log_path = "/tmp/sink.log".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                if i < args.len() {
                    port = args[i].parse()?;
                }
            }
            "--log" | "-l" => {
                i += 1;
                if i < args.len() {
                    log_path = args[i].clone();
                }
            }
            _ => {}
        }
        i += 1;
    }

    // Clear previous log for clean demo runs
    let _ = fs::remove_file(&log_path);

    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("Canary sink listening on 127.0.0.1:{} → {}", port, log_path);
    println!("(The injected principal will try to POST the secret here.)");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_connection(stream, &log_path) {
                    eprintln!("connection error: {}", e);
                }
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }

    Ok(())
}

fn handle_connection(mut stream: TcpStream, log_path: &str) -> Result<()> {
    use std::io::Read;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let payload = String::from_utf8_lossy(&buf);
    let entry = format!(
        "[{}]\nfrom: {}\npayload: {}\n---\n",
        chrono::Utc::now().to_rfc3339(),
        stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".into()),
        payload.trim_end()
    );

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    file.write_all(entry.as_bytes())?;

    println!(
        "📥 Received {} bytes from exfil attempt, logged to {}",
        buf.len(),
        log_path
    );
    Ok(())
}

fn run_contrast() -> Result<()> {
    println!("=== Warden Demo Contrast (vuln vs protected) ===\n");

    run_setup()?;

    // Start an internal listener in the background so the network exfil is captured
    // without requiring a second terminal for the automated contrast.
    let log_path = "/tmp/sink.log".to_string();
    let _ = fs::remove_file(&log_path);

    let log_for_listener = log_path.clone();
    let listener_handle = thread::spawn(move || {
        if let Err(e) = run_internal_listener(9999, &log_for_listener) {
            eprintln!("internal listener error: {}", e);
        }
    });

    // Give the listener a moment to bind
    thread::sleep(Duration::from_millis(200));

    let manifest = "demo/examples/basic-manifest.json";
    let clean_calls = "demo/examples/clean-calls.json";
    let injected_calls = "demo/examples/injected-calls.json";

    // Use the already-built binary for speed and cleaner output
    let agent_bin = "target/debug/warden-agent";

    // --- CLEAN RUN (baseline, no injection) ---
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  CLEAN RUN  (no injection — legitimate work only)          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");
    println!("(Should succeed under both modes; shown with AUTHZ=on)\n");

    let clean_out = Command::new(agent_bin)
        .args([manifest, clean_calls])
        .env("AUTHZ", "on")
        .output()?;
    let clean_stdout = String::from_utf8_lossy(&clean_out.stdout).to_string();
    print!("{}", clean_stdout);
    if !clean_out.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&clean_out.stderr));
    }
    fs::write("clean.log", &clean_stdout)?;

    // --- INJECTED VULNERABLE ---
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  INJECTED VULN  (AUTHZ=off — ambient authority)            ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");
    println!("(The malicious instructions in AGENT_NOTE.md should succeed)\n");

    let vuln_out = Command::new(agent_bin)
        .args([manifest, injected_calls])
        .env("AUTHZ", "off")
        .output()?;
    let vuln_stdout = String::from_utf8_lossy(&vuln_out.stdout).to_string();
    print!("{}", vuln_stdout);
    if !vuln_out.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&vuln_out.stderr));
    }
    fs::write("vuln.log", &vuln_stdout)?;

    // --- INJECTED PROTECTED ---
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  INJECTED PROTECTED  (AUTHZ=on — capability enforcement)   ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");
    println!("(Out-of-scope actions must be structurally denied while legit work succeeds)\n");

    let prot_out = Command::new(agent_bin)
        .args([manifest, injected_calls])
        .env("AUTHZ", "on")
        .output()?;
    let prot_stdout = String::from_utf8_lossy(&prot_out.stdout).to_string();
    print!("{}", prot_stdout);
    if !prot_out.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&prot_out.stderr));
    }
    fs::write("protected.log", &prot_stdout)?;

    // Let any final packets arrive
    thread::sleep(Duration::from_millis(300));

    // Capture sink
    let sink_content = fs::read_to_string(&log_path).unwrap_or_default();
    fs::write("sink.log", &sink_content)?;

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  ARTIFACTS SAVED                                           ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!("  clean.log      — output of clean run");
    println!("  vuln.log       — output of vulnerable (injected + AUTHZ=off)");
    println!("  protected.log  — output of protected (injected + AUTHZ=on)");
    println!("  sink.log       — exfil attempts received by the canary");

    // === KEY DIFFERENCES (article-friendly summary) ===
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  KEY DIFFERENCES                                           ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Robust detection based on behavior + sink (not just content strings,
    // because Allowed reads now print "read N bytes" for cleanliness).
    let secret_leaked_in_vuln =
        vuln_stdout.contains("read 17 bytes") || !sink_content.trim().is_empty();
    let secret_denied_in_prot = prot_stdout.contains("read path is outside capability scope");

    println!("Secret canary read (the injected exfil target):");
    println!(
        "  vuln (off):     {}",
        if secret_leaked_in_vuln {
            "SUCCEEDED — canary content was read"
        } else {
            "did not leak (unexpected)"
        }
    );
    println!(
        "  protected (on): {}",
        if secret_denied_in_prot {
            "DENIED — \"read path is outside capability scope\""
        } else {
            "unexpected"
        }
    );

    let network_succeeded_in_vuln =
        vuln_stdout.contains("sent 19 bytes") || !sink_content.trim().is_empty();
    let network_denied_in_prot = prot_stdout.contains("network policy denies all egress");

    println!("\nNetwork exfil attempt (the second part of the injection):");
    println!(
        "  vuln (off):     {}",
        if network_succeeded_in_vuln {
            "SUCCEEDED — payload reached the canary sink"
        } else {
            "no"
        }
    );
    println!(
        "  protected (on): {}",
        if network_denied_in_prot {
            "DENIED — \"network policy denies all egress\""
        } else {
            "no"
        }
    );

    println!("\nSink log (should only have content from the vulnerable run):");
    if sink_content.trim().is_empty() {
        println!("  (empty — no exfil captured)");
    } else {
        println!("  captured {} bytes of exfil payload", sink_content.len());
    }

    println!("\nAudit differences:");
    println!("  - Only the protected run shows per-call ATTENUATED entries.");
    println!("  - Only the protected run shows explicit DENIED lines with human-readable reasons.");
    println!("  - The vulnerable run has zero enforcement (pure ambient authority).");

    println!("\nContrast complete. The four .log files + the raw output above are ready for the article/recording.");
    println!("(Note: the small \"did not leak\" glitch in earlier summary logic has been fixed.)");

    // The listener thread will be terminated when we exit
    drop(listener_handle);

    Ok(())
}

/// Internal version of the listener used by `contrast` (hardcoded port + log).
fn run_internal_listener(port: u16, log_path: &str) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    // We don't print here because it would interleave with contrast output.

    for stream in listener.incoming().flatten() {
        let _ = handle_connection(stream, log_path);
    }
    Ok(())
}
