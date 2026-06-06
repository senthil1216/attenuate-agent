//! M0 Spike B — does OS-level containment actually bite inside our container?
//!
//! Applies a Landlock ruleset (filesystem reads confined to `/allowed`) and a
//! seccomp filter (block `socket()`), then proves a disallowed read returns
//! EACCES and a network connect is refused. If this passes inside Docker, the
//! Phase 4 sandbox crate has a real foundation to build on.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::net::TcpStream;

use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

fn main() {
    let mut failures = 0u32;

    // ---- Landlock: confine filesystem reads to /allowed ----------------------
    fs::create_dir_all("/allowed").expect("create /allowed");
    fs::write("/allowed/ok.txt", "in scope").expect("seed in-scope file");

    let abi = ABI::V1;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .unwrap()
        .create()
        .unwrap()
        .add_rules(path_beneath_rules(["/allowed"], AccessFs::from_read(abi)))
        .unwrap()
        .restrict_self()
        .unwrap();

    match status.ruleset {
        RulesetStatus::FullyEnforced => println!("landlock : fully enforced"),
        RulesetStatus::PartiallyEnforced => println!("landlock : PARTIALLY enforced (kernel ABI gap)"),
        RulesetStatus::NotEnforced => {
            println!("landlock : NOT enforced (kernel < 5.13 or Landlock disabled)");
            failures += 1;
        }
    }

    match fs::read_to_string("/allowed/ok.txt") {
        Ok(_) => println!("PASS     : in-scope read of /allowed/ok.txt allowed"),
        Err(e) => {
            println!("FAIL     : in-scope read blocked: {e}");
            failures += 1;
        }
    }

    match fs::read_to_string("/etc/hostname") {
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            println!("PASS     : out-of-scope read of /etc/hostname denied (EACCES)")
        }
        Ok(_) => {
            println!("FAIL     : out-of-scope read SUCCEEDED — Landlock is not containing");
            failures += 1;
        }
        Err(e) => {
            println!("FAIL     : out-of-scope read gave unexpected error: {e}");
            failures += 1;
        }
    }

    // ---- seccomp: block socket() so egress is impossible ---------------------
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_socket, vec![]);
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                     // default: allow
        SeccompAction::Errno(libc::EPERM as u32), // socket(): EPERM
        std::env::consts::ARCH.try_into().unwrap(),
    )
    .unwrap();
    let program: BpfProgram = filter.try_into().unwrap();
    seccompiler::apply_filter(&program).expect("apply seccomp filter");

    match TcpStream::connect("1.1.1.1:80") {
        Err(_) => println!("PASS     : network egress blocked by seccomp"),
        Ok(_) => {
            println!("FAIL     : socket connect SUCCEEDED — seccomp is not blocking");
            failures += 1;
        }
    }

    if failures == 0 {
        println!("\nSPIKE PASS: Landlock + seccomp both contain inside this container.");
    } else {
        println!("\nSPIKE FAIL: {failures} check(s) failed — see the Docker seccomp gotcha in README.md.");
        std::process::exit(1);
    }
}
