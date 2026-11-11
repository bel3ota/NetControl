//! `netcontrol-helper` — the only privileged component.
//!
//! It reads one JSON request from stdin, validates every field, performs a
//! whitelisted nftables/tc operation, and prints one JSON response. It is
//! designed to be the sole command allowed by a narrowly scoped sudoers rule:
//!
//! ```text
//! nova ALL=(root) NOPASSWD: /usr/lib/netcontrol/netcontrol-helper
//! ```

use std::io::Read;
use std::time::Duration;

#[cfg(not(unix))]
fn main() {
    eprintln!("netcontrol-helper is a Linux-only enforcement helper");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    // Reading from a pipe is bounded: a malformed caller cannot feed an
    // unbounded request into a root process.
    let mut input = String::new();
    if std::io::stdin()
        .take(64 * 1024)
        .read_to_string(&mut input)
        .is_err()
    {
        eprintln!("netcontrol-helper: failed to read request");
        std::process::exit(2);
    }
    let request: netcontrol_gateway::linux::HelperRequest = match serde_json::from_str(&input) {
        Ok(request) => request,
        Err(err) => {
            eprintln!("netcontrol-helper: invalid request: {err}");
            std::process::exit(2);
        }
    };
    // Defense in depth: the helper refuses to run unprivileged even if invoked
    // directly, so failures are explicit instead of silently doing nothing.
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("netcontrol-helper: must be executed via the NetControl sudoers rule");
        std::process::exit(3);
    }
    // The underlying implementation is synchronous and short-lived.
    let response = netcontrol_gateway::linux::execute_helper(&request);
    println!(
        "{}",
        serde_json::to_string(&response).unwrap_or_else(|_| {
            "{\"ok\":false,\"verified\":false,\"detail\":\"serialization failure\",\"rule_id\":null,\"data\":null}".into()
        })
    );
    // Give the kernel a moment to flush when run under a serializer; no
    // long-running state is retained.
    std::thread::sleep(Duration::from_millis(1));
}
