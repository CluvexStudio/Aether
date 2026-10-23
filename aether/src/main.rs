// With the tor feature, the layout of this future takes 130 query levels to compute, past
// the default limit of 128 that Rust 1.99 holds it to ("queries overflow the depth limit");
// Rust 1.98 built it.
#![recursion_limit = "256"]

use std::time::Duration;

fn main() -> aether::error::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(aether::run());
    // A question the core put on the terminal can still be waiting there for a line, a read that
    // no task can stop: the core does not wait for it as it ends. Its tasks are still dropped, Tor
    // and Psiphon with them, given this long to go.
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}
