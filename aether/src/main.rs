// With the tor feature, the layout of this future takes 130 query levels to compute, past
// the default limit of 128 that Rust 1.99 holds it to ("queries overflow the depth limit");
// Rust 1.98 built it.
#![recursion_limit = "256"]

#[tokio::main]
async fn main() -> aether::error::Result<()> {
    aether::run().await
}
