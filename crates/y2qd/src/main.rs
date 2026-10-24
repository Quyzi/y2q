//! `y2qd` — HTTP daemon for the y2q post-quantum secure object store.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    y2qd::run().await
}
