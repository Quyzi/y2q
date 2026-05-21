use crate::cmd::{cp, objects};
use crate::error::CliError;
use crate::output::OutputMode;
use crate::path::CpEndpoint;

pub async fn run(
    src: String,
    dst: String,
    labels: Vec<String>,
    sync: Option<String>,
    mode: OutputMode,
) -> Result<(), CliError> {
    let src_ep = CpEndpoint::parse(&src);

    // Copy first; only delete the source if the copy succeeded.
    cp::run(src.clone(), dst.clone(), labels, sync, false, mode).await?;

    match src_ep {
        CpEndpoint::Remote(_) => objects::rm(src, true, mode).await,
        CpEndpoint::Local(local) => {
            if local == "-" {
                return Err(CliError::Other("cannot move from stdin".into()));
            }
            tokio::fs::remove_file(&local).await.map_err(CliError::Io)
        }
    }
}
