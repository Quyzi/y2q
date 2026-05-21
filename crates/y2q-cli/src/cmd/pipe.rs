use crate::cmd::cp;
use crate::error::CliError;
use crate::output::OutputMode;

pub async fn run(
    dst: String,
    labels: Vec<String>,
    sync: Option<String>,
    mode: OutputMode,
) -> Result<(), CliError> {
    cp::run("-".to_owned(), dst, labels, sync, false, mode).await
}
