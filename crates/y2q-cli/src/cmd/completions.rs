use clap::CommandFactory;
use clap_complete::Shell;

use crate::cli::Cli;

pub fn run(shell: Shell) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
}
