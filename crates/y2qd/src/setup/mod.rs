//! `y2qd setup`: interactive setup wizard.
//!
//! Scans this host, walks the operator through service configuration and the
//! node-key authority, creates directories with the right modes, optionally
//! installs the `deploy/` systemd units and writes the config file.
//!
//! Everything but [`run`] and [`sanitize`] is Linux-only: release CI builds
//! macOS and Windows, where `y2qd setup` reports that it needs Linux.

use std::io;

use crate::cli::Cli;

#[cfg(target_os = "linux")]
mod answers;
#[cfg(target_os = "linux")]
mod apply;
#[cfg(target_os = "linux")]
mod authority;
#[cfg(target_os = "linux")]
mod config_doc;
#[cfg(target_os = "linux")]
mod existing;
#[cfg(target_os = "linux")]
mod scan;
#[cfg(target_os = "linux")]
mod sys;
#[cfg(target_os = "linux")]
mod term;
#[cfg(target_os = "linux")]
mod ui;
#[cfg(target_os = "linux")]
mod units;
#[cfg(target_os = "linux")]
mod validate;
#[cfg(target_os = "linux")]
mod wizard;

/// Replace every control character (C0, DEL, C1) and Unicode format character
/// (bidi overrides, zero-width joiners, tag characters, ...) with a visible
/// `\u{..}` escape. All TUI text and all plain output pass through this: a path
/// or error string may come from the filesystem or the environment and must not
/// be able to move the cursor, retitle the window or reorder what the operator
/// reads.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || is_format_char(c) {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Unicode general category Cf (plus the line/paragraph separators Zl/Zp).
fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD
        | 0x0600..=0x0605
        | 0x061C
        | 0x06DD
        | 0x070F
        | 0x0890..=0x0891
        | 0x08E2
        | 0x180E
        | 0x200B..=0x200F
        | 0x2028..=0x202E
        | 0x2060..=0x2064
        | 0x2066..=0x206F
        | 0xFEFF
        | 0xFFF9..=0xFFFB
        | 0x110BD
        | 0x110CD
        | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A
        | 0xE0001
        | 0xE0020..=0xE007F)
}

#[cfg(not(target_os = "linux"))]
pub fn run(_cli: &Cli) -> io::Result<()> {
    Err(io::Error::other("`y2qd setup` requires Linux"))
}

#[cfg(target_os = "linux")]
pub fn run(cli: &Cli) -> io::Result<()> {
    use std::io::IsTerminal;
    use std::path::Path;

    use y2q_core::secmem::{self, Policy};

    use self::answers::Answers;
    use self::existing::{ExistingInstall, PathPair};
    use self::validate::RealProbes;
    use self::wizard::{Init, Outcome, Reaction, Wizard};

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::other(
            "y2qd setup is interactive and needs a terminal on stdin and stdout",
        ));
    }
    // Secret-bearing variables are never read by setup; refusing them makes
    // every env-reading call inside setup vacuous.
    for var in scan::REFUSED_ENV {
        if std::env::var_os(var).is_some() {
            return Err(io::Error::other(format!(
                "{var} is set; unset it before running setup (setup never reads secrets from the environment)"
            )));
        }
    }
    // BestEffort: `Require` would abort on exactly the hosts the scan diagnoses.
    secmem::harden_process(Policy::BestEffort)
        .map_err(|e| io::Error::other(format!("secmem: {e}")))?;

    let config_path = answers::normalize(cli.config.as_deref().unwrap_or(Path::new("config.toml")));
    let existing_text = match std::fs::read_to_string(&config_path) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(_) => None,
    };
    let doc = existing_text
        .as_deref()
        .and_then(|t| t.parse::<toml_edit::DocumentMut>().ok());
    let tcti = doc.as_ref().and_then(|d| {
        d.get("crypto")?
            .get("devices")?
            .get("tpm_tcti")?
            .as_str()
            .map(str::to_owned)
    });

    // Every probe runs before the TUI owns the screen.
    let facts = scan::collect(tcti.as_deref());
    let probes = RealProbes;
    let defaults = Answers::defaults(&facts, &probes, &config_path);
    let (answers, base_text) = match (&doc, &existing_text) {
        (Some(d), Some(t)) => (
            Answers::from_doc(d, defaults.clone(), &facts, &probes),
            t.clone(),
        ),
        _ => (defaults.clone(), config_doc::fresh_base_text()),
    };
    let (base, ks) = (
        std::path::PathBuf::from(&answers.base_path),
        std::path::PathBuf::from(&answers.keystore_dir),
    );
    let existing = ExistingInstall::detect(
        &config_path,
        &[PathPair {
            base_path: &base,
            keystore_dir: &ks,
        }],
        &probes,
    );

    let mut wiz = Wizard::new(Init {
        facts,
        probes: Box::new(RealProbes),
        answers,
        defaults,
        base_text,
        existing,
        clock: chrono::Utc::now,
    });

    let outcome = {
        let mut tui = term::Tui::enter()?;
        let outcome = loop {
            tui.draw(|f| ui::draw(f, &wiz))?;
            match term::read_input(None)? {
                term::Input::Key(k) => match wiz.on_key(k) {
                    Reaction::Idle => {}
                    Reaction::Done(o) => break o,
                    Reaction::Probe(msg) => {
                        wiz.busy = Some(msg);
                        tui.draw(|f| ui::draw(f, &wiz))?;
                        if let Some(o) = wiz.resume() {
                            break o;
                        }
                    }
                },
                term::Input::Resize | term::Input::Timeout => {}
            }
        };
        tui.leave()?;
        outcome
    };

    match outcome {
        Outcome::Cancel => {
            println!("setup cancelled; nothing was changed");
            Ok(())
        }
        Outcome::Apply(plan) => {
            println!("applying...");
            match apply::run(&plan, &probes, chrono::Utc::now()) {
                Ok(()) => Ok(()),
                Err(f) => {
                    println!();
                    println!("setup stopped: {}", sanitize(&f.message));
                    for line in &f.recovery {
                        println!("  {}", sanitize(line));
                    }
                    println!(
                        "steps listed as done above were completed; the rest were not attempted."
                    );
                    Err(io::Error::other("setup did not finish"))
                }
            }
        }
    }
}
