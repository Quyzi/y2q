//! Clap definitions for daemon-gated commands (Tier 2). These parse fully so
//! the commands appear in `--help` and accept their mc-style flags, but their
//! handlers return [`crate::error::CliError::NotYetSupported`]. Each carries a
//! `gate()` describing the daemon work required to implement it.

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum TagCmd {
    /// Set tags on an object (KEY=VALUE pairs).
    Set {
        target: String,
        #[arg(value_name = "KEY=VALUE")]
        tags: Vec<String>,
    },
    /// List tags on an object.
    #[command(alias = "ls")]
    List { target: String },
    /// Remove all tags from an object.
    #[command(alias = "rm")]
    Remove { target: String },
}

#[derive(Subcommand, Debug)]
pub enum AttributeCmd {
    /// Set user-defined metadata attributes.
    Set {
        target: String,
        #[arg(value_name = "KEY=VALUE")]
        attrs: Vec<String>,
    },
    /// List attributes.
    #[command(alias = "ls")]
    List { target: String },
    /// Remove attributes.
    #[command(alias = "rm")]
    Remove { target: String },
}

#[derive(Subcommand, Debug)]
pub enum VersionCmd {
    /// Enable bucket versioning.
    Enable { target: String },
    /// Disable bucket versioning.
    Disable { target: String },
    /// Suspend bucket versioning.
    Suspend { target: String },
    /// Show versioning state.
    Info { target: String },
}

#[derive(Subcommand, Debug)]
pub enum RetentionCmd {
    /// Set WORM retention (governance|compliance + duration).
    Set {
        target: String,
        mode: Option<String>,
        validity: Option<String>,
        #[arg(long)]
        recursive: bool,
    },
    /// Clear retention.
    Clear { target: String },
    /// Show retention.
    Info { target: String },
}

#[derive(Subcommand, Debug)]
pub enum LegalholdCmd {
    /// Enable legal hold.
    Set { target: String },
    /// Clear legal hold.
    Clear { target: String },
    /// Show legal-hold state.
    Info { target: String },
}

#[derive(Subcommand, Debug)]
pub enum ShareCmd {
    /// Issue a presigned download URL.
    Download {
        target: String,
        #[arg(long)]
        expire: Option<String>,
    },
    /// Issue a presigned upload policy.
    Upload {
        target: String,
        #[arg(long)]
        expire: Option<String>,
    },
    /// List active shares.
    #[command(alias = "ls")]
    List,
    /// Cancel a share.
    Cancel { target: String },
}

#[derive(Subcommand, Debug)]
pub enum AnonymousCmd {
    /// Set anonymous access policy (none|download|upload|public).
    Set { policy: String, target: String },
    /// Show anonymous access policy.
    Get { target: String },
}

#[derive(Subcommand, Debug)]
pub enum CorsCmd {
    /// Set the bucket CORS configuration from a file.
    Set { target: String, config: String },
    /// Show the bucket CORS configuration.
    Get { target: String },
    /// Remove the bucket CORS configuration.
    #[command(alias = "rm")]
    Remove { target: String },
}

#[derive(Subcommand, Debug)]
pub enum QuotaCmd {
    /// Set a bucket size quota.
    Set {
        target: String,
        #[arg(long)]
        size: String,
    },
    /// Clear a bucket quota.
    Clear { target: String },
    /// Show a bucket quota.
    Info { target: String },
}

#[derive(Subcommand, Debug)]
pub enum InventoryCmd {
    /// Add a scheduled inventory report.
    Add { target: String },
    /// List inventory configurations.
    #[command(alias = "ls")]
    List { target: String },
    /// Remove an inventory configuration.
    #[command(alias = "rm")]
    Remove { target: String, id: String },
}

#[derive(Subcommand, Debug)]
pub enum IlmCmd {
    /// Manage lifecycle rules.
    Rule {
        #[command(subcommand)]
        cmd: IlmRuleCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum IlmRuleCmd {
    /// Add a lifecycle rule.
    Add {
        target: String,
        #[arg(long)]
        expire_days: Option<u32>,
    },
    /// List lifecycle rules.
    #[command(alias = "ls")]
    List { target: String },
    /// Edit a lifecycle rule.
    Edit { target: String, id: String },
    /// Remove a lifecycle rule.
    #[command(alias = "rm")]
    Remove { target: String, id: String },
    /// Export lifecycle rules.
    Export { target: String },
    /// Import lifecycle rules.
    Import { target: String },
}

#[derive(Subcommand, Debug)]
pub enum EncryptCmd {
    /// Set the bucket default SSE configuration.
    Set {
        target: String,
        algo: Option<String>,
    },
    /// Show the bucket SSE configuration.
    Info { target: String },
    /// Remove the bucket default SSE configuration.
    Clear { target: String },
}

#[derive(Subcommand, Debug)]
pub enum EventCmd {
    /// Wire a bucket notification target.
    Add {
        target: String,
        arn: String,
        #[arg(long, value_name = "EVENT", number_of_values = 1)]
        event: Vec<String>,
    },
    /// List bucket notification targets.
    #[command(alias = "ls")]
    List { target: String },
    /// Remove a bucket notification target.
    #[command(alias = "rm")]
    Remove { target: String, arn: String },
}

#[derive(Subcommand, Debug)]
pub enum BatchCmd {
    /// Generate a batch job template.
    Generate { job_type: String },
    /// Start a batch job from a YAML file.
    Start { alias: String, file: String },
    /// List batch jobs.
    #[command(alias = "ls")]
    List { alias: String },
    /// Show batch job status.
    Status { alias: String, job_id: String },
    /// Describe a batch job.
    Describe { alias: String, job_id: String },
    /// Cancel a batch job.
    Cancel { alias: String, job_id: String },
}
