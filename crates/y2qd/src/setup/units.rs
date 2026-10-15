//! Rendering of the shipped `deploy/` unit files for a chosen set of parameters.
//!
//! The templates are the files in `deploy/`, embedded verbatim; rendering edits
//! directive lines only (comments are untouched), so rendering with
//! [`UnitParams::shipped`] reproduces each file byte-for-byte.

const Y2QD_SERVICE: &str = include_str!("../../../../deploy/y2qd.service");
const KEYD_SOCKET: &str = include_str!("../../../../deploy/y2q-keyd.socket");
const KEYD_SERVICE: &str = include_str!("../../../../deploy/y2q-keyd@.service");
const SWEEP_SERVICE: &str = include_str!("../../../../deploy/y2q-keyd-sweep.service");
const SWEEP_TIMER: &str = include_str!("../../../../deploy/y2q-keyd-sweep.timer");
const TMPFILES: &str = include_str!("../../../../deploy/y2q-keyd.tmpfiles.conf");
const UDEV_RULE: &str = include_str!("../../../../deploy/70-y2q-fido2.rules");

/// Directory the shipped `y2qd.service` grants write access to.
const SHIPPED_RW_ROOT: &str = "/var/lib/y2q";

/// Parameters of one rendering. Pure data; no host lookups.
#[derive(Debug, Clone)]
pub struct UnitParams {
    pub bin: String,
    pub config: String,
    pub daemon_user: String,
    pub key_user: String,
    pub group: String,
    pub socket_group: String,
    pub key_user_group: String,
    pub socket_path: String,
    pub state_dir: String,
    pub keystore_dir: String,
    pub rw_dirs: Vec<String>,
    pub helper: bool,
    pub arm_on_start: bool,
    pub udev_vendor_id: String,
}

#[cfg(test)]
impl UnitParams {
    /// The literals the files in `deploy/` ship with.
    pub fn shipped() -> Self {
        Self {
            bin: "/usr/local/bin/y2qd".into(),
            config: "/etc/y2q/config.toml".into(),
            daemon_user: "y2qd".into(),
            key_user: "y2q-keyd".into(),
            group: "y2q".into(),
            socket_group: "y2qd".into(),
            key_user_group: "y2q-keyd".into(),
            socket_path: "/run/y2q-keyd.sock".into(),
            state_dir: "/run/y2q-keyd".into(),
            keystore_dir: "/var/lib/y2q/keystore".into(),
            rw_dirs: vec!["/var/lib/y2q/data".into(), "/var/lib/y2q/keystore".into()],
            helper: true,
            arm_on_start: true,
            udev_vendor_id: "1050".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnitFile {
    /// Relative to the unit root, e.g. `systemd/system/y2qd.service`.
    pub rel_path: String,
    pub content: String,
}

/// Shared character rule for every path/identity rendered into config, units or
/// printed: rejects control characters (incl. DEL, C1), whitespace and
/// `"` `'` `%` `$` `\` `;`.
pub fn clean_param(what: &str, value: &str) -> Result<(), String> {
    for c in value.chars() {
        if c.is_control() || c.is_whitespace() || matches!(c, '"' | '\'' | '%' | '$' | '\\' | ';') {
            return Err(format!(
                "{what} contains the character {:?}, which is not allowed",
                c
            ));
        }
    }
    Ok(())
}

fn check(what: &str, value: &str, absolute: bool) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{what} is empty"));
    }
    clean_param(what, value)?;
    if absolute && !value.starts_with('/') {
        return Err(format!("{what} must be an absolute path"));
    }
    Ok(())
}

fn validate(p: &UnitParams) -> Result<(), String> {
    check("binary path", &p.bin, true)?;
    check("config path", &p.config, true)?;
    check("daemon user", &p.daemon_user, false)?;
    check("key user", &p.key_user, false)?;
    check("group", &p.group, false)?;
    check("socket group", &p.socket_group, false)?;
    check("key user group", &p.key_user_group, false)?;
    check("socket path", &p.socket_path, true)?;
    check("state directory", &p.state_dir, true)?;
    check("keystore directory", &p.keystore_dir, true)?;
    for d in &p.rw_dirs {
        check("read-write directory", d, true)?;
    }
    check("udev vendor id", &p.udev_vendor_id, false)?;
    Ok(())
}

enum Action {
    Keep,
    Replace(String),
    /// Remove the line and the run of `#` lines directly above it.
    Drop,
}

/// Apply `f` to every line (without its newline) and reassemble.
fn map_lines(text: &str, mut f: impl FnMut(&str) -> Action) -> String {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split_inclusive('\n') {
        let (line, nl) = match raw.strip_suffix('\n') {
            Some(l) => (l, "\n"),
            None => (raw, ""),
        };
        match f(line) {
            Action::Keep => out.push(raw.to_string()),
            Action::Replace(s) => out.push(format!("{s}{nl}")),
            Action::Drop => {
                while out.last().is_some_and(|l| l.starts_with('#')) {
                    out.pop();
                }
            }
        }
    }
    out.concat()
}

/// `Key=value` directive lines only; comments and section headers yield `None`.
fn directive(line: &str) -> Option<(&str, &str)> {
    if line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    line.split_once('=')
}

fn set_value(key: &str, value: &str) -> Action {
    Action::Replace(format!("{key}={value}"))
}

/// Rewrite an `ExecStart=`/`ExecStartPre=` value: keep exec prefix characters,
/// replace the binary and the `--config` argument, leave other tokens alone.
fn exec_line(key: &str, value: &str, bin: &str, config: &str) -> Action {
    let prefix_len = value
        .find(|c: char| !matches!(c, '+' | '-' | '!' | '@' | ':'))
        .unwrap_or(value.len());
    let (prefix, rest) = value.split_at(prefix_len);
    let mut tokens: Vec<String> = rest.split(' ').map(str::to_string).collect();
    if let Some(first) = tokens.first_mut() {
        *first = bin.to_string();
    }
    for i in 1..tokens.len() {
        if tokens[i - 1] == "--config" {
            tokens[i] = config.to_string();
        }
    }
    Action::Replace(format!("{key}={prefix}{}", tokens.join(" ")))
}

fn under(dir: &str, root: &str) -> bool {
    dir == root || dir.strip_prefix(root).is_some_and(|r| r.starts_with('/'))
}

/// The config file sits directly in `/etc/y2q`, the directory that
/// `ConfigurationDirectory=y2q` manages.
fn config_in_shipped_dir(p: &UnitParams) -> bool {
    std::path::Path::new(&p.config).parent() == Some(std::path::Path::new("/etc/y2q"))
}

fn render_y2qd(p: &UnitParams) -> String {
    let rw_default = p.rw_dirs.iter().all(|d| under(d, SHIPPED_RW_ROOT));
    let keep_config_dir = config_in_shipped_dir(p);
    let mut seen: Vec<&str> = Vec::new();
    for d in &p.rw_dirs {
        if !seen.contains(&d.as_str()) {
            seen.push(d);
        }
    }
    let rw = seen.join(" ");
    map_lines(Y2QD_SERVICE, |line| {
        let Some((key, value)) = directive(line) else {
            return Action::Keep;
        };
        match key {
            "ExecStartPre" => {
                if !p.helper || !p.arm_on_start {
                    Action::Drop
                } else {
                    exec_line(key, value, &p.bin, &p.config)
                }
            }
            "ExecStart" => exec_line(key, value, &p.bin, &p.config),
            "Requires" if !p.helper && value == "y2q-keyd.socket" => Action::Drop,
            "After" if !p.helper => set_value(key, "network.target"),
            "User" => set_value(key, &p.daemon_user),
            "Group" => set_value(key, &p.group),
            "ReadWritePaths" if !rw_default => set_value(key, &rw),
            // The shipped `ConfigurationDirectory=y2q` / `StateDirectory=y2q` make
            // systemd create and chown /etc/y2q and /var/lib/y2q for the unit's
            // user. With config or data elsewhere they would take over those
            // directories (possibly another install's), so they go.
            "ConfigurationDirectory" | "ConfigurationDirectoryMode" if !keep_config_dir => {
                Action::Drop
            }
            "StateDirectory" | "StateDirectoryMode" if !rw_default => Action::Drop,
            _ => Action::Keep,
        }
    })
}

fn render_socket(p: &UnitParams) -> String {
    map_lines(KEYD_SOCKET, |line| match directive(line) {
        Some(("ListenStream", _)) => set_value("ListenStream", &p.socket_path),
        Some(("SocketUser", _)) => set_value("SocketUser", &p.daemon_user),
        Some(("SocketGroup", _)) => set_value("SocketGroup", &p.socket_group),
        _ => Action::Keep,
    })
}

fn render_helper(template: &str, p: &UnitParams, rw: &str) -> String {
    let keep_config_dir = config_in_shipped_dir(p);
    map_lines(template, |line| {
        let Some((key, value)) = directive(line) else {
            return Action::Keep;
        };
        match key {
            "ExecStart" => exec_line(key, value, &p.bin, &p.config),
            "User" => set_value(key, &p.key_user),
            "Group" => set_value(key, &p.group),
            "ReadWritePaths" => set_value(key, rw),
            "ConfigurationDirectory" | "ConfigurationDirectoryMode" if !keep_config_dir => {
                Action::Drop
            }
            _ => Action::Keep,
        }
    })
}

fn render_tmpfiles(p: &UnitParams) -> String {
    map_lines(TMPFILES, |line| {
        if line.starts_with("d ") {
            Action::Replace(format!(
                "d {} 0700 {} {} -",
                p.state_dir, p.key_user, p.group
            ))
        } else if line.starts_with("f ") {
            Action::Replace(format!(
                "f {}/.lock 0660 {} {} -",
                p.keystore_dir, p.daemon_user, p.group
            ))
        } else {
            Action::Keep
        }
    })
}

/// Replace the quoted value following `marker` (which ends in `"`).
fn replace_quoted(line: &str, marker: &str, value: &str) -> String {
    let Some(start) = line.find(marker).map(|i| i + marker.len()) else {
        return line.to_string();
    };
    let Some(len) = line[start..].find('"') else {
        return line.to_string();
    };
    format!("{}{}{}", &line[..start], value, &line[start + len..])
}

fn render_udev(p: &UnitParams) -> String {
    map_lines(UDEV_RULE, |line| {
        if line.starts_with('#') || !line.contains("ATTRS{idVendor}") {
            return Action::Keep;
        }
        let l = replace_quoted(line, "ATTRS{idVendor}==\"", &p.udev_vendor_id);
        Action::Replace(replace_quoted(&l, "GROUP=\"", &p.key_user_group))
    })
}

fn file(rel: &str, content: String) -> UnitFile {
    UnitFile {
        rel_path: rel.to_string(),
        content,
    }
}

/// All files to install for these parameters.
pub fn render(p: &UnitParams, install_udev_rule: bool) -> Result<Vec<UnitFile>, String> {
    validate(p)?;
    let mut out = vec![file("systemd/system/y2qd.service", render_y2qd(p))];
    if p.helper {
        let rw_keyd = format!("{} {}", p.keystore_dir, p.state_dir);
        out.push(file("systemd/system/y2q-keyd.socket", render_socket(p)));
        out.push(file(
            "systemd/system/y2q-keyd@.service",
            render_helper(KEYD_SERVICE, p, &rw_keyd),
        ));
        out.push(file(
            "systemd/system/y2q-keyd-sweep.service",
            render_helper(SWEEP_SERVICE, p, &p.keystore_dir),
        ));
        out.push(file(
            "systemd/system/y2q-keyd-sweep.timer",
            SWEEP_TIMER.to_string(),
        ));
        out.push(file("tmpfiles.d/y2q-keyd.conf", render_tmpfiles(p)));
    }
    if install_udev_rule {
        out.push(file("udev/rules.d/70-y2q-fido2.rules", render_udev(p)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(files: &'a [UnitFile], rel: &str) -> &'a str {
        &files.iter().find(|f| f.rel_path == rel).unwrap().content
    }

    /// A template without the directory directives that custom paths drop.
    fn without_dir_directives(text: &str) -> String {
        text.split_inclusive('\n')
            .filter(|l| {
                ![
                    "ConfigurationDirectory=",
                    "ConfigurationDirectoryMode=",
                    "StateDirectory=",
                    "StateDirectoryMode=",
                ]
                .iter()
                .any(|k| l.starts_with(k))
            })
            .collect()
    }

    fn changed(a: &str, b: &str) -> Vec<(String, String)> {
        let (a, b): (Vec<_>, Vec<_>) = (a.lines().collect(), b.lines().collect());
        assert_eq!(a.len(), b.len());
        a.iter()
            .zip(&b)
            .filter(|(x, y)| x != y)
            .map(|(x, y)| (x.to_string(), y.to_string()))
            .collect()
    }

    #[test]
    fn shipped_params_reproduce_deploy_files() {
        let f = render(&UnitParams::shipped(), true).unwrap();
        assert_eq!(f.len(), 7);
        assert_eq!(find(&f, "systemd/system/y2qd.service"), Y2QD_SERVICE);
        assert_eq!(find(&f, "systemd/system/y2q-keyd.socket"), KEYD_SOCKET);
        assert_eq!(find(&f, "systemd/system/y2q-keyd@.service"), KEYD_SERVICE);
        assert_eq!(
            find(&f, "systemd/system/y2q-keyd-sweep.service"),
            SWEEP_SERVICE
        );
        assert_eq!(find(&f, "systemd/system/y2q-keyd-sweep.timer"), SWEEP_TIMER);
        assert_eq!(find(&f, "tmpfiles.d/y2q-keyd.conf"), TMPFILES);
        assert_eq!(find(&f, "udev/rules.d/70-y2q-fido2.rules"), UDEV_RULE);
    }

    fn custom() -> UnitParams {
        UnitParams {
            bin: "/opt/y2/bin/y2qd".into(),
            config: "/srv/y2/config.toml".into(),
            daemon_user: "svc".into(),
            key_user: "keyu".into(),
            group: "grp".into(),
            socket_group: "sock".into(),
            key_user_group: "hid".into(),
            socket_path: "/run/k.sock".into(),
            state_dir: "/run/k".into(),
            keystore_dir: "/srv/y2/keys".into(),
            rw_dirs: vec!["/srv/y2/data".into(), "/srv/y2/keys".into()],
            helper: true,
            arm_on_start: true,
            udev_vendor_id: "1234".into(),
        }
    }

    #[test]
    fn custom_params_change_only_targeted_lines() {
        let f = render(&custom(), true).unwrap();
        let d = changed(
            &without_dir_directives(Y2QD_SERVICE),
            find(&f, "systemd/system/y2qd.service"),
        );
        let new: Vec<&str> = d.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(
            new,
            [
                "ExecStartPre=+/opt/y2/bin/y2qd --key-arm --config /srv/y2/config.toml",
                "ExecStart=/opt/y2/bin/y2qd --config /srv/y2/config.toml",
                "User=svc",
                "Group=grp",
                "ReadWritePaths=/srv/y2/data /srv/y2/keys",
            ]
        );
        let d = changed(KEYD_SOCKET, find(&f, "systemd/system/y2q-keyd.socket"));
        let new: Vec<&str> = d.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(
            new,
            [
                "ListenStream=/run/k.sock",
                "SocketUser=svc",
                "SocketGroup=sock"
            ]
        );
        let d = changed(
            &without_dir_directives(KEYD_SERVICE),
            find(&f, "systemd/system/y2q-keyd@.service"),
        );
        let new: Vec<&str> = d.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(
            new,
            [
                "ExecStart=/opt/y2/bin/y2qd --key-serve --config /srv/y2/config.toml",
                "User=keyu",
                "Group=grp",
                "ReadWritePaths=/srv/y2/keys /run/k",
            ]
        );
        let d = changed(
            &without_dir_directives(SWEEP_SERVICE),
            find(&f, "systemd/system/y2q-keyd-sweep.service"),
        );
        let new: Vec<&str> = d.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(
            new,
            [
                "ExecStart=/opt/y2/bin/y2qd --key-sweep --config /srv/y2/config.toml",
                "User=keyu",
                "Group=grp",
                "ReadWritePaths=/srv/y2/keys",
            ]
        );
        let d = changed(TMPFILES, find(&f, "tmpfiles.d/y2q-keyd.conf"));
        let new: Vec<&str> = d.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(
            new,
            [
                "d /run/k 0700 keyu grp -",
                "f /srv/y2/keys/.lock 0660 svc grp -"
            ]
        );
        let d = changed(UDEV_RULE, find(&f, "udev/rules.d/70-y2q-fido2.rules"));
        assert_eq!(d.len(), 1);
        assert_eq!(
            d[0].1,
            "SUBSYSTEM==\"hidraw\", ATTRS{idVendor}==\"1234\", GROUP=\"hid\", MODE=\"0660\""
        );
    }

    #[test]
    fn operator_mode_renders_only_daemon_unit_without_helper_directives() {
        let mut p = UnitParams::shipped();
        p.helper = false;
        let f = render(&p, false).unwrap();
        assert_eq!(f.len(), 1);
        let s = &f[0].content;
        assert!(!s.contains("Requires="));
        assert!(!s.contains("ExecStartPre"));
        assert!(!s.contains("The node key is fetched once"));
        assert!(!s.contains("Unattended arm as root"));
        assert!(s.contains("After=network.target\n"));
        assert!(s.contains("Wants=network.target\n"));
        assert!(s.contains("[Service]\nType=simple\nExecStart="));
        assert!(s.contains("StartLimitIntervalSec=300"));
    }

    #[test]
    fn no_arm_drops_only_exec_start_pre() {
        let mut p = UnitParams::shipped();
        p.arm_on_start = false;
        let f = render(&p, false).unwrap();
        let s = find(&f, "systemd/system/y2qd.service");
        assert!(!s.contains("ExecStartPre"));
        assert!(!s.contains("Unattended arm as root"));
        assert!(!s.contains("sudo y2qd --key-arm"));
        assert!(s.contains("Requires=y2q-keyd.socket"));
        assert!(s.contains("The node key is fetched once"));
        assert!(s.contains("Type=simple\nExecStart="));
    }

    #[test]
    fn rw_dirs_prefix_is_by_component() {
        let mut p = UnitParams::shipped();
        p.rw_dirs = vec!["/var/lib/y2q-extra/data".into()];
        let f = render(&p, false).unwrap();
        assert!(
            find(&f, "systemd/system/y2qd.service")
                .contains("ReadWritePaths=/var/lib/y2q-extra/data\n")
        );
    }

    #[test]
    fn shipped_directory_directives_follow_the_paths() {
        let has = |text: &str, key: &str| text.lines().any(|l| l.starts_with(&format!("{key}=")));

        // Config in /etc/y2q and data under /var/lib/y2q: all kept (shipped output).
        let f = render(&UnitParams::shipped(), false).unwrap();
        let y = find(&f, "systemd/system/y2qd.service");
        assert!(has(y, "ConfigurationDirectory") && has(y, "StateDirectory"));

        // Config elsewhere: no unit may manage /etc/y2q, but state is unaffected.
        let mut p = UnitParams::shipped();
        p.config = "/etc/y2q-other/config.toml".into();
        let f = render(&p, true).unwrap();
        for unit in [
            "systemd/system/y2qd.service",
            "systemd/system/y2q-keyd@.service",
            "systemd/system/y2q-keyd-sweep.service",
        ] {
            let t = find(&f, unit);
            assert!(!has(t, "ConfigurationDirectory"), "{unit}");
            assert!(!has(t, "ConfigurationDirectoryMode"), "{unit}");
        }
        assert!(has(
            find(&f, "systemd/system/y2qd.service"),
            "StateDirectory"
        ));

        // Data elsewhere: the daemon must not manage /var/lib/y2q either.
        let mut p = UnitParams::shipped();
        p.rw_dirs = vec!["/srv/y2q/data".into()];
        let y = render(&p, false).unwrap().remove(0).content;
        assert!(!has(&y, "StateDirectory") && !has(&y, "StateDirectoryMode"));
        assert!(has(&y, "ConfigurationDirectory"));
        // Neighbouring lines survive; only the StateDirectory pair went.
        assert!(
            y.contains("UMask=0077\nConfigurationDirectory=y2q\nConfigurationDirectoryMode=0750\n")
        );
    }

    #[test]
    fn rejects_bad_parameters() {
        for bad in [
            "a\"b", "a b", "a\nb", "a'b", "a%b", "a$b", "a\\b", "a;b", "a\u{85}b", "a\x7fb",
        ] {
            let mut p = UnitParams::shipped();
            p.daemon_user = bad.into();
            assert!(render(&p, false).is_err(), "{bad:?}");
            let mut p = UnitParams::shipped();
            p.rw_dirs = vec![format!("/x/{bad}")];
            assert!(render(&p, false).is_err(), "{bad:?}");
        }
        let mut p = UnitParams::shipped();
        p.bin = "bin/y2qd".into();
        assert!(render(&p, false).unwrap_err().contains("absolute"));
        let mut p = UnitParams::shipped();
        p.group = String::new();
        assert!(render(&p, false).is_err());
    }

    #[test]
    fn clean_param_accepts_normal_paths() {
        clean_param("p", "/var/lib/y2q/data-1/a_b.c").unwrap();
        clean_param("p", "y2q-keyd").unwrap();
    }
}
