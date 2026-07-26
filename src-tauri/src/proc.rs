//! Spawning child processes without flashing console windows.
//!
//! Every external thing VulnScope runs — git, semgrep, bandit, gitleaks,
//! cargo-audit, the package managers, the user's editor — is a console program,
//! and Windows hands a console program its own window unless told otherwise.
//! Startup alone probes a dozen scanners with `--version`, so opening the app
//! throws a dozen black rectangles across the screen before it is even usable.
//!
//! For a security scanner that is worse than ugly: a burst of console windows
//! from a program you just launched is exactly what malware looks like, and a
//! user who cannot tell the difference is right to be alarmed. The windows carry
//! no information — nothing is ever typed into them and their output is captured
//! and parsed — so the honest fix is to not create them. Which tools ran is
//! shown in the report's "движки" list and on the tools panel, where it can
//! actually be read.
//!
//! `CREATE_NO_WINDOW` suppresses the console for the child *and* its descendants
//! that inherit the creation flags, which matters because npm and scoop are
//! `.cmd` shims (see `pkgmgr::resolve_program`) that go on to spawn more.

use std::ffi::OsStr;

/// Windows `CREATE_NO_WINDOW`: run the child without allocating a console.
///
/// Spelled out rather than pulled from `windows-sys` — one constant is not worth
/// a dependency, and the value is part of the stable Win32 ABI.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `std::process::Command`, minus the console window.
pub fn std_command(program: impl AsRef<OsStr>) -> std::process::Command {
    #[allow(unused_mut)]
    let mut cmd = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// `tokio::process::Command`, minus the console window.
pub fn command(program: impl AsRef<OsStr>) -> tokio::process::Command {
    #[allow(unused_mut)]
    let mut cmd = tokio::process::Command::new(program);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

#[cfg(test)]
mod tests {
    /// Nothing spawns a process except through this module.
    ///
    /// A single `Command::new` added later brings the flashing window back for
    /// that one tool, and it is invisible in review: the code looks perfectly
    /// ordinary and the difference only shows on Windows, at runtime, as a black
    /// rectangle. Measured before the fix: 23 console windows on screen at once
    /// during startup, for about five seconds.
    #[test]
    fn every_spawn_goes_through_this_module() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();

        for entry in std::fs::read_dir(&dir).expect("src/ читается") {
            let path = entry.expect("запись каталога").path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            // This module is where the exception lives. `rules.rs` is excluded
            // because it *detects* shell spawns: `Command::new` appears there
            // inside rule patterns and prose, not as code that runs.
            if name == "proc.rs" || name == "rules.rs" || path.extension().is_none_or(|e| e != "rs")
            {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap_or_default();
            for (i, line) in src.lines().enumerate() {
                if line.contains("Command::new") && !line.trim_start().starts_with("//") {
                    offenders.push(format!("{name}:{}", i + 1));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "прямой Command::new мимо proc.rs — на Windows это мигающее консольное окно: {offenders:?}"
        );
    }
}
