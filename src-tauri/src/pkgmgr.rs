use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

/// Finds an executable on PATH, honouring PATHEXT on Windows.
///
/// `Command::new("npm")` fails on Windows: npm, scoop and many other tools are
/// `.cmd` shims, and the OS only auto-resolves `.exe`. Without this, those tools
/// are reported as "not installed" even when they are on PATH — and the obvious
/// workaround, running through `cmd /c`, would drag a shell into every spawn.
pub fn resolve_program(name: &str) -> Option<PathBuf> {
    // An explicit path is used as given.
    if name.contains('/') || name.contains('\\') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }

    let path = std::env::var_os("PATH")?;

    #[cfg(windows)]
    let exts: Vec<String> = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
        .split(';')
        .filter(|e| !e.is_empty())
        .map(|e| e.to_ascii_lowercase())
        .collect();
    #[cfg(not(windows))]
    let exts: Vec<String> = vec![String::new()];

    // On Windows a PATHEXT match must win over a bare file of the same name.
    // `C:\Program Files\nodejs\npm` exists but is a Unix shell script that
    // CreateProcess cannot run; the executable one is `npm.cmd` beside it.
    // Trying the bare name first would resolve to the unusable file.
    let already_has_ext = std::path::Path::new(name).extension().is_some();

    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            if ext.is_empty() {
                continue;
            }
            let candidate = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }

        // Bare name: correct on Unix, and on Windows only when the caller
        // already spelled out an extension.
        if !cfg!(windows) || already_has_ext {
            let direct = dir.join(name);
            if direct.is_file() {
                return Some(direct);
            }
        }
    }
    None
}

/// A package manager we can install scanners through.
///
/// Installation always goes through one of these rather than fetching a binary
/// from a release URL ourselves: they verify signatures and checksums, and a
/// security scanner that downloads and executes arbitrary binaries would be the
/// supply-chain risk it exists to find.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PkgMgr {
    Pip,
    Pipx,
    Cargo,
    Scoop,
    Winget,
    Brew,
    Npm,
    Go,
}

impl PkgMgr {
    pub const ALL: &'static [PkgMgr] = &[
        PkgMgr::Pip,
        PkgMgr::Pipx,
        PkgMgr::Cargo,
        PkgMgr::Scoop,
        PkgMgr::Winget,
        PkgMgr::Brew,
        PkgMgr::Npm,
        PkgMgr::Go,
    ];

    pub fn id(self) -> &'static str {
        match self {
            PkgMgr::Pip => "pip",
            PkgMgr::Pipx => "pipx",
            PkgMgr::Cargo => "cargo",
            PkgMgr::Scoop => "scoop",
            PkgMgr::Winget => "winget",
            PkgMgr::Brew => "brew",
            PkgMgr::Npm => "npm",
            PkgMgr::Go => "go",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PkgMgr::Pip => "pip",
            PkgMgr::Pipx => "pipx",
            PkgMgr::Cargo => "Cargo",
            PkgMgr::Scoop => "Scoop",
            PkgMgr::Winget => "winget",
            PkgMgr::Brew => "Homebrew",
            PkgMgr::Npm => "npm",
            PkgMgr::Go => "Go",
        }
    }

    fn probe(self) -> (&'static str, &'static [&'static str]) {
        match self {
            PkgMgr::Pip => ("pip", &["--version"]),
            PkgMgr::Pipx => ("pipx", &["--version"]),
            PkgMgr::Cargo => ("cargo", &["--version"]),
            PkgMgr::Scoop => ("scoop", &["--version"]),
            PkgMgr::Winget => ("winget", &["--version"]),
            PkgMgr::Brew => ("brew", &["--version"]),
            PkgMgr::Npm => ("npm", &["--version"]),
            PkgMgr::Go => ("go", &["version"]),
        }
    }

    /// The argv used to install `pkg`. Returned as a vector so the caller can
    /// both display it and execute it without re-parsing a string — a shell
    /// string would reintroduce quoting bugs and the shell itself.
    pub fn install_argv(self, pkg: &str) -> Vec<String> {
        let base: Vec<&str> = match self {
            PkgMgr::Pip => vec!["pip", "install", "--upgrade"],
            PkgMgr::Pipx => vec!["pipx", "install"],
            PkgMgr::Cargo => vec!["cargo", "install", "--locked"],
            PkgMgr::Scoop => vec!["scoop", "install"],
            PkgMgr::Winget => vec!["winget", "install", "--accept-package-agreements", "--accept-source-agreements", "-e", "--id"],
            PkgMgr::Brew => vec!["brew", "install"],
            PkgMgr::Npm => vec!["npm", "install", "-g"],
            PkgMgr::Go => vec!["go", "install"],
        };
        base.into_iter()
            .map(|s| s.to_string())
            .chain(std::iter::once(pkg.to_string()))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PkgMgrStatus {
    pub id: String,
    pub label: String,
    pub available: bool,
    pub version: Option<String>,
}

async fn detect_one(m: PkgMgr) -> PkgMgrStatus {
    let (bin, args) = m.probe();

    let Some(exe) = resolve_program(bin) else {
        return PkgMgrStatus {
            id: m.id().to_string(),
            label: m.label().to_string(),
            available: false,
            version: None,
        };
    };

    let result = tokio::time::timeout(
        Duration::from_secs(8),
        tokio::process::Command::new(&exe)
            .args(args)
            .stdin(Stdio::null())
            .output(),
    )
    .await;

    let version = match result {
        Ok(Ok(out)) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty()),
        _ => None,
    };

    PkgMgrStatus {
        id: m.id().to_string(),
        label: m.label().to_string(),
        available: version.is_some(),
        version,
    }
}

/// Probes every package manager at once.
///
/// Each probe spawns a process and waits for it to print a version; done in a
/// row that is seconds of dead time before the app can show anything. The
/// results are reassembled by index so the order stays the catalogue's, not
/// whichever process happened to finish first.
pub async fn detect() -> Vec<PkgMgrStatus> {
    let mut set = tokio::task::JoinSet::new();
    for (i, m) in PkgMgr::ALL.iter().enumerate() {
        let m = *m;
        set.spawn(async move { (i, detect_one(m).await) });
    }

    let mut slots: Vec<Option<PkgMgrStatus>> = (0..PkgMgr::ALL.len()).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((i, st)) = joined {
            slots[i] = Some(st);
        }
    }
    slots.into_iter().flatten().collect()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    pub ok: bool,
    /// The exact argv that ran, so the UI can show what happened.
    pub command: String,
    pub output: String,
}

/// Runs an install command.
///
/// `program` and `args` come from `install_argv`, never from user input, and are
/// passed to the OS directly — no shell is involved, so there is nothing for
/// metacharacters to escape into.
pub async fn install(program: &str, args: &[String]) -> InstallResult {
    let command = format!("{} {}", program, args.join(" "));

    let Some(exe) = resolve_program(program) else {
        return InstallResult {
            ok: false,
            command,
            output: format!("{program} не найден в PATH"),
        };
    };

    let result = tokio::time::timeout(
        // Compiling a Rust tool from source genuinely takes minutes.
        Duration::from_secs(900),
        tokio::process::Command::new(&exe)
            .args(args)
            .stdin(Stdio::null())
            .output(),
    )
    .await;

    match result {
        Ok(Ok(out)) => {
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.trim().is_empty() {
                text.push('\n');
                text.push_str(&err);
            }
            // Keep the tail: package managers put the useful part last.
            let trimmed: String = text.lines().rev().take(24).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
            InstallResult {
                ok: out.status.success(),
                command,
                output: trimmed,
            }
        }
        Ok(Err(e)) => InstallResult {
            ok: false,
            command,
            output: format!("не удалось запустить: {e}"),
        },
        Err(_) => InstallResult {
            ok: false,
            command,
            output: "превышен лимит времени (15 минут)".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_argv_is_a_vector_not_a_shell_string() {
        let argv = PkgMgr::Pip.install_argv("semgrep");
        assert_eq!(argv, vec!["pip", "install", "--upgrade", "semgrep"]);
        // The package name must be its own argument: joining into one string is
        // what would let a name like "a; rm -rf /" become two commands.
        assert_eq!(argv.last().unwrap(), "semgrep");
    }

    #[test]
    fn cargo_installs_are_locked() {
        let argv = PkgMgr::Cargo.install_argv("cargo-audit");
        assert!(argv.contains(&"--locked".to_string()));
    }

    #[test]
    fn winget_pins_the_exact_id() {
        let argv = PkgMgr::Winget.install_argv("Gitleaks.Gitleaks");
        assert!(argv.contains(&"-e".to_string()));
        assert!(argv.contains(&"--id".to_string()));
        assert_eq!(argv.last().unwrap(), "Gitleaks.Gitleaks");
    }

    #[test]
    fn every_manager_has_a_distinct_id() {
        let mut ids: Vec<&str> = PkgMgr::ALL.iter().map(|m| m.id()).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(before, ids.len());
    }

    #[test]
    fn resolves_an_executable_that_is_definitely_on_path() {
        // Every platform we target has some form of this on PATH.
        #[cfg(windows)]
        let probe = "cmd";
        #[cfg(not(windows))]
        let probe = "sh";
        assert!(
            resolve_program(probe).is_some(),
            "{probe} should be resolvable via PATH"
        );
    }

    #[test]
    fn probe_real_managers() {
        for name in ["npm", "scoop", "pip", "cargo", "go", "winget", "pipx", "brew"] {
            println!("{name:>8} -> {:?}", resolve_program(name));
        }
    }

    #[test]
    fn missing_program_resolves_to_none() {
        assert!(resolve_program("definitely-not-a-real-binary-xyz-123").is_none());
    }

    /// The bug this guards: `npm` is `npm.cmd` on Windows, and looking only for
    /// `.exe` reported it as "not installed" while it sat on PATH.
    #[cfg(windows)]
    #[test]
    fn resolves_cmd_shims_not_just_exe() {
        if let Some(p) = resolve_program("npm") {
            let ext = p
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            assert!(
                ["cmd", "exe", "bat"].contains(&ext.as_str()),
                "unexpected npm resolution: {p:?}"
            );
        }
    }

    #[test]
    fn a_package_name_never_becomes_extra_arguments() {
        // Whatever the name looks like, it stays a single argv entry.
        let argv = PkgMgr::Pip.install_argv("evil; rm -rf /");
        assert_eq!(argv.len(), 4);
        assert_eq!(argv[3], "evil; rm -rf /");
    }
}
