use anyhow::{bail, Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Accepts the URL shapes people actually paste: https, ssh, and `owner/repo`.
static GITHUB_URL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^(?:https?://(?:www\.)?(github\.com|gitlab\.com|bitbucket\.org)/|git@(github\.com|gitlab\.com|bitbucket\.org):)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    )
    .unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRef {
    pub host: String,
    pub owner: String,
    pub name: String,
}

impl RepoRef {
    pub fn clone_url(&self) -> String {
        format!("https://{}/{}/{}.git", self.host, self.owner, self.name)
    }

    pub fn label(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

pub fn parse_repo_url(input: &str) -> Result<RepoRef> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("пустой адрес репозитория");
    }

    let caps = GITHUB_URL
        .captures(trimmed)
        .with_context(|| format!("не похоже на адрес репозитория: {trimmed}"))?;

    let host = caps
        .get(1)
        .or_else(|| caps.get(2))
        .map(|m| m.as_str().to_ascii_lowercase())
        .unwrap_or_else(|| "github.com".to_string());

    Ok(RepoRef {
        host,
        owner: caps[3].to_string(),
        name: caps[4].to_string(),
    })
}

pub fn git_available() -> bool {
    crate::proc::std_command("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `git -C <root>` for reading a repository VulnScope did not create.
///
/// The repository being scanned is untrusted input, and so is its
/// `.git/config`: a folder unpacked from an archive brings one along. Git runs
/// programs named there — `core.fsmonitor` on any command that refreshes the
/// index, external diff and textconv drivers — so a plain `git diff` in such a
/// folder executes whatever the archive's author chose. These overrides take
/// precedence over the repository's own config: fsmonitor is switched off
/// here, and the commands that could reach a diff driver pass `--no-ext-diff`
/// and `--no-textconv` themselves. None of the commands used runs hooks.
/// Optional locks are off too, so reading never writes the index.
pub fn hardened(root: &Path) -> std::process::Command {
    let mut cmd = crate::proc::std_command("git");
    cmd.arg("-C")
        .arg(root)
        .args(["-c", "core.fsmonitor=false"])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null());
    cmd
}

/// NUL-separated paths from a git listing, forward-slashed and non-empty.
fn nul_paths(out: &[u8]) -> impl Iterator<Item = String> + '_ {
    out.split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).replace('\\', "/"))
}

/// Files under `root` that differ from the last commit — staged, unstaged or
/// untracked (but not ignored) — as paths relative to `root`, forward-slashed
/// like discovery's. Deleted files are left out: there is nothing to scan.
///
/// A repository without commits yet has no HEAD to compare with, so everything
/// in it counts as changed.
pub fn changed_files(root: &Path) -> Result<std::collections::HashSet<String>> {
    let inside = hardened(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .context("git не запустился")?;
    if !inside.status.success() || String::from_utf8_lossy(&inside.stdout).trim() != "true" {
        bail!("режим «только изменения» работает в git-репозитории, а {} — не он", root.display());
    }

    let mut changed = std::collections::HashSet::new();
    let has_head = hardened(root)
        .args(["rev-parse", "--verify", "--quiet", "HEAD"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let listing = if has_head {
        // `--relative`: paths relative to `root` and only below it, which is
        // what a scan of a subfolder of a repository needs.
        hardened(root)
            .args(["diff", "HEAD", "--name-only", "-z", "--relative", "--diff-filter=d", "--no-ext-diff", "--no-textconv", "--no-renames"])
            .output()
    } else {
        hardened(root).args(["ls-files", "-z"]).output()
    }
    .context("git не запустился")?;
    if !listing.status.success() {
        bail!("git не смог перечислить изменения: {}", String::from_utf8_lossy(&listing.stderr).trim());
    }
    changed.extend(nul_paths(&listing.stdout));

    let untracked = hardened(root)
        .args(["ls-files", "--others", "--exclude-standard", "-z"])
        .output()
        .context("git не запустился")?;
    if untracked.status.success() {
        changed.extend(nul_paths(&untracked.stdout));
    }
    Ok(changed)
}

/// Working directory for cloned repositories, under the OS cache dir.
pub fn clone_root() -> Result<PathBuf> {
    let dir = dirs::cache_dir()
        .context("не удалось определить каталог кэша")?
        .join("vulnscope")
        .join("repos");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Shallow-clones a public repository. `--depth 1` keeps it fast: we analyse
/// the current tree, not history.
pub async fn shallow_clone(repo: &RepoRef) -> Result<PathBuf> {
    if !git_available() {
        bail!("git не найден в PATH. Установите Git, чтобы сканировать репозитории по ссылке.");
    }

    let root = clone_root()?;
    let dest = root.join(format!("{}__{}", repo.owner, repo.name));

    if dest.exists() {
        std::fs::remove_dir_all(&dest)
            .with_context(|| format!("не удалось очистить {}", dest.display()))?;
    }

    let url = repo.clone_url();
    let output = crate::proc::command("git")
        .args([
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            "--config",
            // Never let a clone prompt for credentials: a private or misspelled
            // repo must fail fast rather than hang the scan on a hidden dialog.
            "credential.helper=",
            &url,
        ])
        .arg(&dest)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "echo")
        .stdin(Stdio::null())
        .output()
        .await
        .context("не удалось запустить git")?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let hint = if err.contains("Authentication failed") || err.contains("could not read Username") {
            "репозиторий приватный или не существует"
        } else if err.contains("not found") || err.contains("Repository not found") {
            "репозиторий не найден"
        } else {
            "клонирование не удалось"
        };
        bail!("{hint}: {}", err.trim().lines().last().unwrap_or("").trim());
    }

    Ok(dest)
}

/// Frees disk from a clone once its scan is done.
pub fn cleanup_clone(path: &Path) {
    let Ok(root) = clone_root() else { return };
    // Only ever delete inside our own cache directory.
    if path.starts_with(&root) && path != root {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// Removes every clone except `keep`.
///
/// A finished scan's clone must survive: the report references it by path, and
/// the code viewer reads the source from disk on demand. So clones are purged
/// when the *next* one is made rather than when their own scan ends, which
/// bounds disk use to one repository at a time.
pub fn purge_other_clones(keep: &Path) {
    let Ok(root) = clone_root() else { return };
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path != keep && path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_url() {
        let r = parse_repo_url("https://github.com/pallets/flask").unwrap();
        assert_eq!(r.owner, "pallets");
        assert_eq!(r.name, "flask");
        assert_eq!(r.host, "github.com");
    }

    #[test]
    fn parses_url_with_git_suffix_and_trailing_slash() {
        assert_eq!(parse_repo_url("https://github.com/a/b.git").unwrap().name, "b");
        assert_eq!(parse_repo_url("https://github.com/a/b/").unwrap().name, "b");
    }

    #[test]
    fn parses_ssh_url() {
        let r = parse_repo_url("git@github.com:owner/repo.git").unwrap();
        assert_eq!(r.owner, "owner");
        assert_eq!(r.name, "repo");
    }

    #[test]
    fn parses_shorthand_owner_slash_repo() {
        let r = parse_repo_url("torvalds/linux").unwrap();
        assert_eq!(r.host, "github.com");
        assert_eq!(r.label(), "torvalds/linux");
    }

    #[test]
    fn supports_gitlab_and_bitbucket() {
        assert_eq!(parse_repo_url("https://gitlab.com/a/b").unwrap().host, "gitlab.com");
        assert_eq!(
            parse_repo_url("https://bitbucket.org/a/b").unwrap().host,
            "bitbucket.org"
        );
    }

    #[test]
    fn builds_https_clone_url() {
        let r = parse_repo_url("git@github.com:owner/repo.git").unwrap();
        assert_eq!(r.clone_url(), "https://github.com/owner/repo.git");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_repo_url("").is_err());
        assert!(parse_repo_url("not a url at all").is_err());
        assert!(parse_repo_url("https://example.com/a/b/c/d").is_err());
    }

    /// A throwaway repository with one committed file, or None without git.
    fn temp_repo(tag: &str) -> Option<PathBuf> {
        if !git_available() {
            eprintln!("git недоступен — тест пропущен");
            return None;
        }
        let dir = std::env::temp_dir().join(format!("vs-git-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let git = |args: &[&str]| {
            let ok = crate::proc::std_command("git")
                .arg("-C")
                .arg(&dir)
                .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
                .args(args)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            assert!(ok, "git {args:?}");
        };
        git(&["init", "-q"]);
        std::fs::write(dir.join("kept.py"), "a = 1\n").unwrap();
        std::fs::write(dir.join("edited.py"), "b = 1\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "init"]);
        Some(dir)
    }

    #[test]
    fn changed_files_lists_edits_and_new_files_only() {
        let Some(dir) = temp_repo("changed") else { return };
        std::fs::write(dir.join("edited.py"), "b = 2\n").unwrap();
        std::fs::write(dir.join("sub").join("new.py"), "c = 1\n").unwrap();
        std::fs::write(dir.join(".gitignore"), "ignored.py\n").unwrap();
        std::fs::write(dir.join("ignored.py"), "d = 1\n").unwrap();

        let changed = changed_files(&dir).expect("a work tree");
        assert!(changed.contains("edited.py"), "{changed:?}");
        assert!(changed.contains("sub/new.py"), "forward slashes, like discovery: {changed:?}");
        assert!(changed.contains(".gitignore"));
        assert!(!changed.contains("kept.py"), "unchanged files are not scanned");
        assert!(!changed.contains("ignored.py"), "ignored files are not scanned");

        // A subfolder scan sees paths relative to itself, and only below it.
        let sub = changed_files(&dir.join("sub")).unwrap();
        assert_eq!(sub.into_iter().collect::<Vec<_>>(), vec!["new.py".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_files_refuses_a_plain_folder() {
        let dir = std::env::temp_dir().join(format!("vs-git-plain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A temp dir can sit inside some repository on a developer machine;
        // only assert when it really is outside one.
        let inside = hardened(&dir).args(["rev-parse", "--is-inside-work-tree"]).output();
        if inside.map(|o| o.status.success()).unwrap_or(true) {
            return;
        }
        assert!(changed_files(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reason every git call goes through `proc`: a scanned repository's own
    /// `.git/config` must not get to run a program. Proven against the real
    /// attack — a `core.fsmonitor` command — on the git commands scans use.
    #[test]
    fn a_scanned_repository_cannot_run_its_fsmonitor() {
        let Some(dir) = temp_repo("fsmonitor") else { return };
        let marker = dir.join("pwned.txt");
        crate::proc::std_command("git")
            .arg("-C")
            .arg(&dir)
            .args(["config", "core.fsmonitor", "echo pwned > pwned.txt"])
            .output()
            .unwrap();
        std::fs::write(dir.join("edited.py"), "b = 2\n").unwrap();

        let _ = changed_files(&dir);
        for args in [vec!["ls-files", "-z"], vec!["blame", "--line-porcelain", "-L", "1,1", "--", "kept.py"]] {
            // Plain `git -C`, no `-c`: the environment from `proc` alone.
            let _ = crate::proc::std_command("git").arg("-C").arg(&dir).args(&args).output();
        }
        assert!(!marker.exists(), "the repository's core.fsmonitor ran");

        // Control: without the override the same config does run, so the
        // assertion above is testing something real on this machine.
        let _ = crate::proc::std_command("git")
            .arg("-C")
            .arg(&dir)
            .args(["ls-files"])
            .env_remove("GIT_CONFIG_COUNT")
            .output();
        let ran = marker.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(ran, "control: an unprotected git should have run the hook");
    }

    #[test]
    fn cleanup_refuses_paths_outside_cache() {
        // A real directory outside the clone cache — temp never sits under
        // cache_dir/vulnscope/repos on any platform. The earlier version asserted
        // on a hardcoded D:\Project, so it only proved anything on a machine that
        // happened to have one and failed everywhere else, CI included.
        let outside = std::env::temp_dir().join("vulnscope-cleanup-guard");
        std::fs::create_dir_all(&outside).expect("temp dir for the test");
        cleanup_clone(&outside);
        let survived = outside.exists();
        let _ = std::fs::remove_dir_all(&outside);
        assert!(survived, "cleanup must never touch paths outside its cache");
    }
}
