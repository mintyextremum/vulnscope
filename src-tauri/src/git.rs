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
    std::process::Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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
    let output = tokio::process::Command::new("git")
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

    #[test]
    fn cleanup_refuses_paths_outside_cache() {
        // Must not delete an arbitrary path even if asked.
        let outside = PathBuf::from("D:\\Project");
        cleanup_clone(&outside);
        assert!(outside.exists(), "cleanup must never touch paths outside its cache");
    }
}
