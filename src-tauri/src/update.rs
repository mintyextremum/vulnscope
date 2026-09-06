//! Version notification — a check, deliberately not an updater.
//!
//! This asks the public releases feed for the latest tag and compares it with
//! the running one. That is the whole feature: nothing is downloaded, nothing
//! is executed, and no installer is ever launched. The user is told a newer
//! version exists and given a link they open themselves.
//!
//! The line matters for this project specifically. VulnScope tells its users
//! that a security scanner which fetches and runs binaries becomes the
//! supply-chain threat it exists to find, and it refuses to install external
//! scanners for that reason. A self-updater would need a signing key whose
//! leak means pushing arbitrary code to every install — a worse trade than
//! asking someone to click a link twice a year.
//!
//! It is also the one place besides OSV where this app talks to the network,
//! so it obeys `offline` and can be switched off on its own.

use serde::Serialize;

/// Where the version comes from. Only the tag name and the page URL are read.
const RELEASES_API: &str =
    "https://api.github.com/repos/mintyextremum/vulnscope/releases/latest";

/// Where the user is sent. Never fetched by the app.
pub const RELEASES_PAGE: &str = "https://github.com/mintyextremum/vulnscope/releases/latest";

#[derive(Serialize, Default, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    /// The running version, from the crate metadata — never hand-written, so it
    /// cannot drift from what was actually built.
    pub current: String,
    /// The newest published version, when the check got an answer.
    pub latest: Option<String>,
    pub update_available: bool,
    pub url: &'static str,
    /// Why there is no answer. Shown nowhere by default: a failed version check
    /// is not a problem the user has to act on, and an app that nags about its
    /// own connectivity is worse than one that stays quiet.
    pub error: Option<String>,
}

impl UpdateInfo {
    fn quiet(reason: &str) -> Self {
        UpdateInfo {
            current: current_version().to_string(),
            latest: None,
            update_available: false,
            url: RELEASES_PAGE,
            error: Some(reason.to_string()),
        }
    }
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// `1.2.3` → `(1, 2, 3)`. Tolerates a leading `v` and anything after a `-` or
/// `+` (pre-release and build metadata), so `v1.2.3-rc.1` reads as 1.2.3.
/// Returns `None` for anything else rather than guessing: an unparseable tag
/// must not be able to announce an update.
fn parse_version(raw: &str) -> Option<(u32, u32, u32)> {
    let s = raw.trim();
    let s = s.strip_prefix('v').or_else(|| s.strip_prefix('V')).unwrap_or(s);
    let s = s.split(['-', '+']).next()?;
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    // A tag may legitimately be `1.2`; the missing components are zero.
    let minor = parts.next().map_or(Some(0), |p| p.parse().ok())?;
    let patch = parts.next().map_or(Some(0), |p| p.parse().ok())?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Whether `latest` is a newer release than `current`. Unparseable input on
/// either side answers "no": staying quiet is the safe failure.
fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Asks the releases feed for the newest version.
///
/// `offline` wins over everything: the setting says no network, and a version
/// check is network. Failures are swallowed into `error` — a scanner must not
/// interrupt anyone because a GitHub request timed out.
pub async fn check(offline: bool, enabled: bool) -> UpdateInfo {
    if offline {
        return UpdateInfo::quiet("offline");
    }
    if !enabled {
        return UpdateInfo::quiet("disabled");
    }

    let client = match reqwest::Client::builder()
        // Short on purpose: this runs at startup and must never be something
        // the user waits for.
        .timeout(std::time::Duration::from_secs(6))
        .user_agent(concat!("VulnScope/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => return UpdateInfo::quiet(&e.to_string()),
    };

    let resp = match client
        .get(RELEASES_API)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return UpdateInfo::quiet(&e.to_string()),
    };
    if !resp.status().is_success() {
        return UpdateInfo::quiet(&format!("HTTP {}", resp.status().as_u16()));
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => return UpdateInfo::quiet(&e.to_string()),
    };

    let tag = body.get("tag_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if tag.is_empty() {
        return UpdateInfo::quiet("no tag_name in response");
    }

    let current = current_version();
    UpdateInfo {
        update_available: is_newer(&tag, current),
        latest: Some(tag.trim_start_matches(['v', 'V']).to_string()),
        current: current.to_string(),
        url: RELEASES_PAGE,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_tag_shapes_github_actually_serves() {
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version(" v1.0.0 "), Some((1, 0, 0)));
        assert_eq!(parse_version("v1.2"), Some((1, 2, 0)));
        assert_eq!(parse_version("v1.2.3-rc.1"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2.3+build7"), Some((1, 2, 3)));
    }

    /// An unparseable tag must not be able to claim an update: the banner would
    /// send people to a release that does not exist.
    #[test]
    fn refuses_to_guess_at_nonsense() {
        assert_eq!(parse_version("latest"), None);
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("v1.x.0"), None);
        assert!(!is_newer("latest", "1.0.0"));
        assert!(!is_newer("2.0.0", "garbage"));
    }

    #[test]
    fn compares_by_component_not_by_string() {
        assert!(is_newer("1.0.1", "1.0.0"));
        assert!(is_newer("1.1.0", "1.0.9"));
        assert!(is_newer("2.0.0", "1.9.9"));
        // The string comparison this replaces got exactly these wrong.
        assert!(is_newer("1.10.0", "1.9.0"));
        assert!(is_newer("0.10.0", "0.9.0"));
    }

    #[test]
    fn same_or_older_is_not_an_update() {
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("v1.0.0", "1.0.0"));
        assert!(!is_newer("0.9.0", "1.0.0"));
        // Running a build newer than the published release — a maintainer on
        // main — must not be told to "update" backwards.
        assert!(!is_newer("1.0.0", "1.1.0"));
    }

    /// Offline is a promise, not a preference: it outranks the update setting.
    #[tokio::test]
    async fn offline_makes_no_request() {
        let info = check(true, true).await;
        assert!(!info.update_available);
        assert_eq!(info.latest, None);
        assert_eq!(info.error.as_deref(), Some("offline"));
    }

    #[tokio::test]
    async fn disabled_makes_no_request() {
        let info = check(false, false).await;
        assert!(!info.update_available);
        assert_eq!(info.error.as_deref(), Some("disabled"));
    }

    /// The reported version comes from the crate, so a release cannot ship
    /// announcing the wrong "current".
    #[test]
    fn current_version_tracks_the_crate() {
        assert_eq!(current_version(), env!("CARGO_PKG_VERSION"));
        assert!(parse_version(current_version()).is_some());
    }
}
