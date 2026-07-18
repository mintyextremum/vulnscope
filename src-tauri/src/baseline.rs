use crate::model::{Finding, Severity};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// A stable identity for a finding across scans.
///
/// Deliberately excludes the line number. Inserting an import at the top of a
/// file shifts every line below it; keying on the line would mark every finding
/// in that file as "fixed" and immediately "new" again, and would silently void
/// every suppression the user wrote. Instead this hashes the offending code with
/// whitespace collapsed, so reformatting does not break it either.
pub fn fingerprint(f: &Finding) -> String {
    let code = normalize_code(&f.snippet);

    let mut h = Sha256::new();
    h.update(f.rule_id.as_bytes());
    h.update([0]);
    h.update(f.file.as_bytes());
    h.update([0]);
    h.update(code.as_bytes());

    // Dependency findings repeat per package, and their snippet is just the
    // package name — include the version so an upgrade reads as a real change.
    if let Some(p) = &f.package {
        h.update([0]);
        h.update(p.name.as_bytes());
        h.update([0]);
        h.update(p.version.as_bytes());
    }

    hex16(&h.finalize())
}

/// First 8 bytes of a digest as hex. Enough to distinguish findings within one
/// project, short enough to stay readable in .vulnscope-ignore.
fn hex16(bytes: &[u8]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Collapses whitespace and drops empty lines so that reindenting or
/// reformatting a block does not change its identity.
fn normalize_code(snippet: &str) -> String {
    snippet
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

// ------------------------------------------------------------ suppression

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Suppression {
    /// Fingerprint of one specific finding, or empty when suppressing by rule.
    #[serde(default)]
    pub fingerprint: String,
    pub rule_id: String,
    /// Kept for humans reading the file; matching uses the fingerprint.
    #[serde(default)]
    pub file: String,
    /// Suppress every finding of `rule_id` in `file` rather than just one.
    #[serde(default)]
    pub whole_file: bool,
    /// Required: a suppression without a stated reason is indistinguishable
    /// from someone hiding a real problem.
    pub reason: String,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IgnoreFile {
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
}

/// Lives in the scanned project, not in app config: a suppression is a
/// statement about *this code*, so it belongs in the repository next to it and
/// should travel with a clone and show up in review.
pub const IGNORE_FILE: &str = ".vulnscope-ignore";

pub fn ignore_path(root: &Path) -> PathBuf {
    root.join(IGNORE_FILE)
}

pub fn load_ignores(root: &Path) -> (Vec<Suppression>, Option<String>) {
    let path = ignore_path(root);
    if !path.exists() {
        return (Vec::new(), None);
    }
    match std::fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<IgnoreFile>(&raw) {
            Ok(f) => (f.suppressions, None),
            // A malformed file must not silently disable every suppression, nor
            // abort the scan: report it and scan with none.
            Err(e) => (
                Vec::new(),
                Some(format!(
                    ".vulnscope-ignore повреждён и не применён: {e}. Правила подавления сейчас не действуют."
                )),
            ),
        },
        Err(e) => (
            Vec::new(),
            Some(format!("не удалось прочитать .vulnscope-ignore: {e}")),
        ),
    }
}

pub fn save_ignores(root: &Path, items: &[Suppression]) -> Result<()> {
    let path = ignore_path(root);
    let file = IgnoreFile {
        suppressions: items.to_vec(),
    };
    let json = serde_json::to_string_pretty(&file)?;
    std::fs::write(&path, json).with_context(|| format!("не удалось записать {}", path.display()))
}

/// The suppression covering `f`, if any — the scanner needs the matched entry
/// to show its reason, so this returns it instead of a bare bool.
pub fn match_suppression<'a>(
    f: &Finding,
    fp: &str,
    ignores: &'a [Suppression],
) -> Option<&'a Suppression> {
    ignores.iter().find(|s| {
        if s.whole_file {
            s.rule_id == f.rule_id && s.file == f.file
        } else {
            // An empty fingerprint would match every unfingerprinted finding.
            !s.fingerprint.is_empty() && s.fingerprint == fp
        }
    })
}

/// True when `f` is covered by any suppression. A readability shim for the
/// tests; the scanner takes `match_suppression` because it needs the reason.
#[cfg(test)]
pub fn is_suppressed(f: &Finding, fp: &str, ignores: &[Suppression]) -> bool {
    match_suppression(f, fp, ignores).is_some()
}

// -------------------------------------------------------------- comparison

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingStatus {
    /// Not present in the previous scan of this target.
    New,
    /// Present in both.
    Existing,
}

/// What changed since the previous scan of the same target.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanDelta {
    /// None when this is the first scan of the target: "0 new" would be a lie.
    pub previous_scan_at: Option<String>,
    pub new_count: u32,
    pub fixed_count: u32,
    pub unchanged_count: u32,
    /// Findings gone since last time, kept so the user can see what they fixed.
    pub fixed: Vec<FixedFinding>,
    pub new_by_severity: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixedFinding {
    pub fingerprint: String,
    pub rule_id: String,
    pub title: String,
    pub file: String,
    pub severity: Severity,
}

/// The slice of a report kept for comparison. Storing whole reports would grow
/// without bound; this keeps history cheap.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub scanned_at: String,
    pub target_label: String,
    pub findings: Vec<SnapshotFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotFinding {
    pub fingerprint: String,
    pub rule_id: String,
    pub title: String,
    pub file: String,
    pub severity: Severity,
}

fn history_dir() -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .context("не удалось определить каталог данных")?
        .join("vulnscope")
        .join("history");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// A stable key for a scanned root, so the same project always maps to the same
/// baseline. `D:\proj`, `D:/proj`, a trailing slash and a differently-cased drive
/// letter all name the same directory on Windows yet hash differently — keying on
/// the raw string silently reset the delta to "first scan" whenever the spelling
/// changed. Canonicalising collapses those forms; a path that no longer exists
/// falls back to normalising the string it was given.
fn normalize_root(root: &Path) -> String {
    if let Ok(c) = std::fs::canonicalize(root) {
        return c.to_string_lossy().to_lowercase();
    }
    root.to_string_lossy().replace('\\', "/").trim_end_matches('/').to_lowercase()
}

/// One file per scanned root, so scanning project A never disturbs project B's
/// baseline.
fn snapshot_path(root: &Path) -> Result<PathBuf> {
    let mut h = Sha256::new();
    h.update(normalize_root(root).as_bytes());
    let key = hex16(&h.finalize());
    Ok(history_dir()?.join(format!("{key}.json")))
}

pub fn load_snapshot(root: &Path) -> Option<Snapshot> {
    let path = snapshot_path(root).ok()?;
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_snapshot(root: &Path, snap: &Snapshot) -> Result<()> {
    let path = snapshot_path(root)?;
    std::fs::write(&path, serde_json::to_string(snap)?)?;
    Ok(())
}

pub fn to_snapshot(target_label: &str, scanned_at: &str, findings: &[(String, &Finding)]) -> Snapshot {
    Snapshot {
        scanned_at: scanned_at.to_string(),
        target_label: target_label.to_string(),
        findings: findings
            .iter()
            .map(|(fp, f)| SnapshotFinding {
                fingerprint: fp.clone(),
                rule_id: f.rule_id.clone(),
                title: f.title.clone(),
                file: f.file.clone(),
                severity: f.severity,
            })
            .collect(),
    }
}

/// Compares this scan against the previous snapshot of the same target.
/// Splits the current findings into new / unchanged, and names what is gone.
///
/// `suppressed` holds the fingerprints the user has silenced. They are absent
/// from `current` (which is the active set), so without this they would look
/// exactly like findings that vanished from the code, and suppressing anything
/// would congratulate the user for "fixing" it. Silencing a finding is not
/// fixing it, so those fingerprints are excluded from `fixed`.
pub fn compare(
    current: &[(String, &Finding)],
    previous: Option<&Snapshot>,
    suppressed: &HashSet<String>,
) -> (ScanDelta, HashMap<String, FindingStatus>) {
    let mut statuses = HashMap::new();

    let Some(prev) = previous else {
        // First scan: everything is "existing", not "new". Calling every
        // finding new on a first run makes the delta meaningless.
        for (fp, _) in current {
            statuses.insert(fp.clone(), FindingStatus::Existing);
        }
        return (ScanDelta::default(), statuses);
    };

    let prev_fps: HashSet<&str> = prev.findings.iter().map(|f| f.fingerprint.as_str()).collect();
    let cur_fps: HashSet<&str> = current.iter().map(|(fp, _)| fp.as_str()).collect();

    let mut delta = ScanDelta {
        previous_scan_at: Some(prev.scanned_at.clone()),
        ..Default::default()
    };

    for (fp, f) in current {
        if prev_fps.contains(fp.as_str()) {
            statuses.insert(fp.clone(), FindingStatus::Existing);
            delta.unchanged_count += 1;
        } else {
            statuses.insert(fp.clone(), FindingStatus::New);
            delta.new_count += 1;
            *delta
                .new_by_severity
                .entry(severity_key(f.severity))
                .or_insert(0) += 1;
        }
    }

    for p in &prev.findings {
        if !cur_fps.contains(p.fingerprint.as_str()) && !suppressed.contains(&p.fingerprint) {
            delta.fixed_count += 1;
            delta.fixed.push(FixedFinding {
                fingerprint: p.fingerprint.clone(),
                rule_id: p.rule_id.clone(),
                title: p.title.clone(),
                file: p.file.clone(),
                severity: p.severity,
            });
        }
    }

    delta.fixed.sort_by_key(|f| std::cmp::Reverse(f.severity));
    (delta, statuses)
}

fn severity_key(s: Severity) -> String {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, FindingSource, PackageInfo};

    #[test]
    fn snapshot_key_ignores_path_spelling() {
        // A non-existent path exercises the string-normalisation branch, which is
        // deterministic on any machine (canonicalize would need the dir to exist).
        // All four spell the same directory and must produce the same key, or the
        // baseline resets to "first scan" when the path is typed differently.
        let key = |p: &str| {
            let mut h = Sha256::new();
            h.update(normalize_root(Path::new(p)).as_bytes());
            hex16(&h.finalize())
        };
        let forms = ["Z:/nope/proj", "Z:\\nope\\proj", "Z:\\Nope\\Proj\\", "z:/nope/proj/"];
        let keys: Vec<_> = forms.iter().map(|p| key(p)).collect();
        assert!(keys.windows(2).all(|w| w[0] == w[1]), "same dir, different spelling: {keys:?}");
        // A genuinely different directory must still key differently.
        assert_ne!(key("Z:/nope/proj"), key("Z:/nope/other"));
    }

    fn f(rule: &str, file: &str, line: u32, snippet: &str) -> Finding {
        Finding {
            id: format!("{rule}:{file}:{line}"),
            fingerprint: String::new(),
            suppressed: false,
            suppression_reason: None,
            is_new: false,
            rule_id: rule.into(),
            title: "t".into(),
            description: String::new(),
            recommendation: String::new(),
            severity: Severity::High,
            confidence: Confidence::High,
            source: FindingSource::Builtin,
            source_label: "x".into(),
            category: "c".into(),
            file: file.into(),
            line,
            end_line: line,
            column: 1,
            end_column: 1,
            snippet: snippet.into(),
            snippet_start_line: line,
            cwe: vec![],
            owasp: None,
            cve: vec![],
            references: vec![],
            package: None,
        }
    }

    /// The whole point of the fingerprint: adding an import above a finding
    /// must not make it look like a different problem.
    #[test]
    fn fingerprint_survives_line_shifts() {
        let a = f("VS-PY-001", "app.py", 10, "eval(user_input)");
        let b = f("VS-PY-001", "app.py", 42, "eval(user_input)");
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_survives_reindentation() {
        let a = f("VS-PY-001", "app.py", 10, "    eval(x)");
        let b = f("VS-PY-001", "app.py", 10, "        eval(x)");
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_when_the_code_changes() {
        let a = f("VS-PY-001", "app.py", 10, "eval(user_input)");
        let b = f("VS-PY-001", "app.py", 10, "eval(other_input)");
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_distinguishes_rule_and_file() {
        let base = f("VS-PY-001", "app.py", 1, "eval(x)");
        let other_rule = f("VS-PY-002", "app.py", 1, "eval(x)");
        let other_file = f("VS-PY-001", "lib.py", 1, "eval(x)");
        assert_ne!(fingerprint(&base), fingerprint(&other_rule));
        assert_ne!(fingerprint(&base), fingerprint(&other_file));
    }

    #[test]
    fn dependency_upgrade_reads_as_a_change() {
        // The snippet is just the package name, so without the version an
        // upgrade would look like the same finding.
        let mut a = f("GHSA-x", "package.json", 0, "lodash");
        a.package = Some(PackageInfo {
            name: "lodash".into(),
            version: "4.17.20".into(),
            ecosystem: "npm".into(),
            fixed_version: None,
        });
        let mut b = a.clone();
        b.package.as_mut().unwrap().version = "4.17.21".into();
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    fn sup(fp: &str, rule: &str, file: &str, whole: bool) -> Suppression {
        Suppression {
            fingerprint: fp.into(),
            rule_id: rule.into(),
            file: file.into(),
            whole_file: whole,
            reason: "проверено, ложное срабатывание".into(),
            created_at: "2026-07-15".into(),
        }
    }

    #[test]
    fn suppresses_one_finding_by_fingerprint() {
        let finding = f("VS-PY-001", "app.py", 10, "eval(x)");
        let fp = fingerprint(&finding);
        let ig = vec![sup(&fp, "VS-PY-001", "app.py", false)];
        assert!(is_suppressed(&finding, &fp, &ig));

        // A different finding of the same rule stays visible.
        let other = f("VS-PY-001", "app.py", 20, "eval(y)");
        let ofp = fingerprint(&other);
        assert!(!is_suppressed(&other, &ofp, &ig));
    }

    #[test]
    fn suppresses_a_whole_rule_in_one_file() {
        let ig = vec![sup("", "VS-JS-015", "src/rng.js", true)];
        let a = f("VS-JS-015", "src/rng.js", 1, "Math.random()");
        let b = f("VS-JS-015", "src/rng.js", 99, "Math.random()");
        assert!(is_suppressed(&a, &fingerprint(&a), &ig));
        assert!(is_suppressed(&b, &fingerprint(&b), &ig));

        // Same rule elsewhere is not covered.
        let c = f("VS-JS-015", "src/other.js", 1, "Math.random()");
        assert!(!is_suppressed(&c, &fingerprint(&c), &ig));
    }

    #[test]
    fn a_fingerprint_suppression_does_not_leak_across_files() {
        let a = f("VS-PY-001", "app.py", 10, "eval(x)");
        let b = f("VS-PY-001", "other.py", 10, "eval(x)");
        let ig = vec![sup(&fingerprint(&a), "VS-PY-001", "app.py", false)];
        assert!(!is_suppressed(&b, &fingerprint(&b), &ig));
    }

    #[test]
    fn the_matched_suppression_carries_its_reason_back() {
        // The scanner shows this text in the UI; matching without returning the
        // entry would leave the user with a silenced finding and no "why".
        let a = f("VS-PY-001", "app.py", 10, "eval(x)");
        let ig = vec![sup(&fingerprint(&a), "VS-PY-001", "app.py", false)];
        let hit = match_suppression(&a, &fingerprint(&a), &ig).expect("должно совпасть");
        assert_eq!(hit.reason, ig[0].reason);
    }

    #[test]
    fn first_scan_reports_no_delta_rather_than_all_new() {
        let a = f("R1", "a.py", 1, "x");
        let cur = vec![(fingerprint(&a), &a)];
        let (delta, statuses) = compare(&cur, None, &HashSet::new());
        assert_eq!(delta.new_count, 0);
        assert!(delta.previous_scan_at.is_none());
        assert_eq!(statuses[&fingerprint(&a)], FindingStatus::Existing);
    }

    #[test]
    fn compare_splits_new_fixed_and_unchanged() {
        let kept = f("R1", "a.py", 1, "eval(x)");
        let added = f("R2", "b.py", 5, "exec(y)");
        let gone = f("R3", "c.py", 9, "pickle.loads(z)");

        let prev = to_snapshot("proj", "2026-07-14", &[(fingerprint(&kept), &kept), (fingerprint(&gone), &gone)]);
        let cur = vec![(fingerprint(&kept), &kept), (fingerprint(&added), &added)];

        let (delta, statuses) = compare(&cur, Some(&prev), &HashSet::new());
        assert_eq!(delta.new_count, 1);
        assert_eq!(delta.fixed_count, 1);
        assert_eq!(delta.unchanged_count, 1);
        assert_eq!(delta.fixed[0].rule_id, "R3");
        assert_eq!(delta.previous_scan_at.as_deref(), Some("2026-07-14"));
        assert_eq!(statuses[&fingerprint(&added)], FindingStatus::New);
        assert_eq!(statuses[&fingerprint(&kept)], FindingStatus::Existing);
        assert_eq!(delta.new_by_severity["high"], 1);
    }

    #[test]
    fn suppressing_a_finding_does_not_read_as_fixing_it() {
        // Silencing a finding removes it from the active set, which looks
        // identical to the code being fixed. Rewarding a suppression with
        // "1 fixed" would turn the delta into a lie the user can game.
        let a = f("R1", "a.py", 1, "eval(x)");
        let fp = fingerprint(&a);
        let prev = to_snapshot("p", "2026-07-14", &[(fp.clone(), &a)]);

        let suppressed: HashSet<String> = [fp.clone()].into_iter().collect();
        let (delta, _) = compare(&[], Some(&prev), &suppressed);
        assert_eq!(delta.fixed_count, 0);
        assert!(delta.fixed.is_empty());

        // ...but genuinely deleting the code still counts as fixed.
        let (delta, _) = compare(&[], Some(&prev), &HashSet::new());
        assert_eq!(delta.fixed_count, 1);
    }

    #[test]
    fn moving_code_within_a_file_is_not_new_work() {
        // The same finding at a new line must not be reported as one fixed and
        // one new — that is the failure mode this whole design avoids.
        let before = f("R1", "a.py", 10, "eval(x)");
        let after = f("R1", "a.py", 40, "eval(x)");
        let prev = to_snapshot("p", "t", &[(fingerprint(&before), &before)]);
        let cur = vec![(fingerprint(&after), &after)];

        let (delta, _) = compare(&cur, Some(&prev), &HashSet::new());
        assert_eq!(delta.new_count, 0);
        assert_eq!(delta.fixed_count, 0);
        assert_eq!(delta.unchanged_count, 1);
    }

    #[test]
    fn ignore_file_round_trips() {
        let dir = std::env::temp_dir().join("vulnscope-test-ignore");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let items = vec![sup("abc123", "VS-PY-001", "app.py", false)];
        save_ignores(&dir, &items).unwrap();
        let (back, warn) = load_ignores(&dir);
        assert!(warn.is_none());
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].fingerprint, "abc123");
        assert_eq!(back[0].reason, "проверено, ложное срабатывание");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_broken_ignore_file_warns_rather_than_silently_disabling() {
        let dir = std::env::temp_dir().join("vulnscope-test-ignore-bad");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(ignore_path(&dir), "{ not json").unwrap();

        let (items, warn) = load_ignores(&dir);
        assert!(items.is_empty());
        // Silently ignoring a corrupt file would hide that suppressions stopped
        // applying, which reads as a pile of new findings out of nowhere.
        assert!(warn.is_some(), "corrupt ignore file must warn");
        assert!(warn.unwrap().contains("повреждён"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_ignore_file_is_not_an_error() {
        let dir = std::env::temp_dir().join("vulnscope-test-ignore-none");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (items, warn) = load_ignores(&dir);
        assert!(items.is_empty());
        assert!(warn.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
