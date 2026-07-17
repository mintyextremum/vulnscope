use crate::deps::Dependency;
use crate::model::Severity;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const OSV_QUERY_BATCH: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN: &str = "https://api.osv.dev/v1/vulns";

/// OSV accepts up to 1000 queries per batch; smaller batches keep memory and
/// retry cost sane without meaningfully slowing things down.
const BATCH_SIZE: usize = 200;

/// Parallel advisory fetches. High enough to hide round-trip latency, low
/// enough to stay a polite client of a free public API.
const FETCH_CONCURRENCY: usize = 16;

/// Cached advisories older than this are re-fetched. A week is a reasonable
/// trade between freshness and hammering the API on every scan.
const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub details: String,
    pub aliases: Vec<String>,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub cwe: Vec<String>,
    pub references: Vec<String>,
    /// First version that contains the fix, when the advisory states one.
    pub fixed_version: Option<String>,
    pub published: Option<String>,
}

impl Advisory {
    /// CVE identifiers, which is what users actually recognise. OSV's own id is
    /// often a GHSA, with the CVE listed as an alias.
    pub fn cve_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .aliases
            .iter()
            .chain(std::iter::once(&self.id))
            .filter(|a| a.starts_with("CVE-"))
            .cloned()
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

// ---------------------------------------------------------------- wire types

#[derive(Serialize)]
struct BatchRequest<'a> {
    queries: Vec<Query<'a>>,
}

#[derive(Serialize)]
struct Query<'a> {
    package: QueryPackage<'a>,
    version: &'a str,
}

#[derive(Serialize)]
struct QueryPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnStub>,
}

#[derive(Deserialize)]
struct VulnStub {
    id: String,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
    #[serde(default)]
    published: Option<String>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct OsvReference {
    #[serde(default)]
    url: String,
}

// ------------------------------------------------------------ CVSS handling

/// Extracts the base score from a CVSS v3/v4 vector string.
///
/// OSV and RustSec both give the vector, not the number, so we compute the base
/// score from the exploitability and impact metrics per the CVSS v3.1 spec.
pub fn cvss_base_score(vector: &str) -> Option<f32> {
    let mut m: HashMap<&str, &str> = HashMap::new();
    for part in vector.split('/') {
        let mut it = part.splitn(2, ':');
        if let (Some(k), Some(v)) = (it.next(), it.next()) {
            m.insert(k, v);
        }
    }
    if !vector.starts_with("CVSS:3") {
        return None;
    }

    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let scope_changed = *m.get("S")? == "C";
    let pr = match *m.get("PR")? {
        "N" => 0.85,
        "L" => {
            if scope_changed {
                0.68
            } else {
                0.62
            }
        }
        "H" => {
            if scope_changed {
                0.50
            } else {
                0.27
            }
        }
        _ => return None,
    };
    let impact_val = |s: &str| -> f64 {
        match s {
            "H" => 0.56,
            "L" => 0.22,
            "N" => 0.0,
            _ => 0.0,
        }
    };
    let c = impact_val(m.get("C").copied().unwrap_or("N"));
    let i = impact_val(m.get("I").copied().unwrap_or("N"));
    let a = impact_val(m.get("A").copied().unwrap_or("N"));

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact: f64 = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let base = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    // CVSS rounds up to one decimal.
    Some(((base * 10.0).ceil() / 10.0) as f32)
}

fn extract_cwes(v: &OsvVuln) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(db) = &v.database_specific {
        if let Some(ids) = db.get("cwe_ids").and_then(|c| c.as_array()) {
            for id in ids {
                if let Some(s) = id.as_str() {
                    out.push(s.to_string());
                }
            }
        }
    }
    out
}

/// GitHub advisories carry a severity label even when no CVSS vector is present.
fn github_severity_label(v: &OsvVuln) -> Option<Severity> {
    let db = v.database_specific.as_ref()?;
    let s = db.get("severity")?.as_str()?;
    Some(Severity::from_label(s))
}

fn first_fixed(v: &OsvVuln) -> Option<String> {
    for affected in &v.affected {
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(fixed) = event.get("fixed") {
                    return Some(fixed.clone());
                }
            }
        }
    }
    // Some ecosystems express the fix as a list of patched versions instead.
    for affected in &v.affected {
        if let Some(db) = &affected.database_specific {
            if let Some(v) = db.get("last_known_affected_version_range").and_then(|x| x.as_str()) {
                return Some(format!("новее {}", v.trim_start_matches(['<', '=', ' '])));
            }
        }
    }
    None
}

fn to_advisory(v: OsvVuln) -> Advisory {
    let cvss_vector = v
        .severity
        .iter()
        .find(|s| s.kind.starts_with("CVSS_V3"))
        .or_else(|| v.severity.first())
        .map(|s| s.score.clone());

    let cvss_score = cvss_vector.as_deref().and_then(cvss_base_score);

    let severity = match cvss_score {
        Some(score) => Severity::from_cvss(score),
        // Without a vector, fall back to the advisory's own label, then to a
        // deliberately conservative default rather than guessing high.
        None => github_severity_label(&v).unwrap_or(Severity::Medium),
    };

    Advisory {
        cwe: extract_cwes(&v),
        fixed_version: first_fixed(&v),
        references: v.references.iter().map(|r| r.url.clone()).take(6).collect(),
        id: v.id,
        summary: v.summary,
        details: v.details.chars().take(1200).collect(),
        aliases: v.aliases,
        severity,
        cvss_score,
        cvss_vector,
        published: v.published,
    }
}

// -------------------------------------------------------------------- cache

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    fetched_at: u64,
    advisory: Advisory,
}

pub struct Cache {
    dir: PathBuf,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Cache {
    pub fn new() -> Result<Cache> {
        let dir = dirs::cache_dir()
            .context("не удалось определить каталог кэша")?
            .join("vulnscope")
            .join("osv");
        std::fs::create_dir_all(&dir)?;
        Ok(Cache { dir })
    }

    fn path_for(&self, id: &str) -> PathBuf {
        // Advisory ids are safe filename material, but sanitise defensively:
        // they end up as paths.
        let safe: String = id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
            .collect();
        self.dir.join(format!("{safe}.json"))
    }

    pub fn get(&self, id: &str) -> Option<Advisory> {
        let raw = std::fs::read_to_string(self.path_for(id)).ok()?;
        let entry: CacheEntry = serde_json::from_str(&raw).ok()?;
        if now_secs().saturating_sub(entry.fetched_at) > CACHE_TTL_SECS {
            return None;
        }
        Some(entry.advisory)
    }

    pub fn put(&self, advisory: &Advisory) {
        let entry = CacheEntry {
            fetched_at: now_secs(),
            advisory: advisory.clone(),
        };
        if let Ok(json) = serde_json::to_string(&entry) {
            let _ = std::fs::write(self.path_for(&advisory.id), json);
        }
    }
}

// ------------------------------------------------------------------- client

pub struct OsvClient {
    http: reqwest::Client,
    cache: Option<Cache>,
}

/// Advisories found for one dependency.
pub struct DependencyAdvisories {
    pub dependency: Dependency,
    pub advisories: Vec<Advisory>,
}

impl OsvClient {
    pub fn new() -> OsvClient {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("VulnScope/0.1 (local security scanner)")
            .build()
            .unwrap_or_default();
        OsvClient {
            http,
            cache: Cache::new().ok(),
        }
    }

    /// Maps each dependency to its advisories. Cached advisories are reused, so
    /// a repeat scan of the same project needs no network at all.
    pub async fn query(&self, deps: &[Dependency]) -> Result<Vec<DependencyAdvisories>> {
        if deps.is_empty() {
            return Ok(Vec::new());
        }

        let mut per_dep_ids: Vec<Vec<String>> = Vec::with_capacity(deps.len());

        for chunk in deps.chunks(BATCH_SIZE) {
            let req = BatchRequest {
                queries: chunk
                    .iter()
                    .map(|d| Query {
                        package: QueryPackage {
                            name: &d.name,
                            ecosystem: &d.ecosystem,
                        },
                        version: &d.version,
                    })
                    .collect(),
            };

            let resp = self
                .http
                .post(OSV_QUERY_BATCH)
                .json(&req)
                .send()
                .await
                .context("не удалось обратиться к OSV.dev")?;

            if !resp.status().is_success() {
                anyhow::bail!("OSV.dev вернул статус {}", resp.status());
            }

            let body: BatchResponse = resp.json().await.context("некорректный ответ OSV.dev")?;

            // OSV guarantees results are positionally aligned with queries.
            for i in 0..chunk.len() {
                let ids = body
                    .results
                    .get(i)
                    .map(|r| r.vulns.iter().map(|v| v.id.clone()).collect())
                    .unwrap_or_default();
                per_dep_ids.push(ids);
            }
        }

        // Fetch each distinct advisory once, regardless of how many packages hit it.
        let mut unique: Vec<String> = per_dep_ids.iter().flatten().cloned().collect();
        unique.sort();
        unique.dedup();

        let mut advisories: HashMap<String, Advisory> = HashMap::new();
        let mut to_fetch: Vec<String> = Vec::new();

        for id in &unique {
            match self.cache.as_ref().and_then(|c| c.get(id)) {
                Some(cached) => {
                    advisories.insert(id.clone(), cached);
                }
                None => to_fetch.push(id.clone()),
            }
        }

        // Advisories are independent GETs, so fetching them one at a time makes
        // the scan latency-bound: a project with 100 advisories would spend
        // minutes waiting on round-trips. Fetch in bounded-concurrency waves.
        for chunk in to_fetch.chunks(FETCH_CONCURRENCY) {
            let mut set = tokio::task::JoinSet::new();
            for id in chunk {
                let http = self.http.clone();
                let id = id.clone();
                set.spawn(async move {
                    let result = Self::fetch_with(&http, &id).await;
                    (id, result)
                });
            }
            while let Some(joined) = set.join_next().await {
                // A single bad advisory must not sink the whole scan.
                let Ok((id, Ok(adv))) = joined else { continue };
                if let Some(c) = &self.cache {
                    c.put(&adv);
                }
                advisories.insert(id, adv);
            }
        }

        Ok(deps
            .iter()
            .zip(per_dep_ids)
            .map(|(dep, ids)| {
                let mut found: Vec<Advisory> = ids
                    .iter()
                    .filter_map(|id| advisories.get(id).cloned())
                    .collect();
                found.sort_by_key(|a| std::cmp::Reverse(a.severity));
                DependencyAdvisories {
                    dependency: dep.clone(),
                    advisories: found,
                }
            })
            .filter(|d| !d.advisories.is_empty())
            .collect())
    }

    async fn fetch_with(http: &reqwest::Client, id: &str) -> Result<Advisory> {
        let resp = http
            .get(format!("{OSV_VULN}/{id}"))
            .send()
            .await?
            .error_for_status()?;
        let vuln: OsvVuln = resp.json().await?;
        Ok(to_advisory(vuln))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_cvss_v3_base_score() {
        // Known vectors with published base scores.
        let s = cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((s - 9.8).abs() < 0.05, "got {s}, expected 9.8");

        let s = cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").unwrap();
        assert!((s - 7.5).abs() < 0.05, "got {s}, expected 7.5");

        let s = cvss_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N").unwrap();
        assert!((s - 1.8).abs() < 0.05, "got {s}, expected 1.8");
    }

    #[test]
    fn computes_scope_changed_score() {
        // Scope change applies the 1.08 multiplier and different PR weights.
        let s = cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").unwrap();
        assert!((s - 6.1).abs() < 0.05, "got {s}, expected 6.1");
    }

    #[test]
    fn rejects_non_v3_vectors() {
        assert!(cvss_base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P").is_none());
        assert!(cvss_base_score("garbage").is_none());
    }

    #[test]
    fn maps_score_to_severity_bands() {
        assert_eq!(Severity::from_cvss(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.3), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.1), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::Info);
    }

    #[test]
    fn extracts_cve_from_aliases() {
        let adv = Advisory {
            id: "GHSA-1234-5678-90ab".into(),
            summary: String::new(),
            details: String::new(),
            aliases: vec!["CVE-2021-23337".into(), "SNYK-JS-LODASH-1040724".into()],
            severity: Severity::High,
            cvss_score: None,
            cvss_vector: None,
            cwe: vec![],
            references: vec![],
            fixed_version: None,
            published: None,
        };
        assert_eq!(adv.cve_ids(), vec!["CVE-2021-23337"]);
    }

    #[test]
    fn parses_osv_vuln_json_into_advisory() {
        let json = r#"{
            "id": "GHSA-35jh-r3h4-6jhm",
            "summary": "Command Injection in lodash",
            "details": "lodash versions prior to 4.17.21 are vulnerable.",
            "aliases": ["CVE-2021-23337"],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
            "references": [{"type": "WEB", "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"}],
            "database_specific": {"cwe_ids": ["CWE-77"], "severity": "HIGH"}
        }"#;
        let vuln: OsvVuln = serde_json::from_str(json).unwrap();
        let adv = to_advisory(vuln);
        assert_eq!(adv.severity, Severity::Critical);
        assert_eq!(adv.fixed_version.as_deref(), Some("4.17.21"));
        assert_eq!(adv.cve_ids(), vec!["CVE-2021-23337"]);
        assert_eq!(adv.cwe, vec!["CWE-77"]);
        assert!(adv.cvss_score.unwrap() > 9.0);
    }

    #[test]
    fn falls_back_to_label_when_no_cvss_vector() {
        let json = r#"{
            "id": "GHSA-xxxx",
            "summary": "x",
            "affected": [],
            "database_specific": {"severity": "MODERATE"}
        }"#;
        let vuln: OsvVuln = serde_json::from_str(json).unwrap();
        let adv = to_advisory(vuln);
        assert_eq!(adv.severity, Severity::Medium);
        assert!(adv.cvss_score.is_none());
    }
}
