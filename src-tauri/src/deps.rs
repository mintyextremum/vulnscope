use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;

/// One resolved dependency, in the shape OSV.dev expects.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    /// OSV ecosystem identifier: "npm", "PyPI", "crates.io", "Go", ...
    pub ecosystem: String,
    /// Manifest this came from, relative to the scan root.
    pub manifest: String,
    /// Line in the manifest, for pointing the UI at it. 0 when unknown.
    pub line: u32,
    pub direct: bool,
}

pub const ECOSYSTEM_NPM: &str = "npm";
pub const ECOSYSTEM_PYPI: &str = "PyPI";
pub const ECOSYSTEM_CRATES: &str = "crates.io";

/// Strips npm range operators. OSV needs a concrete version, so ranges that do
/// not pin anything ("*", "latest", a git URL) yield `None`.
fn clean_npm_version(raw: &str) -> Option<String> {
    let v = raw.trim();
    if v.is_empty()
        || v == "*"
        || v == "latest"
        || v.starts_with("workspace:")
        || v.starts_with("file:")
        || v.starts_with("link:")
        || v.starts_with("git")
        || v.contains("://")
        || v.contains('/')
    {
        return None;
    }
    let v = v.trim_start_matches(['^', '~', '>', '<', '=', 'v', ' ']).trim();
    // A range like ">=1.2.0 <2.0.0": take the lower bound as the assumed version.
    let first = v.split_whitespace().next().unwrap_or(v);
    let first = first.split("||").next().unwrap_or(first).trim();
    if first.is_empty() || !first.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return None;
    }
    Some(first.to_string())
}

#[derive(Debug, Deserialize)]
struct PackageJson {
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
}

pub fn parse_package_json(content: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(pkg) = serde_json::from_str::<PackageJson>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let groups = [
        &pkg.dependencies,
        &pkg.dev_dependencies,
        &pkg.optional_dependencies,
    ];
    for group in groups {
        for (name, raw) in group.iter() {
            if let Some(version) = clean_npm_version(raw) {
                out.push(Dependency {
                    name: name.clone(),
                    version,
                    ecosystem: ECOSYSTEM_NPM.to_string(),
                    manifest: manifest.to_string(),
                    line: find_line(content, name),
                    direct: true,
                });
            }
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct PackageLock {
    #[serde(default)]
    packages: BTreeMap<String, LockPackage>,
    #[serde(default)]
    dependencies: BTreeMap<String, LockDepV1>,
}

#[derive(Debug, Deserialize)]
struct LockPackage {
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LockDepV1 {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, LockDepV1>,
}

fn collect_lock_v1(
    deps: &BTreeMap<String, LockDepV1>,
    manifest: &str,
    out: &mut Vec<Dependency>,
) {
    for (name, dep) in deps {
        if let Some(v) = &dep.version {
            out.push(Dependency {
                name: name.clone(),
                version: v.clone(),
                ecosystem: ECOSYSTEM_NPM.to_string(),
                manifest: manifest.to_string(),
                line: 0,
                direct: false,
            });
        }
        collect_lock_v1(&dep.dependencies, manifest, out);
    }
}

/// package-lock.json gives exact resolved versions for the whole tree, which is
/// what actually ships — far more accurate than the ranges in package.json.
pub fn parse_package_lock(content: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(lock) = serde_json::from_str::<PackageLock>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    // lockfileVersion 2/3: flat "packages" map keyed by install path.
    for (path, pkg) in &lock.packages {
        if path.is_empty() {
            continue; // the root project itself
        }
        let Some(version) = &pkg.version else { continue };
        // "node_modules/foo" or "node_modules/@scope/foo/node_modules/bar"
        let Some(idx) = path.rfind("node_modules/") else {
            continue;
        };
        let name = &path[idx + "node_modules/".len()..];
        if name.is_empty() {
            continue;
        }
        out.push(Dependency {
            name: name.to_string(),
            version: version.clone(),
            ecosystem: ECOSYSTEM_NPM.to_string(),
            manifest: manifest.to_string(),
            line: 0,
            direct: !path[..idx].contains("node_modules"),
        });
    }

    // lockfileVersion 1: nested "dependencies".
    if out.is_empty() {
        collect_lock_v1(&lock.dependencies, manifest, &mut out);
    }

    out.sort();
    out.dedup();
    out
}

static REQ_LINE: Lazy<Regex> = Lazy::new(|| {
    // name[extras]==version, with optional environment markers after ';'
    Regex::new(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([0-9][A-Za-z0-9._+!-]*)").unwrap()
});

pub fn parse_requirements_txt(content: &str, manifest: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        if let Some(caps) = REQ_LINE.captures(line) {
            out.push(Dependency {
                name: caps[1].to_string(),
                version: caps[2].to_string(),
                ecosystem: ECOSYSTEM_PYPI.to_string(),
                manifest: manifest.to_string(),
                line: (i + 1) as u32,
                direct: true,
            });
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<CargoLockPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoLockPackage {
    name: String,
    version: String,
    /// Absent for path/workspace members — those are the user's own crates.
    #[serde(default)]
    source: Option<String>,
}

pub fn parse_cargo_lock(content: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(lock) = toml::from_str::<CargoLock>(content) else {
        return Vec::new();
    };
    lock.package
        .into_iter()
        .filter(|p| p.source.is_some())
        .map(|p| Dependency {
            line: find_line(content, &p.name),
            name: p.name,
            version: p.version,
            ecosystem: ECOSYSTEM_CRATES.to_string(),
            manifest: manifest.to_string(),
            direct: false,
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct CargoToml {
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, toml::Value>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: BTreeMap<String, toml::Value>,
}

/// Cargo.toml versions are requirements, not resolved versions. We read them
/// only when Cargo.lock is absent.
fn cargo_dep_version(value: &toml::Value) -> Option<String> {
    let raw = match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(t) => {
            if t.contains_key("path") || t.contains_key("git") {
                return None;
            }
            t.get("version")?.as_str()?.to_string()
        }
        _ => return None,
    };
    let v = raw.trim_start_matches(['^', '~', '>', '<', '=', ' ']).trim();
    let first = v.split(',').next().unwrap_or(v).trim();
    if first.is_empty() || first == "*" {
        return None;
    }
    Some(first.to_string())
}

pub fn parse_cargo_toml(content: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(cargo) = toml::from_str::<CargoToml>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for group in [
        &cargo.dependencies,
        &cargo.dev_dependencies,
        &cargo.build_dependencies,
    ] {
        for (name, value) in group {
            if let Some(version) = cargo_dep_version(value) {
                out.push(Dependency {
                    name: name.clone(),
                    version,
                    ecosystem: ECOSYSTEM_CRATES.to_string(),
                    manifest: manifest.to_string(),
                    line: find_line(content, name),
                    direct: true,
                });
            }
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct PyProject {
    #[serde(default)]
    project: Option<PyProjectProject>,
}

#[derive(Debug, Deserialize)]
struct PyProjectProject {
    #[serde(default)]
    dependencies: Vec<String>,
}

pub fn parse_pyproject(content: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(py) = toml::from_str::<PyProject>(content) else {
        return Vec::new();
    };
    let Some(project) = py.project else {
        return Vec::new();
    };
    project
        .dependencies
        .iter()
        .filter_map(|spec| {
            let caps = REQ_LINE.captures(spec)?;
            Some(Dependency {
                name: caps[1].to_string(),
                version: caps[2].to_string(),
                ecosystem: ECOSYSTEM_PYPI.to_string(),
                manifest: manifest.to_string(),
                line: find_line(content, &caps[1]),
                direct: true,
            })
        })
        .collect()
}

/// Best-effort line lookup for pointing the UI at a dependency in its manifest.
fn find_line(content: &str, name: &str) -> u32 {
    for (i, line) in content.lines().enumerate() {
        if line.contains(name) {
            return (i + 1) as u32;
        }
    }
    0
}

/// Dispatches on the manifest filename. `rel_path` uses forward slashes.
pub fn parse_manifest(rel_path: &str, content: &str) -> Vec<Dependency> {
    let name = rel_path
        .rsplit('/')
        .next()
        .unwrap_or(rel_path)
        .to_ascii_lowercase();

    match name.as_str() {
        "package.json" => parse_package_json(content, rel_path),
        "package-lock.json" => parse_package_lock(content, rel_path),
        "cargo.lock" => parse_cargo_lock(content, rel_path),
        "cargo.toml" => parse_cargo_toml(content, rel_path),
        "pyproject.toml" => parse_pyproject(content, rel_path),
        n if n.starts_with("requirements") && n.ends_with(".txt") => {
            parse_requirements_txt(content, rel_path)
        }
        _ => Vec::new(),
    }
}

/// When both a lockfile and its manifest are present, the lockfile wins: it has
/// resolved versions, so keeping both would double-report every package.
pub fn dedupe(deps: Vec<Dependency>) -> Vec<Dependency> {
    let has_npm_lock = deps.iter().any(|d| d.manifest.ends_with("package-lock.json"));
    let has_cargo_lock = deps.iter().any(|d| d.manifest.ends_with("Cargo.lock"));

    let mut out: Vec<Dependency> = deps
        .into_iter()
        .filter(|d| {
            if has_npm_lock && d.manifest.ends_with("package.json") {
                return false;
            }
            if has_cargo_lock && d.manifest.ends_with("Cargo.toml") {
                return false;
            }
            true
        })
        .collect();

    out.sort();
    out.dedup_by(|a, b| a.name == b.name && a.version == b.version && a.ecosystem == b.ecosystem);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_npm_range_operators() {
        assert_eq!(clean_npm_version("^1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(clean_npm_version("~4.17.21").as_deref(), Some("4.17.21"));
        assert_eq!(clean_npm_version(">=1.2.0 <2.0.0").as_deref(), Some("1.2.0"));
        assert_eq!(clean_npm_version("1.0.0").as_deref(), Some("1.0.0"));
    }

    #[test]
    fn rejects_unpinnable_npm_versions() {
        assert!(clean_npm_version("*").is_none());
        assert!(clean_npm_version("latest").is_none());
        assert!(clean_npm_version("workspace:*").is_none());
        assert!(clean_npm_version("file:../local").is_none());
        assert!(clean_npm_version("github:user/repo").is_none());
    }

    #[test]
    fn parses_package_json() {
        let json = r#"{
            "dependencies": { "lodash": "^4.17.20", "express": "4.17.1" },
            "devDependencies": { "jest": "~29.0.0" }
        }"#;
        let deps = parse_package_json(json, "package.json");
        assert_eq!(deps.len(), 3);
        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.20");
        assert_eq!(lodash.ecosystem, "npm");
    }

    #[test]
    fn parses_package_lock_v3_and_scoped_names() {
        let json = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.20" },
                "node_modules/@babel/core": { "version": "7.20.0" },
                "node_modules/foo/node_modules/bar": { "version": "2.0.0" }
            }
        }"#;
        let deps = parse_package_lock(json, "package-lock.json");
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"@babel/core"));
        assert!(names.contains(&"bar"));
        // Nested packages are transitive, not direct.
        let bar = deps.iter().find(|d| d.name == "bar").unwrap();
        assert!(!bar.direct);
    }

    #[test]
    fn parses_requirements_txt() {
        let txt = "flask==2.0.1\nrequests==2.25.0  # comment\n-r other.txt\n\ndjango>=3.0\nPyYAML[extra]==5.3.1\n";
        let deps = parse_requirements_txt(txt, "requirements.txt");
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"flask"));
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"PyYAML"));
        // Unpinned ranges give OSV nothing to match against.
        assert!(!names.contains(&"django"));
    }

    #[test]
    fn parses_cargo_lock_and_skips_local_crates() {
        let toml_str = r#"
[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-app"
version = "0.1.0"
"#;
        let deps = parse_cargo_lock(toml_str, "Cargo.lock");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].ecosystem, "crates.io");
    }

    #[test]
    fn parses_cargo_toml_table_and_string_forms() {
        let toml_str = r#"
[dependencies]
serde = "1.0.100"
tokio = { version = "1.20", features = ["full"] }
local = { path = "../local" }
"#;
        let deps = parse_cargo_toml(toml_str, "Cargo.toml");
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"tokio"));
        assert!(!names.contains(&"local"));
    }

    #[test]
    fn lockfile_takes_precedence_over_manifest() {
        let deps = vec![
            Dependency {
                name: "lodash".into(),
                version: "4.17.20".into(),
                ecosystem: ECOSYSTEM_NPM.into(),
                manifest: "package.json".into(),
                line: 3,
                direct: true,
            },
            Dependency {
                name: "lodash".into(),
                version: "4.17.21".into(),
                ecosystem: ECOSYSTEM_NPM.into(),
                manifest: "package-lock.json".into(),
                line: 0,
                direct: true,
            },
        ];
        let out = dedupe(deps);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].version, "4.17.21");
    }

    #[test]
    fn malformed_manifest_yields_nothing_rather_than_panicking() {
        assert!(parse_package_json("{ not json", "package.json").is_empty());
        assert!(parse_cargo_lock("[[[garbage", "Cargo.lock").is_empty());
    }

    #[test]
    fn dispatches_by_filename() {
        let deps = parse_manifest("frontend/package.json", r#"{"dependencies":{"a":"1.0.0"}}"#);
        assert_eq!(deps.len(), 1);
        assert!(parse_manifest("src/main.rs", "fn main() {}").is_empty());
    }
}
