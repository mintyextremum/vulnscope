use crate::model::{BlameInfo, Finding};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};

/// Annotates findings with `git blame` attribution: who last touched each
/// offending line, in which commit, and when. This is what turns a finding into
/// an accountable work item — the report can then break results down per author.
///
/// Attribution is deliberately skipped when it would lie:
/// - outside a git work tree there is nothing to blame;
/// - in a shallow clone every line is pinned to the truncation boundary commit,
///   which credits the wrong person (our repo scans clone with `--depth 1`);
/// - uncommitted lines belong to no commit yet.
///
/// A blame failure on one file (renamed, outside the repo, .gitignored) simply
/// leaves those findings unattributed — never fails the scan.
pub fn annotate(root: &Path, findings: &mut [Finding]) {
    if !repo_supports_blame(root) {
        return;
    }

    // Group finding indices by file; dependency findings (line 0) have no line
    // to blame.
    let mut by_file: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        if f.line > 0 && !f.file.is_empty() {
            by_file.entry(f.file.as_str()).or_default().push(i);
        }
    }

    // A bound on subprocess count. Findings concentrate in few files in
    // practice; a pathological project stops attributing rather than stalling
    // the scan tail on thousands of git spawns.
    const MAX_FILES: usize = 800;
    let files: Vec<(&str, Vec<u32>)> = by_file
        .iter()
        .take(MAX_FILES)
        .map(|(file, idxs)| {
            let mut lines: Vec<u32> = idxs.iter().map(|&i| findings[i].line).collect();
            lines.sort_unstable();
            lines.dedup();
            (*file, lines)
        })
        .collect();

    let blamed: HashMap<String, HashMap<u32, BlameInfo>> = files
        .par_iter()
        .filter_map(|(file, lines)| {
            blame_file(root, file, lines).map(|m| (file.to_string(), m))
        })
        .collect();

    for f in findings.iter_mut() {
        let Some(info) = blamed.get(&f.file).and_then(|m| m.get(&f.line)) else {
            continue;
        };
        f.extra.get_or_insert_with(Default::default).blame = Some(info.clone());
    }
}

/// True only for a non-shallow work tree — the two conditions under which blame
/// output can be trusted.
fn repo_supports_blame(root: &Path) -> bool {
    let Ok(out) = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--is-inside-work-tree", "--is-shallow-repository"])
        .stdin(Stdio::null())
        .output()
    else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    lines.next() == Some("true") && lines.next() == Some("false")
}

/// Blames just the finding lines of one file (`-L n,n` per line, one process
/// per file) and returns line → attribution.
fn blame_file(root: &Path, file: &str, lines: &[u32]) -> Option<HashMap<u32, BlameInfo>> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(root).args(["blame", "--line-porcelain"]);
    for l in lines {
        cmd.arg("-L").arg(format!("{l},{l}"));
    }
    // Git wants forward slashes for pathspecs regardless of platform.
    cmd.arg("--").arg(file.replace('\\', "/"));
    let out = cmd.stdin(Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_line_porcelain(&String::from_utf8_lossy(&out.stdout)))
}

/// Parses `git blame --line-porcelain` output. Each blamed line is a block:
/// a `<sha> <orig> <final>` header, `key value` attribution lines, then the
/// tab-prefixed content line. `--line-porcelain` repeats full attribution for
/// every line, so blocks can be parsed independently.
fn parse_line_porcelain(out: &str) -> HashMap<u32, BlameInfo> {
    let mut map = HashMap::new();
    let mut sha = "";
    let mut final_line: u32 = 0;
    let mut author = "";
    let mut mail = "";
    let mut time: i64 = 0;

    for line in out.lines() {
        if let Some(rest) = line.strip_prefix('\t') {
            let _ = rest; // the content line closes the block
            // All-zero sha means the line is not committed yet: no attribution.
            if final_line > 0 && !sha.is_empty() && !sha.bytes().all(|b| b == b'0') {
                let date = chrono::DateTime::from_timestamp(time, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_default();
                let email = mail
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string();
                map.insert(
                    final_line,
                    BlameInfo {
                        author: author.to_string(),
                        email: (!email.is_empty()).then_some(email),
                        commit: sha.chars().take(8).collect(),
                        date,
                    },
                );
            }
            sha = "";
            final_line = 0;
            author = "";
            mail = "";
            time = 0;
        } else if let Some(v) = line.strip_prefix("author ") {
            author = v;
        } else if let Some(v) = line.strip_prefix("author-mail ") {
            mail = v;
        } else if let Some(v) = line.strip_prefix("author-time ") {
            time = v.parse().unwrap_or(0);
        } else if sha.is_empty() {
            // Block header: `<sha> <orig_line> <final_line> [<group_size>]`.
            let mut parts = line.split(' ');
            if let (Some(h), Some(_), Some(fl)) = (parts.next(), parts.next(), parts.next()) {
                if h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    sha = h;
                    final_line = fl.parse().unwrap_or(0);
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
1234567890abcdef1234567890abcdef12345678 3 3 1
author Мария Иванова
author-mail <maria@example.com>
author-time 1721600000
author-tz +0300
committer Мария Иванова
committer-mail <maria@example.com>
committer-time 1721600000
committer-tz +0300
summary add db query
filename db.py
\tcursor.execute(\"select * from users where id = \" + user_id)
0000000000000000000000000000000000000000 7 7 1
author Not Committed Yet
author-mail <not.committed.yet>
author-time 1721600001
author-tz +0300
summary Version of db.py from db.py
filename db.py
\teval(payload)
";

    #[test]
    fn parses_author_commit_and_date_per_line() {
        let map = parse_line_porcelain(SAMPLE);
        let info = map.get(&3).expect("line 3 attributed");
        assert_eq!(info.author, "Мария Иванова");
        assert_eq!(info.email.as_deref(), Some("maria@example.com"));
        assert_eq!(info.commit, "12345678");
        assert_eq!(info.date, "2024-07-21");
    }

    #[test]
    fn uncommitted_lines_are_left_unattributed() {
        // The all-zero sha is git's "not committed yet" marker; naming a phantom
        // author would put fiction in the accountability report.
        let map = parse_line_porcelain(SAMPLE);
        assert!(!map.contains_key(&7));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn tolerates_garbage_input() {
        assert!(parse_line_porcelain("").is_empty());
        assert!(parse_line_porcelain("fatal: no such path 'x' in HEAD").is_empty());
    }
}
