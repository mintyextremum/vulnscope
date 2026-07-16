use crate::model::{Language, SkipReason, SkippedFile};
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Files above this size are not worth regex-scanning; they are almost always
/// generated data rather than hand-written source.
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

/// If any line is longer than this the file is treated as minified/bundled.
const MINIFIED_LINE_LEN: usize = 2_000;

/// How much of the head of a file we sniff to decide whether it is binary.
const SNIFF_BYTES: usize = 8_000;

const BINARY_EXTS: &[&str] = &[
    "exe", "dll", "so", "dylib", "bin", "o", "obj", "a", "lib", "class", "jar", "pyc", "pyd", "pyo",
    "wasm", "node", "rlib", "rmeta", "pdb", "msi", "apk", "aab", "ipa", "dex", "elf", "com", "sys",
    "ocx", "cab", "deb", "rpm", "dmg", "pkg", "img", "iso", "db", "sqlite", "sqlite3", "mdb",
    "dat", "idx", "pack", "bak",
];

const MEDIA_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "icns", "webp", "avif", "tiff", "tif", "svgz", "psd",
    "ai", "eps", "mp3", "mp4", "wav", "flac", "ogg", "avi", "mov", "mkv", "webm", "wmv", "m4a",
    "m4v", "aac", "ttf", "otf", "woff", "woff2", "eot", "pdf", "doc", "docx", "xls", "xlsx", "ppt",
    "pptx",
];

const ARCHIVE_EXTS: &[&str] = &[
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "tgz", "tbz", "zst", "lz4", "lzma", "whl", "egg",
];

/// Directory names that hold third-party or generated code. Findings inside them
/// are not actionable for the user, and they dominate scan time.
const VENDOR_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "site-packages",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".gradle",
    ".idea",
    ".vscode",
    "coverage",
    ".nyc_output",
    "bower_components",
    ".git",
    ".svn",
    ".hg",
    "Pods",
    "DerivedData",
    ".terraform",
    ".serverless",
    "bin",
    "obj",
];

/// Filenames that are dependency manifests. They are parsed by `deps`, not by
/// the regex rules, but must never be skipped as "generated".
pub const MANIFEST_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "cargo.toml",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
];

pub struct Candidate {
    pub abs_path: PathBuf,
    pub rel_path: String,
    pub language: Language,
    pub is_manifest: bool,
}

pub struct Discovery {
    pub candidates: Vec<Candidate>,
    pub skipped: Vec<SkippedFile>,
}

pub struct WalkOptions {
    pub respect_gitignore: bool,
    pub include_vendor: bool,
    pub follow_symlinks: bool,
    pub max_file_size: u64,
    pub minified_line_len: usize,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            respect_gitignore: true,
            include_vendor: false,
            follow_symlinks: false,
            max_file_size: MAX_FILE_SIZE,
            minified_line_len: MINIFIED_LINE_LEN,
        }
    }
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn ext_of(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_manifest(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| MANIFEST_FILES.contains(&n.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Extension-based classification. Returns `None` when the file looks scannable.
fn classify_by_extension(path: &Path) -> Option<SkipReason> {
    let ext = ext_of(path);
    if BINARY_EXTS.contains(&ext.as_str()) {
        return Some(SkipReason::BinaryExtension);
    }
    if MEDIA_EXTS.contains(&ext.as_str()) {
        return Some(SkipReason::Media);
    }
    if ARCHIVE_EXTS.contains(&ext.as_str()) {
        return Some(SkipReason::Archive);
    }

    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Bundler output and sourcemaps: generated, and huge.
    if name.ends_with(".min.js")
        || name.ends_with(".min.css")
        || name.ends_with(".map")
        || name.ends_with(".bundle.js")
        || name.ends_with(".chunk.js")
    {
        return Some(SkipReason::Minified);
    }

    None
}

/// Sniffs the first bytes for NUL / invalid UTF-8. Catches binaries that carry a
/// text-looking extension or none at all.
fn looks_binary(head: &[u8]) -> bool {
    if head.is_empty() {
        return false;
    }
    if head.contains(&0) {
        return true;
    }
    // A high share of non-printable control bytes means it is not source code.
    let suspicious = head
        .iter()
        .filter(|&&b| b < 0x09 || (b > 0x0d && b < 0x20))
        .count();
    suspicious * 100 / head.len() > 10
}

fn read_head(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; SNIFF_BYTES];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

pub fn discover(root: &Path, opts: &WalkOptions) -> Discovery {
    let mut candidates = Vec::new();
    let mut skipped = Vec::new();

    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .git_ignore(opts.respect_gitignore)
        .git_global(opts.respect_gitignore)
        .git_exclude(opts.respect_gitignore)
        .ignore(opts.respect_gitignore)
        .follow_links(opts.follow_symlinks)
        .parents(false);

    if !opts.include_vendor {
        let vendor = VENDOR_DIRS.to_vec();
        builder.filter_entry(move |entry| {
            // Only prune directories; a *file* named `bin` should still be read.
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    return !vendor.contains(&name);
                }
            }
            true
        });
    }

    for result in builder.build() {
        let entry = match result {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }

        let path = entry.path();

        // Our own ignore file is not the user's code. Counting it would inflate
        // the file and line totals, and its stored rule ids and paths are
        // exactly the kind of text the secret and pattern rules react to.
        if path.file_name().and_then(|n| n.to_str()) == Some(crate::baseline::IGNORE_FILE) {
            continue;
        }

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let rel = rel_path(root, path);
        let manifest = is_manifest(path);

        if let Some(reason) = classify_by_extension(path) {
            skipped.push(SkippedFile::new(rel, reason, size));
            continue;
        }

        if size > opts.max_file_size && !manifest {
            skipped.push(SkippedFile::new(rel, SkipReason::TooLarge, size));
            continue;
        }

        match read_head(path) {
            Ok(head) => {
                if looks_binary(&head) {
                    skipped.push(SkippedFile::new(rel, SkipReason::BinaryContent, size));
                    continue;
                }
                // Long-line check on the sniffed head catches bundles that dodged
                // the filename patterns above.
                if !manifest
                    && head
                        .split(|&b| b == b'\n')
                        .any(|line| line.len() > opts.minified_line_len)
                {
                    skipped.push(SkippedFile::new(rel, SkipReason::Minified, size));
                    continue;
                }
            }
            Err(_) => {
                skipped.push(SkippedFile::new(rel, SkipReason::ReadError, size));
                continue;
            }
        }

        candidates.push(Candidate {
            abs_path: path.to_path_buf(),
            rel_path: rel,
            language: Language::from_path(path),
            is_manifest: manifest,
        });
    }

    candidates.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    skipped.sort_by(|a, b| a.path.cmp(&b.path));

    Discovery { candidates, skipped }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_nul_bytes_as_binary() {
        assert!(looks_binary(b"MZ\x90\x00\x03\x00\x00\x00"));
    }

    #[test]
    fn plain_source_is_not_binary() {
        assert!(!looks_binary(b"fn main() {\n    println!(\"hi\");\n}\n"));
    }

    #[test]
    fn empty_file_is_not_binary() {
        assert!(!looks_binary(b""));
    }

    #[test]
    fn skips_compiled_and_media_extensions() {
        assert_eq!(
            classify_by_extension(Path::new("a/b/app.exe")),
            Some(SkipReason::BinaryExtension)
        );
        assert_eq!(
            classify_by_extension(Path::new("logo.png")),
            Some(SkipReason::Media)
        );
        assert_eq!(
            classify_by_extension(Path::new("bundle.min.js")),
            Some(SkipReason::Minified)
        );
        assert_eq!(classify_by_extension(Path::new("src/main.rs")), None);
    }

    #[test]
    fn recognises_manifests_case_insensitively() {
        assert!(is_manifest(Path::new("x/Cargo.toml")));
        assert!(is_manifest(Path::new("package.json")));
        assert!(!is_manifest(Path::new("src/lib.rs")));
    }
}
