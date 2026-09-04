# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities in VulnScope **privately**, through GitHub's
private vulnerability reporting:

**[Report a vulnerability →](https://github.com/mintyextremum/vulnscope/security/advisories/new)**

That opens a private advisory visible only to you and the maintainer. Please do
not open a public issue for a security problem — the issue tracker is world
readable the moment you press submit.

Include what you have: the version, the platform, what an attacker gains, and the
steps to reproduce it. A proof of concept is welcome but not required to file.

**What to expect.** This is a single-maintainer project, so response times are
best-effort rather than contractual. You should get an acknowledgement within a
few days and an assessment once the report has been reproduced. Fixes ship in a
patch release, and the advisory is published with credit to you unless you would
rather stay anonymous.

## What is in scope

VulnScope is a desktop application that reads untrusted input — source code,
repository URLs, and the output of external scanners — so the interesting attack
surface is anything that turns *reading* into *executing*. In particular:

- Code execution from scanning a crafted repository or file
- Path traversal escaping the selected scan target, especially through archives,
  symlinks, or `..` in a repository path
- Command injection through a repository URL, a file path, or a configured editor
  command
- Injection into an export (`SARIF`, `HTML`, `CSV`, `Markdown`, `XML`) that
  executes in whatever opens it — including CSV formula injection
- **Any path by which a detected secret escapes masking** and reaches the UI, an
  export, a log, or a network request
- Any outbound network request beyond the documented OSV.dev query
- Tampering with the update or release artifacts

## What is out of scope

- **A missed vulnerability, or a false positive, in scanned code.** VulnScope is a
  heuristic scanner and does not claim completeness — that is a detection bug, not
  a security vulnerability. Please open a normal issue; those are genuinely
  welcome and usually become a new rule or a regression test.
- Vulnerabilities in the external scanners (Semgrep, Bandit, Gitleaks, Trivy and
  the rest). VulnScope never bundles, downloads, or installs them; report those
  upstream. If VulnScope *mishandles* their output, that is in scope.
- Advisories against dependencies with no demonstrated path to exploiting
  VulnScope. CI already runs `npm audit` and `cargo audit`; a report that only
  restates their output does not need a private advisory.
- Findings that require an attacker to already have code execution as the user
  running VulnScope.

## Design commitments

These are properties the project intends to hold. A demonstrated break of any of
them is a valid report:

1. **Analysis is local.** Your source code never leaves your machine. The only
   outbound request is to OSV.dev, carrying package names and versions — never
   code — and only when the CVE check is enabled. Offline mode removes even that.
2. **Secrets are masked everywhere.** A detected secret's raw value never reaches
   the interface, an export, or a log. This is enforced by a test that walks the
   real pipeline (`secret_values_never_reach_the_finding`).
3. **Nothing is downloaded or executed on your behalf.** VulnScope shows you the
   command to install an external scanner and lets you copy it; it does not fetch
   or run binaries. A security scanner that installs software is the supply-chain
   threat it exists to find.
4. **Telemetry is off and cannot be switched on.** Scanner telemetry and
   provider-side verification of discovered secrets are forced off.

## Supported versions

The latest release receives security fixes. Given the release cadence of a
single-maintainer project, please upgrade before reporting.

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |
