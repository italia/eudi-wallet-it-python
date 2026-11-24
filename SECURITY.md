# Security Policy

Report vulnerabilities privately so maintainers can fix them before public disclosure.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

Security fixes are not backported to older releases than the latest. The team does not have the capacity to guarantee that these backports will exist. You are advised to be prepared to upgrade to the latest version once the fix is out.

## Reporting a Vulnerability

Report security vulnerabilities **privately**. Do not open a public issue or pull request for a suspected vulnerability.

Preferred channels, in order:

1. **GitHub Private Vulnerability Reporting** on [italia/eudi-wallet-it-python](https://github.com/italia/eudi-wallet-it-python/security/advisories/new), when the repository offers the *Report a vulnerability* button.
2. **Email** to `demarcog83@gmail.com` if private reporting is unavailable or you cannot use GitHub.

Include as much of the following as you can:

- Affected component and version (PyPI `pyeudiw` version, git tag, or commit).
- Steps to reproduce, or a proof of concept.
- Impact (confidentiality, integrity, or availability) and who is affected.
- Optional suggested fix.

The maintainer will verify the issue and contact you on how it will be handled.

## Scope

This policy covers the `pyeudiw` library published from this repository, including:

- Cryptographic helpers (`jwk`, `jwt`, `sd_jwt`, `oauth2.dpop`).
- Trust evaluation (`federation`, `x509`, `trust`).
- OpenID4VP / OpenID4VCI schemas and flows.
- SATOSA OpenID4VP backend and OpenID4VCI frontend.
- Status List revocation checks.

Out of scope: vulnerabilities that exist only in third-party dependencies with no exploit path through `pyeudiw`, and issues in deployments that misuse the library (for example weak key material or disabled trust checks in integrator configuration). Dependency CVEs that affect users of this project may still be reported so the pin can be tightened.

## Public Discussions

When a new vulnerability is reported and verified, a security advisory is created on GitHub and the issue may be assigned a CVE identifier. Progress on the mitigation is tracked privately until a fix is ready.

When the fix is ready, a release plan is prepared and communication channels are used to notify the community of the issue and the expected upgrade path.

When the advisory is published, GitHub notifies dependent projects. Projects that depend on `pyeudiw` should receive Dependabot pull requests where enabled.

## Supply-chain controls

This repository uses:

- **pip-audit** in CI (`.github/workflows/security-audit.yml`) to fail on known vulnerable dependencies, with documented exceptions when an upstream fix does not exist.
- **GitGuardian** (`.gitguardian.yaml`) to reduce the risk of committing secrets.
