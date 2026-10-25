# Security policy

oneq is an **educational project without an independent cryptographic audit**. Do not rely on it for anything you could not afford to lose.
`specifications.html` states the protocol, the threat model and, explicitly, what oneq does not guarantee.

## Reporting a vulnerability

Please report privately, not in a public issue:

* GitHub: Security tab of the repository, "Report a vulnerability" (private vulnerability reporting), or
* e-mail: `<SECURITY-CONTACT>` (to be filled in before the repository is published).

Include what you found, the version (the package version, `oneqrelay` / `oneqclient` build) and a way to reproduce it.
There is no bug bounty and no guaranteed response time.

## Scope

In scope: the wire protocol `tunmesh-pq/v2` (`meshproto.py`, `oneqtunel.py`, `client/core/src/wire.rs`), the registry and relay (`oneqrelay`, `meshdb`,
`oneqadmin`, `oneqtotp`), the nodes (`oneqnode`, the Rust client), the packaging scripts and the browser extension.

Limits that are documented are not vulnerabilities by themselves: see `specifications.html`, section 12, and "Limite cunoscute" in `ARCHITECTURE.md`.

## Supported versions

Only the latest release receives fixes. A protocol change gets a new `LABEL` and is not backwards compatible; compatibility rules between
components are in `CHANGELOG.md`.

## For contributors

* Never commit credentials, CA or signing keys, TOTP secrets, passwords or tokens. `.gitignore` blocks the usual names; check `git status` before every push.
* A key that reached the git history must be treated as compromised and replaced, even if the commit is later removed.
* Release signing keys belong in the CI secret store and are used only by the release workflow.
