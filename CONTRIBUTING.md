Contributing to Joro
====================

Thanks for your interest in contributing. This document describes the expectations for pull requests against this repository.

## General

* Contributions to core code must be GPLv3 (but not libraries).
* Open a GitHub issue to discuss non-trivial changes before opening a PR.
* **Each PR should cover a single change.** Don't bundle multiple features, refactors, or dependency bumps into one pull request - split unrelated work into separate PRs.
* Keep pull requests small and focused. Large or sprawling PRs will be asked to split before review.
* Prefer building domain-specific features as plugins - see `sdk/sdk.go` and `examples/plugins/` - rather than adding them to core.
* Changes should be made in a new branch.
* Commits [must be signed](https://docs.github.com/en/github/authenticating-to-github/signing-commits) for any PR to `main`.
* Provide meaningful commit messages, and reference the related issue.
* `gofmt` your Go code.
* Avoid `import "C"` and CGO-wrapped C library dependencies in source code - they hurt cross-compilation and portability. Prefer pure-Go libraries (e.g. `modernc.org/sqlite` over the cgo sqlite driver). This is about source dependencies, not the `CGO_ENABLED` build flag - release binaries are built with `CGO_ENABLED=1` (via `zig cc`) so Go's `plugin` package works on Linux and macOS.
* Avoid global variables in internal packages; pass dependencies as parameters.
* Do not call `os.Exit` outside `main.go`; errors should always be handled cleanly.
* Frontend changes must use semantic Tailwind classes from the theme system (see `CLAUDE.md`).
* New dependencies need a short justification in the PR description.
* Any changes under `third_party/` should be in a distinct commit.
* There is no automated test suite yet; include a short manual verification note in the PR description, and a screenshot for UI changes.

## Security

* _Never_ trust the user, applied in a common-sense way.
* __Secure by default__ - prefer failing closed over operating in an insecure state.
* _Never_ use homegrown or non-peer-reviewed cryptography or random number generation.
* Report vulnerabilities privately via the GitHub advisory link in [`SECURITY.md`](SECURITY.md) - not public issues.
