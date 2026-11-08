# Changelog

All notable changes to nbprefix are documented here. The version number is in `VERSION` (x.y.z)
and is read by the script at startup.

## [0.2.1] - 2026-11-08

### Added
- `SECURITY.md`: how to report a vulnerability privately, what a report must contain, and what
  is in scope. The README points to it.

### Fixed
- The local web server now only answers requests whose `Host` is `127.0.0.1:<port>` or
  `localhost:<port>`. Before, a web page could reach it through a hostname of its own that resolves
  to 127.0.0.1 (DNS rebinding) and read the prefix tree.
- A POST must carry an `Origin` that matches the local page exactly, and one without `Origin` is
  refused. Before, any origin starting with `http://localhost` or `http://127.0.0.1` was accepted,
  so a page on e.g. `localhost.example.com` could change the NetBox URL in the config and have
  the stored token sent there.

## [0.2.0] - 2026-11-07

### Added
- License: MIT or Apache-2.0 at the recipient's choice (`LICENSE-MIT` and `LICENSE-APACHE`), SPDX line
  at the top of `nbprefix.py` and a license section in the README.

### Changed
- All text is now in English: user interface, code comments, README, changelog, example config and `.gitignore`.
- Number and time formatting use the en-GB locale: comma as thousands separator, 24-hour times, no space
  before %.
- README rewritten for the public repository on GitHub (github.com/rjorgensen123/prefixbrowser).
- README now states the official repository, https://github.com/rjorgensen123/prefixbrowser, and no longer
  describes it as a mirror.

## [0.1.0] - 2026-11-03

### Added
- README.md describing the tool: it runs locally on each PC and only reads from NetBox.
- Support for NetBox v2 tokens (NetBox 4.5+): `nbt_<key>.<token>` is sent as `Authorization: Bearer`.
  v1 tokens (40 characters) are still sent as `Authorization: Token`.
- The token can be given as a complete `nbt_<key>.<token>`, as `<key>.<token>` without the prefix,
  or as key and token separately (new field "Key" in the settings dialog).
- Explanatory help text when NetBox rejects the token (e.g. only the token part of a v2 token pasted in).
- The status line shows which token version is in use.
- `VERSION` file and this changelog. The version is shown at startup, in the User-Agent and with `--version`.
- `.gitignore` keeping `nbprefix.json` (local config with token) and `__pycache__` out of git.

### Changed
- Example config and docstring document both token formats.

## [0.0.1] - 2026-11-03

### Added
- First release: read-only prefix browser for NetBox IPAM with a local web server, tree view per VRF,
  free blocks, coverage and search by text, IP or prefix. Standard library only.
