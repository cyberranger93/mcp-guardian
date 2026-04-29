# Changelog

All notable changes to MCP Guardian will be documented in this file.

This project follows semantic versioning before 1.0 with the usual pre-1.0 caveat: minor versions may include breaking changes as the CLI and policy format stabilize.

## [0.1.3] - 2026-04-29

### Changed

- Switched npm publication target to the authenticated npm user scope `@cyberranger/mcp-guardian`.
- Kept GitHub repository and GitHub Action usage under `cyberranger93/mcp-guardian`.

## [0.1.2] - 2026-04-29

### Changed

- Prepared npm publication under the available scoped package name `@cyberranger93/mcp-guardian`.
- Kept the executable binary name as `mcp-guardian`.
- Added npm publishing documentation while keeping GitHub install as the live public install path.

## [0.1.1] - 2026-04-29

### Changed

- Added launch playbook, social copy, and channel-specific outreach guidance.
- Added README badges and a short block-decision demo above the fold.
- Added GitHub issue templates and pull request template for contributor flow.
- Included docs, changelog, and security policy in packaged release contents.
- Updated public install docs to use the GitHub install path before npm publication.

## [0.1.0] - 2026-04-28

### Added

- Initial TypeScript package metadata for the `mcp-guardian` CLI.
- Config model for proxy mode, audit logging, redaction, tool policy, runtime rules, and scanner settings.
- Launch documentation covering install, quickstart, architecture, policy, scanner, demos, GitHub Action usage, and threat model.
- Example policies for strict local development, monitor-mode rollout, and CI scanning.
