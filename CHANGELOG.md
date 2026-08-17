# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `parseDotenv`: quoted values followed by inline comments (`KEY="a b" # note`)
  no longer leak the literal quotes into the parsed value.
- `Journal.readAll`: a single damaged line in the audit journal no longer hides
  the rest of the journal — unparseable lines are skipped.

## [0.1.0] - 2026-08-17

### Added

- Initial release: gates sensitive file access (`tools/pre-execute`),
  masks secret-shaped tool results (`tools/post-execute`), provides safe
  `sg_*` inspection tools, keeps a JSONL audit journal with rotation, and
  hot-reloads rules from an external JSON file.
