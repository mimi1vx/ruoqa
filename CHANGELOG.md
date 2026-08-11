# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/mimi1vx/ruoqa/compare/v0.1.4...v0.2.0) - 2026-08-11

### Added

- *(consts)* mirror the current OpenQA::Jobs::Constants
- *(client)* support sub-path openQA deployments
- *(client)* classify response bodies instead of assuming JSON
- *(client)* [**breaking**] resolve API credentials from the environment as one pair

### Fixed

- *(config)* [**breaking**] stop merging /etc and user client.conf across tiers
- *(consts)* order STATES by job lifecycle like openQA does
- *(tls)* warn wherever certificate verification is disabled
- *(policy)* harden retry backoff and response-cap arithmetic against panics
- *(client)* [**breaking**] stop replaying non-idempotent writes after retryable statuses
- *(client)* make the retry deadline bound the whole operation
- *(client)* reject cross-origin and non-relative request paths
- *(client)* follow redirects the way openQA's client does
- *(auth)* sign the URL the server receives

### Other

- scope out the openQA worker protocol
- *(deps)* bump serde-saphyr in the cargo-minor-patch group
- *(policy)* say which upstream client upstream_compat mirrors

## [0.1.4](https://github.com/mimi1vx/ruoqa/compare/v0.1.3...v0.1.4) - 2026-08-05

### Fixed

- *(security)* redact URL userinfo from errors, logs, and Debug output

### Other

- add project logo and GitHub social preview header
- *(release)* let release-plz publish so the tag order fixes itself

## [0.1.3](https://github.com/mimi1vx/ruoqa/compare/v0.1.2...v0.1.3) - 2026-08-04

### Added

- *(client)* support injecting a pre-built reqwest::Client

### Other

- *(release)* invoke crates.io publish from release-plz directly

## [0.1.2](https://github.com/mimi1vx/ruoqa/compare/v0.1.1...v0.1.2) - 2026-08-03

### Added

- *(client)* add form-encoded request bodies
- *(client)* allow injecting client.conf search paths via ClientBuilder

### Other

- *(release)* make crates.io publish idempotent against duplicate tag pushes

## [0.1.1](https://github.com/mimi1vx/ruoqa/compare/v0.1.0...v0.1.1) - 2026-08-03

### Added

- *(config)* honor $OPENQA_CONFIG and $XDG_CONFIG_HOME in client.conf discovery

### Other

- add cargo-semver-checks now that a crates.io baseline exists
