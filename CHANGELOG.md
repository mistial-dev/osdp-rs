# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- *(driver)* Add PD-side secure-channel handshake handling for SCS_11 through
  SCS_14, including secure command unsealing, secure reply sealing, and
  install-mode `KEYSET` support.
- *(driver)* Add ACU-side secure-channel handshake helpers for SCS_11 through
  SCS_14 and automatic secure command/reply exchange once a `PdState` is
  secure.
- *(driver)* Add ACU-side `AcuSecureKeyProvider` and `AcuSecureKeyMaterial`
  for secure-channel key selection.
- *(driver)* Add PD-side `PdSecureKeyProvider` for secure-channel key
  selection.
- *(driver)* Add `PdState::is_secure` and `PdState::secure_session` accessors
  for ACU-side secure-channel state.
- *(secure)* Add PD-side secure-session primitives and secure frame
  seal/unseal helpers for MAC-only and encrypted secure traffic.
- *(secure)* Add `SecureRandom` injection points for ACU and PD secure-channel
  handshakes.
- *(errors)* Add secure-session errors for missing key material, invalid secure
  transitions, plaintext DATA in secure frames, and not-yet-secure operations.
- *(examples)* Add secure loopback and secure `KEYSET` install-mode flows.

### Changed

- *(driver)* Require ACU secure-channel handshake APIs to obtain SCBK material
  through an `AcuSecureKeyProvider` instead of taking raw key bytes directly.
- *(driver)* Move PD secure-channel key lookup out of `PdHandler`.
- *(driver)* Route ACU command exchange through secure frame protection after
  SCS-CS completes.

### Fixed

- *(secure)* Reject plaintext DATA in production secure frames.
- *(secure)* Verify secure frame MACs before decrypting encrypted DATA.
- *(secure)* Reset secure sessions to disconnected state after invalid MACs or
  cryptograms.
- *(driver)* Reject inbound plaintext secure DATA and wrong-direction secure
  replies instead of dispatching them.

## [0.3.1](https://github.com/Quantumlyy/osdp-rs/compare/v0.3.0...v0.3.1) - 2026-05-09

### Changed

- No user-visible changes; patch release for internal maintenance.

## [0.3.0](https://github.com/Quantumlyy/osdp-rs/compare/v0.2.1...v0.3.0) - 2026-05-05

### Added

- *(secure)* Zeroize Session and SessionKeys on drop
- *(driver)* Enforce SQN echo per spec table 2

### Changed

- Replace stringly-typed length errors with typed variants
- *(tests)* Share helpers via tests/common, add VecTransport::shuffle_to
- *(driver)* Dedupe ACU receive loop, name magic numbers
- *(secure)* Dedupe Session<S> state-transition boilerplate

### Documentation

- Drop Session:: qualifier from handshake state diagram
- Add runnable doctests for the high-traffic public APIs
- *(readme)* Add architecture + handshake diagrams; refresh stale stats
- Add mermaid diagrams for the four core state machines
- Wire up aquamarine + docs.rs metadata

### Testing

- *(reply)* Add unit tests for every reply body
- *(command)* Add unit tests for every command body

## [0.2.1](https://github.com/Quantumlyy/osdp-rs/compare/v0.2.0...v0.2.1) - 2026-05-04

### Changed

- *(cipher)* Construct complement ICV functionally

### Testing

- *(cipher)* Derive test keys/IVs via computed fixture

## [0.2.0](https://github.com/Quantumlyy/osdp-rs/compare/v0.1.22...v0.2.0) - 2026-05-04

### Added

- Add ascii utils

### Documentation

- Docs gen

### Testing

- Property + integration coverage; rewrite README

### V0.2.0

- Rewrite for OSDP v2.2 compliance
