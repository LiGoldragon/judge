# Agent guidance — judge

Read `ARCHITECTURE.md` before editing.

This repo is a shared Rust library for judge adapter mechanics only. Do not add
Mind semantics, concrete prompt text, provider credentials, daemon runtime, or
socket activation here. Keep behavior on data-bearing Rust types and expose
checks through `flake.nix`.
