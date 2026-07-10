# skills — judge

- Keep this crate domain-neutral; Mind-specific types belong in
  `signal-mind-judge` or `mind-judge`.
- Store secret handles as references only. Never commit secret values.
- Internal records are typed Rust values with NOTA projection added only at
  edge helper surfaces.
- Codex calls must consume an approved external-session reference, run in an
  isolated process group, and terminate/reap every group member on deadline
  without rendering stderr or credentials. Timeout tests require a descendant
  that explicitly ignores `SIGTERM`, proving escalation leaves neither a live
  descendant nor its sentinel.
- Run `cargo fmt`, `cargo test --all-features`, and `nix flake check` after Rust changes.
