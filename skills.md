# skills — judge

- Keep this crate domain-neutral; Mind-specific types belong in
  `signal-mind-judge` or `mind-judge`.
- Store secret handles as references only. Never commit secret values.
- Internal records are typed Rust values with NOTA projection added only at
  edge helper surfaces.
- Run `cargo fmt`, `cargo test`, and `nix flake check` after Rust changes.
