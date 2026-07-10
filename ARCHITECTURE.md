# judge — architecture

`judge` is a shared library for judgment-edge adapter mechanics.

It is intentionally domain-neutral. Concrete adapters, such as `mind-judge`,
bring domain contracts and prompt/config data. This crate provides reusable mechanics for provider/proxy calls, secret-source
references, diagnostic records, bounded child-process execution, and
format-failure handling. Provider calls are single-attempt: adapters decide
whether a domain-specific retry is safe.

## Boundary

Owned here:

- provider and model identifiers;
- references to externally-owned secret sources or explicitly ambient sessions,
  never secret values;
- prompt text and provider call records;
- bounded, typed provider-command failures and format-failure records.

Not owned here:

- Mind request or reply semantics;
- prompt prose;
- provider credentials;
- daemon lifecycle or socket serving.
