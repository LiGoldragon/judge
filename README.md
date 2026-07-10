# judge

Shared adapter mechanics for model-backed judge edges.

This repo owns provider/proxy calling support, secret-source and external-session
references, bounded/redacted child-process failure mechanics, and provider reply
records. Calls are single-attempt; adapters own any domain-specific retry. NOTA
rendering/parsing, diagnostics policy, prompt text, and domain semantics remain
at the adapter boundary.
