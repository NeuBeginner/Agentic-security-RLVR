"""
integrations.modal_mcp
======================

A small, protected HTTP/MCP interface in front of the Modal workspace of this
repository.

The server is deliberately *small*: it exposes a fixed set of named Modal
operations (no arbitrary shell execution, no arbitrary file access) and refuses
everything that is not on the allowlist. It is the executor that a ChatGPT
plugin - or the maintainer - talks to.

The design rules that the whole package follows:

* **fail closed** - a missing credential, an unknown application, an
  unexpected environment or a disabled write operation ends in a refusal, never
  in a guess;
* **no secrets in the output** - a tool result never carries a token, a
  credential or the value of a secret; only names, digests, states and
  measurements;
* **read first** - every diagnostic tool is read-only and is marked as such in
  the MCP annotations, so that a chat client can call it without asking for a
  confirmation;
* **explicit writes** - the management tools (deploy, stop) exist but stay
  disabled until they are switched on explicitly *and* the caller passes the
  one-time confirmation value.

The package has no dependency on the rest of the repository: it imports nothing
from ``core`` and nothing from ``sandbox``, so it can neither change the R1
dispatch registry nor weaken the fail-closed approval of the benchmark.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "aegis-modal-mcp/1.0.0"
