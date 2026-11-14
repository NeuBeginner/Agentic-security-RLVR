"""
integrations
============

The integrations of the repository with the outside world.

The packages of this directory are standalone: they do not import ``core`` and
they do not import ``sandbox``, so that they can neither change the R1
dispatch registry nor weaken the fail-closed approval of the benchmark.
"""

from __future__ import annotations

__all__: list[str] = []
