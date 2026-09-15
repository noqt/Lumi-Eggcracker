"""Small, opt-in v2 native containment experiment.

The v2 experiment is deliberately separate from the consumed v1 replay. Its
modules are not imported at package import time so ``python -m`` execution
does not preload a module or mutate anything before the selected entry point.
"""

__all__ = ()
