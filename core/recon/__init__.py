"""Information-gathering modules (passive archives + active crawling).

Submodules are imported explicitly by callers to avoid a circular import
between :mod:`core.config_loader` and the recon modules.
"""

__all__ = ["active", "passive", "urls"]
