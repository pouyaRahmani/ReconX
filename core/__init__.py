"""ReconX — modular web vulnerability reconnaissance framework.

The package is organised in four layers:

* ``core.recon``    – passive / active information gathering
* ``core.params``   – parameter extraction and merging
* ``core.templates``– fuzz job generation
* ``core.fuzz``     – HTTP engine, detectors and finding storage
* ``core.redact``   – credential / secret scrubbing
* ``core.notify``   – Telegram and webhook notifications
* ``core.report``   – aggregation and reporting

The public entry point is :func:`core.cli.main`.
"""

__version__ = "2.0.0"
__author__ = "Pouya Rahmani, Samaneh Mirhosseini"
__all__ = ["__version__"]
