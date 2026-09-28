"""
SentinelForge – Professional Security Assessment Framework
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Professional, modular penetration testing and security auditing framework
for authorized security assessments.

Usage::

    from sentinelforge import SentinelForge
    sf = SentinelForge()
    sf.scan("example.com")

:license: MIT
"""

__version__ = "1.0.0"
__author__ = "SentinelForge Team"
__description__ = "Professional Security Assessment Framework"

from sentinelforge.core.engine import SentinelEngine

# Public API surface
SentinelForge = SentinelEngine

__all__ = ["SentinelForge", "SentinelEngine", "__version__"]
