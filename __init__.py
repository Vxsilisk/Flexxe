"""
Flexxe — website technology fingerprinter for Python.

Point it at a URL and get back the stack: WAFs / security, e-commerce
platforms, payment processors, CMS, frameworks, analytics, CDN, languages,
the origin server and its IP — plus an optional Playwright deep scan for
runtime-only signals.

    >>> import Flexxe
    >>> Flexxe.analyze("https://www.shopify.com")

:see: :func:`Flexxe.analyze`, :class:`Flexxe.Flexxe`, :class:`WebPage`.
"""

from .Flexxe import Flexxe, analyze
from .web import WebPage
from .deepscan import HAS_PLAYWRIGHT, deep_scan, deep_scan_async

__version__ = "2.0.0"

__all__ = [
    "Flexxe",
    "WebPage",
    "analyze",
    "deep_scan",
    "deep_scan_async",
    "HAS_PLAYWRIGHT",
    "__version__",
]
