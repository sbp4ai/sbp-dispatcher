"""sbp-dispatcher: the SBP relay (untrusted middle box)."""
from .app import make_app, main

__all__ = ["make_app", "main"]
__version__ = "0.5.8"
