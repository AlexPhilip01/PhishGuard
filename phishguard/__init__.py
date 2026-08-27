"""
PhishGuard — a Python tool to analyze phishing email headers.

Restructured from the original Colab notebook into an installable package
with a CLI, persistent local history, and an optional live threat-feed
check. All original detection logic (header checks, IP checks, keyword
scoring) is unchanged from the notebook version.
"""
from .core import analyze_single
from .scorer import calculate_score, get_verdict

__version__ = "2.0.0"

__all__ = ["analyze_single", "calculate_score", "get_verdict"]
