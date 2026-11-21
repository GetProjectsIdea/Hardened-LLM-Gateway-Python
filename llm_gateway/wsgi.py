"""WSGI entry point for gunicorn/uwsgi: ``gunicorn -w 2 -b 127.0.0.1:8088 llm_gateway.wsgi:app``.

Runs the same preflight as ``serve`` and refuses to start on errors.
Note: rate limits and token budgets are per process; use one worker or a shared store for strict limits.
"""
import sys

from .settings import Settings, has_errors, preflight

settings = Settings.from_env()
_checks = preflight(settings)
if has_errors(_checks):
    for c in _checks:
        if c.level == "ERROR":
            print(f"ERROR {c.name}: {c.message}", file=sys.stderr)
    raise SystemExit("REFUSING TO START: weak or default secrets / unsafe settings")

from .gateway import create_app  # noqa: E402

app = create_app(settings)
