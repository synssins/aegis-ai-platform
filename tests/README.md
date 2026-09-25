# Offline regression tests

Unit tests for the security fixes that run WITHOUT the live stack (no Docker, no GPUs, no Ollama). They exercise the
real code in `proxy/veto_filter.py`, `caddy/hub/hub.py` and `caddy/hub/imagegate.py` with the classifier replaced
by a recording stand-in and harmless marker strings. No harmful content is used or needed.

    python3.12 -m pip install argon2-cffi cryptography httpx fastapi
    python3.12 -m unittest discover -s tests -v

`scripts/sentinel_test.py` (phase 10) covers the same fixes end-to-end against a running deployment.
