# Adversarial review round 6 — 01: `caddy/hub/scheduler.py` (smoke run, 2026-09-24 late)

Status: **open — not yet fixed, not yet re-reviewed.** Produced while verifying that Claude can call Gemini (`agy`) directly;
the server was shut down for the night right after. Resume here: fix → acceptance-suite assertions (new phase 10) → re-review.

Reviewer: Gemini via `agy -p … --add-dir caddy/hub --output-format json`, read-only command allow-list, 107 s, `read_ok: true`.

| # | Line | Finding | Proposed fix |
|---|---|---|---|
| 1 | 51 | protected() queries USE using the unnormalized model name instead of _base(model), unlike the pinned check on line 49. When resident() reports models with tags from Ollama (e.g. 'llama3:latest') while callers record usage under stripped base names ('llama3'), USE.get(model) misses. Consequently, active in-flight requests and administrator hold times are ignored, allowing unauthorized users to evict models currently in use or held by administrators. | Normalize model names using _base(model) in both note_use() when setting entries in USE and in protected() when retrieving them. |
| 2 | 63 | resident() fails open when http('GET', url + '/api/ps') times out or returns a non-200 status code. It silently catches non-dict responses and returns an empty list []. In ensure_resident(), an empty resident list causes others and blocked to be empty, completely bypassing access-control eviction checks and permitting non-admin requests to initiate model loads that evict resident admin-held or pinned models. | Verify that st == 200 and that ps contains a valid 'models' list in resident(); if the call fails, propagate an error or fail closed so ensure_resident() refuses eviction and loading. |
| 3 | 88 | ensure_resident() checks any(why == 'answering another request' for _, why in blocked) when deciding to wait. If one resident model is blocked for a non-transient reason ('pinned by an administrator' or held under admin_hold_min) while another is answering a request, the function still enters a 45-second sleep loop, unnecessarily blocking worker threads before ultimately rejecting the request. | Only enter the wait loop if all blocked models are waitable (e.g. all(why == 'answering another request' for _, why in blocked)); reject immediately if any model is blocked by a non-transient restriction like pinning or admin hold. |

Claude's reading of the findings (to confirm on resume): 1 — real: `USE` is keyed by the raw name while pins use `_base()`, so `model:latest` vs `model` can slip past the admin hold; normalise keys. 2 — real: an unreachable pool must fail **closed** (refuse the request), not look empty. 3 — real: the wait loop should only wait when every blocker is merely in flight; a pinned/held blocker means refuse at once.
