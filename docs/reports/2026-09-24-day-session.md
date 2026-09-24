# Day session report — 2026-09-24

Follows the overnight run (`2026-09-25-overnight-run.md`). Executor: Claude Code; adversarial reviewer: Agy (Gemini) in permission-gated print mode; operator directing throughout.

## Delivered
| Area | State |
|---|---|
| Hub v2 | Admin control centre at `/hub`: Overview · Safety · Models · Access · Gateway. Fixed collapsible left nav, independent scrolling, pagination on every table, dark theme. |
| Safety | VetoGuard policy editable in the hub (S4 locked; classifier and fail-closed not configurable); audit log viewer; alert webhook; **diagnostics snippet toggle (default off)**. |
| VetoGuard | 2.2 → **2.7** through five completed Agy rounds (round 6 was blocked by Gemini's content filter — not a clean verdict) (records in `docs/tests/agy-vetoguard-review-*.md`). Whole-history tripwires, multi-turn window classification, every request field and output field covered, fail-closed on every unscannable path, bounded executors/queues. |
| Models | `modeld` pull-only sidecar; pull/remove/expose from the hub; apps never fetch models. `gemma3:27b` pulled as the ≤ 20 GB main-model candidate for pairing with the 8B guard. |
| Access | API keys minted/revoked in the hub; **admin password rotation** in the hub (file-based Caddy credential, complexity policy, bcrypt 14). |
| Gateway | Local Caddy build with Cloudflare DNS-01; **Let's Encrypt certificate live for `aegis.denofsyn.com`** with no inbound ports; certificate monitor; isolation layer view-only. |
| Frameworks | Monitoring profile (Prometheus, node-exporter, DCGM, Grafana at `/grafana`) — up and scraping. Apps profile (Fish Speech, ComfyUI hard-503). |
| Tests | 76 assertions; 64/64 on the final run with 12 hub-page tests skipped (password rotated from the UI). |

## Incidents today
1. **8B guard + Mixtral → CPU fallback (15:02–15:12).** Operator selected `llama-guard3:8b`; the two models evicted each other, Ollama's runner lost the GPUs (`NVML: Unknown Error`) and both models loaded on CPU. Fixed with `docker compose restart ollama`, policy reverted to 1B. Dashboard now warns on zero-VRAM residency; suite asserts GPU residency. Durable fix is host-level (NVIDIA runtime CDI mode) — supervised.
2. **Home Assistant false positive (15:16).** "Good morning." reply withheld: classifier S1 on the *output*. 1B measured 0/20 false positives on generic exchanges, so the flag was content-specific; the no-content audit design blocked diagnosis. Added the snippet toggle so the next one is diagnosable.

## Decisions for the operator
- **Guard strength:** to run 8B, expose `gemma3:27b` (Models → Installed → Expose), make it the default in Open WebUI / Home Assistant, then select 8B in Safety → VetoGuard policy. Do **not** select 8B while Mixtral is the main model.
- **Snippet diagnostics:** turn on only while chasing a false positive; turn off after. Never captures S4/CSAM vetoes.
- **Hub tests:** run `scripts/sentinel_test.py --label <x> --hub-password '<current>'` after a rotation (or update `HUB_ADMIN_PASSWORD` in `.env`).
- **Push:** four commits on `main`, nothing pushed. Review, then push.

## Agy loop — how to run it
`agy -p "<prompt>" --add-dir <dir-with-file> --output-format json` (JSON mode is reliable; text mode is intermittently empty). Extract `response` from the JSON. Round 6 on 2.7 was refused by Gemini's safety filter (the likely cause of the earlier intermittent empty outputs); rerun with rephrasing or let the next code change trigger it. Findings that were false positives across rounds: hook argument order (×3, verified against LiteLLM source); multi-event-loop races (single worker).
