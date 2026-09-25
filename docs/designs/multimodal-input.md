# Design: images and documents in chat (multimodal input)

Status: **phase 1 implemented on branch `feature/multimodal-input` for testing, switched OFF by default.** Not for
production until the decision in section 5 is made and a Gemini (`agy`) review round ends clean.
Roadmap #13. Research date: 2026-09-24.

## 1. Goal and non-negotiables
Let users paste images and attach documents in chat, the way hosted assistants allow, without weakening the
platform's rules:
- **No model sees anything that was not checked first.** Every image and every document is checked before
  inference, and the model receives exactly the checked copy (re-encoded pixels, extracted text), never the raw upload.
- **S4 stays locked** and applies to images as strictly as to text.
- **Fail closed**: undecodable, oversized, unclassifiable, or unknown → refused.
- **Zero retention** of refused content (see section 5 for the legal tension this creates for images).

## 2. How others do it (sources in section 8)
| Practice | Who does it publicly | Use here |
|---|---|---|
| Perceptual-hash every uploaded image against known-CSAM lists, before anything else | Anthropic (NCMEC hash DB), OpenAI (internal + Thorn) | Phase 3 — needs vetted access to a hash list (section 5) |
| Classifier for new abusive imagery alongside hash matching | OpenAI (Thorn classifier), Google Content Safety API (ranks for human review) | Self-hosted image classifier ensemble (phases 1–2) |
| OCR the image, then run the text moderation on the extracted text (typographic jailbreaks) | GPT-4V system card; AWS Bedrock evaluates the first 100 words; Azure multimodal ~1K chars | Phase 1: the vision classifier transcribes visible text, which goes through Llama Guard with the user's words |
| PDFs become extracted text (+ page images), other formats text only | OpenAI, Anthropic | Phase 1: text extraction; phase 2: page rendering + OCR comparison |
| Uploaded/retrieved documents are untrusted; scan for injected instructions separately | Azure Prompt Shields (document attacks), Anthropic injection classifiers, OWASP LLM01 | Phase 1: documents delimited as untrusted data (spotlighting); phase 2: Prompt Guard 2 |
| Hard limits on format, bytes, pixels, images per request | Azure (4 MB, 50–7200 px), Bedrock (4 MB, 8000 px, 20 images) | Phase 1: 8 MB, 24 MP, 4 images, 10 MB / 200 pages / 150k chars per document |
| Classify input **and** output | Meta (Llama Guard 4 card), AWS | Already true: every reply is classified before release |
| Image classifiers cover fewer categories than text; a moderation model is not a CSAM detector | OpenAI (sexual/minors is text-only in omni-moderation; "not a substitute" for hash matching) | Never rely on one image classifier for S4; hard rule "any possible minor + any sexual signal = refuse" |
| Flagged content retained for review/reporting | OpenAI (even under ZDR), Anthropic (2 years) | **Conflicts with zero retention** — decision required (section 5) |

## 3. Pipeline (phase 1, as built)
All in the LiteLLM pre-call hook (`proxy/media_gate.py`, called from `proxy/veto_filter.py`), in memory only:

1. **Admission.** Only `data:` URLs (no fetching of remote URLs — avoids SSRF and check/use races). Images only in
   user turns. Audio, video, SVG, HEIC, GIF/animated, `file_id` references → refused.
2. **Images.** Magic-byte check (PNG/JPEG/WebP) → Pillow with a format allow-list and `MAX_IMAGE_PIXELS` → first
   frame only → converted to RGB and **re-encoded as a fresh PNG** (drops metadata, trailing bytes, polyglots),
   long side capped at 1568 px. The request is rewritten to carry the re-encoded copy.
3. **Image verdict.** The re-encoded image goes to the image classifier on the safety pool (Ollama, JSON verdict:
   nsfw, sexual_content, minor_present, sexual_minor, illegal, violence_gore, description, text_in_image). Hard
   rules: sexual_minor, or minor_present with any sexual/nudity signal → **S4 refuse**; illegal → refuse; nudity,
   sexual or gore → refuse unless the policy explicitly allows adult images. Unreadable verdict → refuse.
4. **Image content into the text gate.** The verdict's description and the transcribed visible text are added to
   what Llama Guard classifies, together with the user's words — so a harmful request written *inside* an image, or
   an innocent-looking image paired with harmful text, is judged as a whole.
5. **Documents.** PDF (pypdf, page cap, encrypted refused), DOCX (zip entry/size caps before parsing, macros and
   embedded objects refused, python-docx which parses with `resolve_entities=False`), UTF-8 text. Embedded images
   are checked exactly like pasted images. The file part is **replaced** with the extracted text, wrapped as
   untrusted data (spotlighting): the model never parses the file.
6. **Then the normal gate**: tripwires (child-safety list locked on) → Llama Guard over the new turn including the
   extracted text and image descriptions → model → output classified before release.
7. **Retention**: nothing written; audit entries carry only reason codes (e.g. `media_image_type`, `image_classifier`
   + category).

Where users can attach: the **hub portal chat** (stores nothing server-side; the browser keeps a placeholder, never
the file). **Open WebUI stays off**: it stores uploads on disk before any filter can see them (Open WebUI discussion
#24239), which breaks zero retention.

## 4. Classifier choice (research summary)
- The official Ollama library has **no purpose-built image safety classifier**; `llama-guard3` there is text-only.
- A general VLM used as a prompted judge (today's `gemma3:27b`) trails dedicated guards by 2–10 F1 points
  (ShieldGemma 2 paper) and far more in other studies (LlavaGuard: base VLM 61% vs guard 91% balanced accuracy).
  Acceptable for testing; **not** acceptable as the only classifier in production.
- Candidates:
  - **NVIDIA Nemotron 3.5 Content Safety (4B, Gemma-3-4B base)**: image + text, has a "Sexual (minor)" category,
    low false positives, community GGUF with mmproj (llama.cpp / Ollama import). Primary candidate.
  - **Llama Guard 4 (12B)**: image + text, S1–S14 incl. S4, different vendor → best second opinion; transformers /
    vLLM only; tight on this hardware.
  - **ShieldGemma 2 (4B)**: best published F1 on sexual / dangerous / violent images, **no child-safety category**.
  - Fast NSFW pre-filters (Marqo ViT-tiny, Falconsai, NudeNet): cheap first pass; none detect minors.
- Age estimation is unreliable (NIST FATE: MAE ≈ 3 years; teenagers tend to be over-estimated) → the hard rule
  treats *any* possible-minor signal plus *any* sexual signal as S4.
- Known attacks: typographic jailbreaks (FigStep ~82% ASR on open VLMs), image-amplified jailbreaks (HADES),
  universal adversarial images. No single defence works universally (MMJ-Bench) → layered: re-encode + OCR→text guard
  + image guard ensemble ("any unsafe = block") + output classification.

## 5. Decision required before production: known-CSAM detection and the law
Research summary (not legal advice — **a lawyer must answer these before images are enabled for real users**):
- Hash-matching lists for known CSAM (NCMEC hash sharing, IWF, PhotoDNA Cloud, Thorn Safer, Google tools) all require
  **vetting/membership**; PDQ hashing code is open source, the lists are not. Hosted options send images (PhotoDNA,
  Google) or hashes/content (Safer hosted) off the platform; self-hosted Safer or downloaded lists keep it local.
- 18 U.S.C. §2258A: a provider with **actual knowledge** must report to NCMEC's CyberTipline; filing a report is
  treated as a request to **preserve** the reported content for **1 year** (REPORT Act 2024). §2258A(f): no duty to
  scan proactively.
- Therefore **"zero retention" and "detect + report" cannot both hold once a report is made.** Whether an automated
  block without human review creates "actual knowledge" is unresolved in the sources found.
- AI-generated or modified material can be illegal (18 U.S.C. §2256(8)(B)/(C), §1466A; Minn. Stat. §617.246).

Options for the operator: (a) keep images **off** in production (documents only), (b) enable images with the
classifier layers only and zero retention, after legal advice, (c) enable with hash matching + a sealed,
access-controlled quarantine path used only when legally required. The branch implements the switch; it ships OFF.

## 6. Phases
| Phase | Content | State |
|---|---|---|
| 1 | Media gate (admission, re-encode, document extraction, zip/page limits, spotlighting), vision-verdict classifier on the safety pool, verdict text into Llama Guard, hard S4 rule, portal paste/attach, policy switches (off), tests | **Built on branch, for testing** |
| 2 | Dedicated image guard ensemble (Nemotron 3.5 CS primary + Llama Guard 4 or ShieldGemma 2), fast NSFW pre-filter; parsers in an isolated no-network gVisor worker with timeouts; PDF page render + OCR vs extracted text (hidden-text detection); Prompt Guard 2 over document text | Planned |
| 3 | Known-CSAM hash matching (PDQ locally against a vetted list, or PhotoDNA/Safer) — only after the section 5 decision | Blocked on decision |
| 4 | Open WebUI attachments (only if its storage can be kept out of the path), audio input | Not planned |

## 7. Testing
- Offline: `tests/test_media_gate.py` — admission rules, re-encoding strips trailing payloads and metadata, pixel and
  size limits, animated refused, documents (PDF/DOCX/text) extracted and replaced, macros/zip bombs/encrypted refused,
  embedded images classified, hard S4 rule, fail-closed on classifier errors, switch off → refused, nothing written.
- Live (after deploy with the switch on in a test instance): benign photo → answered; image with visible sentinel
  text → refused by the text gate; document containing the sentinel → refused; oversize → refused; classifier
  unloaded → refused.
- Classifier quality: measure false positives on a benign set before choosing a production classifier; never build
  S4 test material — rely on vendor evaluations for S4 and on the hard rule.

## 8. Sources
OpenAI moderation guide (developers.openai.com/api/docs/guides/moderation), CSAM guidance
(developers.openai.com/api/docs/guides/csam-guidance), data controls (developers.openai.com/api/docs/guides/your-data),
PDF inputs (developers.openai.com/api/docs/guides/pdf-files), GPT-4V system card (cdn.openai.com/papers/GPTV_System_Card.pdf);
Anthropic PDF support (platform.claude.com/docs/en/build-with-claude/pdf-support), CSAM detection
(support.claude.com/en/articles/9020328), prompt-injection defenses (anthropic.com/research/prompt-injection-defenses);
Gemini safety settings (ai.google.dev/gemini-api/docs/safety-settings); Google tools for partners
(protectingchildren.google/tools-for-partners); Azure Content Safety harm categories, Prompt Shields
(learn.microsoft.com/azure/ai-services/content-safety/…); AWS Bedrock multimodal guardrails
(docs.aws.amazon.com/bedrock/latest/userguide/guardrails-mmfilter.html); Llama Guard 4 and 3-Vision model cards,
ShieldGemma 2 (arxiv.org/html/2504.01081), Nemotron 3.5 Content Safety (huggingface.co/nvidia/Nemotron-3.5-Content-Safety),
LlavaGuard (arxiv.org/html/2406.05113), GuardReasoner-Omni (arxiv.org/html/2602.03328v2), UnsafeBench
(arxiv.org/abs/2405.03486), FigStep (arxiv.org/abs/2311.05608), HADES (arxiv.org/abs/2403.09792), MMJ-Bench
(AAAI 2025), NIST FATE age estimation (nist.gov, 2024); 18 U.S.C. §§2258A, 2258B, 2252A, 2256, 1466A
(law.cornell.edu); REPORT Act explainer (thorn.org); Minn. Stat. §617.246 (revisor.mn.gov); PhotoDNA FAQ
(microsoft.com/photodna/faq), NCMEC hash sharing (lesp.ncmec.org), Thorn Safer (safer.io), IWF hash list (iwf.org.uk),
ThreatExchange/PDQ (github.com/facebook/ThreatExchange); pypdf security advisories, Pillow 12.2/12.3 release notes,
python-docx parser settings, defusedxml, Dangerzone (dangerzone.rocks), gVisor, Prompt Guard 2
(huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M), Spotlighting (arxiv.org/abs/2403.14720), hidden text in PDFs
(arxiv.org/pdf/2509.10248), Open WebUI upload order (github.com/open-webui/open-webui/discussions/24239), LiteLLM custom
guardrails and issue #31071.
