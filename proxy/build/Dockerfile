# LiteLLM + the libraries the media gate needs (proxy/media_gate.py). Versions are the ones the offline tests ran with;
# Pillow >= 12.3.0 and pypdf >= 6.14.1 carry the 2026 decompression-bomb / infinite-loop fixes.
# Pin LITELLM_IMAGE to a digest in production (audit M8).
ARG LITELLM_IMAGE=ghcr.io/berriai/litellm:main-stable
FROM ${LITELLM_IMAGE}
RUN pip install --no-cache-dir "pillow==12.3.0" "pypdf==6.19.0" "python-docx==1.2.0"
