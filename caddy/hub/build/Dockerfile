# Aegis hub runtime: python:3.12-alpine + argon2id password hashing + Fernet (TOTP secret at rest) + QR (SVG) for MFA enrollment.
# (pillow removed 2026-09-24: it only served the perceptual hash for image evidence, which zero retention removed.)
FROM python:3.12-alpine
RUN apk add --no-cache libffi && pip install --no-cache-dir argon2-cffi==23.1.0 cryptography==43.0.3 qrcode==8.0
