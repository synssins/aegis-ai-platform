# Aegis hub runtime: python:3.12-alpine + argon2id password hashing + Fernet (TOTP secret at rest).
FROM python:3.12-alpine
RUN apk add --no-cache libffi && pip install --no-cache-dir argon2-cffi==23.1.0 cryptography==43.0.3
