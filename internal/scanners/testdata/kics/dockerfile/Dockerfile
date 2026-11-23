# iac: intentionally misconfigured Dockerfile for Draugr's `iac` control (Trivy config)
# and an old base image for the `images` control (Trivy).
FROM python:3.8-slim

# iac: runs as root (no USER directive), copies everything, no healthcheck.
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

EXPOSE 5000
CMD ["python", "app.py"]
