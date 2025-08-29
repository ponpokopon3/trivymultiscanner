# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM python:3.11-slim

# 基本ツール
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gnupg unzip \
 && rm -rf /var/lib/apt/lists/*

# Trivy
ARG TRIVY_VERSION=0.65.0
ARG TARGETOS
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64)  TRIVY_ARCH="64bit" ;; \
      arm64)  TRIVY_ARCH="ARM64" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trivy.tgz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tgz; \
    /usr/local/bin/trivy --version

# Nodejs/npm
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*

# Pipenv
RUN pip install --no-cache-dir pipenv

WORKDIR /app
COPY ./app/app.py .
COPY ./app/input.csv .

ENV TZ=Asia/Tokyo \
    PYTHONUNBUFFERED=1 \
    TRIVY_PATH=/usr/local/bin/trivy
