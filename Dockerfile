# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM python:3.11-slim

ARG TRIVY_VERSION=0.65.0
# BuildKit が自動で埋める（例: TARGETOS=linux, TARGETARCH=amd64/arm64）
ARG TARGETOS
ARG TARGETARCH

# 基本ツール
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gnupg unzip \
 && rm -rf /var/lib/apt/lists/*

# Trivy バイナリ導入（アーキに応じて取得）
# amd64 → Linux-64bit, arm64 → Linux-ARM64
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

# （本当に必要な場合のみ）nodejs/npm を入れる
# RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*

# Pipenv（必要なら）
RUN pip install --no-cache-dir pipenv

WORKDIR /app
COPY app.py /app/app.py

ENV TZ=Asia/Tokyo \
    PYTHONUNBUFFERED=1 \
    TRIVY_PATH=/usr/local/bin/trivy

RUN mkdir -p /app/output

CMD ["python", "app.py"]
