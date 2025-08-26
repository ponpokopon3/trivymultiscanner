# syntax=docker/dockerfile:1
FROM python:3.11-slim

# バージョンは必要に応じて変更可
ARG TRIVY_VERSION=0.65.0

# 基本ツールと（必要なら）nodejs/npm を導入
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gnupg unzip \
    nodejs npm \
 && rm -rf /var/lib/apt/lists/*

# Trivy バイナリ導入（公式リリースのLinux 64bit）
RUN curl -fsSL -o /tmp/trivy.tgz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
 && tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy \
 && rm /tmp/trivy.tgz

# Pipenv
RUN pip install --no-cache-dir pipenv

# 実行環境
WORKDIR /app
# スクリプトをコンテナにコピー（ファイル名はあなたの実ファイル名に合わせて）
COPY app.py /app/app.py

# タイムゾーンとTrivyパス（念のため環境変数でも指定）
ENV TZ=Asia/Tokyo \
    PYTHONUNBUFFERED=1 \
    TRIVY_PATH=/usr/local/bin/trivy

# 出力ディレクトリ（ボリュームで上書きされてもOK）
RUN mkdir -p /app/sbom_outputs

# デフォルト実行（引数を渡せば上書き可能）
CMD ["python", "app.py"]
