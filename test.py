docker run --rm \
  -e PYTHONUNBUFFERED=1 \
  -e LOG_FILE=/app/sbom_outputs/app.log \
  -v "$PWD/sbom_outputs:/app/sbom_outputs" \
  myapp python -X dev -u /app/app.py
