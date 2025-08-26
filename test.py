docker run --rm -it \
  -v "$PWD/sbom_outputs:/app/sbom_outputs" \
  myapp bash -lc '
    set -euxo pipefail
    echo "== whoami =="; id
    echo "== target dir inside =="
    ls -ld /app/sbom_outputs || true
    test -d /app/sbom_outputs
    echo ok2 > /app/sbom_outputs/_probe2.txt
    ls -l /app/sbom_outputs
    cat /app/sbom_outputs/_probe2.txt
  '
