docker build -t myapp .
docker run --rm -it myapp bash -lc '
  set -euxo pipefail
  id
  ls -ld /app/sbom_outputs
  touch /app/sbom_outputs/_probe1.txt
  echo ok1 > /app/sbom_outputs/_probe2.txt
  ls -l /app/sbom_outputs
  cat /app/sbom_outputs/_probe2.txt
'
