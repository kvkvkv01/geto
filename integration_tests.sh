#!/bin/sh
set -euo pipefail

IMAGE_TAG="file-cgi:test"
CONTAINER_NAME="file-cgi-test"
PORT=18080
BASE_URL="http://localhost:${PORT}/cgi-bin/file_cgi.cgi"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[build] docker image"
docker build -t "${IMAGE_TAG}" .

start_container() {
  cleanup
  docker run -d --rm --name "${CONTAINER_NAME}" -p "${PORT}:8080" "$@" "${IMAGE_TAG}" >/dev/null
}

wait_healthy() {
  for i in $(seq 1 30); do
    if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "server did not become healthy" >&2
  exit 1
}

tmpdir=$(mktemp -d)

echo "[test] payload too large returns 413"
start_container -e MAX_UPLOAD_BYTES=1024
wait_healthy
dd if=/dev/zero bs=1 count=2048 2>/dev/null | curl -s -o /tmp/resp -w "%{http_code}" --data-binary @- "${BASE_URL}/upload" | grep -q "413"

echo "[test] upload/download flow and dedupe"
start_container
wait_healthy

echo "hello world" > "${tmpdir}/f1.txt"

upload_json=$(curl -fsS -F "file=@${tmpdir}/f1.txt" "${BASE_URL}/upload")
token1=$(printf "%s" "${upload_json}" | python - <<'PY'
import json,sys
print(json.load(sys.stdin)["token"])
PY
)
curl -fsS -o "${tmpdir}/dl1" "${BASE_URL}/download/${token1}"
diff -u "${tmpdir}/f1.txt" "${tmpdir}/dl1"

upload_json2=$(curl -fsS -F "file=@${tmpdir}/f1.txt" "${BASE_URL}/upload")
token2=$(printf "%s" "${upload_json2}" | python - <<'PY'
import json,sys
print(json.load(sys.stdin)["token"])
PY
)
test "${token1}" != "${token2}"

echo "[pass] all integration checks"
