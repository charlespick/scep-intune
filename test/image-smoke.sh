#!/usr/bin/env bash
# Starts the container image as the Deployment in docs/kubernetes.md runs it (read-only root,
# no capabilities, config mounted read-only at the default path) and checks that it serves.
# The config goes in through a volume rather than a bind mount, so this also runs against a
# Docker VM that shares no host folders.
# Usage: test/image-smoke.sh <image>
set -euo pipefail

image=${1:?usage: $0 <image>}
name=scep-intune-smoke-$$
work=$(mktemp -d)
cleanup() {
  docker logs "$name" 2>&1 || true
  docker rm -f "$name" "$name-seed" >/dev/null 2>&1 || true
  docker volume rm "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

cat >"$work/config.yaml" <<'EOF'
server:
  listen: ":8080"
intune:
  auth: client_secret
EOF
chmod 0644 "$work/config.yaml"

docker volume create "$name" >/dev/null
docker create --name "$name-seed" -v "$name:/etc/scep-intune" "$image" >/dev/null
docker cp "$work/config.yaml" "$name-seed:/etc/scep-intune/config.yaml"
docker rm "$name-seed" >/dev/null

docker run -d --name "$name" -p 127.0.0.1::8080 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$name:/etc/scep-intune:ro" \
  -e SCEP_VALIDATE_SECRET="$(openssl rand -base64 64 | tr -d '\n')" \
  -e SCEP_NOTIFY_SECRET="$(openssl rand -base64 64 | tr -d '\n')" \
  -e INTUNE_TENANT_ID=00000000-0000-0000-0000-000000000000 \
  -e INTUNE_CLIENT_ID=00000000-0000-0000-0000-000000000000 \
  -e INTUNE_CLIENT_SECRET=smoke-test \
  "$image" >/dev/null

sleep 1
url="http://$(docker port "$name" 8080/tcp | head -1)"
for _ in $(seq 30); do
  curl -fsS -o /dev/null "$url/healthz" && break
  sleep 1
done

test "$(docker inspect -f '{{.State.Running}}' "$name")" = true
test "$(curl -s -o /dev/null -w '%{http_code}' "$url/healthz")" = 200
test "$(curl -s -o /dev/null -w '%{http_code}' -X POST -d '{}' "$url/validate")" = 401
test "$(docker inspect -f '{{.Config.User}}' "$image")" = 65532:65532
echo "image smoke test passed: $image"
