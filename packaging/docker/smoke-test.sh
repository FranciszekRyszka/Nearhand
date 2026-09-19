#!/bin/sh
# Build the server's image and check it works: it starts, prints what agents
# pin and how to make the first administrator, serves the console and the web
# viewer over HTTPS, keeps its data in the volume, and stops cleanly when
# asked. CI runs this.
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${IMAGE:-nearhand-server:smoke}"
name="nearhand-smoke-$$"
port="${PORT:-18443}"

docker build -f "$root/packaging/docker/Dockerfile" -t "$image" "$root"

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "$name" -v "$name:/data" \
    -p "127.0.0.1:$port:443/tcp" -p "127.0.0.1:$port:443/udp" \
    -e "NEARHAND_HTTP_PUBLIC_URL=https://127.0.0.1:$port" "$image" >/dev/null

# Up when the console answers.
tries=0
until curl -skf -o /dev/null "https://127.0.0.1:$port/"; do
    tries=$((tries + 1))
    if [ "$tries" -ge 30 ]; then
        docker logs "$name"
        echo "FAIL: the console did not answer" >&2
        exit 1
    fi
    sleep 1
done

# The web viewer was built into it, not left out.
curl -skf -o /dev/null "https://127.0.0.1:$port/pkg/nearhand_web_bg.wasm" \
    || { echo "FAIL: the image has no web viewer" >&2; exit 1; }

logs="$(docker logs "$name" 2>&1)"
echo "$logs"
echo "$logs" | grep -q '^fingerprint: ' || { echo "FAIL: no fingerprint printed" >&2; exit 1; }
echo "$logs" | grep -q "#setup=" || { echo "FAIL: no setup link printed" >&2; exit 1; }

# SIGTERM stops it within the grace period; a kill would exit 137.
docker stop -t 20 "$name" >/dev/null
code="$(docker inspect -f '{{.State.ExitCode}}' "$name")"
[ "$code" = 0 ] || { echo "FAIL: exited with $code on docker stop" >&2; exit 1; }

# The volume holds what must survive: a restart keeps the fingerprint.
docker start "$name" >/dev/null
sleep 3
again="$(docker logs "$name" 2>&1 | grep '^fingerprint: ' | sort -u | wc -l)"
[ "$again" = 1 ] || { echo "FAIL: the fingerprint changed across a restart" >&2; exit 1; }
# The other commands run through the same entry point.
docker run --rm -v "$name:/data" "$image" migrate

echo "OK: $image"
