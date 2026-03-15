#!/usr/bin/env bash
# Test: Simple tunnel — client fetches nginx page through DNS tunnel
set -euo pipefail
cd "$(dirname "$0")"

cleanup() { docker compose down -v 2>/dev/null; }
trap cleanup EXIT

echo "--- Building and starting services ---"
docker compose up -d --build

echo "--- Waiting for tunnel (up to 30s) ---"
for i in $(seq 1 30); do
    if docker compose exec -T client wget -q -O- http://localhost:7000 2>/dev/null | grep -q "Welcome to nginx"; then
        echo ""
        echo "=== PASS ==="
        exit 0
    fi
    printf "."
    sleep 1
done

echo ""
echo "--- Tunnel did not come up. Dumping logs ---"
docker compose logs client server
echo "=== FAIL ==="
exit 1
