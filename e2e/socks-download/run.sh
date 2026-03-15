#!/usr/bin/env bash
# Test: SOCKS5 heavy download — 10MB file through DNS tunnel via SOCKS5
set -euo pipefail
cd "$(dirname "$0")"

cleanup() { docker compose down -v 2>/dev/null; }
trap cleanup EXIT

echo "--- Building and starting services ---"
docker compose up -d --build

echo "--- Waiting for SOCKS tunnel (up to 30s) ---"
for i in $(seq 1 30); do
    if docker compose exec -T client curl -s \
        --socks5-hostname localhost:7000 --proxy-user user:pass \
        --connect-timeout 5 http://heavy/ 2>/dev/null | grep -q "Welcome to nginx"; then
        echo ""
        echo "--- SOCKS tunnel is up, starting download ---"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo ""
        docker compose logs client server socks heavy
        echo "=== FAIL (tunnel not ready) ==="
        exit 1
    fi
    printf "."
    sleep 1
done

echo "--- Downloading 10MB file through DNS tunnel via SOCKS5 ---"
download_output=$(docker compose exec -T client \
    curl -s --socks5-hostname localhost:7000 --proxy-user user:pass \
    --max-time 300 \
    -w '\nspeed_download=%{speed_download}\ntime_total=%{time_total}\nsize_download=%{size_download}\n' \
    -o /tmp/bigfile \
    http://heavy/bigfile 2>&1) || true

speed=$(echo "$download_output" | grep '^speed_download=' | cut -d= -f2)
elapsed=$(echo "$download_output" | grep '^time_total=' | cut -d= -f2)
size=$(echo "$download_output" | grep '^size_download=' | cut -d= -f2)

echo "  Downloaded: ${size:-0} bytes"
echo "  Elapsed:    ${elapsed:-?} seconds"
if [ -n "$speed" ]; then
    speed_kb=$(echo "$speed" | awk '{printf "%.1f", $1/1024}')
    echo "  Speed:      ${speed_kb} KB/s"
fi

expected_size=10485760
if [ "${size:-0}" = "$expected_size" ]; then
    echo "=== PASS ==="
else
    echo "--- Expected $expected_size bytes, got ${size:-0} ---"
    docker compose logs client server
    echo "=== FAIL ==="
    exit 1
fi
