#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

cleanup() {
    echo "--- Cleaning up ---"
    docker compose down -v 2>/dev/null
}
trap cleanup EXIT

echo "--- Building and starting services ---"
docker compose up -d --build

# =============================================================================
# Test 1: Simple tunnel — wget nginx default page
# =============================================================================
echo ""
echo "=== Test 1: Simple tunnel ==="
echo "--- Waiting for tunnel (up to 30s) ---"
test1_pass=false
for i in $(seq 1 30); do
    if docker compose exec -T client wget -q -O- http://localhost:7000 2>/dev/null | grep -q "Welcome to nginx"; then
        echo ""
        echo "=== Test 1: PASS ==="
        test1_pass=true
        break
    fi
    printf "."
    sleep 1
done

if [ "$test1_pass" = false ]; then
    echo ""
    echo "--- Test 1: Tunnel did not come up. Dumping logs ---"
    docker compose logs client server
    echo "=== Test 1: FAIL ==="
    exit 1
fi

# =============================================================================
# Test 2: SOCKS5 heavy download (10MB through DNS tunnel)
# =============================================================================
echo ""
echo "=== Test 2: SOCKS5 speed test (10MB download) ==="
echo "--- Waiting for SOCKS tunnel (up to 30s) ---"
test2_ready=false
for i in $(seq 1 30); do
    # Quick check: can we reach the heavy server through the SOCKS tunnel?
    if docker compose exec -T client-socks curl -s --socks5-hostname localhost:7000 --proxy-user user:pass --connect-timeout 5 http://heavy/ 2>/dev/null | grep -q "Welcome to nginx"; then
        echo ""
        echo "--- SOCKS tunnel is up, starting download ---"
        test2_ready=true
        break
    fi
    printf "."
    sleep 1
done

if [ "$test2_ready" = false ]; then
    echo ""
    echo "--- Test 2: SOCKS tunnel did not come up. Dumping logs ---"
    docker compose logs client-socks server-socks socks heavy
    echo "=== Test 2: FAIL (tunnel not ready) ==="
    exit 1
fi

# Download the 10MB file through the SOCKS5 tunnel
echo "--- Downloading 10MB file through DNS tunnel via SOCKS5 ---"
download_output=$(docker compose exec -T client-socks \
    curl -s --socks5-hostname localhost:7000 --proxy-user user:pass \
    --max-time 300 \
    -w '\nspeed_download=%{speed_download}\ntime_total=%{time_total}\nsize_download=%{size_download}\n' \
    -o /tmp/bigfile \
    http://heavy/bigfile 2>&1) || true

# Parse stats from curl output
speed=$(echo "$download_output" | grep '^speed_download=' | cut -d= -f2)
elapsed=$(echo "$download_output" | grep '^time_total=' | cut -d= -f2)
size=$(echo "$download_output" | grep '^size_download=' | cut -d= -f2)

echo "  Downloaded: ${size:-0} bytes"
echo "  Elapsed:    ${elapsed:-?} seconds"
if [ -n "$speed" ]; then
    speed_kb=$(echo "$speed" | awk '{printf "%.1f", $1/1024}')
    echo "  Speed:      ${speed_kb} KB/s"
fi

# Verify file size is 10MB (10485760 bytes)
expected_size=10485760
if [ "${size:-0}" = "$expected_size" ]; then
    echo ""
    echo "=== Test 2: PASS ==="
else
    echo ""
    echo "--- Test 2: Expected $expected_size bytes, got ${size:-0} ---"
    docker compose logs client-socks server-socks
    echo "=== Test 2: FAIL ==="
    exit 1
fi

# =============================================================================
# Test 3: Two concurrent heavy downloads + post-recovery check
# =============================================================================
echo ""
echo "=== Test 3: Concurrent streams + recovery ==="
echo "--- Launching two 10MB downloads simultaneously ---"

# Launch two concurrent downloads in background
docker compose exec -T client-socks \
    curl -s --socks5-hostname localhost:7000 --proxy-user user:pass \
    --max-time 300 \
    -w '\nsize_download=%{size_download}\ntime_total=%{time_total}\nspeed_download=%{speed_download}\n' \
    -o /tmp/bigfile_a \
    http://heavy/bigfile 2>&1 > /tmp/dl_a.out &
pid_a=$!

docker compose exec -T client-socks \
    curl -s --socks5-hostname localhost:7000 --proxy-user user:pass \
    --max-time 300 \
    -w '\nsize_download=%{size_download}\ntime_total=%{time_total}\nspeed_download=%{speed_download}\n' \
    -o /tmp/bigfile_b \
    http://heavy/bigfile2 2>&1 > /tmp/dl_b.out &
pid_b=$!

echo "  PIDs: $pid_a, $pid_b — waiting for both..."
wait_failed=false
wait "$pid_a" || wait_failed=true
wait "$pid_b" || wait_failed=true

# Parse results
size_a=$(grep '^size_download=' /tmp/dl_a.out 2>/dev/null | cut -d= -f2)
time_a=$(grep '^time_total=' /tmp/dl_a.out 2>/dev/null | cut -d= -f2)
speed_a=$(grep '^speed_download=' /tmp/dl_a.out 2>/dev/null | cut -d= -f2)

size_b=$(grep '^size_download=' /tmp/dl_b.out 2>/dev/null | cut -d= -f2)
time_b=$(grep '^time_total=' /tmp/dl_b.out 2>/dev/null | cut -d= -f2)
speed_b=$(grep '^speed_download=' /tmp/dl_b.out 2>/dev/null | cut -d= -f2)

echo "  Stream A: ${size_a:-0} bytes in ${time_a:-?}s ($(echo "${speed_a:-0}" | awk '{printf "%.1f", $1/1024}') KB/s)"
echo "  Stream B: ${size_b:-0} bytes in ${time_b:-?}s ($(echo "${speed_b:-0}" | awk '{printf "%.1f", $1/1024}') KB/s)"

expected_size=10485760
if [ "${size_a:-0}" != "$expected_size" ] || [ "${size_b:-0}" != "$expected_size" ]; then
    echo ""
    echo "--- Test 3: Concurrent downloads failed ---"
    echo "  Expected both $expected_size bytes, got A=${size_a:-0} B=${size_b:-0}"
    docker compose logs client-socks server-socks
    echo "=== Test 3: FAIL ==="
    exit 1
fi

echo "--- Both downloads complete. Checking tunnel recovery ---"

# Post-recovery: verify the tunnel still works for new connections
recovery_ok=false
for i in $(seq 1 15); do
    if docker compose exec -T client-socks curl -s --socks5-hostname localhost:7000 --proxy-user user:pass --connect-timeout 5 http://heavy/ 2>/dev/null | grep -q "Welcome to nginx"; then
        recovery_ok=true
        break
    fi
    printf "."
    sleep 1
done

if [ "$recovery_ok" = true ]; then
    echo ""
    echo "=== Test 3: PASS ==="
else
    echo ""
    echo "--- Test 3: Tunnel did not recover after concurrent downloads ---"
    docker compose logs client-socks server-socks
    echo "=== Test 3: FAIL ==="
    exit 1
fi

echo ""
echo "=== ALL TESTS PASSED ==="
