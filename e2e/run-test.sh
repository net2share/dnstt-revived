#!/usr/bin/env bash
# Runs all e2e tests sequentially. Each test can also be run individually.
set -euo pipefail
cd "$(dirname "$0")"

failed=0
total=0

for test_dir in tunnel socks-download recovery; do
    total=$((total + 1))
    echo ""
    echo "========================================"
    echo "  e2e/$test_dir"
    echo "========================================"
    if bash "$test_dir/run.sh"; then
        echo ""
    else
        echo ""
        failed=$((failed + 1))
    fi
done

echo "========================================"
echo "  $((total - failed))/$total tests passed"
echo "========================================"

if [ "$failed" -gt 0 ]; then
    exit 1
fi
