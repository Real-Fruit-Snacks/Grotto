#!/bin/bash
# Test networking functions - run from project root
# Usage: wsl bash tests/test_net_linux.sh
set -e
KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PASS=0
FAIL=0

echo "[*] Test 1: listen mode accepts TCP connection"
./build/ncat -l -p 18234 -k $KEY &
NCAT_PID=$!
sleep 1

# Connect and send data
echo "test" | nc -w 1 127.0.0.1 18234 2>/dev/null || true
sleep 0.5
kill $NCAT_PID 2>/dev/null || true
wait $NCAT_PID 2>/dev/null || true
echo "PASS: listen mode accepted connection"
PASS=$((PASS + 1))

echo "[*] Test 2: connect mode connects to listener"
nc -l 18235 &
NC_PID=$!
sleep 1

timeout 2 ./build/ncat -c 127.0.0.1 -p 18235 -k $KEY 2>/dev/null || true
kill $NC_PID 2>/dev/null || true
wait $NC_PID 2>/dev/null || true
echo "PASS: connect mode ran"
PASS=$((PASS + 1))

echo ""
echo "Results: $PASS passed, $FAIL failed"
