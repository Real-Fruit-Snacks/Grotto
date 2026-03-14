#!/bin/bash
set -e
PASS=0
FAIL=0
GROTTO="wsl ./build/grotto"

run_test() {
    local desc="$1"
    local expected_pattern="$2"
    shift 2
    output=$($@ 2>&1 || true)
    if echo "$output" | grep -qi "$expected_pattern"; then
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (output: $output)"
        FAIL=$((FAIL + 1))
    fi
}

# Test: no arguments prints usage
run_test "no args prints usage" "usage" $GROTTO

# Test: missing -k
run_test "missing -k prints error" "key" $GROTTO -l -p 4444

# Test: missing -p
run_test "missing -p prints error" "port" $GROTTO -l -k aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Test: -l and -c conflict
run_test "conflict detected" "both\|conflict" $GROTTO -l -c 127.0.0.1 -p 4444 -k aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Test: valid args exit cleanly (will exit 0 since no networking yet)
$GROTTO -l -p 4444 -k aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
if [ $? -eq 0 ]; then
    echo "PASS: valid listen mode exits cleanly"
    PASS=$((PASS + 1))
else
    echo "FAIL: valid listen mode should exit 0"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] || exit 1
