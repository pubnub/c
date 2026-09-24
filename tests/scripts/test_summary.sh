#!/bin/bash
# Run all test binaries and report pass/fail at both binary and test-case level.
# Usage: ./tests/scripts/test_summary.sh <build-dir>
# Example: ./tests/scripts/test_summary.sh build/full

set -uo pipefail

BUILD_DIR="${1:?Usage: $0 <build-dir>}"
TESTS_DIR="${BUILD_DIR}/tests"

if [ ! -d "$TESTS_DIR" ]; then
    echo "Error: ${TESTS_DIR} not found" >&2
    exit 1
fi

total_cases=0
passed_cases=0
failed_cases=0
total_binaries=0
passed_binaries=0
failed_binaries=0
skipped_binaries=0
failed_binary_names=""

while IFS= read -r bin; do
    name=$(basename "$bin")
    output=$("$bin" 2>&1) || true
    rc=$?

    run=$(echo "$output" | grep -o '[0-9]* test(s) run' | head -1 | grep -o '^[0-9]*' || true)
    pass=$(echo "$output" | grep '\[ *PASSED *\]' | grep -o '[0-9]*' | tail -1 || true)
    fail=$(echo "$output" | grep '\[ *FAILED *\]' | grep -o '[0-9]*' | tail -1 || true)

    if [ -z "$run" ]; then
        skipped_binaries=$((skipped_binaries + 1))
        echo "  warning: ${name} did not report test count" >&2
        continue
    fi

    total_binaries=$((total_binaries + 1))
    total_cases=$((total_cases + run))

    if [ -n "$pass" ]; then
        passed_cases=$((passed_cases + pass))
    fi
    if [ -n "$fail" ] && [ "$fail" -gt 0 ]; then
        failed_cases=$((failed_cases + fail))
    fi

    if [ "$rc" -eq 0 ]; then
        passed_binaries=$((passed_binaries + 1))
    else
        failed_binaries=$((failed_binaries + 1))
        failed_binary_names="${failed_binary_names}\n    ${name}"
    fi
done < <(find "$TESTS_DIR" -type f -perm +111 -name "test_*" | sort)

echo ""
echo "=== Test Summary ==="
echo "  Binaries:       ${passed_binaries} passed, ${failed_binaries} failed / ${total_binaries} total"
echo "  Test cases:     ${passed_cases} passed, ${failed_cases} failed / ${total_cases} total"
if [ "$skipped_binaries" -gt 0 ]; then
    echo "  Skipped:        ${skipped_binaries} binaries (no output)"
fi
if [ "$failed_binaries" -gt 0 ]; then
    echo ""
    echo "  Failed binaries:"
    echo -e "$failed_binary_names"
fi
echo "===================="

if [ "$failed_binaries" -gt 0 ] || [ "$failed_cases" -gt 0 ]; then
    exit 1
fi
