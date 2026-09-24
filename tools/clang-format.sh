#!/bin/bash
# Project-pinned clang-format wrapper.
# CI and local developers must use the SAME major version to avoid drift.
#
# Version contract: clang-format 19.x
# - CI installs clang-format-19 from apt.llvm.org (see .github/workflows/format.yml)
# - Local (macOS): brew install llvm@19
# - Local (Linux): sudo apt install clang-format-19

set -euo pipefail

REQUIRED_MAJOR=19

# Resolution order: explicit versioned binary, then generic clang-format
if command -v clang-format-${REQUIRED_MAJOR} &>/dev/null; then
    CF="clang-format-${REQUIRED_MAJOR}"
elif [ -x "/opt/homebrew/opt/llvm@${REQUIRED_MAJOR}/bin/clang-format" ]; then
    CF="/opt/homebrew/opt/llvm@${REQUIRED_MAJOR}/bin/clang-format"
elif [ -x "/usr/local/opt/llvm@${REQUIRED_MAJOR}/bin/clang-format" ]; then
    CF="/usr/local/opt/llvm@${REQUIRED_MAJOR}/bin/clang-format"
elif command -v clang-format &>/dev/null; then
    CF="clang-format"
else
    echo "ERROR: clang-format not found. Install llvm@${REQUIRED_MAJOR}." >&2
    exit 1
fi

ACTUAL_VERSION=$($CF --version | grep -oE '[0-9]+' | head -1)
if [ "$ACTUAL_VERSION" != "$REQUIRED_MAJOR" ]; then
    echo "ERROR: need clang-format ${REQUIRED_MAJOR}.x, found version ${ACTUAL_VERSION} ($CF)" >&2
    echo "  macOS: brew install llvm@${REQUIRED_MAJOR}" >&2
    echo "  Linux: sudo apt install clang-format-${REQUIRED_MAJOR}" >&2
    exit 1
fi

if [ $# -eq 0 ]; then
    # Default: format-check all project sources
    find include/ src/ tests/ \
        -type f \( -name '*.c' -o -name '*.h' \) \
        -not -path '*/build/*' \
        -not -path '*/_deps/*' \
        -not -name '*.h.in' \
        | xargs "$CF" --dry-run --Werror
else
    # Pass-through mode: forward all arguments
    exec "$CF" "$@"
fi
