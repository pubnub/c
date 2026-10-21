#!/bin/bash
# C99 conformance gate for SDK sources.
#
# Syntax-checks every src/ translation unit from the compile database with
# -std=c99 -pedantic-errors -Wall -Wextra -Werror. Recorded -std, -Werror and
# output flags are replaced. Mixed declarations are not flagged: C99 allows them.
#
# Coverage: only translation units in the given compile database are checked.
# Embedded-only providers (arena allocator, FreeRTOS, Zephyr, mbedTLS, curl,
# Windows) need RTOS or vendor headers that the ci-lint database does not
# build, so they are not checked here.
#
# Local run:
#   cmake --preset ci-lint
#   tools/c99-check.sh build/ci-lint
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${1:-$ROOT/build/ci-lint}"
DB="$BUILD_DIR/compile_commands.json"

if [ ! -f "$DB" ]; then
    echo "ERROR: $DB not found. Run: cmake --preset ci-lint" >&2
    exit 1
fi

python3 - "$DB" "$ROOT" <<'PY'
import json
import shlex
import subprocess
import sys

db_path, root = sys.argv[1], sys.argv[2]
src_prefix = root + "/src/"
drop_with_value = {"-o", "-MF", "-MT", "-MQ"}
drop_flags = {"-c", "-MD", "-MMD", "-Werror"}

checked = 0
failed = []

for entry in json.load(open(db_path)):
    path = entry["file"]
    if not path.startswith(src_prefix) or "/_deps/" in path:
        continue

    if "arguments" in entry:
        args = entry["arguments"]
    else:
        args = shlex.split(entry["command"])
    cmd = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in drop_with_value:
            skip_next = True
            continue
        if arg in drop_flags or arg.startswith("-std=") or arg.startswith("-Werror="):
            continue
        if arg == path:
            continue
        cmd.append(arg)
    cmd += ["-std=c99", "-pedantic-errors", "-Wall", "-Wextra", "-Werror", "-fsyntax-only", path]

    checked += 1
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        failed.append(path)
        sys.stderr.write(result.stderr)

if checked == 0:
    print("ERROR: no src/ entries found in compile database", file=sys.stderr)
    sys.exit(1)

print(f"C99 check: {checked} translation units, {len(failed)} failed")
if failed:
    for path in failed:
        print(f"  FAILED: {path}", file=sys.stderr)
    sys.exit(1)
PY
