#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=tests/assert.sh
source "$SCRIPT_DIR/assert.sh"

run_output_test() {
  local message="$1"
  local expected="$2"
  shift 2
  local actual

  actual="$("$PROJECT_DIR/123.sh" "$@")"
  assert_equals "$expected" "$actual" "$message"
}

run_exit_code_test() {
  local message="$1"
  local expected="$2"
  shift 2
  local exit_code=0

  if "$PROJECT_DIR/123.sh" "$@" >/dev/null 2>&1; then
    exit_code=0
  else
    exit_code=$?
  fi

  assert_exit_code "$expected" "$exit_code" "$message"
}

main() {
  run_output_test "reverse flips text" "dlrow olleh" reverse "hello world"
  run_output_test "wordcount counts words" "3" wordcount "one two three"
  run_output_test "wordcount handles extra spaces" "3" wordcount "  alpha   beta   gamma  "
  run_output_test "palindrome accepts phrase" "yes" palindrome "Never odd or even"
  run_output_test "palindrome rejects non palindrome" "no" palindrome "Codex"
  run_exit_code_test "unknown command returns failure" 1 unknown

  printf '\nAll tests passed.\n'
}

main "$@"
