#!/usr/bin/env bash

assert_equals() {
  local expected="$1"
  local actual="$2"
  local message="$3"

  if [[ "$expected" != "$actual" ]]; then
    printf 'FAIL: %s\nExpected: %s\nActual: %s\n' "$message" "$expected" "$actual" >&2
    return 1
  fi

  printf 'PASS: %s\n' "$message"
}

assert_exit_code() {
  local expected="$1"
  local actual="$2"
  local message="$3"

  if [[ "$expected" -ne "$actual" ]]; then
    printf 'FAIL: %s\nExpected exit code: %s\nActual exit code: %s\n' "$message" "$expected" "$actual" >&2
    return 1
  fi

  printf 'PASS: %s\n' "$message"
}
