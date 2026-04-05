#!/usr/bin/env bash
set -euo pipefail

print_help() {
  cat <<'EOF'
Usage:
  ./123.sh reverse <text>
  ./123.sh wordcount <text>
  ./123.sh palindrome <text>
  ./123.sh help

Examples:
  ./123.sh reverse "hello world"
  ./123.sh wordcount "one two three"
  ./123.sh palindrome "Never odd or even"
EOF
}

reverse_text() {
  local input="${1-}"
  local index
  local reversed=""

  for (( index=${#input}-1; index>=0; index-- )); do
    reversed+="${input:index:1}"
  done

  printf '%s\n' "$reversed"
}

word_count() {
  local input="${1-}"
  local -a words=()

  if [[ -z "${input// }" ]]; then
    printf '0\n'
    return
  fi

  read -r -a words <<< "$input"
  printf '%s\n' "${#words[@]}"
}

normalize_text() {
  local input="${1-}"

  printf '%s' "$input" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]'
}

is_palindrome() {
  local normalized
  normalized="$(normalize_text "${1-}")"

  if [[ -z "$normalized" ]]; then
    return 1
  fi

  [[ "$normalized" == "$(reverse_text "$normalized")" ]]
}

main() {
  local command="${1-help}"
  shift || true

  case "$command" in
    reverse)
      if [[ $# -eq 0 ]]; then
        printf 'Error: missing text for reverse.\n' >&2
        exit 1
      fi
      reverse_text "$*"
      ;;
    wordcount)
      if [[ $# -eq 0 ]]; then
        printf 'Error: missing text for wordcount.\n' >&2
        exit 1
      fi
      word_count "$*"
      ;;
    palindrome)
      if [[ $# -eq 0 ]]; then
        printf 'Error: missing text for palindrome.\n' >&2
        exit 1
      fi
      if is_palindrome "$*"; then
        printf 'yes\n'
      else
        printf 'no\n'
      fi
      ;;
    help|-h|--help)
      print_help
      ;;
    *)
      printf 'Error: unknown command "%s".\n' "$command" >&2
      print_help >&2
      exit 1
      ;;
  esac
}

main "$@"
