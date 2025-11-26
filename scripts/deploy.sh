#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "ansible-playbook not found. Please install Ansible." >&2
  exit 1
fi

LIMIT_ARG=${LIMIT:-}
TAGS_ARG=${TAGS:-}

ARGS=()
[[ -n "${LIMIT_ARG}" ]] && ARGS+=(--limit "${LIMIT_ARG}")
[[ -n "${TAGS_ARG}" ]] && ARGS+=(--tags "${TAGS_ARG}")

ansible-playbook -i inventory/hosts.yml playbooks/site.yml "${ARGS[@]}"
