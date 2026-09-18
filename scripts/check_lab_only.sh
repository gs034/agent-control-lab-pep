#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fail-closed Lab-only check: reconstructed brand tokens must not appear
# in the tracked tree, path names, branch name, or commit subjects/bodies
# on this branch (versus main).
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${ROOT}" ]]; then
  echo "lab-only: not a git checkout" >&2
  exit 1
fi
cd "${ROOT}"

if ! command -v rg >/dev/null 2>&1; then
  echo "lab-only: rg (ripgrep) is required" >&2
  exit 1
fi

# Split so this file does not contain the brand strings as literals.
TOKENS=(
  "AE""GIS"
  "Cap""Scope"
  "AG""F"
  "Cygnet""Quant"
  "Sig""net"
  "Sig""netQuant"
  "Excali""VAR"
  "AI""PTH"
  "think""money"
  "Fal""con"
  "PIPE""LINE"
  "C""Q"
)

PHRASES=(
  "Cygnet"" Quant"
  "Sig""net Quant"
  "Think"" Money"
  "IP""-transfer"
  "acquired""-from"
)

PATH_PARTS=(
  "cygnet""quant"
  "think""money"
)

RG_WORD_ARGS=()
for token in "${TOKENS[@]}"; do
  RG_WORD_ARGS+=(-e "${token}")
done

rg_word_hit() {
  rg -n -i -w --hidden --glob '!.git/**' "${RG_WORD_ARGS[@]}" "$@"
}

fail_if_word_hit() {
  local label="$1"
  shift
  local code=0
  set +e
  rg_word_hit "$@"
  code=$?
  set -e
  if [[ "${code}" -eq 0 ]]; then
    echo "lab-only: forbidden brand token in ${label}" >&2
    exit 1
  fi
  if [[ "${code}" -ge 2 ]]; then
    echo "lab-only: rg failed while scanning ${label}" >&2
    exit 1
  fi
}

fail_if_phrase_hit() {
  local label="$1"
  shift
  local phrase code
  for phrase in "${PHRASES[@]}"; do
    code=0
    set +e
    rg -n -i -F --hidden --glob '!.git/**' -e "${phrase}" "$@"
    code=$?
    set -e
    if [[ "${code}" -eq 0 ]]; then
      echo "lab-only: forbidden phrase in ${label}" >&2
      exit 1
    fi
    if [[ "${code}" -ge 2 ]]; then
      echo "lab-only: rg failed while scanning ${label}" >&2
      exit 1
    fi
  done
}

self_test() {
  local tmp token phrase
  tmp="$(mktemp -d)"
  for token in "${TOKENS[@]}"; do
    printf '%s\n' "${token}" >"${tmp}/probe.txt"
    if ! rg -q -i -w -e "${token}" "${tmp}/probe.txt"; then
      rm -rf "${tmp}"
      echo "lab-only: self-test miss for a reconstructed token" >&2
      exit 1
    fi
  done
  for phrase in "${PHRASES[@]}"; do
    printf '%s\n' "${phrase}" >"${tmp}/probe.txt"
    if ! rg -q -i -F -e "${phrase}" "${tmp}/probe.txt"; then
      rm -rf "${tmp}"
      echo "lab-only: self-test miss for a reconstructed phrase" >&2
      exit 1
    fi
  done
  printf '%s\n' "Agent Control Lab host/runtime PEP stub" >"${tmp}/ok.txt"
  if rg -q -i -w "${RG_WORD_ARGS[@]}" "${tmp}/ok.txt"; then
    rm -rf "${tmp}"
    echo "lab-only: self-test false positive on Lab wording" >&2
    exit 1
  fi
  rm -rf "${tmp}"
}

self_test

fail_if_word_hit "working tree" .
fail_if_phrase_hit "working tree" .

mapfile -t TRACKED < <(git ls-files)
if [[ "${#TRACKED[@]}" -eq 0 ]]; then
  echo "lab-only: no tracked files" >&2
  exit 1
fi

fail_if_word_hit "tracked file contents" -- "${TRACKED[@]}"
fail_if_phrase_hit "tracked file contents" -- "${TRACKED[@]}"

paths="$(printf '%s\n' "${TRACKED[@]}")"
fail_if_word_hit "tracked path names" -- <<<"${paths}"
fail_if_phrase_hit "tracked path names" -- <<<"${paths}"

lower_paths="$(printf '%s\n' "${TRACKED[@]}" | tr '[:upper:]' '[:lower:]')"
for part in "${PATH_PARTS[@]}"; do
  if grep -Fq -- "${part}" <<<"${lower_paths}"; then
    echo "lab-only: forbidden path segment in tracked paths" >&2
    exit 1
  fi
done

branch="${GITHUB_HEAD_REF:-}"
if [[ -z "${branch}" ]]; then
  branch="$(git branch --show-current || true)"
fi
if [[ -z "${branch}" ]]; then
  branch="${GITHUB_REF_NAME:-}"
fi
if [[ -n "${branch}" ]]; then
  fail_if_word_hit "branch name '${branch}'" -- <<<"${branch}"
  fail_if_phrase_hit "branch name '${branch}'" -- <<<"${branch}"
fi

base=""
if git rev-parse --verify --quiet origin/main >/dev/null; then
  base="origin/main"
elif git rev-parse --verify --quiet main >/dev/null; then
  base="main"
fi
if [[ -n "${base}" ]] && [[ "$(git rev-parse HEAD)" != "$(git rev-parse "${base}")" ]]; then
  commits="$(git log --format='%s%n%b' "${base}..HEAD")"
  if [[ -n "${commits}" ]]; then
    fail_if_word_hit "commit subjects/bodies (${base}..HEAD)" -- <<<"${commits}"
    fail_if_phrase_hit "commit subjects/bodies (${base}..HEAD)" -- <<<"${commits}"
  fi
fi

echo "lab-only: clean"
