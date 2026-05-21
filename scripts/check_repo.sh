#!/usr/bin/env bash
set -euo pipefail

echo "Checking repository for files that should not be committed..."

BAD=0

check_path() {
  local pattern="$1"
  if find . -path "$pattern" -print -quit | grep -q .; then
    echo "Found unwanted path: $pattern"
    BAD=1
  fi
}

check_path "*/venv"
check_path "*/.venv"
check_path "*/__pycache__"

if find . -name '.env' -print -quit | grep -q .; then
  echo "Found .env file. Do not commit it."
  BAD=1
fi

if find . -name '*.pyc' -print -quit | grep -q .; then
  echo "Found Python bytecode files."
  BAD=1
fi

if [ "$BAD" -eq 0 ]; then
  echo "Repository looks clean for GitHub push."
else
  echo "Please remove unwanted files before pushing."
  exit 1
fi
