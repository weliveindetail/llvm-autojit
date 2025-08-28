#!/usr/bin/env bash
set -euo pipefail

FileCheck/build_autojit/bin/FileCheck --version

prefixes=(
  PASS1
  PASS2
  FAIL1
)

for prefix in "${prefixes[@]}"; do
  FileCheck/build_autojit/bin/FileCheck \
    --input-file=inputs/same.txt \
    --check-prefix="$prefix" \
    inputs/same.txt
done
