#!/usr/bin/env bash

FileCheck/build_regular/bin/FileCheck --version

prefixes=(
  PASS1
  PASS2
  FAIL1
)

# FAIL prefixes are expected to fail
for prefix in "${prefixes[@]}"; do
  if FileCheck/build_regular/bin/FileCheck \
       --input-file=inputs/same.txt \
       --check-prefix="$prefix" \
       inputs/same.txt; then
    [[ "$prefix" != FAIL* ]] || { echo "Unexpected pass: $prefix"; exit 1; }
  else
    [[ "$prefix" == FAIL* ]] || { echo "Unexpected fail: $prefix"; exit 1; }
  fi
done
