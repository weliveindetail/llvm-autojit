#!/usr/bin/env bash
set -e

# Usage: lld-run.sh <path to lld> <threads> <output file>
lld="$(realpath "$1")"
output="$(realpath "$3")"
cd lld/workload
"$lld" -flavor gnu @response.txt --threads="$2" -o "$output"
