#!/usr/bin/env bash
set -euo pipefail

mkdir -p bzip2/outputs

cp inputs/data1.txt bzip2/outputs/data1_autojit.txt
bzip2/$AUTOJIT_BUILD_DIR/bzip2 -1 -f bzip2/outputs/data1_autojit.txt

cp inputs/data2.txt bzip2/outputs/data2_autojit.txt
bzip2/$AUTOJIT_BUILD_DIR/bzip2 -1 -f bzip2/outputs/data2_autojit.txt
