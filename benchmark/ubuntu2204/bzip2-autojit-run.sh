#!/usr/bin/env bash

mkdir -p bzip2/outputs

cp inputs/data1.txt bzip2/outputs/data1_autojit.txt
bzip2/build_autojit/bzip2 -1 -f bzip2/outputs/data1_autojit.txt

cp inputs/data2.txt bzip2/outputs/data2_autojit.txt
bzip2/build_autojit/bzip2 -1 -f bzip2/outputs/data2_autojit.txt
