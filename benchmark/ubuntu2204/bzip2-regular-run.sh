#!/usr/bin/env bash

bzip2/build_regular/bzip2 -1 inputs/data1.txt --stdout > bzip2/outputs/data1_regular.txt
bzip2/build_regular/bzip2 -1 inputs/data2.txt --stdout > bzip2/outputs/data2_regular.txt
