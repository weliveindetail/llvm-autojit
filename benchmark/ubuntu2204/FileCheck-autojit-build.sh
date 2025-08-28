#!/usr/bin/env bash

echo "Building autojit binary.."
ninja -j8 -C FileCheck/build_autojit FileCheck

# Find free filename for the trace
last_num=$(ls FileCheck/trace-autojit-*.json 2>/dev/null \
    | sed -E 's/.*trace-autojit-([0-9]+)\.json/\1/' \
    | sort -n \
    | tail -1)
if [[ -z "$last_num" ]]; then
    outfile="FileCheck/trace-autojit-1.json"
else
    outfile="FileCheck/trace-autojit-$((last_num+1)).json"
fi

touch $outfile
ninjatracing/ninjatracing FileCheck/build_autojit/.ninja_log > $outfile
