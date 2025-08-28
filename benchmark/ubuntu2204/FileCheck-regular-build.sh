#!/usr/bin/env bash

echo "Building regular binary.."
ninja -j8 -C FileCheck/build_regular FileCheck

# Find free filename for the trace
last_num=$(ls FileCheck/trace-regular-*.json 2>/dev/null \
    | sed -E 's/.*trace-regular-([0-9]+)\.json/\1/' \
    | sort -n \
    | tail -1)
if [[ -z "$last_num" ]]; then
    outfile="FileCheck/trace-regular-1.json"
else
    outfile="FileCheck/trace-regular-$((last_num+1)).json"
fi

touch $outfile
ninjatracing/ninjatracing FileCheck/build_regular/.ninja_log > $outfile
