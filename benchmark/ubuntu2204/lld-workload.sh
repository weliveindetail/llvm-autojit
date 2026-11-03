#!/usr/bin/env bash
set -e

# The workload is the link of the regular lld itself. We record it with
# --reproduce, so it's self-contained and the same for every run.
rm -rf lld/workload lld/workload.tar
# Only the link itself, not the symlinks that follow it
link_cmd=$(ninja -C lld/build_regular -t commands bin/lld | tail -1 \
    | sed -e 's/^: && //' -e 's/ && .*$//')
(cd lld/build_regular && eval "$link_cmd -Wl,--reproduce=../workload.tar -o bin/lld-reproduce")
rm -f lld/build_regular/bin/lld-reproduce
tar -xf lld/workload.tar -C lld
echo "Recorded workload in lld/workload ($(du -sh lld/workload | cut -f1))"
