#!/usr/bin/env bash
set -e

echo "Test lld with autojit"
mkdir -p lld
export CCACHE_DISABLE=1

if [ ! -x lld/build_regular/bin/lld ]; then
  echo "Build regular lld: lld/test-regular-build.log"
  ./lld-regular-setup.sh > lld/test-regular-setup.log 2>&1
  ./lld-regular-build.sh > lld/test-regular-build.log 2>&1
fi
if [ ! -f lld/workload/response.txt ]; then
  ./lld-workload.sh
fi
./lld-run.sh lld/build_regular/bin/lld 16 lld/expected.out

for mode in shlib static; do
  if [ $mode = static ]; then
    export AUTOJIT_BUILD_DIR=build_autojit_static AUTOJIT_LINK_STATIC_RUNTIME=On
  else
    export AUTOJIT_BUILD_DIR=build_autojit AUTOJIT_LINK_STATIC_RUNTIME=Off
  fi
  echo "Build autojit lld ($mode): lld/test-autojit-$mode-build.log"
  ./lld-autojit-setup.sh > lld/test-autojit-$mode-setup.log 2>&1
  ./lld-autojit-build.sh > lld/test-autojit-$mode-build.log 2>&1
  for threads in 1 16; do
    echo "Run autojit lld ($mode, --threads=$threads): lld/test-autojit-$mode-run.log"
    timeout 600 ./lld-run.sh lld/$AUTOJIT_BUILD_DIR/bin/lld $threads lld/autojit.out \
        > lld/test-autojit-$mode-run.log 2>&1
    cmp lld/expected.out lld/autojit.out
  done
done
echo "Outputs match"
