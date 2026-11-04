#!/usr/bin/env bash
set -xeo pipefail

export CCACHE_DISABLE=1
export AUTOJIT_DEBUG=Off

# Default to shlib build
if [ -z "$AUTOJIT_BUILD_DIR" ]; then
  export AUTOJIT_LINK_STATIC_RUNTIME=Off
  export AUTOJIT_BUILD_DIR=build_autojit_shlib
fi

for arg in "$@"; do
  case "$arg" in
    # Opt-in to static build with external autojitd for local testing
    --autojitd)
      export AUTOJITD_FORCE_SPAWN=Off
      export AUTOJITD_FORCE_DAEMON=On
      export AUTOJIT_LINK_STATIC_RUNTIME=On
      export AUTOJIT_BUILD_DIR=build_autojit_static
      ;;
    # Build and run the full json test suite instead of test-hash_cpp11 only
    --all)
      export JSON_TEST_ALL=On
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

echo "Test json with autojit"
rm -rf json
mkdir -p json

./json-autojit-setup.sh 2>&1 | tee json/test-autojit-setup.log
./json-autojit-build.sh 2>&1 | tee json/test-autojit-build.log
./json-autojit-run.sh 2>&1 | tee json/test-autojit-run.log
