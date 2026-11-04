#!/usr/bin/env bash

if [ "$JSON_TEST_ALL" = "On" ]; then
  # Label "all" covers the unit tests, ctest pulls in the test data fixture
  ctest --test-dir json/$AUTOJIT_BUILD_DIR -L all -j"$(nproc)" --output-on-failure
else
  json/$AUTOJIT_BUILD_DIR/tests/test-hash_cpp11
fi
