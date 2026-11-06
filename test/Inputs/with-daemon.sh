#!/bin/sh
# Runs a command against a standalone daemon on its own socket
AUTOJIT_SOCKET_PATH=$1
export AUTOJIT_SOCKET_PATH
shift
rm -f "$AUTOJIT_SOCKET_PATH"
"$AUTOJIT_DAEMON_PATH" > /dev/null 2>&1 < /dev/null &
daemon=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
  [ -S "$AUTOJIT_SOCKET_PATH" ] && break
  sleep 0.2
done
env -u AUTOJITD_FORCE_SPAWN "$@"
status=$?
kill $daemon
rm -f "$AUTOJIT_SOCKET_PATH"
exit $status
