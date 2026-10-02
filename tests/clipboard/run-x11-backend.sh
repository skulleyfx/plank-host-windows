#!/usr/bin/env bash
set -euo pipefail
# Run only on a disposable Linux builder with Xvfb; no desktop access required.
repo=$(cd "$(dirname "$0")/../.." && pwd)
scratch=$(mktemp -d)
xvfb_pid=
cleanup() {
  if [[ -n "$xvfb_pid" ]]; then kill "$xvfb_pid" 2>/dev/null || true; wait "$xvfb_pid" 2>/dev/null || true; fi
  rm -rf "$scratch"
}
trap cleanup EXIT
"${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror -DSUNSHINE_BUILD_X11 \
  -I"$repo/tests/clipboard/include" -I"$repo" \
  "$repo/src/platform/linux/x11_clipboard.cpp" "$repo/tests/clipboard/x11-backend.cxx" \
  $(pkg-config --cflags --libs xcb x11) -o "$scratch/clipboard-test"
# No TCP listener; Xvfb is private to this disposable test process/container.
Xvfb -displayfd 3 -screen 0 640x480x24 -nolisten tcp -noreset -ac 3>"$scratch/display" >"$scratch/xvfb.log" 2>&1 &
xvfb_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
  [[ -s "$scratch/display" ]] && break
  kill -0 "$xvfb_pid"
  sleep 0.05
done
test -s "$scratch/display"
export DISPLAY=":$(cat "$scratch/display")"
"$scratch/clipboard-test"

# Keep the tested wait path wired into the real worker, not only the fixture.
if ! sed -n '/void localClipboardThread(/,/^  }/p' "$repo/src/stream.cpp" |
    grep -Fq 'session->clipboard->wait_for_activity()'; then
  echo 'FAIL clipboard worker does not use the tested X11 wait' >&2
  exit 1
fi

if [[ "${1:-}" == --negative-controls ]]; then
  # Compile the exact reviewed implementation with this same real-X11 harness.
  # Diagnostic stubs avoid unrelated product dependencies; X11 calls are real.
  baseline=1ad746b626f31f43ec564f49d5e78ce14ab7a68e
  mkdir -p "$scratch/baseline/src/platform/linux"
  for file in x11_clipboard.cpp x11_clipboard.h; do
    git -C "$repo" -c safe.directory="$repo" show "$baseline:src/platform/linux/$file" \
      > "$scratch/baseline/src/platform/linux/$file"
  done
  "${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror -DSUNSHINE_BUILD_X11 -DPLANK_CLIPBOARD_SLEEP_POLL \
    -I"$scratch/baseline" -I"$repo/tests/clipboard/include" -I"$repo" \
    "$scratch/baseline/src/platform/linux/x11_clipboard.cpp" "$repo/tests/clipboard/x11-backend.cxx" \
    $(pkg-config --cflags --libs x11 xfixes) -o "$scratch/baseline-test"
  for regression in 'destroyed requestor' 'independent selections' '150ms delayed reply' '512KiB INCR reply'; do
    if "$scratch/baseline-test" "$regression" >"$scratch/negative.log" 2>&1; then
      echo "FAIL negative control unexpectedly passed: $regression" >&2
      exit 1
    fi
    echo "PASS negative control reproduces: $regression"
  done

  # The asynchronous backend alone is insufficient: the old worker's fixed
  # 250 ms sleep still times out a legal 512 KiB transfer in 16 KiB chunks.
  "${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror -DSUNSHINE_BUILD_X11 -DPLANK_CLIPBOARD_SLEEP_POLL \
    -I"$repo/tests/clipboard/include" -I"$repo" \
    "$repo/src/platform/linux/x11_clipboard.cpp" "$repo/tests/clipboard/x11-backend.cxx" \
    $(pkg-config --cflags --libs xcb x11) -o "$scratch/sleep-poll-test"
  if "$scratch/sleep-poll-test" '512KiB INCR worker cadence' >"$scratch/negative.log" 2>&1; then
    echo 'FAIL fixed-sleep negative control unexpectedly passed' >&2
    exit 1
  fi
  echo 'PASS negative control reproduces: INCR worker cadence'
fi
