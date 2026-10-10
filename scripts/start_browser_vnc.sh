#!/usr/bin/env bash
# Optional local display for BugHunter browser sessions. No recon CDP or profile reuse.
set -euo pipefail
umask 077

display_number="${HACKBOT_BROWSER_DISPLAY_NUMBER:-901}"
vnc_port="${HACKBOT_BROWSER_VNC_PORT:-6901}"
runtime_dir="${HACKBOT_BROWSER_VNC_RUNTIME_DIR:-${HOME}/.local/state/bughunter-agent/browser-vnc}"
novnc_root="${NOVNC_ROOT:-/usr/share/novnc}"

if [[ ! "$display_number" =~ ^[0-9]{3,4}$ || "$display_number" == 99 ]]; then
  printf '%s\n' 'Invalid dedicated display number' >&2
  exit 2
fi
if [[ ! "$vnc_port" =~ ^[0-9]{4,5}$ || "$vnc_port" == 6080 ]]; then
  printf '%s\n' 'Invalid dedicated VNC port' >&2
  exit 2
fi
for tool in Xvfb fluxbox x11vnc websockify xauth mcookie; do
  command -v "$tool" >/dev/null || { printf 'Missing dependency: %s\n' "$tool" >&2; exit 2; }
done
[[ -d "$novnc_root" ]] || { printf '%s\n' 'noVNC static files are unavailable' >&2; exit 2; }

export DISPLAY=":${display_number}"
export XAUTHORITY="$runtime_dir/Xauthority"
socket="$runtime_dir/vnc.sock"
if [[ -e "/tmp/.X${display_number}-lock" || -e "/tmp/.X11-unix/X${display_number}" ]]; then
  printf '%s\n' 'Dedicated display is already in use; refusing to alter it' >&2
  exit 2
fi
mkdir -p "$runtime_dir"
chmod 700 "$runtime_dir"
if [[ -e "$socket" ]]; then
  printf '%s\n' 'Dedicated VNC socket already exists; refusing to replace it' >&2
  exit 2
fi
xauth -f "$XAUTHORITY" add "$DISPLAY" . "$(mcookie)" >/dev/null
chmod 600 "$XAUTHORITY"

pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -f "$socket"
}
trap cleanup EXIT INT TERM

Xvfb "$DISPLAY" -screen 0 1440x900x24 -nolisten tcp -auth "$XAUTHORITY" -noreset \
  >"$runtime_dir/xvfb.log" 2>&1 &
pids+=("$!")
for _ in {1..50}; do
  [[ -S "/tmp/.X11-unix/X${display_number}" ]] && break
  sleep 0.1
done
[[ -S "/tmp/.X11-unix/X${display_number}" ]] || { printf '%s\n' 'Dedicated display did not start' >&2; exit 1; }

fluxbox -display "$DISPLAY" >"$runtime_dir/fluxbox.log" 2>&1 &
pids+=("$!")
x11vnc -display "$DISPLAY" -no6 -rfbport 0 -rfbportv6 0 -unixsock "$socket" \
  -forever -shared -nopw -noxdamage -repeat -o "$runtime_dir/x11vnc.log" &
pids+=("$!")
for _ in {1..50}; do
  [[ -S "$socket" ]] && break
  sleep 0.1
done
[[ -S "$socket" ]] || { printf '%s\n' 'Dedicated VNC socket did not start' >&2; exit 1; }

websockify --web="$novnc_root" --unix-target="$socket" "127.0.0.1:${vnc_port}" \
  >"$runtime_dir/websockify.log" 2>&1 &
pids+=("$!")
printf 'BugHunter VNC ready on 127.0.0.1:%s (display %s)\n' "$vnc_port" "$DISPLAY"
wait -n "${pids[@]}"
exit 1
