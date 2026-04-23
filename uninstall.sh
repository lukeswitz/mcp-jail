#!/usr/bin/env bash
# mcp-jail full uninstall. Reverses install.sh and leaves the system as
# close to pre-install state as possible.
#
# What this removes:
#   1. Client config wrappings (runs `mcp-jail unwrap` to restore originals)
#   2. Sentry watchdog (launchd agent on macOS, systemd user units on Linux,
#      Scheduled Tasks on Windows — via `mcp-jail sentry uninstall`)
#   3. The mcp-jail binary from every known install location
#   4. Residual plist/service files the sentry helper may have missed
#   5. State directory ~/.mcp-jail/ (signing key, allow-list, audit log,
#      pending queue, sandbox profiles)
#
# Flags:
#   --keep-state   leave ~/.mcp-jail/ in place (keeps approved fingerprints
#                  and signing key for a future reinstall)
#   --yes          skip the final confirmation prompt
#   --dry-run      show what would be removed, change nothing
#
# Exit 0 on clean uninstall, 1 if something refused to die. Re-run is safe.

set -uo pipefail

KEEP_STATE=0
ASSUME_YES=0
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    --keep-state) KEEP_STATE=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    --dry-run)    DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) printf 'unknown flag: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m ok:\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

run() {
  if (( DRY_RUN )); then
    printf '    [dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

run_sudo() {
  if (( DRY_RUN )); then
    printf '    [dry-run] sudo %s\n' "$*"
    return 0
  fi
  local first_dir
  first_dir="$(dirname "${2:-/}" 2>/dev/null || echo /)"
  if [[ -w "$first_dir" ]]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    warn "cannot elevate to remove ${2:-}; no sudo available"
    return 1
  fi
}

confirm() {
  (( ASSUME_YES )) && return 0
  local reply
  printf '\nProceed? [y/N] '
  read -r reply || reply=""
  [[ "$reply" =~ ^[Yy] ]]
}

# ---------------------------------------------------------------------------
# 1. Unwrap MCP client configs (restore originals from backups).
# ---------------------------------------------------------------------------
step_unwrap() {
  log "restoring MCP client configs (mcp-jail unwrap)"
  if ! have mcp-jail; then
    warn "mcp-jail not on PATH — cannot run unwrap; any wrapped configs will stay wrapped"
    warn "reinstall briefly (curl ... install.sh) then re-run this uninstaller if that matters"
    return 0
  fi
  if (( DRY_RUN )); then
    printf '    [dry-run] mcp-jail unwrap\n'
    return 0
  fi
  # unwrap is interactive by default; pipe `y` repeatedly if we have --yes,
  # otherwise let the user confirm per-file.
  if (( ASSUME_YES )); then
    yes | mcp-jail unwrap || warn "unwrap returned non-zero — check `mcp-jail list` and client configs manually"
  else
    mcp-jail unwrap || warn "unwrap returned non-zero — check client configs manually"
  fi
}

# ---------------------------------------------------------------------------
# 2. Uninstall the sentry watchdog (launchd / systemd / Scheduled Tasks).
# ---------------------------------------------------------------------------
step_sentry() {
  log "removing sentry watchdog"
  if have mcp-jail; then
    if (( DRY_RUN )); then
      printf '    [dry-run] mcp-jail sentry uninstall\n'
    else
      mcp-jail sentry uninstall >/dev/null 2>&1 || warn "sentry uninstall returned non-zero"
    fi
  else
    warn "mcp-jail not on PATH — cleaning sentry files directly"
  fi
  # Belt-and-braces cleanup in case the binary was already removed before
  # sentry-uninstall had a chance to run.
  local os; os="$(uname -s)"
  case "$os" in
    Darwin)
      local plist="$HOME/Library/LaunchAgents/com.lukeswitz.mcp-jail.sentry.plist"
      if [[ -e "$plist" ]]; then
        run launchctl bootout "gui/$(id -u)" "$plist" 2>/dev/null || true
        run launchctl unload "$plist" 2>/dev/null || true
        run rm -f "$plist"
        ok "removed $plist"
      fi
      ;;
    Linux)
      local unit_dir="$HOME/.config/systemd/user"
      if have systemctl; then
        for u in com.lukeswitz.mcp-jail.sentry.service \
                 com.lukeswitz.mcp-jail.sentry.timer \
                 com.lukeswitz.mcp-jail.sentry.path; do
          run systemctl --user stop    "$u" 2>/dev/null || true
          run systemctl --user disable "$u" 2>/dev/null || true
        done
        run systemctl --user daemon-reload 2>/dev/null || true
      fi
      for u in "$unit_dir/com.lukeswitz.mcp-jail.sentry.service" \
               "$unit_dir/com.lukeswitz.mcp-jail.sentry.timer" \
               "$unit_dir/com.lukeswitz.mcp-jail.sentry.path"; do
        [[ -e "$u" ]] && { run rm -f "$u"; ok "removed $u"; }
      done
      ;;
    MINGW*|MSYS*|CYGWIN*)
      for task in mcp-jail-sentry mcp-jail-sentry-watcher; do
        run schtasks.exe /Delete /TN "$task" /F 2>/dev/null || true
      done
      ;;
  esac
}

# ---------------------------------------------------------------------------
# 3. Remove the binary from every known location.
# ---------------------------------------------------------------------------
step_binary() {
  log "removing mcp-jail binary"
  local candidates=(
    "/usr/local/bin/mcp-jail"
    "/opt/homebrew/bin/mcp-jail"
    "$HOME/.cargo/bin/mcp-jail"
    "$HOME/.local/bin/mcp-jail"
    "/usr/bin/mcp-jail"
  )
  local removed=0
  for c in "${candidates[@]}"; do
    [[ -e "$c" || -L "$c" ]] || continue
    if [[ -w "$(dirname "$c")" ]]; then
      run rm -f "$c" && { ok "removed $c"; removed=$((removed+1)); }
    elif have sudo; then
      run_sudo rm -f "$c" && { ok "removed $c (sudo)"; removed=$((removed+1)); }
    else
      warn "cannot remove $c — no write perm and no sudo"
    fi
  done
  # Catch .exe on Windows if present.
  if [[ -e "/usr/local/bin/mcp-jail.exe" ]]; then
    run rm -f /usr/local/bin/mcp-jail.exe && ok "removed /usr/local/bin/mcp-jail.exe"
  fi
  (( removed == 0 )) && log "no binary found on common paths"
  # Final check: anything still on PATH?
  if have mcp-jail; then
    warn "mcp-jail is still reachable at: $(command -v mcp-jail)"
    warn "remove it manually or adjust PATH"
  fi
}

# ---------------------------------------------------------------------------
# 4. Remove state dir (unless --keep-state).
# ---------------------------------------------------------------------------
step_state() {
  local dir="$HOME/.mcp-jail"
  if (( KEEP_STATE )); then
    log "keeping state dir (--keep-state): $dir"
    return 0
  fi
  if [[ -d "$dir" ]]; then
    log "removing state dir $dir"
    run rm -rf "$dir" && ok "state dir removed"
  else
    log "no state dir at $dir"
  fi
}

# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------
main() {
  echo "mcp-jail uninstall"
  echo "  unwrap client configs : yes"
  echo "  remove sentry watchdog: yes"
  echo "  remove binary         : yes ($(command -v mcp-jail 2>/dev/null || echo not-found))"
  if (( KEEP_STATE )); then
    echo "  remove ~/.mcp-jail    : NO (--keep-state)"
  else
    echo "  remove ~/.mcp-jail    : yes"
  fi
  (( DRY_RUN )) && echo "  mode                  : DRY RUN (nothing will change)"

  if ! confirm; then
    echo "aborted."
    exit 0
  fi

  step_unwrap
  step_sentry
  step_binary
  step_state

  echo
  if (( DRY_RUN )); then
    log "dry-run complete. Re-run without --dry-run to actually uninstall."
  else
    ok "mcp-jail uninstalled. Restart your MCP client(s) for changes to take full effect."
  fi
}

main "$@"
