#!/usr/bin/env bash

set -euo pipefail

REPO="lukeswitz/mcp-jail"
VERSION="${MCP_JAIL_VERSION:-latest}"
PREFIX="${MCP_JAIL_PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os-$arch" in
    Darwin-arm64)              echo "aarch64-apple-darwin" ;;
    Darwin-x86_64)             echo "x86_64-apple-darwin" ;;
    Linux-aarch64|Linux-arm64) echo "aarch64-unknown-linux-gnu" ;;
    Linux-x86_64)              echo "x86_64-unknown-linux-gnu" ;;
    MINGW*|MSYS*|CYGWIN*)      echo "x86_64-pc-windows-msvc" ;;
    *) die "unsupported platform: $os $arch" ;;
  esac
}

release_url() {
  local target="$1" ext="$2"
  if [[ "$VERSION" == "latest" ]]; then
    echo "https://github.com/$REPO/releases/latest/download/mcp-jail-$target.$ext"
  else
    echo "https://github.com/$REPO/releases/download/$VERSION/mcp-jail-$target.$ext"
  fi
}

sudo_if_needed() {
  if [[ -w "$BIN_DIR" ]]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    die "$BIN_DIR not writable and sudo unavailable; set MCP_JAIL_PREFIX=\$HOME/.local"
  fi
}

# Remove stale copies in other common locations so a single binary on PATH wins.
# Runs before install so old copies never shadow the fresh one.
cleanup_stale_copies() {
  local target="$BIN_DIR/mcp-jail"
  local candidates=(
    "/usr/local/bin/mcp-jail"
    "/opt/homebrew/bin/mcp-jail"
    "$HOME/.cargo/bin/mcp-jail"
    "$HOME/.local/bin/mcp-jail"
    "/usr/bin/mcp-jail"
  )
  local removed=0 c real_c real_target
  real_target="$(cd "$(dirname "$target")" 2>/dev/null && pwd -P)/$(basename "$target")" || real_target="$target"
  for c in "${candidates[@]}"; do
    [[ -e "$c" || -L "$c" ]] || continue
    real_c="$(cd "$(dirname "$c")" 2>/dev/null && pwd -P)/$(basename "$c")" || real_c="$c"
    [[ "$real_c" == "$real_target" ]] && continue
    log "removing stale $c"
    if [[ -w "$(dirname "$c")" ]]; then rm -f "$c"
    elif have sudo; then sudo rm -f "$c"
    else warn "cannot remove $c (no write perm, no sudo) — this may shadow $target"; continue
    fi
    removed=$((removed + 1))
  done
  [[ $removed -gt 0 ]] && log "cleaned $removed stale copy/copies"
  return 0
}

verify_single_on_path() {
  have mcp-jail || return 0
  local resolved target_real
  resolved="$(command -v mcp-jail)"
  target_real="$(cd "$(dirname "$BIN_DIR/mcp-jail")" 2>/dev/null && pwd -P)/mcp-jail"
  local resolved_real
  resolved_real="$(cd "$(dirname "$resolved")" 2>/dev/null && pwd -P)/$(basename "$resolved")"
  if [[ "$resolved_real" != "$target_real" ]]; then
    warn "PATH resolves mcp-jail to $resolved (expected $BIN_DIR/mcp-jail)"
    warn "another copy is shadowing the install — remove it or adjust PATH"
    return 1
  fi
  # Second check: more than one mcp-jail reachable via PATH.
  local count
  count="$(command -v -a mcp-jail 2>/dev/null | awk 'NF' | sort -u | wc -l | tr -d ' ')"
  if [[ "${count:-0}" -gt 1 ]]; then
    warn "multiple mcp-jail binaries on PATH:"
    command -v -a mcp-jail | awk 'NF' | sort -u | sed 's/^/  /' >&2
    return 1
  fi
  log "mcp-jail resolves to $resolved (clean)"
}

install_binary() {
  local target ext url sha_url
  target="$(detect_target)"
  ext="tar.gz"
  [[ "$target" == *windows* ]] && ext="zip"
  url="$(release_url "$target" "$ext")"
  sha_url="$url.sha256"
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp:-}"' EXIT

  log "fetching $(basename "$url")"
  curl -fsSL "$url" -o "$tmp/pkg.$ext" || die "download failed: $url"

  if curl -fsSL "$sha_url" -o "$tmp/pkg.$ext.sha256" 2>/dev/null; then
    log "verifying SHA-256"
    local expected actual
    expected="$(awk '{print $1}' "$tmp/pkg.$ext.sha256")"
    if   have shasum;   then actual="$(shasum -a 256 "$tmp/pkg.$ext" | awk '{print $1}')"
    elif have sha256sum; then actual="$(sha256sum "$tmp/pkg.$ext" | awk '{print $1}')"
    else warn "no sha tool; skipping integrity check"; actual="$expected"; fi
    [[ "$actual" == "$expected" ]] || die "SHA mismatch: expected $expected, got $actual"
  else
    warn "no .sha256 sidecar for $VERSION — continuing without integrity check"
  fi

  if [[ "$ext" == "tar.gz" ]]; then
    tar -xzf "$tmp/pkg.$ext" -C "$tmp"
  else
    have unzip || die "unzip required on Windows"
    unzip -q "$tmp/pkg.$ext" -d "$tmp"
  fi

  local staged="$tmp/mcp-jail-$target/mcp-jail"
  [[ "$target" == *windows* ]] && staged="$tmp/mcp-jail-$target/mcp-jail.exe"
  [[ -x "$staged" ]] || die "binary not found in archive"

  mkdir -p "$BIN_DIR"
  cleanup_stale_copies
  sudo_if_needed install -m 0755 "$staged" "$BIN_DIR/$(basename "$staged")"
  log "installed $(basename "$staged") → $BIN_DIR"
  verify_single_on_path || true
}

run_init() {
  if have mcp-jail; then
    log "running mcp-jail init"
    mcp-jail init || warn "mcp-jail init returned non-zero"
  else
    warn "mcp-jail not on PATH; add $BIN_DIR or restart your shell"
  fi
}

offer_wrap() {
  have mcp-jail || return 0
  if [[ "${MCP_JAIL_NO_WRAP:-}" == "1" ]]; then
    return 0
  fi

  echo
  if [[ -t 0 ]]; then
    mcp-jail wrap
  elif [[ -r /dev/tty && -w /dev/tty ]]; then
    mcp-jail wrap </dev/tty >/dev/tty
  else
    echo "mcp-jail found your MCP client configs and can protect them."
    echo "Because this shell has no interactive input, it did not modify them."
    echo "Run  \`mcp-jail wrap\`  in a terminal to review and apply."
  fi
}

main() {
  have curl || die "curl is required"
  install_binary
  export PATH="$BIN_DIR:$PATH"
  run_init
  offer_wrap
}

main "$@"
