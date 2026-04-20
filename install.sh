#!/usr/bin/env bash
# mcp-jail one-shot installer.
#
#   curl -fsSL https://raw.githubusercontent.com/lukeswitz/mcp-jail/main/install.sh | bash
#
# Detects OS/arch, downloads the signed release binary, verifies SHA-256,
# runs `mcp-jail init`. Idempotent. Re-run to upgrade.

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

install_binary() {
  local target ext tmp url sha_url
  target="$(detect_target)"
  ext="tar.gz"
  [[ "$target" == *windows* ]] && ext="zip"
  url="$(release_url "$target" "$ext")"
  sha_url="$url.sha256"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

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
  sudo_if_needed install -m 0755 "$staged" "$BIN_DIR/$(basename "$staged")"
  log "installed $(basename "$staged") → $BIN_DIR"
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
  log "scanning known MCP client configs"
  mcp-jail wrap --dry-run || return 0

  if [[ ! -t 0 ]]; then
    echo
    echo "(stdin not a TTY — run 'mcp-jail wrap' to apply, or 'mcp-jail unwrap' to revert)"
    return 0
  fi

  printf '\nApply this wrap plan now? [y/N] '
  local ans; read -r ans
  case "$ans" in
    y|Y|yes|YES) mcp-jail wrap --yes ;;
    *) log "skipped. run 'mcp-jail wrap' any time to apply." ;;
  esac
}

main() {
  log "mcp-jail installer (version=$VERSION, prefix=$PREFIX)"
  have curl || die "curl is required"
  install_binary
  export PATH="$BIN_DIR:$PATH"
  run_init
  offer_wrap
  cat <<EOF

──────────────────────────────────────────────────────────────────
  mcp-jail installed.

  Start your MCP client (Claude Code / Cursor / Windsurf / …).
  Each MCP server will block on first launch and print a
  fingerprint. Approve it once with:

    mcp-jail approve <fingerprint> --id <name>

  Then it runs sandboxed from then on.

    mcp-jail list    # approved servers
    mcp-jail logs    # decision audit
    mcp-jail upgrade # re-run the installer
──────────────────────────────────────────────────────────────────
EOF
}

main "$@"
