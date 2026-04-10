#!/bin/sh
# vault installer — https://github.com/niteshdangi/vault
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/niteshdangi/vault/main/install.sh | sh
#
# Environment variables:
#   VAULT_INSTALL_DIR  — override install directory (default: ~/.local/bin or /usr/local/bin with sudo)
#
# Supports Linux and macOS on x86_64 and aarch64/arm64.

set -e

REPO="niteshdangi/vault"
BINARY="vault"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"
GITHUB_DL="https://github.com/${REPO}/releases/download"

# --- Formatting helpers -------------------------------------------------------

bold=""
reset=""
red=""
green=""
cyan=""
if [ -t 1 ]; then
    bold="\033[1m"
    reset="\033[0m"
    red="\033[31m"
    green="\033[32m"
    cyan="\033[36m"
fi

info()  { printf "${bold}${cyan}info${reset}: %s\n" "$1"; }
ok()    { printf "${bold}${green}  ok${reset}: %s\n" "$1"; }
err()   { printf "${bold}${red}error${reset}: %s\n" "$1" >&2; }
warn()  { printf "${bold}${red} warn${reset}: %s\n" "$1" >&2; }

# --- Platform detection -------------------------------------------------------

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        *)       err "Unsupported operating system: $(uname -s)"; exit 1 ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)       echo "x86_64" ;;
        aarch64|arm64)      echo "aarch64" ;;
        *)                  err "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
}

# --- Download helpers ---------------------------------------------------------

has_cmd() { command -v "$1" >/dev/null 2>&1; }

download() {
    # $1 = url, $2 = output file
    if has_cmd curl; then
        curl -fsSL "$1" -o "$2"
    elif has_cmd wget; then
        wget -qO "$2" "$1"
    else
        err "Neither curl nor wget found. Please install one and try again."
        exit 1
    fi
}

fetch_url() {
    # $1 = url — prints to stdout
    if has_cmd curl; then
        curl -fsSL "$1"
    elif has_cmd wget; then
        wget -qO- "$1"
    else
        err "Neither curl nor wget found. Please install one and try again."
        exit 1
    fi
}

# --- Checksum verification ----------------------------------------------------

verify_checksum() {
    # $1 = checksums file, $2 = binary file, $3 = expected filename in checksums
    if has_cmd sha256sum; then
        expected=$(grep "$3" "$1" | awk '{print $1}')
        actual=$(sha256sum "$2" | awk '{print $1}')
    elif has_cmd shasum; then
        expected=$(grep "$3" "$1" | awk '{print $1}')
        actual=$(shasum -a 256 "$2" | awk '{print $1}')
    else
        warn "Neither sha256sum nor shasum found — skipping checksum verification"
        return 0
    fi

    if [ -z "$expected" ]; then
        warn "No checksum entry found for $3 — skipping verification"
        return 0
    fi

    if [ "$expected" != "$actual" ]; then
        err "Checksum mismatch!"
        err "  Expected: $expected"
        err "  Actual:   $actual"
        err "The downloaded binary may be corrupted or tampered with."
        return 1
    fi

    ok "Checksum verified (sha256)"
}

# --- Install directory --------------------------------------------------------

determine_install_dir() {
    if [ -n "$VAULT_INSTALL_DIR" ]; then
        echo "$VAULT_INSTALL_DIR"
    elif [ "$(id -u)" -eq 0 ]; then
        echo "/usr/local/bin"
    else
        echo "${HOME}/.local/bin"
    fi
}

# --- Main ---------------------------------------------------------------------

main() {
    printf "\n"
    printf "${bold}  vault installer${reset}\n"
    printf "  https://github.com/${REPO}\n"
    printf "\n"

    # Detect platform
    OS=$(detect_os)
    ARCH=$(detect_arch)
    info "Detected platform: ${OS} ${ARCH}"

    # Determine asset name
    ASSET="${BINARY}-${OS}-${ARCH}"

    # Fetch latest release tag
    info "Fetching latest release..."
    RELEASE_JSON=$(fetch_url "$GITHUB_API") || {
        err "Failed to fetch release info from GitHub."
        err "Check your internet connection and try again."
        exit 1
    }

    # Parse tag — works with basic tools, no jq required
    TAG=$(printf '%s' "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    if [ -z "$TAG" ]; then
        err "Could not determine latest release tag."
        err "Visit https://github.com/${REPO}/releases to download manually."
        exit 1
    fi
    info "Latest release: ${TAG}"

    # Build download URLs
    BINARY_URL="${GITHUB_DL}/${TAG}/${ASSET}"
    CHECKSUMS_URL="${GITHUB_DL}/${TAG}/checksums-sha256.txt"

    # Create temp directory
    TMP_DIR=$(mktemp -d) || { err "Failed to create temp directory"; exit 1; }
    trap 'rm -rf "$TMP_DIR"' EXIT

    # Download binary
    info "Downloading ${ASSET}..."
    download "$BINARY_URL" "${TMP_DIR}/${ASSET}" || {
        err "Failed to download binary."
        err "URL: ${BINARY_URL}"
        err "The release may not have a binary for your platform (${OS}/${ARCH})."
        exit 1
    }
    ok "Downloaded ${ASSET}"

    # Download and verify checksum
    info "Verifying checksum..."
    if download "$CHECKSUMS_URL" "${TMP_DIR}/checksums-sha256.txt" 2>/dev/null; then
        verify_checksum "${TMP_DIR}/checksums-sha256.txt" "${TMP_DIR}/${ASSET}" "$ASSET" || exit 1
    else
        warn "Checksums file not available — skipping verification"
    fi

    # Install
    INSTALL_DIR=$(determine_install_dir)
    info "Installing to ${INSTALL_DIR}..."

    if [ ! -d "$INSTALL_DIR" ]; then
        mkdir -p "$INSTALL_DIR" || {
            err "Failed to create directory: ${INSTALL_DIR}"
            err "Try: VAULT_INSTALL_DIR=/path/to/dir sh install.sh"
            exit 1
        }
    fi

    cp "${TMP_DIR}/${ASSET}" "${INSTALL_DIR}/${BINARY}" || {
        err "Failed to copy binary to ${INSTALL_DIR}/${BINARY}"
        err "You may need to run with sudo or set VAULT_INSTALL_DIR."
        exit 1
    }
    chmod +x "${INSTALL_DIR}/${BINARY}"
    ok "Installed vault to ${INSTALL_DIR}/${BINARY}"

    # Verify installation
    if "${INSTALL_DIR}/${BINARY}" --help >/dev/null 2>&1; then
        ok "vault is working"
    else
        warn "vault binary installed but --help check failed"
        warn "You may need to check platform compatibility"
    fi

    # PATH check
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            printf "\n"
            warn "${INSTALL_DIR} is not in your PATH"
            printf "\n"
            printf "  Add it to your shell profile:\n"
            printf "\n"
            printf "    ${bold}# bash${reset}\n"
            printf "    echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc\n" "$INSTALL_DIR"
            printf "\n"
            printf "    ${bold}# zsh${reset}\n"
            printf "    echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc\n" "$INSTALL_DIR"
            printf "\n"
            printf "    ${bold}# fish${reset}\n"
            printf "    fish_add_path %s\n" "$INSTALL_DIR"
            printf "\n"
            printf "  Then restart your shell or run:\n"
            printf "\n"
            printf "    export PATH=\"%s:\$PATH\"\n" "$INSTALL_DIR"
            printf "\n"
            ;;
    esac

    # Done
    printf "\n"
    printf "  ${bold}${green}vault ${TAG} has been installed!${reset}\n"
    printf "\n"
    printf "  Get started:\n"
    printf "\n"
    printf "    ${bold}vault init${reset}          Initialize a new vault\n"
    printf "    ${bold}vault set KEY val${reset}   Store a secret\n"
    printf "    ${bold}vault get KEY${reset}       Retrieve a secret\n"
    printf "    ${bold}vault --help${reset}        Show all commands\n"
    printf "\n"
}

main "$@"
