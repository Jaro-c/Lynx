#!/usr/bin/env bash
# =============================================================================
# Helmly Installer
# =============================================================================
# Description: Master orchestrator for installing Helmly components.
#              Supports Dashboard and Agent installation.
#
# Usage:
#   git clone https://github.com/Glyndor/helmly.git
#   cd helmly && sudo bash install.sh
#
#   Piping this file into bash does not work and never did: it sources
#   scripts/detect-os.sh, execs internal/dashboard/setup-dashboard.sh for the
#   dashboard, and reads the menu choice from stdin, which a pipe has already
#   taken. It used to advertise the pipe in its own root-check error message.
#
# Requirements:
#   - Must be run as root
#   - Supported OS: Ubuntu, Debian, Fedora, CentOS, RHEL, Rocky, AlmaLinux, Arch, Manjaro
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# Colors
# -----------------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

export RED YELLOW GREEN CYAN BOLD RESET

# This script needs its own checkout: it sources scripts/detect-os.sh below
# and, for the dashboard, execs internal/dashboard/setup-dashboard.sh. Piped
# into bash there is no checkout and no BASH_SOURCE, and under `set -u` the
# old one-liner died on "unbound variable" at this line, before printing
# anything an operator could act on. A default value would not have helped;
# the missing thing is the directory, not the variable.
SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
if [[ -z "$SCRIPT_DIR" || ! -f "$SCRIPT_DIR/scripts/detect-os.sh" ]]; then
    echo -e "${RED}Error: this installer must run from a checkout, not from a pipe.${RESET}" >&2
    echo -e "${YELLOW}  git clone https://github.com/Glyndor/helmly.git${RESET}" >&2
    echo -e "${YELLOW}  cd helmly && sudo bash install.sh${RESET}" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Root check
# -----------------------------------------------------------------------------
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}Error: this script must be run as root.${RESET}" >&2
    echo -e "${YELLOW}Use: sudo bash install.sh${RESET}" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Detect OS
# -----------------------------------------------------------------------------
source "$SCRIPT_DIR/scripts/detect-os.sh"
detect_os
echo -e "${CYAN}Detected OS: ${BOLD}${OS_NAME}${RESET} — using ${BOLD}${PKG_MANAGER}${RESET}"
echo

# -----------------------------------------------------------------------------
# Agent installer: fetch and verify
# -----------------------------------------------------------------------------
# The agent lives in its own repository since the extraction, so its installer
# has to be fetched. It used to be fetched from a branch with no signature and
# no checksum, then run as root:
#
#     curl .../Glyndor/panel-agent/main/setup-agent.sh -o "$tmp"
#     chmod 700 "$tmp" && exec bash "$tmp"
#
# That file is the root of trust for an agent install. It carries the pinned
# Ed25519 release key that setup-agent.sh then uses to verify the agent binary
# it downloads, so whoever controlled the fetch chose which binary verified,
# and every signature check underneath it proved nothing.
# Glyndor/helmly-agent#181.
#
# What this buys, stated exactly, because it is narrower than "now it is
# signed": write access to Glyndor/helmly-agent alone no longer suffices to
# replace the installer, since the release signing key is a separate secret.
# It does NOT defend an operator against someone who can tamper with this
# file, and this file is distributed by cloning the repository.

# Baked-in base64 (unpadded) raw Ed25519 public keys, matching podup's
# install.sh so the two stay comparable. Slot 2 carries the next key during a
# make-before-break rotation and is empty otherwise; the signature passes if
# any populated slot validates. Retire a key by clearing its slot.
HELMLY_RELEASE_PUBKEY_B64="${HELMLY_RELEASE_PUBKEY_B64:-HFv7vg5FCY7YyKUDbJhaQSfB9SboJGSblJtFbLmLHzM}"
HELMLY_RELEASE_PUBKEY2_B64="${HELMLY_RELEASE_PUBKEY2_B64:-}"

# Pin a specific agent release with AGENT_VERSION=v2.0.1; the default tracks
# the latest. Either way the signature is what is trusted, not the URL.
AGENT_REPO="Glyndor/helmly-agent"
AGENT_VERSION="${AGENT_VERSION:-}"

# --proto '=https' only constrains the initial URL. GitHub release assets
# redirect to its CDN and that redirect is governed by --proto-redir, which
# needs its own pin or an unpinned redirect could fall back to http.
# --max-time is the version-independent backstop, since --max-filesize is only
# honoured by newer curl or when the server sends Content-Length.
_agent_download() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --max-filesize 209715200 --max-time 300 \
        -fsSL -o "$2" "$1"
}

# Verify an Ed25519 detached signature.
#   _agent_verify <sig-file> <data-file>
# 0 verified, 1 signature present but INVALID, 2 cannot verify (no python3 or
# no cryptography), 3 the configured key is malformed. 3 is kept distinct from
# 1 so a bad override is not reported as a tampered release.
_agent_verify() {
    local keys=()
    [[ -n "$HELMLY_RELEASE_PUBKEY_B64" ]]  && keys+=("$HELMLY_RELEASE_PUBKEY_B64")
    [[ -n "$HELMLY_RELEASE_PUBKEY2_B64" ]] && keys+=("$HELMLY_RELEASE_PUBKEY2_B64")
    [[ ${#keys[@]} -gt 0 ]] || return 2
    command -v python3 >/dev/null 2>&1 || return 2
    python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey" 2>/dev/null || return 2
    python3 - "$1" "$2" "${keys[@]}" <<'PYEOF'
import base64, binascii, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
sig = open(sys.argv[1], "rb").read()
data = open(sys.argv[2], "rb").read()
for slot, pubkey_b64 in enumerate(sys.argv[3:]):
    try:
        # Pad to a 4-byte boundary the way the key is stored unpadded.
        raw = base64.b64decode(pubkey_b64 + "=" * (-len(pubkey_b64) % 4))
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, data)
        sys.exit(0)
    except (binascii.Error, ValueError) as exc:
        print(f"configured release key slot {slot} is malformed: {exc}", file=sys.stderr)
        sys.exit(3)
    except InvalidSignature:
        continue
sys.exit(1)
PYEOF
    case $? in
        0) return 0 ;;
        3) return 3 ;;
        *) return 1 ;;
    esac
}

install_agent() {
    local base tmpdir f
    if [[ -n "$AGENT_VERSION" ]]; then
        base="https://github.com/${AGENT_REPO}/releases/download/${AGENT_VERSION}"
    else
        base="https://github.com/${AGENT_REPO}/releases/latest/download"
    fi

    tmpdir="$(mktemp -d /tmp/helmly-agent-install.XXXXXX)"
    chmod 700 "$tmpdir"
    trap 'rm -rf "$tmpdir"' EXIT

    # Both scripts, because setup-agent.sh execs update-agent.sh as a sibling
    # when the operator chooses Update on a host that already has the agent.
    # Fetching one file is what made that path die on "No such file or
    # directory". Glyndor/helmly-agent#187.
    echo -e "${CYAN}Fetching the agent installer from ${AGENT_REPO}...${RESET}"
    for f in setup-agent.sh setup-agent.sh.sig update-agent.sh update-agent.sh.sig; do
        if ! _agent_download "${base}/${f}" "${tmpdir}/${f}"; then
            echo -e "${RED}Failed to download ${base}/${f}${RESET}" >&2
            exit 1
        fi
    done

    echo -e "${CYAN}Verifying signatures against the pinned release key...${RESET}"
    for f in setup-agent.sh update-agent.sh; do
        local rc=0
        _agent_verify "${tmpdir}/${f}.sig" "${tmpdir}/${f}" || rc=$?
        case "$rc" in
            0) echo -e "${GREEN}  ${f} verified${RESET}" ;;
            1) echo -e "${RED}Signature verification FAILED for ${f} — refusing to run it.${RESET}" >&2
               exit 1 ;;
            2) echo -e "${RED}Cannot verify ${f}: python3 with the 'cryptography' package is required.${RESET}" >&2
               echo -e "${YELLOW}Install it and re-run. This installer will not execute an unverified script as root.${RESET}" >&2
               exit 1 ;;
            3) echo -e "${RED}The configured release key is malformed — check HELMLY_RELEASE_PUBKEY_B64.${RESET}" >&2
               exit 1 ;;
            *) echo -e "${RED}Unexpected verification status ${rc} for ${f}.${RESET}" >&2
               exit 1 ;;
        esac
    done

    chmod 700 "${tmpdir}/setup-agent.sh" "${tmpdir}/update-agent.sh"

    # The EXIT trap above covers the failure paths only, and that is all it
    # can cover: measured, bash runs EXIT traps on `exit 1` but not around
    # `exec`, neither when exec succeeds nor when it fails. So the directory
    # deliberately outlives a successful handover — setup-agent.sh execs
    # update-agent.sh out of it when the operator chooses Update — and a
    # failed exec leaks it, which is a temporary directory and not worth
    # more machinery than saying so.
    exec bash "${tmpdir}/setup-agent.sh"
}

# -----------------------------------------------------------------------------
# Menu
# -----------------------------------------------------------------------------
echo -e "${BOLD}${CYAN}Helmly Installer${RESET}"
echo -e "Select what to install:\n"
echo -e "  ${BOLD}1)${RESET} Dashboard — installs the Helmly dashboard on this VPS"
echo -e "  ${BOLD}2)${RESET} Agent     — installs the Helmly agent on this VPS"
echo

read -rp "Option [1/2] (default: 1): " OPTION
OPTION="${OPTION:-1}"

case "$OPTION" in
    1|2)
        if [[ "$OPTION" == "1" ]]; then
            echo -e "\n${GREEN}Starting Dashboard installation...${RESET}"
        else
            echo -e "\n${GREEN}Starting Agent installation...${RESET}"
        fi

        echo
        echo -e "${RED}${BOLD}IMPORTANT:${RESET} Before proceeding, make sure you have backed up:"
        echo -e "  ${YELLOW}•${RESET} Docker volumes and container data"
        echo -e "  ${YELLOW}•${RESET} Current firewall rules (ufw/iptables/nftables)"
        echo -e "  ${YELLOW}•${RESET} Existing Podman images, containers and volumes"
        echo -e "  ${YELLOW}•${RESET} Any other data you want to keep"
        echo -e "${RED}Everything will be permanently deleted or overwritten. We are not responsible for data loss.${RESET}"
        echo
        read -rp "I have made a backup and want to continue [y/N]: " BACKUP_CONFIRM
        BACKUP_CONFIRM="${BACKUP_CONFIRM:-N}"

        if [[ ! "$BACKUP_CONFIRM" =~ ^[yY]$ ]]; then
            echo -e "${RED}Installation cancelled. Please make a backup first.${RESET}"
            exit 0
        fi

        echo
        echo -e "${YELLOW}${BOLD}WARNING:${RESET} This installer will make the following changes to your system:"
        echo -e "  ${RED}✖${RESET} Remove Docker and all its components completely (including configs from all user home directories)"
        echo -e "  ${RED}✖${RESET} Remove ufw and iptables completely"
        echo -e "  ${GREEN}✔${RESET} Install Podman as container runtime"
        echo -e "  ${GREEN}✔${RESET} Install nftables as firewall"
        echo

        read -rp "Do you want to proceed? [y/N]: " CONFIRM
        CONFIRM="${CONFIRM:-N}"

        if [[ ! "$CONFIRM" =~ ^[yY]$ ]]; then
            echo -e "${RED}Installation cancelled.${RESET}"
            exit 0
        fi

        if [[ "$OPTION" == "1" ]]; then
            exec "$SCRIPT_DIR/internal/dashboard/setup-dashboard.sh"
        else
            install_agent
        fi
        ;;
    *)
        echo -e "${RED}Invalid option. Exiting.${RESET}" >&2
        exit 1
        ;;
esac
