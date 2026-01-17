#!/bin/bash
set -euo pipefail

BIN_NAME="secreta"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
LAUNCH_AGENTS_DIR="${LAUNCH_AGENTS_DIR:-${HOME}/Library/LaunchAgents}"
PLIST_LABEL="com.secreta.agent"
PLIST_PATH="${LAUNCH_AGENTS_DIR}/${PLIST_LABEL}.plist"

if [ -f "${PLIST_PATH}" ]; then
    launchctl unload "${PLIST_PATH}" >/dev/null 2>&1 || true
    rm -f "${PLIST_PATH}"
fi

if [ -S "/tmp/secreta.sock" ]; then
    rm -f "/tmp/secreta.sock"
fi

if [ -f "${INSTALL_DIR}/${BIN_NAME}" ]; then
    rm -f "${INSTALL_DIR}/${BIN_NAME}"
fi

echo "Removed ${BIN_NAME} and launch agent ${PLIST_LABEL}."
