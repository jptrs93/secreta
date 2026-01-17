#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_NAME="secreta"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
LAUNCH_AGENTS_DIR="${LAUNCH_AGENTS_DIR:-${HOME}/Library/LaunchAgents}"
PLIST_LABEL="com.secreta.agent"
PLIST_PATH="${LAUNCH_AGENTS_DIR}/${PLIST_LABEL}.plist"

mkdir -p "${INSTALL_DIR}"
mkdir -p "${LAUNCH_AGENTS_DIR}"

swift build -c release --package-path "${REPO_ROOT}"
install -m 755 "${REPO_ROOT}/.build/release/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"

cat > "${PLIST_PATH}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${BIN_NAME}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

launchctl unload "${PLIST_PATH}" >/dev/null 2>&1 || true
launchctl load "${PLIST_PATH}"

if [ -S "/tmp/secreta.sock" ]; then
    rm -f "/tmp/secreta.sock"
fi

launchctl kickstart -k "gui/$(id -u)/${PLIST_LABEL}" >/dev/null 2>&1 || true

echo "Installed ${BIN_NAME} to ${INSTALL_DIR} and loaded launch agent ${PLIST_LABEL}."
