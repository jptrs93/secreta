#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_NAME="secreta"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
APP_INSTALL_DIR="${APP_INSTALL_DIR:-${HOME}/Applications}"
APP_BUNDLE_NAME="SecretaDaemon.app"
APP_BUNDLE_PATH="${APP_INSTALL_DIR}/${APP_BUNDLE_NAME}"
APP_BUNDLE_EXECUTABLE="${APP_BUNDLE_PATH}/Contents/MacOS/${BIN_NAME}"
LAUNCH_AGENTS_DIR="${LAUNCH_AGENTS_DIR:-${HOME}/Library/LaunchAgents}"
PLIST_LABEL="com.secreta.agent"
PLIST_PATH="${LAUNCH_AGENTS_DIR}/${PLIST_LABEL}.plist"

mkdir -p "${INSTALL_DIR}"
mkdir -p "${APP_INSTALL_DIR}"
mkdir -p "${LAUNCH_AGENTS_DIR}"

swift build -c release --package-path "${REPO_ROOT}"
install -m 755 "${REPO_ROOT}/.build/release/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"

rm -rf "${APP_BUNDLE_PATH}"
mkdir -p "${APP_BUNDLE_PATH}/Contents/MacOS"
mkdir -p "${APP_BUNDLE_PATH}/Contents/Resources"
install -m 755 "${REPO_ROOT}/.build/release/${BIN_NAME}" "${APP_BUNDLE_EXECUTABLE}"
cat > "${APP_BUNDLE_PATH}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>${BIN_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>com.secreta.daemon</string>
    <key>CFBundleName</key>
    <string>SecretaDaemon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
EOF

cat > "${PLIST_PATH}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${APP_BUNDLE_EXECUTABLE}</string>
        <string>daemon</string>
        <string>run</string>
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
