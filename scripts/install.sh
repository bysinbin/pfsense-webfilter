#!/bin/sh
#
# PoseaFilter pfSense Package Installer
# Installs the high-performance UTM Web Filter on pfSense CE / Plus
#

set -e

echo "=========================================================="
echo "  PoseaFilter for pfSense - UTM Web Filter Installation   "
echo "=========================================================="

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This script must be run as root."
    exit 1
fi

# Detect pfSense
if [ ! -f "/etc/inc/globals.inc" ]; then
    echo "[!] Warning: /etc/inc/globals.inc not found. Are you running inside pfSense?"
fi

# Determine source directory or download tarball if running piped via stdin
SCRIPT_DIR="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"

if [ ! -d "${SCRIPT_DIR}/pfsense-pkg" ] || [ ! -d "${SCRIPT_DIR}/daemon" ]; then
    echo "[*] Piped installer detected. Downloading repository files from GitHub..."
    TMP_DIR="/tmp/pfsense_wf_install"
    rm -rf "${TMP_DIR}"
    mkdir -p "${TMP_DIR}"

    ARCHIVE_URL="https://codeload.github.com/bysinbin/pfsense-webfilter/tar.gz/refs/heads/main"
    if ! fetch -q -o "${TMP_DIR}/main.tar.gz" "${ARCHIVE_URL}"; then
        echo "[*] Trying fallback GitHub URL..."
        fetch -q -o "${TMP_DIR}/main.tar.gz" "https://github.com/bysinbin/pfsense-webfilter/archive/refs/heads/main.tar.gz"
    fi

    tar -xzf "${TMP_DIR}/main.tar.gz" -C "${TMP_DIR}"
    SCRIPT_DIR="${TMP_DIR}/pfsense-webfilter-main"

    if [ ! -d "${SCRIPT_DIR}/pfsense-pkg" ]; then
        echo "[!] Error: Failed to unpack repository files."
        exit 1
    fi
    echo "[+] Repository files downloaded successfully."
fi

echo "[*] Step 1: Installing PoseaFilter Daemon for FreeBSD..."
if [ -f "${SCRIPT_DIR}/daemon/bin/poseafilterd" ]; then
    echo "[+] Found precompiled FreeBSD amd64 binary: ${SCRIPT_DIR}/daemon/bin/poseafilterd"
    cp "${SCRIPT_DIR}/daemon/bin/poseafilterd" /usr/local/sbin/poseafilterd
    chmod 755 /usr/local/sbin/poseafilterd
    echo "[+] Daemon successfully installed to /usr/local/sbin/poseafilterd"
elif [ -d "${SCRIPT_DIR}/daemon" ]; then
    cd "${SCRIPT_DIR}/daemon"

    CC_BIN=""
    if command -v clang >/dev/null 2>&1 || which clang >/dev/null 2>&1; then
        CC_BIN="clang"
    elif command -v cc >/dev/null 2>&1 || which cc >/dev/null 2>&1; then
        CC_BIN="cc"
    elif command -v gcc >/dev/null 2>&1 || which gcc >/dev/null 2>&1; then
        CC_BIN="gcc"
    fi

    if [ -z "${CC_BIN}" ]; then
        echo "[!] C compiler not found in base. Attempting to install clang via pkg-static..."
        pkg-static install -y clang || pkg install -y clang || true
        if command -v clang >/dev/null 2>&1 || which clang >/dev/null 2>&1; then
            CC_BIN="clang"
        elif command -v cc >/dev/null 2>&1 || which cc >/dev/null 2>&1; then
            CC_BIN="cc"
        fi
    fi

    if [ -n "${CC_BIN}" ]; then
        echo "[*] Compiling using: ${CC_BIN}..."
        make CC="${CC_BIN}" clean >/dev/null 2>&1 || true
        make CC="${CC_BIN}" -j$(sysctl -n hw.ncpu 2>/dev/null || echo 2)
        strip poseafilterd 2>/dev/null || true
        cp poseafilterd /usr/local/sbin/poseafilterd
        chmod 755 /usr/local/sbin/poseafilterd
        echo "[+] Daemon compiled and installed to /usr/local/sbin/poseafilterd"
    else
        echo "[!] Warning: No C compiler found and no precompiled binary available."
    fi
fi

echo "[*] Step 2: Creating Working Directories..."
mkdir -p /var/etc/poseafilter
mkdir -p /var/log/poseafilter
chmod 750 /var/etc/poseafilter
chmod 750 /var/log/poseafilter

echo "[*] Step 3: Installing FreeBSD rc.d Service..."
mkdir -p /usr/local/etc/rc.d
cp "${SCRIPT_DIR}/pfsense-pkg/etc/rc.d/poseafilter.sh" /usr/local/etc/rc.d/poseafilter.sh
chmod 755 /usr/local/etc/rc.d/poseafilter.sh

echo "[*] Step 4: Installing pfSense WebGUI Components..."
mkdir -p /usr/local/pkg
mkdir -p /usr/local/www
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/poseafilter.xml" /usr/local/pkg/poseafilter.xml
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/poseafilter.inc" /usr/local/pkg/poseafilter.inc
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/poseafilter_monitor.php" /usr/local/www/poseafilter_monitor.php
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/poseafilter_rules.php" /usr/local/www/poseafilter_rules.php
if [ -f "${SCRIPT_DIR}/scripts/update_feeds.sh" ]; then
    cp "${SCRIPT_DIR}/scripts/update_feeds.sh" /usr/local/pkg/update_feeds.sh
    chmod 755 /usr/local/pkg/update_feeds.sh
fi
chmod 644 /usr/local/pkg/poseafilter.*
chmod 644 /usr/local/www/poseafilter_*

echo "[*] Step 5: Registering Package in pfSense config.xml..."
php -r '
require_once("config.inc");
require_once("/usr/local/pkg/poseafilter.inc");

$pkg_found = false;
if (isset($config["installedpackages"]["package"])) {
    foreach ($config["installedpackages"]["package"] as $pkg) {
        if ($pkg["name"] == "poseafilter") {
            $pkg_found = true;
            break;
        }
    }
}

if (!$pkg_found) {
    $config["installedpackages"]["package"][] = [
        "name" => "poseafilter",
        "descr" => "Next-Gen UTM Web Filter for pfSense",
        "website" => "https://github.com/bysinbin/pfsense-webfilter",
        "version" => "1.0.0",
        "status" => "Stable",
        "configurationfile" => "poseafilter.xml",`r`n        "filter_rule_function" => "poseafilter_generate_rules"
    ];
    echo "[+] Registered PoseaFilter package in pfSense config.xml\n";
} else {
    echo "[*] PoseaFilter already registered in pfSense config.xml\n";
}

$menu_found = false;
if (isset($config["installedpackages"]["menu"])) {
    foreach ($config["installedpackages"]["menu"] as $m) {
        if ($m["name"] == "PoseaFilter") {
            $menu_found = true;
            break;
        }
    }
}
if (!$menu_found) {
    $config["installedpackages"]["menu"][] = [
        "name" => "PoseaFilter",
        "section" => "Services",
        "url" => "/pkg_edit.php?xml=poseafilter.xml"
    ];
    echo "[+] Registered PoseaFilter in Services menu\n";
}
write_config("Installed PoseaFilter package and menu");

poseafilter_install();
'

echo "[*] Step 6: Starting PoseaFilter Service..."
/usr/local/etc/rc.d/poseafilter.sh start || true

# Cleanup temporary download directory
if [ -d "/tmp/pfsense_wf_install" ]; then
    rm -rf "/tmp/pfsense_wf_install"
fi

echo "=========================================================="
echo "  [SUCCESS] PoseaFilter has been successfully installed!  "
echo "  Access in pfSense WebGUI: Services > PoseaFilter        "
echo "=========================================================="
