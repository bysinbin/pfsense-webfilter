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

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] Step 1: Compiling PoseaFilter Daemon for FreeBSD..."
if [ -d "${SCRIPT_DIR}/daemon" ]; then
    cd "${SCRIPT_DIR}/daemon"
    make clean >/dev/null 2>&1 || true
    make -j$(sysctl -n hw.ncpu 2>/dev/null || echo 2)
    cp poseafilterd /usr/local/sbin/poseafilterd
    chmod 755 /usr/local/sbin/poseafilterd
    echo "[+] Daemon compiled and installed to /usr/local/sbin/poseafilterd"
fi

echo "[*] Step 2: Creating Working Directories..."
mkdir -p /var/etc/poseafilter
mkdir -p /var/log/poseafilter
chmod 750 /var/etc/poseafilter
chmod 750 /var/log/poseafilter

echo "[*] Step 3: Installing FreeBSD rc.d Service..."
cp "${SCRIPT_DIR}/pfsense-pkg/etc/rc.d/poseafilter.sh" /usr/local/etc/rc.d/poseafilter.sh
chmod 755 /usr/local/etc/rc.d/poseafilter.sh

echo "[*] Step 4: Installing pfSense WebGUI Components..."
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/poseafilter.xml" /usr/local/pkg/poseafilter.xml
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/poseafilter.inc" /usr/local/pkg/poseafilter.inc
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/poseafilter_monitor.php" /usr/local/www/poseafilter_monitor.php
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/poseafilter_rules.php" /usr/local/www/poseafilter_rules.php
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
        "configurationfile" => "poseafilter.xml"
    ];
    write_config("Installed PoseaFilter package");
    echo "[+] Registered PoseaFilter in pfSense config.xml\n";
} else {
    echo "[*] PoseaFilter already registered in pfSense config.xml\n";
}

poseafilter_install();
'

echo "[*] Step 6: Starting PoseaFilter Service..."
/usr/local/etc/rc.d/poseafilter.sh start || true

echo "=========================================================="
echo "  [SUCCESS] PoseaFilter has been successfully installed!  "
echo "  Access in pfSense WebGUI: Services > PoseaFilter        "
echo "=========================================================="
