#!/bin/sh
#
# Build FreeBSD Package (.txz) for PoseaFilter pfSense Package
#

set -e

PKG_NAME="poseafilter"
PKG_VERSION="1.1.0"
STAGE_DIR="/tmp/poseafilter_stage"

echo "[*] Building PoseaFilter FreeBSD package v${PKG_VERSION}..."

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}/usr/local/sbin"
mkdir -p "${STAGE_DIR}/usr/local/bin"
mkdir -p "${STAGE_DIR}/usr/local/etc/rc.d"
mkdir -p "${STAGE_DIR}/usr/local/etc/newsyslog.conf.d"
mkdir -p "${STAGE_DIR}/usr/local/pkg"
mkdir -p "${STAGE_DIR}/usr/local/www"
mkdir -p "${STAGE_DIR}/var/etc/poseafilter/categories"
mkdir -p "${STAGE_DIR}/var/log/poseafilter"

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Compile
cd "${SCRIPT_DIR}/daemon"
make clean
make

cp "${SCRIPT_DIR}/daemon/poseafilterd" "${STAGE_DIR}/usr/local/sbin/"
if [ -f "${SCRIPT_DIR}/pfsense-pkg/usr/local/bin/poseactl" ]; then
    cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/bin/poseactl" "${STAGE_DIR}/usr/local/bin/"
    chmod 755 "${STAGE_DIR}/usr/local/bin/poseactl"
fi
cp "${SCRIPT_DIR}/pfsense-pkg/etc/rc.d/poseafilter.sh" "${STAGE_DIR}/usr/local/etc/rc.d/"
if [ -f "${SCRIPT_DIR}/pfsense-pkg/etc/newsyslog.conf.d/poseafilter.conf" ]; then
    cp "${SCRIPT_DIR}/pfsense-pkg/etc/newsyslog.conf.d/poseafilter.conf" "${STAGE_DIR}/usr/local/etc/newsyslog.conf.d/"
fi
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/"* "${STAGE_DIR}/usr/local/pkg/"
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/"* "${STAGE_DIR}/usr/local/www/"

# Generate FreeBSD +MANIFEST
cat <<EOF > "${STAGE_DIR}/+MANIFEST"
name: ${PKG_NAME}
version: "${PKG_VERSION}"
origin: net-mgmt/${PKG_NAME}
comment: "Next-Gen UTM Web Filter for pfSense"
desc: "PoseaFilter brings granular client-based UTM Web and Content Filtering to pfSense, replacing deprecated Squid/SquidGuard with high-speed C daemon, DNS Sinkhole, TLS SNI, and PF packet filter integration."
maintainer: "bysinbin"
www: "https://github.com/bysinbin/pfsense-webfilter"
prefix: /
EOF

cd "${STAGE_DIR}"
pkg create -m "${STAGE_DIR}" -r "${STAGE_DIR}" -o "${SCRIPT_DIR}"
echo "[+] Package built: ${SCRIPT_DIR}/${PKG_NAME}-${PKG_VERSION}.txz"

rm -rf "${STAGE_DIR}"
