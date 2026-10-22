#!/bin/sh
#
# PoseaFilter Threat Feed Updater for pfSense
# Automatically fetches USOM and UTM feeds, sorts them, and hot-reloads poseafilterd
#

FEED_TARGET="/var/etc/poseafilter/feeds.txt"
TMP_FEED="/tmp/poseafilter_feed_raw.txt"

echo "[*] Updating PoseaFilter Threat Feeds..."

# 1. Fetch USOM (Türkiye Ulusal Siber Olaylara Müdahale Merkezi Zararlı Bağlantılar)
echo "[*] Downloading USOM Blacklist..."
fetch -q -o - "https://www.usom.gov.tr/url-list.txt" 2>/dev/null | grep -v '^#' | sed -e 's/[[:space:]]*$//' > "${TMP_FEED}" || true

# 2. Append OISD Big or StevenBlack Malicious Domains (optional fallback)
echo "[*] Downloading StevenBlack Malware/Adware Domains..."
fetch -q -o - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" 2>/dev/null | \
    grep '^0.0.0.0 ' | awk '{print $2}' | grep -v '0.0.0.0' >> "${TMP_FEED}" || true

# 3. Sort, deduplicate, and prepare for binary search
echo "[*] Sorting and optimizing feed with unique binary sorting..."
sort -u "${TMP_FEED}" | grep -v '^$' > "${FEED_TARGET}"
rm -f "${TMP_FEED}"

TOTAL_DOMAINS=$(wc -l < "${FEED_TARGET}" | tr -d ' ')
echo "[+] Feed update completed: ${TOTAL_DOMAINS} domains ready in ${FEED_TARGET}"

# 4. Hot reload PoseaFilter daemon without dropping any connections
if [ -f "/var/run/poseafilter.pid" ]; then
    kill -HUP $(cat /var/run/poseafilter.pid) 2>/dev/null
    echo "[+] SIGHUP sent to poseafilterd (Zero-downtime hot reload complete)"
else
    killall -HUP poseafilterd 2>/dev/null || true
fi
