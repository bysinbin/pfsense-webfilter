#!/bin/sh
#
# PoseaFilter Threat Feed Updater for pfSense
# Invokes native PHP feed engine with HaGeZi & UT1 Capitole support
#

if [ -f "/usr/local/pkg/update_feeds.php" ]; then
    /usr/local/bin/php /usr/local/pkg/update_feeds.php "$@"
elif [ -f "$(dirname "$0")/../pfsense-pkg/usr/local/pkg/update_feeds.php" ]; then
    /usr/local/bin/php "$(dirname "$0")/../pfsense-pkg/usr/local/pkg/update_feeds.php" "$@"
else
    echo "[!] PoseaFilter feed engine not found."
    exit 1
fi
