#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoseaFilter Automated Remote Deployment Tool
Deploys PoseaFilter (v1.1.0) to pfSense firewall at 185.189.54.89
"""

import sys
import os
import time
import paramiko

# Server Credentials
HOST = "185.189.54.89"
PORT = 422
USER = "admin"
PASS = "K@dir571.1453"

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PKG_DIR = os.path.join(BASE_DIR, "pfsense-pkg")
DAEMON_BIN = os.path.join(BASE_DIR, "daemon", "bin", "poseafilterd")

FILES_TO_DEPLOY = [
    # Package PHP/INC/XML
    (os.path.join(PKG_DIR, "usr", "local", "pkg", "poseafilter.inc"), "/usr/local/pkg/poseafilter.inc", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "pkg", "poseafilter.xml"), "/usr/local/pkg/poseafilter.xml", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "pkg", "poseafilter_notify.inc"), "/usr/local/pkg/poseafilter_notify.inc", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "pkg", "update_feeds.php"), "/usr/local/pkg/update_feeds.php", 0o755),

    # WebGUI Pages & Widgets
    (os.path.join(PKG_DIR, "usr", "local", "www", "poseafilter_block.php"), "/usr/local/www/poseafilter_block.php", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "www", "poseafilter_blockpage.php"), "/usr/local/www/poseafilter_blockpage.php", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "www", "poseafilter_feeds.php"), "/usr/local/www/poseafilter_feeds.php", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "www", "poseafilter_monitor.php"), "/usr/local/www/poseafilter_monitor.php", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "www", "poseafilter_rules.php"), "/usr/local/www/poseafilter_rules.php", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "www", "posea_suite_backup.php"), "/usr/local/www/posea_suite_backup.php", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "www", "widgets", "include", "poseafilter.inc"), "/usr/local/www/widgets/include/poseafilter.inc", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "www", "widgets", "include", "posea_suite.inc"), "/usr/local/www/widgets/include/posea_suite.inc", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "www", "widgets", "widgets", "poseafilter.widget.php"), "/usr/local/www/widgets/widgets/poseafilter.widget.php", 0o644),
    (os.path.join(PKG_DIR, "usr", "local", "www", "widgets", "widgets", "posea_suite.widget.php"), "/usr/local/www/widgets/widgets/posea_suite.widget.php", 0o644),

    # CLI & Init Scripts
    (os.path.join(PKG_DIR, "usr", "local", "bin", "poseactl"), "/usr/local/bin/poseactl", 0o755),
    (os.path.join(PKG_DIR, "etc", "rc.d", "poseafilter.sh"), "/usr/local/etc/rc.d/poseafilter.sh", 0o755),
    (os.path.join(PKG_DIR, "etc", "newsyslog.conf.d", "poseafilter.conf"), "/etc/newsyslog.conf.d/poseafilter.conf", 0o644),
]

DIRS_TO_CREATE = [
    "/usr/local/pkg",
    "/usr/local/www",
    "/usr/local/www/widgets/include",
    "/usr/local/www/widgets/widgets",
    "/usr/local/bin",
    "/usr/local/etc/rc.d",
    "/etc/newsyslog.conf.d",
    "/var/etc/poseafilter/categories",
    "/var/log/poseafilter"
]

def main():
    print(f"[*] Connecting to {HOST}:{PORT} as {USER}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, port=PORT, username=USER, password=PASS, timeout=15)
    print("[+] SSH connection established.")

    sftp = ssh.open_sftp()

    # 1. Create directories
    print("[*] Ensuring remote directories exist...")
    for d in DIRS_TO_CREATE:
        stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {d}")
        stdout.read()

    # 2. Upload daemon binary if present
    if os.path.exists(DAEMON_BIN):
        print(f"[*] Uploading binary {DAEMON_BIN} -> /usr/local/sbin/poseafilterd...")
        sftp.put(DAEMON_BIN, "/usr/local/sbin/poseafilterd")
        sftp.chmod("/usr/local/sbin/poseafilterd", 0o755)
        print("[+] Binary deployed successfully.")
    else:
        print("[!] Note: daemon binary not found locally, skipping binary upload.")

    # 3. Upload package files
    print("[*] Uploading package PHP/XML/CLI/Conf files...")
    for local_p, remote_p, mode in FILES_TO_DEPLOY:
        if not os.path.exists(local_p):
            print(f"[!] Warning: local file {local_p} missing!")
            continue
        print(f"  -> Uploading {os.path.basename(local_p)} to {remote_p}")
        sftp.put(local_p, remote_p)
        sftp.chmod(remote_p, mode)

    sftp.close()
    print("[+] All files uploaded.")

    # 4. Verify syntax of uploaded PHP files
    print("\n[*] Verifying PHP syntax on remote pfSense...")
    cmd_lint = """
    for f in /usr/local/pkg/poseafilter.inc \
             /usr/local/pkg/poseafilter_notify.inc \
             /usr/local/pkg/update_feeds.php \
             /usr/local/www/poseafilter_block.php \
             /usr/local/www/poseafilter_blockpage.php \
             /usr/local/www/poseafilter_feeds.php \
             /usr/local/www/poseafilter_monitor.php \
             /usr/local/www/poseafilter_rules.php \
             /usr/local/bin/poseactl; do
        php -l "$f"
    done
    """
    stdin, stdout, stderr = ssh.exec_command(cmd_lint)
    lint_out = stdout.read().decode().strip()
    print(lint_out)
    if "Errors parsing" in lint_out or "Fatal error" in lint_out:
        print("[!] Remote PHP syntax error detected! Aborting.")
        ssh.close()
        sys.exit(1)

    # 5. Sync pfSense rules and restart PoseaFilter
    print("\n[*] Synchronizing pfSense filter rules & restarting poseafilter...")
    cmd_restart = """
    # Sync rules and generate PF tables
    php -r '
    require_once("/etc/inc/config.inc");
    require_once("/etc/inc/filter.inc");
    require_once("/usr/local/pkg/poseafilter.inc");
    poseafilter_sync_rules();
    filter_configure();
    '
    
    # Restart daemon
    /usr/local/etc/rc.d/poseafilter.sh restart
    sleep 2
    """
    stdin, stdout, stderr = ssh.exec_command(cmd_restart)
    print(stdout.read().decode())
    err = stderr.read().decode()
    if err:
        print("STDERR:\n", err)

    # 6. Verify Service Status & CLI Tests
    print("\n[*] Verifying Service Status via poseactl...")
    stdin, stdout, stderr = ssh.exec_command("/usr/local/bin/poseactl status; /usr/local/bin/poseactl stats")
    print(stdout.read().decode())

    # 7. Test DNS Resolution locally on the firewall
    print("[*] Testing local DNS query on 127.0.0.1:5353...")
    stdin, stdout, stderr = ssh.exec_command("sockstat -4 -l | grep 5353; drill @127.0.0.1 -p 5353 google.com 2>/dev/null || dig @127.0.0.1 -p 5353 google.com")
    print(stdout.read().decode())

    ssh.close()
    print("\n[+] DEPLOYMENT COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
