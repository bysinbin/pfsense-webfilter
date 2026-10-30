import sys
import paramiko

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('185.189.54.89', port=422, username='admin', password='K@dir571.1453', timeout=8)

cmd = """
/etc/rc.php-fpm_restart
sleep 2
ls -la /var/run/php-fpm.*
curl -k -I https://127.0.0.1:448/index.php
"""

stdin, stdout, stderr = ssh.exec_command(cmd)
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print("STDERR:\n", err)
ssh.close()
