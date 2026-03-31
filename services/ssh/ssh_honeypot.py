# services/ssh/ssh_honeypot.py
#
# Behaviour-Aware SSH Honeypot
# Real SSH protocol, fake shell, rich filesystem with Easter eggs
# Every interaction is logged to the Core API for behaviour analysis

import socket
import threading
import paramiko
import time
import requests
import random
import os

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

CORE_EVENT_ENDPOINT = "http://host.docker.internal:5001/event"
SSH_PORT = 2222

# Believable hostname — does NOT say "honeypot"
HOSTNAME = "prod-web-01"

# ─────────────────────────────────────────────
# PERSISTENT HOST KEY
# Saved to disk so the fingerprint stays the same
# across container restarts — no more scary warnings
# ─────────────────────────────────────────────

# Kill chain password — must match LEAKED_SSH_PASS in services/http/app.py
KILL_CHAIN_PASSWORD = "Adm1n#2024"
KILL_CHAIN_USER = "admin"

def load_or_generate_host_key(path: str) -> paramiko.RSAKey:
    """Load existing host key or generate and save a new one."""
    os.makedirs(os.path.dirname(path), exist_ok=True)

    if os.path.exists(path):
        print(f"[SSH] Loading existing host key from {path}")
        return paramiko.RSAKey(filename=path)

    print(f"[SSH] Generating new host key and saving to {path}")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key

HOST_KEY = load_or_generate_host_key(KEY_PATH)

# ─────────────────────────────────────────────
# FAKE USERS
# username → home directory
# ─────────────────────────────────────────────

FAKE_USERS = {
    "root":    "/root",
    "admin":   "/home/admin",
    "ubuntu":  "/home/ubuntu",
    "deploy":  "/home/deploy",
    "test":    "/home/test",
}

# ─────────────────────────────────────────────
# FAKE FILESYSTEM
# Directory structure with file listings
# ─────────────────────────────────────────────

FAKE_FS = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "run", "srv", "tmp", "usr", "var"],
    "/bin": ["bash", "cat", "cp", "echo", "grep", "ls", "mkdir", "mv", "ps", "pwd", "rm", "sh", "uname"],
    "/etc": ["crontab", "environment", "hostname", "hosts", "issue", "os-release", "passwd", "shadow", "ssh", "sudoers"],
    "/etc/ssh": ["sshd_config", "ssh_host_rsa_key", "ssh_host_rsa_key.pub"],
    "/home": ["admin", "ubuntu", "deploy", "test"],
    "/home/admin": [".bash_history", ".bashrc", ".env", ".profile", ".ssh", "backup.sh", "notes.txt"],
    "/home/admin/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts"],
    "/home/ubuntu": [".bash_history", ".bashrc", ".profile", "app", "startup.sh"],
    "/home/ubuntu/app": ["config.py", "requirements.txt", "run.py", "settings.json"],
    "/home/deploy": [".bash_history", ".bashrc", "deploy.sh", "rollback.sh"],
    "/home/test": ["readme.txt"],
    "/root": [".bash_history", ".bashrc", ".profile", ".ssh", "secret", ".viminfo"],
    "/root/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub"],
    "/root/secret": ["credentials.txt", "db_backup.sql", "internal_ips.txt"],
    "/var": ["backups", "log", "mail", "opt", "spool", "tmp", "www"],
    "/var/log": ["auth.log", "dpkg.log", "kern.log", "syslog", "ufw.log"],
    "/var/www": ["html"],
    "/var/www/html": ["index.html", "wp-config.php", ".htaccess"],
    "/proc": ["cpuinfo", "meminfo", "version"],
    "/tmp": [],
    "/opt": ["monitoring", "scripts"],
    "/opt/scripts": ["backup.sh", "cleanup.sh", "healthcheck.sh"],
}

# ─────────────────────────────────────────────
# FAKE FILE CONTENTS
# Easter eggs — keep attacker engaged and log high-value interactions
# ─────────────────────────────────────────────

FAKE_FILE_CONTENTS = {

    # ── ROOT EASTER EGGS ──────────────────────

    "/root/secret/credentials.txt": """\
# Internal Service Credentials
# Last updated: 2024-11-03 by admin

[database]
host     = prod-db-01.internal
port     = 5432
user     = db_admin
password = Pr0d@dm1n#2024!

[redis]
host     = cache-01.internal
port     = 6379
password = r3d1s_s3cr3t_k3y

[aws]
access_key_id     = AKIAIOSFODNN7EXAMPLE
secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region            = us-east-1

[monitoring]
grafana_admin = admin
grafana_pass  = Gr@fan@2024
""",

    "/root/secret/internal_ips.txt": """\
# Internal Network Map — DO NOT SHARE
prod-web-01     10.0.1.10   (this server)
prod-web-02     10.0.1.11
prod-db-01      10.0.1.20   (PostgreSQL primary)
prod-db-02      10.0.1.21   (PostgreSQL replica)
cache-01        10.0.1.30   (Redis)
monitoring-01   10.0.1.40   (Grafana/Prometheus)
vpn-gw          10.0.1.1    (OpenVPN gateway)
""",

    "/root/secret/db_backup.sql": """\
-- PostgreSQL database dump
-- Dumped from database version 14.5
-- Database: production

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    email VARCHAR(100),
    password_hash VARCHAR(255),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO users VALUES (1,'admin','admin@company.internal','$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBdXwtGJ3FHQBS','superadmin','2023-01-15 09:00:00');
INSERT INTO users VALUES (2,'john.doe','john@company.internal','$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36X7l1ukWHF5CQmEv8yIiwG','admin','2023-03-22 14:30:00');
INSERT INTO users VALUES (3,'deploy','deploy@company.internal','$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lHwy','deploy','2023-06-01 08:00:00');
""",

    # ── ROOT BASH HISTORY ─────────────────────
    # Gives attacker breadcrumbs to follow

    "/root/.bash_history": """\
ls -la /root/secret
cat /root/secret/credentials.txt
mysql -h prod-db-01.internal -u db_admin -p
ssh deploy@prod-db-01.internal
scp /root/secret/db_backup.sql admin@10.0.1.40:/tmp/
aws s3 ls s3://company-backups/
aws s3 cp /root/secret/db_backup.sql s3://company-backups/prod/
systemctl status nginx
tail -f /var/log/auth.log
""",

    # ── ADMIN HOME ────────────────────────────

    "/home/admin/notes.txt": """\
TODO:
- migrate prod-db-01 to new instance by end of month
- rotate AWS keys (overdue since Oct)
- set up 2FA for all admin accounts
- check why backup.sh is failing on Tuesdays

IMPORTANT:
SSH key for prod-db-01 is in /root/.ssh/id_rsa
DO NOT store credentials in .env — use vault!
(yes I know I put them in .env anyway, will fix)
""",

    "/home/admin/.env": """\
# App environment — production
APP_ENV=production
APP_SECRET_KEY=s3cr3t_k3y_ch@ng3_m3_pl3as3
DB_HOST=prod-db-01.internal
DB_PORT=5432
DB_NAME=production
DB_USER=app_user
DB_PASS=AppUs3r#P@ss2024
REDIS_URL=redis://:r3d1s_s3cr3t_k3y@cache-01.internal:6379/0
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_FAKEKEY1234567890abcdefghijklmno
""",

    "/home/admin/backup.sh": """\
#!/bin/bash
# Daily backup script — runs via cron at 02:00
set -e

BACKUP_DIR="/var/backups"
DB_HOST="prod-db-01.internal"
DB_USER="db_admin"
DB_PASS="Pr0d@dm1n#2024!"
S3_BUCKET="s3://company-backups/prod"

echo "[$(date)] Starting backup..."
pg_dump -h $DB_HOST -U $DB_USER production > $BACKUP_DIR/prod_$(date +%Y%m%d).sql
aws s3 cp $BACKUP_DIR/prod_$(date +%Y%m%d).sql $S3_BUCKET/
echo "[$(date)] Backup complete."
""",

    "/home/admin/.bash_history": """\
sudo su
cd /root/secret
cat credentials.txt
ssh root@prod-db-01.internal
mysql -h prod-db-01.internal -u db_admin -pPr0d@dm1n#2024!
nano .env
cat .env
./backup.sh
tail -100 /var/log/auth.log
""",

    "/home/admin/.ssh/authorized_keys": """\
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3vJ8pLmNk7xQzF9R2wT4yHuG6dK1oP5sM0eN3aB8cV7iL2jW9qE4tY6mX0rZ5fD1gS3hA2kN8pQ7vR4uI6lO9yT1wE5jM0bK3xC7dF2gH4nP8qS1tV6rY9iL0oM3eN5aB2cW7jK4pQ8uR1vT6xZ0fD3gH5nS2tY7mX1wE4jM9bK6xC0dF2gH3nP7qS4tV8rY1iL2oM5eN9aB6cW0jK7pQ4uR3vT8xZ2fD7gH1nS6tY0mX3wE8jM2bK9xC4dF6gH7nP0qS3tV2rY5iL4oM7eN1aB8cW3jK0pQ6uR9vT4xZ6fD1gH3nS8tY2mX7wE0jM4bK1xC8dF4gH9nP2qS7tV0rY3iL6oM9eN3aB0cW5jK2pQ8uR1vT6xZ4fD9gH7nS0tY4mX1wE2 admin@workstation
""",

    # ── UBUNTU APP ────────────────────────────

    "/home/ubuntu/app/settings.json": """\
{
  "environment": "production",
  "debug": false,
  "database": {
    "host": "prod-db-01.internal",
    "port": 5432,
    "name": "production",
    "user": "app_user",
    "password": "AppUs3r#P@ss2024"
  },
  "jwt_secret": "jwt_s3cr3t_k3y_n3v3r_sh@r3",
  "allowed_hosts": ["prod-web-01.internal", "10.0.1.10"]
}
""",

    "/home/ubuntu/app/config.py": """\
import os

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://app_user:AppUs3r#P@ss2024@prod-db-01.internal:5432/production"
)
SECRET_KEY = os.environ.get("APP_SECRET_KEY", "s3cr3t_k3y_ch@ng3_m3_pl3as3")
DEBUG = False
""",

    # ── SYSTEM FILES ──────────────────────────

    "/etc/passwd": """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:admin,,,:/home/admin:/bin/bash
ubuntu:x:1001:1001:ubuntu,,,:/home/ubuntu:/bin/bash
deploy:x:1002:1002:deploy,,,:/home/deploy:/bin/bash
test:x:1003:1003::/home/test:/bin/sh
""",

    "/etc/hosts": """\
127.0.0.1       localhost
127.0.1.1       prod-web-01

# Internal network
10.0.1.10       prod-web-01 prod-web-01.internal
10.0.1.11       prod-web-02 prod-web-02.internal
10.0.1.20       prod-db-01  prod-db-01.internal
10.0.1.21       prod-db-02  prod-db-02.internal
10.0.1.30       cache-01    cache-01.internal
10.0.1.40       monitoring-01 monitoring-01.internal
10.0.1.1        vpn-gw
""",

    "/etc/issue": "Ubuntu 20.04.6 LTS \\n \\l\n",

    "/var/log/auth.log": """\
Nov  3 02:15:01 prod-web-01 sshd[2341]: Accepted password for admin from 192.168.1.5 port 54821 ssh2
Nov  3 02:17:44 prod-web-01 sshd[2341]: Disconnected from user admin 192.168.1.5 port 54821
Nov  3 08:00:01 prod-web-01 CRON[3012]: pam_unix(cron:session): session opened for user root
Nov  3 08:00:02 prod-web-01 CRON[3012]: pam_unix(cron:session): session closed for user root
Nov  4 03:12:55 prod-web-01 sshd[4102]: Failed password for root from 45.33.32.156 port 39812 ssh2
Nov  4 03:12:57 prod-web-01 sshd[4102]: Failed password for root from 45.33.32.156 port 39814 ssh2
Nov  4 03:13:01 prod-web-01 sshd[4103]: Failed password for admin from 45.33.32.156 port 39820 ssh2
Nov  5 14:30:11 prod-web-01 sshd[5201]: Accepted password for deploy from 10.0.1.40 port 48822 ssh2
""",

    "/var/www/html/wp-config.php": """\
<?php
define('DB_NAME', 'wordpress_prod');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'Wordpr3ss#P@ss!');
define('DB_HOST', 'prod-db-01.internal');
define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
$table_prefix = 'wp_';
""",

    "/home/test/readme.txt": "Test account. Do not use for production.\n",

    "/proc/version": "Linux version 5.15.0-88-generic (buildd@lcy02-amd64-032) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023\n",

    "/proc/cpuinfo": """\
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model name      : Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz
cpu MHz         : 2400.072
cache size      : 30720 KB
""",
}

# ─────────────────────────────────────────────
# HIGH VALUE FILES
# Reading these triggers a high-confidence alert
# ─────────────────────────────────────────────

HIGH_VALUE_FILES = {
    "/root/secret/credentials.txt",
    "/root/secret/db_backup.sql",
    "/root/secret/internal_ips.txt",
    "/home/admin/.env",
    "/home/admin/backup.sh",
    "/home/admin/.ssh/authorized_keys",
    "/home/ubuntu/app/settings.json",
    "/home/ubuntu/app/config.py",
    "/var/www/html/wp-config.php",
    "/etc/shadow",
    "/root/.ssh/id_rsa",
}

# ─────────────────────────────────────────────
# MOTD — shown after login
# ─────────────────────────────────────────────

MOTD = (
    "Ubuntu 20.04.6 LTS\r\n"
    "\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    " * Management:     https://landscape.canonical.com\r\n"
    " * Support:        https://ubuntu.com/advantage\r\n"
    "\r\n"
    "  System information as of {date}\r\n"
    "\r\n"
    "  System load:  0.{load}          Processes:             142\r\n"
    "  Usage of /:   {disk}% of 49.9GB   Users logged in:       0\r\n"
    "  Memory usage: {mem}%               IPv4 address for eth0: 10.0.1.10\r\n"
    "  Swap usage:   0%\r\n"
    "\r\n"
    "Last login: {last_login} from {last_ip}\r\n"
    "\r\n"
)

# ─────────────────────────────────────────────
# CORE API
# ─────────────────────────────────────────────

def send_event(event_type: str, details: dict, high_value: bool = False):
    """Send event to core API. high_value=True boosts confidence scoring."""
    try:
        payload = {
            "event_type": event_type,
            "details": {**details, "high_value": high_value}
        }
        requests.post(CORE_EVENT_ENDPOINT, json=payload, timeout=5)
    except Exception:
        pass


# ─────────────────────────────────────────────
# SSH SERVER INTERFACE
# ─────────────────────────────────────────────

class HoneypotSSHServer(paramiko.ServerInterface):

    def __init__(self, client_ip: str):
        self.client_ip = client_ip
        self.username = None
        self.auth_attempts = 0

    def check_auth_password(self, username: str, password: str):
        self.auth_attempts += 1
        self.username = username

        # ── KILL CHAIN DETECTION ──────────────────────────────
        # If attacker uses the exact credentials leaked in the HTTP .env file
        # this confirms they completed the full HTTP → SSH kill chain
        if username == KILL_CHAIN_USER and password == KILL_CHAIN_PASSWORD:
            send_event("SSH_KILL_CHAIN_LOGIN", {
                "username": username,
                "password": password,
                "client_ip": self.client_ip,
                "kill_chain_stage": "SSH_ACCESS_CONFIRMED",
                "high_value": True,
            }, high_value=True)
        else:
            send_event("SSH_LOGIN_ATTEMPT", {
                "username": username,
                "password": password,
                "client_ip": self.client_ip,
                "attempt_number": self.auth_attempts,
            })

        # Always accept — we want them in
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, *args):
        return True


# ─────────────────────────────────────────────
# COMMAND HANDLER
# ─────────────────────────────────────────────

class FakeShell:

    def __init__(self, username: str, client_ip: str, channel):
        self.username = username
        self.client_ip = client_ip
        self.chan = channel
        self.cwd = FAKE_USERS.get(username, "/home/test")
        self.command_count = 0

    def _out(self, text: str):
        """Send a line of text to the SSH terminal with correct CRLF ending."""
        # Strip any existing line endings, then add clean \r\n
        text = text.rstrip("\r\n")
        self.chan.send((text + "\r\n").encode("utf-8", errors="ignore"))

    def _resolve_path(self, path: str) -> str:
        """Resolve a path relative to cwd."""
        if path.startswith("/"):
            return path.rstrip("/") or "/"
        parts = self.cwd.rstrip("/").split("/") + path.split("/")
        resolved = []
        for p in parts:
            if p == "..":
                if resolved:
                    resolved.pop()
            elif p and p != ".":
                resolved.append(p)
        return "/" + "/".join(resolved)

    def handle(self, cmd: str) -> bool:
        """
        Handle one command. Returns False if session should end.
        """
        if not cmd.strip():
            return True

        self.command_count += 1

        # Log every command
        send_event("SSH_COMMAND", {
            "command": cmd,
            "client_ip": self.client_ip,
            "cwd": self.cwd,
            "command_number": self.command_count,
        })

        parts = cmd.strip().split()
        base = parts[0]
        args = parts[1:]

        # ── exit / logout ──────────────────────────
        if base in ("exit", "logout", "quit"):
            self._out("logout")
            return False

        # ── ls ────────────────────────────────────
        elif base == "ls":
            target = self._resolve_path(args[-1]) if args and not args[-1].startswith("-") else self.cwd
            contents = FAKE_FS.get(target, [])
            if not contents:
                self._out("")
                return True
            if "-la" in args or "-al" in args or "-l" in args:
                self._out(f"total {random.randint(20, 80)}")
                self._out(f"drwxr-xr-x  {random.randint(2,8)} {self.username} {self.username}  4096 Nov  3 08:12 .")
                self._out(f"drwxr-xr-x  {random.randint(3,6)} {self.username} {self.username}  4096 Oct 28 14:30 ..")
                for item in contents:
                    is_dir = self._resolve_path(f"{target}/{item}") in FAKE_FS
                    perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                    size = random.randint(128, 8192) if not is_dir else 4096
                    month = random.choice(["Sep", "Oct", "Nov"])
                    day = random.randint(1, 28)
                    hour = random.randint(0, 23)
                    minute = random.randint(0, 59)
                    self._out(f"{perm}  1 {self.username} {self.username}  {size:>6} {month} {day:>2} {hour:02}:{minute:02} {item}")
            else:
                self._out("  ".join(contents))

        # ── cd ────────────────────────────────────
        elif base == "cd":
            if not args or args[0] == "~":
                self.cwd = FAKE_USERS.get(self.username, "/home/test")
            else:
                new_path = self._resolve_path(args[0])
                if new_path in FAKE_FS:
                    self.cwd = new_path
                else:
                    self._out(f"bash: cd: {args[0]}: No such file or directory")

        # ── pwd ───────────────────────────────────
        elif base == "pwd":
            self._out(self.cwd)

        # ── whoami ────────────────────────────────
        elif base == "whoami":
            self._out(self.username)

        # ── id ────────────────────────────────────
        elif base == "id":
            uid = 0 if self.username == "root" else random.randint(1000, 1003)
            self._out(f"uid={uid}({self.username}) gid={uid}({self.username}) groups={uid}({self.username})")

        # ── hostname ──────────────────────────────
        elif base == "hostname":
            self._out(HOSTNAME)

        # ── uname ─────────────────────────────────
        elif base == "uname":
            if "-a" in args:
                self._out("Linux prod-web-01 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux")
            else:
                self._out("Linux")

        # ── uptime ────────────────────────────────
        elif base == "uptime":
            days = random.randint(10, 120)
            self._out(f" 14:32:01 up {days} days,  2:14,  1 user,  load average: 0.{random.randint(10,40)}, 0.{random.randint(10,40)}, 0.{random.randint(10,40)}")

        # ── cat ───────────────────────────────────
        elif base == "cat":
            if not args:
                self._out("cat: missing operand")
                return True

            filepath = self._resolve_path(args[0])

            # High value file — log with elevated flag
            is_high_value = filepath in HIGH_VALUE_FILES
            if is_high_value:
                send_event("SSH_HIGH_VALUE_ACCESS", {
                    "file": filepath,
                    "command": cmd,
                    "client_ip": self.client_ip,
                }, high_value=True)

            if filepath in FAKE_FILE_CONTENTS:
                # Send each line individually with correct CRLF
                for line in FAKE_FILE_CONTENTS[filepath].split("\n"):
                    self._out(line)
            elif filepath in HIGH_VALUE_FILES:
                self._out("cat: " + args[0] + ": Permission denied")
            else:
                parent = "/".join(filepath.split("/")[:-1]) or "/"
                filename = filepath.split("/")[-1]
                if parent in FAKE_FS and filename in FAKE_FS[parent]:
                    self._out("")
                else:
                    self._out(f"cat: {args[0]}: No such file or directory")

        # ── echo ──────────────────────────────────
        elif base == "echo":
            self._out(" ".join(args))

        # ── env / printenv ────────────────────────
        elif base in ("env", "printenv"):
            self._out(f"USER={self.username}")
            self._out(f"HOME={FAKE_USERS.get(self.username, '/home/test')}")
            self._out(f"SHELL=/bin/bash")
            self._out(f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            self._out(f"HOSTNAME={HOSTNAME}")
            self._out(f"TERM=xterm-256color")
            self._out(f"LANG=en_US.UTF-8")

        # ── ps ────────────────────────────────────
        elif base == "ps":
            self._out("  PID TTY          TIME CMD")
            self._out(f"{random.randint(1000,2000)}   pts/0    00:00:00 bash")
            self._out(f"{random.randint(2001,3000)}   pts/0    00:00:00 ps")
            if "aux" in cmd or "-aux" in args or "ax" in args:
                self._out("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND")
                self._out(f"root           1  0.0  0.1 169352 10908 ?        Ss   Oct28   0:08 /sbin/init")
                self._out(f"root         523  0.0  0.0  72296  6284 ?        Ss   Oct28   0:00 /usr/sbin/sshd -D")
                self._out(f"www-data    1042  0.1  0.5 412348 44212 ?        S    Oct28   2:11 nginx: worker process")
                self._out(f"deploy      2103  0.0  0.8 712444 66840 ?        Sl   Nov01   1:03 python3 run.py")

        # ── netstat / ss ──────────────────────────
        elif base in ("netstat", "ss"):
            self._out("Active Internet connections (only servers)")
            self._out("Proto Recv-Q Send-Q Local Address           Foreign Address         State")
            self._out("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN")
            self._out("tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN")
            self._out("tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN")
            self._out(f"tcp        0      0 10.0.1.10:22            {self.client_ip}:54821  ESTABLISHED")

        # ── ifconfig / ip addr ────────────────────
        elif base in ("ifconfig", "ip"):
            self._out("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500")
            self._out("        inet 10.0.1.10  netmask 255.255.255.0  broadcast 10.0.1.255")
            self._out("        inet6 fe80::4ab0:2dff:fe4a:1234  prefixlen 64  scopeid 0x20<link>")
            self._out("        ether 4a:b0:2d:4a:12:34  txqueuelen 1000  (Ethernet)")

        # ── history ───────────────────────────────
        elif base == "history":
            history_file = f"{FAKE_USERS.get(self.username, '/home/test')}/.bash_history"
            if history_file in FAKE_FILE_CONTENTS:
                for i, line in enumerate(FAKE_FILE_CONTENTS[history_file].strip().split("\n"), 1):
                    self._out(f"  {i:>3}  {line}")
            else:
                self._out("    1  ls")
                self._out("    2  pwd")

        # ── find ──────────────────────────────────
        elif base == "find":
            send_event("SSH_RECON_COMMAND", {
                "command": cmd,
                "client_ip": self.client_ip,
            })
            # Show a few believable results
            self._out("/home/admin/.env")
            self._out("/home/ubuntu/app/config.py")
            self._out("/var/www/html/wp-config.php")
            time.sleep(0.5)

        # ── sudo ──────────────────────────────────
        elif base == "sudo":
            send_event("SSH_PRIVILEGE_ESCALATION", {
                "command": cmd,
                "client_ip": self.client_ip,
            }, high_value=True)
            self._out(f"[sudo] password for {self.username}: ")
            time.sleep(1.5)
            self._out("Sorry, try again.")
            self._out(f"[sudo] password for {self.username}: ")
            time.sleep(1.0)
            self._out("sudo: 3 incorrect password attempts")

        # ── su ────────────────────────────────────
        elif base == "su":
            send_event("SSH_PRIVILEGE_ESCALATION", {
                "command": cmd,
                "client_ip": self.client_ip,
            }, high_value=True)
            self._out("Password: ")
            time.sleep(1.5)
            self._out("su: Authentication failure")

        # ── wget ──────────────────────────────────
        elif base == "wget":
            url = args[0] if args else "unknown"
            send_event("SSH_DOWNLOAD_ATTEMPT", {
                "command": cmd,
                "url": url,
                "client_ip": self.client_ip,
            }, high_value=True)
            self._out(f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}")
            self._out(f"Resolving {url.split('/')[2] if '/' in url else url}...")
            time.sleep(2)
            self._out("Connecting... connected.")
            self._out("HTTP request sent, awaiting response...")
            time.sleep(1)
            self._out("200 OK")
            self._out("Saving to: 'payload'")
            time.sleep(1.5)
            self._out("payload  [=========================================>] 100%")

        # ── curl ──────────────────────────────────
        elif base == "curl":
            url = next((a for a in args if a.startswith("http")), "unknown")
            send_event("SSH_DOWNLOAD_ATTEMPT", {
                "command": cmd,
                "url": url,
                "client_ip": self.client_ip,
            }, high_value=True)
            time.sleep(2)
            self._out('{"status": "ok"}')

        # ── chmod / chown ─────────────────────────
        elif base in ("chmod", "chown"):
            # Silent success — lets attacker think it worked
            pass

        # ── ssh (lateral movement attempt) ────────
        elif base == "ssh":
            send_event("SSH_LATERAL_MOVEMENT", {
                "command": cmd,
                "client_ip": self.client_ip,
                "target": " ".join(args),
            }, high_value=True)
            target = args[-1] if args else "unknown"
            self._out(f"ssh: connect to host {target} port 22: Connection timed out")

        # ── scp ───────────────────────────────────
        elif base == "scp":
            send_event("SSH_DATA_EXFILTRATION", {
                "command": cmd,
                "client_ip": self.client_ip,
            }, high_value=True)
            time.sleep(2)
            self._out("scp: Connection timed out")

        # ── python / python3 ──────────────────────
        elif base in ("python", "python3"):
            send_event("SSH_INTERPRETER_ACCESS", {
                "command": cmd,
                "client_ip": self.client_ip,
            }, high_value=True)
            self._out("Python 3.8.10 (default, Nov 14 2022, 12:59:47)")
            self._out('[GCC 9.4.0] on linux\nType "help", "copyright", "credits" or "license" for more information.')
            self._out(">>> ")

        # ── nano / vi / vim ───────────────────────
        elif base in ("nano", "vi", "vim"):
            self._out(f"  GNU nano 4.8{' ' * 30}{args[0] if args else 'New Buffer'}")
            time.sleep(0.3)
            self._out("")
            self._out("^G Get Help  ^O Write Out  ^W Where Is  ^K Cut Text")

        # ── clear ─────────────────────────────────
        elif base == "clear":
            self.chan.send(b"\033[2J\033[H")

        # ── anything else ─────────────────────────
        else:
            # Make common tools respond believably
            if base in ("apt", "apt-get", "yum", "snap"):
                self._out(f"E: Could not open lock file /var/lib/dpkg/lock - open (13: Permission denied)")
            elif base in ("systemctl", "service"):
                self._out("Failed to connect to bus: No such file or directory")
            elif base in ("docker",):
                self._out("Got permission denied while trying to connect to the Docker daemon socket")
            else:
                # Randomly say not found OR permission denied for realism
                if random.random() < 0.7:
                    self._out(f"bash: {base}: command not found")
                else:
                    self._out(f"bash: {base}: Permission denied")

        return True


# ─────────────────────────────────────────────
# CLIENT HANDLER
# ─────────────────────────────────────────────

def readline(chan) -> str:
    """
    Read one line from a Paramiko channel.
    Handles SSH PTY input correctly — echoes characters, handles backspace.
    Returns the command string (without line terminator).
    """
    line = b""
    while True:
        ch = chan.recv(1)
        if not ch:
            raise EOFError("channel closed")

        # Enter key — \r or \n signals end of line
        if ch in (b"\r", b"\n"):
            chan.send(b"\r\n")
            break

        # Backspace / DEL
        if ch in (b"\x7f", b"\x08"):
            if line:
                line = line[:-1]
                chan.send(b"\x08 \x08")  # erase character on terminal
            continue

        # Ctrl+C
        if ch == b"\x03":
            chan.send(b"^C\r\n")
            return ""

        # Ctrl+D (EOF)
        if ch == b"\x04":
            raise EOFError("ctrl+d")

        # Ignore other control/escape sequences (arrow keys, etc.)
        if ch[0] < 32 or ch[0] == 127:
            continue

        line += ch
        chan.send(ch)  # echo the character back

    return line.decode("utf-8", errors="ignore").strip()


def handle_client(client, addr):
    ip = addr[0]

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)

        server = HoneypotSSHServer(ip)
        transport.start_server(server=server)

        chan = transport.accept(20)
        if chan is None:
            return

        user = server.username if server.username in FAKE_USERS else "test"

        # Send MOTD
        motd = MOTD.format(
            date=time.strftime("%a %b %d %H:%M:%S UTC %Y"),
            load=random.randint(10, 60),
            disk=random.randint(30, 75),
            mem=random.randint(20, 60),
            last_login=time.strftime(
                "%a %b %d %H:%M:%S %Y",
                time.localtime(time.time() - random.randint(3600, 86400))
            ),
            last_ip=f"192.168.1.{random.randint(2, 254)}",
        )
        chan.send(motd.encode())

        shell = FakeShell(user, ip, chan)

        while True:
            # Show prompt — update after every command so cd works
            prompt = (
                f"{'root' if user == 'root' else user}"
                f"@{HOSTNAME}:{shell.cwd}"
                f"{'#' if user == 'root' else '$'} "
            )
            chan.send(prompt.encode())

            try:
                cmd = readline(chan)
            except EOFError:
                break

            should_continue = shell.handle(cmd)
            if not should_continue:
                break

    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def start_ssh_honeypot():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", SSH_PORT))
    sock.listen(100)
    print(f"[SSH] Honeypot listening on port {SSH_PORT}")
    print(f"[SSH] Hostname: {HOSTNAME}")
    print(f"[SSH] Core API: {CORE_EVENT_ENDPOINT}")

    while True:
        try:
            client, addr = sock.accept()
            print(f"[SSH] Connection from {addr[0]}:{addr[1]}")
            threading.Thread(
                target=handle_client,
                args=(client, addr),
                daemon=True
            ).start()
        except Exception as e:
            print(f"[SSH] Accept error: {e}")


if __name__ == "__main__":
    start_ssh_honeypot()