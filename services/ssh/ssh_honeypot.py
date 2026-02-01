# services/ssh/ssh_honeypot.py

import socket
import threading
import paramiko
import time
import requests

HOST_KEY = paramiko.RSAKey.generate(2048)
CORE_EVENT_ENDPOINT = "http://host.docker.internal:5001/event"
SSH_PORT = 2222

# ---------------- FAKE SYSTEM ----------------

FAKE_USERS = {
    "root": "/root",
    "admin": "/home/admin",
    "test": "/home/test"
}

FAKE_FS = {
    "/": ["bin", "etc", "home", "var"],
    "/home": ["admin", "test"],
    "/home/admin": ["notes.txt", "backup.sh"],
    "/home/test": ["readme.txt"],
    "/root": ["flag.txt"],
    "/etc": ["passwd", "shadow"],
    "/var": ["log"],
}

# ---------------- HELPERS ----------------

def send_event(event_type, details):
    try:
        requests.post(
            CORE_EVENT_ENDPOINT,
            json={"event_type": event_type, "details": details},
            timeout=5
        )
    except Exception:
        pass

def normalize_path(path):
    if path == "/":
        return "/"
    return path.rstrip("/")

# ---------------- SSH SERVER ----------------

class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.username = None

    def check_auth_password(self, username, password):
        self.username = username
        send_event(
            "SSH_LOGIN_ATTEMPT",
            {
                "username": username,
                "password": password,
                "client_ip": self.client_ip
            }
        )
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    # 🔥 REQUIRED FOR INTERACTIVE SHELL
    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
        return True

# ---------------- CLIENT HANDLER ----------------

def handle_client(client, addr):
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)

    server = HoneypotSSHServer(addr[0])
    transport.start_server(server=server)

    chan = transport.accept(20)
    if not chan:
        return

    user = server.username if server.username in FAKE_USERS else "test"
    cwd = FAKE_USERS.get(user, "/home/test")

    chan.send(b"Welcome to Ubuntu 20.04.6 LTS\r\n")
    chan.send(b"Last login: Thu Jan 31 12:00:00 2026\r\n")

    buffer = ""

    while True:
        try:
            prompt = f"{user}@honeypot:{cwd}$ "
            chan.send(prompt.encode())

            buffer = ""

            while True:
                char = chan.recv(1).decode("utf-8", errors="ignore")

                if char in ("\r", "\n"):
                    chan.send(b"\r\n")
                    break

                elif char == "\x7f":  # Backspace
                    if buffer:
                        buffer = buffer[:-1]
                        chan.send(b"\b \b")
                else:
                    buffer += char
                    chan.send(char.encode())

            command = buffer.strip()
            if not command:
                continue

            send_event(
                "SSH_COMMAND",
                {"command": command, "client_ip": addr[0]}
            )

            # -------- COMMAND HANDLING --------

            if command in ("exit", "logout"):
                break

            elif command == "pwd":
                chan.send((cwd + "\r\n").encode())

            elif command == "whoami":
                chan.send((user + "\r\n").encode())

            elif command == "ls":
                files = FAKE_FS.get(cwd, [])
                chan.send(("  ".join(files) + "\r\n").encode())

            elif command.startswith("cd"):
                parts = command.split(maxsplit=1)
                target = parts[1] if len(parts) > 1 else FAKE_USERS[user]

                if target == "..":
                    cwd = "/" if cwd.count("/") <= 1 else "/".join(cwd.split("/")[:-1])
                else:
                    new_path = normalize_path(
                        target if target.startswith("/") else f"{cwd}/{target}"
                    )
                    if new_path in FAKE_FS:
                        cwd = new_path
                    else:
                        chan.send(b"No such file or directory\r\n")

            elif command == "id":
                chan.send(f"uid=1000({user}) gid=1000({user}) groups=1000({user})\r\n".encode())

            elif command.startswith("cat"):
                chan.send(b"Permission denied\r\n")

            else:
                chan.send((command + ": command not found\r\n").encode())

            time.sleep(0.3)

        except Exception:
            break

    chan.close()
    transport.close()

# ---------------- MAIN ----------------

def start_ssh_honeypot():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", SSH_PORT))
    sock.listen(100)
    print(f"[SSH] Honeypot listening on port {SSH_PORT}")

    while True:
        client, addr = sock.accept()
        threading.Thread(
            target=handle_client,
            args=(client, addr),
            daemon=True
        ).start()

if __name__ == "__main__":
    start_ssh_honeypot()
