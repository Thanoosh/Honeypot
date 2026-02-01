import socket
import threading
import paramiko
import time
import requests

HOST_KEY = paramiko.RSAKey.generate(2048)
CORE_EVENT_ENDPOINT = "http://host.docker.internal:5001/event"
SSH_PORT = 2222

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
}

def send_event(event_type, details):
    try:
        requests.post(
            CORE_EVENT_ENDPOINT,
            json={"event_type": event_type, "details": details},
            timeout=5
        )
    except Exception:
        pass

class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.username = None

    def check_auth_password(self, username, password):
        self.username = username
        send_event("SSH_LOGIN_ATTEMPT", {
            "username": username,
            "password": password,
            "client_ip": self.client_ip
        })
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, *args):
        return True


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

    chan.send(b"Ubuntu 20.04.6 LTS\r\n")

    while True:
        try:
            chan.send(f"{user}@honeypot:{cwd}$ ".encode())
            cmd = chan.recv(1024).decode().strip()

            if not cmd:
                continue

            send_event("SSH_COMMAND", {
                "command": cmd,
                "client_ip": addr[0]
            })

            if cmd in ("exit", "logout"):
                break
            elif cmd == "ls":
                chan.send(("  ".join(FAKE_FS.get(cwd, [])) + "\r\n").encode())
            elif cmd == "pwd":
                chan.send((cwd + "\r\n").encode())
            elif cmd == "whoami":
                chan.send((user + "\r\n").encode())
            else:
                chan.send(b"command not found\r\n")

            time.sleep(0.2)

        except Exception:
            break

    chan.close()
    transport.close()


def start_ssh_honeypot():
    sock = socket.socket()
    sock.bind(("0.0.0.0", SSH_PORT))
    sock.listen(100)
    print(f"[SSH] Honeypot listening on port {SSH_PORT}")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    start_ssh_honeypot()
