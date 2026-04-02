#!/bin/bash

PROJECT_ROOT="/home/hemanth/Honeypot"

echo "[*] Stopping Honeypot Infrastructure..."
cd "$PROJECT_ROOT"
docker compose down

echo "[*] Cleaning up any orphaned honeypot containers..."
docker rm -f honeypot_http honeypot_ssh 2>/dev/null

echo "[-] Honeypot stopped."
