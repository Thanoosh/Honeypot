#!/bin/bash

# Configuration
PROJECT_ROOT="/home/hemanth/Honeypot"
CLOUDFLARE_BIN="$PROJECT_ROOT/cloudflared"
BORE_BIN="$PROJECT_ROOT/bore"

# External Logs
TRY_LOG="$PROJECT_ROOT/trycloudflare.log"
DASH_LOG="$PROJECT_ROOT/dashboard_tunnel.log"
BORE_LOG="$PROJECT_ROOT/bore.log"

echo "[*] Killing any existing tunnel processes..."
pkill -f "cloudflared"
pkill -f "bore"
sleep 2

echo "[*] Starting Cloudflare Tunnel for HTTP Trap (8080)..."
nohup "$CLOUDFLARE_BIN" tunnel --url http://localhost:8080 > "$TRY_LOG" 2>&1 &
echo "[*] Starting Cloudflare Tunnel for Dashboard (8501)..."
nohup "$CLOUDFLARE_BIN" tunnel --url http://localhost:8501 > "$DASH_LOG" 2>&1 &

echo "[*] Starting Bore Tunnel for SSH Trap (2222)..."
nohup "$BORE_BIN" local 2222 --to bore.pub > "$BORE_LOG" 2>&1 &

echo "[+] Tunnels started in background."
echo "    - HTTP Trap: check $TRY_LOG"
echo "    - Dashboard: check $DASH_LOG"
echo "    - SSH Trap:  check $BORE_LOG"
