#!/bin/bash

PROJECT_ROOT="/home/hemanth/Honeypot"

echo "[*] Starting Honeypot Infrastructure with Integrated Tunnels..."
cd "$PROJECT_ROOT"
# Stop existing to ensure fresh tunnels/links
docker compose down > /dev/null 2>&1 
docker compose up -d

echo "[*] Waiting for services to initialize and links to generate (15 sec)..."
sleep 15

echo "--------------------------------------------------------"
echo "🛡️ HONEYPOT EXTERNAL ACCESS LINKS"
echo "--------------------------------------------------------"

# Extract Cloudflare URLs from container logs
# The format in logs is typically ' |  https://xxxx.trycloudflare.com '
DASH_URL=$(docker compose logs tunnel-dash 2>&1 | grep "trycloudflare.com" | tail -n 1 | grep -o 'https://[^ ]*')
HTTP_URL=$(docker compose logs tunnel-http 2>&1 | grep "trycloudflare.com" | tail -n 1 | grep -o 'https://[^ ]*')

# Extract Bore port
BORE_ACCESS=$(docker compose logs tunnel-ssh 2>&1 | grep "listening at" | tail -n 1 | awk -F 'listening at ' '{print $2}' | xargs)

if [ -z "$DASH_URL" ]; then
    echo "[!] Dashboard URL generation pending... wait a few more seconds."
else
    echo "📊 DASHBOARD:   $DASH_URL"
fi

if [ -z "$HTTP_URL" ]; then
    echo "[!] HTTP Trap URL generation pending..."
else
    echo "🌐 HTTP TRAP:   $HTTP_URL"
fi

if [ -z "$BORE_ACCESS" ]; then
    echo "[!] SSH Tunnel pending..."
else
    echo "🔑 SSH ACCESS:  ssh root@$BORE_ACCESS"
fi

echo "--------------------------------------------------------"
echo "[+] Honeypot is LIVE."
echo "--------------------------------------------------------"
