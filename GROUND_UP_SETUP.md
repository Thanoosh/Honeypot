# Honeypot: Ground-Up Setup Guide

This document provides a clean, step-by-step guide to building and running the Behaviour-Aware Honeypot project from scratch.

---

## 1. Prerequisites
- **Docker Desktop**: Must be installed and running. 
- **System Path**: Ensure `docker` is available in your terminal. (If you installed to a custom drive like `E:`, make sure `E:\docker\App\resources\bin` is in your System PATH).
- **Drive Space**: Approximately 10GB of free space is recommended for the full build.

---

## 2. One-Command Startup (Recommended)
The easiest way to start the entire system is:
```powershell
docker compose up --build -d
```
This command will automatically build all necessary images and launch the containers.

---

## 3. Manual Step-by-Step Build (Optional)
If you prefer to build the stages manually:

### Step A: Build Base Dependencies
```powershell
docker compose build --no-cache core-base dashboard-base
```

### Step B: Build Application Services
```powershell
docker compose build --no-cache core dashboard
```

### Step C: Launch Services
```powershell
docker compose up -d
```

---

## 4. Accessing the System
Once the containers are running, you can access the following:

| Service | URL |
| :--- | :--- |
| **Main Dashboard** | `http://localhost:8501` |
| **Core API** | `http://localhost:5001` |
| **Public Tunnels** | Check logs: `docker compose logs tunnel-dash` |

---

## 5. Verification
To verify that all services are healthy, run:
```powershell
docker ps
```
You should see 5 containers running: `honeypot_dashboard`, `honeypot_core`, `tunnel_dash`, `tunnel_http`, and `tunnel_ssh`.

