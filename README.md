Behaviour-Aware Honeypot
Adaptive Deception and Behavioural Threat Intelligence Platform
📌 Project Overview

This project implements a Behaviour-Aware Honeypot designed to expose real network services (such as SSH and HTTP) in a safe and isolated environment, observe attacker behaviour over time, and adapt deception strategies dynamically based on observed patterns.

Unlike traditional honeypots that only log attacks, this system:

analyses attacker behaviour at the session level

classifies behaviour probabilistically

adapts its responses during the attack

provides actionable alerts and forensic evidence

The project is intended as:

a final-year engineering capstone

a research-oriented security system

a deployable local application for behavioural threat detection

🎯 Objectives

Deploy realistic honeypot services (SSH, HTTP)

Capture high-quality attacker behaviour data

Classify attacker behaviour using rules and lightweight ML

Adapt honeypot responses dynamically

Provide a centralized dashboard for monitoring and control

Ensure forensic integrity of collected evidence

Maintain safety, isolation, and reproducibility

🧠 What “Behaviour-Aware” Means in This Project

The system does not attempt to infer attacker intent.

Instead, it:

Observes what the attacker does

Extracts behavioural patterns (timing, sequence, tools)

Classifies sessions probabilistically

Selects a deception strategy based on confidence

Adapts behaviour while the session is still active

All claims are evidence-based and academically defensible.

🏗️ High-Level Architecture
User / Attacker
      ↓
Real Network Protocols (SSH / HTTP)
      ↓
Isolated Trap Services (Docker Containers)
      ↓
Core Orchestrator (Event Bus)
      ↓
Behaviour Engine (Rules + ML)
      ↓
Alerts • Dashboard • Forensics

🔧 Core Components
1️⃣ Core Orchestrator

Central controller of the system

Spawns and stops trap services

Routes events between modules

Does NOT analyze attacks directly

2️⃣ Trap Services
SSH Honeypot

Real SSH protocol

Accepts real SSH clients and tools

Fake shell and filesystem

Commands are logged, not executed

HTTP Honeypot

Real web service

Intentionally vulnerable endpoints

Detects attacks such as SQL Injection and XSS

No real database or code execution

All trap services run inside Docker containers for safety.

3️⃣ Behaviour Engine

Session-level behaviour modeling

Rule-based classification (primary)

Lightweight ML for:

anomaly detection

behaviour clustering

Maps behaviour to known attack patterns (classification only)

4️⃣ Adaptive Deception Engine

Based on observed behaviour, the system dynamically adjusts:

response timing

verbosity

fake environment richness

success / failure messages

This adaptation happens in real time.

5️⃣ Dashboard

View live logs

View alerts by severity

Start / stop honeypot services

Inspect behaviour classification results

The dashboard is designed for clarity and control, not SOC-scale complexity.

6️⃣ Forensics & Integrity

All logs stored in structured JSON format

Logs hashed using SHA-256 to detect tampering

Optional chained hashes for integrity verification

Network traffic captured as PCAP files

Logical session “snapshots” for post-incident analysis

🧪 Example Demo Scenarios
SSH Attack Simulation

Start SSH honeypot

Connect using ssh or brute-force tools

Observe behaviour classification

Trigger adaptive responses and alerts

HTTP Attack Simulation

Start HTTP honeypot

Access vulnerable endpoints

Attempt SQL injection or XSS

Observe detection, classification, and alerts

🛠️ Technology Stack
Layer	Technology
Language	Python
Isolation	Docker
SSH Trap	Protocol-real honeypot
HTTP Trap	Flask / FastAPI
Dashboard	Streamlit
ML	scikit-learn (local)
Logging	JSON + SHA-256
Version Control	Git / GitHub

All tools are free and open-source.

🧑‍🤝‍🧑 Team Structure

Member 1

Core Orchestrator

Behaviour Engine

Forensics

System integration

Member 2

HTTP Honeypot

Dashboard

Alert visualization

🚫 Explicit Non-Goals

No real OS access for attackers

No real credentials

No real databases

No execution of attacker payloads

No intent prediction claims

No replacement for firewalls or antivirus

📦 Deployment Model

The system runs as a local application:

Users install Docker

Clone the repository

Start the application

Enable honeypot services via dashboard or config

Designed to be:

portable

reproducible

safe for student and lab environments

🎓 Academic Positioning

“This project demonstrates a behaviour-aware honeypot that dynamically adapts deception strategies based on observed attacker behaviour using session-level analysis and probabilistic classification.”

🔒 Design Status

Architecture frozen.
Changes are made only after explicit discussion.

📌 How to Use This Repository

Read this README fully

Follow setup instructions (to be added)

Start services using provided scripts

Monitor attacks via dashboard

Analyze behaviour and forensic data

📄 License

For academic and research use.# Honeypot
