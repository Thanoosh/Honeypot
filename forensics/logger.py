# forensics/logger.py

import json
import hashlib
import os
import threading

class CentralLogger:
    """
    Centrally logs all events with cryptographic chaining (Forensic Integrity).
    """
    def __init__(self, log_dir="data/logs"):
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(log_dir, "events.log")
        self.ref_file = os.path.join(log_dir, ".chain_ref")
        self.last_hash = self._load_last_hash()
        self._lock = threading.Lock()

    def _load_last_hash(self):
        """Load the last hash from disk or initial genesis state."""
        if os.path.exists(self.ref_file):
            try:
                with open(self.ref_file, "r") as f:
                    return f.read().strip()
            except Exception:
                pass
        return "GENESIS_BLOCK"

    def _save_last_hash(self, h):
        """Persist the current hash as the 'last_hash' for the next entry."""
        try:
            with open(self.ref_file, "w") as f:
                f.write(h)
            self.last_hash = h
        except Exception as e:
            print(f"[LOGGER ERROR] Could not save chain ref: {e}")

    def log(self, event: dict):
        """
        Log an event with SHA-256 chaining to ensure forensic integrity. 
        """
        event_copy = dict(event)
        
        def json_serial(obj):
            if isinstance(obj, set): return list(obj)
            return str(obj)

        with self._lock:
            # Forensic Chaining (Prevents modification/deletion of history)
            event_copy["previous_hash"] = self.last_hash

            try:
                # Calculate final hash (of data + previous_hash)
                current_hash = hashlib.sha256(
                    json.dumps(event_copy, sort_keys=True, default=json_serial).encode()
                ).hexdigest()
                
                event_copy["hash"] = current_hash
                
                # Persist to disk
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event_copy, default=json_serial) + "\n")
                
                # Update the chain
                self._save_last_hash(current_hash)

            except Exception as e:
                print(f"[LOGGER ERROR] Failed to log event: {e}")
