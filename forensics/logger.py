# forensics/logger.py
#
# Async, queue-based forensic logger.
#
# Design goals:
#   1. NEVER block Flask's /event handler — all disk I/O happens in a dedicated
#      background worker thread.
#   2. Maintain SHA-256 hash chaining for forensic integrity (unmodified).
#   3. The queue is unbounded (deque) so fast attackers never lose events.
#   4. Clean shutdown via stop() if the process exits gracefully.

import json
import hashlib
import os
import threading
from collections import deque


class CentralLogger:
    """
    Non-blocking forensic event logger.

    The public `log(event)` method enqueues the event and returns immediately.
    A single background daemon thread drains the queue sequentially,
    computing hash chains and writing to disk — zero contention with Flask workers.
    """

    def __init__(self, log_dir="data/logs"):
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(log_dir, "events.log")
        self.ref_file = os.path.join(log_dir, ".chain_ref")
        self.last_hash = self._load_last_hash()

        # Unbounded deque as the async work queue
        self._queue: deque = deque()
        self._queue_event = threading.Event()
        self._running = True

        # Single writer thread — sequential hash chain is maintained correctly
        self._worker = threading.Thread(
            target=self._drain_loop,
            name="logger-worker",
            daemon=True,
        )
        self._worker.start()

    # ─────────────────────────────────────────────
    # PUBLIC API — called from Flask handler thread
    # ─────────────────────────────────────────────

    def log(self, event: dict):
        """
        Enqueue an event for async logging. Returns immediately — never blocks.
        """
        self._queue.append(dict(event))
        self._queue_event.set()     # Wake the worker if it is sleeping

    def stop(self):
        """Signal worker to drain remaining events and exit."""
        self._running = False
        self._queue_event.set()
        self._worker.join(timeout=5)

    # ─────────────────────────────────────────────
    # WORKER — background thread only
    # ─────────────────────────────────────────────

    def _drain_loop(self):
        """Continuously drain the queue, sleeping when empty."""
        while self._running or self._queue:
            self._queue_event.wait(timeout=1.0)
            self._queue_event.clear()
            while self._queue:
                event_copy = self._queue.popleft()
                self._write(event_copy)

    def _write(self, event_copy: dict):
        """Hash-chain and persist a single event. Runs in worker thread only."""
        def json_serial(obj):
            if isinstance(obj, set):
                return list(obj)
            return str(obj)

        try:
            event_copy["previous_hash"] = self.last_hash

            current_hash = hashlib.sha256(
                json.dumps(event_copy, sort_keys=True, default=json_serial).encode()
            ).hexdigest()

            event_copy["hash"] = current_hash

            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_copy, default=json_serial) + "\n")

            self._save_last_hash(current_hash)

        except Exception as e:
            print(f"[LOGGER ERROR] Failed to log event: {e}")

    # ─────────────────────────────────────────────
    # CHAIN PERSISTENCE
    # ─────────────────────────────────────────────

    def _load_last_hash(self) -> str:
        if os.path.exists(self.ref_file):
            try:
                with open(self.ref_file, "r") as f:
                    return f.read().strip()
            except Exception:
                pass
        return "GENESIS_BLOCK"

    def _save_last_hash(self, h: str):
        try:
            with open(self.ref_file, "w") as f:
                f.write(h)
            self.last_hash = h
        except Exception as e:
            print(f"[LOGGER ERROR] Could not save chain ref: {e}")
