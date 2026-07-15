"""
test_database_writer_phase2.py - Phase 2 Writer Transition Tests
=================================================================

Covers transition-lock handling in DatabaseWriter.
"""

import os
import sys
import threading
import time
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.database_writer import DatabaseWriter


class TestDatabaseWriterPhase2:
    def test_drops_batch_on_shutdown_when_transition_lock_held(self):
        transition_lock = threading.Lock()
        transition_lock.acquire()

        writer = DatabaseWriter(max_queue_size=10, mode_transition_lock=transition_lock)
        writer._save_fn = MagicMock(return_value=1)
        writer.enqueue([{"source_ip": "1.1.1.1", "dest_ip": "2.2.2.2"}])

        writer._stop_event.set()
        t = threading.Thread(target=writer._run, daemon=True)
        t.start()
        t.join(timeout=2)

        transition_lock.release()

        assert not t.is_alive()
        writer._save_fn.assert_not_called()

    def test_waits_for_transition_lock_then_writes(self):
        transition_lock = threading.Lock()
        transition_lock.acquire()

        writer = DatabaseWriter(max_queue_size=10, mode_transition_lock=transition_lock)
        writer._save_fn = MagicMock(return_value=1)
        writer.enqueue([{"source_ip": "1.1.1.1", "dest_ip": "2.2.2.2"}])

        t = threading.Thread(target=writer._run, daemon=True)
        t.start()

        time.sleep(0.15)
        writer._save_fn.assert_not_called()

        transition_lock.release()
        writer._stop_event.set()
        t.join(timeout=2)

        assert not t.is_alive()
        writer._save_fn.assert_called_once()
