"""
test_alert_queries_lock_retry.py - Alert write lock retry regressions
===================================================================
"""

import contextlib
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.queries import alert_queries as aq


class TestAlertQueryLockRetry:
    def test_acknowledge_alert_retries_on_locked_database(self, initialized_db, monkeypatch):
        alert_id = aq.create_alert(
            alert_type="new_device",
            severity="warning",
            message="test alert",
        )
        assert alert_id is not None

        real_get_connection = aq.get_connection
        attempts = {"count": 0}

        @contextlib.contextmanager
        def flaky_get_connection():
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise sqlite3.OperationalError("database is locked")
            with real_get_connection() as conn:
                yield conn

        monkeypatch.setattr(aq, "get_connection", flaky_get_connection)
        monkeypatch.setattr("time.sleep", lambda *_args, **_kwargs: None)

        assert aq.acknowledge_alert(alert_id) is True
        assert attempts["count"] >= 2

    def test_resolve_alert_retries_on_locked_database(self, initialized_db, monkeypatch):
        alert_id = aq.create_alert(
            alert_type="security",
            severity="high",
            message="test resolve retry",
        )
        assert alert_id is not None

        real_get_connection = aq.get_connection
        attempts = {"count": 0}

        @contextlib.contextmanager
        def flaky_get_connection():
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise sqlite3.OperationalError("database is locked")
            with real_get_connection() as conn:
                yield conn

        monkeypatch.setattr(aq, "get_connection", flaky_get_connection)
        monkeypatch.setattr("time.sleep", lambda *_args, **_kwargs: None)

        assert aq.resolve_alert(alert_id, resolved_by="pytest") is True
        assert attempts["count"] >= 2
