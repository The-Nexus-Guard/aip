#!/usr/bin/env python3
"""Tests for admin endpoints."""

import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "service"))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

os.environ["AIP_TESTING"] = "1"
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix=".db")
os.close(_test_db_fd)
os.environ["AIP_DATABASE_PATH"] = _test_db_path

from fastapi.testclient import TestClient
import database
import unittest

database.init_database()

from main import app
client = TestClient(app)


class TestAdminEndpoints(unittest.TestCase):

    def setUp(self):
        """Reset database before each test."""
        import sqlite3
        conn = sqlite3.connect(_test_db_path)
        for table in ["registrations", "vouches", "platform_links", "key_history", "messages", "skill_signatures"]:
            try:
                conn.execute(f"DELETE FROM {table}")
            except sqlite3.OperationalError:
                pass
        conn.commit()
        conn.close()

    def test_list_registrations_empty(self):
        resp = client.get("/admin/registrations")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("registrations", data)
        self.assertIn("count", data)

    def test_list_registrations_with_data(self):
        # Insert a registration directly
        import hashlib, base64
        from nacl.signing import SigningKey
        sk = SigningKey.generate()
        pk = sk.verify_key.encode()
        did = "did:aip:" + hashlib.sha256(pk).hexdigest()[:32]
        pk_b64 = base64.b64encode(pk).decode()
        database.register_did(did, pk_b64)
        database.add_platform_link(did, "moltbook", "TestAgent")

        resp = client.get("/admin/registrations")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["count"], 1)
        found = [r for r in data["registrations"] if r["did"] == did]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["platforms"][0]["username"], "TestAgent")

    def test_get_registration_not_found(self):
        resp = client.get("/admin/registrations/did:aip:nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_get_registration_detail(self):
        import hashlib, base64
        from nacl.signing import SigningKey
        sk = SigningKey.generate()
        pk = sk.verify_key.encode()
        did = "did:aip:" + hashlib.sha256(pk).hexdigest()[:32]
        pk_b64 = base64.b64encode(pk).decode()
        database.register_did(did, pk_b64)

        resp = client.get(f"/admin/registrations/{did}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("registration", data)
        self.assertIn("vouches_given", data)
        self.assertIn("vouches_received", data)

    def test_stats_endpoint(self):
        """Test /stats returns network statistics."""
        resp = client.get("/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("service", data)
        self.assertIn("status", data)
        self.assertEqual(data["status"], "operational")
        self.assertIn("stats", data)
        stats = data["stats"]
        self.assertIn("registrations", stats)
        self.assertIn("active_vouches", stats)
        self.assertIn("messages", stats)
        self.assertIn("by_platform", stats)
        self.assertIn("growth", stats)
        self.assertIn("registrations_last_7d", stats)
        self.assertIn("vouches_last_7d", stats)

    def test_stats_with_data(self):
        """Test /stats counts correctly after inserting data."""
        import hashlib, base64
        from nacl.signing import SigningKey
        sk = SigningKey.generate()
        pk = sk.verify_key.encode()
        did = "did:aip:" + hashlib.sha256(pk).hexdigest()[:32]
        pk_b64 = base64.b64encode(pk).decode()
        database.register_did(did, pk_b64)
        database.add_platform_link(did, "moltbook", "StatsTest")

        resp = client.get("/stats")
        data = resp.json()
        stats = data["stats"]
        self.assertGreaterEqual(stats["registrations"], 1)
        self.assertIn("moltbook", stats["by_platform"])

    def test_pagination(self):
        resp = client.get("/admin/registrations?limit=1&offset=0")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["limit"], 1)
        self.assertLessEqual(data["count"], 1)


if __name__ == "__main__":
    unittest.main()
