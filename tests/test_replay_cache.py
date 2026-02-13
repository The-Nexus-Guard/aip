#!/usr/bin/env python3
"""
Replay Cache Tests

Tests that replay cache is properly stored in database and survives restarts.
"""

import sys
import os
import time
from pathlib import Path

# Add paths
sys.path.insert(0, str(Path(__file__).parent.parent / "service"))

# Disable rate limiting for tests
os.environ["AIP_TESTING"] = "1"

# Set test database
import tempfile
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix=".db")
os.close(_test_db_fd)
os.environ["AIP_DATABASE_PATH"] = _test_db_path

import database


def test_replay_cache_persists_across_restart():
    """Test that replay cache survives 'restart' (clears in-memory state, but DB persists)."""
    # Initialize database
    database.init_database()
    
    sig_hash = "test_sig_hash_12345"
    expires_at = time.time() + 300  # 5 minutes from now
    
    # First check - should insert and return False (not a replay)
    is_replay = database.check_replay(sig_hash, expires_at)
    assert is_replay == False, "First check should not be a replay"
    
    # Second check immediately - should return True (replay detected)
    is_replay = database.check_replay(sig_hash, expires_at)
    assert is_replay == True, "Second check should detect replay"
    
    # Simulate restart by getting a fresh connection
    # The signature should still be in the DB
    with database.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT sig_hash FROM replay_cache WHERE sig_hash = ?", (sig_hash,))
        row = cursor.fetchone()
        assert row is not None, "Signature should persist in database"
        assert row["sig_hash"] == sig_hash
    
    print("✓ Replay cache persists across restart")


def test_replay_cache_cleanup():
    """Test that expired replay cache entries are removed."""
    # Initialize database
    database.init_database()
    
    # Insert expired and non-expired entries
    expired_sig = "expired_sig_hash"
    valid_sig = "valid_sig_hash"
    
    now = time.time()
    expired_time = now - 100  # 100 seconds ago (expired)
    valid_time = now + 300    # 5 minutes in future
    
    with database.get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO replay_cache (sig_hash, expires_at) VALUES (?, ?)",
            (expired_sig, expired_time)
        )
        conn.execute(
            "INSERT OR REPLACE INTO replay_cache (sig_hash, expires_at) VALUES (?, ?)",
            (valid_sig, valid_time)
        )
        conn.commit()
    
    # Run cleanup
    removed_count = database.cleanup_replay_cache()
    
    # Should have removed at least 1 (the expired one)
    assert removed_count >= 1, f"Should have removed at least 1 expired entry, removed {removed_count}"
    
    # Check that expired entry is gone
    with database.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT sig_hash FROM replay_cache WHERE sig_hash = ?", (expired_sig,))
        assert cursor.fetchone() is None, "Expired entry should be removed"
        
        cursor.execute("SELECT sig_hash FROM replay_cache WHERE sig_hash = ?", (valid_sig,))
        assert cursor.fetchone() is not None, "Valid entry should remain"
    
    print("✓ Replay cache cleanup removes expired entries")


def test_demos_directory_removed():
    """Test that vouch_demo.py has been removed."""
    demos_path = Path(__file__).parent.parent / "demos" / "vouch_demo.py"
    assert not demos_path.exists(), "demos/vouch_demo.py should be deleted"
    print("✓ vouch_demo.py removed")


def teardown_module(module):
    """Cleanup test database."""
    if os.path.exists(_test_db_path):
        os.unlink(_test_db_path)


if __name__ == "__main__":
    print("Running replay cache tests...")
    test_replay_cache_persists_across_restart()
    test_replay_cache_cleanup()
    test_demos_directory_removed()
    teardown_module(None)
    print("\n✅ All replay cache tests passed!")
