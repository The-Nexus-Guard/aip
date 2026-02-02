"""
Database operations for AIP service.

Uses SQLite for simplicity and portability.
"""

import sqlite3
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

DATABASE_PATH = os.environ.get("AIP_DATABASE_PATH", "aip.db")


def get_db_path():
    return DATABASE_PATH


@contextmanager
def get_connection():
    """Get a database connection with automatic cleanup."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_database():
    """Initialize the database schema."""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Registrations table - core DID records
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS registrations (
                did TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Platform links - DID to platform identity mappings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS platform_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                did TEXT NOT NULL,
                platform TEXT NOT NULL,
                username TEXT NOT NULL,
                proof_post_id TEXT,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (did) REFERENCES registrations(did),
                UNIQUE(platform, username)
            )
        """)

        # Vouches - trust statements between agents
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vouches (
                id TEXT PRIMARY KEY,
                voucher_did TEXT NOT NULL,
                target_did TEXT NOT NULL,
                scope TEXT NOT NULL,
                statement TEXT,
                signature TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                revoked_at TIMESTAMP,
                FOREIGN KEY (voucher_did) REFERENCES registrations(did),
                FOREIGN KEY (target_did) REFERENCES registrations(did)
            )
        """)

        # Challenges - for live verification
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS challenges (
                challenge TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0
            )
        """)

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_platform_links_did ON platform_links(did)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vouches_voucher ON vouches(voucher_did)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vouches_target ON vouches(target_did)")

        conn.commit()


# Registration operations

def register_did(did: str, public_key: str) -> bool:
    """Register a new DID with its public key."""
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO registrations (did, public_key) VALUES (?, ?)",
                (did, public_key)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # DID already exists


def get_registration(did: str) -> Optional[Dict[str, Any]]:
    """Get a registration by DID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT did, public_key, created_at FROM registrations WHERE did = ?",
            (did,)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def add_platform_link(did: str, platform: str, username: str, proof_post_id: Optional[str] = None) -> bool:
    """Link a DID to a platform identity."""
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO platform_links (did, platform, username, proof_post_id)
                   VALUES (?, ?, ?, ?)""",
                (did, platform, username, proof_post_id)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # Username already linked


def get_platform_links(did: str) -> List[Dict[str, Any]]:
    """Get all platform links for a DID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT platform, username, proof_post_id, registered_at
               FROM platform_links WHERE did = ?""",
            (did,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_did_by_platform(platform: str, username: str) -> Optional[str]:
    """Get DID for a platform username."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT did FROM platform_links WHERE platform = ? AND username = ?",
            (platform, username)
        )
        row = cursor.fetchone()
        if row:
            return row["did"]
        return None


# Challenge operations

def create_challenge(did: str, challenge: str, expires_in_seconds: int = 30) -> bool:
    """Create a new challenge for verification."""
    expires_at = datetime.utcnow() + timedelta(seconds=expires_in_seconds)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO challenges (challenge, did, expires_at) VALUES (?, ?, ?)",
            (challenge, did, expires_at.isoformat())
        )
        conn.commit()
        return True


def get_challenge(challenge: str) -> Optional[Dict[str, Any]]:
    """Get a challenge if it exists and is valid."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT challenge, did, created_at, expires_at, used
               FROM challenges WHERE challenge = ?""",
            (challenge,)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def mark_challenge_used(challenge: str) -> bool:
    """Mark a challenge as used."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE challenges SET used = 1 WHERE challenge = ?",
            (challenge,)
        )
        conn.commit()
        return cursor.rowcount > 0


def cleanup_expired_challenges():
    """Remove expired challenges."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM challenges WHERE expires_at < ?",
            (datetime.utcnow().isoformat(),)
        )
        conn.commit()


# Vouch operations

def create_vouch(vouch_id: str, voucher_did: str, target_did: str,
                 scope: str, statement: str, signature: str) -> bool:
    """Create a new vouch."""
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO vouches (id, voucher_did, target_did, scope, statement, signature)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (vouch_id, voucher_did, target_did, scope, statement, signature)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def get_vouches_for(did: str) -> List[Dict[str, Any]]:
    """Get vouches where this DID is the target (others vouching for them)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, voucher_did, scope, statement, created_at
               FROM vouches WHERE target_did = ? AND revoked_at IS NULL""",
            (did,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_vouches_by(did: str) -> List[Dict[str, Any]]:
    """Get vouches where this DID is the voucher (they vouching for others)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, target_did, scope, statement, created_at
               FROM vouches WHERE voucher_did = ? AND revoked_at IS NULL""",
            (did,)
        )
        return [dict(row) for row in cursor.fetchall()]


def revoke_vouch(vouch_id: str, voucher_did: str) -> bool:
    """Revoke a vouch (only the voucher can revoke)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE vouches SET revoked_at = ?
               WHERE id = ? AND voucher_did = ? AND revoked_at IS NULL""",
            (datetime.utcnow().isoformat(), vouch_id, voucher_did)
        )
        conn.commit()
        return cursor.rowcount > 0


# Initialize on import
init_database()
