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
                expires_at TIMESTAMP,
                revoked_at TIMESTAMP,
                FOREIGN KEY (voucher_did) REFERENCES registrations(did),
                FOREIGN KEY (target_did) REFERENCES registrations(did)
            )
        """)

        # Migration: add expires_at column if missing (for existing databases)
        try:
            cursor.execute("ALTER TABLE vouches ADD COLUMN expires_at TIMESTAMP")
        except sqlite3.OperationalError:
            pass  # Column already exists

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

        # Messages table - encrypted agent-to-agent messages
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender_did TEXT NOT NULL,
                recipient_did TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                FOREIGN KEY (sender_did) REFERENCES registrations(did),
                FOREIGN KEY (recipient_did) REFERENCES registrations(did)
            )
        """)

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_platform_links_did ON platform_links(did)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vouches_voucher ON vouches(voucher_did)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vouches_target ON vouches(target_did)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_did)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_did)")

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


def rotate_key(did: str, new_public_key: str) -> bool:
    """Rotate the public key for a DID.

    Args:
        did: The DID to rotate keys for
        new_public_key: The new base64-encoded public key

    Returns:
        True if rotation succeeded
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE registrations SET public_key = ? WHERE did = ?",
            (new_public_key, did)
        )
        conn.commit()
        return cursor.rowcount > 0


def mark_key_compromised(did: str) -> int:
    """Mark a DID's key as compromised, revoking all vouches made by it.

    Args:
        did: The DID whose key was compromised

    Returns:
        Number of vouches revoked
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute(
            """UPDATE vouches SET revoked_at = ?
               WHERE voucher_did = ? AND revoked_at IS NULL""",
            (now, did)
        )
        count = cursor.rowcount
        conn.commit()
        return count


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
                 scope: str, statement: str, signature: str,
                 ttl_days: Optional[int] = None) -> bool:
    """Create a new vouch.

    Args:
        vouch_id: Unique ID for the vouch
        voucher_did: DID of the agent vouching
        target_did: DID being vouched for
        scope: Trust scope (GENERAL, CODE_SIGNING, etc.)
        statement: Optional trust statement
        signature: Signature proving voucher identity
        ttl_days: Optional time-to-live in days (None = permanent)

    Returns:
        True if vouch was created successfully
    """
    expires_at = None
    if ttl_days is not None and ttl_days > 0:
        expires_at = (datetime.utcnow() + timedelta(days=ttl_days)).isoformat()

    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO vouches (id, voucher_did, target_did, scope, statement, signature, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (vouch_id, voucher_did, target_did, scope, statement, signature, expires_at)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def get_vouches_for(did: str, include_expired: bool = False) -> List[Dict[str, Any]]:
    """Get vouches where this DID is the target (others vouching for them).

    Args:
        did: Target DID
        include_expired: If True, include expired vouches

    Returns:
        List of active vouches for this DID
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        if include_expired:
            cursor.execute(
                """SELECT id, voucher_did, scope, statement, created_at, expires_at
                   FROM vouches WHERE target_did = ? AND revoked_at IS NULL""",
                (did,)
            )
        else:
            cursor.execute(
                """SELECT id, voucher_did, scope, statement, created_at, expires_at
                   FROM vouches WHERE target_did = ? AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > ?)""",
                (did, now)
            )
        return [dict(row) for row in cursor.fetchall()]


def get_vouches_by(did: str, include_expired: bool = False) -> List[Dict[str, Any]]:
    """Get vouches where this DID is the voucher (they vouching for others).

    Args:
        did: Voucher DID
        include_expired: If True, include expired vouches

    Returns:
        List of active vouches by this DID
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        if include_expired:
            cursor.execute(
                """SELECT id, target_did, scope, statement, created_at, expires_at
                   FROM vouches WHERE voucher_did = ? AND revoked_at IS NULL""",
                (did,)
            )
        else:
            cursor.execute(
                """SELECT id, target_did, scope, statement, created_at, expires_at
                   FROM vouches WHERE voucher_did = ? AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > ?)""",
                (did, now)
            )
        return [dict(row) for row in cursor.fetchall()]


def cleanup_expired_vouches() -> int:
    """Remove expired vouches from database.

    Returns:
        Number of vouches cleaned up
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute(
            "DELETE FROM vouches WHERE expires_at IS NOT NULL AND expires_at < ?",
            (now,)
        )
        count = cursor.rowcount
        conn.commit()
        return count


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


# Message operations

def store_message(message_id: str, sender_did: str, recipient_did: str,
                  encrypted_content: str, signature: str) -> bool:
    """Store an encrypted message."""
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO messages (id, sender_did, recipient_did, encrypted_content, signature)
                   VALUES (?, ?, ?, ?, ?)""",
                (message_id, sender_did, recipient_did, encrypted_content, signature)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def get_messages_for(recipient_did: str, unread_only: bool = False) -> List[Dict[str, Any]]:
    """Get messages for a recipient."""
    with get_connection() as conn:
        cursor = conn.cursor()
        if unread_only:
            cursor.execute(
                """SELECT id, sender_did, encrypted_content, signature, created_at
                   FROM messages WHERE recipient_did = ? AND read_at IS NULL
                   ORDER BY created_at DESC""",
                (recipient_did,)
            )
        else:
            cursor.execute(
                """SELECT id, sender_did, encrypted_content, signature, created_at, read_at
                   FROM messages WHERE recipient_did = ?
                   ORDER BY created_at DESC LIMIT 100""",
                (recipient_did,)
            )
        return [dict(row) for row in cursor.fetchall()]


def mark_message_read(message_id: str, recipient_did: str) -> bool:
    """Mark a message as read. Only recipient can mark."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE messages SET read_at = ?
               WHERE id = ? AND recipient_did = ? AND read_at IS NULL""",
            (datetime.utcnow().isoformat(), message_id, recipient_did)
        )
        conn.commit()
        return cursor.rowcount > 0


def delete_message(message_id: str, recipient_did: str) -> bool:
    """Delete a message. Only recipient can delete."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM messages WHERE id = ? AND recipient_did = ?",
            (message_id, recipient_did)
        )
        conn.commit()
        return cursor.rowcount > 0


def get_message_count(did: str) -> Dict[str, int]:
    """Get message counts for a DID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) as count FROM messages WHERE recipient_did = ? AND read_at IS NULL",
            (did,)
        )
        unread = cursor.fetchone()["count"]
        cursor.execute(
            "SELECT COUNT(*) as count FROM messages WHERE sender_did = ?",
            (did,)
        )
        sent = cursor.fetchone()["count"]
        return {"unread": unread, "sent": sent}


# Trust path operations

def find_trust_path(source_did: str, target_did: str, scope: Optional[str] = None, max_depth: int = 5) -> Optional[List[Dict[str, Any]]]:
    """Find a trust path from source to target DID via vouches.

    Uses BFS to find the shortest path. Returns list of vouches forming the path,
    or None if no path exists within max_depth.

    Args:
        source_did: Starting DID (the one who wants to verify trust)
        target_did: Ending DID (the one being verified)
        scope: Optional scope filter - only follow vouches with this scope
        max_depth: Maximum path length to search (default 5)

    Returns:
        List of vouch dicts forming the path, or None if no path exists
    """
    if source_did == target_did:
        return []  # Already at target

    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()

        # BFS state
        visited = {source_did}
        queue = [(source_did, [])]  # (current_did, path_so_far)

        while queue:
            current_did, path = queue.pop(0)

            if len(path) >= max_depth:
                continue

            # Get vouches FROM current_did (who they vouch for)
            if scope:
                cursor.execute(
                    """SELECT id, voucher_did, target_did, scope, statement, created_at, expires_at
                       FROM vouches
                       WHERE voucher_did = ? AND scope = ? AND revoked_at IS NULL
                       AND (expires_at IS NULL OR expires_at > ?)""",
                    (current_did, scope, now)
                )
            else:
                cursor.execute(
                    """SELECT id, voucher_did, target_did, scope, statement, created_at, expires_at
                       FROM vouches
                       WHERE voucher_did = ? AND revoked_at IS NULL
                       AND (expires_at IS NULL OR expires_at > ?)""",
                    (current_did, now)
                )

            for row in cursor.fetchall():
                vouch = dict(row)
                next_did = vouch["target_did"]

                if next_did == target_did:
                    # Found the target
                    return path + [vouch]

                if next_did not in visited:
                    visited.add(next_did)
                    queue.append((next_did, path + [vouch]))

        return None  # No path found


# List operations

def list_registrations(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """List all registrations with their platform links.

    Args:
        limit: Maximum number of results (default 100)
        offset: Offset for pagination (default 0)

    Returns:
        List of registration dicts with platform links
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT did, public_key, created_at FROM registrations
               ORDER BY created_at DESC LIMIT ? OFFSET ?""",
            (limit, offset)
        )
        registrations = []
        for row in cursor.fetchall():
            reg = dict(row)
            # Get platform links for this DID
            cursor.execute(
                """SELECT platform, username, registered_at FROM platform_links WHERE did = ?""",
                (reg["did"],)
            )
            reg["platforms"] = [dict(link) for link in cursor.fetchall()]
            registrations.append(reg)
        return registrations


# Stats operations

def get_stats() -> Dict[str, Any]:
    """Get service statistics."""
    with get_connection() as conn:
        cursor = conn.cursor()

        # Count registrations
        cursor.execute("SELECT COUNT(*) as count FROM registrations")
        total_registrations = cursor.fetchone()["count"]

        # Count platform links
        cursor.execute("SELECT COUNT(*) as count FROM platform_links")
        total_links = cursor.fetchone()["count"]

        # Count by platform
        cursor.execute("""
            SELECT platform, COUNT(*) as count
            FROM platform_links
            GROUP BY platform
        """)
        by_platform = {row["platform"]: row["count"] for row in cursor.fetchall()}

        # Count vouches
        cursor.execute("SELECT COUNT(*) as count FROM vouches WHERE revoked_at IS NULL")
        active_vouches = cursor.fetchone()["count"]

        # Count challenges used (verifications)
        cursor.execute("SELECT COUNT(*) as count FROM challenges WHERE used = 1")
        verifications = cursor.fetchone()["count"]

        return {
            "registrations": total_registrations,
            "platform_links": total_links,
            "by_platform": by_platform,
            "active_vouches": active_vouches,
            "verifications_completed": verifications
        }


# Initialize on import
init_database()
