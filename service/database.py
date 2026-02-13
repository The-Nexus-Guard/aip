"""
Database operations for AIP service.

Uses SQLite for simplicity and portability.
"""

import sqlite3
import os
from datetime import datetime, timedelta, timezone
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
        conn.execute("PRAGMA journal_mode=WAL")
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

        # Migration: add verified column to platform_links (default False)
        try:
            cursor.execute("ALTER TABLE platform_links ADD COLUMN verified BOOLEAN DEFAULT 0")
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

        # Key history table - tracks all keys ever associated with a DID
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS key_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                did TEXT NOT NULL,
                public_key TEXT NOT NULL,
                valid_from TEXT NOT NULL,
                valid_until TEXT,
                is_current BOOLEAN NOT NULL DEFAULT 1,
                FOREIGN KEY (did) REFERENCES registrations(did)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_history_did ON key_history(did)")

        # Backfill key_history for existing registrations that have no history entry
        cursor.execute("""
            INSERT INTO key_history (did, public_key, valid_from, is_current)
            SELECT r.did, r.public_key, r.created_at, 1
            FROM registrations r
            WHERE NOT EXISTS (SELECT 1 FROM key_history kh WHERE kh.did = r.did)
        """)

        # Rate limits table - database-backed rate limiting
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT NOT NULL,
                window_start INTEGER NOT NULL,
                count INTEGER DEFAULT 1,
                PRIMARY KEY (key, window_start)
            )
        """)

        # Webhooks table - notification callbacks for events
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id TEXT PRIMARY KEY,
                owner_did TEXT NOT NULL,
                url TEXT NOT NULL,
                events TEXT NOT NULL DEFAULT 'registration',
                secret TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_triggered_at TIMESTAMP,
                failure_count INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT 1,
                FOREIGN KEY (owner_did) REFERENCES registrations(did)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_owner ON webhooks(owner_did)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks(active)")

        # Webhook delivery logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                id TEXT PRIMARY KEY,
                webhook_id TEXT NOT NULL,
                event TEXT NOT NULL,
                status_code INTEGER,
                success BOOLEAN NOT NULL,
                error TEXT,
                duration_ms INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_wid ON webhook_deliveries(webhook_id)")

        # Agent profiles table - optional metadata
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                did TEXT PRIMARY KEY,
                display_name TEXT,
                bio TEXT,
                avatar_url TEXT,
                website TEXT,
                tags TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (did) REFERENCES registrations(did)
            )
        """)

        # Add last_active column to registrations (migration)
        try:
            cursor.execute("ALTER TABLE registrations ADD COLUMN last_active TIMESTAMP")
        except sqlite3.OperationalError:
            pass  # Column already exists

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
            # Record initial key in key history
            cursor.execute(
                """INSERT INTO key_history (did, public_key, valid_from, is_current)
                   VALUES (?, ?, ?, 1)""",
                (did, public_key, datetime.now(tz=timezone.utc).isoformat())
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
            "SELECT did, public_key, created_at, last_active FROM registrations WHERE did = ?",
            (did,)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def touch_activity(did: str) -> None:
    """Update last_active timestamp for a DID."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE registrations SET last_active = ? WHERE did = ?",
            (datetime.now(tz=timezone.utc).isoformat(), did)
        )
        conn.commit()


def rotate_key(did: str, new_public_key: str) -> bool:
    """Rotate the public key for a DID.

    Preserves key history: the old key is marked as no longer current,
    and the new key is recorded. The DID remains bound to the original key
    (it was derived from the first key at registration time).

    Args:
        did: The DID to rotate keys for
        new_public_key: The new base64-encoded public key

    Returns:
        True if rotation succeeded
    """
    now = datetime.now(tz=timezone.utc).isoformat()
    with get_connection() as conn:
        cursor = conn.cursor()

        # Mark all current keys as no longer current
        cursor.execute(
            "UPDATE key_history SET is_current = 0, valid_until = ? WHERE did = ? AND is_current = 1",
            (now, did)
        )

        # Insert new key into history
        cursor.execute(
            "INSERT INTO key_history (did, public_key, valid_from, is_current) VALUES (?, ?, ?, 1)",
            (did, new_public_key, now)
        )

        # Update the current key in registrations
        cursor.execute(
            "UPDATE registrations SET public_key = ? WHERE did = ?",
            (new_public_key, did)
        )
        success = cursor.rowcount > 0
        conn.commit()
        return success


def get_key_history(did: str) -> List[Dict[str, Any]]:
    """Get the full key history for a DID.

    Returns:
        List of key records ordered by valid_from, newest first
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT public_key, valid_from, valid_until, is_current
               FROM key_history WHERE did = ? ORDER BY valid_from DESC""",
            (did,)
        )
        return [dict(row) for row in cursor.fetchall()]


def mark_key_compromised(did: str) -> int:
    """Mark a DID's key as compromised, revoking all vouches made by it.

    Args:
        did: The DID whose key was compromised

    Returns:
        Number of vouches revoked
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.now(tz=timezone.utc).isoformat()
        cursor.execute(
            """UPDATE vouches SET revoked_at = ?
               WHERE voucher_did = ? AND revoked_at IS NULL""",
            (now, did)
        )
        count = cursor.rowcount
        conn.commit()
        return count


def add_platform_link(did: str, platform: str, username: str, proof_post_id: Optional[str] = None, verified: bool = False) -> bool:
    """Link a DID to a platform identity."""
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO platform_links (did, platform, username, proof_post_id, verified)
                   VALUES (?, ?, ?, ?, ?)""",
                (did, platform, username, proof_post_id, 1 if verified else 0)
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
            """SELECT platform, username, proof_post_id, registered_at, verified
               FROM platform_links WHERE did = ?""",
            (did,)
        )
        return [dict(row) for row in cursor.fetchall()]


def set_platform_verified(did: str, platform: str, username: str, proof_post_id: Optional[str] = None) -> bool:
    """Mark a platform link as verified."""
    with get_connection() as conn:
        cursor = conn.cursor()
        if proof_post_id:
            cursor.execute(
                """UPDATE platform_links SET verified = 1, proof_post_id = ?
                   WHERE did = ? AND platform = ? AND username = ?""",
                (proof_post_id, did, platform, username)
            )
        else:
            cursor.execute(
                """UPDATE platform_links SET verified = 1
                   WHERE did = ? AND platform = ? AND username = ?""",
                (did, platform, username)
            )
        conn.commit()
        return cursor.rowcount > 0


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
    expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in_seconds)
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


def cleanup_expired_challenges() -> int:
    """Remove expired challenges.

    Returns:
        Number of challenges removed
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM challenges WHERE expires_at < ?",
            (datetime.now(tz=timezone.utc).isoformat(),)
        )
        count = cursor.rowcount
        conn.commit()
        return count


# Vouch operations

def has_active_vouch(voucher_did: str, target_did: str, scope: str) -> bool:
    """Check if an active (non-revoked, non-expired) vouch exists for the given triple."""
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.now(tz=timezone.utc).isoformat()
        cursor.execute(
            """SELECT 1 FROM vouches
               WHERE voucher_did = ? AND target_did = ? AND scope = ?
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?)
               LIMIT 1""",
            (voucher_did, target_did, scope, now)
        )
        return cursor.fetchone() is not None


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
        expires_at = (datetime.now(tz=timezone.utc) + timedelta(days=ttl_days)).isoformat()

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
        now = datetime.now(tz=timezone.utc).isoformat()
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
        now = datetime.now(tz=timezone.utc).isoformat()
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
        now = datetime.now(tz=timezone.utc).isoformat()
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
            (datetime.now(tz=timezone.utc).isoformat(), vouch_id, voucher_did)
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
            (datetime.now(tz=timezone.utc).isoformat(), message_id, recipient_did)
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
        now = datetime.now(tz=timezone.utc).isoformat()

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

            # Compute last_activity from vouches/messages/profile updates
            cursor.execute(
                """SELECT MAX(ts) as last_activity FROM (
                    SELECT MAX(created_at) as ts FROM vouches WHERE voucher_did = ? OR target_did = ?
                    UNION ALL
                    SELECT MAX(created_at) as ts FROM messages WHERE sender_did = ? OR recipient_did = ?
                    UNION ALL
                    SELECT MAX(updated_at) as ts FROM profiles WHERE did = ?
                    UNION ALL
                    SELECT last_active as ts FROM registrations WHERE did = ?
                )""",
                (reg["did"], reg["did"], reg["did"], reg["did"], reg["did"], reg["did"])
            )
            activity_row = cursor.fetchone()
            reg["last_activity"] = activity_row["last_activity"] if activity_row and activity_row["last_activity"] else reg["created_at"]

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

        # Count messages
        cursor.execute("SELECT COUNT(*) as count FROM messages")
        total_messages = cursor.fetchone()["count"]

        # Count skill signatures (table may not exist in older DBs)
        try:
            cursor.execute("SELECT COUNT(*) as count FROM skill_signatures")
            total_signatures = cursor.fetchone()["count"]
        except Exception:
            total_signatures = 0

        # Growth: registrations per day (last 30 days)
        cursor.execute("""
            SELECT DATE(created_at) as day, COUNT(*) as count
            FROM registrations
            WHERE created_at >= datetime('now', '-30 days')
            GROUP BY DATE(created_at)
            ORDER BY day
        """)
        daily_registrations = [{"date": row["day"], "count": row["count"]} for row in cursor.fetchall()]

        return {
            "registrations": total_registrations,
            "platform_links": total_links,
            "by_platform": by_platform,
            "active_vouches": active_vouches,
            "verifications_completed": verifications,
            "messages": total_messages,
            "skill_signatures": total_signatures,
            "growth": {
                "daily_registrations": daily_registrations
            }
        }


# Message cleanup operations

MESSAGE_TTL_DAYS = 30
MAX_INBOX_SIZE = 1000


def cleanup_old_messages(ttl_days: int = MESSAGE_TTL_DAYS) -> int:
    """Delete read messages older than ttl_days.

    Returns:
        Number of messages deleted
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=ttl_days)).isoformat()
        cursor.execute(
            "DELETE FROM messages WHERE read_at IS NOT NULL AND created_at < ?",
            (cutoff,)
        )
        count = cursor.rowcount
        conn.commit()
        return count


def enforce_inbox_limits(max_size: int = MAX_INBOX_SIZE) -> int:
    """Trim inboxes that exceed max_size, deleting oldest read messages first,
    then oldest unread messages.

    Returns:
        Total number of messages deleted across all inboxes
    """
    total_deleted = 0
    with get_connection() as conn:
        cursor = conn.cursor()
        # Find DIDs with oversized inboxes
        cursor.execute(
            """SELECT recipient_did, COUNT(*) as cnt
               FROM messages GROUP BY recipient_did HAVING cnt > ?""",
            (max_size,)
        )
        oversized = cursor.fetchall()

        for row in oversized:
            did = row["recipient_did"]
            excess = row["cnt"] - max_size
            # Delete oldest read messages first, then oldest unread
            cursor.execute(
                """DELETE FROM messages WHERE id IN (
                    SELECT id FROM messages WHERE recipient_did = ?
                    ORDER BY
                        CASE WHEN read_at IS NOT NULL THEN 0 ELSE 1 END,
                        created_at ASC
                    LIMIT ?
                )""",
                (did, excess)
            )
            total_deleted += cursor.rowcount

        conn.commit()
    return total_deleted


def run_all_cleanup() -> Dict[str, int]:
    """Run all cleanup tasks and return stats."""
    expired_challenges = 0
    expired_vouches = 0
    old_messages = 0
    trimmed_messages = 0

    try:
        expired_challenges = cleanup_expired_challenges()
    except Exception:
        pass

    try:
        expired_vouches = cleanup_expired_vouches()
    except Exception:
        pass

    try:
        old_messages = cleanup_old_messages()
    except Exception:
        pass

    try:
        trimmed_messages = enforce_inbox_limits()
    except Exception:
        pass

    return {
        "expired_challenges_removed": expired_challenges,
        "expired_vouches_removed": expired_vouches,
        "old_messages_removed": old_messages,
        "inbox_trimmed_messages": trimmed_messages,
    }


# Webhook operations

def add_webhook(webhook_id: str, owner_did: str, url: str, events: str = "registration", secret: Optional[str] = None) -> bool:
    """Register a new webhook."""
    with get_connection() as conn:
        try:
            conn.execute(
                "INSERT INTO webhooks (id, owner_did, url, events, secret) VALUES (?, ?, ?, ?, ?)",
                (webhook_id, owner_did, url, events, secret)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def get_webhooks_for_event(event: str) -> List[Dict[str, Any]]:
    """Get all active webhooks that subscribe to a given event."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM webhooks WHERE active = 1 AND failure_count < 5"
        )
        rows = cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            subscribed_events = d.get("events", "").split(",")
            if event in subscribed_events or "*" in subscribed_events:
                result.append(d)
        return result


def get_webhooks_by_owner(owner_did: str) -> List[Dict[str, Any]]:
    """Get all webhooks owned by a DID."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM webhooks WHERE owner_did = ?", (owner_did,))
        return [dict(row) for row in cursor.fetchall()]


def delete_webhook(webhook_id: str, owner_did: str) -> bool:
    """Delete a webhook (owner must match)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM webhooks WHERE id = ? AND owner_did = ?", (webhook_id, owner_did))
        conn.commit()
        return cursor.rowcount > 0


def update_webhook_status(webhook_id: str, success: bool):
    """Update webhook after trigger attempt."""
    with get_connection() as conn:
        if success:
            conn.execute(
                "UPDATE webhooks SET last_triggered_at = CURRENT_TIMESTAMP, failure_count = 0 WHERE id = ?",
                (webhook_id,)
            )
        else:
            conn.execute(
                "UPDATE webhooks SET failure_count = failure_count + 1 WHERE id = ?",
                (webhook_id,)
            )
        conn.commit()


def log_webhook_delivery(webhook_id: str, event: str, success: bool,
                         status_code: Optional[int] = None, error: Optional[str] = None,
                         duration_ms: Optional[int] = None) -> str:
    """Log a webhook delivery attempt."""
    delivery_id = str(__import__('uuid').uuid4())
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO webhook_deliveries (id, webhook_id, event, status_code, success, error, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (delivery_id, webhook_id, event, status_code, success, error, duration_ms)
        )
        conn.commit()
    return delivery_id


def get_webhook_deliveries(webhook_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Get recent delivery logs for a webhook."""
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT id, webhook_id, event, status_code, success, error, duration_ms, created_at
               FROM webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC LIMIT ?""",
            (webhook_id, limit)
        ).fetchall()
        return [dict(r) for r in rows]


# Profile operations

PROFILE_FIELDS = {"display_name", "bio", "avatar_url", "website", "tags"}
MAX_BIO_LENGTH = 500
MAX_FIELD_LENGTH = 200
MAX_TAGS = 10


def get_profile(did: str) -> Optional[Dict[str, Any]]:
    """Get an agent's profile."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT did, display_name, bio, avatar_url, website, tags, updated_at FROM profiles WHERE did = ?",
            (did,)
        )
        row = cursor.fetchone()
        if row:
            profile = dict(row)
            # Parse tags from comma-separated string
            profile["tags"] = [t.strip() for t in (profile["tags"] or "").split(",") if t.strip()]
            return profile
        return None


def upsert_profile(did: str, **fields) -> bool:
    """Create or update an agent's profile. Only known fields are accepted.

    Args:
        did: The DID whose profile to update
        **fields: Profile fields (display_name, bio, avatar_url, website, tags)

    Returns:
        True if profile was created/updated
    """
    # Filter to allowed fields only
    safe_fields = {k: v for k, v in fields.items() if k in PROFILE_FIELDS and v is not None}
    if not safe_fields:
        return False

    # Validate lengths
    if "bio" in safe_fields and len(safe_fields["bio"]) > MAX_BIO_LENGTH:
        raise ValueError(f"Bio must be {MAX_BIO_LENGTH} characters or less")
    for field in ("display_name", "avatar_url", "website"):
        if field in safe_fields and len(safe_fields[field]) > MAX_FIELD_LENGTH:
            raise ValueError(f"{field} must be {MAX_FIELD_LENGTH} characters or less")

    # Convert tags list to comma-separated string
    if "tags" in safe_fields:
        if isinstance(safe_fields["tags"], list):
            if len(safe_fields["tags"]) > MAX_TAGS:
                raise ValueError(f"Maximum {MAX_TAGS} tags allowed")
            safe_fields["tags"] = ",".join(safe_fields["tags"][:MAX_TAGS])

    now = datetime.now(tz=timezone.utc).isoformat()
    safe_fields["updated_at"] = now

    with get_connection() as conn:
        cursor = conn.cursor()
        # Check if profile exists
        cursor.execute("SELECT 1 FROM profiles WHERE did = ?", (did,))
        exists = cursor.fetchone() is not None

        if exists:
            set_clause = ", ".join(f"{k} = ?" for k in safe_fields)
            values = list(safe_fields.values()) + [did]
            cursor.execute(f"UPDATE profiles SET {set_clause} WHERE did = ?", values)
        else:
            safe_fields["did"] = did
            cols = ", ".join(safe_fields.keys())
            placeholders = ", ".join("?" for _ in safe_fields)
            cursor.execute(f"INSERT INTO profiles ({cols}) VALUES ({placeholders})", list(safe_fields.values()))

        conn.commit()
        return True


def delete_profile(did: str) -> bool:
    """Delete an agent's profile."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM profiles WHERE did = ?", (did,))
        conn.commit()
        return cursor.rowcount > 0


# Initialize on import
init_database()
