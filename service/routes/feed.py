"""Trust event feed — public JSON and Atom feed of AIP network activity."""

from fastapi import APIRouter, Query, Response
from database import get_connection
from datetime import datetime, timezone
import json

router = APIRouter(tags=["Feed"])


def _get_events(limit: int = 50, since: str = None, event_type: str = None):
    """Query recent trust events from the database."""
    events = []

    with get_connection() as conn:
        cursor = conn.cursor()

        # Registrations
        if event_type is None or event_type == "registration":
            q = """
                SELECT r.did, r.created_at, p.platform, p.username,
                       pr.display_name
                FROM registrations r
                LEFT JOIN platform_links p ON r.did = p.did
                LEFT JOIN profiles pr ON r.did = pr.did
            """
            params = []
            if since:
                q += " WHERE r.created_at > ?"
                params.append(since)
            q += " ORDER BY r.created_at DESC LIMIT ?"
            params.append(limit)
            rows = cursor.execute(q, params).fetchall()
            for row in rows:
                events.append({
                    "type": "registration",
                    "did": row["did"],
                    "timestamp": row["created_at"],
                    "platform": row["platform"],
                    "username": row["username"],
                    "display_name": row["display_name"],
                })

        # Vouches
        if event_type is None or event_type == "vouch":
            q = """
                SELECT voucher_did, target_did, scope, statement, created_at
                FROM vouches
                WHERE revoked_at IS NULL
            """
            params = []
            if since:
                q += " AND created_at > ?"
                params.append(since)
            q += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = cursor.execute(q, params).fetchall()
            for row in rows:
                events.append({
                    "type": "vouch",
                    "voucher": row["voucher_did"],
                    "vouched": row["target_did"],
                    "scope": row["scope"],
                    "statement": row["statement"],
                    "timestamp": row["created_at"],
                })

        # Revocations
        if event_type is None or event_type == "revocation":
            q = """
                SELECT voucher_did, target_did, scope, revoked_at
                FROM vouches
                WHERE revoked_at IS NOT NULL
            """
            params = []
            if since:
                q += " AND revoked_at > ?"
                params.append(since)
            q += " ORDER BY revoked_at DESC LIMIT ?"
            params.append(limit)
            rows = cursor.execute(q, params).fetchall()
            for row in rows:
                events.append({
                    "type": "revocation",
                    "voucher": row["voucher_did"],
                    "vouched": row["target_did"],
                    "scope": row["scope"],
                    "timestamp": row["revoked_at"],
                })

    # Sort by timestamp descending, take limit
    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return events[:limit]


@router.get("/feed")
async def trust_feed(
    limit: int = Query(50, ge=1, le=200),
    since: str = Query(None, description="ISO timestamp — only events after this time"),
    type: str = Query(None, description="Filter: registration, vouch, revocation"),
    format: str = Query("json", description="Output format: json or atom"),
):
    """Public feed of AIP trust events.

    Returns recent registrations, vouches, and revocations.
    Use `since` for incremental polling. Use `format=atom` for RSS readers.
    """
    events = _get_events(limit=limit, since=since, event_type=type)

    if format == "atom":
        return Response(
            content=_to_atom(events),
            media_type="application/atom+xml",
        )

    return {
        "events": events,
        "count": len(events),
        "feed_url": "https://aip-service.fly.dev/feed",
        "format": "json",
    }


def _to_atom(events):
    """Convert events to Atom XML feed."""
    now = datetime.now(timezone.utc).isoformat()
    entries = []
    for e in events:
        etype = e["type"]
        ts = e.get("timestamp", now)

        if etype == "registration":
            name = e.get("display_name") or e.get("username") or e["did"][:20]
            title = f"New agent registered: {name}"
            content = f"DID: {e['did']}\nPlatform: {e.get('platform', '?')}/{e.get('username', '?')}"
        elif etype == "vouch":
            title = f"Vouch: {e['voucher'][:20]}... → {e['vouched'][:20]}..."
            content = f"Scope: {e.get('scope', 'GENERAL')}\nStatement: {e.get('statement', '')}"
        elif etype == "revocation":
            title = f"Revocation: {e['voucher'][:20]}... revoked {e['vouched'][:20]}..."
            content = f"Scope: {e.get('scope', 'GENERAL')}"
        else:
            continue

        entry_id = f"urn:aip:event:{etype}:{ts}"
        entries.append(f"""  <entry>
    <title>{_xml_escape(title)}</title>
    <id>{entry_id}</id>
    <updated>{ts}</updated>
    <content type="text">{_xml_escape(content)}</content>
    <category term="{etype}"/>
  </entry>""")

    return f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>AIP Trust Network Feed</title>
  <link href="https://aip-service.fly.dev/feed?format=atom" rel="self"/>
  <link href="https://the-nexus-guard.github.io/aip/"/>
  <id>urn:aip:feed:trust-events</id>
  <updated>{now}</updated>
  <subtitle>Real-time trust events from the Agent Identity Protocol network</subtitle>
{chr(10).join(entries)}
</feed>"""


def _xml_escape(s):
    """Basic XML escaping."""
    if not s:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
