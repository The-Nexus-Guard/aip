"""
Observation submission and PDR scoring endpoint.

Allows agents to submit behavioral observations (promise/delivery format)
and retrieve computed PDR scores. Observations are stored per-agent and
PDR scores are computed on demand.

Based on Nanook's PDR framework and 28-day pilot data.
"""
import hashlib
import json
import time
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

import database
from rate_limit import default_limiter

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

router = APIRouter(tags=["observations"])


# --- Models ---

class ObservationSubmit(BaseModel):
    """A single behavioral observation."""
    promised: List[str] = Field(..., description="What the agent committed to deliver")
    delivered: List[str] = Field(..., description="What the agent actually delivered")
    timestamp: Optional[str] = Field(None, description="ISO 8601 timestamp (defaults to now)")
    conditions: Optional[Dict[str, Any]] = Field(None, description="Environmental context")


class ObservationBatch(BaseModel):
    """Batch of observations submitted by an agent."""
    did: str = Field(..., description="The agent's DID (must match signature)")
    observations: List[ObservationSubmit] = Field(..., min_length=1, max_length=100)
    signature: str = Field(..., description="Ed25519 signature of the nonce")
    nonce: str = Field(..., description="Unique nonce for replay protection")


class PDRScoreResponse(BaseModel):
    """Computed PDR scores for an agent."""
    did: str
    calibration: Optional[float] = None
    robustness: Optional[float] = None
    observation_count: int = 0
    window_days: int = 0
    chain_hash: str = ""
    computed_at: str = ""


# --- Database helpers ---

def _ensure_observations_table():
    with database.get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                did TEXT NOT NULL,
                promised TEXT NOT NULL,
                delivered TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                conditions TEXT,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_observations_did
            ON observations(did)
        """)
        conn.commit()


# --- Routes ---

@router.post("/observations", response_model=dict)
async def submit_observations(batch: ObservationBatch):
    """
    Submit behavioral observations for PDR scoring.

    Agents submit what they promised vs. what they delivered.
    Requires Ed25519 signature of the nonce for authentication.
    """
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    _ensure_observations_table()

    # Verify the agent exists
    reg = database.get_registration(batch.did)
    if not reg:
        raise HTTPException(status_code=404, detail="Agent not registered")

    public_key_hex = reg["public_key"]

    # Verify signature (sign the nonce to prove ownership)
    try:
        import base64
        # Public key may be base64 or hex encoded
        try:
            pk_bytes = base64.b64decode(public_key_hex)
        except Exception:
            pk_bytes = bytes.fromhex(public_key_hex)
        verify_key = VerifyKey(pk_bytes)
        verify_key.verify(batch.nonce.encode(), bytes.fromhex(batch.signature))
    except (BadSignatureError, ValueError, Exception):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Check nonce replay
    nonce_hash = f"obs_nonce:{hashlib.sha256(batch.nonce.encode()).hexdigest()[:32]}"
    with database.get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM rate_limits WHERE key = ?", (nonce_hash,)
        ).fetchone()
        if row:
            raise HTTPException(status_code=409, detail="Nonce already used")
        conn.execute(
            "INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)",
            (nonce_hash, time.time()),
        )
        conn.commit()

    # Store observations
    now = time.time()
    inserted = 0
    with database.get_connection() as conn:
        for obs in batch.observations:
            ts = obs.timestamp or datetime.now(tz=__import__("datetime").timezone.utc).isoformat()
            conditions_json = json.dumps(obs.conditions) if obs.conditions else None
            conn.execute(
                "INSERT INTO observations (did, promised, delivered, timestamp, conditions, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (batch.did, json.dumps(obs.promised), json.dumps(obs.delivered),
                 ts, conditions_json, now),
            )
            inserted += 1
        conn.commit()

    return {
        "status": "ok",
        "observations_stored": inserted,
        "did": batch.did,
    }


@router.get("/observations/{did}/scores", response_model=PDRScoreResponse)
async def get_pdr_scores(
    did: str,
    window_days: int = Query(28, ge=1, le=365, description="Scoring window in days"),
):
    """
    Get computed PDR scores for an agent based on stored observations.
    Scores are computed on demand from the observation history.
    """
    from aip_identity.pdr import Observation, compute_pdr_from_promises

    _ensure_observations_table()

    with database.get_connection() as conn:
        rows = conn.execute(
            "SELECT promised, delivered, timestamp, conditions FROM observations "
            "WHERE did = ? ORDER BY timestamp ASC",
            (did,),
        ).fetchall()

    if not rows:
        return PDRScoreResponse(
            did=did,
            observation_count=0,
            computed_at=datetime.now(tz=__import__("datetime").timezone.utc).isoformat(),
        )

    # Convert to Observation objects
    observations = []
    for row in rows:
        try:
            promised = json.loads(row["promised"])
            delivered = json.loads(row["delivered"])
            conditions = json.loads(row["conditions"]) if row["conditions"] else None
            timestamp = datetime.fromisoformat(row["timestamp"])
            observations.append(Observation.from_promises(
                agent_id=did,
                timestamp=timestamp,
                promised=promised,
                delivered=delivered,
                conditions=conditions,
            ))
        except (json.JSONDecodeError, ValueError):
            continue

    scores = compute_pdr_from_promises(observations)

    return PDRScoreResponse(
        did=did,
        calibration=scores.calibration,
        robustness=scores.robustness,
        observation_count=scores.observation_count,
        window_days=scores.window_days,
        chain_hash=scores.chain_hash,
        computed_at=datetime.now(tz=__import__("datetime").timezone.utc).isoformat(),
    )


@router.get("/observations/{did}", response_model=dict)
async def get_observations(
    did: str,
    limit: int = Query(50, ge=1, le=200),
):
    """Get stored observations for an agent."""
    _ensure_observations_table()

    with database.get_connection() as conn:
        rows = conn.execute(
            "SELECT id, promised, delivered, timestamp, conditions FROM observations "
            "WHERE did = ? ORDER BY timestamp DESC LIMIT ?",
            (did, limit),
        ).fetchall()

    observations = []
    for row in rows:
        obs = {
            "id": row["id"],
            "promised": json.loads(row["promised"]),
            "delivered": json.loads(row["delivered"]),
            "timestamp": row["timestamp"],
        }
        if row["conditions"]:
            obs["conditions"] = json.loads(row["conditions"])
        observations.append(obs)

    return {
        "did": did,
        "observations": observations,
        "count": len(observations),
    }
