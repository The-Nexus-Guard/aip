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

PROMISE_SCHEMAS = {
    "task_completion": {
        "description": "Did the agent complete the promised tasks?",
        "promised_fields": ["tasks"],
        "delivered_fields": ["tasks"],
    },
    "response_time": {
        "description": "Did the agent respond within promised time?",
        "promised_fields": ["max_ms"],
        "delivered_fields": ["actual_ms"],
    },
    "quality_threshold": {
        "description": "Did the agent meet the promised quality bar?",
        "promised_fields": ["min_score", "metric"],
        "delivered_fields": ["actual_score", "metric"],
    },
    "uptime": {
        "description": "Did the agent maintain promised availability?",
        "promised_fields": ["target_pct", "window_hours"],
        "delivered_fields": ["actual_pct", "window_hours"],
    },
    "generic": {
        "description": "Free-form promise/delivery (default)",
        "promised_fields": [],
        "delivered_fields": [],
    },
}


class ObservationSubmit(BaseModel):
    """A single behavioral observation."""
    promised: List[str] = Field(..., description="What the agent committed to deliver")
    delivered: List[str] = Field(..., description="What the agent actually delivered")
    timestamp: Optional[str] = Field(None, description="ISO 8601 timestamp (defaults to now)")
    conditions: Optional[Dict[str, Any]] = Field(None, description="Environmental context")
    schema_type: Optional[str] = Field(
        "generic",
        description=f"Promise schema type: {', '.join(PROMISE_SCHEMAS.keys())}",
    )


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
    adaptation: Optional[float] = None
    robustness: Optional[float] = None
    observation_count: int = 0
    window_days: int = 0
    chain_hash: str = ""
    computed_at: str = ""


class DriftAlertResponse(BaseModel):
    """A single drift alert."""
    dimension: str
    cumulative_score: float
    windowed_score: float
    delta: float
    severity: str
    window_size: int
    message: str


class SlidingWindowResponse(BaseModel):
    """PDR scores with sliding window drift detection."""
    did: str
    cumulative: PDRScoreResponse
    windowed: PDRScoreResponse
    window_size: int
    drift_alerts: List[DriftAlertResponse]
    confidence: float
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
                schema_type TEXT DEFAULT 'generic',
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_observations_did
            ON observations(did)
        """)
        # Add schema_type column if missing (migration for existing DBs)
        try:
            conn.execute("SELECT schema_type FROM observations LIMIT 0")
        except Exception:
            conn.execute("ALTER TABLE observations ADD COLUMN schema_type TEXT DEFAULT 'generic'")
        # PDR score snapshots for history tracking
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pdr_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                did TEXT NOT NULL,
                calibration REAL,
                robustness REAL,
                observation_count INTEGER NOT NULL,
                window_days INTEGER NOT NULL,
                chain_hash TEXT NOT NULL,
                computed_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_pdr_snapshots_did
            ON pdr_snapshots(did)
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

    # Validate schema types
    for obs in batch.observations:
        if obs.schema_type and obs.schema_type not in PROMISE_SCHEMAS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown schema_type '{obs.schema_type}'. Valid: {list(PROMISE_SCHEMAS.keys())}",
            )

    # Store observations
    now = time.time()
    inserted = 0
    with database.get_connection() as conn:
        for obs in batch.observations:
            ts = obs.timestamp or datetime.now(tz=__import__("datetime").timezone.utc).isoformat()
            conditions_json = json.dumps(obs.conditions) if obs.conditions else None
            conn.execute(
                "INSERT INTO observations (did, promised, delivered, timestamp, conditions, schema_type, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (batch.did, json.dumps(obs.promised), json.dumps(obs.delivered),
                 ts, conditions_json, obs.schema_type or "generic", now),
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

    now = time.time()
    computed_at = datetime.now(tz=__import__("datetime").timezone.utc).isoformat()

    # Save snapshot for history tracking
    if scores.calibration is not None or scores.robustness is not None:
        try:
            with database.get_connection() as conn:
                conn.execute(
                    "INSERT INTO pdr_snapshots "
                    "(did, calibration, robustness, observation_count, window_days, chain_hash, computed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (did, scores.calibration, scores.robustness,
                     scores.observation_count, scores.window_days,
                     scores.chain_hash, now),
                )
                conn.commit()
        except Exception:
            pass  # Don't fail the request if snapshot storage fails

    return PDRScoreResponse(
        did=did,
        calibration=scores.calibration,
        adaptation=scores.adaptation,
        robustness=scores.robustness,
        observation_count=scores.observation_count,
        window_days=scores.window_days,
        chain_hash=scores.chain_hash,
        computed_at=computed_at,
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
            "SELECT id, promised, delivered, timestamp, conditions, schema_type FROM observations "
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
            "schema_type": row["schema_type"] if "schema_type" in row.keys() else "generic",
        }
        if row["conditions"]:
            obs["conditions"] = json.loads(row["conditions"])
        observations.append(obs)

    return {
        "did": did,
        "observations": observations,
        "count": len(observations),
    }


# --- Cleaner URL aliases ---

@router.get("/pdr/schemas", response_model=dict)
async def list_promise_schemas():
    """List available promise schema types for observations."""
    return {
        "schemas": PROMISE_SCHEMAS,
        "default": "generic",
    }


@router.get("/pdr/{did}", response_model=PDRScoreResponse)
async def get_pdr_alias(
    did: str,
    window_days: int = Query(28, ge=1, le=365, description="Scoring window in days"),
):
    """Get PDR scores for an agent (alias for /observations/{did}/scores)."""
    return await get_pdr_scores(did, window_days)


@router.get("/pdr/{did}/history", response_model=dict)
async def get_pdr_history(
    did: str,
    limit: int = Query(50, ge=1, le=500, description="Max snapshots to return"),
):
    """
    Get PDR score history for an agent.

    Returns historical PDR score snapshots, showing how behavioral
    reliability has changed over time. Snapshots are created each time
    scores are computed via /observations/{did}/scores or /pdr/{did}.
    """
    _ensure_observations_table()

    with database.get_connection() as conn:
        rows = conn.execute(
            "SELECT calibration, robustness, observation_count, window_days, "
            "chain_hash, computed_at FROM pdr_snapshots "
            "WHERE did = ? ORDER BY computed_at DESC LIMIT ?",
            (did, limit),
        ).fetchall()

    snapshots = []
    for row in rows:
        snapshots.append({
            "calibration": row["calibration"],
            "robustness": row["robustness"],
            "observation_count": row["observation_count"],
            "window_days": row["window_days"],
            "chain_hash": row["chain_hash"],
            "computed_at": datetime.fromtimestamp(
                row["computed_at"], tz=__import__("datetime").timezone.utc
            ).isoformat(),
        })

    return {
        "did": did,
        "snapshots": snapshots,
        "count": len(snapshots),
    }


@router.get("/pdr/{did}/drift", response_model=SlidingWindowResponse)
async def get_pdr_drift(
    did: str,
    window_size: int = Query(20, ge=5, le=200, description="Sliding window size (observations)"),
    warning_threshold: float = Query(0.15, ge=0.01, le=0.5, description="Drift warning threshold"),
    critical_threshold: float = Query(0.30, ge=0.05, le=0.8, description="Drift critical threshold"),
):
    """
    Get PDR scores with sliding window drift detection.

    Compares cumulative (all-time) scores with windowed (recent N observations)
    scores. When the delta exceeds thresholds, drift alerts are generated.

    Key insight: an agent with 50 stable observations at ~0.95 followed by
    sudden degradation over 10 observations will show cumulative ~0.85 while
    the sliding window drops to ~0.4. The divergence is the signal.

    Also returns a confidence score (0.0-0.95) based on observation count
    and temporal spread.
    """
    from aip_identity.pdr import (
        Observation as PDRObservation,
        compute_pdr_sliding_window,
    )

    _ensure_observations_table()

    with database.get_connection() as conn:
        rows = conn.execute(
            "SELECT promised, delivered, timestamp, conditions FROM observations "
            "WHERE did = ? ORDER BY timestamp ASC",
            (did,),
        ).fetchall()

    if not rows:
        now_iso = datetime.now(tz=__import__("datetime").timezone.utc).isoformat()
        empty_scores = PDRScoreResponse(did=did, computed_at=now_iso)
        return SlidingWindowResponse(
            did=did,
            cumulative=empty_scores,
            windowed=empty_scores,
            window_size=0,
            drift_alerts=[],
            confidence=0.0,
            computed_at=now_iso,
        )

    # Convert to Observation objects
    observations = []
    for row in rows:
        try:
            promised = json.loads(row["promised"])
            delivered = json.loads(row["delivered"])
            conditions = json.loads(row["conditions"]) if row["conditions"] else None
            timestamp = datetime.fromisoformat(row["timestamp"])
            observations.append(PDRObservation.from_promises(
                agent_id=did,
                timestamp=timestamp,
                promised=promised,
                delivered=delivered,
                conditions=conditions,
            ))
        except (json.JSONDecodeError, ValueError):
            continue

    result = compute_pdr_sliding_window(
        observations,
        window_size=window_size,
        drift_warning_threshold=warning_threshold,
        drift_critical_threshold=critical_threshold,
    )

    now_iso = datetime.now(tz=__import__("datetime").timezone.utc).isoformat()

    cum = result.cumulative
    win = result.windowed

    return SlidingWindowResponse(
        did=did,
        cumulative=PDRScoreResponse(
            did=did,
            calibration=cum.calibration,
            adaptation=cum.adaptation,
            robustness=cum.robustness,
            observation_count=cum.observation_count,
            window_days=cum.window_days,
            chain_hash=cum.chain_hash,
            computed_at=now_iso,
        ),
        windowed=PDRScoreResponse(
            did=did,
            calibration=win.calibration,
            adaptation=win.adaptation,
            robustness=win.robustness,
            observation_count=win.observation_count,
            window_days=win.window_days,
            chain_hash=win.chain_hash,
            computed_at=now_iso,
        ),
        window_size=result.window_size,
        drift_alerts=[
            DriftAlertResponse(
                dimension=a.dimension,
                cumulative_score=a.cumulative_score,
                windowed_score=a.windowed_score,
                delta=a.delta,
                severity=a.severity,
                window_size=a.window_size,
                message=a.message,
            )
            for a in result.drift_alerts
        ],
        confidence=result.confidence,
        computed_at=now_iso,
    )
