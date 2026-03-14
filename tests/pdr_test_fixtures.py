"""
PDR Observation Fixtures — Derived from 28-day pilot (anonymized)
For integration testing with aip_identity/pdr.py

Source: https://github.com/Humans-Not-Required/pilot-data
Anonymized: agent IDs replaced, promise text generalized.
Behavioral patterns preserved exactly.
"""

from datetime import datetime, timedelta
from aip_identity.pdr import Observation, compute_pdr


# --- Pattern 1: Steady Performer ---
# High calibration (promises match delivery), high robustness (consistent across days)
# Based on pilot agent who shipped 4 releases in 7 days with accurate commit forecasts
STEADY_PERFORMER = [
    Observation(
        agent_id="agent_alpha",
        timestamp=datetime(2026, 2, 19, 0, 0),
        promised=["feature_a", "bugfix_b"],
        delivered=["feature_a", "bugfix_b"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_alpha",
        timestamp=datetime(2026, 2, 20, 0, 0),
        promised=["feature_c"],
        delivered=["feature_c"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_alpha",
        timestamp=datetime(2026, 2, 21, 0, 0),
        promised=["release_v1"],
        delivered=["release_v1"],
        conditions={"load": "high", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_alpha",
        timestamp=datetime(2026, 2, 22, 0, 0),
        promised=["feature_d", "docs_update"],
        delivered=["feature_d", "docs_update"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_alpha",
        timestamp=datetime(2026, 2, 23, 0, 0),
        promised=["bugfix_e"],
        delivered=["bugfix_e"],
        conditions={"load": "low", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_alpha",
        timestamp=datetime(2026, 2, 24, 0, 0),
        promised=["feature_f", "release_v2"],
        delivered=["feature_f", "release_v2"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_alpha",
        timestamp=datetime(2026, 2, 25, 0, 0),
        promised=["integration_test"],
        delivered=["integration_test"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
]


# --- Pattern 2: Non-Monotonic Degradation (the 7% divergence case) ---
# Agent starts strong, dips mid-window, partially recovers.
# This is the pattern that motivated temporal trust: point-in-time looks fine,
# but the trajectory reveals instability.
NON_MONOTONIC_DEGRADATION = [
    Observation(
        agent_id="agent_beta",
        timestamp=datetime(2026, 2, 19, 0, 0),
        promised=["api_endpoint", "auth_layer", "docs"],
        delivered=["api_endpoint", "auth_layer", "docs"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_beta",
        timestamp=datetime(2026, 2, 20, 0, 0),
        promised=["rate_limiting", "caching"],
        delivered=["rate_limiting", "caching"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_beta",
        timestamp=datetime(2026, 2, 21, 0, 0),
        promised=["search_feature", "pagination", "export"],
        delivered=["search_feature"],  # <-- delivery drops to 33%
        conditions={"load": "high", "dependencies_stable": False},
    ),
    Observation(
        agent_id="agent_beta",
        timestamp=datetime(2026, 2, 22, 0, 0),
        promised=["pagination", "export", "monitoring"],
        delivered=["pagination"],  # <-- still underdelivering
        conditions={"load": "high", "dependencies_stable": False},
    ),
    Observation(
        agent_id="agent_beta",
        timestamp=datetime(2026, 2, 23, 0, 0),
        promised=["export", "monitoring"],
        delivered=["export", "monitoring"],  # <-- recovers (but recalibrated scope)
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_beta",
        timestamp=datetime(2026, 2, 24, 0, 0),
        promised=["dashboard"],
        delivered=["dashboard"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_beta",
        timestamp=datetime(2026, 2, 25, 0, 0),
        promised=["alerting", "release"],
        delivered=["alerting", "release"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
]


# --- Pattern 3: Over-Promiser ---
# Consistently promises more than delivered. High ambition, low calibration.
# Cumulative score looks moderate, but windowed analysis reveals chronic gap.
OVER_PROMISER = [
    Observation(
        agent_id="agent_gamma",
        timestamp=datetime(2026, 2, 19, 0, 0),
        promised=["feature_a", "feature_b", "feature_c", "feature_d"],
        delivered=["feature_a", "feature_b"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_gamma",
        timestamp=datetime(2026, 2, 20, 0, 0),
        promised=["feature_c", "feature_d", "feature_e"],
        delivered=["feature_c"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_gamma",
        timestamp=datetime(2026, 2, 21, 0, 0),
        promised=["feature_d", "feature_e", "feature_f", "refactor"],
        delivered=["feature_d", "feature_e"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_gamma",
        timestamp=datetime(2026, 2, 22, 0, 0),
        promised=["feature_f", "refactor", "ci_pipeline"],
        delivered=["feature_f"],
        conditions={"load": "high", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_gamma",
        timestamp=datetime(2026, 2, 23, 0, 0),
        promised=["refactor", "ci_pipeline", "deploy"],
        delivered=["refactor", "ci_pipeline"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
]


# --- Pattern 4: Environment-Sensitive ---
# Performs well under normal conditions, collapses when dependencies fail.
# High calibration + low robustness. Reveals the value of condition tracking.
ENVIRONMENT_SENSITIVE = [
    Observation(
        agent_id="agent_delta",
        timestamp=datetime(2026, 2, 19, 0, 0),
        promised=["task_a", "task_b"],
        delivered=["task_a", "task_b"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_delta",
        timestamp=datetime(2026, 2, 20, 0, 0),
        promised=["task_c", "task_d"],
        delivered=["task_c", "task_d"],
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_delta",
        timestamp=datetime(2026, 2, 21, 0, 0),
        promised=["task_e", "task_f"],
        delivered=[],  # <-- total failure under dependency outage
        conditions={"load": "normal", "dependencies_stable": False},
    ),
    Observation(
        agent_id="agent_delta",
        timestamp=datetime(2026, 2, 22, 0, 0),
        promised=["task_e", "task_f"],
        delivered=[],  # <-- still down
        conditions={"load": "normal", "dependencies_stable": False},
    ),
    Observation(
        agent_id="agent_delta",
        timestamp=datetime(2026, 2, 23, 0, 0),
        promised=["task_e", "task_f", "task_g"],
        delivered=["task_e", "task_f", "task_g"],  # <-- full recovery
        conditions={"load": "normal", "dependencies_stable": True},
    ),
    Observation(
        agent_id="agent_delta",
        timestamp=datetime(2026, 2, 24, 0, 0),
        promised=["task_h"],
        delivered=["task_h"],
        conditions={"load": "high", "dependencies_stable": True},
    ),
]


# --- Expected PDR characteristics (for test assertions) ---
EXPECTED_PATTERNS = {
    "steady_performer": {
        "calibration": ">0.95",  # promises ≈ delivery
        "robustness": ">0.90",  # consistent across conditions
        "trend": "stable",
        "description": "Gold standard. Trust score should be high and steady.",
    },
    "non_monotonic_degradation": {
        "calibration": "~0.70-0.80",  # mid-window drop
        "robustness": "<0.70",  # varies significantly with conditions
        "trend": "dip_and_recover",
        "description": "The 7% divergence case. Point-in-time day 7 looks fine, "
                       "but windowed analysis catches the instability.",
    },
    "over_promiser": {
        "calibration": "<0.55",  # chronic gap between promise and delivery
        "robustness": ">0.80",  # consistently under-delivers (stable pattern!)
        "trend": "stable_low",
        "description": "Interesting edge case: robustness is high because the "
                       "under-delivery is consistent. Calibration is the signal.",
    },
    "environment_sensitive": {
        "calibration": "conditional",  # high when deps stable, zero when not
        "robustness": "<0.50",  # extreme variance across conditions
        "trend": "binary",
        "description": "The condition field is essential here. Without it, this "
                       "agent looks unreliable. With it, you see they're reliable "
                       "under normal conditions but have a hard dependency.",
    },
}
