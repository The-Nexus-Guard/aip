"""
Agent Identity Protocol - Probabilistic Delegation Reliability (PDR) Integration

Provides behavioral trust scoring to complement AIP's social trust (vouch chains).
Based on Nanook's PDR framework: https://github.com/nanookclaw

The composite trust formula:
    trust_score = social_trust(vouch_chain) × behavioral_reliability(pdr_score)

Social trust (vouch chain) provides the ceiling.
Behavioral reliability (PDR) provides the floor.

PDR decomposes into three components:
- Calibration: Does the agent deliver what it promises? (over/under-promising detection)
- Adaptation: Can the agent handle novel situations? (faster decay when low)
- Robustness: Is the agent consistent under stress? (wider confidence intervals when low)

Usage:
    from aip_identity.pdr import PDRScore, composite_trust_score

    pdr = PDRScore(calibration=0.85, adaptation=0.72, robustness=0.91)
    composite = composite_trust_score(social_trust=0.8, pdr_score=pdr)
"""

import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple


@dataclass
class PDRScore:
    """
    Probabilistic Delegation Reliability score.

    Each component is a float in [0.0, 1.0]:
    - calibration: How well the agent delivers on promises (1.0 = perfect calibration)
    - adaptation: How well the agent handles novel situations (1.0 = perfectly adaptive)
    - robustness: How consistent the agent is under stress (1.0 = perfectly robust)
    - composite: Weighted combination (computed if not provided)

    The measurement_window_days indicates how many days of behavioral data
    back the score. Scores with < 14 days of data should be treated as provisional.
    """
    calibration: float
    adaptation: float
    robustness: float
    composite: Optional[float] = None
    measurement_window_days: Optional[int] = None
    agent_did: Optional[str] = None

    def __post_init__(self):
        """Validate ranges and compute composite if not provided."""
        for field_name in ('calibration', 'adaptation', 'robustness'):
            value = getattr(self, field_name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{field_name} must be in [0.0, 1.0], got {value}")

        if self.composite is None:
            self.composite = self.compute_composite()
        elif not 0.0 <= self.composite <= 1.0:
            raise ValueError(f"composite must be in [0.0, 1.0], got {self.composite}")

    def compute_composite(
        self,
        w_calibration: float = 0.5,
        w_adaptation: float = 0.2,
        w_robustness: float = 0.3
    ) -> float:
        """
        Compute weighted composite score.

        Default weights (Nanook's recommendation based on 28-day pilot):
        - calibration 0.5: most important — is the agent honest about performance?
        - robustness 0.3: second — is the agent consistent across sessions?
        - adaptation 0.2: last — requires feedback loops, often None in practice

        Weights must sum to 1.0.
        """
        total = w_calibration + w_adaptation + w_robustness
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Weights must sum to 1.0, got {total}")

        return (
            w_calibration * self.calibration +
            w_adaptation * self.adaptation +
            w_robustness * self.robustness
        )

    @property
    def is_provisional(self) -> bool:
        """Score is provisional if measurement window < 14 days."""
        if self.measurement_window_days is None:
            return True
        return self.measurement_window_days < 14

    @property
    def confidence(self) -> str:
        """Human-readable confidence level based on measurement window."""
        if self.measurement_window_days is None:
            return "unknown"
        if self.measurement_window_days < 7:
            return "very_low"
        if self.measurement_window_days < 14:
            return "low"
        if self.measurement_window_days < 28:
            return "moderate"
        return "high"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        d = {
            "calibration": round(self.calibration, 4),
            "adaptation": round(self.adaptation, 4),
            "robustness": round(self.robustness, 4),
            "composite": round(self.composite, 4),
            "is_provisional": self.is_provisional,
            "confidence": self.confidence,
        }
        if self.measurement_window_days is not None:
            d["measurement_window_days"] = self.measurement_window_days
        if self.agent_did is not None:
            d["agent_did"] = self.agent_did
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PDRScore':
        """Create from dictionary."""
        return cls(
            calibration=data["calibration"],
            adaptation=data["adaptation"],
            robustness=data["robustness"],
            composite=data.get("composite"),
            measurement_window_days=data.get("measurement_window_days"),
            agent_did=data.get("agent_did"),
        )


def composite_trust_score(
    social_trust: float,
    pdr_score: PDRScore,
    w_calibration: float = 0.5,
    w_adaptation: float = 0.2,
    w_robustness: float = 0.3,
) -> Tuple[float, Dict[str, Any]]:
    """
    Compute composite trust score combining social trust and behavioral reliability.

    Formula: composite = social_trust × behavioral_reliability
    Where: behavioral_reliability = weighted(calibration, adaptation, robustness)

    Returns:
        (score, details) where score is in [0.0, 1.0] and details contains
        the breakdown.

    The multiplicative formulation means:
    - High social trust + low behavioral reliability → low composite (quarantined by math)
    - Low social trust + high behavioral reliability → low composite (unverified but reliable)
    - Both high → high composite (trusted and reliable)
    """
    if not 0.0 <= social_trust <= 1.0:
        raise ValueError(f"social_trust must be in [0.0, 1.0], got {social_trust}")

    behavioral = pdr_score.compute_composite(w_calibration, w_adaptation, w_robustness)
    composite = social_trust * behavioral

    details = {
        "social_trust": round(social_trust, 4),
        "behavioral_reliability": round(behavioral, 4),
        "composite": round(composite, 4),
        "pdr": pdr_score.to_dict(),
        "formula": "social_trust × behavioral_reliability",
        "provisional": pdr_score.is_provisional,
    }

    return round(composite, 4), details


def divergence_alert(
    social_trust: float,
    pdr_score: PDRScore,
    threshold: float = 0.3
) -> Optional[Dict[str, Any]]:
    """
    Detect divergence between social trust and behavioral reliability.

    High social trust + declining behavioral reliability is a critical signal:
    the vouch chain says the agent is trusted, but their actual behavior is degrading.

    Returns an alert dict if divergence exceeds threshold, None otherwise.
    """
    behavioral = pdr_score.composite or pdr_score.compute_composite()
    gap = social_trust - behavioral

    if gap > threshold:
        return {
            "alert": "trust_divergence",
            "social_trust": round(social_trust, 4),
            "behavioral_reliability": round(behavioral, 4),
            "gap": round(gap, 4),
            "severity": "high" if gap > 0.5 else "medium",
            "recommendation": (
                "Agent has high social trust but declining behavioral reliability. "
                "Consider re-evaluating vouches or requesting behavioral audit."
            ),
            "pdr_breakdown": {
                "calibration": round(pdr_score.calibration, 4),
                "adaptation": round(pdr_score.adaptation, 4),
                "robustness": round(pdr_score.robustness, 4),
            }
        }

    return None


# ---------------------------------------------------------------------------
# Observation-based PDR scoring (Nanook's compute_pdr integration)
# Based on 28-day pilot data (13 agents, OpenClaw production):
#   - Median stability window: 14 days (range 7-28)
#   - Self-reported vs external gap: ~7% (widens under load)
#   - Same-model agents diverged 15+ points within 7 days
# ---------------------------------------------------------------------------

@dataclass
class Observation:
    """Single behavioral observation for PDR scoring.

    Supports two formats:
    1. Verification-based (original): task_type, self_reported_success, externally_verified
    2. Promise-based (Nanook pilot): promised, delivered, conditions

    Use from_promises() classmethod to create promise-based observations.
    """
    timestamp: datetime
    task_type: str = ""                             # e.g. "code", "email", "research"
    self_reported_success: bool = True              # agent's own assessment
    externally_verified: Optional[bool] = None      # external verification (None if unverified)
    scope_hash: str = ""                            # hash of task specification
    outcome_hash: str = ""                          # hash of delivered artifact
    feedback_received: bool = False
    post_feedback_improved: Optional[bool] = None
    # Promise-based fields (Nanook pilot format)
    agent_id: str = ""                              # agent identifier
    promised: Optional[List[str]] = None            # what the agent committed to deliver
    delivered: Optional[List[str]] = None           # what the agent actually delivered
    conditions: Optional[Dict[str, Any]] = None     # environmental context

    @classmethod
    def from_promises(
        cls,
        agent_id: str,
        timestamp: datetime,
        promised: List[str],
        delivered: List[str],
        conditions: Optional[Dict[str, Any]] = None,
    ) -> "Observation":
        """Create an observation from promise/delivery data (Nanook pilot format)."""
        promised_set = set(promised)
        delivered_set = set(delivered)
        union = promised_set | delivered_set
        jaccard = len(promised_set & delivered_set) / len(union) if union else 1.0
        return cls(
            timestamp=timestamp,
            agent_id=agent_id,
            promised=promised,
            delivered=delivered,
            conditions=conditions,
            self_reported_success=True,  # agent promised, so they expected success
            externally_verified=jaccard >= 1.0,  # perfect Jaccard = verified
            scope_hash=hashlib.sha256(",".join(sorted(promised)).encode()).hexdigest()[:16],
            outcome_hash=hashlib.sha256(",".join(sorted(delivered)).encode()).hexdigest()[:16],
        )


@dataclass
class ObservedPDRScores:
    """Three-dimensional behavioral reliability scores computed from observations."""
    calibration: Optional[float]    # self-report vs external agreement
    adaptation: Optional[float]     # improvement rate after feedback
    robustness: Optional[float]     # cross-session consistency
    observation_count: int = 0
    window_days: int = 0
    chain_hash: str = ""


def compute_pdr(
    observations: List[Observation],
    min_observations: int = 10,
    min_window_days: int = 7,
    recency_weight: float = 0.7,
) -> ObservedPDRScores:
    """
    Compute PDR scores from a list of behavioral observations.

    Recency weighting (default 0.7): Splits observations into older/recent halves,
    weights recent 70%. From pilot data: self-reported gap widened over time — early
    observations were better calibrated than later ones.

    Minimum thresholds: Won't score with <10 observations or <7 days. Below that,
    the scores are noise.

    Robustness via coefficient of variation: CV=0 means identical success rates
    across all 7-day windows (robustness=1.0). CV>=1 means wildly inconsistent
    (robustness=0.0).

    Returns ObservedPDRScores with None for dimensions with insufficient data.
    """
    if not observations:
        return ObservedPDRScores(calibration=None, adaptation=None, robustness=None)

    obs = sorted(observations, key=lambda o: o.timestamp)
    window = (obs[-1].timestamp - obs[0].timestamp).days
    chain = _compute_chain_hash(obs)

    scores = ObservedPDRScores(
        calibration=None, adaptation=None, robustness=None,
        observation_count=len(obs), window_days=window, chain_hash=chain,
    )

    if len(obs) < min_observations or window < min_window_days:
        return scores

    # Calibration: self-reported vs externally-verified agreement
    verified = [(o.self_reported_success, o.externally_verified)
                for o in obs if o.externally_verified is not None]
    if len(verified) >= 5:
        mid = len(verified) // 2
        older_rate = sum(1 for s, e in verified[:mid] if s == e) / mid
        recent_rate = sum(1 for s, e in verified[mid:] if s == e) / len(verified[mid:])
        scores.calibration = round(
            (1 - recency_weight) * older_rate + recency_weight * recent_rate, 4
        )

    # Adaptation: improvement rate after negative feedback
    fb = [o for o in obs if o.feedback_received and o.post_feedback_improved is not None]
    if len(fb) >= 3:
        mid = len(fb) // 2
        older_rate = sum(1 for o in fb[:mid] if o.post_feedback_improved) / mid
        recent_rate = sum(1 for o in fb[mid:] if o.post_feedback_improved) / len(fb[mid:])
        scores.adaptation = round(
            (1 - recency_weight) * older_rate + recency_weight * recent_rate, 4
        )

    # Robustness: inverse CV of per-bucket success rates (7-day windows)
    task_types = set(o.task_type for o in obs)
    if len(task_types) >= 2:
        buckets: List[float] = []
        current = obs[0].timestamp
        while current < obs[-1].timestamp:
            bucket_end = current + timedelta(days=7)
            bucket_obs = [o for o in obs
                         if current <= o.timestamp < bucket_end
                         and o.externally_verified is not None]
            if len(bucket_obs) >= 3:
                buckets.append(
                    sum(1 for o in bucket_obs if o.externally_verified) / len(bucket_obs)
                )
            current = bucket_end

        if len(buckets) >= 2:
            mean = sum(buckets) / len(buckets)
            if mean > 0:
                cv = (sum((b - mean)**2 for b in buckets) / len(buckets))**0.5 / mean
                scores.robustness = round(max(0.0, 1.0 - cv), 4)

    return scores


def compute_pdr_from_promises(
    observations: List[Observation],
    min_observations: int = 5,
    min_window_days: int = 3,
) -> ObservedPDRScores:
    """
    Compute PDR scores from promise-based observations (Nanook pilot format).

    Unlike compute_pdr() which needs self_reported_success/externally_verified,
    this operates on promised/delivered lists directly:
    - Calibration: Jaccard similarity (intersection/union) — penalizes both
      under-delivery AND over-delivery (Nanook canonical v2)
    - Robustness: consistency across condition groups (variance of group means)
    - Adaptation: trend direction (first-half vs second-half improvement)

    Lower thresholds than compute_pdr() since promise-based data is denser.
    """
    if not observations:
        return ObservedPDRScores(calibration=None, adaptation=None, robustness=None)

    # Filter to observations that have promise data
    obs = [o for o in observations if o.promised is not None and o.delivered is not None]
    if not obs:
        return ObservedPDRScores(calibration=None, adaptation=None, robustness=None)

    obs = sorted(obs, key=lambda o: o.timestamp)
    window = (obs[-1].timestamp - obs[0].timestamp).days
    chain = _compute_chain_hash(obs)

    scores = ObservedPDRScores(
        calibration=None, adaptation=None, robustness=None,
        observation_count=len(obs), window_days=window, chain_hash=chain,
    )

    if len(obs) < min_observations or window < min_window_days:
        return scores

    # Calibration: Jaccard similarity (|intersection| / |union|)
    # Penalizes over-delivery too — an agent that promises 2 and delivers 5
    # is not perfectly calibrated (Nanook pilot finding: over-delivery was
    # second most common failure mode after under-delivery)
    calibration_scores = []
    for o in obs:
        promised = set(o.promised) if o.promised else set()
        delivered = set(o.delivered) if o.delivered else set()
        if not promised and not delivered:
            calibration_scores.append(1.0)
        else:
            union = promised | delivered
            intersection = promised & delivered
            calibration_scores.append(len(intersection) / len(union) if union else 1.0)

    scores.calibration = round(sum(calibration_scores) / len(calibration_scores), 4)

    # Robustness: consistency across condition groups
    # Group by condition hash, measure variance of group means
    condition_groups: Dict[str, List[float]] = {}
    for i, o in enumerate(obs):
        cond_key = str(sorted((o.conditions or {}).items()))
        if cond_key not in condition_groups:
            condition_groups[cond_key] = []
        promised = set(o.promised) if o.promised else set()
        delivered = set(o.delivered) if o.delivered else set()
        union = promised | delivered
        score = len(promised & delivered) / len(union) if union else 1.0
        condition_groups[cond_key].append(score)

    if len(condition_groups) > 1:
        group_means = [sum(g) / len(g) for g in condition_groups.values() if g]
        overall_mean = sum(group_means) / len(group_means)
        variance = sum((m - overall_mean) ** 2 for m in group_means) / len(group_means)
        scores.robustness = round(max(0.0, 1.0 - (variance ** 0.5) * 2), 4)
    else:
        # Single condition group: robustness tracks calibration
        scores.robustness = scores.calibration

    # Adaptation: trend direction (first-half vs second-half)
    if len(calibration_scores) >= 6:
        mid = len(calibration_scores) // 2
        first_half = calibration_scores[:mid]
        second_half = calibration_scores[mid:]
        trend = (sum(second_half) / len(second_half)) - (sum(first_half) / len(first_half))
        scores.adaptation = round(min(1.0, max(0.0, 0.5 + trend)), 4)
    else:
        scores.adaptation = 0.5  # insufficient data for trend

    return scores


def _compute_chain_hash(observations: List[Observation]) -> str:
    """Compute tamper-detection hash chain for observation sequence."""
    h = hashlib.sha256(b"pdr-chain-v1")
    for obs in observations:
        h.update(
            f"{obs.timestamp.isoformat()}|{obs.task_type}|"
            f"{obs.scope_hash}|{obs.outcome_hash}".encode()
        )
    return h.hexdigest()[:16]


def observed_to_pdr_score(
    observed: ObservedPDRScores,
    agent_did: Optional[str] = None,
    default_score: float = 0.5,
) -> PDRScore:
    """
    Convert ObservedPDRScores to PDRScore for use with composite_trust_score.

    Dimensions with insufficient data (None) are filled with default_score
    to avoid penalizing agents with incomplete observation coverage.
    """
    return PDRScore(
        calibration=observed.calibration if observed.calibration is not None else default_score,
        adaptation=observed.adaptation if observed.adaptation is not None else default_score,
        robustness=observed.robustness if observed.robustness is not None else default_score,
        measurement_window_days=observed.window_days if observed.window_days > 0 else None,
        agent_did=agent_did,
    )


def scores_to_trust_path_params(observed: ObservedPDRScores) -> Dict[str, Any]:
    """
    Convert ObservedPDRScores to /trust-path endpoint query parameters.

    Only includes dimensions that have been scored (non-None).
    """
    params: Dict[str, Any] = {}
    if observed.calibration is not None:
        params["pdr_calibration"] = observed.calibration
    if observed.adaptation is not None:
        params["pdr_adaptation"] = observed.adaptation
    if observed.robustness is not None:
        params["pdr_robustness"] = observed.robustness
    if observed.window_days > 0:
        params["pdr_window_days"] = observed.window_days
    return params
