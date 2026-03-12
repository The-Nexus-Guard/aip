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

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, Tuple


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
        w_calibration: float = 0.4,
        w_adaptation: float = 0.35,
        w_robustness: float = 0.25
    ) -> float:
        """
        Compute weighted composite score.

        Default weights reflect that calibration (delivering on promises) is
        most important for trust, followed by adaptation (handling novelty),
        then robustness (consistency under stress).

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
    w_calibration: float = 0.4,
    w_adaptation: float = 0.35,
    w_robustness: float = 0.25,
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
