"""
Tests using Nanook's real-world behavioral observation fixtures.
Source: https://gist.github.com/nanookclaw/88e5adf08c14913dbc081a178bf0eb07

These test patterns derived from the 28-day PDR pilot data.
"""
import pytest
from tests.pdr_test_fixtures import (
    STEADY_PERFORMER,
    NON_MONOTONIC_DEGRADATION,
    OVER_PROMISER,
    ENVIRONMENT_SENSITIVE,
    EXPECTED_PATTERNS,
)
from aip_identity.pdr import (
    Observation,
    compute_pdr_from_promises,
    composite_trust_score,
    PDRScore,
)


class TestNanookFixtures:
    """Test PDR scoring against real pilot data patterns."""

    def test_steady_performer_high_calibration(self):
        """Steady performer should have calibration > 0.95."""
        scores = compute_pdr_from_promises(STEADY_PERFORMER)
        assert scores.calibration is not None
        assert scores.calibration > 0.95, (
            f"Steady performer calibration {scores.calibration} should be > 0.95"
        )

    def test_steady_performer_high_robustness(self):
        """Steady performer should have robustness > 0.90."""
        scores = compute_pdr_from_promises(STEADY_PERFORMER)
        assert scores.robustness is not None
        assert scores.robustness > 0.90, (
            f"Steady performer robustness {scores.robustness} should be > 0.90"
        )

    def test_non_monotonic_degradation_lower_calibration(self):
        """Non-monotonic degradation should show calibration drop (~0.70-0.80)."""
        scores = compute_pdr_from_promises(NON_MONOTONIC_DEGRADATION)
        assert scores.calibration is not None
        assert scores.calibration < 0.90, (
            f"Degradation calibration {scores.calibration} should be < 0.90"
        )
        assert scores.calibration > 0.50, (
            f"Degradation calibration {scores.calibration} should be > 0.50 (partial recovery)"
        )

    def test_non_monotonic_degradation_low_robustness(self):
        """Non-monotonic degradation should have low robustness (inconsistent)."""
        scores = compute_pdr_from_promises(NON_MONOTONIC_DEGRADATION)
        assert scores.robustness is not None
        assert scores.robustness < 0.80, (
            f"Degradation robustness {scores.robustness} should be < 0.80"
        )

    def test_over_promiser_low_calibration(self):
        """Over-promiser should have low calibration (< 0.55)."""
        scores = compute_pdr_from_promises(OVER_PROMISER)
        assert scores.calibration is not None
        assert scores.calibration < 0.60, (
            f"Over-promiser calibration {scores.calibration} should be < 0.60"
        )

    def test_over_promiser_high_robustness(self):
        """Over-promiser should have high robustness (consistently under-delivers)."""
        scores = compute_pdr_from_promises(OVER_PROMISER)
        assert scores.robustness is not None
        assert scores.robustness > 0.70, (
            f"Over-promiser robustness {scores.robustness} should be > 0.70 "
            "(consistent under-delivery is still consistent)"
        )

    def test_environment_sensitive_low_robustness(self):
        """Environment-sensitive agent should have low robustness."""
        scores = compute_pdr_from_promises(ENVIRONMENT_SENSITIVE)
        assert scores.robustness is not None
        assert scores.robustness < 0.60, (
            f"Env-sensitive robustness {scores.robustness} should be < 0.60 "
            "(extreme variance across conditions)"
        )

    def test_composite_trust_with_pdr_scores(self):
        """Composite trust should weight social trust by behavioral reliability."""
        steady = compute_pdr_from_promises(STEADY_PERFORMER)
        degraded = compute_pdr_from_promises(NON_MONOTONIC_DEGRADATION)

        social_trust = 0.8
        steady_pdr = PDRScore(
            calibration=steady.calibration or 0.5,
            adaptation=0.8,
            robustness=steady.robustness or 0.5,
        )
        degraded_pdr = PDRScore(
            calibration=degraded.calibration or 0.5,
            adaptation=0.5,
            robustness=degraded.robustness or 0.5,
        )

        steady_composite = composite_trust_score(social_trust, steady_pdr)
        degraded_composite = composite_trust_score(social_trust, degraded_pdr)

        assert steady_composite > degraded_composite, (
            f"Steady ({steady_composite}) should score higher than degraded ({degraded_composite})"
        )

    def test_all_patterns_score_differently(self):
        """Each pattern should produce distinguishable PDR profiles."""
        patterns = {
            "steady": compute_pdr_from_promises(STEADY_PERFORMER),
            "degraded": compute_pdr_from_promises(NON_MONOTONIC_DEGRADATION),
            "over_promiser": compute_pdr_from_promises(OVER_PROMISER),
            "env_sensitive": compute_pdr_from_promises(ENVIRONMENT_SENSITIVE),
        }

        calibrations = {
            name: s.calibration for name, s in patterns.items() if s.calibration is not None
        }
        assert len(calibrations) == 4, "All patterns should produce calibration scores"

        # Steady should have highest calibration
        assert calibrations["steady"] == max(calibrations.values()), (
            f"Steady should have highest calibration, got {calibrations}"
        )

    def test_observation_from_promises(self):
        """Observation.from_promises should correctly convert promise data."""
        from datetime import datetime
        obs = Observation.from_promises(
            agent_id="test_agent",
            timestamp=datetime(2026, 3, 1),
            promised=["task_a", "task_b"],
            delivered=["task_a"],
            conditions={"load": "normal"},
        )
        assert obs.agent_id == "test_agent"
        assert obs.externally_verified is False  # only delivered 1/2
        assert obs.scope_hash  # should have computed hash
        assert obs.conditions == {"load": "normal"}

    def test_observation_from_promises_full_delivery(self):
        """Full delivery should mark externally_verified=True."""
        from datetime import datetime
        obs = Observation.from_promises(
            agent_id="test_agent",
            timestamp=datetime(2026, 3, 1),
            promised=["task_a", "task_b"],
            delivered=["task_a", "task_b"],
        )
        assert obs.externally_verified is True

    def test_chain_hash_deterministic(self):
        """Chain hash should be deterministic for same input."""
        scores1 = compute_pdr_from_promises(STEADY_PERFORMER)
        scores2 = compute_pdr_from_promises(STEADY_PERFORMER)
        assert scores1.chain_hash == scores2.chain_hash
        assert scores1.chain_hash != ""

    def test_jaccard_penalizes_over_delivery(self):
        """Jaccard similarity should penalize over-delivery (extras beyond promised)."""
        from datetime import datetime, timedelta
        base = datetime(2026, 1, 1)
        # Agent that always over-delivers: promises 2, delivers 4 (including the 2)
        obs = [
            Observation.from_promises(
                agent_id="over_deliverer",
                timestamp=base + timedelta(days=i),
                promised=["task_a", "task_b"],
                delivered=["task_a", "task_b", "task_c", "task_d"],
            )
            for i in range(10)
        ]
        scores = compute_pdr_from_promises(obs, min_observations=5, min_window_days=3)
        assert scores.calibration is not None
        # Jaccard = 2/4 = 0.5, not 1.0 (delivery rate would be 1.0)
        assert scores.calibration == 0.5, (
            f"Over-delivery calibration should be 0.5 (Jaccard), got {scores.calibration}"
        )

    def test_adaptation_improving_agent(self):
        """Agent that improves over time should have adaptation > 0.5."""
        from datetime import datetime, timedelta
        base = datetime(2026, 1, 1)
        obs = []
        for i in range(12):
            if i < 6:
                # First half: poor delivery
                obs.append(Observation.from_promises(
                    agent_id="improver",
                    timestamp=base + timedelta(days=i),
                    promised=["a", "b", "c"],
                    delivered=["a"],
                ))
            else:
                # Second half: perfect delivery
                obs.append(Observation.from_promises(
                    agent_id="improver",
                    timestamp=base + timedelta(days=i),
                    promised=["a", "b", "c"],
                    delivered=["a", "b", "c"],
                ))
        scores = compute_pdr_from_promises(obs, min_observations=5, min_window_days=3)
        assert scores.adaptation is not None
        assert scores.adaptation > 0.5, (
            f"Improving agent adaptation should be > 0.5, got {scores.adaptation}"
        )

    def test_adaptation_degrading_agent(self):
        """Agent that degrades over time should have adaptation < 0.5."""
        from datetime import datetime, timedelta
        base = datetime(2026, 1, 1)
        obs = []
        for i in range(12):
            if i < 6:
                # First half: perfect
                obs.append(Observation.from_promises(
                    agent_id="degrader",
                    timestamp=base + timedelta(days=i),
                    promised=["a", "b", "c"],
                    delivered=["a", "b", "c"],
                ))
            else:
                # Second half: poor
                obs.append(Observation.from_promises(
                    agent_id="degrader",
                    timestamp=base + timedelta(days=i),
                    promised=["a", "b", "c"],
                    delivered=["a"],
                ))
        scores = compute_pdr_from_promises(obs, min_observations=5, min_window_days=3)
        assert scores.adaptation is not None
        assert scores.adaptation < 0.5, (
            f"Degrading agent adaptation should be < 0.5, got {scores.adaptation}"
        )

    def test_steady_performer_has_adaptation(self):
        """Steady performer should now return adaptation scores."""
        scores = compute_pdr_from_promises(STEADY_PERFORMER)
        assert scores.adaptation is not None, "Adaptation should be computed for sufficient data"
        # Steady performer should be ~0.5 (stable, no trend)
        assert 0.3 <= scores.adaptation <= 0.7, (
            f"Steady performer adaptation {scores.adaptation} should be near 0.5"
        )
