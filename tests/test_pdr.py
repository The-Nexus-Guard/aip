"""Tests for PDR (Probabilistic Delegation Reliability) integration module."""
import pytest
from datetime import datetime, timedelta
from aip_identity.pdr import (
    PDRScore, composite_trust_score, divergence_alert,
    Observation, ObservedPDRScores, compute_pdr,
    observed_to_pdr_score, scores_to_trust_path_params,
    _compute_chain_hash,
)


class TestPDRScore:
    """Tests for PDRScore dataclass."""

    def test_basic_creation(self):
        score = PDRScore(calibration=0.85, adaptation=0.72, robustness=0.91)
        assert score.calibration == 0.85
        assert score.adaptation == 0.72
        assert score.robustness == 0.91
        assert score.composite is not None

    def test_composite_auto_computed(self):
        score = PDRScore(calibration=1.0, adaptation=1.0, robustness=1.0)
        assert score.composite == 1.0

    def test_composite_zero(self):
        score = PDRScore(calibration=0.0, adaptation=0.0, robustness=0.0)
        assert score.composite == 0.0

    def test_composite_weighted(self):
        score = PDRScore(calibration=0.8, adaptation=0.6, robustness=0.4)
        # Default weights: 0.5 * 0.8 + 0.2 * 0.6 + 0.3 * 0.4
        expected = 0.5 * 0.8 + 0.2 * 0.6 + 0.3 * 0.4
        assert abs(score.composite - expected) < 0.001

    def test_custom_composite(self):
        score = PDRScore(calibration=0.5, adaptation=0.5, robustness=0.5, composite=0.75)
        assert score.composite == 0.75

    def test_validation_out_of_range(self):
        with pytest.raises(ValueError):
            PDRScore(calibration=1.5, adaptation=0.5, robustness=0.5)

    def test_validation_negative(self):
        with pytest.raises(ValueError):
            PDRScore(calibration=-0.1, adaptation=0.5, robustness=0.5)

    def test_validation_composite_out_of_range(self):
        with pytest.raises(ValueError):
            PDRScore(calibration=0.5, adaptation=0.5, robustness=0.5, composite=1.5)

    def test_is_provisional_no_window(self):
        score = PDRScore(calibration=0.8, adaptation=0.8, robustness=0.8)
        assert score.is_provisional is True

    def test_is_provisional_short_window(self):
        score = PDRScore(calibration=0.8, adaptation=0.8, robustness=0.8,
                        measurement_window_days=10)
        assert score.is_provisional is True

    def test_not_provisional(self):
        score = PDRScore(calibration=0.8, adaptation=0.8, robustness=0.8,
                        measurement_window_days=14)
        assert score.is_provisional is False

    def test_confidence_levels(self):
        assert PDRScore(0.8, 0.8, 0.8).confidence == "unknown"
        assert PDRScore(0.8, 0.8, 0.8, measurement_window_days=3).confidence == "very_low"
        assert PDRScore(0.8, 0.8, 0.8, measurement_window_days=10).confidence == "low"
        assert PDRScore(0.8, 0.8, 0.8, measurement_window_days=20).confidence == "moderate"
        assert PDRScore(0.8, 0.8, 0.8, measurement_window_days=30).confidence == "high"

    def test_to_dict(self):
        score = PDRScore(calibration=0.85, adaptation=0.72, robustness=0.91,
                        measurement_window_days=21, agent_did="did:aip:test")
        d = score.to_dict()
        assert d["calibration"] == 0.85
        assert d["adaptation"] == 0.72
        assert d["robustness"] == 0.91
        assert "composite" in d
        assert d["measurement_window_days"] == 21
        assert d["agent_did"] == "did:aip:test"
        assert d["confidence"] == "moderate"
        assert d["is_provisional"] is False

    def test_from_dict_roundtrip(self):
        original = PDRScore(calibration=0.85, adaptation=0.72, robustness=0.91,
                           measurement_window_days=21)
        d = original.to_dict()
        restored = PDRScore.from_dict(d)
        assert restored.calibration == original.calibration
        assert restored.adaptation == original.adaptation
        assert restored.robustness == original.robustness
        assert abs(restored.composite - original.composite) < 0.001

    def test_custom_weights(self):
        score = PDRScore(calibration=1.0, adaptation=0.0, robustness=0.0)
        # Equal weights
        result = score.compute_composite(1/3, 1/3, 1/3)
        assert abs(result - 1/3) < 0.001

    def test_invalid_weights(self):
        score = PDRScore(calibration=0.5, adaptation=0.5, robustness=0.5)
        with pytest.raises(ValueError, match="Weights must sum to 1.0"):
            score.compute_composite(0.5, 0.5, 0.5)


class TestCompositeTrustScore:
    """Tests for composite trust scoring."""

    def test_perfect_scores(self):
        pdr = PDRScore(calibration=1.0, adaptation=1.0, robustness=1.0)
        score, details = composite_trust_score(social_trust=1.0, pdr_score=pdr)
        assert score == 1.0
        assert details["social_trust"] == 1.0
        assert details["behavioral_reliability"] == 1.0

    def test_zero_social_trust(self):
        pdr = PDRScore(calibration=1.0, adaptation=1.0, robustness=1.0)
        score, _ = composite_trust_score(social_trust=0.0, pdr_score=pdr)
        assert score == 0.0

    def test_zero_behavioral(self):
        pdr = PDRScore(calibration=0.0, adaptation=0.0, robustness=0.0)
        score, _ = composite_trust_score(social_trust=1.0, pdr_score=pdr)
        assert score == 0.0

    def test_multiplicative_quarantine(self):
        """High social trust + low behavioral = low composite (quarantined by math)."""
        pdr = PDRScore(calibration=0.3, adaptation=0.2, robustness=0.1)
        score, details = composite_trust_score(social_trust=0.9, pdr_score=pdr)
        assert score < 0.25  # Effectively quarantined
        assert details["social_trust"] == 0.9

    def test_realistic_scores(self):
        pdr = PDRScore(calibration=0.85, adaptation=0.72, robustness=0.91,
                      measurement_window_days=21)
        score, details = composite_trust_score(social_trust=0.8, pdr_score=pdr)
        assert 0.5 < score < 0.8
        assert details["provisional"] is False

    def test_invalid_social_trust(self):
        pdr = PDRScore(calibration=0.5, adaptation=0.5, robustness=0.5)
        with pytest.raises(ValueError):
            composite_trust_score(social_trust=1.5, pdr_score=pdr)

    def test_details_structure(self):
        pdr = PDRScore(calibration=0.8, adaptation=0.7, robustness=0.9)
        _, details = composite_trust_score(social_trust=0.8, pdr_score=pdr)
        assert "social_trust" in details
        assert "behavioral_reliability" in details
        assert "composite" in details
        assert "pdr" in details
        assert "formula" in details


class TestDivergenceAlert:
    """Tests for trust divergence detection."""

    def test_no_divergence(self):
        pdr = PDRScore(calibration=0.8, adaptation=0.8, robustness=0.8)
        alert = divergence_alert(social_trust=0.8, pdr_score=pdr)
        assert alert is None

    def test_divergence_detected(self):
        pdr = PDRScore(calibration=0.3, adaptation=0.2, robustness=0.1)
        alert = divergence_alert(social_trust=0.9, pdr_score=pdr)
        assert alert is not None
        assert alert["alert"] == "trust_divergence"
        assert alert["gap"] > 0.3

    def test_high_severity(self):
        pdr = PDRScore(calibration=0.1, adaptation=0.1, robustness=0.1)
        alert = divergence_alert(social_trust=0.9, pdr_score=pdr)
        assert alert["severity"] == "high"

    def test_medium_severity(self):
        pdr = PDRScore(calibration=0.4, adaptation=0.4, robustness=0.4)
        alert = divergence_alert(social_trust=0.8, pdr_score=pdr)
        assert alert is not None
        assert alert["severity"] == "medium"

    def test_custom_threshold(self):
        pdr = PDRScore(calibration=0.6, adaptation=0.6, robustness=0.6)
        # Default threshold 0.3 - no alert
        assert divergence_alert(social_trust=0.8, pdr_score=pdr) is None
        # Lower threshold - alert
        alert = divergence_alert(social_trust=0.8, pdr_score=pdr, threshold=0.1)
        assert alert is not None

    def test_behavioral_higher_than_social(self):
        """No divergence alert when behavioral > social (agent is better than reputation)."""
        pdr = PDRScore(calibration=0.9, adaptation=0.9, robustness=0.9)
        alert = divergence_alert(social_trust=0.3, pdr_score=pdr)
        assert alert is None


# ---------------------------------------------------------------------------
# Observation-based scoring tests (Nanook's compute_pdr)
# ---------------------------------------------------------------------------

def _make_observations(
    count: int = 20,
    days: int = 21,
    success_rate: float = 0.8,
    feedback_rate: float = 0.3,
    improvement_rate: float = 0.7,
    task_types: tuple = ("code", "research", "email"),
) -> list:
    """Helper to generate test observations."""
    import hashlib as _h
    base = datetime(2026, 1, 1)
    obs = []
    for i in range(count):
        ts = base + timedelta(days=days * i / count)
        success = (i % int(1 / success_rate if success_rate > 0 else 999)) != 0
        ext_verified = success if i % 3 != 2 else None  # 2/3 externally verified
        has_feedback = i % int(1 / feedback_rate) == 0 if feedback_rate > 0 else False
        improved = (i % int(1 / improvement_rate) != 0) if has_feedback and improvement_rate > 0 else None
        obs.append(Observation(
            timestamp=ts,
            task_type=task_types[i % len(task_types)],
            self_reported_success=success,
            externally_verified=ext_verified if ext_verified is not None else (not success if i % 5 == 0 else None),
            scope_hash=_h.sha256(f"scope-{i}".encode()).hexdigest()[:16],
            outcome_hash=_h.sha256(f"outcome-{i}".encode()).hexdigest()[:16],
            feedback_received=has_feedback,
            post_feedback_improved=improved,
        ))
    return obs


class TestObservation:
    """Tests for Observation dataclass."""

    def test_basic_creation(self):
        obs = Observation(
            timestamp=datetime(2026, 1, 1),
            task_type="code",
            self_reported_success=True,
            externally_verified=True,
            scope_hash="abc123",
            outcome_hash="def456",
        )
        assert obs.task_type == "code"
        assert obs.feedback_received is False

    def test_with_feedback(self):
        obs = Observation(
            timestamp=datetime(2026, 1, 1),
            task_type="research",
            self_reported_success=True,
            externally_verified=False,
            scope_hash="abc",
            outcome_hash="def",
            feedback_received=True,
            post_feedback_improved=True,
        )
        assert obs.feedback_received is True
        assert obs.post_feedback_improved is True


class TestComputePDR:
    """Tests for compute_pdr observation-based scoring."""

    def test_empty_observations(self):
        scores = compute_pdr([])
        assert scores.calibration is None
        assert scores.adaptation is None
        assert scores.robustness is None
        assert scores.observation_count == 0

    def test_insufficient_observations(self):
        obs = _make_observations(count=5, days=3)
        scores = compute_pdr(obs)
        assert scores.calibration is None  # below min_observations
        assert scores.observation_count == 5

    def test_insufficient_window(self):
        obs = _make_observations(count=20, days=3)
        scores = compute_pdr(obs, min_window_days=7)
        assert scores.calibration is None  # below min_window_days

    def test_sufficient_data_produces_scores(self):
        obs = _make_observations(count=30, days=28)
        scores = compute_pdr(obs)
        assert scores.observation_count == 30
        assert scores.window_days >= 20
        # At least calibration should be scored (we have verified observations)
        assert scores.calibration is not None
        assert 0.0 <= scores.calibration <= 1.0

    def test_chain_hash_deterministic(self):
        obs = _make_observations(count=15, days=14)
        hash1 = _compute_chain_hash(obs)
        hash2 = _compute_chain_hash(obs)
        assert hash1 == hash2
        assert len(hash1) == 16

    def test_chain_hash_changes_with_data(self):
        obs = _make_observations(count=15, days=14)
        hash1 = _compute_chain_hash(obs)
        obs[0].task_type = "modified"
        hash2 = _compute_chain_hash(obs)
        assert hash1 != hash2

    def test_perfect_calibration(self):
        """Agent that always reports accurately should have high calibration."""
        base = datetime(2026, 1, 1)
        obs = []
        for i in range(20):
            success = i % 3 != 0
            obs.append(Observation(
                timestamp=base + timedelta(days=i),
                task_type=["code", "research"][i % 2],
                self_reported_success=success,
                externally_verified=success,  # always matches
                scope_hash=f"s{i}",
                outcome_hash=f"o{i}",
            ))
        scores = compute_pdr(obs)
        assert scores.calibration is not None
        assert scores.calibration >= 0.9

    def test_poor_calibration(self):
        """Agent that over-reports success should have low calibration."""
        base = datetime(2026, 1, 1)
        obs = []
        for i in range(20):
            obs.append(Observation(
                timestamp=base + timedelta(days=i),
                task_type=["code", "research"][i % 2],
                self_reported_success=True,      # always claims success
                externally_verified=(i % 2 == 0), # only half actually succeed
                scope_hash=f"s{i}",
                outcome_hash=f"o{i}",
            ))
        scores = compute_pdr(obs)
        assert scores.calibration is not None
        assert scores.calibration < 0.7

    def test_adaptation_scoring(self):
        """Agent that improves after feedback should have adaptation scored."""
        base = datetime(2026, 1, 1)
        obs = []
        for i in range(20):
            has_fb = i % 3 == 0
            obs.append(Observation(
                timestamp=base + timedelta(days=i),
                task_type=["code", "research"][i % 2],
                self_reported_success=True,
                externally_verified=True,
                scope_hash=f"s{i}",
                outcome_hash=f"o{i}",
                feedback_received=has_fb,
                post_feedback_improved=True if has_fb else None,
            ))
        scores = compute_pdr(obs)
        # 7 feedback events (0,3,6,9,12,15,18) — enough for adaptation
        if scores.adaptation is not None:
            assert scores.adaptation >= 0.8

    def test_robustness_consistent_agent(self):
        """Agent with consistent performance should have high robustness."""
        base = datetime(2026, 1, 1)
        obs = []
        for i in range(30):
            obs.append(Observation(
                timestamp=base + timedelta(days=i),
                task_type=["code", "research", "email"][i % 3],
                self_reported_success=True,
                externally_verified=True,  # always succeeds
                scope_hash=f"s{i}",
                outcome_hash=f"o{i}",
            ))
        scores = compute_pdr(obs)
        if scores.robustness is not None:
            assert scores.robustness >= 0.9

    def test_custom_thresholds(self):
        obs = _make_observations(count=8, days=10)
        # With lowered thresholds, should score
        scores = compute_pdr(obs, min_observations=5, min_window_days=3)
        assert scores.observation_count == 8


class TestObservedToPDRScore:
    """Tests for converting ObservedPDRScores to PDRScore."""

    def test_full_conversion(self):
        observed = ObservedPDRScores(
            calibration=0.85, adaptation=0.72, robustness=0.91,
            observation_count=50, window_days=28, chain_hash="abc123",
        )
        pdr = observed_to_pdr_score(observed, agent_did="did:aip:test")
        assert pdr.calibration == 0.85
        assert pdr.adaptation == 0.72
        assert pdr.robustness == 0.91
        assert pdr.measurement_window_days == 28
        assert pdr.agent_did == "did:aip:test"

    def test_none_dimensions_get_default(self):
        observed = ObservedPDRScores(
            calibration=0.85, adaptation=None, robustness=None,
        )
        pdr = observed_to_pdr_score(observed, default_score=0.5)
        assert pdr.calibration == 0.85
        assert pdr.adaptation == 0.5
        assert pdr.robustness == 0.5

    def test_zero_window_becomes_none(self):
        observed = ObservedPDRScores(
            calibration=0.8, adaptation=0.7, robustness=0.9, window_days=0,
        )
        pdr = observed_to_pdr_score(observed)
        assert pdr.measurement_window_days is None


class TestScoresToTrustPathParams:
    """Tests for scores_to_trust_path_params conversion."""

    def test_full_params(self):
        observed = ObservedPDRScores(
            calibration=0.85, adaptation=0.72, robustness=0.91, window_days=28,
        )
        params = scores_to_trust_path_params(observed)
        assert params["pdr_calibration"] == 0.85
        assert params["pdr_adaptation"] == 0.72
        assert params["pdr_robustness"] == 0.91
        assert params["pdr_window_days"] == 28

    def test_partial_params(self):
        observed = ObservedPDRScores(
            calibration=0.85, adaptation=None, robustness=None,
        )
        params = scores_to_trust_path_params(observed)
        assert "pdr_calibration" in params
        assert "pdr_adaptation" not in params
        assert "pdr_robustness" not in params

    def test_no_window(self):
        observed = ObservedPDRScores(
            calibration=0.8, adaptation=0.7, robustness=0.9, window_days=0,
        )
        params = scores_to_trust_path_params(observed)
        assert "pdr_window_days" not in params
