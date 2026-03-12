"""Tests for PDR (Probabilistic Delegation Reliability) integration module."""
import pytest
from aip_identity.pdr import PDRScore, composite_trust_score, divergence_alert


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
        # Default weights: 0.4 * 0.8 + 0.35 * 0.6 + 0.25 * 0.4
        expected = 0.4 * 0.8 + 0.35 * 0.6 + 0.25 * 0.4
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
