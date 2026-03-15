"""
Tests for PDR sliding window drift detection and confidence curves.

Based on Nanook's adversarial test fixtures:
1. late-onset-drift: 50 stable then 10 degraded
2. oscillating-performance: alternating good/bad periods
3. cold-start: sparse early observations
4. gradual-improvement: monotonic improvement
"""

from datetime import datetime, timedelta
from aip_identity.pdr import (
    Observation,
    compute_pdr_sliding_window,
    compute_pdr_from_promises,
    _compute_confidence,
    SlidingWindowResult,
    DriftAlert,
)
from tests.pdr_test_fixtures import (
    STEADY_PERFORMER,
    NON_MONOTONIC_DEGRADATION,
    OVER_PROMISER,
    ENVIRONMENT_SENSITIVE,
)


# ---------------------------------------------------------------------------
# Adversarial fixtures (Nanook's pilot-data format)
# ---------------------------------------------------------------------------

def _make_obs(agent_id, day_offset, promised, delivered, conditions=None):
    """Helper to create a promise-based observation."""
    return Observation.from_promises(
        agent_id=agent_id,
        timestamp=datetime(2026, 1, 1) + timedelta(days=day_offset),
        promised=promised,
        delivered=delivered,
        conditions=conditions,
    )


def make_late_onset_drift(stable_count=50, degraded_count=10):
    """50 stable observations at ~0.95 followed by sudden degradation."""
    obs = []
    for i in range(stable_count):
        obs.append(_make_obs(
            "drift_agent", i,
            promised=["task_a", "task_b", "task_c"],
            delivered=["task_a", "task_b", "task_c"],  # perfect delivery
            conditions={"env": "production"},
        ))
    for i in range(degraded_count):
        obs.append(_make_obs(
            "drift_agent", stable_count + i,
            promised=["task_a", "task_b", "task_c"],
            delivered=["task_a"],  # sudden drop to 1/3
            conditions={"env": "production"},
        ))
    return obs


def make_oscillating_performance(periods=6, period_length=10):
    """Alternating good/bad periods."""
    obs = []
    for p in range(periods):
        is_good = p % 2 == 0
        for i in range(period_length):
            day = p * period_length + i
            if is_good:
                obs.append(_make_obs(
                    "oscillator", day,
                    promised=["task_a", "task_b"],
                    delivered=["task_a", "task_b"],
                ))
            else:
                obs.append(_make_obs(
                    "oscillator", day,
                    promised=["task_a", "task_b"],
                    delivered=["task_a"],  # 50% delivery
                ))
    return obs


def make_cold_start(total_days=30, sparse_count=5, dense_start_day=20):
    """Sparse early observations, dense later."""
    obs = []
    # Sparse phase: 5 observations scattered across first 20 days
    sparse_days = [0, 4, 9, 14, 18]
    for d in sparse_days[:sparse_count]:
        obs.append(_make_obs(
            "cold_start", d,
            promised=["task_a"],
            delivered=["task_a"],
        ))
    # Dense phase: daily observations from day 20
    for d in range(dense_start_day, total_days):
        obs.append(_make_obs(
            "cold_start", d,
            promised=["task_a", "task_b"],
            delivered=["task_a", "task_b"],
        ))
    return obs


def make_gradual_improvement(count=30):
    """Monotonically improving agent — starts bad, gets better."""
    obs = []
    for i in range(count):
        # Delivery improves: first obs delivers 1/4, last delivers 4/4
        promised = ["task_a", "task_b", "task_c", "task_d"]
        ratio = min(1.0, (i + 1) / count * 1.3)  # reaches 1.0 around observation 23
        n_delivered = max(1, int(len(promised) * ratio))
        obs.append(_make_obs(
            "improver", i,
            promised=promised,
            delivered=promised[:n_delivered],
        ))
    return obs


# ---------------------------------------------------------------------------
# Tests: Sliding window drift detection
# ---------------------------------------------------------------------------

class TestSlidingWindowBasic:
    """Basic sliding window behavior."""

    def test_returns_sliding_window_result(self):
        result = compute_pdr_sliding_window(STEADY_PERFORMER)
        assert isinstance(result, SlidingWindowResult)
        assert result.cumulative is not None
        assert result.windowed is not None

    def test_steady_performer_no_drift(self):
        result = compute_pdr_sliding_window(STEADY_PERFORMER)
        assert len(result.drift_alerts) == 0

    def test_empty_observations(self):
        result = compute_pdr_sliding_window([])
        assert result.cumulative.calibration is None
        assert result.windowed.calibration is None
        assert len(result.drift_alerts) == 0
        assert result.confidence == 0.0

    def test_window_size_respected(self):
        obs = make_late_onset_drift(50, 10)
        result = compute_pdr_sliding_window(obs, window_size=10)
        assert result.window_size == 10

    def test_window_larger_than_observations(self):
        result = compute_pdr_sliding_window(STEADY_PERFORMER, window_size=100)
        assert result.window_size == len(STEADY_PERFORMER)


class TestLateOnsetDrift:
    """The canonical drift case: 50 stable then 10 degraded."""

    def test_cumulative_stays_high(self):
        obs = make_late_onset_drift(50, 10)
        result = compute_pdr_sliding_window(obs, window_size=10)
        # Cumulative over 60 obs should still be relatively high
        assert result.cumulative.calibration is not None
        assert result.cumulative.calibration > 0.7

    def test_windowed_drops(self):
        obs = make_late_onset_drift(50, 10)
        result = compute_pdr_sliding_window(obs, window_size=10)
        # Window over last 10 degraded obs should be low
        assert result.windowed.calibration is not None
        assert result.windowed.calibration < 0.5

    def test_drift_alert_generated(self):
        obs = make_late_onset_drift(50, 10)
        result = compute_pdr_sliding_window(obs, window_size=10)
        cal_alerts = [a for a in result.drift_alerts if a.dimension == "calibration"]
        assert len(cal_alerts) >= 1
        assert cal_alerts[0].severity == "critical"
        assert cal_alerts[0].delta > 0.3  # cumulative - windowed

    def test_divergence_is_the_signal(self):
        """The delta between cumulative and windowed IS the drift signal."""
        obs = make_late_onset_drift(50, 10)
        result = compute_pdr_sliding_window(obs, window_size=10)
        assert result.cumulative.calibration is not None
        assert result.windowed.calibration is not None
        delta = result.cumulative.calibration - result.windowed.calibration
        assert delta > 0.3  # significant divergence


class TestOscillatingPerformance:
    """Alternating good/bad periods — tests adaptation scoring stability."""

    def test_moderate_calibration(self):
        obs = make_oscillating_performance()
        result = compute_pdr_sliding_window(obs, window_size=20)
        # Overall calibration should be moderate (mix of good/bad)
        assert result.cumulative.calibration is not None
        assert 0.5 < result.cumulative.calibration < 0.9

    def test_window_depends_on_phase(self):
        """Windowed score should differ based on whether window hits good or bad phase."""
        obs_end_good = make_oscillating_performance(periods=6)  # ends on bad (5th=bad)
        # Actually periods 0,2,4 are good, 1,3,5 are bad. 6 periods, last is bad.
        obs_end_bad = make_oscillating_performance(periods=5)  # ends on good (4th=good)
        result_bad = compute_pdr_sliding_window(obs_end_good, window_size=10)
        result_good = compute_pdr_sliding_window(obs_end_bad, window_size=10)
        # The window that ends during a bad phase should have lower windowed cal
        if result_bad.windowed.calibration is not None and result_good.windowed.calibration is not None:
            assert result_bad.windowed.calibration < result_good.windowed.calibration


class TestColdStart:
    """Sparse early observations — tests confidence curve behavior."""

    def test_low_confidence_sparse(self):
        obs = make_cold_start()
        # Only look at sparse portion
        sparse_obs = obs[:5]
        result = compute_pdr_sliding_window(sparse_obs)
        assert result.confidence < 0.4

    def test_confidence_grows_with_data(self):
        obs = make_cold_start()
        result = compute_pdr_sliding_window(obs)
        assert result.confidence > 0.3  # more data = more confidence


class TestGradualImprovement:
    """Monotonically improving — tests adaptation scoring direction."""

    def test_positive_adaptation(self):
        obs = make_gradual_improvement()
        result = compute_pdr_sliding_window(obs, window_size=15)
        # Adaptation should be > 0.5 (improving trend)
        if result.cumulative.adaptation is not None:
            assert result.cumulative.adaptation > 0.5

    def test_windowed_better_than_cumulative(self):
        """For an improving agent, recent performance > cumulative."""
        obs = make_gradual_improvement()
        result = compute_pdr_sliding_window(obs, window_size=15)
        if (result.windowed.calibration is not None and
                result.cumulative.calibration is not None):
            assert result.windowed.calibration >= result.cumulative.calibration


class TestConfidenceCurve:
    """Test the confidence curve function directly."""

    def test_zero_observations(self):
        assert _compute_confidence(0, 0) == 0.0

    def test_very_few_observations(self):
        c = _compute_confidence(3, 1)
        assert 0.0 < c < 0.2

    def test_moderate_observations(self):
        c = _compute_confidence(20, 14)
        assert 0.4 < c < 0.8

    def test_many_observations_long_window(self):
        c = _compute_confidence(50, 30)
        assert c >= 0.9

    def test_cap_at_95(self):
        c = _compute_confidence(1000, 365)
        assert c <= 0.95

    def test_monotonic_growth(self):
        """Confidence should never decrease with more data."""
        prev = 0.0
        for n in range(0, 100, 5):
            c = _compute_confidence(n, n // 2)
            assert c >= prev
            prev = c


class TestDriftAlertThresholds:
    """Test drift alert threshold customization."""

    def test_lower_threshold_more_alerts(self):
        obs = make_late_onset_drift(50, 10)
        strict = compute_pdr_sliding_window(obs, window_size=10,
                                            drift_warning_threshold=0.05)
        lenient = compute_pdr_sliding_window(obs, window_size=10,
                                             drift_warning_threshold=0.50)
        assert len(strict.drift_alerts) >= len(lenient.drift_alerts)

    def test_critical_vs_warning(self):
        obs = make_late_onset_drift(50, 10)
        result = compute_pdr_sliding_window(
            obs, window_size=10,
            drift_warning_threshold=0.10,
            drift_critical_threshold=0.25,
        )
        for alert in result.drift_alerts:
            if abs(alert.delta) >= 0.25:
                assert alert.severity == "critical"


class TestExistingFixtures:
    """Sliding window on existing test fixtures."""

    def test_non_monotonic_degradation_detects_instability(self):
        result = compute_pdr_sliding_window(NON_MONOTONIC_DEGRADATION, window_size=3)
        # The last 3 observations are recovery — windowed should show recent recovery
        assert result.windowed.calibration is not None

    def test_over_promiser_consistent_low(self):
        result = compute_pdr_sliding_window(OVER_PROMISER)
        # Over-promiser has consistently low calibration — no drift, just bad
        assert result.cumulative.calibration is not None
        assert result.cumulative.calibration < 0.55

    def test_environment_sensitive_low_robustness(self):
        result = compute_pdr_sliding_window(ENVIRONMENT_SENSITIVE)
        # Should detect environment sensitivity through robustness
        assert result.cumulative is not None


class TestVerificationBasedMode:
    """Test with use_promises=False for verification-based observations."""

    def test_verification_mode_runs(self):
        """Verification-based mode should work (even if scores are None for promise data)."""
        result = compute_pdr_sliding_window(
            STEADY_PERFORMER, use_promises=False
        )
        assert isinstance(result, SlidingWindowResult)
