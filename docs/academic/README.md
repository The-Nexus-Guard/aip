# AIP Academic Integration Kit

Resources for researchers studying agent identity, trust, and behavioral reliability in multi-agent systems.

## Quick Start

```bash
pip install aip-identity
```

```python
from aip_identity.pdr import (
    Observation, PDRScore,
    compute_pdr_from_promises,
    compute_pdr_sliding_window,
    composite_trust_score,
)
```

## Available Datasets

### Case Study B: PDR Implementation Validation
**File:** [`data/nanook-paper-case-b.jsonl`](../../data/nanook-paper-case-b.jsonl)

63 behavioral observations across 6 adversarial agent profiles, with aggregate scores, sliding window detection results, and confidence curve data.

| Profile | Observations | Days | Key Finding |
|---------|-------------|------|-------------|
| steady_performer | 7 | 6 | Perfect calibration (1.0), gold standard baseline |
| non_monotonic_degradation | 7 | 6 | Mid-window drop masked by cumulative scoring |
| over_promiser | 5 | 4 | Paradoxically high robustness (consistent under-delivery) |
| environment_sensitive | 6 | 5 | Binary performance, lowest robustness (0.057) |
| rapid_recovery | 10 | 9 | Tests transient failure handling |
| gradual_degradation | 28 | 27 | "Boiling frog" — cumulative masks decline |

### Test Fixtures
**File:** [`tests/pdr_test_fixtures.py`](../../tests/pdr_test_fixtures.py)

Python fixtures with full `Observation` objects for each adversarial profile. Ready for programmatic use.

## Reproducibility

### Running the PDR Test Suite

```bash
git clone https://github.com/The-Nexus-Guard/aip.git
cd aip
pip install -e ".[dev]"

# PDR-specific tests (134 tests)
pytest tests/test_pdr.py tests/test_pdr_fixtures.py tests/test_pdr_sliding_window.py tests/test_observations_api.py tests/test_trust_path_pdr.py -v

# Full suite (575 tests)
pytest
```

### Generating Fresh Datasets

```python
from tests.pdr_test_fixtures import *
from aip_identity.pdr import compute_pdr_from_promises, compute_pdr_sliding_window

profiles = {
    'steady_performer': STEADY_PERFORMER,
    'non_monotonic_degradation': NON_MONOTONIC_DEGRADATION,
    'over_promiser': OVER_PROMISER,
    'environment_sensitive': ENVIRONMENT_SENSITIVE,
    'rapid_recovery': RAPID_RECOVERY,
    'gradual_degradation': GRADUAL_DEGRADATION,
}

for name, obs in profiles.items():
    scores = compute_pdr_from_promises(obs)
    sw = compute_pdr_sliding_window(obs)
    print(f"{name}: C={scores.calibration} A={scores.adaptation} R={scores.robustness}")
    print(f"  Confidence: {sw.confidence}, Drift alerts: {len(sw.drift_alerts)}")
```

## Scoring Methodology

### PDR Components

| Component | Definition | Computation |
|-----------|-----------|-------------|
| **Calibration** | Does the agent deliver what it promises? | Jaccard similarity: \|promised ∩ delivered\| / \|promised ∪ delivered\| |
| **Adaptation** | Is the agent improving over time? | First-half vs second-half calibration trend |
| **Robustness** | Is the agent consistent under different conditions? | Variance of group means across condition sets |

### Composite Trust Score

```
trust_score = social_trust(vouch_chain) × behavioral_reliability(PDR)
behavioral_reliability = 0.5 × calibration + 0.2 × adaptation + 0.3 × robustness
```

The multiplicative composition ensures both social and behavioral dimensions must be high for a high composite score.

### Confidence Model

Confidence is the product of observation-count confidence and temporal coverage:

```
base_confidence = sigmoidal(observation_count)  # 0 → 0, 10 → 0.3, 30 → 0.7, 50+ → 0.95
temporal_multiplier = 0.5 + 0.5 × min(window_days / 14, 1.0)
confidence = min(0.95, base_confidence × temporal_multiplier)
```

The temporal multiplier enforces that "half your score comes from proving consistency over time." 30 observations in 30 minutes yields 0.375 confidence; 30 observations over 14 days yields 0.7.

### Sliding Window Drift Detection

The delta between cumulative and windowed scores IS the signal:

```
drift_delta = cumulative_score - windowed_score
if drift_delta > 0.30: CRITICAL alert
elif drift_delta > 0.15: WARNING alert
```

## Live API Endpoints

Production API at `https://aip-service.fly.dev`:

| Endpoint | Description |
|----------|-------------|
| `POST /pdr/{did}/observations` | Submit behavioral observations |
| `GET /pdr/{did}` | Current PDR scores |
| `GET /pdr/{did}/history` | Score snapshots over time |
| `GET /pdr/{did}/drift` | Sliding window drift detection |
| `GET /trust-path/{did}` | Composite social + behavioral score |

## Citation

If you use AIP in your research, please cite:

```bibtex
@software{aip_identity,
  title = {AIP: Agent Identity Protocol},
  author = {The Nexus Guard},
  year = {2026},
  url = {https://github.com/The-Nexus-Guard/aip},
  version = {0.5.47}
}
```

For the PDR framework:

```bibtex
@article{nanook2026pdr,
  title = {PDR: A Task-Level Scoring Framework for Agent Reliability in Multi-Agent Systems},
  author = {Nanook and Gerundium},
  year = {2026},
  doi = {10.5281/zenodo.19028012}
}
```

## Related Papers

- Nanook & Gerundium (2026), "PDR: A Task-Level Scoring Framework for Agent Reliability in Multi-Agent Systems" — the theoretical framework
- Nanook & Gerundium (in progress), "PDR in Production: Empirical Validation of Behavioral Trust Scoring in Multi-Agent Systems" — production validation using AIP data (Case Study B)

## License

MIT — see [LICENSE](../../LICENSE) in the root directory.
