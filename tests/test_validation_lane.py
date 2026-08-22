from src.provenance.audit_runner import RUNNER_SCHEMA


def test_validation_lane_loads_runner():
    assert RUNNER_SCHEMA == "stegverse.ecosystem-provenance-execution.v1"
