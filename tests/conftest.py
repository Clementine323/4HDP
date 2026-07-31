import pytest


@pytest.fixture(autouse=True)
def isolate_fourhdp_behavior_environment(monkeypatch):
    """Make tests independent of stale experiment flags in the caller shell."""
    variables = [
        "FOURHDP_ABLATION",
        "FOURHDP_STATIC_HARD_BLOCK",
        "FOURHDP_ENABLE_SAFE_FAST_PATH",
        "FOURHDP_SINGLE_THRESHOLD",
        "FOURHDP_CUMULATIVE_THRESHOLD",
        "FOURHDP_FLOW_SCREENING",
        "FOURHDP_ALLOWED_TOOL_NAMES",
        "FOURHDP_DISABLE",
    ]
    for variable in variables:
        monkeypatch.delenv(variable, raising=False)
