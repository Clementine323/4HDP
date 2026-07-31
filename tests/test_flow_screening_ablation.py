import types

from fourhdp.core.instrumentation.interceptor import SystemInterceptor


def test_flow_screening_bypasses_internal_call_by_default(monkeypatch):
    interceptor = SystemInterceptor()
    module = types.SimpleNamespace(target=lambda x: x + 1)
    monkeypatch.setattr("importlib.import_module", lambda name: module)
    monkeypatch.setattr(interceptor, "_identify_caller", lambda: "INTERNAL_BYPASS")

    audited = []
    interceptor.hook_function("fake_module", "target", lambda ctx, original, *a, **k: audited.append(ctx) or original(*a, **k))
    assert module.target(1) == 2
    assert audited == []


def test_flow_screening_off_audits_internal_call(monkeypatch):
    interceptor = SystemInterceptor()
    module = types.SimpleNamespace(target=lambda x: x + 1)
    monkeypatch.setattr("importlib.import_module", lambda name: module)
    monkeypatch.setattr(interceptor, "_identify_caller", lambda: "INTERNAL_BYPASS")
    monkeypatch.setenv("FOURHDP_FLOW_SCREENING", "0")

    audited = []
    interceptor.hook_function("fake_module", "target", lambda ctx, original, *a, **k: audited.append(ctx) or original(*a, **k))
    assert module.target(1) == 2
    assert len(audited) == 1
    assert audited[0].agent_id == "UNFILTERED_INTERNAL"
    assert audited[0].flow_screening_enabled is False
