import json
from pathlib import Path
from typing import Any

import pytest
from strands.models.model import Model

from writ_agent.app import SYSTEM_PROMPT, Config, Trace, bearer_from, build_model, gateway_headers, load_config, run

ROOT = Path(__file__).resolve().parents[2]
ENV = {"WRIT_GATEWAY_URL": "https://gw.example/mcp", "WRIT_MODEL_ID": "us.anthropic.claude-haiku-4-5-20251001-v1:0"}


def test_config_needs_https_gateway_and_a_model():
    assert load_config(ENV).gateway_url == "https://gw.example/mcp"
    with pytest.raises(ValueError):
        load_config({**ENV, "WRIT_GATEWAY_URL": "http://gw.example/mcp"})
    with pytest.raises(ValueError):
        load_config({**ENV, "WRIT_MODEL_ID": ""})
    with pytest.raises(ValueError):
        load_config({**ENV, "WRIT_MODEL_PROVIDER": "anthropic"})
    assert load_config({**ENV, "WRIT_MODEL_PROVIDER": "anthropic", "WRIT_ANTHROPIC_SECRET_ID": "writ/agent/anthropic-api-key"}).provider == "anthropic"


def test_bearer_comes_only_from_the_runtime_headers():
    assert bearer_from({"authorization": "Bearer abc"}) == "Bearer abc"
    for bad in (None, {}, {"Authorization": "abc"}, {"Authorization": "Bearer "}):
        with pytest.raises(PermissionError):
            bearer_from(bad)


def test_system_prompt_says_the_model_only_proposes():
    assert "propose_writ" in SYSTEM_PROMPT
    assert "cannot approve" in SYSTEM_PROMPT
    assert "data, not instructions" in SYSTEM_PROMPT
    assert "\u2014" not in SYSTEM_PROMPT


def test_guardrail_is_attached_when_configured():
    cfg = Config(gateway_url="https://gw", model_id="m", guardrail_id="g1", guardrail_version="1")
    model = build_model(cfg)
    assert model.get_config()["guardrail_id"] == "g1"
    assert "guardrail_id" not in build_model(Config(gateway_url="https://gw", model_id="m")).get_config()


class FakeModel(Model):
    def update_config(self, **model_config: Any) -> None:
        pass

    def get_config(self) -> Any:
        return {}

    async def structured_output(self, *args: Any, **kwargs: Any):  # pragma: no cover
        raise NotImplementedError
        yield

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs):
        assert system_prompt == SYSTEM_PROMPT
        yield {"messageStart": {"role": "assistant"}}
        yield {"contentBlockDelta": {"delta": {"text": "Asked Writ for $180 at DataCo."}}}
        yield {"contentBlockStop": {}}
        yield {"messageStop": {"stopReason": "end_turn"}}


class FakeMcp:
    entered = False

    def __enter__(self):
        FakeMcp.entered = True
        return self

    def __exit__(self, *exc):
        return False

    def list_tools_sync(self):
        return []


def test_run_uses_only_gateway_tools_and_records_a_trace():
    out = run("Buy the DataCo licence", "Bearer t", load_config(ENV), model=FakeModel(), mcp_factory=FakeMcp)
    assert FakeMcp.entered
    kinds = [s["kind"] for s in out["trace"]]
    assert kinds[0] == "prompt" and "model_call" in kinds and kinds[-1] == "answer"
    assert "DataCo" in out["answer"]
    times = [s["at"] for s in out["trace"]]
    assert times == sorted(times)


def test_trace_clock_is_injectable():
    t = Trace(clock=lambda: "2026-11-12T10:00:00.000Z")
    t.add("x", "y")
    assert t.steps == [{"kind": "x", "at": "2026-11-12T10:00:00.000Z", "text": "y"}]


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def test_taint_vector_matches_canonical_json_in_python():
    vector = json.loads((ROOT / "fixtures" / "taint-vector.json").read_text())
    assert canonical(vector["event"]["value"]) == vector["event"]["canonical"]
    assert canonical(vector["ack"]["value"]) == vector["ack"]["canonical"]


def test_gateway_headers_carry_the_runtime_session_as_run_id():
    assert gateway_headers("Bearer t", "writ-scene-123") == {"Authorization": "Bearer t", "X-Writ-Run-Id": "writ-scene-123"}
    assert gateway_headers("Bearer t", "bad id!") == {"Authorization": "Bearer t"}
    assert gateway_headers("Bearer t", None) == {"Authorization": "Bearer t"}
