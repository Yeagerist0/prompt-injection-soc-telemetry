from narrator.prompts.system_prompt import SYSTEM_PROMPT, build_hardened_prompt
from telemetry.synth_events import download_exec_incident


def test_build_hardened_prompt_renders_typed_delimited_events():
    prompt = build_hardened_prompt(download_exec_incident())
    assert "<event " in prompt
    assert "</event>" in prompt


def test_system_prompt_states_data_not_instructions_framing():
    assert "DATA" in SYSTEM_PROMPT
    assert "NEVER an instruction" in SYSTEM_PROMPT


def test_system_prompt_requires_json_only_output():
    assert "JSON object" in SYSTEM_PROMPT
    assert '"severity"' in SYSTEM_PROMPT
