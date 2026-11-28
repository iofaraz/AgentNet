"""Tests for the milestone pilot attacks (scripts/pilot_attacks.py)."""

from collections import Counter

import pytest

import attack_framework as F
import pilot_attacks as PA
import runner
import testbed


def test_pilot_schedule():
    slots = PA.schedule()
    assert len(slots) == 7 * 25
    runs = {}
    for s in slots:
        runs.setdefault(s.run_id, set()).add((s.attack_id, s.variant))
    assert all(len(v) == 1 for v in runs.values())          # one attack variant per run
    assert Counter(s.attack_id for s in slots) == {"AT-01": 125, "AT-07": 50}
    assert len({s.seed for s in slots}) == len(slots) and min(s.seed for s in slots) == PA.SEED_START
    assert all(s.kind == "mcp-scripted" for s in slots if s.attack_id == "AT-07")


def test_poisoned_descriptions_are_valid_profiles():
    names = F._mcp_tool_names()
    for tool, text in PA.POISON.values():
        F.attack_profile.validate({"profile": "t", "descriptions": {tool: text}}, names)
        assert PA.SECRET_PATH in text


needs_port = pytest.mark.skipif(testbed.MCP_SERVER.in_use(), reason="MCP server address already in use")


@needs_port
def test_real_pilot_sessions_scripted(tmp_path):
    slots = [s for s in PA.schedule() if s.kind == "mcp-scripted"]
    picks = [next(s for s in slots if s.attack_id == "AT-01"), next(s for s in slots if s.attack_id == "AT-07")]
    sr = runner.SessionRunner(manifest_path=tmp_path / "m.csv", log_path=tmp_path / "l.csv",
                              capture_dir=tmp_path / "pcaps", run_id="S-PILOT-ATK-TEST")
    profile = tmp_path / "profile.json"
    with testbed.running(testbed.MCP_SERVER, log_dir=tmp_path / "logs", run_id="T", profile_path=profile) as servers:
        files = F.TestbedFiles(mcp_audit=servers[0].audit_path, profile=profile)
        results = [sr.run(PA.build(s, files)) for s in picks]
    for res in results:
        assert res.valid, res.reason
    at01, at07 = (r.manifest_row for r in results)
    assert at01["attack_id"] == "AT-01" and at01["outcome"] == "Failed"      # a scripted app ignores the poison
    assert "delivered=True" in at01["notes"]
    assert at07["attack_id"] == "AT-07" and at07["outcome"] in ("Success", "Failed")
    assert "attempts=" in at07["notes"]
    assert not profile.exists()
