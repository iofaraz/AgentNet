"""Tests for the testbed address plan (software_testbed/addresses.py)."""

import ipaddress
import re

import testbed

A = testbed.addresses
NET = ipaddress.ip_network(A.TESTBED_NET)


def all_hosts():
    return {"mcp": A.MCP_HOST, "a2a": A.A2A_HOST, **{f"ws:{k}": v for k, v in A.WORKSTATIONS.items()}}


def test_every_address_is_loopback_inside_the_testbed_net():
    assert NET.subnet_of(ipaddress.ip_network("127.0.0.0/8")), "never leaves the computer"
    for role, addr in all_hosts().items():
        ip = ipaddress.ip_address(addr)
        assert ip.is_loopback and ip in NET, f"{role} {addr}"


def test_testbed_net_excludes_other_local_programs():
    # Ollama, editors and Docker listen on 127.0.0.1; the capture filter must not include it.
    assert ipaddress.ip_address("127.0.0.1") not in NET
    assert A.CAPTURE_FILTER == f"net {A.TESTBED_NET}"


def test_roles_have_distinct_addresses():
    servers = {A.MCP_HOST, A.A2A_HOST}
    people = {v for k, v in A.WORKSTATIONS.items() if k != "ops-agent"}
    assert len(servers) == 2 and len(people) == len(A.WORKSTATIONS) - 1
    assert not servers & people


def test_service_account_uses_the_assistants_host():
    assert A.workstation("ops-agent") == A.A2A_HOST


def test_attacker_range_is_reserved():
    attacker = ipaddress.ip_network(A.ATTACKER_NET)
    assert attacker.subnet_of(NET)
    for role, addr in all_hosts().items():
        assert ipaddress.ip_address(addr) not in attacker, f"{role} uses the attacker range"


def test_every_identity_has_a_workstation():
    import sys
    sys.path.insert(0, str(testbed.TESTBED / "mcp"))
    import workspace
    assert set(workspace.World().users) | {"anonymous"} == set(A.WORKSTATIONS)
    assert A.workstation(None) == A.WORKSTATIONS["anonymous"]


def test_unknown_identity_has_no_address():
    import pytest
    with pytest.raises(KeyError):
        A.workstation("mallory")


def test_urls_follow_the_plan():
    assert A.MCP_URL == f"http://{A.MCP_HOST}:{A.MCP_PORT}/mcp"
    assert A.A2A_URL == f"http://{A.A2A_HOST}:{A.A2A_PORT}"


def test_no_hard_coded_testbed_addresses_outside_the_plan():
    """Every component must take its address from addresses.py."""
    allowed = {testbed.TESTBED / "addresses.py"}
    offenders = []
    for path in list(testbed.TESTBED.rglob("*.py")) + list(testbed.REPO_ROOT.joinpath("scripts").glob("*.py")):
        if path in allowed:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for m in re.finditer(r"\b127\.\d+\.\d+\.\d+\b", line):
                # Ollama deliberately stays on 127.0.0.1, outside the testbed net.
                if m.group() == "127.0.0.1" and ("11434" in line or "Ollama" in line):
                    continue
                offenders.append(f"{path.name}:{number}: {m.group()}")
    assert not offenders, offenders
