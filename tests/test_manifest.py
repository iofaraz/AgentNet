"""Tests for scripts/manifest.py (the dataset contract in code)."""

import csv
from datetime import datetime, timedelta, timezone

import pytest

import manifest as m

PKT = timezone(timedelta(hours=5))


def benign(**overrides):
    rec = {
        "session_id": "MCP-S-B0001",
        "label": "Benign",
        "attack_id": "AT-00",
        "protocol": "MCP",
        "transport": "HTTP",
        "environment": "Software",
        "capture_file": "mcp_benign_software_001.pcapng",
        "outcome": "N/A",
        "start_time": "2026-11-21T10:30:00.000+05:00",
        "end_time": "2026-11-21T10:30:15.000+05:00",
        "attack_variant": "N/A",
    }
    rec.update(overrides)
    return rec


def attack(**overrides):
    rec = benign(
        session_id="MCP-S-AT01-0001",
        label="Attack",
        attack_id="AT-01",
        capture_file="mcp_at01_software_001.pcapng",
        outcome="Success",
        attack_variant="V1",
    )
    rec.update(overrides)
    return rec


def errors(rec):
    full = {c: "" for c in m.COLUMNS}
    full.update(rec)
    return m.check_record(full).errors


# ---- valid records --------------------------------------------------------

def test_valid_benign_record():
    assert errors(benign()) == []


def test_valid_attack_record():
    assert errors(attack()) == []


def test_failed_attack_is_valid():
    assert errors(attack(outcome="Failed")) == []


def test_a2a_attack_on_allowed_protocol():
    assert errors(attack(
        session_id="A2A-S-AT06-0001", attack_id="AT-06", protocol="A2A",
        capture_file="a2a_at06_software_001.pcapng",
    )) == []


def test_hardware_and_https_are_valid():
    assert errors(benign(
        session_id="MCP-H-B0001", environment="Hardware", transport="HTTPS",
        capture_file="mcp_benign_hardware_001.pcapng",
    )) == []


def test_hardware_link_transports_are_valid():
    for transport in ("MQTT", "Serial"):
        assert errors(benign(
            session_id="MCP-H-B0001", environment="Hardware", transport=transport,
            capture_file="mcp_benign_hardware_001.pcapng",
        )) == []


def test_hardware_attack_is_valid():
    assert errors(attack(
        session_id="MCP-H-AT07-0001", attack_id="AT-07", environment="Hardware",
        capture_file="mcp_at07_hardware_001.pcapng",
    )) == []


def test_large_numbers_allowed():
    assert errors(benign(session_id="MCP-S-B12500", capture_file="mcp_benign_software_12500.pcapng")) == []


def test_software_and_hardware_ids_never_clash():
    sw = _full(benign())
    hw = _full(benign(session_id="MCP-H-B0001", environment="Hardware",
                      capture_file="mcp_benign_hardware_001.pcapng"))
    assert m.check_records([sw, hw]).ok


# ---- consistency between fields ------------------------------------------

@pytest.mark.parametrize("rec, fragment", [
    (benign(outcome="Success"), "benign sessions have outcome"),
    (benign(label="Attack"), "is benign traffic but label"),
    (benign(attack_variant="V1"), "benign sessions have attack_variant"),
    (attack(label="Benign"), "is an attack but label"),
    (attack(outcome="N/A"), "attack outcome must be one of"),
    (attack(protocol="A2A", session_id="A2A-S-AT01-0001",
            capture_file="a2a_at01_software_001.pcapng"), "AT-01 is not defined for A2A"),
    (attack(session_id="MCP-S-AT02-0001"), "implies AT-02"),
    (benign(session_id="A2A-S-B0001"), "says A2A but protocol"),
    (benign(capture_file="mcp_at01_software_001.pcapng"), "implies AT-01"),
    (benign(capture_file="a2a_benign_software_001.pcapng"), "says a2a"),
    (benign(capture_file="mcp_benign_hardware_001.pcapng"), "says hardware"),
])
def test_inconsistent_fields_rejected(rec, fragment):
    errs = errors(rec)
    assert any(fragment in e for e in errs), errs


# ---- bad values -----------------------------------------------------------

@pytest.mark.parametrize("rec, fragment", [
    (benign(session_id="MCP-1"), "does not match the contract format"),
    (benign(session_id="MCP-S-B001"), "does not match the contract format"),
    (benign(session_id="MCP-B0001"), "does not match the contract format"),
    (benign(session_id="MCP-B001"), "does not match the contract format"),
    (benign(session_id="MCP-X-B0001"), "does not match the contract format"),
    (benign(session_id="mcp-s-b0001"), "does not match the contract format"),
    (benign(session_id="MCP-H-B0001"), "says Hardware but environment"),
    (benign(session_id="MCP-S-B0001", environment="Hardware",
            capture_file="mcp_benign_hardware_001.pcapng"), "says Software but environment"),
    (attack(session_id="MCP-S-AT08-0001", attack_id="AT-08"), "attack_id must be one of"),
    (benign(protocol="HTTP"), "protocol must be one of"),
    (benign(transport="TLS"), "transport must be one of"),
    (benign(environment="Cloud"), "environment must be one of"),
    (benign(capture_file="capture.pcap"), "does not match"),
    (benign(capture_file="../mcp_benign_software_001.pcapng"), "bare file name"),
    (benign(start_time="21/11/2026 10:30"), "start_time is not ISO 8601"),
    (benign(end_time="2026-11-21T10:29:00.000+05:00"), "is before start_time"),
    (benign(end_time="2026-11-21T10:31:00"), "mix timestamps"),
    (benign(label="Benign "), "leading or trailing spaces"),
    (benign(capture_file=""), "missing required value"),
])
def test_bad_values_rejected(rec, fragment):
    errs = errors(rec)
    assert any(fragment in e for e in errs), errs


# ---- legacy spellings are accepted with a warning -------------------------

def test_legacy_benign_na_warns_but_passes():
    full = {c: "" for c in m.COLUMNS}
    full.update(benign(attack_id="N/A"))
    r = m.check_record(full)
    assert r.ok and any("AT-00" in w for w in r.warnings)


def test_legacy_failure_spelling_warns_but_passes():
    full = {c: "" for c in m.COLUMNS}
    full.update(attack(outcome="Failure"))
    r = m.check_record(full)
    assert r.ok and any("Failed" in w for w in r.warnings)


# ---- cross-row rules ------------------------------------------------------

def _full(rec):
    full = {c: "" for c in m.COLUMNS}
    full.update(rec)
    return full


def test_duplicate_session_id_rejected():
    r = m.check_records([_full(benign()), _full(benign(capture_file="mcp_benign_software_002.pcapng"))])
    assert any("already used" in e for e in r.errors)


def test_overlap_in_shared_capture_rejected():
    a = benign()
    b = benign(session_id="MCP-S-B0002", start_time="2026-11-21T10:30:10.000+05:00",
               end_time="2026-11-21T10:30:20.000+05:00")
    assert any("overlap" in e for e in m.check_records([_full(a), _full(b)]).errors)


def test_back_to_back_sessions_in_shared_capture_allowed():
    a = benign()
    b = benign(session_id="MCP-S-B0002", start_time="2026-11-21T10:30:15.000+05:00",
               end_time="2026-11-21T10:30:20.000+05:00")
    assert m.check_records([_full(a), _full(b)]).ok


def test_mixed_timezone_conventions_rejected():
    a = benign()
    b = benign(session_id="MCP-S-B0002", capture_file="mcp_benign_software_002.pcapng",
               start_time="2026-11-21T11:00:00", end_time="2026-11-21T11:00:05")
    assert any("one convention" in e for e in m.check_records([_full(a), _full(b)]).errors)


# ---- files ----------------------------------------------------------------

def test_init_creates_header_and_refuses_overwrite(tmp_path):
    p = m.init(tmp_path / "manifest.csv")
    assert p.read_text(encoding="utf-8").strip() == ",".join(m.COLUMNS)
    with pytest.raises(m.ManifestError, match="already exists"):
        m.init(p)


def test_append_and_load_round_trip(tmp_path):
    p = tmp_path / "manifest.csv"
    m.append(p, benign())
    m.append(p, attack())
    records, report = m.load(p)
    assert report.ok, report.errors
    assert [r["session_id"] for r in records] == ["MCP-S-B0001", "MCP-S-AT01-0001"]
    assert records[1]["outcome"] == "Success"


def test_append_rejects_invalid_and_writes_nothing(tmp_path):
    p = tmp_path / "manifest.csv"
    m.append(p, benign())
    before = p.read_bytes()
    with pytest.raises(m.ManifestError):
        m.append(p, benign(session_id="MCP-S-B0002", outcome="Success"))
    with pytest.raises(m.ManifestError, match="already used"):
        m.append(p, benign(capture_file="mcp_benign_software_002.pcapng"))
    assert p.read_bytes() == before


def test_append_rejects_unknown_field(tmp_path):
    with pytest.raises(m.ManifestError, match="unknown field"):
        m.append(tmp_path / "manifest.csv", benign(colour="red"))


def test_append_neutralises_csv_injection(tmp_path):
    p = tmp_path / "manifest.csv"
    row = m.append(p, benign(notes='=HYPERLINK("http://evil","x")\nsecond line'))
    assert row["notes"].startswith("'=")
    assert "\n" not in row["notes"]
    records, report = m.load(p)
    assert report.ok and records[0]["notes"] == row["notes"]


def test_load_rejects_unknown_and_missing_columns(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("session_id,label,colour\nMCP-B001,Benign,red\n", encoding="utf-8")
    _, report = m.load(p)
    assert any("missing required column" in e for e in report.errors)
    assert any("unknown column" in e for e in report.errors)


def test_load_rejects_ragged_rows(tmp_path):
    p = tmp_path / "ragged.csv"
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(m.COLUMNS)
        w.writerow(["MCP-S-B0001", "Benign"])
    _, report = m.load(p)
    assert any("fewer values" in e for e in report.errors)


def test_load_accepts_excel_byte_order_mark(tmp_path):
    p = tmp_path / "excel.csv"
    m.append(p, benign())
    p.write_bytes(b"\xef\xbb\xbf" + p.read_bytes())
    _, report = m.load(p)
    assert report.ok, report.errors


def test_timestamp_requires_timezone():
    assert m.timestamp(datetime(2026, 11, 21, 10, 30, tzinfo=PKT)) == "2026-11-21T10:30:00.000+05:00"
    with pytest.raises(m.ManifestError):
        m.timestamp(datetime(2026, 11, 21, 10, 30))


def test_cli_validate_exit_codes(tmp_path, capsys):
    good = tmp_path / "good.csv"
    m.append(good, benign())
    assert m.main(["validate", str(good)]) == 0
    bad = tmp_path / "bad.csv"
    bad.write_text("nonsense\n", encoding="utf-8")
    assert m.main(["validate", str(bad)]) == 1
    assert m.main(["validate", str(tmp_path / "missing.csv")]) == 1
    assert m.main(["frobnicate"]) == 2
