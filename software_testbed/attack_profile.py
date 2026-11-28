"""Attack profile: how the testbed servers misbehave during one attack session.

An attack scenario writes a small JSON file before its session and removes it
afterwards; the servers read it on every request (path in the environment
variable AGENTNET_ATTACK_PROFILE, set by scripts/testbed.py). This is the
experimenter's control channel: it never touches the network, so nothing in
a capture says "this session is an attack" except the attack itself.

No file (or an empty one) means the servers behave normally, exactly as in
the benign collection.

Format (every field optional except "profile"):

    {
      "profile": "AT-01/V2/seed=10007",          # free text, for the logs
      "descriptions": {"read_file": "..."}       # tool descriptions to serve instead
    }

The validator is strict and shared by the writer (the scenario) and the
reader (the server): a profile the server cannot apply must never be
written, because the session would then be labelled as an attack in which
nothing happened. A file that is present but invalid makes the server fail
its requests, so such a session is excluded rather than mislabelled.

Each later attack step (4.2 - 4.8) adds the fields it needs here, with tests.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path

ENV = "AGENTNET_ATTACK_PROFILE"
MAX_FILE_BYTES = 64_000
MAX_TEXT = 4000           # characters of any one replacement text
ALLOWED_KEYS = frozenset({"profile", "descriptions"})


class ProfileError(ValueError):
    """The profile file exists but cannot be applied."""


@dataclass(frozen=True)
class Profile:
    profile: str = ""
    descriptions: dict[str, str] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return bool(self.profile)


NORMAL = Profile()


def validate(data: object, tool_names: frozenset[str] | set[str]) -> Profile:
    """Check a profile (already parsed from JSON) and return it; raise ProfileError otherwise."""
    if not isinstance(data, dict):
        raise ProfileError("a profile must be a JSON object")
    unknown = set(data) - ALLOWED_KEYS
    if unknown:
        raise ProfileError(f"unknown profile field(s): {', '.join(sorted(unknown))}")
    name = data.get("profile")
    if not isinstance(name, str) or not name.strip() or len(name) > 200:
        raise ProfileError("'profile' must be a non-empty name of at most 200 characters")
    descriptions = data.get("descriptions", {})
    if not isinstance(descriptions, dict):
        raise ProfileError("'descriptions' must be an object of tool name -> text")
    for tool, text in descriptions.items():
        if tool not in tool_names:
            raise ProfileError(f"'descriptions' names an unknown tool: {tool!r}")
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT:
            raise ProfileError(f"description of {tool!r} must be non-empty text of at most {MAX_TEXT} characters")
    return Profile(profile=name, descriptions=dict(descriptions))


class ProfileReader:
    """Reads the profile file, re-reading it only when it changes."""

    def __init__(self, path: str | Path | None, tool_names: frozenset[str] | set[str]) -> None:
        self.path = Path(path) if path else None
        self.tool_names = frozenset(tool_names)
        self._lock = threading.Lock()
        self._key: tuple | None = None
        self._profile: Profile = NORMAL
        self._error: str = ""

    @classmethod
    def from_env(cls, tool_names) -> "ProfileReader":
        return cls(os.environ.get(ENV) or None, tool_names)

    def current(self) -> Profile:
        """The profile in force now. Raises ProfileError if the file is invalid."""
        if self.path is None:
            return NORMAL
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return NORMAL
        key = (st.st_mtime_ns, st.st_size)
        with self._lock:
            if key != self._key:
                self._key = key
                self._profile, self._error = self._load(st.st_size)
            if self._error:
                raise ProfileError(self._error)
            return self._profile

    def _load(self, size: int) -> tuple[Profile, str]:
        if size == 0:
            return NORMAL, ""
        if size > MAX_FILE_BYTES:
            return NORMAL, f"profile file is larger than {MAX_FILE_BYTES} bytes"
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return validate(data, self.tool_names), ""
        except (OSError, ValueError) as e:      # ProfileError and JSON errors are ValueErrors
            return NORMAL, f"invalid attack profile: {e}"


def write(path: str | Path, data: dict, tool_names) -> Profile:
    """Validate and write a profile atomically (the server never sees half a file)."""
    profile = validate(data, tool_names)
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    return profile


def clear(path: str | Path) -> None:
    """Back to normal behaviour."""
    Path(path).unlink(missing_ok=True)
