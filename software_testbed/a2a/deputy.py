"""The Lab Assistant's own authorization check (the "deputy" check).

The Lab Assistant calls the MCP server with its own privileged service
account (ops-agent, admin), as real assistant agents usually do. On its own
that is the classic confused-deputy setup: any requester could get the
assistant to use admin rights for them. So before acting, the assistant
enforces the *requester's* permissions:

* the model is only shown the tools the requester's role may use;
* calls to other tools are refused without reaching the MCP server;
* admin-only files (finance/, secrets/) cannot be read for non-admins, and
  are removed from file listings and search results.

These rules mirror the MCP server's own rules (tests check they agree).
Confused-deputy experiments (AT-04) target exactly this layer.

Notes tools are not offered: every call uses the one service account, so
different requesters' notes would be mixed together.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

ROLES = ("anonymous", "viewer", "operator", "admin")
RESTRICTED_FOLDERS = ("finance/", "secrets/")

# Minimum requester role per tool the assistant offers.
TOOL_MIN_ROLE = {
    "calculate": "anonymous",
    "get_weather": "anonymous",
    "get_server_status": "anonymous",
    "list_files": "viewer",
    "read_file": "viewer",
    "search_files": "viewer",
    "list_devices": "viewer",
    "read_sensor": "viewer",
    "set_led": "operator",
    "sound_buzzer": "operator",
}


def allowed(role: str, tool: str) -> bool:
    need = TOOL_MIN_ROLE.get(tool)
    return need is not None and ROLES.index(role) >= ROLES.index(need)


def _restricted(path: str) -> bool:
    """True for a restricted folder itself ("finance", "finance/") or anything inside it."""
    if not isinstance(path, str):
        return False
    p = path.strip().lstrip("/")
    return any(p == folder.rstrip("/") or p.startswith(folder) for folder in RESTRICTED_FOLDERS)


@dataclass
class _Text:
    text: str
    type: str = "text"


@dataclass
class DeputyResult:
    """Looks like an MCP tool result, for refusals and filtered results."""

    content: list
    structured_content: object = None
    is_error: bool = False


def _refusal(message: str) -> DeputyResult:
    return DeputyResult(content=[_Text(f"Refused by assistant policy: {message}")], is_error=True)


@dataclass
class Decision:
    tool: str
    arguments: dict
    outcome: str          # forwarded | refused | filtered
    detail: str = ""


@dataclass
class DeputySession:
    """Wraps an MCP session; enforces the requester's role on every call."""

    session: object
    requester_role: str
    decisions: list[Decision] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.requester_role not in ROLES:
            raise ValueError(f"unknown role {self.requester_role!r}")

    async def list_tools(self):
        listed = await self.session.list_tools()
        listed.tools = [t for t in listed.tools if allowed(self.requester_role, t.name)]
        return listed

    async def call_tool(self, name: str, arguments: dict):
        arguments = dict(arguments or {})
        if not allowed(self.requester_role, name):
            need = TOOL_MIN_ROLE.get(name, "a tool the assistant does not offer")
            self.decisions.append(Decision(name, arguments, "refused", f"requires {need}"))
            return _refusal(f"{name} requires the {need} role (requester is {self.requester_role})")

        admin = self.requester_role == "admin"
        if name == "read_file" and not admin and _restricted(arguments.get("path", "")):
            self.decisions.append(Decision(name, arguments, "refused", "restricted path"))
            return _refusal(f"{arguments.get('path')} is admin-only (requester is {self.requester_role})")
        if name == "list_files" and not admin and _restricted(arguments.get("folder", "")):
            self.decisions.append(Decision(name, arguments, "refused", "restricted folder"))
            return _refusal(f"{arguments.get('folder')} is admin-only (requester is {self.requester_role})")

        result = await self.session.call_tool(name, arguments)
        if name in ("list_files", "search_files") and not admin and not result.is_error:
            filtered = self._filter_listing(result)
            if filtered is not None:
                self.decisions.append(Decision(name, arguments, "filtered", "admin-only entries removed"))
                return filtered
        self.decisions.append(Decision(name, arguments, "forwarded"))
        return result

    @staticmethod
    def _filter_listing(result):
        """Remove admin-only entries from a list_files/search_files result.

        Returns None if nothing had to be removed. If the result cannot be
        inspected, it is withheld entirely rather than passed on unchecked.
        """
        data = result.structured_content
        items = data.get("result") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return _refusal("could not verify the listing")
        kept = [i for i in items if not (isinstance(i, dict) and _restricted(i.get("path", "")))]
        if len(kept) == len(items):
            return None
        return DeputyResult(content=[_Text(json.dumps(kept, ensure_ascii=False))],
                            structured_content={"result": kept})
