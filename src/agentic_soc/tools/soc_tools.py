"""Investigation tools exposed to the agents.

Design choice: the model never writes raw SIEM queries (SPL/KQL/SQL). It fills in a
narrow, typed query interface. That removes query-injection and runaway-cost classes of
failure and makes every lookup auditable. A real deployment would implement the same
interface on top of Splunk, Sentinel or Databricks.
"""

from __future__ import annotations

import ipaddress
import json
from collections import Counter
from typing import Any

from agentic_soc.tools.labdata import LabData
from agentic_soc.tools.registry import Tool

MAX_EVENTS = 50


def _norm_ts(value: str | None) -> str | None:
    if not value:
        return None
    return value.replace("+00:00", "Z")


def build_tools(data: LabData) -> list[Tool]:
    sources = sorted(data.logs)

    def _match(
        event: dict[str, Any], filters: dict[str, Any] | None, contains: str | None, start: str | None, end: str | None
    ) -> bool:
        for key, want in (filters or {}).items():
            if str(event.get(key, "")).lower() != str(want).lower():
                return False
        if contains and contains.lower() not in json.dumps(event).lower():
            return False
        ts = event.get("timestamp", "")
        if start and ts < start:
            return False
        return not (end and ts > end)

    def search_logs(
        source: str,
        filters: dict[str, Any] | None = None,
        contains: str | None = None,
        start: str | None = None,
        end: str | None = None,
        limit: int = 25,
    ) -> dict[str, Any]:
        if source not in data.logs:
            raise ValueError(f"unknown source '{source}'; available: {sources}")
        limit = max(1, min(int(limit), MAX_EVENTS))
        start, end = _norm_ts(start), _norm_ts(end)
        hits = [e for e in data.logs[source] if _match(e, filters, contains, start, end)]
        return {
            "source": source,
            "total_matches": len(hits),
            "returned": min(len(hits), limit),
            "events": hits[:limit],
        }

    def summarize_logs(
        source: str,
        group_by: str,
        filters: dict[str, Any] | None = None,
        contains: str | None = None,
        start: str | None = None,
        end: str | None = None,
    ) -> dict[str, Any]:
        if source not in data.logs:
            raise ValueError(f"unknown source '{source}'; available: {sources}")
        start, end = _norm_ts(start), _norm_ts(end)
        hits = [e for e in data.logs[source] if _match(e, filters, contains, start, end)]
        counts = Counter(str(e.get(group_by, "<missing>")) for e in hits)
        times = sorted(e.get("timestamp", "") for e in hits)
        return {
            "source": source,
            "group_by": group_by,
            "total_matches": len(hits),
            "distinct_values": len(counts),
            "first_seen": times[0] if times else None,
            "last_seen": times[-1] if times else None,
            "top": counts.most_common(20),
        }

    def lookup_ip_reputation(ip: str) -> dict[str, Any]:
        addr = ipaddress.ip_address(ip)
        if ip in data.intel:
            return {"ip": ip, "found": True, **data.intel[ip]}
        for key, record in data.intel.items():
            if "/" in key and addr in ipaddress.ip_network(key):
                return {"ip": ip, "found": True, "matched_range": key, **record}
        return {"ip": ip, "found": False, "note": "no threat-intel record"}

    def get_user_context(user: str) -> dict[str, Any]:
        for name, record in data.users.items():
            if name.lower() == user.lower():
                return {"user": name, "found": True, **record}
        return {"user": user, "found": False}

    def get_host_context(host: str) -> dict[str, Any]:
        for name, record in data.hosts.items():
            if name.lower() == host.lower():
                return {"host": name, "found": True, **record}
        return {"host": host, "found": False}

    def lookup_attack_technique(technique_id: str) -> dict[str, Any]:
        record = data.attack.get(technique_id.upper())
        if record:
            return {"id": technique_id.upper(), "found": True, **record}
        return {
            "id": technique_id,
            "found": False,
            "note": "not in the local ATT&CK subset; only use it if you are certain it exists",
        }

    def find_related_alerts(entity: str) -> dict[str, Any]:
        needle = entity.lower()
        related = [
            {"id": a.id, "title": a.title, "severity": a.severity.value, "created_at": a.created_at.isoformat()}
            for a in data.alerts
            if any(needle == v.lower() for values in a.entities.values() for v in values)
        ]
        return {"entity": entity, "count": len(related), "alerts": related}

    filters_schema = {
        "type": "object",
        "description": 'Exact-match (case-insensitive) field filters, e.g. {"client_ip": "203.0.113.10"}',
        "additionalProperties": {"type": "string"},
    }
    time_props = {
        "start": {"type": "string", "description": "ISO-8601 UTC lower bound, e.g. 2026-09-14T02:00:00Z"},
        "end": {"type": "string", "description": "ISO-8601 UTC upper bound"},
    }

    return [
        Tool(
            "search_logs",
            f"Return raw events from a log source. Sources: {sources}. Use filters and a time "
            "window to keep results small; use summarize_logs for counts.",
            {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "enum": sources},
                    "filters": filters_schema,
                    "contains": {"type": "string", "description": "Case-insensitive substring match across the event"},
                    **time_props,
                    "limit": {"type": "integer", "minimum": 1, "maximum": MAX_EVENTS},
                },
                "required": ["source"],
            },
            search_logs,
        ),
        Tool(
            "summarize_logs",
            "Count events grouped by one field (top 20 values) with first/last seen. Ideal for "
            "volumes, distinct usernames per IP, status-code splits.",
            {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "enum": sources},
                    "group_by": {"type": "string"},
                    "filters": filters_schema,
                    "contains": {"type": "string"},
                    **time_props,
                },
                "required": ["source", "group_by"],
            },
            summarize_logs,
        ),
        Tool(
            "lookup_ip_reputation",
            "Threat-intel and ownership lookup for an IP address (includes known corporate ranges).",
            {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
            lookup_ip_reputation,
        ),
        Tool(
            "get_user_context",
            "Identity directory record: type, role, privilege, usual countries, devices, ownership.",
            {"type": "object", "properties": {"user": {"type": "string"}}, "required": ["user"]},
            get_user_context,
            untrusted_output=False,
        ),
        Tool(
            "get_host_context",
            "Asset inventory record for a host: owner, criticality, network, protection status.",
            {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
            get_host_context,
            untrusted_output=False,
        ),
        Tool(
            "lookup_attack_technique",
            "Validate a MITRE ATT&CK technique ID and get its name and tactic.",
            {"type": "object", "properties": {"technique_id": {"type": "string"}}, "required": ["technique_id"]},
            lookup_attack_technique,
            untrusted_output=False,
        ),
        Tool(
            "find_related_alerts",
            "Find other alerts that share an entity (IP, user, host, access key).",
            {"type": "object", "properties": {"entity": {"type": "string"}}, "required": ["entity"]},
            find_related_alerts,
        ),
    ]
