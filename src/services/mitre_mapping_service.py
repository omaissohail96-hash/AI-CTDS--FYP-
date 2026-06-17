from __future__ import annotations

from typing import Any, Dict, List


class MITREMappingService:
    """
    Static ATT&CK mapping layer for IDS detections.
    Keeps mappings deterministic and explainable for scan history, dashboards,
    hunting views, and reports.
    """

    _CATALOG: Dict[str, Dict[str, Any]] = {
        "T1566": {
            "technique_id": "T1566",
            "technique": "Phishing",
            "tactic": "Initial Access",
            "description": "Adversaries send phishing messages or links to gain access.",
            "severity": "HIGH",
        },
        "T1566.002": {
            "technique_id": "T1566.002",
            "technique": "Spearphishing Link",
            "tactic": "Initial Access",
            "description": "A malicious link is used to direct users to credential theft or malware delivery.",
            "severity": "HIGH",
        },
        "T1056": {
            "technique_id": "T1056",
            "technique": "Input Capture",
            "tactic": "Credential Access",
            "description": "Credential harvesting behavior may capture user input or authentication secrets.",
            "severity": "CRITICAL",
        },
        "T1190": {
            "technique_id": "T1190",
            "technique": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": "Web application exploitation can abuse public endpoints for initial access.",
            "severity": "CRITICAL",
        },
        "T1595": {
            "technique_id": "T1595",
            "technique": "Active Scanning",
            "tactic": "Reconnaissance",
            "description": "Network reconnaissance or scanning probes exposed hosts and services.",
            "severity": "MEDIUM",
        },
        "T1046": {
            "technique_id": "T1046",
            "technique": "Network Service Discovery",
            "tactic": "Discovery",
            "description": "Discovery activity attempts to identify reachable services and ports.",
            "severity": "HIGH",
        },
        "T1110": {
            "technique_id": "T1110",
            "technique": "Brute Force",
            "tactic": "Credential Access",
            "description": "Repeated authentication failures can indicate password guessing or brute force.",
            "severity": "HIGH",
        },
    }

    _KEYWORD_MAP = (
        ("phishing email", ["T1566"]),
        ("phishing", ["T1566", "T1566.002"]),
        ("credential", ["T1056", "T1566.002"]),
        ("harvest", ["T1056", "T1566.002"]),
        ("sql injection", ["T1190"]),
        ("sqli", ["T1190"]),
        ("cross-site scripting", ["T1190"]),
        ("xss", ["T1190"]),
        ("path traversal", ["T1190"]),
        ("network anomaly", ["T1595", "T1046"]),
        ("port scanning", ["T1595", "T1046"]),
        ("reconnaissance", ["T1595", "T1046"]),
        ("failed authentication", ["T1110"]),
        ("brute force", ["T1110"]),
    )

    @classmethod
    def list_mappings(cls) -> List[Dict[str, Any]]:
        return list(cls._CATALOG.values())

    @classmethod
    def get_mapping(cls, technique_id: str) -> Dict[str, Any] | None:
        return cls._CATALOG.get(technique_id.upper())

    @classmethod
    def map_detection(
        cls,
        input_type: str,
        attack_type: str | None,
        vector_details: List[Dict[str, Any]] | None = None,
        metadata: Dict[str, Any] | None = None,
    ) -> List[Dict[str, Any]]:
        search_blob = " ".join(
            str(part or "")
            for part in [
                input_type,
                attack_type,
                metadata,
                " ".join(str(item.get("attack_type", "")) for item in vector_details or []),
                " ".join(str((item.get("metadata") or {}).get("matched_pattern", "")) for item in vector_details or []),
            ]
        ).lower()

        technique_ids: List[str] = []
        for keyword, mapped_ids in cls._KEYWORD_MAP:
            if keyword in search_blob:
                technique_ids.extend(mapped_ids)

        if input_type == "email" and not technique_ids:
            technique_ids.append("T1566")
        elif input_type == "web" and not technique_ids:
            technique_ids.append("T1190")
        elif input_type == "network" and not technique_ids:
            technique_ids.append("T1046")

        deduped = []
        seen = set()
        for technique_id in technique_ids:
            if technique_id in seen:
                continue
            seen.add(technique_id)
            mapping = cls.get_mapping(technique_id)
            if mapping:
                deduped.append(mapping)
        return deduped
