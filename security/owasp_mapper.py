from dataclasses import dataclass


@dataclass(frozen=True)
class OwaspMapping:
    owasp: str
    severity: str
    recommendation: str


OWASP_MAPPINGS: dict[str, OwaspMapping] = {
    "Prompt Injection": OwaspMapping(
        owasp="ASI01",
        severity="HIGH",
        recommendation="Validate external instructions before processing.",
    ),
    "Path Traversal": OwaspMapping(
        owasp="ASI02",
        severity="MEDIUM",
        recommendation="Restrict file access to approved directories.",
    ),
    "Malicious Payload": OwaspMapping(
        owasp="ASI02",
        severity="HIGH",
        recommendation="Block execution of suspicious payloads and investigate the file.",
    ),
    "Privilege Abuse": OwaspMapping(
        owasp="ASI03",
        severity="HIGH",
        recommendation="Implement role-based access controls.",
    ),
    "Memory Poisoning": OwaspMapping(
        owasp="ASI06",
        severity="MEDIUM",
        recommendation="Validate and sanitize memory entries.",
    ),
    "Knowledge Base Poisoning": OwaspMapping(
        owasp="ASI06",
        severity="HIGH",
        recommendation="Verify knowledge source integrity.",
    ),
    "Inter-Agent Spoofing": OwaspMapping(
        owasp="ASI07",
        severity="HIGH",
        recommendation="Authenticate inter-agent communication.",
    ),
}

_UNKNOWN_MAPPING = OwaspMapping(
    owasp="UNKNOWN",
    severity="LOW",
    recommendation="No recommendation available.",
)


def get_owasp_mapping(attack_name: str) -> OwaspMapping:
    return OWASP_MAPPINGS.get(attack_name, _UNKNOWN_MAPPING)