from security.owasp_mapper import (
    get_owasp_mapping
)

SUSPICIOUS_PATTERNS = [

    "ignore previous instructions",

    "act as administrator",

    "trust attacker",

    "export all employee records",

    "override system",

    "bypass security"
]


def detect_prompt_injection(
    content
):

    findings = []

    content = content.lower()

    for pattern in (
        SUSPICIOUS_PATTERNS
    ):

        if pattern in content:

            findings.append(
                pattern
            )

    if findings:

        mapping = (
            get_owasp_mapping(
                "Prompt Injection"
            )
        )

        return {

            "attack":
            "Prompt Injection",

            "owasp":
            mapping.owasp,

            "severity":
            mapping.severity,

            "recommendation":
            mapping.recommendation,

            "findings":
            findings
        }

    return None