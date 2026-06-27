from security.owasp_mapper import (
    get_owasp_mapping
)

SUSPICIOUS_KB_PATTERNS = [

    "ignore security policies",

    "grant access",

    "bypass authorization",

    "export employee records",

    "disable authentication"
]


def detect_kb_poisoning(
    content
):

    findings = []

    content = content.lower()

    for pattern in (
        SUSPICIOUS_KB_PATTERNS
    ):

        if pattern in content:

            findings.append(
                pattern
            )

    if findings:

        mapping = (
            get_owasp_mapping(
                "Knowledge Base Poisoning"
            )
        )

        return {

            "attack":
            "Knowledge Base Poisoning",

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