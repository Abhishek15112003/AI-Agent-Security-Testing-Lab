from security.owasp_mapper import (
    get_owasp_mapping
)

SUSPICIOUS_AGENT_PATTERNS = [

    "agent_a authorized",

    "agent_b says",

    "agent_c approved",

    "grant admin access",

    "authorized data export"
]


def detect_agent_spoofing(
    message
):

    findings = []

    lower_message = (
        message.lower()
    )

    for pattern in (
        SUSPICIOUS_AGENT_PATTERNS
    ):

        if pattern in lower_message:

            findings.append(
                pattern
            )

    if findings:

        mapping = (
            get_owasp_mapping(
                "Inter-Agent Spoofing"
            )
        )

        return {

            "attack":
            "Inter-Agent Spoofing",

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