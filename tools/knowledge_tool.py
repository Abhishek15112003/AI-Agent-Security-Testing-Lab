import os

from security.knowledge_detector import (
    detect_kb_poisoning
)

from logs.security_logger import (
    log_security_event
)

KB_PATH = "knowledge_base"


def search_knowledge(filename):

    filepath = os.path.join(
        KB_PATH,
        filename
    )

    if not os.path.exists(filepath):

        return "Knowledge Not Found"

    with open(
        filepath,
        "r",
        encoding="utf-8"
    ) as file:

        content = file.read()

    result = detect_kb_poisoning(
        content
    )

    if result:

        log_security_event(

            "Knowledge Base Poisoning",

            result["severity"]
        )

        return f"""
ATTACK DETECTED

Attack:
{result['attack']}

OWASP:
{result['owasp']}

Severity:
{result['severity']}

Recommendation:
{result['recommendation']}

Matched Patterns:
{', '.join(result['findings'])}
"""

    return content