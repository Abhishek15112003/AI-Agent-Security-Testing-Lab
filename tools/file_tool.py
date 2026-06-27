import os

from logs.security_logger import (
    log_security_event
)

from security.injection_detector import (
    detect_prompt_injection
)

DATA_DIRECTORY = "data"


def read_file(filename):

    if ".." in filename:

        log_security_event(

            "Path Traversal Attempt",

            "MEDIUM"
        )

        return "Access Denied"

    filepath = os.path.join(
        DATA_DIRECTORY,
        filename
    )

    if not os.path.exists(filepath):

        return "File not found"

    with open(
        filepath,
        "r",
        encoding="utf-8"
    ) as file:

        content = file.read()

    result = (
        detect_prompt_injection(
            content
        )
    )

    if result:

        log_security_event(

            "Prompt Injection Detected",

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