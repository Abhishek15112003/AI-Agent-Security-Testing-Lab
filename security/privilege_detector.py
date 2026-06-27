SUSPICIOUS_PRIVILEGE_PATTERNS = [
    "grant admin access",
    "administrator access",
    "become root",
    "sudo su",
    "sudo -i",
    "elevate privileges",
    "disable authorization",
    "disable access control",
    "add user to admin group",
    "bypass authorization",
]


def detect_privilege_abuse(content: str) -> list[str]:
    content = content.lower()
    return [
        pattern
        for pattern in SUSPICIOUS_PRIVILEGE_PATTERNS
        if pattern in content
    ]