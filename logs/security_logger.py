from datetime import datetime


def log_security_event(
    event,
    severity
):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    log_entry = (
        f"{timestamp}|"
        f"{severity}|"
        f"{event}\n"
    )

    with open(
        "logs/security.log",
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            log_entry
        )