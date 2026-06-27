from datetime import datetime

def log_activity(message):
    with open(
        "logs/activity.log",
        "a",
        encoding="utf-8"
    ) as logfile:

        logfile.write(
            f"{datetime.now()} - {message}\n"
        )