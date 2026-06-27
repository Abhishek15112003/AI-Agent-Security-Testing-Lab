import json
from logs.security_logger import (
    log_security_event
)

MEMORY_FILE = "memory/memory.json"


def save_memory(memory_text):

    with open(MEMORY_FILE, "r", encoding="utf-8") as file:
        memories = json.load(file)

    memories.append({
        "memory": memory_text
    })

    with open(MEMORY_FILE, "w", encoding="utf-8") as file:
        json.dump(memories, file, indent=4)

    # Detect memory poisoning attempts
    if (
        "trust attacker" in memory_text.lower()
        or
        "ignore security" in memory_text.lower()
    ):

        log_security_event(
            "Memory Poisoning Attempt",
            "MEDIUM"
        )

    return "Memory Stored Successfully"


def get_memories():

    with open(MEMORY_FILE, "r", encoding="utf-8") as file:
        memories = json.load(file)

    if not memories:
        return "No memories found"

    output = []

    for item in memories:
        output.append(item["memory"])

    return "\n".join(output)