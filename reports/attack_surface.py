ATTACK_SURFACE = {

    "Memory":
    [
        "Memory Poisoning",
        "Persistence"
    ],

    "File Tool":
    [
        "Path Traversal",
        "Unauthorized Access"
    ],

    "Database":
    [
        "Data Extraction",
        "Sensitive Records"
    ],

    "Agent":
    [
        "Goal Hijack",
        "Prompt Injection"
    ],

    "Documents":
    [
        "Indirect Prompt Injection",
        "Malicious Content",
        "Embedded Instructions"
    ]
}


def display_attack_surface():

    for component, risks in (
        ATTACK_SURFACE.items()
    ):

        print(
            f"\n{component}"
        )

        for risk in risks:

            print(
                f"  - {risk}"
            )