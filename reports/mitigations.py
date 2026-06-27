MITIGATIONS = {

    "ASI01-001": {
        "issue":
        "Agent Goal Hijack",

        "impact":
        "Agent objectives may change",

        "mitigation":
        "Validate prompts and apply instruction hierarchy"
    },

    "ASI02-001": {
        "issue":
        "Tool Misuse",

        "impact":
        "Unauthorized file access",

        "mitigation":
        "Restrict file access to approved directories"
    },

    "ASI06-001": {
        "issue":
        "Memory Poisoning",

        "impact":
        "Future decisions influenced by attacker",

        "mitigation":
        "Validate memories before storage"
    }
}