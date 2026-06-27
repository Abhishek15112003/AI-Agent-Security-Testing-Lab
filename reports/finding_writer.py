def write_finding(
    attack_id,
    attack_name,
    severity
):

    with open(
        "reports/findings.txt",
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            f"{attack_id} | "
            f"{attack_name} | "
            f"{severity}\n"
        )