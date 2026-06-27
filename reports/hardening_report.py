from reports.mitigation_engine import (
    get_mitigation
)


def generate_hardening_report(
    findings
):

    with open(
        "reports/hardening_report.txt",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "AI Agent Hardening Report\n\n"
        )

        for finding in findings:

            mitigation = get_mitigation(
                finding
            )

            if mitigation:

                file.write(
                    f"Issue: "
                    f"{mitigation['issue']}\n"
                )

                file.write(
                    f"Impact: "
                    f"{mitigation['impact']}\n"
                )

                file.write(
                    f"Mitigation: "
                    f"{mitigation['mitigation']}\n"
                )

                file.write(
                    "-" * 50 + "\n"
                )