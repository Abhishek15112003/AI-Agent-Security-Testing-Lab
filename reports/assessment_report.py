def generate_report(
    score,
    risk,
    passed,
    failed,
    review
):

    with open(
        "reports/assessment_report.txt",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "AI Agent Security Assessment\n\n"
        )

        file.write(
            f"Passed: {passed}\n"
        )

        file.write(
            f"Failed: {failed}\n"
        )

        file.write(
            f"Review: {review}\n"
        )

        file.write(
            f"\nScore: {score}\n"
        )

        file.write(
            f"\nRisk: {risk}\n"
        )