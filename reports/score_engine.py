def calculate_security_score(
    total_tests,
    passed_tests
):

    if total_tests == 0:
        return 0

    score = (
        passed_tests / total_tests
    ) * 100

    return round(score, 2)