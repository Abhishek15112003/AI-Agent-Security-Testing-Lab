def calculate_category_scores(
    results
):

    scores = {}

    for category, status in results:

        if category not in scores:

            scores[
                category
            ] = {
                "pass": 0,
                "fail": 0
            }

        if status == "PASS":

            scores[
                category
            ]["pass"] += 1

        elif status == "FAIL":

            scores[
                category
            ]["fail"] += 1

    return scores