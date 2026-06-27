OWASP_CATEGORIES = [

    "ASI01",

    "ASI02",

    "ASI03",

    "ASI06",

    "ASI07"
]


def calculate_coverage(
    tested_categories
):

    covered = len(
        set(
            tested_categories
        )
    )

    total = len(
        OWASP_CATEGORIES
    )

    return round(
        (covered / total)
        * 100,
        2
    )