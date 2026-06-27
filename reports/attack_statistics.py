def count_attacks(
    attacks
):

    stats = {}

    for attack in attacks:

        category = attack[
            "id"
        ].split("-")[0]

        stats[
            category
        ] = stats.get(
            category,
            0
        ) + 1

    return stats