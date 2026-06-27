import csv


def extract_csv_text(filepath):

    try:

        content = []

        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as file:

            reader = csv.reader(file)

            for row in reader:

                content.extend(row)

        return "\n".join(content)

    except Exception as error:

        return (
            f"CSV_READ_ERROR: "
            f"{error}"
        )