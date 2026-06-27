import json


def extract_json_text(filepath):

    try:

        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        return str(data)

    except Exception as error:

        return (
            f"JSON_READ_ERROR: "
            f"{error}"
        )