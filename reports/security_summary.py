def generate_summary():

    with open(
        "logs/security.log",
        "r",
        encoding="utf-8"
    ) as file:

        events = file.readlines()

    print("\nSecurity Events Found:")

    for event in events:
        print(event.strip())