def classify_risk(score):

    if score >= 90:
        return "LOW"

    elif score >= 70:
        return "MEDIUM"

    return "HIGH"