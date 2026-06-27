from reports.mitigations import MITIGATIONS


def get_mitigation(attack_id):

    if attack_id in MITIGATIONS:

        return MITIGATIONS[attack_id]

    return None