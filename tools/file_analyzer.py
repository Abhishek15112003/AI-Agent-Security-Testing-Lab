import os

from security.injection_detector import detect_prompt_injection
from security.knowledge_detector import detect_kb_poisoning
from security.privilege_detector import detect_privilege_abuse
from security.agent_detector import detect_agent_spoofing
from security.malware_detector import detect_malware
from security.owasp_mapper import get_owasp_mapping, OwaspMapping
from security.virustotal_client import scan_file
from tools.pdf_reader import extract_pdf_text
from tools.docx_reader import extract_docx_text
from tools.xml_reader import extract_xml_text
from tools.json_reader import extract_json_text
from tools.csv_reader import extract_csv_text
from security.malware_risk import calculate_malware_risk
from logs.security_logger import log_security_event

DETECTORS = [
    ("Prompt Injection",         detect_prompt_injection),
    ("Knowledge Base Poisoning", detect_kb_poisoning),
    ("Privilege Abuse",          detect_privilege_abuse),
    ("Inter-Agent Spoofing",     detect_agent_spoofing),
    ("Malicious Payload",        detect_malware),
]

_SECTION = "────────────────────"


def _format_finding(attack: str, matches: list[str], mapping: OwaspMapping) -> str:
    return (
        f"Attack:           {attack}\n"
        f"OWASP:            {mapping.owasp}\n"
        f"Severity:         {mapping.severity}\n"
        f"Recommendation:   {mapping.recommendation}\n"
        f"Matched Patterns: {', '.join(matches)}"
    )


def _format_virustotal(vt: dict) -> str:
    header = f"VIRUSTOTAL ANALYSIS\n{_SECTION}"
    if "error" in vt:
        return f"{header}\nError: {vt['error']}"
    return (
        f"{header}\n"
        f"Malicious:    {vt['malicious']}\n"
        f"Suspicious:   {vt['suspicious']}\n"
        f"Harmless:     {vt['harmless']}\n"
        f"Undetected:   {vt['undetected']}\n"
        f"Threat Level: {vt['threat_level']}"
    )


def analyze_file(filepath: str) -> str:
    if not os.path.exists(filepath):
        return "File not found."

    try:
        extension = os.path.splitext(filepath)[1].lower()
        if extension == ".pdf":
            content = extract_pdf_text(filepath)
        elif extension == ".docx":
            content = extract_docx_text(filepath)
        elif extension == ".xml":
            content = extract_xml_text(filepath)
        elif extension == ".json":
            content = extract_json_text(filepath)
        elif extension == ".csv":
            content = extract_csv_text(filepath)
        else:
            # .log and any other plain-text format
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
    except Exception as e:
        return f"Unable to read file: {e}"

    findings = [
        (label, matches)
        for label, detect in DETECTORS
        if (matches := detect(content))
    ]

    local_header = f"LOCAL ANALYSIS\n{_SECTION}"
    if findings:
        local_entries = []
        attack_names = []
        severities = []
        
        for attack, matches in findings:
            mapping = get_owasp_mapping(attack)
            attack_names.append(attack)
            severities.append(mapping.severity)
            
            # Extract matched patterns list depending on return type of detector
            if isinstance(matches, dict):
                matched_patterns = matches.get("findings", [])
            else:
                matched_patterns = matches

            entry = _format_finding(attack, matched_patterns, mapping)
            if attack == "Malicious Payload":
                risk = calculate_malware_risk(matched_patterns)
                entry += f"\nRisk Level: {risk}"
                if risk in ["HIGH", "CRITICAL"]:
                    severities.append(risk)
            local_entries.append(entry)

        # Determine highest severity
        severity_priority = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        highest_severity = "LOW"
        for sev in severities:
            if severity_priority.get(sev, 1) > severity_priority.get(highest_severity, 1):
                highest_severity = sev
                
        # Log a single consolidated security event
        filename = os.path.basename(filepath)
        if len(attack_names) > 1:
            consolidated_event = f"Multi-Vector File Attack: {', '.join(attack_names)} in {filename}"
        else:
            consolidated_event = f"{attack_names[0]} Detected in {filename}"
            
        log_security_event(consolidated_event, highest_severity)
        local_section = local_header + "\n\n" + "\n\n".join(local_entries)
    else:
        local_section = f"{local_header}\nNo Security Issues Found\n\nFile appears safe."

    vt_section = _format_virustotal(scan_file(filepath))

    return f"{local_section}\n\n{vt_section}"