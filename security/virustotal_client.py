import json
import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

_API_KEY = os.getenv("VT_API_KEY")
_BASE_URL = "https://www.virustotal.com/api/v3"
_HEADERS = {"x-apikey": _API_KEY}

_MAX_RETRIES = 5
_POLL_DELAY = 5   # seconds between status checks
_TIMEOUT = 30     # seconds per HTTP request

_REPORTS_DIR = "reports"
_VT_RESULTS_FILE = os.path.join(_REPORTS_DIR, "vt_results.json")


def _get_threat_level(malicious: int, suspicious: int) -> str:
    score = malicious * 2 + suspicious
    if score == 0:  return "CLEAN"
    if score <= 2:  return "LOW"
    if score <= 5:  return "MEDIUM"
    if score <= 10: return "HIGH"
    return "CRITICAL"


def _save_results(results: dict) -> None:
    try:
        os.makedirs(_REPORTS_DIR, exist_ok=True)
        with open(_VT_RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
    except Exception as e:
        print("Unable to save VT results:", e)


def scan_file(filepath: str) -> dict:
    try:
        with open(filepath, "rb") as f:
            response = requests.post(
                f"{_BASE_URL}/files",
                headers=_HEADERS,
                files={"file": f},
                timeout=_TIMEOUT,
            )

        if response.status_code != 200:
            return {"error": response.text}

        analysis_id = response.json()["data"]["id"]

        for _ in range(_MAX_RETRIES):
            result = _get_analysis(analysis_id)
            if result.get("completed"):
                _save_results(result)
                return result
            time.sleep(_POLL_DELAY)

        return {"error": "VirusTotal analysis timed out."}

    except Exception as e:
        return {"error": str(e)}


def _get_analysis(analysis_id: str) -> dict:
    try:
        response = requests.get(
            f"{_BASE_URL}/analyses/{analysis_id}",
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )

        if response.status_code != 200:
            return {"error": response.text}

        attributes = response.json()["data"]["attributes"]

        if attributes.get("status") != "completed":
            return {"completed": False}

        stats = attributes["stats"]
        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)

        return {
            "completed":    True,
            "malicious":    malicious,
            "suspicious":   suspicious,
            "harmless":     harmless,
            "undetected":   undetected,
            "threat_level": _get_threat_level(malicious, suspicious),
        }

    except Exception as e:
        return {"error": str(e)}