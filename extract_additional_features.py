"""
extract_additional_features.py
--------------------------------
Module to extract structured numerical features from the 'additional' section
of phishing analysis JSON files.

This section compares 'rd' (root domain) and 'sd' (subdomain) information,
including DNS, SSL, content and historical wayback data.

"""

from typing import Dict, Any
from datetime import datetime


def extract_additional_features(additional: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts comparison and differential features between root domain (rd)
    and subdomain (sd) from the 'additional' section.

    Parameters
    ----------
    additional : dict
        The 'additional' dictionary extracted from the JSON.

    Returns
    -------
    dict
        Dictionary of numeric feature_name: value pairs.
    """

    features = {}

    # -------------------------------
    # Safely extract base sub-blocks
    # -------------------------------
    if not isinstance(additional, dict):
        return features

    rd = additional.get("rd") or {}
    sd = additional.get("sd") or {}

    rd_wayback = rd.get("wayback_info") or {}
    sd_wayback = sd.get("wayback_info") or {}

    rd_content = rd.get("content_info") or {}
    sd_content = sd.get("content_info") or {}

    rd_host = rd.get("host_info") or {}
    sd_host = sd.get("host_info") or {}

    # -------------------------------
    # Wayback (historical activity)
    # -------------------------------
    def count_wayback_entries(wayback_years: Dict[str, Any]) -> int:
        """Count total captures across years (defensive)."""
        if not isinstance(wayback_years, dict):
            return 0
        total = 0
        for months in wayback_years.values():
            if isinstance(months, list):
                total += sum(m for m in months if isinstance(m, (int, float)))
        return total

    rd_wayback_count = count_wayback_entries(rd_wayback.get("years", {}))
    sd_wayback_count = count_wayback_entries(sd_wayback.get("years", {}))

    features["rd_wayback_count"] = rd_wayback_count
    features["sd_wayback_count"] = sd_wayback_count
    features["wayback_diff"] = rd_wayback_count - sd_wayback_count
    features["rd_has_wayback"] = int(rd_wayback_count > 0)
    features["sd_has_wayback"] = int(sd_wayback_count > 0)

    # Time span of captures
    def parse_ts(ts: str):
        if not ts:
            return None
        try:
            return datetime.strptime(ts, "%Y%m%d%H%M%S")
        except Exception:
            return None

    rd_first = parse_ts(rd_wayback.get("first_ts"))
    rd_last = parse_ts(rd_wayback.get("last_ts"))
    features["rd_wayback_span_days"] = (
        (rd_last - rd_first).days if rd_first and rd_last else 0
    )

    # -------------------------------
    # SSL / HTTPS information
    # -------------------------------
    rd_ssl_valid = int(rd_host.get("ssl", {}).get("is_valid_cert", False))
    sd_ssl_valid = int(sd_host.get("ssl", {}).get("is_valid_cert", False))
    features["rd_ssl_valid"] = rd_ssl_valid
    features["sd_ssl_valid"] = sd_ssl_valid
    features["ssl_valid_diff"] = abs(rd_ssl_valid - sd_ssl_valid)

    rd_https = int(rd_host.get("is_https", False))
    sd_https = int(sd_host.get("is_https", False))
    features["https_diff"] = abs(rd_https - sd_https)

    # -------------------------------
    # ASN and geolocation comparison
    # -------------------------------
    rd_maxmind = rd_host.get("maxmind") or []
    sd_maxmind = sd_host.get("maxmind") or []

    def extract_asn_list(maxmind_list):
        if not isinstance(maxmind_list, list):
            return []
        return [
            mm.get("answers", {}).get("asn_code")
            for mm in maxmind_list
            if isinstance(mm, dict) and mm.get("answers")
        ]

    rd_asns = extract_asn_list(rd_maxmind)
    sd_asns = extract_asn_list(sd_maxmind)

    features["rd_unique_asn_count"] = len(set(rd_asns))
    features["sd_unique_asn_count"] = len(set(sd_asns))
    features["asn_overlap"] = int(bool(set(rd_asns) & set(sd_asns)))

    # -------------------------------
    # Content comparison (status, title, etc.)
    # -------------------------------
    rd_status = int(rd_content.get("status_code", 0) or 0)
    sd_status = int(sd_content.get("status_code", 0) or 0)
    features["rd_status_code"] = rd_status
    features["sd_status_code"] = sd_status
    features["status_diff"] = abs(rd_status - sd_status)

    rd_html_len = len(rd_content.get("html", "")) if isinstance(rd_content.get("html"), str) else 0
    sd_html_len = len(sd_content.get("html", "")) if isinstance(sd_content.get("html"), str) else 0
    features["rd_html_len"] = rd_html_len
    features["sd_html_len"] = sd_html_len
    features["html_len_diff"] = abs(rd_html_len - sd_html_len)

    features["rd_has_screenshot"] = int(bool(rd_content.get("screenshot")))
    features["sd_has_screenshot"] = int(bool(sd_content.get("screenshot")))

    # Ratio (avoid division by zero)
    features["html_len_ratio"] = sd_html_len / rd_html_len if rd_html_len > 0 else 0

    # -------------------------------
    # Network/server headers
    # -------------------------------
    def extract_server_from_har(content: Dict[str, Any]) -> str:
        if not isinstance(content, dict):
            return ""
        har = content.get("har") or []
        if not isinstance(har, list) or not har:
            return ""
        first = har[0] if isinstance(har[0], dict) else {}
        headers = first.get("response", {}).get("headers", [])
        if not isinstance(headers, list):
            return ""
        for h in headers:
            if not isinstance(h, dict):
                continue
            if h.get("key", "").lower() == "server":
                return h.get("value", "").lower()
        return ""

    rd_server = extract_server_from_har(rd_content)
    sd_server = extract_server_from_har(sd_content)

    features["same_server_type"] = int(rd_server == sd_server)
    features["rd_server_envoy"] = int("envoy" in rd_server)
    features["sd_server_envoy"] = int("envoy" in sd_server)

    # -------------------------------
    # Derived global indicators
    # -------------------------------
    features["same_asn_and_server"] = int(features["asn_overlap"] and features["same_server_type"])
    features["is_likely_legit"] = int(
        rd_wayback_count > 0 and features["same_server_type"] and features["asn_overlap"]
    )

    return features


# -------------------------------
# Quick test
# -------------------------------
if __name__ == "__main__":
    import json

    example = {
        "rd": {
            "wayback_info": None,
            "content_info": {"status_code": 200, "html": "<html></html>"},
            "host_info": {"is_https": True, "ssl": {"is_valid_cert": True}},
        },
        "sd": {
            "wayback_info": {"years": {"2024": [1, 2]}},
            "content_info": {"status_code": 404, "html": ""},
            "host_info": {"is_https": True, "ssl": {"is_valid_cert": False}},
        },
    }

    print(json.dumps(extract_additional_features(example), indent=2))
