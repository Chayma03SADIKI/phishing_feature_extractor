"""
extract_general_features.py
--------------------------------
Module to extract simple scalar, lexical, and categorical features from
the top-level JSON keys (including 'url', 'tech_info', DNS, and content metadata).

These features provide a quick overview of the URL structure, encoding patterns,
and general status indicators relevant for phishing detection.

"""

from typing import Dict, Any
import re
from urllib.parse import urlparse


def extract_general_features(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts general and URL-level features from the JSON root.

    Parameters
    ----------
    data : dict
        The full JSON dictionary (at the top level of each file).

    Returns
    -------
    dict
        Dictionary of feature_name: numeric_value pairs.
    """

    features = {}

    # ============================================================
    # URL structure analysis
    # ============================================================
    url = data.get("url", "") or ""
    parsed = urlparse(url)

    features["url_length"] = len(url)
    features["scheme_http"] = int(parsed.scheme == "http")
    features["scheme_https"] = int(parsed.scheme == "https")

    # Path & query analysis
    path = parsed.path or ""
    query = parsed.query or ""
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    features["num_path_segments"] = path.count("/") if path else 0
    features["num_query_params"] = query.count("&") + 1 if query else 0
    features["has_query"] = int(bool(query))

    # Filename / extension detection
    match_ext = re.search(r"\.([a-zA-Z0-9]{1,6})$", path)
    features["has_file_extension"] = int(bool(match_ext))
    features["file_extension_len"] = len(match_ext.group(1)) if match_ext else 0

    # ============================================================
    # Subdomain analysis
    # ============================================================
    subdomain = data.get("subdomain", "") or parsed.netloc or ""
    features["has_subdomain"] = int(data.get("has_subdomain", False))
    features["subdomain_length"] = len(subdomain)
    features["num_subdomain_levels"] = subdomain.count(".")
    features["contains_random_subdomain"] = int(bool(re.search(r"[0-9a-z]{15,}", subdomain)))

    # ============================================================
    # URL lexical/entropy indicators
    # ============================================================
    features["num_digits_in_url"] = len(re.findall(r"\d", url))
    features["num_special_chars"] = len(re.findall(r"[^a-zA-Z0-9]", url))
    features["contains_ip_in_url"] = int(bool(re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url)))
    features["contains_encoded_chars"] = int("%" in url or any(c in url for c in ["+", "-", "_", "="]))

    # Suspicious keywords
    suspicious_terms = ["login", "update", "verify", "secure", "bank", "account", "signin", "password", "confirm"]
    features["contains_suspicious_keyword"] = int(any(term in url.lower() for term in suspicious_terms))

    # Ratio features
    features["digit_ratio"] = round(features["num_digits_in_url"] / (features["url_length"] + 1), 3)
    features["special_char_ratio"] = round(features["num_special_chars"] / (features["url_length"] + 1), 3)

    # ============================================================
    # DNS and HTTP content status
    # ============================================================
    dns_status = str(data.get("dns_status", "")).lower()
    content_status = int(data.get("content_status", 0))

    features["dns_resolves"] = int("resolve" in dns_status)
    features["dns_error"] = int("error" in dns_status or "fail" in dns_status)

    features["content_status"] = content_status
    features["is_http_ok"] = int(200 <= content_status < 300)
    features["is_http_redirect"] = int(300 <= content_status < 400)
    features["is_http_client_error"] = int(400 <= content_status < 500)
    features["is_http_server_error"] = int(500 <= content_status < 600)

    # ============================================================
    # Derived heuristics and tech_info
    # ============================================================
    features["is_complex_url"] = int(
        features["url_length"] > 80
        or features["num_special_chars"] > 10
        or features["contains_random_subdomain"]
    )

    features["is_suspicious_dns_or_status"] = int(
        features["dns_error"] or features["is_http_client_error"] or features["is_http_server_error"]
    )

    # tech_info array summary
    tech_info = data.get("tech_info", [])
    features["tech_info_count"] = len(tech_info)
    features["has_tech_info"] = int(bool(tech_info))

    return features


# ============================================================
# Quick test example
# ============================================================
if __name__ == "__main__":
    import json

    example_data = {
        "url": "https://ctcggaptffisfgxbf3b4c7amaazzwni5rt4leqols7tyurhvbokq.ar-io.dev/FMRjAfMpUSKa4S7DwXwMADObNR2M-LJBy5fnikT1C5U",
        "tech_info": [],
        "has_path": True,
        "has_subdomain": True,
        "subdomain": "ctcggaptffisfgxbf3b4c7amaazzwni5rt4leqols7tyurhvbokq.ar-io.dev",
        "content_status": 404,
        "dns_status": "dns_resolves",
    }

    feats = extract_general_features(example_data)
    print(json.dumps(feats, indent=2))
