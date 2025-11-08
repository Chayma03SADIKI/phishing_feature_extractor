"""
extract_hostinfo_features.py
--------------------------------
Module to extract numerical and categorical features from the 'host_info' section
of phishing analysis JSON files.

"""

from typing import Dict, Any
from datetime import datetime


def extract_hostinfo_features(host_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts structured numerical features from the 'host_info' JSON section.

    Parameters
    ----------
    host_info : dict
        The 'host_info' dictionary extracted from the JSON.

    Returns
    -------
    dict
        Dictionary mapping feature names to numeric values.
    """

    features = {}

    # -------------------------------
    # 1 DNS record counts
    # -------------------------------
    dns_types = ["a", "aaaa", "ns", "txt", "soa", "mx", "dmarc"]
    for dns_type in dns_types:
        answers = host_info.get(dns_type, {}).get("answers", [])
        features[f"num_{dns_type}_records"] = len(answers)
        status = host_info.get(dns_type, {}).get("status", "")
        features[f"{dns_type}_status_ok"] = int(status == "NOERROR")

    # -------------------------------
    #  MaxMind (geolocation & ASN)
    # -------------------------------
    maxmind_list = host_info.get("maxmind", [])
    features["num_maxmind_records"] = len(maxmind_list)

    if maxmind_list:
        # Extract info from the first record (most representative)
        first_ans = maxmind_list[0].get("answers", {})
        features["asn_code"] = int(first_ans.get("asn_code", 0))
        features["asn_is_amazon"] = int("amazon" in first_ans.get("asn_org", "").lower())
        features["country_code"] = hash(first_ans.get("cc_code", "")) % 1000  # encoded numeric
    else:
        features["asn_code"] = 0
        features["asn_is_amazon"] = 0
        features["country_code"] = 0

    # -------------------------------
    #  SSL certificate information
    # -------------------------------
    ssl = host_info.get("ssl", {})
    features["ssl_valid"] = int(ssl.get("is_valid_cert", False))
    features["ssl_issuer_amazon"] = int("amazon" in ssl.get("issuer", "").lower())

    # Parse validity period (in days)
    try:
        valid_from = datetime.strptime(ssl.get("valid_from", ""), "%Y-%m-%d")
        valid_until = datetime.strptime(ssl.get("valid_until", ""), "%Y-%m-%d")
        features["ssl_validity_days"] = (valid_until - valid_from).days
    except Exception:
        features["ssl_validity_days"] = 0

    features["ssl_subject_count"] = len(ssl.get("subject", []))
    features["ssl_msg_success"] = int(ssl.get("msg", "").lower() == "success")

    # -------------------------------
    #  HTTPS and protocol info
    # -------------------------------
    features["is_https"] = int(host_info.get("is_https", False))

    # -------------------------------
    #  Derived indicators
    # -------------------------------
    features["has_dns"] = int(sum(features[f"num_{t}_records"] for t in dns_types) > 0)
    features["has_ipv6_support"] = int(features["num_aaaa_records"] > 0)
    features["has_mail_config"] = int(features["num_mx_records"] > 0)
    features["is_secure_host"] = int(features["ssl_valid"] and features["is_https"])

    return features


# -------------------------------
#  Quick test example
# -------------------------------
if __name__ == "__main__":
    import json

    # Example data snippet (you can test directly with your JSON)
    example_host_info = {
        "a": {"status": "NOERROR", "answers": ["18.245.46.79", "18.245.46.115"]},
        "aaaa": {"status": "NOERROR", "answers": []},
        "ns": {"status": "NOERROR", "answers": []},
        "maxmind": [
            {
                "status": "NOERROR",
                "answers": {"ip": "18.245.46.79", "asn_code": 16509, "asn_org": "AMAZON-02", "cc_code": "US"},
            }
        ],
        "ssl": {
            "subject": ["*.ar-io.dev", "ar-io.dev"],
            "issuer": "Amazon",
            "valid_from": "2024-02-22",
            "valid_until": "2025-03-22",
            "msg": "success",
            "is_valid_cert": True,
        },
        "is_https": True,
    }

    feats = extract_hostinfo_features(example_host_info)
    print(json.dumps(feats, indent=2))
