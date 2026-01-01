from typing import Dict, Any
from urllib.parse import urlparse
import re


def extract_contentinfo_features(content_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts numerical and categorical features from the 'content_info' JSON section.
    """

    features = {}

    # Basic page metadata
    destination = content_info.get("destination", "")
    features["status_code"] = int(content_info.get("status_code", 0))
    features["html_length"] = len(content_info.get("html", ""))

    # derived feature
    domain = urlparse(destination).netloc
    tld = domain.split('.')[-1].lower()
    
    suspicious_tlds = {
        'xyz', 'top', 'shop', 'site', 'live', 'buzz', 'online', 'vip', 
        'work', 'click', 'club', 'link', 'space', 'cloud',
        'cn', 'ru', 'gq', 'ml', 'cf', 'tk', 'ga', 'su', 'ir'
    }
    features["is_suspicous_cloaking"] = int((tld in suspicious_tlds) and (features["status_code"] in [403, 503, 429]))

    # Destination URL
    destination_domain = urlparse(destination).netloc
    destination_tld = domain.split('.')[-1].lower()
    destination_rd = destination_domain.split('.')[-2:]
    destination_rd = '.'.join(destination_rd)
    url_rd = domain.split('.')[-2:]
    url_rd = '.'.join(url_rd) 

    # derived
    features["is_same_tld_dest_url"] = int((tld == destination_tld) and (destination_rd == url_rd))

    #  HAR 
    har_entries = content_info.get("har", [])
    responses = content_info.get("responses", [])
    features["num_requests"] = len(har_entries)
    features["num_responses"] = len(responses)

    # Extract server/CDN hints
    servers, content_types = [], []

    for entry in har_entries:
        headers = entry.get("response", {}).get("headers", [])
        for h in headers:
            key = h.get("key", "").lower()
            value = h.get("value", "").lower()
            if key == "server":
                servers.append(value)
            if key == "content-type":
                content_types.append(value)

    server_string = " ".join(servers)

    features["has_cloudflare"] = int("cloudflare" in server_string)
    features["num_js_files"] = sum("javascript" in t for t in content_types)
    features["num_css_files"] = sum("css" in t for t in content_types)
    features["num_html_files"] = sum("html" in t for t in content_types)

    # Derived indicators (heuristics)
    features["is_heavy_page"] = int(features["num_requests"] > 40 or features["num_js_files"] > 20 or features['num_css_files'] > 5)

    return features


#  Quick test example
if __name__ == "__main__":
    import json

    with open("example_contentinfo.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    feats = extract_contentinfo_features(data)
    print(json.dumps(feats, indent=2))
