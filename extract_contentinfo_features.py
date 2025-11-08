"""
extract_contentinfo_features.py
--------------------------------
Module to extract structured features from the 'content_info' section
of phishing analysis JSON files.

"""

from typing import Dict, Any
import re


def extract_contentinfo_features(content_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts numerical and categorical features from the 'content_info' JSON section.

    Parameters
    ----------
    content_info : dict
        The 'content_info' dictionary extracted from the JSON.

    Returns
    -------
    dict
        Dictionary mapping feature names to numeric values.
    """

    features = {}

    # -------------------------------
    # Basic page metadata
    # -------------------------------
    features["status_code"] = int(content_info.get("status_code", 0))
    features["has_error"] = int(content_info.get("error_msg") is not None)
    features["title_length"] = len(content_info.get("title", "")) if content_info.get("title") else 0
    features["has_html"] = int(bool(content_info.get("html")))
    features["html_length"] = len(content_info.get("html", ""))

    # Analyze HTML content if available
    html = content_info.get("html", "").lower()
    features["contains_loader_text"] = int(any(p in html for p in ["please wait", "loading", "redirect"]))
    features["contains_script_tag"] = int("<script" in html)
    features["contains_iframe"] = int("<iframe" in html)
    features["contains_form"] = int("<form" in html)
    features["num_links"] = html.count("href=")
    features["num_scripts"] = html.count("<script")

    # -------------------------------
    # Destination URL
    # -------------------------------
    destination = content_info.get("destination", "")
    features["url_length"] = len(destination)
    features["num_subdomains"] = destination.count(".")
    features["uses_https"] = int(destination.startswith("https"))
    features["contains_ip_in_url"] = int(bool(re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", destination)))
    features["contains_encoded_chars"] = int("%" in destination or any(x in destination for x in ["+", "-", "_"]))
    features["is_arweave_host"] = int(".ar-io.dev" in destination or "arweave" in destination)

    # -------------------------------
    #  HAR and network responses
    # -------------------------------
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
    content_string = " ".join(content_types)

    features["has_cloudflare"] = int("cloudflare" in server_string)
    features["has_aws_cloudfront"] = int("cloudfront" in server_string)
    features["has_tencent_cos"] = int("tencent-cos" in server_string)
    features["num_js_files"] = sum("javascript" in t for t in content_types)
    features["num_css_files"] = sum("css" in t for t in content_types)
    features["num_html_files"] = sum("html" in t for t in content_types)
    features["has_gzip_encoding"] = int("gzip" in content_string)
    features["has_csp_header"] = int("content-security-policy" in content_string)

    # -------------------------------
    # Response metadata (from responses[])
    # -------------------------------
    md5_list = [r.get("md5") for r in responses if "md5" in r]
    features["num_unique_md5"] = len(set(md5_list))
    features["avg_file_size_class"] = (
        sum(len(r.get("file_type", "")) for r in responses) / (len(responses) or 1)
    )
    features["num_long_lines_files"] = sum("long lines" in r.get("file_type", "").lower() for r in responses)
    features["num_ascii_files"] = sum("ascii" in r.get("file_type", "").lower() for r in responses)

    # -------------------------------
    # Derived indicators
    # -------------------------------
    features["is_suspicious_loader_page"] = int(
        features["contains_loader_text"]
        and features["num_js_files"] > 3
        and features["url_length"] > 100
    )
    features["is_heavy_page"] = int(features["html_length"] > 10000 and features["num_requests"] > 5)

    return features


# -------------------------------
#  Quick test example
# -------------------------------
if __name__ == "__main__":
    import json

    with open("example_contentinfo.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    feats = extract_contentinfo_features(data["content_info"])
    print(json.dumps(feats, indent=2))
