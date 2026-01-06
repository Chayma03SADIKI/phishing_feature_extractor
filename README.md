# Phishing Feature Extractor

Python pipeline to extract phishing-related features (general, host-based,
content-based and additional comparative features) from analysis JSON files
and build a CSV dataset ready for machine learning model training.

---

## Repository Structure

- `orchestrator.py` : main script that iterates over `benign` and `malicious`
  directories, calls each feature extractor and builds the final DataFrame.
- `extract_general_features.py` : extraction of URL-level, lexical and
  HTTP/DNS status features.
- `extract_hostinfo_features.py` : extraction of host-related features
  (DNS, SSL, ASN, geolocation).
- `extract_contentinfo_features.py` : extraction of content-related features
  (HTML structure, screenshots, headers, network activity).
- `extract_additional_features.py` : comparative analysis between `rd`
  (root domain) and `sd` (subdomain), including Wayback history and hosting
  inconsistencies.
- `output/` : generated directory containing `phishing_dataset.csv`.
---

## Requirements

- Python 3.8+ (recommanded)  
- `pip` (or use a virtual environment)  

---

## Installation (recommended: virtualenv)

### Windows (PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Linux / macOS (bash)
```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**Minimal `requirements.txt` example:**
```
pandas
tqdm
numpy
```
---

## Configuration Before Execution

Open `orchestrator.py` and update the global variables at the top of the file to point to the directories containing your phishing analysis JSON files:

```python
BENIGN_PATH = r"D:\Downloads\benign"       # path to benign JSON files
MALICIOUS_PATH = r"D:\Downloads\malicious" # path to malicious JSON files
```

Make sure these directories exist and contain `.json` files.

---

## Expected JSON Format

- Minified JSON files (single-line JSON) are fully supported by `json.load()`.  
- Each file should be a valid JSON object and ideally contain the following top-level keys:

```json
{
  "url": "...",
  "host_info": {...},
  "content_info": {...},
  "additional": {...}
}
```
- The pipeline includes defensive checks for missing or malformed fields, but heavily corrupted JSON files may still cause parsing errors.  

---

## Execution

From the root of the project (with the virtual environment activated):

```bash
python orchestrator.py
```

The script produces:
- `output/phishing_dataset.csv` — final CSV dataset containing all extracted features.
- A preview of the generated DataFrame is printed to the console (configurable in `orchestrator.py`).  

## Host Information Features
### File: extract_hostinfo_features.py
The extracted features are derived from the "host_info" section of the
phishing analysis JSON files.

---
1. DNS Record Features
---

These features describe the presence, quantity, and correctness of DNS records.
Phishing domains often have incomplete DNS configurations or missing records.

| Feature name              | Type     | Possible values        | Utility |
|---|---|---|---|
| num_a_records             | Integer  | >= 0                   | Counts IPv4 addresses associated with the domain. Legitimate sites usually have at least one A record. |
| a_status_ok               | Boolean  | 0, 1                   | Indicates whether the A record DNS query succeeded (NOERROR). |
| num_aaaa_records          | Integer  | >= 0                   | Counts IPv6 records. Legitimate infrastructures often support IPv6. |
| aaaa_status_ok            | Boolean  | 0, 1                   | Indicates success of the AAAA DNS query. |
| num_ns_records            | Integer  | >= 0                   | Number of authoritative name servers. Phishing domains often lack proper NS configuration. |
| ns_status_ok              | Boolean  | 0, 1                   | Indicates whether NS resolution succeeded. |
| num_txt_records           | Integer  | >= 0                   | Number of TXT records (used for SPF, verification, etc.). |
| txt_status_ok             | Boolean  | 0, 1                   | Indicates success of TXT record resolution. |
| num_soa_records           | Integer  | >= 0                   | Presence of SOA record indicates a properly configured DNS zone. |
| soa_status_ok             | Boolean  | 0, 1                   | Indicates success of SOA resolution. |
| num_mx_records            | Integer  | >= 0                   | Indicates whether the domain is configured to receive emails. |
| mx_status_ok              | Boolean  | 0, 1                   | Indicates success of MX record resolution. |
| num_dmarc_records         | Integer  | >= 0                   | DMARC records are commonly missing in phishing domains. |
| dmarc_status_ok           | Boolean  | 0, 1                   | Indicates success of DMARC DNS resolution. |

---
2. Geolocation and ASN (MaxMind) Features
---

These features describe the Autonomous System, hosting organization,
and country associated with the IP address. Phishing websites are often
hosted on specific ASNs or cloud providers.

| Feature name            | Type     | Possible values        | Utility |
|---|---|---|---|
| num_maxmind_records     | Integer  | >= 0                   | Number of IP geolocation records found. |
| asn_code                | Integer  | >= 0                   | ASN identifier of the hosting network. Certain ASNs are overrepresented in phishing datasets. |
| country_code            | Integer  | Encoded numeric value  | Encoded country code of the hosting IP. Geographic distribution can help detect anomalies. |

---
3. SSL Certificate Features
---

These features analyze the SSL/TLS certificate of the website.
Phishing sites often use invalid, short-lived, or misconfigured certificates.

| Feature name             | Type     | Possible values        | Utility |
|--------------------------|----------|------------------------|---------|
| ssl_valid                | Boolean  | 0, 1                   | Indicates whether the SSL certificate is valid. |
| ssl_validity_days        | Integer  | >= 0                   | Validity duration of the SSL certificate in days. Very short durations can be suspicious. |
| ssl_subject_count        | Integer  | >= 0                   | Number of subject entries in the certificate. |
| ssl_msg_success          | Boolean  | 0, 1                   | Indicates whether SSL analysis completed successfully. |

---
4. Protocol and Security Indicators
---

These features summarize high-level security and protocol information.

| Feature name        | Type     | Possible values | Utility |
|---|---|---|---|
| is_https            | Boolean  | 0, 1            | Indicates whether the website uses HTTPS. |
| has_dns             | Boolean  | 0, 1            | Indicates whether any DNS records exist at all. |
| has_ipv6_support    | Boolean  | 0, 1            | Indicates IPv6 availability, common in mature infrastructures. |
| has_mail_config     | Boolean  | 0, 1            | Indicates presence of MX records. |
| is_secure_host      | Boolean  | 0, 1            | Derived feature combining HTTPS usage and valid SSL certificate. |

## Content-Based Features
### File: extract_contentinfo_features.py
The extracted features are derived from the "content_info" section of the
phishing analysis JSON files.

---
1. Page Metadata Features
---

These features describe basic properties of the fetched web page.

| Feature name      | Type     | Possible values | Utility |
|------------------|----------|-----------------|---------|
| status_code      | Integer  | HTTP codes (200, 404, ...) | HTTP response status of the page. Error codes are common in failed or blocked phishing pages. |
| html_length      | Integer  | >= 0            | Size of the HTML page. Abnormally small or large pages can be suspicious. |

---
2. Network Activity and HAR Features
---

These features analyze network requests and responses captured during page load.

| Feature name              | Type     | Possible values | Utility |
|---------------------------|----------|-----------------|---------|
| num_requests              | Integer  | >= 0            | Number of HTTP requests generated by the page. |
| num_responses             | Integer  | >= 0            | Number of received responses. |
| has_cloudflare            | Boolean  | 0, 1            | Indicates usage of Cloudflare CDN. |
| num_js_files              | Integer  | >= 0            | Number of JavaScript resources loaded. |
| num_css_files             | Integer  | >= 0            | Number of CSS resources loaded. |
| num_html_files            | Integer  | >= 0            | Number of HTML responses. |
| is_heavy_page            | Boolean  | 0, 1            | If loading the page needs a lot of network requests and files |

---
3. Derived Behavioral Indicators
---

These features combine multiple signals to capture high-level phishing behaviors.

| Feature name                  | Type     | Possible values | Utility |
|-------------------------------|----------|-----------------|---------|
| is_suspicous_cloaking       | Boolean  | 0, 1            | if the website blocks access depending on the user agent type and has suspicious tld. |
| is_heavy_page                 | Boolean  | 0, 1            | Indicates unusually heavy pages with large HTML and many requests. |
| is_same_tld_dest_url           | Boolean  | 0, 1            | if there was a forward to an external website with different tld than the original url. |

## General and URL-Level Features
### File: extract_general_features.py
This module extracts general, lexical, and structural features from the
top-level fields of the phishing analysis JSON files.

---
1. URL Structure, Path and Query Features
---

These features describe the basic structure of the URL, path and query string.

| Feature name       | Type     | Possible values | Utility |
|--------------------|----------|-----------------|---------|
| url_length         | Integer  | >= 0            | Long URLs are often used to hide malicious patterns. |
| path_length            | Integer  | >= 0            | Long paths are common in phishing URLs. |
| query_length           | Integer  | >= 0            | Long queries may contain encoded payloads. |
| num_path_segments      | Integer  | >= 0            | Excessive path depth is suspicious. |
| num_query_params       | Integer  | >= 0            | Many query parameters may indicate tracking or obfuscation. |
| has_file_extension     | Boolean  | 0, 1            | Phishing URLs often end with fake file extensions. |

---
2. Subdomain Features
---

These features analyze subdomain usage, a common phishing technique.

| Feature name                   | Type     | Possible values | Utility |
|--------------------------------|----------|-----------------|---------|
| subdomain_length               | Integer  | >= 0            | Very long subdomains are suspicious. |
| num_subdomain_levels           | Integer  | >= 0            | Excessive subdomain nesting is a strong phishing indicator. |
| contains_random_subdomain      | Boolean  | 0, 1            | Detects randomly generated subdomains often used by phishing kits. |

---
3. Lexical and Entropy-Based Features
---

These features capture character-level properties of the URL.

| Feature name                   | Type     | Possible values | Utility |
|--------------------------------|----------|-----------------|---------|
| num_digits_in_url              | Integer  | >= 0            | Phishing URLs often contain many digits. |
| num_special_chars              | Integer  | >= 0            | Special characters are used for obfuscation. |
| digit_ratio                    | Float    | [0, 1]          | Ratio of digits to URL length. |
| special_char_ratio             | Float    | [0, 1]          | Ratio of special characters to URL length. |

---
4. Derived Heuristics
---

These features combine multiple signals into higher-level indicators.

| Feature name                   | Type     | Possible values | Utility |
|--------------------------------|----------|-----------------|---------|
| is_complex_url                 | Boolean  | 0, 1            | Flags URLs that are long, noisy, or randomly generated. |


## Additional Comparative Features (Root Domain vs Subdomain)
### File: extract_additional_features.py

This module extracts comparative and differential features between the
root domain (rd) and the subdomain (sd).

The extracted features are derived from the "additional" section of the
phishing analysis JSON files.

---
1. Wayback (Historical Activity) Features
---

These features analyze historical presence using Wayback Machine data.

| Feature name            | Type     | Possible values | Utility |
|-------------------------|----------|-----------------|---------|
| rd_wayback_count        | Integer  | >= 0            | Number of historical captures for the root domain. |
| sd_wayback_count        | Integer  | >= 0            | Number of historical captures for the subdomain. |
| wayback_diff            | Integer  | Can be negative | Difference between root and subdomain history. |
| rd_has_wayback          | Boolean  | 0, 1            | Indicates whether root domain has historical data. |
| sd_has_wayback          | Boolean  | 0, 1            | Indicates whether subdomain has historical data. |
| rd_wayback_span_days    | Integer  | >= 0            | Time span (in days) between first and last captures of the root domain. |
| asn_overlap               | Boolean  | 0, 1            | Indicates whether rd and sd share at least one ASN. |
| same_server_type    | Boolean  | 0, 1            | Indicates whether rd and sd share the same server technology. |
---
2. Content and Response Comparison
---

These features compare HTTP responses and content size.

| Feature name        | Type     | Possible values | Utility |
|---------------------|----------|-----------------|---------|
| rd_status_code      | Integer  | HTTP codes      | HTTP response code of root domain. |
| sd_status_code      | Integer  | HTTP codes      | HTTP response code of subdomain. |
| status_match         | Bool  | 0, 1           | Match between HTTP status codes families. |
| html_len_diff       | Integer  | >= 0            | Absolute difference in HTML size. |
| html_len_ratio      | Float    | >= 0            | Ratio of subdomain HTML size to root domain HTML size. |
| rd_has_screenshot   | Boolean  | 0, 1            | Indicates screenshot availability for root domain. |
| sd_has_screenshot   | Boolean  | 0, 1            | Indicates screenshot availability for subdomain. |


--------------------------------------------------------
3. Derived Legitimacy Indicators
--------------------------------------------------------

These features combine multiple comparisons into high-level indicators.

| Feature name            | Type     | Possible values | Utility |
|-------------------------|----------|-----------------|---------|
| same_asn_and_server     | Boolean  | 0, 1            | Indicates consistent hosting between rd and sd. |
| is_constistant_history  | Boolean  | 0, 1            | Flags cases where the history of sd and rd exists and similar ASNs |