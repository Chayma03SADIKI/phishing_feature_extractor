# phishing_feature_extractor
========================================================
## Host Information Features
File: extract_hostinfo_features.py
========================================================

This module extracts features related to the hosting infrastructure,
DNS configuration, SSL certificate, and network-level properties of a website.
These features are crucial for phishing detection, as malicious websites
often rely on weak, incomplete, or suspicious hosting setups.

The extracted features are derived from the "host_info" section of the
phishing analysis JSON files.

--------------------------------------------------------
1. DNS Record Features
--------------------------------------------------------

These features describe the presence, quantity, and correctness of DNS records.
Phishing domains often have incomplete DNS configurations or missing records.

| Feature name              | Type     | Possible values        | Utility |
|---------------------------|----------|------------------------|---------|
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

--------------------------------------------------------
2. Geolocation and ASN (MaxMind) Features
--------------------------------------------------------

These features describe the Autonomous System, hosting organization,
and country associated with the IP address. Phishing websites are often
hosted on specific ASNs or cloud providers.

| Feature name            | Type     | Possible values        | Utility |
|-------------------------|----------|------------------------|---------|
| num_maxmind_records     | Integer  | >= 0                   | Number of IP geolocation records found. |
| asn_code                | Integer  | >= 0                   | ASN identifier of the hosting network. Certain ASNs are overrepresented in phishing datasets. |
| asn_is_amazon           | Boolean  | 0, 1                   | Indicates whether the hosting provider is Amazon (AWS). |
| country_code            | Integer  | Encoded numeric value  | Encoded country code of the hosting IP. Geographic distribution can help detect anomalies. |

--------------------------------------------------------
3. SSL Certificate Features
--------------------------------------------------------

These features analyze the SSL/TLS certificate of the website.
Phishing sites often use invalid, short-lived, or misconfigured certificates.

| Feature name             | Type     | Possible values        | Utility |
|--------------------------|----------|------------------------|---------|
| ssl_valid                | Boolean  | 0, 1                   | Indicates whether the SSL certificate is valid. |
| ssl_issuer_amazon        | Boolean  | 0, 1                   | Indicates whether the certificate issuer is Amazon. |
| ssl_validity_days        | Integer  | >= 0                   | Validity duration of the SSL certificate in days. Very short durations can be suspicious. |
| ssl_subject_count        | Integer  | >= 0                   | Number of subject entries in the certificate. |
| ssl_msg_success          | Boolean  | 0, 1                   | Indicates whether SSL analysis completed successfully. |

--------------------------------------------------------
4. Protocol and Security Indicators
--------------------------------------------------------

These features summarize high-level security and protocol information.

| Feature name        | Type     | Possible values | Utility |
|---------------------|----------|-----------------|---------|
| is_https            | Boolean  | 0, 1            | Indicates whether the website uses HTTPS. |
| has_dns             | Boolean  | 0, 1            | Indicates whether any DNS records exist at all. |
| has_ipv6_support    | Boolean  | 0, 1            | Indicates IPv6 availability, common in mature infrastructures. |
| has_mail_config     | Boolean  | 0, 1            | Indicates presence of MX records. |
| is_secure_host      | Boolean  | 0, 1            | Derived feature combining HTTPS usage and valid SSL certificate. |

--------------------------------------------------------
Summary
--------------------------------------------------------

Host-based features provide critical insights into the legitimacy of a website's
infrastructure. Phishing websites often exhibit weak DNS setups, suspicious hosting
providers, missing email configurations, or invalid SSL certificates. Combining
these indicators significantly improves the robustness of phishing detection models.

========================================================
## Content-Based Features
File: extract_contentinfo_features.py
========================================================

This module extracts features related to the web page content, HTML structure,
network activity, and destination URL. Content-based analysis is essential for
phishing detection, as phishing pages often mimic legitimate websites while
exhibiting abnormal HTML patterns, excessive scripts, loaders, or suspicious
network behaviors.

The extracted features are derived from the "content_info" section of the
phishing analysis JSON files.

--------------------------------------------------------
1. Page Metadata Features
--------------------------------------------------------

These features describe basic properties of the fetched web page.

| Feature name      | Type     | Possible values | Utility |
|------------------|----------|-----------------|---------|
| status_code      | Integer  | HTTP codes (200, 404, ...) | HTTP response status of the page. Error codes are common in failed or blocked phishing pages. |
| has_error        | Boolean  | 0, 1            | Indicates whether an error message was returned during page retrieval. |
| title_length     | Integer  | >= 0            | Length of the HTML title. Phishing pages often use very short or generic titles. |
| has_html         | Boolean  | 0, 1            | Indicates whether HTML content was successfully retrieved. |
| html_length      | Integer  | >= 0            | Size of the HTML page. Abnormally small or large pages can be suspicious. |

--------------------------------------------------------
2. HTML Structure and Content Features
--------------------------------------------------------

These features analyze the structure and content of the HTML page.
Phishing pages frequently rely on scripts, forms, and iframes to capture credentials.

| Feature name              | Type     | Possible values | Utility |
|---------------------------|----------|-----------------|---------|
| contains_loader_text      | Boolean  | 0, 1            | Detects loading or redirect messages commonly used in phishing pages. |
| contains_script_tag       | Boolean  | 0, 1            | Indicates presence of JavaScript code. |
| contains_iframe           | Boolean  | 0, 1            | Iframes are often used to embed malicious or deceptive content. |
| contains_form             | Boolean  | 0, 1            | Presence of HTML forms is a strong indicator of credential harvesting. |
| num_links                 | Integer  | >= 0            | Number of hyperlinks in the page. |
| num_scripts               | Integer  | >= 0            | Number of script tags. Excessive scripts may indicate obfuscation. |

--------------------------------------------------------
3. Destination URL Features
--------------------------------------------------------

These features analyze the destination URL associated with the page.
Phishing URLs often contain unusual patterns, IP addresses, or excessive length.

| Feature name              | Type     | Possible values | Utility |
|---------------------------|----------|-----------------|---------|
| url_length                | Integer  | >= 0            | Long URLs are commonly used to hide malicious intent. |
| num_subdomains            | Integer  | >= 0            | Excessive subdomains are frequently used in phishing URLs. |
| uses_https                | Boolean  | 0, 1            | Indicates whether HTTPS is used. |
| contains_ip_in_url        | Boolean  | 0, 1            | URLs using raw IP addresses are highly suspicious. |
| contains_encoded_chars    | Boolean  | 0, 1            | Encoded or special characters are often used to evade detection. |
| is_arweave_host           | Boolean  | 0, 1            | Indicates use of decentralized hosting (e.g., Arweave), sometimes abused for phishing. |

--------------------------------------------------------
4. Network Activity and HAR Features
--------------------------------------------------------

These features analyze network requests and responses captured during page load.

| Feature name              | Type     | Possible values | Utility |
|---------------------------|----------|-----------------|---------|
| num_requests              | Integer  | >= 0            | Number of HTTP requests generated by the page. |
| num_responses             | Integer  | >= 0            | Number of received responses. |
| has_cloudflare            | Boolean  | 0, 1            | Indicates usage of Cloudflare CDN. |
| has_aws_cloudfront        | Boolean  | 0, 1            | Indicates usage of AWS CloudFront CDN. |
| has_tencent_cos           | Boolean  | 0, 1            | Indicates hosting on Tencent Cloud COS. |
| num_js_files              | Integer  | >= 0            | Number of JavaScript resources loaded. |
| num_css_files             | Integer  | >= 0            | Number of CSS resources loaded. |
| num_html_files            | Integer  | >= 0            | Number of HTML responses. |
| has_gzip_encoding         | Boolean  | 0, 1            | Indicates gzip compression usage. |
| has_csp_header            | Boolean  | 0, 1            | Presence of Content-Security-Policy header (often missing in phishing pages). |

--------------------------------------------------------
5. Response Metadata Features
--------------------------------------------------------

These features describe file-level metadata extracted from network responses.

| Feature name              | Type     | Possible values | Utility |
|---------------------------|----------|-----------------|---------|
| num_unique_md5            | Integer  | >= 0            | Number of unique file hashes. Low diversity can indicate cloned pages. |
| avg_file_size_class       | Float    | >= 0            | Average length of file type descriptors. |
| num_long_lines_files      | Integer  | >= 0            | Detects files with unusually long lines (possible obfuscation). |
| num_ascii_files           | Integer  | >= 0            | Counts ASCII-based files, common in script-heavy phishing pages. |

--------------------------------------------------------
6. Derived Behavioral Indicators
--------------------------------------------------------

These features combine multiple signals to capture high-level phishing behaviors.

| Feature name                  | Type     | Possible values | Utility |
|-------------------------------|----------|-----------------|---------|
| is_suspicious_loader_page     | Boolean  | 0, 1            | Detects loader-style phishing pages combining scripts, long URLs, and redirect text. |
| is_heavy_page                 | Boolean  | 0, 1            | Indicates unusually heavy pages with large HTML and many requests. |

--------------------------------------------------------
Summary
--------------------------------------------------------

Content-based features capture how a webpage behaves, what it loads,
and how it is structured. Phishing pages often exhibit abnormal HTML
patterns, excessive scripting, suspicious URLs, and unusual network
activity. These features provide strong complementary signals to
URL-based and host-based analysis for accurate phishing detection.

========================================================
## General and URL-Level Features
File: extract_general_features.py
========================================================

This module extracts general, lexical, and structural features from the
top-level fields of the phishing analysis JSON files. These features provide
a fast and lightweight characterization of the URL, its structure, and
high-level DNS and HTTP status indicators.

Such features are widely used in phishing detection as they capture
abnormal URL patterns, suspicious keywords, and inconsistent network behavior.

--------------------------------------------------------
1. URL Structure Features
--------------------------------------------------------

These features describe the basic structure of the URL.

| Feature name       | Type     | Possible values | Utility |
|--------------------|----------|-----------------|---------|
| url_length         | Integer  | >= 0            | Long URLs are often used to hide malicious patterns. |
| scheme_http        | Boolean  | 0, 1            | Indicates use of HTTP (less secure). |
| scheme_https       | Boolean  | 0, 1            | Indicates use of HTTPS. |

--------------------------------------------------------
2. Path and Query Features
--------------------------------------------------------

These features analyze the URL path and query string.

| Feature name           | Type     | Possible values | Utility |
|------------------------|----------|-----------------|---------|
| path_length            | Integer  | >= 0            | Long paths are common in phishing URLs. |
| query_length           | Integer  | >= 0            | Long queries may contain encoded payloads. |
| num_path_segments      | Integer  | >= 0            | Excessive path depth is suspicious. |
| num_query_params       | Integer  | >= 0            | Many query parameters may indicate tracking or obfuscation. |
| has_query              | Boolean  | 0, 1            | Indicates presence of query parameters. |

--------------------------------------------------------
3. File Extension Features
--------------------------------------------------------

These features detect file-like URLs, which are often used to mimic login pages.

| Feature name           | Type     | Possible values | Utility |
|------------------------|----------|-----------------|---------|
| has_file_extension     | Boolean  | 0, 1            | Phishing URLs often end with fake file extensions. |
| file_extension_len     | Integer  | >= 0            | Unusual extension lengths can indicate obfuscation. |

--------------------------------------------------------
4. Subdomain Features
--------------------------------------------------------

These features analyze subdomain usage, a common phishing technique.

| Feature name                   | Type     | Possible values | Utility |
|--------------------------------|----------|-----------------|---------|
| has_subdomain                  | Boolean  | 0, 1            | Phishing URLs frequently rely on subdomains. |
| subdomain_length               | Integer  | >= 0            | Very long subdomains are suspicious. |
| num_subdomain_levels           | Integer  | >= 0            | Excessive subdomain nesting is a strong phishing indicator. |
| contains_random_subdomain      | Boolean  | 0, 1            | Detects randomly generated subdomains often used by phishing kits. |

--------------------------------------------------------
5. Lexical and Entropy-Based Features
--------------------------------------------------------

These features capture character-level properties of the URL.

| Feature name                   | Type     | Possible values | Utility |
|--------------------------------|----------|-----------------|---------|
| num_digits_in_url              | Integer  | >= 0            | Phishing URLs often contain many digits. |
| num_special_chars              | Integer  | >= 0            | Special characters are used for obfuscation. |
| contains_ip_in_url             | Boolean  | 0, 1            | URLs using IP addresses instead of domains are highly suspicious. |
| contains_encoded_chars         | Boolean  | 0, 1            | Encoded characters help evade detection. |
| contains_suspicious_keyword    | Boolean  | 0, 1            | Detects phishing-related keywords (login, verify, bank, etc.). |
| digit_ratio                    | Float    | [0, 1]          | Ratio of digits to URL length. |
| special_char_ratio             | Float    | [0, 1]          | Ratio of special characters to URL length. |

--------------------------------------------------------
6. DNS and HTTP Status Features
--------------------------------------------------------

These features summarize DNS resolution and HTTP response behavior.

| Feature name                   | Type     | Possible values | Utility |
|--------------------------------|----------|-----------------|---------|
| dns_resolves                   | Boolean  | 0, 1            | Indicates whether DNS resolution succeeded. |
| dns_error                      | Boolean  | 0, 1            | DNS errors are common for malicious or short-lived domains. |
| content_status                 | Integer  | HTTP codes      | HTTP response code of the page. |
| is_http_ok                     | Boolean  | 0, 1            | Indicates successful HTTP responses (2xx). |
| is_http_redirect               | Boolean  | 0, 1            | Redirects are often used to hide final phishing destinations. |
| is_http_client_error           | Boolean  | 0, 1            | Client-side errors (4xx). |
| is_http_server_error           | Boolean  | 0, 1            | Server-side errors (5xx). |

--------------------------------------------------------
7. Derived Heuristics
--------------------------------------------------------

These features combine multiple signals into higher-level indicators.

| Feature name                   | Type     | Possible values | Utility |
|--------------------------------|----------|-----------------|---------|
| is_complex_url                 | Boolean  | 0, 1            | Flags URLs that are long, noisy, or randomly generated. |
| is_suspicious_dns_or_status    | Boolean  | 0, 1            | Combines DNS and HTTP errors into a single suspicion signal. |

--------------------------------------------------------
8. Technology Fingerprinting (tech_info)
--------------------------------------------------------

These features summarize detected technologies associated with the website.

| Feature name       | Type     | Possible values | Utility |
|--------------------|----------|-----------------|---------|
| tech_info_count    | Integer  | >= 0            | Number of detected technologies. |
| has_tech_info      | Boolean  | 0, 1            | Indicates whether technology information was extracted. |

--------------------------------------------------------
Summary
--------------------------------------------------------

General and URL-level features provide a fast and effective first layer
for phishing detection. By capturing URL complexity, lexical anomalies,
suspicious keywords, and abnormal DNS or HTTP behavior, these features
enable early detection of malicious URLs before deeper content or
host-based analysis is performed.

========================================================
## Additional Comparative Features (Root Domain vs Subdomain)
File: extract_additional_features.py
========================================================

This module extracts comparative and differential features between the
root domain (rd) and the subdomain (sd). Phishing attacks frequently rely
on malicious subdomains hosted on infrastructures that differ from the
legitimate root domain.

By comparing historical activity, hosting, SSL configuration, network
headers, and content properties between rd and sd, these features capture
strong legitimacy and impersonation signals.

The extracted features are derived from the "additional" section of the
phishing analysis JSON files.

--------------------------------------------------------
1. Wayback (Historical Activity) Features
--------------------------------------------------------

These features analyze historical presence using Wayback Machine data.
Legitimate domains usually have long and consistent historical activity,
while phishing subdomains often have little or none.

| Feature name            | Type     | Possible values | Utility |
|-------------------------|----------|-----------------|---------|
| rd_wayback_count        | Integer  | >= 0            | Number of historical captures for the root domain. |
| sd_wayback_count        | Integer  | >= 0            | Number of historical captures for the subdomain. |
| wayback_diff            | Integer  | Can be negative | Difference between root and subdomain history. |
| rd_has_wayback          | Boolean  | 0, 1            | Indicates whether root domain has historical data. |
| sd_has_wayback          | Boolean  | 0, 1            | Indicates whether subdomain has historical data. |
| rd_wayback_span_days    | Integer  | >= 0            | Time span (in days) between first and last captures of the root domain. |

--------------------------------------------------------
2. SSL and HTTPS Comparison Features
--------------------------------------------------------

These features compare SSL validity and HTTPS usage between root domain
and subdomain.

| Feature name        | Type     | Possible values | Utility |
|---------------------|----------|-----------------|---------|
| rd_ssl_valid        | Boolean  | 0, 1            | Indicates whether root domain has a valid SSL certificate. |
| sd_ssl_valid        | Boolean  | 0, 1            | Indicates whether subdomain has a valid SSL certificate. |
| ssl_valid_diff      | Integer  | 0 or 1          | Highlights SSL inconsistencies between rd and sd. |
| https_diff          | Integer  | 0 or 1          | Indicates difference in HTTPS usage. |

--------------------------------------------------------
3. ASN and Hosting Comparison
--------------------------------------------------------

These features compare the hosting Autonomous Systems of rd and sd.

| Feature name              | Type     | Possible values | Utility |
|---------------------------|----------|-----------------|---------|
| rd_unique_asn_count       | Integer  | >= 0            | Number of distinct ASNs for the root domain. |
| sd_unique_asn_count       | Integer  | >= 0            | Number of distinct ASNs for the subdomain. |
| asn_overlap               | Boolean  | 0, 1            | Indicates whether rd and sd share at least one ASN. |

--------------------------------------------------------
4. Content and Response Comparison
--------------------------------------------------------

These features compare HTTP responses and content size.

| Feature name        | Type     | Possible values | Utility |
|---------------------|----------|-----------------|---------|
| rd_status_code      | Integer  | HTTP codes      | HTTP response code of root domain. |
| sd_status_code      | Integer  | HTTP codes      | HTTP response code of subdomain. |
| status_diff         | Integer  | >= 0            | Difference between HTTP status codes. |
| rd_html_len         | Integer  | >= 0            | HTML size of root domain page. |
| sd_html_len         | Integer  | >= 0            | HTML size of subdomain page. |
| html_len_diff       | Integer  | >= 0            | Absolute difference in HTML size. |
| html_len_ratio      | Float    | >= 0            | Ratio of subdomain HTML size to root domain HTML size. |
| rd_has_screenshot   | Boolean  | 0, 1            | Indicates screenshot availability for root domain. |
| sd_has_screenshot   | Boolean  | 0, 1            | Indicates screenshot availability for subdomain. |

--------------------------------------------------------
5. Server and Network Header Comparison
--------------------------------------------------------

These features analyze server headers extracted from HAR data.

| Feature name        | Type     | Possible values | Utility |
|---------------------|----------|-----------------|---------|
| same_server_type    | Boolean  | 0, 1            | Indicates whether rd and sd share the same server technology. |
| rd_server_envoy     | Boolean  | 0, 1            | Indicates usage of Envoy proxy on root domain. |
| sd_server_envoy     | Boolean  | 0, 1            | Indicates usage of Envoy proxy on subdomain. |

--------------------------------------------------------
6. Derived Legitimacy Indicators
--------------------------------------------------------

These features combine multiple comparisons into high-level indicators.

| Feature name            | Type     | Possible values | Utility |
|-------------------------|----------|-----------------|---------|
| same_asn_and_server     | Boolean  | 0, 1            | Indicates consistent hosting between rd and sd. |
| is_likely_legit         | Boolean  | 0, 1            | Flags cases where subdomain strongly resembles the legitimate root domain. |

--------------------------------------------------------
Summary
--------------------------------------------------------

Additional comparative features provide powerful signals for phishing
detection by highlighting inconsistencies between root domains and their
subdomains. Phishing campaigns often operate on newly created subdomains
with different hosting, SSL configuration, and no historical presence.
These features help distinguish legitimate subdomains from malicious
impersonations with high precision.
