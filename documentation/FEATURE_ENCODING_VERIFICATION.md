# UCI ARFF Feature-Encoding Verification

This report records the encoding-only correction made after the feature audit. Feature logic, thresholds, data sources, and the model were not changed. The reference is the local original `Training Dataset.arff` nominal-domain declaration.

`Produced values` means the complete set of values that the current extractor can return for that feature. Every set is a subset of the ARFF allowed values. The conservative `-1` placeholders for unavailable binary WHOIS/reputation fields are **valid encoding only**; they are not measurements.

| # | Feature | Allowed ARFF values | Produced values now |
|---:|---|---|---|
| 1 | having_IP_Address | -1, 1 | -1, 1 |
| 2 | URL_Length | -1, 0, 1 | -1, 0, 1 |
| 3 | Shortining_Service | -1, 1 | -1, 1 |
| 4 | having_At_Symbol | -1, 1 | -1, 1 |
| 5 | double_slash_redirecting | -1, 1 | -1, 1 |
| 6 | Prefix_Suffix | -1, 1 | -1, 1 |
| 7 | having_Sub_Domain | -1, 0, 1 | -1, 0, 1 |
| 8 | SSLfinal_State | -1, 0, 1 | -1, 1 |
| 9 | Domain_registeration_length | -1, 1 | -1 |
| 10 | Favicon | -1, 1 | -1, 1 |
| 11 | port | -1, 1 | -1, 1 |
| 12 | HTTPS_token | -1, 1 | -1, 1 |
| 13 | Request_URL | -1, 1 | -1, 1 |
| 14 | URL_of_Anchor | -1, 0, 1 | -1, 0, 1 |
| 15 | Links_in_tags | -1, 0, 1 | -1, 0, 1 |
| 16 | SFH | -1, 0, 1 | -1, 0, 1 |
| 17 | Submitting_to_email | -1, 1 | -1, 1 |
| 18 | Abnormal_URL | -1, 1 | -1, 1 |
| 19 | Redirect | 0, 1 | 0, 1 |
| 20 | on_mouseover | -1, 1 | -1, 1 |
| 21 | RightClick | -1, 1 | -1, 1 |
| 22 | popUpWidnow | -1, 1 | -1, 1 |
| 23 | Iframe | -1, 1 | -1, 1 |
| 24 | age_of_domain | -1, 1 | -1 |
| 25 | DNSRecord | -1, 1 | -1, 1 |
| 26 | web_traffic | -1, 0, 1 | 0 |
| 27 | Page_Rank | -1, 1 | -1 |
| 28 | Google_Index | -1, 1 | -1 |
| 29 | Links_pointing_to_page | -1, 0, 1 | 0 |
| 30 | Statistical_report | -1, 1 | -1, 1 |

## Encoding changes

| Feature | Old invalid output possibility | New allowed output |
|---|---:|---:|
| Domain_registeration_length | 0 | -1 |
| Redirect | -1 | 0 |
| age_of_domain | 0 | -1 |
| DNSRecord | 0 | 1 |
| Page_Rank | 0 | -1 |
| Google_Index | 0 | -1 |

`ALLOWED_VALUES` in `feature_extractor.py` is now a runtime guard. If a future code change produces a value outside the original ARFF domain, the extractor raises an error rather than silently sending invalid data to the model.
