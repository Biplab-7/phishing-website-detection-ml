"""Extract UCI phishing-website features from a URL for the Flask app.

The training dataset includes several historical reputation/WHOIS features.  Those
are not universally available from a URL alone, so this module uses 0 (neutral)
for them rather than pretending it can determine them accurately.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


FEATURE_NAMES = (
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report",
)

# Exact nominal domains declared by the original Training Dataset.arff.
ALLOWED_VALUES = {
    "having_IP_Address": {-1, 1}, "URL_Length": {-1, 0, 1},
    "Shortining_Service": {-1, 1}, "having_At_Symbol": {-1, 1},
    "double_slash_redirecting": {-1, 1}, "Prefix_Suffix": {-1, 1},
    "having_Sub_Domain": {-1, 0, 1}, "SSLfinal_State": {-1, 0, 1},
    "Domain_registeration_length": {-1, 1}, "Favicon": {-1, 1},
    "port": {-1, 1}, "HTTPS_token": {-1, 1}, "Request_URL": {-1, 1},
    "URL_of_Anchor": {-1, 0, 1}, "Links_in_tags": {-1, 0, 1},
    "SFH": {-1, 0, 1}, "Submitting_to_email": {-1, 1},
    "Abnormal_URL": {-1, 1}, "Redirect": {0, 1}, "on_mouseover": {-1, 1},
    "RightClick": {-1, 1}, "popUpWidnow": {-1, 1}, "Iframe": {-1, 1},
    "age_of_domain": {-1, 1}, "DNSRecord": {-1, 1},
    "web_traffic": {-1, 0, 1}, "Page_Rank": {-1, 1},
    "Google_Index": {-1, 1}, "Links_pointing_to_page": {-1, 0, 1},
    "Statistical_report": {-1, 1},
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
}
SUSPICIOUS_WORDS = (".exe", ".zip", ".rar", "free", "login", "ebayisapi", "webscr")
REQUEST_TIMEOUT = 8


def _normalise_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Enter a website URL.")
    if not re.match(r"^https?://", value, re.IGNORECASE):
        raise ValueError("Include http:// or https:// at the beginning of the URL.")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// website URL.")
    return value


def _is_public_host(host: str) -> bool:
    """Prevent a local server from fetching loopback/private network addresses."""
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror as error:
        raise ValueError("The website host could not be resolved.") from error
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("Local, private, and reserved network addresses are not allowed.")
    return True


def _fetch(url: str) -> tuple[str, str, list[str]]:
    """Fetch up to five public redirects and return final URL, HTML, redirect URLs."""
    session = requests.Session()
    session.headers["User-Agent"] = "PhishingDetector/1.0 (+local educational project)"
    redirects: list[str] = []
    current = url
    try:
        for _ in range(5):
            _is_public_host(urlparse(current).hostname or "")
            response = session.get(current, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if response.is_redirect and response.headers.get("Location"):
                current = urljoin(current, response.headers["Location"])
                redirects.append(current)
                continue
            response.raise_for_status()
            return current, response.text, redirects
    except requests.RequestException as error:
        raise ValueError(f"The website could not be fetched: {error}") from error
    raise ValueError("The website redirected too many times.")


def _same_domain(link: str, host: str) -> bool:
    link_host = urlparse(link).hostname
    return not link_host or link_host == host or link_host.endswith(f".{host}") or host.endswith(f".{link_host}")


def _ratio_score(bad: int, total: int) -> int:
    if total == 0:
        return 1
    ratio = bad / total
    return -1 if ratio >= 0.61 else (0 if ratio >= 0.22 else 1)


def extract_features(raw_url: str) -> dict[str, int | str]:
    """Return numeric values keyed by the dataset's exact feature names."""
    url = _normalise_url(raw_url)
    original = urlparse(url)
    host = original.hostname or ""
    try:
        ipaddress.ip_address(host)
        has_ip = True
    except ValueError:
        has_ip = False

    # A URL can be malicious precisely because it is offline, newly registered,
    # or blocked. In that case, run the URL-only checks rather than rejecting it.
    # Page-content features use their safe empty-page defaults.
    fetch_warning = None
    try:
        final_url, html, redirects = _fetch(url)
    except ValueError as error:
        final_url, html, redirects = url, "", []
        fetch_warning = str(error)
    parsed = urlparse(final_url)
    final_host = parsed.hostname or host
    soup = BeautifulSoup(html, "html.parser")
    page_text = html.lower()
    labels = host.split(".")
    subdomains = max(0, len(labels) - 2)

    assets = soup.find_all(["img", "script", "link", "audio", "video", "embed", "object"])
    external_assets = 0
    for tag in assets:
        source = tag.get("src") or tag.get("href") or ""
        if source and not _same_domain(urljoin(final_url, source), final_host):
            external_assets += 1

    anchors = soup.find_all("a")
    unsafe_anchors = 0
    for anchor in anchors:
        href = (anchor.get("href") or "").strip().lower()
        target = urljoin(final_url, href) if href else ""
        if not href or href.startswith(("#", "javascript:")) or not _same_domain(target, final_host):
            unsafe_anchors += 1

    resource_tags = soup.find_all(["meta", "script", "link"])
    external_tags = sum(
        1 for tag in resource_tags
        if (tag.get("src") or tag.get("href"))
        and not _same_domain(urljoin(final_url, tag.get("src") or tag.get("href")), final_host)
    )
    forms = soup.find_all("form")
    form_actions = [(form.get("action") or "").strip().lower() for form in forms]
    sfh = -1 if any(not action or action == "about:blank" for action in form_actions) else (
        0 if any(not _same_domain(urljoin(final_url, action), final_host) for action in form_actions) else 1
    )
    nonstandard_port = parsed.port not in (None, 80, 443)
    url_length = len(final_url)

    # Values match the -1 / 0 / 1 convention used by the source dataset.
    features = {
        "having_IP_Address": -1 if has_ip else 1,
        "URL_Length": 1 if url_length < 54 else (0 if url_length <= 75 else -1),
        "Shortining_Service": -1 if host.lower() in SHORTENERS else 1,
        "having_At_Symbol": -1 if "@" in final_url else 1,
        "double_slash_redirecting": -1 if "//" in final_url.split("://", 1)[-1] else 1,
        "Prefix_Suffix": -1 if "-" in host else 1,
        "having_Sub_Domain": 1 if subdomains == 0 else (0 if subdomains == 1 else -1),
        "SSLfinal_State": 1 if parsed.scheme == "https" else -1,
        # These unavailable binary UCI features must still use their ARFF domain.
        # -1 is the conservative placeholder; it does not claim the feature was measured.
        "Domain_registeration_length": -1,
        "Favicon": -1 if any("favicon" in (tag.get("rel") or []) and not _same_domain(urljoin(final_url, tag.get("href", "")), final_host) for tag in soup.find_all("link")) else 1,
        "port": -1 if nonstandard_port else 1,
        "HTTPS_token": -1 if "https" in host.lower() else 1,
        "Request_URL": _ratio_score(external_assets, len(assets)),
        "URL_of_Anchor": _ratio_score(unsafe_anchors, len(anchors)),
        "Links_in_tags": _ratio_score(external_tags, len(resource_tags)),
        "SFH": sfh,
        "Submitting_to_email": -1 if "mailto:" in page_text or "mail(" in page_text else 1,
        "Abnormal_URL": 1 if final_host.endswith(host) or host.endswith(final_host) else -1,
        "Redirect": 1 if len(redirects) <= 1 else 0,
        "on_mouseover": -1 if "onmouseover" in page_text else 1,
        "RightClick": -1 if "contextmenu" in page_text or "event.button==2" in page_text else 1,
        "popUpWidnow": -1 if "window.open" in page_text or "alert(" in page_text else 1,
        "Iframe": -1 if soup.find("iframe") else 1,
        "age_of_domain": -1,
        "DNSRecord": -1 if fetch_warning else 1,
        "web_traffic": 0,
        "Page_Rank": -1,
        "Google_Index": -1,
        # The dataset's value is a backlink count. It cannot be inferred from
        # outgoing links on the page, so unknown is represented as neutral.
        "Links_pointing_to_page": 0,
        "Statistical_report": -1 if has_ip or any(word in final_url.lower() for word in SUSPICIOUS_WORDS) else 1,
    }
    if fetch_warning:
        features["__analysis_warning"] = (
            "The website could not be reached, so this result is based on the URL only. "
            f"Details: {fetch_warning}"
        )
    invalid = {
        name: value for name, value in features.items()
        if name in ALLOWED_VALUES and value not in ALLOWED_VALUES[name]
    }
    if invalid:
        raise RuntimeError(f"Extractor produced values outside UCI ARFF domains: {invalid}")
    return features
