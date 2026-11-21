import ipaddress
from urllib.parse import urlsplit

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure", "update",
    "password", "signin", "banking", "confirm", "wallet",
    "payment", "free", "gift", "suspended"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "shorturl.at"
]

# Popular brands and their official domains
BRANDS = {
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "paypal": ["paypal.com"],
    "amazon":["amazon.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "apple": ["apple.com"],
    "netflix": ["netflix.com"],
}

def validate_url(url):
    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if any(char.isspace() for char in url):
        raise ValueError("URL cannot contain spaces.")

    if "://" not in url:
        url = "https://" + url

    parsed = urlsplit(url)

    if parsed.scheme not in ["http", "https"]:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL.")

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid domain name.")

    return url, parsed, hostname.lower()


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def check_suspicious_domain(hostname):
    findings = []
    score = 0

    # Check for brand impersonation
    for brand, official_domains in BRANDS.items():

        if brand in hostname:
            legitimate = any(
                hostname == domain or hostname.endswith("." + domain)
                for domain in official_domains
            )

            if not legitimate:
                score += 30
                findings.append(
                    f"The domain may be impersonating {brand}."
                )

    # Check for excessive numbers in domain
    if not is_ip_address(hostname):
        domain_name = hostname.split(".")[0]

        if sum(char.isdigit() for char in domain_name) >= 3:
            score += 10
            findings.append(
                "The domain contains an unusual number of digits."
            )

    return score, findings


def analyze_url(url):

    url, parsed, hostname = validate_url(url)

    score = 0
    findings = []

    # HTTPS check
    if parsed.scheme == "http":
        score += 15
        findings.append("The URL uses HTTP instead of HTTPS.")
    else:
        findings.append("The URL uses HTTPS.")

    # IP address check
    if is_ip_address(hostname):
        score += 25
        findings.append(
            "The URL uses an IP address instead of a domain."
        )

    # @ symbol check
    if "@" in url:
        score += 20
        findings.append("The URL contains an @ symbol.")

    # URL length check
    if len(url) > 120:
        score += 20
        findings.append("The URL is unusually long.")
    elif len(url) > 75:
        score += 10
        findings.append("The URL is longer than usual.")

    # Suspicious keywords
    lower_url = url.lower()

    found_keywords = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in lower_url
    ]

    if found_keywords:
        score += 10
        findings.append(
            "Suspicious keywords found: "
            + ", ".join(found_keywords)
        )

    # Subdomain check
    if not is_ip_address(hostname):
        if len(hostname.split(".")) > 3:
            score += 10
            findings.append(
                "The domain contains multiple subdomains."
            )

    # Hyphen check
    domain_parts = hostname.split(".")

    if len(domain_parts) >= 2:
        if "-" in domain_parts[-2]:
            score += 5
            findings.append(
                "The main domain contains a hyphen."
            )

    # Punycode check
    if "xn--" in hostname:
        score += 15
        findings.append(
            "The domain contains punycode."
        )

    # URL shortener check
    if hostname in SHORTENERS:
        score += 10
        findings.append(
            "The domain belongs to a known URL shortener."
        )

    # New suspicious domain detection
    domain_score, domain_findings = check_suspicious_domain(
        hostname
    )

    score += domain_score
    findings.extend(domain_findings)

    # Maximum score
    score = min(score, 100)

    # Risk classification
    if score >= 50:
        risk = "HIGH"
    elif score >= 25:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "url": url,
        "domain": hostname,
        "score": score,
        "risk": risk,
        "findings": findings
    }