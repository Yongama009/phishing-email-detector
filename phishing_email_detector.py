import ipaddress
import re
import sys
from urllib.parse import urlparse

SUSPICIOUS_PHRASES = [
    "urgent action required",
    "verify your account",
    "click here now",
    "suspicious activity",
    "password expired",
    "limited time offer",
    "claim your prize",
    "wire transfer",
]


def analyze_url(url):
    findings = []
    cleaned_url = url.rstrip(".,!?;:)")
    parsed_url = urlparse(cleaned_url)

    if parsed_url.scheme not in ("http", "https"):
        findings.append("Unusual URL scheme")

    hostname = parsed_url.hostname
    if not hostname:
        findings.append("Missing hostname")
        return findings

    try:
        ipaddress.ip_address(hostname)
        findings.append("URL uses an IP address instead of a domain")
    except ValueError:
        pass

    if "@" in parsed_url.netloc:
        findings.append("URL contains an @ symbol")

    if parsed_url.scheme != "https":
        findings.append("URL does not use HTTPS")

    if hostname.count(".") >= 3:
        findings.append("Hostname contains multiple subdomains")

    return findings


def detect_suspicious_phrases(email_text):
    text = (email_text or "").lower()
    found_phrases = []

    for phrase in SUSPICIOUS_PHRASES:
        if phrase in text:
            found_phrases.append(phrase)

    return found_phrases


def extract_urls(email_text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, email_text or "")


def analyze_email(email_text):
    detected_phrases = detect_suspicious_phrases(email_text)
    urls = extract_urls(email_text)
    return detected_phrases, urls


def print_report(email_text):
    detected_phrases, urls = analyze_email(email_text)

    print("\n" + "=" * 45)
    print("             ANALYSIS REPORT")
    print("=" * 45)

    print("\n[EMAIL CONTENT ANALYSIS]")
    if detected_phrases:
        print("Suspicious phrases detected:")
        for phrase in detected_phrases:
            print(f" - {phrase}")
    else:
        print("No known suspicious phrases detected.")

    print("\n[URL ANALYSIS]")
    if urls:
        for url in urls:
            print(f"\nURL: {url}")
            findings = analyze_url(url)
            if findings:
                print("Warnings:")
                for finding in findings:
                    print(f" - {finding}")
            else:
                print("No basic URL warnings detected.")
    else:
        print("No HTTP or HTTPS URLs found in the email.")

    print("\n" + "=" * 45)
    print("Analysis complete.")
    print("=" * 45)


if __name__ == "__main__":
    default_email = (
        "Urgent action required. Verify your account immediately before suspicious activity "
        "is detected. Click here now: http://10.0.0.5/login and https://example.com/secure."
    )

    if len(sys.argv) > 1:
        email_text = " ".join(sys.argv[1:])
    else:
        email_text = default_email

    print_report(email_text)