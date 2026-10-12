import argparse
import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_PHRASES = [
    "urgent action required",
    "verify your account",
    "click here now",
    "suspicious activity",
    "account suspended",
    "confirm your identity",
    "claim your prize",
    "limited time",
    "send your password",
    "bank account",
]

URL_RISK_POINTS = {
    "URL uses an IP address instead of a domain": 25,
    "URL does not use HTTPS": 20,
    "URL contains an @ symbol": 25,
    "Hostname contains multiple subdomains": 10,
    "Unusual URL scheme": 20,
    "Missing hostname": 20,
    "URL could not be parsed correctly": 20,
}


def detect_suspicious_phrases(email_text):
    normalized_text = (email_text or "").lower()
    return [phrase for phrase in SUSPICIOUS_PHRASES if phrase in normalized_text]


def extract_urls(email_text):
    url_pattern = r'https?://[^\s<>"\']+'
    raw_urls = re.findall(url_pattern, email_text or "", re.IGNORECASE)

    unique_urls = []
    seen = set()

    for url in raw_urls:
        clean_url = url.rstrip(".,!?;:)")
        normalized = clean_url.lower()

        if clean_url and normalized not in seen:
            unique_urls.append(clean_url)
            seen.add(normalized)

    return unique_urls


def analyze_url(url):
    findings = []

    try:
        parsed_url = urlparse(url)

        if parsed_url.scheme not in ("http", "https"):
            findings.append("Unusual URL scheme")
            return findings

        hostname = (parsed_url.hostname or "").lower().rstrip(".")

        if not hostname:
            findings.append("Missing hostname")
            return findings

        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            is_ip_address = False

        if is_ip_address:
            findings.append("URL uses an IP address instead of a domain")

        if "@" in parsed_url.netloc:
            findings.append("URL contains an @ symbol")

        if parsed_url.scheme != "https":
            findings.append("URL does not use HTTPS")

        if not is_ip_address and hostname.count(".") >= 3:
            findings.append("Hostname contains multiple subdomains")

    except ValueError:
        findings.append("URL could not be parsed correctly")

    return findings


def calculate_risk(detected_phrases, urls):
    phrase_points = min(len(detected_phrases) * 15, 45)
    total_url_points = 0

    for url in set(urls):
        for finding in set(analyze_url(url)):
            total_url_points += URL_RISK_POINTS.get(finding, 0)

    total_url_points = min(total_url_points, 55)
    return min(phrase_points + total_url_points, 100)


def classify_risk(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def build_report(email_text):
    detected_phrases = detect_suspicious_phrases(email_text)
    urls = extract_urls(email_text)

    url_results = []
    total_url_points = 0

    for url in urls:
        findings = analyze_url(url)
        url_results.append({"url": url, "findings": findings})
        for finding in set(findings):
            total_url_points += URL_RISK_POINTS.get(finding, 0)

    phrase_points = min(len(detected_phrases) * 15, 45)
    total_url_points = min(total_url_points, 55)
    risk_score = min(phrase_points + total_url_points, 100)
    risk_level = classify_risk(risk_score)

    return {
        "detected_phrases": detected_phrases,
        "urls": urls,
        "url_results": url_results,
        "phrase_points": phrase_points,
        "url_points": total_url_points,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def print_report(report):
    print("\n" + "=" * 55)
    print("                  ANALYSIS REPORT")
    print("=" * 55)

    print("\n[EMAIL CONTENT ANALYSIS]")
    if report["detected_phrases"]:
        print("Suspicious phrases detected:")
        for phrase in report["detected_phrases"]:
            print(f" - {phrase}")
    else:
        print("No known suspicious phrases detected.")

    print("\n[URL ANALYSIS]")
    print(f"URLs detected: {len(report['urls'])}")

    if report["url_results"]:
        for result in report["url_results"]:
            print(f"\nURL: {result['url']}")

            if result["findings"]:
                print("Warnings:")
                for finding in result["findings"]:
                    print(f" - {finding}")
            else:
                print("No basic URL warnings detected.")
    else:
        print("No HTTP or HTTPS URLs found.")

    print("\n" + "=" * 55)
    print("                 RISK ASSESSMENT")
    print("=" * 55)
    print(f"Phrase risk points:  {report['phrase_points']}/45")
    print(f"URL risk points:     {report['url_points']}/55")
    print(f"TOTAL RISK SCORE:    {report['risk_score']}/100")
    print(f"RISK CLASSIFICATION: {report['risk_level']}")

    print("\n[SECURITY RECOMMENDATION]")
    if report["risk_level"] == "CRITICAL":
        print("Very suspicious characteristics detected.")
        print("Do not click links or provide sensitive information.")
        print("Verify the message through an independent channel.")
    elif report["risk_level"] == "HIGH":
        print("Several suspicious characteristics were detected.")
        print("Treat this email with caution.")
        print("Verify the sender before taking any action.")
    elif report["risk_level"] == "MEDIUM":
        print("Some suspicious characteristics were detected.")
        print("Check the sender and links carefully.")
        print("Avoid sharing sensitive information without verification.")
    else:
        print("Few suspicious characteristics were detected.")
        print("This does not guarantee that the email is safe.")
        print("Remain cautious when opening links or attachments.")

    print("\n" + "=" * 55)
    print("Analysis complete.")
    print("=" * 55)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Detect phishing risks in email text.")
    parser.add_argument("--subject", help="Email subject line")
    parser.add_argument("--message", help="Email message body")
    parser.add_argument("--file", dest="input_file", help="Read email text from a file")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.input_file:
        with open(args.input_file, "r", encoding="utf-8") as file:
            email_text = file.read()
    elif args.subject or args.message:
        subject = args.subject or ""
        message = args.message or ""
        email_text = f"{subject} {message}".strip()
    else:
        subject = input("\nEmail subject: ")
        email_body = input("Email message: ")
        email_text = f"{subject} {email_body}".strip()

    report = build_report(email_text)
    print_report(report)


if __name__ == "__main__":
    main()