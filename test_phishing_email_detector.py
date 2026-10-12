import pytest

from phishing_email_detector import (
    analyze_url,
    calculate_risk,
    classify_risk,
    detect_suspicious_phrases,
    extract_urls,
)


def test_detect_suspicious_phrases():
    text = "Urgent action required. Verify your account immediately."
    result = detect_suspicious_phrases(text)
    assert "urgent action required" in result
    assert "verify your account" in result


def test_extract_urls_removes_trailing_punctuation():
    email_text = "Click here now: http://10.0.0.5/login, and https://example.com/secure."
    result = extract_urls(email_text)
    assert result == ["http://10.0.0.5/login", "https://example.com/secure"]


def test_analyze_url_flags_ip_and_http():
    findings = analyze_url("http://10.0.0.5/login")
    assert "URL uses an IP address instead of a domain" in findings
    assert "URL does not use HTTPS" in findings


def test_calculate_risk_and_classify_risk():
    suspicious = ["urgent action required", "verify your account"]
    urls = ["http://10.0.0.5/login", "http://evil.com"]
    risk_score = calculate_risk(suspicious, urls)

    assert risk_score >= 80
    assert classify_risk(risk_score) == "CRITICAL"


def test_non_phishing_email_has_low_risk():
    suspicious = []
    urls = ["https://example.com/secure"]
    risk_score = calculate_risk(suspicious, urls)
    assert risk_score < 30
    assert classify_risk(risk_score) == "LOW"
