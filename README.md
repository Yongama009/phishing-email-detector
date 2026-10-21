# Phishing Email Detector

A small command-line tool that checks email text for a set of suspicious phrases and basic URL warning signs. It prints a risk score and a corresponding classification to help you decide whether a message deserves closer inspection.

## Requirements

- Python 3
- No third-party packages are needed to run the detector.
- `pytest` is needed only to run the tests.

## Usage

Run the detector interactively and enter an email subject and message when prompted:

```bash
python phishing_email_detector.py
```

Or pass the subject and message as command-line options:

```bash
python phishing_email_detector.py \
  --subject "Urgent action required" \
  --message "Verify your account at http://example.com"
```

To analyze text saved in a file:

```bash
python phishing_email_detector.py --file email.txt
```

The report includes detected phrases, URLs and their warnings, the score breakdown, and a risk classification.

## How the score works

- **Suspicious phrases:** Each matching phrase adds 15 points, up to 45 points.
- **URL warnings:** Warnings contribute points, up to 55 points total. Checks include IP-address hosts, non-HTTPS URLs, an `@` symbol, and hostnames with multiple subdomains.
- The final score is capped at 100.

| Score | Classification |
| --- | --- |
| 0–29 | LOW |
| 30–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

The phrase list and point values are fixed in the source code; the score is a heuristic, not a definitive verdict.

## Run the tests

Install pytest if it is not already available:

```bash
python -m pip install pytest
```

Then run:

```bash
python -m pytest -q
```

## Limitations

This tool performs simple text matching and URL-shape checks. It does not contact websites, verify senders, inspect attachments, or use threat-intelligence data. A low score does **not** mean an email is safe, and legitimate email can also trigger warnings. Verify suspicious messages through a trusted, independent channel.

WTC-X42MSYH9
