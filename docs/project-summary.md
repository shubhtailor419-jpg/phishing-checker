# Phishing Checker — Project Summary

**Program:** IBM SkillsBuild × BharatCares National Cybersecurity Bootcamp, October 2026
**Author:** Shubh Tailor
**Type:** Web application (Python / Flask)
**Repository:** https://github.com/shubhtailor419-jpg/phishing-checker
**Live demo:** <add your hosted link, if deployed>

## 1. Abstract

Phishing is one of the most common cyber attacks: criminals send fake links and messages that imitate banks, delivery services and government bodies to steal passwords, OTPs and money. This project is a web application that analyses a link, email or SMS and gives a 0–100 risk score with a plain-English explanation of every warning sign it found. Unlike a simple "safe / unsafe" answer, the tool teaches users what to look for.

## 2. Problem statement

Many people cannot tell a fake link from a real one, especially on a phone. Existing checkers often give a verdict without a reason, so users do not learn from them, and some work by visiting the suspicious link, which can itself be risky.

## 3. Objectives

1. Detect common phishing patterns in URLs and in message text.
2. Explain each finding clearly so users learn to spot attacks themselves.
3. Never visit or contact the link being checked.
4. Follow secure-development practices, since this is a security tool.
5. Make it free, private and usable on a phone.

## 4. How it works

1. The user pastes a link or a message in the browser.
2. The browser sends it to a JSON API (`POST /api/analyze`).
3. The server validates it (type, length, rate limit), then runs the rule-based detection engine.
4. The engine applies weighted rules and returns a score, a verdict, advice and the list of findings.
5. The browser displays the result. All text is inserted safely, with no HTML injection.

**Link rules (20):** IP-address hosts, look-alike spellings (`paypa1`), brand names on the wrong domain, too many subdomains, `@` tricks, punycode and non-ASCII homographs, link shorteners, suspicious TLDs, direct program downloads, hidden redirect parameters, missing HTTPS, long or hyphen-heavy addresses, unusual ports, login-style words on unknown sites, and script/data links.

**Message rules (5):** urgency language, requests for OTP/passwords/PIN, threats or fake rewards, generic greetings, and a risky link inside the message (every link is analysed with the link rules).

**Score bands:** 0–20 Low risk · 21–50 Suspicious · 51–100 Likely phishing.

## 5. Technology

Python 3, Flask, HTML/CSS/vanilla JavaScript, pytest, gunicorn. The detection engine (`checker/`) uses only the Python standard library and is independent of the web layer.

## 6. Security measures built in

- Never fetches the pasted URL (no SSRF, no contact with malicious sites).
- Strict Content-Security-Policy and other security headers; no inline scripts or styles.
- XSS-safe rendering and Jinja auto-escaping.
- Input validation, length limits, request-size limit and rate limiting.
- No server-side storage of user input; the short "recent checks" list lives only in the user's browser.
- No third-party scripts, fonts or trackers.

## 7. Testing

The project has an automated test suite (pytest, 43 tests) covering the detection rules (genuine sites score zero, each attack pattern is flagged, defanged links, false-positive guards such as whole-word matching) and the web app (pages, API validation, error codes, security headers, rate limiting, absence of inline scripts).

## 8. Results

- Genuine sites such as `google.com` and `amazon.in` score 0.
- `http://paypa1-secure-login.xyz/verify` scores 65 (Likely phishing) with four explained findings.
- A typical scam SMS (urgency + OTP request + threat + fake bank link) scores 100.

These are hand-written test cases, not a statistical evaluation on a large dataset.

## 9. Limitations

- Rule-based: it cannot prove a link is safe and does not know about brand-new attacks.
- It does not open the page, so it cannot judge its content.
- Rules can misfire on unusual but genuine sites.
- The brand list is small.

## 10. Future scope

Threat-intelligence look-ups (e.g. Google Safe Browsing), domain-age signals, a browser extension, Hindi interface, and a machine-learning classifier trained on public phishing datasets and compared against this rule-based baseline.

## 11. What I learned

<Add 3–4 sentences in your own words: for example what phishing techniques you studied, what was hardest to build, and how you would improve it.>
