import pytest

from checker import analyze_email, analyze_url


def titles(result):
    return [f.title for f in result.findings]


@pytest.mark.parametrize("url", [
    "https://www.google.com",
    "https://accounts.google.com/signin",
    "https://www.amazon.in/gp/cart",
    "https://login.sbi.co.in/",
    "https://pineapple.com",
])
def test_genuine_sites_score_zero(url):
    result = analyze_url(url)
    assert result.score == 0
    assert result.level == "low"


def test_empty_input_is_zero():
    assert analyze_url("   ").score == 0
    assert analyze_email("").score == 0


def test_ip_address_and_at_symbol_are_high_risk():
    result = analyze_url("http://192.168.1.1/paypal-login@secure.xyz")
    assert result.level == "high"
    assert "IP address instead of a domain" in titles(result)
    assert "'@' symbol in the address" in titles(result)


def test_numeric_ip_is_detected():
    assert "IP address instead of a domain" in titles(analyze_url("http://3232235777/login"))


def test_lookalike_domain():
    result = analyze_url("http://paypa1-secure-login.xyz/verify")
    assert "Look-alike spelling" in titles(result)
    assert result.level == "high"


def test_brand_on_wrong_domain_and_subdomains():
    result = analyze_url("https://login.paypal.com.account-verify.top/update")
    assert "Brand name on the wrong domain" in titles(result)
    assert "Too many subdomains" in titles(result)
    assert result.level == "high"


def test_real_brand_subdomain_is_fine():
    assert analyze_url("https://mail.google.com/mail").score == 0


def test_brand_only_in_path():
    assert "Brand name only in the path" in titles(analyze_url("https://evil.top/paypal/login"))


def test_shortener_is_at_least_medium():
    result = analyze_url("https://bit.ly/3abcd")
    assert "Shortened link" in titles(result)
    assert result.level == "medium"


def test_defanged_links_are_understood():
    result = analyze_url("hxxp://sbi-kyc-update[.]top/login")
    assert result.subject == "http://sbi-kyc-update.top/login"
    assert "Brand name on the wrong domain" in titles(result)


def test_javascript_scheme_is_high_risk():
    result = analyze_url("javascript:alert(1)")
    assert result.level == "high"
    assert titles(result) == ["Script or data link"]


def test_malformed_link():
    assert "Malformed link" in titles(analyze_url("http://[::1"))


def test_unicode_homograph_is_flagged():
    result = analyze_url("https://аpple.com")
    assert "Non-ASCII characters in the domain" in titles(result)
    assert result.level in ("medium", "high")


def test_punycode_and_download_and_redirect():
    assert "Punycode domain (xn--)" in titles(analyze_url("https://xn--pple-43d.com"))
    assert "Link to a program download" in titles(analyze_url("https://x.com/get/app.apk"))
    assert "Another link hidden inside the link" in titles(
        analyze_url("https://x.com/go?next=https://evil.top"))


def test_unusual_port_and_http():
    result = analyze_url("http://example.com:8080/")
    assert "Unusual port number" in titles(result)
    assert "No HTTPS" in titles(result)


def test_missing_scheme_does_not_count_as_http():
    assert "No HTTPS" not in titles(analyze_url("example.com/page"))


def test_score_never_exceeds_100():
    nasty = "http://192.168.1.1:8080/paypal-login-verify-update@secure.xyz/a.apk?url=http://x"
    assert analyze_url(nasty).score <= 100


SCAM = ("Dear customer, URGENT: your account will be suspended within 24 hours. "
        "Confirm your OTP and password at http://sbi-kyc-update.top/login "
        "to avoid legal action.")


def test_scam_message_is_high_risk_with_reasons():
    result = analyze_email(SCAM)
    assert result.level == "high"
    found = titles(result)
    for expected in ("Pressure and urgency", "Asks for sensitive information",
                     "Threats or rewards", "Generic greeting",
                     "Risky link inside the message"):
        assert expected in found


def test_friendly_message_is_low_risk():
    result = analyze_email("Hi! Lunch tomorrow? Here is the map: https://www.google.com/maps")
    assert result.score == 0
    assert result.level == "low"


def test_whole_word_matching_avoids_false_positives():
    result = analyze_email("I was shopping and spinning around, no problem at all.")
    assert result.score == 0


def test_only_distinct_links_are_analysed():
    text = "See http://bit.ly/a and again http://bit.ly/a."
    result = analyze_email(text)
    assert titles(result).count("Link: Shortened link") == 1


def test_many_links_are_capped():
    text = " ".join(f"http://192.168.0.{i}/x" for i in range(1, 40))
    result = analyze_email(text)
    assert titles(result).count("Link: IP address instead of a domain") <= 10
