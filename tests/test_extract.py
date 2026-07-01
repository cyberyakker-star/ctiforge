"""Tests for deterministic IOC extraction — especially defanged forms."""

from pathlib import Path

from ctiforge.extract import extract_indicators

FIXTURE = Path(__file__).parent / "fixtures" / "sample_advisory.txt"


def _by_type(indicators):
    out = {}
    for i in indicators:
        out.setdefault(i.type, set()).add(i.value)
    return out


def test_defanged_url_ip_domain():
    text = (
        "See hxxps://evil.example[.]org/x and host evil[.]com talking to 1.2.3[.]4. "
        + "filler " * 100
    )
    got = _by_type(extract_indicators(text))
    assert "https://evil.example.org/x" in got.get("url", set())
    assert "1.2.3.4" in got.get("ipv4", set())
    assert "evil.com" in got.get("domain", set())


def test_private_ip_dropped_by_default():
    text = "Internal host 192.168.1.10 and public 8.8.8.8. " + "filler " * 100
    got = _by_type(extract_indicators(text))
    assert "8.8.8.8" in got.get("ipv4", set())
    assert "192.168.1.10" not in got.get("ipv4", set())


def test_private_ip_kept_with_flag():
    text = "Internal host 192.168.1.10 here. " + "filler " * 100
    got = _by_type(extract_indicators(text, include_private=True))
    assert "192.168.1.10" in got.get("ipv4", set())


def test_filename_false_positives_dropped():
    text = "Open example.py and report.pdf and config.yaml files. " + "filler " * 100
    got = _by_type(extract_indicators(text))
    domains = got.get("domain", set())
    assert "example.py" not in domains
    assert "report.pdf" not in domains
    assert "config.yaml" not in domains


def test_hash_bucketing():
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    text = f"Hashes {md5} {sha1} {sha256}. " + "filler " * 100
    got = _by_type(extract_indicators(text))
    assert md5 in got.get("md5", set())
    assert sha1 in got.get("sha1", set())
    assert sha256 in got.get("sha256", set())


def test_case_insensitive_dedupe():
    md5 = "44D88612FEA8A8F36DE82E1278ABB02F"
    text = f"{md5} and {md5.lower()} appear twice. " + "filler " * 100
    hashes = [i for i in extract_indicators(text) if i.type == "md5"]
    assert len(hashes) == 1


def test_defanged_original_recorded():
    text = "Beacon to evil[.]com now. " + "filler " * 100
    dom = next(i for i in extract_indicators(text) if i.type == "domain")
    assert dom.value == "evil.com"
    assert dom.defanged_original == "evil[.]com"


def test_fixture_advisory_extracts_expected():
    text = FIXTURE.read_text(encoding="utf-8")
    got = _by_type(extract_indicators(text))
    assert "45.77.88.99" in got.get("ipv4", set())
    assert "evil-c2.example" in got.get("domain", set())
    assert "https://malicious.example.org/update" in got.get("url", set())
    assert "phish@evil-c2.example" in got.get("email", set())
    assert "44d88612fea8a8f36de82e1278abb02f" in got.get("md5", set())
