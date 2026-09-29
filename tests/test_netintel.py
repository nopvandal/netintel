"""Offline tests for netintel: no network access, every service is mocked.

Run from the project directory with the interpreter that has dnspython installed:
    python -m unittest discover -s tests -v
"""
import contextlib
import http.client
import io
import ssl
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

import dns.message
import dns.rcode
import dns.resolver
import dns.rrset

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import netintel as n


def rec(name, kind, value, ttl=300):
    return {"name": name if name.endswith(".") else name + ".", "ttl": ttl, "type": kind, "value": value}


class FakeClient:
    """Answers from tables; anything not configured fails loudly as an upstream error."""

    timeout = 5
    resolver_label = "test resolver over UDP"

    def __init__(self, records=None, dns_errors=None, ad=False):
        self.records = records or {}
        self.dns_errors = dns_errors or {}
        self.ad = ad
        self.rdap = Mock(side_effect=n.UpstreamError("rdap not mocked"))
        self.http = Mock(side_effect=n.UpstreamError("http not mocked"))
        self.network = Mock(side_effect=n.UpstreamError("network not mocked"))
        self.whois = Mock(side_effect=n.UpstreamError("whois not mocked"))
        self.peering = Mock(side_effect=n.UpstreamError("peering not mocked"))
        self.ripe = Mock(side_effect=n.UpstreamError("ripe not mocked"))
        self.doh_json = Mock(side_effect=n.UpstreamError("doh not mocked"))

    def dns(self, name, kind):
        if (name, kind) in self.dns_errors:
            raise n.UpstreamError(self.dns_errors[(name, kind)])
        value = self.records.get((name, kind), [])
        if value == "NXDOMAIN":
            return {"status": "NXDOMAIN", "records": [], "ad": False}
        return {"status": "NOERROR", "records": value, "ad": self.ad}

    def dns_values(self, name, kind):
        return [r["value"] for r in self.dns(name, kind)["records"] if r["type"] == kind]


def render(command, args, client=None, feeds=None, grep=False):
    target = getattr(args, "target", None) or getattr(args, "command", None)
    out = n.GrepOutput(target) if grep else n.HumanOutput(target, color=False, width=120)
    ctx = SimpleNamespace(args=args, client=client or FakeClient(), feeds=feeds or Mock(), out=out)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
        command(ctx)
        code = out.finish()
    return buffer.getvalue(), code


def failing_feeds(directory):
    client = Mock()
    client.http.side_effect = n.UpstreamError("service unavailable")
    return n.Feeds(client, directory, 0)


def clean_feeds(directory):
    client = Mock()

    def http(url, **kwargs):
        if "drop_v4" in url:
            return '{"cidr":"198.51.100.0/24","sblid":"SBL1"}\n{"type":"metadata"}\n'
        if "drop_v6" in url:
            return '{"cidr":"2001:db8:dead::/48","sblid":"SBL6"}\n'
        if "asndrop" in url:
            return '{"asn":64666,"asname":"BAD-AS","cc":"ZZ"}\n'
        if "feodo" in url:
            return "# Feodo Tracker\n203.0.113.66\n"
        return "203.0.113.77\n"

    client.http.side_effect = http
    return n.Feeds(client, directory, 3600)


class InputTests(unittest.TestCase):
    def test_target_detection(self):
        for value, expected in {
            "Example.COM.": ("domain", "example.com"),
            "bücher.de": ("domain", "xn--bcher-kva.de"),
            "_dmarc.example.com": ("domain", "_dmarc.example.com"),
            "1.1.1.1": ("ip", "1.1.1.1"),
            "2606:4700:4700::1111": ("ip", "2606:4700:4700::1111"),
            "1.1.1.8/24": ("prefix", "1.1.1.0/24"),
            "as0013335": ("asn", "AS13335"),
        }.items():
            with self.subTest(value=value):
                self.assertEqual(n.detect(value), expected)

    def test_invalid_targets(self):
        for value in ["999.1.1.1", "01.1.1.1", "192.0.2.1::", "fe80::1%eth0", "https://example.com",
                      "-bad.com", "a..com", "AS4294967296", "2001:db8::/129", "example.com\nend"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                n.detect(value)

    def test_options_and_aliases(self):
        args, _ = n.parse_args(["--grep", "--dns-transport", "tcp", "rep", "1.1.1.1", "--max-ips", "2", "--color", "never"])
        self.assertEqual((args.command, args.kind, args.dns_transport, args.max_ips, args.grep, args.color),
                         ("reputation", "ip", "tcp", 2, True, "never"))
        self.assertEqual(n.parse_args(["neighbors", "13335"])[0].command, "neighbors")
        self.assertEqual(n.parse_args(["neighbours", "13335"])[0].command, "neighbors")
        self.assertEqual(n.parse_args(["--color", "always", "example.com"])[0].command, "domain")
        self.assertEqual(n.parse_args(["-g", "example.com"])[0].grep, True)

    def test_invalid_options_exit_2_with_short_message(self):
        for argv in [["--timeout", "nan", "check"], ["--max-ips", "0", "check"], ["rpki", "1.1.1.1", "13335"],
                     ["as-set", "AS-X\n!gAS1"], ["--json", "example.com"], ["--color", "sometimes", "check"]]:
            stderr = io.StringIO()
            with self.subTest(argv=argv), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                n.parse_args(argv)
            self.assertEqual(caught.exception.code, 2)
            self.assertIn("help' for usage", stderr.getvalue())
            self.assertNotIn("{lookup,domain", stderr.getvalue(), "the full usage block should not be printed")

    def test_resolver_names(self):
        for value in ["dns.quad9.net", "1.1.1.1", "2606:4700:4700::1111"]:
            self.assertEqual(n.resolver_spec(value), value)

    def test_bulk_framing(self):
        self.assertEqual(n.bulk_request(["# comment", "", "1.1.1.1", "as13335"]),
                         "begin\r\nverbose\r\n1.1.1.1\r\nAS13335\r\nend\r\n")
        with self.assertRaises(ValueError):
            n.bulk_request(["1.1.1.1", "end"])


class ParserTests(unittest.TestCase):
    def test_radb(self):
        self.assertEqual(n.parse_radb("A10\nAS1 AS2\nC\n"), ["AS1", "AS2"])
        self.assertEqual(n.parse_radb("D\n"), [])
        with self.assertRaises(n.UpstreamError):
            n.parse_radb("F bad query\n")

    def test_ris(self):
        self.assertEqual(n.parse_ris("% banner\n13335 1.1.1.0/24 42\n"), {"1.1.1.0/24": 42})
        with self.assertRaises(n.UpstreamError):
            n.parse_ris("rate limited")

    def test_txt_and_spf(self):
        self.assertFalse(n.spf_summary([])["present"])
        self.assertIsNone(n.spf_summary(None)["present"], "a failed TXT lookup must be unknown, not 'no SPF'")
        self.assertFalse(n.spf_summary(["v=spf1 -all", "v=spf1 ~all"])["valid"])
        summary = n.spf_summary(["v=spf1 include:_spf.example.com a mx ~all"])
        self.assertEqual((summary["all"], summary["includes"], summary["dns_lookup_terms"]), ("~all", ["_spf.example.com"], 3))

    def test_dmarc(self):
        summary = n.dmarc_summary("v=DMARC1; p=reject; rua=mailto:r@example.com; pct=50")
        self.assertEqual((summary["policy"], summary["percent"], summary["present"]), ("reject", "50", True))

    def test_dnsbl(self):
        self.assertEqual(n.dnsbl_query_name("1.2.3.4", "zone.example"), "4.3.2.1.zone.example")
        self.assertEqual(len(n.dnsbl_query_name("2001:db8::1", "zone.example").split(".")[:-2]), 32)
        listed, notes = n.decode_dnsbl(["127.255.255.254"], n.ZEN_CODES)
        self.assertIsNone(listed)
        self.assertIn("public", notes[0])
        self.assertEqual(n.decode_dnsbl(["127.0.0.24"], bitmask=n.SURBL_BITS), (True, ["PH: phishing", "MW: malware"]))
        self.assertIsNone(n.decode_dnsbl(["127.0.0.1"], bitmask=n.SURBL_BITS)[0])

    def test_text_helpers(self):
        self.assertEqual(n.strip_whois("% banner\n\n13335\t1.1.1.0/24\n\n\n% tail\n"), "13335\t1.1.1.0/24")
        self.assertEqual(n.strip_banner("% a\n% b\n\n% RRC Peer\nrrc00 1\n"), "% RRC Peer\nrrc00 1")
        self.assertEqual(n.ede_codes(["EDE(16): Censored", "Response from x"]), [16])
        self.assertEqual([n.short_ttl(v) for v in (0, 30, 300, 213, 5400, 3600, 86400, 83467, 90061)],
                         ["0s", "30s", "5m", "3m33s", "1h30m", "1h", "1d", "23h11m", "1d1h"])
        self.assertEqual([n.link_speed(v) for v in (100, 1000, 10000, 2500, None)], ["100M", "1G", "10G", "2.5G", "-"])
        self.assertEqual(n.link_speed(0), "-")
        self.assertEqual(n.display_name("mx.example.com."), "mx.example.com")
        self.assertEqual(n.display_name("0 ."), "0 .")
        self.assertEqual(n.format_ds("2371 13 2 ABCD"), "key tag 2371 · ECDSAP256SHA256 · SHA-256")
        now = n.parse_time("2026-01-01T00:00:00Z")
        self.assertEqual(n.ago(n.parse_time("2024-01-01T00:00:00Z"), now), "2 years ago")
        self.assertEqual(n.ago(n.parse_time("2026-01-01T03:00:00Z"), now), "in 3 hours")

    def test_scope_descriptions(self):
        import ipaddress
        for value, expected in (("192.0.2.1", "documentation address"), ("100.64.1.1", "carrier-grade NAT address"),
                                ("10.1.1.1", "private address"), ("127.0.0.1", "loopback address"),
                                ("fe80::1", "link-local address"), ("2001:db8::1", "documentation address"),
                                ("fd00::1", "unique local address"), ("224.0.0.1", "multicast address")):
            self.assertEqual(n.scope_description(ipaddress.ip_address(value)), expected)

    def test_route_steps_cover_every_origin(self):
        steps = n.route_steps("1.1.1.0/24", ["AS1", "AS2"])
        self.assertEqual(sum(step[0] == "rpki" for step in steps), 2)


class FilterVerdictTests(unittest.TestCase):
    baseline: ClassVar[dict] = {"status": 0, "answers": ["192.0.2.1"]}

    def test_reviewer_cases(self):
        self.assertFalse(n.filter_verdict(self.baseline, self.baseline))
        self.assertTrue(n.filter_verdict(self.baseline, {"status": 3, "answers": []}))
        self.assertTrue(n.filter_verdict(self.baseline, {"status": 0, "answers": ["0.0.0.0"]}))
        self.assertIsNone(n.filter_verdict({"status": 3, "answers": []}, self.baseline))

    def test_servfail_and_refused_without_evidence_are_unknown(self):
        self.assertIsNone(n.filter_verdict(self.baseline, {"status": 2, "answers": []}))
        self.assertIsNone(n.filter_verdict(self.baseline, {"status": 5, "answers": []}))
        self.assertIsNone(n.filter_verdict(self.baseline, {"status": 0, "answers": []}))

    def test_extended_errors_are_evidence(self):
        self.assertTrue(n.filter_verdict(self.baseline, {"status": 5, "answers": [], "ede": [15]}))
        self.assertTrue(n.filter_verdict(self.baseline, {"status": 0, "answers": ["0.0.0.0"], "comment": ["EDE(16): Censored"]}))
        self.assertIsNone(n.filter_verdict(self.baseline, {"status": 2, "answers": [], "ede": [22]}))

    def test_different_real_answer_is_not_a_block(self):
        self.assertFalse(n.filter_verdict(self.baseline, {"status": 0, "answers": ["192.0.2.99"]}))


class InterceptionProbeTests(unittest.TestCase):
    query = dns.message.make_query("id.server", "TXT", rdclass="CH")

    def reply(self, identity=None, rcode=0):
        response = dns.message.make_response(self.query)
        response.set_rcode(rcode)
        if identity:
            response.answer = [dns.rrset.from_text("id.server.", 0, "CH", "TXT", f'"{identity}"')]
        return response

    def probe(self, udp, tls):
        kwargs = lambda value: {"side_effect": value} if isinstance(value, Exception) else {"return_value": value}  # noqa: E731
        with patch("dns.query.udp", **kwargs(udp)), patch("dns.query.tls", **kwargs(tls)):
            return n.interception_probe(1)

    def test_same_site_is_direct(self):
        self.assertEqual(self.probe(self.reply("sjc06"), self.reply("sjc10"))["state"], "direct")

    def test_different_identities_are_not_direct(self):
        result = self.probe(self.reply("local-proxy"), self.reply("cloudflare"))
        self.assertEqual(result["state"], "redirected")
        self.assertNotIn("Direct:", result["verdict"])

    def test_refused_udp_is_not_an_answer(self):
        self.assertEqual(self.probe(self.reply(rcode=dns.rcode.REFUSED), self.reply("sjc06"))["state"], "intercepted")

    def test_mismatched_udp_reply_is_interception(self):
        error = dns.query.BadResponse("A DNS query response does not respond to the question asked.")
        self.assertEqual(self.probe(error, self.reply("sjc06"))["state"], "intercepted")

    def test_tls_blocked_and_no_path(self):
        self.assertEqual(self.probe(self.reply("sjc06"), OSError("refused"))["state"], "tls-blocked")
        self.assertEqual(self.probe(OSError("x"), OSError("y"))["state"], "no-path")


class DnssecTests(unittest.TestCase):
    def test_validated_deep_hostname_is_signed(self):
        client = Mock()
        client.dns_values.side_effect = lambda name, kind: ["12345 13 2 ABCD"] if name == "example.com" else []
        result = n.dnssec_summary(client, "a.b.example.com", True)
        self.assertIs(result["delegation_signed"], True)
        self.assertEqual(result["zone"], "example.com")

    def test_unvalidated_name_uses_the_zone_apex(self):
        client = FakeClient({("example.com", "SOA"): [rec("example.com", "SOA", "ns. host. 1 2 3 4 5")]})
        result = n.dnssec_summary(client, "a.b.example.com", False)
        self.assertEqual((result["delegation_signed"], result["zone"]), (False, "example.com"))

    def test_signed_zone_behind_non_validating_resolver(self):
        client = FakeClient({("example.com", "SOA"): [rec("example.com", "SOA", "ns. host. 1 2 3 4 5")],
                             ("example.com", "DS"): [rec("example.com", "DS", "2371 13 2 AB")]})
        result = n.dnssec_summary(client, "www.example.com", False)
        self.assertEqual((result["delegation_signed"], result["validated"]), (True, False))
        self.assertIn("does not validate", result["note"])

    def test_cname_target_soa_does_not_make_the_alias_an_apex(self):
        client = FakeClient({("www.example.com", "SOA"): [rec("www.example.com", "CNAME", "cdn.example.net."),
                                                          rec("cdn.example.net", "SOA", "ns. host. 1 2 3 4 5")],
                             ("example.com", "SOA"): [rec("example.com", "SOA", "ns. host. 1 2 3 4 5")]})
        self.assertEqual(n.find_zone_apex(client, "www.example.com"), "example.com")

    def test_apex_not_found_is_unknown(self):
        self.assertIsNone(n.dnssec_summary(FakeClient(), "example.com", False)["delegation_signed"])


class EmailAuthTests(unittest.TestCase):
    def test_dmarc_found_at_parent_and_spf_unknown(self):
        client = FakeClient({("_dmarc.example.com", "TXT"): [rec("_dmarc.example.com", "TXT", "v=DMARC1; p=none")]})
        result = n.email_auth_summary(client, "mail.example.com", None)
        self.assertIsNone(result["spf"]["present"])
        self.assertEqual((result["dmarc"]["policy"], result["dmarc"]["found_at"]), ("none", "_dmarc.example.com"))


class FeedTests(unittest.TestCase):
    def test_parse_feed_accepts_real_shapes(self):
        entries, problem = n.parse_feed("spamhaus_drop_v4", '{"cidr":"1.1.1.0/24","sblid":"x"}\n{"type":"metadata"}\n')
        self.assertIsNone(problem)
        self.assertEqual(str(entries[0][0]), "1.1.1.0/24")
        self.assertEqual(n.parse_feed("spamhaus_asndrop", '{"asn":13335}\n')[0].keys(), {13335})
        self.assertEqual(n.parse_feed("tor_exits", "# c\n1.1.1.1\n")[0], {"1.1.1.1"})
        self.assertEqual(n.parse_feed("feodo_c2", "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist\n# nothing\n"), (set(), None))

    def test_parse_feed_rejects_error_pages(self):
        for key, text in [("spamhaus_drop_v4", "<html>temporarily unavailable</html>"),
                          ("tor_exits", "<!DOCTYPE html><title>502</title>"),
                          ("tor_exits", "Rate limit exceeded"),
                          ("feodo_c2", "Rate limit exceeded"),
                          ("tor_exits", ""),
                          ("tor_exits", "1.1.1.1\n" + "garbage\n" * 5)]:
            with self.subTest(key=key, text=text[:20]):
                entries, problem = n.parse_feed(key, text)
                self.assertIsNone(entries)
                self.assertTrue(problem)

    def test_one_bad_line_is_tolerated(self):
        text = "".join(f"10.0.{i // 250}.{i % 250}\n" for i in range(300)) + "truncated-last-li"
        self.assertEqual(len(n.parse_feed("tor_exits", text)[0]), 300)

    def test_fresh_cache_avoids_http(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "tor_exits.txt").write_text("1.1.1.1\n")
            client = Mock()
            self.assertEqual(n.Feeds(client, directory, 86400).load("tor_exits")["source"], "cache")
            client.http.assert_not_called()

    def test_refresh_failure_preserves_stale_data(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "tor_exits.txt").write_text("1.1.1.1\n")
            client = Mock()
            client.http.side_effect = n.UpstreamError("timeout")
            entry = n.Feeds(client, directory, 0, refresh=True).load("tor_exits")
            self.assertIn("1.1.1.1", entry["data"])
            self.assertEqual(entry["source"], "stale cache")
            self.assertIn("timeout", entry["warning"])

    def test_bad_refresh_never_overwrites_good_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spamhaus_drop_v4.txt"
            good = '{"cidr":"1.1.1.0/24","sblid":"test"}\n'
            path.write_text(good)
            client = Mock()
            client.http.return_value = "<html>temporarily unavailable</html>"
            entry = n.Feeds(client, directory, 0, refresh=True).load("spamhaus_drop_v4")
            self.assertEqual(path.read_text(), good)
            self.assertEqual(entry["entries"], 1)
            self.assertIn("HTML", entry["warning"])

    def test_bad_download_without_cache_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client.http.return_value = "<html>oops</html>"
            with self.assertRaises(n.UpstreamError):
                n.Feeds(client, directory, 0).load("tor_exits")
            self.assertFalse((Path(directory) / "tor_exits.txt").exists())

    def test_corrupt_cache_from_older_versions_is_refetched(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "tor_exits.txt").write_text("<html>old bug</html>")
            client = Mock()
            client.http.return_value = "1.1.1.1\n"
            entry = n.Feeds(client, directory, 86400).load("tor_exits")
            self.assertEqual((entry["source"], entry["data"]), ("download", {"1.1.1.1"}))

    def test_failures_are_remembered_and_downloads_happen_once(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client.http.side_effect = n.UpstreamError("down")
            feeds = n.Feeds(client, directory, 0)
            for _ in range(3):
                with self.assertRaises(n.UpstreamError):
                    feeds.load("tor_exits")
            self.assertEqual(client.http.call_count, 1)

    def test_concurrent_loads_share_one_download(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()

            def slow(url, **kwargs):
                time.sleep(0.2)
                return "1.1.1.1\n"

            client.http.side_effect = slow
            feeds = n.Feeds(client, directory, 0)
            threads = [threading.Thread(target=feeds.load, args=("tor_exits",)) for _ in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(client.http.call_count, 1)
            self.assertEqual((Path(directory) / "tor_exits.txt").read_text(), "1.1.1.1\n")

    def test_failed_feeds_are_unknown_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = failing_feeds(directory).check_ip("192.0.2.1")
            self.assertEqual([row["listed"] for row in rows], [None, None, None])
            self.assertTrue(all("error" in row for row in rows))

    def test_matching(self):
        with tempfile.TemporaryDirectory() as directory:
            feeds = clean_feeds(directory)
            self.assertEqual([row["listed"] for row in feeds.check_ip("198.51.100.9")], [True, False, False])
            self.assertEqual([row["listed"] for row in feeds.check_ip("203.0.113.66")], [False, True, False])
            self.assertEqual([row["listed"] for row in feeds.check_ip("203.0.113.77")], [False, False, True])
            self.assertEqual([row["listed"] for row in feeds.check_ip("2001:db8:dead::1")], [True, False, False])
            prefix_rows = feeds.check_prefix("198.51.0.0/16")
            self.assertEqual(prefix_rows[0]["detail"], ["198.51.100.0/24 (SBL1)"])
            self.assertEqual(feeds.check_prefix("203.0.113.0/24")[1]["detail"], ["1 address"])
            self.assertTrue(feeds.check_asn("AS64666")["listed"])
            self.assertFalse(feeds.check_asn("AS13335")["listed"])


class ClientTests(unittest.TestCase):
    def test_cname_ttl_and_txt_strings(self):
        answer = dns.message.make_response(dns.message.make_query("example.com", "TXT"))
        answer.answer = [dns.rrset.from_text("example.com.", 60, "IN", "CNAME", "www.example.com."),
                         dns.rrset.from_text("www.example.com.", 30, "IN", "TXT", '"v=spf1 " "-all"')]
        client = n.Client()
        client._resolver = Mock()
        client._resolver.resolve.return_value.response = answer
        records = client.dns("example.com", "TXT")["records"]
        self.assertEqual([(r["type"], r["ttl"]) for r in records], [("CNAME", 60), ("TXT", 30)])
        self.assertEqual(records[1]["value"], "v=spf1 -all")

    def test_nxdomain_distinguished_from_failure(self):
        client = n.Client()
        client._resolver = Mock()
        client._resolver.resolve.side_effect = dns.resolver.NXDOMAIN
        self.assertEqual(client.dns("example.invalid", "A")["status"], "NXDOMAIN")
        client._resolver.resolve.side_effect = dns.resolver.NoNameservers
        with self.assertRaises(n.UpstreamError):
            client.dns("example.com", "A")

    def test_resolver_construction(self):
        client = n.Client(resolver="1.1.1.1")
        client._build_resolver()
        self.assertEqual((client._transport, client._resolver.nameservers[0].hostname), ("tls", "cloudflare-dns.com"))
        self.assertTrue(client._resolver.flags & dns.flags.AD, "the AD bit must be requested")
        self.assertEqual(client._resolver.edns, -1, "EDNS stays off so intercepting proxies do not drop big answers")
        client = n.Client(transport="tcp")
        client._build_resolver()
        self.assertTrue(client._tcp)

    def error(self, url, code, body=b"{}"):
        return HTTPError(url, code, "error", {}, io.BytesIO(body))

    def test_rdap_404_meanings(self):
        client = n.Client()
        with patch.object(client, "fetch", side_effect=self.error("https://rdap.verisign.com/com/v1/domain/x.com", 404)):
            with self.assertRaises(n.NotFoundError):
                client.rdap("domain", "x.com")
        body = b'{"title": "No RDAP service is available for this resource"}'
        with patch.object(client, "fetch", side_effect=self.error("https://rdap.org/domain/x.de", 404, body)):
            with self.assertRaises(n.UpstreamError) as caught:
                client.rdap("domain", "x.de")
            self.assertNotIsInstance(caught.exception, n.NotFoundError)
            self.assertIn("No RDAP service", str(caught.exception))
        with patch.object(client, "fetch", side_effect=self.error("https://rdap.org/ip/1.1.1.1", 429)):
            with self.assertRaisesRegex(n.UpstreamError, "rate limited"):
                client.rdap("ip", "1.1.1.1")

    def test_truncated_http_body_is_an_upstream_error(self):
        with patch.object(n, "urlopen", side_effect=http.client.IncompleteRead(b"partial")):
            with self.assertRaises(n.UpstreamError):
                n.Client().http("https://example.com/feed", raw=True)

    def test_registration_walks_to_parent_and_reports_unregistered(self):
        client = FakeClient()

        def rdap(kind, value):
            if value == "example.com":
                return {"objectClassName": "domain", "ldhName": "EXAMPLE.COM", "events": [], "entities": []}
            raise n.NotFoundError(f"registry has no record of {value}")

        client.rdap = rdap
        found = n.domain_registration_lookup(client, "www.example.com")
        self.assertEqual((found["found"], found["queried_name"]), (True, "example.com"))
        self.assertFalse(n.domain_registration_lookup(client, "unregistered-name.com")["found"])
        client.rdap = Mock(side_effect=n.UpstreamError("rdap.org: No RDAP service is available"))
        with self.assertRaises(n.UpstreamError):
            n.domain_registration_lookup(client, "example.de")


class OutputTests(unittest.TestCase):
    def human(self, color=False, unicode=True):
        return n.HumanOutput("t", color=color, width=80, unicode=unicode)

    def capture(self, out, build):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            build(out)
            code = out.finish()
        return buffer.getvalue(), code

    def test_human_layout(self):
        def build(out):
            out.section("Registration", "registration", source="RDAP")
            out.kv("registrar", "Example Registrar")
            out.kv("nameservers", ["a.example", "b.example", "c.example"], limit=2)
            out.kv("skipped", None)
            out.status("zen", "Spamhaus ZEN", "good", "not listed")
            out.table(["PREFIX", "PEERS"], [["10.0.0.0/8", 1], ["10.1.0.0/16", 2], ["10.2.0.0/16", 3]], limit=2)
            out.section("Hidden", "hidden", grep_only=True)
            out.kv("secret", "only in grep")
            out.next_steps(["netintel a", "netintel b"])

        text, code = self.capture(self.human(), build)
        self.assertEqual(code, 0)
        self.assertIn("Registration  RDAP", text)
        self.assertIn("  registrar    Example Registrar", text)
        self.assertIn("a.example, b.example, … 1 more (--grep lists all)", text)
        self.assertNotIn("skipped", text)
        self.assertIn("✓ Spamhaus ZEN  not listed", text)
        self.assertIn("… 1 more (--grep lists all)", text.split("PREFIX")[1])
        self.assertNotIn("only in grep", text)
        self.assertIn("$ netintel a", text)
        self.assertNotIn("\x1b[", text)

    def test_failures_set_exit_code_and_footer(self):
        def build(out):
            out.section("A", "a")
            out.error("timed out")
            out.status("x", "Source", "error", "unknown", "down")

        text, code = self.capture(self.human(), build)
        self.assertEqual(code, 1)
        self.assertIn("✗ timed out", text)
        self.assertIn("? Source  unknown  down", text)
        self.assertIn("2 lookups failed; the results above are partial", text)

    def test_colour_and_ascii(self):
        text, _ = self.capture(self.human(color=True), lambda out: (out.section("S", "s"), out.status("k", "L", "bad", "listed")))
        self.assertIn("\x1b[1;36mS\x1b[0m", text)
        self.assertIn("\x1b[1;31mlisted\x1b[0m", text)
        text, _ = self.capture(self.human(unicode=False), lambda out: (out.section("S", "s"), out.status("k", "L", "good", "ok", "a · b")))
        self.assertIn("+ L  ok  a - b", text)

    def test_grep_lines(self):
        def build(out):
            out.header("t", "ignored")
            out.section("DNS", "dns")
            out.table(["TYPE", "VALUE"], [["A", "192.0.2.1"], ["TXT", "has\ttab and\nnewline"]])
            out.kv("name servers", ["a", "b"])
            out.status("zen", "Spamhaus ZEN", "good", "not listed")
            out.note("never printed")
            out.section("Observed", "observed", grep_only=True)
            out.kv("prefix", "10.0.0.0/8")
            out.error("boom")
            out.next_steps(["netintel x"])

        text, code = self.capture(n.GrepOutput("t"), build)
        self.assertEqual(code, 1)
        self.assertEqual(text.splitlines(), [
            "t\tdns\tA\t192.0.2.1",
            "t\tdns\tTXT\thas tab and newline",
            "t\tdns\tname-servers\ta",
            "t\tdns\tname-servers\tb",
            "t\tdns\tzen\tnot listed",
            "t\tobserved\tprefix\t10.0.0.0/8",
            "t\tobserved\terror\tboom",
            "t\tnext\tnetintel x",
        ])


class CommandTests(unittest.TestCase):
    def reputation_ip_args(self, ip="192.0.2.10"):
        return SimpleNamespace(target=ip, kind="ip", max_ips=16)

    def test_failed_shodan_is_unknown_not_zero_ports(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict("os.environ", {}, clear=True), \
                patch.object(n, "internetdb", side_effect=n.UpstreamError("timeout")), \
                patch.object(n, "ipapi", return_value={"proxy": False, "hosting": False, "mobile": False}), \
                patch.object(n, "robtex_ip", return_value={"names": []}), \
                patch("ipaddress.IPv4Address.is_global", new=True):
            text, code = render(n.cmd_reputation_ip, self.reputation_ip_args(), feeds=clean_feeds(directory))
        self.assertEqual(code, 1)
        self.assertIn("? Shodan InternetDB", text)
        self.assertNotIn("0 open ports", text)
        self.assertRegex(text, r"not checked\s+Shodan InternetDB")

    def test_all_feed_failures_make_the_report_partial(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict("os.environ", {}, clear=True), \
                patch.object(n, "internetdb", return_value={"found": False}), \
                patch.object(n, "ipapi", return_value={}), \
                patch.object(n, "robtex_ip", return_value={"names": []}), \
                patch("ipaddress.IPv4Address.is_global", new=True):
            text, code = render(n.cmd_reputation_ip, self.reputation_ip_args(), feeds=failing_feeds(directory))
        self.assertEqual(code, 1)
        for label in ("Spamhaus DROP", "Feodo Tracker C2", "Tor exit list"):
            self.assertRegex(text, rf"\? {label}\s+unknown")
        self.assertNotIn("✓ Spamhaus DROP", text)

    def test_clean_and_listed_summaries(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict("os.environ", {}, clear=True), \
                patch.object(n, "internetdb", return_value={"found": True, "ports": [443], "vulns": [], "cpes": [], "hostnames": [], "tags": []}), \
                patch.object(n, "ipapi", return_value={"hosting": True}), \
                patch.object(n, "robtex_ip", return_value={"names": ["a.example"]}), \
                patch("ipaddress.IPv4Address.is_global", new=True):
            feeds = clean_feeds(directory)
            text, code = render(n.cmd_reputation_ip, self.reputation_ip_args(), feeds=feeds)
            self.assertEqual(code, 0)
            self.assertIn("clean on all 4 checks that answered", text)
            self.assertIn("1 open port", text)
            client = FakeClient({("10.2.0.192.zen.spamhaus.org", "A"): [rec("x", "A", "127.0.0.2")]})
            text, code = render(n.cmd_reputation_ip, self.reputation_ip_args(), client=client, feeds=feeds)
            self.assertIn("✗ Spamhaus ZEN", text)
            self.assertIn("flagged by 1 of 4 checks that answered: Spamhaus ZEN", text)

    def test_filter_servfail_is_unknown_not_clean(self):
        servfail = {"blocked": None, "unfiltered": {"status": 0, "answers": ["192.0.2.1"]}, "filtered": {"status": 2, "answers": []}}
        clean = {"blocked": False, "unfiltered": {"status": 0, "answers": ["192.0.2.1"]}, "filtered": {"status": 0, "answers": ["192.0.2.1"]}}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(n, "cloudflare_filter", return_value=servfail), \
                patch.object(n, "quad9_filter", return_value=clean), \
                patch.object(n, "robtex_domain", return_value={"records": [
                    {"rrtype": "A", "rrdata": "192.0.2.1", "time_first": 1700000000, "time_last": 1790000000}]}):
            text, code = render(n.cmd_reputation_domain, SimpleNamespace(target="example.com", kind="domain", max_ips=16),
                                feeds=clean_feeds(directory))
        self.assertEqual(code, 1)
        self.assertRegex(text, r"\? Cloudflare filter\s+unknown")
        self.assertRegex(text, r"✓ Quad9 filter\s+not blocked")
        self.assertRegex(text, r"TYPE\s+FIRST SEEN\s+LAST SEEN\s+VALUE\n\s+A\s+2023-11-14\s+2026-09-21\s+192\.0\.2\.1")

    def test_routes_compare_and_withhold(self):
        client = FakeClient()
        replies = {"-F -i AS64500": "64500 192.0.2.0/24 42\n64500 198.51.100.0/24 3\n",
                   "!gAS64500": "A20\n192.0.2.0/24 203.0.113.0/24\nC\n", "!6AS64500": "D\n"}
        client.whois = lambda host, query: replies[query]
        text, code = render(n.cmd_routes, SimpleNamespace(target="AS64500"), client=client)
        self.assertEqual(code, 0)
        self.assertIn("In BGP without an exact IRR route object (1)", text)
        self.assertIn("198.51.100.0/24  3", text)
        self.assertIn("In IRR but not seen in BGP (1)", text)
        grep, _ = render(n.cmd_routes, SimpleNamespace(target="AS64500"), client=client, grep=True)
        self.assertIn("AS64500\tobserved\t192.0.2.0/24\t42", grep)
        self.assertIn("AS64500\tregistered\t203.0.113.0/24", grep)

        def flaky(host, query):
            if query == "!gAS64500":
                raise n.UpstreamError("timeout")
            return replies[query]

        client.whois = flaky
        text, code = render(n.cmd_routes, SimpleNamespace(target="AS64500"), client=client)
        self.assertEqual(code, 1)
        self.assertIn("Comparison withheld", text)
        self.assertNotIn("In IRR but not seen", text)

    def domain_args(self, name="example.com"):
        return SimpleNamespace(target=name, max_ips=16, quick=True)

    def test_domain_nxdomain_and_unregistered(self):
        client = FakeClient({("nope.example", kind): "NXDOMAIN" for kind in n.DNS_TYPES})
        client.rdap = Mock(side_effect=n.NotFoundError("registry has no record of nope.example"))
        client.http = Mock(return_value=[])
        text, _ = render(n.cmd_domain, self.domain_args("nope.example"), client=client)
        self.assertIn("NXDOMAIN: the name does not exist", text)
        self.assertIn("not registered", text)

    def test_domain_failed_lookups_are_unknown_not_empty(self):
        client = FakeClient(records={("example.com", "AAAA"): []},
                            dns_errors={("example.com", "A"): "timeout", ("example.com", "TXT"): "timeout"})
        client.http = Mock(return_value=[])
        text, code = render(n.cmd_domain, self.domain_args(), client=client)
        self.assertEqual(code, 1)
        self.assertIn("unknown: the A/AAAA lookup failed", text)
        self.assertIn("unknown: the TXT lookup failed", text)
        self.assertNotIn("none: the name has no A or AAAA records", text)
        self.assertNotIn("SPF           none published", text)

    def test_domain_report_sections(self):
        client = FakeClient({
            ("example.com", "A"): [rec("example.com", "A", "192.0.2.1")],
            ("example.com", "MX"): [rec("example.com", "MX", "0 .")],
            ("example.com", "TXT"): [rec("example.com", "TXT", "v=spf1 -all")],
            ("_dmarc.example.com", "TXT"): [rec("_dmarc.example.com", "TXT", "v=DMARC1; p=reject")],
            ("example.com", "SOA"): [rec("example.com", "SOA", "ns. host. 1 2 3 4 5")],
        })
        client.rdap = Mock(return_value={"objectClassName": "domain", "ldhName": "EXAMPLE.COM", "status": ["active"],
                                         "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
                                         "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Test Registrar"]]]}]})
        client.http = Mock(return_value=[{"dns_names": ["example.com", "www.example.com"], "not_before": "2026-01-01T00:00:00Z"}])
        text, code = render(n.cmd_domain, self.domain_args(), client=client)
        self.assertEqual(code, 0, text)
        for expected in ("0 .  (null MX: accepts no mail)", "192.0.2.1", "documentation address",
                         "fail: only the listed senders", "p=reject: reject failures", "Test Registrar",
                         "1995-08-14", "www.example.com", "not signed", "$ "):
            self.assertIn(expected, text)


def command_args(command, **extra):
    """Arguments as parse_args would produce them for each command."""
    target = {"domain": "example.com", "ip": "192.0.2.10", "asn": "AS64500", "prefix": "192.0.2.0/24",
              "routes": "AS64500", "reputation": "192.0.2.10", "rpki": "192.0.2.0/24", "ripestat": "AS64500",
              "abuse": "192.0.2.10", "neighbors": "AS64500", "ix": "AS64500", "as-set": "AS-EXAMPLE"}.get(command)
    kind = n.detect(target)[0] if command == "reputation" else None
    values = {"command": command, "target": target, "kind": kind, "asn": "AS64500", "quick": False, "max_ips": 16,
              "recursive": False, "net": True, "timeout": 5, "bulk_payload": "begin\r\nverbose\r\n192.0.2.1\r\nend\r\n"}
    values.update(extra)
    return SimpleNamespace(**values)


class EveryCommandTests(unittest.TestCase):
    """Guards against crashes in commands the focused tests do not reach."""

    commands = sorted(set(n.COMMANDS) - {"routeviews", "he"})

    def test_every_command_survives_total_upstream_failure(self):
        for command in self.commands:
            for kind_target in ((None,) if command != "reputation" else ("192.0.2.10", "example.com", "AS64500", "192.0.2.0/24")):
                extra = {"target": kind_target, "kind": n.detect(kind_target)[0]} if kind_target else {}
                with self.subTest(command=command, target=kind_target), tempfile.TemporaryDirectory() as directory, \
                        patch.object(n, "interception_probe", side_effect=n.UpstreamError("down")), \
                        patch.object(n, "tcp_probe", side_effect=n.UpstreamError("down")), \
                        patch.object(n, "dot_answer", side_effect=n.UpstreamError("down")), \
                        patch("ipaddress.IPv4Address.is_global", new=True):
                    client = FakeClient(dns_errors={})
                    client.dns = Mock(side_effect=n.UpstreamError("dns down"))
                    client.dns_values = Mock(side_effect=n.UpstreamError("dns down"))
                    client.tcp = Mock(side_effect=n.UpstreamError("tcp down"))
                    for grep in (False, True):
                        text, code = render(n.COMMANDS[command], command_args(command, **extra), client=client,
                                            feeds=failing_feeds(directory), grep=grep)
                        self.assertEqual(code, 1, f"{command} should report failure\n{text}")

    def test_every_command_renders_realistic_data(self):
        ripe = {
            "rpki-validation": {"status": "valid", "validating_roas": [{"origin": "64500", "prefix": "192.0.2.0/24",
                                                                        "max_length": 24, "validity": "valid"}]},
            "whois": {"authorities": ["ripe"], "records": [[{"key": "aut-num", "value": "AS64500"}, {"key": "as-name", "value": "EXAMPLE"}]],
                      "irr_records": [[{"key": "route", "value": "192.0.2.0/24"}]]},
            "abuse-contact-finder": {"abuse_contacts": ["abuse@example.net"], "authoritative_rir": "ripe"},
            "asn-neighbours": {"neighbours": [{"type": "left", "asn": 64501, "power": 9, "v4_peers": 3, "v6_peers": 1},
                                              {"type": "right", "asn": 64502, "power": 2, "v4_peers": 1, "v6_peers": 0}]},
            "looking-glass": {"rrcs": [{"rrc": "RRC00", "peers": [{"as_path": "64501 64500", "prefix": "192.0.2.0/24"}]}]},
            "network-info": {"prefix": "192.0.2.0/24", "asns": ["64500"]},
        }
        net = {"name": "Example Net", "asn": 64500, "irr_as_set": "AS-EXAMPLE", "info_types": ["NSP"], "ix_count": 1, "fac_count": 2,
               "netixlan_set": [{"name": "Example IX", "ipaddr4": "198.51.100.1", "ipaddr6": None, "speed": 10000, "is_rs_peer": True}]}
        rdap = {"objectClassName": "ip network", "name": "EXAMPLE-NET", "handle": "NET-192-0-2-0-1",
                "startAddress": "192.0.2.0", "endAddress": "192.0.2.255", "port43": "whois.example.net",
                "entities": [{"handle": "EX1", "roles": ["technical", "administrative"],
                              "vcardArray": ["vcard", [["fn", {}, "text", "Example Ops"], ["email", {}, "text", "ops@example.net"]]]}],
                "links": [{"rel": "self", "href": "https://rdap.example.net/ip/192.0.2.0"}]}
        whois = {"riswhois.ripe.net": "% banner\n\n64500\t192.0.2.0/24\t40\n", "whois.radb.net": "A12\n192.0.2.0/24\nC\n",
                 "whois.cymru.com": "AS | IP\n64500 | 192.0.2.10\n", "bgp.tools": "AS | IP\n64500 | 192.0.2.10\n"}
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict("os.environ", {}, clear=True), \
                patch.object(n, "interception_probe", return_value={"state": "direct", "verdict": "Direct: ok"}), \
                patch.object(n, "tcp_probe", return_value="reachable"), \
                patch.object(n, "internetdb", return_value={"found": False}), \
                patch.object(n, "ipapi", return_value={"hosting": True, "as": "AS64500 Example"}), \
                patch.object(n, "robtex_ip", return_value={"names": []}), \
                patch.object(n, "robtex_domain", return_value={"records": []}), \
                patch.object(n, "cloudflare_filter", return_value={"blocked": False, "filtered": {}, "unfiltered": {}}), \
                patch.object(n, "quad9_filter", return_value={"blocked": False, "filtered": {}, "unfiltered": {}}), \
                patch("ipaddress.IPv4Address.is_global", new=True):
            client = FakeClient({("example.com", "A"): [rec("example.com", "A", "192.0.2.10")],
                                 ("example.com", "SOA"): [rec("example.com", "SOA", "ns. host. 1 2 3 4 5")],
                                 ("10.2.0.192.in-addr.arpa", "PTR"): [rec("10.2.0.192.in-addr.arpa", "PTR", "host.example.")],
                                 ("1.1.1.1.origin.asn.cymru.com", "TXT"): [rec("x", "TXT", "13335 | 1.1.1.0/24 | AU | apnic | 2011")]})
            client.ripe = lambda call, **params: ripe[call]
            client.network = lambda ip: {"ip": ip, "prefix": "192.0.2.0/24", "asns": ["AS64500"]}
            client.peering = lambda value, depth=0: [net]
            client.rdap = lambda kind, value: rdap if kind != "domain" else {"objectClassName": "domain", "ldhName": "EXAMPLE.COM"}
            client.whois = lambda host, query: whois[host]
            client.tcp = lambda host, payload: "64500 | 192.0.2.1 | EXAMPLE\n"
            client.http = Mock(return_value=[])
            client.doh_json = Mock(return_value={"status": 0, "answers": ["93.184.215.14"], "comment": [], "ede": []})
            for command in self.commands:
                for grep in (False, True):
                    with self.subTest(command=command, grep=grep):
                        text, code = render(n.COMMANDS[command], command_args(command), client=client,
                                            feeds=clean_feeds(directory), grep=grep)
                        self.assertEqual(code, 0, f"{command} reported a failure\n{text}")
                        self.assertTrue(text.strip(), f"{command} printed nothing")
                        if grep:
                            self.assertNotIn("\x1b[", text)
                            self.assertTrue(all("\t" in line for line in text.splitlines()) or command in {"as-set", "bulk-bgp", "bulk-cymru", "ris-peers"})


class SecondReviewRegressions(unittest.TestCase):
    """Issues from the second external review of 1.2.0, and the same class of problem elsewhere."""

    def grep_lines(self, build, target="t"):
        out = n.GrepOutput(target)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            build(out)
            code = out.finish()
        return buffer.getvalue(), code

    def stale_row(self, listed):
        return {"key": "spamhaus-drop", "label": "Spamhaus DROP", "listed": listed,
                "detail": ["192.0.2.0/24 (SBL1)"] if listed else [],
                "feed": {"entries": 1, "fetched": n.parse_time("2026-01-01T00:00:00Z"), "warning": "refresh failed: timeout"}}

    def test_spf_version_token_must_match_exactly(self):
        self.assertTrue(n.spf_summary(["v=spf1 -all", "v=spf10 -all"])["valid"])
        self.assertFalse(n.spf_summary(["v=spf10 -all"])["present"])
        self.assertTrue(n.spf_summary(["V=SPF1 -all"])["present"])
        self.assertTrue(n.spf_summary(["v=spf1"])["present"])
        self.assertFalse(n.is_dmarc_record("v=DMARC10; p=none"))
        self.assertTrue(n.is_dmarc_record("v=DMARC1;p=none"))
        self.assertTrue(n.is_dmarc_record("V=DMARC1 ; p=none"))

    def test_inherited_dmarc_uses_sp(self):
        record = {("_dmarc.example.com", "TXT"): [rec("_dmarc.example.com", "TXT", "v=DMARC1; p=reject; sp=none")]}
        inherited = n.email_auth_summary(FakeClient(record), "sub.example.com", [])["dmarc"]
        direct = n.email_auth_summary(FakeClient(record), "example.com", [])["dmarc"]
        self.assertEqual((inherited["policy"], inherited["policy_tag"]), ("none", "sp"))
        self.assertEqual((direct["policy"], direct["policy_tag"]), ("reject", "p"))
        no_sp = {("_dmarc.example.com", "TXT"): [rec("_dmarc.example.com", "TXT", "v=DMARC1; p=quarantine")]}
        self.assertEqual(n.email_auth_summary(FakeClient(no_sp), "a.b.example.com", [])["dmarc"]["policy"], "quarantine")
        text, _ = self.grep_lines(lambda out: n.show_email(out, n.Result({"spf": n.spf_summary([]), "dmarc": inherited})))
        self.assertIn("sp=none: monitor only", text)
        self.assertIn("inherited", text)

    def connection(self, recv, send_error=None):
        conn = Mock()
        conn.__enter__ = Mock(return_value=conn)
        conn.__exit__ = Mock(return_value=False)
        conn.recv.side_effect = recv
        if send_error:
            conn.sendall.side_effect = send_error
        return conn

    def test_bulk_send_failure_is_an_error(self):
        with patch("socket.create_connection", return_value=self.connection([b"partial\r\n", b""], OSError("reset"))):
            with self.assertRaisesRegex(n.UpstreamError, "reply is incomplete"):
                n.Client().tcp("whois.example", "begin\r\n1.1.1.1\r\nend\r\n")
        with patch("socket.create_connection", return_value=self.connection([b"first ", b"second\r\n", b""])):
            self.assertEqual(n.Client().tcp("whois.example", "q\r\n"), "first second\r\n")

    def test_robtex_rejects_unrecognised_replies(self):
        client = Mock()
        for body in ("<html>Service temporarily unavailable</html>", "Too many requests", '{"status": "ratelimited"}',
                     '{"rrtype":"A","rrdata":"192.0.2.1"}\nnot json\nnot json either\n'):
            client.http.return_value = body
            with self.subTest(body=body[:20]), self.assertRaises(n.UpstreamError):
                n.robtex_domain(client, "example.com")
        for body, count in (("[]", 0), ("", 0), ('{"rrtype":"A","rrdata":"192.0.2.1","time_first":1}\n', 1),
                            ("".join(f'{{"rrtype":"A","rrdata":"192.0.2.{i}"}}\n' for i in range(150)) + '{"rrty', 150)):
            client.http.return_value = body
            with self.subTest(body=body[:20]):
                self.assertEqual(len(n.robtex_domain(client, "example.com")["records"]), count)

    def test_stale_feed_copies_are_always_disclosed(self):
        text, _ = self.grep_lines(lambda out: n.feed_row(out, self.stale_row(listed=True)))
        self.assertIn("stale copy: refresh failed: timeout", text)
        asn_result = n.Result({"listed": True, "detail": {"asname": "BAD"}, "feed": self.stale_row(True)["feed"]})
        text, _ = self.grep_lines(lambda out: n.asn_drop_row(out, asn_result))
        self.assertIn("stale copy", text)
        clean = {"blocked": False, "unfiltered": {"status": 0, "answers": ["192.0.2.1"]}, "filtered": {"status": 0, "answers": ["192.0.2.1"]}}
        feeds = Mock()
        feeds.check_ip.return_value = [self.stale_row(listed=False)]
        client = FakeClient({("example.com", "A"): [rec("example.com", "A", "192.0.2.1")]})
        with patch.object(n, "cloudflare_filter", return_value=clean), patch.object(n, "quad9_filter", return_value=clean), \
                patch.object(n, "robtex_domain", return_value={"records": []}):
            text, _ = render(n.cmd_reputation_domain, SimpleNamespace(target="example.com", max_ips=16), client=client, feeds=feeds)
        self.assertRegex(text, r"! 192\.0\.2\.1\s+no feed matches\s+stale copy of Spamhaus DROP")

    def test_grep_lists_every_shodan_port(self):
        feeds = Mock()
        feeds.check_ip.return_value = []
        ports = list(range(1, 41))
        with patch.dict("os.environ", {}, clear=True), \
                patch.object(n, "internetdb", return_value={"found": True, "ports": ports, "vulns": [], "cpes": [], "hostnames": [], "tags": []}), \
                patch.object(n, "ipapi", return_value={}), patch.object(n, "robtex_ip", return_value={"names": []}), \
                patch("ipaddress.IPv4Address.is_global", new=True):
            grep, _ = render(n.cmd_reputation_ip, SimpleNamespace(target="192.0.2.10"), feeds=feeds, grep=True)
            human, _ = render(n.cmd_reputation_ip, SimpleNamespace(target="192.0.2.10"), feeds=feeds)
        self.assertEqual(sorted(int(line.split("\t")[3]) for line in grep.splitlines() if "\tshodan\tports\t" in line), ports)
        self.assertIn("… 8 more (--grep lists all)", human)

    def test_replies_missing_fields_are_errors_not_empty_answers(self):
        client = FakeClient()
        client.ripe = lambda call, **params: {}
        for command, args, absent in ((n.cmd_rpki, SimpleNamespace(target="192.0.2.0/24", asn="AS64500"), "not found"),
                                      (n.cmd_abuse, SimpleNamespace(target="192.0.2.1"), "none published"),
                                      (n.cmd_neighbors, SimpleNamespace(target="AS64500"), "0 neighbors"),
                                      (n.cmd_prefix, SimpleNamespace(target="192.0.2.0/24", quick=True), "not seen by any")):
            with self.subTest(command=command.__name__):
                text, code = render(command, args, client=client)
                self.assertEqual(code, 1, text)
                self.assertIn("the response lacks", text)
                self.assertNotIn(absent, text)
        real = n.Client()
        with patch.object(real, "ripe", return_value={"asns": []}), self.assertRaises(n.UpstreamError):
            real.network("192.0.2.1")
        with patch.object(real, "ripe", return_value={"asns": [], "prefix": ""}):
            self.assertEqual(real.network("192.0.2.1")["prefix"], None)
        http = Mock(return_value={"errors": [{"detail": "bad key"}]})
        with self.assertRaises(n.UpstreamError):
            n.abuseipdb(SimpleNamespace(http=http), "192.0.2.1", "key")
        http.return_value = {"message": "unexpected"}
        with self.assertRaises(n.UpstreamError):
            n.greynoise(SimpleNamespace(http=http), "192.0.2.1", "key")


class ThirdReviewRegressions(unittest.TestCase):
    """Issues from the third external review of 1.2.1, and the same class of problem elsewhere."""

    def tls_context(self, resolver):
        client = n.Client(resolver=resolver)
        client._build_resolver()
        query = dns.message.make_query("example.com", "A")
        with patch("dns.query.make_ssl_socket", side_effect=RuntimeError("stop before network")) as factory:
            with self.assertRaisesRegex(RuntimeError, "stop before network"):
                client._resolver.nameservers[0].query(query, timeout=1, source=None, source_port=0)
        return client, factory.call_args.kwargs["ssl_context"], factory.call_args.kwargs.get("server_hostname")

    def test_shodan_replies_are_validated(self):
        client = Mock()
        for body in ({"error": "temporarily unavailable"}, {"ip": "192.0.2.1", "ports": 443},
                     {"ip": "192.0.2.1", "ports": [443], "vulns": "CVE-1"}, {"ip": "192.0.2.1", "ports": ["443"]}):
            client.http.return_value = body
            with self.subTest(body=body):
                self.assertFalse(n.attempt(n.internetdb, client, "192.0.2.1").ok)
        client.http.return_value = {"ip": "192.0.2.1", "ports": [443], "vulns": [], "cpes": [], "hostnames": [], "tags": []}
        self.assertEqual(n.internetdb(client, "192.0.2.1")["ports"], [443])

    def test_malformed_shodan_reply_fails_its_section_only(self):
        client = FakeClient()
        client.http = Mock(return_value={"ip": "192.0.2.10", "ports": 443, "vulns": []})
        feeds = Mock()
        feeds.check_ip.return_value = []
        with patch.dict("os.environ", {}, clear=True), patch.object(n, "ipapi", return_value={}), \
                patch.object(n, "robtex_ip", return_value={"names": []}), patch("ipaddress.IPv4Address.is_global", new=True):
            text, code = render(n.cmd_reputation_ip, SimpleNamespace(target="192.0.2.10"), client=client, feeds=feeds)
        self.assertEqual(code, 1)
        self.assertRegex(text, r"\? Shodan InternetDB\s+unknown\s+Shodan InternetDB: ports is int")
        self.assertIn("Summary", text, "the rest of the report must still render")

    def test_every_command_survives_wrong_typed_replies(self):
        wrong = {"status": 5, "validating_roas": "x", "abuse_contacts": "a@b", "authoritative_rir": 5, "neighbours": [1],
                 "records": "x", "irr_records": [["x"]], "authorities": [5], "rrcs": 5, "prefix": 5, "asns": 5}
        client = FakeClient()
        client.ripe = lambda call, **params: dict(wrong)
        client.network = Mock(side_effect=n.UpstreamError("bad"))
        client.peering = lambda value, depth=0: n.Client.peering(SimpleNamespace(http=lambda *a, **k: {"data": [1]}), value, depth)
        client.rdap = lambda kind, value: {"objectClassName": "x", "entities": [{"roles": "tech", "handle": 5}], "status": 7,
                                           "events": "x", "nameservers": [{"ldhName": 5}], "name": 9}
        client.http = Mock(return_value={"unexpected": True, "data": "x", "noise": 1, "riot": 1, "classification": 5})
        client.doh_json = Mock(return_value={"status": 0, "answers": [5], "comment": [], "ede": []})
        client.whois = lambda host, query: "weird\treply\n"
        client.tcp = lambda host, payload: "weird\n"
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "k", "GREYNOISE_API_KEY": "k"}), \
                patch.object(n, "interception_probe", return_value={"state": 5, "verdict": 7}), \
                patch.object(n, "tcp_probe", return_value="reachable"), \
                patch.object(n, "dot_answer", return_value={"status": "x", "answers": [None], "comment": [], "ede": []}), \
                patch("ipaddress.IPv4Address.is_global", new=True):
            for command in EveryCommandTests.commands:
                targets = ("192.0.2.10", "example.com", "AS64500", "192.0.2.0/24") if command == "reputation" else (None,)
                for target in targets:
                    extra = {"target": target, "kind": n.detect(target)[0]} if target else {}
                    for grep in (False, True):
                        with self.subTest(command=command, target=target, grep=grep):
                            try:
                                _text, code = render(n.COMMANDS[command], command_args(command, **extra), client=client,
                                                    feeds=clean_feeds(directory), grep=grep)
                            except Exception as exc:
                                self.fail(f"{command} crashed on wrong-typed replies: {type(exc).__name__}: {exc}")
                            self.assertIn(code, (0, 1))

    def test_internal_errors_become_a_failed_lookup_not_a_traceback(self):
        def broken(ctx):
            ctx.out.section("Partial", "partial")
            ctx.out.kv("shown", "yes")
            raise TypeError("renderer bug")

        stdout = io.StringIO()
        with patch.dict(n.COMMANDS, {"asn": broken}), patch.dict("os.environ", {}, clear=True), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = n.main(["--color", "never", "asn", "64500"])
        self.assertEqual(code, 1)
        self.assertIn("shown  yes", stdout.getvalue())
        self.assertIn("internal error while building the report: TypeError: renderer bug", stdout.getvalue())
        with patch.dict(n.COMMANDS, {"asn": broken}), patch.dict("os.environ", {"NETINTEL_DEBUG": "1"}), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(TypeError):
            n.main(["asn", "64500"])

    def test_spf_redirect_is_followed_not_called_neutral(self):
        summary = n.spf_summary(["v=spf1 redirect=_spf.example.com"])
        self.assertEqual(summary["redirect"], "_spf.example.com")
        self.assertNotIn("implicit neutral", summary["all_meaning"])
        both = n.spf_summary(["v=spf1 -all redirect=_spf.example.com"])
        self.assertEqual((both["redirect"], both["redirect_ignored"]), (None, True))
        self.assertIn("implicit neutral", n.spf_summary(["v=spf1 ip4:192.0.2.1"])["all_meaning"])
        records = {("_spf.example.com", "TXT"): [rec("_spf.example.com", "TXT", "v=spf1 redirect=_spf2.example.com")],
                   ("_spf2.example.com", "TXT"): [rec("_spf2.example.com", "TXT", "v=spf1 ip4:192.0.2.0/24 -all")]}
        spf = n.email_auth_summary(FakeClient(records), "example.com", ["v=spf1 redirect=_spf.example.com"])["spf"]
        self.assertEqual((spf["redirect_chain"], spf["effective_all"]), (["_spf.example.com", "_spf2.example.com"], "-all"))
        loop = {("_spf.example.com", "TXT"): [rec("_spf.example.com", "TXT", "v=spf1 redirect=example.com")]}
        self.assertIn("loop", n.email_auth_summary(FakeClient(loop), "example.com", ["v=spf1 redirect=_spf.example.com"])["spf"]["redirect_problem"])
        empty = n.email_auth_summary(FakeClient(), "example.com", ["v=spf1 redirect=_spf.example.com"])["spf"]
        self.assertIn("no single valid SPF record", empty["redirect_problem"])
        macro = n.email_auth_summary(FakeClient(), "example.com", ["v=spf1 redirect=%{d}._spf.example.com"])["spf"]
        self.assertIn("macros", macro["redirect_problem"])
        failing = FakeClient(dns_errors={("_spf.example.com", "TXT"): "timeout"})
        spf = n.email_auth_summary(failing, "example.com", ["v=spf1 redirect=_spf.example.com"])["spf"]
        self.assertIn("timeout", spf["redirect_error"])

    def test_spf_redirect_rendering(self):
        records = {("_spf.example.com", "TXT"): [rec("_spf.example.com", "TXT", "v=spf1 ip4:192.0.2.0/24 -all")]}
        cases = ((FakeClient(records), "fail: only the listed senders (via redirect to _spf.example.com)", 0),
                 (FakeClient(dns_errors={("_spf.example.com", "TXT"): "timeout"}), "redirected to _spf.example.com; not evaluated", 1),
                 (FakeClient(), "redirected to _spf.example.com: _spf.example.com has no single valid SPF record", 0))
        for client, expected, failures in cases:
            summary = n.email_auth_summary(client, "example.com", ["v=spf1 redirect=_spf.example.com"])
            out = n.GrepOutput("example.com")
            buffer = io.StringIO()
            with self.subTest(expected=expected), contextlib.redirect_stdout(buffer):
                n.show_email(out, n.Result(summary))
                self.assertEqual(out.finish(), failures)
            self.assertIn(expected, buffer.getvalue())

    def test_dns_over_tls_always_checks_an_identity(self):
        for spec, identity in (("203.0.113.53", "203.0.113.53"), ("203.0.113.53#dns.example.net", "dns.example.net"),
                               ("1.1.1.1", "cloudflare-dns.com"), ("9.9.9.10", "dns10.quad9.net")):
            with self.subTest(spec=spec):
                client, context, server_hostname = self.tls_context(spec)
                self.assertTrue(context.check_hostname)
                self.assertEqual((client._tls_identity, server_hostname), (identity, identity))
        self.assertEqual(n.resolver_spec("203.0.113.53#DNS.Example.NET"), "203.0.113.53#dns.example.net")
        for bad, message in (("203.0.113.53#", "host name after"), ("#dns.example.net", "IP address before"),
                             ("dns.example.net#dns.example.net", "IP address before"), ("203.0.113.53#not a name", "host name after")):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, message):
                n.resolver_spec(bad)
        args, _ = n.parse_args(["--resolver", "203.0.113.53#dns.example.net", "example.com"])
        self.assertEqual(args.resolver, "203.0.113.53#dns.example.net")

    def test_certificate_failures_are_named_not_called_servfail(self):
        client = n.Client(resolver="203.0.113.53")
        client._build_resolver()
        failure = ssl.SSLCertVerificationError(1, "certificate verify failed: IP address mismatch")
        error = dns.resolver.NoNameservers(request=dns.message.make_query("example.com", "A"),
                                           errors=[("DoT:203.0.113.53@853", True, 853, failure, None)])
        client._resolver = Mock()
        client._resolver.resolve.side_effect = error
        with self.assertRaises(n.UpstreamError) as caught:
            client.dns("example.com", "A")
        self.assertIn("TLS certificate check for 203.0.113.53 failed", str(caught.exception))
        self.assertIn("ADDRESS#NAME", str(caught.exception))
        self.assertNotIn("SERVFAIL", str(caught.exception))


class FourthReviewRegressions(unittest.TestCase):
    """Issues from the fourth external review of 1.2.2, and the same class of problem elsewhere."""

    def email_text(self, summary):
        out = n.GrepOutput("example.com")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            n.show_email(out, n.Result(summary))
            code = out.finish()
        return buffer.getvalue(), code

    def test_spf_grammar(self):
        for record in ("v=spf1 all", "v=spf1 +all", "v=spf1 -all", "v=spf1 ~all", "v=spf1 ?all", "v=spf1 a mx -all",
                       "v=spf1 a:mail.example.com/24 mx/24 ptr ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.com ~all",
                       "v=spf1 exists:%{i}.spf.example.com redirect=_spf.example.com", "v=spf1 exp=explain.example.com -all",
                       "v=spf1 unknown-modifier=value -all", "V=SPF1 IP4:192.0.2.1 -ALL"):
            with self.subTest(record=record):
                self.assertTrue(n.spf_summary([record])["valid"])
        for record, reason in (("v=spf1 --all", "not an SPF mechanism"), ("v=spf1 all:x", "takes no argument"),
                               ("v=spf1 include -all", "needs a domain"), ("v=spf1 ip4:2001:db8::1 -all", "IPv6 address"),
                               ("v=spf1 ip6:192.0.2.1 -all", "IPv4 address"), ("v=spf1 ip4:999.1.1.1 -all", "valid IPv4"),
                               ("v=spf1 foo -all", "not an SPF mechanism"), ("v=spf1 ax -all", "not an SPF mechanism"),
                               ("v=spf1 redirect=a redirect=b", "appears 2 times"), ("v=spf1 redirect=", "has no domain")):
            with self.subTest(record=record):
                summary = n.spf_summary([record])
                self.assertFalse(summary["valid"])
                self.assertIn(reason, summary["note"])

    def test_malformed_spf_is_reported_and_the_report_continues(self):
        summary = n.email_auth_summary(FakeClient(), "example.com", ["v=spf1 --all"])
        text, _ = self.email_text(summary)
        self.assertIn("spf-policy\tinvalid: permanent error", text)
        client = FakeClient({("example.com", "TXT"): [rec("example.com", "TXT", "v=spf1 --all")]})
        client.rdap = Mock(side_effect=n.NotFoundError("no record"))
        client.http = Mock(return_value=[])
        text, _ = render(n.cmd_domain, SimpleNamespace(target="example.com", max_ips=16, quick=True), client=client, grep=True)
        self.assertNotIn("internal error", text)
        for section in ("\temail\t", "\tregistration\t", "\tct\t"):
            self.assertIn(section, text)

    def test_a_crashing_section_does_not_hide_later_sections(self):
        client = FakeClient({("example.com", "A"): [rec("example.com", "A", "192.0.2.1")]})
        client.rdap = Mock(side_effect=n.NotFoundError("no record"))
        client.http = Mock(return_value=[])
        broken = {"spf": {"present": True, "valid": True, "record": "v=spf1", "all": None, "all_meaning": None,
                          "dns_lookup_terms": 0}, "dmarc": {"present": False}}
        with patch.dict("os.environ", {}, clear=True), patch.object(n, "email_auth_summary", return_value=broken):
            text, code = render(n.cmd_domain, SimpleNamespace(target="example.com", max_ips=16, quick=True), client=client)
        self.assertEqual(code, 1)
        self.assertIn("internal error while rendering email: TypeError", text)
        self.assertIn("Registration", text)
        self.assertIn("Certificate transparency", text)
        self.assertIn("Next steps", text)

    def test_duplicate_dmarc_records_are_discarded(self):
        both = [rec("_dmarc.example.com", "TXT", "v=DMARC1; p=reject"), rec("_dmarc.example.com", "TXT", "v=DMARC1; p=none")]
        summary = n.email_auth_summary(FakeClient({("_dmarc.example.com", "TXT"): both}), "example.com", [])
        self.assertFalse(summary["dmarc"]["present"])
        text, _ = self.email_text(summary)
        self.assertNotIn("reject failures", text)
        self.assertIn("dmarc-problem\t_dmarc.example.com (2 records) were all discarded", text)
        self.assertIn("dmarc\tnone in effect", text)
        records = {("_dmarc.mail.example.com", "TXT"): [rec("x", "TXT", "v=DMARC1; p=reject"), rec("x", "TXT", "v=DMARC1; p=none")],
                   ("_dmarc.example.com", "TXT"): [rec("_dmarc.example.com", "TXT", "v=DMARC1; p=quarantine; sp=reject")]}
        summary = n.email_auth_summary(FakeClient(records), "mail.example.com", [])
        self.assertEqual((summary["dmarc"]["policy"], summary["dmarc"]["found_at"]), ("reject", "_dmarc.example.com"))
        text, _ = self.email_text(summary)
        self.assertIn("dmarc-problem\t_dmarc.mail.example.com (2 records) were all discarded", text)
        self.assertIn("dmarc\tsp=reject: reject failures", text)

    def test_missing_or_invalid_dmarc_policy(self):
        with_rua = n.dmarc_summary("v=DMARC1; p=rejekt; rua=mailto:r@example.com")
        self.assertEqual((with_rua["valid"], with_rua["policy"]), (True, "none"))
        without = n.dmarc_summary("v=DMARC1; rua=")
        self.assertEqual((without["valid"], without["policy"]), (False, None))
        self.assertEqual(n.dmarc_summary("v=DMARC1; p=REJECT")["policy"], "reject")
        self.assertEqual(n.dmarc_summary("v=DMARC1; p=reject; sp=bogus", inherited=True)["valid"], False)
        text, _ = self.email_text({"spf": n.spf_summary([]), "dmarc": {**without, "found_at": "_dmarc.example.com"}})
        self.assertIn("dmarc\tno effective policy: p= is missing or invalid and there is no valid rua=", text)
        text, _ = self.email_text({"spf": n.spf_summary([]), "dmarc": {**with_rua, "found_at": "_dmarc.example.com"}})
        self.assertIn("dmarc-problem\tp= is missing or invalid, so receivers treat the record as p=none", text)
        self.assertIn("dmarc\tp=none: monitor only", text)


class FifthReviewRegressions(unittest.TestCase):
    """Issues from the fifth external review of 1.2.3 and the refactors it suggested."""

    def email_text(self, record, name="example.com"):
        client = FakeClient({("_dmarc.example.com", "TXT"): [rec("_dmarc.example.com", "TXT", record)]})
        summary = n.email_auth_summary(client, name, [])
        out = n.GrepOutput(name)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            n.show_email(out, n.Result(summary))
            out.finish()
        return summary["dmarc"], buffer.getvalue()

    def test_dmarc_record_is_validated_as_a_whole(self):
        dmarc, text = self.email_text("v=DMARC1; p=typo; sp=reject", name="mail.example.com")
        self.assertEqual((dmarc["valid"], dmarc["policy"]), (False, None))
        self.assertIn("no effective policy: p= is missing or invalid", text)
        dmarc, text = self.email_text("v=DMARC1; p=reject; sp=typo; rua=mailto:r@example.com")
        self.assertEqual((dmarc["policy"], dmarc["policy_tag"]), ("none", "p"))
        self.assertIn("dmarc-problem\tsp= is missing or invalid, so receivers treat the record as p=none", text)
        self.assertNotIn("reject failures", text)
        dmarc, _ = self.email_text("v=DMARC1; p=reject; np=maybe")
        self.assertFalse(dmarc["valid"])
        self.assertIn("np=", dmarc["problem"])
        dmarc, _ = self.email_text("v=DMARC1; p=bad; sp=worse")
        self.assertIn("p= and sp= are missing or invalid", dmarc["problem"])
        for record, policy in (("v=DMARC1; p=none; sp=reject", "reject"), ("v=DMARC1; p=quarantine", "quarantine"),
                               ("v=DMARC1; p=reject; sp=none; np=reject", "none")):
            with self.subTest(record=record):
                self.assertEqual(self.email_text(record, name="mail.example.com")[0]["policy"], policy)
        self.assertEqual(self.email_text("v=DMARC1; p=none; sp=reject")[0]["policy"], "none")

    def test_only_valid_report_addresses_rescue_an_invalid_policy(self):
        self.assertEqual(n.dmarc_report_uris("mailto:a@example.com!10m, mailto:b@example.net"),
                         ["mailto:a@example.com!10m", "mailto:b@example.net"])
        for rua in ("", "mailto:", "mailto:nobody", "https://example.com/report", "a@example.com"):
            with self.subTest(rua=rua):
                self.assertFalse(n.dmarc_summary(f"v=DMARC1; p=typo; rua={rua}")["valid"])
        self.assertTrue(n.dmarc_summary("v=DMARC1; p=typo; rua=https://x, mailto:r@example.com")["valid"])

    def test_looking_glass_keeps_every_path_and_upstream(self):
        target = "192.0.2.0/24"
        client = FakeClient()
        client.ripe = lambda call, **params: {"rrcs": [{"peers": [{"prefix": target, "as_path": f"{64500 + i} 64496"}
                                                                  for i in range(12)]}]}
        args = SimpleNamespace(target=target, quick=True)
        grep, _ = render(n.cmd_prefix, args, client=client, grep=True)
        self.assertEqual(sum("\tlooking-glass\tupstreams\t" in line for line in grep.splitlines()), 12)
        self.assertEqual(sum("\tlooking-glass\t1\t" in line for line in grep.splitlines()), 12)
        human, _ = render(n.cmd_prefix, args, client=client)
        self.assertIn("… 2 more (--grep lists all)", human)
        self.assertIn("… 7 more (--grep lists all)", human)

    def test_spf_terms_are_parsed_once(self):
        terms = n.parse_spf_terms("v=spf1 -include:_spf.example.com ip4:192.0.2.0/24 redirect=other.example ~ALL x=y !bad")
        self.assertEqual([t["kind"] for t in terms], ["mechanism", "mechanism", "modifier", "mechanism", "modifier", "invalid"])
        self.assertEqual((terms[0]["qualifier"], terms[0]["name"], terms[0]["argument"]), ("-", "include", ":_spf.example.com"))
        self.assertEqual((terms[3]["qualifier"], terms[3]["name"]), ("~", "all"))
        summary = n.spf_summary(["v=spf1 include:a.example -include:b.example mx a:c.example ptr exists:d.example ~all redirect=e.example"])
        self.assertEqual((summary["dns_lookup_terms"], summary["redirect"], summary["redirect_ignored"]), (6, None, True))
        self.assertEqual(summary["includes"], ["a.example", "b.example"])
        self.assertEqual((summary["all"], summary["all_qualifier"]), ("~all", "~"))
        self.assertEqual(n.spf_summary(["v=spf1 redirect=e.example"])["dns_lookup_terms"], 1)
        self.assertEqual(n.spf_summary(["v=spf1 all"])["all_meaning"], "pass for everyone: no protection")

    def test_a_crashing_reputation_row_does_not_hide_the_rest(self):
        feeds = Mock()
        feeds.check_ip.return_value = []
        with patch.dict("os.environ", {}, clear=True), \
                patch.object(n, "internetdb", return_value={"found": True, "ports": None, "vulns": [], "cpes": [], "hostnames": [], "tags": []}), \
                patch.object(n, "ipapi", return_value={"hosting": True}), \
                patch.object(n, "robtex_ip", return_value={"names": ["a.example"]}), \
                patch("ipaddress.IPv4Address.is_global", new=True):
            text, code = render(n.cmd_reputation_ip, SimpleNamespace(target="192.0.2.10"), feeds=feeds)
        self.assertEqual(code, 1)
        self.assertIn("internal error while rendering shodan row: TypeError", text)
        self.assertIn("Robtex passive DNS", text)
        self.assertRegex(text, r"not checked\s+Shodan InternetDB")
        self.assertIn("datacenter address", text)
        self.assertIn("Next steps", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
