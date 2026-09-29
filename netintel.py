#!/usr/bin/env python3
"""Internet routing, registration and reputation lookups for the terminal."""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import functools
import http.client
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import sys
import textwrap
import threading
import time
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

VERSION = "1.2.4"
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")
DNS_ORDER = {kind: index for index, kind in enumerate(("CNAME", "A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"))}
WHOIS_HOSTS = ("whois.cymru.com", "bgp.tools", "riswhois.ripe.net", "whois.radb.net")
DNS_TRANSPORTS = ("auto", "udp", "tcp", "tls")
API_KEYS = ("PEERINGDB_API_KEY", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY")

# Well-known resolvers and the certificate name each presents for DNS over TLS.
TLS_RESOLVERS = {
    "1.1.1.1": "cloudflare-dns.com", "1.0.0.1": "cloudflare-dns.com",
    "2606:4700:4700::1111": "cloudflare-dns.com", "2606:4700:4700::1001": "cloudflare-dns.com",
    "1.1.1.2": "security.cloudflare-dns.com", "1.0.0.2": "security.cloudflare-dns.com",
    "2606:4700:4700::1112": "security.cloudflare-dns.com", "2606:4700:4700::1002": "security.cloudflare-dns.com",
    "1.1.1.3": "family.cloudflare-dns.com", "1.0.0.3": "family.cloudflare-dns.com",
    "9.9.9.9": "dns.quad9.net", "149.112.112.112": "dns.quad9.net", "2620:fe::fe": "dns.quad9.net",
    "9.9.9.10": "dns10.quad9.net", "149.112.112.10": "dns10.quad9.net", "2620:fe::10": "dns10.quad9.net",
    "9.9.9.11": "dns11.quad9.net", "149.112.112.11": "dns11.quad9.net",
    "8.8.8.8": "dns.google", "8.8.4.4": "dns.google",
    "2001:4860:4860::8888": "dns.google", "2001:4860:4860::8844": "dns.google",
    "208.67.222.222": "dns.opendns.com", "208.67.220.220": "dns.opendns.com",
    "94.140.14.14": "dns.adguard-dns.com", "94.140.15.15": "dns.adguard-dns.com",
}

# DNS-based blocklists. Free use is low-volume and non-commercial, and Spamhaus and
# SURBL refuse queries that arrive from public resolvers.
SPAMHAUS_ERRORS = {
    "127.255.255.252": "query refused: typing error in the DNSBL name",
    "127.255.255.254": "query refused: sent through a public or open resolver",
    "127.255.255.255": "query refused: excessive query volume",
}
ZEN_CODES = {
    "127.0.0.2": "SBL: verified spam source", "127.0.0.3": "CSS: snowshoe or low-reputation spam source",
    "127.0.0.4": "XBL: exploited host or botnet member", "127.0.0.5": "XBL", "127.0.0.6": "XBL", "127.0.0.7": "XBL",
    "127.0.0.9": "DROP: hijacked or leased-to-abusers range",
    "127.0.0.10": "PBL: end-user address space (ISP-maintained)",
    "127.0.0.11": "PBL: end-user address space (Spamhaus-maintained)",
}
SPAMCOP_CODES = {"127.0.0.2": "reported spam source"}
BOGON_CODES = {"127.0.0.2": "unallocated, reserved or not routed"}
DBL_CODES = {
    "127.0.1.2": "spam domain", "127.0.1.4": "phishing domain", "127.0.1.5": "malware domain",
    "127.0.1.6": "botnet C&C domain", "127.0.1.102": "abused legitimate site: spam",
    "127.0.1.103": "abused spammed redirector", "127.0.1.104": "abused legitimate site: phishing",
    "127.0.1.105": "abused legitimate site: malware", "127.0.1.106": "abused legitimate site: botnet C&C",
    "127.0.1.255": "IP queries are prohibited on DBL",
}
SURBL_BITS = {4: "DM: disposable mail", 8: "PH: phishing", 16: "MW: malware",
              32: "CT: click tracker", 64: "ABUSE: spam or abuse", 128: "CR: cracked site"}

# Extended DNS Error codes (RFC 8914) that filtering resolvers attach to blocked answers.
BLOCKING_EDE_CODES = {15: "Blocked", 16: "Censored", 17: "Filtered"}
SINKHOLE_ADDRESSES = {"0.0.0.0", "::"}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DNSSEC_ALGORITHMS = {5: "RSASHA1", 7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256", 10: "RSASHA512",
                     13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384", 15: "ED25519", 16: "ED448"}
DS_DIGESTS = {1: "SHA-1", 2: "SHA-256", 4: "SHA-384"}
RPKI_STATES = {
    "valid": ("good", "valid", "a ROA authorises this origin at this prefix length"),
    "invalid_asn": ("bad", "invalid", "ROAs cover this prefix, but none authorise this origin AS"),
    "invalid_length": ("bad", "invalid", "the announcement is more specific than the ROA maxLength allows"),
    "invalid": ("bad", "invalid", "the covering ROAs do not authorise this announcement"),
    "unknown": ("warn", "not found", "no ROA covers this prefix, so validating routers treat it as unknown"),
}

# Downloadable feeds, cached locally and matched offline.
FEEDS = {
    "spamhaus_drop_v4": ("https://www.spamhaus.org/drop/drop_v4.json", "Spamhaus DROP IPv4"),
    "spamhaus_drop_v6": ("https://www.spamhaus.org/drop/drop_v6.json", "Spamhaus DROP IPv6"),
    "spamhaus_asndrop": ("https://www.spamhaus.org/drop/asndrop.json", "Spamhaus ASN-DROP"),
    "feodo_c2": ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "Feodo Tracker C2"),
    "tor_exits": ("https://check.torproject.org/torbulkexitlist", "Tor exit list"),
}
# A feed that can legitimately list nothing must still carry its header to count as valid.
FEED_MARKERS = {"feodo_c2": "Feodo Tracker"}
REPUTATION_NOTE = ("Listings are indicators, not verdicts. CDN, shared-hosting and carrier-grade NAT "
                   "addresses collect reports from many unrelated users, and feeds lag reality.")


class UpstreamError(Exception):
    """A source could not answer, as distinct from a successful empty answer."""


class NotFoundError(UpstreamError):
    """The authoritative source answered, and the object does not exist there."""


# ---------- input validation ----------

def asn(value):
    value = value.upper().removeprefix("AS")
    if not re.fullmatch(r"[0-9]{1,10}", value) or int(value) > 4294967295:
        raise ValueError("ASN must be between 0 and 4294967295")
    return f"AS{int(value)}"


def address(value):
    if "%" in value:
        raise ValueError("IPv6 zone identifiers are local, not Internet lookup targets")
    return str(ipaddress.ip_address(value))


def prefix(value):
    if "/" not in value:
        return address(value)
    if "%" in value:
        raise ValueError("IPv6 zone identifiers are not supported")
    return str(ipaddress.ip_network(value, strict=False))


def domain(value):
    try:
        name = value.removesuffix(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid internationalized domain name") from exc
    # Leading underscores are allowed so that _dmarc.example.com and DKIM selectors can be queried.
    label = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
    if (len(name) > 253 or "." not in name or re.fullmatch(r"[0-9.]+", name)
            or any(not re.fullmatch(label, part) for part in name.split("."))):
        raise ValueError("expected a domain such as example.com (not a URL or IP:port)")
    return name


def detect(value):
    try:
        return "ip", address(value)
    except ValueError:
        pass
    if "/" in value:
        return "prefix", prefix(value)
    if re.fullmatch(r"(?:AS)?[0-9]+", value, re.I):
        return "asn", asn(value)
    return "domain", domain(value)


def resource(value):
    kind, normalized = detect(value)
    if kind == "domain":
        raise ValueError("this command needs an IP, prefix or ASN; look up the domain first")
    return normalized


def resolver_spec(value):
    """An IP address or a hostname, or ADDRESS#NAME to give the certificate name a DNS-over-TLS resolver must present."""
    target, separator, tls_name = value.partition("#")
    if separator:
        example = "for example 1.1.1.1#cloudflare-dns.com"
        try:
            ip = address(target)
        except ValueError as exc:
            raise ValueError(f"--resolver ADDRESS#NAME needs an IP address before '#', {example}") from exc
        try:
            return f"{ip}#{domain(tls_name)}"
        except ValueError as exc:
            raise ValueError(f"--resolver ADDRESS#NAME needs the certificate's host name after '#', {example}") from exc
    try:
        return address(value)
    except ValueError:
        return domain(value)


def positive_timeout(value):
    try:
        result = float(value)
        if not math.isfinite(result) or not 0 < result <= 99999:
            raise ValueError
        return result
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number greater than 0 and at most 99999") from exc


def positive_count(value):
    try:
        result = int(value)
        if not 1 <= result <= 9999:
            raise ValueError
        return result
    except ValueError as exc:
        raise argparse.ArgumentTypeError("max-ips must be an integer from 1 to 9999") from exc


# ---------- parsers ----------

def parse_radb(reply):
    """Strip IRRd framing without converting server errors into empty results."""
    items = []
    for raw in reply.splitlines():
        line = raw.strip()
        if not line or re.fullmatch(r"A[0-9]+", line) or line in {"C", "D"}:
            continue
        if line == "E" or line.startswith("F") or line.startswith("% ERROR"):
            raise UpstreamError(f"RADb: {line}")
        items.extend(line.split())
    return items


def parse_ris(reply):
    routes = {}
    for line in reply.splitlines():
        fields = line.split()
        if len(fields) < 3 or not fields[0].isdigit() or "/" not in fields[1]:
            continue
        try:
            network = prefix(fields[1])
            peers = int(fields[2])
        except ValueError:
            continue
        routes[network] = max(routes.get(network, 0), peers)
    if not routes and reply.strip() and not re.search(r"no (entries|routes|match|results)", reply, re.I):
        payload = [line for line in reply.splitlines() if line.strip() and not line.startswith("%")]
        if payload:
            raise UpstreamError("RIS reply had no recognizable route rows; comparison withheld")
    return routes


def network_key(value):
    network = ipaddress.ip_network(value, strict=False)
    return network.version, int(network.network_address), network.prefixlen


SPF_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
SPF_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
SPF_RESULTS = {"-": "fail: only the listed senders", "~": "softfail: other senders are suspicious",
               "?": "neutral: no protection", "+": "pass for everyone: no protection"}
SPF_TONES = {"-": "good", "~": None, "?": "warn", "+": "bad"}


def parse_spf_terms(record):
    """Read each term after v=spf1 once: a modifier (name=value), a mechanism (qualifier, name, argument),
    or text that is neither. Everything else about the record is derived from this list."""
    terms = []
    for text in record.split()[1:]:
        modifier = re.fullmatch(r"([A-Za-z][A-Za-z0-9._-]*)=(.*)", text)
        mechanism = None if modifier else re.fullmatch(r"([+\-~?]?)([A-Za-z][A-Za-z0-9._-]*)(.*)", text)
        if modifier:
            terms.append({"text": text, "kind": "modifier", "name": modifier.group(1).lower(), "value": modifier.group(2)})
        elif mechanism:
            terms.append({"text": text, "kind": "mechanism", "qualifier": mechanism.group(1) or "+",
                          "name": mechanism.group(2).lower(), "argument": mechanism.group(3)})
        else:
            terms.append({"text": text, "kind": "invalid"})
    return terms


def spf_term_problem(term):
    """None when a parsed term is a valid SPF mechanism or modifier (RFC 7208 5, 6, 12), else the reason it is not."""
    text = term["text"]
    if term["kind"] == "modifier":
        if term["name"] in ("redirect", "exp") and not term["value"]:
            return f"'{text}' has no domain"
        return None
    if term["kind"] != "mechanism" or term["name"] not in SPF_MECHANISMS:
        return f"'{text}' is not an SPF mechanism or modifier"
    name, rest = term["name"], term["argument"]
    if name == "all" and rest:
        return f"'{text}': all takes no argument"
    if name in ("include", "exists") and (len(rest) < 2 or rest[0] != ":"):
        return f"'{text}' needs a domain"
    if name in ("a", "mx", "ptr") and rest and rest[0] not in ":/":
        return f"'{text}' is not an SPF mechanism or modifier"
    if name in ("ip4", "ip6"):
        try:
            if not rest.startswith(":"):
                raise ValueError
            network = ipaddress.ip_network(rest[1:], strict=False)
        except ValueError:
            return f"'{text}' needs a valid IPv{name[-1]} address or network"
        if network.version != int(name[-1]):
            return f"'{text}' contains an IPv{network.version} address"
    return None


def spf_summary(txt_values):
    if txt_values is None:
        return {"present": None, "note": "the TXT lookup failed, so SPF is unknown"}
    # RFC 7208 4.5: the record starts with exactly "v=spf1", then a space or the end; v=spf10 is not SPF.
    records = [v for v in txt_values if re.match(r"v=spf1(?: |$)", v, re.I)]
    if not records:
        return {"present": False, "note": "no SPF record at this name"}
    if len(records) > 1:
        return {"present": True, "valid": False, "records": records,
                "note": "more than one SPF record is a permanent error (RFC 7208)"}
    terms = parse_spf_terms(records[0])
    problems = [problem for problem in map(spf_term_problem, terms) if problem]
    modifiers = Counter(t["name"] for t in terms if t["kind"] == "modifier")
    problems += [f"{name}= appears {modifiers[name]} times" for name in ("redirect", "exp") if modifiers[name] > 1]
    if problems:
        return {"present": True, "valid": False, "records": records,
                "note": "permanent error (receivers treat the record as broken): " + "; ".join(problems[:3])}
    mechanisms = [t for t in terms if t["kind"] == "mechanism"]
    all_term = next((t for t in mechanisms if t["name"] == "all"), None)
    redirect = next((t["value"] for t in terms if t["kind"] == "modifier" and t["name"] == "redirect"), None)
    if all_term:
        redirect = None   # with an 'all' term present, redirect= is ignored (RFC 7208 6.1)
        meaning = SPF_RESULTS[all_term["qualifier"]]
    elif redirect:
        meaning = f"redirect: the SPF record at {redirect} decides the result"
    else:
        meaning = "no 'all' term: implicit neutral"
    return {"present": True, "valid": True, "record": records[0],
            "all": all_term["text"] if all_term else None, "all_qualifier": all_term["qualifier"] if all_term else None,
            "all_meaning": meaning, "redirect": redirect,
            "redirect_ignored": bool(all_term and modifiers["redirect"]),
            "includes": [t["argument"][1:] for t in mechanisms if t["name"] == "include"],
            "dns_lookup_terms": sum(t["name"] in SPF_LOOKUP_MECHANISMS for t in mechanisms) + (1 if redirect else 0),
            "lookup_limit": 10}


def is_dmarc_record(value):
    return re.match(r"v=dmarc1\s*(?:;|$)", value, re.I) is not None


DMARC_POLICIES = {"none": "monitor only", "quarantine": "quarantine failures", "reject": "reject failures"}


def dmarc_report_uris(value):
    """Valid aggregate-report addresses from a rua= tag (mailto URIs, optionally with a !size limit)."""
    return [uri.strip() for uri in (value or "").split(",")
            if re.fullmatch(r"mailto:[^@\s!,]+@[^@\s!,]+(?:![0-9]+[kmgt]?)?", uri.strip(), re.I)]


def dmarc_summary(value, inherited=False):
    """inherited: found at a parent, so a subdomain policy (sp=) overrides p= (RFC 9989 4.10). The record is
    validated as a whole first: an invalid p=, sp= or np= means p=none when a report address is given, and no
    DMARC policy otherwise (RFC 9989 4.10.1), whichever tag would have applied."""
    tags = {}
    for part in value.split(";"):
        if "=" in part:
            key, _, val = part.strip().partition("=")
            tags[key.strip().lower()] = val.strip()
    invalid = [tag for tag in ("p", "sp", "np")
               if (tag == "p" or tag in tags) and (tags.get(tag) or "").lower() not in DMARC_POLICIES]
    tag = "sp" if inherited and "sp" in tags else "p"
    summary = {"present": True, "valid": True, "record": value, "policy_tag": tag, "inherited": inherited,
               "published_policy": tags.get("p"), "subdomain_policy": tags.get("sp"), "percent": tags.get("pct", "100"),
               "aggregate_reports": tags.get("rua"), "forensic_reports": tags.get("ruf"),
               "dkim_alignment": tags.get("adkim", "r"), "spf_alignment": tags.get("aspf", "r")}
    if not invalid:
        policy = tags[tag].lower()
        return {**summary, "policy": policy, "policy_meaning": DMARC_POLICIES[policy]}
    which = " and ".join(f"{t}=" for t in invalid)
    verb = "is" if len(invalid) == 1 else "are"
    if dmarc_report_uris(tags.get("rua")):
        return {**summary, "policy": "none", "policy_tag": "p", "policy_meaning": DMARC_POLICIES["none"],
                "problem": f"{which} {verb} missing or invalid, so receivers treat the record as p=none because rua= names a report address"}
    return {**summary, "valid": False, "policy": None, "policy_meaning": "",
            "problem": f"{which} {verb} missing or invalid and there is no valid rua=, so receivers apply no DMARC policy"}


def parent_names(name):
    """The name, then each parent down to two labels: example.com for www.example.com."""
    labels = name.split(".")
    return [".".join(labels[i:]) for i in range(0, max(1, len(labels) - 1))]


def dnsbl_query_name(ip, zone):
    stem = ipaddress.ip_address(ip).reverse_pointer.rsplit(".", 2)[0]
    return f"{stem}.{zone}"


def decode_dnsbl(values, codes=None, bitmask=None):
    listed, meanings = True, []
    for value in values:
        if value in SPAMHAUS_ERRORS:
            listed = None
            meanings.append(SPAMHAUS_ERRORS[value])
        elif bitmask is not None:
            if value == "127.0.0.1":
                listed = None
                meanings.append("query refused: access from this resolver is blocked")
                continue
            last = int(value.rsplit(".", 1)[-1])
            hits = [label for bit, label in bitmask.items() if last & bit]
            meanings.extend(hits or [f"listed with code {value}"])
        else:
            meanings.append((codes or {}).get(value, f"listed with code {value}"))
    return listed, meanings


def cymru_fields(value):
    return [part.strip() for part in value.split("|")]


def strip_whois(text):
    """Drop % comment lines and collapse runs of blank lines."""
    lines, blank = [], False
    for line in text.splitlines():
        if line.startswith("%"):
            continue
        if not line.strip():
            blank = bool(lines)
            continue
        if blank:
            lines.append("")
        lines.append(line.rstrip())
        blank = False
    return "\n".join(lines)


def strip_banner(text):
    """Drop a leading % banner block (up to the first blank line) but keep later % header lines."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith("%"):
        return text
    for index, line in enumerate(lines):
        if not line.strip():
            return "\n".join(lines[index + 1:])
    return text


def ede_codes(comments):
    codes = []
    for comment in comments or []:
        codes += [int(code) for code in re.findall(r"EDE\s*\(?(\d+)\)?", str(comment))]
    return codes


# ---------- small formatting helpers ----------

def plural(count, singular, plural_form=None):
    return f"{count} {singular if count == 1 else plural_form or singular + 's'}"


def parse_time(value):
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def ago(when, now=None):
    if when is None:
        return ""
    seconds = ((now or datetime.now(timezone.utc)) - when).total_seconds()
    future, seconds = seconds < 0, abs(seconds)
    for unit, size in (("year", 31557600), ("month", 2629800), ("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            text = plural(int(seconds // size), unit)
            return f"in {text}" if future else f"{text} ago"
    return "just now"


def dated(value):
    when = parse_time(value)
    return f"{when:%Y-%m-%d} ({ago(when)})" if when else None


def short_ttl(seconds):
    """300 -> 5m, 5400 -> 1h30m, 83467 -> 23h11m: at most two units, rounded down."""
    value = int(seconds)
    units = ((86400, "d"), (3600, "h"), (60, "m"), (1, "s"))
    for index, (size, unit) in enumerate(units):
        if value >= size or size == 1:
            major, rest = divmod(value, size)
            text = f"{major}{unit}"
            if index + 1 < len(units) and rest >= units[index + 1][0]:
                text += f"{rest // units[index + 1][0]}{units[index + 1][1]}"
            return text
    return f"{value}s"


def link_speed(mbps):
    try:
        value = int(mbps)
    except (TypeError, ValueError):
        return "-"
    if value <= 0:
        return "-"
    if value >= 1000:
        return f"{value / 1000:g}G"
    return f"{value}M"


def display_name(value):
    return value[:-1] if len(value) > 1 and value.endswith(".") and not value.endswith(" .") else value


def format_ds(value):
    parts = value.split()
    try:
        tag, algorithm, digest = int(parts[0]), int(parts[1]), int(parts[2])
    except (IndexError, ValueError):
        return value
    return (f"key tag {tag} · {DNSSEC_ALGORITHMS.get(algorithm, f'algorithm {algorithm}')} · "
            f"{DS_DIGESTS.get(digest, f'digest type {digest}')}")


SPECIAL_RANGES = [(ipaddress.ip_network(network), text) for network, text in (
    ("192.0.2.0/24", "documentation"), ("198.51.100.0/24", "documentation"), ("203.0.113.0/24", "documentation"),
    ("2001:db8::/32", "documentation"), ("100.64.0.0/10", "carrier-grade NAT"), ("198.18.0.0/15", "benchmarking"),
    ("fc00::/7", "unique local"), ("64:ff9b::/96", "NAT64"))]


def scope_description(ip):
    for network, text in SPECIAL_RANGES:
        if ip.version == network.version and ip in network:
            return f"{text} address"
    for attribute, text in (("is_loopback", "loopback"), ("is_link_local", "link-local"),
                            ("is_multicast", "multicast"), ("is_private", "private"),
                            ("is_reserved", "reserved"), ("is_unspecified", "unspecified")):
        if getattr(ip, attribute):
            return f"{text} address"
    return "not globally routable"


# ---------- network client ----------

def resolver_label(spec, transport):
    effective = transport if transport != "auto" else ("tls" if spec else "udp")
    return f"{spec or 'system resolver'} over {effective.upper()}"


class Client:
    def __init__(self, timeout=30, resolver=None, transport="auto"):
        self.timeout = timeout
        self.resolver_spec = resolver
        self.transport = transport
        self._resolver = None
        self._transport = None
        self._tls_identity = None
        self._tcp = False
        self._lock = threading.Lock()

    @property
    def resolver_label(self):
        return resolver_label(self.resolver_spec, self.transport)

    def _build_resolver(self):
        import dns.flags
        import dns.nameserver
        import dns.resolver

        transport = self.transport
        if self.resolver_spec is None:
            resolver = dns.resolver.Resolver()
            if transport == "auto":
                transport = "udp"
            if transport == "tls":
                if not resolver.nameservers:
                    raise UpstreamError("no system nameserver configured to use over TLS")
                first = str(resolver.nameservers[0])
                self._tls_identity = TLS_RESOLVERS.get(first) or first
                resolver.nameservers = [dns.nameserver.DoTNameserver(first, hostname=self._tls_identity)]
        else:
            resolver = dns.resolver.Resolver(configure=False)
            if transport == "auto":
                transport = "tls"
            spec, _, tls_name = self.resolver_spec.partition("#")
            try:
                target = address(spec)
                # The certificate must match a name: the one given, a known one, or else the IP address itself
                # (public resolvers list their addresses in the certificate). Never check the CA chain alone.
                hostname = tls_name or TLS_RESOLVERS.get(target) or target
            except ValueError:
                hostname = spec
                try:
                    target = socket.getaddrinfo(hostname, 853, proto=socket.IPPROTO_TCP)[0][4][0]
                except OSError as exc:
                    raise UpstreamError(f"cannot resolve resolver hostname {hostname}: {exc}") from exc
            if transport == "tls":
                self._tls_identity = hostname
                resolver.nameservers = [dns.nameserver.DoTNameserver(target, hostname=hostname)]
            else:
                resolver.nameservers = [dns.nameserver.Do53Nameserver(target)]
        # Ask for the AD bit without EDNS/DO: validating resolvers still set AD (RFC 6840 5.7),
        # answers stay small (no RRSIGs), and truncated answers fall back to TCP automatically.
        # Some DNS proxies (ChromeOS containers, for one) drop EDNS answers larger than 512 bytes.
        resolver.flags = dns.flags.RD | dns.flags.AD
        self._tcp = transport == "tcp"
        self._transport = transport
        self._resolver = resolver

    def dns(self, name, record_type):
        try:
            import dns.exception
            import dns.flags
            import dns.rdatatype
            import dns.resolver
        except ImportError as exc:
            raise UpstreamError("DNS needs dnspython; run 'netintel deps' for installation instructions") from exc
        try:
            with self._lock:
                if self._resolver is None:
                    self._build_resolver()
            answer = self._resolver.resolve(
                name.rstrip(".") + ".", record_type, lifetime=self.timeout,
                search=False, raise_on_no_answer=False, tcp=self._tcp,
            )
            records = []
            for rrset in answer.response.answer:
                kind = dns.rdatatype.to_text(rrset.rdtype)
                for item in rrset:
                    if kind == "TXT":
                        value = "".join(part.decode("utf-8", "replace") for part in item.strings)
                    else:
                        value = item.to_text()
                    records.append({"name": str(rrset.name), "ttl": rrset.ttl, "type": kind, "value": value})
            return {"status": "NOERROR", "records": records,
                    "ad": bool(answer.response.flags & dns.flags.AD)}
        except dns.resolver.NXDOMAIN:
            return {"status": "NXDOMAIN", "records": [], "ad": False}
        except dns.resolver.NoNameservers as exc:
            failures = [entry[3] for entry in (exc.kwargs or {}).get("errors", []) if len(entry) > 3]
            tls_failures = [error for error in failures if isinstance(error, ssl.SSLError)]
            if tls_failures:
                raise UpstreamError(f"DNS {name} {record_type}: the TLS certificate check for {self._tls_identity} failed "
                                    f"({getattr(tls_failures[0], 'verify_message', None) or tls_failures[0]}); if the address is "
                                    "right, name its certificate with --resolver ADDRESS#NAME") from exc
            text = str(exc)
            if re.search(r"\b(SERVFAIL|REFUSED)\b", text):
                text += " (filtering resolvers refuse blocked names; validating resolvers fail on broken DNSSEC)"
            elif self._transport == "tls":
                text += " (DNS over TLS to the chosen resolver failed; try --dns-transport udp)"
            raise UpstreamError(f"DNS {name} {record_type}: {text}") from exc
        except dns.exception.DNSException as exc:
            hint = ""
            if self._transport == "tls":
                hint = " (DNS over TLS to the chosen resolver failed; try --dns-transport udp)"
            raise UpstreamError(f"DNS {name} {record_type}: {exc}{hint}") from exc

    def dns_values(self, name, record_type):
        """Record values of one type; [] for NXDOMAIN or no data."""
        result = self.dns(name, record_type)
        return [r["value"] for r in result["records"] if r["type"] == record_type]

    def fetch(self, url, headers=None):
        """GET a URL and return the body. HTTP errors propagate as HTTPError; transport errors become UpstreamError."""
        request = Request(url, headers={"User-Agent": f"netintel/{VERSION}",
                                       "Accept": "application/json", **(headers or {})})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return response.read()
        except HTTPError:
            raise
        except (URLError, OSError, ValueError, http.client.HTTPException) as exc:
            reason = getattr(exc, "reason", None) or exc
            raise UpstreamError(f"request to {urlparse(url).hostname} failed: {reason}") from exc

    def http(self, url, params=None, headers=None, missing_ok=False, raw=False):
        if params:
            url += "?" + urlencode(params)
        base = url.split("?")[0]
        try:
            body = self.fetch(url, headers)
        except HTTPError as exc:
            if exc.code == 404 and missing_ok:
                return None
            hints = {401: " (authentication required or key rejected)",
                     403: " (refused: outside the service's free tier or policy)",
                     429: " (rate limited; try again later)"}
            raise UpstreamError(f"HTTP {exc.code} from {base}{hints.get(exc.code, '')}") from exc
        if raw:
            return body.decode("utf-8", errors="replace")
        try:
            return json.loads(body)
        except ValueError as exc:
            raise UpstreamError(f"{base}: the response was not JSON") from exc

    def rdap(self, kind, value):
        url = f"https://rdap.org/{kind}/{value}"
        try:
            body = self.fetch(url, {"Accept": "application/rdap+json, application/json"})
        except HTTPError as exc:
            host = urlparse(exc.geturl() or url).hostname or "rdap.org"
            title = ""
            try:
                title = str(json.loads(exc.read()).get("title") or "")
            except (ValueError, OSError, AttributeError, http.client.HTTPException):
                pass
            if exc.code == 404 and host != "rdap.org":
                raise NotFoundError(f"{host} has no record of {value}") from exc
            if exc.code == 404:
                raise UpstreamError(f"rdap.org: {title or 'no RDAP service is available for this resource'}") from exc
            hint = " (rate limited; try again later)" if exc.code == 429 else ""
            raise UpstreamError(f"HTTP {exc.code} from {host}{hint}") from exc
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise UpstreamError("RDAP: the response was not JSON") from exc
        if not isinstance(data, dict) or "objectClassName" not in data:
            raise UpstreamError("RDAP: the response has no registration object")
        return data

    def doh_json(self, endpoint, name, record_type="A"):
        """DNS over HTTPS with the JSON API (Cloudflare, Google). Works even where port 53 is intercepted."""
        data = self.http(endpoint, {"name": name, "type": record_type}, {"Accept": "application/dns-json"})
        if not isinstance(data, dict) or "Status" not in data:
            raise UpstreamError(f"DoH {endpoint}: unexpected response")
        comment = data.get("Comment") or []
        comments = [comment] if isinstance(comment, str) else [str(c) for c in comment]
        answers = [str(a.get("data")) for a in data.get("Answer") or [] if isinstance(a, dict) and a.get("type") in (1, 28)]
        return {"status": data["Status"], "ad": data.get("AD"), "answers": answers,
                "comment": comments, "ede": ede_codes(comments)}

    def ripe(self, call, **params):
        result = self.http(f"https://stat.ripe.net/data/{call}/data.json",
                           {"sourceapp": "netintel", **params})
        if not isinstance(result, dict) or result.get("status") != "ok" or not isinstance(result.get("data"), dict):
            raise UpstreamError(f"RIPEstat {call}: the response has no successful data object")
        return result["data"]

    def network(self, ip):
        data = require(self.ripe("network-info", resource=ip), "prefix", "asns", source="RIPEstat network-info")
        try:
            route = prefix(data["prefix"]) if data.get("prefix") else None
            origins = [asn(str(a)) for a in data.get("asns", [])]
        except (ValueError, TypeError) as exc:
            raise UpstreamError("RIPEstat returned malformed prefix/origin data") from exc
        return {"ip": ip, "prefix": route, "asns": origins}

    def peering(self, value, depth=0):
        headers = {}
        if os.environ.get("PEERINGDB_API_KEY"):
            headers["Authorization"] = "Api-Key " + os.environ["PEERINGDB_API_KEY"]
        result = self.http("https://www.peeringdb.com/api/net",
                           {"asn": value.removeprefix("AS"), "depth": depth}, headers)
        if not isinstance(result, dict) or not isinstance(result.get("data"), list):
            raise UpstreamError("PeeringDB: malformed response")
        for net in expect_list(result["data"], dict, "PeeringDB", "data"):
            expect_list(net.get("netixlan_set") or [], dict, "PeeringDB", "netixlan_set")
        return result["data"]

    def tcp(self, host, request, port=43):
        """Send a request and read until the server closes. Sending happens on a helper thread so a
        large bulk request cannot deadlock against a server that starts replying before it has read
        everything."""
        deadline = time.monotonic() + self.timeout
        payload = request.encode("ascii")
        send_errors = []

        def send(connection):
            try:
                connection.sendall(payload)
            except OSError as exc:
                send_errors.append(exc)

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as connection:
                sender = threading.Thread(target=send, args=(connection,), daemon=True)
                sender.start()
                chunks = []
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("query deadline exceeded")
                    connection.settimeout(remaining)
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                sender.join(timeout=1)
                if send_errors or sender.is_alive():
                    reason = send_errors[0] if send_errors else "the server closed before the whole request was sent"
                    raise UpstreamError(f"{host}:{port}: sending the request failed ({reason}), so the reply is incomplete")
            return b"".join(chunks).decode("utf-8", errors="replace")
        except OSError as exc:
            raise UpstreamError(f"{host}:{port}: {exc}") from exc

    def whois(self, host, query):
        if "\n" in query or "\r" in query:
            raise ValueError("WHOIS query cannot contain newlines")
        reply = self.tcp(host, query + "\r\n")
        if not reply.strip():
            raise UpstreamError(f"{host}: empty response")
        if re.search(r"(?im)^(?:%\s*(?:error|fatal)|error:|access denied|query limit|rate limit)", reply):
            raise UpstreamError(f"{host}: {reply.strip()}")
        return reply


def require(data, *keys, source):
    """Legitimate empty answers still carry these fields; a reply without them is malformed, not 'nothing found'."""
    missing = [key for key in keys if not isinstance(data, dict) or key not in data]
    if missing:
        raise UpstreamError(f"{source}: the response lacks {', '.join(missing)}")
    return data


def expect(value, kinds, source, field):
    """Reject a field of the wrong type, so a malformed reply fails its own section instead of the whole report."""
    if not isinstance(value, kinds):
        raise UpstreamError(f"{source}: {field} is {type(value).__name__}, not the expected type")
    return value


def expect_list(value, kinds, source, field):
    expect(value, list, source, field)
    for item in value:
        expect(item, kinds, source, f"an item of {field}")
    return value


NUMBER = (int, float, type(None))
TEXT = (str, type(None))


def tcp_probe(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "reachable"
    except OSError as exc:
        raise UpstreamError(f"{host}:{port}: {exc}") from exc


# ---------- local feed cache ----------

def parse_feed(key, text):
    """Parse a feed body. Returns (entries, problem); problem is None only when the text looks like the feed,
    so an HTML error page or a rate-limit message can never replace or pose as a real blocklist."""
    head = text.lstrip()[:512].lower()
    if head.startswith("<") or "<html" in head or "<!doctype" in head:
        return None, "the download is an HTML page, not the feed"
    content = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    bad = 0
    if key in ("spamhaus_drop_v4", "spamhaus_drop_v6"):
        entries = []
        for line in content:
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError(line)
                if "cidr" in item:
                    entries.append((ipaddress.ip_network(item["cidr"], strict=False), item))
            except (ValueError, TypeError):
                bad += 1
    elif key == "spamhaus_asndrop":
        entries = {}
        for line in content:
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError(line)
                if "asn" in item:
                    entries[int(item["asn"])] = item
            except (ValueError, TypeError):
                bad += 1
    else:
        entries = set()
        for line in content:
            try:
                entries.add(str(ipaddress.ip_address(line)))
            except ValueError:
                bad += 1
    if bad > max(1, len(content) // 100):
        return None, f"{bad} of {len(content)} lines are not feed entries"
    if not entries:
        marker = FEED_MARKERS.get(key)
        if not marker or marker not in text:
            return None, "the download contains no entries"
    return entries, None


class Feeds:
    def __init__(self, client, cache_dir, ttl, refresh=False):
        self.client = client
        self.cache_dir = Path(cache_dir)
        self.ttl = ttl
        self.refresh = refresh
        self._entries = {}
        self._failures = {}
        self._locks = {}
        self._lock = threading.Lock()

    def status(self):
        rows = []
        for key, (_, label) in FEEDS.items():
            try:
                mtime = (self.cache_dir / f"{key}.txt").stat().st_mtime
            except OSError:
                rows.append({"key": key, "label": label, "cached": False})
                continue
            rows.append({"key": key, "label": label, "cached": True,
                         "fetched": datetime.fromtimestamp(mtime, timezone.utc),
                         "stale": time.time() - mtime > self.ttl})
        return rows

    def load(self, key):
        """One download per feed per run, even when several threads ask at once; failures are remembered."""
        with self._lock:
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:
            if key in self._entries:
                return self._entries[key]
            if key in self._failures:
                raise self._failures[key]
            try:
                entry = self._load(key)
            except UpstreamError as exc:
                self._failures[key] = exc
                raise
            self._entries[key] = entry
            return entry

    def _read_cache(self, key, path):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            mtime = path.stat().st_mtime
        except OSError:
            return None
        entries, problem = parse_feed(key, text)
        return None if problem else (entries, mtime)

    def _load(self, key):
        url, label = FEEDS[key]
        path = self.cache_dir / f"{key}.txt"
        cached = self._read_cache(key, path)
        if cached and not self.refresh and time.time() - cached[1] < self.ttl:
            return self._entry(key, cached[0], cached[1], "cache")
        try:
            text = self.client.http(url, raw=True)
            entries, problem = parse_feed(key, text)
            if problem:
                raise UpstreamError(f"download rejected: {problem}")
        except UpstreamError as exc:
            if cached:
                return self._entry(key, cached[0], cached[1], "stale cache", warning=f"refresh failed: {exc}")
            raise UpstreamError(f"{label}: {exc}") from exc
        self._write_cache(path, text)
        return self._entry(key, entries, time.time(), "download")

    def _write_cache(self, path, text):
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(path)
        except OSError:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _entry(key, entries, mtime, source, warning=None):
        return {"key": key, "label": FEEDS[key][1], "data": entries, "entries": len(entries),
                "fetched": datetime.fromtimestamp(mtime, timezone.utc), "source": source, "warning": warning}

    def _check(self, slug, label, key, match):
        """One feed check. A feed that cannot be loaded yields listed=None and the error, never a clean result."""
        try:
            entry = self.load(key)
        except UpstreamError as exc:
            return {"key": slug, "label": label, "listed": None, "error": str(exc)}
        hits = match(entry["data"])
        return {"key": slug, "label": label, "listed": bool(hits), "detail": hits, "feed": entry}

    def check_ip(self, ip):
        addr = ipaddress.ip_address(ip)
        drop = "spamhaus_drop_v4" if addr.version == 4 else "spamhaus_drop_v6"
        return [
            self._check("spamhaus-drop", "Spamhaus DROP", drop,
                        lambda data: [f"{item.get('cidr')} ({item.get('sblid')})" for network, item in data if addr in network]),
            self._check("feodo-c2", "Feodo Tracker C2", "feodo_c2",
                        lambda data: ["botnet C2 server"] if str(addr) in data else []),
            self._check("tor-exit", "Tor exit list", "tor_exits",
                        lambda data: ["Tor exit node"] if str(addr) in data else []),
        ]

    def check_prefix(self, network_text):
        network = ipaddress.ip_network(network_text, strict=False)
        drop = "spamhaus_drop_v4" if network.version == 4 else "spamhaus_drop_v6"

        def inside(data):
            count = sum(1 for ip in data if ipaddress.ip_address(ip) in network)
            return [plural(count, "address", "addresses")] if count else []

        return [
            self._check("spamhaus-drop", "Spamhaus DROP", drop,
                        lambda data: [f"{item.get('cidr')} ({item.get('sblid')})" for listed, item in data if listed.overlaps(network)]),
            self._check("feodo-c2", "Feodo Tracker C2", "feodo_c2", inside),
            self._check("tor-exit", "Tor exit list", "tor_exits", inside),
        ]

    def check_asn(self, value):
        entry = self.load("spamhaus_asndrop")
        item = entry["data"].get(int(value.removeprefix("AS")))
        return {"key": "spamhaus-asndrop", "label": "Spamhaus ASN-DROP", "listed": item is not None,
                "detail": item, "feed": entry}


# ---------- lookups that combine several queries ----------

def find_zone_apex(client, name):
    """The closest enclosing zone: the first name, walking up, whose SOA query returns an SOA owned by that name."""
    labels = name.split(".")
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        result = client.dns(candidate, "SOA")
        if any(r["type"] == "SOA" and r["name"].rstrip(".").lower() == candidate for r in result["records"]):
            return candidate
    return None


def dnssec_summary(client, name, ad_flag):
    if ad_flag:
        # The resolver validated the answer, so the chain is signed. Show the closest DS for context.
        for candidate in parent_names(name):
            ds = client.dns_values(candidate, "DS")
            if ds:
                return {"delegation_signed": True, "validated": True, "zone": candidate, "ds_records": ds}
        return {"delegation_signed": True, "validated": True, "zone": None, "ds_records": []}
    apex = find_zone_apex(client, name)
    if apex is None:
        return {"delegation_signed": None, "validated": False, "zone": None, "ds_records": [],
                "note": "could not find the zone that contains this name"}
    ds = client.dns_values(apex, "DS")
    summary = {"delegation_signed": bool(ds), "validated": False, "zone": apex, "ds_records": ds}
    if ds:
        summary["note"] = ("The parent publishes DS records, but the resolver did not set the AD flag. "
                           "It probably does not validate DNSSEC; try --resolver 1.1.1.1.")
    return summary


def follow_spf_redirect(client, spf, name):
    """Follow redirect= to the record that decides the result, as a receiver would (at most 10 hops)."""
    chain, seen, current = [], {name}, spf
    while current.get("redirect"):
        target = current["redirect"].rstrip(".").lower()
        if "%" in target:
            return {**spf, "redirect_chain": [*chain, target], "redirect_problem": "the target uses SPF macros, so it is not evaluated here"}
        if target in seen or len(chain) >= 10:
            return {**spf, "redirect_chain": [*chain, target], "redirect_problem": "redirect loop or too many redirects (a permanent error)"}
        seen.add(target)
        chain.append(target)
        current = spf_summary(client.dns_values(target, "TXT"))
        if not current.get("present") or not current.get("valid"):
            return {**spf, "redirect_chain": chain, "redirect_problem": f"{target} has no single valid SPF record (a permanent error)"}
    return {**spf, "redirect_chain": chain, "effective_all": current.get("all"), "effective_qualifier": current.get("all_qualifier"),
            "effective_meaning": current["all_meaning"], "effective_record": current.get("record")}


def email_auth_summary(client, name, txt_values):
    spf = spf_summary(txt_values)
    if spf.get("redirect"):
        try:
            spf = follow_spf_redirect(client, spf, name)
        except UpstreamError as exc:
            spf = {**spf, "redirect_error": str(exc)}
    result = {"spf": spf}
    discarded = []
    for candidate in parent_names(name):
        records = [v for v in client.dns_values(f"_dmarc.{candidate}", "TXT") if is_dmarc_record(v)]
        if len(records) > 1:
            # RFC 9989 4.10: several records at one name are all discarded, and discovery moves up the tree.
            discarded.append(f"_dmarc.{candidate} ({len(records)} records)")
            continue
        if records:
            result["dmarc"] = dmarc_summary(records[0], inherited=candidate != name)
            result["dmarc"]["found_at"] = f"_dmarc.{candidate}"
            break
    else:
        result["dmarc"] = {"present": False, "note": "no DMARC record at the name or its parents"}
    result["dmarc"]["discarded"] = discarded
    return result


def vcard_field(entity, field):
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item and item[0] == field:
                value = item[3]
                if isinstance(value, list):
                    value = " ".join(str(v) for v in value if v)
                return str(value).strip() or None
    except (IndexError, TypeError, AttributeError):
        pass
    return None


def self_link(data):
    return next((link.get("href") for link in data.get("links") or []
                 if isinstance(link, dict) and link.get("rel") == "self" and link.get("href")), None)


def rdap_summary(data):
    start = data.get("startAddress") or (f"AS{data['startAutnum']}" if data.get("startAutnum") is not None else None)
    end = data.get("endAddress") or (f"AS{data['endAutnum']}" if data.get("endAutnum") is not None else None)
    entities = []
    for entity in data.get("entities") or []:
        if isinstance(entity, dict):
            handle = entity.get("handle")
            entities.append({"handle": None if handle is None else str(handle),
                             "roles": [str(r) for r in expect(entity.get("roles") or [], list, "RDAP", "roles")],
                             "name": vcard_field(entity, "fn"), "email": vcard_field(entity, "email")})
    source = self_link(data)
    text = {field: None if data.get(field) is None else str(data.get(field)) for field in ("name", "handle", "type", "country", "port43")}
    return {"name": text["name"], "handle": text["handle"], "type": text["type"],
            "country": text["country"], "start": start, "end": end, "whois": text["port43"],
            "entities": entities, "source": urlparse(source).hostname if source else None}


def domain_registration(data):
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
    registrar = None
    for entity in data.get("entities", []):
        if isinstance(entity, dict) and "registrar" in (entity.get("roles") or []):
            registrar = vcard_field(entity, "fn") or entity.get("handle")
    secure = data.get("secureDNS") or {}
    source = self_link(data)
    return {"found": True, "name": data.get("ldhName"), "registrar": registrar,
            "registered": events.get("registration"), "expires": events.get("expiration"),
            "last_changed": events.get("last changed"),
            "status": [str(s) for s in expect(data.get("status") or [], list, "RDAP", "status")],
            "nameservers": [str(ns["ldhName"]) for ns in data.get("nameservers") or [] if isinstance(ns, dict) and ns.get("ldhName")],
            "dnssec_delegation_signed": secure.get("delegationSigned"),
            "source": urlparse(source).hostname if source else None}


def domain_registration_lookup(client, name):
    """RDAP for the name, then its parents. A registry 404 at every level means not registered; a missing
    RDAP service or any other failure is an error, never 'not registered'."""
    last = None
    for candidate in parent_names(name):
        try:
            data = client.rdap("domain", candidate)
        except NotFoundError as exc:
            last = exc
            continue
        summary = domain_registration(data)
        summary["queried_name"] = candidate
        if candidate != name:
            summary["note"] = f"No RDAP record for {name}; showing its registered parent {candidate}."
        return summary
    return {"found": False, "queried_name": name, "note": str(last) if last else None}


def cert_transparency(client, name):
    data = client.http("https://api.certspotter.com/v1/issuances",
                       {"domain": name, "include_subdomains": "true", "expand": "dns_names"})
    if not isinstance(data, list):
        raise UpstreamError("Cert Spotter: unexpected response")
    names = sorted({str(n).lower() for cert in data for n in cert.get("dns_names", [])})
    starts = [c.get("not_before") for c in data if c.get("not_before")]
    return {"issuances": len(data), "names": names,
            "earliest_not_before": min(starts) if starts else None,
            "latest_not_before": max(starts) if starts else None}


def looking_glass_summary(data):
    origins, adjacent, paths, prefixes = Counter(), Counter(), Counter(), Counter()
    collectors, total = 0, 0
    for rrc in data.get("rrcs", []):
        peers = rrc.get("peers", [])
        if peers:
            collectors += 1
        total += len(peers)
        for peer in peers:
            if peer.get("prefix"):
                prefixes[peer["prefix"]] += 1
            path = str(peer.get("as_path", "")).split()
            if not path:
                continue
            origin = path[-1]
            origins[origin] += 1
            paths[" ".join(path)] += 1
            upstream = next((hop for hop in reversed(path) if hop != origin), None)
            if upstream:
                adjacent[upstream] += 1
    return {"collectors": collectors, "peer_views": total, "origins": dict(origins.most_common()),
            "prefixes": dict(prefixes.most_common()), "adjacent": dict(adjacent.most_common()),
            "paths": [{"path": p, "count": c} for p, c in paths.most_common()]}


def irr_routes(client, query):
    entries = parse_radb(client.whois("whois.radb.net", query))
    try:
        if any("/" not in item for item in entries):
            raise ValueError("non-prefix token")
        return sorted({prefix(item) for item in entries}, key=network_key)
    except ValueError as exc:
        raise UpstreamError("RADb returned malformed route data; comparison withheld") from exc


# ---------- reputation sources ----------

def dnsbl_ip(client, ip, zone, codes):
    values = client.dns_values(dnsbl_query_name(ip, zone), "A")
    if not values:
        return {"listed": False, "zone": zone, "codes": [], "meaning": []}
    listed, meanings = decode_dnsbl(values, codes=codes)
    return {"listed": listed, "zone": zone, "codes": values, "meaning": meanings}


def dnsbl_domain(client, name, zone, codes=None, bitmask=None):
    values = client.dns_values(f"{name}.{zone}", "A")
    if not values:
        return {"listed": False, "zone": zone, "codes": [], "meaning": []}
    listed, meanings = decode_dnsbl(values, codes=codes, bitmask=bitmask)
    return {"listed": listed, "zone": zone, "codes": values, "meaning": meanings}


def filter_verdict(unfiltered, filtered):
    """True only with evidence of blocking, False only when the filtered resolver gave a real answer,
    None (unknown) otherwise: SERVFAIL, REFUSED or an empty answer prove nothing either way."""
    if unfiltered.get("status") != 0 or not unfiltered.get("answers"):
        return None
    codes = set(filtered.get("ede") or []) | set(ede_codes(filtered.get("comment")))
    if codes & set(BLOCKING_EDE_CODES):
        return True
    status, answers = filtered.get("status"), filtered.get("answers") or []
    if status == 3:
        return True     # NXDOMAIN for a name that resolves elsewhere is how Quad9 blocks
    if status == 0 and answers:
        return all(answer in SINKHOLE_ADDRESSES for answer in answers)
    return None


def describe_dns_answer(result):
    parts = [", ".join(str(a) for a in result.get("answers") or []) or RCODE_NAMES.get(result.get("status"), f"rcode {result.get('status')}")]
    parts += [str(c) for c in result.get("comment") or [] if str(c).upper().startswith("EDE")]
    return " ".join(parts)


def cloudflare_filter(client, name):
    unfiltered = client.doh_json("https://cloudflare-dns.com/dns-query", name)
    filtered = client.doh_json("https://security.cloudflare-dns.com/dns-query", name)
    return {"blocked": filter_verdict(unfiltered, filtered), "unfiltered": unfiltered, "filtered": filtered}


def dot_answer(name, server, hostname, timeout):
    import dns.edns
    import dns.exception
    import dns.message
    import dns.query
    import dns.rdatatype

    query = dns.message.make_query(name, "A", use_edns=0, payload=1232)
    try:
        response = dns.query.tls(query, server, timeout=timeout, server_hostname=hostname)
    except (dns.exception.DNSException, OSError) as exc:
        raise UpstreamError(f"{hostname} over TLS: {exc or type(exc).__name__}") from exc
    ede = [(int(option.code), option.text) for option in response.options if isinstance(option, dns.edns.EDEOption)]
    answers = [str(item) for rrset in response.answer
               if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) for item in rrset]
    return {"status": response.rcode(), "answers": answers, "ede": [code for code, _ in ede],
            "comment": [f"EDE({code}): {text or BLOCKING_EDE_CODES.get(code, '')}".rstrip(": ") for code, text in ede]}


def quad9_filter(client, name):
    unfiltered = dot_answer(name, "9.9.9.10", "dns10.quad9.net", client.timeout)
    filtered = dot_answer(name, "9.9.9.9", "dns.quad9.net", client.timeout)
    return {"blocked": filter_verdict(unfiltered, filtered), "unfiltered": unfiltered, "filtered": filtered}


def internetdb(client, ip):
    data = client.http(f"https://internetdb.shodan.io/{ip}", missing_ok=True)
    if data is None:
        return {"found": False}
    source = "Shodan InternetDB"
    require(data, "ip", "ports", source=source)
    result = {"found": True, "ports": expect_list(data["ports"], int, source, "ports")}
    for key in ("vulns", "cpes", "hostnames", "tags"):
        result[key] = expect_list(data.get(key, []), str, source, key)
    return result


def ipapi(client, ip):
    data = client.http(f"http://ip-api.com/json/{ip}",
                       {"fields": "status,message,country,as,isp,org,proxy,hosting,mobile"})
    if data.get("status") != "success":
        raise UpstreamError(f"ip-api: {data.get('message', 'unknown error')}")
    return {key: data.get(key) for key in ("country", "as", "isp", "org", "proxy", "hosting", "mobile")}


def robtex_ip(client, ip):
    data = client.http(f"https://freeapi.robtex.com/ipquery/{ip}")
    if data.get("status") != "ok":
        raise UpstreamError(f"Robtex: {data.get('status', 'unknown status')}")
    entries = expect_list(data.get("pas") or [], dict, "Robtex", "pas") + expect_list(data.get("act") or [], dict, "Robtex", "act")
    names = sorted({str(e["o"]) for e in entries if e.get("o")})
    return {"names": names, "asname": data.get("asname"), "route": data.get("bgproute")}


def robtex_domain(client, name):
    """Robtex answers one JSON object per line, or [] when it has never seen the name. Anything else
    (an HTML error page, a rate-limit message) is a failure, never 'no history'."""
    text = client.http(f"https://freeapi.robtex.com/pdns/forward/{name}", raw=True).strip()
    try:
        whole = json.loads(text) if text.startswith(("[", "{")) else None
    except ValueError:
        whole = None
    if isinstance(whole, list):
        items, lines = whole, len(whole)
    elif isinstance(whole, dict) and not ({"rrtype", "rrdata"} & whole.keys()):
        raise UpstreamError(f"Robtex: {whole.get('status') or 'unexpected response'}")
    else:
        items, lines = [], 0
        for line in text.splitlines():
            if line.strip():
                lines += 1
                try:
                    items.append(json.loads(line))
                except ValueError:
                    items.append(None)
    records = [{key: item.get(key) for key in ("rrtype", "rrdata", "time_first", "time_last", "count")}
               for item in items if isinstance(item, dict) and ({"rrtype", "rrdata"} & item.keys())]
    bad = lines - len(records)
    if bad and (not records or bad > max(1, lines // 100)):
        raise UpstreamError(f"Robtex: {bad} of {lines} lines were not passive DNS records (an error page or rate limit?)")
    return {"records": records}


def abuseipdb(client, ip, key):
    data = require(client.http("https://api.abuseipdb.com/api/v2/check",
                               {"ipAddress": ip, "maxAgeInDays": 90}, {"Key": key}), "data", source="AbuseIPDB")
    record = expect(data["data"], dict, "AbuseIPDB", "data")
    for field in ("abuseConfidenceScore", "totalReports", "numDistinctUsers"):
        expect(record.get(field), NUMBER, "AbuseIPDB", field)
    fields = ("abuseConfidenceScore", "totalReports", "numDistinctUsers", "lastReportedAt", "usageType", "isp")
    return {field: record.get(field) for field in fields}


def greynoise(client, ip, key):
    data = client.http(f"https://api.greynoise.io/v3/community/{ip}", headers={"key": key}, missing_ok=True)
    if data is None:
        return {"observed": False}
    require(data, "noise", "riot", source="GreyNoise")
    for field in ("classification", "name"):
        expect(data.get(field), TEXT, "GreyNoise", field)
    return {"observed": True, **{field: data.get(field) for field in ("noise", "riot", "classification", "name", "last_seen")}}


KEYED_SOURCES = (("ABUSEIPDB_API_KEY", "abuseipdb", "AbuseIPDB", abuseipdb),
                 ("GREYNOISE_API_KEY", "greynoise", "GreyNoise", greynoise))


def interception_probe(timeout):
    """Ask 1.1.1.1 who it is (id.server, class CH) over UDP/53 and over DNS over TLS, then compare the sites."""
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdataclass

    query = dns.message.make_query("id.server", "TXT", rdclass=dns.rdataclass.CH)

    def ask(function):
        try:
            response = function()
        except Exception as exc:  # any failure is a diagnostic result here
            return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"[:160]}
        identities = ["".join(part.decode("utf-8", "replace") for part in getattr(item, "strings", ()))
                      for rrset in response.answer for item in rrset]
        identities = [value for value in identities if value]
        if response.rcode() != 0 or not identities:
            return {"ok": False, "detail": f"answered {dns.rcode.to_text(response.rcode())} with no server identity"}
        return {"ok": True, "identity": identities[0]}

    udp = ask(lambda: dns.query.udp(query, "1.1.1.1", timeout=timeout))
    tls = ask(lambda: dns.query.tls(query, "1.1.1.1", timeout=timeout, server_hostname="cloudflare-dns.com"))

    def site(identity):
        return re.sub(r"[^a-z]", "", identity.lower()) or identity.lower()

    if udp["ok"] and tls["ok"]:
        if site(udp["identity"]) == site(tls["identity"]):
            state, verdict = "direct", f"Direct: UDP/53 and TLS/853 both reach Cloudflare ({tls['identity']})."
        else:
            state, verdict = "redirected", (f"UDP/53 is answered by '{udp['identity']}' but DNS over TLS by "
                                            f"'{tls['identity']}': port 53 is probably redirected to another resolver.")
    elif tls["ok"]:
        state, verdict = "intercepted", (f"UDP/53 to 1.1.1.1 is intercepted or blocked ({udp['detail']}); "
                                         f"DNS over TLS reaches Cloudflare ({tls['identity']}). --resolver uses TLS by default.")
    elif udp["ok"]:
        state, verdict = "tls-blocked", (f"TLS/853 is blocked ({tls['detail']}), so the UDP answer "
                                         f"('{udp['identity']}') cannot be verified. Use --dns-transport udp with --resolver.")
    else:
        state, verdict = "no-path", "Neither UDP/53 nor TLS/853 reaches 1.1.1.1; only the system resolver is usable."
    return {"state": state, "udp": udp, "tls": tls, "verdict": verdict}


# ---------- running several lookups ----------

class Result:
    __slots__ = ("elapsed", "error", "value")

    def __init__(self, value=None, error=None, elapsed=0.0):
        self.value, self.error, self.elapsed = value, error, elapsed

    @property
    def ok(self):
        return self.error is None


def attempt(function, *args, **kwargs):
    started = time.monotonic()
    try:
        value = function(*args, **kwargs)
    except UpstreamError as exc:
        return Result(error=str(exc), elapsed=time.monotonic() - started)
    except BrokenPipeError:
        raise
    except (KeyError, IndexError, TypeError, ValueError, AttributeError) as exc:
        return Result(error=f"malformed response: {exc}", elapsed=time.monotonic() - started)
    except Exception as exc:  # one failing source must not abort the report
        return Result(error=f"unexpected {type(exc).__name__}: {exc}", elapsed=time.monotonic() - started)
    return Result(value, elapsed=time.monotonic() - started)


def gather(jobs, workers=8):
    """Run {name: (function, args)} concurrently and return {name: Result} in the same order."""
    if not jobs:
        return {}
    pool = ThreadPoolExecutor(max_workers=min(workers, len(jobs)))
    try:
        futures = {name: pool.submit(attempt, function, *arguments) for name, (function, arguments) in jobs.items()}
        return {name: future.result() for name, future in futures.items()}
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


# ---------- output ----------

SYMBOLS = {"good": "✓", "bad": "✗", "warn": "!", "error": "?", "info": "•", "skip": "–"}  # noqa: RUF001
ASCII = str.maketrans({"✓": "+", "✗": "x", "•": "*", "–": "-", "·": "-", "…": "..."})  # noqa: RUF001
ANSI = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "cyan": "36"}
TONE_STYLES = {"good": ("green",), "bad": ("bold", "red"), "warn": ("yellow",), "error": ("yellow",),
               "info": (), "skip": ("dim",), "dim": ("dim",), "red": ("red",)}
MORE = "--grep lists all"


class Style:
    def __init__(self, enabled):
        self.enabled = enabled

    def __call__(self, text, *names):
        if not self.enabled or not names or not text:
            return text
        return f"\x1b[{';'.join(ANSI[name] for name in names)}m{text}\x1b[0m"

    def tone(self, text, tone):
        return self(text, *TONE_STYLES.get(tone, ()))


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-") or "-"


class Output:
    """Shared by both renderers: counts failures, which decide the exit status."""

    def __init__(self, target, unicode=True):
        self.target = str(target or "-")
        self.unicode = unicode
        self.failures = 0

    def _print(self, text, stream=None):
        if not self.unicode:
            text = text.translate(ASCII)
        print(text, file=stream or sys.stdout, flush=True)

    def raw_lines(self, lines):
        for line in lines:
            self._print(line)

    def raw_error(self, message):
        self.failures += 1
        self._print(f"error: {message}", sys.stderr)

    def finish(self):
        return 1 if self.failures else 0


class HumanOutput(Output):
    """Sections with aligned rows, color and status marks. Each section is buffered so it can be aligned."""

    def __init__(self, target, color=False, width=100, unicode=True):
        super().__init__(target, unicode)
        self.style = Style(color)
        self.width = width
        self.title = self.source = None
        self.blocks = []
        self.hidden = False
        self.rendered = False

    # building blocks
    def header(self, target, subtitle):
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        self._print(self.style(target, "bold") + "  " + self.style(f"{subtitle} · {stamp}", "dim"))
        self.rendered = True

    def section(self, title, slug, source=None, grep_only=False):
        self._flush()
        self.hidden = grep_only
        if not grep_only:
            self.title, self.source = title, source

    def _add(self, *block):
        if not self.hidden:
            self.blocks.append(block)

    def kv(self, key, value, tone=None, limit=None, always=False):
        if value in (None, "", [], ()) and not always:
            return
        self._add("kv", str(key), value, tone, limit)

    def status(self, key, label, state, word, detail=""):
        if state == "error":
            self.failures += 1
        self._add("status", str(label), state if state in SYMBOLS else "info", str(word), "" if detail in (None, "") else str(detail))

    def table(self, headers, rows, limit=None):
        if rows:
            self._add("table", headers, rows, limit)

    def text(self, text):
        if text and text.strip():
            self._add("text", text)

    def blank(self):
        self._add("blank")

    def note(self, text):
        if text:
            self._add("note", text)

    def error(self, message):
        self.failures += 1
        self._add("error", message)

    def next_steps(self, commands, limit=8):
        if commands:
            self.section("Next steps", "next")
            self._add("commands", commands, limit)

    def finish(self):
        self._flush()
        if self.failures and self.rendered:
            message = f"{plural(self.failures, 'lookup')} failed; the results above are partial"
            self._print("\n" + self.style.tone(f"{SYMBOLS['warn']} {message}", "warn"))
        return super().finish()

    # rendering
    def _flush(self):
        if self.title is None and not self.blocks:
            return
        lines = []
        if self.title is not None:
            heading = self.style(self.title, "bold", "cyan")
            if self.source:
                heading += "  " + self.style(self.source, "dim")
            lines += ["", heading]
        keyw = min(max((len(b[1]) for b in self.blocks if b[0] == "kv"), default=0), 18)
        labelw = min(max((len(b[1]) for b in self.blocks if b[0] == "status"), default=0), 24)
        wordw = min(max((len(b[3]) for b in self.blocks if b[0] == "status"), default=0), 18)
        for block in self.blocks:
            lines += getattr(self, f"_render_{block[0]}")(block, keyw, labelw, wordw)
        if not self.blocks:
            lines.append("  " + self.style("no data", "dim"))
        self._print("\n".join(lines))
        self.rendered = True
        self.title = self.source = None
        self.blocks = []

    def _wrap(self, text, indent):
        room = max(24, self.width - indent)
        pieces = []
        for paragraph in str(text).splitlines() or [""]:
            pieces += textwrap.wrap(paragraph, room, break_long_words=False, break_on_hyphens=False) or [""]
        return pieces

    def _render_kv(self, block, keyw, _labelw, _wordw):
        _, key, value, tone, limit = block
        if isinstance(value, (list, tuple)):
            items = [str(item) for item in value]
            if limit and len(items) > limit:
                items = [*items[:limit], f"… {len(value) - limit} more ({MORE})"]
            text = ", ".join(items)
        else:
            text = str(value)
        width = max(keyw, len(key))
        indent = 2 + width + 2
        return [("  " + key.ljust(width) + "  " if index == 0 else " " * indent) + self.style.tone(piece, tone)
                for index, piece in enumerate(self._wrap(text, indent))]

    def _render_status(self, block, _keyw, labelw, wordw):
        _, label, state, word, detail = block
        lead = f"  {self.style.tone(SYMBOLS[state], state)} {label.ljust(labelw)}  "
        if not detail:
            return [lead + self.style.tone(word, state)]
        indent = 2 + 2 + labelw + 2 + wordw + 2
        detail_tone = "dim" if state == "skip" else None
        pieces = self._wrap(detail, indent)
        lines = [lead + self.style.tone(word.ljust(wordw), state) + "  " + self.style.tone(pieces[0], detail_tone)]
        return lines + [" " * indent + self.style.tone(piece, detail_tone) for piece in pieces[1:]]

    def _render_table(self, block, *_):
        _, headers, rows, limit = block
        shown = rows[:limit] if limit and len(rows) > limit else rows
        cells = [[cell if isinstance(cell, tuple) else ("" if cell is None else str(cell), None) for cell in row]
                 for row in shown]
        columns = max([len(headers or [])] + [len(row) for row in cells])
        widths = [0] * columns
        for row in ([[(h, None) for h in headers]] if headers else []) + cells:
            for index, (text, _) in enumerate(row):
                widths[index] = max(widths[index], len(text))
        widths = [min(width, 48) for width in widths]
        indent = 2 + sum(widths[:-1]) + 2 * (columns - 1)
        lines = []
        if headers:
            lines.append("  " + self.style("  ".join(h.ljust(widths[i]) if i < columns - 1 else h
                                                      for i, h in enumerate(headers)), "dim"))
        for row in cells:
            parts, extra = [], []
            for index, (text, tone) in enumerate(row):
                if index < len(row) - 1:
                    parts.append(self.style.tone(text.ljust(widths[index]), tone))
                    continue
                pieces = self._wrap(text, indent) if indent < self.width - 24 else [text]
                parts.append(self.style.tone(pieces[0], tone))
                extra = [" " * indent + self.style.tone(piece, tone) for piece in pieces[1:]]
            lines += ["  " + "  ".join(parts), *extra]
        if len(shown) < len(rows):
            lines.append("  " + self.style(f"… {len(rows) - len(shown)} more ({MORE})", "dim"))
        return lines

    def _render_text(self, block, *_):
        return ["  " + line.expandtabs(8).rstrip() if line.strip() else "" for line in block[1].strip("\n").splitlines()]

    def _render_blank(self, *_):
        return [""]

    def _render_note(self, block, *_):
        return ["  " + self.style(piece, "dim") for piece in self._wrap(block[1], 2)]

    def _render_error(self, block, *_):
        pieces = self._wrap(block[1], 4)
        return (["  " + self.style.tone(f"{SYMBOLS['bad']} {pieces[0]}", "red")]
                + ["    " + self.style.tone(piece, "red") for piece in pieces[1:]])

    def _render_commands(self, block, *_):
        _, commands, limit = block
        shown = commands[:limit] if limit and len(commands) > limit else commands
        lines = ["  " + self.style("$ ", "dim") + self.style(command, "cyan") for command in shown]
        if len(shown) < len(commands):
            lines.append("  " + self.style(f"… {len(commands) - len(shown)} more ({MORE})", "dim"))
        return lines


class GrepOutput(Output):
    """One fact per line: target, section, then fields, separated by tabs. Nothing is truncated."""

    def __init__(self, target, unicode=True):
        super().__init__(target, unicode)
        self.slug = "-"

    def _emit(self, *fields):
        values = [re.sub(r"\s*[\t\r\n]+\s*", " ", "" if field is None else str(field)).strip() for field in fields]
        while values and values[-1] == "":
            values.pop()
        self._print("\t".join([self.target, self.slug, *values]))

    def header(self, target, subtitle):
        pass

    def section(self, title, slug, source=None, grep_only=False):
        self.slug = slug

    def kv(self, key, value, tone=None, limit=None, always=False):
        if value in (None, "", [], ()) and not always:
            return
        for item in value if isinstance(value, (list, tuple)) else [value]:
            self._emit(slugify(key), item)

    def status(self, key, label, state, word, detail=""):
        if state == "error":
            self.failures += 1
        self._emit(key, word, detail)

    def table(self, headers, rows, limit=None):
        for row in rows:
            self._emit(*[cell[0] if isinstance(cell, tuple) else cell for cell in row])

    def text(self, text):
        for line in (text or "").splitlines():
            if line.strip():
                self._emit(line.rstrip())

    def blank(self):
        pass

    def note(self, text):
        pass

    def error(self, message):
        self.failures += 1
        self._emit("error", message)

    def next_steps(self, commands, limit=None):
        self.slug = "next"
        for command in commands:
            self._emit(command)


# ---------- shared views ----------

def guarded(default=None):
    """Contain an unexpected error to the section that raised it, so later sections still print."""
    def decorate(function):
        label = function.__name__.removeprefix("show_").replace("_", " ")

        @functools.wraps(function)
        def wrapper(out, *args, **kwargs):
            try:
                return function(out, *args, **kwargs)
            except BrokenPipeError:
                raise
            except Exception as exc:
                if os.environ.get("NETINTEL_DEBUG"):
                    raise
                out.error(f"internal error while rendering {label}: {type(exc).__name__}: {exc} "
                          "(NETINTEL_DEBUG=1 for a traceback)")
                return default
        return wrapper
    return decorate


@functools.lru_cache(maxsize=1)
def program_prefix():
    if Path(sys.argv[0]).name in {"netintel", "netintel.exe"} or shutil.which("netintel"):
        return ("netintel",)
    paths = []
    for path in (Path(sys.executable), Path(__file__).resolve()):
        try:
            paths.append(str(path.relative_to(Path.cwd())))
        except ValueError:
            paths.append(str(path))
    return tuple(paths)


def command_line(*arguments):
    return shlex.join([*program_prefix(), *arguments])


def suggest(steps):
    return list(dict.fromkeys(command_line(*step) for step in steps))


def route_steps(route, origins):
    steps = [("prefix", route)] if route else []
    for origin in origins:
        steps.append(("asn", origin))
        if route and "/" in route:
            steps.append(("rpki", route, origin))
    return steps


def stale_note(entry):
    return f" · stale copy: {entry['warning']}" if entry and entry.get("warning") else ""


def feed_info(entry):
    text = f"{plural(entry['entries'], 'entry', 'entries')} · downloaded {ago(entry['fetched'])}"
    if entry.get("warning"):
        text += f" · stale copy: {entry['warning']}"
    return text


@guarded()
def show_rdap(out, result, title="Registration"):
    if not result.ok:
        out.section(title, "registration", source="RDAP")
        out.error(result.error)
        return
    data = result.value
    out.section(title, "registration", source=f"RDAP · {data['source']}" if data.get("source") else "RDAP")
    span = None
    if data.get("start"):
        span = data["start"] if data["start"] == data.get("end") else f"{data['start']} - {data.get('end')}"
    out.kv("name", data.get("name"))
    if data.get("handle") not in (span, data.get("name")):
        out.kv("handle", data.get("handle"))
    out.kv("range", span)
    out.kv("type", data.get("type"))
    out.kv("country", data.get("country"))
    for entity in data.get("entities") or []:
        handle, name = entity.get("handle"), entity.get("name")
        parts = [handle, name if name and name != handle else None, f"<{entity['email']}>" if entity.get("email") else None]
        roles = "/".join(ROLE_NAMES.get(role, role) for role in entity.get("roles") or []) or "contact"
        out.kv(roles, "  ".join(p for p in parts if p))
    out.kv("whois", data.get("whois"))


ROLE_NAMES = {"technical": "tech", "administrative": "admin", "registrant": "registrant", "abuse": "abuse",
              "noc": "noc", "billing": "billing", "registrar": "registrar", "reseller": "reseller"}


@guarded()
def show_whois(out, results, sections):
    for key, title in sections:
        result = results[key]
        out.section(title, key)
        if result.ok:
            out.text(strip_whois(result.value) or "(empty reply)")
        else:
            out.error(result.error)


@guarded(default="error")
def dnsbl_row(out, key, label, result):
    if not result.ok:
        out.status(key, label, "error", "unknown", result.error)
        return "error"
    data = result.value
    if data["listed"] is None:
        out.status(key, label, "error", "refused", "; ".join(data["meaning"]))
        return "error"
    if data["listed"]:
        out.status(key, label, "bad", "listed", "; ".join(data["meaning"]))
        return "bad"
    out.status(key, label, "good", "not listed")
    return "good"


@guarded(default="error")
def feed_row(out, row, listed_state="bad", listed_word="listed", clean_word="not listed"):
    if row.get("error"):
        out.status(row["key"], row["label"], "error", "unknown", row["error"])
        return "error"
    if row["listed"]:
        out.status(row["key"], row["label"], listed_state, listed_word, "; ".join(row["detail"]) + stale_note(row["feed"]))
        return listed_state
    out.status(row["key"], row["label"], "warn" if row["feed"].get("warning") else "good", clean_word, feed_info(row["feed"]))
    return "good"


@guarded()
def summary(out, tally, flags=()):
    """tally: [(label, state, is_blocklist)]. Unknown results are named, never counted as clean."""
    out.section("Summary", "summary")
    lists = [(label, state) for label, state, blocklist in tally if blocklist and state != "skip"]
    listed = [label for label, state in lists if state == "bad"]
    answered = [label for label, state in lists if state in ("good", "bad", "warn")]
    unknown = [label for label, state, _ in tally if state == "error"]
    checks = plural(len(answered), "check")
    if listed:
        out.kv("blocklists", f"flagged by {len(listed)} of {checks} that answered: {', '.join(listed)}", tone="bad")
    elif answered:
        out.kv("blocklists", f"clean on {'all ' if len(answered) > 1 else ''}{checks} that answered",
               tone="warn" if any(label in unknown for label, _ in lists) else "good")
    else:
        out.kv("blocklists", "none could be checked", tone="warn")
    out.kv("flags", list(flags) or "none", tone="warn" if flags else None)
    out.kv("not checked", unknown, tone="warn")


# ---------- commands ----------

@guarded()
def show_dns(out, name, results):
    out.section("DNS", "dns")
    if any(r.ok and r.value["status"] == "NXDOMAIN" for r in results.values()):
        out.kv("status", "NXDOMAIN: the name does not exist", tone="bad")
        for kind, result in results.items():
            if not result.ok:
                out.error(f"{kind}: {result.error}")
        return
    rows, seen, empty, failed = [], set(), [], []
    for kind, result in results.items():
        if not result.ok:
            failed.append((kind, result.error))
            continue
        records = [r for r in result.value["records"] if r["type"] in (kind, "CNAME")]
        if not any(r["type"] == kind for r in records):
            empty.append(kind)
        for record in records:
            key = (record["name"].lower(), record["type"], record["value"])
            if key not in seen:
                seen.add(key)
                rows.append(record)

    def order(record):
        value = record["value"]
        preference = int(value.split()[0]) if record["type"] == "MX" and value.split()[0].isdigit() else 0
        return DNS_ORDER.get(record["type"], 99), record["name"], preference, value

    rows.sort(key=order)
    owner = name.lower() + "."
    show_owner = any(record["name"].lower() != owner for record in rows)

    def shown(record):
        value = record["value"]
        if record["type"] == "MX" and value.split()[-1:] == ["."]:
            return f"{value}  (null MX: accepts no mail)"
        return display_name(value) if record["type"] in ("CNAME", "NS", "PTR", "MX") else value

    headers = (["NAME"] if show_owner else []) + ["TYPE", "TTL", "VALUE"]
    out.table(headers, [([display_name(r["name"])] if show_owner else []) + [r["type"], short_ttl(r["ttl"]), shown(r)]
                        for r in rows])
    for kind, error in failed:
        out.error(f"{kind}: {error}")
    if empty:
        out.note(f"No {', '.join(empty)} records.")


@guarded()
def show_dnssec(out, result):
    out.section("DNSSEC", "dnssec")
    if not result.ok:
        out.error(result.error)
        return
    data = result.value
    signed, validated = data["delegation_signed"], data.get("validated")
    if signed and validated:
        out.kv("status", "signed and validated by the resolver", tone="good")
    elif signed:
        out.kv("status", "signed, but this resolver did not validate the answer", tone="warn")
    elif signed is False:
        out.kv("status", "not signed")
    else:
        out.kv("status", "unknown", tone="warn")
    out.kv("zone", data.get("zone"))
    out.kv("DS", [format_ds(value) for value in data.get("ds_records") or []])
    out.note(data.get("note"))


@guarded()
def show_email(out, result):
    out.section("Email authentication", "email")
    if not result.ok:
        out.error(result.error)
        return
    spf, dmarc = result.value["spf"], result.value["dmarc"]
    if spf.get("present") is None:
        out.kv("SPF", "unknown: the TXT lookup failed", tone="warn")
    elif not spf["present"]:
        out.kv("SPF", "none published", tone="warn")
    elif not spf.get("valid"):
        out.kv("SPF", spf["records"], tone="bad")
        out.kv("SPF policy", f"invalid: {spf['note']}", tone="bad")
    else:
        lookups = spf["dns_lookup_terms"]
        count = f" · {lookups} of 10 DNS lookups at the top level"
        out.kv("SPF", spf["record"])
        chain = " -> ".join(spf.get("redirect_chain") or [spf.get("redirect") or ""])
        if not spf.get("redirect"):
            out.kv("SPF policy", spf["all_meaning"] + count,
                   tone="bad" if lookups > 10 else SPF_TONES.get(spf.get("all_qualifier"), "warn"))
        elif spf.get("redirect_error"):
            out.kv("SPF policy", f"redirected to {spf['redirect']}; not evaluated" + count, tone="warn")
            out.error(f"SPF redirect lookup: {spf['redirect_error']}")
        elif spf.get("redirect_problem"):
            out.kv("SPF policy", f"redirected to {chain}: {spf['redirect_problem']}", tone="bad")
        else:
            out.kv("SPF policy", f"{spf['effective_meaning']} (via redirect to {chain})" + count,
                   tone="bad" if lookups > 10 else SPF_TONES.get(spf.get("effective_qualifier"), "warn"))
            out.kv("SPF redirect", spf.get("effective_record"))
        if spf.get("redirect_ignored"):
            out.note("This record's redirect= modifier is ignored because the record has an 'all' term.")
    for place in dmarc.get("discarded") or []:
        out.kv("DMARC problem", f"{place} were all discarded: receivers ignore a name with more than one DMARC record",
               tone="bad")
    if not dmarc.get("present"):
        out.kv("DMARC", "none in effect" if dmarc.get("discarded") else "none published", tone="warn")
        return
    if not dmarc.get("valid", True):
        out.kv("DMARC", f"no effective policy: {dmarc['problem']}", tone="bad")
        out.kv("DMARC record", dmarc.get("found_at"))
        return
    if dmarc.get("problem"):
        out.kv("DMARC problem", dmarc["problem"], tone="warn")
    policy = dmarc.get("policy")
    text = f"{dmarc.get('policy_tag', 'p')}={policy}: {dmarc['policy_meaning']}"
    if dmarc.get("percent") not in (None, "100"):
        text += f", applied to {dmarc['percent']}% of mail"
    out.kv("DMARC", text, tone={"reject": "good", "quarantine": "good"}.get(policy, "warn"))
    record = dmarc.get("found_at")
    if dmarc.get("inherited"):
        record += " (inherited: this name has no record of its own"
        record += ", so the subdomain policy sp= applies)" if dmarc.get("policy_tag") == "sp" else ")"
    out.kv("DMARC record", record)
    out.kv("DMARC reports", dmarc.get("aggregate_reports"))
    out.note(dmarc.get("note"))


@guarded()
def show_domain_registration(out, result):
    if not result.ok:
        out.section("Registration", "registration", source="RDAP")
        out.error(result.error)
        return
    data = result.value
    out.section("Registration", "registration", source=f"RDAP · {data['source']}" if data.get("source") else "RDAP")
    if not data.get("found"):
        out.kv("status", "not registered: the registry has no record of this name", tone="warn")
        out.note(data.get("note"))
        return
    out.kv("registrar", data.get("registrar"))
    created = parse_time(data.get("registered"))
    if created:
        days = (datetime.now(timezone.utc) - created).days
        out.kv("created", dated(data["registered"]) + (" · newly registered" if days < 30 else ""),
               tone="bad" if days < 30 else "warn" if days < 180 else None)
    expires = parse_time(data.get("expires"))
    if expires:
        left = (expires - datetime.now(timezone.utc)).days
        out.kv("expires", dated(data["expires"]), tone="bad" if left < 0 else "warn" if left < 30 else None)
    out.kv("updated", dated(data.get("last_changed")))
    statuses = data.get("status") or []
    hold = any("hold" in s.lower() for s in statuses)
    ending = any("pending delete" in s.lower() or "redemption" in s.lower() for s in statuses)
    out.kv("status", statuses, tone="bad" if hold or ending else None)
    out.kv("nameservers", [ns.lower() for ns in data.get("nameservers") or []])
    signed = data.get("dnssec_delegation_signed")
    out.kv("DNSSEC", {True: "signed delegation", False: "unsigned delegation"}.get(signed))
    if hold:
        out.note("A hold status means the registry is not publishing the domain in DNS.")
    out.note(data.get("note"))


@guarded()
def show_ct(out, result):
    out.section("Certificate transparency", "ct", source="Cert Spotter")
    if not result.ok:
        out.error(result.error)
        return
    data = result.value
    if not data["issuances"]:
        out.kv("certificates", "none found", tone="dim")
        return
    out.kv("certificates", str(data["issuances"]) + (" (first page only)" if data["issuances"] >= 100 else ""))
    out.kv("newest", dated(data.get("latest_not_before")))
    out.kv("names", data["names"], limit=24)


def cmd_domain(ctx):
    args, client, out = ctx.args, ctx.client, ctx.out
    name = args.target
    out.header(name, f"domain · {client.resolver_label}")
    jobs = {kind: (client.dns, (name, kind)) for kind in DNS_TYPES}
    jobs["rdap"] = (domain_registration_lookup, (client, name))
    jobs["ct"] = (cert_transparency, (client, name))
    res = gather(jobs, workers=10)
    show_dns(out, name, {kind: res[kind] for kind in DNS_TYPES})
    exists = not any(res[kind].ok and res[kind].value["status"] == "NXDOMAIN" for kind in DNS_TYPES)

    ips, origins, pairs, extra = [], [], [], {}
    if exists:
        failed = [kind for kind in ("A", "AAAA") if not res[kind].ok]
        for kind in ("A", "AAAA"):
            if res[kind].ok:
                for record in res[kind].value["records"]:
                    if record["type"] == kind and address(record["value"]) not in ips:
                        ips.append(address(record["value"]))
        ips.sort(key=lambda ip: (ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip))))
        lookups = {ip: (client.network, (ip,)) for index, ip in enumerate(ips)
                   if index < args.max_ips and ipaddress.ip_address(ip).is_global and not ipaddress.ip_address(ip).is_multicast}
        txt = res["TXT"]
        a_result = res["A"]
        extra = gather({**lookups,
                        "dnssec": (dnssec_summary, (client, name, a_result.value.get("ad") if a_result.ok else None)),
                        "email": (email_auth_summary, (client, name,
                                  [r["value"] for r in txt.value["records"] if r["type"] == "TXT"] if txt.ok else None))})
        out.section("Addresses", "addresses", source="RIPEstat")
        if not ips:
            out.kv("addresses", "unknown: the A/AAAA lookup failed" if failed else "none: the name has no A or AAAA records",
                   tone="warn" if failed else "dim")
        rows, errors = [], []
        for ip in ips:
            parsed = ipaddress.ip_address(ip)
            if not parsed.is_global or parsed.is_multicast:
                rows.append([ip, (scope_description(parsed), "dim"), ""])
            elif ip not in extra:
                rows.append([ip, ("not looked up (--max-ips)", "dim"), ""])
            elif not extra[ip].ok:
                rows.append([ip, ("lookup failed", "error"), ""])
                errors.append(f"{ip}: {extra[ip].error}")
            else:
                info = extra[ip].value
                rows.append([ip, info["prefix"] or ("not announced", "warn"), ", ".join(info["asns"]) or "-"])
                origins += [a for a in info["asns"] if a not in origins]
                pairs += [(info["prefix"], a) for a in info["asns"] if info["prefix"] and (info["prefix"], a) not in pairs]
        out.table(["ADDRESS", "PREFIX", "ORIGIN"], rows)
        for error in errors:
            out.error(error)
        if failed and ips:
            out.note(f"The {' and '.join(failed)} lookup failed, so this list may be incomplete.")
        show_dnssec(out, extra["dnssec"])
        show_email(out, extra["email"])
    show_domain_registration(out, res["rdap"])
    show_ct(out, res["ct"])
    # One ip suggestion per network keeps the list short when a name has many addresses.
    representatives = {}
    for ip in ips:
        info = extra[ip].value if exists and ip in extra and extra[ip].ok else None
        representatives.setdefault(info["prefix"] if info and info["prefix"] else ip, ip)
    steps = [("reputation", name), *[("ip", ip) for ip in representatives.values()], *[("asn", a) for a in origins],
             *[("rpki", p, a) for p, a in pairs]]
    out.next_steps(suggest(steps))


def cmd_ip(ctx):
    args, client, out = ctx.args, ctx.client, ctx.out
    ip = ipaddress.ip_address(args.target)
    text = str(ip)
    out.header(text, "IP address")
    routable = ip.is_global and not ip.is_multicast
    reverse = ip.reverse_pointer
    jobs = {"ptr": (client.dns, (reverse, "PTR"))}
    if routable:
        if ip.version == 4:
            stem = reverse.removesuffix(".in-addr.arpa")
            origin_name = f"{stem}.origin.asn.cymru.com"
            jobs["peers"] = (client.dns_values, (f"{stem}.peer.asn.cymru.com", "TXT"))
        else:
            origin_name = reverse.removesuffix(".ip6.arpa") + ".origin6.asn.cymru.com"
        jobs["origin"] = (client.dns_values, (origin_name, "TXT"))
        jobs["network"] = (client.network, (text,))
        jobs["rdap"] = (lambda: rdap_summary(client.rdap("ip", text)), ())
        if not args.quick:
            jobs["whois-cymru"] = (client.whois, ("whois.cymru.com", f" -v {text}"))
            jobs["whois-bgptools"] = (client.whois, ("bgp.tools", f"-v {text}"))
            jobs["whois-ris"] = (client.whois, ("riswhois.ripe.net", f"-M -F {text}"))
    res = gather(jobs)

    out.section("Reverse DNS", "ptr")
    ptr = res["ptr"]
    if not ptr.ok:
        out.error(ptr.error)
    else:
        names = [display_name(r["value"]) for r in ptr.value["records"] if r["type"] == "PTR"]
        out.kv("PTR", names or "none", tone=None if names else "dim")
    if not routable:
        out.section("Scope", "scope")
        out.kv("address", f"{scope_description(ip)}; public routing, registration and reputation data do not apply",
               tone="warn")
        return

    out.section("Routing", "routing", source="RIPEstat")
    info = {"prefix": None, "asns": []}
    if res["network"].ok:
        info = res["network"].value
        out.kv("prefix", info["prefix"] or "not announced in BGP", tone=None if info["prefix"] else "warn")
        if info["prefix"]:
            out.kv("origin", info["asns"] or "none", tone="warn" if len(info["asns"]) != 1 else None)
        if len(info["asns"]) > 1:
            out.note("More than one AS originates this prefix. That can be intended (anycast) or a hijack.")
    else:
        out.error(res["network"].error)

    out.section("Team Cymru", "cymru", source="DNS")
    origin = res["origin"]
    if not origin.ok:
        out.error(f"origin: {origin.error}")
    for value in origin.value or []:
        fields = cymru_fields(value)
        if len(fields) >= 5:
            asns = " ".join(f"AS{a}" for a in fields[0].split())
            out.kv("origin", f"{asns} · {fields[1]} · {fields[2] or '??'} · {fields[3]} · allocated {fields[4] or 'unknown'}")
        else:
            out.kv("origin", value)
    if origin.ok and not origin.value:
        out.kv("origin", "no data", tone="dim")
    if "peers" in res:
        if res["peers"].ok:
            for value in res["peers"].value:
                out.kv("peers", [f"AS{a}" for a in cymru_fields(value)[0].split()])
        else:
            out.error(f"peers: {res['peers'].error}")

    show_rdap(out, res["rdap"])
    if not args.quick:
        show_whois(out, res, [("whois-cymru", "WHOIS · Team Cymru"), ("whois-bgptools", "WHOIS · bgp.tools"),
                              ("whois-ris", "WHOIS · RIPE RIS")])
    out.next_steps(suggest([("reputation", text), ("abuse", text), *route_steps(info["prefix"], info["asns"])]))


@guarded()
def show_peeringdb(out, result):
    out.section("PeeringDB", "peeringdb")
    if not result.ok:
        out.error(result.error)
        return
    if not result.value:
        out.kv("record", "not in PeeringDB", tone="dim")
    for net in result.value:
        kinds = net.get("info_types") or net.get("info_type")
        out.kv("name", net.get("name"))
        out.kv("website", net.get("website"))
        out.kv("as-set", net.get("irr_as_set"))
        out.kv("type", kinds)
        out.kv("scope", net.get("info_scope"))
        out.kv("traffic", net.get("info_traffic"))
        out.kv("ratio", net.get("info_ratio"))
        out.kv("policy", net.get("policy_general"))
        if net.get("info_prefixes4") or net.get("info_prefixes6"):
            out.kv("prefixes", f"{net.get('info_prefixes4') or 0} IPv4 · {net.get('info_prefixes6') or 0} IPv6 (configured maximum)")
        out.kv("presence", f"{plural(net.get('ix_count') or 0, 'exchange')} · "
                           f"{plural(net.get('fac_count') or 0, 'facility', 'facilities')}")
        out.kv("looking glass", net.get("looking_glass"))
        out.kv("route server", net.get("route_server"))


@guarded(default="error")
def asn_drop_row(out, result):
    label = "Spamhaus ASN-DROP"
    if not result.ok:
        out.status("spamhaus-asndrop", label, "error", "unknown", result.error)
        return "error"
    data = result.value
    if data["listed"]:
        entry = data["detail"] or {}
        out.status("spamhaus-asndrop", label, "bad", "listed",
                   " · ".join(str(v) for v in (entry.get("asname"), entry.get("cc"), entry.get("domain")) if v)
                   + stale_note(data["feed"]))
        return "bad"
    out.status("spamhaus-asndrop", label, "warn" if data["feed"].get("warning") else "good", "not listed", feed_info(data["feed"]))
    return "good"


def cmd_asn(ctx):
    args, client, out, feeds = ctx.args, ctx.client, ctx.out, ctx.feeds
    value = args.target
    out.header(value, "autonomous system")
    jobs = {"rdap": (lambda: rdap_summary(client.rdap("autnum", value[2:])), ()),
            "cymru": (client.dns_values, (f"{value}.asn.cymru.com", "TXT")),
            "peeringdb": (client.peering, (value,)),
            "asndrop": (feeds.check_asn, (value,))}
    if not args.quick:
        jobs["whois-cymru"] = (client.whois, ("whois.cymru.com", f" -v {value}"))
        jobs["whois-bgptools"] = (client.whois, ("bgp.tools", f"-v {value}"))
    res = gather(jobs)
    show_rdap(out, res["rdap"])
    out.section("Team Cymru", "cymru", source="DNS")
    cymru = res["cymru"]
    if not cymru.ok:
        out.error(cymru.error)
    elif not cymru.value:
        out.kv("record", "no data", tone="dim")
    for record in cymru.value or []:
        fields = cymru_fields(record)
        if len(fields) >= 5:
            out.kv("name", fields[4])
            out.kv("country", fields[1])
            out.kv("registry", fields[2])
            out.kv("allocated", fields[3])
        else:
            out.kv("record", record)
    show_peeringdb(out, res["peeringdb"])
    out.section("Blocklists", "blocklists")
    asn_drop_row(out, res["asndrop"])
    if not args.quick:
        show_whois(out, res, [("whois-cymru", "WHOIS · Team Cymru"), ("whois-bgptools", "WHOIS · bgp.tools")])
    out.next_steps(suggest([(command, value) for command in ("routes", "neighbors", "ix", "reputation", "abuse")]))


def cmd_prefix(ctx):
    args, client, out = ctx.args, ctx.client, ctx.out
    target = args.target
    out.header(target, "prefix")
    jobs = {"rdap": (lambda: rdap_summary(client.rdap("ip", target)), ()),
            "lg": (lambda: looking_glass_summary(require(client.ripe("looking-glass", resource=target), "rrcs",
                                                         source="RIPEstat looking-glass")), ())}
    if not args.quick:
        jobs["whois-ris"] = (client.whois, ("riswhois.ripe.net", target))
        jobs["whois-radb"] = (client.whois, ("whois.radb.net", target))
    res = gather(jobs)
    if not args.quick:
        show_whois(out, res, [("whois-ris", "BGP · RIPE RIS"), ("whois-radb", "IRR · RADb")])
    show_rdap(out, res["rdap"])
    out.section("Looking glass", "looking-glass", source="RIPEstat · live RIS collectors")
    origins, matched = [], target
    lg = res["lg"]
    if not lg.ok:
        out.error(lg.error)
    elif not lg.value["peer_views"]:
        out.kv("visibility", "not seen by any RIS collector", tone="warn")
    else:
        data = lg.value
        origins = [f"AS{a}" for a in data["origins"]]
        matched = next(iter(data["prefixes"]), target)
        out.kv("visibility", f"{plural(data['collectors'], 'collector')} · {plural(data['peer_views'], 'peer session')}")
        if matched != target:
            out.kv("matched", list(data["prefixes"]))
        out.kv("origin", [f"AS{a} ({n})" for a, n in data["origins"].items()], tone="warn" if len(origins) > 1 else None)
        out.kv("upstreams", [f"AS{a} ({n})" for a, n in data["adjacent"].items()], limit=10)
        out.table(["SEEN", "AS PATH"], [[p["count"], p["path"]] for p in data["paths"]], limit=5)
        out.note("Upstreams are the ASNs directly before the origin in collected paths, with how many sessions show each.")
    steps = [("reputation", target), *route_steps(matched if "/" in matched else None, origins)]
    out.next_steps(suggest([step for step in steps if step != ("prefix", target)]))


def cmd_routes(ctx):
    args, client, out = ctx.args, ctx.client, ctx.out
    value = args.target
    out.header(value, "originated routes")
    res = gather({"ris": (lambda: parse_ris(client.whois("riswhois.ripe.net", f"-F -i {value}")), ()),
                  "v4": (irr_routes, (client, f"!g{value}")),
                  "v6": (irr_routes, (client, f"!6{value}"))})
    out.section("Routes", "routes")
    observed = res["ris"].value if res["ris"].ok else None
    if observed is not None:
        out.kv("in BGP", f"{plural(len(observed), 'prefix', 'prefixes')} seen by RIPE RIS")
    else:
        out.error(f"RIS: {res['ris'].error}")
    for key, family in (("v4", "IPv4"), ("v6", "IPv6")):
        if not res[key].ok:
            out.error(f"RADb {family}: {res[key].error}")
    if res["v4"].ok and res["v6"].ok:
        v4, v6 = res["v4"].value, res["v6"].value
        out.kv("in IRR", f"{plural(len(v4) + len(v6), 'route object')} in RADb · {len(v4)} IPv4 · {len(v6)} IPv6")
    if observed is None or not res["v4"].ok or not res["v6"].ok:
        out.note("Comparison withheld: a source failed, and missing data is not an empty route set.")
        return
    out.note("Exact matches only: a covering aggregate does not count. RIS visibility and IRR registration "
             "can differ for legitimate reasons, so a difference alone does not prove a leak.")
    registered = set(res["v4"].value) | set(res["v6"].value)
    only_seen = sorted(set(observed) - registered, key=lambda p: (-observed[p], network_key(p)))
    only_registered = sorted(registered - set(observed), key=network_key)
    out.section(f"In BGP without an exact IRR route object ({len(only_seen)})", "observed-only")
    out.table(["PREFIX", "RIS PEERS"], [[p, observed[p]] for p in only_seen], limit=100)
    if not only_seen:
        out.note("None.")
    out.section(f"In IRR but not seen in BGP ({len(only_registered)})", "registered-only")
    out.table(["PREFIX"], [[p] for p in only_registered], limit=100)
    if not only_registered:
        out.note("None.")
    out.section("Observed routes", "observed", grep_only=True)
    out.table(["PREFIX", "RIS PEERS"], [[p, observed[p]] for p in sorted(observed, key=network_key)])
    out.section("Registered routes", "registered", grep_only=True)
    out.table(["PREFIX"], [[p] for p in sorted(registered, key=network_key)])


@guarded(default="error")
def keyed_row(out, key, label, env, result):
    """AbuseIPDB or GreyNoise: skipped without a key, else one classified row."""
    if result is None:
        out.status(key, label, "skip", "skipped", f"set {env} to enable")
        return "skip"
    if not result.ok:
        out.status(key, label, "error", "unknown", result.error)
        return "error"
    data = result.value
    if key == "abuseipdb":
        score = data.get("abuseConfidenceScore")
        state = "info" if score is None else "bad" if score >= 50 else "warn" if score > 0 else "good"
        detail = f"{plural(data.get('totalReports') or 0, 'report')} from {plural(data.get('numDistinctUsers') or 0, 'user')}"
        if data.get("lastReportedAt"):
            detail += f" · last {dated(data['lastReportedAt'])}"
        if data.get("usageType"):
            detail += f" · {data['usageType']}"
        out.status(key, label, state, f"{score}% confidence" if score is not None else "no score", detail)
        return state
    if not data["observed"]:
        out.status(key, label, "good", "not observed", "not seen scanning the Internet")
        return "good"
    classification = data.get("classification") or "unknown"
    state = "good" if data.get("riot") or classification == "benign" else "bad" if classification == "malicious" else "warn"
    out.status(key, label, state, "benign service" if data.get("riot") else classification,
               " · ".join(str(v) for v in (data.get("name"), dated(data.get("last_seen"))) if v))
    return state


@guarded(default="error")
def bogon_row(out, result):
    label = "Team Cymru bogons"
    if not result.ok:
        out.status("bogon", label, "error", "unknown", result.error)
        return "error"
    if result.value["listed"] is None:
        out.status("bogon", label, "error", "refused", "; ".join(result.value["meaning"]))
        return "error"
    if result.value["listed"]:
        out.status("bogon", label, "bad", "bogon", "; ".join(result.value["meaning"]))
        return "bad"
    out.status("bogon", label, "good", "not a bogon")
    return "good"


@guarded(default="error")
def ipapi_row(out, result):
    if not result.ok:
        out.status("ip-api", "ip-api.com", "error", "unknown", result.error)
        return "error"
    data = result.value
    marks = [text for field, text in (("proxy", "proxy/VPN"), ("hosting", "datacenter"), ("mobile", "mobile")) if data.get(field)]
    state = "warn" if data.get("proxy") else "info"
    out.status("ip-api", "ip-api.com", state, ", ".join(marks) or "no flags",
               " · ".join(str(v) for v in (data.get("as"), data.get("country")) if v))
    return state


@guarded(default="error")
def shodan_row(out, result):
    label = "Shodan InternetDB"
    if not result.ok:
        out.status("shodan", label, "error", "unknown", result.error)
        return "error"
    if not result.value["found"]:
        out.status("shodan", label, "info", "no data", "not in the weekly scan data")
        return "info"
    ports, vulns = result.value["ports"], result.value["vulns"]
    state = "bad" if vulns else "info"
    out.status("shodan", label, state, plural(len(ports), "open port"), plural(len(vulns), "known CVE") if vulns else "no known CVEs")
    return state


@guarded(default="error")
def robtex_row(out, result):
    if not result.ok:
        out.status("robtex", "Robtex passive DNS", "error", "unknown", result.error)
        return "error"
    names = result.value["names"]
    out.status("robtex", "Robtex passive DNS", "info", plural(len(names), "name"),
               ", ".join(names[:3]) + (f" … {len(names) - 3} more" if len(names) > 3 else ""))
    return "info"


@guarded()
def show_exposed_services(out, result):
    shodan = result.value if result.ok and result.value["found"] else None
    if shodan and any(shodan[key] for key in ("ports", "vulns", "hostnames", "cpes", "tags")):
        out.section("Exposed services", "shodan", source="Shodan InternetDB · weekly")
        out.kv("ports", [str(p) for p in shodan["ports"]], limit=32)
        out.kv("CVEs", shodan["vulns"], tone="bad", limit=20)
        out.kv("software", shodan["cpes"], limit=12)
        out.kv("hostnames", shodan["hostnames"], limit=12)
        out.kv("tags", shodan["tags"])


@guarded()
def show_passive_names(out, result):
    if result.ok and result.value["names"]:
        out.section("Passive DNS", "passive-dns", source="Robtex")
        out.kv("names", result.value["names"], limit=20)


def ip_flags(res, feed_rows):
    """Profile facts the summary calls out, read from the data rather than from what was rendered."""
    flags = []
    if res["bogon"].ok and res["bogon"].value["listed"]:
        flags.append("bogon")
    if any(row["key"] == "tor-exit" and row.get("listed") for row in feed_rows):
        flags.append("Tor exit node")
    ipapi_result, shodan = res.get("ipapi"), res.get("shodan")
    if ipapi_result and ipapi_result.ok:
        if ipapi_result.value.get("proxy"):
            flags.append("proxy or VPN (ip-api.com)")
        if ipapi_result.value.get("hosting"):
            flags.append("datacenter address")
    if shodan and shodan.ok and shodan.value.get("found") and shodan.value["vulns"]:
        flags.append(f"{plural(len(shodan.value['vulns']), 'known CVE')} on exposed services (Shodan)")
    return flags


def cmd_reputation_ip(ctx):
    args, client, out, feeds = ctx.args, ctx.client, ctx.out, ctx.feeds
    ip = args.target
    parsed = ipaddress.ip_address(ip)
    routable = parsed.is_global and not parsed.is_multicast
    out.header(ip, "IP reputation")
    bogon_zone = "v4.fullbogons.cymru.com" if parsed.version == 4 else "v6.fullbogons.cymru.com"
    jobs = {"bogon": (dnsbl_ip, (client, ip, bogon_zone, BOGON_CODES))}
    if routable:
        jobs["zen"] = (dnsbl_ip, (client, ip, "zen.spamhaus.org", ZEN_CODES))
        if parsed.version == 4:
            jobs["spamcop"] = (dnsbl_ip, (client, ip, "bl.spamcop.net", SPAMCOP_CODES))
        jobs["feeds"] = (feeds.check_ip, (ip,))
        jobs["shodan"] = (internetdb, (client, ip))
        jobs["ipapi"] = (ipapi, (client, ip))
        jobs["robtex"] = (robtex_ip, (client, ip))
        for env, key, _, function in KEYED_SOURCES:
            if os.environ.get(env):
                jobs[key] = (function, (client, ip, os.environ[env]))
    res = gather(jobs)
    tally, feed_rows = [], []
    if routable:
        feed_rows = res["feeds"].value if res["feeds"].ok else [
            {"key": key, "label": label, "listed": None, "error": res["feeds"].error}
            for key, label in (("spamhaus-drop", "Spamhaus DROP"), ("feodo-c2", "Feodo Tracker C2"), ("tor-exit", "Tor exit list"))]
        out.section("Blocklists", "blocklists")
        tally.append(("Spamhaus ZEN", dnsbl_row(out, "spamhaus-zen", "Spamhaus ZEN", res["zen"]), True))
        if "spamcop" in res:
            tally.append(("SpamCop", dnsbl_row(out, "spamcop", "SpamCop", res["spamcop"]), True))
        for row in feed_rows:
            if row["key"] != "tor-exit":
                tally.append((row["label"], feed_row(out, row), True))
        for env, key, label, _ in KEYED_SOURCES:
            tally.append((label, keyed_row(out, key, label, env, res.get(key)), True))

    out.section("Profile", "profile")
    tally.append(("Team Cymru bogons", bogon_row(out, res["bogon"]), False))
    if not routable:
        out.status("scope", "Address scope", "warn", scope_description(parsed), "public reputation sources do not track it")
        return
    for row in feed_rows:
        if row["key"] == "tor-exit":
            tally.append((row["label"], feed_row(out, row, listed_state="warn", listed_word="Tor exit",
                                                 clean_word="not a Tor exit"), False))
    tally.append(("ip-api.com", ipapi_row(out, res["ipapi"]), False))
    tally.append(("Shodan InternetDB", shodan_row(out, res["shodan"]), False))
    tally.append(("Robtex passive DNS", robtex_row(out, res["robtex"]), False))
    show_exposed_services(out, res["shodan"])
    show_passive_names(out, res["robtex"])
    summary(out, tally, ip_flags(res, feed_rows))
    out.note(REPUTATION_NOTE)
    out.next_steps(suggest([("ip", ip), ("abuse", ip)]))


@guarded(default="error")
def filter_row(out, key, label, result):
    if not result.ok:
        out.status(key, label, "error", "unknown", result.error)
        return "error"
    data = result.value
    filtered, unfiltered = data["filtered"], data["unfiltered"]
    if data["blocked"] is True:
        out.status(key, label, "bad", "blocked", f"answered {describe_dns_answer(filtered)}")
        return "bad"
    if data["blocked"] is False:
        out.status(key, label, "good", "not blocked")
        return "good"
    if unfiltered.get("status") != 0 or not unfiltered.get("answers"):
        out.status(key, label, "info", "no verdict", f"the name does not resolve normally ({describe_dns_answer(unfiltered)})")
        return "info"
    out.status(key, label, "error", "unknown", f"the filtering resolver answered {describe_dns_answer(filtered)}, "
                                              "which neither shows nor rules out a block")
    return "error"


@guarded(default="error")
def address_feed_row(out, ip, rows):
    """One address of a domain against the cached feeds; a failed feed is shown, never folded into 'no matches'."""
    hits = [row for row in rows if row.get("listed") and row["key"] != "tor-exit"]
    errors = [row for row in rows if row.get("error")]
    tor = any(row.get("listed") for row in rows if row["key"] == "tor-exit")
    stale = [f"{row['label']} ({row['feed']['warning']})" for row in rows if (row.get("feed") or {}).get("warning")]
    stale_text = f"stale copy of {'; '.join(stale)}" if stale else ""
    state = "good"
    if hits:
        detail = "; ".join(f"{row['label']}: {', '.join(row['detail'])}" for row in hits)
        out.status(ip, ip, "bad", "listed", " · ".join(filter(None, [detail, stale_text])))
        state = "bad"
    elif not errors:
        state = "warn" if stale else "good"
        out.status(ip, ip, state, "no feed matches", " · ".join(filter(None, ["Tor exit node" if tor else "", stale_text])))
    if errors:
        out.status(ip, ip, "error", "unknown", "; ".join(f"{row['label']}: {row['error']}" for row in errors))
        state = "error"
    return state


def cmd_reputation_domain(ctx):
    args, client, out, feeds = ctx.args, ctx.client, ctx.out, ctx.feeds
    name = args.target
    out.header(name, "domain reputation")
    res = gather({
        "dbl": (lambda: dnsbl_domain(client, name, "dbl.spamhaus.org", codes=DBL_CODES), ()),
        "surbl": (lambda: dnsbl_domain(client, name, "multi.surbl.org", bitmask=SURBL_BITS), ()),
        "cloudflare": (cloudflare_filter, (client, name)),
        "quad9": (quad9_filter, (client, name)),
        "robtex": (robtex_domain, (client, name)),
        "A": (client.dns_values, (name, "A")),
        "AAAA": (client.dns_values, (name, "AAAA")),
    })
    tally, flags = [], []
    out.section("Blocklists", "blocklists")
    tally.append(("Spamhaus DBL", dnsbl_row(out, "spamhaus-dbl", "Spamhaus DBL", res["dbl"]), True))
    tally.append(("SURBL", dnsbl_row(out, "surbl", "SURBL", res["surbl"]), True))
    tally.append(("Cloudflare filter", filter_row(out, "cloudflare-filter", "Cloudflare filter", res["cloudflare"]), True))
    tally.append(("Quad9 filter", filter_row(out, "quad9-filter", "Quad9 filter", res["quad9"]), True))

    ips, failed = [], []
    for kind in ("A", "AAAA"):
        if res[kind].ok:
            ips += [address(v) for v in res[kind].value if address(v) not in ips]
        else:
            failed.append(kind)
    checks = gather({ip: (feeds.check_ip, (ip,)) for ip in ips[:args.max_ips]})
    out.section("Addresses", "addresses", source="Spamhaus DROP · Feodo Tracker · Tor exit list")
    for kind in failed:
        out.error(f"{kind} lookup: {res[kind].error}")
        tally.append((f"{kind} lookup", "error", False))
    if not ips and not failed:
        out.kv("addresses", "none: the name has no A or AAAA records", tone="dim")
    for ip, result in checks.items():
        rows = result.value if result.ok else [{"label": "feeds", "listed": None, "error": result.error, "key": "feeds"}]
        tally.append((f"feeds for {ip}", address_feed_row(out, ip, rows), False))
        hits = [row["label"] for row in rows if row.get("listed") and row["key"] != "tor-exit"]
        if hits:
            flags.append(f"{ip} on {', '.join(hits)}")
        if any(row.get("listed") for row in rows if row["key"] == "tor-exit"):
            flags.append(f"{ip} is a Tor exit node")
    if len(ips) > args.max_ips:
        out.note(f"Checked {args.max_ips} of {len(ips)} addresses; use --max-ips to check more.")

    out.section("Passive DNS", "passive-dns", source="Robtex")
    robtex = res["robtex"]
    if not robtex.ok:
        out.error(robtex.error)
        tally.append(("Robtex passive DNS", "error", False))
    elif not robtex.value["records"]:
        out.kv("records", "none: Robtex has not seen this name", tone="dim")
    else:
        def day(value):
            when = parse_time(value)
            return f"{when:%Y-%m-%d}" if when else "-"

        out.table(["TYPE", "FIRST SEEN", "LAST SEEN", "VALUE"],
                  [[r.get("rrtype") or "?", day(r.get("time_first")), day(r.get("time_last")), r.get("rrdata") or ""]
                   for r in robtex.value["records"]], limit=15)
    summary(out, tally, flags)
    out.note(REPUTATION_NOTE + " Domain lists also track abused legitimate sites.")
    out.next_steps(suggest([("domain", name), *[("reputation", ip) for ip in ips]]))


def cmd_reputation_asn(ctx):
    out = ctx.out
    value = ctx.args.target
    out.header(value, "AS reputation")
    result = attempt(ctx.feeds.check_asn, value)
    out.section("Blocklists", "blocklists")
    state = asn_drop_row(out, result)
    summary(out, [("Spamhaus ASN-DROP", state, True)])
    out.next_steps(suggest([("asn", value), ("routes", value)]))


def cmd_reputation_prefix(ctx):
    out = ctx.out
    target = ctx.args.target
    out.header(target, "prefix reputation")
    result = attempt(ctx.feeds.check_prefix, target)
    rows = result.value if result.ok else [{"key": "feeds", "label": "feeds", "listed": None, "error": result.error}]
    tally, flags = [], []
    out.section("Blocklists", "blocklists")
    for row in rows:
        if row["key"] == "spamhaus-drop":
            tally.append((row["label"], feed_row(out, row, listed_word="overlaps"), True))
    for row in rows:
        if row["key"] == "feodo-c2":
            state = feed_row(out, row, listed_word="C2 inside", clean_word="none inside")
            tally.append((row["label"], state, True))
        elif row["key"] == "tor-exit":
            state = feed_row(out, row, listed_state="warn", listed_word="exits inside", clean_word="none inside")
            if state == "warn":
                flags.append(f"Tor exit nodes inside ({', '.join(row['detail'])})")
            tally.append((row["label"], state, False))
        elif row["key"] == "feeds":
            tally.append(("feeds", feed_row(out, row), True))
    summary(out, tally, flags)
    out.next_steps(suggest([("prefix", target)]))


def cmd_reputation(ctx):
    {"ip": cmd_reputation_ip, "domain": cmd_reputation_domain,
     "asn": cmd_reputation_asn, "prefix": cmd_reputation_prefix}[ctx.args.kind](ctx)


def rpki_validation(client, route, origin):
    source = "RIPEstat rpki-validation"
    data = require(client.ripe("rpki-validation", resource=origin[2:], prefix=route), "status", source=source)
    expect(data["status"], str, source, "status")
    expect_list(data.get("validating_roas") or [], dict, source, "validating_roas")
    return data


def ripestat_whois(client, target):
    source = "RIPEstat whois"
    data = client.ripe("whois", resource=target)
    for field in ("records", "irr_records"):
        for group in expect_list(data.get(field) or [], list, source, field):
            expect_list(group, dict, source, field)
    expect_list(data.get("authorities") or [], str, source, "authorities")
    return data


def abuse_contacts(client, target):
    source = "RIPEstat abuse-contact-finder"
    data = require(client.ripe("abuse-contact-finder", resource=target), "abuse_contacts", source=source)
    expect_list(data["abuse_contacts"], str, source, "abuse_contacts")
    expect(data.get("authoritative_rir"), TEXT, source, "authoritative_rir")
    return data


def asn_neighbors(client, value):
    source = "RIPEstat asn-neighbours"
    data = require(client.ripe("asn-neighbours", resource=value), "neighbours", source=source)
    for item in expect_list(data["neighbours"], dict, source, "neighbours"):
        expect(item.get("type", item.get("position", "unknown")), str, source, "type")
        for field in ("asn", "power", "v4_peers", "v6_peers"):
            expect(item.get(field), NUMBER, source, field)
    return data


def cmd_rpki(ctx):
    args, client, out = ctx.args, ctx.client, ctx.out
    route, origin = args.target, args.asn
    out.header(f"{route} · {origin}", "RPKI origin validation")
    result = attempt(rpki_validation, client, route, origin)
    out.section("RPKI origin validation", "rpki", source="RIPEstat")
    if not result.ok:
        out.error(result.error)
        return
    data = result.value
    status = str(data.get("status") or "unknown")
    state, word, detail = RPKI_STATES.get(status, ("warn", status, ""))
    out.status("rpki", f"{route} from {origin}", state, word, detail)
    roas = data.get("validating_roas") or []
    if roas:
        out.section("Covering ROAs", "roas")
        out.table(["ORIGIN", "ROA PREFIX", "MAX LENGTH", "RESULT"],
                  [[f"AS{roa.get('origin')}", roa.get("prefix"), roa.get("max_length"),
                    (roa.get("validity") or "?", "good" if roa.get("validity") == "valid" else "bad")] for roa in roas])
    out.next_steps(suggest([("prefix", route), ("asn", origin)]))


def cmd_ripestat(ctx):
    client, out, target = ctx.client, ctx.out, ctx.args.target
    out.header(target, "RIPEstat WHOIS")
    result = attempt(ripestat_whois, client, target)
    if not result.ok:
        out.section("Registry records", "records", source="RIPEstat")
        out.error(result.error)
        return
    data = result.value
    for field, title, slug in (("records", "Registry records", "records"), ("irr_records", "IRR records", "irr")):
        groups = data.get(field) or []
        authorities = ", ".join(data.get("authorities") or []) if field == "records" else None
        out.section(title, slug, source=f"RIPEstat · {authorities}" if authorities else "RIPEstat")
        if not groups:
            out.kv("records", "none", tone="dim")
        for index, group in enumerate(groups):
            if index:
                out.blank()
            for item in group:
                out.kv(str(item.get("key", "?")), item.get("value"))


def cmd_abuse(ctx):
    client, out, target = ctx.client, ctx.out, ctx.args.target
    out.header(target, "abuse contact")
    result = attempt(abuse_contacts, client, target)
    out.section("Abuse contact", "abuse", source="RIPEstat")
    if not result.ok:
        out.error(result.error)
        return
    contacts = result.value.get("abuse_contacts") or []
    out.kv("contact", contacts or "none published", tone=None if contacts else "warn")
    registry = result.value.get("authoritative_rir")
    out.kv("registry", registry.upper() if registry else None)


def cmd_neighbors(ctx):
    client, out, value = ctx.client, ctx.out, ctx.args.target
    out.header(value, "BGP neighbors")
    result = attempt(asn_neighbors, client, value)
    out.section("Neighbors", "neighbors", source="RIPEstat · RIS AS paths")
    if not result.ok:
        out.error(result.error)
        return
    items = result.value.get("neighbours") or []
    counts = Counter(n.get("type", n.get("position", "unknown")) for n in items)
    out.kv("total", plural(len(items), "neighbor"))
    out.kv("positions", " · ".join(f"{kind} {count}" for kind, count in sorted(counts.items())))
    rows = sorted(items, key=lambda n: (-(n.get("power") or 0), n.get("asn") or 0))
    out.table(["POSITION", "NEIGHBOR", "POWER", "IPv4 PEERS", "IPv6 PEERS"],
              [[n.get("type", n.get("position", "?")), f"AS{n.get('asn')}", n.get("power"), n.get("v4_peers"), n.get("v6_peers")]
               for n in rows], limit=40)
    out.note("left: the neighbor sits before this AS in collected paths (usually an upstream); right: after it "
             "(usually a customer); power: how many paths show the adjacency. Positions do not prove a commercial relationship.")
    out.next_steps(suggest([("ix", value), ("routes", value)]))


def cmd_ix(ctx):
    client, out, value = ctx.client, ctx.out, ctx.args.target
    out.header(value, "exchange presence")
    result = attempt(client.peering, value, 2)
    if not result.ok or not result.value:
        out.section("Exchange presence", "ix", source="PeeringDB")
        if result.ok:
            out.kv("record", "not in PeeringDB", tone="dim")
        else:
            out.error(result.error)
        return
    for net in result.value:
        out.section(net.get("name") or value, "ix", source="PeeringDB")
        out.kv("presence", f"{plural(net.get('ix_count') or 0, 'exchange')} · "
                           f"{plural(net.get('fac_count') or 0, 'facility', 'facilities')}")
        out.kv("as-set", net.get("irr_as_set"))
        links = sorted(net.get("netixlan_set") or [], key=lambda x: str(x.get("name") or "").lower())
        out.table(["EXCHANGE", "IPv4", "IPv6", "SPEED", "RS PEER"],
                  [[x.get("name") or "?", x.get("ipaddr4") or "-", x.get("ipaddr6") or "-", link_speed(x.get("speed")),
                    "yes" if x.get("is_rs_peer") else "no"] for x in links])


def cmd_as_set(ctx):
    args, client, out = ctx.args, ctx.client, ctx.out
    query = f"!i{args.target}" + (",1" if args.recursive else "")
    result = attempt(lambda: parse_radb(client.whois("whois.radb.net", query)))
    if not result.ok:
        out.raw_error(result.error)
    elif not result.value:
        out._print("no members: the set does not exist or is empty", sys.stderr)
    else:
        out.raw_lines(result.value)


def cmd_bulk(ctx):
    host = "bgp.tools" if ctx.args.command == "bulk-bgp" else "whois.cymru.com"
    result = attempt(ctx.client.tcp, host, ctx.args.bulk_payload)
    if result.ok:
        ctx.out.raw_lines(result.value.rstrip("\n").splitlines())
    else:
        ctx.out.raw_error(result.error)


def cmd_ris_peers(ctx):
    result = attempt(ctx.client.whois, "riswhois.ripe.net", "peers")
    if result.ok:
        ctx.out.raw_lines(strip_banner(result.value).rstrip("\n").splitlines())
    else:
        ctx.out.raw_error(result.error)


async def telnet_session(host, timeout):
    try:
        import telnetlib3
    except ImportError as exc:
        raise UpstreamError("route-server sessions need telnetlib3; run 'netintel deps' for installation instructions") from exc
    try:
        _, writer = await telnetlib3.open_connection(
            host, 23, shell=telnetlib3.telnet_client_shell, connect_timeout=timeout,
        )
        await writer.protocol.waiter_closed
    except OSError as exc:
        raise UpstreamError(f"{host}:23: {exc}") from exc


def cmd_telnet(ctx):
    host = "route-views.routeviews.org" if ctx.args.command == "routeviews" else "route-server.he.net"
    try:
        asyncio.run(telnet_session(host, ctx.args.timeout))
    except UpstreamError as exc:
        ctx.out.raw_error(str(exc))


def cmd_check(ctx):
    args, client, out, feeds = ctx.args, ctx.client, ctx.out, ctx.feeds
    out.header(f"netintel {VERSION}", "environment check")
    out.section("Environment", "environment")
    python_ok = sys.version_info >= (3, 10)
    out.status("python", "Python", "good" if python_ok else "error", sys.version.split()[0],
               sys.executable if python_ok else "Python 3.10 or newer is required")
    for package, label, required, use in (("dns", "dnspython", True, "all DNS lookups"),
                                          ("telnetlib3", "telnetlib3", False, "routeviews and he only")):
        installed = importlib.util.find_spec(package) is not None
        if installed:
            out.status(package, label, "good", "installed", use)
        else:
            out.status(package, label, "error" if required else "skip", "missing" if required else "not installed",
                       f"needed for {use}; run 'netintel deps'")
    out.status("resolver", "DNS resolver", "info", client.resolver_label)
    keys = [env for env in API_KEYS if os.environ.get(env)]
    out.status("api-keys", "API keys", "info", f"{len(keys)} of {len(API_KEYS)} set", ", ".join(keys) or "optional: " + ", ".join(API_KEYS))

    out.section("Feed cache", "feed-cache", source=str(feeds.cache_dir))
    for row in feeds.status():
        if not row["cached"]:
            out.status(row["key"], row["label"], "skip", "not cached", "downloaded on first use")
        elif row["stale"]:
            out.status(row["key"], row["label"], "warn", "stale", f"downloaded {ago(row['fetched'])}; refreshed on next use")
        else:
            out.status(row["key"], row["label"], "good", "cached", f"downloaded {ago(row['fetched'])}")
    out.note(f"Feeds are reused for {short_ttl(feeds.ttl)} (NETINTEL_FEED_TTL); --refresh forces a download.")
    if not args.net:
        out.note("Add --net to test DNS, HTTPS and WHOIS reachability.")
        return

    jobs = {"dns": (client.dns_values, ("1.1.1.1.origin.asn.cymru.com", "TXT")),
            "path": (interception_probe, (min(client.timeout, 8),)),
            "ripestat": (client.network, ("1.1.1.1",)),
            "rdap": (lambda: client.rdap("ip", "1.1.1.1"), ()),
            "peeringdb": (lambda: client.peering("AS13335"), ()),
            "doh": (client.doh_json, ("https://cloudflare-dns.com/dns-query", "example.com")),
            "internetdb": (internetdb, (client, "1.1.1.1")),
            "feed": (feeds.load, ("spamhaus_drop_v4",))}
    for host in WHOIS_HOSTS:
        jobs[host] = (tcp_probe, (host, 43, client.timeout))
    res = gather(jobs, workers=12)
    out.section("Connectivity", "connectivity")
    dns_result = res["dns"]
    if not dns_result.ok:
        out.status("dns", "DNS", "error", "failed", dns_result.error)
    elif any("13335" in value for value in dns_result.value):
        out.status("dns", "DNS", "good", "answered", f"{client.resolver_label} · {dns_result.elapsed:.2f}s")
    else:
        out.status("dns", "DNS", "warn", "odd answer", ", ".join(dns_result.value) or "empty answer")
    path = res["path"]
    if not path.ok:
        out.status("resolver-path", "Resolver path", "error", "unknown", path.error)
    else:
        state = {"direct": "good", "no-path": "warn"}.get(path.value["state"], "warn")
        out.status("resolver-path", "Resolver path", state, path.value["state"], path.value["verdict"])
    for key, label in (("ripestat", "RIPEstat"), ("rdap", "rdap.org"), ("peeringdb", "PeeringDB"),
                       ("doh", "Cloudflare DoH"), ("internetdb", "Shodan InternetDB"), ("feed", "Spamhaus feed")):
        result = res[key]
        if result.ok:
            out.status(key, label, "good", "reachable", f"{result.elapsed:.2f}s")
        else:
            out.status(key, label, "error", "failed", result.error)
    for host in WHOIS_HOSTS:
        result = res[host]
        if result.ok:
            out.status(host, f"{host}:43", "good", "reachable", f"{result.elapsed:.2f}s")
        else:
            out.status(host, f"{host}:43", "error", "failed", result.error)


COMMANDS = {"domain": cmd_domain, "ip": cmd_ip, "asn": cmd_asn, "prefix": cmd_prefix, "routes": cmd_routes,
            "reputation": cmd_reputation, "rpki": cmd_rpki, "ripestat": cmd_ripestat, "abuse": cmd_abuse,
            "neighbors": cmd_neighbors, "ix": cmd_ix, "as-set": cmd_as_set, "bulk-bgp": cmd_bulk,
            "bulk-cymru": cmd_bulk, "ris-peers": cmd_ris_peers, "routeviews": cmd_telnet, "he": cmd_telnet,
            "check": cmd_check}


# ---------- command line ----------

class Parser(argparse.ArgumentParser):
    def error(self, message):
        program = self.prog.split()[0]
        self.exit(2, f"{self.prog}: error: {message}\nRun '{program} help' for usage.\n")


def bulk_request(lines):
    values = []
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            kind, value = detect(line)
            if kind not in {"ip", "asn"}:
                raise ValueError("bulk input accepts IPs and ASNs only")
            values.append(value)
        except ValueError as exc:
            raise ValueError(f"bulk input line {number}: {exc}") from exc
    if not values:
        raise ValueError("bulk input contains no IPs or ASNs")
    return "begin\r\nverbose\r\n" + "\r\n".join(values) + "\r\nend\r\n"


def build_parser():
    shared = argparse.ArgumentParser(add_help=False)
    # Suppressed defaults allow flags both before and after a subcommand.
    shared.add_argument("-g", "--grep", action="store_true", default=argparse.SUPPRESS,
                        help="one fact per line, tab-separated: target, section, field, value (no color, nothing truncated)")
    shared.add_argument("--color", choices=("auto", "always", "never"), default=argparse.SUPPRESS,
                        help="color output (default auto: only on a terminal, and never when NO_COLOR is set)")
    shared.add_argument("--quick", action="store_true", default=argparse.SUPPRESS, help="skip WHOIS sections in ip/asn/prefix")
    shared.add_argument("--timeout", type=positive_timeout, default=argparse.SUPPRESS, help="network timeout in seconds (default 30)")
    shared.add_argument("--max-ips", type=positive_count, default=argparse.SUPPRESS, help="maximum domain addresses to enrich (default 16)")
    shared.add_argument("--resolver", default=argparse.SUPPRESS,
                        help="DNS resolver: IP, hostname, or IP#certificate-name; queried over DNS over TLS by default")
    shared.add_argument("--dns-transport", choices=DNS_TRANSPORTS, default=argparse.SUPPRESS,
                        help="auto (tls with --resolver, else system udp), udp, tcp or tls")
    shared.add_argument("--refresh", action="store_true", default=argparse.SUPPRESS, help="re-download cached blocklist feeds")
    parser = Parser(
        description="Start with a domain, IP, CIDR prefix or ASN. No shell tools required.",
        epilog="Examples: netintel example.com | netintel 1.1.1.1 --quick | netintel reputation 1.1.1.1 | netintel asn AS13335 --grep",
        parents=[shared],
    )
    parser.add_argument("--version", action="version", version=f"netintel {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    descriptions = {
        "lookup": "automatically detect the target type", "domain": "DNS, DNSSEC, email auth, registration, CT and serving networks",
        "ip": "reverse DNS, BGP origins and registration", "asn": "ASN identity, registration, PeeringDB and ASN-DROP",
        "prefix": "BGP, IRR, registration and live AS paths", "routes": "compare observed and registered routes",
        "reputation": "blocklists, filtering resolvers, exposed services and passive DNS",
        "as-set": "expand an IRR AS-SET", "rpki": "validate prefix/origin against ROAs",
        "ripestat": "RIPEstat WHOIS aggregation", "abuse": "find abuse contacts",
        "neighbors": "observed AS-path adjacencies", "ix": "PeeringDB exchange presence",
        "bulk-bgp": "bgp.tools bulk query", "bulk-cymru": "Team Cymru bulk query",
        "ris-peers": "list RIS peers", "routeviews": "interactive RouteViews session",
        "he": "interactive Hurricane Electric session", "check": "check dependencies, configuration and connectivity",
        "deps": "show installation instructions", "version": "show version", "help": "show help",
    }
    aliases = {"neighbors": ["neighbours"], "reputation": ["rep"]}
    for name, description in descriptions.items():
        command = sub.add_parser(name, help=description, parents=[shared], aliases=aliases.get(name, []))
        if name in {"lookup", "domain", "ip", "asn", "prefix", "routes", "reputation", "as-set", "rpki", "ripestat", "abuse", "neighbors", "ix"}:
            command.add_argument("target")
        if name == "rpki":
            command.add_argument("asn")
        if name == "as-set":
            command.add_argument("--recursive", action="store_true")
        if name.startswith("bulk-"):
            command.add_argument("file", nargs="?", default="-")
        if name == "check":
            command.add_argument("--net", action="store_true")
    return parser, set(descriptions) | {alias for names in aliases.values() for alias in names}


def parse_args(argv):
    parser, commands = build_parser()
    argv = list(argv)
    # Insert 'lookup' before the first positional target, skipping global option values.
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in {"--timeout", "--max-ips", "--resolver", "--dns-transport", "--color"}:
            index += 2
            continue
        if item.startswith("-"):
            index += 1
            continue
        if item not in commands:
            argv.insert(index, "lookup")
        break
    if not argv:
        argv = ["help"]
    args = parser.parse_args(argv)
    args.grep = getattr(args, "grep", False)
    args.color = getattr(args, "color", "auto")
    args.quick = getattr(args, "quick", False)
    args.refresh = getattr(args, "refresh", False)
    args.resolver = getattr(args, "resolver", None)
    args.dns_transport = getattr(args, "dns_transport", "auto")
    try:
        args.timeout = positive_timeout(getattr(args, "timeout", os.environ.get("NETINTEL_TIMEOUT", "30")))
        args.max_ips = positive_count(getattr(args, "max_ips", os.environ.get("NETINTEL_MAX_IPS", "16")))
        if args.resolver:
            args.resolver = resolver_spec(args.resolver)
        args.command = {"neighbours": "neighbors", "rep": "reputation"}.get(args.command, args.command)
        if args.command == "lookup":
            args.command, args.target = detect(args.target)
        elif args.command == "reputation":
            args.kind, args.target = detect(args.target)
        elif args.command == "domain":
            args.target = domain(args.target)
        elif args.command == "ip":
            args.target = address(args.target)
        elif args.command in {"asn", "routes", "neighbors", "ix"}:
            args.target = asn(args.target)
        elif args.command in {"prefix", "rpki"}:
            if args.command == "rpki" and "/" not in args.target:
                raise ValueError("RPKI requires a CIDR prefix")
            args.target = prefix(args.target)
            if args.command == "rpki":
                args.asn = asn(args.asn)
        elif args.command in {"ripestat", "abuse"}:
            args.target = resource(args.target)
        elif args.command == "as-set":
            args.target = args.target.upper()
            if not re.fullmatch(r"(?:AS[0-9]+:|AS-[A-Z0-9_-]+:)*AS-[A-Z0-9_-]+", args.target):
                raise ValueError("expected an AS-SET such as AS-EXAMPLE or AS13335:AS-EXAMPLE")
        if args.command in {"routeviews", "he"} and not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise ValueError("interactive route-server sessions need a terminal on stdin and stdout")
        if args.command.startswith("bulk-"):
            if args.file == "-":
                if sys.stdin.isatty():
                    print("reading IPs/ASNs from stdin; end with Ctrl-D", file=sys.stderr, flush=True)
                args.bulk_payload = bulk_request(sys.stdin)
            else:
                with open(args.file, encoding="utf-8") as stream:
                    args.bulk_payload = bulk_request(stream)
    except (ValueError, OSError, argparse.ArgumentTypeError) as exc:
        parser.error(str(exc))
    return args, parser


def use_color(choice, stream):
    if choice == "always":
        return True
    if choice == "never" or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return stream.isatty() and os.environ.get("TERM") != "dumb"


def supports_unicode(stream):
    try:
        "✓✗•–·…".encode(getattr(stream, "encoding", None) or "ascii")  # noqa: RUF001
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def make_output(args):
    target = getattr(args, "target", None) or ("netintel" if args.command == "check" else args.command)
    unicode = supports_unicode(sys.stdout)
    if args.grep:
        return GrepOutput(target, unicode)
    width = shutil.get_terminal_size((100, 24)).columns if sys.stdout.isatty() else 100
    return HumanOutput(target, color=use_color(args.color, sys.stdout), width=max(60, min(width, 160)), unicode=unicode)


DEPS_TEXT = """Python 3.10+ and Python packages only:
Install the app from its source directory with pipx:
  pipx install .
  netintel check --net

Or use a project virtual environment:
  python3 -m venv .venv
  .venv/bin/python -m pip install .
  .venv/bin/python netintel.py check

dnspython handles DNS (UDP, TCP and DNS over TLS); telnetlib3 handles interactive route servers.
WHOIS, HTTP, DNS over HTTPS (JSON), IP validation and feeds use Python's standard library.
No dig, whois, curl, jq, nc, timeout or telnet executables are needed.

Output is colored sections on a terminal; --grep prints tab-separated lines instead.
NO_COLOR disables color; --color always forces it (for example when piping into less -R).

Optional keys, read from the environment and sent only to the named service:
  PEERINGDB_API_KEY   PeeringDB (lifts the anonymous rate limit)
  ABUSEIPDB_API_KEY   AbuseIPDB reports in 'reputation' (free tier available)
  GREYNOISE_API_KEY   GreyNoise community scanner classification in 'reputation'
Blocklist feeds are cached under $XDG_CACHE_HOME/netintel (default ~/.cache/netintel)."""


def main(argv=None):
    args, parser = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "help":
        parser.print_help()
        return 0
    if args.command == "version":
        print(f"netintel {VERSION}")
        return 0
    if args.command == "deps":
        print(DEPS_TEXT)
        return 0
    client = Client(args.timeout, args.resolver, args.dns_transport)
    cache_dir = os.environ.get("NETINTEL_CACHE_DIR") or Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "netintel"
    try:
        ttl = max(0, int(os.environ.get("NETINTEL_FEED_TTL", "86400")))
    except ValueError:
        ttl = 86400
    out = make_output(args)
    ctx = SimpleNamespace(args=args, client=client, feeds=Feeds(client, cache_dir, ttl, args.refresh), out=out)
    try:
        COMMANDS[args.command](ctx)
    except UpstreamError as exc:
        out.error(str(exc))
    except BrokenPipeError:
        raise
    except Exception as exc:
        if os.environ.get("NETINTEL_DEBUG"):
            raise
        out.error(f"internal error while building the report: {type(exc).__name__}: {exc} "
                  "(the output above is incomplete; set NETINTEL_DEBUG=1 for a traceback)")
    return out.finish()


def cli():
    """Shared entry point for pipx's console command and direct execution."""
    try:
        return main()
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr, flush=True)
        sys.stdout.flush()
        os._exit(130)  # do not wait for worker threads still blocked on the network
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(cli())
