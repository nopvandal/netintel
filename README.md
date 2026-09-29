# netintel

A command-line tool for DNS, routing, registration, and reputation lookups.
Give it a domain, IP address, prefix, or ASN:

```sh
netintel example.com
netintel 1.1.1.1
netintel 1.1.1.0/24
netintel AS13335
```

Reports include suggested commands for following up on an address, network, or
origin ASN.

## Install

Requires Python 3.10 or newer and [pipx](https://pipx.pypa.io/).
From a checkout of this repository:

```sh
pipx install .
netintel check
```

If your shell can't find `netintel`, run `pipx ensurepath` and open a new terminal.
After pulling an update, run `pipx reinstall netintel`.

The dependencies are `dnspython` for DNS and `telnetlib3` for interactive route
servers. You don't need separate `dig`, `whois`, or `telnet` commands installed.

## Usage

```sh
# DNS, email authentication, registration, certificates, and serving networks
netintel example.com

# Routing and registration, without the extra WHOIS queries
netintel 1.1.1.1 --quick

# Reputation checks for a domain or address
netintel reputation example.com
netintel reputation 1.1.1.1

# Compare observed BGP routes with IRR registrations
netintel routes AS13335

# Check a prefix and its origin against RPKI records
netintel rpki 1.1.1.0/24 AS13335

# Exchange presence and observed AS-path neighbors
netintel ix AS13335
netintel neighbors AS13335

# Published abuse contacts
netintel abuse 1.1.1.1
```

Targets are hostnames, not URLs. IPv6 and internationalized domain names are
supported. Prefixes with host bits are normalized to their containing network.
Private addresses skip public routing and registration lookups.

### Output

Terminal output uses color and these status marks:

| Mark | Meaning |
| --- | --- |
| `✓` | Clean or successful result |
| `✗` | Listing or other adverse result |
| `!` | Warning |
| `?` | Lookup failed or could not be checked |
| `•` | Information |
| `–` | Check skipped |

Use `--grep` for uncolored, tab-separated output with full lists. Each line
starts with the target and section, followed by the fields for that result.

```sh
netintel example.com --grep > example.tsv
netintel example.com --grep | awk -F'\t' '$2 == "registration"'
netintel routes AS13335 --grep | awk -F'\t' '$2 == "observed-only"'
```

`--color always` keeps color when piping to `less -R`. `--color never` and
`NO_COLOR` disable it.

Exit codes are `0` for completed lookups, `1` for partial results or failed
lookups, `2` for invalid input, and `130` for an interrupted run. A blocklist
match by itself does not cause a nonzero exit code.

### DNS resolvers

The default is the system resolver over UDP. Setting `--resolver` selects DNS
over TLS unless you specify another transport:

```sh
netintel example.com --resolver 1.1.1.1
netintel example.com --resolver dns.quad9.net
netintel example.com --resolver 10.0.0.53 --dns-transport udp
```

TLS checks the resolver's certificate. Known public resolver addresses use their
configured certificate names; other addresses must match the certificate's IP
address. For a server whose certificate contains only a hostname, use
`--resolver ADDRESS#NAME`:

```sh
netintel example.com --resolver 203.0.113.53#dns.example.net
```

Some networks redirect port 53 traffic to a local DNS proxy. `netintel check
--net` compares resolver identities over UDP and TLS to help spot this, and
checks connectivity to the other services.

### Options

Options can go before or after the command.

| Option | Purpose |
| --- | --- |
| `--quick` | Skip WHOIS sections in `ip`, `asn`, and `prefix` |
| `--timeout SECONDS` | Network timeout; default 30 |
| `--max-ips N` | Maximum addresses to look up for a domain; default 16 |
| `--refresh` | Re-download cached blocklist feeds |
| `--resolver ADDRESS` | DNS resolver IP, hostname, or `ADDRESS#NAME` |
| `--dns-transport auto\|udp\|tcp\|tls` | DNS transport |
| `--grep`, `-g` | Tab-separated output |
| `--color auto\|always\|never` | Color control |

Timeouts apply to individual DNS queries and socket operations, not to the
whole report. WHOIS reads also have an overall deadline. Independent lookups run
concurrently, but queries that depend on earlier results add to the total time.

### Commands

| Command | Purpose |
| --- | --- |
| `lookup TARGET` or `TARGET` | Detect the target type |
| `domain DOMAIN` | DNS, DNSSEC, SPF/DMARC, registration, certificates, networks |
| `ip IP` | Reverse DNS, routing, RDAP, Cymru, WHOIS |
| `asn ASN` | Registration, Cymru, PeeringDB, ASN-DROP, WHOIS |
| `prefix IP_OR_CIDR` | RIS, IRR, RDAP, AS paths |
| `routes ASN` | Compare observed and registered routes |
| `reputation TARGET`, `rep TARGET` | Blocklists, filtering resolvers, services, passive DNS |
| `as-set SET [--recursive]` | IRR set members, one per line |
| `rpki PREFIX ASN` | Origin validation and matching ROAs |
| `ripestat RESOURCE` | RIPEstat WHOIS aggregation |
| `abuse RESOURCE` | Abuse contacts |
| `neighbors ASN`, `neighbours ASN` | Observed AS-path neighbors |
| `ix ASN` | PeeringDB exchange presence |
| `bulk-bgp [FILE]`, `bulk-cymru [FILE]` | Bulk lookups; reads stdin if no file is given |
| `ris-peers` | RIS peer listing |
| `routeviews`, `he` | Interactive Telnet sessions; requires a terminal |
| `check [--net]` | Dependencies, configuration, cache, optional connectivity checks |
| `deps`, `help`, `version` | Installation instructions, usage, version |

Bulk input accepts one IP or ASN per line. Blank lines and lines starting with
`#` are ignored:

```sh
printf '1.1.1.1\n8.8.8.8\nAS13335\n' | netintel bulk-cymru
```

`as-set` prints one member per line, so it works in pipelines:

```sh
netintel as-set AS-EXAMPLE --recursive | sort -u
```

## Configuration

| Environment variable | Default or use |
| --- | --- |
| `NETINTEL_TIMEOUT` | 30 seconds |
| `NETINTEL_MAX_IPS` | 16 addresses |
| `NETINTEL_CACHE_DIR` | `$XDG_CACHE_HOME/netintel`, or `~/.cache/netintel` |
| `NETINTEL_FEED_TTL` | 86400 seconds |
| `PEERINGDB_API_KEY` | Optional PeeringDB authentication |
| `ABUSEIPDB_API_KEY` | Enable AbuseIPDB reputation checks |
| `GREYNOISE_API_KEY` | Enable GreyNoise community checks |
| `NETINTEL_DEBUG` | Set to `1` to show tracebacks for internal errors |

API keys are read from the environment. Don't put them in source files.

Blocklist feeds are downloaded on first use and cached for a day. If a refresh
fails, an available cached copy is used and marked stale. Without a usable copy,
the check reports a failure.

## Data sources

The tables below list the services queried by the script. Which ones are used
depends on the command and target. Ordinary DNS records, reverse DNS, DNSSEC,
and SPF/DMARC records come through the system resolver or the resolver selected
with `--resolver`.

### Routing, registration, and certificates

| Source | Used for | Interface |
| --- | --- | --- |
| [RIPEstat](https://stat.ripe.net/docs/data-api/ripestat-data-api) | Network prefixes and origin ASNs, looking-glass paths, RPKI validation, WHOIS aggregation, abuse contacts, AS neighbors | HTTPS API at `stat.ripe.net` |
| [RIPE RIS](https://ris.ripe.net/) | Observed routes, prefix WHOIS, and RIS peer listings | WHOIS at `riswhois.ripe.net` |
| [RADb](https://www.radb.net/) | IRR route objects and AS-SET expansion | WHOIS at `whois.radb.net` |
| [RDAP.org](https://rdap.org/) | Domain, IP, and ASN registration | HTTPS bootstrap service; redirects to the responsible registry's RDAP service |
| [Team Cymru](https://www.team-cymru.com/ip-asn-mapping) | IP-to-ASN mapping, peer ASNs, ASN details, and bulk lookups | DNS under `asn.cymru.com`; WHOIS at `whois.cymru.com` |
| [bgp.tools](https://bgp.tools/) | IP/ASN WHOIS and bulk routing lookups | WHOIS at `bgp.tools` |
| [PeeringDB](https://www.peeringdb.com/) | Network profiles, exchange presence, and peering details | HTTPS API at `www.peeringdb.com/api/net` |
| [Cert Spotter / SSLMate](https://sslmate.com/help/reference/ct_search_api_v1) | Certificate Transparency issuances and certificate DNS names | HTTPS API at `api.certspotter.com/v1/issuances` |

### Reputation and filtering

| Source | Used for | Interface |
| --- | --- | --- |
| [Spamhaus ZEN and DBL](https://www.spamhaus.org/) | IP and domain blocklist checks | DNS: `zen.spamhaus.org`, `dbl.spamhaus.org` |
| Spamhaus DROP and ASN-DROP | Listed IPv4/IPv6 ranges and ASNs | Cached JSON feeds: [IPv4](https://www.spamhaus.org/drop/drop_v4.json), [IPv6](https://www.spamhaus.org/drop/drop_v6.json), [ASN](https://www.spamhaus.org/drop/asndrop.json) |
| [SURBL](https://www.surbl.org/) | Domain blocklist checks | DNS: `multi.surbl.org` |
| [SpamCop](https://www.spamcop.net/) | IP blocklist checks | DNS: `bl.spamcop.net` |
| [Team Cymru fullbogons](https://www.team-cymru.com/) | Bogon checks for IPv4 and IPv6 | DNS: `v4.fullbogons.cymru.com`, `v6.fullbogons.cymru.com` |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Botnet command-and-control addresses | Cached [IP blocklist](https://feodotracker.abuse.ch/downloads/ipblocklist.txt) |
| [Tor Project](https://www.torproject.org/) | Tor exit-node membership | Cached [exit list](https://check.torproject.org/torbulkexitlist) |
| [Cloudflare](https://developers.cloudflare.com/1.1.1.1/) | Compare filtered and unfiltered domain answers | DNS over HTTPS: `security.cloudflare-dns.com` and `cloudflare-dns.com` |
| [Quad9](https://quad9.net/) | Compare filtered and unfiltered domain answers | DNS over TLS: `9.9.9.9` and `9.9.9.10` |
| [Shodan InternetDB](https://internetdb.shodan.io/) | Observed open ports, CVEs, software identifiers, hostnames, and tags | HTTPS API at `internetdb.shodan.io` |
| [ip-api](https://ip-api.com/) | Country, ASN/ISP, proxy, hosting, and mobile flags | Plain HTTP API at `ip-api.com/json` |
| [Robtex](https://www.robtex.com/) | Passive DNS history and IP-associated names | HTTPS API at `freeapi.robtex.com` |
| [AbuseIPDB](https://docs.abuseipdb.com/) | Abuse confidence scores and report counts | HTTPS API; requires `ABUSEIPDB_API_KEY` |
| [GreyNoise](https://docs.greynoise.io/) | Community scanner classification and known-service flags | HTTPS API; requires `GREYNOISE_API_KEY` |

PeeringDB accepts an optional `PEERINGDB_API_KEY`. AbuseIPDB and GreyNoise checks
are skipped unless their keys are set. The other integrations do not send API
keys. The Cloudflare and Quad9 reputation comparisons use the endpoints above,
independently of `--resolver`. The resolver-path diagnostic in `check --net`
also queries Cloudflare's `1.1.1.1` over UDP and TLS.

### Interactive route servers

| Source | Command | Telnet host |
| --- | --- | --- |
| [Route Views](https://www.routeviews.org/) | `netintel routeviews` | `route-views.routeviews.org:23` |
| [Hurricane Electric](https://he.net/) | `netintel he` | `route-server.he.net:23` |

## Limitations

These services have their own access policies, quotas, and terms. Some DNS
blocklists refuse queries through public resolvers. Failed or refused lookups
are reported separately from an empty result. The ip-api endpoint uses plain
HTTP.

Reputation data can be stale and shared addresses can carry reports about
unrelated users. A listing needs context. Serving addresses and PTR names don't
establish domain ownership, and registration country fields aren't reliable IP
geolocation.

DNSSEC status relies on the resolver's AD flag and published DS records. SPF
redirects are followed up to ten hops; macro-based redirects aren't evaluated.
Email-authentication output summarizes published policy, without testing delivery
of an actual message. Only one page of Certificate Transparency results is fetched.

Routing data reflects what collectors see. AS-path neighbors don't establish
commercial relationships. Route comparisons require exact prefix matches; a
covering aggregate doesn't count as an exact match. A difference between BGP and
IRR data alone doesn't prove a route leak.

## Development and tests

The tests cover input parsing, DNS and API responses, feed caching, output, and
command behavior. Services are mocked, so the suite runs without network access.
From a checkout:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

For an editable pipx install, use `pipx install --editable .` instead. Source
changes will then take effect without reinstalling.
