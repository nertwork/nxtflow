"""Public DNS, domain suffix, CIDR, and IANA protocol defaults for nxtflow."""

from __future__ import annotations

import ipaddress

PROTO_MAP: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

PUBLIC_WELL_KNOWN_IPS: dict[str, str] = {
    "1.1.1.1": "cloudflare-dns",
    "1.0.0.1": "cloudflare-dns",
    "8.8.8.8": "google-dns",
    "8.8.4.4": "google-dns",
    "9.9.9.9": "quad9-dns",
    "149.112.112.112": "quad9-dns",
    "208.67.222.222": "opendns",
    "208.67.220.220": "opendns",
    "2606:4700:4700::1111": "cloudflare-dns",
    "2606:4700:4700::1001": "cloudflare-dns",
    "2001:4860:4860::8888": "google-dns",
    "2001:4860:4860::8844": "google-dns",
    "2620:fe::fe": "quad9-dns",
    "2620:fe::9": "quad9-dns",
}

PUBLIC_DOMAIN_SERVICES: dict[str, str] = {
    # Cloud / CDN
    "1e100.net": "google",
    "google.com": "google",
    "gvt1.com": "google",
    "gvt2.com": "google",
    "googlevideo.com": "youtube",
    "ytimg.com": "youtube",
    "cloudfront.net": "aws-cloudfront",
    "amazonaws.com": "aws",
    "cloudflare.com": "cloudflare",
    "fastly.net": "fastly",
    "fastlylb.net": "fastly",
    "akamai.net": "akamai",
    "akamaiedge.net": "akamai",
    "akamaitechnologies.com": "akamai",
    "azure.com": "azure",
    "windows.net": "azure",
    "oraclecloud.com": "oracle-cloud",
    "digitalocean.com": "digitalocean",
    "vercel.app": "vercel",
    "vercel-dns.com": "vercel",
    # SaaS / Dev / Collaboration
    "github.com": "github",
    "githubusercontent.com": "github",
    "gitlab.com": "gitlab",
    "microsoft.com": "microsoft",
    "msedge.net": "microsoft",
    "live.com": "microsoft",
    "office365.com": "microsoft-365",
    "office.com": "microsoft-365",
    "slack.com": "slack",
    "zoom.us": "zoom",
    "zoom.com": "zoom",
    "discord.com": "discord",
    "discord.gg": "discord",
    "discordapp.com": "discord",
    "discord.media": "discord",
    "dropbox.com": "dropbox",
    "backblaze.com": "backblaze",
    "backblazeb2.com": "backblaze",
    "tailscale.com": "tailscale",
    # Apple / Meta / Media / Gaming
    "push.apple.com": "apple-push",
    "icloud-content.com": "apple-icloud",
    "apple.com": "apple",
    "mzstatic.com": "apple",
    "cdn-apple.com": "apple",
    "fbcdn.net": "facebook",
    "facebook.com": "facebook",
    "instagram.com": "instagram",
    "whatsapp.net": "whatsapp",
    "netflix.com": "netflix",
    "nflxvideo.net": "netflix",
    "spotify.com": "spotify",
    "scdn.co": "spotify",
    "twitch.tv": "twitch",
    "twitchcdn.net": "twitch",
    "hulu.com": "hulu",
    "disneyplus.com": "disney-plus",
    "steampowered.com": "steam",
    "steamcontent.com": "steam",
    "valvesoftware.com": "steam",
    "playstation.net": "playstation",
    "playstation.com": "playstation",
    "sonyentertainmentnetwork.com": "playstation",
    "amazon.com": "amazon",
    "roku.com": "roku",
}

_RAW_PUBLIC_CIDRS: list[tuple[str, str]] = [
    # Cloudflare
    ("104.16.0.0/13", "cloudflare"),
    ("104.24.0.0/14", "cloudflare"),
    ("172.64.0.0/13", "cloudflare"),
    ("141.101.64.0/18", "cloudflare"),
    ("162.158.0.0/15", "cloudflare"),
    ("188.114.96.0/20", "cloudflare"),
    ("198.41.128.0/17", "cloudflare"),
    ("131.0.72.0/22", "cloudflare"),
    ("173.245.48.0/20", "cloudflare"),
    ("103.21.244.0/22", "cloudflare"),
    ("103.22.200.0/22", "cloudflare"),
    ("103.31.4.0/22", "cloudflare"),
    ("108.162.192.0/18", "cloudflare"),
    ("190.93.240.0/20", "cloudflare"),
    ("197.234.240.0/22", "cloudflare"),
    ("2400:cb00::/32", "cloudflare"),
    ("2606:4700::/32", "cloudflare"),
    ("2803:f800::/32", "cloudflare"),
    ("2405:b500::/32", "cloudflare"),
    ("2405:8100::/32", "cloudflare"),
    ("2a06:98c0::/29", "cloudflare"),
    ("2c0f:f248::/32", "cloudflare"),
    # Fastly
    ("151.101.0.0/16", "fastly"),
    ("199.232.0.0/16", "fastly"),
    ("146.75.0.0/16", "fastly"),
    ("2a04:4e40::/32", "fastly"),
    ("2a04:4e42::/32", "fastly"),
    # Akamai
    ("23.0.0.0/12", "akamai"),
    ("23.32.0.0/11", "akamai"),
    ("23.192.0.0/11", "akamai"),
    ("104.64.0.0/10", "akamai"),
    # AWS & CloudFront
    ("13.32.0.0/15", "aws-cloudfront"),
    ("13.224.0.0/14", "aws-cloudfront"),
    ("99.84.0.0/16", "aws-cloudfront"),
    ("108.138.0.0/15", "aws-cloudfront"),
    ("3.0.0.0/9", "aws"),
    ("18.0.0.0/11", "aws"),
    ("35.80.0.0/12", "aws"),
    ("44.192.0.0/11", "aws"),
    ("52.0.0.0/11", "aws"),
    ("54.64.0.0/11", "aws"),
    ("99.77.0.0/18", "aws"),
    # Google & GCP
    ("199.36.153.0/24", "google-psc"),
    ("142.250.0.0/15", "google"),
    ("172.217.0.0/16", "google"),
    ("216.58.0.0/16", "google"),
    ("74.125.0.0/16", "google"),
    ("64.233.0.0/16", "google"),
    ("216.239.32.0/19", "google"),
    ("209.85.128.0/17", "google"),
    ("108.177.0.0/17", "google"),
    ("72.14.192.0/18", "google"),
    ("2607:f8b0::/32", "google"),
    ("34.0.0.0/9", "google-cloud"),
    ("34.128.0.0/10", "google-cloud"),
    ("35.190.0.0/17", "google-cloud"),
    ("35.192.0.0/12", "google-cloud"),
    ("130.211.0.0/16", "google-cloud"),
    ("8.34.208.0/20", "google-cloud"),
    ("8.35.192.0/20", "google-cloud"),
    ("2600:1900::/28", "google-cloud"),
    # Microsoft / Azure / M365 / Teams / Bing
    ("52.96.0.0/14", "microsoft-365"),
    ("52.112.0.0/14", "ms-teams"),
    ("204.79.195.0/24", "bing"),
    ("204.79.197.0/24", "bing"),
    ("13.64.0.0/11", "microsoft"),
    ("20.0.0.0/11", "microsoft"),
    ("40.64.0.0/10", "microsoft"),
    ("52.100.0.0/14", "microsoft"),
    ("52.104.0.0/13", "microsoft"),
    ("52.120.0.0/14", "microsoft"),
    ("52.128.0.0/9", "microsoft"),
    ("150.171.0.0/16", "microsoft"),
    ("172.176.0.0/12", "microsoft"),
    # GitHub
    ("185.199.108.0/22", "github"),
    ("192.30.252.0/22", "github"),
    ("140.82.112.0/20", "github"),
    ("143.55.64.0/20", "github"),
    # Quad9
    ("9.9.9.0/24", "quad9-dns"),
    ("149.112.112.0/24", "quad9-dns"),
    ("2620:fe::/48", "quad9-dns"),
    # Major Public Clouds / CDNs / SaaS
    ("17.0.0.0/8", "apple"),
    ("31.13.0.0/16", "facebook"),
    ("157.240.0.0/16", "facebook"),
    ("185.60.216.0/22", "whatsapp"),
    ("129.153.0.0/16", "oracle-cloud"),
    ("141.148.0.0/16", "oracle-cloud"),
    ("68.183.0.0/16", "digitalocean"),
    ("167.99.0.0/16", "digitalocean"),
    ("143.244.128.0/17", "digitalocean"),
    ("164.92.0.0/16", "digitalocean"),
    ("149.137.0.0/16", "backblaze"),
    ("162.125.0.0/16", "dropbox"),
    ("216.150.0.0/16", "vercel"),
    ("199.7.48.0/21", "steam"),
    ("146.66.152.0/21", "steam"),
    ("155.133.224.0/20", "steam"),
    ("162.254.192.0/21", "steam"),
    ("192.69.96.0/22", "playstation"),
    ("44.234.0.0/15", "twitch"),
    ("165.225.0.0/16", "zscaler"),
    ("104.129.192.0/18", "zscaler"),
    ("45.60.0.0/16", "imperva"),
]

_COMPILED = [
    (ipaddress.ip_network(cidr, strict=False), name)
    for cidr, name in _RAW_PUBLIC_CIDRS
]
_V4_CIDRS: list[tuple[ipaddress.IPv4Network, str]] = sorted(
    [(net, name) for net, name in _COMPILED if isinstance(net, ipaddress.IPv4Network)],
    key=lambda item: (-item[0].prefixlen, int(item[0].network_address)),
)
_V6_CIDRS: list[tuple[ipaddress.IPv6Network, str]] = sorted(
    [(net, name) for net, name in _COMPILED if isinstance(net, ipaddress.IPv6Network)],
    key=lambda item: (-item[0].prefixlen, int(item[0].network_address)),
)
PUBLIC_CIDRS: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = [*_V4_CIDRS, *_V6_CIDRS]


def simplify_rdns(hostname: str, extra_services: dict[str, str] | None = None) -> str:
    """Map an rDNS PTR hostname to a canonical service label or registered 2-label domain."""
    h = hostname.strip().rstrip(".").lower()
    if not h:
        return hostname
    parts = h.split(".")
    if all(part.isdigit() for part in parts):
        return hostname

    merged = dict(PUBLIC_DOMAIN_SERVICES)
    if extra_services:
        for domain, label in extra_services.items():
            clean_dom = str(domain).strip().lstrip(".").rstrip(".").lower()
            if clean_dom:
                merged[clean_dom] = str(label)

    for suffix, label in sorted(merged.items(), key=lambda kv: (-len(kv[0]), kv[0])):
        if h == suffix or h.endswith("." + suffix):
            return label

    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h


def lookup_public_cidr(ip: str) -> str | None:
    """Look up a public IPv4 or IPv6 address against longest-prefix-first PUBLIC_CIDRS."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        for net, label in _V4_CIDRS:
            if addr in net:
                return label
    else:
        for net, label in _V6_CIDRS:
            if addr in net:
                return label
    return None
