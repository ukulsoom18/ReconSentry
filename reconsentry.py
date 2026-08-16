#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║              ReconSentry - Footprinting & Recon Tool          ║
║          All-in-one passive & active reconnaissance           ║
║                  For authorized use only                      ║
╚═══════════════════════════════════════════════════════════════╝

Author  : Umme Kulsoom
Purpose : Cybersecurity Assignment - Footprinting & Reconnaissance
Language: Python 3
"""

import sys
import os
import json
import socket
import struct
import time
import datetime
import argparse
import threading
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-party imports
try:
    import requests
    import whois
    import dns.resolver
    import dns.reversename
    from colorama import init, Fore, Back, Style
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Run: pip install dnspython python-whois requests colorama")
    sys.exit(1)

init(autoreset=True)  # Initialize colorama

# ─────────────────────────────────────────────
#  CONSTANTS & CONFIG
# ─────────────────────────────────────────────
VERSION = "1.0.0"
TOOL_NAME = "ReconSentry"
AUTHOR = "Umme Kulsoom"

# API Keys (set your own or leave empty for keyless fallback)
SHODAN_API_KEY = ""   # Optional: Get free key at shodan.io
HUNTER_API_KEY = ""   # Optional: Get free key at hunter.io

# Threading
MAX_THREADS = 100
PORT_TIMEOUT = 1.0

# Common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]

# Common subdomains for brute-force enumeration
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "dev", "test", "stage", "api", "app", "mobile",
    "vpn", "remote", "portal", "secure", "login", "blog",
    "shop", "store", "cdn", "static", "media", "images",
    "ns1", "ns2", "mx", "support", "help", "docs", "git",
    "jenkins", "jira", "confluence", "cloud", "server",
    "dashboard", "panel", "cpanel", "whm", "phpmyadmin"
]


# ─────────────────────────────────────────────
#  BANNER & DISPLAY HELPERS
# ─────────────────────────────────────────────

def print_banner():
    banner = f"""
{Fore.CYAN}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝
███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}       All-in-One Footprinting & Reconnaissance Tool{Style.RESET_ALL}
{Fore.WHITE}       Version: {VERSION} | Author: {AUTHOR}{Style.RESET_ALL}
{Fore.RED}       [!] For authorized and ethical use ONLY{Style.RESET_ALL}
{Fore.CYAN}{'═'*60}{Style.RESET_ALL}
"""
    print(banner)


def section_header(title):
    print(f"\n{Fore.CYAN}{'═'*60}")
    print(f"  {Fore.YELLOW}[+] {Fore.WHITE}{title}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")


def info(msg):
    print(f"  {Fore.GREEN}[→]{Style.RESET_ALL} {msg}")


def warn(msg):
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def error(msg):
    print(f"  {Fore.RED}[✗]{Style.RESET_ALL} {msg}")


def found(msg):
    print(f"  {Fore.MAGENTA}[★]{Style.RESET_ALL} {msg}")


def progress(msg):
    print(f"  {Fore.CYAN}[~]{Style.RESET_ALL} {msg}")


# ─────────────────────────────────────────────
#  MODULE 1: WHOIS + DNS RECONNAISSANCE
# ─────────────────────────────────────────────

def module_whois_dns(target, results):
    section_header("MODULE 1 — WHOIS & DNS Reconnaissance")
    dns_data = {}
    whois_data = {}

    # ── WHOIS Lookup ──
    progress(f"Querying WHOIS for: {target}")
    try:
        w = whois.whois(target)
        whois_data = {
            "domain_name": str(w.domain_name) if w.domain_name else "N/A",
            "registrar": str(w.registrar) if w.registrar else "N/A",
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "updated_date": str(w.updated_date) if w.updated_date else "N/A",
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "status": str(w.status) if w.status else "N/A",
            "emails": list(w.emails) if w.emails else [],
            "org": str(w.org) if w.org else "N/A",
            "country": str(w.country) if w.country else "N/A",
        }
        info(f"Registrar      : {whois_data['registrar']}")
        info(f"Org            : {whois_data['org']}")
        info(f"Country        : {whois_data['country']}")
        info(f"Created        : {whois_data['creation_date']}")
        info(f"Expires        : {whois_data['expiration_date']}")
        if whois_data["emails"]:
            for em in whois_data["emails"]:
                found(f"Email          : {em}")
        if whois_data["name_servers"]:
            for ns in whois_data["name_servers"]:
                info(f"Name Server    : {ns}")
    except Exception as e:
        error(f"WHOIS failed: {e}")

    # ── DNS Record Types ──
    progress("Enumerating DNS records...")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            records = [str(r) for r in answers]
            dns_data[rtype] = records
            for r in records:
                info(f"DNS {rtype:<5}     : {r}")
        except Exception:
            dns_data[rtype] = []

    results["whois"] = whois_data
    results["dns"] = dns_data
    return results


# ─────────────────────────────────────────────
#  MODULE 2: IP GEOLOCATION + ASN
# ─────────────────────────────────────────────

def module_ip_geolocation(target, results):
    section_header("MODULE 2 — IP Geolocation & ASN Intelligence")
    geo_data = {}

    # Resolve domain to IP if needed
    ip_address = target
    if not is_ip(target):
        try:
            ip_address = socket.gethostbyname(target)
            info(f"Resolved {target} → {ip_address}")
        except Exception as e:
            error(f"Could not resolve {target}: {e}")
            results["geolocation"] = {}
            return results

    # ── ip-api.com (free, no key needed) ──
    progress(f"Fetching geolocation for IP: {ip_address}")
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"
        resp = requests.get(url, timeout=8)
        data = resp.json()

        if data.get("status") == "success":
            geo_data = {
                "ip": data.get("query", ip_address),
                "country": data.get("country", "N/A"),
                "country_code": data.get("countryCode", "N/A"),
                "region": data.get("regionName", "N/A"),
                "city": data.get("city", "N/A"),
                "zip": data.get("zip", "N/A"),
                "latitude": data.get("lat", "N/A"),
                "longitude": data.get("lon", "N/A"),
                "timezone": data.get("timezone", "N/A"),
                "isp": data.get("isp", "N/A"),
                "org": data.get("org", "N/A"),
                "asn": data.get("as", "N/A"),
                "asn_name": data.get("asname", "N/A"),
            }
            info(f"IP Address     : {geo_data['ip']}")
            info(f"Country        : {geo_data['country']} ({geo_data['country_code']})")
            info(f"Region/City    : {geo_data['region']}, {geo_data['city']}")
            info(f"Coordinates    : {geo_data['latitude']}, {geo_data['longitude']}")
            info(f"Timezone       : {geo_data['timezone']}")
            info(f"ISP            : {geo_data['isp']}")
            info(f"Organization   : {geo_data['org']}")
            found(f"ASN            : {geo_data['asn']}")
            found(f"ASN Name       : {geo_data['asn_name']}")
        else:
            warn(f"ip-api.com: {data.get('message', 'Unknown error')}")
    except Exception as e:
        error(f"Geolocation failed: {e}")

    # ── Reverse DNS ──
    try:
        rev_name = dns.reversename.from_address(ip_address)
        ptr = str(dns.resolver.resolve(rev_name, "PTR")[0])
        geo_data["reverse_dns"] = ptr
        info(f"Reverse DNS    : {ptr}")
    except Exception:
        geo_data["reverse_dns"] = "N/A"

    results["geolocation"] = geo_data
    results["resolved_ip"] = ip_address
    return results


# ─────────────────────────────────────────────
#  MODULE 3: SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────

def module_subdomain_enum(target, results):
    section_header("MODULE 3 — Subdomain Enumeration")
    found_subs = []

    # Ensure we're working with the base domain
    domain = target.replace("www.", "")

    # ── Method 1: crt.sh (Certificate Transparency Logs) ──
    progress(f"Querying Certificate Transparency logs (crt.sh) for: {domain}")
    crt_subs = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") and "*" not in sub:
                        crt_subs.add(sub)
            if crt_subs:
                found(f"crt.sh found {len(crt_subs)} subdomains")
                for sub in sorted(crt_subs)[:20]:  # show top 20
                    info(f"  {sub}")
                if len(crt_subs) > 20:
                    warn(f"  ... and {len(crt_subs) - 20} more (see JSON report)")
    except Exception as e:
        warn(f"crt.sh query failed: {e}")

    # ── Method 2: DNS Brute-Force (common subdomains) ──
    progress(f"DNS brute-force enumeration ({len(COMMON_SUBDOMAINS)} common subdomains)...")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    brute_lock = threading.Lock()
    brute_found = []

    def check_subdomain(sub):
        full = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(full, "A")
            ips = [str(r) for r in answers]
            with brute_lock:
                brute_found.append({"subdomain": full, "ips": ips})
            info(f"  {full} → {', '.join(ips)}")
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=30) as executor:
        executor.map(check_subdomain, COMMON_SUBDOMAINS)

    # Combine results
    all_subs = list(crt_subs)
    for item in brute_found:
        if item["subdomain"] not in all_subs:
            all_subs.append(item["subdomain"])

    found(f"Total unique subdomains discovered: {len(all_subs)}")

    results["subdomains"] = {
        "crt_sh": sorted(list(crt_subs)),
        "brute_force": brute_found,
        "total_unique": len(all_subs)
    }
    return results


# ─────────────────────────────────────────────
#  MODULE 4: PORT SCANNER + BANNER GRABBING
# ─────────────────────────────────────────────

def module_port_scan(target, results, ports=None):
    section_header("MODULE 4 — Port Scanning & Banner Grabbing")

    if ports is None:
        ports = COMMON_PORTS

    # Resolve IP
    ip = target
    if not is_ip(target):
        ip = results.get("resolved_ip", None)
        if not ip:
            try:
                ip = socket.gethostbyname(target)
            except Exception as e:
                error(f"Could not resolve {target}: {e}")
                results["port_scan"] = {}
                return results

    progress(f"Scanning {len(ports)} ports on {ip}...")

    open_ports = []
    scan_lock = threading.Lock()

    # Service name map
    SERVICE_MAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
        135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
        3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_TIMEOUT)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = SERVICE_MAP.get(port, "Unknown")
                banner = ""
                # Banner grabbing
                try:
                    if port in [80, 8080, 8443, 443]:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(512).decode("utf-8", errors="ignore").strip()
                        banner = banner.split("\r\n")[0]  # First line only
                    elif port in [21, 22, 25, 110, 143]:
                        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                        banner = banner[:100]
                except Exception:
                    pass
                sock.close()

                port_info = {
                    "port": port,
                    "service": service,
                    "state": "open",
                    "banner": banner if banner else "N/A"
                }
                with scan_lock:
                    open_ports.append(port_info)
                info(f"  {Fore.GREEN}OPEN{Style.RESET_ALL}  {port:<6} {service:<12} | {banner[:60] if banner else ''}")
            else:
                sock.close()
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.map(scan_port, ports)

    open_ports.sort(key=lambda x: x["port"])
    found(f"Open ports found: {len(open_ports)}")

    results["port_scan"] = {
        "target_ip": ip,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "open_count": len(open_ports)
    }
    return results


# ─────────────────────────────────────────────
#  MODULE 5: EMAIL HARVESTING
# ─────────────────────────────────────────────

def module_email_harvest(domain, results):
    section_header("MODULE 5 — Email Harvesting & Validation")
    emails_found = set()

    # Ensure clean domain
    domain = domain.replace("www.", "").strip()

    # ── Method 1: Hunter.io API (if key provided) ──
    if HUNTER_API_KEY:
        progress(f"Querying Hunter.io for emails at: {domain}")
        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_API_KEY}&limit=20"
            resp = requests.get(url, timeout=10)
            data = resp.json()
            hunter_emails = data.get("data", {}).get("emails", [])
            for item in hunter_emails:
                email = item.get("value", "")
                if email:
                    emails_found.add(email)
                    found(f"  Hunter.io → {email} ({item.get('type', 'N/A')})")
        except Exception as e:
            warn(f"Hunter.io failed: {e}")
    else:
        warn("Hunter.io API key not set — skipping (add key in config section)")

    # ── Method 2: EmailFormat patterns (generate likely emails) ──
    progress(f"Generating likely email patterns for: {domain}")
    patterns = [
        f"info@{domain}",
        f"contact@{domain}",
        f"admin@{domain}",
        f"support@{domain}",
        f"security@{domain}",
        f"webmaster@{domain}",
        f"mail@{domain}",
        f"abuse@{domain}",
        f"noc@{domain}",
        f"help@{domain}",
    ]
    for p in patterns:
        info(f"  Pattern generated: {p}")
        emails_found.add(p)

    # ── Method 3: Extract from WHOIS emails (already collected) ──
    whois_emails = results.get("whois", {}).get("emails", [])
    for em in whois_emails:
        if em and "@" in em:
            emails_found.add(em)
            found(f"  From WHOIS: {em}")

    # ── Validate email format ──
    valid_emails = []
    email_regex = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    for email in emails_found:
        if re.match(email_regex, email):
            valid_emails.append(email)

    found(f"Total email addresses collected: {len(valid_emails)}")

    results["email_harvest"] = {
        "domain": domain,
        "emails": sorted(valid_emails),
        "count": len(valid_emails),
        "sources": ["Hunter.io (API)" if HUNTER_API_KEY else "Hunter.io (skipped)", "WHOIS", "Pattern Generation"]
    }
    return results


# ─────────────────────────────────────────────
#  MODULE 6: SHODAN IoT / HOST INTELLIGENCE
# ─────────────────────────────────────────────

def module_shodan_iot(target, results):
    section_header("MODULE 6 — IoT & Host Intelligence (Shodan)")

    ip = results.get("resolved_ip", None)
    if not ip and is_ip(target):
        ip = target
    if not ip:
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            error("Could not resolve IP for Shodan lookup")
            results["shodan"] = {"error": "IP resolution failed"}
            return results

    shodan_data = {}

    if SHODAN_API_KEY:
        progress(f"Querying Shodan for: {ip}")
        try:
            import shodan as shodan_lib
            api = shodan_lib.Shodan(SHODAN_API_KEY)
            host = api.host(ip)

            shodan_data = {
                "ip": host.get("ip_str", ip),
                "organization": host.get("org", "N/A"),
                "isp": host.get("isp", "N/A"),
                "os": host.get("os", "N/A"),
                "country": host.get("country_name", "N/A"),
                "last_update": host.get("last_update", "N/A"),
                "ports": host.get("ports", []),
                "vulns": list(host.get("vulns", {}).keys()),
                "tags": host.get("tags", []),
                "hostnames": host.get("hostnames", []),
                "services": []
            }

            for item in host.get("data", []):
                svc = {
                    "port": item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "product": item.get("product", "N/A"),
                    "version": item.get("version", "N/A"),
                    "banner": item.get("data", "")[:100]
                }
                shodan_data["services"].append(svc)
                info(f"  Port {svc['port']}/{svc['transport']} — {svc['product']} {svc['version']}")

            if shodan_data["vulns"]:
                for v in shodan_data["vulns"]:
                    found(f"  [VULN] {v}")
            else:
                info("No known CVEs found in Shodan")

            if shodan_data["tags"]:
                info(f"Shodan Tags    : {', '.join(shodan_data['tags'])}")

        except Exception as e:
            warn(f"Shodan API error: {e}")
            shodan_data = {"error": str(e), "ip": ip}
    else:
        warn("Shodan API key not set — using fallback (ip-api.com enrichment)")
        progress("Fetching additional host intelligence via ipwho.is...")
        try:
            resp = requests.get(f"https://ipwho.is/{ip}", timeout=8)
            data = resp.json()
            connection = data.get("connection", {})
            shodan_data = {
                "ip": ip,
                "note": "Shodan API key not configured — showing enriched IP data",
                "organization": connection.get("org", "N/A"),
                "isp": connection.get("isp", "N/A"),
                "asn": connection.get("asn", "N/A"),
                "country": data.get("country", "N/A"),
                "type": data.get("type", "N/A"),
                "security": data.get("security", {}),
                "company": data.get("company", {}),
            }
            info(f"Organization   : {shodan_data['organization']}")
            info(f"ISP            : {shodan_data['isp']}")
            info(f"ASN            : {shodan_data['asn']}")
            info(f"IP Type        : {shodan_data['type']}")
            security = shodan_data.get("security", {})
            if security:
                info(f"Proxy          : {security.get('proxy', False)}")
                info(f"VPN            : {security.get('vpn', False)}")
                info(f"Tor            : {security.get('tor', False)}")
                found(f"Bot            : {security.get('bot', False)}")
            warn("Add SHODAN_API_KEY in tool config for full IoT/vulnerability data")
        except Exception as e:
            error(f"Fallback enrichment failed: {e}")
            shodan_data = {"error": str(e), "ip": ip}

    results["shodan"] = shodan_data
    return results


# ─────────────────────────────────────────────
#  REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_report(target, results, output_dir="."):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace("/", "_")
    base_name = f"ReconSentry_{safe_target}_{timestamp}"

    # ── JSON Report ──
    json_path = os.path.join(output_dir, f"{base_name}.json")
    with open(json_path, "w") as f:
        json.dump({
            "tool": TOOL_NAME,
            "version": VERSION,
            "author": AUTHOR,
            "target": target,
            "scan_time": datetime.datetime.now().isoformat(),
            "results": results
        }, f, indent=4, default=str)

    # ── TXT Report ──
    txt_path = os.path.join(output_dir, f"{base_name}.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write(f"  {TOOL_NAME} v{VERSION} — Footprinting & Reconnaissance Report\n")
        f.write(f"  Target  : {target}\n")
        f.write(f"  Scanned : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Author  : {AUTHOR}\n")
        f.write("=" * 70 + "\n\n")

        # WHOIS
        f.write("[ MODULE 1 — WHOIS & DNS ]\n")
        f.write("-" * 40 + "\n")
        w = results.get("whois", {})
        for k, v in w.items():
            f.write(f"  {k:<20}: {v}\n")
        f.write("\nDNS Records:\n")
        for rtype, records in results.get("dns", {}).items():
            for r in records:
                f.write(f"  {rtype:<6}: {r}\n")
        f.write("\n")

        # Geolocation
        f.write("[ MODULE 2 — IP GEOLOCATION ]\n")
        f.write("-" * 40 + "\n")
        geo = results.get("geolocation", {})
        for k, v in geo.items():
            f.write(f"  {k:<20}: {v}\n")
        f.write("\n")

        # Subdomains
        f.write("[ MODULE 3 — SUBDOMAINS ]\n")
        f.write("-" * 40 + "\n")
        subs = results.get("subdomains", {})
        f.write(f"  Total found: {subs.get('total_unique', 0)}\n")
        for s in subs.get("crt_sh", [])[:30]:
            f.write(f"  [crt.sh]    {s}\n")
        for item in subs.get("brute_force", []):
            f.write(f"  [brute]     {item['subdomain']} → {', '.join(item['ips'])}\n")
        f.write("\n")

        # Ports
        f.write("[ MODULE 4 — PORT SCAN ]\n")
        f.write("-" * 40 + "\n")
        ps = results.get("port_scan", {})
        f.write(f"  Ports Scanned : {ps.get('ports_scanned', 0)}\n")
        f.write(f"  Open Ports    : {ps.get('open_count', 0)}\n\n")
        for p in ps.get("open_ports", []):
            f.write(f"  {p['port']:<6} {p['service']:<12} {p['banner'][:50]}\n")
        f.write("\n")

        # Emails
        f.write("[ MODULE 5 — EMAIL HARVEST ]\n")
        f.write("-" * 40 + "\n")
        em = results.get("email_harvest", {})
        f.write(f"  Emails found  : {em.get('count', 0)}\n")
        for e in em.get("emails", []):
            f.write(f"  {e}\n")
        f.write("\n")

        # Shodan
        f.write("[ MODULE 6 — IoT / HOST INTEL ]\n")
        f.write("-" * 40 + "\n")
        sh = results.get("shodan", {})
        for k, v in sh.items():
            if k not in ["services", "vulns"]:
                f.write(f"  {k:<20}: {v}\n")
        vulns = sh.get("vulns", [])
        if vulns:
            f.write(f"\n  CVEs Found    : {len(vulns)}\n")
            for v in vulns:
                f.write(f"    {v}\n")
        f.write("\n" + "=" * 70 + "\n")
        f.write("  END OF REPORT — ReconSentry\n")
        f.write("=" * 70 + "\n")

    return json_path, txt_path


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def validate_target(target):
    """Basic validation for domain or IP."""
    if is_ip(target):
        return True
    domain_regex = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_regex, target))


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} — Footprinting & Reconnaissance Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target domain or IP address (e.g., example.com)")
    parser.add_argument("-o", "--output", default=".", help="Output directory for reports (default: current dir)")
    parser.add_argument("--ports", help="Comma-separated port list (default: common 21 ports)")
    parser.add_argument("--skip", help="Skip modules (e.g., --skip 3,5)")
    parser.add_argument("--shodan-key", help="Shodan API key (overrides config)")
    parser.add_argument("--hunter-key", help="Hunter.io API key (overrides config)")

    args = parser.parse_args()

    # Override API keys from CLI if provided
    global SHODAN_API_KEY, HUNTER_API_KEY
    if args.shodan_key:
        SHODAN_API_KEY = args.shodan_key
    if args.hunter_key:
        HUNTER_API_KEY = args.hunter_key

    target = args.target.strip().lower()

    # Validate
    if not validate_target(target):
        error(f"Invalid target: '{target}'. Please provide a valid domain or IP.")
        sys.exit(1)

    # Parse ports
    ports = COMMON_PORTS
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except Exception:
            warn("Invalid port list — using defaults")

    # Parse skipped modules
    skip_modules = set()
    if args.skip:
        try:
            skip_modules = set(int(m.strip()) for m in args.skip.split(","))
        except Exception:
            warn("Invalid skip list — running all modules")

    # Output dir
    os.makedirs(args.output, exist_ok=True)

    print(f"\n  {Fore.WHITE}Target  : {Fore.YELLOW}{target}")
    print(f"  {Fore.WHITE}Output  : {Fore.YELLOW}{args.output}")
    print(f"  {Fore.WHITE}Time    : {Fore.YELLOW}{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {Fore.WHITE}Modules : {Fore.YELLOW}{'All' if not skip_modules else f'Skipping {skip_modules}'}")

    results = {}
    start_time = time.time()

    # ── Run Modules ──
    if 1 not in skip_modules:
        results = module_whois_dns(target, results)
    if 2 not in skip_modules:
        results = module_ip_geolocation(target, results)
    if 3 not in skip_modules:
        results = module_subdomain_enum(target, results)
    if 4 not in skip_modules:
        results = module_port_scan(target, results, ports)
    if 5 not in skip_modules:
        results = module_email_harvest(target, results)
    if 6 not in skip_modules:
        results = module_shodan_iot(target, results)

    # ── Generate Reports ──
    section_header("REPORT GENERATION")
    elapsed = time.time() - start_time
    json_path, txt_path = generate_report(target, results, args.output)

    print(f"\n{Fore.CYAN}{'═'*60}")
    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} Scan completed in {elapsed:.2f} seconds")
    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} JSON report : {Fore.YELLOW}{json_path}")
    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} TXT report  : {Fore.YELLOW}{txt_path}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"\n  {Fore.RED}[!] ReconSentry results are for authorized use only.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
