import re
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
import quopri
import ipaddress
from dotenv import load_dotenv
import os

load_dotenv()

TOKEN = os.getenv("VT_API_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

if not TOKEN or not IPINFO_TOKEN:
    print("Please set VT_API_KEY and IPINFO_TOKEN in .env or your environment.")
    sys.exit(1)


def ipinfo_lookup(ip):
    url_ipinfo = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
    try:
        response = requests.get(url_ipinfo, timeout=5)
        response.raise_for_status()
        data = response.json()
        return {
            "ip": data.get("ip", "-"),
            "hostname": data.get("hostname", "-"),
            "city": data.get("city", "-"),
            "region": data.get("region", "-"),
            "country": data.get("country", "-"),
            "org": data.get("org", "-"),
        }
    except Exception as e:
        print(f"[IPInfo] Failed for {ip}: {e}")
        return None


def vt_ip_scan(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": TOKEN}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0), stats.get("suspicious", 0)
    except Exception as e:
        print(f"[VirusTotal] IP scan failed for {ip}: {e}")
        return "-", "-"


def vt_url_scan(url_input):
    headers = {"x-apikey": TOKEN}
    try:
        post = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url_input},
                             timeout=10)
        post.raise_for_status()
        analysis_url = post.json()["data"]["links"]["self"]

        get = requests.get(analysis_url, headers=headers, timeout=10)
        get.raise_for_status()
        stats = get.json()["data"]["attributes"]["stats"]
        return stats.get("malicious", 0), stats.get("suspicious", 0)
    except Exception as e:
        print(f"[VirusTotal] URL scan failed for {url_input}: {e}")
        return "-", "-"


def extract_links(html_encoded):
    decoded = quopri.decodestring(html_encoded).decode("utf-8", errors="replace")
    soup = BeautifulSoup(decoded, "html.parser")
    links = set(tag['href'] for tag in soup.find_all("a", href=True))

    if not links:
        for e in re.findall(r'https?://[^\s"\',>]+', decoded):
            links.add(e)

    if not links:
        print("No links found in the input.")
        sys.exit(1)
    return links


def resolve_ips(links):
    results = {}
    for link in links:
        try:
            hostname = urlparse(link).hostname
            if hostname:
                addr_info = socket.getaddrinfo(hostname, None)
                ips = list({info[4][0] for info in addr_info})
                results[link] = ips[0] if ips else "Unresolved"
        except Exception as e:
            results[link] = f"Error: {e}"
    return results


def main():
    print("Paste the full phishing email (HTML or raw). Press Enter and Ctrl+D (or Ctrl+Z on Windows) to finish:\n")
    email_content = sys.stdin.read()

    try:
        links = extract_links(email_content.encode("utf-8"))
        print("\nExtracted Links:")
        for link in links:
            print(f" - {link}")

        ip_map = resolve_ips(links)
        print("\nPhishing Detection Report:\n" + "=" * 60)
        for link, ip in ip_map.items():
            url_mal, url_susp = vt_url_scan(link)

            try:
                ipaddress.ip_address(ip)
                valid_ip = True
            except ValueError:
                valid_ip = False

            if valid_ip:
                ip_mal, ip_susp = vt_ip_scan(ip)
                geo = ipinfo_lookup(ip) or {}
            else:
                ip_mal = ip_susp = "-"
                geo = {}

            print(f"🔗 URL: {link}")
            print(f"  - Malicious (URL): {url_mal}, Suspicious (URL): {url_susp}")
            print(f"  - Resolved IP: {ip} ({'IPv6' if ':' in ip else 'IPv4'})")
            print(f"  - Malicious (IP): {ip_mal}, Suspicious (IP): {ip_susp}")
            if geo:
                print(
                    f"  - Geo Info: {geo.get('city', '-')}, {geo.get('region', '-')}, {geo.get('country', '-')} | Org: {geo.get('org', '-')}")
            print("-" * 60)

    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
