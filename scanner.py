import requests
import dns.resolver
import whois
import tldextract
import urllib.parse
import random
import time
import argparse
import ssl
import socket
import certifi
import os
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from urllib.robotparser import RobotFileParser
from requests.exceptions import SSLError, RequestException

def get_apex_domain(url: str) -> str:
    """Extract the apex domain from a URL (e.g., example.com from sub.example.com)."""
    parsed = tldextract.extract(url)
    return f"{parsed.domain}.{parsed.suffix}"

def get_dns_info(domain: str) -> Dict[str, List[str]]:
    """Retrieve DNS records (A, MX, NS, TXT) for a domain."""
    dns_info = {"A": [], "MX": [], "NS": [], "TXT": []}
    for record_type in dns_info.keys():
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_info[record_type] = [str(rdata) for rdata in answers]
        except Exception as e:
            dns_info[record_type] = [f"Error: {str(e)}"]
    return dns_info

def get_whois_info(domain: str) -> Dict:
    """Fetch WHOIS information for a domain."""
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.get("registrar", "N/A"),
            "registrant": w.get("registrant_name", "N/A"),
            "creation_date": str(w.get("creation_date", "N/A")),
            "expiration_date": str(w.get("expiration_date", "N/A")),
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}

def verify_ssl(url: str) -> Dict:
    """Verify SSL certificate for an HTTPS URL."""
    if not url.startswith("https://"):
        return {"valid": False, "error": "Not an HTTPS URL"}
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "not_after": cert.get("notAfter", "N/A")
                }
    except (SSLError, socket.timeout, ConnectionError) as e:
        return {"valid": False, "error": str(e)}

def check_robots_txt(base_url: str, user_agents: List[str]) -> List[str]:
    """Fetch and parse robots.txt for disallowed paths."""
    robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
    try:
        response = requests.get(robots_url, headers={"User-Agent": random.choice(user_agents)}, timeout=5)
        if response.status_code == 200:
            parser = RobotFileParser()
            parser.set_url(robots_url)
            parser.parse(response.text.splitlines())
            disallowed = [rule for rule in parser.entries[0].rulelines if not rule.allowance]
            return [str(rule.path) for rule in disallowed if rule.path]
        return ["Not found or inaccessible"]
    except RequestException as e:
        return [f"Error: {str(e)}"]

def detect_js_redirect(response_text: str) -> Optional[str]:
    """Check for JavaScript-based redirects in the response HTML."""
    try:
        soup = BeautifulSoup(response_text, "html.parser")
        meta_refresh = soup.find("meta", attrs={"http-equiv": "refresh"})
        if meta_refresh and meta_refresh.get("content"):
            content = meta_refresh.get("content")
            if "url=" in content.lower():
                return content.split("url=")[-1].strip()
        scripts = soup.find_all("script")
        for script in scripts:
            if script.string and ("window.location" in script.string or "document.location" in script.string):
                for line in script.string.splitlines():
                    if "window.location" in line or "document.location" in line:
                        if "=" in line:
                            possible_url = line.split("=")[-1].strip().strip("'\" ;")
                            if possible_url.startswith(("http://", "https://")):
                                return possible_url
        return None
    except Exception:
        return None

def detect_forms(response_text: str) -> bool:
    """Check for HTML forms in the response."""
    try:
        soup = BeautifulSoup(response_text, "html.parser")
        return bool(soup.find("form"))
    except Exception:
        return False

def take_screenshot(url: str, output_dir: str, filename: str) -> str:
    """Capture a screenshot of the page using Playwright."""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=10000)
            screenshot_path = os.path.join(output_dir, filename)
            page.screenshot(path=screenshot_path)
            browser.close()
            return screenshot_path
    except Exception as e:
        return f"Error: {str(e)}"

def check_initial_redirect(url: str, user_agents: List[str], verbose: bool) -> List[Dict]:
    """Check if the initial URL redirects (HTTP, JS, or DNS)."""
    redirects = []
    current_url = url
    headers = {"User-Agent": random.choice(user_agents)}
    
    try:
        parsed_url = urllib.parse.urlparse(current_url)
        domain = parsed_url.netloc
        apex_domain = get_apex_domain(current_url)
        try:
            dns_answers = dns.resolver.resolve(domain, "A")
            resolved_ips = [str(rdata) for rdata in dns_answers]
        except Exception:
            resolved_ips = ["DNS resolution failed"]
        
        redirects.append({
            "url": current_url,
            "apex_domain": apex_domain,
            "type": "Initial",
            "status_code": None,
            "resolved_ips": resolved_ips,
            "redirect_url": None
        })
        
        response = requests.get(current_url, headers=headers, allow_redirects=False, timeout=5)
        if response.status_code in (301, 302, 303, 307, 308):
            redirect_url = response.headers.get("Location", None)
            if redirect_url:
                redirects.append({
                    "url": current_url,
                    "apex_domain": apex_domain,
                    "type": "HTTP",
                    "status_code": response.status_code,
                    "resolved_ips": resolved_ips,
                    "redirect_url": redirect_url
                })
                current_url = urllib.parse.urljoin(current_url, redirect_url)
        
        final_response = requests.get(current_url, headers=headers, allow_redirects=True, timeout=5)
        js_redirect = detect_js_redirect(final_response.text)
        if js_redirect:
            redirects.append({
                "url": current_url,
                "apex_domain": get_apex_domain(current_url),
                "type": "JavaScript",
                "status_code": final_response.status_code,
                "resolved_ips": resolved_ips,
                "redirect_url": js_redirect
            })
            current_url = js_redirect
        
        return redirects
    except RequestException as e:
        redirects.append({
            "url": current_url,
            "apex_domain": apex_domain,
            "type": "Error",
            "status_code": None,
            "resolved_ips": ["N/A"],
            "redirect_url": f"Error: {str(e)}"
        })
        return redirects

def fuzz_directories(base_url: str, directories: List[str], user_agents: List[str], delay: float, verbose: bool, output_dir: str) -> List[Dict]:
    """Fuzz the target URL for directories/files, with enhanced checks."""
    results = []
    
    for directory in directories:
        target_url = urllib.parse.urljoin(base_url, directory)
        headers = {"User-Agent": random.choice(user_agents)}
        try:
            response = requests.get(target_url, headers=headers, allow_redirects=False, timeout=5)
            result = {
                "url": target_url,
                "status_code": response.status_code,
                "exists": response.status_code == 200,
                "redirect": None,
                "response_size": len(response.content),
                "headers": dict(response.headers),
                "has_form": False,
                "screenshot": None
            }
            
            if response.status_code == 429:
                if verbose:
                    print(f"  [!] Rate limit detected (429) for {target_url}. Pausing for 5 seconds...")
                time.sleep(5)
                response = requests.get(target_url, headers=headers, allow_redirects=False, timeout=5)
                result["status_code"] = response.status_code
                result["exists"] = response.status_code == 200
                result["response_size"] = len(response.content)
                result["headers"] = dict(response.headers)
            
            if response.status_code in (301, 302, 303, 307, 308):
                result["redirect"] = response.headers.get("Location", "Unknown")
            
            if not result["redirect"]:
                response = requests.get(target_url, headers=headers, allow_redirects=True, timeout=5)
                result["status_code"] = response.status_code
                result["exists"] = response.status_code == 200
                result["response_size"] = len(response.content)
                result["headers"] = dict(response.headers)
            
            if result["exists"]:
                result["has_form"] = detect_forms(response.text)
                screenshot_filename = f"screenshot_{urllib.parse.quote(directory, safe='')}.png"
                result["screenshot"] = take_screenshot(target_url, output_dir, screenshot_filename)
            
            results.append(result)
        except RequestException as e:
            results.append({
                "url": target_url,
                "status_code": None,
                "exists": False,
                "redirect": None,
                "response_size": 0,
                "headers": {},
                "has_form": False,
                "screenshot": None,
                "error": str(e)
            })
        
        time.sleep(delay)
    
    return results

def save_results_to_file(results: List[Dict], filename: str):
    """Save fuzzing results to a file."""
    with open(filename, "w") as f:
        for result in results:
            f.write(f"URL: {result['url']}\n")
            f.write(f"Exists: {'Yes' if result['exists'] else 'No'}\n")
            f.write(f"Status Code: {result['status_code'] if result['status_code'] else 'N/A'}\n")
            f.write(f"Response Size: {result['response_size']} bytes\n")
            f.write(f"Headers: {result['headers']}\n")
            f.write(f"Has Form: {'Yes' if result['has_form'] else 'No'}\n")
            f.write(f"Screenshot: {result['screenshot'] if result['screenshot'] else 'None'}\n")
            f.write(f"Redirect: {result['redirect'] if result['redirect'] else 'None'}\n")
            if result.get("error"):
                f.write(f"Error: {result['error']}\n")
            f.write("\n")

def main():
    # Parse CLI arguments
    parser = argparse.ArgumentParser(description="USPS Scam Fuzzing Tool")
    parser.add_argument("url", help="Target URL (e.g., http://example.com)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests (seconds)")
    parser.add_argument("--output", default="fuzzing_results.txt", help="Output file for results")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # User-Agent list
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    ]
    
    # VPN Reminder
    print("\n[!] IMPORTANT: For your privacy and safety, please ensure you are using a VPN before scanning.")
    input("Press Enter to continue...")
    
    # Input
    target_url = args.url
    directory_file = "files_directories.txt"
    output_dir = "screenshots"
    
    # Create screenshots directory
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Ensure URL has a scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"
    
    # Extract domain and apex domain
    parsed_url = urllib.parse.urlparse(target_url)
    domain = parsed_url.netloc
    apex_domain = get_apex_domain(target_url)
    
    print(f"\n[+] Target URL: {target_url}")
    print(f"[+] Domain: {domain}")
    print(f"[+] Apex Domain: {apex_domain}")
    
    # SSL Verification
    print("\n[+] SSL Verification:")
    ssl_info = verify_ssl(target_url)
    if ssl_info["valid"]:
        print(f"  Valid: Yes")
        print(f"  Issuer: {ssl_info['issuer']}")
        print(f"  Subject: {ssl_info['subject']}")
        print(f"  Expires: {ssl_info['not_after']}")
    else:
        print(f"  Valid: No")
        print(f"  Error: {ssl_info['error']}")
    
    # robots.txt Check
    print("\n[+] robots.txt Disallowed Paths:")
    robots_paths = check_robots_txt(target_url, user_agents)
    for path in robots_paths:
        print(f"  {path}")
    
    # Check for redirects
    print("\n[+] Checking for redirects...")
    redirects = check_initial_redirect(target_url, user_agents, args.verbose)
    
    # Display redirect information
    final_url = target_url
    if len(redirects) > 1 or any(r["type"] != "Initial" for r in redirects):
        print("\n[+] Redirect Information:")
        for redirect in redirects:
            print(f"  URL: {redirect['url']}")
            print(f"  Apex Domain: {redirect['apex_domain']}")
            print(f"  Type: {redirect['type']}")
            print(f"  Status Code: {redirect['status_code'] if redirect['status_code'] else 'N/A'}")
            print(f"  Resolved IPs: {', '.join(redirect['resolved_ips'])}")
            print(f"  Redirect URL: {redirect['redirect_url'] if redirect['redirect_url'] else 'None'}")
            print()
            if redirect["redirect_url"] and redirect["type"] != "Error":
                final_url = redirect["redirect_url"]
        
        print(f"[+] Final URL after redirects: {final_url}")
        choice = input("\nDo you want to proceed with fuzzing the final URL? (y/n): ").strip().lower()
        if choice != "y":
            print("Aborting scan.")
            return
    else:
        print("\n[+] No redirects detected.")
        choice = input(f"Do you want to proceed with fuzzing the original URL ({target_url})? (y/n): ").strip().lower()
        if choice != "y":
            print("Aborting scan.")
            return
    
    # DNS Information
    print("\n[+] DNS Information for Apex Domain:")
    dns_info = get_dns_info(apex_domain)
    for record_type, records in dns_info.items():
        print(f"  {record_type}: {', '.join(records) if records else 'None'}")
    
    # WHOIS Information
    print("\n[+] WHOIS Information for Apex Domain:")
    whois_info = get_whois_info(apex_domain)
    for key, value in whois_info.items():
        print(f"  {key.replace('_', ' ').title()}: {value}")
    
    # Fuzzing
    print(f"\n[+] Fuzzing directories from {directory_file} on {final_url}...")
    directories = read_directory_list(directory_file)
    if not directories:
        print("No directories to fuzz. Exiting.")
        return
    
    results = fuzz_directories(final_url, directories, user_agents, args.delay, args.verbose, output_dir)
    
    # Display Results
    print("\n[+] Fuzzing Results:")
    for result in results:
        status = f"Status: {result['status_code']}" if result['status_code'] else f"Error: {result.get('error', 'Unknown')}"
        exists = "Found" if result['exists'] else "Not Found"
        redirect = f" | Redirect: {result['redirect']}" if result['redirect'] else ""
        size = f" | Size: {result['response_size']} bytes"
        form = f" | Form: {'Yes' if result['has_form'] else 'No'}"
        screenshot = f" | Screenshot: {result['screenshot']}" if result['screenshot'] else ""
        print(f"  {result['url']} | {exists} | {status}{redirect}{size}{form}{screenshot}")
        if args.verbose and result["headers"]:
            print(f"    Headers: {result['headers']}")
    
    # Save results to file
    save_results_to_file(results, args.output)
    print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
