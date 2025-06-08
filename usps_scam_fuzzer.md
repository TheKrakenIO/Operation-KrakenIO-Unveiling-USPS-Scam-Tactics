# USPS Scam Fuzzing Tool

## Overview

The **USPS Scam Fuzzing Tool** is a Python-based utility developed as part of **Operation KrakenIO**, designed to expose deceptive practices in USPS-related scams. The tool analyzes target websites to identify common scam tactics by fuzzing for specific files and directories, retrieving DNS and WHOIS information, checking for redirections, and performing advanced checks, such as SSL verification and form detection. It empowers users to detect and safeguard against fraudulent schemes mimicking the United States Postal Service (USPS).

## Features

- **Directory Fuzzing**: Scans for standard scam-related files ( `cc.php`, `index.php`, `thanks.php`) listed in `files_directories.txt`.
- **DNS and WHOIS Lookup**: Retrieves DNS records (A, MX, NS, TXT) and WHOIS data (registrar, registrant, dates) for the target domain.
- **Redirection Detection**: Identifies HTTP, JavaScript, and DNS-based redirects, displaying the redirection chain and apex domains, with user prompts to proceed with fuzzing.
- **SSL Verification**: Validates SSL certificates for HTTPS URLs, showing issuer, subject, and expiration details.
- **Response Size Check**: Logs response sizes to identify lightweight scam pages.
- **Rate Limit Detection**: Detects HTTP 429 (Too Many Requests) responses, pausing and retrying to avoid blocking.
- **CLI Options**: Supports command-line arguments for delay, output file, and verbose mode.
- **robots.txt Analysis**: Parses `robots.txt` to list disallowed paths that may hide scam pages.
- **HTTP Header Analysis**: Captures response headers ( `Server`, `X-Powered-By`) to reveal server tech stack.
- **Form Detection**: Identifies HTML forms in responses, flagging potential phishing pages.
- **Screenshots**: Captures screenshots of pages with an HTTP 200 status and saves them to a `screenshots/` directory.
- **Steady Fuzzing**: Adds delays between requests to avoid server blocking.
- **User-Agent Rotation**: Uses a customizable list of browser-like User-Agents to mimic real traffic.
- **VPN Reminder**: Prompts users to use a VPN for privacy before scanning.
- **Output Logging**: Saves detailed results (status, size, headers, forms, screenshots, redirects) to a specified file.

## Prerequisites

### Software
- Python 3.8+
- `playwright` browser binaries (installed via `playwright install`)

### Python Libraries
Install the required libraries using pip:

```bash
pip install requests dnspython python-whois tldextract beautifulsoup4 playwright
playwright install
```
## Input File
Create a files_directories.txt file with scam-related files, one per line:

```text
cc.php
index.php
index2.php
index3.php
index4.php
index5.php
wait1.php
wait2.php
wait3.php
wait4.php
wait5.php
thanks.php
thank.php
Thank.php
sms.php
sms2.php
```

## Installation
1- Clone or download this repository.

2- Install the required Python libraries (see above).

3- Create files_directories.txt with the list of files to fuzz.

4- Ensure playwright browser binaries are installed.

## Usage

Run the script via the command line, providing the target URL and optional arguments:

```bash
python usps_scam_fuzzer.py <target_url> [--delay <seconds>] [--output <filename>] [--verbose]
```
## Arguments
* <target_url>: The URL to scan ( http://suspicious-site.com).
--delay: Delay between requests in seconds (default: 1.0).
--output: Output file for results (default: fuzzing_results.txt).
--verbose: Enable detailed output, including headers and rate limit messages.
```bash
python usps_scam_fuzzer.py http://suspicious-site .com --delay 0.5 --output results.txt --verbose
```
## Workflow
* VPN Reminder: This prompt reminds you to use a VPN for enhanced privacy (press Enter to continue).
* Input Validation: Ensures the URL has a scheme (defaults to https:// if missing).
* SSL Check: Verifies SSL certificate for HTTPS URLs.
* robots.txt: Lists disallowed paths from robots.txt.
* Redirect Check: Detects HTTP, JS, or DNS redirects and prompts to fuzz the final URL (or the original URL if no redirects are detected).
* DNS/WHOIS: Displays DNS records and WHOIS data for the apex domain.
* Fuzzing: Scans for files in files_directories.txt, checking status, size, headers, forms, and capturing screenshots for HTTP 200 responses.
* Output: Prints results to the console and saves them to the specified file.

Sample Output

```bash
 [!] IMPORTANT: For your privacy and safety, please ensure you are using a VPN before scanning.
Press Enter to continue...

[+] Target URL: http://suspicious-site.com
[+] Domain: suspicious-site.com
[+] Apex Domain: suspicious-site.com

[+] SSL Verification:
  Valid: No
  Error: Not an HTTPS URL

[+] robots.txt Disallowed Paths:
  /admin
  /private

[+] Checking for redirects...
[+] No redirects detected.
Do you want to proceed with fuzzing the original URL (http://suspicious-site.com)? (y/n): y

[+] DNS Information for Apex Domain:
  A: 192.0.2.1
  MX: mx.suspicious-site.com
  NS: ns1.suspicious-site.com
  TXT: None

[+] WHOIS Information for Apex Domain:
  Registrar: GoDaddy
  Registrant: John Doe
  Creation Date: 2024-01-01
  Expiration Date: 2026-01-01

[+] Fuzzing directories from files_directories.txt on http://suspicious-site.com...

[+] Fuzzing Results:
  http://suspicious-site.com/cc.php | Found | Status: 200 | Size: 1234 bytes | Form: Yes | Screenshot: screenshots/screenshot_cc.php.png
    Headers: {'Server': 'nginx', 'Content-Type': 'text/html'}
  http://suspicious-site.com/index.php | Not Found | Status: 404 | Size: 300 bytes | Form: No
  http://suspicious-site.com/thanks.php | Not Found | Status: 302 | Redirect: https://www.usps.com | Size: 0 bytes | Form: No

[+] Results saved to results.txt
```
## Output File (results.txt)

```bash
URL: http://suspicious-site.com/cc.php
Exists: Yes
Status Code: 200
Response Size: 1234 bytes
Headers: {'Server': 'nginx', 'Content-Type': 'text/html'}
Has Form: Yes
Screenshot: screenshots/screenshot_cc.php.png
Redirect: None

URL: http://suspicious-site.com/index.php
Exists: No
Status Code: 404
Response Size: 300 bytes
Headers: {'Server': 'nginx'}
Has Form: No
Screenshot: None
Redirect: None
...
```
