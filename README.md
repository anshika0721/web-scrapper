# WebVulnScanner

A comprehensive web application vulnerability scanner built in Python.

## Features

- 🔍 Recursive crawling with robots.txt respect
- 🛡️ Multiple vulnerability checks (XSS, SQLi, RCE, etc.)
- 🧠 Technology detection and fingerprinting
- 🕵️‍♀️ Authentication support
- 🧰 WAF bypass techniques
- 🧪 Burp Suite integration
- 📊 Web dashboard for results
- ⚙️ Modular plugin architecture

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/webvulnscanner.git
cd webvulnscanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
python scanner.py --url https://example.com
```

### With Authentication
```bash
python scanner.py --url https://example.com --auth-url https://example.com/login --username admin --password secret
```

### Using Burp Suite Proxy
```bash
python scanner.py --url https://example.com --burp-proxy http://127.0.0.1:8080
```

### Full Options
```bash
python scanner.py --url https://example.com \
    --depth 3 \
    --threads 10 \
    --delay 1 \
    --timeout 30 \
    --output results.json \
    --cookie "session=abc123" \
    --proxy http://127.0.0.1:8080
```

## Web Dashboard

Start the dashboard:
```bash
python dashboard.py
```

Access the dashboard at: http://localhost:5000

## Vulnerability Checks

The scanner includes checks for:
- Cross-Site Scripting (XSS)
- SQL Injection
- Command Injection
- Server-Side Request Forgery (SSRF)
- Local File Inclusion (LFI)
- Directory Traversal
- Open Redirects
- Clickjacking
- Insecure HTTP Headers

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any website. 