# 🔍 NmapX v3.0

NmapX is an advanced Python wrapper around `nmap` with asynchronous scanning, session history, change diffing, CVE enrichment, export capabilities, and Telegram alerts.

> Use this tool only on authorized systems and networks you control.

---

## ✨ What makes NmapX different

- **Asynchronous scanning** for faster multi-target operations
- **Built-in scan profiles** for common workflows
- **Scan history and diffs** using SQLite sessions
- **CVE enrichment** via NVD for detected services and CPEs
- **Secure input validation** to reduce injection risk
- **Safe API key handling** with masked logs and errors
- **Flexible exports**: JSON, CSV, Excel, HTML
- **Telegram notifications** for important scan events
- **Resume support** to skip already-completed scans

---

## 📦 Requirements

- Python 3.8 or newer
- Nmap installed and accessible in `PATH`
- Recommended: create a Python virtual environment

### Install Nmap

```bash
# Debian / Ubuntu
sudo apt install nmap

# macOS
brew install nmap

# Windows
# Download and install from https://nmap.org/download.html
```

---

## ⚡ Install NmapX

Install directly from source (recommended — makes `nmapx` available system-wide):

```bash
pip install .
```

After installation, you can run NmapX from anywhere using:

```bash
nmapx scanme.nmap.org
```

Or install dependencies without packaging:

```bash
pip install -r requirements.txt
```

---

## 🚀 Quick Start

```bash
# Basic scan (using the installed command)
nmapx scanme.nmap.org

# Or run directly from source
python nmapx_app.py scanme.nmap.org

# Service scan + CVE enrichment
nmapx 192.168.1.0/24 -p service --cve --nvd-key "YOUR_NVD_API_KEY"

# Scan multiple targets and export to JSON/CSV
nmapx 10.0.0.1 10.0.0.2 -p quick --json report.json --csv report.csv

# Generate an interactive HTML report
nmapx scanme.nmap.org -p service --cve --html report.html
```

---

## 🎯 Scan Profiles

| Profile      | Purpose                                 | Example flags                         |
|--------------|-----------------------------------------|----------------------------------------|
| `quick`      | Top 100 ports with speed T4             | `-T4 --top-ports 100`                  |
| `full`       | Full port scan across all 65535 ports   | `-T4 -p-`                              |
| `stealth`    | SYN stealth scan (privileged)           | `-sS -T2 -p-`                          |
| `service`    | Service/version detection               | `-sV --version-intensity 7 -T4`        |
| `os`         | OS fingerprinting (privileged)          | `-O -T4`                               |
| `vuln`       | Run NSE vulnerability scripts           | `-sV --script=vuln -T4`                |
| `aggressive` | OS/version/scripts/traceroute combo     | `-A -T4`                               |
| `udp`        | UDP top ports (privileged)              | `-sU -T4 --top-ports 100`              |
| `ping`       | Host discovery only                     | `-sn`                                  |
| `custom`     | Use raw nmap flags                      | `--flags "<nmap flags>"`             |

List available profiles:

```bash
python nmapx_app.py --list
```

---

## 📁 Export Formats

```bash
# JSON with schema
python nmapx_app.py target -p service --json report.json

# CSV export
python nmapx_app.py target -p service --csv report.csv

# Excel workbook
python nmapx_app.py target -p service --excel report.xlsx

# HTML interactive report
python nmapx_app.py target -p service --cve --html report.html

# Raw nmap output only
python nmapx_app.py target -p service --raw
```

---

## 📊 Session History & Diffs

Use history and diff features to track changes over time.

```bash
# Show recent scan sessions
python nmapx_app.py --history

# Compare the two most recent scans for a target
python nmapx_app.py --diff scanme.nmap.org
```

The diff output highlights:
- newly opened or closed ports
- version changes
- service changes
- CPE updates
- CVE additions/removals

---

## 🔔 Telegram Notifications

Setup a Telegram bot using [@BotFather](https://t.me/BotFather), then configure environment variables:

```bash
set TELEGRAM_BOT_TOKEN=123456:ABCDEF
set TELEGRAM_CHAT_ID=123456789
```

Run with notifications enabled:

```bash
python nmapx_app.py 192.168.1.10 -p service --notify telegram
```

Only notify on specific events:

```bash
python nmapx_app.py 192.168.1.10 -p service --cve --notify telegram --notify-on new-port,critical-cve
```

Supported event types:
- `new-port`
- `version-change`
- `critical-cve`
- `scan-failed`

---

## 🔧 Advanced Usage

```bash
# Run more workers for parallel scans
python nmapx_app.py targets.txt -p service --workers 10

# Skip specific hosts or ranges
python nmapx_app.py 10.0.0.0/24 -p ping --exclude 10.0.0.1,10.0.0.2

# Send scanning through proxies
python nmapx_app.py target -p service --proxies "http://proxy1:8080,https://proxy2:3128"

# Provide NSE script arguments
python nmapx_app.py target -p vuln --script-args "http.useragent=nmapx,ftp.anon=true"

# Resume from previously completed results
python nmapx_app.py target1 target2 -p service --resume
```

---

## 🔐 Security & best practices

- Validate targets only on authorized systems
- Keep NVD API keys secret
- Prefer environment variables over CLI API key arguments
- Use `--resume` to avoid repeated work
- Always run scans with the minimum privileges needed

Recommended environment settings:

```bash
set NVD_API_KEY=your_nvd_api_key
set TELEGRAM_BOT_TOKEN=your_token
set TELEGRAM_CHAT_ID=your_chat_id
```

---

## ✅ Testing

Run the repository test suite:

```bash
python -m pytest test_api_key_verification.py tests -q
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE).

Developed by **KIMYA_Lab**.
