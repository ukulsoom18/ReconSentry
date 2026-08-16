# ReconSentry
# 🔍 ReconSentry — Footprinting & Reconnaissance Tool

> **All-in-one passive & active reconnaissance framework for authorized cybersecurity assessments.**

---

## 📌 Overview

**ReconSentry** is a Python-based cybersecurity tool designed for footprinting and reconnaissance — the first phase of ethical hacking and penetration testing. It automates intelligence gathering on a target domain or IP address across six specialized modules, combining passive OSINT with active probing techniques.

Developed as part of a BS Cybersecurity assignment at COMSATS University Islamabad.

---

## ⚙️ Modules

| # | Module | Techniques Used |
|---|--------|----------------|
| 1 | **WHOIS & DNS Recon** | WHOIS lookup, A/AAAA/MX/NS/TXT/SOA/CNAME records |
| 2 | **IP Geolocation & ASN** | IP-API, PTR/Reverse DNS, ISP & ASN mapping |
| 3 | **Subdomain Enumeration** | Certificate Transparency (crt.sh), DNS brute-force |
| 4 | **Port Scanner & Banner Grabbing** | TCP connect scan, service banner extraction |
| 5 | **Email Harvesting** | Hunter.io API, WHOIS emails, pattern generation |
| 6 | **IoT / Host Intelligence** | Shodan API, ipwho.is enrichment, VPN/Proxy/Bot detection |

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ReconSentry.git
cd ReconSentry

# Install dependencies
pip install -r requirements.txt
```

---

## 🛠️ Usage

### Basic Scan
```bash
python reconsentry.py example.com
```

### Custom Output Directory
```bash
python reconsentry.py example.com -o ./reports
```

### With API Keys (recommended)
```bash
python reconsentry.py example.com --shodan-key YOUR_KEY --hunter-key YOUR_KEY
```

### Custom Port List
```bash
python reconsentry.py example.com --ports 22,80,443,8080,8443
```

### Skip Specific Modules
```bash
python reconsentry.py example.com --skip 3,5
```

---

## 📋 Output

ReconSentry generates two report files automatically:
- **JSON** — Machine-readable structured data (for integration/further analysis)
- **TXT** — Human-readable formatted report

Example output files:
```
ReconSentry_example_com_20260816_143022.json
ReconSentry_example_com_20260816_143022.txt
```

---

## 🔑 API Keys (Optional)

| API | Free Tier | Used For |
|-----|-----------|----------|
| [Shodan](https://shodan.io) | 1 query/sec | IoT device intel, open ports, CVEs |
| [Hunter.io](https://hunter.io) | 25 req/month | Email harvesting |

Without API keys, ReconSentry falls back to free public APIs and still provides substantial intelligence.

---

## 📁 Project Structure

```
ReconSentry/
├── reconsentry.py      # Main tool (all 6 modules)
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## ⚠️ Legal Disclaimer

ReconSentry is intended **strictly for authorized penetration testing and security research**. Always obtain written permission before scanning any system or network you do not own. Unauthorized scanning may violate laws including the Computer Fraud and Abuse Act (CFAA) and similar regulations in your jurisdiction.

The author assumes **no liability** for misuse of this tool.

---

## 👩‍💻 Author

**Umme Kulsoom**  
BS Cybersecurity, COMSATS University Islamabad  

---

## 📄 License

This project is licensed for educational use only.

