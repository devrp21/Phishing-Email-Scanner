# 🛡️ Phishing Email Scanner

This Python tool helps you analyze HTML email content to detect phishing links. It extracts URLs, resolves their IP addresses (including IPv6), and checks both against VirusTotal and IPInfo for reputation and geolocation details.

---

## 🚀 Features

- ✅ Extracts links from HTML and quoted-printable emails
- 🌐 Resolves domain names to **IPv4/IPv6**
- 🔍 Scans URLs and IPs using [VirusTotal](https://www.virustotal.com/)
- 📍 Gets IP location & ISP info from [IPInfo.io](https://ipinfo.io/)
- 📊 Provides clear detection report on malicious or suspicious items

---

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/devrp21/Phishing-Email-Scanner.git
cd phishing-email-scanner
````

### 2. Set Up Environment

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Edit the `.env` file to include your API keys.

### 3. Install Requirements

```bash
pip install -r requirements.txt
```

---

## 🔑 Get API Tokens

* **VirusTotal API key**: [Get one here](https://www.virustotal.com/gui/join-us)
* **IPInfo API token**: [Get one here](https://ipinfo.io/signup)

---

## 📄 Usage

### Run the Script:

```bash
python phishing_email_scanner.py
```

### Then paste your email content:

* Press **Enter**, then
* **Ctrl+D** (Linux/macOS) or **Ctrl+Z + Enter** (Windows) to end input.

---

## 🧪 Example

### Sample Email Input:

Paste this:

```html
<html>
  <body>
    <a href="http://malicious-website.com/login">Click here to login</a>
  </body>
</html>
```

### Sample Output:

```
Extracted Links:
 - http://malicious-website.com/login

Phishing Detection Report:
============================================================
🔗 URL: http://malicious-website.com/login
  - Malicious (URL): 2, Suspicious (URL): 1
  - Resolved IP: 203.0.113.42 (IPv4)
  - Malicious (IP): 3, Suspicious (IP): 0
  - Geo Info: Amsterdam, North Holland, NL | Org: AS12345 BadISP
------------------------------------------------------------
```

---

## 🧾 Requirements

See `requirements.txt`:

```txt
requests
beautifulsoup4
python-dotenv
```

Install with:

```bash
pip install -r requirements.txt
```

---

## 📁 File Descriptions

| File                        | Description                        |
| --------------------------- | ---------------------------------- |
| `phishing_email_scanner.py` | Main script                        |
| `.env.example`              | Template for environment variables |
| `requirements.txt`          | Dependencies                       |
| `README.md`                 | Documentation                      |

---

## 🛡️ Disclaimer

This tool is intended for **educational and cybersecurity analysis** purposes. Do not use it for unauthorized scanning of systems.

---

## 📬 Contribute

Feel free to open issues or PRs for enhancements!

---

## 👨‍💻 Author

Made with ❤️ by [Dev](https://github.com/devrp21)
