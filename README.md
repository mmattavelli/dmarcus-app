# DMARCus Analyzer

## Description

**DMARCus Analyzer** is a **Flask-based web application** for parsing, analyzing, and visualizing DMARC aggregate reports.  
It provides system administrators and security teams with actionable insights to improve email authentication policies (DMARC, SPF, DKIM), detect anomalies, and monitor email traffic patterns.

Developed by **Mattia Mattavelli** & **Luca Armiraglio**  

This tool is designed for **on-premises deployment** with:
- **Hardcoded credentials** for access control
- **Flat-file JSON storage** (no external database)
- Built-in security measures against CSRF, brute force, and malicious file uploads

---

## Key Features

### Analysis Capabilities
- Parses DMARC aggregate reports in **XML**, **GZIP (.gz)**, and **ZIP** formats
- Extracts and analyzes:
  - SPF/DKIM authentication results
  - Policy dispositions
  - Source IPs and associated domains
- Identifies **internal vs external** email sources via IP classification
- Optional **GeoIP integration** for IP location lookup
- Calculates KPIs such as:
  - Authentication pass rate
  - Alignment failures
  - Top IP senders

### Interactive Dashboard
- Overview metrics and key statistics at a glance
- Time-series charts for email/report trends
- Top IP and domain distribution graphs
- Drill-down into **organization-level** and **report-level** details
- Responsive HTML templates with Bootstrap & Chart.js

### Report Management
- Web-based upload with:
  - File type & MIME validation
  - Size limits
  - CSRF protection
- Export in **CSV** or **JSON** formats
- Manual reload of stored data without application restart
- Data stored in secure JSON flat files

---

## Security Features

- Hardcoded credentials verified using **constant-time comparison**
- **CSRF protection** on all POST requests
- **Rate limiting** to prevent brute-force login attempts and abuse
- File upload security:
  - Extension & MIME type checks
  - Secure temporary storage with random filenames
  - XML parsing with `defusedxml` to prevent XXE attacks
- Session security:
  - `HttpOnly` and `SameSite` cookies
  - Session lifetime control
- Content Security Policy (CSP) and strict HTTP headers

---

## Security Hardening

In addition to the default protections, DMARCus Analyzer includes:

1. **Restricted File Permissions**  
   JSON database files (`dmarc_reports.json`, `domains.json`) are created with owner-only read/write permissions.

2. **Secure Temporary File Handling**  
   Uploaded files are stored with random, non-guessable filenames and removed after processing.

3. **XML Parser Hardening**  
   All XML parsing uses `defusedxml` to block XML External Entity (XXE) and Billion Laughs attacks.

4. **MIME Type Validation**  
   Uploaded files are checked against expected MIME types (`application/xml`, `application/gzip`, `application/zip`) in addition to extension checks.

5. **Strict Session Security**  
   - `SESSION_COOKIE_HTTPONLY = True` to block JavaScript access  
   - `SESSION_COOKIE_SAMESITE = 'Strict'` to prevent CSRF via cross-site requests  
   - `SESSION_COOKIE_SECURE = True` for HTTPS-only cookies  

6. **Rate Limiting**  
   - Login endpoint: `5 per minute`  
   - Upload endpoint: `10 per minute`  

7. **Content Security Policy (CSP)**  
   Limits allowed sources for scripts, styles, and fonts to prevent XSS.

---

## Technology Stack

- **Backend**: Python 3, Flask
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5, Chart.js
- **Database**: JSON flat-file storage
- **Security Libraries**:
  - `flask-wtf` (CSRF protection)
  - `flask-limiter` (rate limiting)
  - `defusedxml` (secure XML parsing)
- **Parsing & Analysis**:
  - `ipaddress` (IP classification)
  - `geoip2` (optional IP geolocation)
  - `xml.etree` / `defusedxml` (report parsing)

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/<your-org>/dmarcus-analyzer.git
   cd dmarcus-analyzer
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **(Optional)** Set up GeoIP:
   - Download `GeoLite2-City.mmdb` from MaxMind
   - Place it in the application directory

4. **Run the application**:
   ```bash
   python dmarcus.py
   ```

---

