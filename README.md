# DMARCus Analyzer

## Description

DMARCus Analyzer is a Flask-based web application designed to parse and visualize DMARC reports in an intuitive way. This tool helps system administrators and security professionals monitor email authentication, identify potential threats, and improve DMARC policies.

Developed by **Mattia Mattavelli** & **Luca Armiraglio**

## Key Features

### Analysis Capabilities
- **Advanced parsing** of DMARC reports in XML and XML.gz formats
- **Detailed statistics** on SPF/DKIM authentication, dispositions, source IPs, and domains
- **Internal IP detection** to identify internal vs external traffic
- **GeoIP support** (optional with provided database)

### Interactive Dashboard
- **Comprehensive data visualization** with charts and tables
- **6 different chart types** for multidimensional analysis
- **KPI cards** for at-a-glance metrics
- **Summary table** of all reports with authentication status

### Report Management
- **Simple upload** of single or batch reports
- **Data export** in CSV and JSON formats
- **Manual reload** of reports without restart
- **Persistent storage** in JSON database

### User Interface
- **Modern design** with light/dark theme
- **Navigable sidebar** for quick access to functions
- **Smooth animations** and visual feedback
- **Responsive design** for various devices

## Technology Stack

- **Backend**: Python 3, Flask
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5, Chart.js
- **Database**: JSON flat-file
- **Key Dependencies**:
  - `geoip2` for IP geolocation
  - `ipaddress` for IP address analysis
  - `xml.etree` for XML parsing

## Installation

```bash
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. (Optional) Set up GeoIP with `GeoLite2-City.mmdb` database
4. Run: `python dmarcus.py`
