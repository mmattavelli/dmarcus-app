import json
import os
from datetime import datetime

DB_FILE = 'dmarc_reports.json'

def init_db():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, 'w') as f:
            json.dump({"reports": [], "last_updated": None}, f)

def save_reports(reports):
    with open(DB_FILE, 'w') as f:
        json.dump({
            "reports": reports,
            "last_updated": datetime.now().isoformat()
        }, f, indent=2)

def load_reports():
    init_db()
    with open(DB_FILE, 'r') as f:
        data = json.load(f)
    return data.get("reports", [])

def add_report(report):
    reports = load_reports()
    reports.append(report)
    save_reports(reports)
