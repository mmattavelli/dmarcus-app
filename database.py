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
    try:
        with open(DB_FILE, 'r') as f:
            data = json.load(f)
            return data.get("reports", [])
    except (json.JSONDecodeError, FileNotFoundError):
        return []

def report_id_exists(report_id):
    """Check if a report with this ID already exists"""
    if not report_id:  # If report_id is None or empty string
        return False
        
    reports = load_reports()
    return any(str(report.get('report_id', '')).strip().lower() == str(report_id).strip().lower() 
           for report in reports)

def add_report(report):
    """Add a new report to the database if it doesn't exist already"""
    report_id = report.get('report_id')
    if report_id_exists(report_id):
        raise ValueError(f"Report with ID '{report_id}' already exists in the database")
    
    reports = load_reports()
    reports.append(report)
    save_reports(reports)