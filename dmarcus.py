import gzip
import shutil
from flask import Flask, render_template_string, request, redirect, url_for, flash, make_response
import os
from xml.etree import ElementTree as ET
from datetime import datetime, timedelta
from collections import defaultdict
import json
import csv
from io import StringIO
import ipaddress
import geoip2.database
from werkzeug.utils import secure_filename
from database import load_reports, save_reports, add_report
from flask import render_template
import re

import logging
logging.basicConfig(filename='dmarcus.log', level=logging.INFO)

# Setup GeoIP (commentato se non disponibile)
# geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
__version__ = "0.6"

app = Flask(__name__)
print("Static folder path:", app.static_folder)

app.secret_key = 'supersecretkey'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DB_FILE = 'dmarc_reports.json'
DOMAINS_FILE = 'domains.json'

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize data structures
reports_data = []
domains_data = []




def init_db():
    """Initialize database files if they don't exist"""
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, 'w') as f:
            json.dump({"reports": [], "last_updated": None}, f)
    else:
        # Verifica che il file sia valido
        try:
            with open(DB_FILE, 'r') as f:
                json.load(f)
        except json.JSONDecodeError:
            # Se il file è corrotto, ricrealo
            with open(DB_FILE, 'w') as f:
                json.dump({"reports": [], "last_updated": None}, f)
    
    if not os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE, 'w') as f:
            json.dump({"domains": [], "last_updated": None}, f)
    else:
        # Verifica che il file sia valido
        try:
            with open(DOMAINS_FILE, 'r') as f:
                json.load(f)
        except json.JSONDecodeError:
            # Se il file è corrotto, ricrealo
            with open(DOMAINS_FILE, 'w') as f:
                json.dump({"domains": [], "last_updated": None}, f)



def analyze_email_headers(headers):
    """Analyze email headers for DMARC, SPF, DKIM"""
    try:
        headers_dict = parse_email_headers(headers)
        if not headers_dict:
            return {'error': 'Invalid email headers format'}
        
        # Extract basic info
        from_header = headers_dict.get('From', 'N/A')
        subject = headers_dict.get('Subject', 'N/A')
        date = headers_dict.get('Date', 'N/A')
        
        # Initialize results
        results = {
            'basic_info': {
                'from': from_header,
                'subject': subject,
                'date': date
            },
            'dmarc': {
                'status': 'none',
                'domain': 'N/A',
                'policy': 'N/A',
                'alignment': 'N/A',
                'result': 'N/A'
            },
            'spf': {
                'status': 'none',
                'domain': 'N/A',
                'ip': 'N/A',
                'scope': 'N/A',
                'result': 'N/A'
            },
            'dkim': {
                'status': 'none',
                'domain': 'N/A',
                'selector': 'N/A',
                'algorithm': 'N/A',
                'result': 'N/A'
            },
            'raw_headers': headers
        }
        
        # Parse Authentication-Results header if present
        auth_results = headers_dict.get('Authentication-Results', '')
        if auth_results:
            # Simple parsing - in a real app you'd want more robust parsing
            if 'dmarc=pass' in auth_results.lower():
                results['dmarc']['status'] = 'pass'
                results['dmarc']['result'] = 'DMARC validation passed'
            elif 'dmarc=fail' in auth_results.lower():
                results['dmarc']['status'] = 'fail'
                results['dmarc']['result'] = 'DMARC validation failed'
            
            if 'spf=pass' in auth_results.lower():
                results['spf']['status'] = 'pass'
                results['spf']['result'] = 'SPF validation passed'
            elif 'spf=fail' in auth_results.lower():
                results['spf']['status'] = 'fail'
                results['spf']['result'] = 'SPF validation failed'
            
            if 'dkim=pass' in auth_results.lower():
                results['dkim']['status'] = 'pass'
                results['dkim']['result'] = 'DKIM validation passed'
            elif 'dkim=fail' in auth_results.lower():
                results['dkim']['status'] = 'fail'
                results['dkim']['result'] = 'DKIM validation failed'
        
        # Parse DKIM-Signature header if present
        dkim_sig = headers_dict.get('DKIM-Signature', '')
        if dkim_sig:
            # Extract DKIM info
            dkim_parts = [p.strip() for p in dkim_sig.split(';') if p.strip()]
            for part in dkim_parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    key = key.strip().lower()
                    if key == 'd':
                        results['dkim']['domain'] = value.strip()
                    elif key == 's':
                        results['dkim']['selector'] = value.strip()
                    elif key == 'a':
                        results['dkim']['algorithm'] = value.strip()
        
        # Parse Received-SPF header if present
        received_spf = headers_dict.get('Received-SPF', '')
        if received_spf:
            # Extract SPF info
            spf_parts = [p.strip() for p in received_spf.split(' ') if p.strip()]
            for part in spf_parts:
                if part.startswith('client-ip='):
                    results['spf']['ip'] = part.split('=')[1]
                elif part.startswith('envelope-from='):
                    results['spf']['scope'] = 'mfrom'
                    results['spf']['domain'] = part.split('@')[-1] if '@' in part else 'N/A'
        
        # Parse DMARC policy if present
        dmarc_policy = headers_dict.get('DMARC-Results', '')
        if dmarc_policy:
            # Extract DMARC policy info
            policy_parts = [p.strip() for p in dmarc_policy.split(';') if p.strip()]
            for part in policy_parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    key = key.strip().lower()
                    if key == 'p':
                        results['dmarc']['policy'] = value.strip()
                    elif key == 'adkim':
                        results['dmarc']['alignment'] = 'Strict' if value.strip() == 's' else 'Relaxed'
        
        return results
    except Exception as e:
        print(f"Error analyzing headers: {str(e)}")
        return {'error': str(e)}

def parse_eml_file(file):
    """Parse an EML file for analysis"""
    try:
        # Parse the EML file
        msg = BytesParser(policy=policy.default).parse(file)
        
        # Get headers as text
        headers = '\n'.join(f"{k}: {v}" for k, v in msg.items())
        
        # Analyze the headers
        return analyze_email_headers(headers)
    except Exception as e:
        return {'error': str(e)}

def parse_dmarc_report(file):
    """Parse a DMARC report file (XML or GZ)"""
    try:
        # Read file content
        if file.filename.endswith('.gz'):
            import gzip
            import io
            file_content = file.read()
            with gzip.open(io.BytesIO(file_content), 'rb') as f_in:
                content = f_in.read().decode('utf-8')
        else:
            content = file.read().decode('utf-8')
        
        # Reset file pointer
        file.seek(0)
        
        # Parse XML
        root = ET.fromstring(content)
        
        report = {
            'org': safe_find_text(root, './/org_name'),
            'email': safe_find_text(root, './/email'),
            'report_id': safe_find_text(root, './/report_id'),
            'date_range': {
                'start': timestamp_to_date(safe_find_text(root, './/date_range/begin')),
                'end': timestamp_to_date(safe_find_text(root, './/date_range/end')),
                'start_ts': int(safe_find_text(root, './/date_range/begin', '0')),
                'end_ts': int(safe_find_text(root, './/date_range/end', '0'))
            },
            'policy': {
                'domain': safe_find_text(root, './/policy_published/domain'),
                'adkim': safe_find_text(root, './/policy_published/adkim', 'r'),
                'aspf': safe_find_text(root, './/policy_published/aspf', 'r'),
                'p': safe_find_text(root, './/policy_published/p'),
                'sp': safe_find_text(root, './/policy_published/sp', 'N/A'),
                'pct': safe_find_text(root, './/policy_published/pct', '100'),
                'fo': safe_find_text(root, './/policy_published/fo', '0')
            },
            'records': []
        }

        # Extract records
        for record in root.findall('.//record'):
            policy_evaluated = record.find('.//row/policy_evaluated')
            auth_results = record.find('.//auth_results')
            
            source_ip = safe_find_text(record, './/row/source_ip')
            count = int(safe_find_text(record, './/row/count', "0"))
            
            row_data = {
                'source_ip': source_ip,
                'count': count,
                'disposition': safe_find_text(policy_evaluated, './/disposition') if policy_evaluated is not None else 'N/A',
                'dkim': safe_find_text(auth_results, './/dkim/result', '').lower() if auth_results is not None else 'N/A',
                'spf': safe_find_text(auth_results, './/spf/result', '').lower() if auth_results is not None else 'N/A',
                'header_from': safe_find_text(record, './/identifiers/header_from'),
                'is_internal': is_ip_private(source_ip),
                'location': get_ip_location(source_ip),
                'dkim_domain': safe_find_text(auth_results, './/dkim/domain', '') if auth_results is not None else '',
                'spf_domain': safe_find_text(auth_results, './/spf/domain', '') if auth_results is not None else ''
            }
            report['records'].append(row_data)
        
        return report
        
    except Exception as e:
        return {'error': str(e)}


def save_reports(reports):
    with open(DB_FILE, 'w') as f:
        json.dump({
            "reports": reports,
            "last_updated": datetime.now().isoformat()
        }, f, indent=2)


def load_domains():
    """Load domains from JSON file"""
    init_db()
    try:
        with open(DOMAINS_FILE, 'r') as f:
            data = json.load(f)
            return data.get("domains", [])
    except Exception as e:
        print(f"Error loading domains: {str(e)}")
        return []

def sync_domains():
    """Sync in-memory domains with file"""
    global domains_data
    domains_data = load_domains()

def save_domains(domains):
    """Save domains to JSON file"""
    try:
        with open(DOMAINS_FILE, 'w') as f:
            json.dump({
                "domains": domains,
                "last_updated": datetime.now().isoformat()
            }, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving domains: {str(e)}")
        return False

def add_domain(domain):
    """Add a new domain to the database"""
    domains = load_domains()
    domains.append(domain)
    if save_domains(domains):
        sync_domains()
        return True
    return False

def load_reports():
    init_db()
    try:
        with open(DB_FILE, 'r') as f:
            data = json.load(f)
            print(f"\nDEBUG: Loaded data from {DB_FILE}")  # Debug
            print(f"Data keys: {data.keys()}")  # Debug
            print(f"Number of reports: {len(data.get('reports', []))}")  # Debug
            return data.get("reports", [])
    except Exception as e:
        print(f"DEBUG: Error loading reports - {str(e)}")  # Debug
        return []

def add_report(report):
    reports = load_reports()
    reports.append(report)
    save_reports(reports)
    reports_data.append(report)

def backup_domains():
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = f"domains_backup_{timestamp}.json"
    with open(DOMAINS_FILE, 'r') as src, open(backup_file, 'w') as dst:
        dst.write(src.read())

# Carica i report all'avvio
reports_data = load_reports()
domains_data = load_domains()

def format_datetime(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return "Never"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format)

app.jinja_env.filters['format_datetime'] = format_datetime

# Helper functions
def safe_find_text(element, path, default="N/A"):
    found = element.find(path)
    return found.text if found is not None else default

def timestamp_to_date(ts, default="N/A"):
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M')
    except:
        return default

def extract_gz(gz_path, output_path):
    with gzip.open(gz_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return output_path

def get_ip_location(ip):
    try:
        # Implementazione reale richiede database GeoIP
        # response = geoip_reader.city(ip)
        # return f"{response.city.name}, {response.country.name}"
        return "Location data unavailable"
    except:
        return "Unknown"

def is_ip_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

# Sostituisci le funzioni importate da utils con queste:

def load_report(report_id):
    """Carica un report dall'array in memoria usando l'ID"""
    try:
        report_id = int(report_id)  # Converti in indice array
        if 0 <= report_id < len(reports_data):
            return reports_data[report_id]
        raise ValueError("Invalid report ID")
    except (ValueError, IndexError):
        raise ValueError(f"Report {report_id} not found")

def aggregate_reports(report_ids):
    """Combina più report dalla memoria"""
    reports = []
    for id in report_ids:
        try:
            reports.append(load_report(id))
        except ValueError:
            continue
    
    if not reports:
        return None
    
    return {
        'org': reports[0]['org'],
        'report_id': ','.join(r['report_id'] for r in reports),
        'date_range': {
            'start': min(r['date_range']['start'] for r in reports),
            'end': max(r['date_range']['end'] for r in reports)
        },
        'policy': reports[0]['policy'],
        'records': [record for r in reports for record in r['records']]
    }

def parse_dmarc_report(file):
    try:
        # Leggi il contenuto del file in memoria
        if file.filename.endswith('.gz'):
            # Se è un file gzip, decomprimi in memoria
            import gzip
            import io
            file_content = file.read()
            with gzip.open(io.BytesIO(file_content), 'rb') as f_in:
                content = f_in.read().decode('utf-8')
        else:
            # Se è un file XML normale, leggi direttamente
            content = file.read().decode('utf-8')
        
        # Resetta il puntatore del file dopo la lettura
        file.seek(0)
        
        # Parsing del contenuto XML
        root = ET.fromstring(content)
        
        # Resto del codice rimane uguale...
        report = {
            'org': safe_find_text(root, './/org_name'),
            'email': safe_find_text(root, './/email'),
            'report_id': safe_find_text(root, './/report_id'),
            'date_range': {
                'start': timestamp_to_date(safe_find_text(root, './/date_range/begin')),
                'end': timestamp_to_date(safe_find_text(root, './/date_range/end')),
                'start_ts': int(safe_find_text(root, './/date_range/begin', '0')),
                'end_ts': int(safe_find_text(root, './/date_range/end', '0'))
            },
            'policy': {
                'domain': safe_find_text(root, './/policy_published/domain'),
                'adkim': safe_find_text(root, './/policy_published/adkim', 'r'),
                'aspf': safe_find_text(root, './/policy_published/aspf', 'r'),
                'p': safe_find_text(root, './/policy_published/p'),
                'sp': safe_find_text(root, './/policy_published/sp', 'N/A'),
                'pct': safe_find_text(root, './/policy_published/pct', '100'),
                'fo': safe_find_text(root, './/policy_published/fo', '0')
            },
            'records': []
        }

        # Estrazione dei record (come nella versione precedente)
        for record in root.findall('.//record'):
            policy_evaluated = record.find('.//row/policy_evaluated')
            auth_results = record.find('.//auth_results')
            
            source_ip = safe_find_text(record, './/row/source_ip')
            count = int(safe_find_text(record, './/row/count', "0"))
            
            row_data = {
                'source_ip': source_ip,
                'count': count,
                'disposition': safe_find_text(policy_evaluated, './/disposition') if policy_evaluated is not None else 'N/A',
                'dkim': safe_find_text(auth_results, './/dkim/result', '').lower() if auth_results is not None else 'N/A',
                'spf': safe_find_text(auth_results, './/spf/result', '').lower() if auth_results is not None else 'N/A',
                'header_from': safe_find_text(record, './/identifiers/header_from'),
                'is_internal': is_ip_private(source_ip),
                'location': get_ip_location(source_ip),
                'dkim_domain': safe_find_text(auth_results, './/dkim/domain', '') if auth_results is not None else '',
                'spf_domain': safe_find_text(auth_results, './/spf/domain', '') if auth_results is not None else ''
            }
            report['records'].append(row_data)
        
        return report
        
    except Exception as e:
        return {'error': str(e)}

def backup_domains():
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = f"domains_backup_{timestamp}.json"
    with open(DOMAINS_FILE, 'r') as src, open(backup_file, 'w') as dst:
        dst.write(src.read())    



def calculate_pass_rate(report):
    """Calculate authentication pass rate for a report"""
    total = len(report['records'])
    if total == 0:
        return 0
    
    passed = sum(1 for r in report['records']
              if r['spf'] == 'pass' and r['dkim'] == 'pass'
              and r['spf_domain'].endswith(report['policy']['domain'])
              and r['dkim_domain'].endswith(report['policy']['domain']))
    
    return round((passed / total) * 100, 1)

def calculate_auth_data(report):
    """Calculate authentication data for charts"""
    data = {
        'both_pass': 0,
        'spf_pass': 0,
        'dkim_pass': 0,
        'alignment_fail': 0,
        'fail': 0
    }
    
    for record in report['records']:
        spf_ok = record['spf'] == 'pass'
        dkim_ok = record['dkim'] == 'pass'
        spf_aligned = record['spf_domain'].endswith(report['policy']['domain'])
        dkim_aligned = record['dkim_domain'].endswith(report['policy']['domain'])
        
        if spf_ok and dkim_ok and spf_aligned and dkim_aligned:
            data['both_pass'] += 1
        elif spf_ok and spf_aligned:
            data['spf_pass'] += 1
        elif dkim_ok and dkim_aligned:
            data['dkim_pass'] += 1
        elif spf_ok or dkim_ok:
            data['alignment_fail'] += 1
        else:
            data['fail'] += 1
    
    return data

def calculate_dispositions(report):
    """Conta le disposizioni dei record"""
    dispositions = defaultdict(int)
    for record in report['records']:
        dispositions[record['disposition']] += 1
    return dispositions

def calculate_internal_external(report):
    """Calcola il rapporto IP interni/esterni"""
    counts = {'internal': 0, 'external': 0}
    for record in report['records']:
        if record['is_internal']:
            counts['internal'] += 1
        else:
            counts['external'] += 1
    return counts

def prepare_ip_chart_data(report):
    """Prepara i dati per il grafico degli IP"""
    ip_counts = defaultdict(int)
    for record in report['records']:
        ip_counts[record['source_ip']] += record['count']
    
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        'ips': [ip[0] for ip in sorted_ips],
        'counts': [ip[1] for ip in sorted_ips]
    }

def get_ip_addresses(report):
    """Restituisce gli IP unici con i loro conteggi"""
    ip_counts = defaultdict(int)
    for record in report['records']:
        ip_counts[record['source_ip']] += record['count']
    return ip_counts

def report_id_exists(report_id):
    """Check if a report with this ID already exists"""
    return any(report['report_id'] == report_id for report in reports_data)

def domain_exists(domain_name):
    """Check if a domain already exists (case-insensitive)"""
    return any(d['name'].lower() == domain_name.lower() for d in domains_data)

def generate_stats(reports_data, time_filter='30days'):
    if not reports_data:
        return None
        
    # Inizializza le strutture dati per le statistiche
    stats = {
        'total_reports': len(reports_data),
        'total_emails': sum(len(r['records']) for r in reports_data),
        'domains': defaultdict(int),
        'org_domains': defaultdict(lambda: defaultdict(list)),
        'auth_results': {
            'both_pass': 0,
            'spf_pass': 0,
            'dkim_pass': 0,
            'fail': 0,
            'alignment_fail': 0
        },
        'ip_addresses': defaultdict(int),
        'dispositions': defaultdict(int),
        'top_ips': {'ips': [], 'counts': []},
        'domain_distribution': {'domains': [], 'counts': []},
        'time_series': defaultdict(lambda: defaultdict(int)),
        'internal_vs_external': {'internal': 0, 'external': 0},
        'policy_evaluation': {
            'policies': defaultdict(int),
            'pct_compliance': 0
        }
    }

    # Calcola il range di date in base al filtro
    end_date = datetime.now()
    if time_filter == 'today':
        start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_filter == '7days':
        start_date = end_date - timedelta(days=7)
    elif time_filter == '30days':
        start_date = end_date - timedelta(days=30)
    elif time_filter == 'month':
        start_date = end_date.replace(day=1)
    else:  # default
        start_date = end_date - timedelta(days=30)

    # Prepara i bucket temporali per le serie temporali (ultimi 30 giorni)
    time_buckets = [(end_date - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(30, -1, -1)]

    for report in reports_data:
        try:
            # Estrai la data dal report (gestendo sia formato con che senza timestamp)
            date_str = report['date_range']['start'].split()[0]  # Prende solo la parte YYYY-MM-DD
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            
            # Filtra i report in base al range di date
            if start_date.date() <= report_date <= end_date.date():
                domain = report['policy']['domain']
                org = report['org']
                
                # Aggiorna le statistiche per dominio e organizzazione
                stats['domains'][domain] += 1
                stats['org_domains'][org][domain].append(report)
                
                # Aggiungi ai bucket temporali
                if date_str in time_buckets:
                    stats['time_series'][date_str]['reports'] += 1
                    stats['time_series'][date_str]['emails'] += len(report['records'])

                # Processa ogni record nel report
                for record in report['records']:
                    ip = record['source_ip']
                    count = record['count']
                    disposition = record['disposition']
                    
                    # Aggiorna le statistiche degli IP e disposizioni
                    stats['ip_addresses'][ip] += count
                    stats['dispositions'][disposition] += count
                    
                    # Internal vs external
                    if record['is_internal']:
                        stats['internal_vs_external']['internal'] += count
                    else:
                        stats['internal_vs_external']['external'] += count
                    
                    # Verifica risultati autenticazione
                    spf_ok = record['spf'] == 'pass'
                    dkim_ok = record['dkim'] == 'pass'
                    spf_aligned = record['spf_domain'].endswith(domain)
                    dkim_aligned = record['dkim_domain'].endswith(domain)
                    
                    if spf_ok and dkim_ok and spf_aligned and dkim_aligned:
                        stats['auth_results']['both_pass'] += count
                    elif spf_ok and spf_aligned:
                        stats['auth_results']['spf_pass'] += count
                    elif dkim_ok and dkim_aligned:
                        stats['auth_results']['dkim_pass'] += count
                    elif spf_ok or dkim_ok:
                        stats['auth_results']['alignment_fail'] += count
                    else:
                        stats['auth_results']['fail'] += count

        except Exception as e:
            print(f"Error processing report: {str(e)}")
            continue

    # Prepara i dati per i grafici
    # Top IPs
    if stats['ip_addresses']:
        top_ips = sorted(stats['ip_addresses'].items(), key=lambda x: x[1], reverse=True)[:10]
        stats['top_ips']['ips'] = [ip[0] for ip in top_ips]
        stats['top_ips']['counts'] = [ip[1] for ip in top_ips]
    
    # Distribuzione domini
    if stats['domains']:
        domains_sorted = sorted(stats['domains'].items(), key=lambda x: x[1], reverse=True)
        stats['domain_distribution']['domains'] = [d[0] for d in domains_sorted]
        stats['domain_distribution']['counts'] = [d[1] for d in domains_sorted]
    
    # Serie temporali
    stats['time_series_labels'] = time_buckets
    stats['time_series_report_counts'] = [stats['time_series'][d].get('reports', 0) for d in time_buckets]
    stats['time_series_email_counts'] = [stats['time_series'][d].get('emails', 0) for d in time_buckets]
    
    # Calcola la percentuale di compliance
    total = sum(stats['auth_results'].values())
    if total > 0:
        compliant = stats['auth_results']['both_pass'] + stats['auth_results']['spf_pass'] + stats['auth_results']['dkim_pass']
        stats['policy_evaluation']['pct_compliance'] = round((compliant / total) * 100, 1)
    
    return stats

# Routes
@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('dashboard'))




@app.route('/dashboard')
def dashboard():
    try:
        time_filter = request.args.get('time_filter', '30days')
    
        # Gestione range personalizzato
        if time_filter == 'custom':
            try:
                start_date = datetime.strptime(request.args.get('start'), '%Y-%m-%d')
                end_date = datetime.strptime(request.args.get('end'), '%Y-%m-%d')
            except (ValueError, TypeError):
                flash('Invalid date format', 'error')
                return redirect(url_for('dashboard', time_filter='30days'))
        else:
            end_date = datetime.now()
            if time_filter == 'today':
                start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
            elif time_filter == '7days':
                start_date = end_date - timedelta(days=7)
            elif time_filter == '30days':
                start_date = end_date - timedelta(days=30)
            elif time_filter == 'month':
                start_date = end_date.replace(day=1)
            else:
                start_date = end_date - timedelta(days=30)

        # Filtra i report gestendo sia date con che senza orario
        filtered_reports = []
        for r in reports_data:
            try:
                # Estrai solo la parte della data (ignora l'orario se presente)
                date_part = r['date_range']['start'].split(' ')[0]
                report_date = datetime.strptime(date_part, '%Y-%m-%d')
                
                if start_date.date() <= report_date.date() <= end_date.date():
                    filtered_reports.append(r)
            except (ValueError, KeyError, AttributeError) as e:
                print(f"Skipping malformed report - {str(e)}")
                continue
    
        stats = None
        if filtered_reports:
            try:
                stats = generate_stats(filtered_reports)
            except Exception as e:
                flash(f"Error generating stats: {str(e)}", "error")
                stats = None
    
        # Group reports by org and domain
        org_domain_map = defaultdict(lambda: defaultdict(list))
        for report in reports_data:
            org_domain_map[report['org']][report['policy']['domain']].append(report)
        
        # Prepare grouped reports for the table
        grouped_reports = []
        for org, domains in org_domain_map.items():
            for domain, reports in domains.items():
                # Calculate statistics
                total_records = sum(len(r['records']) for r in reports)
                pass_count = 0
                total_auth = 0
                report_details = []
                
                for report in reports:
                    report_details.append({
                        'id': reports_data.index(report),
                        'date': report['date_range']['start']
                    })
                    for record in report['records']:
                        total_auth += 2  # SPF + DKIM
                        if record['spf'] == 'pass':
                            pass_count += 1
                        if record['dkim'] == 'pass':
                            pass_count += 1
                
                pass_rate = round((pass_count / total_auth * 100), 1) if total_auth > 0 else 0
                
                grouped_reports.append({
                    'org': org,
                    'domain': domain,
                    'total_reports': len(reports),
                    'total_records': total_records,
                    'pass_rate': pass_rate,
                    'reports': report_details,
                    'date_range': {
                        'start': min(r['date_range']['start'] for r in reports),
                        'end': max(r['date_range']['end'] for r in reports)
                    }
                })
        
        return render_template(
            'dashboard.html',
            stats=stats,
            grouped_reports=grouped_reports,
            UPLOAD_FOLDER=UPLOAD_FOLDER,
            version=__version__,
            current_time_filter=time_filter
        )

    except Exception as e:
        flash(f"An unexpected error occurred: {str(e)}", "error")
        return redirect(url_for('dashboard', time_filter='30days'))

@app.route('/report/<org_name>')
@app.route('/report/<org_name>/<report_id>')
def report_detail(org_name, report_id=None):
    try:
        # Normalizza il nome dell'org per case-insensitive comparison
        org_name_lower = org_name.lower()
        
        # Carica tutti i report dell'organizzazione (case-insensitive)
        org_reports = [
            {'id': idx, **r} for idx, r in enumerate(reports_data) 
            if r['org'].lower() == org_name_lower
        ]
        
        if not org_reports:
            return f"No reports found for organization: {org_name}", 404

        # Se report_id è None o 'all', mostra aggregato
        if not report_id or report_id == 'all':
            report = aggregate_reports([str(r['id']) for r in org_reports])
            selected_report_id = 'all'
        else:
            # Cerca il report specifico
            selected_report = next(
                (r for r in org_reports if str(r['id']) == str(report_id)), 
                None
            )
            if not selected_report:
                return f"Report {report_id} not found for {org_name}", 404
            report = selected_report
            selected_report_id = str(report['id'])

        # Calcolo dati per i grafici
        pass_rate = calculate_pass_rate(report)
        auth_data = calculate_auth_data(report)
        dispositions = calculate_dispositions(report)
        internal_vs_external = calculate_internal_external(report)
        ip_chart_data = prepare_ip_chart_data(report)
        
        return render_template(
            'report_detail.html',
            report=report,
            org_name=org_name,
            selected_report_id=selected_report_id,
            org_reports=org_reports,  # Per il dropdown
            pass_rate=pass_rate,
            auth_data=auth_data,
            dispositions=dispositions,
            internal_vs_external=internal_vs_external,
            ip_chart_data=ip_chart_data,
            ip_addresses=get_ip_addresses(report)
        )
    except Exception as e:
        flash(f"System error: {str(e)}", "error")
        return redirect(url_for('dashboard', time_filter='30days'))


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        return render_template('upload.html')
    
    # Se è una richiesta POST
    file = request.files.get('files')
    
    if not file or file.filename == '':
        flash('Nessun file selezionato', 'error')
        return redirect(request.url)
        
    # Controllo estensione file
    if not (file.filename.lower().endswith('.xml') or file.filename.lower().endswith('.xml.gz')):
        flash('Formato file non supportato. Usare solo .xml o .xml.gz', 'error')
        return redirect(request.url)
    
    try:
        # Processa il file
        report = parse_dmarc_report(file)
        
        if 'error' in report:
            flash(f'Errore nel report: {report["error"]}', 'error')
            return redirect(request.url)
            
        if report_id_exists(report['report_id']):
            flash(f'Report ID {report["report_id"]} già esistente!', 'error')
            return redirect(request.url)
            
        add_report(report)
        flash('Report caricato con successo!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Errore: {str(e)}', 'error')
        return redirect(request.url)


@app.route('/export/csv/<org_name>')
@app.route('/export/csv/<org_name>/<report_id>')
def export_csv(org_name, report_id=None):
    si = StringIO()
    cw = csv.writer(si)
    
    if report_id is not None:
        # Export single report
        if report_id < 0 or report_id >= len(reports_data):
            flash('Invalid report ID!', 'error')
            return redirect(url_for('dashboard'))
        
        report = reports_data[report_id]
        cw.writerow(['DMARC Report Export - ' + report['org'] + ' - ' + report['report_id']])
        cw.writerow([])
        cw.writerow(['Organization', report['org']])
        cw.writerow(['Email', report['email']])
        cw.writerow(['Report ID', report['report_id']])
        cw.writerow(['Date Range', f"{report['date_range']['start']} to {report['date_range']['end']}"])
        cw.writerow(['Domain', report['policy']['domain']])
        cw.writerow(['Policy', report['policy']['p']])
        cw.writerow(['Percentage', report['policy']['pct']])
        cw.writerow([])
        cw.writerow(['Source IP', 'Count', 'SPF', 'DKIM', 'Disposition', 'Header From', 'Location', 'Internal'])
        
        for record in report['records']:
            cw.writerow([
                record['source_ip'],
                record['count'],
                record['spf'],
                record['dkim'],
                record['disposition'],
                record['header_from'],
                record['location'],
                'Yes' if record['is_internal'] else 'No'
            ])
        
        filename = f"dmarc_report_{report['report_id']}.csv"
    else:
        # Export all reports
        cw.writerow(['DMARC Reports Summary Export'])
        cw.writerow(['Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        cw.writerow(['Total Reports', len(reports_data)])
        cw.writerow(['Total Emails', sum(len(r['records']) for r in reports_data)])
        cw.writerow([])
        cw.writerow(['Organization', 'Domain', 'Report ID', 'Date Range', 'Records', 'Policy'])
        
        for report in reports_data:
            cw.writerow([
                report['org'],
                report['policy']['domain'],
                report['report_id'],
                f"{report['date_range']['start']} to {report['date_range']['end']}",
                len(report['records']),
                report['policy']['p']
            ])
        
        filename = "dmarc_reports_summary.csv"
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={filename}"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/domains', methods=['GET', 'POST'])
def domains():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            domain_name = request.form.get('domain_name', '').strip()
            dmarc_policy = request.form.get('dmarc_policy', 'none')
            enable_reporting = request.form.get('enable_reporting') == 'on'
            report_emails = request.form.get('report_emails', '')
            
            # Validazione
            if not domain_name:
                flash('Domain name is required', 'error')
                return redirect(url_for('domains'))
            
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain_name):
                flash('Invalid domain format', 'error')
                return redirect(url_for('domains'))
            
            if domain_exists(domain_name):
                flash(f'Domain {domain_name} already exists', 'error')
                return redirect(url_for('domains'))
            
            # Creazione nuovo dominio
            domain = {
                'name': domain_name,
                'dmarc_policy': dmarc_policy,
                'enable_reporting': enable_reporting,
                'report_emails': [e.strip() for e in report_emails.split(',') if e.strip()],
                'created_at': datetime.now().isoformat(),
                'status': 'pending',
                'last_report': None,
                'auth_score': 0
            }
            
            add_domain(domain)
            flash(f'Domain {domain_name} added successfully', 'success')
            return redirect(url_for('domains'))
        
        elif action == 'update':
            domain_name = request.form.get('domain_name', '').strip()
            dmarc_policy = request.form.get('dmarc_policy', 'none')
            enable_reporting = request.form.get('enable_reporting') == 'on'
            report_emails = request.form.get('report_emails', '')
            
            domains = load_domains()
            updated = False
            
            for domain in domains:
                if domain['name'] == domain_name:
                    domain.update({
                        'dmarc_policy': dmarc_policy,
                        'enable_reporting': enable_reporting,
                        'report_emails': [e.strip() for e in report_emails.split(',') if e.strip()],
                        'status': 'active'  # Imposta come attivo dopo l'aggiornamento
                    })
                    updated = True
                    break
            
            if updated:
                save_domains(domains)
                sync_domains()
                flash(f'Domain {domain_name} updated successfully', 'success')
            else:
                flash(f'Domain {domain_name} not found', 'error')
            
            return redirect(url_for('domains'))
        
        elif action == 'delete':
            domain_name = request.form.get('domain_name', '').strip()
            confirm_delete = request.form.get('confirm_delete') == 'on'
            
            if not confirm_delete:
                flash('Please confirm deletion', 'error')
                return redirect(url_for('domains'))
            
            domains = load_domains()
            initial_count = len(domains)
            domains = [d for d in domains if d['name'] != domain_name]
            
            if len(domains) < initial_count:
                save_domains(domains)
                sync_domains()
                flash(f'Domain {domain_name} deleted successfully', 'success')
            else:
                flash(f'Domain {domain_name} not found', 'error')
            
            return redirect(url_for('domains'))
    
    # Carica sempre i dati aggiornati per il template
    domains_data = load_domains()
    return render_template('domains.html', domains=domains_data, version=__version__)

@app.route('/policy-generator', methods=['GET', 'POST'])
def policy_generator():
    if request.method == 'POST':
        domain = request.form.get('domain')
        policy = request.form.get('policy')
        pct = request.form.get('pct')
        rua = request.form.get('rua')
        ruf = request.form.get('ruf')
        fo = request.form.get('fo')
        aspf = request.form.get('aspf')
        adkim = request.form.get('adkim')
        ri = request.form.get('ri')
        
        # Validate inputs
        if not domain:
            flash('Domain is required', 'error')
            return redirect(url_for('policy_generator'))
        
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            flash('Invalid domain format', 'error')
            return redirect(url_for('policy_generator'))
        
        # Generate DMARC record
        record = f"v=DMARC1; p={policy}; pct={pct}"
        
        if rua:
            rua_addresses = [a.strip() for a in rua.split(',') if a.strip()]
            record += f"; rua={','.join(rua_addresses)}"
        
        if ruf:
            ruf_addresses = [a.strip() for a in ruf.split(',') if a.strip()]
            record += f"; ruf={','.join(ruf_addresses)}"
        
        if fo != '0':
            record += f"; fo={fo}"
        
        if aspf != 'r':
            record += f"; aspf={aspf}"
        
        if adkim != 'r':
            record += f"; adkim={adkim}"
        
        if ri and ri != '86400':
            record += f"; ri={ri}"
        
        return render_template('policy_generator.html', 
                            dmarc_record=record,
                            domain=domain,
                            version=__version__)
    
    return render_template('policy_generator.html', version=__version__)

@app.route('/analyzer', methods=['GET', 'POST'])
def analyzer():
    if request.method == 'POST':
        if 'emlFile' in request.files:
            file = request.files['emlFile']
            if file and file.filename.endswith('.eml'):
                analysis = parse_eml_file(file)
                return render_template('analyzer.html', analysis=analysis, version=__version__)
        
        elif 'emailHeaders' in request.form:
            headers = request.form['emailHeaders']
            analysis = analyze_email_headers(headers)
            return render_template('analyzer.html', analysis=analysis, version=__version__)
    
    return render_template('analyzer.html', version=__version__)

@app.route('/export/json')
def export_json():
    data = {
        'generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_reports': len(reports_data),
        'total_emails': sum(len(r['records']) for r in reports_data),
        'reports': reports_data
    }
    
    output = make_response(json.dumps(data, indent=2))
    output.headers["Content-Disposition"] = "attachment; filename=dmarc_reports_export.json"
    output.headers["Content-type"] = "application/json"
    return output

@app.route('/reload')
def reload_reports():
    global reports_data, domains_data
    reports_data = load_reports()
    domains_data = load_domains()
    flash('Data reloaded successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/all_reports')
def all_reports():
    try:
        # Group reports by org and domain (stessa logica della dashboard)
        org_domain_map = defaultdict(lambda: defaultdict(list))
        for report in reports_data:
            org_domain_map[report['org']][report['policy']['domain']].append(report)
        
        grouped_reports = []
        for org, domains in org_domain_map.items():
            for domain, reports in domains.items():
                total_records = sum(len(r['records']) for r in reports)
                pass_count = 0
                total_auth = 0
                report_details = []
                
                for report in reports:
                    report_details.append({
                        'id': reports_data.index(report),
                        'date': report['date_range']['start']
                    })
                    for record in report['records']:
                        total_auth += 2
                        if record['spf'] == 'pass':
                            pass_count += 1
                        if record['dkim'] == 'pass':
                            pass_count += 1
                
                pass_rate = round((pass_count / total_auth * 100), 1) if total_auth > 0 else 0
                
                grouped_reports.append({
                    'org': org,
                    'domain': domain,
                    'total_reports': len(reports),
                    'total_records': total_records,
                    'pass_rate': pass_rate,
                    'reports': report_details,
                    'date_range': {
                        'start': min(r['date_range']['start'] for r in reports),
                        'end': max(r['date_range']['end'] for r in reports)
                    }
                })
        
        return render_template(
            'all_reports.html',
            grouped_reports=grouped_reports,
            version=__version__
        )

    except Exception as e:
        flash(f"An unexpected error occurred: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route('/api/domains', methods=['GET'])
def api_domains():
    sync_domains()
    return jsonify(domains_data)
    

if __name__ == '__main__':
    reports_data = load_reports()
    domains_data = load_domains()
    print(f"\n🚀 Starting DMARCus Analyzer with {len(reports_data)} reports in database")
    app.run('0.0.0.0', port=3627, debug=True)
