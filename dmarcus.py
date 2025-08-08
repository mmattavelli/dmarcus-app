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

# Setup GeoIP (commentato se non disponibile)
# geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
__version__ = "0.1"

app = Flask(__name__)
print("Static folder path:", app.static_folder)

app.secret_key = 'supersecretkey'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DB_FILE = 'dmarc_reports.json'

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

reports_data = []




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

# Carica i report all'avvio
reports_data = load_reports()

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
    


# Enhanced statistics generator
def generate_stats(reports_data):
    if not reports_data:
        return None
        
    stats = {
        'total_reports': len(reports_data),
        'total_emails': sum(len(r['records']) for r in reports_data),
        'domains': defaultdict(int),
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

    # Calculate time buckets for time series (last 30 days)
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)
    time_buckets = [(start_date + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(31)]

    for report in reports_data:
        domain = report['policy']['domain']
        stats['domains'][domain] += 1
        
        # Time series data
        report_date = datetime.utcfromtimestamp(report['date_range']['start_ts']).strftime('%Y-%m-%d')
        if report_date in time_buckets:
            stats['time_series'][report_date]['reports'] += 1
            stats['time_series'][report_date]['emails'] += len(report['records'])
        
        for record in report['records']:
            ip = record['source_ip']
            count = record['count']
            disposition = record['disposition']
            
            stats['ip_addresses'][ip] += count
            stats['dispositions'][disposition] += 1
            
            # Internal vs external
            if record['is_internal']:
                stats['internal_vs_external']['internal'] += 1
            else:
                stats['internal_vs_external']['external'] += 1
            
            # Authentication results
            spf_ok = record['spf'] == 'pass'
            dkim_ok = record['dkim'] == 'pass'
            
            # Check alignment
            spf_aligned = record['spf_domain'].endswith(report['policy']['domain'])
            dkim_aligned = record['dkim_domain'].endswith(report['policy']['domain'])
            
            if spf_ok and dkim_ok and spf_aligned and dkim_aligned:
                stats['auth_results']['both_pass'] += 1
            elif spf_ok and spf_aligned:
                stats['auth_results']['spf_pass'] += 1
            elif dkim_ok and dkim_aligned:
                stats['auth_results']['dkim_pass'] += 1
            elif spf_ok or dkim_ok:
                stats['auth_results']['alignment_fail'] += 1
            else:
                stats['auth_results']['fail'] += 1

    # Prepare chart data
    if stats['ip_addresses']:
        top_ips = sorted(stats['ip_addresses'].items(), key=lambda x: x[1], reverse=True)[:10]
        stats['top_ips']['ips'] = [ip[0] for ip in top_ips]
        stats['top_ips']['counts'] = [ip[1] for ip in top_ips]
    
    if stats['domains']:
        domains_sorted = sorted(stats['domains'].items(), key=lambda x: x[1], reverse=True)
        stats['domain_distribution']['domains'] = [d[0] for d in domains_sorted]
        stats['domain_distribution']['counts'] = [d[1] for d in domains_sorted]
    
    # Prepare time series data
    stats['time_series_labels'] = time_buckets
    stats['time_series_report_counts'] = [stats['time_series'][d].get('reports', 0) for d in time_buckets]
    stats['time_series_email_counts'] = [stats['time_series'][d].get('emails', 0) for d in time_buckets]
    
    # Calculate policy compliance percentage
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
    # Usa la variabile globale reports_data invece di caricare di nuovo
    stats = generate_stats(reports_data) if reports_data else None
    
                               
    
    return render_template(
        'dashboard.html',
        stats=stats,
        reports_data=reports_data,
        UPLOAD_FOLDER=UPLOAD_FOLDER,
        version=__version__
    )

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected!', 'error')
            return redirect(request.url)
        
        if file and (file.filename.endswith('.xml') or file.filename.endswith('.xml.gz')):
            try:
                report = parse_dmarc_report(file)
                if 'error' in report:
                    flash(f"Error: {report['error']}", 'error')
                    return redirect(request.url)
                
                # Use the database function that checks for duplicates
                from database import add_report
                add_report(report)
                
                # Update the global reports_data
                global reports_data
                reports_data = load_reports()
                flash('Report uploaded successfully!', 'success')
                return redirect(url_for('dashboard'))
                
            except ValueError as e:
                flash(str(e), 'error')
            except Exception as e:
                flash(f"Error processing file: {str(e)}", 'error')
            
            return redirect(request.url)
        
        flash('Invalid file type. Only .xml and .xml.gz are allowed.', 'error')
        return redirect(request.url)
    
    return render_template('upload.html')

@app.route('/report/<int:report_id>')
def report_detail(report_id):
    try:
        current_reports = load_reports()
        
        if not current_reports:
            flash('No reports available!', 'error')
            return redirect(url_for('dashboard'))
            
        if report_id < 0 or report_id >= len(current_reports):
            flash('Invalid report ID!', 'error')
            return redirect(url_for('dashboard'))
        
        report = current_reports[report_id]
        
        if not report.get('records'):
            flash('This report contains no records!', 'warning')
            return redirect(url_for('dashboard'))
        
        # Inizializza tutte le variabili necessarie
        auth_data = {
            'both_pass': 0,
            'spf_pass': 0,
            'dkim_pass': 0,
            'alignment_fail': 0,
            'fail': 0
        }
        
        dispositions = defaultdict(int)
        ip_addresses = defaultdict(int)
        internal_vs_external = {'internal': 0, 'external': 0}
        
        # Calcola le statistiche
        for record in report['records']:
            # Conteggio IP
            ip_addresses[record['source_ip']] += record['count']
            
            # Conteggio disposizioni
            dispositions[record['disposition']] += record['count']
            
            # Interno/Esterno
            if record['is_internal']:
                internal_vs_external['internal'] += record['count']
            else:
                internal_vs_external['external'] += record['count']
            
            # Verifica autenticazione
            spf_ok = record['spf'] == 'pass'
            dkim_ok = record['dkim'] == 'pass'
            spf_aligned = record['spf_domain'].endswith(report['policy']['domain'])
            dkim_aligned = record['dkim_domain'].endswith(report['policy']['domain'])
            
            if spf_ok and dkim_ok and spf_aligned and dkim_aligned:
                auth_data['both_pass'] += 1
            elif spf_ok and spf_aligned:
                auth_data['spf_pass'] += 1
            elif dkim_ok and dkim_aligned:
                auth_data['dkim_pass'] += 1
            elif spf_ok or dkim_ok:
                auth_data['alignment_fail'] += 1
            else:
                auth_data['fail'] += 1
        
        # Prepara i dati per il grafico degli IP
        top_ips = sorted(ip_addresses.items(), key=lambda x: x[1], reverse=True)[:5]
        ip_chart_data = {
            'ips': [ip[0] for ip in top_ips],
            'counts': [ip[1] for ip in top_ips]
        }
        
        # Calcola il tasso di successo (CORRETTO)
        total_auth = sum(auth_data.values())
        pass_rate = round((auth_data['both_pass'] + auth_data['spf_pass'] + auth_data['dkim_pass']) / total_auth * 100, 1) if total_auth > 0 else 0
        
        return render_template(
            'report_detail.html', 
            report=report,
            report_id=report_id,
            auth_data=auth_data,
            dispositions=dict(dispositions),
            ip_addresses=ip_addresses,
            ip_chart_data=ip_chart_data,
            internal_vs_external=internal_vs_external,
            pass_rate=pass_rate
        )
    
    except Exception as e:
        print(f"DEBUG: Error in report_detail - {str(e)}")
        flash(f'Error loading report: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    
@app.route('/export/csv')
@app.route('/export/csv/<int:report_id>')
def export_csv(report_id=None):
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
    global reports_data
    reports_data = load_reports()  # Usa la funzione esistente load_reports()
    flash('Reports reloaded successfully!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    reports_data = load_reports()
    print(f"\n🚀 Starting DMARCus Analyzer with {len(reports_data)} reports in database")
    app.run('0.0.0.0', debug=True)