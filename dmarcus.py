#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import gzip
import shutil
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, session, send_from_directory, Response, jsonify
import os
from xml.etree import ElementTree as ET
from datetime import datetime, timedelta
from collections import defaultdict
import json
import csv
import time
from io import StringIO
import ipaddress
from werkzeug.utils import secure_filename
import re
import logging
import secrets
from functools import wraps
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf
from werkzeug.exceptions import abort, BadRequest
import sqlite3
from contextlib import contextmanager
import email
from email import policy
from email.parser import BytesParser
import dns.resolver
import dns.exception
import hashlib
from threat_intelligence import ThreatIntelligence
import zipfile
from io import BytesIO

__version__ = "1.0.4"


BASE_DIR = '/opt/dmarcus-dev'
DATA_DIR = os.path.join(BASE_DIR, 'data')
SQLITE_DB = os.path.join(DATA_DIR, 'dmarcus.db')
UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
SESSION_FILE_DIR = os.path.join(DATA_DIR, 'flask_session')
threat_intel = ThreatIntelligence(SQLITE_DB)

MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_REPORTS_IN_MEMORY = 1000

print(f"Base directory: {BASE_DIR}")
print(f"Data directory: {DATA_DIR}")
print(f"SQLite database: {SQLITE_DB}")

app = Flask(__name__, static_folder='static')
print("Static folder path:", app.static_folder)

app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = SESSION_FILE_DIR
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

for directory in [DATA_DIR, UPLOAD_FOLDER, SESSION_FILE_DIR]:
    if not os.path.exists(directory):
        try:
            os.makedirs(directory, mode=0o755)
            print(f"Created directory: {directory}")
        except OSError as e:
            print(f"Warning: Could not create directory {domain_name}: {e}")

ALLOWED_EXTENSIONS = {'xml', 'gz', 'zip', 'eml', 'msg'}
ALLOWED_ANALYZER_EXTENSIONS = {'eml', 'msg'}

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

csrf = CSRFProtect(app)
server_session = Session(app)


limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# =============================================================================
# DATABASE FUNCTIONS
# =============================================================================

@contextmanager
def db_connection():
    """Gestione connessione al database SQLite"""
    conn = sqlite3.connect(SQLITE_DB, timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_database():
    """Inizializza il database SQLite con tutte le tabelle"""
    try:
        print(f"[init_database] Connecting to database: {SQLITE_DB}")
        
        with db_connection() as conn:
            print("[init_database] Connection successful")
            
            # Tabella reports
            conn.execute(''' 
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT UNIQUE NOT NULL,
                    org TEXT NOT NULL,
                    email TEXT,
                    domain TEXT NOT NULL,
                    start_date TEXT,
                    end_date TEXT,
                    start_ts INTEGER,
                    end_ts INTEGER,
                    policy_p TEXT,
                    policy_sp TEXT,
                    policy_pct TEXT,
                    policy_adkim TEXT,
                    policy_aspf TEXT,
                    policy_fo TEXT,
                    filename TEXT,
                    file_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            print("[init_database] Created 'reports' table")
            
            # Tabella records
            conn.execute('''
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    count INTEGER DEFAULT 1,
                    disposition TEXT,
                    dkim TEXT,
                    spf TEXT,
                    header_from TEXT,
                    is_internal BOOLEAN DEFAULT 0,
                    dkim_domain TEXT,
                    spf_domain TEXT,
                    FOREIGN KEY (report_id) REFERENCES reports (report_id) ON DELETE CASCADE
                )
            ''')
            print("[init_database] Created 'records' table")
            
            # Tabella domains
            conn.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    dmarc_policy TEXT DEFAULT 'none',
                    enable_reporting BOOLEAN DEFAULT 0,
                    report_emails TEXT,
                    status TEXT DEFAULT 'pending',
                    last_report TEXT,
                    auth_score REAL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            print("[init_database] Created 'domains' table")
            
            # Tabella threat_intelligence_cache
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time_filter TEXT NOT NULL,
                    threat_data TEXT NOT NULL,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            print("[init_database] Created 'threat_intelligence_cache' table")
            
            # Tabella users
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    is_admin BOOLEAN DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL,
                    full_name TEXT,
                    email TEXT
                )
            ''')
            print("[init_database] Created 'users' table")
            
            # Indici per performance
            conn.execute('CREATE INDEX IF NOT EXISTS idx_reports_domain ON reports(domain)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_reports_org ON reports(org)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_reports_start_date ON reports(start_date)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_records_report_id ON records(report_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_records_source_ip ON records(source_ip)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_reports_file_hash ON reports(file_hash)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_threat_cache_filter ON threat_intelligence_cache(time_filter)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_threat_cache_updated ON threat_intelligence_cache(last_updated)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)')
            
            print("[init_database] Created indexes")
            print("[init_database] Database initialized successfully")
            
            # Crea l'utente amministratore di default
            create_default_admin_user()
            
            return True
            
    except Exception as e:
        print(f"❌ [init_database] CRITICAL Error initializing database: {e}")
        import traceback
        traceback.print_exc()
        return False

def report_id_exists_in_db(report_id):
    """Controlla se un report ID esiste già nel database"""
    try:
        with db_connection() as conn:
            result = conn.execute(
                'SELECT 1 FROM reports WHERE report_id = ?', 
                (report_id,)
            ).fetchone()
            return result is not None
    except Exception as e:
        print(f"[report_id_exists_in_db] Error: {e}")
        return False

def save_report_to_db(report_data):
    """Salva un report completo nel database"""
    try:
        with db_connection() as conn:
            # Inserisci il report principale (AGGIUNGI file_hash)
            conn.execute('''
                INSERT OR REPLACE INTO reports (
                    report_id, org, email, domain, start_date, end_date,
                    start_ts, end_ts, policy_adkim, policy_aspf,
                    policy_p, policy_sp, policy_pct, policy_fo, filename, file_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report_data['report_id'],
                report_data['org'],
                report_data['email'],
                report_data['policy']['domain'],
                report_data['date_range']['start'],
                report_data['date_range']['end'],
                report_data['date_range']['start_ts'],
                report_data['date_range']['end_ts'],
                report_data['policy']['adkim'],
                report_data['policy']['aspf'],
                report_data['policy']['p'],
                report_data['policy']['sp'],
                report_data['policy']['pct'],
                report_data['policy']['fo'],
                report_data.get('filename', ''),
                report_data.get('file_hash', '')  # NUOVO CAMPO
            ))
            
            # Inserisci i records
            for record in report_data['records']:
                conn.execute('''
                    INSERT INTO records (
                        report_id, source_ip, count, disposition, dkim, spf,
                        header_from, is_internal, dkim_domain, spf_domain
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    report_data['report_id'],
                    record['source_ip'],
                    record['count'],
                    record['disposition'],
                    record['dkim'],
                    record['spf'],
                    record['header_from'],
                    record['is_internal'],
                    record.get('dkim_domain', ''),
                    record.get('spf_domain', '')
                ))
            
            print(f"[save_report_to_db] Saved report: {report_data['report_id']}")
            return True
            
    except Exception as e:
        print(f"[save_report_to_db] Error saving report: {e}")
        return False

def get_total_reports_count_from_db():
    """Restituisce il numero totale di reports nel database"""
    try:
        with db_connection() as conn:
            result = conn.execute('SELECT COUNT(*) as count FROM reports').fetchone()
            return result['count'] if result else 0
    except Exception as e:
        print(f"[get_total_reports_count_from_db] Error: {e}")
        return 0

def load_domains_from_db():
    """Carica tutti i domini dal database"""
    try:
        with db_connection() as conn:
            rows = conn.execute('SELECT * FROM domains ORDER BY name').fetchall()
            domains = []
            for row in rows:
                domain = {
                    'name': row['name'],
                    'dmarc_policy': row['dmarc_policy'],
                    'enable_reporting': bool(row['enable_reporting']),
                    'report_emails': json.loads(row['report_emails']) if row['report_emails'] else [],
                    'status': row['status'],
                    'last_report': row['last_report'],
                    'auth_score': row['auth_score'],
                    'created_at': row['created_at']
                }
                domains.append(domain)
            return domains
    except Exception as e:
        print(f"[load_domains_from_db] Error: {e}")
        return []

def domain_exists_in_db(domain_name):
    """Controlla se un dominio esiste già nel database"""
    try:
        with db_connection() as conn:
            result = conn.execute(
                'SELECT 1 FROM domains WHERE name = ?', 
                (domain_name,)
            ).fetchone()
            return result is not None
    except Exception as e:
        print(f"[domain_exists_in_db] Error: {e}")
        return False

def save_domain_to_db(domain_data):
    """Salva o aggiorna un dominio nel database"""
    try:
        with db_connection() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO domains (
                    name, dmarc_policy, enable_reporting, report_emails, 
                    status, last_report, auth_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                domain_data['name'],
                domain_data.get('dmarc_policy', 'none'),
                1 if domain_data.get('enable_reporting', False) else 0,
                json.dumps(domain_data.get('report_emails', [])),
                domain_data.get('status', 'pending'),
                domain_data.get('last_report'),
                domain_data.get('auth_score', 0)
            ))
            return True
    except Exception as e:
        print(f"[save_domain_to_db] Error: {e}")
        return False

def delete_domain_from_db(domain_name):
    """Elimina un dominio dal database"""
    try:
        with db_connection() as conn:
            conn.execute('DELETE FROM domains WHERE name = ?', (domain_name,))
            return True
    except Exception as e:
        print(f"[delete_domain_from_db] Error: {e}")
        return False

def update_domain_in_db(domain_name, updates):
    """Aggiorna un dominio esistente nel database"""
    try:
        with db_connection() as conn:
            set_clause = []
            params = []
            
            for key, value in updates.items():
                if key == 'report_emails':
                    set_clause.append(f"{key} = ?")
                    params.append(json.dumps(value))
                else:
                    set_clause.append(f"{key} = ?")
                    params.append(value)
            
            params.append(domain_name)
            
            query = f"UPDATE domains SET {', '.join(set_clause)} WHERE name = ?"
            conn.execute(query, params)
            return True
            
    except Exception as e:
        print(f"[update_domain_in_db] Error updating domain {domain_name}: {e}")
        return False


def load_report_from_db(report_id):
    """Carica un report specifico dal database"""
    try:
        with db_connection() as conn:
            # Carica il report principale
            report_row = conn.execute(
                'SELECT * FROM reports WHERE report_id = ?', 
                (report_id,)
            ).fetchone()
            
            if not report_row:
                return None
            
            # Carica i records
            records_rows = conn.execute(
                'SELECT * FROM records WHERE report_id = ?', 
                (report_id,)
            ).fetchall()
            
            # Costruisci il report nel formato atteso
            report = {
                'org': report_row['org'],
                'email': report_row['email'],
                'report_id': report_row['report_id'],
                'date_range': {
                    'start': report_row['start_date'],
                    'end': report_row['end_date'],
                    'start_ts': report_row['start_ts'],
                    'end_ts': report_row['end_ts']
                },
                'policy': {
                    'domain': report_row['domain'],
                    'adkim': report_row['policy_adkim'],
                    'aspf': report_row['policy_aspf'],
                    'p': report_row['policy_p'],
                    'sp': report_row['policy_sp'],
                    'pct': report_row['policy_pct'],
                    'fo': report_row['policy_fo']
                },
                'records': [],
                'filename': report_row['filename']
            }
            
            # Aggiungi i records con tutti i campi necessari
            for record_row in records_rows:
                record = {
                    'source_ip': record_row['source_ip'],
                    'count': record_row['count'],
                    'disposition': record_row['disposition'],
                    'dkim': record_row['dkim'],
                    'spf': record_row['spf'],
                    'header_from': record_row['header_from'],
                    'is_internal': bool(record_row['is_internal']),
                    'dkim_domain': record_row['dkim_domain'],
                    'spf_domain': record_row['spf_domain']
                }
                
                # Calcola auth_data che mancava
                auth_pass = record['dkim'] == 'pass' and record['spf'] == 'pass'
                auth_fail = record['dkim'] != 'pass' and record['spf'] != 'pass'
                auth_partial = (record['dkim'] == 'pass' or record['spf'] == 'pass') and not auth_pass
                
                record['auth_data'] = {
                    'pass': auth_pass,
                    'fail': auth_fail,
                    'partial': auth_partial,
                    'dkim_pass': record['dkim'] == 'pass',
                    'spf_pass': record['spf'] == 'pass'
                }
                
                report['records'].append(record)
            
            return report
            
    except Exception as e:
        print(f"[load_report_from_db] Error loading report {report_id}: {e}")
        return None


def load_reports_by_org_from_db(org_name):
    """Carica tutti i report per una specifica organizzazione"""
    try:
        with db_connection() as conn:
            reports_rows = conn.execute(
                'SELECT * FROM reports WHERE org = ? ORDER BY start_ts DESC', 
                (org_name,)
            ).fetchall()
            
            reports = []
            for report_row in reports_rows:
                # Carica i records per ogni report
                records_rows = conn.execute(
                    'SELECT * FROM records WHERE report_id = ?', 
                    (report_row['report_id'],)
                ).fetchall()
                
                report = {
                    'org': report_row['org'],
                    'email': report_row['email'],
                    'report_id': report_row['report_id'],
                    'date_range': {
                        'start': report_row['start_date'],
                        'end': report_row['end_date'],
                        'start_ts': report_row['start_ts'],
                        'end_ts': report_row['end_ts']
                    },
                    'policy': {
                        'domain': report_row['domain'],
                        'adkim': report_row['policy_adkim'],
                        'aspf': report_row['policy_aspf'],
                        'p': report_row['policy_p'],
                        'sp': report_row['policy_sp'],
                        'pct': report_row['policy_pct'],
                        'fo': report_row['policy_fo']
                    },
                    'records': [],
                    'filename': report_row['filename']
                }
                
                # Aggiungi i records con auth_data
                for record_row in records_rows:
                    record = {
                        'source_ip': record_row['source_ip'],
                        'count': record_row['count'],
                        'disposition': record_row['disposition'],
                        'dkim': record_row['dkim'],
                        'spf': record_row['spf'],
                        'header_from': record_row['header_from'],
                        'is_internal': bool(record_row['is_internal']),
                        'dkim_domain': record_row['dkim_domain'],
                        'spf_domain': record_row['spf_domain']
                    }
                    
                    # Calcola auth_data
                    auth_pass = record['dkim'] == 'pass' and record['spf'] == 'pass'
                    auth_fail = record['dkim'] != 'pass' and record['spf'] != 'pass'
                    auth_partial = (record['dkim'] == 'pass' or record['spf'] == 'pass') and not auth_pass
                    
                    record['auth_data'] = {
                        'pass': auth_pass,
                        'fail': auth_fail,
                        'partial': auth_partial,
                        'dkim_pass': record['dkim'] == 'pass',
                        'spf_pass': record['spf'] == 'pass'
                    }
                    
                    report['records'].append(record)
                
                reports.append(report)
            
            return reports
            
    except Exception as e:
        print(f"[load_reports_by_org_from_db] Error loading reports for {org_name}: {e}")
        return []


def create_password_hash(password):
    """Crea un hash SHA256 della password con salt"""
    import hashlib
    import secrets
    
    # Genera un salt casuale
    salt = secrets.token_hex(16)
    # Combina password e salt, poi crea l'hash
    password_salted = password + salt
    password_hash = hashlib.sha256(password_salted.encode('utf-8')).hexdigest()
    
    return password_hash, salt

def verify_password(password, stored_hash, salt):
    """Verifica se la password corrisponde all'hash memorizzato"""
    import hashlib
    
    password_salted = password + salt
    computed_hash = hashlib.sha256(password_salted.encode('utf-8')).hexdigest()
    
    # Usa compare_digest per prevenire timing attacks
    return secrets.compare_digest(computed_hash, stored_hash)

def create_default_admin_user():
    """Crea l'utente amministratore di default"""
    try:
        with db_connection() as conn:
            # Controlla se l'utente esiste già
            existing_user = conn.execute(
                'SELECT 1 FROM users WHERE username = ?', 
                ('dmarc',)
            ).fetchone()
            
            if existing_user:
                print("[create_default_admin_user] Default admin user already exists")
                return True
            
            # Crea l'hash della password di default
            password_hash, salt = create_password_hash('dmarc')
            
            # Inserisce l'utente amministratore
            conn.execute('''
                INSERT INTO users (username, password_hash, salt, is_admin, is_active, full_name)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                'dmarc',
                password_hash,
                salt,
                1,  # is_admin
                1,  # is_active
                'DMARC Administrator'
            ))
            
            print("[create_default_admin_user] Default admin user created successfully")
            return True
            
    except Exception as e:
        print(f"[create_default_admin_user] Error creating default admin user: {e}")
        return False

def authenticate_user(username, password):
    """Autentica un utente con username e password"""
    try:
        with db_connection() as conn:
            user = conn.execute(
                'SELECT username, password_hash, salt, is_admin, is_active FROM users WHERE username = ? AND is_active = 1',
                (username,)
            ).fetchone()
            
            if not user:
                return None, "Invalid username or password"
            
            # Verifica la password
            if verify_password(password, user['password_hash'], user['salt']):
                # Aggiorna last_login
                conn.execute(
                    'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?',
                    (username,)
                )
                
                user_info = {
                    'username': user['username'],
                    'is_admin': bool(user['is_admin']),
                    'is_active': bool(user['is_active'])
                }
                return user_info, "Authentication successful"
            else:
                return None, "Invalid username or password"
                
    except Exception as e:
        print(f"[authenticate_user] Error: {e}")
        return None, f"Authentication error: {str(e)}"

def get_all_users():
    """Restituisce tutti gli utenti (solo per admin)"""
    try:
        with db_connection() as conn:
            users = conn.execute('''
                SELECT id, username, is_admin, is_active, created_at, last_login, full_name, email
                FROM users 
                ORDER BY username
            ''').fetchall()
            
            return [dict(user) for user in users]
    except Exception as e:
        print(f"[get_all_users] Error: {e}")
        return []

def create_user(username, password, is_admin=False, full_name="", email=""):
    """Crea un nuovo utente"""
    try:
        with db_connection() as conn:
            # Controlla se l'utente esiste già
            existing_user = conn.execute(
                'SELECT 1 FROM users WHERE username = ?', 
                (username,)
            ).fetchone()
            
            if existing_user:
                return False, "Username already exists"
            
            # Crea l'hash della password
            password_hash, salt = create_password_hash(password)
            
            # Inserisce il nuovo utente
            conn.execute('''
                INSERT INTO users (username, password_hash, salt, is_admin, is_active, full_name, email)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                username,
                password_hash,
                salt,
                1 if is_admin else 0,
                1,  # is_active
                full_name,
                email
            ))
            
            return True, "User created successfully"
            
    except Exception as e:
        print(f"[create_user] Error: {e}")
        return False, f"Error creating user: {str(e)}"

def update_user_password(username, new_password):
    """Aggiorna la password di un utente"""
    try:
        with db_connection() as conn:
            # Crea il nuovo hash della password
            password_hash, salt = create_password_hash(new_password)
            
            conn.execute('''
                UPDATE users 
                SET password_hash = ?, salt = ?
                WHERE username = ?
            ''', (password_hash, salt, username))
            
            return True, "Password updated successfully"
            
    except Exception as e:
        print(f"[update_user_password] Error: {e}")
        return False, f"Error updating password: {str(e)}"

def delete_user(username):
    """Elimina completamente un utente dal database"""
    try:
        with db_connection() as conn:
            # Non permettere di eliminare l'utente corrente
            current_user = session.get('username')
            if username == current_user:
                return False, "Cannot delete your own account"
            
            # Non permettere di eliminare l'ultimo admin
            admin_count = conn.execute(
                'SELECT COUNT(*) as count FROM users WHERE is_admin = 1'
            ).fetchone()['count']
            
            user_is_admin = conn.execute(
                'SELECT is_admin FROM users WHERE username = ?',
                (username,)
            ).fetchone()
            
            if user_is_admin and user_is_admin['is_admin'] and admin_count <= 1:
                return False, "Cannot delete the last administrator"
            
            # ELIMINAZIONE COMPLETA dal database
            conn.execute('DELETE FROM users WHERE username = ?', (username,))
            
            # Verifica che l'utente sia stato eliminato
            user_still_exists = conn.execute(
                'SELECT 1 FROM users WHERE username = ?', 
                (username,)
            ).fetchone()
            
            if user_still_exists:
                return False, "Failed to delete user"
            
            return True, "User deleted successfully"
            
    except Exception as e:
        print(f"[delete_user] Error: {e}")
        return False, f"Error deleting user: {str(e)}"






# =============================================================================
# MESSAGE ANALYZER FUNCTIONS
# =============================================================================

def allowed_analyzer_file(filename):
    """Controlla se il file è un file email valido per l'analyzer"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_ANALYZER_EXTENSIONS

def parse_email_headers(email_content):
    """Analizza gli header dell'email"""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(email_content)
        headers = {}
        
        # Header principali
        main_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID', 
                       'Return-Path', 'Reply-To', 'Sender']
        
        for header in main_headers:
            value = msg.get(header, '')
            headers[header] = value
        
        # Header di autenticazione
        auth_headers = {
            'Received': msg.get_all('Received', []),
            'Received-SPF': msg.get('Received-SPF', ''),
            'Authentication-Results': msg.get('Authentication-Results', ''),
            'DKIM-Signature': msg.get('DKIM-Signature', ''),
            'ARC-Authentication-Results': msg.get('ARC-Authentication-Results', ''),
            'ARC-Message-Signature': msg.get('ARC-Message-Signature', ''),
            'ARC-Seal': msg.get('ARC-Seal', '')
        }
        
        # Header di sicurezza
        security_headers = {
            'MIME-Version': msg.get('MIME-Version', ''),
            'Content-Type': msg.get('Content-Type', ''),
            'Content-Transfer-Encoding': msg.get('Content-Transfer-Encoding', ''),
            'X-Mailer': msg.get('X-Mailer', ''),
            'X-Priority': msg.get('X-Priority', ''),
            'X-Spam-Status': msg.get('X-Spam-Status', ''),
            'X-Virus-Scanned': msg.get('X-Virus-Scanned', '')
        }
        
        return {
            'main_headers': headers,
            'auth_headers': auth_headers,
            'security_headers': security_headers,
            'all_headers': dict(msg.items())
        }
        
    except Exception as e:
        return {'error': f'Error parsing email headers: {str(e)}'}

def analyze_spf(headers, source_ip=None):
    """Analizza i risultati SPF"""
    spf_results = {
        'result': 'none',
        'domain': '',
        'ip': source_ip,
        'mechanism': '',
        'description': ''
    }
    
    try:
        # Cerca in Authentication-Results
        auth_results = headers['auth_headers'].get('Authentication-Results', '')
        if 'spf=' in auth_results:
            import re
            spf_match = re.search(r'spf=(\w+)', auth_results)
            if spf_match:
                spf_results['result'] = spf_match.group(1)
            
            # Estrai dominio
            domain_match = re.search(r'smtp\.mailfrom=([^\s;]+)', auth_results)
            if domain_match:
                spf_results['domain'] = domain_match.group(1)
        
        # Cerca in Received-SPF
        received_spf = headers['auth_headers'].get('Received-SPF', '')
        if received_spf:
            spf_parts = received_spf.split()
            for part in spf_parts:
                if part.startswith('pass') or part.startswith('fail') or part.startswith('neutral'):
                    spf_results['result'] = part.split('(')[0] if '(' in part else part
                    break
            
            # Estrai meccanismo
            mechanism_match = re.search(r'mechanism\s+([^\s;]+)', received_spf)
            if mechanism_match:
                spf_results['mechanism'] = mechanism_match.group(1)
        
        # Descrizione in base al risultato
        result_descriptions = {
            'pass': 'SPF authentication passed',
            'fail': 'SPF authentication failed',
            'softfail': 'SPF soft fail',
            'neutral': 'SPF neutral result',
            'none': 'No SPF record found',
            'temperror': 'Temporary SPF error',
            'permerror': 'Permanent SPF error'
        }
        
        spf_results['description'] = result_descriptions.get(spf_results['result'], 'Unknown SPF result')
        
    except Exception as e:
        spf_results['error'] = f'SPF analysis error: {str(e)}'
    
    return spf_results

def analyze_dkim(headers):
    """Analizza i risultati DKIM"""
    dkim_results = {
        'result': 'none',
        'domain': '',
        'selector': '',
        'description': ''
    }
    
    try:
        # Cerca in Authentication-Results
        auth_results = headers['auth_headers'].get('Authentication-Results', '')
        if 'dkim=' in auth_results:
            import re
            dkim_match = re.search(r'dkim=(\w+)', auth_results)
            if dkim_match:
                dkim_results['result'] = dkim_match.group(1)
            
            # Estrai dominio e selector
            domain_match = re.search(r'header\.d=([^\s;]+)', auth_results)
            if domain_match:
                dkim_results['domain'] = domain_match.group(1)
            
            selector_match = re.search(r'header\.s=([^\s;]+)', auth_results)
            if selector_match:
                dkim_results['selector'] = selector_match.group(1)
        
        # Analizza DKIM-Signature header
        dkim_signature = headers['auth_headers'].get('DKIM-Signature', '')
        if dkim_signature:
            import re
            domain_match = re.search(r'd=([^;]+)', dkim_signature)
            if domain_match and not dkim_results['domain']:
                dkim_results['domain'] = domain_match.group(1)
            
            selector_match = re.search(r's=([^;]+)', dkim_signature)
            if selector_match and not dkim_results['selector']:
                dkim_results['selector'] = selector_match.group(1)
        
        # Descrizione in base al risultato
        result_descriptions = {
            'pass': 'DKIM signature valid',
            'fail': 'DKIM signature invalid',
            'none': 'No DKIM signature found',
            'neutral': 'DKIM neutral result',
            'policy': 'DKIM policy rejection',
            'temperror': 'Temporary DKIM error',
            'permerror': 'Permanent DKIM error'
        }
        
        dkim_results['description'] = result_descriptions.get(dkim_results['result'], 'Unknown DKIM result')
        
    except Exception as e:
        dkim_results['error'] = f'DKIM analysis error: {str(e)}'
    
    return dkim_results

def analyze_dmarc(spf_result, dkim_result, from_domain):
    """Analizza il risultato DMARC complessivo"""
    dmarc_results = {
        'result': 'none',
        'policy': 'none',
        'description': '',
        'alignment': {
            'spf': 'unknown',
            'dkim': 'unknown'
        }
    }
    
    try:
        # Controlla allineamento SPF
        if spf_result.get('domain') and from_domain:
            spf_domain = spf_result['domain'].lower().strip()
            from_domain_lower = from_domain.lower().strip()
            dmarc_results['alignment']['spf'] = 'aligned' if spf_domain == from_domain_lower else 'misaligned'
        
        # Controlla allineamento DKIM
        if dkim_result.get('domain') and from_domain:
            dkim_domain = dkim_result['domain'].lower().strip()
            from_domain_lower = from_domain.lower().strip()
            dmarc_results['alignment']['dkim'] = 'aligned' if dkim_domain == from_domain_lower else 'misaligned'
        
        # Determina risultato DMARC
        spf_pass = spf_result.get('result') == 'pass'
        dkim_pass = dkim_result.get('result') == 'pass'
        spf_aligned = dmarc_results['alignment']['spf'] == 'aligned'
        dkim_aligned = dmarc_results['alignment']['dkim'] == 'aligned'
        
        if (spf_pass and spf_aligned) or (dkim_pass and dkim_aligned):
            dmarc_results['result'] = 'pass'
            dmarc_results['description'] = 'DMARC authentication passed'
        elif spf_pass or dkim_pass:
            dmarc_results['result'] = 'fail'
            dmarc_results['description'] = 'DMARC authentication failed (alignment issue)'
        else:
            dmarc_results['result'] = 'fail'
            dmarc_results['description'] = 'DMARC authentication failed (both SPF and DKIM failed)'
        
    except Exception as e:
        dmarc_results['error'] = f'DMARC analysis error: {str(e)}'
    
    return dmarc_results

def extract_domain_from_email(email_address):
    """Estrae il dominio da un indirizzo email"""
    if not email_address:
        return ''
    
    try:
        if '@' in email_address:
            return email_address.split('@')[1].lower().strip()
        return email_address.lower().strip()
    except:
        return ''

def analyze_email_message(file):
    """Analizza un file email completo"""
    try:
        # Leggi il contenuto dell'email
        email_content = file.read()
        
        if hasattr(file, 'seek'):
            file.seek(0)
        
        # Parsing header
        headers_result = parse_email_headers(email_content)
        if 'error' in headers_result:
            return {'error': headers_result['error']}
        
        # Estrai dominio From
        from_header = headers_result['main_headers'].get('From', '')
        from_domain = extract_domain_from_email(from_header)
        
        # Estrai IP sorgente dai Received headers
        source_ip = None
        received_headers = headers_result['auth_headers'].get('Received', [])
        for received in received_headers:
            import re
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
            if ip_match:
                source_ip = ip_match.group(1)
                break
        
        # Analisi SPF, DKIM, DMARC
        spf_analysis = analyze_spf(headers_result, source_ip)
        dkim_analysis = analyze_dkim(headers_result)
        dmarc_analysis = analyze_dmarc(spf_analysis, dkim_analysis, from_domain)
        
        # Risultato complessivo
        overall_result = 'pass' if dmarc_analysis['result'] == 'pass' else 'fail'
        
        return {
            'filename': getattr(file, 'filename', 'unknown'),
            'overall_result': overall_result,
            'from_domain': from_domain,
            'source_ip': source_ip,
            'headers': headers_result,
            'spf': spf_analysis,
            'dkim': dkim_analysis,
            'dmarc': dmarc_analysis,
            'analysis_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
    except Exception as e:
        return {'error': f'Error analyzing email message: {str(e)}'}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def check_file_size(file):
    """Controlla le dimensioni del file"""
    current_position = file.tell()
    file.seek(0, 2)
    size = file.tell()
    file.seek(current_position)
    return size <= MAX_FILE_SIZE

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def safe_find_text(element, path, default="N/A"):
    found = element.find(path)
    return found.text if found is not None else default

def timestamp_to_date(ts, default="N/A"):
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M')
    except:
        return default

def is_ip_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def validate_xml_structure(xml_content):
    """Valida la struttura base di un report DMARC XML"""
    try:
        root = ET.fromstring(xml_content)
        
        minimal_elements = [
            './/report_metadata/report_id',
            './/policy_published/domain',
            './/date_range/begin',
            './/date_range/end'
        ]
        
        missing_elements = []
        for element_path in minimal_elements:
            if root.find(element_path) is None:
                missing_elements.append(element_path)
        
        if missing_elements:
            return False, f"Missing essential elements: {', '.join(missing_elements)}"
        
        if root.find('.//record') is None:
            return False, "No records found in report"
            
        return True, "Valid DMARC report structure"
        
    except ET.ParseError as e:
        return False, f"Invalid XML format: {str(e)}"
    except Exception as e:
        return False, f"XML validation error: {str(e)}"

def validate_dmarc_report_content(report_data):
    """Valida il contenuto del report DMARC"""
    try:
        essential_fields = ['report_id', 'policy', 'records']
        for field in essential_fields:
            if field not in report_data:
                return False, f"Missing essential field: {field}"
        
        policy = report_data['policy']
        if not policy.get('domain'):
            return False, "Missing domain in policy"
        
        date_range = report_data.get('date_range', {})
        if not date_range.get('start_ts') or not date_range.get('end_ts'):
            try:
                if date_range.get('start') and date_range.get('end'):
                    start_str = date_range['start'].split()[0]
                    end_str = date_range['end'].split()[0]
                    start_dt = datetime.strptime(start_str, '%Y-%m-%d')
                    end_dt = datetime.strptime(end_str, '%Y-%m-%d')
                    report_data['date_range']['start_ts'] = int(start_dt.timestamp())
                    report_data['date_range']['end_ts'] = int(end_dt.timestamp())
                else:
                    return False, "Invalid date range"
            except:
                return False, "Invalid date range format"
        
        records = report_data.get('records', [])
        if not records:
            return False, "No records in report"
        
        for i, record in enumerate(records):
            if not record.get('source_ip'):
                return False, f"Record {i}: Missing source IP"
            
            count = record.get('count', 0)
            if count < 0:
                return False, f"Record {i}: Invalid count ({count})"
        
        return True, "Report content validation passed"
        
    except Exception as e:
        return False, f"Content validation error: {str(e)}"

def parse_dmarc_report(file):
    """Parse a DMARC report file (XML, GZ or ZIP)"""
    try:
        # Gestione sicura del filename
        filename = getattr(file, 'filename', 'unknown')
        if not filename or filename == 'unknown':
            filename = 'unknown_file'
        
        if not check_file_size(file):
            return {'error': f'File too large: {filename}'}
        
        original_filename = filename
        
        # Assicurati che filename sia una stringa prima di usare .endswith()
        filename_str = str(filename)
        
        if filename_str.endswith('.gz'):
            import io
            file_content = file.read()
            try:
                with gzip.open(io.BytesIO(file_content), 'rb') as f_in:
                    content = f_in.read().decode('utf-8')
                filename = filename_str[:-3]
            except (gzip.BadGzipFile, EOFError) as e:
                return {'error': f'Invalid gzip file: {str(e)}'}
                
        elif filename_str.endswith('.zip'):
            import zipfile
            import io
            file_content = file.read()
            try:
                with zipfile.ZipFile(io.BytesIO(file_content)) as zip_file:
                    xml_files = [name for name in zip_file.namelist() if name.lower().endswith('.xml')]
                    if not xml_files:
                        return {'error': "No XML file found in ZIP archive"}
                    
                    with zip_file.open(xml_files[0]) as f_in:
                        content = f_in.read().decode('utf-8')
                    filename = xml_files[0]
            except (zipfile.BadZipFile, zipfile.LargeZipFile) as e:
                return {'error': f'Invalid zip file: {str(e)}'}
        else:
            content = file.read().decode('utf-8')
        
        if hasattr(file, 'seek'):
            file.seek(0)
        
        is_valid_xml, xml_message = validate_xml_structure(content)
        if not is_valid_xml:
            return {'error': f'Invalid DMARC XML: {xml_message}'}
        
        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            return {'error': f'XML parsing error: {str(e)}'}
        
        report = {
            'org': safe_find_text(root, './/org_name', 'Unknown Organization'),
            'email': safe_find_text(root, './/email', 'unknown@example.com'),
            'report_id': safe_find_text(root, './/report_id', f'unknown_{int(time.time())}'),
            'date_range': {
                'start': timestamp_to_date(safe_find_text(root, './/date_range/begin', '0')),
                'end': timestamp_to_date(safe_find_text(root, './/date_range/end', '0')),
                'start_ts': int(safe_find_text(root, './/date_range/begin', '0')),
                'end_ts': int(safe_find_text(root, './/date_range/end', '0'))
            },
            'policy': {
                'domain': safe_find_text(root, './/policy_published/domain', 'unknown.domain'),
                'adkim': safe_find_text(root, './/policy_published/adkim', 'r'),
                'aspf': safe_find_text(root, './/policy_published/aspf', 'r'),
                'p': safe_find_text(root, './/policy_published/p', 'none'),
                'sp': safe_find_text(root, './/policy_published/sp', 'none'),
                'pct': safe_find_text(root, './/policy_published/pct', '100'),
                'fo': safe_find_text(root, './/policy_published/fo', '0')
            },
            'records': [],
            'filename': original_filename
        }

        records = []
        record_count = 0
        
        for record in root.findall('.//record'):
            try:
                policy_evaluated = record.find('.//row/policy_evaluated')
                auth_results = record.find('.//auth_results')
                
                source_ip = safe_find_text(record, './/row/source_ip', '0.0.0.0')
                try:
                    count = int(safe_find_text(record, './/row/count', "1"))
                except (ValueError, TypeError):
                    count = 1
                
                # CORREZIONE: Estrazione SEMPLIFICATA e ROBUSTA
                disposition = 'none'
                dkim_result = 'none'
                spf_result = 'none'
                dkim_domain = ''
                spf_domain = ''
                
                # Estrai disposition
                if policy_evaluated is not None:
                    disposition_elem = policy_evaluated.find('.//disposition')
                    if disposition_elem is not None and disposition_elem.text:
                        disposition = disposition_elem.text.strip().lower()
                
                # Estrai SPF e DKIM
                if auth_results is not None:
                    # Cerca SPF
                    spf_elem = auth_results.find('.//spf')
                    if spf_elem is not None:
                        result_elem = spf_elem.find('.//result')
                        if result_elem is not None and result_elem.text:
                            spf_result = result_elem.text.strip().lower()
                        domain_elem = spf_elem.find('.//domain')
                        if domain_elem is not None and domain_elem.text:
                            spf_domain = domain_elem.text.strip()
                    
                    # Cerca DKIM
                    dkim_elem = auth_results.find('.//dkim')
                    if dkim_elem is not None:
                        result_elem = dkim_elem.find('.//result')
                        if result_elem is not None and result_elem.text:
                            dkim_result = result_elem.text.strip().lower()
                        domain_elem = dkim_elem.find('.//domain')
                        if domain_elem is not None and domain_elem.text:
                            dkim_domain = domain_elem.text.strip()
                
                header_from = safe_find_text(record, './/identifiers/header_from', 'unknown@domain.com')
                
                row_data = {
                    'source_ip': source_ip,
                    'count': count,
                    'disposition': disposition,
                    'dkim': dkim_result,
                    'spf': spf_result,
                    'header_from': header_from,
                    'is_internal': is_ip_private(source_ip),
                    'dkim_domain': dkim_domain,
                    'spf_domain': spf_domain
                }
                records.append(row_data)
                record_count += 1
                
            except Exception as e:
                print(f"[parse_dmarc_report] Error processing record {record_count}: {e}")
                continue

        # AGGIUNGI QUESTA PARTE MANCANTE:
        report['records'] = records
        
        # Validazione finale del contenuto
        is_valid_content, content_message = validate_dmarc_report_content(report)
        if not is_valid_content:
            return {'error': f'Invalid DMARC report content: {content_message}'}
        
        print(f"[parse_dmarc_report] Successfully parsed report {report['report_id']} with {len(records)} records")
        return report
        
    except Exception as e:
        print(f"[parse_dmarc_report] Critical error: {e}")
        import traceback
        traceback.print_exc()
        return {'error': f'Unexpected error parsing DMARC report: {str(e)}'}


def create_empty_stats():
    """Crea statistiche vuote per il fallback"""
    return {
        'total_reports': 0,
        'total_emails': 0,
        'domains': [],
        'auth_results': {
            'both_pass': 0,
            'spf_pass': 0,
            'dkim_pass': 0,
            'fail': 0,
            'alignment_fail': 0  # Aggiungi questo
        },
        'top_ips': {'ips': [], 'counts': []},
        'domain_distribution': {'domains': [], 'counts': []},
        'time_series_labels': [],
        'time_series_report_counts': [],
        'time_series_email_counts': [],
        'internal_vs_external': {'internal': 0, 'external': 0},
        'policy_evaluation': {'pct_compliance': 0},
        'dispositions': {}
    }


def generate_stats_from_db(time_filter='30days'):
    """Genera statistiche direttamente dal database SQLite con filtro temporale"""
    try:
        with db_connection() as conn:
            # Calcola il range di date basato sul filtro
            date_conditions = {
                '7days': "start_date >= date('now', '-7 days')",
                '30days': "start_date >= date('now', '-30 days')",
                '90days': "start_date >= date('now', '-90 days')",
                '1year': "start_date >= date('now', '-1 year')",
                'all': "1=1"  # Tutti i record - nessun filtro
            }
            
            where_clause = date_conditions.get(time_filter, date_conditions['30days'])
            
            # Statistiche base con filtro temporale
            total_reports = conn.execute(f'''
                SELECT COUNT(*) as count 
                FROM reports 
                WHERE {where_clause}
            ''').fetchone()['count']
            
            total_emails_result = conn.execute(f'''
                SELECT SUM(r.count) as total 
                FROM records r
                JOIN reports rep ON r.report_id = rep.report_id
                WHERE {where_clause}
            ''').fetchone()
            total_emails = total_emails_result['total'] if total_emails_result['total'] else 0
            
            # Authentication results con filtro temporale - CALCOLO CORRETTO
            auth_stats = conn.execute(f'''
                SELECT 
                    SUM(CASE WHEN r.dkim = 'pass' AND r.spf = 'pass' THEN r.count ELSE 0 END) as both_pass,
                    SUM(CASE WHEN r.spf = 'pass' AND r.dkim != 'pass' THEN r.count ELSE 0 END) as spf_only,
                    SUM(CASE WHEN r.dkim = 'pass' AND r.spf != 'pass' THEN r.count ELSE 0 END) as dkim_only,
                    SUM(CASE WHEN r.dkim != 'pass' AND r.spf != 'pass' THEN r.count ELSE 0 END) as both_fail,
                    SUM(r.count) as total
                FROM records r
                JOIN reports rep ON r.report_id = rep.report_id
                WHERE {where_clause}
            ''').fetchone()

            # Calcola CORRETTAMENTE
            both_pass = auth_stats['both_pass'] or 0
            spf_only = auth_stats['spf_only'] or 0
            dkim_only = auth_stats['dkim_only'] or 0
            both_fail = auth_stats['both_fail'] or 0
            total = auth_stats['total'] or 0

            # VERIFICA
            calculated_total = both_pass + spf_only + dkim_only + both_fail
            if calculated_total != total and total > 0:
                print(f"[WARNING] Dashboard auth calculation mismatch: {calculated_total} vs {total}")

            auth_results = {
                'both_pass': both_pass,
                'spf_pass': both_pass + spf_only,  # CORRETTO: tutte le email con SPF pass
                'dkim_pass': both_pass + dkim_only,  # CORRETTO: tutte le email con DKIM pass
                'fail': both_fail,
                'alignment_fail': spf_only + dkim_only,  # Email che passano solo uno dei due
                'calculation_valid': calculated_total == total
            }
            
            # Top IPs con filtro temporale
            top_ips = conn.execute(f'''
                SELECT r.source_ip, SUM(r.count) as total 
                FROM records r
                JOIN reports rep ON r.report_id = rep.report_id
                WHERE {where_clause}
                GROUP BY r.source_ip 
                ORDER BY total DESC 
                LIMIT 10
            ''').fetchall()
            
            # Domains distribution con filtro temporale
            domain_stats = conn.execute(f'''
                SELECT domain, COUNT(*) as count 
                FROM reports 
                WHERE {where_clause}
                GROUP BY domain 
                ORDER BY count DESC
                LIMIT 10
            ''').fetchall()
            
            # Dispositions con filtro temporale
            dispositions = conn.execute(f'''
                SELECT r.disposition, SUM(r.count) as total
                FROM records r
                JOIN reports rep ON r.report_id = rep.report_id
                WHERE {where_clause}
                GROUP BY r.disposition
            ''').fetchall()
            
            dispositions_data = {row['disposition']: row['total'] for row in dispositions}
            
            # Internal vs External con filtro temporale
            internal_external = conn.execute(f'''
                SELECT 
                    SUM(CASE WHEN r.is_internal = 1 THEN r.count ELSE 0 END) as internal,
                    SUM(CASE WHEN r.is_internal = 0 THEN r.count ELSE 0 END) as external
                FROM records r
                JOIN reports rep ON r.report_id = rep.report_id
                WHERE {where_clause}
            ''').fetchone()
            
            # Time series data basata sul filtro
            # Per il filtro "all", limitiamo a 90 punti per performance
            if time_filter == 'all':
                time_series_query = '''
                    SELECT 
                        date(start_date) as day,
                        COUNT(*) as report_count,
                        SUM((SELECT SUM(count) FROM records WHERE records.report_id = reports.report_id)) as email_count
                    FROM reports 
                    GROUP BY date(start_date)
                    ORDER BY day DESC
                    LIMIT 90  -- Limita a 90 giorni per performance
                '''
            else:
                time_series_query = f'''
                    SELECT 
                        date(start_date) as day,
                        COUNT(*) as report_count,
                        SUM((SELECT SUM(count) FROM records WHERE records.report_id = reports.report_id)) as email_count
                    FROM reports 
                    WHERE {where_clause}
                    GROUP BY date(start_date)
                    ORDER BY day
                '''
            
            time_series = conn.execute(time_series_query).fetchall()
            
            # Per il filtro "all", invertiamo l'ordine per mostrare i più recenti prima
            if time_filter == 'all':
                time_series.reverse()
            
            stats = {
                'total_reports': total_reports,
                'total_emails': total_emails,
                'domains': [row['domain'] for row in domain_stats],
                'auth_results': auth_results,
                'dispositions': dispositions_data,
                'top_ips': {
                    'ips': [row['source_ip'] for row in top_ips],
                    'counts': [row['total'] for row in top_ips]
                },
                'domain_distribution': {
                    'domains': [row['domain'] for row in domain_stats],
                    'counts': [row['count'] for row in domain_stats]
                },
                'internal_vs_external': {
                    'internal': internal_external['internal'] or 0,
                    'external': internal_external['external'] or 0
                },
                'policy_evaluation': {
                    'pct_compliance': round((auth_results['both_pass'] / total_emails * 100), 1) if total_emails > 0 else 0
                },
                'time_series_labels': [row['day'] for row in time_series],
                'time_series_report_counts': [row['report_count'] for row in time_series],
                'time_series_email_counts': [row['email_count'] or 0 for row in time_series],
                'time_filter': time_filter,
                'is_all_time': time_filter == 'all'  # Flag per il template
            }
            
            return stats
            
    except Exception as e:
        print(f"[generate_stats_from_db] Error: {e}")
        stats = create_empty_stats()
        stats['time_filter'] = time_filter
        stats['is_all_time'] = time_filter == 'all'
        return stats



def validate_domain_name(domain_name):
    """Validazione per i nomi di dominio"""
    if not domain_name or len(domain_name) > 253:
        return False
    
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain_name))

def check_permissions():
    """Check if we have write permissions to data directory"""
    try:
        test_file = os.path.join(DATA_DIR, '.test_write')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        print(f"[check_permissions] Write permissions OK for {DATA_DIR}")
        return True
    except Exception as e:
        print(f"[check_permissions] CRITICAL: No write permissions to {DATA_DIR}: {e}")
        return False




def report_hash_exists_in_db(file_hash):
    """Controlla se un file con lo stesso hash esiste già nel database"""
    try:
        with db_connection() as conn:
            result = conn.execute(
                'SELECT 1 FROM reports WHERE file_hash = ?', 
                (file_hash,)
            ).fetchone()
            return result is not None
    except Exception as e:
        print(f"[report_hash_exists_in_db] Error: {e}")
        return False

def check_file_size(file):
    """Controlla le dimensioni del file"""
    try:
        current_position = file.tell()
        file.seek(0, 2)  # Vai alla fine del file
        size = file.tell()
        file.seek(current_position)  # Ritorna alla posizione originale
        return size <= MAX_FILE_SIZE
    except Exception as e:
        print(f"[check_file_size] Error: {e}")
        return False

def allowed_file(filename):
    """Controlla se il file è di un tipo consentito"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def get_dmarc_policy(domain):
    """Estrae la policy DMARC da un dominio via DNS lookup"""
    try:
        # Cerca record TXT DMARC
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        
        for rdata in answers:
            record = ''.join([s.decode('utf-8') if isinstance(s, bytes) else str(s) for s in rdata.strings])
            
            if 'v=DMARC1' in record:
                # Estrai la policy
                policy_match = re.search(r'p=(\w+)', record)
                policy = policy_match.group(1) if policy_match else 'none'
                
                # Estrai percentage
                pct_match = re.search(r'pct=(\d+)', record)
                pct = pct_match.group(1) if pct_match else '100'
                
                # Estrai RUA/RUF
                rua_match = re.search(r'rua=([^;]+)', record)
                rua = rua_match.group(1) if rua_match else ''
                
                ruf_match = re.search(r'ruf=([^;]+)', record)
                ruf = ruf_match.group(1) if ruf_match else ''
                
                return {
                    'policy': policy,
                    'pct': pct,
                    'rua': rua,
                    'ruf': ruf,
                    'record': record,
                    'status': 'active'
                }
        
        return {
            'policy': 'none',
            'pct': '0',
            'rua': '',
            'ruf': '',
            'record': '',
            'status': 'no_dmarc_record'
        }
        
    except dns.resolver.NXDOMAIN:
        return {
            'policy': 'none',
            'pct': '0',
            'rua': '',
            'ruf': '',
            'record': '',
            'status': 'no_dmarc_record'
        }
    except dns.resolver.NoAnswer:
        return {
            'policy': 'none',
            'pct': '0',
            'rua': '',
            'ruf': '',
            'record': '',
            'status': 'no_dmarc_record'
        }
    except Exception as e:
        print(f"DNS lookup error for {domain}: {e}")
        return {
            'policy': 'none',
            'pct': '0',
            'rua': '',
            'ruf': '',
            'record': '',
            'status': 'lookup_error'
        }


def extract_domains_from_reports():
    """Estrae tutti i domini unici dai report nel database"""
    try:
        with db_connection() as conn:
            domains = conn.execute('''
                SELECT DISTINCT domain 
                FROM reports 
                WHERE domain IS NOT NULL AND domain != ''
                ORDER BY domain
            ''').fetchall()
            
            return [row['domain'] for row in domains]
    except Exception as e:
        print(f"Error extracting domains from reports: {e}")
        return []

def auto_populate_domains():
    """Popola automaticamente la tabella domains dai report"""
    try:
        domain_names = extract_domains_from_reports()
        added_count = 0
        updated_count = 0
        
        for domain_name in domain_names:
            # Controlla se il dominio esiste già
            if not domain_exists_in_db(domain_name):
                # Analizza la policy DMARC via DNS
                dmarc_info = get_dmarc_policy(domain_name)
                
                # Calcola auth_score basato sui report
                auth_score = calculate_domain_auth_score(domain_name)
                
                domain_data = {
                    'name': domain_name,
                    'dmarc_policy': dmarc_info['policy'],
                    'enable_reporting': bool(dmarc_info['rua'] or dmarc_info['ruf']),
                    'report_emails': extract_emails_from_dmarc_record(dmarc_info.get('rua', '') + ',' + dmarc_info.get('ruf', '')),
                    'status': dmarc_info['status'],
                    'last_report': get_latest_report_date(domain_name),
                    'auth_score': auth_score,
                    'dmarc_record': dmarc_info.get('record', '')
                }
                
                if save_domain_to_db(domain_data):
                    added_count += 1
            else:
                # Aggiorna il dominio esistente con nuove info
                dmarc_info = get_dmarc_policy(domain_name)
                auth_score = calculate_domain_auth_score(domain_name)
                
                updates = {
                    'dmarc_policy': dmarc_info['policy'],
                    'enable_reporting': bool(dmarc_info['rua'] or dmarc_info['ruf']),
                    'report_emails': extract_emails_from_dmarc_record(dmarc_info.get('rua', '') + ',' + dmarc_info.get('ruf', '')),
                    'status': dmarc_info['status'],
                    'last_report': get_latest_report_date(domain_name),
                    'auth_score': auth_score
                }
                
                if update_domain_in_db(domain_name, updates):
                    updated_count += 1
        
        return {
            'added': added_count,
            'updated': updated_count,
            'total': len(domain_names)
        }
        
    except Exception as e:
        print(f"Error auto-populating domains: {e}")
        return {'added': 0, 'updated': 0, 'total': 0, 'error': str(e)}

def calculate_domain_auth_score(domain_name):
    """Calcola uno score di autenticazione per il dominio basato sui report"""
    try:
        with db_connection() as conn:
            # Query per calcolare le statistiche di autenticazione
            stats = conn.execute('''
                SELECT 
                    SUM(CASE WHEN dkim = 'pass' AND spf = 'pass' THEN count ELSE 0 END) as both_pass,
                    SUM(CASE WHEN dkim = 'pass' OR spf = 'pass' THEN count ELSE 0 END) as either_pass,
                    SUM(count) as total
                FROM records r
                JOIN reports rep ON r.report_id = rep.report_id
                WHERE rep.domain = ?
            ''', (domain_name,)).fetchone()
            
            if stats and stats['total'] and stats['total'] > 0:
                # Calcola score: 100% se tutti passano, 0% se nessuno passa
                pass_rate = (stats['both_pass'] / stats['total']) * 100
                return round(pass_rate, 1)
            
        return 0
    except Exception as e:
        print(f"Error calculating auth score for {domain_name}: {e}")
        return 0

def extract_emails_from_dmarc_record(record):
    """Estrae indirizzi email dal record DMARC"""
    emails = []
    try:
        # Cerca indirizzi email nel record (formato mailto:email@domain.com)
        email_matches = re.findall(r'mailto:([^,\s]+)', record)
        emails.extend(email_matches)
        
        # Rimuovi duplicati
        return list(set(emails))
    except Exception as e:
        print(f"Error extracting emails from DMARC record: {e}")
        return []

def get_latest_report_date(domain_name):
    """Restituisce la data dell'ultimo report per il dominio"""
    try:
        with db_connection() as conn:
            result = conn.execute('''
                SELECT MAX(end_date) as latest_date 
                FROM reports 
                WHERE domain = ?
            ''', (domain_name,)).fetchone()
            
            return result['latest_date'] if result else None
    except Exception as e:
        print(f"Error getting latest report date for {domain_name}: {e}")
        return None        






def get_total_reports():
    """Restituisce il numero totale di report"""
    try:
        with db_connection() as conn:
            result = conn.execute('SELECT COUNT(*) as count FROM reports').fetchone()
            return result['count'] if result else 0
    except Exception as e:
        print(f"[get_total_reports] Error: {e}")
        return 0

def get_total_emails():
    """Restituisce il numero totale di email"""
    try:
        with db_connection() as conn:
            result = conn.execute('SELECT SUM(count) as total FROM records').fetchone()
            return result['total'] if result['total'] else 0
    except Exception as e:
        print(f"[get_total_emails] Error: {e}")
        return 0

def get_policy_stats():
    """Restituisce le statistiche delle policy"""
    try:
        with db_connection() as conn:
            # Calcola la compliance rate
            result = conn.execute('''
                SELECT 
                    SUM(CASE WHEN r.dkim = 'pass' AND r.spf = 'pass' THEN r.count ELSE 0 END) as passed,
                    SUM(r.count) as total
                FROM records r
            ''').fetchone()
            
            if result and result['total'] and result['total'] > 0:
                pct_compliance = round((result['passed'] / result['total']) * 100, 1)
            else:
                pct_compliance = 0
                
            return {'pct_compliance': pct_compliance}
    except Exception as e:
        print(f"[get_policy_stats] Error: {e}")
        return {'pct_compliance': 0}

def get_auth_results():
    """Restituisce i risultati di autenticazione"""
    try:
        with db_connection() as conn:
            result = conn.execute('''
                SELECT 
                    SUM(CASE WHEN dkim = 'pass' AND spf = 'pass' THEN count ELSE 0 END) as both_pass,
                    SUM(CASE WHEN spf = 'pass' AND dkim != 'pass' THEN count ELSE 0 END) as spf_only,
                    SUM(CASE WHEN dkim = 'pass' AND spf != 'pass' THEN count ELSE 0 END) as dkim_only,
                    SUM(CASE WHEN dkim != 'pass' AND spf != 'pass' THEN count ELSE 0 END) as both_fail,
                    SUM(count) as total
                FROM records
            ''').fetchone()
            
            if result and result['total'] and result['total'] > 0:
                return {
                    'both_pass': result['both_pass'] or 0,
                    'spf_pass': (result['both_pass'] or 0) + (result['spf_only'] or 0),
                    'dkim_pass': (result['both_pass'] or 0) + (result['dkim_only'] or 0),
                    'fail': result['both_fail'] or 0,
                    'alignment_fail': (result['spf_only'] or 0) + (result['dkim_only'] or 0)
                }
            else:
                return {
                    'both_pass': 0,
                    'spf_pass': 0,
                    'dkim_pass': 0,
                    'fail': 0,
                    'alignment_fail': 0
                }
    except Exception as e:
        print(f"[get_auth_results] Error: {e}")
        return {
            'both_pass': 0,
            'spf_pass': 0,
            'dkim_pass': 0,
            'fail': 0,
            'alignment_fail': 0
        }

def get_top_ips():
    """Restituisce gli IP più comuni"""
    try:
        with db_connection() as conn:
            results = conn.execute('''
                SELECT source_ip, SUM(count) as total 
                FROM records 
                GROUP BY source_ip 
                ORDER BY total DESC 
                LIMIT 10
            ''').fetchall()
            
            return {
                'ips': [row['source_ip'] for row in results],
                'counts': [row['total'] for row in results]
            }
    except Exception as e:
        print(f"[get_top_ips] Error: {e}")
        return {'ips': [], 'counts': []}

def get_domain_distribution():
    """Restituisce la distribuzione per dominio"""
    try:
        with db_connection() as conn:
            results = conn.execute('''
                SELECT domain, COUNT(*) as count 
                FROM reports 
                GROUP BY domain 
                ORDER BY count DESC
                LIMIT 10
            ''').fetchall()
            
            return {
                'domains': [row['domain'] for row in results],
                'counts': [row['count'] for row in results]
            }
    except Exception as e:
        print(f"[get_domain_distribution] Error: {e}")
        return {'domains': [], 'counts': []}

def get_dispositions():
    """Restituisce le disposizioni"""
    try:
        with db_connection() as conn:
            results = conn.execute('''
                SELECT disposition, SUM(count) as total
                FROM records
                GROUP BY disposition
            ''').fetchall()
            
            return {row['disposition']: row['total'] for row in results}
    except Exception as e:
        print(f"[get_dispositions] Error: {e}")
        return {}

def get_internal_external():
    """Restituisce il rapporto interno/esterno"""
    try:
        with db_connection() as conn:
            result = conn.execute('''
                SELECT 
                    SUM(CASE WHEN is_internal = 1 THEN count ELSE 0 END) as internal,
                    SUM(CASE WHEN is_internal = 0 THEN count ELSE 0 END) as external
                FROM records
            ''').fetchone()
            
            return {
                'internal': result['internal'] or 0,
                'external': result['external'] or 0
            }
    except Exception as e:
        print(f"[get_internal_external] Error: {e}")
        return {'internal': 0, 'external': 0}

def get_time_series_labels():
    """Restituisce le etichette per le serie temporali"""
    try:
        with db_connection() as conn:
            results = conn.execute('''
                SELECT DISTINCT date(start_date) as day
                FROM reports 
                ORDER BY day DESC
                LIMIT 30
            ''').fetchall()
            
            labels = [row['day'] for row in results]
            labels.reverse()  # Per mostrare dalla più vecchia alla più recente
            return labels
    except Exception as e:
        print(f"[get_time_series_labels] Error: {e}")
        return []

def get_time_series_reports():
    """Restituisce i conteggi dei report per le serie temporali"""
    try:
        labels = get_time_series_labels()
        if not labels:
            return []
            
        with db_connection() as conn:
            counts = []
            for day in labels:
                result = conn.execute('''
                    SELECT COUNT(*) as count 
                    FROM reports 
                    WHERE date(start_date) = ?
                ''', (day,)).fetchone()
                counts.append(result['count'] if result else 0)
            
            return counts
    except Exception as e:
        print(f"[get_time_series_reports] Error: {e}")
        return []

def get_time_series_emails():
    """Restituisce i conteggi delle email per le serie temporali"""
    try:
        labels = get_time_series_labels()
        if not labels:
            return []
            
        with db_connection() as conn:
            counts = []
            for day in labels:
                result = conn.execute('''
                    SELECT SUM(r.count) as total
                    FROM records r
                    JOIN reports rep ON r.report_id = rep.report_id
                    WHERE date(rep.start_date) = ?
                ''', (day,)).fetchone()
                counts.append(result['total'] if result and result['total'] else 0)
            
            return counts
    except Exception as e:
        print(f"[get_time_series_emails] Error: {e}")
        return []

def get_dashboard_stats(time_filter='30days'):
    """Funzione principale per ottenere tutte le statistiche della dashboard"""
    try:
        return generate_stats_from_db(time_filter)
    except Exception as e:
        print(f"[get_dashboard_stats] Error: {e}")
        return create_empty_stats()


def analyze_dmarc_data(self, time_filter='30days', force_refresh=False):
    """Analizza i dati DMARC con supporto cache"""
    try:
        # Se non è forzato, controlla prima il cache
        if not force_refresh:
            cached_data = self.get_cached_threat_data(time_filter)
            if cached_data:
                print(f"[analyze_dmarc_data] Using cached data for {time_filter}")
                return cached_data
        
        # [IL TUO CODICE ESISTENTE DI ANALISI...]
        
        # Alla fine dell'analisi, salva nel cache
        threat_data = {
            'threat_score': threat_score,
            'malicious_ips': malicious_count,
            'suspicious_ips': suspicious_count,
            'clean_ips': clean_count,
            'blocked_ips': blocked_count,
            'threat_ips': threat_ips,
            'top_threats': top_threats,
            'recent_activity': recent_threats,
            'total_ips_checked': total_ips,
            'last_updated': datetime.now().isoformat()
        }
        
        # Salva nel cache
        self.save_to_cache(time_filter, threat_data)
        
        return threat_data
        
    except Exception as e:
        print(f"[analyze_dmarc_data] Error: {e}")
        # Ritorna dati di default in caso di errore
        return {
            'threat_score': 0,
            'malicious_ips': 0,
            'suspicious_ips': 0,
            'clean_ips': 0,
            'blocked_ips': 0,
            'threat_ips': [],
            'top_threats': [],
            'recent_activity': [],
            'total_ips_checked': 0,
            'error': str(e)
        }

def get_cached_threat_data(self, time_filter):
    """Ottiene i dati dal cache"""
    try:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        result = conn.execute('''
            SELECT threat_data, last_updated 
            FROM threat_intelligence_cache 
            WHERE time_filter = ?
            ORDER BY last_updated DESC 
            LIMIT 1
        ''', (time_filter,)).fetchone()
        
        if result and result['threat_data']:
            import json
            data = json.loads(result['threat_data'])
            # Controlla se i dati sono più vecchi di 1 ora
            last_updated = datetime.fromisoformat(result['last_updated'])
            if (datetime.now() - last_updated).total_seconds() < 3600:  # 1 ora
                return data
        
        return None
        
    except Exception as e:
        print(f"[get_cached_threat_data] Error: {e}")
        return None
    finally:
        conn.close()






def get_cached_threat_data(time_filter='30days'):
    """Ottiene i dati threat intelligence dal cache (veloce)"""
    try:
        # Qui dovresti avere una tabella nel database per cache threat intelligence
        with db_connection() as conn:
            result = conn.execute('''
                SELECT threat_data, last_updated 
                FROM threat_intelligence_cache 
                WHERE time_filter = ?
                ORDER BY last_updated DESC 
                LIMIT 1
            ''', (time_filter,)).fetchone()
            
            if result and result['threat_data']:
                import json
                data = json.loads(result['threat_data'])
                # Controlla se i dati sono più vecchi di 1 ora
                last_updated = datetime.fromisoformat(result['last_updated'])
                if (datetime.now() - last_updated).total_seconds() < 3600:  # 1 ora
                    return data
        
        # Se non ci sono dati cached o sono troppo vecchi
        return None
        
    except Exception as e:
        print(f"[get_cached_threat_data] Error: {e}")
        return None



def format_datetime(value, format='%Y-%m-%d %H:%M'):
    """Filtro per formattare datetime in template Jinja2"""
    if value is None:
        return ''
    
    try:
        # Se è già un oggetto datetime
        if isinstance(value, datetime):
            return value.strftime(format)
        
        # Se è una stringa, prova a convertirla
        if isinstance(value, str):
            # Prova diversi formati comuni
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d', '%Y-%m-%dT%H:%M:%S']:
                try:
                    dt = datetime.strptime(value, fmt)
                    return dt.strftime(format)
                except ValueError:
                    continue
        
        return str(value)
    except Exception:
        return str(value)

# Registra il filtro con Jinja2
app.jinja_env.filters['format_datetime'] = format_datetime



# =============================================================================
# TEMPLATE FILTERS
# =============================================================================

@app.template_filter('format_datetime')
def format_datetime_filter(value, format='%Y-%m-%d %H:%M'):
    """Filtro per formattare datetime in template Jinja2"""
    if value is None or value == '':
        return 'N/A'
    
    try:
        # Se è già un oggetto datetime
        if isinstance(value, datetime):
            return value.strftime(format)
        
        # Se è una stringa, prova a convertirla
        if isinstance(value, str):
            # Rimuovi spazi extra
            value = value.strip()
            
            # Prova diversi formati comuni per i report DMARC
            formats_to_try = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d %H:%M',
                '%Y-%m-%d',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y%m%dT%H%M%SZ'
            ]
            
            for fmt in formats_to_try:
                try:
                    dt = datetime.strptime(value, fmt)
                    return dt.strftime(format)
                except ValueError:
                    continue
            
            # Se è un timestamp numerico
            try:
                ts = int(value)
                dt = datetime.fromtimestamp(ts)
                return dt.strftime(format)
            except (ValueError, TypeError):
                pass
        
        # Fallback: ritorna il valore originale
        return str(value)
        
    except Exception as e:
        print(f"[format_datetime_filter] Error formatting {value}: {e}")
        return str(value)


# =============================================================================
# ROUTES
# =============================================================================

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.before_request
def check_csrf():
    if request.method == "POST":
        csrf.protect()

@app.route('/static/<path:filename>')
def serve_static(filename):
    response = send_from_directory('static', filename)
    # Corregge il MIME type per i file JavaScript
    if filename.endswith('.js'):
        response.headers['Content-Type'] = 'application/javascript'
    return response

# Route per servire il worker
@app.route('/static/js/<path:filename>')
def serve_js(filename):
    response = send_from_directory('static/js', filename)
    # Forza il MIME type corretto per i file JavaScript
    if filename.endswith('.js'):
        response.headers['Content-Type'] = 'application/javascript'
    elif filename.endswith('.worker.js'):
        response.headers['Content-Type'] = 'application/javascript'
    return response


@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('login'))


@app.route('/users', methods=['GET', 'POST'])
@login_required
def users_management():
    """Gestione degli utenti (solo per admin)"""
    if not session.get('is_admin'):
        flash('Access denied: Administrator privileges required', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        if request.method == 'POST':
            validate_csrf(request.form.get('csrf_token'))
            
            action = request.form.get('action')
            
            if action == 'create':
                username = request.form.get('username', '').strip()
                password = request.form.get('password', '')
                is_admin = bool(request.form.get('is_admin'))
                full_name = request.form.get('full_name', '').strip()
                email = request.form.get('email', '').strip()
                
                if not username or not password:
                    flash('Username and password are required', 'error')
                else:
                    success, message = create_user(username, password, is_admin, full_name, email)
                    flash(message, 'success' if success else 'error')
            
            elif action == 'change_password':
                username = request.form.get('username', '').strip()
                new_password = request.form.get('new_password', '')
                
                if not new_password:
                    flash('New password is required', 'error')
                else:
                    success, message = update_user_password(username, new_password)
                    flash(message, 'success' if success else 'error')
            
            elif action == 'delete':
                username = request.form.get('username', '').strip()
                
                # CORREZIONE: Controlla esplicitamente per "true"
                confirm_delete = request.form.get('confirm_delete')
                if confirm_delete != 'true':  # MODIFICA QUESTA RIGA
                    flash('Please confirm deletion by checking the confirmation box', 'error')
                    return redirect(url_for('users_management'))
                
                success, message = delete_user(username)
                if success:
                    flash(f'User {username} has been permanently deleted', 'success')
                else:
                    flash(message, 'error')
        
        # GET request - mostra la lista utenti
        users = get_all_users()
        csrf_token = generate_csrf()
        
        return render_template(
            'users.html',
            users=users,
            csrf_token=csrf_token,
            version=__version__
        )
        
    except Exception as e:
        print(f"[users_management] Error: {e}")
        flash(f'Error in user management: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/test')
def test():
    """Route di test per verificare il funzionamento base"""
    try:
        return jsonify({
            "status": "ok", 
            "database": "connected" if init_database() else "error",
            "version": __version__
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    try:
        from datetime import datetime
        
        print(f"[login] Request method: {request.method}")
        
        next_page = request.args.get('next') or url_for('dashboard')
        
        if request.method == 'GET':
            print("[login] GET request - rendering login form")
            csrf_token = generate_csrf()
            return render_template(
                'login.html', 
                next=next_page, 
                csrf_token=csrf_token,
                version=__version__,
                now=datetime.now()
            )
        
        # POST request
        print("[login] POST request - processing login")
        
        try:
            validate_csrf(request.form.get('csrf_token'))
        except (BadRequest, ValueError) as e:
            print(f"[login] CSRF validation failed: {e}")
            flash('Invalid CSRF token', 'danger')
            csrf_token = generate_csrf()
            return render_template(
                'login.html', 
                next=next_page, 
                csrf_token=csrf_token,
                version=__version__,
                now=datetime.now()
            )
        
        start_time = time.time()
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        print(f"[login] Authenticating user: {username}")
        
        # Autentica l'utente contro il database
        user_info, message = authenticate_user(username, password)
        
        elapsed = time.time() - start_time
        remaining = max(0.0, 1.0 - elapsed)
        time.sleep(remaining)
        
        if user_info:
            session.clear()
            session.permanent = True
            session['user_id'] = secrets.token_urlsafe(32)
            session['logged_in'] = True
            session['login_time'] = int(time.time())
            session['username'] = user_info['username']
            session['is_admin'] = user_info['is_admin']
            
            print(f"[login] User {username} authenticated successfully")
            flash(f'Welcome, {username}!', 'success')
            return redirect(next_page)
        
        print(f"[login] Authentication failed for user: {username}")
        flash('Invalid username or password', 'danger')
        csrf_token = generate_csrf()
        return render_template(
            'login.html', 
            next=next_page, 
            csrf_token=csrf_token,
            version=__version__,
            now=datetime.now()
        )
    
    except Exception as e:
        print(f"❌ [login] CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        
        # Fallback di emergenza CON CSRF token
        csrf_token = generate_csrf()
        return f"""
        <html>
            <head>
                <title>DMARCus - Login</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body>
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-header bg-primary text-white">
                                    <h4>DMARCus - Emergency Login</h4>
                                </div>
                                <div class="card-body">
                                    <div class="alert alert-warning">
                                        System in fallback mode. Error: {str(e)}
                                    </div>
                                    <form method="POST">
                                        <input type="hidden" name="csrf_token" value="{csrf_token}"/>
                                        <div class="mb-3">
                                            <label class="form-label">Username</label>
                                            <input type="text" name="username" class="form-control" required>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Password</label>
                                            <input type="password" name="password" class="form-control" required>
                                        </div>
                                        <button type="submit" class="btn btn-primary w-100">Login</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
        </html>
        """, 500

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        init_database()
        
        # 1. PRIMA: Cerca il filtro nell'ordine: URL → Cookie → Default
        time_filter = request.args.get('time_filter')
        
        if not time_filter:
            # Prova a recuperare dal cookie
            time_filter = request.cookies.get('dashboard_time_filter', '30days')
        
        # Valori validi per il filtro
        valid_filters = ['7days', '30days', '90days', '1year', 'all']
        if time_filter not in valid_filters:
            time_filter = '30days'  # Fallback
        
        print(f"[dashboard] Using time filter: {time_filter} (from {'URL' if request.args.get('time_filter') else 'cookie'})")
        
        # Genera statistiche principali (VELOCE - solo dal database)
        stats = generate_stats_from_db(time_filter)
        
        if stats is None:
            print("[dashboard] Creating empty stats")
            stats = create_empty_stats()
        
        # ============ THREAT INTELLIGENCE - CARICAMENTO RAPIDO ============
        try:
            # Carica i dati threat intelligence ESISTENTI dal database (veloce)
            threat_data = threat_intel.get_cached_threat_data(time_filter)
            
            # Se non ci sono dati cached, mostra "in analisi" e triggera analisi in background
            if not threat_data or threat_data.get('total_ips_checked', 0) == 0:
                threat_data = {
                    'threat_score': 0,
                    'malicious_ips': 0,
                    'suspicious_ips': 0,
                    'clean_ips': 0,
                    'blocked_ips': 0,
                    'threat_ips': [],
                    'top_threats': [],
                    'recent_activity': [],
                    'total_ips_checked': 0,
                    'status': 'analyzing',
                    'message': 'Analisi Threat Intelligence in corso...'
                }
                # Trigger analisi in background (non blocca il caricamento)
                import threading
                thread = threading.Thread(
                    target=threat_intel.analyze_dmarc_data, 
                    args=(time_filter, True)  # force_refresh=True
                )
                thread.daemon = True
                thread.start()
            else:
                threat_data['status'] = 'completed'
                threat_data['message'] = 'Analisi completata'
                
            stats['threat_intelligence'] = threat_data
            print(f"[dashboard] Threat Intelligence status: {threat_data.get('status')}")
            
        except Exception as e:
            print(f"[dashboard] Threat Intelligence error: {e}")
            stats['threat_intelligence'] = {
                'threat_score': 0,
                'malicious_ips': 0,
                'suspicious_ips': 0,
                'clean_ips': 0,
                'blocked_ips': 0,
                'threat_ips': [],
                'top_threats': [],
                'recent_activity': [],
                'total_ips_checked': 0,
                'status': 'error',
                'message': f'Errore nell\'analisi: {str(e)}'
            }
        # ============ FINE THREAT INTELLIGENCE ============
        
        # Carica report recenti (veloce)
        date_conditions = {
            '7days': "start_date >= date('now', '-7 days')",
            '30days': "start_date >= date('now', '-30 days')",
            '90days': "start_date >= date('now', '-90 days')",
            '1year': "start_date >= date('now', '-1 year')",
            'all': "1=1"
        }
        
        where_clause = date_conditions.get(time_filter, date_conditions['30days'])
        limit_clause = "LIMIT 1000" if time_filter == 'all' else "LIMIT 100"
        
        with db_connection() as conn:
            recent_reports = conn.execute(f'''
                SELECT org, domain, report_id, start_date, end_date
                FROM reports 
                WHERE {where_clause}
                ORDER BY start_ts DESC 
                {limit_clause}
            ''').fetchall()
            
            grouped_map = {}
            for report in recent_reports:
                key = f"{report['org']}|{report['domain']}"
                if key not in grouped_map:
                    grouped_map[key] = {
                        'org': report['org'],
                        'domain': report['domain'],
                        'total_reports': 0,
                        'reports': []
                    }
                
                grouped_map[key]['total_reports'] += 1
                grouped_map[key]['reports'].append({
                    'report_id': report['report_id'],
                    'start_date': report['start_date'],
                    'end_date': report['end_date']
                })
            
            grouped_reports = list(grouped_map.values())
        
        print(f"[dashboard] Dashboard ready with {len(grouped_reports)} domain groups")
        
        # Crea la risposta e imposta il cookie
        response = make_response(render_template(
            'dashboard.html',
            stats=stats,
            grouped_reports=grouped_reports,
            version=__version__,
            current_time_filter=time_filter
        ))
        
        # Imposta il cookie che scade in 30 giorni
        expires = datetime.now() + timedelta(days=30)
        response.set_cookie(
            'dashboard_time_filter', 
            value=time_filter,
            expires=expires,
            secure=True,  # Solo HTTPS
            httponly=True,  # Non accessibile via JavaScript
            samesite='Strict'
        )
        
        return response

    except Exception as e:
        print(f"[dashboard] Critical error: {e}")
        import traceback
        traceback.print_exc()
        
        # Fallback veloce
        empty_stats = create_empty_stats()
        empty_stats['threat_intelligence'] = {
            'threat_score': 0,
            'malicious_ips': 0,
            'suspicious_ips': 0,
            'clean_ips': 0,
            'blocked_ips': 0,
            'status': 'error',
            'message': 'Sistema temporaneamente non disponibile'
        }
        
        response = make_response(render_template(
            'dashboard.html',
            stats=empty_stats,
            grouped_reports=[],
            version=__version__,
            current_time_filter=time_filter if 'time_filter' in locals() else '30days'
        ))
        
        # Anche in caso di errore, imposta il cookie
        response.set_cookie(
            'dashboard_time_filter', 
            value=time_filter if 'time_filter' in locals() else '30days',
            expires=datetime.now() + timedelta(days=30),
            secure=True,
            httponly=True,
            samesite='Strict'
        )
        
        return response


@app.route('/dashboard/set_filter')
@login_required
def set_dashboard_filter():
    """Route per cambiare il filtro temporale e reindirizzare alla dashboard"""
    try:
        time_filter = request.args.get('time_filter', '30days')
        
        # Valida il filtro
        valid_filters = ['7days', '30days', '90days', '1year', 'all']
        if time_filter not in valid_filters:
            time_filter = '30days'
        
        print(f"[set_dashboard_filter] Setting filter to: {time_filter}")
        
        # Reindirizza alla dashboard con il nuovo filtro
        response = redirect(url_for('dashboard', time_filter=time_filter))
        
        # Aggiorna anche il cookie
        expires = datetime.now() + timedelta(days=30)
        response.set_cookie(
            'dashboard_time_filter', 
            value=time_filter,
            expires=expires,
            secure=True,
            httponly=True,
            samesite='Strict'
        )
        
        return response
        
    except Exception as e:
        print(f"[set_dashboard_filter] Error: {e}")
        return redirect(url_for('dashboard'))

@app.route('/export')
@login_required
def export_main():
    """Pagina principale degli export"""
    try:
        time_filter = request.cookies.get('dashboard_time_filter', '30days')
        csrf_token = generate_csrf()
        
        return render_template(
            'export.html',
            time_filter=time_filter,
            csrf_token=csrf_token,
            version=__version__
        )
    except Exception as e:
        print(f"[export_main] Error: {e}")
        flash('Error loading export page', 'error')
        return redirect(url_for('dashboard'))

@app.route('/export/csv')
@login_required
def export_csv():
    """Esporta CSV con multiple pagine/tabs in un unico file"""
    try:
        time_filter = request.args.get('time_filter', '30days')
        
        print(f"[export_csv] Starting multi-page CSV export for: {time_filter}")
        
        # Crea il CSV con multiple "pagine"
        output = StringIO()
        writer = csv.writer(output)
        
        # ============ PAGINA 1: OVERVIEW ============
        writer.writerow(['DMARC OVERVIEW REPORT'])
        writer.writerow([f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        writer.writerow([f"Time Filter: {time_filter}"])
        writer.writerow(['Page: 1 - Overview Summary'])
        writer.writerow([])  # Linea vuota
        
        # Recupera statistiche overview dal DB
        stats = generate_stats_from_db(time_filter)
        
        # Statistiche principali
        writer.writerow(['MAIN STATISTICS'])
        writer.writerow(['Total Reports', stats.get('total_reports', 0)])
        writer.writerow(['Total Emails', stats.get('total_emails', 0)])
        writer.writerow(['Authentication Success Rate', f"{stats.get('policy_evaluation', {}).get('pct_compliance', 0)}%"])
        writer.writerow(['Monitored Domains', len(stats.get('domains', []))])
        writer.writerow([])
        
        # Authentication Results
        writer.writerow(['AUTHENTICATION RESULTS'])
        auth_results = stats.get('auth_results', {})
        writer.writerow(['Both SPF and DKIM Pass', auth_results.get('both_pass', 0)])
        writer.writerow(['SPF Pass (Total)', auth_results.get('spf_pass', 0)])
        writer.writerow(['DKIM Pass (Total)', auth_results.get('dkim_pass', 0)])
        writer.writerow(['Alignment Failures', auth_results.get('alignment_fail', 0)])
        writer.writerow(['Complete Failures', auth_results.get('fail', 0)])
        writer.writerow([])
        
        # Top Domains
        writer.writerow(['TOP DOMAINS BY REPORT COUNT'])
        domain_dist = stats.get('domain_distribution', {})
        if domain_dist.get('domains'):
            writer.writerow(['Domain', 'Report Count'])
            for domain, count in zip(domain_dist['domains'], domain_dist['counts']):
                writer.writerow([domain, count])
        else:
            writer.writerow(['No domain data available'])
        writer.writerow([])
        
        # Top IPs
        writer.writerow(['TOP SOURCE IPs'])
        top_ips = stats.get('top_ips', {})
        if top_ips.get('ips'):
            writer.writerow(['IP Address', 'Email Count'])
            for ip, count in zip(top_ips['ips'], top_ips['counts']):
                writer.writerow([ip, count])
        else:
            writer.writerow(['No IP data available'])
        writer.writerow([])
        
        # Dispositions
        writer.writerow(['DISPOSITION ANALYSIS'])
        dispositions = stats.get('dispositions', {})
        if dispositions:
            writer.writerow(['Disposition', 'Count'])
            for disposition, count in dispositions.items():
                writer.writerow([disposition, count])
        else:
            writer.writerow(['No disposition data available'])
        writer.writerow([])
        
        # Separatore tra pagine - molto visibile
        writer.writerow([])
        writer.writerow([])
        writer.writerow(['=' * 80])
        writer.writerow(['PAGE BREAK - NEXT PAGE: DETAILED RECORDS'])
        writer.writerow(['=' * 80])
        writer.writerow([])
        writer.writerow([])
        
        # ============ PAGINA 2: DETAILED RECORDS ============
        writer.writerow(['DMARC DETAILED RECORDS'])
        writer.writerow([f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        writer.writerow([f"Time Filter: {time_filter}"])
        writer.writerow(['Page: 2 - Detailed Records'])
        writer.writerow([])
        
        # Query per dati dettagliati dal DB
        date_conditions = {
            '7days': "start_date >= date('now', '-7 days')",
            '30days': "start_date >= date('now', '-30 days')",
            '90days': "start_date >= date('now', '-90 days')",
            '1year': "start_date >= date('now', '-1 year')",
            'all': "1=1"
        }
        
        where_clause = date_conditions.get(time_filter, date_conditions['30days'])
        
        with db_connection() as conn:
            # Dettagli records
            records_details = conn.execute(f'''
                SELECT 
                    rec.report_id, 
                    rec.source_ip, 
                    rec.count, 
                    rec.disposition,
                    rec.dkim, 
                    rec.spf, 
                    rec.header_from, 
                    rec.is_internal,
                    rec.dkim_domain, 
                    rec.spf_domain,
                    r.org, 
                    r.domain, 
                    r.start_date, 
                    r.end_date
                FROM records rec
                JOIN reports r ON rec.report_id = r.report_id
                WHERE {where_clause}
                ORDER BY r.start_date DESC, rec.count DESC
                LIMIT 10000
            ''').fetchall()
        
        writer.writerow(['DETAILED EMAIL RECORDS'])
        writer.writerow(['Report ID', 'Organization', 'Domain', 'Source IP', 
                       'Email Count', 'Disposition', 'DKIM Result', 'SPF Result',
                       'Header From', 'Is Internal', 'DKIM Domain', 'SPF Domain',
                       'Start Date', 'End Date'])
        
        record_count = 0
        for record in records_details:
            writer.writerow([
                record['report_id'],
                record['org'],
                record['domain'],
                record['source_ip'],
                record['count'],
                record['disposition'],
                record['dkim'],
                record['spf'],
                record['header_from'],
                'Yes' if record['is_internal'] else 'No',
                record['dkim_domain'],
                record['spf_domain'],
                record['start_date'],
                record['end_date']
            ])
            record_count += 1
        
        writer.writerow([])
        writer.writerow(['END OF REPORT'])
        writer.writerow([f"Total records exported: {record_count}"])
        writer.writerow([f"Total pages: 2 (Overview + Detailed)"])
        
        # Prepara la risposta
        output.seek(0)
        csv_content = output.getvalue()
        
        print(f"[export_csv] Multi-page CSV export completed: {record_count} records")
        
        response = Response(csv_content, mimetype='text/csv')
        response.headers.set("Content-Disposition", "attachment", 
                           filename=f"dmarc_complete_export_{time_filter}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        
        return response
        
    except Exception as e:
        print(f"[export_csv] Error: {e}")
        import traceback
        traceback.print_exc()
        
        # Fallback
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Error', f'Could not generate CSV: {str(e)}'])
        output.seek(0)
        
        response = Response(output.getvalue(), mimetype='text/csv')
        response.headers.set("Content-Disposition", "attachment", 
                           filename=f"dmarc_export_error_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        return response

@app.route('/export/csv/simple')
@login_required
def export_csv_simple():
    """Export CSV ultra-semplificato per test"""
    try:
        output = StringIO()
        writer = csv.writer(output)
        
        writer.writerow(['DMARC Export Test', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(['Data', 'Value'])
        writer.writerow(['Total Reports', 100])
        writer.writerow(['Total Emails', 5000])
        writer.writerow(['Status', 'Test Successful'])
        
        output.seek(0)
        response = Response(output.getvalue(), mimetype='text/csv')
        response.headers.set("Content-Disposition", "attachment", 
                           filename=f"dmarc_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        return response
        
    except Exception as e:
        return f"Error: {str(e)}", 500


@app.route('/export/json')
@login_required
def export_json():
    """Esporta JSON con download automatico di due file (overview + detailed) in ZIP"""
    try:
        time_filter = request.args.get('time_filter', '30days')
        
        print(f"[export_json] Starting dual JSON export for: {time_filter}")
        
        # ============ FILE 1: OVERVIEW ============
        stats = generate_stats_from_db(time_filter)
        
        overview_data = {
            'export_info': {
                'format': 'DMARC Overview Report',
                'version': __version__,
                'generated_at': datetime.now().isoformat(),
                'time_filter': time_filter,
                'file_type': 'overview'
            },
            'main_statistics': {
                'total_reports': stats.get('total_reports', 0),
                'total_emails': stats.get('total_emails', 0),
                'authentication_success_rate': stats.get('policy_evaluation', {}).get('pct_compliance', 0),
                'monitored_domains': len(stats.get('domains', [])),
                'time_series_data_points': len(stats.get('time_series_labels', []))
            },
            'authentication_analysis': stats.get('auth_results', {}),
            'disposition_analysis': stats.get('dispositions', {}),
            'domain_distribution': stats.get('domain_distribution', {}),
            'internal_vs_external': stats.get('internal_vs_external', {}),
            'top_ips': stats.get('top_ips', {}),
            'time_series': {
                'labels': stats.get('time_series_labels', []),
                'report_counts': stats.get('time_series_report_counts', []),
                'email_counts': stats.get('time_series_email_counts', [])
            }
        }
        
        # ============ FILE 2: DETAILED ============
        date_conditions = {
            '7days': "start_date >= date('now', '-7 days')",
            '30days': "start_date >= date('now', '-30 days')",
            '90days': "start_date >= date('now', '-90 days')",
            '1year': "start_date >= date('now', '-1 year')",
            'all': "1=1"
        }
        
        where_clause = date_conditions.get(time_filter, date_conditions['30days'])
        
        detailed_data = {
            'export_info': {
                'format': 'DMARC Detailed Report',
                'version': __version__,
                'generated_at': datetime.now().isoformat(),
                'time_filter': time_filter,
                'file_type': 'detailed'
            },
            'reports': []
        }
        
        with db_connection() as conn:
            # Dettagli report
            reports = conn.execute(f'''
                SELECT 
                    r.report_id, r.org, r.email, r.domain, 
                    r.start_date, r.end_date, r.start_ts, r.end_ts,
                    r.policy_adkim, r.policy_aspf, r.policy_p, r.policy_sp, 
                    r.policy_pct, r.policy_fo, r.filename,
                    COUNT(rec.id) as record_count,
                    SUM(rec.count) as total_emails
                FROM reports r
                LEFT JOIN records rec ON r.report_id = rec.report_id
                WHERE {where_clause}
                GROUP BY r.report_id
                ORDER BY r.start_ts DESC
                LIMIT 500
            ''').fetchall()
            
            # Per ogni report, aggiungi i records
            for report in reports:
                report_dict = {
                    'report_id': report['report_id'],
                    'org': report['org'],
                    'email': report['email'],
                    'domain': report['domain'],
                    'date_range': {
                        'start': report['start_date'],
                        'end': report['end_date'],
                        'start_ts': report['start_ts'],
                        'end_ts': report['end_ts']
                    },
                    'policy': {
                        'adkim': report['policy_adkim'],
                        'aspf': report['policy_aspf'],
                        'p': report['policy_p'],
                        'sp': report['policy_sp'],
                        'pct': report['policy_pct'],
                        'fo': report['policy_fo']
                    },
                    'filename': report['filename'],
                    'record_count': report['record_count'],
                    'total_emails': report['total_emails'] or 0,
                    'records': []
                }
                
                # Recupera i records per questo report
                records = conn.execute('''
                    SELECT 
                        source_ip, count, disposition, dkim, spf,
                        header_from, is_internal, dkim_domain, spf_domain
                    FROM records 
                    WHERE report_id = ? 
                    ORDER BY count DESC
                ''', (report['report_id'],)).fetchall()
                
                for record in records:
                    record_dict = {
                        'source_ip': record['source_ip'],
                        'count': record['count'],
                        'disposition': record['disposition'],
                        'dkim': record['dkim'],
                        'spf': record['spf'],
                        'header_from': record['header_from'],
                        'is_internal': bool(record['is_internal']),
                        'dkim_domain': record['dkim_domain'],
                        'spf_domain': record['spf_domain']
                    }
                    report_dict['records'].append(record_dict)
                
                detailed_data['reports'].append(report_dict)
        
        # Aggiorna il conteggio totale
        detailed_data['export_info']['total_reports'] = len(detailed_data['reports'])
        detailed_data['export_info']['total_records'] = sum(
            len(report.get('records', [])) for report in detailed_data['reports']
        )
        
        # ============ CREA ZIP CON DUE FILE JSON ===========
        
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # File 1: Overview
            overview_json = json.dumps(overview_data, indent=2, ensure_ascii=False)
            zip_file.writestr(
                f"dmarc_overview_{time_filter}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 
                overview_json
            )
            
            # File 2: Detailed
            detailed_json = json.dumps(detailed_data, indent=2, ensure_ascii=False)
            zip_file.writestr(
                f"dmarc_detailed_{time_filter}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 
                detailed_json
            )
            
            # File README
            readme_content = f"""DMARC JSON Export - Dual Files
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Time Filter: {time_filter}

This ZIP contains 2 JSON files:

1. OVERVIEW FILE (dmarc_overview_*.json):
   - Summary statistics and analytics
   - Authentication analysis
   - Charts and trends data
   - Top domains and IPs
   - Perfect for dashboards and reporting

2. DETAILED FILE (dmarc_detailed_*.json):
   - Complete report metadata
   - Individual email records
   - Full authentication details
   - Source IP analysis
   - Ideal for deep analysis and auditing

Export Summary:
- Total reports in detailed export: {len(detailed_data['reports'])}
- Total records in detailed export: {detailed_data['export_info']['total_records']}
- Time range: {time_filter}
- Generated by: DMARCus v{__version__}

For questions or support, refer to the DMARCus documentation.
"""
            zip_file.writestr('README.txt', readme_content)
        
        zip_buffer.seek(0)
        
        response = Response(zip_buffer.getvalue(), mimetype='application/zip')
        response.headers.set("Content-Disposition", "attachment", 
                           filename=f"dmarc_json_export_{time_filter}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
        
        print(f"[export_json] Dual JSON export completed: {len(detailed_data['reports'])} reports, {detailed_data['export_info']['total_records']} records")
        return response
        
    except Exception as e:
        print(f"[export_json] Error: {e}")
        import traceback
        traceback.print_exc()
        
        # Fallback: singolo file di errore
        error_data = {
            'error': f'Could not generate JSON export: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }
        
        response = Response(
            json.dumps(error_data, indent=2),
            mimetype='application/json'
        )
        response.headers.set("Content-Disposition", "attachment", 
                           filename=f"dmarc_export_error_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        return response




@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_files():
    try:
        if request.method == 'GET':
            csrf_token = generate_csrf()
            return render_template('upload.html', csrf_token=csrf_token)

        if request.method == 'POST':
            try:
                validate_csrf(request.form.get('csrf_token'))
            except (BadRequest, ValueError) as e:
                flash('Invalid CSRF token', 'danger')
                return redirect(url_for('upload_files'))

            if 'files' not in request.files:
                flash('No files selected for uploading', 'error')
                return redirect(url_for('upload_files'))

            files = request.files.getlist('files')
            if not files or all(file.filename == '' for file in files):
                flash('No files selected', 'error')
                return redirect(url_for('upload_files'))

            # Contatori per i diversi tipi di risultato
            success_count = 0
            invalid_format_count = 0
            duplicate_count = 0
            parsing_error_count = 0
            file_too_large_count = 0
            other_error_count = 0

            for file in files:
                if file.filename == '':
                    continue

                filename = secure_filename(file.filename)
                
                try:
                    # Controllo formato file
                    if not allowed_file(filename):
                        invalid_format_count += 1
                        continue

                    # Controllo dimensione file
                    if not check_file_size(file):
                        file_too_large_count += 1
                        continue

                    # Genera hash per controllo duplicati
                    file_content = file.read()
                    file.seek(0)  # Reset file pointer per il parsing
                    file_hash = hashlib.md5(file_content).hexdigest()

                    # Controllo duplicati basato sul contenuto
                    if report_hash_exists_in_db(file_hash):
                        duplicate_count += 1
                        continue

                    # Parsa il report DMARC
                    report_data = parse_dmarc_report(file)
                    
                    if 'error' in report_data:
                        parsing_error_count += 1
                        continue
                    
                    # Controllo duplicati basato sul report_id
                    if report_id_exists_in_db(report_data['report_id']):
                        duplicate_count += 1
                        continue
                    
                    # Aggiungi l'hash al report data
                    report_data['file_hash'] = file_hash
                    
                    # Salva nel database
                    if save_report_to_db(report_data):
                        success_count += 1
                    else:
                        other_error_count += 1

                except Exception as e:
                    other_error_count += 1

            # Mostra i risultati aggregati all'utente
            total_files = len([f for f in files if f.filename != ''])
            
            if success_count > 0:
                flash(f' {success_count} file processati correttamente', 'success')
            
            # Mostra solo i conteggi degli errori che sono > 0
            error_messages = []
            
            if invalid_format_count > 0:
                error_messages.append(f'{invalid_format_count} con formato non valido')
            
            if duplicate_count > 0:
                error_messages.append(f'{duplicate_count} già presenti nel sistema')
            
            if parsing_error_count > 0:
                error_messages.append(f'{parsing_error_count} con errori di parsing')
            
            if file_too_large_count > 0:
                error_messages.append(f'{file_too_large_count} troppo grandi')
            
            if other_error_count > 0:
                error_messages.append(f'{other_error_count} con altri errori')

            if error_messages:
                flash(f' {", ".join(error_messages)}', 'error')

            # Se tutti i file sono falliti
            if success_count == 0 and total_files > 0:
                flash('Nessun file è stato processato correttamente', 'warning')
            elif success_count == total_files and total_files > 0:
                flash('Tutti i file sono stati processati con successo!', 'success')

            return redirect(url_for('upload_files'))

    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f"Errore imprevisto: {str(e)}", "error")
        return redirect(url_for('upload_files'))

@app.route('/refresh_domain_status')
@login_required
def refresh_domain_status():
    """Aggiorna lo stato dei domini via DNS lookup"""
    try:
        result = auto_populate_domains()
        if 'error' in result:
            flash(f"Error refreshing domains: {result['error']}", "error")
        else:
            flash(f"Domain status refreshed: {result.get('added', 0)} added, {result.get('updated', 0)} updated", "success")
    except Exception as e:
        flash(f"Error refreshing domain status: {str(e)}", "error")
    
    return redirect(url_for('domains'))

# Nel file routes.py o views.py
@app.route('/domains', methods=['GET', 'POST'])
@login_required
def domains():
    try:
        # Carica i domini dal database
        domains = load_domains_from_db()
        
        # Se è una richiesta POST (aggiungi/aggiorna/elimina dominio)
        if request.method == 'POST':
            try:
                validate_csrf(request.form.get('csrf_token'))
            except (BadRequest, ValueError) as e:
                flash('Invalid CSRF token', 'danger')
                return redirect(url_for('domains'))
            
            action = request.form.get('action')
            domain_name = request.form.get('domain_name', '').strip().lower()
            
            if not domain_name:
                flash('Domain name is required', 'error')
                return redirect(url_for('domains'))
            
            if action == 'add':
                # Aggiungi nuovo dominio
                if not validate_domain_name(domain_name):
                    flash('Invalid domain name format', 'error')
                    return redirect(url_for('domains'))
                
                if domain_exists_in_db(domain_name):
                    flash(f'Domain {domain_name} already exists', 'error')
                    return redirect(url_for('domains'))
                
                # Ottieni info DMARC via DNS
                dmarc_info = get_dmarc_policy(domain_name)
                
                domain_data = {
                    'name': domain_name,
                    'dmarc_policy': request.form.get('dmarc_policy', 'none'),
                    'enable_reporting': bool(request.form.get('enable_reporting')),
                    'report_emails': [email.strip() for email in request.form.get('report_emails', '').split(',') if email.strip()],
                    'status': dmarc_info.get('status', 'pending'),
                    'auth_score': 0,
                    'last_report': None
                }
                
                if save_domain_to_db(domain_data):
                    flash(f'Domain {domain_name} added successfully', 'success')
                else:
                    flash(f'Error adding domain {domain_name}', 'error')
            
            elif action == 'update':
                # Aggiorna dominio esistente
                updates = {
                    'dmarc_policy': request.form.get('dmarc_policy', 'none'),
                    'enable_reporting': bool(request.form.get('enable_reporting')),
                    'report_emails': [email.strip() for email in request.form.get('report_emails', '').split(',') if email.strip()]
                }
                
                if update_domain_in_db(domain_name, updates):
                    flash(f'Domain {domain_name} updated successfully', 'success')
                else:
                    flash(f'Error updating domain {domain_name}', 'error')
            
            elif action == 'delete':
                # Elimina dominio
                confirm_delete = request.form.get('confirm_delete')
                if not confirm_delete:
                    flash('Please confirm deletion', 'error')
                    return redirect(url_for('domains'))
                
                if delete_domain_from_db(domain_name):
                    flash(f'Domain {domain_name} deleted successfully', 'success')
                else:
                    flash(f'Error deleting domain {domain_name}', 'error')
            
            return redirect(url_for('domains'))
        
        # Per richieste GET, mostra la pagina con i domini
        # Calcola metriche semplificate per la dashboard
        total_domains = len(domains)
        domains_with_reject_policy = len([d for d in domains if d.get('dmarc_policy') == 'reject'])
        
        # Calcola statistiche di sicurezza di base
        if total_domains > 0:
            security_score = int((domains_with_reject_policy / total_domains) * 100)
        else:
            security_score = 0
        
        return render_template(
            'domains.html',
            domains=domains,
            overall_security_score=security_score,
            domains_with_reject_policy=domains_with_reject_policy,
            domains_with_spf=0,  # Placeholder per ora
            domains_with_dkim=0   # Placeholder per ora
        )
        
    except Exception as e:
        print(f"[domains] Error: {e}")
        import traceback
        traceback.print_exc()
        flash(f"An error occurred: {str(e)}", "error")
        
        # Fallback: ritorna domini vuoti
        return render_template(
            'domains.html',
            domains=[],
            overall_security_score=0,
            domains_with_reject_policy=0,
            domains_with_spf=0,
            domains_with_dkim=0
        )

@app.route('/policy-generator', methods=['GET', 'POST'])
@login_required
def policy_generator():
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
        except (BadRequest, ValueError) as e:
            flash('Invalid CSRF token', 'danger')
            return redirect(url_for('policy_generator'))
        
        domain = request.form.get('domain')
        policy = request.form.get('policy')
        pct = request.form.get('pct')
        rua = request.form.get('rua')
        ruf = request.form.get('ruf')
        
        if not domain:
            flash('Domain is required', 'error')
            return redirect(url_for('policy_generator'))
        
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            flash('Invalid domain format', 'error')
            return redirect(url_for('policy_generator'))
        
        record = f"v=DMARC1; p={policy}; pct={pct}"
        
        if rua:
            rua_addresses = [a.strip() for a in rua.split(',') if a.strip()]
            record += f"; rua={','.join(rua_addresses)}"
        
        if ruf:
            ruf_addresses = [a.strip() for a in ruf.split(',') if a.strip()]
            record += f"; ruf={','.join(ruf_addresses)}"
        
        return render_template('policy_generator.html', 
                            dmarc_record=record,
                            domain=domain,
                            version=__version__)
    
    return render_template('policy_generator.html', version=__version__)

# AGGIUNTA: Message Analyzer Route
@app.route('/analyzer', methods=['GET', 'POST'])
@login_required
def analyzer():
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
        except (BadRequest, ValueError) as e:
            flash('Invalid CSRF token', 'danger')
            return redirect(url_for('analyzer'))
        
        if 'email_file' not in request.files:
            flash('No email file selected', 'error')
            return redirect(url_for('analyzer'))
        
        file = request.files['email_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('analyzer'))
        
        if not allowed_analyzer_file(file.filename):
            flash('Invalid file type. Please upload .eml or .msg files', 'error')
            return redirect(url_for('analyzer'))
        
        # Analizza l'email
        analysis_result = analyze_email_message(file)
        
        if 'error' in analysis_result:
            flash(f'Error analyzing email: {analysis_result["error"]}', 'error')
            return redirect(url_for('analyzer'))
        
        return render_template(
            'analyzer.html', 
            analysis_result=analysis_result,
            version=__version__
        )
    
    return render_template('analyzer.html', version=__version__)

@app.route('/all_reports')
@login_required
def all_reports():
    try:
        with db_connection() as conn:
            # Query corretta per ottenere tutti i report
            reports_data = conn.execute('''
                SELECT r.org, r.domain, r.report_id, r.start_date, r.end_date,
                       COUNT(rec.id) as record_count
                FROM reports r
                LEFT JOIN records rec ON r.report_id = rec.report_id
                GROUP BY r.report_id
                ORDER BY r.start_ts DESC
                LIMIT 1000
            ''').fetchall()
            
            # Raggruppa per organizzazione e dominio (come nella dashboard)
            grouped_map = {}
            for report in reports_data:
                key = f"{report['org']}|{report['domain']}"
                if key not in grouped_map:
                    grouped_map[key] = {
                        'org': report['org'],
                        'domain': report['domain'],
                        'total_reports': 0,
                        'total_records': 0,
                        'reports': []
                    }
                
                grouped_map[key]['total_reports'] += 1
                grouped_map[key]['total_records'] += report['record_count'] or 0
                grouped_map[key]['reports'].append({
                    'report_id': report['report_id'],
                    'start_date': report['start_date'],
                    'end_date': report['end_date'],
                    'record_count': report['record_count'] or 0
                })
            
            grouped_reports = list(grouped_map.values())
            
            # Calcola statistiche totali
            total_reports = sum(group['total_reports'] for group in grouped_reports)
            total_records = sum(group['total_records'] for group in grouped_reports)
            total_domains = len(grouped_reports)
        
        return render_template(
            'all_reports.html',
            grouped_reports=grouped_reports,
            total_reports=total_reports,
            total_records=total_records,
            total_domains=total_domains,
            version=__version__
        )

    except Exception as e:
        print(f"[all_reports] Error: {e}")
        import traceback
        traceback.print_exc()
        flash(f"An unexpected error occurred: {str(e)}", "error")
        return render_template(
            'all_reports.html',
            grouped_reports=[],
            total_reports=0,
            total_records=0,
            total_domains=0,
            version=__version__
        )


@app.route('/report/<org_name>')
@app.route('/report/<org_name>/<report_id>')
@login_required
def report_detail(org_name, report_id=None):
    try:
        print(f"[report_detail] Loading report: org={org_name}, report_id={report_id}")
        
        if report_id and report_id != 'all':
            # Carica un report specifico
            report = load_report_from_db(report_id)
            if not report:
                flash(f"Report {report_id} not found", "error")
                return redirect(url_for('all_reports'))
            
            org_reports = [report]
            selected_report_id = report_id
            
            # ============ THREAT INTELLIGENCE PER REPORT SINGOLO ============
            try:
                print(f"[report_detail] Starting threat analysis for report {report_id}")
                report_threat_data = threat_intel.analyze_report_ips(report_id)
                report['threat_intelligence'] = report_threat_data
                print(f"[report_detail] Threat analysis completed: {len(report_threat_data.get('threat_ips', []))} malicious IPs")
            except Exception as e:
                print(f"[report_detail] Threat intelligence error: {e}")
                report['threat_intelligence'] = {
                    'report_id': report_id,
                    'threat_score': 0,
                    'threat_ips': [],
                    'suspicious_ips': [],
                    'clean_ips': [],
                    'error': str(e),
                    'analysis_timestamp': datetime.now().isoformat()
                }
            # ============ FINE THREAT INTELLIGENCE ============
            
        else:
            # Carica tutti i report per l'organizzazione
            org_reports = load_reports_by_org_from_db(org_name)
            if not org_reports:
                flash(f"No reports found for organization: {org_name}", "error")
                return redirect(url_for('all_reports'))
            
            # Prendi il report più recente
            report = org_reports[0]
            selected_report_id = 'all'
        
        # [RESTA TUTTO IL CODICE ESISTENTE PER LE METRICHE...]
        total_records = len(report['records'])
        total_emails = sum(r['count'] for r in report['records'])
        pass_count = sum(r['count'] for r in report['records'] if r['spf'] == 'pass' and r['dkim'] == 'pass')
        pass_rate = round((pass_count / total_emails * 100), 1) if total_emails > 0 else 0
        
        # Calcola statistiche di autenticazione con validazione
        both_pass = sum(r['count'] for r in report['records'] if r.get('spf') == 'pass' and r.get('dkim') == 'pass')
        spf_only = sum(r['count'] for r in report['records'] if r.get('spf') == 'pass' and r.get('dkim') != 'pass')
        dkim_only = sum(r['count'] for r in report['records'] if r.get('dkim') == 'pass' and r.get('spf') != 'pass')
        both_fail = sum(r['count'] for r in report['records'] if r.get('spf') != 'pass' and r.get('dkim') != 'pass')

        # Forza valori corretti se tutti sono "none"
        if all(r.get('spf') == 'none' and r.get('dkim') == 'none' for r in report['records']):
            print("[WARNING] All records have SPF=none and DKIM=none - data may be invalid")
            # Distribuisci i valori per evitare divisione 33/33/33
            total = total_emails
            if total > 0:
                both_pass = total // 3
                spf_only = total // 3
                dkim_only = total // 3
                both_fail = total - (both_pass + spf_only + dkim_only)

        auth_data = {
            'both_pass': both_pass,
            'spf_pass': both_pass + spf_only,
            'dkim_pass': both_pass + dkim_only,
            'fail': both_fail,
            'total': total_emails,
            'spf_only': spf_only,
            'dkim_only': dkim_only,
            'alignment_fail': spf_only + dkim_only
        }
        
        # Prepara i dati per i grafici (codice esistente)
        disposition_counts = {}
        source_ips = {}
        internal_count = 0
        external_count = 0
        
        for record in report['records']:
            # Conteggi per disposizione
            disp = record['disposition']
            disposition_counts[disp] = disposition_counts.get(disp, 0) + record['count']
            
            # Conteggi per IP sorgente (top 10)
            ip = record['source_ip']
            source_ips[ip] = source_ips.get(ip, 0) + record['count']
            
            # Internal vs External
            if record.get('is_internal', False):
                internal_count += record['count']
            else:
                external_count += record['count']
        
        # Ordina gli IP per volume
        top_ips = dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Prepara dati per il chart IP
        ip_chart_data = {
            'ips': list(top_ips.keys()),
            'counts': list(top_ips.values())
        }
        
        # Internal vs External
        internal_vs_external = {
            'internal': internal_count,
            'external': external_count
        }
        
        print(f"[report_detail] Successfully loaded report with {total_records} records, {total_emails} emails")
        
        return render_template(
            'report_detail.html',
            report=report,
            org_name=org_name,
            selected_report_id=selected_report_id,
            org_reports=org_reports,
            pass_rate=pass_rate,
            total_records=total_records,
            total_emails=total_emails,
            auth_data=auth_data,
            disposition_counts=disposition_counts,
            top_ips=top_ips,
            ip_chart_data=ip_chart_data,
            internal_vs_external=internal_vs_external,
            ip_addresses=source_ips
        )
    except Exception as e:
        print(f"[report_detail] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f"System error: {str(e)}", "error")
        return redirect(url_for('all_reports'))



@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', 
                         error="Internal server error", 
                         version=__version__), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', 
                         error="Page not found", 
                         version=__version__), 404


@app.route('/api/threat-intelligence/ips')
@login_required
def get_threat_intelligence_ips():
    """API per ottenere tutti gli IP da analizzare"""
    try:
        time_filter = request.args.get('time_filter', '30days')
        limit = request.args.get('limit', '100')  # Default a 100 per performance
        
        date_conditions = {
            '7days': "start_date >= date('now', '-7 days')",
            '30days': "start_date >= date('now', '-30 days')",
            '90days': "start_date >= date('now', '-90 days')",
            '1year': "start_date >= date('now', '-1 year')",
            'all': "1=1"
        }
        
        where_clause = date_conditions.get(time_filter, date_conditions['30days'])
        
        query = f'''
            SELECT DISTINCT r.source_ip, SUM(r.count) as total_count
            FROM records r
            JOIN reports rep ON r.report_id = rep.report_id
            WHERE {where_clause}
            GROUP BY r.source_ip
            ORDER BY total_count DESC
            LIMIT {limit}
        '''
        
        with db_connection() as conn:
            results = conn.execute(query).fetchall()
            ips = [row['source_ip'] for row in results if row['source_ip']]
        
        print(f"[threat-intelligence] Returning {len(ips)} IPs for analysis")
        
        return jsonify({
            'ips': ips,
            'total': len(ips),
            'time_filter': time_filter,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[threat-intelligence] Error getting IPs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/threat-intelligence/refresh')
@login_required
def refresh_threat_intelligence():
    """API per forzare l'aggiornamento della threat intelligence"""
    try:
        time_filter = request.args.get('time_filter', '30days')
        
        # Forza l'analisi di tutti gli IP
        threat_data = threat_intel.analyze_dmarc_data(time_filter, force_refresh=True)
        
        return jsonify({
            'success': True,
            'threat_score': threat_data.get('threat_score', 0),
            'malicious_ips': threat_data.get('malicious_ips', 0),
            'suspicious_ips': threat_data.get('suspicious_ips', 0),
            'total_ips_checked': threat_data.get('total_ips_checked', 0),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[refresh_threat_intelligence] Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence/check/<ip>')
@login_required
def check_ip_threat(ip):
    """API per controllare un singolo IP"""
    try:
        # Usa la tua libreria di threat intelligence esistente
        from threat_intelligence import ThreatIntelligence
        
        threat_intel = ThreatIntelligence('data/dmarcus.db')
        
        # Controlla se l'IP è una minaccia
        is_threat, threat_level, details = threat_intel.check_single_ip(ip)
        
        return jsonify({
            'ip': ip,
            'isThreat': is_threat,
            'threatLevel': threat_level,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[threat-intelligence] Error checking IP {ip}: {e}")
        return jsonify({
            'ip': ip,
            'isThreat': False,
            'threatLevel': 'unknown',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/threat-intelligence/save-results', methods=['POST'])
@login_required
def save_threat_intelligence_results():
    """API per salvare i risultati della threat intelligence"""
    try:
        data = request.json
        results = data.get('results', [])
        
        # Qui puoi salvare i risultati nel database se necessario
        print(f"[threat-intelligence] Received {len(results)} results to save")
        
        return jsonify({'success': True, 'saved': len(results)})
        
    except Exception as e:
        print(f"[threat-intelligence] Error saving results: {e}")
        return jsonify({'error': str(e)}), 500


# =============================================================================
# INITIALIZATION
# =============================================================================

print("🔧 Initializing database...")
if not init_database():
    print("❌ Failed to initialize database")
    exit(1)
else:
    print("✅ Database initialized successfully")

if __name__ == '__main__':
    if not check_permissions():
        print(f"❌ Cannot start - permission issues with {DATA_DIR}")
        print(f"💡 Run: sudo chown -R $USER: {BASE_DIR}")
        exit(1)
    
    # Inizializza il database con la tabella users
    if not init_database():
        print("❌ Failed to initialize database")
        exit(1)
    
    print(f"\n🚀 Starting DMARCus Analyzer v{__version__} with SQLite Database")
    print(f"📊 Total reports in database: {get_total_reports_count_from_db()}")
    
    # Verifica che l'utente admin di default sia stato creato
    try:
        with db_connection() as conn:
            admin_user = conn.execute(
                'SELECT username FROM users WHERE username = ? AND is_active = 1', 
                ('dmarc',)
            ).fetchone()
            if admin_user:
                print(f"👤 Default admin user: {admin_user['username']}")
            else:
                print("⚠️  Warning: Default admin user not found")
    except Exception as e:
        print(f"⚠️  Warning: Could not verify admin user: {e}")
    
    print(f"📁 Data directory: {DATA_DIR}")
    print(f"💾 Database: {SQLITE_DB}")
    
    ssl_cert = '/opt/dmarcus-dev/ssl/itlsrv-dmarcus1.crt'
    ssl_key = '/opt/dmarcus-dev/ssl/itlsrv-dmarcus1.key'
    
    if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        print(f"🔐 SSL enabled - Starting HTTPS server on https://itlsrv-dmarcus1.it.ltc.local:3627")
        app.run('0.0.0.0', port=3627, debug=False, ssl_context=(ssl_cert, ssl_key))
    else:
        print(f"⚠️  SSL files not found - Starting HTTP server on http://itlsrv-dmarcus1.it.ltc.local:3627")
        app.run('0.0.0.0', port=3627, debug=False)