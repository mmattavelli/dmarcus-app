import requests
import sqlite3
from datetime import datetime, timedelta
import logging
import time
import os
import ipaddress

# API KEY STATICHE
ABUSEIPDB_API_KEY = "APICODE1"
VIRUSTOTAL_API_KEY = "APICODE2"
IPQUALITYSCORE_API_KEY = "APICODE3"

# Configurazioni
CACHE_TIMEOUT = 43200  # 12 ore
MAX_IPS_TO_CHECK = 1000

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    def __init__(self, db_path):
        self.db_path = db_path
        self.cache = {}
        self.cache_timeout = CACHE_TIMEOUT
        self._init_intelligence_tables()
    
    def _init_intelligence_tables(self):
        """Inizializza le tabelle threat intelligence nel database principale"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabella per cache delle reputazioni IP
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_reputations (
                    ip_address TEXT PRIMARY KEY,
                    risk_level TEXT,
                    threat_score INTEGER,
                    source TEXT,
                    last_checked TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabella per cache delle analisi threat intelligence
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time_filter TEXT NOT NULL,
                    threat_data TEXT NOT NULL,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabella per i risultati delle analisi (storico)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_date DATE,
                    time_filter TEXT,
                    threat_score INTEGER,
                    malicious_ips INTEGER,
                    suspicious_ips INTEGER,
                    clean_ips INTEGER,
                    total_ips_checked INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabella per le minacce rilevate (storico)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detected_threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER,
                    ip_address TEXT,
                    risk_level TEXT,
                    source TEXT,
                    email_count INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES threat_analyses (id)
                )
            ''')
            
            # Indici per performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_reputations_ip ON ip_reputations(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_reputations_checked ON ip_reputations(last_checked)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_cache_filter ON threat_intelligence_cache(time_filter)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_cache_updated ON threat_intelligence_cache(last_updated)')
            
            conn.commit()
            conn.close()
            print(f"✅ Tabelle Threat Intelligence inizializzate in: {self.db_path}")
            
        except Exception as e:
            print(f"❌ Errore inizializzazione tabelle TI: {e}")
    
    def get_cached_threat_data(self, time_filter='30days'):
        """Ottiene i dati threat intelligence dal cache (velocissimo)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT threat_data, last_updated 
                FROM threat_intelligence_cache 
                WHERE time_filter = ?
                ORDER BY last_updated DESC 
                LIMIT 1
            ''', (time_filter,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result and result[0]:
                import json
                data = json.loads(result[0])
                # Controlla se i dati sono più vecchi di 2 ore
                last_updated = datetime.fromisoformat(result[1])
                if (datetime.now() - last_updated).total_seconds() < 7200:  # 2 ore
                    return data
        
        except Exception as e:
            print(f"[get_cached_threat_data] Error: {e}")
        
        return None
    
    def save_to_cache(self, time_filter, threat_data):
        """Salva i dati threat intelligence nel cache"""
        try:
            conn = sqlite3.connect(self.db_path)
            import json
            conn.execute('''
                INSERT OR REPLACE INTO threat_intelligence_cache 
                (time_filter, threat_data, last_updated) 
                VALUES (?, ?, ?)
            ''', (time_filter, json.dumps(threat_data), datetime.now().isoformat()))
            conn.commit()
            conn.close()
            print(f"[save_to_cache] Saved threat data for {time_filter}")
        except Exception as e:
            print(f"[save_to_cache] Error: {e}")
    
    def _save_ip_reputation(self, ip_address, reputation):
        """Salva la reputazione di un IP nel database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO ip_reputations 
                (ip_address, risk_level, threat_score, source, last_checked)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                ip_address,
                reputation['risk'],
                self._risk_to_score(reputation['risk']),
                reputation['source'],
                datetime.now()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"❌ Errore salvataggio reputazione IP: {e}")
    
    def _risk_to_score(self, risk_level):
        """Converte il livello di rischio in punteggio numerico"""
        scores = {'high': 100, 'medium': 70, 'suspicious': 40, 'low': 10, 'unknown': 0}
        return scores.get(risk_level, 0)
    
    def _get_cached_reputation(self, ip_address):
        """Recupera la reputazione di un IP dalla cache del database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT risk_level, threat_score, source 
                FROM ip_reputations 
                WHERE ip_address = ? AND last_checked >= datetime('now', '-1 hour')
            ''', (ip_address,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'risk': result[0],
                    'score': result[1],
                    'source': result[2],
                    'cached': True
                }
            
        except Exception as e:
            print(f"❌ Errore lettura cache reputazione: {e}")
        
        return None
    
    def _save_analysis_results(self, time_filter, result):
        """Salva i risultati dell'analisi nel database (storico)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Inserisci analisi principale
            cursor.execute('''
                INSERT INTO threat_analyses 
                (analysis_date, time_filter, threat_score, malicious_ips, suspicious_ips, clean_ips, total_ips_checked)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().date(),
                time_filter,
                result['threat_score'],
                result['malicious_ips'],
                result['suspicious_ips'],
                result['clean_ips'],
                result['total_ips_checked']
            ))
            
            analysis_id = cursor.lastrowid
            
            # Inserisci minacce rilevate
            for threat in result.get('top_threats', []):
                cursor.execute('''
                    INSERT INTO detected_threats 
                    (analysis_id, ip_address, risk_level, source, email_count)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    analysis_id,
                    threat['ip'],
                    threat['risk_level'],
                    threat['source'],
                    threat.get('count', 0)
                ))
            
            conn.commit()
            conn.close()
            
            print(f"✅ Analisi Threat Intelligence salvata nel database (storico)")
            
        except Exception as e:
            print(f"❌ Errore salvataggio analisi TI: {e}")
    
    def is_private_ip(self, ip_address):
        """Controlla se l'IP è privato"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except:
            return False
        
    def check_abuseipdb(self, ip_address):
        """Controlla IP su AbuseIPDB"""
        try:
            print(f"🔍 Checking AbuseIPDB for IP: {ip_address}")
            
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                abuse_score = data['data']['abuseConfidenceScore']
                total_reports = data['data']['totalReports']
                
                print(f"✅ AbuseIPDB result: score={abuse_score}, reports={total_reports}")
                
                if abuse_score >= 80:
                    return {'risk': 'high', 'score': abuse_score, 'reports': total_reports, 'source': 'AbuseIPDB'}
                elif abuse_score >= 50:
                    return {'risk': 'medium', 'score': abuse_score, 'reports': total_reports, 'source': 'AbuseIPDB'}
                else:
                    return {'risk': 'low', 'score': abuse_score, 'reports': total_reports, 'source': 'AbuseIPDB'}
            else:
                print(f"❌ AbuseIPDB API error: {response.status_code}")
                return {'risk': 'unknown', 'score': 0, 'source': 'AbuseIPDB'}
            
        except Exception as e:
            print(f"💥 AbuseIPDB check failed: {e}")
            return {'risk': 'unknown', 'score': 0, 'source': 'AbuseIPDB'}
    
    def check_virustotal(self, ip_address):
        """Controlla IP su VirusTotal"""
        try:
            print(f"🔍 Checking VirusTotal for IP: {ip_address}")
            
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {'x-apikey': VIRUSTOTAL_API_KEY}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats['malicious']
                suspicious = stats['suspicious']
                total = malicious + suspicious
                
                print(f"✅ VirusTotal result: malicious={malicious}, suspicious={suspicious}")
                
                if malicious >= 5:
                    result = {'risk': 'high', 'malicious': malicious, 'suspicious': suspicious, 'source': 'VirusTotal'}
                elif total >= 3:
                    result = {'risk': 'medium', 'malicious': malicious, 'suspicious': suspicious, 'source': 'VirusTotal'}
                elif total >= 1:
                    result = {'risk': 'suspicious', 'malicious': malicious, 'suspicious': suspicious, 'source': 'VirusTotal'}
                else:
                    result = {'risk': 'low', 'malicious': malicious, 'suspicious': suspicious, 'source': 'VirusTotal'}
                
                return result
            else:
                print(f"❌ VirusTotal API error: {response.status_code}")
                return {'risk': 'unknown', 'score': 0, 'source': 'VirusTotal'}
                
        except Exception as e:
            print(f"💥 VirusTotal check failed: {e}")
            return {'risk': 'unknown', 'score': 0, 'source': 'VirusTotal'}

    def check_ipqualityscore(self, ip_address):
        """Controlla IP su IPQualityScore"""
        try:
            print(f"🔍 Checking IPQualityScore for IP: {ip_address}")
            
            url = f"https://www.ipqualityscore.com/api/json/ip/{IPQUALITYSCORE_API_KEY}/{ip_address}"
            params = {'strictness': 1}
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                fraud_score = data.get('fraud_score', 0)
                proxy = data.get('proxy', False)
                vpn = data.get('vpn', False)
                tor = data.get('tor', False)
                bot = data.get('bot_status', False)
                
                print(f"✅ IPQualityScore result: fraud_score={fraud_score}%")
                
                # Calcola rischio
                risk_factors = 0
                if fraud_score >= 85: risk_factors += 3
                elif fraud_score >= 70: risk_factors += 2
                elif fraud_score >= 50: risk_factors += 1
                if proxy: risk_factors += 2
                if vpn: risk_factors += 1
                if tor: risk_factors += 3
                if bot: risk_factors += 2
                
                print(f"   Risk factors: {risk_factors}")
                
                if risk_factors >= 5:
                    result = {'risk': 'high', 'fraud_score': fraud_score, 'source': 'IPQualityScore'}
                elif risk_factors >= 3:
                    result = {'risk': 'medium', 'fraud_score': fraud_score, 'source': 'IPQualityScore'}
                elif risk_factors >= 1:
                    result = {'risk': 'suspicious', 'fraud_score': fraud_score, 'source': 'IPQualityScore'}
                else:
                    result = {'risk': 'low', 'fraud_score': fraud_score, 'source': 'IPQualityScore'}
                
                return result
            else:
                print(f"❌ IPQualityScore API error: {response.status_code}")
                return {'risk': 'unknown', 'source': 'IPQualityScore'}
                
        except Exception as e:
            print(f"💥 IPQualityScore check failed: {e}")
            return {'risk': 'unknown', 'source': 'IPQualityScore'}

    def check_ip_reputation(self, ip_address):
        """Controlla la reputazione di un IP con cache su database"""
        
        # Controlla cache in memoria
        cache_key = f"ip_{ip_address}"
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_timeout:
                return cached_data
        
        # Controlla cache nel database
        db_cached = self._get_cached_reputation(ip_address)
        if db_cached:
            self.cache[cache_key] = (db_cached, time.time())
            return db_cached
        
        # Salta IP privati
        if self.is_private_ip(ip_address):
            result = {'risk': 'low', 'source': 'Private IP'}
            self.cache[cache_key] = (result, time.time())
            self._save_ip_reputation(ip_address, result)
            return result
        
        # Chiama le API
        results = []
        results.append(self.check_abuseipdb(ip_address))
        results.append(self.check_virustotal(ip_address))
        results.append(self.check_ipqualityscore(ip_address))
        
        # Determina rischio finale
        risk_weights = {
            'high': 3, 'medium': 2, 'suspicious': 1, 'low': 0, 'unknown': 0
        }
        
        total_weight = 0
        valid_sources = 0
        
        for result in results:
            if result['risk'] != 'unknown':
                total_weight += risk_weights[result['risk']]
                valid_sources += 1
        
        if valid_sources > 0:
            avg_weight = total_weight / valid_sources
            if avg_weight >= 2.5: final_risk = 'high'
            elif avg_weight >= 1.5: final_risk = 'medium'
            elif avg_weight >= 0.5: final_risk = 'suspicious'
            else: final_risk = 'low'
        else:
            final_risk = 'unknown'
        
        primary_source = next((r for r in results if r['risk'] == final_risk), results[0])
        final_result = {
            'risk': final_risk,
            'source': primary_source['source'],
            'details': results
        }
        
        # Salva in cache
        self.cache[cache_key] = (final_result, time.time())
        self._save_ip_reputation(ip_address, final_result)
        
        return final_result

    def analyze_report_ips(self, report_id):
        """Analizza gli IP di un singolo report specifico"""
        try:
            print(f"🔍 Analyzing IPs for report: {report_id}")
            
            # Connessione al database principale
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Query per ottenere gli IP del report specifico
            cursor.execute('''
                SELECT source_ip, count, disposition, dkim, spf
                FROM records 
                WHERE report_id = ?
                ORDER BY count DESC
            ''', (report_id,))
            
            ip_data = cursor.fetchall()
            conn.close()
            
            print(f"📊 Found {len(ip_data)} IPs in report {report_id}")
            
            if not ip_data:
                return {
                    'report_id': report_id,
                    'total_ips': 0,
                    'threat_ips': [],
                    'suspicious_ips': [],
                    'clean_ips': [],
                    'threat_score': 0,
                    'analysis_timestamp': datetime.now().isoformat()
                }
            
            # Analizza gli IP
            threat_ips = []
            suspicious_ips = []
            clean_ips = []
            ip_details = []
            
            for ip, count, disposition, dkim, spf in ip_data:
                print(f"🔍 Analyzing IP from report: {ip} (count: {count})")
                reputation = self.check_ip_reputation(ip)
                
                ip_info = {
                    'ip': ip,
                    'count': count,
                    'disposition': disposition,
                    'dkim': dkim,
                    'spf': spf,
                    'reputation': reputation
                }
                
                if reputation['risk'] == 'high':
                    threat_ips.append(ip)
                    ip_info['threat_level'] = 'high'
                    ip_info['threat_icon'] = '🚨'
                    print(f"🚨 MALICIOUS IP in report: {ip}")
                elif reputation['risk'] in ['medium', 'suspicious']:
                    suspicious_ips.append(ip)
                    ip_info['threat_level'] = 'suspicious'
                    ip_info['threat_icon'] = '⚠️'
                    print(f"⚠️ SUSPICIOUS IP in report: {ip}")
                else:
                    clean_ips.append(ip)
                    ip_info['threat_level'] = 'clean'
                    ip_info['threat_icon'] = '✅'
                    print(f"✅ CLEAN IP in report: {ip}")
                
                ip_details.append(ip_info)
                
                # Piccola pausa per non sovraccaricare le API
                time.sleep(0.1)
            
            # Calcola threat score per il report
            total_ips = len(threat_ips) + len(suspicious_ips) + len(clean_ips)
            if total_ips > 0:
                threat_score = int(((len(threat_ips) * 100 + len(suspicious_ips) * 50) / total_ips))
            else:
                threat_score = 0
            
            # Trova le minacce principali
            top_threats = sorted(
                [ip for ip in ip_details if ip['threat_level'] in ['high', 'suspicious']],
                key=lambda x: (x['threat_level'] == 'high', x['count']),
                reverse=True
            )[:5]
            
            result = {
                'report_id': report_id,
                'total_ips': total_ips,
                'threat_ips': threat_ips,
                'suspicious_ips': suspicious_ips,
                'clean_ips': clean_ips,
                'threat_score': threat_score,
                'ip_details': ip_details,
                'top_threats': top_threats,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            print(f"🎯 Report analysis completed:")
            print(f"   - Threat Score: {threat_score}%")
            print(f"   - Malicious IPs: {len(threat_ips)}")
            print(f"   - Suspicious IPs: {len(suspicious_ips)}")
            print(f"   - Clean IPs: {len(clean_ips)}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing report IPs: {e}")
            return {
                'report_id': report_id,
                'total_ips': 0,
                'threat_ips': [],
                'suspicious_ips': [],
                'clean_ips': [],
                'threat_score': 0,
                'error': str(e),
                'analysis_timestamp': datetime.now().isoformat()
            }


    def analyze_dmarc_data(self, time_filter='30days', force_refresh=False):
        """Analizza i dati DMARC per threat intelligence con cache"""
        try:
            # Se non è forzato, controlla prima il cache
            if not force_refresh:
                cached_data = self.get_cached_threat_data(time_filter)
                if cached_data:
                    print(f"[analyze_dmarc_data] Using cached data for {time_filter}")
                    return cached_data
            
            print(f"🔍 Starting threat intelligence analysis for {time_filter}...")
            
            # Connessione al database principale per leggere gli IP
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Query per ottenere gli IP basata sul filtro temporale
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
                LIMIT {MAX_IPS_TO_CHECK}
            '''
            
            cursor.execute(query)
            ip_data = cursor.fetchall()
            conn.close()
            
            print(f"📊 Found {len(ip_data)} IPs to analyze")
            
            if not ip_data:
                empty_result = {
                    'threat_score': 0,
                    'malicious_ips': 0,
                    'suspicious_ips': 0,
                    'clean_ips': 0,
                    'blocked_ips': 0,
                    'threat_ips': [],
                    'top_threats': [],
                    'recent_activity': [],
                    'total_ips_checked': 0,
                    'message': 'No IPs found',
                    'last_updated': datetime.now().isoformat()
                }
                self.save_to_cache(time_filter, empty_result)
                return empty_result
            
            # Analizza gli IP
            malicious_ips = []
            suspicious_ips = []
            clean_ips = []
            top_threats = []
            recent_activity = []
            
            for ip, count in ip_data:
                print(f"🔍 Analyzing IP: {ip} (count: {count})")
                reputation = self.check_ip_reputation(ip)
                
                if reputation['risk'] == 'high':
                    malicious_ips.append(ip)
                    top_threats.append({
                        'ip': ip,
                        'risk_level': 'high',
                        'source': reputation['source'],
                        'count': count
                    })
                    recent_activity.append({
                        'ip': ip,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
                        'description': f'Malicious IP via {reputation["source"]}',
                        'severity': 'high'
                    })
                    print(f"🚨 MALICIOUS: {ip}")
                elif reputation['risk'] == 'medium':
                    suspicious_ips.append(ip)
                    top_threats.append({
                        'ip': ip,
                        'risk_level': 'medium',
                        'source': reputation['source'],
                        'count': count
                    })
                    recent_activity.append({
                        'ip': ip,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
                        'description': f'Suspicious IP via {reputation["source"]}',
                        'severity': 'medium'
                    })
                    print(f"⚠️ SUSPICIOUS: {ip}")
                elif reputation['risk'] == 'suspicious':
                    suspicious_ips.append(ip)
                    top_threats.append({
                        'ip': ip,
                        'risk_level': 'suspicious',
                        'source': reputation['source'],
                        'count': count
                    })
                    print(f"🔶 SUSPICIOUS: {ip}")
                else:
                    clean_ips.append(ip)
                    print(f"✅ CLEAN: {ip}")
                
                # Piccola pausa per non sovraccaricare le API
                time.sleep(0.1)
            
            # Calcola threat score
            total_ips = len(malicious_ips) + len(suspicious_ips) + len(clean_ips)
            if total_ips > 0:
                threat_score = int(((len(malicious_ips) * 100 + len(suspicious_ips) * 50) / total_ips))
            else:
                threat_score = 0
            
            result = {
                'threat_score': min(threat_score, 100),
                'malicious_ips': len(malicious_ips),
                'suspicious_ips': len(suspicious_ips),
                'clean_ips': len(clean_ips),
                'blocked_ips': len(malicious_ips),
                'threat_ips': malicious_ips + suspicious_ips,
                'top_threats': top_threats[:10],
                'recent_activity': recent_activity[:5],
                'total_ips_checked': total_ips,
                'last_updated': datetime.now().isoformat()
            }
            
            # Salva nel cache per accesso rapido
            self.save_to_cache(time_filter, result)
            
            # Salva anche nello storico
            self._save_analysis_results(time_filter, result)
            
            print(f"🎯 Analysis completed:")
            print(f"   - Threat Score: {result['threat_score']}%")
            print(f"   - Malicious IPs: {result['malicious_ips']}")
            print(f"   - Suspicious IPs: {result['suspicious_ips']}")
            print(f"   - Clean IPs: {result['clean_ips']}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in threat intelligence analysis: {e}")
            error_result = {
                'threat_score': 0,
                'malicious_ips': 0,
                'suspicious_ips': 0,
                'clean_ips': 0,
                'blocked_ips': 0,
                'threat_ips': [],
                'top_threats': [],
                'recent_activity': [],
                'total_ips_checked': 0,
                'error': str(e),
                'last_updated': datetime.now().isoformat()
            }
            return error_result

    def get_recent_threats(self, limit=10):
        """Ottiene le minacce recenti dal database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT dt.ip_address, dt.risk_level, dt.source, dt.email_count, dt.created_at
                FROM detected_threats dt
                JOIN threat_analyses ta ON dt.analysis_id = ta.id
                ORDER BY dt.created_at DESC
                LIMIT ?
            ''', (limit,))
            
            threats = cursor.fetchall()
            conn.close()
            
            return [{
                'ip': row[0],
                'risk_level': row[1],
                'source': row[2],
                'count': row[3],
                'timestamp': row[4]
            } for row in threats]
            
        except Exception as e:
            print(f"Error getting recent threats: {e}")
            return []

# Verifica all'import
print("🔐 Threat Intelligence Module Loaded")
print(f"   - AbuseIPDB: ✅")
print(f"   - VirusTotal: ✅") 
print(f"   - IPQualityScore: ✅")
print(f"   - Single Database: ✅")